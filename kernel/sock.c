#include "kernel.h"

// ---- P5-1: soket UDP untuk program user (syscall 3..7, docs/SYSCALL.md) ----
// Tabel global SOCK_MAX soket; fd = indeks tabel, hanya task pembuatnya yang
// boleh memakai. Datagram masuk (net task, sesudah filter P4, jatah laju UDP dan
// checksum) diantre SOCK_QLEN per soket; antrean penuh = dibuang (sock_drop).
// Kirim: syscall menyalin data ke slot TX soket lalu menunggu; net task (satu-
// satunya pengguna ring TX) mencari MAC (cache kecil, ARP bila perlu), mengirim,
// dan membangunkan pemanggil. Task yang menunggu tidur (TASK_SLEEPING) paling
// lama SOCK_WAIT_CHUNK tick per putaran; net task membangunkannya lebih awal.
// Syscall jalan dengan interrupt mati (gerbang int 0x80); net task mengubah
// keadaan soket di dalam irq_save().

#define SOCK_QLEN        4
#define SOCK_ARP_N       8
#define SOCK_ARP_TRIES   3
#define SOCK_ARP_WAIT    50     // tick antar ARP request (3 x 0,5 s lalu -113)
#define SOCK_WAIT_CHUNK  100    // tick tidur maks sebelum memeriksa ulang
#define SOCK_TX_LIMIT    500    // tick: net task tidak menyelesaikan kirim -> -5

enum { SK_TX_NONE, SK_TX_WANT, SK_TX_ARP, SK_TX_DONE };

typedef struct {
    uint8_t ip[4];
    uint16_t port;
    uint16_t len;
    uint8_t data[SOCK_DGRAM_MAX];
} sk_dgram_t;

typedef struct {
    int used;
    size_t owner;          // indeks task pemilik
    uint16_t port;         // 0 = belum bind
    uint32_t qh, qn;
    sk_dgram_t q[SOCK_QLEN];
    int tx_state;
    int64_t tx_res;
    uint8_t tx_ip[4];
    uint16_t tx_port;
    uint16_t tx_len;
    uint32_t tx_arp_n;
    uint64_t tx_at;
    uint8_t tx_data[SOCK_DGRAM_MAX];
    uint64_t rx, tx, drop;
} sk_t;

typedef struct {
    int ok;
    uint8_t ip[4];
    uint8_t mac[6];
} sk_arp_t;

static sk_t g_sk[SOCK_MAX];
static sk_arp_t g_sk_arp[SOCK_ARP_N];
static uint32_t g_sk_arp_next;
static uint64_t g_sk_page_phys;

uint64_t g_sock_rx = 0;       // datagram masuk antrean
uint64_t g_sock_tx = 0;       // datagram terkirim
uint64_t g_sock_drop = 0;     // antrean penuh
uint64_t g_sock_err = 0;      // syscall soket berakhir dengan kode galat
uint64_t g_sock_noarp = 0;    // kirim gagal: ARP tanpa jawaban

static int sk_ip_eq(const volatile uint8_t *a, const uint8_t *b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static int64_t sk_fail(int64_t e)
{
    g_sock_err++;
    return e;
}

// fd milik task yang sedang berjalan, atau NULL.
static sk_t *sk_get(uint64_t fd)
{
    if (fd >= SOCK_MAX || !g_sk[fd].used || g_sk[fd].owner != current_index) {
        return 0;
    }
    return &g_sk[fd];
}

// Port boleh dipakai program user: 1024..49151 (49152.. = port sumber acak
// kernel: DNS, SNTP, pantau) selain port layanan sistem.
int sock_port_ok(uint32_t port)
{
    return port >= 1024 && port <= 49151 && port != NETCON_SRC_PORT && port != g_netcon_port &&
           !(port >= 7777 && port <= 7780);
}

// Tidur sampai deadline (paling lama SOCK_WAIT_CHUNK tick; pemanggil
// memeriksa ulang kondisinya sendiri).
static void sk_sleep(uint64_t deadline)
{
    uint64_t now = timer_ticks;
    uint64_t t = deadline > now ? deadline - now : 1;

    task_sleep(t > SOCK_WAIT_CHUNK ? SOCK_WAIT_CHUNK : t);
}

static const uint8_t *sk_arp_find(const uint8_t *ip)
{
    for (uint32_t i = 0; i < SOCK_ARP_N; i++) {
        if (g_sk_arp[i].ok && sk_ip_eq(g_sk_arp[i].ip, ip)) {
            return g_sk_arp[i].mac;
        }
    }
    return 0;
}

static void sk_arp_learn(const volatile uint8_t *ip, const volatile uint8_t *mac)
{
    sk_arp_t *e = 0;

    for (uint32_t i = 0; i < SOCK_ARP_N && !e; i++) {
        if (g_sk_arp[i].ok && sk_ip_eq(ip, g_sk_arp[i].ip)) {
            e = &g_sk_arp[i];
        }
    }
    if (!e) {
        e = &g_sk_arp[g_sk_arp_next];
        g_sk_arp_next = (g_sk_arp_next + 1) % SOCK_ARP_N;
    }
    for (int i = 0; i < 4; i++) {
        e->ip[i] = ip[i];
    }
    for (int i = 0; i < 6; i++) {
        e->mac[i] = mac[i];
    }
    e->ok = 1;
}

void sock_init(void)
{
    g_sk_page_phys = pmm_alloc();
}

// Dipanggil task_exit(): semua soket milik task itu ditutup (juga saat task
// user dihentikan karena exception).
void sock_task_exit(size_t idx)
{
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].owner == idx) {
            g_sk[i].used = 0;
        }
    }
}

int sock_wants(uint16_t dport)
{
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].port == dport) {
            return 1;
        }
    }
    return 0;
}

// Datagram UDP sah (checksum, filter, jatah sudah diperiksa net.c) untuk port
// soket. MAC pengirim dicatat supaya balasan tidak perlu ARP.
void sock_rx(const volatile uint8_t *src_mac, const volatile uint8_t *src_ip, uint16_t sport,
             uint16_t dport, const volatile uint8_t *data, uint32_t len)
{
    uint64_t lf = irq_save();

    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        sk_t *s = &g_sk[i];

        if (!s->used || s->port != dport) {
            continue;
        }
        sk_arp_learn(src_ip, src_mac);
        if (s->qn >= SOCK_QLEN) {
            s->drop++;
            g_sock_drop++;
            break;
        }
        sk_dgram_t *d = &s->q[(s->qh + s->qn) % SOCK_QLEN];
        uint32_t n = len > SOCK_DGRAM_MAX ? SOCK_DGRAM_MAX : len;

        for (int k = 0; k < 4; k++) {
            d->ip[k] = src_ip[k];
        }
        d->port = sport;
        d->len = (uint16_t)n;
        for (uint32_t k = 0; k < n; k++) {
            d->data[k] = data[k];
        }
        s->qn++;
        s->rx++;
        g_sock_rx++;
        task_wake(s->owner);
        break;
    }
    irq_restore(lf);
}

// ARP (reply atau request) dari alamat yang sedang ditunggu slot TX.
void sock_arp_seen(const volatile uint8_t *buf)
{
    uint64_t lf = irq_save();

    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].tx_state == SK_TX_ARP && sk_ip_eq(buf + 28, g_sk[i].tx_ip)) {
            sk_arp_learn(buf + 28, buf + 22);
            g_sk[i].tx_at = 0;   // kirim di putaran sock_poll berikut
        }
    }
    irq_restore(lf);
}

static void sk_tx_finish(sk_t *s, int64_t res)
{
    s->tx_res = res;
    s->tx_state = SK_TX_DONE;
    task_wake(s->owner);
}

// Tiap putaran net task: selesaikan slot TX yang menunggu.
void sock_poll(void)
{
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        uint64_t lf = irq_save();
        sk_t *s = &g_sk[i];

        if (!s->used || (s->tx_state != SK_TX_WANT && s->tx_state != SK_TX_ARP)) {
            irq_restore(lf);
            continue;
        }
        uint8_t *p = (uint8_t *)(g_sk_page_phys + hhdm_offset);
        const uint8_t *mac = sk_arp_find(s->tx_ip);

        if (mac) {
            for (uint32_t k = 0; k < s->tx_len; k++) {
                p[42 + k] = s->tx_data[k];
            }
            uint32_t n = net_udp_build(p, mac, s->tx_ip, s->port, s->tx_port, s->tx_len);

            if (e1000_tx_send(g_sk_page_phys, n)) {
                s->tx++;
                g_sock_tx++;
                sk_tx_finish(s, s->tx_len);
            } else {
                g_sock_err++;
                sk_tx_finish(s, SOCK_EIO);
            }
        } else if (s->tx_state == SK_TX_WANT) {
            s->tx_state = SK_TX_ARP;
            s->tx_arp_n = 0;
            s->tx_at = 0;
        }
        if (s->tx_state == SK_TX_ARP && timer_ticks >= s->tx_at) {
            if (s->tx_arp_n >= SOCK_ARP_TRIES) {
                g_sock_noarp++;
                g_sock_err++;
                sk_tx_finish(s, SOCK_EHOSTUNREACH);
            } else {
                s->tx_arp_n++;
                s->tx_at = timer_ticks + SOCK_ARP_WAIT;
                e1000_tx_send(g_sk_page_phys, net_arp_request_build(p, s->tx_ip));
            }
        }
        irq_restore(lf);
    }
}

// ---- syscall (dipanggil trap.c, interrupt mati) ----

uint64_t sock_sys_socket(uint64_t type, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a1; (void)a2; (void)a3; (void)a4;

    if (type != SOCK_UDP) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (!g_sk[i].used) {
            sk_t *s = &g_sk[i];

            s->port = 0;
            s->qh = s->qn = 0;
            s->tx_state = SK_TX_NONE;
            s->rx = s->tx = s->drop = 0;
            s->owner = current_index;
            s->used = 1;
            return i;
        }
    }
    return (uint64_t)sk_fail(SOCK_EMFILE);
}

uint64_t sock_sys_bind(uint64_t fd, uint64_t port, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a2; (void)a3; (void)a4;
    sk_t *s = sk_get(fd);

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (s->port != 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    if (port > 65535 || !sock_port_ok((uint32_t)port)) {
        return (uint64_t)sk_fail(SOCK_EACCES);
    }
    if (sock_wants((uint16_t)port)) {
        return (uint64_t)sk_fail(SOCK_EADDRINUSE);
    }
    s->port = (uint16_t)port;
    return 0;
}

uint64_t sock_sys_sendto(uint64_t fd, uint64_t buf, uint64_t len, uint64_t addr, uint64_t a4)
{
    (void)a4;
    sk_t *s = sk_get(fd);
    uint8_t ip[4] = { (uint8_t)(addr >> 40), (uint8_t)(addr >> 32), (uint8_t)(addr >> 24),
                      (uint8_t)(addr >> 16) };
    uint16_t dport = (uint16_t)addr;

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (len > SOCK_DGRAM_MAX) {
        return (uint64_t)sk_fail(SOCK_EMSGSIZE);
    }
    if (!is_valid_user_ptr(g_current_pml4_phys, buf, len, false)) {
        g_sys_rejected++;
        return (uint64_t)sk_fail(SOCK_EFAULT);
    }
    if (s->port == 0 || dport == 0 || (addr >> 48) != 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    if (!g_e1000_rx_initialized || !net_ip_ready() || g_sk_page_phys == 0) {
        return (uint64_t)sk_fail(SOCK_ENETDOWN);
    }
    // Tanpa gateway: hanya /24 sendiri, bukan alamat jaringan/broadcast/diri sendiri.
    if (ip[0] != g_net_ip[0] || ip[1] != g_net_ip[1] || ip[2] != g_net_ip[2] || ip[3] == 0 ||
        ip[3] == 255 || ip[3] == g_net_ip[3]) {
        return (uint64_t)sk_fail(SOCK_EHOSTUNREACH);
    }

    const uint8_t *src = (const uint8_t *)buf;

    for (uint64_t k = 0; k < len; k++) {
        s->tx_data[k] = src[k];
    }
    for (int k = 0; k < 4; k++) {
        s->tx_ip[k] = ip[k];
    }
    s->tx_port = dport;
    s->tx_len = (uint16_t)len;
    s->tx_state = SK_TX_WANT;
    net_rx_tick_wake();

    uint64_t limit = timer_ticks + SOCK_TX_LIMIT;

    while (s->tx_state != SK_TX_DONE) {
        if (timer_ticks >= limit) {
            s->tx_state = SK_TX_NONE;
            return (uint64_t)sk_fail(SOCK_EIO);
        }
        sk_sleep(limit);
    }
    s->tx_state = SK_TX_NONE;
    return (uint64_t)s->tx_res;
}

uint64_t sock_sys_recvfrom(uint64_t fd, uint64_t buf, uint64_t cap, uint64_t from, uint64_t timeout)
{
    sk_t *s = sk_get(fd);

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (cap > SOCK_DGRAM_MAX) {
        cap = SOCK_DGRAM_MAX;
    }
    if (!is_valid_user_ptr(g_current_pml4_phys, buf, cap, true) ||
        (from != 0 && !is_valid_user_ptr(g_current_pml4_phys, from, 8, true))) {
        g_sys_rejected++;
        return (uint64_t)sk_fail(SOCK_EFAULT);
    }
    if (s->port == 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }

    uint64_t deadline = timer_ticks + timeout;

    while (s->qn == 0) {
        if (timeout != 0 && timer_ticks >= deadline) {
            return (uint64_t)sk_fail(SOCK_EAGAIN);
        }
        sk_sleep(timeout != 0 ? deadline : timer_ticks + SOCK_WAIT_CHUNK);
    }

    sk_dgram_t *d = &s->q[s->qh];
    uint32_t n = d->len < cap ? d->len : (uint32_t)cap;   // sisa datagram dibuang
    uint8_t *dst = (uint8_t *)buf;

    for (uint32_t k = 0; k < n; k++) {
        dst[k] = d->data[k];
    }
    if (from != 0) {
        *(uint64_t *)from = SOCK_ADDR(d->ip[0], d->ip[1], d->ip[2], d->ip[3], d->port);
    }
    s->qh = (s->qh + 1) % SOCK_QLEN;
    s->qn--;
    return n;
}

uint64_t sock_sys_close(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a1; (void)a2; (void)a3; (void)a4;
    sk_t *s = sk_get(fd);

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    s->used = 0;
    return 0;
}

// `soket` (juga peran ro): satu baris per soket terbuka + penghitung.
int sock_execute(const volatile uint8_t *cmd, uint32_t len)
{
    char line[160];
    int n = 0;

    if (!net_cmd_is(cmd, len, "soket")) {
        return 0;
    }
    g_cmd_len = 0;
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        sk_t *s = &g_sk[i];

        if (!s->used) {
            continue;
        }
        n++;
        ksnprintf(line, sizeof(line), "%u: udp port %u task %lu antre %u/%u masuk=%lu kirim=%lu "
                  "buang=%lu\n", i, s->port, (uint64_t)s->owner, s->qn, SOCK_QLEN, s->rx, s->tx,
                  s->drop);
        cmd_puts(line);
    }
    if (n == 0) {
        cmd_puts("soket: tidak ada yang terbuka\n");
    }
    ksnprintf(line, sizeof(line), "soket: %d/%d terbuka masuk=%lu kirim=%lu buang=%lu galat=%lu "
              "tanpa_arp=%lu\n", n, SOCK_MAX, g_sock_rx, g_sock_tx, g_sock_drop, g_sock_err,
              g_sock_noarp);
    cmd_puts(line);
    return 1;
}

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
//
// P5-2: soket TCP server (listen/accept/send/recv). TCB tetap milik net.c dan
// hanya diubah net task; tiap slot TCB user (SOCK_TCP_CONN) punya pasangan di
// g_skc: ring masuk dan ring keluar SOCK_TCP_RING byte plus flag. net task
// memanggil kait sock_tcp_* (di dalam irq_save) untuk mengisi ring masuk,
// mengambil ring keluar, dan melaporkan handshake/FIN/penutupan; syscall hanya
// menyentuh g_skc. Slot koneksi bebas lagi setelah TCB CLOSED dan fd ditutup
// (koneksi yang belum di-accept: begitu TCB CLOSED).
//
// P5-3: connect (klien). Syscall hanya mencatat tujuan di slot TX soket
// (tx_state, seperti sendto); net task (sock_poll) mencari MAC (cache/ARP),
// lalu net_tcp_user_connect memilih slot TCB user, port lokal acak, dan
// mengirim SYN. Semua pengambilan slot koneksi terjadi di net task.

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
    int type;              // SOCK_UDP / SOCK_TCP (P5-2)
    int listening;         // P5-2: TCP, sesudah listen
    int conn;              // P5-2: TCP hasil accept: indeks g_skc, selain itu -1
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

// P5-2: keadaan slot koneksi TCP user.
enum { SKC_FREE = 0, SKC_SYN, SKC_OPEN, SKC_DONE };

typedef struct {
    int state;
    int accepted;          // fd hasil accept memegang slot ini
    size_t owner;          // task pemilik fd (dibangunkan net task)
    int app;               // ditulis syscall: 0, SOCK_TCP_APP_CLOSE, SOCK_TCP_APP_ABORT
    int peer_fin;          // FIN peer diterima
    int reset;             // TCB berakhir tanpa penutupan baik-baik (RST, timeout)
    int est;               // P5-3: handshake pernah selesai (ESTABLISHED)
    int refused;           // P5-3: SYN kita dijawab RST
    uint64_t order;        // urutan ESTABLISHED: accept mengambil yang tertua
    uint16_t lport, rport;
    uint8_t ip[4];
    uint32_t rx_h, rx_n, tx_h, tx_n;
    uint8_t rx[SOCK_TCP_RING];
    uint8_t tx[SOCK_TCP_RING];
    uint64_t rx_bytes, tx_bytes;
} skc_t;

static sk_t g_sk[SOCK_MAX];
static skc_t g_skc[SOCK_TCP_CONN];
static uint64_t g_skc_order;
static sk_arp_t g_sk_arp[SOCK_ARP_N];
static uint32_t g_sk_arp_next;
static uint64_t g_sk_page_phys;

uint64_t g_sock_rx = 0;       // datagram masuk antrean
uint64_t g_sock_tx = 0;       // datagram terkirim
uint64_t g_sock_drop = 0;     // antrean penuh
uint64_t g_sock_err = 0;      // syscall soket berakhir dengan kode galat
uint64_t g_sock_noarp = 0;    // kirim gagal: ARP tanpa jawaban
uint64_t g_sock_tcp_accept = 0;   // P5-2: koneksi yang di-accept
uint64_t g_sock_tcp_rx = 0;       // byte masuk ring (dari peer)
uint64_t g_sock_tcp_tx = 0;       // byte diambil net task dari ring keluar
uint64_t g_sock_tcp_reset = 0;    // koneksi milik fd berakhir dengan reset
uint64_t g_sock_connect = 0;      // P5-3: connect berhasil

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

// P5-2: lepas fd. Koneksi TCP: FIN setelah ring keluar habis, atau RST bila
// masih ada data masuk yang belum dibaca (seperti Linux); TCB yang sudah
// CLOSED langsung membebaskan slot. Soket listen: koneksi yang belum di-accept
// di port itu di-RST. Interrupt mati (syscall) atau di dalam irq_save.
static void sk_release(sk_t *s)
{
    if (s->conn >= 0) {
        skc_t *c = &g_skc[s->conn];

        if (c->state == SKC_DONE) {
            c->state = SKC_FREE;
        } else {
            c->app = c->rx_n > 0 ? SOCK_TCP_APP_ABORT : SOCK_TCP_APP_CLOSE;
        }
        net_rx_tick_wake();
    }
    if (s->listening) {
        for (uint32_t i = 0; i < SOCK_TCP_CONN; i++) {
            skc_t *c = &g_skc[i];

            if ((c->state == SKC_SYN || c->state == SKC_OPEN) && !c->accepted &&
                c->lport == s->port) {
                c->app = SOCK_TCP_APP_ABORT;
            }
        }
        net_rx_tick_wake();
    }
    s->used = 0;
}

// Dipanggil task_exit(): semua soket milik task itu ditutup (juga saat task
// user dihentikan karena exception).
void sock_task_exit(size_t idx)
{
    uint64_t lf = irq_save();

    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].owner == idx) {
            sk_release(&g_sk[i]);
        }
    }
    irq_restore(lf);
}

static int sk_port_used(int type, uint16_t port)
{
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].type == type && g_sk[i].port == port) {
            return 1;
        }
    }
    return 0;
}

int sock_wants(uint16_t dport)
{
    return sk_port_used(SOCK_UDP, dport);
}

// Datagram UDP sah (checksum, filter, jatah sudah diperiksa net.c) untuk port
// soket. MAC pengirim dicatat supaya balasan tidak perlu ARP.
void sock_rx(const volatile uint8_t *src_mac, const volatile uint8_t *src_ip, uint16_t sport,
             uint16_t dport, const volatile uint8_t *data, uint32_t len)
{
    uint64_t lf = irq_save();

    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        sk_t *s = &g_sk[i];

        if (!s->used || s->type != SOCK_UDP || s->port != dport) {
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

        if (mac && s->type == SOCK_TCP) {
            // P5-3: connect. Entropi belum cukup: coba lagi putaran berikut.
            int c = net_tcp_user_connect(mac, s->tx_ip, s->tx_port, s->owner);

            if (c >= 0) {
                s->conn = c;
                sk_tx_finish(s, 0);
            } else if (c != SOCK_EAGAIN) {
                g_sock_err++;
                sk_tx_finish(s, c);
            }
        } else if (mac) {
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

    if (type != SOCK_UDP && type != SOCK_TCP) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (!g_sk[i].used) {
            sk_t *s = &g_sk[i];

            s->type = (int)type;
            s->listening = 0;
            s->conn = -1;
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
    if (s->port != 0 || s->conn >= 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    if (port > 65535 || !sock_port_ok((uint32_t)port)) {
        return (uint64_t)sk_fail(SOCK_EACCES);
    }
    if (sk_port_used(s->type, (uint16_t)port)) {
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
    if (s->type != SOCK_UDP || s->port == 0 || dport == 0 || (addr >> 48) != 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    // P5-2: juga sebelum loop net task jalan (inisialisasi modul jaringan + pindai
    // LOG.BIN bisa > 5 s di QEMU TCG): kalau tidak, batas kirim habis -> -5.
    if (!g_e1000_rx_initialized || !net_ip_ready() || g_sk_page_phys == 0 || g_net_loops == 0) {
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
    if (s->type != SOCK_UDP || s->port == 0) {
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
    sk_release(s);
    return 0;
}

// ---- P5-2: kait TCP untuk net.c (net task) ----
// c = indeks slot TCB user (0..SOCK_TCP_CONN-1).

static const char *sk_conn_str(const skc_t *c)
{
    if (c->state == SKC_SYN) {
        return "menyambung";   // P5-3: SYN_SENT (accept hanya mengambil SKC_OPEN)
    }
    if (c->state == SKC_DONE) {
        return c->reset ? "reset" : "tutup";
    }
    return c->peer_fin ? "fin" : "terbuka";
}

static void sk_conn_wake(const skc_t *c)
{
    if (c->accepted) {
        task_wake(c->owner);
    }
}

// 1 = ada soket TCP listen di port itu.
int sock_tcp_listening(uint16_t port)
{
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].type == SOCK_TCP && g_sk[i].listening &&
            g_sk[i].port == port) {
            return 1;
        }
    }
    return 0;
}

// 1 = slot koneksi bebas (TCB CLOSED dan tidak dipegang fd).
int sock_tcp_slot_free(uint32_t c)
{
    return c < SOCK_TCP_CONN && g_skc[c].state == SKC_FREE;
}

// SYN diterima ke port listen: slot dipakai koneksi baru (SYN_RCVD).
void sock_tcp_syn(uint32_t c, const volatile uint8_t *ip, uint16_t rport, uint16_t lport)
{
    uint64_t lf = irq_save();
    skc_t *k = &g_skc[c];

    k->state = SKC_SYN;
    k->accepted = 0;
    k->owner = 0;
    k->app = 0;
    k->peer_fin = 0;
    k->reset = 0;
    k->est = 0;
    k->refused = 0;
    k->lport = lport;
    k->rport = rport;
    for (int i = 0; i < 4; i++) {
        k->ip[i] = ip[i];
    }
    k->rx_h = k->rx_n = k->tx_h = k->tx_n = 0;
    k->rx_bytes = k->tx_bytes = 0;
    irq_restore(lf);
}

// P5-3: slot dipakai connect: langsung dipegang fd pemanggil (seperti accept).
void sock_tcp_conn(uint32_t c, const uint8_t *ip, uint16_t rport, uint16_t lport, size_t owner)
{
    uint64_t lf = irq_save();

    sock_tcp_syn(c, ip, rport, lport);
    g_skc[c].accepted = 1;
    g_skc[c].owner = owner;
    irq_restore(lf);
}

void sock_tcp_refused(uint32_t c)
{
    g_skc[c].refused = 1;
}

// Handshake selesai: koneksi siap di-accept; pemilik soket listen dibangunkan.
void sock_tcp_open(uint32_t c)
{
    uint64_t lf = irq_save();
    skc_t *k = &g_skc[c];

    k->state = SKC_OPEN;
    k->est = 1;
    k->order = ++g_skc_order;
    sk_conn_wake(k);   // P5-3: connect menunggu
    for (uint32_t i = 0; i < SOCK_MAX; i++) {
        if (g_sk[i].used && g_sk[i].type == SOCK_TCP && g_sk[i].listening &&
            g_sk[i].port == k->lport) {
            task_wake(g_sk[i].owner);
        }
    }
    irq_restore(lf);
}

// Ruang ring masuk (= jendela yang diiklankan TCB).
uint32_t sock_tcp_rx_space(uint32_t c)
{
    return SOCK_TCP_RING - g_skc[c].rx_n;
}

// Data dalam urutan dari peer. Return jumlah byte yang masuk ring (sisanya
// tidak di-ACK). Setelah close tidak ada pembaca: 0 (net.c memutus dengan RST).
uint32_t sock_tcp_rx(uint32_t c, const volatile uint8_t *d, uint32_t len)
{
    uint64_t lf = irq_save();
    skc_t *k = &g_skc[c];
    uint32_t room = SOCK_TCP_RING - k->rx_n;
    uint32_t n = len > room ? room : len;

    if (k->app != 0) {
        n = 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        k->rx[(k->rx_h + k->rx_n + i) % SOCK_TCP_RING] = d[i];
    }
    k->rx_n += n;
    k->rx_bytes += n;
    g_sock_tcp_rx += n;
    if (n > 0) {
        sk_conn_wake(k);
    }
    irq_restore(lf);
    return n;
}

void sock_tcp_fin(uint32_t c)
{
    uint64_t lf = irq_save();

    g_skc[c].peer_fin = 1;
    sk_conn_wake(&g_skc[c]);
    irq_restore(lf);
}

// Ambil maks max byte dari ring keluar ke dst. Pemilik dibangunkan (ruang
// kosong untuk send berikutnya).
uint32_t sock_tcp_tx_take(uint32_t c, uint8_t *dst, uint32_t max)
{
    uint64_t lf = irq_save();
    skc_t *k = &g_skc[c];
    uint32_t n = k->tx_n > max ? max : k->tx_n;

    for (uint32_t i = 0; i < n; i++) {
        dst[i] = k->tx[(k->tx_h + i) % SOCK_TCP_RING];
    }
    k->tx_h = (k->tx_h + n) % SOCK_TCP_RING;
    k->tx_n -= n;
    k->tx_bytes += n;
    g_sock_tcp_tx += n;
    if (n > 0) {
        sk_conn_wake(k);
    }
    irq_restore(lf);
    return n;
}

// Flag untuk net task: SOCK_TCP_APP_* | SOCK_TCP_ACCEPTED | SOCK_TCP_TXQ (ring
// keluar belum kosong).
int sock_tcp_app(uint32_t c)
{
    const skc_t *k = &g_skc[c];

    return k->app | (k->accepted ? SOCK_TCP_ACCEPTED : 0) | (k->tx_n ? SOCK_TCP_TXQ : 0);
}

// TCB menjadi CLOSED. reset = 1 bila bukan penutupan baik-baik (kedua FIN).
void sock_tcp_closed(uint32_t c, int reset)
{
    uint64_t lf = irq_save();
    skc_t *k = &g_skc[c];

    if (!k->accepted || k->app != 0) {
        k->state = SKC_FREE;   // tidak ada fd yang memegangnya lagi
    } else {
        k->state = SKC_DONE;
        k->reset = reset;
        if (reset && k->est) {   // P5-3: connect gagal tidak dihitung
            g_sock_tcp_reset++;
        }
        sk_conn_wake(k);
    }
    irq_restore(lf);
}

// ---- P5-2: syscall TCP ----

uint64_t sock_sys_listen(uint64_t fd, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a1; (void)a2; (void)a3; (void)a4;
    sk_t *s = sk_get(fd);

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (s->type != SOCK_TCP || s->port == 0 || s->listening || s->conn >= 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    s->listening = 1;
    return 0;
}

uint64_t sock_sys_accept(uint64_t fd, uint64_t from, uint64_t timeout, uint64_t a3, uint64_t a4)
{
    (void)a3; (void)a4;
    sk_t *s = sk_get(fd);

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (from != 0 && !is_valid_user_ptr(g_current_pml4_phys, from, 8, true)) {
        g_sys_rejected++;
        return (uint64_t)sk_fail(SOCK_EFAULT);
    }
    if (!s->listening) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }

    uint64_t deadline = timer_ticks + timeout;

    for (;;) {
        skc_t *c = 0;
        uint32_t ci = 0;

        for (uint32_t i = 0; i < SOCK_TCP_CONN; i++) {
            skc_t *k = &g_skc[i];

            if (k->state == SKC_OPEN && !k->accepted && k->app == 0 && k->lport == s->port &&
                (c == 0 || k->order < c->order)) {
                c = k;
                ci = i;
            }
        }
        if (c) {
            for (uint32_t i = 0; i < SOCK_MAX; i++) {
                if (!g_sk[i].used) {
                    sk_t *n = &g_sk[i];

                    n->type = SOCK_TCP;
                    n->listening = 0;
                    n->conn = (int)ci;
                    n->port = c->lport;
                    n->qh = n->qn = 0;
                    n->tx_state = SK_TX_NONE;
                    n->rx = n->tx = n->drop = 0;
                    n->owner = current_index;
                    n->used = 1;
                    c->accepted = 1;
                    c->owner = current_index;
                    g_sock_tcp_accept++;
                    if (from != 0) {
                        *(uint64_t *)from = SOCK_ADDR(c->ip[0], c->ip[1], c->ip[2], c->ip[3],
                                                      c->rport);
                    }
                    return i;
                }
            }
            return (uint64_t)sk_fail(SOCK_EMFILE);   // koneksi tetap menunggu
        }
        if (timeout != 0 && timer_ticks >= deadline) {
            return (uint64_t)sk_fail(SOCK_EAGAIN);
        }
        sk_sleep(timeout != 0 ? deadline : timer_ticks + SOCK_WAIT_CHUNK);
    }
}

// fd koneksi TCP milik task ini, atau galat (negatif) lewat *err.
static skc_t *sk_conn_get(uint64_t fd, int64_t *err)
{
    sk_t *s = sk_get(fd);

    if (!s) {
        *err = SOCK_EBADF;
        return 0;
    }
    if (s->type != SOCK_TCP || s->conn < 0) {
        *err = SOCK_ENOTCONN;
        return 0;
    }
    return &g_skc[s->conn];
}

uint64_t sock_sys_send(uint64_t fd, uint64_t buf, uint64_t len, uint64_t timeout, uint64_t a4)
{
    (void)a4;
    int64_t err = 0;
    skc_t *c = sk_conn_get(fd, &err);

    if (!c) {
        return (uint64_t)sk_fail(err);
    }
    if (len > SOCK_TCP_RING) {
        len = SOCK_TCP_RING;
    }
    if (!is_valid_user_ptr(g_current_pml4_phys, buf, len, false)) {
        g_sys_rejected++;
        return (uint64_t)sk_fail(SOCK_EFAULT);
    }

    uint64_t deadline = timer_ticks + timeout;
    const uint8_t *src = (const uint8_t *)buf;

    for (;;) {
        if (c->state == SKC_DONE) {
            return (uint64_t)sk_fail(c->reset ? SOCK_ECONNRESET : SOCK_EPIPE);
        }
        if (len == 0) {
            return 0;
        }

        uint32_t room = SOCK_TCP_RING - c->tx_n;

        if (room > 0) {
            uint32_t n = len > room ? room : (uint32_t)len;

            for (uint32_t i = 0; i < n; i++) {
                c->tx[(c->tx_h + c->tx_n + i) % SOCK_TCP_RING] = src[i];
            }
            c->tx_n += n;
            net_rx_tick_wake();
            return n;
        }
        if (timeout != 0 && timer_ticks >= deadline) {
            return (uint64_t)sk_fail(SOCK_EAGAIN);
        }
        sk_sleep(timeout != 0 ? deadline : timer_ticks + SOCK_WAIT_CHUNK);
    }
}

uint64_t sock_sys_recv(uint64_t fd, uint64_t buf, uint64_t cap, uint64_t timeout, uint64_t a4)
{
    (void)a4;
    int64_t err = 0;
    skc_t *c = sk_conn_get(fd, &err);

    if (!c) {
        return (uint64_t)sk_fail(err);
    }
    if (cap > SOCK_TCP_RING) {
        cap = SOCK_TCP_RING;
    }
    if (!is_valid_user_ptr(g_current_pml4_phys, buf, cap, true)) {
        g_sys_rejected++;
        return (uint64_t)sk_fail(SOCK_EFAULT);
    }

    uint64_t deadline = timer_ticks + timeout;
    uint8_t *dst = (uint8_t *)buf;

    for (;;) {
        if (c->rx_n > 0 || cap == 0) {
            uint32_t n = c->rx_n < cap ? c->rx_n : (uint32_t)cap;
            uint32_t before = SOCK_TCP_RING - c->rx_n;

            for (uint32_t i = 0; i < n; i++) {
                dst[i] = c->rx[(c->rx_h + i) % SOCK_TCP_RING];
            }
            c->rx_h = (c->rx_h + n) % SOCK_TCP_RING;
            c->rx_n -= n;
            if (n > 0 && before < SOCK_TCP_WND_UPD) {
                net_rx_tick_wake();   // jendela terbuka lagi: net task kirim ACK
            }
            return n;
        }
        // Data yang sudah masuk tetap bisa dibaca setelah FIN/RST.
        if (c->state == SKC_DONE && c->reset) {
            return (uint64_t)sk_fail(SOCK_ECONNRESET);
        }
        if (c->peer_fin || c->state == SKC_DONE) {
            return 0;
        }
        if (timeout != 0 && timer_ticks >= deadline) {
            return (uint64_t)sk_fail(SOCK_EAGAIN);
        }
        sk_sleep(timeout != 0 ? deadline : timer_ticks + SOCK_WAIT_CHUNK);
    }
}

// P5-3: connect(fd, alamat, timeout). Soket TCP baru (belum bind/listen/
// connect). Tujuan seperti sendto: /24 sendiri tanpa .0/.255/IP sendiri.
// Menunggu sampai ESTABLISHED (0), RST (-111), SYN tanpa jawaban (-110),
// ARP tanpa jawaban (-113), slot koneksi user penuh (-24), atau timeout tick
// (0 = sampai kernel menyerah, ~31 s) -> -110 dan percobaan dibatalkan.
// Gagal: fd tetap soket TCP baru (boleh connect lagi atau close).
uint64_t sock_sys_connect(uint64_t fd, uint64_t addr, uint64_t timeout, uint64_t a3, uint64_t a4)
{
    (void)a3; (void)a4;
    sk_t *s = sk_get(fd);
    uint8_t ip[4] = { (uint8_t)(addr >> 40), (uint8_t)(addr >> 32), (uint8_t)(addr >> 24),
                      (uint8_t)(addr >> 16) };
    uint16_t rport = (uint16_t)addr;

    if (!s) {
        return (uint64_t)sk_fail(SOCK_EBADF);
    }
    if (s->type != SOCK_TCP || s->port != 0 || s->listening || s->conn >= 0 ||
        rport == 0 || (addr >> 48) != 0) {
        return (uint64_t)sk_fail(SOCK_EINVAL);
    }
    if (!g_e1000_rx_initialized || !net_ip_ready() || g_sk_page_phys == 0 || g_net_loops == 0) {
        return (uint64_t)sk_fail(SOCK_ENETDOWN);
    }
    if (ip[0] != g_net_ip[0] || ip[1] != g_net_ip[1] || ip[2] != g_net_ip[2] || ip[3] == 0 ||
        ip[3] == 255 || ip[3] == g_net_ip[3]) {
        return (uint64_t)sk_fail(SOCK_EHOSTUNREACH);
    }
    for (int k = 0; k < 4; k++) {
        s->tx_ip[k] = ip[k];
    }
    s->tx_port = rport;
    s->tx_res = 0;
    s->tx_state = SK_TX_WANT;
    net_rx_tick_wake();

    uint64_t deadline = timer_ticks + timeout;

    for (;;) {
        if (s->tx_state == SK_TX_DONE && s->tx_res < 0) {
            s->tx_state = SK_TX_NONE;
            return (uint64_t)s->tx_res;   // sudah dihitung sock_poll (sock_err)
        }
        if (s->tx_state == SK_TX_DONE) {
            skc_t *c = &g_skc[s->conn];

            if (c->est) {
                s->tx_state = SK_TX_NONE;
                g_sock_connect++;
                return 0;
            }
            if (c->state == SKC_DONE) {
                int64_t e = c->refused ? SOCK_ECONNREFUSED : SOCK_ETIMEDOUT;

                c->state = SKC_FREE;
                s->conn = -1;
                s->tx_state = SK_TX_NONE;
                return (uint64_t)sk_fail(e);
            }
        }
        if (timeout != 0 && timer_ticks >= deadline) {
            if (s->tx_state == SK_TX_DONE) {
                // SYN_SENT: net task melepas TCB; slot bebas setelahnya.
                g_skc[s->conn].accepted = 0;
                g_skc[s->conn].app = SOCK_TCP_APP_ABORT;
                s->conn = -1;
                net_rx_tick_wake();
            }
            s->tx_state = SK_TX_NONE;
            return (uint64_t)sk_fail(SOCK_ETIMEDOUT);
        }
        sk_sleep(timeout != 0 ? deadline : timer_ticks + SOCK_WAIT_CHUNK);
    }
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
        if (s->type == SOCK_UDP) {
            ksnprintf(line, sizeof(line), "%u: udp port %u task %lu antre %u/%u masuk=%lu "
                      "kirim=%lu buang=%lu\n", i, s->port, (uint64_t)s->owner, s->qn, SOCK_QLEN,
                      s->rx, s->tx, s->drop);
        } else if (s->conn >= 0) {
            skc_t *c = &g_skc[s->conn];

            ksnprintf(line, sizeof(line), "%u: tcp port %u task %lu ke %u.%u.%u.%u:%u %s "
                      "antre %u/%u masuk=%lu kirim=%lu\n", i, c->lport, (uint64_t)s->owner,
                      c->ip[0], c->ip[1], c->ip[2], c->ip[3], c->rport, sk_conn_str(c), c->rx_n,
                      c->tx_n, c->rx_bytes, c->tx_bytes);
        } else {
            ksnprintf(line, sizeof(line), "%u: tcp port %u task %lu %s\n", i, s->port,
                      (uint64_t)s->owner, s->listening ? "listen" : "belum listen");
        }
        cmd_puts(line);
    }
    if (n == 0) {
        cmd_puts("soket: tidak ada yang terbuka\n");
    }
    ksnprintf(line, sizeof(line), "soket: %d/%d terbuka masuk=%lu kirim=%lu buang=%lu galat=%lu "
              "tanpa_arp=%lu\n", n, SOCK_MAX, g_sock_rx, g_sock_tx, g_sock_drop, g_sock_err,
              g_sock_noarp);
    cmd_puts(line);

    uint32_t nc = 0;

    for (uint32_t i = 0; i < SOCK_TCP_CONN; i++) {
        nc += g_skc[i].state != SKC_FREE;
    }
    ksnprintf(line, sizeof(line), "tcp: %u/%u koneksi diterima=%lu keluar=%lu masuk=%lu kirim=%lu "
              "reset=%lu\n", nc, SOCK_TCP_CONN, g_sock_tcp_accept, g_sock_connect, g_sock_tcp_rx,
              g_sock_tcp_tx, g_sock_tcp_reset);
    cmd_puts(line);
    return 1;
}

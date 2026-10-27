#include "kernel.h"

// P3-3: klien DNS (query A) sekali jalan + cache 8 entri. `dns <nama> [oktet
// [port]]` (admin): nama yang masih ada di cache langsung dijawab; selain itu
// query dikirim ke 192.168.50.<oktet>:<port> (bawaan .1:53, server di /24
// sendiri, tanpa gateway) dan hasilnya dilihat dengan mengulang perintah atau
// `dns` (status + isi cache, juga peran read-only).
// Query: ID + port sumber acak, RD=1, satu pertanyaan A/IN, nama 1..63 byte
// ([a-z0-9-], label 1..63, huruf besar -> kecil). Balasan diterima hanya dari
// IP:port server ke port kita, ID sama, QR=1, opcode 0, TC=0, QDCOUNT=1 dan
// pertanyaan identik (byte demi byte, huruf besar/kecil diabaikan). RCODE 3 =
// jawaban negatif (cache 60 s); A/IN pertama di bagian answer dipakai (CNAME di
// depannya dilewati). Nama di answer hanya DILOMPATI, tidak pernah diikuti:
// pointer kompresi (2 byte) mengakhiri nama, jadi loop pointer tidak mungkin.
// TTL dibatasi 5..3600 s. Cache penuh -> entri yang paling cepat kedaluwarsa
// diganti. Balasan rusak/tidak cocok diabaikan dan dihitung (g_dns_bad).

#define DNS_NAME_MAX   63
#define DNS_QMAX       (12 + DNS_NAME_MAX + 2 + 4)
#define DNS_CACHE      8
#define DNS_ARP_TRIES  3
#define DNS_ARP_EVERY  100   // tick
#define DNS_TIMEOUT    300   // tick setelah query terkirim
#define DNS_TTL_MIN    5
#define DNS_TTL_MAX    3600
#define DNS_NEG_TTL    60
#define DNS_ANS_MAX    16    // answer yang diperiksa per balasan

enum { DNS_IDLE, DNS_ARP, DNS_SENT };

typedef struct {
    char name[DNS_NAME_MAX + 1];   // "" = kosong
    uint8_t ip[4];
    uint8_t neg;                   // 1 = NXDOMAIN
    uint64_t expires;              // tick
} dns_entry_t;

static dns_entry_t g_dns_cache[DNS_CACHE];
static int g_dns_state;
static uint8_t g_dns_host;
static uint16_t g_dns_port, g_dns_lport, g_dns_id;
static uint8_t g_dns_mac[6];
static int g_dns_mac_ok;
static uint32_t g_dns_arp_n;
static uint64_t g_dns_at;
static uint64_t g_dns_page_phys;
static char g_dns_name[DNS_NAME_MAX + 1];
static uint8_t g_dns_q[DNS_QMAX];          // query lengkap (header + pertanyaan)
static uint32_t g_dns_qlen;
static char g_dns_last[96] = "belum pernah";
uint64_t g_dns_ok, g_dns_fail, g_dns_bad;
static int g_dns_probe;                    // P6-2: query milik pemantau (`pantau dns`)
static uint32_t g_dns_probe_tok;

static void dn_ip(uint8_t ip[4])
{
    ip[0] = g_net_ip[0];
    ip[1] = g_net_ip[1];
    ip[2] = g_net_ip[2];
    ip[3] = g_dns_host;
}

void dns_init(void)
{
    if (!g_e1000_rx_initialized || g_dns_page_phys != 0) {
        return;
    }
    g_dns_page_phys = pmm_alloc();
}

// Nama -> huruf kecil di out (NUL), dan bentuk label DNS di q (diakhiri 0).
// 0 = nama tidak sah. *qlen = panjang bentuk label.
static int dn_encode(const volatile uint8_t *s, uint32_t n, char *out, uint8_t *q, uint32_t *qlen)
{
    uint32_t lab = 0, lpos = 0;

    if (n == 0 || n > DNS_NAME_MAX) {
        return 0;
    }
    for (uint32_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '.') {
            if (i == lab) {
                return 0;               // label kosong (".." / awal / akhir titik)
            }
            if (i < n) {
                out[i] = '.';
            }
            q[lpos] = (uint8_t)(i - lab);
            lpos = i + 1;
            lab = i + 1;
            continue;
        }
        uint8_t c = s[i];
        if (c >= 'A' && c <= 'Z') {
            c = (uint8_t)(c - 'A' + 'a');
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
            return 0;
        }
        out[i] = (char)c;
        q[i + 1] = c;
    }
    out[n] = 0;
    q[n + 1] = 0;
    *qlen = n + 2;
    return 1;
}

// Kernel tidak punya strcmp; nama di cache selalu huruf kecil + NUL.
static int dn_eq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static dns_entry_t *dn_find(const char *name)
{
    for (int i = 0; i < DNS_CACHE; i++) {
        if (g_dns_cache[i].name[0] && dn_eq(g_dns_cache[i].name, name) &&
            g_dns_cache[i].expires > timer_ticks) {
            return &g_dns_cache[i];
        }
    }
    return 0;
}

static void dn_store(const char *name, const uint8_t ip[4], int neg, uint32_t ttl)
{
    dns_entry_t *e = 0;

    for (int i = 0; i < DNS_CACHE && !e; i++) {
        if (g_dns_cache[i].name[0] && dn_eq(g_dns_cache[i].name, name)) {
            e = &g_dns_cache[i];
        }
    }
    for (int i = 0; i < DNS_CACHE && !e; i++) {
        if (!g_dns_cache[i].name[0] || g_dns_cache[i].expires <= timer_ticks) {
            e = &g_dns_cache[i];
        }
    }
    if (!e) {
        e = &g_dns_cache[0];
        for (int i = 1; i < DNS_CACHE; i++) {
            if (g_dns_cache[i].expires < e->expires) {
                e = &g_dns_cache[i];
            }
        }
    }
    if (ttl < DNS_TTL_MIN) {
        ttl = DNS_TTL_MIN;
    }
    if (ttl > DNS_TTL_MAX) {
        ttl = DNS_TTL_MAX;
    }
    memcpy(e->name, name, strlen(name) + 1);
    memcpy(e->ip, ip, 4);
    e->neg = (uint8_t)neg;
    e->expires = timer_ticks + (uint64_t)ttl * 100;
}

// ok = server menjawab (A atau NXDOMAIN); a = ada jawaban A. P6-2: query milik
// pemantau dilaporkan ke monitor_dns_done tanpa baris log (pemantau mencatat
// perubahan NAIK/TURUN saja).
static void dn_done(int ok, int a, const char *what)
{
    g_dns_state = DNS_IDLE;
    if (ok) {
        g_dns_ok++;
    } else {
        g_dns_fail++;
    }
    ksnprintf(g_dns_last, sizeof(g_dns_last), "%s %s", g_dns_name, what);
    if (g_dns_probe) {
        g_dns_probe = 0;
        monitor_dns_done(g_dns_probe_tok, a, what);
        return;
    }
    kprintf("P3: DNS %s %s\r\n", g_dns_name, what);
}

static void dn_send_arp(void)
{
    uint8_t *p = (uint8_t *)(g_dns_page_phys + hhdm_offset);
    uint8_t ip[4];

    dn_ip(ip);
    e1000_tx_send(g_dns_page_phys, net_arp_request_build(p, ip));
}

static void dn_send_query(void)
{
    uint8_t *p = (uint8_t *)(g_dns_page_phys + hhdm_offset);
    uint8_t ip[4];

    dn_ip(ip);
    memcpy(p + 42, g_dns_q, g_dns_qlen);
    uint32_t len = net_udp_build(p, g_dns_mac, ip, g_dns_lport, g_dns_port, g_dns_qlen);

    if (!e1000_tx_send(g_dns_page_phys, len)) {
        dn_done(0, 0, "kirim gagal");
        return;
    }
    g_dns_state = DNS_SENT;
    g_dns_at = timer_ticks + DNS_TIMEOUT;
}

// Mulai query untuk nama (sudah dicek). 0 = OK; selain itu pesan di *why.
static int dn_start(const char *name, const uint8_t *qname, uint32_t qnlen, uint32_t host,
                    uint32_t port, const char **why)
{
    uint8_t r[4];

    if (g_dns_page_phys == 0) {
        *why = "tanpa NIC";
        return -1;
    }
    if (host < 1 || host > 254 || host == g_net_ip[3] || port < 1 || port > 65535) {
        *why = "oktet 1..254 (bukan IP sendiri), port 1..65535";
        return -1;
    }
    if (g_dns_state != DNS_IDLE) {
        *why = "query sebelumnya masih berjalan";
        return -1;
    }
    if (!entropy_get(r, sizeof(r))) {
        *why = "entropi belum cukup";
        return -1;
    }
    g_dns_id = (uint16_t)(r[0] << 8 | r[1]);
    g_dns_lport = (uint16_t)(49152 + (((uint32_t)r[2] << 8 | r[3]) % 16384));
    memset(g_dns_q, 0, sizeof(g_dns_q));
    g_dns_q[0] = (uint8_t)(g_dns_id >> 8);
    g_dns_q[1] = (uint8_t)g_dns_id;
    g_dns_q[2] = 0x01;             // RD
    g_dns_q[5] = 1;                // QDCOUNT
    memcpy(g_dns_q + 12, qname, qnlen);
    g_dns_q[12 + qnlen + 1] = 1;   // QTYPE A
    g_dns_q[12 + qnlen + 3] = 1;   // QCLASS IN
    g_dns_qlen = 12 + qnlen + 4;
    memcpy(g_dns_name, name, strlen(name) + 1);
    g_dns_host = (uint8_t)host;
    g_dns_port = (uint16_t)port;
    g_dns_mac_ok = 0;
    g_dns_arp_n = 0;
    g_dns_at = 0;
    g_dns_state = DNS_ARP;
    g_dns_probe = 0;
    return 0;
}

// P6-2: nama -> huruf kecil di out (>= DNS_NAME_MAX + 1 byte). 1 = sah.
int dns_name_check(const volatile uint8_t *s, uint32_t n, char *out)
{
    uint8_t q[DNS_NAME_MAX + 2];
    uint32_t qn;

    return dn_encode(s, n, out, q, &qn);
}

// P6-2: query untuk pemantau (tanpa cache; hasil ke monitor_dns_done(tok, ...),
// tanpa baris log). 0 = dimulai; -1 = tidak bisa sekarang (query lain berjalan,
// tanpa NIC, entropi, nama/server tidak sah).
int dns_probe_start(const char *name, uint32_t host, uint32_t port, uint32_t tok)
{
    char n[DNS_NAME_MAX + 1];
    uint8_t q[DNS_NAME_MAX + 2];
    uint32_t qn;
    const char *why;

    if (!dn_encode((const volatile uint8_t *)name, (uint32_t)strlen(name), n, q, &qn) ||
        dn_start(n, q, qn, host, port, &why) != 0) {
        return -1;
    }
    g_dns_probe = 1;
    g_dns_probe_tok = tok;
    return 0;
}

void dns_arp_seen(const volatile uint8_t *buf)
{
    uint8_t ip[4];
    int zero = 1;

    if (g_dns_state != DNS_ARP || g_dns_mac_ok) {
        return;
    }
    dn_ip(ip);
    for (int i = 0; i < 4; i++) {
        if (buf[28 + i] != ip[i]) {
            return;
        }
    }
    for (int i = 0; i < 6; i++) {
        zero &= buf[22 + i] == 0;
    }
    if ((buf[22] & 0x01) || zero) {
        return;
    }
    for (int i = 0; i < 6; i++) {
        g_dns_mac[i] = buf[22 + i];
    }
    g_dns_mac_ok = 1;
}

void dns_poll(void)
{
    if (g_dns_state == DNS_ARP) {
        if (g_dns_mac_ok) {
            dn_send_query();
        } else if (timer_ticks >= g_dns_at) {
            if (g_dns_arp_n >= DNS_ARP_TRIES) {
                dn_done(0, 0, "gagal: tanpa balasan ARP");
                return;
            }
            g_dns_arp_n++;
            g_dns_at = timer_ticks + DNS_ARP_EVERY;
            dn_send_arp();
        }
    } else if (g_dns_state == DNS_SENT && timer_ticks >= g_dns_at) {
        dn_done(0, 0, "gagal: tanpa balasan DNS (3 s)");
    }
}

int dns_wants(const volatile uint8_t *src_ip, uint16_t sport, uint16_t dport)
{
    uint8_t ip[4];

    if (g_dns_state != DNS_SENT || sport != g_dns_port || dport != g_dns_lport) {
        return 0;
    }
    dn_ip(ip);
    for (int i = 0; i < 4; i++) {
        if (src_ip[i] != ip[i]) {
            return 0;
        }
    }
    return 1;
}

static uint32_t dn_be16(const volatile uint8_t *p)
{
    return ((uint32_t)p[0] << 8) | p[1];
}

// Lompati nama mulai off (label biasa atau pointer kompresi yang mengakhiri
// nama). Return offset sesudah nama, 0 = rusak (melewati len / label > 63 /
// bit 01 atau 10 yang dicadangkan / nama > 255 byte).
static uint32_t dn_skip_name(const volatile uint8_t *p, uint32_t len, uint32_t off)
{
    uint32_t total = 0;

    while (off < len) {
        uint8_t c = p[off];
        if (c == 0) {
            return off + 1;
        }
        if ((c & 0xC0) == 0xC0) {
            return off + 2 <= len ? off + 2 : 0;
        }
        if (c & 0xC0) {
            return 0;
        }
        total += c + 1u;
        if (total > 255 || off + 1 + c > len) {
            return 0;
        }
        off += 1u + c;
    }
    return 0;
}

static void dn_bad(void)
{
    g_dns_bad++;
}

// Isi UDP balasan (checksum sah). Tidak cocok/rusak -> diabaikan, tetap menunggu.
void dns_rx(const volatile uint8_t *p, uint32_t len)
{
    char what[64];

    if (len < g_dns_qlen || dn_be16(p) != g_dns_id) {
        dn_bad();
        return;
    }
    uint32_t fl = dn_be16(p + 2);
    if (!(fl & 0x8000) || (fl & 0x7800) || (fl & 0x0200) || dn_be16(p + 4) != 1) {
        dn_bad();
        return;
    }
    for (uint32_t i = 12; i < g_dns_qlen; i++) {   // pertanyaan identik
        uint8_t a = p[i], b = g_dns_q[i];
        if (a >= 'A' && a <= 'Z') {
            a = (uint8_t)(a - 'A' + 'a');
        }
        if (a != b) {
            dn_bad();
            return;
        }
    }
    uint32_t rcode = fl & 0xF;
    static const uint8_t none[4] = { 0, 0, 0, 0 };

    if (rcode == 3) {
        dn_store(g_dns_name, none, 1, DNS_NEG_TTL);
        dn_done(1, 0, "= tidak ada (NXDOMAIN)");
        return;
    }
    if (rcode != 0) {
        ksnprintf(what, sizeof(what), "gagal: rcode %u", rcode);
        dn_done(0, 0, what);
        return;
    }
    uint32_t an = dn_be16(p + 6), off = g_dns_qlen;

    for (uint32_t k = 0; k < an && k < DNS_ANS_MAX; k++) {
        off = dn_skip_name(p, len, off);
        if (off == 0 || off + 10 > len) {
            dn_bad();
            return;
        }
        uint32_t type = dn_be16(p + off), cls = dn_be16(p + off + 2);
        uint32_t ttl = ((uint32_t)p[off + 4] << 24) | ((uint32_t)p[off + 5] << 16) |
                       ((uint32_t)p[off + 6] << 8) | p[off + 7];
        uint32_t rdlen = dn_be16(p + off + 8);
        off += 10;
        if (off + rdlen > len) {
            dn_bad();
            return;
        }
        if (type == 1 && cls == 1 && rdlen == 4) {
            uint8_t ip[4] = { p[off], p[off + 1], p[off + 2], p[off + 3] };
            dn_store(g_dns_name, ip, 0, ttl);
            ksnprintf(what, sizeof(what), "= %u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
            dn_done(1, 1, what);
            return;
        }
        off += rdlen;
    }
    dn_done(0, 0, "gagal: tanpa jawaban A");
}

static void dn_line(const dns_entry_t *e, const char *tail)
{
    char line[128];
    uint64_t left = e->expires > timer_ticks ? (e->expires - timer_ticks) / 100 : 0;

    if (e->neg) {
        ksnprintf(line, sizeof(line), "%s = tidak ada (NXDOMAIN) sisa=%lu s%s\n", e->name, left, tail);
    } else {
        ksnprintf(line, sizeof(line), "%s = %u.%u.%u.%u sisa=%lu s%s\n", e->name, e->ip[0], e->ip[1],
                  e->ip[2], e->ip[3], left, tail);
    }
    cmd_puts(line);
}

static void dn_status(void)
{
    char line[160];
    uint32_t n = 0;

    for (int i = 0; i < DNS_CACHE; i++) {
        n += g_dns_cache[i].name[0] && g_dns_cache[i].expires > timer_ticks;
    }
    ksnprintf(line, sizeof(line), "dns: %s terakhir=%s ok=%lu gagal=%lu diabaikan=%lu cache=%u/%u\n",
              g_dns_state == DNS_IDLE ? "diam" : "berjalan", g_dns_last, g_dns_ok, g_dns_fail,
              g_dns_bad, n, (unsigned)DNS_CACHE);
    cmd_puts(line);
    for (int i = 0; i < DNS_CACHE; i++) {
        if (g_dns_cache[i].name[0] && g_dns_cache[i].expires > timer_ticks) {
            dn_line(&g_dns_cache[i], "");
        }
    }
}

// `dns` (status + cache; peran ro boleh) dan `dns <nama> [oktet [port]]` (admin).
int dns_execute(const volatile uint8_t *cmd, uint32_t len)
{
    char name[DNS_NAME_MAX + 1], line[128];
    uint8_t q[DNS_NAME_MAX + 2];
    uint32_t qn = 0, i = 4, s, v[2] = { 1, 53 }, k = 0;
    const char *why = "";

    if (net_cmd_is(cmd, len, "dns")) {
        g_cmd_len = 0;
        dn_status();
        return 1;
    }
    if (len < 5 || !net_cmd_is(cmd, 4, "dns ")) {
        return 0;
    }
    g_cmd_len = 0;
    s = i;
    while (i < len && cmd[i] != ' ') {
        i++;
    }
    if (!dn_encode(cmd + s, i - s, name, q, &qn)) {
        cmd_puts("ERR: dns: nama 1..63 byte, label a-z 0-9 '-' dipisah titik\n");
        return 1;
    }
    while (i < len && k < 3) {
        while (i < len && cmd[i] == ' ') {
            i++;
        }
        if (i >= len) {
            break;
        }
        uint32_t st = i, n = 0;
        while (i < len && cmd[i] >= '0' && cmd[i] <= '9' && i - st < 6) {
            n = n * 10 + (uint32_t)(cmd[i] - '0');
            i++;
        }
        if (i == st || k >= 2 || (i < len && cmd[i] != ' ')) {
            k = 3;
            break;
        }
        v[k++] = n;
    }
    if (k > 2) {
        cmd_puts("ERR: dns: format: dns <nama> [oktet [port]]\n");
        return 1;
    }
    const dns_entry_t *e = dn_find(name);
    if (e) {
        dn_line(e, " (cache)");
        return 1;
    }
    if (dn_start(name, q, qn, v[0], v[1], &why) != 0) {
        ksnprintf(line, sizeof(line), "ERR: dns: %s\n", why);
        cmd_puts(line);
        return 1;
    }
    ksnprintf(line, sizeof(line), "OK: DNS %s ke %u.%u.%u.%u:%u dimulai, ulangi perintah (maks 6 s)\n",
              name, g_net_ip[0], g_net_ip[1], g_net_ip[2], v[0], v[1]);
    cmd_puts(line);
    return 1;
}

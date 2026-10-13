// F1.7: uji parser paket dan checksum (kernel/net.c) di host.
// net.c disertakan langsung (#include) supaya fungsi static bisa diuji.
// Frame dimasukkan ke net_rx_dispatch() dalam buffer seukuran frame persis
// (malloc), jadi pembacaan lewat batas frame tertangkap ASan. Frame yang
// dikirim ditangkap stub e1000_tx_send() dan diperiksa checksum-nya.

#include <ctype.h>
#include <stdlib.h>
#include "test.h"
#include "net.c"

// ---- stub driver/memori untuk net.c ----
uint8_t g_e1000_mac[6] = { 0x00, 0x0c, 0x29, 0x86, 0xef, 0x48 };
uint8_t *g_e1000_rx_ring_virt = 0;
uint64_t g_e1000_rx_buf_phys[E1000_RX_RING_SIZE];
int g_e1000_rx_initialized = 0;
uint32_t g_e1000_rx_next = 0;
uint64_t hhdm_offset = 0;   // "fisik" = alamat host

uint64_t pmm_alloc(void)
{
    return (uint64_t)(uintptr_t)aligned_alloc(4096, 4096);
}

void e1000_log_ip(volatile uint8_t *p)
{
    (void)p;
}

// entropy_get: byte tetap 0xA0.. (ISN yang bisa diperiksa), atau tolak
// bila g_entropy_ok = 0 (kolam belum siap).
static int g_entropy_ok = 1;
static int g_isn_set;      // 1: entropy_get memberi g_isn (big-endian), untuk uji putaran 2^32
static uint32_t g_isn;

int entropy_get(uint8_t *out, uint32_t len)
{
    if (!g_entropy_ok) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(0xA0 + i);
        if (g_isn_set && i < 4) {
            out[i] = (uint8_t)(g_isn >> (24 - 8 * i));
        }
    }
    return 1;
}

// D1: auth_tcp_login ada di auth.c (vektor HMAC diuji di test_auth). Stub:
// "login " + 64 'a' = OK admin, 64 'r' = OK read-only (D4), 70 byte "login ..."
// lain = hmac salah (5), lainnya format (2); g_login_off = 1 meniru kunci
// tidak dimuat. Nonce dicatat.
static uint8_t g_login_nonce[16];
static int g_login_off;

int auth_tcp_login(const uint8_t nonce[16], const uint8_t *line, uint32_t len,
                   int *role)
{
    memcpy(g_login_nonce, nonce, 16);
    if (g_login_off) {
        return 1;
    }
    if (len != 70 || memcmp(line, "login ", 6) != 0) {
        return 2;
    }
    int a = 1, r = 1;
    for (uint32_t i = 6; i < 70; i++) {
        a &= line[i] == 'a';
        r &= line[i] == 'r';
    }
    if (!a && !r) {
        return 5;
    }
    *role = a ? AUTH_ROLE_ADMIN : AUTH_ROLE_RO;
    return 0;
}

// D2: auth_tcp_cmd/auth_tcp_exec ada di auth.c (vektor HMAC di test_auth).
// Stub auth_tcp_cmd: format sama dengan aslinya; "hmac" = 64 kali digit
// ('0' + seq % 10) = OK, 64 hex lain = salah (5); g_login_off = nonaktif.
// Stub exec: "big" = 1300 byte pola, "reboot" = minta reboot, lainnya
// "<perintah>\n". auth_reboot hanya dihitung.
static uint64_t g_cmd_seq_seen;
static int g_reboots;
static int g_cmd_role_seen, g_exec_role_seen;   // D4: peran yang diteruskan net.c

int auth_tcp_cmd(const uint8_t nonce[16], int role, uint64_t seq,
                 const uint8_t *line, uint32_t len, uint32_t *cmd_len)
{
    (void)nonce;
    g_cmd_seq_seen = seq;
    g_cmd_role_seen = role;
    if (g_login_off) {
        return 1;
    }
    if (len < 66 || len > 129 || line[len - 65] != ' ') {
        return 2;
    }
    int ok = 1;
    for (uint32_t i = len - 64; i < len; i++) {
        if (!isxdigit(line[i])) {
            return 2;
        }
        ok &= line[i] == '0' + seq % 10;
    }
    if (!ok) {
        return 5;
    }
    *cmd_len = len - 65;
    return 0;
}

uint32_t auth_tcp_exec(int role, const uint8_t *cmd, uint32_t len, uint8_t *out,
                       uint32_t max, int *reboot)
{
    uint32_t n = 0;
    *reboot = 0;
    g_exec_role_seen = role;
    if (len == 3 && memcmp(cmd, "big", 3) == 0) {
        for (n = 0; n < 1300 && n < max; n++) {
            out[n] = (uint8_t)('a' + n % 26);
        }
        return n;
    }
    if (len == 6 && memcmp(cmd, "reboot", 6) == 0) {
        *reboot = 1;
    }
    memcpy(out, cmd, len);
    out[len] = '\n';
    return len + 1;
}

void auth_reboot(void)
{
    g_reboots++;
}

// D5: auth_cmd_allowed ada di auth.c (diuji di test_auth). Stub: ro tidak
// boleh pping/reboot/audit. audit_record dicatat (kejadian terakhir + jumlah).
int auth_cmd_allowed(int role, const uint8_t *cmd, uint32_t len)
{
    return role == AUTH_ROLE_ADMIN ||
           !((len == 5 && memcmp(cmd, "pping", 5) == 0) ||
             (len == 6 && memcmp(cmd, "reboot", 6) == 0) ||
             (len == 5 && memcmp(cmd, "audit", 5) == 0));
}

static struct {
    int n, ev, chan, role, code;
    uint8_t ip[4];
    uint16_t port;
    char cmd[200];
} g_au;

void audit_record(int ev, int chan, const volatile uint8_t *ip, uint16_t port,
                  int role, int code, const volatile uint8_t *cmd, uint32_t cmd_len)
{
    g_au.n++;
    g_au.ev = ev;
    g_au.chan = chan;
    g_au.role = role;
    g_au.code = code;
    for (int i = 0; i < 4; i++) {
        g_au.ip[i] = ip[i];
    }
    g_au.port = port;
    for (uint32_t i = 0; i < cmd_len && i < sizeof(g_au.cmd) - 1; i++) {
        g_au.cmd[i] = (char)cmd[i];
    }
    g_au.cmd[cmd_len < sizeof(g_au.cmd) - 1 ? cmd_len : sizeof(g_au.cmd) - 1] = 0;
}

int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name)
{
    uint32_t i = 0;
    while (name[i]) {
        if (i >= len || cmd[i] != (uint8_t)name[i]) {
            return 0;
        }
        i++;
    }
    return i == len;
}

// ktimer.c ikut dikompilasi (C3c); ktimer_selftest memanggil task_sleep.
void task_sleep(uint64_t ticks)
{
    timer_ticks += ticks;
}

void entropy_event(uint32_t src, uint64_t extra)
{
    (void)src;
    (void)extra;
}

static int g_cmd_calls;
static uint32_t g_cmd_ihl, g_cmd_udp_len;

void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len)
{
    (void)req;
    g_cmd_calls++;
    g_cmd_ihl = ihl;
    g_cmd_udp_len = udp_len;
}

// ---- checksum acuan (independen dari net.c) ----
static uint16_t ref_csum(const uint8_t *p, size_t n, uint64_t sum)
{
    for (size_t i = 0; i + 1 < n; i += 2) {
        sum += (uint64_t)(p[i] << 8 | p[i + 1]);
    }
    if (n & 1) {
        sum += (uint64_t)p[n - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t ref_l4_csum(const uint8_t *ip_hdr, uint8_t proto, const uint8_t *l4, size_t n)
{
    uint8_t ph[12];
    memcpy(ph, ip_hdr + 12, 8);   // src, dst
    ph[8] = 0;
    ph[9] = proto;
    ph[10] = (uint8_t)(n >> 8);
    ph[11] = (uint8_t)n;
    uint64_t sum = 0;
    for (int i = 0; i < 12; i += 2) {
        sum += (uint64_t)(ph[i] << 8 | ph[i + 1]);
    }
    return ref_csum(l4, n, sum);
}

static void fix_csums(uint8_t *f, size_t n);

// ---- tangkapan TX + invarian frame keluar ----
#define TX_MAX 8
static uint8_t g_tx[TX_MAX][2048];
static uint32_t g_tx_len[TX_MAX];
static int g_tx_n;
static int g_tx_bad;   // frame keluar yang melanggar invarian

int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    const uint8_t *p = (const uint8_t *)(uintptr_t)pkt_phys;
    int bad = frame_len < 60 || frame_len > 1514;

    if (!bad && p[12] == 0x08 && p[13] == 0x00) {
        uint32_t ihl = (uint32_t)(p[14] & 0xF) * 4;
        uint32_t tot = (uint32_t)(p[16] << 8 | p[17]);
        bad |= ihl != 20 || 14 + tot > frame_len || ref_csum(p + 14, 20, 0) != 0;
        if (!bad && (p[23] == 6 || p[23] == 17)) {
            bad |= ref_l4_csum(p + 14, p[23], p + 34, tot - 20) != 0;
        }
        if (!bad && p[23] == 1) {
            bad |= ref_csum(p + 34, tot - 20, 0) != 0;
        }
    }
    if (bad) {
        g_tx_bad++;
    }
    if (g_tx_n < TX_MAX) {
        memcpy(g_tx[g_tx_n], p, frame_len);
        g_tx_len[g_tx_n] = frame_len;
    }
    g_tx_n++;
    return 1;
}

// ---- pembangun frame ----
static const uint8_t PEER_MAC[6] = { 0x02, 0, 0, 0, 0, 0x01 };
static const uint8_t PEER_IP[4] = { 192, 168, 50, 1 };
static const uint8_t OUR_IP[4] = { 192, 168, 50, 200 };

static size_t eth_hdr(uint8_t *f, uint16_t type)
{
    memcpy(f, g_e1000_mac, 6);
    memcpy(f + 6, PEER_MAC, 6);
    f[12] = (uint8_t)(type >> 8);
    f[13] = (uint8_t)type;
    return 14;
}

static size_t mk_arp(uint8_t *f, const uint8_t *target_ip)
{
    memset(f, 0, 60);
    eth_hdr(f, 0x0806);
    static const uint8_t h[8] = { 0, 1, 8, 0, 6, 4, 0, 1 };
    memcpy(f + 14, h, 8);
    memcpy(f + 22, PEER_MAC, 6);
    memcpy(f + 28, PEER_IP, 4);
    memcpy(f + 38, target_ip, 4);
    return 60;
}

// IPv4 dengan opsi opsional (opt_words kata 32-bit), payload disalin apa adanya.
static size_t mk_ip(uint8_t *f, uint8_t proto, const uint8_t *pl, size_t n, int opt_words)
{
    eth_hdr(f, 0x0800);
    uint8_t *ip = f + 14;
    size_t ihl = 20 + 4 * (size_t)opt_words;
    memset(ip, 0, ihl);
    ip[0] = (uint8_t)(0x40 | (ihl / 4));
    ip[2] = (uint8_t)((ihl + n) >> 8);
    ip[3] = (uint8_t)(ihl + n);
    ip[4] = 0x12;
    ip[5] = 0x34;
    ip[6] = 0x40;   // DF
    ip[8] = 64;
    ip[9] = proto;
    memcpy(ip + 12, PEER_IP, 4);
    memcpy(ip + 16, OUR_IP, 4);
    for (size_t i = 20; i < ihl; i++) {
        ip[i] = 1;   // NOP
    }
    uint16_t c = ref_csum(ip, ihl, 0);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
    memcpy(ip + ihl, pl, n);
    return 14 + ihl + n;
}

static size_t mk_icmp_echo(uint8_t *f, const char *data, int opt_words)
{
    uint8_t m[1600] = { 8, 0, 0, 0, 0x12, 0x34, 0x00, 0x07 };
    size_t n = 8 + strlen(data);
    memcpy(m + 8, data, n - 8);
    uint16_t c = ref_csum(m, n, 0);
    m[2] = (uint8_t)(c >> 8);
    m[3] = (uint8_t)c;
    return mk_ip(f, 1, m, n, opt_words);
}

static size_t mk_udp(uint8_t *f, uint16_t sport, uint16_t dport, const char *data, int opt_words)
{
    uint8_t u[1600];
    size_t n = 8 + strlen(data);
    u[0] = (uint8_t)(sport >> 8);
    u[1] = (uint8_t)sport;
    u[2] = (uint8_t)(dport >> 8);
    u[3] = (uint8_t)dport;
    u[4] = (uint8_t)(n >> 8);
    u[5] = (uint8_t)n;
    u[6] = u[7] = 0;
    memcpy(u + 8, data, n - 8);
    size_t len = mk_ip(f, 17, u, n, opt_words);
    uint8_t *ip = f + 14;
    uint8_t *l4 = ip + (ip[0] & 0xF) * 4;
    uint16_t c = ref_l4_csum(ip, 17, l4, n);
    if (c == 0) {
        c = 0xFFFF;
    }
    l4[6] = (uint8_t)(c >> 8);
    l4[7] = (uint8_t)c;
    return len;
}

#define F_FIN 0x01
#define F_SYN 0x02
#define F_RST 0x04
#define F_ACK 0x10

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static size_t mk_tcp(uint8_t *f, uint16_t sport, uint16_t dport, uint32_t seq,
                     uint32_t ack, uint8_t flags, const char *data)
{
    uint8_t t[512];
    size_t n = 20 + strlen(data);
    memset(t, 0, 20);
    t[0] = (uint8_t)(sport >> 8);
    t[1] = (uint8_t)sport;
    t[2] = (uint8_t)(dport >> 8);
    t[3] = (uint8_t)dport;
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = 0x50;
    t[13] = flags;
    t[14] = 0x10;   // window 4096
    memcpy(t + 20, data, n - 20);
    size_t len = mk_ip(f, 6, t, n, 0);
    uint16_t c = ref_l4_csum(f + 14, 6, f + 34, n);
    f[34 + 16] = (uint8_t)(c >> 8);
    f[34 + 17] = (uint8_t)c;
    return len;
}

// Kirim frame ke parser dalam buffer seukuran persis. timer_ticks dimajukan
// satu detik supaya batas laju tidak ikut campur.
static void rx(const uint8_t *f, size_t len)
{
    uint8_t *b = malloc(len ? len : 1);
    memcpy(b, f, len);
    timer_ticks += 100;
    g_tx_n = 0;
    net_rx_dispatch(b, (uint32_t)len);
    free(b);
}

// ---- uji ----
static void test_checksum(void)
{
    // RFC 1071 bagian 3: jumlah 0xddf2, checksum = ~0xddf2.
    uint8_t v[8] = { 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    CHECK(net_checksum16(v, 8) == (uint16_t)~0xddf2);
    CHECK(net_checksum16(v, 0) == 0xFFFF);

    // Acak: semua panjang 0..1500 (ganjil dan genap), dibandingkan acuan.
    static uint8_t buf[1500];
    srand(1);
    int ok = 1;
    for (size_t n = 0; n <= sizeof(buf); n++) {
        for (size_t i = 0; i < n; i++) {
            buf[i] = (uint8_t)rand();
        }
        if (net_checksum16(buf, (uint32_t)n) != ref_csum(buf, n, 0)) {
            ok = 0;
        }
    }
    CHECK(ok);

    // Semua 0xFF (jumlah carry maksimum).
    memset(buf, 0xFF, sizeof(buf));
    CHECK(net_checksum16(buf, sizeof(buf)) == ref_csum(buf, sizeof(buf), 0));

    // UDP/TCP pseudo-header: segmen yang sudah berisi checksum valid -> 0.
    uint8_t f[600];
    mk_udp(f, 5000, 7777, "halo bmahOS", 0);
    CHECK(net_udp_checksum(f + 26, f + 30, f + 34, 8 + 11) == 0);
    f[34 + 8] ^= 1;
    CHECK(net_udp_checksum(f + 26, f + 30, f + 34, 8 + 11) != 0);
    mk_tcp(f, 4000, 80, 1, 0, F_SYN, "x");   // panjang ganjil
    CHECK(net_tcp_checksum(f + 26, f + 30, f + 34, 21) == 0);
}

static void test_arp(void)
{
    uint8_t f[64];
    rx(f, mk_arp(f, OUR_IP));
    CHECK(g_tx_n == 1);
    CHECK(g_tx_len[0] == 60);
    uint8_t *r = g_tx[0];
    CHECK(memcmp(r, PEER_MAC, 6) == 0 && memcmp(r + 6, g_e1000_mac, 6) == 0);
    CHECK(r[12] == 0x08 && r[13] == 0x06 && r[20] == 0 && r[21] == 2);
    CHECK(memcmp(r + 22, g_e1000_mac, 6) == 0 && memcmp(r + 28, OUR_IP, 4) == 0);
    CHECK(memcmp(r + 32, PEER_MAC, 6) == 0 && memcmp(r + 38, PEER_IP, 4) == 0);

    static const uint8_t other[4] = { 192, 168, 50, 7 };
    rx(f, mk_arp(f, other));
    CHECK(g_tx_n == 0);

    // ARP reply (oper 2) dan ARP 41 byte: tidak dibalas.
    mk_arp(f, OUR_IP);
    f[21] = 2;
    rx(f, 60);
    CHECK(g_tx_n == 0);
    mk_arp(f, OUR_IP);
    rx(f, 41);
    CHECK(g_tx_n == 0);
}

static void test_icmp(void)
{
    uint8_t f[600];
    for (int opt = 0; opt <= 2; opt++) {
        size_t n = mk_icmp_echo(f, "abcdefghijklmnopqrstuvwxyz", opt);
        size_t ihl = 20 + 4 * (size_t)opt;
        rx(f, n);
        CHECK(g_tx_n == 1);
        uint8_t *r = g_tx[0];
        CHECK(g_tx_len[0] == 60 || g_tx_len[0] == 14 + 20 + 8 + 26);
        CHECK(memcmp(r + 26, OUR_IP, 4) == 0 && memcmp(r + 30, PEER_IP, 4) == 0);
        CHECK(r[34] == 0);   // echo reply
        CHECK(memcmp(r + 38, f + 14 + ihl + 4, 4 + 26) == 0);   // id, seq, data
    }
    CHECK(g_tx_bad == 0);

    // Checksum IP salah, ICMP salah, fragmen, IP tujuan lain: tidak dibalas.
    size_t n = mk_icmp_echo(f, "x", 0);
    f[24] ^= 0x40;
    rx(f, n);
    CHECK(g_tx_n == 0);
    n = mk_icmp_echo(f, "x", 0);
    f[34 + 8] ^= 1;
    rx(f, n);
    CHECK(g_tx_n == 0);
    n = mk_icmp_echo(f, "x", 0);
    f[14 + 7] = 8;   // fragment offset != 0
    fix_csums(f, n);
    rx(f, n);
    CHECK(g_tx_n == 0);
    n = mk_icmp_echo(f, "x", 0);
    f[30 + 3] = 201;
    rx(f, n);
    CHECK(g_tx_n == 0);
}

static void test_udp(void)
{
    uint8_t f[600];
    size_t n = mk_udp(f, 5000, 7777, "echo ini", 0);
    rx(f, n);
    CHECK(g_tx_n == 1);
    uint8_t *r = g_tx[0];
    CHECK(r[34] == 7777 >> 8 && r[35] == (7777 & 0xFF));
    CHECK(r[36] == 5000 >> 8 && r[37] == (5000 & 0xFF));
    CHECK(memcmp(r + 42, "echo ini", 8) == 0);
    CHECK(g_tx_bad == 0);

    // Checksum 0 = tidak dipakai (RFC 768): tetap diterima.
    n = mk_udp(f, 5000, 7777, "nol", 0);
    f[40] = f[41] = 0;
    rx(f, n);
    CHECK(g_tx_n == 1);

    // Checksum salah: dibuang dan dihitung.
    uint64_t bad0 = g_net_udp_badsum;
    n = mk_udp(f, 5000, 7777, "rusak", 0);
    f[42] ^= 1;
    rx(f, n);
    CHECK(g_tx_n == 0);
    CHECK(g_net_udp_badsum == bad0 + 1);

    // Port lain: diam. Port 7778: ke net_cmd_handle dengan ihl/udp_len benar.
    rx(f, mk_udp(f, 5000, 9999, "x", 0));
    CHECK(g_tx_n == 0);
    g_cmd_calls = 0;
    rx(f, mk_udp(f, 5000, 7778, "uptime", 1));
    CHECK(g_cmd_calls == 1 && g_cmd_ihl == 24 && g_cmd_udp_len == 8 + 6);

    // Panjang UDP melebihi panjang payload IP: dibuang.
    n = mk_udp(f, 5000, 7777, "abc", 0);
    f[38] = 0;
    f[39] = 200;
    rx(f, n);
    CHECK(g_tx_n == 0);
}

// Batas ukuran: ICMP < 8 byte dan IHL < 20 dibuang; balasan terbesar
// (UDP 1472, ICMP 1480) masih dikirim, satu byte lebih dibuang.
static void test_limits(void)
{
    static uint8_t f[1600];
    static char big[1600];

    for (size_t len = 0; len < 8; len++) {
        size_t n = mk_icmp_echo(f, "", 0);
        f[16] = 0;
        f[17] = (uint8_t)(20 + len);
        fix_csums(f, n);
        rx(f, 14 + 20 + len);
        CHECK(g_tx_n == 0);
    }

    // IHL 16 byte: "header TCP" mulai di IP tujuan (port 0xC0A8 -> 0x32C8);
    // ack dipilih supaya data offset = 5 dan flag = SYN di posisi itu.
    // Tanpa cek IHL frame ini dibalas RST.
    size_t n = mk_tcp(f, 4000, 80, 1, 0x50020000, F_SYN, "");
    f[14] = 0x44;
    fix_csums(f, n);
    rx(f, n);
    CHECK(g_tx_n == 0);

    memset(big, 'u', sizeof(big));
    big[1464] = 0;
    rx(f, mk_udp(f, 5000, 7777, big, 0));
    CHECK(g_tx_n == 1 && g_tx_len[0] == 14 + 20 + 1472);
    big[1464] = 'u';
    big[1465] = 0;
    rx(f, mk_udp(f, 5000, 7777, big, 0));
    CHECK(g_tx_n == 0);

    big[1465] = 'u';
    big[1472] = 0;
    rx(f, mk_icmp_echo(f, big, 0));
    CHECK(g_tx_n == 1 && g_tx_len[0] == 14 + 20 + 1480);
    big[1472] = 'u';
    big[1473] = 0;
    rx(f, mk_icmp_echo(f, big, 0));
    CHECK(g_tx_n == 0);
    CHECK(g_tx_bad == 0);
}

// Semua slot TCB kosong, timer retransmisinya dilepas dari senarai ktimer.
static void tcp_reset(void)
{
    for (int k = 0; k < TCP_MAX_CONN; k++) {
        ktimer_cancel(&g_tcp_rtx_timer[k]);
    }
    memset(g_tcbs, 0, sizeof(g_tcbs));
}

static void test_tcp(void)
{
    uint8_t f[600];
    tcp_reset();

    // Port tertutup: SYN -> RST|ACK, ack = seq + 1.
    rx(f, mk_tcp(f, 4000, 80, 1000, 0, F_SYN, ""));
    CHECK(g_tx_n == 1);
    uint8_t *r = g_tx[0] + 34;
    CHECK(r[13] == (F_RST | F_ACK) && get32(r + 4) == 0 && get32(r + 8) == 1001);
    CHECK(r[0] == 0 && r[1] == 80 && r[2] == 4000 >> 8 && r[3] == (4000 & 0xFF));

    // Segmen ber-ACK ke port tertutup: RST dengan seq = ack mereka.
    rx(f, mk_tcp(f, 4000, 80, 1, 5555, F_ACK, "data"));
    CHECK(g_tx_n == 1 && g_tx[0][34 + 13] == F_RST && get32(g_tx[0] + 38) == 5555);

    // RST tidak pernah dibalas.
    rx(f, mk_tcp(f, 4000, 80, 1, 0, F_RST, ""));
    CHECK(g_tx_n == 0);

    // Port 7: handshake, data, FIN.
    rx(f, mk_tcp(f, 4001, 7, 7000, 0, F_SYN, ""));
    CHECK(g_tx_n == 1);
    r = g_tx[0] + 34;
    CHECK(r[13] == (F_SYN | F_ACK) && get32(r + 8) == 7001);
    CHECK((r[12] >> 4) == 6 && r[20] == 2 && r[21] == 4);   // opsi MSS
    uint32_t iss = get32(r + 4);
    CHECK(iss == 0xA0A1A2A3);
    CHECK(g_tcbs[0].state == TCP_SYN_RCVD);

    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, ""));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_ESTABLISHED);

    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, "hello"));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7006);

    // Duplikat (seq lama): ACK posisi kita, rcv_nxt tetap.
    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, "hello"));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7006);

    // C5a: SYN kedua dari IP yang sama memakai slot lain; ketiga ditolak
    // (maks TCP_MAX_PER_IP per IP) dengan RST, bukan "sibuk".
    uint64_t busy0 = g_tcp_busy, full0 = g_tcp_src_full;
    rx(f, mk_tcp(f, 4002, 7, 1, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && g_tx[0][34 + 13] == (F_SYN | F_ACK) && g_tcbs[1].state == TCP_SYN_RCVD);
    rx(f, mk_tcp(f, 4003, 7, 1, 0, F_SYN, ""));
    CHECK(g_tcp_src_full == full0 + 1 && g_tcp_busy == busy0 && g_tx_n == 1 &&
          (g_tx[0][34 + 13] & F_RST));

    rx(f, mk_tcp(f, 4001, 7, 7006, iss + 1, F_ACK | F_FIN, ""));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7007);
    CHECK(g_tcbs[0].state == TCP_CLOSE_WAIT);
    CHECK(g_tx_bad == 0);

    // Entropi belum cukup: SYN port 7 dibuang tanpa balasan (bukan RST),
    // TCB tetap CLOSED; port tertutup tetap dibalas RST.
    tcp_reset();
    g_entropy_ok = 0;
    uint64_t ne0 = g_tcp_noentropy;
    rx(f, mk_tcp(f, 4003, 7, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_CLOSED && g_tcp_noentropy == ne0 + 1);
    rx(f, mk_tcp(f, 4003, 80, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && (g_tx[0][34 + 13] & F_RST));
    g_entropy_ok = 1;

    // Checksum TCP salah: dibuang dan dihitung.
    uint64_t bad0 = g_tcp_badsum;
    size_t n = mk_tcp(f, 4000, 80, 1, 0, F_SYN, "");
    f[34 + 4] ^= 1;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_tcp_badsum == bad0 + 1);

    // Data offset < 5 atau melebihi segmen (checksum dibetulkan): dibuang.
    n = mk_tcp(f, 4000, 80, 1, 0, F_SYN, "");
    f[34 + 12] = 0x40;
    fix_csums(f, n);
    rx(f, n);
    CHECK(g_tx_n == 0);
    n = mk_tcp(f, 4000, 80, 1, 0, F_SYN, "");
    f[34 + 12] = 0xF0;
    fix_csums(f, n);
    rx(f, n);
    CHECK(g_tx_n == 0);
    tcp_reset();
}

// Hitung ulang checksum IP dan L4 setelah frame diubah, supaya frame lolos
// pemeriksaan checksum dan sampai ke parser yang lebih dalam.
static void fix_csums(uint8_t *f, size_t n)
{
    if (n < 34 || f[12] != 0x08 || f[13] != 0x00) {
        return;
    }
    uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0xF) * 4;
    if (ihl < 12 || 14 + ihl > n) {   // < 20 juga, supaya IHL salah teruji
        return;
    }
    ip[10] = ip[11] = 0;
    uint16_t c = ref_csum(ip, ihl, 0);
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;

    size_t tot = (size_t)(ip[2] << 8 | ip[3]);
    if (tot < ihl || 14 + tot > n) {
        return;
    }
    uint8_t *l4 = ip + ihl;
    size_t len = tot - ihl;
    size_t off;
    if (ip[9] == 1 && len >= 4) {
        off = 2;
        l4[off] = l4[off + 1] = 0;
        c = ref_csum(l4, len, 0);
    } else if (ip[9] == 17 && len >= 8) {
        size_t ul = (size_t)(l4[4] << 8 | l4[5]);
        if (ul < 8 || ul > len) {
            return;
        }
        off = 6;
        l4[off] = l4[off + 1] = 0;
        c = ref_l4_csum(ip, 17, l4, ul);
    } else if (ip[9] == 6 && len >= 18) {
        off = 16;
        l4[off] = l4[off + 1] = 0;
        c = ref_l4_csum(ip, 6, l4, len);
    } else {
        return;
    }
    l4[off] = (uint8_t)(c >> 8);
    l4[off + 1] = (uint8_t)c;
}

// Frame contoh untuk dipotong dan diacak.
#define NTPL 9
static uint8_t g_tpl[NTPL][600];
static size_t g_tpl_len[NTPL];

static void build_templates(void)
{
    g_tpl_len[0] = mk_arp(g_tpl[0], OUR_IP);
    g_tpl_len[1] = mk_icmp_echo(g_tpl[1], "ping ping ping", 0);
    g_tpl_len[2] = mk_icmp_echo(g_tpl[2], "opsi", 3);
    g_tpl_len[3] = mk_udp(g_tpl[3], 5000, 7777, "echo echo", 0);
    g_tpl_len[4] = mk_udp(g_tpl[4], 5000, 7778, "uptime", 2);
    g_tpl_len[5] = mk_tcp(g_tpl[5], 4000, 7, 1, 0, F_SYN, "");
    g_tpl_len[6] = mk_tcp(g_tpl[6], 4000, 80, 1, 9, F_ACK | F_FIN, "isi segmen");
    g_tpl_len[7] = mk_udp(g_tpl[7], 5000, 7777, "", 0);
    g_tpl_len[8] = mk_ip(g_tpl[8], 99, (const uint8_t *)"proto lain", 10, 0);
}

// Semua frame contoh dipotong di setiap panjang 0..penuh. Tidak boleh ada
// baca di luar buffer (ASan) dan frame terpotong tidak boleh dibalas.
static void test_truncation(void)
{
    int ok = 1;
    for (int t = 0; t < NTPL; t++) {
        for (size_t n = 0; n < g_tpl_len[t]; n++) {
            tcp_reset();
            rx(g_tpl[t], n);
            // ARP dibalas asal >= 42 byte (frame minimum Ethernet 60 diisi NIC).
            if (g_tx_n != 0 && !(t == 0 && n >= 42)) {
                ok = 0;
                fprintf(stderr, "GAGAL: contoh %d terpotong %zu byte tetap dibalas\n", t, n);
            }
        }
    }
    CHECK(ok);
    CHECK(g_tx_bad == 0);
}

// Acak: ubah 1-4 byte (condong ke header), kadang potong frame. Pada 3 dari 4
// iterasi checksum dibetulkan dulu supaya parser lapisan atas ikut teruji.
static int g_fuzz_fixed, g_fuzz_tx;

static void test_fuzz(void)
{
    uint32_t s = 12345;
    uint8_t f[600];
    for (int it = 0; it < 200000; it++) {
        int t = it % NTPL;
        size_t n = g_tpl_len[t];
        memcpy(f, g_tpl[t], n);
        s = s * 1103515245u + 12345u;
        int k = 1 + (int)((s >> 16) % 4);
        for (int j = 0; j < k; j++) {
            s = s * 1103515245u + 12345u;
            size_t pos = (s >> 8) % (j == 0 ? (n < 60 ? n : 60) : n);
            s = s * 1103515245u + 12345u;
            f[pos] = (uint8_t)(s >> 16);
        }
        s = s * 1103515245u + 12345u;
        if ((s >> 16) % 8 == 0) {
            n = (s >> 4) % (n + 1);
        }
        if ((s >> 20) % 4 != 0) {
            fix_csums(f, n);
            g_fuzz_fixed++;
        }
        rx(f, n);
        g_fuzz_tx += g_tx_n;
        if ((it & 1023) == 0) {
            tcp_reset();
        }
    }
    CHECK(g_tx_bad == 0);
    // Pastikan pengacakan tidak semuanya berakhir dibuang di depan.
    printf("net fuzz: %d frame, %d checksum dibetulkan, %d balasan\n",
           200000, g_fuzz_fixed, g_fuzz_tx);
    CHECK(g_fuzz_tx > 20000);
}

// ---- C3b: kirim data TCP ----

static uint16_t g_wport = 7;

// Segmen TCP dari peer dengan data biner dan jendela pilihan.
static size_t mk_tcp_w(uint8_t *f, uint32_t seq, uint32_t ack, uint8_t flags,
                       const uint8_t *data, size_t dlen, uint16_t wnd)
{
    uint8_t t[1600];
    memset(t, 0, 20);
    t[0] = 4500 >> 8;
    t[1] = 4500 & 0xFF;
    t[2] = (uint8_t)(g_wport >> 8);   // D1: port tujuan pilihan (default 7)
    t[3] = (uint8_t)g_wport;
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = 0x50;
    t[13] = flags;
    t[14] = (uint8_t)(wnd >> 8);
    t[15] = (uint8_t)wnd;
    if (dlen > 0) {
        memcpy(t + 20, data, dlen);
    }
    size_t len = mk_ip(f, 6, t, 20 + dlen, 0);
    uint16_t c = ref_l4_csum(f + 14, 6, f + 34, 20 + dlen);
    f[34 + 16] = (uint8_t)(c >> 8);
    f[34 + 17] = (uint8_t)c;
    return len;
}

// Isi segmen TCP yang kita kirim: seq, ack, flags, jendela, data.
struct seg {
    uint32_t seq, ack, len;
    uint8_t flags;
    uint16_t wnd;
    const uint8_t *data;
};

static struct seg tx_seg(int i)
{
    const uint8_t *p = g_tx[i];
    struct seg s;
    uint32_t tot = (uint32_t)(p[16] << 8 | p[17]);
    uint32_t hl = (uint32_t)(p[34 + 12] >> 4) * 4;
    s.seq = get32(p + 38);
    s.ack = get32(p + 42);
    s.flags = p[47];
    s.wnd = (uint16_t)(p[48] << 8 | p[49]);
    s.len = tot - 20 - hl;
    s.data = p + 34 + hl;
    return s;
}

static uint32_t g_pseq;   // nomor urut peer berikutnya
static uint32_t g_iss;

// Handshake dengan ISN kita dan ISN peer pilihan (dekat putaran 2^32).
static void tcp_open(uint32_t our_isn, uint32_t peer_isn, uint16_t wnd)
{
    uint8_t f[200];
    tcp_reset();
    g_isn_set = 1;
    g_isn = our_isn;
    rx(f, mk_tcp_w(f, peer_isn, 0, F_SYN, 0, 0, wnd));
    g_isn_set = 0;
    g_iss = our_isn;
    g_pseq = peer_isn + 1;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, wnd));
}

static void test_tcp_send(void)
{
    static uint8_t f[1700];
    uint8_t big[1200];
    struct seg s;

    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 13 + 5);
    }

    // ISN kita dan peer melewati 2^32 di tengah uji.
    tcp_open(0xFFFFFFFCu, 0xFFFFFFFAu, 4096);
    CHECK(g_tcbs[0].state == TCP_ESTABLISHED && g_tcbs[0].snd_una == 0xFFFFFFFDu);

    // Data -> dikirim balik dalam satu segmen PSH|ACK yang juga meng-ACK.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK | 0x08, (const uint8_t *)"hello", 5, 4096));
    g_pseq += 5;
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.seq == g_iss + 1 && s.ack == g_pseq && s.flags == (0x08 | F_ACK));
    CHECK(s.len == 5 && memcmp(s.data, "hello", 5) == 0 && s.wnd == TCP_BUF_SIZE - 5);
    CHECK(g_pseq == 0);   // nomor urut peer sudah berputar (0xFFFFFFFB + 5)

    // Stop-and-wait: data baru selagi "hello" belum di-ACK -> ACK saja.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"abc", 3, 4096));
    g_pseq += 3;
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.ack == g_pseq && s.wnd == TCP_BUF_SIZE - 8);

    // ACK melewati snd_nxt: diabaikan (dibalas ACK), buffer tetap.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 100, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0 && g_tcbs[0].snd_una == g_iss + 1 && g_tcbs[0].buf_count == 8);

    // ACK untuk "hello" (snd_una melewati 2^32) -> "abc" dikirim.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 6, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.seq == g_iss + 6 && s.len == 3 && memcmp(s.data, "abc", 3) == 0);
    CHECK(g_tcbs[0].snd_una == g_iss + 6 && g_tcbs[0].snd_una < 0x10 && g_tcbs[0].buf_count == 3);

    // ACK lama: tidak mengubah apa pun (juga jendela peer tidak diperbarui).
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 7));
    CHECK(g_tx_n == 0 && g_tcbs[0].snd_una == g_iss + 6 && g_tcbs[0].snd_wnd == 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 9, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].buf_count == 0 && g_tcbs[0].snd_una == g_tcbs[0].snd_nxt);

    // Segmen pertama dibatasi MSS; sisanya dikirim setelah ACK.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 9, F_ACK, big, 600, 4096));
    g_pseq += 600;
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == TCP_MSS && memcmp(s.data, big, TCP_MSS) == 0);
    uint32_t una = g_iss + 9 + TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 64 && memcmp(s.data, big + TCP_MSS, 64) == 0);
    una += 64;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));

    // Jendela peer 100: segmen <= 100. Jendela peer 0: tidak ada data,
    // lalu pembaruan jendela dari peer -> data dikirim.
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, big, 300, 100));
    g_pseq += 300;
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 100);
    una += 100;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 0));
    CHECK(g_tx_n == 0 && g_tcbs[0].snd_wnd == 0 && g_tcbs[0].buf_count == 200);
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 200 && memcmp(s.data, big + 100, 200) == 0);
    una += 200;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    CHECK(g_tcbs[0].buf_count == 0);

    // Buffer penuh: jendela peer 0 supaya tidak ada yang terkirim, lalu
    // 1200 byte -> hanya 1024 diterima, ACK dengan jendela 0.
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, big, 1200, 0));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.wnd == 0 && s.ack == g_pseq + TCP_BUF_SIZE);
    CHECK(g_tcbs[0].buf_count == TCP_BUF_SIZE);
    g_pseq += TCP_BUF_SIZE;
    // Segmen saat jendela 0: dipotong habis, tetap di-ACK (jendela 0).
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, big, 10, 0));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.wnd == 0 && s.ack == g_pseq);
    // Peer membuka jendela: 536 byte terkirim, membawa jendela kita yang masih 0.
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == TCP_MSS && s.wnd == 0);
    // ACK membebaskan 536 byte: sisa 488 byte dikirim dengan jendela baru 536.
    una += TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == TCP_BUF_SIZE - TCP_MSS && s.wnd == TCP_MSS);
    CHECK(memcmp(s.data, big + TCP_MSS, TCP_BUF_SIZE - TCP_MSS) == 0);
    una += TCP_BUF_SIZE - TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 0));
    CHECK(g_tcbs[0].buf_count == 0);

    // Jendela kita kembali >= MSS tetapi tidak ada yang bisa dikirim (jendela
    // peer 0): pembaruan jendela tetap dikirim lewat ACK.
    tcp_reset();
    tcp_open(1000, 2000, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, big, 1024, 0));
    g_pseq += 1024;
    CHECK(g_tcbs[0].buf_count == 1024 && g_tcbs[0].adv_wnd == 0);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 600));   // kirim 536
    una = g_iss + 1 + TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 0));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.wnd == TCP_MSS);
    tcp_reset();
}

// Aliran acak 20000 byte lewat echo: potongan acak sebatas jendela kita,
// ACK untuk semua data yang diterima. Hasil echo harus sama persis.
static void test_tcp_stream(void)
{
    static uint8_t f[1700], src[20000], got[20000];
    size_t sent = 0, recvd = 0;
    uint32_t una;
    int guard = 0;

    for (size_t i = 0; i < sizeof(src); i++) {
        src[i] = (uint8_t)rand();
    }
    tcp_open(0xFFFFFF00u, 0x7FFFFFF0u, 4096);
    una = g_iss + 1;

    while (recvd < sizeof(src) && guard++ < 100000) {
        size_t room = TCP_BUF_SIZE - g_tcbs[0].buf_count;
        size_t n = (size_t)(rand() % 700);
        if (n > room) {
            n = room;
        }
        if (n > sizeof(src) - sent) {
            n = sizeof(src) - sent;
        }
        rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, src + sent, n, 4096));
        sent += n;
        g_pseq += (uint32_t)n;
        for (int i = 0; i < g_tx_n && i < TX_MAX; i++) {
            struct seg s = tx_seg(i);
            if (s.len > 0 && s.seq == una + (uint32_t)0 && recvd + s.len <= sizeof(got)) {
                memcpy(got + recvd, s.data, s.len);
                recvd += s.len;
                una += s.len;
            }
        }
    }
    printf("net tcp: aliran %zu byte, kembali %zu byte, %d putaran\n", sent, recvd, guard);
    CHECK(recvd == sizeof(src) && memcmp(got, src, sizeof(src)) == 0);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- C3c: retransmisi ----

// Majukan satu tick lalu jalankan timer dan net_tcp_tick seperti loop net
// task. Return jumlah frame yang dikirim pada tick itu.
static int step(void)
{
    g_tx_n = 0;
    timer_ticks++;
    ktimer_run();
    net_tcp_tick();
    return g_tx_n;
}

// Jalankan sampai ada frame keluar (maks `max` tick). Return jumlah tick.
static uint32_t run_until_tx(uint32_t max)
{
    for (uint32_t i = 1; i <= max; i++) {
        if (step() > 0) {
            return i;
        }
    }
    return 0;
}

static void test_tcp_retx(void)
{
    static uint8_t f[1700];
    uint8_t big[600];
    struct seg s;
    uint64_t retx0 = g_tcp_retx, give0 = g_tcp_retx_giveup, to0 = g_tcp_timeouts;

    for (size_t i = 0; i < sizeof(big); i++) {
        big[i] = (uint8_t)(i * 31 + 7);
    }

    // SYN-ACK tidak di-ACK: dikirim ulang setelah 100 lalu 200 tick, sama persis.
    tcp_reset();
    g_isn_set = 1;
    g_isn = 0xFFFFFFFFu;
    rx(f, mk_tcp_w(f, 500, 0, F_SYN, 0, 0, 4096));
    g_isn_set = 0;
    CHECK(g_tx_n == 1 && ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(run_until_tx(1000) == 100);
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (F_SYN | F_ACK) && s.seq == 0xFFFFFFFFu && s.ack == 501);
    CHECK(run_until_tx(1000) == 200 && tx_seg(0).flags == (F_SYN | F_ACK));
    CHECK(g_tcp_retx == retx0 + 2);

    // ACK handshake: timer berhenti, backoff kembali ke awal.
    g_iss = 0xFFFFFFFFu;
    g_pseq = 501;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 4096));
    CHECK(g_tcbs[0].state == TCP_ESTABLISHED && !ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(g_tcbs[0].rto == TCP_RTO_INIT && g_tcbs[0].retries == 0);
    // Diam tanpa data belum di-ACK: timeout menganggur biasa (C3d: FIN
    // setelah 3000 tick, bukan RST).
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1 && tx_seg(0).flags == (F_FIN | F_ACK));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_1 && g_tcp_timeouts == to0 + 1);

    // Data tidak di-ACK: kirim ulang setelah 100, 200, 400, 800, 800 tick (isi
    // dan seq sama, melewati 2^32), lalu RST setelah 800 tick lagi. Total
    // 3100 tick > timeout menganggur 3000: timeout itu tidak berlaku.
    tcp_open(0xFFFFFFF0u, 9000, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, big, 20, 4096));
    g_pseq += 20;
    CHECK(g_tx_n == 1 && tx_seg(0).len == 20);
    static const uint32_t gaps[5] = { 100, 200, 400, 800, 800 };
    int same = 1;
    for (int i = 0; i < 5; i++) {
        uint32_t g = run_until_tx(2000);
        s = tx_seg(0);
        same &= g == gaps[i] && g_tx_n == 1 && s.seq == g_iss + 1 && s.ack == g_pseq &&
                s.len == 20 && memcmp(s.data, big, 20) == 0 && s.flags == (0x08 | F_ACK);
    }
    CHECK(same);
    CHECK(run_until_tx(2000) == 800);
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (F_RST | F_ACK) && s.seq == g_iss + 21);
    CHECK(g_tcbs[0].state == TCP_CLOSED && !ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(g_tcp_retx_giveup == give0 + 1 && g_tcp_timeouts == to0 + 1);
    CHECK(run_until_tx(5000) == 0);

    // ACK sebagian setelah 2 kirim ulang: backoff kembali ke 100 tick, yang
    // dikirim ulang hanya sisa yang belum di-ACK.
    tcp_open(1000, 2000, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, big, 600, 4096));
    g_pseq += 600;
    CHECK(tx_seg(0).len == TCP_MSS);
    CHECK(run_until_tx(1000) == 100 && run_until_tx(1000) == 200);
    uint32_t una = g_iss + 1 + 100;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].retries == 0 && ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(run_until_tx(1000) == 100);
    s = tx_seg(0);
    CHECK(s.seq == una && s.len == TCP_MSS - 100 && memcmp(s.data, big + 100, TCP_MSS - 100) == 0);
    // ACK penuh: sisa 64 byte dikirim, timer mulai lagi dari 100 tick.
    una = g_iss + 1 + TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.seq == una && s.len == 64 && g_tcbs[0].rto == TCP_RTO_INIT);
    CHECK(run_until_tx(1000) == 100 && tx_seg(0).len == 64);
    // ACK semua: tidak ada lagi yang dikirim ulang.
    rx(f, mk_tcp_w(f, g_pseq, una + 64, F_ACK, 0, 0, 4096));
    CHECK(g_tcbs[0].buf_count == 0 && !ktimer_pending(&g_tcp_rtx_timer[0]));
    // RST dari peer selagi data menunggu ACK: timer dibatalkan.
    rx(f, mk_tcp_w(f, g_pseq, una + 64, F_ACK, big, 5, 4096));
    g_pseq += 5;
    CHECK(ktimer_pending(&g_tcp_rtx_timer[0]));
    rx(f, mk_tcp_w(f, g_pseq, 0, F_RST, 0, 0, 0));
    CHECK(g_tcbs[0].state == TCP_CLOSED && !ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(run_until_tx(3000) == 0);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- C3d: penutupan ----

static void rx_now(const uint8_t *f, size_t len);

static void test_tcp_close(void)
{
    static uint8_t f[1700];
    struct seg s;
    uint64_t ok0 = g_tcp_close_ok, rst0 = g_tcp_rst_state, give0 = g_tcp_retx_giveup;
    uint64_t busy0 = g_tcp_busy;

    // A. Tutup pasif, buffer kosong: FIN peer langsung dibalas FIN|ACK
    // (LAST_ACK), FIN dikirim ulang, FIN peer ulang dibalas ACK, ACK -> CLOSED.
    tcp_open(5000, 100, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"abc", 3, 4096));
    g_pseq += 3;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 4, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].buf_count == 0);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 4, F_ACK | F_FIN, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (F_FIN | F_ACK) && s.seq == g_iss + 4 && s.ack == g_pseq + 1);
    CHECK(g_tcbs[0].state == TCP_LAST_ACK && ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(run_until_tx(1000) == 100);
    s = tx_seg(0);
    CHECK(s.flags == (F_FIN | F_ACK) && s.seq == g_iss + 4 && s.ack == g_pseq + 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 4, F_ACK | F_FIN, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == F_ACK && s.seq == g_iss + 5 && s.ack == g_pseq + 1);
    g_pseq++;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 5, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_CLOSED && !ktimer_pending(&g_tcp_rtx_timer[0]));
    CHECK(g_tcp_close_ok == ok0 + 1 && run_until_tx(5000) == 0);
    // Port 7 langsung bebas.
    rx(f, mk_tcp(f, 4100, 7, 1, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && g_tcp_busy == busy0);

    // B. FIN bersama data: echo dulu (tanpa FIN), FIN kita setelah echo di-ACK.
    // Lalu data baru di LAST_ACK -> RST.
    tcp_open(7000, 300, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK | F_FIN | 0x08, (const uint8_t *)"hello", 5, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (0x08 | F_ACK) && s.len == 5 && s.ack == g_pseq + 6);
    CHECK(g_tcbs[0].state == TCP_CLOSE_WAIT);
    g_pseq += 6;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 6, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (F_FIN | F_ACK) && s.seq == g_iss + 6 && g_tcbs[0].state == TCP_LAST_ACK);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 6, F_ACK, (const uint8_t *)"x", 1, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == (F_RST | F_ACK) && s.seq == g_iss + 7);
    CHECK(g_tcbs[0].state == TCP_CLOSED && g_tcp_rst_state == rst0 + 1 && !ktimer_pending(&g_tcp_rtx_timer[0]));

    // C. FIN kita tidak pernah di-ACK: 5 kirim ulang lalu RST.
    tcp_open(9000, 500, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK | F_FIN, 0, 0, 4096));
    CHECK(tx_seg(0).flags == (F_FIN | F_ACK));
    int fin_ok = 1;
    static const uint32_t gaps[5] = { 100, 200, 400, 800, 800 };
    for (int i = 0; i < 5; i++) {
        fin_ok &= run_until_tx(2000) == gaps[i] && tx_seg(0).flags == (F_FIN | F_ACK) &&
                  tx_seg(0).seq == g_iss + 1;
    }
    CHECK(fin_ok);
    CHECK(run_until_tx(2000) == 800 && tx_seg(0).flags == (F_RST | F_ACK));
    CHECK(g_tcbs[0].state == TCP_CLOSED && g_tcp_retx_giveup == give0 + 1);

    // D. Tutup aktif saat diam: FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT. FIN
    // peer ulang dibalas ACK, RST diabaikan (RFC 1337), SYN lain memakai slot
    // lain (C5a), TIME_WAIT berakhir setelah TCP_TIME_WAIT_TICKS tanpa kirim apa pun.
    tcp_open(0xFFFFFFFEu, 700, 4096);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1);
    s = tx_seg(0);
    CHECK(s.flags == (F_FIN | F_ACK) && s.seq == 0xFFFFFFFFu && g_tcbs[0].state == TCP_FIN_WAIT_1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_FIN_WAIT_2 && !ktimer_pending(&g_tcp_rtx_timer[0]));
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK | F_FIN, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == F_ACK && s.seq == g_iss + 2 && s.ack == g_pseq + 1);
    CHECK(g_tcbs[0].state == TCP_TIME_WAIT);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK | F_FIN, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_ACK && tx_seg(0).ack == g_pseq + 1);
    rx(f, mk_tcp_w(f, g_pseq + 1, 0, F_RST, 0, 0, 0));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_TIME_WAIT);
    rx_now(f, mk_tcp(f, 4200, 7, 1, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && g_tcp_busy == busy0);
    CHECK(g_tcbs[1].state == TCP_SYN_RCVD);
    rx_now(f, mk_tcp(f, 4200, 7, 2, 0, F_RST, ""));   // tutup slot 1, waktu tetap
    CHECK(g_tx_n == 0 && g_tcbs[1].state == TCP_CLOSED);
    // C5b: FIN ulang dan RST (2 x 100 tick) tidak memperpanjang TIME_WAIT:
    // sudah TCP_TIME_WAIT_TICKS sejak FIN peer pertama, berakhir tick berikutnya.
    CHECK(TCP_TIME_WAIT_TICKS == 200 && g_tcbs[0].state == TCP_TIME_WAIT);
    CHECK(step() == 0 && g_tcbs[0].state == TCP_CLOSED && g_tcp_close_ok == ok0 + 2);

    // E. FIN_WAIT_2 tanpa FIN peer: RST setelah TCP_FIN_WAIT_2_TIMEOUT.
    tcp_open(100, 900, 4096);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK, 0, 0, 4096));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_2);
    CHECK(run_until_tx(5000) == TCP_FIN_WAIT_2_TIMEOUT + 1);
    CHECK(tx_seg(0).flags == (F_RST | F_ACK) && g_tcbs[0].state == TCP_CLOSED);

    // F. Data setelah FIN kita (ACK FIN dan data dalam satu segmen): RST.
    tcp_open(200, 1100, 4096);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK, (const uint8_t *)"zz", 2, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_tcbs[0].state == TCP_CLOSED);
    CHECK(g_tcp_rst_state == rst0 + 2);

    // G. Tutup bersamaan: FIN peer sebelum FIN kita di-ACK -> CLOSING ->
    // (ACK) TIME_WAIT. FIN + ACK FIN kita dalam satu segmen -> TIME_WAIT.
    tcp_open(300, 1300, 4096);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK | F_FIN, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == F_ACK && s.seq == g_iss + 2 && s.ack == g_pseq + 1);
    CHECK(g_tcbs[0].state == TCP_CLOSING && ktimer_pending(&g_tcp_rtx_timer[0]));
    g_pseq++;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_TIME_WAIT && !ktimer_pending(&g_tcp_rtx_timer[0]));
    tcp_open(400, 1500, 4096);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK | F_FIN, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_ACK && g_tcbs[0].state == TCP_TIME_WAIT);

    // H. Diam dengan data tertahan (jendela peer 0): RST, bukan FIN.
    tcp_open(500, 1700, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"abc", 3, 0));
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0 && g_tcbs[0].buf_count == 3);
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1 && tx_seg(0).flags == (F_RST | F_ACK));
    CHECK(g_tcbs[0].state == TCP_CLOSED);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- C4: batas laju koneksi TCP ----

// Seperti rx(), tetapi tanpa memajukan timer_ticks (banyak frame dalam satu
// jendela batas laju).
static void rx_now(const uint8_t *f, size_t len)
{
    uint8_t *b = malloc(len ? len : 1);
    memcpy(b, f, len);
    g_tx_n = 0;
    net_rx_dispatch(b, (uint32_t)len);
    free(b);
}

static void test_tcp_limits(void)
{
    static uint8_t f[1700];
    uint64_t drop0 = g_tcp_conn_dropped, lim0 = g_tcp_dupack_limited;

    // Koneksi aktif: 2000 segmen dalam satu detik diproses (jauh di atas
    // batas UDP 20/s per IP), segmen ke-2001 dibuang.
    tcp_open(1000, 3000, 4096);
    timer_ticks += 100;   // jendela baru
    uint64_t rx0 = g_tcp_rx;
    int acks = 0;
    for (uint32_t j = 0; j < TCP_CONN_SEG_PER_SEC / 2; j++) {
        rx_now(f, mk_tcp_w(f, g_pseq, g_iss + 1 + j, F_ACK, (const uint8_t *)"a", 1, 4096));
        g_pseq++;
        acks += g_tx_n;
        // Echo "a" di-ACK supaya buffer tidak penuh.
        rx_now(f, mk_tcp_w(f, g_pseq, g_iss + 1 + j + 1, F_ACK, 0, 0, 4096));
    }
    CHECK(g_tcp_rx == rx0 + TCP_CONN_SEG_PER_SEC && g_tcp_conn_dropped == drop0 && acks == TCP_CONN_SEG_PER_SEC / 2);
    rx_now(f, mk_tcp_w(f, g_pseq, g_iss + 1 + TCP_CONN_SEG_PER_SEC / 2, F_ACK, (const uint8_t *)"b", 1, 4096));
    CHECK(g_tx_n == 0 && g_tcp_conn_dropped == drop0 + 1 && g_tcp_rx == rx0 + TCP_CONN_SEG_PER_SEC);
    // Jendela berikutnya: diproses lagi.
    timer_ticks += 100;
    rx_now(f, mk_tcp_w(f, g_pseq, g_iss + 1 + TCP_CONN_SEG_PER_SEC / 2, F_ACK, (const uint8_t *)"b", 1, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).len == 1);
    g_pseq++;

    // Segmen bukan milik koneksi (IP sama, port lain) tetap kena batas per IP.
    uint64_t src0 = g_net_udp_src_dropped;
    timer_ticks += 100;
    int rst = 0;
    for (int i = 0; i < 30; i++) {
        rx_now(f, mk_tcp(f, 4500, 80, 1, 0, F_SYN, ""));
        rst += g_tx_n;
    }
    CHECK(rst == NET_UDP_SRC_PER_SEC && g_net_udp_src_dropped == src0 + 30 - NET_UDP_SRC_PER_SEC);

    // ACK untuk segmen di luar urutan: maks TCP_DUPACK_PER_SEC per detik.
    timer_ticks += 100;
    int dup = 0;
    for (int i = 0; i < 25; i++) {
        rx_now(f, mk_tcp_w(f, g_pseq + 5000, g_iss + 1 + TCP_CONN_SEG_PER_SEC / 2 + 1, F_ACK,
                            (const uint8_t *)"zz", 2, 4096));
        dup += g_tx_n;
    }
    CHECK(dup == TCP_DUPACK_PER_SEC && g_tcp_dupack_limited == lim0 + 25 - TCP_DUPACK_PER_SEC);
    // ACK melewati snd_nxt juga dihitung di batas yang sama.
    rx_now(f, mk_tcp_w(f, g_pseq, g_iss + 99999, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcp_dupack_limited == lim0 + 25 - TCP_DUPACK_PER_SEC + 1);
    timer_ticks += 100;
    rx_now(f, mk_tcp_w(f, g_pseq + 5000, g_iss + 1, F_ACK, (const uint8_t *)"zz", 2, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_ACK && tx_seg(0).ack == g_pseq);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- C5a: tabel TCB ----

// SYN/ACK/RST dari IP 192.168.50.<ip3> (mk_tcp memakai PEER_IP, lalu IP
// sumber diganti dan checksum dihitung ulang).
static uint16_t g_from_port = 7;   // D4: port tujuan mk_tcp_from/syn_from

static size_t mk_tcp_from(uint8_t *f, uint8_t ip3, uint16_t sport, uint32_t seq,
                          uint32_t ack, uint8_t flags, const char *data)
{
    size_t n = mk_tcp(f, sport, g_from_port, seq, ack, flags, data);
    f[29] = ip3;
    fix_csums(f, n);
    return n;
}

// SYN dengan ISN kita = isn; return 1 bila dibalas SYN-ACK yang benar.
static int syn_from(uint8_t *f, uint8_t ip3, uint16_t sport, uint32_t pseq, uint32_t isn)
{
    g_isn_set = 1;
    g_isn = isn;
    rx(f, mk_tcp_from(f, ip3, sport, pseq, 0, F_SYN, ""));
    g_isn_set = 0;
    return g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && tx_seg(0).seq == isn &&
           tx_seg(0).ack == pseq + 1 && g_tx[0][33] == ip3;
}

static void test_tcp_table(void)
{
    static uint8_t f[600];
    uint64_t full0 = g_tcp_src_full, ev0 = g_tcp_synrcvd_evicted, busy0 = g_tcp_busy;

    tcp_reset();
    CHECK(net_tcp_conn_active() == 0 && net_tcp_state() == TCP_CLOSED);

    // Dua koneksi dari .31 (ESTABLISHED), yang ketiga ditolak RST.
    CHECK(syn_from(f, 31, 5001, 100, 1000));
    rx(f, mk_tcp_from(f, 31, 5001, 101, 1001, F_ACK, ""));
    CHECK(syn_from(f, 31, 5002, 200, 2000));
    rx(f, mk_tcp_from(f, 31, 5002, 201, 2001, F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_ESTABLISHED && g_tcbs[1].state == TCP_ESTABLISHED);
    rx(f, mk_tcp_from(f, 31, 5003, 300, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && tx_seg(0).ack == 301);
    CHECK(g_tcp_src_full == full0 + 1 && net_tcp_conn_active() == 2);

    // Dua SYN_RCVD dari .32 lalu .33: tabel penuh.
    CHECK(syn_from(f, 32, 5010, 400, 3000));
    CHECK(syn_from(f, 33, 5020, 500, 4000));
    CHECK(net_tcp_conn_active() == 4);

    // .34: SYN_RCVD tertua (.32) digusur tanpa RST, .34 mendapat slotnya.
    CHECK(syn_from(f, 34, 5030, 600, 5000));
    CHECK(g_tcp_synrcvd_evicted == ev0 + 1 && g_tcbs[2].ip[3] == 34 && g_tcbs[3].ip[3] == 33);
    // ACK handshake .32 yang terlambat: koneksi tidak ada lagi -> RST seq=ack.
    rx(f, mk_tcp_from(f, 32, 5010, 401, 3001, F_ACK, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_RST && tx_seg(0).seq == 3001);

    // Semua ESTABLISHED: SYN baru -> RST (sibuk), tidak ada yang digusur.
    rx(f, mk_tcp_from(f, 33, 5020, 501, 4001, F_ACK, ""));
    rx(f, mk_tcp_from(f, 34, 5030, 601, 5001, F_ACK, ""));
    CHECK(g_tcbs[2].state == TCP_ESTABLISHED && g_tcbs[3].state == TCP_ESTABLISHED);
    rx(f, mk_tcp_from(f, 35, 5040, 700, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_tcp_busy == busy0 + 1);
    CHECK(g_tcp_synrcvd_evicted == ev0 + 1 && net_tcp_conn_active() == 4);

    // Echo per koneksi: data .33 kembali ke .33 dengan nomor urutnya sendiri,
    // koneksi lain tidak tersentuh.
    rx(f, mk_tcp_from(f, 33, 5020, 501, 4001, F_ACK | 0x08, "tiga"));
    CHECK(g_tx_n == 1 && g_tx[0][33] == 33 && tx_seg(0).seq == 4001 && tx_seg(0).ack == 505 &&
          tx_seg(0).len == 4 && memcmp(tx_seg(0).data, "tiga", 4) == 0);
    CHECK(g_tcbs[3].buf_count == 4 && g_tcbs[0].buf_count == 0 && g_tcbs[2].buf_count == 0);
    CHECK(ktimer_pending(&g_tcp_rtx_timer[3]) && !ktimer_pending(&g_tcp_rtx_timer[2]));

    // RST dari .31:5001 hanya menutup slot 0; slot itu lalu dipakai SYN baru.
    rx(f, mk_tcp_from(f, 31, 5001, 101, 0, F_RST, ""));
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_CLOSED && net_tcp_conn_active() == 3);
    CHECK(net_tcp_state() == TCP_ESTABLISHED);
    CHECK(syn_from(f, 36, 5050, 800, 6000) && g_tcbs[0].ip[3] == 36);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- C5b: timeout hanya diperpanjang oleh kemajuan ----

// Jalankan `n` tick tanpa frame keluar. Return 1 bila memang sunyi.
static int quiet(uint32_t n)
{
    int ok = 1;
    for (uint32_t i = 0; i < n; i++) {
        ok &= step() == 0;
    }
    return ok;
}

static void test_tcp_idle(void)
{
    static uint8_t f[600];
    uint64_t to0 = g_tcp_timeouts;
    uint64_t t0;
    int ok;

    // A. ESTABLISHED: ACK duplikat, keepalive (seq - 1), jendela berubah,
    // RST seq salah, SYN: tidak ada yang memperpanjang. FIN tetap tepat
    // TCP_IDLE_TIMEOUT + 1 tick setelah handshake.
    tcp_open(1000, 2000, 4096);
    t0 = timer_ticks;
    ok = 1;
    for (int i = 0; i < 5; i++) {
        ok &= quiet(400);
        if (i == 0) {
            rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 4096));
        } else if (i == 1) {
            rx(f, mk_tcp_w(f, g_pseq - 1, g_iss + 1, F_ACK, 0, 0, 4096));
        } else if (i == 2) {
            rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 100));
        } else if (i == 3) {
            rx(f, mk_tcp_w(f, g_pseq + 5000, 0, F_RST, 0, 0, 0));
        } else {
            rx(f, mk_tcp_w(f, 77, 0, F_SYN, 0, 0, 4096));
        }
        ok &= g_tcbs[0].state == TCP_ESTABLISHED;
    }
    CHECK(ok);
    CHECK(run_until_tx(5000) > 0 && timer_ticks - t0 == TCP_IDLE_TIMEOUT + 1);
    CHECK(tx_seg(0).flags == (F_FIN | F_ACK) && g_tcbs[0].state == TCP_FIN_WAIT_1);
    CHECK(g_tcp_timeouts == to0 + 1);

    // B. Kemajuan memperpanjang: data baru + ACK echo-nya di tick ~2500,
    // FIN TCP_IDLE_TIMEOUT + 1 tick setelah ACK itu.
    tcp_open(3000, 4000, 4096);
    CHECK(quiet(2400));
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"x", 1, 4096));
    g_pseq++;
    CHECK(g_tx_n == 1 && tx_seg(0).len == 1);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 2, F_ACK, 0, 0, 4096));
    t0 = timer_ticks;
    CHECK(run_until_tx(5000) == TCP_IDLE_TIMEOUT + 1 && tx_seg(0).flags == (F_FIN | F_ACK));

    // C. SYN_RCVD: SYN ulang tiap 100 tick tidak memperpanjang; RST tepat
    // TCP_SYNRCVD_TIMEOUT + 1 tick setelah SYN pertama.
    tcp_reset();
    rx(f, mk_tcp_w(f, 800, 0, F_SYN, 0, 0, 4096));
    t0 = timer_ticks;
    ok = g_tx_n == 1 && g_tcbs[0].state == TCP_SYN_RCVD;
    for (int i = 0; i < 4; i++) {
        rx(f, mk_tcp_w(f, 800, 0, F_SYN, 0, 0, 4096));
        ok &= g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK);
    }
    CHECK(ok);
    int rst = 0;
    for (uint32_t i = 0; i < 2000 && !rst; i++) {
        step();
        for (int j = 0; j < g_tx_n; j++) {
            rst |= (tx_seg(j).flags & F_RST) != 0;
        }
    }
    CHECK(rst && timer_ticks - t0 == TCP_SYNRCVD_TIMEOUT + 1 && g_tcbs[0].state == TCP_CLOSED);

    // D. Data tertahan jendela 0: ACK jendela 0 berulang tidak menahan
    // koneksi; RST TCP_IDLE_TIMEOUT + 1 tick setelah data terakhir.
    tcp_open(5000, 6000, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"abc", 3, 0));
    g_pseq += 3;
    t0 = timer_ticks;
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0 && g_tcbs[0].buf_count == 3);
    ok = 1;
    for (int i = 0; i < 5; i++) {
        ok &= quiet(400);
        rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 0));
        ok &= g_tx_n == 0 && g_tcbs[0].state == TCP_ESTABLISHED;
    }
    CHECK(ok);
    CHECK(run_until_tx(5000) > 0 && timer_ticks - t0 == TCP_IDLE_TIMEOUT + 1);
    CHECK(tx_seg(0).flags == (F_RST | F_ACK) && g_tcbs[0].state == TCP_CLOSED);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- D1: CLI port 7779 (login) ----

static const char BANNER[] = "bmahOS login\nnonce: a4a5a6a7a8a9aaabacadaeafb0b1b2b3\n";
#define BLEN (sizeof(BANNER) - 1)

// Koneksi CLI: handshake, banner diperiksa, banner di-ACK. Return 1 bila
// banner benar. g_iss + 1 + BLEN = snd_nxt setelahnya.
static int cli_open(uint32_t our_isn, uint32_t peer_isn)
{
    uint8_t f[200];
    g_wport = 7779;
    tcp_open(our_isn, peer_isn, 4096);
    struct seg s = tx_seg(0);
    int ok = g_tx_n == 1 && s.len == BLEN && memcmp(s.data, BANNER, BLEN) == 0 &&
             s.seq == g_iss + 1 && g_tcbs[0].app == TCP_APP_CLI;
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1 + BLEN, F_ACK, 0, 0, 4096));
    return ok && g_tx_n == 0;
}

static int cli_send(const char *line, uint32_t ack)
{
    static uint8_t f[700];
    uint32_t n = (uint32_t)strlen(line);
    rx(f, mk_tcp_w(f, g_pseq, ack, F_ACK | 0x08, (const uint8_t *)line, n, 4096));
    g_pseq += n;
    return g_tx_n;
}

static int reply_is(const char *want)
{
    struct seg s = tx_seg(0);
    size_t n = strlen(want);
    return g_tx_n == 1 && s.len == n && memcmp(s.data, want, n) == 0 && s.ack == g_pseq;
}

static void test_tcp_cli(void)
{
    static uint8_t f[300];
    char line[200];
    uint64_t ok0 = g_cli_login_ok, fail0 = g_cli_login_fail;
    uint64_t to0 = g_cli_login_timeout, long0 = g_cli_line_long;
    uint32_t una;

    // A. Login benar (CRLF diterima), nonce = byte 4..19 dari entropi SYN.
    CHECK(cli_open(1000, 2000));
    una = g_iss + 1 + BLEN;
    memcpy(line, "login ", 6);
    memset(line + 6, 'a', 64);
    memcpy(line + 70, "\r\n", 3);
    cli_send(line, una);
    CHECK(reply_is("OK login\n") && g_cli_login_ok == ok0 + 1 && g_tcbs[0].cli_authed);
    CHECK(g_login_nonce[0] == 0xA4 && g_login_nonce[15] == 0xB3);
    una += 9;
    // Setelah login baris kosong diabaikan; baris tanpa hmac: ERR + tutup (D2).
    cli_send("\n", una);
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0);
    cli_send("help\n", una);
    CHECK(reply_is("ERR: format: <perintah> <hmac-hex64>\n") && g_tcbs[0].close_after);

    // B. HMAC salah: ERR, lalu FIN setelah ERR di-ACK; satu percobaan saja.
    CHECK(cli_open(3000, 4000));
    una = g_iss + 1 + BLEN;
    memset(line + 6, 'b', 64);
    line[70] = '\n';
    line[71] = 0;
    cli_send(line, una);
    CHECK(reply_is("ERR: login gagal\n") && g_cli_login_fail == fail0 + 1);
    CHECK(g_tcbs[0].close_after && g_tcbs[0].state == TCP_ESTABLISHED);
    una += 17;
    // Data sesudah keputusan tutup dibuang (tetap di-ACK), tidak diproses.
    memset(line + 6, 'a', 64);
    cli_send(line, una);
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_FIN | F_ACK) && tx_seg(0).seq == una);
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_1 && g_cli_login_ok == ok0 + 1);

    // C. Format salah (tanpa "login ") dan auth nonaktif: juga gagal + tutup.
    CHECK(cli_open(5000, 6000));
    cli_send("halo\n", g_iss + 1 + BLEN);
    CHECK(reply_is("ERR: login gagal\n") && g_cli_login_fail == fail0 + 2);
    CHECK(cli_open(7000, 8000));
    g_login_off = 1;
    cli_send("halo\n", g_iss + 1 + BLEN);
    g_login_off = 0;
    CHECK(reply_is("ERR: auth nonaktif\n") && g_cli_login_fail == fail0 + 3);

    // D. Tidak login: ERR tepat TCP_LOGIN_TIMEOUT + 1 tick setelah ESTABLISHED
    // (cli_open sudah memajukan 100 tick), lalu FIN setelah di-ACK.
    CHECK(cli_open(9000, 10000));
    una = g_iss + 1 + BLEN;
    CHECK(run_until_tx(5000) == TCP_LOGIN_TIMEOUT + 1 - 100);
    CHECK(reply_is("ERR: login timeout\n") && g_cli_login_timeout == to0 + 1);
    rx(f, mk_tcp_w(f, g_pseq, una + 19, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_FIN | F_ACK) && g_tcbs[0].state == TCP_FIN_WAIT_1);

    // E. Baris > TCP_LINE_MAX tanpa LF: ERR + tutup, semua byte di-ACK.
    CHECK(cli_open(11000, 12000));
    memset(line, 'x', 199);
    line[199] = 0;
    cli_send(line, g_iss + 1 + BLEN);
    CHECK(reply_is("ERR: baris terlalu panjang\n") && g_cli_line_long == long0 + 1);
    CHECK(g_tcbs[0].close_after && g_cli_login_fail == fail0 + 3);
    // 127 byte + LF masih satu baris (format salah, bukan terlalu panjang).
    CHECK(cli_open(13000, 14000));
    memset(line, 'y', 127);
    line[127] = '\n';
    line[128] = 0;
    cli_send(line, g_iss + 1 + BLEN);
    CHECK(reply_is("ERR: login gagal\n") && g_cli_line_long == long0 + 1);

    // F. Port 7 tetap echo (bukan CLI).
    g_wport = 7;
    tcp_open(15000, 16000, 4096);
    CHECK(g_tx_n == 0 && g_tcbs[0].app == TCP_APP_ECHO);
    cli_send("login\n", g_iss + 1);
    CHECK(reply_is("login\n"));
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- D2: shell TCP (perintah bertanda tangan nomor urut) ----

// Koneksi CLI yang sudah login; return snd_nxt (semua balasan di-ACK).
static uint32_t cli_login(uint32_t our_isn, uint32_t peer_isn)
{
    char line[80];
    uint8_t f[200];
    CHECK(cli_open(our_isn, peer_isn));
    memcpy(line, "login ", 6);
    memset(line + 6, 'a', 64);
    memcpy(line + 70, "\n", 2);
    cli_send(line, g_iss + 1 + BLEN);
    CHECK(reply_is("OK login\n"));
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1 + BLEN + 9, F_ACK, 0, 0, 4096));
    return g_iss + 1 + BLEN + 9;
}

// "<perintah> <64 x digit seq>\n"
static const char *cmd_line(const char *cmd, uint64_t seq)
{
    static char line[200];
    size_t n = strlen(cmd);
    memcpy(line, cmd, n);
    line[n] = ' ';
    memset(line + n + 1, '0' + (int)(seq % 10), 64);
    line[n + 65] = '\n';
    line[n + 66] = 0;
    return line;
}

static void test_tcp_shell(void)
{
    static uint8_t f[300];
    static uint8_t got[2000];
    uint64_t ok0 = g_cli_cmd_ok, fail0 = g_cli_cmd_fail;
    uint32_t una, glen;
    struct seg s;

    // A. Dua perintah berurutan: keluaran + "END <n>", nomor urut 1 lalu 2.
    una = cli_login(20000, 21000);
    cli_send(cmd_line("ping", 1), una);
    CHECK(reply_is("ping\nEND 1\n") && g_cmd_seq_seen == 1);
    una += 11;
    cli_send(cmd_line("uptime", 2), una);
    CHECK(reply_is("uptime\nEND 2\n") && g_cmd_seq_seen == 2);
    una += 13;
    CHECK(g_cli_cmd_ok == ok0 + 2 && g_tcbs[0].cmd_seq == 2);
    // Baris yang sama diulang (replay seq 2 saat yang diharapkan 3): ERR + FIN.
    cli_send(cmd_line("uptime", 2), una);
    CHECK(reply_is("ERR: hmac salah\n") && g_cmd_seq_seen == 3);
    CHECK(g_cli_cmd_fail == fail0 + 1 && g_tcbs[0].close_after);
    rx(f, mk_tcp_w(f, g_pseq, una + 16, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_FIN | F_ACK) &&
          g_tcbs[0].state == TCP_FIN_WAIT_1);

    // B. Keluaran 1306 byte (> buffer 1024) dialirkan bertahap; baris yang
    // datang selama keluaran belum habis tidak dibaca dan tidak di-ACK.
    una = cli_login(22000, 23000);
    cli_send(cmd_line("big", 1), una);
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == TCP_MSS && g_tcbs[0].out_pos == TCP_BUF_SIZE);
    memcpy(got, s.data, s.len);
    glen = s.len;
    // Baris berikutnya tanpa ACK baru: ditolak masuk (rcv_nxt tetap).
    uint32_t rn = g_tcbs[0].rcv_nxt;
    cli_send(cmd_line("ping", 2), una);
    CHECK(g_tcbs[0].rcv_nxt == rn && g_tcbs[0].cmd_seq == 1);
    g_pseq = rn;
    for (int i = 0; i < 5 && glen < 1306; i++) {
        rx(f, mk_tcp_w(f, g_pseq, una + glen, F_ACK, 0, 0, 4096));
        s = tx_seg(0);
        if (g_tx_n != 1 || s.len == 0 || s.seq != una + glen) {
            break;
        }
        memcpy(got + glen, s.data, s.len);
        glen += s.len;
    }
    int pat = glen == 1306 && memcmp(got + 1300, "END 1\n", 6) == 0;
    for (uint32_t i = 0; pat && i < 1300; i++) {
        pat = got[i] == 'a' + i % 26;
    }
    CHECK(pat);
    rx(f, mk_tcp_w(f, g_pseq, una + glen, F_ACK, 0, 0, 4096));
    CHECK(g_tcbs[0].out_pos == g_tcbs[0].out_len && g_tcbs[0].buf_count == 0);
    una += glen;
    // Setelah habis, perintah berikutnya diterima.
    cli_send(cmd_line("ping", 2), una);
    CHECK(reply_is("ping\nEND 2\n"));
    una += 11;

    // C. exit: "bye" + END, lalu FIN setelah di-ACK.
    cli_send(cmd_line("exit", 3), una);
    CHECK(reply_is("bye\nEND 3\n") && g_tcbs[0].close_after);
    rx(f, mk_tcp_w(f, g_pseq, una + 10, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_FIN | F_ACK));

    // D. reboot: hanya setelah keluaran di-ACK.
    int rb0 = g_reboots;
    una = cli_login(24000, 25000);
    cli_send(cmd_line("reboot", 1), una);
    CHECK(reply_is("reboot\nEND 1\n") && g_reboots == rb0 && g_tcbs[0].reboot_after);
    rx_now(f, mk_tcp_w(f, g_pseq, una + 13, F_ACK, 0, 0, 4096));
    CHECK(g_reboots == rb0 + 1 && !g_tcbs[0].reboot_after);
    // Tanpa ACK: paling lambat TCP_REBOOT_WAIT tick setelah perintah.
    una = cli_login(26000, 27000);
    cli_send(cmd_line("reboot", 1), una);
    CHECK(g_reboots == rb0 + 1);
    uint32_t k = 0;
    while (g_reboots == rb0 + 1 && k < 1000) {
        step();
        k++;
    }
    CHECK(g_reboots == rb0 + 2 && k == TCP_REBOOT_WAIT + 1);
    // ACK keluaran + FIN peer dalam satu segmen (Windows Close()): reboot
    // tetap jalan (dulu FIN CLOSE_WAIT didahulukan dan reboot hilang).
    una = cli_login(32000, 33000);
    cli_send(cmd_line("reboot", 1), una);
    rx_now(f, mk_tcp_w(f, g_pseq, una + 13, F_ACK | F_FIN, 0, 0, 4096));
    CHECK(g_reboots == rb0 + 3 && !g_cli_reboot);
    for (k = 0; k < 300; k++) {
        step();
    }
    CHECK(g_reboots == rb0 + 3);
    // RST peer sebelum keluaran di-ACK (TCB tertutup): reboot setelah batas.
    una = cli_login(34000, 35000);
    cli_send(cmd_line("reboot", 1), una);
    rx_now(f, mk_tcp_w(f, g_pseq, 0, F_RST, 0, 0, 0));
    CHECK(g_tcbs[0].state == TCP_CLOSED && g_reboots == rb0 + 3);
    for (k = 0; k < TCP_REBOOT_WAIT + 1 && g_reboots == rb0 + 3; k++) {
        step();
    }
    CHECK(g_reboots == rb0 + 4 && k == TCP_REBOOT_WAIT + 1);

    // E. Format salah dan auth nonaktif setelah login: ERR + tutup.
    una = cli_login(28000, 29000);
    cli_send("ping zz\n", una);
    CHECK(reply_is("ERR: format: <perintah> <hmac-hex64>\n") && g_tcbs[0].close_after);
    una = cli_login(30000, 31000);
    g_login_off = 1;
    cli_send(cmd_line("ping", 1), una);
    g_login_off = 0;
    CHECK(reply_is("ERR: auth nonaktif\n") && g_cli_cmd_fail == fail0 + 3);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- D4: peran, jumlah sesi, idle sesi ----

static void test_tcp_session(void)
{
    static uint8_t f[300];
    char line[80];
    uint64_t ro0 = g_cli_login_ro, ok0 = g_cli_login_ok, full0 = g_cli_sess_full;
    uint64_t idle0 = g_cli_idle_timeout, ev0 = g_tcp_synrcvd_evicted;
    uint32_t una;

    // A. Login read-only: "OK login ro", peran diteruskan ke cmd dan exec.
    CHECK(cli_open(40000, 41000));
    una = g_iss + 1 + BLEN;
    memcpy(line, "login ", 6);
    memset(line + 6, 'r', 64);
    memcpy(line + 70, "\n", 2);
    cli_send(line, una);
    CHECK(reply_is("OK login ro\n") && g_cli_login_ro == ro0 + 1 &&
          g_cli_login_ok == ok0 + 1 && g_tcbs[0].role == AUTH_ROLE_RO);
    una += 12;
    cli_send(cmd_line("ping", 1), una);
    CHECK(reply_is("ping\nEND 1\n") && g_cmd_role_seen == AUTH_ROLE_RO &&
          g_exec_role_seen == AUTH_ROLE_RO);
    una = cli_login(42000, 43000);
    cli_send(cmd_line("ping", 1), una);
    CHECK(g_tcbs[0].role == AUTH_ROLE_ADMIN && g_cmd_role_seen == AUTH_ROLE_ADMIN &&
          g_exec_role_seen == AUTH_ROLE_ADMIN && g_cli_login_ro == ro0 + 1);
    una += 11;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));

    // B. Idle sesi: batas diam TCP 30 s tidak berlaku; perintah sah
    // memperpanjang; byte tanpa LF tidak; ERR tepat TCP_CLI_IDLE + 1 tick
    // setelah perintah terakhir, lalu FIN setelah di-ACK.
    CHECK(quiet(TCP_IDLE_TIMEOUT + 500) && g_tcbs[0].state == TCP_ESTABLISHED);
    cli_send(cmd_line("uptime", 2), una);
    CHECK(reply_is("uptime\nEND 2\n"));
    una += 13;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    uint64_t t0 = timer_ticks;
    CHECK(quiet(TCP_CLI_IDLE - 1000));
    cli_send("pi", una);   // tanpa LF: di-ACK, tidak memperpanjang sesi
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0);
    uint32_t k = run_until_tx(5000);
    // t0 = tick ACK; perintah uptime diproses 100 tick sebelumnya (rx).
    CHECK(k > 0 && timer_ticks - (t0 - 100) == TCP_CLI_IDLE + 1);
    CHECK(reply_is("ERR: sesi idle\n") && g_cli_idle_timeout == idle0 + 1 &&
          g_tcbs[0].close_after);
    CHECK(g_au.ev == AUDIT_IDLE && g_au.role == AUTH_ROLE_ADMIN && g_au.cmd[0] == 0);
    rx(f, mk_tcp_w(f, g_pseq, una + 15, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_FIN | F_ACK) &&
          g_tcbs[0].state == TCP_FIN_WAIT_1);
    // Belum login tetap kena batas login 10 s (bukan TCP_CLI_IDLE).
    CHECK(cli_open(44000, 45000));
    CHECK(run_until_tx(5000) == TCP_LOGIN_TIMEOUT + 1 - 100);
    CHECK(reply_is("ERR: login timeout\n"));

    // C. Maks TCP_CLI_MAX TCB port 7779 dari IP berbeda: SYN_RCVD CLI
    // tertua digusur; dua sesi ESTABLISHED -> SYN 7779 berikutnya RST
    // (cli_sess_full); port 7 tetap diterima.
    tcp_reset();
    g_from_port = 7779;
    CHECK(syn_from(f, 40, 50000, 100, 1000));
    CHECK(syn_from(f, 41, 50001, 200, 2000));
    CHECK(syn_from(f, 42, 50002, 300, 3000));
    CHECK(g_tcp_synrcvd_evicted == ev0 + 1 && net_tcp_conn_active() == 2);
    rx(f, mk_tcp_from(f, 41, 50001, 201, 2001, F_ACK, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).len == BLEN);   // banner
    rx(f, mk_tcp_from(f, 42, 50002, 301, 3001, F_ACK, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).len == BLEN);
    rx(f, mk_tcp_from(f, 40, 50000, 101, 1001, F_ACK, ""));   // digusur
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_RST);
    rx(f, mk_tcp_from(f, 43, 50003, 400, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && tx_seg(0).ack == 401);
    CHECK(g_cli_sess_full == full0 + 1 && net_tcp_conn_active() == 2);
    g_from_port = 7;
    CHECK(syn_from(f, 44, 50004, 500, 5000) && net_tcp_conn_active() == 3);
    CHECK(g_cli_sess_full == full0 + 1);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

// ---- D5: kejadian audit dari CLI TCP ----

// 1 bila kejadian audit terakhir = (ev, role, code, cmd) dan tepat satu baru
// sejak n0; IP/port = peer uji (192.168.50.1:4500), jalur TCP.
static int au_is(int n0, int ev, int role, int code, const char *cmd)
{
    return g_au.n == n0 + 1 && g_au.ev == ev && g_au.role == role &&
           g_au.code == code && strcmp(g_au.cmd, cmd) == 0 &&
           g_au.chan == AUDIT_TCP && memcmp(g_au.ip, PEER_IP, 4) == 0 &&
           g_au.port == 4500;
}

static void test_tcp_audit(void)
{
    char line[200];
    uint32_t una;
    int n0;

    // Login admin, perintah sah, exit (ro juga boleh exit).
    n0 = g_au.n;
    una = cli_login(50000, 51000);
    CHECK(au_is(n0, AUDIT_LOGIN, AUTH_ROLE_ADMIN, 0, ""));
    n0 = g_au.n;
    cli_send(cmd_line("ping", 1), una);
    CHECK(au_is(n0, AUDIT_CMD, AUTH_ROLE_ADMIN, 0, "ping"));
    una += 11;
    // HMAC salah: kode 5, teks perintah (belum terverifikasi) tidak dicatat.
    n0 = g_au.n;
    cli_send(cmd_line("uptime", 1), una);
    CHECK(reply_is("ERR: hmac salah\n"));
    CHECK(au_is(n0, AUDIT_CMD_FAIL, AUTH_ROLE_ADMIN, 5, ""));
    tcp_reset();

    // Login ro: perintah terlarang dicatat sebagai tolak-peran, exit sebagai cmd.
    CHECK(cli_open(52000, 53000));
    una = g_iss + 1 + BLEN;
    memcpy(line, "login ", 6);
    memset(line + 6, 'r', 64);
    memcpy(line + 70, "\n", 2);
    n0 = g_au.n;
    cli_send(line, una);
    CHECK(au_is(n0, AUDIT_LOGIN, AUTH_ROLE_RO, 0, ""));
    una += 12;
    n0 = g_au.n;
    cli_send(cmd_line("pping", 1), una);
    CHECK(au_is(n0, AUDIT_CMD_ROLE, AUTH_ROLE_RO, 0, "pping"));
    una += 12;
    n0 = g_au.n;
    cli_send(cmd_line("audit", 2), una);
    CHECK(au_is(n0, AUDIT_CMD_ROLE, AUTH_ROLE_RO, 0, "audit"));
    una += 12;
    n0 = g_au.n;
    cli_send(cmd_line("exit", 3), una);
    CHECK(au_is(n0, AUDIT_CMD, AUTH_ROLE_RO, 0, "exit"));
    tcp_reset();

    // Login gagal (hmac 5, format 2), baris terlalu panjang, login timeout.
    CHECK(cli_open(54000, 55000));
    memset(line + 6, 'b', 64);
    n0 = g_au.n;
    cli_send(line, g_iss + 1 + BLEN);
    CHECK(au_is(n0, AUDIT_LOGIN_FAIL, AUTH_ROLE_NONE, 5, ""));
    tcp_reset();
    CHECK(cli_open(56000, 57000));
    n0 = g_au.n;
    cli_send("halo\n", g_iss + 1 + BLEN);
    CHECK(au_is(n0, AUDIT_LOGIN_FAIL, AUTH_ROLE_NONE, 2, ""));
    tcp_reset();
    CHECK(cli_open(58000, 59000));
    memset(line, 'x', 199);
    line[199] = 0;
    n0 = g_au.n;
    cli_send(line, g_iss + 1 + BLEN);
    CHECK(au_is(n0, AUDIT_LINE_LONG, AUTH_ROLE_NONE, 0, ""));
    tcp_reset();
    CHECK(cli_open(60000, 61000));
    n0 = g_au.n;
    CHECK(run_until_tx(5000) > 0 && reply_is("ERR: login timeout\n"));
    CHECK(au_is(n0, AUDIT_LOGIN_TIMEOUT, AUTH_ROLE_NONE, 0, ""));
    tcp_reset();

    // Port 7 (echo) tidak menghasilkan kejadian audit.
    g_wport = 7;
    n0 = g_au.n;
    tcp_open(62000, 63000, 4096);
    cli_send("login\n", g_iss + 1);
    CHECK(reply_is("login\n") && g_au.n == n0);
    CHECK(g_tx_bad == 0);
    tcp_reset();
}

int main(void)
{
    test_checksum();
    test_arp();
    test_icmp();
    test_udp();
    test_tcp();
    test_tcp_send();
    test_tcp_stream();
    test_tcp_retx();
    test_tcp_close();
    test_tcp_limits();
    test_tcp_table();
    test_tcp_idle();
    test_tcp_cli();
    test_tcp_shell();
    test_tcp_session();
    test_tcp_audit();
    test_limits();
    build_templates();
    test_truncation();
    test_fuzz();
    return test_done("net");
}

// F1.7: uji parser paket dan checksum (kernel/net.c) di host.
// net.c disertakan langsung (#include) supaya fungsi static bisa diuji.
// Frame dimasukkan ke net_rx_dispatch() dalam buffer seukuran frame persis
// (malloc), jadi pembacaan lewat batas frame tertangkap ASan. Frame yang
// dikirim ditangkap stub e1000_tx_send() dan diperiksa checksum-nya.

#include <ctype.h>
#include <stdlib.h>
#include "test.h"
#include "net.c"
#include "netcon.c"   // R2
#include "sock.c"     // P5-2: soket TCP user lewat net.c
#include "ip6.c"      // F7: IPv6 lewat net_rx_dispatch
#include "bearssl.h"
#include "tls_test_keys.h"

// ---- stub driver/memori untuk net.c ----
// P5-2: sock.c (di-#include) butuh konteks task/syscall.
size_t current_index = 9;
uint64_t g_current_pml4_phys;
uint64_t g_sys_rejected;
uint32_t g_cmd_len;
volatile uint64_t g_net_loops = 1;

void task_wake(size_t idx)
{
    (void)idx;
}

bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable)
{
    (void)pml4_phys;
    (void)ptr;
    (void)len;
    (void)require_writable;
    return true;
}

void net_rx_tick_wake(void)
{
}

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
// P5-3: g_on_sleep = net task + peer tiruan selama syscall menunggu (connect).
static void (*g_on_sleep)(void);

void task_sleep(uint64_t ticks)
{
    timer_ticks += ticks;
    if (g_on_sleep) {
        g_on_sleep();
    }
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

// P3-4: kait DHCP (dhcp.c tidak ikut di uji ini).
static int g_dh_wait, g_dh_rx_n, g_dh_arp_n;
static uint32_t g_dh_rx_len;
static uint8_t g_dh_rx0;
int dhcp_waiting(void)
{
    return g_dh_wait;
}

void dhcp_rx(const volatile uint8_t *d, uint32_t len)
{
    g_dh_rx_n++;
    g_dh_rx_len = len;
    g_dh_rx0 = d[0];
}

void dhcp_arp_seen(const volatile uint8_t *buf)
{
    (void)buf;
    g_dh_arp_n++;
}

// P6-2: kait jawaban probe TCP pantau (monitor.c tidak ikut di uji ini).
static int g_probe_ret, g_probe_calls;
int monitor_tcp_seen(const volatile uint8_t *buf, uint32_t r)
{
    (void)buf;
    (void)r;
    g_probe_calls++;
    return g_probe_ret;
}

// Checksum ICMPv6/UDP acuan: pseudo-header IPv6 (src, dst, panjang, next header).
static uint16_t ref_l4_csum6(const uint8_t *ip6_hdr, uint8_t nxt, const uint8_t *l4, size_t n)
{
    uint64_t sum = 0;
    for (int i = 8; i < 40; i += 2) {
        sum += (uint64_t)(ip6_hdr[i] << 8 | ip6_hdr[i + 1]);
    }
    sum += n;
    sum += nxt;
    return ref_csum(l4, n, sum);
}

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
    if (!bad && p[12] == 0x86 && p[13] == 0xDD) {   // F7: IPv6
        uint32_t plen = (uint32_t)(p[18] << 8 | p[19]);
        bad |= p[14] != 0x60 || plen > 1460 || 54 + plen > frame_len || (p[20] != 58 && p[20] != 17);
        if (!bad) {
            bad |= ref_l4_csum6(p + 14, p[20], p + 54, plen) != 0;
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
    for (int k = 0; k < TCP_TCB_N; k++) {
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
static void fix6(uint8_t *f, size_t n);

static void fix_csums(uint8_t *f, size_t n)
{
    if (n >= 54 && f[12] == 0x86 && f[13] == 0xDD) {
        fix6(f, n);   // F7: IPv6
        return;
    }
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

// ---- F7: IPv6 (ip6.c) ----
static const uint8_t PEER6[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const uint8_t OUR6[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x0c, 0x29, 0xff, 0xfe, 0x86, 0xef, 0x48 };
static const uint8_t SN6[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x86, 0xef, 0x48 };
static const uint8_t ALL6[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

// Frame Ethernet + IPv6 persis 54 + n byte (tanpa padding), checksum belum diisi.
static size_t mk_ip6(uint8_t *f, const uint8_t *src, const uint8_t *dst, uint8_t nxt, uint8_t hop,
                     const uint8_t *pl, size_t n)
{
    eth_hdr(f, 0x86DD);
    memset(f + 14, 0, 40);
    f[14] = 0x60;
    f[18] = (uint8_t)(n >> 8);
    f[19] = (uint8_t)n;
    f[20] = nxt;
    f[21] = hop;
    memcpy(f + 22, src, 16);
    memcpy(f + 38, dst, 16);
    memcpy(f + 54, pl, n);
    return 54 + n;
}

// Isi checksum ICMPv6/UDP frame IPv6 di tempat (acuan independen dari ip6.c).
static void fix6(uint8_t *f, size_t n)
{
    if (n < 54 || f[12] != 0x86 || f[13] != 0xDD) {
        return;
    }
    size_t plen = (size_t)(f[18] << 8 | f[19]);
    if (plen > 1500 || 54 + plen > n) {
        return;
    }
    size_t off;
    if (f[20] == 58 && plen >= 4) {
        off = 2;
    } else if (f[20] == 17 && plen >= 8) {
        off = 6;
    } else {
        return;
    }
    f[54 + off] = f[54 + off + 1] = 0;
    uint16_t c = ref_l4_csum6(f + 14, f[20], f + 54, plen);
    if (f[20] == 17 && c == 0) {
        c = 0xFFFF;
    }
    f[54 + off] = (uint8_t)(c >> 8);
    f[54 + off + 1] = (uint8_t)c;
}

static size_t mk_icmp6(uint8_t *f, const uint8_t *src, const uint8_t *dst, uint8_t hop,
                       uint8_t type, const uint8_t *body, size_t bn)
{
    uint8_t m[1600] = { type, 0, 0, 0 };
    memcpy(m + 4, body, bn);
    size_t len = mk_ip6(f, src, dst, 58, hop, m, 4 + bn);
    fix6(f, len);
    return len;
}

static size_t mk_echo6(uint8_t *f, const uint8_t *src, const uint8_t *dst, const char *data)
{
    uint8_t b[1600] = { 0x12, 0x34, 0x00, 0x09 };
    size_t n = strlen(data);
    memcpy(b + 4, data, n);
    return mk_icmp6(f, src, dst, 64, 128, b, 4 + n);
}

// NS: target, opsi SLLA (mac) bila slla != NULL.
static size_t mk_ns6(uint8_t *f, const uint8_t *src, const uint8_t *dst, uint8_t hop,
                     const uint8_t *target, const uint8_t *slla)
{
    uint8_t b[40] = { 0, 0, 0, 0 };
    size_t n = 4 + 16;
    memcpy(b + 4, target, 16);
    if (slla) {
        b[n] = 1;
        b[n + 1] = 1;
        memcpy(b + n + 2, slla, 6);
        n += 8;
    }
    size_t len = mk_icmp6(f, src, dst, hop, 135, b, n);
    if (slla) {
        memcpy(f + 6, slla, 6);   // SLLA harus sama dengan MAC sumber Ethernet
    }
    return len;
}

static size_t mk_na6(uint8_t *f, const uint8_t *src, const uint8_t *dst, uint8_t flags,
                     const uint8_t *target, const uint8_t *tlla)
{
    uint8_t b[40] = { flags, 0, 0, 0 };
    size_t n = 4 + 16;
    memcpy(b + 4, target, 16);
    if (tlla) {
        b[n] = 2;
        b[n + 1] = 1;
        memcpy(b + n + 2, tlla, 6);
        n += 8;
    }
    return mk_icmp6(f, src, dst, 255, 136, b, n);
}

static size_t mk_udp6(uint8_t *f, const uint8_t *src, const uint8_t *dst, uint16_t sport,
                      uint16_t dport, const char *data)
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
    size_t len = mk_ip6(f, src, dst, 17, 64, u, n);
    fix6(f, len);
    return len;
}

// Tanpa memajukan timer_ticks (uji batas laju).
static void rx_nt(const uint8_t *f, size_t len)
{
    uint8_t *b = malloc(len ? len : 1);
    memcpy(b, f, len);
    g_tx_n = 0;
    net_rx_dispatch(b, (uint32_t)len);
    free(b);
}

// IPv6 hidup dari awal: init + probe DAD sampai UP.
static void ip6_bring_up(void)
{
    g_ip6_cfg = 1;
    g_e1000_rx_initialized = 1;
    ip6_init();
    for (int i = 0; i < 4; i++) {
        ip6_poll();
        timer_ticks += 100;
    }
    g_e1000_rx_initialized = 0;
}

static void ip6_bring_down(void)
{
    g_ip6_cfg = 0;
    ip6_init();
}

static void test_ip6_fmt(void)
{
    char a[40];
    uint8_t x[16] = { 0 };
    ip6_fmt(a, sizeof(a), x);
    CHECK_STR(a, "::");
    x[15] = 1;
    ip6_fmt(a, sizeof(a), x);
    CHECK_STR(a, "::1");
    ip6_fmt(a, sizeof(a), OUR6);
    CHECK_STR(a, "fe80::20c:29ff:fe86:ef48");
    uint8_t y[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    ip6_fmt(a, sizeof(a), y);
    CHECK_STR(a, "2001:db8::1");
    uint8_t z[16] = { 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 4 };
    ip6_fmt(a, sizeof(a), z);   // dua run nol (2 dan 2 grup... pertama menang)
    CHECK_STR(a, "1::2:0:0:3:4");
    uint8_t w[16] = { 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4, 0, 5, 0, 6 };
    ip6_fmt(a, sizeof(a), w);   // nol tunggal tidak dipadatkan
    CHECK_STR(a, "1:0:2:0:3:4:5:6");
    ip6_fmt(a, sizeof(a), SN6);
    CHECK_STR(a, "ff02::1:ff86:ef48");
}

static void test_ip6(void)
{
    uint8_t f[1600];
    size_t n;
    uint8_t snmac[6] = { 0x33, 0x33, 0xff, 0x86, 0xef, 0x48 };

    test_ip6_fmt();

    // Nonaktif (bawaan): frame hanya dihitung ip6_off, tanpa balasan.
    ip6_bring_down();
    CHECK(ip6_up_metric() == 0 && strcmp(ip6_state_name(), "nonaktif") == 0);
    uint64_t off0 = g_ip6_off;
    rx(f, mk_echo6(f, PEER6, OUR6, "halo"));
    CHECK(g_tx_n == 0 && g_ip6_off == off0 + 1);

    // Nyala: link-local EUI-64 dari MAC, DAD dua probe lalu UP.
    g_ip6_cfg = 1;
    g_e1000_rx_initialized = 1;
    ip6_init();
    CHECK(memcmp(g_ip6_ll, OUR6, 16) == 0 && strcmp(ip6_state_name(), "DAD") == 0);
    g_tx_n = 0;
    ip6_poll();   // probe 1 segera
    CHECK(g_tx_n == 1 && g_tx_len[0] == 78 && g_tx_bad == 0);
    CHECK(memcmp(g_tx[0], snmac, 6) == 0 && g_tx[0][12] == 0x86 && g_tx[0][13] == 0xDD);
    CHECK(memcmp(g_tx[0] + 22, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0);   // sumber ::
    CHECK(memcmp(g_tx[0] + 38, SN6, 16) == 0 && g_tx[0][21] == 255 && g_tx[0][54] == 135);
    CHECK(memcmp(g_tx[0] + 62, OUR6, 16) == 0);
    ip6_poll();   // jeda belum lewat
    CHECK(g_tx_n == 1);
    // Selama DAD: echo ke alamat kita tidak dijawab.
    rx_nt(f, mk_echo6(f, PEER6, OUR6, "dini"));
    CHECK(g_tx_n == 0);
    g_tx_n = 0;
    timer_ticks += 100;
    ip6_poll();   // probe 2
    CHECK(g_tx_n == 1 && strcmp(ip6_state_name(), "DAD") == 0);
    timer_ticks += 100;
    ip6_poll();   // selesai
    CHECK(strcmp(ip6_state_name(), "aktif") == 0 && ip6_up_metric() == 1);
    timer_ticks += 100;
    ip6_poll();
    CHECK(g_tx_n == 1);   // tidak ada probe lagi

    // Echo request unicast: reply ke MAC pengirim, sumber kita, hop 64, data sama.
    uint64_t echo0 = g_icmp6_echo;
    rx(f, mk_echo6(f, PEER6, OUR6, "ping6 data"));
    CHECK(g_tx_n == 1 && g_tx_bad == 0 && g_icmp6_echo == echo0 + 1);
    CHECK(memcmp(g_tx[0], PEER_MAC, 6) == 0 && memcmp(g_tx[0] + 22, OUR6, 16) == 0);
    CHECK(memcmp(g_tx[0] + 38, PEER6, 16) == 0 && g_tx[0][20] == 58 && g_tx[0][21] == 64);
    CHECK(g_tx[0][54] == 129 && g_tx[0][55] == 0 && memcmp(g_tx[0] + 58, f + 58, 14) == 0);
    CHECK(g_tx_len[0] == 54 + 18);
    // Padding Ethernet sesudah muatan diterima; satu byte data (muatan 9) juga.
    n = mk_echo6(f, PEER6, OUR6, "x");
    memset(f + n, 0, 8);
    rx(f, n + 8);
    CHECK(g_tx_n == 1 && g_tx_len[0] == 63 && g_tx_bad == 0);

    // Tidak dijawab: checksum salah, hop 0, tujuan multicast, solicited-node, sumber
    // multicast/global/loopback/kita sendiri, kode bukan 0.
    uint64_t bad0 = g_ip6_badsum, drop0 = g_ip6_drop;
    n = mk_echo6(f, PEER6, OUR6, "salah");
    f[54 + 2] ^= 0x5A;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_ip6_badsum == bad0 + 1);
    n = mk_echo6(f, PEER6, OUR6, "x");
    f[21] = 0;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_ip6_drop == drop0 + 1);
    rx(f, mk_echo6(f, PEER6, ALL6, "x"));
    CHECK(g_tx_n == 0);
    rx(f, mk_echo6(f, PEER6, SN6, "x"));
    CHECK(g_tx_n == 0);
    rx(f, mk_echo6(f, ALL6, OUR6, "x"));
    CHECK(g_tx_n == 0);
    rx(f, mk_echo6(f, OUR6, OUR6, "x"));
    CHECK(g_tx_n == 0);
    {
        uint8_t glob[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
        uint8_t lo[16] = { 0 };
        lo[15] = 1;
        rx(f, mk_echo6(f, glob, OUR6, "x"));
        CHECK(g_tx_n == 0);
        rx(f, mk_echo6(f, lo, OUR6, "x"));
        CHECK(g_tx_n == 0);
        // Untuk host lain (bukan kita, bukan multicast kita): diam, tidak dihitung.
        uint64_t rx0 = g_ip6_rx, dr = g_ip6_drop;
        rx(f, mk_echo6(f, PEER6, glob, "x"));
        CHECK(g_tx_n == 0 && g_ip6_rx == rx0 + 1 && g_ip6_drop == dr);
    }
    {
        uint8_t b[8] = { 0x12, 0x34, 0, 1, 0, 0, 0, 0 };
        n = mk_icmp6(f, PEER6, OUR6, 64, 128, b, 4);
        f[55] = 7;   // kode != 0
        fix6(f, n);
        rx(f, n);
        CHECK(g_tx_n == 0);
    }
    // Tipe lain (Redirect 137, RA 134, RS 133, MLD 130) diabaikan tanpa efek.
    {
        uint8_t b[40] = { 0 };
        uint64_t nb = g_nd_bad, ns = g_nd_ns_rx, na = g_nd_na_rx, bs = g_ip6_badsum;
        static const uint8_t ty[4] = { 137, 134, 133, 130 };
        for (int i = 0; i < 4; i++) {
            rx(f, mk_icmp6(f, PEER6, OUR6, 255, ty[i], b, 36));
            CHECK(g_tx_n == 0);
        }
        CHECK(g_nd_bad == nb && g_nd_ns_rx == ns && g_nd_na_rx == na && g_ip6_badsum == bs);
        // Redirect dengan checksum salah juga tidak sampai ke pemeriksaan checksum.
        n = mk_icmp6(f, PEER6, OUR6, 255, 137, b, 36);
        f[56] ^= 1;
        rx(f, n);
        CHECK(g_ip6_badsum == bs);
    }

    // Header/panjang: versi, plen 0, plen > frame, plen > 1460, terpotong.
    n = mk_echo6(f, PEER6, OUR6, "x");
    f[14] = 0x40;
    drop0 = g_ip6_drop;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_ip6_drop == drop0 + 1);
    n = mk_echo6(f, PEER6, OUR6, "x");
    f[18] = f[19] = 0;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_ip6_drop == drop0 + 2);
    n = mk_echo6(f, PEER6, OUR6, "x");
    f[19] += 1;
    rx(f, n);
    CHECK(g_tx_n == 0 && g_ip6_drop == drop0 + 3);
    {
        char big[1500];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = 0;
        n = mk_echo6(f, PEER6, OUR6, big);   // muatan 4 + 1499 > 1460
        rx(f, n);
        CHECK(g_tx_n == 0 && g_ip6_drop == drop0 + 4);
        big[1452] = 0;   // muatan tepat 1460: dijawab, frame 1514
        n = mk_echo6(f, PEER6, OUR6, big);
        rx(f, n);
        CHECK(g_tx_n == 1 && g_tx_len[0] == 1514 && g_tx_bad == 0);
    }
    rx(f, 20);
    CHECK(g_tx_n == 0);

    // Next header: TCP, hop-by-hop (0), routing (43), fragmen (44), ESP/AH, no-next (59).
    {
        uint8_t pl[24] = { 0 };
        uint64_t t0 = g_ip6_tcp_drop, x0 = g_ip6_nxt_drop;
        rx(f, mk_ip6(f, PEER6, OUR6, 6, 64, pl, 24));
        CHECK(g_tx_n == 0 && g_ip6_tcp_drop == t0 + 1);
        static const uint8_t ext[6] = { 0, 43, 44, 50, 51, 59 };
        for (int i = 0; i < 6; i++) {
            rx(f, mk_ip6(f, PEER6, OUR6, ext[i], 64, pl, 24));
            CHECK(g_tx_n == 0);
        }
        CHECK(g_ip6_nxt_drop == x0 + 6 && g_ip6_tcp_drop == t0 + 1);
    }

    // NS unicast dengan SLLA: NA (S|O) ke SLLA, tetangga dipelajari.
    {
        uint8_t m1[6] = { 0x02, 0, 0, 0, 0x0a, 0x01 };
        uint64_t nas = g_nd_na_tx;
        CHECK(ip6_neigh_count() == 0);
        rx(f, mk_ns6(f, PEER6, OUR6, 255, OUR6, m1));
        CHECK(g_tx_n == 1 && g_tx_bad == 0 && g_nd_na_tx == nas + 1 && g_tx_len[0] == 86);
        CHECK(memcmp(g_tx[0], m1, 6) == 0 && memcmp(g_tx[0] + 22, OUR6, 16) == 0);
        CHECK(memcmp(g_tx[0] + 38, PEER6, 16) == 0 && g_tx[0][21] == 255 && g_tx[0][54] == 136);
        CHECK(g_tx[0][58] == 0x60 && memcmp(g_tx[0] + 62, OUR6, 16) == 0);
        CHECK(g_tx[0][78] == 2 && g_tx[0][79] == 1 && memcmp(g_tx[0] + 80, g_e1000_mac, 6) == 0);
        CHECK(ip6_neigh_count() == 1);
        // Ke solicited-node multicast tanpa SLLA: rusak. Dengan SLLA: dijawab.
        uint64_t bad = g_nd_bad;
        rx(f, mk_ns6(f, PEER6, SN6, 255, OUR6, NULL));
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 1);
        rx(f, mk_ns6(f, PEER6, SN6, 255, OUR6, m1));
        CHECK(g_tx_n == 1 && g_tx[0][58] == 0x60);
        // Unicast tanpa SLLA: dijawab ke MAC frame (PEER_MAC).
        rx(f, mk_ns6(f, PEER6, OUR6, 255, OUR6, NULL));
        CHECK(g_tx_n == 1 && memcmp(g_tx[0], PEER_MAC, 6) == 0);
        // Target lain, hop != 255, target multicast, opsi panjang 0 / melewati batas.
        rx(f, mk_ns6(f, PEER6, SN6, 255, PEER6, m1));
        CHECK(g_tx_n == 0);
        bad = g_nd_bad;
        rx(f, mk_ns6(f, PEER6, OUR6, 254, OUR6, m1));
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 1);
        rx(f, mk_ns6(f, PEER6, OUR6, 255, ALL6, m1));
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 2);
        n = mk_ns6(f, PEER6, OUR6, 255, OUR6, m1);
        f[54 + 25] = 0;   // panjang opsi 0
        fix6(f, n);
        rx(f, n);
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 3);
        n = mk_ns6(f, PEER6, OUR6, 255, OUR6, m1);
        f[54 + 25] = 2;   // opsi melewati akhir
        fix6(f, n);
        rx(f, n);
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 4);
        n = mk_ns6(f, PEER6, OUR6, 255, OUR6, m1);
        f[55] = 1;   // kode != 0
        fix6(f, n);
        rx(f, n);
        CHECK(g_tx_n == 0 && g_nd_bad == bad + 5);
        // Terlalu pendek (< 24).
        {
            uint8_t b[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
            rx(f, mk_icmp6(f, PEER6, OUR6, 255, 135, b, 8));
            CHECK(g_tx_n == 0 && g_nd_bad == bad + 6);
        }
        // Checksum NS salah.
        n = mk_ns6(f, PEER6, OUR6, 255, OUR6, m1);
        f[60] ^= 1;
        uint64_t bs = g_ip6_badsum;
        rx(f, n);
        CHECK(g_tx_n == 0 && g_ip6_badsum == bs + 1);
        // NS DAD tetangga (sumber ::) untuk alamat kita saat UP: NA O ke ff02::1.
        {
            uint8_t zero[16] = { 0 };
            uint8_t allmac[6] = { 0x33, 0x33, 0, 0, 0, 1 };
            rx(f, mk_ns6(f, zero, SN6, 255, OUR6, NULL));
            CHECK(g_tx_n == 1 && g_tx[0][58] == 0x20 && memcmp(g_tx[0], allmac, 6) == 0);
            CHECK(memcmp(g_tx[0] + 38, ALL6, 16) == 0);
            // NS DAD dengan SLLA, atau ke unicast: rusak.
            bad = g_nd_bad;
            rx(f, mk_ns6(f, zero, SN6, 255, OUR6, m1));
            CHECK(g_tx_n == 0 && g_nd_bad == bad + 1);
            rx(f, mk_ns6(f, zero, OUR6, 255, OUR6, NULL));
            CHECK(g_tx_n == 0 && g_nd_bad == bad + 2);
            // Sumber :: hanya untuk NS: echo dari :: dibuang.
            rx(f, mk_echo6(f, zero, OUR6, "x"));
            CHECK(g_tx_n == 0);
        }
    }

    // NA: memperbarui entri yang ada, tidak pernah membuat entri; S=1 ke multicast rusak.
    {
        uint8_t m2[6] = { 0x02, 0, 0, 0, 0x0b, 0x02 };
        uint8_t other[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 };
        uint8_t ip[16], mac[6];
        uint64_t na0 = g_nd_na_rx;
        int cnt = ip6_neigh_count();
        rx(f, mk_na6(f, PEER6, OUR6, 0x60, PEER6, m2));
        CHECK(g_tx_n == 0 && g_nd_na_rx == na0 + 1 && ip6_neigh_count() == cnt);
        CHECK(ip6_neigh_get(0, ip, mac) && memcmp(ip, PEER6, 16) == 0 && memcmp(mac, m2, 6) == 0);
        rx(f, mk_na6(f, other, ALL6, 0x20, other, m2));
        CHECK(ip6_neigh_count() == cnt);   // NA tak diminta tidak membuat entri
        uint64_t bad = g_nd_bad;
        rx(f, mk_na6(f, PEER6, ALL6, 0x60, PEER6, m2));
        CHECK(g_nd_bad == bad + 1);
        rx(f, mk_na6(f, PEER6, OUR6, 0x60, ALL6, m2));   // target multicast
        CHECK(g_nd_bad == bad + 2);
    }

    // Tabel tetangga penuh: korban = entri tertua, tabel tetap 8.
    {
        uint8_t src[16];
        uint8_t m[6] = { 0x02, 0, 0, 0, 0x0c, 0 };
        uint8_t ip[16], mac[6];
        uint64_t ev0 = g_nd_evict;
        memcpy(src, PEER6, 16);
        for (int i = 2; i <= 9; i++) {   // PEER6 (::1) sudah ada; ::2..::9
            src[15] = (uint8_t)i;
            m[5] = (uint8_t)i;
            rx(f, mk_ns6(f, src, OUR6, 255, OUR6, m));
            timer_ticks += 1;
        }
        CHECK(ip6_neigh_count() == 8 && g_nd_evict == ev0 + 1);
        int has1 = 0, has9 = 0;
        for (int i = 0; ip6_neigh_get(i, ip, mac); i++) {
            has1 |= ip[15] == 1;
            has9 |= ip[15] == 9;
        }
        CHECK(!has1 && has9);   // ::1 tertua (diperbarui paling awal) tergusur
    }

    // UDP echo 7777: port ditukar, payload sama, checksum sah.
    {
        uint64_t u0 = g_udp6_echo;
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7777, "halo v6"));
        CHECK(g_tx_n == 1 && g_tx_bad == 0 && g_udp6_echo == u0 + 1 && g_tx_len[0] == 69);
        CHECK(g_tx[0][20] == 17 && memcmp(g_tx[0] + 22, OUR6, 16) == 0 && memcmp(g_tx[0] + 38, PEER6, 16) == 0);
        CHECK(g_tx[0][54] == 7777 >> 8 && g_tx[0][55] == (7777 & 0xFF));
        CHECK(g_tx[0][56] == 5000 >> 8 && g_tx[0][57] == (5000 & 0xFF) && memcmp(g_tx[0] + 62, "halo v6", 7) == 0);
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7777, ""));
        CHECK(g_tx_n == 1 && g_tx_len[0] == 62);
        // Checksum nol (dilarang di IPv6) atau salah: dibuang, dihitung.
        uint64_t bs = g_ip6_badsum;
        n = mk_udp6(f, PEER6, OUR6, 5000, 7777, "nol");
        f[54 + 6] = f[54 + 7] = 0;
        rx(f, n);
        CHECK(g_tx_n == 0 && g_ip6_badsum == bs + 1);
        n = mk_udp6(f, PEER6, OUR6, 5000, 7777, "salah");
        f[54 + 8] ^= 1;
        rx(f, n);
        CHECK(g_tx_n == 0 && g_ip6_badsum == bs + 2);
        // Panjang UDP tak sama dengan muatan IPv6; port lain (7778, 7); multicast.
        n = mk_udp6(f, PEER6, OUR6, 5000, 7777, "panjang");
        f[54 + 5] -= 1;
        fix6(f, n);
        rx(f, n);
        CHECK(g_tx_n == 0);
        uint64_t d0 = g_ip6_drop;
        int cc0 = g_cmd_calls;
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7778, "uptime"));
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7, "x"));
        CHECK(g_tx_n == 0 && g_ip6_drop == d0 + 2 && g_cmd_calls == cc0);
        rx(f, mk_udp6(f, PEER6, ALL6, 5000, 7777, "mcast"));
        CHECK(g_tx_n == 0);
        // echo=0 mematikan echo IPv6 juga.
        g_net_echo = 0;
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7777, "mati"));
        CHECK(g_tx_n == 0);
        g_net_echo = 1;
        rx(f, mk_udp6(f, PEER6, OUR6, 5000, 7777, "hidup"));
        CHECK(g_tx_n == 1);
    }

    // Batas laju: 20/s per sumber (g_net_src_rate), sumber lain tetap dilayani;
    // tabel IPv4 tidak tersentuh oleh banjir IPv6.
    {
        net_src_budget_t snap[NET_UDP_SRC_SLOTS];
        memcpy(snap, g_net_src, sizeof(snap));
        timer_ticks += 1000;
        uint64_t r0 = g_ip6_rate_drop;
        int replies = 0;
        n = mk_echo6(f, PEER6, OUR6, "banjir");
        for (int i = 0; i < 30; i++) {
            rx_nt(f, n);
            replies += g_tx_n;
        }
        CHECK(replies == (int)g_net_src_rate && g_ip6_rate_drop == r0 + 30 - g_net_src_rate);
        uint8_t o[16];
        memcpy(o, PEER6, 16);
        o[15] = 0x77;
        rx_nt(f, mk_echo6(f, o, OUR6, "lain"));
        CHECK(g_tx_n == 1);
        // 9 sumber berbeda memenuhi tabel 8 slot (korban tertua), tanpa menyentuh IPv4.
        for (int i = 0; i < 12; i++) {
            o[15] = (uint8_t)(0x80 + i);
            rx_nt(f, mk_echo6(f, o, OUR6, "x"));
        }
        CHECK(memcmp(snap, g_net_src, sizeof(snap)) == 0);
        // Jatah global IPv6 (100/s) terpisah dari IPv4: habis -> dibuang walau sumber baru,
        // tanpa menyentuh counter IPv4; jatah IPv4 yang habis tidak menahan IPv6.
        timer_ticks += 1000;
        g_ip6_bused = NET_UDP_BUDGET_PER_SEC;
        g_ip6_bwin = timer_ticks;
        r0 = g_ip6_rate_drop;
        uint64_t ud0 = g_net_udp_dropped;
        o[15] = 0xC0;
        rx_nt(f, mk_echo6(f, o, OUR6, "global"));
        CHECK(g_tx_n == 0 && g_ip6_rate_drop == r0 + 1 && g_net_udp_dropped == ud0);
        timer_ticks += 1000;
        g_net_budget_used = NET_UDP_BUDGET_PER_SEC;
        g_net_budget_window = timer_ticks;
        o[15] = 0xC1;
        rx_nt(f, mk_echo6(f, o, OUR6, "v4habis"));
        CHECK(g_tx_n == 1 && g_net_udp_dropped == ud0);
        timer_ticks += 1000;
    }

    // DAD konflik: NA untuk target kita saat DAD -> nonaktif, tidak ada balasan lagi.
    {
        uint8_t m2[6] = { 0x02, 0, 0, 0, 0x0d, 0x03 };
        uint64_t c0 = g_ip6_dad_conflict;
        g_ip6_cfg = 1;
        g_e1000_rx_initialized = 1;
        ip6_init();
        g_e1000_rx_initialized = 0;
        ip6_poll();
        CHECK(ip6_neigh_count() == 0 && strcmp(ip6_state_name(), "DAD") == 0);
        rx(f, mk_na6(f, PEER6, ALL6, 0x20, PEER6, m2));   // target lain: tidak konflik
        CHECK(strcmp(ip6_state_name(), "DAD") == 0);
        rx(f, mk_na6(f, PEER6, ALL6, 0x20, OUR6, m2));
        CHECK(strcmp(ip6_state_name(), "nonaktif (DAD konflik)") == 0 && g_ip6_dad_conflict == c0 + 1);
        uint64_t o0 = g_ip6_off, dd0 = g_ip6_drop;
        timer_ticks += 1000;
        ip6_poll();
        rx(f, mk_echo6(f, PEER6, OUR6, "x"));
        // Konflik: frame dihitung ip6_drop (bukan ip6_off, itu hanya untuk nonaktif).
        CHECK(g_tx_n == 0 && g_ip6_off == o0 && g_ip6_drop == dd0 + 1 && ip6_up_metric() == 0);
        // Konflik lewat NS DAD tetangga (sumber ::, target kita) saat DAD.
        uint8_t zero[16] = { 0 };
        g_e1000_rx_initialized = 1;
        ip6_init();
        g_e1000_rx_initialized = 0;
        rx(f, mk_ns6(f, PEER6, OUR6, 255, OUR6, m2));   // NS biasa saat DAD: bukan konflik
        CHECK(strcmp(ip6_state_name(), "DAD") == 0);
        rx(f, mk_ns6(f, zero, SN6, 255, OUR6, NULL));
        CHECK(strcmp(ip6_state_name(), "nonaktif (DAD konflik)") == 0 && g_ip6_dad_conflict == c0 + 2);
    }

    // CONFIG: ipv6 punya kunci, bawaan 0.
    ip6_bring_down();
    CHECK(strcmp(ip6_state_name(), "nonaktif") == 0);
    g_ip6_cfg = 0;
}

// Perbaikan temuan review IPv6: saring dulu baru jatah, jatah IPv6 sendiri, MAC sendiri,
// SLLA, NS dari :: hanya ke solicited-node, muatan ganjil.
static void test_ip6_review(void)
{
    uint8_t f[1600];
    size_t n;
    static const uint8_t zero6[16] = { 0 };

    ip6_bring_up();
    CHECK(ip6_up_metric() == 1);

    // Panjang ganjil: echo ICMPv6 3 byte data (plen 11) dan UDP 3 byte (plen 11);
    // checksum balasan diverifikasi pengait kirim (g_tx_bad).
    timer_ticks += 1000;
    n = mk_echo6(f, PEER6, OUR6, "abc");
    CHECK((f[18] << 8 | f[19]) == 11);
    uint64_t e0 = g_icmp6_echo;
    rx_nt(f, n);
    CHECK(g_tx_n == 1 && g_tx_bad == 0 && g_icmp6_echo == e0 + 1 && g_tx[0][54] == 129);
    CHECK((g_tx[0][18] << 8 | g_tx[0][19]) == 11 && memcmp(g_tx[0] + 54 + 8, "abc", 3) == 0);
    n = mk_udp6(f, PEER6, OUR6, 5001, 7777, "abc");
    CHECK((f[18] << 8 | f[19]) == 11);
    uint64_t u0 = g_udp6_echo;
    rx_nt(f, n);
    CHECK(g_tx_n == 1 && g_tx_bad == 0 && g_udp6_echo == u0 + 1);
    CHECK((g_tx[0][18] << 8 | g_tx[0][19]) == 11 && memcmp(g_tx[0] + 54 + 8, "abc", 3) == 0);

    // RA/MLD/RS ke ff02::1 tidak menyentuh jatah (IPv6 maupun IPv4) dan tidak dibalas.
    {
        timer_ticks += 1000;
        uint8_t b[40] = { 0 };
        uint8_t o[16];
        static const uint8_t ty[3] = { 134, 130, 133 };
        uint32_t used6 = g_ip6_bused;
        uint32_t used4 = g_net_budget_used;
        uint64_t d4 = g_net_udp_dropped, s4 = g_net_udp_src_dropped;
        uint64_t rd = g_ip6_rate_drop, ig = g_ip6_ignored;
        net_src_budget_t snap[NET_UDP_SRC_SLOTS];
        memcpy(snap, g_net_src, sizeof(snap));

        memcpy(o, PEER6, 16);
        for (int i = 0; i < 300; i++) {
            o[15] = (uint8_t)(i + 2);
            rx_nt(f, mk_icmp6(f, o, ALL6, 255, ty[i % 3], b, 36));
            CHECK(g_tx_n == 0);
        }
        CHECK(g_ip6_bused == used6 && g_net_budget_used == used4);
        CHECK(g_net_udp_dropped == d4 && g_net_udp_src_dropped == s4 && g_ip6_rate_drop == rd);
        CHECK(g_ip6_ignored == ig + 300 && memcmp(snap, g_net_src, sizeof(snap)) == 0);

        // Banjir tipe diabaikan tidak membuat UDP echo IPv4 (dan IPv6) kelaparan.
        rx_nt(f, mk_udp(f, 5000, 7777, "echo4", 0));
        CHECK(g_tx_n == 1);
        timer_ticks += 1000;
        rx_nt(f, mk_udp6(f, PEER6, OUR6, 5002, 7777, "echo6"));
        CHECK(g_tx_n == 1);
        // Unicast host lain dihitung diabaikan, bukan jatah.
        uint8_t other[16];
        memcpy(other, OUR6, 16);
        other[15] ^= 0x55;
        ig = g_ip6_ignored;
        rx_nt(f, mk_echo6(f, PEER6, other, "x"));
        CHECK(g_tx_n == 0 && g_ip6_ignored == ig + 1);
    }

    // SLLA harus sama dengan MAC sumber Ethernet: beda -> dibuang, nd_bad, tanpa NA
    // dan tanpa entri tetangga; sama -> NA ke MAC itu.
    {
        timer_ticks += 1000;
        uint8_t m1[6] = { 0x02, 0, 0, 0, 0x0b, 0x01 };
        uint64_t nb = g_nd_bad;
        int nc = ip6_neigh_count();
        n = mk_ns6(f, PEER6, SN6, 255, OUR6, m1);
        memcpy(f + 6, PEER_MAC, 6);   // MAC Ethernet berbeda dari SLLA
        rx_nt(f, n);
        CHECK(g_tx_n == 0 && g_nd_bad == nb + 1 && ip6_neigh_count() == nc);
        rx_nt(f, mk_ns6(f, PEER6, SN6, 255, OUR6, m1));
        CHECK(g_tx_n == 1 && g_tx_bad == 0 && memcmp(g_tx[0], m1, 6) == 0);
    }

    // NS dari :: ke ff02::1 (bukan solicited-node kita): dibuang, nd_bad, tanpa NA.
    {
        timer_ticks += 1000;
        uint64_t nb = g_nd_bad;
        rx_nt(f, mk_ns6(f, zero6, ALL6, 255, OUR6, NULL));
        CHECK(g_tx_n == 0 && g_nd_bad == nb + 1);
        rx_nt(f, mk_ns6(f, zero6, SN6, 255, OUR6, NULL));   // ke solicited-node: NA ke ff02::1
        CHECK(g_tx_n == 1 && g_tx[0][38] == 0xff && g_tx[0][39] == 0x02 && g_tx[0][53] == 1);
    }

    // DAD: NS dari :: ke ff02::1 bukan konflik; NS/NA berMAC sumber kita sendiri
    // (pantulan, RFC 4862 5.4.3) bukan konflik; NS dari MAC lain tetap konflik.
    {
        uint64_t c0 = g_ip6_dad_conflict, ig;
        g_ip6_cfg = 1;
        g_e1000_rx_initialized = 1;
        ip6_init();
        g_e1000_rx_initialized = 0;
        ip6_poll();
        CHECK(strcmp(ip6_state_name(), "DAD") == 0);
        rx_nt(f, mk_ns6(f, zero6, ALL6, 255, OUR6, NULL));
        CHECK(strcmp(ip6_state_name(), "DAD") == 0 && g_ip6_dad_conflict == c0);
        ig = g_ip6_ignored;
        n = mk_ns6(f, zero6, SN6, 255, OUR6, NULL);
        memcpy(f + 6, g_e1000_mac, 6);
        rx_nt(f, n);
        CHECK(strcmp(ip6_state_name(), "DAD") == 0 && g_ip6_dad_conflict == c0 &&
              g_ip6_ignored == ig + 1);
        n = mk_na6(f, PEER6, ALL6, 0x20, OUR6, g_e1000_mac);
        memcpy(f + 6, g_e1000_mac, 6);
        rx_nt(f, n);
        CHECK(strcmp(ip6_state_name(), "DAD") == 0 && g_ip6_dad_conflict == c0 &&
              g_ip6_ignored == ig + 2);
        rx_nt(f, mk_ns6(f, zero6, SN6, 255, OUR6, NULL));   // MAC sumber PEER_MAC: konflik
        CHECK(strcmp(ip6_state_name(), "nonaktif (DAD konflik)") == 0 &&
              g_ip6_dad_conflict == c0 + 1);
    }
    ip6_bring_down();
}

// Frame contoh untuk dipotong dan diacak.
#define NTPL 14
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
    // F7: IPv6 (butuh ip6 UP, lihat ip6_bring_up).
    static const uint8_t mac1[6] = { 0x02, 0, 0, 0, 0x0a, 0x01 };
    static const uint8_t zero6[16] = { 0 };
    g_tpl_len[9] = mk_echo6(g_tpl[9], PEER6, OUR6, "ping6 ping6");
    g_tpl_len[10] = mk_ns6(g_tpl[10], PEER6, SN6, 255, OUR6, mac1);
    g_tpl_len[11] = mk_udp6(g_tpl[11], PEER6, OUR6, 5000, 7777, "echo6 echo6");
    g_tpl_len[12] = mk_ns6(g_tpl[12], zero6, SN6, 255, OUR6, NULL);
    g_tpl_len[13] = mk_na6(g_tpl[13], PEER6, ALL6, 0x20, OUR6, mac1);
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

    // B. Keluaran 1307 byte (> buffer 1024) dialirkan bertahap; baris yang
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
    for (int i = 0; i < 5 && glen < 1307; i++) {
        rx(f, mk_tcp_w(f, g_pseq, una + glen, F_ACK, 0, 0, 4096));
        s = tx_seg(0);
        if (g_tx_n != 1 || s.len == 0 || s.seq != una + glen) {
            break;
        }
        memcpy(got + glen, s.data, s.len);
        glen += s.len;
    }
    // "big" tanpa '\n' di akhir: net.c menambahkannya sebelum END (temuan VMware `pci`).
    int pat = glen == 1307 && memcmp(got + 1300, "\nEND 1\n", 7) == 0;
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

// D7: echo=0 -> UDP 7777 diam, SYN port 7 dibalas RST (port 7779 tetap);
// udp_rate mengganti batas per IP.
static void test_config_vals(void)
{
    uint8_t f[600];
    tcp_reset();

    g_net_echo = 0;
    rx(f, mk_udp(f, 5000, 7777, "halo", 0));
    CHECK(g_tx_n == 0);
    rx(f, mk_tcp(f, 4000, 7, 1000, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && g_tx[0][34 + 13] == (F_RST | F_ACK) && g_tcbs[0].state == TCP_CLOSED);
    rx(f, mk_tcp(f, 4001, NET_TCP_CLI_PORT, 1000, 0, F_SYN, ""));
    CHECK(g_tx_n >= 1 && g_tx[0][34 + 13] == (F_SYN | F_ACK));
    tcp_reset();

    g_net_echo = 1;
    rx(f, mk_udp(f, 5000, 7777, "halo", 0));
    CHECK(g_tx_n == 1);
    rx(f, mk_tcp(f, 4000, 7, 1000, 0, F_SYN, ""));
    CHECK(g_tx_n >= 1 && g_tx[0][34 + 13] == (F_SYN | F_ACK));
    tcp_reset();

    int n5 = 0, n20 = 0;
    g_net_src_rate = 5;
    timer_ticks += 100;
    for (int i = 0; i < 12; i++) {
        rx_now(f, mk_udp(f, 5000, 7777, "x", 0));
        n5 += g_tx_n;
    }
    g_net_src_rate = NET_UDP_SRC_PER_SEC;
    timer_ticks += 100;
    for (int i = 0; i < 30; i++) {
        rx_now(f, mk_udp(f, 5000, 7777, "x", 0));
        n20 += g_tx_n;
    }
    CHECK(n5 == 5 && n20 == NET_UDP_SRC_PER_SEC);
    timer_ticks += 100;
}

// ---- D9: TLS port 7780 (kernel/tls.c + BearSSL) ----

// Stub fat32_read_name: hanya TLSKEY.DER / TLSCERT.DER dari g_fk/g_fc.
static const uint8_t *g_fk, *g_fc;
static uint32_t g_fk_len, g_fc_len;
static const uint8_t *g_fsk;   // F7 SSH-1b: SSHKEY.DER
static uint32_t g_fsk_len;

int fat32_read_name(const char *name83, uint8_t *out, uint32_t max, uint32_t *out_size)
{
    const uint8_t *d = 0;
    uint32_t n = 0;
    if (memcmp(name83, "TLSKEY  DER", 11) == 0) {
        d = g_fk;
        n = g_fk_len;
    } else if (memcmp(name83, "TLSCERT DER", 11) == 0) {
        d = g_fc;
        n = g_fc_len;
    } else if (memcmp(name83, "SSHKEY  DER", 11) == 0) {
        d = g_fsk;
        n = g_fsk_len;
    }
    if (d == 0) {
        return FAT32_ERR_NOENT;
    }
    if (n > max) {
        return FAT32_ERR_TOOBIG;
    }
    memcpy(out, d, n);
    *out_size = n;
    return FAT32_OK;
}

// Stub cmd_puts (tls_status) ke buffer.
static char g_cmdbuf[2048];
static size_t g_cmdbuf_len;

void cmd_puts(const char *s)
{
    size_t n = strlen(s);
    if (g_cmdbuf_len + n < sizeof(g_cmdbuf)) {
        memcpy(g_cmdbuf + g_cmdbuf_len, s, n + 1);
        g_cmdbuf_len += n;
    }
}

// ---- R2: netconsole ----
// Datagram netcon ke-i di g_tx: payload (diakhiri '\0') bila frame UDP sah ke
// PEER_MAC/.1:6666 dari port 6665, selain itu NULL.
static uint16_t nc_get16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static const char *nc_payload(int i)
{
    static char pl[2048];
    const uint8_t *p = g_tx[i];

    if (g_tx_len[i] < 60 || p[12] != 0x08 || p[13] != 0x00 || p[23] != 17 ||
        memcmp(p, PEER_MAC, 6) != 0 || memcmp(p + 30, PEER_IP, 4) != 0 ||
        nc_get16(p + 34) != NETCON_SRC_PORT || nc_get16(p + 36) != g_netcon_port) {
        return NULL;
    }
    uint32_t n = nc_get16(p + 38) - 8;
    memcpy(pl, p + 42, n);
    pl[n] = '\0';
    return pl;
}

static int nc_is_arp_req(int i, uint8_t host)
{
    const uint8_t *p = g_tx[i];
    static const uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t h[8] = { 0, 1, 8, 0, 6, 4, 0, 1 };

    return g_tx_len[i] == 60 && memcmp(p, bc, 6) == 0 && memcmp(p + 6, g_e1000_mac, 6) == 0 &&
           p[12] == 0x08 && p[13] == 0x06 && memcmp(p + 14, h, 8) == 0 &&
           memcmp(p + 22, g_e1000_mac, 6) == 0 && memcmp(p + 28, OUR_IP, 4) == 0 &&
           p[38] == 192 && p[39] == 168 && p[40] == 50 && p[41] == host;
}

static int nc_queued(void)
{
    return (int)(g_nc_head - g_nc_tail);
}

static void test_netcon(void)
{
    char line[200];
    uint8_t f[64];

    g_e1000_rx_initialized = 1;
    g_netcon_on = 0;
    g_netcon_host = 1;
    g_netcon_port = 6666;
    serial_capture_reset();
    netcon_init();
    CHECK(g_nc_page_phys != 0);
    CHECK(strstr(g_serial_cap, "R2: netcon siap aktif=0 tujuan=192.168.50.1:6666\r\n") != NULL);

    // nonaktif: baris tidak diantre, tidak ada TX
    netcon_line("abc", 3);
    g_tx_n = 0;
    netcon_poll();
    CHECK(nc_queued() == 0 && g_tx_n == 0);

    // aktif tanpa MAC: ARP request maks 1x per 100 tick, baris ditahan
    g_netcon_on = 1;
    timer_ticks += 1000;
    g_tx_n = 0;
    netcon_poll();
    CHECK(g_tx_n == 1 && nc_is_arp_req(0, 1));
    netcon_poll();
    timer_ticks += 99;
    netcon_poll();
    CHECK(g_tx_n == 1);
    timer_ticks += 1;
    netcon_poll();
    CHECK(g_tx_n == 2 && nc_is_arp_req(1, 1) && g_nc_arp == 2);

    // antrean penuh: 40 baris x 101 byte muat (4040), 5 sisanya dibuang
    for (int i = 0; i < 45; i++) {
        memset(line, 'a' + i % 26, 100);
        netcon_line(line, 100);
    }
    CHECK(nc_queued() == 4040 && g_nc_lost == 5 && g_nc_lost_pending == 5);

    // ARP dari IP lain / pengirim multicast / MAC nol: diabaikan
    mk_arp(f, OUR_IP);
    f[31] = 9;
    rx(f, 60);
    CHECK(!g_nc_mac_ok);
    mk_arp(f, OUR_IP);
    f[22] = 0x01;
    rx(f, 60);
    CHECK(!g_nc_mac_ok);
    mk_arp(f, OUR_IP);
    memset(f + 22, 0, 6);
    rx(f, 60);
    CHECK(!g_nc_mac_ok);

    // ARP request dari .1 (juga dibalas seperti biasa): MAC dipelajari
    serial_capture_reset();
    mk_arp(f, OUR_IP);
    rx(f, 60);
    CHECK(g_nc_mac_ok && memcmp(g_nc_mac, PEER_MAC, 6) == 0 && g_tx_n == 1);
    CHECK(strstr(g_serial_cap, "R2: netcon MAC tujuan 192.168.50.1 = 02:00:00:00:00:01\r\n"));
    // baris MAC itu sendiri tidak masuk antrean di host (log_capture = kernel.c)
    CHECK(nc_queued() == 4040);

    // datagram pertama: penanda + baris utuh, <= 1024 byte
    g_tx_n = 0;
    g_tx_bad = 0;
    netcon_poll();
    const char *pl = nc_payload(0);
    CHECK(g_tx_n == 1 && pl != NULL);
    CHECK(pl && strncmp(pl, "netcon: 5 baris dibuang\n", 24) == 0);
    CHECK(pl && strlen(pl) <= 1024 && pl[strlen(pl) - 1] == '\n');
    CHECK(pl && strlen(pl) == 24 + 9 * 101);   // 24 + 9 baris = 933, baris ke-10 tidak muat
    CHECK(g_nc_lost_pending == 0 && g_nc_sent == 1);

    // sisa: 31 baris -> 4 datagram (10+10+10+1)
    int got = 1;
    for (int i = 0; i < 10; i++) {
        netcon_poll();
    }
    got = g_tx_n;
    CHECK(got == 5 && nc_queued() == 0 && g_tx_bad == 0);
    for (int i = 1; i < got && i < TX_MAX; i++) {
        pl = nc_payload(i);
        CHECK(pl != NULL && pl[0] == 'a' + (9 + 10 * (i - 1)) % 26);
    }

    // batas laju: 20 datagram per jendela 100 tick
    timer_ticks += 100;
    g_tx_n = 0;
    for (int i = 0; i < 30; i++) {
        netcon_line("x", 1);
        netcon_poll();
    }
    CHECK(g_tx_n == 20 && nc_queued() == 20);
    netcon_poll();
    CHECK(g_tx_n == 20);
    timer_ticks += 100;
    netcon_poll();
    CHECK(g_tx_n == 21 && nc_queued() == 0);
    pl = nc_payload(20 % TX_MAX);
    (void)pl;

    // panic: kirim semua tanpa batas laju (jendela sudah dipakai)
    for (int i = 0; i < 19; i++) {
        netcon_line("x", 1);
        netcon_poll();
    }
    CHECK(g_tx_n == 40);
    for (int i = 0; i < 45; i++) {
        memset(line, 'p', 100);
        netcon_line(line, 100);
    }
    netcon_poll();
    CHECK(g_tx_n == 40);
    g_tx_n = 0;
    netcon_panic_flush();
    CHECK(g_tx_n == 5 && nc_queued() == 0 && g_tx_bad == 0);
    pl = nc_payload(0);
    CHECK(pl && strncmp(pl, "netcon: 5 baris dibuang\npppp", 28) == 0);

    // g_netcon_hold (panic: register umum): baris tidak diantre
    g_netcon_hold = 1;
    netcon_line("PANIC: RAX=1", 12);
    g_netcon_hold = 0;
    CHECK(nc_queued() == 0);

    // status
    g_cmdbuf_len = 0;
    g_cmdbuf[0] = '\0';
    netcon_status();
    CHECK(strstr(g_cmdbuf, "netcon: aktif=1 tujuan=192.168.50.1:6666 port_sumber=6665\n"
                           "netcon: mac=02:00:00:00:00:01 arp=2\n"
                           "netcon: terkirim=") != NULL);
    CHECK(strstr(g_cmdbuf, " antre=0 dibuang=10 tx_gagal=0\n") != NULL);

    // port berubah langsung dipakai; host berubah -> MAC lupa, ARP ke host baru
    g_netcon_port = 17666;
    netcon_line("p", 1);
    timer_ticks += 100;
    g_tx_n = 0;
    netcon_poll();
    CHECK(g_tx_n == 1 && nc_payload(0) && strcmp(nc_payload(0), "p\n") == 0);
    g_netcon_host = 9;
    netcon_line("q", 1);
    g_tx_n = 0;
    netcon_poll();
    CHECK(g_tx_n == 1 && nc_is_arp_req(0, 9) && !g_nc_mac_ok && nc_queued() == 2);
    g_tx_n = 0;
    netcon_panic_flush();
    CHECK(g_tx_n == 0);   // tanpa MAC: panic tidak mengirim

    // netcon=0: antrean dikosongkan, tidak ada TX
    g_netcon_on = 0;
    netcon_poll();
    CHECK(nc_queued() == 0 && g_tx_n == 0);
    netcon_line("r", 1);
    CHECK(nc_queued() == 0);

    // tanpa NIC
    g_e1000_rx_initialized = 0;
    g_cmdbuf_len = 0;
    netcon_status();
    CHECK(strcmp(g_cmdbuf, "netcon: NIC tidak ada\n") == 0);

    // ARP peer tiba sebelum poll pertama setelah netcon dinyalakan (VMware:
    // Windows ARP duluan): MAC tetap, tanpa ARP request baru.
    g_e1000_rx_initialized = 1;
    g_netcon_host = 1;
    netcon_poll();            // sinkron: netcon=0
    g_netcon_on = 1;
    mk_arp(f, OUR_IP);
    rx(f, 60);
    CHECK(g_nc_mac_ok);
    uint64_t arp0 = g_nc_arp;
    g_tx_n = 0;
    netcon_line("s", 1);
    netcon_poll();
    CHECK(g_nc_mac_ok && g_nc_arp == arp0 && g_tx_n == 1 && nc_payload(0) &&
          strcmp(nc_payload(0), "s\n") == 0);
    g_netcon_on = 0;
    netcon_poll();
    g_e1000_rx_initialized = 0;

    g_netcon_host = 1;
    g_netcon_port = 6666;
}

static void tls_files(const uint8_t *k, uint32_t kl, const uint8_t *ce, uint32_t cl)
{
    g_fk = k;
    g_fk_len = kl;
    g_fc = ce;
    g_fc_len = cl;
    serial_capture_reset();
    tls_load();
}

// ---- klien TCP+TLS tiruan ----
static uint32_t g_rnxt;              // byte server berikutnya yang diharapkan
static uint8_t g_inbox[65536];       // byte TCP dari server belum masuk engine klien
static size_t g_inbox_len;
static uint8_t g_raw[65536];         // semua byte TCP dari server (cek plaintext)
static size_t g_raw_len;
static int g_rst_seen, g_fin_seen;
static char g_app[8192];             // plaintext yang diterima klien
static size_t g_app_len;

static br_ssl_client_context g_cc;
static br_x509_minimal_context g_xm;
static br_x509_knownkey_context g_xk;
static uint8_t g_cbuf[BR_SSL_BUFSIZE_BIDI];
static uint8_t g_kq[65];
static br_ec_public_key g_kpub;

// Proses frame keluaran server dari rx terakhir: ACK -> g_pseq, data/FIN
// dalam urutan -> inbox, lalu ACK balik (memicu segmen berikutnya).
static void srv_collect(void)
{
    static uint8_t f[200];
    for (int round = 0; round < 200; round++) {
        int fresh = 0;
        int n = g_tx_n < TX_MAX ? g_tx_n : TX_MAX;
        for (int i = 0; i < n; i++) {
            struct seg s = tx_seg(i);
            if (s.flags & F_RST) {
                g_rst_seen = 1;
                continue;
            }
            if ((s.flags & F_ACK) && (int32_t)(s.ack - g_pseq) > 0) {
                g_pseq = s.ack;
            }
            if (s.len > 0 && s.seq == g_rnxt) {
                if (g_inbox_len + s.len <= sizeof(g_inbox) &&
                    g_raw_len + s.len <= sizeof(g_raw)) {
                    memcpy(g_inbox + g_inbox_len, s.data, s.len);
                    memcpy(g_raw + g_raw_len, s.data, s.len);
                    g_inbox_len += s.len;
                    g_raw_len += s.len;
                    g_rnxt += s.len;
                    fresh = 1;
                }
            }
            if ((s.flags & F_FIN) && s.seq + s.len == g_rnxt && !g_fin_seen) {
                g_fin_seen = 1;
                g_rnxt++;
                fresh = 1;
            }
        }
        if (!fresh) {
            return;
        }
        rx_now(f, mk_tcp_w(f, g_pseq, g_rnxt, F_ACK, 0, 0, 4096));
    }
}

// Kirim n byte ke server; return byte yang di-ACK.
static uint32_t srv_send(const uint8_t *d, size_t n)
{
    static uint8_t f[1700];
    uint32_t before = g_pseq;
    rx_now(f, mk_tcp_w(f, g_pseq, g_rnxt, F_ACK | 0x08, d, n, 4096));
    srv_collect();
    return g_pseq - before;
}

// Jalankan engine klien sampai tidak ada kemajuan.
static void cl_run(void)
{
    br_ssl_engine_context *e = &g_cc.eng;
    for (int it = 0; it < 500; it++) {
        int prog = 0;
        size_t len;
        unsigned char *b;
        if (g_rst_seen) {
            return;
        }
        b = br_ssl_engine_sendrec_buf(e, &len);
        if (b && len) {
            uint32_t acc = srv_send(b, len > 536 ? 536 : len);
            br_ssl_engine_sendrec_ack(e, acc);
            prog |= acc > 0;
        }
        if (g_inbox_len) {
            b = br_ssl_engine_recvrec_buf(e, &len);
            if (b && len) {
                size_t m = len < g_inbox_len ? len : g_inbox_len;
                memcpy(b, g_inbox, m);
                memmove(g_inbox, g_inbox + m, g_inbox_len - m);
                g_inbox_len -= m;
                br_ssl_engine_recvrec_ack(e, m);
                prog = 1;
            }
        }
        b = br_ssl_engine_recvapp_buf(e, &len);
        if (b && len) {
            size_t m = len < sizeof(g_app) - 1 - g_app_len ? len : sizeof(g_app) - 1 - g_app_len;
            memcpy(g_app + g_app_len, b, m);
            g_app_len += m;
            g_app[g_app_len] = 0;
            br_ssl_engine_recvapp_ack(e, len);
            prog = 1;
        }
        if (!prog) {
            return;
        }
    }
}

// Kirim plaintext dari klien.
static void cl_write(const char *s)
{
    br_ssl_engine_context *e = &g_cc.eng;
    size_t n = strlen(s), off = 0;
    while (off < n) {
        size_t len;
        unsigned char *b = br_ssl_engine_sendapp_buf(e, &len);
        if (!b) {
            cl_run();
            if (!br_ssl_engine_sendapp_buf(e, &len)) {
                return;
            }
            continue;
        }
        size_t m = n - off < len ? n - off : len;
        memcpy(b, s + off, m);
        br_ssl_engine_sendapp_ack(e, m);
        off += m;
    }
    br_ssl_engine_flush(e, 0);
    cl_run();
}

// Kunci publik sertifikat (pin) untuk klien.
static void cl_pin(const uint8_t *cert, size_t n)
{
    br_x509_decoder_context dc;
    br_x509_decoder_init(&dc, 0, 0);
    br_x509_decoder_push(&dc, cert, n);
    br_x509_pkey *pk = br_x509_decoder_get_pkey(&dc);
    memcpy(g_kq, pk->key.ec.q, pk->key.ec.qlen);
    g_kpub.curve = pk->key.ec.curve;
    g_kpub.q = g_kq;
    g_kpub.qlen = pk->key.ec.qlen;
}

// TCP ke 7780 + klien TLS dengan satu suite; pin = sertifikat `pin`.
static void tls_connect(uint16_t suite, const uint8_t *pin, size_t pin_len)
{
    static const uint8_t seed[32] = { 7, 7, 7 };
    uint16_t suites[1] = { suite };
    g_wport = 7780;
    tcp_open(30000, 31000, 4096);
    g_rnxt = g_iss + 1;
    g_inbox_len = g_raw_len = g_app_len = 0;
    g_app[0] = 0;
    g_rst_seen = g_fin_seen = 0;
    cl_pin(pin, pin_len);
    br_ssl_client_init_full(&g_cc, &g_xm, 0, 0);
    br_x509_knownkey_init_ec(&g_xk, &g_kpub, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN);
    br_ssl_engine_set_x509(&g_cc.eng, &g_xk.vtable);
    br_ssl_engine_set_suites(&g_cc.eng, suites, 1);
    br_ssl_engine_set_buffer(&g_cc.eng, g_cbuf, sizeof(g_cbuf), 1);
    br_ssl_engine_inject_entropy(&g_cc.eng, seed, sizeof(seed));
    br_ssl_client_reset(&g_cc, 0, 0);
    cl_run();
}

static int raw_has(const char *s)
{
    size_t n = strlen(s);
    for (size_t i = 0; i + n <= g_raw_len; i++) {
        if (memcmp(g_raw + i, s, n) == 0) {
            return 1;
        }
    }
    return 0;
}

// Banner "bmahOS login\nnonce: <32 hex>\n" diterima lewat TLS.
static int tls_banner_ok(void)
{
    return g_app_len == BLEN && memcmp(g_app, "bmahOS login\nnonce: ", 20) == 0 &&
           g_app[BLEN - 1] == '\n';
}

static void test_tls_load(void)
{
    static uint8_t f[200];
    uint8_t junk[100];

    // Tanpa file: nonaktif, SYN 7780 -> RST, 7779 tetap.
    tls_files(0, 0, 0, 0);
    CHECK(!tls_enabled() && strstr(g_serial_cap, "TLS: nonaktif (TLSKEY.DER tidak ada)"));
    tcp_reset();
    rx(f, mk_tcp(f, 4000, 7780, 1000, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_tcbs[0].state == TCP_CLOSED);

    // Kunci ada, sertifikat tidak.
    tls_files(T_KEYA, sizeof(T_KEYA), 0, 0);
    CHECK(!tls_enabled() && strstr(g_serial_cap, "TLSCERT.DER tidak ada"));

    // Kunci dan sertifikat beda pasangan.
    tls_files(T_KEYA, sizeof(T_KEYA), T_CERTB, sizeof(T_CERTB));
    CHECK(!tls_enabled() && strstr(g_serial_cap, "tidak cocok dengan TLSKEY.DER"));

    // Kunci bukan DER EC.
    tls_files(T_CERTA, sizeof(T_CERTA), T_CERTA, sizeof(T_CERTA));
    CHECK(!tls_enabled() && strstr(g_serial_cap, "bukan kunci EC"));

    // Sertifikat rusak.
    memset(junk, 0x30, sizeof(junk));
    tls_files(T_KEYA, sizeof(T_KEYA), junk, sizeof(junk));
    CHECK(!tls_enabled() && strstr(g_serial_cap, "bukan sertifikat X.509"));

    // Kunci terlalu besar (> 512 byte).
    tls_files(g_raw, 600, T_CERTA, sizeof(T_CERTA));
    CHECK(!tls_enabled() && strstr(g_serial_cap, "gagal dibaca/terlalu besar"));

    // PKCS#8 juga diterima; pin = sha256 sertifikat.
    tls_files(T_KEYA8, sizeof(T_KEYA8), T_CERTA, sizeof(T_CERTA));
    CHECK(tls_enabled() && strstr(g_serial_cap, "TLS: aktif port 7780 pin=") &&
          strstr(g_serial_cap, T_CERTA_PIN));

    tls_files(T_KEYA, sizeof(T_KEYA), T_CERTA, sizeof(T_CERTA));
    CHECK(tls_enabled());
    g_cmdbuf_len = 0;
    tls_status();
    CHECK(strstr(g_cmdbuf, "tls: aktif port 7780\npin: ") && strstr(g_cmdbuf, T_CERTA_PIN) &&
          strstr(g_cmdbuf, "sesi: aktif=0 maks=2"));
}

static void tcp_reset_tls(void)
{
    for (int k = 0; k < TCP_MAX_CONN; k++) {
        net_tcp_tls_release(&g_tcbs[k]);
    }
    tcp_reset();
}

static void test_tls_session(uint16_t suite)
{
    uint64_t ok0 = g_tls_hs_ok, login0 = g_cli_login_ok;
    br_ssl_session_parameters sp;
    char want[2000];

    tls_connect(suite, T_CERTA, sizeof(T_CERTA));
    CHECK(g_tcbs[0].tls == 1 && g_tcbs[0].app == TCP_APP_CLI && tls_sess_active() == 1);
    CHECK(tls_banner_ok() && !g_rst_seen && g_tls_hs_ok == ok0 + 1);
    br_ssl_engine_get_session_parameters(&g_cc.eng, &sp);
    CHECK(sp.cipher_suite == suite && tls_suite(0) == suite);
    CHECK(strstr(g_serial_cap, suite == BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ?
                 "D9: TLS handshake OK suite=c02b" : "D9: TLS handshake OK suite=cca9"));

    // Login + perintah lewat TLS; nonce banner = nonce yang dipakai login.
    g_app_len = 0;
    char line[80];
    memcpy(line, "login ", 6);
    memset(line + 6, 'a', 64);
    memcpy(line + 70, "\n", 2);
    cl_write(line);
    CHECK(strcmp(g_app, "OK login\n") == 0 && g_cli_login_ok == login0 + 1);
    CHECK(g_au.chan == AUDIT_TLS);
    g_app_len = 0;
    cl_write(cmd_line("ping", 1));
    CHECK(strcmp(g_app, "ping\nEND 1\n") == 0);

    // Keluaran besar (1300 + END) lewat beberapa record.
    g_app_len = 0;
    cl_write(cmd_line("big", 2));
    for (int i = 0; i < 1300; i++) {
        want[i] = (char)('a' + i % 26);
    }
    memcpy(want + 1300, "\nEND 2\n", 8);
    CHECK(g_app_len == 1307 && memcmp(g_app, want, 1307) == 0);

    // Tidak ada plaintext di kabel.
    CHECK(!raw_has("bmahOS login") && !raw_has("nonce:") && !raw_has("OK login") &&
          !raw_has("END 1") && !raw_has("abcdefghij"));

    // exit: bye + close_notify + FIN; balasan close_notify klien dibuang, bukan RST.
    uint64_t rst0 = g_tcp_rst_state;
    g_app_len = 0;
    cl_write(cmd_line("exit", 3));
    CHECK(strcmp(g_app, "bye\nEND 3\n") == 0);
    CHECK(g_fin_seen && !g_rst_seen);
    CHECK(br_ssl_engine_current_state(&g_cc.eng) == BR_SSL_CLOSED &&
          br_ssl_engine_last_error(&g_cc.eng) == BR_ERR_OK);
    cl_run();
    CHECK(g_tcp_rst_state == rst0 && !g_rst_seen);
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_2 || g_tcbs[0].state == TCP_TIME_WAIT);
    CHECK(g_tx_bad == 0);
    tcp_reset_tls();
    CHECK(tls_sess_active() == 0);
}

static void test_tls_fail(void)
{
    static uint8_t f[200];
    uint64_t fail0 = g_tls_fail;

    // Pin salah: klien menolak tanda tangan server -> alert -> server RST.
    tls_connect(BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, T_CERTB, sizeof(T_CERTB));
    CHECK(br_ssl_engine_last_error(&g_cc.eng) != BR_ERR_OK && g_app_len == 0);
    {
        // Klien BearSSL berhenti tanpa alert; OpenSSL/SChannel mengirim alert
        // fatal (handshake_failure) lalu menutup: tiru itu.
        static const uint8_t alert[7] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };
        srv_send(alert, sizeof(alert));
    }
    CHECK(g_rst_seen && g_tcbs[0].state == TCP_CLOSED && tls_sess_active() == 0);
    CHECK(g_tls_fail == fail0 + 1 && g_app_len == 0);
    tcp_reset_tls();

    // Sampah (bukan record TLS) -> RST, slot dibebaskan.
    g_wport = 7780;
    tcp_open(40000, 41000, 4096);
    g_rnxt = g_iss + 1;
    g_rst_seen = 0;
    srv_send((const uint8_t *)"GET / HTTP/1.0\r\n\r\n", 18);
    CHECK(g_rst_seen && g_tcbs[0].state == TCP_CLOSED && tls_sess_active() == 0);
    CHECK(g_tls_fail == fail0 + 2 && strstr(g_serial_cap, "D9: TLS gagal err="));
    tcp_reset_tls();

    // Login timeout selama handshake belum mulai: FIN langsung (tanpa TLS close).
    g_wport = 7780;
    tcp_open(42000, 43000, 4096);
    g_rnxt = g_iss + 1;
    g_fin_seen = 0;
    for (int i = 0; i < 1100 && !g_fin_seen; i++) {
        step();
        srv_collect();
    }
    CHECK(g_fin_seen && g_tcbs[0].state == TCP_FIN_WAIT_2);
    tcp_reset_tls();

    // Entropi belum cukup: SYN 7780 dibuang tanpa slot.
    g_entropy_ok = 0;
    rx(f, mk_tcp(f, 4000, 7780, 1000, 0, F_SYN, ""));
    g_entropy_ok = 1;
    CHECK(g_tx_n == 0 && tls_sess_active() == 0 && g_tcbs[0].state == TCP_CLOSED);
}

static void test_tls_limit(void)
{
    static uint8_t f[200];
    uint64_t full0 = g_cli_sess_full, ev0 = g_tcp_synrcvd_evicted;

    tcp_reset_tls();
    g_from_port = 7780;
    // Sesi 1 dari .1 (ESTABLISHED, belum handshake TLS).
    g_wport = 7780;
    tcp_open(50000, 51000, 4096);
    // Sesi 2 SYN_RCVD dari .77, lalu .78 menggusurnya (slot TLS dipindah).
    CHECK(syn_from(f, 77, 5000, 100, 52000));
    CHECK(tls_sess_active() == 2);
    CHECK(syn_from(f, 78, 5001, 200, 53000));
    CHECK(tls_sess_active() == 2 && g_tcp_synrcvd_evicted == ev0 + 1);
    rx(f, mk_tcp_from(f, 78, 5001, 201, 53001, F_ACK, ""));
    // Dua TCB 7780 ESTABLISHED: SYN berikutnya -> RST, tanpa slot baru.
    rx(f, mk_tcp_from(f, 79, 5002, 300, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_cli_sess_full == full0 + 1);
    CHECK(tls_sess_active() == 2);
    // 7779 tidak terpengaruh sesi 7780.
    g_from_port = 7779;
    CHECK(syn_from(f, 80, 5003, 400, 54000));
    // D9d: cli_plain=0 -> SYN 7779 dibalas RST, 7780 tetap menerima.
    g_cli_plain = 0;
    rx(f, mk_tcp_from(f, 81, 5004, 500, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK));
    g_cli_plain = 1;
    g_from_port = 7;
    tcp_reset_tls();
    CHECK(tls_sess_active() == 0);
}

// ---- F7 SSH-1b: port 22 (transport SSH-2, kernel/ssh.c) ----
// Klien tiruan di sini hanya sampai baris versi/KEXINIT; kex penuh (curve25519 +
// GCM) diuji di test_ssh.c dan tests/ssh-interop.sh (klien uji itu terikat ke
// ssh.c yang di-#include di sana, mahal dipakai ulang di sini).
static void ssh_files(const uint8_t *k, uint32_t kl)
{
    g_fsk = k;
    g_fsk_len = kl;
    serial_capture_reset();
    ssh_load();
}

static void tcp_reset_ssh(void)
{
    for (int k = 0; k < TCP_MAX_CONN; k++) {
        net_tcp_tls_release(&g_tcbs[k]);
    }
    for (int i = 0; i < SSH_MAX_SESS; i++) {
        ssh_close(i);
    }
    tcp_reset();
}

static uint32_t tx_data_total(void)
{
    uint32_t n = 0;

    for (int i = 0; i < g_tx_n; i++) {
        n += tx_seg(i).len;
    }
    return n;
}

// SYN + ACK ke port 22 dari .ip3; return 1 bila SYN-ACK benar. Banner ada di g_tx.
static int ssh_conn(uint8_t *f, uint8_t ip3, uint16_t sport, uint32_t pseq, uint32_t isn)
{
    int ok = syn_from(f, ip3, sport, pseq, isn);

    rx(f, mk_tcp_from(f, ip3, sport, pseq + 1, isn + 1, F_ACK, ""));
    return ok;
}

static void test_ssh_net(void)
{
    static uint8_t f[200];
    uint64_t conn0 = g_ssh_conn, full0 = g_ssh_full, ne0 = g_ssh_noentropy, ev0 = g_tcp_synrcvd_evicted;

    g_from_port = 22;
    // Kunci host belum ada -> SYN dibalas RST, tanpa TCB.
    tcp_reset_ssh();
    ssh_files(0, 0);
    CHECK(!ssh_enabled() && strstr(g_serial_cap, "SSH: nonaktif (SSHKEY.DER tidak ada)"));
    rx(f, mk_tcp_from(f, 40, 5000, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && net_tcp_ssh_active() == 0);
    ssh_files(f, 20);   // sampah
    CHECK(!ssh_enabled() && strstr(g_serial_cap, "SSH: nonaktif (SSHKEY.DER bukan kunci EC"));
    ssh_files(T_KEYA, sizeof(T_KEYA));
    CHECK(ssh_enabled() && strstr(g_serial_cap, "SSH: aktif port 22 fp=SHA256:"));

    // Entropi belum siap: SYN dibuang (tanpa balasan, tanpa TCB).
    g_entropy_ok = 0;
    rx(f, mk_tcp_from(f, 40, 5000, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 0 && net_tcp_ssh_active() == 0 && g_ssh_noentropy == ne0 + 1);
    g_entropy_ok = 1;
    // Entropi hilang antara SYN dan ESTABLISHED: ssh_open gagal -> RST, TCB lepas.
    CHECK(syn_from(f, 40, 5000, 100, 1000));
    g_entropy_ok = 0;
    rx(f, mk_tcp_from(f, 40, 5000, 101, 1001, F_ACK, ""));
    g_entropy_ok = 1;
    CHECK(g_tx_n == 1 && (tx_seg(0).flags & F_RST) && g_tcbs[0].state == TCP_CLOSED);
    CHECK(g_ssh_noentropy == ne0 + 2 && net_tcp_ssh_active() == 0);

    // Banner SSH-2.0 sesudah ESTABLISHED; SYN_RCVD belum memakai slot ssh.
    tcp_reset_ssh();
    CHECK(syn_from(f, 41, 5001, 100, 2000));
    CHECK(net_tcp_ssh_active() == 1 && ssh_state(0) == SSH_ST_FREE && g_tcbs[0].ssh == 0);
    rx(f, mk_tcp_from(f, 41, 5001, 101, 2001, F_ACK, ""));
    CHECK(g_ssh_conn == conn0 + 1 && g_tcbs[0].ssh == 1 && ssh_state(0) == SSH_ST_VERSION);
    CHECK(g_tx_n >= 1 && tx_seg(0).len >= 8 && memcmp(tx_seg(0).data, "SSH-2.0-", 8) == 0);
    CHECK(!strstr(g_serial_cap, "login") && g_tcbs[0].app == TCP_APP_SSH);   // tanpa banner CLI

    // Batas 10 s sejak ESTABLISHED, tanpa lalu lintas: RST, slot ssh lepas.
    serial_capture_reset();
    timer_ticks += 500;
    g_tx_n = 0;
    net_tcp_tick();
    CHECK(g_tx_n == 0 && g_tcbs[0].state == TCP_ESTABLISHED);
    timer_ticks += 600;
    net_tcp_tick();
    CHECK(g_tx_n == 1 && (tx_seg(0).flags & F_RST) && g_tcbs[0].state == TCP_CLOSED);
    CHECK(ssh_state(0) == SSH_ST_FREE && g_tcbs[0].ssh == 0 && net_tcp_ssh_active() == 0);
    CHECK(strstr(g_serial_cap, "SSH: ditutup (batas waktu 10 s)") != 0);

    // Lalu lintas kecil tidak memperpanjang batas: ketukan tiap detik tetap diputus.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 42, 5002, 100, 3000));
    // Satu byte DATA sah per detik (memajukan `last`), jadi batas berbasis `last` ketahuan.
    uint32_t got42 = tx_data_total();
    int iter42 = 0;
    serial_capture_reset();
    while (iter42 < 20 && g_tcbs[0].state == TCP_ESTABLISHED) {
        char one[2] = { "SSH-2.0-abcdefghijklmnop"[iter42], 0 };

        rx(f, mk_tcp_from(f, 42, 5002, 101 + (uint32_t)iter42, 3001 + got42, F_ACK, one));
        net_tcp_tick();
        iter42++;
    }
    CHECK(iter42 == 11 && g_tcbs[0].state == TCP_CLOSED && ssh_state(0) == SSH_ST_FREE);
    CHECK(strstr(g_serial_cap, "SSH: ditutup (batas waktu 10 s)") != 0);

    // Panjang paket tidak sah: DISCONNECT (pesan 1, polos) terkirim SEBELUM FIN.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 45, 5005, 100, 5500));
    uint32_t s45 = tx_data_total();
    rx(f, mk_tcp_from(f, 45, 5005, 101, 5501 + s45, F_ACK, "SSH-2.0-x\r\n\xff\xff\xff\xff"));
    CHECK(ssh_state(0) == SSH_ST_CLOSING);
    int disc45 = 0;
    for (int i = 0; i < g_tx_n; i++) {
        CHECK(!(tx_seg(i).flags & (F_FIN | F_RST)));
        if (tx_seg(i).len > 6 && tx_seg(i).data[5] == 1) {
            disc45 = 1;
        }
    }
    s45 += tx_data_total();
    CHECK(disc45);
    rx(f, mk_tcp_from(f, 45, 5005, 116, 5501 + s45, F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_1);
    rx(f, mk_tcp_from(f, 45, 5005, 116, 5502 + s45, F_RST | F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_CLOSED && ssh_state(0) == SSH_ST_FREE);

    // RST dari peer melepas slot.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 43, 5003, 100, 4000));
    CHECK(ssh_state(0) == SSH_ST_VERSION);
    rx(f, mk_tcp_from(f, 43, 5003, 101, 0, F_RST, ""));
    CHECK(g_tcbs[0].state == TCP_CLOSED && ssh_state(0) == SSH_ST_FREE && g_tcbs[0].ssh == 0);

    // Versi klien salah: ssh menutup -> sisa keluaran -> FIN; data sesudahnya dibuang tanpa RST.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 44, 5004, 100, 5000));
    uint32_t sent = tx_data_total();
    rx(f, mk_tcp_from(f, 44, 5004, 101, 5001 + sent, F_ACK, "SSH-1.5-x\r\n"));
    sent += tx_data_total();
    CHECK(ssh_state(0) == SSH_ST_CLOSING && ssh_why(0)[0]);
    rx(f, mk_tcp_from(f, 44, 5004, 112, 5001 + sent, F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_1 && g_tcbs[0].snd_nxt == g_tcbs[0].iss + 2 + sent);   // FIN sudah keluar
    rx(f, mk_tcp_from(f, 44, 5004, 112, 5002 + sent, F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_2);
    rx(f, mk_tcp_from(f, 44, 5004, 112, 5002 + sent, F_ACK, "xyz"));
    CHECK(g_tcbs[0].state == TCP_FIN_WAIT_2 && (g_tx_n == 0 || !(tx_seg(0).flags & F_RST)));
    rx(f, mk_tcp_from(f, 44, 5004, 115, 5002 + sent, F_FIN | F_ACK, ""));
    CHECK(g_tcbs[0].state == TCP_TIME_WAIT);
    timer_ticks += 100000;
    net_tcp_tick();
    CHECK(g_tcbs[0].state == TCP_CLOSED && ssh_state(0) == SSH_ST_FREE && g_ssh_fail > 0);

    // Penuh: dua ESTABLISHED, sesi ke-3 -> RST (g_ssh_full), 7779/7780 tak terpengaruh.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 50, 5010, 100, 6000));
    CHECK(ssh_conn(f, 51, 5011, 100, 6100));
    rx(f, mk_tcp_from(f, 52, 5012, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_ssh_full == full0 + 1);
    CHECK(net_tcp_ssh_active() == 2);
    g_from_port = 7779;
    CHECK(syn_from(f, 53, 5013, 100, 6200));
    g_from_port = 22;
    // Satu ESTABLISHED + SYN_RCVD: sesi baru menggusur SYN_RCVD ssh tertua.
    tcp_reset_ssh();
    CHECK(ssh_conn(f, 54, 5020, 100, 7000));
    CHECK(syn_from(f, 55, 5021, 100, 7100));
    CHECK(syn_from(f, 56, 5022, 100, 7200));
    CHECK(g_tcp_synrcvd_evicted == ev0 + 1 && net_tcp_ssh_active() == 2);

    // Backpressure: jendela peer 60 byte -> keluaran ditahan, sisanya mengalir setelah ACK.
    tcp_reset_ssh();
    g_wport = 22;
    tcp_open(8000, 9000, 60);
    uint32_t first = tx_data_total();
    CHECK(g_tcbs[0].ssh == 1 && first > 0 && first <= 60);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1 + first, F_ACK, 0, 0, 4096));
    CHECK(tx_data_total() > 0 && g_tcbs[0].state == TCP_ESTABLISHED);
    g_wport = 7;
    tcp_reset_ssh();
    ssh_files(0, 0);
    g_from_port = 7;
}

#ifndef BMAHOS_FUZZ   // R7: tests/fuzz/fuzz_net.c memakai helper file ini
// P6-2: SYN probe pantau, dan jawaban SYN-ACK/RST yang diakui kait monitor_tcp_seen.
static void test_tcp_probe(void)
{
    uint8_t f[600];
    uint8_t *p = malloc(64);
    static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x07 };
    static const uint8_t ip[4] = { 192, 168, 50, 7 };

    tcp_reset();
    CHECK(net_tcp_syn_build(p, mac, ip, 50000, 80, 0x01020304) == 60);
    CHECK(memcmp(p, mac, 6) == 0 && memcmp(p + 6, g_e1000_mac, 6) == 0 && p[12] == 0x08 &&
          p[13] == 0);
    CHECK(p[16] == 0 && p[17] == 40 && p[23] == 6 && memcmp(p + 26, OUR_IP, 4) == 0 &&
          memcmp(p + 30, ip, 4) == 0 && ref_csum(p + 14, 20, 0) == 0);
    CHECK(ref_l4_csum(p + 14, 6, p + 34, 20) == 0);
    CHECK(p[34] == 0xC3 && p[35] == 0x50 && p[36] == 0 && p[37] == 80 &&
          get32(p + 38) == 0x01020304 && get32(p + 42) == 0);
    CHECK(p[46] == 0x50 && p[47] == F_SYN && p[48] == 0x04 && p[49] == 0 && p[52] == 0);
    int bad0 = g_tx_bad;
    g_tx_n = 0;
    e1000_tx_send((uint64_t)(uintptr_t)p, 60);
    CHECK(g_tx_bad == bad0);
    free(p);

    // SYN-ACK milik probe: dibalas RST (seq = ack mereka) tanpa baris log port tertutup.
    g_probe_calls = 0;
    g_probe_ret = 1;
    serial_capture_reset();
    rx(f, mk_tcp(f, 80, 50000, 9000, 0x01020305, F_SYN | F_ACK, ""));
    CHECK(g_probe_calls == 1 && g_tx_n == 1 && g_tx[0][34 + 13] == F_RST &&
          get32(g_tx[0] + 38) == 0x01020305);
    CHECK(strstr(g_serial_cap, "port tertutup") == NULL);
    // RST milik probe: tidak dibalas.
    rx(f, mk_tcp(f, 80, 50000, 0, 0x01020305, F_RST | F_ACK, ""));
    CHECK(g_probe_calls == 2 && g_tx_n == 0);
    // Bukan milik probe: perilaku lama (baris log + RST).
    g_probe_ret = 0;
    serial_capture_reset();
    rx(f, mk_tcp(f, 80, 50000, 9000, 0x01020305, F_SYN | F_ACK, ""));
    CHECK(g_probe_calls == 3 && g_tx_n == 1 && g_tx[0][34 + 13] == F_RST &&
          strstr(g_serial_cap, "C1: TCP port tertutup dari ") != NULL);
    // Segmen untuk port dengar (SYN ke port 7) tidak sampai ke kait.
    rx(f, mk_tcp(f, 4001, 7, 7000, 0, F_SYN, ""));
    CHECK(g_probe_calls == 3 && g_tx_n == 1 && g_tx[0][34 + 13] == (F_SYN | F_ACK));
    tcp_reset();
}

// P3-4: tanpa IP (DHCP belum terikat) ARP tidak dijawab dan IPv4 dibuang;
// balasan DHCP (UDP 67 -> 68) ke alamat tujuan mana pun diserahkan ke dhcp_rx
// selama klien menunggu, bila checksum sah.
static size_t mk_dhcp(uint8_t *f, uint16_t dport, const char *data)
{
    size_t n = mk_udp(f, 67, dport, data, 0);
    memset(f + 30, 255, 4);
    fix_csums(f, n);
    return n;
}

static void test_dhcp_hooks(void)
{
    uint8_t f[600];
    static const uint8_t zero[4] = { 0, 0, 0, 0 };

    g_dh_arp_n = 0;
    rx(f, mk_arp(f, OUR_IP));
    CHECK(g_tx_n == 1 && g_dh_arp_n == 1 && net_ip_ready());
    memset(g_net_ip, 0, 4);
    CHECK(!net_ip_ready());
    rx(f, mk_arp(f, OUR_IP));
    CHECK(g_tx_n == 0 && g_dh_arp_n == 2);
    rx(f, mk_arp(f, zero));                        // ARP untuk 0.0.0.0
    CHECK(g_tx_n == 0);
    size_t n = mk_icmp_echo(f, "x", 0);
    memset(f + 30, 0, 4);                          // ping ke 0.0.0.0
    fix_csums(f, n);
    rx(f, n);
    CHECK(g_tx_n == 0);

    g_dh_wait = 1;
    g_dh_rx_n = 0;
    rx(f, mk_dhcp(f, 68, "bootp"));
    CHECK(g_dh_rx_n == 1 && g_dh_rx_len == 5 && g_dh_rx0 == 'b' && g_tx_n == 0);
    rx(f, mk_dhcp(f, 69, "x"));                    // port lain
    n = mk_dhcp(f, 68, "x");
    f[40] ^= 0xFF;                                 // checksum UDP rusak
    rx(f, n);
    n = mk_dhcp(f, 68, "x");
    f[24] ^= 0xFF;                                 // checksum IP rusak
    rx(f, n);
    CHECK(g_dh_rx_n == 1);
    g_dh_wait = 0;
    rx(f, mk_dhcp(f, 68, "x"));                    // klien tidak menunggu
    CHECK(g_dh_rx_n == 1);
    memcpy(g_net_ip, OUR_IP, 4);
}

// ---- P5-2: soket TCP user (sock.c asli, lewat syscall-nya) ----

#define U(x)  ((uint64_t)(uintptr_t)(x))

static int64_t sys_neg(uint64_t r)
{
    return (int64_t)r;
}
#define UTCB  (&g_tcbs[TCP_MAX_CONN])   // slot TCB user pertama

static void user_reset(void)
{
    tcp_reset();
    memset(g_sk, 0, sizeof(g_sk));
    memset(g_skc, 0, sizeof(g_skc));
    g_wport = 5556;
}

// fd 0 = soket listen port 5556.
static void user_listen(void)
{
    user_reset();
    CHECK(sock_sys_socket(SOCK_TCP, 0, 0, 0, 0) == 0);
    CHECK(sock_sys_bind(0, 5556, 0, 0, 0) == 0);
    CHECK(sock_sys_listen(0, 0, 0, 0, 0) == 0);
}

// Handshake peer port 4500 -> 5556 di slot user pertama, lalu accept (fd 1).
static void user_open(uint32_t our_isn, uint32_t peer_isn)
{
    uint8_t f[200];
    uint64_t from = 0;

    g_isn_set = 1;
    g_isn = our_isn;
    rx(f, mk_tcp_w(f, peer_isn, 0, F_SYN, 0, 0, 4096));
    g_isn_set = 0;
    g_iss = our_isn;
    g_pseq = peer_isn + 1;
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && tx_seg(0).wnd == SOCK_TCP_RING);
    CHECK(UTCB->state == TCP_SYN_RCVD && g_tcbs[0].state == TCP_CLOSED);
    CHECK(sys_neg(sock_sys_accept(0, 0, 1, 0, 0)) == SOCK_EAGAIN);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && UTCB->state == TCP_ESTABLISHED);
    CHECK(sock_sys_accept(0, U(&from), 0, 0, 0) == 1);
    CHECK(from == SOCK_ADDR(192, 168, 50, 1, 4500));
}

// Data segmen keluar (urut dari g_usnd + g_ugot) dikumpulkan ke g_uo.
static uint8_t g_uo[4000];
static uint32_t g_usnd, g_ugot, g_useg_max;

static void user_collect(void)
{
    for (int k = 0; k < g_tx_n && k < TX_MAX; k++) {
        struct seg s = tx_seg(k);

        if (s.len > 0 && s.seq == g_usnd + g_ugot && g_ugot + s.len <= sizeof(g_uo)) {
            memcpy(g_uo + g_ugot, s.data, s.len);
            g_ugot += s.len;
            if (s.len > g_useg_max) {
                g_useg_max = s.len;
            }
        }
    }
}

static void test_tcp_user(void)
{
    static uint8_t f[1700], b[3000], o[3000];
    struct seg s;

    // Tanpa soket listen: SYN ke 5556 -> RST.
    user_reset();
    rx(f, mk_tcp_w(f, 100, 0, F_SYN, 0, 0, 4096));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK));

    user_listen();
    user_open(1000, 5000);

    // Data masuk -> ring; ACK dengan jendela = ruang ring.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"halo", 4, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.ack == g_pseq + 4 && s.wnd == SOCK_TCP_RING - 4 && s.len == 0);
    g_pseq += 4;
    CHECK(sock_sys_recv(1, U(o), 100, 0, 0) == 4 && memcmp(o, "halo", 4) == 0);

    // send: net task mengirim di tick berikutnya.
    CHECK(sock_sys_send(1, U("balas"), 5, 0, 0) == 5);
    CHECK(step() == 1);
    s = tx_seg(0);
    CHECK(s.seq == g_iss + 1 && s.len == 5 && memcmp(s.data, "balas", 5) == 0 && s.ack == g_pseq);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 6, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && UTCB->snd_una == g_iss + 6);

    // 2500 byte: ring keluar + antrean TCB, stop-and-wait <= MSS per segmen.
    for (int i = 0; i < 2500; i++) {
        b[i] = (uint8_t)(i * 7 + 3);
    }
    g_usnd = g_iss + 6;
    g_ugot = 0;
    g_useg_max = 0;
    uint32_t sent = 0;
    for (int round = 0; round < 40 && g_ugot < 2500; round++) {
        if (sent < 2500) {
            int64_t r = (int64_t)sock_sys_send(1, U(b + sent), 2500 - sent, 1, 0);

            if (r > 0) {
                sent += (uint32_t)r;
            }
        }
        step();
        user_collect();
        rx(f, mk_tcp_w(f, g_pseq, g_usnd + g_ugot, F_ACK, 0, 0, 4096));
        user_collect();
    }
    CHECK(sent == 2500 && g_ugot == 2500 && memcmp(g_uo, b, 2500) == 0);
    rx(f, mk_tcp_w(f, g_pseq, g_usnd + g_ugot, F_ACK, 0, 0, 4096));   // segmen terakhir
    CHECK(g_tx_n == 0);
    CHECK(g_useg_max == TCP_MSS && UTCB->buf_count == 0 && UTCB->snd_una == g_usnd + 2500);
    uint32_t ack = g_usnd + 2500;

    // Ring masuk penuh: jendela 0, data berikutnya tidak di-ACK; recv membuka
    // jendela lagi -> net task mengirim ACK pembaruan jendela.
    memset(b, 'w', 1100);
    rx(f, mk_tcp_w(f, g_pseq, ack, F_ACK, b, 536, 4096));
    g_pseq += 536;
    rx(f, mk_tcp_w(f, g_pseq, ack, F_ACK, b, 488, 4096));
    g_pseq += 488;
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.ack == g_pseq && s.wnd == 0);
    rx(f, mk_tcp_w(f, g_pseq, ack, F_ACK, b, 10, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.ack == g_pseq && s.wnd == 0);   // 10 byte tidak diterima
    CHECK(step() == 0);
    CHECK(sock_sys_recv(1, U(o), sizeof(o), 0, 0) == SOCK_TCP_RING && o[1023] == 'w');
    CHECK(step() == 1);
    s = tx_seg(0);
    CHECK(s.flags == F_ACK && s.wnd == SOCK_TCP_RING && s.ack == g_pseq && s.len == 0);
    CHECK(step() == 0);

    // Dipegang program dengan antrean kosong: batas diam 30 s tidak berlaku.
    timer_ticks += 5000;
    CHECK(step() == 0 && UTCB->state == TCP_ESTABLISHED);

    // FIN peer: recv 0, FIN kita baru setelah close.
    rx(f, mk_tcp_w(f, g_pseq, ack, F_FIN | F_ACK, 0, 0, 4096));
    g_pseq++;
    CHECK(g_tx_n == 1 && tx_seg(0).flags == F_ACK && UTCB->state == TCP_CLOSE_WAIT);
    CHECK(sock_sys_recv(1, U(o), 100, 0, 0) == 0);
    timer_ticks += 5000;
    CHECK(step() == 0 && UTCB->state == TCP_CLOSE_WAIT);
    CHECK(sock_sys_send(1, U("akhir"), 5, 0, 0) == 5);
    CHECK(step() == 1 && tx_seg(0).len == 5 && tx_seg(0).seq == ack);
    rx(f, mk_tcp_w(f, g_pseq, ack + 5, F_ACK, 0, 0, 4096));
    CHECK(sock_sys_close(1, 0, 0, 0, 0) == 0);
    CHECK(step() == 1 && tx_seg(0).flags == (F_FIN | F_ACK) && UTCB->state == TCP_LAST_ACK);
    CHECK(!sock_tcp_slot_free(0));
    rx(f, mk_tcp_w(f, g_pseq, ack + 6, F_ACK, 0, 0, 4096));
    CHECK(UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0) && g_sock_tcp_reset == 0);

    // close dengan data belum dibaca: RST.
    user_open(2000, 6000);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, (const uint8_t *)"x", 1, 4096));
    CHECK(sock_sys_close(1, 0, 0, 0, 0) == 0);
    CHECK(step() == 1 && tx_seg(0).flags == (F_RST | F_ACK));
    CHECK(UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0) && g_sock_tcp_reset == 0);

    // RST peer: recv -104, slot bebas setelah close.
    user_open(3000, 7000);
    rx(f, mk_tcp_w(f, g_pseq, 0, F_RST, 0, 0, 0));
    CHECK(g_tx_n == 0 && UTCB->state == TCP_CLOSED && !sock_tcp_slot_free(0));
    CHECK(sys_neg(sock_sys_recv(1, U(o), 100, 0, 0)) == SOCK_ECONNRESET);
    CHECK(g_sock_tcp_reset == 1);
    // Slot masih dipegang fd: SYN baru memakai slot user kedua.
    g_isn_set = 0;
    rx(f, mk_tcp(f, 4700, 5556, 900, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && g_tcbs[TCP_MAX_CONN + 1].state == TCP_SYN_RCVD);
    CHECK(sock_sys_close(1, 0, 0, 0, 0) == 0 && sock_tcp_slot_free(0));

    // Slot user penuh SYN_RCVD: SYN baru menggusur yang tertua; ESTABLISHED
    // semua -> RST. Slot layanan kernel tidak terpengaruh.
    uint64_t ev0 = g_tcp_synrcvd_evicted, busy0 = g_tcp_busy;
    rx(f, mk_tcp(f, 4701, 5556, 910, 0, F_SYN, ""));
    CHECK(UTCB->state == TCP_SYN_RCVD && UTCB->rport == 4701);
    rx(f, mk_tcp(f, 4702, 5556, 920, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && g_tcp_synrcvd_evicted == ev0 + 1);
    CHECK(g_tcbs[TCP_MAX_CONN + 1].rport == 4702);   // 4700 (tertua) digusur
    rx(f, mk_tcp(f, 4701, 5556, 911, 0xA0A1A2A4, F_ACK, ""));
    rx(f, mk_tcp(f, 4702, 5556, 921, 0xA0A1A2A4, F_ACK, ""));
    CHECK(UTCB->state == TCP_ESTABLISHED && g_tcbs[TCP_MAX_CONN + 1].state == TCP_ESTABLISHED);
    rx(f, mk_tcp(f, 4703, 5556, 930, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK) && g_tcp_busy == busy0 + 1);
    for (int k = 0; k < TCP_MAX_CONN; k++) {
        CHECK(g_tcbs[k].state == TCP_CLOSED);
    }
    rx(f, mk_tcp(f, 4704, 7, 940, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_SYN | F_ACK) && g_tcbs[0].state == TCP_SYN_RCVD);

    // Belum di-accept + listen ditutup: keduanya RST, slot bebas.
    CHECK(sock_sys_close(0, 0, 0, 0, 0) == 0);
    CHECK(step() == 2 && tx_seg(0).flags == (F_RST | F_ACK) && tx_seg(1).flags == (F_RST | F_ACK));
    CHECK(sock_tcp_slot_free(0) && sock_tcp_slot_free(1));
    CHECK(UTCB->state == TCP_CLOSED && g_tcbs[TCP_MAX_CONN + 1].state == TCP_CLOSED);
    rx(f, mk_tcp(f, 4705, 5556, 950, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK));   // port 5556 tutup lagi
    CHECK(g_tx_bad == 0);
    user_reset();
    g_wport = 7;
}

// ---- P5-3: connect (net.c SYN_SENT + sock.c lewat syscall) ----
enum { CM_NONE, CM_OK, CM_REFUSE, CM_BADACK };
static int g_cmode;
static int g_c_syns, g_c_rsts, g_c_acks, g_c_mss;
static uint32_t g_c_iss, g_c_rst_seq, g_c_rst_flags;
static uint16_t g_c_lport, g_c_rport;
#define C_PISN 0x70000000u

static uint16_t seg_sport(int i)
{
    return (uint16_t)(g_tx[i][34] << 8 | g_tx[i][35]);
}

static void c_scan(void)
{
    for (int k = 0; k < g_tx_n && k < TX_MAX; k++) {
        struct seg s = tx_seg(k);

        if (s.flags == F_SYN) {
            g_c_syns++;
            g_c_iss = s.seq;
            g_c_lport = seg_sport(k);
            g_c_rport = (uint16_t)(g_tx[k][36] << 8 | g_tx[k][37]);
            g_c_mss = (g_tx[k][46] >> 4) == 6 && g_tx[k][54] == 2 && g_tx[k][56] == TCP_MSS >> 8;
        } else if (s.flags & F_RST) {
            g_c_rsts++;
            g_c_rst_seq = s.seq;
            g_c_rst_flags = s.flags;
        } else if (s.flags == F_ACK && s.ack == C_PISN + 1 && s.seq == g_c_iss + 1) {
            g_c_acks++;
        }
    }
}

// Satu putaran net task (sock_poll, timer, tick) lalu jawaban peer atas SYN baru.
static void c_net(void)
{
    uint8_t f[200];
    int syns = g_c_syns;

    g_tx_n = 0;
    sock_poll();
    ktimer_run();
    net_tcp_tick();
    c_scan();
    if (g_c_syns == syns || g_cmode == CM_NONE) {
        return;
    }
    if (g_cmode == CM_BADACK) {
        rx(f, mk_tcp(f, g_c_rport, g_c_lport, C_PISN, g_c_iss + 100, F_SYN | F_ACK, ""));
        c_scan();
        g_cmode = CM_OK;
    }
    if (g_cmode == CM_OK) {
        rx(f, mk_tcp(f, g_c_rport, g_c_lport, C_PISN, g_c_iss + 1, F_SYN | F_ACK, ""));
    } else {
        rx(f, mk_tcp(f, g_c_rport, g_c_lport, 0, g_c_iss + 1, F_RST | F_ACK, ""));
    }
    c_scan();
}

static int64_t c_connect(int mode, uint16_t port, uint64_t timeout)
{
    g_cmode = mode;
    g_c_syns = g_c_rsts = g_c_acks = g_c_mss = 0;
    return sys_neg(sock_sys_connect(0, SOCK_ADDR(192, 168, 50, 1, port), timeout, 0, 0));
}

static void test_tcp_connect(void)
{
    uint8_t f[200], o[64];
    struct seg s;

    user_reset();
    sock_init();
    g_e1000_rx_initialized = 1;
    sk_arp_learn(PEER_IP, PEER_MAC);
    g_on_sleep = c_net;
    g_isn_set = 1;
    g_isn = 0x11110000;

    // Berhasil: SYN dengan MSS dari port acak 49152.., SYN-ACK -> ACK, ESTABLISHED.
    CHECK(sock_sys_socket(SOCK_TCP, 0, 0, 0, 0) == 0);
    uint64_t open0 = g_tcp_conn_open, rst0 = g_sock_tcp_reset;
    CHECK(c_connect(CM_OK, 8080, 0) == 0);
    CHECK(g_c_syns == 1 && g_c_mss && g_c_iss == 0x11110000 && g_c_rport == 8080);
    CHECK(g_c_lport >= 49152 && g_c_acks == 1 && g_c_rsts == 0);
    CHECK(UTCB->state == TCP_ESTABLISHED && UTCB->lport == g_c_lport && UTCB->snd_wnd == 4096);
    CHECK(g_tcp_conn_open == open0 + 1 && g_sock_connect == 1 && g_skc[0].accepted);
    g_on_sleep = 0;

    // Data dua arah.
    CHECK(sock_sys_send(0, U("GET\n"), 4, 0, 0) == 4);
    CHECK(step() == 1);
    s = tx_seg(0);
    CHECK(s.seq == g_c_iss + 1 && s.len == 4 && memcmp(s.data, "GET\n", 4) == 0 && s.ack == C_PISN + 1);
    rx(f, mk_tcp(f, 8080, g_c_lport, C_PISN + 1, g_c_iss + 5, F_ACK, "OK\n"));
    CHECK(g_tx_n == 1 && tx_seg(0).ack == C_PISN + 4);
    CHECK(sock_sys_recv(0, U(o), sizeof(o), 0, 0) == 3 && memcmp(o, "OK\n", 3) == 0);
    // SYN-ACK ulang (ACK kita hilang): ACK lagi.
    rx(f, mk_tcp(f, 8080, g_c_lport, C_PISN, g_c_iss + 1, F_SYN | F_ACK, ""));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.flags == F_ACK && s.seq == g_c_iss + 5 && s.ack == C_PISN + 4);
    // FIN peer -> recv 0; close -> FIN kita; ACK -> CLOSED, slot bebas.
    rx(f, mk_tcp(f, 8080, g_c_lport, C_PISN + 4, g_c_iss + 5, F_FIN | F_ACK, ""));
    CHECK(UTCB->state == TCP_CLOSE_WAIT && sock_sys_recv(0, U(o), sizeof(o), 0, 0) == 0);
    CHECK(sock_sys_close(0, 0, 0, 0, 0) == 0);
    CHECK(step() == 1 && tx_seg(0).flags == (F_FIN | F_ACK) && UTCB->state == TCP_LAST_ACK);
    rx(f, mk_tcp(f, 8080, g_c_lport, C_PISN + 5, g_c_iss + 6, F_ACK, ""));
    CHECK(UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0) && g_sock_tcp_reset == rst0);

    // Ditolak: RST|ACK atas SYN -> -111, tanpa RST balik, slot bebas.
    g_on_sleep = c_net;
    CHECK(sock_sys_socket(SOCK_TCP, 0, 0, 0, 0) == 0);
    CHECK(c_connect(CM_REFUSE, 81, 0) == SOCK_ECONNREFUSED);
    CHECK(g_c_syns == 1 && g_c_rsts == 0 && UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0));
    CHECK(g_sock_tcp_reset == rst0);

    // SYN-ACK dengan ACK salah -> RST (seq = ack itu, tanpa ACK), tetap menunggu;
    // SYN-ACK benar berikutnya diterima.
    CHECK(c_connect(CM_BADACK, 82, 0) == 0);
    CHECK(g_c_rsts == 1 && g_c_rst_seq == g_c_iss + 100 && g_c_rst_flags == F_RST && g_c_acks == 1);
    g_on_sleep = 0;
    rx(f, mk_tcp(f, 82, g_c_lport, C_PISN + 1, 0, F_RST, ""));
    CHECK(UTCB->state == TCP_CLOSED && g_sock_tcp_reset == rst0 + 1);
    CHECK(sys_neg(sock_sys_recv(0, U(o), 8, 0, 0)) == SOCK_ECONNRESET);
    CHECK(sock_sys_close(0, 0, 0, 0, 0) == 0 && sock_tcp_slot_free(0));

    // Tanpa jawaban: SYN 1 + 5 kali kirim ulang (1, 2, 4, 8, 8 s), lalu RST
    // tanpa ACK dan -110 (~31 s).
    g_on_sleep = c_net;
    CHECK(sock_sys_socket(SOCK_TCP, 0, 0, 0, 0) == 0);
    uint64_t giveup0 = g_tcp_retx_giveup, t0 = timer_ticks;
    CHECK(c_connect(CM_NONE, 9, 0) == SOCK_ETIMEDOUT);
    CHECK(g_c_syns == 6 && g_c_rsts == 1 && g_c_rst_flags == F_RST && g_c_rst_seq == g_c_iss + 1);
    CHECK(timer_ticks - t0 >= 3100 && timer_ticks - t0 <= 3300);
    CHECK(g_tcp_retx_giveup == giveup0 + 1 && UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0));

    // Batas waktu syscall 150 tick: -110, TCB dilepas tanpa segmen di tick berikut.
    t0 = timer_ticks;
    CHECK(c_connect(CM_NONE, 9, 150) == SOCK_ETIMEDOUT);
    CHECK(timer_ticks - t0 >= 150 && g_c_syns == 1 && UTCB->state == TCP_SYN_SENT);
    g_on_sleep = 0;
    CHECK(step() == 0 && UTCB->state == TCP_CLOSED && sock_tcp_slot_free(0));
    CHECK(g_sock_tcp_reset == rst0 + 1);
    CHECK(sock_sys_close(0, 0, 0, 0, 0) == 0);

    // Dua slot user SYN_SENT (port lokal berbeda): connect ketiga -> slot penuh;
    // SYN ke port listen -> RST (SYN_SENT tidak digusur); SYN tanpa ACK
    // (simultaneous open) diabaikan.
    CHECK(net_tcp_user_connect(PEER_MAC, PEER_IP, 80, 9) == 0);
    CHECK(net_tcp_user_connect(PEER_MAC, PEER_IP, 80, 9) == 1);
    CHECK(net_tcp_user_connect(PEER_MAC, PEER_IP, 80, 9) == SOCK_EMFILE);
    CHECK(g_tcbs[TCP_MAX_CONN + 1].lport == UTCB->lport + 1 && UTCB->state == TCP_SYN_SENT);
    CHECK(sock_sys_socket(SOCK_TCP, 0, 0, 0, 0) == 0);
    CHECK(sock_sys_bind(0, 5556, 0, 0, 0) == 0 && sock_sys_listen(0, 0, 0, 0, 0) == 0);
    rx(f, mk_tcp(f, 4800, 5556, 1, 0, F_SYN, ""));
    CHECK(g_tx_n == 1 && tx_seg(0).flags == (F_RST | F_ACK));
    rx(f, mk_tcp(f, 80, UTCB->lport, 5, 0, F_SYN, ""));
    CHECK(g_tx_n == 0 && UTCB->state == TCP_SYN_SENT && g_tcbs[TCP_MAX_CONN + 1].state == TCP_SYN_SENT);
    CHECK(g_tx_bad == 0);

    g_isn_set = 0;
    g_on_sleep = 0;
    g_e1000_rx_initialized = 0;
    user_reset();
    g_wport = 7;
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
    test_tcp_user();
    test_tcp_connect();
    test_tcp_limits();
    test_tcp_table();
    test_tcp_idle();
    test_tcp_cli();
    test_tcp_shell();
    test_tcp_session();
    test_tcp_audit();
    test_config_vals();
    test_tls_load();
    test_tls_session(BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    test_tls_session(BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
    test_tls_fail();
    test_tls_limit();
    test_ssh_net();   // F7 SSH-1b
    test_limits();
    ip6_bring_up();   // F7: IPv6 aktif selama truncation + fuzz
    build_templates();
    test_truncation();
    test_fuzz();
    ip6_bring_down();
    test_netcon();
    test_tcp_probe();
    test_dhcp_hooks();
    test_ip6();
    test_ip6_review();
    return test_done("net");
}
#endif

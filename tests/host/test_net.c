// F1.7: uji parser paket dan checksum (kernel/net.c) di host.
// net.c disertakan langsung (#include) supaya fungsi static bisa diuji.
// Frame dimasukkan ke net_rx_dispatch() dalam buffer seukuran frame persis
// (malloc), jadi pembacaan lewat batas frame tertangkap ASan. Frame yang
// dikirim ditangkap stub e1000_tx_send() dan diperiksa checksum-nya.

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

static void test_tcp(void)
{
    uint8_t f[600];
    memset(&g_tcb, 0, sizeof(g_tcb));

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
    CHECK(g_tcb.state == TCP_SYN_RCVD);

    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, ""));
    CHECK(g_tx_n == 0 && g_tcb.state == TCP_ESTABLISHED);

    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, "hello"));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7006);

    // Duplikat (seq lama): ACK posisi kita, rcv_nxt tetap.
    rx(f, mk_tcp(f, 4001, 7, 7001, iss + 1, F_ACK, "hello"));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7006);

    // SYN dari port lain saat TCB sibuk: RST.
    uint64_t busy0 = g_tcp_busy;
    rx(f, mk_tcp(f, 4002, 7, 1, 0, F_SYN, ""));
    CHECK(g_tcp_busy == busy0 + 1 && g_tx_n == 1 && (g_tx[0][34 + 13] & F_RST));

    rx(f, mk_tcp(f, 4001, 7, 7006, iss + 1, F_ACK | F_FIN, ""));
    CHECK(g_tx_n == 1 && get32(g_tx[0] + 34 + 8) == 7007);
    CHECK(g_tcb.state == TCP_CLOSE_WAIT);
    CHECK(g_tx_bad == 0);

    // Entropi belum cukup: SYN port 7 dibuang tanpa balasan (bukan RST),
    // TCB tetap CLOSED; port tertutup tetap dibalas RST.
    memset(&g_tcb, 0, sizeof(g_tcb));
    g_entropy_ok = 0;
    uint64_t ne0 = g_tcp_noentropy;
    rx(f, mk_tcp(f, 4003, 7, 100, 0, F_SYN, ""));
    CHECK(g_tx_n == 0 && g_tcb.state == TCP_CLOSED && g_tcp_noentropy == ne0 + 1);
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
    memset(&g_tcb, 0, sizeof(g_tcb));
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
            memset(&g_tcb, 0, sizeof(g_tcb));
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
            memset(&g_tcb, 0, sizeof(g_tcb));
        }
    }
    CHECK(g_tx_bad == 0);
    // Pastikan pengacakan tidak semuanya berakhir dibuang di depan.
    printf("net fuzz: %d frame, %d checksum dibetulkan, %d balasan\n",
           200000, g_fuzz_fixed, g_fuzz_tx);
    CHECK(g_fuzz_tx > 20000);
}

// ---- C3b: kirim data TCP ----

// Segmen TCP dari peer dengan data biner dan jendela pilihan.
static size_t mk_tcp_w(uint8_t *f, uint32_t seq, uint32_t ack, uint8_t flags,
                       const uint8_t *data, size_t dlen, uint16_t wnd)
{
    uint8_t t[1600];
    memset(t, 0, 20);
    t[0] = 4500 >> 8;
    t[1] = 4500 & 0xFF;
    t[3] = 7;
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
    memset(&g_tcb, 0, sizeof(g_tcb));
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
    CHECK(g_tcb.state == TCP_ESTABLISHED && g_tcb.snd_una == 0xFFFFFFFDu);

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
    CHECK(g_tx_n == 1 && tx_seg(0).len == 0 && g_tcb.snd_una == g_iss + 1 && g_tcb.buf_count == 8);

    // ACK untuk "hello" (snd_una melewati 2^32) -> "abc" dikirim.
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 6, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.seq == g_iss + 6 && s.len == 3 && memcmp(s.data, "abc", 3) == 0);
    CHECK(g_tcb.snd_una == g_iss + 6 && g_tcb.snd_una < 0x10 && g_tcb.buf_count == 3);

    // ACK lama: tidak mengubah apa pun (juga jendela peer tidak diperbarui).
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 7));
    CHECK(g_tx_n == 0 && g_tcb.snd_una == g_iss + 6 && g_tcb.snd_wnd == 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 9, F_ACK, 0, 0, 4096));
    CHECK(g_tx_n == 0 && g_tcb.buf_count == 0 && g_tcb.snd_una == g_tcb.snd_nxt);

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
    CHECK(g_tx_n == 0 && g_tcb.snd_wnd == 0 && g_tcb.buf_count == 200);
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 200 && memcmp(s.data, big + 100, 200) == 0);
    una += 200;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 4096));
    CHECK(g_tcb.buf_count == 0);

    // Buffer penuh: jendela peer 0 supaya tidak ada yang terkirim, lalu
    // 1200 byte -> hanya 1024 diterima, ACK dengan jendela 0.
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, big, 1200, 0));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.wnd == 0 && s.ack == g_pseq + TCP_BUF_SIZE);
    CHECK(g_tcb.buf_count == TCP_BUF_SIZE);
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
    CHECK(g_tcb.buf_count == 0);

    // Jendela kita kembali >= MSS tetapi tidak ada yang bisa dikirim (jendela
    // peer 0): pembaruan jendela tetap dikirim lewat ACK.
    memset(&g_tcb, 0, sizeof(g_tcb));
    tcp_open(1000, 2000, 4096);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, big, 1024, 0));
    g_pseq += 1024;
    CHECK(g_tcb.buf_count == 1024 && g_tcb.adv_wnd == 0);
    rx(f, mk_tcp_w(f, g_pseq, g_iss + 1, F_ACK, 0, 0, 600));   // kirim 536
    una = g_iss + 1 + TCP_MSS;
    rx(f, mk_tcp_w(f, g_pseq, una, F_ACK, 0, 0, 0));
    s = tx_seg(0);
    CHECK(g_tx_n == 1 && s.len == 0 && s.wnd == TCP_MSS);
    memset(&g_tcb, 0, sizeof(g_tcb));
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
        size_t room = TCP_BUF_SIZE - g_tcb.buf_count;
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
    memset(&g_tcb, 0, sizeof(g_tcb));
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
    test_limits();
    build_templates();
    test_truncation();
    test_fuzz();
    return test_done("net");
}

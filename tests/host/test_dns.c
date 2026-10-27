// P3-3: uji klien DNS (dns.c di-#include). NIC tiruan sama seperti test_sntp:
// frame keluar disalin, net_udp_build/net_arp_request_build minimal, entropi
// deterministik.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/dns.c"

extern char g_serial_cap[];
void serial_capture_reset(void);

int g_e1000_rx_initialized = 1;
uint8_t g_e1000_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
const uint8_t g_net_ip[4] = { 192, 168, 50, 200 };
uint64_t hhdm_offset = 0;

static uint8_t g_page[4096] __attribute__((aligned(4096)));
uint64_t pmm_alloc(void)
{
    return (uint64_t)(uintptr_t)g_page;
}

static uint8_t g_tx[8][160];
static uint32_t g_tx_len[8];
static int g_ntx;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_ntx < 8) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 160 ? 160 : frame_len);
        g_tx_len[g_ntx] = frame_len;
        g_ntx++;
    }
    return 1;
}

uint32_t net_arp_request_build(uint8_t *p, const volatile uint8_t *ip)
{
    memset(p, 0, 60);
    p[12] = 0x08;
    p[13] = 0x06;
    p[21] = 1;
    for (int i = 0; i < 4; i++) {
        p[38 + i] = ip[i];
    }
    return 60;
}

uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
    }
    for (int i = 0; i < 4; i++) {
        p[30 + i] = dst_ip[i];
    }
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)sport;
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)dport;
    return 42 + plen;
}

static uint8_t g_ent_next = 0x40;
int entropy_get(uint8_t *out, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        out[i] = g_ent_next++;
    }
    return 1;
}

// P6-2: hasil query pemantau (monitor.c tidak ikut di uji ini).
static int g_md_n, g_md_a;
static uint32_t g_md_tok;
static char g_md_what[96];
void monitor_dns_done(uint32_t tok, int a, const char *what)
{
    g_md_n++;
    g_md_tok = tok;
    g_md_a = a;
    snprintf(g_md_what, sizeof(g_md_what), "%s", what);
}

static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len = 0;
void cmd_puts(const char *s)
{
    while (*s && g_cmd_len < CMD_OUT_MAX) {
        g_out[g_cmd_len++] = *s++;
    }
    g_out[g_cmd_len] = 0;
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

static const char *run(const char *c)
{
    g_cmd_len = 0;
    g_out[0] = 0;
    if (!dns_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

static const uint8_t SRV_MAC[6] = { 0x02, 0, 0, 0, 0, 0x53 };

static void arp_from(uint8_t host)
{
    uint8_t f[60] = { 0 };
    memcpy(f + 22, SRV_MAC, 6);
    f[28] = 192; f[29] = 168; f[30] = 50; f[31] = host;
    dns_arp_seen(f);
}

// Mulai query lewat perintah, jawab ARP, kirim query. Return 1 bila query keluar.
static int start(const char *cmd)
{
    g_ntx = 0;
    if (strncmp(run(cmd), "OK: DNS ", 8) != 0) {
        return 0;
    }
    dns_poll();                    // ARP
    arp_from(g_dns_host);
    dns_poll();                    // query
    return g_dns_state == DNS_SENT;
}

// Balasan mulai dari salinan query (header + pertanyaan), lalu diubah per kasus.
static uint8_t g_r[512];
static uint32_t g_rl;
static void rep_begin(uint16_t flags, uint16_t ancount)
{
    memcpy(g_r, g_dns_q, g_dns_qlen);
    g_r[2] = (uint8_t)(flags >> 8);
    g_r[3] = (uint8_t)flags;
    g_r[6] = (uint8_t)(ancount >> 8);
    g_r[7] = (uint8_t)ancount;
    g_rl = g_dns_qlen;
}

// Answer: nama = pointer ke pertanyaan (0xC00C) atau nama mentah, lalu RR.
static void rep_rr(const uint8_t *name, uint32_t nlen, uint16_t type, uint32_t ttl,
                   const uint8_t *rd, uint16_t rdlen)
{
    memcpy(g_r + g_rl, name, nlen);
    g_rl += nlen;
    uint8_t h[10] = { (uint8_t)(type >> 8), (uint8_t)type, 0, 1, (uint8_t)(ttl >> 24),
                      (uint8_t)(ttl >> 16), (uint8_t)(ttl >> 8), (uint8_t)ttl,
                      (uint8_t)(rdlen >> 8), (uint8_t)rdlen };
    memcpy(g_r + g_rl, h, 10);
    g_rl += 10;
    memcpy(g_r + g_rl, rd, rdlen);
    g_rl += rdlen;
}

static const uint8_t PTR_Q[2] = { 0xC0, 0x0C };
static const uint8_t IP1[4] = { 192, 168, 50, 123 };

static void reset(void)
{
    memset(g_dns_cache, 0, sizeof(g_dns_cache));
    g_dns_state = DNS_IDLE;
    g_dns_ok = g_dns_fail = g_dns_bad = 0;
    timer_ticks = 1000;
}

static void test_names(void)
{
    char out[64];
    uint8_t q[65];
    uint32_t ql = 0;

    CHECK(dn_encode((const uint8_t *)"Host-1.Uji", 10, out, q, &ql) && strcmp(out, "host-1.uji") == 0);
    CHECK(ql == 12 && q[0] == 6 && memcmp(q + 1, "host-1", 6) == 0 && q[7] == 3 && q[11] == 0);
    CHECK(dn_encode((const uint8_t *)"a", 1, out, q, &ql) && ql == 3 && strcmp(out, "a") == 0);
    static const char *const bad[] = { "", ".", "a.", ".a", "a..b", "a_b", "a b", "\xff" };
    int all = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        all &= !dn_encode((const uint8_t *)bad[i], (uint32_t)strlen(bad[i]), out, q, &ql);
    }
    CHECK(all);
    char longn[80];
    memset(longn, 'a', 64);
    CHECK(!dn_encode((const uint8_t *)longn, 64, out, q, &ql));   // > 63
    CHECK(dn_encode((const uint8_t *)longn, 63, out, q, &ql) && ql == 65);
}

static void test_query_and_answers(void)
{
    reset();
    CHECK_STR(run("dns bmahos.uji"), "OK: DNS bmahos.uji ke 192.168.50.1:53 dimulai, ulangi perintah (maks 6 s)\n");
    CHECK_STR(run("dns lain.uji"), "ERR: dns: query sebelumnya masih berjalan\n");
    g_dns_state = DNS_IDLE;

    CHECK(start("dns BMAHOS.uji 1 10053"));
    CHECK(g_ntx == 2 && g_tx[0][13] == 0x06 && g_tx[0][41] == 1);
    const uint8_t *q = g_tx[1] + 42;
    CHECK(g_tx_len[1] == 42 + 12 + 12 + 4 && memcmp(g_tx[1], SRV_MAC, 6) == 0);
    CHECK(g_tx[1][36] == (10053 >> 8) && g_tx[1][37] == (10053 & 0xFF));
    CHECK(q[2] == 0x01 && q[3] == 0 && q[5] == 1 && q[7] == 0);     // RD, QDCOUNT 1
    CHECK(q[12] == 6 && memcmp(q + 13, "bmahos", 6) == 0 && q[19] == 3 && q[23] == 0);
    CHECK(q[24] == 0 && q[25] == 1 && q[26] == 0 && q[27] == 1);    // A, IN

    static const uint8_t ip_src[4] = { 192, 168, 50, 1 }, ip_x[4] = { 192, 168, 50, 2 };
    CHECK(dns_wants(ip_src, 10053, g_dns_lport) && !dns_wants(ip_x, 10053, g_dns_lport) &&
          !dns_wants(ip_src, 53, g_dns_lport));

    // Balasan jahat/rusak: diabaikan, tetap menunggu.
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 60, IP1, 4);
    g_r[1] ^= 1;                                   // ID salah
    dns_rx(g_r, g_rl);
    g_r[1] ^= 1;
    dns_rx(g_r, g_dns_qlen - 1);                   // lebih pendek dari pertanyaan
    g_r[2] = 0x01;                                 // QR = 0
    dns_rx(g_r, g_rl);
    g_r[2] = 0x81 | 0x08;                          // opcode 1
    dns_rx(g_r, g_rl);
    g_r[2] = 0x81 | 0x02;                          // TC
    dns_rx(g_r, g_rl);
    g_r[2] = 0x81;
    g_r[14] ^= 0x01;                               // pertanyaan beda ('m' -> 'l')
    dns_rx(g_r, g_rl);
    g_r[14] ^= 0x01;
    g_r[5] = 2;                                    // QDCOUNT 2
    dns_rx(g_r, g_rl);
    g_r[5] = 1;
    CHECK(g_dns_bad == 7 && g_dns_state == DNS_SENT);

    // Answer rusak: label 0x40 (dicadangkan), pointer terpotong, rdlen melewati paket.
    rep_begin(0x8180, 1);
    static const uint8_t badlab[2] = { 0x40, 'a' };
    rep_rr(badlab, 2, 1, 60, IP1, 4);
    dns_rx(g_r, g_rl);
    rep_begin(0x8180, 1);
    g_r[g_rl++] = 0xC0;                            // pointer tanpa byte kedua
    dns_rx(g_r, g_rl);
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 60, IP1, 4);
    g_r[g_rl - 5] = 0x20;                          // rdlen 32 > sisa paket
    dns_rx(g_r, g_rl);
    CHECK(g_dns_bad == 10 && g_dns_state == DNS_SENT);

    // Sah: CNAME (nama mentah berlabel) lalu A dengan nama terkompresi; TTL 1 -> 5 s.
    serial_capture_reset();
    rep_begin(0x8180, 2);
    static const uint8_t cname_rd[6] = { 4, 'c', 'd', 'n', 'x', 0 };
    rep_rr(PTR_Q, 2, 5, 300, cname_rd, 6);
    const uint8_t ptr_cn[2] = { 0xC0, (uint8_t)(g_dns_qlen + 12) };
    rep_rr(ptr_cn, 2, 1, 1, IP1, 4);
    dns_rx(g_r, g_rl);
    CHECK(g_dns_state == DNS_IDLE && g_dns_ok == 1);
    CHECK(strstr(g_serial_cap, "P3: DNS bmahos.uji = 192.168.50.123\r\n") != 0);
    CHECK_STR(run("dns bmahos.uji"), "bmahos.uji = 192.168.50.123 sisa=5 s (cache)\n");
    timer_ticks += 500;                            // TTL 5 s habis
    g_ent_next = 0x40;
    CHECK(strncmp(run("dns bmahos.uji"), "OK: DNS ", 8) == 0);   // kirim ulang
    g_dns_state = DNS_IDLE;

    // NXDOMAIN -> cache negatif 60 s.
    CHECK(start("dns tidakada.uji"));
    rep_begin(0x8183, 0);
    dns_rx(g_r, g_rl);
    CHECK(g_dns_ok == 2 && g_dns_state == DNS_IDLE);
    CHECK_STR(run("dns tidakada.uji"), "tidakada.uji = tidak ada (NXDOMAIN) sisa=60 s (cache)\n");

    // RCODE lain = gagal; tanpa A = gagal; TTL raksasa dibatasi 3600 s.
    CHECK(start("dns gagal.uji"));
    rep_begin(0x8182, 0);
    dns_rx(g_r, g_rl);
    CHECK(g_dns_fail == 1 && strstr(g_dns_last, "gagal: rcode 2") != 0);
    CHECK(start("dns kosong.uji"));
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 16, 60, (const uint8_t *)"\x03txt", 4);
    dns_rx(g_r, g_rl);
    CHECK(g_dns_fail == 2 && strstr(g_dns_last, "tanpa jawaban A") != 0);
    CHECK(start("dns lama.uji"));
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 0xFFFFFFFFu, IP1, 4);
    dns_rx(g_r, g_rl);
    CHECK_STR(run("dns lama.uji"), "lama.uji = 192.168.50.123 sisa=3600 s (cache)\n");

    const char *st = run("dns");
    const char *exp = "dns: diam terakhir=lama.uji = 192.168.50.123 ok=3 gagal=2 diabaikan=10 cache=2/8\n";
    CHECK(strncmp(st, exp, strlen(exp)) == 0);
    CHECK(strstr(st, "tidakada.uji = tidak ada (NXDOMAIN) sisa=") != 0);
}

static void test_cache_full_and_timeouts(void)
{
    reset();
    // 9 nama: cache 8 penuh -> yang paling cepat kedaluwarsa (TTL terkecil) diganti.
    for (int i = 0; i < 9; i++) {
        char c[32];
        snprintf(c, sizeof(c), "dns n%d.uji", i);
        CHECK(start(c));
        rep_begin(0x8180, 1);
        rep_rr(PTR_Q, 2, 1, (uint32_t)(100 + (i == 3 ? -50 : i)), IP1, 4);
        dns_rx(g_r, g_rl);
    }
    CHECK(strstr(run("dns"), "cache=8/8") != 0);
    CHECK(strstr(g_out, "n3.uji") == 0 && strstr(g_out, "n8.uji") != 0 && strstr(g_out, "n0.uji") != 0);

    // ARP tanpa jawaban: 3 percobaan lalu gagal; query tanpa balasan: 3 s.
    g_ntx = 0;
    CHECK(strncmp(run("dns x.uji 9"), "OK: DNS ", 8) == 0);
    for (int i = 0; i < 4; i++) {
        dns_poll();
        timer_ticks += 100;
    }
    CHECK(g_ntx == 3 && g_dns_state == DNS_IDLE && strstr(g_dns_last, "tanpa balasan ARP") != 0);
    CHECK(start("dns y.uji"));
    timer_ticks += 300;
    dns_poll();
    CHECK(g_dns_state == DNS_IDLE && strstr(g_dns_last, "tanpa balasan DNS") != 0);

    CHECK_STR(run("dns a_b"), "ERR: dns: nama 1..63 byte, label a-z 0-9 '-' dipisah titik\n");
    CHECK_STR(run("dns a.uji 1 2 3"), "ERR: dns: format: dns <nama> [oktet [port]]\n");
    CHECK_STR(run("dns a.uji x"), "ERR: dns: format: dns <nama> [oktet [port]]\n");
    CHECK_STR(run("dns a.uji 200"), "ERR: dns: oktet 1..254 (bukan IP sendiri), port 1..65535\n");
    CHECK_STR(run("dnsx"), "(tidak ditangani)");
}

// Jawab ARP lalu kirim query yang sudah dimulai (oleh perintah atau pemantau).
static int pump(void)
{
    g_ntx = 0;
    dns_poll();
    arp_from(g_dns_host);
    dns_poll();
    return g_dns_state == DNS_SENT && g_ntx == 2;
}

// P6-2: query milik pemantau: tanpa cache, tanpa baris log, hasil + token ke
// monitor_dns_done; a = 1 hanya bila ada jawaban A.
static void test_probe(void)
{
    char out[64];

    reset();
    CHECK(dns_name_check((const uint8_t *)"Bmahos.UJI", 10, out) && strcmp(out, "bmahos.uji") == 0);
    CHECK(!dns_name_check((const uint8_t *)"a_b", 3, out) && !dns_name_check((const uint8_t *)"", 0, out));

    CHECK(start("dns bmahos.uji"));                // nama masuk cache lewat perintah biasa
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 100, IP1, 4);
    dns_rx(g_r, g_rl);
    CHECK(g_md_n == 0 && g_dns_state == DNS_IDLE);

    serial_capture_reset();
    CHECK(dns_probe_start("bmahos.uji", 1, 53, 77) == 0);   // di cache, tetap ditanya
    CHECK(dns_probe_start("lain.uji", 1, 53, 78) == -1);    // query lain berjalan
    CHECK(pump());
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 100, IP1, 4);
    dns_rx(g_r, g_rl);
    CHECK(g_md_n == 1 && g_md_tok == 77 && g_md_a == 1 && strcmp(g_md_what, "= 192.168.50.123") == 0);
    CHECK(strstr(g_serial_cap, "P3: DNS") == NULL && g_dns_ok == 2);

    CHECK(dns_probe_start("tidakada.uji", 1, 53, 79) == 0);
    CHECK(pump());
    rep_begin(0x8183, 0);
    dns_rx(g_r, g_rl);
    CHECK(g_md_n == 2 && g_md_tok == 79 && g_md_a == 0 &&
          strcmp(g_md_what, "= tidak ada (NXDOMAIN)") == 0);

    CHECK(dns_probe_start("x.uji", 1, 53, 80) == 0);
    CHECK(pump());
    timer_ticks += 300;
    dns_poll();
    CHECK(g_md_n == 3 && g_md_tok == 80 && g_md_a == 0 &&
          strcmp(g_md_what, "gagal: tanpa balasan DNS (3 s)") == 0);
    CHECK(strstr(g_serial_cap, "P3: DNS") == NULL);

    // Perintah `dns` sesudahnya: baris log lagi, tanpa laporan ke pemantau.
    CHECK(start("dns y.uji"));
    rep_begin(0x8183, 0);
    dns_rx(g_r, g_rl);
    CHECK(g_md_n == 3 && strstr(g_serial_cap, "P3: DNS y.uji = tidak ada (NXDOMAIN)") != NULL);

    CHECK(dns_probe_start("a_b", 1, 53, 81) == -1);         // nama tidak sah
    CHECK(dns_probe_start("z.uji", 200, 53, 81) == -1);     // IP sendiri
    CHECK(g_dns_state == DNS_IDLE && g_md_n == 3);
}

int main(void)
{
    dns_init();
    test_names();
    test_query_and_answers();
    test_cache_full_and_timeouts();
    test_probe();
    return test_done("dns");
}

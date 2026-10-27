// P3-2: uji klien SNTP (sntp.c di-#include; rtc.c dan kprintf.c ikut ditautkan).
// NIC tiruan: e1000_tx_send menyalin frame keluar; net_udp_build cukup menulis
// MAC/IP/port tujuan supaya bisa diperiksa; entropy_get deterministik.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/sntp.c"

extern char g_serial_cap[];
void serial_capture_reset(void);

int g_e1000_rx_initialized = 1;
uint8_t g_e1000_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
uint8_t g_net_ip[4] = { 192, 168, 50, 200 };
uint64_t hhdm_offset = 0;

static uint8_t g_page[4096] __attribute__((aligned(4096)));
static int g_pmm_ok = 1;
uint64_t pmm_alloc(void)
{
    return g_pmm_ok ? (uint64_t)(uintptr_t)g_page : 0;
}

static uint8_t g_tx[8][128];
static uint32_t g_tx_len[8];
static int g_ntx;
static int g_tx_ok = 1;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_ntx < 8) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 128 ? 128 : frame_len);
        g_tx_len[g_ntx] = frame_len;
        g_ntx++;
    }
    return g_tx_ok;
}

uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;
    for (int i = 0; i < 4; i++) {
        p[30 + i] = dst_ip[i];
    }
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)sport;
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)dport;
    return 42 + plen;
}

// Sama dengan net_arp_request_build di net.c (net.c tidak ditautkan di uji ini).
uint32_t net_arp_request_build(uint8_t *p, const volatile uint8_t *ip)
{
    memset(p, 0, 60);
    for (int i = 0; i < 6; i++) {
        p[i] = 0xFF;
        p[6 + i] = g_e1000_mac[i];
        p[22 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x06;
    p[15] = 0x01;
    p[16] = 0x08;
    p[18] = 6;
    p[19] = 4;
    p[21] = 0x01;
    for (int i = 0; i < 4; i++) {
        p[28 + i] = g_net_ip[i];
        p[38 + i] = ip[i];
    }
    return 60;
}

static int g_ent_ok = 1;
static uint8_t g_ent_next = 0x10;
int entropy_get(uint8_t *out, uint32_t len)
{
    if (!g_ent_ok) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        out[i] = g_ent_next++;
    }
    return 1;
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
    if (!sntp_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

static char g_st[256];
static void st_cpy(const char *s)
{
    snprintf(g_st, sizeof(g_st), "%s", s);
}

static const uint8_t SRV_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

// ARP dari .host dengan MAC mac (bentuk frame seperti di kabel).
static void arp_from(uint8_t host, const uint8_t *mac)
{
    uint8_t f[60] = { 0 };
    memcpy(f + 22, mac, 6);
    f[28] = 192; f[29] = 168; f[30] = 50; f[31] = host;
    sntp_arp_seen(f);
}

// Balasan NTP: mode/versi/LI di byte 0, stratum, originate, transmit (detik NTP).
static uint8_t g_rep[48];
static void mk_rep(uint8_t b0, uint8_t stratum, const uint8_t *orig, uint32_t ntp_secs)
{
    memset(g_rep, 0, sizeof(g_rep));
    g_rep[0] = b0;
    g_rep[1] = stratum;
    memcpy(g_rep + 24, orig, 8);
    g_rep[40] = (uint8_t)(ntp_secs >> 24);
    g_rep[41] = (uint8_t)(ntp_secs >> 16);
    g_rep[42] = (uint8_t)(ntp_secs >> 8);
    g_rep[43] = (uint8_t)ntp_secs;
}

static void reset(void)
{
    g_sntp_state = SNTP_IDLE;
    g_sntp_ok = g_sntp_fail = g_sntp_bad = 0;
    g_sntp_last = "belum pernah";
    g_ntx = 0;
    g_rtc_ok = 0;
    g_time_src = 0;
}

static void test_start_errors(void)
{
    const char *why = "";

    reset();
    g_sntp_page_phys = 0;
    CHECK(sntp_start(1, 123, &why) != 0 && strcmp(why, "tanpa NIC") == 0);
    g_pmm_ok = 0;
    sntp_init();
    CHECK(g_sntp_page_phys == 0);
    g_pmm_ok = 1;
    sntp_init();
    CHECK(g_sntp_page_phys == (uint64_t)(uintptr_t)g_page);
    CHECK(sntp_start(0, 123, &why) != 0 && sntp_start(255, 123, &why) != 0);
    CHECK(sntp_start(200, 123, &why) != 0);     // IP sendiri
    CHECK(sntp_start(1, 0, &why) != 0 && sntp_start(1, 65536, &why) != 0);
    g_ent_ok = 0;
    CHECK(sntp_start(1, 123, &why) != 0 && strcmp(why, "entropi belum cukup") == 0);
    g_ent_ok = 1;
    CHECK(g_sntp_state == SNTP_IDLE);
}

static void test_flow(void)
{
    const char *why = "";
    uint8_t orig[8];

    reset();
    timer_ticks = 5000;
    g_ent_next = 0x10;
    CHECK(sntp_start(1, 123, &why) == 0 && g_sntp_state == SNTP_ARP);
    CHECK(sntp_start(1, 123, &why) != 0 && strcmp(why, "sinkron sebelumnya masih berjalan") == 0);
    CHECK(g_sntp_lport >= 49152);

    sntp_poll();                                   // ARP pertama langsung
    CHECK(g_ntx == 1 && g_tx[0][12] == 0x08 && g_tx[0][13] == 0x06 && g_tx[0][21] == 1);
    CHECK(g_tx[0][38] == 192 && g_tx[0][41] == 1 && g_tx[0][0] == 0xFF);
    sntp_poll();
    CHECK(g_ntx == 1);                             // berikutnya setelah 100 tick

    static const uint8_t mcast[6] = { 0x01, 0, 0, 0, 0, 1 }, zero[6] = { 0 };
    arp_from(2, SRV_MAC);                          // IP lain
    arp_from(1, mcast);                            // MAC multicast
    arp_from(1, zero);                             // MAC nol
    CHECK(!g_sntp_mac_ok);
    arp_from(1, SRV_MAC);
    CHECK(g_sntp_mac_ok);
    sntp_poll();                                   // permintaan NTP
    CHECK(g_ntx == 2 && g_sntp_state == SNTP_SENT);
    CHECK(memcmp(g_tx[1], SRV_MAC, 6) == 0 && g_tx[1][42] == 0x23 && g_tx_len[1] == 90);
    CHECK(g_tx[1][36] == 0 && g_tx[1][37] == 123);
    CHECK((uint16_t)(g_tx[1][34] << 8 | g_tx[1][35]) == g_sntp_lport);
    memcpy(orig, g_tx[1] + 42 + 40, 8);
    CHECK(memcmp(orig, g_sntp_nonce, 8) == 0);

    static const uint8_t ip1[4] = { 192, 168, 50, 1 }, ip2[4] = { 192, 168, 50, 2 };
    CHECK(sntp_wants(ip1, 123, g_sntp_lport));
    CHECK(!sntp_wants(ip2, 123, g_sntp_lport));
    CHECK(!sntp_wants(ip1, 124, g_sntp_lport));
    CHECK(!sntp_wants(ip1, 123, (uint16_t)(g_sntp_lport + 1)));

    // Balasan palsu/rusak: diabaikan, tetap menunggu.
    uint32_t t2030 = (uint32_t)(1893456000ULL + NTP_UNIX_DELTA);   // 2030-01-01 00:00:00 UTC
    uint8_t bad_orig[8];
    memcpy(bad_orig, orig, 8);
    bad_orig[7] ^= 1;
    mk_rep(0x24, 2, orig, t2030);
    sntp_rx(g_rep, 47);                            // pendek
    mk_rep(0xE4, 2, orig, t2030);
    sntp_rx(g_rep, 48);                            // LI 3 (tidak sinkron)
    mk_rep(0x14, 2, orig, t2030);
    sntp_rx(g_rep, 48);                            // versi 2
    mk_rep(0x23, 2, orig, t2030);
    sntp_rx(g_rep, 48);                            // mode 3
    mk_rep(0x24, 0, orig, t2030);
    sntp_rx(g_rep, 48);                            // stratum 0 (kiss-o'-death)
    mk_rep(0x24, 16, orig, t2030);
    sntp_rx(g_rep, 48);                            // stratum 16
    mk_rep(0x24, 2, bad_orig, t2030);
    sntp_rx(g_rep, 48);                            // originate bukan nonce kita
    mk_rep(0x24, 2, orig, 1000);
    sntp_rx(g_rep, 48);                            // sebelum 1970
    CHECK(g_sntp_bad == 8 && g_sntp_state == SNTP_SENT && !g_rtc_ok);

    // Sah (versi 3 juga boleh): jam diset, koreksi 0 karena belum ada jam.
    serial_capture_reset();
    mk_rep(0x1C, 2, orig, t2030);
    sntp_rx(g_rep, 48);
    CHECK(g_sntp_state == SNTP_IDLE && g_sntp_ok == 1 && g_rtc_ok && g_time_src == 1);
    CHECK(rtc_now() == 1893456000ULL);
    CHECK(strstr(g_serial_cap, "P3: SNTP ok dari 192.168.50.1 stratum 2 koreksi 0 s\r\n") != 0);
    timer_ticks += 250;                            // 2,5 s kemudian
    rtc_status(st_cpy);
    CHECK_STR(g_st, "waktu: 2030-01-01 00:00:02 epoch=1893456002 sumber=sntp oktet=1 stratum=2 "
                    "(UTC) koreksi=0 s\n");
    sntp_status(st_cpy);
    CHECK_STR(g_st, "sntp: diam terakhir=ok ok=1 gagal=0 diabaikan=8\n");
    CHECK(!sntp_wants(ip1, 123, g_sntp_lport));    // tidak menunggu lagi

    // Sinkron kedua 60 s lebih awal: koreksi -62 (jam sekarang +2 s).
    CHECK(sntp_start(1, 123, &why) == 0);
    arp_from(1, SRV_MAC);
    sntp_poll();
    memcpy(orig, g_sntp_nonce, 8);
    mk_rep(0x24, 3, orig, t2030 - 60);
    sntp_rx(g_rep, 48);
    CHECK(g_sntp_ok == 2 && rtc_now() == 1893456000ULL - 60);
    rtc_status(st_cpy);
    CHECK(strstr(g_st, "stratum=3 (UTC) koreksi=-62 s\n") != 0);
}

static void test_timeouts(void)
{
    const char *why = "";

    reset();
    timer_ticks = 10000;
    CHECK(sntp_start(9, 4123, &why) == 0);
    for (int i = 0; i < 5; i++) {
        sntp_poll();
        timer_ticks += 100;
    }
    // ARP pada tick 10000, 10100, 10200; tick 10300: 3 percobaan habis -> gagal.
    CHECK(g_ntx == 3 && g_sntp_state == SNTP_IDLE && g_sntp_fail == 1);
    sntp_status(st_cpy);
    CHECK_STR(g_st, "sntp: diam terakhir=tanpa balasan ARP ok=0 gagal=1 diabaikan=0\n");

    CHECK(sntp_start(9, 4123, &why) == 0);
    arp_from(9, SRV_MAC);
    sntp_poll();
    CHECK(g_sntp_state == SNTP_SENT);
    timer_ticks += 299;
    sntp_poll();
    CHECK(g_sntp_state == SNTP_SENT);
    timer_ticks += 1;
    sntp_poll();
    CHECK(g_sntp_state == SNTP_IDLE && g_sntp_fail == 2);
    CHECK(strcmp(g_sntp_last, "tanpa balasan NTP (3 s)") == 0);

    // Kirim gagal.
    CHECK(sntp_start(9, 4123, &why) == 0);
    arp_from(9, SRV_MAC);
    g_tx_ok = 0;
    sntp_poll();
    g_tx_ok = 1;
    CHECK(g_sntp_state == SNTP_IDLE && strcmp(g_sntp_last, "kirim gagal") == 0);
}

static void test_cmd(void)
{
    reset();
    CHECK_STR(run("waktu"), "(tidak ditangani)");
    CHECK_STR(run("waktu sinkron"), "(tidak ditangani)");
    CHECK_STR(run("waktu sinkron 1"), "OK: SNTP ke 192.168.50.1:123 dimulai, lihat `waktu` (maks 6 s)\n");
    CHECK_STR(run("waktu sinkron 1"), "ERR: waktu: sinkron sebelumnya masih berjalan\n");
    reset();
    CHECK_STR(run("waktu sinkron 7  12300"),
              "OK: SNTP ke 192.168.50.7:12300 dimulai, lihat `waktu` (maks 6 s)\n");
    reset();
    static const char *const bad[] = { "waktu sinkron x", "waktu sinkron 1 2 3", "waktu sinkron 1x",
                                       "waktu sinkron 1234567", "waktu sinkron -1", "waktu sinkron  " };
    int all = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        all &= strcmp(run(bad[i]), "ERR: waktu: format: waktu sinkron <oktet 1..254> [port]\n") == 0;
    }
    CHECK(all);
    CHECK_STR(run("waktu sinkron 300"), "ERR: waktu: oktet 1..254 (bukan IP sendiri), port 1..65535\n");
    CHECK(g_sntp_state == SNTP_IDLE);
}

int main(void)
{
    test_start_errors();
    test_flow();
    test_timeouts();
    test_cmd();
    return test_done("sntp");
}

// P6-1: uji pemantau ping (monitor.c di-#include). NIC tiruan: frame keluar
// disalin; net_checksum16 asli (RFC 1071) supaya checksum frame bisa dicek.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/monitor.c"

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

static uint8_t g_tx[16][64];
static uint32_t g_tx_len[16];
static int g_ntx;
static int g_tx_ok = 1;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_ntx < 16) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 64 ? 64 : frame_len);
        g_tx_len[g_ntx] = frame_len;
        g_ntx++;
    }
    return g_tx_ok;
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

uint16_t net_checksum16(volatile uint8_t *p, uint32_t len)
{
    uint32_t sum = 0;

    for (uint32_t i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t)p[i] << 8 | p[i + 1];
    }
    if (len & 1) {
        sum += (uint32_t)p[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
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
    if (!monitor_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

static const uint8_t TGT_MAC[6] = { 0x02, 0, 0, 0, 0, 0x01 };

static void arp_from(uint8_t host)
{
    uint8_t f[60] = { 0 };
    memcpy(f + 22, TGT_MAC, 6);
    f[28] = 192; f[29] = 168; f[30] = 50; f[31] = host;
    monitor_arp_seen(f);
}

// Balasan echo (type 0) dari .host dengan id/seq; frame = Ethernet + IPv4 20 + ICMP 8.
static void reply(uint8_t host, uint16_t id, uint16_t seq, uint8_t type)
{
    uint8_t f[64] = { 0 };
    f[14] = 0x45;
    f[23] = 1;
    f[26] = 192; f[27] = 168; f[28] = 50; f[29] = host;
    f[34] = type;
    f[38] = (uint8_t)(id >> 8);
    f[39] = (uint8_t)id;
    f[40] = (uint8_t)(seq >> 8);
    f[41] = (uint8_t)seq;
    monitor_icmp_reply(f, 20, 8 + MON_PAYLOAD);
}

static void reset(void)
{
    memset(g_mon, 0, sizeof(g_mon));
    g_ntx = 0;
    timer_ticks = 1000;
}

static void test_cmds(void)
{
    reset();
    CHECK_STR(run("pantau"), "pantau: target=0/4 (ping; NAIK = 1 balasan, TURUN = 3 gagal)\n");
    CHECK_STR(run("pantauX"), "(tidak ditangani)");
    CHECK_STR(run("pantau tambah 1"), "OK pantau 1: 192.168.50.1 tiap 10 s\n");
    CHECK_STR(run("pantau tambah 7 5"), "OK pantau 2: 192.168.50.7 tiap 5 s\n");
    CHECK_STR(run("pantau tambah 1 20"), "ERR: pantau: target sudah ada\n");
    const char *e = "ERR: pantau: tambah <oktet 1..254, bukan IP sendiri> [interval 5..3600 s]\n";
    CHECK_STR(run("pantau tambah 200"), e);
    CHECK_STR(run("pantau tambah 0"), e);
    CHECK_STR(run("pantau tambah 255"), e);
    CHECK_STR(run("pantau tambah 9 4"), e);
    CHECK_STR(run("pantau tambah 9 3601"), e);
    CHECK_STR(run("pantau tambah 9 5 6"), e);
    CHECK_STR(run("pantau tambah x"), e);
    CHECK_STR(run("pantau tambah 3"), "OK pantau 3: 192.168.50.3 tiap 10 s\n");
    CHECK_STR(run("pantau tambah 4"), "OK pantau 4: 192.168.50.4 tiap 10 s\n");
    CHECK_STR(run("pantau tambah 5"), "ERR: pantau: penuh (maks 4 target)\n");
    CHECK_STR(run("pantau hapus 2"), "OK pantau: target 2 dihapus\n");
    CHECK_STR(run("pantau hapus 2"), "ERR: pantau: hapus <nomor target>\n");
    CHECK_STR(run("pantau hapus 9"), "ERR: pantau: hapus <nomor target>\n");
    CHECK_STR(run("pantau tambah 5 3600"), "OK pantau 2: 192.168.50.5 tiap 3600 s\n");   // slot kosong dipakai
    CHECK_STR(run("pantau apa"),
              "ERR: pantau: pantau | pantau tambah <oktet> [interval] | pantau hapus <n>\n");
    CHECK(strstr(run("pantau"), "target=4/4") != 0);
    CHECK(strstr(g_out, "2: 192.168.50.5 belum tiap=3600 s kirim=0 balas=0 gagal_beruntun=0 "
                        "rtt=0/0/0 ms ganti=0\n") != 0);
}

static void test_naik_turun(void)
{
    reset();
    CHECK(strncmp(run("pantau tambah 7 5"), "OK", 2) == 0);
    mon_t *m = &g_mon[0];

    monitor_poll();                                // ARP
    CHECK(g_ntx == 1 && g_tx[0][13] == 0x06 && g_tx[0][41] == 7);
    arp_from(6);                                   // host lain: abaikan
    CHECK(!m->mac_ok);
    arp_from(7);
    CHECK(m->mac_ok);
    timer_ticks += 1;
    monitor_poll();                                // echo request
    CHECK(g_ntx == 2 && m->waiting && m->sent == 1 && m->seq == 1);
    const uint8_t *f = g_tx[1];
    CHECK(memcmp(f, TGT_MAC, 6) == 0 && f[12] == 0x08 && f[13] == 0 && f[23] == 1);
    CHECK(f[30] == 192 && f[33] == 7 && f[34] == 8 && f[38] == 0xB0 && f[39] == 0xA0 && f[41] == 1);
    CHECK(g_tx_len[1] == 60 && f[16] == 0 && f[17] == 44);
    CHECK(net_checksum16((uint8_t *)f + 14, 20) == 0);             // checksum IP sah
    CHECK(net_checksum16((uint8_t *)f + 34, 8 + MON_PAYLOAD) == 0); // checksum ICMP sah
    CHECK(memcmp(f + 42, "bmahOS-pantau-P6", 16) == 0);

    // Balasan salah: id lain, seq lain, IP lain, type 8 -> diabaikan.
    reply(7, 0xB0A1, 1, 0);
    reply(7, 0xB0A0, 2, 0);
    reply(8, 0xB0A0, 1, 0);
    reply(7, 0xB0A0, 1, 8);
    CHECK(m->waiting && m->recv == 0);

    serial_capture_reset();
    timer_ticks += 3;
    reply(7, 0xB0A0, 1, 0);
    CHECK(!m->waiting && m->recv == 1 && m->state == MON_STATE_NAIK && m->rtt_last == 3);
    CHECK(strstr(g_serial_cap, "P6: 192.168.50.7 NAIK (rtt 30 ms)\r\n") != 0);
    reply(7, 0xB0A0, 1, 0);                       // duplikat: tidak menunggu lagi
    CHECK(m->recv == 1);

    // Tiga probe tanpa balasan (tiap 5 s, tunggu 1 s) -> TURUN satu kali.
    serial_capture_reset();
    for (int k = 0; k < 3; k++) {
        timer_ticks = m->next_at;
        monitor_poll();                            // kirim
        CHECK(m->waiting);
        timer_ticks += MON_WAIT;
        monitor_poll();                            // batas waktu
        CHECK(!m->waiting);
    }
    CHECK(m->fails == 3 && m->state == MON_STATE_TURUN && !m->mac_ok && m->changes == 2);
    CHECK(strstr(g_serial_cap, "P6: 192.168.50.7 TURUN (3 gagal berturut-turut, terakhir: "
                               "tanpa balasan ping)\r\n") != 0);
    CHECK(strstr(g_serial_cap, "NAIK") == 0);

    // Probe berikutnya ARP ulang; jawaban -> NAIK lagi, gagal_beruntun 0.
    serial_capture_reset();
    timer_ticks = m->next_at;
    int before = g_ntx;
    monitor_poll();
    CHECK(g_ntx == before + 1 && g_tx[before][13] == 0x06);
    arp_from(7);
    monitor_poll();
    CHECK(m->waiting);
    timer_ticks += 7;
    reply(7, 0xB0A0, m->seq, 0);
    CHECK(m->state == MON_STATE_NAIK && m->fails == 0 && m->rtt_min == 3 && m->rtt_max == 7);
    CHECK(strstr(g_serial_cap, "P6: 192.168.50.7 NAIK (rtt 70 ms)\r\n") != 0);
    CHECK(strstr(run("pantau"), "1: 192.168.50.7 naik tiap=5 s kirim=5 balas=2 gagal_beruntun=0 "
                                "rtt=70/30/70 ms ganti=3\n") != 0);
}

static void test_arp_gagal(void)
{
    reset();
    CHECK(strncmp(run("pantau tambah 9 5"), "OK", 2) == 0);
    mon_t *m = &g_mon[0];

    serial_capture_reset();
    for (int i = 0; i < 2000 && m->fails < 3; i++) {
        monitor_poll();
        timer_ticks += 10;
    }
    // Tiap probe: 3 ARP (1 s) lalu gagal; probe berikutnya 5 s setelah awal probe.
    CHECK(m->fails == 3 && m->state == MON_STATE_TURUN && m->sent == 0 && g_ntx == 9);
    CHECK(strstr(g_serial_cap, "P6: 192.168.50.9 TURUN (3 gagal berturut-turut, terakhir: "
                               "tanpa balasan ARP)\r\n") != 0);
    CHECK(timer_ticks >= 1000 + 1300 && timer_ticks < 1000 + 1500);

    // Kirim gagal = kegagalan juga.
    reset();
    run("pantau tambah 9 5");
    m = &g_mon[0];
    monitor_poll();
    arp_from(9);
    g_tx_ok = 0;
    monitor_poll();
    g_tx_ok = 1;
    CHECK(m->fails == 1 && !m->waiting);

    // Tanpa NIC (halaman TX belum ada): tambah ditolak.
    reset();
    uint64_t pg = g_mon_page_phys;
    g_mon_page_phys = 0;
    CHECK_STR(run("pantau tambah 9"), "ERR: pantau: tanpa NIC\n");
    g_mon_page_phys = pg;
}

int main(void)
{
    monitor_init();
    test_cmds();
    test_naik_turun();
    test_arp_gagal();
    return test_done("monitor");
}

// P6: uji pemantau ping/tcp/dns + syslog (monitor.c di-#include). NIC tiruan:
// frame keluar disalin; net_checksum16 asli (RFC 1071) supaya checksum frame
// echo bisa dicek; dns.c diganti dns_probe_start/dns_name_check tiruan; jam dari
// rtc.c asli (rtc_set_sntp).

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/monitor.c"

extern char g_serial_cap[];
void serial_capture_reset(void);

int g_e1000_rx_initialized = 1;
uint8_t g_e1000_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
uint8_t g_net_ip[4] = { 192, 168, 50, 200 };
uint64_t hhdm_offset = 0;

int net_ip_ready(void)
{
    return (g_net_ip[0] | g_net_ip[1] | g_net_ip[2] | g_net_ip[3]) != 0;
}

static uint8_t g_page[4096] __attribute__((aligned(4096)));
uint64_t pmm_alloc(void)
{
    return (uint64_t)(uintptr_t)g_page;
}

#define TXN 32
static uint8_t g_tx[TXN][256];
static uint32_t g_tx_len[TXN];
static int g_ntx;
static int g_tx_ok = 1;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_ntx < TXN) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 256 ? 256 : frame_len);
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

void net_ipv4_hdr(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                  uint8_t proto, uint32_t l4_len)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0;
    memset(p + 14, 0, 20);
    p[14] = 0x45;
    p[16] = (uint8_t)((20 + l4_len) >> 8);
    p[17] = (uint8_t)(20 + l4_len);
    p[20] = 0x40;
    p[22] = 64;
    p[23] = proto;
    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = dst_ip[i];
    }
    uint16_t c = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(c >> 8);
    p[25] = (uint8_t)c;
}

// SYN tiruan: hanya field yang dibaca uji (frame asli diuji di test_net).
uint32_t net_tcp_syn_build(uint8_t *p, const volatile uint8_t *dst_mac,
                           const volatile uint8_t *dst_ip, uint16_t sport,
                           uint16_t dport, uint32_t seq)
{
    memset(p, 0, 60);
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
    }
    p[12] = 0x08;
    p[23] = 6;
    for (int i = 0; i < 4; i++) {
        p[30 + i] = dst_ip[i];
    }
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)sport;
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)dport;
    p[38] = (uint8_t)(seq >> 24);
    p[39] = (uint8_t)(seq >> 16);
    p[40] = (uint8_t)(seq >> 8);
    p[41] = (uint8_t)seq;
    p[47] = 0x02;
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

static uint8_t g_ent_next = 0x10;
static int g_ent_fail;
int entropy_get(uint8_t *out, uint32_t len)
{
    if (g_ent_fail) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        out[i] = g_ent_next++;
    }
    return 1;
}

// dns.c tiruan: nama a-z 0-9 '-' '.', huruf besar -> kecil; probe dicatat.
int dns_name_check(const volatile uint8_t *s, uint32_t n, char *out)
{
    if (n < 1 || n > 63) {
        return 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        char c = (char)s[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            return 0;
        }
        out[i] = c;
    }
    out[n] = 0;
    return 1;
}

static int g_dp_ret, g_dp_n;
static char g_dp_name[64];
static uint32_t g_dp_host, g_dp_port, g_dp_tok;
int dns_probe_start(const char *name, uint32_t host, uint32_t port, uint32_t tok)
{
    if (g_dp_ret != 0) {
        return g_dp_ret;
    }
    g_dp_n++;
    snprintf(g_dp_name, sizeof(g_dp_name), "%s", name);
    g_dp_host = host;
    g_dp_port = port;
    g_dp_tok = tok;
    return 0;
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
static const uint8_t SL_MAC[6] = { 0x02, 0, 0, 0, 0, 0x14 };
static const uint8_t SL_MAC2[6] = { 0x02, 0, 0, 0, 0, 0x15 };

static void arp_mac(uint8_t host, const uint8_t mac[6])
{
    uint8_t f[60] = { 0 };
    memcpy(f + 22, mac, 6);
    f[28] = 192; f[29] = 168; f[30] = 50; f[31] = host;
    monitor_arp_seen(f);
}

static void arp_from(uint8_t host)
{
    arp_mac(host, TGT_MAC);
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

// Segmen TCP dari .host:sport ke port lokal dport (header TCP di offset 34).
static int tcp_reply(uint8_t host, uint16_t sport, uint16_t dport, uint8_t fl, uint32_t ack)
{
    uint8_t f[60] = { 0 };
    f[14] = 0x45;
    f[23] = 6;
    f[26] = 192; f[27] = 168; f[28] = 50; f[29] = host;
    f[34] = (uint8_t)(sport >> 8);
    f[35] = (uint8_t)sport;
    f[36] = (uint8_t)(dport >> 8);
    f[37] = (uint8_t)dport;
    f[42] = (uint8_t)(ack >> 24);
    f[43] = (uint8_t)(ack >> 16);
    f[44] = (uint8_t)(ack >> 8);
    f[45] = (uint8_t)ack;
    f[46] = 0x50;
    f[47] = fl;
    return monitor_tcp_seen(f, 34);
}

static uint16_t frame_lport(const uint8_t *f)
{
    return (uint16_t)(f[34] << 8 | f[35]);
}

static uint32_t frame_seq(const uint8_t *f)
{
    return (uint32_t)f[38] << 24 | (uint32_t)f[39] << 16 | (uint32_t)f[40] << 8 | f[41];
}

static void reset(void)
{
    memset(g_mon, 0, sizeof(g_mon));
    memset(&g_sl, 0, sizeof(g_sl));
    g_sl_head = g_sl_tail = 0;
    g_ntx = 0;
    g_ent_fail = 0;
    g_dp_ret = 0;
    g_time_src = 0;
    g_rtc_ok = 0;
    timer_ticks = 1000;
}

static void test_cmds(void)
{
    reset();
    CHECK_STR(run("pantau"), "pantau: target=0/4 (NAIK = 1 berhasil, TURUN = 3 gagal berturut-turut)\n"
                             "syslog: mati terkirim=0 dibuang=0\n");
    CHECK_STR(run("pantauX"), "(tidak ditangani)");
    CHECK_STR(run("pantau ping 1"), "OK pantau 1: ping 192.168.50.1 tiap 10 s\n");
    CHECK_STR(run("pantau ping 7 5"), "OK pantau 2: ping 192.168.50.7 tiap 5 s\n");
    CHECK_STR(run("pantau ping 1 20"), "ERR: pantau: target sudah ada\n");
    const char *e = "ERR: pantau: ping <oktet 1..254, bukan IP sendiri> [interval 5..3600 s]\n";
    CHECK_STR(run("pantau ping 200"), e);
    CHECK_STR(run("pantau ping 0"), e);
    CHECK_STR(run("pantau ping 255"), e);
    CHECK_STR(run("pantau ping 9 4"), e);
    CHECK_STR(run("pantau ping 9 3601"), e);
    CHECK_STR(run("pantau ping 9 5 6"), e);
    CHECK_STR(run("pantau ping x"), e);
    CHECK_STR(run("pantau tcp 1 80"), "OK pantau 3: tcp 192.168.50.1:80 tiap 10 s\n");
    CHECK_STR(run("pantau tcp 1 80 30"), "ERR: pantau: target sudah ada\n");
    e = "ERR: pantau: tcp <oktet 1..254, bukan IP sendiri> <port 1..65535> [interval 5..3600 s]\n";
    CHECK_STR(run("pantau tcp 1"), e);
    CHECK_STR(run("pantau tcp 1 0"), e);
    CHECK_STR(run("pantau tcp 1 65536"), e);
    CHECK_STR(run("pantau tcp 1 80 4"), e);
    CHECK_STR(run("pantau tcp 200 80"), e);
    CHECK_STR(run("pantau tcp 1 81"), "OK pantau 4: tcp 192.168.50.1:81 tiap 10 s\n");
    CHECK_STR(run("pantau dns a.uji 1 53"), "ERR: pantau: penuh (maks 4 target)\n");
    CHECK_STR(run("pantau hapus 2"), "OK pantau: target 2 dihapus\n");
    CHECK_STR(run("pantau hapus 2"), "ERR: pantau: hapus <nomor target>\n");
    CHECK_STR(run("pantau hapus 9"), "ERR: pantau: hapus <nomor target>\n");
    e = "ERR: pantau: dns <nama> <oktet server 1..254> <port 1..65535> [interval 5..3600 s]\n";
    CHECK_STR(run("pantau dns a_b 1 53"), e);
    CHECK_STR(run("pantau dns a.uji 1"), e);
    CHECK_STR(run("pantau dns a.uji 200 53"), e);
    CHECK_STR(run("pantau dns a.uji 1 53 2"), e);
    CHECK_STR(run("pantau dns Bmahos.UJI 1 53 3600"),
              "OK pantau 2: dns bmahos.uji@192.168.50.1:53 tiap 3600 s\n");   // slot kosong dipakai
    CHECK_STR(run("pantau apa"),
              "ERR: pantau: pantau | ping|tcp|dns ... | hapus <n> | syslog <oktet> [port]|mati\n");
    CHECK(strstr(run("pantau"), "target=4/4") != 0);
    CHECK(strstr(g_out, "2: dns bmahos.uji@192.168.50.1:53 belum tiap=3600 s kirim=0 balas=0 "
                        "gagal_beruntun=0 rtt=0/0/0 ms ganti=0\n") != 0);
    CHECK(strstr(g_out, "3: tcp 192.168.50.1:80 belum tiap=10 s ") != 0);
    CHECK(strstr(g_out, "1: ping 192.168.50.1 belum tiap=10 s ") != 0);
    e = "ERR: pantau: syslog <oktet 1..254, bukan IP sendiri> [port, bawaan 514] | syslog mati\n";
    CHECK_STR(run("pantau syslog 1 70000"), e);
    CHECK_STR(run("pantau syslog 200"), e);
    CHECK_STR(run("pantau syslog 1 2 3"), e);
    CHECK_STR(run("pantau syslog"),
              "ERR: pantau: pantau | ping|tcp|dns ... | hapus <n> | syslog <oktet> [port]|mati\n");
}

static void test_ping(void)
{
    reset();
    CHECK(strncmp(run("pantau ping 7 5"), "OK", 2) == 0);
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
    g_serial_mute = 1;                            // frame pemicu kena pembatas B4b
    reply(7, 0xB0A0, 1, 0);
    CHECK(g_serial_mute == 1);                    // dikembalikan sesudah baris P6
    g_serial_mute = 0;
    CHECK(!m->waiting && m->recv == 1 && m->state == MON_STATE_NAIK && m->rtt_last == 3);
    CHECK(strstr(g_serial_cap, "P6: ping 192.168.50.7 NAIK (rtt 30 ms)\r\n") != 0);
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
    CHECK(strstr(g_serial_cap, "P6: ping 192.168.50.7 TURUN (3 gagal berturut-turut, terakhir: "
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
    CHECK(strstr(g_serial_cap, "P6: ping 192.168.50.7 NAIK (rtt 70 ms)\r\n") != 0);
    CHECK(strstr(run("pantau"), "1: ping 192.168.50.7 naik tiap=5 s kirim=5 balas=2 gagal_beruntun=0 "
                                "rtt=70/30/70 ms ganti=3\n") != 0);
}

static void test_arp_gagal(void)
{
    reset();
    CHECK(strncmp(run("pantau ping 9 5"), "OK", 2) == 0);
    mon_t *m = &g_mon[0];

    serial_capture_reset();
    for (int i = 0; i < 2000 && m->fails < 3; i++) {
        monitor_poll();
        timer_ticks += 10;
    }
    // Tiap probe: 3 ARP (1 s) lalu gagal; probe berikutnya 5 s setelah awal probe.
    CHECK(m->fails == 3 && m->state == MON_STATE_TURUN && m->sent == 0 && g_ntx == 9);
    CHECK(strstr(g_serial_cap, "P6: ping 192.168.50.9 TURUN (3 gagal berturut-turut, terakhir: "
                               "tanpa balasan ARP)\r\n") != 0);
    CHECK(timer_ticks >= 1000 + 1300 && timer_ticks < 1000 + 1500);

    // Kirim gagal = kegagalan juga.
    reset();
    run("pantau ping 9 5");
    m = &g_mon[0];
    monitor_poll();
    arp_from(9);
    g_tx_ok = 0;
    monitor_poll();
    g_tx_ok = 1;
    CHECK(m->fails == 1 && !m->waiting);

    // Tanpa NIC (halaman TX belum ada): tambah dan syslog ditolak.
    reset();
    uint64_t pg = g_mon_page_phys;
    g_mon_page_phys = 0;
    CHECK_STR(run("pantau ping 9"), "ERR: pantau: tanpa NIC\n");
    CHECK_STR(run("pantau syslog 1"), "ERR: pantau: tanpa NIC\n");
    g_mon_page_phys = pg;
}

static void test_tcp(void)
{
    reset();
    CHECK_STR(run("pantau tcp 7 80 5"), "OK pantau 1: tcp 192.168.50.7:80 tiap 5 s\n");
    mon_t *m = &g_mon[0];

    monitor_poll();                                // ARP
    CHECK(g_ntx == 1 && g_tx[0][13] == 0x06 && g_tx[0][41] == 7);
    arp_from(7);
    g_ent_next = 0x10;
    monitor_poll();                                // SYN
    CHECK(g_ntx == 2 && m->waiting && m->sent == 1);
    const uint8_t *f = g_tx[1];
    uint16_t lp = frame_lport(f);
    uint32_t isn = frame_seq(f);
    CHECK(memcmp(f, TGT_MAC, 6) == 0 && f[33] == 7 && f[36] == 0 && f[37] == 80 && f[47] == 0x02);
    CHECK(lp == 49152 + (0x1011 % 16384) && isn == 0x12131415);

    // Bukan jawaban SYN kita -> 0 (net.c memperlakukannya seperti biasa).
    CHECK(tcp_reply(7, 80, (uint16_t)(lp + 1), 0x12, isn + 1) == 0);   // port lokal lain
    CHECK(tcp_reply(7, 81, lp, 0x12, isn + 1) == 0);                  // port target lain
    CHECK(tcp_reply(8, 80, lp, 0x12, isn + 1) == 0);                  // IP lain
    CHECK(tcp_reply(7, 80, lp, 0x12, isn) == 0);                      // ACK salah
    CHECK(tcp_reply(7, 80, lp, 0x02, isn + 1) == 0);                  // SYN tanpa ACK
    CHECK(tcp_reply(7, 80, lp, 0x10, isn + 1) == 0);                  // ACK saja
    CHECK(m->waiting && m->recv == 0);

    serial_capture_reset();
    timer_ticks += 2;
    CHECK(tcp_reply(7, 80, lp, 0x12, isn + 1) == 1);                  // SYN-ACK
    CHECK(!m->waiting && m->state == MON_STATE_NAIK && m->rtt_last == 2);
    CHECK(strstr(g_serial_cap, "P6: tcp 192.168.50.7:80 NAIK (rtt 20 ms)\r\n") != 0);
    CHECK(tcp_reply(7, 80, lp, 0x12, isn + 1) == 0);                  // ulangan: probe selesai

    // RST|ACK (port tertutup) 3x -> TURUN; tiap probe port lokal + nomor urut baru.
    serial_capture_reset();
    for (int k = 0; k < 3; k++) {
        timer_ticks = m->next_at;
        int b = g_ntx;
        monitor_poll();
        CHECK(g_ntx == b + 1 && g_tx[b][47] == 0x02);
        CHECK(frame_lport(g_tx[b]) != lp && frame_seq(g_tx[b]) != isn);
        lp = frame_lport(g_tx[b]);
        isn = frame_seq(g_tx[b]);
        CHECK(tcp_reply(7, 80, lp, 0x14, isn + 1) == 1);
        CHECK(!m->waiting && m->fails == (uint32_t)k + 1);
    }
    CHECK(m->state == MON_STATE_TURUN && !m->mac_ok);
    CHECK(strstr(g_serial_cap, "P6: tcp 192.168.50.7:80 TURUN (3 gagal berturut-turut, terakhir: "
                               "port tertutup (RST))\r\n") != 0);

    // Tanpa jawaban (port difilter): "tanpa balasan TCP".
    timer_ticks = m->next_at;
    monitor_poll();                                // ARP lagi (MAC dilupakan)
    arp_from(7);
    monitor_poll();                                // SYN
    CHECK(m->waiting);
    timer_ticks += MON_WAIT;
    monitor_poll();
    CHECK(!m->waiting && m->fails == 4);

    // Entropi belum siap: SYN tidak dikirim, bukan kegagalan, coba lagi 1 s.
    timer_ticks = m->next_at;
    monitor_poll();                                // ARP
    arp_from(7);
    int b = g_ntx;
    uint64_t s0 = m->sent;
    g_ent_fail = 1;
    monitor_poll();
    g_ent_fail = 0;
    CHECK(g_ntx == b && !m->waiting && m->sent == s0 && m->fails == 4 &&
          m->next_at == timer_ticks + MON_RETRY);
    CHECK(strstr(run("pantau"), "1: tcp 192.168.50.7:80 turun tiap=5 s kirim=5 balas=1 "
                                "gagal_beruntun=4 ") != 0);
}

static void test_dns_probe(void)
{
    reset();
    CHECK_STR(run("pantau dns BmahOS.uji 3 5353 5"),
              "OK pantau 1: dns bmahos.uji@192.168.50.3:5353 tiap 5 s\n");
    mon_t *m = &g_mon[0];

    arp_from(3);
    CHECK(!m->mac_ok);                             // dns: ARP diurus dns.c
    g_dp_n = 0;
    monitor_poll();
    CHECK(g_dp_n == 1 && strcmp(g_dp_name, "bmahos.uji") == 0 && g_dp_host == 3 &&
          g_dp_port == 5353 && m->waiting && m->sent == 1 && g_ntx == 0);
    uint32_t tok = g_dp_tok;
    monitor_dns_done(tok + 1, 1, "= 1.2.3.4");     // token lain
    CHECK(m->waiting && m->recv == 0);

    serial_capture_reset();
    timer_ticks += 4;
    monitor_dns_done(tok, 1, "= 192.168.50.123");
    CHECK(!m->waiting && m->state == MON_STATE_NAIK && m->rtt_last == 4);
    CHECK(strstr(g_serial_cap, "P6: dns bmahos.uji@192.168.50.3:5353 NAIK "
                               "(192.168.50.123, rtt 40 ms)\r\n") != 0);

    // dns.c sibuk (query `dns` lain): coba lagi 1 s kemudian, bukan kegagalan.
    timer_ticks = m->next_at;
    g_dp_ret = -1;
    monitor_poll();
    g_dp_ret = 0;
    CHECK(!m->waiting && m->sent == 1 && m->fails == 0 && m->next_at == timer_ticks + MON_RETRY);

    // NXDOMAIN, tanpa hasil (batas MON_DNS_WAIT; hasil telat diabaikan), tanpa balasan -> TURUN.
    serial_capture_reset();
    timer_ticks = m->next_at;
    monitor_poll();
    CHECK(g_dp_tok != tok);
    monitor_dns_done(g_dp_tok, 0, "= tidak ada (NXDOMAIN)");
    CHECK(m->fails == 1 && !m->waiting);
    timer_ticks = m->next_at;
    monitor_poll();
    tok = g_dp_tok;
    timer_ticks += MON_DNS_WAIT;
    monitor_poll();
    CHECK(m->fails == 2 && !m->waiting);
    monitor_dns_done(tok, 1, "= 192.168.50.123");
    CHECK(m->fails == 2 && m->recv == 1);
    timer_ticks = m->next_at;
    monitor_poll();
    monitor_dns_done(g_dp_tok, 0, "gagal: tanpa balasan DNS (3 s)");
    CHECK(m->fails == 3 && m->state == MON_STATE_TURUN);
    CHECK(strstr(g_serial_cap, "P6: dns bmahos.uji@192.168.50.3:5353 TURUN (3 gagal berturut-turut, "
                               "terakhir: tanpa balasan DNS (3 s))\r\n") != 0);

    // Target dihapus saat query berjalan: hasilnya diabaikan.
    timer_ticks = m->next_at;
    monitor_poll();
    tok = g_dp_tok;
    CHECK_STR(run("pantau hapus 1"), "OK pantau: target 1 dihapus\n");
    serial_capture_reset();
    monitor_dns_done(tok, 1, "= 192.168.50.123");
    CHECK(strstr(g_serial_cap, "P6:") == 0);
}

static void test_syslog(void)
{
    reset();
    uint64_t ep = rtc_days_from_civil(2026, 10, 28) * 86400 + 3 * 3600 + 4 * 60 + 5;
    rtc_set_sntp(ep, 1, 2);                        // jam UTC dari SNTP mulai tick ini
    CHECK_STR(run("pantau syslog 1 5514"),
              "OK pantau: syslog ke 192.168.50.1:5514 (pesan uji dikirim)\n");
    CHECK(g_sl_tail - g_sl_head == 1);
    monitor_poll();                                // ARP ke .1
    CHECK(g_ntx == 1 && g_tx[0][13] == 0x06 && g_tx[0][41] == 1);
    monitor_poll();                                // belum 1 s: tanpa ARP ulang
    CHECK(g_ntx == 1);
    arp_mac(1, SL_MAC);
    monitor_poll();                                // datagram
    CHECK(g_ntx == 2 && g_sl.sent == 1 && g_sl_tail == g_sl_head);
    const uint8_t *f = g_tx[1];
    const char *want = "<134>1 2026-10-28T03:04:05Z 192.168.50.200 bmahOS - pantau - "
                       "syslog pantau aktif ke 192.168.50.1:5514";
    CHECK(memcmp(f, SL_MAC, 6) == 0 && f[33] == 1 && f[34] == 0x02 && f[35] == 0x02 &&
          f[36] == 0x15 && f[37] == 0x8A);
    CHECK(g_tx_len[1] == 42 + strlen(want) && memcmp(f + 42, want, strlen(want)) == 0);

    // Perubahan keadaan target -> pesan syslog (NAIK = notice, PRI 133).
    CHECK(strncmp(run("pantau ping 7 5"), "OK", 2) == 0);
    mon_t *m = &g_mon[0];
    monitor_poll();                                // ARP target
    arp_from(7);
    monitor_poll();                                // echo
    reply(7, 0xB0A0, m->seq, 0);
    CHECK(m->state == MON_STATE_NAIK && g_sl_tail - g_sl_head == 1);
    monitor_poll();
    f = g_tx[g_ntx - 1];
    want = "<133>1 2026-10-28T03:04:05Z 192.168.50.200 bmahOS - pantau - ping 192.168.50.7 NAIK (rtt 0 ms)";
    CHECK(g_tx_len[g_ntx - 1] == 42 + strlen(want) && memcmp(f + 42, want, strlen(want)) == 0);

    // MAC tujuan selalu diperbarui dari ARP.
    arp_mac(1, SL_MAC2);
    CHECK(memcmp(g_sl.mac, SL_MAC2, 6) == 0);

    // Tujuan baru tanpa jawaban ARP: antrean 8 penuh -> pesan baru dibuang;
    // 3 ARP tanpa jawaban -> isi antrean dibuang.
    CHECK_STR(run("pantau syslog 9"), "OK pantau: syslog ke 192.168.50.9:514 (pesan uji dikirim)\n");
    for (int i = 0; i < 9; i++) {
        sl_push(5, "x");
    }
    CHECK(g_sl_tail - g_sl_head == 8 && g_sl.lost == 2);
    for (int i = 0; i < 4; i++) {
        monitor_poll();
        timer_ticks += 100;
    }
    CHECK(g_sl_tail == g_sl_head && g_sl.lost == 10 && g_sl.sent == 2);
    CHECK(strstr(run("pantau"), "syslog: 192.168.50.9:514 terkirim=2 dibuang=10 antre=0\n") != 0);

    // Jam bukan dari SNTP: cap waktu "-" (NILVALUE).
    g_time_src = 0;
    run("pantau syslog 1 5514");
    CHECK(strcmp(g_sl_q[(g_sl_tail - 1) % MON_SL_QUEUE], "<134>1 - 192.168.50.200 bmahOS - pantau - "
                 "syslog pantau aktif ke 192.168.50.1:5514") == 0);

    // Mati: antrean dikosongkan, peristiwa baru tidak diantre.
    CHECK_STR(run("pantau syslog mati"), "OK pantau: syslog mati\n");
    CHECK(g_sl_tail == g_sl_head);
    sl_push(5, "y");
    CHECK(g_sl_tail == g_sl_head);
    CHECK(strstr(run("pantau"), "syslog: mati terkirim=2 dibuang=10\n") != 0);
}

int main(void)
{
    monitor_init();
    test_cmds();
    test_ping();
    test_arp_gagal();
    test_tcp();
    test_dns_probe();
    test_syslog();
    return test_done("monitor");
}

#include "kernel.h"

// P3-2: klien SNTP (RFC 4330) sekali jalan, dipicu admin `waktu sinkron <oktet>
// [port]`. Server harus di /24 sendiri (tanpa gateway, sama seperti netconsole).
// Alur di net task: ARP request tiap 1 s (maks SNTP_ARP_TRIES) -> permintaan NTP
// v4 mode 3 dari port sumber acak dengan transmit timestamp = 8 byte acak (nonce)
// -> balasan hanya diterima bila dari IP:port server ke port kita, panjang >= 48,
// LI != 3, versi 3/4, mode 4, stratum 1..15, originate == nonce, transmit bukan 0;
// selain itu diabaikan dan dihitung (g_sntp_bad), tetap menunggu sampai batas
// SNTP_TIMEOUT. Hasil mengganti jam dinding rtc.c (sumber=sntp, UTC), presisi 1 s
// (pecahan detik dan jeda jaringan diabaikan). Era NTP 0 saja (sampai 2036).

#define SNTP_ARP_TRIES 3
#define SNTP_ARP_EVERY 100   // tick
#define SNTP_TIMEOUT   300   // tick setelah permintaan terkirim
#define NTP_UNIX_DELTA 2208988800ULL   // 1900-01-01 -> 1970-01-01

enum { SNTP_IDLE, SNTP_ARP, SNTP_SENT };

static int g_sntp_state;
static uint8_t g_sntp_host;
static uint16_t g_sntp_port, g_sntp_lport;
static uint8_t g_sntp_mac[6];
static int g_sntp_mac_ok;
static uint8_t g_sntp_nonce[8];
static uint32_t g_sntp_arp_n;
static uint64_t g_sntp_at;
static uint64_t g_sntp_page_phys;
static const char *g_sntp_last = "belum pernah";
uint64_t g_sntp_ok, g_sntp_fail, g_sntp_bad;

static void sn_ip(uint8_t ip[4])
{
    ip[0] = g_net_ip[0];
    ip[1] = g_net_ip[1];
    ip[2] = g_net_ip[2];
    ip[3] = g_sntp_host;
}

// Dari net task setelah NIC siap (sebelum loop). Tanpa NIC / tanpa halaman TX:
// `waktu sinkron` menolak.
void sntp_init(void)
{
    if (!g_e1000_rx_initialized || g_sntp_page_phys != 0) {
        return;
    }
    g_sntp_page_phys = pmm_alloc();
}

static void sn_fail(const char *why)
{
    g_sntp_state = SNTP_IDLE;
    g_sntp_fail++;
    g_sntp_last = why;
    kprintf("P3: SNTP gagal: %s\r\n", why);
}

static void sn_send_arp(void)
{
    uint8_t *p = (uint8_t *)(g_sntp_page_phys + hhdm_offset);
    uint8_t ip[4];

    sn_ip(ip);
    memset(p, 0, 60);
    for (int i = 0; i < 6; i++) {
        p[i] = 0xFF;
        p[6 + i] = g_e1000_mac[i];
        p[22 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x06;
    p[15] = 0x01;   // htype Ethernet
    p[16] = 0x08;   // ptype IPv4
    p[18] = 6;
    p[19] = 4;
    p[21] = 0x01;   // request
    for (int i = 0; i < 4; i++) {
        p[28 + i] = g_net_ip[i];
        p[38 + i] = ip[i];
    }
    e1000_tx_send(g_sntp_page_phys, 60);
}

static void sn_send_req(void)
{
    uint8_t *p = (uint8_t *)(g_sntp_page_phys + hhdm_offset);
    uint8_t ip[4];

    sn_ip(ip);
    memset(p + 42, 0, 48);
    p[42] = 0x23;   // LI 0, versi 4, mode 3 (klien)
    memcpy(p + 42 + 40, g_sntp_nonce, 8);
    uint32_t len = net_udp_build(p, g_sntp_mac, ip, g_sntp_lport, g_sntp_port, 48);

    if (!e1000_tx_send(g_sntp_page_phys, len)) {
        sn_fail("kirim gagal");
        return;
    }
    g_sntp_state = SNTP_SENT;
    g_sntp_at = timer_ticks + SNTP_TIMEOUT;
}

// Mulai sinkron. 0 = OK; selain itu pesan galat di *why.
int sntp_start(uint32_t host, uint32_t port, const char **why)
{
    uint8_t r[10];

    if (g_sntp_page_phys == 0) {
        *why = "tanpa NIC";
        return -1;
    }
    if (host < 1 || host > 254 || host == g_net_ip[3] || port < 1 || port > 65535) {
        *why = "oktet 1..254 (bukan IP sendiri), port 1..65535";
        return -1;
    }
    if (g_sntp_state != SNTP_IDLE) {
        *why = "sinkron sebelumnya masih berjalan";
        return -1;
    }
    if (!entropy_get(r, sizeof(r))) {
        *why = "entropi belum cukup";
        return -1;
    }
    memcpy(g_sntp_nonce, r, 8);
    g_sntp_lport = (uint16_t)(49152 + (((uint32_t)r[8] << 8 | r[9]) % 16384));
    g_sntp_host = (uint8_t)host;
    g_sntp_port = (uint16_t)port;
    g_sntp_mac_ok = 0;
    g_sntp_arp_n = 0;
    g_sntp_at = 0;
    g_sntp_state = SNTP_ARP;
    return 0;
}

// Dari net_handle_arp untuk setiap ARP sah: MAC server bila pengirimnya IP server.
void sntp_arp_seen(const volatile uint8_t *buf)
{
    uint8_t ip[4];
    int zero = 1;

    if (g_sntp_state != SNTP_ARP || g_sntp_mac_ok) {
        return;
    }
    sn_ip(ip);
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
        g_sntp_mac[i] = buf[22 + i];
    }
    g_sntp_mac_ok = 1;
}

// Tiap putaran net task.
void sntp_poll(void)
{
    if (g_sntp_state == SNTP_ARP) {
        if (g_sntp_mac_ok) {
            sn_send_req();
        } else if (timer_ticks >= g_sntp_at) {
            if (g_sntp_arp_n >= SNTP_ARP_TRIES) {
                sn_fail("tanpa balasan ARP");
                return;
            }
            g_sntp_arp_n++;
            g_sntp_at = timer_ticks + SNTP_ARP_EVERY;
            sn_send_arp();
        }
    } else if (g_sntp_state == SNTP_SENT && timer_ticks >= g_sntp_at) {
        sn_fail("tanpa balasan NTP (3 s)");
    }
}

// Datagram ini ditunggu SNTP? (dicek net_handle_udp sebelum filter port).
int sntp_wants(const volatile uint8_t *src_ip, uint16_t sport, uint16_t dport)
{
    uint8_t ip[4];

    if (g_sntp_state != SNTP_SENT || sport != g_sntp_port || dport != g_sntp_lport) {
        return 0;
    }
    sn_ip(ip);
    for (int i = 0; i < 4; i++) {
        if (src_ip[i] != ip[i]) {
            return 0;
        }
    }
    return 1;
}

static uint32_t sn_be32(const volatile uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

// Isi UDP balasan (sudah lolos checksum). Balasan tidak sah diabaikan.
void sntp_rx(const volatile uint8_t *p, uint32_t len)
{
    uint8_t li = p[0] >> 6, vn = (p[0] >> 3) & 7, mode = p[0] & 7, stratum = p[1];
    int same = 1;

    if (len >= 48) {
        for (int i = 0; i < 8; i++) {
            same &= p[24 + i] == g_sntp_nonce[i];
        }
    }
    if (len < 48 || li == 3 || (vn != 3 && vn != 4) || mode != 4 || stratum < 1 ||
        stratum > 15 || !same || sn_be32(p + 40) < NTP_UNIX_DELTA) {
        g_sntp_bad++;
        return;
    }
    uint64_t epoch = sn_be32(p + 40) - NTP_UNIX_DELTA;
    int64_t adj = rtc_set_sntp(epoch, g_sntp_host, stratum);

    g_sntp_state = SNTP_IDLE;
    g_sntp_ok++;
    g_sntp_last = "ok";
    kprintf("P3: SNTP ok dari %u.%u.%u.%u stratum %u koreksi %ld s\r\n", g_net_ip[0],
            g_net_ip[1], g_net_ip[2], (unsigned)g_sntp_host, (unsigned)stratum, adj);
}

// Baris kedua perintah `waktu`.
void sntp_status(void (*out)(const char *))
{
    char line[112];

    ksnprintf(line, sizeof(line), "sntp: %s terakhir=%s ok=%lu gagal=%lu diabaikan=%lu\n",
              g_sntp_state == SNTP_IDLE ? "diam" : "berjalan", g_sntp_last, g_sntp_ok,
              g_sntp_fail, g_sntp_bad);
    out(line);
}

// `waktu sinkron <oktet> [port]` (admin; tidak di daftar read-only).
int sntp_execute(const volatile uint8_t *cmd, uint32_t len)
{
    static const char pre[] = "waktu sinkron ";
    uint32_t np = sizeof(pre) - 1, i = np, v[2] = { 0, 123 }, k = 0;
    const char *why = "";
    char line[112];

    if (len < np || !net_cmd_is(cmd, np, pre)) {
        return 0;
    }
    g_cmd_len = 0;
    while (i < len && k < 2) {
        uint32_t s = i, n = 0;
        while (i < len && cmd[i] >= '0' && cmd[i] <= '9' && i - s < 6) {
            n = n * 10 + (uint32_t)(cmd[i] - '0');
            i++;
        }
        if (i == s || (i < len && cmd[i] != ' ')) {
            k = 3;   // format salah
            break;
        }
        v[k++] = n;
        while (i < len && cmd[i] == ' ') {
            i++;
        }
    }
    if (k == 0 || k > 2 || i < len) {
        cmd_puts("ERR: waktu: format: waktu sinkron <oktet 1..254> [port]\n");
        return 1;
    }
    if (sntp_start(v[0], v[1], &why) != 0) {
        ksnprintf(line, sizeof(line), "ERR: waktu: %s\n", why);
        cmd_puts(line);
        return 1;
    }
    ksnprintf(line, sizeof(line), "OK: SNTP ke %u.%u.%u.%u:%u dimulai, lihat `waktu` (maks 6 s)\n",
              g_net_ip[0], g_net_ip[1], g_net_ip[2], v[0], v[1]);
    cmd_puts(line);
    return 1;
}

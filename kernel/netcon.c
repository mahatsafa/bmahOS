#include "kernel.h"

// R2: netconsole UDP. Setiap baris yang masuk ring log (log_capture) disalin
// ke antrean statis g_nc_ring (NETCON_RING byte) selama netcon=1; net task
// mengirimnya sebagai datagram UDP (baris utuh, maks NETCON_DGRAM_MAX byte)
// dari port NETCON_SRC_PORT ke 192.168.50.<netcon_host>:<netcon_port>.
// - Tanpa heap: antrean + satu halaman TX sendiri (pmm_alloc sekali di
//   netcon_init), terpisah dari g_net_tx_buf_phys supaya jalur panic tidak
//   menimpa frame milik net task.
// - MAC tujuan: ARP request maks 1x/detik sampai ada ARP (reply atau request)
//   yang pengirimnya IP tujuan (netcon_arp_seen). Belum ada MAC -> baris ditahan.
// - Batas laju NETCON_PER_SEC datagram per 100 tick. Antrean penuh -> baris
//   BARU dibuang dan dihitung; datagram berikutnya diawali
//   "netcon: N baris dibuang".
// - Panic (depth 1): isi antrean dikirim langsung tanpa batas laju, sekali di
//   awal dan sekali setelah dump (netcon_panic_flush).
// - Jalur kirim tidak menulis log (tanpa umpan balik).
// - g_netcon_hold = 1: baris tidak diantre (panic.c: register umum, bisa
//   memuat sisa data rahasia, hanya ke serial).

#define NETCON_RING      4096
#define NETCON_DGRAM_MAX 1024
#define NETCON_PER_SEC   20
#define NETCON_ARP_EVERY 100   // tick
#define NETCON_PANIC_MAX 8     // datagram per flush panic (antrean 4 KB = maks 5)

uint32_t g_netcon_on = 0;
uint32_t g_netcon_host = NETCON_HOST_DEF;
uint32_t g_netcon_port = NETCON_PORT_DEF;
volatile int g_netcon_hold = 0;

static char g_nc_ring[NETCON_RING];
static uint32_t g_nc_head, g_nc_tail;   // terus naik; terisi = head - tail
static uint64_t g_nc_lost_pending;      // baris dibuang yang belum dilaporkan
uint64_t g_nc_lost, g_nc_sent, g_nc_arp, g_nc_tx_fail;   // R3: metrics netcon_*
static uint8_t g_nc_mac[6];
static int g_nc_mac_ok;
static uint32_t g_nc_cur_on, g_nc_cur_host;
static uint64_t g_nc_arp_at;
static uint64_t g_nc_win_start;
static uint32_t g_nc_win_used;
static uint64_t g_nc_page_phys;

static void nc_dst_ip(uint8_t ip[4])
{
    ip[0] = g_net_ip[0];
    ip[1] = g_net_ip[1];
    ip[2] = g_net_ip[2];
    ip[3] = (uint8_t)g_netcon_host;
}

// Dari log_capture (interrupt mati). s tanpa '\n', n <= panjang baris log.
void netcon_line(const char *s, uint32_t n)
{
    if (!g_netcon_on || !g_e1000_rx_initialized || g_netcon_hold) {
        return;
    }

    if (n + 1 > NETCON_RING - (g_nc_head - g_nc_tail)) {
        g_nc_lost++;
        g_nc_lost_pending++;
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        g_nc_ring[g_nc_head++ % NETCON_RING] = s[i];
    }
    g_nc_ring[g_nc_head++ % NETCON_RING] = '\n';
}

// Isi payload dengan penanda (bila ada baris dibuang) + baris utuh dari
// antrean, maks max byte. Panggil dengan interrupt mati. Return panjang.
static uint32_t nc_fill(uint8_t *out, uint32_t max)
{
    uint32_t len = 0;

    if (g_nc_lost_pending) {
        len = (uint32_t)ksnprintf((char *)out, max, "netcon: %lu baris dibuang\n",
                                  g_nc_lost_pending);
        g_nc_lost_pending = 0;
    }

    while (g_nc_tail != g_nc_head) {
        uint32_t n = 0;

        while (g_nc_ring[(g_nc_tail + n) % NETCON_RING] != '\n') {
            n++;
        }
        n++;   // '\n'

        if (len + n > max) {
            break;
        }

        for (uint32_t i = 0; i < n; i++) {
            out[len++] = (uint8_t)g_nc_ring[g_nc_tail++ % NETCON_RING];
        }
    }

    return len;
}

// Kirim satu datagram dari antrean. Return 1 bila ada yang dikirim.
static int nc_send_one(void)
{
    uint8_t *p = (uint8_t *)(g_nc_page_phys + hhdm_offset);
    uint8_t ip[4];

    uint64_t f = irq_save();
    uint32_t plen = nc_fill(p + 42, NETCON_DGRAM_MAX);
    irq_restore(f);

    if (plen == 0) {
        return 0;
    }

    nc_dst_ip(ip);
    uint32_t len = net_udp_build(p, g_nc_mac, ip, NETCON_SRC_PORT, (uint16_t)g_netcon_port, plen);

    if (e1000_tx_send(g_nc_page_phys, len)) {
        g_nc_sent++;
    } else {
        g_nc_tx_fail++;
    }
    return 1;
}

static void nc_send_arp(void)
{
    uint8_t *p = (uint8_t *)(g_nc_page_phys + hhdm_offset);
    uint8_t ip[4];

    nc_dst_ip(ip);

    for (int i = 0; i < 60; i++) {
        p[i] = 0;
    }
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

    if (e1000_tx_send(g_nc_page_phys, 60)) {
        g_nc_arp++;
    } else {
        g_nc_tx_fail++;
    }
}

// Dari net task setelah NIC siap (sebelum loop). Tanpa NIC: tidak aktif.
void netcon_init(void)
{
    if (!g_e1000_rx_initialized || g_nc_page_phys != 0) {
        return;
    }

    g_nc_page_phys = pmm_alloc();

    kprintf("R2: netcon %s aktif=%u tujuan=%u.%u.%u.%u:%u\r\n",
            g_nc_page_phys ? "siap" : "GAGAL (pmm_alloc)", g_netcon_on,
            g_net_ip[0], g_net_ip[1], g_net_ip[2], g_netcon_host, g_netcon_port);
}

static void nc_mac_str(char m[18])
{
    static const char hex[] = "0123456789abcdef";

    for (int i = 0; i < 6; i++) {
        m[i * 3] = hex[g_nc_mac[i] >> 4];
        m[i * 3 + 1] = hex[g_nc_mac[i] & 0xF];
        m[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
}

// Dari net_handle_arp untuk setiap ARP sah (htype/ptype/panjang sudah dicek).
void netcon_arp_seen(const volatile uint8_t *buf)
{
    uint8_t ip[4];

    if (!g_netcon_on || g_nc_mac_ok) {
        return;
    }

    nc_dst_ip(ip);

    for (int i = 0; i < 4; i++) {
        if (buf[28 + i] != ip[i]) {
            return;
        }
    }

    // Pengirim harus unicast dan bukan nol.
    if (buf[22] & 0x01) {
        return;
    }
    int zero = 1;
    for (int i = 0; i < 6; i++) {
        zero &= buf[22 + i] == 0;
    }
    if (zero) {
        return;
    }

    for (int i = 0; i < 6; i++) {
        g_nc_mac[i] = buf[22 + i];
    }
    g_nc_mac_ok = 1;
    // MAC berlaku untuk keadaan saat ini; nc_sync hanya menghapusnya bila
    // netcon/host berubah SETELAH ini (ARP peer bisa tiba sebelum poll pertama).
    g_nc_cur_on = g_netcon_on;
    g_nc_cur_host = g_netcon_host;

    char m[18];
    nc_mac_str(m);
    kprintf("R2: netcon MAC tujuan %u.%u.%u.%u = %s\r\n", ip[0], ip[1], ip[2], ip[3], m);
}

// Perubahan config (set) diterapkan di sini: host berubah -> ARP ulang;
// netcon=0 -> antrean dikosongkan.
static void nc_sync(void)
{
    if (g_netcon_host != g_nc_cur_host) {
        g_nc_cur_host = g_netcon_host;
        g_nc_mac_ok = 0;
        g_nc_arp_at = 0;
    }

    if (g_netcon_on != g_nc_cur_on) {
        g_nc_cur_on = g_netcon_on;
        g_nc_mac_ok = 0;
        g_nc_arp_at = 0;

        if (!g_netcon_on) {
            uint64_t f = irq_save();
            g_nc_tail = g_nc_head;
            g_nc_lost_pending = 0;
            irq_restore(f);
        }
    }
}

// Dari loop net task (tiap bangun, >= 1x per tick).
void netcon_poll(void)
{
    nc_sync();

    if (!g_netcon_on || g_nc_page_phys == 0) {
        return;
    }

    if (!g_nc_mac_ok) {
        if (timer_ticks >= g_nc_arp_at) {
            g_nc_arp_at = timer_ticks + NETCON_ARP_EVERY;
            nc_send_arp();
        }
        return;
    }

    if (timer_ticks - g_nc_win_start >= 100) {
        g_nc_win_start = timer_ticks;
        g_nc_win_used = 0;
    }

    if (g_nc_win_used < NETCON_PER_SEC && nc_send_one()) {
        g_nc_win_used++;
    }
}

// Dari panic_begin/panic_finish (interrupt mati, net task tidak jalan).
void netcon_panic_flush(void)
{
    if (!g_netcon_on || g_nc_page_phys == 0 || !g_nc_mac_ok) {
        return;
    }

    for (int i = 0; i < NETCON_PANIC_MAX && nc_send_one(); i++) {
    }
}

// Perintah `netcon` (admin dan read-only).
void netcon_status(void)
{
    char t[128];

    if (!g_e1000_rx_initialized) {
        cmd_puts("netcon: NIC tidak ada\n");
        return;
    }

    ksnprintf(t, sizeof(t), "netcon: aktif=%u tujuan=%u.%u.%u.%u:%u port_sumber=%u\n",
              g_netcon_on, g_net_ip[0], g_net_ip[1], g_net_ip[2], g_netcon_host,
              g_netcon_port, NETCON_SRC_PORT);
    cmd_puts(t);

    char m[18] = "belum";

    if (g_nc_mac_ok) {
        nc_mac_str(m);
    }
    ksnprintf(t, sizeof(t), "netcon: mac=%s arp=%lu\n", m, g_nc_arp);
    cmd_puts(t);

    uint64_t f = irq_save();
    uint32_t q = g_nc_head - g_nc_tail;
    irq_restore(f);

    ksnprintf(t, sizeof(t), "netcon: terkirim=%lu antre=%u dibuang=%lu tx_gagal=%lu\n",
              g_nc_sent, q, g_nc_lost, g_nc_tx_fail);
    cmd_puts(t);
}

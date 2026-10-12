#include "kernel.h"

// ---- Net-5: konfigurasi IP statis + ARP responder + dispatch RX ----
const uint8_t g_net_ip[4] = {192, 168, 50, 200};
uint32_t g_net_arp_replies_sent = 0;
uint64_t g_net_tx_buf_phys = 0;

static int net_ip_equal(volatile uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 4; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

// req = pointer ke awal frame ARP request di buffer RX.
static void net_arp_send_reply(volatile uint8_t *req)
{
    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-5: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);

    for (uint64_t i = 0; i < 64; i++) {
        p[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }

    p[12] = 0x08;
    p[13] = 0x06;

    p[14] = 0x00;
    p[15] = 0x01;
    p[16] = 0x08;
    p[17] = 0x00;
    p[18] = 6;
    p[19] = 4;
    p[20] = 0x00;
    p[21] = 0x02;

    for (int i = 0; i < 6; i++) {
        p[22 + i] = g_e1000_mac[i];
        p[32 + i] = req[22 + i];
    }

    for (int i = 0; i < 4; i++) {
        p[28 + i] = g_net_ip[i];
        p[38 + i] = req[28 + i];
    }

    int ok = e1000_tx_send(g_net_tx_buf_phys, 60);

    if (ok) {
        g_net_arp_replies_sent++;
    }

    uint64_t lf = irq_save();
    serial_write("Net-5: ARP reply -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

static void net_handle_arp(volatile uint8_t *buf)
{
    uint32_t htype = ((uint32_t)buf[14] << 8) | (uint32_t)buf[15];
    uint32_t ptype = ((uint32_t)buf[16] << 8) | (uint32_t)buf[17];
    uint32_t oper = ((uint32_t)buf[20] << 8) | (uint32_t)buf[21];

    if (htype != 1 || ptype != 0x0800 || buf[18] != 6 || buf[19] != 4) {
        return;
    }

    if (oper == 1 && net_ip_equal(buf + 38, g_net_ip)) {
        uint64_t lf = irq_save();
        serial_write("Net-5: ARP request untuk IP kita dari ");
        e1000_log_ip(buf + 28);
        serial_write("\r\n");
        irq_restore(lf);
        net_arp_send_reply(buf);
    }
}

// ---- Net-6: checksum, IPv4 parse, ICMP echo reply ----
uint32_t g_net_icmp_replies_sent = 0;
uint16_t g_net_ip_id = 1;

// Internet checksum (RFC 1071). Hitung atas data yang sudah berisi field
// checksum -> hasil 0 kalau valid. Hitung dengan field checksum = 0 ->
// hasilnya nilai yang ditulis (big-endian) ke field checksum.
uint16_t net_checksum16(volatile uint8_t *p, uint32_t len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | (uint32_t)p[1];
        p += 2;
        len -= 2;
    }

    if (len == 1) {
        sum += (uint32_t)p[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// req = awal frame Ethernet request (IPv4 header di offset 14),
// ihl = panjang header IP request (byte), icmp_len = panjang pesan ICMP.
static void net_icmp_send_echo_reply(volatile uint8_t *req, uint32_t ihl,
                                     uint32_t icmp_len)
{
    if (icmp_len > 1480) {
        serial_write("Net-6: ICMP terlalu besar, drop\r\n");
        return;
    }

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-6: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);

    uint32_t frame_len = 14 + 20 + icmp_len;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = 0; i < send_len; i++) {
        p[i] = 0;
    }

    // Ethernet
    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    // IPv4 header (20 byte, tanpa options)
    p[14] = 0x45;
    p[15] = 0x00;
    p[16] = (uint8_t)((20 + icmp_len) >> 8);
    p[17] = (uint8_t)((20 + icmp_len) & 0xFF);
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[21] = 0x00;
    p[22] = 64;
    p[23] = 1;
    p[24] = 0;
    p[25] = 0;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = req[26 + i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    // ICMP: salin pesan request, ubah type -> 0 (echo reply)
    for (uint32_t i = 0; i < icmp_len; i++) {
        p[34 + i] = req[14 + ihl + i];
    }
    p[34] = 0;
    p[36] = 0;
    p[37] = 0;

    uint16_t icc = net_checksum16(p + 34, icmp_len);
    p[36] = (uint8_t)(icc >> 8);
    p[37] = (uint8_t)(icc & 0xFF);

    int ok = e1000_tx_send(g_net_tx_buf_phys, send_len);

    if (ok) {
        g_net_icmp_replies_sent++;
    }

    uint64_t lf = irq_save();
    serial_write("Net-6: ICMP echo reply -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

// ---- Net-8: UDP echo (port 7777) ----
#define NET_UDP_ECHO_PORT 7777

uint32_t g_net_udp_echo_count = 0;

// ---- Net-15: batas laju datagram UDP + counter (benih "metrics") ----
// Datagram ke port layanan kita dibatasi NET_UDP_BUDGET_PER_SEC per detik
// (jendela tetap 100 tick). Sisanya dibuang SEBELUM log dan HMAC. Hanya
// dipanggil dari net task, jadi tidak perlu lock.

static uint64_t g_net_budget_window = 0;
static uint32_t g_net_budget_used = 0;
uint64_t g_net_udp_dropped = 0;
uint64_t g_net_rx_frames = 0;
uint64_t g_net_rx_errors = 0;
uint64_t g_auth_ok = 0;
uint64_t g_auth_denied[5] = {0, 0, 0, 0, 0};
// Net-18A: [1] nonaktif [2] format [3] nonce tak dikenal/dipakai
// [4] kedaluwarsa [5] hmac salah
uint64_t g_chal_issued = 0;
uint64_t g_chal_noentropy = 0;
uint64_t g_chal_ip_recycled = 0;
uint64_t g_priv_ok = 0;
uint64_t g_priv_denied[6] = {0, 0, 0, 0, 0, 0};
// B2: datagram jalur counter yang ditolak karena jalur itu dimatikan
uint64_t g_auth_ctr_off = 0;
// Net-19: frame per jenis + UDP checksum salah
uint64_t g_net_rx_arp = 0;
uint64_t g_net_rx_ipv4 = 0;
uint64_t g_net_rx_other = 0;
uint64_t g_net_udp_badsum = 0;

static int net_udp_budget_ok(void)
{
    uint64_t now = timer_ticks;

    if (now - g_net_budget_window >= 100) {
        g_net_budget_window = now;
        g_net_budget_used = 0;
    }

    if (g_net_budget_used >= NET_UDP_BUDGET_PER_SEC) {
        g_net_udp_dropped++;
        return 0;
    }

    g_net_budget_used++;
    return 1;
}

// B4: batas per alamat IP sumber, dicek SEBELUM batas global. Datagram yang
// melewati batas sumbernya dibuang tanpa memakai jatah global, jadi satu
// pengirim paling banyak memakai NET_UDP_SRC_PER_SEC dari jatah global dan
// pengirim lain tetap terlayani. Tabel kecil: sumber baru menggusur slot
// kosong atau slot dengan jendela tertua (IP palsu yang banyak bisa
// menggusur slot penyerang; batas global tetap berlaku).
#define NET_UDP_SRC_SLOTS   8

typedef struct {
    uint8_t ip[4];
    uint64_t window;
    uint32_t used;
    int in_use;
} net_src_budget_t;

static net_src_budget_t g_net_src[NET_UDP_SRC_SLOTS];
uint64_t g_net_udp_src_dropped = 0;
// C1: counter TCP
uint64_t g_tcp_rx = 0;
uint64_t g_tcp_badsum = 0;
uint64_t g_tcp_rst_sent = 0;
// C2
uint64_t g_tcp_conn_open = 0;
uint64_t g_tcp_busy = 0;
uint64_t g_tcp_rx_bytes = 0;
uint64_t g_tcp_timeouts = 0;
uint64_t g_tcp_noentropy = 0;
uint64_t g_tcp_tx_bytes = 0;      // C3b: byte data dikirim (pertama kali)
uint64_t g_tcp_acked_bytes = 0;   // C3b: byte data kita yang di-ACK peer

// RXO-1: register statistik E1000 MPC (paket dibuang karena ring RX
// penuh) dan RNBC (paket datang saat tidak ada buffer) clear-on-read,
// jadi dijumlahkan ke counter 64-bit setiap kali dibaca.
uint64_t g_e1000_mpc = 0;
uint64_t g_e1000_rnbc = 0;

void e1000_stats_poll(void)
{
    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    if (!g_e1000_rx_initialized) {
        return;
    }

    g_e1000_mpc += mmio[0x4010 / 4];
    g_e1000_rnbc += mmio[0x40A0 / 4];
}

// B4b: jatah frame per detik yang log-nya boleh ke UART.
#define NET_SERIAL_LOG_PER_SEC 10
static uint64_t g_net_log_window = 0;
static uint32_t g_net_log_used = 0;
uint64_t g_net_log_muted = 0;

static int net_serial_log_ok(void)
{
    uint64_t now = timer_ticks;

    if (now - g_net_log_window >= 100) {
        g_net_log_window = now;
        g_net_log_used = 0;
    }

    if (g_net_log_used >= NET_SERIAL_LOG_PER_SEC) {
        g_net_log_muted++;
        return 0;
    }

    g_net_log_used++;
    return 1;
}

static int net_udp_src_budget_ok(const volatile uint8_t *ip)
{
    uint64_t now = timer_ticks;
    net_src_budget_t *s = 0;
    net_src_budget_t *victim = 0;

    for (uint32_t i = 0; i < NET_UDP_SRC_SLOTS; i++) {
        net_src_budget_t *e = &g_net_src[i];

        if (e->in_use && e->ip[0] == ip[0] && e->ip[1] == ip[1] &&
            e->ip[2] == ip[2] && e->ip[3] == ip[3]) {
            s = e;
            break;
        }

        // Slot kosong diutamakan; kalau tidak ada, slot dengan jendela tertua.
        if (victim == 0 ||
            (victim->in_use && (!e->in_use || e->window < victim->window))) {
            victim = e;
        }
    }

    if (s == 0) {
        s = victim;
        for (int i = 0; i < 4; i++) {
            s->ip[i] = ip[i];
        }
        s->window = now;
        s->used = 0;
        s->in_use = 1;
    }

    if (now - s->window >= 100) {
        s->window = now;
        s->used = 0;
    }

    if (s->used >= NET_UDP_SRC_PER_SEC) {
        g_net_udp_src_dropped++;
        return 0;
    }

    s->used++;
    return 1;
}

static uint32_t net_sum16(const volatile uint8_t *p, uint32_t len, uint32_t sum)
{
    while (len > 1) {
        sum += ((uint32_t)p[0] << 8) | (uint32_t)p[1];
        p += 2;
        len -= 2;
    }

    if (len == 1) {
        sum += (uint32_t)p[0] << 8;
    }

    return sum;
}

// Checksum UDP dengan pseudo-header (src IP, dst IP, proto 17, panjang UDP).
// Data yang sudah berisi checksum valid -> hasil 0. Field checksum = 0 saat
// menghitung -> hasil adalah nilai yang ditulis ke field checksum.
uint16_t net_udp_checksum(const volatile uint8_t *src_ip,
                                 const volatile uint8_t *dst_ip,
                                 const volatile uint8_t *udp,
                                 uint32_t udp_len)
{
    uint32_t sum = 0;

    sum = net_sum16(src_ip, 4, sum);
    sum = net_sum16(dst_ip, 4, sum);
    sum += 17;
    sum += udp_len;
    sum = net_sum16(udp, udp_len, sum);

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// req = awal frame Ethernet request, ihl = panjang header IP request,
// udp_len = panjang datagram UDP (header 8 byte + payload).
static void net_udp_send_echo(volatile uint8_t *req, uint32_t ihl,
                              uint32_t udp_len)
{
    if (udp_len > 1472) {
        serial_write("Net-8: UDP terlalu besar, drop\r\n");
        return;
    }

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-8: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t r = 14 + ihl;

    uint32_t frame_len = 14 + 20 + udp_len;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = 0; i < send_len; i++) {
        p[i] = 0;
    }

    // Ethernet
    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    // IPv4 header, protocol 17
    p[14] = 0x45;
    p[15] = 0x00;
    p[16] = (uint8_t)((20 + udp_len) >> 8);
    p[17] = (uint8_t)((20 + udp_len) & 0xFF);
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[21] = 0x00;
    p[22] = 64;
    p[23] = 17;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = req[26 + i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    // UDP: port ditukar (src <- dst request, dst <- src request)
    p[34] = req[r + 2];
    p[35] = req[r + 3];
    p[36] = req[r + 0];
    p[37] = req[r + 1];
    p[38] = (uint8_t)(udp_len >> 8);
    p[39] = (uint8_t)(udp_len & 0xFF);

    for (uint32_t i = 0; i + 8 < udp_len; i++) {
        p[42 + i] = req[r + 8 + i];
    }

    uint16_t uc = net_udp_checksum(p + 26, p + 30, p + 34, udp_len);
    if (uc == 0) {
        uc = 0xFFFF;
    }
    p[40] = (uint8_t)(uc >> 8);
    p[41] = (uint8_t)(uc & 0xFF);

    int ok = e1000_tx_send(g_net_tx_buf_phys, send_len);

    if (ok) {
        g_net_udp_echo_count++;
    }

    uint64_t lf = irq_save();
    serial_write("Net-8: UDP echo reply -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

// ---- C1: TCP, parsing header + checksum, RST untuk port tertutup ----
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

// Checksum TCP dengan pseudo-header (proto 6); segmen valid -> hasil 0.
static uint16_t net_tcp_checksum(const volatile uint8_t *src_ip,
                                 const volatile uint8_t *dst_ip,
                                 const volatile uint8_t *tcp,
                                 uint32_t tcp_len)
{
    uint32_t sum = 0;

    sum = net_sum16(src_ip, 4, sum);
    sum = net_sum16(dst_ip, 4, sum);
    sum += 6;
    sum += tcp_len;
    sum = net_sum16(tcp, tcp_len, sum);

    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// Balas RST ke segmen request (RFC 793: segmen untuk koneksi yang tidak ada).
// seg_len = panjang data + SYN + FIN pada request.
static void net_tcp_send_rst(volatile uint8_t *req, uint32_t ihl,
                             uint32_t seg_len)
{
    uint32_t r = 14 + ihl;
    uint8_t rflags = req[r + 13];
    uint32_t rseq = ((uint32_t)req[r + 4] << 24) | ((uint32_t)req[r + 5] << 16) |
                    ((uint32_t)req[r + 6] << 8) | (uint32_t)req[r + 7];
    uint32_t rack = ((uint32_t)req[r + 8] << 24) | ((uint32_t)req[r + 9] << 16) |
                    ((uint32_t)req[r + 10] << 8) | (uint32_t)req[r + 11];
    uint32_t seq, ack;
    uint8_t flags;

    if (rflags & TCP_ACK) {
        seq = rack;
        ack = 0;
        flags = TCP_RST;
    } else {
        seq = 0;
        ack = rseq + seg_len;
        flags = TCP_RST | TCP_ACK;
    }

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("C1: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);

    for (uint32_t i = 0; i < 60; i++) {
        p[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    p[14] = 0x45;
    p[16] = 0;
    p[17] = 40;
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[22] = 64;
    p[23] = 6;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = req[26 + i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    p[34] = req[r + 2];
    p[35] = req[r + 3];
    p[36] = req[r + 0];
    p[37] = req[r + 1];
    p[38] = (uint8_t)(seq >> 24);
    p[39] = (uint8_t)(seq >> 16);
    p[40] = (uint8_t)(seq >> 8);
    p[41] = (uint8_t)seq;
    p[42] = (uint8_t)(ack >> 24);
    p[43] = (uint8_t)(ack >> 16);
    p[44] = (uint8_t)(ack >> 8);
    p[45] = (uint8_t)ack;
    p[46] = 0x50;
    p[47] = flags;

    uint16_t tc = net_tcp_checksum(p + 26, p + 30, p + 34, 20);
    p[50] = (uint8_t)(tc >> 8);
    p[51] = (uint8_t)(tc & 0xFF);

    if (e1000_tx_send(g_net_tx_buf_phys, 60)) {
        g_tcp_rst_sent++;
    }
}

// ---- C2/C3b: satu koneksi TCP (port 7) ----
// C3b: data yang diterima masuk ke g_tcp_buf lalu dikirim balik (echo
// sementara; uji echo penuh 1 MB di C4). Jendela yang diiklankan = ruang
// kosong g_tcp_buf; segmen di luar urutan dibuang (DECISIONS 2026-10-12).
// Kirim stop-and-wait: maks satu segmen data belum di-ACK, <= TCP_MSS dan
// <= jendela peer. Nomor urut dibandingkan bertanda (seq_lt/seq_le) karena
// berputar di 2^32. Retransmisi (C3c) dan FIN kita (C3d) belum ada; timeout
// aman tetap supaya satu TCB tidak mengunci port selamanya.
#define NET_TCP_ECHO_PORT   7
#define TCP_BUF_SIZE        1024
#define TCP_MSS             536
#define TCP_SYNRCVD_TIMEOUT 500    // tick (5 detik)
#define TCP_IDLE_TIMEOUT    3000   // tick (30 detik), sementara sampai C3/C5

enum { TCP_CLOSED = 0, TCP_SYN_RCVD, TCP_ESTABLISHED, TCP_CLOSE_WAIT };

typedef struct {
    int state;
    uint8_t mac[6];
    uint8_t ip[4];
    uint16_t rport;
    uint16_t lport;
    uint32_t iss;       // ISN kita
    uint32_t snd_nxt;
    uint32_t irs;       // ISN peer
    uint32_t rcv_nxt;
    uint64_t last;      // tick aktivitas terakhir
    uint32_t snd_una;   // byte tertua yang belum di-ACK peer
    uint32_t snd_wnd;   // jendela peer terakhir
    uint32_t adv_wnd;   // jendela terakhir yang kita iklankan
    uint32_t buf_head;  // indeks g_tcp_buf untuk byte snd_una
    uint32_t buf_count; // isi g_tcp_buf: belum di-ACK + belum dikirim
} tcp_tcb_t;

static tcp_tcb_t g_tcb;
static uint8_t g_tcp_buf[TCP_BUF_SIZE];

static inline int seq_lt(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) < 0;
}

static inline int seq_le(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0;
}

static uint32_t net_tcp_rcv_wnd(void)
{
    return TCP_BUF_SIZE - g_tcb.buf_count;
}

static uint32_t net_rd32(const volatile uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Segmen TCP dari kita ke peer, dengan data (dlen <= TCP_MSS) atau tanpa.
// mss_opt != 0: sertakan opsi MSS. Jendela = ruang kosong g_tcp_buf.
static void net_tcp_send_seg(const uint8_t *mac, const uint8_t *ip,
                             uint16_t sport, uint16_t dport,
                             uint32_t seq, uint32_t ack, uint8_t flags,
                             int mss_opt, const uint8_t *data, uint32_t dlen)
{
    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("C2: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t hl = mss_opt ? 24 : 20;
    uint32_t wnd = net_tcp_rcv_wnd();

    if (dlen > TCP_MSS) {
        dlen = TCP_MSS;
    }

    uint32_t frame_len = 14 + 20 + hl + dlen;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = 0; i < send_len; i++) {
        p[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        p[i] = mac[i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    p[14] = 0x45;
    p[16] = (uint8_t)((20 + hl + dlen) >> 8);
    p[17] = (uint8_t)((20 + hl + dlen) & 0xFF);
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[22] = 64;
    p[23] = 6;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = ip[i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)(sport & 0xFF);
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)(dport & 0xFF);
    p[38] = (uint8_t)(seq >> 24);
    p[39] = (uint8_t)(seq >> 16);
    p[40] = (uint8_t)(seq >> 8);
    p[41] = (uint8_t)seq;
    p[42] = (uint8_t)(ack >> 24);
    p[43] = (uint8_t)(ack >> 16);
    p[44] = (uint8_t)(ack >> 8);
    p[45] = (uint8_t)ack;
    p[46] = (uint8_t)((hl / 4) << 4);
    p[47] = flags;
    p[48] = (uint8_t)(wnd >> 8);
    p[49] = (uint8_t)(wnd & 0xFF);
    g_tcb.adv_wnd = wnd;

    if (mss_opt) {
        p[54] = 2;
        p[55] = 4;
        p[56] = (uint8_t)(TCP_MSS >> 8);
        p[57] = (uint8_t)(TCP_MSS & 0xFF);
    }

    for (uint32_t i = 0; i < dlen; i++) {
        p[34 + hl + i] = data[i];
    }

    uint16_t tc = net_tcp_checksum(p + 26, p + 30, p + 34, hl + dlen);
    p[50] = (uint8_t)(tc >> 8);
    p[51] = (uint8_t)(tc & 0xFF);

    if (e1000_tx_send(g_net_tx_buf_phys, send_len)) {
        if (flags & TCP_RST) {
            g_tcp_rst_sent++;
        }
    }
}

static void net_tcp_tcb_send(uint32_t seq, uint8_t flags, int mss_opt)
{
    net_tcp_send_seg(g_tcb.mac, g_tcb.ip, g_tcb.lport, g_tcb.rport,
                     seq, g_tcb.rcv_nxt, flags, mss_opt, 0, 0);
}

// Kirim data yang menunggu bila tidak ada segmen data yang belum di-ACK
// (stop-and-wait). Return 1 bila segmen terkirim (segmen data membawa ACK).
static int net_tcp_output(void)
{
    tcp_tcb_t *t = &g_tcb;

    if (t->state != TCP_ESTABLISHED && t->state != TCP_CLOSE_WAIT) {
        return 0;
    }
    if (t->snd_nxt != t->snd_una) {
        return 0;
    }

    uint32_t n = t->buf_count;

    if (n > TCP_MSS) {
        n = TCP_MSS;
    }
    if (n > t->snd_wnd) {
        n = t->snd_wnd;
    }
    if (n == 0) {
        return 0;
    }

    uint8_t seg[TCP_MSS];

    for (uint32_t i = 0; i < n; i++) {
        seg[i] = g_tcp_buf[(t->buf_head + i) % TCP_BUF_SIZE];
    }
    net_tcp_send_seg(t->mac, t->ip, t->lport, t->rport, t->snd_nxt, t->rcv_nxt,
                     TCP_PSH | TCP_ACK, 0, seg, n);
    t->snd_nxt += n;
    g_tcp_tx_bytes += n;
    return 1;
}

static void net_tcp_log(const char *msg)
{
    uint64_t lf = irq_save();
    serial_write("C2: TCP ");
    serial_write(msg);
    serial_write("\r\n");
    irq_restore(lf);
}

// Dipanggil tiap loop net task (tick-wake ~100 Hz).
void net_tcp_tick(void)
{
    if (g_tcb.state == TCP_CLOSED) {
        return;
    }

    uint64_t limit = g_tcb.state == TCP_SYN_RCVD ? TCP_SYNRCVD_TIMEOUT
                                                 : TCP_IDLE_TIMEOUT;

    if (timer_ticks - g_tcb.last > limit) {
        net_tcp_tcb_send(g_tcb.snd_nxt, TCP_RST | TCP_ACK, 0);
        g_tcp_timeouts++;
        g_tcb.state = TCP_CLOSED;
        net_tcp_log("timeout, koneksi diputus (RST)");
    }
}

// Return 1 jika segmen sudah ditangani, 0 jika harus dibalas RST (port tutup).
static int net_tcp_input(volatile uint8_t *buf, uint32_t ihl, uint32_t doff,
                         uint32_t plen)
{
    uint32_t r = 14 + ihl;
    uint16_t sport = (uint16_t)(((uint32_t)buf[r + 0] << 8) | buf[r + 1]);
    uint16_t dport = (uint16_t)(((uint32_t)buf[r + 2] << 8) | buf[r + 3]);
    uint32_t seq = net_rd32(buf + r + 4);
    uint32_t ack = net_rd32(buf + r + 8);
    uint8_t flags = buf[r + 13];
    uint32_t dlen = plen - doff;
    tcp_tcb_t *t = &g_tcb;

    int match = t->state != TCP_CLOSED && dport == t->lport &&
                sport == t->rport;

    for (int i = 0; match && i < 4; i++) {
        if (buf[26 + i] != t->ip[i]) {
            match = 0;
        }
    }

    if (match) {
        t->last = timer_ticks;

        if (flags & TCP_RST) {
            if (seq == t->rcv_nxt) {
                t->state = TCP_CLOSED;
                net_tcp_log("RST dari peer, koneksi ditutup");
            }
            return 1;
        }

        if (flags & TCP_SYN) {
            if (t->state == TCP_SYN_RCVD && seq == t->irs) {
                net_tcp_tcb_send(t->iss, TCP_SYN | TCP_ACK, 1);
            }
            return 1;
        }

        if (!(flags & TCP_ACK)) {
            return 1;
        }

        if (t->state == TCP_SYN_RCVD) {
            if (ack != t->snd_nxt) {
                net_tcp_send_seg(t->mac, t->ip, t->lport, t->rport,
                                 ack, 0, TCP_RST, 0, 0, 0);
                t->state = TCP_CLOSED;
                net_tcp_log("ACK handshake salah, koneksi dibatalkan");
                return 1;
            }

            t->snd_una = ack;
            t->state = TCP_ESTABLISHED;
            g_tcp_conn_open++;
            net_tcp_log("ESTABLISHED");
        }

        // C3b: ACK untuk data kita. ACK melewati snd_nxt (data yang belum
        // pernah dikirim) diabaikan dan dibalas ACK; ACK lama diabaikan.
        if (seq_lt(t->snd_nxt, ack)) {
            net_tcp_tcb_send(t->snd_nxt, TCP_ACK, 0);
            return 1;
        }
        if (seq_lt(t->snd_una, ack)) {
            uint32_t acked = ack - t->snd_una;

            t->buf_head = (t->buf_head + acked) % TCP_BUF_SIZE;
            t->buf_count -= acked;
            t->snd_una = ack;
            g_tcp_acked_bytes += acked;
        }
        if (seq_le(t->snd_una, ack)) {
            t->snd_wnd = ((uint32_t)buf[r + 14] << 8) | (uint32_t)buf[r + 15];
        }

        if (seq != t->rcv_nxt) {
            // Di luar urutan / duplikat: dibuang, balas ACK posisi kita.
            net_tcp_tcb_send(t->snd_nxt, TCP_ACK, 0);
            return 1;
        }

        uint32_t n = 0;
        int need_ack = dlen > 0;

        if (t->state == TCP_ESTABLISHED && dlen > 0) {
            // Hanya sebanyak ruang buffer (= jendela yang kita iklankan).
            uint32_t room = TCP_BUF_SIZE - t->buf_count;
            uint32_t tail = (t->buf_head + t->buf_count) % TCP_BUF_SIZE;

            n = dlen > room ? room : dlen;
            for (uint32_t i = 0; i < n; i++) {
                g_tcp_buf[(tail + i) % TCP_BUF_SIZE] = buf[r + doff + i];
            }
            t->buf_count += n;
            t->rcv_nxt += n;
            g_tcp_rx_bytes += n;
        }

        if ((flags & TCP_FIN) && n == dlen) {
            t->rcv_nxt++;
            t->state = TCP_CLOSE_WAIT;
            net_tcp_log("FIN dari peer (CLOSE_WAIT)");
            need_ack = 1;
        }

        // Jendela terbuka lagi (ACK membebaskan buffer): kabari peer.
        if (t->adv_wnd < TCP_MSS && net_tcp_rcv_wnd() >= TCP_MSS) {
            need_ack = 1;
        }

        if (!net_tcp_output() && need_ack) {
            net_tcp_tcb_send(t->snd_nxt, TCP_ACK, 0);
        }

        return 1;
    }

    if (dport == NET_TCP_ECHO_PORT && (flags & TCP_SYN) &&
        !(flags & (TCP_ACK | TCP_RST))) {
        if (t->state != TCP_CLOSED) {
            g_tcp_busy++;
            return 0;
        }

        uint8_t isn[4];

        // F1.8: tanpa entropi cukup SYN dibuang (bukan RST); peer mengulang.
        if (!entropy_get(isn, sizeof(isn))) {
            g_tcp_noentropy++;
            net_tcp_log("SYN dibuang: entropi belum cukup");
            return 1;
        }

        for (int i = 0; i < 6; i++) {
            t->mac[i] = buf[6 + i];
        }
        for (int i = 0; i < 4; i++) {
            t->ip[i] = buf[26 + i];
        }
        t->rport = sport;
        t->lport = dport;
        t->iss = ((uint32_t)isn[0] << 24) | ((uint32_t)isn[1] << 16) |
                 ((uint32_t)isn[2] << 8) | (uint32_t)isn[3];
        t->snd_nxt = t->iss + 1;
        t->irs = seq;
        t->rcv_nxt = seq + 1;
        t->last = timer_ticks;
        t->snd_una = t->iss;
        t->snd_wnd = ((uint32_t)buf[r + 14] << 8) | (uint32_t)buf[r + 15];
        t->buf_head = 0;
        t->buf_count = 0;
        t->state = TCP_SYN_RCVD;
        net_tcp_tcb_send(t->iss, TCP_SYN | TCP_ACK, 1);
        net_tcp_log("SYN diterima, SYN-ACK dikirim (SYN_RCVD)");
        return 1;
    }

    return 0;
}

static void net_handle_tcp(volatile uint8_t *buf, uint32_t ihl,
                           uint32_t ip_payload_len)
{
    if (ip_payload_len < 20) {
        return;
    }

    uint32_t r = 14 + ihl;
    uint32_t doff = (uint32_t)(buf[r + 12] >> 4) * 4;

    if (doff < 20 || doff > ip_payload_len) {
        return;
    }

    if (!net_udp_src_budget_ok(buf + 26)) {
        return;
    }

    if (!net_udp_budget_ok()) {
        return;
    }

    g_tcp_rx++;

    if (net_tcp_checksum(buf + 26, buf + 30, buf + r, ip_payload_len) != 0) {
        g_tcp_badsum++;
        serial_write("C1: TCP checksum salah, drop\r\n");
        return;
    }

    uint8_t flags = buf[r + 13];

    if (net_tcp_input(buf, ihl, doff, ip_payload_len)) {
        return;
    }

    // Segmen RST tidak pernah dibalas.
    if (flags & TCP_RST) {
        return;
    }

    // Port tertutup (atau koneksi lain): balas RST.
    uint32_t seg_len = ip_payload_len - doff;

    if (flags & TCP_SYN) {
        seg_len++;
    }
    if (flags & TCP_FIN) {
        seg_len++;
    }

    uint64_t lf = irq_save();
    serial_write("C1: TCP port tertutup dari ");
    e1000_log_ip(buf + 26);
    serial_write(" flags=");
    serial_write_hex((uint64_t)flags);
    serial_write(" -> RST\r\n");
    irq_restore(lf);

    net_tcp_send_rst(buf, ihl, seg_len);
}

static void net_handle_udp(volatile uint8_t *buf, uint32_t ihl,
                           uint32_t ip_payload_len)
{
    if (ip_payload_len < 8) {
        return;
    }

    uint32_t r = 14 + ihl;
    uint32_t src_port = ((uint32_t)buf[r + 0] << 8) | (uint32_t)buf[r + 1];
    uint32_t dst_port = ((uint32_t)buf[r + 2] << 8) | (uint32_t)buf[r + 3];
    uint32_t udp_len = ((uint32_t)buf[r + 4] << 8) | (uint32_t)buf[r + 5];
    uint32_t csum = ((uint32_t)buf[r + 6] << 8) | (uint32_t)buf[r + 7];

    if (udp_len < 8 || udp_len > ip_payload_len) {
        return;
    }

    if (dst_port != NET_UDP_ECHO_PORT && dst_port != NET_UDP_CMD_PORT) {
        return;
    }

    if (!net_udp_src_budget_ok(buf + 26)) {
        return;
    }

    if (!net_udp_budget_ok()) {
        return;
    }

    if (csum != 0 &&
        net_udp_checksum(buf + 26, buf + 30, buf + r, udp_len) != 0) {
        g_net_udp_badsum++;
        serial_write("Net-8: UDP checksum salah, drop\r\n");
        return;
    }

    uint64_t lf = irq_save();
    serial_write(dst_port == NET_UDP_CMD_PORT
                 ? "Net-9: UDP cmd port 7778 dari "
                 : "Net-8: UDP echo port 7777 dari ");
    e1000_log_ip(buf + 26);
    serial_write(" src_port=");
    serial_write_hex((uint64_t)src_port);
    serial_write(" payload=");
    serial_write_hex((uint64_t)(udp_len - 8));
    serial_write(" byte\r\n");
    irq_restore(lf);

    if (dst_port == NET_UDP_CMD_PORT) {
        net_cmd_handle(buf, ihl, udp_len);
    } else {
        net_udp_send_echo(buf, ihl, udp_len);
    }
}

static void net_handle_ipv4(volatile uint8_t *buf, uint32_t len)
{
    if (len < 14 + 20) {
        return;
    }

    uint32_t ver = buf[14] >> 4;
    uint32_t ihl = (uint32_t)(buf[14] & 0x0F) * 4;
    uint32_t total_len = ((uint32_t)buf[16] << 8) | (uint32_t)buf[17];
    uint32_t frag = ((uint32_t)(buf[20] & 0x3F) << 8) | (uint32_t)buf[21];

    if (ver != 4 || ihl < 20 || total_len < ihl || 14 + total_len > len) {
        return;
    }

    if (frag != 0) {
        return;
    }

    if (!net_ip_equal(buf + 30, g_net_ip)) {
        return;
    }

    if (net_checksum16(buf + 14, ihl) != 0) {
        serial_write("Net-6: IPv4 header checksum salah, drop\r\n");
        return;
    }

    if (buf[23] == 17) {
        net_handle_udp(buf, ihl, total_len - ihl);
        return;
    }

    if (buf[23] == 6) {
        net_handle_tcp(buf, ihl, total_len - ihl);
        return;
    }

    if (buf[23] != 1) {
        return;
    }

    uint32_t icmp_len = total_len - ihl;

    if (icmp_len < 8) {
        return;
    }

    if (net_checksum16(buf + 14 + ihl, icmp_len) != 0) {
        serial_write("Net-6: ICMP checksum salah, drop\r\n");
        return;
    }

    if (buf[14 + ihl] == 8 && buf[14 + ihl + 1] == 0) {
        uint64_t lf = irq_save();
        serial_write("Net-6: ICMP echo request dari ");
        e1000_log_ip(buf + 26);
        serial_write(" seq=");
        serial_write_hex((uint64_t)(((uint32_t)buf[14 + ihl + 6] << 8) |
                                    (uint32_t)buf[14 + ihl + 7]));
        serial_write("\r\n");
        irq_restore(lf);
        net_icmp_send_echo_reply(buf, ihl, icmp_len);
    }
}

static void net_rx_dispatch(volatile uint8_t *buf, uint32_t len)
{
    if (len < 14) {
        return;
    }

    uint32_t ethertype = ((uint32_t)buf[12] << 8) | (uint32_t)buf[13];

    // B4b: log frame ini ke UART hanya kalau jatah per detik masih ada;
    // kalau tidak, tetap tercatat di ring log (perintah `log`).
    g_serial_mute = !net_serial_log_ok();

    if (ethertype == 0x0806 && len >= 42) {
        g_net_rx_arp++;
        net_handle_arp(buf);
    } else if (ethertype == 0x0800) {
        g_net_rx_ipv4++;
        net_handle_ipv4(buf, len);
    } else {
        g_net_rx_other++;
    }

    g_serial_mute = 0;
}

// Konsumsi ring RX berurutan mulai g_e1000_rx_next. Tiap slot DD:
// log ringkas, decode ARP, recycle descriptor, update RDT.
static void __attribute__((unused)) e1000_rx_listen(uint64_t max_iter, int max_packets)
{
    if (!g_e1000_rx_initialized) {
        serial_write("E1000: RX listen dibatalkan - RX belum di-init\r\n");
        return;
    }

    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;
    int got = 0;
    uint64_t guard = 0;

    serial_write("E1000: RX listen mulai\r\n");

    while (got < max_packets && guard < max_iter &&
           g_net_icmp_replies_sent < 8) {
        volatile uint8_t *desc =
            (volatile uint8_t *)(g_e1000_rx_ring_virt + (g_e1000_rx_next * 16));

        if (!(desc[0x0C] & E1000_RXD_STA_DD)) {
            guard++;
            continue;
        }

        uint32_t len = (uint32_t)desc[0x08] | ((uint32_t)desc[0x09] << 8);
        volatile uint8_t *buf =
            (volatile uint8_t *)(g_e1000_rx_buf_phys[g_e1000_rx_next] + hhdm_offset);
        uint32_t ethertype = ((uint32_t)buf[12] << 8) | (uint32_t)buf[13];

        serial_write("E1000: RX slot=");
        serial_write_hex((uint64_t)g_e1000_rx_next);
        serial_write(" len=");
        serial_write_hex((uint64_t)len);
        serial_write(" ethertype=");
        serial_write_hex((uint64_t)ethertype);
        serial_write(" src=");
        e1000_log_mac(buf + 6);
        serial_write("\r\n");

        if (ethertype == 0x0806 && len >= 42) {
            uint32_t oper = ((uint32_t)buf[20] << 8) | (uint32_t)buf[21];

            serial_write("E1000: RX ARP ");
            serial_write(oper == 2 ? "REPLY" : (oper == 1 ? "REQUEST" : "OPER-?"));
            serial_write(" sender_mac=");
            e1000_log_mac(buf + 22);
            serial_write(" sender_ip=");
            e1000_log_ip(buf + 28);
            serial_write(" target_ip=");
            e1000_log_ip(buf + 38);
            serial_write("\r\n");
        }

        net_rx_dispatch(buf, len);

        desc[0x0C] = 0;
        desc[0x0D] = 0;
        mmio[E1000_REG_RDT / 4] = g_e1000_rx_next;
        g_e1000_rx_next = (g_e1000_rx_next + 1) % E1000_RX_RING_SIZE;
        got++;
    }

    serial_write("E1000: RX listen selesai, paket=");
    serial_write_hex((uint64_t)got);
    serial_write("\r\n");
}

// Net-7: proses SEMUA slot RX yang siap (DD set), lalu return.
// Tidak memblok. Return = jumlah paket yang diproses.
int net_poll(void)
{
    if (!g_e1000_rx_initialized) {
        return 0;
    }

    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;
    int processed = 0;

    while (processed < E1000_RX_RING_SIZE) {
        volatile uint8_t *desc =
            (volatile uint8_t *)(g_e1000_rx_ring_virt + (g_e1000_rx_next * 16));

        if (!(desc[0x0C] & E1000_RXD_STA_DD)) {
            break;
        }

        uint32_t len = (uint32_t)desc[0x08] | ((uint32_t)desc[0x09] << 8);
        volatile uint8_t *buf =
            (volatile uint8_t *)(g_e1000_rx_buf_phys[g_e1000_rx_next] + hhdm_offset);

        g_net_rx_frames++;
        entropy_event(ENTROPY_SRC_RX, len);

        if (desc[0x0D] == 0) {
            net_rx_dispatch(buf, len);
        } else {
            g_net_rx_errors++;
        }

        desc[0x0C] = 0;
        desc[0x0D] = 0;
        mmio[E1000_REG_RDT / 4] = g_e1000_rx_next;
        g_e1000_rx_next = (g_e1000_rx_next + 1) % E1000_RX_RING_SIZE;
        processed++;
    }

    return processed;
}

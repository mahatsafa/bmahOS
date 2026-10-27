#include "kernel.h"

// ---- Net-5: konfigurasi IP statis + ARP responder + dispatch RX ----
const uint8_t g_net_ip[4] = {192, 168, 50, 200};

// D7: nilai runtime yang bisa diubah CONFIG.CFG (config.c); awal = default.
uint32_t g_cli_idle_s = CFG_CLI_IDLE_DEF;
uint32_t g_net_src_rate = NET_UDP_SRC_PER_SEC;
uint32_t g_net_echo = 1;
uint32_t g_cli_plain = 1;   // D9: CONFIG.CFG cli_plain
uint32_t g_udp_admin = 1;   // D9: CONFIG.CFG udp_admin (dipakai auth.c)
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

    netcon_arp_seen(buf);   // R2: MAC tujuan netconsole
    sntp_arp_seen(buf);     // P3-2: MAC server SNTP
    dns_arp_seen(buf);      // P3-3: MAC server DNS

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
uint64_t g_tcp_retx = 0;          // C3c: segmen dikirim ulang (SYN-ACK + data)
uint64_t g_tcp_retx_giveup = 0;   // C3c: koneksi diputus setelah TCP_RTX_MAX
uint64_t g_tcp_close_ok = 0;      // C3d: koneksi selesai lewat FIN dua arah
uint64_t g_tcp_rst_state = 0;     // C3d: RST karena data di keadaan penutupan
uint64_t g_tcp_conn_dropped = 0;  // C4: segmen koneksi aktif melewati batas per koneksi
uint64_t g_tcp_dupack_limited = 0; // C4: ACK untuk segmen di luar urutan yang tidak dikirim
uint64_t g_tcp_src_full = 0;       // C5a: SYN ditolak, IP sumber sudah punya TCP_MAX_PER_IP TCB
uint64_t g_tcp_synrcvd_evicted = 0; // C5a: SYN_RCVD tertua digusur saat tabel penuh
uint64_t g_cli_login_ok = 0;       // D1: login TCP 7779 berhasil
uint64_t g_cli_login_fail = 0;     // D1: login gagal (format/hmac/auth nonaktif)
uint64_t g_cli_login_timeout = 0;  // D1: tidak login dalam TCP_LOGIN_TIMEOUT
uint64_t g_cli_line_long = 0;      // D1: baris > TCP_LINE_MAX, koneksi ditutup
uint64_t g_cli_cmd_ok = 0;         // D2: perintah sesi TCP terverifikasi
uint64_t g_cli_cmd_fail = 0;       // D2: perintah ditolak (format/hmac), koneksi ditutup
uint64_t g_cli_login_ro = 0;       // D4: login berhasil dengan peran read-only
uint64_t g_cli_sess_full = 0;      // D4: SYN 7779 ditolak, sudah TCP_CLI_MAX sesi
uint64_t g_cli_idle_timeout = 0;   // D4: sesi login tanpa perintah TCP_CLI_IDLE

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

    if (s->used >= g_net_src_rate) {
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

// P3-3a: ARP request "who-has ip" (broadcast) 60 byte di p, dari MAC/IP kita.
// Dipakai netconsole dan SNTP (dulu tiap modul menyalin kode ini). Return 60.
uint32_t net_arp_request_build(uint8_t *p, const volatile uint8_t *ip)
{
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
    return 60;
}

// R2-1: isi header Ethernet + IPv4 (proto 17) + UDP di depan payload yang
// SUDAH ada di p[42..42+plen), padding sampai 60 byte dinolkan, checksum IP
// dan UDP dihitung. Return = panjang frame yang dikirim (>= 60).
uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen)
{
    uint32_t udp_len = 8 + plen;
    uint32_t frame_len = 14 + 20 + udp_len;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = frame_len; i < send_len; i++) {
        p[i] = 0;
    }

    // Ethernet
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
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
    p[24] = 0;
    p[25] = 0;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = dst_ip[i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    // UDP
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)(sport & 0xFF);
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)(dport & 0xFF);
    p[38] = (uint8_t)(udp_len >> 8);
    p[39] = (uint8_t)(udp_len & 0xFF);
    p[40] = 0;
    p[41] = 0;

    uint16_t uc = net_udp_checksum(p + 26, p + 30, p + 34, udp_len);
    if (uc == 0) {
        uc = 0xFFFF;
    }
    p[40] = (uint8_t)(uc >> 8);
    p[41] = (uint8_t)(uc & 0xFF);

    return send_len;
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

    for (uint32_t i = 0; i + 8 < udp_len; i++) {
        p[42 + i] = req[r + 8 + i];
    }

    // UDP: port ditukar (src <- dst request, dst <- src request)
    uint16_t sport = (uint16_t)(((uint32_t)req[r + 2] << 8) | req[r + 3]);
    uint16_t dport = (uint16_t)(((uint32_t)req[r + 0] << 8) | req[r + 1]);
    uint32_t send_len = net_udp_build(p, req + 6, req + 26, sport, dport, udp_len - 8);

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

// ---- C2/C3b/C5a: koneksi TCP (port 7) ----
// C5a: tabel statis TCP_MAX_CONN TCB, masing-masing dengan buffer dan timer
// retransmisi sendiri. SYN baru: IP sumber yang sudah memegang TCP_MAX_PER_IP
// TCB (keadaan apa pun) -> RST; slot kosong dipakai; tabel penuh -> SYN_RCVD
// tertua digusur diam-diam (tanpa RST, umumnya IP palsu; peer sah mengulang
// SYN); tidak ada SYN_RCVD -> RST. Koneksi ESTABLISHED tidak pernah digusur.
// C3b: data yang diterima masuk ke g_tcp_buf lalu dikirim balik (echo
// sementara; uji echo penuh 1 MB di C4). Jendela yang diiklankan = ruang
// kosong g_tcp_buf; segmen di luar urutan dibuang (DECISIONS 2026-10-12).
// Kirim stop-and-wait: maks satu segmen data belum di-ACK, <= TCP_MSS dan
// <= jendela peer. Nomor urut dibandingkan bertanda (seq_lt/seq_le) karena
// berputar di 2^32. C3c: SYN-ACK dan data yang belum di-ACK dikirim ulang
// (lihat net_tcp_rtx_fire).
// C3d penutupan: FIN peer -> CLOSE_WAIT; setelah echo habis dan di-ACK, FIN
// kita -> LAST_ACK -> CLOSED (tutup pasif, port langsung bebas). Koneksi diam
// TCP_IDLE_TIMEOUT dengan buffer kosong ditutup aktif: FIN -> FIN_WAIT_1 ->
// FIN_WAIT_2 (maks TCP_FIN_WAIT_2_TIMEOUT) -> TIME_WAIT (TCP_TIME_WAIT_TICKS);
// FIN bersamaan -> CLOSING. FIN kita memakai satu nomor urut dan dikirim
// ulang seperti data. Data baru setelah FIN peer atau setelah FIN kita -> RST.
// C5b: `last` (dasar semua timeout keadaan) hanya diperbarui oleh kemajuan:
// handshake selesai, ACK yang memajukan snd_una, data baru dalam urutan, FIN
// peer. ACK duplikat, keepalive, jendela 0 berulang, SYN ulang, dan RST/segmen
// di luar urutan tidak memperpanjang timeout, jadi peer (atau penebak 4-tuple)
// tidak bisa menahan slot TCB tanpa batas dengan segmen kosong.
#define NET_TCP_ECHO_PORT   7
#define TCP_BUF_SIZE        1024
#define TCP_MSS             536
#define TCP_SYNRCVD_TIMEOUT 500    // tick (5 detik)
#define TCP_IDLE_TIMEOUT    3000   // tick (30 detik) tanpa kemajuan (C5b); tidak
                                   // berlaku selama ada segmen belum di-ACK
#define TCP_RTO_INIT        100    // tick (1 detik), RTO awal tetap (C3c)
#define TCP_RTO_MAX         800    // tick: backoff 1, 2, 4, 8, 8 detik
#define TCP_RTX_MAX         5      // kirim ulang maks 5x, berikutnya RST
#define TCP_FIN_WAIT_2_TIMEOUT 1000   // tick (10 detik) menunggu FIN peer (C3d)
#define TCP_TIME_WAIT_TICKS 200    // tick (2 detik), bukan 2*MSL (C0, C3d)
// C4: segmen dari peer koneksi aktif (IP + port cocok TCB) tidak memakai batas
// UDP (20/s per IP, 100/s global) yang terlalu kecil untuk aliran data, tetapi
// dibatasi per koneksi; lebihnya dibuang (peer mengirim ulang). Balasan ACK
// untuk segmen di luar urutan/duplikat/ACK berlebih dibatasi supaya segmen
// palsu dengan 4-tuple tertebak tidak bisa memicu banjir balasan.
#define TCP_CONN_SEG_PER_SEC 2000
#define TCP_DUPACK_PER_SEC  10
// C5a: jumlah slot TCB (tabel statis, tanpa heap) dan batas per IP sumber.
#define TCP_MAX_CONN        4
#define TCP_MAX_PER_IP      2
// D1: CLI port 7779. Setelah handshake server mengirim "bmahOS login\n" dan
// "nonce: <32 hex>\n" (nonce per koneksi dari DRBG, dibuat saat SYN); klien
// mengirim "login <hmac-hex64>" (lihat auth_tcp_login, PROTOCOL.md). Satu
// percobaan per koneksi; gagal/timeout/baris terlalu panjang -> ERR lalu FIN.
// Baris maks TCP_LINE_MAX byte termasuk LF.
// D2: setelah login tiap baris "<perintah> <hmac>" (auth_tcp_cmd, nomor urut
// per koneksi); salah -> ERR lalu FIN. Keluaran (maks TCP_CLI_OUT_MAX, diakhiri
// "END <n>") disimpan per TCB dan dialirkan ke antrean kirim saat ada ruang;
// selama belum habis, baris berikutnya tidak dibaca (tidak di-ACK).
#define NET_TCP_CLI_PORT    7779
#define TCP_LINE_MAX        128
#define TCP_LOGIN_TIMEOUT   1000   // tick (10 detik) sejak ESTABLISHED
#define TCP_CLI_REPLY_MAX   64     // balasan ERR/OK CLI terpanjang (byte)
#define TCP_CLI_OUT_MAX     1432   // keluaran perintah (g_cmd_out 1400) + END
#define TCP_REBOOT_WAIT     200    // tick: reboot paling lambat 2 s setelah perintah
// D4: maks TCP_CLI_MAX TCB port 7779 (keadaan apa pun); SYN berikutnya: SYN_RCVD
// CLI tertua digusur, tanpa SYN_RCVD CLI -> RST (cli_sess_full). Sesi yang
// sudah login ditutup (ERR lalu FIN) TCP_CLI_IDLE setelah perintah sah
// terakhir; batas diam TCP 30 s tidak berlaku untuknya selama antrean kirim
// kosong. Byte yang menetes tanpa perintah utuh tidak memperpanjang sesi.
#define TCP_CLI_MAX         2
// D9: port 7780 = protokol baris yang sama di dalam TLS 1.2 (kernel/tls.c).
// Hanya dibuka bila tls_load berhasil (selain itu SYN -> RST). Maks
// TLS_MAX_SESS TCB 7780 (keadaan apa pun), aturan penggusuran sama dengan 7779.
// Banner dikirim setelah handshake TLS selesai; batas login 10 s dihitung
// sejak ESTABLISHED TCP (termasuk handshake). Error TLS -> RST.
#define NET_TCP_TLS_PORT    7780
#define TCP_CLI_IDLE        ((uint64_t)g_cli_idle_s * 100)  // tick (D7: cli_idle)
enum { TCP_APP_ECHO = 0, TCP_APP_CLI };

// Nilai juga dipakai metrics tcp_state.
enum { TCP_CLOSED = 0, TCP_SYN_RCVD, TCP_ESTABLISHED, TCP_CLOSE_WAIT,
       TCP_LAST_ACK, TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSING,
       TCP_TIME_WAIT };

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
    uint32_t rto;       // C3c: RTO berikutnya (tick)
    uint32_t retries;   // C3c: kirim ulang sejak kemajuan snd_una terakhir
    int fin_sent;       // C3d: FIN kita terkirim (nomor urutnya snd_nxt - 1)
    uint64_t seg_window, dupack_window;   // C4: awal jendela 1 detik
    uint32_t seg_used, dupack_used;
    int app;            // D1: TCP_APP_ECHO (port 7) / TCP_APP_CLI (7779)
    int cli_authed;     // D1: login berhasil
    int role;           // D4: AUTH_ROLE_* setelah login
    uint64_t cli_last;  // D4: tick login / perintah sah terakhir
    int close_after;    // D1: FIN setelah antrean kirim habis dan di-ACK
    uint64_t opened;    // D1: tick ESTABLISHED (batas login)
    uint8_t nonce[16];  // D1: nonce login koneksi ini
    uint32_t line_len;
    uint8_t line[TCP_LINE_MAX];
    uint64_t cmd_seq;   // D2: perintah terverifikasi terakhir (berikutnya +1)
    int reboot_after;   // D2: reboot setelah keluaran di-ACK
    uint32_t out_len, out_pos;   // D2: keluaran out[out_pos..out_len) belum diantre
    uint8_t out[TCP_CLI_OUT_MAX];
    int tls;            // D9: slot TLS + 1 (0 = teks polos)
    int tls_banner;     // D9: handshake selesai, banner sudah dikirim
    int tls_closing;    // D9: close_notify kita sudah diantre
} tcp_tcb_t;

#define TCB_CHAN(t)  ((t)->tls ? AUDIT_TLS : AUDIT_TCP)

static tcp_tcb_t g_tcbs[TCP_MAX_CONN];
// D2: reboot diminta lewat CLI; batas waktunya global (bukan di TCB) supaya
// tetap jalan walau koneksi sudah ditutup/RST sebelum keluaran di-ACK.
static int g_cli_reboot;
static uint64_t g_cli_reboot_at;
static uint8_t g_tcp_buf[TCP_MAX_CONN][TCP_BUF_SIZE];
// C3c: di luar TCB (ada di senarai ktimer), satu per slot.
static ktimer_t g_tcp_rtx_timer[TCP_MAX_CONN];

#define TCB_BUF(t)   (g_tcp_buf[(t) - g_tcbs])
#define TCB_TIMER(t) (&g_tcp_rtx_timer[(t) - g_tcbs])

static void net_tcp_rtx_arm(tcp_tcb_t *t);
static void net_tcp_log(const char *msg);
static int net_tcp_cli_flushed(const tcp_tcb_t *t);

// Metrics tcp_state: keadaan slot aktif pertama, 0 bila semua CLOSED.
int net_tcp_state(void)
{
    for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
        if (g_tcbs[k].state != TCP_CLOSED) {
            return g_tcbs[k].state;
        }
    }
    return TCP_CLOSED;
}

int net_tcp_conn_active(void)
{
    int n = 0;

    for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
        n += g_tcbs[k].state != TCP_CLOSED;
    }
    return n;
}

// R3: jumlah TCB bukan CLOSED dengan port lokal tertentu (metrics).
static int net_tcp_port_active(uint16_t port)
{
    int n = 0;

    for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
        n += g_tcbs[k].state != TCP_CLOSED && g_tcbs[k].lport == port;
    }
    return n;
}

int net_tcp_cli_active(void)
{
    return net_tcp_port_active(NET_TCP_CLI_PORT);
}

int net_tcp_tls_active(void)
{
    return net_tcp_port_active(NET_TCP_TLS_PORT);
}

static inline int seq_lt(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) < 0;
}

static inline int seq_le(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) <= 0;
}

static uint32_t net_tcp_rcv_wnd(const tcp_tcb_t *t)
{
    return TCP_BUF_SIZE - t->buf_count;
}

// D1: tambahkan data ke antrean kirim TCB (ekor TCB_BUF), maks sebanyak ruang
// kosong. Return jumlah byte yang masuk; pengiriman oleh net_tcp_output.
static uint32_t net_tcp_queue(tcp_tcb_t *t, const volatile uint8_t *d,
                              uint32_t len)
{
    uint32_t room = TCP_BUF_SIZE - t->buf_count;
    uint32_t tail = (t->buf_head + t->buf_count) % TCP_BUF_SIZE;
    uint32_t n = len > room ? room : len;

    for (uint32_t i = 0; i < n; i++) {
        TCB_BUF(t)[(tail + i) % TCP_BUF_SIZE] = d[i];
    }
    t->buf_count += n;
    return n;
}

static uint32_t net_rd32(const volatile uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Segmen TCP dari TCB t ke peer-nya, dengan data (dlen <= TCP_MSS) atau tanpa.
// mss_opt != 0: sertakan opsi MSS. Jendela = ruang kosong buffer TCB.
static void net_tcp_send_seg(tcp_tcb_t *t, uint32_t seq, uint32_t ack,
                             uint8_t flags, int mss_opt,
                             const uint8_t *data, uint32_t dlen)
{
    const uint8_t *mac = t->mac;
    const uint8_t *ip = t->ip;
    uint16_t sport = t->lport;
    uint16_t dport = t->rport;

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("C2: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t hl = mss_opt ? 24 : 20;
    uint32_t wnd = net_tcp_rcv_wnd(t);

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
    t->adv_wnd = wnd;

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

static void net_tcp_tcb_send(tcp_tcb_t *t, uint32_t seq, uint8_t flags,
                             int mss_opt)
{
    net_tcp_send_seg(t, seq, t->rcv_nxt, flags, mss_opt, 0, 0);
}

// C4: ACK posisi kita sebagai balasan segmen yang tidak diterima (di luar
// urutan, duplikat, ACK melewati snd_nxt). Maks TCP_DUPACK_PER_SEC per detik.
static void net_tcp_send_dupack(tcp_tcb_t *t)
{
    uint64_t now = timer_ticks;

    if (now - t->dupack_window >= 100) {
        t->dupack_window = now;
        t->dupack_used = 0;
    }
    if (t->dupack_used >= TCP_DUPACK_PER_SEC) {
        g_tcp_dupack_limited++;
        return;
    }
    t->dupack_used++;
    net_tcp_tcb_send(t, t->snd_nxt, TCP_ACK, 0);
}

// C4/C5a: TCB koneksi aktif yang cocok dengan segmen (IP sumber, port sumber,
// port tujuan), atau 0. Dipakai sebelum checksum untuk memilih batas laju.
static tcp_tcb_t *net_tcp_find(const volatile uint8_t *buf, uint32_t r)
{
    uint16_t sport = (uint16_t)(((uint32_t)buf[r + 0] << 8) | buf[r + 1]);
    uint16_t dport = (uint16_t)(((uint32_t)buf[r + 2] << 8) | buf[r + 3]);

    for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
        tcp_tcb_t *t = &g_tcbs[k];
        int match = t->state != TCP_CLOSED && sport == t->rport &&
                    dport == t->lport;

        for (int i = 0; match && i < 4; i++) {
            if (buf[26 + i] != t->ip[i]) {
                match = 0;
            }
        }
        if (match) {
            return t;
        }
    }
    return 0;
}

static int net_tcp_conn_budget_ok(tcp_tcb_t *t)
{
    uint64_t now = timer_ticks;

    if (now - t->seg_window >= 100) {
        t->seg_window = now;
        t->seg_used = 0;
    }
    if (t->seg_used >= TCP_CONN_SEG_PER_SEC) {
        g_tcp_conn_dropped++;
        return 0;
    }
    t->seg_used++;
    return 1;
}

// C3d: FIN kita. Hanya dipanggil bila data kita habis dan semua di-ACK
// (snd_una == snd_nxt, buf_count == 0), jadi FIN satu-satunya yang menunggu
// ACK dan timer retransmisi mengirim ulang FIN saja.
static void net_tcp_send_fin(tcp_tcb_t *t, int next_state)
{
    net_tcp_tcb_send(t, t->snd_nxt, TCP_FIN | TCP_ACK, 0);
    t->snd_nxt++;
    t->fin_sent = 1;
    t->state = next_state;
    net_tcp_rtx_arm(t);
}

// Kirim data yang menunggu bila tidak ada segmen data yang belum di-ACK
// (stop-and-wait). Return 1 bila segmen terkirim (segmen data membawa ACK).
static int net_tcp_output(tcp_tcb_t *t)
{
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
        // D2: reboot setelah keluaran perintah terkirim dan di-ACK. Dicek
        // sebelum FIN: peer bisa mengirim ACK + FIN dalam satu segmen
        // (Windows Close()), lalu koneksi CLOSE_WAIT.
        if (t->reboot_after && net_tcp_cli_flushed(t)) {
            t->reboot_after = 0;
            g_cli_reboot = 0;
            net_tcp_log("CLI reboot");
            auth_reboot();
            return 0;
        }
        // C3d: peer sudah FIN dan echo habis terkirim + di-ACK: FIN kita
        // (sekaligus ACK untuk FIN peer).
        if (t->state == TCP_CLOSE_WAIT && t->buf_count == 0) {
            net_tcp_send_fin(t, TCP_LAST_ACK);
            net_tcp_log("FIN dikirim (LAST_ACK)");
            return 1;
        }
        // D1: CLI memutuskan menutup (login gagal/timeout, baris panjang):
        // FIN setelah balasan terkirim dan di-ACK.
        if (t->state == TCP_ESTABLISHED && t->close_after && net_tcp_cli_flushed(t)) {
            net_tcp_send_fin(t, TCP_FIN_WAIT_1);
            net_tcp_log("FIN dikirim (FIN_WAIT_1)");
            return 1;
        }
        return 0;
    }

    uint8_t seg[TCP_MSS];

    for (uint32_t i = 0; i < n; i++) {
        seg[i] = TCB_BUF(t)[(t->buf_head + i) % TCP_BUF_SIZE];
    }
    net_tcp_send_seg(t, t->snd_nxt, t->rcv_nxt, TCP_PSH | TCP_ACK, 0, seg, n);
    t->snd_nxt += n;
    g_tcp_tx_bytes += n;
    net_tcp_rtx_arm(t);
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

// ---- C3c: retransmisi ----
// Satu timer per TCB. Yang dikirim ulang: SYN-ACK (SYN_RCVD) atau
// byte snd_una..snd_nxt yang masih ada di g_tcp_buf mulai buf_head (stop-and-
// wait: <= TCP_MSS), jadi tidak perlu salinan segmen. RTO awal tetap
// TCP_RTO_INIT (tanpa pengukuran RTT), dilipatduakan tiap kirim ulang sampai
// TCP_RTO_MAX; ACK yang memajukan snd_una mengembalikannya ke awal. Setelah
// TCP_RTX_MAX kirim ulang tanpa kemajuan: RST dan TCB dibebaskan.
static void net_tcp_rtx_fire(void *arg);

static void net_tcp_rtx_arm(tcp_tcb_t *t)
{
    ktimer_start(TCB_TIMER(t), t->rto, net_tcp_rtx_fire, t);
}

// snd_una maju: backoff kembali ke awal, timer jalan lagi bila masih ada
// byte yang belum di-ACK.
static void net_tcp_rtx_progress(tcp_tcb_t *t)
{
    t->rto = TCP_RTO_INIT;
    t->retries = 0;
    if (t->snd_una == t->snd_nxt) {
        ktimer_cancel(TCB_TIMER(t));
    } else {
        net_tcp_rtx_arm(t);
    }
}

// D9: slot TLS dilepas (dan dihapus) setiap kali TCB menjadi CLOSED.
static void net_tcp_tls_release(tcp_tcb_t *t)
{
    if (t->tls) {
        tls_free(t->tls - 1);
        t->tls = 0;
    }
}

static void net_tcp_close(tcp_tcb_t *t, const char *why)
{
    ktimer_cancel(TCB_TIMER(t));
    net_tcp_tls_release(t);
    t->state = TCP_CLOSED;
    net_tcp_log(why);
}

static void net_tcp_rtx_fire(void *arg)
{
    tcp_tcb_t *t = arg;

    if (t->state == TCP_CLOSED || t->snd_una == t->snd_nxt) {
        return;
    }
    if (t->retries >= TCP_RTX_MAX) {
        net_tcp_tcb_send(t, t->snd_nxt, TCP_RST | TCP_ACK, 0);
        g_tcp_retx_giveup++;
        net_tcp_close(t, "kirim ulang habis, koneksi diputus (RST)");
        return;
    }

    uint32_t n = t->snd_nxt - t->snd_una;

    if (t->state == TCP_SYN_RCVD) {
        net_tcp_tcb_send(t, t->iss, TCP_SYN | TCP_ACK, 1);
    } else if (t->fin_sent) {
        net_tcp_tcb_send(t, t->snd_una, TCP_FIN | TCP_ACK, 0);   // C3d
    } else {
        uint8_t seg[TCP_MSS];

        for (uint32_t i = 0; i < n; i++) {
            seg[i] = TCB_BUF(t)[(t->buf_head + i) % TCP_BUF_SIZE];
        }
        net_tcp_send_seg(t, t->snd_una, t->rcv_nxt, TCP_PSH | TCP_ACK, 0,
                         seg, n);
    }
    t->retries++;
    g_tcp_retx++;
    kprintf("C3c: TCP kirim ulang ke-%u seq=%x len=%u rto=%u tick\r\n",
            t->retries, t->snd_una, t->state == TCP_SYN_RCVD || t->fin_sent ? 0 : n, t->rto);
    t->rto = t->rto * 2 > TCP_RTO_MAX ? TCP_RTO_MAX : t->rto * 2;
    net_tcp_rtx_arm(t);
}

// ---- D1: CLI port 7779 (login) ----
// D9b-1: satu pintu keluaran CLI. Return jumlah byte yang masuk antrean.
// D9: sesi TLS menulis plaintext ke engine (jadi record; dipindah ke antrean
// TCP oleh net_tcp_tls_pump).
static uint32_t net_tcp_cli_write(tcp_tcb_t *t, const volatile uint8_t *d,
                                  uint32_t len)
{
    if (t->tls) {
        return tls_app_write(t->tls - 1, d, len);
    }
    return net_tcp_queue(t, d, len);
}

// Ruang antrean untuk balasan CLI (byte).
static uint32_t net_tcp_cli_space(const tcp_tcb_t *t)
{
    if (t->tls) {
        return tls_app_space(t->tls - 1);
    }
    return TCP_BUF_SIZE - t->buf_count;
}

// Keluaran CLI sudah habis terkirim dan di-ACK (syarat FIN close_after/reboot).
// D9: juga tanpa record TLS menunggu, dan close_notify sudah diantre bila
// menutup (kecuali handshake belum selesai: langsung FIN).
static int net_tcp_cli_flushed(const tcp_tcb_t *t)
{
    if (t->buf_count != 0 || t->out_pos != t->out_len) {
        return 0;
    }
    if (!t->tls) {
        return 1;
    }

    uint32_t pending;

    (void)tls_rec_out(t->tls - 1, &pending);
    return pending == 0 && (!t->close_after || t->tls_closing || !t->tls_banner);
}

static void net_tcp_cli_reply(tcp_tcb_t *t, const char *s)
{
    uint32_t n = 0;

    while (s[n]) {
        n++;
    }
    net_tcp_cli_write(t, (const volatile uint8_t *)s, n);
}

// Dipanggil saat handshake selesai: banner + nonce login.
static void net_tcp_cli_banner(tcp_tcb_t *t)
{
    static const char hx[] = "0123456789abcdef";
    char m[64];
    uint32_t k = 0;
    const char *p = "bmahOS login\nnonce: ";

    while (*p) {
        m[k++] = *p++;
    }
    for (int i = 0; i < 16; i++) {
        m[k++] = hx[t->nonce[i] >> 4];
        m[k++] = hx[t->nonce[i] & 0xF];
    }
    m[k++] = '\n';
    net_tcp_cli_write(t, (const volatile uint8_t *)m, k);
}

// D2: alirkan keluaran yang tersisa ke antrean kirim (sebanyak ruang).
static void net_tcp_cli_drain(tcp_tcb_t *t)
{
    t->out_pos += net_tcp_cli_write(t, t->out + t->out_pos, t->out_len - t->out_pos);
}

static void net_tcp_cli_cmd(tcp_tcb_t *t, uint32_t len)
{
    uint32_t clen = 0;
    int rc = auth_tcp_cmd(t->nonce, t->role, t->cmd_seq + 1, t->line, len, &clen);

    if (rc != 0) {
        g_cli_cmd_fail++;
        audit_record(AUDIT_CMD_FAIL, TCB_CHAN(t), t->ip, t->rport, t->role, rc, 0, 0);
        net_tcp_cli_reply(t, rc == 1 ? "ERR: auth nonaktif\n" :
                          rc == 2 ? "ERR: format: <perintah> <hmac-hex64>\n" :
                          "ERR: hmac salah\n");
        t->close_after = 1;
        net_tcp_log("CLI perintah ditolak, koneksi ditutup");
        return;
    }
    t->cmd_seq++;
    t->cli_last = timer_ticks;
    g_cli_cmd_ok++;
    audit_record(net_cmd_is(t->line, clen, "exit") ||
                 auth_cmd_allowed(t->role, t->line, clen) ? AUDIT_CMD : AUDIT_CMD_ROLE,
                 TCB_CHAN(t), t->ip, t->rport, t->role, 0, t->line, clen);

    uint32_t n;
    int reboot = 0;

    if (net_cmd_is(t->line, clen, "exit")) {
        static const char bye[] = "bye\n";

        for (n = 0; bye[n]; n++) {
            t->out[n] = (uint8_t)bye[n];
        }
        t->close_after = 1;
    } else {
        n = auth_tcp_exec(t->role, t->line, clen, t->out, TCP_CLI_OUT_MAX - 32, &reboot);
    }
    if (reboot) {
        t->reboot_after = 1;
        g_cli_reboot = 1;
        g_cli_reboot_at = timer_ticks;
    }
    n += (uint32_t)ksnprintf((char *)t->out + n, TCP_CLI_OUT_MAX - n, "END %lu\n",
                             t->cmd_seq);
    t->out_len = n;
    t->out_pos = 0;
    net_tcp_cli_drain(t);
}

static void net_tcp_cli_line(tcp_tcb_t *t)
{
    uint32_t len = t->line_len;

    t->line_len = 0;
    if (len > 0 && t->line[len - 1] == '\r') {
        len--;
    }
    if (len == 0) {
        return;
    }
    if (t->cli_authed) {
        net_tcp_cli_cmd(t, len);
        return;
    }

    int role = AUTH_ROLE_NONE;
    int rc = auth_tcp_login(t->nonce, t->line, len, &role);

    if (rc == 0) {
        t->cli_authed = 1;
        t->role = role;
        t->cli_last = timer_ticks;
        g_cli_login_ok++;
        audit_record(AUDIT_LOGIN, TCB_CHAN(t), t->ip, t->rport, role, 0, 0, 0);
        if (role == AUTH_ROLE_ADMIN) {
            net_tcp_cli_reply(t, "OK login\n");
            net_tcp_log("CLI login OK");
        } else {
            g_cli_login_ro++;
            net_tcp_cli_reply(t, "OK login ro\n");
            net_tcp_log("CLI login OK (read-only)");
        }
        return;
    }
    g_cli_login_fail++;
    audit_record(AUDIT_LOGIN_FAIL, TCB_CHAN(t), t->ip, t->rport, AUTH_ROLE_NONE, rc, 0, 0);
    net_tcp_cli_reply(t, rc == 1 ? "ERR: auth nonaktif\n" : "ERR: login gagal\n");
    t->close_after = 1;
    net_tcp_log("CLI login gagal, koneksi ditutup");
}

// Data CLI masuk per baris. Return jumlah byte yang dikonsumsi; sisanya
// tidak di-ACK (peer mengirim ulang) bila ruang balasan kurang dari
// TCP_CLI_REPLY_MAX atau keluaran perintah sebelumnya belum habis (D2).
// Setelah memutuskan menutup, sisa data dibuang.
static uint32_t net_tcp_cli_rx(tcp_tcb_t *t, const volatile uint8_t *d,
                               uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++) {
        if (t->close_after) {
            continue;
        }
        if (net_tcp_cli_space(t) < TCP_CLI_REPLY_MAX ||
            t->out_pos < t->out_len) {
            break;
        }

        uint8_t c = d[i];

        if (c == '\n') {
            net_tcp_cli_line(t);
        } else if (t->line_len < TCP_LINE_MAX - 1) {
            t->line[t->line_len++] = c;
        } else {
            g_cli_line_long++;
            audit_record(AUDIT_LINE_LONG, TCB_CHAN(t), t->ip, t->rport, t->role, 0, 0, 0);
            net_tcp_cli_reply(t, "ERR: baris terlalu panjang\n");
            t->close_after = 1;
            net_tcp_log("CLI baris terlalu panjang, koneksi ditutup");
        }
    }
    return i;
}

// D9: pindahkan data antara engine TLS dan TCB: record keluar -> antrean
// TCP (sebanyak ruang), banner setelah handshake, keluaran CLI tersisa ->
// engine, plaintext masuk -> parser baris CLI, close_notify saat close_after.
// Return 0 bila TCB ditutup (error TLS -> RST).
static int net_tcp_tls_pump(tcp_tcb_t *t)
{
    int s = t->tls - 1;

    if (t->state != TCP_ESTABLISHED && t->state != TCP_CLOSE_WAIT) {
        return 1;
    }
    for (int round = 0; round < 16; round++) {
        int moved = 0;
        uint32_t len;
        const uint8_t *p = tls_rec_out(s, &len);

        if (len > 0) {
            uint32_t n = net_tcp_queue(t, p, len);

            tls_rec_out_ack(s, n);
            moved |= n > 0;
        }

        int st = tls_state(s);

        if (st < 0) {
            kprintf("D9: TLS gagal err=%d, koneksi diputus (RST)\r\n", tls_last_error(s));
            net_tcp_tcb_send(t, t->snd_nxt, TCP_RST | TCP_ACK, 0);
            net_tcp_close(t, "TLS gagal (RST)");
            return 0;
        }
        if (st > 0) {
            // Peer mengirim close_notify: tutup juga (FIN setelah antrean habis).
            t->close_after = 1;
            t->tls_closing = 1;
            t->out_len = t->out_pos = 0;
            return 1;
        }
        if (!tls_ready(s)) {
            return 1;   // handshake masih berjalan
        }
        if (!t->tls_banner) {
            if (tls_app_space(s) < TCP_CLI_REPLY_MAX) {
                continue;   // record handshake terakhir belum diambil
            }
            t->tls_banner = 1;
            kprintf("D9: TLS handshake OK suite=%x\r\n", (unsigned)tls_suite(s));
            net_tcp_cli_banner(t);
            moved = 1;
        }
        if (t->out_pos < t->out_len) {
            uint32_t before = t->out_pos;

            net_tcp_cli_drain(t);
            moved |= t->out_pos != before;
        }
        p = tls_app_in(s, &len);
        if (len > 0) {
            uint32_t c = net_tcp_cli_rx(t, p, len);

            tls_app_in_ack(s, c);
            moved |= c > 0;
        }
        if (t->close_after && !t->tls_closing && t->out_pos == t->out_len) {
            tls_close(s);
            t->tls_closing = 1;
            moved = 1;
        }
        if (!moved) {
            break;
        }
    }
    return 1;
}

static void net_tcp_tick_one(tcp_tcb_t *t)
{
    if (t->state == TCP_CLOSED) {
        return;
    }
    // D9: antrean TLS bisa bergerak tanpa segmen masuk (ruang TCB bebas).
    if (t->tls) {
        if (!net_tcp_tls_pump(t)) {
            return;
        }
        net_tcp_output(t);
    }
    // D1: login CLI harus selesai dalam TCP_LOGIN_TIMEOUT sejak ESTABLISHED.
    if (t->app == TCP_APP_CLI && t->state == TCP_ESTABLISHED && !t->cli_authed &&
        !t->close_after && timer_ticks - t->opened > TCP_LOGIN_TIMEOUT) {
        g_cli_login_timeout++;
        audit_record(AUDIT_LOGIN_TIMEOUT, TCB_CHAN(t), t->ip, t->rport, AUTH_ROLE_NONE, 0,
                     0, 0);
        net_tcp_cli_reply(t, "ERR: login timeout\n");
        t->close_after = 1;
        net_tcp_log("CLI login timeout, koneksi ditutup");
        net_tcp_output(t);
        return;
    }
    // D4: sesi login tanpa perintah sah TCP_CLI_IDLE -> ERR lalu FIN.
    if (t->app == TCP_APP_CLI && t->state == TCP_ESTABLISHED && t->cli_authed &&
        !t->close_after && timer_ticks - t->cli_last > TCP_CLI_IDLE) {
        g_cli_idle_timeout++;
        audit_record(AUDIT_IDLE, TCB_CHAN(t), t->ip, t->rport, t->role, 0, 0, 0);
        t->out_len = t->out_pos = 0;
        net_tcp_cli_reply(t, "ERR: sesi idle\n");
        t->close_after = 1;
        net_tcp_log("CLI sesi idle, koneksi ditutup");
        net_tcp_output(t);
        return;
    }
    // D4: sesi login yang diam dengan antrean kirim kosong diatur TCP_CLI_IDLE,
    // bukan batas diam TCP (data tertahan jendela 0 tetap kena batas TCP).
    if (t->app == TCP_APP_CLI && t->state == TCP_ESTABLISHED && t->cli_authed &&
        !t->close_after && t->buf_count == 0) {
        return;
    }
    // C3c: selama ada segmen belum di-ACK, retransmisi (TCP_RTX_MAX) yang
    // memutus koneksi macet; timeout menganggur hanya untuk koneksi diam.
    // Termasuk FIN_WAIT_1/CLOSING/LAST_ACK: FIN kita selalu menunggu ACK.
    if (t->state != TCP_SYN_RCVD && ktimer_pending(TCB_TIMER(t))) {
        return;
    }

    uint64_t limit = TCP_IDLE_TIMEOUT;

    if (t->state == TCP_SYN_RCVD) {
        limit = TCP_SYNRCVD_TIMEOUT;
    } else if (t->state == TCP_TIME_WAIT) {
        limit = TCP_TIME_WAIT_TICKS;
    } else if (t->state == TCP_FIN_WAIT_2) {
        limit = TCP_FIN_WAIT_2_TIMEOUT;
    }

    if (timer_ticks - t->last <= limit) {
        return;
    }
    if (t->state == TCP_TIME_WAIT) {
        g_tcp_close_ok++;
        net_tcp_close(t, "TIME_WAIT selesai (CLOSED)");
        return;
    }
    g_tcp_timeouts++;
    // C3d: koneksi diam tanpa data menunggu ditutup baik-baik (FIN). Data
    // yang tertahan (jendela peer 0, belum ada persist timer) atau FIN peer
    // yang tak kunjung datang di FIN_WAIT_2: RST.
    if (t->state == TCP_ESTABLISHED && t->buf_count == 0 &&
        t->snd_una == t->snd_nxt) {
        net_tcp_send_fin(t, TCP_FIN_WAIT_1);
        net_tcp_log("diam, FIN dikirim (FIN_WAIT_1)");
        return;
    }
    net_tcp_tcb_send(t, t->snd_nxt, TCP_RST | TCP_ACK, 0);
    net_tcp_close(t, "timeout, koneksi diputus (RST)");
}

// Dipanggil tiap loop net task (tick-wake ~100 Hz).
void net_tcp_tick(void)
{
    // D2: keluaran reboot tidak di-ACK dalam TCP_REBOOT_WAIT (atau koneksi
    // sudah tertutup): reboot juga.
    if (g_cli_reboot && timer_ticks - g_cli_reboot_at > TCP_REBOOT_WAIT) {
        g_cli_reboot = 0;
        for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
            g_tcbs[k].reboot_after = 0;
        }
        net_tcp_log("CLI reboot (keluaran belum di-ACK)");
        auth_reboot();
    }
    for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
        net_tcp_tick_one(&g_tcbs[k]);
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
    tcp_tcb_t *t = net_tcp_find(buf, r);

    if (t) {
        if (flags & TCP_RST) {
            // C3d: RST di TIME_WAIT diabaikan (RFC 1337), keadaan itu
            // berakhir sendiri setelah TCP_TIME_WAIT_TICKS.
            if (seq == t->rcv_nxt && t->state != TCP_TIME_WAIT) {
                net_tcp_close(t, "RST dari peer, koneksi ditutup");
            }
            return 1;
        }

        if (flags & TCP_SYN) {
            if (t->state == TCP_SYN_RCVD && seq == t->irs) {
                net_tcp_tcb_send(t, t->iss, TCP_SYN | TCP_ACK, 1);
            }
            return 1;
        }

        if (!(flags & TCP_ACK)) {
            return 1;
        }

        if (t->state == TCP_SYN_RCVD) {
            if (ack != t->snd_nxt) {
                net_tcp_send_seg(t, ack, 0, TCP_RST, 0, 0, 0);
                net_tcp_close(t, "ACK handshake salah, koneksi dibatalkan");
                return 1;
            }

            t->snd_una = ack;
            net_tcp_rtx_progress(t);
            t->state = TCP_ESTABLISHED;
            t->last = timer_ticks;   // C5b: kemajuan
            g_tcp_conn_open++;
            net_tcp_log("ESTABLISHED");
            if (t->app == TCP_APP_CLI) {
                t->opened = timer_ticks;
                if (!t->tls) {
                    net_tcp_cli_banner(t);   // D9: TLS: setelah handshake
                }
            }
        }

        // C3b: ACK untuk data kita. ACK melewati snd_nxt (data yang belum
        // pernah dikirim) diabaikan dan dibalas ACK; ACK lama diabaikan.
        if (seq_lt(t->snd_nxt, ack)) {
            net_tcp_send_dupack(t);
            return 1;
        }
        if (seq_lt(t->snd_una, ack)) {
            uint32_t acked = ack - t->snd_una;
            // C3d: FIN kita memakai satu nomor urut tanpa byte di buffer.
            int fin_acked = t->fin_sent && ack == t->snd_nxt;

            if (fin_acked) {
                acked--;
            }
            t->buf_head = (t->buf_head + acked) % TCP_BUF_SIZE;
            t->buf_count -= acked;
            t->snd_una = ack;
            t->last = timer_ticks;   // C5b: kemajuan
            g_tcp_acked_bytes += acked;
            net_tcp_rtx_progress(t);

            if (fin_acked && t->state == TCP_LAST_ACK) {
                g_tcp_close_ok++;
                net_tcp_close(t, "FIN kita di-ACK, koneksi ditutup (CLOSED)");
                return 1;
            }
            if (fin_acked && t->state == TCP_FIN_WAIT_1) {
                t->state = TCP_FIN_WAIT_2;
                net_tcp_log("FIN kita di-ACK (FIN_WAIT_2)");
            } else if (fin_acked && t->state == TCP_CLOSING) {
                t->state = TCP_TIME_WAIT;
                net_tcp_log("FIN kita di-ACK (TIME_WAIT)");
            }
        }
        if (seq_le(t->snd_una, ack)) {
            t->snd_wnd = ((uint32_t)buf[r + 14] << 8) | (uint32_t)buf[r + 15];
        }
        if (t->tls) {
            if (!net_tcp_tls_pump(t)) {
                return 1;
            }
        } else if (t->app == TCP_APP_CLI && t->out_pos < t->out_len) {
            net_tcp_cli_drain(t);
        }

        if (seq != t->rcv_nxt) {
            // Di luar urutan / duplikat: dibuang, balas ACK posisi kita.
            net_tcp_send_dupack(t);
            return 1;
        }

        uint32_t n = 0;
        int need_ack = dlen > 0;

        // C3d: data baru setelah FIN peer melanggar protokol; data setelah FIN
        // kita tidak punya pembaca (echo sudah menutup). Keduanya: RST.
        // D9: kecuali record TLS (close_notify balasan peer) setelah close_notify
        // + FIN kita: di-ACK lalu dibuang.
        if (t->tls && t->tls_closing && dlen > 0 &&
            (t->state == TCP_FIN_WAIT_1 || t->state == TCP_FIN_WAIT_2)) {
            n = dlen;
            t->rcv_nxt += n;
        } else if (t->state != TCP_ESTABLISHED && dlen > 0) {
            net_tcp_tcb_send(t, t->snd_nxt, TCP_RST | TCP_ACK, 0);
            g_tcp_rst_state++;
            net_tcp_close(t, "data di keadaan penutupan, RST");
            return 1;
        }

        if (t->state == TCP_ESTABLISHED && dlen > 0) {
            // Echo: data masuk langsung jadi data kirim, hanya sebanyak ruang
            // buffer (= jendela yang kita iklankan).
            if (t->tls) {
                n = tls_feed(t->tls - 1, buf + r + doff, dlen);   // D9: record
            } else if (t->app == TCP_APP_CLI) {
                n = net_tcp_cli_rx(t, buf + r + doff, dlen);
            } else {
                n = net_tcp_queue(t, buf + r + doff, dlen);
            }
            t->rcv_nxt += n;
            g_tcp_rx_bytes += n;
            if (n > 0) {
                t->last = timer_ticks;   // C5b: kemajuan
            }
            if (t->tls && !net_tcp_tls_pump(t)) {
                return 1;
            }
        }

        // FIN peer hanya berarti di ESTABLISHED/FIN_WAIT_1/FIN_WAIT_2; di
        // keadaan lain FIN peer sudah diterima (FIN baru dibalas ACK saja).
        if ((flags & TCP_FIN) && n == dlen) {
            need_ack = 1;
            if (t->state == TCP_ESTABLISHED || t->state == TCP_FIN_WAIT_1 ||
                t->state == TCP_FIN_WAIT_2) {
                t->last = timer_ticks;   // C5b: FIN peer pertama = kemajuan
            }
            if (t->state == TCP_ESTABLISHED) {
                t->rcv_nxt++;
                t->state = TCP_CLOSE_WAIT;
                net_tcp_log("FIN dari peer (CLOSE_WAIT)");
            } else if (t->state == TCP_FIN_WAIT_1) {
                t->rcv_nxt++;
                t->state = TCP_CLOSING;   // FIN kita belum di-ACK: tutup bersamaan
                net_tcp_log("FIN dari peer (CLOSING)");
            } else if (t->state == TCP_FIN_WAIT_2) {
                t->rcv_nxt++;
                t->state = TCP_TIME_WAIT;
                net_tcp_log("FIN dari peer (TIME_WAIT)");
            }
        }

        // Jendela terbuka lagi (ACK membebaskan buffer): kabari peer.
        if (t->adv_wnd < TCP_MSS && net_tcp_rcv_wnd(t) >= TCP_MSS) {
            need_ack = 1;
        }

        if (!net_tcp_output(t) && need_ack) {
            net_tcp_tcb_send(t, t->snd_nxt, TCP_ACK, 0);
        }

        return 1;
    }

    if (((dport == NET_TCP_ECHO_PORT && g_net_echo) ||
         (dport == NET_TCP_CLI_PORT && g_cli_plain) ||
         (dport == NET_TCP_TLS_PORT && tls_enabled())) &&
        (flags & TCP_SYN) &&
        !(flags & (TCP_ACK | TCP_RST))) {
        uint32_t same_ip = 0, cli_n = 0;
        tcp_tcb_t *victim = 0, *cli_victim = 0;

        for (uint32_t k = 0; k < TCP_MAX_CONN; k++) {
            tcp_tcb_t *e = &g_tcbs[k];
            int eq = 1;

            if (e->state == TCP_CLOSED) {
                if (t == 0) {
                    t = e;
                }
                continue;
            }
            for (int i = 0; i < 4; i++) {
                if (e->ip[i] != buf[26 + i]) {
                    eq = 0;
                }
            }
            same_ip += eq;
            if (e->state == TCP_SYN_RCVD &&
                (victim == 0 || e->last < victim->last)) {
                victim = e;
            }
            if (e->app == TCP_APP_CLI && e->lport == dport) {   // D9: per port
                cli_n++;
                if (e->state == TCP_SYN_RCVD &&
                    (cli_victim == 0 || e->last < cli_victim->last)) {
                    cli_victim = e;
                }
            }
        }
        // C5a: batas per IP dicek sebelum penggusuran, jadi satu IP tidak
        // bisa menggusur koneksi setengah terbuka milik IP lain berulang-ulang.
        if (same_ip >= TCP_MAX_PER_IP) {
            g_tcp_src_full++;
            return 0;
        }
        // D4: sesi CLI penuh: hanya SYN_RCVD CLI yang boleh digusur.
        if (dport != NET_TCP_ECHO_PORT &&
            cli_n >= (dport == NET_TCP_TLS_PORT ? TLS_MAX_SESS : TCP_CLI_MAX)) {
            if (cli_victim == 0) {
                g_cli_sess_full++;
                return 0;
            }
            t = 0;
            victim = cli_victim;
        }
        if (t == 0 && victim == 0) {
            g_tcp_busy++;
            return 0;
        }

        uint8_t isn[20];   // D1: 4 byte ISN + 16 byte nonce login

        // F1.8: tanpa entropi cukup SYN dibuang (bukan RST); peer mengulang.
        if (!entropy_get(isn, sizeof(isn))) {
            g_tcp_noentropy++;
            net_tcp_log("SYN dibuang: entropi belum cukup");
            return 1;
        }
        // C5a: tabel penuh: SYN_RCVD tertua digusur tanpa RST dan tanpa log
        // serial (banjir SYN tidak boleh membebani UART, lihat B4b).
        if (t == 0) {
            ktimer_cancel(TCB_TIMER(victim));
            net_tcp_tls_release(victim);
            victim->state = TCP_CLOSED;
            g_tcp_synrcvd_evicted++;
            t = victim;
        }

        // D9: slot TLS (pool = batas TCB 7780, jadi penuh hanya bila ada bug).
        int tls_slot = -1;

        if (dport == NET_TCP_TLS_PORT) {
            tls_slot = tls_open();
            if (tls_slot == -3) {
                net_tcp_log("SYN 7780 dibuang: entropi belum cukup");
                return 1;
            }
            if (tls_slot < 0) {
                return 0;
            }
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
        t->rto = TCP_RTO_INIT;
        t->retries = 0;
        t->fin_sent = 0;
        t->app = dport == NET_TCP_ECHO_PORT ? TCP_APP_ECHO : TCP_APP_CLI;
        t->tls = tls_slot + 1;
        t->tls_banner = 0;
        t->tls_closing = 0;
        t->cli_authed = 0;
        t->role = AUTH_ROLE_NONE;
        t->cli_last = 0;
        t->close_after = 0;
        t->line_len = 0;
        t->cmd_seq = 0;
        t->reboot_after = 0;
        t->out_len = 0;
        t->out_pos = 0;
        for (int i = 0; i < 16; i++) {
            t->nonce[i] = isn[4 + i];
        }
        t->state = TCP_SYN_RCVD;
        net_tcp_tcb_send(t, t->iss, TCP_SYN | TCP_ACK, 1);
        net_tcp_rtx_arm(t);
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

    // C4: koneksi aktif memakai batas per koneksi; segmen lain (SYN, port
    // tertutup) tetap memakai batas per IP + global seperti UDP.
    tcp_tcb_t *conn = net_tcp_find(buf, r);

    if (conn) {
        if (!net_tcp_conn_budget_ok(conn)) {
            return;
        }
    } else {
        if (!net_udp_src_budget_ok(buf + 26)) {
            return;
        }

        if (!net_udp_budget_ok()) {
            return;
        }
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

    if (sntp_wants(buf + 26, (uint16_t)src_port, (uint16_t)dst_port)) {
        // P3-2: balasan SNTP yang sedang ditunggu (satu datagram, tanpa batas laju).
        if (csum != 0 &&
            net_udp_checksum(buf + 26, buf + 30, buf + r, udp_len) != 0) {
            g_net_udp_badsum++;
            return;
        }
        sntp_rx(buf + r + 8, udp_len - 8);
        return;
    }

    if (dns_wants(buf + 26, (uint16_t)src_port, (uint16_t)dst_port)) {
        // P3-3: balasan DNS yang sedang ditunggu (satu datagram, tanpa batas laju).
        if (csum != 0 &&
            net_udp_checksum(buf + 26, buf + 30, buf + r, udp_len) != 0) {
            g_net_udp_badsum++;
            return;
        }
        dns_rx(buf + r + 8, udp_len - 8);
        return;
    }

    if (dst_port != NET_UDP_ECHO_PORT && dst_port != NET_UDP_CMD_PORT) {
        return;
    }

    if (dst_port == NET_UDP_ECHO_PORT && !g_net_echo) {
        return;   // D7: echo=0
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

    if (!filter_ipv4(buf, ihl, total_len - ihl)) {
        return;   // P4: dibuang aturan filter (dihitung di filter.c)
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

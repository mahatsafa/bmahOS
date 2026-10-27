// P3-4: uji klien DHCP (dhcp.c di-#include). NIC tiruan: frame keluar disalin;
// net_udp_build/net_arp_request_build tiruan mengisi field yang diperiksa;
// entropi deterministik.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/dhcp.c"

extern char g_serial_cap[];
void serial_capture_reset(void);

int g_e1000_rx_initialized = 1;
uint8_t g_e1000_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
uint8_t g_net_ip[4] = { 192, 168, 50, 200 };
uint64_t hhdm_offset = 0;

static uint8_t g_page[4096] __attribute__((aligned(4096)));
static int g_page_fail;
uint64_t pmm_alloc(void)
{
    return g_page_fail ? 0 : (uint64_t)(uintptr_t)g_page;
}

#define TXN 32
static uint8_t g_tx[TXN][400];
static uint32_t g_tx_len[TXN];
static int g_ntx;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_ntx < TXN) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 400 ? 400 : frame_len);
        g_tx_len[g_ntx] = frame_len;
        g_ntx++;
    }
    return 1;
}

// UDP tiruan: Ethernet tujuan, IP sumber (= g_net_ip saat kirim) dan tujuan, port.
uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;
    p[23] = 17;
    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = dst_ip[i];
    }
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)sport;
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)dport;
    return 42 + plen;
}

uint32_t net_arp_request_build(uint8_t *p, const volatile uint8_t *ip)
{
    memset(p, 0, 60);
    memset(p, 0xFF, 6);
    p[12] = 0x08;
    p[13] = 0x06;
    p[21] = 1;
    for (int i = 0; i < 4; i++) {
        p[28 + i] = g_net_ip[i];
        p[38 + i] = ip[i];
    }
    return 60;
}

static uint8_t g_ent_next = 0x40;
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

static int g_nc_changed, g_mon_changed;
void netcon_ip_changed(void)
{
    g_nc_changed++;
}

void monitor_ip_changed(void)
{
    g_mon_changed++;
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
    if (!dhcp_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

static const uint8_t SRV[4] = { 192, 168, 50, 1 };
static const uint8_t SRV2[4] = { 192, 168, 50, 2 };
static const uint8_t YI[4] = { 192, 168, 50, 77 };
static const uint8_t DNS2[8] = { 192, 168, 50, 53, 8, 8, 8, 8 };   // dua server DNS
static const uint8_t M24[4] = { 255, 255, 255, 0 };
static const uint8_t M16[4] = { 255, 255, 0, 0 };
static const uint8_t ZERO4[4] = { 0, 0, 0, 0 };
static const uint8_t OTHER_MAC[6] = { 0x02, 0, 0, 0, 0, 0x99 };

// ---- frame keluar ----
static const uint8_t *tx_bootp(int i)
{
    return g_tx[i] + 42;
}

static uint32_t tx_xid(int i)
{
    const uint8_t *d = tx_bootp(i);
    return (uint32_t)d[4] << 24 | (uint32_t)d[5] << 16 | (uint32_t)d[6] << 8 | d[7];
}

// Panjang option code di pesan BOOTP frame i (v = isinya), -1 bila tidak ada.
static int tx_opt(int i, uint8_t code, const uint8_t **v)
{
    const uint8_t *d = tx_bootp(i);
    uint32_t n = g_tx_len[i] - 42;

    for (uint32_t k = 240; k < n && d[k] != 255;) {
        if (d[k] == 0) {
            k++;
            continue;
        }
        if (d[k] == code) {
            *v = d + k + 2;
            return d[k + 1];
        }
        k += 2u + d[k + 1];
    }
    return -1;
}

static int tx_type(int i)
{
    const uint8_t *v;
    return tx_opt(i, 53, &v) == 1 ? v[0] : -1;
}

// ---- balasan server ----
static uint8_t g_rep[600];
static uint32_t g_rl;

static void rep_begin(uint32_t xid, const uint8_t yi[4])
{
    memset(g_rep, 0, sizeof(g_rep));
    g_rep[0] = 2;
    g_rep[1] = 1;
    g_rep[2] = 6;
    g_rep[4] = (uint8_t)(xid >> 24);
    g_rep[5] = (uint8_t)(xid >> 16);
    g_rep[6] = (uint8_t)(xid >> 8);
    g_rep[7] = (uint8_t)xid;
    memcpy(g_rep + 16, yi, 4);
    memcpy(g_rep + 28, g_e1000_mac, 6);
    g_rep[236] = 99;
    g_rep[237] = 130;
    g_rep[238] = 83;
    g_rep[239] = 99;
    g_rl = 240;
}

static void rep_opt(uint8_t c, uint8_t l, const uint8_t *v)
{
    g_rep[g_rl++] = c;
    g_rep[g_rl++] = l;
    memcpy(g_rep + g_rl, v, l);
    g_rl += l;
}

// OFFER/ACK/NAK lengkap; mask/lease/srv = 0 -> option tidak disertakan.
static void rep_std(uint8_t type, uint32_t xid, const uint8_t yi[4], const uint8_t *srv,
                    const uint8_t *mask, uint32_t lease)
{
    uint8_t t[1] = { type };
    uint8_t l4[4] = { (uint8_t)(lease >> 24), (uint8_t)(lease >> 16), (uint8_t)(lease >> 8),
                      (uint8_t)lease };

    rep_begin(xid, yi);
    rep_opt(53, 1, t);
    if (srv) {
        rep_opt(54, 4, srv);
    }
    if (lease) {
        rep_opt(51, 4, l4);
    }
    if (mask) {
        rep_opt(1, 4, mask);
    }
    rep_opt(3, 4, SRV);
    rep_opt(6, 8, DNS2);
    g_rep[g_rl++] = 255;
}

static void send_rep(void)
{
    dhcp_rx(g_rep, g_rl);
}

static void arp_from(const uint8_t mac[6], const uint8_t ip[4])
{
    uint8_t f[60] = { 0 };
    memcpy(f + 22, mac, 6);
    memcpy(f + 28, ip, 4);
    dhcp_arp_seen(f);
}

static void reset(int on)
{
    static const uint8_t ip200[4] = { 192, 168, 50, 200 };

    memcpy(g_net_ip, ip200, 4);
    g_dhcp_cfg = (uint32_t)on;
    g_dh_state = DH_OFF;
    g_dh_t1 = g_dh_t2 = g_dh_end = 0;
    g_dhcp_tx = g_dhcp_offers = g_dhcp_acks = g_dhcp_naks = g_dhcp_declines = g_dhcp_bad = 0;
    g_ntx = 0;
    g_ent_fail = 0;
    g_nc_changed = g_mon_changed = 0;
    timer_ticks = 1000;
    dhcp_prepare();
    dhcp_init();
}

// Dari mulai sampai terikat ke YI (sewa lease); return 1 bila terikat.
static int bind_to(uint32_t lease)
{
    reset(1);
    dhcp_poll();                                   // DISCOVER
    if (g_ntx != 1) {
        return 0;
    }
    rep_std(DH_OFFER, tx_xid(0), YI, SRV, M24, lease);
    send_rep();                                    // -> REQUEST
    rep_std(DH_ACK, tx_xid(1), YI, SRV, M24, lease);
    send_rep();                                    // -> cek ARP
    timer_ticks += DH_CHECK_WAIT;
    dhcp_poll();
    return g_dh_state == DH_BOUND && memcmp(g_net_ip, YI, 4) == 0;
}

static void test_off(void)
{
    reset(0);
    CHECK(g_dh_state == DH_OFF && g_net_ip[3] == 200 && !dhcp_waiting());
    dhcp_poll();
    CHECK(g_ntx == 0);
    CHECK_STR(run("dhcp"), "dhcp: mode=statis ip=192.168.50.200/24\n");
    g_dhcp_cfg = 1;                                // `set dhcp 1` saat berjalan
    CHECK_STR(run("dhcp"), "dhcp: mode=statis (dhcp=1 berlaku setelah reboot) ip=192.168.50.200/24\n");
    CHECK_STR(run("dhcpx"), "(tidak ditangani)");
}

static void test_discover(void)
{
    serial_capture_reset();
    reset(1);
    CHECK(g_dh_state == DH_INIT && memcmp(g_net_ip, ZERO4, 4) == 0);
    CHECK(strstr(g_serial_cap, "P3: DHCP mulai (IP 0.0.0.0 sampai terikat, maks 30 s)\r\n") != 0);
    g_ent_fail = 1;
    dhcp_poll();                                   // entropi belum siap: tunggu
    CHECK(g_ntx == 0 && g_dh_state == DH_INIT);
    g_ent_fail = 0;
    timer_ticks += 100;
    g_ent_next = 0x40;
    dhcp_poll();
    CHECK(g_ntx == 1 && g_dh_state == DH_SELECT && dhcp_waiting());

    const uint8_t *f = g_tx[0], *d = tx_bootp(0), *v;
    static const uint8_t bcast[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    CHECK(memcmp(f, bcast, 6) == 0 && memcmp(f + 26, ZERO4, 4) == 0 && f[30] == 255 &&
          f[33] == 255 && f[35] == 68 && f[37] == 67 && g_tx_len[0] == 42 + 300);
    CHECK(d[0] == 1 && d[1] == 1 && d[2] == 6 && tx_xid(0) == 0x40414243 && d[10] == 0x80 &&
          memcmp(d + 12, ZERO4, 4) == 0 && memcmp(d + 28, g_e1000_mac, 6) == 0);
    CHECK(d[236] == 99 && d[237] == 130 && d[238] == 83 && d[239] == 99);
    CHECK(tx_type(0) == DH_DISCOVER && tx_opt(0, 50, &v) == -1 && tx_opt(0, 54, &v) == -1);
    CHECK(tx_opt(0, 55, &v) == 4 && v[0] == 1 && v[1] == 3 && v[2] == 6 && v[3] == 51);
    CHECK(tx_opt(0, 12, &v) == 6 && memcmp(v, "bmahos", 6) == 0);

    // Tanpa OFFER: DISCOVER ulang 2 s, 4 s, 8 s, ... dengan xid baru.
    timer_ticks += 199;
    dhcp_poll();
    CHECK(g_ntx == 1);
    timer_ticks += 1;
    dhcp_poll();
    CHECK(g_ntx == 2 && tx_type(1) == DH_DISCOVER && tx_xid(1) != tx_xid(0));
    timer_ticks += 400;
    dhcp_poll();
    CHECK(g_ntx == 3);
    timer_ticks += 799;
    dhcp_poll();
    CHECK(g_ntx == 3);
    timer_ticks += 1;
    dhcp_poll();
    CHECK(g_ntx == 4);
}

static void test_offers_rejected(void)
{
    reset(1);
    dhcp_poll();
    uint32_t x = tx_xid(0);
    static const uint8_t Y127[4] = { 127, 0, 0, 5 }, Y255[4] = { 192, 168, 50, 255 };

    rep_std(DH_OFFER, x + 1, YI, SRV, M24, 3600);  // xid lain
    send_rep();
    rep_std(DH_OFFER, x, YI, SRV, M24, 3600);      // chaddr lain
    g_rep[33] ^= 1;
    send_rep();
    rep_std(DH_OFFER, x, YI, SRV, M24, 3600);      // op 1
    g_rep[0] = 1;
    send_rep();
    rep_std(DH_OFFER, x, YI, SRV, M24, 3600);      // cookie salah
    g_rep[239] = 0;
    send_rep();
    rep_std(DH_OFFER, x, YI, 0, M24, 3600);        // tanpa server
    send_rep();
    CHECK(strcmp(g_dh_last, "ditolak: tanpa server (54)") == 0);
    rep_std(DH_OFFER, x, YI, SRV, M16, 3600);      // mask /16
    send_rep();
    CHECK(strcmp(g_dh_last, "ditolak: mask bukan /24") == 0);
    rep_std(DH_OFFER, x, YI, SRV, 0, 3600);        // tanpa mask
    send_rep();
    rep_std(DH_OFFER, x, YI, SRV, M24, 0);         // tanpa sewa
    send_rep();
    rep_std(DH_OFFER, x, Y127, SRV, M24, 3600);    // loopback
    send_rep();
    rep_std(DH_OFFER, x, Y255, SRV, M24, 3600);    // oktet 255
    send_rep();
    rep_std(DH_OFFER, x, YI, SRV, M24, 3600);      // option melewati ujung
    g_rep[g_rl - 1] = 6;
    g_rep[g_rl - 2] = 200;
    send_rep();
    CHECK(strcmp(g_dh_last, "ditolak: option melewati ujung") == 0);
    dhcp_rx(g_rep, 239);                           // terlalu pendek
    CHECK(g_ntx == 1 && g_dh_state == DH_SELECT && g_dhcp_bad == 12 && g_dhcp_offers == 0);
    rep_std(DH_ACK, x, YI, SRV, M24, 3600);        // ACK tanpa REQUEST
    send_rep();
    CHECK(g_dh_state == DH_SELECT && g_dhcp_bad == 13);
}

static void test_bind(void)
{
    const uint8_t *v;

    reset(1);
    dhcp_poll();
    uint32_t x = tx_xid(0);
    rep_std(DH_OFFER, x, YI, SRV, M24, 3600);
    send_rep();
    CHECK(g_ntx == 2 && g_dh_state == DH_REQUEST && dhcp_waiting() && g_dhcp_offers == 1);
    const uint8_t *d = tx_bootp(1);
    CHECK(tx_type(1) == DH_REQUEST_MSG && tx_xid(1) == x && d[10] == 0x80 &&
          memcmp(d + 12, ZERO4, 4) == 0 && memcmp(g_tx[1] + 26, ZERO4, 4) == 0);
    CHECK(tx_opt(1, 50, &v) == 4 && memcmp(v, YI, 4) == 0 && tx_opt(1, 54, &v) == 4 &&
          memcmp(v, SRV, 4) == 0 && tx_opt(1, 55, &v) == 4);

    rep_std(DH_OFFER, x, YI, SRV2, M24, 3600);     // OFFER kedua: diabaikan
    send_rep();
    static const uint8_t Y78[4] = { 192, 168, 50, 78 };
    rep_std(DH_ACK, x, Y78, SRV, M24, 3600);       // alamat lain
    send_rep();
    rep_std(DH_ACK, x, YI, SRV2, M24, 3600);       // server lain
    send_rep();
    CHECK(g_dh_state == DH_REQUEST && g_ntx == 2 && g_dhcp_bad == 3);

    serial_capture_reset();
    rep_std(DH_ACK, x, YI, SRV, M24, 3600);
    send_rep();
    CHECK(g_dh_state == DH_CHECK && !dhcp_waiting() && memcmp(g_net_ip, ZERO4, 4) == 0);
    CHECK(g_ntx == 3 && g_tx[2][13] == 0x06 && memcmp(g_tx[2] + 28, ZERO4, 4) == 0 &&
          memcmp(g_tx[2] + 38, YI, 4) == 0);      // probe ARP, pengirim 0.0.0.0
    static const uint8_t OTHER_IP[4] = { 192, 168, 50, 9 };
    arp_from(OTHER_MAC, OTHER_IP);                 // IP lain: bukan bentrok
    arp_from(g_e1000_mac, YI);                     // MAC sendiri: bukan bentrok
    timer_ticks += DH_CHECK_WAIT - 1;
    dhcp_poll();
    CHECK(g_dh_state == DH_CHECK);
    timer_ticks += 1;
    dhcp_poll();
    CHECK(g_dh_state == DH_BOUND && memcmp(g_net_ip, YI, 4) == 0 && g_nc_changed == 1 &&
          g_mon_changed == 1 && g_dhcp_acks == 1);
    CHECK(strstr(g_serial_cap, "P3: DHCP terikat 192.168.50.77/24 dari 192.168.50.1 sewa 3600 s "
                               "router 192.168.50.1 dns 192.168.50.53\r\n") != 0);
    CHECK_STR(run("dhcp"), "dhcp: mode=dhcp keadaan=terikat ip=192.168.50.77/24 server=192.168.50.1 "
              "sewa=3600 s sisa=3600 s router=192.168.50.1 dns=192.168.50.53\n"
              "dhcp: kirim=2 tawaran=1 ack=1 nak=0 decline=0 diabaikan=3 terakhir=terikat\n");
    g_dhcp_cfg = 0;
    CHECK(strncmp(run("dhcp"), "dhcp: mode=dhcp (dhcp=0 berlaku setelah reboot) keadaan=terikat", 63) == 0);
    rep_std(DH_ACK, x, YI, SRV, M24, 3600);        // sesudah terikat: tidak menunggu
    CHECK(!dhcp_waiting());
}

static void test_conflict_and_nak(void)
{
    const uint8_t *v;

    reset(1);
    dhcp_poll();
    rep_std(DH_OFFER, tx_xid(0), YI, SRV, M24, 3600);
    send_rep();
    rep_std(DH_ACK, tx_xid(1), YI, SRV, M24, 3600);
    send_rep();
    serial_capture_reset();
    arp_from(OTHER_MAC, YI);                       // alamat sudah dipakai
    CHECK(g_dh_state == DH_INIT && g_dhcp_declines == 1 && memcmp(g_net_ip, ZERO4, 4) == 0);
    CHECK(g_ntx == 4 && tx_type(3) == DH_DECLINE && tx_opt(3, 50, &v) == 4 &&
          memcmp(v, YI, 4) == 0 && tx_opt(3, 54, &v) == 4 && tx_opt(3, 55, &v) == -1);
    CHECK(strstr(g_serial_cap, "P3: DHCP alamat 192.168.50.77 sudah dipakai 02:00:00:00:00:99 -> "
                               "DECLINE\r\n") != 0);
    timer_ticks += DH_DECLINE_WAIT - 1;
    dhcp_poll();
    CHECK(g_ntx == 4);                             // tunggu >= 10 s
    timer_ticks += 1;
    dhcp_poll();
    CHECK(g_ntx == 5 && tx_type(4) == DH_DISCOVER);

    // NAK dari server yang dipilih saat REQUEST -> DISCOVER lagi langsung.
    rep_std(DH_OFFER, tx_xid(4), YI, SRV, M24, 3600);
    send_rep();
    rep_std(DH_NAK, tx_xid(5), ZERO4, SRV2, 0, 0); // server lain: diabaikan
    send_rep();
    CHECK(g_dh_state == DH_REQUEST);
    rep_std(DH_NAK, tx_xid(5), ZERO4, SRV, 0, 0);
    send_rep();
    CHECK(g_dh_state == DH_INIT && g_dhcp_naks == 1);
    dhcp_poll();
    CHECK(g_ntx == 7 && tx_type(6) == DH_DISCOVER);
}

static void test_renew(void)
{
    const uint8_t *v;

    CHECK(bind_to(120));                           // T1 60 s, T2 105 s, habis 120 s
    uint64_t t0 = timer_ticks;
    int n0 = g_ntx;
    timer_ticks = t0 + 5999;
    dhcp_poll();
    CHECK(g_ntx == n0 && g_dh_state == DH_BOUND);
    timer_ticks = t0 + 6000;
    dhcp_poll();                                   // T1: REQUEST perpanjangan
    CHECK(g_dh_state == DH_RENEW && dhcp_waiting() && g_ntx == n0 + 1);
    const uint8_t *d = tx_bootp(n0);
    CHECK(tx_type(n0) == DH_REQUEST_MSG && memcmp(d + 12, YI, 4) == 0 && d[10] == 0 &&
          memcmp(g_tx[n0] + 26, YI, 4) == 0 && tx_opt(n0, 50, &v) == -1 && tx_opt(n0, 54, &v) == -1);
    timer_ticks = t0 + 6999;
    dhcp_poll();
    CHECK(g_ntx == n0 + 1);
    timer_ticks = t0 + 7000;
    dhcp_poll();                                   // ulang tiap 10 s
    CHECK(g_ntx == n0 + 2 && tx_xid(n0 + 1) != tx_xid(n0));

    // ACK: sewa baru 600 s dari sekarang.
    serial_capture_reset();
    rep_std(DH_ACK, tx_xid(n0 + 1), YI, SRV, M24, 600);
    send_rep();
    CHECK(g_dh_state == DH_BOUND && g_dh_lease == 600 && g_dh_t1 == timer_ticks + 30000 &&
          g_dh_end == timer_ticks + 60000 && g_nc_changed == 1);
    CHECK(strstr(g_serial_cap, "P3: DHCP diperpanjang 192.168.50.77 dari 192.168.50.1 sewa 600 s\r\n") != 0);

    // Tanpa ACK: T2 -> ikat-ulang (broadcast sama), sewa habis -> IP dilepas.
    uint64_t t1 = timer_ticks;
    timer_ticks = t1 + 30000;
    dhcp_poll();
    CHECK(g_dh_state == DH_RENEW);
    timer_ticks = t1 + 52500;
    dhcp_poll();
    CHECK(g_dh_state == DH_REBIND && dhcp_waiting());
    serial_capture_reset();
    timer_ticks = t1 + 60000;
    dhcp_poll();
    CHECK(g_dh_state == DH_INIT && memcmp(g_net_ip, ZERO4, 4) == 0);
    CHECK(strstr(g_serial_cap, "P3: DHCP sewa habis -> IP 192.168.50.77 dilepas, DISCOVER lagi\r\n") != 0);
    int n1 = g_ntx;
    dhcp_poll();
    CHECK(g_ntx == n1 + 1 && tx_type(n1) == DH_DISCOVER && memcmp(g_tx[n1] + 26, ZERO4, 4) == 0);

    // NAK dan ACK dengan alamat lain saat perpanjangan -> IP dilepas.
    CHECK(bind_to(120));
    timer_ticks += 6000;
    dhcp_poll();
    rep_std(DH_NAK, tx_xid(g_ntx - 1), ZERO4, SRV, 0, 0);
    send_rep();
    CHECK(g_dh_state == DH_INIT && memcmp(g_net_ip, ZERO4, 4) == 0 && g_dhcp_naks == 1);
    CHECK(bind_to(120));
    timer_ticks += 6000;
    dhcp_poll();
    static const uint8_t Y78[4] = { 192, 168, 50, 78 };
    rep_std(DH_ACK, tx_xid(g_ntx - 1), Y78, SRV, M24, 120);
    send_rep();
    CHECK(g_dh_state == DH_INIT && memcmp(g_net_ip, ZERO4, 4) == 0);
}

static void test_lease_limits_and_fallback(void)
{
    CHECK(bind_to(10));                            // < 60 s -> 60 s
    CHECK(g_dh_lease == 60 && g_dh_t1 == timer_ticks + 3000);
    CHECK(bind_to(0xFFFFFFFFu));                   // tanpa batas: tidak pernah diperpanjang
    CHECK(g_dh_t1 == 0 && g_dh_end == 0);
    CHECK(strstr(run("dhcp"), " sewa=tanpa-batas sisa=0 s ") != 0);
    int n0 = g_ntx;
    timer_ticks += 100000000;
    dhcp_poll();
    CHECK(g_ntx == n0 && g_dh_state == DH_BOUND);

    // Tanpa server: 30 s -> IP statis, DHCP berhenti.
    serial_capture_reset();
    reset(1);
    for (int i = 0; i < 400 && g_dh_state != DH_STATIC; i++) {
        dhcp_poll();
        timer_ticks += 10;
    }
    CHECK(g_dh_state == DH_STATIC && g_net_ip[3] == 200 && g_nc_changed == 1 && g_ntx == 5);
    CHECK(timer_ticks >= 1000 + DH_BOOT_MAX && timer_ticks <= 1000 + DH_BOOT_MAX + 10);
    CHECK(strstr(g_serial_cap, "P3: DHCP tanpa sewa dalam 30 s -> IP statis 192.168.50.200 (DHCP "
                               "berhenti sampai reboot)\r\n") != 0);
    n0 = g_ntx;
    timer_ticks += 100000;
    dhcp_poll();
    CHECK(g_ntx == n0 && !dhcp_waiting());
    CHECK(strncmp(run("dhcp"), "dhcp: mode=dhcp keadaan=statis ip=192.168.50.200/24", 51) == 0);

    // Tanpa halaman TX: langsung IP statis.
    g_page_fail = 1;
    g_dh_page_phys = 0;
    reset(1);
    CHECK(g_dh_state == DH_STATIC && g_net_ip[3] == 200);
    g_page_fail = 0;
    g_dh_page_phys = 0;
}

int main(void)
{
    test_off();
    test_discover();
    test_offers_rejected();
    test_bind();
    test_conflict_and_nak();
    test_renew();
    test_lease_limits_and_fallback();
    return test_done("dhcp");
}

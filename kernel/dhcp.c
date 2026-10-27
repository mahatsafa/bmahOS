#include "kernel.h"

// P3-4: klien DHCP (RFC 2131) untuk IPv4 /24, hanya bila CONFIG.CFG dhcp=1
// (bawaan 0 = IP statis 192.168.50.200 seperti sebelumnya; perubahan berlaku
// setelah reboot). dhcp=1: IP dikosongkan (0.0.0.0) sebelum paket IP pertama;
// tanpa IP bmahOS tidak menjawab ARP dan hanya menerima balasan DHCP.
// DISCOVER (broadcast, xid acak, flag BROADCAST) -> OFFER -> REQUEST (alamat +
// server dari OFFER) -> ACK -> probe ARP alamat itu (pengirim 0.0.0.0, tunggu
// 1 s; ada yang memakai -> DECLINE, mulai lagi 10 s kemudian) -> terikat.
// Balasan hanya diterima dari UDP 67 ke 68 dengan op=2, Ethernet/6, xid kita,
// chaddr = MAC kita, magic cookie, option 53 (jenis) dan 54 (server); OFFER/ACK
// juga wajib membawa sewa (51) dan mask 255.255.255.0 (bmahOS hanya /24), dengan
// alamat bukan 0.x/127.x/>=224.x dan oktet terakhir 1..254. Option overload (52)
// tidak didukung (sname/file tidak dibaca). Sewa < 60 s dianggap 60 s,
// 0xFFFFFFFF = tanpa batas; T1 = sewa/2, T2 = sewa*7/8 (option 58/59 diabaikan).
// Perpanjangan: REQUEST dengan ciaddr tiap 10 s mulai T1, broadcast (RFC:
// unicast saat RENEWING; broadcast tetap dilayani server dan tidak butuh MAC
// server). ACK dengan alamat lain, NAK, atau sewa habis -> IP dilepas, mulai
// lagi dari DISCOVER. Belum terikat 30 s sejak mulai -> IP statis
// 192.168.50.200 dan DHCP berhenti sampai reboot (perangkat tetap bisa
// dicapai). Router dan DNS dari server hanya dicatat (bmahOS tidak me-routing).

#define DH_MIN_LEN      300     // panjang pesan BOOTP minimal (RFC 1542)
#define DH_OPT_OFF      240     // option sesudah magic cookie
#define DH_BOOT_MAX     3000    // tick: belum terikat sejak mulai -> IP statis
#define DH_REQ_WAIT     400     // tick menunggu ACK
#define DH_RENEW_EVERY  1000    // tick antar REQUEST perpanjangan
#define DH_CHECK_WAIT   100     // tick menunggu jawaban probe ARP
#define DH_DECLINE_WAIT 1000    // tick sesudah DECLINE (RFC 2131: >= 10 s)
#define DH_LEASE_MIN    60      // detik
#define DH_INFINITE     0xFFFFFFFFu

enum { DH_DISCOVER = 1, DH_OFFER, DH_REQUEST_MSG, DH_DECLINE, DH_ACK, DH_NAK };
enum { DH_OFF, DH_INIT, DH_SELECT, DH_REQUEST, DH_CHECK, DH_BOUND, DH_RENEW, DH_REBIND, DH_STATIC };
static const char *const g_dh_state_name[] = { "mati", "mulai", "pilih", "minta", "cek-arp",
                                               "terikat", "perpanjang", "ikat-ulang", "statis" };

uint32_t g_dhcp_cfg;   // CONFIG.CFG dhcp (config.c), dibaca dhcp_prepare saat boot
static const uint8_t g_dh_static[4] = { 192, 168, 50, 200 };
static int g_dh_state = DH_OFF;
static uint32_t g_dh_xid, g_dh_tries, g_dh_lease;
static uint64_t g_dh_at, g_dh_start, g_dh_t1, g_dh_t2, g_dh_end;
static uint8_t g_dh_offer[4], g_dh_server[4], g_dh_router[4], g_dh_dns[4];
static uint64_t g_dh_page_phys;
static char g_dh_last[64] = "-";
uint64_t g_dhcp_tx, g_dhcp_offers, g_dhcp_acks, g_dhcp_naks, g_dhcp_declines, g_dhcp_bad;

static uint32_t dh_get32(const volatile uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static int dh_eq(const volatile uint8_t *a, const volatile uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static void dh_cpy4(uint8_t *dst, const volatile uint8_t *src)
{
    for (int i = 0; i < 4; i++) {
        dst[i] = src[i];
    }
}

// Satu-satunya tempat IP diubah sesudah boot. IP baru (bukan 0.0.0.0): MAC yang
// dipelajari netcon/pantau dilupakan (prefiks /24 bisa berganti).
static void dh_set_ip(const uint8_t ip[4])
{
    if (dh_eq(g_net_ip, ip, 4)) {
        return;
    }
    memcpy(g_net_ip, ip, 4);
    if (ip[0] | ip[1] | ip[2] | ip[3]) {
        netcon_ip_changed();
        monitor_ip_changed();
    }
}

// Dari e1000_probe_and_log sesudah config_load, sebelum paket IP pertama.
void dhcp_prepare(void)
{
    static const uint8_t zero[4] = { 0, 0, 0, 0 };

    if (!g_dhcp_cfg) {
        g_dh_state = DH_OFF;
        return;
    }
    memcpy(g_net_ip, zero, 4);
    g_dh_state = DH_INIT;
}

static void dh_fallback(void)
{
    g_dh_state = DH_STATIC;
    dh_set_ip(g_dh_static);
    ksnprintf(g_dh_last, sizeof(g_dh_last), "tanpa sewa 30 s, IP statis");
    kprintf("P3: DHCP tanpa sewa dalam 30 s -> IP statis %u.%u.%u.%u (DHCP berhenti sampai "
            "reboot)\r\n", g_dh_static[0], g_dh_static[1], g_dh_static[2], g_dh_static[3]);
}

// Net task, sebelum modul jaringan lain.
void dhcp_init(void)
{
    if (g_dh_state != DH_INIT) {
        return;
    }
    if (g_dh_page_phys == 0) {
        g_dh_page_phys = pmm_alloc();
    }
    if (!g_e1000_rx_initialized || g_dh_page_phys == 0) {
        dh_fallback();
        return;
    }
    g_dh_start = timer_ticks;
    g_dh_at = timer_ticks;
    g_dh_tries = 0;
    kprintf("P3: DHCP mulai (IP 0.0.0.0 sampai terikat, maks 30 s)\r\n");
}

// Pesan BOOTREQUEST jenis type di p+42 lalu kirim (broadcast, 68 -> 67).
static void dh_send(uint8_t type)
{
    static const uint8_t bcast_mac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    static const uint8_t bcast_ip[4] = { 255, 255, 255, 255 };
    static const uint8_t opts[] = { 55, 4, 1, 3, 6, 51,                       // mask router dns sewa
                                    12, 6, 'b', 'm', 'a', 'h', 'o', 's' };   // nama host
    uint8_t *p = (uint8_t *)(g_dh_page_phys + hhdm_offset);
    uint8_t *d = p + 42;
    int renew = g_dh_state == DH_RENEW || g_dh_state == DH_REBIND;
    uint32_t n = DH_OPT_OFF;

    memset(d, 0, DH_MIN_LEN);
    d[0] = 1;   // BOOTREQUEST
    d[1] = 1;   // Ethernet
    d[2] = 6;
    d[4] = (uint8_t)(g_dh_xid >> 24);
    d[5] = (uint8_t)(g_dh_xid >> 16);
    d[6] = (uint8_t)(g_dh_xid >> 8);
    d[7] = (uint8_t)g_dh_xid;
    if (renew) {
        memcpy(d + 12, g_net_ip, 4);   // ciaddr
    } else {
        d[10] = 0x80;                  // BROADCAST: IP belum dipakai
    }
    memcpy(d + 28, g_e1000_mac, 6);
    d[236] = 99;
    d[237] = 130;
    d[238] = 83;
    d[239] = 99;
    d[n++] = 53;
    d[n++] = 1;
    d[n++] = type;
    if (type == DH_DECLINE || (type == DH_REQUEST_MSG && !renew)) {
        d[n++] = 50;   // alamat yang diminta/ditolak
        d[n++] = 4;
        memcpy(d + n, g_dh_offer, 4);
        n += 4;
        d[n++] = 54;   // server
        d[n++] = 4;
        memcpy(d + n, g_dh_server, 4);
        n += 4;
    }
    if (type != DH_DECLINE) {
        memcpy(d + n, opts, sizeof(opts));
        n += sizeof(opts);
    }
    d[n++] = 255;
    g_dhcp_tx++;
    e1000_tx_send(g_dh_page_phys, net_udp_build(p, bcast_mac, bcast_ip, 68, 67,
                                                n < DH_MIN_LEN ? DH_MIN_LEN : n));
}

static int dh_new_xid(void)
{
    uint8_t r[4];

    if (!entropy_get(r, sizeof(r))) {
        return 0;
    }
    g_dh_xid = (uint32_t)r[0] << 24 | (uint32_t)r[1] << 16 | (uint32_t)r[2] << 8 | r[3];
    return 1;
}

static void dh_lease_times(uint64_t now)
{
    if (g_dh_lease == DH_INFINITE) {
        g_dh_t1 = g_dh_t2 = g_dh_end = 0;
        return;
    }
    g_dh_t1 = now + (uint64_t)g_dh_lease * 50;
    g_dh_t2 = now + (uint64_t)g_dh_lease * 700 / 8;
    g_dh_end = now + (uint64_t)g_dh_lease * 100;
}

static void dh_lease_str(char *out, uint32_t n)
{
    if (g_dh_lease == DH_INFINITE) {
        ksnprintf(out, n, "tanpa-batas");
    } else {
        ksnprintf(out, n, "%u s", g_dh_lease);
    }
}

static void dh_bind(void)
{
    char ls[24];

    dh_set_ip(g_dh_offer);
    dh_lease_times(timer_ticks);
    g_dh_state = DH_BOUND;
    dh_lease_str(ls, sizeof(ls));
    ksnprintf(g_dh_last, sizeof(g_dh_last), "terikat");
    kprintf("P3: DHCP terikat %u.%u.%u.%u/24 dari %u.%u.%u.%u sewa %s router %u.%u.%u.%u dns "
            "%u.%u.%u.%u\r\n", g_net_ip[0], g_net_ip[1], g_net_ip[2], g_net_ip[3], g_dh_server[0],
            g_dh_server[1], g_dh_server[2], g_dh_server[3], ls, g_dh_router[0], g_dh_router[1],
            g_dh_router[2], g_dh_router[3], g_dh_dns[0], g_dh_dns[1], g_dh_dns[2], g_dh_dns[3]);
}

// Sewa hilang (NAK, sewa habis, alamat lain): IP dilepas, DISCOVER lagi.
static void dh_restart(const char *why)
{
    static const uint8_t zero[4] = { 0, 0, 0, 0 };

    kprintf("P3: DHCP %s -> IP %u.%u.%u.%u dilepas, DISCOVER lagi\r\n", why, g_net_ip[0],
            g_net_ip[1], g_net_ip[2], g_net_ip[3]);
    ksnprintf(g_dh_last, sizeof(g_dh_last), "%s", why);
    dh_set_ip(zero);
    g_dh_state = DH_INIT;
    g_dh_start = timer_ticks;
    g_dh_at = timer_ticks;
    g_dh_tries = 0;
    g_dh_t1 = g_dh_t2 = g_dh_end = 0;
}

void dhcp_poll(void)
{
    uint64_t now = timer_ticks;

    switch (g_dh_state) {
    case DH_INIT:
    case DH_SELECT:
    case DH_REQUEST:
        if (now - g_dh_start >= DH_BOOT_MAX) {
            dh_fallback();
            return;
        }
        if (now < g_dh_at) {
            return;   // menunggu OFFER/ACK, atau jeda sesudah DECLINE
        }
        if (!dh_new_xid()) {
            g_dh_at = now + 100;   // entropi belum siap
            return;
        }
        g_dh_state = DH_SELECT;
        dh_send(DH_DISCOVER);
        g_dh_at = now + (g_dh_tries == 0 ? 200 : g_dh_tries == 1 ? 400 : 800);
        g_dh_tries++;
        return;
    case DH_CHECK:
        if (now >= g_dh_at) {
            dh_bind();   // probe ARP tanpa jawaban: alamat bebas
        }
        return;
    case DH_BOUND:
    case DH_RENEW:
    case DH_REBIND:
        if (g_dh_end && now >= g_dh_end) {
            dh_restart("sewa habis");
            return;
        }
        if (g_dh_state == DH_BOUND) {
            if (!g_dh_t1 || now < g_dh_t1) {
                return;
            }
            g_dh_state = DH_RENEW;
            g_dh_at = now;
        }
        if (g_dh_state == DH_RENEW && now >= g_dh_t2) {
            g_dh_state = DH_REBIND;
        }
        if (now >= g_dh_at && dh_new_xid()) {
            dh_send(DH_REQUEST_MSG);
            g_dh_at = now + DH_RENEW_EVERY;
        }
        return;
    default:
        return;
    }
}

// 1 = menunggu balasan DHCP: net.c menyerahkan UDP 67 -> 68 ke dhcp_rx tanpa
// cek IP tujuan (balasan bisa broadcast, ke alamat tawaran, atau ke IP kita).
int dhcp_waiting(void)
{
    return g_dh_state == DH_SELECT || g_dh_state == DH_REQUEST || g_dh_state == DH_RENEW ||
           g_dh_state == DH_REBIND;
}

static void dh_reject(const char *why)
{
    g_dhcp_bad++;
    ksnprintf(g_dh_last, sizeof(g_dh_last), "ditolak: %s", why);
}

// Isi UDP dari port 67 (checksum sudah sah).
void dhcp_rx(const volatile uint8_t *d, uint32_t len)
{
    uint8_t type = 0, srv[4] = { 0 }, mask[4] = { 0 }, router[4] = { 0 }, dns[4] = { 0 };
    uint32_t lease = 0, have = 0;   // bit 1 server, 2 sewa, 4 mask

    if (!dhcp_waiting()) {
        return;
    }
    if (len < DH_OPT_OFF || d[0] != 2 || d[1] != 1 || d[2] != 6 || dh_get32(d + 4) != g_dh_xid ||
        !dh_eq(d + 28, g_e1000_mac, 6) || d[236] != 99 || d[237] != 130 || d[238] != 83 ||
        d[239] != 99) {
        dh_reject("header/xid/MAC");
        return;
    }
    for (uint32_t i = DH_OPT_OFF; i < len && d[i] != 255;) {
        uint32_t c = d[i], l;
        if (c == 0) {
            i++;
            continue;
        }
        if (i + 2 > len || i + 2 + d[i + 1] > len) {
            dh_reject("option melewati ujung");
            return;
        }
        l = d[i + 1];
        const volatile uint8_t *v = d + i + 2;
        if (c == 53 && l == 1) {
            type = v[0];
        } else if (c == 54 && l == 4) {
            dh_cpy4(srv, v);
            have |= 1;
        } else if (c == 51 && l == 4) {
            lease = dh_get32(v);
            have |= 2;
        } else if (c == 1 && l == 4) {
            dh_cpy4(mask, v);
            have |= 4;
        } else if (c == 3 && l >= 4) {
            dh_cpy4(router, v);
        } else if (c == 6 && l >= 4) {
            dh_cpy4(dns, v);
        }
        i += 2 + l;
    }
    if (!(have & 1)) {
        dh_reject("tanpa server (54)");
        return;
    }

    const volatile uint8_t *yi = d + 16;
    static const uint8_t m24[4] = { 255, 255, 255, 0 };
    int addr_ok = (have & 6) == 6 && dh_eq(mask, m24, 4) && yi[0] != 0 && yi[0] != 127 &&
                  yi[0] < 224 && yi[3] >= 1 && yi[3] <= 254;
    uint32_t lease_eff = lease == DH_INFINITE ? lease : lease < DH_LEASE_MIN ? DH_LEASE_MIN : lease;

    if (type == DH_OFFER && g_dh_state == DH_SELECT) {
        if (!addr_ok) {
            dh_reject((have & 4) && !dh_eq(mask, m24, 4) ? "mask bukan /24" : "alamat/sewa");
            return;
        }
        g_dhcp_offers++;
        dh_cpy4(g_dh_offer, yi);
        memcpy(g_dh_server, srv, 4);
        g_dh_state = DH_REQUEST;
        dh_send(DH_REQUEST_MSG);
        g_dh_at = timer_ticks + DH_REQ_WAIT;
    } else if (type == DH_ACK && g_dh_state == DH_REQUEST) {
        if (!addr_ok || !dh_eq(srv, g_dh_server, 4) || !dh_eq(yi, g_dh_offer, 4)) {
            dh_reject("ACK tidak cocok tawaran");
            return;
        }
        g_dhcp_acks++;
        g_dh_lease = lease_eff;
        memcpy(g_dh_router, router, 4);
        memcpy(g_dh_dns, dns, 4);
        // Probe ARP (pengirim 0.0.0.0: IP belum dipakai); jawaban -> dhcp_arp_seen.
        g_dh_state = DH_CHECK;
        g_dh_at = timer_ticks + DH_CHECK_WAIT;
        e1000_tx_send(g_dh_page_phys,
                      net_arp_request_build((uint8_t *)(g_dh_page_phys + hhdm_offset), g_dh_offer));
    } else if (type == DH_ACK && (g_dh_state == DH_RENEW || g_dh_state == DH_REBIND)) {
        if (!addr_ok) {
            dh_reject("ACK perpanjangan");
            return;
        }
        if (!dh_eq(yi, g_net_ip, 4)) {
            dh_restart("ACK perpanjangan dengan alamat lain");
            return;
        }
        char ls[24];
        g_dhcp_acks++;
        g_dh_lease = lease_eff;
        memcpy(g_dh_server, srv, 4);
        memcpy(g_dh_router, router, 4);
        memcpy(g_dh_dns, dns, 4);
        dh_lease_times(timer_ticks);
        g_dh_state = DH_BOUND;
        dh_lease_str(ls, sizeof(ls));
        ksnprintf(g_dh_last, sizeof(g_dh_last), "diperpanjang");
        kprintf("P3: DHCP diperpanjang %u.%u.%u.%u dari %u.%u.%u.%u sewa %s\r\n", g_net_ip[0],
                g_net_ip[1], g_net_ip[2], g_net_ip[3], srv[0], srv[1], srv[2], srv[3], ls);
    } else if (type == DH_NAK && g_dh_state == DH_REQUEST && dh_eq(srv, g_dh_server, 4)) {
        g_dhcp_naks++;
        ksnprintf(g_dh_last, sizeof(g_dh_last), "NAK");
        kprintf("P3: DHCP NAK dari %u.%u.%u.%u, DISCOVER lagi\r\n", srv[0], srv[1], srv[2], srv[3]);
        g_dh_state = DH_INIT;
        g_dh_at = timer_ticks;
    } else if (type == DH_NAK && (g_dh_state == DH_RENEW || g_dh_state == DH_REBIND)) {
        g_dhcp_naks++;
        dh_restart("NAK");
    } else {
        dh_reject("jenis/keadaan");
    }
}

// Dari net_handle_arp: selama cek ARP, pengirim yang memakai alamat tawaran
// (MAC lain) = bentrok -> DECLINE, mulai lagi DH_DECLINE_WAIT kemudian.
void dhcp_arp_seen(const volatile uint8_t *buf)
{
    if (g_dh_state != DH_CHECK || !dh_eq(buf + 28, g_dh_offer, 4) || dh_eq(buf + 22, g_e1000_mac, 6)) {
        return;
    }
    g_dhcp_declines++;
    ksnprintf(g_dh_last, sizeof(g_dh_last), "alamat dipakai, DECLINE");
    kprintf("P3: DHCP alamat %u.%u.%u.%u sudah dipakai %02x:%02x:%02x:%02x:%02x:%02x -> DECLINE\r\n",
            g_dh_offer[0], g_dh_offer[1], g_dh_offer[2], g_dh_offer[3], buf[22], buf[23], buf[24],
            buf[25], buf[26], buf[27]);
    dh_send(DH_DECLINE);
    g_dh_state = DH_INIT;
    g_dh_at = timer_ticks + DH_DECLINE_WAIT;
}

// `dhcp` (juga peran ro): mode, keadaan, sewa, penghitung.
int dhcp_execute(const volatile uint8_t *cmd, uint32_t len)
{
    char line[200], ls[24];

    if (!net_cmd_is(cmd, len, "dhcp")) {
        return 0;
    }
    g_cmd_len = 0;
    if (g_dh_state == DH_OFF) {
        ksnprintf(line, sizeof(line), "dhcp: mode=statis%s ip=%u.%u.%u.%u/24\n",
                  g_dhcp_cfg ? " (dhcp=1 berlaku setelah reboot)" : "", g_net_ip[0], g_net_ip[1],
                  g_net_ip[2], g_net_ip[3]);
        cmd_puts(line);
        return 1;
    }
    uint64_t left = g_dh_end > timer_ticks ? (g_dh_end - timer_ticks) / 100 : 0;
    dh_lease_str(ls, sizeof(ls));
    ksnprintf(line, sizeof(line), "dhcp: mode=dhcp%s keadaan=%s ip=%u.%u.%u.%u/24 server=%u.%u.%u.%u "
              "sewa=%s sisa=%lu s router=%u.%u.%u.%u dns=%u.%u.%u.%u\n",
              g_dhcp_cfg ? "" : " (dhcp=0 berlaku setelah reboot)", g_dh_state_name[g_dh_state],
              g_net_ip[0], g_net_ip[1], g_net_ip[2], g_net_ip[3], g_dh_server[0], g_dh_server[1],
              g_dh_server[2], g_dh_server[3], ls, left, g_dh_router[0], g_dh_router[1],
              g_dh_router[2], g_dh_router[3], g_dh_dns[0], g_dh_dns[1], g_dh_dns[2], g_dh_dns[3]);
    cmd_puts(line);
    ksnprintf(line, sizeof(line), "dhcp: kirim=%lu tawaran=%lu ack=%lu nak=%lu decline=%lu "
              "diabaikan=%lu terakhir=%s\n", g_dhcp_tx, g_dhcp_offers, g_dhcp_acks, g_dhcp_naks,
              g_dhcp_declines, g_dhcp_bad, g_dh_last);
    cmd_puts(line);
    return 1;
}

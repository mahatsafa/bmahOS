#include "kernel.h"

// P6: pemantau jaringan. Maks MON_MAX target di /24 sendiri (hanya RAM, hilang
// saat reboot), diatur admin; `pantau` (juga peran ro) menampilkan status:
//   pantau ping <oktet> [interval]                ICMP echo (P6-1)
//   pantau tcp <oktet> <port> [interval]          TCP-connect setengah terbuka (P6-2)
//   pantau dns <nama> <oktet> <port> [interval]   query A ke server DNS (P6-2)
//   pantau hapus <n>
//   pantau syslog <oktet> [port] | syslog mati    alert syslog UDP (P6-2)
// Tiap target diperiksa tiap interval (5..3600 s, bawaan 10). ping/tcp: tanpa
// MAC -> ARP request maks 3 x 1 s (tanpa jawaban = satu kegagalan). ping: echo
// request (id per target, seq naik), balasan type 0 dari IP target dengan
// id+seq yang ditunggu, dalam 1 s. tcp: SYN dari port lokal acak dengan nomor
// urut acak; SYN-ACK atau RST yang membawa ACK = nomor urut + 1, dari IP:port
// target ke port lokal itu, dalam 1 s. SYN-ACK = berhasil (net.c membalasnya
// dengan RST, koneksi tidak pernah dibuka), RST = port tertutup. dns: query
// lewat dns.c (ARP, query, validasi balasan di sana; tanpa cache), berhasil
// bila ada jawaban A. Satu keberhasilan -> NAIK; MON_FAIL_DOWN kegagalan
// berturut-turut -> TURUN (MAC dilupakan, ARP ulang). Perubahan keadaan dicatat
// lewat kprintf ("P6: <target> NAIK|TURUN ...") -> serial, layar, LOG.BIN,
// netconsole, dan bila diatur juga sebagai pesan syslog RFC 5424 lewat UDP
// (antrean MON_SL_QUEUE pesan; penuh -> pesan baru dibuang; tujuan tanpa
// jawaban ARP 3x -> isi antrean dibuang). Balasan ping lewat packet filter P4
// (`tolak icmp` = TURUN); SYN-ACK/RST tidak.

#define MON_MAX         4
#define MON_FAIL_DOWN   3
#define MON_WAIT        100    // tick menunggu balasan ping/tcp
#define MON_DNS_WAIT    800    // tick; dns.c selesai paling lambat ~6 s (ARP 3 s + query 3 s)
#define MON_RETRY       100    // tick; dns.c sibuk / entropi belum siap -> coba lagi
#define MON_ARP_TRIES   3
#define MON_ARP_EVERY   100
#define MON_INT_MIN     5
#define MON_INT_MAX     3600
#define MON_INT_DEF     10
#define MON_ID_BASE     0xB0A0
#define MON_PAYLOAD     16
#define MON_NAME        64     // nama dns 1..63 + NUL
#define MON_SL_QUEUE    8
#define MON_SL_MSG      200
#define MON_SL_PORT     514    // port tujuan bawaan dan port sumber syslog

enum { MON_STATE_BELUM, MON_STATE_NAIK, MON_STATE_TURUN };
enum { MON_PING, MON_TCP, MON_DNS };

typedef struct {
    uint8_t used, type, host, state, mac_ok, waiting;
    uint8_t mac[6];
    uint16_t seq, port, lport;
    uint32_t interval;             // detik
    uint32_t arp_n, fails, isn, tok;
    uint64_t next_at, deadline, sent_at, probe_at;
    uint64_t sent, recv, changes;
    uint64_t rtt_last, rtt_min, rtt_max;   // tick (10 ms)
    char name[MON_NAME];           // dns
} mon_t;

static mon_t g_mon[MON_MAX];
static uint64_t g_mon_page_phys;
static uint32_t g_mon_tok;
static const char *const g_mon_state[] = { "belum", "naik", "turun" };

// Tujuan syslog + antrean pesan (head/tail terus naik, isi = tail - head).
static struct {
    uint8_t on, host, mac_ok;
    uint8_t mac[6];
    uint16_t port;
    uint32_t arp_n;
    uint64_t at, sent, lost;
} g_sl;
static char g_sl_q[MON_SL_QUEUE][MON_SL_MSG];
static uint32_t g_sl_len[MON_SL_QUEUE];
static uint32_t g_sl_head, g_sl_tail;

void monitor_init(void)
{
    if (!g_e1000_rx_initialized || g_mon_page_phys != 0) {
        return;
    }
    g_mon_page_phys = pmm_alloc();
}

static void mon_ip(uint8_t host, uint8_t ip[4])
{
    ip[0] = g_net_ip[0];
    ip[1] = g_net_ip[1];
    ip[2] = g_net_ip[2];
    ip[3] = host;
}

// "ping a.b.c.d", "tcp a.b.c.d:port", "dns nama@a.b.c.d:port".
static void mon_desc(const mon_t *m, char *out, uint32_t n)
{
    if (m->type == MON_PING) {
        ksnprintf(out, n, "ping %u.%u.%u.%u", g_net_ip[0], g_net_ip[1], g_net_ip[2],
                  (unsigned)m->host);
    } else if (m->type == MON_TCP) {
        ksnprintf(out, n, "tcp %u.%u.%u.%u:%u", g_net_ip[0], g_net_ip[1], g_net_ip[2],
                  (unsigned)m->host, (unsigned)m->port);
    } else {
        ksnprintf(out, n, "dns %s@%u.%u.%u.%u:%u", m->name, g_net_ip[0], g_net_ip[1], g_net_ip[2],
                  (unsigned)m->host, (unsigned)m->port);
    }
}

// Pesan RFC 5424 "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG",
// fasilitas local0 (16). Cap waktu hanya bila jam dari SNTP (UTC); jam RTC
// zonanya tidak diketahui -> "-" (NILVALUE).
static void sl_push(uint32_t sev, const char *msg)
{
    char ts[24] = "-";

    if (!g_sl.on) {
        return;
    }
    if (g_sl_tail - g_sl_head >= MON_SL_QUEUE) {
        g_sl.lost++;
        return;
    }
    if (g_time_src == 1 && g_rtc_ok) {
        rtc_time_t t;
        rtc_civil_from_epoch(rtc_now(), &t);
        ksnprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02uZ", t.year, t.month, t.day, t.hour,
                  t.min, t.sec);
    }
    char *q = g_sl_q[g_sl_tail % MON_SL_QUEUE];
    ksnprintf(q, MON_SL_MSG, "<%u>1 %s %u.%u.%u.%u bmahOS - pantau - %s", 16 * 8 + sev, ts,
              g_net_ip[0], g_net_ip[1], g_net_ip[2], g_net_ip[3], msg);
    g_sl_len[g_sl_tail % MON_SL_QUEUE] = (uint32_t)strlen(q);
    g_sl_tail++;
}

// Tiap putaran: ARP tujuan bila MAC belum ada, lalu kirim seluruh antrean.
static void sl_poll(uint64_t now)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint8_t ip[4];

    if (!g_sl.on || g_sl_head == g_sl_tail) {
        return;
    }
    mon_ip(g_sl.host, ip);
    if (!g_sl.mac_ok) {
        if (now < g_sl.at) {
            return;
        }
        if (g_sl.arp_n >= MON_ARP_TRIES) {
            g_sl.lost += g_sl_tail - g_sl_head;
            g_sl_head = g_sl_tail;
            g_sl.arp_n = 0;
            return;
        }
        g_sl.arp_n++;
        g_sl.at = now + MON_ARP_EVERY;
        e1000_tx_send(g_mon_page_phys, net_arp_request_build(p, ip));
        return;
    }
    while (g_sl_head != g_sl_tail) {
        uint32_t k = g_sl_head % MON_SL_QUEUE;
        memcpy(p + 42, g_sl_q[k], g_sl_len[k]);
        if (e1000_tx_send(g_mon_page_phys, net_udp_build(p, g_sl.mac, ip, MON_SL_PORT, g_sl.port,
                                                         g_sl_len[k]))) {
            g_sl.sent++;
        } else {
            g_sl.lost++;
        }
        g_sl_head++;
    }
}

// Perubahan keadaan: baris log "P6: <target> <teks>" + pesan syslog (bila aktif).
static void mon_event(const mon_t *m, uint32_t sev, const char *text)
{
    char d[96], line[MON_SL_MSG];

    mon_desc(m, d, sizeof(d));
    ksnprintf(line, sizeof(line), "%s %s", d, text);
    // Jarang dan penting: selalu sampai ke UART walau frame pemicunya kena
    // pembatas log B4b (seperti baris AUDIT sah). Hanya net task yang mengubah
    // g_serial_mute.
    int mute = g_serial_mute;
    g_serial_mute = 0;
    kprintf("P6: %s\r\n", line);
    g_serial_mute = mute;
    sl_push(sev, line);
}

static void mon_send_arp(const mon_t *m)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint8_t ip[4];

    mon_ip(m->host, ip);
    e1000_tx_send(g_mon_page_phys, net_arp_request_build(p, ip));
}

// Ethernet + IPv4 (proto 1) + ICMP echo request id/seq + 16 byte isi.
static int mon_send_echo(mon_t *m, uint16_t id)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint32_t icmp_len = 8 + MON_PAYLOAD;
    uint8_t ip[4];

    mon_ip(m->host, ip);
    memset(p, 0, 60);
    net_ipv4_hdr(p, m->mac, ip, 1, icmp_len);
    p[34] = 8;      // echo request
    p[38] = (uint8_t)(id >> 8);
    p[39] = (uint8_t)id;
    p[40] = (uint8_t)(m->seq >> 8);
    p[41] = (uint8_t)m->seq;
    memcpy(p + 42, "bmahOS-pantau-P6", MON_PAYLOAD);
    uint16_t c = net_checksum16(p + 34, icmp_len);
    p[36] = (uint8_t)(c >> 8);
    p[37] = (uint8_t)c;
    return e1000_tx_send(g_mon_page_phys, 34 + icmp_len < 60 ? 60 : 34 + icmp_len);
}

static int mon_send_syn(const mon_t *m)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint8_t ip[4];

    mon_ip(m->host, ip);
    return e1000_tx_send(g_mon_page_phys, net_tcp_syn_build(p, m->mac, ip, m->lport, m->port, m->isn));
}

static void mon_fail(mon_t *m, const char *why)
{
    char t[128];

    m->fails++;
    m->waiting = 0;
    if (m->fails >= MON_FAIL_DOWN) {
        m->mac_ok = 0;   // ARP ulang: host bisa saja berganti kartu/MAC
        if (m->state != MON_STATE_TURUN) {
            m->state = MON_STATE_TURUN;
            m->changes++;
            ksnprintf(t, sizeof(t), "TURUN (%u gagal berturut-turut, terakhir: %s)", m->fails, why);
            mon_event(m, 4, t);   // warning
        }
    }
}

// Probe berhasil; extra = hasil tambahan di pesan NAIK (dns: alamat), boleh 0.
static void mon_ok(mon_t *m, const char *extra)
{
    uint64_t rtt = timer_ticks - m->sent_at;
    char t[96];

    m->waiting = 0;
    m->recv++;
    m->fails = 0;
    m->rtt_last = rtt;
    if (m->recv == 1 || rtt < m->rtt_min) {
        m->rtt_min = rtt;
    }
    if (rtt > m->rtt_max) {
        m->rtt_max = rtt;
    }
    if (m->state != MON_STATE_NAIK) {
        m->state = MON_STATE_NAIK;
        m->changes++;
        if (extra) {
            ksnprintf(t, sizeof(t), "NAIK (%s, rtt %lu ms)", extra, rtt * 10);
        } else {
            ksnprintf(t, sizeof(t), "NAIK (rtt %lu ms)", rtt * 10);
        }
        mon_event(m, 5, t);   // notice
    }
}

// Probe ping/tcp dengan MAC yang sudah diketahui: kirim lalu tunggu MON_WAIT.
static void mon_start(mon_t *m, int k, uint64_t now)
{
    if (m->type == MON_TCP) {
        uint8_t r[6];
        if (!entropy_get(r, sizeof(r))) {
            m->next_at = now + MON_RETRY;   // bukan kegagalan target
            return;
        }
        m->lport = (uint16_t)(49152 + (((uint32_t)r[0] << 8 | r[1]) % 16384));
        m->isn = (uint32_t)r[2] << 24 | (uint32_t)r[3] << 16 | (uint32_t)r[4] << 8 | r[5];
    } else {
        m->seq++;
    }
    m->sent++;
    m->sent_at = now;
    m->deadline = now + MON_WAIT;
    m->next_at = m->probe_at + (uint64_t)m->interval * 100;
    m->waiting = 1;
    int ok = m->type == MON_TCP ? mon_send_syn(m) : mon_send_echo(m, (uint16_t)(MON_ID_BASE + k));
    if (!ok) {
        mon_fail(m, "kirim gagal");
    }
}

// Probe dns: ARP dan batas waktu ada di dns.c; hasil lewat monitor_dns_done.
static void mon_start_dns(mon_t *m, uint64_t now)
{
    uint32_t tok = ++g_mon_tok;

    if (dns_probe_start(m->name, m->host, m->port, tok) != 0) {
        m->next_at = now + MON_RETRY;   // query `dns` lain berjalan / entropi
        return;
    }
    m->tok = tok;
    m->probe_at = now;
    m->sent++;
    m->sent_at = now;
    m->deadline = now + MON_DNS_WAIT;
    m->next_at = now + (uint64_t)m->interval * 100;
    m->waiting = 1;
}

// P3-4 (dhcp.c): IP berubah (prefiks /24 bisa lain) -> semua MAC dipelajari ulang.
void monitor_ip_changed(void)
{
    for (int k = 0; k < MON_MAX; k++) {
        g_mon[k].mac_ok = 0;
    }
    g_sl.mac_ok = 0;
}

void monitor_poll(void)
{
    static const char *const timeout[] = { "tanpa balasan ping", "tanpa balasan TCP",
                                           "tanpa hasil DNS" };
    uint64_t now = timer_ticks;

    if (!net_ip_ready()) {
        return;   // P3-4: tanpa IP (DHCP belum terikat) tidak ada probe/syslog
    }

    for (int k = 0; k < MON_MAX; k++) {
        mon_t *m = &g_mon[k];

        if (!m->used) {
            continue;
        }
        if (m->waiting) {
            if (now >= m->deadline) {
                mon_fail(m, timeout[m->type]);
            }
            continue;
        }
        if (now < m->next_at) {
            continue;
        }
        if (m->type == MON_DNS) {
            mon_start_dns(m, now);
            continue;
        }
        if (!m->mac_ok) {
            if (m->arp_n >= MON_ARP_TRIES) {
                m->arp_n = 0;
                m->next_at = m->probe_at + (uint64_t)m->interval * 100;
                mon_fail(m, "tanpa balasan ARP");
                continue;
            }
            if (m->arp_n == 0) {
                m->probe_at = now;
            }
            m->arp_n++;
            m->next_at = now + MON_ARP_EVERY;
            mon_send_arp(m);
            continue;
        }
        if (m->arp_n == 0) {
            m->probe_at = now;
        }
        m->arp_n = 0;
        mon_start(m, k, now);
    }
    sl_poll(now);
}

// Dari net_handle_arp untuk setiap ARP sah: MAC target ping/tcp yang belum
// diketahui, dan MAC tujuan syslog (selalu diperbarui).
void monitor_arp_seen(const volatile uint8_t *buf)
{
    int zero = 1;

    for (int i = 0; i < 6; i++) {
        zero &= buf[22 + i] == 0;
    }
    if ((buf[22] & 0x01) || zero || buf[28] != g_net_ip[0] || buf[29] != g_net_ip[1] ||
        buf[30] != g_net_ip[2]) {
        return;
    }
    for (int k = 0; k < MON_MAX; k++) {
        mon_t *m = &g_mon[k];
        if (m->used && m->type != MON_DNS && !m->mac_ok && buf[31] == m->host) {
            for (int i = 0; i < 6; i++) {
                m->mac[i] = buf[22 + i];
            }
            m->mac_ok = 1;
            if (m->arp_n > 0) {
                m->next_at = timer_ticks;   // kirim probe pada putaran berikutnya
            }
        }
    }
    if (g_sl.on && buf[31] == g_sl.host) {
        for (int i = 0; i < 6; i++) {
            g_sl.mac[i] = buf[22 + i];
        }
        g_sl.mac_ok = 1;
        g_sl.arp_n = 0;
    }
}

// Dari net_handle_ipv4: ICMP echo reply (type 0) yang checksum-nya sudah sah.
void monitor_icmp_reply(const volatile uint8_t *buf, uint32_t ihl, uint32_t icmp_len)
{
    const volatile uint8_t *c = buf + 14 + ihl;

    if (icmp_len < 8 || c[0] != 0 || c[1] != 0) {
        return;
    }
    uint16_t id = (uint16_t)(c[4] << 8 | c[5]), seq = (uint16_t)(c[6] << 8 | c[7]);
    if (id < MON_ID_BASE || id >= MON_ID_BASE + MON_MAX) {
        return;
    }
    mon_t *m = &g_mon[id - MON_ID_BASE];

    if (!m->used || m->type != MON_PING || !m->waiting || seq != m->seq ||
        buf[26] != g_net_ip[0] || buf[27] != g_net_ip[1] || buf[28] != g_net_ip[2] ||
        buf[29] != m->host) {
        return;
    }
    mon_ok(m, 0);
}

// Dari net_handle_tcp untuk segmen sah (checksum) yang bukan milik koneksi atau
// port dengar (r = offset header TCP). 1 = jawaban probe tcp: net.c membalas
// SYN-ACK dengan RST tanpa baris log "port tertutup".
int monitor_tcp_seen(const volatile uint8_t *buf, uint32_t r)
{
    uint16_t sport = (uint16_t)(buf[r] << 8 | buf[r + 1]);
    uint16_t dport = (uint16_t)(buf[r + 2] << 8 | buf[r + 3]);
    uint32_t ack = (uint32_t)buf[r + 8] << 24 | (uint32_t)buf[r + 9] << 16 |
                   (uint32_t)buf[r + 10] << 8 | buf[r + 11];
    uint8_t fl = buf[r + 13];

    for (int k = 0; k < MON_MAX; k++) {
        mon_t *m = &g_mon[k];

        if (!m->used || m->type != MON_TCP || !m->waiting || sport != m->port ||
            dport != m->lport || buf[26] != g_net_ip[0] || buf[27] != g_net_ip[1] ||
            buf[28] != g_net_ip[2] || buf[29] != m->host) {
            continue;
        }
        if (!(fl & 0x10) || ack != m->isn + 1) {
            return 0;    // bukan jawaban untuk SYN kita
        }
        if (fl & 0x04) {
            mon_fail(m, "port tertutup (RST)");
        } else if (fl & 0x02) {
            mon_ok(m, 0);
        } else {
            return 0;
        }
        return 1;
    }
    return 0;
}

// Dari dns.c saat query pemantau selesai: a = ada jawaban A; what = hasil dns.c
// ("= a.b.c.d", "= tidak ada (NXDOMAIN)", "gagal: ...", "kirim gagal").
void monitor_dns_done(uint32_t tok, int a, const char *what)
{
    if (what[0] == '=' && what[1] == ' ') {
        what += 2;
    } else if (strlen(what) > 7 && memcmp(what, "gagal: ", 7) == 0) {
        what += 7;
    }
    for (int k = 0; k < MON_MAX; k++) {
        mon_t *m = &g_mon[k];
        if (m->used && m->type == MON_DNS && m->waiting && m->tok == tok) {
            if (a) {
                mon_ok(m, what);
            } else {
                mon_fail(m, what);
            }
            return;
        }
    }
}

static void mon_list(void)
{
    char line[200], d[96];
    uint32_t n = 0;

    for (int k = 0; k < MON_MAX; k++) {
        n += g_mon[k].used;
    }
    ksnprintf(line, sizeof(line), "pantau: target=%u/%u (NAIK = 1 berhasil, TURUN = %u gagal "
              "berturut-turut)\n", n, (unsigned)MON_MAX, (unsigned)MON_FAIL_DOWN);
    cmd_puts(line);
    if (g_sl.on) {
        ksnprintf(line, sizeof(line), "syslog: %u.%u.%u.%u:%u terkirim=%lu dibuang=%lu antre=%u\n",
                  g_net_ip[0], g_net_ip[1], g_net_ip[2], (unsigned)g_sl.host, (unsigned)g_sl.port,
                  g_sl.sent, g_sl.lost, g_sl_tail - g_sl_head);
    } else {
        ksnprintf(line, sizeof(line), "syslog: mati terkirim=%lu dibuang=%lu\n", g_sl.sent, g_sl.lost);
    }
    cmd_puts(line);
    for (int k = 0; k < MON_MAX; k++) {
        const mon_t *m = &g_mon[k];
        if (!m->used) {
            continue;
        }
        mon_desc(m, d, sizeof(d));
        ksnprintf(line, sizeof(line), "%u: %s %s tiap=%u s kirim=%lu balas=%lu gagal_beruntun=%u "
                  "rtt=%lu/%lu/%lu ms ganti=%lu\n", (unsigned)(k + 1), d, g_mon_state[m->state],
                  m->interval, m->sent, m->recv, m->fails, m->rtt_last * 10, m->rtt_min * 10,
                  m->rtt_max * 10, m->changes);
        cmd_puts(line);
    }
}

// Angka desimal 1..6 digit dari s[*i..len) diikuti spasi/akhir. 1 = OK.
static int mon_num(const volatile uint8_t *s, uint32_t len, uint32_t *i, uint32_t *out)
{
    uint32_t st = *i, v = 0;

    while (*i < len && s[*i] >= '0' && s[*i] <= '9' && *i - st < 6) {
        v = v * 10 + (uint32_t)(s[*i] - '0');
        (*i)++;
    }
    if (*i == st || (*i < len && s[*i] != ' ')) {
        return 0;
    }
    while (*i < len && s[*i] == ' ') {
        (*i)++;
    }
    *out = v;
    return 1;
}

static const char *const g_mon_usage[] = {
    "ERR: pantau: ping <oktet 1..254, bukan IP sendiri> [interval 5..3600 s]\n",
    "ERR: pantau: tcp <oktet 1..254, bukan IP sendiri> <port 1..65535> [interval 5..3600 s]\n",
    "ERR: pantau: dns <nama> <oktet server 1..254> <port 1..65535> [interval 5..3600 s]\n",
};

// `pantau ping|tcp|dns ...`; i = awal argumen pertama.
static void mon_cmd_add(const volatile uint8_t *cmd, uint32_t len, uint32_t i, int type)
{
    char name[MON_NAME] = "", line[160], d[96];
    uint32_t host = 0, port = 0, iv = MON_INT_DEF;
    int bad = 0, slot = -1;

    if (type == MON_DNS) {
        uint32_t st = i;
        while (i < len && cmd[i] != ' ') {
            i++;
        }
        bad = !dns_name_check(cmd + st, i - st, name);
        while (i < len && cmd[i] == ' ') {
            i++;
        }
    }
    bad |= !mon_num(cmd, len, &i, &host);
    if (type != MON_PING) {
        bad |= !mon_num(cmd, len, &i, &port);
    }
    if (i < len) {
        bad |= !mon_num(cmd, len, &i, &iv);
    }
    if (bad || i < len || host < 1 || host > 254 || host == g_net_ip[3] || iv < MON_INT_MIN ||
        iv > MON_INT_MAX || (type != MON_PING && (port < 1 || port > 65535))) {
        cmd_puts(g_mon_usage[type]);
        return;
    }
    if (g_mon_page_phys == 0) {
        cmd_puts("ERR: pantau: tanpa NIC\n");
        return;
    }
    for (int k = 0; k < MON_MAX; k++) {
        const mon_t *m = &g_mon[k];
        if (m->used && m->type == type && m->host == host && m->port == port &&
            memcmp(m->name, name, MON_NAME) == 0) {
            cmd_puts("ERR: pantau: target sudah ada\n");
            return;
        }
        if (!m->used && slot < 0) {
            slot = k;
        }
    }
    if (slot < 0) {
        cmd_puts("ERR: pantau: penuh (maks 4 target)\n");
        return;
    }
    mon_t *m = &g_mon[slot];
    memset(m, 0, sizeof(*m));
    m->used = 1;
    m->type = (uint8_t)type;
    m->host = (uint8_t)host;
    m->port = (uint16_t)port;
    m->interval = iv;
    memcpy(m->name, name, MON_NAME);
    m->next_at = timer_ticks;
    mon_desc(m, d, sizeof(d));
    ksnprintf(line, sizeof(line), "OK pantau %d: %s tiap %u s\n", slot + 1, d, iv);
    cmd_puts(line);
}

static void mon_cmd_syslog(const volatile uint8_t *cmd, uint32_t len)
{
    char line[128];
    uint32_t i = 14, host, port = MON_SL_PORT;

    if (net_cmd_is(cmd + 14, len - 14, "mati")) {
        g_sl.on = 0;
        g_sl_head = g_sl_tail;
        cmd_puts("OK pantau: syslog mati\n");
        return;
    }
    if (!mon_num(cmd, len, &i, &host) || (i < len && !mon_num(cmd, len, &i, &port)) || i < len ||
        host < 1 || host > 254 || host == g_net_ip[3] || port < 1 || port > 65535) {
        cmd_puts("ERR: pantau: syslog <oktet 1..254, bukan IP sendiri> [port, bawaan 514] | "
                 "syslog mati\n");
        return;
    }
    if (g_mon_page_phys == 0) {
        cmd_puts("ERR: pantau: tanpa NIC\n");
        return;
    }
    g_sl.on = 1;
    g_sl.host = (uint8_t)host;
    g_sl.port = (uint16_t)port;
    g_sl.mac_ok = 0;
    g_sl.arp_n = 0;
    g_sl.at = 0;
    ksnprintf(line, sizeof(line), "syslog pantau aktif ke %u.%u.%u.%u:%u", g_net_ip[0], g_net_ip[1],
              g_net_ip[2], host, port);
    sl_push(6, line);   // informational: pesan uji untuk penerima
    ksnprintf(line, sizeof(line), "OK pantau: syslog ke %u.%u.%u.%u:%u (pesan uji dikirim)\n",
              g_net_ip[0], g_net_ip[1], g_net_ip[2], host, port);
    cmd_puts(line);
}

// `pantau` (juga ro); `pantau ping|tcp|dns|hapus|syslog ...` (admin).
int monitor_execute(const volatile uint8_t *cmd, uint32_t len)
{
    char line[96];
    uint32_t i, n;

    if (net_cmd_is(cmd, len, "pantau")) {
        g_cmd_len = 0;
        mon_list();
        return 1;
    }
    if (len < 7 || !net_cmd_is(cmd, 7, "pantau ")) {
        return 0;
    }
    g_cmd_len = 0;
    if (len > 12 && net_cmd_is(cmd, 12, "pantau ping ")) {
        mon_cmd_add(cmd, len, 12, MON_PING);
        return 1;
    }
    if (len > 11 && net_cmd_is(cmd, 11, "pantau tcp ")) {
        mon_cmd_add(cmd, len, 11, MON_TCP);
        return 1;
    }
    if (len > 11 && net_cmd_is(cmd, 11, "pantau dns ")) {
        mon_cmd_add(cmd, len, 11, MON_DNS);
        return 1;
    }
    if (len > 14 && net_cmd_is(cmd, 14, "pantau syslog ")) {
        mon_cmd_syslog(cmd, len);
        return 1;
    }
    if (len > 13 && net_cmd_is(cmd, 13, "pantau hapus ")) {
        i = 13;
        if (!mon_num(cmd, len, &i, &n) || i < len || n < 1 || n > MON_MAX || !g_mon[n - 1].used) {
            cmd_puts("ERR: pantau: hapus <nomor target>\n");
            return 1;
        }
        g_mon[n - 1].used = 0;
        ksnprintf(line, sizeof(line), "OK pantau: target %u dihapus\n", n);
        cmd_puts(line);
        return 1;
    }
    cmd_puts("ERR: pantau: pantau | ping|tcp|dns ... | hapus <n> | syslog <oktet> [port]|mati\n");
    return 1;
}

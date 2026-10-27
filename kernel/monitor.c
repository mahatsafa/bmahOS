#include "kernel.h"

// P6-1: pemantau ping. Maks MON_MAX target di /24 sendiri (hanya RAM, hilang saat
// reboot), diatur admin: `pantau tambah <oktet> [interval]`, `pantau hapus <n>`;
// `pantau` (juga peran ro) menampilkan status. Tiap target diperiksa tiap
// interval (5..3600 s, bawaan 10): tanpa MAC -> ARP request maks 3 x 1 s (tanpa
// jawaban = satu kegagalan), lalu ICMP echo request (id per target, seq naik);
// balasan type 0 hanya diterima dari IP target dengan id+seq yang ditunggu,
// dalam 1 s. Satu balasan -> NAIK; MON_FAIL_DOWN kegagalan berturut-turut ->
// TURUN (MAC dilupakan, ARP ulang). Perubahan keadaan dicatat lewat kprintf
// ("P6: a.b.c.d NAIK|TURUN ..."), jadi ikut ke serial, layar, LOG.BIN, dan
// netconsole. Balasan ICMP juga lewat packet filter P4 (`tolak icmp` = TURUN).

#define MON_MAX         4
#define MON_FAIL_DOWN   3
#define MON_WAIT        100    // tick menunggu balasan echo
#define MON_ARP_TRIES   3
#define MON_ARP_EVERY   100
#define MON_INT_MIN     5
#define MON_INT_MAX     3600
#define MON_INT_DEF     10
#define MON_ID_BASE     0xB0A0
#define MON_PAYLOAD     16

enum { MON_STATE_BELUM, MON_STATE_NAIK, MON_STATE_TURUN };

typedef struct {
    uint8_t used, host, state, mac_ok, waiting;
    uint8_t mac[6];
    uint16_t seq;
    uint32_t interval;             // detik
    uint32_t arp_n, fails;
    uint64_t next_at, deadline, sent_at, probe_at;
    uint64_t sent, recv, changes;
    uint64_t rtt_last, rtt_min, rtt_max;   // tick (10 ms)
} mon_t;

static mon_t g_mon[MON_MAX];
static uint64_t g_mon_page_phys;
static const char *const g_mon_state[] = { "belum", "naik", "turun" };

void monitor_init(void)
{
    if (!g_e1000_rx_initialized || g_mon_page_phys != 0) {
        return;
    }
    g_mon_page_phys = pmm_alloc();
}

static void mon_ip(const mon_t *m, uint8_t ip[4])
{
    ip[0] = g_net_ip[0];
    ip[1] = g_net_ip[1];
    ip[2] = g_net_ip[2];
    ip[3] = m->host;
}

static void mon_send_arp(const mon_t *m)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint8_t ip[4];

    mon_ip(m, ip);
    e1000_tx_send(g_mon_page_phys, net_arp_request_build(p, ip));
}

// Ethernet + IPv4 (proto 1) + ICMP echo request id/seq + 16 byte isi.
static int mon_send_echo(mon_t *m, uint16_t id)
{
    uint8_t *p = (uint8_t *)(g_mon_page_phys + hhdm_offset);
    uint32_t icmp_len = 8 + MON_PAYLOAD;
    uint8_t ip[4];

    mon_ip(m, ip);
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

static void mon_fail(mon_t *m, const char *why)
{
    m->fails++;
    m->waiting = 0;
    if (m->fails >= MON_FAIL_DOWN) {
        m->mac_ok = 0;   // ARP ulang: host bisa saja berganti kartu/MAC
        if (m->state != MON_STATE_TURUN) {
            m->state = MON_STATE_TURUN;
            m->changes++;
            kprintf("P6: %u.%u.%u.%u TURUN (%u gagal berturut-turut, terakhir: %s)\r\n",
                    g_net_ip[0], g_net_ip[1], g_net_ip[2], (unsigned)m->host, m->fails, why);
        }
    }
}

void monitor_poll(void)
{
    uint64_t now = timer_ticks;

    for (int k = 0; k < MON_MAX; k++) {
        mon_t *m = &g_mon[k];

        if (!m->used) {
            continue;
        }
        if (m->waiting) {
            if (now >= m->deadline) {
                mon_fail(m, "tanpa balasan ping");
            }
            continue;
        }
        if (now < m->next_at) {
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
        m->seq++;
        m->sent++;
        m->sent_at = now;
        m->deadline = now + MON_WAIT;
        m->next_at = m->probe_at + (uint64_t)m->interval * 100;
        m->waiting = 1;
        if (!mon_send_echo(m, (uint16_t)(MON_ID_BASE + k))) {
            mon_fail(m, "kirim gagal");
        }
    }
}

// Dari net_handle_arp untuk setiap ARP sah: MAC target yang belum diketahui.
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
        if (m->used && !m->mac_ok && buf[31] == m->host) {
            for (int i = 0; i < 6; i++) {
                m->mac[i] = buf[22 + i];
            }
            m->mac_ok = 1;
            if (m->arp_n > 0) {
                m->next_at = timer_ticks;   // kirim echo pada putaran berikutnya
            }
        }
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

    if (!m->used || !m->waiting || seq != m->seq || buf[26] != g_net_ip[0] ||
        buf[27] != g_net_ip[1] || buf[28] != g_net_ip[2] || buf[29] != m->host) {
        return;
    }
    uint64_t rtt = timer_ticks - m->sent_at;

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
        kprintf("P6: %u.%u.%u.%u NAIK (rtt %lu ms)\r\n", g_net_ip[0], g_net_ip[1],
                g_net_ip[2], (unsigned)m->host, rtt * 10);
    }
}

static void mon_list(void)
{
    char line[160];
    uint32_t n = 0;

    for (int k = 0; k < MON_MAX; k++) {
        n += g_mon[k].used;
    }
    ksnprintf(line, sizeof(line), "pantau: target=%u/%u (ping; NAIK = 1 balasan, TURUN = %u gagal)\n",
              n, (unsigned)MON_MAX, (unsigned)MON_FAIL_DOWN);
    cmd_puts(line);
    for (int k = 0; k < MON_MAX; k++) {
        const mon_t *m = &g_mon[k];
        if (!m->used) {
            continue;
        }
        ksnprintf(line, sizeof(line), "%u: %u.%u.%u.%u %s tiap=%u s kirim=%lu balas=%lu gagal_beruntun=%u "
                  "rtt=%lu/%lu/%lu ms ganti=%lu\n", (unsigned)(k + 1), g_net_ip[0], g_net_ip[1],
                  g_net_ip[2], (unsigned)m->host, g_mon_state[m->state], m->interval, m->sent, m->recv,
                  m->fails, m->rtt_last * 10, m->rtt_min * 10, m->rtt_max * 10, m->changes);
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

// `pantau` (juga ro), `pantau tambah <oktet> [interval]`, `pantau hapus <n>` (admin).
int monitor_execute(const volatile uint8_t *cmd, uint32_t len)
{
    char line[96];
    uint32_t i, host, iv = MON_INT_DEF, n;

    if (net_cmd_is(cmd, len, "pantau")) {
        g_cmd_len = 0;
        mon_list();
        return 1;
    }
    if (len < 7 || !net_cmd_is(cmd, 7, "pantau ")) {
        return 0;
    }
    g_cmd_len = 0;
    if (len > 14 && net_cmd_is(cmd, 14, "pantau tambah ")) {
        i = 14;
        if (!mon_num(cmd, len, &i, &host) || (i < len && !mon_num(cmd, len, &i, &iv)) || i < len ||
            host < 1 || host > 254 || host == g_net_ip[3] || iv < MON_INT_MIN || iv > MON_INT_MAX) {
            cmd_puts("ERR: pantau: tambah <oktet 1..254, bukan IP sendiri> [interval 5..3600 s]\n");
            return 1;
        }
        if (g_mon_page_phys == 0) {
            cmd_puts("ERR: pantau: tanpa NIC\n");
            return 1;
        }
        int slot = -1;
        for (int k = 0; k < MON_MAX; k++) {
            if (g_mon[k].used && g_mon[k].host == host) {
                cmd_puts("ERR: pantau: target sudah ada\n");
                return 1;
            }
            if (!g_mon[k].used && slot < 0) {
                slot = k;
            }
        }
        if (slot < 0) {
            cmd_puts("ERR: pantau: penuh (maks 4 target)\n");
            return 1;
        }
        memset(&g_mon[slot], 0, sizeof(g_mon[slot]));
        g_mon[slot].used = 1;
        g_mon[slot].host = (uint8_t)host;
        g_mon[slot].interval = iv;
        g_mon[slot].next_at = timer_ticks;
        ksnprintf(line, sizeof(line), "OK pantau %d: %u.%u.%u.%u tiap %u s\n", slot + 1, g_net_ip[0],
                  g_net_ip[1], g_net_ip[2], host, iv);
        cmd_puts(line);
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
    cmd_puts("ERR: pantau: pantau | pantau tambah <oktet> [interval] | pantau hapus <n>\n");
    return 1;
}

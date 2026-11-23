#include "kernel.h"

// F7: IPv6 dasar (ROADMAP Fase 7). Sengaja kecil dan bawaan MATI (CONFIG.CFG ipv6=0;
// ipv6=1 berlaku setelah reboot, seperti dhcp).
//   - Hanya alamat link-local fe80::/64 dari EUI-64 MAC (tanpa SLAAC global, tanpa
//     DHCPv6, tanpa RA/RS). DAD: IP6_DAD_PROBES NS dari :: tiap IP6_DAD_TICKS tick;
//     NS/NA konflik -> IPv6 nonaktif (IP6_CONFLICT) + log. Sampai DAD selesai tidak
//     ada echo/UDP yang dilayani.
//   - Header IPv6 tetap 40 byte. Next header selain ICMPv6 (58) dan UDP (17) dibuang
//     dan dihitung (ekstensi, fragmen, TCP: ip6_nxt_drop / ip6_tcp_drop). Muatan
//     maks IP6_PAYLOAD_MAX. Tujuan harus alamat kita, solicited-node kita, atau
//     ff02::1; sumber harus fe80::/10 (atau :: hanya untuk NS DAD), jadi hanya
//     tetangga se-link yang dilayani.
//   - ICMPv6: echo request -> reply (hanya ke unicast kita), NS -> NA, NA (DAD +
//     perbarui tetangga yang sudah ada). Hop limit ND harus 255. RA/RS/Redirect dan
//     lainnya diabaikan. Checksum pseudo-header wajib (ip6_badsum).
//   - UDP: hanya echo 7777 (g_net_echo), checksum wajib (nol = dibuang). Tidak ada
//     UDP 7778 (perintah), soket user, TCP, atau aturan filter P4 (khusus IPv4;
//     IPv6 punya kebijakan tetap di atas).
//   - Batas laju: per sumber (tabel 8 slot sendiri, kunci 16 byte, kode yang sama
//     dengan IPv4 B4) lalu global, SEBELUM checksum dan balasan.
//   - Tabel tetangga IP6_NEIGH_MAX (8): dibuat hanya dari NS bersumber unicast yang
//     membawa SLLA; NA tak pernah membuat entri; penuh -> korban tertua. Hanya cache
//     diagnostik (perintah ip): balasan memakai MAC dari NS/frame, bukan tabel.
// Dipanggil hanya dari net task (tanpa lock). Satu TX buffer net.c dipakai bersama.

#define IP6_DAD_PROBES   2
#define IP6_DAD_TICKS    100
#define IP6_NEIGH_MAX    8
#define IP6_SRC_SLOTS    8
#define IP6_PAYLOAD_MAX  1460

enum { IP6_OFF = 0, IP6_DAD, IP6_UP, IP6_CONFLICT };

typedef struct {
    uint8_t ip[16];
    uint8_t mac[6];
    uint64_t at;
    int in_use;
} ip6_neigh_t;

uint32_t g_ip6_cfg;            // CONFIG.CFG ipv6 (config.c), dibaca ip6_init saat boot
uint8_t g_ip6_ll[16];
static int g_ip6_state = IP6_OFF;
static uint8_t g_ip6_snmc[16];  // ff02::1:ffXX:XXXX
static uint8_t g_ip6_snmac[6];  // 33:33:ff:XX:XX:XX
static uint32_t g_ip6_probes;
static uint64_t g_ip6_next;
static ip6_neigh_t g_ip6_neigh[IP6_NEIGH_MAX];
static net_src_budget_t g_ip6_src[IP6_SRC_SLOTS];

uint64_t g_ip6_rx, g_ip6_drop, g_ip6_off, g_ip6_nxt_drop, g_ip6_tcp_drop;
uint64_t g_ip6_ignored;   // ICMPv6 tipe lain, unicast host lain, NS/NA pantulan MAC sendiri
uint64_t g_ip6_rate_drop, g_ip6_badsum, g_icmp6_echo, g_nd_ns_rx, g_nd_na_tx;
uint64_t g_nd_na_rx, g_nd_bad, g_nd_evict, g_ip6_dad_conflict, g_udp6_echo;

static const uint8_t IP6_ALLNODES[16] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const uint8_t IP6_ALLNODES_MAC[6] = { 0x33, 0x33, 0, 0, 0, 1 };

static int ip6_eq(const volatile uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static int ip6_is_zero(const volatile uint8_t *a)
{
    for (int i = 0; i < 16; i++) {
        if (a[i]) {
            return 0;
        }
    }
    return 1;
}

// "fe80::20c:29ff:fe86:ef48" (RFC 5952: nol terpanjang >= 2 grup jadi "::", yang
// pertama bila sama panjang). out minimal 40 byte.
void ip6_fmt(char *out, uint32_t max, const volatile uint8_t *a)
{
    uint32_t g[8];
    int best = -1, blen = 0;

    for (int i = 0; i < 8; i++) {
        g[i] = ((uint32_t)a[2 * i] << 8) | a[2 * i + 1];
    }
    for (int i = 0; i < 8;) {
        if (g[i] != 0) {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && g[j] == 0) {
            j++;
        }
        if (j - i > blen) {
            best = i;
            blen = j - i;
        }
        i = j;
    }
    if (blen < 2) {
        best = -1;
    }

    uint32_t n = 0;
    char tmp[8];

    for (int i = 0; i < 8; i++) {
        if (i == best) {
            n += (uint32_t)ksnprintf(out + n, max - n, "::");
            i += blen - 1;
            continue;
        }
        if (n && out[n - 1] != ':') {
            n += (uint32_t)ksnprintf(out + n, max - n, ":");
        }
        ksnprintf(tmp, sizeof(tmp), "%x", g[i]);
        n += (uint32_t)ksnprintf(out + n, max - n, "%s", tmp);
    }
}

int ip6_active(void)
{
    return g_ip6_state != IP6_OFF;
}

const char *ip6_state_name(void)
{
    switch (g_ip6_state) {
    case IP6_DAD:
        return "DAD";
    case IP6_UP:
        return "aktif";
    case IP6_CONFLICT:
        return "nonaktif (DAD konflik)";
    default:
        return "nonaktif";
    }
}

int ip6_neigh_count(void)
{
    int n = 0;

    for (int i = 0; i < IP6_NEIGH_MAX; i++) {
        n += g_ip6_neigh[i].in_use;
    }
    return n;
}

// i-th entri terpakai (urutan tabel); 0 bila tidak ada.
int ip6_neigh_get(int idx, uint8_t ip[16], uint8_t mac[6])
{
    for (int i = 0; i < IP6_NEIGH_MAX; i++) {
        if (g_ip6_neigh[i].in_use && idx-- == 0) {
            memcpy(ip, g_ip6_neigh[i].ip, 16);
            memcpy(mac, g_ip6_neigh[i].mac, 6);
            return 1;
        }
    }
    return 0;
}

static ip6_neigh_t *ip6_neigh_find(const volatile uint8_t *ip)
{
    for (int i = 0; i < IP6_NEIGH_MAX; i++) {
        if (g_ip6_neigh[i].in_use && ip6_eq(ip, g_ip6_neigh[i].ip)) {
            return &g_ip6_neigh[i];
        }
    }
    return 0;
}

// create=1 (NS dengan SLLA): buat atau perbarui; penuh -> korban = entri tertua.
// create=0 (NA): hanya perbarui entri yang sudah ada.
static void ip6_neigh_put(const volatile uint8_t *ip, const volatile uint8_t *mac, int create)
{
    ip6_neigh_t *e = ip6_neigh_find(ip);

    if (!e) {
        if (!create) {
            return;
        }
        for (int i = 0; i < IP6_NEIGH_MAX; i++) {
            if (!g_ip6_neigh[i].in_use) {
                e = &g_ip6_neigh[i];
                break;
            }
        }
        if (!e) {
            e = &g_ip6_neigh[0];
            for (int i = 1; i < IP6_NEIGH_MAX; i++) {
                if (g_ip6_neigh[i].at < e->at) {
                    e = &g_ip6_neigh[i];
                }
            }
            g_nd_evict++;
        }
        for (int i = 0; i < 16; i++) {
            e->ip[i] = ip[i];
        }
        e->in_use = 1;
    }
    for (int i = 0; i < 6; i++) {
        e->mac[i] = mac[i];
    }
    e->at = timer_ticks;
}

// Checksum ICMPv6/UDP dengan pseudo-header (RFC 8200 8.1): src, dst, panjang 32 bit,
// 3 nol + next header. Data yang sudah berisi checksum valid -> 0.
uint16_t ip6_l4_checksum(const volatile uint8_t *src, const volatile uint8_t *dst, uint8_t nxt,
                         const volatile uint8_t *l4, uint32_t len)
{
    uint32_t sum = net_sum16(src, 16, 0);

    sum = net_sum16(dst, 16, sum);
    sum += len;
    sum += nxt;
    sum = net_sum16(l4, len, sum);
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint8_t *ip6_txbuf(void)
{
    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("IPv6: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return 0;
        }
    }
    return (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
}

// Ethernet + IPv6 (40 byte) di p; muatan plen byte menyusul di p[54..]. Sumber = src.
static void ip6_hdr(uint8_t *p, const uint8_t *dst_mac, const uint8_t *src, const uint8_t *dst,
                    uint8_t nxt, uint8_t hop, uint32_t plen)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x86;
    p[13] = 0xDD;
    p[14] = 0x60;
    p[15] = p[16] = p[17] = 0;
    p[18] = (uint8_t)(plen >> 8);
    p[19] = (uint8_t)plen;
    p[20] = nxt;
    p[21] = hop;
    for (int i = 0; i < 16; i++) {
        p[22 + i] = src[i];
        p[38 + i] = dst[i];
    }
}

// Isi checksum ICMPv6/UDP di l4[off..off+1] lalu kirim frame (min 60 byte). 1 = terkirim.
static int ip6_finish(uint8_t *p, uint8_t nxt, uint32_t plen, uint32_t csum_off)
{
    uint8_t *l4 = p + 54;
    uint32_t flen = 54 + plen;

    l4[csum_off] = l4[csum_off + 1] = 0;
    uint16_t c = ip6_l4_checksum(p + 22, p + 38, nxt, l4, plen);

    if (nxt == 17 && c == 0) {
        c = 0xFFFF;
    }
    l4[csum_off] = (uint8_t)(c >> 8);
    l4[csum_off + 1] = (uint8_t)c;
    for (uint32_t i = flen; i < 60; i++) {
        p[i] = 0;
    }
    return e1000_tx_send(g_net_tx_buf_phys, flen < 60 ? 60 : flen);
}

// NS DAD: dari :: ke solicited-node kita, target = alamat kita (24 byte, tanpa opsi).
static void ip6_send_dad_ns(void)
{
    static const uint8_t zero[16] = { 0 };
    uint8_t *p = ip6_txbuf();

    if (!p) {
        return;
    }
    ip6_hdr(p, g_ip6_snmac, zero, g_ip6_snmc, 58, 255, 24);
    for (int i = 0; i < 24; i++) {
        p[54 + i] = 0;
    }
    p[54] = 135;
    memcpy(p + 54 + 8, g_ip6_ll, 16);
    ip6_finish(p, 58, 24, 2);
}

// NA untuk alamat kita (32 byte: 24 + TLLA). flags: 0x60 S|O (balasan), 0x20 O (tak diminta).
static void ip6_send_na(const uint8_t *dst_mac, const volatile uint8_t *dst, uint8_t flags)
{
    uint8_t d[16];
    uint8_t *p = ip6_txbuf();

    if (!p) {
        return;
    }
    for (int i = 0; i < 16; i++) {
        d[i] = dst[i];
    }
    ip6_hdr(p, dst_mac, g_ip6_ll, d, 58, 255, 32);
    for (int i = 0; i < 32; i++) {
        p[54 + i] = 0;
    }
    p[54] = 136;
    p[58] = flags;
    memcpy(p + 54 + 8, g_ip6_ll, 16);
    p[54 + 24] = 2;
    p[54 + 25] = 1;
    memcpy(p + 54 + 26, g_e1000_mac, 6);
    if (ip6_finish(p, 58, 32, 2)) {
        g_nd_na_tx++;
    }
}

static void ip6_conflict(const volatile uint8_t *mac)
{
    char a[40];

    g_ip6_state = IP6_CONFLICT;
    g_ip6_dad_conflict++;
    ip6_fmt(a, sizeof(a), g_ip6_ll);
    kprintf("IPv6: DAD GAGAL: %s dipakai host lain (MAC %02x:%02x:%02x:%02x:%02x:%02x), "
            "IPv6 dinonaktifkan\r\n", a, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Sesudah config_load, di net task sebelum modul jaringan lain mengirim.
void ip6_init(void)
{
    char a[40];

    memset(g_ip6_neigh, 0, sizeof(g_ip6_neigh));
    memset(g_ip6_src, 0, sizeof(g_ip6_src));
    g_ip6_state = IP6_OFF;
    if (!g_ip6_cfg || !g_e1000_rx_initialized) {
        kprintf("IPv6: nonaktif (ipv6=0 bawaan; set ipv6 1 lalu reboot)\r\n");
        return;
    }
    memset(g_ip6_ll, 0, 16);
    g_ip6_ll[0] = 0xfe;
    g_ip6_ll[1] = 0x80;
    g_ip6_ll[8] = g_e1000_mac[0] ^ 0x02;   // EUI-64: balik bit U/L
    g_ip6_ll[9] = g_e1000_mac[1];
    g_ip6_ll[10] = g_e1000_mac[2];
    g_ip6_ll[11] = 0xff;
    g_ip6_ll[12] = 0xfe;
    g_ip6_ll[13] = g_e1000_mac[3];
    g_ip6_ll[14] = g_e1000_mac[4];
    g_ip6_ll[15] = g_e1000_mac[5];
    memset(g_ip6_snmc, 0, 16);
    g_ip6_snmc[0] = 0xff;
    g_ip6_snmc[1] = 0x02;
    g_ip6_snmc[11] = 0x01;
    g_ip6_snmc[12] = 0xff;
    g_ip6_snmc[13] = g_ip6_ll[13];
    g_ip6_snmc[14] = g_ip6_ll[14];
    g_ip6_snmc[15] = g_ip6_ll[15];
    g_ip6_snmac[0] = 0x33;
    g_ip6_snmac[1] = 0x33;
    g_ip6_snmac[2] = 0xff;
    g_ip6_snmac[3] = g_ip6_ll[13];
    g_ip6_snmac[4] = g_ip6_ll[14];
    g_ip6_snmac[5] = g_ip6_ll[15];
    g_ip6_probes = 0;
    g_ip6_next = timer_ticks;
    g_ip6_state = IP6_DAD;
    ip6_fmt(a, sizeof(a), g_ip6_ll);
    kprintf("IPv6: link-local %s, DAD mulai (%u probe, jeda %u tick)\r\n", a,
            (unsigned)IP6_DAD_PROBES, (unsigned)IP6_DAD_TICKS);
}

// Dari loop net task: kirim probe DAD berikutnya atau selesaikan DAD.
void ip6_poll(void)
{
    char a[40];

    if (g_ip6_state != IP6_DAD || timer_ticks < g_ip6_next) {
        return;
    }
    if (g_ip6_probes < IP6_DAD_PROBES) {
        ip6_send_dad_ns();
        g_ip6_probes++;
        g_ip6_next = timer_ticks + IP6_DAD_TICKS;
        return;
    }
    g_ip6_state = IP6_UP;
    ip6_fmt(a, sizeof(a), g_ip6_ll);
    kprintf("IPv6: DAD selesai, %s aktif\r\n", a);
}

// Opsi ND (RFC 4861 4.6) pada icmp[off..plen): panjang 0 atau melewati batas = rusak
// (-1). Mengembalikan penunjuk data link-layer (6 byte) opsi tipe `want`, atau 0.
static int ip6_nd_opts(const volatile uint8_t *icmp, uint32_t plen, uint8_t want,
                       const volatile uint8_t **ll)
{
    uint32_t off = 24;

    *ll = 0;
    while (off < plen) {
        if (off + 2 > plen) {
            return -1;
        }
        uint32_t olen = (uint32_t)icmp[off + 1] * 8;

        if (olen == 0 || off + olen > plen) {
            return -1;
        }
        if (icmp[off] == want && olen == 8 && *ll == 0) {
            *ll = icmp + off + 2;
        }
        off += olen;
    }
    return 0;
}

// Jatah global IPv6 sendiri (jendela 100 tick, sebesar jatah UDP IPv4): tidak menyentuh
// g_net_budget_* maupun g_net_udp_dropped IPv4. Hanya frame yang akan dijawab
// (echo, NS, NA, UDP ke 7777 untuk kita) memakainya.
static uint64_t g_ip6_bwin;
static uint32_t g_ip6_bused;

static int ip6_budget_ok(void)
{
    uint64_t now = timer_ticks;

    if (now - g_ip6_bwin >= 100) {
        g_ip6_bwin = now;
        g_ip6_bused = 0;
    }
    if (g_ip6_bused >= NET_UDP_BUDGET_PER_SEC) {
        return 0;
    }
    g_ip6_bused++;
    return 1;
}

static void ip6_icmp(volatile uint8_t *buf, uint32_t plen, int to_us, int to_mc)
{
    volatile uint8_t *l4 = buf + 54;
    volatile uint8_t *src = buf + 22;
    uint8_t type = l4[0];
    int up = g_ip6_state == IP6_UP;

    if (plen < 8) {
        g_ip6_drop++;
        return;
    }
    // Hanya echo (butuh UP) dan ND yang diproses; sisanya (RA, RS, Redirect, MLD, ...)
    // diabaikan sebelum checksum.
    if (type != 128 && type != 135 && type != 136) {
        return;
    }
    if (ip6_l4_checksum(src, buf + 38, 58, l4, plen) != 0) {
        g_ip6_badsum++;
        return;
    }

    if (type == 128) {
        if (!up || !to_us || l4[1] != 0) {
            return;
        }
        uint8_t *p = ip6_txbuf();

        if (!p) {
            return;
        }
        {
            char a[40];

            ip6_fmt(a, sizeof(a), src);
            kprintf("IPv6: ICMPv6 echo request dari %s seq=%x\r\n", a,
                    ((uint32_t)l4[6] << 8) | l4[7]);
        }
        ip6_hdr(p, (const uint8_t *)buf + 6, g_ip6_ll, (const uint8_t *)src, 58, 64, plen);
        for (uint32_t i = 0; i < plen; i++) {
            p[54 + i] = l4[i];
        }
        p[54] = 129;
        if (ip6_finish(p, 58, plen, 2)) {
            g_icmp6_echo++;
        }
        return;
    }

    // ND: hop limit 255 (tidak mungkin dilewati router), kode 0, panjang >= 24.
    if (buf[21] != 255 || l4[1] != 0 || plen < 24 || l4[8] == 0xff) {
        g_nd_bad++;
        return;
    }
    const volatile uint8_t *target = l4 + 8;
    const volatile uint8_t *lladdr;

    if (type == 135) {
        int unspec = ip6_is_zero(src);

        if (ip6_nd_opts(l4, plen, 1, &lladdr) < 0 ||
            (unspec && (lladdr || !ip6_eq(buf + 38, g_ip6_snmc))) ||
            (!unspec && to_mc && !lladdr)) {
            g_nd_bad++;
            return;
        }
        // SLLA harus sama dengan MAC sumber Ethernet: kalau tidak, NA akan dipantulkan
        // ke MAC korban dan cache tetangga bisa diracuni.
        if (lladdr) {
            for (int i = 0; i < 6; i++) {
                if (lladdr[i] != buf[6 + i]) {
                    g_nd_bad++;
                    return;
                }
            }
        }
        g_nd_ns_rx++;
        if (!ip6_eq(target, g_ip6_ll)) {
            return;
        }
        if (g_ip6_state == IP6_DAD) {
            if (unspec) {
                ip6_conflict(buf + 6);   // tetangga juga sedang probe alamat yang sama
            }
            return;
        }
        if (!up) {
            return;
        }
        if (unspec) {
            ip6_send_na(IP6_ALLNODES_MAC, IP6_ALLNODES, 0x20);
            return;
        }
        const volatile uint8_t *mac = lladdr ? lladdr : buf + 6;

        if (lladdr) {
            ip6_neigh_put(src, lladdr, 1);
        }
        {
            uint8_t m[6];

            for (int i = 0; i < 6; i++) {
                m[i] = mac[i];
            }
            ip6_send_na(m, src, 0x60);
        }
        return;
    }

    // NA (136): S=1 dengan tujuan multicast tidak sah.
    if (ip6_nd_opts(l4, plen, 2, &lladdr) < 0 || ((l4[4] & 0x40) && to_mc)) {
        g_nd_bad++;
        return;
    }
    g_nd_na_rx++;
    if (g_ip6_state == IP6_DAD && ip6_eq(target, g_ip6_ll)) {
        ip6_conflict(lladdr ? lladdr : buf + 6);
        return;
    }
    if (lladdr) {
        ip6_neigh_put(target, lladdr, 0);
    }
}

static void ip6_udp(volatile uint8_t *buf, uint32_t plen, int to_us)
{
    volatile uint8_t *l4 = buf + 54;

    // plen >= 8 dulu: header UDP tidak boleh dibaca dari muatan yang lebih pendek
    // (temuan fuzz_net, tests/fuzz/regress/net/udp6-pendek).
    if (g_ip6_state != IP6_UP || !to_us || plen < 8) {
        g_ip6_drop++;
        return;
    }

    uint32_t sport = ((uint32_t)l4[0] << 8) | l4[1];
    uint32_t dport = ((uint32_t)l4[2] << 8) | l4[3];
    uint32_t ulen = ((uint32_t)l4[4] << 8) | l4[5];
    uint32_t csum = ((uint32_t)l4[6] << 8) | l4[7];

    if (ulen != plen) {
        g_ip6_drop++;
        return;
    }
    if (dport != 7777 || !g_net_echo) {
        g_ip6_drop++;   // satu-satunya layanan IPv6; 7778/soket user tidak lewat IPv6
        return;
    }
    // IPv6 mewajibkan checksum UDP (RFC 8200 8.1): nol atau salah dibuang.
    if (csum == 0 || ip6_l4_checksum(buf + 22, buf + 38, 17, l4, plen) != 0) {
        g_ip6_badsum++;
        return;
    }
    uint8_t *p = ip6_txbuf();

    if (!p) {
        return;
    }
    {
        char a[40];

        ip6_fmt(a, sizeof(a), buf + 22);
        kprintf("IPv6: UDP echo port 7777 dari %s src_port=%x payload=%x byte\r\n", a, sport,
                plen - 8);
    }
    ip6_hdr(p, (const uint8_t *)buf + 6, g_ip6_ll, (const uint8_t *)(buf + 22), 17, 64, plen);
    p[54] = (uint8_t)(dport >> 8);
    p[55] = (uint8_t)dport;
    p[56] = (uint8_t)(sport >> 8);
    p[57] = (uint8_t)sport;
    p[58] = (uint8_t)(plen >> 8);
    p[59] = (uint8_t)plen;
    for (uint32_t i = 8; i < plen; i++) {
        p[54 + i] = l4[i];
    }
    if (ip6_finish(p, 17, plen, 6)) {
        g_udp6_echo++;
    }
}

// Dari net_rx_dispatch untuk EtherType 0x86DD; len = panjang frame.
void ip6_rx(volatile uint8_t *buf, uint32_t len)
{
    if (g_ip6_state == IP6_OFF) {
        g_ip6_off++;
        return;
    }
    if (g_ip6_state == IP6_CONFLICT) {
        g_ip6_drop++;   // konflik DAD: IPv6 mati sampai reboot, frame dihitung dibuang
        return;
    }
    g_ip6_rx++;
    if (len < 54 || (buf[14] >> 4) != 6) {
        g_ip6_drop++;
        return;
    }

    uint32_t plen = ((uint32_t)buf[18] << 8) | buf[19];
    uint8_t nxt = buf[20];
    volatile uint8_t *src = buf + 22;
    volatile uint8_t *dst = buf + 38;

    // plen 0 (jumbogram/hop-by-hop) dan frame terpotong dibuang; padding Ethernet
    // sesudah muatan boleh.
    if (plen == 0 || plen > IP6_PAYLOAD_MAX || 54 + plen > len) {
        g_ip6_drop++;
        return;
    }

    int to_us = ip6_eq(dst, g_ip6_ll);
    int to_mc = ip6_eq(dst, g_ip6_snmc) || ip6_eq(dst, IP6_ALLNODES);

    if (!to_us && !to_mc) {
        g_ip6_ignored++;   // lalu lintas host lain (NIC promiscuous): bukan urusan kita
        return;
    }
    // Sumber: link-local se-link; :: hanya untuk NS (DAD tetangga). Alamat kita
    // sendiri (pantulan), multicast, loopback, global: dibuang.
    if (ip6_is_zero(src)) {
        if (nxt != 58 || buf[54] != 135) {
            g_ip6_drop++;
            return;
        }
    } else if (src[0] != 0xfe || (src[1] & 0xC0) != 0x80 || ip6_eq(src, g_ip6_ll)) {
        g_ip6_drop++;
        return;
    }
    if (buf[21] == 0) {
        g_ip6_drop++;
        return;
    }
    if (nxt == 6) {
        g_ip6_tcp_drop++;   // TCP belum lewat IPv6 (tanpa RST: gagal tertutup)
        return;
    }
    if (nxt != 58 && nxt != 17) {
        g_ip6_nxt_drop++;   // header ekstensi, fragmen, protokol lain
        return;
    }
    // Saring dulu, jatah belakangan: hanya frame yang akan diproses (ICMPv6 128/135/136,
    // UDP ke kita port 7777) memakai jatah. RA, MLD dan tipe lain tidak mengurangi apa pun.
    int cost = 0;

    if (nxt == 58) {
        uint8_t type = buf[54];

        if (plen < 8) {
            g_ip6_drop++;
            return;
        }
        if (type != 128 && type != 135 && type != 136) {
            g_ip6_ignored++;
            return;
        }
        // NS/NA yang MAC sumbernya MAC kita sendiri: pantulan (DAD terpantul, RFC 4862
        // 5.4.3), bukan tetangga. Bukan konflik.
        if (type != 128) {
            int own = 1;

            for (int i = 0; i < 6; i++) {
                own &= buf[6 + i] == g_e1000_mac[i];
            }
            if (own) {
                g_ip6_ignored++;
                return;
            }
        }
        cost = 1;
    } else {
        cost = to_us && plen >= 8 && g_ip6_state == IP6_UP && g_net_echo &&
               ((((uint32_t)buf[56] << 8) | buf[57]) == 7777);
    }
    // B4: per sumber lalu global (jatah IPv6 sendiri), sebelum checksum dan balasan.
    if (cost && (!net_src_budget_take(g_ip6_src, IP6_SRC_SLOTS, src, 16) || !ip6_budget_ok())) {
        g_ip6_rate_drop++;
        return;
    }
    if (nxt == 58) {
        ip6_icmp(buf, plen, to_us, to_mc);
    } else {
        ip6_udp(buf, plen, to_us);
    }
}

uint64_t ip6_up_metric(void)
{
    return g_ip6_state == IP6_UP;
}

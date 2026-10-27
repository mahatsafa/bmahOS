#include "kernel.h"

// P4: packet filter. Aturan (maks FILTER_MAX) diperiksa berurutan; aturan
// pertama yang cocok menentukan, tanpa aturan yang cocok -> izinkan (perilaku
// sebelum P4). Diperiksa di net_handle_ipv4 setelah checksum header, sebelum
// batas laju UDP, untuk UDP, ICMP, dan segmen TCP SYN tanpa ACK (koneksi
// baru); segmen koneksi yang sudah berjalan tidak disentuh. TCP ke
// FILTER_MGMT_PORT (TLS 7780) selalu lolos, supaya admin tidak bisa mengunci
// diri sendiri dari jarak jauh. Paket yang ditolak dibuang diam-diam (tanpa
// RST/ICMP), hanya dihitung.
//
// Sintaks satu aturan (juga satu baris FILTER.CFG, '#' = komentar):
//   <izinkan|tolak> <semua|tcp|udp|icmp> <semua|a.b.c.d[/n]> [port A[-B]] [laju N]
// port hanya cocok dengan paket TCP/UDP; laju N = paling banyak N paket per
// jendela 100 tick untuk aturan itu (total, bukan per IP), sisanya dibuang.
// FILTER.CFG dengan satu baris salah diabaikan seluruhnya (tanpa aturan) dan
// alasannya dicatat di serial, sama seperti CONFIG.CFG (D7).

#define FILTER_MAX       16
#define FILTER_FILE_MAX  1536   // 16 aturan terpanjang (61 byte) + header < 1100
#define FILTER_MGMT_PORT 7780
#define FILTER_RATE_MAX  10000

typedef struct {
    uint8_t allow;           // 1 izinkan, 0 tolak
    uint8_t proto;           // 0 semua, 1 icmp, 6 tcp, 17 udp
    uint8_t prefix;          // 0..32
    uint8_t has_port;
    uint32_t ip;             // urutan host, sudah di-mask prefix
    uint16_t port_lo, port_hi;
    uint32_t rate;           // 0 = tanpa batas
    uint64_t window;
    uint32_t used;
    uint64_t hits, dropped;
} filter_rule_t;

static filter_rule_t g_filter[FILTER_MAX];
static uint32_t g_filter_n;
static uint8_t g_filter_buf[FILTER_FILE_MAX];
static const char *g_filter_src = "belum dimuat";
uint64_t g_filter_drop;      // total paket yang dibuang filter

static uint32_t flt_mask(uint32_t prefix)
{
    return prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
}

// Token berikutnya (dipisah spasi) dari s[*pos..n).
static int flt_tok(const uint8_t *s, uint32_t n, uint32_t *pos, const uint8_t **t, uint32_t *tl)
{
    while (*pos < n && s[*pos] == ' ') {
        (*pos)++;
    }
    if (*pos >= n) {
        return 0;
    }
    *t = s + *pos;
    while (*pos < n && s[*pos] != ' ') {
        (*pos)++;
    }
    *tl = (uint32_t)(s + *pos - *t);
    return 1;
}

static int flt_eq(const uint8_t *t, uint32_t tl, const char *w)
{
    uint32_t i = 0;

    for (; i < tl && w[i]; i++) {
        if (t[i] != (uint8_t)w[i]) {
            return 0;
        }
    }
    return i == tl && w[i] == 0;
}

// Angka desimal tanpa tanda, 1..10 digit, <= max. 1 = OK.
static int flt_num(const uint8_t *t, uint32_t tl, uint32_t max, uint32_t *out)
{
    uint64_t v = 0;

    if (tl == 0 || tl > 10) {
        return 0;
    }
    for (uint32_t i = 0; i < tl; i++) {
        if (t[i] < '0' || t[i] > '9') {
            return 0;
        }
        v = v * 10 + (uint32_t)(t[i] - '0');
    }
    if (v > max) {
        return 0;
    }
    *out = (uint32_t)v;
    return 1;
}

// "a.b.c.d" atau "a.b.c.d/n". Bit di luar prefix harus 0 (192.168.50.7/24
// ditolak supaya maksud aturan tidak ambigu).
static int flt_ip(const uint8_t *t, uint32_t tl, uint32_t *ip, uint8_t *prefix)
{
    uint32_t v = 0, part = 0, octets = 0, i = 0, start = 0, pfx = 32;

    for (; i <= tl; i++) {
        if (i == tl || t[i] == '.' || t[i] == '/') {
            if (!flt_num(t + start, i - start, 255, &part) || i - start > 3) {
                return 0;
            }
            v = (v << 8) | part;
            octets++;
            start = i + 1;
            if (i < tl && t[i] == '/') {
                break;
            }
            if (i == tl) {
                break;
            }
            if (octets == 4) {
                return 0;
            }
        }
    }
    if (octets != 4) {
        return 0;
    }
    if (i < tl) {   // '/'
        if (!flt_num(t + i + 1, tl - i - 1, 32, &pfx) || tl - i - 1 > 2) {
            return 0;
        }
    }
    if ((v & ~flt_mask(pfx)) != 0) {
        return 0;
    }
    *ip = v;
    *prefix = (uint8_t)pfx;
    return 1;
}

// Satu aturan teks -> r. Alasan gagal di *why. 1 = OK.
static int filter_parse_rule(const uint8_t *s, uint32_t n, filter_rule_t *r, const char **why)
{
    uint32_t pos = 0, tl, v;
    const uint8_t *t;

    memset(r, 0, sizeof(*r));
    *why = "aksi harus izinkan|tolak";
    if (!flt_tok(s, n, &pos, &t, &tl)) {
        *why = "aturan kosong";
        return 0;
    }
    if (flt_eq(t, tl, "izinkan")) {
        r->allow = 1;
    } else if (!flt_eq(t, tl, "tolak")) {
        return 0;
    }

    *why = "protokol harus semua|tcp|udp|icmp";
    if (!flt_tok(s, n, &pos, &t, &tl)) {
        return 0;
    }
    if (flt_eq(t, tl, "tcp")) {
        r->proto = 6;
    } else if (flt_eq(t, tl, "udp")) {
        r->proto = 17;
    } else if (flt_eq(t, tl, "icmp")) {
        r->proto = 1;
    } else if (!flt_eq(t, tl, "semua")) {
        return 0;
    }

    *why = "sumber harus semua atau a.b.c.d[/n] (bit host 0)";
    if (!flt_tok(s, n, &pos, &t, &tl)) {
        return 0;
    }
    if (!flt_eq(t, tl, "semua") && !flt_ip(t, tl, &r->ip, &r->prefix)) {
        return 0;
    }

    while (flt_tok(s, n, &pos, &t, &tl)) {
        if (flt_eq(t, tl, "port") && !r->has_port && !r->rate) {
            *why = "port A atau A-B (0..65535, A <= B), bukan untuk icmp";
            if (r->proto == 1 || !flt_tok(s, n, &pos, &t, &tl)) {
                return 0;
            }
            uint32_t dash = 0;
            while (dash < tl && t[dash] != '-') {
                dash++;
            }
            uint32_t lo, hi;
            if (!flt_num(t, dash, 65535, &lo)) {
                return 0;
            }
            hi = lo;
            if (dash < tl && !flt_num(t + dash + 1, tl - dash - 1, 65535, &hi)) {
                return 0;
            }
            if (lo > hi) {
                return 0;
            }
            r->has_port = 1;
            r->port_lo = (uint16_t)lo;
            r->port_hi = (uint16_t)hi;
        } else if (flt_eq(t, tl, "laju") && !r->rate) {
            *why = "laju N (1..10000), hanya untuk izinkan";
            if (!r->allow || !flt_tok(s, n, &pos, &t, &tl) ||
                !flt_num(t, tl, FILTER_RATE_MAX, &v) || v == 0) {
                return 0;
            }
            r->rate = v;
        } else {
            *why = "kata tak dikenal (port/laju, urutan port lalu laju, sekali saja)";
            return 0;
        }
    }
    return 1;
}

// Bentuk kanonik (dipakai `filter` dan saat menulis FILTER.CFG).
static void flt_fmt(const filter_rule_t *r, char *b, uint32_t max)
{
    static const char *const pn[] = { "semua", "icmp", "tcp", "udp" };
    const char *p = pn[r->proto == 1 ? 1 : r->proto == 6 ? 2 : r->proto == 17 ? 3 : 0];
    uint32_t len;

    if (r->prefix == 0) {
        len = (uint32_t)ksnprintf(b, max, "%s %s semua", r->allow ? "izinkan" : "tolak", p);
    } else {
        len = (uint32_t)ksnprintf(b, max, "%s %s %u.%u.%u.%u/%u", r->allow ? "izinkan" : "tolak",
                                  p, r->ip >> 24, (r->ip >> 16) & 0xFF, (r->ip >> 8) & 0xFF,
                                  r->ip & 0xFF, (unsigned)r->prefix);
    }
    if (r->has_port && len < max) {
        if (r->port_lo == r->port_hi) {
            len += (uint32_t)ksnprintf(b + len, max - len, " port %u", (unsigned)r->port_lo);
        } else {
            len += (uint32_t)ksnprintf(b + len, max - len, " port %u-%u",
                                       (unsigned)r->port_lo, (unsigned)r->port_hi);
        }
    }
    if (r->rate && len < max) {
        ksnprintf(b + len, max - len, " laju %u", r->rate);
    }
}

// Isi FILTER.CFG -> aturan. 1 = OK; 0 = ditolak (*bad_line, *why).
static int filter_parse(const uint8_t *b, uint32_t len, filter_rule_t *out, uint32_t *nout,
                        uint32_t *bad_line, const char **why)
{
    uint32_t line = 0, n = 0, i = 0;

    *bad_line = 0;
    while (i < len) {
        uint32_t s = i;
        while (i < len && b[i] != '\n') {
            i++;
        }
        uint32_t e = i;
        i++;   // lewati '\n'
        line++;
        if (e > s && b[e - 1] == '\r') {
            e--;
        }
        uint32_t k = s;
        while (k < e && b[k] == ' ') {
            k++;
        }
        if (k == e || b[k] == '#') {
            continue;
        }
        if (n >= FILTER_MAX) {
            *bad_line = line;
            *why = "lebih dari 16 aturan";
            return 0;
        }
        if (!filter_parse_rule(b + k, e - k, &out[n], why)) {
            *bad_line = line;
            return 0;
        }
        n++;
    }
    *nout = n;
    return 1;
}

void filter_load(void)
{
    uint32_t size = 0, bad = 0, n = 0;
    const char *why = "";
    int rc = fat32_read_name("FILTER  CFG", g_filter_buf, sizeof(g_filter_buf), &size);

    g_filter_n = 0;
    if (rc == FAT32_OK && filter_parse(g_filter_buf, size, g_filter, &n, &bad, &why)) {
        g_filter_n = n;
        g_filter_src = "disk";
        kprintf("P4: filter sumber=disk aturan=%u\r\n", n);
        return;
    }
    if (rc == FAT32_OK) {
        g_filter_src = "FILTER.CFG ditolak";
        kprintf("P4: FILTER.CFG ditolak baris %u (%s), tanpa aturan\r\n", bad, why);
    } else if (rc == FAT32_ERR_TOOBIG) {
        g_filter_src = "FILTER.CFG ditolak";
        kprintf("P4: FILTER.CFG > %u byte, tanpa aturan\r\n", (unsigned)FILTER_FILE_MAX);
    } else {
        g_filter_src = rc == FAT32_ERR_NOENT ? "tanpa file" :
                       rc == FAT32_ERR_NOVOL ? "tanpa disk" : "galat baca disk";
        kprintf("P4: filter tanpa aturan (%s)\r\n", g_filter_src);
    }
}

// 1 = lolos, 0 = buang. ip_src = 4 byte urutan jaringan; dport hanya
// berarti untuk TCP/UDP.
int filter_check(const volatile uint8_t *ip_src, uint8_t proto, uint16_t dport)
{
    if (proto == 6 && dport == FILTER_MGMT_PORT) {
        return 1;
    }
    uint32_t src = ((uint32_t)ip_src[0] << 24) | ((uint32_t)ip_src[1] << 16) |
                   ((uint32_t)ip_src[2] << 8) | (uint32_t)ip_src[3];

    for (uint32_t i = 0; i < g_filter_n; i++) {
        filter_rule_t *r = &g_filter[i];

        if (r->proto != 0 && r->proto != proto) {
            continue;
        }
        if ((src & flt_mask(r->prefix)) != r->ip) {
            continue;
        }
        if (r->has_port && ((proto != 6 && proto != 17) ||
                            dport < r->port_lo || dport > r->port_hi)) {
            continue;
        }
        r->hits++;
        if (r->allow && r->rate) {
            uint64_t now = timer_ticks;
            if (now - r->window >= 100) {
                r->window = now;
                r->used = 0;
            }
            if (r->used >= r->rate) {
                r->dropped++;
                g_filter_drop++;
                return 0;
            }
            r->used++;
        }
        if (!r->allow) {
            r->dropped++;
            g_filter_drop++;
            return 0;
        }
        return 1;
    }
    return 1;
}

// Dipanggil net_handle_ipv4 (header IPv4 sah, tujuan IP kita). Paket yang
// terlalu pendek untuk dibaca portnya dibiarkan lewat (ditolak di jalur
// protokolnya sendiri).
int filter_ipv4(const volatile uint8_t *buf, uint32_t ihl, uint32_t payload_len)
{
    uint8_t proto = buf[23];
    const volatile uint8_t *l4 = buf + 14 + ihl;

    if (g_filter_n == 0) {
        return 1;
    }
    if (proto == 17 && payload_len >= 8) {
        return filter_check(buf + 26, 17, (uint16_t)((l4[2] << 8) | l4[3]));
    }
    if (proto == 6 && payload_len >= 20) {
        if ((l4[13] & 0x12) != 0x02) {   // bukan SYN tanpa ACK: koneksi berjalan
            return 1;
        }
        return filter_check(buf + 26, 6, (uint16_t)((l4[2] << 8) | l4[3]));
    }
    if (proto == 1) {
        return filter_check(buf + 26, 1, 0);
    }
    return 1;
}

static void flt_list(void)
{
    char line[160];

    // 16 aturan terpanjang + hitungan wajar < CMD_OUT_MAX (1400).
    ksnprintf(line, sizeof(line), "filter: aturan=%u dibuang=%lu sumber=%s [cocok/dibuang]; "
              "tanpa cocok: izinkan; tcp %u selalu lolos\n", g_filter_n, g_filter_drop,
              g_filter_src, (unsigned)FILTER_MGMT_PORT);
    cmd_puts(line);
    for (uint32_t i = 0; i < g_filter_n; i++) {
        char rule[64];
        flt_fmt(&g_filter[i], rule, sizeof(rule));
        ksnprintf(line, sizeof(line), "%u: %s [%lu/%lu]\n", i + 1, rule,
                  g_filter[i].hits, g_filter[i].dropped);
        cmd_puts(line);
    }
}

// Tulis aturan rules[0..n) ke FILTER.CFG (atomik lewat FILTER.TMP). 1 = OK.
static int flt_save(const filter_rule_t *rules, uint32_t n)
{
    uint32_t len = (uint32_t)ksnprintf((char *)g_filter_buf, sizeof(g_filter_buf),
                                       "# bmahOS FILTER.CFG (ditulis oleh perintah filter)\n");

    for (uint32_t i = 0; i < n; i++) {
        char rule[64];
        flt_fmt(&rules[i], rule, sizeof(rule));
        len += (uint32_t)ksnprintf((char *)g_filter_buf + len, sizeof(g_filter_buf) - len,
                                   "%s\n", rule);
    }
    if (len >= sizeof(g_filter_buf)) {   // tidak terjadi untuk 16 aturan (lihat FILTER_FILE_MAX)
        cmd_puts("ERR: filter: FILTER.CFG terlalu besar, aturan tidak diubah\n");
        return 0;
    }
    int rc = fat32_replace_name("FILTER  CFG", "FILTER  TMP", g_filter_buf, len);

    if (rc != FAT32_OK) {
        cmd_puts("ERR: filter: tidak tersimpan, aturan tidak diubah (fs: ");
        cmd_puts(fscmd_strerror(rc));
        cmd_puts(")\n");
        return 0;
    }
    return 1;
}

// `filter` (baca, juga peran ro), `filter tambah <aturan>`, `filter hapus <n>`,
// `filter kosong` (admin; aturan RAM hanya diubah bila FILTER.CFG tersimpan).
// Penghitung aturan yang tersisa ikut terbawa saat hapus.
int filter_execute(const volatile uint8_t *cmd, uint32_t len)
{
    static filter_rule_t nr[FILTER_MAX];
    uint8_t c[64];
    const char *why = "";

    if (net_cmd_is(cmd, len, "filter")) {
        g_cmd_len = 0;
        flt_list();
        return 1;
    }
    if (len < 7 || !net_cmd_is(cmd, 7, "filter ")) {
        return 0;
    }
    g_cmd_len = 0;
    if (len - 7 > sizeof(c)) {
        cmd_puts("ERR: filter: terlalu panjang\n");
        return 1;
    }
    for (uint32_t i = 7; i < len; i++) {
        c[i - 7] = cmd[i];
    }
    uint32_t n = len - 7;

    if (n > 7 && net_cmd_is(c, 7, "tambah ")) {
        if (g_filter_n >= FILTER_MAX) {
            cmd_puts("ERR: filter: penuh (maks 16 aturan)\n");
            return 1;
        }
        if (!filter_parse_rule(c + 7, n - 7, &nr[g_filter_n], &why)) {
            cmd_puts("ERR: filter: ");
            cmd_puts(why);
            cmd_puts("\n");
            return 1;
        }
        memcpy(nr, g_filter, sizeof(filter_rule_t) * g_filter_n);
        if (!flt_save(nr, g_filter_n + 1)) {
            return 1;
        }
        g_filter[g_filter_n] = nr[g_filter_n];
        g_filter_n++;
        g_filter_src = "disk";
        char rule[64], line[112];
        flt_fmt(&g_filter[g_filter_n - 1], rule, sizeof(rule));
        ksnprintf(line, sizeof(line), "OK filter %u: %s (tersimpan)\n", g_filter_n, rule);
        cmd_puts(line);
        return 1;
    }
    if (n > 6 && net_cmd_is(c, 6, "hapus ")) {
        uint32_t k;
        if (!flt_num(c + 6, n - 6, FILTER_MAX, &k) || k == 0 || k > g_filter_n) {
            cmd_puts("ERR: filter: hapus <nomor aturan 1..n>\n");
            return 1;
        }
        uint32_t m = 0;
        for (uint32_t i = 0; i < g_filter_n; i++) {
            if (i != k - 1) {
                nr[m++] = g_filter[i];
            }
        }
        if (!flt_save(nr, m)) {
            return 1;
        }
        memcpy(g_filter, nr, sizeof(filter_rule_t) * m);
        g_filter_n = m;
        g_filter_src = "disk";
        char line[64];
        ksnprintf(line, sizeof(line), "OK filter: aturan %u dihapus, sisa %u (tersimpan)\n", k, m);
        cmd_puts(line);
        return 1;
    }
    if (net_cmd_is(c, n, "kosong")) {
        if (!flt_save(nr, 0)) {
            return 1;
        }
        g_filter_n = 0;
        g_filter_src = "disk";
        cmd_puts("OK filter: semua aturan dihapus (tersimpan)\n");
        return 1;
    }
    cmd_puts("ERR: filter: filter | filter tambah <aturan> | filter hapus <n> | filter kosong\n");
    return 1;
}

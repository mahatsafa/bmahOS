#include "kernel.h"

// D7: konfigurasi persisten di CONFIG.CFG (root FAT32), dibaca sekali saat
// boot (config_load, setelah auth_load_key) dan ditulis ulang utuh oleh
// perintah admin `set` lewat fat32_replace_name (CONFIG.TMP lalu satu tulis
// sektor). Format: teks ASCII, satu "kunci=nilai" per baris, LF (CR di
// akhir baris dibuang), baris kosong dan "#..." diabaikan, maks
// CFG_FILE_MAX byte. Satu baris salah -> SELURUH file ditolak, semua nilai
// bawaan (gagal tertutup; default = nilai hardcode sebelum D7).
//   config              nilai efektif + sumbernya (admin dan read-only)
//   set KUNCI NILAI     simpan + terapkan (admin); NILAI "-" = default
// Nilai di RAM hanya berubah bila file berhasil ditulis.

#define CFG_FILE_MAX 512
#define CFG_NKEYS    9
#define CFG_K_CLI_PLAIN 3
#define CFG_K_UDP_ADMIN 4

typedef struct {
    const char *key;
    uint32_t min, max, def;
    uint32_t *var;
} cfg_key_t;

static const cfg_key_t g_cfg_keys[CFG_NKEYS] = {
    { "cli_idle", 30, 3600, CFG_CLI_IDLE_DEF, &g_cli_idle_s },       // detik, sesi CLI login
    { "udp_rate", 1, 100, NET_UDP_SRC_PER_SEC, &g_net_src_rate },    // datagram/s per IP
    { "echo", 0, 1, 1, &g_net_echo },                                // TCP 7 + UDP 7777
    { "cli_plain", 0, 1, 1, &g_cli_plain },                          // D9: CLI TCP 7779
    { "udp_admin", 0, 1, 1, &g_udp_admin },                          // D9: UDP selain baca
    { "netcon", 0, 1, 0, &g_netcon_on },                             // R2: netconsole UDP
    { "netcon_host", 1, 254, NETCON_HOST_DEF, &g_netcon_host },      // R2: 192.168.50.x
    { "netcon_port", 1024, 65535, NETCON_PORT_DEF, &g_netcon_port }, // R2
    { "dhcp", 0, 1, 0, &g_dhcp_cfg },                                // P3-4: berlaku saat boot
};

// D9: tanpa TLS aktif, cli_plain=0 + udp_admin=0 menutup semua jalur admin
// jaringan (perbaikan hanya lewat disk saat VM mati). `set` menolaknya;
// file di disk yang berisi kombinasi itu (TLS hilang setelah ditulis) ->
// cli_plain dipaksa 1 saat boot.
static int cfg_admin_lockout(const uint32_t *v)
{
    return !tls_enabled() && v[CFG_K_CLI_PLAIN] == 0 && v[CFG_K_UDP_ADMIN] == 0;
}

enum { CFG_SRC_DEFAULT_NOFILE, CFG_SRC_DEFAULT_NODISK, CFG_SRC_DEFAULT_IO,
       CFG_SRC_REJECTED, CFG_SRC_DISK };

static int g_cfg_src = CFG_SRC_DEFAULT_NODISK;
static uint32_t g_cfg_bad_line = 0;
static const char *g_cfg_why = "";
static uint8_t g_cfg_buf[CFG_FILE_MAX];

static int cfg_key_eq(const uint8_t *s, uint32_t n, const char *k)
{
    uint32_t i = 0;

    while (k[i]) {
        if (i >= n || s[i] != (uint8_t)k[i]) {
            return 0;
        }
        i++;
    }

    return i == n;
}

static int cfg_find(const uint8_t *s, uint32_t n)
{
    for (int k = 0; k < CFG_NKEYS; k++) {
        if (cfg_key_eq(s, n, g_cfg_keys[k].key)) {
            return k;
        }
    }

    return -1;
}

// Desimal 1..5 digit tanpa nol di depan (kecuali "0"). Return 1 bila sah.
static int cfg_num(const uint8_t *s, uint32_t n, uint32_t *out)
{
    uint32_t v = 0;

    if (n == 0 || n > 5 || (n > 1 && s[0] == '0')) {
        return 0;
    }

    for (uint32_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return 0;
        }
        v = v * 10 + (s[i] - '0');
    }

    *out = v;
    return 1;
}

// Uraikan isi file. Return 1 bila sah (out[] = nilai, default untuk kunci
// yang tidak ada); 0 bila ditolak (*bad_line = nomor baris, 0 = seluruh
// file; *why = alasan).
int config_parse(const uint8_t *b, uint32_t len, uint32_t *out, uint32_t *bad_line,
                 const char **why)
{
    uint32_t seen = 0, line = 0, p = 0;

    for (int k = 0; k < CFG_NKEYS; k++) {
        out[k] = g_cfg_keys[k].def;
    }

    *bad_line = 0;

    if (len > CFG_FILE_MAX) {
        *why = "file > 512 byte";
        return 0;
    }

    while (p < len) {
        uint32_t s = p, e;

        while (p < len && b[p] != '\n') {
            p++;
        }
        e = p;
        p++;   // LF (atau lewat akhir file)
        line++;

        if (e > s && b[e - 1] == '\r') {
            e--;
        }

        for (uint32_t i = s; i < e; i++) {
            if (b[i] < 0x20 || b[i] > 0x7e) {
                *bad_line = line;
                *why = "byte bukan ASCII tercetak";
                return 0;
            }
        }

        if (e == s || b[s] == '#') {
            continue;
        }

        uint32_t q = s;

        while (q < e && b[q] != '=') {
            q++;
        }

        int k = q < e ? cfg_find(b + s, q - s) : -1;
        uint32_t v;

        if (k < 0) {
            *bad_line = line;
            *why = q < e ? "kunci tak dikenal" : "bukan kunci=nilai";
            return 0;
        }

        if (seen & (1u << k)) {
            *bad_line = line;
            *why = "kunci ganda";
            return 0;
        }

        if (!cfg_num(b + q + 1, e - q - 1, &v)) {
            *bad_line = line;
            *why = "nilai bukan angka desimal";
            return 0;
        }

        if (v < g_cfg_keys[k].min || v > g_cfg_keys[k].max) {
            *bad_line = line;
            *why = "nilai di luar rentang";
            return 0;
        }

        seen |= 1u << k;
        out[k] = v;
    }

    return 1;
}

static void cfg_apply(const uint32_t *v)
{
    for (int k = 0; k < CFG_NKEYS; k++) {
        *g_cfg_keys[k].var = v[k];
    }
}

// "sumber=..." ke buf.
static void cfg_src_str(char *buf, uint32_t max)
{
    switch (g_cfg_src) {
    case CFG_SRC_DISK:
        ksnprintf(buf, max, "disk");
        break;
    case CFG_SRC_DEFAULT_NOFILE:
        ksnprintf(buf, max, "bawaan (tidak ada file)");
        break;
    case CFG_SRC_DEFAULT_IO:
        ksnprintf(buf, max, "bawaan (error baca disk)");
        break;
    case CFG_SRC_REJECTED:
        if (g_cfg_bad_line) {
            ksnprintf(buf, max, "bawaan (ditolak baris %u: %s)", g_cfg_bad_line, g_cfg_why);
        } else {
            ksnprintf(buf, max, "bawaan (ditolak: %s)", g_cfg_why);
        }
        break;
    default:
        ksnprintf(buf, max, "bawaan (tanpa disk)");
        break;
    }
}

void config_load(void)
{
    uint32_t v[CFG_NKEYS];
    uint32_t size = 0;
    int rc = fat32_read_name("CONFIG  CFG", g_cfg_buf, sizeof(g_cfg_buf), &size);

    g_cfg_bad_line = 0;

    if (rc == FAT32_OK && config_parse(g_cfg_buf, size, v, &g_cfg_bad_line, &g_cfg_why)) {
        g_cfg_src = CFG_SRC_DISK;
    } else {
        for (int k = 0; k < CFG_NKEYS; k++) {
            v[k] = g_cfg_keys[k].def;
        }

        if (rc == FAT32_OK) {
            g_cfg_src = CFG_SRC_REJECTED;
        } else if (rc == FAT32_ERR_TOOBIG) {
            g_cfg_src = CFG_SRC_REJECTED;
            g_cfg_why = "file > 512 byte";
        } else if (rc == FAT32_ERR_NOENT) {
            g_cfg_src = CFG_SRC_DEFAULT_NOFILE;
        } else if (rc == FAT32_ERR_NOVOL) {
            g_cfg_src = CFG_SRC_DEFAULT_NODISK;
        } else {
            g_cfg_src = CFG_SRC_DEFAULT_IO;
        }
    }

    if (cfg_admin_lockout(v)) {
        v[CFG_K_CLI_PLAIN] = 1;
        serial_write("CONFIG: TLS nonaktif, cli_plain dipaksa 1 (jalur admin terakhir)\r\n");
    }
    cfg_apply(v);

    char src[96], line[256];

    cfg_src_str(src, sizeof(src));
    ksnprintf(line, sizeof(line), "CONFIG: sumber=%s cli_idle=%u udp_rate=%u echo=%u "
              "cli_plain=%u udp_admin=%u netcon=%u netcon_host=%u netcon_port=%u dhcp=%u\r\n",
              src, g_cli_idle_s, g_net_src_rate, g_net_echo, g_cli_plain, g_udp_admin, g_netcon_on,
              g_netcon_host, g_netcon_port, g_dhcp_cfg);
    serial_write(line);
}

static void cfg_show(void)
{
    char src[96], t[32];

    cfg_src_str(src, sizeof(src));
    cmd_puts("config: sumber=");
    cmd_puts(src);
    cmd_putc('\n');

    for (int k = 0; k < CFG_NKEYS; k++) {
        ksnprintf(t, sizeof(t), "%s=%u\n", g_cfg_keys[k].key, *g_cfg_keys[k].var);
        cmd_puts(t);
    }
}

// set KUNCI NILAI (c = sesudah "set ").
static void cfg_set(const uint8_t *c, uint32_t n)
{
    uint32_t sp = 0;
    char t[96];

    while (sp < n && c[sp] != ' ') {
        sp++;
    }

    int k = cfg_find(c, sp);

    if (k < 0) {
        cmd_puts("ERR: config: kunci tak dikenal (cli_idle udp_rate echo cli_plain udp_admin "
                 "netcon netcon_host netcon_port dhcp)\n");
        return;
    }

    const cfg_key_t *key = &g_cfg_keys[k];
    uint32_t v;

    if (sp + 2 == n && c[sp + 1] == '-') {
        v = key->def;
    } else if (sp >= n || !cfg_num(c + sp + 1, n - sp - 1, &v) || v < key->min ||
               v > key->max) {
        ksnprintf(t, sizeof(t), "ERR: config: format: set %s %u..%u|-\n", key->key,
                  key->min, key->max);
        cmd_puts(t);
        return;
    }

    uint32_t nv[CFG_NKEYS];
    uint32_t len = 0;

    for (int j = 0; j < CFG_NKEYS; j++) {
        nv[j] = j == k ? v : *g_cfg_keys[j].var;
    }

    if (cfg_admin_lockout(nv)) {
        cmd_puts("ERR: config: TLS nonaktif, cli_plain=0 + udp_admin=0 menutup semua jalur admin\n");
        return;
    }

    len += (uint32_t)ksnprintf((char *)g_cfg_buf, sizeof(g_cfg_buf),
                               "# bmahOS CONFIG.CFG (ditulis oleh perintah set)\n");

    for (int j = 0; j < CFG_NKEYS; j++) {
        len += (uint32_t)ksnprintf((char *)g_cfg_buf + len, sizeof(g_cfg_buf) - len,
                                   "%s=%u\n", g_cfg_keys[j].key, nv[j]);
    }

    int rc = fat32_replace_name("CONFIG  CFG", "CONFIG  TMP", g_cfg_buf, len);

    if (rc != FAT32_OK) {
        cmd_puts("ERR: config: tidak tersimpan, nilai tidak diubah (fs: ");
        cmd_puts(fscmd_strerror(rc));
        cmd_puts(")\n");
        return;
    }

    cfg_apply(nv);
    g_cfg_src = CFG_SRC_DISK;
    ksnprintf(t, sizeof(t), "OK %s=%u (tersimpan)\n", key->key, v);
    cmd_puts(t);
}

int config_execute(const volatile uint8_t *cmd, uint32_t len)
{
    uint8_t c[64];

    if (net_cmd_is(cmd, len, "config")) {
        g_cmd_len = 0;
        cfg_show();
        return 1;
    }

    if (len < 3 || cmd[0] != 's' || cmd[1] != 'e' || cmd[2] != 't' ||
        (len > 3 && cmd[3] != ' ')) {
        return 0;
    }

    g_cmd_len = 0;

    if (len <= 4 || len - 4 > sizeof(c)) {
        cmd_puts("ERR: config: format: set KUNCI NILAI\n");
        return 1;
    }

    for (uint32_t i = 4; i < len; i++) {
        c[i - 4] = cmd[i];
    }

    cfg_set(c, len - 4);
    return 1;
}

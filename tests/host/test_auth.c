// F1.7: uji parser perintah terautentikasi (kernel/auth.c) di host.
// auth.c disertakan langsung (#include) supaya auth_verify/priv_verify/
// priv_try_handle (static) bisa diuji. Pesan dibuat dengan hmac_sha256 dari
// crypto.c (sudah diuji terpisah di test_crypto) dan dimasukkan dalam buffer
// seukuran persis supaya pembacaan lewat batas tertangkap ASan.

#include <ctype.h>
#include <stdlib.h>
#include "test.h"
#include "auth.c"

// ---- stub untuk auth.c ----
#ifdef BMAHOS_FUZZ
void fuzz_machine_reboot(void) __attribute__((noreturn));   // R7: fuzz_auth.c (longjmp)
void machine_reboot(void) { fuzz_machine_reboot(); }
#else
void machine_reboot(void) { abort(); }   // R1-1: acpi.c
#endif
uint64_t g_auth_ctr_off = 0;
uint64_t g_chal_issued = 0;
uint64_t g_chal_noentropy = 0;
uint64_t g_chal_ip_recycled = 0;
uint64_t g_priv_ok = 0;
uint32_t g_udp_admin = 1;   // D9d: net.c
uint64_t g_priv_denied[6];

// Salinan perilaku cmd.c (buffer balasan + pencocokan nama perintah).
static char g_out[1400];
uint32_t g_cmd_len = 0;

void cmd_putc(char c)
{
    if (g_cmd_len < sizeof(g_out)) {
        g_out[g_cmd_len++] = c;
    }
}

void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
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

static char g_exec[256];

const char *cmd_out(void)
{
    return g_out;
}

void net_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;
    for (uint32_t i = 0; i < len && i < sizeof(g_exec) - 1; i++) {
        g_exec[i] = (char)cmd[i];
        g_exec[i + 1] = 0;
    }
    cmd_puts("exec\n");
}

static int g_replies;

void net_udp_send_cmd_reply(volatile uint8_t *req, uint32_t ihl)
{
    (void)req;
    (void)ihl;
    g_replies++;
}

// entropy_get: nonce unik dari counter (urutan bisa diulang), atau tolak
// bila g_entropy_ok = 0.
static int g_entropy_ok = 1;
static uint64_t g_entropy_ctr;

int entropy_get(uint8_t *out, uint32_t len)
{
    if (!g_entropy_ok) {
        return 0;
    }
    g_entropy_ctr++;
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(g_entropy_ctr >> (8 * (i % 8))) ^ (uint8_t)(i * 37);
    }
    return 1;
}

// Kunci dari "disk": fat32_find_file/fat32_load_file membaca g_disk_key.
static const char *g_disk_key;

// D4: KEYRO.TXT membaca g_disk_rokey (cluster 6).
static const char *g_disk_rokey;

int fat32_find_file(const char *name_83, uint32_t *out_cluster, uint32_t *out_size)
{
    int ro = strcmp(name_83, "KEYRO   TXT") == 0;
    const char *k = ro ? g_disk_rokey : g_disk_key;
    if (k == NULL) {
        return -1;
    }
    *out_cluster = ro ? 6 : 5;
    *out_size = (uint32_t)strlen(k);
    return 0;
}

uint8_t *fat32_load_file(uint32_t first_cluster, uint32_t file_size)
{
    static uint8_t buf[600];
    memcpy(buf, first_cluster == 6 ? g_disk_rokey : g_disk_key, file_size);
    return buf;
}

// D6: perintah berkas di-stub (fscmd.c diuji di test_fat32); "ls" dikenali.
int fscmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    if (len == 2 && cmd[0] == 'l' && cmd[1] == 's') {
        g_cmd_len = 0;
        cmd_puts("fs-stub\n");
        return 1;
    }
    return 0;
}

// D7: config/set di-stub (config.c diuji di test_config).
int panic_test_execute(const volatile uint8_t *cmd, uint32_t len)   // R1
{
    (void)cmd;
    (void)len;
    return 0;
}

int wd_test_execute(const volatile uint8_t *cmd, uint32_t len)   // R5
{
    (void)cmd;
    (void)len;
    return 0;
}

int config_execute(const volatile uint8_t *cmd, uint32_t len)
{
    if ((len == 6 && memcmp((const void *)cmd, "config", 6) == 0) ||
        (len > 4 && memcmp((const void *)cmd, "set ", 4) == 0)) {
        g_cmd_len = 0;
        cmd_puts("cfg-stub\n");
        return 1;
    }
    return 0;
}

// ---- pembantu ----
static const char KEY[] = "kunci-uji-bmahOS-0123456789";

static void load_key(const char *k)
{
    g_auth_key_len = 0;
    g_auth_ro_key_len = 0;
    g_disk_key = k;
    auth_load_key();
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hx[b[i] >> 4];
        out[i * 2 + 1] = hx[b[i] & 0xF];
    }
    out[n * 2] = 0;
}

// "<prefix> <cmd> <hmac>" dengan hmac atas "<prefix> <cmd>".
static size_t sign(char *out, const char *prefix, const char *cmd)
{
    uint8_t mac[32];
    int n = sprintf(out, "%s %s", prefix, cmd);
    hmac_sha256((const uint8_t *)KEY, (uint32_t)strlen(KEY), (const uint8_t *)out, (uint32_t)n, mac);
    out[n++] = ' ';
    hex(mac, 32, out + n);
    return (size_t)n + 64;
}

static uint8_t *dup_exact(const char *s, size_t n)
{
    uint8_t *b = malloc(n ? n : 1);
    memcpy(b, s, n);
    return b;
}

static int ctr_verify(const char *s, size_t n, char *cmd_out)
{
    uint8_t *b = dup_exact(s, n);
    volatile uint8_t *c = 0;
    uint32_t cl = 0;
    uint64_t ctr = 0;
    int rc = auth_verify(b, (uint32_t)n, &c, &cl, &ctr);
    if (rc == 0 && cmd_out) {
        memcpy(cmd_out, (const void *)c, cl);
        cmd_out[cl] = 0;
    }
    free(b);
    return rc;
}

static int prv_verify(const char *s, size_t n, char *cmd_out)
{
    uint8_t *b = dup_exact(s, n);
    volatile uint8_t *c = 0;
    uint32_t cl = 0;
    int rc = priv_verify(b, (uint32_t)n, &c, &cl);
    if (rc == 0 && cmd_out) {
        memcpy(cmd_out, (const void *)c, cl);
        cmd_out[cl] = 0;
    }
    free(b);
    return rc;
}

// Pasang nonce di slot (seperti CHAL) dan kembalikan hex-nya.
static void put_nonce(int slot, uint8_t seed, char hexout[33])
{
    priv_nonce_t *e = &g_priv_nonces[slot];
    for (int i = 0; i < 16; i++) {
        e->nonce[i] = (uint8_t)(seed + i * 17);
    }
    e->issued = timer_ticks;
    e->in_use = 1;
    hex(e->nonce, 16, hexout);
}

// ---- uji ----
static void test_load_key(void)
{
    g_crypto_ok = 1;

    load_key(NULL);
    CHECK(g_auth_key_len == 0);
    load_key("pendek");   // < 16 byte
    CHECK(g_auth_key_len == 0);
    load_key("0123456789abcde");   // 15
    CHECK(g_auth_key_len == 0);
    load_key("0123456789abcdef\r\n  ");   // 16 + spasi/CRLF di akhir dibuang
    CHECK(g_auth_key_len == 16);
    char k64[80], k65[80];
    memset(k64, 'k', 64);
    k64[64] = 0;
    memset(k65, 'k', 65);
    k65[65] = 0;
    load_key(k64);
    CHECK(g_auth_key_len == 64);
    load_key(k65);
    CHECK(g_auth_key_len == 0);
    static char big[600];
    memset(big, 'k', 513);   // > 512 byte ditolak sebelum dimuat
    load_key(big);
    CHECK(g_auth_key_len == 0);

    g_crypto_ok = 0;   // kripto gagal self-test: kunci tidak dimuat
    load_key(KEY);
    CHECK(g_auth_key_len == 0);
    g_crypto_ok = 1;
    load_key(KEY);
    CHECK(g_auth_key_len == strlen(KEY));
    CHECK(memcmp(g_auth_key, KEY, strlen(KEY)) == 0);
}

static void test_counter(void)
{
    char m[400], c[256];
    size_t n;

    g_auth_last_counter = 0;
    n = sign(m, "5", "uptime");
    CHECK(ctr_verify(m, n, c) == 0);
    CHECK_STR(c, "uptime");
    CHECK(g_auth_last_counter == 5);
    CHECK(ctr_verify(m, n, NULL) == 4);   // replay
    n = sign(m, "4", "uptime");
    CHECK(ctr_verify(m, n, NULL) == 4);   // counter mundur
    n = sign(m, "6", "stats  log");   // spasi di perintah tetap bagian perintah
    CHECK(ctr_verify(m, n, c) == 0);
    CHECK_STR(c, "stats  log");
    n = sign(m, "9999999999999999999", "x");   // 19 digit: batas
    CHECK(ctr_verify(m, n, NULL) == 0);
    n = sign(m, "10000000000000000000", "x");   // 20 digit
    CHECK(ctr_verify(m, n, NULL) == 2);

    g_auth_last_counter = 0;
    n = sign(m, "7", "ping");
    m[n - 1] ^= 1;   // hmac salah
    CHECK(ctr_verify(m, n, NULL) == 3);
    CHECK(g_auth_last_counter == 0);   // gagal tidak memajukan counter
    n = sign(m, "7", "ping");
    for (size_t i = n - 64; i < n; i++) {
        if (m[i] >= 'a') {
            m[i] = (char)(m[i] - 'a' + 'A');   // hex huruf besar diterima
        }
    }
    CHECK(ctr_verify(m, n, NULL) == 0);

    n = sign(m, "8", "ping");
    m[n - 5] = 'g';
    CHECK(ctr_verify(m, n, NULL) == 2);
    n = sign(m, "8a", "ping");
    CHECK(ctr_verify(m, n, NULL) == 2);
    n = sign(m, "8", "");   // perintah kosong
    CHECK(ctr_verify(m, n, NULL) == 2);
    n = sign(m, "8", "ping");
    CHECK(ctr_verify(m, n - 1, NULL) == 2);   // hmac 63 hex

    char longcmd[260];
    memset(longcmd, 'a', 197);
    longcmd[197] = 0;
    n = sign(m, "9", longcmd);   // pesan 1+1+197 = 199
    CHECK(ctr_verify(m, n, NULL) == 0);
    longcmd[197] = 'a';
    longcmd[199] = 0;
    longcmd[198] = 'a';
    n = sign(m, "10", longcmd);   // pesan 202 > 200
    CHECK(ctr_verify(m, n, NULL) == 2);

    uint32_t kl = g_auth_key_len;
    g_auth_key_len = 0;
    n = sign(m, "50", "ping");
    CHECK(ctr_verify(m, n, NULL) == 1);
    g_auth_key_len = kl;
}

static void test_priv(void)
{
    char m[400], c[256], nh[33];
    size_t n;

    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    timer_ticks = 1000;
    put_nonce(3, 0x11, nh);

    n = sign(m, nh, "pping");
    m[n - 1] ^= 1;
    CHECK(prv_verify(m, n, NULL) == 5);
    CHECK(g_priv_nonces[3].in_use);   // hmac salah: nonce TIDAK dibebaskan
    n = sign(m, nh, "pping");
    CHECK(prv_verify(m, n, c) == 0);
    CHECK_STR(c, "pping");
    CHECK(!g_priv_nonces[3].in_use);
    CHECK(prv_verify(m, n, NULL) == 3);   // sekali pakai

    put_nonce(0, 0x22, nh);
    timer_ticks += PRIV_NONCE_TTL;   // tepat di batas: masih berlaku
    n = sign(m, nh, "ping");
    CHECK(prv_verify(m, n, NULL) == 0);
    put_nonce(0, 0x23, nh);
    timer_ticks += PRIV_NONCE_TTL + 1;
    n = sign(m, nh, "ping");
    CHECK(prv_verify(m, n, NULL) == 4);

    put_nonce(1, 0x33, nh);
    nh[0] = nh[0] == 'f' ? 'e' : 'f';   // nonce tak dikenal
    n = sign(m, nh, "ping");
    CHECK(prv_verify(m, n, NULL) == 3);

    put_nonce(1, 0x34, nh);
    nh[5] = 'x';
    n = sign(m, nh, "ping");
    CHECK(prv_verify(m, n, NULL) == 2);   // nonce bukan hex
    put_nonce(1, 0x35, nh);
    n = sign(m, nh, "");
    CHECK(prv_verify(m, n, NULL) == 2);   // perintah kosong
    nh[31] = 0;
    n = sign(m, nh, "ping");   // nonce 31 hex
    CHECK(prv_verify(m, n, NULL) == 2);

    // Pesan (nonce + spasi + perintah) maksimal 200 byte.
    char longcmd[260];
    memset(longcmd, 'a', 167);
    longcmd[167] = 0;
    put_nonce(1, 0x36, nh);
    n = sign(m, nh, longcmd);   // 32 + 1 + 167 = 200
    CHECK(prv_verify(m, n, NULL) == 0);
    longcmd[167] = 'a';
    longcmd[168] = 0;
    put_nonce(1, 0x37, nh);
    n = sign(m, nh, longcmd);   // 201
    CHECK(prv_verify(m, n, NULL) == 2);
}

// Jalur lengkap net_cmd_handle: frame UDP, balasan di g_out.
static size_t mk_cmd_frame(uint8_t *f, const char *payload)
{
    memset(f, 0, 42);
    f[12] = 0x08;
    f[14] = 0x45;
    static const uint8_t src[4] = { 192, 168, 50, 1 };
    memcpy(f + 26, src, 4);
    f[34] = 50000 >> 8;   // D5: port sumber UDP (dicatat audit)
    f[35] = 50000 & 0xFF;
    size_t n = strlen(payload);
    memcpy(f + 42, payload, n);
    return 42 + n;
}

static const char *handle(const char *payload)
{
    static uint8_t frame[600];
    size_t n = mk_cmd_frame(frame, payload);
    uint8_t *b = malloc(n);
    memcpy(b, frame, n);
    g_replies = 0;
    g_cmd_len = 0;
    timer_ticks += 1;
    net_cmd_handle(b, 20, (uint32_t)(n - 34));
    free(b);
    g_out[g_cmd_len < sizeof(g_out) ? g_cmd_len : sizeof(g_out) - 1] = 0;
    return g_out;
}

static void test_handle(void)
{
    char m[400];
    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));

    // CHAL -> "nonce: <32 hex>\n", lalu perintah dengan nonce itu.
    const char *r = handle("CHAL\r\n");
    CHECK(g_replies == 1 && strncmp(r, "nonce: ", 7) == 0 && strlen(r) == 7 + 32 + 1);
    char nh[33];
    memcpy(nh, r + 7, 32);
    nh[32] = 0;

    sign(m, nh, "pping");
    strcat(m, "\n");
    uint64_t ok0 = g_priv_ok;
    CHECK_STR(handle(m), "ppong\n");
    CHECK(g_priv_ok == ok0 + 1);
    CHECK_STR(handle(m), "ERR: nonce tidak dikenal atau sudah dipakai\n");

    // Perintah baca lewat jalur nonce diteruskan ke net_cmd_execute.
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    sign(m, nh, "uptime");
    CHECK_STR(handle(m), "exec\n");
    CHECK_STR(g_exec, "uptime");

    // Jalur counter mati (tanpa LEGACYCTR).
    uint64_t off0 = g_auth_ctr_off;
    sign(m, "99", "uptime");
    r = handle(m);
    CHECK(strncmp(r, "ERR: jalur counter dimatikan", 28) == 0);
    CHECK(g_auth_ctr_off == off0 + 1);

    // Kosong / hanya CRLF.
    handle("\r\n");
    CHECK(g_replies == 1);

    // Banjir CHAL dari satu IP: maksimal PRIV_NONCE_PER_IP slot dipakai IP itu.
    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    for (int i = 0; i < 10; i++) {
        handle("CHAL");
    }
    int used = 0;
    for (int i = 0; i < PRIV_NONCE_SLOTS; i++) {
        used += g_priv_nonces[i].in_use;
    }
    CHECK(used == PRIV_NONCE_PER_IP);

    // Entropi belum cukup: CHAL ditolak, tabel tidak disentuh.
    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    put_nonce(5, 0x55, nh);
    g_entropy_ok = 0;
    uint64_t ne0 = g_chal_noentropy, ch0 = g_chal_issued;
    CHECK_STR(handle("CHAL"), "ERR: entropi belum cukup, coba lagi\n");
    CHECK(g_chal_noentropy == ne0 + 1 && g_chal_issued == ch0 && g_replies == 1);
    used = 0;
    for (int i = 0; i < PRIV_NONCE_SLOTS; i++) {
        used += g_priv_nonces[i].in_use;
    }
    CHECK(used == 1 && g_priv_nonces[5].in_use);
    g_entropy_ok = 1;

    // Kunci tidak dimuat: CHAL ditolak.
    uint32_t kl = g_auth_key_len;
    g_auth_key_len = 0;
    CHECK_STR(handle("CHAL"), "ERR: auth nonaktif (kunci tidak dimuat)\n");
    g_auth_key_len = kl;
}

// Semua potongan pesan valid dan pengacakan byte: tidak boleh baca di luar
// buffer, dan hanya pesan utuh yang diterima.
static void test_fuzz(void)
{
    char m[400], nh[33];
    int ok = 1;

    size_t n = sign(m, "12345", "metrics");
    for (size_t k = 0; k < n; k++) {
        g_auth_last_counter = 0;
        if (ctr_verify(m, k, NULL) == 0) {
            ok = 0;
        }
    }
    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    put_nonce(2, 0x44, nh);
    n = sign(m, nh, "pping");
    for (size_t k = 0; k < n; k++) {
        if (prv_verify(m, k, NULL) == 0) {
            ok = 0;
        }
    }
    CHECK(ok);

    uint32_t s = 777;
    int accepted = 0, case_only = 0;
    for (int it = 0; it < 100000; it++) {
        char x[400];
        int priv = it & 1;
        if (priv) {
            put_nonce(2, 0x44, nh);
            n = sign(x, nh, "pping");
        } else {
            n = sign(x, "12345", "metrics");
        }
        s = s * 1103515245u + 12345u;
        size_t pos = (s >> 8) % n;
        s = s * 1103515245u + 12345u;
        uint8_t v = (uint8_t)(s >> 16);
        char orig = x[pos];
        int changed = orig != (char)v;
        x[pos] = (char)v;
        g_auth_last_counter = 0;
        int rc = priv ? prv_verify(x, n, NULL) : ctr_verify(x, n, NULL);
        // Hanya beda huruf besar/kecil di hex HMAC yang boleh diterima
        // (HMAC dihitung atas teks sebelum HMAC, jadi nonce tidak termasuk).
        if (rc == 0 && changed) {
            if (pos >= n - 64 && tolower((unsigned char)orig) == tolower(v)) {
                case_only++;
            } else {
                accepted++;
                fprintf(stderr, "GAGAL: pesan diubah di %zu (%02x -> %02x) diterima\n",
                        pos, (unsigned char)orig, v);
            }
        }
    }
    printf("auth fuzz: 100000 pesan, %d beda huruf hex HMAC diterima (boleh)\n", case_only);
    CHECK(accepted == 0);
}

// D1: vektor dihitung dengan Python (hmac/hashlib), bukan dengan kode ini:
// HMAC-SHA256(KEY, "a4a5...b3 tcp-login").
static void test_tcp_login(void)
{
    uint8_t nonce[16];
    char line[80];
    const char *mac = "580a6719d8a5192912eec0c9c44f7a78da1b74ff6b6210401b38f043cd8303d2";

    for (int i = 0; i < 16; i++) {
        nonce[i] = (uint8_t)(0xA4 + i);
    }
    int role = 0;
    load_key(KEY);
    snprintf(line, sizeof(line), "login %s", mac);
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 0);
    line[69] ^= 1;                                         // hex lain
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 5);
    line[69] ^= 1;
    nonce[0] ^= 1;                                         // nonce lain
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 5);
    nonce[0] ^= 1;
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 69, &role) == 2);
    line[10] = 'g';
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 2);
    snprintf(line, sizeof(line), "LOGIN %s", mac);
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 2);
    snprintf(line, sizeof(line), "login %s", mac);
    uint32_t kl = g_auth_key_len;
    g_auth_key_len = 0;
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 1);
    g_auth_key_len = kl;
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 0);
}

// D2: vektor dihitung dengan Python (hmac/hashlib), bukan dengan kode ini:
// HMAC-SHA256(KEY, "a4a5...b3 tcp-cmd <seq> <perintah>").
static void test_tcp_cmd(void)
{
    uint8_t nonce[16];
    char line[200];
    uint32_t cl = 0;
    const char *m1 = "0adfc0430724a6583fa9e60d47cf6dc963919db6748d2e5821d9b68120104beb";
    const char *m2 = "d019ab5c8ee372e204ab0b6a7a9f3351ba9d626b3204eb14aa0cc167bc387acf";
    const char *mbig = "090ba1d9cd31dc8f1cc5616eb30480911dd8ae2159bee25826f14d4a7b608b0c";
    const char *m64 = "1c8bcdf5ca1d8eb3907135c4e90ae6c8315f6d2bf146587ef6936add04cd1a5f";
    uint32_t n;

    for (int i = 0; i < 16; i++) {
        nonce[i] = (uint8_t)(0xA4 + i);
    }
    load_key(KEY);
#define TC(seq, rc) auth_tcp_cmd(nonce, AUTH_ROLE_ADMIN, (seq), (const uint8_t *)line, (uint32_t)strlen(line), &cl) == (rc)
    snprintf(line, sizeof(line), "ping %s", m1);
    CHECK(TC(1, 0) && cl == 4);
    CHECK(TC(2, 5));                                       // nomor urut lain (replay)
    snprintf(line, sizeof(line), "ping %s", m2);
    CHECK(TC(2, 0) && TC(1, 5));
    snprintf(line, sizeof(line), "uptime %s", mbig);
    CHECK(TC(12345678901234567890ULL, 0) && cl == 6);
    snprintf(line, sizeof(line), "uptimf %s", mbig);       // perintah diubah
    CHECK(TC(12345678901234567890ULL, 5));
    n = (uint32_t)snprintf(line, sizeof(line), "%.64s %s",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", m64);
    CHECK(n == 129 && TC(3, 0) && cl == 64);               // perintah 64 byte = batas
    snprintf(line, sizeof(line), "x%.64s %s",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", m64);
    CHECK(TC(3, 2));                                       // 65 byte: format
    nonce[0] ^= 1;
    snprintf(line, sizeof(line), "ping %s", m1);
    CHECK(TC(1, 5));                                       // nonce koneksi lain
    nonce[0] ^= 1;
    snprintf(line, sizeof(line), "ping%s", m1);            // tanpa spasi
    CHECK(TC(1, 2));
    snprintf(line, sizeof(line), " %s", m1);               // perintah kosong
    CHECK(TC(1, 2));
    snprintf(line, sizeof(line), "ping  %s", m1);          // spasi di ujung perintah
    CHECK(TC(1, 2));
    snprintf(line, sizeof(line), "ping %s", m1);
    line[10] = 'g';
    CHECK(TC(1, 2));
    snprintf(line, sizeof(line), "ping %s", m1);
    line[10] = line[10] == '0' ? '1' : '0';                // satu digit hex berbeda
    CHECK(TC(1, 5));
    snprintf(line, sizeof(line), "login %s", m1);          // bukti login bukan perintah
    CHECK(TC(1, 5));
    snprintf(line, sizeof(line), "ping %s", m1);
    uint32_t kl = g_auth_key_len;
    g_auth_key_len = 0;
    CHECK(TC(1, 1));
    g_auth_key_len = kl;
    CHECK(TC(1, 0));
#undef TC

    // auth_tcp_exec: keluaran disalin (dipotong ke max), reboot dilaporkan.
    uint8_t out[16];
    int rb = 7;
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"pping", 5, out, sizeof(out), &rb) == 6 &&
          memcmp(out, "ppong\n", 6) == 0 && rb == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"uptime", 6, out, 3, &rb) == 3 &&
          memcmp(out, "exe", 3) == 0 && strcmp(g_exec, "uptime") == 0 && rb == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"reboot", 6, out, sizeof(out), &rb) == 16 &&
          rb == 1 && g_priv_reboot_pending == 0);
}

// D4: peran read-only. Vektor dihitung dengan Python (hmac/hashlib):
// HMAC-SHA256(ROKEY, "a4a5...b3 tcp-login") dan "... tcp-cmd 1 ping".
static void test_tcp_role(void)
{
    static const char ROKEY[] = "kunci-ro-bmahOS-abcdefghij";
    const char *adm = "580a6719d8a5192912eec0c9c44f7a78da1b74ff6b6210401b38f043cd8303d2";
    const char *ro = "cfd3ad7b81ee751000e374dba065a89710e95adc7654f8b169ec236e8814c29f";
    const char *adm1 = "0adfc0430724a6583fa9e60d47cf6dc963919db6748d2e5821d9b68120104beb";
    const char *ro1 = "aecdd1469a651efc1d2192af06e2ee288899aad8dff840f4afc07e83f972d057";
    uint8_t nonce[16];
    char line[200];
    uint32_t cl = 0;
    int role;

    for (int i = 0; i < 16; i++) {
        nonce[i] = (uint8_t)(0xA4 + i);
    }
#define LG(m) (snprintf(line, sizeof(line), "login %s", (m)), role = 0, \
               auth_tcp_login(nonce, (const uint8_t *)line, 70, &role))
#define TC(r, m, rc) (snprintf(line, sizeof(line), "ping %s", (m)), \
                      auth_tcp_cmd(nonce, (r), 1, (const uint8_t *)line, 69, &cl) == (rc))
    // Tanpa KEYRO.TXT: hanya admin.
    g_disk_rokey = NULL;
    load_key(KEY);
    CHECK(g_auth_ro_key_len == 0);
    CHECK(LG(adm) == 0 && role == AUTH_ROLE_ADMIN);
    CHECK(LG(ro) == 5 && role == 0);
    CHECK(TC(AUTH_ROLE_RO, ro1, 1));                          // peran ro tanpa kunci
    // KEYRO.TXT dimuat (CRLF di akhir dibuang).
    g_disk_rokey = "kunci-ro-bmahOS-abcdefghij\r\n";
    load_key(KEY);
    CHECK(g_auth_ro_key_len == strlen(ROKEY) &&
          memcmp(g_auth_ro_key, ROKEY, strlen(ROKEY)) == 0 && g_auth_key_len == strlen(KEY));
    CHECK(LG(adm) == 0 && role == AUTH_ROLE_ADMIN);
    CHECK(LG(ro) == 0 && role == AUTH_ROLE_RO);
    line[69] = line[69] == '0' ? '1' : '0';                // satu digit hex lain
    role = 0;
    CHECK(auth_tcp_login(nonce, (const uint8_t *)line, 70, &role) == 5 && role == 0);
    // Perintah ditandatangani kunci sesuai peran; kunci peran lain ditolak.
    CHECK(TC(AUTH_ROLE_RO, ro1, 0) && cl == 4);
    CHECK(TC(AUTH_ROLE_ADMIN, adm1, 0));
    CHECK(TC(AUTH_ROLE_RO, adm1, 5));
    CHECK(TC(AUTH_ROLE_ADMIN, ro1, 5));
    CHECK(TC(AUTH_ROLE_NONE, adm1, 1));
    // Ditolak: sama dengan kunci admin, terlalu pendek, kunci admin tidak ada.
    g_disk_rokey = KEY;
    load_key(KEY);
    CHECK(g_auth_ro_key_len == 0 && g_auth_key_len == strlen(KEY));
    g_disk_rokey = "pendek";
    load_key(KEY);
    CHECK(g_auth_ro_key_len == 0);
    g_disk_rokey = ROKEY;
    load_key(NULL);
    CHECK(g_auth_ro_key_len == 0);
    CHECK(LG(ro) == 1);
#undef LG
#undef TC

    // Daftar putih read-only: pping/reboot/lainnya ditolak, perintah baca jalan.
    uint8_t out[64];
    int rb = 7;
    uint64_t d0 = g_cli_role_denied;
    g_exec[0] = 0;
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"pping", 5, out, sizeof(out), &rb) == 21 &&
          memcmp(out, "ERR: peran read-only\n", 21) == 0 && rb == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"reboot", 6, out, sizeof(out), &rb) == 21 &&
          rb == 0 && g_priv_reboot_pending == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"pingx", 5, out, sizeof(out), &rb) == 21);
    CHECK(auth_tcp_exec(AUTH_ROLE_NONE, (const uint8_t *)"pping", 5, out, sizeof(out), &rb) == 21);
    CHECK(g_cli_role_denied == d0 + 4 && g_exec[0] == 0);
    static const char *const okc[] = { "help", "ping", "uptime", "mem", "log", "irq",
                                       "stats", "metrics", "mac", "ip", "tasks" };
    int all = 1;
    for (size_t i = 0; i < sizeof(okc) / sizeof(okc[0]); i++) {
        auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)okc[i], (uint32_t)strlen(okc[i]),
                      out, sizeof(out), &rb);
        all &= strcmp(g_exec, okc[i]) == 0 && rb == 0;
    }
    CHECK(all && g_cli_role_denied == d0 + 4);
    // R3: metrics dengan argumen boleh untuk ro; nama lain berawalan "metrics" tidak.
    CHECK(auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"metrics tcp_", 12));
    CHECK(auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"metrics 40", 10));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"metricsx", 8));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"metrics ", 8));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"metric tcp_", 11));
    auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"metrics cpu_", 12, out, sizeof(out), &rb);
    CHECK(strcmp(g_exec, "metrics cpu_") == 0 && g_cli_role_denied == d0 + 4);
    g_disk_rokey = NULL;
    load_key(KEY);
}

// D5: jalur UDP mencatat perintah sah (admin + teks) dan yang ditolak (kode,
// tanpa teks); `audit`/`audit gagal` hanya untuk admin (bukan daftar putih ro).
static void test_audit(void)
{
    char m[400], nh[33];
    const char *r;

    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    nh[32] = 0;
    sign(m, nh, "uptime");
    serial_capture_reset();
    CHECK_STR(handle(m), "exec\n");
    CHECK(strstr(g_serial_cap, " 192.168.50.1:50000 udp admin cmd uptime\r\n") != NULL);
    serial_capture_reset();
    CHECK_STR(handle(m), "ERR: nonce tidak dikenal atau sudah dipakai\n");
    CHECK(strstr(g_serial_cap, " 192.168.50.1:50000 udp none cmd-gagal kode=3\r\n") != NULL);
    // CHAL tidak dicatat.
    serial_capture_reset();
    r = handle("CHAL");
    CHECK(strstr(g_serial_cap, "AUDIT") == NULL);
    memcpy(nh, r + 7, 32);
    sign(m, nh, "audit");
    r = handle(m);
    CHECK(strncmp(r, "audit ok: total=", 16) == 0 &&
          strstr(r, " udp admin cmd uptime\n") != NULL &&
          strcmp(r + strlen(r) - 21, " udp admin cmd audit\n") == 0);
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    sign(m, nh, "audit gagal");
    r = handle(m);
    CHECK(strncmp(r, "audit gagal: total=", 19) == 0 &&
          strstr(r, " udp none cmd-gagal kode=3\n") != NULL);

    // Peran: audit hanya admin.
    uint8_t out[64];
    int rb = 0;
    CHECK(auth_cmd_allowed(AUTH_ROLE_ADMIN, (const uint8_t *)"audit", 5));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"audit", 5));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"audit gagal", 11));
    CHECK(auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"uptime", 6));
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"audit", 5, out, sizeof(out), &rb) == 21 &&
          memcmp(out, "ERR: peran read-only\n", 21) == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"audit", 5, out, sizeof(out), &rb) ==
          sizeof(out) && memcmp(out, "audit ok: total=", 16) == 0);

    // D6: perintah berkas hanya admin (tidak di daftar putih ro).
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"ls", 2));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"tulis A.TXT x", 13));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"baca A.TXT", 10));
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"ls", 2, out, sizeof(out), &rb) == 21 &&
          memcmp(out, "ERR: peran read-only\n", 21) == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"ls", 2, out, sizeof(out), &rb) == 8 &&
          memcmp(out, "fs-stub\n", 8) == 0);

    // D7: config boleh untuk read-only, set dan hapus/ganti hanya admin.
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"config", 6, out, sizeof(out), &rb) == 9 &&
          memcmp(out, "cfg-stub\n", 9) == 0);
    CHECK(auth_tcp_exec(AUTH_ROLE_RO, (const uint8_t *)"set echo 0", 10, out, sizeof(out), &rb) ==
          21 && memcmp(out, "ERR: peran read-only\n", 21) == 0);
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"config x", 8));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"hapus A.TXT", 11));
    CHECK(!auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)"ganti A.TXT B.TXT", 17));
    CHECK(auth_tcp_exec(AUTH_ROLE_ADMIN, (const uint8_t *)"set echo 0", 10, out, sizeof(out), &rb) ==
          9 && memcmp(out, "cfg-stub\n", 9) == 0);
}

// D9d: udp_admin=0 -> UDP hanya daftar baca; pping/reboot/set ERR (audit cmd-peran).
static void test_udp_admin(void)
{
    char m[400], nh[33];
    const char *r;

    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    g_udp_admin = 0;
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    nh[32] = 0;
    sign(m, nh, "pping");
    CHECK_STR(handle(m), "ERR: udp_admin=0: hanya perintah baca lewat UDP (pakai TLS 7780)\n");
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    sign(m, nh, "set udp_admin 1");
    CHECK_STR(handle(m), "ERR: udp_admin=0: hanya perintah baca lewat UDP (pakai TLS 7780)\n");
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    sign(m, nh, "uptime");
    CHECK_STR(handle(m), "exec\n");
    r = handle("CHAL");
    memcpy(nh, r + 7, 32);
    sign(m, nh, "tls");
    CHECK_STR(handle(m), "exec\n");
    g_udp_admin = 1;
}

#ifndef BMAHOS_FUZZ   // R7: tests/fuzz/fuzz_auth.c memakai helper file ini
int main(void)
{
    test_load_key();
    test_counter();
    test_priv();
    test_handle();
    test_fuzz();
    test_tcp_login();
    test_tcp_cmd();
    test_tcp_role();
    test_audit();
    test_udp_admin();
    return test_done("auth");
}
#endif

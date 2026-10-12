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
int g_acpi_reset_ok = 0;
uint16_t g_acpi_reset_port = 0;
uint8_t g_acpi_reset_value = 0;
uint64_t g_auth_ctr_off = 0;
uint64_t g_chal_issued = 0;
uint64_t g_chal_noentropy = 0;
uint64_t g_chal_ip_recycled = 0;
uint64_t g_priv_ok = 0;
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

int fat32_find_file(const char *name_83, uint32_t *out_cluster, uint32_t *out_size)
{
    (void)name_83;
    if (g_disk_key == NULL) {
        return -1;
    }
    *out_cluster = 5;
    *out_size = (uint32_t)strlen(g_disk_key);
    return 0;
}

uint8_t *fat32_load_file(uint32_t first_cluster, uint32_t file_size)
{
    (void)first_cluster;
    static uint8_t buf[600];
    memcpy(buf, g_disk_key, file_size);
    return buf;
}

// ---- pembantu ----
static const char KEY[] = "kunci-uji-bmahOS-0123456789";

static void load_key(const char *k)
{
    g_auth_key_len = 0;
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

int main(void)
{
    test_load_key();
    test_counter();
    test_priv();
    test_handle();
    test_fuzz();
    return test_done("auth");
}

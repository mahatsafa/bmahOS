// R7: fuzz parser baris login/perintah (kernel/auth.c) dengan stub dari
// tests/host/test_auth.c. Byte 0 = mode, byte 1 = parameter, sisanya data
// (buffer seukuran persis):
//   0 auth_tcp_login mentah            1 auth_tcp_cmd mentah (peran, seq = param)
//   2 perintah TCP bertanda tangan sah (data = perintah) lalu auth_tcp_exec
//   3 datagram UDP 7778 mentah ke net_cmd_handle
//   4 CHAL lalu perintah UDP bertanda tangan sah (data = perintah)
// Mode 2 dan 4 melewati HMAC supaya parser SESUDAH autentikasi ikut teruji.

#include <setjmp.h>
#include "test_auth.c"
#include "fuzz.h"

// machine_reboot (noreturn) kembali ke awal LLVMFuzzerTestOneInput.
static jmp_buf g_fz_reboot;
static int g_fz_reboots;

// Buffer input dibebaskan di awal input berikutnya (longjmp melewati free).
static uint8_t *g_fz_buf[3];

static uint8_t *fz_alloc(int slot, size_t n)
{
    free(g_fz_buf[slot]);
    g_fz_buf[slot] = malloc(n ? n : 1);
    return g_fz_buf[slot];
}

void fuzz_machine_reboot(void)
{
    g_fz_reboots++;
    longjmp(g_fz_reboot, 1);
}

static const char FZ_ROKEY[] = "kunci-ro-fuzz-bmahOS-0123";

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    g_crypto_ok = 1;
    g_disk_rokey = FZ_ROKEY;
    load_key(KEY);
    FUZZ_ASSERT(g_auth_key_len != 0 && g_auth_ro_key_len != 0);
    return 0;
}

static void fz_nonce(uint8_t nonce[16], uint8_t p)
{
    for (int i = 0; i < 16; i++) {
        nonce[i] = (uint8_t)(p + i * 29);
    }
}

// "<cmd> <hmac>" untuk auth_tcp_cmd, hmac atas "<nonce32hex> tcp-cmd <seq> <cmd>".
static size_t fz_sign_tcp(char *out, const uint8_t nonce[16], int role, uint64_t seq,
                          const uint8_t *cmd, size_t clen)
{
    char m[200], nh[33];
    uint8_t mac[32];
    hex(nonce, 16, nh);
    int k = snprintf(m, sizeof(m), "%s tcp-cmd %lu ", nh, (unsigned long)seq);
    memcpy(m + k, cmd, clen);
    const uint8_t *key = role == AUTH_ROLE_ADMIN ? g_auth_key : g_auth_ro_key;
    uint32_t kl = role == AUTH_ROLE_ADMIN ? g_auth_key_len : g_auth_ro_key_len;
    hmac_sha256(key, kl, (const uint8_t *)m, (uint32_t)(k + (int)clen), mac);
    memcpy(out, cmd, clen);
    out[clen] = ' ';
    hex(mac, 32, out + clen + 1);
    return clen + 65;
}

// Datagram UDP 7778 dengan payload biner apa adanya.
static void fz_udp(const uint8_t *pl, size_t n)
{
    uint8_t *b = fz_alloc(2, 42 + n);
    static uint8_t hdr[600];
    mk_cmd_frame(hdr, "");
    memcpy(b, hdr, 42);
    memcpy(b + 42, pl, n);
    g_replies = 0;
    g_cmd_len = 0;
    timer_ticks += 1;
    net_cmd_handle(b, 20, (uint32_t)(n + 8));
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 2) {
        return 0;
    }
    uint8_t mode = d[0] % 5, p = d[1];
    const uint8_t *x = d + 2;
    size_t xn = n - 2;
    uint8_t nonce[16];
    int role = p & 1 ? AUTH_ROLE_RO : AUTH_ROLE_ADMIN;
    uint32_t cl = 0;
    uint8_t *b = fz_alloc(0, xn);
    memcpy(b, x, xn);
    fz_nonce(nonce, p);
    g_priv_reboot_pending = 0;
    memset(g_priv_nonces, 0, sizeof(g_priv_nonces));
    if (setjmp(g_fz_reboot)) {
        return 0;
    }

    if (mode == 0) {
        int r = 0;
        int rc = auth_tcp_login(nonce, b, (uint32_t)xn, &r);
        FUZZ_ASSERT(rc != 0 || r == AUTH_ROLE_ADMIN || r == AUTH_ROLE_RO);
    } else if (mode == 1) {
        int rc = auth_tcp_cmd(nonce, role, p, b, (uint32_t)xn, &cl);
        FUZZ_ASSERT(rc != 0 || (cl >= 1 && cl <= 64 && cl + 65 == xn));
    } else if (mode == 2) {
        size_t clen = xn > 64 ? 64 : xn;
        char line[200];
        size_t ln = fz_sign_tcp(line, nonce, role, p, b, clen);
        uint8_t *lb = fz_alloc(1, ln);
        memcpy(lb, line, ln);
        if (auth_tcp_cmd(nonce, role, p, lb, (uint32_t)ln, &cl) == 0) {
            FUZZ_ASSERT(cl == clen);
            uint8_t out[1432];   // = TCP_CLI_OUT_MAX (net.c)
            int reboot = 0;
            int allowed = auth_cmd_allowed(role, lb, cl);
            uint32_t on = auth_tcp_exec(role, lb, cl, out, sizeof(out), &reboot);
            FUZZ_ASSERT(on <= sizeof(out));
            // Peran ro tidak boleh menjalankan perintah di luar daftar putih.
            static const char deny[] = "ERR: peran read-only\n";
            FUZZ_ASSERT(allowed || (on == sizeof(deny) - 1 && memcmp(out, deny, on) == 0));
            FUZZ_ASSERT(role == AUTH_ROLE_ADMIN || reboot == 0);
            if (reboot) {
                auth_reboot();
            }
        }
    } else if (mode == 3) {
        fz_udp(b, xn);
    } else {
        char m[400], nh[33], cmd[200];
        size_t k = 0;
        for (size_t i = 0; i < xn && k < 100 && x[i] != 0; i++) {
            cmd[k++] = (char)x[i];
        }
        cmd[k] = 0;
        fz_udp((const uint8_t *)"CHAL", 4);   // bukan handle(): reboot tertunda bisa longjmp
        g_out[g_cmd_len < sizeof(g_out) ? g_cmd_len : sizeof(g_out) - 1] = 0;
        const char *r = g_out;
        if (strncmp(r, "nonce: ", 7) == 0) {
            memcpy(nh, r + 7, 32);
            nh[32] = 0;
            size_t ln = sign(m, nh, cmd);
            if (p & 2) {
                m[ln++] = '\n';
            }
            fz_udp((const uint8_t *)m, ln);
        }
    }
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const struct {
        const char *name;
        uint8_t mode, p;
        const char *data;
    } s[] = {
        { "login", 0, 0, "login 580a6719d8a5192912eec0c9c44f7a78da1b74ff6b6210401b38f043cd8303d2" },
        { "cmdraw", 1, 1, "uptime 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
        { "tcp_uptime", 2, 0, "uptime" },
        { "tcp_ro_reboot", 2, 1, "reboot" },
        { "tcp_metrics", 2, 1, "metrics tcp_ 3" },
        { "tcp_logdisk", 2, 0, "logdisk 12" },
        { "tcp_audit", 2, 0, "audit gagal" },
        { "tcp_ls", 2, 0, "ls" },
        { "tcp_set", 2, 0, "set cli_idle 600" },
        { "udp_chal", 3, 0, "CHAL\r\n" },
        { "udp_ctr", 3, 0, "99 uptime 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
        { "udp_pping", 4, 2, "pping" },
        { "udp_reboot", 4, 0, "reboot" },
        { "udp_audit", 4, 0, "audit" },
    };
    for (size_t i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
        uint8_t b[200];
        size_t n = strlen(s[i].data);
        b[0] = s[i].mode;
        b[1] = s[i].p;
        memcpy(b + 2, s[i].data, n);
        fuzz_seed(dir, s[i].name, b, n + 2);
    }
}

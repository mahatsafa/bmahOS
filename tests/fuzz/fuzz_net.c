// R7: fuzz net_rx_dispatch (Ethernet/ARP/IPv4/ICMP/UDP/TCP, CLI 7779, TLS 7780)
// dengan stub dan pembangun frame dari tests/host/test_net.c.
// Input = deret rekaman [op][panjang 2 byte BE][frame], maks FZ_FRAMES frame:
//   op bit0   : betulkan checksum IP/ICMP/UDP/TCP (fix_csums)
//   op bit1   : seq/ack/port TCP diambil dari segmen keluar terakhir (sesi maju
//               tanpa harus menebak nomor urut)
//   op bit2..4: tick dimajukan sebelum frame (lihat g_fz_ticks), timer + net_tcp_tick ikut jalan
// Setiap input mulai dari tabel TCB kosong; frame keluar harus lolos invarian
// e1000_tx_send (panjang, checksum), selain itu abort.

#include "test_net.c"
#include "fuzz.h"

#define FZ_FRAMES 64

static const uint32_t g_fz_ticks[8] = { 0, 1, 5, 20, 100, 300, 1000, 30000 };

// Segmen TCP keluar terakhir (untuk op bit1).
static struct {
    int ok;
    uint8_t sport[2], dport[2];
    uint32_t seq, ack;
} g_fz_last;

static void fz_note_tx(void)
{
    int n = g_tx_n < TX_MAX ? g_tx_n : TX_MAX;
    for (int i = n - 1; i >= 0; i--) {
        const uint8_t *p = g_tx[i];
        if (g_tx_len[i] < 54 || p[12] != 0x08 || p[13] != 0x00 || p[23] != 6) {
            continue;
        }
        uint32_t ihl = (uint32_t)(p[14] & 0xF) * 4;
        uint32_t tot = (uint32_t)(p[16] << 8 | p[17]);
        const uint8_t *t = p + 14 + ihl;
        uint32_t doff = (uint32_t)(t[12] >> 4) * 4;
        uint32_t dlen = tot - ihl - doff;
        g_fz_last.ok = 1;
        memcpy(g_fz_last.sport, t, 2);
        memcpy(g_fz_last.dport, t + 2, 2);
        g_fz_last.seq = get32(t + 4) + dlen + ((t[13] & (F_SYN | F_FIN)) != 0);
        g_fz_last.ack = get32(t + 8);
        return;
    }
}

static void fz_follow(uint8_t *f, size_t n)
{
    if (!g_fz_last.ok || n < 14 + 20 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6) {
        return;
    }
    size_t ihl = (size_t)(f[14] & 0xF) * 4;
    if (ihl < 20 || 14 + ihl + 20 > n) {
        return;
    }
    uint8_t *t = f + 14 + ihl;
    memcpy(t, g_fz_last.dport, 2);
    memcpy(t + 2, g_fz_last.sport, 2);
    put32(t + 4, g_fz_last.ack);
    put32(t + 8, g_fz_last.seq);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    tls_files(T_KEYA, sizeof(T_KEYA), T_CERTA, sizeof(T_CERTA));
    FUZZ_ASSERT(tls_enabled());
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    size_t pos = 0;

    tcp_reset_tls();
    timer_ticks += 100000;   // jendela batas laju semua sumber sudah lewat
    memset(&g_fz_last, 0, sizeof(g_fz_last));
    g_tx_bad = 0;

    for (int k = 0; k < FZ_FRAMES && pos + 3 <= n; k++) {
        uint8_t op = d[pos];
        size_t len = (size_t)(d[pos + 1] << 8 | d[pos + 2]);
        pos += 3;
        if (len > n - pos) {
            len = n - pos;
        }
        uint8_t *f = malloc(len ? len : 1);
        memcpy(f, d + pos, len);
        pos += len;

        uint32_t ticks = g_fz_ticks[(op >> 2) & 7];
        if (ticks > 100) {
            timer_ticks += ticks - 1;
            ticks = 1;
        }
        for (uint32_t i = 0; i < ticks; i++) {
            step();
            fz_note_tx();
        }
        if (op & 2) {
            fz_follow(f, len);
        }
        if (op & 1) {
            fix_csums(f, len);
        }
        g_tx_n = 0;
        net_rx_dispatch(f, (uint32_t)len);
        free(f);
        fz_note_tx();
        FUZZ_ASSERT(g_tx_bad == 0);
    }
    // Biarkan timer yang tersisa (retransmisi, timeout) berjalan sekali.
    timer_ticks += 1000;
    step();
    FUZZ_ASSERT(g_tx_bad == 0);
    return 0;
}

// ---- korpus awal ----

static uint8_t g_sd[16384];
static size_t g_sd_len;

static void sd_add(uint8_t op, const uint8_t *f, size_t len)
{
    g_sd[g_sd_len++] = op;
    g_sd[g_sd_len++] = (uint8_t)(len >> 8);
    g_sd[g_sd_len++] = (uint8_t)len;
    memcpy(g_sd + g_sd_len, f, len);
    g_sd_len += len;
}

// Sesi TCP ke port: SYN, ACK, lalu baris data (op bit0|bit1: checksum + ikuti).
static void sd_session(const char *dir, const char *name, uint16_t port,
                       const char *const *lines, int nl)
{
    uint8_t f[600];
    g_sd_len = 0;
    sd_add(0, f, mk_tcp(f, 40000, port, 1000, 0, F_SYN, ""));
    sd_add(3, f, mk_tcp(f, 40000, port, 0, 0, F_ACK, ""));
    for (int i = 0; i < nl; i++) {
        sd_add(3, f, mk_tcp(f, 40000, port, 0, 0, F_ACK, lines[i]));
    }
    sd_add(3 | 4 << 2, f, mk_tcp(f, 40000, port, 0, 0, F_ACK | F_FIN, ""));
    fuzz_seed(dir, name, g_sd, g_sd_len);
}

void fuzz_seeds(const char *dir)
{
    char name[32];
    char login_a[80], login_r[80], cmd1[160], cmd2[160];

    build_templates();
    for (int i = 0; i < NTPL; i++) {
        g_sd_len = 0;
        sd_add(0, g_tpl[i], g_tpl_len[i]);
        snprintf(name, sizeof(name), "tpl%d", i);
        fuzz_seed(dir, name, g_sd, g_sd_len);
    }

    // Login stub test_net: 64 'a' = admin, 64 'r' = ro; perintah ke-n bertanda
    // 64 x digit n % 10.
    snprintf(login_a, sizeof(login_a), "login %.64s\n",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(login_r, sizeof(login_r), "login %.64s\n",
             "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr");
    snprintf(cmd1, sizeof(cmd1), "uptime %.64s\n",
             "1111111111111111111111111111111111111111111111111111111111111111");
    snprintf(cmd2, sizeof(cmd2), "big %.64s\n",
             "2222222222222222222222222222222222222222222222222222222222222222");
    const char *adm[] = { login_a, cmd1, cmd2, "exit\n" };
    const char *ro[] = { login_r, "reboot 1111111111111111111111111111111111111111111111111111111111111111\n" };
    const char *echo[] = { "halo echo\n", "kedua\n" };
    const char *bad[] = { "LOGIN xyz\n", "baris tanpa akhir yang panjang sekali" };
    static const char hello[] = "\x16\x03\x03\x01\x10\x01";   // awal record ClientHello (tanpa NUL: mk_tcp memakai strlen)
    const char *tls[] = { hello };

    sd_session(dir, "cli_admin", NET_TCP_CLI_PORT, adm, 4);
    sd_session(dir, "cli_ro", NET_TCP_CLI_PORT, ro, 2);
    sd_session(dir, "cli_bad", NET_TCP_CLI_PORT, bad, 2);
    sd_session(dir, "echo7", 7, echo, 2);
    sd_session(dir, "tls7780", 7780, tls, 1);
}

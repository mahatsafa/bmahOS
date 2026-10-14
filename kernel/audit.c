#include "kernel.h"

// ---- D5: audit log (siapa = IP:port + peran, apa, kapan = tick) ----
// Dua ring statis di RAM. Ring ok: kejadian dari pihak yang lolos HMAC (login,
// perintah, perintah ditolak karena peran, sesi idle). Ring gagal: login gagal
// atau timeout, baris terlalu panjang, perintah dengan format/hmac salah.
// Penyerang tanpa kunci hanya bisa menimpa ring gagal. Ring penuh: entri
// tertua ditimpa; nomor urut (#) global terus naik, jadi celah terlihat.
// Teks perintah hanya dicatat bila sudah terverifikasi (maks AUDIT_CMD_MAX
// byte, selain 0x21..0x7e dan spasi jadi '?'). Isi hilang saat reboot (log
// persisten = R4); tiap entri juga dikirim ke UART sebagai baris "AUDIT ...",
// tanpa masuk ring log (peran ro bisa membaca `log`). Entri ok selalu ke UART,
// entri gagal ikut pembatas B4b. Hanya dipanggil dari net task (tanpa lock).
#define AUDIT_OK_MAX   16
#define AUDIT_FAIL_MAX 8
#define AUDIT_CMD_MAX  16
#define AUDIT_LINE_MAX 128   // baris terpanjang ~115 byte (u64 penuh)

typedef struct {
    uint64_t seq;
    uint64_t tick;
    uint8_t ip[4];
    uint16_t port;
    uint8_t chan, role, ev, code;
    char cmd[AUDIT_CMD_MAX + 1];
} audit_ent_t;

static audit_ent_t g_audit_ok[AUDIT_OK_MAX];
static audit_ent_t g_audit_fail[AUDIT_FAIL_MAX];
static uint64_t g_audit_ok_n, g_audit_fail_n;   // total sejak boot per ring
static uint64_t g_audit_seq;

static const char *const g_audit_ev[] = {
    "login", "cmd", "tolak-peran", "idle",
    "login-gagal", "login-timeout", "baris-panjang", "cmd-gagal",
};

static uint32_t audit_fmt(const audit_ent_t *e, char *buf)
{
    static const char *const roles[] = { "none", "admin", "ro" };
    size_t n = ksnprintf(buf, AUDIT_LINE_MAX, "#%lu t=%lu %u.%u.%u.%u:%u %s %s %s",
                         e->seq, e->tick, e->ip[0], e->ip[1], e->ip[2], e->ip[3],
                         e->port, e->chan == AUDIT_UDP ? "udp" : e->chan == AUDIT_TLS ? "tls" : "tcp",
                         e->role <= AUTH_ROLE_RO ? roles[e->role] : "?",
                         g_audit_ev[e->ev]);

    if (e->code && n < AUDIT_LINE_MAX) {
        n += ksnprintf(buf + n, AUDIT_LINE_MAX - n, " kode=%u", e->code);
    }
    if (e->cmd[0] && n < AUDIT_LINE_MAX) {
        n += ksnprintf(buf + n, AUDIT_LINE_MAX - n, " %s", e->cmd);
    }
    return (uint32_t)(n < AUDIT_LINE_MAX ? n : AUDIT_LINE_MAX - 1);
}

void audit_record(int ev, int chan, const volatile uint8_t *ip, uint16_t port,
                  int role, int code, const volatile uint8_t *cmd, uint32_t cmd_len)
{
    int fail = ev >= AUDIT_LOGIN_FAIL;
    audit_ent_t *e;

    if (ev < 0 || ev > AUDIT_CMD_FAIL) {
        return;
    }
    if (fail) {
        e = &g_audit_fail[g_audit_fail_n++ % AUDIT_FAIL_MAX];
    } else {
        e = &g_audit_ok[g_audit_ok_n++ % AUDIT_OK_MAX];
    }
    e->seq = ++g_audit_seq;
    e->tick = timer_ticks;
    for (int i = 0; i < 4; i++) {
        e->ip[i] = ip[i];
    }
    e->port = port;
    e->chan = (uint8_t)chan;
    e->role = (uint8_t)role;
    e->ev = (uint8_t)ev;
    e->code = (uint8_t)code;

    uint32_t k = cmd_len < AUDIT_CMD_MAX ? cmd_len : AUDIT_CMD_MAX;

    for (uint32_t i = 0; i < k; i++) {
        uint8_t c = cmd[i];
        e->cmd[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    e->cmd[k] = 0;

    char line[AUDIT_LINE_MAX];
    uint64_t lf = irq_save();
    int mute = g_serial_mute;

    audit_fmt(e, line);
    if (!fail) {
        g_serial_mute = 0;
    }
    serial_write_nolog("AUDIT ");
    serial_write_nolog(line);
    serial_write_nolog("\r\n");
    g_serial_mute = mute;
    irq_restore(lf);
}

// Perintah `audit` (fail = 0) / `audit gagal` (fail = 1), hanya admin: header
// lalu entri tertua -> terbaru ke keluaran perintah. Bila baris berikutnya
// tidak muat di CMD_OUT_MAX, keluaran diakhiri "...(terpotong)".
void audit_dump(int fail)
{
    static const char cut[] = "...(terpotong)\n";
    const audit_ent_t *r = fail ? g_audit_fail : g_audit_ok;
    uint64_t total = fail ? g_audit_fail_n : g_audit_ok_n;
    uint64_t max = fail ? AUDIT_FAIL_MAX : AUDIT_OK_MAX;
    uint64_t k = total < max ? total : max;
    char line[AUDIT_LINE_MAX + 1];

    g_cmd_len = 0;
    ksnprintf(line, sizeof(line), "audit %s: total=%lu tampil=%lu ditimpa=%lu\n",
              fail ? "gagal" : "ok", total, k, total - k);
    cmd_puts(line);
    for (uint64_t i = total - k; i < total; i++) {
        uint32_t n = audit_fmt(&r[i % max], line);

        line[n++] = '\n';
        line[n] = 0;
        if (g_cmd_len + n > CMD_OUT_MAX - (sizeof(cut) - 1)) {
            cmd_puts(cut);
            return;
        }
        cmd_puts(line);
    }
}

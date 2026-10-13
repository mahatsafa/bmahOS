// D5: uji audit log (kernel/audit.c) di host. audit.c disertakan langsung
// supaya ring (static) bisa diperiksa dan direset.

#include <stdint.h>
#include "test.h"
#include "audit.c"

// Salinan perilaku cmd.c (buffer balasan CMD_OUT_MAX).
static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len = 0;

void cmd_putc(char c)
{
    if (g_cmd_len < CMD_OUT_MAX) {
        g_out[g_cmd_len++] = c;
    }
}

void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
}

static const uint8_t IP1[4] = { 192, 168, 50, 1 };

static void reset(void)
{
    memset(g_audit_ok, 0, sizeof(g_audit_ok));
    memset(g_audit_fail, 0, sizeof(g_audit_fail));
    g_audit_ok_n = g_audit_fail_n = g_audit_seq = 0;
    timer_ticks = 0;
    serial_capture_reset();
}

static const char *dump(int fail)
{
    audit_dump(fail);
    g_out[g_cmd_len] = 0;
    return g_out;
}

static void rec(int ev, int chan, int role, int code, const char *cmd)
{
    audit_record(ev, chan, IP1, 50000, role, code, (const uint8_t *)cmd,
                 cmd ? (uint32_t)strlen(cmd) : 0);
}

static void test_basic(void)
{
    reset();
    CHECK_STR(dump(0), "audit ok: total=0 tampil=0 ditimpa=0\n");
    CHECK_STR(dump(1), "audit gagal: total=0 tampil=0 ditimpa=0\n");

    // Satu baris per kejadian, juga ke UART dengan awalan AUDIT.
    timer_ticks = 5;
    rec(AUDIT_LOGIN, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, NULL);
    CHECK_STR(g_serial_cap, "AUDIT #1 t=5 192.168.50.1:50000 tcp admin login\r\n");
    timer_ticks = 7;
    rec(AUDIT_CMD, AUDIT_UDP, AUTH_ROLE_ADMIN, 0, "uptime");
    rec(AUDIT_CMD_ROLE, AUDIT_TCP, AUTH_ROLE_RO, 0, "pping");
    rec(AUDIT_LOGIN_FAIL, AUDIT_TCP, AUTH_ROLE_NONE, 5, NULL);
    rec(AUDIT_IDLE, AUDIT_TCP, AUTH_ROLE_RO, 0, NULL);
    CHECK_STR(dump(0), "audit ok: total=4 tampil=4 ditimpa=0\n"
                       "#1 t=5 192.168.50.1:50000 tcp admin login\n"
                       "#2 t=7 192.168.50.1:50000 udp admin cmd uptime\n"
                       "#3 t=7 192.168.50.1:50000 tcp ro tolak-peran pping\n"
                       "#5 t=7 192.168.50.1:50000 tcp ro idle\n");
    CHECK_STR(dump(1), "audit gagal: total=1 tampil=1 ditimpa=0\n"
                       "#4 t=7 192.168.50.1:50000 tcp none login-gagal kode=5\n");

    // Semua jenis kejadian punya nama; jenis di luar enum diabaikan.
    rec(AUDIT_LOGIN_TIMEOUT, AUDIT_TCP, AUTH_ROLE_NONE, 0, NULL);
    rec(AUDIT_LINE_LONG, AUDIT_TCP, AUTH_ROLE_NONE, 0, NULL);
    rec(AUDIT_CMD_FAIL, AUDIT_UDP, AUTH_ROLE_NONE, 3, NULL);
    rec(-1, AUDIT_TCP, 0, 0, NULL);
    rec(AUDIT_CMD_FAIL + 1, AUDIT_TCP, 0, 0, NULL);
    CHECK(g_audit_seq == 8 && g_audit_fail_n == 4 && g_audit_ok_n == 4);
    CHECK(strstr(dump(1), "#6 t=7 192.168.50.1:50000 tcp none login-timeout\n") &&
          strstr(g_out, "#7 t=7 192.168.50.1:50000 tcp none baris-panjang\n") &&
          strstr(g_out, "#8 t=7 192.168.50.1:50000 udp none cmd-gagal kode=3\n"));
}

static void test_cmd_text(void)
{
    reset();
    // Maks AUDIT_CMD_MAX byte; byte kontrol/non-ASCII jadi '?'; spasi tetap.
    rec(AUDIT_CMD, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, "abcdefghijklmnopqrstuvwxyz");
    rec(AUDIT_CMD, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, "a\x01\x7f\xff b\r");
    rec(AUDIT_CMD, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, "audit gagal");
    CHECK(strcmp(g_audit_ok[0].cmd, "abcdefghijklmnop") == 0);
    CHECK(strcmp(g_audit_ok[1].cmd, "a??? b?") == 0);
    CHECK(strstr(dump(0), " cmd audit gagal\n") != NULL);
    // Peran di luar enum tidak membaca di luar tabel nama.
    rec(AUDIT_CMD, AUDIT_TCP, 7, 0, "x");
    CHECK(strstr(dump(0), "tcp ? cmd x\n") != NULL);
}

static void test_rings(void)
{
    reset();
    rec(AUDIT_LOGIN, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, NULL);
    // Banjir kejadian gagal hanya menimpa ring gagal.
    for (int i = 0; i < 100; i++) {
        rec(AUDIT_LOGIN_FAIL, AUDIT_TCP, AUTH_ROLE_NONE, 5, NULL);
    }
    CHECK_STR(dump(0), "audit ok: total=1 tampil=1 ditimpa=0\n"
                       "#1 t=0 192.168.50.1:50000 tcp admin login\n");
    dump(1);
    CHECK(strncmp(g_out, "audit gagal: total=100 tampil=8 ditimpa=92\n#94 ", 47) == 0);
    CHECK(strstr(g_out, "#101 ") && !strstr(g_out, "#93 "));

    // Ring ok memutar: 20 entri -> 16 terbaru, urut tertua -> terbaru.
    for (int i = 0; i < 19; i++) {
        timer_ticks = (uint64_t)i;
        rec(AUDIT_CMD, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, "ping");
    }
    dump(0);
    CHECK(strncmp(g_out, "audit ok: total=20 tampil=16 ditimpa=4\n#105 t=3 ", 48) == 0);
    CHECK(strstr(g_out, "#120 t=18 ") != NULL && !strstr(g_out, "#104 "));
    int lines = 0;
    for (uint32_t i = 0; i < g_cmd_len; i++) {
        lines += g_out[i] == '\n';
    }
    CHECK(lines == 17);
}

static void test_mute_and_limit(void)
{
    reset();
    // UART dibungkam (B4b): entri ok tetap dikirim, entri gagal tidak; mute
    // dikembalikan seperti semula.
    g_serial_mute = 1;
    rec(AUDIT_CMD, AUDIT_TCP, AUTH_ROLE_ADMIN, 0, "ping");
    CHECK(g_serial_mute == 1 && strstr(g_serial_cap, "AUDIT #1 ") != NULL);
    serial_capture_reset();
    rec(AUDIT_CMD_FAIL, AUDIT_TCP, AUTH_ROLE_NONE, 5, NULL);
    CHECK(g_serial_mute == 1 && g_serial_cap_len == 0);
    g_serial_mute = 0;

    // Baris terpanjang (u64 penuh, IP/port maksimum, perintah 16 byte):
    // keluaran tidak lewat CMD_OUT_MAX dan diakhiri "...(terpotong)".
    static const uint8_t ipmax[4] = { 255, 255, 255, 255 };
    reset();
    g_audit_seq = UINT64_MAX - 100;
    timer_ticks = UINT64_MAX;
    for (int i = 0; i < 16; i++) {
        audit_record(AUDIT_CMD_ROLE, AUDIT_UDP, ipmax, 65535, AUTH_ROLE_ADMIN, 255,
                     (const uint8_t *)"abcdefghijklmnopq", 17);
    }
    char one[AUDIT_LINE_MAX];
    uint32_t n = audit_fmt(&g_audit_ok[0], one);
    CHECK(n < AUDIT_LINE_MAX - 1 && strlen(one) == n);
    dump(0);
    CHECK(g_cmd_len <= CMD_OUT_MAX && g_cmd_len > CMD_OUT_MAX - 2 * n);
    CHECK(strcmp(g_out + g_cmd_len - 15, "...(terpotong)\n") == 0);
    // Ring gagal penuh (8 baris) masih muat utuh.
    for (int i = 0; i < 8; i++) {
        audit_record(AUDIT_LOGIN_TIMEOUT, AUDIT_UDP, ipmax, 65535, AUTH_ROLE_RO, 255,
                     0, 0);
    }
    dump(1);
    CHECK(strstr(g_out, "terpotong") == NULL && strstr(g_out, "tampil=8 "));
}

int main(void)
{
    test_basic();
    test_cmd_text();
    test_rings();
    test_mute_and_limit();
    return test_done("audit");
}

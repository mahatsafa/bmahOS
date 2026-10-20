// R1: uji fungsi murni panic.c di host: nama exception, uraian error #PF,
// penelusuran rantai rbp (frame tiruan di array; ASan menangkap baca di luar
// frame), dan perintah uji panic (pemicu tidak dijalankan).

#include <stdint.h>
#include <stdlib.h>
#include "test.h"
#include "panic.c"

// ---- stub untuk panic.c ----
char __text_start[1];
char __text_end[1];
uint8_t g_df_stack[DF_STACK_SIZE];
size_t current_index = 0;
task_t tasks[MAX_TASKS];   // R6-2: pemilik stack guard
size_t task_count = 0;

void machine_reboot(void)
{
    abort();
}

void pit_init(uint32_t frequency_hz)
{
    (void)frequency_hz;
}

static int g_timer_started = 0;
static uint64_t g_timer_ticks = 0;

void ktimer_start(ktimer_t *t, uint64_t ticks, void (*fn)(void *arg), void *arg)
{
    (void)t;
    (void)fn;
    (void)arg;
    g_timer_started++;
    g_timer_ticks = ticks;
}

static char g_out[256];
static size_t g_out_len = 0;

void cmd_puts(const char *s)
{
    while (*s && g_out_len < sizeof(g_out) - 1) {
        g_out[g_out_len++] = *s++;
    }
    g_out[g_out_len] = '\0';
}

int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name)
{
    size_t n = strlen(name);
    return len == n && memcmp((const void *)cmd, name, n) == 0;
}

// ---- uji ----
static void test_names(void)
{
    CHECK_STR(panic_exc_name(0), "#DE pembagian nol");
    CHECK_STR(panic_exc_name(8), "#DF double fault");
    CHECK_STR(panic_exc_name(13), "#GP general protection fault");
    CHECK_STR(panic_exc_name(14), "#PF page fault");
    CHECK_STR(panic_exc_name(21), "#CP control protection");
    CHECK_STR(panic_exc_name(31), "vektor cadangan 31");
    CHECK_STR(panic_exc_name(32), "vektor tidak dikenal");
    CHECK_STR(panic_exc_name(UINT64_MAX), "vektor tidak dikenal");
    for (uint64_t v = 0; v < 32; v++) {
        CHECK(panic_exc_name(v) != NULL && panic_exc_name(v)[0] != '\0');
    }
}

static void test_pf_decode(void)
{
    char b[48];
    panic_pf_decode(0x2, b, sizeof(b));
    CHECK_STR(b, "tidak-ada tulis kernel");
    panic_pf_decode(0x0, b, sizeof(b));
    CHECK_STR(b, "tidak-ada baca kernel");
    panic_pf_decode(0x11, b, sizeof(b));   // NXTEST: fetch di halaman NX
    CHECK_STR(b, "proteksi baca kernel fetch");
    panic_pf_decode(0x7, b, sizeof(b));
    CHECK_STR(b, "proteksi tulis user");
    panic_pf_decode(0x1F, b, sizeof(b));
    CHECK_STR(b, "proteksi tulis user rsvd fetch");
    char s[8];
    panic_pf_decode(0x1F, s, sizeof(s));   // terpotong, tetap diakhiri NUL
    CHECK(strlen(s) == 7);
}

#define TXT_LO 0x1000
#define TXT_HI 0x2000

// Frame tiruan di stk: frame i di stk[at[i]] = { rbp berikut, alamat kembali }.
static uint64_t g_stk[256];

static uint64_t fr(int idx)
{
    return (uint64_t)(uintptr_t)&g_stk[idx];
}

static void set_frame(int idx, uint64_t next, uint64_t ret)
{
    g_stk[idx] = next;
    g_stk[idx + 1] = ret;
}

static void test_walk(void)
{
    panic_bounds_t b = { TXT_LO, TXT_HI, 0 };
    uint64_t out[16];
    int why = -1;

    // Rantai normal 3 frame, ujung rbp 0.
    memset(g_stk, 0, sizeof(g_stk));
    set_frame(0, fr(8), 0x1100);
    set_frame(8, fr(20), 0x1200);
    set_frame(20, 0, 0x1300);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 3);
    CHECK(why == PANIC_WALK_END);
    CHECK(out[0] == 0x1100 && out[1] == 0x1200 && out[2] == 0x1300);

    // Ujung karena alamat kembali 0 (frame awal task).
    set_frame(20, fr(30), 0);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 2);
    CHECK(why == PANIC_WALK_END);

    // rbp awal 0: nol frame, normal.
    CHECK(panic_walk(0, &b, out, 16, &why) == 0);
    CHECK(why == PANIC_WALK_END);

    // Tidak rata 8.
    CHECK(panic_walk(fr(0) + 4, &b, out, 16, &why) == 0);
    CHECK(why == PANIC_WALK_BADRBP);

    // Menunjuk diri sendiri (lingkaran).
    set_frame(0, fr(0), 0x1100);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 1);
    CHECK(why == PANIC_WALK_BADRBP);

    // Turun (stack tumbuh ke bawah, rantai harus naik).
    set_frame(10, fr(4), 0x1100);
    set_frame(4, 0, 0x1200);
    CHECK(panic_walk(fr(10), &b, out, 16, &why) == 1);
    CHECK(why == PANIC_WALK_BADRBP);

    // Lompatan terlalu jauh (> 64 KB): tidak dibaca.
    set_frame(0, fr(0) + 65536 + 8, 0x1100);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 1);
    CHECK(why == PANIC_WALK_BADRBP);

    // Di bawah stack_min: ditolak sebelum dibaca.
    panic_bounds_t bmin = { TXT_LO, TXT_HI, fr(64) };
    set_frame(0, fr(8), 0x1100);
    CHECK(panic_walk(fr(0), &bmin, out, 16, &why) == 0);
    CHECK(why == PANIC_WALK_BADRBP);

    // Dekat UINT64_MAX: ditolak sebelum dibaca.
    CHECK(panic_walk(UINT64_MAX - 7, &b, out, 16, &why) == 0);
    CHECK(why == PANIC_WALK_BADRBP);

    // Alamat kembali di luar .text.
    set_frame(0, fr(8), 0x1100);
    set_frame(8, fr(20), 0x2000);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 1);
    CHECK(why == PANIC_WALK_NOTEXT);
    set_frame(8, fr(20), 0xFFF);
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 1);
    CHECK(why == PANIC_WALK_NOTEXT);

    // Batas jumlah frame: rantai 20 frame, max 16 dan max 5.
    memset(g_stk, 0, sizeof(g_stk));
    for (int i = 0; i < 20; i++) {
        set_frame(i * 4, i == 19 ? 0 : fr((i + 1) * 4), 0x1000 + (uint64_t)i);
    }
    CHECK(panic_walk(fr(0), &b, out, 16, &why) == 16);
    CHECK(why == PANIC_WALK_MAX);
    CHECK(out[15] == 0x100F);
    CHECK(panic_walk(fr(0), &b, out, 5, &why) == 5);
    CHECK(why == PANIC_WALK_MAX);
    CHECK(panic_walk(fr(0), &b, out, 0, &why) == 0);
    CHECK(why == PANIC_WALK_MAX);
    // Tanpa batas: 20 frame utuh lalu ujung.
    uint64_t big[32];
    CHECK(panic_walk(fr(0), &b, big, 32, &why) == 20);
    CHECK(why == PANIC_WALK_END);
}

static int exec(const char *c)
{
    g_out_len = 0;
    g_out[0] = '\0';
    return panic_test_execute((const volatile uint8_t *)c, (uint32_t)strlen(c));
}

static void test_cmd(void)
{
    CHECK(exec("panic") == 0);
    CHECK(exec("panic xx") == 0);
    CHECK(exec("panic pfx") == 0);
    CHECK(g_timer_started == 0);
    CHECK(g_panic_test_kind == -1);

    CHECK(exec("panic df") == 1);
    CHECK_STR(g_out, "panic: uji df dalam 1 detik\n");
    CHECK(g_timer_started == 1 && g_timer_ticks == 100);
    CHECK(g_panic_test_kind == 1);

    // Kedua kali: ditolak, timer tidak dipasang ulang.
    CHECK(exec("panic pf") == 1);
    CHECK_STR(g_out, "ERR: uji panic sudah dijadwalkan\n");
    CHECK(g_timer_started == 1);
    CHECK(g_panic_test_kind == 1);

    g_panic_test_kind = -1;
    g_panic_test_kind = -1;
    CHECK(exec("panic stack") == 1);   // R6-2
    CHECK_STR(g_out, "panic: uji stack dalam 1 detik\n");
    CHECK(g_panic_test_kind == 4);
    CHECK(exec("panic stackx") == 0);

    g_panic_test_kind = -1;
    CHECK(exec("panic assert") == 1);
    CHECK_STR(g_out, "panic: uji assert dalam 1 detik\n");
    CHECK(g_panic_test_kind == 3);
}

int main(void)
{
    test_names();
    test_pf_decode();
    test_walk();
    test_cmd();
    return test_done("panic");
}

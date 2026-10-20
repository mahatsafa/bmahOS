// R5: uji watchdog.c di host (di-#include: akses state static). Tick dan
// task tiruan; panic_begin/panic_finish ditangkap (longjmp) supaya isi dump
// dan sumber trace (frame interrupt vs konteks tersimpan) bisa diperiksa.

#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

volatile uint64_t timer_ticks;
task_t tasks[MAX_TASKS];
size_t current_index;

static jmp_buf g_panic_jmp;
static int g_panic_begun;
static uint64_t g_panic_rip, g_panic_rbp;

void panic_begin(void)
{
    g_panic_begun++;
}

void panic_finish(uint64_t rip, uint64_t rbp)
{
    g_panic_rip = rip;
    g_panic_rbp = rbp;
    longjmp(g_panic_jmp, 1);
}

static int g_timer_started;
static uint64_t g_timer_ticks;

void ktimer_start(ktimer_t *t, uint64_t ticks, void (*fn)(void *arg), void *arg)
{
    (void)t;
    (void)fn;
    (void)arg;
    g_timer_started++;
    g_timer_ticks = ticks;
}

void sem_wait(semaphore_t *sem)
{
    (void)sem;
    abort();   // pemicu uji tidak dijalankan di host
}

static char g_out[256];
static size_t g_out_len;

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

#include "watchdog.c"

static void wd_reset(void)
{
    g_wd_last = 0;
    g_wd_armed = 0;
    g_wd_task = 0;
    g_wd_pets = 0;
    g_wd_gap_max = 0;
    g_panic_begun = 0;
    g_panic_rip = g_panic_rbp = 0;
    timer_ticks = 0;
    current_index = 0;
    memset(tasks, 0, sizeof(tasks));
    serial_capture_reset();
}

// 1 = watchdog_check memanggil panic (dump ditangkap).
static int check_fires(struct exception_context *c)
{
    if (setjmp(g_panic_jmp) == 0) {
        watchdog_check(c);
        return 0;
    }
    return 1;
}

static const char *status_out(void)
{
    g_out_len = 0;
    g_out[0] = '\0';
    watchdog_status();
    return g_out;
}

static void test_overdue(void)
{
    CHECK(wd_overdue(0, 0) == 0);
    CHECK(wd_overdue(1000, 0) == 0);                 // tepat di batas: masih sehat
    CHECK(wd_overdue(1001, 0) == 1001);
    CHECK(wd_overdue(5000, 4000) == 0);
    CHECK(wd_overdue(5001, 4000) == 1001);
    CHECK(wd_overdue(500, UINT64_MAX - 100) == 0);   // wrap: jeda 601
    CHECK(wd_overdue(1000, UINT64_MAX - 100) == 1101);
    CHECK(WD_TIMEOUT_TICKS == 1000);
    CHECK(watchdog_timeout_ticks() == 1000);
}

static void test_pet(void)
{
    struct exception_context c;

    wd_reset();
    memset(&c, 0, sizeof(c));

    // Belum aktif: berapa pun jedanya tidak memicu panic.
    timer_ticks = 1000000;
    CHECK(check_fires(&c) == 0);
    CHECK(g_panic_begun == 0);
    CHECK_STR(status_out(), "watchdog: belum aktif batas=1000 tick jeda_sekarang=0 "
              "jeda_maks=0 tepukan=0 slot=0\n");

    // Tepukan pertama: aktif, slot dicatat, baris serial sidik jari.
    current_index = 6;
    timer_ticks = 2000;
    watchdog_pet();
    CHECK(g_wd_armed == 1 && g_wd_task == 6 && g_wd_last == 2000);
    CHECK(g_wd_pets == 1 && g_wd_gap_max == 0);
    CHECK(strstr(g_serial_cap, "R5: watchdog aktif batas=1000 tick (net task slot 6)\r\n") != NULL);

    // Tepukan berikut: jeda_maks naik, tidak turun.
    timer_ticks = 2003;
    watchdog_pet();
    timer_ticks = 2500;
    watchdog_pet();
    timer_ticks = 2501;
    watchdog_pet();
    CHECK(g_wd_pets == 4 && g_wd_gap_max == 497 && g_wd_last == 2501);
    serial_capture_reset();
    watchdog_pet();
    CHECK(strstr(g_serial_cap, "R5:") == NULL);   // sidik jari sekali saja

    timer_ticks = 2501 + 1000;
    CHECK(check_fires(&c) == 0);
    CHECK_STR(status_out(), "watchdog: aktif batas=1000 tick jeda_sekarang=1000 "
              "jeda_maks=497 tepukan=5 slot=6\n");
    CHECK(g_panic_begun == 0);
}

static void test_fire_running(void)
{
    struct exception_context c;

    wd_reset();
    memset(&c, 0, sizeof(c));
    current_index = 3;
    timer_ticks = 100;
    watchdog_pet();
    tasks[3].status = TASK_READY;
    c.rip = 0xffffffff80001234ULL;
    c.rbp = 0xffff800000abc000ULL;
    serial_capture_reset();

    timer_ticks = 1101;
    CHECK(check_fires(&c) == 1);
    CHECK(g_panic_begun == 1);
    CHECK(g_panic_rip == c.rip && g_panic_rbp == c.rbp);
    CHECK(strstr(g_serial_cap, "PANIC: watchdog: net task tanpa tepukan 1001 tick (batas 1000) "
                 "status=READY berjalan=ya\r\n") != NULL);
    CHECK(strstr(g_serial_cap, "PANIC: tepukan terakhir tick=100 tepukan=1 jeda_maks=0\r\n") != NULL);
}

static void test_fire_saved(void)
{
    struct exception_context c;
    uint64_t stack[24];

    wd_reset();
    memset(&c, 0, sizeof(c));
    c.rip = 0x1111;   // milik task lain (idle): tidak boleh dipakai
    c.rbp = 0x2222;
    current_index = 2;
    timer_ticks = 50;
    watchdog_pet();

    // Konteks context_switch: r15..r8 di [0..7], rbp [8], rdi..rax [9..14], ret [15].
    for (int i = 0; i < 24; i++) {
        stack[i] = 0xdead0000ULL + (uint64_t)i;
    }
    stack[8] = 0xffff800000def000ULL;
    stack[15] = 0xffffffff80005678ULL;
    tasks[2].rsp = (uint64_t)(uintptr_t)stack;
    tasks[2].status = TASK_BLOCKED;
    current_index = 5;   // idle sedang berjalan

    uint64_t rip = 0, rbp = 0;
    wd_saved_frame(tasks[2].rsp, &rip, &rbp);
    CHECK(rip == stack[15] && rbp == stack[8]);

    timer_ticks = 1050;
    CHECK(check_fires(&c) == 0);   // jeda 1000: belum
    timer_ticks = 4000;
    serial_capture_reset();
    CHECK(check_fires(&c) == 1);
    CHECK(g_panic_rip == 0xffffffff80005678ULL && g_panic_rbp == 0xffff800000def000ULL);
    CHECK(strstr(g_serial_cap, "tanpa tepukan 3950 tick (batas 1000) status=BLOCKED "
                 "berjalan=tidak\r\n") != NULL);

    tasks[2].status = TASK_SLEEPING;
    serial_capture_reset();
    CHECK(check_fires(&c) == 1);
    CHECK(strstr(g_serial_cap, "status=SLEEPING berjalan=tidak") != NULL);
}

static int exec(const char *c)
{
    g_out_len = 0;
    g_out[0] = '\0';
    return wd_test_execute((const volatile uint8_t *)c, (uint32_t)strlen(c));
}

static void test_cmd(void)
{
    g_timer_started = 0;
    CHECK(exec("wdtest") == 0);
    CHECK(exec("wdtest xx") == 0);
    CHECK(exec("wdtest loopx") == 0);
    CHECK(g_timer_started == 0 && g_wd_test_kind == -1);

    CHECK(exec("wdtest blok") == 1);
    CHECK_STR(g_out, "wdtest: net task macet (blok) dalam 1 detik\n");
    CHECK(g_timer_started == 1 && g_timer_ticks == 100 && g_wd_test_kind == 1);

    CHECK(exec("wdtest loop") == 1);
    CHECK_STR(g_out, "ERR: uji watchdog sudah dijadwalkan\n");
    CHECK(g_timer_started == 1 && g_wd_test_kind == 1);

    g_wd_test_kind = -1;
    CHECK(exec("wdtest loop") == 1);
    CHECK_STR(g_out, "wdtest: net task macet (loop) dalam 1 detik\n");
    CHECK(g_wd_test_kind == 0);
}

int main(void)
{
    test_overdue();
    test_pet();
    test_fire_running();
    test_fire_saved();
    test_cmd();
    return test_done("watchdog");
}

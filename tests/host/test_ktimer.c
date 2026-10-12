// C3a: uji timer kernel (kernel/ktimer.c) di host. ktimer.c disertakan
// langsung (#include) supaya senarai g_ktimers bisa diperiksa. timer_ticks
// diatur tangan; ktimer_selftest() tidak diuji di sini (butuh scheduler).

#include <stdlib.h>
#include "test.h"
#include "ktimer.c"

void task_sleep(uint64_t ticks)
{
    timer_ticks += ticks;
}

#define LOG_MAX 4096
static int g_log[LOG_MAX];
static uint64_t g_log_tick[LOG_MAX];
static int g_log_n;

static void rec(void *arg)
{
    if (g_log_n < LOG_MAX) {
        g_log[g_log_n] = (int)(intptr_t)arg;
        g_log_tick[g_log_n] = timer_ticks;
        g_log_n++;
    }
}

static void reset(void)
{
    g_ktimers = 0;
    g_log_n = 0;
    timer_ticks = 1000;
    g_ktimer_fired = g_ktimer_cancelled = g_ktimer_late_max = 0;
}

// Senarai harus terurut deadline, tanpa siklus, dan hanya berisi timer armed.
static int list_ok(void)
{
    int n = 0;
    for (ktimer_t *t = g_ktimers; t != 0; t = t->next) {
        if (!t->armed || (t->next && t->next->deadline < t->deadline) || ++n > 10000) {
            return 0;
        }
    }
    return 1;
}

static void test_basic(void)
{
    ktimer_t a = { 0 }, b = { 0 }, c = { 0 };

    reset();
    ktimer_start(&a, 10, rec, (void *)1);
    ktimer_start(&b, 5, rec, (void *)2);
    ktimer_start(&c, 10, rec, (void *)3);   // deadline sama dengan a: jalan setelah a
    CHECK(list_ok() && g_ktimers == &b);

    timer_ticks += 4;
    CHECK(ktimer_run() == 0);
    timer_ticks += 1;
    CHECK(ktimer_run() == 1 && g_log[0] == 2 && !ktimer_pending(&b));
    timer_ticks += 7;   // terlambat 2 tick
    CHECK(ktimer_run() == 2 && g_log[1] == 1 && g_log[2] == 3);
    CHECK(g_ktimer_late_max == 2 && g_ktimer_fired == 3);
    CHECK(g_ktimers == 0);

    // Batal: hanya sekali, timer yang sudah jalan tidak bisa dibatalkan.
    ktimer_start(&a, 3, rec, (void *)1);
    CHECK(ktimer_cancel(&a) == 1 && ktimer_cancel(&a) == 0 && g_ktimer_cancelled == 1);
    timer_ticks += 10;
    CHECK(ktimer_run() == 0);
    CHECK(ktimer_cancel(&b) == 0);

    // Pasang ulang timer yang masih armed: pindah posisi, tidak ganda.
    ktimer_start(&a, 5, rec, (void *)1);
    ktimer_start(&b, 8, rec, (void *)2);
    ktimer_start(&a, 20, rec, (void *)1);
    CHECK(list_ok() && g_ktimers == &b && b.next == &a && a.next == 0);

    // ticks = 0 dianggap 1.
    ktimer_cancel(&a);
    ktimer_cancel(&b);
    ktimer_start(&c, 0, rec, (void *)3);
    CHECK(c.deadline == timer_ticks + 1 && ktimer_run() == 0);
}

// Callback memasang ulang dirinya dengan 0 tick: ktimer_run() harus selesai
// (timer baru jatuh di tick berikutnya, bukan tick yang sama).
static ktimer_t g_self;
static int g_self_n;

static void self_rearm(void *arg)
{
    (void)arg;
    g_self_n++;
    ktimer_start(&g_self, 0, self_rearm, 0);
}

static void test_self_rearm(void)
{
    reset();
    g_self_n = 0;
    ktimer_start(&g_self, 1, self_rearm, 0);
    for (int i = 0; i < 50; i++) {
        timer_ticks++;
        CHECK(ktimer_run() == 1);
    }
    CHECK(g_self_n == 50);
    ktimer_cancel(&g_self);
}

// Callback membatalkan timer lain yang juga sudah jatuh tempo.
static ktimer_t g_x, g_y;

static void cancel_y(void *arg)
{
    rec(arg);
    ktimer_cancel(&g_y);
}

static void test_cancel_from_callback(void)
{
    reset();
    ktimer_start(&g_x, 5, cancel_y, (void *)7);
    ktimer_start(&g_y, 5, rec, (void *)8);
    timer_ticks += 5;
    CHECK(ktimer_run() == 1 && g_log_n == 1 && g_log[0] == 7 && !ktimer_pending(&g_y));
}

// Acak: 64 timer, operasi start/cancel/run dibandingkan dengan model
// (deadline + urutan pasang per timer).
#define NT 64

static void test_model(void)
{
    static ktimer_t t[NT];
    uint64_t m_deadline[NT];
    uint64_t m_seq[NT];
    int m_armed[NT];
    uint64_t seq = 0;
    int ok = 1;

    reset();
    memset(t, 0, sizeof(t));
    memset(m_armed, 0, sizeof(m_armed));
    srand(42);

    for (int it = 0; it < 200000 && ok; it++) {
        int op = rand() % 10;
        int i = rand() % NT;

        if (op < 5) {
            uint64_t ticks = (uint64_t)(rand() % 50);
            ktimer_start(&t[i], ticks, rec, (void *)(intptr_t)i);
            m_deadline[i] = timer_ticks + (ticks ? ticks : 1);
            m_seq[i] = seq++;
            m_armed[i] = 1;
        } else if (op < 7) {
            int r = ktimer_cancel(&t[i]);
            ok &= r == m_armed[i];
            m_armed[i] = 0;
        } else {
            timer_ticks += (uint64_t)(rand() % 6);
            // Harapan: semua armed dengan deadline <= now, urut (deadline, seq).
            int want[NT], nw = 0;
            for (int k = 0; k < NT; k++) {
                if (m_armed[k] && m_deadline[k] <= timer_ticks) {
                    want[nw++] = k;
                }
            }
            for (int a = 1; a < nw; a++) {
                for (int b = a; b > 0; b--) {
                    int p = want[b - 1], q = want[b];
                    if (m_deadline[q] < m_deadline[p] ||
                        (m_deadline[q] == m_deadline[p] && m_seq[q] < m_seq[p])) {
                        want[b - 1] = q;
                        want[b] = p;
                    }
                }
            }
            g_log_n = 0;
            int n = ktimer_run();
            ok &= n == nw && g_log_n == nw;
            for (int k = 0; ok && k < nw; k++) {
                ok &= g_log[k] == want[k];
                m_armed[want[k]] = 0;
            }
        }
        for (int k = 0; ok && k < NT; k++) {
            ok &= ktimer_pending(&t[k]) == m_armed[k];
        }
        ok &= list_ok();
        if (!ok) {
            fprintf(stderr, "GAGAL model di iterasi %d (op %d timer %d)\n", it, op, i);
        }
    }
    CHECK(ok);
}

int main(void)
{
    test_basic();
    test_self_rearm();
    test_cancel_from_callback();
    test_model();
    return test_done("ktimer");
}

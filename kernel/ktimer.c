#include "kernel.h"

// C3a: timer kernel dengan callback pada tick ke-N, bisa dibatalkan.
//
// ktimer_t dimiliki pemanggil (statis, tanpa heap) dan disimpan di senarai
// terurut deadline; batas atas jumlah timer = jumlah ktimer_t yang ada di
// kode. Callback dijalankan oleh ktimer_run() di konteks task (loop net
// task, dibangunkan tiap tick), BUKAN di IRQ: callback boleh mengirim paket
// dan menulis log. Akibatnya timer hanya dilayani selama net task hidup
// (tanpa NIC tidak ada net task) dan bisa terlambat bila net task sibuk.
//
// Timer dilepas dari senarai sebelum callback-nya dipanggil, jadi callback
// boleh memasang ulang timernya sendiri. ticks = 0 dianggap 1 supaya timer
// yang memasang ulang diri tidak membuat ktimer_run() berputar selamanya.

static ktimer_t *g_ktimers;   // terurut deadline naik; deadline sama = urutan pasang

uint64_t g_ktimer_fired = 0;
uint64_t g_ktimer_cancelled = 0;
uint64_t g_ktimer_late_max = 0;   // keterlambatan terbesar (tick) saat callback jalan

static void ktimer_unlink(ktimer_t *t)
{
    ktimer_t **pp = &g_ktimers;

    while (*pp != 0) {
        if (*pp == t) {
            *pp = t->next;
            break;
        }
        pp = &(*pp)->next;
    }
    t->next = 0;
    t->armed = 0;
}

void ktimer_start(ktimer_t *t, uint64_t ticks, void (*fn)(void *arg), void *arg)
{
    if (ticks == 0) {
        ticks = 1;
    }

    uint64_t flags = irq_save();

    if (t->armed) {
        ktimer_unlink(t);
    }

    t->deadline = timer_ticks + ticks;
    t->fn = fn;
    t->arg = arg;
    t->armed = 1;

    ktimer_t **pp = &g_ktimers;
    while (*pp != 0 && (*pp)->deadline <= t->deadline) {
        pp = &(*pp)->next;
    }
    t->next = *pp;
    *pp = t;

    irq_restore(flags);
}

// Return 1 bila timer tadinya terpasang (dan kini tidak akan jalan), 0 bila
// sudah jalan, sudah dibatalkan, atau tidak pernah dipasang.
int ktimer_cancel(ktimer_t *t)
{
    uint64_t flags = irq_save();
    int was = t->armed;

    if (was) {
        ktimer_unlink(t);
        g_ktimer_cancelled++;
    }
    irq_restore(flags);
    return was;
}

int ktimer_pending(const ktimer_t *t)
{
    return t->armed;
}

// Jalankan semua timer dengan deadline <= tick saat ini, urut deadline.
// Return jumlah callback yang dijalankan.
int ktimer_run(void)
{
    int n = 0;
    uint64_t now = timer_ticks;

    for (;;) {
        uint64_t flags = irq_save();
        ktimer_t *t = g_ktimers;

        if (t == 0 || t->deadline > now) {
            irq_restore(flags);
            break;
        }

        g_ktimers = t->next;
        t->next = 0;
        t->armed = 0;
        if (now - t->deadline > g_ktimer_late_max) {
            g_ktimer_late_max = now - t->deadline;
        }
        g_ktimer_fired++;

        void (*fn)(void *) = t->fn;
        void *arg = t->arg;
        irq_restore(flags);

        fn(arg);
        n++;
    }
    return n;
}

// ---- self-test saat net task mulai (butuh interrupt aktif) ----

#define KT_TEST_EVENTS 8

static uint64_t g_kt_tick[KT_TEST_EVENTS];
static char g_kt_id[KT_TEST_EVENTS];
static int g_kt_n;
static ktimer_t g_kt_a, g_kt_b, g_kt_c, g_kt_r;
static int g_kt_rearm;

static void kt_record(void *arg)
{
    if (g_kt_n < KT_TEST_EVENTS) {
        g_kt_id[g_kt_n] = (char)(uintptr_t)arg;
        g_kt_tick[g_kt_n] = timer_ticks;
        g_kt_n++;
    }
}

static void kt_rearm(void *arg)
{
    kt_record(arg);
    if (++g_kt_rearm < 3) {
        ktimer_start(&g_kt_r, 4, kt_rearm, arg);
    }
}

void ktimer_selftest(void)
{
    uint64_t t0 = timer_ticks;

    g_kt_n = 0;
    g_kt_rearm = 0;
    ktimer_start(&g_kt_a, 10, kt_record, (void *)'A');
    ktimer_start(&g_kt_b, 5, kt_record, (void *)'B');    // dibatalkan
    ktimer_start(&g_kt_c, 20, kt_record, (void *)'C');
    ktimer_start(&g_kt_r, 3, kt_rearm, (void *)'R');     // 3, 7, 11
    int cancel_ok = ktimer_cancel(&g_kt_b) == 1 && ktimer_cancel(&g_kt_b) == 0 &&
                    !ktimer_pending(&g_kt_b) && ktimer_pending(&g_kt_a);

    while (timer_ticks - t0 < 30) {
        task_sleep(1);
        ktimer_run();
    }

    // Urutan yang diharapkan: R(3) R(7) A(10) R(11) C(20); B tidak pernah.
    static const char want[] = "RRARC";
    int order_ok = g_kt_n == 5;
    for (int i = 0; order_ok && i < 5; i++) {
        order_ok = g_kt_id[i] == want[i];
    }
    static const uint64_t due[5] = { 3, 7, 10, 11, 20 };
    uint64_t late = 0;
    int time_ok = order_ok;
    for (int i = 0; time_ok && i < 5; i++) {
        uint64_t at = g_kt_tick[i] - t0;
        time_ok = at >= due[i];
        if (at - due[i] > late) {
            late = at - due[i];
        }
    }
    // Batas longgar: net task bergiliran round-robin dengan task lain (build
    // dev punya task uji), jadi bisa menunggu beberapa tick sebelum jalan.
    time_ok = time_ok && late <= 10;

    // task_sleep(20) harus tidur paling sedikit 20 tick (paling lambat 30).
    uint64_t s0 = timer_ticks;
    task_sleep(20);
    uint64_t slept = timer_ticks - s0;
    int sleep_ok = slept >= 20 && slept <= 30;

    kprintf("Timer: self-test %s (urutan=%s batal=%s telat_maks=%lu tick, sleep 20 -> %lu tick)\r\n",
            order_ok && time_ok && cancel_ok && sleep_ok ? "PASS" : "FAIL",
            order_ok ? "ok" : "SALAH", cancel_ok ? "ok" : "SALAH", late, slept);
}

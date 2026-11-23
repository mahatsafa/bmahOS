// F7 SMP-1: uji spinlock (kernel.h). Kontensi lewat pthread; trylock untuk kunci yang dipegang.

#include <pthread.h>
#include <stdint.h>
#include "kernel.h"
#include "test.h"

// Uji kunci serial (kernel/serial.c di-#include): CPU palsu lewat cpu_index().
static int g_fake_cpu;
int cpu_index(void) { return g_fake_cpu; }
void fbcon_putc(char c) { (void)c; }
void log_capture(char c) { (void)c; }
#include "serial.c"

static spinlock_t g_lock = SPINLOCK_INIT;
static uint64_t g_counter;

#define THREADS 4
#define ITER    100000

static void *worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < ITER; i++) {
        spin_lock(&g_lock);
        g_counter++;
        spin_unlock(&g_lock);
    }
    return NULL;
}

static void test_basic(void)
{
    spinlock_t l = SPINLOCK_INIT;

    CHECK(l.v == 0);
    spin_lock(&l);
    CHECK(l.v == 1);
    CHECK(!spin_trylock(&l));   // sudah dipegang
    spin_unlock(&l);
    CHECK(l.v == 0);
    CHECK(spin_trylock(&l));
    CHECK(l.v == 1);
    spin_unlock(&l);

    uint64_t f = spin_lock_irqsave(&l);
    CHECK(l.v == 1 && !spin_trylock(&l));
    spin_unlock_irqrestore(&l, f);
    CHECK(l.v == 0);
}

static void test_contention(void)
{
    pthread_t t[THREADS];

    g_counter = 0;
    for (int i = 0; i < THREADS; i++) {
        CHECK(pthread_create(&t[i], NULL, worker, NULL) == 0);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
    }
    CHECK(g_counter == (uint64_t)THREADS * ITER);
    CHECK(g_lock.v == 0);
}

static void test_serial_lock(void)
{
    uint64_t f1, f2;

    g_fake_cpu = 0;
    f1 = serial_lock();
    CHECK(g_serial_owner == 0 && g_serial_depth == 1 && g_serial_lock.v == 1);
    f2 = serial_lock();                       // reentran (pemilik sama)
    CHECK(g_serial_depth == 2);
    serial_write("");                         // mengunci lagi lalu melepas (UART host tak dipanggil)
    CHECK(g_serial_depth == 2);
    serial_unlock(f2);
    CHECK(g_serial_depth == 1 && g_serial_lock.v == 1);

    g_fake_cpu = 1;                           // bukan pemilik: unlock diabaikan
    serial_unlock(0);
    CHECK(g_serial_depth == 1 && g_serial_owner == 0 && g_serial_lock.v == 1);
    g_fake_cpu = 0;
    serial_unlock(f1);
    CHECK(g_serial_depth == 0 && g_serial_owner == -1 && g_serial_lock.v == 0);
    serial_unlock(0);                         // tanpa pemegang: tidak merusak
    CHECK(g_serial_depth == 0 && g_serial_lock.v == 0);

    g_fake_cpu = MAX_CPUS;                    // sentinel: kunci biasa, owner = sentinel
    f1 = serial_lock();
    CHECK(g_serial_owner == MAX_CPUS && g_serial_depth == 1 && g_serial_lock.v == 1);
    serial_unlock(f1);
    CHECK(g_serial_depth == 0 && g_serial_lock.v == 0);

    g_fake_cpu = 0;                           // panic: reset memutus kunci yang ditinggal
    f1 = serial_lock();
    serial_lock_reset();
    CHECK(g_serial_depth == 0 && g_serial_owner == -1 && g_serial_lock.v == 0);
    serial_unlock(f1);                        // pemegang lama: diabaikan
    CHECK(g_serial_depth == 0 && g_serial_lock.v == 0);
}

int main(void)
{
    test_serial_lock();
    test_basic();
    test_contention();
    return test_done("spinlock");
}

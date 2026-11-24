// F7 SMP-2: uji inti BKL (kernel/bkl.c, di-#include): kunci tiket + pembukuan pemilik, aturan lepas saat
// keluar ISR (ring 3 / jendela idle), dan kontensi lewat pthread (pengecualian bersama + pemilik benar).

#include <pthread.h>
#include <stdint.h>
#include "kernel.h"
#include "test.h"

#include "bkl.c"

static void test_dasar(void)
{
    bkl_t l = { 0, 0, -1 };
    uint64_t spins = 0;

    CHECK(!bkl_core_held(&l, 0));
    bkl_core_lock(&l, 0, NULL, &spins, 0);
    CHECK(bkl_core_held(&l, 0));
    CHECK(!bkl_core_held(&l, 1));
    CHECK(l.next == 1 && l.serving == 0);
    bkl_core_unlock(&l, 1);   // bukan pemilik: tidak melepas
    CHECK(bkl_core_held(&l, 0) && l.serving == 0);
    bkl_core_unlock(&l, 0);
    CHECK(!bkl_core_held(&l, 0) && l.owner == -1 && l.serving == 1);
    bkl_core_lock(&l, 3, NULL, &spins, 0);
    CHECK(bkl_core_held(&l, 3) && spins == 0);
    bkl_core_unlock(&l, 3);
    CHECK(!bkl_core_held(&l, -1));   // indeks tak sah tak pernah pemilik
}

static void test_awal_bsp(void)
{
    bkl_t l = BKL_INIT_BSP;

    // BSP memegang sejak boot: tiket sudah diambil.
    CHECK(l.next == 1 && l.serving == 0 && l.owner == 0);
    CHECK(bkl_core_held(&l, 0));
    bkl_core_unlock(&l, 0);
    CHECK(l.serving == 1 && l.next == 1 && l.owner == -1);
    bkl_core_lock(&l, 1, NULL, NULL, 0);
    CHECK(bkl_core_held(&l, 1));
}

static void test_aturan_keluar(void)
{
    uint64_t lo = 0x1000, hi = 0x1001;

    CHECK(bkl_exit_releases(0x2B, 0x400000, lo, hi));     // kembali ke ring 3 (RPL 3)
    CHECK(bkl_exit_releases(0x33, 0x400000, lo, hi));
    CHECK(bkl_exit_releases(0x08, lo, lo, hi));           // kembali tepat ke hlt di jendela idle
    CHECK(bkl_exit_releases(0x08, hi, lo, hi));           // atau sesudah hlt
    CHECK(!bkl_exit_releases(0x08, 0x2000, lo, hi));      // kode kernel biasa: BKL tetap dipegang
    CHECK(!bkl_exit_releases(0x08, hi + 1, lo, hi));      // di luar jendela
    CHECK(!bkl_exit_releases(0x08, lo - 1, lo, hi));
}

// Simulasi ISR: masuk (ambil bila bukan pemilik), keluar (lepas bila ke ring 3/idle).
static bkl_t g_isr = BKL_INIT_BSP;

static int isr_enter(int cpu)
{
    if (bkl_core_held(&g_isr, cpu)) {
        return 0;
    }
    bkl_core_lock(&g_isr, cpu, NULL, NULL, 0);
    return 1;
}

static void isr_leave(int cpu, uint64_t cs, uint64_t rip)
{
    if (bkl_exit_releases(cs, rip, 0x1000, 0x1001)) {
        bkl_core_unlock(&g_isr, cpu);
    }
}

static void test_isr(void)
{
    // BSP pemilik (kode kernel jalan): ISR dari ring 0 tidak mengambil/melepas.
    CHECK(isr_enter(0) == 0);
    isr_leave(0, 0x08, 0x2000);
    CHECK(bkl_core_held(&g_isr, 0));
    // Kembali ke ring 3: lepas.
    isr_leave(0, 0x2B, 0x400000);
    CHECK(!bkl_core_held(&g_isr, 0));
    // AP dari ring 3 mengambil, kembali ke ring 3 melepas.
    CHECK(isr_enter(1) == 1 && bkl_core_held(&g_isr, 1));
    isr_leave(1, 0x2B, 0x400000);
    CHECK(g_isr.owner == -1);
    // Dari jendela idle (RIP di hlt, bukan pemilik): ambil, dan kembali ke jendela idle melepas.
    CHECK(isr_enter(1) == 1);
    isr_leave(1, 0x08, 0x1001);
    CHECK(g_isr.owner == -1);
    // ISR menyela kode kernel, di dalamnya pindah task, kembali ke kode kernel: tetap dipegang.
    CHECK(isr_enter(2) == 1);
    CHECK(isr_enter(2) == 0);   // ISR bersarang di CPU yang sama tidak mengambil lagi
    isr_leave(2, 0x08, 0x2000);
    CHECK(bkl_core_held(&g_isr, 2));
    isr_leave(2, 0x2B, 0x400000);
    CHECK(g_isr.owner == -1);
}

#define THREADS 4
#define ITER    50000

static bkl_t g_l = { 0, 0, -1 };
static uint64_t g_counter;
static uint64_t g_polls;
static int g_violations;
static volatile int g_inside;

static void poll_hook(void)
{
    __atomic_fetch_add(&g_polls, 1, __ATOMIC_RELAXED);
}

static void *worker(void *arg)
{
    int me = (int)(intptr_t)arg;
    uint64_t spins = 0;

    for (int i = 0; i < ITER; i++) {
        bkl_core_lock(&g_l, me, poll_hook, &spins, 0);
        if (!bkl_core_held(&g_l, me)) {
            __atomic_fetch_add(&g_violations, 1, __ATOMIC_RELAXED);
        }
        if (__atomic_fetch_add(&g_inside, 1, __ATOMIC_SEQ_CST) != 0) {
            __atomic_fetch_add(&g_violations, 1, __ATOMIC_RELAXED);
        }
        g_counter++;
        __atomic_fetch_sub(&g_inside, 1, __ATOMIC_SEQ_CST);
        bkl_core_unlock(&g_l, me);
    }
    return NULL;
}

static void test_kontensi(void)
{
    pthread_t t[THREADS];

    for (int i = 0; i < THREADS; i++) {
        CHECK(pthread_create(&t[i], NULL, worker, (void *)(intptr_t)i) == 0);
    }
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
    }
    CHECK(g_counter == (uint64_t)THREADS * ITER);
    CHECK(g_violations == 0);
    CHECK(g_l.owner == -1 && g_l.next == g_l.serving);
    CHECK(g_l.next == (uint32_t)(THREADS * ITER));
}

// Review SMP-2 #3: hitungan CPU berhenti dihitung sekali walau smp_stop_self dipanggil dua kali.
static void test_halt_mark(void)
{
    volatile uint32_t flag[4] = {0, 0, 0, 0};
    volatile uint32_t count = 0;

    CHECK(smp_halt_mark(&flag[1], &count) == 1 && count == 1);
    CHECK(smp_halt_mark(&flag[1], &count) == 0 && count == 1);   // CPU yang sama lagi (panic kalah + NMI)
    CHECK(smp_halt_mark(&flag[2], &count) == 1 && count == 2);
    CHECK(smp_halt_mark(&flag[2], &count) == 0 && smp_halt_mark(&flag[1], &count) == 0 && count == 2);
}

// Review SMP-2 #7: permintaan berurutan tidak bercampur dan ack lama tidak dihitung untuk permintaan baru.
static void test_tlbreq(void)
{
    tlbreq_t r;
    uint64_t va, seq;
    uint32_t n;

    memset(&r, 0, sizeof(r));
    CHECK(!tlbreq_take(&r, 1, &va, &n, &seq));   // belum ada permintaan
    uint64_t s1 = tlbreq_begin(&r, 0x1000, 1, 0x6);   // CPU 1 dan 2
    CHECK(s1 == 2 && (s1 & 1) == 0);
    CHECK(!tlbreq_take(&r, 0, &va, &n, &seq));   // CPU 0 bukan tujuan
    CHECK(!tlbreq_take(&r, 3, &va, &n, &seq));
    CHECK(tlbreq_take(&r, 1, &va, &n, &seq) && va == 0x1000 && n == 1 && seq == s1);
    CHECK(tlbreq_missing(&r, 0x6, s1) == 0x6);
    tlbreq_ack(&r, 1, seq);
    CHECK(!tlbreq_take(&r, 1, &va, &n, &seq));   // sudah dijawab: tidak diproses dua kali
    CHECK(tlbreq_missing(&r, 0x6, s1) == 0x4);
    // Timeout: CPU 2 tidak menjawab. Permintaan baru dimulai.
    tlbreq_end(&r);
    CHECK(!tlbreq_take(&r, 2, &va, &n, &seq));   // need = 0
    uint64_t s2 = tlbreq_begin(&r, 0x7000, 4, 0x6);
    CHECK(s2 == s1 + 2);
    CHECK(tlbreq_missing(&r, 0x6, s2) == 0x6);   // ack CPU 1 milik s1 tidak dihitung untuk s2
    CHECK(tlbreq_take(&r, 2, &va, &n, &seq) && va == 0x7000 && n == 4 && seq == s2);
    // CPU 2 terlambat mengambil permintaan lama? Tidak mungkin: yang terbaca selalu permintaan s2 yang konsisten.
    tlbreq_ack(&r, 2, seq);
    CHECK(tlbreq_missing(&r, 0x6, s2) == 0x2);
    // Sedang ditulis (seq ganjil): tidak ada yang boleh membaca.
    r.seq++;
    CHECK(!tlbreq_take(&r, 1, &va, &n, &seq));
    r.seq++;
    CHECK(tlbreq_take(&r, 1, &va, &n, &seq) && seq == r.seq);
}

// Batas TSC pada bkl_core_lock (host: tsc_read = 0 -> tidak pernah menyerah; kunci yang bebas tetap didapat).
static void test_batas(void)
{
    bkl_t l = { 0, 0, -1 };

    CHECK(bkl_core_lock(&l, 0, NULL, NULL, 1000) == 1 && bkl_core_held(&l, 0));
}

int main(void)
{
    test_halt_mark();
    test_tlbreq();
    test_batas();
    test_dasar();
    test_awal_bsp();
    test_aturan_keluar();
    test_isr();
    test_kontensi();
    return test_done("bkl");
}

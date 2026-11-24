#include "kernel.h"

// ============================================================
// F7 SMP-2: Big Kernel Lock (BKL).
//
// Satu kunci global untuk SELURUH kode kernel: task kernel, syscall, ISR yang menyentuh data
// bersama, schedule(), alokator. Hanya kode ring 3 yang benar-benar paralel antar CPU. Kunci
// halus per subsistem sengaja BELUM ada (tahap lain).
//
// Bentuk kunci: tiket (adil, tanpa kelaparan). Pemilik = INDEKS CPU, bukan task: task yang
// pindah konteks di dalam kernel mewarisi BKL milik CPU-nya.
//
// INVARIAN (diperiksa ASSERT di build dev):
//  I1. CPU yang menjalankan kode kernel (task kernel, syscall, ISR yang menyentuh data
//      bersama, schedule()) memegang BKL. Lepas hanya di dua tempat:
//        (a) saat kembali ke ring 3 (bkl_isr_leave sebelum iretq; bkl_to_user di jalur
//            pertama kali masuk ring 3), dan
//        (b) saat idle, sebelum "sti; hlt" (bkl_idle_wait); diambil lagi sesudah bangun.
//  I2. Semua pengambilan/pelepasan BKL berlangsung dengan IF=0 (ISR = interrupt gate; task
//      idle cli dulu; jalur ke ring 3 cli dulu). Dengan begitu tidak ada interrupt yang
//      menyelip di antara "lepas BKL" dan iretq / hlt.
//  I3. schedule() hanya jalan dengan BKL milik CPU ini dan IF=0. context_switch dilakukan
//      DI BAWAH BKL: task baru langsung mewarisi BKL CPU ini (tidak ada serah-terima kunci).
//  I4. Urutan kunci: BKL dulu, baru kunci serial (dan spinlock kecil lain). Jangan pernah
//      mengambil BKL sambil memegang kunci serial. Dijamin: BKL diambil hanya di awal ISR
//      (dari ring 3 / jendela idle, saat belum memegang apa pun), di awal AP masuk
//      scheduler, dan sesudah bangun dari idle. Perintah `log` memegang kunci serial saat
//      menyalin ring tetapi tidak pernah meminta BKL di dalamnya.
//  I5. Handler yang TIDAK mengambil BKL (hanya sentuh data per-CPU/atomik): IPI TLB
//      shootdown, IPI uji, IPI resched sebelum scheduler AP hidup, NMI (panic), IRQ liar.
//      Tunggu BKL (bkl_core_lock) memanggil tlb_service() tiap putaran, sehingga CPU yang
//      menunggu BKL dengan IF=0 tetap menjawab shootdown (kalau tidak: pemegang BKL menunggu
//      ack sambil CPU tujuan menunggu BKL = deadlock).
//
// Pembukuan masuk/keluar ISR (bkl_isr_enter / bkl_isr_leave), tanpa menyimpan "apakah aku
// yang mengambil" di stack (task bisa pindah stack di tengah ISR lewat context_switch, dan
// ISR yang dilanjutkan belakangan di CPU yang sama harus tetap benar):
//   MASUK : bila CPU ini sudah pemilik (interrupt datang saat kode kernel jalan) -> tidak
//           melakukan apa pun. Bila bukan (datang dari ring 3 atau dari jendela idle) -> ambil.
//   KELUAR: dilepas bila ISR akan kembali ke ring 3 (CS RPL 3), atau kembali ke jendela idle
//           (RIP == bkl_idle_hlt / bkl_idle_after, tempat kode idle memang tidak
//           memegang BKL). Selain itu (kembali ke kode kernel) BKL tetap dipegang.
//   Hanya keadaan frame yang menentukan, jadi benar juga setelah ISR melompat ke task lain.
// Task user pertama kali masuk ring 3 (user_task_trampoline) melepas BKL lewat bkl_to_user.
// Exception/kill task user (task_exit) pindah ke task lain di CPU yang sama (BKL mengalir);
// jalur kembali ke ring 3 melepasnya seperti biasa.
// Panic: NMI menghentikan CPU lain; pemenang panic tidak memerlukan BKL.
// ============================================================

bkl_t g_bkl = BKL_INIT_BSP;

// ---- inti kunci (murni: dipakai juga oleh uji host) ----

int bkl_core_lock(bkl_t *l, int cpu, void (*poll)(void), uint64_t *spins, uint64_t tsc_limit)
{
    uint32_t t = __atomic_fetch_add(&l->next, 1, __ATOMIC_SEQ_CST);
    uint64_t t0 = tsc_limit ? tsc_read() : 0;

    while (__atomic_load_n(&l->serving, __ATOMIC_ACQUIRE) != t) {
        if (spins != NULL) {
            (*spins)++;
        }
        if (poll != NULL) {
            poll();
        }
        if (tsc_limit && tsc_read() - t0 > tsc_limit) {
            return 0;   // pemanggil panic; tiket ini tidak pernah dilayani lagi
        }
#ifndef BMAHOS_HOST_TEST
        __builtin_ia32_pause();
#endif
    }
    __atomic_store_n(&l->owner, cpu, __ATOMIC_RELAXED);
    return 1;
}

void bkl_core_unlock(bkl_t *l, int cpu)
{
    if (__atomic_load_n(&l->owner, __ATOMIC_RELAXED) != cpu) {
        return;   // bukan pemilik: tidak melepas milik CPU lain
    }
    __atomic_store_n(&l->owner, -1, __ATOMIC_RELAXED);
    __atomic_store_n(&l->serving, l->serving + 1, __ATOMIC_RELEASE);
}

int bkl_core_held(const bkl_t *l, int cpu)
{
    return cpu >= 0 && __atomic_load_n(&l->owner, __ATOMIC_RELAXED) == cpu;
}

// ---- permintaan TLB shootdown (murni, lihat kernel.h) ----

uint64_t tlbreq_begin(tlbreq_t *r, uint64_t va, uint32_t npages, uint32_t mask)
{
    __atomic_store_n(&r->need, 0, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&r->seq, 1, __ATOMIC_SEQ_CST);   // ganjil: sedang ditulis
    r->va = va;
    r->npages = npages;
    uint64_t s = __atomic_add_fetch(&r->seq, 1, __ATOMIC_SEQ_CST);   // genap: stabil

    __atomic_store_n(&r->need, mask, __ATOMIC_SEQ_CST);
    return s;
}

int tlbreq_take(tlbreq_t *r, int cpu, uint64_t *va, uint32_t *npages, uint64_t *seq)
{
    if (cpu < 0 || cpu >= MAX_CPUS || !(__atomic_load_n(&r->need, __ATOMIC_SEQ_CST) & (1u << cpu))) {
        return 0;
    }
    uint64_t s1 = __atomic_load_n(&r->seq, __ATOMIC_SEQ_CST);

    if ((s1 & 1) || __atomic_load_n(&r->ack[cpu], __ATOMIC_SEQ_CST) == s1) {
        return 0;   // sedang ditulis (dicoba lagi lewat poll) atau permintaan ini sudah dijawab
    }
    uint64_t v = r->va;
    uint32_t n = r->npages;

    if (__atomic_load_n(&r->seq, __ATOMIC_SEQ_CST) != s1) {
        return 0;   // berganti permintaan di tengah baca: buang bacaan, coba lagi nanti
    }
    *va = v;
    *npages = n;
    *seq = s1;
    return 1;
}

void tlbreq_ack(tlbreq_t *r, int cpu, uint64_t seq)
{
    __atomic_store_n(&r->ack[cpu], seq, __ATOMIC_SEQ_CST);
}

uint32_t tlbreq_missing(const tlbreq_t *r, uint32_t mask, uint64_t seq)
{
    uint32_t miss = 0;

    for (int i = 0; i < MAX_CPUS; i++) {
        if ((mask & (1u << i)) && __atomic_load_n(&r->ack[i], __ATOMIC_SEQ_CST) != seq) {
            miss |= 1u << i;
        }
    }
    return miss;
}

void tlbreq_end(tlbreq_t *r)
{
    __atomic_store_n(&r->need, 0, __ATOMIC_SEQ_CST);
}

// CPU ditandai berhenti tepat sekali (CPU yang kalah panic lalu menerima NMI juga memanggil smp_stop_self).
int smp_halt_mark(volatile uint32_t *flag, volatile uint32_t *counter)
{
    uint32_t expected = 0;

    if (!__atomic_compare_exchange_n(flag, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        return 0;
    }
    __atomic_fetch_add(counter, 1, __ATOMIC_SEQ_CST);
    return 1;
}

// 1 = ISR yang akan kembali ke (cs, rip) harus melepas BKL.
int bkl_exit_releases(uint64_t cs, uint64_t rip, uint64_t idle_lo, uint64_t idle_hi)
{
    return (cs & 3) == 3 || rip == idle_lo || rip == idle_hi;
}

#ifndef BMAHOS_HOST_TEST

uint64_t g_bsp_bkl_wait_tsc;   // diisi smp_init setelah kalibrasi TSC (5 detik); 0 = tanpa batas

// Batas tunggu hanya untuk BSP: BSP menunggu BKL dengan IF=0 berarti tick PIT (watchdog R5) berhenti, jadi
// AP yang macet memegang BKL harus berujung panic yang jelas, bukan sistem diam. AP boleh menunggu tanpa
// batas: BSP yang memegang BKL lama (TLS handshake, I/O disk) sah, dan bila BSP macet dengan IF=1 watchdog
// BSP sendiri yang memanggil panic.
static void bkl_acquire(int ci)
{
    cpu_t *c = this_cpu();
    uint64_t lim = ci == 0 ? g_bsp_bkl_wait_tsc : 0;

    if (!bkl_core_lock(&g_bkl, ci, tlb_service, &c->bkl_spin, lim)) {
        bkl_wait_panic(g_bkl.owner);   // tidak kembali
    }
    tlb_service();   // permintaan yang tidak sempat dijawab saat menunggu
}

void bkl_lock(void)
{
    int ci = cpu_index();

    ASSERT(g_bkl.owner != ci);   // tidak reentran: pemilik tidak boleh minta lagi
    bkl_acquire(ci);
}

void bkl_unlock(void)
{
    bkl_core_unlock(&g_bkl, cpu_index());
}

int bkl_held(void)
{
    return bkl_core_held(&g_bkl, cpu_index());
}

void bkl_isr_enter(void)
{
    int ci = cpu_index();

    if (bkl_core_held(&g_bkl, ci)) {
        return;
    }
    bkl_acquire(ci);
}

void bkl_isr_leave(const struct exception_context *c)
{
    int rel = bkl_exit_releases(c->cs, c->rip, (uint64_t)(uintptr_t)bkl_idle_hlt,
                                (uint64_t)(uintptr_t)bkl_idle_after);

    ASSERT(bkl_held());   // keluar ISR selalu dengan BKL di tangan
    if (rel) {
        bkl_unlock();
#ifndef BMAHOS_PROD
        ASSERT(!bkl_held());
#endif
    }
}

// Task user pertama kali masuk ring 3: lepas BKL lalu iretq (enter_usermode). IF=0 sampai iretq.
void bkl_to_user(void)
{
    __asm__ volatile("cli" ::: "memory");
    ASSERT(bkl_held());
    bkl_unlock();
    ASSERT(!bkl_held());
}

// Satu putaran idle (task idle tiap CPU): lepas BKL, tidur sampai interrupt, ambil lagi.
// Dipanggil dengan BKL milik CPU ini. Interrupt yang membangunkan (dan ISR-nya, yang
// mengambil BKL sendiri lalu melepasnya lagi di bkl_isr_leave) berlangsung di jendela asm.
void cpu_idle_once(void)
{
    __asm__ volatile("cli" ::: "memory");
    ASSERT(bkl_held());
    bkl_unlock();
    bkl_idle_wait();   // sti; hlt; cli
    bkl_lock();
}

#endif

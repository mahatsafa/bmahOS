#include <limine.h>
#include "kernel.h"

// ============================================================
// F7 SMP-1: bangunkan AP lewat Limine MP, per-CPU, IPI uji.
// Task, scheduler, IOAPIC tetap hanya di BSP. AP hanya: pindah ke
// page table kernel, GDT/TSS/IDT sendiri, LAPIC aktif, lalu sti+hlt
// (bangun hanya oleh IPI).
//
// Indeks CPU dicari dari ID LAPIC (bukan GS_BASE): kernel belum memakai swapgs,
// enter_usermode memuat selector 0x33 ke GS (mengubah GS_BASE CPU itu), dan ring 3
// bisa melakukan hal yang sama. ID LAPIC hanya dibaca ring 0 dan tidak bisa diubah user.
// ============================================================

extern volatile struct limine_mp_request mp_request;   // kernel.c (.limine_requests)

cpu_t g_cpus[MAX_CPUS];
volatile uint32_t g_smp_ncpu = 0;     // CPU tercatat (<= MAX_CPUS), 0 sebelum smp_init
volatile uint32_t g_smp_online = 0;   // CPU aktif (BSP termasuk)
volatile uint32_t g_smp_halted = 0;   // CPU yang sudah menerima IPI berhenti

// Stack AP: region sendiri di PML4 0x130 (bersama kheap/kstack/slab), tidak lewat kstack_alloc
// (tabelnya 16 stack, sudah dipakai task). Per CPU 64 KB virtual:
// [guard 4K][stack 16K][guard 4K][IST1 #DF 16K]; guard tidak dipetakan.
#define AP_STACK_BASE    (KHEAP_START + 0x5000000000ULL)   // kheap + 320 GB
#define AP_STACK_STRIDE  0x10000ULL
#define AP_STACK_SIZE    16384ULL
#define AP_WAIT_TICKS    200      // tunggu AP online / ack IPI, batas 2 s (tick 100 Hz)
#define AP_WAIT_SPIN     400000000ULL

// AP parkir Limine menjalankan kodenya dari alias HHDM; nx_harden_higher_half memberi NX pada
// HHDM, jadi AP yang masih di sana akan #PF (triple fault) kapan saja. Karena itu SEMUA AP
// (juga yang akan diabaikan > MAX_CPUS) dipindahkan lebih dulu, sebelum nx_harden, ke stub di
// .text kernel (smp_park_stub). Stub tanpa stack: cli, hitung masuk (atomik), lalu tunggu
// cpu_t.go != 0 (slot di extra_argument; 0 = tanpa slot -> cli;hlt selamanya). Sesudah go,
// lompat ke smp_ap_entry yang memasang CR3 kernel, stack sendiri, dst.
volatile uint32_t g_smp_parked = 0;
volatile uint64_t g_smp_stray = 0;     // IRQ timer/NIC yang salah masuk ke CPU selain BSP
static struct limine_mp_info *g_mp_info[MAX_CPUS];
static uint32_t g_total = 1;           // CPU bersedia (BSP + AP dengan slot)
static uint64_t g_limine_count = 0;    // cpu_count dari Limine
static uint32_t g_ignored = 0;
static int g_park_ok = 1;
volatile int g_smp_sched_ok = 0;       // SMP-2: kalibrasi timer LAPIC berhasil -> AP boleh menjalankan task
static uint32_t g_lapic_per_tick = 0;  // hitungan timer LAPIC (pembagi 16) per tick 10 ms
static uint64_t g_resched_tx = 0;      // IPI resched terkirim

__asm__(
    ".section .text\n"
    ".global smp_park_stub\n"
    ".type smp_park_stub, @function\n"
    "smp_park_stub:\n"
    "    cli\n"
    "    lock incl g_smp_parked(%rip)\n"
    "    movq 24(%rdi), %rax\n"          // limine_mp_info.extra_argument = cpu_t* atau 0
    "    testq %rax, %rax\n"
    "    jz 2f\n"
    "1:  pause\n"
    "    cmpl $0, (%rax)\n"              // cpu_t.go (offset 0)
    "    je 1b\n"
    "    jmp smp_ap_entry\n"             // rdi = info tetap utuh
    "2:  cli\n"
    "    hlt\n"
    "    jmp 2b\n"
    ".size smp_park_stub, .-smp_park_stub\n"
);
extern void smp_park_stub(void);
void smp_ap_entry(struct limine_mp_info *info);

// kmain: SEBELUM nx_harden_higher_half. 1 = semua AP sudah di stub (aman memasang NX HHDM).
int smp_park_aps(void)
{
    struct limine_mp_response *r = mp_request.response;
    uint32_t bsp = r ? r->bsp_lapic_id : 0;
    uint32_t expect = 0;

    g_cpus[0].index = 0;
    g_cpus[0].lapic_id = bsp;
    g_cpus[0].online = 1;
    if (r == NULL) {
        return 1;
    }
    g_limine_count = r->cpu_count;
    for (uint64_t i = 0; i < r->cpu_count; i++) {
        struct limine_mp_info *p = r->cpus[i];

        if (p->lapic_id == bsp) {
            continue;
        }
        if (g_total < MAX_CPUS) {
            g_cpus[g_total].index = g_total;
            g_cpus[g_total].lapic_id = p->lapic_id;
            g_mp_info[g_total] = p;
            p->extra_argument = (uint64_t)(uintptr_t)&g_cpus[g_total];
            g_total++;
        } else {
            p->extra_argument = 0;   // diabaikan: parkir selamanya di stub
            g_ignored++;
        }
        expect++;
        __atomic_store_n(&p->goto_address, (limine_goto_address)smp_park_stub, __ATOMIC_SEQ_CST);
    }
    for (uint64_t i = 0; i < AP_WAIT_SPIN && g_smp_parked < expect; i++) {
        __builtin_ia32_pause();
    }
    g_park_ok = g_smp_parked >= expect;
    if (!g_park_ok) {
        kprintf("SMP: hanya %u dari %u AP parkir di stub kernel, NX HHDM tidak dipasang\r\n",
                (unsigned)g_smp_parked, expect);
    }
    return g_park_ok;
}

// SMP-2: cpu_index() lewat IA32_TSC_AUX (MSR 0xC0000103) + RDTSCP bila CPUID mendukung (CPUID.80000001H:EDX[27]).
// Tiap CPU mengisi TSC_AUX = indeksnya sendiri (BSP di smp_init, AP di awal smp_ap_main). Murah (tanpa akses
// MMIO LAPIC yang di VM memicu exit), dan aman: ring 3 hanya bisa MEMBACA TSC_AUX lewat rdtscp (bocor indeks
// CPU, tidak berbahaya), tidak bisa menulisnya (wrmsr = #GP di ring 3). Tidak dipakai GS karena
// enter_usermode memuat GS user dan ring 3 bebas mengubahnya. RDPID tidak dipakai: rdtscp lebih luas
// didukung, selisih biayanya kecil. Tanpa RDTSCP: cadangan ID LAPIC (baca MMIO tiap panggilan).
volatile uint32_t g_tscaux_ok = 0;

#define MSR_TSC_AUX 0xC0000103u

static void tscaux_write(uint32_t v)
{
    __asm__ volatile("wrmsr" : : "a"(v), "d"(0), "c"(MSR_TSC_AUX));
}

static int cpu_has_rdtscp(void)
{
    uint32_t a, b, c, d;

    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000000u), "c"(0));
    if (a < 0x80000001u) {
        return 0;
    }
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000001u), "c"(0));
    return (d >> 27) & 1;
}

int cpu_index(void)
{
    if (!g_lapic_ready || g_smp_ncpu <= 1) {
        return 0;
    }
    if (g_tscaux_ok) {
        uint32_t lo, hi, aux;

        __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
        return aux < g_smp_ncpu ? (int)aux : MAX_CPUS;
    }
    uint32_t id = lapic_id_self();

    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        if (g_cpus[i].lapic_id == id) {
            return (int)i;
        }
    }
    return MAX_CPUS;   // tidak dikenal: sentinel (bukan pemilik kunci apa pun)
}

void smp_ipi_rx(void)
{
    int ci = cpu_index();

    if (ci < MAX_CPUS) {
        __atomic_fetch_add(&g_cpus[ci].ipi_rx, 1, __ATOMIC_SEQ_CST);
    }
}

// SMP-2: cpu_t CPU ini. Indeks tak dikenal (ID LAPIC/TSC_AUX di luar tabel) = panic, JANGAN jatuh ke CPU 0
// (akan merusak pembukuan CPU 0). Dipakai jalur scheduler/BKL, bukan jalur cetak panic.
cpu_t *this_cpu(void)
{
    int ci = cpu_index();

    if (ci >= MAX_CPUS) {
        panic_msg("indeks CPU tidak dikenal (ID LAPIC/TSC_AUX di luar tabel CPU)");
    }
    return &g_cpus[ci];
}

// BSP menunggu BKL lebih lama dari batas: pemegangnya macet (mis. AP). Panic menghentikan CPU lain lewat NMI,
// dan karena pemegang BKL bukan CPU ini, flush disk/NIC dilewati (panic_begin).
void bkl_wait_panic(int owner)
{
    panic_begin();
    kprintf("\r\nPANIC: BKL tidak dilepas CPU %d selama > 5 detik (BSP menunggu dengan IF=0)\r\n", owner);
    panic_finish(0, (uint64_t)(uintptr_t)__builtin_frame_address(0));
}

void smp_stop_self(void)
{
    int ci = cpu_index();

    if (ci < MAX_CPUS) {
        smp_halt_mark(&g_cpus[ci].halted, &g_smp_halted);   // sekali per CPU (panic kalah + NMI tidak ganda)
    }
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static volatile int g_stop_sent;
static uint32_t g_stop_others;
#define STOP_WAIT_TSC 400000000ULL   // batas tunggu CPU lain berhenti (siklus TSC), bukan putaran pause

// Panic: sekali saja (guard rekursi). SMP-2: NMI (bukan IPI fixed) supaya CPU yang sedang IF=0 (mis. menunggu
// BKL atau di dalam ISR) pun berhenti; handler NMI (trap.c) memeriksa g_panic_cpu lalu smp_stop_self().
// Dikirim ke CPU online satu per satu (AP yang masih di stub parkir belum punya IDT kita). Menunggu dibatasi
// waktu TSC, tanpa tick (timer BSP mungkin tak berjalan di panic). IPI berhenti TIDAK dihitung di ipi_tx.
void smp_panic_stop_others(void)
{
    if (__atomic_exchange_n(&g_stop_sent, 1, __ATOMIC_SEQ_CST)) {
        return;
    }
    if (g_smp_online <= 1) {
        return;
    }
    int me = cpu_index();
    uint32_t others = 0;

    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        if ((int)i != me && g_cpus[i].online) {
            others++;
        }
    }
    g_stop_others = others;
    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        if ((int)i != me && g_cpus[i].online) {
            lapic_send_nmi(g_cpus[i].lapic_id);
        }
    }
    uint64_t t0 = tsc_read();

    while (g_smp_halted < others && tsc_read() - t0 < STOP_WAIT_TSC) {
        __builtin_ia32_pause();
    }
}

// Dipanggil sesudah serial_lock_reset (panic_begin): bukti CPU lain berhenti.
void smp_panic_report(void)
{
    if (g_stop_others > 0) {
        kprintf("SMP: CPU lain dihentikan %u/%u\r\n", (unsigned)g_smp_halted, (unsigned)g_stop_others);
    }
}

// 0 = berhasil; gagal -> semua frame yang sudah diambil dikembalikan (tanpa bocor).
static int smp_map_stacks(cpu_t *c, uint32_t i)
{
    uint64_t base = AP_STACK_BASE + (uint64_t)i * AP_STACK_STRIDE;
    uint64_t flags = VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NX;
    uint64_t pages = AP_STACK_SIZE / PMM_PAGE_SIZE;
    uint64_t frames[8];
    uint64_t n = 0;

    for (; n < 2 * pages; n++) {
        frames[n] = pmm_alloc();
        if (frames[n] == 0) {
            break;
        }
    }
    if (n < 2 * pages) {
        for (uint64_t k = 0; k < n; k++) {
            pmm_free(frames[k]);
        }
        return -1;
    }
    for (uint64_t k = 0; k < pages; k++) {
        vmm_map(g_kernel_pml4_phys, base + PMM_PAGE_SIZE + k * PMM_PAGE_SIZE, frames[k], flags);
        vmm_map(g_kernel_pml4_phys, base + 2 * PMM_PAGE_SIZE + AP_STACK_SIZE + k * PMM_PAGE_SIZE,
                frames[pages + k], flags);
    }
    c->stack_top = base + PMM_PAGE_SIZE + AP_STACK_SIZE;
    c->df_top = base + 2 * PMM_PAGE_SIZE + 2 * AP_STACK_SIZE;
    return 0;
}

// Berjalan di stack AP sendiri (dipanggil dari smp_ap_entry).
void smp_ap_main(cpu_t *c)
{
    uint64_t cr0, cr4, cr3;
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;

    // SMP-2: TSC_AUX = indeks CPU, PALING AWAL (sebelum kode apa pun yang memanggil cpu_index()).
    if (g_tscaux_ok) {
        tscaux_write(c->index);
    }
    gdt_load_ap(c->gdt);   // GDT + TSS sendiri (ltr)
    idtr.limit = sizeof(bmahOS_idt) - 1;
    idtr.base = (uint64_t)&bmahOS_idt[0];
    __asm__ volatile("lidt %0" : : "m"(idtr));

    // CR0/CR4 per CPU: WP, SMEP, SMAP sama seperti BSP.
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 1ULL << 16;
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    if (g_smep_on) {
        cr4 |= 1ULL << 20;
    }
    if (g_smap_on) {
        cr4 |= 1ULL << 21;
    }
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");

    // Buang TLB (tidak menyimpan terjemahan HHDM lama dari fase parkir Limine).
    __asm__ volatile("mov %%cr3, %0; mov %0, %%cr3" : "=r"(cr3) : : "memory");

    lapic_enable_this_cpu();

    kprintf("SMP: AP %u aktif (lapic=%u)\r\n", c->index, c->lapic_id);
    __atomic_store_n(&c->online, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&g_smp_online, 1, __ATOMIC_SEQ_CST);

    // SMP-2: tunggu BSP menyerahkan scheduler (idle task AP sudah dibuat, kmain). Sampai itu hanya
    // IPI tanpa BKL yang dilayani (IPI uji, TLB shootdown, STOP/NMI). IF=0 saat memeriksa tanda,
    // lalu "sti; hlt" (sti menunda interrupt sampai hlt: tidak ada kehilangan bangun).
    for (;;) {
        __asm__ volatile("cli" ::: "memory");
        if (__atomic_load_n(&c->sched_go, __ATOMIC_ACQUIRE) && c->idle != (size_t)-1) {
            break;
        }
        __asm__ volatile("sti; hlt" ::: "memory");
    }
    smp_ap_idle_start(c);   // tidak kembali
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

// SMP-2: AP masuk scheduler: ambil BKL, jadikan idle task CPU ini sebagai task berjalan, nyalakan timer
// LAPIC periodik, lalu context_switch ke idle (stack boot AP ditinggalkan). Dipanggil IF=0.
void smp_ap_idle_start(cpu_t *c)
{
    uint64_t dummy_rsp;   // RSP lama dibuang: konteks ini tidak pernah dilanjutkan
    size_t id;

    bkl_lock();
    id = c->idle;
    c->current = id;
    tasks[id].running_on = (int)c->index;
    c->cr3 = tasks[id].pml4_phys;
    c->tss.rsp0 = tasks[id].rsp0;
    __atomic_store_n(&c->sched_on, 1, __ATOMIC_RELEASE);
    kprintf("SMP: AP %u masuk scheduler (idle slot %lu, tick lokal %u hitungan)\r\n", c->index,
            (uint64_t)id, g_lapic_per_tick);
    smp_ltimer_start();
    context_switch(&dummy_rsp, tasks[id].rsp, tasks[id].pml4_phys);
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

// Dilompati dari smp_park_stub setelah go: stack Limine, tabel halaman Limine, interrupt mati.
void smp_ap_entry(struct limine_mp_info *info)
{
    cpu_t *c = (cpu_t *)(uintptr_t)info->extra_argument;
    uint64_t cr3 = g_kernel_pml4_phys;
    uint64_t top = c->stack_top;

    if (g_vmm_nx_ok) {   // NXE lebih dulu: tabel kernel memakai bit NX
        uint32_t lo, hi;
        __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
        lo |= 1u << 11;
        __asm__ volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(0xC0000080u));
    }
    __asm__ volatile("mov %0, %%cr3" : : "r"(cr3) : "memory");
    __asm__ volatile("movq %0, %%rsp\n\t"
                     "xorl %%ebp, %%ebp\n\t"
                     "movq %1, %%rdi\n\t"
                     "call smp_ap_main\n\t"
                     "1: cli; hlt; jmp 1b"
                     : : "r"(top), "r"(c) : "memory");
    for (;;) {
    }
}

static int smp_wait_online(uint32_t want)
{
    uint64_t t0 = timer_ticks;

    for (uint64_t i = 0; i < AP_WAIT_SPIN && g_smp_online < want; i++) {
        if (timer_ticks - t0 >= AP_WAIT_TICKS) {
            break;
        }
        __builtin_ia32_pause();
    }
    return g_smp_online >= want;
}

static void smp_ipi_selftest(void)
{
    uint32_t aps = 0, acked = 0;

    for (uint32_t i = 1; i < g_smp_ncpu; i++) {
        cpu_t *c = &g_cpus[i];

        if (!c->online) {
            continue;
        }
        aps++;
        uint64_t before = c->ipi_rx;
        uint64_t t0 = timer_ticks;

        if (lapic_send_ipi(c->lapic_id, SMP_VEC_IPI_TEST) != 0) {
            continue;   // gagal kirim: tidak dihitung ipi_tx
        }
        g_cpus[0].ipi_tx++;
        for (uint64_t k = 0; k < AP_WAIT_SPIN && c->ipi_rx == before; k++) {
            if (timer_ticks - t0 >= AP_WAIT_TICKS) {
                break;
            }
            __builtin_ia32_pause();
        }
        if (c->ipi_rx > before) {
            acked++;
        }
    }
    if (aps == 0) {
        kprintf("SMP: uji IPI dilewati (tanpa AP aktif)\r\n");
    } else if (acked == aps) {
        kprintf("SMP: uji IPI PASS (%u AP)\r\n", aps);
    } else {
        kprintf("SMP: uji IPI FAIL (%u dari %u AP menjawab)\r\n", acked, aps);
    }
}

// ---- SMP-2: timer LAPIC lokal (AP) ----
// Kalibrasi terhadap PIT di BSP (timer_ticks naik 100 Hz dari IRQ0): hitung berapa hitungan timer LAPIC
// (pembagi 16) selama CAL_TICKS tick PIT. Dibatasi waktu (tick DAN putaran); gagal -> AP tidak menjalankan task.
#define LAPIC_CAL_TICKS   10          // 100 ms
#define LAPIC_CAL_TSC     4000000000ULL   // batas total tunggu (siklus TSC, ~1-4 detik)

static uint32_t lapic_calibrate(void)
{
    uint64_t t0 = timer_ticks;
    uint64_t tsc0 = tsc_read();

    // Selaraskan ke batas tick PIT (hitungan mulai tepat di awal tick).
    while (timer_ticks == t0 && tsc_read() - tsc0 < LAPIC_CAL_TSC) {
        __builtin_ia32_pause();
    }
    if (timer_ticks == t0) {
        return 0;   // PIT tidak berjalan
    }
    uint64_t start = timer_ticks;
    uint64_t tsc_start = tsc_read();

    lapic_timer_start(0xFFFFFFFFu, 0, 1, SMP_VEC_LTIMER);   // satu kali, tanpa interrupt
    while (timer_ticks - start < LAPIC_CAL_TICKS && tsc_read() - tsc_start < LAPIC_CAL_TSC) {
        __builtin_ia32_pause();
    }
    uint64_t ticks = timer_ticks - start;
    uint64_t tsc_end = tsc_read();
    uint32_t cur = lapic_timer_count();

    lapic_timer_stop();
    if (ticks < LAPIC_CAL_TICKS || cur == 0xFFFFFFFFu || cur == 0) {
        return 0;
    }
    uint64_t per = (uint64_t)(0xFFFFFFFFu - cur) / ticks;

    if (per < 1000 || per > 0x3FFFFFFFULL) {
        return 0;   // tidak masuk akal
    }
    // Siklus TSC per tick -> batas tunggu BKL BSP = 5 detik (500 tick).
    g_bsp_bkl_wait_tsc = (tsc_end - tsc_start) / ticks * 500;
    return (uint32_t)per;
}

void smp_ltimer_start(void)
{
    lapic_timer_start(g_lapic_per_tick, 1, 0, SMP_VEC_LTIMER);
}

// ---- SMP-2: IPI resched (CPU idle) ----
void smp_resched_rx(void)
{
    cpu_t *c = this_cpu();

    c->resched_rx++;
    __atomic_store_n(&c->kick, 0, __ATOMIC_SEQ_CST);
}

// Dipanggil di bawah BKL setiap ada task yang jadi READY. user=1 (task user): semua CPU lain yang idle
// (termasuk BSP). user=0 (task kernel): hanya BSP, karena task kernel tidak jalan di AP (afinitas). Satu IPI
// tertunda per CPU (kick), jadi tanpa banjir.
void smp_kick_idle(int user)
{
    if (g_smp_online <= 1) {
        return;
    }
    int me = cpu_index();

    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        cpu_t *c = &g_cpus[i];

        if ((int)i == me || (!user && i != 0) || !__atomic_load_n(&c->sched_on, __ATOMIC_ACQUIRE) ||
            c->current != c->idle) {
            continue;
        }
        if (__atomic_exchange_n(&c->kick, 1, __ATOMIC_SEQ_CST)) {
            continue;
        }
        if (lapic_send_ipi(c->lapic_id, SMP_VEC_RESCHED) == 0) {
            g_resched_tx++;
        } else {
            __atomic_store_n(&c->kick, 0, __ATOMIC_SEQ_CST);
        }
    }
}

// kmain: setelah scheduler BSP hidup dan idle task AP dibuat: beri tanda go ke tiap AP yang punya idle task.
void smp_sched_release(void)
{
    for (uint32_t i = 1; i < g_smp_ncpu; i++) {
        cpu_t *c = &g_cpus[i];

        if (c->online && c->idle != (size_t)-1) {
            __atomic_store_n(&c->sched_go, 1, __ATOMIC_RELEASE);
            lapic_send_ipi(c->lapic_id, SMP_VEC_RESCHED);   // bangunkan dari hlt (diabaikan sebelum sched_on)
        }
    }
}

// ---- SMP-2: TLB shootdown ----
// Satu permintaan pada satu waktu (pemanggil memegang BKL; busy hanya pengaman). CPU tujuan menjawab dari
// handler IPI (tanpa BKL) atau dari putaran tunggu BKL (bkl_core_lock memanggil tlb_service). Tidak menjawab
// dalam TLB_WAIT_TSC -> dicatat (g_tlb_late: flush penuh begitu CPU itu mengambil BKL / menerima layanan).
#define TLB_WAIT_TSC   400000000ULL
#define TLB_RANGE_MAX  32          // lebih dari ini: muat ulang CR3 (flush penuh)

static tlbreq_t g_tlb;
static volatile uint32_t g_tlb_late;
static uint64_t g_tlb_count;
static uint64_t g_tlb_timeouts;

static inline void tlb_flush_all_local(void)
{
    uint64_t cr3;

    __asm__ volatile("mov %%cr3, %0; mov %0, %%cr3" : "=r"(cr3) : : "memory");
}

void tlb_service(void)
{
    if (g_smp_online <= 1) {
        return;
    }
    int ci = cpu_index();

    if (ci >= MAX_CPUS) {
        return;
    }
    uint32_t bit = 1u << ci;
    uint64_t va, seq;
    uint32_t n;

    if (__atomic_load_n(&g_tlb_late, __ATOMIC_ACQUIRE) & bit) {
        __atomic_fetch_and(&g_tlb_late, ~bit, __ATOMIC_SEQ_CST);
        tlb_flush_all_local();
    }
    if (!tlbreq_take(&g_tlb, ci, &va, &n, &seq)) {
        return;
    }
    if (n > TLB_RANGE_MAX) {
        tlb_flush_all_local();
    } else {
        for (uint32_t k = 0; k < n; k++) {
            uint64_t a = va + (uint64_t)k * PMM_PAGE_SIZE;

            __asm__ volatile("invlpg (%0)" : : "r"(a) : "memory");
        }
    }
    tlbreq_ack(&g_tlb, ci, seq);   // ack membawa nomor urut permintaan yang benar-benar di-flush
}

void tlb_ipi_rx(void)
{
    tlb_service();
}

// Dipanggil vmm_unmap SESUDAH PTE dikosongkan dan invlpg lokal, SEBELUM frame dibebaskan pemanggil.
// Alamat kernel (half atas) ada di semua CPU; alamat user hanya CPU yang sedang memuat PML4 itu.
// IF dimatikan di seluruh fungsi: kalau dipreempt (timer ISR -> schedule) sambil menunggu, task lain bisa
// masuk tlb_shootdown dan berputar di g_tlb.busy dengan BKL + IF=0. Return 1 = semua CPU tujuan sudah
// membatalkan TLB; 0 = ada yang belum menjawab dalam batas waktu (pemanggil JANGAN membebaskan frame).
int tlb_shootdown(uint64_t pml4_phys, uint64_t vaddr, uint32_t npages)
{
    if (g_smp_online <= 1 || !g_lapic_ready || g_smp_ncpu <= 1) {
        return 1;
    }
    uint64_t fl = irq_save();
    int me = cpu_index();
    int kern = vaddr >= 0xFFFF800000000000ULL;
    uint32_t mask = 0;
    int ok = 1;

    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        cpu_t *c = &g_cpus[i];

        if ((int)i == me || !c->online) {
            continue;
        }
        if (kern || (c->sched_on && c->cr3 == pml4_phys)) {
            mask |= 1u << i;
        }
    }
    if (mask == 0) {
        irq_restore(fl);
        return 1;
    }
    // busy hanya pengaman (pemanggil memegang BKL, jadi tak ada pesaing). Batas TSC: tidak berputar selamanya.
    uint64_t tb = tsc_read();

    while (__atomic_exchange_n(&g_tlb.busy, 1, __ATOMIC_ACQUIRE)) {
        tlb_service();
        if (tsc_read() - tb > TLB_WAIT_TSC) {
            g_tlb_timeouts++;
            kprintf("SMP: TLB shootdown: busy macet, diambil alih\r\n");
            break;
        }
        __builtin_ia32_pause();
    }
    uint64_t seq = tlbreq_begin(&g_tlb, vaddr & ~(PMM_PAGE_SIZE - 1), npages, mask);

    for (uint32_t i = 0; i < g_smp_ncpu; i++) {
        if (mask & (1u << i)) {
            lapic_send_ipi(g_cpus[i].lapic_id, SMP_VEC_TLB);
        }
    }
    uint64_t t0 = tsc_read();
    uint32_t missing = tlbreq_missing(&g_tlb, mask, seq);

    while (missing && tsc_read() - t0 < TLB_WAIT_TSC) {
        tlb_service();
        __builtin_ia32_pause();
        missing = tlbreq_missing(&g_tlb, mask, seq);
    }
    tlbreq_end(&g_tlb);
    if (missing) {
        __atomic_fetch_or(&g_tlb_late, missing, __ATOMIC_SEQ_CST);
        if (g_tlb_timeouts++ == 0) {
            kprintf("SMP: TLB shootdown: CPU mask 0x%x tidak menjawab dalam batas waktu\r\n", missing);
        }
        ok = 0;
    }
    g_tlb_count++;
    __atomic_store_n(&g_tlb.busy, 0, __ATOMIC_RELEASE);
    irq_restore(fl);
    return ok;
}

// SMP-2: uji protokol shootdown saat boot: petakan satu halaman kernel, sentuh, lepas (vmm_unmap -> shootdown ke
// semua AP online, tunggu ack), bebaskan frame. Lulus bila hitungan shootdown naik dan tidak ada CPU yang terlambat.
// Membuktikan alur IPI + ack; staleness TLB nyata di AP tidak teramati langsung (catatan risiko).
static void smp_tlb_selftest(void)
{
    if (g_smp_online <= 1) {
        return;
    }
    uint64_t va = 0xFFFF900000010000ULL;
    uint64_t fr = pmm_alloc();

    if (fr == 0) {
        kprintf("SMP: uji TLB shootdown dilewati (pmm habis)\r\n");
        return;
    }
    uint64_t before = g_tlb_count;
    uint64_t late = g_tlb_timeouts;

    vmm_map(g_kernel_pml4_phys, va, fr, VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NX);
    *(volatile uint64_t *)va = 0x5A5A5A5AULL;
    if (vmm_unmap(g_kernel_pml4_phys, va)) {
        pmm_free(fr);
    }
    if (g_tlb_count == before + 1 && g_tlb_timeouts == late) {
        kprintf("SMP: uji TLB shootdown PASS (%u AP)\r\n", g_smp_online - 1);
    } else {
        kprintf("SMP: uji TLB shootdown FAIL (hitungan %lu -> %lu, terlambat %lu)\r\n", before, g_tlb_count,
                g_tlb_timeouts - late);
    }
}

// kmain: sesudah LAPIC + IDT + sti. AP sudah parkir di stub (smp_park_aps); di sini hanya
// mengisi stack/GDT/TSS lalu memberi sinyal go.
void smp_init(void)
{
    uint32_t total = g_total;
    uint32_t bsp = g_lapic_ready ? lapic_id_self() : g_cpus[0].lapic_id;
    uint32_t mapped = 1;   // CPU yang diberi stack (BSP termasuk)

    g_cpus[0].lapic_id = bsp;
    g_cpus[0].idle = (size_t)-1;
    for (uint32_t i = 1; i < MAX_CPUS; i++) {
        g_cpus[i].idle = (size_t)-1;
    }
    // SMP-2: cpu_index() lewat TSC_AUX bila ada RDTSCP; BSP = 0. Diisi SEBELUM g_smp_ncpu > 1 (sebelum itu
    // cpu_index() selalu 0).
    if (total > 1 && g_lapic_ready && cpu_has_rdtscp()) {
        tscaux_write(0);
        g_tscaux_ok = 1;
    }
    g_smp_ncpu = total;
    g_smp_online = 1;

    if (g_ignored) {
        kprintf("SMP: %u CPU melebihi MAX_CPUS=%d, diabaikan (parkir di stub kernel)\r\n",
                g_ignored, MAX_CPUS);
    }
    // MADT vs Limine: beda hanya dicatat.
    if (mp_request.response != NULL && g_acpi_cpus != g_limine_count) {
        kprintf("SMP: jumlah CPU beda: MADT=%u Limine=%lu\r\n", g_acpi_cpus, g_limine_count);
    }

    // Vektor IPI (IDT dipakai bersama semua CPU; spurious 0xFF dipasang idt_init).
    extern void irq240(void);
    extern void irq241(void);
    extern void irq239(void);
    extern void irq242(void);
    extern void irq243(void);
    idt_set_entry(SMP_VEC_IPI_TEST, (uint64_t)irq240, 0x08, 0x8E);
    idt_set_entry(SMP_VEC_STOP, (uint64_t)irq241, 0x08, 0x8E);
    idt_set_entry(SMP_VEC_LTIMER, (uint64_t)irq239, 0x08, 0x8E);   // SMP-2
    idt_set_entry(SMP_VEC_RESCHED, (uint64_t)irq242, 0x08, 0x8E);
    idt_set_entry(SMP_VEC_TLB, (uint64_t)irq243, 0x08, 0x8E);

    if (total > 1 && !g_lapic_ready) {
        kprintf("SMP: LAPIC tidak aktif, AP tidak dijalankan\r\n");
    } else if (total > 1) {
        for (uint32_t i = 1; i < total; i++) {
            if (smp_map_stacks(&g_cpus[i], i) != 0) {
                kprintf("SMP: pmm habis untuk stack AP %u, AP %u dst. tidak dijalankan (memori)\r\n",
                        i, i);
                break;
            }
            gdt_build_ap(g_cpus[i].gdt, &g_cpus[i].tss, g_cpus[i].stack_top, g_cpus[i].df_top);
            mapped++;
        }
        for (uint32_t i = 1; i < mapped; i++) {
            __atomic_store_n(&g_cpus[i].go, 1, __ATOMIC_SEQ_CST);
        }
        smp_wait_online(mapped);
    }
    kprintf("SMP: %u/%u CPU aktif (BSP lapic=%u)\r\n", g_smp_online, total, bsp);
    if (total > 1) {
        kprintf("SMP: cpu_index lewat %s\r\n", g_tscaux_ok ? "TSC_AUX (rdtscp)" : "ID LAPIC (tanpa rdtscp)");
    }
    if (g_smp_online > 1) {
        g_lapic_per_tick = lapic_calibrate();
        if (g_lapic_per_tick != 0) {
            g_smp_sched_ok = 1;
            kprintf("SMP: timer LAPIC terkalibrasi %u hitungan per tick (pembagi 16, 100 Hz); AP menjalankan task\r\n",
                    g_lapic_per_tick);
        } else {
            kprintf("SMP: kalibrasi timer LAPIC gagal; AP tidak menjalankan task (tetap idle)\r\n");
        }
    }
    if (mapped < total) {
        kprintf("SMP: %u CPU tidak dijalankan (memori)\r\n", total - mapped);
    }
    if (g_smp_online < mapped) {
        kprintf("SMP: %u CPU tidak menjawab dalam batas waktu\r\n", mapped - g_smp_online);
    }
    smp_ipi_selftest();
    smp_tlb_selftest();
}

uint64_t smp_metric_cpus(void)
{
    return g_smp_ncpu ? g_smp_ncpu : 1;
}

uint64_t smp_metric_online(void)
{
    return g_smp_online ? g_smp_online : 1;
}

uint64_t smp_metric_ipi_tx(void)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < MAX_CPUS; i++) {
        n += g_cpus[i].ipi_tx;
    }
    return n;
}

uint64_t smp_metric_stray(void)
{
    return g_smp_stray;
}

uint64_t smp_metric_switch_ap(void)
{
    uint64_t n = 0;

    for (uint32_t i = 1; i < MAX_CPUS; i++) {
        n += g_cpus[i].switches;
    }
    return n;
}

uint64_t smp_metric_tlb(void)
{
    return g_tlb_count;
}

uint64_t smp_metric_resched(void)
{
    return g_resched_tx;
}

uint64_t smp_metric_bkl_spin(void)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < MAX_CPUS; i++) {
        n += g_cpus[i].bkl_spin;
    }
    return n;
}

uint64_t smp_metric_ipi_rx(void)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < MAX_CPUS; i++) {
        n += g_cpus[i].ipi_rx;
    }
    return n;
}

// Perintah `cpu` (hanya baca): satu baris ringkasan + satu baris per CPU (SMP-2: task yang berjalan,
// jumlah context switch, tick lokal).
void smp_list(void (*out)(const char *))
{
    char line[192];
    uint32_t n = g_smp_ncpu ? g_smp_ncpu : 1;

    ksnprintf(line, sizeof(line), "cpu: tercatat=%u aktif=%u maks=%d stray=%lu sched_ap=%d tlb=%lu resched=%lu bkl_spin=%lu\n", n,
              (unsigned)smp_metric_online(), MAX_CPUS, (uint64_t)g_smp_stray, g_smp_sched_ok,
              g_tlb_count, g_resched_tx, smp_metric_bkl_spin());
    out(line);
    for (uint32_t i = 0; i < n; i++) {
        char task[16];

        if (g_cpus[i].sched_on) {
            ksnprintf(task, sizeof(task), "%lu", (uint64_t)g_cpus[i].current);
        } else {
            ksnprintf(task, sizeof(task), "-");
        }
        ksnprintf(line, sizeof(line), "cpu %u: lapic=%u online=%u ipi_rx=%lu task=%s switch=%lu tick=%lu%s\n", i,
                  g_cpus[i].lapic_id, i == 0 ? 1u : (unsigned)g_cpus[i].online,
                  (uint64_t)g_cpus[i].ipi_rx, task, g_cpus[i].switches, g_cpus[i].ltick,
                  i == 0 ? " (BSP)" : "");
        out(line);
    }
}

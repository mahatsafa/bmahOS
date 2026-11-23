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

int cpu_index(void)
{
    if (!g_lapic_ready || g_smp_ncpu <= 1) {
        return 0;
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

void smp_stop_self(void)
{
    __atomic_fetch_add(&g_smp_halted, 1, __ATOMIC_SEQ_CST);
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static volatile int g_stop_sent;
static uint32_t g_stop_others;

// Panic: sekali saja (guard rekursi). IPI fixed hanya sampai ke CPU dengan IF=1; CPU yang
// sedang IF=0 tidak berhenti (batas SMP-1, dicatat). Menunggu dibatasi putaran, tanpa tick.
// IPI berhenti TIDAK dihitung di ipi_tx (hanya IPI uji).
void smp_panic_stop_others(void)
{
    if (__atomic_exchange_n(&g_stop_sent, 1, __ATOMIC_SEQ_CST)) {
        return;
    }
    if (g_smp_online <= 1) {
        return;
    }
    uint32_t others = g_smp_online - 1;

    g_stop_others = others;
    lapic_send_ipi_others(SMP_VEC_STOP);
    for (uint64_t i = 0; i < 2000000ULL && g_smp_halted < others; i++) {
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

    for (;;) {
        __asm__ volatile("sti; hlt");
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

// kmain: sesudah LAPIC + IDT + sti. AP sudah parkir di stub (smp_park_aps); di sini hanya
// mengisi stack/GDT/TSS lalu memberi sinyal go.
void smp_init(void)
{
    uint32_t total = g_total;
    uint32_t bsp = g_lapic_ready ? lapic_id_self() : g_cpus[0].lapic_id;
    uint32_t mapped = 1;   // CPU yang diberi stack (BSP termasuk)

    g_cpus[0].lapic_id = bsp;
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
    idt_set_entry(SMP_VEC_IPI_TEST, (uint64_t)irq240, 0x08, 0x8E);
    idt_set_entry(SMP_VEC_STOP, (uint64_t)irq241, 0x08, 0x8E);

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
    if (mapped < total) {
        kprintf("SMP: %u CPU tidak dijalankan (memori)\r\n", total - mapped);
    }
    if (g_smp_online < mapped) {
        kprintf("SMP: %u CPU tidak menjawab dalam batas waktu\r\n", mapped - g_smp_online);
    }
    smp_ipi_selftest();
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

uint64_t smp_metric_ipi_rx(void)
{
    uint64_t n = 0;

    for (uint32_t i = 0; i < MAX_CPUS; i++) {
        n += g_cpus[i].ipi_rx;
    }
    return n;
}

// Perintah `cpu` (hanya baca): satu baris ringkasan + satu baris per CPU.
void smp_list(void (*out)(const char *))
{
    char line[96];
    uint32_t n = g_smp_ncpu ? g_smp_ncpu : 1;

    ksnprintf(line, sizeof(line), "cpu: tercatat=%u aktif=%u maks=%d stray=%lu\n", n,
              (unsigned)smp_metric_online(), MAX_CPUS, (uint64_t)g_smp_stray);
    out(line);
    for (uint32_t i = 0; i < n; i++) {
        ksnprintf(line, sizeof(line), "cpu %u: lapic=%u online=%u ipi_rx=%lu%s\n", i,
                  g_cpus[i].lapic_id, i == 0 ? 1u : (unsigned)g_cpus[i].online,
                  (uint64_t)g_cpus[i].ipi_rx, i == 0 ? " (BSP)" : "");
        out(line);
    }
}

#include "kernel.h"

// R1: panic handler. Semua exception CPU (kecuali int 0x80) dan ASSERT berakhir
// di sini: nama exception, register, stack trace lewat rantai rbp (kernel
// dikompilasi -O0 + -fno-omit-frame-pointer, BearSSL juga), lalu reboot
// otomatis setelah PANIC_REBOOT_S detik lewat machine_reboot() (acpi.c).
// Interrupt mati selama panic: waktu tunggu dihitung dengan polling counter
// PIT channel 0 (diprogram ulang 100 Hz, satu putaran = 10 ms), tanpa TSC.
// Panic di dalam panic: satu baris lalu langsung reboot, tanpa trace.
// #DF memakai stack IST1 (g_df_stack, cpu.c) sehingga stack rusak tetap
// menghasilkan dump, bukan triple fault.

#define PANIC_TRACE_MAX 16
#define PANIC_FRAME_MAX 65536                    // jarak maks antar frame (byte)
#define PANIC_STACK_MIN 0xffff800000000000ULL    // rbp harus di half atas

extern char __text_start[];
extern char __text_end[];

static volatile int g_panic_depth = 0;

static const char *const g_exc_names[32] = {
    "#DE pembagian nol", "#DB debug", "NMI", "#BP breakpoint",
    "#OF overflow", "#BR bound range", "#UD opcode tidak sah", "#NM FPU tidak tersedia",
    "#DF double fault", "segmen koprosesor", "#TS TSS tidak sah", "#NP segmen tidak ada",
    "#SS stack segment fault", "#GP general protection fault", "#PF page fault", "vektor cadangan 15",
    "#MF x87", "#AC alignment check", "#MC machine check", "#XM SIMD",
    "#VE virtualisasi", "#CP control protection", "vektor cadangan 22", "vektor cadangan 23",
    "vektor cadangan 24", "vektor cadangan 25", "vektor cadangan 26", "vektor cadangan 27",
    "#HV injeksi hypervisor", "#VC VMM communication", "#SX security", "vektor cadangan 31",
};

const char *panic_exc_name(uint64_t vector)
{
    return vector < 32 ? g_exc_names[vector] : "vektor tidak dikenal";
}

// Kode error #PF: P (0 = halaman tidak ada, 1 = pelanggaran proteksi),
// W (tulis), U (dari ring 3), RSVD (bit cadangan di entri tabel), I (fetch).
void panic_pf_decode(uint64_t err, char *buf, size_t size)
{
    ksnprintf(buf, size, "%s %s %s%s%s",
              (err & 1) ? "proteksi" : "tidak-ada",
              (err & 2) ? "tulis" : "baca",
              (err & 4) ? "user" : "kernel",
              (err & 8) ? " rsvd" : "",
              (err & 16) ? " fetch" : "");
}

// Rantai frame: [rbp] = rbp pemanggil, [rbp+8] = alamat kembali. Setiap rbp
// dicek SEBELUM dibaca: rata 8, >= stack_min, naik ketat dari frame sebelumnya
// dan paling jauh PANIC_FRAME_MAX (stack tumbuh ke bawah). rbp 0 atau alamat
// kembali 0 = ujung rantai normal. Alamat kembali di luar .text -> berhenti.
int panic_walk(uint64_t rbp, const panic_bounds_t *b, uint64_t *out, int max, int *why)
{
    int n = 0;
    uint64_t prev = 0;

    while (n < max) {
        if (rbp == 0) {
            *why = PANIC_WALK_END;
            return n;
        }
        if ((rbp & 7) != 0 || rbp < b->stack_min || rbp > UINT64_MAX - 16 ||
            (prev != 0 && (rbp <= prev || rbp - prev > PANIC_FRAME_MAX))) {
            *why = PANIC_WALK_BADRBP;
            return n;
        }

        const uint64_t *f = (const uint64_t *)(uintptr_t)rbp;
        uint64_t ret = f[1];

        if (ret == 0) {
            *why = PANIC_WALK_END;
            return n;
        }
        if (ret < b->text_lo || ret >= b->text_hi) {
            *why = PANIC_WALK_NOTEXT;
            return n;
        }
        out[n++] = ret;
        prev = rbp;
        rbp = f[0];
    }
    *why = PANIC_WALK_MAX;
    return n;
}

static const char *panic_walk_reason(int why)
{
    switch (why) {
    case PANIC_WALK_END:    return "ujung rantai";
    case PANIC_WALK_BADRBP: return "rbp tidak sah";
    case PANIC_WALK_NOTEXT: return "alamat kembali di luar .text";
    default:                return "batas frame";
    }
}

static uint16_t panic_pit_read(void)
{
    outb(0x43, 0x00);   // latch channel 0
    uint8_t lo = inb(0x40);
    uint8_t hi = inb(0x40);
    return (uint16_t)(lo | (hi << 8));
}

void panic_begin(void)
{
    __asm__ volatile("cli");
    g_serial_mute = 0;   // dump wajib sampai ke UART
    g_panic_depth++;

    if (g_panic_depth == 2) {
        serial_write("\r\nPANIC: fault di dalam panic handler, reboot sekarang\r\n");
        machine_reboot();
    }
    if (g_panic_depth > 2) {
        // Fault di dalam machine_reboot: triple fault langsung.
        struct __attribute__((packed)) {
            uint16_t limit;
            uint64_t base;
        } zero_idt = {0, 0};
        __asm__ volatile("lidt %0; int3" : : "m"(zero_idt));
        for (;;) {
            __asm__ volatile("hlt");
        }
    }

    netcon_panic_flush();   // R2: kosongkan antrean dulu, ruang untuk dump
    logdisk_sync(1);        // R4: begitu juga antrean LOG.BIN
}

// rip != 0: frame #0 (RIP saat exception). rbp: awal rantai frame.
void panic_finish(uint64_t rip, uint64_t rbp)
{
    panic_bounds_t b = {
        (uint64_t)(uintptr_t)__text_start,
        (uint64_t)(uintptr_t)__text_end,
        PANIC_STACK_MIN,
    };
    uint64_t ret[PANIC_TRACE_MAX];
    int why = PANIC_WALK_END;

    // #0 = RIP saat exception (bila ada); #1.. = alamat kembali. Tanpa RIP
    // (ASSERT) #0 adalah kassert_fail sendiri dan tidak dicetak.
    kprintf("PANIC: tick=%lu task=%lu\r\n", (uint64_t)timer_ticks, (uint64_t)current_index);
    if (rip != 0) {
        kprintf("PANIC: trace #0 %p\r\n", (void *)(uintptr_t)rip);
    }
    int n = panic_walk(rbp, &b, ret, PANIC_TRACE_MAX - 1, &why);
    for (int i = 0; i < n; i++) {
        kprintf("PANIC: trace #%d %p\r\n", i + 1, (void *)(uintptr_t)ret[i]);
    }
    kprintf("PANIC: trace %d frame (%s); terjemahkan: tools/symbolize.sh <log>\r\n",
            n + (rip != 0), panic_walk_reason(why));

    pit_init(100);
    kprintf("PANIC: reboot otomatis dalam %d detik\r\n", PANIC_REBOOT_S);
    netcon_panic_flush();   // R2
    logdisk_sync(1);        // R4: dump ke LOG.BIN (tanpa register umum)

    uint32_t periods = 0;
    uint32_t same = 0;
    uint16_t prev = panic_pit_read();

    while (periods < PANIC_REBOOT_S * 100) {
        uint16_t cur = panic_pit_read();
        if (cur > prev) {
            periods++;   // counter mode 2 diisi ulang = satu periode 10 ms
        }
        if (cur == prev) {
            if (++same > 1000000) {
                kprintf("PANIC: PIT tidak berjalan, reboot sekarang\r\n");
                break;
            }
        } else {
            same = 0;
        }
        prev = cur;
    }
    machine_reboot();
}

// R6-3: alokasi wajib gagal (lihat kernel.h). Trace dari pemanggil.
void oom_panic(const char *where)
{
    panic_begin();
    kprintf("\r\nPANIC: memori habis: %s (pmm_alloc=%lu pmm_free=%lu pmm_gagal=%lu)\r\n",
            where, g_pmm_allocs, g_pmm_frees, g_pmm_fail);
    panic_finish(0, (uint64_t)(uintptr_t)__builtin_frame_address(0));
}

void panic_exception(struct exception_context *c)
{
    panic_begin();

    uint64_t cr0, cr2, cr3, cr4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));

    char pf[48] = "";
    if (c->vector == 14) {
        pf[0] = ' ';
        pf[1] = '[';
        panic_pf_decode(c->error_code, pf + 2, sizeof(pf) - 3);
        size_t l = 0;
        while (pf[l] != '\0') {
            l++;
        }
        pf[l] = ']';
        pf[l + 1] = '\0';
    }

    uint64_t at = (uint64_t)(uintptr_t)c;
    uint64_t df_lo = (uint64_t)(uintptr_t)g_df_stack;
    int on_ist = at >= df_lo && at < df_lo + DF_STACK_SIZE;

    kprintf("\r\nPANIC: exception %s (vektor %lu) error=0x%lx%s\r\n",
            panic_exc_name(c->vector), c->vector, c->error_code, pf);
    kprintf("PANIC: RIP=%p CS=0x%lx RFLAGS=0x%lx mode=%s\r\n",
            (void *)(uintptr_t)c->rip, c->cs, c->rflags, (c->cs & 3) ? "user" : "kernel");
    kprintf("PANIC: RSP=%p SS=0x%lx stack=%s\r\n",
            (void *)(uintptr_t)c->rsp, c->ss, on_ist ? "IST1" : "biasa");
    kprintf("PANIC: CR0=0x%lx CR2=%p CR3=0x%lx CR4=0x%lx\r\n",
            cr0, (void *)(uintptr_t)cr2, cr3, cr4);
    // R6-2: #PF/#DF di halaman guard = stack kernel meluap. Pemilik dicari
    // lewat rsp0 (puncak stack) di tabel task.
    uint64_t g_lo, g_top;
    if ((c->vector == 14 || c->vector == 8) && kstack_guard_find(cr2, &g_lo, &g_top)) {
        long slot = -1;
        for (size_t i = 0; i < task_count; i++) {
            if (tasks[i].rsp0 > g_lo && tasks[i].rsp0 <= g_top) {
                slot = (long)i;
            }
        }
        kprintf("PANIC: stack guard dilanggar: task slot %d (guard %p, stack %p..%p)\r\n",
                (int)slot, (void *)(uintptr_t)g_lo, (void *)(uintptr_t)(g_lo + 4096),
                (void *)(uintptr_t)g_top);
    }
    g_netcon_hold = 1;   // R2: register umum (bisa berisi sisa rahasia) hanya ke serial
    kprintf("PANIC: RAX=%p RBX=%p RCX=%p RDX=%p\r\n",
            (void *)c->rax, (void *)c->rbx, (void *)c->rcx, (void *)c->rdx);
    kprintf("PANIC: RSI=%p RDI=%p RBP=%p R8=%p\r\n",
            (void *)c->rsi, (void *)c->rdi, (void *)c->rbp, (void *)c->r8);
    kprintf("PANIC: R9=%p R10=%p R11=%p R12=%p\r\n",
            (void *)c->r9, (void *)c->r10, (void *)c->r11, (void *)c->r12);
    kprintf("PANIC: R13=%p R14=%p R15=%p\r\n",
            (void *)c->r13, (void *)c->r14, (void *)c->r15);
    g_netcon_hold = 0;

    panic_finish(c->rip, c->rbp);
}

#ifndef BMAHOS_PROD
// R1: pemicu uji (build dev saja, perintah admin "panic pf|df|ud|assert").
// Fault dipicu 1 detik kemudian dari ktimer (loop net task) supaya balasan
// perintah sempat terkirim, lewat UDP maupun TCP/TLS.
static ktimer_t g_panic_test_timer;
static int g_panic_test_kind = -1;

static void panic_test_pf(void)
{
    *(volatile uint64_t *)(uintptr_t)0 = 0xBADC0DE;   // halaman 0 tidak dipetakan
}

static void panic_test_df(void)
{
    // RSP non-kanonik -> push memicu #SS; mengirim #SS butuh push ke RSP yang
    // sama -> #DF. Tanpa IST1 ini berakhir triple fault tanpa pesan.
    __asm__ volatile("movabs $0x0000800000000000, %%rax\n\t"
                     "mov %%rax, %%rsp\n\t"
                     "pushq %%rax"
                     : : : "rax", "memory");
}

static void panic_test_ud(void)
{
    __asm__ volatile("ud2");
}

// R6-2: rekursi sampai menabrak halaman guard stack net task.
static void panic_test_stack(uint64_t depth)
{
    volatile uint8_t pad[256];

    pad[0] = (uint8_t)depth;
    if (depth < 1000000) {
        panic_test_stack(depth + 1);
    }
    pad[1] = pad[0];
}

static void panic_test_assert(void)
{
    ASSERT(g_panic_test_kind != 3);
}

static void panic_test_fire(void *arg)
{
    (void)arg;
    switch (g_panic_test_kind) {
    case 0: panic_test_pf(); break;
    case 1: panic_test_df(); break;
    case 2: panic_test_ud(); break;
    case 4: panic_test_stack(0); break;
    default: panic_test_assert(); break;
    }
    kprintf("PANIC-UJI: fault tidak terjadi (jenis %d)\r\n", g_panic_test_kind);
    g_panic_test_kind = -1;
}

int panic_test_execute(const volatile uint8_t *cmd, uint32_t len)
{
    static const char *const kinds[5] = { "pf", "df", "ud", "assert", "stack" };
    static const char *const cmds[5] = { "panic pf", "panic df", "panic ud", "panic assert",
                                         "panic stack" };

    for (int i = 0; i < 5; i++) {
        if (!net_cmd_is(cmd, len, cmds[i])) {
            continue;
        }
        if (g_panic_test_kind >= 0) {
            cmd_puts("ERR: uji panic sudah dijadwalkan\n");
            return 1;
        }
        g_panic_test_kind = i;
        ktimer_start(&g_panic_test_timer, 100, panic_test_fire, 0);
        cmd_puts("panic: uji ");
        cmd_puts(kinds[i]);
        cmd_puts(" dalam 1 detik\n");
        return 1;
    }
    return 0;
}
#endif

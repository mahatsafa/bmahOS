#include "kernel.h"

_Static_assert(
    sizeof(struct exception_context) == 22 * sizeof(uint64_t),
    "exception_context size is wrong"
);

// ===============================================================
// Syscall dispatch table
//
// Konvensi: rax = nomor syscall, rdi/rsi/rdx/r10/r8 = argumen 1..5
// (sama seperti konvensi Linux x86-64 syscall ABI, supaya familiar
// dan gampang dibandingkan referensi). Return value ditaruh balik
// ke context->rax sebelum iretq.
// ===============================================================

// Forward declaration -- definisi lengkap is_valid_user_ptr() ada
// di bawah (dekat vmm_map(), butuh VMM_FLAG_* dan hhdm_offset yang
// didefinisikan di situ), tapi sys_write() di section syscall ini
// perlu memanggilnya lebih dulu secara urutan baris.

#define SYS_TEST  0
#define SYS_WRITE 1
#define SYS_EXIT  2
// P5-1: soket UDP (sock.c, validasi pointer di dalam fungsinya sendiri)
#define SYS_SOCKET   3
#define SYS_BIND     4
#define SYS_SENDTO   5
#define SYS_RECVFROM 6
#define SYS_CLOSE    7
// P5-2: soket TCP server
#define SYS_LISTEN   8
#define SYS_ACCEPT   9
#define SYS_SEND     10
#define SYS_RECV     11
#define SYS_CONNECT  12   // P5-3: klien TCP
#ifndef BMAHOS_PROD
#define SYS_CPU      13   // SMP-2 (dev): indeks CPU yang menjalankan syscall (bukti task user jalan di AP)
#define SYSCALL_COUNT 14
#else
#define SYSCALL_COUNT 13
#endif

static uint64_t sys_test(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    (void)arg3; (void)arg4;
    serial_write("sys_test dipanggil, arg0=");
    serial_write_hex(arg0);
    serial_write(" arg1=");
    serial_write_hex(arg1);
    serial_write(" arg2=");
    serial_write_hex(arg2);
    serial_write("\r\n");
    return 0xAAAA;
}

// Validasi pointer/len TIDAK LAGI dilakukan di sini -- dipindah ke
// syscall_handler() lewat metadata has_user_ptr (lihat syscall_desc_t).
// Saat fungsi ini dipanggil, buf_ptr/len SUDAH dipastikan valid untuk
// diakses ring 3 oleh dispatcher, sebelum dispatch terjadi.
static uint64_t sys_write(uint64_t buf_ptr, uint64_t len, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    (void)arg2; (void)arg3; (void)arg4;

    // F7: salin per blok ke buffer kernel di dalam jendela stac/clac, lalu cetak di luar
    // jendela (serial_putc tidak ikut berjalan dengan AC=1).
    const char *buf = (const char *)buf_ptr;
    char blk[128];
    uint64_t done = 0;

    while (done < len) {
        uint64_t n = len - done > sizeof(blk) ? sizeof(blk) : len - done;

        user_access_begin();
        for (uint64_t i = 0; i < n; i++) {
            blk[i] = buf[done + i];
        }
        user_access_end();
        for (uint64_t i = 0; i < n; i++) {
            serial_putc(blk[i]);
        }
        done += n;
    }

    return len;
}

// Task minta mengakhiri dirinya sendiri secara permanen dari ring 3.
// Delegasi murni ke task_exit() (Layer 5) -- TIDAK ADA mekanisme exit
// kedua. task_exit() dipanggil dari sini di dalam INTERRUPT context
// (int 0x80 gate sudah cli otomatis), tapi ini AMAN: context_switch()
// yang dipanggil task_exit()->schedule() cuma menukar rsp lalu ret --
// stack lama (termasuk frame isr128->syscall_handler->sys_exit di
// dalamnya) ditinggalkan total begitu context switch terjadi, tidak
// pernah "kembali" lagi. Beda dengan task_sleep()/task_wait_for()
// yang MEMANG akan resume tepat di titik pemanggilan.
static uint64_t sys_exit(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4;

    task_exit();

    // Tidak pernah sampai sini kalau context_switch() berhasil pergi
    // ke task lain. Kalau task ini satu-satunya yang hidup,
    // task_exit() sudah hlt selamanya duluan sebelum baris ini.
    return 0;
}

// P5-1a: 5 argumen (rdi, rsi, rdx, r10, r8), sama seperti urutan Linux.
typedef uint64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

// Metadata per-syscall -- Layer 8 checkpoint: centralize syscall
// pointer validation. has_user_ptr berarti spesifik: arg0 (rdi)
// adalah user pointer, arg1 (rsi) adalah len, KEDUANYA divalidasi
// oleh syscall_handler() SEBELUM dispatch ke fn. Ini BUKAN framework
// validasi pointer generik -- baru mendukung SATU pola (ptr di arg0,
// len di arg1) karena baru SYS_WRITE yang butuh. Kalau nanti ada
// syscall dengan pola beda (pointer bukan di arg0, atau lebih dari
// satu pointer), field ini perlu digeneralisasi -- BUKAN dipaksakan
// sekarang.
typedef struct {
    syscall_fn_t fn;
    bool has_user_ptr;  // arg0=user_ptr, arg1=len; validate before dispatch
} syscall_desc_t;

#ifndef BMAHOS_PROD
// SMP-2 (dev): rdtscp (TSC_AUX = indeks CPU, tak bisa diubah ring 3) lewat cpu_index(). Tunduk pada jatah
// syscall per jendela seperti syscall lain.
static uint64_t sys_cpu(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4;
    if (g_panic_ap_arm && cpu_index() != 0) {
        panic_msg("uji panic dari AP (syscall dev)");   // SMP-2: perintah dev `panic ap`
    }
    return (uint64_t)cpu_index();
}
#endif

static const syscall_desc_t syscall_table[SYSCALL_COUNT] = {
    [SYS_TEST]  = { sys_test,  false },
    [SYS_WRITE] = { sys_write, true  },
    [SYS_EXIT]  = { sys_exit,  false },
    [SYS_SOCKET]   = { sock_sys_socket,   false },
    [SYS_BIND]     = { sock_sys_bind,     false },
    [SYS_SENDTO]   = { sock_sys_sendto,   false },
    [SYS_RECVFROM] = { sock_sys_recvfrom, false },
    [SYS_CLOSE]    = { sock_sys_close,    false },
    [SYS_LISTEN]   = { sock_sys_listen,   false },
    [SYS_ACCEPT]   = { sock_sys_accept,   false },
    [SYS_SEND]     = { sock_sys_send,     false },
    [SYS_RECV]     = { sock_sys_recv,     false },
    [SYS_CONNECT]  = { sock_sys_connect,  false },
#ifndef BMAHOS_PROD
    [SYS_CPU]      = { sys_cpu,           false },
#endif
};

// Dispatch syscall (int 0x80). context->rax = nomor syscall saat
// masuk, ditimpa dengan return value sebelum kembali ke pemanggil.
uint64_t g_sys_calls;      // R6-1: semua int 0x80
uint64_t g_sys_rejected;   // nomor tidak dikenal / pointer atau len ditolak
uint64_t g_user_faults;    // exception dari ring 3 (task dihentikan)

static void syscall_handler(struct exception_context *context)
{
    uint64_t syscall_num = context->rax;

    g_sys_calls++;
#ifndef BMAHOS_PROD
    // F7 (dev): task uji menyalakan EFLAGS.AC lalu SYS_TEST dengan rdi=0xAC; AC di kernel
    // harus 0 (clac di entry) bila SMAP aktif.
    if (syscall_num == SYS_TEST && context->rdi == 0xAC) {
        uint64_t fl;

        __asm__ volatile("pushfq\n\tpopq %0" : "=r"(fl));
        if (res_log_ok(&tasks[current_index], current_index, timer_ticks)) {
            kprintf("F7: syscall AC user=%lu kernel=%lu smap=%lu\r\n",
                    (context->rflags >> 18) & 1, (fl >> 18) & 1, (uint64_t)g_smap_on);
        }
    }
#endif
    // F7: batas sumber daya task user (prio.c): jatah syscall per jendela dan byte SYS_WRITE.
    // Ditolak = tanpa efek, kode SOCK_EDQUOT. Terlalu lama melanggar = task dihentikan
    // (seperti sys_exit: tidak kembali). SYS_EXIT tidak pernah ditolak. Sebelum cek nomor:
    // banjir nomor tak dikenal (satu baris serial tiap panggilan) ikut terbatasi.
    {
        int kind = syscall_num == SYS_EXIT ? RES_SC_EXIT :
                   syscall_num == SYS_WRITE ? RES_SC_WRITE : RES_SC_OTHER;
        int rc = res_syscall(&tasks[current_index], current_index, timer_ticks, kind, context->rsi);

        if (rc == RES_KILL)
        {
            task_exit();
        }
        if (rc == RES_DENY)
        {
            context->rax = (uint64_t)(int64_t)SOCK_EDQUOT;
            return;
        }
    }

    if (syscall_num >= SYSCALL_COUNT || syscall_table[syscall_num].fn == 0)
    {
        g_sys_rejected++;
        if (res_reject(&tasks[current_index], current_index, timer_ticks)) {   // F7: log terbatas
            serial_write("SYSCALL tidak dikenal: ");
            serial_write_hex(syscall_num);
            serial_write("\r\n");
        }
        context->rax = (uint64_t)-1;
        return;
    }

    if (syscall_table[syscall_num].has_user_ptr)
    {
        // R6-1: len dibatasi dulu. sys_write menulis ke UART dengan polling
        // saat interrupt mati: len besar = sistem macet tanpa tick (watchdog
        // R5 pun tidak melihatnya).
        if (context->rsi > SYS_WRITE_MAX ||
            !is_valid_user_ptr(g_current_pml4_phys, context->rdi, context->rsi, false))
        {
            g_sys_rejected++;
            if (res_reject(&tasks[current_index], current_index, timer_ticks)) {   // F7: log terbatas
                serial_write("syscall_handler(): DITOLAK -- pointer/len tidak valid (syscall=");
                serial_write_hex(syscall_num);
                serial_write(", ptr=");
                serial_write_hex(context->rdi);
                serial_write(", len=");
                serial_write_hex(context->rsi);
                serial_write(")\r\n");
            }
            context->rax = (uint64_t)-1;
            return;
        }
    }

    context->rax = syscall_table[syscall_num].fn(
        context->rdi,
        context->rsi,
        context->rdx,
        context->r10,
        context->r8
    );
}

static void exception_body(struct exception_context *context)
{
    if (context->vector == 128)
    {
        syscall_handler(context);
        return;
    }

    // R6-1: exception dari ring 3 hanya menghentikan task itu (kecuali NMI,
    // #DF, #MC: masalah mesin, tetap panic). Kata "fault"/"exception" sengaja
    // tidak dipakai di baris log (grep fault di uji).
    uint64_t v = context->vector;
    if ((context->cs & 3) == 3 && v != 2 && v != 8 && v != 18)
    {
        uint64_t cr2;
        __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
        g_user_faults++;
        kprintf("R6: task user slot %lu dihentikan (vektor %lu kode=0x%lx rip=%p cr2=%p)\r\n",
                (uint64_t)current_index, v, context->error_code,
                (void *)(uintptr_t)context->rip, (void *)(uintptr_t)cr2);
        task_exit();   // tidak kembali (sama seperti sys_exit)
    }

    // R1: dump register + stack trace + reboot otomatis (panic.c).
    panic_exception(context);
}

// SMP-2: semua exception/syscall berjalan di bawah BKL (bkl.c). NMI TIDAK mengambil BKL: bila ada
// panic di CPU lain, CPU ini berhenti selamanya (smp_stop_self); NMI di luar panic ke jalur lama.
void exception_dispatcher(struct exception_context *context)
{
    // Sudah ada panic: CPU lain (NMI atau exception sendiri) berhenti, TANPA mengambil BKL (pemiliknya
    // mungkin sudah dihentikan NMI: menunggu BKL = berputar selamanya). CPU pemilik panic (exception
    // bersarang di dalam panic handler) langsung ke exception_body supaya jaminan reboot R1 tetap ada.
    int pc = g_panic_cpu;

    if (pc >= 0) {
        if (pc != cpu_index()) {
            smp_stop_self();   // tidak kembali
        }
        exception_body(context);
        return;
    }
    if (context->vector == 2) {
        exception_body(context);   // NMI biasa tanpa panic: jalur lama (panic)
        return;
    }
    bkl_isr_enter();
    exception_body(context);
    bkl_isr_leave(context);
}
volatile uint64_t timer_ticks = 0;

// Dipanggil dari irq_common_stub (kernel/interrupt.S) untuk SEMUA
// IRQ. Beda dari exception_dispatcher: TIDAK boleh halt permanen,
// dan WAJIB kirim EOI ke PIC di akhir supaya interrupt berikutnya
// bisa masuk.
static void irq_body(struct exception_context *context)
{
    uint64_t irq_num = context->vector;
    int res_kill = 0;

    // SMP-1: IPI. Tidak menyentuh scheduler/timer (hanya BSP yang menjalankan task).
    if (irq_num == SMP_VEC_IPI_TEST) {
        smp_ipi_rx();
        lapic_send_eoi();
        return;
    }
    if (irq_num == SMP_VEC_STOP) {
        smp_stop_self();   // tidak kembali
    }
    if (irq_num == SMP_VEC_TLB) {   // SMP-2: tanpa BKL; hanya invlpg + ack
        tlb_ipi_rx();
        lapic_send_eoi();
        return;
    }
    if (irq_num == SMP_VEC_RESCHED) {   // SMP-2: bangunkan CPU idle (BKL sudah diambil wrapper)
        smp_resched_rx();
        lapic_send_eoi();
        schedule();
        return;
    }
    if (irq_num == SMP_VEC_LTIMER) {   // SMP-2: tick lokal AP (~100 Hz). BSP tetap memakai IRQ0 PIT.
        cpu_t *c = this_cpu();
        int ci = (int)c->index;
        int kill = 0;

        if (ci != 0 && c->sched_on) {
            size_t cur = c->current;

            c->ltick++;
            if (cur < task_count) {
                // Jatah CPU task user dihitung di CPU yang menjalankannya (cuplik current per CPU).
                kill = res_tick(&tasks[cur], cur, timer_ticks, (context->cs & 3) == 3) == RES_KILL;
            }
            lapic_send_eoi();
            if (kill) {
                task_exit();   // batas sumber daya dilanggar terus (tidak kembali)
            }
            schedule();
        } else {
            lapic_send_eoi();
        }
        return;
    }

    // SMP-1: IRQ timer/NIC hanya boleh sampai ke BSP (IOAPIC diarahkan ke ID LAPIC BSP).
    // Bila masuk ke CPU lain: hitung (smp_irq_stray), EOI, abaikan (jangan menyentuh task/scheduler).
    if (irq_num <= 1 && g_smp_online > 1 && cpu_index() != 0) {
        g_smp_stray++;
        lapic_send_eoi();
        return;
    }

    if (irq_num == 0) {
        timer_ticks++;
        g_cpus[0].ltick++;
        metrics_cpu_tick(current_index == g_idle_index);   // R3
        entropy_event(ENTROPY_SRC_TIMER, 0);
        net_rx_tick_wake();
        watchdog_check(context);   // R5: hanya memeriksa; tepukan dari net task
        if (scheduler_started && current_index < task_count) {
            // F7: bebankan tick ke task yang jalan; RES_KILL hanya bila tick jatuh di ring 3
            res_kill = res_tick(&tasks[current_index], current_index, timer_ticks,
                                (context->cs & 3) == 3) == RES_KILL;
        }
    }

    if (irq_num == 1) {
        entropy_event(ENTROPY_SRC_NIC_IRQ, 0);
        e1000_irq_service();
    }

    // LAPIC (bukan legacy PIC) yang mengirim interrupt ini (lewat
    // IOAPIC redirection), jadi EOI WAJIB ke LAPIC juga.
    lapic_send_eoi();

    // EOI WAJIB dikirim SEBELUM schedule()/context_switch() -- kalau
    // dibalik, LAPIC ISR bit masih nyala selama kita pindah task, dan
    // timer berikutnya (untuk task manapun) tidak akan pernah masuk.
    if (irq_num == 0) {
        if (res_kill) {
            task_exit();   // F7: batas sumber daya dilanggar terus (tidak kembali)
        }
        schedule();
    }
}




static void trigger_divide_error(void)
{
    uint64_t dividend = 1;
    uint64_t divisor = 0;
    uint64_t result;

    __asm__ volatile (
        "divq %2"
        : "=a"(result)
        : "a"(dividend), "r"(divisor)
        : "rdx"
    );
}

static void trigger_general_protection_fault(void)
{
    __asm__ volatile (
        "movw $0x28, %%ax\n\t"
        "movw %%ax, %%ds"
        :
        :
        : "ax", "memory"
    );
}

static void trigger_double_fault(void)
{
    // Matikan present bit (bit 7) pada IDT[0] (#DE handler).
    // 0x8E = 1000 1110 -> 0x0E = 0000 1110
    // Saat #DE terjadi, CPU akan gagal masuk handler karena
    // entry-nya "not present", memicu fault kedua -> #DF.
    bmahOS_idt[0].type_attr &= 0x7F;

    trigger_divide_error();
}

static void trigger_invalid_opcode(void)
{
    // ud2 adalah instruksi resmi x86 yang memang didesain
    // untuk sengaja memicu #UD (Invalid Opcode).
    __asm__ volatile ("ud2");
}

static void trigger_invalid_tss(void)
{
    // ltr dengan selector 0x08 (code segment kita, bukan TSS
    // descriptor). CPU cek tipe descriptor yang ditunjuk,
    // ternyata bukan TSS valid -> #TS.
    __asm__ volatile (
        "movw $0x08, %%ax\n\t"
        "ltr %%ax"
        :
        :
        : "ax"
    );
}

static void trigger_page_fault(void)
{
    // Dereference NULL pointer (alamat virtual 0x0).
    // Tidak dipetakan di ruang alamat kernel manapun (bukan
    // higher-half kernel, bukan HHDM Limine) -> MMU gagal
    // translate -> #PF. CPU simpan alamat gagal ini di CR2.
    volatile uint64_t *null_ptr = (volatile uint64_t *)0x0;
    volatile uint64_t value = *null_ptr;
    (void)value;
}

static void trigger_not_present(void)
{
    // Matikan present bit pada GDT data segment (index 2, 0x10).
    // Load ulang DS dengan selector itu -> CPU deteksi segment
    // not-present pada DS/ES/FS/GS -> #NP (bukan #SS).
    bmahOS_gdt[2].access &= 0x7F;
    __asm__ volatile (
        "movw $0x10, %%ax\n\t"
        "movw %%ax, %%ds"
        :
        :
        : "ax", "memory"
    );
}

static void trigger_stack_fault(void)
{
    // Sama seperti #NP, tapi kali ini yang di-reload adalah SS.
    // Sesuai Intel SDM: load SS ke segment not-present secara
    // spesifik memicu #SS, berbeda dari DS/ES/FS/GS yang -> #NP.
    bmahOS_gdt[2].access &= 0x7F;
    __asm__ volatile (
        "movw $0x10, %%ax\n\t"
        "movw %%ax, %%ss"
        :
        :
        : "ax", "memory"
    );
}

void trigger_breakpoint(void)
{
    // int3 adalah instruksi resmi 1-byte (0xCC) yang memang
    // didesain untuk memicu #BP, dipakai debugger untuk software
    // breakpoint.
    __asm__ volatile ("int3");
}

static void trigger_overflow(void)
{
    // CATATAN: instruksi "into" DIHAPUS di mode 64-bit (long mode)
    // oleh spesifikasi AMD64/x86-64 -- bukan keterbatasan bmahOS,
    // tapi keterbatasan arsitektur CPU itu sendiri. Assembler modern
    // menolak compile "into" untuk target 64-bit.
    //
    // Akibatnya #OF TIDAK dapat ditrigger via software biasa di
    // kernel 64-bit manapun. Vektor 4 tetap terdaftar di IDT
    // (stub ISR_NOERR 4 ada, dispatcher siap menangani jika CPU
    // pernah mengirimnya lewat jalur lain), tapi sengaja tidak
    // ditest aktif karena tidak ada mekanisme software valid untuk
    // memicunya di long mode.
}

// SMP-2: vektor yang tidak menyentuh data bersama tidak mengambil BKL (bkl.c, I5). Resched/tick
// LAPIC hanya bila scheduler CPU ini sudah hidup (sebelum itu: abaikan, EOI saja).
static int irq_wants_bkl(uint64_t v)
{
    switch (v) {
    case SMP_VEC_IPI_TEST:
    case SMP_VEC_STOP:
    case SMP_VEC_TLB:
        return 0;
    case SMP_VEC_RESCHED:
    case SMP_VEC_LTIMER:
        return this_cpu()->sched_on;
    default:
        break;
    }
    if (v <= 1 && g_smp_online > 1 && cpu_index() != 0) {
        return 0;   // IRQ liar di AP: hitung + EOI saja (irq_body)
    }
    return 1;
}

void irq_handler(struct exception_context *context)
{
    int bkl = irq_wants_bkl(context->vector);

    if (bkl) {
        bkl_isr_enter();
    }
    irq_body(context);
    if (bkl) {
        bkl_isr_leave(context);
    }
}

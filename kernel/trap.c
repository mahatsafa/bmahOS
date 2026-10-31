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
#define SYSCALL_COUNT 3

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

    const char *buf = (const char *)buf_ptr;
    for (uint64_t i = 0; i < len; i++) {
        serial_putc(buf[i]);
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

static const syscall_desc_t syscall_table[SYSCALL_COUNT] = {
    [SYS_TEST]  = { sys_test,  false },
    [SYS_WRITE] = { sys_write, true  },
    [SYS_EXIT]  = { sys_exit,  false },
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
    if (syscall_num >= SYSCALL_COUNT || syscall_table[syscall_num].fn == 0)
    {
        g_sys_rejected++;
        serial_write("SYSCALL tidak dikenal: ");
        serial_write_hex(syscall_num);
        serial_write("\r\n");
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
            serial_write("syscall_handler(): DITOLAK -- pointer/len tidak valid (syscall=");
            serial_write_hex(syscall_num);
            serial_write(", ptr=");
            serial_write_hex(context->rdi);
            serial_write(", len=");
            serial_write_hex(context->rsi);
            serial_write(")\r\n");
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

void exception_dispatcher(struct exception_context *context)
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
volatile uint64_t timer_ticks = 0;

// Dipanggil dari irq_common_stub (kernel/interrupt.S) untuk SEMUA
// IRQ. Beda dari exception_dispatcher: TIDAK boleh halt permanen,
// dan WAJIB kirim EOI ke PIC di akhir supaya interrupt berikutnya
// bisa masuk.
void irq_handler(struct exception_context *context)
{
    uint64_t irq_num = context->vector;

    if (irq_num == 0) {
        timer_ticks++;
        metrics_cpu_tick(current_index == g_idle_index);   // R3
        entropy_event(ENTROPY_SRC_TIMER, 0);
        net_rx_tick_wake();
        watchdog_check(context);   // R5: hanya memeriksa; tepukan dari net task
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

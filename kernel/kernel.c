#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>
#include "kernel.h"

__attribute__((used, section(".limine_requests")))
static volatile uint64_t limine_base_revision[] =
    LIMINE_BASE_REVISION(6);

__attribute__((used, section(".limine_requests_start_marker")))
static volatile uint64_t limine_requests_start_marker[] =
    LIMINE_REQUESTS_START_MARKER;

__attribute__((used, section(".limine_requests")))
static volatile struct limine_hhdm_request hhdm_request = {
    .id = LIMINE_HHDM_REQUEST_ID,
};

uint64_t hhdm_offset = 0;

// Address space YANG DIPAKAI SEMUA task saat ini (kernel maupun
// user) -- arsitektur sekarang belum isolasi per-proses (ditunda ke
// Layer 8+, lihat catatan rencana). Diisi sekali di kmain() dari
// read_cr3(), dipakai syscall (mis. sys_write) untuk validasi
// pointer user lewat is_valid_user_ptr().
uint64_t g_current_pml4_phys = 0;
// Checkpoint spawn: PML4 kernel ASLI (hasil read_cr3() sekali di awal
// boot), TIDAK PERNAH berubah setelah diisi -- beda dari
// g_current_pml4_phys yang berubah tiap schedule() mengikuti task
// aktif. Ini sumber kebenaran stabil untuk spawn()/vmm_clone_kernel_pml4()
// supaya tidak perlu terima kernel_pml4_phys sebagai parameter caller.
uint64_t g_kernel_pml4_phys = 0;

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
};

__attribute__((used, section(".limine_requests")))
volatile struct limine_rsdp_request rsdp_request = {
    .id = LIMINE_RSDP_REQUEST_ID,
};

extern void irq32(void);
extern void irq33(void);

void kmain(void);

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end_marker[] =
    LIMINE_REQUESTS_END_MARKER;

static void e1000_irq_service(void);
static void net_rx_tick_wake(void);
// Forward declaration struct -- definisi lengkap ada dekat task_t,
// tapi tipenya perlu dikenal compiler di sini untuk sem_wait/sem_post.
typedef struct semaphore semaphore_t;



// ---- Net-12: ring buffer log (disaring: tanpa baris schedule()) ----
#define LOG_LINE_MAX  160

char g_log_ring[LOG_RING_SIZE];
uint32_t g_log_head = 0;
uint64_t g_log_total = 0;
static char g_log_line[LOG_LINE_MAX];
static uint32_t g_log_line_len = 0;

// Dipanggil dari serial_putc() dengan interrupt dimatikan. Merakit baris
// dulu; baris lengkap masuk ring kecuali kosong atau diawali
// "schedule(): switch" (bising, ~100 baris/detik).
void log_capture(char c)
{
    static const char noisy[] = "schedule(): switch";
    const uint32_t noisy_len = sizeof(noisy) - 1;

    if (c == '\r') {
        return;
    }

    if (c != '\n') {
        if (g_log_line_len < LOG_LINE_MAX) {
            g_log_line[g_log_line_len++] = c;
        }
        return;
    }

    int skip = (g_log_line_len == 0);

    if (!skip && g_log_line_len >= noisy_len) {
        skip = 1;
        for (uint32_t i = 0; i < noisy_len; i++) {
            if (g_log_line[i] != noisy[i]) {
                skip = 0;
                break;
            }
        }
    }

    if (!skip) {
        for (uint32_t i = 0; i < g_log_line_len; i++) {
            g_log_ring[g_log_head] = g_log_line[i];
            g_log_head = (g_log_head + 1) & (LOG_RING_SIZE - 1);
            g_log_total++;
        }

        g_log_ring[g_log_head] = '\n';
        g_log_head = (g_log_head + 1) & (LOG_RING_SIZE - 1);
        g_log_total++;
    }

    g_log_line_len = 0;
}


struct exception_context
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;

    uint64_t vector;
    uint64_t error_code;

    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
};

_Static_assert(
    sizeof(struct exception_context) == 20 * sizeof(uint64_t),
    "exception_context size is wrong"
);

static uint64_t read_ss(void)
{
    uint16_t ss;

    __asm__ volatile (
        "mov %%ss, %0"
        : "=r"(ss)
    );

    return ss;
}

// ===============================================================
// Syscall dispatch table
//
// Konvensi: rax = nomor syscall, rdi/rsi/rdx = argumen 1/2/3
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

static uint64_t sys_test(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
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
static uint64_t sys_write(uint64_t buf_ptr, uint64_t len, uint64_t arg2)
{
    (void)arg2;

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
static uint64_t sys_exit(uint64_t arg0, uint64_t arg1, uint64_t arg2)
{
    (void)arg0; (void)arg1; (void)arg2;

    task_exit();

    // Tidak pernah sampai sini kalau context_switch() berhasil pergi
    // ke task lain. Kalau task ini satu-satunya yang hidup,
    // task_exit() sudah hlt selamanya duluan sebelum baris ini.
    return 0;
}

typedef uint64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t);

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
static void syscall_handler(struct exception_context *context)
{
    uint64_t syscall_num = context->rax;

    if (syscall_num >= SYSCALL_COUNT || syscall_table[syscall_num].fn == 0)
    {
        serial_write("SYSCALL tidak dikenal: ");
        serial_write_hex(syscall_num);
        serial_write("\r\n");
        context->rax = (uint64_t)-1;
        return;
    }

    if (syscall_table[syscall_num].has_user_ptr)
    {
        if (!is_valid_user_ptr(g_current_pml4_phys, context->rdi, context->rsi, false))
        {
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
        context->rdx
    );
}

void exception_dispatcher(struct exception_context *context)
{
    if (context->vector == 128)
    {
        syscall_handler(context);
        return;
    }

    serial_write("\r\n");
    serial_write("=== EXCEPTION DISPATCHER ===\r\n");

    serial_write("vector:  ");
    serial_write_hex(context->vector);
    serial_write("\r\n");

    serial_write("error:   ");
    serial_write_hex(context->error_code);
    serial_write("\r\n");

    serial_write("RIP:     ");
    serial_write_hex(context->rip);
    serial_write("\r\n");

    serial_write("CS:      ");
    serial_write_hex(context->cs);
    serial_write("\r\n");

    serial_write("RFLAGS:  ");
    serial_write_hex(context->rflags);
    serial_write("\r\n");

    serial_write("SS:      ");
    serial_write_hex(read_ss());
    serial_write("\r\n");

        {
        uint64_t cr2;
        __asm__ volatile ("mov %%cr2, %0" : "=r"(cr2));
        serial_write("CR2 (fault addr, relevan utk #PF): ");
        serial_write_hex(cr2);
        serial_write("\r\n");
    }

    serial_write("=== END EXCEPTION ===\r\n");
    for (;;) { __asm__ volatile ("hlt"); }
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
        net_rx_tick_wake();
    }

    if (irq_num == 1) {
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

static void trigger_breakpoint(void)
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

// =============================================================
// Layer 7: user task creation (checkpoint -- dummy code hardcode,
// belum dipanggil dari mana pun, cuma dites kompilasi dulu).
//
// Dummy code IDENTIK dengan test usermode manual di kmain() (Layer 6):
// SYS_TEST(0x99) lalu spin loop (jmp $, BUKAN hlt -- hlt privileged,
// akan #GP di ring 3).
static const uint8_t user_task_dummy_code[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, 0   (SYS_TEST)
    0xBF, 0x99, 0x00, 0x00, 0x00,   // mov edi, 0x99 (arg0)
    0xBE, 0x00, 0x00, 0x00, 0x00,   // mov esi, 0
    0xBA, 0x00, 0x00, 0x00, 0x00,   // mov edx, 0
    0xCD, 0x80,                     // int 0x80
    0xEB, 0xFE                      // jmp $ (spin loop)
};

// Layer 8 checkpoint 4: uji isolasi address space sesungguhnya. Task
// ini (tasks[2], PML4 privat sendiri hasil vmm_clone_kernel_pml4())
// mencoba SYS_WRITE ke 0x600000 -- alamat yang VALID dan MAPPED milik
// task LAIN (tasks[3], lihat USER_CODE_VADDR2), tapi TIDAK PERNAH
// di-map di PML4 milik task INI. Kalau isolasi bekerja benar,
// is_valid_user_ptr() HARUS menolak (vmm_is_user_page() menemukan
// halaman not-present saat walk di PML4 task ini sendiri) -- BUKAN
// menolak karena alasan lain (mis. alamat kernel seperti test
// sebelumnya). Ini pembeda penting: test lama membuktikan "pointer ke
// kernel ditolak", test ini membuktikan "pointer ke SESAMA USER TASK
// LAIN ikut ditolak", yang jauh lebih kuat sebagai bukti isolasi.
static const uint8_t user_task_isolation_test_code[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xBF, 0x00, 0x00, 0x60, 0x00,
    0xBE, 0x05, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xEB, 0xFE
};

static const uint8_t user_task_syswrite_test_code[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xBF, 0x33, 0x00, 0x60, 0x00,
    0xBE, 0x06, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,

    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xBF, 0x00, 0x00, 0x00, 0x80,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xBE, 0x05, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,

    0xEB, 0xFE,

    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A
};

// Checkpoint spawn (B) -- uji nyata: BEDA dari user_task_syswrite_test_code
// di atas, array ini punya immediate address yang dihitung untuk base
// USER_VADDR_ALLOC_BASE (0x400000), BUKAN 0x600000. Ini bukan bug
// spawn() -- ini pembelajaran: kode biner mentah yang ditulis manual
// TIDAK position-independent, pointer string di dalamnya adalah
// alamat absolut yang cuma benar untuk SATU base tertentu. spawn()
// yang dipakai untuk menjalankan image dari base MANAPUN (hasil
// vmm_alloc_vaddr()) butuh image yang memang dirakit untuk base itu,
// atau (nanti) mekanisme relokasi/PIC -- di luar lingkup checkpoint
// spawn generik pertama, dicatat sebagai konteks penting, bukan utang
// yang perlu diselesaikan sekarang karena base allocator sudah tetap
// (USER_VADDR_ALLOC_BASE) sejauh ini.
static const uint8_t user_task_spawn_test_code[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0xBF, 0x33, 0x00, 0x40, 0x00,
    0xBE, 0x06, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,

    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x48, 0xBF, 0x00, 0x00, 0x00, 0x80,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xBE, 0x05, 0x00, 0x00, 0x00,
    0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,

    0xEB, 0xFE,

    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x0A
};
// Layer 8: uji SYS_EXIT. Urutan: SYS_WRITE("before exit\n"),
// SYS_EXIT(), SYS_WRITE("after exit\n") [TIDAK BOLEH PERNAH
// TEREKSEKUSI], jmp $ (fallback kalau somehow lolos). Offset string
// dihitung otomatis dari panjang kode (bukan manual) lewat script
// Python terpisah saat menyusun array ini, base vaddr 0x800000.
static const uint8_t user_task_sysexit_test_code[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, 0xBF, 0x44, 0x00, 0x80, 0x00,
    0xBE, 0x0C, 0x00, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xB8, 0x02, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x00, 0x00,
    0xBE, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xB8, 0x01, 0x00, 0x00, 0x00, 0xBF, 0x50, 0x00, 0x80, 0x00,
    0xBE, 0x0B, 0x00, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xEB, 0xFE,
    0x62, 0x65, 0x66, 0x6F, 0x72, 0x65, 0x20, 0x65, 0x78, 0x69, 0x74, 0x0A,
    0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x65, 0x78, 0x69, 0x74, 0x0A
};

static void vmm_unmap(uint64_t pml4_phys, uint64_t vaddr)
{
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    uint64_t *pml4_virt = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t pml4_entry = pml4_virt[pml4_idx];
    if ((pml4_entry & VMM_FLAG_PRESENT) == 0) return;

    uint64_t pdpt_phys = pml4_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pdpt_virt = (uint64_t *)(pdpt_phys + hhdm_offset);
    uint64_t pdpt_entry = pdpt_virt[pdpt_idx];
    if ((pdpt_entry & VMM_FLAG_PRESENT) == 0) return;

    uint64_t pd_phys = pdpt_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pd_virt = (uint64_t *)(pd_phys + hhdm_offset);
    uint64_t pd_entry = pd_virt[pd_idx];
    if ((pd_entry & VMM_FLAG_PRESENT) == 0) return;

    uint64_t pt_phys = pd_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pt_virt = (uint64_t *)(pt_phys + hhdm_offset);

    pt_virt[pt_idx] = 0;

    __asm__ volatile ("invlpg (%0)" : : "r"(vaddr) : "memory");
}



volatile uint64_t g_net_loops = 0;
static semaphore_t g_net_rx_sem = { .count = 0 };

// Cadangan: tiap tick timer membangunkan net task (maks. 1 post tertunda)
// supaya interrupt yang terlewat paling lama tertunda satu tick. Aktif
// hanya setelah GSI E1000 terkunci.
static void net_rx_tick_wake(void)
{
    if (g_net_rx_sem.count < 1) {
        sem_post(&g_net_rx_sem);
    }
}

// Dipanggil dari irq_handler() (interrupt mati, sebelum EOI). Baca ICR
// dulu (melepas garis level-triggered), lalu catat GSI mana yang
// Remote-IRR-nya menyala. Bila ICR = 0 berarti bukan interrupt kita:
// mask GSI yang menyala supaya tidak jadi interrupt storm.
static void e1000_irq_service(void)
{
    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;
    uint32_t icr = mmio[0x00C0 / 4];
    uint32_t rirr = 0;

    for (uint32_t gsi = 16; gsi <= g_e1000_irq_last_gsi; gsi++) {
        uint32_t low = ioapic_read(IOAPIC_REDTBL_BASE + gsi * 2);

        if (low & (1u << 14)) {
            rirr |= 1u << (gsi - 16);
        }
    }

    g_e1000_irq_count++;
    g_e1000_irq_last_icr = icr;
    g_e1000_irq_icr_or |= icr;

    if (icr != 0) {
        g_e1000_irq_rirr_or |= rirr;

        // Tepat satu pin dengan Remote-IRR menyala saat ICR != 0 -> pin itu
        // INTx E1000. Kunci, lalu mask semua kandidat lain.
        if (g_e1000_irq_gsi == 0 && rirr != 0 && (rirr & (rirr - 1)) == 0) {
            uint32_t bit = 0;

            while (!(rirr & (1u << bit))) {
                bit++;
            }

            uint32_t locked = 16 + bit;

            for (uint32_t gsi = 16; gsi <= g_e1000_irq_last_gsi; gsi++) {
                if (gsi != locked) {
                    uint32_t idx = IOAPIC_REDTBL_BASE + gsi * 2;

                    ioapic_write(idx, ioapic_read(idx) | (1u << 16));
                    g_e1000_irq_masked |= 1u << (gsi - 16);
                }
            }

            g_e1000_irq_gsi = locked;
        }

        if (g_net_rx_sem.count < 1) {
            sem_post(&g_net_rx_sem);
        }

        return;
    }

    g_e1000_irq_spurious++;

    for (uint32_t gsi = 16; gsi <= g_e1000_irq_last_gsi; gsi++) {
        if ((rirr & (1u << (gsi - 16))) && gsi != g_e1000_irq_gsi) {
            uint32_t idx = IOAPIC_REDTBL_BASE + gsi * 2;
            uint32_t low = ioapic_read(idx);

            ioapic_write(idx, low | (1u << 16));
            g_e1000_irq_masked |= 1u << (gsi - 16);
        }
    }
}

// Kernel task jaringan: polling terus, dipreempt scheduler (timer).
// Utang teknis: busy-poll (pause), belum interrupt-driven, jadi CPU
// tidak pernah idle. Akan diganti IRQ E1000 via IOAPIC.
// Task idle: tidak pernah blok. Task kernel baru mulai dengan IF=0 (lihat
// Net-7), jadi sti dulu; hlt berhenti sampai interrupt berikutnya (tick).
static void idle_task_entry(void)
{
    __asm__ volatile ("sti");

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

static void net_task_entry(void)
{
    if (!g_e1000_rx_initialized) {
        serial_write("Net-7: RX belum di-init, net task berhenti\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    uint64_t rf_before;
    __asm__ volatile ("pushfq; popq %0" : "=r"(rf_before));

    // Task kernel baru masuk lewat ret dari context_switch (bukan iretq),
    // jadi mewarisi IF dari konteks pemanggil. Kalau dipanggil dari dalam
    // handler timer, IF=0 -> tanpa sti loop ini tidak pernah dipreempt.
    __asm__ volatile ("sti");

    uint64_t rf_after;
    __asm__ volatile ("pushfq; popq %0" : "=r"(rf_after));

    uint64_t lf = irq_save();
    serial_write("Net-7: net task dimulai (polling permanen) RFLAGS sebelum=");
    serial_write_hex(rf_before);
    serial_write(" sesudah sti=");
    serial_write_hex(rf_after);
    serial_write("\r\n");
    irq_restore(lf);

    for (;;) {
        static int irq_reported = 0;

        if (!irq_reported && g_e1000_irq_count > 0) {
            irq_reported = 1;

            uint64_t lf2 = irq_save();
            serial_write("IRQ-exp: interrupt E1000 pertama terlihat, count=");
            serial_write_hex((uint64_t)g_e1000_irq_count);
            serial_write(" icr_or=");
            serial_write_hex((uint64_t)g_e1000_irq_icr_or);
            serial_write(" rirr_or=");
            serial_write_hex((uint64_t)g_e1000_irq_rirr_or);
            serial_write("\r\n");
            irq_restore(lf2);
        }

        g_net_loops++;

        while (net_poll() > 0) {
        }

        net_tcp_tick();
        sem_wait(&g_net_rx_sem);
    }
}

static void e1000_send_arp_request(void)
{
    uint64_t pkt_phys = pmm_alloc();

    if (pkt_phys == 0) {
        serial_write("Net-3: FATAL - pmm_alloc gagal\r\n");
        return;
    }

    uint8_t *pkt_virt = (uint8_t *)(pkt_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        pkt_virt[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        pkt_virt[i] = 0xFF;
    }

    for (int i = 0; i < 6; i++) {
        pkt_virt[6 + i] = g_e1000_mac[i];
    }

    pkt_virt[12] = 0x08;
    pkt_virt[13] = 0x06;

    uint32_t a = 14;

    pkt_virt[a + 0x00] = 0x00;
    pkt_virt[a + 0x01] = 0x01;

    pkt_virt[a + 0x02] = 0x08;
    pkt_virt[a + 0x03] = 0x00;

    pkt_virt[a + 0x04] = 6;
    pkt_virt[a + 0x05] = 4;

    pkt_virt[a + 0x06] = 0x00;
    pkt_virt[a + 0x07] = 0x01;

    for (int i = 0; i < 6; i++) {
        pkt_virt[a + 0x08 + i] = g_e1000_mac[i];
    }

    pkt_virt[a + 0x0E] = 192;
    pkt_virt[a + 0x0F] = 168;
    pkt_virt[a + 0x10] = 50;
    pkt_virt[a + 0x11] = 200;

    for (int i = 0; i < 6; i++) {
        pkt_virt[a + 0x12 + i] = 0x00;
    }

    pkt_virt[a + 0x18] = 192;
    pkt_virt[a + 0x19] = 168;
    pkt_virt[a + 0x1A] = 50;
    pkt_virt[a + 0x1B] = 1;

    uint32_t frame_len = 14 + 28;

    if (frame_len < 60) {
        frame_len = 60;
    }

    serial_write("Net-3: mengirim ARP request, panjang=");
    serial_write_hex(frame_len);
    serial_write(" byte\r\n");
    serial_write("Net-3: sender_ip=192.168.50.200 target_ip=192.168.50.1\r\n");

    int ok = e1000_tx_send(pkt_phys, frame_len);

    serial_write("Net-3: e1000_tx_send -> ");
    serial_write(ok ? "sukses (DD set)" : "GAGAL");
    serial_write("\r\n");

}

static void ahci_probe_and_log(uint64_t pml4_phys)
{
    if (!g_ahci_found) {
        serial_write("AHCI: controller tidak ditemukan, skip\r\n");
        return;
    }

    // PCI Command bit1 Memory Space + bit2 Bus Master (DMA). Firmware tidak
    // selalu menyalakannya; status (16 bit atas) write-1-to-clear, tulis 0.
    uint32_t ahci_cmd = pci_config_read32(AHCI_PCI_BUS, AHCI_PCI_DEVICE,
                                          AHCI_PCI_FUNCTION, 0x04) & 0xFFFFu;
    pci_config_write32(AHCI_PCI_BUS, AHCI_PCI_DEVICE, AHCI_PCI_FUNCTION,
                       0x04, ahci_cmd | 0x0006u);

    uint32_t bar5 = pci_config_read32(AHCI_PCI_BUS, AHCI_PCI_DEVICE, AHCI_PCI_FUNCTION, AHCI_BAR5_OFFSET);
    uint64_t abar_phys = bar5 & 0xFFFFFFF0ULL;

    serial_write("AHCI: BAR5 raw = ");
    serial_write_hex(bar5);
    serial_write(", ABAR phys = ");
    serial_write_hex(abar_phys);
    serial_write("\r\n");

    if (abar_phys == 0) {
        serial_write("AHCI: ABAR physical address 0, skip (device tidak ditemukan di B/D/F ini?)\r\n");
        return;
    }

    vmm_map(pml4_phys, AHCI_VIRT, abar_phys,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE | VMM_FLAG_NX);

    volatile uint32_t *hba = (volatile uint32_t *)AHCI_VIRT;

    uint32_t cap = hba[AHCI_REG_CAP / 4];
    uint32_t ghc = hba[AHCI_REG_GHC / 4];
    uint32_t is_reg = hba[AHCI_REG_IS / 4];
    uint32_t pi = hba[AHCI_REG_PI / 4];
    uint32_t vs = hba[AHCI_REG_VS / 4];

    serial_write("AHCI: CAP=");
    serial_write_hex(cap);
    serial_write(" GHC=");
    serial_write_hex(ghc);
    serial_write(" IS=");
    serial_write_hex(is_reg);
    serial_write(" PI=");
    serial_write_hex(pi);
    serial_write(" VS=");
    serial_write_hex(vs);
    serial_write("\r\n");

    serial_write("AHCI: Port detection (PxSSTS/PxSIG per implemented port)\r\n");

    for (uint32_t i = 0; i < 32; i++) {
        if (!(pi & (1u << i))) {
            continue;
        }

        uint32_t port_base = 0x100 + (i * 0x80);
        uint32_t ssts = hba[(port_base + 0x28) / 4];
        uint32_t det = ssts & 0xF;

        if (det != 0x3) {
            continue;
        }

        uint32_t sig = hba[(port_base + 0x24) / 4];

        serial_write("AHCI: Port ");
        serial_write_hex(i);
        serial_write(" DET=3 (device attached) SSTS=");
        serial_write_hex(ssts);
        serial_write(" SIG=");
        serial_write_hex(sig);
        serial_write("\r\n");

        if (sig == 0x00000101) {
            ahci_port_init(hba, i);
        }
    }

    ahci_fat32_probe_and_log();
    fat32_probe_root_cluster();
    fat32_list_root_directory();
    fat32_read_file(3, 0x1D);

    uint32_t found_cluster = 0;
    uint32_t found_size = 0;
    int found = fat32_find_file("HELLO   TXT", &found_cluster, &found_size);

    serial_write("FAT32-4A: fat32_find_file(\"HELLO   TXT\") found=");
    serial_write_hex((uint64_t)found);
    serial_write(" cluster=");
    serial_write_hex(found_cluster);
    serial_write(" size=");
    serial_write_hex(found_size);
    serial_write("\r\n");

    if (found) {
        uint8_t *loaded = fat32_load_file(found_cluster, found_size);

        serial_write("FAT32-4A: fat32_load_file() -> ");
        serial_write(loaded ? "sukses" : "GAGAL");
        serial_write("\r\n");

        if (loaded) {
            serial_write("FAT32-4A: buffer isi = \"");
            for (uint32_t i = 0; i < found_size; i++) {
                serial_putc((char)loaded[i]);
            }
            serial_write("\"\r\n");
        }
    }

    // FAT32-4B: find + load PROG.BIN (biner x86-64 nyata, bukan teks),
    // lalu spawn() sungguhan dari buffer yang datang dari disk. Ini
    // pengujian pertama yang membuktikan rantai penuh:
    // disk -> FAT32 -> buffer -> spawn() -> eksekusi user-mode nyata.
    uint32_t prog_cluster = 0;
    uint32_t prog_size = 0;
    int prog_found = fat32_find_file("PROG    BIN", &prog_cluster, &prog_size);

    serial_write("FAT32-4B: fat32_find_file(\"PROG    BIN\") found=");
    serial_write_hex((uint64_t)prog_found);
    serial_write(" cluster=");
    serial_write_hex(prog_cluster);
    serial_write(" size=");
    serial_write_hex(prog_size);
    serial_write("\r\n");

    if (prog_found) {
        uint8_t *prog_buf = fat32_load_file(prog_cluster, prog_size);

        serial_write("FAT32-4B: fat32_load_file(PROG.BIN) -> ");
        serial_write(prog_buf ? "sukses" : "GAGAL");
        serial_write("\r\n");

        if (prog_buf) {
            serial_write("FAT32-4B: memanggil spawn() dengan buffer dari disk\r\n");
            spawn(prog_buf, prog_size);
        }
    }
}

// B3: Limine memetakan HHDM (seluruh RAM fisik, termasuk stack boot) tanpa NX,
// jadi setiap frame heap/stack juga bisa dieksekusi lewat alias HHDM-nya. Pasang
// NX di semua entri PML4 half atas yang ada, kecuali entri yang memuat kernel
// .text. Entri yang dibuat belakangan (heap, MMIO) sudah NX di level daun.
// Dipanggil sebelum PML4 task user di-clone, supaya salinannya ikut NX.
static void nx_harden_higher_half(uint64_t pml4_phys)
{
    if (!g_vmm_nx_ok) {
        return;
    }

    uint64_t *pml4 = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t text_idx = ((uint64_t)&nx_harden_higher_half >> 39) & 0x1FF;
    uint64_t n = 0;

    for (uint64_t i = 256; i < 512; i++) {
        if (i == text_idx || !(pml4[i] & VMM_FLAG_PRESENT)) {
            continue;
        }
        pml4[i] |= VMM_FLAG_NX;
        n++;
    }

    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" : : : "rax", "memory");

    serial_write("NX: entri PML4 half atas diberi NX: ");
    serial_write_hex(n);
    serial_write(" (kecuali index kernel .text ");
    serial_write_hex(text_idx);
    serial_write(")\r\n");
}

static int nx_expect(const char *name, uint64_t pml4_phys, uint64_t vaddr, int want)
{
    int got = vmm_nx_of(pml4_phys, vaddr);

    serial_write("NX: ");
    serial_write(name);
    serial_write(got < 0 ? " tidak terpetakan" : (got ? " nx=1" : " nx=0"));
    serial_write(got == want ? " OK\r\n" : " SALAH\r\n");
    return got == want;
}

static const char g_nx_rodata_probe[] = "nx";

// Dipanggil di kmain setelah heap, MMIO, dan task user dibuat.
static void nx_selftest(uint64_t kernel_pml4, uint64_t user_pml4,
                        uint64_t user_code, uint64_t user_stack)
{
    if (!g_vmm_nx_ok) {
        serial_write("NX: self-test dilewati (NX tidak aktif)\r\n");
        return;
    }

    void *heap_probe = kmalloc(16);
    uint64_t stack_probe = (uint64_t)&heap_probe;
    int ok = 1;

    ok &= nx_expect("kernel .text", kernel_pml4, (uint64_t)&nx_selftest, 0);
    ok &= nx_expect("kernel .rodata", kernel_pml4, (uint64_t)g_nx_rodata_probe, 1);
    ok &= nx_expect("kernel .data", kernel_pml4, (uint64_t)&g_vmm_nx_ok, 1);
    ok &= nx_expect("kernel heap", kernel_pml4, (uint64_t)heap_probe, 1);
    ok &= nx_expect("stack boot", kernel_pml4, stack_probe, 1);
    uint64_t hhdm_frame = pmm_alloc();
    ok &= nx_expect("HHDM (frame RAM)", kernel_pml4, hhdm_frame + hhdm_offset, 1);
    pmm_free(hhdm_frame);
    ok &= nx_expect("MMIO LAPIC", kernel_pml4, LAPIC_VIRT, 1);
    ok &= nx_expect("user code", user_pml4, user_code, 0);
    ok &= nx_expect("user stack", user_pml4, user_stack, 1);

    serial_write(ok ? "NX: self-test PASS\r\n" : "NX: self-test FAIL\r\n");

#ifdef BMAHOS_NXTEST
    // Harus berakhir di #PF dengan error code bit 4 (I/D, instruction fetch).
    serial_write("NX: NXTEST eksekusi dari heap (harus #PF error 0x11)\r\n");
    ((volatile uint8_t *)heap_probe)[0] = 0xC3;
    ((void (*)(void))heap_probe)();
    serial_write("NX: NXTEST GAGAL - eksekusi dari heap tidak diblokir\r\n");
#endif

    kfree(heap_probe);
}
void kmain(void)
{
    serial_init();

    pci_scan_and_log();
    pci_find_devices();
    nx_init();

    gdt_init();

    serial_write("TSS descriptor BEFORE LTR:\r\n");
    print_bmahOS_gdt();
    gdt_load_and_reload();

    tss_load_asm();

    uint64_t tr = tss_read_asm();

    serial_write("TR: ");
    serial_write_hex(tr);
    serial_write("\r\n");

    serial_write("TSS.RSP0: ");
    serial_write_hex(bmahOS_tss.rsp0);
    serial_write("\r\n");

    serial_write("TSS descriptor AFTER LTR:\r\n");
    print_bmahOS_gdt();
    serial_write("\r\n");

    idt_init();
    idt_set_entry(32, (uint64_t)irq32, 0x08, 0x8E);
    idt_set_entry(33, (uint64_t)irq33, 0x08, 0x8E);
    print_idt_entry32();


    print_idt_entry0();

    serial_write("Loading IDT...\r\n");

    idt_load();

    serial_write("Testing int 0x80 syscall gate (SYS_TEST)...\r\n");
    uint64_t syscall_ret;
    __asm__ volatile (
        "movq $0, %%rax\n\t"
        "movq $0x11, %%rdi\n\t"
        "movq $0x22, %%rsi\n\t"
        "movq $0x33, %%rdx\n\t"
        "int $0x80\n\t"
        "movq %%rax, %0"
        : "=r"(syscall_ret)
        :
        : "rax", "rdi", "rsi", "rdx"
    );
    serial_write("Return value dari SYS_TEST: ");
    serial_write_hex(syscall_ret);
    serial_write("\r\n");
    serial_write("Kembali dari int 0x80, kernel masih hidup.\r\n");


    read_idtr();

    serial_write("\r\n");

    serial_write("bmahOS booted!\r\n");
    serial_write("kernel: ");
    serial_write_hex(0xFFFFFFFF80000000ULL);
    serial_write("\r\n");

    read_segment_registers();
    read_gdtr();
    read_gdt_entries();

    read_bmahOS_gdtr();

    if (memmap_request.response != NULL) {
        pmm_init(memmap_request.response);
        serial_write("PMM: initialized\r\n");
        serial_write("PMM usable memory: ");
        serial_write_hex(pmm_usable_memory);
        serial_write("\r\n");

        uint64_t test_frame = pmm_alloc();
        serial_write("PMM allocate test frame: ");
        serial_write_hex(test_frame);
        serial_write("\r\n");

        serial_write("PMM: freeing test frame\r\n");
        pmm_free(test_frame);

        serial_write("PMM: double-free (should be no-op)\r\n");
        pmm_free(test_frame);

        uint64_t test_frame2 = pmm_alloc();
        serial_write("PMM allocate after free: ");
        serial_write_hex(test_frame2);
        serial_write("\r\n");

        if (test_frame2 == test_frame) {
            serial_write("PMM free/realloc test: PASS (frame reused)\r\n");
        } else {
            serial_write("PMM free/realloc test: FAIL (frame not reused)\r\n");
        }
        serial_write("\r\n");
    } else {
        serial_write("PMM: MEMMAP response NULL, skip init\r\n");
    }

    // ===== VMM foundation: HHDM offset + CR3 (PML4 physical addr) =====
    if (hhdm_request.response != NULL) {
        hhdm_offset = hhdm_request.response->offset;
        serial_write("HHDM offset: ");
        serial_write_hex(hhdm_offset);
        serial_write("\r\n");
    } else {
        serial_write("HHDM: response NULL, VMM cannot proceed safely\r\n");
    }

    uint64_t pml4_phys = read_cr3();
    g_current_pml4_phys = pml4_phys;
    g_kernel_pml4_phys = pml4_phys;
    serial_write("CR3 (PML4 physical addr): ");
    serial_write_hex(pml4_phys);
    serial_write("\r\n");

    vmm_dump_pml4(pml4_phys);
    nx_harden_higher_half(pml4_phys);
    uint64_t test_frame_phys = pmm_alloc();
    serial_write("VMM test: allocated physical frame: ");
    serial_write_hex(test_frame_phys);
    serial_write("\r\n");

    uint64_t test_vaddr = 0xFFFF900000000000ULL;
    vmm_map(pml4_phys, test_vaddr, test_frame_phys, VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
    serial_write("VMM test: mapped vaddr ");
    serial_write_hex(test_vaddr);
    serial_write(" -> paddr ");
    serial_write_hex(test_frame_phys);
    serial_write("\r\n");

    volatile uint64_t *test_ptr = (volatile uint64_t *)test_vaddr;
    *test_ptr = 0xDEADBEEFCAFEBABEULL;
    uint64_t readback = *test_ptr;

    serial_write("VMM test: wrote 0xDEADBEEFCAFEBABE, read back: ");
    serial_write_hex(readback);
    serial_write("\r\n");

    if (readback == 0xDEADBEEFCAFEBABEULL) {
        serial_write("VMM test: PASS (write/read via new mapping matches)\r\n");
    } else {
        serial_write("VMM test: FAIL (mismatch)\r\n");
    }
    serial_write("\r\n");
    // vmm_unmap() sudah diverifikasi bekerja (lihat git log/commit
    // sebelumnya): unmap test_vaddr lalu akses ulang berhasil memicu
    // #PF dengan CR2 = test_vaddr persis, membuktikan TLB flush dan
    // page table clearing keduanya benar. Kode pemicu crash-nya
    // dinonaktifkan di sini supaya boot bisa lanjut ke test berikutnya.

    kheap_init(pml4_phys);
    serial_write("kheap: initialized\r\n");

    char *a = (char *)kmalloc(32);
    char *b = (char *)kmalloc(64);
    char *c = (char *)kmalloc(5000);

    serial_write("kmalloc(32)   -> "); serial_write_hex((uint64_t)a); serial_write("\r\n");
    serial_write("kmalloc(64)   -> "); serial_write_hex((uint64_t)b); serial_write("\r\n");
    serial_write("kmalloc(5000) -> "); serial_write_hex((uint64_t)c); serial_write("\r\n");

    for (int i = 0; i < 32; i++) a[i] = 0xAA;
    for (int i = 0; i < 64; i++) b[i] = 0xBB;
    for (int i = 0; i < 5000; i++) c[i] = 0xCC;

    int pass = 1;
    for (int i = 0; i < 32; i++) if ((unsigned char)a[i] != 0xAA) pass = 0;
    for (int i = 0; i < 64; i++) if ((unsigned char)b[i] != 0xBB) pass = 0;
    for (int i = 0; i < 5000; i++) if ((unsigned char)c[i] != 0xCC) pass = 0;

    if (pass) {
        serial_write("kmalloc test: PASS (semua alokasi terisi benar, tidak tumpang tindih)\r\n");
    } else {
        serial_write("kmalloc test: FAIL\r\n");
    }
    serial_write("\r\n");
    char *d = (char *)kmalloc(16);
    serial_write("kmalloc(16) untuk test kfree -> ");
    serial_write_hex((uint64_t)d);
    serial_write("\r\n");

    uint64_t before_free = kheap_current;
    kfree(d);
    uint64_t after_free = kheap_current;

    serial_write("kheap_current sebelum kfree: ");
    serial_write_hex(before_free);
    serial_write("\r\n");
    serial_write("kheap_current sesudah kfree: ");
    serial_write_hex(after_free);
    serial_write("\r\n");

    char *e = (char *)kmalloc(16);
    serial_write("kmalloc(16) lagi setelah kfree -> ");
    serial_write_hex((uint64_t)e);
    serial_write("\r\n");

    if (e == d) {
        serial_write("kfree test: PASS (alamat berhasil di-reuse, LIFO reclaim bekerja)\r\n");
    } else {
        serial_write("kfree test: FAIL (alamat tidak sama, reclaim tidak bekerja)\r\n");
    }
    serial_write("\r\n");

    /* DISABLED (Layer 7 trampoline checkpoint) -- known-good reference,
     * jangan dihapus, diganti task_create_user() + scheduler di bawah.
    // =============================================================
    // User mode entry test (Layer 6)
    //
    // Kode user dummy ditulis manual sebagai raw machine code (bukan
    // lewat compiler C), karena harus berdiri sendiri di halaman
    // terpisah yang di-map dengan VMM_FLAG_USER -- bukan bagian dari
    // .text kernel. Instruksi (encoding x86-64, AT&T-equivalent):
    //
    //   mov eax, 0        B8 00 00 00 00   (SYS_TEST = 0)
    //   mov edi, 0x99     BF 99 00 00 00   (arg0, angka sembarang
    //                                       biar gampang dikenali di log)
    //   mov esi, 0        BE 00 00 00 00   (arg1)
    //   mov edx, 0        BA 00 00 00 00   (arg2)
    //   int 0x80          CD 80
    // loop:
    //   jmp loop          EB FE   (spin loop -- BUKAN hlt!)
    //
    // PENTING: hlt TIDAK BOLEH dipakai di sini -- hlt adalah
    // instruksi privileged (CPL harus 0), jadi kalau dieksekusi di
    // ring 3 akan memicu #GP. Spin loop (jmp ke diri sendiri) tidak
    // privileged, aman dieksekusi di ring manapun, walau boros CPU
    // (busy-wait). Cukup untuk tahap verifikasi ini.
    //
    // Catatan: "mov eax,imm32" (bukan "mov rax,imm64") tetap
    // meng-nolkan 32 bit atas rax -- cukup untuk nilai kecil ini,
    // dan lebih pendek encoding-nya.
    static const uint8_t user_code[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0xBF, 0x99, 0x00, 0x00, 0x00,
        0xBE, 0x00, 0x00, 0x00, 0x00,
        0xBA, 0x00, 0x00, 0x00, 0x00,
        0xCD, 0x80,
        0xEB, 0xFE
    };

    uint64_t user_code_frame = pmm_alloc();
    uint64_t user_stack_frame = pmm_alloc();

    // Checkpoint permission (bagian 1): code read-only, sama seperti
    // task_create_user()/spawn().
    vmm_map(pml4_phys, USER_CODE_VADDR, user_code_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_USER);
    vmm_map(pml4_phys, USER_STACK_VADDR, user_stack_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER | VMM_FLAG_NX);

    // Checkpoint permission (bagian 1) FIX: dulu kode ini menulis
    // lewat alamat virtual USER_CODE_VADDR langsung -- kebetulan tetap
    // berhasil sebelumnya karena PML4 task ini SAMA dengan CR3 aktif
    // saat kmain() menjalankan baris ini (task pertama, sebelum PML4
    // privat dipakai di task manapun). Begitu code page jadi read-only
    // (VMM_FLAG_WRITABLE dihapus di atas), menulis lewat virtual
    // address akan #PF write-to-read-only walau CR3 aktif sama persis
    // -- PTE tidak peduli siapa yang menulis, cuma peduli bit WRITABLE.
    // Fix: tulis lewat HHDM (physical frame + hhdm_offset), pola sama
    // seperti task_create_user()/spawn() sejak Layer 8 checkpoint 3.
    uint8_t *user_code_dst = (uint8_t *)(user_code_frame + hhdm_offset);
    for (uint64_t i = 0; i < sizeof(user_code); i++) {
        user_code_dst[i] = user_code[i];
    }

    serial_write("User mode test: kode user di-copy ke ");
    serial_write_hex(USER_CODE_VADDR);
    serial_write(", stack di ");
    serial_write_hex(USER_STACK_VADDR);
    serial_write("\r\n");
    serial_write("User mode test: melompat ke ring 3 lewat enter_usermode()...\r\n");

    enter_usermode(USER_CODE_VADDR, USER_STACK_VADDR + PMM_PAGE_SIZE);

    serial_write("ERROR: kembali ke kmain() setelah enter_usermode (tidak diharapkan)\r\n");
    serial_write("\r\n");
     */

    #define USER_CODE_VADDR  0x0000000000400000ULL
    #define USER_STACK_VADDR 0x0000000000500000ULL

    serial_write("=== ACPI: mencari MADT untuk info Local APIC/IOAPIC ===\r\n");
    acpi_init();
    serial_write("=== APIC: enable Local APIC + program IOAPIC redirection ===\r\n");
    apic_enable_local_apic(pml4_phys);
    ahci_probe_and_log(pml4_phys);

    e1000_probe_and_log(pml4_phys);
    if (g_e1000_rx_initialized) {
        e1000_send_test_packet();
        e1000_send_arp_request();
    }
    ioapic_map_and_configure(pml4_phys, g_irq0_gsi, 32, 0);
#ifndef BMAHOS_NOIRQ
    e1000_irq_experiment();
#else
    serial_write("NOIRQ: eksperimen interrupt E1000 dilewati (hanya tick-wake)\r\n");
#endif
    serial_write("\r\n");
    pic_remap();
    // pic_unmask_irq(0) SENGAJA TIDAK dipanggil -- IRQ0/GSI2 sekarang
    // ditangani via IOAPIC redirection table (lihat ioapic_map_and_configure
    // di atas), PIC harus tetap mask supaya tidak ada pengiriman ganda.
    pit_init(100); // 100 Hz = tiap 10ms

    __asm__ volatile ("sti");

    // Test hardware-triggered IRQ0 via IOAPIC (BUKAN software int $32).
    // Kalau timer_ticks naik sendiri di sini, migrasi PIC->APIC/IOAPIC
    // berhasil menyelesaikan KNOWN LIMITATION sebelumnya (legacy PIC
    // delivery tidak reliable di VMware+OVMF).
    serial_write("APIC IRQ0 hardware delivery test: menunggu timer_ticks naik otomatis...\r\n");
    uint64_t start_ticks = timer_ticks;
    for (volatile uint64_t i = 0; i < 50000000ULL; i++)
    {
        if (timer_ticks != start_ticks) break;
    }
    serial_write("timer_ticks sebelum busy-wait: ");
    serial_write_hex(start_ticks);
    serial_write(", sesudah: ");
    serial_write_hex(timer_ticks);
    serial_write("\r\n");
    if (timer_ticks != start_ticks)
    {
        serial_write("APIC IRQ0 test: PASS (timer_ticks naik otomatis via hardware IOAPIC delivery)\r\n");
    }
    else
    {
        serial_write("APIC IRQ0 test: FAIL (timer_ticks tidak naik -- hardware delivery masih belum sampai ke CPU)\r\n");
    }
    serial_write("\r\n");

    serial_write("Task scheduling test: membuat task A, B, dan 1 user task...\r\n");
    task_create(&tasks[0], task_a_entry, 4096);
    task_create(&tasks[1], task_b_entry, 4096);
    // Layer 8 checkpoint 3: task user sekarang dapat PML4 PRIVAT
    // sendiri (hasil clone), BUKAN lagi PML4 global -- ini titik
    // perubahan behavior utama Layer 8. vmm_map() di dalam
    // task_create_user() akan otomatis alokasi PDPT/PD/PT baru untuk
    // user_code_vaddr/user_stack_vaddr, karena index PML4 rendah
    // (0x000) SENGAJA kosong di hasil clone.
    uint64_t pml4_task2 = vmm_clone_kernel_pml4(pml4_phys);
    task_create_user(&tasks[2], pml4_task2, USER_CODE_VADDR, USER_STACK_VADDR, 4096,
                      user_task_isolation_test_code, sizeof(user_task_isolation_test_code));

    #define USER_CODE_VADDR2  0x0000000000600000ULL
    #define USER_STACK_VADDR2 0x0000000000700000ULL

    uint64_t pml4_task3 = vmm_clone_kernel_pml4(pml4_phys);
    task_create_user(&tasks[3], pml4_task3, USER_CODE_VADDR2, USER_STACK_VADDR2, 4096,
                      user_task_syswrite_test_code, sizeof(user_task_syswrite_test_code));

    #define USER_CODE_VADDR3  0x0000000000800000ULL
    #define USER_STACK_VADDR3 0x0000000000900000ULL

    uint64_t pml4_task4 = vmm_clone_kernel_pml4(pml4_phys);
    task_create_user(&tasks[4], pml4_task4, USER_CODE_VADDR3, USER_STACK_VADDR3, 4096,
                      user_task_sysexit_test_code, sizeof(user_task_sysexit_test_code));

    task_count = 5;

    // Checkpoint spawn (B) -- uji nyata pertama: buat task ke-6 (slot
    // index 5) LEWAT spawn() generik, BUKAN task_create_user() manual.
    // Image yang dipakai SENGAJA sama dengan task 3
    // (user_task_syswrite_test_code, mencetak "hello\n") -- bukti yang
    // diharapkan: "hello" muncul DUA KALI di boot log (task 3 lama +
    // task 5 baru), dari dua PML4 privat yang BERBEDA (isolasi tetap
    // terjaga), dengan alamat code/stack dari vmm_alloc_vaddr() (bukan
    // konstanta USER_CODE_VADDR* manual seperti task 0-4).
    spawn(user_task_spawn_test_code, sizeof(user_task_spawn_test_code));

    nx_selftest(pml4_phys, tasks[2].pml4_phys, USER_CODE_VADDR, USER_STACK_VADDR);

    serial_write("Task A, B, dan user task dibuat, mulai jalankan lewat scheduler...\r\n");
    serial_write("\r\n");

#ifdef BMAHOS_PROD
    task_count = 0;
    serial_write("PROD: task uji dilewati (task_count direset ke 0)\r\n");
#endif

    if (task_count < MAX_TASKS) {
        task_create(&tasks[task_count], net_task_entry, 8192);
        serial_write("Net-7: net task dibuat di slot ");
        serial_write_hex((uint64_t)task_count);
        serial_write("\r\n");
        task_count++;
    } else {
        serial_write("Net-7: WARNING - slot task penuh, net task tidak dibuat\r\n");
    }

    if (task_count < MAX_TASKS) {
        g_idle_index = task_count;
        task_create(&tasks[task_count], idle_task_entry, 4096);
        serial_write("Idle: task idle dibuat di slot ");
        serial_write_hex((uint64_t)task_count);
        serial_write("\r\n");
        task_count++;
    } else {
        serial_write("Idle: WARNING - slot task penuh, tanpa task idle\r\n");
    }

    static task_t kernel_dummy_task;
    // current_index WAJIB di-set sebelum switch pertama -- kalau
    // timer keburu aktif duluan dan masuk sebelum ini, schedule()
    // akan baca task_count masih 0 dan tidak melakukan apa-apa (aman,
    // guard menangani ini), tapi index harus tetap benar sebelum
    // context_switch pertama terjadi.
    current_index = 0;
    // scheduler_started WAJIB true SEBELUM context_switch pertama --
    // sejak titik ini, RSP yang berjalan adalah RSP task_a yang valid
    // (hasil task_create()), BUKAN lagi stack kmain(). Kalau timer
    // masuk setelah ini, schedule() boleh mulai menyimpan/memuat
    // context task dengan aman.
    scheduler_started = true;
    context_switch(&kernel_dummy_task.rsp, tasks[0].rsp, tasks[0].pml4_phys);

    serial_write("ERROR: kembali ke kmain() setelah task selesai (tidak diharapkan)\r\n");
    serial_write("ABOUT TO TRIGGER #BP\r\n");
    trigger_breakpoint();
    serial_write("ERROR: #BP DID NOT OCCUR\r\n");

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

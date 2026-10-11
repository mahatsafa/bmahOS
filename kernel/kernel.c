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
static uint64_t g_current_pml4_phys = 0;
// Checkpoint spawn: PML4 kernel ASLI (hasil read_cr3() sekali di awal
// boot), TIDAK PERNAH berubah setelah diisi -- beda dari
// g_current_pml4_phys yang berubah tiap schedule() mengikuti task
// aktif. Ini sumber kebenaran stabil untuk spawn()/vmm_clone_kernel_pml4()
// supaya tidak perlu terima kernel_pml4_phys sebagai parameter caller.
static uint64_t g_kernel_pml4_phys = 0;

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
static void schedule(void);
static void task_exit(void);
static void task_sleep(uint64_t ticks);
static void task_wait_for(size_t target_index);
// Forward declaration struct -- definisi lengkap ada dekat task_t,
// tapi tipenya perlu dikenal compiler di sini untuk sem_wait/sem_post.
typedef struct semaphore semaphore_t;
static void sem_wait(semaphore_t *sem);
static void sem_post(semaphore_t *sem);



// ---- Net-12: ring buffer log (disaring: tanpa baris schedule()) ----
#define LOG_RING_SIZE 8192
#define LOG_LINE_MAX  160

static char g_log_ring[LOG_RING_SIZE];
static uint32_t g_log_head = 0;
static uint64_t g_log_total = 0;
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



extern void enter_usermode(uint64_t entry_vaddr, uint64_t user_stack_top);

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

extern void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp, uint64_t new_pml4_phys);

// TASK_READY: task valid, boleh dipilih scheduler.
// TASK_DEAD: task sudah selesai, scheduler WAJIB melewatinya --
// task menandai dirinya sendiri DEAD di akhir entry function-nya
// (lihat task_a_entry()/task_b_entry()).
typedef enum {
    TASK_READY,
    TASK_DEAD,
    TASK_SLEEPING,
    TASK_BLOCKED,
} task_status_t;

// Semaphore sederhana: counter + "wake maksimal 1 waiter per post"
// (lihat sem_post()). Tidak ada waiter queue eksplisit -- sem_post()
// scan tasks[] cari SATU task BLOCKED pada semaphore ini, konsisten
// dengan gaya schedule() yang sudah ada (linear scan), bukan struktur
// antrian terpisah. Semantiknya tetap sama: 1 post membangunkan
// maksimal 1 task.
typedef struct semaphore {
    int count;
} semaphore_t;

typedef struct {
    uint64_t rsp;
    task_status_t status;
    uint64_t wake_at_tick;
    size_t waiting_for;
    // NULL kalau task tidak sedang menunggu semaphore manapun.
    // BLOCKED karena task_wait_for() punya waiting_for_sem == NULL;
    // BLOCKED karena sem_wait() punya waiting_for_sem != NULL.
    semaphore_t *waiting_for_sem;
    // true kalau task ini jalan di ring 3 (user task). Scheduler
    // belum membedakan perlakuan berdasarkan field ini -- baru
    // dipakai untuk penandaan; integrasi penuh (context_switch vs
    // enter_usermode saat first-run) menyusul.
    bool is_user_task;
    // Top of this task's kernel stack -- disalin ke bmahOS_tss.rsp0
    // oleh schedule() setiap kali task ini yang akan berjalan. Wajib
    // per-task supaya banyak user task preemptive tidak berebut satu
    // kernel stack global saat masing-masing trap ke ring 0.
    uint64_t rsp0;
    // Dipakai HANYA oleh user_task_trampoline() saat task user ini
    // pertama kali dijalankan lewat context_switch(). user_stack_top
    // sudah dihitung sebagai base+PMM_PAGE_SIZE (siap pakai langsung
    // sebagai RSP awal ring 3, tidak perlu dihitung ulang).
    uint64_t user_entry;
    uint64_t user_stack_top;
    // Layer 8 checkpoint 1 (dormant): PML4 physical address milik
    // task ini. Task kernel (task_create()) akan diisi dengan PML4
    // global (read_cr3() awal) -- TIDAK PUNYA address space sendiri,
    // sengaja tetap share. Task user (task_create_user()) akan diisi
    // hasil vmm_clone_kernel_pml4() -- PML4 privat per task. BELUM
    // dipakai schedule()/context_switch() di checkpoint ini -- field
    // ini ada tapi tidak mengubah behavior apa pun sampai checkpoint
    // berikutnya.
    uint64_t pml4_phys;
    // Checkpoint allocator: alamat virtual berikutnya yang bebas
    // dipakai di address space task ini (bump allocator, TIDAK ADA
    // free/reclaim). Hanya bermakna untuk user task -- task kernel
    // tidak pernah exec() sehingga field ini tidak diinisialisasi
    // untuk task_create() biasa. Nilai awal diisi USER_VADDR_ALLOC_BASE
    // oleh task_create_user().
    uint64_t next_free_vaddr;
} task_t;

// Siapkan stack awal task baru supaya context_switch() bisa
// "melompat" ke entry_function pertama kali task ini dijalankan.
// Stack direkayasa supaya urutan pop di context_switch() (rax..r15,
// 15 register, matching irq_common_stub) lalu ret, membuat CPU
// seolah baru masuk ke entry_function.
static void task_create(task_t *task, void (*entry_function)(void), uint64_t stack_size)
{
    uint64_t stack_base = (uint64_t)kmalloc(stack_size);
    uint64_t stack_top = stack_base + stack_size;

    // Stack tumbuh ke bawah, jadi kita mulai dari alamat tinggi.
    uint64_t *sp = (uint64_t *)stack_top;

    // Return address palsu untuk RET di context_switch().
    sp--;
    *sp = (uint64_t)entry_function;

    // 15 register, urutan sama seperti urutan PUSH di context_switch()/
    // irq_common_stub (rax..r15), semua nol (task baru, belum ada state).
    sp--; *sp = 0; // rax
    sp--; *sp = 0; // rbx
    sp--; *sp = 0; // rcx
    sp--; *sp = 0; // rdx
    sp--; *sp = 0; // rsi
    sp--; *sp = 0; // rdi
    sp--; *sp = 0; // rbp
    sp--; *sp = 0; // r8
    sp--; *sp = 0; // r9
    sp--; *sp = 0; // r10
    sp--; *sp = 0; // r11
    sp--; *sp = 0; // r12
    sp--; *sp = 0; // r13
    sp--; *sp = 0; // r14
    sp--; *sp = 0; // r15

    task->rsp = (uint64_t)sp;
    task->status = TASK_READY;
    task->waiting_for_sem = 0;
    task->is_user_task = false;
    task->rsp0 = stack_top;
    // Layer 8 checkpoint 2: task kernel SENGAJA share PML4 global --
    // tidak ada manfaat isolasi address space untuk task yang tidak
    // pernah masuk ring 3. g_current_pml4_phys sudah diisi di kmain()
    // sebelum task_create() pertama dipanggil.
    task->pml4_phys = g_current_pml4_phys;
}
#define MAX_TASKS 8

static task_t tasks[MAX_TASKS];
static size_t task_count = 0;
// Indeks task idle di tasks[]; (size_t)-1 = belum ada. Tidak ikut round-robin:
// hanya dipilih scheduler kalau tidak ada task lain yang READY.
static size_t g_idle_index = (size_t)-1;
static volatile bool scheduler_started = false;
static size_t current_index = 0;

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

// Dipanggil via ret dari context_switch() -- BUKAN dipanggil biasa,
// jadi tidak boleh punya parameter (harus cocok dengan konvensi
// "entry_function" yang dipakai task_create()). Baca entry/stack
// milik task yang SEDANG aktif (current_index sudah diupdate oleh
// schedule() SEBELUM context_switch() dipanggil), lalu masuk ring 3
// lewat enter_usermode(). Fungsi ini tidak pernah return (persis
// seperti enter_usermode() -- ring 3 tidak akan ret ke sini).
static void user_task_trampoline(void)
{
    serial_write("user_task_trampoline(): masuk (masih ring 0), current_index=");
    serial_write_hex(current_index);
    serial_write("\r\n");

    uint64_t entry = tasks[current_index].user_entry;
    uint64_t stack_top = tasks[current_index].user_stack_top;

    serial_write("user_task_trampoline(): memanggil enter_usermode()...\r\n");
    enter_usermode(entry, stack_top);
}

// Varian task_create() untuk task user. Beda dari task_create():
// - entry_function yang dirig ke stack SELALU user_task_trampoline,
//   bukan parameter caller (ring 0 -> ring 3 harus lewat iretq,
//   context_switch() biasa (ret) tidak bisa melakukan itu langsung).
// - Butuh pml4_phys eksplisit sebagai parameter karena pml4_phys
//   di kmain() adalah variabel LOKAL (dari read_cr3()), bukan global.
// - Mengalokasikan DUA jenis memori terpisah: kernel_stack (buat
//   task->rsp/rsp0, dipakai saat trap balik ke ring 0) dan halaman
//   user code+stack (VMM_FLAG_USER, dipakai kode ring 3).
// code/code_len digeneralisasi (Layer 7 lanjutan) -- sebelumnya
// task_create_user() hardcode user_task_dummy_code[] di dalam badan
// fungsi. Sekarang pemanggil (kmain() atau nanti syscall exec/spawn)
// yang menentukan kode apa yang dijalankan di ring 3.
//
// code_len WAJIB <= PMM_PAGE_SIZE (4096) -- kita cuma alokasikan
// SATU frame fisik untuk halaman kode. Kalau code_len lebih besar,
// byte yang meluber akan menimpa memori di luar frame yang dialokasikan
// (bug diam-diam, tidak akan #PF karena masih di halaman yang sama
// index-nya secara virtual tapi menabrak data lain di physical
// memory kalau alignment tidak pas -- makanya DICEGAH di awal, bukan
// dibiarkan lalu diharapkan #PF menangkapnya).
// Checkpoint allocator: bump allocator sederhana untuk alamat
// virtual per-task. TIDAK PERNAH membebaskan alamat (tidak ada
// free-list/coalescing) -- cukup untuk exec() yang mengalokasikan
// code/data/stack sekali di awal hidup task, lalu dibuang total saat
// task exit. Bukan konstanta arsitektural MMU -- ini murni policy
// allocator saat ini, aman direvisi naik kalau kebutuhan berubah.
#define USER_VADDR_ALLOC_BASE 0x0000000000400000ULL
#define USER_VADDR_LIMIT      0x0000000010000000ULL  // batas eksklusif, 256 MiB

// Alokasikan `size` byte alamat virtual bebas di address space milik
// `task`, page-aligned ke atas. Mengembalikan base alamat, atau 0
// kalau gagal (overflow aritmetika ATAU melewati USER_VADDR_LIMIT).
// TIDAK melakukan mapping fisik apa pun -- itu tetap tanggung jawab
// vmm_map() terpisah, dipanggil caller setelah alamat ini didapat.
static uint64_t vmm_alloc_vaddr(task_t *task, size_t size)
{
    uint64_t aligned_size = (size + (PMM_PAGE_SIZE - 1)) & ~(PMM_PAGE_SIZE - 1);

    // Overflow check SEBELUM penjumlahan -- jangan percaya
    // (next_free_vaddr + aligned_size) > LIMIT kalau penjumlahannya
    // sendiri bisa wraparound duluan.
    if (aligned_size > USER_VADDR_LIMIT - task->next_free_vaddr) {
        serial_write("vmm_alloc_vaddr(): USER_VADDR_LIMIT exceeded (next_free=");
        serial_write_hex(task->next_free_vaddr);
        serial_write(", requested=");
        serial_write_hex(aligned_size);
        serial_write(")\r\n");
        return 0;
    }

    uint64_t base = task->next_free_vaddr;
    task->next_free_vaddr += aligned_size;

    return base;
}

static void task_create_user(
    task_t *task,
    uint64_t pml4_phys,
    uint64_t user_code_vaddr,
    uint64_t user_stack_vaddr,
    uint64_t kernel_stack_size,
    const uint8_t *code,
    size_t code_len
)
{
    if (code_len > PMM_PAGE_SIZE) {
        serial_write("task_create_user(): FATAL -- code_len melebihi 1 halaman (");
        serial_write_hex(code_len);
        serial_write(" > ");
        serial_write_hex(PMM_PAGE_SIZE);
        serial_write("), dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    // --- Kernel stack task ini (dipakai context_switch() & RSP0) ---
    uint64_t kstack_base = (uint64_t)kmalloc(kernel_stack_size);
    uint64_t kstack_top = kstack_base + kernel_stack_size;

    uint64_t *sp = (uint64_t *)kstack_top;

    // Return address palsu untuk RET di context_switch() -- selalu
    // trampoline, task user tidak pernah "entry_function" langsung.
    sp--;
    *sp = (uint64_t)user_task_trampoline;

    // 15 register kosong, sama seperti task_create().
    for (int i = 0; i < 15; i++) {
        sp--;
        *sp = 0;
    }

    task->rsp = (uint64_t)sp;
    task->rsp0 = kstack_top;
    task->status = TASK_READY;
    task->waiting_for_sem = 0;
    task->is_user_task = true;
    // Layer 8 checkpoint 2: simpan pml4_phys yang DIOPER pemanggil.
    // Checkpoint ini pemanggil masih selalu mengoper PML4 global
    // (identik task kernel) -- isolasi sungguhan (PML4 privat per
    // user task) baru aktif di checkpoint 3.
    task->pml4_phys = pml4_phys;
    // Checkpoint allocator: mulai dari basis alokasi -- dormant,
    // belum ada pemanggil vmm_alloc_vaddr() manapun di checkpoint
    // ini, task_create_user() masih menerima user_code_vaddr/
    // user_stack_vaddr eksplisit dari caller seperti sebelumnya.
    task->next_free_vaddr = USER_VADDR_ALLOC_BASE;

    // --- Halaman user code + stack (ring 3, VMM_FLAG_USER) ---
    uint64_t user_code_frame = pmm_alloc();
    uint64_t user_stack_frame = pmm_alloc();

    // Checkpoint permission (bagian 1): code TIDAK LAGI writable --
    // WRITABLE dihapus dari mapping code, HANYA stack yang tetap
    // writable. Copy image tetap berhasil karena dilakukan lewat HHDM
    // (physical frame langsung), bukan lewat PTE user code_vaddr ini.
    // Belum ada NX/XD (EFER.NXE belum pernah diset di boot sequence
    // bmahOS) -- jadi stack MASIH bisa dieksekusi sebagai kode kalau
    // task melompat ke sana; itu checkpoint permission bagian 2
    // terpisah, butuh setup MSR IA32_EFER dulu.
    vmm_map(pml4_phys, user_code_vaddr, user_code_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_USER);
    vmm_map(pml4_phys, user_stack_vaddr, user_stack_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER | VMM_FLAG_NX);

    // Layer 8 checkpoint 3 FIX: TIDAK BOLEH menulis lewat alamat
    // virtual user_code_vaddr di sini -- PML4 yang baru saja dipetakan
    // (pml4_phys milik task ini, hasil vmm_clone_kernel_pml4()) BELUM
    // TENTU sama dengan CR3 yang SEDANG AKTIF saat task_create_user()
    // dipanggil (kmain() masih jalan dengan PML4 kernel lama, task ini
    // belum pernah di-context-switch). Menulis ke user_code_vaddr lewat
    // pointer biasa memakai page table AKTIF SEKARANG, yang tidak
    // punya mapping tersebut -- menyebabkan #PF not-present (terbukti
    // nyata: CR2=user_code_vaddr, error code=write). Solusi: tulis
    // lewat HHDM (alamat fisik + hhdm_offset), yang SELALU bisa
    // diakses dari address space manapun yang sedang aktif, karena
    // HHDM adalah salah satu entri kernel-shared yang ikut di-copy
    // vmm_clone_kernel_pml4() (VMM_SHARED_PML4_IDX_HHDM).
    uint8_t *user_code_dst = (uint8_t *)(user_code_frame + hhdm_offset);
    for (size_t i = 0; i < code_len; i++) {
        user_code_dst[i] = code[i];
    }

    task->user_entry = user_code_vaddr;
    task->user_stack_top = user_stack_vaddr + PMM_PAGE_SIZE;

    serial_write("task_create_user(): kode (");
    serial_write_hex(code_len);
    serial_write(" byte) di ");
    serial_write_hex(user_code_vaddr);
    serial_write(", stack di ");
    serial_write_hex(user_stack_vaddr);
    serial_write(", rsp0 di ");
    serial_write_hex(kstack_top);
    serial_write("\r\n");
}

// Checkpoint spawn (B): primitive generik pertama untuk membuat task
// user baru dari image di memori -- MENGGANTIKAN pola hardcoded
// task_create_user(&tasks[N], pml4_taskN, USER_CODE_VADDRn, ...) yang
// dipakai kmain() sejauh ini. Perbedaan utama dari task_create_user():
//   - Tidak menerima pml4_phys dari caller -- selalu clone dari
//     g_kernel_pml4_phys (source of truth stabil, checkpoint A).
//   - Tidak menerima alamat virtual dari caller -- selalu dapat dari
//     vmm_alloc_vaddr() (checkpoint allocator), bukan konstanta
//     USER_CODE_VADDR/USER_STACK_VADDR manual.
//   - Slot task diambil dari tasks[task_count++] -- TIDAK ADA reuse
//     slot DEAD (utang teknis eksplisit, ditunda).
// SENGAJA BELUM ditangani di checkpoint ini (utang teknis eksplisit):
//   - Code/data/stack permission masih writable semua (tidak ada
//     read-only code / NX) -- checkpoint permission terpisah nanti.
//   - Rollback kalau alokasi gagal di tengah jalan -- FATAL+halt saja,
//     tidak membebaskan frame yang sudah terlanjur dialokasikan.
//   - exec() (mengganti address space task yang sedang berjalan) --
//     tidak dibahas sama sekali, spawn() selalu bikin task BARU.
// Batasan yang dipertahankan dari task_create_user(): image_len tidak
// boleh melebihi 1 halaman (code cuma dialokasikan 1 frame fisik) --
// bukan generalisasi ke image besar, itu di luar lingkup checkpoint
// "spawn generik pertama".
static task_t *spawn(const uint8_t *image, size_t image_len)
{
    if (task_count >= MAX_TASKS) {
        serial_write("spawn(): FATAL -- MAX_TASKS tercapai (");
        serial_write_hex(task_count);
        serial_write("), dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    if (image_len > PMM_PAGE_SIZE) {
        serial_write("spawn(): FATAL -- image_len melebihi 1 halaman (");
        serial_write_hex(image_len);
        serial_write(" > ");
        serial_write_hex(PMM_PAGE_SIZE);
        serial_write("), dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    task_t *task = &tasks[task_count];

    uint64_t pml4_phys = vmm_clone_kernel_pml4(g_kernel_pml4_phys);

    // next_free_vaddr HARUS di-set sebelum vmm_alloc_vaddr() dipanggil
    // -- fungsi itu cuma membaca+memajukan field ini, tidak pernah
    // menginisialisasinya sendiri.
    task->next_free_vaddr = USER_VADDR_ALLOC_BASE;

    uint64_t code_vaddr = vmm_alloc_vaddr(task, image_len);
    if (code_vaddr == 0) {
        serial_write("spawn(): FATAL -- vmm_alloc_vaddr() gagal untuk code, dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    uint64_t stack_vaddr = vmm_alloc_vaddr(task, PMM_PAGE_SIZE);
    if (stack_vaddr == 0) {
        serial_write("spawn(): FATAL -- vmm_alloc_vaddr() gagal untuk stack, dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    // --- Kernel stack task ini (dipakai context_switch() & RSP0) ---
    // Ukuran sama seperti seluruh call site task_create_user() yang
    // ada sekarang (4096) -- bukan angka baru.
    uint64_t kstack_base = (uint64_t)kmalloc(4096);
    uint64_t kstack_top = kstack_base + 4096;

    uint64_t *sp = (uint64_t *)kstack_top;

    sp--;
    *sp = (uint64_t)user_task_trampoline;

    for (int i = 0; i < 15; i++) {
        sp--;
        *sp = 0;
    }

    task->rsp = (uint64_t)sp;
    task->rsp0 = kstack_top;
    task->status = TASK_READY;
    task->waiting_for_sem = 0;
    task->is_user_task = true;
    task->pml4_phys = pml4_phys;

    // --- Halaman code + stack (ring 3, VMM_FLAG_USER) ---
    uint64_t code_frame = pmm_alloc();
    uint64_t stack_frame = pmm_alloc();

    // Checkpoint permission (bagian 1): code read-only, sama seperti
    // task_create_user() -- lihat komentar di sana untuk detail.
    vmm_map(pml4_phys, code_vaddr, code_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_USER);
    vmm_map(pml4_phys, stack_vaddr, stack_frame,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER | VMM_FLAG_NX);

    // Copy image via HHDM, BUKAN lewat code_vaddr -- alasan identik
    // dengan fix Layer 8 checkpoint 3: pml4_phys milik task ini belum
    // tentu sama dengan CR3 aktif saat spawn() dipanggil.
    uint8_t *code_dst = (uint8_t *)(code_frame + hhdm_offset);
    for (size_t i = 0; i < image_len; i++) {
        code_dst[i] = image[i];
    }

    task->user_entry = code_vaddr;
    task->user_stack_top = stack_vaddr + PMM_PAGE_SIZE;

    serial_write("spawn(): task baru di slot ");
    serial_write_hex(task_count);
    serial_write(", kode (");
    serial_write_hex(image_len);
    serial_write(" byte) di ");
    serial_write_hex(code_vaddr);
    serial_write(", stack di ");
    serial_write_hex(stack_vaddr);
    serial_write(", rsp0 di ");
    serial_write_hex(kstack_top);
    serial_write("\r\n");

    task_count++;

    return task;
}

// Semaphore uji: count=1 -- simulasi 1 "slot" critical section yang
// diperebutkan Task A dan B (lihat task_a_entry()/task_b_entry()).
static semaphore_t test_sem = { .count = 1 };

// Round-robin generik untuk N task (N <= MAX_TASKS). current_index
// adalah SATU-SATUNYA source of truth untuk "task mana yang sedang
// jalan" -- kalau butuh pointer ke task aktif, turunkan dari index
// ini (&tasks[current_index]), jangan simpan pointer terpisah supaya
// tidak ada dua state yang bisa saling tidak sinkron.
// Dipanggil dari irq_handler() saat timer (IRQ0) masuk -- ini yang
// membuat scheduling PREEMPTIVE: task tidak lagi manggil
// context_switch() sendiri, timer dari luar yang memaksa ganti giliran.
static void schedule(void)
{
    // Guard ganda: (1) belum ada task terdaftar, ATAU (2) scheduler
    // belum pernah benar-benar diserahkan alih dari kmain() ke task
    // pertama. Tanpa guard (2), timer yang masuk di antara
    // task_count di-set dan context_switch() pertama benar-benar
    // terjadi akan salah kira RSP kmain() saat itu adalah RSP task
    // aktif, lalu menimpanya ke tasks[current_index].rsp -- merusak
    // context task yang sebenarnya belum pernah jalan sama sekali.
    if (task_count == 0 || !scheduler_started) {
        return;
    }

    // Sebelum mencari task berikutnya: bangunkan semua task SLEEPING
    // yang waktu bangunnya sudah tiba. Scheduler yang bertanggung
    // jawab menentukan "siapa yang runnable", jadi pengecekan ini
    // wajar dilakukan di sini, bukan di irq_handler() terpisah.
    for (size_t i = 0; i < task_count; i++) {
        if (tasks[i].status == TASK_SLEEPING &&
            timer_ticks >= tasks[i].wake_at_tick) {
            tasks[i].status = TASK_READY;
        }
    }

    // Sama seperti pengecekan SLEEPING di atas: bangunkan task yang
    // BLOCKED kalau task yang dia tunggu (waiting_for) sudah DEAD.
    // Scheduler pasif mengecek kondisi eksternal, bukan task_exit()
    // yang aktif mencari "siapa saja yang menungguku" (itu butuh
    // reverse-lookup per-task yang lebih kompleks).
    for (size_t i = 0; i < task_count; i++) {
        // waiting_for_sem == 0 WAJIB dicek -- ini blok KHUSUS untuk
        // task_wait_for() (menunggu TASK lain mati). Task yang BLOCKED
        // via sem_wait() (waiting_for_sem != NULL) TIDAK BOLEH kena
        // logika ini -- field waiting_for milik mereka tidak valid/
        // relevan (bisa berisi nilai basi dari task_wait_for()
        // sebelumnya), dan mereka cuma boleh dibangunkan oleh
        // sem_post() (lihat sem_post()), bukan oleh scan generik ini.
        if (tasks[i].status == TASK_BLOCKED &&
            tasks[i].waiting_for_sem == 0 &&
            tasks[tasks[i].waiting_for].status == TASK_DEAD) {
            tasks[i].status = TASK_READY;
        }
    }

    // Bounded scan: cari task READY berikutnya, MAKSIMAL task_count
    // kali percobaan. Ini WAJIB dibatasi -- kalau semua task DEAD,
    // loop tanpa batas akan menggantung scheduler selamanya di dalam
    // interrupt context (fatal, karena timer berikutnya pun tidak
    // akan pernah bisa masuk lagi).
    size_t next_index = current_index;
    bool found = false;

    for (size_t attempt = 0; attempt < task_count; attempt++) {
        next_index = (next_index + 1) % task_count;
        if (tasks[next_index].status == TASK_READY &&
            next_index != g_idle_index) {
            found = true;
            break;
        }
    }

    // Semua task DEAD (atau tidak ada yang READY) -- tidak ada yang
    // bisa dijalankan, jangan context switch ke mana pun.
    // Kalau ada task idle, pindah ke sana (kecuali sudah di idle).
    if (!found) {
        if (g_idle_index == (size_t)-1 || current_index == g_idle_index) {
            return;
        }
        next_index = g_idle_index;
    }

    // Bug tersembunyi yang baru terungkap lewat task_sleep(): bounded
    // scan bisa saja "menemukan" task yang SEDANG BERJALAN SEKARANG
    // (current_index) sebagai satu-satunya TASK_READY, kalau semua
    // task lain sedang SLEEPING/DEAD. Scheduler tidak membedakan
    // "sedang jalan" dari "berstatus READY" -- keduanya sama saja di
    // field status. Tanpa guard ini, context_switch(&tasks[i].rsp,
    // tasks[i].rsp) akan menyimpan dan memuat RSP dari alamat yang
    // SAMA, tapi nilai new_rsp sudah "dibekukan" SEBELUM push register
    // terjadi -- hasilnya RSP dimuat dari titik yang salah, ret
    // melompat ke alamat sampah (terbukti dari crash RIP=0x0 #PF saat
    // Task A sleep dan Task B jadi satu-satunya TASK_READY).
    if (next_index == current_index) {
        return;
    }

    size_t prev_index = current_index;
    current_index = next_index;

    // Swap TSS.RSP0 ke kernel stack task berikutnya SEBELUM context
    // switch -- kalau task ini (nanti) user task dan trap ke ring 0
    // via syscall/interrupt, CPU harus menemukan RSP0 milik task
    // yang benar, bukan sisa milik task sebelumnya.
    bmahOS_tss.rsp0 = tasks[next_index].rsp0;

    // Layer 8 checkpoint 2: g_current_pml4_phys MENCERMINKAN task
    // aktif (cache/mirror), BUKAN source of truth kedua --
    // tasks[i].pml4_phys tetap satu-satunya tempat state PML4
    // per-task disimpan. Diupdate di sini, SEBELUM context_switch(),
    // supaya syscall (is_valid_user_ptr) yang trap segera setelah
    // switch selalu baca PML4 task yang BENAR sedang berjalan.
    g_current_pml4_phys = tasks[next_index].pml4_phys;

    // Log HANYA untuk switch yang melibatkan user task -- kalau
    // dicetak untuk SEMUA switch (termasuk A<->B biasa), log akan
    // banjir karena schedule() dipanggil tiap tick timer. Ini
    // pembuktian langsung bahwa TSS.RSP0 benar-benar berubah nilai
    // setiap kali scheduler masuk/keluar dari task user, BUKAN
    // sekadar diasumsikan dari kode.
    // B4b: hanya 16 switch pertama. Dulu dicetak di setiap switch task user
    // (~400 baris/detik di build dev), melebihi kapasitas UART, sehingga semua
    // task tertahan di serial_putc() dengan interrupt mati.
    static uint32_t sched_log_left = 16;

    if ((tasks[next_index].is_user_task || tasks[prev_index].is_user_task) &&
        sched_log_left > 0) {
        sched_log_left--;
        serial_write("schedule(): switch prev_idx=");
        serial_write_hex(prev_index);
        serial_write(" next_idx=");
        serial_write_hex(next_index);
        serial_write(" TSS.RSP0=");
        serial_write_hex(bmahOS_tss.rsp0);
        serial_write("\r\n");
    }

    context_switch(&tasks[prev_index].rsp, tasks[next_index].rsp, tasks[next_index].pml4_phys);
}

// Dipanggil task untuk mengakhiri dirinya sendiri secara permanen.
// BEDA dari irq_handler() yang manggil schedule() dari INTERRUPT
// context (otomatis cli lewat gate) -- task_exit() dipanggil dari
// NORMAL task context, di mana interrupt masih aktif (task sti di
// awal hidupnya). Tanpa irq_save()/irq_restore() di sini, timer bisa
// masuk DI TENGAH badan schedule() (yang tidak reentrant -- lihat
// komentar di schedule()), menyebabkan dua instance schedule() saling
// menimpa state satu sama lain.
static void task_exit(void)
{
    uint64_t flags = irq_save();

    tasks[current_index].status = TASK_DEAD;
    schedule();

    // Kalau eksekusi balik ke titik ini, schedule() tidak menemukan
    // task READY lain (found == false) -- task ini satu-satunya yang
    // masih hidup. Tidak ada gunanya lanjut apa pun, restore interrupt
    // state lalu hlt selamanya.
    irq_restore(flags);
    for (;;) {
        __asm__ volatile ("hlt");
    }
}

// Task minta "tidur" selama ticks timer, lalu otomatis dibangunkan
// scheduler sendiri (lihat pengecekan wake_at_tick di schedule()) --
// task lain TIDAK perlu tahu-menahu untuk membangunkannya.
static void task_sleep(uint64_t ticks)
{
    // irq_save() WAJIB -- task_sleep() dipanggil dari NORMAL task
    // context (interrupt aktif), bukan dari irq_handler(). Tanpa ini,
    // timer bisa masuk di tengah kita menulis wake_at_tick/status,
    // menyebabkan schedule() (yang tidak reentrant) terpanggil dua
    // kali bertumpuk.
    uint64_t flags = irq_save();

    tasks[current_index].wake_at_tick = timer_ticks + ticks;
    tasks[current_index].status = TASK_SLEEPING;

    schedule();

    // Baris ini baru benar-benar dieksekusi ketika task ini nanti
    // dibangunkan scheduler dan mendapat giliran CPU lagi -- BUKAN
    // langsung setelah schedule() dipanggil di atas. Sama seperti
    // task_exit(): jangan mengandalkan kode setelah schedule() untuk
    // jalan seketika kalau context switch berhasil terjadi.
    irq_restore(flags);
}

// Task minta "diblokir" sampai task lain (target_index) menjadi
// TASK_DEAD. BEDA dari task_sleep() -- syarat bangun bukan waktu,
// tapi status task lain (event-based blocking, bukan time-based).
static void task_wait_for(size_t target_index)
{
    uint64_t flags = irq_save();

    // Guard dasar: index invalid atau menunggu diri sendiri (self-wait
    // = deadlock instan untuk 1 task). Deadlock circular antar 2+
    // task (A wait B, B wait A) BELUM ditangani di primitive ini --
    // dicatat sebagai known limitation, bukan diabaikan begitu saja.
    if (target_index >= task_count || target_index == current_index) {
        irq_restore(flags);
        return;
    }

    tasks[current_index].waiting_for = target_index;
    tasks[current_index].status = TASK_BLOCKED;

    schedule();

    // Sama seperti task_sleep(): baris ini baru benar-benar
    // dieksekusi ketika task ini dibangunkan (target sudah DEAD) dan
    // mendapat giliran CPU lagi.
    irq_restore(flags);
}

// Minta akses semaphore. Kalau count > 0, langsung ambil (count--)
// dan lanjut TANPA blocking. Kalau count == 0, task BLOCKED sampai
// sem_post() membangunkannya -- TAPI wake TIDAK SAMA DENGAN acquire:
// begitu dibangunkan, task WAJIB mengecek ulang count (loop), karena
// bisa saja task lain "menyerobot" slot itu duluan sebelum giliran
// CPU sampai ke task ini (meski di desain sem_post() sekarang -- wake
// maksimal 1 waiter per post -- skenario itu semestinya tidak
// terjadi untuk kasus sederhana; loop tetap dipertahankan sebagai
// praktik aman standar terhadap spurious wakeup).
static void sem_wait(semaphore_t *sem)
{
    uint64_t flags = irq_save();

    while (sem->count <= 0) {
        tasks[current_index].waiting_for_sem = sem;
        tasks[current_index].status = TASK_BLOCKED;
        schedule();
        // Baris ini baru jalan lagi ketika sem_post() membangunkan
        // task ini DAN scheduler benar-benar memberi giliran CPU.
    }

    sem->count--;
    tasks[current_index].waiting_for_sem = 0;

    irq_restore(flags);
}

// Lepas akses semaphore. Membangunkan MAKSIMAL SATU task yang BLOCKED
// menunggu semaphore ini (linear scan, bukan waiter queue eksplisit --
// konsisten dengan gaya schedule() yang sudah ada). Kalau tidak ada
// yang menunggu, count++ saja (slot tersedia untuk sem_wait() di
// masa depan).
static void sem_post(semaphore_t *sem)
{
    uint64_t flags = irq_save();

    // count++ SELALU terjadi, ada atau tidak ada yang dibangunkan --
    // "melepas 1 slot" itu maknanya. Kalau ada task yang dibangunkan,
    // dia akan lolos pengecekan while(count <= 0) miliknya begitu
    // giliran CPU sampai ke dia. Kalau tidak ada yang menunggu, count
    // yang naik ini menunggu sem_wait() berikutnya datang.
    sem->count++;

    for (size_t i = 0; i < task_count; i++) {
        if (tasks[i].status == TASK_BLOCKED &&
            tasks[i].waiting_for_sem == sem) {
            tasks[i].status = TASK_READY;
            break;
        }
    }

    irq_restore(flags);
}

static void task_a_entry(void)
{
    // Task baru dijalankan lewat context_switch() (ret-based), TIDAK
    // pernah lewat iretq -- jadi RFLAGS.IF tidak otomatis di-restore.
    // Kalau task ini di-switch-in saat IF sedang 0 (misal dari dalam
    // irq_handler yang tadi cli), timer tidak akan pernah bisa
    // menginterupsi task ini lagi. sti eksplisit di sini menjamin
    // task baru selalu mulai dengan interrupt aktif.
    __asm__ volatile ("sti");

    // Uji sem_wait()/sem_post(): test_sem count=1, A dan B sama-sama
    // memperebutkan. Task yang duluan dapat, yang satunya BLOCKED
    // sampai sem_post() dari pemegang sebelumnya.
    serial_write("Task A minta semaphore...\r\n");
    sem_wait(&test_sem);
    serial_write("Task A dapat semaphore\r\n");

    for (int i = 0; i < 3; i++) {
        // Satu critical section untuk SELURUH baris log (3 panggilan
        // serial_write/serial_write_hex sekaligus) -- kalau tiap
        // panggilan dilock terpisah, timer masih bisa menyelip DI
        // ANTARA panggilan, membuat baris dari task lain menyisip
        // di tengah baris ini walau tiap panggilan sendiri utuh.
        uint64_t flags = irq_save();
        serial_write("Task A jalan, iterasi ke-");
        serial_write_hex((uint64_t)i);
        serial_write("\r\n");
        irq_restore(flags);

        // Uji task_sleep(): setelah iterasi pertama, A "tidur" 5 tick
        // timer -- scheduler harus otomatis memberi giliran ke task
        // lain selama itu, lalu membangunkan A sendiri tanpa task
        // manapun perlu tahu-menahu.
        if (i == 0) {
            serial_write("Task A akan tidur 5 tick...\r\n");
            task_sleep(5);
            serial_write("Task A bangun dari tidur\r\n");
        }
    }
    serial_write("Task A selesai\r\n");

    serial_write("Task A melepas semaphore\r\n");
    sem_post(&test_sem);

    // Serahkan CPU secara permanen -- task_exit() menandai diri
    // sendiri DEAD dan meminta scheduler pindah ke task lain.
    task_exit();
}

static void task_b_entry(void)
{
    // Task baru dijalankan lewat context_switch() (ret-based), TIDAK
    // pernah lewat iretq -- jadi RFLAGS.IF tidak otomatis di-restore.
    // Kalau task ini di-switch-in saat IF sedang 0 (misal dari dalam
    // irq_handler yang tadi cli), timer tidak akan pernah bisa
    // menginterupsi task ini lagi. sti eksplisit di sini menjamin
    // task baru selalu mulai dengan interrupt aktif.
    __asm__ volatile ("sti");

    // Uji sem_wait()/sem_post(): B mencoba ambil semaphore yang SAMA
    // dengan A sejak awal (kontensi nyata) -- test_sem count=1, jadi
    // salah satu pasti BLOCKED sampai yang lain sem_post().
    serial_write("Task B minta semaphore...\r\n");
    sem_wait(&test_sem);
    serial_write("Task B dapat semaphore\r\n");

    for (int i = 0; i < 3; i++) {
        // Satu critical section untuk SELURUH baris log (3 panggilan
        // serial_write/serial_write_hex sekaligus) -- kalau tiap
        // panggilan dilock terpisah, timer masih bisa menyelip DI
        // ANTARA panggilan, membuat baris dari task lain menyisip
        // di tengah baris ini walau tiap panggilan sendiri utuh.
        uint64_t flags = irq_save();
        serial_write("Task B jalan, iterasi ke-");
        serial_write_hex((uint64_t)i);
        serial_write("\r\n");
        irq_restore(flags);
    }
    serial_write("Task B selesai\r\n");

    serial_write("Task B melepas semaphore\r\n");
    sem_post(&test_sem);

    // Serahkan CPU secara permanen -- task_exit() menandai diri
    // sendiri DEAD dan meminta scheduler pindah ke task lain.
    task_exit();
}


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



// ---- Net-11b: kunci autentikasi dari disk FAT32 (KEY.TXT) ----
static uint8_t g_auth_key[64];
static uint32_t g_auth_key_len = 0;
static uint64_t g_auth_last_counter = 0;

void auth_load_key(void)
{
    if (!g_crypto_ok) {
        serial_write("Net-11: kripto tidak lulus self-test, auth tidak aktif\r\n");
        return;
    }

    uint32_t cluster = 0;
    uint32_t size = 0;

    // Return value tidak dipakai untuk memutuskan: konvensinya belum
    // dipastikan. Yang dipercaya adalah output cluster/size (diinit 0).
    int rc = fat32_find_file("KEY     TXT", &cluster, &size);

    serial_write("Net-11: cari KEY.TXT rc=");
    serial_write_hex((uint64_t)(uint32_t)rc);
    serial_write(" cluster=");
    serial_write_hex((uint64_t)cluster);
    serial_write(" size=");
    serial_write_hex((uint64_t)size);
    serial_write("\r\n");

    if (cluster < 2 || size == 0 || size > 512) {
        serial_write("Net-11: KEY.TXT tidak ada/tidak valid, semua perintah ditolak\r\n");
        return;
    }

    uint8_t *k = fat32_load_file(cluster, size);

    if (k == 0) {
        serial_write("Net-11: gagal memuat KEY.TXT, semua perintah ditolak\r\n");
        return;
    }

    uint32_t n = size;

    while (n > 0 && (k[n - 1] == '\n' || k[n - 1] == '\r' ||
                     k[n - 1] == ' '  || k[n - 1] == 0)) {
        n--;
    }

    if (n < 16 || n > sizeof(g_auth_key)) {
        serial_write("Net-11: panjang kunci harus 16..64 byte, semua perintah ditolak\r\n");
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        g_auth_key[i] = k[i];
    }

    g_auth_key_len = n;

    serial_write("Net-11: kunci dimuat, panjang=");
    serial_write_hex((uint64_t)n);
    serial_write("\r\n");
}

static volatile uint64_t g_net_loops = 0;
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

// ---- Net-9: remote command lewat UDP (port 7778), HANYA perintah baca ----

static char g_cmd_out[1400];
static uint32_t g_cmd_len = 0;

static void cmd_putc(char c)
{
    if (g_cmd_len < sizeof(g_cmd_out)) {
        g_cmd_out[g_cmd_len++] = c;
    }
}

static void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
}

static void cmd_putdec(uint64_t v)
{
    char tmp[21];
    int n = 0;

    if (v == 0) {
        tmp[n++] = '0';
    }

    while (v > 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }

    while (n > 0) {
        cmd_putc(tmp[--n]);
    }
}

static void cmd_puthex8(uint8_t b)
{
    static const char h[] = "0123456789ABCDEF";
    cmd_putc(h[b >> 4]);
    cmd_putc(h[b & 0xF]);
}

static int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name)
{
    uint32_t i = 0;

    while (name[i]) {
        if (i >= len || cmd[i] != (uint8_t)name[i]) {
            return 0;
        }
        i++;
    }

    return i == len;
}

// Net-19: satu baris "kunci=nilai" untuk perintah metrics
static void cmd_kv(const char *k, uint64_t v)
{
    cmd_puts(k);
    cmd_putc('=');
    cmd_putdec(v);
    cmd_putc('\n');
}

static const char *cmd_status_name(task_status_t s)
{
    switch (s) {
    case TASK_READY:    return "READY";
    case TASK_DEAD:     return "DEAD";
    case TASK_SLEEPING: return "SLEEPING";
    case TASK_BLOCKED:  return "BLOCKED";
    default:            return "?";
    }
}

static void net_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;

    if (len == 0) {
        cmd_puts("ERR: perintah kosong (ketik help)\n");
    } else if (net_cmd_is(cmd, len, "help")) {
        cmd_puts("perintah: help ping uptime mem log irq stats metrics mac ip tasks\n");
        cmd_puts("berprivilege: pping reboot\n");
        cmd_puts("kirim CHAL, lalu <nonce> <perintah> <hmac>\n");
#ifdef BMAHOS_LEGACYCTR
        cmd_puts("jalur counter (LEGACYCTR): <counter> <perintah> <hmac>, tanpa pping/reboot\n");
#endif
    } else if (net_cmd_is(cmd, len, "ping")) {
        cmd_puts("pong\n");
    } else if (net_cmd_is(cmd, len, "uptime")) {
        uint64_t t = timer_ticks;
        cmd_puts("uptime: ");
        cmd_putdec(t / 100);
        cmd_puts(" detik (");
        cmd_putdec(t);
        cmd_puts(" tick @100Hz)\n");
    } else if (net_cmd_is(cmd, len, "mac")) {
        cmd_puts("mac: ");
        for (int i = 0; i < 6; i++) {
            cmd_puthex8(g_e1000_mac[i]);
            if (i < 5) {
                cmd_putc(':');
            }
        }
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "ip")) {
        cmd_puts("ip: ");
        for (int i = 0; i < 4; i++) {
            cmd_putdec(g_net_ip[i]);
            if (i < 3) {
                cmd_putc('.');
            }
        }
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "log")) {
        // Salin di bawah irq_save supaya konsisten terhadap penulisan
        // ring dari konteks lain (tanpa I/O di dalam bagian ini).
        uint64_t lf = irq_save();
        uint64_t avail = g_log_total < LOG_RING_SIZE ? g_log_total : LOG_RING_SIZE;
        uint64_t want = avail < 1200 ? avail : 1200;
        uint32_t start = (uint32_t)((g_log_head + LOG_RING_SIZE - want) &
                                    (LOG_RING_SIZE - 1));
        uint64_t i = 0;

        if (want < avail) {
            // Potongan mulai di tengah baris: lewati sampai newline pertama.
            while (i < want && g_log_ring[(start + i) & (LOG_RING_SIZE - 1)] != '\n') {
                i++;
            }
            if (i < want) {
                i++;
            }
        }

        for (; i < want; i++) {
            char ch = g_log_ring[(start + i) & (LOG_RING_SIZE - 1)];
            cmd_putc((ch == '\n' || (ch >= 32 && ch < 127)) ? ch : '?');
        }

        irq_restore(lf);

        if (g_cmd_len == 0) {
            cmd_puts("(log kosong)\n");
        }
    } else if (net_cmd_is(cmd, len, "irq")) {
        cmd_puts("e1000 irq: count=");
        cmd_putdec(g_e1000_irq_count);
        cmd_puts(" spurious=");
        cmd_putdec(g_e1000_irq_spurious);
        cmd_puts(" last_icr=0x");
        cmd_puthex8((uint8_t)(g_e1000_irq_last_icr >> 8));
        cmd_puthex8((uint8_t)g_e1000_irq_last_icr);
        cmd_puts(" icr_or=0x");
        cmd_puthex8((uint8_t)(g_e1000_irq_icr_or >> 8));
        cmd_puthex8((uint8_t)g_e1000_irq_icr_or);
        cmd_puts(" gsi_terkunci=");
        cmd_putdec(g_e1000_irq_gsi);
        cmd_puts(" net_loop=");
        cmd_putdec(g_net_loops);
        cmd_puts("\ngsi_aktif:");

        for (uint32_t i = 0; i < 8; i++) {
            if (g_e1000_irq_rirr_or & (1u << i)) {
                cmd_putc(' ');
                cmd_putdec(16 + i);
            }
        }

        cmd_puts("\ngsi_dimask:");

        for (uint32_t i = 0; i < 8; i++) {
            if (g_e1000_irq_masked & (1u << i)) {
                cmd_putc(' ');
                cmd_putdec(16 + i);
            }
        }

        cmd_puts("\nrentang: 16..");
        cmd_putdec(g_e1000_irq_last_gsi);
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "stats")) {
        cmd_puts("udp: echo=");
        cmd_putdec(g_net_udp_echo_count);
        cmd_puts(" dibuang_batas=");
        cmd_putdec(g_net_udp_dropped);
        cmd_puts(" batas/detik=");
        cmd_putdec(NET_UDP_BUDGET_PER_SEC);
        cmd_puts(" dibuang_sumber=");
        cmd_putdec(g_net_udp_src_dropped);
        cmd_puts(" batas_sumber/detik=");
        cmd_putdec(NET_UDP_SRC_PER_SEC);
        cmd_puts("\nauth: ok=");
        cmd_putdec(g_auth_ok);
        cmd_puts(" nonaktif=");
        cmd_putdec(g_auth_denied[1]);
        cmd_puts(" format=");
        cmd_putdec(g_auth_denied[2]);
        cmd_puts(" hmac=");
        cmd_putdec(g_auth_denied[3]);
        cmd_puts(" replay=");
        cmd_putdec(g_auth_denied[4]);
        cmd_puts(" jalur_mati=");
        cmd_putdec(g_auth_ctr_off);
        cmd_puts("\npriv: chal=");
        cmd_putdec(g_chal_issued);
        cmd_puts(" ok=");
        cmd_putdec(g_priv_ok);
        cmd_puts(" nonaktif=");
        cmd_putdec(g_priv_denied[1]);
        cmd_puts(" format=");
        cmd_putdec(g_priv_denied[2]);
        cmd_puts(" nonce=");
        cmd_putdec(g_priv_denied[3]);
        cmd_puts(" kedaluwarsa=");
        cmd_putdec(g_priv_denied[4]);
        cmd_puts(" hmac=");
        cmd_putdec(g_priv_denied[5]);
        cmd_puts("\nrx_irq=");
        cmd_putdec(g_e1000_irq_count);
        cmd_puts(" rx_frames=");
        cmd_putdec(g_net_rx_frames);
        cmd_puts(" rx_err=");
        cmd_putdec(g_net_rx_errors);
        cmd_puts(" ring=");
        cmd_putdec(E1000_RX_RING_SIZE);
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "metrics")) {
        // Format stabil untuk skrip: satu kunci=nilai per baris.
        uint64_t free_frames = 0;

        for (uint64_t f = 0; f < PMM_MAX_FRAMES; f++) {
            if (!pmm_bitmap_test(f)) {
                free_frames++;
            }
        }

        cmd_kv("uptime_ticks", timer_ticks);
        cmd_kv("mem_free_kb", free_frames * PMM_PAGE_SIZE / 1024ULL);
        cmd_kv("heap_used", (uint64_t)kheap_current - (uint64_t)KHEAP_START);
        cmd_kv("tasks", task_count);
        cmd_kv("log_total", g_log_total);
        cmd_kv("rx_frames", g_net_rx_frames);
        cmd_kv("rx_err", g_net_rx_errors);
        cmd_kv("rx_irq", g_e1000_irq_count);
        e1000_stats_poll();
        cmd_kv("rx_missed", g_e1000_mpc);
        cmd_kv("rx_nobuf", g_e1000_rnbc);
        cmd_kv("rx_overrun_irq", (g_e1000_irq_icr_or >> 6) & 1u);
        cmd_kv("rx_arp", g_net_rx_arp);
        cmd_kv("rx_ipv4", g_net_rx_ipv4);
        cmd_kv("rx_other", g_net_rx_other);
        cmd_kv("tx_ok", g_net_tx_ok);
        cmd_kv("tx_fail", g_net_tx_fail);
        cmd_kv("arp_reply", g_net_arp_replies_sent);
        cmd_kv("icmp_reply", g_net_icmp_replies_sent);
        cmd_kv("udp_echo", g_net_udp_echo_count);
        cmd_kv("udp_dropped", g_net_udp_dropped);
        cmd_kv("udp_src_dropped", g_net_udp_src_dropped);
        cmd_kv("log_serial_muted", g_net_log_muted);
        cmd_kv("udp_badsum", g_net_udp_badsum);
        cmd_kv("tcp_rx", g_tcp_rx);
        cmd_kv("tcp_badsum", g_tcp_badsum);
        cmd_kv("tcp_rst_sent", g_tcp_rst_sent);
        cmd_kv("tcp_conn_open", g_tcp_conn_open);
        cmd_kv("tcp_dropped_busy", g_tcp_busy);
        cmd_kv("tcp_rx_bytes", g_tcp_rx_bytes);
        cmd_kv("tcp_timeout", g_tcp_timeouts);
        cmd_kv("auth_ok", g_auth_ok);
        cmd_kv("auth_nonaktif", g_auth_denied[1]);
        cmd_kv("auth_format", g_auth_denied[2]);
        cmd_kv("auth_hmac", g_auth_denied[3]);
        cmd_kv("auth_replay", g_auth_denied[4]);
        cmd_kv("auth_counter_off", g_auth_ctr_off);
        cmd_kv("priv_chal", g_chal_issued);
        cmd_kv("chal_ip_recycled", g_chal_ip_recycled);
        cmd_kv("priv_ok", g_priv_ok);
        cmd_kv("priv_nonaktif", g_priv_denied[1]);
        cmd_kv("priv_format", g_priv_denied[2]);
        cmd_kv("priv_nonce", g_priv_denied[3]);
        cmd_kv("priv_kedaluwarsa", g_priv_denied[4]);
        cmd_kv("priv_hmac", g_priv_denied[5]);
    } else if (net_cmd_is(cmd, len, "mem")) {
        // Hitung frame bebas dengan scan bitmap. Tidak dikunci terhadap
        // pmm_alloc() task lain, jadi angkanya perkiraan sesaat.
        uint64_t free_frames = 0;

        for (uint64_t f = 0; f < PMM_MAX_FRAMES; f++) {
            if (!pmm_bitmap_test(f)) {
                free_frames++;
            }
        }

        cmd_puts("pmm bebas: ");
        cmd_putdec(free_frames);
        cmd_puts(" frame (");
        cmd_putdec(free_frames * PMM_PAGE_SIZE / 1048576ULL);
        cmd_puts(" MB)\n");
        cmd_puts("kheap terpakai: ");
        cmd_putdec((uint64_t)kheap_current - (uint64_t)KHEAP_START);
        cmd_puts(" byte, termap: ");
        cmd_putdec(kheap_mapped_end - (uint64_t)KHEAP_START);
        cmd_puts(" byte\n");
    } else if (net_cmd_is(cmd, len, "tasks")) {
        for (size_t i = 0; i < task_count; i++) {
            cmd_puts("slot ");
            cmd_putdec(i);
            cmd_puts(": ");
            cmd_puts(cmd_status_name(tasks[i].status));
            if (tasks[i].is_user_task) {
                cmd_puts(" user");
            }
            if (i == g_idle_index) {
                cmd_puts(" idle");
            }
            if (i == current_index) {
                cmd_puts(" (menjalankan perintah ini)");
            }
            cmd_putc('\n');
        }
    } else {
        cmd_puts("ERR: perintah tidak dikenal (ketik help)\n");
    }
}

// Kirim g_cmd_out sebagai datagram UDP balasan ke pengirim req.
static void net_udp_send_cmd_reply(volatile uint8_t *req, uint32_t ihl)
{
    uint32_t plen = g_cmd_len;
    uint32_t udp_len = 8 + plen;

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-9: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t r = 14 + ihl;

    uint32_t frame_len = 14 + 20 + udp_len;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = 0; i < send_len; i++) {
        p[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    p[14] = 0x45;
    p[15] = 0x00;
    p[16] = (uint8_t)((20 + udp_len) >> 8);
    p[17] = (uint8_t)((20 + udp_len) & 0xFF);
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[21] = 0x00;
    p[22] = 64;
    p[23] = 17;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = req[26 + i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    p[34] = req[r + 2];
    p[35] = req[r + 3];
    p[36] = req[r + 0];
    p[37] = req[r + 1];
    p[38] = (uint8_t)(udp_len >> 8);
    p[39] = (uint8_t)(udp_len & 0xFF);

    for (uint32_t i = 0; i < plen; i++) {
        p[42 + i] = (uint8_t)g_cmd_out[i];
    }

    uint16_t uc = net_udp_checksum(p + 26, p + 30, p + 34, udp_len);
    if (uc == 0) {
        uc = 0xFFFF;
    }
    p[40] = (uint8_t)(uc >> 8);
    p[41] = (uint8_t)(uc & 0xFF);

    int ok = e1000_tx_send(g_net_tx_buf_phys, send_len);

    uint64_t lf = irq_save();
    serial_write("Net-9: balasan perintah (");
    serial_write_hex((uint64_t)plen);
    serial_write(" byte) -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

static int auth_hexval(uint8_t c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Format: "<counter> <perintah> <hmac-hex-64>".
// Return: 0 OK, 1 auth nonaktif, 2 format salah, 3 HMAC salah, 4 replay.
static int auth_verify(volatile uint8_t *d, uint32_t len,
                       volatile uint8_t **cmd_out, uint32_t *cmd_len_out,
                       uint64_t *counter_out)
{
    if (g_auth_key_len == 0) {
        return 1;
    }

    // minimum: counter(1) + spasi + perintah(1) + spasi + hmac(64)
    if (len < 68) {
        return 2;
    }

    uint32_t sp = len;

    while (sp > 0 && d[sp - 1] != ' ') {
        sp--;
    }

    if (sp == 0 || len - sp != 64) {
        return 2;
    }

    uint32_t msg_len = sp - 1;

    if (msg_len == 0 || msg_len > 200) {
        return 2;
    }

    uint32_t fs = 0;

    while (fs < msg_len && d[fs] != ' ') {
        fs++;
    }

    if (fs == 0 || fs > 19 || fs + 1 >= msg_len) {
        return 2;
    }

    uint64_t counter = 0;

    for (uint32_t i = 0; i < fs; i++) {
        if (d[i] < '0' || d[i] > '9') {
            return 2;
        }
        counter = counter * 10 + (uint64_t)(d[i] - '0');
    }

    uint8_t rx[32];

    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(d[sp + i * 2]);
        int lo = auth_hexval(d[sp + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t m[200];

    for (uint32_t i = 0; i < msg_len; i++) {
        m[i] = d[i];
    }

    uint8_t mac[32];
    hmac_sha256(g_auth_key, g_auth_key_len, m, msg_len, mac);

    uint8_t diff = 0;

    for (uint32_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(mac[i] ^ rx[i]);
    }

    if (diff != 0) {
        return 3;
    }

    if (counter <= g_auth_last_counter) {
        return 4;
    }

    g_auth_last_counter = counter;
    *cmd_out = d + fs + 1;
    *cmd_len_out = msg_len - fs - 1;
    *counter_out = counter;

    return 0;
}

// ---- Net-18A: challenge-response nonce untuk perintah berprivilege ----
// Klien kirim "CHAL" -> server balas nonce 32 hex (16 byte), sekali pakai,
// TTL 5 detik. Perintah: "<nonce32hex> <perintah> <hmac-hex64>", hmac atas
// "<nonce> <perintah>". Menutup replay setelah reboot (counter lama di RAM).
// Hanya dipanggil dari net task, jadi tidak perlu lock.
#define PRIV_NONCE_SLOTS 16
#define PRIV_NONCE_PER_IP 4   // M1: slot hidup maks per IP sumber
#define PRIV_NONCE_TTL   500

typedef struct {
    uint8_t nonce[16];
    uint64_t issued;
    uint8_t ip[4];
    int in_use;
} priv_nonce_t;

static priv_nonce_t g_priv_nonces[PRIV_NONCE_SLOTS];
static uint8_t g_nonce_pool[32];
static uint64_t g_nonce_ctr = 0;
static int g_rdrand_state = -1;   // -1 belum dicek, 0 tidak ada, 1 ada

static inline uint64_t priv_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int priv_have_rdrand(void)
{
#ifdef BMAHOS_NORDRAND
    return 0;
#else
    uint32_t a = 1, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    return (c >> 30) & 1;
#endif
}

static int priv_rdrand64(uint64_t *out)
{
#ifdef BMAHOS_NORDRAND
    (void)out;
    return 0;
#else
    for (int i = 0; i < 10; i++) {
        uint64_t v;
        uint8_t ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) {
            *out = v;
            return 1;
        }
    }
    return 0;
#endif
}

static uint8_t priv_cmos_read(uint8_t reg)
{
    outb(0x70, reg);
    return inb(0x71);
}

// SHA-256 atas pool + rdrand + TSC + timer_ticks + counter + RTC.
// Pool diperbarui dari hash dengan label berbeda dari keluaran nonce.
void priv_nonce_generate(uint8_t out[16])
{
    static const uint8_t rtc_regs[6] = {0x00, 0x02, 0x04, 0x07, 0x08, 0x09};
    sha256_ctx_t ctx;
    uint8_t h[32];
    uint8_t t[32];
    uint64_t v;

    if (g_rdrand_state < 0) {
        g_rdrand_state = priv_have_rdrand();

        uint64_t lf = irq_save();
#ifdef BMAHOS_NORDRAND
        serial_write("Net-18: sumber nonce tanpa rdrand (build NORDRAND)\r\n");
#else
        serial_write(g_rdrand_state
                     ? "Net-18: sumber nonce memakai rdrand\r\n"
                     : "Net-18: CPU tanpa rdrand, nonce dari TSC/tick/RTC saja\r\n");
#endif
        irq_restore(lf);
    }

    g_nonce_ctr++;

    sha256_init(&ctx);
    sha256_update(&ctx, g_nonce_pool, 32);

    if (g_rdrand_state == 1) {
        for (int i = 0; i < 4; i++) {
            if (priv_rdrand64(&v)) {
                sha256_update(&ctx, (const uint8_t *)&v, 8);
            }
        }
    }

    v = priv_rdtsc();
    sha256_update(&ctx, (const uint8_t *)&v, 8);
    v = timer_ticks;
    sha256_update(&ctx, (const uint8_t *)&v, 8);
    sha256_update(&ctx, (const uint8_t *)&g_nonce_ctr, 8);

    for (int i = 0; i < 6; i++) {
        uint8_t r = priv_cmos_read(rtc_regs[i]);
        sha256_update(&ctx, &r, 1);
    }

    sha256_final(&ctx, h);

    sha256_init(&ctx);
    sha256_update(&ctx, h, 32);
    sha256_update(&ctx, (const uint8_t *)"pool", 4);
    sha256_final(&ctx, g_nonce_pool);

    sha256_init(&ctx);
    sha256_update(&ctx, h, 32);
    sha256_update(&ctx, (const uint8_t *)"nonce", 5);
    sha256_final(&ctx, t);

    for (int i = 0; i < 16; i++) {
        out[i] = t[i];
    }
}

// M1: slot kosong/kedaluwarsa dipakai dulu. IP yang sudah punya
// PRIV_NONCE_PER_IP nonce hidup hanya mengganti nonce miliknya sendiri yang
// tertua, jadi banjir CHAL satu IP tidak menggusur nonce IP lain.
// Tabel penuh oleh banyak IP berbeda: ganti yang tertua (batas diketahui).

static uint32_t priv_nonce_issue(const volatile uint8_t *ip)
{
    uint32_t slot = 0;
    int found = 0;
    uint32_t mine = 0;
    int mine_old = -1;

    for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
        priv_nonce_t *e = &g_priv_nonces[i];

        if (e->in_use && timer_ticks - e->issued > PRIV_NONCE_TTL) {
            e->in_use = 0;
        }

        if (e->in_use && e->ip[0] == ip[0] && e->ip[1] == ip[1] &&
            e->ip[2] == ip[2] && e->ip[3] == ip[3]) {
            mine++;
            if (mine_old < 0 || e->issued < g_priv_nonces[mine_old].issued) {
                mine_old = (int)i;
            }
        }
    }

    if (mine >= PRIV_NONCE_PER_IP) {
        slot = (uint32_t)mine_old;
        g_chal_ip_recycled++;
    } else {
        for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
            if (!g_priv_nonces[i].in_use) {
                slot = i;
                found = 1;
                break;
            }
        }

        if (!found) {
            for (uint32_t i = 1; i < PRIV_NONCE_SLOTS; i++) {
                if (g_priv_nonces[i].issued < g_priv_nonces[slot].issued) {
                    slot = i;
                }
            }
        }
    }

    for (int i = 0; i < 4; i++) {
        g_priv_nonces[slot].ip[i] = ip[i];
    }

    priv_nonce_generate(g_priv_nonces[slot].nonce);
    g_priv_nonces[slot].issued = timer_ticks;
    g_priv_nonces[slot].in_use = 1;

    return slot;
}

// Format: "<nonce32hex> <perintah> <hmac-hex64>".
// Return: 0 OK, 1 nonaktif, 2 format, 3 nonce tak dikenal/dipakai,
// 4 kedaluwarsa, 5 hmac salah. Nonce dicari sebelum HMAC (murah dulu),
// dan slot dibebaskan HANYA setelah HMAC valid.
static int priv_verify(volatile uint8_t *d, uint32_t len,
                       volatile uint8_t **cmd_out, uint32_t *cmd_len_out)
{
    if (g_auth_key_len == 0) {
        return 1;
    }

    // minimum: nonce(32) + spasi + perintah(1) + spasi + hmac(64)
    if (len < 99) {
        return 2;
    }

    uint32_t sp = len;

    while (sp > 0 && d[sp - 1] != ' ') {
        sp--;
    }

    if (sp == 0 || len - sp != 64) {
        return 2;
    }

    uint32_t msg_len = sp - 1;

    if (msg_len < 34 || msg_len > 200 || d[32] != ' ') {
        return 2;
    }

    uint8_t nonce[16];

    for (uint32_t i = 0; i < 16; i++) {
        int hi = auth_hexval(d[i * 2]);
        int lo = auth_hexval(d[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        nonce[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t rx[32];

    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(d[sp + i * 2]);
        int lo = auth_hexval(d[sp + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    int slot = -1;

    for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
        if (!g_priv_nonces[i].in_use) {
            continue;
        }

        uint8_t nd = 0;

        for (uint32_t j = 0; j < 16; j++) {
            nd |= (uint8_t)(g_priv_nonces[i].nonce[j] ^ nonce[j]);
        }

        if (nd == 0) {
            slot = (int)i;
            break;
        }
    }

    if (slot < 0) {
        return 3;
    }

    if (timer_ticks - g_priv_nonces[slot].issued > PRIV_NONCE_TTL) {
        return 4;
    }

    uint8_t m[200];

    for (uint32_t i = 0; i < msg_len; i++) {
        m[i] = d[i];
    }

    uint8_t mac[32];
    hmac_sha256(g_auth_key, g_auth_key_len, m, msg_len, mac);

    uint8_t diff = 0;

    for (uint32_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(mac[i] ^ rx[i]);
    }

    if (diff != 0) {
        return 5;
    }

    g_priv_nonces[slot].in_use = 0;
    *cmd_out = d + 33;
    *cmd_len_out = msg_len - 33;

    return 0;
}

// ---- Net-18B: reboot berprivilege ----
// Dipanggil SETELAH balasan terkirim. Urutan: register reset ACPI (FADT,
// ACPI-R), 8042 pulse reset (0xFE), lalu cadangan triple fault (IDT limit 0
// lalu int3). NOACPIRESET=1 dan NOKBDRESET=1 melewati jalur masing-masing
// untuk menguji cadangan.
static int g_priv_reboot_pending = 0;

static void priv_do_reboot(void)
{
    __asm__ volatile("cli");
    g_serial_mute = 0;

#ifndef BMAHOS_NOACPIRESET
    if (g_acpi_reset_ok) {
        serial_write("ACPI-R: reboot via register reset FADT\r\n");
        outb(g_acpi_reset_port, g_acpi_reset_value);

        for (uint32_t i = 0; i < 1000000; i++) {
            (void)inb(0x64);
        }

        serial_write("ACPI-R: reset ACPI tidak me-reset, lanjut 8042\r\n");
    }
#else
    serial_write("ACPI-R: reset ACPI dilewati (build NOACPIRESET)\r\n");
#endif

#ifndef BMAHOS_NOKBDRESET
    serial_write("Net-18B: reboot via 8042 (0xFE)\r\n");

    for (uint32_t i = 0; i < 100000; i++) {
        if ((inb(0x64) & 0x02) == 0) {
            break;
        }
    }

    outb(0x64, 0xFE);

    for (uint32_t i = 0; i < 1000000; i++) {
        (void)inb(0x64);
    }

    serial_write("Net-18B: 8042 tidak me-reset, cadangan triple fault\r\n");
#else
    serial_write("Net-18B: reboot via triple fault (build NOKBDRESET)\r\n");
#endif

    struct __attribute__((packed)) {
        uint16_t limit;
        uint64_t base;
    } zero_idt = {0, 0};

    __asm__ volatile("lidt %0; int3" : : "m"(zero_idt));

    for (;;) {
        __asm__ volatile("hlt");
    }
}

static void priv_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;

    if (net_cmd_is(cmd, len, "pping")) {
        cmd_puts("ppong\n");
    } else if (net_cmd_is(cmd, len, "reboot")) {
        cmd_puts("reboot: dimulai\n");
        g_priv_reboot_pending = 1;
    } else {
        // B2: perintah baca juga boleh lewat jalur nonce.
        net_cmd_execute(cmd, len);
    }
}

// Return 1 jika datagram adalah CHAL atau berformat nonce (balasan sudah
// diisi di g_cmd_out), 0 jika harus lewat jalur counter lama.
static int priv_try_handle(volatile uint8_t *cmd, uint32_t len,
                           const volatile uint8_t *src_ip)
{
    if (net_cmd_is(cmd, len, "CHAL")) {
        g_cmd_len = 0;

        if (g_auth_key_len == 0) {
            g_priv_denied[1]++;
            cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
            return 1;
        }

        uint32_t slot = priv_nonce_issue(src_ip);
        g_chal_issued++;

        cmd_puts("nonce: ");
        for (int i = 0; i < 16; i++) {
            static const char hx[] = "0123456789abcdef";
            cmd_putc(hx[g_priv_nonces[slot].nonce[i] >> 4]);
            cmd_putc(hx[g_priv_nonces[slot].nonce[i] & 0xF]);
        }
        cmd_putc('\n');

        uint64_t lf = irq_save();
        serial_write("Net-18: CHAL nonce dikeluarkan slot=");
        serial_write_hex((uint64_t)slot);
        serial_write("\r\n");
        irq_restore(lf);
        return 1;
    }

    uint32_t fs = 0;

    while (fs < len && cmd[fs] != ' ') {
        fs++;
    }

    if (fs != 32) {
        return 0;
    }

    volatile uint8_t *pc = 0;
    uint32_t pcl = 0;
    int prc = priv_verify(cmd, len, &pc, &pcl);

    uint64_t lf = irq_save();
    if (prc == 0) {
        serial_write("Net-18: priv OK\r\n");
    } else {
        serial_write("Net-18: priv DITOLAK kode=");
        serial_write_hex((uint64_t)prc);
        serial_write("\r\n");
    }
    irq_restore(lf);

    if (prc == 0) {
        g_priv_ok++;
        priv_cmd_execute(pc, pcl);
        return 1;
    }

    g_priv_denied[prc]++;
    g_cmd_len = 0;

    if (prc == 1) {
        cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
    } else if (prc == 2) {
        cmd_puts("ERR: format: <nonce32hex> <perintah> <hmac-hex64>\n");
    } else if (prc == 3) {
        cmd_puts("ERR: nonce tidak dikenal atau sudah dipakai\n");
    } else if (prc == 4) {
        cmd_puts("ERR: nonce kedaluwarsa (minta CHAL baru)\n");
    } else {
        cmd_puts("ERR: hmac salah\n");
    }

    return 1;
}

void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len)
{
    volatile uint8_t *cmd = req + 14 + ihl + 8;
    uint32_t len = udp_len - 8;

    // Buang trailing CR/LF/spasi/NUL (nc, PowerShell, dll. sering menambah).
    while (len > 0 && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' ||
                       cmd[len - 1] == ' '  || cmd[len - 1] == 0)) {
        len--;
    }

    if (priv_try_handle(cmd, len, req + 14 + 12)) {
        net_udp_send_cmd_reply(req, ihl);

        if (g_priv_reboot_pending) {
            priv_do_reboot();
        }
        return;
    }

#ifndef BMAHOS_LEGACYCTR
    // B2: jalur counter dimatikan. Counter terakhir hanya ada di RAM, jadi
    // setelah reboot datagram lama bisa diputar ulang sekali; jalur nonce
    // tidak punya masalah itu. LEGACYCTR=1 menyalakannya lagi.
    g_auth_ctr_off++;
    g_cmd_len = 0;
    cmd_puts("ERR: jalur counter dimatikan; kirim CHAL lalu <nonce> <perintah> <hmac>\n");
    net_udp_send_cmd_reply(req, ihl);
    return;
#endif

    volatile uint8_t *ac = 0;
    uint32_t acl = 0;
    uint64_t actr = 0;

    int arc = auth_verify(cmd, len, &ac, &acl, &actr);

    if (arc == 0) {
        g_auth_ok++;
    } else if (arc >= 1 && arc <= 4) {
        g_auth_denied[arc]++;
    }

    if (arc == 0) {
        uint64_t lf = irq_save();
        serial_write("Net-11: auth OK counter=");
        serial_write_hex(actr);
        serial_write("\r\n");
        irq_restore(lf);

        net_cmd_execute(ac, acl);
    } else {
        uint64_t lf = irq_save();
        serial_write("Net-11: auth DITOLAK kode=");
        serial_write_hex((uint64_t)arc);
        serial_write("\r\n");
        irq_restore(lf);

        g_cmd_len = 0;

        if (arc == 1) {
            cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
        } else if (arc == 2) {
            cmd_puts("ERR: format: <counter> <perintah> <hmac-hex64>\n");
        } else if (arc == 3) {
            cmd_puts("ERR: hmac salah\n");
        } else {
            cmd_puts("ERR: counter replay\n");
        }
    }

    net_udp_send_cmd_reply(req, ihl);
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

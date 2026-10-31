#include "kernel.h"

// TASK_READY: task valid, boleh dipilih scheduler.
// TASK_DEAD: task sudah selesai, scheduler WAJIB melewatinya --
// task menandai dirinya sendiri DEAD di akhir entry function-nya
// (lihat task_a_entry()/task_b_entry()).

// Semaphore sederhana: counter + "wake maksimal 1 waiter per post"
// (lihat sem_post()). Tidak ada waiter queue eksplisit -- sem_post()
// scan tasks[] cari SATU task BLOCKED pada semaphore ini, konsisten
// dengan gaya schedule() yang sudah ada (linear scan), bukan struktur
// antrian terpisah. Semantiknya tetap sama: 1 post membangunkan
// maksimal 1 task.


// Siapkan stack awal task baru supaya context_switch() bisa
// "melompat" ke entry_function pertama kali task ini dijalankan.
// Stack direkayasa supaya urutan pop di context_switch() (rax..r15,
// 15 register, matching irq_common_stub) lalu ret, membuat CPU
// seolah baru masuk ke entry_function.
void task_create(task_t *task, void (*entry_function)(void), uint64_t stack_size)
{
    uint64_t stack_base = kstack_alloc(stack_size);   // R6-2: dengan guard page
    if (stack_base == 0) {
        oom_panic("stack kernel task");   // R6-3
    }
    // R6-2: frame pertama task (rbp=0) dibaca panic_walk sampai rbp+8; sisakan
    // KSTACK_PAD byte nol supaya bacaan itu tidak jatuh ke guard stack berikutnya.
    uint64_t stack_top = stack_base + stack_size - KSTACK_PAD;

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

task_t tasks[MAX_TASKS];
size_t task_count = 0;
// Indeks task idle di tasks[]; (size_t)-1 = belum ada. Tidak ikut round-robin:
// hanya dipilih scheduler kalau tidak ada task lain yang READY.
size_t g_idle_index = (size_t)-1;
volatile bool scheduler_started = false;
size_t current_index = 0;


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

void task_create_user(
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
    uint64_t kstack_base = kstack_alloc(kernel_stack_size);   // R6-2
    if (kstack_base == 0) {
        oom_panic("stack kernel task user");   // R6-3
    }
    uint64_t kstack_top = kstack_base + kernel_stack_size - KSTACK_PAD;

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
    if (user_code_frame == 0 || user_stack_frame == 0) {
        oom_panic("halaman user task");   // R6-3
    }

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
task_t *spawn(const uint8_t *image, size_t image_len)
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

    // R6-1: satu halaman guard (tidak dipetakan) di antara kode dan stack:
    // stack yang meluap ke bawah memicu #PF not-present, bukan menabrak kode.
    uint64_t guard_vaddr = vmm_alloc_vaddr(task, PMM_PAGE_SIZE);
    uint64_t stack_vaddr = guard_vaddr ? vmm_alloc_vaddr(task, PMM_PAGE_SIZE) : 0;
    if (stack_vaddr == 0) {
        serial_write("spawn(): FATAL -- vmm_alloc_vaddr() gagal untuk stack, dibatalkan.\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    // --- Kernel stack task ini (dipakai context_switch() & RSP0) ---
    // Ukuran sama seperti seluruh call site task_create_user() yang
    // ada sekarang (4096) -- bukan angka baru.
    uint64_t kstack_base = kstack_alloc(4096);   // R6-2
    if (kstack_base == 0) {
        oom_panic("stack kernel spawn");   // R6-3
    }
    uint64_t kstack_top = kstack_base + 4096 - KSTACK_PAD;

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
    if (code_frame == 0 || stack_frame == 0) {
        oom_panic("halaman user spawn");   // R6-3
    }

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
void schedule(void)
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
void task_exit(void)
{
    uint64_t flags = irq_save();

    sock_task_exit(current_index);   // P5-1
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
void task_sleep(uint64_t ticks)
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

// P5-1: bangunkan task yang sedang task_sleep() sebelum waktunya (data soket
// masuk / kirim selesai). Task lain yang tidak tidur tidak berubah.
void task_wake(size_t idx)
{
    uint64_t flags = irq_save();

    if (idx < task_count && tasks[idx].status == TASK_SLEEPING) {
        tasks[idx].status = TASK_READY;
    }
    irq_restore(flags);
}

// Task minta "diblokir" sampai task lain (target_index) menjadi
// TASK_DEAD. BEDA dari task_sleep() -- syarat bangun bukan waktu,
// tapi status task lain (event-based blocking, bukan time-based).
void task_wait_for(size_t target_index)
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
void sem_wait(semaphore_t *sem)
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
void sem_post(semaphore_t *sem)
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

void task_a_entry(void)
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

void task_b_entry(void)
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

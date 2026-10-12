#ifndef BMAHOS_KERNEL_H
#define BMAHOS_KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---- Port I/O ----
// F1.7: di uji host (BMAHOS_HOST_TEST, user mode) port I/O akan fault,
// jadi out* tidak melakukan apa pun dan in* mengembalikan 0.
static inline void outb(uint16_t port, uint8_t value)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    (void)value;
    return;
#endif
    __asm__ volatile (
        "outb %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint8_t inb(uint16_t port)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    return 0;
#endif
    uint8_t value;

    __asm__ volatile (
        "inb %1, %0"
        : "=a"(value)
        : "Nd"(port)
    );

    return value;
}

// Checkpoint PCI: varian 32-bit outb/inb -- dibutuhkan karena PCI
// configuration space diakses lewat CONFIG_ADDRESS/CONFIG_DATA yang
// keduanya register 32-bit (port 0xCF8/0xCFC), bukan 8-bit seperti
// PIC/PIT/serial yang sudah ada.
static inline void outl(uint16_t port, uint32_t value)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    (void)value;
    return;
#endif
    __asm__ volatile (
        "outl %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint32_t inl(uint16_t port)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    return 0;
#endif
    uint32_t value;

    __asm__ volatile (
        "inl %1, %0"
        : "=a"(value)
        : "Nd"(port)
    );

    return value;
}

// irq_save/irq_restore: proteksi critical section yang AMAN terhadap
// nested call (beda dari cli/sti polos). irq_save() menyimpan kondisi
// IF (Interrupt Flag) yang SEBENARNYA sebelum cli, lewat pushfq (baca
// seluruh RFLAGS). irq_restore() hanya sti KALAU kondisi sebelumnya
// memang IF=1 -- kalau caller sudah cli duluan sebelum manggil kita,
// kita tidak akan sengaja menyalakan interrupt yang caller matikan.
static inline uint64_t irq_save(void)
{
#ifdef BMAHOS_HOST_TEST
    return 0;   // F1.7: uji di host (user mode), cli/sti akan fault
#endif
    uint64_t flags;
    __asm__ volatile (
        "pushfq\n\t"
        "popq %0\n\t"
        "cli"
        : "=r"(flags)
        :
        : "memory"
    );
    return flags;
}

static inline void irq_restore(uint64_t flags)
{
#ifdef BMAHOS_HOST_TEST
    return;
#endif
    // Bit ke-9 RFLAGS = IF. Kalau nyala di kondisi yang disimpan,
    // berarti sebelum irq_save() dipanggil interrupt memang aktif.
    if (flags & (1 << 9)) {
        __asm__ volatile ("sti" ::: "memory");
    }
}

// ---- serial.c ----
void serial_init(void);
void serial_putc(char c);
void serial_write(const char *s);
void serial_write_hex(uint64_t value);
extern volatile int g_serial_mute;

// ---- kernel.c (ring log; dipakai serial_putc) ----
void log_capture(char c);

// ---- cpu.c (GDT/TSS/IDT) ----
struct gdt_entry
{
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct tss
{
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint32_t reserved1;
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint32_t reserved2;
    uint32_t reserved3;
    uint16_t iopb_offset;
    uint8_t  reserved4[6];
} __attribute__((packed));

struct idt_entry
{
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

extern struct gdt_entry bmahOS_gdt[7];
extern struct tss bmahOS_tss;
extern struct idt_entry bmahOS_idt[256];
extern void tss_load_asm(void);
extern uint64_t tss_read_asm(void);
void idt_set_entry(uint8_t vector, uint64_t handler, uint16_t selector, uint8_t type_attr);
void idt_init(void);
void print_idt_entry0(void);
void print_idt_entry32(void);
void gdt_init(void);
void print_bmahOS_gdt(void);
void idt_load(void);
void read_idtr(void);
void gdt_load_and_reload(void);
void read_bmahOS_gdtr(void);
void read_segment_registers(void);
void read_gdtr(void);
void read_gdt_entries(void);

// ---- pmm.c (physical memory manager) ----
#define PMM_PAGE_SIZE          0x1000ULL
#define PMM_MAX_PHYS_ADDR      0x100000000ULL
#define PMM_MAX_FRAMES         (PMM_MAX_PHYS_ADDR / PMM_PAGE_SIZE)
#define PMM_BITMAP_SIZE        (PMM_MAX_FRAMES / 8ULL)

struct limine_memmap_response;
extern uint64_t pmm_usable_memory;
int pmm_bitmap_test(uint64_t frame);
void pmm_init(struct limine_memmap_response *response);
uint64_t pmm_alloc(void);
void pmm_free(uint64_t phys_addr);

// ---- vmm.c (paging + kernel heap) ----
#define VMM_FLAG_PRESENT   0x1ULL
#define VMM_FLAG_WRITABLE  0x2ULL
#define VMM_FLAG_NOCACHE   0x10ULL  // PCD bit -- wajib untuk MMIO (Local APIC, IOAPIC)
#define VMM_FLAG_USER      0x4ULL   // US bit -- wajib untuk halaman yang boleh diakses ring 3
#define VMM_FLAG_NX        (1ULL << 63) // XD bit -- halaman tidak bisa dieksekusi
#define VMM_ENTRY_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define VMM_SHARED_PML4_IDX_HHDM     0x100  // hhdm_offset region
#define VMM_SHARED_PML4_IDX_APIC1    0x120  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_APIC2    0x122  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_KHEAP    0x130  // KHEAP_START region
#define VMM_SHARED_PML4_IDX_KERNEL   0x1FF  // kernel higher-half (.text/.data)
#define KHEAP_START 0xFFFF980000000000ULL
extern uint64_t hhdm_offset;
extern int g_vmm_nx_ok;
extern uint64_t kheap_current;
extern uint64_t kheap_mapped_end;
uint64_t read_cr3(void);
void vmm_dump_pml4(uint64_t pml4_phys);
void vmm_map(uint64_t pml4_phys, uint64_t vaddr, uint64_t paddr, uint64_t flags);
int vmm_nx_of(uint64_t pml4_phys, uint64_t vaddr);
void nx_init(void);
uint64_t vmm_clone_kernel_pml4(uint64_t kernel_pml4_phys);
bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable);
void kheap_init(uint64_t pml4_phys);
void * kmalloc(uint64_t size);
void kfree(void *ptr);

// ---- acpi.c (RSDP/MADT/FADT) ----
struct acpi_rsdp
{
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    // Fields berikut hanya valid kalau revision >= 2 (ACPI 2.0+)
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));
struct acpi_sdt_header
{
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));
struct acpi_madt
{
    struct acpi_sdt_header header;
    uint32_t local_apic_address;
    uint32_t flags;
    // Diikuti entries dengan panjang variabel
} __attribute__((packed));
struct acpi_madt_entry_header
{
    uint8_t entry_type;
    uint8_t entry_length;
} __attribute__((packed));
struct acpi_madt_local_apic
{
    struct acpi_madt_entry_header header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));
struct acpi_madt_ioapic
{
    struct acpi_madt_entry_header header;
    uint8_t ioapic_id;
    uint8_t reserved;
    uint32_t ioapic_address;
    uint32_t global_system_interrupt_base;
} __attribute__((packed));
struct acpi_madt_iso
{
    struct acpi_madt_entry_header header;
    uint8_t bus_source;
    uint8_t irq_source;
    uint32_t global_system_interrupt;
    uint16_t flags;
} __attribute__((packed));
extern uint64_t g_local_apic_address;
extern uint32_t g_ioapic_address;
extern uint32_t g_ioapic_gsi_base;
extern uint32_t g_irq0_gsi;
extern int g_acpi_reset_ok;
extern uint16_t g_acpi_reset_port;
extern uint8_t g_acpi_reset_value;
void acpi_init(void);

// ---- pic.c (8259 PIC + PIT) ----
void pic_remap(void);
void pit_init(uint32_t frequency_hz);

// ---- pci.c (PCI config space + pencarian perangkat) ----
#define AHCI_PCI_BUS      g_ahci_bus
#define AHCI_PCI_DEVICE   g_ahci_dev
#define AHCI_PCI_FUNCTION g_ahci_fn
#define AHCI_BAR5_OFFSET  0x24
#define E1000_PCI_BUS      g_e1000_bus
#define E1000_PCI_DEVICE   g_e1000_dev
#define E1000_PCI_FUNCTION g_e1000_fn
#define E1000_BAR0_OFFSET  0x10

extern uint8_t g_ahci_bus, g_ahci_dev, g_ahci_fn;
extern uint8_t g_e1000_bus, g_e1000_dev, g_e1000_fn;
extern int g_ahci_found;
extern int g_e1000_found;
uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);
void pci_scan_and_log(void);
void pci_config_write32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
void pci_find_devices(void);

// ---- apic.c (Local APIC + IOAPIC) ----
#define LAPIC_VIRT  0xFFFF910000000000ULL
#define IOAPIC_REDTBL_BASE  0x10

void lapic_send_eoi(void);
uint32_t ioapic_read(uint32_t reg);
void ioapic_write(uint32_t reg, uint32_t value);
void apic_enable_local_apic(uint64_t pml4_phys);
void ioapic_map_and_configure(uint64_t pml4_phys, uint32_t gsi, uint8_t vector, uint8_t dest_apic_id);

// ---- ahci.c (AHCI/SATA baca) ----
#define AHCI_VIRT 0xFFFF910000002000ULL  // setelah IOAPIC_VIRT (+0x1000)
#define AHCI_REG_CAP  0x00
#define AHCI_REG_GHC  0x04
#define AHCI_REG_IS   0x08
#define AHCI_REG_PI   0x0C
#define AHCI_REG_VS   0x10
#define AHCI_OK              0

extern int g_ahci_ata_port_count;
void ahci_port_init(volatile uint32_t *hba, uint32_t port);
int ahci_read(uint32_t port_index, uint64_t lba, uint32_t count, uint8_t **out_buf);

// ---- fat32.c (FAT32 baca) ----
void ahci_fat32_probe_and_log(void);
int fat32_find_file(const char *name_83, uint32_t *out_cluster, uint32_t *out_size);
uint8_t * fat32_load_file(uint32_t first_cluster, uint32_t file_size);
void fat32_probe_root_cluster(void);
void fat32_list_root_directory(void);
void fat32_read_file(uint32_t first_cluster, uint32_t file_size);

// ---- e1000.c (driver NIC Intel 8254x) ----
#define E1000_REG_RDT      0x2818
#define E1000_RX_RING_SIZE 64
#define E1000_RXD_STA_DD   0x01
#define E1000_VIRT 0xFFFF910000003000ULL  // setelah AHCI_VIRT (+0x1000)

extern uint8_t g_e1000_mac[6];
extern uint8_t *g_e1000_rx_ring_virt;
extern uint64_t g_e1000_rx_buf_phys[E1000_RX_RING_SIZE];
extern int g_e1000_rx_initialized;
extern uint64_t g_net_tx_ok;
extern uint64_t g_net_tx_fail;
extern volatile uint64_t g_e1000_irq_count;
extern volatile uint64_t g_e1000_irq_spurious;
extern volatile uint32_t g_e1000_irq_last_icr;
extern volatile uint32_t g_e1000_irq_icr_or;
extern volatile uint32_t g_e1000_irq_rirr_or;
extern volatile uint32_t g_e1000_irq_masked;
extern volatile uint32_t g_e1000_irq_last_gsi;
extern volatile uint32_t g_e1000_irq_gsi;
extern uint32_t g_e1000_rx_next;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len);
void e1000_irq_experiment(void);
void e1000_probe_and_log(uint64_t pml4_phys);
void e1000_send_test_packet(void);
void e1000_log_ip(volatile uint8_t *p);
void e1000_log_mac(volatile uint8_t *p);
void crypto_selftest(void);
void auth_load_key(void);

// ---- crypto.c (SHA-256 + HMAC-SHA256) ----
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

extern int g_crypto_ok;
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint32_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t *hash);
void hmac_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *msg, uint32_t msglen, uint8_t *out);

// ---- net.c (ARP/IPv4/ICMP/UDP/TCP) ----
#define NET_UDP_BUDGET_PER_SEC 100
#define NET_UDP_SRC_PER_SEC 20

extern const uint8_t g_net_ip[4];
extern uint32_t g_net_arp_replies_sent;
extern uint64_t g_net_tx_buf_phys;
extern uint32_t g_net_icmp_replies_sent;
extern uint16_t g_net_ip_id;
extern uint32_t g_net_udp_echo_count;
extern uint64_t g_net_udp_dropped;
extern uint64_t g_net_rx_frames;
extern uint64_t g_net_rx_errors;
extern uint64_t g_auth_ok;
extern uint64_t g_auth_denied[5];
extern uint64_t g_chal_issued;
extern uint64_t g_chal_noentropy;
extern uint64_t g_chal_ip_recycled;
extern uint64_t g_priv_ok;
extern uint64_t g_priv_denied[6];
extern uint64_t g_auth_ctr_off;
extern uint64_t g_net_rx_arp;
extern uint64_t g_net_rx_ipv4;
extern uint64_t g_net_rx_other;
extern uint64_t g_net_udp_badsum;
extern uint64_t g_net_udp_src_dropped;
extern uint64_t g_tcp_rx;
extern uint64_t g_tcp_badsum;
extern uint64_t g_tcp_rst_sent;
extern uint64_t g_tcp_conn_open;
extern uint64_t g_tcp_busy;
extern uint64_t g_tcp_rx_bytes;
extern uint64_t g_tcp_timeouts;
extern uint64_t g_tcp_noentropy;
extern uint64_t g_e1000_mpc;
extern uint64_t g_e1000_rnbc;
extern uint64_t g_net_log_muted;
uint16_t net_checksum16(volatile uint8_t *p, uint32_t len);
void e1000_stats_poll(void);
uint16_t net_udp_checksum(const volatile uint8_t *src_ip, const volatile uint8_t *dst_ip, const volatile uint8_t *udp, uint32_t udp_len);
void net_tcp_tick(void);
int net_poll(void);

// ---- kernel.c (dipakai modul lain) ----
#define NET_UDP_CMD_PORT 7778
extern volatile uint64_t timer_ticks;
void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len);

// ---- auth.c (kunci, HMAC, nonce, perintah berprivilege): tanpa simbol baru ----

// ---- kernel.c: perintah (cmd), dipakai auth.c ----
extern uint32_t g_cmd_len;
void cmd_putc(char c);
void cmd_puts(const char *s);
int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name);
void net_cmd_execute(const volatile uint8_t *cmd, uint32_t len);
void net_udp_send_cmd_reply(volatile uint8_t *req, uint32_t ihl);

// ---- sched.c (task, scheduler, semaphore, user task, spawn) ----
#define MAX_TASKS 8

typedef enum {
    TASK_READY,
    TASK_DEAD,
    TASK_SLEEPING,
    TASK_BLOCKED,
} task_status_t;

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

extern task_t tasks[MAX_TASKS];
extern size_t task_count;
extern size_t g_idle_index;
extern volatile bool scheduler_started;
extern size_t current_index;
extern void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp, uint64_t new_pml4_phys);
void task_create(task_t *task, void (*entry_function)(void), uint64_t stack_size);
void task_create_user(task_t *task, uint64_t pml4_phys, uint64_t user_code_vaddr, uint64_t user_stack_vaddr, uint64_t kernel_stack_size, const uint8_t *code, size_t code_len);
task_t * spawn(const uint8_t *image, size_t image_len);
void schedule(void);
void task_exit(void);
void task_sleep(uint64_t ticks);
void task_wait_for(size_t target_index);
void sem_wait(semaphore_t *sem);
void sem_post(semaphore_t *sem);
void task_a_entry(void);
void task_b_entry(void);

// ---- kernel.c: dipakai sched.c ----
extern void enter_usermode(uint64_t entry_vaddr, uint64_t user_stack_top);
extern uint64_t g_current_pml4_phys;
extern uint64_t g_kernel_pml4_phys;


// ---- cmd.c (isi perintah) ----


// ---- kernel.c: dipakai cmd.c ----
#define LOG_RING_SIZE 8192
extern char g_log_ring[LOG_RING_SIZE];
extern uint32_t g_log_head;
extern uint64_t g_log_total;
extern volatile uint64_t g_net_loops;


// ---- trap.c (exception, IRQ, syscall) ----
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
void trigger_breakpoint(void);

// ---- kernel.c: dipakai trap.c ----

void net_rx_tick_wake(void);
void e1000_irq_service(void);

// ---- cpufeat.c (F1.5: fitur CPU dari CPUID) ----
struct cpu_features {
    char vendor[13];
    char hv_vendor[13];
    uint32_t max_leaf;
    uint32_t max_ext_leaf;
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint8_t rdrand, rdseed, nx, smep, smap, umip, pcid;
    uint8_t apic, x2apic, tsc, tsc_invariant, sse2, hypervisor;
};
extern struct cpu_features g_cpu;
void cpu_features_init(void);

// ---- entropy.c (F1.8: kolam entropi + HMAC-DRBG SP 800-90A) ----
// entropy_get() = 0 berarti entropi belum cukup: pemanggil WAJIB menolak.
#define ENTROPY_SRC_TIMER   0
#define ENTROPY_SRC_NIC_IRQ 1
#define ENTROPY_SRC_RX      2
#define ENTROPY_SRC_COUNT   3
typedef struct {
    uint8_t k[32];
    uint8_t v[32];
    uint64_t reseed_counter;
} hmac_drbg_t;
void hmac_drbg_instantiate(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                           const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *pers, uint32_t pers_len);
void hmac_drbg_reseed(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                      const uint8_t *add, uint32_t add_len);
void hmac_drbg_generate(hmac_drbg_t *d, uint8_t *out, uint32_t out_len,
                        const uint8_t *add, uint32_t add_len);
int hmac_drbg_selftest(void);
void entropy_init(void);
void entropy_event(uint32_t src, uint64_t extra);
void entropy_event_tsc(uint32_t src, uint64_t tsc, uint64_t extra);
void entropy_poll(void);
int entropy_get(uint8_t *out, uint32_t len);
extern int g_entropy_ready;
extern uint64_t g_entropy_ready_tick;
extern uint64_t g_entropy_events;
extern uint64_t g_entropy_jitter_bits;
extern uint64_t g_entropy_hw_bits;
extern uint64_t g_entropy_denied;
extern uint64_t g_drbg_reseeds;

// ---- kprintf.c (F1.6: kprintf, ksnprintf, ASSERT) ----
// Format: %s %c %d %u %x %p %%, awalan 'l' = 64-bit untuk d/u/x.
void kprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
size_t ksnprintf(char *buf, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void kprintf_selftest(void);
__attribute__((noreturn)) void kassert_fail(const char *expr, const char *file, int line, const char *func);
#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            kassert_fail(#cond, __FILE__, __LINE__, __func__); \
        } \
    } while (0)

#endif

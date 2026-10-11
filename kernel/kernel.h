#ifndef BMAHOS_KERNEL_H
#define BMAHOS_KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ---- Port I/O ----
static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile (
        "outb %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint8_t inb(uint16_t port)
{
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
    __asm__ volatile (
        "outl %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint32_t inl(uint16_t port)
{
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

#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limine.h>

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

static uint64_t hhdm_offset = 0;

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
static volatile struct limine_rsdp_request rsdp_request = {
    .id = LIMINE_RSDP_REQUEST_ID,
};

extern void isr0(void);
extern void isr13(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr14(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr128(void);
extern void irq32(void);

void kmain(void);

#define PMM_PAGE_SIZE          0x1000ULL
#define PMM_MAX_PHYS_ADDR      0x100000000ULL
#define PMM_MAX_FRAMES         (PMM_MAX_PHYS_ADDR / PMM_PAGE_SIZE)
#define PMM_BITMAP_SIZE        (PMM_MAX_FRAMES / 8ULL)

static uint8_t pmm_bitmap[PMM_BITMAP_SIZE];

static uint64_t pmm_usable_memory = 0;
static uint64_t pmm_usable_frames = 0;
static uint64_t pmm_next_frame = 0;

static void pmm_bitmap_set(uint64_t frame)
{
    pmm_bitmap[frame / 8] |= (uint8_t)(1U << (frame % 8));
}

static void pmm_bitmap_clear(uint64_t frame)
{
    pmm_bitmap[frame / 8] &= (uint8_t)~(1U << (frame % 8));
}

static int pmm_bitmap_test(uint64_t frame)
{
    return (pmm_bitmap[frame / 8] &
            (uint8_t)(1U << (frame % 8))) != 0;
}

static uint64_t pmm_align_up(uint64_t value)
{
    return (value + PMM_PAGE_SIZE - 1) &
           ~(PMM_PAGE_SIZE - 1);
}

static uint64_t pmm_align_down(uint64_t value)
{
    return value & ~(PMM_PAGE_SIZE - 1);
}

static void pmm_init(struct limine_memmap_response *response)
{
    for (uint64_t i = 0; i < PMM_BITMAP_SIZE; i++) {
        pmm_bitmap[i] = 0xFF;
    }

    pmm_usable_memory = 0;
    pmm_usable_frames = 0;
    pmm_next_frame = 0;

    for (uint64_t i = 0; i < response->entry_count; i++) {
        struct limine_memmap_entry *entry = response->entries[i];

        if (entry->type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        uint64_t start = pmm_align_up(entry->base);
        uint64_t end = pmm_align_down(entry->base + entry->length);

        if (end <= start) {
            continue;
        }

        if (start >= PMM_MAX_PHYS_ADDR) {
            continue;
        }

        if (end > PMM_MAX_PHYS_ADDR) {
            end = PMM_MAX_PHYS_ADDR;
        }

        uint64_t length = end - start;
        uint64_t first_frame = start / PMM_PAGE_SIZE;
        uint64_t last_frame = end / PMM_PAGE_SIZE;

        pmm_usable_memory += length;
        pmm_usable_frames += last_frame - first_frame;

        for (uint64_t frame = first_frame;
             frame < last_frame;
             frame++) {
            pmm_bitmap_clear(frame);
        }
    }
}

static uint64_t pmm_alloc(void)
{
    for (uint64_t frame = pmm_next_frame;
         frame < PMM_MAX_FRAMES;
         frame++) {

        if (!pmm_bitmap_test(frame)) {
            pmm_bitmap_set(frame);
            pmm_next_frame = frame + 1;

            return frame * PMM_PAGE_SIZE;
        }
    }

    return 0;
}

static void pmm_free(uint64_t phys_addr)
{
    if (phys_addr == 0) {
        return;
    }

    if ((phys_addr & (PMM_PAGE_SIZE - 1)) != 0) {
        return;
    }

    uint64_t frame = phys_addr / PMM_PAGE_SIZE;

    if (frame >= PMM_MAX_FRAMES) {
        return;
    }

    if (pmm_bitmap_test(frame)) {
        pmm_bitmap_clear(frame);

        if (frame < pmm_next_frame) {
            pmm_next_frame = frame;
        }
    }
}

__attribute__((used, section(".limine_requests_end_marker")))
static volatile uint64_t limine_requests_end_marker[] =
    LIMINE_REQUESTS_END_MARKER;

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

static void serial_write(const char *s);
static void serial_write_hex(uint64_t value);
static void lapic_send_eoi(void);
static void schedule(void);
static void task_exit(void);
static void task_sleep(uint64_t ticks);
static void task_wait_for(size_t target_index);
// Forward declaration struct -- definisi lengkap ada dekat task_t,
// tapi tipenya perlu dikenal compiler di sini untuk sem_wait/sem_post.
typedef struct semaphore semaphore_t;
static void sem_wait(semaphore_t *sem);
static void sem_post(semaphore_t *sem);

// Checkpoint PCI: baca 1 register 32-bit dari PCI configuration space
// lewat Legacy Configuration Mechanism #1 (CONFIG_ADDRESS/CONFIG_DATA,
// port 0xCF8/0xCFC) -- didukung universal di x86 (termasuk VMware),
// tidak butuh parsing tabel ACPI MCFG seperti PCIe Enhanced Config
// Access Mechanism. offset WAJIB word-aligned (kelipatan 4) -- bit
// 1-0 CONFIG_ADDRESS selalu 00, caller yang salah offset akan diam-
// diam dibulatkan ke bawah oleh mask di bawah, bukan error eksplisit.
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

static uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset)
{
    uint32_t address =
        (1U << 31) |
        ((uint32_t)bus << 16) |
        ((uint32_t)device << 11) |
        ((uint32_t)function << 8) |
        ((uint32_t)offset & 0xFC);

    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

// Checkpoint PCI: scan brute-force SELURUH kombinasi bus/device/
// function (256 x 32 x 8 = 65536 probe), TANPA optimisasi multi-
// function header (skip function 1-7 kalau device bukan multi-
// function) -- checkpoint pertama sengaja dibuat sesempit mungkin,
// murni discovery + log, TIDAK ADA pci_device_t/registry/lookup API/
// driver apa pun. Vendor ID == 0xFFFF berarti device tidak ada di
// slot itu (satu-satunya kondisi skip yang kita pakai).
static void pci_scan_and_log(void)
{
    serial_write("PCI: mulai scan bus/device/function...\r\n");

    for (uint32_t bus = 0; bus < 256; bus++) {
        for (uint32_t device = 0; device < 32; device++) {
            for (uint32_t function = 0; function < 8; function++) {
                uint32_t reg0 = pci_config_read32((uint8_t)bus, (uint8_t)device, (uint8_t)function, 0x00);
                uint16_t vendor_id = (uint16_t)(reg0 & 0xFFFF);

                if (vendor_id == 0xFFFF) {
                    continue;
                }

                uint16_t device_id = (uint16_t)((reg0 >> 16) & 0xFFFF);

                uint32_t reg8 = pci_config_read32((uint8_t)bus, (uint8_t)device, (uint8_t)function, 0x08);
                uint8_t prog_if    = (uint8_t)((reg8 >> 8) & 0xFF);
                uint8_t subclass   = (uint8_t)((reg8 >> 16) & 0xFF);
                uint8_t class_code = (uint8_t)((reg8 >> 24) & 0xFF);

                serial_write("PCI: bus=");
                serial_write_hex(bus);
                serial_write(" device=");
                serial_write_hex(device);
                serial_write(" function=");
                serial_write_hex(function);
                serial_write(" vendor=");
                serial_write_hex(vendor_id);
                serial_write(" device_id=");
                serial_write_hex(device_id);
                serial_write(" class=");
                serial_write_hex(class_code);
                serial_write(" subclass=");
                serial_write_hex(subclass);
                serial_write(" prog_if=");
                serial_write_hex(prog_if);
                serial_write("\r\n");
            }
        }
    }

    serial_write("PCI: scan selesai.\r\n");
}

// ============================================================
// ACPI: RSDP -> RSDT/XSDT -> MADT parsing
// Base revision Limine kita = 6, artinya RSDP address dikembalikan
// sebagai virtual (HHDM) -- lihat PROTOCOL.md Base Revision 4:
// "RSDP address is returned as virtual (HHDM) again (physical only
// in base revision 3)." Jadi rsdp_request.response->address bisa
// langsung di-dereference tanpa tambah hhdm_offset.
// ============================================================

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

// Entry type 0: Processor Local APIC
struct acpi_madt_local_apic
{
    struct acpi_madt_entry_header header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));

// Entry type 1: I/O APIC
struct acpi_madt_ioapic
{
    struct acpi_madt_entry_header header;
    uint8_t ioapic_id;
    uint8_t reserved;
    uint32_t ioapic_address;
    uint32_t global_system_interrupt_base;
} __attribute__((packed));

// Entry type 2: Interrupt Source Override
struct acpi_madt_iso
{
    struct acpi_madt_entry_header header;
    uint8_t bus_source;
    uint8_t irq_source;
    uint32_t global_system_interrupt;
    uint16_t flags;
} __attribute__((packed));

static uint64_t g_local_apic_address = 0;
static uint32_t g_ioapic_address = 0;
static uint32_t g_ioapic_id = 0;
static uint32_t g_ioapic_gsi_base = 0;
static uint32_t g_irq0_gsi = 0; // default asumsi: IRQ0 -> GSI0, kecuali ada override

static struct acpi_sdt_header *acpi_find_table(void *root_sdt, int use_xsdt, const char *signature)
{
    struct acpi_sdt_header *root_header = (struct acpi_sdt_header *)root_sdt;
    uint32_t entries_length = root_header->length - sizeof(struct acpi_sdt_header);

    if (use_xsdt)
    {
        uint64_t *entries = (uint64_t *)((uint8_t *)root_sdt + sizeof(struct acpi_sdt_header));
        uint32_t count = entries_length / sizeof(uint64_t);
        for (uint32_t i = 0; i < count; i++)
        {
            struct acpi_sdt_header *table = (struct acpi_sdt_header *)(entries[i] + hhdm_offset);
            if (
                table->signature[0] == signature[0] &&
                table->signature[1] == signature[1] &&
                table->signature[2] == signature[2] &&
                table->signature[3] == signature[3])
            {
                return table;
            }
        }
    }
    else
    {
        uint32_t *entries = (uint32_t *)((uint8_t *)root_sdt + sizeof(struct acpi_sdt_header));
        uint32_t count = entries_length / sizeof(uint32_t);
        for (uint32_t i = 0; i < count; i++)
        {
            struct acpi_sdt_header *table = (struct acpi_sdt_header *)((uint64_t)entries[i] + hhdm_offset);
            if (
                table->signature[0] == signature[0] &&
                table->signature[1] == signature[1] &&
                table->signature[2] == signature[2] &&
                table->signature[3] == signature[3])
            {
                return table;
            }
        }
    }

    return NULL;
}

static void acpi_parse_madt(struct acpi_madt *madt)
{
    g_local_apic_address = madt->local_apic_address;
    serial_write("MADT: Local APIC address = ");
    serial_write_hex(g_local_apic_address);
    serial_write("\r\n");

    uint8_t *entry_ptr = (uint8_t *)madt + sizeof(struct acpi_madt);
    uint8_t *madt_end = (uint8_t *)madt + madt->header.length;

    while (entry_ptr < madt_end)
    {
        struct acpi_madt_entry_header *entry_header = (struct acpi_madt_entry_header *)entry_ptr;

        if (entry_header->entry_type == 0)
        {
            struct acpi_madt_local_apic *lapic = (struct acpi_madt_local_apic *)entry_ptr;
            serial_write("MADT: Local APIC entry -- processor_id=");
            serial_write_hex(lapic->acpi_processor_id);
            serial_write(" apic_id=");
            serial_write_hex(lapic->apic_id);
            serial_write(" flags=");
            serial_write_hex(lapic->flags);
            serial_write("\r\n");
        }
        else if (entry_header->entry_type == 1)
        {
            struct acpi_madt_ioapic *ioapic = (struct acpi_madt_ioapic *)entry_ptr;
            serial_write("MADT: IOAPIC entry -- id=");
            serial_write_hex(ioapic->ioapic_id);
            serial_write(" address=");
            serial_write_hex(ioapic->ioapic_address);
            serial_write(" gsi_base=");
            serial_write_hex(ioapic->global_system_interrupt_base);
            serial_write("\r\n");

            // Asumsi single-IOAPIC system (umum di hardware kelas ini):
            // simpan yang pertama ditemukan.
            if (g_ioapic_address == 0)
            {
                g_ioapic_address = ioapic->ioapic_address;
                g_ioapic_id = ioapic->ioapic_id;
                g_ioapic_gsi_base = ioapic->global_system_interrupt_base;
            }
        }
        else if (entry_header->entry_type == 2)
        {
            struct acpi_madt_iso *iso = (struct acpi_madt_iso *)entry_ptr;
            serial_write("MADT: Interrupt Source Override -- bus_source=");
            serial_write_hex(iso->bus_source);
            serial_write(" irq_source=");
            serial_write_hex(iso->irq_source);
            serial_write(" gsi=");
            serial_write_hex(iso->global_system_interrupt);
            serial_write(" flags=");
            serial_write_hex(iso->flags);
            serial_write("\r\n");

            if (iso->irq_source == 0)
            {
                g_irq0_gsi = iso->global_system_interrupt;
                serial_write("MADT: IRQ0 di-override ke GSI ");
                serial_write_hex(g_irq0_gsi);
                serial_write("\r\n");
            }
        }
        else
        {
            serial_write("MADT: entry type lain (");
            serial_write_hex(entry_header->entry_type);
            serial_write("), diabaikan\r\n");
        }

        entry_ptr += entry_header->entry_length;
    }
}

static void acpi_init(void)
{
    if (rsdp_request.response == NULL)
    {
        serial_write("ACPI: RSDP tidak tersedia (rsdp_request.response == NULL)\r\n");
        return;
    }

    struct acpi_rsdp *rsdp = (struct acpi_rsdp *)rsdp_request.response->address;

    serial_write("ACPI: RSDP ditemukan, revision=");
    serial_write_hex(rsdp->revision);
    serial_write("\r\n");

    struct acpi_madt *madt = NULL;

    if (rsdp->revision >= 2 && rsdp->xsdt_address != 0)
    {
        serial_write("ACPI: menggunakan XSDT di physical ");
        serial_write_hex(rsdp->xsdt_address);
        serial_write("\r\n");
        void *xsdt = (void *)(rsdp->xsdt_address + hhdm_offset);
        madt = (struct acpi_madt *)acpi_find_table(xsdt, 1, "APIC");
    }
    else
    {
        serial_write("ACPI: menggunakan RSDT di physical ");
        serial_write_hex(rsdp->rsdt_address);
        serial_write("\r\n");
        void *rsdt = (void *)((uint64_t)rsdp->rsdt_address + hhdm_offset);
        madt = (struct acpi_madt *)acpi_find_table(rsdt, 0, "APIC");
    }

    if (madt == NULL)
    {
        serial_write("ACPI: MADT (signature APIC) TIDAK DITEMUKAN\r\n");
        return;
    }

    serial_write("ACPI: MADT ditemukan, parsing...\r\n");
    acpi_parse_madt(madt);
}

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1

#define PIC_EOI      0x20

#define PIT_CHANNEL0 0x40
#define PIT_COMMAND  0x43

// Remap PIC supaya IRQ0-7 -> vektor 32-39, IRQ8-15 -> vektor 40-47.
// WAJIB dilakukan sebelum enable interrupt apa pun -- default BIOS
// memetakan IRQ0-7 ke vektor 8-15, yang BENTROK dengan CPU exception
// kita (misal #DF=8, #GP=13) yang sudah diverifikasi di Layer 3.
static inline void io_wait(void)
{
    outb(0x80, 0);
}

static void pic_remap(void)
{
    // Paksa sistem ke PIC mode (bukan APIC/IOAPIC) lewat IMCR.
    // Di banyak sistem UEFI modern (termasuk VMware+OVMF), IRQ
    // secara default diarahkan lewat IOAPIC, sehingga menulis ke
    // port PIC legacy 0x20/0x21 TIDAK berpengaruh sama sekali --
    // interrupt tidak pernah sampai ke CPU meski PIC "terlihat"
    // terkonfigurasi benar. IMCR (port 0x22/0x23) mengembalikan
    // sistem ke mode PIC legacy.
    outb(0x22, 0x70);
    outb(0x23, 0x01);
    io_wait();

    outb(PIC1_COMMAND, 0x11); io_wait();
    outb(PIC2_COMMAND, 0x11); io_wait();

    outb(PIC1_DATA, 0x20); io_wait(); // Master: IRQ0-7 -> vektor 32-39
    outb(PIC2_DATA, 0x28); io_wait(); // Slave:  IRQ8-15 -> vektor 40-47

    outb(PIC1_DATA, 0x04); io_wait(); // Master: slave ada di IRQ2
    outb(PIC2_DATA, 0x02); io_wait(); // Slave: identitas cascade

    outb(PIC1_DATA, 0x01); io_wait(); // mode 8086
    outb(PIC2_DATA, 0x01); io_wait();

    // Mask semua IRQ dulu (0xFF = semua bit 1 = semua di-mask/disable),
    // nanti kita unmask satu-satu sesuai kebutuhan (mulai dari timer).
    outb(PIC1_DATA, 0xFF); io_wait();
    outb(PIC2_DATA, 0xFF); io_wait();
}

// Unmask (enable) satu IRQ tertentu di PIC.
static void pic_unmask_irq(uint8_t irq)
{
    uint16_t port;
    uint8_t mask;

    if (irq < 8) {
        port = PIC1_DATA;
    } else {
        port = PIC2_DATA;
        irq -= 8;
    }

    mask = inb(port);
    mask &= ~(1 << irq);
    outb(port, mask);
}

// WAJIB dipanggil di akhir tiap IRQ handler -- memberi tahu PIC
// bahwa interrupt sudah selesai ditangani, supaya PIC mau kirim
// interrupt berikutnya. Kalau lupa, timer akan berhenti berdetak
// setelah interrupt pertama.
static void pic_send_eoi(uint8_t irq)
{
    if (irq >= 8) {
        outb(PIC2_COMMAND, PIC_EOI);
    }
    outb(PIC1_COMMAND, PIC_EOI);
}

// Set frekuensi PIT. PIT berjalan di clock dasar ~1.193182 MHz,
// jadi divisor = base_clock / frekuensi_diinginkan.
static void pit_init(uint32_t frequency_hz)
{
    uint32_t divisor = 1193182 / frequency_hz;

    outb(PIT_COMMAND, 0x36); // channel 0, mode 3 (square wave), binary
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));        // low byte
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF)); // high byte
}


#define COM1 0x3F8

static void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
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

static void serial_putc(char c)
{
    while (!(inb(COM1 + 5) & 0x20))
        ;

    outb(COM1, (uint8_t)c);
}

// Versi TANPA lock -- dipakai internal oleh fungsi lain yang SUDAH
// pegang lock sendiri (mis. serial_write_hex()), supaya tidak nested
// lock diri sendiri (nested cli aman secara hardware, tapi nested
// irq_save/irq_restore naif bisa salah restore state kalau tidak hati-hati).
static void serial_write_nolock(const char *s)
{
    while (*s)
    {
        serial_putc(*s++);
    }
}

// Versi PUBLIK dengan lock -- pakai ini dari luar (task, dsb.) supaya
// satu pemanggilan serial_write() tidak bisa disisipi task lain
// di tengah-tengah string.
static void serial_write(const char *s)
{
    uint64_t flags = irq_save();
    serial_write_nolock(s);
    irq_restore(flags);
}

static void serial_write_hex(uint64_t value)
{
    static const char hex[] = "0123456789ABCDEF";

    // Lock SEKALI untuk seluruh "0x" + digit-digitnya -- kalau tidak,
    // ada celah antara serial_write("0x") selesai dan loop digit mulai,
    // di mana task lain bisa menyelip di tengah angka hex.
    uint64_t flags = irq_save();

    serial_write_nolock("0x");

    for (int i = 15; i >= 0; i--)
    {
        uint8_t digit = (value >> (i * 4)) & 0xF;
        serial_putc(hex[digit]);
    }

    irq_restore(flags);
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
static bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable);

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
static volatile uint64_t timer_ticks = 0;

// Dipanggil dari irq_common_stub (kernel/interrupt.S) untuk SEMUA
// IRQ. Beda dari exception_dispatcher: TIDAK boleh halt permanen,
// dan WAJIB kirim EOI ke PIC di akhir supaya interrupt berikutnya
// bisa masuk.
void irq_handler(struct exception_context *context)
{
    uint64_t irq_num = context->vector;

    if (irq_num == 0) {
        timer_ticks++;
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

static struct gdt_entry bmahOS_gdt[7];
static struct tss bmahOS_tss;

// Kernel stack statis untuk TSS.RSP0 (dipakai CPU saat transisi
// ring 3 -> ring 0 lewat interrupt/syscall). Static karena kmalloc
// (lewat PMM) belum siap saat gdt_init() dipanggil di kmain().
#define RSP0_STACK_SIZE 16384
static uint8_t rsp0_stack[RSP0_STACK_SIZE];

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

static struct idt_entry bmahOS_idt[256];

_Static_assert(sizeof(struct idt_entry) == 16, "IDT entry size is wrong");
_Static_assert(sizeof(bmahOS_idt) == 4096, "IDT size is wrong");

static void idt_set_entry(
    uint8_t vector,
    uint64_t handler,
    uint16_t selector,
    uint8_t type_attr
)
{
    bmahOS_idt[vector].offset_low =
        (uint16_t)(handler & 0xFFFF);

    bmahOS_idt[vector].selector = selector;
    bmahOS_idt[vector].ist = 0;

    bmahOS_idt[vector].type_attr = type_attr;

    bmahOS_idt[vector].offset_mid =
        (uint16_t)((handler >> 16) & 0xFFFF);

    bmahOS_idt[vector].offset_high =
        (uint32_t)((handler >> 32) & 0xFFFFFFFF);

    bmahOS_idt[vector].reserved = 0;
}

typedef struct
{
    uint8_t  vector;
    uint64_t handler;
} idt_vector_entry_t;

static const idt_vector_entry_t bmahOS_idt_vectors[] = {
    { 0,  (uint64_t)isr0  },
    { 1,  (uint64_t)isr1  },
    { 2,  (uint64_t)isr2  },
    { 3,  (uint64_t)isr3  },
    { 4,  (uint64_t)isr4  },
    { 5,  (uint64_t)isr5  },
    { 6,  (uint64_t)isr6  },
    { 7,  (uint64_t)isr7  },
    { 8,  (uint64_t)isr8  },
    { 9,  (uint64_t)isr9  },
    { 10, (uint64_t)isr10 },
    { 11, (uint64_t)isr11 },
    { 12, (uint64_t)isr12 },
    { 13, (uint64_t)isr13 },
    { 14, (uint64_t)isr14 },
    { 16, (uint64_t)isr16 },
    { 17, (uint64_t)isr17 },
    { 18, (uint64_t)isr18 },
    { 19, (uint64_t)isr19 },
};

static const uint64_t bmahOS_idt_vector_count =
    sizeof(bmahOS_idt_vectors) / sizeof(bmahOS_idt_vectors[0]);

static void idt_init(void)
{
    for (uint64_t i = 0; i < 256; i++)
    {
        bmahOS_idt[i].offset_low = 0;
        bmahOS_idt[i].selector = 0;
        bmahOS_idt[i].ist = 0;
        bmahOS_idt[i].type_attr = 0;
        bmahOS_idt[i].offset_mid = 0;
        bmahOS_idt[i].offset_high = 0;
        bmahOS_idt[i].reserved = 0;
    }

    for (uint64_t i = 0; i < bmahOS_idt_vector_count; i++)
    {
        idt_set_entry(
            bmahOS_idt_vectors[i].vector,
            bmahOS_idt_vectors[i].handler,
            0x08,
            0x8E
        );
    }

    // int 0x80 -- syscall gate. DPL=3 (0xEE) supaya ring 3 boleh
    // trigger tanpa #GP. Selector tetap 0x08 (kernel code) karena
    // handler-nya SELALU jalan di ring 0, terlepas dari ring pemanggil.
    idt_set_entry(128, (uint64_t)isr128, 0x08, 0xEE);
}



static void print_idt_entry0(void)
{
    uint64_t handler =
        ((uint64_t)bmahOS_idt[0].offset_low) |
        ((uint64_t)bmahOS_idt[0].offset_mid << 16) |
        ((uint64_t)bmahOS_idt[0].offset_high << 32);

    serial_write("IDT[0] handler: ");
    serial_write_hex(handler);
    serial_write("\r\n");

    serial_write("IDT[0] selector: ");
    serial_write_hex(bmahOS_idt[0].selector);
    serial_write("\r\n");

    serial_write("IDT[0] type_attr: ");
    serial_write_hex(bmahOS_idt[0].type_attr);
    serial_write("\r\n");
}
static void print_idt_entry32(void)
{
    uint64_t handler =
        ((uint64_t)bmahOS_idt[32].offset_low) |
        ((uint64_t)bmahOS_idt[32].offset_mid << 16) |
        ((uint64_t)bmahOS_idt[32].offset_high << 32);

    serial_write("IDT[32] handler: ");
    serial_write_hex(handler);
    serial_write("\r\n");

    serial_write("IDT[32] selector: ");
    serial_write_hex(bmahOS_idt[32].selector);
    serial_write("\r\n");

    serial_write("IDT[32] type_attr: ");
    serial_write_hex(bmahOS_idt[32].type_attr);
    serial_write("\r\n");
}


_Static_assert(sizeof(struct tss) == 0x68, "TSS size is wrong");
_Static_assert(sizeof(struct gdt_entry) == 8, "GDT entry size is wrong");
_Static_assert(sizeof(bmahOS_gdt) == 56, "GDT size is wrong");

static void gdt_set_entry(
    int index,
    uint8_t access,
    uint8_t granularity
)
{
    bmahOS_gdt[index].limit_low = 0x0000;
    bmahOS_gdt[index].base_low = 0x0000;
    bmahOS_gdt[index].base_middle = 0x00;
    bmahOS_gdt[index].access = access;
    bmahOS_gdt[index].granularity = granularity;
    bmahOS_gdt[index].base_high = 0x00;
}

static void tss_set_descriptor(int index, uint64_t base, uint32_t limit)
{
    uint8_t *descriptor = (uint8_t *)&bmahOS_gdt[index];

    descriptor[0] = (uint8_t)(limit >> 0);
    descriptor[1] = (uint8_t)(limit >> 8);

    descriptor[2] = (uint8_t)(base >> 0);
    descriptor[3] = (uint8_t)(base >> 8);
    descriptor[4] = (uint8_t)(base >> 16);

    descriptor[5] = 0x89;

    descriptor[6] = (uint8_t)((limit >> 16) & 0x0F);

    descriptor[7] = (uint8_t)(base >> 24);

    descriptor[8]  = (uint8_t)(base >> 32);
    descriptor[9]  = (uint8_t)(base >> 40);
    descriptor[10] = (uint8_t)(base >> 48);
    descriptor[11] = (uint8_t)(base >> 56);

    descriptor[12] = 0x00;
    descriptor[13] = 0x00;
    descriptor[14] = 0x00;
    descriptor[15] = 0x00;
}

static void gdt_init(void)
{
    gdt_set_entry(0, 0x00, 0x00);
    gdt_set_entry(1, 0x9B, 0x20);
    gdt_set_entry(2, 0x93, 0x00);
    gdt_set_entry(5, 0xFB, 0x20);
    gdt_set_entry(6, 0xF3, 0x00);

    tss_set_descriptor(
        3,
        (uint64_t)&bmahOS_tss,
        sizeof(bmahOS_tss) - 1
    );

    // Stack tumbuh ke bawah -> RSP0 harus nunjuk ke alamat TERTINGGI
    // dari buffer, bukan awal buffer.
    bmahOS_tss.rsp0 = (uint64_t)&rsp0_stack[RSP0_STACK_SIZE];
}

static void print_bmahOS_gdt(void)
{
    serial_write("bmahOS GDT entries:\r\n");

    for (uint64_t i = 0; i < 5; i++)
    {
        uint64_t descriptor =
            *(volatile uint64_t *)&bmahOS_gdt[i];

        serial_write("bmahOS_GDT[");
        serial_write_hex(i);
        serial_write("] = ");
        serial_write_hex(descriptor);
        serial_write("\r\n");
    }
}

extern void gdt_load_and_reload_asm(const void *gdtr);
extern void tss_load_asm(void);
extern uint64_t tss_read_asm(void);
extern void enter_usermode(uint64_t entry_vaddr, uint64_t user_stack_top);
extern void idt_load_asm(const void *idtr);

static void idt_load(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;

    idtr.limit = sizeof(bmahOS_idt) - 1;
    idtr.base = (uint64_t)&bmahOS_idt[0];

    idt_load_asm(&idtr);
}

static void read_idtr(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;

    __asm__ volatile ("sidt %0" : "=m"(idtr));

    serial_write("IDT limit: ");
    serial_write_hex(idtr.limit);
    serial_write("\r\n");

    serial_write("IDT base: ");
    serial_write_hex(idtr.base);
    serial_write("\r\n");
}

static void gdt_load_and_reload(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;

    gdtr.limit = sizeof(bmahOS_gdt) - 1;
    gdtr.base = (uint64_t)&bmahOS_gdt[0];

    gdt_load_and_reload_asm(&gdtr);
}

static void read_bmahOS_gdtr(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;

    gdtr.limit = sizeof(bmahOS_gdt) - 1;
    gdtr.base = (uint64_t)&bmahOS_gdt[0];

    serial_write("bmahOS GDT limit: ");
    serial_write_hex(gdtr.limit);
    serial_write("\r\n");

    serial_write("bmahOS GDT base: ");
    serial_write_hex(gdtr.base);
    serial_write("\r\n");
}

static void read_segment_registers(void)
{
    uint16_t cs;
    uint16_t ds;
    uint16_t ss;

    __asm__ volatile ("mov %%cs, %0" : "=r"(cs));
    __asm__ volatile ("mov %%ds, %0" : "=r"(ds));
    __asm__ volatile ("mov %%ss, %0" : "=r"(ss));

    serial_write("CS: ");
    serial_write_hex(cs);
    serial_write("\r\n");

    serial_write("DS: ");
    serial_write_hex(ds);
    serial_write("\r\n");

    serial_write("SS: ");
    serial_write_hex(ss);
    serial_write("\r\n");
}


static void read_gdtr(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;

    __asm__ volatile ("sgdt %0" : "=m"(gdtr));

    serial_write("GDT limit: ");
    serial_write_hex(gdtr.limit);
    serial_write("\r\n");

    serial_write("GDT base: ");
    serial_write_hex(gdtr.base);
    serial_write("\r\n");
}

static void read_gdt_entries(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;

    __asm__ volatile ("sgdt %0" : "=m"(gdtr));

    uint64_t entries = (gdtr.limit + 1) / 8;

    serial_write("GDT entries:\r\n");

    for (uint64_t i = 0; i < entries; i++)
    {
        uint64_t descriptor =
            *(volatile uint64_t *)(gdtr.base + (i * 8));

        serial_write("GDT[");
        serial_write_hex(i);
        serial_write("] = ");
        serial_write_hex(descriptor);
        serial_write("\r\n");
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

static uint64_t read_cr3(void)
{
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static void vmm_dump_pml4(uint64_t pml4_phys)
{
    // Konversi physical -> virtual lewat HHDM, supaya CPU
    // bisa baca isinya (CPU tidak bisa akses physical address
    // secara langsung).
    uint64_t *pml4_virt =
        (uint64_t *)(pml4_phys + hhdm_offset);

    serial_write("PML4 non-empty entries:\r\n");

    for (uint64_t i = 0; i < 512; i++) {
        uint64_t entry = pml4_virt[i];

        // Bit 0 = present bit. Skip entry kosong supaya log
        // tidak banjir (PML4 biasanya sebagian besar kosong).
        if ((entry & 0x1) == 0) {
            continue;
        }

        serial_write("  PML4[");
        serial_write_hex(i);
        serial_write("] = ");
        serial_write_hex(entry);
        serial_write("\r\n");
    }
}
#define VMM_FLAG_PRESENT   0x1ULL
#define VMM_FLAG_WRITABLE  0x2ULL
#define VMM_FLAG_NOCACHE   0x10ULL  // PCD bit -- wajib untuk MMIO (Local APIC, IOAPIC)
#define VMM_FLAG_USER      0x4ULL   // US bit -- wajib untuk halaman yang boleh diakses ring 3
#define VMM_ENTRY_ADDR_MASK 0x000FFFFFFFFFF000ULL

static uint64_t vmm_get_or_create_table(uint64_t *table_virt, uint64_t index)
{
    uint64_t entry = table_virt[index];

    if (entry & VMM_FLAG_PRESENT) {
        return entry & VMM_ENTRY_ADDR_MASK;
    }

    uint64_t new_table_phys = pmm_alloc();
    if (new_table_phys == 0) {
        serial_write("VMM: pmm_alloc() FAILED\r\n");
        return 0;
    }

    uint64_t *new_table_virt = (uint64_t *)(new_table_phys + hhdm_offset);
    for (uint64_t i = 0; i < 512; i++) {
        new_table_virt[i] = 0;
    }

    // Tabel perantara SELALU diberi US=1 -- ini standar desain
    // paging x86: izin akhir tetap ditentukan gabungan semua level,
    // jadi US=1 di tabel perantara tidak membuka akses apa pun
    // kalau PTE (leaf) tidak ikut diberi US=1.
    table_virt[index] = new_table_phys | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER;
    return new_table_phys;
}
static void vmm_map(uint64_t pml4_phys, uint64_t vaddr, uint64_t paddr, uint64_t flags)
{
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;
    uint64_t *pml4_virt = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t pdpt_phys = vmm_get_or_create_table(pml4_virt, pml4_idx);
    if (pdpt_phys == 0) return;
    uint64_t *pdpt_virt = (uint64_t *)(pdpt_phys + hhdm_offset);
    uint64_t pd_phys = vmm_get_or_create_table(pdpt_virt, pdpt_idx);
    if (pd_phys == 0) return;
    uint64_t *pd_virt = (uint64_t *)(pd_phys + hhdm_offset);
    uint64_t pt_phys = vmm_get_or_create_table(pd_virt, pd_idx);
    if (pt_phys == 0) return;
    uint64_t *pt_virt = (uint64_t *)(pt_phys + hhdm_offset);
    pt_virt[pt_idx] = (paddr & VMM_ENTRY_ADDR_MASK) | flags;
}

// Layer 8 checkpoint 1 (dormant, belum dipanggil manapun): bikin PML4
// baru untuk SATU user task, cuma berisi entri kernel-shared yang
// diperlukan (HHDM, kernel higher-half, MMIO APIC/IOAPIC, kheap).
// SENGAJA TIDAK menyalin semua 512 entri PML4 -- terbukti lewat
// vmm_dump_pml4() nyata (boot log) bahwa PML4[0x000] mencakup SELURUH
// rentang alamat rendah 0x0-0x7FFFFFFFFF, tempat SEMUA user task
// (USER_CODE_VADDR dkk) berada. Kalau index itu ikut disalin, PML4
// baru akan menunjuk ke PDPT/PD/PT YANG SAMA dengan task lain --
// isolasi nol walau kelihatannya sudah punya PML4 terpisah. Index di
// bawah ini WAJIB diverifikasi ulang lewat vmm_dump_pml4() kalau
// layout memori (HHDM offset, KHEAP_START, dst) berubah di masa
// depan -- ini bukan konstanta arsitektural x86, murni hasil
// observasi layout bmahOS SEKARANG.
#define VMM_SHARED_PML4_IDX_HHDM     0x100  // hhdm_offset region
#define VMM_SHARED_PML4_IDX_APIC1    0x120  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_APIC2    0x122  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_KHEAP    0x130  // KHEAP_START region
#define VMM_SHARED_PML4_IDX_KERNEL   0x1FF  // kernel higher-half (.text/.data)

static uint64_t vmm_clone_kernel_pml4(uint64_t kernel_pml4_phys)
{
    uint64_t new_pml4_phys = pmm_alloc();
    if (new_pml4_phys == 0) {
        serial_write("vmm_clone_kernel_pml4(): pmm_alloc() FAILED\r\n");
        return 0;
    }

    uint64_t *new_pml4_virt = (uint64_t *)(new_pml4_phys + hhdm_offset);
    for (uint64_t i = 0; i < 512; i++) {
        new_pml4_virt[i] = 0;
    }

    uint64_t *kernel_pml4_virt = (uint64_t *)(kernel_pml4_phys + hhdm_offset);

    static const uint64_t shared_indices[] = {
        VMM_SHARED_PML4_IDX_HHDM,
        VMM_SHARED_PML4_IDX_APIC1,
        VMM_SHARED_PML4_IDX_APIC2,
        VMM_SHARED_PML4_IDX_KHEAP,
        VMM_SHARED_PML4_IDX_KERNEL,
    };

    for (uint64_t i = 0; i < sizeof(shared_indices) / sizeof(shared_indices[0]); i++) {
        uint64_t idx = shared_indices[i];
        new_pml4_virt[idx] = kernel_pml4_virt[idx];
    }

    // Index 0 (alamat rendah, tempat user code/stack) SENGAJA
    // dibiarkan 0 (belum present) -- akan terisi fresh saat vmm_map()
    // dipanggil untuk memetakan user code/stack milik task ini,
    // lewat vmm_get_or_create_table() yang otomatis alokasi PDPT/PD/PT
    // baru karena entry-nya belum present di PML4 baru ini.

    return new_pml4_phys;
}

// ===============================================================
// Syscall pointer validation (Layer 7 lanjutan)
//
// vmm_is_user_page(): walk page table READ-ONLY untuk SATU alamat
// (dibulatkan ke awal halaman 4KB). BEDA dari vmm_get_or_create_table()
// yang dipakai vmm_map() -- fungsi ini TIDAK PERNAH mengalokasikan
// tabel baru. Kalau level manapun (PML4/PDPT/PD/PT) belum present,
// itu berarti alamat tersebut PASTI belum pernah di-map -- otomatis
// tidak valid, tidak perlu jalan lebih jauh.
//
// Syarat valid: seluruh level present DAN leaf (PTE) punya bit US=1
// (VMM_FLAG_USER). US=1 di tabel perantara saja TIDAK CUKUP -- x86
// paging AND semua level, tapi untuk tujuan "boleh diakses ring 3",
// yang benar-benar menentukan adalah PTE (leaf), karena tabel
// perantara SELALU diberi US=1 oleh vmm_get_or_create_table() (lihat
// komentarnya) sehingga tidak bisa dipakai membedakan kernel vs user
// page.
// Checkpoint permission: require_writable menambahkan syarat WRITABLE
// DI ATAS syarat USER, bukan menggantikannya -- pemanggil yang minta
// require_writable=true tetap harus lolos cek USER seperti biasa,
// baru kemudian PTE juga wajib punya VMM_FLAG_WRITABLE. Halaman non-
// writable (mis. hipotetis code page read-only) tetap valid diakses
// kalau require_writable=false (dipakai untuk syscall yang membaca
// dari user, seperti SYS_WRITE).
static bool vmm_is_user_page(uint64_t pml4_phys, uint64_t vaddr, bool require_writable)
{
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    uint64_t *pml4_virt = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t pml4_entry = pml4_virt[pml4_idx];
    if ((pml4_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pdpt_phys = pml4_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pdpt_virt = (uint64_t *)(pdpt_phys + hhdm_offset);
    uint64_t pdpt_entry = pdpt_virt[pdpt_idx];
    if ((pdpt_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pd_phys = pdpt_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pd_virt = (uint64_t *)(pd_phys + hhdm_offset);
    uint64_t pd_entry = pd_virt[pd_idx];
    if ((pd_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pt_phys = pd_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pt_virt = (uint64_t *)(pt_phys + hhdm_offset);
    uint64_t pt_entry = pt_virt[pt_idx];
    if ((pt_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    if ((pt_entry & VMM_FLAG_USER) == 0) {
        return false;
    }

    if (require_writable && (pt_entry & VMM_FLAG_WRITABLE) == 0) {
        return false;
    }

    return true;
}

// ptr/len byte-granular dari sudut pandang pemanggil syscall, tapi
// paging bekerja per-halaman (4KB) -- jadi validasi SEMUA halaman
// yang disentuh oleh range [ptr, ptr+len), bukan cuma byte pertama.
static bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable)
{
    if (len == 0) {
        return true;
    }

    uint64_t end = ptr + len;
    if (end < ptr) {
        return false;
    }

    uint64_t page_start = ptr & ~(PMM_PAGE_SIZE - 1);
    uint64_t page_end = (end - 1) & ~(PMM_PAGE_SIZE - 1);

    for (uint64_t page = page_start; page <= page_end; page += PMM_PAGE_SIZE) {
        if (!vmm_is_user_page(pml4_phys, page, require_writable)) {
            return false;
        }
    }

    return true;
}

#define KHEAP_START 0xFFFF980000000000ULL

static uint64_t kheap_current = 0;
static uint64_t kheap_mapped_end = 0;
static uint64_t kheap_pml4_phys = 0;

static void kheap_init(uint64_t pml4_phys)
{
    kheap_pml4_phys = pml4_phys;
    kheap_current = KHEAP_START;
    kheap_mapped_end = KHEAP_START;
}

static void *kmalloc(uint64_t size)
{
    uint64_t total = size + sizeof(uint64_t);
    total = (total + 15) & ~((uint64_t)15);

    while (kheap_current + total > kheap_mapped_end) {
        uint64_t new_frame = pmm_alloc();
        if (new_frame == 0) {
            serial_write("kmalloc: pmm_alloc() FAILED, heap kehabisan memori\r\n");
            return (void *)0;
        }
        vmm_map(kheap_pml4_phys, kheap_mapped_end, new_frame,
                VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE);
        kheap_mapped_end += PMM_PAGE_SIZE;
    }

    uint64_t header_addr = kheap_current;
    uint64_t *header = (uint64_t *)header_addr;
    *header = total;

    kheap_current += total;

    return (void *)(header_addr + sizeof(uint64_t));
}

static void kfree(void *ptr)
{
    if (ptr == (void *)0) {
        return;
    }

    uint64_t data_addr = (uint64_t)ptr;
    uint64_t header_addr = data_addr - sizeof(uint64_t);
    uint64_t *header = (uint64_t *)header_addr;
    uint64_t total = *header;

    if (header_addr + total == kheap_current) {
        kheap_current = header_addr;
        serial_write("kfree: alokasi terakhir, berhasil reclaim\r\n");
    } else {
        serial_write("kfree: bukan alokasi terakhir, tidak bisa reclaim aman (no-op)\r\n");
    }
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
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER);

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
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER);

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
        if (tasks[next_index].status == TASK_READY) {
            found = true;
            break;
        }
    }

    // Semua task DEAD (atau tidak ada yang READY) -- tidak ada yang
    // bisa dijalankan, jangan context switch ke mana pun.
    if (!found) {
        return;
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
    if (tasks[next_index].is_user_task || tasks[prev_index].is_user_task) {
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

// ============================================================
// Local APIC & IOAPIC
// Alamat MMIO (0xFEE00000 / 0xFEC00000) TIDAK dipetakan oleh HHDM
// Limine (HHDM cuma memetakan region usable/reclaimable/module/
// framebuffer), jadi kita map manual pakai vmm_map() dengan flag
// NOCACHE (PCD) karena ini device MMIO, bukan RAM biasa.
// ============================================================

#define LAPIC_VIRT  0xFFFF910000000000ULL
#define IOAPIC_VIRT 0xFFFF910000001000ULL

#define LAPIC_REG_ID   0x20
#define LAPIC_REG_SVR  0xF0
#define LAPIC_REG_EOI  0xB0

#define IOAPIC_REG_IOREGSEL 0x00
#define IOAPIC_REG_IOWIN    0x10
#define IOAPIC_REDTBL_BASE  0x10

// Checkpoint AHCI (discovery): B/D/F di-HARDCODE berdasarkan hasil
// nyata pci_scan_and_log() di VMware (bus=2 device=4 function=0,
// vendor=0x15AD VMware, class=0x01 subclass=0x06 prog_if=0x01 = AHCI
// SATA). UTANG TEKNIS EKSPLISIT: nanti perlu diganti pencarian
// otomatis (scan ulang cari class/subclass/prog_if yang cocok),
// supaya tidak rapuh kalau konfigurasi VM atau hardware fisik beda.
#define AHCI_PCI_BUS      2
#define AHCI_PCI_DEVICE   4
#define AHCI_PCI_FUNCTION 0
#define AHCI_BAR5_OFFSET  0x24

#define AHCI_VIRT 0xFFFF910000002000ULL  // setelah IOAPIC_VIRT (+0x1000)

#define AHCI_REG_CAP  0x00
#define AHCI_REG_GHC  0x04
#define AHCI_REG_IS   0x08
#define AHCI_REG_PI   0x0C
#define AHCI_REG_VS   0x10

static uint32_t lapic_read(uint32_t reg)
{
    volatile uint32_t *ptr = (volatile uint32_t *)(LAPIC_VIRT + reg);
    return *ptr;
}

static void lapic_write(uint32_t reg, uint32_t value)
{
    volatile uint32_t *ptr = (volatile uint32_t *)(LAPIC_VIRT + reg);
    *ptr = value;
}

// LAPIC EOI: BEDA dari pic_send_eoi() (legacy 8259 PIC). Interrupt
// yang datang lewat IOAPIC/LAPIC WAJIB di-EOI lewat register LAPIC
// ini (offset 0xB0), bukan port PIC lama -- kalau salah, LAPIC ISR
// bit untuk vector itu tidak pernah clear, dan interrupt berikutnya
// tidak akan pernah dikirim lagi (macet setelah 1x).
static void lapic_send_eoi(void)
{
    lapic_write(LAPIC_REG_EOI, 0);
}

static uint32_t ioapic_read(uint32_t reg)
{
    volatile uint32_t *regsel = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOREGSEL);
    volatile uint32_t *win    = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOWIN);
    *regsel = reg;
    return *win;
}

static void ioapic_write(uint32_t reg, uint32_t value)
{
    volatile uint32_t *regsel = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOREGSEL);
    volatile uint32_t *win    = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOWIN);
    *regsel = reg;
    *win = value;
}

// Panggil setelah acpi_init() sukses (g_local_apic_address dan
// g_ioapic_address sudah terisi).
static void apic_enable_local_apic(uint64_t pml4_phys)
{
    if (g_local_apic_address == 0)
    {
        serial_write("APIC: Local APIC address tidak diketahui, skip\r\n");
        return;
    }

    vmm_map(pml4_phys, LAPIC_VIRT, g_local_apic_address,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE);

    uint32_t id = lapic_read(LAPIC_REG_ID);
    serial_write("LAPIC: mapped, ID register = ");
    serial_write_hex(id);
    serial_write("\r\n");

    // Spurious Interrupt Vector Register: bit 8 = APIC software enable,
    // bit 0-7 = spurious vector (konvensi umum: 0xFF).
    uint32_t svr = lapic_read(LAPIC_REG_SVR);
    svr |= (1 << 8);
    svr = (svr & ~0xFFu) | 0xFF;
    lapic_write(LAPIC_REG_SVR, svr);

    serial_write("LAPIC: enabled via SVR (software enable bit + spurious vector 0xFF)\r\n");
}

// Program IOAPIC redirection table entry untuk GSI tertentu supaya
// interrupt itu diarahkan ke 'vector', destination = Local APIC ID
// 'dest_apic_id', unmasked, physical delivery mode, active-high edge
// (default 0 untuk polarity/trigger bit -- cocok dengan ISO flags 0x5
// yang kita lihat untuk IRQ0->GSI2 di boot log).
static void ioapic_map_and_configure(uint64_t pml4_phys, uint32_t gsi, uint8_t vector, uint8_t dest_apic_id)
{
    if (g_ioapic_address == 0)
    {
        serial_write("APIC: IOAPIC address tidak diketahui, skip\r\n");
        return;
    }

    vmm_map(pml4_phys, IOAPIC_VIRT, g_ioapic_address,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE);

    uint32_t ioapic_id_reg = ioapic_read(0x00);
    serial_write("IOAPIC: mapped, ID register = ");
    serial_write_hex(ioapic_id_reg);
    serial_write("\r\n");

    uint32_t redtbl_index = IOAPIC_REDTBL_BASE + (gsi * 2);

    uint32_t low = vector; // delivery mode=000 (fixed), dest mode=0 (physical),
                           // polarity=0 (active high), trigger=0 (edge), mask=0
    uint32_t high = ((uint32_t)dest_apic_id) << 24;

    ioapic_write(redtbl_index, low);
    ioapic_write(redtbl_index + 1, high);

    serial_write("IOAPIC: GSI ");
    serial_write_hex(gsi);
    serial_write(" -> vector ");
    serial_write_hex(vector);
    serial_write(" -> dest APIC ID ");
    serial_write_hex(dest_apic_id);
    serial_write(" (redirection table diprogram)\r\n");
}

// Checkpoint AHCI (discovery): map BAR5 (ABAR) ke virtual seperti
// LAPIC/IOAPIC, baca register generik HBA (CAP/GHC/IS/PI/VS), log ke
// serial. MURNI observasi -- TIDAK ADA command list, FIS, port init,
// atau baca/tulis sector apa pun di checkpoint ini. Port yang benar-
// benar punya device terpasang bisa dilihat dari bit PI yang set DAN
// PxSSTS port itu (belum dibaca di checkpoint ini -- checkpoint
// berikutnya).
static struct {
    volatile uint32_t *hba;
    uint32_t port;
    uint64_t cmd_table_phys;
    uint8_t *cmd_table_virt;
    int initialized;
} g_ahci_ata_port;

static void ahci_port_init(volatile uint32_t *hba, uint32_t port)
{
    uint32_t port_base = 0x100 + (port * 0x80);

    volatile uint32_t *pclb  = &hba[(port_base + 0x00) / 4];
    volatile uint32_t *pclbu = &hba[(port_base + 0x04) / 4];
    volatile uint32_t *pfb   = &hba[(port_base + 0x08) / 4];
    volatile uint32_t *pfbu  = &hba[(port_base + 0x0C) / 4];
    volatile uint32_t *pis   = &hba[(port_base + 0x10) / 4];
    volatile uint32_t *pcmd  = &hba[(port_base + 0x18) / 4];
    volatile uint32_t *ptfd  = &hba[(port_base + 0x20) / 4];

    serial_write("AHCI: port_init start, port ");
    serial_write_hex(port);
    serial_write("\r\n");

    uint32_t cmd = *pcmd;

    if (cmd & (1u << 0)) {
        cmd &= ~(1u << 0);
        *pcmd = cmd;
    }

    while (*pcmd & (1u << 15)) {
        /* poll PxCMD.CR sampai 0 - TIDAK ADA TIMEOUT, utang teknis */
    }

    cmd = *pcmd;

    if (cmd & (1u << 4)) {
        cmd &= ~(1u << 4);
        *pcmd = cmd;
    }

    while (*pcmd & (1u << 14)) {
        /* poll PxCMD.FR sampai 0 - TIDAK ADA TIMEOUT, utang teknis */
    }

    serial_write("AHCI: port_init: port stopped (CR=0, FR=0)\r\n");

    uint64_t cmd_list_phys  = pmm_alloc();
    uint64_t fis_phys       = pmm_alloc();
    uint64_t cmd_table_phys = pmm_alloc();

    if (cmd_list_phys == 0 || fis_phys == 0 || cmd_table_phys == 0) {
        serial_write("AHCI: port_init: FATAL - pmm_alloc gagal\r\n");
        for (;;) {
            __asm__ volatile ("hlt");
        }
    }

    uint8_t *cmd_list_virt  = (uint8_t *)(cmd_list_phys + hhdm_offset);
    uint8_t *fis_virt       = (uint8_t *)(fis_phys + hhdm_offset);
    uint8_t *cmd_table_virt = (uint8_t *)(cmd_table_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        cmd_list_virt[i] = 0;
        fis_virt[i] = 0;
        cmd_table_virt[i] = 0;
    }

    uint32_t *cmd_header0 = (uint32_t *)cmd_list_virt;
    cmd_header0[2] = (uint32_t)(cmd_table_phys & 0xFFFFFFFFu);
    cmd_header0[3] = (uint32_t)(cmd_table_phys >> 32);

    *pclb  = (uint32_t)(cmd_list_phys & 0xFFFFFFFFu);
    *pclbu = (uint32_t)(cmd_list_phys >> 32);
    *pfb   = (uint32_t)(fis_phys & 0xFFFFFFFFu);
    *pfbu  = (uint32_t)(fis_phys >> 32);

    uint32_t is_val = *pis;
    *pis = is_val;

    cmd = *pcmd;
    cmd |= (1u << 4);
    *pcmd = cmd;

    cmd = *pcmd;
    cmd |= (1u << 0);
    *pcmd = cmd;

    uint32_t tfd = *ptfd;

    serial_write("AHCI: port_init: PxTFD=");
    serial_write_hex(tfd);
    serial_write("\r\n");

    if (tfd & 0x1) {
        serial_write("AHCI: port_init: WARNING - TFD.ERR set\r\n");
    }

    serial_write("AHCI: port_init: done, port ready (CLB=");
    serial_write_hex(cmd_list_phys);
    serial_write(" FB=");
    serial_write_hex(fis_phys);
    serial_write(" CTBA=");
    serial_write_hex(cmd_table_phys);
    serial_write(")\r\n");

    g_ahci_ata_port.hba = hba;
    g_ahci_ata_port.port = port;
    g_ahci_ata_port.cmd_table_phys = cmd_table_phys;
    g_ahci_ata_port.cmd_table_virt = cmd_table_virt;
    g_ahci_ata_port.initialized = 1;
}

#define AHCI_OK              0
#define AHCI_ERR_LBA        -1
#define AHCI_ERR_COUNT      -2
#define AHCI_ERR_ALLOC      -3
#define AHCI_ERR_NOT_INIT   -4
#define AHCI_ERR_DEVICE     -5

// Block-device style read: LBA + jumlah sektor -> buffer virtual (HHDM).
// count dibatasi 1..8 (1 halaman fisik = 4096 byte = 8 sektor 512 byte),
// karena buffer dialokasikan sebagai SATU frame pmm_alloc() -- dua
// pmm_alloc() berturut-turut TIDAK dijamin contiguous secara fisik,
// jadi kita sengaja tidak mendukung count > 8 di checkpoint ini
// (utang teknis eksplisit, bukan lupa: perlu multi-PRDT/scatter-gather
// untuk mendukung lebih dari 1 halaman).
static int ahci_read(uint64_t lba, uint32_t count, uint8_t **out_buf)
{
    if (!g_ahci_ata_port.initialized) {
        return AHCI_ERR_NOT_INIT;
    }

    if (count == 0 || count > 8) {
        return AHCI_ERR_COUNT;
    }

    uint64_t lba_end = lba + (uint64_t)(count - 1);

    if (lba_end > 0x0000FFFFFFFFFFFFULL) {
        return AHCI_ERR_LBA;
    }

    volatile uint32_t *hba = g_ahci_ata_port.hba;
    uint32_t port = g_ahci_ata_port.port;
    uint32_t port_base = 0x100 + (port * 0x80);

    volatile uint32_t *pci_reg = &hba[(port_base + 0x38) / 4];
    volatile uint32_t *ptfd    = &hba[(port_base + 0x20) / 4];
    volatile uint32_t *pclb    = &hba[(port_base + 0x00) / 4];

    uint64_t data_buf_phys = pmm_alloc();

    if (data_buf_phys == 0) {
        return AHCI_ERR_ALLOC;
    }

    uint8_t *data_buf_virt = (uint8_t *)(data_buf_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        data_buf_virt[i] = 0xAA;
    }

    uint8_t *cmd_table_virt = g_ahci_ata_port.cmd_table_virt;

    for (uint64_t i = 0; i < 0x90; i++) {
        cmd_table_virt[i] = 0;
    }

    uint32_t byte_count = count * 512u;

    cmd_table_virt[0x00] = 0x27;
    cmd_table_virt[0x01] = 0x80;
    cmd_table_virt[0x02] = 0x25;
    cmd_table_virt[0x03] = 0x00;
    cmd_table_virt[0x04] = (uint8_t)((lba >> 0) & 0xFF);
    cmd_table_virt[0x05] = (uint8_t)((lba >> 8) & 0xFF);
    cmd_table_virt[0x06] = (uint8_t)((lba >> 16) & 0xFF);
    cmd_table_virt[0x07] = 0x40;
    cmd_table_virt[0x08] = (uint8_t)((lba >> 24) & 0xFF);
    cmd_table_virt[0x09] = (uint8_t)((lba >> 32) & 0xFF);
    cmd_table_virt[0x0A] = (uint8_t)((lba >> 40) & 0xFF);
    cmd_table_virt[0x0B] = 0x00;
    cmd_table_virt[0x0C] = (uint8_t)(count & 0xFF);
    cmd_table_virt[0x0D] = (uint8_t)((count >> 8) & 0xFF);
    cmd_table_virt[0x0E] = 0x00;
    cmd_table_virt[0x0F] = 0x00;

    uint32_t *prdt0 = (uint32_t *)(cmd_table_virt + 0x80);
    prdt0[0] = (uint32_t)(data_buf_phys & 0xFFFFFFFFu);
    prdt0[1] = (uint32_t)(data_buf_phys >> 32);
    prdt0[2] = 0;
    prdt0[3] = (byte_count - 1);

    uint64_t cmd_list_phys_current = (uint64_t)(*pclb);
    uint32_t *header0 = (uint32_t *)(cmd_list_phys_current + hhdm_offset);

    header0[0] = 5u;
    header0[0] |= (1u << 16);
    header0[1] = 0;

    *pci_reg = (1u << 0);

    while (*pci_reg & (1u << 0)) {
        /* poll PxCI sampai 0 - TIDAK ADA TIMEOUT, utang teknis */
    }

    uint32_t tfd = *ptfd;

    if (tfd & 0x1) {
        return AHCI_ERR_DEVICE;
    }

    *out_buf = data_buf_virt;

    return AHCI_OK;
}

static void ahci_probe_and_log(uint64_t pml4_phys)
{
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
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE);

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

            uint8_t *test_buf = 0;
            int rc = ahci_read(0, 1, &test_buf);

            serial_write("AHCI: ahci_read(lba=0, count=1) rc=");
            serial_write_hex((uint64_t)(int64_t)rc);
            serial_write("\r\n");

            if (rc == AHCI_OK) {
                serial_write("AHCI: ahci_read: first 8 bytes = ");
                for (int j = 0; j < 8; j++) {
                    serial_write_hex(test_buf[j]);
                    serial_write(" ");
                }
                serial_write("\r\n");
            }

            uint8_t *test_buf2 = 0;
            int rc2 = ahci_read(0, 2, &test_buf2);

            serial_write("AHCI: ahci_read(lba=0, count=2) rc=");
            serial_write_hex((uint64_t)(int64_t)rc2);
            serial_write("\r\n");

            if (rc2 == AHCI_OK) {
                serial_write("AHCI: ahci_read: byte offset 512 (awal sektor ke-2) = ");
                serial_write_hex(test_buf2[512]);
                serial_write("\r\n");
            }

            int rc3 = ahci_read(0, 9, &test_buf2);

            serial_write("AHCI: ahci_read(lba=0, count=9, HARUS DITOLAK) rc=");
            serial_write_hex((uint64_t)(int64_t)rc3);
            serial_write("\r\n");
        }
    }
}

void kmain(void)
{
    serial_init();

    pci_scan_and_log();

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
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER);

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
    ioapic_map_and_configure(pml4_phys, g_irq0_gsi, 32, 0);
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

    serial_write("Task A, B, dan user task dibuat, mulai jalankan lewat scheduler...\r\n");
    serial_write("\r\n");

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

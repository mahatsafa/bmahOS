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

static void serial_write(const char *s);
static void serial_write_hex(uint64_t value);
static void lapic_send_eoi(void);
static void schedule(void);

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

void exception_dispatcher(struct exception_context *context)
{
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

static struct gdt_entry bmahOS_gdt[5];
static struct tss bmahOS_tss;

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
_Static_assert(sizeof(bmahOS_gdt) == 40, "GDT size is wrong");

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

    tss_set_descriptor(
        3,
        (uint64_t)&bmahOS_tss,
        sizeof(bmahOS_tss) - 1
    );
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

    table_virt[index] = new_table_phys | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE;
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
extern void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp);

// TASK_READY: task valid, boleh dipilih scheduler.
// TASK_DEAD: task sudah selesai, scheduler WAJIB melewatinya --
// task menandai dirinya sendiri DEAD di akhir entry function-nya
// (lihat task_a_entry()/task_b_entry()).
typedef enum {
    TASK_READY,
    TASK_DEAD,
} task_status_t;

typedef struct {
    uint64_t rsp;
    task_status_t status;
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
}
#define MAX_TASKS 8

static task_t tasks[MAX_TASKS];
static size_t task_count = 0;
static volatile bool scheduler_started = false;
static size_t current_index = 0;

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

    size_t prev_index = current_index;
    current_index = next_index;

    context_switch(&tasks[prev_index].rsp, tasks[next_index].rsp);
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
    }
    serial_write("Task A selesai\r\n");

    // Tandai diri sendiri DEAD supaya scheduler melewati task ini
    // di rotasi round-robin berikutnya (lihat schedule()). current_index
    // masih menunjuk ke task ini sendiri saat baris ini dieksekusi.
    tasks[current_index].status = TASK_DEAD;
    for (;;) {
        __asm__ volatile ("hlt");
    }
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

    // Tandai diri sendiri DEAD supaya scheduler melewati task ini
    // di rotasi round-robin berikutnya (lihat schedule()). current_index
    // masih menunjuk ke task ini sendiri saat baris ini dieksekusi.
    tasks[current_index].status = TASK_DEAD;
    for (;;) {
        __asm__ volatile ("hlt");
    }
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







void kmain(void)
{
    serial_init();

    gdt_init();

    serial_write("TSS descriptor BEFORE LTR:\r\n");
    print_bmahOS_gdt();
    gdt_load_and_reload();

    tss_load_asm();

    uint64_t tr = tss_read_asm();

    serial_write("TR: ");
    serial_write_hex(tr);
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
    serial_write("=== ACPI: mencari MADT untuk info Local APIC/IOAPIC ===\r\n");
    acpi_init();
    serial_write("=== APIC: enable Local APIC + program IOAPIC redirection ===\r\n");
    apic_enable_local_apic(pml4_phys);
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

    serial_write("Task scheduling test: membuat task A dan B...\r\n");

    task_create(&tasks[0], task_a_entry, 4096);
    task_create(&tasks[1], task_b_entry, 4096);
    task_count = 2;

    serial_write("Task A dan B dibuat, mulai jalankan Task A...\r\n");
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
    context_switch(&kernel_dummy_task.rsp, tasks[0].rsp);

    serial_write("ERROR: kembali ke kmain() setelah task selesai (tidak diharapkan)\r\n");
    serial_write("ABOUT TO TRIGGER #BP\r\n");
    trigger_breakpoint();
    serial_write("ERROR: #BP DID NOT OCCUR\r\n");

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

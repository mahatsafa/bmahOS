#include <stdint.h>
#include <stddef.h>
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

__attribute__((used, section(".limine_requests")))
static volatile struct limine_memmap_request memmap_request = {
    .id = LIMINE_MEMMAP_REQUEST_ID,
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

static void serial_putc(char c)
{
    while (!(inb(COM1 + 5) & 0x20))
        ;

    outb(COM1, (uint8_t)c);
}

static void serial_write(const char *s)
{
    while (*s)
    {
        serial_putc(*s++);
    }
}

static void serial_write_hex(uint64_t value)
{
    static const char hex[] = "0123456789ABCDEF";

    serial_write("0x");

    for (int i = 15; i >= 0; i--)
    {
        uint8_t digit = (value >> (i * 4)) & 0xF;
        serial_putc(hex[digit]);
    }
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

    serial_write("ABOUT TO TRIGGER #PF\r\n");
    trigger_page_fault();
    serial_write("ERROR: #PF DID NOT OCCUR\r\n");

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

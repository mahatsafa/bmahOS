#include <stdint.h>
#include <stddef.h>
#include <limine.h>

void kmain(void);

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

    serial_write("bmahOS booted!\r\n");
    serial_write("kernel: ");
    serial_write_hex(0xFFFFFFFF80000000ULL);
    serial_write("\r\n");

    read_segment_registers();
    read_gdtr();
    read_gdt_entries();

    read_bmahOS_gdtr();

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

#include "kernel.h"

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

struct gdt_entry bmahOS_gdt[7];
struct tss bmahOS_tss;

// Kernel stack statis untuk TSS.RSP0 (dipakai CPU saat transisi
// ring 3 -> ring 0 lewat interrupt/syscall). Static karena kmalloc
// (lewat PMM) belum siap saat gdt_init() dipanggil di kmain().
#define RSP0_STACK_SIZE 16384
static uint8_t rsp0_stack[RSP0_STACK_SIZE];

struct idt_entry bmahOS_idt[256];

_Static_assert(sizeof(struct idt_entry) == 16, "IDT entry size is wrong");
_Static_assert(sizeof(bmahOS_idt) == 4096, "IDT size is wrong");

void idt_set_entry(
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

void idt_init(void)
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



void print_idt_entry0(void)
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
void print_idt_entry32(void)
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

void gdt_init(void)
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

void print_bmahOS_gdt(void)
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
extern void idt_load_asm(const void *idtr);

void idt_load(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idtr;

    idtr.limit = sizeof(bmahOS_idt) - 1;
    idtr.base = (uint64_t)&bmahOS_idt[0];

    idt_load_asm(&idtr);
}

void read_idtr(void)
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

void gdt_load_and_reload(void)
{
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) gdtr;

    gdtr.limit = sizeof(bmahOS_gdt) - 1;
    gdtr.base = (uint64_t)&bmahOS_gdt[0];

    gdt_load_and_reload_asm(&gdtr);
}

void read_bmahOS_gdtr(void)
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

void read_segment_registers(void)
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


void read_gdtr(void)
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

void read_gdt_entries(void)
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

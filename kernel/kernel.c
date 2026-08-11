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

static void serial_write(const char *s)
{
    while (*s)
    {
        while (!(inb(COM1 + 5) & 0x20))
            ;

        outb(COM1, (uint8_t)*s++);
    }
}

void kmain(void)
{
    serial_init();

    outb(COM1, 'A');

    for (;;) {
        __asm__ volatile ("hlt");
    }
}

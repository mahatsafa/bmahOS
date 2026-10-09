#include "kernel.h"

#define COM1 0x3F8

void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

// B4b: 1 = karakter hanya masuk ring log, tidak dikirim ke UART. Diset net
// task saat jatah log paket per detik habis (lihat net_rx_dispatch()).
volatile int g_serial_mute = 0;

void serial_putc(char c)
{
    if (!g_serial_mute) {
        while (!(inb(COM1 + 5) & 0x20))
            ;

        outb(COM1, (uint8_t)c);
    }

    uint64_t lf = irq_save();
    log_capture(c);
    irq_restore(lf);
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
void serial_write(const char *s)
{
    uint64_t flags = irq_save();
    serial_write_nolock(s);
    irq_restore(flags);
}

void serial_write_hex(uint64_t value)
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

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

// SMP-1: kunci serial reentran. Pemilik = indeks CPU; CPU yang sama boleh masuk lagi (serial_write ->
// serial_putc, kprintf -> serial_putc). Interrupt lokal dimatikan selama dipegang, jadi ISR di CPU
// yang sama tidak pernah menunggu kunci yang dipegang kode yang ia interupsi.
static spinlock_t g_serial_lock = SPINLOCK_INIT;
static volatile int g_serial_owner = -1;
static uint32_t g_serial_depth;

uint64_t serial_lock(void)
{
    uint64_t flags = irq_save();
    int me = cpu_index();

    // me == MAX_CPUS (ID LAPIC tidak dikenal) tidak pernah dianggap pemilik: tanpa reentran.
    if (me < MAX_CPUS && g_serial_owner == me && g_serial_depth > 0) {
        g_serial_depth++;
    } else {
        spin_lock(&g_serial_lock);
        g_serial_owner = me;
        g_serial_depth = 1;
    }
    return flags;
}

void serial_unlock(uint64_t flags)
{
    // Defensif: hanya pemilik yang melepas (setelah serial_lock_reset di panic, CPU lain
    // yang masih menelepon unlock tidak boleh merusak kunci pemenang panic).
    if (g_serial_depth == 0 || g_serial_owner != cpu_index()) {
        irq_restore(flags);
        return;
    }
    if (--g_serial_depth == 0) {
        g_serial_owner = -1;
        spin_unlock(&g_serial_lock);
    }
    irq_restore(flags);
}

// Panic: CPU lain mungkin berhenti sambil memegang kunci. Dipanggil dengan interrupt mati.
void serial_lock_reset(void)
{
    g_serial_lock.v = 0;
    g_serial_owner = -1;
    g_serial_depth = 0;
}

void serial_putc(char c)
{
    uint64_t sl = serial_lock();

    if (!g_serial_mute) {
        while (!(inb(COM1 + 5) & 0x20))
            ;

        outb(COM1, (uint8_t)c);
    }

    if (!g_serial_mute) {
        fbcon_putc(c);   // P1: layar ikut UART (termasuk mute B4b)
    }
    log_capture(c);
    serial_unlock(sl);
}

// D5: hanya ke UART (tidak masuk ring log), untuk baris AUDIT. Ikut g_serial_mute.
void serial_write_nolog(const char *s)
{
    if (g_serial_mute) {
        return;
    }

    uint64_t flags = serial_lock();

    while (*s) {
        while (!(inb(COM1 + 5) & 0x20))
            ;

        outb(COM1, (uint8_t)*s++);
    }

    serial_unlock(flags);
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
    uint64_t flags = serial_lock();
    serial_write_nolock(s);
    serial_unlock(flags);
}

void serial_write_hex(uint64_t value)
{
    static const char hex[] = "0123456789ABCDEF";

    // Lock SEKALI untuk seluruh "0x" + digit-digitnya -- kalau tidak,
    // ada celah antara serial_write("0x") selesai dan loop digit mulai,
    // di mana task lain bisa menyelip di tengah angka hex.
    uint64_t flags = serial_lock();

    serial_write_nolock("0x");

    for (int i = 15; i >= 0; i--)
    {
        uint8_t digit = (value >> (i * 4)) & 0xF;
        serial_putc(hex[digit]);
    }

    serial_unlock(flags);
}

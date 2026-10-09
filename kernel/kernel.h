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

#endif

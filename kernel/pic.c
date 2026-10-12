#include "kernel.h"

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

void pic_remap(void)
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
// PIT-1: mode 2 (rate generator), satu pulsa per periode. Mode 3 (square
// wave) di QEMU q35 menghasilkan 2 interrupt per periode lewat IOAPIC
// (terukur 200 tick/s untuk 100 Hz), jadi semua "detik" kernel cuma 0,5 s.
void pit_init(uint32_t frequency_hz)
{
    uint32_t divisor = 1193182 / frequency_hz;

    outb(PIT_COMMAND, 0x34); // channel 0, lobyte/hibyte, mode 2 (rate generator), binary
    outb(PIT_CHANNEL0, (uint8_t)(divisor & 0xFF));        // low byte
    outb(PIT_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF)); // high byte
}

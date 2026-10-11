#include "kernel.h"

// ============================================================
// Local APIC & IOAPIC
// Alamat MMIO (0xFEE00000 / 0xFEC00000) TIDAK dipetakan oleh HHDM
// Limine (HHDM cuma memetakan region usable/reclaimable/module/
// framebuffer), jadi kita map manual pakai vmm_map() dengan flag
// NOCACHE (PCD) karena ini device MMIO, bukan RAM biasa.
// ============================================================

#define IOAPIC_VIRT 0xFFFF910000001000ULL

#define LAPIC_REG_ID   0x20
#define LAPIC_REG_SVR  0xF0
#define LAPIC_REG_EOI  0xB0

#define IOAPIC_REG_IOREGSEL 0x00
#define IOAPIC_REG_IOWIN    0x10

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
void lapic_send_eoi(void)
{
    lapic_write(LAPIC_REG_EOI, 0);
}

uint32_t ioapic_read(uint32_t reg)
{
    volatile uint32_t *regsel = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOREGSEL);
    volatile uint32_t *win    = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOWIN);
    *regsel = reg;
    return *win;
}

void ioapic_write(uint32_t reg, uint32_t value)
{
    volatile uint32_t *regsel = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOREGSEL);
    volatile uint32_t *win    = (volatile uint32_t *)(IOAPIC_VIRT + IOAPIC_REG_IOWIN);
    *regsel = reg;
    *win = value;
}

// Panggil setelah acpi_init() sukses (g_local_apic_address dan
// g_ioapic_address sudah terisi).
void apic_enable_local_apic(uint64_t pml4_phys)
{
    if (g_local_apic_address == 0)
    {
        serial_write("APIC: Local APIC address tidak diketahui, skip\r\n");
        return;
    }

    vmm_map(pml4_phys, LAPIC_VIRT, g_local_apic_address,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE | VMM_FLAG_NX);

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
void ioapic_map_and_configure(uint64_t pml4_phys, uint32_t gsi, uint8_t vector, uint8_t dest_apic_id)
{
    if (g_ioapic_address == 0)
    {
        serial_write("APIC: IOAPIC address tidak diketahui, skip\r\n");
        return;
    }

    vmm_map(pml4_phys, IOAPIC_VIRT, g_ioapic_address,
            VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE | VMM_FLAG_NX);

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

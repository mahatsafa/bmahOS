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
#define LAPIC_REG_ICR_LO 0x300
#define LAPIC_REG_ICR_HI 0x310
#define LAPIC_ICR_PENDING (1u << 12)
#define LAPIC_ICR_ASSERT  (1u << 14)
#define LAPIC_ICR_OTHERS  (3u << 18)
#define LAPIC_IPI_SPIN    200000
#define LAPIC_ICR_NMI     (4u << 8)    // SMP-2: delivery mode NMI
#define LAPIC_REG_LVT_TIMER  0x320
#define LAPIC_REG_TIMER_INIT 0x380
#define LAPIC_REG_TIMER_CUR  0x390
#define LAPIC_REG_TIMER_DIV  0x3E0
#define LAPIC_LVT_MASK       (1u << 16)
#define LAPIC_TIMER_PERIODIC (1u << 17)

volatile int g_lapic_ready = 0;   // SMP-1: 1 setelah MMIO LAPIC dipetakan BSP

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

uint32_t lapic_id_self(void)
{
    if (!g_lapic_ready) {
        return 0;   // LAPIC belum dipetakan (tanpa ACPI/MADT)
    }
    return lapic_read(LAPIC_REG_ID) >> 24;   // xAPIC: ID di bit 31..24
}

// AP: software enable + vektor spurious 0xFF (sama seperti BSP).
void lapic_enable_this_cpu(void)
{
    uint32_t svr = lapic_read(LAPIC_REG_SVR);

    svr |= (1 << 8);
    svr = (svr & ~0xFFu) | 0xFF;
    lapic_write(LAPIC_REG_SVR, svr);
}

static int lapic_icr_wait(void)
{
    for (uint32_t i = 0; i < LAPIC_IPI_SPIN; i++) {
        if (!(lapic_read(LAPIC_REG_ICR_LO) & LAPIC_ICR_PENDING)) {
            return 0;
        }
        __builtin_ia32_pause();
    }
    return -1;
}

// IPI fixed ke satu LAPIC ID (mode fisik, edge, assert). Batas putaran: tidak menggantung.
int lapic_send_ipi(uint32_t lapic_id, uint8_t vector)
{
    if (!g_lapic_ready) {
        return -1;
    }
    uint64_t f = irq_save();
    int rc = lapic_icr_wait();

    if (rc == 0) {
        lapic_write(LAPIC_REG_ICR_HI, lapic_id << 24);
        lapic_write(LAPIC_REG_ICR_LO, LAPIC_ICR_ASSERT | vector);
        rc = lapic_icr_wait();
    }
    irq_restore(f);
    return rc;
}

// Shorthand "semua kecuali diri sendiri" (dipakai panic: tanpa perlu daftar CPU).
int lapic_send_ipi_others(uint8_t vector)
{
    if (!g_lapic_ready) {
        return -1;
    }
    uint64_t f = irq_save();
    int rc = lapic_icr_wait();

    if (rc == 0) {
        lapic_write(LAPIC_REG_ICR_LO, LAPIC_ICR_OTHERS | LAPIC_ICR_ASSERT | vector);
        rc = lapic_icr_wait();
    }
    irq_restore(f);
    return rc;
}

// SMP-2: NMI ke SATU CPU (panic). Delivery mode 100b (NMI); vektor diabaikan CPU. Dikirim satu per satu
// ke CPU yang sudah online saja: AP yang masih parkir di stub Limine belum punya IDT kita (NMI = triple fault).
int lapic_send_nmi(uint32_t lapic_id)
{
    if (!g_lapic_ready) {
        return -1;
    }
    uint64_t f = irq_save();
    int rc = lapic_icr_wait();

    if (rc == 0) {
        lapic_write(LAPIC_REG_ICR_HI, lapic_id << 24);
        lapic_write(LAPIC_REG_ICR_LO, LAPIC_ICR_ASSERT | LAPIC_ICR_NMI);
        rc = lapic_icr_wait();
    }
    irq_restore(f);
    return rc;
}

// SMP-2: timer LAPIC lokal. Pembagi 16 (nilai 0x3). mode: 0 = satu kali, 1 = periodik.
// masked = 1: hitung tanpa interrupt (kalibrasi). Menulis hitungan awal = mulai menghitung.
void lapic_timer_start(uint32_t initial, int periodic, int masked, uint8_t vector)
{
    if (!g_lapic_ready) {
        return;
    }
    lapic_write(LAPIC_REG_TIMER_DIV, 0x3);
    lapic_write(LAPIC_REG_LVT_TIMER, (periodic ? LAPIC_TIMER_PERIODIC : 0) |
                                     (masked ? LAPIC_LVT_MASK : 0) | vector);
    lapic_write(LAPIC_REG_TIMER_INIT, initial);
}

uint32_t lapic_timer_count(void)
{
    return g_lapic_ready ? lapic_read(LAPIC_REG_TIMER_CUR) : 0;
}

void lapic_timer_stop(void)
{
    if (!g_lapic_ready) {
        return;
    }
    lapic_write(LAPIC_REG_LVT_TIMER, LAPIC_LVT_MASK | SMP_VEC_LTIMER);
    lapic_write(LAPIC_REG_TIMER_INIT, 0);
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

    g_lapic_ready = 1;
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

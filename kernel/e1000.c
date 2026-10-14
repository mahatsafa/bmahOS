#include "kernel.h"

#define E1000_REG_CTRL     0x0000
#define E1000_REG_STATUS   0x0008
#define E1000_REG_RAL0     0x5400
#define E1000_REG_RAH0     0x5404
#define E1000_REG_TCTL     0x0400
#define E1000_REG_TDBAL    0x3800
#define E1000_REG_TDBAH    0x3804
#define E1000_REG_TDLEN    0x3808
#define E1000_REG_TDH      0x3810
#define E1000_REG_TDT      0x3818
#define E1000_REG_TXDCTL   0x3828
#define E1000_REG_TIPG     0x0410
#define E1000_REG_IMC      0x00D8
#define E1000_REG_RCTL     0x0100
#define E1000_REG_RDBAL    0x2800
#define E1000_REG_RDBAH    0x2804
#define E1000_REG_RDLEN    0x2808
#define E1000_REG_RDH      0x2810

#define E1000_RCTL_EN      (1u << 1)
#define E1000_RCTL_UPE     (1u << 3)
#define E1000_RCTL_MPE     (1u << 4)
#define E1000_RCTL_BAM     (1u << 15)
#define E1000_RCTL_STANDARD (E1000_RCTL_EN | E1000_RCTL_UPE | \
                             E1000_RCTL_MPE | E1000_RCTL_BAM)

#define E1000_CTRL_RST     (1u << 26)

#define E1000_CTRL_FD    (1u << 0)
#define E1000_CTRL_ASDE  (1u << 5)
#define E1000_CTRL_SLU   (1u << 6)

#define E1000_TCTL_EN      (1u << 1)
#define E1000_TCTL_PSP     (1u << 3)
#define E1000_TCTL_CT_SHIFT   4
#define E1000_TCTL_COLD_SHIFT 12
#define E1000_TCTL_STANDARD ( \
    E1000_TCTL_EN | \
    E1000_TCTL_PSP | \
    (0x0Fu << E1000_TCTL_CT_SHIFT) | \
    (0x40u << E1000_TCTL_COLD_SHIFT) \
)

#define E1000_TXD_CMD_EOP  (1u << 0)
#define E1000_TXD_CMD_RS   (1u << 3)
#define E1000_TXD_STA_DD   (1u << 0)


// Net-1: E1000 NIC discovery. Baca BAR0, map MMIO, baca STATUS dan
// RAL0/RAH0 (Receive Address Low/High -- register yang menyimpan MAC
// address NIC) sebagai bukti independen chip yang benar terbaca,
// dibandingkan dengan MAC yang tertera di VMware VM Settings.
// Murni discovery, belum setup TX/RX descriptor ring sama sekali
// (checkpoint berikutnya, Net-2).
uint8_t g_e1000_mac[6];

static uint64_t g_e1000_tx_ring_phys = 0;
static uint8_t *g_e1000_tx_ring_virt = 0;
static int g_e1000_tx_initialized = 0;

// TX ring HANYA di-setup SEKALI (dipanggil dari e1000_probe_and_log()).
// Sebelumnya setiap fungsi kirim reprogram TDBAL/TDBAH/TDLEN/TCTL dari
// nol -- ini salah secara arsitektur: driver asli setup ring sekali,
// lalu pengiriman berikutnya CUMA sentuh TDT. Reprogram base address
// ring yang sedang aktif berpotensi bikin NIC bingung state internal
// meski DD tetap ter-set (DD cuma bukti "descriptor terbaca", bukan
// "paket benar-benar dikirim ke wire").
static void e1000_tx_init(volatile uint32_t *mmio)
{
    g_e1000_tx_ring_phys = pmm_alloc();

    if (g_e1000_tx_ring_phys == 0) {
        serial_write("E1000: FATAL - pmm_alloc gagal untuk TX ring\r\n");
        return;
    }

    g_e1000_tx_ring_virt = (uint8_t *)(g_e1000_tx_ring_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        g_e1000_tx_ring_virt[i] = 0;
    }

    mmio[E1000_REG_TDBAL / 4] = (uint32_t)(g_e1000_tx_ring_phys & 0xFFFFFFFFu);
    mmio[E1000_REG_TDBAH / 4] = (uint32_t)(g_e1000_tx_ring_phys >> 32);
    mmio[E1000_REG_TDLEN / 4] = 8 * 16;
    mmio[E1000_REG_TDH / 4] = 0;
    mmio[E1000_REG_TDT / 4] = 0;

    mmio[E1000_REG_TCTL / 4] = E1000_TCTL_STANDARD;
    mmio[E1000_REG_TXDCTL / 4] = mmio[E1000_REG_TXDCTL / 4] | (1u << 25);

    g_e1000_tx_initialized = 1;

    serial_write("E1000: TX ring init selesai (satu kali), ring_phys=");
    serial_write_hex(g_e1000_tx_ring_phys);
    serial_write("\r\n");
}

static uint64_t g_e1000_rx_ring_phys = 0;
uint8_t *g_e1000_rx_ring_virt = 0;
uint64_t g_e1000_rx_buf_phys[E1000_RX_RING_SIZE];
int g_e1000_rx_initialized = 0;

// RX ring di-setup SEKALI. 8 descriptor, 8 buffer @2048 byte
// (4 halaman pmm, tiap halaman = 2 buffer, tidak ada buffer yang
// melintasi batas halaman). RCTL: EN|UPE|MPE|BAM, BSIZE=00 (2048).
static void e1000_rx_init(volatile uint32_t *mmio)
{
    g_e1000_rx_ring_phys = pmm_alloc();

    if (g_e1000_rx_ring_phys == 0) {
        serial_write("E1000: FATAL - pmm_alloc gagal untuk RX ring\r\n");
        return;
    }

    g_e1000_rx_ring_virt = (uint8_t *)(g_e1000_rx_ring_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        g_e1000_rx_ring_virt[i] = 0;
    }

    for (int p = 0; p < E1000_RX_RING_SIZE / 2; p++) {
        uint64_t page_phys = pmm_alloc();

        if (page_phys == 0) {
            serial_write("E1000: FATAL - pmm_alloc gagal untuk RX buffer\r\n");
            return;
        }

        uint8_t *page_virt = (uint8_t *)(page_phys + hhdm_offset);

        for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
            page_virt[i] = 0;
        }

        g_e1000_rx_buf_phys[p * 2] = page_phys;
        g_e1000_rx_buf_phys[p * 2 + 1] = page_phys + 2048;
    }

    for (int i = 0; i < E1000_RX_RING_SIZE; i++) {
        uint64_t *desc_addr = (uint64_t *)(g_e1000_rx_ring_virt + (i * 16));
        *desc_addr = g_e1000_rx_buf_phys[i];
    }

    mmio[E1000_REG_RDBAL / 4] = (uint32_t)(g_e1000_rx_ring_phys & 0xFFFFFFFFu);
    mmio[E1000_REG_RDBAH / 4] = (uint32_t)(g_e1000_rx_ring_phys >> 32);
    mmio[E1000_REG_RDLEN / 4] = E1000_RX_RING_SIZE * 16;
    mmio[E1000_REG_RDH / 4] = 0;
    mmio[E1000_REG_RDT / 4] = 0;

    mmio[E1000_REG_RCTL / 4] = E1000_RCTL_STANDARD;

    mmio[E1000_REG_RDT / 4] = E1000_RX_RING_SIZE - 1;

    g_e1000_rx_initialized = 1;

    serial_write("E1000: RX ring init selesai, ring_phys=");
    serial_write_hex(g_e1000_rx_ring_phys);
    serial_write(" RCTL=");
    serial_write_hex((uint64_t)mmio[E1000_REG_RCTL / 4]);
    serial_write(" RDH=");
    serial_write_hex((uint64_t)mmio[E1000_REG_RDH / 4]);
    serial_write(" RDT=");
    serial_write_hex((uint64_t)mmio[E1000_REG_RDT / 4]);
    serial_write("\r\n");
}

static void e1000_log_hexbyte(uint8_t b)
{
    static const char h[] = "0123456789ABCDEF";
    serial_putc(h[b >> 4]);
    serial_putc(h[b & 0xF]);
}

// Polling slot 0 sampai NIC set DD (ada paket masuk), lalu dump
// sampai 64 byte pertama dari buffer 0.
static void __attribute__((unused)) e1000_rx_poll_test(void)
{
    if (!g_e1000_rx_initialized) {
        serial_write("E1000: RX poll dibatalkan - RX ring belum di-init\r\n");
        return;
    }

    volatile uint8_t *desc = (volatile uint8_t *)g_e1000_rx_ring_virt;
    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    serial_write("E1000: RX poll menunggu paket di slot 0...\r\n");

    uint64_t guard = 0;

    while (!(desc[0x0C] & E1000_RXD_STA_DD)) {
        guard++;
        if (guard > 2000000000ULL) {
            serial_write("E1000: RX poll TIMEOUT, tidak ada paket. RDH=");
            serial_write_hex((uint64_t)mmio[E1000_REG_RDH / 4]);
            serial_write(" RDT=");
            serial_write_hex((uint64_t)mmio[E1000_REG_RDT / 4]);
            serial_write("\r\n");
            return;
        }
    }

    uint32_t len = (uint32_t)desc[0x08] | ((uint32_t)desc[0x09] << 8);

    serial_write("E1000: RX paket diterima! len=");
    serial_write_hex((uint64_t)len);
    serial_write(" status=");
    serial_write_hex((uint64_t)desc[0x0C]);
    serial_write(" errors=");
    serial_write_hex((uint64_t)desc[0x0D]);
    serial_write(" RDH=");
    serial_write_hex((uint64_t)mmio[E1000_REG_RDH / 4]);
    serial_write("\r\n");

    volatile uint8_t *buf =
        (volatile uint8_t *)(g_e1000_rx_buf_phys[0] + hhdm_offset);

    uint32_t dump_len = len > 64 ? 64 : len;

    serial_write("E1000: RX dump:");
    for (uint32_t i = 0; i < dump_len; i++) {
        if ((i % 16) == 0) {
            serial_write("\r\n  ");
        }
        e1000_log_hexbyte(buf[i]);
        serial_putc(' ');
    }
    serial_write("\r\n");
}

// Kirim 1 frame yang sudah lengkap (pkt_virt/pkt_phys), pakai ring
// yang sudah di-init sekali oleh e1000_tx_init(). HANYA sentuh TDT,
// tidak pernah reprogram TDBAL/TDBAH/TDLEN/TCTL lagi.

// Net-19: counter TX (dibaca perintah metrics)
uint64_t g_net_tx_ok = 0;
uint64_t g_net_tx_fail = 0;

int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (!g_e1000_tx_initialized) {
        serial_write("E1000: FATAL - TX ring belum di-init\r\n");
        g_net_tx_fail++;
        return 0;
    }

    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    uint32_t tdt_now = mmio[E1000_REG_TDT / 4];
    uint8_t *desc = g_e1000_tx_ring_virt + (tdt_now * 16);

    uint64_t *desc_addr = (uint64_t *)(desc + 0x00);
    *desc_addr = pkt_phys;

    desc[0x08] = (uint8_t)(frame_len & 0xFF);
    desc[0x09] = (uint8_t)((frame_len >> 8) & 0xFF);
    desc[0x0A] = 0;
    desc[0x0B] = E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS | 0x02u; /* IFCS */
    desc[0x0C] = 0;
    desc[0x0D] = 0;
    desc[0x0E] = 0;
    desc[0x0F] = 0;

    mmio[E1000_REG_TDT / 4] = (tdt_now + 1) % 8;

    int guard = 0;
    while (!(desc[0x0C] & E1000_TXD_STA_DD)) {
        guard++;
        if (guard > 1000000) {
            serial_write("E1000: FATAL - timeout menunggu DD di e1000_tx_send\r\n");
            g_net_tx_fail++;
            return 0;
        }
    }

    g_net_tx_ok++;
    return 1;
}

static void e1000_diag_dump(const char *tag);

static void e1000_pci_cmd_write(uint16_t cmd)
{
    uint32_t addr = 0x80000000u
                  | ((uint32_t)E1000_PCI_BUS << 16)
                  | ((uint32_t)E1000_PCI_DEVICE << 11)
                  | ((uint32_t)E1000_PCI_FUNCTION << 8)
                  | 0x04u;

    __asm__ volatile ("outl %0, %1" : : "a"(addr), "Nd"((uint16_t)0xCF8));
    __asm__ volatile ("outl %0, %1" : : "a"((uint32_t)cmd), "Nd"((uint16_t)0xCFC));
}

static void e1000_diag_reg(const char *name, uint64_t value)
{
    serial_write("DIAG ");
    serial_write(name);
    serial_write("=");
    serial_write_hex(value);
    serial_write("\r\n");
}

static void e1000_diag_dump(const char *tag)
{
    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    serial_write("DIAG ---- ");
    serial_write(tag);
    serial_write(" ----\r\n");

    uint32_t pci04 = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                       E1000_PCI_FUNCTION, 0x04);

    e1000_diag_reg("PCI_CMD", (uint64_t)(pci04 & 0xFFFF));
    e1000_diag_reg("PCI_STATUS", (uint64_t)(pci04 >> 16));
    e1000_diag_reg("STATUS", (uint64_t)mmio[E1000_REG_STATUS / 4]);
    e1000_diag_reg("CTRL", (uint64_t)mmio[E1000_REG_CTRL / 4]);
    e1000_diag_reg("RCTL", (uint64_t)mmio[E1000_REG_RCTL / 4]);
    e1000_diag_reg("RDH", (uint64_t)mmio[E1000_REG_RDH / 4]);
    e1000_diag_reg("RDT", (uint64_t)mmio[E1000_REG_RDT / 4]);
    e1000_diag_reg("TDH", (uint64_t)mmio[E1000_REG_TDH / 4]);
    e1000_diag_reg("TDT", (uint64_t)mmio[E1000_REG_TDT / 4]);
    e1000_diag_reg("CRCERRS", (uint64_t)mmio[0x4000 / 4]);
    e1000_diag_reg("MPC", (uint64_t)mmio[0x4010 / 4]);
    e1000_diag_reg("RNBC", (uint64_t)mmio[0x40A0 / 4]);
    e1000_diag_reg("GPRC", (uint64_t)mmio[0x4074 / 4]);
    e1000_diag_reg("GPTC", (uint64_t)mmio[0x4080 / 4]);
    e1000_diag_reg("TPR", (uint64_t)mmio[0x40D0 / 4]);
    e1000_diag_reg("TPT", (uint64_t)mmio[0x40D4 / 4]);
}

// Net-13a: diagnostik saja, TIDAK mengubah perilaku. Catat info interrupt
// PCI (Interrupt Line/Pin di config 0x3C) dan register interrupt E1000.
// Catatan: membaca ICR meng-clear bit sebab yang tertunda.
// ---- Net-13c: eksperimen interrupt RX E1000 (cari GSI INTx) ----
volatile uint64_t g_e1000_irq_count = 0;
volatile uint64_t g_e1000_irq_spurious = 0;
volatile uint32_t g_e1000_irq_last_icr = 0;
volatile uint32_t g_e1000_irq_icr_or = 0;
volatile uint32_t g_e1000_irq_rirr_or = 0;
volatile uint32_t g_e1000_irq_masked = 0;
volatile uint32_t g_e1000_irq_last_gsi = 0;
volatile uint32_t g_e1000_irq_gsi = 0;

// Dipanggil setelah IOAPIC ter-map, saat interrupt masih mati (sebelum sti).
// Petakan GSI 16..min(max_entry,23) -> vektor 33, level + active-low,
// lalu nyalakan IMS.RXT0 di E1000.
void e1000_irq_experiment(void)
{
    if (!g_e1000_rx_initialized) {
        serial_write("IRQ-exp: E1000 tidak aktif, eksperimen interrupt dilewati\r\n");
        return;
    }

    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    uint64_t lf = irq_save();

    uint32_t ver = ioapic_read(0x01);
    uint32_t max_entry = (ver >> 16) & 0xFF;
    uint32_t last = max_entry < 23 ? max_entry : 23;

    serial_write("IRQ-exp: IOAPIC ver=");
    serial_write_hex((uint64_t)ver);
    serial_write(" max_entry=");
    serial_write_hex((uint64_t)max_entry);
    serial_write(" gsi_base=");
    serial_write_hex((uint64_t)g_ioapic_gsi_base);
    serial_write("\r\n");

    if (last < 16) {
        serial_write("IRQ-exp: IOAPIC tidak punya pin 16+, eksperimen dilewati\r\n");
        irq_restore(lf);
        return;
    }

    g_e1000_irq_last_gsi = last;

    for (uint32_t gsi = 16; gsi <= last; gsi++) {
        uint32_t idx = IOAPIC_REDTBL_BASE + gsi * 2;

        ioapic_write(idx + 1, 0);
        // vektor 33, fixed, physical, active-low (bit13), level (bit15), unmasked
        ioapic_write(idx, 33u | (1u << 13) | (1u << 15));
    }

    mmio[0x00D8 / 4] = 0xFFFFFFFFu;
    uint32_t dummy = mmio[0x00C0 / 4];
    (void)dummy;
    mmio[0x00D0 / 4] = 0xC0u;

    serial_write("IRQ-exp: GSI 16..");
    serial_write_hex((uint64_t)last);
    serial_write(" -> vektor 33 (level, active-low), IMS readback=");
    serial_write_hex((uint64_t)mmio[0x00D0 / 4]);
    serial_write("\r\n");

    irq_restore(lf);
}

// Net-13b: telusuri PCI capability list (pointer di config 0x34).
// id: 0x01 PM, 0x05 MSI, 0x07 PCI-X, 0x10 PCIe, 0x11 MSI-X.
static void e1000_pci_caps_diag(void)
{
    uint32_t st = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                    E1000_PCI_FUNCTION, 0x04) >> 16;

    uint64_t lf = irq_save();

    serial_write("Caps-diag: PCI status=");
    serial_write_hex((uint64_t)st);

    if (!(st & 0x10)) {
        serial_write(" (tidak ada capability list)\r\n");
        irq_restore(lf);
        return;
    }

    serial_write("\r\n");

    uint32_t ptr = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                     E1000_PCI_FUNCTION, 0x34) & 0xFC;

    for (int guard = 0; guard < 16 && ptr >= 0x40; guard++) {
        uint32_t dw = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                        E1000_PCI_FUNCTION, (uint8_t)ptr);

        serial_write("Caps-diag: offset=");
        serial_write_hex((uint64_t)ptr);
        serial_write(" id=");
        serial_write_hex((uint64_t)(dw & 0xFF));
        serial_write(" next=");
        serial_write_hex((uint64_t)((dw >> 8) & 0xFF));
        serial_write(" ctrl=");
        serial_write_hex((uint64_t)(dw >> 16));
        serial_write("\r\n");

        ptr = ((dw >> 8) & 0xFF) & 0xFC;
    }

    serial_write("Caps-diag: selesai\r\n");
    irq_restore(lf);
}

static void e1000_irq_diag(volatile uint32_t *mmio)
{
    uint32_t r3c = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                     E1000_PCI_FUNCTION, 0x3C);

    uint64_t lf = irq_save();
    serial_write("IRQ-diag: PCI 0x3C raw=");
    serial_write_hex((uint64_t)r3c);
    serial_write(" interrupt_line=");
    serial_write_hex((uint64_t)(r3c & 0xFF));
    serial_write(" interrupt_pin=");
    serial_write_hex((uint64_t)((r3c >> 8) & 0xFF));
    serial_write("\r\n");
    serial_write("IRQ-diag: E1000 IMS=");
    serial_write_hex((uint64_t)mmio[0x00D0 / 4]);
    serial_write(" ITR=");
    serial_write_hex((uint64_t)mmio[0x00C4 / 4]);
    serial_write(" ICR(clear-on-read)=");
    serial_write_hex((uint64_t)mmio[0x00C0 / 4]);
    serial_write("\r\n");
    irq_restore(lf);
}

void e1000_probe_and_log(uint64_t pml4_phys)
{
    crypto_selftest();
    auth_load_key();
    tls_load();      // D9: TLSKEY.DER + TLSCERT.DER (port 7780), sebelum config
    config_load();   // D7: CONFIG.CFG (default bila tidak ada / ditolak)

    if (!g_e1000_found) {
        serial_write("E1000: perangkat tidak ditemukan, skip\r\n");
        return;
    }

    uint32_t bar0 = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE, E1000_PCI_FUNCTION, E1000_BAR0_OFFSET);
    uint64_t mmio_phys = bar0 & 0xFFFFFFF0ULL;

    serial_write("E1000: BAR0 raw = ");
    serial_write_hex(bar0);
    serial_write(", MMIO phys = ");
    serial_write_hex(mmio_phys);
    serial_write("\r\n");

    if (mmio_phys == 0) {
        serial_write("E1000: MMIO physical address 0, skip (device tidak ditemukan di B/D/F ini?)\r\n");
        return;
    }

    // E1000 register RAL0/RAH0 (MAC address) ada di offset 0x5400/0x5404,
    // jauh melebihi 1 halaman (0x1000). Map 6 halaman (0x6000 byte,
    // mencakup sampai offset 0x5FFF) supaya semua register yang kita
    // pakai di checkpoint ini ter-cover. Utang teknis: masih hardcode
    // 6 halaman, bukan dihitung dari ukuran BAR sebenarnya (yang bisa
    // dibaca dari PCI config space kalau mau presisi).
    for (uint64_t page = 0; page < 6; page++) {
        vmm_map(pml4_phys, E1000_VIRT + (page * PMM_PAGE_SIZE),
                mmio_phys + (page * PMM_PAGE_SIZE),
                VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NOCACHE | VMM_FLAG_NX);
    }

    volatile uint32_t *mmio = (volatile uint32_t *)E1000_VIRT;

    // Full device reset -- BELUM PERNAH dilakukan sama sekali sebelum
    // checkpoint ini. Driver nyata SELALU reset device di awal init
    // (langkah pertama di datasheet Intel 8254x), bukan opsional.
    // Kemungkinan ada state internal sisa startup VMware yang perlu
    // dibersihkan sebelum konfigurasi TX benar-benar valid. Dilakukan
    // SEBELUM baca STATUS/RAL0/RAH0 supaya MAC yang disimpan adalah
    // hasil pasca-reset (dibaca ulang dari EEPROM oleh hardware).
    mmio[E1000_REG_CTRL / 4] = mmio[E1000_REG_CTRL / 4] | E1000_CTRL_RST;

    int reset_guard = 0;
    while (mmio[E1000_REG_CTRL / 4] & E1000_CTRL_RST) {
        reset_guard++;
        if (reset_guard > 1000000) {
            serial_write("E1000: WARNING - RST tidak clear sendiri setelah timeout\r\n");
            break;
        }
    }

    serial_write("E1000: device reset selesai (CTRL=");
    serial_write_hex(mmio[E1000_REG_CTRL / 4]);
    serial_write(")\r\n");

    mmio[E1000_REG_IMC / 4] = 0xFFFFFFFFu;

    uint32_t status = mmio[E1000_REG_STATUS / 4];
    uint32_t ral0 = mmio[E1000_REG_RAL0 / 4];
    uint32_t rah0 = mmio[E1000_REG_RAH0 / 4];

    serial_write("E1000: STATUS=");
    serial_write_hex(status);
    serial_write(" (link_up=");
    serial_write_hex((uint64_t)((status >> 1) & 0x1));
    serial_write(")\r\n");

    uint8_t mac[6];
    mac[0] = (uint8_t)(ral0 & 0xFF);
    mac[1] = (uint8_t)((ral0 >> 8) & 0xFF);
    mac[2] = (uint8_t)((ral0 >> 16) & 0xFF);
    mac[3] = (uint8_t)((ral0 >> 24) & 0xFF);
    mac[4] = (uint8_t)(rah0 & 0xFF);
    mac[5] = (uint8_t)((rah0 >> 8) & 0xFF);

    uint32_t rah0_valid = (rah0 >> 31) & 0x1;

    serial_write("E1000: RAL0=");
    serial_write_hex(ral0);
    serial_write(" RAH0=");
    serial_write_hex(rah0);
    serial_write(" (valid=");
    serial_write_hex((uint64_t)rah0_valid);
    serial_write(")\r\n");

    serial_write("E1000: MAC address = ");
    for (int i = 0; i < 6; i++) {
        serial_write_hex(mac[i]);
        if (i < 5) {
            serial_write(":");
        }
    }
    serial_write("\r\n");

    for (int i = 0; i < 6; i++) {
        g_e1000_mac[i] = mac[i];
    }

    uint32_t ctrl_before = mmio[E1000_REG_CTRL / 4];

    serial_write("E1000: CTRL sebelum = ");
    serial_write_hex(ctrl_before);
    serial_write("\r\n");

    uint32_t ctrl_after = ctrl_before | E1000_CTRL_SLU | E1000_CTRL_ASDE;
    mmio[E1000_REG_CTRL / 4] = ctrl_after;

    serial_write("E1000: CTRL sesudah (SLU|ASDE dipaksa) = ");
    serial_write_hex(mmio[E1000_REG_CTRL / 4]);
    serial_write("\r\n");

    serial_write("E1000: TXDCTL = ");
    serial_write_hex(mmio[E1000_REG_TXDCTL / 4]);
    serial_write(" TIPG = ");
    serial_write_hex(mmio[E1000_REG_TIPG / 4]);
    serial_write("\r\n");

    // TIPG kosong (0x0) ditemukan sebagai kemungkinan penyebab paket
    // tidak keluar ke wire meski DD selalu ter-set -- nilai standar
    // dari datasheet Intel untuk full-duplex.
    mmio[E1000_REG_TIPG / 4] = 0x0060200Au;

    mmio[E1000_REG_TXDCTL / 4] = mmio[E1000_REG_TXDCTL / 4] | (1u << 25);

    serial_write("E1000: TIPG sesudah = ");
    serial_write_hex(mmio[E1000_REG_TIPG / 4]);
    serial_write(" TXDCTL sesudah = ");
    serial_write_hex(mmio[E1000_REG_TXDCTL / 4]);
    serial_write("\r\n");

    // Setelah CTRL.RST, link_up sempat balik ke 0 (ditemukan lewat log
    // boot nyata: STATUS.LU=0 tepat sesudah reset, padahal SEBELUM
    // reset selalu 1 sejak awal boot). PHY butuh waktu renegosiasi
    // ulang link setelah reset -- ini normal untuk hardware nyata
    // maupun emulasi yang meniru perilaku hardware. Tunggu sampai
    // STATUS.LU kembali 1 sebelum lanjut ke TX, supaya paket tidak
    // diam-diam dibuang karena link belum benar-benar up.
    serial_write("E1000: menunggu link up kembali setelah reset...\r\n");

    int link_guard = 0;
    uint32_t status_now = mmio[E1000_REG_STATUS / 4];

    while (!((status_now >> 1) & 0x1)) {
        link_guard++;
        if (link_guard > 5000000) {
            serial_write("E1000: WARNING - link tidak kembali up setelah timeout\r\n");
            break;
        }
        status_now = mmio[E1000_REG_STATUS / 4];
    }

    serial_write("E1000: STATUS setelah tunggu link = ");
    serial_write_hex(status_now);
    serial_write(" (link_up=");
    serial_write_hex((uint64_t)((status_now >> 1) & 0x1));
    serial_write(", iterasi=");
    serial_write_hex((uint64_t)link_guard);
    serial_write(")\r\n");

    e1000_diag_dump("SEBELUM enable bus master");

    // PCI Command: bit1 Memory Space + bit2 Bus Master. Status di
    // upper 16 bit bersifat write-1-to-clear, jadi hanya tulis 16 bit bawah.
    uint32_t pci_cmd_now = pci_config_read32(E1000_PCI_BUS, E1000_PCI_DEVICE,
                                             E1000_PCI_FUNCTION, 0x04) & 0xFFFFu;
    e1000_pci_cmd_write((uint16_t)(pci_cmd_now | 0x0006u));

    e1000_diag_dump("SESUDAH enable bus master");

    e1000_tx_init(mmio);
    e1000_rx_init(mmio);
    e1000_diag_dump("SESUDAH rx poll");
    e1000_irq_diag(mmio);
    e1000_pci_caps_diag();
}

// Net-2: setup TX descriptor ring (8 slot, cuma slot 0 dipakai),
// bangun 1 Ethernet frame broadcast, kirim lewat TDT trigger, poll
// sampai NIC set bit DD (Descriptor Done) di STA. EtherType 0x88B5
// dipilih karena termasuk rentang "experimental" yang aman dipakai
// testing, tidak bentrok dengan protokol nyata yang mungkin lewat
// di jaringan yang sama.
void e1000_send_test_packet(void)
{
    uint64_t pkt_phys = pmm_alloc();

    if (pkt_phys == 0) {
        serial_write("Net-2: FATAL - pmm_alloc gagal\r\n");
        return;
    }

    uint8_t *pkt_virt = (uint8_t *)(pkt_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        pkt_virt[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        pkt_virt[i] = 0xFF;
    }

    for (int i = 0; i < 6; i++) {
        pkt_virt[6 + i] = g_e1000_mac[i];
    }

    pkt_virt[12] = 0x88;
    pkt_virt[13] = 0xB5;

    const char *payload = "bmahOS network test";
    int payload_len = 0;
    while (payload[payload_len] != 0) {
        pkt_virt[14 + payload_len] = (uint8_t)payload[payload_len];
        payload_len++;
    }

    uint32_t frame_len = 14 + (uint32_t)payload_len;

    if (frame_len < 60) {
        frame_len = 60;
    }

    serial_write("Net-2: mengirim frame, panjang=");
    serial_write_hex(frame_len);
    serial_write(" byte\r\n");

    int ok = e1000_tx_send(pkt_phys, frame_len);

    serial_write("Net-2: e1000_tx_send -> ");
    serial_write(ok ? "sukses (DD set)" : "GAGAL");
    serial_write("\r\n");
}

// Net-3: kirim ARP request sungguhan (EtherType 0x0806) untuk menguji
// dugaan dari Net-2 bahwa NAT device VMware memfilter EtherType asing.
// Sender IP pakai placeholder 192.168.115.200 (bmahOS BELUM punya IP
// stack sungguhan -- ini murni supaya format paket valid, bukan klaim
// kepemilikan IP). Target 192.168.115.254 (gateway NAT, sudah terbukti
// aktif dari capture Wireshark sebelumnya).
uint32_t g_e1000_rx_next = 0;

static void e1000_log_dec8(uint8_t v)
{
    if (v >= 100) {
        serial_putc((char)('0' + v / 100));
    }
    if (v >= 10) {
        serial_putc((char)('0' + (v / 10) % 10));
    }
    serial_putc((char)('0' + v % 10));
}

void e1000_log_ip(volatile uint8_t *p)
{
    for (int i = 0; i < 4; i++) {
        e1000_log_dec8(p[i]);
        if (i < 3) {
            serial_putc('.');
        }
    }
}

void e1000_log_mac(volatile uint8_t *p)
{
    for (int i = 0; i < 6; i++) {
        e1000_log_hexbyte(p[i]);
        if (i < 5) {
            serial_putc(':');
        }
    }
}

#include "kernel.h"

// Checkpoint PCI: baca 1 register 32-bit dari PCI configuration space
// lewat Legacy Configuration Mechanism #1 (CONFIG_ADDRESS/CONFIG_DATA,
// port 0xCF8/0xCFC) -- didukung universal di x86 (termasuk VMware),
// tidak butuh parsing tabel ACPI MCFG seperti PCIe Enhanced Config
// Access Mechanism. offset WAJIB word-aligned (kelipatan 4) -- bit
// 1-0 CONFIG_ADDRESS selalu 00, caller yang salah offset akan diam-
// diam dibulatkan ke bawah oleh mask di bawah, bukan error eksplisit.
#define PCI_CONFIG_ADDRESS 0xCF8
#define PCI_CONFIG_DATA    0xCFC

uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset)
{
    uint32_t address =
        (1U << 31) |
        ((uint32_t)bus << 16) |
        ((uint32_t)device << 11) |
        ((uint32_t)function << 8) |
        ((uint32_t)offset & 0xFC);

    outl(PCI_CONFIG_ADDRESS, address);
    return inl(PCI_CONFIG_DATA);
}

// P2: enumerasi generik ke tabel g_pci_devs (sekali saat boot). Semua bus
// 0..255 diperiksa (tanpa bergantung topologi bridge), tapi fungsi 1..7 hanya
// bila fungsi 0 ada dan header type bit 7 (multi-function) menyala. Tabel
// penuh -> perangkat berikutnya hanya dihitung (g_pci_dropped). Pembaca
// config space lewat pointer supaya bisa diganti di uji host.
pci_dev_t g_pci_devs[PCI_MAX_DEVS];
uint32_t g_pci_ndevs;
uint32_t g_pci_dropped;
uint32_t (*g_pci_read)(uint8_t, uint8_t, uint8_t, uint8_t) = pci_config_read32;

static void pci_add(uint8_t bus, uint8_t dev, uint8_t fn, uint32_t reg0, uint8_t hdr)
{
    if (g_pci_ndevs >= PCI_MAX_DEVS) {
        g_pci_dropped++;
        return;
    }
    pci_dev_t *d = &g_pci_devs[g_pci_ndevs++];

    d->bus = bus;
    d->dev = dev;
    d->fn = fn;
    d->hdr = hdr & 0x7F;
    d->vendor = (uint16_t)(reg0 & 0xFFFF);
    d->device = (uint16_t)(reg0 >> 16);
    d->cls = g_pci_read(bus, dev, fn, 0x08) >> 8;   // kelas:subkelas:prog_if
}

void pci_enumerate(void)
{
    g_pci_ndevs = 0;
    g_pci_dropped = 0;
    for (uint32_t bus = 0; bus < 256; bus++) {
        for (uint32_t dev = 0; dev < 32; dev++) {
            uint32_t reg0 = g_pci_read((uint8_t)bus, (uint8_t)dev, 0, 0x00);

            if ((reg0 & 0xFFFF) == 0xFFFF) {
                continue;
            }
            uint8_t hdr = (uint8_t)(g_pci_read((uint8_t)bus, (uint8_t)dev, 0, 0x0C) >> 16);

            pci_add((uint8_t)bus, (uint8_t)dev, 0, reg0, hdr);
            if (!(hdr & 0x80)) {
                continue;
            }
            for (uint32_t fn = 1; fn < 8; fn++) {
                reg0 = g_pci_read((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x00);
                if ((reg0 & 0xFFFF) == 0xFFFF) {
                    continue;
                }
                hdr = (uint8_t)(g_pci_read((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, 0x0C) >> 16);
                pci_add((uint8_t)bus, (uint8_t)dev, (uint8_t)fn, reg0, hdr);
            }
        }
    }
}

const pci_dev_t *pci_find_class(uint32_t cls)
{
    for (uint32_t i = 0; i < g_pci_ndevs; i++) {
        if (g_pci_devs[i].cls == cls) {
            return &g_pci_devs[i];
        }
    }
    return 0;
}

const pci_dev_t *pci_find_id(uint16_t vendor, uint16_t device)
{
    for (uint32_t i = 0; i < g_pci_ndevs; i++) {
        if (g_pci_devs[i].vendor == vendor && g_pci_devs[i].device == device) {
            return &g_pci_devs[i];
        }
    }
    return 0;
}

// Satu baris per perangkat: "BB:DD.F vvvv:dddd kelas KK:SS:PP hdr H".
void pci_list(void (*out)(const char *))
{
    char line[64];

    for (uint32_t i = 0; i < g_pci_ndevs; i++) {
        const pci_dev_t *d = &g_pci_devs[i];

        ksnprintf(line, sizeof(line), "%02x:%02x.%u %04x:%04x kelas %02x:%02x:%02x hdr %u\n",
                  d->bus, d->dev, d->fn, d->vendor, d->device, (d->cls >> 16) & 0xFF,
                  (d->cls >> 8) & 0xFF, d->cls & 0xFF, d->hdr);
        out(line);
    }
    ksnprintf(line, sizeof(line), "pci: %u perangkat, tidak muat %u\n",
              g_pci_ndevs, g_pci_dropped);
    out(line);
}

static void pci_out_serial(const char *s)
{
    serial_write("PCI: ");
    for (; *s; s++) {
        if (*s == '\n') {
            serial_write("\r\n");
        } else {
            char c[2] = { *s, 0 };
            serial_write(c);
        }
    }
}

void pci_scan_and_log(void)
{
    pci_enumerate();
    pci_list(pci_out_serial);
}

// PCI-1: B/D/F AHCI dan E1000 dicari otomatis oleh pci_find_devices()
// (dulu di-hardcode hasil VMware: AHCI 2:4.0, E1000 2:1.0). AHCI =
// class 0x01 subclass 0x06 prog_if 0x01; E1000 = vendor 0x8086 dengan
// device ID yang sudah diuji (0x100F 82545EM VMware, 0x100E 82540EM QEMU).
// Ambil yang pertama ditemukan. Driver dilewati kalau g_*_found == 0.
uint8_t g_ahci_bus, g_ahci_dev, g_ahci_fn;
uint8_t g_e1000_bus, g_e1000_dev, g_e1000_fn;
int g_ahci_found = 0;
int g_e1000_found = 0;



void pci_config_write32(uint8_t bus, uint8_t device, uint8_t function,
                               uint8_t offset, uint32_t value)
{
    uint32_t address =
        (1U << 31) |
        ((uint32_t)bus << 16) |
        ((uint32_t)device << 11) |
        ((uint32_t)function << 8) |
        ((uint32_t)offset & 0xFC);

    outl(PCI_CONFIG_ADDRESS, address);
    outl(PCI_CONFIG_DATA, value);
}

static void pci_log_bdf(const char *name, uint8_t bus, uint8_t dev, uint8_t fn)
{
    serial_write("PCI-1: ");
    serial_write(name);
    serial_write(" di bus=");
    serial_write_hex(bus);
    serial_write(" device=");
    serial_write_hex(dev);
    serial_write(" function=");
    serial_write_hex(fn);
    serial_write("\r\n");
}

void pci_find_devices(void)
{
    const pci_dev_t *d = pci_find_class(0x010601u);   // P2: dari tabel g_pci_devs

    if (d) {
        g_ahci_bus = d->bus;
        g_ahci_dev = d->dev;
        g_ahci_fn = d->fn;
        g_ahci_found = 1;
    }
    d = pci_find_id(0x8086, 0x100F);
    if (!d) {
        d = pci_find_id(0x8086, 0x100E);
    }
    if (d) {
        g_e1000_bus = d->bus;
        g_e1000_dev = d->dev;
        g_e1000_fn = d->fn;
        g_e1000_found = 1;
    }

    if (g_ahci_found) {
        pci_log_bdf("AHCI", g_ahci_bus, g_ahci_dev, g_ahci_fn);
    } else {
        serial_write("PCI-1: AHCI tidak ditemukan\r\n");
    }

    if (g_e1000_found) {
        pci_log_bdf("E1000", g_e1000_bus, g_e1000_dev, g_e1000_fn);
    } else {
        serial_write("PCI-1: E1000 tidak ditemukan\r\n");
    }
}

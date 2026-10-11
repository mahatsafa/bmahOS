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

// Checkpoint PCI: scan brute-force SELURUH kombinasi bus/device/
// function (256 x 32 x 8 = 65536 probe), TANPA optimisasi multi-
// function header (skip function 1-7 kalau device bukan multi-
// function) -- checkpoint pertama sengaja dibuat sesempit mungkin,
// murni discovery + log, TIDAK ADA pci_device_t/registry/lookup API/
// driver apa pun. Vendor ID == 0xFFFF berarti device tidak ada di
// slot itu (satu-satunya kondisi skip yang kita pakai).
void pci_scan_and_log(void)
{
    serial_write("PCI: mulai scan bus/device/function...\r\n");

    for (uint32_t bus = 0; bus < 256; bus++) {
        for (uint32_t device = 0; device < 32; device++) {
            for (uint32_t function = 0; function < 8; function++) {
                uint32_t reg0 = pci_config_read32((uint8_t)bus, (uint8_t)device, (uint8_t)function, 0x00);
                uint16_t vendor_id = (uint16_t)(reg0 & 0xFFFF);

                if (vendor_id == 0xFFFF) {
                    continue;
                }

                uint16_t device_id = (uint16_t)((reg0 >> 16) & 0xFFFF);

                uint32_t reg8 = pci_config_read32((uint8_t)bus, (uint8_t)device, (uint8_t)function, 0x08);
                uint8_t prog_if    = (uint8_t)((reg8 >> 8) & 0xFF);
                uint8_t subclass   = (uint8_t)((reg8 >> 16) & 0xFF);
                uint8_t class_code = (uint8_t)((reg8 >> 24) & 0xFF);

                serial_write("PCI: bus=");
                serial_write_hex(bus);
                serial_write(" device=");
                serial_write_hex(device);
                serial_write(" function=");
                serial_write_hex(function);
                serial_write(" vendor=");
                serial_write_hex(vendor_id);
                serial_write(" device_id=");
                serial_write_hex(device_id);
                serial_write(" class=");
                serial_write_hex(class_code);
                serial_write(" subclass=");
                serial_write_hex(subclass);
                serial_write(" prog_if=");
                serial_write_hex(prog_if);
                serial_write("\r\n");
            }
        }
    }

    serial_write("PCI: scan selesai.\r\n");
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
    for (uint32_t bus = 0; bus < 256; bus++) {
        for (uint32_t dev = 0; dev < 32; dev++) {
            for (uint32_t fn = 0; fn < 8; fn++) {
                uint32_t reg0 = pci_config_read32((uint8_t)bus, (uint8_t)dev,
                                                  (uint8_t)fn, 0x00);
                uint16_t vendor = (uint16_t)(reg0 & 0xFFFF);
                if (vendor == 0xFFFF) {
                    continue;
                }
                uint16_t device_id = (uint16_t)(reg0 >> 16);
                uint32_t reg8 = pci_config_read32((uint8_t)bus, (uint8_t)dev,
                                                  (uint8_t)fn, 0x08);
                uint32_t cls = reg8 >> 8; // class:subclass:prog_if

                if (!g_ahci_found && cls == 0x010601u) {
                    g_ahci_bus = (uint8_t)bus;
                    g_ahci_dev = (uint8_t)dev;
                    g_ahci_fn = (uint8_t)fn;
                    g_ahci_found = 1;
                }

                if (!g_e1000_found && vendor == 0x8086 &&
                    (device_id == 0x100F || device_id == 0x100E)) {
                    g_e1000_bus = (uint8_t)bus;
                    g_e1000_dev = (uint8_t)dev;
                    g_e1000_fn = (uint8_t)fn;
                    g_e1000_found = 1;
                }
            }
        }
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

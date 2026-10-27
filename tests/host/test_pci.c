// P2: uji enumerasi PCI generik (pci.c di-#include). Config space tiruan:
// tabel perangkat per (bus, dev, fn); pembaca dipasang lewat g_pci_read.

#include <stdint.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/pci.c"

typedef struct {
    uint8_t bus, dev, fn, hdr;
    uint16_t vendor, device;
    uint32_t cls;
} fake_t;

static const fake_t *g_fake;
static int g_nfake;
static uint32_t g_reads;
static int g_ghost_fn;   // fungsi 1..7 "ada" walau fungsi 0 bukan multi-function

static uint32_t fake_read(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off)
{
    g_reads++;
    for (int i = 0; i < g_nfake; i++) {
        const fake_t *f = &g_fake[i];
        if (f->bus == bus && f->dev == dev && f->fn == fn) {
            if (off == 0x00) {
                return f->vendor | (uint32_t)f->device << 16;
            }
            if (off == 0x08) {
                return f->cls << 8 | 0x01;   // revisi 1
            }
            if (off == 0x0C) {
                return (uint32_t)f->hdr << 16;
            }
            return 0;
        }
    }
    // Perangkat bukan multi-function yang tidak mendekode nomor fungsi:
    // fungsi 1..7 memantulkan fungsi 0 (alasan cek bit 7 header).
    if (g_ghost_fn && fn != 0) {
        for (int i = 0; i < g_nfake; i++) {
            const fake_t *f = &g_fake[i];
            if (f->bus == bus && f->dev == dev && f->fn == 0 && !(f->hdr & 0x80)) {
                return fake_read(bus, dev, 0, off);
            }
        }
    }
    return 0xFFFFFFFF;
}

static void run(const fake_t *f, int n)
{
    g_fake = f;
    g_nfake = n;
    g_reads = 0;
    g_pci_read = fake_read;
    pci_enumerate();
}

static char g_out[4096];
static void out_cat(const char *s)
{
    strncat(g_out, s, sizeof(g_out) - strlen(g_out) - 1);
}

static void test_q35(void)
{
    // Mirip QEMU q35: host bridge 00:00.0, VGA, E1000, ISA bridge
    // multi-function 00:1f.0 dengan SATA AHCI 00:1f.2 dan SMBus 00:1f.3.
    static const fake_t f[] = {
        { 0, 0x00, 0, 0x00, 0x8086, 0x29c0, 0x060000 },
        { 0, 0x01, 0, 0x00, 0x1234, 0x1111, 0x030000 },
        { 0, 0x02, 0, 0x00, 0x8086, 0x100e, 0x020000 },
        { 0, 0x1f, 0, 0x80, 0x8086, 0x2918, 0x060100 },
        { 0, 0x1f, 2, 0x00, 0x8086, 0x2922, 0x010601 },
        { 0, 0x1f, 3, 0x00, 0x8086, 0x2930, 0x0c0500 },
        { 3, 0x05, 0, 0x01, 0x1b36, 0x0001, 0x060400 },   // bridge di bus lain
    };
    g_ghost_fn = 1;
    run(f, 7);
    CHECK(g_pci_ndevs == 7 && g_pci_dropped == 0);
    // Bukan multi-function -> fungsi 1..7 tidak dibaca (tanpa hantu).
    CHECK(pci_find_id(0x1234, 0x1111) == &g_pci_devs[1]);
    const pci_dev_t *a = pci_find_class(0x010601);
    CHECK(a && a->bus == 0 && a->dev == 0x1f && a->fn == 2 && a->hdr == 0);
    CHECK(g_pci_devs[3].hdr == 0 && g_pci_devs[3].fn == 0);   // bit 7 dibuang
    CHECK(g_pci_devs[6].bus == 3 && g_pci_devs[6].hdr == 1);
    CHECK(pci_find_id(0x8086, 0x100f) == 0 && pci_find_class(0x999999) == 0);
    // Probe: 256 x 32 fungsi 0 + header untuk yang ada + 7 fungsi multi-function.
    CHECK(g_reads < 256 * 32 + 64);

    pci_find_devices();
    CHECK(g_ahci_found && g_ahci_bus == 0 && g_ahci_dev == 0x1f && g_ahci_fn == 2);
    CHECK(g_e1000_found && g_e1000_dev == 2 && g_e1000_fn == 0);

    g_out[0] = 0;
    pci_list(out_cat);
    CHECK(strstr(g_out, "00:1f.2 8086:2922 kelas 01:06:01 hdr 0\n") != 0);
    CHECK(strstr(g_out, "03:05.0 1b36:0001 kelas 06:04:00 hdr 1\n") != 0);
    CHECK(strstr(g_out, "pci: 7 perangkat, tidak muat 0\n") != 0);
}

static void test_full_table(void)
{
    // 80 perangkat > PCI_MAX_DEVS 64: 64 disimpan, 16 dihitung.
    static fake_t f[80];
    for (int i = 0; i < 80; i++) {
        f[i] = (fake_t){ (uint8_t)(i / 32), (uint8_t)(i % 32), 0, 0, 0x10ec, (uint16_t)i, 0x020000 };
    }
    g_ghost_fn = 0;
    run(f, 80);
    CHECK(g_pci_ndevs == PCI_MAX_DEVS && g_pci_dropped == 16);
    CHECK(g_pci_devs[63].device == 63);
    g_out[0] = 0;
    pci_list(out_cat);
    CHECK(strstr(g_out, "pci: 64 perangkat, tidak muat 16\n") != 0);

    run(f, 0);   // tanpa perangkat: tabel kosong, enumerasi ulang mengosongkan
    CHECK(g_pci_ndevs == 0 && g_pci_dropped == 0 && pci_find_class(0x020000) == 0);
}

int main(void)
{
    test_q35();
    test_full_table();
    return test_done("pci");
}

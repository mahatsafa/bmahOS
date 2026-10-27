#include <limine.h>
#include "kernel.h"

extern volatile struct limine_rsdp_request rsdp_request;

// ============================================================
// ACPI: RSDP -> RSDT/XSDT -> MADT parsing
// Base revision Limine kita = 6, artinya RSDP address dikembalikan
// sebagai virtual (HHDM) -- lihat PROTOCOL.md Base Revision 4:
// "RSDP address is returned as virtual (HHDM) again (physical only
// in base revision 3)." Jadi rsdp_request.response->address bisa
// langsung di-dereference tanpa tambah hhdm_offset.
// ============================================================





// Entry type 0: Processor Local APIC

// Entry type 1: I/O APIC

// Entry type 2: Interrupt Source Override

uint64_t g_local_apic_address = 0;
uint32_t g_ioapic_address = 0;
static uint32_t g_ioapic_id = 0;
uint32_t g_ioapic_gsi_base = 0;
uint32_t g_irq0_gsi = 0; // default asumsi: IRQ0 -> GSI0, kecuali ada override

// P2: setiap tabel divalidasi sebelum dibaca isinya: panjang >= header,
// <= ACPI_TABLE_MAX, dan jumlah semua byte = 0 (mod 256). Tabel yang ditolak
// dihitung (g_acpi_bad) dan dilewati. Entri XSDT/RSDT dibaca dengan memcpy
// (tidak sejajar 8 byte di offset 36).
#define ACPI_TABLE_MAX (1u << 20)
#define ACPI_LIST_MAX  24

uint32_t g_acpi_bad;
uint32_t g_acpi_cpus;
uint64_t g_hpet_base;
uint16_t g_hpet_min_tick;
int g_hpet_ok;

static struct {
    char sig[5];
    uint32_t len;
    uint8_t rev, ok;
} g_acpi_tabs[ACPI_LIST_MAX];
static uint32_t g_acpi_ntabs;

static int acpi_sum_ok(const void *p, uint32_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    uint8_t sum = 0;

    for (uint32_t i = 0; i < len; i++) {
        sum = (uint8_t)(sum + b[i]);
    }
    return sum == 0;
}

int acpi_table_ok(const struct acpi_sdt_header *h)
{
    return h->length >= sizeof(*h) && h->length <= ACPI_TABLE_MAX &&
           acpi_sum_ok(h, h->length);
}

static void acpi_note(const struct acpi_sdt_header *h, int ok)
{
    if (g_acpi_ntabs >= ACPI_LIST_MAX) {
        return;
    }
    for (int k = 0; k < 4; k++) {
        char c = h->signature[k];
        g_acpi_tabs[g_acpi_ntabs].sig[k] = (c >= 0x20 && c < 0x7F) ? c : '?';
    }
    g_acpi_tabs[g_acpi_ntabs].sig[4] = 0;
    g_acpi_tabs[g_acpi_ntabs].len = h->length;
    g_acpi_tabs[g_acpi_ntabs].rev = h->revision;
    g_acpi_tabs[g_acpi_ntabs].ok = (uint8_t)ok;
    g_acpi_ntabs++;
}

static int acpi_sig(const struct acpi_sdt_header *h, const char *sig)
{
    return memcmp(h->signature, sig, 4) == 0;
}

static void acpi_parse_madt(struct acpi_madt *madt)
{
    if (madt->header.length < sizeof(struct acpi_madt)) {
        serial_write("MADT: terlalu pendek, diabaikan\r\n");
        g_acpi_bad++;
        return;
    }
    g_local_apic_address = madt->local_apic_address;
    serial_write("MADT: Local APIC address = ");
    serial_write_hex(g_local_apic_address);
    serial_write("\r\n");

    uint8_t *entry_ptr = (uint8_t *)madt + sizeof(struct acpi_madt);
    uint8_t *madt_end = (uint8_t *)madt + madt->header.length;

    while (entry_ptr + sizeof(struct acpi_madt_entry_header) <= madt_end)
    {
        struct acpi_madt_entry_header *entry_header = (struct acpi_madt_entry_header *)entry_ptr;
        uint8_t elen = entry_header->entry_length;

        // P2: panjang 0/1 dulu membuat loop ini berputar selamanya.
        if (elen < sizeof(struct acpi_madt_entry_header) || entry_ptr + elen > madt_end) {
            kprintf("MADT: entri rusak (tipe %u panjang %u), berhenti\r\n",
                    (unsigned)entry_header->entry_type, (unsigned)elen);
            g_acpi_bad++;
            break;
        }

        if (entry_header->entry_type == 0 && elen >= sizeof(struct acpi_madt_local_apic))
        {
            struct acpi_madt_local_apic *lapic = (struct acpi_madt_local_apic *)entry_ptr;
            serial_write("MADT: Local APIC entry -- processor_id=");
            serial_write_hex(lapic->acpi_processor_id);
            serial_write(" apic_id=");
            serial_write_hex(lapic->apic_id);
            serial_write(" flags=");
            serial_write_hex(lapic->flags);
            serial_write("\r\n");
            if (lapic->flags & 3) {   // aktif atau bisa dinyalakan
                g_acpi_cpus++;
            }
        }
        else if (entry_header->entry_type == 9 && elen >= 16)
        {
            uint32_t xflags;
            memcpy(&xflags, entry_ptr + 8, 4);   // x2APIC: flags di offset 8
            if (xflags & 3) {
                g_acpi_cpus++;
            }
        }
        else if (entry_header->entry_type == 1 && elen >= sizeof(struct acpi_madt_ioapic))
        {
            struct acpi_madt_ioapic *ioapic = (struct acpi_madt_ioapic *)entry_ptr;
            serial_write("MADT: IOAPIC entry -- id=");
            serial_write_hex(ioapic->ioapic_id);
            serial_write(" address=");
            serial_write_hex(ioapic->ioapic_address);
            serial_write(" gsi_base=");
            serial_write_hex(ioapic->global_system_interrupt_base);
            serial_write("\r\n");

            // Asumsi single-IOAPIC system (umum di hardware kelas ini):
            // simpan yang pertama ditemukan.
            if (g_ioapic_address == 0)
            {
                g_ioapic_address = ioapic->ioapic_address;
                g_ioapic_id = ioapic->ioapic_id;
                g_ioapic_gsi_base = ioapic->global_system_interrupt_base;
            }
        }
        else if (entry_header->entry_type == 2 && elen >= sizeof(struct acpi_madt_iso))
        {
            struct acpi_madt_iso *iso = (struct acpi_madt_iso *)entry_ptr;
            serial_write("MADT: Interrupt Source Override -- bus_source=");
            serial_write_hex(iso->bus_source);
            serial_write(" irq_source=");
            serial_write_hex(iso->irq_source);
            serial_write(" gsi=");
            serial_write_hex(iso->global_system_interrupt);
            serial_write(" flags=");
            serial_write_hex(iso->flags);
            serial_write("\r\n");

            if (iso->irq_source == 0)
            {
                g_irq0_gsi = iso->global_system_interrupt;
                serial_write("MADT: IRQ0 di-override ke GSI ");
                serial_write_hex(g_irq0_gsi);
                serial_write("\r\n");
            }
        }
        else
        {
            serial_write("MADT: entry type lain (");
            serial_write_hex(entry_header->entry_type);
            serial_write("), diabaikan\r\n");
        }

        entry_ptr += elen;
    }
}

// P2: HPET (signature "HPET"): GAS alamat basis di offset 40 (ruang @40,
// alamat 64-bit @44), nomor HPET @52, tick minimum periodik @53. Hanya dicatat
// (dipakai nanti di H4); ruang alamat harus memori (0).
static void acpi_parse_hpet(const struct acpi_sdt_header *h)
{
    const uint8_t *b = (const uint8_t *)h;

    if (h->length < 56) {
        serial_write("P2: HPET terlalu pendek, diabaikan\r\n");
        g_acpi_bad++;
        return;
    }
    memcpy(&g_hpet_base, b + 44, 8);
    memcpy(&g_hpet_min_tick, b + 53, 2);
    g_hpet_ok = b[40] == 0 && g_hpet_base != 0;
    kprintf("P2: HPET base=0x%lx nomor=%u min_tick=%u ruang=%u %s\r\n",
            g_hpet_base, (unsigned)b[52], (unsigned)g_hpet_min_tick, (unsigned)b[40],
            g_hpet_ok ? "ok" : "tidak dipakai");
}

// ACPI-R: register reset di FADT (signature "FACP"). Flags offset 112
// bit 10 = RESET_REG_SUP; RESET_REG (Generic Address Structure 12 byte)
// di offset 116, RESET_VALUE di offset 128 (FADT revisi 2+, length >= 129).
// Hanya ruang alamat I/O (space_id 1) yang didukung; memori/PCI dicatat
// sebagai tidak didukung (reboot lanjut ke 8042).
int g_acpi_reset_ok = 0;
uint16_t g_acpi_reset_port = 0;
uint8_t g_acpi_reset_value = 0;

// R1-1 (dulu priv_do_reboot di auth.c): register reset ACPI (FADT, ACPI-R),
// 8042 pulse reset (0xFE), lalu cadangan triple fault (IDT limit 0 lalu
// int3). NOACPIRESET=1 dan NOKBDRESET=1 melewati jalur masing-masing untuk
// menguji cadangan. Tidak pernah kembali.
void machine_reboot(void)
{
    __asm__ volatile("cli");
    g_serial_mute = 0;

#ifndef BMAHOS_NOACPIRESET
    if (g_acpi_reset_ok) {
        serial_write("ACPI-R: reboot via register reset FADT\r\n");
        logdisk_sync(0);   // R4: sisa log (termasuk baris ini) ke LOG.BIN
        outb(g_acpi_reset_port, g_acpi_reset_value);

        for (uint32_t i = 0; i < 1000000; i++) {
            (void)inb(0x64);
        }

        serial_write("ACPI-R: reset ACPI tidak me-reset, lanjut 8042\r\n");
    }
#else
    serial_write("ACPI-R: reset ACPI dilewati (build NOACPIRESET)\r\n");
#endif

#ifndef BMAHOS_NOKBDRESET
    serial_write("Net-18B: reboot via 8042 (0xFE)\r\n");
    logdisk_sync(0);   // R4

    for (uint32_t i = 0; i < 100000; i++) {
        if ((inb(0x64) & 0x02) == 0) {
            break;
        }
    }

    outb(0x64, 0xFE);

    for (uint32_t i = 0; i < 1000000; i++) {
        (void)inb(0x64);
    }

    serial_write("Net-18B: 8042 tidak me-reset, cadangan triple fault\r\n");
#else
    serial_write("Net-18B: reboot via triple fault (build NOKBDRESET)\r\n");
#endif

    struct __attribute__((packed)) {
        uint16_t limit;
        uint64_t base;
    } zero_idt = {0, 0};

    __asm__ volatile("lidt %0; int3" : : "m"(zero_idt));

    for (;;) {
        __asm__ volatile("hlt");
    }
}

static void acpi_parse_fadt(struct acpi_sdt_header *fadt)
{
    uint8_t *f = (uint8_t *)fadt;

    serial_write("ACPI-R: FADT revision=");
    serial_write_hex(fadt->revision);
    serial_write(" length=");
    serial_write_hex(fadt->length);
    serial_write("\r\n");

    if (fadt->length < 129) {
        serial_write("ACPI-R: FADT terlalu pendek, tanpa register reset\r\n");
        return;
    }

    uint32_t flags = *(uint32_t *)(f + 112);
    uint8_t space = f[116];
    uint64_t addr = *(uint64_t *)(f + 120);
    uint8_t value = f[128];

    serial_write("ACPI-R: RESET_REG_SUP=");
    serial_write_hex((flags >> 10) & 1);
    serial_write(" space=");
    serial_write_hex(space);
    serial_write(" addr=");
    serial_write_hex(addr);
    serial_write(" value=");
    serial_write_hex(value);
    serial_write("\r\n");

    if (!((flags >> 10) & 1) || addr == 0) {
        serial_write("ACPI-R: register reset tidak tersedia\r\n");
        return;
    }

    if (space != 1 || addr > 0xFFFF) {
        serial_write("ACPI-R: ruang alamat reset bukan I/O, tidak didukung\r\n");
        return;
    }

    g_acpi_reset_port = (uint16_t)addr;
    g_acpi_reset_value = value;
    g_acpi_reset_ok = 1;
    serial_write("ACPI-R: reset ACPI siap\r\n");
}

// P2: RSDP (checksum 20 byte; revisi 2+ juga checksum panjang penuh) ->
// XSDT (atau RSDT bila XSDT tidak ada/rusak) -> setiap tabel divalidasi,
// dicatat untuk perintah `acpi`, lalu FADT, MADT, HPET di-parse.
int acpi_parse_rsdp(const struct acpi_rsdp *rsdp)
{
    struct acpi_madt *madt = NULL;
    struct acpi_sdt_header *fadt = NULL, *hpet = NULL;

    g_acpi_ntabs = 0;
    serial_write("ACPI: RSDP ditemukan, revision=");
    serial_write_hex(rsdp->revision);
    serial_write("\r\n");
    if (memcmp(rsdp->signature, "RSD PTR ", 8) != 0 || !acpi_sum_ok(rsdp, 20)) {
        serial_write("ACPI: RSDP rusak (signature/checksum), ACPI dilewati\r\n");
        g_acpi_bad++;
        return -1;
    }
    int use_xsdt = rsdp->revision >= 2 && rsdp->xsdt_address != 0;

    if (use_xsdt && (rsdp->length < sizeof(struct acpi_rsdp) || rsdp->length > 4096 ||
                     !acpi_sum_ok(rsdp, rsdp->length))) {
        serial_write("ACPI: checksum RSDP panjang salah, pakai RSDT\r\n");
        g_acpi_bad++;
        use_xsdt = 0;
    }

    const struct acpi_sdt_header *root;

    if (use_xsdt) {
        serial_write("ACPI: menggunakan XSDT di physical ");
        serial_write_hex(rsdp->xsdt_address);
        root = (const struct acpi_sdt_header *)(rsdp->xsdt_address + hhdm_offset);
    } else {
        serial_write("ACPI: menggunakan RSDT di physical ");
        serial_write_hex(rsdp->rsdt_address);
        root = (const struct acpi_sdt_header *)((uint64_t)rsdp->rsdt_address + hhdm_offset);
    }
    serial_write("\r\n");
    if (!acpi_table_ok(root) || !acpi_sig(root, use_xsdt ? "XSDT" : "RSDT")) {
        serial_write("ACPI: XSDT/RSDT rusak, ACPI dilewati\r\n");
        g_acpi_bad++;
        return -1;
    }

    uint32_t esz = use_xsdt ? 8 : 4;
    uint32_t n = (root->length - (uint32_t)sizeof(*root)) / esz;
    const uint8_t *ent = (const uint8_t *)root + sizeof(*root);

    for (uint32_t i = 0; i < n; i++) {
        uint64_t pa = 0;

        memcpy(&pa, ent + (uint64_t)i * esz, esz);
        if (pa == 0) {
            continue;
        }
        struct acpi_sdt_header *h = (struct acpi_sdt_header *)(pa + hhdm_offset);
        int ok = acpi_table_ok(h);

        acpi_note(h, ok);
        if (!ok) {
            g_acpi_bad++;
            continue;
        }
        if (madt == NULL && acpi_sig(h, "APIC")) {
            madt = (struct acpi_madt *)h;
        } else if (fadt == NULL && acpi_sig(h, "FACP")) {
            fadt = h;
        } else if (hpet == NULL && acpi_sig(h, "HPET")) {
            hpet = h;
        }
    }

    if (fadt != NULL) {
        acpi_parse_fadt(fadt);
    } else {
        serial_write("ACPI-R: FADT (FACP) tidak ditemukan\r\n");
    }
    if (hpet != NULL) {
        acpi_parse_hpet(hpet);
    }
    if (madt == NULL) {
        serial_write("ACPI: MADT (signature APIC) TIDAK DITEMUKAN\r\n");
    } else {
        serial_write("ACPI: MADT ditemukan, parsing...\r\n");
        acpi_parse_madt(madt);
    }
    kprintf("P2: ACPI tabel=%u ditolak=%u cpu=%u hpet=%s\r\n", g_acpi_ntabs, g_acpi_bad,
            g_acpi_cpus, g_hpet_ok ? "ada" : "tidak ada");
    return 0;
}

// Perintah `acpi`: satu baris per tabel dari XSDT/RSDT, lalu ringkasan.
void acpi_list(void (*out)(const char *))
{
    char line[80];

    for (uint32_t i = 0; i < g_acpi_ntabs; i++) {
        ksnprintf(line, sizeof(line), "%s len=%u rev=%u %s\n", g_acpi_tabs[i].sig,
                  g_acpi_tabs[i].len, (unsigned)g_acpi_tabs[i].rev,
                  g_acpi_tabs[i].ok ? "ok" : "rusak");
        out(line);
    }
    ksnprintf(line, sizeof(line), "acpi: tabel=%u ditolak=%u cpu=%u hpet=0x%lx%s\n",
              g_acpi_ntabs, g_acpi_bad, g_acpi_cpus, g_hpet_base,
              g_hpet_ok ? "" : " (tidak dipakai)");
    out(line);
}

#ifndef BMAHOS_HOST_TEST
void acpi_init(void)
{
    if (rsdp_request.response == NULL)
    {
        serial_write("ACPI: RSDP tidak tersedia (rsdp_request.response == NULL)\r\n");
        return;
    }
    acpi_parse_rsdp((const struct acpi_rsdp *)rsdp_request.response->address);
}
#endif

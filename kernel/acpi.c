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

static struct acpi_sdt_header *acpi_find_table(void *root_sdt, int use_xsdt, const char *signature)
{
    struct acpi_sdt_header *root_header = (struct acpi_sdt_header *)root_sdt;
    uint32_t entries_length = root_header->length - sizeof(struct acpi_sdt_header);

    if (use_xsdt)
    {
        uint64_t *entries = (uint64_t *)((uint8_t *)root_sdt + sizeof(struct acpi_sdt_header));
        uint32_t count = entries_length / sizeof(uint64_t);
        for (uint32_t i = 0; i < count; i++)
        {
            struct acpi_sdt_header *table = (struct acpi_sdt_header *)(entries[i] + hhdm_offset);
            if (
                table->signature[0] == signature[0] &&
                table->signature[1] == signature[1] &&
                table->signature[2] == signature[2] &&
                table->signature[3] == signature[3])
            {
                return table;
            }
        }
    }
    else
    {
        uint32_t *entries = (uint32_t *)((uint8_t *)root_sdt + sizeof(struct acpi_sdt_header));
        uint32_t count = entries_length / sizeof(uint32_t);
        for (uint32_t i = 0; i < count; i++)
        {
            struct acpi_sdt_header *table = (struct acpi_sdt_header *)((uint64_t)entries[i] + hhdm_offset);
            if (
                table->signature[0] == signature[0] &&
                table->signature[1] == signature[1] &&
                table->signature[2] == signature[2] &&
                table->signature[3] == signature[3])
            {
                return table;
            }
        }
    }

    return NULL;
}

static void acpi_parse_madt(struct acpi_madt *madt)
{
    g_local_apic_address = madt->local_apic_address;
    serial_write("MADT: Local APIC address = ");
    serial_write_hex(g_local_apic_address);
    serial_write("\r\n");

    uint8_t *entry_ptr = (uint8_t *)madt + sizeof(struct acpi_madt);
    uint8_t *madt_end = (uint8_t *)madt + madt->header.length;

    while (entry_ptr < madt_end)
    {
        struct acpi_madt_entry_header *entry_header = (struct acpi_madt_entry_header *)entry_ptr;

        if (entry_header->entry_type == 0)
        {
            struct acpi_madt_local_apic *lapic = (struct acpi_madt_local_apic *)entry_ptr;
            serial_write("MADT: Local APIC entry -- processor_id=");
            serial_write_hex(lapic->acpi_processor_id);
            serial_write(" apic_id=");
            serial_write_hex(lapic->apic_id);
            serial_write(" flags=");
            serial_write_hex(lapic->flags);
            serial_write("\r\n");
        }
        else if (entry_header->entry_type == 1)
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
        else if (entry_header->entry_type == 2)
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

        entry_ptr += entry_header->entry_length;
    }
}

// ACPI-R: register reset di FADT (signature "FACP"). Flags offset 112
// bit 10 = RESET_REG_SUP; RESET_REG (Generic Address Structure 12 byte)
// di offset 116, RESET_VALUE di offset 128 (FADT revisi 2+, length >= 129).
// Hanya ruang alamat I/O (space_id 1) yang didukung; memori/PCI dicatat
// sebagai tidak didukung (reboot lanjut ke 8042).
int g_acpi_reset_ok = 0;
uint16_t g_acpi_reset_port = 0;
uint8_t g_acpi_reset_value = 0;

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

void acpi_init(void)
{
    if (rsdp_request.response == NULL)
    {
        serial_write("ACPI: RSDP tidak tersedia (rsdp_request.response == NULL)\r\n");
        return;
    }

    struct acpi_rsdp *rsdp = (struct acpi_rsdp *)rsdp_request.response->address;

    serial_write("ACPI: RSDP ditemukan, revision=");
    serial_write_hex(rsdp->revision);
    serial_write("\r\n");

    struct acpi_madt *madt = NULL;
    struct acpi_sdt_header *fadt = NULL;

    if (rsdp->revision >= 2 && rsdp->xsdt_address != 0)
    {
        serial_write("ACPI: menggunakan XSDT di physical ");
        serial_write_hex(rsdp->xsdt_address);
        serial_write("\r\n");
        void *xsdt = (void *)(rsdp->xsdt_address + hhdm_offset);
        madt = (struct acpi_madt *)acpi_find_table(xsdt, 1, "APIC");
        fadt = acpi_find_table(xsdt, 1, "FACP");
    }
    else
    {
        serial_write("ACPI: menggunakan RSDT di physical ");
        serial_write_hex(rsdp->rsdt_address);
        serial_write("\r\n");
        void *rsdt = (void *)((uint64_t)rsdp->rsdt_address + hhdm_offset);
        madt = (struct acpi_madt *)acpi_find_table(rsdt, 0, "APIC");
        fadt = acpi_find_table(rsdt, 0, "FACP");
    }

    if (fadt != NULL) {
        acpi_parse_fadt(fadt);
    } else {
        serial_write("ACPI-R: FADT (FACP) tidak ditemukan\r\n");
    }

    if (madt == NULL)
    {
        serial_write("ACPI: MADT (signature APIC) TIDAK DITEMUKAN\r\n");
        return;
    }

    serial_write("ACPI: MADT ditemukan, parsing...\r\n");
    acpi_parse_madt(madt);
}

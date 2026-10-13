#include "kernel.h"

// Checkpoint AHCI (discovery): map BAR5 (ABAR) ke virtual seperti
// LAPIC/IOAPIC, baca register generik HBA (CAP/GHC/IS/PI/VS), log ke
// serial. MURNI observasi -- TIDAK ADA command list, FIS, port init,
// atau baca/tulis sector apa pun di checkpoint ini. Port yang benar-
// benar punya device terpasang bisa dilihat dari bit PI yang set DAN
// PxSSTS port itu (belum dibaca di checkpoint ini -- checkpoint
// berikutnya).
#define AHCI_MAX_ATA_PORTS 4

static struct {
    volatile uint32_t *hba;
    uint32_t port;
    uint64_t cmd_table_phys;
    uint8_t *cmd_table_virt;
    uint64_t data_phys;      // D6-1: buffer DMA 1 halaman per port, dipakai ulang
    uint8_t *data_virt;
    int initialized;
} g_ahci_ata_ports[AHCI_MAX_ATA_PORTS];

int g_ahci_ata_port_count = 0;

// D6-1: semua poll register dibatasi (dulu tanpa timeout). Satu baca MMIO di VM
// ~1 us, jadi 5 juta putaran = beberapa detik; habis -> error, bukan macet.
#define AHCI_POLL_MAX 5000000u

static int ahci_wait_clear(volatile uint32_t *reg, uint32_t mask)
{
    for (uint32_t i = 0; i < AHCI_POLL_MAX; i++) {
        if (!(*reg & mask)) {
            return 1;
        }
    }

    return 0;
}

void ahci_port_init(volatile uint32_t *hba, uint32_t port)
{
    if (g_ahci_ata_port_count >= AHCI_MAX_ATA_PORTS) {
        serial_write("AHCI: port_init: WARNING - AHCI_MAX_ATA_PORTS tercapai, port ");
        serial_write_hex(port);
        serial_write(" dilewati\r\n");
        return;
    }

    uint32_t port_base = 0x100 + (port * 0x80);

    volatile uint32_t *pclb  = &hba[(port_base + 0x00) / 4];
    volatile uint32_t *pclbu = &hba[(port_base + 0x04) / 4];
    volatile uint32_t *pfb   = &hba[(port_base + 0x08) / 4];
    volatile uint32_t *pfbu  = &hba[(port_base + 0x0C) / 4];
    volatile uint32_t *pis   = &hba[(port_base + 0x10) / 4];
    volatile uint32_t *pcmd  = &hba[(port_base + 0x18) / 4];
    volatile uint32_t *ptfd  = &hba[(port_base + 0x20) / 4];

    serial_write("AHCI: port_init start, port ");
    serial_write_hex(port);
    serial_write("\r\n");

    uint32_t cmd = *pcmd;

    if (cmd & (1u << 0)) {
        cmd &= ~(1u << 0);
        *pcmd = cmd;
    }

    if (!ahci_wait_clear(pcmd, 1u << 15)) {
        serial_write("AHCI: port_init: ERROR - PxCMD.CR tidak turun (timeout), port dilewati\r\n");
        return;
    }

    cmd = *pcmd;

    if (cmd & (1u << 4)) {
        cmd &= ~(1u << 4);
        *pcmd = cmd;
    }

    if (!ahci_wait_clear(pcmd, 1u << 14)) {
        serial_write("AHCI: port_init: ERROR - PxCMD.FR tidak turun (timeout), port dilewati\r\n");
        return;
    }

    serial_write("AHCI: port_init: port stopped (CR=0, FR=0)\r\n");

    uint64_t cmd_list_phys  = pmm_alloc();
    uint64_t fis_phys       = pmm_alloc();
    uint64_t cmd_table_phys = pmm_alloc();
    uint64_t data_phys      = pmm_alloc();

    if (cmd_list_phys == 0 || fis_phys == 0 || cmd_table_phys == 0 || data_phys == 0) {
        // D6-1: dulu halt; kini port dilewati (pmm_free(0) no-op).
        serial_write("AHCI: port_init: ERROR - pmm_alloc gagal, port dilewati\r\n");
        pmm_free(cmd_list_phys);
        pmm_free(fis_phys);
        pmm_free(cmd_table_phys);
        pmm_free(data_phys);
        return;
    }

    uint8_t *cmd_list_virt  = (uint8_t *)(cmd_list_phys + hhdm_offset);
    uint8_t *fis_virt       = (uint8_t *)(fis_phys + hhdm_offset);
    uint8_t *cmd_table_virt = (uint8_t *)(cmd_table_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        cmd_list_virt[i] = 0;
        fis_virt[i] = 0;
        cmd_table_virt[i] = 0;
    }

    uint32_t *cmd_header0 = (uint32_t *)cmd_list_virt;
    cmd_header0[2] = (uint32_t)(cmd_table_phys & 0xFFFFFFFFu);
    cmd_header0[3] = (uint32_t)(cmd_table_phys >> 32);

    *pclb  = (uint32_t)(cmd_list_phys & 0xFFFFFFFFu);
    *pclbu = (uint32_t)(cmd_list_phys >> 32);
    *pfb   = (uint32_t)(fis_phys & 0xFFFFFFFFu);
    *pfbu  = (uint32_t)(fis_phys >> 32);

    uint32_t is_val = *pis;
    *pis = is_val;

    cmd = *pcmd;
    cmd |= (1u << 4);
    *pcmd = cmd;

    cmd = *pcmd;
    cmd |= (1u << 0);
    *pcmd = cmd;

    uint32_t tfd = *ptfd;

    serial_write("AHCI: port_init: PxTFD=");
    serial_write_hex(tfd);
    serial_write("\r\n");

    if (tfd & 0x1) {
        serial_write("AHCI: port_init: WARNING - TFD.ERR set\r\n");
    }

    serial_write("AHCI: port_init: done, port ready (CLB=");
    serial_write_hex(cmd_list_phys);
    serial_write(" FB=");
    serial_write_hex(fis_phys);
    serial_write(" CTBA=");
    serial_write_hex(cmd_table_phys);
    serial_write(")\r\n");

    int slot = g_ahci_ata_port_count;

    g_ahci_ata_ports[slot].hba = hba;
    g_ahci_ata_ports[slot].port = port;
    g_ahci_ata_ports[slot].cmd_table_phys = cmd_table_phys;
    g_ahci_ata_ports[slot].cmd_table_virt = cmd_table_virt;
    g_ahci_ata_ports[slot].data_phys = data_phys;
    g_ahci_ata_ports[slot].data_virt = (uint8_t *)(data_phys + hhdm_offset);
    g_ahci_ata_ports[slot].initialized = 1;

    g_ahci_ata_port_count++;

    serial_write("AHCI: port_init: terdaftar sebagai port_index ");
    serial_write_hex((uint64_t)slot);
    serial_write("\r\n");
}

#define AHCI_ERR_LBA        -1
#define AHCI_ERR_COUNT      -2
#define AHCI_ERR_ALLOC      -3
#define AHCI_ERR_NOT_INIT   -4
#define AHCI_ERR_DEVICE     -5

// Block-device style read: LBA + jumlah sektor -> buffer virtual (HHDM).
// count dibatasi 1..8 (1 halaman fisik = 4096 byte = 8 sektor 512 byte),
// karena buffer dialokasikan sebagai SATU frame pmm_alloc() -- dua
// pmm_alloc() berturut-turut TIDAK dijamin contiguous secara fisik,
// jadi kita sengaja tidak mendukung count > 8 di checkpoint ini
// (utang teknis eksplisit, bukan lupa: perlu multi-PRDT/scatter-gather
// untuk mendukung lebih dari 1 halaman).
// D6-1: *out_buf = buffer DMA milik port (tidak lagi pmm_alloc per panggilan,
// dulu bocor 1 halaman tiap baca); isinya hanya berlaku sampai panggilan
// ahci_* berikutnya. Timeout PxCI -> AHCI_ERR_TIMEOUT dan port dimatikan
// (perintah mungkin masih berjalan, buffer tidak boleh dipakai lagi).
#define AHCI_ERR_BAD_PORT   -6
#define AHCI_ERR_TIMEOUT    -7

// D6-3: satu perintah ATA lewat slot 0. ata_cmd 0x25 READ DMA EXT,
// 0x35 WRITE DMA EXT (wbuf = isi count sektor, disalin ke buffer DMA port),
// 0xEA FLUSH CACHE EXT (count 0, tanpa PRDT).
static int ahci_issue(uint32_t port_index, uint8_t ata_cmd, uint64_t lba,
                      uint32_t count, const uint8_t *wbuf)
{
    if (port_index >= (uint32_t)g_ahci_ata_port_count) {
        return AHCI_ERR_BAD_PORT;
    }

    if (!g_ahci_ata_ports[port_index].initialized) {
        return AHCI_ERR_NOT_INIT;
    }

    if (count > 8 || (count == 0 && ata_cmd != 0xEA)) {
        return AHCI_ERR_COUNT;
    }

    if (count > 0 && lba + (uint64_t)(count - 1) > 0x0000FFFFFFFFFFFFULL) {
        return AHCI_ERR_LBA;
    }

    volatile uint32_t *hba = g_ahci_ata_ports[port_index].hba;
    uint32_t port = g_ahci_ata_ports[port_index].port;
    uint32_t port_base = 0x100 + (port * 0x80);

    volatile uint32_t *pci_reg = &hba[(port_base + 0x38) / 4];
    volatile uint32_t *ptfd    = &hba[(port_base + 0x20) / 4];
    volatile uint32_t *pclb    = &hba[(port_base + 0x00) / 4];

    uint64_t data_buf_phys = g_ahci_ata_ports[port_index].data_phys;
    uint8_t *data_buf_virt = g_ahci_ata_ports[port_index].data_virt;

    if (wbuf) {
        for (uint32_t i = 0; i < count * 512u; i++) {
            data_buf_virt[i] = wbuf[i];
        }
    } else {
        for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
            data_buf_virt[i] = 0xAA;
        }
    }

    uint8_t *cmd_table_virt = g_ahci_ata_ports[port_index].cmd_table_virt;

    for (uint64_t i = 0; i < 0x90; i++) {
        cmd_table_virt[i] = 0;
    }

    uint32_t byte_count = count * 512u;

    cmd_table_virt[0x00] = 0x27;
    cmd_table_virt[0x01] = 0x80;
    cmd_table_virt[0x02] = ata_cmd;
    cmd_table_virt[0x03] = 0x00;
    cmd_table_virt[0x04] = (uint8_t)((lba >> 0) & 0xFF);
    cmd_table_virt[0x05] = (uint8_t)((lba >> 8) & 0xFF);
    cmd_table_virt[0x06] = (uint8_t)((lba >> 16) & 0xFF);
    cmd_table_virt[0x07] = 0x40;
    cmd_table_virt[0x08] = (uint8_t)((lba >> 24) & 0xFF);
    cmd_table_virt[0x09] = (uint8_t)((lba >> 32) & 0xFF);
    cmd_table_virt[0x0A] = (uint8_t)((lba >> 40) & 0xFF);
    cmd_table_virt[0x0B] = 0x00;
    cmd_table_virt[0x0C] = (uint8_t)(count & 0xFF);
    cmd_table_virt[0x0D] = (uint8_t)((count >> 8) & 0xFF);
    cmd_table_virt[0x0E] = 0x00;
    cmd_table_virt[0x0F] = 0x00;

    uint32_t *prdt0 = (uint32_t *)(cmd_table_virt + 0x80);
    prdt0[0] = (uint32_t)(data_buf_phys & 0xFFFFFFFFu);
    prdt0[1] = (uint32_t)(data_buf_phys >> 32);
    prdt0[2] = 0;
    prdt0[3] = (byte_count - 1);

    uint64_t cmd_list_phys_current = (uint64_t)(*pclb);
    uint32_t *header0 = (uint32_t *)(cmd_list_phys_current + hhdm_offset);

    header0[0] = 5u;
    if (count > 0) {
        header0[0] |= (1u << 16);   // PRDTL = 1
    }
    if (wbuf) {
        header0[0] |= (1u << 6);    // W: host -> perangkat
    }
    header0[1] = 0;

    *pci_reg = (1u << 0);

    if (!ahci_wait_clear(pci_reg, 1u << 0)) {
        g_ahci_ata_ports[port_index].initialized = 0;
        return AHCI_ERR_TIMEOUT;
    }

    uint32_t tfd = *ptfd;

    if (tfd & 0x1) {
        return AHCI_ERR_DEVICE;
    }

    return AHCI_OK;
}

int ahci_read(uint32_t port_index, uint64_t lba, uint32_t count, uint8_t **out_buf)
{
    if (count == 0) {
        return AHCI_ERR_COUNT;
    }

    int rc = ahci_issue(port_index, 0x25, lba, count, 0);

    if (rc == AHCI_OK) {
        *out_buf = g_ahci_ata_ports[port_index].data_virt;
    }

    return rc;
}

// D6-3: tulis count (1..8) sektor dari buf. Cache perangkat belum tentu
// sudah ke media: pemanggil yang butuh urutan memanggil ahci_flush().
int ahci_write(uint32_t port_index, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    if (count == 0 || !buf) {
        return AHCI_ERR_COUNT;
    }

    return ahci_issue(port_index, 0x35, lba, count, buf);
}

int ahci_flush(uint32_t port_index)
{
    return ahci_issue(port_index, 0xEA, 0, 0, 0);
}

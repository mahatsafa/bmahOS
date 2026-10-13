#include "kernel.h"

// FAT32-1: scan semua port ATA yang sudah di-init, coba baca boot sector
// (LBA 0), validasi signature 0x55AA DAN field BPB (RootEntryCount==0
// dan FATSz16==0) untuk memastikan ini benar-benar FAT32, bukan FAT12/16
// yang kebetulan punya signature sama. Murni parsing + logging, belum
// baca FAT table atau directory sama sekali (checkpoint berikutnya).
static struct {
    int valid;
    uint32_t port_index;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t reserved_sector_count;
    uint32_t num_fats;
    uint32_t fat_sz32;
    uint32_t root_cluster;
    uint64_t fat_start_lba;
    uint64_t data_start_lba;
    uint64_t total_sectors;    // D6-2
    uint32_t max_cluster;      // D6-2: cluster sah = 2..max_cluster
    uint32_t fsinfo_sector;    // D6-3
    int writable;              // D6-3: 0 = baca saja (BPB/FSInfo, atau error I/O saat tulis)
} g_fat32_volume;

static uint32_t fat32_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void fat32_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

// D6-3: FSInfo sah = tiga tanda tangan di tempatnya.
static int fat32_fsinfo_ok(const uint8_t *b)
{
    return fat32_le32(b) == 0x41615252u && fat32_le32(b + 484) == 0x61417272u &&
           fat32_le32(b + 508) == 0xAA550000u;
}

// D6-2: nomor cluster dari disk (dir entry, FAT, BPB) tidak dipercaya.
static int fat32_cluster_ok(uint32_t c)
{
    return c >= 2 && c <= g_fat32_volume.max_cluster;
}

// D6-2: validasi BPB lengkap. Return NULL kalau sah, selain itu alasan
// penolakan (volume dilewati, tidak pernah halt).
static const char *fat32_bpb_check(const uint8_t *buf, uint64_t *out_total,
                                   uint32_t *out_max)
{
    uint16_t bps = (uint16_t)buf[0x0B] | ((uint16_t)buf[0x0C] << 8);
    uint8_t spc = buf[0x0D];
    uint16_t rsvd = (uint16_t)buf[0x0E] | ((uint16_t)buf[0x0F] << 8);
    uint8_t nf = buf[0x10];
    uint16_t rec = (uint16_t)buf[0x11] | ((uint16_t)buf[0x12] << 8);
    uint16_t tot16 = (uint16_t)buf[0x13] | ((uint16_t)buf[0x14] << 8);
    uint16_t fsz16 = (uint16_t)buf[0x16] | ((uint16_t)buf[0x17] << 8);
    uint32_t tot32 = (uint32_t)buf[0x20] | ((uint32_t)buf[0x21] << 8) |
                     ((uint32_t)buf[0x22] << 16) | ((uint32_t)buf[0x23] << 24);
    uint32_t fsz32 = (uint32_t)buf[0x24] | ((uint32_t)buf[0x25] << 8) |
                     ((uint32_t)buf[0x26] << 16) | ((uint32_t)buf[0x27] << 24);
    uint32_t root = (uint32_t)buf[0x2C] | ((uint32_t)buf[0x2D] << 8) |
                    ((uint32_t)buf[0x2E] << 16) | ((uint32_t)buf[0x2F] << 24);

    if (rec != 0 || fsz16 != 0) {
        return "RootEntryCount/FATSz16 tidak nol (FAT12/16)";
    }
    if (bps != 512) {
        return "BytesPerSector bukan 512";
    }
    if (spc != 1 && spc != 2 && spc != 4 && spc != 8) {
        return "SectorsPerCluster bukan 1/2/4/8";
    }
    if (rsvd == 0) {
        return "ReservedSectorCount nol";
    }
    if (nf != 1 && nf != 2) {
        return "NumFATs bukan 1/2";
    }
    if (fsz32 == 0) {
        return "FATSz32 nol";
    }

    uint64_t total = tot16 != 0 ? tot16 : tot32;
    uint64_t data_start = (uint64_t)rsvd + (uint64_t)nf * fsz32;

    if (total <= data_start) {
        return "area data di luar ukuran volume";
    }

    uint64_t clusters = (total - data_start) / spc;

    if (clusters == 0 || clusters > 0x0FFFFFF5u) {
        return "jumlah cluster di luar jangkauan";
    }
    if ((uint64_t)fsz32 * 128 < clusters + 2) {
        return "FAT terlalu kecil untuk jumlah cluster";
    }
    if (root < 2 || root > clusters + 1) {
        return "RootCluster di luar jangkauan";
    }

    *out_total = total;
    *out_max = (uint32_t)(clusters + 1);
    return 0;
}

void ahci_fat32_probe_and_log(void)
{
    serial_write("FAT32: scanning ATA ports untuk boot sector valid\r\n");

    for (int idx = 0; idx < g_ahci_ata_port_count; idx++) {
        uint8_t *buf = 0;
        int rc = ahci_read((uint32_t)idx, 0, 1, &buf);

        serial_write("FAT32: port_index ");
        serial_write_hex((uint64_t)idx);
        serial_write(" ahci_read rc=");
        serial_write_hex((uint64_t)(int64_t)rc);
        serial_write("\r\n");

        if (rc != AHCI_OK) {
            continue;
        }

        if (buf[0x1FE] != 0x55 || buf[0x1FF] != 0xAA) {
            serial_write("FAT32: port_index ");
            serial_write_hex((uint64_t)idx);
            serial_write(" - signature 0x55AA tidak ada, skip\r\n");
            continue;
        }

        uint16_t bytes_per_sector = (uint16_t)buf[0x0B] | ((uint16_t)buf[0x0C] << 8);
        uint8_t sectors_per_cluster = buf[0x0D];
        uint16_t reserved_sector_count = (uint16_t)buf[0x0E] | ((uint16_t)buf[0x0F] << 8);
        uint8_t num_fats = buf[0x10];
        uint16_t root_entry_count = (uint16_t)buf[0x11] | ((uint16_t)buf[0x12] << 8);
        uint16_t fat_sz16 = (uint16_t)buf[0x16] | ((uint16_t)buf[0x17] << 8);
        uint32_t fat_sz32 = (uint32_t)buf[0x24] | ((uint32_t)buf[0x25] << 8) |
                             ((uint32_t)buf[0x26] << 16) | ((uint32_t)buf[0x27] << 24);
        uint32_t root_cluster = (uint32_t)buf[0x2C] | ((uint32_t)buf[0x2D] << 8) |
                                 ((uint32_t)buf[0x2E] << 16) | ((uint32_t)buf[0x2F] << 24);

        serial_write("FAT32: port_index ");
        serial_write_hex((uint64_t)idx);
        serial_write(" BytesPerSector=");
        serial_write_hex(bytes_per_sector);
        serial_write(" SectorsPerCluster=");
        serial_write_hex(sectors_per_cluster);
        serial_write(" ReservedSectorCount=");
        serial_write_hex(reserved_sector_count);
        serial_write(" NumFATs=");
        serial_write_hex(num_fats);
        serial_write(" RootEntryCount=");
        serial_write_hex(root_entry_count);
        serial_write(" FATSz16=");
        serial_write_hex(fat_sz16);
        serial_write(" FATSz32=");
        serial_write_hex(fat_sz32);
        serial_write(" RootCluster=");
        serial_write_hex(root_cluster);
        serial_write("\r\n");

        uint64_t total_sectors = 0;
        uint32_t max_cluster = 0;
        const char *why = fat32_bpb_check(buf, &total_sectors, &max_cluster);

        if (why) {
            serial_write("FAT32: port_index ");
            serial_write_hex((uint64_t)idx);
            serial_write(" - BPB ditolak: ");
            serial_write(why);
            serial_write(", skip\r\n");
            continue;
        }

        g_fat32_volume.valid = 1;
        g_fat32_volume.port_index = (uint32_t)idx;
        g_fat32_volume.bytes_per_sector = bytes_per_sector;
        g_fat32_volume.sectors_per_cluster = sectors_per_cluster;
        g_fat32_volume.reserved_sector_count = reserved_sector_count;
        g_fat32_volume.num_fats = num_fats;
        g_fat32_volume.fat_sz32 = fat_sz32;
        g_fat32_volume.root_cluster = root_cluster;
        g_fat32_volume.fat_start_lba = (uint64_t)reserved_sector_count;
        g_fat32_volume.data_start_lba = (uint64_t)reserved_sector_count +
            ((uint64_t)num_fats * (uint64_t)fat_sz32);
        g_fat32_volume.total_sectors = total_sectors;
        g_fat32_volume.max_cluster = max_cluster;

        // D6-3: tulis hanya bila semua FAT dicerminkan (ExtFlags bit 7 = 0)
        // dan FSInfo sah. buf (buffer DMA) dipakai ulang oleh baca FSInfo.
        uint16_t ext_flags = (uint16_t)buf[0x28] | ((uint16_t)buf[0x29] << 8);
        uint16_t fsinfo = (uint16_t)buf[0x30] | ((uint16_t)buf[0x31] << 8);
        const char *ro_why = 0;

        g_fat32_volume.fsinfo_sector = fsinfo;
        g_fat32_volume.writable = 0;

        if (ext_flags & 0x80) {
            ro_why = "mirroring FAT mati (ExtFlags bit 7)";
        } else if (fsinfo == 0 || fsinfo >= reserved_sector_count) {
            ro_why = "sektor FSInfo di luar area reserved";
        } else if (ahci_read((uint32_t)idx, fsinfo, 1, &buf) != AHCI_OK) {
            ro_why = "FSInfo tidak terbaca";
        } else if (!fat32_fsinfo_ok(buf)) {
            ro_why = "tanda tangan FSInfo salah";
        } else {
            g_fat32_volume.writable = 1;
        }

        serial_write("FAT32: port_index ");
        serial_write_hex((uint64_t)idx);
        serial_write(" - VALID FAT32 volume ditemukan\r\n");
        serial_write("FAT32: max_cluster=");
        serial_write_hex(max_cluster);
        if (ro_why) {
            serial_write(" mode=baca-saja: ");
            serial_write(ro_why);
            serial_write("\r\n");
        } else {
            serial_write(" mode=tulis\r\n");
        }
    }
}

static uint32_t fat32_read_fat_entry(uint32_t cluster);

// FAT32-4A: cari file di root directory berdasar nama 8.3 EXACT 11 byte
// (format directory entry apa adanya, contoh "HELLO   TXT" -- BUKAN
// "HELLO.TXT"). Konversi otomatis nama biasa -> 8.3 sengaja TIDAK
// dilakukan di checkpoint ini, supaya kontrak fungsi deterministic
// dan tidak menambah satu sumber bug baru sekaligus.
int fat32_find_file(const char *name_83, uint32_t *out_cluster, uint32_t *out_size)
{
    if (!g_fat32_volume.valid) {
        return 0;
    }

    uint32_t root_cluster = g_fat32_volume.root_cluster;

    if (root_cluster < 2) {
        return 0;
    }

    uint64_t root_lba = g_fat32_volume.data_start_lba +
        (uint64_t)(root_cluster - 2) * (uint64_t)g_fat32_volume.sectors_per_cluster;

    uint32_t sectors_to_read = g_fat32_volume.sectors_per_cluster;

    if (sectors_to_read == 0 || sectors_to_read > 8) {
        return 0;
    }

    uint8_t *buf = 0;
    int rc = ahci_read(g_fat32_volume.port_index, root_lba, sectors_to_read, &buf);

    if (rc != AHCI_OK) {
        return 0;
    }

    uint32_t cluster_size_bytes = sectors_to_read * g_fat32_volume.bytes_per_sector;
    uint32_t entry_count = cluster_size_bytes / 32;

    for (uint32_t i = 0; i < entry_count; i++) {
        uint8_t *entry = buf + (i * 32);

        if (entry[0x00] == 0x00) {
            break;
        }

        if (entry[0x00] == 0xE5) {
            continue;
        }

        uint8_t attr = entry[0x0B];

        if (attr == 0x0F) {
            continue;
        }

        int match = 1;

        for (int c = 0; c < 11; c++) {
            if (entry[c] != (uint8_t)name_83[c]) {
                match = 0;
                break;
            }
        }

        if (!match) {
            continue;
        }

        uint16_t cluster_high = (uint16_t)entry[0x14] | ((uint16_t)entry[0x15] << 8);
        uint16_t cluster_low  = (uint16_t)entry[0x1A] | ((uint16_t)entry[0x1B] << 8);
        uint32_t first_cluster = ((uint32_t)cluster_high << 16) | (uint32_t)cluster_low;
        uint32_t file_size = (uint32_t)entry[0x1C] | ((uint32_t)entry[0x1D] << 8) |
                              ((uint32_t)entry[0x1E] << 16) | ((uint32_t)entry[0x1F] << 24);

        *out_cluster = first_cluster;
        *out_size = file_size;

        return 1;
    }

    return 0;
}

// FAT32-4A: alokasi 1 halaman via pmm_alloc(), isi dengan konten file
// (mengikuti cluster chain, SAMA seperti fat32_read_file() tapi tulis
// ke buffer alih-alih serial_putc()). Return pointer HHDM ke buffer,
// atau NULL kalau gagal. file_size==0 ditangani sebagai kasus khusus:
// buffer tetap dialokasikan tapi tidak ada cluster yang dibaca sama
// sekali (first_cluster untuk file kosong sering bernilai 0 di FAT32,
// itu bukan error).
uint8_t *fat32_load_file(uint32_t first_cluster, uint32_t file_size)
{
    if (!g_fat32_volume.valid) {
        return 0;
    }

    if (file_size > PMM_PAGE_SIZE) {
        serial_write("FAT32-4A: FATAL - file_size melebihi 1 halaman, dibatalkan\r\n");
        return 0;
    }

    uint64_t buf_phys = pmm_alloc();

    if (buf_phys == 0) {
        return 0;
    }

    uint8_t *buf_virt = (uint8_t *)(buf_phys + hhdm_offset);

    for (uint64_t i = 0; i < PMM_PAGE_SIZE; i++) {
        buf_virt[i] = 0;
    }

    if (file_size == 0) {
        return buf_virt;
    }

    if (!fat32_cluster_ok(first_cluster)) {
        serial_write("FAT32-4A: ERROR - first_cluster di luar jangkauan padahal file_size > 0\r\n");
        goto fail;
    }

    uint32_t sectors_per_cluster = g_fat32_volume.sectors_per_cluster;

    if (sectors_per_cluster == 0 || sectors_per_cluster > 8) {
        goto fail;
    }

    uint32_t cluster_size_bytes = sectors_per_cluster * g_fat32_volume.bytes_per_sector;

    uint32_t cluster = first_cluster;
    uint32_t bytes_remaining = file_size;
    uint32_t buf_offset = 0;
    int iteration_guard = 0;

    while (bytes_remaining > 0 && cluster < 0x0FFFFFF8u) {
        iteration_guard++;

        if (iteration_guard > 1000) {
            serial_write("FAT32-4A: FATAL - lebih dari 1000 iterasi cluster chain\r\n");
            goto fail;
        }

        uint64_t lba = g_fat32_volume.data_start_lba +
            (uint64_t)(cluster - 2) * (uint64_t)sectors_per_cluster;

        uint8_t *sector_buf = 0;
        int rc = ahci_read(g_fat32_volume.port_index, lba, sectors_per_cluster, &sector_buf);

        if (rc != AHCI_OK) {
            goto fail;
        }

        uint32_t to_copy = bytes_remaining;

        if (to_copy > cluster_size_bytes) {
            to_copy = cluster_size_bytes;
        }

        for (uint32_t i = 0; i < to_copy; i++) {
            buf_virt[buf_offset + i] = sector_buf[i];
        }

        buf_offset += to_copy;
        bytes_remaining -= to_copy;

        if (bytes_remaining == 0) {
            break;
        }

        cluster = fat32_read_fat_entry(cluster);

        if (cluster == 0xFFFFFFFFu) {
            goto fail;
        }

        if (cluster < 0x0FFFFFF8u && !fat32_cluster_ok(cluster)) {
            serial_write("FAT32-4A: ERROR - rantai cluster di luar jangkauan\r\n");
            goto fail;
        }
    }

    if (bytes_remaining > 0) {
        serial_write("FAT32-4A: WARNING - chain berakhir tapi masih ada byte tersisa\r\n");
        goto fail;
    }

    return buf_virt;

fail:
    // D6-3: dulu halaman ini bocor di setiap jalur gagal.
    pmm_free(buf_phys);
    return 0;
}

// FAT32-2: konversi RootCluster (nomor cluster dari BPB) menjadi LBA
// sebenarnya, lalu baca satu entry FAT table untuk cluster tersebut.
// Belum membaca isi directory sama sekali (checkpoint berikutnya).
void fat32_probe_root_cluster(void)
{
    if (!g_fat32_volume.valid) {
        serial_write("FAT32-2: tidak ada volume FAT32 valid, skip\r\n");
        return;
    }

    uint32_t root_cluster = g_fat32_volume.root_cluster;

    if (root_cluster < 2) {
        serial_write("FAT32-2: root_cluster < 2, volume tidak valid\r\n");
        return;
    }

    uint64_t root_lba = g_fat32_volume.data_start_lba +
        (uint64_t)(root_cluster - 2) * (uint64_t)g_fat32_volume.sectors_per_cluster;

    serial_write("FAT32-2: fat_start_lba=");
    serial_write_hex(g_fat32_volume.fat_start_lba);
    serial_write(" data_start_lba=");
    serial_write_hex(g_fat32_volume.data_start_lba);
    serial_write("\r\n");

    serial_write("FAT32-2: root_cluster=");
    serial_write_hex(root_cluster);
    serial_write(" -> root_lba=");
    serial_write_hex(root_lba);
    serial_write("\r\n");

    uint64_t byte_offset = (uint64_t)root_cluster * 4;
    uint64_t fat_sector = g_fat32_volume.fat_start_lba +
        (byte_offset / (uint64_t)g_fat32_volume.bytes_per_sector);
    uint64_t offset_in_sector = byte_offset % (uint64_t)g_fat32_volume.bytes_per_sector;

    serial_write("FAT32-2: fat_sector=");
    serial_write_hex(fat_sector);
    serial_write(" offset_in_sector=");
    serial_write_hex(offset_in_sector);
    serial_write("\r\n");

    uint8_t *buf = 0;
    int rc = ahci_read(g_fat32_volume.port_index, fat_sector, 1, &buf);

    serial_write("FAT32-2: ahci_read(fat_sector) rc=");
    serial_write_hex((uint64_t)(int64_t)rc);
    serial_write("\r\n");

    if (rc != AHCI_OK) {
        return;
    }

    uint32_t raw_entry = (uint32_t)buf[offset_in_sector] |
                          ((uint32_t)buf[offset_in_sector + 1] << 8) |
                          ((uint32_t)buf[offset_in_sector + 2] << 16) |
                          ((uint32_t)buf[offset_in_sector + 3] << 24);

    uint32_t next_cluster = raw_entry & 0x0FFFFFFFu;

    serial_write("FAT32-2: raw_entry=");
    serial_write_hex(raw_entry);
    serial_write(" next_cluster(masked)=");
    serial_write_hex(next_cluster);
    serial_write("\r\n");

    if (next_cluster >= 0x0FFFFFF8u) {
        serial_write("FAT32-2: next_cluster = END OF CHAIN (root directory 1 cluster)\r\n");
    } else if (next_cluster == 0) {
        serial_write("FAT32-2: WARNING - next_cluster = 0 (free), tidak wajar untuk cluster aktif\r\n");
    } else {
        serial_write("FAT32-2: next_cluster menunjuk cluster lain dalam rantai\r\n");
    }
}

// FAT32-3: baca isi cluster root directory, parse 32-byte directory
// entries (short filename / 8.3 format), list nama yang ditemukan.
// LFN (Long File Name) entries (attribute 0x0F) di-skip, dicatat saja --
// tidak diproses, karena nama file test kita (HELLO.TXT, TEST) muat
// pas di format 8.3 sehingga tidak seharusnya menghasilkan LFN entry.
void fat32_list_root_directory(void)
{
    if (!g_fat32_volume.valid) {
        serial_write("FAT32-3: tidak ada volume FAT32 valid, skip\r\n");
        return;
    }

    uint32_t root_cluster = g_fat32_volume.root_cluster;

    if (root_cluster < 2) {
        serial_write("FAT32-3: root_cluster < 2, volume tidak valid\r\n");
        return;
    }

    uint64_t root_lba = g_fat32_volume.data_start_lba +
        (uint64_t)(root_cluster - 2) * (uint64_t)g_fat32_volume.sectors_per_cluster;

    uint32_t sectors_to_read = g_fat32_volume.sectors_per_cluster;

    if (sectors_to_read == 0 || sectors_to_read > 8) {
        serial_write("FAT32-3: sectors_per_cluster di luar jangkauan ahci_read (utang teknis), skip\r\n");
        return;
    }

    uint8_t *buf = 0;
    int rc = ahci_read(g_fat32_volume.port_index, root_lba, sectors_to_read, &buf);

    serial_write("FAT32-3: ahci_read(root_lba, ");
    serial_write_hex(sectors_to_read);
    serial_write(" sektor) rc=");
    serial_write_hex((uint64_t)(int64_t)rc);
    serial_write("\r\n");

    if (rc != AHCI_OK) {
        return;
    }

    uint32_t cluster_size_bytes = sectors_to_read * g_fat32_volume.bytes_per_sector;
    uint32_t entry_count = cluster_size_bytes / 32;

    serial_write("FAT32-3: listing root directory (max ");
    serial_write_hex(entry_count);
    serial_write(" slot):\r\n");

    for (uint32_t i = 0; i < entry_count; i++) {
        uint8_t *entry = buf + (i * 32);

        if (entry[0x00] == 0x00) {
            serial_write("FAT32-3: end of directory (slot ");
            serial_write_hex(i);
            serial_write(")\r\n");
            break;
        }

        if (entry[0x00] == 0xE5) {
            continue;
        }

        uint8_t attr = entry[0x0B];

        if (attr == 0x0F) {
            serial_write("FAT32-3: slot ");
            serial_write_hex(i);
            serial_write(" - LFN entry (di-skip, tidak diproses)\r\n");
            continue;
        }

        uint16_t cluster_high = (uint16_t)entry[0x14] | ((uint16_t)entry[0x15] << 8);
        uint16_t cluster_low  = (uint16_t)entry[0x1A] | ((uint16_t)entry[0x1B] << 8);
        uint32_t first_cluster = ((uint32_t)cluster_high << 16) | (uint32_t)cluster_low;
        uint32_t file_size = (uint32_t)entry[0x1C] | ((uint32_t)entry[0x1D] << 8) |
                              ((uint32_t)entry[0x1E] << 16) | ((uint32_t)entry[0x1F] << 24);

        serial_write("FAT32-3: slot ");
        serial_write_hex(i);
        serial_write(" name=\"");
        for (int c = 0; c < 11; c++) {
            serial_putc((char)entry[c]);
        }
        serial_write("\" attr=");
        serial_write_hex(attr);
        serial_write(" first_cluster=");
        serial_write_hex(first_cluster);
        serial_write(" size=");
        serial_write_hex(file_size);
        serial_write((attr & 0x10) ? " [DIRECTORY]\r\n" : " [FILE]\r\n");
    }
}

// Baca satu FAT entry untuk nomor cluster tertentu, kembalikan
// next_cluster yang sudah di-mask 0x0FFFFFFF. Return 0xFFFFFFFF
// (sentinel, bukan nilai FAT valid karena sudah di-mask 28 bit)
// kalau ahci_read gagal.
static uint32_t fat32_read_fat_entry(uint32_t cluster)
{
    if (!fat32_cluster_ok(cluster)) {
        return 0xFFFFFFFFu;
    }

    uint64_t byte_offset = (uint64_t)cluster * 4;
    uint64_t fat_sector = g_fat32_volume.fat_start_lba +
        (byte_offset / (uint64_t)g_fat32_volume.bytes_per_sector);
    uint64_t offset_in_sector = byte_offset % (uint64_t)g_fat32_volume.bytes_per_sector;

    uint8_t *buf = 0;
    int rc = ahci_read(g_fat32_volume.port_index, fat_sector, 1, &buf);

    if (rc != AHCI_OK) {
        return 0xFFFFFFFFu;
    }

    uint32_t raw_entry = (uint32_t)buf[offset_in_sector] |
                          ((uint32_t)buf[offset_in_sector + 1] << 8) |
                          ((uint32_t)buf[offset_in_sector + 2] << 16) |
                          ((uint32_t)buf[offset_in_sector + 3] << 24);

    return raw_entry & 0x0FFFFFFFu;
}

// FAT32-4: baca isi file dengan mengikuti cluster chain, mulai dari
// first_cluster (didapat dari directory entry di FAT32-3), berhenti
// setelah file_size byte terbaca atau chain mencapai EOC.
void fat32_read_file(uint32_t first_cluster, uint32_t file_size)
{
    if (!g_fat32_volume.valid) {
        serial_write("FAT32-4: tidak ada volume FAT32 valid, skip\r\n");
        return;
    }

    if (!fat32_cluster_ok(first_cluster)) {
        serial_write("FAT32-4: first_cluster di luar jangkauan, tidak valid\r\n");
        return;
    }

    uint32_t sectors_per_cluster = g_fat32_volume.sectors_per_cluster;

    if (sectors_per_cluster == 0 || sectors_per_cluster > 8) {
        serial_write("FAT32-4: sectors_per_cluster di luar jangkauan ahci_read (utang teknis), skip\r\n");
        return;
    }

    uint32_t cluster_size_bytes = sectors_per_cluster * g_fat32_volume.bytes_per_sector;

    serial_write("FAT32-4: membaca file, first_cluster=");
    serial_write_hex(first_cluster);
    serial_write(" file_size=");
    serial_write_hex(file_size);
    serial_write(" byte\r\n");

    uint32_t cluster = first_cluster;
    uint32_t bytes_remaining = file_size;
    int iteration_guard = 0;

    serial_write("FAT32-4: isi file = \"");

    while (bytes_remaining > 0 && cluster < 0x0FFFFFF8u) {
        iteration_guard++;

        if (iteration_guard > 1000) {
            serial_write("\"\r\nFAT32-4: FATAL - lebih dari 1000 iterasi cluster chain, kemungkinan circular chain (FAT corrupt)\r\n");
            return;
        }

        uint64_t lba = g_fat32_volume.data_start_lba +
            (uint64_t)(cluster - 2) * (uint64_t)sectors_per_cluster;

        uint8_t *buf = 0;
        int rc = ahci_read(g_fat32_volume.port_index, lba, sectors_per_cluster, &buf);

        if (rc != AHCI_OK) {
            serial_write("\"\r\nFAT32-4: ahci_read gagal di tengah pembacaan file, rc=");
            serial_write_hex((uint64_t)(int64_t)rc);
            serial_write("\r\n");
            return;
        }

        uint32_t to_copy = bytes_remaining;

        if (to_copy > cluster_size_bytes) {
            to_copy = cluster_size_bytes;
        }

        for (uint32_t i = 0; i < to_copy; i++) {
            serial_putc((char)buf[i]);
        }

        bytes_remaining -= to_copy;

        if (bytes_remaining == 0) {
            break;
        }

        cluster = fat32_read_fat_entry(cluster);

        if (cluster == 0xFFFFFFFFu) {
            serial_write("\"\r\nFAT32-4: fat32_read_fat_entry gagal di tengah pembacaan file\r\n");
            return;
        }

        if (cluster < 0x0FFFFFF8u && !fat32_cluster_ok(cluster)) {
            serial_write("\"\r\nFAT32-4: ERROR - rantai cluster di luar jangkauan\r\n");
            return;
        }
    }

    serial_write("\"\r\n");

    if (bytes_remaining > 0) {
        serial_write("FAT32-4: WARNING - chain berakhir (EOC) tapi masih ");
        serial_write_hex(bytes_remaining);
        serial_write(" byte tersisa\r\n");
    } else {
        serial_write("FAT32-4: file selesai dibaca, seluruh byte cocok dengan file_size\r\n");
    }
}

// ---- D6-3: FAT32 tulis (root directory saja, file <= FAT32_WRITE_MAX) ----
// Urutan tulis (flush perangkat di antara fase), supaya crash di titik mana
// pun paling buruk menyisakan cluster hilang (lost cluster), tidak pernah
// entri direktori yang menunjuk ke data/rantai yang belum ditulis:
//   1. data ke cluster baru (dan ekor cluster terakhir di belakang ukuran lama)
//   2. entri FAT rantai baru, semua salinan FAT (FAT1 lalu FAT2)
//   3. tambah: sambungkan ujung rantai lama ke rantai baru
//   4. entri direktori (cluster awal + ukuran), satu sektor
//   5. timpa: bebaskan rantai lama (copy-on-write: rantai lama tidak
//      pernah disentuh sebelum entri direktori menunjuk rantai baru)
//   6. FSInfo (jumlah bebas + petunjuk cluster bebas)
// Semua pemeriksaan (nama, ukuran, rantai lama, ruang kosong, slot dir)
// selesai sebelum fase 1. Error I/O setelah fase 1 dimulai -> volume baca
// saja sampai reboot (gagal tertutup).

uint64_t g_fat_wr_ok = 0;
uint64_t g_fat_wr_fail = 0;

static uint8_t g_fw_sec[512];                    // FAT / FSInfo (baca-ubah-tulis)
static uint8_t g_fw_fsi[512];                    // FSInfo
static uint8_t g_fw_dir[FAT32_WRITE_MAX];        // cluster root (spc <= 8)
static uint8_t g_fw_clu[FAT32_WRITE_MAX];        // satu cluster data

#define FAT32_EOC 0x0FFFFFFFu
#define FAT32_CHAIN_MAX (FAT32_WRITE_MAX / 512)  // cluster maks satu file yang ditulis

static int fw_read(uint64_t lba, uint32_t n, uint8_t *dst)
{
    uint8_t *b = 0;

    if (ahci_read(g_fat32_volume.port_index, lba, n, &b) != AHCI_OK) {
        return FAT32_ERR_IO;
    }

    for (uint32_t i = 0; i < n * 512u; i++) {
        dst[i] = b[i];
    }

    return FAT32_OK;
}

static int fw_write(uint64_t lba, uint32_t n, const uint8_t *src)
{
    if (ahci_write(g_fat32_volume.port_index, lba, n, src) != AHCI_OK) {
        return FAT32_ERR_IO;
    }

    return FAT32_OK;
}

static int fw_flush(void)
{
    return ahci_flush(g_fat32_volume.port_index) == AHCI_OK ? FAT32_OK : FAT32_ERR_IO;
}

static uint64_t fw_cluster_lba(uint32_t c)
{
    return g_fat32_volume.data_start_lba +
           (uint64_t)(c - 2) * g_fat32_volume.sectors_per_cluster;
}

// Ubah satu entri di salinan FAT ke-f; 4 bit atas entri lama dipertahankan.
static int fw_fat_set(uint32_t f, uint32_t cluster, uint32_t value)
{
    uint64_t lba = g_fat32_volume.fat_start_lba + (uint64_t)f * g_fat32_volume.fat_sz32 +
                   ((uint64_t)cluster * 4) / 512;
    uint32_t off = (cluster * 4) % 512;

    if (fw_read(lba, 1, g_fw_sec) != FAT32_OK) {
        return FAT32_ERR_IO;
    }

    uint32_t old = fat32_le32(g_fw_sec + off);
    fat32_put32(g_fw_sec + off, (old & 0xF0000000u) | (value & 0x0FFFFFFFu));
    return fw_write(lba, 1, g_fw_sec);
}

// Cari n cluster bebas (entri FAT1 == 0) mulai dari petunjuk, memutar sekali.
static int fw_alloc(uint32_t n, uint32_t hint, uint32_t *out)
{
    uint32_t c = fat32_cluster_ok(hint) ? hint : 2;
    uint32_t found = 0;
    uint64_t cached = ~0ull;

    for (uint32_t k = 0; k < g_fat32_volume.max_cluster - 1 && found < n; k++) {
        uint64_t lba = g_fat32_volume.fat_start_lba + ((uint64_t)c * 4) / 512;

        if (lba != cached) {
            if (fw_read(lba, 1, g_fw_sec) != FAT32_OK) {
                return FAT32_ERR_IO;
            }
            cached = lba;
        }

        if ((fat32_le32(g_fw_sec + (c * 4) % 512) & 0x0FFFFFFFu) == 0) {
            out[found++] = c;
        }

        c = c >= g_fat32_volume.max_cluster ? 2 : c + 1;
    }

    return found == n ? FAT32_OK : FAT32_ERR_FULL;
}

// Rantai file: ceil(size / ukuran cluster) cluster sah, berbeda satu sama lain.
// Rantai yang lebih panjang dari ukuran diterima (sisanya diabaikan = lost
// cluster): itu keadaan sah setelah crash di antara fase 3 dan 4 di bawah.
static int fw_walk(uint32_t first, uint32_t size, uint32_t *chain, uint32_t *count)
{
    uint32_t cs = g_fat32_volume.sectors_per_cluster * 512;
    uint32_t need = (size + cs - 1) / cs;

    *count = 0;

    if (size == 0) {
        return first == 0 ? FAT32_OK : FAT32_ERR_CORRUPT;
    }

    uint32_t c = first;

    for (uint32_t i = 0; i < need; i++) {
        if (!fat32_cluster_ok(c)) {
            return FAT32_ERR_CORRUPT;
        }

        for (uint32_t j = 0; j < i; j++) {
            if (chain[j] == c) {
                return FAT32_ERR_CORRUPT;   // rantai melingkar
            }
        }

        chain[i] = c;

        uint32_t next = fat32_read_fat_entry(c);

        if (next == 0xFFFFFFFFu) {
            return FAT32_ERR_IO;
        }

        if (i + 1 < need) {
            c = next;
        }
    }

    *count = need;
    return FAT32_OK;
}

// Salinan cluster root dir (berlaku sampai fat32_* berikutnya). Hanya cluster
// root pertama; kalau tidak ada penanda akhir (0x00) di sana dan rantai root
// berlanjut -> FAT32_ERR_UNSUP (nama di cluster berikutnya tidak terlihat).
int fat32_root_read(const uint8_t **dir, uint32_t *entries)
{
    if (!g_fat32_volume.valid) {
        return FAT32_ERR_NOVOL;
    }

    uint32_t spc = g_fat32_volume.sectors_per_cluster;

    if (fw_read(fw_cluster_lba(g_fat32_volume.root_cluster), spc, g_fw_dir) != FAT32_OK) {
        return FAT32_ERR_IO;
    }

    uint32_t n = spc * 16;

    for (uint32_t i = 0; i < n; i++) {
        if (g_fw_dir[i * 32] == 0x00) {
            *dir = g_fw_dir;
            *entries = n;
            return FAT32_OK;
        }
    }

    uint32_t next = fat32_read_fat_entry(g_fat32_volume.root_cluster);

    if (next == 0xFFFFFFFFu) {
        return FAT32_ERR_IO;
    }

    if (next < 0x0FFFFFF8u) {
        return FAT32_ERR_UNSUP;
    }

    *dir = g_fw_dir;
    *entries = n;
    return FAT32_OK;
}

// Cluster pertama dari entri direktori 32 byte.
static uint32_t fw_entry_first(const uint8_t *e)
{
    return ((uint32_t)e[0x14] | ((uint32_t)e[0x15] << 8)) << 16 |
           (uint32_t)e[0x1A] | ((uint32_t)e[0x1B] << 8);
}

// Tulis sektor root yang memuat entri idx dari salinan g_fw_dir, lalu flush.
static int fw_dir_commit(int idx)
{
    uint32_t sec = ((uint32_t)idx * 32) / 512;

    if (fw_write(fw_cluster_lba(g_fat32_volume.root_cluster) + sec, 1,
                 g_fw_dir + sec * 512) != FAT32_OK ||
        fw_flush() != FAT32_OK) {
        return FAT32_ERR_IO;
    }

    return FAT32_OK;
}

// Perbarui FSInfo (g_fw_fsi sudah dibaca): add cluster dipakai (terakhir =
// last), freed dibebaskan. Data sudah utuh di disk; gagal di sini hanya
// membuat volume baca saja.
static void fw_fsinfo_commit(int fsi_ok, uint32_t add, uint32_t freed, uint32_t last)
{
    if (!fsi_ok || (add == 0 && freed == 0)) {
        return;
    }

    uint32_t fc = fat32_le32(g_fw_fsi + 488);

    if (fc != 0xFFFFFFFFu) {
        fc = (fc + freed >= add && fc + freed <= g_fat32_volume.max_cluster - 1)
                 ? fc + freed - add : 0xFFFFFFFFu;
        fat32_put32(g_fw_fsi + 488, fc);
    }

    if (add > 0) {
        fat32_put32(g_fw_fsi + 492, last + 1 > g_fat32_volume.max_cluster ? 2 : last + 1);
    }

    if (fw_write(g_fat32_volume.fsinfo_sector, 1, g_fw_fsi) != FAT32_OK ||
        fw_flush() != FAT32_OK) {
        g_fat32_volume.writable = 0;
        serial_write("FAT32: ERROR - FSInfo gagal ditulis, volume kini baca saja\r\n");
    }
}

// Bebaskan rantai (count cluster) di semua salinan FAT, lalu flush.
static int fw_free_chain(const uint32_t *chain, uint32_t count)
{
    for (uint32_t f = 0; f < g_fat32_volume.num_fats; f++) {
        for (uint32_t i = 0; i < count; i++) {
            if (fw_fat_set(f, chain[i], 0) != FAT32_OK) {
                return FAT32_ERR_IO;
            }
        }
    }

    return count > 0 ? fw_flush() : FAT32_OK;
}

// Cari nama 8.3 (11 byte) di salinan root. Return indeks entri atau -1;
// *free_slot = slot 0xE5/0x00 pertama (atau -1).
static int fw_dir_find(const uint8_t *dir, uint32_t n, const char *name83, int *free_slot)
{
    *free_slot = -1;

    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *e = dir + i * 32;

        if (e[0] == 0x00) {
            if (*free_slot < 0) {
                *free_slot = (int)i;
            }
            return -1;
        }

        if (e[0] == 0xE5) {
            if (*free_slot < 0) {
                *free_slot = (int)i;
            }
            continue;
        }

        if (e[0x0B] == 0x0F) {
            continue;   // LFN
        }

        int match = 1;

        for (int c = 0; c < 11; c++) {
            if (e[c] != (uint8_t)name83[c]) {
                match = 0;
                break;
            }
        }

        if (match) {
            return (int)i;
        }
    }

    return -1;
}

// D7: slot kosong (0xE5/0x00) di sektor root ke-sec, atau -1.
static int fw_free_in_sec(const uint8_t *dir, uint32_t n, uint32_t sec)
{
    for (uint32_t i = sec * 16; i < sec * 16 + 16 && i < n; i++) {
        if (dir[i * 32] == 0xE5 || dir[i * 32] == 0x00) {
            return (int)i;
        }
    }

    return -1;
}

// D7: entri didahului entri LFN (nama panjang)? Hapus/rename entri seperti
// itu akan meninggalkan LFN yatim, jadi ditolak.
static int fw_has_lfn(const uint8_t *dir, int idx)
{
    return idx > 0 && dir[(idx - 1) * 32] != 0xE5 && dir[(idx - 1) * 32 + 0x0B] == 0x0F;
}

// Baca file (<= max byte) ke out. Return FAT32_OK / FAT32_ERR_*.
int fat32_read_name(const char *name83, uint8_t *out, uint32_t max, uint32_t *out_size)
{
    const uint8_t *dir;
    uint32_t n;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return rc;
    }

    int free_slot;
    int idx = fw_dir_find(dir, n, name83, &free_slot);

    if (idx < 0) {
        return FAT32_ERR_NOENT;
    }

    const uint8_t *e = dir + idx * 32;

    if (e[0x0B] & 0x18) {
        return FAT32_ERR_NOTFILE;   // direktori / label volume
    }

    uint32_t first = fw_entry_first(e);
    uint32_t size = fat32_le32(e + 0x1C);

    if (size > max || size > FAT32_WRITE_MAX) {
        return FAT32_ERR_TOOBIG;
    }

    uint32_t chain[FAT32_CHAIN_MAX];
    uint32_t cnt;

    rc = fw_walk(first, size, chain, &cnt);

    if (rc != FAT32_OK) {
        return rc;
    }

    uint32_t cs = g_fat32_volume.sectors_per_cluster * 512;
    uint32_t pos = 0;

    for (uint32_t i = 0; i < cnt; i++) {
        if (fw_read(fw_cluster_lba(chain[i]), g_fat32_volume.sectors_per_cluster,
                    g_fw_clu) != FAT32_OK) {
            return FAT32_ERR_IO;
        }

        for (uint32_t j = 0; j < cs && pos < size; j++) {
            out[pos++] = g_fw_clu[j];
        }
    }

    *out_size = size;
    return FAT32_OK;
}

static int fw_fail(int rc, int started)
{
    g_fat_wr_fail++;

    if (started && rc == FAT32_ERR_IO) {
        g_fat32_volume.writable = 0;
        serial_write("FAT32: ERROR - I/O gagal saat menulis, volume kini baca saja\r\n");
    }

    return rc;
}

// Tulis (append = 0: buat/timpa) atau tambah (append = 1: buat bila belum ada)
// len byte ke file name83 (11 byte 8.3) di root. *out_size = ukuran baru.
// want_sec >= 0 (D7): file baru wajib di sektor root itu (DIRFULL bila tidak
// ada slot di sana).
static int fw_write_file(const char *name83, const uint8_t *data, uint32_t len,
                         int append, int want_sec, uint32_t *out_size)
{
    if (!g_fat32_volume.valid) {
        return fw_fail(FAT32_ERR_NOVOL, 0);
    }

    if (!g_fat32_volume.writable) {
        return fw_fail(FAT32_ERR_RO, 0);
    }

    if (len > FAT32_WRITE_MAX) {
        return fw_fail(FAT32_ERR_TOOBIG, 0);
    }

    uint32_t spc = g_fat32_volume.sectors_per_cluster;
    uint32_t cs = spc * 512;
    uint32_t nf = g_fat32_volume.num_fats;
    const uint8_t *dir;
    uint32_t n;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    int free_slot;
    int idx = fw_dir_find(dir, n, name83, &free_slot);
    uint32_t old_first = 0, old_size = 0, old_n = 0;
    uint32_t old[FAT32_CHAIN_MAX];

    if (idx >= 0) {
        const uint8_t *e = dir + idx * 32;

        if (e[0x0B] & 0x1F) {
            return fw_fail(FAT32_ERR_NOTFILE, 0);   // RO/hidden/system/label/dir
        }

        old_first = fw_entry_first(e);
        old_size = fat32_le32(e + 0x1C);

        if (old_size > FAT32_WRITE_MAX) {
            return fw_fail(FAT32_ERR_TOOBIG, 0);
        }

        rc = fw_walk(old_first, old_size, old, &old_n);

        if (rc != FAT32_OK) {
            return fw_fail(rc, 0);
        }
    } else {
        if (want_sec >= 0) {
            free_slot = fw_free_in_sec(dir, n, (uint32_t)want_sec);
        }

        if (free_slot < 0) {
            return fw_fail(FAT32_ERR_DIRFULL, 0);
        }

        idx = free_slot;
    }

    uint32_t new_size = append ? old_size + len : len;

    if (new_size > FAT32_WRITE_MAX) {
        return fw_fail(FAT32_ERR_TOOBIG, 0);
    }

    uint32_t keep = append ? old_n : 0;
    uint32_t need = (new_size + cs - 1) / cs;
    uint32_t add = need - keep;
    uint32_t nw[FAT32_CHAIN_MAX];

    if (fw_read(g_fat32_volume.fsinfo_sector, 1, g_fw_fsi) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 0);
    }

    int fsi_ok = fat32_fsinfo_ok(g_fw_fsi);

    if (add > 0) {
        rc = fw_alloc(add, fsi_ok ? fat32_le32(g_fw_fsi + 492) : 2, nw);

        if (rc != FAT32_OK) {
            return fw_fail(rc, 0);
        }
    }

    // Fase 1: data.
    uint32_t pos = 0;
    uint32_t tail = append ? old_size % cs : 0;

    if (tail != 0 && len > 0) {
        uint64_t lba = fw_cluster_lba(old[old_n - 1]);

        if (fw_read(lba, spc, g_fw_clu) != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }

        for (uint32_t j = tail; j < cs && pos < len; j++) {
            g_fw_clu[j] = data[pos++];
        }

        if (fw_write(lba, spc, g_fw_clu) != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }
    }

    for (uint32_t i = 0; i < add; i++) {
        for (uint32_t j = 0; j < cs; j++) {
            g_fw_clu[j] = pos < len ? data[pos++] : 0;
        }

        if (fw_write(fw_cluster_lba(nw[i]), spc, g_fw_clu) != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }
    }

    if (fw_flush() != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 1);
    }

    // Fase 2 + 3: rantai baru, lalu sambungan dari ujung rantai lama.
    if (add > 0) {
        for (uint32_t f = 0; f < nf; f++) {
            for (uint32_t i = 0; i < add; i++) {
                if (fw_fat_set(f, nw[i], i + 1 < add ? nw[i + 1] : FAT32_EOC) != FAT32_OK) {
                    return fw_fail(FAT32_ERR_IO, 1);
                }
            }
        }

        if (fw_flush() != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }

        if (keep > 0) {
            for (uint32_t f = 0; f < nf; f++) {
                if (fw_fat_set(f, old[keep - 1], nw[0]) != FAT32_OK) {
                    return fw_fail(FAT32_ERR_IO, 1);
                }
            }

            if (fw_flush() != FAT32_OK) {
                return fw_fail(FAT32_ERR_IO, 1);
            }
        }
    }

    // Fase 4: entri direktori (g_fw_dir masih salinan root; fw_* lain tidak
    // menyentuhnya).
    uint32_t first = keep > 0 ? old_first : (add > 0 ? nw[0] : 0);
    uint8_t *e = g_fw_dir + idx * 32;

    if (e[0] == 0x00 || e[0] == 0xE5) {
        for (int j = 0; j < 32; j++) {
            e[j] = 0;
        }
        for (int j = 0; j < 11; j++) {
            e[j] = (uint8_t)name83[j];
        }
        e[0x0B] = 0x20;   // archive
        // Tanggal tetap 2026-01-01 (belum ada RTC tepercaya): ((2026-1980)<<9)|(1<<5)|1
        e[0x10] = 0x21; e[0x11] = 0x5C;   // tanggal buat
        e[0x12] = 0x21; e[0x13] = 0x5C;   // tanggal akses
        e[0x18] = 0x21; e[0x19] = 0x5C;   // tanggal ubah
    }

    e[0x14] = (uint8_t)(first >> 16);
    e[0x15] = (uint8_t)(first >> 24);
    e[0x1A] = (uint8_t)first;
    e[0x1B] = (uint8_t)(first >> 8);
    fat32_put32(e + 0x1C, new_size);

    if (fw_dir_commit(idx) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 1);
    }

    // Fase 5: timpa -> bebaskan rantai lama (file sudah menunjuk rantai baru).
    uint32_t freed = 0;

    if (!append && old_n > 0) {
        if (fw_free_chain(old, old_n) != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }

        freed = old_n;
    }

    // Fase 6: FSInfo. File sudah utuh di disk; gagal di sini hanya membuat
    // volume baca saja, hasil tetap OK.
    fw_fsinfo_commit(fsi_ok, add, freed, add > 0 ? nw[add - 1] : 0);

    g_fat_wr_ok++;
    *out_size = new_size;
    return FAT32_OK;
}

int fat32_write_name(const char *name83, const uint8_t *data, uint32_t len,
                     int append, uint32_t *out_size)
{
    return fw_write_file(name83, data, len, append, -1, out_size);
}

// Pemeriksaan bersama hapus/rename/ganti: entri idx file biasa tanpa LFN.
static int fw_entry_plain(const uint8_t *dir, int idx)
{
    if (dir[idx * 32 + 0x0B] & 0x1F) {
        return FAT32_ERR_NOTFILE;   // RO/hidden/system/label/dir
    }

    return fw_has_lfn(dir, idx) ? FAT32_ERR_LFN : FAT32_OK;
}

// D7: hapus file biasa (<= FAT32_WRITE_MAX). Urutan: entri 0xE5 + flush ->
// bebaskan rantai -> FSInfo. Crash di tengah = cluster hilang saja.
int fat32_delete_name(const char *name83)
{
    if (!g_fat32_volume.valid) {
        return fw_fail(FAT32_ERR_NOVOL, 0);
    }

    if (!g_fat32_volume.writable) {
        return fw_fail(FAT32_ERR_RO, 0);
    }

    const uint8_t *dir;
    uint32_t n;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    int free_slot;
    int idx = fw_dir_find(dir, n, name83, &free_slot);

    if (idx < 0) {
        return fw_fail(FAT32_ERR_NOENT, 0);
    }

    rc = fw_entry_plain(dir, idx);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    uint32_t size = fat32_le32(dir + idx * 32 + 0x1C);
    uint32_t chain[FAT32_CHAIN_MAX];
    uint32_t cnt;

    if (size > FAT32_WRITE_MAX) {
        return fw_fail(FAT32_ERR_TOOBIG, 0);
    }

    rc = fw_walk(fw_entry_first(dir + idx * 32), size, chain, &cnt);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    if (fw_read(g_fat32_volume.fsinfo_sector, 1, g_fw_fsi) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 0);
    }

    int fsi_ok = fat32_fsinfo_ok(g_fw_fsi);

    g_fw_dir[idx * 32] = 0xE5;

    if (fw_dir_commit(idx) != FAT32_OK || fw_free_chain(chain, cnt) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 1);
    }

    fw_fsinfo_commit(fsi_ok, 0, cnt, 0);
    g_fat_wr_ok++;
    return FAT32_OK;
}

// D7: ganti nama file biasa; nama baru tidak boleh sudah ada. Satu tulis
// sektor (11 byte nama).
int fat32_rename_name(const char *old83, const char *new83)
{
    if (!g_fat32_volume.valid) {
        return fw_fail(FAT32_ERR_NOVOL, 0);
    }

    if (!g_fat32_volume.writable) {
        return fw_fail(FAT32_ERR_RO, 0);
    }

    const uint8_t *dir;
    uint32_t n;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    int free_slot;
    int idx = fw_dir_find(dir, n, old83, &free_slot);

    if (idx < 0) {
        return fw_fail(FAT32_ERR_NOENT, 0);
    }

    rc = fw_entry_plain(dir, idx);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    if (fw_dir_find(dir, n, new83, &free_slot) >= 0) {
        return fw_fail(FAT32_ERR_EXIST, 0);
    }

    for (int j = 0; j < 11; j++) {
        g_fw_dir[idx * 32 + j] = (uint8_t)new83[j];
    }

    if (fw_dir_commit(idx) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 1);
    }

    g_fat_wr_ok++;
    return FAT32_OK;
}

// D7: ganti isi dst secara atomik lewat file sementara tmp:
//   1. tmp sisa (crash sebelumnya) dihapus;
//   2. data ditulis ke tmp (jalur fw_write_file), entri tmp di sektor root
//      yang sama dengan dst;
//   3. SATU tulis sektor: dst menunjuk rantai tmp + ukuran tmp, tmp = 0xE5
//      (dst belum ada: entri tmp cukup diganti namanya);
//   4. rantai dst lama dibebaskan, FSInfo.
// Crash sebelum 3: dst lama utuh (tmp mungkin tertinggal); sesudah 3: dst
// baru, paling buruk cluster hilang. Anggapan: tulis satu sektor atomik.
int fat32_replace_name(const char *dst83, const char *tmp83, const uint8_t *data,
                       uint32_t len)
{
    if (!g_fat32_volume.valid) {
        return fw_fail(FAT32_ERR_NOVOL, 0);
    }

    if (!g_fat32_volume.writable) {
        return fw_fail(FAT32_ERR_RO, 0);
    }

    const uint8_t *dir;
    uint32_t n;
    int free_slot;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    int d = fw_dir_find(dir, n, dst83, &free_slot);

    if (d >= 0 && (rc = fw_entry_plain(dir, d)) != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    if (fw_dir_find(dir, n, tmp83, &free_slot) >= 0) {
        rc = fat32_delete_name(tmp83);

        if (rc != FAT32_OK) {
            return rc;
        }
    }

    uint32_t size;

    rc = fw_write_file(tmp83, data, len, 0, d >= 0 ? d * 32 / 512 : -1, &size);

    if (rc != FAT32_OK) {
        return rc;
    }

    rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    int t = fw_dir_find(dir, n, tmp83, &free_slot);

    d = fw_dir_find(dir, n, dst83, &free_slot);

    if (t < 0 || (d >= 0 && d * 32 / 512 != t * 32 / 512)) {
        return fw_fail(FAT32_ERR_CORRUPT, 0);
    }

    if (d < 0) {
        for (int j = 0; j < 11; j++) {
            g_fw_dir[t * 32 + j] = (uint8_t)dst83[j];
        }

        if (fw_dir_commit(t) != FAT32_OK) {
            return fw_fail(FAT32_ERR_IO, 1);
        }

        g_fat_wr_ok++;
        return FAT32_OK;
    }

    uint8_t *de = g_fw_dir + d * 32;
    uint8_t *te = g_fw_dir + t * 32;
    uint32_t old_size = fat32_le32(de + 0x1C);
    uint32_t old[FAT32_CHAIN_MAX];
    uint32_t old_n;

    if (old_size > FAT32_WRITE_MAX) {
        return fw_fail(FAT32_ERR_TOOBIG, 0);
    }

    rc = fw_walk(fw_entry_first(de), old_size, old, &old_n);

    if (rc != FAT32_OK) {
        return fw_fail(rc, 0);
    }

    if (fw_read(g_fat32_volume.fsinfo_sector, 1, g_fw_fsi) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 0);
    }

    int fsi_ok = fat32_fsinfo_ok(g_fw_fsi);

    de[0x14] = te[0x14];
    de[0x15] = te[0x15];
    de[0x1A] = te[0x1A];
    de[0x1B] = te[0x1B];
    for (int j = 0x1C; j < 0x20; j++) {
        de[j] = te[j];
    }
    te[0] = 0xE5;

    if (fw_dir_commit(d) != FAT32_OK || fw_free_chain(old, old_n) != FAT32_OK) {
        return fw_fail(FAT32_ERR_IO, 1);
    }

    fw_fsinfo_commit(fsi_ok, 0, old_n, 0);
    g_fat_wr_ok++;
    return FAT32_OK;
}

int fat32_writable(void)
{
    return g_fat32_volume.valid && g_fat32_volume.writable;
}

// Jumlah cluster bebas dari FSInfo (0xFFFFFFFF = tidak diketahui).
uint32_t fat32_free_hint(void)
{
    if (!g_fat32_volume.valid ||
        fw_read(g_fat32_volume.fsinfo_sector, 1, g_fw_fsi) != FAT32_OK ||
        !fat32_fsinfo_ok(g_fw_fsi)) {
        return 0xFFFFFFFFu;
    }

    return fat32_le32(g_fw_fsi + 488);
}

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
} g_fat32_volume;

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

        if (root_entry_count != 0 || fat_sz16 != 0) {
            serial_write("FAT32: port_index ");
            serial_write_hex((uint64_t)idx);
            serial_write(" - RootEntryCount/FATSz16 tidak nol (ini FAT12/16, bukan FAT32), skip\r\n");
            continue;
        }

        if (bytes_per_sector != 512) {
            serial_write("FAT32: port_index ");
            serial_write_hex((uint64_t)idx);
            serial_write(" - BytesPerSector bukan 512, skip\r\n");
            continue;
        }

        if (fat_sz32 == 0) {
            serial_write("FAT32: port_index ");
            serial_write_hex((uint64_t)idx);
            serial_write(" - FATSz32 nol, bukan FAT32 valid, skip\r\n");
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

        serial_write("FAT32: port_index ");
        serial_write_hex((uint64_t)idx);
        serial_write(" - VALID FAT32 volume ditemukan\r\n");
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

    if (first_cluster < 2) {
        serial_write("FAT32-4A: FATAL - first_cluster < 2 padahal file_size > 0\r\n");
        return 0;
    }

    uint32_t sectors_per_cluster = g_fat32_volume.sectors_per_cluster;

    if (sectors_per_cluster == 0 || sectors_per_cluster > 8) {
        return 0;
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
            return 0;
        }

        uint64_t lba = g_fat32_volume.data_start_lba +
            (uint64_t)(cluster - 2) * (uint64_t)sectors_per_cluster;

        uint8_t *sector_buf = 0;
        int rc = ahci_read(g_fat32_volume.port_index, lba, sectors_per_cluster, &sector_buf);

        if (rc != AHCI_OK) {
            return 0;
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
            return 0;
        }
    }

    if (bytes_remaining > 0) {
        serial_write("FAT32-4A: WARNING - chain berakhir tapi masih ada byte tersisa\r\n");
        return 0;
    }

    return buf_virt;
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

    if (first_cluster < 2) {
        serial_write("FAT32-4: first_cluster < 2, tidak valid\r\n");
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

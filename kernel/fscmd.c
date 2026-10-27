#include "kernel.h"

// D6-3: perintah berkas lewat jalur berprivilege (UDP nonce / shell TCP admin;
// tidak ada di daftar putih read-only). Hanya root directory, nama 8.3.
//   ls                   daftar root + status volume
//   baca NAMA [offset]   isi file (maks FSCMD_READ_MAX byte per balasan)
//   tulis NAMA [teks]    buat/timpa, isi = "teks\n" (tanpa teks: file kosong)
//   tambah NAMA teks     tambah satu baris "teks\n" (buat bila belum ada)
//   hapus NAMA           hapus file biasa (D7)
//   ganti LAMA BARU      ganti nama; BARU tidak boleh sudah ada (D7)
// Teks hanya 0x20..0x7e. Nama yang dilindungi (kunci, program boot) ditolak
// untuk semua perintah; CONFIG.CFG/.TMP (D7, diubah lewat `set`) hanya boleh
// dibaca.

#define FSCMD_READ_MAX 1024
#define FSCMD_LINE_MAX 200

static const char *const g_fs_protected[] = {
    "KEY     TXT", "KEYRO   TXT", "PROG    BIN",
    "TLSKEY  DER", "TLSCERT DER",   // D9
};

static const char *const g_fs_wprotected[] = {
    "CONFIG  CFG", "CONFIG  TMP",
    "FILTER  CFG", "FILTER  TMP",   // P4: hanya lewat perintah filter
    "LOG     BIN",   // R4: dipetakan logdisk, ukuran/rantai tidak boleh berubah
};

static uint8_t g_fs_buf[FAT32_WRITE_MAX];

static int fs_word(const uint8_t *c, uint32_t len, const char *w)
{
    uint32_t i = 0;

    while (w[i]) {
        if (i >= len || c[i] != (uint8_t)w[i]) {
            return 0;
        }
        i++;
    }

    return i == len || c[i] == ' ';
}

static int fs_name_ch(uint8_t ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
}

// "nama.ext" -> 11 byte 8.3 (huruf besar, spasi). Return 1 bila sah.
static int fs_name83(const uint8_t *s, uint32_t n, char out[11])
{
    uint32_t i = 0, b = 0, e = 0;

    for (int k = 0; k < 11; k++) {
        out[k] = ' ';
    }

    while (i < n && s[i] != '.') {
        if (!fs_name_ch(s[i]) || b >= 8) {
            return 0;
        }
        out[b++] = (char)(s[i] >= 'a' && s[i] <= 'z' ? s[i] - 32 : s[i]);
        i++;
    }

    if (b == 0) {
        return 0;
    }

    if (i < n) {
        i++;   // '.'
        if (i == n) {
            return 0;
        }
        while (i < n) {
            if (!fs_name_ch(s[i]) || e >= 3) {
                return 0;
            }
            out[8 + e++] = (char)(s[i] >= 'a' && s[i] <= 'z' ? s[i] - 32 : s[i]);
            i++;
        }
    }

    return 1;
}

static int fs_in_list(const char *n83, const char *const *list, uint32_t count)
{
    for (uint32_t p = 0; p < count; p++) {
        int same = 1;

        for (int k = 0; k < 11; k++) {
            if (n83[k] != list[p][k]) {
                same = 0;
                break;
            }
        }

        if (same) {
            return 1;
        }
    }

    return 0;
}

// write = 1: perintah yang mengubah file (juga menolak CONFIG.CFG/.TMP).
static int fs_protected(const char *n83, int write)
{
    return fs_in_list(n83, g_fs_protected,
                      sizeof(g_fs_protected) / sizeof(g_fs_protected[0])) ||
           (write && fs_in_list(n83, g_fs_wprotected,
                                sizeof(g_fs_wprotected) / sizeof(g_fs_wprotected[0])));
}

// 11 byte 8.3 -> "NAMA.EXT"; byte tak tercetak jadi '?'.
static void fs_put_name(const uint8_t *n83)
{
    for (int k = 0; k < 8 && n83[k] != ' '; k++) {
        cmd_putc(n83[k] >= 0x21 && n83[k] <= 0x7e ? (char)n83[k] : '?');
    }

    if (n83[8] != ' ') {
        cmd_putc('.');
        for (int k = 8; k < 11 && n83[k] != ' '; k++) {
            cmd_putc(n83[k] >= 0x21 && n83[k] <= 0x7e ? (char)n83[k] : '?');
        }
    }
}

static void fs_put_dec(uint64_t v)
{
    char t[24];
    ksnprintf(t, sizeof(t), "%lu", (unsigned long)v);
    cmd_puts(t);
}

const char *fscmd_strerror(int rc)
{
    const char *m;

    switch (rc) {
    case FAT32_ERR_NOVOL:   m = "tidak ada volume FAT32"; break;
    case FAT32_ERR_RO:      m = "volume baca saja"; break;
    case FAT32_ERR_IO:      m = "error disk"; break;
    case FAT32_ERR_CORRUPT: m = "struktur disk rusak"; break;
    case FAT32_ERR_FULL:    m = "disk penuh"; break;
    case FAT32_ERR_DIRFULL: m = "direktori root penuh"; break;
    case FAT32_ERR_TOOBIG:  m = "file melebihi 4096 byte"; break;
    case FAT32_ERR_NOTFILE: m = "bukan file biasa"; break;
    case FAT32_ERR_NOENT:   m = "file tidak ada"; break;
    case FAT32_ERR_UNSUP:   m = "root lebih dari 1 cluster (tidak didukung)"; break;
    case FAT32_ERR_EXIST:   m = "nama tujuan sudah ada"; break;
    case FAT32_ERR_LFN:     m = "file bernama panjang (LFN) tidak didukung"; break;
    default:                m = "error"; break;
    }

    return m;
}

static void fs_err(int rc)
{
    cmd_puts("ERR: fs: ");
    cmd_puts(fscmd_strerror(rc));
    cmd_putc('\n');
}

static void fs_ls(void)
{
    const uint8_t *dir;
    uint32_t n;
    int rc = fat32_root_read(&dir, &n);

    if (rc != FAT32_OK) {
        fs_err(rc);
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *e = dir + i * 32;

        if (e[0] == 0x00) {
            break;
        }

        if (e[0] == 0xE5 || e[0x0B] == 0x0F || (e[0x0B] & 0x08)) {
            continue;   // terhapus, LFN, label volume
        }

        fs_put_name(e);

        if (e[0x0B] & 0x10) {
            cmd_puts("/\n");
        } else {
            cmd_putc(' ');
            fs_put_dec((uint32_t)e[0x1C] | ((uint32_t)e[0x1D] << 8) |
                       ((uint32_t)e[0x1E] << 16) | ((uint32_t)e[0x1F] << 24));
            cmd_putc('\n');
        }
    }

    uint32_t fc = fat32_free_hint();

    cmd_puts("fs: mode=");
    cmd_puts(fat32_writable() ? "tulis" : "baca-saja");
    cmd_puts(" bebas_cluster=");
    if (fc == 0xFFFFFFFFu) {
        cmd_putc('?');
    } else {
        fs_put_dec(fc);
    }
    cmd_puts(" tulis_ok=");
    fs_put_dec(g_fat_wr_ok);
    cmd_puts(" tulis_gagal=");
    fs_put_dec(g_fat_wr_fail);
    cmd_putc('\n');
}

static void fs_baca(const char *n83, const uint8_t *arg, uint32_t arg_len)
{
    uint32_t off = 0;

    for (uint32_t i = 0; i < arg_len; i++) {
        if (arg[i] < '0' || arg[i] > '9' || off > FAT32_WRITE_MAX) {
            cmd_puts("ERR: fs: offset bukan angka 0..4096\n");
            return;
        }
        off = off * 10 + (arg[i] - '0');
    }

    uint32_t size = 0;
    int rc = fat32_read_name(n83, g_fs_buf, sizeof(g_fs_buf), &size);

    if (rc != FAT32_OK) {
        fs_err(rc);
        return;
    }

    if (off > size) {
        off = size;
    }

    uint32_t end = size - off > FSCMD_READ_MAX ? off + FSCMD_READ_MAX : size;

    cmd_puts("isi ");
    fs_put_name((const uint8_t *)n83);
    cmd_puts(" ukuran=");
    fs_put_dec(size);
    cmd_puts(":\n");

    for (uint32_t i = off; i < end; i++) {
        uint8_t ch = g_fs_buf[i];
        cmd_putc(ch == '\n' || (ch >= 0x20 && ch <= 0x7e) ? (char)ch : '?');
    }

    if (end > off && g_fs_buf[end - 1] != '\n') {
        cmd_putc('\n');
    }

    if (end < size) {
        cmd_puts("(terpotong; lanjut: baca ");
        fs_put_name((const uint8_t *)n83);
        cmd_putc(' ');
        fs_put_dec(end);
        cmd_puts(")\n");
    }
}

static void fs_tulis(const char *n83, const uint8_t *text, uint32_t text_len, int append)
{
    uint8_t data[FSCMD_LINE_MAX + 1];
    uint32_t n = 0;

    if (append || text_len > 0) {
        for (uint32_t i = 0; i < text_len; i++) {
            data[n++] = text[i];
        }
        data[n++] = '\n';
    }

    uint32_t size = 0;
    int rc = fat32_write_name(n83, data, n, append, &size);

    if (rc != FAT32_OK) {
        fs_err(rc);
        return;
    }

    cmd_puts("OK ");
    fs_put_name((const uint8_t *)n83);
    cmd_puts(" ukuran=");
    fs_put_dec(size);
    cmd_putc('\n');
}

// D7: hapus NAMA / ganti LAMA BARU (n83 sudah sah dan tidak dilindungi).
static void fs_hapus_ganti(const char *n83, const uint8_t *arg, uint32_t arg_len, int ganti)
{
    char b83[11];
    int rc;

    if (!ganti) {
        if (arg_len != 0) {
            cmd_puts("ERR: fs: format: hapus NAMA\n");
            return;
        }
        rc = fat32_delete_name(n83);
    } else {
        if (arg_len == 0) {
            cmd_puts("ERR: fs: format: ganti LAMA BARU\n");
            return;
        }
        if (!fs_name83(arg, arg_len, b83)) {
            cmd_puts("ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
            return;
        }
        if (fs_protected(b83, 1)) {
            cmd_puts("ERR: fs: nama dilindungi\n");
            return;
        }
        rc = fat32_rename_name(n83, b83);
    }

    if (rc != FAT32_OK) {
        fs_err(rc);
        return;
    }

    cmd_puts(ganti ? "OK ganti " : "OK hapus ");
    fs_put_name((const uint8_t *)n83);
    if (ganti) {
        cmd_puts(" -> ");
        fs_put_name((const uint8_t *)b83);
    }
    cmd_putc('\n');
}

int fscmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    uint8_t c[FSCMD_LINE_MAX];
    int op;

    if (len > sizeof(c)) {
        len = sizeof(c);   // jalur pemanggil sudah membatasi (UDP 200, TCP 64)
    }

    for (uint32_t i = 0; i < len; i++) {
        c[i] = cmd[i];
    }

    if (fs_word(c, len, "ls")) {
        g_cmd_len = 0;
        if (len != 2) {
            cmd_puts("ERR: fs: format: ls\n");
            return 1;
        }
        fs_ls();
        return 1;
    } else if (fs_word(c, len, "baca")) {
        op = 0;
    } else if (fs_word(c, len, "tulis")) {
        op = 1;
    } else if (fs_word(c, len, "tambah")) {
        op = 2;
    } else if (fs_word(c, len, "hapus")) {
        op = 3;
    } else if (fs_word(c, len, "ganti")) {
        op = 4;
    } else {
        return 0;
    }

    g_cmd_len = 0;

    uint32_t p = op == 0 ? 4 : op == 2 ? 6 : 5;

    if (p >= len) {
        cmd_puts(op >= 3 ? "ERR: fs: format: hapus NAMA | ganti LAMA BARU\n"
                         : "ERR: fs: format: baca NAMA [offset] | tulis NAMA [teks] | "
                           "tambah NAMA teks\n");
        return 1;
    }

    p++;   // spasi

    uint32_t ns = p;

    while (p < len && c[p] != ' ') {
        p++;
    }

    char n83[11];

    if (!fs_name83(c + ns, p - ns, n83)) {
        cmd_puts("ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
        return 1;
    }

    if (fs_protected(n83, op != 0)) {
        cmd_puts("ERR: fs: nama dilindungi\n");
        return 1;
    }

    const uint8_t *arg = c + p;
    uint32_t arg_len = 0;

    if (p < len) {
        arg = c + p + 1;   // lewati satu spasi pemisah
        arg_len = len - p - 1;

        if (arg_len == 0) {
            cmd_puts("ERR: fs: spasi di akhir perintah\n");
            return 1;
        }
    }

    for (uint32_t i = 0; i < arg_len; i++) {
        if (arg[i] < 0x20 || arg[i] > 0x7e) {
            cmd_puts("ERR: fs: teks hanya karakter 0x20..0x7e\n");
            return 1;
        }
    }

    if (op >= 3) {
        fs_hapus_ganti(n83, arg, arg_len, op == 4);
    } else if (op == 0) {
        fs_baca(n83, arg, arg_len);
    } else if (op == 2 && arg_len == 0) {
        cmd_puts("ERR: fs: format: tambah NAMA teks\n");
    } else {
        fs_tulis(n83, arg, arg_len, op == 2);
    }

    return 1;
}

// D6: uji FAT32 baca/tulis (fat32.c + fscmd.c di-#include) di atas image
// sungguhan dari mkfs.vfat (dosfstools) + mtools, di-mmap. ahci_read/write/
// flush di-stub ke image itu. Hasil akhir tiap skenario diperiksa fsck.fat -n
// (termasuk jumlah cluster bebas FSInfo) dan mtype. Simulasi crash: tulisan
// ke-k gagal (dan semua sesudahnya), lalu image diperiksa: file = isi lama
// atau isi baru, rantai sah, tanpa cluster dipakai dua file; kemudian
// tulisan di-undo (log sektor asli) dan k berikutnya dicoba.

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "test.h"
#include "../../kernel/fat32.c"
#include "../../kernel/fscmd.c"

// ---- stub kernel ----
uint64_t hhdm_offset = 0;
int g_ahci_ata_port_count = 1;

uint64_t pmm_alloc(void)
{
    return (uint64_t)(uintptr_t)aligned_alloc(4096, 4096);
}

void pmm_free(uint64_t p)
{
    free((void *)(uintptr_t)p);
}

static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len = 0;

void cmd_putc(char c)
{
    if (g_cmd_len < CMD_OUT_MAX) {
        g_out[g_cmd_len++] = c;
    }
}

void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
}

// ---- disk di memori ----
static uint8_t *g_img;
static uint64_t g_img_sectors;
static char g_img_path[256];
static uint8_t g_dma[4096];
static int g_fail_at;       // 0 = tidak ada; k = tulisan ke-k dan sesudahnya gagal
static int g_writes;
static int g_reads_fail;    // 1 = semua baca gagal

#define UNDO_MAX 4096
static struct {
    uint64_t lba;
    uint8_t old[512];
} g_undo[UNDO_MAX];
static int g_undo_n;
static int g_undo_on;

int ahci_read(uint32_t port_index, uint64_t lba, uint32_t count, uint8_t **out_buf)
{
    if (port_index != 0 || count == 0 || count > 8 || lba + count > g_img_sectors ||
        g_reads_fail) {
        return -1;
    }

    memcpy(g_dma, g_img + lba * 512, count * 512);
    *out_buf = g_dma;
    return 0;
}

int ahci_write(uint32_t port_index, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    if (port_index != 0 || count == 0 || count > 8 || lba + count > g_img_sectors) {
        return -1;
    }

    g_writes++;

    if (g_fail_at && g_writes >= g_fail_at) {
        return -5;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (g_undo_on) {
            if (g_undo_n >= UNDO_MAX) {
                abort();
            }
            g_undo[g_undo_n].lba = lba + i;
            memcpy(g_undo[g_undo_n].old, g_img + (lba + i) * 512, 512);
            g_undo_n++;
        }
    }

    memcpy(g_img + lba * 512, buf, count * 512);
    return 0;
}

int ahci_flush(uint32_t port_index)
{
    (void)port_index;
    return g_fail_at && g_writes >= g_fail_at ? -5 : 0;
}

static void undo_all(void)
{
    while (g_undo_n > 0) {
        g_undo_n--;
        memcpy(g_img + g_undo[g_undo_n].lba * 512, g_undo[g_undo_n].old, 512);
    }
}

static int sh(const char *fmt, const char *a, const char *b)
{
    char c[1024];
    snprintf(c, sizeof(c), fmt, a, b);
    return system(c);
}

// Buat image baru: ukuran KB, sektor per cluster, lalu isi dasar lewat mtools.
static void img_open(const char *name, int kb, int spc)
{
    snprintf(g_img_path, sizeof(g_img_path), "build/host/%s.img", name);
    unlink(g_img_path);

    char c[512];
    snprintf(c, sizeof(c), "mkfs.vfat -F 32 -s %d -C %s %d >/dev/null", spc, g_img_path, kb);
    if (system(c) != 0) {
        fprintf(stderr, "mkfs.vfat gagal\n");
        exit(2);
    }

    sh("printf 'halo dari disk\\n' > build/host/hello.txt && "
       "mcopy -i %s build/host/hello.txt ::HELLO.TXT && "
       "mcopy -i %s build/host/hello.txt ::KEY.TXT", g_img_path, g_img_path);
    sh("head -c 5000 /dev/zero | tr '\\0' 'b' > build/host/big.txt && "
       "mcopy -i %s build/host/big.txt ::BIG.TXT && mmd -i %s ::TEST",
       g_img_path, g_img_path);

    int fd = open(g_img_path, O_RDWR);
    off_t sz = lseek(fd, 0, SEEK_END);
    g_img = mmap(0, (size_t)sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_img == MAP_FAILED) {
        exit(2);
    }
    g_img_sectors = (uint64_t)sz / 512;
}

static void img_close(void)
{
    munmap(g_img, g_img_sectors * 512);
    g_img = 0;
}

static int img_fsck(void)
{
    msync(g_img, g_img_sectors * 512, MS_SYNC);
    return sh("fsck.fat -n %s >/dev/null 2>&1%s", g_img_path, "");
}

// Isi file dari sisi mtools sama dengan want?
static int img_mtype_eq(const char *name, const char *want)
{
    msync(g_img, g_img_sectors * 512, MS_SYNC);

    char c[512];
    snprintf(c, sizeof(c), "mtype -i %s ::%s 2>/dev/null", g_img_path, name);
    FILE *p = popen(c, "r");
    char got[8192];
    size_t n = fread(got, 1, sizeof(got) - 1, p);
    pclose(p);
    got[n] = 0;
    return strcmp(got, want) == 0;
}

static void probe(void)
{
    memset(&g_fat32_volume, 0, sizeof(g_fat32_volume));
    serial_capture_reset();
    ahci_fat32_probe_and_log();
}

static const char *run(const char *c)
{
    g_cmd_len = 0;
    if (!fscmd_execute((const volatile uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak dikenali)";
    }
    g_out[g_cmd_len] = 0;
    return g_out;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// Pemeriksa independen (tidak memakai fat32.c): semua file di cluster root
// pertama punya rantai sah sepanjang ukurannya di FAT1, tanpa cluster ganda.
static int img_consistent(void)
{
    const uint8_t *b = g_img;
    uint32_t spc = b[13], rsvd = b[14] | b[15] << 8, nf = b[16], fsz = rd32(b + 36);
    uint32_t root = rd32(b + 44);
    uint64_t data = rsvd + (uint64_t)nf * fsz;
    uint32_t maxc = (uint32_t)((rd32(b + 32) - data) / spc + 1);
    const uint8_t *fat = g_img + (uint64_t)rsvd * 512;
    const uint8_t *dir = g_img + (data + (uint64_t)(root - 2) * spc) * 512;
    static uint8_t used[1 << 20];

    memset(used, 0, sizeof(used));
    for (uint32_t i = 0; i < spc * 16; i++) {
        const uint8_t *e = dir + i * 32;
        if (e[0] == 0) {
            break;
        }
        if (e[0] == 0xE5 || e[11] == 0x0F || (e[11] & 0x18)) {
            continue;
        }
        uint32_t c = (uint32_t)(e[20] | e[21] << 8) << 16 | e[26] | e[27] << 8;
        uint32_t size = rd32(e + 28);
        uint32_t need = (size + spc * 512 - 1) / (spc * 512);
        for (uint32_t k = 0; k < need; k++) {
            if (c < 2 || c > maxc || c >= sizeof(used) || used[c]) {
                return 0;
            }
            used[c] = 1;
            uint32_t nx = rd32(fat + c * 4) & 0x0FFFFFFF;
            // ujung: EOC atau sambungan sah (rantai lebih panjang = lost cluster)
            if (nx < 0x0FFFFFF8 && (nx < 2 || nx > maxc)) {
                return 0;
            }
            c = nx;
        }
        if (need == 0 && c != 0) {
            return 0;
        }
    }
    return 1;
}

static int read_eq(const char *n83, const char *want)
{
    static uint8_t buf[FAT32_WRITE_MAX];
    uint32_t size = 0;
    int rc = fat32_read_name(n83, buf, sizeof(buf), &size);
    return rc == FAT32_OK && size == strlen(want) && memcmp(buf, want, size) == 0;
}

static int read_rc(const char *n83)
{
    static uint8_t buf[FAT32_WRITE_MAX];
    uint32_t size = 0;
    return fat32_read_name(n83, buf, sizeof(buf), &size);
}

static int wr(const char *n83, const char *s, int append)
{
    uint32_t size = 0;
    return fat32_write_name(n83, (const uint8_t *)s, (uint32_t)strlen(s), append, &size);
}

static void test_basic(int spc)
{
    char name[32];
    snprintf(name, sizeof(name), "fat32_spc%d", spc);
    img_open(name, spc == 1 ? 65536 : 300000, spc);
    probe();
    CHECK(g_fat32_volume.valid && g_fat32_volume.writable);
    CHECK(strstr(g_serial_cap, "mode=tulis") != 0);
    CHECK(read_eq("HELLO   TXT", "halo dari disk\n"));
    CHECK(read_rc("NADA    TXT") == FAT32_ERR_NOENT);
    CHECK(read_rc("BIG     TXT") == FAT32_ERR_TOOBIG);
    CHECK(read_rc("TEST       ") == FAT32_ERR_NOTFILE);

    // buat, tambah, timpa
    CHECK_STR(run("tulis catatan.txt baris satu"), "OK CATATAN.TXT ukuran=11\n");
    CHECK_STR(run("tambah CATATAN.TXT baris dua"), "OK CATATAN.TXT ukuran=21\n");
    CHECK(img_mtype_eq("CATATAN.TXT", "baris satu\nbaris dua\n"));
    CHECK_STR(run("baca CATATAN.TXT"), "isi CATATAN.TXT ukuran=21:\nbaris satu\nbaris dua\n");
    CHECK(img_fsck() == 0);

    // tambah sampai tepat 4096 byte (melewati banyak batas cluster bila spc=1)
    static char want[FAT32_WRITE_MAX + 1];
    char line[64];
    size_t wl = 0;
    CHECK(run("tulis PANJANG.TXT")[0] == 'O');
    int ok = 1;
    for (int i = 0; wl + 32 <= FAT32_WRITE_MAX; i++) {
        snprintf(line, sizeof(line), "tambah PANJANG.TXT baris-%04d-xxxxxxxxxxxxxxxxxxxx", i);
        const char *r = run(line);
        ok &= r[0] == 'O';
        wl += (size_t)snprintf(want + wl, sizeof(want) - wl, "baris-%04d-xxxxxxxxxxxxxxxxxxxx\n", i);
    }
    CHECK(ok && wl == FAT32_WRITE_MAX);
    CHECK(img_mtype_eq("PANJANG.TXT", want));
    CHECK(read_eq("PANJANG TXT", want));
    CHECK_STR(run("tambah PANJANG.TXT x"), "ERR: fs: file melebihi 4096 byte\n");
    CHECK(img_mtype_eq("PANJANG.TXT", want));
    const char *r = run("baca PANJANG.TXT");
    CHECK(strstr(r, "(terpotong; lanjut: baca PANJANG.TXT 1024)\n") != 0);
    r = run("baca PANJANG.TXT 4064");
    CHECK(strstr(r, "baris-0127-xxxxxxxxxxxxxxxxxxxx\n") != 0 && strstr(r, "terpotong") == 0);
    CHECK(img_fsck() == 0);

    // timpa file banyak cluster dengan isi pendek -> rantai lama dibebaskan
    CHECK_STR(run("tulis PANJANG.TXT pendek"), "OK PANJANG.TXT ukuran=7\n");
    CHECK(img_mtype_eq("PANJANG.TXT", "pendek\n"));
    CHECK_STR(run("tulis PANJANG.TXT"), "OK PANJANG.TXT ukuran=0\n");
    CHECK(img_mtype_eq("PANJANG.TXT", ""));
    CHECK_STR(run("tambah PANJANG.TXT lagi"), "OK PANJANG.TXT ukuran=5\n");
    CHECK(img_fsck() == 0);

    // aturan nama dan perlindungan
    CHECK_STR(run("tulis KEY.TXT x"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("baca key.txt"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("tulis keyro.txt x"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("tambah PROG.BIN x"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("tulis A.B.C x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis NAMAPANJANG.TXT x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis .TXT x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis A.TEXT x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis A. x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis A/B x"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("tulis A.TXT "), "ERR: fs: spasi di akhir perintah\n");
    CHECK_STR(run("tulis A.TXT a\tb"), "ERR: fs: teks hanya karakter 0x20..0x7e\n");
    CHECK_STR(run("tambah A.TXT"), "ERR: fs: format: tambah NAMA teks\n");
    CHECK_STR(run("tulis"), "ERR: fs: format: baca NAMA [offset] | tulis NAMA [teks] | tambah NAMA teks\n");
    CHECK_STR(run("tulis TEST x"), "ERR: fs: bukan file biasa\n");
    CHECK_STR(run("tulis BIG.TXT x"), "ERR: fs: file melebihi 4096 byte\n");
    CHECK_STR(run("baca HELLO.TXT x"), "ERR: fs: offset bukan angka 0..4096\n");
    CHECK_STR(run("ls x"), "ERR: fs: format: ls\n");
    CHECK_STR(run("tulisan"), "(tidak dikenali)");
    CHECK_STR(run("lsx"), "(tidak dikenali)");
    CHECK(img_mtype_eq("KEY.TXT", "halo dari disk\n"));

    r = run("ls");
    CHECK(strstr(r, "HELLO.TXT 15\n") && strstr(r, "TEST/\n") && strstr(r, "CATATAN.TXT 21\n"));
    CHECK(strstr(r, "fs: mode=tulis bebas_cluster=") != 0);

    // spc=8: entri dir melewati sektor pertama (16 entri per sektor)
    if (spc == 8) {
        ok = 1;
        for (int i = 0; i < 20; i++) {
            snprintf(line, sizeof(line), "tulis F%02d.TXT isi %d", i, i);
            ok &= run(line)[0] == 'O';
        }
        CHECK(ok);
        CHECK(img_mtype_eq("F19.TXT", "isi 19\n"));
        CHECK(img_fsck() == 0);
    }

    CHECK(img_consistent());
    img_close();
}

// Root spc=1 = 16 entri: penuh -> DIRFULL; root yang sudah 2 cluster -> UNSUP.
static void test_dir_limits(void)
{
    img_open("fat32_dir", 65536, 1);
    probe();
    char line[64];
    int ok_n = 0;
    const char *r = "";
    for (int i = 0; i < 20; i++) {
        snprintf(line, sizeof(line), "tulis D%02d.TXT x", i);
        r = run(line);
        if (r[0] == 'O') {
            ok_n++;
        } else {
            break;
        }
    }
    // 16 slot - (HELLO, KEY, BIG, TEST, label volume mkfs? tidak ada) = 12
    CHECK(ok_n == 12);
    CHECK_STR(r, "ERR: fs: direktori root penuh\n");
    CHECK(img_fsck() == 0);
    img_close();

    img_open("fat32_dir2", 65536, 1);
    sh("for i in $(seq 1 20); do mcopy -i %s build/host/hello.txt ::R$i.TXT; done%s",
       g_img_path, "");
    probe();
    CHECK_STR(run("tulis BARU.TXT x"), "ERR: fs: root lebih dari 1 cluster (tidak didukung)\n");
    CHECK_STR(run("ls"), "ERR: fs: root lebih dari 1 cluster (tidak didukung)\n");
    CHECK(img_fsck() == 0);
    img_close();
}

// Disk penuh: semua cluster bebas kecuali 2 ditandai bad (0x0FFFFFF7).
static void test_full(void)
{
    img_open("fat32_full", 65536, 1);
    probe();
    uint32_t keep = 0;
    for (uint32_t f = 0; f < g_fat32_volume.num_fats; f++) {
        uint8_t *fat = g_img + (g_fat32_volume.fat_start_lba +
                                (uint64_t)f * g_fat32_volume.fat_sz32) * 512;
        keep = 0;
        for (uint32_t c = 2; c <= g_fat32_volume.max_cluster; c++) {
            if (rd32(fat + c * 4) == 0 && keep++ >= 2) {
                fat32_put32(fat + c * 4, 0x0FFFFFF7);
            }
        }
    }
    uint8_t *fsi = g_img + g_fat32_volume.fsinfo_sector * 512;
    fat32_put32(fsi + 488, 2);
    CHECK(img_fsck() == 0);

    static char big[1200];
    memset(big, 'z', 1100);   // 1100 byte = 3 cluster
    big[1100] = 0;
    uint32_t size;
    CHECK(fat32_write_name("TIGA    TXT", (const uint8_t *)big, 1100, 0, &size) == FAT32_ERR_FULL);
    CHECK(read_rc("TIGA    TXT") == FAT32_ERR_NOENT);
    CHECK(fat32_write_name("DUA     TXT", (const uint8_t *)big, 1000, 0, &size) == FAT32_OK);
    CHECK_STR(run("tulis SATU.TXT x"), "ERR: fs: disk penuh\n");
    CHECK(strstr(run("ls"), "bebas_cluster=0 ") != 0);
    // timpa DUA (2 cluster) dengan 1 baris: perlu 1 cluster baru dulu -> tetap penuh
    CHECK_STR(run("tulis DUA.TXT y"), "ERR: fs: disk penuh\n");
    CHECK(fat32_writable());
    CHECK(img_fsck() == 0);
    CHECK(img_consistent());
    img_close();
}

// Satu skenario crash: op dijalankan dengan tulisan ke-k gagal, untuk k = 1..
// sampai op berhasil. Setelah tiap crash: file = old atau new, image konsisten.
static void crash_scenario(const char *n83, const char *text, int append,
                           const char *old, const char *neu, int *points)
{
    int done = 0;
    int bad = 0;

    for (int k = 1; k < 200 && !done; k++) {
        probe();
        g_writes = 0;
        g_fail_at = k;
        g_undo_on = 1;
        g_undo_n = 0;
        uint32_t size;
        int rc = fat32_write_name(n83, (const uint8_t *)text, (uint32_t)strlen(text),
                                  append, &size);
        g_fail_at = 0;
        g_undo_on = 0;

        // Crash di fase 6 (FSInfo): file sudah utuh, hasil OK, volume baca saja.
        int fsi_crash = rc == FAT32_OK && !fat32_writable();
        if (rc == FAT32_OK && !fsi_crash) {
            done = 1;
        } else if (!fsi_crash && (rc != FAT32_ERR_IO || fat32_writable())) {
            bad++;
        }

        probe();   // "boot ulang" setelah crash
        int is_old = old ? read_eq(n83, old) : read_rc(n83) == FAT32_ERR_NOENT;
        int is_new = read_eq(n83, neu);
        if (!(done || fsi_crash ? is_new : (is_old || is_new)) || !img_consistent()) {
            bad++;
            fprintf(stderr, "crash %.11s append=%d k=%d rc=%d old=%d new=%d baca=%d\n", n83, append, k, rc, is_old, is_new, read_rc(n83));
        }
        (*points)++;
        undo_all();
    }

    CHECK(done && bad == 0);
}

static void test_crash(void)
{
    img_open("fat32_crash", 65536, 1);
    probe();

    // isi lama 2 cluster (600 byte)
    static char old[601], neu[1300], app[1300];
    memset(old, 'o', 599);
    old[599] = '\n';
    CHECK(wr("CRASH   TXT", old, 0) == FAT32_OK);
    CHECK(img_fsck() == 0);

    memset(neu, 'n', 1199);
    neu[1199] = '\n';
    snprintf(app, sizeof(app), "%s%s", old, "ekor\n");

    int points = 0;
    crash_scenario("CRASH   TXT", neu, 0, old, neu, &points);      // timpa 2 -> 3 cluster
    crash_scenario("CRASH   TXT", "ekor\n", 1, old, app, &points); // tambah di ekor cluster
    static char app2[2000];
    snprintf(app2, sizeof(app2), "%s%s", old, neu);
    crash_scenario("CRASH   TXT", neu, 1, old, app2, &points);     // tambah 3 cluster baru
    crash_scenario("BARU    TXT", "isi baru\n", 0, 0, "isi baru\n", &points); // buat
    printf("fat32 crash: %d titik crash diperiksa\n", points);
    CHECK(points >= 30);

    // setelah semua undo: image kembali seperti sebelum skenario
    probe();
    CHECK(read_eq("CRASH   TXT", old));
    CHECK(img_fsck() == 0);

    // gagal I/O nyata -> baca saja sampai probe berikutnya
    g_writes = 0;
    g_fail_at = 1;
    CHECK(wr("CRASH   TXT", "x\n", 0) == FAT32_ERR_IO);
    g_fail_at = 0;
    CHECK(!fat32_writable());
    CHECK_STR(run("tulis CRASH.TXT y"), "ERR: fs: volume baca saja\n");
    CHECK(strstr(run("ls"), "fs: mode=baca-saja") != 0);
    g_reads_fail = 1;
    CHECK_STR(run("baca CRASH.TXT"), "ERR: fs: error disk\n");
    g_reads_fail = 0;
    img_close();
}

// D7: hapus, ganti nama, perlindungan, LFN.
static void test_delete_rename(void)
{
    img_open("fat32_del", 65536, 1);
    sh("printf x > build/host/x.txt && mcopy -i %s build/host/x.txt ::nama_panjang_sekali.txt%s",
       g_img_path, "");
    probe();
    uint32_t fc0 = fat32_free_hint();

    CHECK_STR(run("tulis DUA.TXT dua"), "OK DUA.TXT ukuran=4\n");
    CHECK_STR(run("hapus dua.txt"), "OK hapus DUA.TXT\n");
    CHECK(read_rc("DUA     TXT") == FAT32_ERR_NOENT);
    CHECK(fat32_free_hint() == fc0);
    CHECK_STR(run("hapus HELLO.TXT"), "OK hapus HELLO.TXT\n");
    CHECK(fat32_free_hint() == fc0 + 1);
    CHECK(img_fsck() == 0);
    CHECK(strstr(run("ls"), "HELLO.TXT") == 0);

    // file kosong (tanpa cluster)
    CHECK_STR(run("tulis KOSONG.TXT"), "OK KOSONG.TXT ukuran=0\n");
    CHECK_STR(run("hapus KOSONG.TXT"), "OK hapus KOSONG.TXT\n");

    CHECK_STR(run("hapus NADA.TXT"), "ERR: fs: file tidak ada\n");
    CHECK_STR(run("hapus TEST"), "ERR: fs: bukan file biasa\n");
    CHECK_STR(run("hapus KEY.TXT"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("hapus CONFIG.CFG"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("hapus config.tmp"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("hapus BIG.TXT"), "ERR: fs: file melebihi 4096 byte\n");
    CHECK_STR(run("hapus A.TXT x"), "ERR: fs: format: hapus NAMA\n");
    CHECK_STR(run("hapus"), "ERR: fs: format: hapus NAMA | ganti LAMA BARU\n");
    CHECK_STR(run("hapusx"), "(tidak dikenali)");

    CHECK_STR(run("tulis SATU.TXT isi satu"), "OK SATU.TXT ukuran=9\n");
    CHECK_STR(run("tulis LAIN.TXT"), "OK LAIN.TXT ukuran=0\n");
    CHECK_STR(run("ganti satu.txt baru.dat"), "OK ganti SATU.TXT -> BARU.DAT\n");
    CHECK(read_rc("SATU    TXT") == FAT32_ERR_NOENT);
    CHECK(img_mtype_eq("BARU.DAT", "isi satu\n"));
    CHECK_STR(run("ganti BARU.DAT LAIN.TXT"), "ERR: fs: nama tujuan sudah ada\n");
    CHECK_STR(run("ganti BARU.DAT BARU.DAT"), "ERR: fs: nama tujuan sudah ada\n");
    CHECK_STR(run("ganti NADA.TXT X.TXT"), "ERR: fs: file tidak ada\n");
    CHECK_STR(run("ganti TEST T2"), "ERR: fs: bukan file biasa\n");
    CHECK_STR(run("ganti BARU.DAT KEY.TXT"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("ganti BARU.DAT CONFIG.CFG"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("ganti KEY.TXT K.TXT"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("ganti BARU.DAT A.B.C"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK_STR(run("ganti BARU.DAT"), "ERR: fs: format: ganti LAMA BARU\n");
    CHECK_STR(run("ganti BARU.DAT X Y"), "ERR: fs: nama bukan 8.3 (A-Z 0-9 _ -)\n");
    CHECK(img_fsck() == 0);

    // nama panjang dari mtools (LFN) -> ditolak, tidak diubah
    CHECK(fat32_delete_name("NAMA_P~1TXT") == FAT32_ERR_LFN);
    CHECK(fat32_rename_name("NAMA_P~1TXT", "X       TXT") == FAT32_ERR_LFN);
    CHECK(img_mtype_eq("nama_panjang_sekali.txt", "x"));

    // CONFIG.CFG boleh dibaca, tidak boleh ditulis lewat fscmd
    CHECK(fat32_replace_name("CONFIG  CFG", "CONFIG  TMP", (const uint8_t *)"a=1\n", 4) ==
          FAT32_OK);
    CHECK_STR(run("baca CONFIG.CFG"), "isi CONFIG.CFG ukuran=4:\na=1\n");
    CHECK_STR(run("tulis CONFIG.CFG x"), "ERR: fs: nama dilindungi\n");
    CHECK_STR(run("tambah CONFIG.TMP x"), "ERR: fs: nama dilindungi\n");

    CHECK(strstr(run("ls"), "fs: mode=tulis") != 0 && fat32_writable());
    CHECK(img_fsck() == 0);
    CHECK(img_consistent());
    img_close();
}

// D7: ganti isi atomik lewat file sementara.
static void test_replace(void)
{
    img_open("fat32_repl", 65536, 1);
    probe();
    static char big[1300];
    memset(big, 'r', 1199);
    big[1199] = '\n';
    uint32_t fc0 = fat32_free_hint();

    // belum ada -> TMP diganti nama
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"v1\n", 3) == FAT32_OK);
    CHECK(read_eq("CFG     TXT", "v1\n") && read_rc("CFG     TMP") == FAT32_ERR_NOENT);
    CHECK(img_fsck() == 0);
    // sudah ada -> isi baru 3 cluster, lalu kembali 1 cluster
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)big, 1200) == FAT32_OK);
    CHECK(read_eq("CFG     TXT", big) && read_rc("CFG     TMP") == FAT32_ERR_NOENT);
    CHECK(fat32_free_hint() == fc0 - 3);
    CHECK(img_fsck() == 0);
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"v3\n", 3) == FAT32_OK);
    CHECK(read_eq("CFG     TXT", "v3\n") && fat32_free_hint() == fc0 - 1);
    // isi kosong
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"", 0) == FAT32_OK);
    CHECK(read_eq("CFG     TXT", "") && fat32_free_hint() == fc0);
    CHECK(img_fsck() == 0);

    // TMP sisa crash (isi lain) dibersihkan dulu
    CHECK(wr("CFG     TMP", big, 0) == FAT32_OK);
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"v4\n", 3) == FAT32_OK);
    CHECK(read_eq("CFG     TXT", "v4\n") && read_rc("CFG     TMP") == FAT32_ERR_NOENT);
    CHECK(fat32_free_hint() == fc0 - 1);
    CHECK(img_fsck() == 0);

    // tujuan bukan file biasa / terlalu besar
    CHECK(fat32_replace_name("TEST       ", "T       TMP", (const uint8_t *)"x", 1) ==
          FAT32_ERR_NOTFILE);
    CHECK(fat32_replace_name("BIG     TXT", "BIG     TMP", (const uint8_t *)"x", 1) ==
          FAT32_ERR_TOOBIG);
    CHECK(read_rc("BIG     TMP") == FAT32_OK);   // TMP tertinggal; BIG utuh
    CHECK(fat32_delete_name("BIG     TMP") == FAT32_OK);
    CHECK(img_consistent() && img_fsck() == 0);
    img_close();

    // sektor entri tujuan penuh -> DIRFULL, tujuan utuh
    img_open("fat32_repl2", 65536, 1);
    probe();
    char line[64];
    CHECK(wr("CFG     TXT", "lama\n", 0) == FAT32_OK);
    int i;
    for (i = 0; i < 20; i++) {
        snprintf(line, sizeof(line), "tulis P%02d.TXT x", i);
        if (run(line)[0] != 'O') {
            break;
        }
    }
    CHECK(i == 11);   // 16 - HELLO, KEY, BIG, TEST, CFG
    CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"baru\n", 5) ==
          FAT32_ERR_DIRFULL);
    CHECK(read_eq("CFG     TXT", "lama\n") && read_rc("CFG     TMP") == FAT32_ERR_NOENT);
    CHECK(fat32_writable() && img_fsck() == 0);
    img_close();
}

// D7: crash di setiap titik tulis replace / hapus / ganti. Setelah crash:
// file = lama atau baru, image konsisten; replace ulang (pemulihan) berhasil.
static void test_crash_d7(void)
{
    img_open("fat32_crash7", 65536, 1);
    probe();
    static char old[700], neu[1300];
    memset(old, 'o', 599);
    old[599] = '\n';
    memset(neu, 'n', 1199);
    neu[1199] = '\n';
    int points = 0, bad = 0, done;

    for (int pass = 0; pass < 2; pass++) {
        // pass 0: CFG belum ada (rename TMP); pass 1: CFG ada (ganti isi)
        if (pass == 1) {
            CHECK(fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)old,
                                     600) == FAT32_OK);
        }
        done = 0;
        for (int k = 1; k < 200 && !done; k++) {
            probe();
            g_writes = 0;
            g_fail_at = k;
            g_undo_on = 1;
            g_undo_n = 0;
            int rc = fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)neu, 1200);
            g_fail_at = 0;
            int fsi_crash = rc == FAT32_OK && !fat32_writable();
            done = rc == FAT32_OK && !fsi_crash;
            if (rc != FAT32_OK && (rc != FAT32_ERR_IO || fat32_writable())) {
                bad++;
            }
            probe();
            int is_old = pass ? read_eq("CFG     TXT", old) : read_rc("CFG     TXT") == FAT32_ERR_NOENT;
            int is_new = read_eq("CFG     TXT", neu);
            if (!(done || fsi_crash ? is_new : (is_old || is_new)) || !img_consistent()) {
                bad++;
                fprintf(stderr, "crash replace pass=%d k=%d rc=%d old=%d new=%d\n", pass, k, rc,
                        is_old, is_new);
            }
            // pemulihan: replace lagi dari keadaan crash
            rc = fat32_replace_name("CFG     TXT", "CFG     TMP", (const uint8_t *)"pulih\n", 6);
            if (rc != FAT32_OK || !read_eq("CFG     TXT", "pulih\n") ||
                read_rc("CFG     TMP") != FAT32_ERR_NOENT || !img_consistent()) {
                bad++;
                fprintf(stderr, "pulih replace pass=%d k=%d rc=%d\n", pass, k, rc);
            }
            g_undo_on = 0;
            points++;
            undo_all();
        }
        CHECK(done);
    }

    // hapus dan ganti nama: file utuh atau tidak ada / nama lama atau baru
    for (int op = 0; op < 2; op++) {
        done = 0;
        for (int k = 1; k < 50 && !done; k++) {
            probe();
            g_writes = 0;
            g_fail_at = k;
            g_undo_on = 1;
            g_undo_n = 0;
            int rc = op == 0 ? fat32_delete_name("CFG     TXT")
                             : fat32_rename_name("CFG     TXT", "LAIN    TXT");
            g_fail_at = 0;
            g_undo_on = 0;
            int fsi_crash = rc == FAT32_OK && !fat32_writable();
            done = rc == FAT32_OK && !fsi_crash;
            probe();
            int a = read_eq("CFG     TXT", old);
            int b = op == 0 ? read_rc("CFG     TXT") == FAT32_ERR_NOENT
                            : read_eq("LAIN    TXT", old) && read_rc("CFG     TXT") == FAT32_ERR_NOENT;
            if (!(done || fsi_crash ? b : (a || b)) || !img_consistent()) {
                bad++;
                fprintf(stderr, "crash op=%d k=%d rc=%d\n", op, k, rc);
            }
            points++;
            undo_all();
        }
        CHECK(done);
    }

    printf("fat32 crash D7: %d titik crash diperiksa\n", points);
    CHECK(bad == 0 && points >= 20);
    probe();
    CHECK(read_eq("CFG     TXT", old) && img_fsck() == 0);
    img_close();
}

// BPB/FSInfo/rantai rusak: tidak pernah crash, kode error / volume ditolak.
static void test_corrupt(void)
{
    img_open("fat32_bad", 65536, 1);
    static uint8_t bs[512];
    memcpy(bs, g_img, 512);

    struct { int off, len; uint32_t val; const char *why; } m[] = {
        {0x0B, 2, 1024, "BytesPerSector bukan 512"},
        {0x0D, 1, 3, "SectorsPerCluster bukan 1/2/4/8"},
        {0x0D, 1, 16, "SectorsPerCluster bukan 1/2/4/8"},
        {0x0E, 2, 0, "ReservedSectorCount nol"},
        {0x10, 1, 0, "NumFATs bukan 1/2"},
        {0x10, 1, 3, "NumFATs bukan 1/2"},
        {0x11, 2, 512, "RootEntryCount/FATSz16 tidak nol (FAT12/16)"},
        {0x16, 2, 9, "RootEntryCount/FATSz16 tidak nol (FAT12/16)"},
        {0x24, 4, 0, "FATSz32 nol"},
        {0x24, 4, 10, "FAT terlalu kecil untuk jumlah cluster"},
        {0x24, 4, 0x7FFFFFFF, "area data di luar ukuran volume"},
        {0x20, 4, 100, "area data di luar ukuran volume"},
        {0x2C, 4, 0, "RootCluster di luar jangkauan"},
        {0x2C, 4, 0x0FFFFFF0, "RootCluster di luar jangkauan"},
    };
    for (size_t i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
        memcpy(g_img, bs, 512);
        for (int b = 0; b < m[i].len; b++) {
            g_img[m[i].off + b] = (uint8_t)(m[i].val >> (8 * b));
        }
        probe();
        if (!(!g_fat32_volume.valid && strstr(g_serial_cap, m[i].why))) {
            fprintf(stderr, "mutasi BPB %zu: %s\n", i, g_serial_cap);
        }
        CHECK(!g_fat32_volume.valid && strstr(g_serial_cap, m[i].why) != 0);
        CHECK_STR(run("tulis A.TXT x"), "ERR: fs: tidak ada volume FAT32\n");
        CHECK_STR(run("ls"), "ERR: fs: tidak ada volume FAT32\n");
    }
    memcpy(g_img, bs, 512);
    g_img[0x1FE] = 0;
    probe();
    CHECK(!g_fat32_volume.valid);
    memcpy(g_img, bs, 512);

    // ExtFlags bit 7 / FSInfo rusak -> baca saja
    g_img[0x28] = 0x80;
    probe();
    CHECK(g_fat32_volume.valid && !fat32_writable() && strstr(g_serial_cap, "ExtFlags"));
    CHECK(read_eq("HELLO   TXT", "halo dari disk\n"));
    CHECK_STR(run("tulis A.TXT x"), "ERR: fs: volume baca saja\n");
    memcpy(g_img, bs, 512);
    uint32_t fsi = g_img[0x30] | g_img[0x31] << 8;
    g_img[fsi * 512 + 2] ^= 0xFF;
    probe();
    CHECK(g_fat32_volume.valid && !fat32_writable() && strstr(g_serial_cap, "FSInfo"));
    g_img[fsi * 512 + 2] ^= 0xFF;
    g_img[0x30] = 0x40;
    g_img[0x31] = 0;
    probe();
    CHECK(g_fat32_volume.valid && !fat32_writable());
    memcpy(g_img, bs, 512);
    probe();
    CHECK(fat32_writable());

    // Rantai rusak: buat file 3 cluster lalu rusak FAT-nya.
    static char t[1300];
    memset(t, 'q', 1199);
    t[1199] = '\n';
    t[1200] = 0;
    CHECK(wr("RANTAI  TXT", t, 0) == FAT32_OK);
    uint32_t first, size;
    CHECK(fat32_find_file("RANTAI  TXT", &first, &size) == 1 && size == 1200);
    uint8_t *fat1 = g_img + g_fat32_volume.fat_start_lba * 512;
    uint32_t c2 = rd32(fat1 + first * 4);
    uint32_t c3 = rd32(fat1 + c2 * 4);

    fat32_put32(fat1 + c2 * 4, first);           // melingkar
    CHECK(read_rc("RANTAI  TXT") == FAT32_ERR_CORRUPT);
    CHECK(wr("RANTAI  TXT", "x\n", 1) == FAT32_ERR_CORRUPT);
    fat32_put32(fat1 + c2 * 4, 0x0FFFFFF0);      // di luar jangkauan
    CHECK(read_rc("RANTAI  TXT") == FAT32_ERR_CORRUPT);
    CHECK(fat32_load_file(first, size) == 0);
    fat32_put32(fat1 + c2 * 4, 0x0FFFFFFF);      // terlalu pendek
    CHECK(read_rc("RANTAI  TXT") == FAT32_ERR_CORRUPT);
    fat32_put32(fat1 + c2 * 4, c3);
    fat32_put32(fat1 + c3 * 4, c3 + 50);         // lebih panjang: sisa diabaikan
    CHECK(read_eq("RANTAI  TXT", t));
    fat32_put32(fat1 + c3 * 4, 0x0FFFFFFF);
    CHECK(read_rc("RANTAI  TXT") == FAT32_OK);
    CHECK(fat32_writable());

    // cluster awal di dir entry di luar jangkauan
    CHECK(fat32_load_file(0x0FFFFFF0, 10) == 0);
    CHECK(fat32_load_file(1, 10) == 0);
    CHECK(img_fsck() == 0);
    img_close();
}

int main(void)
{
    test_basic(1);
    test_basic(8);
    test_dir_limits();
    test_full();
    test_crash();
    test_delete_rename();
    test_replace();
    test_crash_d7();
    test_corrupt();
    return test_done("fat32");
}

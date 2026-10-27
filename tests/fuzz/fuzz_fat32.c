// R7: fuzz fat32.c + fscmd.c dengan disk dari tests/host/test_fat32.c (image
// mkfs.vfat 64 MB, spc 1, dibuat sekali). Input = [n][perintah fscmd n byte]
// lalu isi pengganti tiga jendela sektor image asli, berurutan:
//   W0 sektor 0..31 (BPB, FSInfo, cadangan)   W1 8 sektor awal FAT1
//   W2 8 sektor mulai cluster root (direktori + isi file)
// Input pendek hanya mengganti awal jendela. Setelah tiap input semua tulisan
// di-undo (log g_undo) dan jendela dikembalikan, jadi input tidak saling bergantung.

#include "test_fat32.c"
#include "fuzz.h"

#define FZ_W 3
static uint64_t g_fz_lba[FZ_W];
static uint32_t g_fz_cnt[FZ_W] = { 32, 8, 8 };
static uint8_t *g_fz_base;   // isi asli ketiga jendela, berurutan
static size_t g_fz_base_len;

static void fz_windows(int from_input, const uint8_t *x, size_t xn)
{
    size_t off = 0;
    for (int w = 0; w < FZ_W; w++) {
        size_t len = (size_t)g_fz_cnt[w] * 512;
        uint8_t *dst = g_img + g_fz_lba[w] * 512;
        memcpy(dst, g_fz_base + off, len);
        if (from_input && off < xn) {
            memcpy(dst, x + off, xn - off < len ? xn - off : len);
        }
        off += len;
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    img_open("fuzz_fat32", 65536, 1);
    const uint8_t *bs = g_img;
    uint32_t rsv = (uint32_t)(bs[0x0E] | bs[0x0F] << 8);
    uint32_t fatsz = rd32(bs + 0x24), root = rd32(bs + 0x2C);
    g_fz_lba[0] = 0;
    g_fz_lba[1] = rsv;
    g_fz_lba[2] = rsv + (uint64_t)bs[0x10] * fatsz + (uint64_t)(root - 2) * bs[0x0D];
    FUZZ_ASSERT(rsv >= g_fz_cnt[0]);
    for (int w = 0; w < FZ_W; w++) {
        g_fz_base_len += (size_t)g_fz_cnt[w] * 512;
    }
    g_fz_base = malloc(g_fz_base_len);
    size_t off = 0;
    for (int w = 0; w < FZ_W; w++) {
        memcpy(g_fz_base + off, g_img + g_fz_lba[w] * 512, (size_t)g_fz_cnt[w] * 512);
        off += (size_t)g_fz_cnt[w] * 512;
    }
    return 0;
}

static void fz_cmd(const uint8_t *c, size_t n)
{
    uint8_t *b = malloc(n ? n : 1);
    memcpy(b, c, n);
    g_cmd_len = 0;
    fscmd_execute(b, (uint32_t)n);
    FUZZ_ASSERT(g_cmd_len <= CMD_OUT_MAX);
    free(b);
}

static void fz_run(const char *c)
{
    fz_cmd((const uint8_t *)c, strlen(c));
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 1) {
        return 0;
    }
    size_t cn = d[0];
    if (cn > n - 1) {
        cn = n - 1;
    }
    const uint8_t *x = d + 1 + cn;
    size_t xn = n - 1 - cn;

    fz_windows(1, x, xn);
    g_undo_n = 0;
    g_undo_on = 1;
    g_fail_at = 0;
    g_writes = 0;
    g_reads_fail = 0;

    probe();
    // API baca lama (boot: KEY.TXT, KEYRO.TXT, PROG.BIN); konvensi auth.c:
    // yang dipercaya hanya cluster/size keluaran.
    fat32_probe_root_cluster();
    fat32_list_root_directory();
    static const char *const names[] = { "HELLO   TXT", "BIG     TXT", "KEY     TXT" };
    for (int i = 0; i < 3; i++) {
        uint32_t cl = 0, sz = 0;
        fat32_find_file(names[i], &cl, &sz);
        if (cl >= 2 && sz > 0 && sz <= 8192) {
            uint8_t *k = fat32_load_file(cl, sz);
            if (k) {
                pmm_free((uint64_t)(uintptr_t)k);
            }
            fat32_read_file(cl, sz);
        }
    }
    if (cn > 0) {
        fz_cmd(d + 1, cn);
    }
    fz_run("ls");
    fz_run("baca HELLO.TXT");
    fz_run("baca BIG.TXT 4000");

    fat32_map_t m;
    uint8_t sec[512];
    if (fat32_file_map("BIG     TXT", &m) == FAT32_OK) {
        FUZZ_ASSERT(m.nsec <= FAT32_MAP_MAX);
        for (uint32_t s = 0; s < m.nsec; s += 3) {
            if (fat32_map_read(&m, s, sec) == FAT32_OK) {
                fat32_map_write(&m, s, sec);
            }
        }
    }
    const uint8_t *dir;
    uint32_t ents;
    if (fat32_root_read(&dir, &ents) == FAT32_OK) {
        FUZZ_ASSERT(ents <= FAT32_WRITE_MAX / 32);
    }
    fz_run("tulis FZ.TXT halo fuzz");
    fz_run("tambah FZ.TXT baris kedua");
    fz_run("ganti FZ.TXT GZ.TXT");
    static const uint8_t cfg[] = "cli_idle=600\n";
    fat32_replace_name("CONFIG  CFG", "CONFIG  TMP", cfg, sizeof(cfg) - 1);
    fz_run("hapus GZ.TXT");
    fz_run("ls");

    g_undo_on = 0;
    undo_all();
    fz_windows(0, 0, 0);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const char *const cmds[] = { "", "baca TEST", "tulis A.TXT x", "hapus HELLO.TXT",
                                        "ganti HELLO.TXT BARU.TXT", "baca BIG.TXT 1024" };
    uint8_t *b = malloc(1 + 64 + g_fz_base_len);
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        size_t cn = strlen(cmds[i]);
        b[0] = (uint8_t)cn;
        memcpy(b + 1, cmds[i], cn);
        memcpy(b + 1 + cn, g_fz_base, g_fz_base_len);
        char name[16];
        snprintf(name, sizeof(name), "img%zu", i);
        fuzz_seed(dir, name, b, 1 + cn + g_fz_base_len);
    }
    // Hanya sektor boot (sisa jendela tetap asli).
    b[0] = 0;
    memcpy(b + 1, g_fz_base, 512);
    fuzz_seed(dir, "bpb", b, 513);
    free(b);
}

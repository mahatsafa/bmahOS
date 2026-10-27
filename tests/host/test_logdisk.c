// R4: uji logdisk.c (di-#include: akses state static). fat32_map_* tiruan di
// memori (g_sec), jadi rekaman robek, tulis gagal, dan reboot (state direset,
// "disk" tetap) bisa disimulasikan.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

#define NSEC 128

static uint8_t g_sec[NSEC][512];
static int g_nsec = NSEC;
static int g_map_rc = FAT32_OK;
static int g_writable = 1;
static int g_wfail_at;     // 0 = tidak; k = tulis ke-k dan sesudahnya gagal
static int g_wcount;
volatile int g_ahci_busy;

int fat32_file_map(const char *name83, fat32_map_t *m)
{
    m->nsec = 0;
    if (strcmp(name83, "LOG     BIN") != 0 || g_map_rc != FAT32_OK) {
        return g_map_rc != FAT32_OK ? g_map_rc : FAT32_ERR_NOENT;
    }
    m->nsec = (uint32_t)g_nsec;
    m->spc = 1;
    return FAT32_OK;
}

int fat32_map_read(const fat32_map_t *m, uint32_t sec, uint8_t *buf)
{
    if (sec >= m->nsec) {
        return FAT32_ERR_UNSUP;
    }
    memcpy(buf, g_sec[sec], 512);
    return FAT32_OK;
}

int fat32_map_write(const fat32_map_t *m, uint32_t sec, const uint8_t *buf)
{
    if (sec >= m->nsec) {
        return FAT32_ERR_UNSUP;
    }
    if (!g_writable) {
        return FAT32_ERR_RO;
    }
    g_wcount++;
    if (g_wfail_at && g_wcount >= g_wfail_at) {
        return FAT32_ERR_IO;
    }
    memcpy(g_sec[sec], buf, 512);
    return FAT32_OK;
}

int fat32_writable(void) { return g_writable; }

static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len;
void cmd_putc(char c) { if (g_cmd_len < CMD_OUT_MAX) g_out[g_cmd_len++] = c; }
void cmd_puts(const char *s) { while (*s) cmd_putc(*s++); }

#include "logdisk.c"

// Reboot tiruan: semua state RAM kembali ke awal, isi "disk" tetap.
static void reboot(void)
{
    g_ld_state = LD_INIT;
    g_ld_why = "";
    memset(&g_ld_map, 0, sizeof(g_ld_map));
    g_ld_head = g_ld_tail = 0;
    g_ld_lost_pending = 0;
    g_ld_boot = 0;
    g_ld_next_seq = 0;
    g_ld_slot = 0;
    g_ld_boot_seq = g_ld_prev_seq = 0;
    g_ld_last_write = g_ld_win_start = 0;
    g_ld_win_used = 0;
    g_ld_in_sync = 0;
    g_ld_written = g_ld_lost = g_ld_wfail = g_ld_bad = 0;
    g_netcon_hold = 0;
    g_ahci_busy = 0;
    timer_ticks = 1000;
}

static void wipe(void)
{
    memset(g_sec, 0, sizeof(g_sec));
    g_nsec = NSEC;
    g_map_rc = FAT32_OK;
    g_writable = 1;
    g_wfail_at = 0;
    g_wcount = 0;
}

static const char *run(const char *args)
{
    g_cmd_len = 0;
    logdisk_execute((const volatile uint8_t *)args, (uint32_t)strlen(args));
    g_out[g_cmd_len] = '\0';
    return g_out;
}

static void line(const char *s)
{
    logdisk_line(s, (uint32_t)strlen(s));
}

// Majukan waktu dan jalankan poll sampai antrean kosong (maks n putaran).
static void drain(int n)
{
    for (int i = 0; i < n && (g_ld_head != g_ld_tail || g_ld_lost_pending); i++) {
        timer_ticks += 100;
        logdisk_poll();
    }
}

static uint64_t kv(const char *k)
{
    char key[64];
    snprintf(key, sizeof(key), "%s=", k);
    run("");
    const char *p = strstr(g_out, key);
    return p ? strtoull(p + strlen(key), NULL, 10) : (uint64_t)-1;
}

// Gabungkan semua halaman mulai seq (ikuti logdisk_lanjut=); -1 bila format salah.
static char g_all[200000];
static int read_all(uint64_t seq, int *pages)
{
    char a[32];
    size_t pos = 0;

    *pages = 0;
    g_all[0] = 0;
    for (int i = 0; i < 500; i++) {
        snprintf(a, sizeof(a), " %lu", (unsigned long)seq);
        run(a);
        (*pages)++;
        if (g_cmd_len > CMD_OUT_MAX || g_cmd_len == 0 || g_out[g_cmd_len - 1] != '\n') {
            return -1;
        }
        char *lj = strstr(g_out, "logdisk_lanjut=");
        size_t keep = lj ? (size_t)(lj - g_out) : g_cmd_len;
        if (lj && lj[strlen(lj) - 1] != '\n') {
            return -1;
        }
        memcpy(g_all + pos, g_out, keep);
        pos += keep;
        g_all[pos] = 0;
        if (!lj) {
            return 0;
        }
        seq = strtoull(lj + 15, NULL, 10);
    }
    return -1;
}

static int count(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) {
        n++;
    }
    return n;
}

static void test_off(void)
{
    wipe();
    reboot();
    g_map_rc = FAT32_ERR_NOENT;
    line("sebelum init");
    CHECK(g_ld_head - g_ld_tail == 13);     // antre sebelum init
    serial_capture_reset();
    logdisk_init();
    CHECK(g_ld_state == LD_OFF && g_ld_head == g_ld_tail);
    CHECK(strstr(g_serial_cap, "R4: logdisk nonaktif tanpa LOG.BIN") != NULL);
    CHECK_STR(run(""), "logdisk=nonaktif tanpa LOG.BIN\n");
    CHECK_STR(run(" 1"), "ERR: logdisk nonaktif\n");
    line("sesudah");
    CHECK(g_ld_head == g_ld_tail && g_ld_lost == 0);
    logdisk_sync(1);   // tidak menulis apa pun
    CHECK(g_wcount == 0);

    reboot();
    g_map_rc = FAT32_ERR_TOOBIG;
    logdisk_init();
    CHECK_STR(run(""), "logdisk=nonaktif ukuran LOG.BIN\n");
}

static void test_empty(void)
{
    wipe();
    reboot();
    logdisk_init();
    CHECK(g_ld_written == 0 && g_ld_next_seq == 1);
    CHECK_STR(run(" 1"), "ERR: logdisk kosong\n");
    CHECK(kv("seq_tertua") == 0);
}

static void test_basic(void)
{
    wipe();
    reboot();
    line("awal boot 1");                     // sebelum init: tetap tersimpan
    serial_capture_reset();
    logdisk_init();
    // Antrean awal boot langsung ditulis oleh init (rekaman 1 = "awal boot 1\n").
    CHECK(g_ld_state == LD_ON && g_ld_boot == 1 && g_ld_next_seq == 2 && g_ld_slot == 1);
    CHECK(g_ld_written == 1 && g_ld_head == g_ld_tail);
    CHECK(strstr(g_serial_cap, "R4: logdisk aktif rekaman=128 boot=1 seq=1 rusak=0") != NULL);
    CHECK(kv("seq_tertua") == 1 && kv("seq_boot_lalu") == 0 && kv("seq_boot_ini") == 1);
    logdisk_poll();
    CHECK(g_ld_written == 1);
    CHECK(logdisk_rec_ok(g_sec[0]) == 12 && memcmp(g_sec[0] + 32, "awal boot 1\n", 12) == 0);
    CHECK(g_sec[0][8] == 1 && g_sec[0][16] == 1 && g_sec[0][5] == 0);

    // Kurang dari satu rekaman dan < 5 s: tidak ditulis.
    line("baris dua");
    timer_ticks += 100;
    logdisk_poll();
    CHECK(g_ld_written == 1);
    timer_ticks += 400;
    logdisk_poll();
    CHECK(g_ld_written == 2);
    CHECK_STR(run(" 1"), "=== boot 1 seq 1 ===\nawal boot 1\nbaris dua\n");
    CHECK_STR(run(" 0"), "=== boot 1 seq 1 ===\nawal boot 1\nbaris dua\n");   // < tertua
    CHECK_STR(run(" 2"), "=== boot 1 seq 2 ===\nbaris dua\n");
    CHECK_STR(run(" 3"), "ERR: logdisk: seq di luar ring\n");

    // Teks >= satu rekaman: langsung ditulis, maks 2 per 100 tick.
    char l[100];
    for (int i = 0; i < 40; i++) {
        snprintf(l, sizeof(l), "baris-%03d-%s", i, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        line(l);
    }
    uint64_t w0 = g_ld_written;
    g_ld_win_start = timer_ticks;
    g_ld_win_used = 0;
    for (int i = 0; i < 5; i++) {
        logdisk_poll();
    }
    CHECK(g_ld_written == w0 + 2);           // batas laju
    timer_ticks += 100;
    logdisk_poll();
    logdisk_poll();
    CHECK(g_ld_written == w0 + 4);
    drain(10);
    CHECK(g_ld_head == g_ld_tail);
    int pages;
    CHECK(read_all(1, &pages) == 0 && pages >= 2);
    CHECK(count(g_all, "baris-0") == 40 && count(g_all, "baris-039-") == 1);
    CHECK(count(g_all, "=== boot 1") == pages);  // header di awal tiap halaman
    // Rekaman hanya berisi baris utuh.
    int whole = 1;
    for (int s = 0; s < (int)g_ld_next_seq - 1; s++) {
        int n = logdisk_rec_ok(g_sec[s]);
        whole &= n > 0 && g_sec[s][32 + n - 1] == '\n';
    }
    CHECK(whole);

    // Argumen salah
    CHECK_STR(run(" "), "ERR: logdisk [seq]\n");
    CHECK_STR(run(" x"), "ERR: logdisk [seq]\n");
    CHECK_STR(run("  1"), "ERR: logdisk [seq]\n");
    CHECK_STR(run(" 1 2"), "ERR: logdisk [seq]\n");
    CHECK_STR(run(" 1234567890123456789012"), "ERR: logdisk [seq]\n");
    CHECK(kv("ditulis") == g_ld_written && kv("antre") == 0 && kv("boot") == 1);
}

static void test_reboot_wrap(void)
{
    // Lanjut dari test_basic: reboot -> boot 2, seq lanjut, seq_boot_lalu = 1.
    uint64_t next = g_ld_next_seq;
    reboot();
    logdisk_init();
    CHECK(g_ld_boot == 2 && g_ld_next_seq == next && g_ld_prev_seq == 1 &&
          g_ld_boot_seq == next);
    line("boot dua");
    drain(10);
    int pages;
    CHECK(read_all(1, &pages) == 0);
    CHECK(count(g_all, "=== boot 1 seq 1 ===") == 1 && count(g_all, "=== boot 2 seq ") == 1);
    CHECK(strstr(g_all, "baris-039-") < strstr(g_all, "boot dua"));

    // Isi sampai ring berputar beberapa kali (3 boot lagi), tiap baris unik.
    char l[100];
    int k = 0;
    for (int b = 0; b < 3; b++) {
        reboot();
        logdisk_init();
        for (int i = 0; i < 300; i++) {
            snprintf(l, sizeof(l), "b%u-%05d-%s", g_ld_boot, k++,
                     "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");
            line(l);
            if (g_ld_head - g_ld_tail > 2000) {
                drain(20);
            }
        }
        drain(50);
    }
    CHECK(g_ld_boot == 5 && g_ld_lost == 0);
    uint64_t last = g_ld_next_seq - 1;
    CHECK(last > NSEC);
    CHECK(kv("seq_tertua") == last - NSEC + 1);
    CHECK(read_all(1, &pages) == 0 && pages > 30);
    // 128 rekaman terakhir utuh, urut: baris terakhir ada, baris pertama boot 3 tidak.
    snprintf(l, sizeof(l), "b5-%05d-", k - 1);
    CHECK(strstr(g_all, l) != NULL);
    CHECK(strstr(g_all, "b3-00000-") == NULL && strstr(g_all, "boot dua") == NULL);
    CHECK(count(g_all, "rusak/hilang") == 0);
    int ordered = 1, prev = -1;
    for (const char *p = g_all; (p = strstr(p, "\nb")) != NULL; p++) {
        int v = atoi(p + 4);
        if (p[3] != '-') continue;
        ordered &= v == prev + 1 || prev == -1;
        prev = v;
    }
    CHECK(ordered && prev == k - 1);

    // Reboot setelah wrap: posisi ditemukan dari seq terbesar, bukan sektor 0.
    uint32_t slot = g_ld_slot;
    reboot();
    logdisk_init();
    CHECK(g_ld_slot == slot && g_ld_next_seq == last + 1 && g_ld_boot == 6);
    CHECK(g_ld_prev_seq > last - NSEC && g_ld_prev_seq <= last);
}

static void test_torn(void)
{
    // Rekaman robek (hash salah) di tengah: dihitung rusak saat boot, dilewati saat baca.
    wipe();
    reboot();
    logdisk_init();
    for (int i = 0; i < 6; i++) {
        char l[32];
        snprintf(l, sizeof(l), "rek %d", i);
        line(l);
        timer_ticks += 600;
        logdisk_poll();
    }
    CHECK(g_ld_written == 6);
    g_sec[2][40] ^= 0x55;                 // isi rusak
    g_sec[4][0] = 'X';                    // magic rusak = dianggap kosong
    reboot();
    logdisk_init();
    CHECK(g_ld_bad == 1 && g_ld_next_seq == 7 && g_ld_boot == 2);
    CHECK_STR(run(" 1"), "=== boot 1 seq 1 ===\nrek 0\nrek 1\n=== seq 3 rusak/hilang ===\n"
                         "=== boot 1 seq 4 ===\nrek 3\n=== seq 5 rusak/hilang ===\n"
                         "=== boot 1 seq 6 ===\nrek 5\n");
    CHECK(kv("rusak") == 1);

    // Rekaman dengan seq terbesar robek: tulis berikutnya menimpa sesudah seq sah terakhir.
    g_sec[5][41] ^= 1;
    reboot();
    logdisk_init();
    CHECK(g_ld_next_seq == 5 && g_ld_slot == 4 && g_ld_bad == 2);
}

static void test_overflow_hold(void)
{
    wipe();
    reboot();
    logdisk_init();
    char l[200];
    memset(l, 'q', 159);
    l[159] = 0;
    for (int i = 0; i < 40; i++) {         // 40 x 160 = 6400 > 4096
        line(l);
    }
    CHECK(g_ld_lost == 15 && g_ld_head - g_ld_tail == 25 * 160);
    g_netcon_hold = 1;
    line("rahasia RAX=1234");
    g_netcon_hold = 0;
    CHECK(g_ld_lost == 15);                 // hold: tidak diantre, tidak dihitung
    drain(40);
    line("sesudah");
    drain(5);
    int pages;
    CHECK(read_all(1, &pages) == 0);
    CHECK(count(g_all, "logdisk: 15 baris dibuang\n") == 1 && count(g_all, "rahasia") == 0);
    CHECK(strstr(g_all, "logdisk: 15") < strstr(g_all, "sesudah"));
    CHECK(kv("dibuang") == 15);
}

static void test_sync(void)
{
    wipe();
    reboot();
    logdisk_init();
    for (int i = 0; i < 30; i++) {
        line("PANIC: baris dump panjang xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    }
    // AHCI sedang dipakai -> dilewati
    g_ahci_busy = 1;
    logdisk_sync(1);
    CHECK(g_ld_written == 0);
    g_ahci_busy = 0;
    // Tanpa batas laju, flag panic
    logdisk_sync(1);
    CHECK(g_ld_written >= 5 && g_ld_head == g_ld_tail);
    CHECK((g_sec[0][5] & 1) && logdisk_rec_ok(g_sec[0]) > 0);
    CHECK(strstr(run(" 1"), "=== boot 1 seq 1 panic ===\n") == g_out);
    // Bersarang (g_ld_in_sync) -> tidak menulis
    line("x");
    g_ld_in_sync = 1;
    logdisk_sync(0);
    CHECK(g_ld_head != g_ld_tail);
    g_ld_in_sync = 0;
    logdisk_sync(0);
    CHECK(g_ld_head == g_ld_tail && (g_sec[g_ld_slot - 1][5] & 1) == 0);
}

static void test_panic_mid(void)
{
    // Rekaman panic di tengah boot mendapat header sendiri.
    wipe();
    reboot();
    logdisk_init();
    line("sebelum panic");
    logdisk_sync(0);
    line("PANIC: contoh");
    logdisk_sync(1);
    run(" 1");
    CHECK(strstr(g_out, "=== boot 1 seq 1 ===\n") == g_out);
    CHECK(count(g_out, "=== boot 1 seq 2 panic ===\nPANIC: contoh\n") == 1);
    CHECK(count(g_out, "===") == 2 * 2);
}

static void test_fail_ro(void)
{
    // Tulis gagal -> nonaktif, gagal +1, antrean tidak lagi diisi.
    wipe();
    reboot();
    logdisk_init();
    line("a");
    g_wfail_at = 1;
    timer_ticks += 1000;
    logdisk_poll();
    CHECK(g_ld_state == LD_OFF && g_ld_wfail == 1 && g_ld_written == 0);
    CHECK_STR(run(""), "logdisk=nonaktif tulis gagal\n");
    uint32_t h = g_ld_head;
    line("b");
    CHECK(g_ld_head == h);

    // Volume baca saja: rekaman lama terbaca, tidak ada yang diantre/ditulis.
    wipe();
    reboot();
    logdisk_init();
    line("dari boot 1");
    drain(5);
    reboot();
    g_writable = 0;
    logdisk_init();
    CHECK(g_ld_state == LD_RO);
    line("tidak ditulis");
    CHECK(g_ld_head == g_ld_tail);
    CHECK(strncmp(run(""), "logdisk=baca-saja volume baca saja\nrekaman=128\nboot=2\n", 53) == 0);
    CHECK_STR(run(" 1"), "=== boot 1 seq 1 ===\ndari boot 1\n");

    // File 1 sektor: ring 1 rekaman tetap jalan.
    wipe();
    g_nsec = 1;
    reboot();
    logdisk_init();
    for (int i = 0; i < 3; i++) {
        line(i == 2 ? "terakhir" : "lama");
        timer_ticks += 600;
        logdisk_poll();
    }
    CHECK(g_ld_next_seq == 4 && g_ld_slot == 0);
    CHECK_STR(run(" 1"), "=== boot 1 seq 3 ===\nterakhir\n");
}

#ifndef BMAHOS_FUZZ   // R7: tests/fuzz/fuzz_logdisk.c memakai helper file ini
int main(void)
{
    test_off();
    test_empty();
    test_basic();
    test_reboot_wrap();
    test_torn();
    test_overflow_hold();
    test_sync();
    test_panic_mid();
    test_fail_ro();
    return test_done("logdisk");
}
#endif

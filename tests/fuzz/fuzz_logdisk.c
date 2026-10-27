// R7: fuzz pemindai/pembaca LOG.BIN (kernel/logdisk.c) dengan disk tiruan dari
// tests/host/test_logdisk.c. Byte 0 = jumlah sektor LOG.BIN (1..NSEC), byte 1..8
// = seq untuk "logdisk <seq>" (LE), sisanya isi sektor berurutan (kurang = nol).
// Alur: boot (logdisk_init), status, baca dari seq dan dari 0, tulis baris baru,
// poll, sync, lalu "reboot" dan pindai ulang.

#include "test_logdisk.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

static void fz_run(const char *a)
{
    run(a);
    FUZZ_ASSERT(g_cmd_len <= CMD_OUT_MAX);
}

static void fz_boot(uint64_t seq)
{
    char a[32];
    reboot();
    logdisk_init();
    fz_run("");
    snprintf(a, sizeof(a), " %lu", (unsigned long)seq);
    fz_run(a);
    fz_run(" 0");
    fz_run(" 18446744073709551615");
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 9) {
        return 0;
    }
    uint64_t seq = 0;
    for (int i = 0; i < 8; i++) {
        seq |= (uint64_t)d[1 + i] << (8 * i);
    }
    wipe();
    g_nsec = 1 + d[0] % NSEC;
    size_t xn = n - 9;
    if (xn > (size_t)g_nsec * 512) {
        xn = (size_t)g_nsec * 512;
    }
    memcpy(g_sec, d + 9, xn);

    fz_boot(seq);
    line("baris fuzz pertama");
    line("baris fuzz kedua");
    drain(8);
    logdisk_sync(0);
    fz_boot(seq);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    // Disk dengan dua boot berisi baris log, lalu satu sektor dirusak.
    static uint8_t b[9 + NSEC * 512];
    wipe();
    g_nsec = 16;
    for (int boot = 0; boot < 2; boot++) {
        reboot();
        logdisk_init();
        for (int i = 0; i < 40; i++) {
            char s[64];
            snprintf(s, sizeof(s), "boot %d baris %d isi log untuk korpus", boot, i);
            line(s);
        }
        drain(50);
        logdisk_sync(boot == 1);
    }
    b[0] = 15;
    b[1] = 3;
    memcpy(b + 9, g_sec, 16 * 512);
    fuzz_seed(dir, "dua_boot", b, 9 + 16 * 512);
    b[9 + 512 * 2 + 40] ^= 0x55;
    fuzz_seed(dir, "rusak", b, 9 + 16 * 512);
    b[0] = 0;
    fuzz_seed(dir, "satu", b, 9 + 512);
    fuzz_seed(dir, "kosong", b, 9);
}

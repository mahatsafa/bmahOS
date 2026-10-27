// P3-2: fuzz sntp_rx (balasan NTP dari LAN) dengan stub tests/host/test_sntp.c.
// Byte 0 = mode: bit 0 salin nonce kita ke originate (supaya lolos cek nonce),
// bit 1 byte 0 = 0x24 (LI 0, VN 4, mode 4), bit 2 stratum 2. Sisa = isi UDP.
// Invarian: balasan diterima (ok naik) hanya bila >= 48 byte, nonce cocok,
// mode 4, VN 3/4, LI != 3, stratum 1..15, transmit >= 1970; saat diterima jam =
// transmit - 2208988800 dengan sumber SNTP, selain itu jam tidak berubah.

#include "test_sntp.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    sntp_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    const char *why = "";

    if (n < 1) {
        return 0;
    }
    uint8_t m = d[0];
    size_t xn = n - 1;
    uint8_t *b = malloc(xn ? xn : 1);
    memcpy(b, d + 1, xn);

    reset();
    timer_ticks = 5000;
    if (sntp_start(1, 123, &why) != 0) {
        free(b);
        return 0;
    }
    arp_from(1, SRV_MAC);
    sntp_poll();                       // permintaan dengan nonce
    FUZZ_ASSERT(g_sntp_state == SNTP_SENT);
    if ((m & 1) && xn >= 32) {
        memcpy(b + 24, g_sntp_nonce, 8);
    }
    if ((m & 2) && xn >= 1) {
        b[0] = 0x24;
    }
    if ((m & 4) && xn >= 2) {
        b[1] = 2;
    }
    uint64_t ok0 = g_sntp_ok;
    sntp_rx(b, (uint32_t)xn);

    if (g_sntp_ok != ok0) {
        uint8_t li = b[0] >> 6, vn = (b[0] >> 3) & 7;
        uint32_t tx = (uint32_t)b[40] << 24 | (uint32_t)b[41] << 16 | (uint32_t)b[42] << 8 | b[43];
        FUZZ_ASSERT(xn >= 48 && memcmp(b + 24, g_sntp_nonce, 8) == 0 && (b[0] & 7) == 4);
        FUZZ_ASSERT((vn == 3 || vn == 4) && li != 3 && b[1] >= 1 && b[1] <= 15);
        FUZZ_ASSERT(tx >= NTP_UNIX_DELTA && g_sntp_state == SNTP_IDLE && g_time_src == 1);
        FUZZ_ASSERT(rtc_now() == (uint64_t)(tx - NTP_UNIX_DELTA));
    } else {
        FUZZ_ASSERT(g_sntp_state == SNTP_SENT && g_time_src == 0);
    }
    free(b);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const uint8_t zero8[8] = { 0 };
    uint8_t buf[49];

    mk_rep(0x24, 2, zero8, 3970000000u);   // sah (nonce lewat bit 0)
    buf[0] = 1;
    memcpy(buf + 1, g_rep, 48);
    fuzz_seed(dir, "sah", buf, sizeof(buf));
    mk_rep(0x1C, 1, zero8, 3970000000u);   // VN 3
    memcpy(buf + 1, g_rep, 48);
    fuzz_seed(dir, "vn3", buf, sizeof(buf));
    mk_rep(0xE4, 16, zero8, 100);          // LI 3, stratum 16, sebelum 1970
    buf[0] = 0;
    memcpy(buf + 1, g_rep, 48);
    fuzz_seed(dir, "rusak", buf, sizeof(buf));
    fuzz_seed(dir, "pendek", buf, 30);
}

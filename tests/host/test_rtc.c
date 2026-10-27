// P3-1: uji konversi RTC (rtc.c di-#include; baca CMOS tidak dikompilasi di host).

#include <stdint.h>
#include <time.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/rtc.c"

static uint64_t ref_epoch(int y, int mo, int d, int h, int mi, int s)
{
    struct tm t = { 0 };
    t.tm_year = y - 1900;
    t.tm_mon = mo - 1;
    t.tm_mday = d;
    t.tm_hour = h;
    t.tm_min = mi;
    t.tm_sec = s;
    return (uint64_t)timegm(&t);
}

static void test_civil(void)
{
    CHECK(rtc_days_from_civil(1970, 1, 1) == 0);
    CHECK(rtc_days_from_civil(2000, 2, 29) == 11016);
    CHECK(rtc_days_from_civil(2026, 10, 27) * 86400 == ref_epoch(2026, 10, 27, 0, 0, 0));
    // Bandingkan dengan timegm untuk tiap hari 1970..2100 (termasuk 2000 kabisat,
    // 2100 bukan kabisat), dan kebalikannya.
    int ok = 1, back = 1;
    for (uint64_t days = 0; days < 47847; days++) {
        uint64_t t = days * 86400 + 12345;
        rtc_time_t o;
        rtc_civil_from_epoch(t, &o);
        time_t tt = (time_t)t;
        struct tm g;
        gmtime_r(&tt, &g);
        ok &= o.year == (uint32_t)g.tm_year + 1900 && o.month == (uint32_t)g.tm_mon + 1 &&
              o.day == (uint32_t)g.tm_mday && o.hour == 3 && o.min == 25 && o.sec == 45;
        back &= rtc_days_from_civil(o.year, o.month, o.day) == days;
    }
    CHECK(ok);
    CHECK(back);
}

static void test_raw(void)
{
    // BCD, 24 jam (status B 0x02): 2026-10-27 21:58:07.
    const uint8_t bcd[6] = { 0x07, 0x58, 0x21, 0x27, 0x10, 0x26 };
    CHECK(rtc_raw_to_epoch(bcd, 0x02) == ref_epoch(2026, 10, 27, 21, 58, 7));
    // Biner (bit 2) + 24 jam.
    const uint8_t bin[6] = { 7, 58, 21, 27, 10, 26 };
    CHECK(rtc_raw_to_epoch(bin, 0x06) == ref_epoch(2026, 10, 27, 21, 58, 7));
    // 12 jam BCD: 09 PM = 21, 12 AM = 0, 12 PM = 12.
    const uint8_t pm9[6] = { 0x07, 0x58, 0x89, 0x27, 0x10, 0x26 };
    CHECK(rtc_raw_to_epoch(pm9, 0x00) == ref_epoch(2026, 10, 27, 21, 58, 7));
    const uint8_t am12[6] = { 0, 0, 0x12, 0x01, 0x01, 0x27 };
    CHECK(rtc_raw_to_epoch(am12, 0x00) == ref_epoch(2027, 1, 1, 0, 0, 0));
    const uint8_t pm12[6] = { 0, 0, 0x92, 0x01, 0x01, 0x27 };
    CHECK(rtc_raw_to_epoch(pm12, 0x00) == ref_epoch(2027, 1, 1, 12, 0, 0));
    // Tidak masuk akal -> 0.
    const uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };
    CHECK(rtc_raw_to_epoch(zero, 0x02) == 0);
    const uint8_t mon13[6] = { 0, 0, 0, 1, 0x13, 0x26 };
    CHECK(rtc_raw_to_epoch(mon13, 0x02) == 0);
    const uint8_t ff[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    CHECK(rtc_raw_to_epoch(ff, 0x02) == 0);
}

static char g_out[256];
static void out_cpy(const char *s)
{
    snprintf(g_out, sizeof(g_out), "%s", s);
}

static void test_now(void)
{
    g_rtc_ok = 0;
    rtc_status(out_cpy);
    CHECK_STR(g_out, "waktu: tidak tersedia (RTC tidak masuk akal)\n");
    CHECK(rtc_now() == 0);
    g_rtc_ok = 1;
    g_rtc_boot_epoch = ref_epoch(2026, 10, 27, 23, 59, 59);
    g_rtc_boot_tick = 500;
    timer_ticks = 500 + 150;   // 1,5 s kemudian -> lewat tengah malam
    CHECK(rtc_now() == g_rtc_boot_epoch + 1);
    rtc_status(out_cpy);
    CHECK_STR(g_out, "waktu: 2026-10-28 00:00:00 epoch=1793145600 sumber=rtc (zona host)\n");
}

int main(void)
{
    test_civil();
    test_raw();
    test_now();
    return test_done("rtc");
}

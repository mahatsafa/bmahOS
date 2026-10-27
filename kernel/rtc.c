#include "kernel.h"

// P3-1: jam dinding dari RTC CMOS (port 0x70/0x71). Dibaca sekali saat boot
// (rtc_init) lalu dimajukan dengan timer_ticks, jadi `waktu` tidak menyentuh
// CMOS lagi. Zona waktu RTC tidak diketahui (VMware/Windows umumnya waktu
// lokal host), jadi ditampilkan apa adanya tanpa label UTC. Belum ada SNTP.
// Baca: tunggu bit UIP (status A bit 7) mati, baca semua register, ulang
// sampai dua bacaan berturut-turut sama (maks RTC_TRIES). Status B bit 2 =
// biner (bukan BCD), bit 1 = 24 jam (bila 0, bit 7 jam = PM).

#define RTC_TRIES 8

uint64_t g_rtc_boot_epoch;   // epoch (detik sejak 1970-01-01) saat timer_ticks = g_rtc_boot_tick
uint64_t g_rtc_boot_tick;
int g_rtc_ok;
uint32_t g_time_src;          // P3-2: 0 = RTC (zona host), 1 = SNTP (UTC)
static uint32_t g_time_host, g_time_stratum;
static int64_t g_time_adj;    // koreksi SNTP terakhir (detik, baru - lama)

static uint8_t rtc_bcd(uint8_t v)
{
    return (uint8_t)((v >> 4) * 10 + (v & 0x0F));
}

// Hari sejak 1970-01-01 untuk tanggal Gregorian (algoritme days_from_civil,
// Howard Hinnant, domain publik). Tahun >= 1970.
uint64_t rtc_days_from_civil(uint32_t y, uint32_t m, uint32_t d)
{
    y -= m <= 2;
    uint32_t era = y / 400;
    uint32_t yoe = y - era * 400;
    uint32_t doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    uint32_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (uint64_t)era * 146097 + doe - 719468;
}

// Kebalikan: epoch -> tahun, bulan, hari, jam, menit, detik.
void rtc_civil_from_epoch(uint64_t t, rtc_time_t *o)
{
    uint64_t days = t / 86400;
    uint32_t rem = (uint32_t)(t % 86400);
    uint64_t z = days + 719468;
    uint64_t era = z / 146097;
    uint32_t doe = (uint32_t)(z - era * 146097);
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;

    o->day = doy - (153 * mp + 2) / 5 + 1;
    o->month = mp < 10 ? mp + 3 : mp - 9;
    o->year = (uint32_t)(yoe + era * 400) + (o->month <= 2);
    o->hour = rem / 3600;
    o->min = rem / 60 % 60;
    o->sec = rem % 60;
}

// Register mentah (detik, menit, jam, hari, bulan, tahun 2 digit, status B)
// -> epoch. 0 = isi tidak masuk akal (mis. CMOS kosong / bulan 13).
uint64_t rtc_raw_to_epoch(const uint8_t raw[6], uint8_t status_b)
{
    uint8_t v[6];
    int pm = 0;

    for (int i = 0; i < 6; i++) {
        v[i] = raw[i];
    }
    if (!(status_b & 0x02)) {          // 12 jam: bit 7 jam = PM
        pm = (v[2] & 0x80) != 0;
        v[2] &= 0x7F;
    }
    if (!(status_b & 0x04)) {          // BCD
        for (int i = 0; i < 6; i++) {
            v[i] = rtc_bcd(v[i]);
        }
    }
    if (!(status_b & 0x02)) {
        v[2] = (uint8_t)(v[2] % 12 + (pm ? 12 : 0));
    }
    uint32_t sec = v[0], min = v[1], hour = v[2], day = v[3], mon = v[4];
    uint32_t year = 2000u + v[5];   // abad: CMOS 0x32 tidak selalu ada, anggap 20xx

    if (sec > 59 || min > 59 || hour > 23 || day < 1 || day > 31 || mon < 1 || mon > 12) {
        return 0;
    }
    return rtc_days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec;
}

#ifndef BMAHOS_HOST_TEST
static uint8_t cmos_read(uint8_t reg)
{
    outb(0x70, (uint8_t)(0x80 | reg));   // bit 7: NMI mati selama akses
    return inb(0x71);
}

static void rtc_read_raw(uint8_t r[6])
{
    static const uint8_t regs[6] = { 0x00, 0x02, 0x04, 0x07, 0x08, 0x09 };

    for (uint32_t spin = 0; spin < 100000 && (cmos_read(0x0A) & 0x80); spin++) {
    }
    for (int i = 0; i < 6; i++) {
        r[i] = cmos_read(regs[i]);
    }
}

void rtc_init(void)
{
    uint8_t a[6], b[6];
    int same = 0;

    uint64_t lf = irq_save();
    rtc_read_raw(a);
    for (int t = 0; t < RTC_TRIES && !same; t++) {
        rtc_read_raw(b);
        same = memcmp(a, b, 6) == 0;
        memcpy(a, b, 6);
    }
    uint8_t sb = cmos_read(0x0B);
    g_rtc_boot_tick = timer_ticks;
    irq_restore(lf);

    g_rtc_boot_epoch = same ? rtc_raw_to_epoch(a, sb) : 0;
    g_rtc_ok = g_rtc_boot_epoch != 0;

    rtc_time_t t;
    rtc_civil_from_epoch(g_rtc_boot_epoch, &t);
    kprintf("P3: RTC %s %04u-%02u-%02u %02u:%02u:%02u (status B 0x%x)\r\n",
            g_rtc_ok ? "ok" : "tidak masuk akal", t.year, t.month, t.day, t.hour, t.min,
            t.sec, (unsigned)sb);
}
#endif

uint64_t rtc_now(void)
{
    if (!g_rtc_ok) {
        return 0;
    }
    return g_rtc_boot_epoch + (timer_ticks - g_rtc_boot_tick) / 100;
}

// P3-2: jam dinding dari SNTP (UTC), mulai tick sekarang. Mengembalikan
// koreksi (baru - lama) dalam detik; 0 bila sebelumnya tidak ada jam sah.
int64_t rtc_set_sntp(uint64_t epoch, uint32_t host, uint32_t stratum)
{
    int64_t adj = g_rtc_ok ? (int64_t)epoch - (int64_t)rtc_now() : 0;

    g_rtc_boot_tick = timer_ticks;
    g_rtc_boot_epoch = epoch;
    g_rtc_ok = 1;
    g_time_src = 1;
    g_time_host = host;
    g_time_stratum = stratum;
    g_time_adj = adj;
    return adj;
}

// Perintah `waktu`.
void rtc_status(void (*out)(const char *))
{
    char line[128];
    rtc_time_t t;
    uint64_t now = rtc_now();

    if (!g_rtc_ok) {
        out("waktu: tidak tersedia (RTC tidak masuk akal)\n");
        return;
    }
    rtc_civil_from_epoch(now, &t);
    if (g_time_src == 1) {
        ksnprintf(line, sizeof(line),
                  "waktu: %04u-%02u-%02u %02u:%02u:%02u epoch=%lu sumber=sntp oktet=%u stratum=%u "
                  "(UTC) koreksi=%ld s\n", t.year, t.month, t.day, t.hour, t.min, t.sec, now,
                  g_time_host, g_time_stratum, g_time_adj);
    } else {
        ksnprintf(line, sizeof(line),
                  "waktu: %04u-%02u-%02u %02u:%02u:%02u epoch=%lu sumber=rtc (zona host)\n",
                  t.year, t.month, t.day, t.hour, t.min, t.sec, now);
    }
    out(line);
}

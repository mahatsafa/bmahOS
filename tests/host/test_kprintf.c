// F1.7: uji kprintf/ksnprintf (kernel/kprintf.c) di host.
// Hasil ksnprintf dibandingkan dengan snprintf libc untuk format yang
// didukung (%d %u %x %ld %lu %lx %s %c %%) dan semua ukuran buffer.

#include <limits.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

// Bandingkan ksnprintf dan snprintf untuk semua ukuran buffer 0..len+2.
#define SAME(...) \
    do { \
        char k_[128], l_[128]; \
        int ln_ = snprintf(l_, sizeof(l_), __VA_ARGS__); \
        int ok_ = 1; \
        for (size_t sz_ = 0; sz_ <= (size_t)ln_ + 2 && sz_ <= sizeof(k_); sz_++) { \
            memset(k_, 'Z', sizeof(k_)); \
            memset(l_, 'Z', sizeof(l_)); \
            size_t kr_ = ksnprintf(k_, sz_, __VA_ARGS__); \
            int lr_ = snprintf(l_, sz_, __VA_ARGS__); \
            if (kr_ != (size_t)lr_ || memcmp(k_, l_, sizeof(k_)) != 0) { \
                ok_ = 0; \
                fprintf(stderr, "GAGAL %s:%d: size=%zu ksnprintf=\"%.*s\" (%zu) libc=\"%.*s\" (%d)\n", \
                        __FILE__, __LINE__, sz_, (int)(sz_ ? sz_ : 1), k_, kr_, \
                        (int)(sz_ ? sz_ : 1), l_, lr_); \
                break; \
            } \
        } \
        CHECK(ok_); \
    } while (0)

static void test_ints(void)
{
    static const int iv[] = { 0, 1, -1, 9, 10, -10, 42, -42, 99999, INT_MAX, INT_MIN, INT_MIN + 1 };
    static const unsigned uv[] = { 0, 1, 9, 10, 15, 16, 255, 256, 0xBEEF, 4000000000u, UINT_MAX };
    static const int64_t lv[] = { 0, -1, 1234567890123LL, -1234567890123LL, INT64_MAX, INT64_MIN };
    static const uint64_t luv[] = { 0, 1, 0xFFFF980000000000ULL, UINT64_MAX, 10000000000000000000ULL };

    for (size_t i = 0; i < sizeof(iv) / sizeof(iv[0]); i++) {
        SAME("%d", iv[i]);
        SAME("[%d|%d]", iv[i], -iv[(i + 1) % 3]);
    }
    for (size_t i = 0; i < sizeof(uv) / sizeof(uv[0]); i++) {
        SAME("%u", uv[i]);
        SAME("%x", uv[i]);
        SAME("u=%u x=%x", uv[i], uv[i]);
    }
    for (size_t i = 0; i < sizeof(lv) / sizeof(lv[0]); i++) {
        SAME("%ld", (long)lv[i]);
    }
    for (size_t i = 0; i < sizeof(luv) / sizeof(luv[0]); i++) {
        SAME("%lu", (unsigned long)luv[i]);
        SAME("%lx", (unsigned long)luv[i]);
    }
}

// Lebar ber-nol %0N (P2/P3): sama dengan libc untuk N <= 20.
static void test_width(void)
{
    SAME("%02x", 5u);
    SAME("%02x", 0xabcu);
    SAME("%04x:%04x", 0x8086u, 0x100eu);
    SAME("%02x:%02x.%u", 0u, 0x1fu, 2u);
    SAME("%04u-%02u-%02u %02u:%02u:%02u", 2026u, 10u, 7u, 0u, 5u, 59u);
    SAME("%05d|%05d|%01d|%0d", 42, -42, -7, 7);
    SAME("%03d", INT_MIN);
    SAME("%020lu", (unsigned long)UINT64_MAX);
    SAME("%016lx", 0x1234UL);
    SAME("%020ld", (long)INT64_MIN);
    SAME("[%08x]", 0xdeadbeefu);
}

static void test_strs(void)
{
    SAME("%s", "");
    SAME("%s", "halo");
    SAME("a%sb%sc", "xyz", "");
    SAME("%c%c%c", 'b', 'm', 'h');
    SAME("100%%");
    SAME("%%d %d", 7);
    SAME("tanpa format sama sekali, cukup panjang untuk dipotong di banyak ukuran");
    SAME("campur: %s=%d (%x) %c %lu%%", "nilai", -7, 0xABCu, 'k', 123456789012UL);
}

static void test_special(void)
{
    char b[64];
    size_t r;

    // %p: selalu 0x + 16 digit hex.
    r = ksnprintf(b, sizeof(b), "%p", (void *)0x1234);
    CHECK_STR(b, "0x0000000000001234");
    CHECK(r == 18);
    r = ksnprintf(b, sizeof(b), "%p", (void *)0xffffffff80001000ULL);
    CHECK_STR(b, "0xffffffff80001000");

    // %s NULL -> "(null)".
    const char *volatile nul = NULL;
    ksnprintf(b, sizeof(b), "<%s>", nul);
    CHECK_STR(b, "<(null)>");

    // Format tak dikenal dicetak apa adanya, tidak mengambil argumen:
    // argumen berikutnya tetap milik %d.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"
#endif
    r = ksnprintf(b, sizeof(b), "%q %d %", 5);
#pragma GCC diagnostic pop
    CHECK_STR(b, "%q 5 %");
    CHECK(r == 6);
    // Lebar tanpa nol tidak didukung: dicetak apa adanya, argumen tidak diambil.
    // Lebar > 20 dipotong ke 20 digit; digit ketiga dst. jadi format tak dikenal.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wformat-insufficient-args"
#endif
    r = ksnprintf(b, sizeof(b), "%5d|%d", 9);
    CHECK_STR(b, "%5d|9");
    ksnprintf(b, sizeof(b), "%025u", 1u);
    CHECK_STR(b, "00000000000000000001");
    ksnprintf(b, sizeof(b), "%0999u|%u", 3u);
    CHECK_STR(b, "%0999u|3");
#pragma GCC diagnostic pop

    // size 0: tidak menulis apa pun (buffer boleh NULL), panjang penuh dikembalikan.
    CHECK(ksnprintf(NULL, 0, "%d", 12345) == 5);
    memset(b, 'Z', sizeof(b));
    CHECK(ksnprintf(b, 0, "abc") == 3);
    CHECK(b[0] == 'Z');
}

// kprintf menulis lewat serial_putc (ditangkap stub).
static void test_kprintf_serial(void)
{
    serial_capture_reset();
    kprintf("x=%d y=%s\r\n", -3, "ok");
    CHECK_STR(g_serial_cap, "x=-3 y=ok\r\n");

    serial_capture_reset();
    kprintf_selftest();
    CHECK_STR(g_serial_cap, "kprintf: self-test PASS (12 kasus)\r\n");
}

int main(void)
{
    test_ints();
    test_width();
    test_strs();
    test_special();
    test_kprintf_serial();
    return test_done("kprintf");
}

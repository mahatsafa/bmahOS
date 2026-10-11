#include <stdarg.h>
#include "kernel.h"

// F1.6: kprintf/ksnprintf minimal + ASSERT. Format yang didukung:
// %s %c %d %u %x %p %%, dengan awalan panjang 'l' (64-bit) untuk d/u/x.
// Tanpa lebar/presisi/flag. Format tak dikenal dicetak apa adanya dan
// TIDAK mengambil argumen (supaya va_list tidak bergeser).

typedef void (*kfmt_put_fn)(char c, void *ctx);

static void kfmt_putu(kfmt_put_fn put, void *ctx, uint64_t v, unsigned base, int min_digits)
{
    static const char digits[] = "0123456789abcdef";
    char tmp[20];   // 2^64-1 = 20 digit desimal
    int n = 0;

    do {
        tmp[n++] = digits[v % base];
        v /= base;
    } while (v != 0);

    while (n < min_digits && n < (int)sizeof(tmp)) {
        tmp[n++] = '0';
    }

    while (n > 0) {
        put(tmp[--n], ctx);
    }
}

static void kfmt(kfmt_put_fn put, void *ctx, const char *fmt, va_list ap)
{
    while (*fmt) {
        if (*fmt != '%') {
            put(*fmt++, ctx);
            continue;
        }

        const char *spec_start = fmt;
        fmt++;

        int is_long = 0;
        if (*fmt == 'l') {
            is_long = 1;
            fmt++;
        }

        switch (*fmt) {
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (s == NULL) {
                s = "(null)";
            }
            while (*s) {
                put(*s++, ctx);
            }
            break;
        }
        case 'c':
            put((char)va_arg(ap, int), ctx);
            break;
        case 'd': {
            int64_t v = is_long ? va_arg(ap, int64_t) : (int64_t)va_arg(ap, int);
            uint64_t mag = (uint64_t)v;
            if (v < 0) {
                put('-', ctx);
                mag = (uint64_t)0 - mag;   // aman juga untuk INT64_MIN
            }
            kfmt_putu(put, ctx, mag, 10, 1);
            break;
        }
        case 'u':
            kfmt_putu(put, ctx, is_long ? va_arg(ap, uint64_t) : (uint64_t)va_arg(ap, unsigned int), 10, 1);
            break;
        case 'x':
            kfmt_putu(put, ctx, is_long ? va_arg(ap, uint64_t) : (uint64_t)va_arg(ap, unsigned int), 16, 1);
            break;
        case 'p':
            put('0', ctx);
            put('x', ctx);
            kfmt_putu(put, ctx, (uint64_t)(uintptr_t)va_arg(ap, void *), 16, 16);
            break;
        case '%':
            put('%', ctx);
            break;
        default:
            // Tak dikenal (atau '%' di akhir string): cetak apa adanya.
            while (spec_start < fmt) {
                put(*spec_start++, ctx);
            }
            if (*fmt == '\0') {
                return;
            }
            put(*fmt, ctx);
            break;
        }
        fmt++;
    }
}

static void put_serial(char c, void *ctx)
{
    (void)ctx;
    serial_putc(c);
}

void kprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    // Satu lock untuk seluruh baris supaya tidak disisipi task lain.
    uint64_t flags = irq_save();
    kfmt(put_serial, NULL, fmt, ap);
    irq_restore(flags);
    va_end(ap);
}

struct kbuf {
    char *buf;
    size_t size;
    size_t len;   // panjang penuh (termasuk yang terpotong)
};

static void put_buf(char c, void *ctx)
{
    struct kbuf *b = ctx;
    if (b->size > 0 && b->len < b->size - 1) {
        b->buf[b->len] = c;
    }
    b->len++;
}

// Semantik snprintf: selalu diakhiri NUL bila size > 0; mengembalikan panjang
// yang akan ditulis tanpa batas (>= size berarti terpotong).
size_t ksnprintf(char *buf, size_t size, const char *fmt, ...)
{
    struct kbuf b = { buf, size, 0 };
    va_list ap;
    va_start(ap, fmt);
    kfmt(put_buf, &b, fmt, ap);
    va_end(ap);
    if (size > 0) {
        buf[b.len < size ? b.len : size - 1] = '\0';
    }
    return b.len;
}

#define KASSERT_FMT "PANIC: ASSERT gagal: %s di %s:%d (%s)\r\n"

void kassert_fail(const char *expr, const char *file, int line, const char *func)
{
    __asm__ volatile("cli");
    g_serial_mute = 0;   // pesan ini wajib sampai ke UART
    kprintf(KASSERT_FMT, expr, file, line, func);
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}

static int kstr_eq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static int kprintf_check(int id, const char *got, size_t ret, const char *want, size_t want_ret)
{
    if (kstr_eq(got, want) && ret == want_ret) {
        return 1;
    }
    kprintf("kprintf: self-test FAIL kasus %d: dapat \"%s\" (%lu), harap \"%s\" (%lu)\r\n",
            id, got, (uint64_t)ret, want, (uint64_t)want_ret);
    return 0;
}

void kprintf_selftest(void)
{
    char b[96];
    int ok = 1;
    size_t r;

    r = ksnprintf(b, sizeof(b), "%d|%d|%d", 0, -42, 2147483647);
    ok &= kprintf_check(1, b, r, "0|-42|2147483647", 16);
    r = ksnprintf(b, sizeof(b), "%d", (int)(-2147483647 - 1));
    ok &= kprintf_check(2, b, r, "-2147483648", 11);
    r = ksnprintf(b, sizeof(b), "%u|%x", 4000000000u, 0xBEEFu);
    ok &= kprintf_check(3, b, r, "4000000000|beef", 15);
    r = ksnprintf(b, sizeof(b), "%lu", (uint64_t)18446744073709551615ULL);
    ok &= kprintf_check(4, b, r, "18446744073709551615", 20);
    r = ksnprintf(b, sizeof(b), "%ld", (int64_t)(-9223372036854775807LL - 1));
    ok &= kprintf_check(5, b, r, "-9223372036854775808", 20);
    r = ksnprintf(b, sizeof(b), "%lx", (uint64_t)0xFFFF980000000000ULL);
    ok &= kprintf_check(6, b, r, "ffff980000000000", 16);
    r = ksnprintf(b, sizeof(b), "%p", (void *)0x1234);
    ok &= kprintf_check(7, b, r, "0x0000000000001234", 18);
    const char *volatile nul = NULL;   // volatile: compiler tidak tahu nilainya NULL
    r = ksnprintf(b, sizeof(b), "[%s][%s]", "ab", nul);
    ok &= kprintf_check(8, b, r, "[ab][(null)]", 12);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"
    r = ksnprintf(b, sizeof(b), "%c%%%q%", 'A');   // sengaja: format tak dikenal
#pragma GCC diagnostic pop
    ok &= kprintf_check(9, b, r, "A%%q%", 5);
    r = ksnprintf(b, 5, "abc%sgh", "def");
    ok &= kprintf_check(10, b, r, "abcd", 8);
    r = ksnprintf(b, 1, "xyz");
    ok &= kprintf_check(11, b, r, "", 3);
    r = ksnprintf(b, sizeof(b), KASSERT_FMT, "x == 1", "kernel/a.c", 42, "f");
    ok &= kprintf_check(12, b, r, "PANIC: ASSERT gagal: x == 1 di kernel/a.c:42 (f)\r\n", 50);

    kprintf(ok ? "kprintf: self-test PASS (12 kasus)\r\n" : "kprintf: self-test FAIL\r\n");
}

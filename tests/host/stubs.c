// F1.7: stub simbol kernel untuk uji di host. Semua weak: kalau file uji
// menyertakan modul yang mendefinisikan simbol yang sama, definisi modul menang.
// serial_putc/serial_write ditangkap ke g_serial_cap supaya bisa diperiksa.

#include <stdlib.h>
#include "kernel.h"
#include "test.h"

#define WEAK __attribute__((weak))

int g_test_pass = 0;
int g_test_fail = 0;

char g_serial_cap[65536];
size_t g_serial_cap_len = 0;

void serial_capture_reset(void)
{
    g_serial_cap_len = 0;
    g_serial_cap[0] = '\0';
}

WEAK volatile int g_serial_mute = 0;
WEAK volatile uint64_t timer_ticks = 0;

WEAK void serial_putc(char c)
{
    if (g_serial_cap_len < sizeof(g_serial_cap) - 1) {
        g_serial_cap[g_serial_cap_len++] = c;
        g_serial_cap[g_serial_cap_len] = '\0';
    }
}

WEAK void serial_write(const char *s)
{
    while (*s) {
        serial_putc(*s++);
    }
}

WEAK void serial_write_hex(uint64_t value)
{
    static const char hx[] = "0123456789ABCDEF";
    serial_write("0x");
    for (int i = 60; i >= 0; i -= 4) {
        serial_putc(hx[(value >> i) & 0xF]);
    }
}

int test_done(const char *name)
{
    printf("%-12s %d lulus, %d gagal\n", name, g_test_pass, g_test_fail);
    return g_test_fail == 0 ? 0 : 1;
}

size_t test_unhex(const char *hex, unsigned char *out, size_t max)
{
    size_t n = strlen(hex) / 2;
    if (n > max) {
        abort();
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

int test_hex_eq(const unsigned char *buf, size_t len, const char *hex)
{
    static const char hx[] = "0123456789abcdef";
    if (strlen(hex) != len * 2) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (hex[i * 2] != hx[buf[i] >> 4] || hex[i * 2 + 1] != hx[buf[i] & 0xF]) {
            return 0;
        }
    }
    return 1;
}

// P1: uji fbcon.c di host (di-#include: akses fungsi static). Framebuffer
// tiruan di heap dengan ukuran persis pitch x tinggi, jadi tulisan di luar
// batas tertangkap ASan; pitch sengaja lebih lebar dari lebar x byte/piksel.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/fbcon.c"

static uint8_t *g_fb;
static uint64_t g_pitch, g_h;

static fbcon_t mk(uint64_t w, uint64_t h, uint64_t pitch, uint16_t bpp,
                  uint8_t rsh, uint8_t gsh, uint8_t bsh, uint8_t sz)
{
    fbcon_t f;

    free(g_fb);
    g_fb = malloc(pitch * h);
    memset(g_fb, 0xEE, pitch * h);   // isi sampah: harus terhapus/tertimpa
    g_pitch = pitch;
    g_h = h;
    CHECK(fbcon_setup(&f, g_fb, w, h, pitch, bpp, sz, rsh, sz, gsh, sz, bsh) == 0);
    fb_clear_rows(&f, 0, f.rows);
    return f;
}

static uint32_t px(const fbcon_t *f, uint64_t x, uint64_t y)
{
    const uint8_t *p = g_fb + y * g_pitch + x * f->bypp;

    if (f->bypp == 4) {
        return *(const uint32_t *)p;
    }
    if (f->bypp == 2) {
        return *(const uint16_t *)p;
    }
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16;
}

// Sel (cx, cy) sama persis dengan glyph c (fg/0).
static int cell_is(const fbcon_t *f, uint32_t cx, uint32_t cy, char c)
{
    const uint8_t *gl = g_fbfont[(uint8_t)c - FBFONT_FIRST];

    for (uint32_t y = 0; y < 16; y++) {
        for (uint32_t x = 0; x < 8; x++) {
            uint32_t want = (gl[y] & (0x80 >> x)) ? f->fg : 0;
            if (px(f, cx * 8 + x, cy * 16 + y) != want) {
                return 0;
            }
        }
    }
    return 1;
}

static void puts_on(fbcon_t *f, const char *s)
{
    while (*s) {
        fbcon_putc_on(f, *s++);
    }
}

static void test_setup_reject(void)
{
    fbcon_t f;
    uint8_t buf[64];

    CHECK(fbcon_setup(&f, 0, 640, 480, 2560, 32, 8, 16, 8, 8, 8, 0) == -1);
    CHECK(f.active == 0);
    CHECK(fbcon_setup(&f, buf, 640, 480, 2560, 8, 8, 16, 8, 8, 8, 0) == -1);   // bpp 8
    CHECK(fbcon_setup(&f, buf, 640, 480, 2556, 32, 8, 16, 8, 8, 8, 0) == -1);  // pitch kecil
    CHECK(fbcon_setup(&f, buf, 640, 480, 2560, 32, 9, 16, 8, 8, 8, 0) == -1);  // mask 9 bit
    CHECK(fbcon_setup(&f, buf, 640, 480, 2560, 32, 8, 28, 8, 8, 8, 0) == -1);  // shift lewat bpp
    CHECK(fbcon_setup(&f, buf, 4, 480, 2560, 32, 8, 16, 8, 8, 8, 0) == -1);    // < 1 kolom
    fbcon_putc_on(&f, 'A');   // nonaktif: no-op, tidak menyentuh buf
    CHECK(fbcon_setup(&f, buf, 640, 480, 2560, 32, 8, 16, 8, 8, 8, 0) == 0);
    CHECK(f.cols == 80 && f.rows == 30 && f.bypp == 4);
}

static void test_colors(void)
{
    // xRGB 8:8:8 (r@16), BGR (r@0), RGB565 16 bpp, 24 bpp.
    fbcon_t f = mk(64, 32, 64 * 4 + 24, 32, 16, 8, 0, 8);
    CHECK(f.fg == 0x00C0C0C0);
    f = mk(64, 32, 64 * 4, 32, 0, 8, 16, 8);
    CHECK(f.fg == 0x00C0C0C0);
    fbcon_setup(&f, g_fb, 64, 32, 64 * 2, 16, 5, 11, 6, 5, 5, 0);
    CHECK(f.fg == ((0x18u << 11) | (0x30u << 5) | 0x18u));
    f = mk(64, 32, 64 * 3 + 8, 24, 16, 8, 0, 8);
    CHECK(f.bypp == 3);
    puts_on(&f, "Hi");
    CHECK(cell_is(&f, 0, 0, 'H') && cell_is(&f, 1, 0, 'i'));
}

static void test_text_pitch(void)
{
    // 10 kolom x 4 baris, pitch 40 byte lebih lebar: area di luar lebar
    // (kolom pad) tidak boleh disentuh selain oleh fb_clear_rows (tidak juga).
    fbcon_t f = mk(80, 64, 80 * 4 + 40, 32, 16, 8, 0, 8);

    CHECK(f.cols == 10 && f.rows == 4);
    puts_on(&f, "AB\r\nC\tD~\x01");
    CHECK(cell_is(&f, 0, 0, 'A') && cell_is(&f, 1, 0, 'B'));
    CHECK(cell_is(&f, 0, 1, 'C'));
    CHECK(cell_is(&f, 8, 1, 'D'));          // tab ke kolom 8
    CHECK(cell_is(&f, 9, 1, '~'));
    CHECK(cell_is(&f, 0, 2, '?'));          // bungkus baris, kontrol -> '?'
    CHECK(f.row == 2 && f.col == 1);
    for (uint64_t y = 0; y < g_h; y++) {    // bantalan pitch utuh (0xEE)
        CHECK(g_fb[y * g_pitch + 80 * 4] == 0xEE && g_fb[y * g_pitch + g_pitch - 1] == 0xEE);
    }
}

static void test_scroll(void)
{
    // 4 kolom x 6 baris: baris 0..5 berisi '0'..'5', lalu satu newline lagi
    // -> setengah layar (3 baris) naik: '3','4','5' di baris 0..2, sisanya kosong.
    fbcon_t f = mk(32, 96, 32 * 4 + 16, 32, 16, 8, 0, 8);

    CHECK(f.rows == 6);
    for (char c = '0'; c <= '5'; c++) {
        fbcon_putc_on(&f, c);
        if (c != '5') {
            fbcon_putc_on(&f, '\n');
        }
    }
    CHECK(f.scrolls == 0 && f.row == 5);
    fbcon_putc_on(&f, '\n');
    CHECK(f.scrolls == 1 && f.row == 3 && f.col == 0);
    CHECK(cell_is(&f, 0, 0, '3') && cell_is(&f, 0, 1, '4') && cell_is(&f, 0, 2, '5'));
    CHECK(cell_is(&f, 0, 3, ' ') && cell_is(&f, 0, 5, ' '));
    fbcon_putc_on(&f, 'Z');
    CHECK(cell_is(&f, 0, 3, 'Z'));
    // Ribuan baris: tetap di dalam batas (ASan), gulir berulang.
    for (int i = 0; i < 5000; i++) {
        puts_on(&f, "abcdefg\n");
    }
    CHECK(f.row < f.rows && f.scrolls > 1000);

    // Satu baris saja: gulir "setengah" = 1 baris, tetap aman.
    f = mk(16, 16, 16 * 4, 32, 16, 8, 0, 8);
    CHECK(f.rows == 1);
    puts_on(&f, "ab\ncd");
    CHECK(f.row == 0 && cell_is(&f, 0, 0, 'c') && cell_is(&f, 1, 0, 'd'));
}

int main(void)
{
    test_setup_reject();
    test_colors();
    test_text_pitch();
    test_scroll();
    free(g_fb);
    return test_done("fbcon");
}

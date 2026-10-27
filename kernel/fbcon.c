#ifndef BMAHOS_HOST_TEST
#include <limine.h>
#endif
#include "kernel.h"
#include "fbfont.h"

// P1: konsol framebuffer. Semua keluaran yang sampai ke UART (serial_putc,
// jadi juga kprintf dan dump panic) dicerminkan ke layar dengan font 8x16.
// Alamat baris = base + y * pitch (pitch bisa lebih besar dari lebar x
// byte/piksel); warna disusun dari mask/shift yang dilaporkan Limine.
// Gulir setengah layar sekaligus: gulir per baris menyalin seluruh
// framebuffer tiap baris (beberapa MB), terlalu mahal di QEMU TCG.
// Dipanggil dengan interrupt mati (serial_putc), jadi tanpa kunci sendiri.

#define FB_GW 8
#define FB_GH 16

static uint32_t fb_pack(const fbcon_t *f, uint8_t r, uint8_t g, uint8_t b)
{
    uint32_t v = 0;

    v |= (uint32_t)(r >> (8 - f->rsz)) << f->rsh;
    v |= (uint32_t)(g >> (8 - f->gsz)) << f->gsh;
    v |= (uint32_t)(b >> (8 - f->bsz)) << f->bsh;
    return v;
}

int fbcon_setup(fbcon_t *f, uint8_t *base, uint64_t w, uint64_t h, uint64_t pitch,
                uint16_t bpp, uint8_t rsz, uint8_t rsh, uint8_t gsz, uint8_t gsh,
                uint8_t bsz, uint8_t bsh)
{
    memset(f, 0, sizeof(*f));
    if (base == 0 || (bpp != 16 && bpp != 24 && bpp != 32)) {
        return -1;
    }
    if (rsz == 0 || rsz > 8 || gsz == 0 || gsz > 8 || bsz == 0 || bsz > 8 ||
        rsh + rsz > bpp || gsh + gsz > bpp || bsh + bsz > bpp) {
        return -1;
    }
    if (w < FB_GW || h < FB_GH || pitch < w * (bpp / 8)) {
        return -1;
    }
    f->base = base;
    f->w = w;
    f->h = h;
    f->pitch = pitch;
    f->bypp = bpp / 8;
    f->rsz = rsz; f->rsh = rsh;
    f->gsz = gsz; f->gsh = gsh;
    f->bsz = bsz; f->bsh = bsh;
    f->cols = (uint32_t)(w / FB_GW);
    f->rows = (uint32_t)(h / FB_GH);
    f->fg = fb_pack(f, 0xC0, 0xC0, 0xC0);   // abu-abu terang di atas hitam (0)
    f->active = 1;
    return 0;
}

static void fb_pixel(const fbcon_t *f, uint8_t *p, uint32_t v)
{
    if (f->bypp == 4) {
        *(volatile uint32_t *)p = v;
    } else if (f->bypp == 2) {
        *(volatile uint16_t *)p = (uint16_t)v;
    } else {
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
    }
}

// Satu sel teks (kolom cx, baris cy); karakter di luar font -> '?'.
static void fb_glyph(const fbcon_t *f, uint32_t cx, uint32_t cy, char c)
{
    uint8_t ch = (uint8_t)c;

    if (ch < FBFONT_FIRST || ch > FBFONT_LAST) {
        ch = '?';
    }
    const uint8_t *gl = g_fbfont[ch - FBFONT_FIRST];

    for (uint32_t y = 0; y < FB_GH; y++) {
        uint8_t *row = f->base + (uint64_t)(cy * FB_GH + y) * f->pitch
                       + (uint64_t)cx * FB_GW * f->bypp;
        for (uint32_t x = 0; x < FB_GW; x++) {
            fb_pixel(f, row + x * f->bypp, (gl[y] & (0x80 >> x)) ? f->fg : 0);
        }
    }
}

// Baris teks [from, to) jadi hitam (latar 0 untuk semua mask).
static void fb_clear_rows(const fbcon_t *f, uint32_t from, uint32_t to)
{
    for (uint64_t y = (uint64_t)from * FB_GH; y < (uint64_t)to * FB_GH; y++) {
        memset(f->base + y * f->pitch, 0, f->w * f->bypp);
    }
}

// Separuh bawah layar naik ke atas, sisanya dikosongkan; salinan 64-bit
// maju (tujuan di bawah sumber, jadi aman tanpa memmove).
static void fb_scroll_half(fbcon_t *f)
{
    uint32_t shift = f->rows / 2;
    uint32_t keep;

    if (shift == 0) {
        shift = 1;
    }
    keep = f->rows - shift;
    uint64_t n = (uint64_t)keep * FB_GH * f->pitch;
    uint8_t *dst = f->base;
    uint8_t *src = f->base + (uint64_t)shift * FB_GH * f->pitch;
    uint64_t i = 0;

    if ((((uintptr_t)dst | (uintptr_t)src) & 7) == 0) {
        for (; i + 8 <= n; i += 8) {
            *(volatile uint64_t *)(dst + i) = *(volatile uint64_t *)(src + i);
        }
    }
    for (; i < n; i++) {
        dst[i] = src[i];
    }
    fb_clear_rows(f, keep, f->rows);
    f->row = keep;
    f->scrolls++;
}

static void fb_newline(fbcon_t *f)
{
    f->col = 0;
    f->row++;
    if (f->row >= f->rows) {
        fb_scroll_half(f);
    }
}

void fbcon_putc_on(fbcon_t *f, char c)
{
    if (!f->active) {
        return;
    }
    if (c == '\n') {
        fb_newline(f);
        return;
    }
    if (c == '\r') {
        f->col = 0;
        return;
    }
    if (c == '\t') {
        do {
            fbcon_putc_on(f, ' ');
        } while (f->col % 8 != 0);
        return;
    }
    if (f->col >= f->cols) {
        fb_newline(f);
    }
    fb_glyph(f, f->col, f->row, c);
    f->col++;
    f->chars++;
}

#ifndef BMAHOS_HOST_TEST
__attribute__((used, section(".limine_requests")))
static volatile struct limine_framebuffer_request fb_request = {
    .id = LIMINE_FRAMEBUFFER_REQUEST_ID,
};

static fbcon_t g_fbcon;

void fbcon_init(void)
{
    struct limine_framebuffer_response *r = fb_request.response;

    if (r == 0 || r->framebuffer_count == 0) {
        kprintf("P1: fbcon nonaktif (tanpa framebuffer)\r\n");
        return;
    }
    struct limine_framebuffer *fb = r->framebuffers[0];

    if (fb->memory_model != LIMINE_FRAMEBUFFER_RGB ||
        fbcon_setup(&g_fbcon, (uint8_t *)fb->address, fb->width, fb->height,
                    fb->pitch, fb->bpp, fb->red_mask_size, fb->red_mask_shift,
                    fb->green_mask_size, fb->green_mask_shift,
                    fb->blue_mask_size, fb->blue_mask_shift) != 0) {
        kprintf("P1: fbcon nonaktif (mode tidak didukung %lux%lu bpp=%u model=%u)\r\n",
                fb->width, fb->height, (unsigned)fb->bpp, (unsigned)fb->memory_model);
        return;
    }
    fb_clear_rows(&g_fbcon, 0, g_fbcon.rows);
    kprintf("P1: fbcon aktif %lux%lu bpp=%u pitch=%lu teks %ux%u "
            "mask r=%u@%u g=%u@%u b=%u@%u\r\n",
            fb->width, fb->height, (unsigned)fb->bpp, fb->pitch,
            g_fbcon.cols, g_fbcon.rows,
            (unsigned)fb->red_mask_size, (unsigned)fb->red_mask_shift,
            (unsigned)fb->green_mask_size, (unsigned)fb->green_mask_shift,
            (unsigned)fb->blue_mask_size, (unsigned)fb->blue_mask_shift);
}

void fbcon_putc(char c)
{
    fbcon_putc_on(&g_fbcon, c);
}

const fbcon_t *fbcon_state(void)
{
    return &g_fbcon;
}
#endif

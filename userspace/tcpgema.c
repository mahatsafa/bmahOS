// P5-2: server gema TCP di port 5556 (build dev, ditanam di kernel). Uji
// P5-4: sumber yang sama dibangun ulang sebagai appgema (PORT 5558, NAMA
// "appgema"), tidak ditanam: isi APP.BIN uji yang dimuat dari disk. Sisa
// komentar ini memakai nilai bawaan (tcpgema, 5556).
// ----
// penolakan dulu (listen sebelum bind, port sistem, recv di soket listen,
// accept timeout), lalu satu koneksi dilayani sampai peer menutup; koneksi
// berikutnya menunggu di antrean listen. Data diawali "keluar" = tutup + exit.

#include "bm.h"

#ifndef PORT
#define PORT 5556
#endif
#ifndef NAMA
#define NAMA "tcpgema"
#endif
#define STR_(x) #x
#define STR(x) STR_(x)
#define PFX "P5: " NAMA " "

static bm_u64 slen(const char *s)
{
    bm_u64 n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

static void tulis(const char *s)
{
    bm_write(s, slen(s));
}

// "<teks> <angka bertanda>\n" dalam satu SYS_WRITE (baris tidak terpecah).
static void tulis_angka(const char *s, bm_i64 v)
{
    char b[96];
    char t[24];
    bm_u64 n = 0, k = 0;
    bm_u64 u = v < 0 ? (bm_u64)-v : (bm_u64)v;

    while (s[n] && n < 64) {
        b[n] = s[n];
        n++;
    }
    if (v < 0) {
        b[n++] = '-';
    }
    do {
        t[k++] = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    while (k) {
        b[n++] = t[--k];
    }
    b[n++] = '\n';
    bm_write(b, n);
}

static int awalan_keluar(const char *b, bm_i64 n)
{
    const char *k = "keluar";

    for (int i = 0; i < 6; i++) {
        if (i >= n || b[i] != k[i]) {
            return 0;
        }
    }
    return 1;
}

// Gema satu koneksi. Return 1 bila diminta keluar.
static int layani(bm_i64 c, char *buf)
{
    bm_u64 total = 0;

    for (;;) {
        bm_i64 n = bm_recv(c, buf, BM_TCP_RING, 0);

        if (n == 0) {
            tulis_angka(PFX "recv 0 (FIN), total ", (bm_i64)total);
            return 0;
        }
        if (n < 0) {
            tulis_angka(PFX "recv -> ", n);
            return 0;
        }
        if (total == 0 && awalan_keluar(buf, n)) {
            return 1;
        }
        total += (bm_u64)n;
        for (bm_i64 off = 0; off < n;) {
            bm_i64 r = bm_send(c, buf + off, (bm_u64)(n - off), 0);

            if (r < 0) {
                tulis_angka(PFX "send -> ", r);
                return 0;
            }
            off += r;
        }
    }
}

__attribute__((section(".text.start"), noreturn)) void _start(void)
{
    char buf[BM_TCP_RING];
    bm_i64 fd = bm_socket(BM_SOCK_TCP);

    if (fd < 0) {
        tulis_angka(PFX "socket gagal ", fd);
        bm_exit();
    }
    tulis_angka(PFX "listen tanpa bind -> ", bm_listen(fd));
    tulis_angka(PFX "bind 7779 -> ", bm_bind(fd, 7779));
    bm_i64 r = bm_bind(fd, PORT);
    if (r != 0) {
        tulis_angka(PFX "bind " STR(PORT) " gagal ", r);
        bm_exit();
    }
    tulis_angka(PFX "recv soket listen -> ", bm_recv(fd, buf, 16, 1));
    r = bm_listen(fd);
    if (r != 0) {
        tulis_angka(PFX "listen gagal ", r);
        bm_exit();
    }
    tulis_angka(PFX "accept timeout 10 -> ", bm_accept(fd, 0, 10));
    tulis(PFX "siap port " STR(PORT) "\n");

    for (;;) {
        bm_u64 from = 0;
        bm_i64 c = bm_accept(fd, &from, 0);

        if (c < 0) {
            tulis_angka(PFX "accept gagal ", c);
            break;
        }
        tulis_angka(PFX "accept fd ", c);
        int keluar = layani(c, buf);

        tulis_angka(PFX "close -> ", bm_close(c));
        if (keluar) {
            break;
        }
    }
    tulis_angka(PFX "close listen -> ", bm_close(fd));
    tulis(PFX "selesai\n");
    bm_exit();
}

// P5-1: program user pertama yang memakai soket (build dev, ditanam di kernel).
// Uji penolakan dulu (bind port sistem, kirim ke alamat tanpa ARP), lalu gema
// UDP di port 5555 dengan awalan "gema: ". Datagram "keluar" = tutup + exit.

#include "bm.h"

#define PORT 5555
#define PFX  6   // panjang "gema: "

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

__attribute__((section(".text.start"), noreturn)) void _start(void)
{
    char buf[PFX + BM_DGRAM_MAX - PFX];
    bm_u64 from = 0;
    bm_i64 fd = bm_socket(BM_SOCK_UDP);

    if (fd < 0) {
        tulis_angka("P5: udpgema socket gagal ", fd);
        bm_exit();
    }
    tulis_angka("P5: udpgema bind 7778 -> ", bm_bind(fd, 7778));
    bm_i64 r = bm_bind(fd, PORT);
    if (r != 0) {
        tulis_angka("P5: udpgema bind 5555 gagal ", r);
        bm_exit();
    }
    // -100 = jaringan belum siap (mis. DHCP belum terikat): coba lagi tiap 0,1 s, maks 30 s.
    for (int i = 0; i < 300; i++) {
        r = bm_sendto(fd, "uji", 3, BM_ADDR(192, 168, 50, 77, 9));
        if (r != BM_ENETDOWN) {
            break;
        }
        bm_recvfrom(fd, buf, 16, 0, 10);
    }
    tulis_angka("P5: udpgema sendto 192.168.50.77 -> ", r);
    tulis_angka("P5: udpgema recvfrom timeout 10 -> ", bm_recvfrom(fd, buf, 16, 0, 10));
    tulis("P5: udpgema siap port 5555\n");

    buf[0] = 'g';
    buf[1] = 'e';
    buf[2] = 'm';
    buf[3] = 'a';
    buf[4] = ':';
    buf[5] = ' ';
    for (;;) {
        bm_i64 n = bm_recvfrom(fd, buf + PFX, sizeof(buf) - PFX, &from, 0);

        if (n < 0) {
            tulis_angka("P5: udpgema recvfrom gagal ", n);
            break;
        }
        if (n == 6 && buf[PFX] == 'k' && buf[PFX + 1] == 'e' && buf[PFX + 2] == 'l' &&
            buf[PFX + 3] == 'u' && buf[PFX + 4] == 'a' && buf[PFX + 5] == 'r') {
            break;
        }
        r = bm_sendto(fd, buf, (bm_u64)n + PFX, from);
        if (r < 0) {
            tulis_angka("P5: udpgema sendto gagal ", r);
        }
    }
    tulis_angka("P5: udpgema close -> ", bm_close(fd));
    tulis("P5: udpgema selesai\n");
    bm_exit();
}

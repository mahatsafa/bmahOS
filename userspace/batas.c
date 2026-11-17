// F7 (build dev, ditanam di kernel): program uji batas sumber daya per task user.
// Sengaja melanggar tiga batas lalu terus membanjiri syscall sampai dihentikan kernel:
//   1. soket: buka sampai jatah per task habis (kernel menurunkannya ke 1 untuk task ini: tabel
//      global hanya menyisakan 1 slot) -> socket() ke-2 = -122 (SOCK_EDQUOT), lalu semua
//      ditutup supaya tabel soket global tidak tertahan;
//   2. tulis: 6 x SYS_WRITE 1024 byte -> jatah 4096 byte per jendela habis, sisanya -122;
//   3. syscall: SYS_CLOSE fd tak sah + SYS_WRITE pointer kernel (ditolak) tanpa henti -> lewat
//      500 per jendela = -122; baris log "DITOLAK" terbatas per jendela; setelah 5 jendela
//      beruntun melanggar kernel menghentikan task ini.
// Hasil diperiksa dari log kernel ("RES: ...") dan metrics res_*, bukan dari program ini.

#include "bm.h"

static void tulis_angka(const char *s, bm_i64 v)
{
    char b[64];
    char t[24];
    bm_u64 n = 0, k = 0;
    bm_u64 u = v < 0 ? (bm_u64)-v : (bm_u64)v;

    while (s[n] && n < 40) {
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
    bm_i64 fd[2];
    char buf[1024];

    fd[0] = bm_socket_ulang(BM_SOCK_UDP);
    fd[1] = bm_socket(BM_SOCK_UDP);
    tulis_angka("batas: socket ke-2 kode=", fd[1]);
    for (int i = 0; i < 2; i++) {
        if (fd[i] >= 0) {
            bm_close(fd[i]);
        }
    }

    for (int i = 0; i < 1023; i++) {
        buf[i] = '~';
    }
    buf[1023] = '\n';
    for (int i = 0; i < 6; i++) {
        bm_write(buf, sizeof(buf));
    }

    for (;;) {
        bm_write((const void *)0xFFFFFFFF80100000UL, 8);   // pointer kernel: ditolak, log terbatas
        bm_close(63);
    }
}

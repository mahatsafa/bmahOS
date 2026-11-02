// P5-3: klien TCP (build dev, ditanam di kernel). Uji penolakan connect saat
// boot, lalu menunggu perintah lewat UDP port 5557; balasan dikirim ke
// pengirim perintah:
//   konek <port> [oktet]  connect ke pengirim (atau a.b.c.<oktet>):<port>, kirim
//                         "halo dari tcpklien\n", baca satu baris -> "ok <baris>"
//   gema <port> [oktet]   kirim 3000 byte pola, baca 3000 byte kembali -> "ok gema 3000 cocok|beda"
//   batas <port> <oktet> <tick>  connect dengan timeout -> "galat <kode>" / "ok batas"
//   keluar                tutup soket, exit
// Gagal: "galat <kode>" (kode galat syscall).

#include "bm.h"

#define PORT 5557
#define BESAR 3000

static bm_u64 slen(const char *s)
{
    bm_u64 n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

// "<teks><angka bertanda>" di b, return panjang.
static bm_u64 fmt_angka(char *b, const char *s, bm_i64 v)
{
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
    return n;
}

static void tulis(const char *s)
{
    bm_write(s, slen(s));
}

static void tulis_angka(const char *s, bm_i64 v)
{
    char b[96];
    bm_u64 n = fmt_angka(b, s, v);

    b[n++] = '\n';
    bm_write(b, n);
}

static void balas(bm_i64 u, bm_u64 to, const char *b, bm_u64 n)
{
    bm_sendto(u, b, n, to);
}

static void balas_galat(bm_i64 u, bm_u64 to, bm_i64 e)
{
    char b[48];

    balas(u, to, b, fmt_angka(b, "galat ", e));
}

// Angka desimal mulai b[*i] (spasi dilewati). -1 bila tidak ada.
static bm_i64 baca_angka(const char *b, bm_i64 n, bm_i64 *i)
{
    bm_i64 v = -1;

    while (*i < n && b[*i] == ' ') {
        (*i)++;
    }
    while (*i < n && b[*i] >= '0' && b[*i] <= '9' && v < 100000) {
        v = (v < 0 ? 0 : v * 10) + (b[*i] - '0');
        (*i)++;
    }
    return v;
}

static int awalan(const char *b, bm_i64 n, const char *k)
{
    bm_i64 i = 0;

    for (; k[i]; i++) {
        if (i >= n || b[i] != k[i]) {
            return 0;
        }
    }
    return 1;
}

static unsigned char pola(bm_u64 i)
{
    return (unsigned char)(i * 7 + 3);
}

// Kirim semua (send bisa menerima sebagian). Return 0 atau kode galat.
static bm_i64 kirim_semua(bm_i64 c, const char *b, bm_u64 n)
{
    for (bm_u64 off = 0; off < n;) {
        bm_i64 r = bm_send(c, b + off, n - off, 1000);

        if (r < 0) {
            return r;
        }
        off += (bm_u64)r;
    }
    return 0;
}

static void konek(bm_i64 u, bm_u64 from, bm_u64 tujuan, char *buf)
{
    bm_i64 c = bm_socket(BM_SOCK_TCP);
    bm_i64 r;

    if (c < 0) {
        balas_galat(u, from, c);
        return;
    }
    r = bm_connect(c, tujuan, 0);
    if (r != 0) {
        balas_galat(u, from, r);
        bm_close(c);
        return;
    }
    const char *halo = "halo dari tcpklien\n";

    r = kirim_semua(c, halo, slen(halo));
    bm_u64 n = 3;

    buf[0] = 'o';
    buf[1] = 'k';
    buf[2] = ' ';
    while (r == 0 && n < 200) {
        bm_i64 k = bm_recv(c, buf + n, 200 - n, 500);

        if (k <= 0) {
            r = k == 0 ? 0 : k;
            break;
        }
        n += (bm_u64)k;
        if (buf[n - 1] == '\n') {
            n--;
            break;
        }
    }
    if (r < 0) {
        balas_galat(u, from, r);
    } else {
        balas(u, from, buf, n);
    }
    tulis_angka("P5: tcpklien konek close -> ", bm_close(c));
}

static void gema(bm_i64 u, bm_u64 from, bm_u64 tujuan, char *buf)
{
    bm_i64 c = bm_socket(BM_SOCK_TCP);
    bm_i64 r;

    if (c < 0) {
        balas_galat(u, from, c);
        return;
    }
    r = bm_connect(c, tujuan, 0);
    for (bm_u64 i = 0; r == 0 && i < BESAR; i += BM_TCP_RING) {
        bm_u64 n = BESAR - i < BM_TCP_RING ? BESAR - i : BM_TCP_RING;

        for (bm_u64 k = 0; k < n; k++) {
            buf[k] = (char)pola(i + k);
        }
        r = kirim_semua(c, buf, n);
    }
    bm_u64 got = 0;
    int cocok = 1;

    while (r == 0 && got < BESAR) {
        bm_i64 k = bm_recv(c, buf, BM_TCP_RING, 500);

        if (k <= 0) {
            r = k == 0 ? BM_ECONNRESET : k;
            break;
        }
        for (bm_i64 j = 0; j < k; j++) {
            cocok &= (unsigned char)buf[j] == pola(got + (bm_u64)j);
        }
        got += (bm_u64)k;
    }
    if (r < 0) {
        balas_galat(u, from, r);
    } else {
        const char *m = cocok && got == BESAR ? "ok gema 3000 cocok" : "ok gema 3000 beda";

        balas(u, from, m, slen(m));
    }
    tulis_angka("P5: tcpklien gema close -> ", bm_close(c));
}

static void batas(bm_i64 u, bm_u64 from, bm_u64 tujuan, bm_i64 tick)
{
    bm_i64 c = bm_socket(BM_SOCK_TCP);
    bm_i64 r;

    if (c < 0) {
        balas_galat(u, from, c);
        return;
    }
    r = bm_connect(c, tujuan, tick < 1 ? 1 : (bm_u64)tick);
    if (r != 0) {
        balas_galat(u, from, r);
    } else {
        balas(u, from, "ok batas", 8);
    }
    bm_close(c);
}

// Uji penolakan saat boot (deterministik, sebelum soket UDP dibuat).
static void uji_boot(void)
{
    bm_i64 t = bm_socket(BM_SOCK_TCP);

    tulis_angka("P5: tcpklien connect port 0 -> ", bm_connect(t, BM_ADDR(192, 168, 50, 1, 0), 0));
    tulis_angka("P5: tcpklien bind 6000 -> ", bm_bind(t, 6000));
    tulis_angka("P5: tcpklien connect setelah bind -> ",
                bm_connect(t, BM_ADDR(192, 168, 50, 1, 80), 0));
    bm_close(t);
}

__attribute__((section(".text.start"), noreturn)) void _start(void)
{
    char buf[BM_TCP_RING];
    bm_i64 u;

    uji_boot();
    u = bm_socket(BM_SOCK_UDP);
    if (u < 0 || bm_bind(u, PORT) != 0) {
        tulis_angka("P5: tcpklien soket UDP gagal ", u);
        bm_exit();
    }
    tulis_angka("P5: tcpklien connect soket UDP -> ", bm_connect(u, BM_ADDR(192, 168, 50, 1, 80), 0));

    // .255 ditolak; sebelum loop net task jalan hasilnya -100: ulangi.
    bm_i64 t = bm_socket(BM_SOCK_TCP);
    bm_i64 r;

    for (int i = 0; i < 300; i++) {
        r = bm_connect(t, BM_ADDR(192, 168, 50, 255, 80), 0);
        if (r != BM_ENETDOWN) {
            break;
        }
        bm_recvfrom(u, buf, 16, 0, 10);
    }
    tulis_angka("P5: tcpklien connect .255 -> ", r);
    bm_close(t);
    tulis("P5: tcpklien siap port 5557\n");

    for (;;) {
        bm_u64 from = 0;
        bm_i64 n = bm_recvfrom(u, buf, 64, &from, 0);

        if (n < 0) {
            tulis_angka("P5: tcpklien recvfrom gagal ", n);
            break;
        }
        if (awalan(buf, n, "keluar")) {
            break;
        }

        bm_i64 i = 0;

        while (i < n && buf[i] != ' ') {
            i++;
        }
        bm_i64 port = baca_angka(buf, n, &i);
        bm_i64 oktet = baca_angka(buf, n, &i);
        bm_i64 tick = baca_angka(buf, n, &i);
        bm_u64 tujuan = (from & ~(bm_u64)0xffff) | (bm_u64)(port < 0 ? 0 : port);

        if (oktet >= 0) {
            tujuan = (tujuan & ~((bm_u64)0xff << 16)) | ((bm_u64)(oktet & 0xff) << 16);
        }
        if (awalan(buf, n, "konek ")) {
            konek(u, from, tujuan, buf);
        } else if (awalan(buf, n, "gema ")) {
            gema(u, from, tujuan, buf);
        } else if (awalan(buf, n, "batas ")) {
            batas(u, from, tujuan, tick);
        } else {
            balas(u, from, "galat perintah", 14);
        }
    }
    tulis_angka("P5: tcpklien close -> ", bm_close(u));
    tulis("P5: tcpklien selesai\n");
    bm_exit();
}

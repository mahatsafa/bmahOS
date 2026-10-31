#ifndef BMAHOS_USER_BM_H
#define BMAHOS_USER_BM_H

// P5-1: pembungkus syscall bmahOS untuk program user (ring 3). Daftar lengkap
// dan aturan: docs/SYSCALL.md. int 0x80, rax = nomor, argumen rdi rsi rdx r10 r8,
// hasil di rax (negatif = kode galat, nilai sama seperti errno Linux).
// Program: biner datar maks 4096 byte (kode + rodata, tanpa .data/.bss),
// dimuat di 0x400000, stack 1 halaman. Tanpa SSE (state FPU tidak disimpan).

typedef unsigned long bm_u64;
typedef long bm_i64;

#define BM_SYS_WRITE    1
#define BM_SYS_EXIT     2
#define BM_SYS_SOCKET   3
#define BM_SYS_BIND     4
#define BM_SYS_SENDTO   5
#define BM_SYS_RECVFROM 6
#define BM_SYS_CLOSE    7

#define BM_SOCK_UDP     2
#define BM_DGRAM_MAX    1472

#define BM_EIO          (-5)
#define BM_EBADF        (-9)
#define BM_EAGAIN       (-11)
#define BM_EACCES       (-13)
#define BM_EFAULT       (-14)
#define BM_EINVAL       (-22)
#define BM_EMFILE       (-24)
#define BM_EMSGSIZE     (-90)
#define BM_EADDRINUSE   (-98)
#define BM_ENETDOWN     (-100)
#define BM_EHOSTUNREACH (-113)

// Alamat soket: IPv4 a.b.c.d dan port dalam satu bilangan 48 bit.
#define BM_ADDR(a, b, c, d, port) \
    (((bm_u64)(a) << 40) | ((bm_u64)(b) << 32) | ((bm_u64)(c) << 24) | \
     ((bm_u64)(d) << 16) | (bm_u64)(port))
#define BM_ADDR_PORT(x) ((unsigned)((x) & 0xffff))

static inline bm_i64 bm_sys5(bm_u64 n, bm_u64 a0, bm_u64 a1, bm_u64 a2, bm_u64 a3, bm_u64 a4)
{
    bm_i64 r;
    register bm_u64 r10 __asm__("r10") = a3;
    register bm_u64 r8 __asm__("r8") = a4;

    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8)
                     : "memory");
    return r;
}

static inline bm_i64 bm_write(const void *buf, bm_u64 len)
{
    return bm_sys5(BM_SYS_WRITE, (bm_u64)buf, len, 0, 0, 0);
}

static inline __attribute__((noreturn)) void bm_exit(void)
{
    bm_sys5(BM_SYS_EXIT, 0, 0, 0, 0, 0);
    for (;;) {
    }
}

static inline bm_i64 bm_socket(int type)
{
    return bm_sys5(BM_SYS_SOCKET, (bm_u64)type, 0, 0, 0, 0);
}

static inline bm_i64 bm_bind(bm_i64 fd, unsigned port)
{
    return bm_sys5(BM_SYS_BIND, (bm_u64)fd, port, 0, 0, 0);
}

static inline bm_i64 bm_sendto(bm_i64 fd, const void *buf, bm_u64 len, bm_u64 addr)
{
    return bm_sys5(BM_SYS_SENDTO, (bm_u64)fd, (bm_u64)buf, len, addr, 0);
}

// timeout dalam tick (100/s), 0 = tunggu selamanya. from boleh 0.
static inline bm_i64 bm_recvfrom(bm_i64 fd, void *buf, bm_u64 cap, bm_u64 *from, bm_u64 timeout)
{
    return bm_sys5(BM_SYS_RECVFROM, (bm_u64)fd, (bm_u64)buf, cap, (bm_u64)from, timeout);
}

static inline bm_i64 bm_close(bm_i64 fd)
{
    return bm_sys5(BM_SYS_CLOSE, (bm_u64)fd, 0, 0, 0, 0);
}

#endif

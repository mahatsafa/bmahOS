// F7 SSH-1a: server uji interop. Menjalankan kernel/ssh.c (mesin keadaan murni) melalui soket TCP
// di 127.0.0.1 supaya klien OpenSSH sungguhan bisa tersambung. Dipanggil oleh tests/ssh-interop.sh.
//   ssh_interop KUNCI.DER JUMLAH_KONEKSI   (menulis "PORT <n>" dan "FP <sidik jari>" ke stdout)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "kernel.h"
#include "ssh.h"

int entropy_get(uint8_t *out, uint32_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t n = fd < 0 ? -1 : read(fd, out, len);

    if (fd >= 0) {
        close(fd);
    }
    return n == (ssize_t)len;
}

static int serve(int c)
{
    int s = ssh_open();
    static uint8_t buf[8192];

    if (s < 0) {
        fprintf(stderr, "ssh_open gagal: %d\n", s);
        return 1;
    }
    for (;;) {
        uint32_t n;
        const uint8_t *o = ssh_out_peek(s, &n);

        if (n > 0) {
            ssize_t w = send(c, o, n, MSG_NOSIGNAL);

            if (w <= 0) {
                break;
            }
            ssh_out_consume(s, (uint32_t)w);
            continue;
        }
        if (ssh_done(s)) {
            break;
        }
        ssh_feed(s, 0, 0);   // lanjutkan sisa buffer masuk (setelah keluaran terkuras)
        ssh_out_peek(s, &n);
        if (n > 0) {
            continue;
        }
        struct pollfd p = { c, POLLIN, 0 };

        if (poll(&p, 1, 5000) <= 0) {
            fprintf(stderr, "timeout menunggu klien\n");
            break;
        }
        ssize_t r = recv(c, buf, sizeof(buf), 0);

        if (r <= 0) {
            break;
        }
        uint32_t off = 0;

        while (off < (uint32_t)r) {
            uint32_t k = ssh_feed(s, buf + off, (uint32_t)r - off);

            off += k;
            if (k == 0) {
                // keluaran penuh: kuras dulu
                const uint8_t *q = ssh_out_peek(s, &n);

                if (n == 0 || send(c, q, n, MSG_NOSIGNAL) <= 0) {
                    break;
                }
                ssh_out_consume(s, n);
            }
        }
    }
    fprintf(stderr, "sesi selesai: state=%d alasan=\"%s\"\n", ssh_state(s), ssh_why(s));
    ssh_close(s);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "pakai: %s KUNCI.DER JUMLAH\n", argv[0]);
        return 2;
    }
    static uint8_t der[1024];
    FILE *f = fopen(argv[1], "rb");
    size_t dn = f ? fread(der, 1, sizeof(der), f) : 0;

    if (f) {
        fclose(f);
    }
    if (!ssh_load_key(der, (uint32_t)dn)) {
        fprintf(stderr, "kunci host tidak sah\n");
        return 2;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0 };
    socklen_t al = sizeof(a);

    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 4) != 0 ||
        getsockname(ls, (struct sockaddr *)&a, &al) != 0) {
        perror("soket");
        return 2;
    }
    printf("PORT %u\nFP %s\n", ntohs(a.sin_port), ssh_fingerprint());
    fflush(stdout);
    for (int i = 0; i < atoi(argv[2]); i++) {
        int c = accept(ls, 0, 0);

        if (c < 0) {
            break;
        }
        serve(c);
        close(c);
    }
    return 0;
}

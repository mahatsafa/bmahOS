// SMP-2 (build dev, ditanam di kernel): task user CPU-bound yang melapor CPU yang menjalankannya.
// Syscall dev SYS_CPU (13) mengembalikan indeks CPU (dari TSC_AUX di kernel, tak bisa dipalsukan ring 3).
// Pertama kali tiap CPU terlihat dicetak satu baris "cpuuji: cpu=N" (tak diulang: UART polling mahal). Dengan
// -smp 2 baris "cpuuji: cpu=1" membuktikan kode ring 3 benar-benar jalan di AP. Sengaja memakai CPU terus-menerus (jatah CPU task user membatasinya
// ke separuh jendela, lalu ia dijadwalkan ulang, kadang di CPU lain) supaya uji tekanan nyata.

#include "bm.h"

__attribute__((section(".text.start"), noreturn)) void _start(void)
{
    unsigned seen = 0;
    char b[16];

    for (;;) {
        bm_i64 c = bm_cpu();

        if (c >= 0 && c < 10 && !(seen & (1u << c))) {
            const char *p = "cpuuji: cpu=";
            bm_u64 n = 0;

            seen |= 1u << c;
            while (p[n]) {
                b[n] = p[n];
                n++;
            }
            b[n++] = (char)('0' + c);
            b[n++] = '\n';
            bm_write(b, n);
        }
        for (volatile unsigned long i = 0; i < 400000UL; i++) {
        }
    }
}

// R7: antarmuka harness fuzz (libFuzzer). Tiap tests/fuzz/fuzz_X.c meng-
// #include tests/host/test_X.c (main-nya dilewati oleh BMAHOS_FUZZ) supaya
// stub dan helper uji host dipakai ulang. Dua cara build (lihat Makefile):
//   build/fuzz/fuzz_X   -fsanitize=fuzzer: main dari libFuzzer (make fuzz)
//   build/fuzz/regr_X   tests/fuzz/driver.c: jalankan file/direktori sekali
//                       (make fuzz-regress) atau tulis korpus awal (-s DIR)

#ifndef BMAHOS_FUZZ_H
#define BMAHOS_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

// Tulis korpus awal ke dir (dipanggil driver.c dengan -s DIR).
void fuzz_seeds(const char *dir);

static inline void fuzz_seed(const char *dir, const char *name, const void *d, size_t n)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    FILE *f = fopen(p, "wb");
    if (f == NULL || fwrite(d, 1, n, f) != n || fclose(f) != 0) {
        fprintf(stderr, "fuzz: gagal menulis %s\n", p);
        exit(2);
    }
}

// Pelanggaran invarian = crash yang dicatat libFuzzer sebagai temuan.
#define FUZZ_ASSERT(c)                                                              \
    do {                                                                            \
        if (!(c)) {                                                                 \
            fprintf(stderr, "FUZZ: invarian gagal: %s (%s:%d)\n", #c, __FILE__,     \
                    __LINE__);                                                      \
            abort();                                                                \
        }                                                                           \
    } while (0)

#endif

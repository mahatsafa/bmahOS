#ifndef BMAHOS_HOST_TEST_H
#define BMAHOS_HOST_TEST_H

// F1.7: kerangka uji unit di host. Tiap CHECK yang gagal mencetak file:baris
// dan ekspresinya; test_done() mengembalikan kode keluar (0 = semua lulus).

#include <stdio.h>
#include <string.h>

extern int g_test_pass;
extern int g_test_fail;

#define CHECK(cond) \
    do { \
        if (cond) { \
            g_test_pass++; \
        } else { \
            g_test_fail++; \
            fprintf(stderr, "GAGAL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        } \
    } while (0)

#define CHECK_STR(got, want) \
    do { \
        const char *g_ = (got), *w_ = (want); \
        if (strcmp(g_, w_) == 0) { \
            g_test_pass++; \
        } else { \
            g_test_fail++; \
            fprintf(stderr, "GAGAL %s:%d: dapat \"%s\", harap \"%s\"\n", \
                    __FILE__, __LINE__, g_, w_); \
        } \
    } while (0)

int test_done(const char *name);

// Tangkapan serial dari stub (stubs.c). serial_capture_reset() mengosongkan.
extern char g_serial_cap[65536];
extern size_t g_serial_cap_len;
void serial_capture_reset(void);

// Bandingkan buffer biner dengan string hex (huruf kecil).
int test_hex_eq(const unsigned char *buf, size_t len, const char *hex);
size_t test_unhex(const char *hex, unsigned char *out, size_t max);

#endif

// P7-1: uji ota.c (di-#include). Image .bmo dibuat saat uji oleh
// client/ota-sign.py (openssl) dengan kunci uji tests/ota/ota-uji.pem dan
// kunci acak lain; ota_check harus menerima yang sah dan menolak tiap
// kerusakan dengan kode yang tepat, sebelum isi dipercaya.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/ota.c"

#define D "build/host/ota"

static int sh(const char *cmd)
{
    return system(cmd);
}

static uint8_t *load(const char *path, uint32_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        *len = 0;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(n ? (size_t)n : 1);   // seukuran persis (ASan)
    if (fread(b, 1, (size_t)n, f) != (size_t)n) {
        n = 0;
    }
    fclose(f);
    *len = (uint32_t)n;
    return b;
}

static int check_file(const char *path, const uint8_t *pub)
{
    uint32_t n;
    ota_info_t inf;
    uint8_t *b = load(path, &n);
    int rc = b ? ota_check(b, n, pub, &inf) : -100;
    free(b);
    return rc;
}

static uint8_t g_pub_lain[65];

static void setup(void)
{
    CHECK(sh("rm -rf " D " && mkdir -p " D " && "
             "printf 'halo app\\n' > " D "/app.bin && "
             "head -c 4096 /dev/urandom > " D "/app4k.bin && "
             "head -c 4097 /dev/urandom > " D "/app4k1.bin && "
             "{ printf '\\177ELF'; head -c 70000 /dev/urandom; } > " D "/k.elf && "
             "head -c 1000 /dev/zero > " D "/bukanelf.bin && "
             "openssl ecparam -name prime256v1 -genkey -noout -out " D "/lain.pem 2>/dev/null") == 0);
    const char *s = "python3 client/ota-sign.py --kunci tests/ota/ota-uji.pem";
    char c[2048];
    snprintf(c, sizeof(c), "%s --jenis app --versi 7 " D "/app.bin " D "/app.bmo >/dev/null && "
             "%s --jenis app --versi 1 " D "/app4k.bin " D "/app4k.bmo >/dev/null && "
             "%s --jenis kernel --versi 4294967295 " D "/k.elf " D "/k.bmo >/dev/null && "
             "%s --jenis kernel --versi 2 " D "/bukanelf.bin " D "/bukanelf.bmo >/dev/null && "
             "python3 client/ota-sign.py --kunci " D "/lain.pem --jenis app --versi 7 "
             D "/app.bin " D "/lain.bmo >/dev/null", s, s, s, s);
    CHECK(sh(c) == 0);
    // ota-sign.py sendiri menolak isi di luar batas jenis.
    snprintf(c, sizeof(c), "%s --jenis app --versi 1 " D "/app4k1.bin " D "/x.bmo 2>/dev/null", s);
    CHECK(sh(c) != 0);
    CHECK(sh("python3 client/ota-sign.py --cek tests/ota/ota-uji.pem " D "/app.bmo >/dev/null") == 0);
    CHECK(sh("python3 client/ota-sign.py --pub " D "/lain.pem --nama x | "
             "grep -o '0x[0-9a-f][0-9a-f]' | head -65 > " D "/lain.hex") == 0);
    FILE *f = fopen(D "/lain.hex", "r");
    unsigned v;
    for (int i = 0; f && i < 65 && fscanf(f, "%x", &v) == 1; i++) {
        g_pub_lain[i] = (uint8_t)v;
    }
    if (f) {
        fclose(f);
    }
    CHECK(g_pub_lain[0] == 4);
}

static void test_valid(void)
{
    uint32_t n;
    ota_info_t inf;
    uint8_t *b = load(D "/app.bmo", &n);

    CHECK(b && n == OTA_PREFIX + 9);
    CHECK(ota_check(b, n, ota_pub_uji, &inf) == OTA_OK);
    CHECK(inf.jenis == OTA_JENIS_APP && inf.versi == 7 && inf.ukuran == 9);
    CHECK(inf.sha256[0] == b[24] && inf.sha256[31] == b[55]);
    free(b);

    b = load(D "/k.bmo", &n);
    CHECK(ota_check(b, n, ota_pub_uji, &inf) == OTA_OK && inf.jenis == OTA_JENIS_KERNEL &&
          inf.versi == 0xFFFFFFFFu && inf.ukuran == 70004);
    free(b);
    CHECK(check_file(D "/app4k.bmo", ota_pub_uji) == OTA_OK);
    CHECK(check_file(D "/lain.bmo", g_pub_lain) == OTA_OK);
}

static void test_reject(void)
{
    // kunci salah: image kunci lain / kunci uji vs kunci PROD
    CHECK(check_file(D "/lain.bmo", ota_pub_uji) == OTA_ERR_TTD);
    CHECK(check_file(D "/app.bmo", g_pub_lain) == OTA_ERR_TTD);
    CHECK(check_file(D "/app.bmo", ota_pub_prod) == OTA_ERR_TTD);
    CHECK(check_file(D "/bukanelf.bmo", ota_pub_uji) == OTA_ERR_ELF);

    uint32_t n;
    ota_info_t inf;
    uint8_t *b = load(D "/app.bmo", &n);
    uint8_t *x = malloc(n + 1);

    // tiap byte header/tanda tangan/isi diubah satu bit -> ditolak
    int all = 1;
    for (uint32_t i = 0; i < n; i++) {
        memcpy(x, b, n);
        x[i] ^= 0x10;
        int rc = ota_check(x, n, ota_pub_uji, &inf);
        int want;
        if (i < 8 || (i >= 20 && i < 24) || (i >= 56 && i < 64)) {
            want = OTA_ERR_FORMAT;
        } else if (i >= 8 && i < 12) {
            want = OTA_ERR_JENIS;
        } else if (i >= 16 && i < 20) {
            want = OTA_ERR_UKURAN;
        } else if (i < OTA_PREFIX) {
            want = OTA_ERR_TTD;   // versi, sha256, tanda tangan
        } else {
            want = OTA_ERR_HASH;
        }
        if (rc != want) {
            fprintf(stderr, "byte %u: rc %d harap %d\n", i, rc, want);
            all = 0;
        }
        if (rc != OTA_OK && (inf.jenis || inf.ukuran)) {
            all = 0;   // keluaran dinolkan saat gagal
        }
    }
    CHECK(all);

    // panjang: kurang dari prefix, terpotong, kelebihan byte
    CHECK(ota_check(b, 0, ota_pub_uji, &inf) == OTA_ERR_FORMAT);
    CHECK(ota_check(NULL, n, ota_pub_uji, &inf) == OTA_ERR_FORMAT);
    CHECK(ota_check(b, OTA_PREFIX - 1, ota_pub_uji, &inf) == OTA_ERR_FORMAT);
    CHECK(ota_check(b, n - 1, ota_pub_uji, &inf) == OTA_ERR_UKURAN);
    memcpy(x, b, n);
    x[n] = 0;
    CHECK(ota_check(x, n + 1, ota_pub_uji, &inf) == OTA_ERR_UKURAN);

    // ukuran 0 / di atas batas jenis (header diubah: ditolak sebelum tanda tangan)
    memcpy(x, b, n);
    memset(x + 16, 0, 4);
    CHECK(ota_check(x, n, ota_pub_uji, &inf) == OTA_ERR_UKURAN);
    memcpy(x, b, n);
    x[8] = 3;
    CHECK(ota_check(x, n, ota_pub_uji, &inf) == OTA_ERR_JENIS);
    free(x);
    free(b);

    CHECK(ota_max_size(OTA_JENIS_KERNEL) == 1024 * 1024 && ota_max_size(OTA_JENIS_APP) == 4096 &&
          ota_max_size(0) == 0 && ota_max_size(3) == 0);
    CHECK_STR(ota_strerror(OTA_ERR_TTD), "tanda tangan tidak sah");
    CHECK_STR(ota_strerror(-99), "galat tidak dikenal");
}

static void test_selftest(void)
{
    serial_capture_reset();
    CHECK(ota_selftest() == 1);
    CHECK(strstr(g_serial_cap, "P7: ota swa-uji PASS (ECDSA P-256 BearSSL, kunci uji)") != NULL);
    CHECK(ota_pubkey() == ota_pub_uji);   // uji host = build dev
}

#ifndef BMAHOS_FUZZ
int main(void)
{
    setup();
    test_valid();
    test_reject();
    test_selftest();
    return test_done("ota");
}
#endif

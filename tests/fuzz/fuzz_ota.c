// P7-1: fuzz ota_check (file .bmo dari jaringan, P7-2). Input = file utuh.
// Byte pertama bit 0: perbaiki magic + cadangan supaya cek tanda tangan
// tercapai. Invarian: hanya image swa-uji asli yang sah dengan kunci uji
// (libFuzzer tidak bisa memalsukan ECDSA); gagal -> keluaran nol.

#include "test_ota.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 1 || n > OTA_PREFIX + 8192) {
        return 0;
    }
    size_t xn = n - 1;
    uint8_t *b = malloc(xn ? xn : 1);
    memcpy(b, d + 1, xn);
    if ((d[0] & 1) && xn >= OTA_HDR) {
        memcpy(b, g_ota_magic, 8);
        memset(b + 20, 0, 4);
        memset(b + 56, 0, 8);
    }
    ota_info_t inf;
    int rc = ota_check(b, (uint32_t)xn, ota_pub_uji, &inf);
    if (rc == OTA_OK) {
        FUZZ_ASSERT(xn == sizeof(ota_swauji_img) && memcmp(b, ota_swauji_img, xn) == 0);
    } else {
        FUZZ_ASSERT(rc < 0 && inf.jenis == 0 && inf.versi == 0 && inf.ukuran == 0);
    }
    // P7-2: OTA.BIN dari disk (512 byte pertama) dan limine.conf (seluruh input).
    if (xn >= 512) {
        ota_st_t st;
        uint8_t re[512];

        memset(&st, 0xAA, sizeof(st));
        rc = ota_st_decode(b, &st);
        FUZZ_ASSERT(rc >= -1 && rc <= 1);
        if (rc == 1) {
            ota_st_encode(&st, re);
            FUZZ_ASSERT(memcmp(re, b, 512) == 0);
        } else {
            FUZZ_ASSERT(st.seq == 0xAAAAAAAAu);
        }
    }
    rc = ota_conf_default(b, (uint32_t)xn);
    FUZZ_ASSERT(rc >= 0 && rc <= 2);
    free(b);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    uint8_t buf[sizeof(ota_swauji_img) + 1];
    buf[0] = 0;
    memcpy(buf + 1, ota_swauji_img, sizeof(ota_swauji_img));
    fuzz_seed(dir, "sah", buf, sizeof(buf));
    buf[0] = 1;
    buf[1 + 12] ^= 1;
    fuzz_seed(dir, "versi-ubah", buf, sizeof(buf));
    fuzz_seed(dir, "pendek", buf, 1 + OTA_PREFIX - 1);
}

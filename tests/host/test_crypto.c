// F1.7: uji SHA-256 dan HMAC-SHA256 (kernel/crypto.c) di host.
// Vektor: FIPS 180-4 (contoh resmi), RFC 4231 kasus 1-7, plus rantai digest
// untuk semua panjang pesan 0..200 dan panjang kunci 0..130 (nilai acuan
// dihitung dengan hashlib/hmac Python).

#include <stdlib.h>
#include "kernel.h"
#include "test.h"

static void sha(const void *m, size_t n, uint8_t out[32])
{
    sha256_ctx_t c;
    sha256_init(&c);
    sha256_update(&c, m, (uint32_t)n);
    sha256_final(&c, out);
}

static void test_fips(void)
{
    uint8_t d[32];

    sha("", 0, d);
    CHECK(test_hex_eq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    sha("abc", 3, d);
    CHECK(test_hex_eq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha(m448, strlen(m448), d);
    CHECK(test_hex_eq(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    const char *m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                       "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha(m896, strlen(m896), d);
    CHECK(test_hex_eq(d, 32, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));

    // Sejuta 'a', diumpankan dalam potongan 1000 byte.
    uint8_t a[1000];
    memset(a, 'a', sizeof(a));
    sha256_ctx_t c;
    sha256_init(&c);
    for (int i = 0; i < 1000; i++) {
        sha256_update(&c, a, sizeof(a));
    }
    sha256_final(&c, d);
    CHECK(test_hex_eq(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

static uint8_t g_pat[300];

// Semua panjang 0..200 melewati batas padding (55/56, 63/64, 119/120).
// Tiap panjang juga di-hash dalam dua potongan di semua titik potong;
// hasilnya harus sama dengan sekali update.
static void test_lengths(void)
{
    sha256_ctx_t acc;
    sha256_init(&acc);
    int split_ok = 1;

    for (size_t n = 0; n <= 200; n++) {
        uint8_t one[32];
        sha(g_pat, n, one);
        sha256_update(&acc, one, 32);

        for (size_t k = 0; k <= n; k++) {
            sha256_ctx_t c;
            uint8_t two[32];
            sha256_init(&c);
            sha256_update(&c, g_pat, (uint32_t)k);
            sha256_update(&c, g_pat + k, (uint32_t)(n - k));
            sha256_final(&c, two);
            if (memcmp(one, two, 32) != 0) {
                split_ok = 0;
                fprintf(stderr, "GAGAL potong n=%zu k=%zu\n", n, k);
            }
        }
    }

    uint8_t d[32];
    sha256_final(&acc, d);
    CHECK(test_hex_eq(d, 32, "a762260eaf7d0bf0f3e5c702dd2bc7de18bb629df9cad5b668d384084812f4f8"));
    CHECK(split_ok);
}

static void test_hmac_rfc4231(void)
{
    static const struct {
        int key_byte, key_len;   // key_byte < 0: kunci 0x01..0x19
        const char *msg;
        int msg_byte, msg_len;   // msg == NULL: msg_len kali msg_byte
        const char *mac;
    } tc[] = {
        { 0x0b, 20, "Hi There", 0, 0,
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
        { 0, 0, "what do ya want for nothing?", 0, 0,
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
        { 0xaa, 20, NULL, 0xdd, 50,
          "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" },
        { -1, 25, NULL, 0xcd, 50,
          "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" },
        { 0x0c, 20, "Test With Truncation", 0, 0,
          "a3b6167473100ee06e0c796c2955552b" },   // RFC: 128 bit pertama
        { 0xaa, 131, "Test Using Larger Than Block-Size Key - Hash Key First", 0, 0,
          "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" },
        { 0xaa, 131, "This is a test using a larger than block-size key and a larger "
                     "than block-size data. The key needs to be hashed before being "
                     "used by the HMAC algorithm.", 0, 0,
          "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" },
    };

    for (size_t i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
        uint8_t key[131], msg[200], mac[32];
        uint32_t kl, ml;

        if (i == 1) {
            memcpy(key, "Jefe", 4);
            kl = 4;
        } else {
            kl = (uint32_t)tc[i].key_len;
            for (uint32_t j = 0; j < kl; j++) {
                key[j] = tc[i].key_byte < 0 ? (uint8_t)(j + 1) : (uint8_t)tc[i].key_byte;
            }
        }
        if (tc[i].msg) {
            ml = (uint32_t)strlen(tc[i].msg);
            memcpy(msg, tc[i].msg, ml);
        } else {
            ml = (uint32_t)tc[i].msg_len;
            memset(msg, tc[i].msg_byte, ml);
        }

        hmac_sha256(key, kl, msg, ml, mac);
        size_t cmp = strlen(tc[i].mac) / 2;
        if (!test_hex_eq(mac, cmp, tc[i].mac)) {
            fprintf(stderr, "GAGAL RFC 4231 kasus %zu\n", i + 1);
        }
        CHECK(test_hex_eq(mac, cmp, tc[i].mac));
    }
}

// Panjang kunci 0..130 melewati batas blok 64 (kunci > 64 di-hash dulu).
static void test_hmac_keylens(void)
{
    sha256_ctx_t acc;
    sha256_init(&acc);
    for (uint32_t k = 0; k <= 130; k++) {
        uint8_t mac[32];
        hmac_sha256(g_pat, k, (const uint8_t *)"bmahOS", 6, mac);
        sha256_update(&acc, mac, 32);
    }
    uint8_t d[32];
    sha256_final(&acc, d);
    CHECK(test_hex_eq(d, 32, "fbcc7bed675523886a9a0675f7723db2336a7cc8547ee9e8bd2a32dc4c544cd8"));
}

// F1.9: ct_memeq sama dengan memcmp(...) == 0 untuk semua panjang 0..64,
// beda di tiap posisi dan tiap bit, dan pointer tidak sejajar.
static void test_ct_memeq(void)
{
    uint8_t a[80], b[80];
    int ok = 1;

    for (size_t i = 0; i < sizeof(a); i++) {
        a[i] = b[i] = (uint8_t)(i * 31 + 7);
    }
    for (uint32_t n = 0; n <= 64; n++) {
        for (uint32_t off = 0; off < 3; off++) {
            ok &= ct_memeq(a + off, b + off, n) == 1;
            for (uint32_t i = 0; i < n; i++) {
                for (int bit = 0; bit < 8; bit++) {
                    b[off + i] ^= (uint8_t)(1 << bit);
                    ok &= ct_memeq(a + off, b + off, n) == 0;
                    b[off + i] ^= (uint8_t)(1 << bit);
                }
            }
        }
    }
    // Semua nilai beda 0x01..0xFF di satu byte (cek hasil tanpa cabang).
    for (int v = 1; v < 256; v++) {
        b[5] ^= (uint8_t)v;
        ok &= ct_memeq(a, b, 16) == 0;
        b[5] ^= (uint8_t)v;
    }
    CHECK(ok);
}

// Self-test saat boot juga harus lulus di host dan menyalakan g_crypto_ok.
static void test_selftest(void)
{
    serial_capture_reset();
    g_crypto_ok = 0;
    crypto_selftest();
    CHECK(g_crypto_ok == 1);
    CHECK(strstr(g_serial_cap, "Crypto: self-test SEMUA LULUS") != NULL);
    CHECK(strstr(g_serial_cap, "Crypto: ct_memeq PASS") != NULL);
    CHECK(strstr(g_serial_cap, "FAIL") == NULL);
}

int main(void)
{
    for (size_t i = 0; i < sizeof(g_pat); i++) {
        g_pat[i] = (uint8_t)(i * 7 + 1);
    }
    test_fips();
    test_lengths();
    test_hmac_rfc4231();
    test_hmac_keylens();
    test_ct_memeq();
    test_selftest();
    return test_done("crypto");
}

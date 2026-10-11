#include "kernel.h"

// ---- Net-11a: SHA-256 (FIPS 180-4) + HMAC-SHA256 (RFC 2104) ----

static const uint32_t g_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA_EP0(x)  (SHA_ROTR(x, 2) ^ SHA_ROTR(x, 13) ^ SHA_ROTR(x, 22))
#define SHA_EP1(x)  (SHA_ROTR(x, 6) ^ SHA_ROTR(x, 11) ^ SHA_ROTR(x, 25))
#define SHA_SIG0(x) (SHA_ROTR(x, 7) ^ SHA_ROTR(x, 18) ^ ((x) >> 3))
#define SHA_SIG1(x) (SHA_ROTR(x, 17) ^ SHA_ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t *data)
{
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t i;

    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               (uint32_t)data[i * 4 + 3];
    }

    for (i = 16; i < 64; i++) {
        m[i] = SHA_SIG1(m[i - 2]) + m[i - 7] + SHA_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + SHA_EP1(e) + SHA_CH(e, f, g) + g_sha256_k[i] + m[i];
        t2 = SHA_EP0(a) + SHA_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t *hash)
{
    uint32_t i = ctx->datalen;

    ctx->data[i++] = 0x80;

    if (ctx->datalen < 56) {
        while (i < 56) {
            ctx->data[i++] = 0;
        }
    } else {
        while (i < 64) {
            ctx->data[i++] = 0;
        }
        sha256_transform(ctx, ctx->data);
        for (i = 0; i < 56; i++) {
            ctx->data[i] = 0;
        }
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;

    for (i = 0; i < 8; i++) {
        ctx->data[63 - i] = (uint8_t)(ctx->bitlen >> (i * 8));
    }

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; i++) {
        for (uint32_t j = 0; j < 8; j++) {
            hash[i + j * 4] = (uint8_t)((ctx->state[j] >> (24 - i * 8)) & 0xFF);
        }
    }
}

void hmac_sha256(const uint8_t *key, uint32_t keylen,
                        const uint8_t *msg, uint32_t msglen,
                        uint8_t *out)
{
    uint8_t kblock[64];
    uint8_t pad[64];
    uint8_t inner[32];
    sha256_ctx_t ctx;
    uint32_t i;

    for (i = 0; i < 64; i++) {
        kblock[i] = 0;
    }

    if (keylen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, keylen);
        sha256_final(&ctx, kblock);
    } else {
        for (i = 0; i < keylen; i++) {
            kblock[i] = key[i];
        }
    }

    for (i = 0; i < 64; i++) {
        pad[i] = kblock[i] ^ 0x36;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, inner);

    for (i = 0; i < 64; i++) {
        pad[i] = kblock[i] ^ 0x5c;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

static uint32_t crypto_strlen(const char *s)
{
    uint32_t n = 0;

    while (s[n]) {
        n++;
    }

    return n;
}

int g_crypto_ok = 0;

static int crypto_check(const char *name, const uint8_t *digest,
                        const char *expected_hex)
{
    static const char hx[] = "0123456789abcdef";
    char got[65];

    for (uint32_t i = 0; i < 32; i++) {
        got[i * 2] = hx[digest[i] >> 4];
        got[i * 2 + 1] = hx[digest[i] & 0xF];
    }
    got[64] = 0;

    int same = 1;

    for (uint32_t i = 0; i < 65; i++) {
        if (got[i] != expected_hex[i]) {
            same = 0;
            break;
        }
    }

    serial_write("Crypto: ");
    serial_write(name);
    serial_write(same ? " PASS\r\n" : " FAIL, hasil=");

    if (!same) {
        serial_write(got);
        serial_write("\r\n");
    }

    return same;
}

void crypto_selftest(void)
{
    uint8_t out[32];
    uint8_t key[131];
    sha256_ctx_t ctx;
    int ok = 1;

    sha256_init(&ctx);
    sha256_final(&ctx, out);
    ok &= crypto_check("sha256-kosong", out,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"abc", 3);
    sha256_final(&ctx, out);
    ok &= crypto_check("sha256-abc", out,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    for (uint32_t i = 0; i < 20; i++) {
        key[i] = 0x0b;
    }
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
    ok &= crypto_check("hmac-rfc4231-tc1", out,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    {
        const char *m = "what do ya want for nothing?";
        hmac_sha256((const uint8_t *)"Jefe", 4,
                    (const uint8_t *)m, crypto_strlen(m), out);
        ok &= crypto_check("hmac-rfc4231-tc2", out,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    for (uint32_t i = 0; i < 131; i++) {
        key[i] = 0xaa;
    }
    {
        const char *m = "Test Using Larger Than Block-Size Key - Hash Key First";
        hmac_sha256(key, 131, (const uint8_t *)m, crypto_strlen(m), out);
        ok &= crypto_check("hmac-rfc4231-tc6-kunci-panjang", out,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    g_crypto_ok = ok;

    serial_write(ok ? "Crypto: self-test SEMUA LULUS\r\n"
                    : "Crypto: self-test GAGAL, kripto dinonaktifkan\r\n");
}

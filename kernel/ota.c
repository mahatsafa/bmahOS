// P7-1: format file kiriman OTA (.bmo) + verifikasi tanda tangan ECDSA P-256.
//
// File = header 64 byte + tanda tangan 64 byte (r||s mentah) + isi.
// Header (little endian): magic "BMOTA1\0\0", jenis u32 (1 kernel, 2 app),
// versi u32, ukuran isi u32, cadangan u32 (0), sha256(isi) 32 byte,
// cadangan 8 byte (0). Tanda tangan atas SHA-256(header 64 byte); header
// memuat sha256 isi, jadi isi ikut terikat. Pembuat: client/ota-sign.py.
//
// Urutan cek (gagal tertutup): panjang + format header -> jenis + batas
// ukuran -> tanda tangan -> sha256 isi. Isi tidak dipercaya sebelum tanda
// tangan sah. Verifikasi memakai BearSSL (br_ecdsa_i31_vrfy_raw + p256_m64,
// implementasi yang sama dengan TLS D9); kode ini tidak menulis primitif kripto.
//
// Kunci publik tertanam (kernel/ota_kunci.h): build dev = kunci uji
// (tests/ota/ota-uji.pem, di-commit), build PROD = kunci asli (privat hanya di
// CentOS). Image dev ditolak kernel PROD dan sebaliknya.
#include "kernel.h"
#include "ota_kunci.h"
#include <bearssl.h>

static const uint8_t g_ota_magic[8] = { 'B', 'M', 'O', 'T', 'A', '1', 0, 0 };

static uint32_t ota_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

const uint8_t *ota_pubkey(void)
{
#ifdef BMAHOS_PROD
    return ota_pub_prod;
#else
    return ota_pub_uji;
#endif
}

uint32_t ota_max_size(uint32_t jenis)
{
    if (jenis == OTA_JENIS_KERNEL) {
        return OTA_KERNEL_MAX;
    }
    if (jenis == OTA_JENIS_APP) {
        return OTA_APP_MAX;
    }
    return 0;
}

int ota_check(const uint8_t *buf, uint32_t len, const uint8_t *pub65, ota_info_t *out)
{
    uint8_t h[32];
    sha256_ctx_t c;

    memset(out, 0, sizeof(*out));
    if (!buf || len < OTA_PREFIX) {
        return OTA_ERR_FORMAT;
    }
    if (memcmp(buf, g_ota_magic, 8) != 0 || ota_le32(buf + 20) != 0) {
        return OTA_ERR_FORMAT;
    }
    for (uint32_t i = 56; i < OTA_HDR; i++) {
        if (buf[i] != 0) {
            return OTA_ERR_FORMAT;
        }
    }

    uint32_t jenis = ota_le32(buf + 8);
    uint32_t versi = ota_le32(buf + 12);
    uint32_t ukuran = ota_le32(buf + 16);
    uint32_t max = ota_max_size(jenis);

    if (max == 0) {
        return OTA_ERR_JENIS;
    }
    if (ukuran == 0 || ukuran > max || ukuran != len - OTA_PREFIX) {
        return OTA_ERR_UKURAN;
    }

    // Tanda tangan atas SHA-256(header).
    sha256_init(&c);
    sha256_update(&c, buf, OTA_HDR);
    sha256_final(&c, h);

    br_ec_public_key pk;

    pk.curve = BR_EC_secp256r1;
    pk.q = (unsigned char *)pub65;
    pk.qlen = 65;
    if (br_ecdsa_i31_vrfy_raw(&br_ec_p256_m64, h, sizeof(h), &pk,
                              buf + OTA_HDR, OTA_SIG) != 1) {
        return OTA_ERR_TTD;
    }

    // Isi harus cocok dengan sha256 di header yang sudah sah.
    sha256_init(&c);
    sha256_update(&c, buf + OTA_PREFIX, ukuran);
    sha256_final(&c, h);
    if (!ct_memeq(h, buf + 24, 32)) {
        return OTA_ERR_HASH;
    }
    if (jenis == OTA_JENIS_KERNEL) {
        const uint8_t *e = buf + OTA_PREFIX;

        if (ukuran < 4 || e[0] != 0x7f || e[1] != 'E' || e[2] != 'L' || e[3] != 'F') {
            return OTA_ERR_ELF;
        }
    }

    out->jenis = jenis;
    out->versi = versi;
    out->ukuran = ukuran;
    memcpy(out->sha256, buf + 24, 32);
    return OTA_OK;
}

const char *ota_strerror(int rc)
{
    switch (rc) {
    case OTA_OK:         return "OK";
    case OTA_ERR_FORMAT: return "format/header salah";
    case OTA_ERR_JENIS:  return "jenis tidak dikenal";
    case OTA_ERR_UKURAN: return "ukuran salah";
    case OTA_ERR_TTD:    return "tanda tangan tidak sah";
    case OTA_ERR_HASH:   return "sha256 isi tidak cocok";
    case OTA_ERR_ELF:    return "isi kernel bukan ELF";
    default:             return "galat tidak dikenal";
    }
}

// Swa-uji boot: image uji (kunci uji) harus sah; satu byte isi / header /
// tanda tangan diubah harus ditolak dengan kode yang tepat; kunci build ini
// (PROD) atau kunci uji yang dirusak menolak tanda tangan.
static uint8_t g_ota_st_buf[sizeof(ota_swauji_img)];

int ota_selftest(void)
{
    ota_info_t inf;
    uint8_t badkey[65];
    int ok = 1;
    uint32_t n = sizeof(ota_swauji_img);

    ok &= ota_check(ota_swauji_img, n, ota_pub_uji, &inf) == OTA_OK &&
          inf.jenis == OTA_JENIS_APP && inf.versi == 1 && inf.ukuran == n - OTA_PREFIX;

    memcpy(g_ota_st_buf, ota_swauji_img, n);
    g_ota_st_buf[n - 1] ^= 1;   // isi
    ok &= ota_check(g_ota_st_buf, n, ota_pub_uji, &inf) == OTA_ERR_HASH;

    memcpy(g_ota_st_buf, ota_swauji_img, n);
    g_ota_st_buf[12] ^= 1;      // versi di header
    ok &= ota_check(g_ota_st_buf, n, ota_pub_uji, &inf) == OTA_ERR_TTD;

    memcpy(g_ota_st_buf, ota_swauji_img, n);
    g_ota_st_buf[OTA_HDR + 5] ^= 1;   // tanda tangan
    ok &= ota_check(g_ota_st_buf, n, ota_pub_uji, &inf) == OTA_ERR_TTD;

    memcpy(badkey, ota_pub_uji, sizeof(badkey));
    badkey[64] ^= 1;            // titik tidak di kurva / kunci lain
    ok &= ota_check(ota_swauji_img, n, badkey, &inf) == OTA_ERR_TTD;
#ifdef BMAHOS_PROD
    ok &= ota_check(ota_swauji_img, n, ota_pubkey(), &inf) == OTA_ERR_TTD;
#endif
    ok &= ota_check(ota_swauji_img, OTA_PREFIX - 1, ota_pub_uji, &inf) == OTA_ERR_FORMAT;

    kprintf("P7: ota swa-uji %s (ECDSA P-256 BearSSL, kunci %s)\r\n",
            ok ? "PASS" : "GAGAL",
#ifdef BMAHOS_PROD
            "PROD"
#else
            "uji"
#endif
            );
    return ok;
}

// ---- P7-2: OTA.BIN, limine.conf, cmdline ----
// OTA.BIN (512 byte): magic "BMOTAST1" @0, seq u32 @8, aktif u8 @12 (0 A,
// 1 B), coba u8 @13 (OTA_COBA_TIDAK atau 0/1, P7-3), sisa u8 @14, 0 @15,
// slot A @16 dan slot B @64 (48 byte: status u8, 0 x3, versi u32, ukuran u32,
// 0 u32, sha256 isi 32), nol s.d. 503, 8 byte pertama SHA-256(0..503) @504.
// Ditulis utuh satu sektor (atomik seperti rekaman LOG.BIN). Byte cadangan
// harus nol: berkas yang tidak dikenal dianggap rusak, bukan ditebak.
static const uint8_t g_ota_st_magic[8] = { 'B', 'M', 'O', 'T', 'A', 'S', 'T', '1' };

#define OTA_ST_SLOT(i) (16u + 48u * (i))
#define OTA_ST_HASH    504u

static void ota_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void ota_st_init(ota_st_t *st, uint8_t aktif)
{
    memset(st, 0, sizeof(*st));
    st->aktif = aktif ? 1 : 0;
    st->coba = OTA_COBA_TIDAK;
}

void ota_st_encode(const ota_st_t *st, uint8_t *b)
{
    uint8_t h[32];
    sha256_ctx_t c;

    memset(b, 0, 512);
    memcpy(b, g_ota_st_magic, 8);
    ota_put32(b + 8, st->seq);
    b[12] = st->aktif;
    b[13] = st->coba;
    b[14] = st->sisa;
    for (uint32_t i = 0; i < 2; i++) {
        uint8_t *p = b + OTA_ST_SLOT(i);

        p[0] = st->s[i].status;
        ota_put32(p + 4, st->s[i].versi);
        ota_put32(p + 8, st->s[i].ukuran);
        memcpy(p + 16, st->s[i].sha256, 32);
    }
    sha256_init(&c);
    sha256_update(&c, b, OTA_ST_HASH);
    sha256_final(&c, h);
    memcpy(b + OTA_ST_HASH, h, 8);
}

int ota_st_decode(const uint8_t *b, ota_st_t *st)
{
    uint8_t h[32];
    sha256_ctx_t c;
    int zero = 1;
    ota_st_t t;

    for (uint32_t i = 0; i < 512; i++) {
        zero &= b[i] == 0;
    }
    if (zero) {
        return 0;
    }
    if (memcmp(b, g_ota_st_magic, 8) != 0) {
        return -1;
    }
    sha256_init(&c);
    sha256_update(&c, b, OTA_ST_HASH);
    sha256_final(&c, h);
    if (!ct_memeq(h, b + OTA_ST_HASH, 8)) {
        return -1;
    }
    memset(&t, 0, sizeof(t));
    t.seq = ota_le32(b + 8);
    t.aktif = b[12];
    t.coba = b[13];
    t.sisa = b[14];
    if (t.aktif > 1 || (t.coba != OTA_COBA_TIDAK && t.coba > 1) || b[15] != 0) {
        return -1;
    }
    for (uint32_t i = 0; i < 2; i++) {
        const uint8_t *p = b + OTA_ST_SLOT(i);

        t.s[i].status = p[0];
        t.s[i].versi = ota_le32(p + 4);
        t.s[i].ukuran = ota_le32(p + 8);
        memcpy(t.s[i].sha256, p + 16, 32);
        if (t.s[i].status > OTA_SLOT_DITULIS || p[1] || p[2] || p[3] ||
            ota_le32(p + 12) != 0 || t.s[i].ukuran > OTA_KERNEL_MAX) {
            return -1;
        }
    }
    for (uint32_t i = OTA_ST_SLOT(2); i < OTA_ST_HASH; i++) {
        if (b[i] != 0) {
            return -1;
        }
    }
    *st = t;
    return 1;
}

// limine.conf: baris (di awal baris) "default_entry:" + spasi + 1 atau 2.
int ota_conf_default(const uint8_t *b, uint32_t n)
{
    static const char key[] = "default_entry:";
    const uint32_t kl = sizeof(key) - 1;

    for (uint32_t i = 0; i + kl < n; i++) {
        if ((i == 0 || b[i - 1] == '\n') && memcmp(b + i, key, kl) == 0) {
            uint32_t j = i + kl;

            while (j < n && (b[j] == ' ' || b[j] == '\t')) {
                j++;
            }
            if (j < n && (b[j] == '1' || b[j] == '2') &&
                (j + 1 >= n || b[j + 1] < '0' || b[j + 1] > '9')) {
                return b[j] - '0';
            }
            return 0;
        }
    }
    return 0;
}

// cmdline Limine P7-0: tepat "slot=A" atau "slot=B" (lain = boot ISO/tidak dikenal).
int ota_cmdline_slot(const char *s)
{
    if (s[0] == 's' && s[1] == 'l' && s[2] == 'o' && s[3] == 't' && s[4] == '=' &&
        (s[5] == 'A' || s[5] == 'B') && s[6] == 0) {
        return s[5] == 'A' ? 0 : 1;
    }
    return -1;
}

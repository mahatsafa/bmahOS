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

// P7-2: OTA.BIN encode/decode, limine.conf, cmdline.
static void test_status(void)
{
    ota_st_t a, b;
    uint8_t buf[512], x[512];

    ota_st_init(&a, 1);
    CHECK(a.aktif == 1 && a.coba == OTA_COBA_TIDAK && a.seq == 0 && a.s[0].status == 0);
    a.seq = 0x01020304;
    a.s[0].status = OTA_SLOT_SAH;
    a.s[0].versi = 7;
    a.s[0].ukuran = 368032;
    for (int i = 0; i < 32; i++) {
        a.s[0].sha256[i] = (uint8_t)(i * 7 + 1);
    }
    a.s[1].status = OTA_SLOT_DITULIS;
    a.s[1].versi = 0xFFFFFFFFu;
    a.s[1].ukuran = OTA_KERNEL_MAX;
    ota_st_encode(&a, buf);
    CHECK(memcmp(buf, "BMOTAST1", 8) == 0 && buf[12] == 1 && buf[13] == 0xFF);
    CHECK(buf[8] == 4 && buf[11] == 1 && buf[16] == 1 && buf[20] == 7 && buf[64] == 2);
    memset(&b, 0xAA, sizeof(b));
    CHECK(ota_st_decode(buf, &b) == 1);
    CHECK(b.seq == a.seq && b.aktif == 1 && b.coba == OTA_COBA_TIDAK && b.sisa == 0);
    CHECK(b.s[0].status == OTA_SLOT_SAH && b.s[0].versi == 7 && b.s[0].ukuran == 368032 &&
          memcmp(b.s[0].sha256, a.s[0].sha256, 32) == 0);
    CHECK(b.s[1].status == OTA_SLOT_DITULIS && b.s[1].versi == 0xFFFFFFFFu &&
          b.s[1].ukuran == OTA_KERNEL_MAX);
    ota_st_encode(&b, x);
    CHECK(memcmp(x, buf, 512) == 0);

    // nol semua = kosong (berkas baru dari host); st tidak disentuh
    memset(x, 0, sizeof(x));
    memset(&b, 0xAA, sizeof(b));
    CHECK(ota_st_decode(x, &b) == 0 && b.seq == 0xAAAAAAAAu);

    // tiap bit tiap byte diubah -> rusak (hash, atau cek isi), st tidak disentuh
    int all = 1;
    for (int i = 0; i < 512; i++) {
        for (int bit = 0; bit < 8; bit++) {
            memcpy(x, buf, 512);
            x[i] ^= (uint8_t)(1 << bit);
            memset(&b, 0xAA, sizeof(b));
            if (ota_st_decode(x, &b) != -1 || b.seq != 0xAAAAAAAAu) {
                all = 0;
            }
        }
    }
    CHECK(all);

    // hash sah tetapi isi di luar batas -> rusak
    static const struct { int off; uint8_t v; } bad[] = {
        { 12, 2 }, { 13, 2 }, { 15, 1 }, { 16, 4 }, { 17, 1 }, { 28, 1 }, { 112, 1 }, { 503, 1 },
        { 13, 1 },   // P7-3: coba == aktif (1)
        { 14, 4 },   // P7-3: sisa > 3
    };
    for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++) {
        memcpy(x, buf, 512);
        x[bad[k].off] = bad[k].v;
        sha256_ctx_t c;
        uint8_t h[32];
        sha256_init(&c);
        sha256_update(&c, x, 504);
        sha256_final(&c, h);
        memcpy(x + 504, h, 8);
        CHECK(ota_st_decode(x, &b) == -1);
    }
    // ukuran > 1 MB
    memcpy(x, buf, 512);
    x[16 + 8 + 2] = 0x20;   // ukuran slot A = 0x20xxxx > 1 MB
    {
        sha256_ctx_t c;
        uint8_t h[32];
        sha256_init(&c);
        sha256_update(&c, x, 504);
        sha256_final(&c, h);
        memcpy(x + 504, h, 8);
    }
    CHECK(ota_st_decode(x, &b) == -1);
    // coba 0/1 sah
    a.coba = 0;
    a.sisa = 3;
    ota_st_encode(&a, x);
    CHECK(ota_st_decode(x, &b) == 1 && b.coba == 0 && b.sisa == 3);
    // P7-3: status gagal sah
    a.s[0].status = OTA_SLOT_GAGAL;
    ota_st_encode(&a, x);
    CHECK(ota_st_decode(x, &b) == 1 && b.s[0].status == OTA_SLOT_GAGAL);
}

// P7-3: ganti default_entry di tempat.
static void test_conf_set(void)
{
    char b[513];
    int n = snprintf(b, sizeof(b), "timeout: 3\ndefault_entry: 2\n\n/bmahOS slot A\n"
                     "    protocol: limine\n    path: boot():/KERNA.ELF\n    cmdline: slot=A\n");
    memset(b + n, '#', 512 - (size_t)n);
    b[512] = 0;
    char asli[513];
    memcpy(asli, b, sizeof(b));

    CHECK(ota_conf_set((uint8_t *)b, 512, 1) == 1 && ota_conf_default((uint8_t *)b, 512) == 1);
    // hanya satu byte berubah
    int beda = 0;
    for (int i = 0; i < 512; i++) {
        beda += b[i] != asli[i];
    }
    CHECK(beda == 1 && b[26] == '1');
    CHECK(ota_conf_set((uint8_t *)b, 512, 2) == 1 && memcmp(b, asli, 512) == 0);
    CHECK(ota_conf_set((uint8_t *)b, 512, 0) == 0 && ota_conf_set((uint8_t *)b, 512, 3) == 0 &&
          memcmp(b, asli, 512) == 0);
    char x[] = "timeout: 3\n# default_entry: 2\n";
    CHECK(ota_conf_set((uint8_t *)x, (uint32_t)strlen(x), 1) == 0 &&
          strcmp(x, "timeout: 3\n# default_entry: 2\n") == 0);
    char y[] = "default_entry: 12\n";
    CHECK(ota_conf_set((uint8_t *)y, (uint32_t)strlen(y), 1) == 0 && strcmp(y, "default_entry: 12\n") == 0);
    CHECK(ota_conf_set(NULL, 0, 1) == 0);
}

static ota_st_t st_buat(int aktif, int coba, int sisa, int status_coba)
{
    ota_st_t s;

    ota_st_init(&s, (uint8_t)aktif);
    s.coba = coba < 0 ? OTA_COBA_TIDAK : (uint8_t)coba;
    s.sisa = (uint8_t)sisa;
    s.s[0].status = s.s[1].status = OTA_SLOT_SAH;
    s.s[0].versi = 10;
    s.s[1].versi = 11;
    if (coba >= 0) {
        s.s[coba].status = (uint8_t)status_coba;
    }
    return s;
}

// P7-3: keputusan boot.
static void test_decide(void)
{
    ota_st_t s, a;

    // tanpa coba, slot aktif berjalan / ISO -> biasa, st tetap
    s = st_buat(0, -1, 0, 0);
    a = s;
    CHECK(ota_boot_decide(&s, 0, 1) == OTA_BOOT_BIASA && memcmp(&s, &a, sizeof(s)) == 0);
    CHECK(ota_boot_decide(&s, -1, 2) == OTA_BOOT_BIASA && memcmp(&s, &a, sizeof(s)) == 0);
    // tanpa coba, slot lain berjalan: limine.conf menunjuk slot itu -> perbaiki;
    // limine.conf sudah benar / tak terbaca
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_PERBAIKI && memcmp(&s, &a, sizeof(s)) == 0);
    CHECK(ota_boot_decide(&s, 1, 1) == OTA_BOOT_MANUAL && memcmp(&s, &a, sizeof(s)) == 0);
    CHECK(ota_boot_decide(&s, 1, 0) == OTA_BOOT_PERBAIKI);
    // percobaan B, 3 boot: sisa 3 -> 2 -> 1 -> 0, lalu rollback
    s = st_buat(0, 1, OTA_COBA_SISA, OTA_SLOT_SAH);
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_COBA && s.coba == 1 && s.sisa == 2);
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_COBA && s.sisa == 1);
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_COBA && s.sisa == 0);
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_ROLLBACK && s.coba == OTA_COBA_TIDAK &&
          s.sisa == 0 && s.aktif == 0 && s.s[1].status == OTA_SLOT_GAGAL &&
          s.s[0].status == OTA_SLOT_SAH && s.s[1].versi == 11);
    // sesudah rollback, limine.conf belum kembali (crash) -> perbaiki
    CHECK(ota_boot_decide(&s, 1, 2) == OTA_BOOT_PERBAIKI);
    CHECK(ota_boot_decide(&s, 0, 1) == OTA_BOOT_BIASA);
    // slot coba tidak sah (DITULIS) -> rollback tanpa menandai gagal
    s = st_buat(1, 0, 2, OTA_SLOT_DITULIS);
    CHECK(ota_boot_decide(&s, 0, 1) == OTA_BOOT_ROLLBACK && s.coba == OTA_COBA_TIDAK &&
          s.s[0].status == OTA_SLOT_DITULIS && s.aktif == 1);
    // ada coba, slot aktif berjalan -> batal
    s = st_buat(1, 0, 3, OTA_SLOT_SAH);
    CHECK(ota_boot_decide(&s, 1, 1) == OTA_BOOT_BATAL && s.coba == OTA_COBA_TIDAK && s.sisa == 0 &&
          s.aktif == 1 && s.s[0].status == OTA_SLOT_SAH);
    // ISO saat coba tertunda -> tidak diubah
    s = st_buat(1, 0, 3, OTA_SLOT_SAH);
    a = s;
    CHECK(ota_boot_decide(&s, -1, 1) == OTA_BOOT_ISO_COBA && memcmp(&s, &a, sizeof(s)) == 0);
    // hasil tiap keputusan tetap OTA.BIN yang sah
    uint8_t buf[512];
    ota_st_t d;
    s = st_buat(0, 1, 1, OTA_SLOT_SAH);
    ota_boot_decide(&s, 1, 2);
    ota_st_encode(&s, buf);
    CHECK(ota_st_decode(buf, &d) == 1 && d.sisa == 0 && d.coba == 1);
    ota_boot_decide(&s, 1, 2);
    ota_st_encode(&s, buf);
    CHECK(ota_st_decode(buf, &d) == 1 && d.coba == OTA_COBA_TIDAK && d.s[1].status == OTA_SLOT_GAGAL);
}

static int conf(const char *s)
{
    return ota_conf_default((const uint8_t *)s, (uint32_t)strlen(s));
}

static void test_conf(void)
{
    CHECK(conf("timeout: 3\ndefault_entry: 2\n\n/bmahOS slot A\n") == 2);
    CHECK(conf("default_entry: 1\n") == 1);
    CHECK(conf("default_entry:1") == 1);
    CHECK(conf("default_entry:\t2\n") == 2);
    CHECK(conf("timeout: 3\n") == 0);
    CHECK(conf("default_entry: 3\n") == 0);
    CHECK(conf("default_entry: 12\n") == 0);
    CHECK(conf("default_entry: \n") == 0);
    CHECK(conf("default_entry:") == 0);
    CHECK(conf("# default_entry: 2\n") == 0);   // bukan di awal baris
    CHECK(conf("xdefault_entry: 2\n") == 0);
    CHECK(conf("") == 0);
    CHECK(ota_conf_default(NULL, 0) == 0);
    // berkas 512 byte asli P7-0
    char b[513];
    int n = snprintf(b, sizeof(b), "timeout: 3\ndefault_entry: 2\n\n/bmahOS slot A\n"
                     "    protocol: limine\n    path: boot():/KERNA.ELF\n    cmdline: slot=A\n");
    memset(b + n, '#', 512 - (size_t)n);
    CHECK(ota_conf_default((const uint8_t *)b, 512) == 2);

    CHECK(ota_cmdline_slot("slot=A") == 0);
    CHECK(ota_cmdline_slot("slot=B") == 1);
    CHECK(ota_cmdline_slot("") == -1);
    CHECK(ota_cmdline_slot("slot=C") == -1);
    CHECK(ota_cmdline_slot("slot=AB") == -1);
    CHECK(ota_cmdline_slot("slot=") == -1);
    CHECK(ota_cmdline_slot(" slot=A") == -1);
}

#ifndef BMAHOS_FUZZ
int main(void)
{
    setup();
    test_valid();
    test_reject();
    test_selftest();
    test_status();
    test_conf();
    test_conf_set();
    test_decide();
    return test_done("ota");
}
#endif

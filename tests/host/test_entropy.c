// F1.8: uji kolam entropi dan HMAC-DRBG (kernel/entropy.c) di host.
// entropy.c disertakan langsung (#include) supaya keadaan static bisa
// diperiksa dan direset. Waktu kejadian diberikan lewat entropy_event_tsc()
// supaya urutan TSC bisa diatur (teratur vs acak).

#include <stdlib.h>
#include "test.h"
#include "entropy.c"
#include "drbg_vectors.h"

struct cpu_features g_cpu;

static size_t unhex_s(const char *s, uint8_t *out, size_t max)
{
    return s ? test_unhex(s, out, max) : 0;
}

// ---- HMAC-DRBG ----
static void test_cavp(void)
{
    size_t n = sizeof(g_drbg_vecs) / sizeof(g_drbg_vecs[0]);
    int ok = 1;

    for (size_t i = 0; i < n; i++) {
        const struct drbg_vec *v = &g_drbg_vecs[i];
        uint8_t ent[64], nonce[64], pers[64], rs[64], rsa[64], a1[64], a2[64];
        uint8_t want[256], got[256];
        size_t el = unhex_s(v->ent, ent, sizeof(ent));
        size_t nl = unhex_s(v->nonce, nonce, sizeof(nonce));
        size_t pl = unhex_s(v->pers, pers, sizeof(pers));
        size_t a1l = unhex_s(v->add1, a1, sizeof(a1));
        size_t a2l = unhex_s(v->add2, a2, sizeof(a2));
        size_t ol = unhex_s(v->out, want, sizeof(want));
        hmac_drbg_t d;

        hmac_drbg_instantiate(&d, ent, (uint32_t)el, nonce, (uint32_t)nl, pers, (uint32_t)pl);
        if (v->reseed) {
            size_t rl = unhex_s(v->reseed, rs, sizeof(rs));
            size_t ral = unhex_s(v->reseed_add, rsa, sizeof(rsa));
            hmac_drbg_reseed(&d, rs, (uint32_t)rl, rsa, (uint32_t)ral);
        }
        hmac_drbg_generate(&d, got, (uint32_t)ol, a1, (uint32_t)a1l);
        hmac_drbg_generate(&d, got, (uint32_t)ol, a2, (uint32_t)a2l);
        if (memcmp(got, want, ol) != 0) {
            ok = 0;
            fprintf(stderr, "GAGAL CAVP vektor %zu (pers=%zu add=%zu reseed=%d)\n",
                    i, pl, a1l, v->reseed != NULL);
        }
    }
    CHECK(n == 32);
    CHECK(ok);
    CHECK(hmac_drbg_selftest() == 1);
}

// Keluaran panjang yang tidak kelipatan 32 sama dengan awal keluaran penuh
// (keadaan sama, generate memotong blok terakhir).
static void test_partial_block(void)
{
    uint8_t seed[32] = { 1 }, a[100], b[128];
    hmac_drbg_t d1, d2;
    hmac_drbg_instantiate(&d1, seed, 32, seed, 16, 0, 0);
    hmac_drbg_instantiate(&d2, seed, 32, seed, 16, 0, 0);
    hmac_drbg_generate(&d1, a, sizeof(a), 0, 0);
    hmac_drbg_generate(&d2, b, sizeof(b), 0, 0);
    CHECK(memcmp(a, b, sizeof(a)) == 0);
    CHECK(d1.reseed_counter == 2);
}

// ---- estimator ----
static void test_estimator(void)
{
    entropy_est_t e;
    uint32_t credit = 0;

    // Interval tetap: tidak ada kredit setelah tiga kejadian pertama.
    memset(&e, 0, sizeof(e));
    for (uint64_t i = 0; i < 1000; i++) {
        uint32_t c = entropy_estimate(&e, 5000 + i * 37000);
        if (i >= 3) {
            credit += c;
        }
    }
    CHECK(credit == 0);

    // Percepatan tetap (d2 konstan): juga teratur.
    memset(&e, 0, sizeof(e));
    credit = 0;
    for (uint64_t i = 0; i < 1000; i++) {
        uint32_t c = entropy_estimate(&e, 1000 + i * 37000 + i * i * 11);
        if (i >= 3) {
            credit += c;
        }
    }
    CHECK(credit == 0);

    // Jitter kecil (< ENTROPY_MIN_DELTA): tidak dikredit.
    memset(&e, 0, sizeof(e));
    credit = 0;
    srand(5);
    for (uint64_t i = 0; i < 1000; i++) {
        uint32_t c = entropy_estimate(&e, i * 37000 + (uint64_t)(rand() % 8));
        if (i >= 3) {
            credit += c;
        }
    }
    CHECK(credit == 0);

    // Jitter acak ribuan siklus: hampir semua kejadian dikredit 1 bit.
    memset(&e, 0, sizeof(e));
    credit = 0;
    uint64_t t = 0;
    for (int i = 0; i < 1000; i++) {
        t += 37000 + (uint64_t)(rand() % 4000);
        credit += entropy_estimate(&e, t);
    }
    CHECK(credit > 950 && credit <= 1000);
}

// ---- kolam + kesiapan ----
static void reset_entropy(int rdrand, int rdseed)
{
    memset((void *)g_fast, 0, sizeof(g_fast));
    g_fast_idx = 0;
    g_fast_credit = 0;
    memset(g_est, 0, sizeof(g_est));
    g_pool_bits = 0;
    memset(&g_drbg, 0, sizeof(g_drbg));
    g_drbg_kat_ok = 0;
    g_last_reseed_tick = 0;
    g_extract_ctr = 0;
    g_entropy_ready = 0;
    g_entropy_ready_tick = 0;
    g_entropy_events = 0;
    g_entropy_jitter_bits = 0;
    g_entropy_hw_bits = 0;
    g_entropy_denied = 0;
    g_drbg_reseeds = 0;
    memset(&g_cpu, 0, sizeof(g_cpu));
    g_cpu.rdrand = (uint8_t)rdrand;
    g_cpu.rdseed = (uint8_t)rdseed;
    timer_ticks = 0;
    serial_capture_reset();
    entropy_init();
}

static uint64_t g_tsc;

// Satu tick timer dengan jitter acak (atau teratur bila jitter = 0).
static void tick(uint32_t jitter)
{
    g_tsc += 1000000 + (jitter ? (uint64_t)(rand() % jitter) : 0);
    timer_ticks++;
    entropy_event_tsc(ENTROPY_SRC_TIMER, g_tsc, 0);
}

static void test_ready_jitter(void)
{
    uint8_t buf[16];

    reset_entropy(0, 0);
    CHECK(strstr(g_serial_cap, "DRBG: self-test PASS") != NULL);
    CHECK(strstr(g_serial_cap, "Entropi: tolak sebelum siap PASS") != NULL);
    CHECK(!g_entropy_ready);
    CHECK(g_entropy_denied == 0);   // probe self-test tidak dihitung

    // Sebelum siap: ditolak dan dihitung, buffer tidak disentuh.
    memset(buf, 0x5A, sizeof(buf));
    CHECK(entropy_get(buf, sizeof(buf)) == 0);
    CHECK(g_entropy_denied == 1);
    CHECK(buf[0] == 0x5A && buf[15] == 0x5A);

    // Tick teratur: tidak pernah siap.
    for (int i = 0; i < 2000; i++) {
        tick(0);
        if ((i & 7) == 0) {
            entropy_poll();
        }
    }
    CHECK(!g_entropy_ready);
    CHECK(entropy_get(buf, sizeof(buf)) == 0);

    // Tick dengan jitter: siap setelah >= 256 bit, tidak lebih cepat.
    srand(7);
    int ready_at = -1;
    for (int i = 0; i < 1000 && ready_at < 0; i++) {
        tick(50000);
        if ((i & 7) == 7) {
            entropy_poll();
        }
        if (g_entropy_ready) {
            ready_at = i + 1;
        }
    }
    printf("entropi: siap setelah %d tick berjitter (bit_jitter=%lu)\n",
           ready_at, (unsigned long)g_entropy_jitter_bits);
    CHECK(ready_at >= 256 && ready_at < 300);
    CHECK(g_entropy_jitter_bits >= 256 && g_entropy_hw_bits == 0);
    CHECK(strstr(g_serial_cap, "Entropi: siap tick=") != NULL);
    CHECK(entropy_get(buf, sizeof(buf)) == 1);
    CHECK(entropy_get(buf, ENTROPY_GET_MAX + 1) == 0);   // terlalu besar: tolak
}

// Kolam cepat dibatasi 256 bit kredit: kejadian tanpa entropy_poll() tidak
// boleh menumpuk kredit melebihi isi kolam.
static void test_fast_cap(void)
{
    reset_entropy(0, 0);
    srand(9);
    for (int i = 0; i < 5000; i++) {
        tick(50000);
    }
    CHECK(g_fast_credit == ENTROPY_FAST_MAX);
    entropy_poll();
    CHECK(g_entropy_ready);
    CHECK(g_entropy_jitter_bits == ENTROPY_FAST_MAX);
    CHECK(g_pool_bits == 0);   // ekstraksi mengosongkan kredit kolam
}

// Reseed: paling cepat tiap ENTROPY_RESEED_TICKS dan hanya dengan kolam penuh.
static void test_reseed(void)
{
    uint8_t a[32], b[32];

    reset_entropy(0, 0);
    srand(11);
    for (int i = 0; i < 300; i++) {
        tick(50000);
        entropy_poll();
    }
    CHECK(g_entropy_ready && g_drbg_reseeds == 0);

    for (int i = 0; i < ENTROPY_RESEED_TICKS - 400; i++) {
        tick(50000);
        entropy_poll();
    }
    CHECK(g_drbg_reseeds == 0);   // belum 60 s

    for (int i = 0; i < 600; i++) {
        tick(50000);
        entropy_poll();
    }
    CHECK(g_drbg_reseeds == 1);

    // Keadaan DRBG berubah: dua permintaan berturut-turut berbeda.
    CHECK(entropy_get(a, 32) && entropy_get(b, 32) && memcmp(a, b, 32) != 0);
}

// rdseed/rdrand dari CPU host (bila ada): siap langsung saat init.
static void test_hw(void)
{
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    int has_rdrand = (c >> 30) & 1;

    if (!has_rdrand) {
        printf("entropi: CPU host tanpa rdrand, uji hw dilewati\n");
        return;
    }
    reset_entropy(1, 0);
    CHECK(g_entropy_ready && g_entropy_hw_bits == 256);
    CHECK(strstr(g_serial_cap, "Entropi: rdseed=0 rdrand=1 bit_hw=256") != NULL);
}

// ---- keluaran: unik + uji statistik FIPS 140-2 (20000 bit) ----
static int cmp16(const void *x, const void *y)
{
    return memcmp(x, y, 16);
}

static void test_unique(void)
{
    enum { N = 100000 };
    uint8_t (*v)[16] = malloc(sizeof(uint8_t[16]) * N);
    int ok = 1;

    for (int i = 0; i < N; i++) {
        ok &= entropy_get(v[i], 16);
    }
    qsort(v, N, 16, cmp16);
    int dup = 0;
    for (int i = 1; i < N; i++) {
        dup += memcmp(v[i - 1], v[i], 16) == 0;
    }
    free(v);
    CHECK(ok);
    CHECK(dup == 0);
}

static int fips140_2(const uint8_t *s)
{
    int ones = 0, poker[16] = { 0 };
    int runs[2][7] = { { 0 } };
    int longest = 0, run = 0, prev = -1;

    for (int i = 0; i < 20000; i++) {
        int bit = (s[i / 8] >> (7 - i % 8)) & 1;
        ones += bit;
        if (bit == prev) {
            run++;
        } else {
            if (prev >= 0) {
                runs[prev][run < 6 ? run : 6]++;
            }
            prev = bit;
            run = 1;
        }
        if (run > longest) {
            longest = run;
        }
    }
    runs[prev][run < 6 ? run : 6]++;

    for (int i = 0; i < 2500; i++) {
        poker[s[i] >> 4]++;
        poker[s[i] & 0xF]++;
    }
    double x = 0;
    for (int i = 0; i < 16; i++) {
        x += (double)poker[i] * poker[i];
    }
    x = 16.0 / 5000 * x - 5000;

    static const int lo[7] = { 0, 2315, 1114, 527, 240, 103, 103 };
    static const int hi[7] = { 0, 2685, 1386, 723, 384, 209, 209 };
    int runs_ok = 1;
    for (int b = 0; b < 2; b++) {
        for (int l = 1; l <= 6; l++) {
            runs_ok &= runs[b][l] >= lo[l] && runs[b][l] <= hi[l];
        }
    }
    return ones > 9725 && ones < 10275 && x > 2.16 && x < 46.17 && runs_ok && longest < 26;
}

static void test_stats(void)
{
    uint8_t s[2500];
    int pass = 0;

    int got = 1;
    for (int i = 0; i < 20; i++) {
        for (size_t off = 0; off < sizeof(s); off += 500) {   // batas per permintaan 1024
            got &= entropy_get(s + off, 500);
        }
        pass += fips140_2(s);
    }
    CHECK(got);
    printf("entropi: FIPS 140-2 (monobit, poker, runs, long run) lulus %d/20 blok\n", pass);
    // Untuk keluaran acak sejati tiap blok gagal dengan peluang ~1e-4.
    CHECK(pass >= 19);

    // Pembanding: uji ini memang menolak data tidak acak.
    memset(s, 0x0F, sizeof(s));
    CHECK(!fips140_2(s));
}

int main(void)
{
    test_cavp();
    test_partial_block();
    test_estimator();
    test_ready_jitter();
    test_fast_cap();
    test_reseed();
    test_hw();
    test_unique();
    test_stats();
    return test_done("entropy");
}

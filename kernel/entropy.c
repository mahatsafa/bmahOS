#include "kernel.h"

// F1.8: kolam entropi + HMAC-DRBG (NIST SP 800-90A, SHA-256).
//
// Sumber: TSC saat IRQ timer, IRQ E1000, dan frame RX (jitter), plus
// rdseed/rdrand bila CPUID melaporkannya. Di konteks IRQ kejadian hanya
// dicampur ke "kolam cepat" 256 bit (XOR/rotasi, tanpa SHA); entropy_poll()
// di net task melipatnya ke kolam SHA-256. Saat kolam punya >= 256 bit
// kredit, isinya diekstrak untuk instantiate (atau reseed) DRBG. Sebelum itu
// entropy_get() MENOLAK (return 0) dan pemanggil harus menolak permintaannya.
//
// Kredit jitter: estimator delta tingkat 1..3 per sumber. Kejadian dengan
// min(|d1|,|d2|,|d3|) >= ENTROPY_MIN_DELTA siklus dihitung 1 bit, selain itu
// 0 (interval yang teratur tidak menambah kredit). rdseed/rdrand dikredit
// penuh (64 bit per 64 bit), seperti default Linux (trust CPU); build
// NORDRAND melewatinya. Build NOENTROPY tidak pernah memberi kredit (uji
// jalur "belum cukup entropi"). Di VM jitter cenderung lebih teratur dan
// hypervisor mengendalikan TSC; hasil VM tidak mewakili perangkat keras asli.

#define ENTROPY_READY_BITS   256
#define ENTROPY_POOL_MAX     512   // batas kredit kolam SHA (bit)
#define ENTROPY_FAST_MAX     256   // batas kredit kolam cepat (= ukurannya)
#define ENTROPY_MIN_DELTA    16
#define ENTROPY_RESEED_TICKS 6000  // reseed paling cepat tiap 60 s
#define ENTROPY_GET_MAX      1024  // byte per permintaan

// ---- HMAC-DRBG (SP 800-90A bagian 10.1.2), tanpa prediction resistance ----

// Data masukan Update dirangkai di buffer lokal; semua pemanggil di kernel
// memakai ukuran tetap jauh di bawah batas ini.
#define DRBG_PROVIDED_MAX 256

static void drbg_update(hmac_drbg_t *d,
                        const uint8_t *a, uint32_t alen,
                        const uint8_t *b, uint32_t blen,
                        const uint8_t *c, uint32_t clen)
{
    uint8_t m[32 + 1 + DRBG_PROVIDED_MAX];
    uint32_t plen = alen + blen + clen;

    ASSERT(plen <= DRBG_PROVIDED_MAX);

    for (uint32_t i = 0; i < 32; i++) {
        m[i] = d->v[i];
    }
    for (uint32_t i = 0; i < alen; i++) {
        m[33 + i] = a[i];
    }
    for (uint32_t i = 0; i < blen; i++) {
        m[33 + alen + i] = b[i];
    }
    for (uint32_t i = 0; i < clen; i++) {
        m[33 + alen + blen + i] = c[i];
    }

    for (uint8_t round = 0; round < 2; round++) {
        if (round == 1 && plen == 0) {
            break;
        }
        m[32] = round;
        hmac_sha256(d->k, 32, m, 33 + plen, d->k);
        hmac_sha256(d->k, 32, d->v, 32, d->v);
        for (uint32_t i = 0; i < 32; i++) {
            m[i] = d->v[i];
        }
    }

    for (uint32_t i = 0; i < sizeof(m); i++) {
        ((volatile uint8_t *)m)[i] = 0;
    }
}

void hmac_drbg_instantiate(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                           const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *pers, uint32_t pers_len)
{
    for (uint32_t i = 0; i < 32; i++) {
        d->k[i] = 0x00;
        d->v[i] = 0x01;
    }
    drbg_update(d, ent, ent_len, nonce, nonce_len, pers, pers_len);
    d->reseed_counter = 1;
}

void hmac_drbg_reseed(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                      const uint8_t *add, uint32_t add_len)
{
    drbg_update(d, ent, ent_len, add, add_len, 0, 0);
    d->reseed_counter = 1;
}

void hmac_drbg_generate(hmac_drbg_t *d, uint8_t *out, uint32_t out_len,
                        const uint8_t *add, uint32_t add_len)
{
    if (add_len > 0) {
        drbg_update(d, add, add_len, 0, 0, 0, 0);
    }

    uint32_t done = 0;

    while (done < out_len) {
        hmac_sha256(d->k, 32, d->v, 32, d->v);
        for (uint32_t i = 0; i < 32 && done < out_len; i++) {
            out[done++] = d->v[i];
        }
    }

    drbg_update(d, add, add_len, 0, 0, 0, 0);
    d->reseed_counter++;
}

// ---- sumber ----

typedef struct {
    uint64_t last;
    int64_t last_d1;
    int64_t last_d2;
} entropy_est_t;

static volatile uint64_t g_fast[4];
static volatile uint32_t g_fast_idx;
static volatile uint32_t g_fast_credit;
static entropy_est_t g_est[ENTROPY_SRC_COUNT];

static sha256_ctx_t g_pool;
static uint32_t g_pool_bits;
static hmac_drbg_t g_drbg;
static int g_drbg_kat_ok;
static uint64_t g_last_reseed_tick;
static uint64_t g_extract_ctr;

int g_entropy_ready = 0;
uint64_t g_entropy_ready_tick = 0;
uint64_t g_entropy_events = 0;
uint64_t g_entropy_jitter_bits = 0;
uint64_t g_entropy_hw_bits = 0;
uint64_t g_entropy_denied = 0;
uint64_t g_drbg_reseeds = 0;

static inline uint64_t entropy_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rotl64(uint64_t x, unsigned r)
{
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t abs64(int64_t x)
{
    return x < 0 ? (uint64_t)0 - (uint64_t)x : (uint64_t)x;
}

// 1 bit bila waktu kejadian tidak bisa ditebak dari tiga kejadian
// sebelumnya (delta, perubahan delta, dan perubahan perubahannya), 0 bila
// teratur.
uint32_t entropy_estimate(entropy_est_t *e, uint64_t t)
{
    int64_t d1 = (int64_t)(t - e->last);
    int64_t d2 = d1 - e->last_d1;
    int64_t d3 = d2 - e->last_d2;

    e->last = t;
    e->last_d1 = d1;
    e->last_d2 = d2;

    uint64_t m = abs64(d1);
    if (abs64(d2) < m) {
        m = abs64(d2);
    }
    if (abs64(d3) < m) {
        m = abs64(d3);
    }
    return m >= ENTROPY_MIN_DELTA ? 1 : 0;
}

// Pemetaan x -> rotl(x ^ v) + y bijektif terhadap x, jadi kolam cepat tidak
// kehilangan isi saat dicampur.
static void fast_mix(uint64_t v)
{
    uint32_t i = g_fast_idx++ & 3;
    g_fast[i] = rotl64(g_fast[i] ^ v, 23) + g_fast[(i + 1) & 3];
}

void entropy_event_tsc(uint32_t src, uint64_t tsc, uint64_t extra)
{
    if (src >= ENTROPY_SRC_COUNT) {
        return;
    }

    uint64_t flags = irq_save();
    uint32_t bits = entropy_estimate(&g_est[src], tsc);

    fast_mix(tsc);
    fast_mix(extra ^ ((uint64_t)src << 56));
#ifdef BMAHOS_NOENTROPY
    bits = 0;
#endif
    if (g_fast_credit + bits <= ENTROPY_FAST_MAX) {
        g_fast_credit += bits;
    }
    g_entropy_events++;
    irq_restore(flags);
}

void entropy_event(uint32_t src, uint64_t extra)
{
    entropy_event_tsc(src, entropy_rdtsc(), extra);
}

static void pool_add(const void *data, uint32_t len, uint32_t bits)
{
    sha256_update(&g_pool, (const uint8_t *)data, len);
    g_pool_bits += bits;
    if (g_pool_bits > ENTROPY_POOL_MAX) {
        g_pool_bits = ENTROPY_POOL_MAX;
    }
}

static int hw_rand64(uint64_t *out)
{
#ifdef BMAHOS_NORDRAND
    (void)out;
    return 0;
#else
    for (int i = 0; i < 10; i++) {
        uint64_t v;
        uint8_t ok;
        if (g_cpu.rdseed) {
            __asm__ volatile("rdseed %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        } else if (g_cpu.rdrand) {
            __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        } else {
            return 0;
        }
        if (ok) {
            *out = v;
            return 1;
        }
    }
    return 0;
#endif
}

// 4 x 64 bit dari rdseed/rdrand ke kolam SHA.
static void pool_add_hw(void)
{
    for (int i = 0; i < 4; i++) {
        uint64_t v;
        if (hw_rand64(&v)) {
            uint32_t bits = 64;
#ifdef BMAHOS_NOENTROPY
            bits = 0;
#endif
            pool_add(&v, 8, bits);
            g_entropy_hw_bits += bits;
            v = 0;
        }
    }
}

// Ekstrak 32 byte dari kolam, lalu kolam diganti hash satu arah dari
// isinya (keluaran lama tidak bisa dihitung dari kolam baru).
static void pool_extract(uint8_t out[32])
{
    sha256_ctx_t c = g_pool;
    uint8_t h[32];

    g_extract_ctr++;
    sha256_update(&c, (const uint8_t *)&g_extract_ctr, 8);
    sha256_final(&c, h);

    sha256_init(&c);
    sha256_update(&c, h, 32);
    sha256_update(&c, (const uint8_t *)"keluar", 6);
    sha256_final(&c, out);

    sha256_init(&g_pool);
    sha256_update(&g_pool, h, 32);
    sha256_update(&g_pool, (const uint8_t *)"kolam", 5);
    g_pool_bits = 0;

    for (int i = 0; i < 32; i++) {
        ((volatile uint8_t *)h)[i] = 0;
    }
}

void entropy_poll(void)
{
    uint64_t fast[4];
    uint32_t credit;
    uint64_t flags = irq_save();

    for (int i = 0; i < 4; i++) {
        fast[i] = g_fast[i];
    }
    credit = g_fast_credit;
    g_fast_credit = 0;
    irq_restore(flags);

    pool_add(fast, sizeof(fast), credit);
    g_entropy_jitter_bits += credit;

    uint64_t now = timer_ticks;

    if (g_entropy_ready && now - g_last_reseed_tick >= ENTROPY_RESEED_TICKS &&
        g_pool_bits < ENTROPY_READY_BITS) {
        pool_add_hw();
    }

    if (!g_drbg_kat_ok || g_pool_bits < ENTROPY_READY_BITS) {
        return;
    }
    if (g_entropy_ready && now - g_last_reseed_tick < ENTROPY_RESEED_TICKS) {
        return;
    }

    uint8_t seed[32];
    uint64_t tsc = entropy_rdtsc();
    pool_extract(seed);

    if (!g_entropy_ready) {
        uint64_t nonce[2] = { tsc, now };
        static const char pers[] = "bmahOS F1.8 HMAC-DRBG";
        hmac_drbg_instantiate(&g_drbg, seed, 32, (const uint8_t *)nonce, 16,
                              (const uint8_t *)pers, sizeof(pers) - 1);
        g_entropy_ready = 1;
        g_entropy_ready_tick = now;
        kprintf("Entropi: siap tick=%lu kejadian=%lu bit_hw=%lu bit_jitter=%lu\r\n",
                now, g_entropy_events, g_entropy_hw_bits, g_entropy_jitter_bits);
    } else {
        hmac_drbg_reseed(&g_drbg, seed, 32, (const uint8_t *)&tsc, 8);
        g_drbg_reseeds++;
    }
    g_last_reseed_tick = now;

    for (int i = 0; i < 32; i++) {
        ((volatile uint8_t *)seed)[i] = 0;
    }
}

int entropy_get(uint8_t *out, uint32_t len)
{
    entropy_poll();

    if (!g_entropy_ready || len > ENTROPY_GET_MAX) {
        g_entropy_denied++;
        return 0;
    }

    uint64_t tsc = entropy_rdtsc();
    hmac_drbg_generate(&g_drbg, out, len, (const uint8_t *)&tsc, 8);
    return 1;
}

// ---- init + self-test ----

static int hexval(char c)
{
    return c <= '9' ? c - '0' : c - 'a' + 10;
}

static void unhex(const char *s, uint8_t *out, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(hexval(s[i * 2]) << 4 | hexval(s[i * 2 + 1]));
    }
}

// Known-answer test: CAVP HMAC_DRBG SHA-256, no reseed, tanpa
// personalization/additional input, COUNT 0 (dua kali generate 1024 bit,
// keluaran kedua dibandingkan).
int hmac_drbg_selftest(void)
{
    uint8_t ent[32], nonce[16], want[128], got[128];
    hmac_drbg_t d;

    unhex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488", ent, 32);
    unhex("659ba96c601dc69fc902940805ec0ca8", nonce, 16);
    unhex("e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
          "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
          "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
          "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8", want, 128);

    hmac_drbg_instantiate(&d, ent, 32, nonce, 16, 0, 0);
    hmac_drbg_generate(&d, got, 128, 0, 0);
    hmac_drbg_generate(&d, got, 128, 0, 0);

    uint8_t diff = 0;
    for (int i = 0; i < 128; i++) {
        diff |= (uint8_t)(got[i] ^ want[i]);
    }
    return diff == 0;
}

static uint8_t entropy_cmos_read(uint8_t reg)
{
    outb(0x70, reg);
    return inb(0x71);
}

void entropy_init(void)
{
    sha256_init(&g_pool);
    g_pool_bits = 0;

    g_drbg_kat_ok = hmac_drbg_selftest();
    kprintf(g_drbg_kat_ok ? "DRBG: self-test PASS (CAVP HMAC_DRBG SHA-256)\r\n"
                          : "DRBG: self-test GAGAL, nonce dinonaktifkan\r\n");

    // Sebelum ada kredit, permintaan harus ditolak.
    uint8_t probe[16];
    uint64_t denied = g_entropy_denied;
    int refused = !entropy_get(probe, sizeof(probe)) && g_entropy_denied == denied + 1;
    g_entropy_denied = denied;
    kprintf(refused ? "Entropi: tolak sebelum siap PASS\r\n"
                    : "Entropi: tolak sebelum siap GAGAL\r\n");

    // Tanpa kredit: RTC, TSC, tick (membedakan boot, tidak rahasia).
    static const uint8_t rtc_regs[6] = { 0x00, 0x02, 0x04, 0x07, 0x08, 0x09 };
    for (int i = 0; i < 6; i++) {
        uint8_t r = entropy_cmos_read(rtc_regs[i]);
        pool_add(&r, 1, 0);
    }
    uint64_t t[2] = { entropy_rdtsc(), timer_ticks };
    pool_add(t, sizeof(t), 0);

    pool_add_hw();

#if defined(BMAHOS_NOENTROPY)
    kprintf("Entropi: build NOENTROPY, kredit selalu 0 (nonce akan ditolak)\r\n");
#elif defined(BMAHOS_NORDRAND)
    kprintf("Entropi: build NORDRAND, hanya jitter TSC\r\n");
#else
    kprintf("Entropi: rdseed=%u rdrand=%u bit_hw=%lu\r\n",
            (unsigned)g_cpu.rdseed, (unsigned)g_cpu.rdrand, g_entropy_hw_bits);
#endif

    entropy_poll();
}

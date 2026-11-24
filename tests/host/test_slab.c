// F7: uji slab.c di host (di-#include: akses static). Frame/pemetaan ditiru: wilayah slab
// = mmap anonim, pmm_alloc/pmm_free/vmm_map/vmm_unmap mencatat dan memeriksa pemakaian.

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "kernel.h"
#include "test.h"

#include "slab.c"

#define NFRAME 2048
static uint8_t g_frame_used[NFRAME + 1];
static uint64_t g_frame_limit;     // jumlah frame yang masih boleh dibagikan
static uint64_t g_frame_next;
static uint64_t g_frames_live;
static uint64_t g_maps, g_unmaps;
static int g_map_bad;              // pemetaan ganda / unmap tak terpetakan
static uint8_t g_vmapped[SLAB_NCLASS * (SLAB_PAGES_MAX + 1)];

static uint8_t *g_region;

uint64_t pmm_alloc(void)
{
    if (g_frame_limit == 0 || g_frame_next >= NFRAME) {
        return 0;
    }
    g_frame_limit--;
    uint64_t f = ++g_frame_next;   // 1..NFRAME (0 = gagal)
    g_frame_used[f] = 1;
    g_frames_live++;
    return f * PMM_PAGE_SIZE;
}

void pmm_free(uint64_t phys)
{
    uint64_t f = phys / PMM_PAGE_SIZE;

    if (f == 0 || f > NFRAME || !g_frame_used[f]) {
        g_map_bad++;
        return;
    }
    g_frame_used[f] = 0;
    g_frames_live--;
}

static uint64_t pidx(uint64_t va)
{
    return (va - (uint64_t)(uintptr_t)g_region) / PMM_PAGE_SIZE;
}

void vmm_map(uint64_t pml4, uint64_t va, uint64_t pa, uint64_t flags)
{
    (void)pml4; (void)pa;
    if (g_vmapped[pidx(va)] || !(flags & VMM_FLAG_NX) || (flags & VMM_FLAG_USER)) {
        g_map_bad++;
    }
    g_vmapped[pidx(va)] = 1;
    g_maps++;
}

int g_unmap_rc = 1;   // SMP-2: 0 = shootdown tidak lengkap (frame tak boleh dibebaskan)
int vmm_unmap(uint64_t pml4, uint64_t va)
{
    (void)pml4;
    if (!g_vmapped[pidx(va)]) {
        g_map_bad++;
    }
    g_vmapped[pidx(va)] = 0;
    g_unmaps++;
    return g_unmap_rc;
}

static void reset(uint64_t frames)
{
    memset(g_frame_used, 0, sizeof(g_frame_used));
    memset(g_vmapped, 0, sizeof(g_vmapped));
    memset(g_slab_pg, 0, sizeof(g_slab_pg));
    g_frame_limit = frames;
    g_frame_next = 0;
    g_frames_live = g_maps = g_unmaps = 0;
    g_map_bad = 0;
    g_slab_alloc = g_slab_free = g_slab_fail = g_slab_pages = g_slab_bad_free = g_slab_uaf = 0;
    slab_init(0x1000, (uint64_t)(uintptr_t)g_region);
}

static uint64_t g_rng = 88172645463325252ULL;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 11);
}

static void test_basic(void)
{
    reset(NFRAME);
    CHECK(slab_alloc(SLAB_MAX_SIZE + 1) == 0 && g_slab_fail == 0);   // bukan urusan slab
    CHECK(slab_alloc(~0ULL) == 0);
    static const uint32_t sz[] = { 0, 1, 16, 17, 32, 33, 64, 100, 128, 129, 256, 257, 512, 513, 1000, 1024 };
    static const uint32_t cls[] = { 16, 16, 16, 32, 32, 64, 64, 128, 128, 256, 256, 512, 512, 1024, 1024, 1024 };
    for (unsigned i = 0; i < sizeof(sz) / sizeof(sz[0]); i++) {
        uint8_t *p = slab_alloc(sz[i]);
        CHECK(p != 0);
        if (!p) continue;
        uint64_t off = (uint64_t)(uintptr_t)p - g_slab_base;
        CHECK(off / SLAB_STRIDE == (uint64_t)__builtin_ctz(cls[i] / 16));
        CHECK(((uint64_t)(uintptr_t)p % cls[i]) == 0);               // sejajar ukuran kelas
        memset(p, 0x5A, sz[i]);                                      // ASan/mmap: dalam batas
        CHECK(slab_free(p) == 1);
    }
    CHECK(g_slab_alloc == g_slab_free && g_map_bad == 0);
}

static void test_reject(void)
{
    reset(NFRAME);
    uint8_t *a = slab_alloc(64);
    uint8_t *b = slab_alloc(64);
    CHECK(a && b && a != b);
    CHECK(slab_free(a) == 1 && g_slab_bad_free == 0);
    CHECK(slab_free(a) == 0 && g_slab_bad_free == 1);                // double free
    CHECK(slab_free(b + 1) == 0 && g_slab_bad_free == 2);            // pointer tengah
    CHECK(slab_free(b + 32) == 0 && g_slab_bad_free == 3);           // bukan kelipatan 64
    int x;
    CHECK(slab_free(&x) == 0 && g_slab_bad_free == 4);               // asing (stack)
    CHECK(slab_free(0) == 0 && g_slab_bad_free == 5);
    CHECK(slab_free(g_region - 16) == 0 && g_slab_bad_free == 6);    // sebelum region
    uint8_t *guard = g_region + 2 * SLAB_STRIDE + SLAB_PAGES_MAX * PMM_PAGE_SIZE;
    CHECK(!slab_owns(0) && slab_owns(guard));
    CHECK(slab_free(guard) == 0 && g_slab_bad_free == 7);            // halaman guard
    CHECK(slab_free(g_region + 5 * SLAB_STRIDE + 3 * PMM_PAGE_SIZE) == 0);   // halaman tak dipetakan
    CHECK(slab_free(g_region + SLAB_NCLASS * SLAB_STRIDE) == 0);     // ujung region
    CHECK(g_slab_bad_free == 9 && g_slab_free == 1);
    CHECK(slab_free(b) == 1 && g_slab_alloc == 2 && g_slab_free == 2);
    CHECK(g_map_bad == 0);
}

static void test_exhaust(void)
{
    static uint8_t *held[SLAB_PAGES_MAX * 256 + 8];
    for (uint32_t c = 0; c < SLAB_NCLASS; c++) {
        uint32_t osz = 16u << c, cap = PMM_PAGE_SIZE / osz;
        reset(NFRAME);
        uint64_t n = 0;
        while (n < SLAB_PAGES_MAX * cap + 8 && (held[n] = slab_alloc(osz)) != 0) {
            n++;
        }
        CHECK(n == (uint64_t)SLAB_PAGES_MAX * cap);                  // tepat batas cache
        CHECK(g_slab_fail == 1 && g_slab_pages == SLAB_PAGES_MAX);
        CHECK(slab_alloc(osz) == 0 && g_slab_fail == 2);
        // Kelas lain tidak terpengaruh.
        void *other = slab_alloc(osz == 16 ? 32 : 16);
        CHECK(other != 0 && slab_free(other) == 1);
        // Semua alamat unik, sejajar, dan di dalam sub-region kelas c.
        int ok = 1;
        for (uint64_t i = 0; i < n; i++) {
            uint64_t off = (uint64_t)(uintptr_t)held[i] - g_slab_base;
            if (off / SLAB_STRIDE != c || (off % osz) != 0 || (off % SLAB_STRIDE) / PMM_PAGE_SIZE >= SLAB_PAGES_MAX) ok = 0;
            *(volatile uint8_t *)held[i] = (uint8_t)i;
        }
        CHECK(ok);
        for (uint64_t i = 0; i < n; i++) {
            if (*(volatile uint8_t *)held[i] != (uint8_t)i) ok = 0;   // tidak tumpang tindih
        }
        CHECK(ok);
        for (uint64_t i = 0; i < n; i++) {
            if (!slab_free(held[i])) ok = 0;
        }
        CHECK(ok && g_slab_bad_free == 0);
        // Hanya satu halaman kosong per kelas dipertahankan; frame lain dikembalikan ke pmm.
        CHECK(g_slab_pages <= 2 && g_frames_live == g_slab_pages && g_map_bad == 0);
        CHECK(slab_alloc(osz) != 0);                                 // pulih setelah dibebaskan
    }
}

static void test_pmm_fail(void)
{
    reset(0);
    CHECK(slab_alloc(16) == 0 && g_slab_fail == 1 && g_slab_pages == 0);
    g_frame_limit = 1;
    uint8_t *p = slab_alloc(16);
    CHECK(p != 0);
    // Halaman 16 byte punya 256 slot; frame habis hanya ditolak saat butuh halaman baru.
    for (int i = 1; i < 256; i++) CHECK(slab_alloc(16) != 0);
    CHECK(slab_alloc(16) == 0 && g_slab_fail == 2);
    CHECK(slab_alloc(32) == 0 && g_slab_fail == 3);
    CHECK(slab_free(p) == 1);
    CHECK(slab_alloc(16) == p);
}

#ifdef BMAHOS_PROD
// Varian PROD: tanpa racun. Isi tidak diracun, tulis setelah bebas tidak terhitung.
static void test_poison(void)
{
    reset(NFRAME);
    uint8_t *p = slab_alloc(128);
    memset(p, 0x11, 128);
    CHECK(slab_free(p) == 1);
    CHECK(p[0] == 0x11 && p[127] == 0x11);                           // isi tidak diubah saat bebas
    p[127] = 0;
    CHECK(slab_alloc(128) == p && g_slab_uaf == 0);
    CHECK(slab_selftest() == 1 && g_slab_uaf == 0);
}
#else
static void test_poison(void)
{
    reset(NFRAME);
    uint8_t *p = slab_alloc(128);
    for (int i = 0; i < 128; i++) CHECK(p[i] == SLAB_POISON_BYTE);   // halaman baru sudah diracun
    CHECK(g_slab_uaf == 0);
    memset(p, 0x11, 128);
    CHECK(slab_free(p) == 1);
    for (int i = 0; i < 128; i++) CHECK(p[i] == SLAB_POISON_BYTE);   // diracun saat bebas
    CHECK(slab_alloc(128) == p && g_slab_uaf == 0);
    CHECK(slab_free(p) == 1);
    p[127] = 0;                                                      // tulis setelah bebas
    CHECK(slab_alloc(128) == p && g_slab_uaf == 1);
    // Tulis di objek tetangga yang bebas tidak lolos juga.
    uint8_t *q = slab_alloc(128);
    CHECK(slab_free(q) == 1);
    q[0] ^= 1;
    CHECK(slab_alloc(128) == q && g_slab_uaf == 2);
}
#endif

typedef struct { uint8_t *p; uint32_t size; uint8_t tag; } live_t;

static void test_random(void)
{
    enum { N = 3000 };
    static live_t lv[N];
    reset(NFRAME);
    memset(lv, 0, sizeof(lv));
    uint64_t fails = 0, bad = 0;
    int ok = 1;

    for (int it = 0; it < 400000; it++) {
        uint32_t i = rnd() % N;
        uint32_t r = rnd() % 100;
        if (lv[i].p == 0) {
            uint32_t sz = r < 70 ? 1 + rnd() % 128 : 1 + rnd() % SLAB_MAX_SIZE;
            uint8_t *p = slab_alloc(sz);
            if (!p) { fails++; continue; }
            lv[i].p = p; lv[i].size = sz; lv[i].tag = (uint8_t)(rnd() | 1);
            memset(p, lv[i].tag, sz);
        } else {
            for (uint32_t k = 0; k < lv[i].size; k++) {              // isi utuh = tidak tumpang tindih
                if (lv[i].p[k] != lv[i].tag) { ok = 0; break; }
            }
            if (!slab_free(lv[i].p)) ok = 0;
            if (r < 5) {                                             // double free sengaja
                if (slab_free(lv[i].p) != 0) ok = 0;
                bad++;
            } else if (r < 8) {
                if (slab_free(lv[i].p + 1) != 0) ok = 0;
                bad++;
            }
            lv[i].p = 0;
        }
    }
    CHECK(ok);
    CHECK(g_slab_bad_free == bad && g_slab_uaf == 0);
    CHECK(g_slab_fail == fails && g_map_bad == 0);
    for (int i = 0; i < N; i++) {
        if (lv[i].p && !slab_free(lv[i].p)) ok = 0;
    }
    CHECK(ok && g_slab_alloc == g_slab_free);
    CHECK(g_frames_live == g_slab_pages && g_slab_pages <= SLAB_NCLASS);   // semua dikembalikan kecuali cadangan
}

static void test_selftest(void)
{
    reset(NFRAME);
    serial_capture_reset();
    CHECK(slab_selftest() == 1);
    // Penolakan disengaja dikembalikan: metrics produksi bersih setelah self-test.
    CHECK(g_slab_bad_free == 0 && g_slab_uaf == 0 && g_slab_fail == 0 && g_slab_alloc == g_slab_free);
    CHECK(strstr(g_serial_cap, "SLAB: self-test PASS") != 0 && strstr(g_serial_cap, "bad_free=3") != 0);
    g_slab_fail = 5; g_slab_bad_free = 6; g_slab_uaf = 7;             // nilai awal bukan nol ikut dipulihkan
    CHECK(slab_selftest() == 1 && g_slab_fail == 5 && g_slab_bad_free == 6 && g_slab_uaf == 7);
    CHECK(g_map_bad == 0);
    reset(NFRAME);
    g_slab_base = 0;                                                 // belum slab_init: ditolak, tak crash
    CHECK(slab_alloc(16) == 0 && !slab_owns(g_region));
}

int main(void)
{
    g_region = mmap(0, (size_t)SLAB_NCLASS * SLAB_STRIDE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    CHECK(g_region != MAP_FAILED && ((uintptr_t)g_region % PMM_PAGE_SIZE) == 0);
    test_basic();
    test_reject();
    test_exhaust();
    test_pmm_fail();
    test_poison();
    test_random();
    test_selftest();
    #ifdef BMAHOS_PROD
    return test_done("slab_prod");
#else
    return test_done("slab");
#endif
}

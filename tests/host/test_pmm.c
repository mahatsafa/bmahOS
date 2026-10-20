// R6-3: uji pmm.c di host (di-#include: akses bitmap static). Memmap tiruan
// lewat tests/host/limine.h; alamat fisik hanya angka (tidak pernah dibaca).

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

#include "pmm.c"

static struct limine_memmap_entry g_ent[3];
static struct limine_memmap_entry *g_ents[3] = { &g_ent[0], &g_ent[1], &g_ent[2] };
static struct limine_memmap_response g_mm = { 0, 3, g_ents };

static void reset_counters(void)
{
    g_pmm_allocs = g_pmm_frees = g_pmm_fail = g_pmm_bad_free = 0;
}

// Usable: frame 0..7 (frame 0 selalu dicadangkan) + 0x100..0x103 (base tidak
// sejajar dibulatkan ke atas, ujung dibulatkan ke bawah); satu entri reserved.
static void init_map(void)
{
    g_ent[0] = (struct limine_memmap_entry){ 0x0, 8 * PMM_PAGE_SIZE, LIMINE_MEMMAP_USABLE };
    g_ent[1] = (struct limine_memmap_entry){ 0x9000, 0x4000, LIMINE_MEMMAP_RESERVED };
    g_ent[2] = (struct limine_memmap_entry){ 0x100000 - 0x800, 4 * PMM_PAGE_SIZE + 0x1000,
                                             LIMINE_MEMMAP_USABLE };
    pmm_init(&g_mm);
    reset_counters();
}

static void test_init(void)
{
    init_map();
    CHECK(pmm_bitmap_test(0) == 1);          // frame 0 = tanda gagal, tidak dibagikan
    CHECK(pmm_bitmap_test(1) == 0 && pmm_bitmap_test(7) == 0);
    CHECK(pmm_bitmap_test(8) == 1);
    CHECK(pmm_bitmap_test(9) == 1);          // reserved
    CHECK(pmm_bitmap_test(0xff) == 1);       // base tidak sejajar: halaman pertama dibuang
    CHECK(pmm_bitmap_test(0x100) == 0 && pmm_bitmap_test(0x103) == 0);
    CHECK(pmm_bitmap_test(0x104) == 1);
    CHECK(pmm_usable_frames == 7 + 4);
    CHECK(pmm_usable_memory == 11 * PMM_PAGE_SIZE);
}

static void test_exhaust(void)
{
    uint64_t got[16];
    int n = 0;

    init_map();
    for (;;) {
        uint64_t p = pmm_alloc();
        if (p == 0) {
            break;
        }
        CHECK(n < 16);
        if (n >= 16) {
            break;
        }
        CHECK((p & (PMM_PAGE_SIZE - 1)) == 0);
        for (int i = 0; i < n; i++) {
            CHECK(got[i] != p);   // tidak ada frame dibagikan dua kali
        }
        got[n++] = p;
    }
    CHECK(n == 11);
    CHECK(got[0] == PMM_PAGE_SIZE);   // bukan frame 0
    CHECK(g_pmm_allocs == 11 && g_pmm_fail == 1);
    CHECK(pmm_alloc() == 0 && g_pmm_fail == 2);   // tetap gagal, tidak menebak

    // Lepas satu di tengah -> dipakai lagi (pmm_next_frame mundur).
    pmm_free(got[5]);
    CHECK(g_pmm_frees == 1 && pmm_bitmap_test(got[5] / PMM_PAGE_SIZE) == 0);
    CHECK(pmm_alloc() == got[5]);
    CHECK(g_pmm_allocs == 12 && g_pmm_allocs - g_pmm_frees == 11);

    for (int i = 0; i < n; i++) {
        pmm_free(got[i]);
    }
    CHECK(g_pmm_frees == 12 && g_pmm_bad_free == 0);
    CHECK(g_pmm_allocs == g_pmm_frees);   // seimbang = tanpa kebocoran
}

static void test_bad_free(void)
{
    init_map();
    uint64_t p = pmm_alloc();

    pmm_free(p);
    pmm_free(p);                          // double free: dihitung, tidak di-clear ulang
    CHECK(g_pmm_frees == 1 && g_pmm_bad_free == 1);
    pmm_free(p + 8);                      // tidak sejajar
    pmm_free(PMM_MAX_PHYS_ADDR);          // di luar bitmap
    pmm_free(0x9000);                     // batasan: bitmap tidak membedakan reserved/terpakai
    CHECK(g_pmm_bad_free == 3);
    CHECK(g_pmm_frees == 2);
    pmm_free(0);                          // no-op, bukan kesalahan
    CHECK(g_pmm_bad_free == 3 && g_pmm_frees == 2);
    CHECK(pmm_bitmap_test(0) == 1);
}

int main(void)
{
    test_init();
    test_exhaust();
    test_bad_free();
    return test_done("pmm");
}

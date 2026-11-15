// Uji is_valid_user_ptr / vmm_user_mapped (vmm.c) di host dengan tabel halaman tiruan:
// "fisik" = alamat host (hhdm_offset 0). Mencakup pointer half atas (HHDM/kernel),
// overflow, batas kanonik, halaman 2 MB / 1 GB (bit PS), dan hak tulis di semua level.

#include <stdint.h>
#include <stdlib.h>
#include "test.h"
#include "vmm.c"

// ---- stub untuk vmm.c ----
struct cpu_features g_cpu;
uint64_t hhdm_offset = 0;
static uint64_t g_next;
static uint64_t g_pool[16][512] __attribute__((aligned(4096)));

uint64_t pmm_alloc(void)
{
    return g_next < 16 ? (uint64_t)(uintptr_t)g_pool[g_next++] : 0;
}

void pmm_free(uint64_t phys)
{
    (void)phys;   // F7: dipakai slab.c, tidak dijalankan di uji ini
}

void oom_panic(const char *where)
{
    (void)where;
    abort();
}

#define RW (VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER)
#define RO (VMM_FLAG_PRESENT | VMM_FLAG_USER)

static uint64_t phys(uint64_t *t)
{
    return (uint64_t)(uintptr_t)t;
}

static void test_ptr(void)
{
    memset(g_pool, 0, sizeof(g_pool));
    g_next = 0;
    uint64_t *pml4 = g_pool[g_next++];

    // 4 KB: 0x400000 (R/W) dan 0x401000 (baca-saja); PML4[0] -> PDPT -> PD -> PT.
    vmm_map(phys(pml4), 0x400000, 0x1000, RW);
    vmm_map(phys(pml4), 0x401000, 0x2000, RO);
    CHECK(is_valid_user_ptr(phys(pml4), 0x400000, 4096, true));
    CHECK(is_valid_user_ptr(phys(pml4), 0x400ff0, 16, true));
    CHECK(is_valid_user_ptr(phys(pml4), 0x400000, 0, true));
    CHECK(!is_valid_user_ptr(phys(pml4), 0x400ff0, 17, true));   // melewati ke halaman baca-saja
    CHECK(is_valid_user_ptr(phys(pml4), 0x400ff0, 17, false));   // baca boleh
    CHECK(!is_valid_user_ptr(phys(pml4), 0x401000, 1, true));    // tulis ke baca-saja
    CHECK(!is_valid_user_ptr(phys(pml4), 0x402000, 1, false));   // tidak dipetakan

    // Hak tulis harus ada di SEMUA level: matikan W di PDPT.
    uint64_t *pdpt = (uint64_t *)(uintptr_t)(pml4[0] & VMM_ENTRY_ADDR_MASK);
    pdpt[0] &= ~VMM_FLAG_WRITABLE;
    CHECK(!is_valid_user_ptr(phys(pml4), 0x400000, 1, true));
    CHECK(is_valid_user_ptr(phys(pml4), 0x400000, 1, false));
    pdpt[0] |= VMM_FLAG_WRITABLE;
    CHECK(is_valid_user_ptr(phys(pml4), 0x400000, 1, true));

    // U harus ada di semua level: PD tanpa U -> ditolak.
    uint64_t *pd = (uint64_t *)(uintptr_t)(pdpt[0] & VMM_ENTRY_ADDR_MASK);
    pd[2] &= ~VMM_FLAG_USER;   // 0x400000 >> 21 = 2
    CHECK(!is_valid_user_ptr(phys(pml4), 0x400000, 1, false));
    pd[2] |= VMM_FLAG_USER;
    CHECK(is_valid_user_ptr(phys(pml4), 0x400000, 1, false));
}

static void test_range(void)
{
    memset(g_pool, 0, sizeof(g_pool));
    g_next = 0;
    uint64_t *pml4 = g_pool[g_next++];

    vmm_map(phys(pml4), 0x400000, 0x1000, RW);
    // Overflow ptr + len.
    CHECK(!is_valid_user_ptr(phys(pml4), 0x400000, UINT64_MAX, false));
    CHECK(!is_valid_user_ptr(phys(pml4), UINT64_MAX - 3, 8, false));
    CHECK(!is_valid_user_ptr(phys(pml4), 0xffffffffffffff00ULL, 0x200, false));
    // Batas kanonik: halaman terakhir half bawah, dan melewati batas.
    vmm_map(phys(pml4), VMM_USER_END - 4096, 0x3000, RW);
    CHECK(is_valid_user_ptr(phys(pml4), VMM_USER_END - 4096, 4096, true));
    CHECK(!is_valid_user_ptr(phys(pml4), VMM_USER_END - 4096, 4097, true));
    CHECK(!is_valid_user_ptr(phys(pml4), VMM_USER_END - 1, 2, false));
    CHECK(!is_valid_user_ptr(phys(pml4), VMM_USER_END, 1, false));
    // Pointer half atas (HHDM tipikal, kernel higher-half): ditolak sebelum walk.
    CHECK(!is_valid_user_ptr(phys(pml4), 0xffff800000000000ULL, 16, false));
    CHECK(!is_valid_user_ptr(phys(pml4), 0xffffffff80000000ULL, 16, true));
    CHECK(!is_valid_user_ptr(phys(pml4), 0xffff9840000a0000ULL, 1, false));
    // Alamat non-kanonik.
    CHECK(!is_valid_user_ptr(phys(pml4), VMM_USER_END, 1, false));
    CHECK(!is_valid_user_ptr(phys(pml4), 0x00ff000000000000ULL, 1, false));
}

static void test_huge(void)
{
    memset(g_pool, 0, sizeof(g_pool));
    g_next = 0;
    uint64_t *pml4 = g_pool[g_next++];
    uint64_t *pdpt = g_pool[g_next++];
    uint64_t *pd = g_pool[g_next++];

    // PML4[0] -> PDPT; PDPT[0] -> PD; PD[1] = halaman 2 MB user (0x200000..0x3fffff).
    pml4[0] = phys(pdpt) | RW;
    pdpt[0] = phys(pd) | RW;
    pd[1] = 0x200000 | RW | 0x80;
    CHECK(is_valid_user_ptr(phys(pml4), 0x200000, 0x200000, true));
    CHECK(!is_valid_user_ptr(phys(pml4), 0x200000, 0x200001, true));   // keluar dari 2 MB
    // Halaman 2 MB TANPA U (mirip HHDM): ditolak, dan walk tidak turun ke "PT" palsu.
    pd[2] = 0x400000 | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | 0x80;
    CHECK(!is_valid_user_ptr(phys(pml4), 0x400000, 1, false));
    // 1 GB: PDPT[1] user vs bukan user.
    pdpt[1] = 0x40000000 | RW | 0x80;
    pdpt[2] = 0x80000000 | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | 0x80;
    CHECK(is_valid_user_ptr(phys(pml4), 0x40000000, 4096, true));
    CHECK(is_valid_user_ptr(phys(pml4), 0x7ffff000, 4096, true));
    CHECK(!is_valid_user_ptr(phys(pml4), 0x80000000, 1, false));
    // Entri PDPT 1 GB yang isinya menyerupai pointer tabel tidak pernah diikuti:
    // alamat isi = tabel palsu berisi P|U|W di semua slot.
    uint64_t *fake = g_pool[g_next++];
    for (int i = 0; i < 512; i++) {
        fake[i] = 0x1000 | RW;
    }
    pdpt[3] = phys(fake) | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | 0x80;   // 1 GB tanpa U
    CHECK(!is_valid_user_ptr(phys(pml4), 0xC0000000, 1, false));

    // vmm_user_mapped: sama dengan jalan baca.
    CHECK(vmm_user_mapped(phys(pml4), 0x200000));
    CHECK(!vmm_user_mapped(phys(pml4), 0x400000));
    CHECK(!vmm_user_mapped(phys(pml4), 0xffff800000000000ULL));
}

int main(void)
{
    test_ptr();
    test_range();
    test_huge();
    return test_done("vmm");
}

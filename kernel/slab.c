// F7: slab allocator untuk objek kecil (<= SLAB_MAX_SIZE), di bawah kmalloc.
//
// Desain (alasan lengkap di DECISIONS.md):
// - 7 cache ukuran tetap 16, 32, ..., 1024 byte (pangkat dua). Satu slab = satu halaman
//   4 KB dari pmm, dipetakan P|W|NX di region SLAB_START (PML4 0x130, bersama kheap).
//   Tiap cache punya sub-region sendiri SLAB_PAGES_MAX halaman + 1 halaman guard tak
//   dipetakan, jadi alamat -> (cache, halaman) = pembagian, tanpa pencarian.
// - Metadata (bitmap objek terpakai per halaman) ada di .bss, BUKAN di dalam halaman:
//   tulis melewati ujung objek tidak merusak metadata, dan pointer asing tidak pernah
//   dibaca sebagai header.
// - Batas: SLAB_PAGES_MAX halaman per cache (64 -> 256 KB, total 7 cache <= 1,75 MB).
//   Penuh -> slab_alloc mengembalikan 0 (g_slab_fail++), kmalloc meneruskan NULL.
// - Halaman kosong dilepas ke pmm (unmap + pmm_free) kecuali satu cadangan per cache,
//   sehingga akses lewat pointer lama ke halaman yang dilepas jadi #PF, bukan diam-diam.
// - Build dev (bukan BMAHOS_PROD): objek bebas diisi 0xA5; saat dialokasikan lagi, isi
//   yang berubah dihitung g_slab_uaf (use-after-free tertulis).
// - Satu core, tanpa kunci: JANGAN dipanggil dari ISR atau dua task bersamaan tanpa
//   preempt-off (pemanggil kmalloc saat ini hanya kmain/boot).

#include "kernel.h"

#define SLAB_POISON_BYTE 0xA5
#define SLAB_POISON_WORD 0xA5A5A5A5A5A5A5A5ULL
#ifdef BMAHOS_PROD
#define SLAB_POISON_ON 0
#else
#define SLAB_POISON_ON 1
#endif

typedef struct {
    uint64_t phys;        // frame pmm halaman ini (0 bila tak dipetakan)
    uint64_t bits[4];     // bit 1 = terpakai (bit di luar cap diset 1: tak pernah dipilih)
    uint16_t inuse;       // jumlah objek terpakai
    uint8_t  mapped;
} slab_page_t;

static slab_page_t g_slab_pg[SLAB_NCLASS][SLAB_PAGES_MAX];
static uint64_t g_slab_base;
static uint64_t g_slab_pml4;

uint64_t g_slab_alloc, g_slab_free, g_slab_fail, g_slab_pages, g_slab_bad_free, g_slab_uaf;
uint64_t g_slab_leak;   // SMP-2: frame yang dibocorkan karena shootdown TLB tidak lengkap

static uint32_t slab_size_of(uint32_t c)
{
    return (uint32_t)SLAB_MIN_SIZE << c;
}

static uint32_t slab_cap_of(uint32_t c)
{
    return PMM_PAGE_SIZE / slab_size_of(c);
}

static void slab_fill(uint64_t vaddr, uint64_t n)
{
    uint64_t *w = (uint64_t *)vaddr;

    for (uint64_t i = 0; i < n / 8; i++) {
        w[i] = SLAB_POISON_WORD;
    }
}

static int slab_poison_ok(uint64_t vaddr, uint64_t n)
{
    const uint64_t *w = (const uint64_t *)vaddr;

    for (uint64_t i = 0; i < n / 8; i++) {
        if (w[i] != SLAB_POISON_WORD) {
            return 0;
        }
    }
    return 1;
}

static uint64_t slab_vaddr(uint32_t c, uint32_t n)
{
    return g_slab_base + (uint64_t)c * SLAB_STRIDE + (uint64_t)n * PMM_PAGE_SIZE;
}

void slab_init(uint64_t pml4_phys, uint64_t base)
{
    g_slab_pml4 = pml4_phys;
    g_slab_base = base;
}

int slab_owns(const void *p)
{
    uint64_t a = (uint64_t)(uintptr_t)p;

    return g_slab_base != 0 && a >= g_slab_base &&
           a - g_slab_base < (uint64_t)SLAB_NCLASS * SLAB_STRIDE;
}

// 0 bila ukuran di luar jangkauan slab (> SLAB_MAX_SIZE) atau gagal (cache penuh / pmm habis).
void *slab_alloc(uint64_t size)
{
    if (g_slab_base == 0 || size > SLAB_MAX_SIZE) {
        return (void *)0;
    }

    uint32_t c = 0;
    if (size > SLAB_MIN_SIZE) {
        c = (uint32_t)(64 - __builtin_clzll(size - 1)) - SLAB_MIN_SHIFT;
    }
    uint32_t cap = slab_cap_of(c);
    uint32_t osz = slab_size_of(c);

    // Utamakan halaman yang sebagian terisi (supaya halaman kosong bisa dilepas).
    int part = -1, empty = -1, unmapped = -1;
    for (uint32_t n = 0; n < SLAB_PAGES_MAX; n++) {
        slab_page_t *pg = &g_slab_pg[c][n];
        if (!pg->mapped) {
            if (unmapped < 0) {
                unmapped = (int)n;
            }
        } else if (pg->inuse < cap) {
            if (pg->inuse > 0) {
                part = (int)n;
                break;
            }
            if (empty < 0) {
                empty = (int)n;
            }
        }
    }

    int n = part >= 0 ? part : empty;
    if (n < 0) {
        if (unmapped < 0) {
            g_slab_fail++;
            serial_write("slab: cache penuh (SLAB_PAGES_MAX), alokasi ditolak\r\n");
            return (void *)0;
        }
        uint64_t phys = pmm_alloc();
        if (phys == 0) {
            g_slab_fail++;
            serial_write("slab: pmm_alloc() gagal, alokasi ditolak\r\n");
            return (void *)0;
        }
        n = unmapped;
        uint64_t va = slab_vaddr(c, (uint32_t)n);
        vmm_map(g_slab_pml4, va, phys, VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NX);
        slab_page_t *np = &g_slab_pg[c][n];
        np->phys = phys;
        np->inuse = 0;
        np->mapped = 1;
        for (uint32_t w = 0; w < 4; w++) {
            uint32_t lo = w * 64;
            np->bits[w] = lo >= cap ? ~0ULL : (lo + 64 <= cap ? 0 : ~0ULL << (cap - lo));
        }
        if (SLAB_POISON_ON) {
            slab_fill(va, PMM_PAGE_SIZE);
        }
        g_slab_pages++;
    }

    slab_page_t *pg = &g_slab_pg[c][n];
    uint32_t idx = 0;
    for (uint32_t w = 0; w < 4; w++) {
        if (~pg->bits[w] != 0) {
            idx = w * 64 + (uint32_t)__builtin_ctzll(~pg->bits[w]);
            break;
        }
    }
    pg->bits[idx / 64] |= 1ULL << (idx % 64);
    pg->inuse++;

    uint64_t obj = slab_vaddr(c, (uint32_t)n) + (uint64_t)idx * osz;
    if (SLAB_POISON_ON && !slab_poison_ok(obj, osz)) {
        g_slab_uaf++;
        serial_write("slab: PERINGATAN objek bebas berubah (use-after-free tertulis)\r\n");
    }
    g_slab_alloc++;
    return (void *)(uintptr_t)obj;
}

// 1 = dibebaskan. 0 = ditolak (g_slab_bad_free++): bukan awal objek, halaman tak
// dipetakan, atau objek sudah bebas (double free).
int slab_free(void *p)
{
    if (!slab_owns(p)) {
        g_slab_bad_free++;
        serial_write("slab: kfree pointer asing ditolak\r\n");
        return 0;
    }

    uint64_t off = (uint64_t)(uintptr_t)p - g_slab_base;
    uint32_t c = (uint32_t)(off / SLAB_STRIDE);
    uint64_t r = off % SLAB_STRIDE;
    uint32_t n = (uint32_t)(r / PMM_PAGE_SIZE);
    uint32_t osz = slab_size_of(c);
    uint32_t o = (uint32_t)(r % PMM_PAGE_SIZE);

    if (n >= SLAB_PAGES_MAX || !g_slab_pg[c][n].mapped || (o % osz) != 0) {
        g_slab_bad_free++;
        serial_write("slab: kfree bukan awal objek / halaman tak aktif, ditolak\r\n");
        return 0;
    }

    slab_page_t *pg = &g_slab_pg[c][n];
    uint32_t idx = o / osz;
    if (!(pg->bits[idx / 64] & (1ULL << (idx % 64)))) {
        g_slab_bad_free++;
        serial_write("slab: double free terdeteksi, ditolak\r\n");
        return 0;
    }

    pg->bits[idx / 64] &= ~(1ULL << (idx % 64));
    pg->inuse--;
    g_slab_free++;
    if (SLAB_POISON_ON) {
        slab_fill((uint64_t)(uintptr_t)p, osz);
    }

    if (pg->inuse == 0) {
        // Satu halaman kosong per cache dipertahankan; yang kedua dilepas ke pmm.
        int other = 0;
        for (uint32_t m = 0; m < SLAB_PAGES_MAX; m++) {
            if (m != n && g_slab_pg[c][m].mapped && g_slab_pg[c][m].inuse == 0) {
                other = 1;
                break;
            }
        }
        if (other) {
            if (vmm_unmap(g_slab_pml4, slab_vaddr(c, n))) {
                pmm_free(pg->phys);
            } else {
                // SMP-2: ada CPU yang belum membatalkan TLB: frame dibocorkan (bukan dipakai ulang).
                g_slab_leak++;
                kprintf("slab: frame dibocorkan (shootdown TLB tidak lengkap), total %lu\r\n", g_slab_leak);
            }
            pg->phys = 0;
            pg->mapped = 0;
            g_slab_pages--;
        }
    }
    return 1;
}

// Uji boot: urutan fungsi publik, termasuk penolakan (double free, pointer asing) dan
// batas cache. Seimbang: semua objek uji dibebaskan; counter bad_free/uaf/fail naik
// sesuai rencana (lihat qemu-smoke).
int slab_selftest(void)
{
    int step = 0;
    uint64_t live0 = g_slab_alloc - g_slab_free;
    uint64_t pages0 = g_slab_pages;
    uint64_t bad0 = g_slab_bad_free, fail0 = g_slab_fail, uaf0 = g_slab_uaf;

    step = 1;
    uint8_t *a = slab_alloc(1), *b = slab_alloc(16), *c = slab_alloc(17), *d = slab_alloc(1024);
    if (!a || !b || !c || !d || a == b || b == c || c == d || ((uint64_t)(uintptr_t)c & 31) ||
        ((uint64_t)(uintptr_t)d & 1023)) {
        goto gagal;
    }
    step = 2;
    for (int i = 0; i < 16; i++) { a[i] = 1; b[i] = 2; }
    for (int i = 0; i < 32; i++) { c[i] = 3; }
    for (int i = 0; i < 1024; i++) { d[i] = 4; }
    for (int i = 0; i < 16; i++) { if (a[i] != 1 || b[i] != 2) goto gagal; }
    step = 3;
    if (!slab_free(a) || slab_alloc(16) != a) {   // bit bebas terendah dipakai ulang
        goto gagal;
    }
    step = 4;
    if (slab_free(a) != 1 || slab_free(a) != 0 || g_slab_bad_free != bad0 + 1) {
        goto gagal;                              // double free ditolak
    }
    step = 5;
    int local = 0;
    if (slab_free(&local) != 0 || slab_free(b + 1) != 0 || g_slab_bad_free != bad0 + 3) {
        goto gagal;                              // pointer asing dan pointer tengah objek
    }
    if (SLAB_POISON_ON) {
        step = 6;
        uint8_t *u = slab_alloc(64);
        if (!u || !slab_free(u)) goto gagal;
        u[9] = 0x42;                             // tulis setelah free (sengaja)
        if (slab_alloc(64) != u || g_slab_uaf != uaf0 + 1) goto gagal;
        if (!slab_free(u)) goto gagal;
    }
    step = 7;
    if (!slab_free(b) || !slab_free(c) || !slab_free(d)) {
        goto gagal;
    }
    step = 8;                                    // batas cache 1024: 4 objek/halaman
    {
        static void *held[SLAB_PAGES_MAX * 4];
        uint32_t n = 0;
        while (n < SLAB_PAGES_MAX * 4 && (held[n] = slab_alloc(1024)) != 0) {
            n++;
        }
        int bad = n != SLAB_PAGES_MAX * 4 || slab_alloc(1024) != 0 || g_slab_fail != fail0 + 1;
        for (uint32_t i = 0; i < n; i++) {   // dibebaskan juga bila uji di atas gagal
            if (!slab_free(held[i])) bad = 1;
        }
        if (bad) {
            goto gagal;
        }
    }
    step = 9;
    // Keseimbangan: tidak ada objek tersisa, halaman kembali (maks. satu cadangan baru per kelas yang disentuh).
    if (g_slab_alloc - g_slab_free != live0 || g_slab_pages > pages0 + 4) {
        goto gagal;
    }
    kprintf("SLAB: self-test PASS (kelas=%d 16..%d byte, maks %d halaman/cache, bad_free=%d)\r\n",
            SLAB_NCLASS, SLAB_MAX_SIZE, SLAB_PAGES_MAX, (int)(g_slab_bad_free - bad0));
    // Penolakan/kegagalan di atas disengaja: kembalikan counter supaya metrics produksi bersih
    // (nilai > 0 setelah boot = kejadian nyata). Buktinya baris SLAB di serial.
    g_slab_bad_free = bad0;
    g_slab_fail = fail0;
    g_slab_uaf = uaf0;
    return 1;
gagal:
    kprintf("SLAB: self-test GAGAL (langkah %d)\r\n", step);
    return 0;
}

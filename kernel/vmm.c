#include "kernel.h"

uint64_t read_cr3(void)
{
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

void vmm_dump_pml4(uint64_t pml4_phys)
{
    // Konversi physical -> virtual lewat HHDM, supaya CPU
    // bisa baca isinya (CPU tidak bisa akses physical address
    // secara langsung).
    uint64_t *pml4_virt =
        (uint64_t *)(pml4_phys + hhdm_offset);

    serial_write("PML4 non-empty entries:\r\n");

    for (uint64_t i = 0; i < 512; i++) {
        uint64_t entry = pml4_virt[i];

        // Bit 0 = present bit. Skip entry kosong supaya log
        // tidak banjir (PML4 biasanya sebagian besar kosong).
        if ((entry & 0x1) == 0) {
            continue;
        }

        serial_write("  PML4[");
        serial_write_hex(i);
        serial_write("] = ");
        serial_write_hex(entry);
        serial_write("\r\n");
    }
}

// B3: 1 jika EFER.NXE aktif (diisi nx_init()). Tanpa NXE, bit 63 di PTE
// adalah bit reserved (#PF), jadi vmm_map() membuangnya.
int g_vmm_nx_ok = 0;

static uint64_t vmm_get_or_create_table(uint64_t *table_virt, uint64_t index)
{
    uint64_t entry = table_virt[index];

    if (entry & VMM_FLAG_PRESENT) {
        return entry & VMM_ENTRY_ADDR_MASK;
    }

    uint64_t new_table_phys = pmm_alloc();
    if (new_table_phys == 0) {
        serial_write("VMM: pmm_alloc() FAILED\r\n");
        return 0;
    }

    uint64_t *new_table_virt = (uint64_t *)(new_table_phys + hhdm_offset);
    for (uint64_t i = 0; i < 512; i++) {
        new_table_virt[i] = 0;
    }

    // Tabel perantara SELALU diberi US=1 -- ini standar desain
    // paging x86: izin akhir tetap ditentukan gabungan semua level,
    // jadi US=1 di tabel perantara tidak membuka akses apa pun
    // kalau PTE (leaf) tidak ikut diberi US=1.
    table_virt[index] = new_table_phys | VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_USER;
    return new_table_phys;
}
void vmm_map(uint64_t pml4_phys, uint64_t vaddr, uint64_t paddr, uint64_t flags)
{
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;
    uint64_t *pml4_virt = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t pdpt_phys = vmm_get_or_create_table(pml4_virt, pml4_idx);
    if (pdpt_phys == 0) return;
    uint64_t *pdpt_virt = (uint64_t *)(pdpt_phys + hhdm_offset);
    uint64_t pd_phys = vmm_get_or_create_table(pdpt_virt, pdpt_idx);
    if (pd_phys == 0) return;
    uint64_t *pd_virt = (uint64_t *)(pd_phys + hhdm_offset);
    uint64_t pt_phys = vmm_get_or_create_table(pd_virt, pd_idx);
    if (pt_phys == 0) return;
    uint64_t *pt_virt = (uint64_t *)(pt_phys + hhdm_offset);
    if (!g_vmm_nx_ok) {
        flags &= ~VMM_FLAG_NX;
    }
    pt_virt[pt_idx] = (paddr & VMM_ENTRY_ADDR_MASK) | flags;
}

// B3: NX efektif untuk vaddr = OR bit 63 di semua level sampai entri daun
// (halaman 1 GB/2 MB berhenti di PDPT/PD). Return -1 jika tidak terpetakan.
int vmm_nx_of(uint64_t pml4_phys, uint64_t vaddr)
{
    uint64_t table = pml4_phys;
    uint64_t nx = 0;

    for (int level = 3; level >= 0; level--) {
        uint64_t *t = (uint64_t *)(table + hhdm_offset);
        uint64_t e = t[(vaddr >> (12 + 9 * level)) & 0x1FF];

        if (!(e & VMM_FLAG_PRESENT)) {
            return -1;
        }

        nx |= e & VMM_FLAG_NX;

        if (level == 0 || ((level == 1 || level == 2) && (e & 0x80))) {
            return nx ? 1 : 0;
        }

        table = e & VMM_ENTRY_ADDR_MASK;
    }

    return -1;
}

// Butuh cpu_features_init() lebih dulu (F1.8a: NX dibaca dari g_cpu).
void nx_init(void)
{
    if (!g_cpu.nx) {
        serial_write("NX: CPU tidak mendukung NX/XD, halaman data tetap executable\r\n");
        return;
    }

    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));

    if (!(lo & (1u << 11))) {
        lo |= 1u << 11;
        __asm__ volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(0xC0000080u));
        serial_write("NX: EFER.NXE dinyalakan kernel\r\n");
    } else {
        serial_write("NX: EFER.NXE sudah aktif (dari Limine)\r\n");
    }

    g_vmm_nx_ok = 1;
}

// Layer 8 checkpoint 1 (dormant, belum dipanggil manapun): bikin PML4
// baru untuk SATU user task, cuma berisi entri kernel-shared yang
// diperlukan (HHDM, kernel higher-half, MMIO APIC/IOAPIC, kheap).
// SENGAJA TIDAK menyalin semua 512 entri PML4 -- terbukti lewat
// vmm_dump_pml4() nyata (boot log) bahwa PML4[0x000] mencakup SELURUH
// rentang alamat rendah 0x0-0x7FFFFFFFFF, tempat SEMUA user task
// (USER_CODE_VADDR dkk) berada. Kalau index itu ikut disalin, PML4
// baru akan menunjuk ke PDPT/PD/PT YANG SAMA dengan task lain --
// isolasi nol walau kelihatannya sudah punya PML4 terpisah. Index di
// bawah ini WAJIB diverifikasi ulang lewat vmm_dump_pml4() kalau
// layout memori (HHDM offset, KHEAP_START, dst) berubah di masa
// depan -- ini bukan konstanta arsitektural x86, murni hasil
// observasi layout bmahOS SEKARANG.

uint64_t vmm_clone_kernel_pml4(uint64_t kernel_pml4_phys)
{
    uint64_t new_pml4_phys = pmm_alloc();
    if (new_pml4_phys == 0) {
        serial_write("vmm_clone_kernel_pml4(): pmm_alloc() FAILED\r\n");
        return 0;
    }

    uint64_t *new_pml4_virt = (uint64_t *)(new_pml4_phys + hhdm_offset);
    for (uint64_t i = 0; i < 512; i++) {
        new_pml4_virt[i] = 0;
    }

    uint64_t *kernel_pml4_virt = (uint64_t *)(kernel_pml4_phys + hhdm_offset);

    static const uint64_t shared_indices[] = {
        VMM_SHARED_PML4_IDX_HHDM,
        VMM_SHARED_PML4_IDX_APIC1,
        VMM_SHARED_PML4_IDX_APIC2,
        VMM_SHARED_PML4_IDX_KHEAP,
        VMM_SHARED_PML4_IDX_KERNEL,
    };

    for (uint64_t i = 0; i < sizeof(shared_indices) / sizeof(shared_indices[0]); i++) {
        uint64_t idx = shared_indices[i];
        new_pml4_virt[idx] = kernel_pml4_virt[idx];
    }

    // Index 0 (alamat rendah, tempat user code/stack) SENGAJA
    // dibiarkan 0 (belum present) -- akan terisi fresh saat vmm_map()
    // dipanggil untuk memetakan user code/stack milik task ini,
    // lewat vmm_get_or_create_table() yang otomatis alokasi PDPT/PD/PT
    // baru karena entry-nya belum present di PML4 baru ini.

    return new_pml4_phys;
}

// ===============================================================
// Syscall pointer validation (Layer 7 lanjutan)
//
// vmm_is_user_page(): walk page table READ-ONLY untuk SATU alamat
// (dibulatkan ke awal halaman 4KB). BEDA dari vmm_get_or_create_table()
// yang dipakai vmm_map() -- fungsi ini TIDAK PERNAH mengalokasikan
// tabel baru. Kalau level manapun (PML4/PDPT/PD/PT) belum present,
// itu berarti alamat tersebut PASTI belum pernah di-map -- otomatis
// tidak valid, tidak perlu jalan lebih jauh.
//
// Syarat valid: seluruh level present DAN leaf (PTE) punya bit US=1
// (VMM_FLAG_USER). US=1 di tabel perantara saja TIDAK CUKUP -- x86
// paging AND semua level, tapi untuk tujuan "boleh diakses ring 3",
// yang benar-benar menentukan adalah PTE (leaf), karena tabel
// perantara SELALU diberi US=1 oleh vmm_get_or_create_table() (lihat
// komentarnya) sehingga tidak bisa dipakai membedakan kernel vs user
// page.
// Checkpoint permission: require_writable menambahkan syarat WRITABLE
// DI ATAS syarat USER, bukan menggantikannya -- pemanggil yang minta
// require_writable=true tetap harus lolos cek USER seperti biasa,
// baru kemudian PTE juga wajib punya VMM_FLAG_WRITABLE. Halaman non-
// writable (mis. hipotetis code page read-only) tetap valid diakses
// kalau require_writable=false (dipakai untuk syscall yang membaca
// dari user, seperti SYS_WRITE).
static bool vmm_is_user_page(uint64_t pml4_phys, uint64_t vaddr, bool require_writable)
{
    uint64_t pml4_idx = (vaddr >> 39) & 0x1FF;
    uint64_t pdpt_idx = (vaddr >> 30) & 0x1FF;
    uint64_t pd_idx   = (vaddr >> 21) & 0x1FF;
    uint64_t pt_idx   = (vaddr >> 12) & 0x1FF;

    uint64_t *pml4_virt = (uint64_t *)(pml4_phys + hhdm_offset);
    uint64_t pml4_entry = pml4_virt[pml4_idx];
    if ((pml4_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pdpt_phys = pml4_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pdpt_virt = (uint64_t *)(pdpt_phys + hhdm_offset);
    uint64_t pdpt_entry = pdpt_virt[pdpt_idx];
    if ((pdpt_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pd_phys = pdpt_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pd_virt = (uint64_t *)(pd_phys + hhdm_offset);
    uint64_t pd_entry = pd_virt[pd_idx];
    if ((pd_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    uint64_t pt_phys = pd_entry & VMM_ENTRY_ADDR_MASK;
    uint64_t *pt_virt = (uint64_t *)(pt_phys + hhdm_offset);
    uint64_t pt_entry = pt_virt[pt_idx];
    if ((pt_entry & VMM_FLAG_PRESENT) == 0) {
        return false;
    }

    if ((pt_entry & VMM_FLAG_USER) == 0) {
        return false;
    }

    if (require_writable && (pt_entry & VMM_FLAG_WRITABLE) == 0) {
        return false;
    }

    return true;
}

// ptr/len byte-granular dari sudut pandang pemanggil syscall, tapi
// paging bekerja per-halaman (4KB) -- jadi validasi SEMUA halaman
// yang disentuh oleh range [ptr, ptr+len), bukan cuma byte pertama.
bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable)
{
    if (len == 0) {
        return true;
    }

    uint64_t end = ptr + len;
    if (end < ptr) {
        return false;
    }

    uint64_t page_start = ptr & ~(PMM_PAGE_SIZE - 1);
    uint64_t page_end = (end - 1) & ~(PMM_PAGE_SIZE - 1);

    for (uint64_t page = page_start; page <= page_end; page += PMM_PAGE_SIZE) {
        if (!vmm_is_user_page(pml4_phys, page, require_writable)) {
            return false;
        }
    }

    return true;
}


uint64_t kheap_current = 0;
uint64_t kheap_mapped_end = 0;
static uint64_t kheap_pml4_phys = 0;

// ---- R6-2: stack kernel dengan guard page ----
// [guard 4 KB, tidak dipetakan][stack size, P|W|NX] berurutan dari
// KSTACK_START. Stack meluap -> #PF di guard -> pengiriman #PF butuh push ke
// stack yang sama -> #DF lewat IST1 (R1) -> panic menyebut task-nya.
static uint64_t g_kstack_next = KSTACK_START;
static uint64_t g_kstack_lo[KSTACK_MAX_STACKS];    // alamat halaman guard
static uint64_t g_kstack_top[KSTACK_MAX_STACKS];
static int g_kstack_n;

uint64_t kstack_alloc(uint64_t size)
{
    uint64_t pages = (size + PMM_PAGE_SIZE - 1) / PMM_PAGE_SIZE;
    uint64_t need = (pages + 1) * PMM_PAGE_SIZE;

    if (pages == 0 || g_kstack_n >= KSTACK_MAX_STACKS ||
        need > KSTACK_START + KSTACK_REGION - g_kstack_next) {
        serial_write("kstack_alloc: region/tabel stack penuh\r\n");
        return 0;
    }

    uint64_t base = g_kstack_next + PMM_PAGE_SIZE;
    for (uint64_t i = 0; i < pages; i++) {
        uint64_t frame = pmm_alloc();
        if (frame == 0) {
            serial_write("kstack_alloc: pmm_alloc() gagal\r\n");
            return 0;   // frame yang sudah dipetakan tertinggal (boot saja)
        }
        vmm_map(kheap_pml4_phys, base + i * PMM_PAGE_SIZE, frame,
                VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NX);
    }

    g_kstack_lo[g_kstack_n] = g_kstack_next;
    g_kstack_top[g_kstack_n] = base + pages * PMM_PAGE_SIZE;
    g_kstack_n++;
    g_kstack_next += need;
    return base;
}

// 1 bila addr jatuh di halaman guard salah satu stack (lo = guard, top =
// puncak stack itu = rsp0 task pemiliknya).
int kstack_guard_find(uint64_t addr, uint64_t *lo, uint64_t *top)
{
    for (int i = 0; i < g_kstack_n; i++) {
        if (addr >= g_kstack_lo[i] && addr < g_kstack_lo[i] + PMM_PAGE_SIZE) {
            *lo = g_kstack_lo[i];
            *top = g_kstack_top[i];
            return 1;
        }
    }
    return 0;
}

void kheap_init(uint64_t pml4_phys)
{
    kheap_pml4_phys = pml4_phys;
    kheap_current = KHEAP_START;
    kheap_mapped_end = KHEAP_START;
}

void *kmalloc(uint64_t size)
{
    uint64_t total = size + sizeof(uint64_t);
    total = (total + 15) & ~((uint64_t)15);

    while (kheap_current + total > kheap_mapped_end) {
        uint64_t new_frame = pmm_alloc();
        if (new_frame == 0) {
            serial_write("kmalloc: pmm_alloc() FAILED, heap kehabisan memori\r\n");
            return (void *)0;
        }
        vmm_map(kheap_pml4_phys, kheap_mapped_end, new_frame,
                VMM_FLAG_PRESENT | VMM_FLAG_WRITABLE | VMM_FLAG_NX);
        kheap_mapped_end += PMM_PAGE_SIZE;
    }

    uint64_t header_addr = kheap_current;
    uint64_t *header = (uint64_t *)header_addr;
    *header = total;

    kheap_current += total;

    return (void *)(header_addr + sizeof(uint64_t));
}

void kfree(void *ptr)
{
    if (ptr == (void *)0) {
        return;
    }

    uint64_t data_addr = (uint64_t)ptr;
    uint64_t header_addr = data_addr - sizeof(uint64_t);
    uint64_t *header = (uint64_t *)header_addr;
    uint64_t total = *header;

    if (header_addr + total == kheap_current) {
        kheap_current = header_addr;
        serial_write("kfree: alokasi terakhir, berhasil reclaim\r\n");
    } else {
        serial_write("kfree: bukan alokasi terakhir, tidak bisa reclaim aman (no-op)\r\n");
    }
}

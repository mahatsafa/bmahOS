// P2: uji parsing ACPI (acpi.c di-#include) dengan tabel sintetis di memori
// host; hhdm_offset = 0, jadi "alamat fisik" = pointer host. RSDT (entri
// 32-bit) memakai memori MAP_32BIT supaya alamatnya muat.

#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/acpi.c"

uint64_t hhdm_offset;

static uint8_t g_mem[65536] __attribute__((aligned(16)));
static uint32_t g_used;

static void *alloc(uint32_t n)
{
    void *p = g_mem + g_used;
    g_used += (n + 15) & ~15u;
    memset(p, 0, n);
    return p;
}

static void fix_sum(void *p, uint32_t len, uint8_t *sum_byte)
{
    uint8_t s = 0;
    *sum_byte = 0;
    for (uint32_t i = 0; i < len; i++) {
        s = (uint8_t)(s + ((uint8_t *)p)[i]);
    }
    *sum_byte = (uint8_t)(0x100 - s);
}

static struct acpi_sdt_header *mk_table(const char *sig, uint32_t len)
{
    struct acpi_sdt_header *h = alloc(len);
    memcpy(h->signature, sig, 4);
    h->length = len;
    h->revision = 1;
    return h;
}

static void seal(struct acpi_sdt_header *h)
{
    fix_sum(h, h->length, &h->checksum);
}

// MADT: LAPIC aktif, LAPIC mati, IOAPIC, ISO IRQ0 -> GSI 2, x2APIC aktif,
// lalu `tail` byte entri tambahan (mis. entri panjang 0).
static struct acpi_madt *mk_madt(const uint8_t *tail, uint32_t tail_len)
{
    uint32_t len = sizeof(struct acpi_madt) + 8 + 8 + 12 + 10 + 16 + tail_len;
    struct acpi_madt *m = (struct acpi_madt *)mk_table("APIC", len);
    uint8_t *e = (uint8_t *)m + sizeof(*m);

    m->local_apic_address = 0xFEE00000;
    e[0] = 0; e[1] = 8; e[2] = 0; e[3] = 0; e[4] = 1; e += 8;              // aktif
    e[0] = 0; e[1] = 8; e[2] = 1; e[3] = 1; e[4] = 0; e += 8;              // mati
    e[0] = 1; e[1] = 12; e[2] = 0; memcpy(e + 4, &(uint32_t){0xFEC00000}, 4); e += 12;
    e[0] = 2; e[1] = 10; e[2] = 0; e[3] = 0; memcpy(e + 4, &(uint32_t){2}, 4); e += 10;
    e[0] = 9; e[1] = 16; memcpy(e + 8, &(uint32_t){1}, 4); e += 16;        // x2APIC
    if (tail_len) {
        memcpy(e, tail, tail_len);
    }
    seal(&m->header);
    return m;
}

static struct acpi_sdt_header *mk_hpet(uint8_t space, uint64_t base)
{
    struct acpi_sdt_header *h = mk_table("HPET", 56);
    uint8_t *b = (uint8_t *)h;
    b[40] = space;
    memcpy(b + 44, &base, 8);
    b[52] = 0;
    memcpy(b + 53, &(uint16_t){0x80}, 2);
    seal(h);
    return h;
}

static struct acpi_sdt_header *mk_fadt(void)
{
    struct acpi_sdt_header *h = mk_table("FACP", 244);
    uint8_t *f = (uint8_t *)h;
    uint32_t flags = 1u << 10;
    memcpy(f + 112, &flags, 4);
    f[116] = 1;
    memcpy(f + 120, &(uint64_t){0xCF9}, 8);
    f[128] = 6;
    seal(h);
    return h;
}

static struct acpi_rsdp *mk_rsdp_x(struct acpi_sdt_header **tabs, int n)
{
    struct acpi_sdt_header *x = mk_table("XSDT", 36 + 8 * n);
    for (int i = 0; i < n; i++) {
        uint64_t pa = (uint64_t)(uintptr_t)tabs[i];
        memcpy((uint8_t *)x + 36 + 8 * i, &pa, 8);
    }
    seal(x);
    struct acpi_rsdp *r = alloc(sizeof(*r));
    memcpy(r->signature, "RSD PTR ", 8);
    r->revision = 2;
    r->length = sizeof(*r);
    r->xsdt_address = (uint64_t)(uintptr_t)x;
    fix_sum(r, 20, &r->checksum);
    fix_sum(r, sizeof(*r), &r->extended_checksum);
    return r;
}

static void reset(void)
{
    g_acpi_bad = g_acpi_cpus = 0;
    g_hpet_ok = 0;
    g_hpet_base = 0;
    g_ioapic_address = 0;
    g_irq0_gsi = 0;
    g_acpi_reset_ok = 0;
}

static char g_out[4096];
static void out_cat(const char *s)
{
    strncat(g_out, s, sizeof(g_out) - strlen(g_out) - 1);
}

static void test_good(void)
{
    reset();
    g_used = 0;
    struct acpi_sdt_header *t[3] = { mk_fadt(), &mk_madt(0, 0)->header, mk_hpet(0, 0xFED00000) };
    struct acpi_rsdp *r = mk_rsdp_x(t, 3);

    CHECK(acpi_parse_rsdp(r) == 0);
    CHECK(g_acpi_ntabs == 3 && g_acpi_bad == 0);
    CHECK(g_acpi_cpus == 2);                       // LAPIC aktif + x2APIC aktif
    CHECK(g_ioapic_address == 0xFEC00000 && g_irq0_gsi == 2);
    CHECK(g_local_apic_address == 0xFEE00000);
    CHECK(g_hpet_ok && g_hpet_base == 0xFED00000 && g_hpet_min_tick == 0x80);
    CHECK(g_acpi_reset_ok && g_acpi_reset_port == 0xCF9 && g_acpi_reset_value == 6);
    g_out[0] = 0;
    acpi_list(out_cat);
    CHECK(strstr(g_out, "FACP len=244 rev=1 ok\n") && strstr(g_out, "HPET len=56 rev=1 ok\n"));
    CHECK(strstr(g_out, "acpi: tabel=3 ditolak=0 cpu=2 hpet=0xfed00000\n") != 0);
}

static void test_bad_tables(void)
{
    // MADT dengan checksum salah dilewati (IOAPIC tidak terisi); HPET ruang
    // I/O dicatat tapi tidak dipakai; entri nol di XSDT dilewati.
    reset();
    g_used = 0;
    struct acpi_madt *m = mk_madt(0, 0);
    m->header.checksum ^= 1;
    struct acpi_sdt_header *t[3] = { &m->header, mk_hpet(1, 0x1234), 0 };
    struct acpi_rsdp *r = mk_rsdp_x(t, 3);
    CHECK(acpi_parse_rsdp(r) == 0);
    CHECK(g_acpi_bad == 1 && g_acpi_ntabs == 2 && g_ioapic_address == 0 && g_acpi_cpus == 0);
    CHECK(!g_hpet_ok && g_hpet_base == 0x1234);
    g_out[0] = 0;
    acpi_list(out_cat);
    CHECK(strstr(g_out, "APIC len=") && strstr(g_out, " rusak\n"));
    CHECK(strstr(g_out, "hpet=0x1234 (tidak dipakai)\n") != 0);

    // Tabel terlalu panjang (> 1 MB) ditolak tanpa dibaca isinya.
    reset();
    struct acpi_sdt_header *big = mk_table("SSDT", 64);
    big->length = (1u << 20) + 1;
    CHECK(!acpi_table_ok(big));
    big->length = 10;
    CHECK(!acpi_table_ok(big));

    // RSDP rusak: checksum 20 byte salah -> -1, tidak ada tabel.
    reset();
    struct acpi_sdt_header *t2[1] = { mk_fadt() };
    r = mk_rsdp_x(t2, 1);
    r->checksum ^= 0x55;
    CHECK(acpi_parse_rsdp(r) == -1 && g_acpi_bad == 1 && !g_acpi_reset_ok);
    // XSDT rusak -> -1.
    reset();
    r = mk_rsdp_x(t2, 1);
    ((uint8_t *)(uintptr_t)r->xsdt_address)[9] ^= 1;
    CHECK(acpi_parse_rsdp(r) == -1);
}

static void test_madt_bad_entry(void)
{
    // Entri panjang 0 dulu membuat loop MADT berputar selamanya; kini berhenti.
    static const uint8_t zero[4] = { 0x7F, 0, 0, 0 };
    reset();
    g_used = 0;
    struct acpi_madt *m = mk_madt(zero, sizeof(zero));
    acpi_parse_madt(m);
    CHECK(g_acpi_bad == 1 && g_acpi_cpus == 2 && g_irq0_gsi == 2);
    // Entri melewati ujung tabel.
    static const uint8_t over[3] = { 0, 8, 0 };
    reset();
    m = mk_madt(over, sizeof(over));
    acpi_parse_madt(m);
    CHECK(g_acpi_bad == 1 && g_acpi_cpus == 2);
    // Entri LAPIC terlalu pendek (panjang 4 < 8) dilewati, bukan dibaca.
    static const uint8_t shortl[4] = { 0, 4, 9, 9 };
    reset();
    m = mk_madt(shortl, sizeof(shortl));
    acpi_parse_madt(m);
    CHECK(g_acpi_bad == 0 && g_acpi_cpus == 2);
    // MADT lebih pendek dari header MADT.
    reset();
    m = (struct acpi_madt *)mk_table("APIC", 40);
    acpi_parse_madt(m);
    CHECK(g_acpi_bad == 1 && g_local_apic_address == 0xFEE00000);
}

static void test_rsdt(void)
{
    // ACPI 1.0: revisi 0, RSDT dengan entri 32-bit (memori di bawah 4 GB).
    uint8_t *lo = mmap(0, 65536, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    CHECK(lo != MAP_FAILED);
    if (lo == MAP_FAILED) {
        return;
    }
    reset();
    struct acpi_sdt_header *f = (struct acpi_sdt_header *)lo;
    memcpy(f, mk_fadt(), 244);
    struct acpi_sdt_header *rs = (struct acpi_sdt_header *)(lo + 1024);
    memcpy(rs->signature, "RSDT", 4);
    rs->length = 36 + 4;
    uint32_t pa = (uint32_t)(uintptr_t)f;
    memcpy((uint8_t *)rs + 36, &pa, 4);
    seal(rs);
    struct acpi_rsdp *r = (struct acpi_rsdp *)(lo + 2048);
    memcpy(r->signature, "RSD PTR ", 8);
    r->revision = 0;
    r->rsdt_address = (uint32_t)(uintptr_t)rs;
    fix_sum(r, 20, &r->checksum);
    CHECK(acpi_parse_rsdp(r) == 0 && g_acpi_ntabs == 1 && g_acpi_reset_ok);
    // Revisi 2 dengan checksum panjang salah -> jatuh ke RSDT.
    reset();
    r->revision = 2;
    r->length = sizeof(*r);
    r->xsdt_address = 0x1234;
    fix_sum(r, 20, &r->checksum);
    fix_sum(r, sizeof(*r), &r->extended_checksum);
    r->extended_checksum ^= 1;   // pasti salah
    CHECK(acpi_parse_rsdp(r) == 0 && g_acpi_bad == 1 && g_acpi_reset_ok);
    munmap(lo, 65536);
}

int main(void)
{
    test_good();
    test_bad_tables();
    test_madt_bad_entry();
    test_rsdt();
    return test_done("acpi");
}

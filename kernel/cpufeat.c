#include "kernel.h"

// F1.5: deteksi fitur CPU lewat CPUID, sekali saat boot. Hasil disimpan di
// g_cpu dan dicetak ke serial. Leaf hanya dibaca bila CPU melaporkan leaf itu
// ada (leaf maksimum dasar/extended); fitur dari leaf yang tidak ada = 0.

struct cpu_features g_cpu;

static void cpuid(uint32_t leaf, uint32_t subleaf, uint32_t r[4])
{
    uint32_t a = leaf, b, c = subleaf, d;

    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    r[0] = a;
    r[1] = b;
    r[2] = c;
    r[3] = d;
}

static void copy_regs_str(char *dst, const uint32_t *regs, int n)
{
    for (int i = 0; i < n; i++) {
        for (int k = 0; k < 4; k++) {
            dst[i * 4 + k] = (char)((regs[i] >> (k * 8)) & 0xFF);
        }
    }
    dst[n * 4] = '\0';
}

static void print_flag(const char *name, uint8_t v)
{
    serial_write(" ");
    serial_write(name);
    serial_write(v ? "=1" : "=0");
}

void cpu_features_init(void)
{
    uint32_t r[4];

    for (size_t i = 0; i < sizeof(g_cpu); i++) {
        ((volatile uint8_t *)&g_cpu)[i] = 0;
    }

    // Leaf 0: leaf maksimum + vendor (urutan register EBX, EDX, ECX).
    cpuid(0, 0, r);
    g_cpu.max_leaf = r[0];
    uint32_t vendor[3] = { r[1], r[3], r[2] };
    copy_regs_str(g_cpu.vendor, vendor, 3);

    if (g_cpu.max_leaf >= 1) {
        cpuid(1, 0, r);
        uint32_t base_family = (r[0] >> 8) & 0xF;
        uint32_t base_model = (r[0] >> 4) & 0xF;

        g_cpu.stepping = r[0] & 0xF;
        g_cpu.family = base_family;
        if (base_family == 0xF) {
            g_cpu.family += (r[0] >> 20) & 0xFF;
        }
        g_cpu.model = base_model;
        if (base_family == 0x6 || base_family == 0xF) {
            g_cpu.model |= ((r[0] >> 16) & 0xF) << 4;
        }

        g_cpu.tsc        = (r[3] >> 4) & 1;
        g_cpu.apic       = (r[3] >> 9) & 1;
        g_cpu.sse2       = (r[3] >> 26) & 1;
        g_cpu.pcid       = (r[2] >> 17) & 1;
        g_cpu.x2apic     = (r[2] >> 21) & 1;
        g_cpu.rdrand     = (r[2] >> 30) & 1;
        g_cpu.hypervisor = (r[2] >> 31) & 1;
    }

    if (g_cpu.max_leaf >= 7) {
        cpuid(7, 0, r);
        g_cpu.smep   = (r[1] >> 7) & 1;
        g_cpu.rdseed = (r[1] >> 18) & 1;
        g_cpu.smap   = (r[1] >> 20) & 1;
        g_cpu.umip   = (r[2] >> 2) & 1;
    }

    cpuid(0x80000000u, 0, r);
    g_cpu.max_ext_leaf = r[0];
    // Nilai < 0x80000000 berarti leaf extended tidak ada sama sekali.
    if (g_cpu.max_ext_leaf < 0x80000000u) {
        g_cpu.max_ext_leaf = 0;
    }

    if (g_cpu.max_ext_leaf >= 0x80000001u) {
        cpuid(0x80000001u, 0, r);
        g_cpu.nx = (r[3] >> 20) & 1;
    }

    if (g_cpu.max_ext_leaf >= 0x80000007u) {
        cpuid(0x80000007u, 0, r);
        g_cpu.tsc_invariant = (r[3] >> 8) & 1;
    }

    // Leaf 0x40000000 hanya bermakna bila bit hypervisor menyala.
    if (g_cpu.hypervisor) {
        cpuid(0x40000000u, 0, r);
        uint32_t hv[3] = { r[1], r[2], r[3] };
        copy_regs_str(g_cpu.hv_vendor, hv, 3);
    }

    serial_write("CPU: vendor=");
    serial_write(g_cpu.vendor);
    serial_write(" family=");
    serial_write_hex(g_cpu.family);
    serial_write(" model=");
    serial_write_hex(g_cpu.model);
    serial_write(" stepping=");
    serial_write_hex(g_cpu.stepping);
    serial_write("\r\n");

    serial_write("CPU: leaf_maks=");
    serial_write_hex(g_cpu.max_leaf);
    serial_write(" leaf_ext_maks=");
    serial_write_hex(g_cpu.max_ext_leaf);
    serial_write(" hypervisor=");
    serial_write(g_cpu.hypervisor ? g_cpu.hv_vendor : "-");
    serial_write("\r\n");

    serial_write("CPU: fitur");
    print_flag("rdrand", g_cpu.rdrand);
    print_flag("rdseed", g_cpu.rdseed);
    print_flag("nx", g_cpu.nx);
    print_flag("smep", g_cpu.smep);
    print_flag("smap", g_cpu.smap);
    print_flag("umip", g_cpu.umip);
    print_flag("pcid", g_cpu.pcid);
    print_flag("apic", g_cpu.apic);
    print_flag("x2apic", g_cpu.x2apic);
    print_flag("tsc", g_cpu.tsc);
    print_flag("tsc_invarian", g_cpu.tsc_invariant);
    print_flag("sse2", g_cpu.sse2);
    serial_write("\r\n");
}

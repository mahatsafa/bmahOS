#ifndef BMAHOS_KERNEL_H
#define BMAHOS_KERNEL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>   // D9b: kernel/compat/string.h (implementasi kernel/klib.c)

// ---- Port I/O ----
// F1.7: di uji host (BMAHOS_HOST_TEST, user mode) port I/O akan fault,
// jadi out* tidak melakukan apa pun dan in* mengembalikan 0.
static inline void outb(uint16_t port, uint8_t value)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    (void)value;
    return;
#endif
    __asm__ volatile (
        "outb %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint8_t inb(uint16_t port)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    return 0;
#endif
    uint8_t value;

    __asm__ volatile (
        "inb %1, %0"
        : "=a"(value)
        : "Nd"(port)
    );

    return value;
}

// Checkpoint PCI: varian 32-bit outb/inb -- dibutuhkan karena PCI
// configuration space diakses lewat CONFIG_ADDRESS/CONFIG_DATA yang
// keduanya register 32-bit (port 0xCF8/0xCFC), bukan 8-bit seperti
// PIC/PIT/serial yang sudah ada.
static inline void outl(uint16_t port, uint32_t value)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    (void)value;
    return;
#endif
    __asm__ volatile (
        "outl %0, %1"
        :
        : "a"(value), "Nd"(port)
    );
}

static inline uint32_t inl(uint16_t port)
{
#ifdef BMAHOS_HOST_TEST
    (void)port;
    return 0;
#endif
    uint32_t value;

    __asm__ volatile (
        "inl %1, %0"
        : "=a"(value)
        : "Nd"(port)
    );

    return value;
}

// irq_save/irq_restore: proteksi critical section yang AMAN terhadap
// nested call (beda dari cli/sti polos). irq_save() menyimpan kondisi
// IF (Interrupt Flag) yang SEBENARNYA sebelum cli, lewat pushfq (baca
// seluruh RFLAGS). irq_restore() hanya sti KALAU kondisi sebelumnya
// memang IF=1 -- kalau caller sudah cli duluan sebelum manggil kita,
// kita tidak akan sengaja menyalakan interrupt yang caller matikan.
static inline uint64_t irq_save(void)
{
#ifdef BMAHOS_HOST_TEST
    return 0;   // F1.7: uji di host (user mode), cli/sti akan fault
#endif
    uint64_t flags;
    __asm__ volatile (
        "pushfq\n\t"
        "popq %0\n\t"
        "cli"
        : "=r"(flags)
        :
        : "memory"
    );
    return flags;
}

static inline void irq_restore(uint64_t flags)
{
#ifdef BMAHOS_HOST_TEST
    return;
#endif
    // Bit ke-9 RFLAGS = IF. Kalau nyala di kondisi yang disimpan,
    // berarti sebelum irq_save() dipanggil interrupt memang aktif.
    if (flags & (1 << 9)) {
        __asm__ volatile ("sti" ::: "memory");
    }
}

// ---- serial.c ----
void serial_init(void);
void serial_putc(char c);
void serial_write(const char *s);
void serial_write_hex(uint64_t value);
void serial_write_nolog(const char *s);
extern volatile int g_serial_mute;

// ---- fbcon.c (P1: konsol framebuffer, cermin serial_putc) ----
typedef struct {
    uint8_t *base;
    uint64_t w, h, pitch;          // piksel, piksel, byte per baris
    uint32_t bypp;                 // byte per piksel (2, 3, 4)
    uint8_t rsz, rsh, gsz, gsh, bsz, bsh;
    uint32_t cols, rows;           // ukuran teks (sel 8x16)
    uint32_t col, row;             // posisi kursor
    uint32_t fg;                   // warna teks terkemas; latar selalu 0
    uint64_t chars, scrolls;
    int active;
} fbcon_t;
int fbcon_setup(fbcon_t *f, uint8_t *base, uint64_t w, uint64_t h, uint64_t pitch,
                uint16_t bpp, uint8_t rsz, uint8_t rsh, uint8_t gsz, uint8_t gsh,
                uint8_t bsz, uint8_t bsh);   // 0 OK, -1 mode tidak didukung
void fbcon_putc_on(fbcon_t *f, char c);
void fbcon_init(void);                        // baca request framebuffer Limine
void fbcon_putc(char c);                      // no-op bila nonaktif
const fbcon_t *fbcon_state(void);

// ---- kernel.c (ring log; dipakai serial_putc) ----
void log_capture(char c);

// ---- cpu.c (GDT/TSS/IDT) ----
struct gdt_entry
{
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_middle;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct tss
{
    uint32_t reserved0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved1;   // TSS-1: 64-bit (dulu 32 -> ist* bergeser 4 byte)
    uint64_t ist1;
    uint64_t ist2;
    uint64_t ist3;
    uint64_t ist4;
    uint64_t ist5;
    uint64_t ist6;
    uint64_t ist7;
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb_offset;
} __attribute__((packed));

struct idt_entry
{
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  ist;
    uint8_t  type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed));

extern struct gdt_entry bmahOS_gdt[7];
extern struct tss bmahOS_tss;
extern struct idt_entry bmahOS_idt[256];
extern void tss_load_asm(void);
extern uint64_t tss_read_asm(void);
void idt_set_entry(uint8_t vector, uint64_t handler, uint16_t selector, uint8_t type_attr);
void idt_init(void);
void print_idt_entry0(void);
void print_idt_entry32(void);
void gdt_init(void);
void print_bmahOS_gdt(void);
void idt_load(void);
void read_idtr(void);
void gdt_load_and_reload(void);
void read_bmahOS_gdtr(void);
void read_segment_registers(void);
void read_gdtr(void);
void read_gdt_entries(void);

// ---- pmm.c (physical memory manager) ----
#define PMM_PAGE_SIZE          0x1000ULL
#define PMM_MAX_PHYS_ADDR      0x100000000ULL
#define PMM_MAX_FRAMES         (PMM_MAX_PHYS_ADDR / PMM_PAGE_SIZE)
#define PMM_BITMAP_SIZE        (PMM_MAX_FRAMES / 8ULL)

struct limine_memmap_response;
extern uint64_t pmm_usable_memory;
int pmm_bitmap_test(uint64_t frame);
void pmm_init(struct limine_memmap_response *response);
uint64_t pmm_alloc(void);
void pmm_free(uint64_t phys_addr);

// ---- vmm.c (paging + kernel heap) ----
#define VMM_FLAG_PRESENT   0x1ULL
#define VMM_FLAG_WRITABLE  0x2ULL
#define VMM_FLAG_NOCACHE   0x10ULL  // PCD bit -- wajib untuk MMIO (Local APIC, IOAPIC)
#define VMM_FLAG_USER      0x4ULL   // US bit -- wajib untuk halaman yang boleh diakses ring 3
#define VMM_FLAG_NX        (1ULL << 63) // XD bit -- halaman tidak bisa dieksekusi
#define VMM_ENTRY_ADDR_MASK 0x000FFFFFFFFFF000ULL
#define VMM_SHARED_PML4_IDX_HHDM     0x100  // hhdm_offset region
#define VMM_SHARED_PML4_IDX_APIC1    0x120  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_APIC2    0x122  // MMIO Local APIC/IOAPIC
#define VMM_SHARED_PML4_IDX_KHEAP    0x130  // KHEAP_START region
#define VMM_SHARED_PML4_IDX_KERNEL   0x1FF  // kernel higher-half (.text/.data)
#define KHEAP_START 0xFFFF980000000000ULL
extern uint64_t hhdm_offset;
extern int g_vmm_nx_ok;
extern uint64_t kheap_current;
extern uint64_t kheap_mapped_end;
// R6-2: stack kernel task di region sendiri, di entri PML4 yang sama dengan
// kheap (0x130, ikut terlihat di PML4 user hasil clone). Tiap stack diawali
// satu halaman guard yang tidak dipetakan; stack tidak pernah dibebaskan.
#define KSTACK_START      (KHEAP_START + 0x4000000000ULL)   // kheap + 256 GB
#define KSTACK_REGION     0x100000ULL                       // 1 MB virtual
#define KSTACK_MAX_STACKS 16
#define KSTACK_PAD        16   // byte nol di puncak: rsp0 = dasar + ukuran - KSTACK_PAD
uint64_t kstack_alloc(uint64_t size);   // alamat dasar (rendah), 0 = gagal
int kstack_guard_find(uint64_t addr, uint64_t *lo, uint64_t *top);
uint64_t read_cr3(void);
void vmm_dump_pml4(uint64_t pml4_phys);
void vmm_map(uint64_t pml4_phys, uint64_t vaddr, uint64_t paddr, uint64_t flags);
int vmm_nx_of(uint64_t pml4_phys, uint64_t vaddr);
void nx_init(void);
uint64_t vmm_clone_kernel_pml4(uint64_t kernel_pml4_phys);
bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable);
// R6-1: syscall + fault user (trap.c)
#define SYS_WRITE_MAX 1024   // byte per SYS_WRITE; lebih -> -1 (UART polling, interrupt mati)
extern uint64_t g_sys_calls, g_sys_rejected, g_user_faults;
void kheap_init(uint64_t pml4_phys);
void * kmalloc(uint64_t size);
void kfree(void *ptr);
// R6-3: batas heap + counter alokasi/pelepasan (metrics, `mem`).
#define KHEAP_MAX (16ULL * 1024 * 1024)
extern uint64_t g_pmm_allocs, g_pmm_frees, g_pmm_fail, g_pmm_bad_free;
extern uint64_t g_kmalloc_n, g_kfree_n, g_kfree_noop, g_kmalloc_fail;
// Alokasi wajib (tabel halaman, PML4 task, stack task, halaman user saat
// dibuat) gagal -> panic + reboot, bukan lanjut dengan pemetaan hilang.
__attribute__((noreturn)) void oom_panic(const char *where);

// ---- acpi.c (RSDP/MADT/FADT) ----
struct acpi_rsdp
{
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    // Fields berikut hanya valid kalau revision >= 2 (ACPI 2.0+)
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));
struct acpi_sdt_header
{
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));
struct acpi_madt
{
    struct acpi_sdt_header header;
    uint32_t local_apic_address;
    uint32_t flags;
    // Diikuti entries dengan panjang variabel
} __attribute__((packed));
struct acpi_madt_entry_header
{
    uint8_t entry_type;
    uint8_t entry_length;
} __attribute__((packed));
struct acpi_madt_local_apic
{
    struct acpi_madt_entry_header header;
    uint8_t acpi_processor_id;
    uint8_t apic_id;
    uint32_t flags;
} __attribute__((packed));
struct acpi_madt_ioapic
{
    struct acpi_madt_entry_header header;
    uint8_t ioapic_id;
    uint8_t reserved;
    uint32_t ioapic_address;
    uint32_t global_system_interrupt_base;
} __attribute__((packed));
struct acpi_madt_iso
{
    struct acpi_madt_entry_header header;
    uint8_t bus_source;
    uint8_t irq_source;
    uint32_t global_system_interrupt;
    uint16_t flags;
} __attribute__((packed));
extern uint64_t g_local_apic_address;
extern uint32_t g_ioapic_address;
extern uint32_t g_ioapic_gsi_base;
extern uint32_t g_irq0_gsi;
extern int g_acpi_reset_ok;
extern uint16_t g_acpi_reset_port;
extern uint8_t g_acpi_reset_value;
void acpi_init(void);
void machine_reboot(void) __attribute__((noreturn));

// ---- pic.c (8259 PIC + PIT) ----
void pic_remap(void);
void pit_init(uint32_t frequency_hz);

// ---- pci.c (PCI config space + pencarian perangkat) ----
#define AHCI_PCI_BUS      g_ahci_bus
#define AHCI_PCI_DEVICE   g_ahci_dev
#define AHCI_PCI_FUNCTION g_ahci_fn
#define AHCI_BAR5_OFFSET  0x24
#define E1000_PCI_BUS      g_e1000_bus
#define E1000_PCI_DEVICE   g_e1000_dev
#define E1000_PCI_FUNCTION g_e1000_fn
#define E1000_BAR0_OFFSET  0x10

extern uint8_t g_ahci_bus, g_ahci_dev, g_ahci_fn;
extern uint8_t g_e1000_bus, g_e1000_dev, g_e1000_fn;
extern int g_ahci_found;
extern int g_e1000_found;
uint32_t pci_config_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset);
void pci_scan_and_log(void);
void pci_config_write32(uint8_t bus, uint8_t device, uint8_t function, uint8_t offset, uint32_t value);
void pci_find_devices(void);
// P2: tabel perangkat PCI hasil enumerasi generik (maks PCI_MAX_DEVS, sisanya dihitung).
#define PCI_MAX_DEVS 64
typedef struct {
    uint8_t bus, dev, fn, hdr;     // hdr = header type tanpa bit multi-function
    uint16_t vendor, device;
    uint32_t cls;                  // kelas << 16 | subkelas << 8 | prog_if
} pci_dev_t;
extern pci_dev_t g_pci_devs[PCI_MAX_DEVS];
extern uint32_t g_pci_ndevs, g_pci_dropped;
extern uint32_t (*g_pci_read)(uint8_t, uint8_t, uint8_t, uint8_t);
void pci_enumerate(void);
const pci_dev_t *pci_find_class(uint32_t cls);
const pci_dev_t *pci_find_id(uint16_t vendor, uint16_t device);
void pci_list(void (*out)(const char *));   // perintah `pci` dan log boot
// P2: ACPI tervalidasi (checksum/panjang), HPET, jumlah CPU dari MADT.
extern uint32_t g_acpi_bad, g_acpi_cpus;
extern uint64_t g_hpet_base;
extern uint16_t g_hpet_min_tick;
extern int g_hpet_ok;
int acpi_table_ok(const struct acpi_sdt_header *h);
int acpi_parse_rsdp(const struct acpi_rsdp *rsdp);   // 0 OK, -1 RSDP/root rusak
void acpi_list(void (*out)(const char *));            // perintah `acpi`

// ---- rtc.c (P3-1: jam dinding dari RTC CMOS, dimajukan tick) ----
typedef struct {
    uint32_t year, month, day, hour, min, sec;
} rtc_time_t;
extern uint64_t g_rtc_boot_epoch, g_rtc_boot_tick;
extern int g_rtc_ok;
uint64_t rtc_days_from_civil(uint32_t y, uint32_t m, uint32_t d);
void rtc_civil_from_epoch(uint64_t t, rtc_time_t *o);
uint64_t rtc_raw_to_epoch(const uint8_t raw[6], uint8_t status_b);   // 0 = tidak masuk akal
void rtc_init(void);
uint64_t rtc_now(void);                       // epoch sekarang, 0 bila RTC tidak sah
void rtc_status(void (*out)(const char *));   // perintah `waktu`

// ---- filter.c (P4: packet filter, aturan di FILTER.CFG) ----
extern uint64_t g_filter_drop;
void filter_load(void);                        // saat boot, setelah config_load
int filter_check(const volatile uint8_t *ip_src, uint8_t proto, uint16_t dport);   // 1 lolos
int filter_ipv4(const volatile uint8_t *buf, uint32_t ihl, uint32_t payload_len); // 1 lolos
int filter_execute(const volatile uint8_t *cmd, uint32_t len);                    // 1 = ditangani

// ---- apic.c (Local APIC + IOAPIC) ----
#define LAPIC_VIRT  0xFFFF910000000000ULL
#define IOAPIC_REDTBL_BASE  0x10

void lapic_send_eoi(void);
uint32_t ioapic_read(uint32_t reg);
void ioapic_write(uint32_t reg, uint32_t value);
void apic_enable_local_apic(uint64_t pml4_phys);
void ioapic_map_and_configure(uint64_t pml4_phys, uint32_t gsi, uint8_t vector, uint8_t dest_apic_id);

// ---- ahci.c (AHCI/SATA baca) ----
#define AHCI_VIRT 0xFFFF910000002000ULL  // setelah IOAPIC_VIRT (+0x1000)
#define AHCI_REG_CAP  0x00
#define AHCI_REG_GHC  0x04
#define AHCI_REG_IS   0x08
#define AHCI_REG_PI   0x0C
#define AHCI_REG_VS   0x10
#define AHCI_OK              0

extern int g_ahci_ata_port_count;
void ahci_port_init(volatile uint32_t *hba, uint32_t port);
int ahci_read(uint32_t port_index, uint64_t lba, uint32_t count, uint8_t **out_buf);
int ahci_write(uint32_t port_index, uint64_t lba, uint32_t count, const uint8_t *buf);
int ahci_flush(uint32_t port_index);

// ---- fat32.c (FAT32 baca) ----
void ahci_fat32_probe_and_log(void);
int fat32_find_file(const char *name_83, uint32_t *out_cluster, uint32_t *out_size);
uint8_t * fat32_load_file(uint32_t first_cluster, uint32_t file_size);
void fat32_probe_root_cluster(void);
void fat32_list_root_directory(void);
void fat32_read_file(uint32_t first_cluster, uint32_t file_size);
// D6-3: tulis (root saja). Kode error negatif, tidak pernah halt.
#define FAT32_WRITE_MAX    4096
#define FAT32_OK           0
#define FAT32_ERR_NOVOL   -1
#define FAT32_ERR_RO      -2
#define FAT32_ERR_IO      -3
#define FAT32_ERR_CORRUPT -4
#define FAT32_ERR_FULL    -5
#define FAT32_ERR_DIRFULL -6
#define FAT32_ERR_TOOBIG  -7
#define FAT32_ERR_NOTFILE -8
#define FAT32_ERR_NOENT   -9
#define FAT32_ERR_UNSUP   -10
#define FAT32_ERR_EXIST   -11
#define FAT32_ERR_LFN     -12
extern uint64_t g_fat_wr_ok, g_fat_wr_fail;
int fat32_root_read(const uint8_t **dir, uint32_t *entries);
int fat32_read_name(const char *name83, uint8_t *out, uint32_t max, uint32_t *out_size);
int fat32_write_name(const char *name83, const uint8_t *data, uint32_t len,
                     int append, uint32_t *out_size);
int fat32_writable(void);
int fat32_delete_name(const char *name83);
int fat32_rename_name(const char *old83, const char *new83);
int fat32_replace_name(const char *dst83, const char *tmp83, const uint8_t *data,
                       uint32_t len);
uint32_t fat32_free_hint(void);
// R4-1: peta sektor file yang sudah ada (root, ukuran kelipatan 512, 512 ..
// FAT32_MAP_MAX * 512 byte) untuk baca/timpa per sektor di tempat. Ukuran,
// rantai FAT, dan entri direktori tidak pernah diubah. Peta berlaku selama file
// tidak dihapus/diganti (pemanggil melindungi nama file itu).
#define FAT32_MAP_MAX 128
typedef struct {
    uint32_t nsec;                 // jumlah sektor = ukuran / 512
    uint32_t spc;                  // sektor per cluster saat dipetakan
    uint32_t clu[FAT32_MAP_MAX];   // rantai cluster (nsec / spc dibulatkan ke atas)
} fat32_map_t;
int fat32_file_map(const char *name83, fat32_map_t *m);
int fat32_map_read(const fat32_map_t *m, uint32_t sec, uint8_t *buf512);
int fat32_map_write(const fat32_map_t *m, uint32_t sec, const uint8_t *buf512);
extern volatile int g_ahci_busy;   // R4: >0 selama perintah AHCI berjalan

// ---- logdisk.c (R4: log persisten di LOG.BIN) ----
void logdisk_line(const char *s, uint32_t n);   // dari log_capture (interrupt mati)
void logdisk_init(void);                        // net task, sebelum loop
void logdisk_poll(void);                        // net task, tiap putaran
void logdisk_sync(int panic);                   // panic/reboot: tulis antrean langsung
void logdisk_execute(const volatile uint8_t *args, uint32_t len);
int logdisk_rec_ok(const uint8_t *rec);
extern uint64_t g_ld_written, g_ld_lost, g_ld_wfail, g_ld_bad;
// fscmd.c: perintah ls/baca/tulis/tambah/hapus/ganti (admin). Return 1 bila dikenali.
int fscmd_execute(const volatile uint8_t *cmd, uint32_t len);
const char *fscmd_strerror(int rc);

// ---- tls.c (D9: TLS 1.2 BearSSL, port 7780) ----
#define TLS_MAX_SESS 2   // = batas TCB port 7780; tiap TCB 7780 memegang satu slot
void tls_load(void);
int tls_enabled(void);
int tls_open(void);      // slot, -1 penuh, -2 nonaktif, -3 entropi, -4 engine
void tls_free(int s);
uint32_t tls_feed(int s, const volatile uint8_t *d, uint32_t len);
const uint8_t *tls_app_in(int s, uint32_t *len);
void tls_app_in_ack(int s, uint32_t n);
uint32_t tls_app_space(int s);
uint32_t tls_app_write(int s, const volatile uint8_t *d, uint32_t len);
const uint8_t *tls_rec_out(int s, uint32_t *len);
void tls_rec_out_ack(int s, uint32_t n);
int tls_ready(int s);
int tls_state(int s);    // 0 jalan, 1 ditutup baik-baik, -1 error
int tls_last_error(int s);
void tls_close(int s);
uint16_t tls_suite(int s);
int tls_sess_active(void);
void tls_status(void);
extern uint64_t g_tls_hs_ok, g_tls_fail, g_tls_full, g_tls_noentropy;
uint64_t net_stack_used(void);   // kernel.c: puncak pemakaian stack net task (byte)
uint64_t net_stack_size(void);

// ---- config.c (D7: CONFIG.CFG) ----
#define CFG_CLI_IDLE_DEF 300   // detik
extern uint32_t g_cli_idle_s;     // net.c: idle sesi CLI login (detik)
extern uint32_t g_net_src_rate;   // net.c: batas datagram/s per IP sumber
extern uint32_t g_net_echo;       // net.c: 1 = echo TCP 7 + UDP 7777 aktif
extern uint32_t g_cli_plain;      // net.c (D9): 1 = CLI teks polos TCP 7779 aktif
extern uint32_t g_udp_admin;      // net.c (D9): 0 = UDP 7778 hanya perintah baca
int config_parse(const uint8_t *b, uint32_t len, uint32_t *out, uint32_t *bad_line,
                 const char **why);

// ---- netcon.c (R2: netconsole UDP) ----
#define NETCON_HOST_DEF  1      // tujuan 192.168.50.<host>
#define NETCON_PORT_DEF  6666
#define NETCON_SRC_PORT  6665
extern uint32_t g_netcon_on;      // config netcon (0/1, bawaan 0)
extern uint32_t g_netcon_host;    // config netcon_host (1..254)
extern uint32_t g_netcon_port;    // config netcon_port (1024..65535)
extern volatile int g_netcon_hold; // 1 = baris log tidak diantre (panic: register umum)
void netcon_line(const char *s, uint32_t n);
void netcon_init(void);
void netcon_poll(void);
void netcon_arp_seen(const volatile uint8_t *buf);
void netcon_panic_flush(void);
void netcon_status(void);
void config_load(void);
int config_execute(const volatile uint8_t *cmd, uint32_t len);

// ---- e1000.c (driver NIC Intel 8254x) ----
#define E1000_REG_RDT      0x2818
#define E1000_RX_RING_SIZE 64
#define E1000_RXD_STA_DD   0x01
#define E1000_VIRT 0xFFFF910000003000ULL  // setelah AHCI_VIRT (+0x1000)

extern uint8_t g_e1000_mac[6];
extern uint8_t *g_e1000_rx_ring_virt;
extern uint64_t g_e1000_rx_buf_phys[E1000_RX_RING_SIZE];
extern int g_e1000_rx_initialized;
extern uint64_t g_net_tx_ok;
extern uint64_t g_net_tx_fail;
extern volatile uint64_t g_e1000_irq_count;
extern volatile uint64_t g_e1000_irq_spurious;
extern volatile uint32_t g_e1000_irq_last_icr;
extern volatile uint32_t g_e1000_irq_icr_or;
extern volatile uint32_t g_e1000_irq_rirr_or;
extern volatile uint32_t g_e1000_irq_masked;
extern volatile uint32_t g_e1000_irq_last_gsi;
extern volatile uint32_t g_e1000_irq_gsi;
extern uint32_t g_e1000_rx_next;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len);
void e1000_irq_experiment(void);
void e1000_probe_and_log(uint64_t pml4_phys);
void e1000_send_test_packet(void);
void e1000_log_ip(volatile uint8_t *p);
void e1000_log_mac(volatile uint8_t *p);
void crypto_selftest(void);
void auth_load_key(void);

// ---- crypto.c (SHA-256 + HMAC-SHA256) ----
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

extern int g_crypto_ok;
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint32_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t *hash);
void hmac_sha256(const uint8_t *key, uint32_t keylen, const uint8_t *msg, uint32_t msglen, uint8_t *out);
int ct_memeq(const void *a, const void *b, uint32_t n);

// ---- net.c (ARP/IPv4/ICMP/UDP/TCP) ----
#define NET_UDP_BUDGET_PER_SEC 100
#define NET_UDP_SRC_PER_SEC 20

extern const uint8_t g_net_ip[4];
extern uint32_t g_net_arp_replies_sent;
extern uint64_t g_net_tx_buf_phys;
extern uint32_t g_net_icmp_replies_sent;
extern uint16_t g_net_ip_id;
extern uint32_t g_net_udp_echo_count;
extern uint64_t g_net_udp_dropped;
extern uint64_t g_net_rx_frames;
extern uint64_t g_net_rx_errors;
extern uint64_t g_auth_ok;
extern uint64_t g_auth_denied[5];
extern uint64_t g_chal_issued;
extern uint64_t g_chal_noentropy;
extern uint64_t g_chal_ip_recycled;
extern uint64_t g_priv_ok;
extern uint64_t g_priv_denied[6];
extern uint64_t g_auth_ctr_off;
extern uint64_t g_net_rx_arp;
extern uint64_t g_net_rx_ipv4;
extern uint64_t g_net_rx_other;
extern uint64_t g_net_udp_badsum;
extern uint64_t g_net_udp_src_dropped;
extern uint64_t g_tcp_rx;
extern uint64_t g_tcp_badsum;
extern uint64_t g_tcp_rst_sent;
extern uint64_t g_tcp_conn_open;
extern uint64_t g_tcp_busy;
extern uint64_t g_tcp_rx_bytes;
extern uint64_t g_tcp_timeouts;
extern uint64_t g_tcp_noentropy;
extern uint64_t g_tcp_tx_bytes;
extern uint64_t g_tcp_acked_bytes;
extern uint64_t g_tcp_retx;
extern uint64_t g_tcp_retx_giveup;
extern uint64_t g_tcp_close_ok;
extern uint64_t g_tcp_rst_state;
extern uint64_t g_tcp_conn_dropped;
extern uint64_t g_tcp_dupack_limited;
extern uint64_t g_tcp_src_full;
extern uint64_t g_tcp_synrcvd_evicted;
extern uint64_t g_cli_login_ok;
extern uint64_t g_cli_login_fail;
extern uint64_t g_cli_login_timeout;
extern uint64_t g_cli_line_long;
extern uint64_t g_cli_cmd_ok;
extern uint64_t g_cli_cmd_fail;
extern uint64_t g_cli_login_ro;
extern uint64_t g_cli_sess_full;
extern uint64_t g_cli_idle_timeout;
extern uint64_t g_cli_role_denied;
// D4: peran sesi TCP. Admin = kunci KEY.TXT, read-only = kunci KEYRO.TXT.
enum { AUTH_ROLE_NONE = 0, AUTH_ROLE_ADMIN, AUTH_ROLE_RO };
int auth_tcp_login(const uint8_t nonce[16], const uint8_t *line, uint32_t len,
                   int *role);
int auth_tcp_cmd(const uint8_t nonce[16], int role, uint64_t seq,
                 const uint8_t *line, uint32_t len, uint32_t *cmd_len);
uint32_t auth_tcp_exec(int role, const uint8_t *cmd, uint32_t len, uint8_t *out,
                       uint32_t max, int *reboot);
void auth_reboot(void);
int auth_cmd_allowed(int role, const uint8_t *cmd, uint32_t len);
int net_tcp_state(void);
int net_tcp_conn_active(void);
extern uint64_t g_e1000_mpc;
extern uint64_t g_e1000_rnbc;
extern uint64_t g_net_log_muted;
uint16_t net_checksum16(volatile uint8_t *p, uint32_t len);
void e1000_stats_poll(void);
uint16_t net_udp_checksum(const volatile uint8_t *src_ip, const volatile uint8_t *dst_ip, const volatile uint8_t *udp, uint32_t udp_len);
uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen);
void net_tcp_tick(void);
int net_poll(void);

// ---- kernel.c (dipakai modul lain) ----
#define NET_UDP_CMD_PORT 7778
extern volatile uint64_t timer_ticks;
void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len);

// ---- auth.c (kunci, HMAC, nonce, perintah berprivilege): tanpa simbol baru ----

// ---- audit.c (D5: audit log di RAM, dua ring) ----
// Urutan enum = indeks nama di audit.c; mulai AUDIT_LOGIN_FAIL = ring gagal.
enum { AUDIT_TCP = 0, AUDIT_UDP, AUDIT_TLS };
enum { AUDIT_LOGIN = 0, AUDIT_CMD, AUDIT_CMD_ROLE, AUDIT_IDLE,
       AUDIT_LOGIN_FAIL, AUDIT_LOGIN_TIMEOUT, AUDIT_LINE_LONG, AUDIT_CMD_FAIL };
void audit_record(int ev, int chan, const volatile uint8_t *ip, uint16_t port,
                  int role, int code, const volatile uint8_t *cmd, uint32_t cmd_len);
void audit_dump(int fail);

// ---- kernel.c: perintah (cmd), dipakai auth.c ----
#define CMD_OUT_MAX 1400
extern uint32_t g_cmd_len;
void cmd_putc(char c);
void cmd_puts(const char *s);
int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name);
void net_cmd_execute(const volatile uint8_t *cmd, uint32_t len);
const char *cmd_out(void);

// ---- metrics.c (R3: registry metrik) ----
void metrics_execute(const volatile uint8_t *args, uint32_t len);
void metrics_cpu_tick(int idle);
extern uint64_t g_cpu_idle_ticks;
extern uint32_t g_cpu_busy_pct;
int net_tcp_cli_active(void);   // net.c: TCB port 7779 / 7780 bukan CLOSED
int net_tcp_tls_active(void);
extern uint64_t g_nc_lost, g_nc_sent, g_nc_arp, g_nc_tx_fail;   // netcon.c
extern uint64_t g_audit_seq;    // audit.c: nomor urut entri terakhir
void net_udp_send_cmd_reply(volatile uint8_t *req, uint32_t ihl);

// ---- sched.c (task, scheduler, semaphore, user task, spawn) ----
#define MAX_TASKS 10   // R6-1: 8 -> 10 (slot dev: 8 task uji + net + idle, sejak TSS-1)

typedef enum {
    TASK_READY,
    TASK_DEAD,
    TASK_SLEEPING,
    TASK_BLOCKED,
} task_status_t;

typedef struct semaphore {
    int count;
} semaphore_t;

typedef struct {
    uint64_t rsp;
    task_status_t status;
    uint64_t wake_at_tick;
    size_t waiting_for;
    // NULL kalau task tidak sedang menunggu semaphore manapun.
    // BLOCKED karena task_wait_for() punya waiting_for_sem == NULL;
    // BLOCKED karena sem_wait() punya waiting_for_sem != NULL.
    semaphore_t *waiting_for_sem;
    // true kalau task ini jalan di ring 3 (user task). Scheduler
    // belum membedakan perlakuan berdasarkan field ini -- baru
    // dipakai untuk penandaan; integrasi penuh (context_switch vs
    // enter_usermode saat first-run) menyusul.
    bool is_user_task;
    // Top of this task's kernel stack -- disalin ke bmahOS_tss.rsp0
    // oleh schedule() setiap kali task ini yang akan berjalan. Wajib
    // per-task supaya banyak user task preemptive tidak berebut satu
    // kernel stack global saat masing-masing trap ke ring 0.
    uint64_t rsp0;
    // Dipakai HANYA oleh user_task_trampoline() saat task user ini
    // pertama kali dijalankan lewat context_switch(). user_stack_top
    // sudah dihitung sebagai base+PMM_PAGE_SIZE (siap pakai langsung
    // sebagai RSP awal ring 3, tidak perlu dihitung ulang).
    uint64_t user_entry;
    uint64_t user_stack_top;
    // Layer 8 checkpoint 1 (dormant): PML4 physical address milik
    // task ini. Task kernel (task_create()) akan diisi dengan PML4
    // global (read_cr3() awal) -- TIDAK PUNYA address space sendiri,
    // sengaja tetap share. Task user (task_create_user()) akan diisi
    // hasil vmm_clone_kernel_pml4() -- PML4 privat per task. BELUM
    // dipakai schedule()/context_switch() di checkpoint ini -- field
    // ini ada tapi tidak mengubah behavior apa pun sampai checkpoint
    // berikutnya.
    uint64_t pml4_phys;
    // Checkpoint allocator: alamat virtual berikutnya yang bebas
    // dipakai di address space task ini (bump allocator, TIDAK ADA
    // free/reclaim). Hanya bermakna untuk user task -- task kernel
    // tidak pernah exec() sehingga field ini tidak diinisialisasi
    // untuk task_create() biasa. Nilai awal diisi USER_VADDR_ALLOC_BASE
    // oleh task_create_user().
    uint64_t next_free_vaddr;
} task_t;

extern task_t tasks[MAX_TASKS];
extern size_t task_count;
extern size_t g_idle_index;
extern volatile bool scheduler_started;
extern size_t current_index;
extern void context_switch(uint64_t *old_rsp_ptr, uint64_t new_rsp, uint64_t new_pml4_phys);
void task_create(task_t *task, void (*entry_function)(void), uint64_t stack_size);
void task_create_user(task_t *task, uint64_t pml4_phys, uint64_t user_code_vaddr, uint64_t user_stack_vaddr, uint64_t kernel_stack_size, const uint8_t *code, size_t code_len);
task_t * spawn(const uint8_t *image, size_t image_len);
void schedule(void);
void task_exit(void);
void task_sleep(uint64_t ticks);
void task_wait_for(size_t target_index);
void sem_wait(semaphore_t *sem);
void sem_post(semaphore_t *sem);
void task_a_entry(void);
void task_b_entry(void);

// ---- kernel.c: dipakai sched.c ----
extern void enter_usermode(uint64_t entry_vaddr, uint64_t user_stack_top);
extern uint64_t g_current_pml4_phys;
extern uint64_t g_kernel_pml4_phys;


// ---- cmd.c (isi perintah) ----


// ---- kernel.c: dipakai cmd.c ----
#define LOG_RING_SIZE 8192
extern char g_log_ring[LOG_RING_SIZE];
extern uint32_t g_log_head;
extern uint64_t g_log_total;
extern volatile uint64_t g_net_loops;


// ---- trap.c (exception, IRQ, syscall) ----
struct exception_context
{
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rbp;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rbx;
    uint64_t rax;

    uint64_t vector;
    uint64_t error_code;

    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;      // long mode: CPU selalu menyimpan SS:RSP
    uint64_t ss;
};
void trigger_breakpoint(void);

// ---- kernel.c: dipakai trap.c ----

void net_rx_tick_wake(void);
void e1000_irq_service(void);

// ---- cpufeat.c (F1.5: fitur CPU dari CPUID) ----
struct cpu_features {
    char vendor[13];
    char hv_vendor[13];
    uint32_t max_leaf;
    uint32_t max_ext_leaf;
    uint32_t family;
    uint32_t model;
    uint32_t stepping;
    uint8_t rdrand, rdseed, nx, smep, smap, umip, pcid;
    uint8_t apic, x2apic, tsc, tsc_invariant, sse2, hypervisor;
};
extern struct cpu_features g_cpu;
void cpu_features_init(void);

// ---- ktimer.c (C3a: timer dengan callback, bisa dibatalkan) ----
// Callback dijalankan ktimer_run() di loop net task (konteks task, bukan IRQ).
typedef struct ktimer {
    uint64_t deadline;   // tick absolut
    void (*fn)(void *arg);
    void *arg;
    int armed;
    struct ktimer *next;
} ktimer_t;
void ktimer_start(ktimer_t *t, uint64_t ticks, void (*fn)(void *arg), void *arg);
int ktimer_cancel(ktimer_t *t);
int ktimer_pending(const ktimer_t *t);
int ktimer_run(void);
void ktimer_selftest(void);
extern uint64_t g_ktimer_fired;
extern uint64_t g_ktimer_cancelled;
extern uint64_t g_ktimer_late_max;

// ---- entropy.c (F1.8: kolam entropi + HMAC-DRBG SP 800-90A) ----
// entropy_get() = 0 berarti entropi belum cukup: pemanggil WAJIB menolak.
#define ENTROPY_SRC_TIMER   0
#define ENTROPY_SRC_NIC_IRQ 1
#define ENTROPY_SRC_RX      2
#define ENTROPY_SRC_COUNT   3
typedef struct {
    uint8_t k[32];
    uint8_t v[32];
    uint64_t reseed_counter;
} hmac_drbg_t;
void hmac_drbg_instantiate(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                           const uint8_t *nonce, uint32_t nonce_len,
                           const uint8_t *pers, uint32_t pers_len);
void hmac_drbg_reseed(hmac_drbg_t *d, const uint8_t *ent, uint32_t ent_len,
                      const uint8_t *add, uint32_t add_len);
void hmac_drbg_generate(hmac_drbg_t *d, uint8_t *out, uint32_t out_len,
                        const uint8_t *add, uint32_t add_len);
int hmac_drbg_selftest(void);
void entropy_init(void);
void entropy_event(uint32_t src, uint64_t extra);
void entropy_event_tsc(uint32_t src, uint64_t tsc, uint64_t extra);
void entropy_poll(void);
int entropy_get(uint8_t *out, uint32_t len);
extern int g_entropy_ready;
extern uint64_t g_entropy_ready_tick;
extern uint64_t g_entropy_events;
extern uint64_t g_entropy_jitter_bits;
extern uint64_t g_entropy_hw_bits;
extern uint64_t g_entropy_denied;
extern uint64_t g_drbg_reseeds;

// ---- kprintf.c (F1.6: kprintf, ksnprintf, ASSERT) ----
// Format: %s %c %d %u %x %p %%, awalan 'l' = 64-bit untuk d/u/x.
void kprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
size_t ksnprintf(char *buf, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void kprintf_selftest(void);
__attribute__((noreturn)) void kassert_fail(const char *expr, const char *file, int line, const char *func);
#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            kassert_fail(#cond, __FILE__, __LINE__, __func__); \
        } \
    } while (0)

// ---- panic.c (R1: panic handler) ----
#define PANIC_REBOOT_S 10
#define DF_STACK_SIZE  16384
extern uint8_t g_df_stack[];   // cpu.c, TSS.IST1
typedef struct {
    uint64_t text_lo;
    uint64_t text_hi;
    uint64_t stack_min;
} panic_bounds_t;
enum { PANIC_WALK_END, PANIC_WALK_BADRBP, PANIC_WALK_NOTEXT, PANIC_WALK_MAX };
const char *panic_exc_name(uint64_t vector);
void panic_pf_decode(uint64_t err, char *buf, size_t size);
int panic_walk(uint64_t rbp, const panic_bounds_t *b, uint64_t *out, int max, int *why);
void panic_begin(void);
__attribute__((noreturn)) void panic_finish(uint64_t rip, uint64_t rbp);
__attribute__((noreturn)) void panic_exception(struct exception_context *c);
int panic_test_execute(const volatile uint8_t *cmd, uint32_t len);   // build dev saja

// ---- watchdog.c (R5: watchdog perangkat lunak) ----
#define WD_TIMEOUT_TICKS 1000   // 10 s tanpa tepukan net task -> panic + reboot
extern volatile uint64_t g_wd_last;
extern volatile int g_wd_armed;
extern size_t g_wd_task;
extern uint64_t g_wd_pets, g_wd_gap_max;
uint64_t wd_overdue(uint64_t now, uint64_t last);
void wd_saved_frame(uint64_t rsp, uint64_t *rip, uint64_t *rbp);
void watchdog_pet(void);                          // net task, tiap putaran loop
void watchdog_check(struct exception_context *c); // irq_handler (timer), hanya memeriksa
void watchdog_status(void);                       // perintah `wd`
uint64_t watchdog_timeout_ticks(void);
int wd_test_execute(const volatile uint8_t *cmd, uint32_t len);   // build dev saja

#endif

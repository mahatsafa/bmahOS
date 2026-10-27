// F1.7: stub simbol kernel untuk uji di host. Semua weak: kalau file uji
// menyertakan modul yang mendefinisikan simbol yang sama, definisi modul menang.
// serial_putc/serial_write ditangkap ke g_serial_cap supaya bisa diperiksa.

#include <stdlib.h>
#include "kernel.h"
#include "test.h"

#define WEAK __attribute__((weak))

int g_test_pass = 0;
int g_test_fail = 0;

char g_serial_cap[65536];
size_t g_serial_cap_len = 0;

void serial_capture_reset(void)
{
    g_serial_cap_len = 0;
    g_serial_cap[0] = '\0';
}

WEAK volatile int g_serial_mute = 0;
WEAK volatile uint64_t timer_ticks = 0;

WEAK void serial_putc(char c)
{
    if (g_serial_cap_len < sizeof(g_serial_cap) - 1) {
        g_serial_cap[g_serial_cap_len++] = c;
        g_serial_cap[g_serial_cap_len] = '\0';
    }
}

WEAK void serial_write(const char *s)
{
    while (*s) {
        serial_putc(*s++);
    }
}

WEAK void serial_write_nolog(const char *s)
{
    if (!g_serial_mute) {
        serial_write(s);
    }
}

// R2: netcon.c hanya di-#include oleh test_net.
WEAK uint32_t g_netcon_on = 0;
WEAK uint32_t g_netcon_host = NETCON_HOST_DEF;
WEAK uint32_t g_netcon_port = NETCON_PORT_DEF;
WEAK volatile int g_netcon_hold = 0;
WEAK int g_netcon_flushes = 0;

WEAK void netcon_panic_flush(void)
{
    g_netcon_flushes++;
}

// P4: filter.c tidak ikut di uji lain: tanpa aturan (semua lolos), perintah tidak ditangani.
WEAK int filter_ipv4(const volatile uint8_t *buf, uint32_t ihl, uint32_t payload_len)
{
    (void)buf;
    (void)ihl;
    (void)payload_len;
    return 1;
}

WEAK int filter_execute(const volatile uint8_t *cmd, uint32_t len)
{
    (void)cmd;
    (void)len;
    return 0;
}

// P3-2: sntp.c tidak ikut di uji lain: tidak ada balasan yang ditunggu.
WEAK void sntp_arp_seen(const volatile uint8_t *buf)
{
    (void)buf;
}

WEAK int sntp_wants(const volatile uint8_t *src_ip, uint16_t sport, uint16_t dport)
{
    (void)src_ip;
    (void)sport;
    (void)dport;
    return 0;
}

WEAK void sntp_rx(const volatile uint8_t *p, uint32_t len)
{
    (void)p;
    (void)len;
}

WEAK int sntp_execute(const volatile uint8_t *cmd, uint32_t len)
{
    (void)cmd;
    (void)len;
    return 0;
}

// P3-3: dns.c tidak ikut di uji lain.
WEAK void dns_arp_seen(const volatile uint8_t *buf)
{
    (void)buf;
}

WEAK int dns_wants(const volatile uint8_t *src_ip, uint16_t sport, uint16_t dport)
{
    (void)src_ip;
    (void)sport;
    (void)dport;
    return 0;
}

WEAK void dns_rx(const volatile uint8_t *p, uint32_t len)
{
    (void)p;
    (void)len;
}

WEAK int dns_execute(const volatile uint8_t *cmd, uint32_t len)
{
    (void)cmd;
    (void)len;
    return 0;
}

// P6-1: monitor.c tidak ikut di uji lain.
WEAK void monitor_arp_seen(const volatile uint8_t *buf)
{
    (void)buf;
}

WEAK void monitor_icmp_reply(const volatile uint8_t *buf, uint32_t ihl, uint32_t icmp_len)
{
    (void)buf;
    (void)ihl;
    (void)icmp_len;
}

WEAK int monitor_execute(const volatile uint8_t *cmd, uint32_t len)
{
    (void)cmd;
    (void)len;
    return 0;
}

WEAK int monitor_tcp_seen(const volatile uint8_t *buf, uint32_t r)
{
    (void)buf;
    (void)r;
    return 0;
}

WEAK void monitor_dns_done(uint32_t tok, int a, const char *what)
{
    (void)tok;
    (void)a;
    (void)what;
}

WEAK int g_logdisk_syncs = 0;

WEAK void logdisk_sync(int panic)
{
    (void)panic;
    g_logdisk_syncs++;
}

// R1: kassert_fail (kprintf.c) memanggil panic.c.
// R6-3: counter pmm (dirujuk oom_panic di panic.c).
WEAK uint64_t g_pmm_allocs, g_pmm_frees, g_pmm_fail;

// R6-2: vmm.c tidak dikompilasi di host.
WEAK int kstack_guard_find(uint64_t addr, uint64_t *lo, uint64_t *top)
{
    (void)addr;
    (void)lo;
    (void)top;
    return 0;
}

WEAK void panic_begin(void)
{
}

WEAK void panic_finish(uint64_t rip, uint64_t rbp)
{
    (void)rip;
    (void)rbp;
    abort();
}

WEAK void serial_write_hex(uint64_t value)
{
    static const char hx[] = "0123456789ABCDEF";
    serial_write("0x");
    for (int i = 60; i >= 0; i -= 4) {
        serial_putc(hx[(value >> i) & 0xF]);
    }
}

int test_done(const char *name)
{
    printf("%-12s %d lulus, %d gagal\n", name, g_test_pass, g_test_fail);
    return g_test_fail == 0 ? 0 : 1;
}

size_t test_unhex(const char *hex, unsigned char *out, size_t max)
{
    size_t n = strlen(hex) / 2;
    if (n > max) {
        abort();
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

int test_hex_eq(const unsigned char *buf, size_t len, const char *hex)
{
    static const char hx[] = "0123456789abcdef";
    if (strlen(hex) != len * 2) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (hex[i * 2] != hx[buf[i] >> 4] || hex[i * 2 + 1] != hx[buf[i] & 0xF]) {
            return 0;
        }
    }
    return 1;
}

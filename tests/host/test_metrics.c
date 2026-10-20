// R3: uji registry metrik (kernel/metrics.c di-#include: akses g_metrics).
// Semua counter yang dirujuk tabel didefinisikan di sini; kunci baru tanpa
// definisi di sini = gagal link (sengaja, supaya uji ikut diperbarui).

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

// ---- simbol yang dirujuk tabel ----
uint64_t kheap_current = KHEAP_START + 4096;
uint64_t kheap_mapped_end = KHEAP_START + 65536;
size_t task_count = 4;
uint64_t pmm_usable_memory = 512ULL * 1024 * 1024;
uint64_t g_log_total, g_net_rx_frames, g_net_rx_errors, g_e1000_mpc, g_e1000_rnbc;
volatile uint64_t g_e1000_irq_count;
volatile uint32_t g_e1000_irq_icr_or;
uint64_t g_net_rx_arp, g_net_rx_ipv4, g_net_rx_other, g_net_tx_ok, g_net_tx_fail;
uint32_t g_net_arp_replies_sent, g_net_icmp_replies_sent, g_net_udp_echo_count;
uint64_t g_net_udp_dropped, g_net_udp_src_dropped, g_net_log_muted, g_net_udp_badsum;
uint64_t g_tcp_rx, g_tcp_badsum, g_tcp_rst_sent, g_tcp_conn_open, g_tcp_busy;
uint64_t g_tcp_rx_bytes, g_tcp_timeouts, g_tcp_noentropy, g_tcp_tx_bytes;
uint64_t g_tcp_acked_bytes, g_tcp_retx, g_tcp_retx_giveup, g_tcp_close_ok;
uint64_t g_tcp_rst_state, g_tcp_conn_dropped, g_tcp_dupack_limited, g_tcp_src_full;
uint64_t g_tcp_synrcvd_evicted;
uint64_t g_cli_login_ok, g_cli_login_fail, g_cli_login_timeout, g_cli_line_long;
uint64_t g_cli_cmd_ok, g_cli_cmd_fail, g_cli_login_ro, g_cli_sess_full;
uint64_t g_cli_idle_timeout, g_cli_role_denied;
int g_entropy_ready;
uint64_t g_entropy_ready_tick, g_entropy_events, g_entropy_hw_bits;
uint64_t g_entropy_jitter_bits, g_entropy_denied, g_drbg_reseeds;
uint64_t g_ktimer_fired, g_ktimer_cancelled, g_ktimer_late_max;
uint64_t g_auth_ok, g_auth_denied[5], g_auth_ctr_off, g_chal_issued;
uint64_t g_chal_noentropy, g_chal_ip_recycled, g_priv_ok, g_priv_denied[6];
uint64_t g_tls_hs_ok, g_tls_fail, g_tls_full, g_tls_noentropy;
uint64_t g_nc_lost, g_nc_sent, g_nc_arp, g_nc_tx_fail;
uint64_t g_fat_wr_ok, g_fat_wr_fail, g_audit_seq;
uint64_t g_ld_written, g_ld_lost, g_ld_wfail, g_ld_bad;
uint64_t g_wd_gap_max, g_wd_pets;
uint64_t g_sys_calls, g_sys_rejected, g_user_faults;

// Getter: nilai dikendalikan g_fn_val (0 atau besar).
static uint64_t g_fn_val;
static int g_free_frames_all;   // 1 = semua frame bebas (mem_free_kb besar)
static int g_stats_polls;

int pmm_bitmap_test(uint64_t frame) { (void)frame; return !g_free_frames_all; }
void e1000_stats_poll(void) { g_stats_polls++; }
int net_tcp_state(void) { return (int)(g_fn_val & 0x7fffffff); }
int net_tcp_conn_active(void) { return (int)(g_fn_val & 0x7fffffff); }
int net_tcp_cli_active(void) { return (int)(g_fn_val & 0x7fffffff); }
int net_tcp_tls_active(void) { return (int)(g_fn_val & 0x7fffffff); }
uint64_t net_stack_used(void) { return g_fn_val; }
uint64_t watchdog_timeout_ticks(void) { return g_fn_val; }

// ---- g_cmd_out tiruan ----
static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len;
void cmd_putc(char c) { if (g_cmd_len < CMD_OUT_MAX) g_out[g_cmd_len++] = c; }
void cmd_puts(const char *s) { while (*s) cmd_putc(*s++); }

#include "metrics.c"

static const char *run(const char *args)
{
    g_cmd_len = 0;
    metrics_execute((const volatile uint8_t *)args, (uint32_t)strlen(args));
    g_out[g_cmd_len] = '\0';
    return g_out;
}

// Isi semua counter lewat pointer tabel (nilai maks = baris terpanjang).
static void set_all(uint64_t v)
{
    for (uint32_t i = 0; i < METRICS_N; i++) {
        if (g_metrics[i].p64) {
            *(uint64_t *)(uintptr_t)g_metrics[i].p64 = v;
        } else if (g_metrics[i].p32) {
            *(uint32_t *)(uintptr_t)g_metrics[i].p32 = (uint32_t)v;
        }
    }
    g_fn_val = v;
    g_entropy_ready = (int)(v & 1);
    timer_ticks = v;
    kheap_current = KHEAP_START + (v & 0xffffff);
    g_free_frames_all = v != 0;
}

// Ikuti halaman seperti klien; seen[i] = berapa kali kunci i muncul.
// Return jumlah halaman, -1 bila ada pelanggaran format.
static int walk(const char *pfx, int seen[], uint32_t *maxlen)
{
    char args[64];
    int pages = 0;
    long next = 0;

    memset(seen, 0, sizeof(int) * METRICS_N);
    *maxlen = 0;
    for (;;) {
        if (next == 0) {
            snprintf(args, sizeof(args), "%s%s", pfx[0] ? " " : "", pfx);
        } else {
            snprintf(args, sizeof(args), "%s%s %ld", pfx[0] ? " " : "", pfx, next);
        }
        const char *o = run(args);
        uint32_t n = g_cmd_len;
        pages++;
        if (n > *maxlen) *maxlen = n;
        if (n == 0 || o[n - 1] != '\n' || n > CMD_OUT_MAX || pages > 50) return -1;
        next = -1;
        for (const char *l = o; *l; ) {
            const char *e = strchr(l, '\n');
            const char *eq = memchr(l, '=', (size_t)(e - l));
            if (!eq) return -1;
            size_t kl = (size_t)(eq - l);
            if (kl == strlen(METRICS_NEXT_KEY) - 1 && memcmp(l, METRICS_NEXT_KEY, kl) == 0) {
                if (e[1] != '\0') return -1;          // lanjut harus baris terakhir
                next = strtol(eq + 1, NULL, 10);
            } else {
                int found = 0;
                for (uint32_t i = 0; i < METRICS_N; i++) {
                    if (strlen(g_metrics[i].name) == kl &&
                        memcmp(g_metrics[i].name, l, kl) == 0) {
                        seen[i]++;
                        found = 1;
                    }
                }
                if (!found) return -1;
            }
            l = e + 1;
        }
        if (next < 0) return pages;
    }
}

static void test_table(void)
{
    CHECK(METRICS_N == 107);
    CHECK_STR(g_metrics[0].name, "uptime_ticks");
    CHECK_STR(g_metrics[77].name, "priv_hmac");     // 78 kunci lama di depan
    CHECK_STR(g_metrics[78].name, "uptime_s");
    CHECK_STR(g_metrics[96].name, "audit_seq");
    CHECK_STR(g_metrics[METRICS_N - 1].name, "user_faults");
    int ok_chars = 1, ok_len = 1, ok_uniq = 1, ok_kind = 1;
    for (uint32_t i = 0; i < METRICS_N; i++) {
        const char *n = g_metrics[i].name;
        size_t l = strlen(n);
        if (l < 1 || l > METRICS_PFX_MAX) ok_len = 0;
        if (n[0] < 'a' || n[0] > 'z') ok_chars = 0;
        for (size_t k = 0; k < l; k++) {
            char c = n[k];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) ok_chars = 0;
        }
        if (!strcmp(n, "metrics_lanjut")) ok_uniq = 0;
        for (uint32_t j = 0; j < i; j++) {
            if (!strcmp(n, g_metrics[j].name)) ok_uniq = 0;
        }
        int kinds = !!g_metrics[i].p64 + !!g_metrics[i].p32 + !!g_metrics[i].fn;
        if (kinds != 1) ok_kind = 0;
    }
    CHECK(ok_chars);
    CHECK(ok_len);
    CHECK(ok_uniq);
    CHECK(ok_kind);
}

static void test_pages(void)
{
    int seen[METRICS_N];
    uint32_t maxlen;
    const uint64_t vals[] = { 0, 7, 1234567, UINT64_MAX };

    for (size_t v = 0; v < sizeof(vals) / sizeof(vals[0]); v++) {
        set_all(vals[v]);
        int pages = walk("", seen, &maxlen);
        CHECK(pages >= 2);
        int once = 1;
        for (uint32_t i = 0; i < METRICS_N; i++) {
            if (seen[i] != 1) once = 0;
        }
        CHECK(once);
        CHECK(maxlen <= CMD_OUT_MAX);
        if (vals[v] == UINT64_MAX) {
            CHECK(pages >= 3);   // 97 baris x ~40 byte
        }
    }

    // Nilai kecil: kunci lama (78) masih di halaman 1, sama seperti sebelum R3.
    set_all(0);
    run("");
    CHECK(strstr(g_out, "\npriv_hmac=0\n") != NULL);
    const char *lj = strstr(g_out, "\n" METRICS_NEXT_KEY);
    CHECK(lj != NULL && strtol(lj + strlen(METRICS_NEXT_KEY) + 1, NULL, 10) > 78);
    CHECK(strncmp(g_out, "uptime_ticks=0\nmem_free_kb=0\n", 29) == 0);

    // Nilai: getter dan pointer u32/u64.
    set_all(0);
    g_tcp_rx = 42;
    g_net_udp_echo_count = 9;
    timer_ticks = 12345;
    run(" 78");
    CHECK(strncmp(g_out, "uptime_s=123\n", 13) == 0);
    run(" tcp_rx");
    CHECK_STR(g_out, "tcp_rx=42\ntcp_rx_bytes=0\n");
    run(" udp_echo");
    CHECK_STR(g_out, "udp_echo=9\n");
    g_stats_polls = 0;
    run(" rx_missed");
    CHECK(g_stats_polls == 1);
}

static void test_prefix(void)
{
    int seen[METRICS_N];
    uint32_t maxlen;

    set_all(UINT64_MAX);
    int pages = walk("tcp_", seen, &maxlen);
    CHECK(pages >= 1);
    int ok = 1, n = 0;
    for (uint32_t i = 0; i < METRICS_N; i++) {
        int want = strncmp(g_metrics[i].name, "tcp_", 4) == 0;
        if (seen[i] != want) ok = 0;
        n += want;
    }
    CHECK(ok);
    CHECK(n == 20);
    CHECK(maxlen <= CMD_OUT_MAX);

    set_all(0);
    CHECK_STR(run(" cpu_"), "cpu_idle_ticks=0\ncpu_busy_pct=0\n");
    CHECK_STR(run(" netcon_"), "netcon_sent=0\nnetcon_lost=0\nnetcon_arp=0\nnetcon_tx_fail=0\n");
    CHECK_STR(run(" audit_seq"), "audit_seq=0\n");
    CHECK_STR(run(" tcp_ 42"), "tcp_conn_active=0\n");   // mulai = indeks tabel
    CHECK_STR(run(" priv_hmac 77"), "priv_hmac=0\n");
    CHECK_STR(run(" 96 "), "ERR: metrics [awalan] [mulai]\n");
    CHECK_STR(run(" 97"), "logdisk_written=0\nlogdisk_lost=0\nlogdisk_wfail=0\nlogdisk_bad=0\n"
              "wd_timeout_ticks=0\nwd_gap_max=0\nwd_pets=0\n"
              "sys_calls=0\nsys_rejected=0\nuser_faults=0\n");
    CHECK_STR(run(" 104"), "sys_calls=0\nsys_rejected=0\nuser_faults=0\n");
    CHECK_STR(run(" zzz"), "ERR: metrics: tidak ada kunci yang cocok\n");
    CHECK_STR(run(" tcp_ 43"), "ERR: metrics: tidak ada kunci yang cocok\n");
    // awalan 32 byte boleh, 33 ditolak
    CHECK_STR(run(" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
              "ERR: metrics: tidak ada kunci yang cocok\n");
    CHECK_STR(run(" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "ERR: metrics [awalan] [mulai]\n");
}

static void test_bad_args(void)
{
    static const char *const bad[] = {
        " ", "  ", " tcp_  1", "  tcp_", " tcp_ ", " 1 2", " 1 tcp_", " tcp_ udp_",
        " TCP_", " tcp-", " 107", " 99999", " 123456", " 1a", " tcp_ 1x", "x",
        " tcp_\t", " -1",
    };
    set_all(0);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        const char *o = run(bad[i]);
        if (strcmp(o, "ERR: metrics [awalan] [mulai]\n") != 0) {
            fprintf(stderr, "argumen %zu \"%s\" -> %s", i, bad[i], o);
        }
        CHECK_STR(o, "ERR: metrics [awalan] [mulai]\n");
    }
    CHECK(strncmp(run(" 0"), "uptime_ticks=0\n", 15) == 0);
    CHECK(strncmp(run(" 00"), "uptime_ticks=0\n", 15) == 0);
}

static void test_cpu(void)
{
    // Jendela 100 tick: 25 idle -> 75 %.
    g_cpu_idle_ticks = 0;
    g_cpu_busy_pct = 0;
    g_cpu_win_start = 0;
    g_cpu_win_idle = 0;
    timer_ticks = 0;
    for (int t = 1; t <= 99; t++) {
        timer_ticks = (uint64_t)t;
        metrics_cpu_tick(t <= 25);
    }
    CHECK(g_cpu_busy_pct == 0);          // jendela pertama belum lengkap
    timer_ticks = 100;
    metrics_cpu_tick(0);
    CHECK(g_cpu_busy_pct == 75);
    CHECK(g_cpu_idle_ticks == 25);
    for (int t = 101; t <= 200; t++) {   // semua idle
        timer_ticks = (uint64_t)t;
        metrics_cpu_tick(1);
    }
    CHECK(g_cpu_busy_pct == 0);
    for (int t = 201; t <= 300; t++) {   // tanpa idle
        timer_ticks = (uint64_t)t;
        metrics_cpu_tick(0);
    }
    CHECK(g_cpu_busy_pct == 100);
    CHECK(g_cpu_idle_ticks == 125);
    // Tick terlewat (jendela 150 tick): 30 idle -> 80 %.
    timer_ticks = 330;
    metrics_cpu_tick(1);
    for (int i = 0; i < 29; i++) metrics_cpu_tick(1);  // tick sama, tanpa jendela baru
    timer_ticks = 450;
    metrics_cpu_tick(0);
    CHECK(g_cpu_busy_pct == 80);
}

int main(void)
{
    test_table();
    test_pages();
    test_prefix();
    test_bad_args();
    test_cpu();
    return test_done("metrics");
}

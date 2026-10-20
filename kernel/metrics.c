#include "kernel.h"

// ---- R3: registry metrik ----
// Satu tabel untuk semua kunci perintah `metrics` (format "kunci=nilai" per
// baris, urutan = urutan tabel). Counter tetap didefinisikan di modulnya;
// tabel ini satu-satunya daftar yang diekspor. Nilai dibaca langsung lewat
// pointer (u64/u32) atau getter untuk nilai turunan.
//
// R3-2: `metrics [awalan] [mulai]`. Keluaran dibagi halaman: baris ditulis
// utuh selama muat di CMD_OUT_MAX (dengan cadangan untuk baris penutup);
// kalau masih ada kunci tersisa, baris terakhir "metrics_lanjut=<indeks>"
// dan `metrics [awalan] <indeks>` melanjutkan. Tidak pernah terpotong diam-diam.
// Kunci baru selalu ditambah di akhir tabel (kunci lama tetap di halaman 1).

typedef struct {
    const char *name;
    const volatile uint64_t *p64;
    const volatile uint32_t *p32;
    uint64_t (*fn)(void);
} metric_t;

#define M64(n, v) { n, &(v), 0, 0 }
#define M32(n, v) { n, 0, &(v), 0 }
#define MFN(n, f) { n, 0, 0, f }

#define METRICS_PFX_MAX 32   // panjang awalan maks (nama kunci maks 32, host-test)

// Scan bitmap PMM; tidak dikunci terhadap pmm_alloc() task lain, jadi angka
// perkiraan sesaat (sama seperti perintah mem).
static uint64_t met_mem_free_kb(void)
{
    uint64_t free_frames = 0;

    for (uint64_t f = 0; f < PMM_MAX_FRAMES; f++) {
        if (!pmm_bitmap_test(f)) {
            free_frames++;
        }
    }
    return free_frames * PMM_PAGE_SIZE / 1024ULL;
}

static uint64_t met_heap_used(void)
{
    return (uint64_t)kheap_current - (uint64_t)KHEAP_START;
}

static uint64_t met_tasks(void)
{
    return task_count;
}

// Register statistik E1000 dibaca (dan dikosongkan) sekali, sebelum rx_missed
// dan rx_nobuf.
static uint64_t met_rx_missed(void)
{
    e1000_stats_poll();
    return g_e1000_mpc;
}

static uint64_t met_rx_overrun_irq(void)
{
    return (g_e1000_irq_icr_or >> 6) & 1u;
}

static uint64_t met_tcp_state(void)
{
    return (uint64_t)net_tcp_state();
}

static uint64_t met_tcp_conn_active(void)
{
    return (uint64_t)net_tcp_conn_active();
}

static uint64_t met_entropy_ready(void)
{
    return (uint64_t)g_entropy_ready;
}

static uint64_t met_uptime_s(void)
{
    return timer_ticks / 100;
}

// ---- R3: beban CPU ----
// Dipanggil irq_handler tiap tick timer (interrupt mati); idle = task yang
// terinterupsi adalah task idle (hlt). cpu_busy_pct = persen tick bukan-idle
// pada jendela CPU_WIN_TICKS terakhir yang sudah lengkap (0 sebelum jendela
// pertama selesai).
#define CPU_WIN_TICKS 100

uint64_t g_cpu_idle_ticks = 0;
uint32_t g_cpu_busy_pct = 0;
static uint64_t g_cpu_win_start, g_cpu_win_idle;

void metrics_cpu_tick(int idle)
{
    uint64_t now = timer_ticks;

    if (idle) {
        g_cpu_idle_ticks++;
    }
    if (now - g_cpu_win_start >= CPU_WIN_TICKS) {
        uint64_t span = now - g_cpu_win_start;
        uint64_t n = g_cpu_idle_ticks - g_cpu_win_idle;

        g_cpu_busy_pct = (uint32_t)(n >= span ? 0 : (span - n) * 100 / span);
        g_cpu_win_start = now;
        g_cpu_win_idle = g_cpu_idle_ticks;
    }
}

static uint64_t met_mem_total_kb(void)
{
    return pmm_usable_memory / 1024ULL;
}

static uint64_t met_heap_mapped(void)
{
    return kheap_mapped_end - (uint64_t)KHEAP_START;
}

static uint64_t met_stack_net_used(void)
{
    return net_stack_used();
}

static uint64_t met_wd_timeout(void)
{
    return watchdog_timeout_ticks();
}

static uint64_t met_cli_sess_active(void)
{
    return (uint64_t)net_tcp_cli_active();
}

static uint64_t met_tls_sess_active(void)
{
    return (uint64_t)net_tcp_tls_active();
}

static const metric_t g_metrics[] = {
    M64("uptime_ticks", timer_ticks),
    MFN("mem_free_kb", met_mem_free_kb),
    MFN("heap_used", met_heap_used),
    MFN("tasks", met_tasks),
    M64("log_total", g_log_total),
    M64("rx_frames", g_net_rx_frames),
    M64("rx_err", g_net_rx_errors),
    M64("rx_irq", g_e1000_irq_count),
    MFN("rx_missed", met_rx_missed),
    M64("rx_nobuf", g_e1000_rnbc),
    MFN("rx_overrun_irq", met_rx_overrun_irq),
    M64("rx_arp", g_net_rx_arp),
    M64("rx_ipv4", g_net_rx_ipv4),
    M64("rx_other", g_net_rx_other),
    M64("tx_ok", g_net_tx_ok),
    M64("tx_fail", g_net_tx_fail),
    M32("arp_reply", g_net_arp_replies_sent),
    M32("icmp_reply", g_net_icmp_replies_sent),
    M32("udp_echo", g_net_udp_echo_count),
    M64("udp_dropped", g_net_udp_dropped),
    M64("udp_src_dropped", g_net_udp_src_dropped),
    M64("log_serial_muted", g_net_log_muted),
    M64("udp_badsum", g_net_udp_badsum),
    M64("tcp_rx", g_tcp_rx),
    M64("tcp_badsum", g_tcp_badsum),
    M64("tcp_rst_sent", g_tcp_rst_sent),
    M64("tcp_conn_open", g_tcp_conn_open),
    M64("tcp_dropped_busy", g_tcp_busy),
    M64("tcp_rx_bytes", g_tcp_rx_bytes),
    M64("tcp_timeout", g_tcp_timeouts),
    M64("tcp_noentropy", g_tcp_noentropy),
    M64("tcp_tx_bytes", g_tcp_tx_bytes),
    M64("tcp_acked_bytes", g_tcp_acked_bytes),
    M64("tcp_retx", g_tcp_retx),
    M64("tcp_retx_giveup", g_tcp_retx_giveup),
    M64("tcp_close_ok", g_tcp_close_ok),
    M64("tcp_rst_state", g_tcp_rst_state),
    M64("tcp_conn_dropped", g_tcp_conn_dropped),
    M64("tcp_dupack_limited", g_tcp_dupack_limited),
    MFN("tcp_state", met_tcp_state),
    M64("tcp_src_full", g_tcp_src_full),
    M64("tcp_synrcvd_evicted", g_tcp_synrcvd_evicted),
    MFN("tcp_conn_active", met_tcp_conn_active),
    M64("cli_login_ok", g_cli_login_ok),
    M64("cli_login_fail", g_cli_login_fail),
    M64("cli_login_timeout", g_cli_login_timeout),
    M64("cli_line_long", g_cli_line_long),
    M64("cli_cmd_ok", g_cli_cmd_ok),
    M64("cli_cmd_fail", g_cli_cmd_fail),
    M64("cli_login_ro", g_cli_login_ro),
    M64("cli_sess_full", g_cli_sess_full),
    M64("cli_idle_timeout", g_cli_idle_timeout),
    M64("cli_role_denied", g_cli_role_denied),
    MFN("entropy_ready", met_entropy_ready),
    M64("entropy_ready_tick", g_entropy_ready_tick),
    M64("entropy_events", g_entropy_events),
    M64("entropy_hw_bits", g_entropy_hw_bits),
    M64("entropy_jitter_bits", g_entropy_jitter_bits),
    M64("entropy_denied", g_entropy_denied),
    M64("drbg_reseeds", g_drbg_reseeds),
    M64("ktimer_fired", g_ktimer_fired),
    M64("ktimer_cancelled", g_ktimer_cancelled),
    M64("ktimer_late_max", g_ktimer_late_max),
    M64("auth_ok", g_auth_ok),
    M64("auth_nonaktif", g_auth_denied[1]),
    M64("auth_format", g_auth_denied[2]),
    M64("auth_hmac", g_auth_denied[3]),
    M64("auth_replay", g_auth_denied[4]),
    M64("auth_counter_off", g_auth_ctr_off),
    M64("priv_chal", g_chal_issued),
    M64("chal_noentropy", g_chal_noentropy),
    M64("chal_ip_recycled", g_chal_ip_recycled),
    M64("priv_ok", g_priv_ok),
    M64("priv_nonaktif", g_priv_denied[1]),
    M64("priv_format", g_priv_denied[2]),
    M64("priv_nonce", g_priv_denied[3]),
    M64("priv_kedaluwarsa", g_priv_denied[4]),
    M64("priv_hmac", g_priv_denied[5]),
    // R3-2: kunci baru (selalu di akhir).
    MFN("uptime_s", met_uptime_s),
    M64("cpu_idle_ticks", g_cpu_idle_ticks),
    M32("cpu_busy_pct", g_cpu_busy_pct),
    MFN("mem_total_kb", met_mem_total_kb),
    MFN("heap_mapped", met_heap_mapped),
    MFN("stack_net_used", met_stack_net_used),
    MFN("cli_sess_active", met_cli_sess_active),
    MFN("tls_sess_active", met_tls_sess_active),
    M64("tls_hs_ok", g_tls_hs_ok),
    M64("tls_fail", g_tls_fail),
    M64("tls_full", g_tls_full),
    M64("tls_noentropy", g_tls_noentropy),
    M64("netcon_sent", g_nc_sent),
    M64("netcon_lost", g_nc_lost),
    M64("netcon_arp", g_nc_arp),
    M64("netcon_tx_fail", g_nc_tx_fail),
    M64("fat_wr_ok", g_fat_wr_ok),
    M64("fat_wr_fail", g_fat_wr_fail),
    M64("audit_seq", g_audit_seq),
    // R4
    M64("logdisk_written", g_ld_written),
    M64("logdisk_lost", g_ld_lost),
    M64("logdisk_wfail", g_ld_wfail),
    M64("logdisk_bad", g_ld_bad),
    // R5
    MFN("wd_timeout_ticks", met_wd_timeout),
    M64("wd_gap_max", g_wd_gap_max),
    M64("wd_pets", g_wd_pets),
    // R6
    M64("sys_calls", g_sys_calls),
    M64("sys_rejected", g_sys_rejected),
    M64("user_faults", g_user_faults),
    M64("pmm_alloc", g_pmm_allocs),
    M64("pmm_free", g_pmm_frees),
    M64("pmm_fail", g_pmm_fail),
    M64("pmm_bad_free", g_pmm_bad_free),
    M64("kmalloc", g_kmalloc_n),
    M64("kfree", g_kfree_n),
    M64("kfree_noop", g_kfree_noop),
    M64("kmalloc_fail", g_kmalloc_fail),
};

#define METRICS_N (sizeof(g_metrics) / sizeof(g_metrics[0]))

static uint64_t met_value(const metric_t *m)
{
    if (m->fn) {
        return m->fn();
    }
    if (m->p32) {
        return *m->p32;
    }
    return *m->p64;
}

static uint32_t met_declen(uint64_t v)
{
    uint32_t n = 1;

    while (v >= 10) {
        v /= 10;
        n++;
    }
    return n;
}

static void met_putdec(uint64_t v)
{
    char tmp[21];
    int n = 0;

    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v > 0);

    while (n > 0) {
        cmd_putc(tmp[--n]);
    }
}

static uint32_t met_strlen(const char *s)
{
    uint32_t n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

// Baris penutup "metrics_lanjut=<indeks>\n" (indeks < 100000) selalu muat.
#define METRICS_NEXT_KEY     "metrics_lanjut="
#define METRICS_NEXT_RESERVE (sizeof(METRICS_NEXT_KEY) - 1 + 5 + 1)

// Argumen setelah "metrics": kosong, atau " <awalan>", " <mulai>",
// " <awalan> <mulai>" (tepat satu spasi pemisah). awalan [a-z0-9_] 1..32
// byte, tidak diawali digit; mulai desimal 0..METRICS_N-1 (indeks tabel).
// Salah -> ERR; tidak ada kunci yang cocok -> ERR.
void metrics_execute(const volatile uint8_t *a, uint32_t len)
{
    char pfx[METRICS_PFX_MAX];
    uint32_t pl = 0, start = 0, have_start = 0, shown = 0, i = 0;

    while (i < len) {
        uint32_t s;

        if (a[i] != ' ') {
            goto bad;
        }
        s = ++i;
        while (i < len && a[i] != ' ') {
            i++;
        }
        if (i == s || have_start) {
            goto bad;
        }
        if (a[s] >= '0' && a[s] <= '9') {
            if (i - s > 5) {
                goto bad;
            }
            for (uint32_t k = s; k < i; k++) {
                if (a[k] < '0' || a[k] > '9') {
                    goto bad;
                }
                start = start * 10 + (uint32_t)(a[k] - '0');
            }
            have_start = 1;
        } else {
            if (pl || i - s > METRICS_PFX_MAX) {
                goto bad;
            }
            for (uint32_t k = s; k < i; k++) {
                uint8_t c = a[k];
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
                    goto bad;
                }
                pfx[pl++] = (char)c;
            }
        }
    }
    if (start >= METRICS_N) {
        goto bad;
    }

    for (uint32_t k = start; k < METRICS_N; k++) {
        const char *name = g_metrics[k].name;
        uint32_t j = 0;
        uint64_t v;

        while (j < pl && name[j] == pfx[j]) {
            j++;
        }
        if (j < pl) {
            continue;
        }
        v = met_value(&g_metrics[k]);
        if (g_cmd_len + met_strlen(name) + 1 + met_declen(v) + 1 +
            METRICS_NEXT_RESERVE > CMD_OUT_MAX) {
            cmd_puts(METRICS_NEXT_KEY);
            met_putdec(k);
            cmd_putc('\n');
            return;
        }
        cmd_puts(name);
        cmd_putc('=');
        met_putdec(v);
        cmd_putc('\n');
        shown++;
    }
    if (shown == 0) {
        cmd_puts("ERR: metrics: tidak ada kunci yang cocok\n");
    }
    return;

bad:
    cmd_puts("ERR: metrics [awalan] [mulai]\n");
}

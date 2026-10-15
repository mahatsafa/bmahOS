#include "kernel.h"

// ---- R3: registry metrik ----
// Satu tabel untuk semua kunci perintah `metrics` (format "kunci=nilai" per
// baris, urutan = urutan tabel). Counter tetap didefinisikan di modulnya;
// tabel ini satu-satunya daftar yang diekspor. Nilai dibaca langsung lewat
// pointer (u64/u32) atau getter untuk nilai turunan.

typedef struct {
    const char *name;
    const volatile uint64_t *p64;
    const volatile uint32_t *p32;
    uint64_t (*fn)(void);
} metric_t;

#define M64(n, v) { n, &(v), 0, 0 }
#define M32(n, v) { n, 0, &(v), 0 }
#define MFN(n, f) { n, 0, 0, f }

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

// Tulis semua kunci ke g_cmd_out (pemanggil sudah mengosongkan g_cmd_len).
void metrics_dump(void)
{
    for (uint32_t i = 0; i < METRICS_N; i++) {
        cmd_puts(g_metrics[i].name);
        cmd_putc('=');
        met_putdec(met_value(&g_metrics[i]));
        cmd_putc('\n');
    }
}

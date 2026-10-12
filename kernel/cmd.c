#include "kernel.h"

// ---- Net-9: remote command lewat UDP (port 7778), HANYA perintah baca ----

static char g_cmd_out[1400];
uint32_t g_cmd_len = 0;

void cmd_putc(char c)
{
    if (g_cmd_len < sizeof(g_cmd_out)) {
        g_cmd_out[g_cmd_len++] = c;
    }
}

void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
}

static void cmd_putdec(uint64_t v)
{
    char tmp[21];
    int n = 0;

    if (v == 0) {
        tmp[n++] = '0';
    }

    while (v > 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }

    while (n > 0) {
        cmd_putc(tmp[--n]);
    }
}

static void cmd_puthex8(uint8_t b)
{
    static const char h[] = "0123456789ABCDEF";
    cmd_putc(h[b >> 4]);
    cmd_putc(h[b & 0xF]);
}

int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name)
{
    uint32_t i = 0;

    while (name[i]) {
        if (i >= len || cmd[i] != (uint8_t)name[i]) {
            return 0;
        }
        i++;
    }

    return i == len;
}

// Net-19: satu baris "kunci=nilai" untuk perintah metrics
static void cmd_kv(const char *k, uint64_t v)
{
    cmd_puts(k);
    cmd_putc('=');
    cmd_putdec(v);
    cmd_putc('\n');
}

static const char *cmd_status_name(task_status_t s)
{
    switch (s) {
    case TASK_READY:    return "READY";
    case TASK_DEAD:     return "DEAD";
    case TASK_SLEEPING: return "SLEEPING";
    case TASK_BLOCKED:  return "BLOCKED";
    default:            return "?";
    }
}

void net_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;

    if (len == 0) {
        cmd_puts("ERR: perintah kosong (ketik help)\n");
    } else if (net_cmd_is(cmd, len, "help")) {
        cmd_puts("perintah: help ping uptime mem log irq stats metrics mac ip tasks\n");
        cmd_puts("berprivilege: pping reboot\n");
        cmd_puts("kirim CHAL, lalu <nonce> <perintah> <hmac>\n");
#ifdef BMAHOS_LEGACYCTR
        cmd_puts("jalur counter (LEGACYCTR): <counter> <perintah> <hmac>, tanpa pping/reboot\n");
#endif
    } else if (net_cmd_is(cmd, len, "ping")) {
        cmd_puts("pong\n");
    } else if (net_cmd_is(cmd, len, "uptime")) {
        uint64_t t = timer_ticks;
        cmd_puts("uptime: ");
        cmd_putdec(t / 100);
        cmd_puts(" detik (");
        cmd_putdec(t);
        cmd_puts(" tick @100Hz)\n");
    } else if (net_cmd_is(cmd, len, "mac")) {
        cmd_puts("mac: ");
        for (int i = 0; i < 6; i++) {
            cmd_puthex8(g_e1000_mac[i]);
            if (i < 5) {
                cmd_putc(':');
            }
        }
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "ip")) {
        cmd_puts("ip: ");
        for (int i = 0; i < 4; i++) {
            cmd_putdec(g_net_ip[i]);
            if (i < 3) {
                cmd_putc('.');
            }
        }
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "log")) {
        // Salin di bawah irq_save supaya konsisten terhadap penulisan
        // ring dari konteks lain (tanpa I/O di dalam bagian ini).
        uint64_t lf = irq_save();
        uint64_t avail = g_log_total < LOG_RING_SIZE ? g_log_total : LOG_RING_SIZE;
        uint64_t want = avail < 1200 ? avail : 1200;
        uint32_t start = (uint32_t)((g_log_head + LOG_RING_SIZE - want) &
                                    (LOG_RING_SIZE - 1));
        uint64_t i = 0;

        if (want < avail) {
            // Potongan mulai di tengah baris: lewati sampai newline pertama.
            while (i < want && g_log_ring[(start + i) & (LOG_RING_SIZE - 1)] != '\n') {
                i++;
            }
            if (i < want) {
                i++;
            }
        }

        for (; i < want; i++) {
            char ch = g_log_ring[(start + i) & (LOG_RING_SIZE - 1)];
            cmd_putc((ch == '\n' || (ch >= 32 && ch < 127)) ? ch : '?');
        }

        irq_restore(lf);

        if (g_cmd_len == 0) {
            cmd_puts("(log kosong)\n");
        }
    } else if (net_cmd_is(cmd, len, "irq")) {
        cmd_puts("e1000 irq: count=");
        cmd_putdec(g_e1000_irq_count);
        cmd_puts(" spurious=");
        cmd_putdec(g_e1000_irq_spurious);
        cmd_puts(" last_icr=0x");
        cmd_puthex8((uint8_t)(g_e1000_irq_last_icr >> 8));
        cmd_puthex8((uint8_t)g_e1000_irq_last_icr);
        cmd_puts(" icr_or=0x");
        cmd_puthex8((uint8_t)(g_e1000_irq_icr_or >> 8));
        cmd_puthex8((uint8_t)g_e1000_irq_icr_or);
        cmd_puts(" gsi_terkunci=");
        cmd_putdec(g_e1000_irq_gsi);
        cmd_puts(" net_loop=");
        cmd_putdec(g_net_loops);
        cmd_puts("\ngsi_aktif:");

        for (uint32_t i = 0; i < 8; i++) {
            if (g_e1000_irq_rirr_or & (1u << i)) {
                cmd_putc(' ');
                cmd_putdec(16 + i);
            }
        }

        cmd_puts("\ngsi_dimask:");

        for (uint32_t i = 0; i < 8; i++) {
            if (g_e1000_irq_masked & (1u << i)) {
                cmd_putc(' ');
                cmd_putdec(16 + i);
            }
        }

        cmd_puts("\nrentang: 16..");
        cmd_putdec(g_e1000_irq_last_gsi);
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "stats")) {
        cmd_puts("udp: echo=");
        cmd_putdec(g_net_udp_echo_count);
        cmd_puts(" dibuang_batas=");
        cmd_putdec(g_net_udp_dropped);
        cmd_puts(" batas/detik=");
        cmd_putdec(NET_UDP_BUDGET_PER_SEC);
        cmd_puts(" dibuang_sumber=");
        cmd_putdec(g_net_udp_src_dropped);
        cmd_puts(" batas_sumber/detik=");
        cmd_putdec(NET_UDP_SRC_PER_SEC);
        cmd_puts("\nauth: ok=");
        cmd_putdec(g_auth_ok);
        cmd_puts(" nonaktif=");
        cmd_putdec(g_auth_denied[1]);
        cmd_puts(" format=");
        cmd_putdec(g_auth_denied[2]);
        cmd_puts(" hmac=");
        cmd_putdec(g_auth_denied[3]);
        cmd_puts(" replay=");
        cmd_putdec(g_auth_denied[4]);
        cmd_puts(" jalur_mati=");
        cmd_putdec(g_auth_ctr_off);
        cmd_puts("\npriv: chal=");
        cmd_putdec(g_chal_issued);
        cmd_puts(" ok=");
        cmd_putdec(g_priv_ok);
        cmd_puts(" nonaktif=");
        cmd_putdec(g_priv_denied[1]);
        cmd_puts(" format=");
        cmd_putdec(g_priv_denied[2]);
        cmd_puts(" nonce=");
        cmd_putdec(g_priv_denied[3]);
        cmd_puts(" kedaluwarsa=");
        cmd_putdec(g_priv_denied[4]);
        cmd_puts(" hmac=");
        cmd_putdec(g_priv_denied[5]);
        cmd_puts("\nrx_irq=");
        cmd_putdec(g_e1000_irq_count);
        cmd_puts(" rx_frames=");
        cmd_putdec(g_net_rx_frames);
        cmd_puts(" rx_err=");
        cmd_putdec(g_net_rx_errors);
        cmd_puts(" ring=");
        cmd_putdec(E1000_RX_RING_SIZE);
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "metrics")) {
        // Format stabil untuk skrip: satu kunci=nilai per baris.
        uint64_t free_frames = 0;

        for (uint64_t f = 0; f < PMM_MAX_FRAMES; f++) {
            if (!pmm_bitmap_test(f)) {
                free_frames++;
            }
        }

        cmd_kv("uptime_ticks", timer_ticks);
        cmd_kv("mem_free_kb", free_frames * PMM_PAGE_SIZE / 1024ULL);
        cmd_kv("heap_used", (uint64_t)kheap_current - (uint64_t)KHEAP_START);
        cmd_kv("tasks", task_count);
        cmd_kv("log_total", g_log_total);
        cmd_kv("rx_frames", g_net_rx_frames);
        cmd_kv("rx_err", g_net_rx_errors);
        cmd_kv("rx_irq", g_e1000_irq_count);
        e1000_stats_poll();
        cmd_kv("rx_missed", g_e1000_mpc);
        cmd_kv("rx_nobuf", g_e1000_rnbc);
        cmd_kv("rx_overrun_irq", (g_e1000_irq_icr_or >> 6) & 1u);
        cmd_kv("rx_arp", g_net_rx_arp);
        cmd_kv("rx_ipv4", g_net_rx_ipv4);
        cmd_kv("rx_other", g_net_rx_other);
        cmd_kv("tx_ok", g_net_tx_ok);
        cmd_kv("tx_fail", g_net_tx_fail);
        cmd_kv("arp_reply", g_net_arp_replies_sent);
        cmd_kv("icmp_reply", g_net_icmp_replies_sent);
        cmd_kv("udp_echo", g_net_udp_echo_count);
        cmd_kv("udp_dropped", g_net_udp_dropped);
        cmd_kv("udp_src_dropped", g_net_udp_src_dropped);
        cmd_kv("log_serial_muted", g_net_log_muted);
        cmd_kv("udp_badsum", g_net_udp_badsum);
        cmd_kv("tcp_rx", g_tcp_rx);
        cmd_kv("tcp_badsum", g_tcp_badsum);
        cmd_kv("tcp_rst_sent", g_tcp_rst_sent);
        cmd_kv("tcp_conn_open", g_tcp_conn_open);
        cmd_kv("tcp_dropped_busy", g_tcp_busy);
        cmd_kv("tcp_rx_bytes", g_tcp_rx_bytes);
        cmd_kv("tcp_timeout", g_tcp_timeouts);
        cmd_kv("tcp_noentropy", g_tcp_noentropy);
        cmd_kv("tcp_tx_bytes", g_tcp_tx_bytes);
        cmd_kv("tcp_acked_bytes", g_tcp_acked_bytes);
        cmd_kv("entropy_ready", (uint64_t)g_entropy_ready);
        cmd_kv("entropy_ready_tick", g_entropy_ready_tick);
        cmd_kv("entropy_events", g_entropy_events);
        cmd_kv("entropy_hw_bits", g_entropy_hw_bits);
        cmd_kv("entropy_jitter_bits", g_entropy_jitter_bits);
        cmd_kv("entropy_denied", g_entropy_denied);
        cmd_kv("drbg_reseeds", g_drbg_reseeds);
        cmd_kv("ktimer_fired", g_ktimer_fired);
        cmd_kv("ktimer_cancelled", g_ktimer_cancelled);
        cmd_kv("ktimer_late_max", g_ktimer_late_max);
        cmd_kv("auth_ok", g_auth_ok);
        cmd_kv("auth_nonaktif", g_auth_denied[1]);
        cmd_kv("auth_format", g_auth_denied[2]);
        cmd_kv("auth_hmac", g_auth_denied[3]);
        cmd_kv("auth_replay", g_auth_denied[4]);
        cmd_kv("auth_counter_off", g_auth_ctr_off);
        cmd_kv("priv_chal", g_chal_issued);
        cmd_kv("chal_noentropy", g_chal_noentropy);
        cmd_kv("chal_ip_recycled", g_chal_ip_recycled);
        cmd_kv("priv_ok", g_priv_ok);
        cmd_kv("priv_nonaktif", g_priv_denied[1]);
        cmd_kv("priv_format", g_priv_denied[2]);
        cmd_kv("priv_nonce", g_priv_denied[3]);
        cmd_kv("priv_kedaluwarsa", g_priv_denied[4]);
        cmd_kv("priv_hmac", g_priv_denied[5]);
    } else if (net_cmd_is(cmd, len, "mem")) {
        // Hitung frame bebas dengan scan bitmap. Tidak dikunci terhadap
        // pmm_alloc() task lain, jadi angkanya perkiraan sesaat.
        uint64_t free_frames = 0;

        for (uint64_t f = 0; f < PMM_MAX_FRAMES; f++) {
            if (!pmm_bitmap_test(f)) {
                free_frames++;
            }
        }

        cmd_puts("pmm bebas: ");
        cmd_putdec(free_frames);
        cmd_puts(" frame (");
        cmd_putdec(free_frames * PMM_PAGE_SIZE / 1048576ULL);
        cmd_puts(" MB)\n");
        cmd_puts("kheap terpakai: ");
        cmd_putdec((uint64_t)kheap_current - (uint64_t)KHEAP_START);
        cmd_puts(" byte, termap: ");
        cmd_putdec(kheap_mapped_end - (uint64_t)KHEAP_START);
        cmd_puts(" byte\n");
    } else if (net_cmd_is(cmd, len, "tasks")) {
        for (size_t i = 0; i < task_count; i++) {
            cmd_puts("slot ");
            cmd_putdec(i);
            cmd_puts(": ");
            cmd_puts(cmd_status_name(tasks[i].status));
            if (tasks[i].is_user_task) {
                cmd_puts(" user");
            }
            if (i == g_idle_index) {
                cmd_puts(" idle");
            }
            if (i == current_index) {
                cmd_puts(" (menjalankan perintah ini)");
            }
            cmd_putc('\n');
        }
    } else {
        cmd_puts("ERR: perintah tidak dikenal (ketik help)\n");
    }
}

// Kirim g_cmd_out sebagai datagram UDP balasan ke pengirim req.
void net_udp_send_cmd_reply(volatile uint8_t *req, uint32_t ihl)
{
    uint32_t plen = g_cmd_len;
    uint32_t udp_len = 8 + plen;

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-9: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t r = 14 + ihl;

    uint32_t frame_len = 14 + 20 + udp_len;
    uint32_t send_len = frame_len < 60 ? 60 : frame_len;

    for (uint32_t i = 0; i < send_len; i++) {
        p[i] = 0;
    }

    for (int i = 0; i < 6; i++) {
        p[i] = req[6 + i];
        p[6 + i] = g_e1000_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;

    p[14] = 0x45;
    p[15] = 0x00;
    p[16] = (uint8_t)((20 + udp_len) >> 8);
    p[17] = (uint8_t)((20 + udp_len) & 0xFF);
    p[18] = (uint8_t)(g_net_ip_id >> 8);
    p[19] = (uint8_t)(g_net_ip_id & 0xFF);
    g_net_ip_id++;
    p[20] = 0x40;
    p[21] = 0x00;
    p[22] = 64;
    p[23] = 17;

    for (int i = 0; i < 4; i++) {
        p[26 + i] = g_net_ip[i];
        p[30 + i] = req[26 + i];
    }

    uint16_t ipc = net_checksum16(p + 14, 20);
    p[24] = (uint8_t)(ipc >> 8);
    p[25] = (uint8_t)(ipc & 0xFF);

    p[34] = req[r + 2];
    p[35] = req[r + 3];
    p[36] = req[r + 0];
    p[37] = req[r + 1];
    p[38] = (uint8_t)(udp_len >> 8);
    p[39] = (uint8_t)(udp_len & 0xFF);

    for (uint32_t i = 0; i < plen; i++) {
        p[42 + i] = (uint8_t)g_cmd_out[i];
    }

    uint16_t uc = net_udp_checksum(p + 26, p + 30, p + 34, udp_len);
    if (uc == 0) {
        uc = 0xFFFF;
    }
    p[40] = (uint8_t)(uc >> 8);
    p[41] = (uint8_t)(uc & 0xFF);

    int ok = e1000_tx_send(g_net_tx_buf_phys, send_len);

    uint64_t lf = irq_save();
    serial_write("Net-9: balasan perintah (");
    serial_write_hex((uint64_t)plen);
    serial_write(" byte) -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

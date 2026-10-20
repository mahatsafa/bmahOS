#include "kernel.h"

// ---- Net-9: remote command lewat UDP (port 7778), HANYA perintah baca ----

static char g_cmd_out[CMD_OUT_MAX];
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

// D2: isi balasan (g_cmd_len byte) untuk disalin ke sesi TCP.
const char *cmd_out(void)
{
    return g_cmd_out;
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
        cmd_puts("perintah: help ping uptime mem log irq stats metrics mac ip tasks config tls "
                 "netcon logdisk wd\n");
        cmd_puts("admin: pping reboot audit ls baca tulis tambah hapus ganti set\n");
        cmd_puts("berprivilege: pping reboot audit (audit gagal)\n");
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
        cmd_putdec(g_net_src_rate);
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
    } else if (net_cmd_is(cmd, len, "metrics") ||
               (len > 8 && net_cmd_is(cmd, 8, "metrics "))) {
        metrics_execute(cmd + 7, len - 7);   // R3: registry + halaman di metrics.c
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
    } else if (net_cmd_is(cmd, len, "tls")) {
        // D9: status TLS 7780, pin sertifikat, counter sesi.
        tls_status();
        cmd_puts("stack_net: terpakai_maks=");
        cmd_putdec(net_stack_used());
        cmd_puts(" dari ");
        cmd_putdec(net_stack_size());
        cmd_putc('\n');
    } else if (net_cmd_is(cmd, len, "netcon")) {
        netcon_status();   // R2
    } else if (net_cmd_is(cmd, len, "wd")) {
        watchdog_status();   // R5
    } else if (net_cmd_is(cmd, len, "logdisk") ||
               (len > 8 && net_cmd_is(cmd, 8, "logdisk "))) {
        logdisk_execute(cmd + 7, len - 7);   // R4
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

    if (g_net_tx_buf_phys == 0) {
        g_net_tx_buf_phys = pmm_alloc();

        if (g_net_tx_buf_phys == 0) {
            serial_write("Net-9: FATAL - pmm_alloc gagal untuk TX buffer\r\n");
            return;
        }
    }

    uint8_t *p = (uint8_t *)(g_net_tx_buf_phys + hhdm_offset);
    uint32_t r = 14 + ihl;

    for (uint32_t i = 0; i < plen; i++) {
        p[42 + i] = (uint8_t)g_cmd_out[i];
    }

    uint16_t sport = (uint16_t)(((uint32_t)req[r + 2] << 8) | req[r + 3]);
    uint16_t dport = (uint16_t)(((uint32_t)req[r + 0] << 8) | req[r + 1]);
    uint32_t send_len = net_udp_build(p, req + 6, req + 26, sport, dport, plen);

    int ok = e1000_tx_send(g_net_tx_buf_phys, send_len);

    uint64_t lf = irq_save();
    serial_write("Net-9: balasan perintah (");
    serial_write_hex((uint64_t)plen);
    serial_write(" byte) -> ");
    serial_write(ok ? "terkirim (DD set)" : "GAGAL");
    serial_write("\r\n");
    irq_restore(lf);
}

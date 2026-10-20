#include "kernel.h"

// R5: watchdog perangkat lunak. Net task menepuk (watchdog_pet) di setiap
// putaran loop utamanya; handler IRQ timer hanya MEMERIKSA (watchdog_check),
// tidak pernah menepuk. Tanpa tepukan lebih dari WD_TIMEOUT_TICKS -> dump lewat
// jalur panic R1 (serial, netconsole R2, LOG.BIN R4) lalu reboot otomatis.
// - Aktif sejak tepukan pertama (setelah self-test timer dan init netcon/
//   logdisk), jadi waktu boot tidak dihitung. Tanpa NIC net task berhenti
//   sebelum loop: watchdog tidak pernah aktif.
// - Trace: net task sedang berjalan -> RIP/RBP frame interrupt; tidak ->
//   konteks yang disimpan context_switch (task.S) di stack task itu.
// - Batasan: macet dengan interrupt mati (cli) menghentikan tick, jadi tidak
//   terdeteksi di sini (butuh watchdog perangkat keras, ROADMAP H6).
// - Hanya net task yang ditepuk: task idle dijalankan scheduler hanya saat
//   tidak ada task READY lain, jadi saat banjir paket ia bisa lama tidak jalan.

volatile uint64_t g_wd_last;    // tick tepukan terakhir
volatile int g_wd_armed;
size_t g_wd_task;               // slot net task (diisi saat tepukan pertama)
uint64_t g_wd_pets;
uint64_t g_wd_gap_max;          // jeda terpanjang antar tepukan (tick)

// Jeda yang melewati batas (> WD_TIMEOUT_TICKS), atau 0 bila masih sehat.
uint64_t wd_overdue(uint64_t now, uint64_t last)
{
    uint64_t gap = now - last;

    return gap > WD_TIMEOUT_TICKS ? gap : 0;
}

// Frame context_switch (task.S): 15 register (r15 di rsp[0], rbp di rsp[8])
// lalu alamat kembali ke pemanggil context_switch di rsp[15].
void wd_saved_frame(uint64_t rsp, uint64_t *rip, uint64_t *rbp)
{
    const uint64_t *s = (const uint64_t *)(uintptr_t)rsp;

    *rbp = s[8];
    *rip = s[15];
}

void watchdog_pet(void)
{
    uint64_t now = timer_ticks;

    if (!g_wd_armed) {
        g_wd_task = current_index;
        g_wd_last = now;
        __asm__ volatile("" : : : "memory");
        g_wd_armed = 1;
        kprintf("R5: watchdog aktif batas=%d tick (net task slot %lu)\r\n",
                WD_TIMEOUT_TICKS, (uint64_t)g_wd_task);
    }

    uint64_t gap = now - g_wd_last;
    if (gap > g_wd_gap_max) {
        g_wd_gap_max = gap;
    }
    g_wd_last = now;
    g_wd_pets++;
}

static const char *wd_status_name(task_status_t s)
{
    switch (s) {
    case TASK_READY:    return "READY";
    case TASK_DEAD:     return "DEAD";
    case TASK_SLEEPING: return "SLEEPING";
    case TASK_BLOCKED:  return "BLOCKED";
    default:            return "?";
    }
}

// Dari irq_handler (vektor timer), setelah timer_ticks++.
void watchdog_check(struct exception_context *c)
{
    if (!g_wd_armed) {
        return;
    }
    uint64_t gap = wd_overdue(timer_ticks, g_wd_last);
    if (gap == 0) {
        return;
    }

    const task_t *t = &tasks[g_wd_task];
    int running = current_index == g_wd_task;
    uint64_t rip, rbp;

    if (running) {
        rip = c->rip;
        rbp = c->rbp;
    } else {
        wd_saved_frame(t->rsp, &rip, &rbp);
    }

    panic_begin();
    kprintf("\r\nPANIC: watchdog: net task tanpa tepukan %lu tick (batas %d) status=%s "
            "berjalan=%s\r\n", gap, WD_TIMEOUT_TICKS, wd_status_name(t->status),
            running ? "ya" : "tidak");
    kprintf("PANIC: tepukan terakhir tick=%lu tepukan=%lu jeda_maks=%lu\r\n",
            (uint64_t)g_wd_last, g_wd_pets, g_wd_gap_max);
    panic_finish(rip, rbp);
}

// Perintah `wd` (read-only boleh).
void watchdog_status(void)
{
    char t[160];

    ksnprintf(t, sizeof(t), "watchdog: %s batas=%d tick jeda_sekarang=%lu jeda_maks=%lu "
              "tepukan=%lu slot=%lu\n", g_wd_armed ? "aktif" : "belum aktif",
              WD_TIMEOUT_TICKS, g_wd_armed ? (uint64_t)(timer_ticks - g_wd_last) : 0,
              g_wd_gap_max, g_wd_pets, (uint64_t)g_wd_task);
    cmd_puts(t);
}

uint64_t watchdog_timeout_ticks(void)
{
    return WD_TIMEOUT_TICKS;
}

#ifndef BMAHOS_PROD
// R5: pemicu uji (build dev saja, perintah admin "wdtest loop|blok"). Dijalankan
// 1 detik kemudian dari ktimer (loop net task) supaya balasan sempat terkirim.
// loop: berputar dengan interrupt hidup (tetap di-preempt, tidak menepuk).
// blok: menunggu semaphore yang tidak pernah di-post.
static ktimer_t g_wd_test_timer;
static int g_wd_test_kind = -1;
static semaphore_t g_wd_test_sem;   // count 0, tidak pernah di-post

static void wd_test_spin(void)
{
    for (;;) {
        __asm__ volatile("pause");
    }
}

static void wd_test_block(void)
{
    sem_wait(&g_wd_test_sem);
}

static void wd_test_fire(void *arg)
{
    (void)arg;
    if (g_wd_test_kind == 0) {
        wd_test_spin();
    } else {
        wd_test_block();
    }
    kprintf("WD-UJI: net task kembali (jenis %d)\r\n", g_wd_test_kind);
    g_wd_test_kind = -1;
}

int wd_test_execute(const volatile uint8_t *cmd, uint32_t len)
{
    static const char *const kinds[2] = { "loop", "blok" };
    static const char *const cmds[2] = { "wdtest loop", "wdtest blok" };

    for (int i = 0; i < 2; i++) {
        if (!net_cmd_is(cmd, len, cmds[i])) {
            continue;
        }
        if (g_wd_test_kind >= 0) {
            cmd_puts("ERR: uji watchdog sudah dijadwalkan\n");
            return 1;
        }
        g_wd_test_kind = i;
        ktimer_start(&g_wd_test_timer, 100, wd_test_fire, 0);
        cmd_puts("wdtest: net task macet (");
        cmd_puts(kinds[i]);
        cmd_puts(") dalam 1 detik\n");
        return 1;
    }
    return 0;
}
#endif

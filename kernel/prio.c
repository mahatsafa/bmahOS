#include "kernel.h"

// ---- F7: prioritas task dan batas sumber daya per task user ----
//
// Pemilih (prio_pick): dipanggil schedule() tiap tick dan tiap task tidur/blok/selesai.
//  1. Tingkat: tinggi (net task), normal (task kernel), rendah (task user, termasuk APP.BIN).
//     Dipilih task READY di tingkat tertinggi yang ada; dalam satu tingkat bergilir mulai dari
//     task yang terakhir jalan di tingkat itu (bukan dari task yang baru saja diganti: net task
//     bangun tiap tick dan akan selalu jadi "titik awal" kalau pakai current_index).
//  2. Penuaan (cegah kelaparan): task READY (bukan yang sedang jalan) yang sudah menunggu
//     >= PRIO_AGE_TICKS tick sejak jalan/jadi READY/diganti terakhir dipilih lebih dulu, yang
//     terlama dahulu, satu tick, lalu umurnya diulang dari nol. Batas atas tunggu task READY
//     tanpa batas CPU = PRIO_AGE_TICKS + jumlah task READY tick.
//  3. Idle bukan bagian tingkat: hanya bila tak ada task layak (schedule()).
//
// Batas sumber daya (hanya is_user_task), jendela RES_WIN_TICKS tick yang bergulir malas:
//  - CPU: tiap tick timer dibebankan ke task yang sedang jalan (pencuplikan). Mencapai
//    RES_CPU_MAX di sebuah jendela -> task tidak layak dijadwalkan sampai jendela baru.
//  - syscall > RES_SYS_MAX per jendela, byte SYS_WRITE > RES_WRITE_MAX per jendela:
//    syscall itu ditolak dengan SOCK_EDQUOT (fail-closed, tanpa efek).
//  - soket: RES_FD_MAX per task (diperiksa sock.c, dicatat res_fd_denied).
//  Jendela yang melanggar (CPU habis / syscall / tulis) menambah satu "strike" saat jendela
//  ditutup; jendela bersih atau jendela yang terlewat tanpa kegiatan mereset. RES_STRIKES_MAX
//  strike beruntun -> task dihentikan (res_tick / res_syscall mengembalikan RES_KILL; pemanggil
//  memanggil task_exit). Satu baris log per jenis per task, dan satu baris saat dihentikan.

uint64_t g_res_fd_deny;     // metrics res_fd_deny: socket/accept ditolak (jatah soket)
uint64_t g_res_sys_deny;    // res_sys_deny: syscall ditolak (jatah syscall per jendela)
uint64_t g_res_wr_deny;     // res_wr_deny: SYS_WRITE ditolak (jatah byte)
uint64_t g_res_cpu_win;     // res_cpu_win: jendela yang jatah CPU-nya habis
uint64_t g_res_killed;      // res_killed: task user dihentikan karena batas
uint64_t g_sched_aged;      // sched_aged: pemilihan karena penuaan (bukan karena tingkat)

static size_t g_last[PRIO_LEVELS];   // indeks task yang terakhir dipilih per tingkat

void prio_reset(void)
{
    for (int i = 0; i < PRIO_LEVELS; i++) {
        g_last[i] = 0;
    }
}

const char *prio_name(uint8_t prio)
{
    switch (prio) {
    case PRIO_HIGH:
        return "tinggi";
    case PRIO_NORMAL:
        return "normal";
    case PRIO_LOW:
        return "rendah";
    case PRIO_IDLE:
        return "idle";
    default:
        return "?";
    }
}

void prio_init_task(task_t *t, uint8_t prio, uint64_t now)
{
    t->prio = prio;
    t->ready_at = now;
    t->res_win = now;
    t->res_cpu = 0;
    t->res_sys = 0;
    t->res_wr = 0;
    t->res_strikes = 0;
    t->res_flags = 0;
    t->fd_max = RES_FD_MAX;
    t->cpu_total = 0;
    t->sys_total = 0;
    t->deny_total = 0;
}

// Tutup jendela yang sudah lewat. Jendela yang melanggar dan langsung disusul jendela
// berikutnya = strike; jendela yang terlewat lebih dari satu (task tidur lama) = bersih.
static void res_roll(task_t *t, uint64_t now)
{
    uint64_t el = now - t->res_win;

    if (now < t->res_win || el < RES_WIN_TICKS) {
        return;
    }
    if ((t->res_flags & RESF_BAD) && el < 2 * RES_WIN_TICKS) {
        t->res_strikes++;
    } else {
        t->res_strikes = 0;
    }
    t->res_win = now;
    t->res_cpu = 0;
    t->res_sys = 0;
    t->res_wr = 0;
    t->res_flags &= ~(RESF_BAD | RESF_CPUW);
}

static int prio_eligible(task_t *t, size_t i, size_t idle, uint64_t now)
{
    if (i == idle || t->status != TASK_READY) {
        return 0;
    }
    if (t->is_user_task) {
        res_roll(t, now);
        if (t->res_cpu >= RES_CPU_MAX) {
            return 0;   // jatah CPU jendela ini habis
        }
    }
    return 1;
}

// Indeks task berikutnya, atau (size_t)-1 bila tak ada yang layak (pemanggil memilih idle).
// cur = task yang sedang jalan (umurnya dianggap 0 oleh pemanggil, lihat schedule()).
size_t prio_pick(task_t *t, size_t n, size_t cur, size_t idle, uint64_t now)
{
    size_t best = (size_t)-1;
    size_t aged = (size_t)-1;
    uint64_t aged_wait = 0;

    if (n == 0) {
        return (size_t)-1;
    }
    for (size_t i = 0; i < n; i++) {
        if (!prio_eligible(&t[i], i, idle, now)) {
            continue;
        }
        uint64_t w = (i == cur || now < t[i].ready_at) ? 0 : now - t[i].ready_at;

        if (w >= PRIO_AGE_TICKS && w > aged_wait) {
            aged_wait = w;
            aged = i;
        }
    }
    for (int lvl = 0; lvl < PRIO_LEVELS && best == (size_t)-1; lvl++) {
        for (size_t k = 1; k <= n; k++) {
            size_t i = (g_last[lvl] + k) % n;

            if (t[i].prio == lvl && prio_eligible(&t[i], i, idle, now)) {
                best = i;
                break;
            }
        }
    }

    size_t pick = best;

    if (aged != (size_t)-1 && aged != best) {
        pick = aged;
        g_sched_aged++;
    }
    if (pick != (size_t)-1 && t[pick].prio < PRIO_LEVELS) {
        g_last[t[pick].prio] = pick;
    }
    return pick;
}

static void res_log(task_t *t, size_t slot, uint32_t bit, const char *jenis, uint64_t nilai,
                    uint64_t batas)
{
    if (t->res_flags & bit) {
        return;
    }
    t->res_flags |= bit;
    kprintf("RES: task user slot %lu melanggar batas %s (%lu dari %lu per %u tick)\r\n",
            (uint64_t)slot, jenis, nilai, batas, (uint32_t)RES_WIN_TICKS);
}

static int res_kill_due(task_t *t, size_t slot)
{
    if (t->res_strikes < RES_STRIKES_MAX) {
        return 0;
    }
    g_res_killed++;
    kprintf("RES: task user slot %lu dihentikan (batas dilanggar %u jendela beruntun)\r\n",
            (uint64_t)slot, t->res_strikes);
    return 1;
}

// Tiap tick timer (irq_handler): bebankan satu tick ke task yang sedang jalan. in_user = tick
// jatuh saat ring 3 (task dihentikan hanya di sini, bukan di tengah syscall). RES_KILL/0.
int res_tick(task_t *t, size_t slot, uint64_t now, int in_user)
{
    t->cpu_total++;
    if (!t->is_user_task) {
        return 0;
    }
    res_roll(t, now);
    t->res_cpu++;
    if (t->res_cpu >= RES_CPU_MAX && !(t->res_flags & RESF_CPUW)) {
        t->res_flags |= RESF_CPUW | RESF_BAD;
        g_res_cpu_win++;
        res_log(t, slot, RESF_LOG_CPU, "cpu", t->res_cpu, RES_CPU_MAX);
    }
    if (in_user && res_kill_due(t, slot)) {
        return RES_KILL;
    }
    return RES_ALLOW;
}

// Di awal tiap syscall task user (syscall_handler). kind: RES_SC_*; len = byte SYS_WRITE.
// RES_ALLOW / RES_DENY (tolak dengan SOCK_EDQUOT) / RES_KILL (pemanggil memanggil task_exit).
// SYS_EXIT tidak pernah ditolak dan tidak dihitung.
int res_syscall(task_t *t, size_t slot, uint64_t now, int kind, uint64_t len)
{
    if (!t->is_user_task || kind == RES_SC_EXIT) {
        return RES_ALLOW;
    }
    res_roll(t, now);
    if (res_kill_due(t, slot)) {
        return RES_KILL;
    }
    t->sys_total++;
    t->res_sys++;
    if (t->res_sys > RES_SYS_MAX) {
        g_res_sys_deny++;
        t->deny_total++;
        t->res_flags |= RESF_BAD;
        res_log(t, slot, RESF_LOG_SYS, "syscall", t->res_sys, RES_SYS_MAX);
        return RES_DENY;
    }
    if (kind == RES_SC_WRITE) {
        if (len > RES_WRITE_MAX - t->res_wr) {
            g_res_wr_deny++;
            t->deny_total++;
            t->res_flags |= RESF_BAD;
            res_log(t, slot, RESF_LOG_WR, "tulis", (uint64_t)t->res_wr + len, RES_WRITE_MAX);
            return RES_DENY;
        }
        t->res_wr += (uint32_t)len;
    }
    return RES_ALLOW;
}

// Jatah soket habis (sock.c): tolak saja, tanpa strike (pelanggaran berulang tetap kena jatah
// syscall).
void res_fd_denied(size_t slot)
{
    if (slot >= MAX_TASKS) {
        g_res_fd_deny++;
        return;
    }
    task_t *t = &tasks[slot];

    g_res_fd_deny++;
    t->deny_total++;
    if (!(t->res_flags & RESF_LOG_FD)) {
        t->res_flags |= RESF_LOG_FD;
        kprintf("RES: task user slot %lu melanggar batas soket (jatah %u per task)\r\n",
                (uint64_t)slot, t->fd_max);
    }
}

uint32_t res_fd_limit(size_t slot)
{
    return slot < MAX_TASKS ? tasks[slot].fd_max : 0;   // gagal tertutup
}

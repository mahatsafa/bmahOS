// F7: uji prio.c di host (di-#include: akses state static). Simulasi scheduler tick demi tick:
// pemilihan tingkat + penuaan, jatah CPU, jatah syscall/tulis, strike dan penghentian.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"

#include "prio.c"

task_t tasks[MAX_TASKS];

static void reset(size_t n)
{
    memset(tasks, 0, sizeof(tasks));
    prio_reset();
    g_res_fd_deny = g_res_sys_deny = g_res_wr_deny = g_res_cpu_win = g_res_killed = g_sched_aged = 0;
    for (size_t i = 0; i < n; i++) {
        tasks[i].status = TASK_READY;
        prio_init_task(&tasks[i], PRIO_NORMAL, 0);
    }
}

static void set_user(size_t i)
{
    tasks[i].is_user_task = true;
    prio_init_task(&tasks[i], PRIO_LOW, 0);
}

// Satu langkah scheduler seperti schedule(): umur task yang jalan diulang, pilih, idle bila kosong.
static size_t step(size_t n, size_t cur, size_t idle, uint64_t now)
{
    tasks[cur].ready_at = now;
    size_t nx = prio_pick(tasks, n, cur, idle, now);

    return nx == (size_t)-1 ? idle : nx;
}

static void test_tingkat(void)
{
    // slot 0 net (tinggi), 1 kernel (normal), 2,3 user (rendah), 4 idle
    reset(5);
    tasks[0].prio = PRIO_HIGH;
    set_user(2);
    set_user(3);
    tasks[4].prio = PRIO_IDLE;

    CHECK(prio_pick(tasks, 5, 2, 4, 1) == 0);          // tinggi menang atas semua
    CHECK(prio_pick(tasks, 5, 0, 4, 1) == 0);          // sendirian di tingkatnya: tetap dia
    tasks[0].status = TASK_SLEEPING;
    CHECK(prio_pick(tasks, 5, 2, 4, 1) == 1);          // normal menang atas rendah
    tasks[1].status = TASK_BLOCKED;
    size_t a = prio_pick(tasks, 5, 0, 4, 1);
    size_t b = prio_pick(tasks, 5, 0, 4, 1);
    CHECK((a == 2 && b == 3) || (a == 3 && b == 2));   // rendah bergilir walau cur sama (net task)
    tasks[2].status = TASK_DEAD;
    tasks[3].status = TASK_SLEEPING;
    CHECK(prio_pick(tasks, 5, 0, 4, 1) == (size_t)-1);  // idle tak pernah dipilih, kosong = -1
    CHECK(prio_pick(tasks, 0, 0, (size_t)-1, 1) == (size_t)-1);
    tasks[4].status = TASK_READY;
    CHECK(prio_pick(tasks, 5, 0, 4, 1) == (size_t)-1);  // idle READY pun tetap dikecualikan
}

static void test_bergilir_adil(void)
{
    // tiga task user rendah, cur selalu 0 (net task yang bangun tiap tick): tiap tick tiga
    // task bergilir 1,2,3 persis, bukan yang sama terus
    reset(5);
    tasks[0].prio = PRIO_HIGH;
    tasks[0].status = TASK_SLEEPING;
    for (size_t i = 1; i <= 3; i++) {
        set_user(i);
    }
    tasks[4].prio = PRIO_IDLE;
    size_t cnt[5] = {0};
    for (uint64_t now = 1; now <= 30; now++) {
        size_t p = prio_pick(tasks, 5, 0, 4, now);
        cnt[p]++;
        tasks[p].ready_at = now;
    }
    CHECK(cnt[1] == 10 && cnt[2] == 10 && cnt[3] == 10 && cnt[0] == 0 && cnt[4] == 0);
}

static void test_penuaan(void)
{
    // net task tinggi yang tak pernah berhenti (macet) + dua task user rendah: tanpa penuaan
    // mereka tak pernah jalan. Dengan penuaan tiap task READY kebagian paling lambat
    // PRIO_AGE_TICKS + jumlah task READY tick.
    reset(4);
    tasks[0].prio = PRIO_HIGH;
    set_user(1);
    set_user(2);
    tasks[3].prio = PRIO_IDLE;

    size_t cur = 0;
    uint64_t last[3] = {0, 0, 0};
    uint64_t maxgap[3] = {0, 0, 0};
    size_t cnt[4] = {0};

    for (uint64_t now = 1; now <= 3000; now++) {
        size_t nx = step(4, cur, 3, now);

        cnt[nx]++;
        if (nx < 3) {
            uint64_t gap = now - last[nx];

            if (gap > maxgap[nx]) {
                maxgap[nx] = gap;
            }
            last[nx] = now;
        }
        cur = nx;
    }
    CHECK(cnt[1] > 0 && cnt[2] > 0);
    CHECK(maxgap[1] <= PRIO_AGE_TICKS + 3 + 2);
    CHECK(maxgap[2] <= PRIO_AGE_TICKS + 3 + 2);
    CHECK(cnt[0] > cnt[1] + cnt[2]);                      // tinggi tetap dapat sebagian besar
    CHECK(cnt[1] + cnt[2] >= 3000 / (PRIO_AGE_TICKS + 3) - 2);   // jaminan minimum
    CHECK(g_sched_aged >= cnt[1] + cnt[2] - 2);
    CHECK(cnt[3] == 0);                                    // idle tak dipilih selama ada yang layak
}

static void test_tinggi_tepat_waktu(void)
{
    // task tinggi bangun (READY) di tick T: dipilih di schedule() tick T juga, walau tiga task
    // rendah tak berhenti (watchdog R5 bergantung pada ini)
    reset(5);
    tasks[0].prio = PRIO_HIGH;
    for (size_t i = 1; i <= 3; i++) {
        set_user(i);
    }
    tasks[4].prio = PRIO_IDLE;
    size_t cur = 1;
    uint64_t maxlat = 0;
    uint64_t woke = 0;

    tasks[0].status = TASK_SLEEPING;
    for (uint64_t now = 1; now <= 2000; now++) {
        if (tasks[0].status == TASK_SLEEPING && now % 7 == 0) {
            tasks[0].status = TASK_READY;
            tasks[0].ready_at = now;
            woke = now;
        }
        size_t nx = step(5, cur, 4, now);

        if (nx == 0 && woke) {
            if (now - woke > maxlat) {
                maxlat = now - woke;
            }
            woke = 0;
            tasks[0].status = TASK_SLEEPING;   // net task selesai kerja, tidur lagi
        }
        cur = nx;
    }
    CHECK(maxlat == 0);
}

static void test_jatah_cpu(void)
{
    // satu task user pelahap CPU + idle: jatah 50 dari tiap 100 tick, sisanya idle; strike
    // naik tiap jendela; ke-RES_STRIKES_MAX saat tick di ring 3 -> RES_KILL
    reset(2);
    set_user(0);
    tasks[1].prio = PRIO_IDLE;
    tasks[1].is_user_task = false;

    size_t cur = 0;
    uint64_t run = 0, idle = 0;
    int kill_at = -1;

    for (uint64_t now = 1; now <= 1000 && kill_at < 0; now++) {
        size_t nx = step(2, cur, 1, now);

        cur = nx;
        if (cur == 0) {
            run++;
            if (res_tick(&tasks[0], 0, now, 1) == RES_KILL) {
                kill_at = (int)now;
            }
        } else {
            idle++;
            res_tick(&tasks[1], 1, now, 0);
        }
    }
    CHECK(kill_at > 0);
    CHECK(g_res_killed == 1);
    CHECK(g_res_cpu_win >= RES_STRIKES_MAX);
    // ~5 jendela + ujung: dihentikan antara jendela ke-5 dan ke-7
    CHECK(kill_at >= (int)(RES_STRIKES_MAX * RES_WIN_TICKS) && kill_at <= (int)((RES_STRIKES_MAX + 2) * RES_WIN_TICKS));
    // pemakaian CPU <= ~separuh (+ satu tick per jendela karena pencuplikan)
    CHECK(run <= (uint64_t)(kill_at / 2 + RES_STRIKES_MAX + 5));
    CHECK(run >= (uint64_t)(kill_at / 2 - RES_STRIKES_MAX - 5));
    CHECK(idle > 0);
    CHECK(tasks[0].cpu_total == run);
    CHECK(strstr(g_serial_cap, "RES: task user slot 0 melanggar batas cpu") != NULL);
    CHECK(strstr(g_serial_cap, "RES: task user slot 0 dihentikan") != NULL);
}

static void test_cpu_tidak_melanggar(void)
{
    // task user yang memakai 20 tick per jendela (di bawah jatah) tidak pernah kena strike
    reset(2);
    set_user(0);
    tasks[1].prio = PRIO_IDLE;
    uint64_t killed0 = g_res_killed;

    for (uint64_t now = 1; now <= 2000; now++) {
        if (now % 100 < 20) {
            CHECK(res_tick(&tasks[0], 0, now, 1) == RES_ALLOW);
        }
    }
    CHECK(tasks[0].res_strikes == 0);
    CHECK(g_res_killed == killed0);
    CHECK(g_res_cpu_win == 0);
    CHECK(tasks[0].cpu_total == 400);
}

static void test_tidur_mereset(void)
{
    // jendela melanggar lalu tidur lama: strike dihapus (jendela terlewat bersih)
    reset(1);
    set_user(0);
    for (uint64_t now = 1; now < 100; now++) {
        res_tick(&tasks[0], 0, now, 0);   // 99 tick -> melewati jatah
    }
    CHECK(tasks[0].res_flags & RESF_BAD);
    res_tick(&tasks[0], 0, 100, 0);       // jendela tutup: strike = 1
    CHECK(tasks[0].res_strikes == 1);
    res_tick(&tasks[0], 0, 500, 0);       // tidur 4 jendela: strike direset
    CHECK(tasks[0].res_strikes == 0);
    CHECK(!(tasks[0].res_flags & RESF_BAD) || tasks[0].res_cpu == 1);
}

static void test_syscall(void)
{
    reset(2);
    set_user(0);
    tasks[1].is_user_task = false;   // task kernel: tak pernah dibatasi

    for (int i = 0; i < RES_SYS_MAX; i++) {
        CHECK(res_syscall(&tasks[0], 0, 10, RES_SC_OTHER, 0) == RES_ALLOW);
    }
    CHECK(res_syscall(&tasks[0], 0, 10, RES_SC_OTHER, 0) == RES_DENY);     // ke-501
    CHECK(res_syscall(&tasks[0], 0, 10, RES_SC_WRITE, 1) == RES_DENY);
    CHECK(res_syscall(&tasks[0], 0, 10, RES_SC_EXIT, 0) == RES_ALLOW);     // exit tak pernah
    CHECK(g_res_sys_deny == 2);
    CHECK(tasks[0].deny_total == 2);
    CHECK(strstr(g_serial_cap, "RES: task user slot 0 melanggar batas syscall (501 dari 500 per 100 tick)") != NULL);
    // satu baris saja per jenis per task
    char *p = strstr(g_serial_cap, "melanggar batas syscall");
    CHECK(p != NULL && strstr(p + 5, "melanggar batas syscall") == NULL);
    // jendela baru: bersih lagi
    CHECK(res_syscall(&tasks[0], 0, 110, RES_SC_OTHER, 0) == RES_ALLOW);
    CHECK(tasks[0].res_strikes == 1);
    // kernel tak dibatasi
    for (int i = 0; i < 5 * RES_SYS_MAX; i++) {
        CHECK(res_syscall(&tasks[1], 1, 10, RES_SC_OTHER, 0) == RES_ALLOW);
    }
}

static void test_tulis(void)
{
    reset(1);
    set_user(0);
    for (int i = 0; i < 4; i++) {
        CHECK(res_syscall(&tasks[0], 0, 5, RES_SC_WRITE, 1024) == RES_ALLOW);
    }
    CHECK(res_syscall(&tasks[0], 0, 5, RES_SC_WRITE, 1) == RES_DENY);          // 4096 habis
    CHECK(g_res_wr_deny == 1);
    CHECK(res_syscall(&tasks[0], 0, 5, RES_SC_OTHER, 0) == RES_ALLOW);        // syscall lain tetap
    CHECK(res_syscall(&tasks[0], 0, 105, RES_SC_WRITE, 4096) == RES_ALLOW);    // jendela baru
    CHECK(res_syscall(&tasks[0], 0, 105, RES_SC_WRITE, 0xffffffffffffffffULL) == RES_DENY);   // len raksasa: tanpa luapan
    CHECK(strstr(g_serial_cap, "melanggar batas tulis") != NULL);
}

static void test_henti_banjir(void)
{
    // banjir syscall terus-menerus: tiap jendela melanggar -> setelah RES_STRIKES_MAX jendela
    // beruntun syscall berikut = RES_KILL (task_exit oleh pemanggil)
    reset(1);
    set_user(0);
    int kill_at = -1;

    for (uint64_t now = 1; now <= 2000 && kill_at < 0; now++) {
        for (int k = 0; k < 3; k++) {
            int rc = res_syscall(&tasks[0], 0, now, RES_SC_OTHER, 0);

            if (rc == RES_KILL) {
                kill_at = (int)now;
                break;
            }
        }
        if (now == 1) {
            for (int k = 0; k < RES_SYS_MAX; k++) {
                res_syscall(&tasks[0], 0, now, RES_SC_OTHER, 0);
            }
        } else if (now % RES_WIN_TICKS == 1) {
            for (int k = 0; k < RES_SYS_MAX + 5; k++) {
                if (res_syscall(&tasks[0], 0, now, RES_SC_OTHER, 0) == RES_KILL) {
                    kill_at = (int)now;
                    break;
                }
            }
        }
    }
    CHECK(kill_at > 0);
    CHECK(g_res_killed == 1);
    CHECK(strstr(g_serial_cap, "dihentikan (batas dilanggar 5 jendela beruntun)") != NULL);
}

static void test_fd(void)
{
    reset(2);
    set_user(1);
    res_fd_denied(1);
    res_fd_denied(1);
    CHECK(g_res_fd_deny == 2);
    CHECK(tasks[1].deny_total == 2);
    CHECK(tasks[1].res_strikes == 0);   // soket saja bukan strike
    CHECK(strstr(g_serial_cap, "RES: task user slot 1 melanggar batas soket (jatah 2 per task)") != NULL);
    CHECK(res_fd_limit(1) == RES_FD_MAX && res_fd_limit(MAX_TASKS) == 0);
    tasks[1].fd_max = 1;
    CHECK(res_fd_limit(1) == 1);
    res_fd_denied(MAX_TASKS + 5);   // slot tak sah: hanya dihitung, tanpa menulis di luar tabel
    CHECK(g_res_fd_deny == 3);
}

static void test_nama(void)
{
    CHECK_STR(prio_name(PRIO_HIGH), "tinggi");
    CHECK_STR(prio_name(PRIO_NORMAL), "normal");
    CHECK_STR(prio_name(PRIO_LOW), "rendah");
    CHECK_STR(prio_name(PRIO_IDLE), "idle");
    CHECK_STR(prio_name(99), "?");
}

int main(void)
{
    serial_capture_reset();
    test_tingkat();
    test_bergilir_adil();
    test_penuaan();
    test_tinggi_tepat_waktu();
    test_jatah_cpu();
    test_cpu_tidak_melanggar();
    test_tidur_mereset();
    serial_capture_reset();
    test_syscall();
    test_tulis();
    test_henti_banjir();
    test_fd();
    test_nama();
    return test_done("prio");
}

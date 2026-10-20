#include "kernel.h"

// ---- R4: log persisten di LOG.BIN (ring rekaman 512 byte) ----
// LOG.BIN dialokasikan di luar kernel (ukuran tetap, kelipatan 512, maks
// FAT32_MAP_MAX sektor). Kernel hanya menimpa sektor isinya lewat
// fat32_map_write: FAT, entri direktori, dan ukuran tidak pernah berubah.
// Tanpa LOG.BIN fitur mati (opt-in lewat keberadaan file).
//
// Rekaman (satu sektor):
//   0  "BMLG"   4  versi (1)   5  flag (bit 0 = ditulis saat panic)
//   6  panjang teks u16 (<= LD_TEXT)   8  boot u32   12  0
//   16 seq u64 (naik terus lintas boot)   24 hash: 8 byte pertama SHA-256
//      sektor dengan field hash nol   32.. teks (baris + LF), sisa nol.
// Rekaman robek/rusak (magic/versi/panjang/hash salah) diabaikan. Saat boot
// semua sektor dipindai: seq terbesar menentukan posisi tulis berikutnya
// (sektor sesudahnya) dan boot = boot rekaman itu + 1.
//
// Isi = baris yang masuk ring log (sama seperti netcon: tanpa baris AUDIT,
// tanpa register umum panic lewat g_netcon_hold). log_capture memasukkan
// baris ke antrean statis LD_QUEUE byte (juga sebelum logdisk_init, supaya
// awal boot ikut tersimpan); penuh -> baris BARU dibuang, rekaman berikutnya
// diawali "logdisk: N baris dibuang". Net task menulis satu rekaman bila
// teks cukup untuk penuh, atau tiap LD_FLUSH_TICKS bila ada isi; maks
// LD_RATE tulis per 100 tick (net task terblok selama I/O disk).
// logdisk_sync (panic, reboot) menulis langsung tanpa batas laju.

#define LD_NAME        "LOG     BIN"
#define LD_HDR         32
#define LD_TEXT        (512 - LD_HDR)
#define LD_QUEUE       4096
#define LD_FLUSH_TICKS 500
#define LD_RATE        2
#define LD_SYNC_MAX    8      // rekaman maks per logdisk_sync (antrean 4 KB)
#define LD_FLAG_PANIC  1

enum { LD_INIT = 0, LD_ON, LD_RO, LD_OFF };

static const char *const g_ld_state_name[] = { "belum", "aktif", "baca-saja", "nonaktif" };

static volatile int g_ld_state = LD_INIT;
static const char *g_ld_why = "";
static fat32_map_t g_ld_map;
static char g_ld_q[LD_QUEUE];
static uint32_t g_ld_head, g_ld_tail;      // terus naik; terisi = head - tail
static uint64_t g_ld_lost_pending;
static uint32_t g_ld_boot;
static uint64_t g_ld_next_seq;             // seq rekaman berikutnya
static uint32_t g_ld_slot;                 // sektor tulis berikutnya
static uint64_t g_ld_boot_seq;             // seq pertama boot ini
static uint64_t g_ld_prev_seq;             // seq pertama boot sebelumnya (0 = tidak ada)
static uint64_t g_ld_last_write;
static uint64_t g_ld_win_start;
static uint32_t g_ld_win_used;
static int g_ld_in_sync;
static uint8_t g_ld_rec[512];

uint64_t g_ld_written, g_ld_lost, g_ld_wfail, g_ld_bad;   // R4: metrics logdisk_*

static uint64_t ld_le(const uint8_t *p, int n)
{
    uint64_t v = 0;

    for (int i = n - 1; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static void ld_put(uint8_t *p, uint64_t v, int n)
{
    for (int i = 0; i < n; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void ld_hash(const uint8_t *rec, uint8_t out[8])
{
    uint8_t tmp[512];
    uint8_t h[32];
    sha256_ctx_t c;

    for (int i = 0; i < 512; i++) {
        tmp[i] = rec[i];
    }
    for (int i = 24; i < 32; i++) {
        tmp[i] = 0;
    }
    sha256_init(&c);
    sha256_update(&c, tmp, 512);
    sha256_final(&c, h);
    for (int i = 0; i < 8; i++) {
        out[i] = h[i];
    }
}

// Rekaman sah? Return panjang teks, atau -1.
int logdisk_rec_ok(const uint8_t *rec)
{
    uint8_t h[8];
    uint32_t len = (uint32_t)ld_le(rec + 6, 2);

    if (rec[0] != 'B' || rec[1] != 'M' || rec[2] != 'L' || rec[3] != 'G' ||
        rec[4] != 1 || len > LD_TEXT || ld_le(rec + 16, 8) == 0) {
        return -1;
    }
    ld_hash(rec, h);
    for (int i = 0; i < 8; i++) {
        if (h[i] != rec[24 + i]) {
            return -1;
        }
    }
    return (int)len;
}

// Dari log_capture (interrupt mati). s tanpa '\n'.
void logdisk_line(const char *s, uint32_t n)
{
    if (g_ld_state == LD_OFF || g_ld_state == LD_RO || g_netcon_hold) {
        return;
    }
    if (n + 1 > LD_QUEUE - (g_ld_head - g_ld_tail)) {
        g_ld_lost++;
        g_ld_lost_pending++;
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        g_ld_q[g_ld_head++ % LD_QUEUE] = s[i];
    }
    g_ld_q[g_ld_head++ % LD_QUEUE] = '\n';
}

// Isi g_ld_rec dengan baris utuh dari antrean (penanda dibuang dulu).
// Pemanggil: interrupt mati. Return panjang teks (0 = tidak ada isi).
static uint32_t ld_fill(uint32_t flags)
{
    uint32_t len = 0;

    for (int i = 0; i < 512; i++) {
        g_ld_rec[i] = 0;
    }
    if (g_ld_lost_pending) {
        len = (uint32_t)ksnprintf((char *)g_ld_rec + LD_HDR, LD_TEXT,
                                  "logdisk: %lu baris dibuang\n", g_ld_lost_pending);
        g_ld_lost_pending = 0;
    }
    while (g_ld_tail != g_ld_head) {
        uint32_t n = 0;

        while (g_ld_tail + n != g_ld_head && g_ld_q[(g_ld_tail + n) % LD_QUEUE] != '\n') {
            n++;
        }
        n++;   // LF
        if (len + n > LD_TEXT) {
            break;
        }
        for (uint32_t i = 0; i < n; i++) {
            g_ld_rec[LD_HDR + len + i] = (uint8_t)g_ld_q[(g_ld_tail + i) % LD_QUEUE];
        }
        g_ld_tail += n;
        len += n;
    }
    if (len == 0) {
        return 0;
    }
    g_ld_rec[0] = 'B';
    g_ld_rec[1] = 'M';
    g_ld_rec[2] = 'L';
    g_ld_rec[3] = 'G';
    g_ld_rec[4] = 1;
    g_ld_rec[5] = (uint8_t)flags;
    ld_put(g_ld_rec + 6, len, 2);
    ld_put(g_ld_rec + 8, g_ld_boot, 4);
    ld_put(g_ld_rec + 16, g_ld_next_seq, 8);
    ld_hash(g_ld_rec, g_ld_rec + 24);
    return len;
}

// Tulis g_ld_rec ke slot berikutnya. Gagal -> nonaktif (volume baca saja).
static int ld_write_rec(void)
{
    if (fat32_map_write(&g_ld_map, g_ld_slot, g_ld_rec) != FAT32_OK) {
        g_ld_wfail++;
        g_ld_state = LD_OFF;
        g_ld_why = "tulis gagal";
        return 0;
    }
    g_ld_written++;
    g_ld_next_seq++;
    g_ld_slot = (g_ld_slot + 1) % g_ld_map.nsec;
    g_ld_last_write = timer_ticks;
    return 1;
}

// Net task, sekali sebelum loop (disk sudah di-probe di kmain).
void logdisk_init(void)
{
    uint8_t rec[512];
    uint64_t max_seq = 0;
    uint32_t max_slot = 0, max_boot = 0;
    int rc = fat32_file_map(LD_NAME, &g_ld_map);

    if (rc != FAT32_OK) {
        g_ld_why = rc == FAT32_ERR_NOENT ? "tanpa LOG.BIN" :
                   rc == FAT32_ERR_TOOBIG ? "ukuran LOG.BIN" : "disk";
        g_ld_state = LD_OFF;
    } else {
        for (uint32_t s = 0; s < g_ld_map.nsec; s++) {
            if (fat32_map_read(&g_ld_map, s, rec) != FAT32_OK) {
                g_ld_why = "baca gagal";
                g_ld_state = LD_OFF;
                break;
            }
            if (logdisk_rec_ok(rec) < 0) {
                // Sektor kosong (belum pernah ditulis) bukan "rusak".
                int blank = rec[0] != 'B' || rec[1] != 'M' || rec[2] != 'L' || rec[3] != 'G';
                g_ld_bad += !blank;
                continue;
            }
            uint64_t seq = ld_le(rec + 16, 8);
            if (seq > max_seq) {
                max_seq = seq;
                max_slot = s;
                max_boot = (uint32_t)ld_le(rec + 8, 4);
            }
        }
    }

    if (g_ld_state != LD_OFF) {
        g_ld_boot = max_boot + 1;
        g_ld_next_seq = max_seq + 1;
        g_ld_slot = max_seq ? (max_slot + 1) % g_ld_map.nsec : 0;
        g_ld_boot_seq = g_ld_next_seq;
        // Seq pertama boot sebelumnya: rekaman sah boot max_boot dengan seq terkecil.
        for (uint32_t s = 0; max_seq && s < g_ld_map.nsec; s++) {
            if (fat32_map_read(&g_ld_map, s, rec) == FAT32_OK && logdisk_rec_ok(rec) >= 0 &&
                (uint32_t)ld_le(rec + 8, 4) == max_boot) {
                uint64_t seq = ld_le(rec + 16, 8);
                if (g_ld_prev_seq == 0 || seq < g_ld_prev_seq) {
                    g_ld_prev_seq = seq;
                }
            }
        }
        g_ld_state = fat32_writable() ? LD_ON : LD_RO;
        if (g_ld_state == LD_RO) {
            g_ld_why = "volume baca saja";
        }
    }

    uint64_t lf = irq_save();
    if (g_ld_state != LD_ON) {
        g_ld_head = g_ld_tail = 0;   // antrean awal boot dibuang
        g_ld_lost_pending = 0;
    }
    irq_restore(lf);
    // Antrean awal boot (biasanya penuh: 4 KB pertama) langsung ditulis supaya
    // baris berikutnya, termasuk baris status ini, tidak ikut dibuang.
    logdisk_sync(0);

    kprintf("R4: logdisk %s%s%s rekaman=%u boot=%u seq=%lu rusak=%lu\r\n",
            g_ld_state_name[g_ld_state], *g_ld_why ? " " : "", g_ld_why,
            g_ld_map.nsec, g_ld_boot, g_ld_boot_seq, g_ld_bad);
}

// Net task, tiap putaran.
void logdisk_poll(void)
{
    uint64_t now = timer_ticks;

    if (g_ld_state != LD_ON) {
        return;
    }
    if (now - g_ld_win_start >= 100) {
        g_ld_win_start = now;
        g_ld_win_used = 0;
    }
    if (g_ld_win_used >= LD_RATE) {
        return;
    }

    uint64_t lf = irq_save();
    uint32_t queued = g_ld_head - g_ld_tail;
    int due = queued >= LD_TEXT ||
              ((queued || g_ld_lost_pending) && now - g_ld_last_write >= LD_FLUSH_TICKS);
    uint32_t len = due ? ld_fill(0) : 0;
    irq_restore(lf);

    if (len) {
        g_ld_win_used++;
        ld_write_rec();
    }
}

// Panic / reboot: tulis antrean langsung (interrupt mati, AHCI polling).
// Dilewati bila disk sedang dipakai (panic di tengah I/O) atau bersarang.
void logdisk_sync(int panic)
{
    if (g_ld_state != LD_ON || g_ld_in_sync || g_ahci_busy) {
        return;
    }
    g_ld_in_sync = 1;
    for (int i = 0; i < LD_SYNC_MAX; i++) {
        uint64_t lf = irq_save();
        uint32_t len = ld_fill(panic ? LD_FLAG_PANIC : 0);
        irq_restore(lf);

        if (len == 0 || !ld_write_rec()) {
            break;
        }
    }
    g_ld_in_sync = 0;
}

// Sektor tempat seq berada (berdasarkan posisi tulis), atau -1 bila di luar ring.
static int ld_slot_of(uint64_t seq)
{
    uint64_t last = g_ld_next_seq - 1;

    if (seq == 0 || seq > last || last - seq >= g_ld_map.nsec) {
        return -1;
    }
    return (int)((g_ld_slot + g_ld_map.nsec - 1 - (uint32_t)(last - seq)) % g_ld_map.nsec);
}

static uint64_t ld_oldest(void)
{
    uint64_t last = g_ld_next_seq - 1;

    return last >= g_ld_map.nsec ? last - g_ld_map.nsec + 1 : 1;
}

// Perintah `logdisk` (status) dan `logdisk <seq>` (teks mulai seq, halaman
// <= CMD_OUT_MAX, sisa -> baris akhir logdisk_lanjut=<seq>). a = argumen
// setelah "logdisk" (kosong atau " <desimal>").
void logdisk_execute(const volatile uint8_t *a, uint32_t len)
{
    char line[96];
    uint64_t start = 0;

    if (len > 0) {
        if (len < 2 || len > 21 || a[0] != ' ') {
            cmd_puts("ERR: logdisk [seq]\n");
            return;
        }
        for (uint32_t i = 1; i < len; i++) {
            if (a[i] < '0' || a[i] > '9') {
                cmd_puts("ERR: logdisk [seq]\n");
                return;
            }
            start = start * 10 + (uint64_t)(a[i] - '0');
        }
    }

    if (len == 0) {
        ksnprintf(line, sizeof(line), "logdisk=%s%s%s\n", g_ld_state_name[g_ld_state],
                  *g_ld_why ? " " : "", g_ld_why);
        cmd_puts(line);
        if (g_ld_state != LD_ON && g_ld_state != LD_RO) {
            return;
        }
        ksnprintf(line, sizeof(line), "rekaman=%u\nboot=%u\nseq_tertua=%lu\nseq_berikut=%lu\n",
                  g_ld_map.nsec, g_ld_boot, g_ld_next_seq > 1 ? ld_oldest() : 0, g_ld_next_seq);
        cmd_puts(line);
        ksnprintf(line, sizeof(line), "seq_boot_ini=%lu\nseq_boot_lalu=%lu\nantre=%u\n",
                  g_ld_boot_seq, g_ld_prev_seq, g_ld_head - g_ld_tail);
        cmd_puts(line);
        ksnprintf(line, sizeof(line), "ditulis=%lu\ndibuang=%lu\ngagal=%lu\nrusak=%lu\n",
                  g_ld_written, g_ld_lost, g_ld_wfail, g_ld_bad);
        cmd_puts(line);
        return;
    }

    if (g_ld_state != LD_ON && g_ld_state != LD_RO) {
        cmd_puts("ERR: logdisk nonaktif\n");
        return;
    }
    if (g_ld_next_seq <= 1) {
        cmd_puts("ERR: logdisk kosong\n");
        return;
    }
    if (start < ld_oldest()) {
        start = ld_oldest();
    }
    if (start >= g_ld_next_seq) {
        cmd_puts("ERR: logdisk: seq di luar ring\n");
        return;
    }

    uint8_t rec[512];
    uint32_t prev_boot = 0;
    int prev_panic = 0;
    const uint32_t reserve = 32;   // baris "logdisk_lanjut=<seq>\n"

    for (uint64_t seq = start; seq < g_ld_next_seq; seq++) {
        int slot = ld_slot_of(seq);
        int n = -1;

        if (slot >= 0 && fat32_map_read(&g_ld_map, (uint32_t)slot, rec) == FAT32_OK) {
            n = logdisk_rec_ok(rec);
            if (n >= 0 && ld_le(rec + 16, 8) != seq) {
                n = -1;   // posisi tidak cocok (tulis gagal / berkas diubah)
            }
        }

        uint32_t boot = n >= 0 ? (uint32_t)ld_le(rec + 8, 4) : 0;
        int panic = n >= 0 && (rec[5] & LD_FLAG_PANIC);
        uint32_t hl = 0;

        if (n < 0) {
            hl = (uint32_t)ksnprintf(line, sizeof(line), "=== seq %lu rusak/hilang ===\n", seq);
        } else if (boot != prev_boot || (panic && !prev_panic)) {
            // Header: boot berganti, awal halaman, atau rekaman panic pertama
            // di tengah boot (klien membuang header awal halaman yang sama).
            hl = (uint32_t)ksnprintf(line, sizeof(line), "=== boot %u seq %lu%s ===\n", boot,
                                     seq, panic ? " panic" : "");
        }
        if (g_cmd_len + hl + (uint32_t)(n > 0 ? n : 0) + reserve > CMD_OUT_MAX) {
            if (seq == start) {
                cmd_puts("ERR: logdisk: rekaman terlalu besar\n");   // tidak terjadi: 480 + header
                return;
            }
            ksnprintf(line, sizeof(line), "logdisk_lanjut=%lu\n", seq);
            cmd_puts(line);
            return;
        }
        if (hl) {
            cmd_puts(line);
        }
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                cmd_putc((char)rec[LD_HDR + i]);
            }
        }
        prev_boot = boot;   // rusak -> 0: header dicetak lagi sesudahnya
        prev_panic = panic;
    }
}

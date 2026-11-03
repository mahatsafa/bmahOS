// P7-2: penerimaan kernel baru lewat jaringan dan penulisan slot A/B.
//
// Alur: admin (sesi TCP 7779 / TLS 7780) menjalankan
//   ota terima kernel <ukuran> <sha16>
// (ukuran = panjang file .bmo, sha16 = 16 hex pertama sha256 file itu; sha256
// penuh tidak muat di batas perintah 64 byte). Port TCP 7781 lalu menerima
// SATU koneksi selama OTA_LISTEN_TICKS, hanya dari IP sesi itu. Data masuk ke
// g_ota_buf (statis, 1 MB + 128) sambil di-hash. Setelah lengkap: sha16 ->
// ota_check (tanda tangan ECDSA, P7-1) -> anti-downgrade (versi harus > versi
// slot aktif di OTA.BIN) -> OTA.BIN slot tujuan = DITULIS -> slot ditulis
// OTA_SEC_PER_POLL sektor per putaran net task (sisa sampai 1 MB diisi nol)
// -> dibaca balik + sha256 + ekor nol -> OTA.BIN slot tujuan = SAH. Hasil
// (satu baris OK/ERR) dikirim di koneksi 7781 lalu FIN; juga di `ota`.
//
// Slot tujuan = slot yang BUKAN aktif (OTA.BIN; kosong/rusak -> default_entry
// limine.conf, lalu slot berjalan, lalu A) dan bukan slot yang sedang
// berjalan (cmdline slot=). KERNA.ELF/KERNB.ELF (tepat 1 MB), OTA.BIN (512 B)
// dan limine.conf dibuat dari host; kernel hanya menimpa sektor isinya lewat
// fat32_file_map, jadi FAT dan direktori tidak pernah berubah. Pengecualian:
// OTA.BIN yang belum ada dibuat sekali saat boot (512 byte nol = kosong) bila
// kedua slot ada dan volume bisa ditulis (disk P7-0 belum punya OTA.BIN). Mati listrik di
// tengah penulisan meninggalkan status DITULIS (slot tidak boleh dicoba, P7-3).
// Semua dari net task (tanpa lock).
#include "kernel.h"

#define OTA_PORT          7781
#define OTA_LISTEN_TICKS  6000u   // 60 s menunggu koneksi 7781
#define OTA_SEC_PER_POLL  32u     // sektor per putaran net task (tulis / baca balik)
#define OTA_RX_WND_MAX    4096u   // jendela terima TCP 7781
#define OTA_SLOT_SEC      (OTA_KERNEL_MAX / 512u)
#define OTA_MSG_MAX       120

enum { OS_IDLE = 0, OS_LISTEN, OS_RX, OS_CHECK, OS_MARK, OS_WRITE, OS_VERIFY, OS_COMMIT };
static const char *const g_os_state_name[] = {
    "diam", "menunggu koneksi 7781", "menerima", "memeriksa", "menandai OTA.BIN",
    "menulis slot", "membaca balik", "mengukuhkan OTA.BIN",
};

static uint8_t g_ota_buf[OTA_PREFIX + OTA_KERNEL_MAX] __attribute__((aligned(16)));
static fat32_map_t g_os_slot_map;   // slot tujuan (dipetakan saat `ota terima`)
static fat32_map_t g_os_st_map;     // OTA.BIN
static int g_os_on;                 // OTA.BIN + kedua slot ada
static const char *g_os_why = "belum diperiksa";
static ota_st_t g_os_st;
static const char *g_os_st_src = "-";   // "OTA.BIN" / "kosong" / "rusak"
static const char *g_os_aktif_src = "-";
static int g_os_run = -1;           // slot berjalan (cmdline), -1 = ISO/tidak dikenal

static int g_os_state;
static uint8_t g_os_ip[4];
static uint64_t g_os_deadline;
static uint32_t g_os_len, g_os_got;
static uint8_t g_os_sha16[8];
static sha256_ctx_t g_os_ctx;
static int g_os_target;
static uint32_t g_os_sec;
static ota_info_t g_os_inf;
static char g_os_last[OTA_MSG_MAX] = "-";
static char g_os_reply[OTA_MSG_MAX];
static int g_os_reply_ready;

uint64_t g_ota_terima, g_ota_ok, g_ota_gagal;

static const char g_slot_name83[2][12] = { "KERNA   ELF", "KERNB   ELF" };

static char os_slot_ch(int s)
{
    return s == 0 ? 'A' : 'B';
}

static int os_st_write(void)
{
    uint8_t b[512];

    g_os_st.seq++;
    ota_st_encode(&g_os_st, b);
    if (fat32_map_write(&g_os_st_map, 0, b) != FAT32_OK) {
        return 0;
    }
    g_os_st_src = "OTA.BIN";
    return 1;
}

void ota_init(void)
{
    uint8_t b[512];
    int rc;

    g_os_run = ota_cmdline_slot(g_boot_cmdline);
    g_os_on = 0;
    g_os_why = "";
    for (int i = 0; i < 2; i++) {
        rc = fat32_file_map(g_slot_name83[i], &g_os_slot_map);
        if (rc == FAT32_ERR_NOVOL) {
            g_os_why = "tanpa disk";
            break;
        }
        if (rc != FAT32_OK || g_os_slot_map.nsec != OTA_SLOT_SEC) {
            g_os_why = i == 0 ? "KERNA.ELF tidak ada / bukan 1 MB" :
                       "KERNB.ELF tidak ada / bukan 1 MB";
            break;
        }
    }
    g_os_slot_map.nsec = 0;
    if (!*g_os_why) {
        rc = fat32_file_map("OTA     BIN", &g_os_st_map);
        if (rc == FAT32_ERR_NOENT && fat32_writable()) {
            uint32_t sz;

            memset(b, 0, sizeof(b));
            if (fat32_write_name("OTA     BIN", b, sizeof(b), 0, &sz) == FAT32_OK) {
                kprintf("P7: OTA.BIN dibuat (512 byte kosong)\r\n");
                rc = fat32_file_map("OTA     BIN", &g_os_st_map);
            }
        }
        if (rc != FAT32_OK || g_os_st_map.nsec != 1) {
            g_os_why = rc == FAT32_ERR_NOENT ? "tanpa OTA.BIN" : "OTA.BIN harus 512 byte";
        } else if (fat32_map_read(&g_os_st_map, 0, b) != FAT32_OK) {
            g_os_why = "baca OTA.BIN gagal";
        } else {
            g_os_on = 1;
        }
    }

    if (g_os_on) {
        rc = ota_st_decode(b, &g_os_st);
        if (rc == 1) {
            g_os_st_src = "OTA.BIN";
            g_os_aktif_src = "OTA.BIN";
        } else {
            fat32_map_t *m = &g_os_slot_map;   // dipinjam sebentar
            int d = 0;

            g_os_st_src = rc == 0 ? "kosong" : "rusak";
            if (fat32_file_map("LIMINE~1CON", m) == FAT32_OK && m->nsec == 1 &&
                fat32_map_read(m, 0, b) == FAT32_OK) {
                d = ota_conf_default(b, 512);
            }
            m->nsec = 0;
            if (d) {
                ota_st_init(&g_os_st, (uint8_t)(d - 1));
                g_os_aktif_src = "limine.conf";
            } else if (g_os_run >= 0) {
                ota_st_init(&g_os_st, (uint8_t)g_os_run);
                g_os_aktif_src = "cmdline";
            } else {
                ota_st_init(&g_os_st, 0);
                g_os_aktif_src = "anggapan A";
            }
        }
        kprintf("P7: ota siap berjalan=%s aktif=%c (%s) OTA.BIN=%s slot A v%u slot B v%u\r\n",
                g_os_run < 0 ? "ISO" : g_os_run == 0 ? "A" : "B", os_slot_ch(g_os_st.aktif),
                g_os_aktif_src, g_os_st_src, g_os_st.s[0].versi, g_os_st.s[1].versi);
    } else {
        kprintf("P7: ota mati (%s)\r\n", g_os_why);
    }
}

static void os_finish(int ok, const char *msg)
{
    uint32_t i;

    for (i = 0; msg[i] && i < OTA_MSG_MAX - 2; i++) {
        g_os_last[i] = msg[i];
    }
    g_os_last[i] = 0;
    for (i = 0; g_os_last[i]; i++) {
        g_os_reply[i] = g_os_last[i];
    }
    g_os_reply[i++] = '\n';
    g_os_reply[i] = 0;
    g_os_reply_ready = 1;
    if (ok) {
        g_ota_ok++;
    } else {
        g_ota_gagal++;
    }
    g_os_slot_map.nsec = 0;
    g_os_state = OS_IDLE;
    kprintf("P7: ota %s\r\n", g_os_last);
}

static void os_fail(const char *why)
{
    char m[OTA_MSG_MAX];

    ksnprintf(m, sizeof(m), "ERR ota: %s", why);
    os_finish(0, m);
}

static void os_hex(char *out, const uint8_t *b, uint32_t n)
{
    static const char h[] = "0123456789abcdef";

    for (uint32_t i = 0; i < n; i++) {
        out[2 * i] = h[b[i] >> 4];
        out[2 * i + 1] = h[b[i] & 15];
    }
    out[2 * n] = 0;
}

static int os_hexval(uint8_t c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// ---- jalur net.c (port 7781) ----
int ota_listen_ok(const volatile uint8_t *ip)
{
    // Hanya koneksi 7781 aktif yang menghalangi; yang sedang menutup diganti
    // di net_tcp_ota_syn.
    if (g_os_state != OS_LISTEN || net_tcp_ota_alive() == 1) {
        return 0;
    }
    for (int i = 0; i < 4; i++) {
        if (ip[i] != g_os_ip[i]) {
            return 0;
        }
    }
    return 1;
}

void ota_conn_open(void)
{
    g_os_state = OS_RX;
    g_os_got = 0;
    g_os_reply_ready = 0;
    sha256_init(&g_os_ctx);
}

uint32_t ota_rx_space(void)
{
    if (g_os_state != OS_RX) {
        return 0;
    }
    uint32_t r = g_os_len - g_os_got;

    return r > OTA_RX_WND_MAX ? OTA_RX_WND_MAX : r;
}

uint32_t ota_rx(const volatile uint8_t *d, uint32_t n)
{
    uint32_t sp = ota_rx_space();

    if (n > sp) {
        n = sp;   // lebihnya tidak di-ACK (jendela sudah dipatuhi peer yang benar)
    }
    for (uint32_t i = 0; i < n; i++) {
        g_ota_buf[g_os_got + i] = d[i];
    }
    sha256_update(&g_os_ctx, g_ota_buf + g_os_got, n);
    g_os_got += n;
    if (n && g_os_got == g_os_len) {
        g_os_state = OS_CHECK;
    }
    return n;
}

int ota_busy(void)
{
    return g_os_state >= OS_CHECK;
}

const char *ota_reply_take(void)
{
    if (!g_os_reply_ready) {
        return 0;
    }
    g_os_reply_ready = 0;
    return g_os_reply;
}

// ---- net task, tiap putaran ----
static void os_check(void)
{
    uint8_t h[32];
    char m[OTA_MSG_MAX];
    int rc;

    sha256_final(&g_os_ctx, h);
    if (!ct_memeq(h, g_os_sha16, 8)) {
        os_fail("sha256 file tidak cocok dengan perintah");
        return;
    }
    rc = ota_check(g_ota_buf, g_os_len, ota_pubkey(), &g_os_inf);
    if (rc != OTA_OK) {
        os_fail(ota_strerror(rc));
        return;
    }
    if (g_os_inf.jenis != OTA_JENIS_KERNEL) {
        os_fail("isi bukan kernel");
        return;
    }
    if (g_os_inf.versi <= g_os_st.s[g_os_st.aktif].versi) {
        ksnprintf(m, sizeof(m), "versi %u <= versi slot aktif %c (%u), ditolak",
                  g_os_inf.versi, os_slot_ch(g_os_st.aktif), g_os_st.s[g_os_st.aktif].versi);
        os_fail(m);
        return;
    }
    g_os_state = OS_MARK;
}

void ota_poll(void)
{
    uint8_t sec[512];

    switch (g_os_state) {
    case OS_LISTEN:
        if (net_tcp_ota_alive() == 1) {
            break;
        }
        if (timer_ticks > g_os_deadline) {
            os_fail("tidak ada koneksi 7781 dalam 60 s");
        }
        break;
    case OS_RX:
        if (net_tcp_ota_alive() != 1) {
            char m[OTA_MSG_MAX];

            ksnprintf(m, sizeof(m), "koneksi 7781 ditutup setelah %u dari %u byte",
                      g_os_got, g_os_len);
            os_fail(m);
        }
        break;
    case OS_CHECK:
        os_check();
        break;
    case OS_MARK: {
        ota_slot_t *s = &g_os_st.s[g_os_target];

        s->status = OTA_SLOT_DITULIS;
        s->versi = g_os_inf.versi;
        s->ukuran = g_os_inf.ukuran;
        memcpy(s->sha256, g_os_inf.sha256, 32);
        if (!os_st_write()) {
            os_fail("tulis OTA.BIN gagal");
            break;
        }
        g_os_sec = 0;
        g_os_state = OS_WRITE;
        break;
    }
    case OS_WRITE:
        for (uint32_t k = 0; k < OTA_SEC_PER_POLL && g_os_sec < OTA_SLOT_SEC; k++, g_os_sec++) {
            uint32_t off = g_os_sec * 512u;
            const uint8_t *isi = g_ota_buf + OTA_PREFIX;

            memset(sec, 0, sizeof(sec));
            if (off < g_os_inf.ukuran) {
                uint32_t n = g_os_inf.ukuran - off;

                memcpy(sec, isi + off, n > 512 ? 512 : n);
            }
            if (fat32_map_write(&g_os_slot_map, g_os_sec, sec) != FAT32_OK) {
                os_fail("tulis slot gagal (slot ditandai DITULIS)");
                return;
            }
        }
        if (g_os_sec == OTA_SLOT_SEC) {
            g_os_sec = 0;
            sha256_init(&g_os_ctx);
            g_os_state = OS_VERIFY;
        }
        break;
    case OS_VERIFY:
        for (uint32_t k = 0; k < OTA_SEC_PER_POLL && g_os_sec < OTA_SLOT_SEC; k++, g_os_sec++) {
            uint32_t off = g_os_sec * 512u, n = 0, tail = 1;

            if (fat32_map_read(&g_os_slot_map, g_os_sec, sec) != FAT32_OK) {
                os_fail("baca balik slot gagal");
                return;
            }
            if (off < g_os_inf.ukuran) {
                n = g_os_inf.ukuran - off;
                n = n > 512 ? 512 : n;
                sha256_update(&g_os_ctx, sec, n);
            }
            for (uint32_t i = n; i < 512; i++) {
                tail &= sec[i] == 0;
            }
            if (!tail) {
                os_fail("baca balik: sisa slot tidak nol");
                return;
            }
        }
        if (g_os_sec == OTA_SLOT_SEC) {
            uint8_t h[32];

            sha256_final(&g_os_ctx, h);
            if (!ct_memeq(h, g_os_inf.sha256, 32)) {
                os_fail("baca balik: sha256 slot tidak cocok");
                return;
            }
            g_os_state = OS_COMMIT;
        }
        break;
    case OS_COMMIT: {
        char m[OTA_MSG_MAX], hx[17];

        g_os_st.s[g_os_target].status = OTA_SLOT_SAH;
        if (!os_st_write()) {
            os_fail("tulis OTA.BIN (sah) gagal");
            break;
        }
        os_hex(hx, g_os_inf.sha256, 8);
        ksnprintf(m, sizeof(m), "OK ota: slot %c versi %u ukuran %u sha256 %s ditulis + dibaca balik",
                  os_slot_ch(g_os_target), g_os_inf.versi, g_os_inf.ukuran, hx);
        os_finish(1, m);
        break;
    }
    default:
        break;
    }
}

// ---- perintah ----
static void os_status(void)
{
    static const char *const st[] = { "tanpa-catatan", "sah", "DITULIS(tidak lengkap)" };
    char l[160], hx[17];

    if (!g_os_on) {
        ksnprintf(l, sizeof(l), "ota: mati (%s)\n", g_os_why);
        cmd_puts(l);
        return;
    }
    ksnprintf(l, sizeof(l), "ota: berjalan=%s aktif=%c (%s) OTA.BIN=%s seq=%u\n",
              g_os_run < 0 ? "ISO" : g_os_run == 0 ? "A" : "B", os_slot_ch(g_os_st.aktif),
              g_os_aktif_src, g_os_st_src, g_os_st.seq);
    cmd_puts(l);
    for (int i = 0; i < 2; i++) {
        const ota_slot_t *s = &g_os_st.s[i];

        os_hex(hx, s->sha256, 8);
        ksnprintf(l, sizeof(l), "slot %c: %s versi=%u ukuran=%u sha256=%s\n", os_slot_ch(i),
                  s->status <= 2 ? st[s->status] : "?", s->versi, s->ukuran, hx);
        cmd_puts(l);
    }
    if (g_os_state == OS_LISTEN) {
        uint64_t sisa = g_os_deadline > timer_ticks ? (g_os_deadline - timer_ticks) / 100 : 0;

        ksnprintf(l, sizeof(l), "terima: %s dari %u.%u.%u.%u (sisa %lu s) slot %c\n",
                  g_os_state_name[g_os_state], g_os_ip[0], g_os_ip[1], g_os_ip[2], g_os_ip[3],
                  sisa, os_slot_ch(g_os_target));
    } else if (g_os_state == OS_RX) {
        ksnprintf(l, sizeof(l), "terima: menerima %u/%u byte\n", g_os_got, g_os_len);
    } else if (g_os_state == OS_WRITE || g_os_state == OS_VERIFY) {
        ksnprintf(l, sizeof(l), "terima: %s %u/%u sektor\n", g_os_state_name[g_os_state],
                  g_os_sec, OTA_SLOT_SEC);
    } else {
        ksnprintf(l, sizeof(l), "terima: %s\n", g_os_state_name[g_os_state]);
    }
    cmd_puts(l);
    ksnprintf(l, sizeof(l), "terakhir: %s\n", g_os_last);
    cmd_puts(l);
}

static int os_parse_u32(const volatile uint8_t *p, uint32_t n, uint32_t *out)
{
    uint64_t v = 0;

    if (n == 0 || n > 8) {
        return 0;
    }
    for (uint32_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return 0;
        }
        v = v * 10 + (p[i] - '0');
    }
    *out = (uint32_t)v;
    return 1;
}

static void os_terima(const volatile uint8_t *a, uint32_t n)
{
    static const char fmt[] = "ERR: format: ota terima kernel <ukuran> <sha16>\n";
    uint32_t i = 0, j, ukuran;
    uint8_t sha16[8];
    char l[OTA_MSG_MAX];

    if (!g_os_on) {
        ksnprintf(l, sizeof(l), "ERR: ota mati (%s)\n", g_os_why);
        cmd_puts(l);
        return;
    }
    if (!g_cmd_src_ip) {
        cmd_puts("ERR: ota terima hanya lewat sesi TCP 7779 / TLS 7780\n");
        return;
    }
    // jenis
    for (j = i; j < n && a[j] != ' '; j++) {
    }
    if (net_cmd_is(a + i, j - i, "app")) {
        cmd_puts("ERR: ota terima app belum didukung (P7-4)\n");
        return;
    }
    if (!net_cmd_is(a + i, j - i, "kernel") || j >= n) {
        cmd_puts(fmt);
        return;
    }
    // ukuran
    i = j + 1;
    for (j = i; j < n && a[j] != ' '; j++) {
    }
    if (!os_parse_u32(a + i, j - i, &ukuran) || j >= n) {
        cmd_puts(fmt);
        return;
    }
    // sha16
    i = j + 1;
    if (n - i != 16) {
        cmd_puts(fmt);
        return;
    }
    for (uint32_t k = 0; k < 8; k++) {
        int hi = os_hexval(a[i + 2 * k]), lo = os_hexval(a[i + 2 * k + 1]);

        if (hi < 0 || lo < 0) {
            cmd_puts(fmt);
            return;
        }
        sha16[k] = (uint8_t)(hi << 4 | lo);
    }
    if (ukuran <= OTA_PREFIX || ukuran > OTA_PREFIX + OTA_KERNEL_MAX) {
        ksnprintf(l, sizeof(l), "ERR: ukuran harus %u..%u byte\n", OTA_PREFIX + 1,
                  OTA_PREFIX + OTA_KERNEL_MAX);
        cmd_puts(l);
        return;
    }
    if (g_os_state != OS_IDLE) {
        ksnprintf(l, sizeof(l), "ERR: ota sibuk (%s)\n", g_os_state_name[g_os_state]);
        cmd_puts(l);
        return;
    }
    int target = g_os_st.aktif ? 0 : 1;

    if (target == g_os_run) {
        cmd_puts("ERR: slot tujuan sedang berjalan\n");
        return;
    }
    if (!fat32_writable()) {
        cmd_puts("ERR: disk baca saja\n");
        return;
    }
    if (fat32_file_map(g_slot_name83[target], &g_os_slot_map) != FAT32_OK ||
        g_os_slot_map.nsec != OTA_SLOT_SEC) {
        g_os_slot_map.nsec = 0;
        cmd_puts("ERR: slot tujuan tidak bisa dipetakan\n");
        return;
    }
    for (int k = 0; k < 4; k++) {
        g_os_ip[k] = g_cmd_src_ip[k];
    }
    memcpy(g_os_sha16, sha16, sizeof(sha16));
    g_os_len = ukuran;
    g_os_got = 0;
    g_os_target = target;
    g_os_deadline = timer_ticks + OTA_LISTEN_TICKS;
    g_os_reply_ready = 0;
    g_os_state = OS_LISTEN;
    g_ota_terima++;
    ksnprintf(l, sizeof(l), "OK ota: kirim %u byte ke port %u dalam 60 s (slot %c)\n",
              ukuran, OTA_PORT, os_slot_ch(target));
    cmd_puts(l);
    kprintf("P7: ota terima %u byte slot %c dari %u.%u.%u.%u\r\n", ukuran, os_slot_ch(target),
            g_os_ip[0], g_os_ip[1], g_os_ip[2], g_os_ip[3]);
}

int ota_execute(const volatile uint8_t *cmd, uint32_t len)
{
    if (net_cmd_is(cmd, len, "ota")) {
        os_status();
        return 1;
    }
    if (len > 11 && net_cmd_is(cmd, 11, "ota terima ")) {
        os_terima(cmd + 11, len - 11);
        return 1;
    }
    if (len > 4 && net_cmd_is(cmd, 4, "ota ")) {
        cmd_puts("ERR: format: ota | ota terima kernel <ukuran> <sha16>\n");
        return 1;
    }
    return 0;
}

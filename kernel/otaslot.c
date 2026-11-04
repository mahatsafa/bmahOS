// P7-2: penerimaan kernel baru lewat jaringan dan penulisan slot A/B.
//
// Alur: admin (sesi TCP 7779 / TLS 7780) menjalankan
//   ota terima kernel <ukuran> <sha16>   (P7-4: juga `app`, lihat di bawah)
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
//
// P7-3 boot percobaan: `ota coba` -> OTA.BIN {coba = slot tujuan, sisa = 3}
// lalu digit default_entry limine.conf (satu sektor, lewat peta file) lalu
// reboot. Saat boot (ota_init, dari kmain sebelum net task) ota_boot_decide
// (ota.c) memutuskan: slot coba berjalan -> sisa-1 (mode percobaan), sisa
// habis -> rollback (slot GAGAL, limine.conf ke slot aktif, reboot); lihat
// ota.c untuk kasus lain. Mode percobaan: sehat (uptime >= 60 s, entropi siap,
// jalur admin TLS atau teks polos terbuka; net task jalan karena ota_poll
// dipanggil di sana) -> slot dikukuhkan (OTA.BIN aktif = coba). `ota sah`
// mengukuhkan lebih cepat, `ota batal` membatalkan + reboot. Tidak sehat
// dalam 300 s atau net task tidak jalan -> panic (reboot, percobaan terpakai).
// Urutan tulis selalu OTA.BIN dulu, limine.conf kedua: crash di antaranya
// diselesaikan ota_boot_decide pada boot berikutnya.
//
// P7-4 `ota terima app <ukuran> <sha16>`: jalur 7781 + sha16 + ota_check sama,
// isi harus jenis app, versi > versi APP.BIN sah di disk (app.c; APP.BIN
// tidak ada / tidak sah -> versi apa pun). File .bmo utuh ditimpa lewat
// fat32_write_name (jalur timpa D6: data ke rantai baru, SATU tulis sektor
// entri direktori, rantai lama dibebaskan; crash sebelum tulis entri = APP.BIN
// lama utuh). Tidak memakai file sementara: sektor root APP.BIN bisa penuh
// (disk VMware P7-0). Lalu dibaca balik dan dibandingkan, berlaku setelah
// reboot (app.c memeriksa tanda tangan lagi saat boot).
// Tidak butuh slot/OTA.BIN. Ditolak selama percobaan kernel tertunda: rollback /
// ota batal bisa kembali ke kernel pra-P7-4 yang menjalankan .bmo sebagai biner mentah.
// ota_init dari kmain sebelum net task dibuat; sisanya dari net task (tanpa lock).
#include "kernel.h"

#define OTA_PORT          7781
#define OTA_LISTEN_TICKS  6000u   // 60 s menunggu koneksi 7781
#define OTA_SEC_PER_POLL  32u     // sektor per putaran net task (tulis / baca balik)
#define OTA_RX_WND_MAX    4096u   // jendela terima TCP 7781
#define OTA_SLOT_SEC      (OTA_KERNEL_MAX / 512u)
#define OTA_MSG_MAX       120
#define OTA_SEHAT_TICKS   6000u    // P7-3: sehat 60 s sejak boot -> dikukuhkan
#define OTA_SAKIT_TICKS   30000u   // P7-3: belum sehat 300 s -> panic

enum { OS_IDLE = 0, OS_LISTEN, OS_RX, OS_CHECK, OS_MARK, OS_WRITE, OS_VERIFY, OS_COMMIT,
       OS_APP };
static const char *const g_os_state_name[] = {
    "diam", "menunggu koneksi 7781", "menerima", "memeriksa", "menandai OTA.BIN",
    "menulis slot", "membaca balik", "mengukuhkan OTA.BIN", "menulis APP.BIN",
};

static uint8_t g_ota_buf[OTA_PREFIX + OTA_KERNEL_MAX] __attribute__((aligned(16)));
static fat32_map_t g_os_slot_map;   // slot tujuan (dipetakan saat `ota terima`)
static fat32_map_t g_os_st_map;     // OTA.BIN
static fat32_map_t g_os_conf_map;   // P7-3: limine.conf (1 sektor), nsec 0 = tidak ada
static int g_os_trial;              // P7-3: kernel ini boot percobaan, belum dikukuhkan
// P7-3: penanda uji. Skrip uji menambal "sehat" -> "panik" di ELF sebelum
// ditandatangani: kernel itu panic tepat setelah keputusan boot percobaan.
// Hanya berarti di image bertanda tangan sah (pemegang kunci bisa
// menandatangani kernel apa pun), jadi juga ada di PROD.
static const volatile char g_ota_uji[] = "P7UJI:sehat";
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
static uint32_t g_os_jenis;         // P7-4: OTA_JENIS_* dari perintah
// P7-4: baca balik APP.BIN memakai ekor g_ota_buf (kiriman app <= APP_FILE_MAX).
_Static_assert(sizeof(g_ota_buf) >= 2 * APP_FILE_MAX, "g_ota_buf muat app + baca balik");
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

// P7-4: tujuan kiriman untuk pesan: "slot X" (kernel) / "APP.BIN".
static const char *os_tujuan(char *buf, uint32_t n)
{
    if (g_os_jenis != OTA_JENIS_KERNEL) {
        return "APP.BIN";
    }
    ksnprintf(buf, n, "slot %c", os_slot_ch(g_os_target));
    return buf;
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

// P7-3: simpan status baru; gagal -> status RAM tetap yang lama.
static int os_st_save(const ota_st_t *n)
{
    ota_st_t old = g_os_st;

    g_os_st = *n;
    if (os_st_write()) {
        return 1;
    }
    g_os_st = old;
    return 0;
}

// P7-3: default_entry limine.conf = slot (0 A, 1 B). 1 berhasil (atau sudah).
static int os_conf_write(int slot)
{
    uint8_t b[512];

    if (g_os_conf_map.nsec != 1 || fat32_map_read(&g_os_conf_map, 0, b) != FAT32_OK) {
        return 0;
    }
    if (ota_conf_default(b, 512) == slot + 1) {
        return 1;
    }
    if (!ota_conf_set(b, 512, slot + 1)) {
        return 0;
    }
    return fat32_map_write(&g_os_conf_map, 0, b) == FAT32_OK;
}

static void os_note(const char *msg)
{
    uint32_t i;

    for (i = 0; msg[i] && i < OTA_MSG_MAX - 1; i++) {
        g_os_last[i] = msg[i];
    }
    g_os_last[i] = 0;
    kprintf("P7: %s\r\n", g_os_last);
}

// P7-3: keputusan boot (dari ota_init, OTA.BIN sah, disk bisa ditulis).
static void os_boot(void)
{
    uint8_t b[512];
    char m[OTA_MSG_MAX];
    int conf = 0, act;
    ota_st_t n = g_os_st;
    char ak = os_slot_ch(g_os_st.aktif);

    if (g_os_conf_map.nsec == 1 && fat32_map_read(&g_os_conf_map, 0, b) == FAT32_OK) {
        conf = ota_conf_default(b, 512);
    }
    act = ota_boot_decide(&n, g_os_run, conf);
    switch (act) {
    case OTA_BOOT_COBA:
        g_os_trial = 1;
        ksnprintf(m, sizeof(m), "boot percobaan slot %c versi %u (sisa %u)%s",
                  os_slot_ch(n.coba), n.s[n.coba].versi, n.sisa,
                  os_st_save(&n) ? "" : " (tulis OTA.BIN gagal)");
        os_note(m);
        if (g_ota_uji[6] == 'p' && g_ota_uji[7] == 'a' && g_ota_uji[8] == 'n' &&
            g_ota_uji[9] == 'i' && g_ota_uji[10] == 'k') {
            panic_msg("P7: uji kernel rusak (penanda P7UJI:panik)");
        }
        break;
    case OTA_BOOT_ROLLBACK: {
        char c = os_slot_ch(g_os_st.coba);

        if (os_st_save(&n) && os_conf_write(n.aktif)) {
            ksnprintf(m, sizeof(m), "rollback: slot %c gagal %u boot percobaan, kembali ke slot %c,"
                      " reboot", c, OTA_COBA_SISA, ak);
            os_note(m);
            machine_reboot();
        }
        ksnprintf(m, sizeof(m), "rollback ke slot %c gagal ditulis, tetap di slot %c", ak, c);
        os_note(m);
        break;
    }
    case OTA_BOOT_BATAL:
        ksnprintf(m, sizeof(m), "percobaan slot %c dibatalkan (slot aktif %c berjalan)%s",
                  os_slot_ch(g_os_st.coba), ak,
                  os_st_save(&n) && os_conf_write(n.aktif) ? "" : " (tulis gagal)");
        os_note(m);
        break;
    case OTA_BOOT_PERBAIKI:
        if (os_conf_write(g_os_st.aktif)) {
            ksnprintf(m, sizeof(m), "limine.conf menunjuk slot %c, bukan aktif %c: diperbaiki, reboot",
                      os_slot_ch(g_os_run), ak);
            os_note(m);
            machine_reboot();
        }
        ksnprintf(m, sizeof(m), "limine.conf menunjuk slot %c, bukan aktif %c: perbaikan gagal",
                  os_slot_ch(g_os_run), ak);
        os_note(m);
        break;
    case OTA_BOOT_MANUAL:
        ksnprintf(m, sizeof(m), "slot %c dipilih manual (aktif %c), tidak diubah",
                  os_slot_ch(g_os_run), ak);
        os_note(m);
        break;
    case OTA_BOOT_ISO_COBA:
        ksnprintf(m, sizeof(m), "boot ISO, percobaan slot %c tertunda (tidak diubah)",
                  os_slot_ch(g_os_st.coba));
        os_note(m);
        break;
    default:
        break;
    }
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
        if (fat32_file_map("LIMINE~1CON", &g_os_conf_map) != FAT32_OK ||
            g_os_conf_map.nsec != 1) {
            g_os_conf_map.nsec = 0;
        }
        if (rc == 1) {
            g_os_st_src = "OTA.BIN";
            g_os_aktif_src = "OTA.BIN";
        } else {
            int d = 0;

            g_os_st_src = rc == 0 ? "kosong" : "rusak";
            if (g_os_conf_map.nsec == 1 && fat32_map_read(&g_os_conf_map, 0, b) == FAT32_OK) {
                d = ota_conf_default(b, 512);
            }
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
        if (rc == 1) {
            if (fat32_writable()) {
                os_boot();
            } else if (g_os_st.coba != OTA_COBA_TIDAK) {
                kprintf("P7: disk baca saja, percobaan slot %c tidak diproses\r\n",
                        os_slot_ch(g_os_st.coba));
            }
        }
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
    if (g_os_inf.jenis != g_os_jenis) {
        os_fail(g_os_jenis == OTA_JENIS_APP ? "isi bukan app" : "isi bukan kernel");
        return;
    }
    if (g_os_jenis == OTA_JENIS_APP) {
        uint32_t v;

        if (app_disk_versi(&v) && g_os_inf.versi <= v) {
            ksnprintf(m, sizeof(m), "versi %u <= versi APP.BIN (%u), ditolak", g_os_inf.versi, v);
            os_fail(m);
            return;
        }
        g_os_state = OS_APP;
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

// P7-3: kukuhkan slot percobaan (sehat atau `ota sah`). 1 berhasil.
static int os_kukuh(const char *why)
{
    ota_st_t n = g_os_st;
    char m[OTA_MSG_MAX];
    int c = n.coba;

    g_os_trial = 0;
    if (c == OTA_COBA_TIDAK) {
        return 0;
    }
    n.aktif = (uint8_t)c;
    n.coba = OTA_COBA_TIDAK;
    n.sisa = 0;
    if (!os_st_save(&n)) {
        ksnprintf(m, sizeof(m), "slot %c gagal dikukuhkan (tulis OTA.BIN)", os_slot_ch(c));
        os_note(m);
        return 0;
    }
    ksnprintf(m, sizeof(m), "slot %c versi %u dikukuhkan (%s)", os_slot_ch(c), n.s[c].versi, why);
    os_note(m);
    return 1;
}

static void os_trial_poll(void)
{
    if (timer_ticks >= OTA_SEHAT_TICKS && g_entropy_ready && (tls_enabled() || g_cli_plain)) {
        os_kukuh("sehat 60 s");
    } else if (timer_ticks >= OTA_SAKIT_TICKS) {
        panic_msg("P7: boot percobaan tidak sehat dalam 300 s");
    }
}

void ota_net_dead(void)
{
    if (g_os_trial) {
        panic_msg("P7: boot percobaan tanpa net task");
    }
}

void ota_poll(void)
{
    uint8_t sec[512];

    if (g_os_trial) {
        os_trial_poll();
    }
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
    case OS_APP: {   // P7-4
        char m[OTA_MSG_MAX], hx[17];
        uint8_t *rb = g_ota_buf + APP_FILE_MAX;
        uint32_t got = 0;
        int wrc = fat32_write_name("APP     BIN", g_ota_buf, g_os_len, 0, &got);
        // Baca balik juga bila tulis melapor galat: galat sesudah entri direktori
        // ditulis (bebaskan rantai lama / FSInfo) berarti isi baru sudah di disk,
        // jadi baseline anti-downgrade harus ikut naik.
        int rrc = fat32_read_name("APP     BIN", rb, APP_FILE_MAX, &got);
        int sama = rrc == FAT32_OK && got == g_os_len && memcmp(rb, g_ota_buf, got) == 0;

        if (sama) {
            app_disk_set(g_os_inf.versi);
        }
        if (wrc == FAT32_ERR_TOOBIG || wrc == FAT32_ERR_NOTFILE) {
            // APP.BIN lama > 4096 byte / beratribut: lapisan tulis FAT32 tidak menyentuhnya.
            ksnprintf(m, sizeof(m), "APP.BIN lama tidak bisa ditimpa (%s), perlu akses disk",
                      fscmd_strerror(wrc));
            os_fail(m);
        } else if (wrc != FAT32_OK) {
            ksnprintf(m, sizeof(m), "tulis APP.BIN gagal (%s)%s", fscmd_strerror(wrc),
                      sama ? "; isi baru sudah di disk, berlaku setelah reboot" : "");
            os_fail(m);
        } else if (!sama) {
            os_fail("baca balik APP.BIN tidak cocok");
        } else {
            os_hex(hx, g_os_inf.sha256, 8);
            ksnprintf(m, sizeof(m), "OK ota: APP.BIN versi %u ukuran %u sha256 %s ditulis + dibaca"
                      " balik; berlaku setelah reboot", g_os_inf.versi, g_os_inf.ukuran, hx);
            os_finish(1, m);
        }
        break;
    }
    default:
        break;
    }
}

// ---- perintah ----
static void os_status(void)
{
    static const char *const st[] = { "tanpa-catatan", "sah", "DITULIS(tidak lengkap)", "gagal" };
    char l[160], hx[17];

    if (!g_os_on) {
        ksnprintf(l, sizeof(l), "ota: mati (%s)\n", g_os_why);
        cmd_puts(l);
        goto terima;   // P7-4: `ota terima app` tetap jalan tanpa slot
    }
    ksnprintf(l, sizeof(l), "ota: berjalan=%s aktif=%c (%s) OTA.BIN=%s seq=%u\n",
              g_os_run < 0 ? "ISO" : g_os_run == 0 ? "A" : "B", os_slot_ch(g_os_st.aktif),
              g_os_aktif_src, g_os_st_src, g_os_st.seq);
    cmd_puts(l);
    if (g_os_st.coba != OTA_COBA_TIDAK) {
        ksnprintf(l, sizeof(l), "coba: slot %c sisa %u%s\n", os_slot_ch(g_os_st.coba), g_os_st.sisa,
                  g_os_trial ? " (berjalan; dikukuhkan setelah sehat 60 s)" : "");
        cmd_puts(l);
    }
    for (int i = 0; i < 2; i++) {
        const ota_slot_t *s = &g_os_st.s[i];

        os_hex(hx, s->sha256, 8);
        ksnprintf(l, sizeof(l), "slot %c: %s versi=%u ukuran=%u sha256=%s\n", os_slot_ch(i),
                  s->status <= OTA_SLOT_GAGAL ? st[s->status] : "?", s->versi, s->ukuran, hx);
        cmd_puts(l);
    }
terima:
    if (g_os_state == OS_LISTEN) {
        uint64_t sisa = g_os_deadline > timer_ticks ? (g_os_deadline - timer_ticks) / 100 : 0;
        char tj[10];

        ksnprintf(l, sizeof(l), "terima: %s dari %u.%u.%u.%u (sisa %lu s) %s\n",
                  g_os_state_name[g_os_state], g_os_ip[0], g_os_ip[1], g_os_ip[2], g_os_ip[3],
                  sisa, os_tujuan(tj, sizeof(tj)));
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
    static const char fmt[] = "ERR: format: ota terima kernel|app <ukuran> <sha16>\n";
    uint32_t i = 0, j, ukuran, jenis;
    uint8_t sha16[8];
    char l[OTA_MSG_MAX];

    if (!g_cmd_src_ip) {
        cmd_puts("ERR: ota terima hanya lewat sesi TCP 7779 / TLS 7780\n");
        return;
    }
    // jenis
    for (j = i; j < n && a[j] != ' '; j++) {
    }
    if (net_cmd_is(a + i, j - i, "kernel")) {
        jenis = OTA_JENIS_KERNEL;
    } else if (net_cmd_is(a + i, j - i, "app")) {
        jenis = OTA_JENIS_APP;   // P7-4
    } else {
        cmd_puts(fmt);
        return;
    }
    if (j >= n) {
        cmd_puts(fmt);
        return;
    }
    if (jenis == OTA_JENIS_KERNEL && !g_os_on) {
        ksnprintf(l, sizeof(l), "ERR: ota mati (%s)\n", g_os_why);
        cmd_puts(l);
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
    if (ukuran <= OTA_PREFIX || ukuran > OTA_PREFIX + ota_max_size(jenis)) {
        ksnprintf(l, sizeof(l), "ERR: ukuran harus %u..%u byte\n", OTA_PREFIX + 1,
                  OTA_PREFIX + ota_max_size(jenis));
        cmd_puts(l);
        return;
    }
    if (g_os_state != OS_IDLE) {
        ksnprintf(l, sizeof(l), "ERR: ota sibuk (%s)\n", g_os_state_name[g_os_state]);
        cmd_puts(l);
        return;
    }
    // P7-4: juga app (lihat komentar atas). g_os_st hanya berarti bila g_os_on.
    if (g_os_on && g_os_st.coba != OTA_COBA_TIDAK) {
        ksnprintf(l, sizeof(l), "ERR: percobaan slot %c tertunda (ota sah / ota batal dulu)\n",
                  os_slot_ch(g_os_st.coba));
        cmd_puts(l);
        return;
    }
    if (jenis == OTA_JENIS_APP) {
        if (!fat32_writable()) {
            cmd_puts("ERR: disk tidak ada / baca saja\n");
            return;
        }
        goto mulai;
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
    g_os_target = target;
mulai:
    for (int k = 0; k < 4; k++) {
        g_os_ip[k] = g_cmd_src_ip[k];
    }
    memcpy(g_os_sha16, sha16, sizeof(sha16));
    g_os_jenis = jenis;
    g_os_len = ukuran;
    g_os_got = 0;
    g_os_deadline = timer_ticks + OTA_LISTEN_TICKS;
    g_os_reply_ready = 0;
    g_os_state = OS_LISTEN;
    g_ota_terima++;

    char tj[10];
    const char *tuj = os_tujuan(tj, sizeof(tj));

    ksnprintf(l, sizeof(l), "OK ota: kirim %u byte ke port %u dalam 60 s (%s)\n",
              ukuran, OTA_PORT, tuj);
    cmd_puts(l);
    kprintf("P7: ota terima %u byte %s dari %u.%u.%u.%u\r\n", ukuran, tuj,
            g_os_ip[0], g_os_ip[1], g_os_ip[2], g_os_ip[3]);
}

// P7-3: `ota coba` (admin): slot bukan-aktif yang sah dan lebih baru dicoba.
static void os_coba(void)
{
    char l[OTA_MSG_MAX];
    ota_st_t n = g_os_st;
    int t = g_os_st.aktif ? 0 : 1;

    if (!g_os_on) {
        ksnprintf(l, sizeof(l), "ERR: ota mati (%s)\n", g_os_why);
        cmd_puts(l);
        return;
    }
    if (g_os_run < 0) {
        cmd_puts("ERR: ota coba butuh boot dari disk (kini berjalan dari ISO)\n");
        return;
    }
    if (g_os_st.coba != OTA_COBA_TIDAK) {
        cmd_puts("ERR: percobaan sudah berjalan / tertunda (ota sah / ota batal)\n");
        return;
    }
    if (g_os_run != g_os_st.aktif) {
        cmd_puts("ERR: slot berjalan bukan slot aktif\n");
        return;
    }
    if (g_os_state != OS_IDLE) {
        ksnprintf(l, sizeof(l), "ERR: ota sibuk (%s)\n", g_os_state_name[g_os_state]);
        cmd_puts(l);
        return;
    }
    if (!fat32_writable() || g_os_conf_map.nsec != 1) {
        cmd_puts("ERR: disk baca saja / limine.conf tidak ada\n");
        return;
    }
    if (g_os_st.s[t].status != OTA_SLOT_SAH) {
        ksnprintf(l, sizeof(l), "ERR: slot %c tidak berstatus sah\n", os_slot_ch(t));
        cmd_puts(l);
        return;
    }
    if (g_os_st.s[t].versi <= g_os_st.s[g_os_st.aktif].versi) {
        ksnprintf(l, sizeof(l), "ERR: versi slot %c (%u) <= versi slot aktif (%u)\n", os_slot_ch(t),
                  g_os_st.s[t].versi, g_os_st.s[g_os_st.aktif].versi);
        cmd_puts(l);
        return;
    }
    n.coba = (uint8_t)t;
    n.sisa = OTA_COBA_SISA;
    if (!os_st_save(&n)) {
        cmd_puts("ERR: tulis OTA.BIN gagal\n");
        return;
    }
    if (!os_conf_write(t)) {
        n.coba = OTA_COBA_TIDAK;
        n.sisa = 0;
        os_st_save(&n);
        cmd_puts("ERR: tulis limine.conf gagal (percobaan dibatalkan)\n");
        return;
    }
    ksnprintf(l, sizeof(l), "OK ota: coba slot %c versi %u, %u boot percobaan; reboot\n",
              os_slot_ch(t), g_os_st.s[t].versi, OTA_COBA_SISA);
    cmd_puts(l);
    l[strlen(l) - 1] = 0;
    os_note(l + 8);
    auth_reboot_request();
}

static void os_sah(void)
{
    char l[OTA_MSG_MAX];
    int c = g_os_st.coba;

    if (!g_os_trial) {
        cmd_puts("ERR: tidak ada boot percobaan yang berjalan\n");
        return;
    }
    if (!os_kukuh("ota sah")) {
        cmd_puts("ERR: tulis OTA.BIN gagal\n");
        return;
    }
    ksnprintf(l, sizeof(l), "OK ota: slot %c dikukuhkan\n", os_slot_ch(c));
    cmd_puts(l);
}

static void os_batal(void)
{
    char l[OTA_MSG_MAX];
    ota_st_t n = g_os_st;
    int c = g_os_st.coba, reboot = g_os_trial;

    if (c == OTA_COBA_TIDAK) {
        cmd_puts("ERR: tidak ada percobaan\n");
        return;
    }
    if (!fat32_writable()) {
        cmd_puts("ERR: disk baca saja\n");
        return;
    }
    n.coba = OTA_COBA_TIDAK;
    n.sisa = 0;
    if (!os_st_save(&n)) {
        cmd_puts("ERR: tulis OTA.BIN gagal\n");
        return;
    }
    g_os_trial = 0;
    // limine.conf gagal ditulis: boot berikut (slot coba, tanpa coba) diperbaiki
    // ota_boot_decide (PERBAIKI).
    ksnprintf(l, sizeof(l), "OK ota: percobaan slot %c dibatalkan, slot aktif %c%s%s\n",
              os_slot_ch(c), os_slot_ch(n.aktif),
              os_conf_write(n.aktif) ? "" : " (limine.conf gagal ditulis)",
              reboot ? "; reboot" : "");
    cmd_puts(l);
    l[strlen(l) - 1] = 0;
    os_note(l + 8);
    if (reboot) {
        auth_reboot_request();
    }
}

int ota_execute(const volatile uint8_t *cmd, uint32_t len)
{
    if (net_cmd_is(cmd, len, "ota")) {
        os_status();
        return 1;
    }
    if (net_cmd_is(cmd, len, "ota coba")) {
        os_coba();
        return 1;
    }
    if (net_cmd_is(cmd, len, "ota sah")) {
        os_sah();
        return 1;
    }
    if (net_cmd_is(cmd, len, "ota batal")) {
        os_batal();
        return 1;
    }
    if (len > 11 && net_cmd_is(cmd, 11, "ota terima ")) {
        os_terima(cmd + 11, len - 11);
        return 1;
    }
    if (len > 4 && net_cmd_is(cmd, 4, "ota ")) {
        cmd_puts("ERR: format: ota | ota terima kernel|app <ukuran> <sha16> | ota coba|sah|batal\n");
        return 1;
    }
    return 0;
}

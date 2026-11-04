#include "kernel.h"

// ---- P5-4: program user dari disk (APP.BIN) ----
// Satu program datar (biner x86-64, dimuat di 0x400000 seperti program yang
// ditanam) dibaca dari root FAT32 sekali saat boot, setelah net task dan
// idle dibuat (nomor slot task lain tidak bergeser). PROD dan dev sama.
// Isi harus muat satu halaman kode spawn() (batas P7-4 di bawah); slot task harus
// tersisa. Gagal apa pun -> program tidak dijalankan, sistem tetap jalan
// (gagal tertutup). Tidak di-restart bila keluar atau crash (R6).
// APP.BIN dilindungi fscmd (tidak bisa dibaca/ditulis lewat perintah fs).
//
// P7-4: APP.BIN = file .bmo bertanda tangan (kernel/ota.c, jenis app), dev
// dan PROD sama; kunci = kunci OTA build ini (dev: kunci uji, PROD: kunci
// asli). File mentah, tanda tangan salah, sha256 isi salah, atau jenis
// kernel -> ditolak (satu baris serial), program tidak dijalankan. Yang
// dijalankan hanya isi (sesudah header + tanda tangan). Batas: file <= 4096
// byte (FAT32_WRITE_MAX), jadi isi <= 3968 (OTA_APP_MAX). Diganti lewat
// `ota terima app` (otaslot.c, anti-downgrade terhadap versi APP.BIN sah di
// disk), berlaku setelah reboot.

static uint8_t g_app_buf[APP_FILE_MAX] __attribute__((aligned(16)));
static uint8_t g_app_hash[32];    // sha256 isi (dari header yang sah)
static int g_app_rc;              // APP_* di bawah
static const char *g_app_why = "";
static int g_app_disk_ok;         // P7-4: APP.BIN di disk bertanda tangan sah
static uint32_t g_app_disk_v;     // versinya (atau versi tulisan OTA terakhir)
static int g_app_baru;            // P7-4: ditulis OTA sejak boot ini

uint64_t g_app_loaded;   // metrics app_loaded (0/1)
uint64_t g_app_size;     // metrics app_size (byte isi, 0 bila tidak dimuat)
uint64_t g_app_exit;     // metrics app_exit (1 = task sudah berhenti)
uint64_t g_app_versi;    // metrics app_versi (P7-4, 0 bila tidak dimuat)
int64_t g_app_slot = -1;

enum { APP_NONE, APP_NODISK, APP_REJECT, APP_OK };

static void app_hex(char *out, const uint8_t *h)
{
    static const char d[] = "0123456789abcdef";

    for (int i = 0; i < 32; i++) {
        out[2 * i] = d[h[i] >> 4];
        out[2 * i + 1] = d[h[i] & 15];
    }
    out[64] = 0;
}

void app_load(void)
{
    uint32_t size = 0;
    ota_info_t inf;
    int rc = fat32_read_name("APP     BIN", g_app_buf, APP_FILE_MAX, &size);

    if (rc == FAT32_ERR_NOVOL) {
        g_app_rc = APP_NODISK;
        kprintf("P5-4: APP.BIN tidak ada (tanpa disk)\r\n");
        return;
    }
    if (rc == FAT32_ERR_NOENT) {
        g_app_rc = APP_NONE;
        kprintf("P5-4: APP.BIN tidak ada\r\n");
        return;
    }
    g_app_rc = APP_REJECT;
    if (rc == FAT32_ERR_TOOBIG) {
        g_app_why = "lebih dari 4096 byte";   // APP_FILE_MAX = FAT32_WRITE_MAX
    } else if (rc != FAT32_OK) {
        g_app_why = fscmd_strerror(rc);
    } else if (size == 0) {
        g_app_why = "kosong";
    } else if ((rc = ota_check(g_app_buf, size, ota_pubkey(), &inf)) != OTA_OK) {
        // FORMAT = terlalu pendek / magic / cadangan salah: mis. biner mentah P5-4.
        g_app_why = rc == OTA_ERR_FORMAT ? "bukan .bmo bertanda tangan" : ota_strerror(rc);
    } else if (inf.jenis != OTA_JENIS_APP) {
        g_app_why = "isi bukan app";
    } else {
        g_app_disk_ok = 1;
        g_app_disk_v = inf.versi;
        if (task_count >= MAX_TASKS) {
            g_app_why = "slot task penuh";
        } else {
            g_app_rc = APP_OK;
        }
    }
    if (g_app_rc != APP_OK) {
        kprintf("P5-4: APP.BIN ditolak (%s)\r\n", g_app_why);
        return;
    }

    char hex[65];

    memcpy(g_app_hash, inf.sha256, 32);
    app_hex(hex, g_app_hash);

    g_app_slot = (int64_t)task_count;
    g_app_size = inf.ukuran;
    g_app_versi = inf.versi;
    g_app_loaded = 1;
    kprintf("P5-4: APP.BIN dimuat %u byte versi %u sha256=%s slot %u\r\n",
            inf.ukuran, inf.versi, hex, (uint32_t)g_app_slot);
    spawn(g_app_buf + OTA_PREFIX, inf.ukuran);
}

int app_disk_versi(uint32_t *versi)
{
    *versi = g_app_disk_v;
    return g_app_disk_ok;
}

void app_disk_set(uint32_t versi)
{
    g_app_disk_ok = 1;
    g_app_disk_v = versi;
    g_app_baru = 1;
}

// Dipanggil task_exit() (juga jalur R6 crash program user).
void app_task_exited(size_t slot)
{
    if (g_app_loaded && (int64_t)slot == g_app_slot) {
        g_app_exit = 1;
    }
}

// Perintah `app` (ro boleh): satu baris status.
void app_status(void (*out)(const char *))
{
    char hex[65];
    char b[160];

    switch (g_app_rc) {
    case APP_NODISK:
        out("app: tidak ada (tanpa disk)\n");
        break;
    case APP_NONE:
        out("app: tidak ada\n");
        break;
    case APP_REJECT:
        ksnprintf(b, sizeof(b), "app: ditolak (%s)\n", g_app_why);
        out(b);
        break;
    default:
        app_hex(hex, g_app_hash);
        ksnprintf(b, sizeof(b), "app: dimuat %lu byte versi %lu slot %ld %s\nsha256=%s\n",
                  g_app_size, g_app_versi, g_app_slot, g_app_exit ? "berhenti" : "jalan", hex);
        out(b);
        break;
    }
    if (g_app_baru) {
        ksnprintf(b, sizeof(b), "baru: APP.BIN versi %u ditulis OTA, berlaku setelah reboot\n",
                  g_app_disk_v);
        out(b);
    }
}

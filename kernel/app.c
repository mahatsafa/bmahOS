#include "kernel.h"

// ---- P5-4: program user dari disk (APP.BIN) ----
// Satu program datar (biner x86-64, dimuat di 0x400000 seperti program yang
// ditanam) dibaca dari root FAT32 sekali saat boot, setelah net task dan
// idle dibuat (nomor slot task lain tidak bergeser). PROD dan dev sama.
// Batas: 1..APP_MAX byte (= satu halaman kode spawn()); slot task harus
// tersisa. Gagal apa pun -> program tidak dijalankan, sistem tetap jalan
// (gagal tertutup). Tidak di-restart bila keluar atau crash (R6).
// APP.BIN dilindungi fscmd (tidak bisa dibaca/ditulis lewat perintah fs),
// jadi menggantinya butuh akses fisik ke disk, sama seperti KEY.TXT.

static uint8_t g_app_buf[APP_MAX];
static uint8_t g_app_hash[32];
static int g_app_rc;              // APP_* di bawah
static const char *g_app_why = "";

uint64_t g_app_loaded;   // metrics app_loaded (0/1)
uint64_t g_app_size;     // metrics app_size (byte, 0 bila tidak dimuat)
uint64_t g_app_exit;     // metrics app_exit (1 = task sudah berhenti)
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
    int rc = fat32_read_name("APP     BIN", g_app_buf, APP_MAX, &size);

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
        g_app_why = "lebih dari 4096 byte";
    } else if (rc != FAT32_OK) {
        g_app_why = fscmd_strerror(rc);
    } else if (size == 0) {
        g_app_why = "kosong";
    } else if (task_count >= MAX_TASKS) {
        g_app_why = "slot task penuh";
    } else {
        g_app_rc = APP_OK;
    }
    if (g_app_rc != APP_OK) {
        kprintf("P5-4: APP.BIN ditolak (%s)\r\n", g_app_why);
        return;
    }

    sha256_ctx_t c;
    char hex[65];

    sha256_init(&c);
    sha256_update(&c, g_app_buf, size);
    sha256_final(&c, g_app_hash);
    app_hex(hex, g_app_hash);

    g_app_slot = (int64_t)task_count;
    g_app_size = size;
    g_app_loaded = 1;
    kprintf("P5-4: APP.BIN dimuat %u byte sha256=%s slot %u\r\n",
            size, hex, (uint32_t)g_app_slot);
    spawn(g_app_buf, size);
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
        return;
    case APP_NONE:
        out("app: tidak ada\n");
        return;
    case APP_REJECT:
        ksnprintf(b, sizeof(b), "app: ditolak (%s)\n", g_app_why);
        out(b);
        return;
    default:
        break;
    }
    app_hex(hex, g_app_hash);
    ksnprintf(b, sizeof(b), "app: dimuat %lu byte slot %ld %s\nsha256=%s\n",
              g_app_size, g_app_slot, g_app_exit ? "berhenti" : "jalan", hex);
    out(b);
}

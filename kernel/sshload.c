#include "kernel.h"
#include "ssh.h"

// F7 SSH-1b: kunci host SSH (SSHKEY.DER, P-256 SEC1/PKCS#8 DER) dari root FAT32,
// status perintah `ssh`, dan counter port 22. Pola sama dengan tls_load (tls.c).

#define SSH_KEY_MAX 512

uint64_t g_ssh_conn = 0;         // koneksi port 22 ESTABLISHED dan sesi SSH terbuka
uint64_t g_ssh_kex_ok = 0;       // NEWKEYS klien diterima (kex selesai)
uint64_t g_ssh_fail = 0;         // sesi ditutup karena protokol/kex/batas waktu
uint64_t g_ssh_full = 0;         // SYN ditolak: sesi port 22 penuh
uint64_t g_ssh_noentropy = 0;    // SYN dibuang/RST: entropi belum cukup
uint64_t g_ssh_auth_fail = 0;    // 4 percobaan, atau klien pergi saat userauth
uint64_t g_ssh_login = 0;        // F7 SSH-2: USERAUTH_SUCCESS
uint64_t g_ssh_cmd = 0;          // perintah exec/shell dijalankan (termasuk ditolak peran)
uint64_t g_ssh_idle = 0;         // sesi login ditutup karena cli_idle

static const char *g_ssh_why_off = "belum dimuat";
static uint8_t g_ssh_ld[SSH_KEY_MAX];
// F7 SSH-2: SSHADM.PUB / SSHRO.PUB (authorized_keys, maks 4 kunci x ~200 byte + komentar)
#define SSH_PUB_MAX 2048
static uint8_t g_ssh_pub[SSH_PUB_MAX];

static int ssh_load_pub(const char *name83, int role)
{
    uint32_t size = 0;
    int rc = fat32_read_name(name83, g_ssh_pub, sizeof(g_ssh_pub), &size);
    int n = 0;

    if (rc == FAT32_OK && size > 0) {
        n = ssh_set_authkeys(role, g_ssh_pub, size);
    } else {
        (void)ssh_set_authkeys(role, g_ssh_pub, 0);
    }
    memset(g_ssh_pub, 0, sizeof(g_ssh_pub));
    return n;
}

void ssh_load(void)
{
    char line[160];
    uint32_t size = 0;
    int rc = fat32_read_name("SSHKEY  DER", g_ssh_ld, sizeof(g_ssh_ld), &size);

    ssh_unload_key();
    if (rc == FAT32_ERR_NOENT || rc == FAT32_ERR_NOVOL) {
        g_ssh_why_off = "SSHKEY.DER tidak ada";
    } else if (rc != FAT32_OK || size == 0) {
        g_ssh_why_off = "SSHKEY.DER gagal dibaca/terlalu besar";
    } else if (!ssh_load_key(g_ssh_ld, size)) {
        g_ssh_why_off = "SSHKEY.DER bukan kunci EC P-256 (DER)";
    } else {
        g_ssh_why_off = "";
    }
    memset(g_ssh_ld, 0, sizeof(g_ssh_ld));   // DER dinolkan setelah dipakai
    if (ssh_key_loaded()) {
        ksnprintf(line, sizeof(line), "SSH: aktif port 22 fp=%s\r\n", ssh_fingerprint());
    } else {
        ksnprintf(line, sizeof(line), "SSH: nonaktif (%s)\r\n", g_ssh_why_off);
    }
    serial_write(line);
    // F7 SSH-2: kunci pengguna (tanpa kunci: semua userauth ditolak, port tetap buka)
    net_ssh_install();
    int na = ssh_load_pub("SSHADM  PUB", SSH_ROLE_ADMIN);
    int nr = ssh_load_pub("SSHRO   PUB", SSH_ROLE_RO);

    // DECISIONS 2026-11-24: kunci yang ada di kedua file -> SSHRO.PUB ditolak seluruhnya
    // (seperti KEY.TXT == KEYRO.TXT di D4), admin tetap jalan.
    if (nr > 0 && ssh_authkey_dup() > 0) {
        ksnprintf(line, sizeof(line), "SSH: SSHRO.PUB ditolak: %d kunci sama dengan SSHADM.PUB\r\n",
                  ssh_authkey_dup());
        serial_write(line);
        (void)ssh_set_authkeys(SSH_ROLE_RO, g_ssh_pub, 0);
        nr = 0;
    }
    ksnprintf(line, sizeof(line), "SSH: kunci pengguna admin=%d ro=%d\r\n", na, nr);
    serial_write(line);
}

int ssh_enabled(void)
{
    return ssh_key_loaded();
}

// Perintah `ssh` (cmd.c): status, fingerprint, sesi, counter.
void ssh_status(void)
{
    char b[220];

    if (ssh_key_loaded()) {
        ksnprintf(b, sizeof(b), "ssh: aktif port 22\nfp: %s\n", ssh_fingerprint());
    } else {
        ksnprintf(b, sizeof(b), "ssh: nonaktif (%s)\n", g_ssh_why_off);
    }
    cmd_puts(b);
    ksnprintf(b, sizeof(b), "sesi: aktif=%d maks=%d konek=%lu kex_ok=%lu gagal=%lu "
              "penuh=%lu tanpa_entropi=%lu auth_gagal=%lu\n", net_tcp_ssh_active(),
              SSH_MAX_SESS, g_ssh_conn, g_ssh_kex_ok, g_ssh_fail, g_ssh_full,
              g_ssh_noentropy, g_ssh_auth_fail);
    cmd_puts(b);
    ksnprintf(b, sizeof(b), "login: ok=%lu perintah=%lu idle=%lu kunci_admin=%d kunci_ro=%d\n",
              g_ssh_login, g_ssh_cmd, g_ssh_idle, ssh_authkey_count(SSH_ROLE_ADMIN),
              ssh_authkey_count(SSH_ROLE_RO));
    cmd_puts(b);
}

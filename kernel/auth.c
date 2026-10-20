#include "kernel.h"

// ---- Net-11b: kunci autentikasi dari disk FAT32 (KEY.TXT) ----
static uint8_t g_auth_key[64];
static uint32_t g_auth_key_len = 0;
// D4: kunci peran read-only (KEYRO.TXT, opsional, hanya shell TCP 7779).
static uint8_t g_auth_ro_key[64];
static uint32_t g_auth_ro_key_len = 0;
uint64_t g_cli_role_denied = 0;   // D4: perintah di luar daftar read-only ditolak
static uint64_t g_auth_last_counter = 0;

// D4: KEYRO.TXT = kunci peran read-only shell TCP. Hanya dimuat bila kunci
// admin sudah ada; aturan panjang sama (16..64 byte, spasi/CR/LF/NUL di
// akhir dibuang). Isi sama dengan kunci admin ditolak (peran tidak bisa
// dibedakan). Tidak ada/tidak valid -> peran read-only nonaktif.
static void auth_load_ro_key(void)
{
    uint32_t cluster = 0;
    uint32_t size = 0;

    (void)fat32_find_file("KEYRO   TXT", &cluster, &size);
    if (cluster < 2 || size == 0 || size > 512) {
        serial_write("D4: KEYRO.TXT tidak ada, peran read-only nonaktif\r\n");
        return;
    }

    uint8_t *k = fat32_load_file(cluster, size);
    uint32_t n = size;

    if (k == 0) {
        serial_write("D4: gagal memuat KEYRO.TXT, peran read-only nonaktif\r\n");
        return;
    }
    while (n > 0 && (k[n - 1] == '\n' || k[n - 1] == '\r' ||
                     k[n - 1] == ' '  || k[n - 1] == 0)) {
        n--;
    }
    if (n < 16 || n > sizeof(g_auth_ro_key)) {
        serial_write("D4: panjang KEYRO.TXT harus 16..64 byte, peran read-only nonaktif\r\n");
        return;
    }
    if (n == g_auth_key_len && ct_memeq(k, g_auth_key, n)) {
        serial_write("D4: KEYRO.TXT sama dengan kunci admin, peran read-only nonaktif\r\n");
        return;
    }
    for (uint32_t i = 0; i < n; i++) {
        g_auth_ro_key[i] = k[i];
    }
    g_auth_ro_key_len = n;
    serial_write("D4: kunci read-only dimuat, panjang=");
    serial_write_hex((uint64_t)n);
    serial_write("\r\n");
}

void auth_load_key(void)
{
    if (!g_crypto_ok) {
        serial_write("Net-11: kripto tidak lulus self-test, auth tidak aktif\r\n");
        return;
    }

    uint32_t cluster = 0;
    uint32_t size = 0;

    // Return value tidak dipakai untuk memutuskan: konvensinya belum
    // dipastikan. Yang dipercaya adalah output cluster/size (diinit 0).
    int rc = fat32_find_file("KEY     TXT", &cluster, &size);

    serial_write("Net-11: cari KEY.TXT rc=");
    serial_write_hex((uint64_t)(uint32_t)rc);
    serial_write(" cluster=");
    serial_write_hex((uint64_t)cluster);
    serial_write(" size=");
    serial_write_hex((uint64_t)size);
    serial_write("\r\n");

    if (cluster < 2 || size == 0 || size > 512) {
        serial_write("Net-11: KEY.TXT tidak ada/tidak valid, semua perintah ditolak\r\n");
        return;
    }

    uint8_t *k = fat32_load_file(cluster, size);

    if (k == 0) {
        serial_write("Net-11: gagal memuat KEY.TXT, semua perintah ditolak\r\n");
        return;
    }

    uint32_t n = size;

    while (n > 0 && (k[n - 1] == '\n' || k[n - 1] == '\r' ||
                     k[n - 1] == ' '  || k[n - 1] == 0)) {
        n--;
    }

    if (n < 16 || n > sizeof(g_auth_key)) {
        serial_write("Net-11: panjang kunci harus 16..64 byte, semua perintah ditolak\r\n");
        return;
    }

    for (uint32_t i = 0; i < n; i++) {
        g_auth_key[i] = k[i];
    }

    g_auth_key_len = n;

    serial_write("Net-11: kunci dimuat, panjang=");
    serial_write_hex((uint64_t)n);
    serial_write("\r\n");
    auth_load_ro_key();
}

static int auth_hexval(uint8_t c)
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

// Format: "<counter> <perintah> <hmac-hex-64>".
// Return: 0 OK, 1 auth nonaktif, 2 format salah, 3 HMAC salah, 4 replay.
static int auth_verify(volatile uint8_t *d, uint32_t len,
                       volatile uint8_t **cmd_out, uint32_t *cmd_len_out,
                       uint64_t *counter_out)
{
    if (g_auth_key_len == 0) {
        return 1;
    }

    // minimum: counter(1) + spasi + perintah(1) + spasi + hmac(64)
    if (len < 68) {
        return 2;
    }

    uint32_t sp = len;

    while (sp > 0 && d[sp - 1] != ' ') {
        sp--;
    }

    if (sp == 0 || len - sp != 64) {
        return 2;
    }

    uint32_t msg_len = sp - 1;

    if (msg_len == 0 || msg_len > 200) {
        return 2;
    }

    uint32_t fs = 0;

    while (fs < msg_len && d[fs] != ' ') {
        fs++;
    }

    if (fs == 0 || fs > 19 || fs + 1 >= msg_len) {
        return 2;
    }

    uint64_t counter = 0;

    for (uint32_t i = 0; i < fs; i++) {
        if (d[i] < '0' || d[i] > '9') {
            return 2;
        }
        counter = counter * 10 + (uint64_t)(d[i] - '0');
    }

    uint8_t rx[32];

    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(d[sp + i * 2]);
        int lo = auth_hexval(d[sp + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t m[200];

    for (uint32_t i = 0; i < msg_len; i++) {
        m[i] = d[i];
    }

    uint8_t mac[32];
    hmac_sha256(g_auth_key, g_auth_key_len, m, msg_len, mac);

    if (!ct_memeq(mac, rx, 32)) {
        return 3;
    }

    if (counter <= g_auth_last_counter) {
        return 4;
    }

    g_auth_last_counter = counter;
    *cmd_out = d + fs + 1;
    *cmd_len_out = msg_len - fs - 1;
    *counter_out = counter;

    return 0;
}

// ---- Net-18A: challenge-response nonce untuk perintah berprivilege ----
// Klien kirim "CHAL" -> server balas nonce 32 hex (16 byte), sekali pakai,
// TTL 5 detik. Perintah: "<nonce32hex> <perintah> <hmac-hex64>", hmac atas
// "<nonce> <perintah>". Menutup replay setelah reboot (counter lama di RAM).
// Hanya dipanggil dari net task, jadi tidak perlu lock.
#define PRIV_NONCE_SLOTS 16
#define PRIV_NONCE_PER_IP 4   // M1: slot hidup maks per IP sumber
#define PRIV_NONCE_TTL   500

typedef struct {
    uint8_t nonce[16];
    uint64_t issued;
    uint8_t ip[4];
    int in_use;
} priv_nonce_t;

static priv_nonce_t g_priv_nonces[PRIV_NONCE_SLOTS];
// M1: slot kosong/kedaluwarsa dipakai dulu. IP yang sudah punya
// PRIV_NONCE_PER_IP nonce hidup hanya mengganti nonce miliknya sendiri yang
// tertua, jadi banjir CHAL satu IP tidak menggusur nonce IP lain.
// Tabel penuh oleh banyak IP berbeda: ganti yang tertua (batas diketahui).

static uint32_t priv_nonce_issue(const volatile uint8_t *ip, const uint8_t nonce[16])
{
    uint32_t slot = 0;
    int found = 0;
    uint32_t mine = 0;
    int mine_old = -1;

    for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
        priv_nonce_t *e = &g_priv_nonces[i];

        if (e->in_use && timer_ticks - e->issued > PRIV_NONCE_TTL) {
            e->in_use = 0;
        }

        if (e->in_use && e->ip[0] == ip[0] && e->ip[1] == ip[1] &&
            e->ip[2] == ip[2] && e->ip[3] == ip[3]) {
            mine++;
            if (mine_old < 0 || e->issued < g_priv_nonces[mine_old].issued) {
                mine_old = (int)i;
            }
        }
    }

    if (mine >= PRIV_NONCE_PER_IP) {
        slot = (uint32_t)mine_old;
        g_chal_ip_recycled++;
    } else {
        for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
            if (!g_priv_nonces[i].in_use) {
                slot = i;
                found = 1;
                break;
            }
        }

        if (!found) {
            for (uint32_t i = 1; i < PRIV_NONCE_SLOTS; i++) {
                if (g_priv_nonces[i].issued < g_priv_nonces[slot].issued) {
                    slot = i;
                }
            }
        }
    }

    for (int i = 0; i < 4; i++) {
        g_priv_nonces[slot].ip[i] = ip[i];
    }

    for (int i = 0; i < 16; i++) {
        g_priv_nonces[slot].nonce[i] = nonce[i];
    }
    g_priv_nonces[slot].issued = timer_ticks;
    g_priv_nonces[slot].in_use = 1;

    return slot;
}

// Format: "<nonce32hex> <perintah> <hmac-hex64>".
// Return: 0 OK, 1 nonaktif, 2 format, 3 nonce tak dikenal/dipakai,
// 4 kedaluwarsa, 5 hmac salah. Nonce dicari sebelum HMAC (murah dulu),
// dan slot dibebaskan HANYA setelah HMAC valid.
static int priv_verify(volatile uint8_t *d, uint32_t len,
                       volatile uint8_t **cmd_out, uint32_t *cmd_len_out)
{
    if (g_auth_key_len == 0) {
        return 1;
    }

    // minimum: nonce(32) + spasi + perintah(1) + spasi + hmac(64)
    if (len < 99) {
        return 2;
    }

    uint32_t sp = len;

    while (sp > 0 && d[sp - 1] != ' ') {
        sp--;
    }

    if (sp == 0 || len - sp != 64) {
        return 2;
    }

    uint32_t msg_len = sp - 1;

    if (msg_len < 34 || msg_len > 200 || d[32] != ' ') {
        return 2;
    }

    uint8_t nonce[16];

    for (uint32_t i = 0; i < 16; i++) {
        int hi = auth_hexval(d[i * 2]);
        int lo = auth_hexval(d[i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        nonce[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t rx[32];

    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(d[sp + i * 2]);
        int lo = auth_hexval(d[sp + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }

        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    // F1.9: semua slot dibandingkan (tanpa break), jadi waktu tidak
    // bergantung pada posisi atau isi nonce yang cocok.
    int slot = -1;

    for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
        int eq = ct_memeq(g_priv_nonces[i].nonce, nonce, 16);

        if (eq && g_priv_nonces[i].in_use && slot < 0) {
            slot = (int)i;
        }
    }

    if (slot < 0) {
        return 3;
    }

    if (timer_ticks - g_priv_nonces[slot].issued > PRIV_NONCE_TTL) {
        return 4;
    }

    uint8_t m[200];

    for (uint32_t i = 0; i < msg_len; i++) {
        m[i] = d[i];
    }

    uint8_t mac[32];
    hmac_sha256(g_auth_key, g_auth_key_len, m, msg_len, mac);

    if (!ct_memeq(mac, rx, 32)) {
        return 5;
    }

    g_priv_nonces[slot].in_use = 0;
    *cmd_out = d + 33;
    *cmd_len_out = msg_len - 33;

    return 0;
}

// ---- Net-18B: reboot berprivilege ----
// Dipanggil SETELAH balasan terkirim. Urutan reboot ada di machine_reboot()
// (acpi.c, R1-1).
static int g_priv_reboot_pending = 0;

static void priv_do_reboot(void)
{
    machine_reboot();
}

static void priv_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;

    if (net_cmd_is(cmd, len, "pping")) {
        cmd_puts("ppong\n");
    } else if (net_cmd_is(cmd, len, "reboot")) {
        cmd_puts("reboot: dimulai\n");
        g_priv_reboot_pending = 1;
    } else if (net_cmd_is(cmd, len, "audit")) {
        audit_dump(0);   // D5: hanya admin (tidak di g_ro_cmds)
    } else if (net_cmd_is(cmd, len, "audit gagal")) {
        audit_dump(1);
#ifndef BMAHOS_PROD
    } else if (panic_test_execute(cmd, len)) {
        // R1: panic pf|df|ud|assert (admin; tidak di g_ro_cmds; build dev saja)
    } else if (wd_test_execute(cmd, len)) {
        // R5: wdtest loop|blok (admin; build dev saja)
#endif
    } else if (config_execute(cmd, len)) {
        // D7: config (juga read-only) / set (admin)
    } else if (fscmd_execute(cmd, len)) {
        // D6: ls/baca/tulis/tambah (admin; tidak di g_ro_cmds)
    } else {
        // B2: perintah baca juga boleh lewat jalur nonce.
        net_cmd_execute(cmd, len);
    }
}

// Return 1 jika datagram adalah CHAL atau berformat nonce (balasan sudah
// diisi di g_cmd_out), 0 jika harus lewat jalur counter lama.
// D5: perintah sah dan yang ditolak (kecuali CHAL) dicatat di audit log.
static int priv_try_handle(volatile uint8_t *cmd, uint32_t len,
                           const volatile uint8_t *src_ip, uint16_t src_port)
{
    if (net_cmd_is(cmd, len, "CHAL")) {
        g_cmd_len = 0;

        if (g_auth_key_len == 0) {
            g_priv_denied[1]++;
            cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
            return 1;
        }

        // F1.8: nonce dari DRBG; sebelum entropi cukup, tolak tanpa
        // menyentuh tabel (slot klien lain tidak digusur).
        uint8_t nonce[16];

        if (!entropy_get(nonce, sizeof(nonce))) {
            g_chal_noentropy++;
            cmd_puts("ERR: entropi belum cukup, coba lagi\n");
            return 1;
        }

        uint32_t slot = priv_nonce_issue(src_ip, nonce);
        g_chal_issued++;

        cmd_puts("nonce: ");
        for (int i = 0; i < 16; i++) {
            static const char hx[] = "0123456789abcdef";
            cmd_putc(hx[g_priv_nonces[slot].nonce[i] >> 4]);
            cmd_putc(hx[g_priv_nonces[slot].nonce[i] & 0xF]);
        }
        cmd_putc('\n');

        uint64_t lf = irq_save();
        serial_write("Net-18: CHAL nonce dikeluarkan slot=");
        serial_write_hex((uint64_t)slot);
        serial_write("\r\n");
        irq_restore(lf);
        return 1;
    }

    uint32_t fs = 0;

    while (fs < len && cmd[fs] != ' ') {
        fs++;
    }

    if (fs != 32) {
        return 0;
    }

    volatile uint8_t *pc = 0;
    uint32_t pcl = 0;
    int prc = priv_verify(cmd, len, &pc, &pcl);

    uint64_t lf = irq_save();
    if (prc == 0) {
        serial_write("Net-18: priv OK\r\n");
    } else {
        serial_write("Net-18: priv DITOLAK kode=");
        serial_write_hex((uint64_t)prc);
        serial_write("\r\n");
    }
    irq_restore(lf);

    if (prc == 0) {
        g_priv_ok++;
        // D9: udp_admin=0: balasan UDP teks polos, jadi hanya perintah daftar
        // baca (g_ro_cmds); sisanya lewat TLS 7780.
        if (!g_udp_admin && !auth_cmd_allowed(AUTH_ROLE_RO, (const uint8_t *)pc, pcl)) {
            audit_record(AUDIT_CMD_ROLE, AUDIT_UDP, src_ip, src_port, AUTH_ROLE_ADMIN, 0,
                         pc, pcl);
            g_cmd_len = 0;
            cmd_puts("ERR: udp_admin=0: hanya perintah baca lewat UDP (pakai TLS 7780)\n");
            return 1;
        }
        audit_record(AUDIT_CMD, AUDIT_UDP, src_ip, src_port, AUTH_ROLE_ADMIN, 0,
                     pc, pcl);
        priv_cmd_execute(pc, pcl);
        return 1;
    }

    g_priv_denied[prc]++;
    audit_record(AUDIT_CMD_FAIL, AUDIT_UDP, src_ip, src_port, AUTH_ROLE_NONE, prc,
                 0, 0);
    g_cmd_len = 0;

    if (prc == 1) {
        cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
    } else if (prc == 2) {
        cmd_puts("ERR: format: <nonce32hex> <perintah> <hmac-hex64>\n");
    } else if (prc == 3) {
        cmd_puts("ERR: nonce tidak dikenal atau sudah dipakai\n");
    } else if (prc == 4) {
        cmd_puts("ERR: nonce kedaluwarsa (minta CHAL baru)\n");
    } else {
        cmd_puts("ERR: hmac salah\n");
    }

    return 1;
}

// ---- D1: login TCP port 7779 ----
// Baris "login <hmac-hex64>", hmac = HMAC-SHA256(kunci, "<nonce32hex> tcp-login").
// Nonce milik satu koneksi (net.c, dibuat saat SYN); pesan berbeda dari
// perintah UDP dan nonce tidak ada di tabel UDP, jadi bukti login tidak
// berlaku di jalur lain. Return 0 OK, 1 auth nonaktif, 2 format, 5 hmac salah.
// D4: bukti dicocokkan dengan kunci admin dan (bila dimuat) kunci read-only;
// keduanya selalu dihitung. *role = AUTH_ROLE_ADMIN/AUTH_ROLE_RO bila OK.
int auth_tcp_login(const uint8_t nonce[16], const uint8_t *line, uint32_t len,
                   int *role)
{
    static const char hx[] = "0123456789abcdef";
    static const char pre[] = "login ";
    static const char sfx[] = " tcp-login";

    if (g_auth_key_len == 0) {
        return 1;
    }
    if (len != 6 + 64) {
        return 2;
    }
    for (uint32_t i = 0; i < 6; i++) {
        if (line[i] != (uint8_t)pre[i]) {
            return 2;
        }
    }

    uint8_t rx[32];

    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(line[6 + i * 2]);
        int lo = auth_hexval(line[6 + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }
        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    uint8_t m[32 + 10];

    for (uint32_t i = 0; i < 16; i++) {
        m[i * 2] = (uint8_t)hx[nonce[i] >> 4];
        m[i * 2 + 1] = (uint8_t)hx[nonce[i] & 0xF];
    }
    for (uint32_t i = 0; i < 10; i++) {
        m[32 + i] = (uint8_t)sfx[i];
    }

    uint8_t mac[32];
    int admin, ro = 0;

    hmac_sha256(g_auth_key, g_auth_key_len, m, sizeof(m), mac);
    admin = ct_memeq(mac, rx, 32);
    if (g_auth_ro_key_len != 0) {
        hmac_sha256(g_auth_ro_key, g_auth_ro_key_len, m, sizeof(m), mac);
        ro = ct_memeq(mac, rx, 32);
    }
    if (admin) {
        *role = AUTH_ROLE_ADMIN;
    } else if (ro) {
        *role = AUTH_ROLE_RO;
    } else {
        return 5;
    }
    return 0;
}

// D2: baris perintah sesi TCP "<perintah> <hmac-hex64>", hmac atas
// "<nonce32hex> tcp-cmd <seq> <perintah>" (seq desimal, 1, 2, ... per
// koneksi, tidak dikirim). Nonce koneksi mencegah pemakaian di koneksi lain,
// seq mencegah pengulangan di koneksi yang sama; "tcp-cmd" membedakannya dari
// bukti login. Return 0 OK (*cmd_len = panjang perintah di awal line),
// 1 auth nonaktif, 2 format, 5 hmac salah. D4: kunci sesuai peran sesi.
int auth_tcp_cmd(const uint8_t nonce[16], int role, uint64_t seq,
                 const uint8_t *line, uint32_t len, uint32_t *cmd_len)
{
    static const char hx[] = "0123456789abcdef";
    static const char mid[] = " tcp-cmd ";
    const uint8_t *key = role == AUTH_ROLE_ADMIN ? g_auth_key :
                         role == AUTH_ROLE_RO ? g_auth_ro_key : 0;
    uint32_t key_len = role == AUTH_ROLE_ADMIN ? g_auth_key_len :
                       role == AUTH_ROLE_RO ? g_auth_ro_key_len : 0;

    if (key_len == 0) {
        return 1;
    }
    // minimum: perintah(1) + spasi + hmac(64); perintah maks 64 byte.
    if (len < 1 + 1 + 64 || len > 64 + 1 + 64 || line[len - 65] != ' ') {
        return 2;
    }

    uint32_t clen = len - 65;
    uint8_t rx[32];

    for (uint32_t i = 0; i < clen; i++) {
        if (line[i] == ' ' && (i == 0 || i == clen - 1)) {
            return 2;
        }
    }
    for (uint32_t i = 0; i < 32; i++) {
        int hi = auth_hexval(line[clen + 1 + i * 2]);
        int lo = auth_hexval(line[clen + 1 + i * 2 + 1]);

        if (hi < 0 || lo < 0) {
            return 2;
        }
        rx[i] = (uint8_t)((hi << 4) | lo);
    }

    // "<32 hex>" + " tcp-cmd " + seq (maks 20 digit) + " " + perintah (maks 64)
    uint8_t m[32 + 9 + 20 + 1 + 64];
    uint32_t k = 0;
    char dec[20];
    uint32_t nd = 0;

    for (uint32_t i = 0; i < 16; i++) {
        m[k++] = (uint8_t)hx[nonce[i] >> 4];
        m[k++] = (uint8_t)hx[nonce[i] & 0xF];
    }
    for (uint32_t i = 0; i < 9; i++) {
        m[k++] = (uint8_t)mid[i];
    }
    do {
        dec[nd++] = (char)('0' + seq % 10);
        seq /= 10;
    } while (seq);
    while (nd) {
        m[k++] = (uint8_t)dec[--nd];
    }
    m[k++] = ' ';
    for (uint32_t i = 0; i < clen; i++) {
        m[k++] = line[i];
    }

    uint8_t mac[32];

    hmac_sha256(key, key_len, m, k, mac);
    if (!ct_memeq(mac, rx, 32)) {
        return 5;
    }
    *cmd_len = clen;
    return 0;
}

// D2: jalankan perintah yang sudah diverifikasi auth_tcp_cmd (daftar sama
// dengan jalur UDP nonce), salin keluaran ke out (maks max byte). *reboot = 1
// bila reboot diminta: pemanggil menjalankan auth_reboot() setelah balasan
// terkirim. D4: peran selain admin hanya boleh perintah di daftar putih
// g_ro_cmds (perintah baru otomatis ditolak); lainnya "ERR: peran read-only".
static const char *const g_ro_cmds[] = {
    "help", "ping", "uptime", "mem", "log", "irq", "stats", "metrics", "mac",
    "ip", "tasks", "config", "tls", "netcon", "logdisk", "wd",
};

// D5: juga dipakai net.c untuk menentukan jenis entri audit sebelum exec.
int auth_cmd_allowed(int role, const uint8_t *cmd, uint32_t len)
{
    int allowed = role == AUTH_ROLE_ADMIN;

    for (uint32_t i = 0; i < sizeof(g_ro_cmds) / sizeof(g_ro_cmds[0]); i++) {
        allowed |= net_cmd_is(cmd, len, g_ro_cmds[i]);
    }
    // R3: metrics dengan argumen (awalan/mulai) juga baca saja.
    allowed |= len > 8 && net_cmd_is(cmd, 8, "metrics ");
    allowed |= len > 8 && net_cmd_is(cmd, 8, "logdisk ");   // R4: logdisk <seq>
    return allowed;
}

uint32_t auth_tcp_exec(int role, const uint8_t *cmd, uint32_t len, uint8_t *out,
                       uint32_t max, int *reboot)
{
    const char *o;
    uint32_t n;

    if (!auth_cmd_allowed(role, cmd, len)) {
        g_cli_role_denied++;
        g_cmd_len = 0;
        cmd_puts("ERR: peran read-only\n");
    } else {
        priv_cmd_execute(cmd, len);
    }
    *reboot = g_priv_reboot_pending;
    g_priv_reboot_pending = 0;
    o = cmd_out();
    n = g_cmd_len > max ? max : g_cmd_len;
    for (uint32_t i = 0; i < n; i++) {
        out[i] = (uint8_t)o[i];
    }
    return n;
}

void auth_reboot(void)
{
    priv_do_reboot();
}

void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len)
{
    volatile uint8_t *cmd = req + 14 + ihl + 8;
    uint32_t len = udp_len - 8;

    // Buang trailing CR/LF/spasi/NUL (nc, PowerShell, dll. sering menambah).
    while (len > 0 && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' ||
                       cmd[len - 1] == ' '  || cmd[len - 1] == 0)) {
        len--;
    }

    uint16_t sport = (uint16_t)(((uint32_t)req[14 + ihl] << 8) | req[14 + ihl + 1]);

    if (priv_try_handle(cmd, len, req + 14 + 12, sport)) {
        net_udp_send_cmd_reply(req, ihl);

        if (g_priv_reboot_pending) {
            priv_do_reboot();
        }
        return;
    }

#ifndef BMAHOS_LEGACYCTR
    // B2: jalur counter dimatikan. Counter terakhir hanya ada di RAM, jadi
    // setelah reboot datagram lama bisa diputar ulang sekali; jalur nonce
    // tidak punya masalah itu. LEGACYCTR=1 menyalakannya lagi.
    g_auth_ctr_off++;
    g_cmd_len = 0;
    cmd_puts("ERR: jalur counter dimatikan; kirim CHAL lalu <nonce> <perintah> <hmac>\n");
    net_udp_send_cmd_reply(req, ihl);
    return;
#endif

    volatile uint8_t *ac = 0;
    uint32_t acl = 0;
    uint64_t actr = 0;

    int arc = auth_verify(cmd, len, &ac, &acl, &actr);

    if (arc == 0) {
        g_auth_ok++;
    } else if (arc >= 1 && arc <= 4) {
        g_auth_denied[arc]++;
    }

    if (arc == 0) {
        uint64_t lf = irq_save();
        serial_write("Net-11: auth OK counter=");
        serial_write_hex(actr);
        serial_write("\r\n");
        irq_restore(lf);

        net_cmd_execute(ac, acl);
    } else {
        uint64_t lf = irq_save();
        serial_write("Net-11: auth DITOLAK kode=");
        serial_write_hex((uint64_t)arc);
        serial_write("\r\n");
        irq_restore(lf);

        g_cmd_len = 0;

        if (arc == 1) {
            cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
        } else if (arc == 2) {
            cmd_puts("ERR: format: <counter> <perintah> <hmac-hex64>\n");
        } else if (arc == 3) {
            cmd_puts("ERR: hmac salah\n");
        } else {
            cmd_puts("ERR: counter replay\n");
        }
    }

    net_udp_send_cmd_reply(req, ihl);
}

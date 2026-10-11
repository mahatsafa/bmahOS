#include "kernel.h"

// ---- Net-11b: kunci autentikasi dari disk FAT32 (KEY.TXT) ----
static uint8_t g_auth_key[64];
static uint32_t g_auth_key_len = 0;
static uint64_t g_auth_last_counter = 0;

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

    uint8_t diff = 0;

    for (uint32_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(mac[i] ^ rx[i]);
    }

    if (diff != 0) {
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
static uint8_t g_nonce_pool[32];
static uint64_t g_nonce_ctr = 0;
static int g_rdrand_state = -1;   // -1 belum dicek, 0 tidak ada, 1 ada

static inline uint64_t priv_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static int priv_have_rdrand(void)
{
#ifdef BMAHOS_NORDRAND
    return 0;
#else
    uint32_t a = 1, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
    return (c >> 30) & 1;
#endif
}

static int priv_rdrand64(uint64_t *out)
{
#ifdef BMAHOS_NORDRAND
    (void)out;
    return 0;
#else
    for (int i = 0; i < 10; i++) {
        uint64_t v;
        uint8_t ok;
        __asm__ volatile("rdrand %0; setc %1" : "=r"(v), "=qm"(ok) : : "cc");
        if (ok) {
            *out = v;
            return 1;
        }
    }
    return 0;
#endif
}

static uint8_t priv_cmos_read(uint8_t reg)
{
    outb(0x70, reg);
    return inb(0x71);
}

// SHA-256 atas pool + rdrand + TSC + timer_ticks + counter + RTC.
// Pool diperbarui dari hash dengan label berbeda dari keluaran nonce.
void priv_nonce_generate(uint8_t out[16])
{
    static const uint8_t rtc_regs[6] = {0x00, 0x02, 0x04, 0x07, 0x08, 0x09};
    sha256_ctx_t ctx;
    uint8_t h[32];
    uint8_t t[32];
    uint64_t v;

    if (g_rdrand_state < 0) {
        g_rdrand_state = priv_have_rdrand();

        uint64_t lf = irq_save();
#ifdef BMAHOS_NORDRAND
        serial_write("Net-18: sumber nonce tanpa rdrand (build NORDRAND)\r\n");
#else
        serial_write(g_rdrand_state
                     ? "Net-18: sumber nonce memakai rdrand\r\n"
                     : "Net-18: CPU tanpa rdrand, nonce dari TSC/tick/RTC saja\r\n");
#endif
        irq_restore(lf);
    }

    g_nonce_ctr++;

    sha256_init(&ctx);
    sha256_update(&ctx, g_nonce_pool, 32);

    if (g_rdrand_state == 1) {
        for (int i = 0; i < 4; i++) {
            if (priv_rdrand64(&v)) {
                sha256_update(&ctx, (const uint8_t *)&v, 8);
            }
        }
    }

    v = priv_rdtsc();
    sha256_update(&ctx, (const uint8_t *)&v, 8);
    v = timer_ticks;
    sha256_update(&ctx, (const uint8_t *)&v, 8);
    sha256_update(&ctx, (const uint8_t *)&g_nonce_ctr, 8);

    for (int i = 0; i < 6; i++) {
        uint8_t r = priv_cmos_read(rtc_regs[i]);
        sha256_update(&ctx, &r, 1);
    }

    sha256_final(&ctx, h);

    sha256_init(&ctx);
    sha256_update(&ctx, h, 32);
    sha256_update(&ctx, (const uint8_t *)"pool", 4);
    sha256_final(&ctx, g_nonce_pool);

    sha256_init(&ctx);
    sha256_update(&ctx, h, 32);
    sha256_update(&ctx, (const uint8_t *)"nonce", 5);
    sha256_final(&ctx, t);

    for (int i = 0; i < 16; i++) {
        out[i] = t[i];
    }
}

// M1: slot kosong/kedaluwarsa dipakai dulu. IP yang sudah punya
// PRIV_NONCE_PER_IP nonce hidup hanya mengganti nonce miliknya sendiri yang
// tertua, jadi banjir CHAL satu IP tidak menggusur nonce IP lain.
// Tabel penuh oleh banyak IP berbeda: ganti yang tertua (batas diketahui).

static uint32_t priv_nonce_issue(const volatile uint8_t *ip)
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

    priv_nonce_generate(g_priv_nonces[slot].nonce);
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

    int slot = -1;

    for (uint32_t i = 0; i < PRIV_NONCE_SLOTS; i++) {
        if (!g_priv_nonces[i].in_use) {
            continue;
        }

        uint8_t nd = 0;

        for (uint32_t j = 0; j < 16; j++) {
            nd |= (uint8_t)(g_priv_nonces[i].nonce[j] ^ nonce[j]);
        }

        if (nd == 0) {
            slot = (int)i;
            break;
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

    uint8_t diff = 0;

    for (uint32_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(mac[i] ^ rx[i]);
    }

    if (diff != 0) {
        return 5;
    }

    g_priv_nonces[slot].in_use = 0;
    *cmd_out = d + 33;
    *cmd_len_out = msg_len - 33;

    return 0;
}

// ---- Net-18B: reboot berprivilege ----
// Dipanggil SETELAH balasan terkirim. Urutan: register reset ACPI (FADT,
// ACPI-R), 8042 pulse reset (0xFE), lalu cadangan triple fault (IDT limit 0
// lalu int3). NOACPIRESET=1 dan NOKBDRESET=1 melewati jalur masing-masing
// untuk menguji cadangan.
static int g_priv_reboot_pending = 0;

static void priv_do_reboot(void)
{
    __asm__ volatile("cli");
    g_serial_mute = 0;

#ifndef BMAHOS_NOACPIRESET
    if (g_acpi_reset_ok) {
        serial_write("ACPI-R: reboot via register reset FADT\r\n");
        outb(g_acpi_reset_port, g_acpi_reset_value);

        for (uint32_t i = 0; i < 1000000; i++) {
            (void)inb(0x64);
        }

        serial_write("ACPI-R: reset ACPI tidak me-reset, lanjut 8042\r\n");
    }
#else
    serial_write("ACPI-R: reset ACPI dilewati (build NOACPIRESET)\r\n");
#endif

#ifndef BMAHOS_NOKBDRESET
    serial_write("Net-18B: reboot via 8042 (0xFE)\r\n");

    for (uint32_t i = 0; i < 100000; i++) {
        if ((inb(0x64) & 0x02) == 0) {
            break;
        }
    }

    outb(0x64, 0xFE);

    for (uint32_t i = 0; i < 1000000; i++) {
        (void)inb(0x64);
    }

    serial_write("Net-18B: 8042 tidak me-reset, cadangan triple fault\r\n");
#else
    serial_write("Net-18B: reboot via triple fault (build NOKBDRESET)\r\n");
#endif

    struct __attribute__((packed)) {
        uint16_t limit;
        uint64_t base;
    } zero_idt = {0, 0};

    __asm__ volatile("lidt %0; int3" : : "m"(zero_idt));

    for (;;) {
        __asm__ volatile("hlt");
    }
}

static void priv_cmd_execute(const volatile uint8_t *cmd, uint32_t len)
{
    g_cmd_len = 0;

    if (net_cmd_is(cmd, len, "pping")) {
        cmd_puts("ppong\n");
    } else if (net_cmd_is(cmd, len, "reboot")) {
        cmd_puts("reboot: dimulai\n");
        g_priv_reboot_pending = 1;
    } else {
        // B2: perintah baca juga boleh lewat jalur nonce.
        net_cmd_execute(cmd, len);
    }
}

// Return 1 jika datagram adalah CHAL atau berformat nonce (balasan sudah
// diisi di g_cmd_out), 0 jika harus lewat jalur counter lama.
static int priv_try_handle(volatile uint8_t *cmd, uint32_t len,
                           const volatile uint8_t *src_ip)
{
    if (net_cmd_is(cmd, len, "CHAL")) {
        g_cmd_len = 0;

        if (g_auth_key_len == 0) {
            g_priv_denied[1]++;
            cmd_puts("ERR: auth nonaktif (kunci tidak dimuat)\n");
            return 1;
        }

        uint32_t slot = priv_nonce_issue(src_ip);
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
        priv_cmd_execute(pc, pcl);
        return 1;
    }

    g_priv_denied[prc]++;
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

void net_cmd_handle(volatile uint8_t *req, uint32_t ihl, uint32_t udp_len)
{
    volatile uint8_t *cmd = req + 14 + ihl + 8;
    uint32_t len = udp_len - 8;

    // Buang trailing CR/LF/spasi/NUL (nc, PowerShell, dll. sering menambah).
    while (len > 0 && (cmd[len - 1] == '\n' || cmd[len - 1] == '\r' ||
                       cmd[len - 1] == ' '  || cmd[len - 1] == 0)) {
        len--;
    }

    if (priv_try_handle(cmd, len, req + 14 + 12)) {
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

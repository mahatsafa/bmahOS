// P4: uji packet filter (filter.c di-#include: akses static). fat32_read_name /
// fat32_replace_name di-stub ke buffer di memori; timer_ticks dari stubs.c.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/filter.c"

extern char g_serial_cap[];
void serial_capture_reset(void);

static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len = 0;

void cmd_puts(const char *s)
{
    while (*s && g_cmd_len < CMD_OUT_MAX) {
        g_out[g_cmd_len++] = *s++;
    }
    g_out[g_cmd_len] = 0;
}

int net_cmd_is(const volatile uint8_t *cmd, uint32_t len, const char *name)
{
    uint32_t i = 0;

    while (name[i]) {
        if (i >= len || cmd[i] != (uint8_t)name[i]) {
            return 0;
        }
        i++;
    }
    return i == len;
}

const char *fscmd_strerror(int rc)
{
    return rc == FAT32_ERR_RO ? "volume baca saja" : "error";
}

static char g_file[4096];
static int g_file_len = -1;   // -1 = tidak ada
static int g_read_rc = 0;
static int g_write_rc = 0;
static int g_writes = 0;

int fat32_read_name(const char *name83, uint8_t *out, uint32_t max, uint32_t *out_size)
{
    if (memcmp(name83, "FILTER  CFG", 11) != 0) {
        return FAT32_ERR_NOENT;
    }
    if (g_read_rc) {
        return g_read_rc;
    }
    if (g_file_len < 0) {
        return FAT32_ERR_NOENT;
    }
    if ((uint32_t)g_file_len > max) {
        return FAT32_ERR_TOOBIG;
    }
    memcpy(out, g_file, (size_t)g_file_len);
    *out_size = (uint32_t)g_file_len;
    return FAT32_OK;
}

int fat32_replace_name(const char *dst83, const char *tmp83, const uint8_t *data, uint32_t len)
{
    g_writes++;
    if (memcmp(dst83, "FILTER  CFG", 11) != 0 || memcmp(tmp83, "FILTER  TMP", 11) != 0) {
        return FAT32_ERR_CORRUPT;
    }
    if (g_write_rc) {
        return g_write_rc;
    }
    memcpy(g_file, data, len);
    g_file[len] = 0;
    g_file_len = (int)len;
    return FAT32_OK;
}

// ---- pembantu ----
static void set_file(const char *s)
{
    g_read_rc = 0;
    if (s) {
        g_file_len = (int)strlen(s);
        memcpy(g_file, s, (size_t)g_file_len);
    } else {
        g_file_len = -1;
    }
}

static const char *run(const char *c)
{
    g_cmd_len = 0;
    g_out[0] = 0;
    if (!filter_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

// Parse lalu tulis kanonik; "" = ditolak.
static const char *canon(const char *s)
{
    static char b[64];
    filter_rule_t r;
    const char *why;

    if (!filter_parse_rule((const uint8_t *)s, (uint32_t)strlen(s), &r, &why)) {
        return "";
    }
    flt_fmt(&r, b, sizeof(b));
    return b;
}

static void set_rules(const char *const *rules, uint32_t n)
{
    const char *why;

    g_filter_n = 0;
    g_filter_drop = 0;
    for (uint32_t i = 0; i < n; i++) {
        CHECK(filter_parse_rule((const uint8_t *)rules[i], (uint32_t)strlen(rules[i]),
                                &g_filter[i], &why));
    }
    g_filter_n = n;
}

static const uint8_t IP66[4] = { 192, 168, 50, 66 };
static const uint8_t IP67[4] = { 192, 168, 50, 67 };
static const uint8_t IP10[4] = { 10, 0, 0, 1 };

static void test_parse(void)
{
    CHECK_STR(canon("izinkan semua semua"), "izinkan semua semua");
    CHECK_STR(canon("tolak udp 192.168.50.66 port 7777"), "tolak udp 192.168.50.66/32 port 7777");
    CHECK_STR(canon("tolak tcp 10.0.0.0/8 port 1-1024"), "tolak tcp 10.0.0.0/8 port 1-1024");
    CHECK_STR(canon("izinkan icmp semua laju 5"), "izinkan icmp semua laju 5");
    CHECK_STR(canon("izinkan semua 192.168.50.0/24 port 7777 laju 10000"),
              "izinkan semua 192.168.50.0/24 port 7777 laju 10000");
    CHECK_STR(canon("  tolak   udp   semua  "), "tolak udp semua");
    CHECK_STR(canon("tolak udp 0.0.0.0/0"), "tolak udp semua");
    CHECK_STR(canon("tolak udp semua port 0-65535"), "tolak udp semua port 0-65535");
    CHECK_STR(canon("tolak udp 1.2.3.4/32"), "tolak udp 1.2.3.4/32");

    static const char *const bad[] = {
        "", "   ", "blok udp semua", "tolak xyz semua", "tolak udp", "tolak udp 1.2.3",
        "tolak udp 1.2.3.4.5", "tolak udp 256.1.1.1", "tolak udp 1.2.3.4/33",
        "tolak udp 192.168.50.7/24", "tolak icmp semua port 5", "tolak udp semua port 5-4",
        "tolak udp semua port 70000", "tolak udp semua laju 5", "izinkan udp semua laju 0",
        "izinkan udp semua laju 10001", "izinkan udp semua laju 5 port 7",
        "izinkan udp semua port 7 port 8", "tolak udp semua ekstra", "tolak udp 1.2.3.4/",
        "tolak udp semua port", "tolak udp semua port -5", "tolak udp semua port 5-",
        "tolak udp 1..2.3", "tolak udp 1.2.3.0004", "TOLAK udp semua", "tolak udp 1.2.3.4/024",
    };
    int all = 1;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (canon(bad[i])[0] != 0) {
            fprintf(stderr, "harus ditolak: \"%s\"\n", bad[i]);
            all = 0;
        }
    }
    CHECK(all);
}

static void test_match(void)
{
    static const char *const rules[] = {
        "tolak udp 192.168.50.66 port 7777",
        "izinkan udp 192.168.50.0/24 port 7000-7999 laju 2",
        "tolak semua semua",
    };
    set_rules(rules, 3);
    timer_ticks = 1000;

    CHECK(filter_check(IP66, 17, 7777) == 0);                 // aturan 1
    CHECK(filter_check(IP66, 17, 7778) == 1);                 // aturan 2 (1/2)
    CHECK(filter_check(IP67, 17, 7000) == 1);                 // aturan 2 (2/2)
    CHECK(filter_check(IP67, 17, 7999) == 0);                 // aturan 2: laju habis
    CHECK(filter_check(IP67, 6, 7500) == 0);                  // tcp -> aturan 3
    CHECK(filter_check(IP10, 17, 7500) == 0);                 // luar /24 -> aturan 3
    CHECK(filter_check(IP67, 1, 0) == 0);                     // icmp: port tak cocok -> 3
    CHECK(filter_check(IP10, 6, 7780) == 1);                  // TLS admin selalu lolos
    CHECK(filter_check(IP66, 17, 7780) == 0);                 // hanya TCP; UDP 7780 kena aturan 2 (laju habis)
    CHECK(g_filter[0].hits == 1 && g_filter[0].dropped == 1);
    CHECK(g_filter[1].hits == 4 && g_filter[1].dropped == 2);
    CHECK(g_filter[2].hits == 3 && g_filter[2].dropped == 3);
    CHECK(g_filter_drop == 6);
    timer_ticks += 99;
    CHECK(filter_check(IP67, 17, 7001) == 0);                 // jendela belum lewat
    timer_ticks += 1;
    CHECK(filter_check(IP67, 17, 7001) == 1);                 // jendela baru
    CHECK(filter_check(IP67, 17, 6999) == 0);                 // di luar rentang port -> 3

    // Tanpa aturan: semua lolos, tanpa hitungan.
    set_rules(rules, 0);
    CHECK(filter_check(IP66, 17, 7777) == 1 && g_filter_drop == 0);
}

// Frame Ethernet + IPv4 (ihl 20) dengan protokol/port/flag TCP tertentu.
static uint8_t g_frame[64];
static void mk_frame(uint8_t proto, const uint8_t *src, uint16_t dport, uint8_t tflags)
{
    memset(g_frame, 0, sizeof(g_frame));
    g_frame[14] = 0x45;
    g_frame[23] = proto;
    memcpy(g_frame + 26, src, 4);
    g_frame[34 + 2] = (uint8_t)(dport >> 8);
    g_frame[34 + 3] = (uint8_t)dport;
    g_frame[34 + 13] = tflags;
}

static void test_ipv4(void)
{
    static const char *const rules[] = { "tolak tcp 192.168.50.66 port 7", "tolak udp semua port 7777",
                                         "tolak icmp 10.0.0.0/8" };
    set_rules(rules, 3);
    mk_frame(6, IP66, 7, 0x02);
    CHECK(filter_ipv4(g_frame, 20, 20) == 0);                 // SYN baru -> dibuang
    mk_frame(6, IP66, 7, 0x12);
    CHECK(filter_ipv4(g_frame, 20, 20) == 1);                 // SYN+ACK: bukan koneksi baru
    mk_frame(6, IP66, 7, 0x10);
    CHECK(filter_ipv4(g_frame, 20, 20) == 1);                 // ACK koneksi berjalan
    mk_frame(6, IP66, 7, 0x02);
    CHECK(filter_ipv4(g_frame, 20, 19) == 1);                 // terlalu pendek: biar TCP menolak
    mk_frame(17, IP67, 7777, 0);
    CHECK(filter_ipv4(g_frame, 20, 8) == 0);
    CHECK(filter_ipv4(g_frame, 20, 7) == 1);                  // UDP pendek
    mk_frame(17, IP67, 7778, 0);
    CHECK(filter_ipv4(g_frame, 20, 8) == 1);
    mk_frame(1, IP10, 0, 0);
    CHECK(filter_ipv4(g_frame, 20, 8) == 0);
    mk_frame(1, IP67, 0, 0);
    CHECK(filter_ipv4(g_frame, 20, 8) == 1);
    mk_frame(47, IP10, 0, 0);                                 // GRE: tidak diperiksa
    CHECK(filter_ipv4(g_frame, 20, 8) == 1);
    CHECK(g_filter_drop == 3);
}

static void test_load(void)
{
    serial_capture_reset();
    set_file(0);
    filter_load();
    CHECK(g_filter_n == 0 && strstr(g_serial_cap, "P4: filter tanpa aturan (tanpa file)\r\n"));

    serial_capture_reset();
    set_file("# komentar\r\n\r\ntolak udp semua port 7777\r\n   \n  izinkan icmp semua laju 3\n"
             "# akhir tanpa LF\ntolak tcp 10.0.0.0/8");
    filter_load();
    CHECK(g_filter_n == 3 && strstr(g_serial_cap, "P4: filter sumber=disk aturan=3\r\n"));
    CHECK(g_filter[1].proto == 1 && g_filter[1].rate == 3 && g_filter[2].prefix == 8);

    // Satu baris salah (baris 4) -> seluruh file diabaikan.
    serial_capture_reset();
    set_file("tolak udp semua port 7777\n# ok\n\ntolak udp 1.2.3.4/33\n");
    filter_load();
    CHECK(g_filter_n == 0);
    CHECK(strstr(g_serial_cap, "P4: FILTER.CFG ditolak baris 4 (") != 0);

    // 16 aturan boleh, 17 ditolak.
    char big[2048] = "";
    for (int i = 0; i < 16; i++) {
        strcat(big, "tolak udp semua port 1\n");
    }
    set_file(big);
    filter_load();
    CHECK(g_filter_n == 16);
    strcat(big, "tolak udp semua port 2\n");
    serial_capture_reset();
    set_file(big);
    filter_load();
    CHECK(g_filter_n == 0 && strstr(g_serial_cap, "baris 17 (lebih dari 16 aturan)"));

    serial_capture_reset();
    set_file("tolak udp semua\n");
    g_read_rc = FAT32_ERR_NOVOL;
    filter_load();
    CHECK(g_filter_n == 0 && strstr(g_serial_cap, "P4: filter tanpa aturan (tanpa disk)\r\n"));
    g_read_rc = FAT32_ERR_TOOBIG;
    serial_capture_reset();
    filter_load();
    CHECK(g_filter_n == 0 && strstr(g_serial_cap, "P4: FILTER.CFG > 1536 byte, tanpa aturan\r\n"));
    g_read_rc = 0;
}

static void test_cmds(void)
{
    set_file(0);
    filter_load();
    g_filter_drop = 0;

    CHECK_STR(run("filter"), "filter: aturan=0 dibuang=0 sumber=tanpa file [cocok/dibuang]; "
                             "tanpa cocok: izinkan; tcp 7780 selalu lolos\n");
    CHECK_STR(run("filterx"), "(tidak ditangani)");
    CHECK_STR(run("filter tambah tolak udp 192.168.50.66 port 7777"),
              "OK filter 1: tolak udp 192.168.50.66/32 port 7777 (tersimpan)\n");
    CHECK_STR(run("filter tambah izinkan icmp semua laju 3"),
              "OK filter 2: izinkan icmp semua laju 3 (tersimpan)\n");
    CHECK_STR(run("filter tambah tolak udp semua laju 3"),
              "ERR: filter: laju N (1..10000), hanya untuk izinkan\n");
    CHECK_STR(g_file, "# bmahOS FILTER.CFG (ditulis oleh perintah filter)\n"
                      "tolak udp 192.168.50.66/32 port 7777\nizinkan icmp semua laju 3\n");

    CHECK(filter_check(IP66, 17, 7777) == 0);
    CHECK(filter_check(IP67, 1, 0) == 1);
    CHECK_STR(run("filter"), "filter: aturan=2 dibuang=1 sumber=disk [cocok/dibuang]; "
                             "tanpa cocok: izinkan; tcp 7780 selalu lolos\n"
                             "1: tolak udp 192.168.50.66/32 port 7777 [1/1]\n"
                             "2: izinkan icmp semua laju 3 [1/0]\n");

    // Gagal tulis: RAM tidak berubah.
    g_write_rc = FAT32_ERR_RO;
    CHECK_STR(run("filter tambah tolak tcp semua"),
              "ERR: filter: tidak tersimpan, aturan tidak diubah (fs: volume baca saja)\n");
    CHECK_STR(run("filter hapus 1"),
              "ERR: filter: tidak tersimpan, aturan tidak diubah (fs: volume baca saja)\n");
    CHECK_STR(run("filter kosong"),
              "ERR: filter: tidak tersimpan, aturan tidak diubah (fs: volume baca saja)\n");
    g_write_rc = 0;
    CHECK(g_filter_n == 2);

    // Hapus aturan 1: aturan 2 naik jadi 1, hitungannya ikut.
    CHECK_STR(run("filter hapus 1"), "OK filter: aturan 1 dihapus, sisa 1 (tersimpan)\n");
    CHECK(g_filter_n == 1 && g_filter[0].proto == 1 && g_filter[0].hits == 1);
    CHECK_STR(run("filter hapus 2"), "ERR: filter: hapus <nomor aturan 1..n>\n");
    CHECK_STR(run("filter hapus 0"), "ERR: filter: hapus <nomor aturan 1..n>\n");
    CHECK_STR(run("filter hapus x"), "ERR: filter: hapus <nomor aturan 1..n>\n");
    CHECK_STR(run("filter apa"),
              "ERR: filter: filter | filter tambah <aturan> | filter hapus <n> | filter kosong\n");
    CHECK_STR(run("filter tambah "),
              "ERR: filter: filter | filter tambah <aturan> | filter hapus <n> | filter kosong\n");

    // Penuh: 16 aturan terpanjang, file muat dan bisa dibaca ulang identik.
    CHECK_STR(run("filter kosong"), "OK filter: semua aturan dihapus (tersimpan)\n");
    CHECK(g_filter_n == 0 && strcmp(g_file, "# bmahOS FILTER.CFG (ditulis oleh perintah filter)\n") == 0);
    for (int i = 0; i < 16; i++) {
        char c[96];
        snprintf(c, sizeof(c), "filter tambah izinkan semua 255.255.255.%d port 65534-65535 laju 9999",
                 200 + i);
        // Perintah > 64 byte ditolak di jalur TCP; filter_execute sendiri membatasi 7 + 64.
        CHECK(strncmp(run(c), "OK filter ", 10) == 0);
    }
    CHECK(g_filter_n == 16 && g_file_len < FILTER_FILE_MAX);
    CHECK_STR(run("filter tambah tolak udp semua"), "ERR: filter: penuh (maks 16 aturan)\n");
    filter_rule_t back[FILTER_MAX];
    uint32_t n = 0, bad = 0;
    const char *why = "";
    CHECK(filter_parse((const uint8_t *)g_file, (uint32_t)g_file_len, back, &n, &bad, &why) && n == 16);
    int same = 1;
    for (uint32_t i = 0; i < n; i++) {
        char a[64], b[64];
        flt_fmt(&back[i], a, sizeof(a));
        flt_fmt(&g_filter[i], b, sizeof(b));
        same &= strcmp(a, b) == 0;
    }
    CHECK(same);
    const char *all = run("filter");
    CHECK(strstr(all, "16: izinkan semua 255.255.255.215/32 port 65534-65535 laju 9999 [0/0]\n") != 0);
    CHECK(g_cmd_len < CMD_OUT_MAX);
    CHECK(g_writes > 0);
}

int main(void)
{
    test_parse();
    test_match();
    test_ipv4();
    test_load();
    test_cmds();
    return test_done("filter");
}

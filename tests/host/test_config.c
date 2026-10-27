// D7: uji config.c (di-#include): parser CONFIG.CFG, config_load (sumber +
// baris serial), perintah config/set. fat32_read_name/fat32_replace_name di-
// stub ke satu "file" di memori; ganti-atomik sendiri diuji di test_fat32.

#include <string.h>

#include "test.h"
#include "../../kernel/config.c"

#define NC_DEF "netcon=0\nnetcon_host=1\nnetcon_port=6666\ndhcp=0\n"   // + P3-4 dhcp

// ---- stub kernel ----
uint32_t g_cli_idle_s = CFG_CLI_IDLE_DEF;
uint32_t g_net_src_rate = NET_UDP_SRC_PER_SEC;
uint32_t g_net_echo = 1;
uint32_t g_cli_plain = 1;
uint32_t g_udp_admin = 1;
static int g_tls_on = 1;

int tls_enabled(void)
{
    return g_tls_on;
}

static char g_out[CMD_OUT_MAX + 1];
uint32_t g_cmd_len = 0;

void cmd_putc(char c)
{
    if (g_cmd_len < CMD_OUT_MAX) {
        g_out[g_cmd_len++] = c;
    }
}

void cmd_puts(const char *s)
{
    while (*s) {
        cmd_putc(*s++);
    }
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

static char g_file[5000];
static int g_file_len = -1;      // -1 = tidak ada
static int g_read_rc = 0;        // != 0: fat32_read_name mengembalikan ini
static int g_write_rc = 0;       // != 0: fat32_replace_name gagal
static int g_writes = 0;

int fat32_read_name(const char *name83, uint8_t *out, uint32_t max, uint32_t *out_size)
{
    if (memcmp(name83, "CONFIG  CFG", 11) != 0) {
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
    if (memcmp(dst83, "CONFIG  CFG", 11) != 0 || memcmp(tmp83, "CONFIG  TMP", 11) != 0) {
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
    if (!config_execute((const volatile uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak dikenali)";
    }
    g_out[g_cmd_len] = 0;
    return g_out;
}

// Parse s; return 1 bila sah. Baris/alasan penolakan ke *line/*why.
static int parse(const char *s, uint32_t *v, uint32_t *line, const char **why)
{
    return config_parse((const uint8_t *)s, (uint32_t)strlen(s), v, line, why);
}

static int rejected(const char *s, uint32_t want_line, const char *want_why)
{
    uint32_t v[CFG_NKEYS], line = 99;
    const char *why = "";
    int ok = parse(s, v, &line, &why);
    if (ok || line != want_line || strcmp(why, want_why) != 0) {
        fprintf(stderr, "  parse(%s): ok=%d baris=%u alasan=%s\n", s, ok, line, why);
        return 0;
    }
    return 1;
}

static void test_parse(void)
{
    uint32_t v[CFG_NKEYS], line;
    const char *why;

    CHECK(parse("", v, &line, &why) && v[0] == 300 && v[1] == 20 && v[2] == 1);
    CHECK(parse("cli_idle=600\nudp_rate=5\necho=0\n", v, &line, &why) &&
          v[0] == 600 && v[1] == 5 && v[2] == 0);
    // CRLF, komentar, baris kosong, tanpa LF akhir, sebagian kunci saja
    CHECK(parse("# komentar\r\n\r\n\necho=0\r\nudp_rate=100", v, &line, &why) &&
          v[0] == 300 && v[1] == 100 && v[2] == 0);
    CHECK(parse("cli_idle=30\n", v, &line, &why) && v[0] == 30);
    CHECK(parse("cli_idle=3600\n", v, &line, &why) && v[0] == 3600);
    CHECK(parse("# \x7e ok\n", v, &line, &why));

    CHECK(rejected("echo=1\nnama=x\n", 2, "kunci tak dikenal"));
    CHECK(rejected("echo\n", 1, "bukan kunci=nilai"));
    CHECK(rejected(" echo=1\n", 1, "kunci tak dikenal"));
    CHECK(rejected("echo =1\n", 1, "kunci tak dikenal"));
    CHECK(rejected("ECHO=1\n", 1, "kunci tak dikenal"));
    CHECK(rejected("=1\n", 1, "kunci tak dikenal"));
    CHECK(rejected("echo=1\n#\necho=1\n", 3, "kunci ganda"));
    CHECK(rejected("echo=2\n", 1, "nilai di luar rentang"));
    CHECK(rejected("cli_idle=29\n", 1, "nilai di luar rentang"));
    CHECK(rejected("cli_idle=3601\n", 1, "nilai di luar rentang"));
    CHECK(rejected("udp_rate=0\n", 1, "nilai di luar rentang"));
    CHECK(rejected("udp_rate=101\n", 1, "nilai di luar rentang"));
    CHECK(rejected("udp_rate=\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("udp_rate=020\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("udp_rate=+20\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("udp_rate=20 \n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("udp_rate=0x14\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("cli_idle=999999\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("cli_idle=4294967296\n", 1, "nilai bukan angka desimal"));
    CHECK(rejected("echo=1\r\r\n", 1, "byte bukan ASCII tercetak"));
    CHECK(rejected("echo=1\n# \tx\n", 2, "byte bukan ASCII tercetak"));
    CHECK(rejected("echo=1\n\x80\n", 2, "byte bukan ASCII tercetak"));
    // NUL di tengah (strlen tidak bisa dipakai)
    uint32_t l2;
    const char *w2;
    CHECK(!config_parse((const uint8_t *)"echo=1\n\0\n", 9, v, &l2, &w2) && l2 == 2);

    static char big[600];
    memset(big, '#', 513);
    big[513] = 0;
    CHECK(rejected(big, 0, "file > 512 byte"));
    memset(big, '#', 512);
    big[512] = 0;
    CHECK(parse(big, v, &line, &why));
    // ditolak -> out tetap default di posisi yang belum diproses
    CHECK(!parse("udp_rate=7\necho=9\n", v, &line, &why) && v[0] == 300);
}

static void test_load(void)
{
    // tanpa file
    set_file(NULL);
    serial_capture_reset();
    g_net_echo = 0;
    config_load();
    CHECK(g_net_echo == 1 && g_cli_idle_s == 300 && g_net_src_rate == 20);
    CHECK(strstr(g_serial_cap,
                 "CONFIG: sumber=bawaan (tidak ada file) cli_idle=300 udp_rate=20 echo=1 "
                 "cli_plain=1 udp_admin=1 netcon=0 netcon_host=1 netcon_port=6666 dhcp=0\r\n"));
    CHECK_STR(run("config"),
              "config: sumber=bawaan (tidak ada file)\ncli_idle=300\nudp_rate=20\necho=1\n"
              "cli_plain=1\nudp_admin=1\n" NC_DEF);

    // file sah
    set_file("cli_idle=600\necho=0\n");
    serial_capture_reset();
    config_load();
    CHECK(g_cli_idle_s == 600 && g_net_echo == 0 && g_net_src_rate == 20);
    CHECK(strstr(g_serial_cap, "CONFIG: sumber=disk cli_idle=600 udp_rate=20 echo=0 "
                               "cli_plain=1 udp_admin=1 netcon=0 netcon_host=1 "
                               "netcon_port=6666 dhcp=0\r\n"));
    CHECK_STR(run("config"), "config: sumber=disk\ncli_idle=600\nudp_rate=20\necho=0\n"
              "cli_plain=1\nudp_admin=1\n" NC_DEF);

    // file rusak -> SEMUA bawaan (juga kunci yang sah di baris sebelumnya)
    set_file("cli_idle=600\necho=0\nudp_rate=500\n");
    serial_capture_reset();
    config_load();
    CHECK(g_cli_idle_s == 300 && g_net_echo == 1 && g_net_src_rate == 20);
    CHECK(strstr(g_serial_cap, "CONFIG: sumber=bawaan (ditolak baris 3: nilai di luar rentang) "
                               "cli_idle=300 udp_rate=20 echo=1 cli_plain=1 udp_admin=1 "
                               "netcon=0 netcon_host=1 netcon_port=6666 dhcp=0\r\n"));
    CHECK(strncmp(run("config"), "config: sumber=bawaan (ditolak baris 3: nilai di luar rentang)\n"
                  "cli_idle=300\n", 76) == 0);

    // terlalu besar (> 512) -> ditolak
    static char big[700];
    memset(big, '#', 600);
    big[600] = 0;
    set_file(big);
    serial_capture_reset();
    config_load();
    CHECK(strstr(g_serial_cap, "sumber=bawaan (ditolak: file > 512 byte)"));

    // tanpa volume / error disk
    g_read_rc = FAT32_ERR_NOVOL;
    serial_capture_reset();
    config_load();
    CHECK(strstr(g_serial_cap, "sumber=bawaan (tanpa disk)"));
    g_read_rc = FAT32_ERR_IO;
    serial_capture_reset();
    config_load();
    CHECK(strstr(g_serial_cap, "sumber=bawaan (error baca disk)"));
    g_read_rc = 0;
}

static void test_set(void)
{
    set_file(NULL);
    config_load();
    g_writes = 0;

    CHECK_STR(run("set echo 0"), "OK echo=0 (tersimpan)\n");
    CHECK(g_net_echo == 0);
    CHECK(g_file_len > 0 &&
          strcmp(g_file, "# bmahOS CONFIG.CFG (ditulis oleh perintah set)\n"
                         "cli_idle=300\nudp_rate=20\necho=0\ncli_plain=1\nudp_admin=1\n"
                         NC_DEF) == 0);
    CHECK_STR(run("set cli_idle 3600"), "OK cli_idle=3600 (tersimpan)\n");
    CHECK_STR(run("set udp_rate 1"), "OK udp_rate=1 (tersimpan)\n");
    CHECK(g_cli_idle_s == 3600 && g_net_src_rate == 1);
    CHECK_STR(run("config"), "config: sumber=disk\ncli_idle=3600\nudp_rate=1\necho=0\n"
              "cli_plain=1\nudp_admin=1\n" NC_DEF);

    // file yang ditulis set terbaca ulang identik
    g_net_echo = 1;
    g_cli_idle_s = 1;
    config_load();
    CHECK(g_net_echo == 0 && g_cli_idle_s == 3600 && g_net_src_rate == 1);

    CHECK_STR(run("set udp_rate -"), "OK udp_rate=20 (tersimpan)\n");
    CHECK_STR(run("set echo -"), "OK echo=1 (tersimpan)\n");
    CHECK(g_net_echo == 1 && g_net_src_rate == 20);
    CHECK(g_writes == 5);

    // salah: tidak menulis, tidak mengubah
    CHECK_STR(run("set nama x"),
              "ERR: config: kunci tak dikenal (cli_idle udp_rate echo cli_plain udp_admin "
              "netcon netcon_host netcon_port dhcp)\n");
    CHECK_STR(run("set echo 2"), "ERR: config: format: set echo 0..1|-\n");
    CHECK_STR(run("set cli_idle 29"), "ERR: config: format: set cli_idle 30..3600|-\n");
    CHECK_STR(run("set cli_idle"), "ERR: config: format: set cli_idle 30..3600|-\n");
    CHECK_STR(run("set cli_idle "), "ERR: config: format: set cli_idle 30..3600|-\n");
    CHECK_STR(run("set cli_idle 60 x"), "ERR: config: format: set cli_idle 30..3600|-\n");
    CHECK_STR(run("set cli_idle -1"), "ERR: config: format: set cli_idle 30..3600|-\n");
    CHECK_STR(run("set udp_rate 05"), "ERR: config: format: set udp_rate 1..100|-\n");
    CHECK_STR(run("set"), "ERR: config: format: set KUNCI NILAI\n");
    CHECK_STR(run("set "), "ERR: config: format: set KUNCI NILAI\n");
    CHECK_STR(run("setx"), "(tidak dikenali)");
    CHECK_STR(run("configx"), "(tidak dikenali)");
    CHECK_STR(run("config "), "(tidak dikenali)");
    CHECK(g_writes == 5 && g_cli_idle_s == 3600);

    // gagal tulis (volume baca saja) -> nilai RAM tidak berubah
    g_write_rc = FAT32_ERR_RO;
    CHECK_STR(run("set echo 0"),
              "ERR: config: tidak tersimpan, nilai tidak diubah (fs: volume baca saja)\n");
    CHECK(g_net_echo == 1);
    g_write_rc = 0;

    // file ditolak saat boot -> set menulis ulang utuh dari nilai efektif
    set_file("bogus\n");
    config_load();
    CHECK(g_cli_idle_s == 300);
    CHECK_STR(run("set udp_rate 50"), "OK udp_rate=50 (tersimpan)\n");
    CHECK(strstr(g_file, "cli_idle=300\nudp_rate=50\necho=1\n") && !strstr(g_file, "bogus"));
    CHECK(strncmp(run("config"), "config: sumber=disk\n", 20) == 0);
}

// R2: kunci netconsole.
static void test_netcon_keys(void)
{
    uint32_t v[CFG_NKEYS], line;
    const char *why;

    CHECK(parse("netcon=1\nnetcon_host=254\nnetcon_port=65535\n", v, &line, &why) &&
          v[5] == 1 && v[6] == 254 && v[7] == 65535);
    CHECK(parse("netcon_port=1024\n", v, &line, &why) && v[5] == 0 && v[6] == 1 && v[7] == 1024);
    CHECK(rejected("netcon=2\n", 1, "nilai di luar rentang"));
    CHECK(rejected("netcon_host=0\n", 1, "nilai di luar rentang"));
    CHECK(rejected("netcon_host=255\n", 1, "nilai di luar rentang"));
    CHECK(rejected("netcon_port=1023\n", 1, "nilai di luar rentang"));
    CHECK(rejected("netcon_port=65536\n", 1, "nilai di luar rentang"));
    CHECK(rejected("netcon_port=123456\n", 1, "nilai bukan angka desimal"));

    set_file(NULL);
    config_load();
    CHECK_STR(run("set netcon 1"), "OK netcon=1 (tersimpan)\n");
    CHECK_STR(run("set netcon_host 7"), "OK netcon_host=7 (tersimpan)\n");
    CHECK_STR(run("set netcon_port 17666"), "OK netcon_port=17666 (tersimpan)\n");
    CHECK(g_netcon_on == 1 && g_netcon_host == 7 && g_netcon_port == 17666);
    CHECK(strstr(g_file, "\nnetcon=1\nnetcon_host=7\nnetcon_port=17666\n") != NULL);
    CHECK_STR(run("set netcon_host 255"), "ERR: config: format: set netcon_host 1..254|-\n");
    CHECK_STR(run("set netcon -"), "OK netcon=0 (tersimpan)\n");
    CHECK_STR(run("set netcon_host -"), "OK netcon_host=1 (tersimpan)\n");
    CHECK_STR(run("set netcon_port -"), "OK netcon_port=6666 (tersimpan)\n");
    CHECK(g_netcon_on == 0 && g_netcon_host == 1 && g_netcon_port == 6666);
}

// P3-4: kunci dhcp (0/1, bawaan 0; berlaku saat boot, dibaca dhcp_prepare).
static void test_dhcp_key(void)
{
    uint32_t v[CFG_NKEYS], line;
    const char *why;

    CHECK(parse("dhcp=1\n", v, &line, &why) && v[8] == 1 && v[0] == 300);
    CHECK(parse("netcon=1\n", v, &line, &why) && v[8] == 0);
    CHECK(rejected("dhcp=2\n", 1, "nilai di luar rentang"));
    set_file(NULL);
    config_load();
    CHECK(g_dhcp_cfg == 0);
    CHECK_STR(run("set dhcp 1"), "OK dhcp=1 (tersimpan)\n");
    CHECK(g_dhcp_cfg == 1 && strstr(g_file, "\nnetcon_port=6666\ndhcp=1\n") != NULL);
    serial_capture_reset();
    config_load();
    CHECK(g_dhcp_cfg == 1 && strstr(g_serial_cap, "netcon_port=6666 dhcp=1\r\n") != NULL);
    CHECK_STR(run("set dhcp -"), "OK dhcp=0 (tersimpan)\n");
    CHECK(g_dhcp_cfg == 0);
    CHECK(strstr(run("set dhcpx 1"), "netcon_port dhcp)") != NULL);
}

// D9: cli_plain/udp_admin dan pengaman jalur admin terakhir.
static void test_plain_admin(void)
{
    uint32_t v[CFG_NKEYS], line;
    const char *why;

    CHECK(parse("cli_plain=0\nudp_admin=0\n", v, &line, &why) && v[3] == 0 && v[4] == 0);
    CHECK(rejected("cli_plain=2\n", 1, "nilai di luar rentang"));
    CHECK(rejected("udp_admin=-1\n", 1, "nilai bukan angka desimal"));

    g_tls_on = 1;
    set_file(NULL);
    config_load();
    g_writes = 0;
    CHECK_STR(run("set cli_plain 0"), "OK cli_plain=0 (tersimpan)\n");
    CHECK_STR(run("set udp_admin 0"), "OK udp_admin=0 (tersimpan)\n");
    CHECK(g_cli_plain == 0 && g_udp_admin == 0 && g_writes == 2);
    CHECK(strstr(g_file, "echo=1\ncli_plain=0\nudp_admin=0\n"));

    // TLS hilang (file dihapus saat VM mati): boot memaksa cli_plain=1.
    g_tls_on = 0;
    serial_capture_reset();
    config_load();
    CHECK(g_cli_plain == 1 && g_udp_admin == 0);
    CHECK(strstr(g_serial_cap, "CONFIG: TLS nonaktif, cli_plain dipaksa 1") &&
          strstr(g_serial_cap, "sumber=disk cli_idle=300 udp_rate=20 echo=1 cli_plain=1 "
                               "udp_admin=0 netcon=0 netcon_host=1 netcon_port=6666 dhcp=0\r\n"));

    // Tanpa TLS, set yang menutup jalur terakhir ditolak, tanpa tulis.
    g_writes = 0;
    CHECK_STR(run("set cli_plain 0"),
              "ERR: config: TLS nonaktif, cli_plain=0 + udp_admin=0 menutup semua jalur admin\n");
    CHECK(g_cli_plain == 1 && g_writes == 0);
    CHECK_STR(run("set udp_admin 1"), "OK udp_admin=1 (tersimpan)\n");
    CHECK_STR(run("set cli_plain 0"), "OK cli_plain=0 (tersimpan)\n");
    CHECK_STR(run("set udp_admin 0"),
              "ERR: config: TLS nonaktif, cli_plain=0 + udp_admin=0 menutup semua jalur admin\n");
    CHECK(g_cli_plain == 0 && g_udp_admin == 1);
    CHECK_STR(run("set cli_plain -"), "OK cli_plain=1 (tersimpan)\n");
    g_tls_on = 1;
    set_file(NULL);
    config_load();
}

#ifndef BMAHOS_FUZZ   // R7: tests/fuzz/fuzz_config.c memakai helper file ini
int main(void)
{
    test_parse();
    test_load();
    test_set();
    test_plain_admin();
    test_netcon_keys();
    test_dhcp_key();
    return test_done("config");
}
#endif

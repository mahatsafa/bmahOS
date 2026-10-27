// P4: fuzz filter.c dengan stub tests/host/test_filter.c. Byte 0 = mode:
//   0 filter_parse(data) (isi FILTER.CFG): tiap aturan yang diterima ditulis
//     kanonik (flt_fmt), diparse lagi, ditulis lagi -> teks sama
//   1 filter_execute(data) (perintah filter ...) dengan file awal kosong
//   2 aturan tetap dari FILTER.CFG lalu filter_ipv4(data) sebagai frame
//     Ethernet + IPv4 (ihl/panjang dicek seperti net.c)
// Invarian: aturan <= FILTER_MAX; keluaran perintah <= CMD_OUT_MAX; file yang
// ditulis perintah terbaca ulang dengan jumlah aturan yang sama; filter_ipv4
// hanya 0/1 dan SYN TCP ke port 7780 selalu lolos.

#include "test_filter.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

static const char g_fz_rules[] =
    "# aturan uji fuzz\n"
    "izinkan tcp 192.168.50.1/32 port 7779\n"
    "tolak udp 192.168.50.0/24 port 7777-7778\n"
    "izinkan icmp semua laju 5\n"
    "tolak tcp semua\n"
    "tolak semua 10.0.0.0/8\n";

static void fz_parse(const uint8_t *b, size_t n)
{
    static filter_rule_t out[FILTER_MAX];
    uint32_t cnt = 0, bad = 0;
    const char *why = 0;

    if (!filter_parse(b, (uint32_t)n, out, &cnt, &bad, &why)) {
        FUZZ_ASSERT(why != 0 && bad >= 1);
        return;
    }
    FUZZ_ASSERT(cnt <= FILTER_MAX);
    for (uint32_t i = 0; i < cnt; i++) {
        char t1[96], t2[96];
        filter_rule_t r;
        flt_fmt(&out[i], t1, sizeof(t1));
        FUZZ_ASSERT(filter_parse_rule((const uint8_t *)t1, (uint32_t)strlen(t1), &r, &why));
        flt_fmt(&r, t2, sizeof(t2));
        FUZZ_ASSERT(strcmp(t1, t2) == 0);
    }
}

static void fz_exec(const uint8_t *b, size_t n)
{
    set_file(NULL);
    filter_load();
    g_cmd_len = 0;
    filter_execute(b, (uint32_t)n);
    FUZZ_ASSERT(g_cmd_len <= CMD_OUT_MAX && g_filter_n <= FILTER_MAX);
    if (g_file_len >= 0) {
        static filter_rule_t out[FILTER_MAX];
        uint32_t cnt = 0, bad = 0;
        const char *why = 0;
        FUZZ_ASSERT(filter_parse((const uint8_t *)g_file, (uint32_t)g_file_len, out, &cnt, &bad,
                                 &why) && cnt == g_filter_n);
    }
}

static void fz_ipv4(const uint8_t *b, size_t n)
{
    set_file(g_fz_rules);
    filter_load();
    FUZZ_ASSERT(g_filter_n == 5);
    if (n < 34) {
        return;
    }
    uint32_t ihl = (uint32_t)(b[14] & 0x0F) * 4;
    uint32_t tot = (uint32_t)b[16] << 8 | b[17];
    if (ihl < 20 || tot < ihl || 14 + tot > n) {
        return;
    }
    uint32_t pl = tot - ihl;
    int r = filter_ipv4(b, ihl, pl);
    FUZZ_ASSERT(r == 0 || r == 1);
    const uint8_t *l4 = b + 14 + ihl;
    if (b[23] == 6 && pl >= 20 && (l4[13] & 0x12) == 0x02 && (l4[2] << 8 | l4[3]) == 7780) {
        FUZZ_ASSERT(r == 1);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 1) {
        return 0;
    }
    size_t xn = n - 1;
    uint8_t *b = malloc(xn ? xn : 1);
    memcpy(b, d + 1, xn);
    timer_ticks += 37;   // jendela laju aturan ikut bergerak antar input
    if (d[0] % 3 == 0) {
        fz_parse(b, xn);
    } else if (d[0] % 3 == 1) {
        fz_exec(b, xn);
    } else {
        fz_ipv4(b, xn);
    }
    free(b);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const char *const s[] = {
        "\0izinkan semua semua\ntolak udp 192.168.50.66 port 7777\n",
        "\0tolak tcp 10.0.0.0/8 port 1-1024\r\nizinkan icmp semua laju 5\n\n# k\n",
        "\0  tolak   udp   semua  \ntolak udp 1.2.3.4/32\n",
        "\1filter tambah tolak udp 192.168.50.99 port 7777",
        "\1filter hapus 1",
        "\1filter kosong",
        "\1filter",
    };
    for (size_t i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
        char name[16];
        snprintf(name, sizeof(name), "flt%zu", i);
        fuzz_seed(dir, name, s[i], 1 + strlen(s[i] + 1));
    }
    // Frame: SYN TCP ke 7780 dan 7779, UDP 7777 dari .5, ICMP dari .1.
    static const uint8_t ip5[4] = { 192, 168, 50, 5 }, ip1[4] = { 192, 168, 50, 1 };
    uint8_t f[1 + 64];
    f[0] = 2;
    mk_frame(6, ip5, 7780, 0x02);
    g_frame[16] = 0;
    g_frame[17] = 40;
    memcpy(f + 1, g_frame, 64);
    fuzz_seed(dir, "syn7780", f, sizeof(f));
    mk_frame(6, ip1, 7779, 0x02);
    g_frame[17] = 40;
    memcpy(f + 1, g_frame, 64);
    fuzz_seed(dir, "syn7779", f, sizeof(f));
    mk_frame(17, ip5, 7777, 0);
    g_frame[17] = 28;
    memcpy(f + 1, g_frame, 64);
    fuzz_seed(dir, "udp7777", f, sizeof(f));
    mk_frame(1, ip1, 0, 0);
    g_frame[17] = 28;
    memcpy(f + 1, g_frame, 64);
    fuzz_seed(dir, "icmp", f, sizeof(f));
}

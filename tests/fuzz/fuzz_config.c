// R7: fuzz config.c dengan stub dari tests/host/test_config.c. Byte 0 = mode:
//   0 config_parse(data)   1 config_load dengan CONFIG.CFG = data
//   2 config_execute(data) (perintah config/set, file awal = bawaan)
// Invarian: nilai yang diterima selalu di dalam [min, max] kuncinya.

#include "test_config.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

static void fz_check_vals(const uint32_t *v)
{
    for (int k = 0; k < CFG_NKEYS; k++) {
        FUZZ_ASSERT(v[k] >= g_cfg_keys[k].min && v[k] <= g_cfg_keys[k].max);
    }
}

static void fz_check_live(void)
{
    uint32_t v[CFG_NKEYS];
    for (int k = 0; k < CFG_NKEYS; k++) {
        v[k] = *g_cfg_keys[k].var;
    }
    fz_check_vals(v);
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 1) {
        return 0;
    }
    const uint8_t *x = d + 1;
    size_t xn = n - 1;
    uint8_t *b = malloc(xn ? xn : 1);
    memcpy(b, x, xn);

    g_read_rc = g_write_rc = 0;
    g_tls_on = 1;
    if (d[0] % 3 == 0) {
        uint32_t v[CFG_NKEYS], line = 0;
        const char *why = 0;
        if (config_parse(b, (uint32_t)xn, v, &line, &why)) {
            fz_check_vals(v);
        } else {
            FUZZ_ASSERT(why != 0);
        }
    } else if (d[0] % 3 == 1) {
        g_file_len = xn < sizeof(g_file) ? (int)xn : (int)sizeof(g_file);
        memcpy(g_file, x, (size_t)g_file_len);
        config_load();
        fz_check_live();
    } else {
        set_file(NULL);
        config_load();
        g_cmd_len = 0;
        config_execute(b, (uint32_t)xn);
        FUZZ_ASSERT(g_cmd_len <= CMD_OUT_MAX);
        fz_check_live();
        if (g_file_len >= 0) {
            // Yang ditulis set harus bisa dibaca ulang.
            uint32_t v[CFG_NKEYS], line = 0;
            const char *why = 0;
            FUZZ_ASSERT(config_parse((const uint8_t *)g_file, (uint32_t)g_file_len, v, &line,
                                     &why));
        }
    }
    free(b);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const char *const s[] = {
        "\0# komentar\ncli_idle=600\nudp_rate=5\necho=0\n",
        "\0" NC_DEF "cli_plain=1\nudp_admin=0\n",
        "\0cli_idle=29\n",
        "\0cli_idle=600\r\nudp_rate = 7\n\n",
        "\1cli_idle=600\nnetcon=1\nnetcon_host=20\nnetcon_port=7000\n",
        "\1cli_idle=abc\n",
        "\2config",
        "\2set cli_idle 600",
        "\2set netcon_port 65535",
        "\2set cli_plain 0",
        "\2set udp_admin -",
    };
    for (size_t i = 0; i < sizeof(s) / sizeof(s[0]); i++) {
        char name[16];
        snprintf(name, sizeof(name), "cfg%zu", i);
        fuzz_seed(dir, name, s[i], 1 + strlen(s[i] + 1));
    }
}

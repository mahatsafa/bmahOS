// P3-3: fuzz dns_rx (balasan DNS dari LAN) dengan stub tests/host/test_dns.c.
// Byte 0 = mode: bit 0 query milik pemantau (dns_probe_start, P6-2) bukan
// perintah `dns`, bit 1 perbaiki ID, bit 2 salin pertanyaan dari query (supaya
// bagian answer ikut teruji), bit 3 flag balasan sah (QR, RD/RA, opcode 0).
// Sisa = isi UDP dari server.
// Invarian: keadaan diam (selesai) atau masih menunggu; entri cache: nama
// 1..63 byte, kedaluwarsa dalam TTL 5..3600 s (negatif tepat 60 s); query
// pemantau yang selesai dilaporkan tepat sekali dan a = 1 hanya bila ada
// entri positif.

#include "test_dns.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    dns_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 1) {
        return 0;
    }
    uint8_t m = d[0];
    size_t xn = n - 1;
    uint8_t *b = malloc(xn ? xn : 1);
    memcpy(b, d + 1, xn);

    reset();
    g_md_n = 0;
    if (m & 1) {
        if (dns_probe_start("bmahos.uji", 1, 53, 7) != 0 || !pump()) {
            free(b);
            return 0;
        }
    } else if (!start("dns bmahos.uji")) {
        free(b);
        return 0;
    }
    if ((m & 2) && xn >= 2) {
        b[0] = g_dns_q[0];
        b[1] = g_dns_q[1];
    }
    if ((m & 4) && xn >= g_dns_qlen) {
        memcpy(b + 4, g_dns_q + 4, 2);    // QDCOUNT
        memcpy(b + 12, g_dns_q + 12, g_dns_qlen - 12);
    }
    if ((m & 8) && xn >= 4) {
        b[2] = 0x81;
        b[3] = (uint8_t)(0x80 | (b[3] & 0x0F));
    }
    dns_rx(b, (uint32_t)xn);

    FUZZ_ASSERT(g_dns_state == DNS_IDLE || g_dns_state == DNS_SENT);
    int pos = 0;
    for (int i = 0; i < DNS_CACHE; i++) {
        const dns_entry_t *e = &g_dns_cache[i];
        if (!e->name[0]) {
            continue;
        }
        size_t nl = strnlen(e->name, sizeof(e->name));
        uint64_t left = e->expires - timer_ticks;
        FUZZ_ASSERT(nl >= 1 && nl <= DNS_NAME_MAX);
        if (e->neg) {
            FUZZ_ASSERT(left == (uint64_t)DNS_NEG_TTL * 100);
        } else {
            FUZZ_ASSERT(left >= (uint64_t)DNS_TTL_MIN * 100 && left <= (uint64_t)DNS_TTL_MAX * 100);
            pos = 1;
        }
    }
    if (m & 1) {
        FUZZ_ASSERT(g_md_n == (g_dns_state == DNS_IDLE ? 1 : 0));
        FUZZ_ASSERT(g_md_n == 0 || g_md_tok == 7);
        FUZZ_ASSERT(g_md_n == 0 || !g_md_a || pos);
    } else {
        FUZZ_ASSERT(g_md_n == 0);
    }
    free(b);
    return 0;
}

void fuzz_seeds(const char *dir)
{
    static const uint8_t ip[4] = { 192, 168, 50, 123 };
    static const uint8_t cname[] = { 3, 'w', 'w', 'w', 0xC0, 0x0C };
    uint8_t buf[sizeof(g_r) + 1];

    reset();
    if (!start("dns bmahos.uji")) {
        return;
    }
    // A lewat pointer, NXDOMAIN, CNAME lalu A, pointer melingkar, TTL ekstrem.
    rep_begin(0x8180, 1);
    rep_rr(PTR_Q, 2, 1, 300, ip, 4);
    buf[0] = 2 | 4 | 8;
    memcpy(buf + 1, g_r, g_rl);
    fuzz_seed(dir, "a", buf, g_rl + 1);
    buf[0] = 1 | 2 | 4 | 8;
    fuzz_seed(dir, "a-pantau", buf, g_rl + 1);
    rep_begin(0x8183, 0);
    buf[0] = 2 | 4;
    memcpy(buf + 1, g_r, g_rl);
    fuzz_seed(dir, "nx", buf, g_rl + 1);
    rep_begin(0x8180, 2);
    rep_rr(PTR_Q, 2, 5, 60, cname, sizeof(cname));
    rep_rr(cname, sizeof(cname), 1, 0xFFFFFFFFu, ip, 4);
    buf[0] = 2 | 4 | 8;
    memcpy(buf + 1, g_r, g_rl);
    fuzz_seed(dir, "cname", buf, g_rl + 1);
    rep_begin(0x8180, 1);
    static const uint8_t loop[2] = { 0xC0, 0x0E };
    rep_rr(loop, 2, 1, 1, ip, 4);
    buf[0] = 2 | 4 | 8;
    memcpy(buf + 1, g_r, g_rl);
    fuzz_seed(dir, "loop", buf, g_rl + 1);
}

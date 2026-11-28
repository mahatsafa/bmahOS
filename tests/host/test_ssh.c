// F7 SSH-1a: uji ssh.c (di-#include: akses static). Klien uji di sini menulis ulang sisi klien
// transport SSH-2 (kex curve25519, GCM, turunan kunci) memakai primitif BearSSL yang sama; itu
// bisa salah dengan cara yang sama dengan server, karena itu ada uji interop OpenSSH sungguhan
// (tests/ssh-interop.sh) dan vektor RFC 7748 di sini.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "bearssl.h"
#include "tls_test_keys.h"
#include "../../kernel/ssh.c"

// ---- stub entropi ----
static int g_ent_ok = 1;
static uint32_t g_ent_ctr;

int entropy_get(uint8_t *out, uint32_t len)
{
    if (!g_ent_ok) {
        return 0;
    }
    g_ent_ctr++;
    for (uint32_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(g_ent_ctr * 131 + i * 17 + 7);
    }
    return 1;
}

// ---- klien uji ----
typedef struct {
    int s;
    uint8_t rx[70000];
    uint32_t rxn, rxpos;
    uint8_t pl[36000];
    uint32_t pln;
    int enc_out, enc_in;
    br_aes_ct64_ctr_keys ko, ki;
    br_gcm_context go, gi;
    uint8_t ivo[12], ivi[12];
    uint32_t seq_out, seq_in;
    int strict;
    uint8_t vs[256];
    uint32_t vsn;
    uint8_t is[512];
    uint32_t isn;
    uint8_t ic[512];
    uint32_t icn;
    uint8_t x[32], qc[32];
} cl_t;

static cl_t C;
static uint32_t g_chunk;   // 0 = sekaligus

static void cl_drain(cl_t *c)
{
    uint32_t n;
    const uint8_t *p = ssh_out_peek(c->s, &n);

    if (n > 0 && c->rxn + n <= sizeof(c->rx)) {
        memcpy(c->rx + c->rxn, p, n);
        c->rxn += n;
        ssh_out_consume(c->s, n);
    }
}

// Suap ke server; kuras keluaran di antaranya. Return byte yang diterima server.
static uint32_t cl_feed(cl_t *c, const uint8_t *d, uint32_t n)
{
    uint32_t done = 0;
    int stall = 0;

    while (done < n) {
        uint32_t step = n - done;

        if (g_chunk && step > g_chunk) {
            step = g_chunk;
        }
        uint32_t k = ssh_feed(c->s, d + done, step);

        cl_drain(c);
        if (k == 0) {
            if (++stall > 3) {
                break;
            }
        } else {
            stall = 0;
        }
        done += k;
    }
    return done;
}

static int g_force_pad = -1;       // >= 0: paksa byte padding_length dan plen (uji paket cacat)
static uint32_t g_force_plen;

static uint32_t cl_build(cl_t *c, const uint8_t *pl, uint32_t n, uint8_t *out)
{
    uint32_t blk = c->enc_out ? 16 : 8;
    uint32_t pad = blk - ((c->enc_out ? 1 + n : 5 + n) % blk);

    if (pad < 4) {
        pad += blk;
    }
    uint32_t plen = 1 + n + pad;

    if (g_force_pad >= 0) {
        pad = (uint32_t)g_force_pad;
        plen = g_force_plen;
        memset(out, 0, 4 + plen + 16);
    }

    put32(out, plen);
    out[4] = (uint8_t)pad;
    memcpy(out + 5, pl, n);
    if (g_force_pad < 0) {
        memset(out + 5 + n, 0xA5, pad);
    }
    uint32_t total = 4 + plen;

    if (c->enc_out) {
        br_gcm_reset(&c->go, c->ivo, 12);
        br_gcm_aad_inject(&c->go, out, 4);
        br_gcm_flip(&c->go);
        br_gcm_run(&c->go, 1, out + 4, plen);
        br_gcm_get_tag(&c->go, out + 4 + plen);
        total += 16;
        for (int i = 11; i >= 4; i--) {
            if (++c->ivo[i] != 0) {
                break;
            }
        }
    }
    c->seq_out++;
    return total;
}

static uint8_t g_pktbuf[36100];

static void cl_send(cl_t *c, const uint8_t *pl, uint32_t n)
{
    uint32_t t = cl_build(c, pl, n, g_pktbuf);

    cl_feed(c, g_pktbuf, t);
}

static void cl_send_msg(cl_t *c, uint8_t m)
{
    cl_send(c, &m, 1);
}

// Satu paket dari server -> c->pl (pesan di pl[0]); return panjang payload, -1 belum lengkap,
// -2 tag/format salah.
static int cl_recv(cl_t *c)
{
    uint32_t avail = c->rxn - c->rxpos;
    uint8_t *p = c->rx + c->rxpos;

    if (avail < 4) {
        return -1;
    }
    uint32_t plen = get32(p);
    uint32_t total = 4 + plen + (c->enc_in ? 16 : 0);

    if (plen > SSH_PKT_MAX || plen < 6) {
        return -2;
    }
    if (avail < total) {
        return -1;
    }
    if (c->enc_in) {
        br_gcm_reset(&c->gi, c->ivi, 12);
        br_gcm_aad_inject(&c->gi, p, 4);
        br_gcm_flip(&c->gi);
        br_gcm_run(&c->gi, 0, p + 4, plen);
        if (br_gcm_check_tag(&c->gi, p + 4 + plen) == 0) {
            return -2;
        }
        for (int i = 11; i >= 4; i--) {
            if (++c->ivi[i] != 0) {
                break;
            }
        }
    }
    uint32_t pad = p[4];

    if (pad + 2 > plen) {
        return -2;
    }
    uint32_t pl = plen - 1 - pad;

    memcpy(c->pl, p + 5, pl);
    c->pln = pl;
    c->rxpos += total;
    c->seq_in++;
    return (int)pl;
}

// Baca satu paket; return pesan (byte pertama) atau -1.
static int cl_msg(cl_t *c)
{
    cl_drain(c);
    int r = cl_recv(c);

    return r > 0 ? c->pl[0] : (r == -2 ? -2 : -1);
}

// Kuras semua paket yang menunggu; hitung pesan bertipe m, simpan pesan terakhir.
static int cl_count(cl_t *c, uint8_t m, int *last)
{
    int n = 0;

    cl_drain(c);
    for (;;) {
        int r = cl_recv(c);

        if (r <= 0) {
            break;
        }
        if (c->pl[0] == m) {
            n++;
        }
        if (last) {
            *last = c->pl[0];
        }
    }
    return n;
}

static void cl_new(cl_t *c)
{
    memset(c, 0, sizeof(*c));
    c->s = ssh_open();
}

// ---- KEXINIT klien ----
static uint32_t cl_kexinit(cl_t *c_unused, const char *kex, const char *hk, const char *cip, const char *comp,
                           int follows, uint8_t *out)
{
    (void)c_unused;
    wr_t w = { out, 0, 600, 0 };

    w_u8(&w, M_KEXINIT);
    for (int i = 0; i < 16; i++) {
        w_u8(&w, (uint8_t)(0x40 + i));
    }
    w_cstr(&w, kex);
    w_cstr(&w, hk);
    w_cstr(&w, cip);
    w_cstr(&w, cip);
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, comp);
    w_cstr(&w, comp);
    w_cstr(&w, "");
    w_cstr(&w, "");
    w_u8(&w, (uint8_t)follows);
    w_u32(&w, 0);
    return w.n;
}

#define KEX_STRICT "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com"
#define KEX_PLAIN  "curve25519-sha256,ext-info-c"

// Baca baris banner server dari rx (sampai LF); return 1 bila ada.
static int cl_banner(cl_t *c)
{
    cl_drain(c);
    for (uint32_t i = c->rxpos; i < c->rxn; i++) {
        if (c->rx[i] == '\n') {
            uint32_t n = i - c->rxpos;

            if (n > 0 && c->rx[i - 1] == '\r') {
                n--;
            }
            memcpy(c->vs, c->rx + c->rxpos, n);
            c->vsn = n;
            c->rxpos = i + 1;
            return 1;
        }
    }
    return 0;
}

static const char CLIENT_BANNER[] = "SSH-2.0-OpenSSH_9.9 ujiklien";

static void cl_send_banner(cl_t *c)
{
    cl_feed(c, (const uint8_t *)CLIENT_BANNER, sizeof(CLIENT_BANNER) - 1);
    cl_feed(c, (const uint8_t *)"\r\n", 2);
}

// Sampai KEXINIT klien terkirim dan KEXINIT server terbaca (simpan I_S, I_C).
static int cl_hello(cl_t *c, const char *kex, const char *cip, const char *comp, int follows)
{
    uint8_t ki[600];

    if (!cl_banner(c)) {
        return 0;
    }
    cl_send_banner(c);
    if (cl_msg(c) != M_KEXINIT) {
        return 0;
    }
    memcpy(c->is, c->pl, c->pln);
    c->isn = c->pln;
    uint32_t n = cl_kexinit(c, kex, "ecdsa-sha2-nistp256", cip, comp, follows, ki);

    memcpy(c->ic, ki, n);
    c->icn = n;
    c->strict = strstr(kex, "kex-strict-c") != 0;
    cl_send(c, ki, n);
    return 1;
}

// Kex penuh: dari KEXINIT klien sampai NEWKEYS dua arah. Return 1 bila sukses dan tanda
// tangan + fingerprint terverifikasi. qc_override: kirim Q_C ini (32 byte) bukan hasil x25519.
static uint8_t g_last_k[32];      // rahasia bersama klien terakhir (uji: tidak boleh ada di g_ssh)
static uint8_t g_last_h[32];
static uint8_t g_last_ks[160];
static uint32_t g_last_ksn;
static uint8_t g_last_qs[32];
static uint8_t g_sig_r[33], g_sig_s[33];   // r,s mentah (isi mpint) dari tanda tangan terakhir
static uint32_t g_sig_rn, g_sig_sn;
static int g_sig_canon = 1;                // semua mpint tanda tangan kanonik (RFC 4251 5)

// mpint kanonik: tanpa nol di depan yang tidak perlu, tanpa bit tinggi (positif), tidak kosong.
static int mpint_canon(const uint8_t *v, uint32_t n)
{
    if (n == 0 || (v[0] & 0x80)) {
        return 0;
    }
    return !(n > 1 && v[0] == 0 && !(v[1] & 0x80));
}

static void cl_dh_init(cl_t *c)
{
    uint8_t m[200];
    wr_t w = { m, 0, sizeof(m), 0 };

    for (int i = 0; i < 32; i++) {
        c->x[i] = (uint8_t)(0x11 * (i + 3) + c->s);
    }
    x25519(c->qc, c->x, k_x25519_base);
    w_u8(&w, M_KEXDH_INIT);
    w_str(&w, c->qc, 32);
    cl_send(c, m, w.n);
}

static int cl_kex_finish(cl_t *c);

static int cl_kex(cl_t *c)
{
    cl_dh_init(c);
    return cl_kex_finish(c);
}

// Setelah KEXDH_INIT terkirim: baca REPLY + NEWKEYS, verifikasi, turunkan kunci, kirim NEWKEYS.
static int cl_kex_finish(cl_t *c)
{
    if (cl_msg(c) != M_KEXDH_REPLY) {
        return 0;
    }
    rd_t r = { c->pl + 1, c->pln - 1, 0 };
    uint32_t ksn, qsn, sgn;
    const uint8_t *ks = r_str(&r, &ksn);
    const uint8_t *qs = r_str(&r, &qsn);
    const uint8_t *sg = r_str(&r, &sgn);

    if (r.err || r.n != 0 || qsn != 32) {
        return 0;
    }
    if (cl_msg(c) != M_NEWKEYS) {
        return 0;
    }
    // fingerprint dari K_S sama dengan ssh_fingerprint()
    char fp[56];
    uint8_t dg[32];
    br_sha256_context hc;

    br_sha256_init(&hc);
    br_sha256_update(&hc, ks, ksn);
    br_sha256_out(&hc, dg);
    memcpy(fp, "SHA256:", 7);
    b64_nopad(dg, 32, fp + 7);
    if (strcmp(fp, ssh_fingerprint()) != 0) {
        return 0;
    }
    // K dan H
    uint8_t k[32];

    memcpy(k, qs, 32);
    memcpy(g_last_qs, qs, 32);
    g_last_ksn = ksn < sizeof(g_last_ks) ? ksn : sizeof(g_last_ks);
    memcpy(g_last_ks, ks, g_last_ksn);
    // klien: K = x25519(x_c, Q_S)
    if (!x25519(k, c->x, qs)) {
        return 0;
    }
    memcpy(g_last_k, k, 32);
    uint8_t kmp[40];
    wr_t kw = { kmp, 0, sizeof(kmp), 0 };

    w_mpint(&kw, k, 32);
    uint8_t hbuf[1400];
    wr_t hw = { hbuf, 0, sizeof(hbuf), 0 };

    w_str(&hw, CLIENT_BANNER, sizeof(CLIENT_BANNER) - 1);
    w_str(&hw, c->vs, c->vsn);
    w_str(&hw, c->ic, c->icn);
    w_str(&hw, c->is, c->isn);
    w_str(&hw, ks, ksn);
    w_str(&hw, c->qc, 32);
    w_str(&hw, qs, 32);
    w_bytes(&hw, kmp, kw.n);
    uint8_t h[32];

    br_sha256_init(&hc);
    br_sha256_update(&hc, hbuf, hw.n);
    br_sha256_out(&hc, h);
    memcpy(g_last_h, h, 32);

    // tanda tangan: string "ecdsa-sha2-nistp256", string (mpint r, mpint s)
    rd_t sr = { sg, sgn, 0 };
    uint32_t an, bn;
    const uint8_t *alg = r_str(&sr, &an);
    const uint8_t *rs = r_str(&sr, &bn);

    if (sr.err || !tok_eq(alg, an, "ecdsa-sha2-nistp256")) {
        return 0;
    }
    rd_t rr = { rs, bn, 0 };
    uint32_t rn, sn;
    const uint8_t *rv = r_str(&rr, &rn);
    const uint8_t *sv = r_str(&rr, &sn);

    if (rr.err || rn > 33 || sn > 33 || rr.n != 0) {
        return 0;
    }
    g_sig_canon = mpint_canon(rv, rn) && mpint_canon(sv, sn);
    memcpy(g_sig_r, rv, rn);
    memcpy(g_sig_s, sv, sn);
    g_sig_rn = rn;
    g_sig_sn = sn;
    uint8_t sig[64];

    memset(sig, 0, sizeof(sig));
    while (rn > 32) {
        rv++;
        rn--;
    }
    while (sn > 32) {
        sv++;
        sn--;
    }
    memcpy(sig + 32 - rn, rv, rn);
    memcpy(sig + 64 - sn, sv, sn);
    br_ec_public_key pk;

    pk.curve = BR_EC_secp256r1;
    pk.q = (uint8_t *)(ks + ksn - 65);
    pk.qlen = 65;
    br_sha256_init(&hc);
    br_sha256_update(&hc, h, 32);
    br_sha256_out(&hc, dg);
    if (br_ecdsa_i31_vrfy_raw(&br_ec_p256_m64, dg, 32, &pk, sig, 64) != 1) {
        return 0;
    }
    // kunci klien: masuk = s2c (B, D), keluar = c2s (A, C)
    uint8_t iv_c[32], iv_s[32], key_c[32], key_s[32];

    kdf32(kmp, kw.n, h, 'A', h, iv_c);
    kdf32(kmp, kw.n, h, 'B', h, iv_s);
    kdf32(kmp, kw.n, h, 'C', h, key_c);
    kdf32(kmp, kw.n, h, 'D', h, key_s);
    c->seq_in = c->strict ? 0 : c->seq_in;
    cl_send_msg(c, M_NEWKEYS);
    if (c->strict) {
        c->seq_out = 0;
    }
    br_aes_ct64_ctr_init(&c->ko, key_c, 16);
    br_gcm_init(&c->go, &c->ko.vtable, br_ghash_ctmul64);
    memcpy(c->ivo, iv_c, 12);
    br_aes_ct64_ctr_init(&c->ki, key_s, 16);
    br_gcm_init(&c->gi, &c->ki.vtable, br_ghash_ctmul64);
    memcpy(c->ivi, iv_s, 12);
    c->enc_out = 1;
    c->enc_in = 1;
    return 1;
}

// ---- helper pengujian ----

static void setup_key(void)
{
    ssh_unload_key();
    CHECK(ssh_load_key(T_KEYA, sizeof(T_KEYA)) == 1);
}

static void reset_all(void)
{
    for (int i = 0; i < SSH_MAX_SESS; i++) {
        ssh_close(i);
    }
    g_ent_ok = 1;
    g_chunk = 0;
    g_force_pad = -1;
    g_ssh_unimpl_max = SSH_UNIMPL_MAX;
}

static int start(int strict)
{
    cl_new(&C);
    if (C.s < 0) {
        return 0;
    }
    return cl_hello(&C, strict ? KEX_STRICT : KEX_PLAIN, "aes128-gcm@openssh.com", "none,zlib@openssh.com", 0);
}

static int full(int strict)
{
    return start(strict) && cl_kex(&C);
}

static int disc_seen(cl_t *c)
{
    int last = 0;

    cl_count(c, M_DISCONNECT, &last);
    return last == M_DISCONNECT;
}

static int hex2(const char *h, uint8_t *o)
{
    return (int)test_unhex(h, o, 64);
}

static void x25519_hex(const char *k, const char *u, const char *want)
{
    uint8_t kb[32], ub[32], out[32];

    hex2(k, kb);
    hex2(u, ub);
    CHECK(x25519(out, kb, ub) == 1);
    CHECK(test_hex_eq(out, 32, want));
}

static void test_x25519(void)
{
    // RFC 7748 5.2
    x25519_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
               "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
               "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    x25519_hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
               "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
               "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    // RFC 7748 5.2: satu iterasi (k = u = 9)
    uint8_t nine[32] = { 9 }, out[32];

    CHECK(x25519(out, nine, nine) == 1);
    CHECK(test_hex_eq(out, 32, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
    // RFC 7748 6.1: Diffie-Hellman Alice/Bob
    uint8_t a[32], b[32], pa[32], pb[32], s1[32], s2[32];

    hex2("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
    hex2("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
    CHECK(x25519(pa, a, k_x25519_base) == 1);
    CHECK(x25519(pb, b, k_x25519_base) == 1);
    CHECK(test_hex_eq(pa, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    CHECK(test_hex_eq(pb, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    CHECK(x25519(s1, a, pb) == 1);
    CHECK(x25519(s2, b, pa) == 1);
    CHECK(test_hex_eq(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    CHECK(memcmp(s1, s2, 32) == 0);
}

static void test_key(void)
{
    ssh_unload_key();
    CHECK(!ssh_key_loaded());
    CHECK_STR(ssh_fingerprint(), "");
    CHECK(ssh_open() == SSH_ERR_NOKEY);
    uint8_t junk[40] = { 1, 2, 3 };

    CHECK(ssh_load_key(junk, sizeof(junk)) == 0);
    CHECK(ssh_load_key(junk, 0) == 0);
    CHECK(ssh_load_key(T_KEYA, 60) == 0);                    // terpotong
    CHECK(ssh_load_key(T_CERTA, sizeof(T_CERTA)) == 0);      // bukan kunci
    CHECK(!ssh_key_loaded());
    CHECK(ssh_load_key(T_KEYA, sizeof(T_KEYA)) == 1);
    char fp1[56];
    strcpy(fp1, ssh_fingerprint());
    CHECK(strncmp(fp1, "SHA256:", 7) == 0 && strlen(fp1) == 7 + 43 && strchr(fp1, '=') == 0);
    CHECK(ssh_load_key(T_KEYA8, sizeof(T_KEYA8)) == 1);      // PKCS#8, kunci sama
    CHECK_STR(ssh_fingerprint(), fp1);
    CHECK(ssh_load_key(T_KEYB, sizeof(T_KEYB)) == 1);
    CHECK(strcmp(ssh_fingerprint(), fp1) != 0);
    CHECK(ssh_load_key(junk, sizeof(junk)) == 0 && !ssh_key_loaded() && ssh_open() == SSH_ERR_NOKEY);
    setup_key();
}

static const void *mm(const uint8_t *h, uint32_t hn, const char *nd, uint32_t nn)
{
    for (uint32_t i = 0; i + nn <= hn; i++) {
        if (memcmp(h + i, nd, nn) == 0) {
            return h + i;
        }
    }
    return 0;
}

static void test_banner(void)
{
    reset_all();
    cl_new(&C);
    CHECK(C.s == 0 && ssh_state(C.s) == SSH_ST_VERSION);
    CHECK(cl_banner(&C));
    CHECK(C.vsn == strlen("SSH-2.0-bmahOS_" SSH_VERSION) && memcmp(C.vs, "SSH-2.0-bmahOS_", 15) == 0);
    CHECK(cl_msg(&C) == M_KEXINIT);
    CHECK(C.pln > 100 && C.pln <= 512);
    // daftar algoritme yang diiklankan
    CHECK(mm(C.pl, C.pln, "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com", 75) != 0);
    CHECK(mm(C.pl, C.pln, "aes128-gcm@openssh.com", 22) != 0);
    CHECK(mm(C.pl, C.pln, "chacha20", 8) == 0);
    CHECK(mm(C.pl, C.pln, "hmac-sha2-256", 13) != 0);
    ssh_close(C.s);

    // banner dengan LF saja, dan baris sebelum banner (8 boleh)
    for (int mode = 0; mode < 5; mode++) {
        cl_new(&C);
        cl_banner(&C);
        const char *b;
        int ok = 1;

        switch (mode) {
        case 0: b = "SSH-2.0-x\n"; break;
        case 1: b = "a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\nh\r\nSSH-2.0-x\r\n"; break;           // 8 baris
        case 2: b = "a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\nh\r\ni\r\nSSH-2.0-x\r\n"; ok = 0; break;  // 9
        case 3: b = "SSH-1.99-x\r\n"; ok = 0; break;
        default: b = "SSH-2.0-a\0b\r\n"; ok = 0; break;
        }
        cl_feed(&C, (const uint8_t *)b, mode == 4 ? 14 : (uint32_t)strlen(b));
        CHECK((ssh_state(C.s) == SSH_ST_KEX) == ok);
        CHECK((ssh_state(C.s) == SSH_ST_CLOSING) == !ok);
        if (!ok) {
            CHECK(ssh_done(C.s));   // versi salah: tidak ada paket DISCONNECT, keluaran habis
        }
        ssh_close(C.s);
    }
    // baris > 255 byte tanpa LF
    cl_new(&C);
    cl_banner(&C);
    uint8_t big[300];

    memset(big, 'x', sizeof(big));
    memcpy(big, "SSH-2.0-", 8);
    cl_feed(&C, big, sizeof(big));
    CHECK(ssh_state(C.s) == SSH_ST_CLOSING);
    // tepat 255 byte termasuk CRLF masih sah
    ssh_close(C.s);
    cl_new(&C);
    cl_banner(&C);
    memset(big, 'x', sizeof(big));
    memcpy(big, "SSH-2.0-", 8);
    big[253] = '\r';
    big[254] = '\n';
    cl_feed(&C, big, 255);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    ssh_close(C.s);
    // satu byte per feed
    cl_new(&C);
    g_chunk = 1;
    cl_banner(&C);
    cl_send_banner(&C);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    g_chunk = 0;
    ssh_close(C.s);
}

static void test_kex(int strict, int chunk)
{
    reset_all();
    g_chunk = (uint32_t)chunk;
    CHECK(full(strict));
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE && ssh_cipher_active(C.s));
    // layanan
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    CHECK(cl_msg(&C) == M_SVC_ACCEPT && ssh_state(C.s) == SSH_ST_AUTH);
    ssh_close(C.s);
    g_chunk = 0;
}

static void test_kex_all(void)
{
    test_kex(0, 0);
    test_kex(1, 0);
    test_kex(1, 1);    // satu byte per feed
    test_kex(0, 1);
    test_kex(1, 7);
    // dua sesi bersamaan menghasilkan session_id berbeda
    reset_all();
    CHECK(full(1));
    uint8_t sid0[32];

    memcpy(sid0, g_ssh[C.s].sid, 32);
    int s0 = C.s;

    CHECK(full(1));
    CHECK(C.s != s0 && memcmp(sid0, g_ssh[C.s].sid, 32) != 0);
    reset_all();
}

// Setelah kegagalan: DISCONNECT diterima (atau keluaran kosong), sesi CLOSING, masukan dibuang.
static int closed_hard(cl_t *c)
{
    return ssh_state(c->s) == SSH_ST_CLOSING;
}

static void hello_with(const char *kex, const char *hk, const char *cip, const char *comp, int follows)
{
    uint8_t ki[600];

    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_msg(&C);
    memcpy(C.is, C.pl, C.pln);
    C.isn = C.pln;
    uint32_t n = cl_kexinit(&C, kex, hk, cip, comp, follows, ki);

    memcpy(C.ic, ki, n);
    C.icn = n;
    C.strict = strstr(kex, "kex-strict-c") != 0;
    cl_send(&C, ki, n);
}

static void test_negotiation(void)
{
    reset_all();
    // cipher tanpa aes128-gcm (chacha saja) -> tidak cocok, bahkan dengan strict
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "chacha20-poly1305@openssh.com", "none", 0);
    CHECK(closed_hard(&C) && disc_seen(&C));
    ssh_close(C.s);
    // chacha dulu, gcm kedua: gcm dipilih (chacha tidak didukung server)
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com", "none", 0);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // klien tanpa strict dengan chacha+gcm: tetap gcm
    hello_with(KEX_PLAIN, "ecdsa-sha2-nistp256", "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com", "none", 0);
    CHECK(ssh_state(C.s) == SSH_ST_KEX && cl_kex(&C));
    ssh_close(C.s);
    // alias libssh.org
    hello_with("curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
               "aes128-gcm@openssh.com", "none", 0);
    CHECK(ssh_state(C.s) == SSH_ST_KEX && cl_kex(&C));
    ssh_close(C.s);
    // kex-strict-* tidak pernah terpilih sebagai kex
    hello_with("kex-strict-s-v00@openssh.com,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
               "aes128-gcm@openssh.com", "none", 0);
    CHECK(closed_hard(&C) && disc_seen(&C));
    ssh_close(C.s);
    // kex tak dikenal, hostkey tak dikenal, tanpa kompresi none
    hello_with("diffie-hellman-group14-sha256", "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    hello_with(KEX_STRICT, "ssh-ed25519", "aes128-gcm@openssh.com", "none", 0);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "zlib@openssh.com", 0);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // daftar kosong
    hello_with("", "", "", "", 0);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // tebakan salah (kex pertama klien tidak didukung) + first_kex_packet_follows: satu paket diabaikan
    hello_with("mlkem768x25519-sha256,curve25519-sha256,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
               "aes128-gcm@openssh.com", "none", 1);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    uint8_t guess[] = { 30, 0, 0, 0, 5, 1, 2, 3, 4, 5 };   // KEXDH_INIT milik algoritme lain
    cl_send(&C, guess, sizeof(guess));
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    C.seq_in = 0;
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // tebakan benar (follows=1, kex pertama didukung): paket berikut = KEXDH_INIT sungguhan
    hello_with("curve25519-sha256,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
               "aes128-gcm@openssh.com", "none", 1);
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // KEXINIT cacat
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    uint8_t bad[] = { 20, 1, 2, 3 };

    cl_send(&C, bad, sizeof(bad));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
}

static void test_strict(void)
{
    reset_all();
    uint8_t ign[] = { M_IGNORE, 0, 0, 0, 0 };
    uint8_t dbg[] = { M_DEBUG, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    // strict: IGNORE sebelum KEXINIT -> KEXINIT bukan paket pertama
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_send(&C, ign, sizeof(ign));
    CHECK(ssh_state(C.s) == SSH_ST_KEX);   // belum tahu strict
    uint8_t ki[600];
    uint32_t n = cl_kexinit(&C, KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, ki);

    cl_send(&C, ki, n);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // tanpa strict: IGNORE sebelum KEXINIT sah
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_send(&C, ign, sizeof(ign));
    n = cl_kexinit(&C, KEX_PLAIN, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, ki);
    memcpy(C.ic, ki, n);
    C.icn = n;
    cl_msg(&C);
    memcpy(C.is, C.pl, C.pln);
    C.isn = C.pln;
    cl_send(&C, ki, n);
    cl_send(&C, dbg, sizeof(dbg));
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // strict: IGNORE / DEBUG antara KEXINIT dan KEXDH_INIT, dan antara KEXDH_INIT dan NEWKEYS
    uint8_t unm[] = { M_UNIMPL, 0, 0, 0, 0 };
    const uint8_t *sel[] = { ign, dbg, unm };
    const uint32_t sln[] = { sizeof(ign), sizeof(dbg), sizeof(unm) };

    for (int where = 0; where < 3; where++) {   // IGNORE, DEBUG, UNIMPLEMENTED
        hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
        CHECK(ssh_state(C.s) == SSH_ST_KEX);
        cl_send(&C, sel[where], sln[where]);
        CHECK(closed_hard(&C));
        CHECK(strstr(ssh_why(C.s), "strict") != 0);
        ssh_close(C.s);
    }
    // strict: pesan lain (SERVICE_REQUEST) saat kex -> disconnect; pesan tak dikenal juga
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
    uint8_t sr[] = { M_SVC_REQ, 0, 0, 0, 1, 'x' };
    cl_send(&C, sr, sizeof(sr));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // non-strict: pesan tak terduga saat kex tetap disconnect (bukan UNIMPLEMENTED)
    hello_with(KEX_PLAIN, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
    cl_send(&C, sr, sizeof(sr));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // pesan terselip antara KEXDH_REPLY/NEWKEYS dengan strict: kirim IGNORE sebelum NEWKEYS klien
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    for (int i = 0; i < 32; i++) {
        C.x[i] = (uint8_t)(i * 9 + 1);
    }
    x25519(C.qc, C.x, k_x25519_base);
    w_u8(&w, M_KEXDH_INIT);
    w_str(&w, C.qc, 32);
    cl_send(&C, m, w.n);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    cl_send(&C, ign, sizeof(ign));
    CHECK(closed_hard(&C));
    ssh_close(C.s);

    // nomor urut: UNIMPLEMENTED merujuk nomor urut paket tak dikenal
    // strict: reset ke 0 setelah NEWKEYS -> paket tak dikenal pertama = 0
    CHECK(full(1));
    uint8_t unk[] = { 10 };
    cl_send(&C, unk, 1);
    CHECK(cl_msg(&C) == M_UNIMPL && get32(C.pl + 1) == 0);
    cl_send(&C, unk, 1);
    CHECK(cl_msg(&C) == M_UNIMPL && get32(C.pl + 1) == 1);
    CHECK(g_ssh[C.s].seq_in == 2);
    ssh_close(C.s);
    // non-strict: terus naik (KEXINIT, KEXDH_INIT, NEWKEYS = 3 paket)
    CHECK(full(0));
    cl_send(&C, unk, 1);
    CHECK(cl_msg(&C) == M_UNIMPL && get32(C.pl + 1) == 3);
    CHECK(g_ssh[C.s].seq_in == 4);
    ssh_close(C.s);
}

// Paket polos mentah dengan panjang/padding yang bisa dirusak.
static uint32_t raw_plain(uint8_t *o, uint32_t plen, uint32_t pad, uint32_t body)
{
    memset(o, 0, 4 + body);
    put32(o, plen);
    o[4] = (uint8_t)pad;
    o[5] = 99;   // pesan tak dikenal
    return 4 + body;
}

static void test_malformed_plain(void)
{
    reset_all();
    uint8_t b[64];

    struct { uint32_t plen, pad; const char *nama; } bad[] = {
        { 0, 0, "panjang 0" }, { 5, 4, "panjang < minimum" }, { 13, 4, "bukan kelipatan 8" },
        { 35008, 4, "melebihi 35000" }, { 0xFFFFFFFFu, 4, "sangat besar" },
        { 12, 3, "padding < 4" }, { 12, 11, "padding terlalu besar" }, { 12, 12, "padding = seluruh paket" },
    };

    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        cl_new(&C);
        cl_banner(&C);
        cl_send_banner(&C);
        cl_msg(&C);
        uint32_t n = raw_plain(b, bad[i].plen, bad[i].pad, bad[i].plen > 40 ? 8 : bad[i].plen);

        if (bad[i].plen == 12) {
            n = raw_plain(b, bad[i].plen, bad[i].pad, bad[i].plen);
        }
        cl_feed(&C, b, n);
        if (!closed_hard(&C)) {
            fprintf(stderr, "tidak ditolak: %s\n", bad[i].nama);
        }
        CHECK(closed_hard(&C));
        CHECK(disc_seen(&C));
        // masukan sesudahnya dibuang, tidak ada keluaran baru
        CHECK(ssh_feed(C.s, b, 4) == 4);
        uint32_t ol;
        ssh_out_peek(C.s, &ol);
        CHECK(ol == 0);
        CHECK(ssh_done(C.s));
        ssh_close(C.s);
    }
    // panjang 34996 (+4 = kelipatan 8, terbesar <= 35000) sah: ditunggu, bukan ditolak; panjang 0 ditolak di atas
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_msg(&C);
    put32(b, 34996);
    cl_feed(&C, b, 4);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    ssh_close(C.s);
    // terpotong: ditunda, lalu lengkap -> diproses (pesan tak dikenal saat kex = disconnect, tapi
    // setelah data lengkap, bukan sebelumnya)
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_msg(&C);
    uint32_t n = raw_plain(b, 12, 4, 12);
    cl_feed(&C, b, n - 1);
    CHECK(ssh_state(C.s) == SSH_ST_KEX);
    cl_feed(&C, b + n - 1, 1);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // dipecah satu byte per feed: hasil sama
    cl_new(&C);
    cl_banner(&C);
    cl_send_banner(&C);
    cl_msg(&C);
    g_chunk = 1;
    cl_feed(&C, b, n);
    g_chunk = 0;
    CHECK(closed_hard(&C));
    ssh_close(C.s);
}

static void test_tamper(void)
{
    reset_all();
    uint8_t p[64];

    memset(p, 0x41, sizeof(p));
    p[0] = 99;
    for (int mode = 0; mode < 6; mode++) {
        CHECK(full(1));
        uint32_t t = cl_build(&C, p, 20, g_pktbuf);   // plen 32 (1+20+11)
        switch (mode) {
        case 0: g_pktbuf[t - 1] ^= 1; break;          // tag
        case 1: g_pktbuf[10] ^= 0x80; break;          // isi terenkripsi
        case 2: g_pktbuf[0] = 0x7F; break;            // panjang sangat besar
        case 3: g_pktbuf[3] = 16; break;              // panjang lebih kecil tapi sah: tag gagal
        case 4: g_pktbuf[3] ^= 1; break;              // bukan kelipatan 16
        default: g_pktbuf[3] = 0; break;              // panjang 0
        }
        cl_feed(&C, g_pktbuf, t);
        CHECK(closed_hard(&C));
        CHECK(!mode || ssh_why(C.s)[0] != 0);
        // DISCONNECT terenkripsi dengan kunci server -> klien bisa membaca
        CHECK(cl_msg(&C) == M_DISCONNECT);
        ssh_close(C.s);
    }
    // isi tidak diproses bila tag salah: perintah USERAUTH tidak menaikkan auth_n
    CHECK(full(1));
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    cl_msg(&C);
    uint8_t ua[60];
    wr_t uw = { ua, 0, sizeof(ua), 0 };

    w_u8(&uw, M_UA_REQ);
    w_cstr(&uw, "bima");
    w_cstr(&uw, "ssh-connection");
    w_cstr(&uw, "none");
    uint32_t t = cl_build(&C, ua, uw.n, g_pktbuf);

    g_pktbuf[t - 3] ^= 0x10;
    cl_feed(&C, g_pktbuf, t);
    CHECK(closed_hard(&C) && g_ssh[C.s].auth_n == 0);
    ssh_close(C.s);
    // paket besar sah (panjang mendekati 35000) diterima
    CHECK(full(1));
    static uint8_t big[35000];

    big[0] = M_IGNORE;
    put32(big + 1, 34955);
    cl_send(&C, big, 34960);
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE);
    uint8_t unk = 10;
    cl_send(&C, &unk, 1);
    CHECK(cl_msg(&C) == M_UNIMPL);
    // di atas 35000 (kelipatan 16 = 35008): ditolak
    uint32_t tb = cl_build(&C, big, 34990, g_pktbuf);   // plen 35008
    cl_feed(&C, g_pktbuf, 4);
    (void)tb;
    CHECK(closed_hard(&C));
    ssh_close(C.s);
}

static void test_qc(void)
{
    reset_all();
    static const uint8_t low[32] = {   // titik orde 8 (RFC 7748 5.2 / daftar kecil)
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 };
    uint8_t one[40] = { 1 }, zero[40] = { 0 };
    const uint8_t *qs[] = { zero, one, low };
    const char *nama[] = { "Q_C nol", "Q_C = 1", "titik orde 8" };

    for (int i = 0; i < 3; i++) {
        start(1);
        uint8_t m[60];
        wr_t w = { m, 0, sizeof(m), 0 };

        w_u8(&w, M_KEXDH_INIT);
        w_str(&w, qs[i], 32);
        cl_send(&C, m, w.n);
        if (!closed_hard(&C)) {
            fprintf(stderr, "K nol tidak ditolak: %s\n", nama[i]);
        }
        CHECK(closed_hard(&C));
        CHECK(disc_seen(&C));
        ssh_close(C.s);
    }
    // panjang salah: 0, 31, 33
    uint32_t lens[] = { 0, 31, 33 };

    for (int i = 0; i < 3; i++) {
        start(1);
        uint8_t m[60];
        wr_t w = { m, 0, sizeof(m), 0 };

        w_u8(&w, M_KEXDH_INIT);
        w_str(&w, one, lens[i]);
        cl_send(&C, m, w.n);
        CHECK(closed_hard(&C));
        ssh_close(C.s);
    }
    // string melebihi sisa paket
    start(1);
    uint8_t m2[] = { M_KEXDH_INIT, 0, 0, 0, 32, 1, 2 };
    cl_send(&C, m2, sizeof(m2));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // ada sisa byte setelah Q_C
    start(1);
    uint8_t m3[40];
    wr_t w3 = { m3, 0, sizeof(m3), 0 };

    w_u8(&w3, M_KEXDH_INIT);
    w_str(&w3, C.qc, 32);
    memset(C.qc, 7, 32);
    w_u8(&w3, 0);
    cl_send(&C, m3, w3.n);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // titik dengan bit tinggi terakhir diset tetap sah (RFC 7748: bit diabaikan)
    start(1);
    uint8_t e[32];
    uint8_t k[32];

    for (int i = 0; i < 32; i++) {
        k[i] = (uint8_t)(i + 5);
    }
    x25519(e, k, k_x25519_base);
    e[31] |= 0x80;
    uint8_t m4[60];
    wr_t w4 = { m4, 0, sizeof(m4), 0 };

    w_u8(&w4, M_KEXDH_INIT);
    w_str(&w4, e, 32);
    cl_send(&C, m4, w4.n);
    CHECK(cl_msg(&C) == M_KEXDH_REPLY);
    ssh_close(C.s);
}

static void test_entropy_slots(void)
{
    reset_all();
    g_ent_ok = 0;
    CHECK(ssh_open() == SSH_ERR_ENTROPY);
    CHECK(ssh_state(0) == SSH_ST_FREE && ssh_state(1) == SSH_ST_FREE);
    g_ent_ok = 1;
    int a = ssh_open(), b = ssh_open(), c = ssh_open();

    CHECK(a == 0 && b == 1 && c == SSH_ERR_FULL);
    ssh_close(a);
    CHECK(ssh_open() == 0);
    CHECK(ssh_state(-1) == SSH_ST_FREE && ssh_state(2) == SSH_ST_FREE && ssh_state(99) == SSH_ST_FREE);
    CHECK(ssh_feed(-1, (const uint8_t *)"x", 1) == 0 && ssh_feed(5, (const uint8_t *)"x", 1) == 0);
    ssh_close(-1);
    ssh_close(7);
    ssh_out_consume(7, 1);
    uint32_t n = 5;
    CHECK(ssh_out_peek(7, &n) == 0 && n == 0);
    reset_all();
    // entropi gagal setelah slot terpakai tidak mengganggu sesi lama; sesi baru tetap ditolak
    CHECK(full(1));
    g_ent_ok = 0;
    CHECK(ssh_open() == SSH_ERR_ENTROPY);
    uint8_t unk = 10;
    cl_send(&C, &unk, 1);
    CHECK(cl_msg(&C) == M_UNIMPL);
    reset_all();
    // dua sesi: KEXINIT (cookie) dan Q_S berbeda
    int s0 = ssh_open(), s1 = ssh_open();
    uint32_t n0, n1;
    const uint8_t *o0 = ssh_out_peek(s0, &n0), *o1 = ssh_out_peek(s1, &n1);

    CHECK(n0 == n1 && memcmp(o0, o1, n0) != 0);
    reset_all();
}

static void send_ua(cl_t *c)
{
    uint8_t ua[80];
    wr_t uw = { ua, 0, sizeof(ua), 0 };

    w_u8(&uw, M_UA_REQ);
    w_cstr(&uw, "bima");
    w_cstr(&uw, "ssh-connection");
    w_cstr(&uw, "publickey");
    w_u8(&uw, 0);
    cl_send(c, ua, uw.n);
}

static void test_post(void)
{
    reset_all();
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    // USERAUTH_REQUEST sebelum SERVICE_REQUEST
    CHECK(full(1));
    send_ua(&C);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // layanan lain
    CHECK(full(1));
    w.n = 0;
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-connection");
    cl_send(&C, m, w.n);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // 4 percobaan: 4 FAILURE lalu DISCONNECT; USERAUTH_REQUEST cacat -> disconnect
    CHECK(full(0));
    w.n = 0;
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    CHECK(cl_msg(&C) == M_SVC_ACCEPT);
    uint8_t ign[] = { M_IGNORE, 0, 0, 0, 2, 9, 9 }, dbg[] = { M_DEBUG, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    cl_send(&C, ign, sizeof(ign));
    cl_send(&C, dbg, sizeof(dbg));
    cl_drain(&C);
    CHECK(C.rxn == C.rxpos);   // IGNORE/DEBUG tidak dijawab
    for (int i = 1; i <= 3; i++) {
        send_ua(&C);
        CHECK(cl_msg(&C) == M_UA_FAILURE);
        CHECK(C.pln == 1 + 4 + 9 + 1 && memcmp(C.pl + 5, "publickey", 9) == 0 && C.pl[14] == 0);
        CHECK(ssh_state(C.s) == SSH_ST_AUTH);
    }
    send_ua(&C);
    int last = 0;

    CHECK(cl_count(&C, M_UA_FAILURE, &last) == 1 && last == M_DISCONNECT);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // USERAUTH_REQUEST cacat
    CHECK(full(1));
    w.n = 0;
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    cl_msg(&C);
    uint8_t bad[] = { M_UA_REQ, 0, 0, 0, 9, 'x' };
    cl_send(&C, bad, sizeof(bad));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    // rekey (KEXINIT kedua), NEWKEYS liar, DISCONNECT klien, pesan kanal -> UNIMPLEMENTED
    CHECK(full(1));
    uint8_t ki[600];
    uint32_t n = cl_kexinit(&C, KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, ki);
    cl_send(&C, ki, n);
    CHECK(closed_hard(&C));
    CHECK(strstr(ssh_why(C.s), "rekey") != 0);
    ssh_close(C.s);
    CHECK(full(1));
    cl_send_msg(&C, M_NEWKEYS);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    CHECK(full(1));
    uint8_t dc[] = { M_DISCONNECT, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0 };
    cl_send(&C, dc, sizeof(dc));
    CHECK(closed_hard(&C) && ssh_done(C.s));
    ssh_close(C.s);
    CHECK(full(1));
    // RFC 4252 6: pesan >= 80 sebelum userauth sukses -> DISCONNECT (kanal, global request, 80, 255)
    uint8_t hi[] = { 90, 0, 0, 0, 7, 's', 'e', 's', 's', 'i', 'o', 'n', 0, 0, 0, 0 };
    cl_send(&C, hi, sizeof(hi));
    CHECK(closed_hard(&C) && strstr(ssh_why(C.s), ">= 80") != 0);
    ssh_close(C.s);
    static const uint8_t nums[] = { 80, 81, 100, 255 };

    for (unsigned i = 0; i < sizeof(nums); i++) {
        CHECK(full(1));
        cl_send(&C, &nums[i], 1);
        CHECK(closed_hard(&C));
        ssh_close(C.s);
    }
    // pesan < 80 tak dikenal -> UNIMPLEMENTED dengan nomor urut paket itu; batas 16 lalu DISCONNECT
    CHECK(full(1));
    uint8_t unk10 = 10;
    for (int i = 0; i < SSH_UNIMPL_MAX; i++) {
        cl_send(&C, &unk10, 1);
        CHECK(cl_msg(&C) == M_UNIMPL && get32(C.pl + 1) == (uint32_t)i);
    }
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE);
    cl_send(&C, &unk10, 1);
    CHECK(closed_hard(&C) && strstr(ssh_why(C.s), "UNIMPLEMENTED") != 0);
    ssh_close(C.s);
    // SERVICE_REQUEST: ada sisa byte -> disconnect; kedua kali (state AUTH) -> disconnect
    CHECK(full(1));
    w.n = 0;
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    w_u8(&w, 0);
    cl_send(&C, m, w.n);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    CHECK(full(1));
    w.n = 0;
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    CHECK(cl_msg(&C) == M_SVC_ACCEPT && ssh_state(C.s) == SSH_ST_AUTH);
    cl_send(&C, m, w.n);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    CHECK(full(1));
    // SERVICE_REQUEST cacat
    uint8_t sb[] = { M_SVC_REQ, 0, 0, 0, 40 };
    cl_send(&C, sb, sizeof(sb));
    CHECK(closed_hard(&C));
    ssh_close(C.s);
}

static uint8_t g_flood[1500 * 36 + 64];

static void test_backpressure(void)
{
    reset_all();
    CHECK(full(1));
    g_ssh_unimpl_max = 100000;   // uji ini membanjiri UNIMPLEMENTED; batas normal diuji di test_post
    uint8_t unk = 10;
    uint32_t total = 0;

    // 1500 paket tak dikenal (36 byte terenkripsi) = 54000 byte > buffer masuk; tiap paket
    // dijawab UNIMPLEMENTED (36 byte) tetapi keluaran tidak dikuras sampai penuh.
    for (int i = 0; i < 1500; i++) {
        total += cl_build(&C, &unk, 1, g_flood + total);
    }
    CHECK(total == 1500 * 36);
    uint32_t pos = 0;

    pos += ssh_feed(C.s, g_flood + pos, total - pos);
    CHECK(pos > 0 && pos < total);
    uint32_t ol;

    ssh_out_peek(C.s, &ol);
    CHECK(ol > SSH_OBUF_SIZE - SSH_OUT_RESERVE - 40 && ol <= SSH_OBUF_SIZE);
    // keluaran penuh: tidak mengonsumsi apa pun lagi, tidak membuang
    CHECK(ssh_feed(C.s, g_flood + pos, total - pos) == 0);
    CHECK(ssh_feed(C.s, g_flood + pos, total - pos) == 0);
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE);
    // Menguras keluaran (ssh_out_consume) sendiri melanjutkan sisa buffer masuk: tanpa
    // ssh_feed(s,0,0). Suap sisa hanya saat ruang ada.
    int got = 0, guard = 0;

    while (guard++ < 100000) {
        cl_drain(&C);   // memanggil ssh_out_consume -> ssh_run
        got += cl_count(&C, M_UNIMPL, 0);
        uint32_t k = ssh_feed(C.s, g_flood + pos, total - pos);

        pos += k;
        if (pos == total) {
            cl_drain(&C);
            got += cl_count(&C, M_UNIMPL, 0);
            for (int j = 0; j < 200 && got < 1500; j++) {   // hanya kuras, tanpa feed kosong
                cl_drain(&C);
                got += cl_count(&C, M_UNIMPL, 0);
            }
            break;
        }
    }
    CHECK(pos == total);
    CHECK(got == 1500);
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE);
    reset_all();
}

static void test_limits(void)
{
    reset_all();
    uint8_t unk = 10;

    CHECK(full(1));
    g_ssh[C.s].pk_in = SSH_PKT_LIMIT - 2;
    cl_send(&C, &unk, 1);
    CHECK(ssh_state(C.s) == SSH_ST_SERVICE);
    cl_send(&C, &unk, 1);
    CHECK(closed_hard(&C) && strstr(ssh_why(C.s), "2^28") != 0);
    ssh_close(C.s);
    CHECK(full(1));
    g_ssh[C.s].by_in = SSH_BYTE_LIMIT - 30;
    cl_send(&C, &unk, 1);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    CHECK(full(1));
    g_ssh[C.s].pk_out = SSH_PKT_LIMIT - 1;   // balasan UNIMPLEMENTED menaikkannya ke batas
    cl_send(&C, &unk, 1);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
    CHECK(full(1));
    g_ssh[C.s].by_out = SSH_BYTE_LIMIT - 20;
    cl_send(&C, &unk, 1);
    CHECK(closed_hard(&C));
    ssh_close(C.s);
}

static int all_zero(const void *p, size_t n)
{
    const uint8_t *b = p;

    for (size_t i = 0; i < n; i++) {
        if (b[i]) {
            return 0;
        }
    }
    return 1;
}

static void test_zeroize(void)
{
    reset_all();
    CHECK(full(1));
    int s = C.s;

    CHECK(!all_zero(g_ssh[s].sid, 32));
    CHECK(!all_zero(&g_ssh[s].co, sizeof(g_ssh[s].co)));
    CHECK(!all_zero(&g_ssh[s].ci, sizeof(g_ssh[s].ci)));
    CHECK(!all_zero(&g_ssh[s].rng, sizeof(g_ssh[s].rng)));
    // kunci masuk sementara sudah dinolkan setelah NEWKEYS klien
    CHECK(all_zero(g_ssh[s].in_key, 16) && all_zero(g_ssh[s].in_iv, 12));
    ssh_close(s);
    CHECK(all_zero(&g_ssh[s], sizeof(g_ssh[s])));
    CHECK(ssh_state(s) == SSH_ST_FREE);
    // sesi ditutup saat kex berjalan (X25519 sementara, hash) juga nol
    start(1);
    s = C.s;
    CHECK(!all_zero(&g_ssh[s].hash, sizeof(g_ssh[s].hash)));
    ssh_close(s);
    CHECK(all_zero(&g_ssh[s], sizeof(g_ssh[s])));
    // tidak ada rahasia di stack lokal yang tersisa tidak bisa diuji di sini (dicatat di laporan)
    // kunci host tetap setelah sesi ditutup, dan hilang setelah ssh_unload_key
    CHECK(ssh_key_loaded() && !all_zero(g_key_x, 32));
    ssh_unload_key();
    CHECK(all_zero(g_key_x, 32) && all_zero(g_key_q, 65) && all_zero(g_key_blob, sizeof(g_key_blob)));
    setup_key();
    reset_all();
}

// Dua sesi berselang-seling bersama (satu byte per feed) tetap benar.
static void test_two_sessions(void)
{
    reset_all();
    static cl_t A;

    memset(&A, 0, sizeof(A));
    A.s = ssh_open();
    cl_t *save = &C;

    (void)save;
    CHECK(cl_hello(&A, KEX_STRICT, "aes128-gcm@openssh.com", "none", 0));
    CHECK(full(0));
    CHECK(cl_kex(&A) == 1);
    CHECK(ssh_state(A.s) == SSH_ST_SERVICE && ssh_state(C.s) == SSH_ST_SERVICE);
    uint8_t unk = 10;

    cl_send(&A, &unk, 1);
    cl_send(&C, &unk, 1);
    CHECK(cl_msg(&A) == M_UNIMPL && get32(A.pl + 1) == 0);
    CHECK(cl_msg(&C) == M_UNIMPL && get32(C.pl + 1) == 3);
    reset_all();
}


// ---- vektor tetap (S2): dihitung Python murni (tests/host/ssh_vectors.py), bukan salinan kode server ----

static void hexdump_line(const char *nama, const uint8_t *d, uint32_t n)
{
    printf("%s=", nama);
    for (uint32_t i = 0; i < n; i++) {
        printf("%02x", d[i]);
    }
    printf("\n");
}

#include "ssh_vec.h"

static void test_mpint(void)
{
    uint8_t b[64];
    wr_t w;
    struct { const char *in; const char *want; } v[] = {
        { "", "00000000" },                                   // 0: panjang 0 (RFC 4251 5)
        { "00", "00000000" },                                 // nol di depan dibuang
        { "0000000000", "00000000" },
        { "09a378f9b2e332a7", "0000000809a378f9b2e332a7" },   // contoh RFC 4251
        { "80", "000000020080" },                             // bit tinggi: awalan 0x00
        { "0080", "000000020080" },                           // nol di depan tetap satu
        { "00000080", "000000020080" },
        { "7f", "000000017f" },
        { "ff", "0000000200ff" },
        { "00ff01", "0000000300ff01" },
        { "8000000000000000000000000000000000000000000000000000000000000001",
          "00000021008000000000000000000000000000000000000000000000000000000000000001" },
    };

    for (unsigned i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        uint8_t in[40];
        size_t n = test_unhex(v[i].in, in, sizeof(in));

        w.p = b;
        w.n = 0;
        w.cap = sizeof(b);
        w.err = 0;
        w_mpint(&w, in, (uint32_t)n);
        CHECK(!w.err && test_hex_eq(b, w.n, v[i].want));
    }
    // string: panjang 4 byte big-endian
    w.p = b;
    w.n = 0;
    w.cap = sizeof(b);
    w.err = 0;
    w_cstr(&w, "abc");
    CHECK(test_hex_eq(b, w.n, "00000003616263"));
    // penulis menolak melewati kapasitas (err), tidak menulis
    w.n = 0;
    w.cap = 3;
    w.err = 0;
    w_u32(&w, 1);
    CHECK(w.err && w.n == 0);
}

static void test_vektor(void)
{
    reset_all();
    g_ent_ctr = 0;
    cl_new(&C);
    CHECK(C.s == 0);
    CHECK(cl_hello(&C, KEX_STRICT, "aes128-gcm@openssh.com", "none", 0));
    cl_dh_init(&C);
    cl_drain(&C);
    ssh_sess_t *s = &g_ssh[C.s];
    uint8_t e[16], vk[32];

    if (getenv("SSH_VEC_DUMP")) {
        CHECK(cl_kex_finish(&C));
        hexdump_line("vc", (const uint8_t *)CLIENT_BANNER, sizeof(CLIENT_BANNER) - 1);
        hexdump_line("vs", (const uint8_t *)SSH_BANNER, sizeof(SSH_BANNER) - 1);
        hexdump_line("ic", C.ic, C.icn);
        hexdump_line("is", C.is, C.isn);
        hexdump_line("ks", g_last_ks, g_last_ksn);
        hexdump_line("qc", C.qc, 32);
        hexdump_line("qs", g_last_qs, 32);
        hexdump_line("x", C.x, 32);
        return;
    }
    // sebelum NEWKEYS klien: kunci masuk menunggu, session_id sudah ada, kunci keluar aktif
    CHECK(test_hex_eq(s->sid, 32, VEC_H));
    CHECK(test_hex_eq(s->in_key, 16, VEC_KEY_C));
    CHECK(test_hex_eq(s->in_iv, 12, VEC_IV_C));
    CHECK(test_hex_eq(s->co.iv, 12, VEC_IV_S));
    br_aes_ct64_ctr_keys ks;
    uint8_t key[16];

    test_unhex(VEC_KEY_S, key, sizeof(key));
    br_aes_ct64_ctr_init(&ks, key, 16);
    CHECK(memcmp(&s->co.ks, &ks, sizeof(ks)) == 0);
    (void)e;
    (void)vk;
    CHECK(cl_kex_finish(&C));
    CHECK(test_hex_eq(g_last_k, 32, VEC_K));
    CHECK(test_hex_eq(g_last_h, 32, VEC_H));
    // setelah NEWKEYS klien: kunci masuk dipasang (dan salinan sementaranya dinolkan)
    CHECK(all_zero(s->in_key, 16) && all_zero(s->in_iv, 12));
    test_unhex(VEC_KEY_C, key, sizeof(key));
    br_aes_ct64_ctr_init(&ks, key, 16);
    CHECK(memcmp(&s->ci.ks, &ks, sizeof(ks)) == 0);
    CHECK(test_hex_eq(s->ci.iv, 12, VEC_IV_C));
    // R1: K (32 byte mentah dan bentuk mpint) tidak tersisa di slot sesudah KEXDH_REPLY
    uint8_t kmp[40];
    wr_t kw = { kmp, 0, sizeof(kmp), 0 };

    w_mpint(&kw, g_last_k, 32);
    CHECK(mm((const uint8_t *)s, sizeof(*s), (const char *)g_last_k, 32) == 0);
    CHECK(mm((const uint8_t *)s, sizeof(*s), (const char *)kmp + 4, kw.n - 4) == 0);
    CHECK(mm((const uint8_t *)s, sizeof(*s), (const char *)g_last_k, 16) == 0);
    // konteks SHA-256 menyimpan blok parsial TERAKHIR pesan (berakhir dengan mpint K): ujung K
    CHECK(mm((const uint8_t *)s, sizeof(*s), (const char *)g_last_k + 24, 8) == 0);
    CHECK(mm((const uint8_t *)s, sizeof(*s), (const char *)g_last_k + 12, 8) == 0);
    reset_all();
}


// ---- S1: matriks tahap kex x pesan ----

static void mk_msg(int msg, int strict, uint8_t *b, uint32_t *n)
{
    wr_t w = { b, 0, 700, 0 };

    switch (msg) {
    case 20:
        w.n = cl_kexinit(&C, strict ? KEX_STRICT : KEX_PLAIN, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, b);
        break;
    case 21:
        w_u8(&w, 21);
        break;
    case 30: {
        uint8_t x[32], q[32];

        for (int i = 0; i < 32; i++) {
            x[i] = (uint8_t)(i * 5 + 1);
        }
        x25519(q, x, k_x25519_base);
        w_u8(&w, 30);
        w_str(&w, q, 32);
        break;
    }
    case 31:
        w_u8(&w, 31);
        w_u32(&w, 0);
        w_u32(&w, 0);
        w_u32(&w, 0);
        break;
    case 50:
        w_u8(&w, 50);
        w_u32(&w, 0);
        w_u32(&w, 0);
        w_u32(&w, 0);
        break;
    default:
        w_u8(&w, (uint8_t)msg);
        break;
    }
    *n = w.n;
}

// stage 0: banner saja; 1: KEXINIT klien terkirim; 2: + KEXDH_INIT terkirim
static void stage_up(int stage, int strict)
{
    if (stage == 0) {
        cl_new(&C);
        cl_banner(&C);
        cl_send_banner(&C);
        cl_msg(&C);
        memcpy(C.is, C.pl, C.pln);
        C.isn = C.pln;
        return;
    }
    hello_with(strict ? KEX_STRICT : KEX_PLAIN, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0);
    if (stage == 2) {
        uint8_t b[100];
        uint32_t n;

        mk_msg(30, strict, b, &n);
        cl_send(&C, b, n);
    }
}

static void test_matrix(void)
{
    static const int msgs[] = { 20, 21, 30, 31, 50, 99 };

    for (int strict = 0; strict < 2; strict++) {
        for (int stage = 0; stage < 3; stage++) {
            for (unsigned i = 0; i < sizeof(msgs) / sizeof(msgs[0]); i++) {
                reset_all();
                stage_up(stage, strict);
                CHECK(ssh_state(C.s) == SSH_ST_KEX);
                uint8_t b[700];
                uint32_t n;

                mk_msg(msgs[i], strict, b, &n);
                cl_send(&C, b, n);
                int ok = (stage == 0 && msgs[i] == 20) || (stage == 1 && msgs[i] == 30) ||
                         (stage == 2 && msgs[i] == 21);

                if (ok) {
                    CHECK(ssh_state(C.s) != SSH_ST_CLOSING);
                } else {
                    if (ssh_state(C.s) != SSH_ST_CLOSING) {
                        fprintf(stderr, "matriks: strict=%d tahap=%d pesan=%d tidak ditolak\n", strict, stage, msgs[i]);
                    }
                    CHECK(ssh_state(C.s) == SSH_ST_CLOSING);
                    CHECK(g_ssh[C.s].in_enc == 0);
                    CHECK(ssh_why(C.s)[0] != 0);
                    if (stage < 2) {   // tahap 2: DISCONNECT sudah terenkripsi, klien belum punya kunci
                        CHECK(disc_seen(&C));
                    }
                }
                if (stage == 2 && msgs[i] == 21) {
                    CHECK(g_ssh[C.s].in_enc == 1 && ssh_state(C.s) == SSH_ST_SERVICE);
                }
                reset_all();
            }
        }
    }
    // sisa byte setelah Q_C yang SAH
    uint8_t b[100], x[32], q[32];
    wr_t w = { b, 0, sizeof(b), 0 };

    for (int i = 0; i < 32; i++) {
        x[i] = (uint8_t)(i * 5 + 1);
    }
    x25519(q, x, k_x25519_base);
    reset_all();
    stage_up(1, 1);
    w_u8(&w, 30);
    w_str(&w, q, 32);
    w_u8(&w, 0);
    cl_send(&C, b, w.n);
    CHECK(closed_hard(&C) && g_ssh[C.s].in_enc == 0);
    reset_all();
    // NEWKEYS dengan byte sisa
    stage_up(2, 1);
    uint8_t nk[] = { 21, 0 };
    cl_send(&C, nk, 2);
    CHECK(closed_hard(&C) && g_ssh[C.s].in_enc == 0);
    reset_all();
}

// ---- R2/R3: first_kex_packet_follows ----

static void test_guess(void)
{
    reset_all();
    uint8_t junk[] = { 30, 0, 0, 0, 5, 1, 2, 3, 4, 5 };

    // nama pertama klien = alias libssh: berbeda dari nama pertama SERVER -> tebakan salah
    hello_with("curve25519-sha256@libssh.org,curve25519-sha256,kex-strict-c-v00@openssh.com",
               "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 1);
    CHECK(g_ssh[C.s].ignore_next == 1);
    cl_send(&C, junk, sizeof(junk));
    CHECK(ssh_state(C.s) == SSH_ST_KEX && g_ssh[C.s].ignore_next == 0);
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // hostkey pertama klien bukan milik server -> tebakan salah
    hello_with(KEX_STRICT, "ssh-ed25519,ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 1);
    CHECK(g_ssh[C.s].ignore_next == 1);
    cl_send(&C, junk, sizeof(junk));
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // tebakan benar: tidak ada paket yang diabaikan
    hello_with(KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 1);
    CHECK(g_ssh[C.s].ignore_next == 0);
    CHECK(cl_kex(&C));
    ssh_close(C.s);
    // follows = 0: tidak ada yang diabaikan walau nama pertama berbeda
    hello_with("curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
               "aes128-gcm@openssh.com", "none", 0);
    CHECK(g_ssh[C.s].ignore_next == 0);
    ssh_close(C.s);

    // R3: paket setelah tebakan salah hanya ditelan bila 30..49
    static const struct { uint8_t msg; int swallowed; } cases[] = {
        { 30, 1 }, { 31, 1 }, { 49, 1 }, { 29, 0 }, { 50, 0 }, { M_DISCONNECT, 0 }, { M_IGNORE, 0 },
        { M_DEBUG, 0 }, { M_UNIMPL, 0 }, { M_NEWKEYS, 0 }, { M_KEXINIT, 0 },
    };

    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        hello_with("curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com", "ecdsa-sha2-nistp256",
                   "aes128-gcm@openssh.com", "none", 1);
        uint8_t m[12] = { cases[i].msg };
        cl_send(&C, m, 12);
        int closed = ssh_state(C.s) == SSH_ST_CLOSING;

        if (closed == cases[i].swallowed) {
            fprintf(stderr, "tebakan salah + pesan %d: swallowed=%d closed=%d\n", cases[i].msg, cases[i].swallowed, closed);
        }
        CHECK(closed == !cases[i].swallowed);
        if (cases[i].msg == M_DISCONNECT) {
            CHECK(strstr(ssh_why(C.s), "DISCONNECT") != 0);
        }
        ssh_close(C.s);
    }
}

// ---- R6: kunci host tidak sah ditolak ----

static void test_key_range(void)
{
    uint8_t der[sizeof(T_KEYA)];
    static const char *xs[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",   // 0
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",   // n
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",   // n+1
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",   // FF..
    };
    uint8_t x[32];

    CHECK(T_KEYA[5] == 0x04 && T_KEYA[6] == 0x20);   // SEC1: skalar mulai di offset 7
    for (unsigned i = 0; i < 4; i++) {
        memcpy(der, T_KEYA, sizeof(der));
        test_unhex(xs[i], x, 32);
        memcpy(der + 7, x, 32);
        CHECK(ssh_load_key(der, sizeof(der)) == 0);
        CHECK(!ssh_key_loaded() && ssh_open() == SSH_ERR_NOKEY && all_zero(g_key_x, 32));
    }
    // batas sah: 1 dan n-1 diterima
    memcpy(der, T_KEYA, sizeof(der));
    test_unhex("0000000000000000000000000000000000000000000000000000000000000001", x, 32);
    memcpy(der + 7, x, 32);
    CHECK(ssh_load_key(der, sizeof(der)) == 1);
    test_unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", x, 32);
    memcpy(der + 7, x, 32);
    CHECK(ssh_load_key(der, sizeof(der)) == 1);
    CHECK(full(1));   // kunci n-1 benar-benar bisa dipakai kex + verifikasi tanda tangan
    reset_all();
    setup_key();
}

// ---- R8: arah c2s dan s2c dinegosiasikan terpisah ----

static uint32_t kexinit2(const char *c2s, const char *s2c, const char *z_c2s, const char *z_s2c, uint8_t *out)
{
    wr_t w = { out, 0, 600, 0 };

    w_u8(&w, M_KEXINIT);
    for (int i = 0; i < 16; i++) {
        w_u8(&w, (uint8_t)(0x40 + i));
    }
    w_cstr(&w, KEX_STRICT);
    w_cstr(&w, "ecdsa-sha2-nistp256");
    w_cstr(&w, c2s);
    w_cstr(&w, s2c);
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, z_c2s);
    w_cstr(&w, z_s2c);
    w_cstr(&w, "");
    w_cstr(&w, "");
    w_u8(&w, 0);
    w_u32(&w, 0);
    return w.n;
}

static void test_directions(void)
{
    static const struct { const char *c2s, *s2c, *z1, *z2; int ok; } v[] = {
        { "aes128-gcm@openssh.com", "aes128-gcm@openssh.com", "none", "none", 1 },
        { "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com", "none", "none", 0 },   // s2c tak cocok
        { "chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "none", "none", 0 },   // c2s tak cocok
        { "aes128-gcm@openssh.com", "aes128-gcm@openssh.com", "none", "zlib@openssh.com", 0 },   // kompresi s2c
        { "aes128-gcm@openssh.com", "aes128-gcm@openssh.com", "zlib@openssh.com", "none", 0 },   // kompresi c2s
        { "aes128-gcm@openssh.com", "aes128-gcm@openssh.com", "zlib@openssh.com,none", "none,zlib@openssh.com", 1 },
        { "aes128-ctr", "aes128-gcm@openssh.com", "none", "none", 0 },
        { "aes128-gcm@openssh.com", "", "none", "none", 0 },
    };

    for (unsigned i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        reset_all();
        cl_new(&C);
        cl_banner(&C);
        cl_send_banner(&C);
        cl_msg(&C);
        uint8_t ki[600];
        uint32_t n = kexinit2(v[i].c2s, v[i].s2c, v[i].z1, v[i].z2, ki);

        cl_send(&C, ki, n);
        if ((ssh_state(C.s) == SSH_ST_KEX) != v[i].ok) {
            fprintf(stderr, "arah: kasus %u salah\n", i);
        }
        CHECK((ssh_state(C.s) == SSH_ST_KEX) == v[i].ok);
        reset_all();
    }
    // padding < 4 dan payload 0 byte pada paket terenkripsi sah-GCM
    for (int mode = 0; mode < 3; mode++) {
        CHECK(full(1));
        uint8_t m10 = 10;

        g_force_plen = 16;
        g_force_pad = mode == 0 ? 3 : (mode == 1 ? 15 : 14);   // 0: pad 3; 1: payload 0 byte; 2: pas (payload 1 byte)
        cl_send(&C, &m10, mode == 1 ? 0 : 1);
        g_force_pad = -1;
        if (mode == 2) {
            CHECK(cl_msg(&C) == M_UNIMPL && ssh_state(C.s) == SSH_ST_SERVICE);
        } else {
            CHECK(closed_hard(&C));
        }
        reset_all();
    }
}

// ---- S3: nomor urut ----

static void test_seq(void)
{
    reset_all();
    CHECK(full(1));
    CHECK(g_ssh[C.s].seq_out == 0 && g_ssh[C.s].seq_in == 0);   // strict: direset di kedua arah
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    CHECK(g_ssh[C.s].seq_out == 1 && g_ssh[C.s].seq_in == 1);
    reset_all();
    CHECK(full(0));
    CHECK(g_ssh[C.s].seq_out == 3 && g_ssh[C.s].seq_in == 3);   // KEXINIT, KEX reply/DH_INIT, NEWKEYS
    reset_all();
}

// ---- S4: dua sesi tidak berbagi acak ----

static cl_t D;

static void test_random(void)
{
    reset_all();
    int a = ssh_open(), b = ssh_open();
    uint32_t na, nb;
    const uint8_t *oa = ssh_out_peek(a, &na), *ob = ssh_out_peek(b, &nb);
    uint32_t L = (uint32_t)sizeof(SSH_BANNER) + 1;

    CHECK(na == nb && na > L + 40);
    uint32_t plen = get32(oa + L), pad = oa[L + 4], pl = plen - 1 - pad;

    CHECK(get32(ob + L) == plen && ob[L + 4] == pad);
    CHECK(oa[L + 5] == M_KEXINIT && ob[L + 5] == M_KEXINIT);
    CHECK(memcmp(oa + L + 6, ob + L + 6, 16) != 0);                          // cookie
    CHECK(memcmp(oa + L + 5 + pl, ob + L + 5 + pl, pad) != 0);               // padding
    CHECK(!all_zero(oa + L + 6, 16) && !all_zero(oa + L + 5 + pl, pad));
    // isi KEXINIT selain cookie sama
    CHECK(memcmp(oa + L + 22, ob + L + 22, pl - 17) == 0);
    reset_all();

    // Q_S dan tanda tangan berbeda; padding paket sesudahnya juga
    CHECK(full(1));
    uint8_t qs1[32], r1[33];
    uint32_t r1n = g_sig_rn;

    memcpy(qs1, g_last_qs, 32);
    memcpy(r1, g_sig_r, 33);
    memcpy(&D, &C, sizeof(D));
    CHECK(full(1));
    CHECK(memcmp(qs1, g_last_qs, 32) != 0);
    CHECK(r1n != g_sig_rn || memcmp(r1, g_sig_r, 33) != 0);
    // dua paket berturut dalam satu sesi: padding berbeda (DRBG maju)
    uint8_t m10 = 10;
    cl_send(&C, &m10, 1);
    cl_send(&C, &m10, 1);
    cl_drain(&C);
    CHECK(cl_recv(&C) > 0 && cl_recv(&C) > 0);
    reset_all();
}

// encode_sig dengan r/s buatan: nol di depan, bit tinggi, nol penuh, 0x80..., 0xff...
static void test_encode_sig(void)
{
    static const struct { const char *r, *s; } v[] = {
        { "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
          "7f112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" },
        { "80112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
          "00007f33445566778899aabbccddeeff00112233445566778899aabbccddeeff" },
        { "0000000000000000000000000000000000000000000000000000000000000001",
          "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" },
    };

    for (unsigned i = 0; i < 3; i++) {
        uint8_t sig[64], b[160];
        wr_t w = { b, 0, sizeof(b), 0 };

        test_unhex(v[i].r, sig, 32);
        test_unhex(v[i].s, sig + 32, 32);
        encode_sig(&w, sig);
        CHECK(!w.err);
        rd_t r = { b, w.n, 0 };
        uint32_t an, bn, rn, sn;
        const uint8_t *alg = r_str(&r, &an);
        const uint8_t *blob = r_str(&r, &bn);

        CHECK(!r.err && r.n == 0 && tok_eq(alg, an, "ecdsa-sha2-nistp256"));
        rd_t q = { blob, bn, 0 };
        const uint8_t *rv = r_str(&q, &rn);
        const uint8_t *sv = r_str(&q, &sn);

        CHECK(!q.err && q.n == 0 && mpint_canon(rv, rn) && mpint_canon(sv, sn));
        // nilai sama dengan masukan (tanpa potong diam-diam): tambahkan nol di depan sampai 33 byte
        uint8_t a[33] = { 0 }, c[33] = { 0 };

        memcpy(a + 33 - rn, rv, rn);
        memcpy(c + 33 - sn, sv, sn);
        CHECK(a[0] == 0 && memcmp(a + 1, sig, 32) == 0);
        CHECK(c[0] == 0 && memcmp(c + 1, sig + 32, 32) == 0);
    }
    // kapasitas tidak cukup -> err, bukan potong diam-diam
    uint8_t sig[64] = { 1 }, b[20];
    wr_t w = { b, 0, sizeof(b), 0 };

    encode_sig(&w, sig);
    CHECK(w.err);
}

// Banyak sesi: tanda tangan selalu valid dan mpint r/s selalu kanonik (tanpa potong diam-diam).
static void test_sig_canon(void)
{
    int shorts = 0, bad = 0;

    reset_all();
    for (int i = 0; i < 300; i++) {
        g_ent_ctr = (uint32_t)i * 977 + 5;
        if (!full(1) || !g_sig_canon) {
            bad++;
        }
        if (g_sig_rn < 32 || g_sig_sn < 32) {
            shorts++;
        }
        ssh_close(C.s);
    }
    CHECK(bad == 0);
    CHECK(shorts >= 0);   // informasi: jumlah r/s yang lebih pendek dari 32 byte (nol di depan dibuang)
    fprintf(stderr, "ssh: 300 sesi, r/s pendek = %d, tidak kanonik/gagal = %d\n", shorts, bad);
}

#ifndef BMAHOS_FUZZ   // tests/fuzz/fuzz_ssh.c memakai helper file ini
int main(void)
{
    setup_key();
    test_x25519();
    test_key();
    test_banner();
    test_kex_all();
    test_negotiation();
    test_strict();
    test_malformed_plain();
    test_tamper();
    test_qc();
    test_entropy_slots();
    test_post();
    test_backpressure();
    test_limits();
    test_zeroize();
    test_two_sessions();
    test_mpint();
    test_vektor();
    test_matrix();
    test_guess();
    test_key_range();
    test_directions();
    test_seq();
    test_random();
    test_encode_sig();
    test_sig_canon();
    return test_done("ssh");
}
#endif

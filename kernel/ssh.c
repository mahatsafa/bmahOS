#include "kernel.h"
#include "ssh.h"
#include "bearssl.h"

// ---- F7 SSH-1a: inti transport SSH-2 sisi server (RFC 4253/5656/8731 + OpenSSH) ----
// Keputusan: DECISIONS 2026-11-24 (F7: SSH), PROTOCOL.md "TCP 22: SSH-2". Modul ini murni mesin
// keadaan: tanpa I/O, tanpa heap, tanpa timer (jam 10 s login = tugas SSH-1b). Semua fungsi
// dipanggil hanya dari net task.
//
// Profil: kex curve25519-sha256 (+ alias libssh.org), kunci host ecdsa-sha2-nistp256,
// cipher aes128-gcm@openssh.com dua arah, kompresi none. Strict kex (Terrapin) aktif bila klien
// menawarkan kex-strict-c-v00@openssh.com.
//
// KEPUTUSAN PENGGUNA 2026-11-25 (hanya aes128-gcm, DECISIONS): chacha20-poly1305@openssh.com TIDAK diimplementasikan.
// Poly1305 OpenSSH = MAC atas (panjang terenkripsi || isi terenkripsi) apa adanya. Satu-satunya
// fungsi Poly1305 BearSSL (br_poly1305_ctmulq_run, juga ctmul/ctmul32/i15) memformat AEAD gaya
// RFC 8439: AAD dan isi masing-masing diisi nol sampai kelipatan 16 (blok terakhir diberi bit 2^128)
// lalu SELALU ditambah footer 16 byte (panjang AAD + panjang isi), lihat
// third_party/bearssl/src/symcipher/poly1305_ctmulq.c baris 316-380 (footer baris 349-352,
// blok parsial baris 238-243). Tag-nya tidak sama dengan tag OpenSSH dan tidak ada parameter untuk
// mematikan footer/padding. Memakainya butuh mengubah BearSSL atau menulis Poly1305 sendiri:
// keduanya dilarang. Akibatnya hanya aes128-gcm yang ditawarkan (klien non-strict tetap dilayani,
// jadi aturan "non-strict tidak pernah chacha" terpenuhi dengan sendirinya).
// Implementasi dipilih eksplisit (tanpa *_default_*, tanpa SSE): x25519 m64, P-256 m64 + ecdsa i31,
// AES ct64 + GHASH ctmul64, SHA-256, HMAC_DRBG BearSSL (di-seed entropy_get per sesi).

#ifndef SSH_VERSION
#define SSH_VERSION "F7"
#endif
#define SSH_BANNER "SSH-2.0-bmahOS_" SSH_VERSION

// Nomor pesan (RFC 4253 / 4252)
#define M_DISCONNECT   1
#define M_IGNORE       2
#define M_UNIMPL       3
#define M_DEBUG        4
#define M_SVC_REQ      5
#define M_SVC_ACCEPT   6
#define M_KEXINIT      20
#define M_NEWKEYS      21
#define M_KEXDH_INIT   30
#define M_KEXDH_REPLY  31
#define M_UA_REQ       50
#define M_UA_FAILURE   51
#define M_UA_SUCCESS   52
#define M_UA_PK_OK     60
#define M_GLOBAL_REQ   80
#define M_REQ_FAILURE  82
#define M_CH_OPEN      90
#define M_CH_CONFIRM   91
#define M_CH_OPENFAIL  92
#define M_CH_WINADJ    93
#define M_CH_DATA      94
#define M_CH_EOF       96
#define M_CH_CLOSE     97
#define M_CH_REQ       98
#define M_CH_SUCCESS   99
#define M_CH_FAILURE   100

// Kode DISCONNECT
#define D_PROTO        2
#define D_MAC          5
#define D_SVC_NA       7
#define D_KEXFAIL      3   // KEY_EXCHANGE_FAILED (juga untuk 'tidak ada algoritme cocok', seperti OpenSSH)
#define D_NO_AUTH      14

enum { K_WAIT_KEXINIT = 0, K_WAIT_DH, K_WAIT_NEWKEYS };

typedef struct {
    br_aes_ct64_ctr_keys ks;
    br_gcm_context gc;
    uint8_t iv[12];     // 4 byte tetap + 8 byte pencacah (big-endian, naik tiap paket)
} ssh_gcm_t;

typedef struct {
    int used;
    int state;
    const char *why;
    uint32_t ipos, ilen, olen;
    uint8_t ibuf[SSH_IBUF_SIZE];
    uint8_t obuf[SSH_OBUF_SIZE];

    uint32_t pre_lines;          // baris sebelum banner klien
    uint8_t vc[256];             // baris versi klien tanpa CR LF
    uint32_t vc_len;
    uint8_t is[512];             // payload KEXINIT server (masuk hash)
    uint32_t is_len;

    int kstage;
    int strict;                  // klien menawarkan kex-strict-c-v00@openssh.com
    int ignore_next;             // tebakan kex klien salah: satu paket berikut diabaikan
    br_sha256_context hash;      // V_C V_S I_C I_S sudah masuk setelah KEXINIT klien
    uint8_t sid[32];             // session_id = H pertama
    br_hmac_drbg_context rng;

    uint32_t seq_in, seq_out;
    uint32_t cur_seq;            // nomor urut paket yang sedang diproses
    uint64_t pk_in, pk_out, by_in, by_out;
    int out_enc, in_enc;
    ssh_gcm_t co, ci;
    uint8_t in_key[16], in_iv[12];   // kunci masuk menunggu NEWKEYS klien
    int auth_n;                  // tanda tangan userauth SALAH (batas SSH_AUTH_MAX)
    uint32_t req_n;              // seluruh USERAUTH_REQUEST (batas SSH_UA_REQ_MAX)
    uint32_t unimpl_n;           // UNIMPLEMENTED yang sudah dikirim

    // ---- SSH-2a: hasil userauth + satu kanal session ----
    int role;                    // SSH_ROLE_* setelah USERAUTH_SUCCESS
    char user[SSH_USER_MAX + 1];
    uint32_t cmd_n;              // perintah yang sudah dijalankan
    int reboot;                  // callback exec minta reboot (ssh_take_reboot)
    int ch_open;                 // kanal terbuka (id server selalu 0)
    int ch_used;                 // kanal pernah dibuka (satu kanal per koneksi)
    int ch_kind;                 // CK_NONE / CK_EXEC / CK_SHELL
    int ch_eof_in;               // klien mengirim CHANNEL_EOF
    int ch_fin;                  // kirim exit-status + EOF + CLOSE begitu pend habis
    int ch_close_sent;
    uint32_t ch_code;            // exit-status
    uint32_t cl_id, cl_win, cl_max;   // id/window/max packet kanal sisi klien
    uint32_t win_in, win_credit;      // window masuk tersisa; byte sudah dikonsumsi belum dikreditkan
    uint32_t pend_off, pend_len; // keluaran perintah yang belum terkirim (backpressure + window klien)
    uint32_t inq_pos, inq_len;   // masukan shell yang belum diproses
    uint32_t ln_n;
    int ln_over;
    int ln_cr;                   // karakter terakhir yang diproses adalah CR (CRLF = satu akhir baris)
    uint8_t ln[SSH_CMD_MAX];
    uint8_t pend[SSH_CMD_OUT_MAX + 16];   // keluaran + prompt "bmahOS> "
    uint8_t inq[SSH_WIN_IN];     // = window masuk: klien patuh tidak bisa melebihinya
} ssh_sess_t;

enum { CK_NONE = 0, CK_EXEC, CK_SHELL };

static ssh_sess_t g_ssh[SSH_MAX_SESS];
static uint32_t g_ssh_unimpl_max = SSH_UNIMPL_MAX;   // bukan const: uji backpressure menaikkannya

// Kunci host (satu untuk semua sesi)
static int g_key_on;
static uint8_t g_key_x[32];
static br_ec_private_key g_key_sk;
static uint8_t g_key_q[65];
static uint8_t g_key_blob[160];
static uint32_t g_key_blob_len;
static char g_key_fp[56];
static br_skey_decoder_context g_key_dc;   // statis: decoder 2192 byte, jangan di stack

static const char *const k_kex[] = { "curve25519-sha256", "curve25519-sha256@libssh.org" };
static const char *const k_hostkey[] = { "ecdsa-sha2-nistp256" };
static const char *const k_cipher[] = { "aes128-gcm@openssh.com" };
static const char *const k_comp[] = { "none" };

// Penghapusan rahasia yang tidak bisa dibuang kompilator (akses volatile; tidak bergantung
// pada kernel dikompilasi tanpa -O).
static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = p;

    while (n--) {
        *v++ = 0;
    }
}

// ---- penulis/pembaca bidang SSH ----

typedef struct { uint8_t *p; uint32_t n, cap; int err; } wr_t;
typedef struct { const uint8_t *p; uint32_t n; int err; } rd_t;

static void w_bytes(wr_t *w, const void *d, uint32_t n)
{
    if (w->err || n > w->cap - w->n) {
        w->err = 1;
        return;
    }
    memcpy(w->p + w->n, d, n);
    w->n += n;
}

static void w_u8(wr_t *w, uint8_t v)
{
    w_bytes(w, &v, 1);
}

static void w_u32(wr_t *w, uint32_t v)
{
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };

    w_bytes(w, b, 4);
}

static void w_str(wr_t *w, const void *d, uint32_t n)
{
    w_u32(w, n);
    w_bytes(w, d, n);
}

static void w_cstr(wr_t *w, const char *s)
{
    w_str(w, s, (uint32_t)strlen(s));
}

// mpint dari bilangan big-endian tanpa tanda: buang nol di depan, tambah 0x00 bila bit tinggi.
static void w_mpint(wr_t *w, const uint8_t *d, uint32_t n)
{
    while (n > 0 && d[0] == 0) {
        d++;
        n--;
    }
    if (n > 0 && (d[0] & 0x80)) {
        w_u32(w, n + 1);
        w_u8(w, 0);
    } else {
        w_u32(w, n);
    }
    w_bytes(w, d, n);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint8_t r_u8(rd_t *r)
{
    if (r->err || r->n < 1) {
        r->err = 1;
        return 0;
    }
    r->n--;
    return *r->p++;
}

static uint32_t r_u32(rd_t *r)
{
    if (r->err || r->n < 4) {
        r->err = 1;
        return 0;
    }
    uint32_t v = get32(r->p);

    r->p += 4;
    r->n -= 4;
    return v;
}

// string: panjang dicek terhadap sisa SEBELUM pointer dipakai.
static const uint8_t *r_str(rd_t *r, uint32_t *len)
{
    uint32_t n = r_u32(r);

    if (r->err || n > r->n) {
        r->err = 1;
        *len = 0;
        return 0;
    }
    const uint8_t *p = r->p;

    r->p += n;
    r->n -= n;
    *len = n;
    return p;
}

// ---- name-list ----

static int tok_eq(const uint8_t *t, uint32_t tn, const char *name)
{
    return strlen(name) == tn && memcmp(t, name, tn) == 0;
}

// Elemen pertama daftar klien (l,n) yang juga ada di daftar server sup[] (preferensi klien
// menang, RFC 4253 7.1); return indeks di sup[], atau -1.
static int nl_pick(const uint8_t *l, uint32_t n, const char *const *sup, int nsup)
{
    uint32_t i = 0;

    while (i <= n) {
        uint32_t j = i;

        while (j < n && l[j] != ',') {
            j++;
        }
        for (int k = 0; k < nsup; k++) {
            if (j > i && tok_eq(l + i, j - i, sup[k])) {
                return k;
            }
        }
        i = j + 1;
    }
    return -1;
}

static int nl_has(const uint8_t *l, uint32_t n, const char *name)
{
    uint32_t i = 0;

    while (i <= n) {
        uint32_t j = i;

        while (j < n && l[j] != ',') {
            j++;
        }
        if (j > i && tok_eq(l + i, j - i, name)) {
            return 1;
        }
        i = j + 1;
    }
    return 0;
}

// Elemen pertama daftar sama dengan name?
static int nl_first_is(const uint8_t *l, uint32_t n, const char *name)
{
    uint32_t j = 0;

    while (j < n && l[j] != ',') {
        j++;
    }
    return tok_eq(l, j, name);
}

// ---- kunci host ----

static void b64_nopad(const uint8_t *d, uint32_t n, char *out)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t o = 0;

    for (uint32_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)d[i] << 16;
        uint32_t left = n - i;

        if (left > 1) {
            v |= (uint32_t)d[i + 1] << 8;
        }
        if (left > 2) {
            v |= d[i + 2];
        }
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        if (left > 1) {
            out[o++] = t[(v >> 6) & 63];
        }
        if (left > 2) {
            out[o++] = t[v & 63];
        }
    }
    out[o] = 0;
}

void ssh_unload_key(void)
{
    g_key_on = 0;
    secure_zero(g_key_x, sizeof(g_key_x));
    secure_zero(&g_key_sk, sizeof(g_key_sk));
    secure_zero(g_key_q, sizeof(g_key_q));
    secure_zero(g_key_blob, sizeof(g_key_blob));
    g_key_blob_len = 0;
    g_key_fp[0] = 0;
}

int ssh_load_key(const uint8_t *der, uint32_t len)
{
    ssh_unload_key();
    br_skey_decoder_init(&g_key_dc);
    br_skey_decoder_push(&g_key_dc, der, len);

    const br_ec_private_key *sk = br_skey_decoder_get_ec(&g_key_dc);

    if (br_skey_decoder_last_error(&g_key_dc) != 0 || sk == 0 ||
        sk->curve != BR_EC_secp256r1 || sk->xlen != sizeof(g_key_x)) {
        secure_zero(&g_key_dc, sizeof(g_key_dc));
        return 0;
    }
    memcpy(g_key_x, sk->x, sizeof(g_key_x));
    secure_zero(&g_key_dc, sizeof(g_key_dc));
    g_key_sk.curve = BR_EC_secp256r1;
    g_key_sk.x = g_key_x;
    g_key_sk.xlen = sizeof(g_key_x);

    // Skalar harus 1..n-1 (P-256): x = 0, x >= n, atau FF.. ditolak sebelum dipakai.
    size_t olen = 0;
    const uint8_t *ord = br_ec_p256_m64.order(BR_EC_secp256r1, &olen);
    int nz = 0, lt = 0;   // lt: x < n (perbandingan big-endian, tanpa percabangan data-dependen)

    for (size_t i = 0; i < 32; i++) {
        nz |= g_key_x[i];
    }
    int dec = 0;   // 1 setelah byte pertama yang berbeda ditemukan
    for (size_t i = 0; i < 32 && olen == 32; i++) {
        int a = g_key_x[i], b = ord[i];

        lt |= (!dec && a < b);
        dec |= (a != b);
    }
    if (olen != 32 || nz == 0 || !lt) {
        ssh_unload_key();
        return 0;
    }

    br_ec_public_key pub;
    size_t qlen = br_ec_compute_pub(&br_ec_p256_m64, &pub, g_key_q, &g_key_sk);

    if (qlen != 65 || g_key_q[0] != 4) {
        ssh_unload_key();
        return 0;
    }
    wr_t w = { g_key_blob, 0, sizeof(g_key_blob), 0 };

    w_cstr(&w, "ecdsa-sha2-nistp256");
    w_cstr(&w, "nistp256");
    w_str(&w, g_key_q, 65);
    if (w.err) {
        ssh_unload_key();
        return 0;
    }
    g_key_blob_len = w.n;

    // Uji sekali saat memuat: tanda tangan lalu verifikasi dengan kunci publik yang dihitung.
    uint8_t th[32], tsig[64];

    for (int i = 0; i < 32; i++) {
        th[i] = (uint8_t)(i * 7 + 3);
    }
    pub.curve = BR_EC_secp256r1;
    pub.q = g_key_q;
    pub.qlen = 65;
    if (br_ecdsa_i31_sign_raw(&br_ec_p256_m64, &br_sha256_vtable, th, &g_key_sk, tsig) != 64 ||
        br_ecdsa_i31_vrfy_raw(&br_ec_p256_m64, th, 32, &pub, tsig, 64) != 1) {
        ssh_unload_key();
        return 0;
    }

    br_sha256_context h;
    uint8_t d[32];
    br_sha256_init(&h);
    br_sha256_update(&h, g_key_blob, g_key_blob_len);
    br_sha256_out(&h, d);
    memcpy(g_key_fp, "SHA256:", 7);
    b64_nopad(d, 32, g_key_fp + 7);
    g_key_on = 1;
    return 1;
}

int ssh_key_loaded(void)
{
    return g_key_on;
}

const char *ssh_fingerprint(void)
{
    return g_key_fp;
}

// ---- kunci pengguna (authorized_keys) ----
// Satu blob kunci publik ecdsa-sha2-nistp256 = 4+19 + 4+8 + 4+65 = 104 byte.
#define AK_BLOB 104

static uint8_t g_ak[2][SSH_AUTHKEY_MAX][AK_BLOB];
static int g_ak_n[2];

static int b64v(int ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    return ch == '+' ? 62 : (ch == '/' ? 63 : -1);
}

// Base64 baku (padding wajib, panjang kelipatan 4, '=' hanya di ujung). Return byte atau -1.
static int b64_dec(const uint8_t *s, uint32_t n, uint8_t *out, uint32_t cap)
{
    uint32_t o = 0;

    if (n == 0 || n % 4 != 0) {
        return -1;
    }
    for (uint32_t i = 0; i < n; i += 4) {
        int v[4], pad = 0;

        for (int k = 0; k < 4; k++) {
            uint8_t ch = s[i + k];

            if (ch == '=') {
                if (i + 4 != n || k < 2) {
                    return -1;
                }
                pad++;
                v[k] = 0;
            } else if (pad || (v[k] = b64v(ch)) < 0) {
                return -1;
            }
        }
        uint32_t x = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 | (uint32_t)v[2] << 6 | (uint32_t)v[3];

        if (o + 3 - (uint32_t)pad > cap) {
            return -1;
        }
        out[o++] = (uint8_t)(x >> 16);
        if (pad < 2) {
            out[o++] = (uint8_t)(x >> 8);
        }
        if (pad < 1) {
            out[o++] = (uint8_t)x;
        }
    }
    return (int)o;
}

// Titik P-256 tak terkompresi sah (di kurva)? Kalikan dengan skalar 1: BearSSL menolak titik
// di luar kurva (point_decode memeriksa persamaan kurva).
static int p256_point_ok(const uint8_t *q)
{
    uint8_t t[65];
    static const uint8_t one[1] = { 1 };

    if (q[0] != 4) {
        return 0;
    }
    memcpy(t, q, 65);
    return br_ec_p256_m64.mul(t, 65, one, 1, BR_EC_secp256r1) == 1;
}

// Blob sah: string "ecdsa-sha2-nistp256", string "nistp256", string Q (65 byte, titik sah).
static int ak_blob_ok(const uint8_t *b, uint32_t n)
{
    rd_t r = { b, n, 0 };
    uint32_t a, bn, qn;
    const uint8_t *s1 = r_str(&r, &a);
    const uint8_t *s2 = r_str(&r, &bn);
    const uint8_t *q = r_str(&r, &qn);

    return !r.err && r.n == 0 && n == AK_BLOB && tok_eq(s1, a, "ecdsa-sha2-nistp256") &&
           tok_eq(s2, bn, "nistp256") && qn == 65 && p256_point_ok(q);
}

int ssh_authkey_count(int role)
{
    return (role == SSH_ROLE_ADMIN || role == SSH_ROLE_RO) ? g_ak_n[role - 1] : 0;
}

void ssh_clear_authkeys(void)
{
    memset(g_ak, 0, sizeof(g_ak));
    g_ak_n[0] = g_ak_n[1] = 0;
}

static int is_ws(uint8_t c)
{
    return c == ' ' || c == '\t';
}

// Satu baris authorized_keys -> blob (AK_BLOB byte) atau 0 bila dilewati.
static int ak_line(const uint8_t *l, uint32_t n, uint8_t *blob)
{
    uint8_t tmp[AK_BLOB + 8];
    uint32_t i = 0, j;

    while (i < n && is_ws(l[i])) {
        i++;
    }
    if (i == n || l[i] == '#') {
        return 0;
    }
    for (j = i; j < n && !is_ws(l[j]); j++) {
    }
    if (!tok_eq(l + i, j - i, "ecdsa-sha2-nistp256")) {
        return 0;   // opsi di depan atau tipe lain
    }
    while (j < n && is_ws(l[j])) {
        j++;
    }
    for (i = j; j < n && !is_ws(l[j]); j++) {
    }
    int bn = b64_dec(l + i, j - i, tmp, sizeof(tmp));

    if (bn != AK_BLOB || !ak_blob_ok(tmp, (uint32_t)bn)) {
        return 0;
    }
    memcpy(blob, tmp, AK_BLOB);
    return 1;
}

int ssh_set_authkeys(int role, const uint8_t *txt, uint32_t len)
{
    if (role != SSH_ROLE_ADMIN && role != SSH_ROLE_RO) {
        return 0;
    }
    int ri = role - 1, cnt = 0;
    uint8_t nk[SSH_AUTHKEY_MAX][AK_BLOB];
    uint32_t i = 0;

    while (txt != 0 && i < len) {
        uint32_t j = i;

        while (j < len && txt[j] != '\n') {
            j++;
        }
        uint32_t e = j;

        if (e > i && txt[e - 1] == '\r') {
            e--;
        }
        uint8_t b[AK_BLOB];

        if (cnt < SSH_AUTHKEY_MAX && ak_line(txt + i, e - i, b)) {
            int dup = 0;

            for (int k = 0; k < cnt; k++) {
                dup |= memcmp(nk[k], b, AK_BLOB) == 0;
            }
            if (!dup) {
                memcpy(nk[cnt++], b, AK_BLOB);
            }
        }
        i = j + 1;
    }
    memset(g_ak[ri], 0, sizeof(g_ak[ri]));
    memcpy(g_ak[ri], nk, (size_t)cnt * AK_BLOB);
    g_ak_n[ri] = cnt;
    return cnt;
}

int ssh_authkey_dup(void)
{
    int d = 0;

    for (int k = 0; k < g_ak_n[0]; k++) {
        for (int j = 0; j < g_ak_n[1]; j++) {
            d += memcmp(g_ak[0][k], g_ak[1][j], AK_BLOB) == 0;
        }
    }
    return d;
}

// Peran kunci; 0 bila tidak dikenal. Kunci di kedua daftar -> ro (hak terendah), jadi ro dicek dulu.
static int ak_find(const uint8_t *b, uint32_t n)
{
    if (n != AK_BLOB) {
        return 0;
    }
    for (int r = 1; r >= 0; r--) {
        for (int k = 0; k < g_ak_n[r]; k++) {
            if (memcmp(g_ak[r][k], b, AK_BLOB) == 0) {
                return r + 1;
            }
        }
    }
    return 0;
}

// ---- kirim paket ----

static void ss_close_why(ssh_sess_t *s, const char *why)
{
    s->state = SSH_ST_CLOSING;
    if (s->why == 0) {
        s->why = why;
    }
}

// Mulai paket di ekor obuf: payload ditulis mulai obuf+olen+5; 60 byte cadangan untuk
// padding (maks 19 + 4) dan tag 16.
static wr_t pk_begin(ssh_sess_t *s)
{
    wr_t w;
    uint32_t free_ = SSH_OBUF_SIZE - s->olen;

    w.p = s->obuf + s->olen + 5;
    w.n = 0;
    w.cap = free_ > 64 ? free_ - 64 : 0;
    w.err = 0;
    return w;
}

static void pk_end(ssh_sess_t *s, wr_t *w)
{
    if (w->err || w->n == 0) {
        ss_close_why(s, "buffer keluar penuh");
        return;
    }
    uint32_t pl = w->n;
    uint32_t blk = s->out_enc ? 16 : 8;
    uint32_t pad = blk - ((s->out_enc ? 1 + pl : 5 + pl) % blk);

    if (pad < 4) {
        pad += blk;
    }
    uint8_t *base = s->obuf + s->olen;
    uint32_t plen = 1 + pl + pad;

    put32(base, plen);
    base[4] = (uint8_t)pad;
    br_hmac_drbg_generate(&s->rng, base + 5 + pl, pad);

    uint32_t total = 4 + plen;

    if (s->out_enc) {
        br_gcm_reset(&s->co.gc, s->co.iv, 12);
        br_gcm_aad_inject(&s->co.gc, base, 4);
        br_gcm_flip(&s->co.gc);
        br_gcm_run(&s->co.gc, 1, base + 4, plen);
        br_gcm_get_tag(&s->co.gc, base + 4 + plen);
        total += 16;
        for (int i = 11; i >= 4; i--) {   // pencacah 64 bit big-endian
            if (++s->co.iv[i] != 0) {
                break;
            }
        }
    }
    s->olen += total;
    s->seq_out++;
    s->pk_out++;
    s->by_out += total;
}

static void ssh_fail(ssh_sess_t *s, uint32_t code, const char *msg, const char *why)
{
    if (s->state == SSH_ST_CLOSING) {
        return;
    }
    if (s->state != SSH_ST_VERSION) {
        wr_t w = pk_begin(s);

        w_u8(&w, M_DISCONNECT);
        w_u32(&w, code);
        w_cstr(&w, msg);
        w_cstr(&w, "");
        pk_end(s, &w);
    }
    ss_close_why(s, why);
}

// ---- X25519 (RFC 7748) lewat BearSSL ----
// API BearSSL: titik u = 32 byte LITTLE-endian (bit tinggi byte terakhir diabaikan, sesuai RFC),
// tetapi skalar = BIG-endian dan clamping dikerjakan di dalam (bearssl src/ec/ec_c25519_m64.c
// baris 661-666). Skalar RFC little-endian, jadi dibalik dulu. Hasil di u (little-endian).
// Return 0 bila gagal (panjang salah).
static int x25519(uint8_t *out, const uint8_t *k_le, const uint8_t *u_le)
{
    uint8_t k[32];

    for (int i = 0; i < 32; i++) {
        k[i] = k_le[31 - i];
    }
    memcpy(out, u_le, 32);

    uint32_t r = br_ec_c25519_m64.mul(out, 32, k, 32, BR_EC_curve25519);

    secure_zero(k, sizeof(k));
    return (int)r;
}

static const uint8_t k_x25519_base[32] = { 9 };

static void ssh_run(ssh_sess_t *s);

// ---- sesi ----

static void build_kexinit(ssh_sess_t *s)
{
    wr_t w = pk_begin(s);
    uint8_t cookie[16];

    br_hmac_drbg_generate(&s->rng, cookie, sizeof(cookie));
    w_u8(&w, M_KEXINIT);
    w_bytes(&w, cookie, 16);
    w_cstr(&w, "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com");
    w_cstr(&w, "ecdsa-sha2-nistp256");
    w_cstr(&w, "aes128-gcm@openssh.com");
    w_cstr(&w, "aes128-gcm@openssh.com");
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, "hmac-sha2-256");
    w_cstr(&w, "none");
    w_cstr(&w, "none");
    w_cstr(&w, "");
    w_cstr(&w, "");
    w_u8(&w, 0);
    w_u32(&w, 0);
    if (!w.err && w.n <= sizeof(s->is)) {
        memcpy(s->is, w.p, w.n);   // payload tepat seperti yang dikirim
        s->is_len = w.n;
    } else {
        w.err = 1;
    }
    pk_end(s, &w);
}

int ssh_open(void)
{
    if (!g_key_on) {
        return SSH_ERR_NOKEY;
    }

    int i = -1;

    for (int k = 0; k < SSH_MAX_SESS; k++) {
        if (!g_ssh[k].used) {
            i = k;
            break;
        }
    }
    if (i < 0) {
        return SSH_ERR_FULL;
    }

    uint8_t seed[32];

    if (!entropy_get(seed, sizeof(seed))) {
        return SSH_ERR_ENTROPY;
    }

    ssh_sess_t *s = &g_ssh[i];

    secure_zero(s, sizeof(*s));
    br_hmac_drbg_init(&s->rng, &br_sha256_vtable, seed, sizeof(seed));
    secure_zero(seed, sizeof(seed));
    s->used = 1;
    s->state = SSH_ST_VERSION;
    s->why = 0;

    memcpy(s->obuf, SSH_BANNER "\r\n", sizeof(SSH_BANNER) + 1);
    s->olen = (uint32_t)sizeof(SSH_BANNER) + 1;
    build_kexinit(s);
    if (s->state == SSH_ST_CLOSING) {   // tidak mungkin pada buffer kosong; gagal tertutup
        secure_zero(s, sizeof(*s));
        return SSH_ERR_ENTROPY;
    }
    return i;
}

void ssh_close(int i)
{
    if (i < 0 || i >= SSH_MAX_SESS) {
        return;
    }
    secure_zero(&g_ssh[i], sizeof(g_ssh[i]));   // kunci sesi, DRBG, hash, buffer
}

int ssh_state(int i)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used) {
        return SSH_ST_FREE;
    }
    return g_ssh[i].state;
}

const char *ssh_why(int i)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used || g_ssh[i].why == 0) {
        return "";
    }
    return g_ssh[i].why;
}

int ssh_done(int i)
{
    return i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used && g_ssh[i].state == SSH_ST_CLOSING &&
           g_ssh[i].olen == 0;
}

int ssh_cipher_active(int i)
{
    return i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used && g_ssh[i].out_enc;
}

const uint8_t *ssh_out_peek(int i, uint32_t *len)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used) {
        *len = 0;
        return 0;
    }
    *len = g_ssh[i].olen;
    return g_ssh[i].obuf;
}

void ssh_out_consume(int i, uint32_t n)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used) {
        return;
    }
    ssh_sess_t *s = &g_ssh[i];

    if (n > s->olen) {
        n = s->olen;
    }
    memmove(s->obuf, s->obuf + n, s->olen - n);
    s->olen -= n;
    ssh_run(s);   // ruang keluar bertambah: lanjutkan sisa buffer masuk tanpa perlu ssh_feed(s,0,0)
}

// ---- masukan: baris versi ----

// 1 = ada kemajuan, 0 = butuh byte lagi (atau sudah CLOSING).
static int proc_version(ssh_sess_t *s)
{
    uint32_t avail = s->ilen - s->ipos;
    const uint8_t *p = s->ibuf + s->ipos;
    uint32_t lim = avail < 255 ? avail : 255;
    uint32_t i = 0;

    while (i < lim && p[i] != '\n') {
        i++;
    }
    if (i == lim) {
        if (avail >= 255) {
            ssh_fail(s, D_PROTO, "baris versi terlalu panjang", "baris versi > 255 byte");
            return 0;
        }
        return 0;
    }
    uint32_t n = i;   // panjang tanpa LF

    if (n > 0 && p[n - 1] == '\r') {
        n--;
    }
    for (uint32_t k = 0; k < n; k++) {
        if (p[k] == 0) {
            ssh_fail(s, D_PROTO, "baris versi tidak sah", "NUL di baris versi");
            return 0;
        }
    }
    if (n >= 4 && memcmp(p, "SSH-", 4) == 0) {
        if (n < 8 || memcmp(p, "SSH-2.0-", 8) != 0) {
            ssh_fail(s, D_PROTO, "hanya SSH-2.0", "versi protokol klien bukan SSH-2.0");
            return 0;
        }
        memcpy(s->vc, p, n);
        s->vc_len = n;
        s->state = SSH_ST_KEX;
        s->kstage = K_WAIT_KEXINIT;
    } else if (++s->pre_lines > 8) {
        ssh_fail(s, D_PROTO, "terlalu banyak baris sebelum banner", "baris sebelum banner > 8");
        return 0;
    }
    s->ipos += i + 1;
    return 1;
}

// ---- turunan kunci (RFC 4253 7.2) ----

// HASH(K || H || huruf || session_id), K sebagai mpint (dengan panjang).
static void kdf32(const uint8_t *kmp, uint32_t kmp_len, const uint8_t *h, char letter,
                  const uint8_t *sid, uint8_t *out)
{
    br_sha256_context c;

    br_sha256_init(&c);
    br_sha256_update(&c, kmp, kmp_len);
    br_sha256_update(&c, h, 32);
    br_sha256_update(&c, &letter, 1);
    br_sha256_update(&c, sid, 32);
    br_sha256_out(&c, out);
    secure_zero(&c, sizeof(c));   // konteks memuat blok K
}

static void gcm_setup(ssh_gcm_t *g, const uint8_t *key, const uint8_t *iv)
{
    br_aes_ct64_ctr_init(&g->ks, key, 16);
    br_gcm_init(&g->gc, &g->ks.vtable, br_ghash_ctmul64);
    memcpy(g->iv, iv, 12);
}

// ---- KEXINIT klien ----

static void h_kexinit(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    rd_t r = { pl, n, 0 };
    uint32_t ln[10];
    const uint8_t *l[10];

    r_u8(&r);
    if (r.n < 16) {
        ssh_fail(s, D_PROTO, "KEXINIT terpotong", "KEXINIT terpotong");
        return;
    }
    r.p += 16;
    r.n -= 16;
    for (int i = 0; i < 10; i++) {
        l[i] = r_str(&r, &ln[i]);
    }
    uint8_t follows = r_u8(&r);

    r_u32(&r);
    if (r.err) {
        ssh_fail(s, D_PROTO, "KEXINIT cacat", "KEXINIT cacat");
        return;
    }
    s->strict = nl_has(l[0], ln[0], "kex-strict-c-v00@openssh.com");
    if (s->strict && s->cur_seq != 0) {
        ssh_fail(s, D_PROTO, "strict kex: KEXINIT harus paket pertama", "strict kex: KEXINIT bukan paket pertama");
        return;
    }
    int kx = nl_pick(l[0], ln[0], k_kex, 2);
    int hk = nl_pick(l[1], ln[1], k_hostkey, 1);
    int c1 = nl_pick(l[2], ln[2], k_cipher, 1);
    int c2 = nl_pick(l[3], ln[3], k_cipher, 1);
    int z1 = nl_pick(l[6], ln[6], k_comp, 1);
    int z2 = nl_pick(l[7], ln[7], k_comp, 1);

    // MAC klien tidak dinegosiasikan: cipher AEAD membawa tag sendiri.
    if (kx < 0 || hk < 0 || c1 < 0 || c2 < 0 || z1 < 0 || z2 < 0) {
        ssh_fail(s, D_KEXFAIL, "tidak ada algoritme yang cocok", "tidak ada algoritme yang cocok");
        return;
    }
    // RFC 4253 7: tebakan klien salah bila nama kex/hostkey PERTAMA klien berbeda dari nama
    // pertama SERVER (bukan dari hasil negosiasi).
    if (follows && (!nl_first_is(l[0], ln[0], k_kex[0]) || !nl_first_is(l[1], ln[1], k_hostkey[0]))) {
        s->ignore_next = 1;
    }
    // H dimulai di sini: V_C, V_S, I_C (payload ini), I_S.
    uint8_t len4[4];

    br_sha256_init(&s->hash);
    put32(len4, s->vc_len);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, s->vc, s->vc_len);
    put32(len4, (uint32_t)sizeof(SSH_BANNER) - 1);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, SSH_BANNER, sizeof(SSH_BANNER) - 1);
    put32(len4, n);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, pl, n);
    put32(len4, s->is_len);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, s->is, s->is_len);
    s->kstage = K_WAIT_DH;
}

// Blob tanda tangan RFC 5656 3.1.2: string "ecdsa-sha2-nistp256", string(mpint r, mpint s).
// sig = r||s mentah (2 x 32 byte big-endian); mpint membuang nol di depan dan menambah 0x00
// bila bit tinggi, jadi panjang r/s di kawat 31..33 byte (kanonik, tidak dipotong sembarangan).
static void encode_sig(wr_t *w, const uint8_t *sig)
{
    uint8_t rs[80];
    wr_t rw = { rs, 0, sizeof(rs), 0 };

    w_cstr(w, "ecdsa-sha2-nistp256");
    w_mpint(&rw, sig, 32);
    w_mpint(&rw, sig + 32, 32);
    w_str(w, rs, rw.n);
    if (rw.err) {
        w->err = 1;
    }
}

// ---- KEXDH_INIT ----

static void h_kexdh(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    rd_t r = { pl + 1, n - 1, 0 };
    uint32_t qn = 0;
    const uint8_t *qc = r_str(&r, &qn);

    if (r.err || r.n != 0 || qn != 32) {
        ssh_fail(s, D_KEXFAIL, "kunci publik klien tidak sah", "Q_C bukan 32 byte");
        return;
    }
    uint8_t x[32], qs[32], k[32];

    br_hmac_drbg_generate(&s->rng, x, sizeof(x));
    if (!x25519(qs, x, k_x25519_base) || !x25519(k, x, qc)) {
        secure_zero(x, sizeof(x));
        ssh_fail(s, D_KEXFAIL, "pertukaran kunci gagal", "x25519 gagal");
        return;
    }
    secure_zero(x, sizeof(x));

    uint8_t acc = 0;   // waktu-konstan: semua byte diperiksa
    for (int i = 0; i < 32; i++) {
        acc |= k[i];
    }
    if (acc == 0) {
        secure_zero(k, sizeof(k));
        ssh_fail(s, D_KEXFAIL, "rahasia bersama nol", "K nol (titik orde kecil)");
        return;
    }

    // mpint K (dengan panjang) sekali, dipakai hash dan KDF.
    uint8_t kmp[4 + 33];
    wr_t kw = { kmp, 0, sizeof(kmp), 0 };

    w_mpint(&kw, k, 32);
    secure_zero(k, sizeof(k));

    uint8_t len4[4], h[32];

    put32(len4, g_key_blob_len);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, g_key_blob, g_key_blob_len);
    put32(len4, 32);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, qc, 32);
    br_sha256_update(&s->hash, len4, 4);
    br_sha256_update(&s->hash, qs, 32);
    br_sha256_update(&s->hash, kmp, kw.n);
    br_sha256_out(&s->hash, h);
    secure_zero(&s->hash, sizeof(s->hash));   // buffer parsial konteks memuat bagian K
    memcpy(s->sid, h, 32);   // kex pertama (satu-satunya): session_id = H

    // tanda tangan ECDSA P-256 atas SHA-256(H): r,s (mpint) di dalam string (RFC 5656 3.1.2)
    uint8_t hh[32], sig[64];
    br_sha256_context c;

    br_sha256_init(&c);
    br_sha256_update(&c, h, 32);
    br_sha256_out(&c, hh);
    if (br_ecdsa_i31_sign_raw(&br_ec_p256_m64, &br_sha256_vtable, hh, &g_key_sk, sig) != 64) {
        secure_zero(kmp, sizeof(kmp));
        ssh_fail(s, D_KEXFAIL, "tanda tangan gagal", "ECDSA sign gagal");
        return;
    }
    uint8_t sb[128];
    wr_t sw = { sb, 0, sizeof(sb), 0 };

    encode_sig(&sw, sig);
    if (sw.err) {
        secure_zero(kmp, sizeof(kmp));
        ssh_fail(s, D_KEXFAIL, "tanda tangan gagal", "tanda tangan tidak muat");
        return;
    }

    wr_t w = pk_begin(s);

    w_u8(&w, M_KEXDH_REPLY);
    w_str(&w, g_key_blob, g_key_blob_len);
    w_str(&w, qs, 32);
    w_str(&w, sb, sw.n);
    pk_end(s, &w);
    if (s->state != SSH_ST_CLOSING) {
        w = pk_begin(s);
        w_u8(&w, M_NEWKEYS);
        pk_end(s, &w);
    }
    if (s->state == SSH_ST_CLOSING) {   // buffer keluar penuh: jangan pasang kunci
        secure_zero(kmp, sizeof(kmp));
        secure_zero(h, sizeof(h));
        return;
    }

    // Kunci: A/B = IV c2s/s2c, C/D = kunci c2s/s2c. Server: masuk = c2s, keluar = s2c.
    uint8_t civ[32], skey[32], siv[32], ckey[32];

    kdf32(kmp, kw.n, h, 'A', s->sid, civ);
    kdf32(kmp, kw.n, h, 'B', s->sid, siv);
    kdf32(kmp, kw.n, h, 'C', s->sid, ckey);
    kdf32(kmp, kw.n, h, 'D', s->sid, skey);
    secure_zero(kmp, sizeof(kmp));
    secure_zero(h, sizeof(h));
    gcm_setup(&s->co, skey, siv);
    s->out_enc = 1;
    memcpy(s->in_key, ckey, 16);
    memcpy(s->in_iv, civ, 12);
    secure_zero(civ, sizeof(civ));
    secure_zero(siv, sizeof(siv));
    secure_zero(ckey, sizeof(ckey));
    secure_zero(skey, sizeof(skey));
    if (s->strict) {
        s->seq_out = 0;   // OpenSSH PROTOCOL 1.10: reset setelah NEWKEYS dikirim
    }
    s->kstage = K_WAIT_NEWKEYS;
}

// ---- pesan setelah kex ----

static void send_unimpl(ssh_sess_t *s)
{
    wr_t w = pk_begin(s);

    w_u8(&w, M_UNIMPL);
    w_u32(&w, s->cur_seq);
    pk_end(s, &w);
}

// ---- callback kernel: exec + audit ----

static ssh_exec_fn g_exec_fn;
static ssh_audit_fn g_audit_fn;

void ssh_set_exec(ssh_exec_fn f)
{
    g_exec_fn = f;
}

void ssh_set_audit(ssh_audit_fn f)
{
    g_audit_fn = f;
}

static void audit(ssh_sess_t *s, int ev, const uint8_t *txt, uint32_t len)
{
    if (g_audit_fn) {
        g_audit_fn((int)(s - g_ssh), ev, s->role, txt, len);
    }
}

// ---- userauth publickey (RFC 4252 7, RFC 5656 3.1) ----

static void hs_str(br_sha256_context *h, const void *d, uint32_t n)
{
    uint8_t l4[4];

    put32(l4, n);
    br_sha256_update(h, l4, 4);
    br_sha256_update(h, d, n);
}

// mpint (sudah dibaca sebagai isi) -> 32 byte big-endian. 0 bila negatif, kosong, atau > 32 byte.
static int mp_to32(const uint8_t *v, uint32_t n, uint8_t *o)
{
    if (n > 0 && (v[0] & 0x80)) {
        return 0;   // negatif
    }
    while (n > 0 && v[0] == 0) {
        v++;
        n--;
    }
    if (n == 0 || n > 32) {
        return 0;
    }
    memset(o, 0, 32);
    memcpy(o + 32 - n, v, n);
    return 1;
}

// Verifikasi tanda tangan atas: string session_id, byte 50, string user, string service,
// string "publickey", bool 1, string alg, string blob.
static int ua_verify(ssh_sess_t *s, const uint8_t *user, uint32_t un, const uint8_t *svc, uint32_t sn,
                     const uint8_t *alg, uint32_t an, const uint8_t *blob, uint32_t bn,
                     const uint8_t *sig, uint32_t sgn)
{
    rd_t r = { sig, sgn, 0 };
    uint32_t nn, in;
    const uint8_t *nm = r_str(&r, &nn);
    const uint8_t *inner = r_str(&r, &in);

    if (r.err || r.n != 0 || !tok_eq(nm, nn, "ecdsa-sha2-nistp256")) {
        return 0;
    }
    rd_t m = { inner, in, 0 };
    uint32_t rn, sn2;
    const uint8_t *rv = r_str(&m, &rn);
    const uint8_t *sv = r_str(&m, &sn2);
    uint8_t raw[64];

    if (m.err || m.n != 0 || !mp_to32(rv, rn, raw) || !mp_to32(sv, sn2, raw + 32)) {
        return 0;
    }
    br_sha256_context h;
    uint8_t d[32], one = 1, mt = M_UA_REQ;

    br_sha256_init(&h);
    hs_str(&h, s->sid, 32);
    br_sha256_update(&h, &mt, 1);
    hs_str(&h, user, un);
    hs_str(&h, svc, sn);
    hs_str(&h, "publickey", 9);
    br_sha256_update(&h, &one, 1);
    hs_str(&h, alg, an);
    hs_str(&h, blob, bn);
    br_sha256_out(&h, d);

    br_ec_public_key pub;

    pub.curve = BR_EC_secp256r1;
    pub.q = (uint8_t *)blob + (bn - 65);   // Q = 65 byte terakhir blob (blob sudah dicocokkan)
    pub.qlen = 65;
    return br_ecdsa_i31_vrfy_raw(&br_ec_p256_m64, d, 32, &pub, raw, 64) == 1;
}

static void ua_failure(ssh_sess_t *s)
{
    wr_t w = pk_begin(s);

    w_u8(&w, M_UA_FAILURE);
    w_cstr(&w, "publickey");
    w_u8(&w, 0);
    pk_end(s, &w);
}

static void ch_init(ssh_sess_t *s);

static void h_userauth(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    if (s->state == SSH_ST_CONN) {
        return;   // setelah sukses: diabaikan (RFC 4252 5.3)
    }
    if (s->state != SSH_ST_AUTH) {
        ssh_fail(s, D_PROTO, "userauth sebelum layanan diminta", "USERAUTH_REQUEST sebelum SERVICE_REQUEST");
        return;
    }
    rd_t r = { pl + 1, n - 1, 0 };
    uint32_t un, sn, mn, an = 0, bn = 0, gn = 0;
    const uint8_t *user = r_str(&r, &un);
    const uint8_t *svc = r_str(&r, &sn);
    const uint8_t *meth = r_str(&r, &mn);
    const uint8_t *alg = 0, *blob = 0, *sig = 0;
    int has = 0, pubk = !r.err && tok_eq(meth, mn, "publickey");

    if (pubk) {
        has = r_u8(&r) != 0;
        alg = r_str(&r, &an);
        blob = r_str(&r, &bn);
        if (has) {
            sig = r_str(&r, &gn);
        }
    }
    if (r.err || (pubk && r.n != 0)) {
        ssh_fail(s, D_PROTO, "USERAUTH_REQUEST cacat", "USERAUTH_REQUEST cacat");
        return;
    }
    if (++s->req_n > SSH_UA_REQ_MAX) {
        ssh_fail(s, D_NO_AUTH, "terlalu banyak permintaan autentikasi", "userauth: > 32 permintaan");
        return;
    }
    if (!pubk || !tok_eq(svc, sn, "ssh-connection")) {
        ua_failure(s);   // none / metode lain / layanan lain: tidak dihitung
        return;
    }
    int role = tok_eq(alg, an, "ecdsa-sha2-nistp256") ? ak_find(blob, bn) : 0;

    if (!has) {
        if (!role) {
            ua_failure(s);
            return;
        }
        wr_t w = pk_begin(s);

        w_u8(&w, M_UA_PK_OK);
        w_str(&w, alg, an);
        w_str(&w, blob, bn);
        pk_end(s, &w);
        return;
    }
    uint32_t cn = un > SSH_USER_MAX ? SSH_USER_MAX : un;
    char nm[SSH_USER_MAX + 1];

    for (uint32_t i = 0; i < cn; i++) {   // karakter non-cetak -> '?'
        nm[i] = (user[i] >= 0x20 && user[i] < 0x7f) ? (char)user[i] : '?';
    }
    nm[cn] = 0;
    if (role && ua_verify(s, user, un, svc, sn, alg, an, blob, bn, sig, gn)) {
        wr_t w = pk_begin(s);

        w_u8(&w, M_UA_SUCCESS);
        pk_end(s, &w);
        if (s->state == SSH_ST_CLOSING) {
            return;
        }
        s->role = role;
        memcpy(s->user, nm, cn + 1);
        s->state = SSH_ST_CONN;
        ch_init(s);
        audit(s, SSH_EV_LOGIN, (const uint8_t *)nm, cn);
        return;
    }
    ua_failure(s);
    audit(s, SSH_EV_LOGIN_FAIL, (const uint8_t *)nm, cn);
    if (!role) {
        return;   // kunci tidak terdaftar / alg lain: hanya batas 32 permintaan yang berlaku
    }
    if (++s->auth_n >= SSH_AUTH_MAX) {
        ssh_fail(s, D_NO_AUTH, "terlalu banyak percobaan autentikasi", "userauth: 4 percobaan");
    }
}

static void h_conn(ssh_sess_t *s, const uint8_t *pl, uint32_t n);

static void h_post(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    uint8_t msg = pl[0];

    // RFC 4252 6: pesan >= 80 (layanan/kanal) sebelum userauth sukses tidak sah. Userauth
    // belum pernah sukses di SSH-1a, jadi selalu DISCONNECT.
    if (msg >= 80 && s->state == SSH_ST_CONN) {
        h_conn(s, pl, n);
        return;
    }
    if (msg >= 80) {
        ssh_fail(s, D_PROTO, "pesan sebelum autentikasi", "pesan >= 80 sebelum userauth");
        return;
    }
    switch (msg) {
    case M_IGNORE:
    case M_DEBUG:
    case M_UNIMPL:
        return;
    case M_KEXINIT:
        ssh_fail(s, D_PROTO, "rekey tidak didukung", "KEXINIT kedua (rekey)");
        return;
    case M_NEWKEYS:
        ssh_fail(s, D_PROTO, "NEWKEYS tidak terduga", "NEWKEYS tidak terduga");
        return;
    case M_SVC_REQ: {
        rd_t r = { pl + 1, n - 1, 0 };
        uint32_t sn = 0;
        const uint8_t *sv = r_str(&r, &sn);

        if (s->state != SSH_ST_SERVICE || r.err || r.n != 0 || !tok_eq(sv, sn, "ssh-userauth")) {
            ssh_fail(s, D_SVC_NA, "layanan tidak tersedia", "SERVICE_REQUEST tidak sah (bukan ssh-userauth, bukan state SERVICE, atau ada sisa byte)");
            return;
        }
        wr_t w = pk_begin(s);

        w_u8(&w, M_SVC_ACCEPT);
        w_cstr(&w, "ssh-userauth");
        pk_end(s, &w);
        s->state = SSH_ST_AUTH;
        return;
    }
    case M_UA_REQ:
        h_userauth(s, pl, n);
        return;
    default:
        // Batas UNIMPLEMENTED pra-auth: klien yang terus mengirim pesan tak dikenal ditutup.
        if (++s->unimpl_n > g_ssh_unimpl_max) {
            ssh_fail(s, D_PROTO, "terlalu banyak pesan tak dikenal", "UNIMPLEMENTED > batas");
            return;
        }
        send_unimpl(s);
        return;
    }
}

// ---- lapisan koneksi (RFC 4254): satu kanal session, exec / shell ----
// Keluaran perintah ditaruh di s->pend, lalu chan_pump() memecahnya ke obuf menurut window dan max
// packet klien serta ruang obuf. exit-status/EOF/CLOSE baru dikirim setelah pend habis, jadi tidak
// pernah mendahului data. Sesi ke CLOSING SEGERA setelah CLOSE server terkirim (tidak menunggu CLOSE
// klien): paling sederhana dan tidak bisa digantung klien; TCP baru ditutup net.c saat ssh_done()
// (obuf habis). CLOSE dari klien lebih dulu -> balas CLOSE lalu CLOSING.

#define CH_PROMPT "bmahOS> "
#define CH_HEADROOM 512   // ruang obuf yang disisakan paket DATA untuk paket kendali / DISCONNECT

static void ch_init(ssh_sess_t *s)
{
    s->ch_open = 0;
    s->ch_used = 0;
}

static void ch_put(ssh_sess_t *s, const char *t)   // pend := t (pend sudah kosong)
{
    uint32_t n = (uint32_t)strlen(t);

    memcpy(s->pend, t, n);
    s->pend_off = 0;
    s->pend_len = n;
}

static void ch_simple(ssh_sess_t *s, uint8_t msg)   // pesan + penerima = id kanal klien
{
    wr_t w = pk_begin(s);

    w_u8(&w, msg);
    w_u32(&w, s->cl_id);
    pk_end(s, &w);
}

static void chan_pump(ssh_sess_t *s)
{
    if (s->state != SSH_ST_CONN || !s->ch_open || s->ch_close_sent) {
        return;
    }
    uint32_t free_ = SSH_OBUF_SIZE - s->olen;

    if (s->win_in < SSH_WIN_IN / 2 && s->win_credit > 0 && free_ >= 600) {
        wr_t w = pk_begin(s);

        w_u8(&w, M_CH_WINADJ);
        w_u32(&w, s->cl_id);
        w_u32(&w, s->win_credit);
        pk_end(s, &w);
        s->win_in += s->win_credit;
        s->win_credit = 0;
    }
    while (s->state == SSH_ST_CONN && s->pend_off < s->pend_len) {
        free_ = SSH_OBUF_SIZE - s->olen;
        if (free_ < 73 + CH_HEADROOM + 1) {
            break;
        }
        uint32_t n = s->pend_len - s->pend_off;

        if (n > s->cl_win) {
            n = s->cl_win;
        }
        if (n > s->cl_max) {
            n = s->cl_max;
        }
        if (n > free_ - 73 - CH_HEADROOM) {
            n = free_ - 73 - CH_HEADROOM;
        }
        if (n == 0) {
            break;
        }
        wr_t w = pk_begin(s);

        w_u8(&w, M_CH_DATA);
        w_u32(&w, s->cl_id);
        w_str(&w, s->pend + s->pend_off, n);
        pk_end(s, &w);
        s->cl_win -= n;
        s->pend_off += n;
    }
    if (s->pend_off >= s->pend_len) {
        s->pend_off = s->pend_len = 0;
    }
    free_ = SSH_OBUF_SIZE - s->olen;
    if (s->state == SSH_ST_CONN && s->ch_fin && s->pend_len == 0 && free_ >= 600) {
        wr_t w = pk_begin(s);

        w_u8(&w, M_CH_REQ);
        w_u32(&w, s->cl_id);
        w_cstr(&w, "exit-status");
        w_u8(&w, 0);
        w_u32(&w, s->ch_code);
        pk_end(s, &w);
        ch_simple(s, M_CH_EOF);
        ch_simple(s, M_CH_CLOSE);
        s->ch_close_sent = 1;
        ss_close_why(s, "sesi selesai");
    }
}

// Audit penolakan: maks 16 byte pertama, non-cetak jadi '?'.
static void audit_cmd_fail(ssh_sess_t *s, const uint8_t *cmd, uint32_t len)
{
    uint8_t t[16];
    uint32_t n = len > 16 ? 16 : len;

    for (uint32_t i = 0; i < n; i++) {
        t[i] = (cmd[i] >= 0x20 && cmd[i] < 0x7f) ? cmd[i] : '?';
    }
    audit(s, SSH_EV_CMD_FAIL, t, n);
}

// Perintah sah: 1..SSH_CMD_MAX byte, semuanya 0x20..0x7e.
static int cmd_valid(const uint8_t *cmd, uint32_t len)
{
    if (len == 0 || len > SSH_CMD_MAX) {
        return 0;
    }
    for (uint32_t i = 0; i < len; i++) {
        if (cmd[i] < 0x20 || cmd[i] > 0x7e) {
            return 0;
        }
    }
    return 1;
}

// Jalankan satu perintah; keluarannya masuk pend (kosong sebelumnya). Return exit-status.
// len > SSH_CMD_MAX = terlalu panjang (cmd tetap menunjuk >= 16 byte); ditolak tanpa callback.
static uint32_t run_cmd(ssh_sess_t *s, const uint8_t *cmd, uint32_t len, int shell)
{
    uint32_t o = 0;
    int reboot = 0, denied = 0;

    s->pend_off = 0;
    if (!cmd_valid(cmd, len)) {
        audit_cmd_fail(s, cmd, len);
        ch_put(s, len > SSH_CMD_MAX ? (shell ? "ERR: baris terlalu panjang\n" : "ERR: perintah terlalu panjang\n")
                                    : "ERR: perintah tidak sah\n");
        return 1;
    }
    s->cmd_n++;
    audit(s, SSH_EV_CMD, cmd, len);
    if (!g_exec_fn) {
        ch_put(s, "ERR: perintah tidak tersedia\n");
        o = s->pend_len;
    } else {
        o = g_exec_fn(s->role, cmd, len, s->pend, SSH_CMD_OUT_MAX, &reboot, &denied);
        if (o > SSH_CMD_OUT_MAX) {
            o = SSH_CMD_OUT_MAX;
        }
        s->pend_len = o;
    }
    if (denied) {
        audit(s, SSH_EV_CMD_ROLE, cmd, len);
    }
    if (reboot) {
        s->reboot = 1;
        s->ch_fin = 1;   // setelah keluaran: exit-status, EOF, CLOSE, lalu CLOSING
    }
    return (o >= 3 && memcmp(s->pend, "ERR", 3) == 0) ? 1 : 0;
}

// Satu baris lengkap (n byte di s->ln, over = melebihi batas) -> respons di pend / fin.
static void shell_exec_line(ssh_sess_t *s, uint32_t n, int over)
{
    // Spasi/tab di akhir dibuang (cmd.exe menambah spasi sebelum '&' / ')' dalam pipa;
    // CLI UDP juga membuangnya). Baris berisi spasi saja = baris kosong.
    while (!over && n > 0 && (s->ln[n - 1] == ' ' || s->ln[n - 1] == '\t')) {
        n--;
    }
    if (over) {
        s->ch_code = run_cmd(s, s->ln, SSH_CMD_MAX + 1, 1);
    } else if (n == 0) {
        ch_put(s, CH_PROMPT);
        return;
    } else if (n == 4 && memcmp(s->ln, "exit", 4) == 0) {
        s->ch_code = 0;
        s->ch_fin = 1;
        return;
    } else {
        s->ch_code = run_cmd(s, s->ln, n, 1);
    }
    if (!s->ch_fin) {
        memcpy(s->pend + s->pend_len, CH_PROMPT, sizeof(CH_PROMPT) - 1);
        s->pend_len += sizeof(CH_PROMPT) - 1;
    }
}

// Proses masukan shell sampai satu baris menghasilkan respons. 1 = ada respons / fin.
// Akhir baris: LF, CR, atau CRLF (LF tepat setelah CR dibuang; ln_cr bertahan antar paket).
static int shell_line(ssh_sess_t *s)
{
    while (s->inq_pos < s->inq_len) {
        uint8_t ch = s->inq[s->inq_pos++];

        s->win_credit++;
        if (ch == '\n' && s->ln_cr) {
            s->ln_cr = 0;
            continue;
        }
        if (ch != '\n' && ch != '\r') {
            s->ln_cr = 0;
            if (s->ln_n < SSH_CMD_MAX) {
                s->ln[s->ln_n++] = ch;
            } else {
                s->ln_over = 1;   // buang sampai akhir baris
            }
            continue;
        }
        s->ln_cr = (ch == '\r');
        uint32_t n = s->ln_n;
        int over = s->ln_over;

        s->ln_n = 0;
        s->ln_over = 0;
        shell_exec_line(s, n, over);
        return 1;
    }
    s->inq_pos = s->inq_len = 0;
    return 0;
}

static void chan_step(ssh_sess_t *s)
{
    if (s->state != SSH_ST_CONN || !s->ch_open || s->ch_close_sent) {
        return;
    }
    for (;;) {
        chan_pump(s);
        if (s->state != SSH_ST_CONN || s->ch_close_sent || s->ch_fin || s->ch_kind != CK_SHELL ||
            s->pend_len != 0) {
            return;
        }
        if (shell_line(s)) {
            continue;
        }
        if (s->ch_eof_in) {
            // Baris sisa tanpa akhir baris dijalankan dulu (bila tidak over); exit-status = kode
            // perintah terakhir (ch_code, 0 bila belum ada perintah).
            if (s->ln_n > 0 && !s->ln_over) {
                uint32_t n = s->ln_n;

                s->ln_n = 0;
                shell_exec_line(s, n, 0);
                continue;
            }
            s->ln_n = 0;
            s->ln_over = 0;
            s->ch_fin = 1;
        }
        chan_pump(s);   // kreditkan window masuk dari byte yang baru dikonsumsi
        if (!s->ch_fin) {
            return;
        }
    }
}

static void ch_reply(ssh_sess_t *s, int want, int ok)
{
    if (want) {
        ch_simple(s, ok ? M_CH_SUCCESS : M_CH_FAILURE);
    }
}

static int ch_known(ssh_sess_t *s, uint32_t recip)
{
    if (recip != 0 || !s->ch_open) {
        ssh_fail(s, D_PROTO, "kanal tidak dikenal", "pesan untuk kanal tak dikenal");
        return 0;
    }
    return 1;
}

static void h_ch_open(ssh_sess_t *s, rd_t *r)
{
    uint32_t tn, id, win, mx;
    const uint8_t *t = r_str(r, &tn);

    id = r_u32(r);
    win = r_u32(r);
    mx = r_u32(r);
    if (r->err) {
        ssh_fail(s, D_PROTO, "CHANNEL_OPEN cacat", "CHANNEL_OPEN cacat");
        return;
    }
    uint32_t code = 0;

    if (!tok_eq(t, tn, "session")) {
        code = 3;   // unknown channel type
    } else if (s->ch_used) {
        code = 1;   // administratively prohibited: satu kanal per koneksi
    }
    wr_t w = pk_begin(s);

    if (code) {
        w_u8(&w, M_CH_OPENFAIL);
        w_u32(&w, id);
        w_u32(&w, code);
        w_cstr(&w, code == 3 ? "tipe kanal tidak dikenal" : "hanya satu kanal per koneksi");
        w_cstr(&w, "");
        pk_end(s, &w);
        return;
    }
    s->ch_open = s->ch_used = 1;
    s->cl_id = id;
    s->cl_win = win;
    s->cl_max = mx == 0 ? 1 : mx;
    s->win_in = SSH_WIN_IN;
    w_u8(&w, M_CH_CONFIRM);
    w_u32(&w, id);
    w_u32(&w, 0);
    w_u32(&w, SSH_WIN_IN);
    w_u32(&w, SSH_MAXPKT_IN);
    pk_end(s, &w);
}

static void h_ch_request(ssh_sess_t *s, rd_t *r)
{
    uint32_t tn, cn = 0;
    const uint8_t *t = r_str(r, &tn);
    int want = r_u8(r) != 0;
    const uint8_t *cmd = 0;
    int isexec = !r->err && tok_eq(t, tn, "exec"), isshell = !r->err && tok_eq(t, tn, "shell");

    if (isexec) {
        cmd = r_str(r, &cn);
    }
    if (r->err || (isexec && r->n != 0)) {
        ssh_fail(s, D_PROTO, "CHANNEL_REQUEST cacat", "CHANNEL_REQUEST cacat");
        return;
    }
    if ((!isexec && !isshell) || s->ch_kind != CK_NONE || s->ch_fin) {
        ch_reply(s, want, 0);   // pty-req, env, x11-req, subsystem, dst; atau kedua kali
        return;
    }
    ch_reply(s, want, 1);
    if (isexec) {
        s->ch_kind = CK_EXEC;
        while (cn > 0 && cn <= SSH_CMD_MAX && (cmd[cn - 1] == ' ' || cmd[cn - 1] == '\t')) {
            cn--;   // seperti baris shell (cn > SSH_CMD_MAX tetap "terlalu panjang")
        }
        s->ch_code = run_cmd(s, cmd, cn, 0);
        s->ch_fin = 1;
    } else {
        s->ch_kind = CK_SHELL;
        ch_put(s, CH_PROMPT);
    }
}

static void h_ch_data(ssh_sess_t *s, rd_t *r)
{
    uint32_t n;
    const uint8_t *d = r_str(r, &n);

    if (r->err || r->n != 0) {
        ssh_fail(s, D_PROTO, "CHANNEL_DATA cacat", "CHANNEL_DATA cacat");
        return;
    }
    if (n > s->win_in || n > SSH_MAXPKT_IN) {
        ssh_fail(s, D_PROTO, "melebihi window kanal", "CHANNEL_DATA melebihi window/max packet");
        return;
    }
    s->win_in -= n;
    if (s->ch_kind != CK_SHELL || s->ch_fin) {
        s->win_credit += n;   // exec / sesudah selesai: dibuang, window langsung dikreditkan
        return;
    }
    if (s->inq_pos > 0) {
        memmove(s->inq, s->inq + s->inq_pos, s->inq_len - s->inq_pos);
        s->inq_len -= s->inq_pos;
        s->inq_pos = 0;
    }
    memcpy(s->inq + s->inq_len, d, n);   // muat: win_in + credit + antrean = SSH_WIN_IN
    s->inq_len += n;
}

static void h_conn(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    rd_t r = { pl + 1, n - 1, 0 };
    uint8_t msg = pl[0];

    switch (msg) {
    case M_GLOBAL_REQ: {
        uint32_t a;

        r_str(&r, &a);
        int want = r_u8(&r) != 0;

        if (r.err) {
            ssh_fail(s, D_PROTO, "GLOBAL_REQUEST cacat", "GLOBAL_REQUEST cacat");
        } else if (want) {
            wr_t w = pk_begin(s);

            w_u8(&w, M_REQ_FAILURE);
            pk_end(s, &w);
        }
        return;
    }
    case M_CH_OPEN:
        h_ch_open(s, &r);
        return;
    case M_CH_WINADJ: case M_CH_DATA: case M_CH_EOF: case M_CH_CLOSE: case M_CH_REQ: {
        uint32_t rc = r_u32(&r);

        if (r.err) {
            ssh_fail(s, D_PROTO, "pesan kanal cacat", "pesan kanal cacat");
            return;
        }
        if (!ch_known(s, rc)) {
            return;
        }
        if (msg == M_CH_WINADJ) {
            uint32_t add = r_u32(&r);

            if (r.err || r.n != 0) {
                ssh_fail(s, D_PROTO, "WINDOW_ADJUST cacat", "WINDOW_ADJUST cacat");
            } else {
                s->cl_win = add > 0xFFFFFFFFu - s->cl_win ? 0xFFFFFFFFu : s->cl_win + add;
            }
        } else if (msg == M_CH_DATA) {
            h_ch_data(s, &r);
        } else if (msg == M_CH_EOF) {
            s->ch_eof_in = 1;
        } else if (msg == M_CH_CLOSE) {
            if (!s->ch_close_sent) {
                ch_simple(s, M_CH_CLOSE);
                s->ch_close_sent = 1;
            }
            s->pend_len = s->pend_off = 0;
            ss_close_why(s, "klien menutup kanal");
        } else {
            h_ch_request(s, &r);
        }
        return;
    }
    case M_CH_CONFIRM: case M_CH_OPENFAIL: case M_CH_SUCCESS: case M_CH_FAILURE:
        return;   // balasan untuk permintaan yang tidak pernah kami kirim: abaikan
    default:
        if (++s->unimpl_n > g_ssh_unimpl_max) {
            ssh_fail(s, D_PROTO, "terlalu banyak pesan tak dikenal", "UNIMPLEMENTED > batas");
            return;
        }
        send_unimpl(s);
        return;
    }
}

// ---- accessor SSH-2a ----

int ssh_authed(int i)
{
    return i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used && g_ssh[i].role != 0;
}

int ssh_role(int i)
{
    return (i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used) ? g_ssh[i].role : 0;
}

const char *ssh_user(int i)
{
    return (i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used) ? g_ssh[i].user : "";
}

uint32_t ssh_cmd_count(int i)
{
    return (i >= 0 && i < SSH_MAX_SESS && g_ssh[i].used) ? g_ssh[i].cmd_n : 0;
}

int ssh_take_reboot(int i)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used || !g_ssh[i].reboot) {
        return 0;
    }
    g_ssh[i].reboot = 0;
    return 1;
}

// ---- satu paket masuk ----

static void dispatch(ssh_sess_t *s, const uint8_t *pl, uint32_t n)
{
    uint8_t msg = pl[0];

    if (msg == M_DISCONNECT) {
        ss_close_why(s, "klien memutus (DISCONNECT)");
        return;
    }
    if (s->state != SSH_ST_KEX) {
        h_post(s, pl, n);
        return;
    }
    // kex awal
    if (msg == M_IGNORE || msg == M_DEBUG || msg == M_UNIMPL) {
        if (s->strict) {
            ssh_fail(s, D_PROTO, "strict kex: pesan tak terduga", "strict kex: pesan terselip saat kex");
        }
        return;
    }
    if (s->kstage == K_WAIT_KEXINIT && msg == M_KEXINIT) {
        h_kexinit(s, pl, n);
    } else if (s->kstage == K_WAIT_DH && msg == M_KEXDH_INIT) {
        h_kexdh(s, pl, n);
    } else if (s->kstage == K_WAIT_NEWKEYS && msg == M_NEWKEYS) {
        if (n != 1) {
            ssh_fail(s, D_PROTO, "NEWKEYS cacat", "NEWKEYS cacat");
            return;
        }
        gcm_setup(&s->ci, s->in_key, s->in_iv);
        secure_zero(s->in_key, sizeof(s->in_key));
        secure_zero(s->in_iv, sizeof(s->in_iv));
        s->in_enc = 1;
        if (s->strict) {
            s->seq_in = 0;
        }
        s->state = SSH_ST_SERVICE;
    } else {
        ssh_fail(s, D_PROTO, "pesan tak terduga saat pertukaran kunci", "pesan tak terduga saat kex");
    }
}

// 1 = satu paket diproses, 0 = butuh byte lagi atau CLOSING.
static int proc_packet(ssh_sess_t *s)
{
    uint32_t avail = s->ilen - s->ipos;
    uint8_t *p = s->ibuf + s->ipos;

    if (avail < 4) {
        return 0;
    }
    uint32_t plen = get32(p);
    // GCM: panjang (plaintext, di luar AAD) kelipatan 16; polos: 4 + panjang kelipatan 8.
    uint32_t misal = s->in_enc ? plen % 16 : (plen + 4) % 8;

    if (plen == 0 || plen > SSH_PKT_MAX || misal != 0 || plen < 6) {
        ssh_fail(s, D_PROTO, "panjang paket tidak sah", "panjang paket tidak sah");
        return 0;
    }
    uint32_t total = 4 + plen + (s->in_enc ? 16 : 0);

    if (avail < total) {
        return 0;
    }
    if (s->in_enc) {
        br_gcm_reset(&s->ci.gc, s->ci.iv, 12);
        br_gcm_aad_inject(&s->ci.gc, p, 4);
        br_gcm_flip(&s->ci.gc);
        br_gcm_run(&s->ci.gc, 0, p + 4, plen);
        if (br_gcm_check_tag(&s->ci.gc, p + 4 + plen) == 0) {
            ssh_fail(s, D_MAC, "kesalahan MAC", "tag GCM salah");
            return 0;
        }
        for (int i = 11; i >= 4; i--) {
            if (++s->ci.iv[i] != 0) {
                break;
            }
        }
    }
    uint32_t pad = p[4];

    if (pad < 4 || pad + 2 > plen) {
        ssh_fail(s, D_PROTO, "padding tidak sah", "padding tidak sah");
        return 0;
    }
    uint32_t pl = plen - 1 - pad;

    s->cur_seq = s->seq_in;
    s->seq_in++;
    s->pk_in++;
    s->by_in += total;
    s->ipos += total;   // handler tidak menggeser ibuf; payload tetap valid
    // Tebakan salah: hanya pesan khusus kex (30..49) yang ditelan; DISCONNECT, IGNORE/DEBUG
    // (strict) dan lainnya tetap diperiksa seperti biasa.
    int swallow = s->ignore_next && p[5] >= 30 && p[5] <= 49;

    s->ignore_next = 0;
    if (!swallow) {
        dispatch(s, p + 5, pl);
        chan_step(s);
    }
    if (s->state != SSH_ST_CLOSING &&
        (s->pk_in >= SSH_PKT_LIMIT || s->pk_out >= SSH_PKT_LIMIT ||
         s->by_in >= SSH_BYTE_LIMIT || s->by_out >= SSH_BYTE_LIMIT)) {
        ssh_fail(s, D_PROTO, "batas paket/byte tercapai", "batas 2^28 paket atau 1 GB");
    }
    return 1;
}

static void ssh_run(ssh_sess_t *s)
{
    chan_step(s);   // lanjutkan keluaran tertunda / baris shell setelah ruang atau window bertambah
    while (s->state != SSH_ST_CLOSING && SSH_OBUF_SIZE - s->olen >= SSH_OUT_RESERVE) {
        int r = s->state == SSH_ST_VERSION ? proc_version(s) : proc_packet(s);

        if (!r) {
            break;
        }
    }
}

uint32_t ssh_feed(int i, const volatile uint8_t *d, uint32_t len)
{
    if (i < 0 || i >= SSH_MAX_SESS || !g_ssh[i].used) {
        return 0;
    }
    ssh_sess_t *s = &g_ssh[i];

    if (s->state == SSH_ST_CLOSING) {
        return len;   // dibuang: sesi sudah ditutup, pemanggil tinggal menguras keluaran
    }
    ssh_run(s);
    if (len == 0 || d == 0 || s->state == SSH_ST_CLOSING ||
        SSH_OBUF_SIZE - s->olen < SSH_OUT_RESERVE) {
        return s->state == SSH_ST_CLOSING ? len : 0;
    }
    if (s->ipos > 0) {
        memmove(s->ibuf, s->ibuf + s->ipos, s->ilen - s->ipos);
        s->ilen -= s->ipos;
        s->ipos = 0;
    }
    uint32_t n = SSH_IBUF_SIZE - s->ilen;

    if (n > len) {
        n = len;
    }
    for (uint32_t k = 0; k < n; k++) {
        s->ibuf[s->ilen + k] = d[k];
    }
    s->ilen += n;
    ssh_run(s);
    return s->state == SSH_ST_CLOSING ? len : n;
}

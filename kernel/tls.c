#include "kernel.h"
#include "bearssl.h"

// ---- D9: TLS 1.2 server (BearSSL) untuk CLI port 7780 ----
// Keputusan D8 (DECISIONS 2026-10-13): hanya TLS 1.2, suite
// ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 dan ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
// kurva P-256, tanpa resumption (tanpa cache sesi), tanpa renegosiasi, tanpa
// sertifikat klien. Implementasi dipilih eksplisit (tanpa "default" yang
// memilih SSE/AES-NI): aes_ct64 + ghash_ctmul64, chacha20_ct + poly1305_ctmulq,
// ec_p256_m64, ECDSA i31, SHA-256.
// Identitas server: TLSKEY.DER (kunci EC P-256, DER SEC1/PKCS#8) dan
// TLSCERT.DER (sertifikat self-signed, DER) di root disk; dimuat sekali saat
// boot. Kunci publik sertifikat harus cocok dengan kunci privat. File tidak
// ada/salah -> TLS nonaktif (port 7780 dibalas RST), port lain tidak terpengaruh.
// Sesi: tabel statis TLS_MAX_SESS slot (konteks + buffer, tanpa heap), slot
// dipegang TCB port 7780 sejak SYN sampai TCB CLOSED. Penuh -> tls_open -1.
// DRBG engine di-seed 32 byte dari entropy_get per sesi (tanpa itu gagal).
// Semua fungsi dipanggil hanya dari net task.

#define TLS_IBUF_SIZE   BR_SSL_BUFSIZE_INPUT   // 16709: klien tidak wajib max_fragment_length
#define TLS_OBUF_SIZE   (1024 + 85)            // record keluar <= 1024 byte plaintext
#define TLS_KEY_MAX     512
#define TLS_CERT_MAX    2048

typedef struct {
    int used;
    int hs_counted;     // handshake selesai sudah dihitung
    int fail_counted;   // error engine sudah dihitung
    br_ssl_server_context sc;
    uint8_t ibuf[TLS_IBUF_SIZE];
    uint8_t obuf[TLS_OBUF_SIZE];
} tls_sess_t;

static tls_sess_t g_tls[TLS_MAX_SESS];

static int g_tls_on;
static const char *g_tls_why = "belum dimuat";
static uint8_t g_tls_cert[TLS_CERT_MAX];
static br_x509_certificate g_tls_chain;
static uint8_t g_tls_key_x[32];
static br_ec_private_key g_tls_sk;
static uint8_t g_tls_pin[32];   // sha256(TLSCERT.DER) = pin klien

uint64_t g_tls_hs_ok = 0;       // handshake selesai
uint64_t g_tls_fail = 0;        // sesi berakhir dengan error engine
uint64_t g_tls_full = 0;        // SYN 7780 ditolak, slot penuh
uint64_t g_tls_noentropy = 0;   // sesi gagal dibuka, entropi belum cukup
int g_tls_last_err = 0;         // kode BR_ERR_* terakhir (0 = belum ada)

static const uint16_t g_tls_suites[] = {
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
};

// Buffer kerja saat boot (statis: decoder ~3,4 KB, jangan di stack).
static uint8_t g_tls_ld[TLS_CERT_MAX];
static br_skey_decoder_context g_tls_skdc;
static br_x509_decoder_context g_tls_xdc;

static int tls_load_key(void)
{
    uint32_t size = 0;
    int rc = fat32_read_name("TLSKEY  DER", g_tls_ld, TLS_KEY_MAX, &size);

    if (rc == FAT32_ERR_NOENT || rc == FAT32_ERR_NOVOL) {
        g_tls_why = "TLSKEY.DER tidak ada";
        return 0;
    }
    if (rc != FAT32_OK) {
        g_tls_why = "TLSKEY.DER gagal dibaca/terlalu besar";
        return 0;
    }
    br_skey_decoder_init(&g_tls_skdc);
    br_skey_decoder_push(&g_tls_skdc, g_tls_ld, size);
    memset(g_tls_ld, 0, sizeof(g_tls_ld));

    const br_ec_private_key *sk = br_skey_decoder_get_ec(&g_tls_skdc);

    if (br_skey_decoder_last_error(&g_tls_skdc) != 0 || sk == 0) {
        g_tls_why = "TLSKEY.DER bukan kunci EC (DER)";
        memset(&g_tls_skdc, 0, sizeof(g_tls_skdc));
        return 0;
    }
    if (sk->curve != BR_EC_secp256r1 || sk->xlen != sizeof(g_tls_key_x)) {
        g_tls_why = "TLSKEY.DER bukan P-256";
        memset(&g_tls_skdc, 0, sizeof(g_tls_skdc));
        return 0;
    }
    memcpy(g_tls_key_x, sk->x, sizeof(g_tls_key_x));
    memset(&g_tls_skdc, 0, sizeof(g_tls_skdc));
    g_tls_sk.curve = BR_EC_secp256r1;
    g_tls_sk.x = g_tls_key_x;
    g_tls_sk.xlen = sizeof(g_tls_key_x);
    return 1;
}

static int tls_load_cert(void)
{
    uint32_t size = 0;
    int rc = fat32_read_name("TLSCERT DER", g_tls_cert, sizeof(g_tls_cert), &size);

    if (rc == FAT32_ERR_NOENT || rc == FAT32_ERR_NOVOL) {
        g_tls_why = "TLSCERT.DER tidak ada";
        return 0;
    }
    if (rc != FAT32_OK || size == 0) {
        g_tls_why = "TLSCERT.DER gagal dibaca/terlalu besar";
        return 0;
    }
    br_x509_decoder_init(&g_tls_xdc, 0, 0);
    br_x509_decoder_push(&g_tls_xdc, g_tls_cert, size);

    br_x509_pkey *pk = br_x509_decoder_get_pkey(&g_tls_xdc);

    if (br_x509_decoder_last_error(&g_tls_xdc) != 0 || pk == 0) {
        g_tls_why = "TLSCERT.DER bukan sertifikat X.509 DER";
        return 0;
    }
    if (pk->key_type != BR_KEYTYPE_EC || pk->key.ec.curve != BR_EC_secp256r1) {
        g_tls_why = "kunci sertifikat bukan EC P-256";
        return 0;
    }

    // Kunci publik dari kunci privat harus sama dengan isi sertifikat.
    uint8_t q[BR_EC_KBUF_PUB_MAX_SIZE];
    br_ec_public_key pub;
    size_t qlen = br_ec_compute_pub(&br_ec_p256_m64, &pub, q, &g_tls_sk);

    if (qlen == 0 || qlen != pk->key.ec.qlen || memcmp(q, pk->key.ec.q, qlen) != 0) {
        g_tls_why = "kunci sertifikat tidak cocok dengan TLSKEY.DER";
        return 0;
    }
    g_tls_chain.data = g_tls_cert;
    g_tls_chain.data_len = size;

    br_sha256_context h;

    br_sha256_init(&h);
    br_sha256_update(&h, g_tls_cert, size);
    br_sha256_out(&h, g_tls_pin);
    return 1;
}

// 64 hex huruf kecil + NUL dari pin (ksnprintf tidak punya %02x).
static void tls_pin_hex(char *out)
{
    static const char hx[] = "0123456789abcdef";

    for (int i = 0; i < 32; i++) {
        out[2 * i] = hx[g_tls_pin[i] >> 4];
        out[2 * i + 1] = hx[g_tls_pin[i] & 0xF];
    }
    out[64] = 0;
}

void tls_load(void)
{
    char line[160];
    char pin[65];

    g_tls_on = 0;
    if (tls_load_key() && tls_load_cert()) {
        g_tls_on = 1;
        g_tls_why = "";
    } else {
        memset(g_tls_key_x, 0, sizeof(g_tls_key_x));
    }
    if (g_tls_on) {
        tls_pin_hex(pin);
        ksnprintf(line, sizeof(line), "TLS: aktif port 7780 pin=%s\r\n", pin);
    } else {
        ksnprintf(line, sizeof(line), "TLS: nonaktif (%s)\r\n", g_tls_why);
    }
    serial_write(line);
}

int tls_enabled(void)
{
    return g_tls_on;
}

// Buka sesi baru. Return indeks slot, -1 penuh, -2 TLS nonaktif,
// -3 entropi belum cukup, -4 engine gagal diinisialisasi.
int tls_open(void)
{
    if (!g_tls_on) {
        return -2;
    }

    int s = -1;

    for (int i = 0; i < TLS_MAX_SESS; i++) {
        if (!g_tls[i].used) {
            s = i;
            break;
        }
    }
    if (s < 0) {
        g_tls_full++;
        return -1;
    }

    uint8_t seed[32];

    if (!entropy_get(seed, sizeof(seed))) {
        g_tls_noentropy++;
        return -3;
    }

    tls_sess_t *t = &g_tls[s];
    br_ssl_server_context *sc = &t->sc;
    br_ssl_engine_context *e = &sc->eng;

    br_ssl_server_zero(sc);
    br_ssl_engine_set_versions(e, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(e, g_tls_suites, sizeof(g_tls_suites) / sizeof(g_tls_suites[0]));
    br_ssl_engine_add_flags(e, BR_OPT_NO_RENEGOTIATION);
    br_ssl_engine_set_ec(e, &br_ec_p256_m64);
    br_ssl_server_set_single_ec(sc, &g_tls_chain, 1, &g_tls_sk, BR_KEYTYPE_SIGN,
                                BR_KEYTYPE_EC, &br_ec_p256_m64, br_ecdsa_i31_sign_asn1);
    br_ssl_engine_set_hash(e, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_prf_sha256(e, &br_tls12_sha256_prf);
    br_ssl_engine_set_gcm(e, &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_aes_ctr(e, &br_aes_ct64_ctr_vtable);
    br_ssl_engine_set_ghash(e, &br_ghash_ctmul64);
    br_ssl_engine_set_chapol(e, &br_sslrec_in_chapol_vtable, &br_sslrec_out_chapol_vtable);
    br_ssl_engine_set_chacha20(e, &br_chacha20_ct_run);
    br_ssl_engine_set_poly1305(e, &br_poly1305_ctmulq_run);
    br_ssl_engine_set_buffers_bidi(e, t->ibuf, sizeof(t->ibuf), t->obuf, sizeof(t->obuf));
    br_ssl_engine_inject_entropy(e, seed, sizeof(seed));
    memset(seed, 0, sizeof(seed));

    if (!br_ssl_server_reset(sc)) {
        g_tls_last_err = br_ssl_engine_last_error(e);
        g_tls_fail++;
        memset(t, 0, sizeof(*t));
        return -4;
    }
    t->used = 1;
    t->hs_counted = 0;
    t->fail_counted = 0;
    return s;
}

void tls_free(int s)
{
    if (s < 0 || s >= TLS_MAX_SESS || !g_tls[s].used) {
        return;
    }
    // Hapus kunci sesi dan sisa plaintext dari memori.
    memset(&g_tls[s], 0, sizeof(g_tls[s]));
}

static br_ssl_engine_context *tls_eng(int s)
{
    return &g_tls[s].sc.eng;
}

// Record dari peer (aliran TCP) -> engine. Return byte yang diterima;
// sisanya tidak di-ACK di TCP (peer mengirim ulang).
// Engine meminta header record (5 byte) dulu lalu isinya, jadi diulang
// selama engine masih menerima.
uint32_t tls_feed(int s, const volatile uint8_t *d, uint32_t len)
{
    uint32_t done = 0;

    while (done < len) {
        size_t room;
        uint8_t *b = br_ssl_engine_recvrec_buf(tls_eng(s), &room);

        if (b == 0 || room == 0) {
            break;
        }

        uint32_t n = len - done < room ? len - done : (uint32_t)room;

        for (uint32_t i = 0; i < n; i++) {
            b[i] = d[done + i];
        }
        br_ssl_engine_recvrec_ack(tls_eng(s), n);
        done += n;
    }
    return done;
}

// Plaintext dari peer yang siap dibaca (0 bila tidak ada).
const uint8_t *tls_app_in(int s, uint32_t *len)
{
    size_t n = 0;
    uint8_t *b = br_ssl_engine_recvapp_buf(tls_eng(s), &n);

    *len = b ? (uint32_t)n : 0;
    return b;
}

void tls_app_in_ack(int s, uint32_t n)
{
    if (n > 0) {
        br_ssl_engine_recvapp_ack(tls_eng(s), n);
    }
}

// Ruang plaintext keluar (0 sebelum handshake selesai atau saat record
// sebelumnya belum diambil).
uint32_t tls_app_space(int s)
{
    size_t n = 0;

    return br_ssl_engine_sendapp_buf(tls_eng(s), &n) ? (uint32_t)n : 0;
}

// Plaintext -> engine, langsung jadi record (flush). Return byte diterima.
uint32_t tls_app_write(int s, const volatile uint8_t *d, uint32_t len)
{
    size_t room = 0;
    uint8_t *b = br_ssl_engine_sendapp_buf(tls_eng(s), &room);

    if (b == 0 || room == 0 || len == 0) {
        return 0;
    }

    uint32_t n = len < room ? len : (uint32_t)room;

    for (uint32_t i = 0; i < n; i++) {
        b[i] = d[i];
    }
    br_ssl_engine_sendapp_ack(tls_eng(s), n);
    br_ssl_engine_flush(tls_eng(s), 0);
    return n;
}

// Record yang menunggu dikirim ke peer.
const uint8_t *tls_rec_out(int s, uint32_t *len)
{
    size_t n = 0;
    uint8_t *b = br_ssl_engine_sendrec_buf(tls_eng(s), &n);

    *len = b ? (uint32_t)n : 0;
    return b;
}

void tls_rec_out_ack(int s, uint32_t n)
{
    if (n > 0) {
        br_ssl_engine_sendrec_ack(tls_eng(s), n);
    }
}

// 1 bila handshake selesai (data aplikasi boleh lewat). Menghitung
// g_tls_hs_ok sekali per sesi.
int tls_ready(int s)
{
    br_ssl_engine_context *e = tls_eng(s);
    size_t n;

    if (br_ssl_engine_current_state(e) == BR_SSL_CLOSED) {
        return 0;
    }
    // sendapp tersedia hanya setelah handshake; record keluar yang belum
    // diambil membuatnya NULL sementara, jadi cek juga recvapp/flag sesi.
    if (!g_tls[s].hs_counted &&
        (br_ssl_engine_sendapp_buf(e, &n) || br_ssl_engine_recvapp_buf(e, &n))) {
        g_tls[s].hs_counted = 1;
        g_tls_hs_ok++;
    }
    return g_tls[s].hs_counted;
}

// 0 berjalan, 1 ditutup baik-baik (close_notify), -1 error engine
// (dihitung di g_tls_fail, kode di g_tls_last_err).
int tls_state(int s)
{
    br_ssl_engine_context *e = tls_eng(s);

    if (br_ssl_engine_current_state(e) != BR_SSL_CLOSED) {
        return 0;
    }

    int err = br_ssl_engine_last_error(e);

    if (err == BR_ERR_OK) {
        return 1;
    }
    if (!g_tls[s].fail_counted) {
        g_tls[s].fail_counted = 1;
        g_tls_fail++;
        g_tls_last_err = err;
    }
    return -1;
}

int tls_last_error(int s)
{
    return br_ssl_engine_last_error(tls_eng(s));
}

// Mulai penutupan TLS: close_notify masuk antrean record keluar.
void tls_close(int s)
{
    br_ssl_engine_close(tls_eng(s));
}

// Suite yang disepakati (0 sebelum handshake).
uint16_t tls_suite(int s)
{
    br_ssl_session_parameters p;

    br_ssl_engine_get_session_parameters(tls_eng(s), &p);
    return p.cipher_suite;
}

int tls_sess_active(void)
{
    int n = 0;

    for (int i = 0; i < TLS_MAX_SESS; i++) {
        n += g_tls[i].used;
    }
    return n;
}

// Perintah `tls` (cmd.c): status, pin, counter.
void tls_status(void)
{
    char b[200];
    char pin[65];

    if (g_tls_on) {
        tls_pin_hex(pin);
        ksnprintf(b, sizeof(b), "tls: aktif port 7780\npin: %s\n", pin);
    } else {
        ksnprintf(b, sizeof(b), "tls: nonaktif (%s)\n", g_tls_why);
    }
    cmd_puts(b);
    ksnprintf(b, sizeof(b), "sesi: aktif=%d maks=%d ok=%lu gagal=%lu penuh=%lu "
              "tanpa_entropi=%lu err_terakhir=%d\n", tls_sess_active(), TLS_MAX_SESS,
              g_tls_hs_ok, g_tls_fail, g_tls_full, g_tls_noentropy, g_tls_last_err);
    cmd_puts(b);
}

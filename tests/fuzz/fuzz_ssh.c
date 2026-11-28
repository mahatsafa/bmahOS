// F7 SSH-1a: fuzz ssh.c dengan klien uji tests/host/test_ssh.c. Byte 0 = mode, byte 1 = ukuran
// pecahan feed (0 = sekaligus):
//   0 byte mentah sebagai aliran TCP dari awal (baris versi, paket polos)
//   1 banner sah, lalu SATU paket polos dengan payload = data (byte pertama dipaksa 20 = KEXINIT
//     bila bit0 byte pertama data = 1; selain itu payload apa adanya)
//   2 banner + KEXINIT sah, lalu KEXDH_INIT dengan Q_C = data (kex penuh: x25519 + ECDSA)
//   3 sesi di akhir kex (snapshot, kunci aktif): data mentah sebagai ciphertext
//   4 sesi di akhir kex: data dipecah jadi payload (byte panjang + isi), tiap payload satu paket terenkripsi sah
//   5 urutan paket polos: data = daftar operasi (banner, KEXINIT sah, KEXDH_INIT sah, selesaikan kex
//     sungguhan, NEWKEYS, payload mentah, IGNORE, aliran mentah). Kex sungguhan bisa diselipi pesan
//     lain dan paket sesudahnya dikirim terenkripsi dengan kunci hasil kex.
// Invarian: state sah, buffer dalam batas, CLOSING membuang masukan, semua paket keluaran
// terdekripsi sah oleh klien (tag benar), tidak ada baca/tulis di luar batas (ASan).

#include "test_ssh.c"
#include "fuzz.h"

static ssh_sess_t g_snap;
static cl_t g_csnap;
static int g_snap_slot = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    setup_key();
    return 0;
}

static void check_inv(int s)
{
    ssh_sess_t *x = &g_ssh[s];

    FUZZ_ASSERT(x->ipos <= x->ilen && x->ilen <= SSH_IBUF_SIZE && x->olen <= SSH_OBUF_SIZE);
    FUZZ_ASSERT(x->state >= SSH_ST_VERSION && x->state <= SSH_ST_CLOSING);
    FUZZ_ASSERT(!x->in_enc || x->out_enc);   // kunci masuk hanya aktif setelah kunci keluar
    FUZZ_ASSERT(!x->out_enc || !all_zero(x->sid, 32));
    FUZZ_ASSERT(x->unimpl_n <= g_ssh_unimpl_max + 1 && x->auth_n <= SSH_AUTH_MAX);
}

// Semua paket keluaran harus bisa didekripsi klien (setelah NEWKEYS).
static void check_out(cl_t *c)
{
    cl_drain(c);
    if (c->rxpos == 0 && c->rxn >= 4 && memcmp(c->rx, "SSH-", 4) == 0) {
        FUZZ_ASSERT(cl_banner(c));
    }
    while (c->rxpos < c->rxn) {
        if (!c->enc_in) {
            int r = cl_recv(c);

            FUZZ_ASSERT(r > 0 || r == -1);
            if (r < 0) {
                break;
            }
            if (c->pl[0] == M_NEWKEYS) {   // sisanya terenkripsi, klien belum punya kunci
                break;
            }
        } else {
            int r = cl_recv(c);

            FUZZ_ASSERT(r > 0 || r == -1);
            if (r < 0) {
                break;
            }
        }
    }
}

static void snapshot_init(void)
{
    reset_all();
    FUZZ_ASSERT(full(1));
    uint8_t m[40];
    wr_t w = { m, 0, sizeof(m), 0 };

    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    cl_send(&C, m, w.n);
    FUZZ_ASSERT(cl_msg(&C) == M_SVC_ACCEPT);
    g_snap = g_ssh[C.s];
    g_csnap = C;
    g_snap_slot = C.s;
    reset_all();
}

static void restore(void)
{
    if (g_snap_slot < 0) {
        snapshot_init();
    }
    reset_all();
    g_ssh[g_snap_slot] = g_snap;
    ssh_sess_t *s = &g_ssh[g_snap_slot];

    br_gcm_init(&s->co.gc, &s->co.ks.vtable, br_ghash_ctmul64);   // pointer ke ks salinan sendiri
    br_gcm_init(&s->ci.gc, &s->ci.ks.vtable, br_ghash_ctmul64);
    C = g_csnap;
    br_gcm_init(&C.go, &C.ko.vtable, br_ghash_ctmul64);
    br_gcm_init(&C.gi, &C.ki.vtable, br_ghash_ctmul64);
    C.rxn = C.rxpos = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (n < 2) {
        return 0;
    }
    uint8_t mode = d[0] % 6;

    g_chunk = d[1];
    d += 2;
    n -= 2;
    if (mode == 3 || mode == 4) {
        restore();
        g_chunk = d[-1];
        if (mode == 3) {
            cl_feed(&C, d, (uint32_t)n);
        } else {
            size_t i = 0;

            while (i < n && ssh_state(C.s) != SSH_ST_CLOSING) {
                size_t l = d[i++] % 200;

                if (l > n - i) {
                    l = n - i;
                }
                if (l == 0) {
                    continue;
                }
                cl_send(&C, d + i, (uint32_t)l);
                i += l;
            }
        }
        check_inv(C.s);
        check_out(&C);
        ssh_close(C.s);
        g_chunk = 0;
        return 0;
    }
    reset_all();
    g_chunk = d[-1];
    cl_new(&C);
    FUZZ_ASSERT(C.s >= 0);
    if (mode == 5) {
        size_t i = 0;
        int got_banner = 0;

        while (i < n && ssh_state(C.s) != SSH_ST_CLOSING) {
            uint8_t op = d[i++] % 8;
            uint8_t b[700];

            switch (op) {
            case 0:
                if (!got_banner) {
                    got_banner = cl_banner(&C);
                    cl_send_banner(&C);
                    if (cl_msg(&C) == M_KEXINIT) {
                        memcpy(C.is, C.pl, C.pln);
                        C.isn = C.pln;
                    }
                }
                break;
            case 1: {
                int st = i < n && (d[i++] & 1);
                uint32_t kn = cl_kexinit(&C, st ? KEX_STRICT : KEX_PLAIN, "ecdsa-sha2-nistp256",
                                         "aes128-gcm@openssh.com", "none", 0, b);

                memcpy(C.ic, b, kn);
                C.icn = kn;
                C.strict = st;
                cl_send(&C, b, kn);
                break;
            }
            case 2:
                cl_dh_init(&C);
                break;
            case 3:
                if (!C.enc_out) {
                    cl_kex_finish(&C);
                }
                break;
            case 4:
                cl_send_msg(&C, M_NEWKEYS);
                break;
            case 5: {
                size_t l = i < n ? d[i++] % 100 : 0;

                if (l > n - i) {
                    l = n - i;
                }
                if (l > 0) {
                    cl_send(&C, d + i, (uint32_t)l);
                }
                i += l;
                break;
            }
            case 6: {
                uint8_t ig[5] = { M_IGNORE, 0, 0, 0, 0 };

                cl_send(&C, ig, sizeof(ig));
                break;
            }
            default: {
                size_t l = i < n ? d[i++] % 64 : 0;

                if (l > n - i) {
                    l = n - i;
                }
                cl_feed(&C, d + i, (uint32_t)l);
                i += l;
                break;
            }
            }
            check_inv(C.s);
        }
    } else if (mode == 0) {
        cl_feed(&C, d, (uint32_t)n);
    } else {
        cl_banner(&C);
        cl_send_banner(&C);
        cl_msg(&C);
        if (mode == 1) {
            uint8_t *p = malloc(n + 1);

            memcpy(p, d, n);
            if (n > 0 && (d[0] & 1)) {
                p[0] = M_KEXINIT;
            }
            cl_send(&C, p, (uint32_t)n);
            free(p);
        } else {
            uint8_t ki[600];
            uint32_t kn = cl_kexinit(&C, KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, ki);

            cl_send(&C, ki, kn);
            uint8_t *p = malloc(n + 6);

            p[0] = M_KEXDH_INIT;
            put32(p + 1, (uint32_t)n);
            memcpy(p + 5, d, n);
            cl_send(&C, p, (uint32_t)n + 5);
            free(p);
        }
    }
    check_inv(C.s);
    if (ssh_state(C.s) == SSH_ST_CLOSING) {
        FUZZ_ASSERT(ssh_feed(C.s, d, 1) == 1);
    }
    check_out(&C);
    ssh_close(C.s);
    FUZZ_ASSERT(all_zero(&g_ssh[C.s], sizeof(g_ssh[C.s])));
    g_chunk = 0;
    return 0;
}

void fuzz_seeds(const char *dir)
{
    uint8_t b[700];
    wr_t w;

    // mode 0: banner + paket polos sah; banner saja; sampah
    static const char s0[] = "\0\0SSH-2.0-fuzz\r\n\0\0\0\x0c\x04\x63\0\0\0\0\0\0\0\0";
    fuzz_seed(dir, "banner-paket", s0, sizeof(s0) - 1);
    static const char s1[] = "\0\0a\r\nb\r\nSSH-1.99-x\r\n";
    fuzz_seed(dir, "versi-salah", s1, sizeof(s1) - 1);
    // mode 1: KEXINIT sah sebagai payload (isi tanpa byte 0 = cookie dst)
    uint8_t ki[600];
    uint32_t kn = cl_kexinit(&C, KEX_STRICT, "ecdsa-sha2-nistp256", "aes128-gcm@openssh.com", "none", 0, ki);

    b[0] = 1;
    b[1] = 0;
    memcpy(b + 2, ki, kn);
    fuzz_seed(dir, "kexinit-sah", b, 2 + kn);
    b[1] = 1;
    fuzz_seed(dir, "kexinit-sah-1byte", b, 2 + kn);
    // mode 2: Q_C 32 byte = titik dasar
    b[0] = 2;
    b[1] = 0;
    memset(b + 2, 0, 32);
    b[2] = 9;
    fuzz_seed(dir, "qc-dasar", b, 34);
    memset(b + 2, 0, 32);
    fuzz_seed(dir, "qc-nol", b, 34);
    // mode 3: sampah terenkripsi
    b[0] = 3;
    memset(b + 2, 0x5a, 80);
    fuzz_seed(dir, "cipher-sampah", b, 82);
    // mode 4: payload-payload: SERVICE_REQUEST, USERAUTH_REQUEST, IGNORE, tak dikenal
    w.p = b + 2;
    w.n = 0;
    w.cap = 400;
    w.err = 0;
    b[0] = 4;
    b[1] = 0;
    w_u8(&w, 19);
    w_u8(&w, M_SVC_REQ);
    w_cstr(&w, "ssh-userauth");
    w_u8(&w, 40);
    w_u8(&w, M_UA_REQ);
    w_cstr(&w, "bima");
    w_cstr(&w, "ssh-connection");
    w_cstr(&w, "publickey");
    w_u8(&w, 0);
    w_cstr(&w, "ecdsa-sha2-nistp256");
    w_u8(&w, 3);
    w_u8(&w, M_IGNORE);
    w_u8(&w, 0);
    w_u8(&w, 0);
    w_u8(&w, 2);
    w_u8(&w, 99);
    w_u8(&w, 1);
    fuzz_seed(dir, "pasca-kex", b, 2 + w.n);
    // mode 5: banner, KEXINIT strict, KEXDH_INIT, selesaikan kex, lalu SERVICE_REQUEST mentah
    static const uint8_t s5[] = { 5, 0, 0, 1, 1, 2, 3, 5, 19, 5, 'x', 0, 0, 0, 0, 0, 0 };
    fuzz_seed(dir, "urutan-kex", s5, sizeof(s5));
    static const uint8_t s5b[] = { 5, 0, 0, 1, 1, 2, 6, 3, 4 };
    fuzz_seed(dir, "urutan-selip", s5b, sizeof(s5b));
}

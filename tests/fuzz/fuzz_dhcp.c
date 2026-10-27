// P3-4: fuzz dhcp_rx (balasan BOOTP dari LAN) dengan stub tests/host/test_dhcp.c.
// Byte 0 = mode: bit 0-1 keadaan awal (0 pilih: sesudah DISCOVER, 1 minta:
// sesudah OFFER sah, 2 perpanjang, 3 ikat-ulang: sesudah terikat ke .77),
// bit 2 perbaiki xid, bit 3 perbaiki chaddr, bit 4 perbaiki magic cookie
// (supaya bagian option ikut teruji), bit 5 lanjut dhcp_poll sesudah batas
// cek ARP. Sisa = isi UDP dari port 67.
// Invarian: keadaan dalam rentang; IP 0.0.0.0 saat belum terikat, selain itu
// alamat /24 sah (bukan 0/127/>=224, oktet terakhir 1..254).

#include "test_dhcp.c"
#include "fuzz.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    return 0;
}

static void fz_state(int st)
{
    if (st == 0) {
        reset(1);
        dhcp_poll();
    } else if (st == 1) {
        reset(1);
        dhcp_poll();
        rep_std(DH_OFFER, tx_xid(0), YI, SRV, M24, 3600);
        send_rep();
    } else {
        bind_to(120);
        timer_ticks += 6000;          // T1 -> perpanjang
        dhcp_poll();
        if (st == 3) {
            timer_ticks += 4500;      // T2 -> ikat-ulang
            dhcp_poll();
        }
    }
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

    fz_state(m & 3);
    if ((m & 4) && xn >= 8) {
        b[4] = (uint8_t)(g_dh_xid >> 24);
        b[5] = (uint8_t)(g_dh_xid >> 16);
        b[6] = (uint8_t)(g_dh_xid >> 8);
        b[7] = (uint8_t)g_dh_xid;
    }
    if ((m & 8) && xn >= 34) {
        memcpy(b + 28, g_e1000_mac, 6);
    }
    if ((m & 16) && xn >= 240) {
        b[236] = 99;
        b[237] = 130;
        b[238] = 83;
        b[239] = 99;
    }
    dhcp_rx(b, (uint32_t)xn);
    if (m & 32) {
        timer_ticks += DH_CHECK_WAIT;
        dhcp_poll();
    }

    const uint8_t *ip = g_net_ip;
    int zero = (ip[0] | ip[1] | ip[2] | ip[3]) == 0;
    FUZZ_ASSERT(g_dh_state >= DH_OFF && g_dh_state <= DH_STATIC);
    if (g_dh_state == DH_SELECT || g_dh_state == DH_REQUEST || g_dh_state == DH_CHECK) {
        FUZZ_ASSERT(zero);
    }
    if (g_dh_state == DH_BOUND || g_dh_state == DH_RENEW || g_dh_state == DH_REBIND) {
        FUZZ_ASSERT(!zero);
    }
    if (!zero) {
        FUZZ_ASSERT(ip[0] != 0 && ip[0] != 127 && ip[0] < 224 && ip[3] >= 1 && ip[3] <= 254);
    }
    FUZZ_ASSERT(g_dh_lease == DH_INFINITE || g_dh_lease >= DH_LEASE_MIN || g_dh_lease == 0);
    free(b);
    return 0;
}

// Balasan sah tiap jenis (xid/chaddr/cookie diperbaiki lewat bit mode).
static void fz_seed_rep(const char *dir, const char *name, uint8_t mode)
{
    uint8_t buf[sizeof(g_rep) + 1];

    buf[0] = mode;
    memcpy(buf + 1, g_rep, g_rl);
    fuzz_seed(dir, name, buf, g_rl + 1);
}

void fuzz_seeds(const char *dir)
{
    static const uint8_t Y78[4] = { 192, 168, 50, 78 };

    rep_std(DH_OFFER, 0, YI, SRV, M24, 3600);
    fz_seed_rep(dir, "offer", 0 | 4 | 8 | 16);
    rep_std(DH_OFFER, 0, YI, SRV, M16, 3600);
    fz_seed_rep(dir, "offer16", 0 | 4 | 8 | 16);
    rep_std(DH_ACK, 0, YI, SRV, M24, 3600);
    fz_seed_rep(dir, "ack", 1 | 4 | 8 | 16 | 32);
    rep_std(DH_NAK, 0, ZERO4, SRV, 0, 0);
    fz_seed_rep(dir, "nak", 1 | 4 | 8 | 16);
    rep_std(DH_ACK, 0, YI, SRV, M24, 600);
    fz_seed_rep(dir, "renew", 2 | 4 | 8 | 16);
    rep_std(DH_ACK, 0, Y78, SRV2, M24, 0xFFFFFFFFu);
    fz_seed_rep(dir, "rebind", 3 | 4 | 8 | 16);
    rep_std(DH_NAK, 0, ZERO4, SRV, 0, 0);
    fz_seed_rep(dir, "renewnak", 2 | 4 | 8 | 16);
    rep_std(DH_OFFER, 0, YI, SRV, M24, 3600);
    g_rep[g_rl - 1] = 52;                  // overload tanpa panjang di ujung
    fz_seed_rep(dir, "trunc", 4 | 8 | 16);
}

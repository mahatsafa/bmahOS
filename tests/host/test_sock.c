// P5-1: uji soket UDP program user (sock.c di-#include). task_sleep tiruan
// memajukan waktu dan menjalankan g_on_sleep (net task tiruan: sock_poll, ARP
// reply, datagram masuk); NIC tiruan menyalin frame keluar.

#include <stdint.h>
#include <stdlib.h>
#include "kernel.h"
#include "test.h"
#include "../../kernel/sock.c"

int g_e1000_rx_initialized = 1;
uint8_t g_e1000_mac[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
uint8_t g_net_ip[4] = { 192, 168, 50, 200 };
uint64_t hhdm_offset = 0;
size_t current_index = 3;
size_t task_count = 10;
uint64_t g_current_pml4_phys = 0x1000;
uint64_t g_sys_rejected = 0;

static int g_ip_ready = 1;
int net_ip_ready(void)
{
    return g_ip_ready;
}

static uint8_t g_page[4096] __attribute__((aligned(4096)));
uint64_t pmm_alloc(void)
{
    return (uint64_t)(uintptr_t)g_page;
}

#define BADPTR 0xdead0000ULL
static uint64_t g_last_ptr_len;
static int g_last_ptr_w;
bool is_valid_user_ptr(uint64_t pml4_phys, uint64_t ptr, uint64_t len, bool require_writable)
{
    (void)pml4_phys;
    g_last_ptr_len = len;
    g_last_ptr_w = require_writable;
    return ptr != BADPTR;
}

static int g_tick_wakes;
void net_rx_tick_wake(void)
{
    g_tick_wakes++;
}

static size_t g_woken[16];
static int g_nwoken;
void task_wake(size_t idx)
{
    if (g_nwoken < 16) {
        g_woken[g_nwoken++] = idx;
    }
}

static void (*g_on_sleep)(void);
static int g_nsleep;
static uint64_t g_sleep_max;
void task_sleep(uint64_t ticks)
{
    g_nsleep++;
    if (ticks > g_sleep_max) {
        g_sleep_max = ticks;
    }
    timer_ticks += ticks;
    if (g_on_sleep) {
        g_on_sleep();
    }
}

#define TXN 16
static uint8_t g_tx[TXN][1600];
static uint32_t g_tx_len[TXN];
static int g_ntx;
static int g_tx_fail;
int e1000_tx_send(uint64_t pkt_phys, uint32_t frame_len)
{
    if (g_tx_fail) {
        return 0;
    }
    if (g_ntx < TXN) {
        memcpy(g_tx[g_ntx], (const void *)(uintptr_t)pkt_phys, frame_len > 1600 ? 1600 : frame_len);
        g_tx_len[g_ntx] = frame_len;
        g_ntx++;
    }
    return 1;
}

// UDP tiruan: MAC tujuan, IP tujuan, port; isi sudah di p + 42.
uint32_t net_udp_build(uint8_t *p, const volatile uint8_t *dst_mac, const volatile uint8_t *dst_ip,
                       uint16_t sport, uint16_t dport, uint32_t plen)
{
    for (int i = 0; i < 6; i++) {
        p[i] = dst_mac[i];
    }
    p[12] = 0x08;
    p[13] = 0x00;
    for (int i = 0; i < 4; i++) {
        p[30 + i] = dst_ip[i];
    }
    p[34] = (uint8_t)(sport >> 8);
    p[35] = (uint8_t)sport;
    p[36] = (uint8_t)(dport >> 8);
    p[37] = (uint8_t)dport;
    return 42 + plen;
}

uint32_t net_arp_request_build(uint8_t *p, const volatile uint8_t *ip)
{
    p[12] = 0x08;
    p[13] = 0x06;
    for (int i = 0; i < 4; i++) {
        p[38 + i] = ip[i];
    }
    return 60;
}

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

static const char *run(const char *c)
{
    g_cmd_len = 0;
    g_out[0] = 0;
    if (!sock_execute((const uint8_t *)c, (uint32_t)strlen(c))) {
        return "(tidak ditangani)";
    }
    return g_out;
}

static const uint8_t PEER_MAC[6] = { 0x00, 0x50, 0x56, 0xc0, 0x00, 0x02 };
static const uint8_t PEER_IP[4] = { 192, 168, 50, 1 };

static void reset(void)
{
    memset(g_sk, 0, sizeof(g_sk));
    memset(g_sk_arp, 0, sizeof(g_sk_arp));
    g_sk_arp_next = 0;
    g_sock_rx = g_sock_tx = g_sock_drop = g_sock_err = g_sock_noarp = 0;
    g_sys_rejected = 0;
    g_ntx = 0;
    g_tx_fail = 0;
    g_nwoken = 0;
    g_nsleep = 0;
    g_sleep_max = 0;
    g_on_sleep = 0;
    g_tick_wakes = 0;
    g_ip_ready = 1;
    g_e1000_rx_initialized = 1;
    current_index = 3;
    timer_ticks = 1000;
    sock_init();
}

static int64_t sys(uint64_t r)
{
    return (int64_t)r;
}

static void rx_from(const uint8_t *ip, uint16_t sport, uint16_t dport, const char *d)
{
    sock_rx(PEER_MAC, ip, sport, dport, (const uint8_t *)d, (uint32_t)strlen(d));
}

// ARP reply/request dari ip (MAC pengirim @22, IP pengirim @28).
static void arp_from(const uint8_t *ip, const uint8_t *mac)
{
    uint8_t b[60] = { 0 };

    memcpy(b + 22, mac, 6);
    memcpy(b + 28, ip, 4);
    sock_arp_seen(b);
}

static void test_socket_bind(void)
{
    reset();
    CHECK(sys(sock_sys_socket(1, 0, 0, 0, 0)) == SOCK_EINVAL);
    for (uint64_t i = 0; i < SOCK_MAX; i++) {
        CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == i);
    }
    CHECK(sys(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0)) == SOCK_EMFILE);
    CHECK(sock_sys_close(2, 0, 0, 0, 0) == 0);
    CHECK(sys(sock_sys_close(2, 0, 0, 0, 0)) == SOCK_EBADF);
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 2);   // slot dipakai ulang
    CHECK(sys(sock_sys_close(9, 0, 0, 0, 0)) == SOCK_EBADF);

    // port sistem, rentang, port sumber acak kernel
    static const uint64_t bad[] = { 0, 1023, 6665, 6666, 7777, 7778, 7779, 7780, 49152, 65535, 70000 };
    for (uint32_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(sys(sock_sys_bind(0, bad[i], 0, 0, 0)) == SOCK_EACCES);
    }
    g_netcon_port = 9000;   // netcon_port dari CONFIG.CFG ikut dilindungi
    CHECK(sys(sock_sys_bind(0, 9000, 0, 0, 0)) == SOCK_EACCES);
    CHECK(sock_sys_bind(0, 6666, 0, 0, 0) == 0);           // 6666 bebas bila netcon pindah
    g_netcon_port = NETCON_PORT_DEF;
    CHECK(sock_sys_close(0, 0, 0, 0, 0) == 0);
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(sock_port_ok(1024) && sock_port_ok(49151) && sock_port_ok(7776) && sock_port_ok(7781));
    CHECK(!sock_wants(5555));
    CHECK(sock_sys_bind(0, 5555, 0, 0, 0) == 0);
    CHECK(sock_wants(5555));
    CHECK(sys(sock_sys_bind(0, 5556, 0, 0, 0)) == SOCK_EINVAL);    // sudah terikat
    CHECK(sys(sock_sys_bind(1, 5555, 0, 0, 0)) == SOCK_EADDRINUSE);
    CHECK(g_sock_err == 18);

    // fd milik task lain
    current_index = 4;
    CHECK(sys(sock_sys_bind(1, 6000, 0, 0, 0)) == SOCK_EBADF);
    CHECK(sys(sock_sys_close(0, 0, 0, 0, 0)) == SOCK_EBADF);
    uint8_t b[8];
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 8, 0, 1)) == SOCK_EBADF);
    CHECK(sys(sock_sys_sendto(0, (uint64_t)(uintptr_t)b, 1, SOCK_ADDR(192, 168, 50, 1, 9), 0)) ==
          SOCK_EBADF);
    current_index = 3;

    // task mati -> soketnya ditutup, soket task lain tetap
    current_index = 5;
    CHECK(sock_sys_close(2, 0, 0, 0, 0) == (uint64_t)SOCK_EBADF);
    current_index = 3;
    sock_task_exit(4);
    CHECK(g_sk[0].used);
    sock_task_exit(3);
    CHECK(!g_sk[0].used && !g_sk[1].used && !g_sk[2].used && !g_sk[3].used);
    CHECK(!sock_wants(5555));
}

static void test_rx_recv(void)
{
    uint8_t b[64];
    uint64_t from = 0;

    reset();
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 8, 0, 1)) == SOCK_EINVAL);   // belum bind
    CHECK(sock_sys_bind(0, 5555, 0, 0, 0) == 0);

    rx_from(PEER_IP, 40000, 5556, "lain");   // port lain: diabaikan
    CHECK(g_sock_rx == 0 && g_nwoken == 0);
    rx_from(PEER_IP, 40000, 5555, "halo");
    CHECK(g_sock_rx == 1 && g_nwoken == 1 && g_woken[0] == 3);
    CHECK(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, sizeof(b), (uint64_t)(uintptr_t)&from, 0) == 4);
    CHECK(memcmp(b, "halo", 4) == 0);
    CHECK(from == SOCK_ADDR(192, 168, 50, 1, 40000));
    CHECK(g_last_ptr_len == 8 && g_last_ptr_w);   // from divalidasi writable 8 byte
    CHECK(g_nsleep == 0);

    // dipotong ke cap, sisanya dibuang; cap > 1472 dibatasi
    rx_from(PEER_IP, 40001, 5555, "abcdef");
    CHECK(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 3, 0, 0) == 3);
    CHECK(memcmp(b, "abc", 3) == 0 && g_sk[0].qn == 0);
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 100000, 0, 1)) == SOCK_EAGAIN);
    CHECK(g_last_ptr_len == SOCK_DGRAM_MAX);

    // antrean 4, yang ke-5 dibuang
    for (int i = 0; i < 5; i++) {
        char d[2] = { (char)('0' + i), 0 };
        rx_from(PEER_IP, 40002, 5555, d);
    }
    CHECK(g_sock_rx == 6 && g_sock_drop == 1 && g_sk[0].drop == 1 && g_sk[0].qn == 4);
    for (int i = 0; i < 4; i++) {
        CHECK(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, sizeof(b), 0, 0) == 1);
        CHECK(b[0] == '0' + i);   // urutan masuk
    }

    // datagram 1472 byte utuh
    static uint8_t big[SOCK_DGRAM_MAX];
    static uint8_t got[SOCK_DGRAM_MAX];
    for (int i = 0; i < SOCK_DGRAM_MAX; i++) {
        big[i] = (uint8_t)(i * 7);
    }
    sock_rx(PEER_MAC, PEER_IP, 1, 5555, big, SOCK_DGRAM_MAX);
    CHECK(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)got, SOCK_DGRAM_MAX, 0, 0) == SOCK_DGRAM_MAX);
    CHECK(memcmp(big, got, SOCK_DGRAM_MAX) == 0);

    // pointer buruk
    CHECK(sys(sock_sys_recvfrom(0, BADPTR, 8, 0, 0)) == SOCK_EFAULT);
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 8, BADPTR, 0)) == SOCK_EFAULT);
    CHECK(g_sys_rejected == 2);
}

static void deliver_once(void)
{
    if (g_nsleep == 2) {
        rx_from(PEER_IP, 41000, 5555, "nanti");
    }
}

static void test_recv_wait(void)
{
    uint8_t b[16];

    reset();
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(sock_sys_bind(0, 5555, 0, 0, 0) == 0);

    // timeout 10 tick -> -11 setelah >= 10 tick
    uint64_t t0 = timer_ticks;
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 16, 0, 10)) == SOCK_EAGAIN);
    CHECK(timer_ticks - t0 == 10 && g_nsleep == 1);

    // timeout 0 = tunggu sampai data datang; tidur per putaran <= 100 tick
    g_nsleep = 0;
    g_on_sleep = deliver_once;
    CHECK(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 16, 0, 0) == 5);
    CHECK(memcmp(b, "nanti", 5) == 0 && g_nsleep == 2 && g_sleep_max == SOCK_WAIT_CHUNK);

    // timeout panjang dipecah per 100 tick
    g_nsleep = 0;
    g_on_sleep = 0;
    t0 = timer_ticks;
    CHECK(sys(sock_sys_recvfrom(0, (uint64_t)(uintptr_t)b, 16, 0, 250)) == SOCK_EAGAIN);
    CHECK(g_nsleep == 3 && timer_ticks - t0 == 250);
}

static void poll_net(void)
{
    sock_poll();
}

static int g_arp_reply_after;
static void poll_arp_reply(void)
{
    sock_poll();
    if (g_ntx == g_arp_reply_after) {
        static const uint8_t ip[4] = { 192, 168, 50, 9 };
        static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0x09 };
        arp_from(ip, mac);
    }
}

static int count_arp(const uint8_t *ip)
{
    int n = 0;

    for (int i = 0; i < g_ntx; i++) {
        n += g_tx[i][12] == 0x08 && g_tx[i][13] == 0x06 && memcmp(g_tx[i] + 38, ip, 4) == 0;
    }
    return n;
}

static void test_send(void)
{
    static uint8_t d[SOCK_DGRAM_MAX + 1];
    static const uint8_t IP77[4] = { 192, 168, 50, 77 };
    static const uint8_t IP9[4] = { 192, 168, 50, 9 };
    uint64_t pd = (uint64_t)(uintptr_t)d;

    reset();
    memcpy(d, "balas", 5);
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 9), 0)) == SOCK_EINVAL);   // belum bind
    CHECK(sock_sys_bind(0, 5555, 0, 0, 0) == 0);

    // validasi sebelum menunggu
    CHECK(sys(sock_sys_sendto(0, pd, SOCK_DGRAM_MAX + 1, SOCK_ADDR(192, 168, 50, 1, 9), 0)) ==
          SOCK_EMSGSIZE);
    CHECK(sys(sock_sys_sendto(0, BADPTR, 5, SOCK_ADDR(192, 168, 50, 1, 9), 0)) == SOCK_EFAULT);
    CHECK(g_sys_rejected == 1 && !g_last_ptr_w);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 0), 0)) == SOCK_EINVAL);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 9) | (1ULL << 48), 0)) == SOCK_EINVAL);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 51, 1, 9), 0)) == SOCK_EHOSTUNREACH);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(10, 168, 50, 1, 9), 0)) == SOCK_EHOSTUNREACH);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 0, 9), 0)) == SOCK_EHOSTUNREACH);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 255, 9), 0)) == SOCK_EHOSTUNREACH);
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 200, 9), 0)) == SOCK_EHOSTUNREACH);
    g_ip_ready = 0;
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 9), 0)) == SOCK_ENETDOWN);
    g_ip_ready = 1;
    g_e1000_rx_initialized = 0;
    CHECK(sys(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 9), 0)) == SOCK_ENETDOWN);
    g_e1000_rx_initialized = 1;
    CHECK(g_ntx == 0 && g_nsleep == 0);

    // MAC dikenal dari datagram masuk -> langsung terkirim, tanpa ARP
    rx_from(PEER_IP, 40000, 5555, "x");
    g_on_sleep = poll_net;
    CHECK(sock_sys_sendto(0, pd, 5, SOCK_ADDR(192, 168, 50, 1, 40000), 0) == 5);
    CHECK(g_tick_wakes == 1 && g_ntx == 1 && g_tx_len[0] == 47);
    CHECK(memcmp(g_tx[0], PEER_MAC, 6) == 0 && memcmp(g_tx[0] + 30, PEER_IP, 4) == 0);
    CHECK(g_tx[0][34] == 0x15 && g_tx[0][35] == 0xb3 && g_tx[0][36] == 0x9c && g_tx[0][37] == 0x40);
    CHECK(memcmp(g_tx[0] + 42, "balas", 5) == 0);
    CHECK(g_sock_tx == 1 && g_sk[0].tx == 1 && g_sk[0].tx_state == SK_TX_NONE);

    // 1472 byte
    for (int i = 0; i < SOCK_DGRAM_MAX; i++) {
        d[i] = (uint8_t)i;
    }
    CHECK(sock_sys_sendto(0, pd, SOCK_DGRAM_MAX, SOCK_ADDR(192, 168, 50, 1, 7), 0) == SOCK_DGRAM_MAX);
    CHECK(g_tx_len[1] == 42 + SOCK_DGRAM_MAX && memcmp(g_tx[1] + 42, d, SOCK_DGRAM_MAX) == 0);

    // tanpa jawaban ARP: 3 request berjarak 50 tick, lalu -113
    g_ntx = 0;
    uint64_t t0 = timer_ticks;
    CHECK(sys(sock_sys_sendto(0, pd, 3, SOCK_ADDR(192, 168, 50, 77, 9), 0)) == SOCK_EHOSTUNREACH);
    CHECK(count_arp(IP77) == 3 && g_ntx == 3 && g_sock_noarp == 1);
    CHECK(timer_ticks - t0 >= 3 * SOCK_ARP_WAIT && timer_ticks - t0 < SOCK_TX_LIMIT);

    // ARP dari IP yang tidak ditunggu tidak dipelajari
    static const uint8_t mac9[6] = { 0x02, 0, 0, 0, 0, 0x09 };
    arp_from(IP9, mac9);
    CHECK(sk_arp_find(IP9) == 0);

    // jawaban ARP setelah request pertama -> data terkirim ke MAC itu
    g_ntx = 0;
    g_arp_reply_after = 1;
    g_on_sleep = poll_arp_reply;
    CHECK(sock_sys_sendto(0, pd, 4, SOCK_ADDR(192, 168, 50, 9, 99), 0) == 4);
    CHECK(count_arp(IP9) == 1 && g_ntx == 2 && memcmp(g_tx[1], mac9, 6) == 0);

    // NIC gagal kirim -> -5
    g_on_sleep = poll_net;
    g_tx_fail = 1;
    CHECK(sys(sock_sys_sendto(0, pd, 4, SOCK_ADDR(192, 168, 50, 9, 99), 0)) == SOCK_EIO);
    g_tx_fail = 0;

    // net task tidak pernah memproses -> -5 setelah SOCK_TX_LIMIT, slot bersih
    g_on_sleep = 0;
    t0 = timer_ticks;
    CHECK(sys(sock_sys_sendto(0, pd, 4, SOCK_ADDR(192, 168, 50, 9, 99), 0)) == SOCK_EIO);
    CHECK(timer_ticks - t0 == SOCK_TX_LIMIT && g_sk[0].tx_state == SK_TX_NONE);
    g_on_sleep = poll_net;
    CHECK(sock_sys_sendto(0, pd, 4, SOCK_ADDR(192, 168, 50, 9, 99), 0) == 4);

    // cache ARP 8 entri: yang tertua tergusur
    for (int i = 0; i < SOCK_ARP_N + 1; i++) {
        uint8_t ip[4] = { 192, 168, 50, (uint8_t)(100 + i) };
        sock_rx(PEER_MAC, ip, 1, 5555, (const uint8_t *)"z", 1);
        sock_sys_recvfrom(0, pd, 8, 0, 0);
    }
    static const uint8_t IP100[4] = { 192, 168, 50, 100 };
    static const uint8_t IP108[4] = { 192, 168, 50, 108 };
    CHECK(sk_arp_find(IP100) == 0 && sk_arp_find(IP108) != 0);
}

static void test_cmd(void)
{
    reset();
    CHECK_STR(run("soket x"), "(tidak ditangani)");
    CHECK_STR(run("soket"), "soket: tidak ada yang terbuka\n"
                            "soket: 0/4 terbuka masuk=0 kirim=0 buang=0 galat=0 tanpa_arp=0\n");
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(sock_sys_bind(0, 5555, 0, 0, 0) == 0);
    current_index = 8;
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 1);
    CHECK(sys(sock_sys_bind(1, 7778, 0, 0, 0)) == SOCK_EACCES);
    current_index = 3;
    rx_from(PEER_IP, 1, 5555, "a");
    CHECK_STR(run("soket"), "0: udp port 5555 task 3 antre 1/4 masuk=1 kirim=0 buang=0\n"
                            "1: udp port 0 task 8 antre 0/4 masuk=0 kirim=0 buang=0\n"
                            "soket: 2/4 terbuka masuk=1 kirim=0 buang=0 galat=1 tanpa_arp=0\n");
    // soket baru di slot lama mulai dari nol
    sock_task_exit(3);
    CHECK(sock_sys_socket(SOCK_UDP, 0, 0, 0, 0) == 0);
    CHECK(g_sk[0].qn == 0 && g_sk[0].rx == 0 && g_sk[0].port == 0);
}

int main(void)
{
    test_socket_bind();
    test_rx_recv();
    test_recv_wait();
    test_send();
    test_cmd();
    return test_done("sock");
}

#!/usr/bin/env python3
"""Uji jaringan bmahOS dengan frame Ethernet mentah (QEMU -netdev dgram).

QEMU membungkus tiap frame Ethernet NIC tamu dalam satu datagram UDP di
127.0.0.1, jadi skrip ini bisa berperan sebagai host di jaringan dan
mengirim frame yang tidak bisa dibuat lewat socket biasa: EtherType asing,
checksum UDP rusak, dan alamat IP sumber berbeda-beda.

Dipanggil oleh tests/qemu-smoke.sh (memakai disk dan kunci uji yang sama):
    qemu-rawnet.py --qemu Q --ovmf-code C --ovmf-vars V --iso I --disk D --key K --work W
"""

import argparse
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import time

GUEST_MAC = bytes.fromhex("525400123456")
HOST_MAC = bytes.fromhex("020000000001")
GUEST_IP = bytes([192, 168, 50, 200])
CMD_PORT = 7778
ECHO_PORT = 7777

results = []


def check(name, cond, detail=""):
    results.append(cond)
    print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                        "" if cond or not detail else "  (" + detail + ")"))


def csum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp_frame(src_ip, sport, dport, payload, bad_checksum=False):
    udp_len = 8 + len(payload)
    pseudo = src_ip + GUEST_IP + struct.pack("!BBH", 0, 17, udp_len)
    hdr = struct.pack("!HHHH", sport, dport, udp_len, 0)
    c = csum16(pseudo + hdr + payload) or 0xFFFF
    if bad_checksum:
        c ^= 0x5A5A
    udp = struct.pack("!HHHH", sport, dport, udp_len, c) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, 0x1234, 0x4000,
                     64, 17, 0, src_ip, GUEST_IP)
    ip = ip[:10] + struct.pack("!H", csum16(ip)) + ip[12:]
    frame = GUEST_MAC + HOST_MAC + b"\x08\x00" + ip + udp
    return frame + b"\0" * max(0, 60 - len(frame))


def tcp_frame(src_ip, sport, dport, seq, ack, flags, payload=b"", bad_checksum=False):
    tcp_len = 20 + len(payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 1024, 0, 0)
    pseudo = src_ip + GUEST_IP + struct.pack("!BBH", 0, 6, tcp_len)
    c = csum16(pseudo + hdr + payload)
    if bad_checksum:
        c ^= 0x5A5A
    tcp = hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + tcp_len, 0x1235, 0x4000,
                     64, 6, 0, src_ip, GUEST_IP)
    ip = ip[:10] + struct.pack("!H", csum16(ip)) + ip[12:]
    frame = GUEST_MAC + HOST_MAC + b"\x08\x00" + ip + tcp
    return frame + b"\0" * max(0, 60 - len(frame))


class Net:
    def __init__(self, sock, qemu_addr):
        self.sock = sock
        self.qemu_addr = qemu_addr

    def send(self, frame):
        self.sock.sendto(frame, self.qemu_addr)

    def drain(self):
        self.sock.setblocking(False)
        try:
            while True:
                self.sock.recv(65536)
        except BlockingIOError:
            pass
        finally:
            self.sock.setblocking(True)

    def udp_replies(self, dst_ip, dport, timeout, limit=None):
        """Kumpulkan payload UDP dari tamu ke dst_ip:dport sampai timeout
        (atau sampai `limit` balasan terkumpul)."""
        out = []
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                return out
            self.sock.settimeout(left)
            try:
                f = self.sock.recv(65536)
            except socket.timeout:
                return out
            if len(f) < 42 or f[12:14] != b"\x08\x00" or f[23] != 17:
                continue
            ihl = (f[14] & 0x0F) * 4
            u = 14 + ihl
            if f[30:34] != dst_ip or struct.unpack("!H", f[u + 2:u + 4])[0] != dport:
                continue
            ulen = struct.unpack("!H", f[u + 4:u + 6])[0]
            out.append(f[u + 8:u + ulen])
            if limit is not None and len(out) >= limit:
                return out

    def tcp_replies(self, dst_ip, dport, timeout, payload=False, stamp=False, limit=None):
        """Segmen TCP dari tamu ke dst_ip:dport: list (seq, ack, flags, datalen),
        atau (seq, ack, flags, data) bila payload=True. stamp=True: tiap
        elemen diawali waktu terima (time.time()). limit: berhenti setelah
        sekian segmen (C3c: segmen yang belum di-ACK dikirim ulang tiap RTO)."""
        out = []
        end = time.time() + timeout
        while True:
            left = end - time.time()
            if left <= 0:
                return out
            self.sock.settimeout(left)
            try:
                f = self.sock.recv(65536)
            except socket.timeout:
                return out
            if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
                continue
            t = 14 + (f[14] & 0x0F) * 4
            if f[30:34] != dst_ip or struct.unpack("!H", f[t + 2:t + 4])[0] != dport:
                continue
            tl = struct.unpack("!H", f[16:18])[0] - (f[14] & 0x0F) * 4
            pseudo = f[26:30] + f[30:34] + struct.pack("!BBH", 0, 6, tl)
            if csum16(pseudo + f[t:t + tl]) != 0 or csum16(f[14:t]) != 0:
                out.append(("BADSUM",))
                continue
            seq, ack = struct.unpack("!II", f[t + 4:t + 12])
            tot = struct.unpack("!H", f[16:18])[0]
            dlen = tot - (f[14] & 0x0F) * 4 - (f[t + 12] >> 4) * 4
            if payload:
                d0 = t + (f[t + 12] >> 4) * 4
                item = (seq, ack, f[t + 13], f[d0:d0 + dlen])
            else:
                item = (seq, ack, f[t + 13], dlen)
            out.append((time.time(),) + item if stamp else item)
            if limit is not None and len(out) >= limit:
                return out

    def request(self, src_ip, sport, dport, payload, timeout=10.0):
        self.send(udp_frame(src_ip, sport, dport, payload))
        r = self.udp_replies(src_ip, sport, timeout, limit=1)
        return r[0] if r else None


class Client:
    """Perintah terautentikasi lewat frame mentah (jalur nonce/CHAL)."""

    def __init__(self, net, key, src_ip, sport=40000):
        self.net, self.key, self.src_ip, self.sport = net, key, src_ip, sport

    def sign(self, msg):
        return ("%s %s" % (msg, hmac.new(self.key, msg.encode(),
                                         hashlib.sha256).hexdigest())).encode()

    def cmd(self, c):
        self.sport += 1
        r = self.net.request(self.src_ip, self.sport, CMD_PORT, b"CHAL")
        if r is None or not r.startswith(b"nonce: "):
            return None
        msg = "%s %s" % (r[len(b"nonce: "):].strip().decode(), c)
        r = self.net.request(self.src_ip, self.sport, CMD_PORT, self.sign(msg))
        return r.decode(errors="replace") if r is not None else None

    def metrics(self):
        r = self.cmd("metrics")
        if r is None or "=" not in r:
            return None
        return {k: int(v) for k, v in
                (l.split("=", 1) for l in r.strip().splitlines() if "=" in l)}


def test_fs_persist(net, cli):
    """D6: file yang ditulis di boot pertama terbaca kernel setelah reboot."""
    r = cli.cmd("baca CATATAN.TXT")
    check("D6: setelah reboot baca CATATAN.TXT = baris satu + baris dua",
          r == "isi CATATAN.TXT ukuran=21:\nbaris satu\nbaris dua\n", repr(r))


def test_counters(net, cli):
    """B1: rx_other dan udp_badsum harus naik."""
    m0 = cli.metrics()
    check("metrics lewat frame mentah", m0 is not None)
    if m0 is None:
        return

    for _ in range(3):
        net.send(GUEST_MAC + HOST_MAC + b"\x88\xb5" + b"bmahOS-test".ljust(46, b"\0"))
    src = bytes([192, 168, 50, 1])
    for i in range(2):
        net.send(udp_frame(src, 41000 + i, ECHO_PORT, b"rusak", bad_checksum=True))
    bad = net.udp_replies(src, 41000, 1.5) + net.udp_replies(src, 41001, 0.5)
    good = net.request(src, 41002, ECHO_PORT, b"utuh")

    m1 = cli.metrics()
    if m1 is None:
        check("metrics setelah frame uji", False)
        return
    d_other = m1["rx_other"] - m0["rx_other"]
    d_bad = m1["udp_badsum"] - m0["udp_badsum"]
    check("EtherType asing -> rx_other +3", d_other == 3, "selisih %d" % d_other)
    check("checksum UDP rusak -> udp_badsum +2", d_bad == 2, "selisih %d" % d_bad)
    check("checksum rusak tidak dibalas", not bad)
    check("echo checksum benar dibalas", good == b"utuh", repr(good))


def test_src_limit(net, cli):
    """B4: banjir dari satu IP sumber tidak menghabiskan jatah IP lain."""
    m0 = cli.metrics()
    if m0 is None:
        check("B4: metrics awal", False)
        return
    flood = bytes([192, 168, 50, 11])
    other = bytes([192, 168, 50, 12])
    sent = 0
    for _ in range(5):
        for _ in range(30):
            net.send(udp_frame(flood, 42000 + sent, ECHO_PORT, b"banjir"))
            sent += 1
        time.sleep(0.02)
    got = net.request(other, 43000, ECHO_PORT, b"lain", timeout=5)
    time.sleep(0.5)
    net.drain()
    m1 = cli.metrics()
    if m1 is None:
        check("B4: metrics akhir", False)
        return
    d_src = m1["udp_src_dropped"] - m0["udp_src_dropped"]
    d_glob = m1["udp_dropped"] - m0["udp_dropped"]
    d_echo = m1["udp_echo"] - m0["udp_echo"]
    info = "kirim=%d echo=%d dibuang_sumber=%d dibuang_global=%d" % (sent, d_echo, d_src, d_glob)
    print("info  B4: " + info)
    check("B4: IP lain tetap dilayani saat banjir", got == b"lain", repr(got))
    check("B4: banjir dibatasi per sumber", d_src >= 50 and d_echo - 1 <= 40, info)
    check("B4: jatah global tidak habis", d_glob == 0, info)


def test_chal_flood(net, cli):
    """M1: banjir CHAL dari satu IP tidak menggusur nonce klien sah."""
    m0 = cli.metrics()
    if m0 is None:
        check("M1: metrics awal", False)
        return
    legit = bytes([192, 168, 50, 13])
    flood = bytes([192, 168, 50, 14])
    r = net.request(legit, 44000, CMD_PORT, b"CHAL")
    ok_chal = r is not None and r.startswith(b"nonce: ")
    check("M1: klien sah dapat nonce", ok_chal, repr(r))
    if not ok_chal:
        return
    for i in range(15):
        net.send(udp_frame(flood, 45000 + i, CMD_PORT, b"CHAL"))
        time.sleep(0.01)
    time.sleep(0.5)
    net.drain()
    msg = "%s ping" % r[len(b"nonce: "):].strip().decode()
    pkt = Client(net, cli.key, legit).sign(msg)
    got = net.request(legit, 44000, CMD_PORT, pkt, timeout=5)
    m1 = cli.metrics()
    check("M1: nonce sah tetap berlaku setelah banjir CHAL", got is not None and got.strip() == b"pong", repr(got))
    if m1 is not None:
        d = m1["chal_ip_recycled"] - m0["chal_ip_recycled"]
        check("M1: banjir CHAL didaur ulang per IP", d >= 8, "didaur ulang %d" % d)


def test_tcp_closed(net, cli):
    """C1: TCP ke port tertutup dibalas RST; checksum salah dan RST masuk dibuang."""
    m0 = cli.metrics()
    if m0 is None:
        check("C1: metrics awal", False)
        return
    src = bytes([192, 168, 50, 15])
    net.send(tcp_frame(src, 46000, 80, 1000, 0, 0x02))
    r = net.tcp_replies(src, 46000, 2)
    check("C1: SYN ke port tertutup -> RST|ACK ack=seq+1",
          r == [(0, 1001, 0x14, 0)], repr(r))
    net.send(tcp_frame(src, 46001, 80, 2000, 777, 0x10, b"abc"))
    r = net.tcp_replies(src, 46001, 2)
    check("C1: ACK+data ke port tertutup -> RST seq=ack",
          r == [(777, 0, 0x04, 0)], repr(r))
    net.send(tcp_frame(src, 46002, 80, 3000, 0, 0x02, bad_checksum=True))
    r = net.tcp_replies(src, 46002, 1.5)
    check("C1: checksum TCP salah tidak dibalas", r == [], repr(r))
    net.send(tcp_frame(src, 46003, 80, 4000, 0, 0x04))
    r = net.tcp_replies(src, 46003, 1.5)
    check("C1: RST masuk tidak dibalas", r == [], repr(r))
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("C1: metrics akhir", False)
        return
    d = {k: m1[k] - m0[k] for k in ("tcp_rx", "tcp_badsum", "tcp_rst_sent")}
    check("C1: metrics tcp_rx +4, tcp_badsum +1, tcp_rst_sent +2",
          d["tcp_rx"] == 4 and d["tcp_badsum"] == 1 and d["tcp_rst_sent"] == 2, repr(d))


def test_tcp_handshake(net, cli):
    """C2: handshake port 7, data diterima + ACK, duplikat/out-of-order, busy, FIN, RST."""
    m0 = cli.metrics()
    if m0 is None:
        check("C2: metrics awal", False)
        return
    a = bytes([192, 168, 50, 16])
    b = bytes([192, 168, 50, 17])
    net.send(tcp_frame(a, 47000, 7, 5000, 0, 0x02))
    r = net.tcp_replies(a, 47000, 2, limit=1)
    ok = len(r) == 1 and r[0][2] == 0x12 and r[0][1] == 5001
    check("C2: SYN port 7 -> SYN-ACK ack=seq+1", ok, repr(r))
    if not ok:
        return
    iss = r[0][0]
    net.send(tcp_frame(a, 47000, 7, 5001, iss + 1, 0x10))
    r = net.tcp_replies(a, 47000, 1)
    check("C2: ACK handshake tanpa data tidak dibalas", r == [], repr(r))
    net.send(tcp_frame(a, 47000, 7, 5001, iss + 1, 0x18, b"hello"))
    r = net.tcp_replies(a, 47000, 2, payload=True, limit=1)
    check("C3b: data 5 byte -> echo PSH|ACK ack=5006 berisi hello",
          r == [(iss + 1, 5006, 0x18, b"hello")], repr(r))
    # C3c: ACK echo supaya tidak dikirim ulang di tengah uji berikutnya.
    net.send(tcp_frame(a, 47000, 7, 5006, iss + 6, 0x10))
    net.send(tcp_frame(a, 47000, 7, 5001, iss + 6, 0x18, b"hello"))
    r = net.tcp_replies(a, 47000, 2)
    check("C2: data duplikat -> ACK ulang ack=5006",
          r == [(iss + 6, 5006, 0x10, 0)], repr(r))
    net.send(tcp_frame(a, 47000, 7, 9999, iss + 6, 0x18, b"zz"))
    r = net.tcp_replies(a, 47000, 2)
    check("C2: di luar urutan -> ACK ack=5006",
          r == [(iss + 6, 5006, 0x10, 0)], repr(r))
    net.send(tcp_frame(b, 47001, 7, 7000, 0, 0x02))
    r = net.tcp_replies(b, 47001, 2, limit=1)
    check("C5a: koneksi kedua (IP lain) diterima -> SYN-ACK",
          len(r) == 1 and r[0][2] == 0x12 and r[0][1] == 7001, repr(r))
    net.send(tcp_frame(b, 47001, 7, 7001, 0, 0x04))
    net.send(tcp_frame(a, 47000, 7, 5006, iss + 6, 0x11))
    r = net.tcp_replies(a, 47000, 2, limit=1)
    check("C3d: FIN -> FIN|ACK ack=5007 (echo kosong, LAST_ACK)",
          r == [(iss + 6, 5007, 0x11, 0)], repr(r))
    net.send(tcp_frame(a, 47000, 7, 5007, iss + 6, 0x04))
    r = net.tcp_replies(a, 47000, 1)
    check("C2: RST dari peer tidak dibalas", r == [], repr(r))
    net.send(tcp_frame(b, 47002, 7, 8000, 0, 0x02))
    r = net.tcp_replies(b, 47002, 2, limit=1)
    check("C2: setelah RST, koneksi baru diterima",
          len(r) == 1 and r[0][2] == 0x12 and r[0][1] == 8001, repr(r))
    net.send(tcp_frame(b, 47002, 7, 8001, 0, 0x04))
    net.tcp_replies(b, 47002, 0.5)
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("C2: metrics akhir", False)
        return
    d = {k: m1[k] - m0[k] for k in ("tcp_conn_open", "tcp_dropped_busy", "tcp_rx_bytes", "tcp_tx_bytes")}
    check("C2: metrics conn_open +1, dropped_busy +0, rx_bytes +5, tx_bytes +5",
          d == {"tcp_conn_open": 1, "tcp_dropped_busy": 0, "tcp_rx_bytes": 5, "tcp_tx_bytes": 5}, repr(d))


def test_tcp_send(net, cli):
    """C3b: kirim data dari kernel (echo sementara), stop-and-wait, segmen <= MSS 536."""
    c = bytes([192, 168, 50, 18])
    data = bytes((i * 7 + 3) & 0xFF for i in range(600))
    net.send(tcp_frame(c, 47100, 7, 1000, 0, 0x02))
    r = net.tcp_replies(c, 47100, 2, limit=1)
    if not (len(r) == 1 and r[0][2] == 0x12):
        check("C3b: SYN-ACK", False, repr(r))
        return
    iss = r[0][0]
    net.send(tcp_frame(c, 47100, 7, 1001, iss + 1, 0x10))
    net.send(tcp_frame(c, 47100, 7, 1001, iss + 1, 0x18, data))
    r = net.tcp_replies(c, 47100, 2, payload=True, limit=1)
    check("C3b: 600 byte -> segmen pertama 536 byte, isi sama, ack=1601",
          r == [(iss + 1, 1601, 0x18, data[:536])], repr([(x[0], x[1], x[2], len(x[3])) for x in r]))
    net.send(tcp_frame(c, 47100, 7, 1601, iss + 1 + 536, 0x10))
    r = net.tcp_replies(c, 47100, 2, payload=True, limit=1)
    check("C3b: setelah ACK -> sisa 64 byte, seq=iss+537",
          r == [(iss + 537, 1601, 0x18, data[536:])], repr([(x[0], x[1], x[2], len(x[3])) for x in r]))
    net.send(tcp_frame(c, 47100, 7, 1601, iss + 601, 0x10))
    r = net.tcp_replies(c, 47100, 1)
    check("C3b: ACK semua data -> tidak ada balasan", r == [], repr(r))
    net.send(tcp_frame(c, 47100, 7, 1601, iss + 601, 0x04))
    net.tcp_replies(c, 47100, 0.5)


def test_tcp_retx(net, cli):
    """C3c: ACK sengaja dibuang -> SYN-ACK dan data dikirim ulang (RTO 1 s lalu 2 s)."""
    m0 = cli.metrics()
    if m0 is None:
        check("C3c: metrics awal", False)
        return
    c = bytes([192, 168, 50, 19])
    net.send(tcp_frame(c, 47200, 7, 3000, 0, 0x02))
    t0 = time.time()
    r = net.tcp_replies(c, 47200, 1.6, stamp=True)
    ok = len(r) == 2 and all(x[1:] == (r[0][1], 3001, 0x12, 0) for x in r)
    check("C3c: SYN-ACK tanpa ACK dikirim ulang sekali dalam 1,6 s, sama persis", ok,
          repr([(round(x[0] - t0, 2),) + x[1:] for x in r]))
    if not r or r[0][3] != 0x12:
        return
    iss = r[0][1]
    gap = r[1][0] - r[0][0] if ok else 0
    check("C3c: jeda SYN-ACK ulang ~1 s (0,7..1,5)", 0.7 <= gap <= 1.5, "%.2f" % gap)
    net.send(tcp_frame(c, 47200, 7, 3001, iss + 1, 0x10))
    data = b"kirim-ulang C3c"
    net.send(tcp_frame(c, 47200, 7, 3001, iss + 1, 0x18, data))
    r = net.tcp_replies(c, 47200, 4.0, payload=True, stamp=True)
    want = (iss + 1, 3001 + len(data), 0x18, data)
    ok = len(r) == 3 and all(x[1:] == want for x in r)
    check("C3c: data tanpa ACK -> echo + 2 kirim ulang identik dalam 4 s", ok,
          repr([(round(x[0] - r[0][0], 2), x[1] - iss, x[3], len(x[4])) for x in r]))
    if ok:
        g1, g2 = r[1][0] - r[0][0], r[2][0] - r[1][0]
        check("C3c: backoff eksponensial (jeda ~1 s lalu ~2 s)",
              0.7 <= g1 <= 1.5 and 1.6 <= g2 <= 2.8, "%.2f %.2f" % (g1, g2))
    net.send(tcp_frame(c, 47200, 7, 3001 + len(data), iss + 1 + len(data), 0x10))
    r = net.tcp_replies(c, 47200, 2.5)
    check("C3c: setelah ACK tidak ada kirim ulang lagi", r == [], repr(r))
    net.send(tcp_frame(c, 47200, 7, 3001 + len(data), iss + 1 + len(data), 0x04))
    net.tcp_replies(c, 47200, 0.5)
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("C3c: metrics akhir", False)
        return
    d = {k: m1[k] - m0[k] for k in ("tcp_retx", "tcp_retx_giveup", "tcp_conn_open")}
    check("C3c: metrics tcp_retx +3, tcp_retx_giveup +0, conn_open +1",
          d == {"tcp_retx": 3, "tcp_retx_giveup": 0, "tcp_conn_open": 1}, repr(d))


def test_tcp_close(net, cli):
    """C3d: tutup pasif (FIN|ACK, port langsung bebas), FIN dikirim ulang, data
    setelah FIN -> RST, tutup aktif saat diam 30 s sampai TIME_WAIT 2 s."""
    m0 = cli.metrics()
    if m0 is None:
        check("C3d: metrics awal", False)
        return

    def open_conn(ip, port, pseq):
        net.send(tcp_frame(ip, port, 7, pseq, 0, 0x02))
        r = net.tcp_replies(ip, port, 2, limit=1)
        if not (len(r) == 1 and r[0][2] == 0x12):
            check("C3d: SYN-ACK dari %s:%d" % (ip[3], port), False, repr(r))
            return None
        net.send(tcp_frame(ip, port, 7, pseq + 1, r[0][0] + 1, 0x10))
        return r[0][0]

    a = bytes([192, 168, 50, 20])
    iss = open_conn(a, 47300, 100)
    if iss is None:
        return
    net.send(tcp_frame(a, 47300, 7, 101, iss + 1, 0x18, b"tutup"))
    r = net.tcp_replies(a, 47300, 2, payload=True, limit=1)
    check("C3d: echo sebelum tutup", r == [(iss + 1, 106, 0x18, b"tutup")], repr(r))
    net.send(tcp_frame(a, 47300, 7, 106, iss + 6, 0x10))
    net.send(tcp_frame(a, 47300, 7, 106, iss + 6, 0x11))
    r = net.tcp_replies(a, 47300, 2, limit=1)
    check("C3d: tutup pasif: FIN peer -> FIN|ACK seq=iss+6 ack=107",
          r == [(iss + 6, 107, 0x11, 0)], repr(r))
    net.send(tcp_frame(a, 47300, 7, 107, iss + 7, 0x10))
    r = net.tcp_replies(a, 47300, 1.5)
    check("C3d: ACK untuk FIN kita tidak dibalas", r == [], repr(r))

    # Port langsung bebas (dulu: sibuk sampai timeout 30 s).
    b = bytes([192, 168, 50, 21])
    iss = open_conn(b, 47301, 200)
    check("C3d: koneksi baru langsung diterima setelah tutup", iss is not None)
    if iss is None:
        return
    net.send(tcp_frame(b, 47301, 7, 201, iss + 1, 0x11))
    r = net.tcp_replies(b, 47301, 1.7, stamp=True)
    ok = len(r) == 2 and all(x[1:] == (iss + 1, 202, 0x11, 0) for x in r)
    check("C3d: FIN kita tanpa ACK dikirim ulang (~1 s)",
          ok and 0.7 <= r[1][0] - r[0][0] <= 1.5,
          repr([(round(x[0] - r[0][0], 2),) + x[1:] for x in r]))
    net.send(tcp_frame(b, 47301, 7, 202, iss + 1, 0x18, b"telat"))
    r = net.tcp_replies(b, 47301, 2, limit=1)
    check("C3d: data setelah FIN peer -> RST|ACK", r == [(iss + 2, 202, 0x14, 0)], repr(r))

    # Tutup aktif: diam 30 s -> FIN kita; FIN peer -> ACK; TIME_WAIT 2 s.
    c = bytes([192, 168, 50, 22])
    iss = open_conn(c, 47302, 300)
    if iss is None:
        return
    # C5b: gangguan pada 2, 7, 12, 17, 22 s (ACK duplikat, keepalive seq-1,
    # RST seq salah) tidak memperpanjang timeout diam; keepalive dibalas ACK.
    noise = [tcp_frame(c, 47302, 7, 301, iss + 1, 0x10),
             tcp_frame(c, 47302, 7, 300, iss + 1, 0x10),
             tcp_frame(c, 47302, 7, 9999, 0, 0x04)]
    t0 = time.time()
    fin, acks, other, k = None, 0, [], 0
    while fin is None and time.time() - t0 < 34:
        if k < 5 and time.time() - t0 >= 5 * k + 2:
            net.send(noise[k % 3])
            k += 1
        for x in net.tcp_replies(c, 47302, 0.3, stamp=True):
            if x[1:] == (iss + 1, 301, 0x11, 0):
                fin = fin or x
            elif x[1:] == (iss + 1, 301, 0x10, 0):
                acks += 1
            else:
                other.append(x[1:])
    dt = (fin[0] if fin else time.time()) - t0
    check("C3d: diam ~30 s -> FIN|ACK seq=iss+1 (FIN_WAIT_1)",
          fin is not None and 28 <= dt <= 34, "%r %.1f s" % (fin, dt))
    check("C5b: 5 gangguan tidak menunda FIN, keepalive dibalas ACK 2x",
          fin is not None and k == 5 and acks == 2 and other == [],
          "k=%d acks=%d other=%r" % (k, acks, other))
    net.send(tcp_frame(c, 47302, 7, 301, iss + 2, 0x11))
    r = net.tcp_replies(c, 47302, 2, limit=1)
    check("C3d: FIN peer -> ACK ack=302 (TIME_WAIT)", r == [(iss + 2, 302, 0x10, 0)], repr(r))
    d = bytes([192, 168, 50, 23])
    net.send(tcp_frame(d, 47303, 7, 400, 0, 0x02))
    r = net.tcp_replies(d, 47303, 1, limit=1)
    check("C5a: SYN lain saat TIME_WAIT memakai slot lain -> SYN-ACK",
          len(r) == 1 and r[0][2] == 0x12 and r[0][1] == 401, repr(r))
    net.send(tcp_frame(d, 47303, 7, 401, 0, 0x04))
    time.sleep(2.5)
    iss = open_conn(d, 47304, 500)
    check("C3d: setelah TIME_WAIT 2 s koneksi baru diterima", iss is not None)
    if iss is not None:
        net.send(tcp_frame(d, 47304, 7, 501, iss + 1, 0x04))
        net.tcp_replies(d, 47304, 0.5)

    # C5b: SYN diulang tiap 1 s tidak menahan SYN_RCVD; RST|ACK ~5 s setelah
    # SYN pertama (dulu: baru setelah SYN terakhir + 5 s).
    e = bytes([192, 168, 50, 24])
    syn = tcp_frame(e, 47305, 7, 600, 0, 0x02)
    t0 = time.time()
    net.send(syn)
    rst, k = None, 1
    while rst is None and time.time() - t0 < 9:
        if k < 5 and time.time() - t0 >= k:
            net.send(syn)
            k += 1
        for x in net.tcp_replies(e, 47305, 0.2, stamp=True):
            if x[3] & 0x04:
                rst = rst or x
    dt = (rst[0] if rst else time.time()) - t0
    check("C5b: SYN ulang tiap 1 s -> SYN_RCVD tetap RST|ACK ~5 s",
          rst is not None and rst[3] == 0x14 and k == 5 and 4.3 <= dt <= 6.8,
          "%r k=%d %.1f s" % (rst and rst[1:], k, dt))
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("C3d: metrics akhir", False)
        return
    dd = {k: m1[k] - m0[k] for k in ("tcp_close_ok", "tcp_rst_state", "tcp_timeout")}
    check("C3d: metrics close_ok +2, rst_state +1, timeout +2 (C5b), tcp_state=0",
          dd == {"tcp_close_ok": 2, "tcp_rst_state": 1, "tcp_timeout": 2} and m1["tcp_state"] == 0,
          repr((dd, m1.get("tcp_state"))))


def test_tcp_table(net, cli):
    """C5a: tabel 4 TCB, maks 2 per IP, SYN_RCVD tertua digusur saat penuh,
    semua aktif -> RST, banjir SYN dari banyak IP tidak menghalangi klien sah."""
    m0 = cli.metrics()
    if m0 is None:
        check("C5a: metrics awal", False)
        return

    def syn(ip, port, pseq):
        net.send(tcp_frame(ip, port, 7, pseq, 0, 0x02))
        r = net.tcp_replies(ip, port, 2, limit=1)
        if len(r) == 1 and r[0][2] == 0x12 and r[0][1] == pseq + 1:
            return r[0][0]
        return None

    def echo(ip, port, pseq, iss, data):
        net.send(tcp_frame(ip, port, 7, pseq, iss + 1, 0x18, data))
        r = net.tcp_replies(ip, port, 2, payload=True, limit=1)
        net.send(tcp_frame(ip, port, 7, pseq + len(data), iss + 1 + len(data), 0x10))
        return r == [(iss + 1, pseq + len(data), 0x18, data)], r

    a = bytes([192, 168, 50, 30])
    i1 = syn(a, 47500, 1000)
    i2 = syn(a, 47501, 2000)
    check("C5a: dua koneksi dari satu IP diterima", i1 is not None and i2 is not None)
    if i1 is None or i2 is None:
        return
    net.send(tcp_frame(a, 47500, 7, 1001, i1 + 1, 0x10))
    net.send(tcp_frame(a, 47501, 7, 2001, i2 + 1, 0x10))
    net.send(tcp_frame(a, 47502, 7, 3000, 0, 0x02))
    r = net.tcp_replies(a, 47502, 2)
    check("C5a: koneksi ketiga dari IP yang sama -> RST|ACK", r == [(0, 3001, 0x14, 0)], repr(r))
    ok1, r1 = echo(a, 47500, 1001, i1, b"satu")
    ok2, r2 = echo(a, 47501, 2001, i2, b"dua")
    check("C5a: dua koneksi bersamaan, echo masing-masing benar", ok1 and ok2, repr((r1, r2)))

    # Dua SYN_RCVD (.31 lalu .32) -> tabel penuh; .33 menggusur .31.
    b = bytes([192, 168, 50, 31])
    c = bytes([192, 168, 50, 32])
    d = bytes([192, 168, 50, 33])
    ib = syn(b, 47510, 4000)
    time.sleep(0.2)
    ic = syn(c, 47520, 5000)
    time.sleep(0.2)
    idd = syn(d, 47530, 6000)
    check("C5a: tabel penuh, SYN baru tetap dapat SYN-ACK (SYN_RCVD digusur)",
          None not in (ib, ic, idd))
    if None in (ib, ic, idd):
        return
    net.send(tcp_frame(b, 47510, 7, 4001, ib + 1, 0x10))
    r = net.tcp_replies(b, 47510, 2, limit=1)
    check("C5a: ACK dari SYN_RCVD yang digusur -> RST", r == [(ib + 1, 0, 0x04, 0)], repr(r))
    net.send(tcp_frame(c, 47520, 7, 5001, ic + 1, 0x10))
    net.send(tcp_frame(d, 47530, 7, 6001, idd + 1, 0x10))
    e = bytes([192, 168, 50, 34])
    net.send(tcp_frame(e, 47540, 7, 7000, 0, 0x02))
    r = net.tcp_replies(e, 47540, 2)
    check("C5a: 4 koneksi aktif -> SYN berikutnya RST|ACK", r == [(0, 7001, 0x14, 0)], repr(r))
    ok, r = echo(d, 47530, 6001, idd, b"empat")
    check("C5a: koneksi yang menggusur bekerja (echo)", ok, repr(r))
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("C5a: metrics tengah", False)
        return
    dd = {k: m1[k] - m0[k] for k in ("tcp_src_full", "tcp_synrcvd_evicted", "tcp_dropped_busy")}
    check("C5a: metrics src_full +1, evicted +1, busy +1, conn_active 4",
          dd == {"tcp_src_full": 1, "tcp_synrcvd_evicted": 1, "tcp_dropped_busy": 1}
          and m1["tcp_conn_active"] == 4, repr((dd, m1.get("tcp_conn_active"))))
    for ip, port, seq in ((a, 47500, 1005), (a, 47501, 2004), (c, 47520, 5001), (d, 47530, 6006)):
        net.send(tcp_frame(ip, port, 7, seq, 0, 0x04))
    time.sleep(0.5)
    net.drain()

    # Banjir SYN dari 20 IP palsu, klien sah tetap tersambung; banjir kedua
    # tidak menggusur koneksi ESTABLISHED.
    for i in range(20):
        net.send(tcp_frame(bytes([192, 168, 50, 100 + i]), 48000 + i, 7, 9000, 0, 0x02))
        time.sleep(0.01)
    time.sleep(0.3)
    net.drain()
    g = bytes([192, 168, 50, 35])
    ig = syn(g, 47550, 8000)
    check("C5a: klien sah dapat SYN-ACK setelah banjir SYN 20 IP", ig is not None)
    if ig is None:
        return
    net.send(tcp_frame(g, 47550, 7, 8001, ig + 1, 0x10))
    for i in range(10):
        net.send(tcp_frame(bytes([192, 168, 50, 120 + i]), 48100 + i, 7, 9000, 0, 0x02))
        time.sleep(0.01)
    time.sleep(0.3)
    net.drain()
    ok, r = echo(g, 47550, 8001, ig, b"sah")
    check("C5a: koneksi sah tetap jalan selama banjir SYN kedua", ok, repr(r))
    net.send(tcp_frame(g, 47550, 7, 8004, 0, 0x04))
    # SYN_RCVD palsu berakhir sendiri (5 s).
    time.sleep(6.5)
    net.drain()
    m2 = cli.metrics()
    if m2 is None:
        check("C5a: metrics akhir", False)
        return
    ev = m2["tcp_synrcvd_evicted"] - m1["tcp_synrcvd_evicted"]
    check("C5a: banjir menggusur SYN_RCVD (20..27), semua slot bebas lagi",
          20 <= ev <= 27 and m2["tcp_conn_active"] == 0 and m2["tcp_state"] == 0,
          repr((ev, m2.get("tcp_conn_active"), m2.get("tcp_state"))))


def test_cli_limit(net, cli):
    """D4: maks 2 TCB port 7779 (IP berbeda, di bawah batas per IP): SYN_RCVD
    CLI tertua digusur, dua sesi aktif -> SYN 7779 berikutnya RST|ACK
    (cli_sess_full), port 7 tetap diterima."""
    m0 = cli.metrics()
    if m0 is None:
        check("D4: metrics awal", False)
        return

    def syn(ip, sport, dport, pseq):
        net.send(tcp_frame(ip, sport, dport, pseq, 0, 0x02))
        r = net.tcp_replies(ip, sport, 2, limit=1)
        if len(r) == 1 and r[0][2] == 0x12 and r[0][1] == pseq + 1:
            return r[0][0]
        return None

    a, b, c, d, e = (bytes([192, 168, 50, x]) for x in (60, 61, 62, 63, 64))
    ia = syn(a, 47600, 7779, 1000)
    time.sleep(0.2)
    ib = syn(b, 47610, 7779, 2000)
    time.sleep(0.2)
    ic = syn(c, 47620, 7779, 3000)
    check("D4: SYN 7779 ke-3 tetap SYN-ACK (SYN_RCVD CLI tertua digusur)",
          None not in (ia, ib, ic))
    if None in (ia, ib, ic):
        return
    net.send(tcp_frame(b, 47610, 7779, 2001, ib + 1, 0x10))
    net.send(tcp_frame(c, 47620, 7779, 3001, ic + 1, 0x10))
    rb = net.tcp_replies(b, 47610, 1, limit=1)
    rc = net.tcp_replies(c, 47620, 1, limit=1)
    blen = rb[0][3] if rb else 0
    if rb and rc:   # banner di-ACK supaya tidak dikirim ulang
        net.send(tcp_frame(b, 47610, 7779, 2001, ib + 1 + rb[0][3], 0x10))
        net.send(tcp_frame(c, 47620, 7779, 3001, ic + 1 + rc[0][3], 0x10))
    check("D4: dua sesi CLI dari dua IP terbuka (banner)", blen == 53 and rc and rc[0][3] == 53,
          repr((rb, rc)))
    net.send(tcp_frame(d, 47630, 7779, 4000, 0, 0x02))
    r = net.tcp_replies(d, 47630, 2)
    check("D4: SYN 7779 saat 2 sesi CLI aktif -> RST|ACK", r == [(0, 4001, 0x14, 0)], repr(r))
    ie = syn(e, 47640, 7, 5000)
    check("D4: port 7 tetap diterima saat sesi CLI penuh", ie is not None)
    time.sleep(1.2)
    m1 = cli.metrics()
    if m1 is None:
        check("D4: metrics akhir", False)
        return
    dd = {k: m1[k] - m0[k] for k in ("cli_sess_full", "tcp_synrcvd_evicted", "tcp_src_full")}
    check("D4: metrics cli_sess_full +1, evicted +1, src_full 0",
          dd == {"cli_sess_full": 1, "tcp_synrcvd_evicted": 1, "tcp_src_full": 0}, repr(dd))
    net.send(tcp_frame(b, 47610, 7779, 2001, 0, 0x04))
    net.send(tcp_frame(c, 47620, 7779, 3001, 0, 0x04))
    if ie is not None:
        net.send(tcp_frame(e, 47640, 7, 5001, 0, 0x04))
    time.sleep(0.5)
    net.drain()


def main():
    p = argparse.ArgumentParser()
    for a in ("qemu", "ovmf-code", "ovmf-vars", "iso", "disk", "key", "work"):
        p.add_argument("--" + a, required=True)
    p.add_argument("--boot-timeout", type=int, default=180)
    a = p.parse_args()

    key = open(a.key, "rb").read().rstrip(b"\r\n \x00")
    log = os.path.join(a.work, "serial-rawnet.log")
    vars_fd = os.path.join(a.work, "vars-rawnet.fd")
    with open(a.ovmf_vars, "rb") as src, open(vars_fd, "wb") as dst:
        dst.write(src.read())

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    host_port = sock.getsockname()[1]
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    qemu_port = probe.getsockname()[1]
    probe.close()

    if os.path.exists(log):
        os.remove(log)
    qemu = subprocess.Popen([
        a.qemu, "-machine", "q35", "-m", "512M", "-cpu", "max",
        "-drive", "if=pflash,format=raw,readonly=on,file=" + a.ovmf_code,
        "-drive", "if=pflash,format=raw,file=" + vars_fd,
        "-cdrom", a.iso,
        "-drive", "id=d0,file=%s,format=raw,if=none" % a.disk,
        "-device", "ide-hd,drive=d0,bus=ide.1",
        "-netdev", "dgram,id=n0,local.type=inet,local.host=127.0.0.1,"
                   "local.port=%d,remote.type=inet,remote.host=127.0.0.1,"
                   "remote.port=%d" % (qemu_port, host_port),
        "-device", "e1000,netdev=n0,mac=52:54:00:12:34:56",
        "-display", "none", "-serial", "file:" + log, "-no-reboot",
    ], stdout=subprocess.DEVNULL, stderr=open(os.path.join(a.work, "qemu-rawnet.out"), "w"))

    try:
        end = time.time() + a.boot_timeout
        while True:
            if qemu.poll() is not None:
                print("QEMU (rawnet) berhenti sebelum net task jalan")
                return 1
            # F1.8: CHAL baru dilayani setelah kolam entropi siap; dengan
            # rdseed/rdrand itu terjadi sebelum net task jalan, jadi tunggu keduanya.
            if os.path.exists(log):
                text = open(log, "rb").read()
                if b"net task dimulai" in text and b"Entropi: siap" in text:
                    break
            if time.time() > end:
                print("timeout menunggu boot (rawnet)")
                return 1
            time.sleep(0.5)

        net = Net(sock, ("127.0.0.1", qemu_port))
        net.drain()
        cli = Client(net, key, bytes([192, 168, 50, 1]))

        test_counters(net, cli)
        time.sleep(1.2)
        test_fs_persist(net, cli)
        time.sleep(1.2)
        test_src_limit(net, cli)
        time.sleep(2.2)
        test_chal_flood(net, cli)
        time.sleep(2.2)
        test_tcp_closed(net, cli)
        time.sleep(2.2)
        test_tcp_handshake(net, cli)
        time.sleep(1.2)
        test_tcp_send(net, cli)
        time.sleep(1.2)
        test_tcp_retx(net, cli)
        time.sleep(1.2)
        test_tcp_close(net, cli)
        time.sleep(1.2)
        test_tcp_table(net, cli)
        time.sleep(1.2)
        test_cli_limit(net, cli)

        text = open(log, "rb").read().decode(errors="replace")
        check("rawnet: tanpa exception di log",
              not any(s in text for s in ("EXCEPTION", "#GP", "#PF", "panic", "FATAL")))
    finally:
        qemu.kill()
        qemu.wait()
        sock.close()

    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())

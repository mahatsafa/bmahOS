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

    def tcp_replies(self, dst_ip, dport, timeout):
        """Segmen TCP dari tamu ke dst_ip:dport: list (seq, ack, flags, datalen)."""
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
            seq, ack = struct.unpack("!II", f[t + 4:t + 12])
            tot = struct.unpack("!H", f[16:18])[0]
            out.append((seq, ack, f[t + 13], tot - (f[14] & 0x0F) * 4 - (f[t + 12] >> 4) * 4))

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
            if os.path.exists(log) and b"net task dimulai" in open(log, "rb").read():
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
        test_src_limit(net, cli)
        time.sleep(2.2)
        test_chal_flood(net, cli)
        time.sleep(2.2)
        test_tcp_closed(net, cli)

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

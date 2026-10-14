#!/usr/bin/env python3
"""D9: uji CLI TLS port 7780 dengan klien Python ssl (OpenSSL) sungguhan.

    tls-login.py HOST PORT KEYFILE ROKEYFILE CERTFILE

Pin = sha256 sertifikat (CERTFILE, DER), dibandingkan dengan sertifikat yang
dikirim server sebelum byte aplikasi apa pun. Mencetak "OK <nama>" atau
"GAGAL <nama>: <detail>" per uji; keluar 0 bila semua OK. Teks perintah unik
"uptime"/"metrics" hanya dikirim lewat TLS di sini; pcap-check.py memastikan
teks itu tidak terlihat di kabel port 7780.
"""

import hashlib
import hmac
import socket
import ssl
import sys
import time

AES = "ECDHE-ECDSA-AES128-GCM-SHA256"
CHACHA = "ECDHE-ECDSA-CHACHA20-POLY1305"


def tls_ctx(cipher, tls13_only=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # identitas dicek lewat pin, bukan CA
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(cipher)
    return ctx


def read_line(s, buf):
    while b"\n" not in buf[0]:
        b = s.recv(4096)
        if not b:
            raise EOFError("koneksi ditutup, sisa %r" % buf[0])
        buf[0] += b
    line, buf[0] = buf[0].split(b"\n", 1)
    return line.decode()


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    key = open(sys.argv[3], "rb").read().rstrip(b"\r\n \x00")
    rokey = open(sys.argv[4], "rb").read().rstrip(b"\r\n \x00")
    pin = hashlib.sha256(open(sys.argv[5], "rb").read()).hexdigest()
    res = []

    def run(name, fn):
        try:
            d = fn()
            res.append(d is None)
            print(("OK %s" % name) if d is None else ("GAGAL %s: %s" % (name, d)))
        except Exception as e:  # noqa: BLE001 - laporkan apa pun sebagai gagal
            res.append(False)
            print("GAGAL %s: %r" % (name, e))

    def connect(cipher, want_pin=pin):
        raw = socket.create_connection((host, port), timeout=20)
        s = tls_ctx(cipher).wrap_socket(raw)
        got = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
        if got != want_pin:
            s.close()
            raise PermissionError("pin beda: %s" % got)
        buf = [b""]
        l1, l2 = read_line(s, buf), read_line(s, buf)
        if l1 != "bmahOS login" or not l2.startswith("nonce: ") or len(l2) != 39:
            raise ValueError("banner salah: %r %r" % (l1, l2))
        return s, buf, l2[7:]

    def login(s, buf, nonce, k):
        m = hmac.new(k, (nonce + " tcp-login").encode(), hashlib.sha256).hexdigest()
        s.sendall(("login %s\n" % m).encode())
        return read_line(s, buf)

    def cmd(s, buf, nonce, n, c, k):
        m = hmac.new(k, ("%s tcp-cmd %d %s" % (nonce, n, c)).encode(),
                     hashlib.sha256).hexdigest()
        s.sendall(("%s %s\n" % (c, m)).encode())
        out = []
        while True:
            line = read_line(s, buf)
            if line.startswith("END "):
                if line != "END %d" % n:
                    raise ValueError("END salah: %r" % line)
                return out
            if line.startswith("ERR"):
                return [line]
            out.append(line)

    def t_aes():
        s, buf, nonce = connect(AES)
        if s.cipher()[0] != AES or s.version() != "TLSv1.2":
            return "suite/versi: %r %r" % (s.cipher(), s.version())
        if login(s, buf, nonce, key) != "OK login":
            return "login gagal"
        up = cmd(s, buf, nonce, 1, "uptime", key)
        if not up or not up[0].startswith("uptime: "):
            return "uptime: %r" % up
        met = cmd(s, buf, nonce, 2, "metrics", key)
        if len("\n".join(met)) < 1024 or not any(x.startswith("tcp_rx=") for x in met):
            return "metrics pendek: %d byte" % len("\n".join(met))
        st = cmd(s, buf, nonce, 3, "tls", key)
        if not any(x.startswith("pin: " + pin) for x in st) or \
           not any(x.startswith("sesi: aktif=1 maks=2 ok=") for x in st):
            return "tls: %r" % st
        if cmd(s, buf, nonce, 4, "exit", key) != ["bye"]:
            return "exit"
        s.close()
        return None

    def t_chacha():
        s, buf, nonce = connect(CHACHA)
        if s.cipher()[0] != CHACHA:
            return "suite: %r" % (s.cipher(),)
        if login(s, buf, nonce, key) != "OK login":
            return "login gagal"
        if cmd(s, buf, nonce, 1, "ping", key) != ["pong"]:
            return "ping"
        s.close()   # tanpa exit: server menutup sendiri saat idle/FIN
        return None

    def t_ro():
        s, buf, nonce = connect(AES)
        if login(s, buf, nonce, rokey) != "OK login ro":
            return "login ro gagal"
        if not cmd(s, buf, nonce, 1, "uptime", rokey)[0].startswith("uptime: "):
            return "uptime ro"
        if cmd(s, buf, nonce, 2, "pping", rokey) != ["ERR: peran read-only"]:
            return "pping ro tidak ditolak"
        s.close()
        return None

    def t_pin_wrong():
        try:
            connect(AES, want_pin="00" * 32)
        except PermissionError:
            return None
        return "pin salah diterima"

    def t_hmac_wrong():
        s, buf, nonce = connect(AES)
        r = login(s, buf, nonce, b"x" * 32)
        if r != "ERR: login gagal":
            return "balasan %r" % r
        try:
            if s.recv(100) != b"":
                return "masih ada data"
        except (ssl.SSLError, OSError):
            pass
        s.close()
        return None

    def t_tls13():
        raw = socket.create_connection((host, port), timeout=20)
        try:
            tls_ctx(None, tls13_only=True).wrap_socket(raw)
        except (ssl.SSLError, OSError):
            return None
        return "TLS 1.3 diterima"

    def t_plain():
        s = socket.create_connection((host, port), timeout=20)
        s.sendall(b"login " + b"a" * 64 + b"\n")
        try:
            d = s.recv(100)
        except OSError:
            d = b""
        s.close()
        return None if b"OK" not in d and b"bmahOS" not in d else "teks polos dilayani: %r" % d

    # Jeda: maks 2 TCB per IP dan 2 TCB 7780; sesi yang ditutup server
    # menyisakan TIME_WAIT/FIN_WAIT_2.
    tests = [("aes", t_aes), ("chacha", t_chacha), ("ro", t_ro), ("pin-salah", t_pin_wrong),
             ("hmac-salah", t_hmac_wrong), ("tls13-ditolak", t_tls13),
             ("teks-polos-ditolak", t_plain)]
    for name, fn in tests:
        run(name, fn)
        time.sleep(3)
    return 0 if all(res) else 1


if __name__ == "__main__":
    sys.exit(main())

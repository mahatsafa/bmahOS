#!/usr/bin/env python3
"""D1: uji login TCP port 7779 dengan klien socket sungguhan.

    tcp-login.py HOST PORT KEYFILE

Mencetak satu baris "OK <nama>" atau "GAGAL <nama>: <detail>" per uji;
keluar 0 bila semua OK. Uji: login benar + baris sesudahnya, hmac salah
(ERR lalu koneksi ditutup), tanpa login (ERR timeout ~10 s lalu ditutup).
"""

import hashlib
import hmac
import socket
import sys
import time


def read_line(s, buf):
    while b"\n" not in buf[0]:
        b = s.recv(4096)
        if not b:
            raise EOFError("koneksi ditutup, sisa %r" % buf[0])
        buf[0] += b
    line, buf[0] = buf[0].split(b"\n", 1)
    return line.decode()


def open_cli(host, port):
    s = socket.create_connection((host, port), timeout=15)
    buf = [b""]
    l1 = read_line(s, buf)
    l2 = read_line(s, buf)
    if l1 != "bmahOS login" or not l2.startswith("nonce: ") or len(l2) != 39:
        raise ValueError("banner salah: %r %r" % (l1, l2))
    return s, buf, l2[7:]


def closed(s, buf):
    """True bila server menutup (recv = b'') tanpa data lain."""
    try:
        return s.recv(4096) == b"" and buf[0] == b""
    except OSError:
        return False


def main():
    host, port, keyfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    key = open(keyfile, "rb").read().rstrip(b"\r\n \x00")
    res = []

    def mac(nonce):
        return hmac.new(key, (nonce + " tcp-login").encode(), hashlib.sha256).hexdigest()

    def run(name, fn):
        try:
            d = fn()
            res.append(d is None)
            print(("OK %s" % name) if d is None else ("GAGAL %s: %s" % (name, d)))
        except Exception as e:  # noqa: BLE001 - laporkan apa pun sebagai gagal
            res.append(False)
            print("GAGAL %s: %r" % (name, e))

    def t_ok():
        s, buf, nonce = open_cli(host, port)
        s.sendall(("login %s\r\n" % mac(nonce)).encode())
        r1 = read_line(s, buf)
        s.sendall(b"help\n")
        r2 = read_line(s, buf)
        s.shutdown(socket.SHUT_WR)
        eof = closed(s, buf)
        s.close()
        if (r1, r2, eof) != ("OK login", "ERR: shell belum ada (D2)", True):
            return repr((r1, r2, eof))
        return None

    def t_bad():
        s, buf, nonce = open_cli(host, port)
        s2, buf2, nonce2 = open_cli(host, port)   # nonce koneksi lain
        s2.close()
        s.sendall(("login %s\n" % mac(nonce2)).encode())
        r = read_line(s, buf)
        eof = closed(s, buf)
        s.close()
        if nonce == nonce2 or (r, eof) != ("ERR: login gagal", True):
            return repr((nonce == nonce2, r, eof))
        return None

    def t_timeout():
        s, buf, _ = open_cli(host, port)
        t0 = time.time()
        r = read_line(s, buf)
        dt = time.time() - t0
        eof = closed(s, buf)
        s.close()
        if r != "ERR: login timeout" or not eof or not 8.5 <= dt <= 13:
            return repr((r, eof, round(dt, 1)))
        return None

    run("login-benar", t_ok)
    run("login-nonce-lain", t_bad)
    run("login-timeout", t_timeout)
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""D1/D2: uji login dan shell TCP port 7779 dengan klien socket sungguhan.

    tcp-login.py HOST PORT KEYFILE

Mencetak satu baris "OK <nama>" atau "GAGAL <nama>: <detail>" per uji;
keluar 0 bila semua OK. Uji: login benar, hmac salah (ERR lalu koneksi
ditutup), tanpa login (ERR timeout ~10 s lalu ditutup); D2: perintah
bertanda tangan nomor urut (ping, pping, metrics > 1024 byte), baris yang
diulang ditolak + ditutup, exit menutup koneksi.
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

    def cmd(nonce, n, c):
        m = hmac.new(key, ("%s tcp-cmd %d %s" % (nonce, n, c)).encode(),
                     hashlib.sha256).hexdigest()
        return ("%s %s\n" % (c, m)).encode()

    def reply(s, buf, n):
        """Baris balasan sampai "END <n>" (tidak termasuk)."""
        out = []
        while True:
            line = read_line(s, buf)
            if line == "END %d" % n:
                return out
            out.append(line)

    def login(s, buf, nonce):
        s.sendall(("login %s\r\n" % mac(nonce)).encode())
        return read_line(s, buf)

    def t_ok():
        s, buf, nonce = open_cli(host, port)
        r1 = login(s, buf, nonce)
        s.shutdown(socket.SHUT_WR)
        eof = closed(s, buf)
        s.close()
        if (r1, eof) != ("OK login", True):
            return repr((r1, eof))
        return None

    def t_shell():
        s, buf, nonce = open_cli(host, port)
        if login(s, buf, nonce) != "OK login":
            return "login gagal"
        s.sendall(cmd(nonce, 1, "ping"))
        r1 = reply(s, buf, 1)
        s.sendall(cmd(nonce, 2, "pping"))
        r2 = reply(s, buf, 2)
        s.sendall(cmd(nonce, 3, "metrics"))
        r3 = reply(s, buf, 3)
        size = sum(len(x) + 1 for x in r3)
        # Baris perintah 3 dikirim ulang: nomor urut sudah 4 -> ditolak.
        s.sendall(cmd(nonce, 3, "metrics"))
        r4 = read_line(s, buf)
        eof = closed(s, buf)
        s.close()
        if (r1, r2, r4, eof) != (["pong"], ["ppong"], "ERR: hmac salah", True):
            return repr((r1, r2, r4, eof))
        if size <= 1024 or not any(x.startswith("ktimer_cancelled=") for x in r3):
            return "metrics tidak utuh: %d byte, akhir %r" % (size, r3[-1:])
        print("info metrics lewat TCP: %d byte" % size)
        return None

    def t_exit():
        time.sleep(2.5)   # TIME_WAIT (2 s) uji sebelumnya habis dulu
        s, buf, nonce = open_cli(host, port)
        if login(s, buf, nonce) != "OK login":
            return "login gagal"
        s.sendall(cmd(nonce, 1, "uptime"))
        r1 = reply(s, buf, 1)
        s.sendall(cmd(nonce, 2, "exit"))
        r2 = reply(s, buf, 2)
        eof = closed(s, buf)
        s.close()
        if len(r1) != 1 or not r1[0].startswith("uptime: ") or (r2, eof) != (["bye"], True):
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
        time.sleep(2.5)   # TIME_WAIT (2 s) uji sebelumnya habis dulu
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
    run("shell-perintah", t_shell)
    run("shell-exit", t_exit)
    run("login-timeout", t_timeout)
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    main()

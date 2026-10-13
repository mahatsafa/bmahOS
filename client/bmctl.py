#!/usr/bin/env python3
"""bmctl: klien perintah jarak jauh bmahOS (UDP 7778 / TCP 7779, HMAC-SHA256).

Hanya pustaka standar Python 3, jalan di Windows dan Linux.

Contoh:
    python bmctl.py --key ~/bmahos-key.txt uptime
    python bmctl.py --key key.txt metrics
    python bmctl.py --key key.txt pping
    python bmctl.py --key key.txt reboot
    python bmctl.py --tcp --key key.txt uptime metrics   (satu sesi TCP)
    python bmctl.py --tcp --key key.txt                  (interaktif)

Semua perintah memakai jalur nonce: kirim "CHAL", terima "nonce: <32 hex>",
lalu kirim "<nonce> <perintah> <hmac>". hmac = HMAC-SHA256 atas teks sebelum
spasi terakhir. Nonce sekali pakai dan hilang saat reboot, jadi datagram
rekaman tidak bisa diputar ulang.

--counter memakai jalur lama "<counter> <perintah> <hmac>" (counter = waktu
Unix dalam milidetik), hanya diterima build LEGACYCTR=1 dan tanpa pping/reboot.

--tcp memakai shell TCP 7779 (D2, lihat PROTOCOL.md): login dengan nonce
koneksi, lalu tiap perintah "<perintah> <hmac>" dengan hmac atas
"<nonce> tcp-cmd <n> <perintah>" (n = 1, 2, ... per koneksi); keluaran
berakhir di "END <n>". Tanpa perintah: mode interaktif (prompt bila stdin
terminal, "exit" atau EOF menutup). Kode keluar: 0 OK, 1 ada ERR atau server
menutup, 2 koneksi/timeout.

Kunci dibaca dari file (sama dengan KEY.TXT di disk bmahOS); spasi/CR/LF/NUL
di akhir file dibuang, sama seperti yang dilakukan kernel.
"""

import argparse
import hashlib
import hmac
import os
import socket
import sys
import time

DEFAULT_HOST = "192.168.50.200"
DEFAULT_PORT = 7778
DEFAULT_TCP_PORT = 7779
CMD_MAX = 64   # panjang perintah maks di shell TCP (kernel/auth.c)

READ_CMDS = ("help", "ping", "uptime", "mem", "log", "irq", "stats",
             "metrics", "mac", "ip", "tasks")
PRIV_CMDS = ("pping", "reboot")


def load_key(path):
    with open(os.path.expanduser(path), "rb") as f:
        key = f.read().rstrip(b"\r\n \x00")
    if not 16 <= len(key) <= 64:
        sys.exit("bmctl: panjang kunci harus 16..64 byte (sekarang %d)" % len(key))
    return key


def sign(key, msg):
    mac = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
    return "%s %s" % (msg, mac)


def exchange(sock, addr, text):
    sock.sendto(text.encode(), addr)
    data, _ = sock.recvfrom(4096)
    return data.decode(errors="replace")


class TcpSession:
    """Satu koneksi shell TCP 7779 yang sudah login."""

    def __init__(self, host, port, key, timeout):
        self.key = key
        self.seq = 0
        self.buf = b""
        self.sock = socket.create_connection((host, port), timeout=timeout)
        l1 = self.readline()
        l2 = self.readline()
        if l1 != "bmahOS login" or not l2.startswith("nonce: ") or len(l2) != 39:
            raise ConnectionError("banner tidak dikenal: %r %r" % (l1, l2))
        self.nonce = l2[len("nonce: "):]
        self.send_line("login " + hmac.new(key, (self.nonce + " tcp-login").encode(),
                                           hashlib.sha256).hexdigest())
        self.login_reply = self.readline()

    def readline(self):
        """Satu baris tanpa LF, atau None bila server menutup koneksi."""
        while b"\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                return None
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace")

    def send_line(self, text):
        self.sock.sendall((text + "\n").encode())

    def command(self, cmd):
        """Return (baris keluaran, ok). ok = False bila server menutup
        sebelum END <n> (perintah ditolak) atau keluaran berisi ERR."""
        self.seq += 1
        mac = hmac.new(self.key, ("%s tcp-cmd %d %s" % (self.nonce, self.seq, cmd)).encode(),
                       hashlib.sha256).hexdigest()
        self.send_line("%s %s" % (cmd, mac))
        out = []
        while True:
            line = self.readline()
            if line is None:
                return out + ["bmctl: koneksi ditutup server"], False
            if line == "END %d" % self.seq:
                return out, not any(x.startswith("ERR") for x in out)
            out.append(line)

    def close(self):
        self.sock.close()


def check_cmd(cmd):
    if not 1 <= len(cmd.encode()) <= CMD_MAX or cmd != cmd.strip() or "\n" in cmd:
        return "bmctl: perintah harus 1..%d byte tanpa spasi di awal/akhir" % CMD_MAX
    return None


def run_tcp(args):
    key = load_key(args.key)
    port = args.port or int(os.environ.get("BMAHOS_TCP_PORT", DEFAULT_TCP_PORT))
    for c in args.command:
        err = check_cmd(c)
        if err:
            sys.stderr.write(err + "\n")
            return 2
    try:
        sess = TcpSession(args.host, port, key, args.timeout)
    except (OSError, ConnectionError) as e:
        sys.stderr.write("bmctl: gagal terhubung ke %s:%d: %s\n" % (args.host, port, e))
        return 2
    rc = 0
    try:
        if sess.login_reply != "OK login":
            sys.stdout.write("%s\n" % (sess.login_reply or "bmctl: koneksi ditutup server"))
            return 1
        interactive = not args.command
        tty = interactive and sys.stdin.isatty()
        cmds = iter(args.command) if not interactive else None
        while True:
            if interactive:
                if tty:
                    try:
                        cmd = input("bmahOS> ")
                    except EOFError:
                        cmd = None
                else:
                    cmd = sys.stdin.readline() or None
                if cmd is None:
                    cmd = "exit"
                else:
                    cmd = cmd.strip()
                    if not cmd:
                        continue
                    err = check_cmd(cmd)
                    if err:
                        sys.stderr.write(err + "\n")
                        rc = 1
                        continue
            else:
                cmd = next(cmds, "exit")
            out, ok = sess.command(cmd)
            for line in out:
                sys.stdout.write(line + "\n")
            sys.stdout.flush()
            if not ok:
                rc = 1
                if out and out[-1] == "bmctl: koneksi ditutup server":
                    break
            # reboot: server reboot setelah balasan di-ACK, tidak ada exit.
            if cmd in ("exit", "reboot"):
                break
    except socket.timeout:
        sys.stderr.write("bmctl: tidak ada balasan dari %s:%d (%.1f s)\n"
                         % (args.host, port, args.timeout))
        return 2
    except OSError as e:
        sys.stderr.write("bmctl: koneksi gagal: %s\n" % e)
        return 2
    finally:
        sess.close()
    return rc


def run(args):
    if args.tcp:
        return run_tcp(args)
    if len(args.command) != 1:
        sys.stderr.write("bmctl: jalur UDP butuh tepat satu perintah (pakai --tcp untuk sesi)\n")
        return 2
    args.command = args.command[0]
    if args.port is None:
        args.port = int(os.environ.get("BMAHOS_PORT", DEFAULT_PORT))
    key = load_key(args.key)
    addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    try:
        if args.counter:
            counter = int(time.time() * 1000)
            reply = exchange(sock, addr, sign(key, "%d %s" % (counter, args.command)))
        else:
            reply = exchange(sock, addr, "CHAL")
            if not reply.startswith("nonce: "):
                sys.stdout.write(reply)
                return 1
            nonce = reply[len("nonce: "):].strip()
            reply = exchange(sock, addr, sign(key, "%s %s" % (nonce, args.command)))
    except socket.timeout:
        sys.stderr.write("bmctl: tidak ada balasan dari %s:%d (%.1f s)\n"
                         % (args.host, args.port, args.timeout))
        return 2
    finally:
        sock.close()

    sys.stdout.write(reply if reply.endswith("\n") else reply + "\n")
    return 1 if reply.startswith("ERR") else 0


def main():
    p = argparse.ArgumentParser(
        description="Klien perintah jarak jauh bmahOS (UDP/TCP, HMAC-SHA256).",
        epilog="Perintah baca: %s. Berprivilege: %s. TCP: juga exit."
               % (" ".join(READ_CMDS), " ".join(PRIV_CMDS)))
    p.add_argument("command", nargs="*",
                   help="perintah (UDP: tepat satu; --tcp: nol = interaktif, "
                        "beberapa = dijalankan berurutan dalam satu sesi)")
    p.add_argument("--tcp", action="store_true",
                   help="shell TCP port 7779 (login + perintah bertanda tangan nomor urut)")
    p.add_argument("--key", required=True, help="file kunci (isi sama dengan KEY.TXT)")
    p.add_argument("--host", default=os.environ.get("BMAHOS_HOST", DEFAULT_HOST),
                   help="alamat bmahOS (default %s atau $BMAHOS_HOST)" % DEFAULT_HOST)
    p.add_argument("--port", type=int, default=None,
                   help="port (default UDP %d atau $BMAHOS_PORT; TCP %d atau "
                        "$BMAHOS_TCP_PORT)" % (DEFAULT_PORT, DEFAULT_TCP_PORT))
    p.add_argument("--counter", action="store_true",
                   help="jalur counter lama (hanya build LEGACYCTR=1)")
    p.add_argument("--priv", action="store_true",
                   help="tidak diperlukan lagi (semua perintah lewat CHAL); diabaikan")
    p.add_argument("--timeout", type=float, default=None,
                   help="detik per balasan (default UDP 3, TCP 10)")
    args = p.parse_args()
    if args.timeout is None:
        args.timeout = 10.0 if args.tcp else 3.0
    return run(args)


if __name__ == "__main__":
    sys.exit(main())

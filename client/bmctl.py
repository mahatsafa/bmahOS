#!/usr/bin/env python3
"""bmctl: klien perintah jarak jauh bmahOS (UDP 7778, HMAC-SHA256).

Hanya pustaka standar Python 3, jalan di Windows dan Linux.

Contoh:
    python bmctl.py --key ~/bmahos-key.txt uptime
    python bmctl.py --key key.txt metrics
    python bmctl.py --key key.txt pping
    python bmctl.py --key key.txt reboot

Semua perintah memakai jalur nonce: kirim "CHAL", terima "nonce: <32 hex>",
lalu kirim "<nonce> <perintah> <hmac>". hmac = HMAC-SHA256 atas teks sebelum
spasi terakhir. Nonce sekali pakai dan hilang saat reboot, jadi datagram
rekaman tidak bisa diputar ulang.

--counter memakai jalur lama "<counter> <perintah> <hmac>" (counter = waktu
Unix dalam milidetik), hanya diterima build LEGACYCTR=1 dan tanpa pping/reboot.

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


def run(args):
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
        description="Klien perintah jarak jauh bmahOS (UDP, HMAC-SHA256).",
        epilog="Perintah baca: %s. Berprivilege: %s."
               % (" ".join(READ_CMDS), " ".join(PRIV_CMDS)))
    p.add_argument("command", help="perintah yang dikirim")
    p.add_argument("--key", required=True, help="file kunci (isi sama dengan KEY.TXT)")
    p.add_argument("--host", default=os.environ.get("BMAHOS_HOST", DEFAULT_HOST),
                   help="alamat bmahOS (default %s atau $BMAHOS_HOST)" % DEFAULT_HOST)
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("BMAHOS_PORT", DEFAULT_PORT)),
                   help="port UDP (default %d atau $BMAHOS_PORT)" % DEFAULT_PORT)
    p.add_argument("--counter", action="store_true",
                   help="jalur counter lama (hanya build LEGACYCTR=1)")
    p.add_argument("--priv", action="store_true",
                   help="tidak diperlukan lagi (semua perintah lewat CHAL); diabaikan")
    p.add_argument("--timeout", type=float, default=3.0, help="detik (default 3)")
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())

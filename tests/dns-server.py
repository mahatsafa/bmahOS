#!/usr/bin/env python3
"""P3-3: server DNS uji (UDP, pustaka standar saja).

Pakai: dns-server.py HOST PORT [DURASI_DETIK]
Menjawab query A/IN: bmahos.uji -> 192.168.50.123 (TTL 60), nama lain NXDOMAIN.
Pertanyaan dipantulkan apa adanya, answer memakai pointer 0xC00C. Dipakai
qemu-smoke (lewat slirp: tamu ke 192.168.50.1:PORT = 127.0.0.1:PORT di host).
"""

import socket
import struct
import sys
import time

TABLE = {"bmahos.uji": bytes([192, 168, 50, 123])}


def qname(d, off):
    labels = []
    while off < len(d) and d[off] != 0:
        n = d[off]
        labels.append(d[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels).lower(), off + 1


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    dur = float(sys.argv[3]) if len(sys.argv) > 3 else 60
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    s.settimeout(0.5)
    end = time.time() + dur
    while time.time() < end:
        try:
            d, a = s.recvfrom(512)
        except socket.timeout:
            continue
        if len(d) < 17 or struct.unpack("!H", d[4:6])[0] != 1:
            continue
        name, off = qname(d, 12)
        question = d[12:off + 4]
        ip = TABLE.get(name)
        flags = 0x8180 if ip else 0x8183
        hdr = d[0:2] + struct.pack("!HHHHH", flags, 1, 1 if ip else 0, 0, 0)
        rep = hdr + question
        if ip:
            rep += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip
        s.sendto(rep, a)
        print("dns-server: %s -> %s" % (name, ".".join(map(str, ip)) if ip else "NXDOMAIN"),
              flush=True)


if __name__ == "__main__":
    main()

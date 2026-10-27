#!/usr/bin/env python3
"""P3-2: server SNTP uji (UDP, pustaka standar saja).

Pakai: sntp-server.py HOST PORT [GESER_DETIK] [DURASI_DETIK]
Membalas permintaan mode 3 (klien) dengan mode 4, stratum 2, originate =
transmit klien, transmit = jam host + GESER. Dipakai qemu-smoke (lewat slirp:
tamu ke 192.168.50.1:PORT = 127.0.0.1:PORT di host) dan uji VMware (bind ke
192.168.50.1 di Windows).
"""

import socket
import struct
import sys
import time

NTP_DELTA = 2208988800


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    shift = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    dur = float(sys.argv[4]) if len(sys.argv) > 4 else 60
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, port))
    s.settimeout(0.5)
    end = time.time() + dur
    n = 0
    while time.time() < end:
        try:
            d, a = s.recvfrom(512)
        except socket.timeout:
            continue
        if len(d) < 48 or d[0] & 7 != 3:
            continue
        now = time.time() + shift
        ts = struct.pack("!II", int(now) + NTP_DELTA, int((now % 1) * 2 ** 32))
        rep = (bytes([0x24, 2, 6, 0xEC]) + b"\0" * 8 + b"LOCL" + ts + d[40:48] + ts + ts)
        s.sendto(rep, a)
        n += 1
        print("sntp-server: balas %s:%d" % a, flush=True)
    print("sntp-server: selesai, %d balasan" % n, flush=True)


if __name__ == "__main__":
    main()

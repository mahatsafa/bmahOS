#!/usr/bin/env python3
"""soak: beban berulang + pencatat metrik bmahOS untuk soak test R8.

Hanya pustaka standar Python 3 + bmctl.py (folder yang sama). Jalan di
Windows (VMware, 24 jam) dan Linux (pra-uji QEMU lewat hostfwd slirp).

Contoh:
    python soak.py --key key.txt --pin tlspin.txt --keluar D:\\soak-R8
    python soak.py --key K --pin P --host 127.0.0.1 --udp 17778 --echo 17007 \\
        --cli 17779 --tls 17780 --udp-echo 17777 --tanpa-ping --durasi 3600

Satu proses, langkah berurutan. Paling banyak 2 koneksi TCP sekaligus
(batas kernel 2 TCB per IP; Windows hanya punya satu IP). Setiap --interval
detik beban jeda dan satu sesi shell 7779 mengambil `metrics` (semua halaman),
`mem`, `wd`, `tls`, `uptime` -> satu baris JSON di metrik.jsonl. Langkah beban
yang gagal -> klien.jsonl. status.json diperbarui tiap sampel. Setelah
--durasi: beban berhenti, jeda --tenang detik, lalu sampel "akhir".

Beban per putaran (lihat docs/soak-R8.md):
  echo     3 koneksi TCP 7 x 8 KB acak, isi balasan dicek SHA-256
  shell    2 sesi 7779: uptime, mem, metrics (halaman 1), exit
  tls      1 sesi 7780: handshake + pin + login + uptime + exit
  udp      5x CHAL + uptime bertanda tangan (UDP 7778)
  uecho    10 datagram UDP 7777 (di bawah batas 20/s per IP)
  ping     10 ICMP (ping.exe / ping), dilewati dengan --tanpa-ping
  banjir   200 datagram UDP 7777 secepatnya (sengaja melewati batas laju)
  tolak    koneksi TCP ke-3 serentak (harus ditolak), login HMAC salah
  diam     tiap 5 putaran: sesi 7779 tanpa login, server harus menutup (10 s)
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bmctl  # noqa: E402

TW_WAIT = 2.5   # TIME_WAIT server 2 s ikut dihitung batas 2 TCB per IP


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def keep_awake():
    """Windows: tahan sleep selama proses hidup (tanpa mengubah pengaturan daya)."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000000 | 0x00000001)
    except Exception as e:  # pragma: no cover
        print("soak: SetThreadExecutionState gagal: %s" % e)


class Soak:
    def __init__(self, a):
        self.a = a
        self.key = bmctl.load_key(a.key)
        self.pin = bmctl.load_pin(a.pin) if a.pin else None
        os.makedirs(a.keluar, exist_ok=True)
        self.f_met = open(os.path.join(a.keluar, "metrik.jsonl"), "a", buffering=1)
        self.f_kli = open(os.path.join(a.keluar, "klien.jsonl"), "a", buffering=1)
        self.t0 = time.time()
        self.stat = {}        # langkah -> {"ok": n, "gagal": n}
        self.info = {}        # angka tambahan (balasan banjir dsb.)
        self.putaran = 0
        self.last_uptime = None

    # --- pencatatan ---
    def rel(self):
        return round(time.time() - self.t0, 1)

    def hasil(self, langkah, ok, pesan=""):
        s = self.stat.setdefault(langkah, {"ok": 0, "gagal": 0})
        s["ok" if ok else "gagal"] += 1
        if not ok:
            rec = {"waktu": now_iso(), "t": self.rel(), "putaran": self.putaran,
                   "langkah": langkah, "pesan": str(pesan)[:300]}
            self.f_kli.write(json.dumps(rec) + "\n")
            print("  GAGAL %s: %s" % (langkah, pesan))

    def jalan(self, langkah, fn):
        try:
            r = fn()
        except Exception as e:
            self.hasil(langkah, False, "%s: %s" % (type(e).__name__, e))
            return None
        if r is True or r is None:
            self.hasil(langkah, True)
        else:
            self.hasil(langkah, False, r)
        return r

    # --- langkah beban ---
    def echo_one(self, n=8192):
        data = os.urandom(n)
        s = socket.create_connection((self.a.host, self.a.echo), timeout=self.a.timeout)
        try:
            s.sendall(data)
            got = b""
            while len(got) < n:
                d = s.recv(65536)
                if not d:
                    return "server menutup setelah %d/%d byte" % (len(got), n)
                got += d
            s.shutdown(socket.SHUT_WR)
            while s.recv(4096):
                pass
        finally:
            s.close()
        if hashlib.sha256(got[:n]).digest() != hashlib.sha256(data).digest():
            return "isi echo beda (sha256)"
        return True

    def session(self, port, pin, cmds):
        sess = bmctl.TcpSession(self.a.host, port, self.key, self.a.timeout, pin)
        try:
            if sess.login_reply not in ("OK login", "OK login ro"):
                return None, "login: %r" % sess.login_reply
            outs = {}
            for c in cmds:
                out, ok = sess.command(c)
                if not ok:
                    return None, "%s: %s" % (c, " | ".join(out[-2:]))
                outs[c] = out
            out, ok = sess.command("exit")
            return outs, None
        finally:
            sess.close()

    def shell(self):
        _, err = self.session(self.a.cli, None, ["uptime", "mem", "metrics"])
        time.sleep(TW_WAIT)
        return err or True

    def tls(self):
        _, err = self.session(self.a.tls, self.pin, ["uptime"])
        time.sleep(TW_WAIT)
        return err or True

    def udp_cmd(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        addr = (self.a.host, self.a.udp)
        try:
            r = bmctl.exchange(sock, addr, "CHAL")
            if not r.startswith("nonce: "):
                return "CHAL: %r" % r[:80]
            nonce = r[len("nonce: "):].strip()
            r = bmctl.exchange(sock, addr, bmctl.sign(self.key, "%s uptime" % nonce))
            if r.startswith("ERR"):
                return "uptime: %r" % r[:80]
            return True
        finally:
            sock.close()

    def udp_echo(self, n, gap, wait=2.0):
        """Kirim n datagram (jeda gap), kembalikan jumlah balasan sah."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        addr = (self.a.host, self.a.udp_echo)
        tag = os.urandom(4).hex()
        sent = set()
        try:
            sock.setblocking(False)
            got = set()
            for i in range(n):
                msg = ("soak %s %d" % (tag, i)).encode()
                sent.add(msg)
                sock.sendto(msg, addr)
                if gap:
                    time.sleep(gap)
                got |= self._drain(sock, sent, 0)
            got |= self._drain(sock, sent, wait)
            return len(got)
        finally:
            sock.close()

    @staticmethod
    def _drain(sock, sent, wait):
        got = set()
        end = time.time() + wait
        while True:
            try:
                d, _ = sock.recvfrom(4096)
                if d in sent:
                    got.add(d)
                continue
            except (BlockingIOError, InterruptedError):
                pass
            except OSError:   # Windows: ICMP port unreachable -> WSAECONNRESET
                pass
            if time.time() >= end:
                return got
            time.sleep(0.02)

    def uecho(self):
        n = self.udp_echo(10, 0.1)
        return True if n == 10 else "balasan %d/10" % n

    def banjir(self):
        n = self.udp_echo(200, 0)
        self.info["banjir_balas_min"] = min(self.info.get("banjir_balas_min", n), n)
        self.info["banjir_balas_maks"] = max(self.info.get("banjir_balas_maks", n), n)
        time.sleep(1.5)   # jendela batas laju per IP bersih lagi
        return True if n > 0 else "banjir: 0 balasan (net task macet?)"

    def ping(self):
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "10", "-w", "1000", self.a.host]
        else:
            cmd = ["ping", "-c", "10", "-i", "0.5", "-W", "1", self.a.host]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=60)
        txt = r.stdout.decode(errors="replace")
        m = re.search(r"Received = (\d+)|(\d+) (?:packets )?received", txt)
        n = int(m.group(1) or m.group(2)) if m else -1
        return True if n >= 9 else "ping balasan %d/10" % n

    def tolak(self):
        """2 koneksi echo terbuka -> koneksi ke-3 harus ditolak (tcp_src_full)."""
        held = []
        try:
            for _ in range(2):
                held.append(socket.create_connection((self.a.host, self.a.echo),
                                                     timeout=self.a.timeout))
            # Pastikan keduanya ESTABLISHED di server (echo 1 byte).
            for s in held:
                s.sendall(b"x")
                if s.recv(16) != b"x":
                    return "echo 1 byte gagal"
            return self.ke3_ditolak()
        finally:
            for s in held:
                s.close()
            time.sleep(TW_WAIT)

    def ke3_ditolak(self):
        """VMware: connect() langsung ditolak (RST). Hostfwd slirp (QEMU)
        menerima connect() di host lalu menutupnya saat bmahOS mengirim RST,
        jadi echo 1 byte yang tidak kembali juga berarti ditolak."""
        try:
            c = socket.create_connection((self.a.host, self.a.echo), timeout=10)
        except (ConnectionRefusedError, ConnectionResetError):
            return True
        except socket.timeout:
            return "koneksi ke-3 timeout (harus RST)"
        try:
            c.settimeout(5)
            c.sendall(b"x")
            if c.recv(16) == b"x":
                return "koneksi ke-3 diterima (harus ditolak)"
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return True
        except socket.timeout:
            return "koneksi ke-3 tanpa echo dan tanpa tutup"
        finally:
            c.close()

    def login_salah(self):
        s = socket.create_connection((self.a.host, self.a.cli), timeout=self.a.timeout)
        try:
            buf = b""
            while buf.count(b"\n") < 2:
                d = s.recv(4096)
                if not d:
                    return "server menutup sebelum banner"
                buf += d
            s.sendall(b"login " + b"0" * 64 + b"\n")
            while True:
                d = s.recv(4096)
                if not d:
                    break
                buf += d
            if b"ERR" not in buf.split(b"\n", 2)[2]:
                return "tanpa ERR: %r" % buf[-60:]
        finally:
            s.close()
        time.sleep(TW_WAIT)
        return True

    def diam(self):
        """Sesi tanpa login: server harus menutup (timeout login 10 s)."""
        s = socket.create_connection((self.a.host, self.a.cli), timeout=30)
        t = time.time()
        try:
            while s.recv(4096):
                pass
        finally:
            s.close()
        dt = time.time() - t
        time.sleep(TW_WAIT)
        return True if 8 <= dt <= 20 else "ditutup setelah %.1f s (harus ~10 s)" % dt

    def putaran_beban(self):
        self.putaran += 1
        for _ in range(3):
            self.jalan("echo", self.echo_one)
        for _ in range(2):
            self.jalan("shell", self.shell)
        if self.pin:
            self.jalan("tls", self.tls)
        for _ in range(5):
            self.jalan("udp", self.udp_cmd)
            time.sleep(0.3)
        self.jalan("uecho", self.uecho)
        if not self.a.tanpa_ping:
            self.jalan("ping", self.ping)
        self.jalan("banjir", self.banjir)
        self.jalan("tolak", self.tolak)
        self.jalan("login_salah", self.login_salah)
        if self.putaran % 5 == 0:
            self.jalan("diam", self.diam)

    # --- sampel metrik ---
    def sampel(self, jenis):
        time.sleep(3)
        rec = {"waktu": now_iso(), "t": self.rel(), "jenis": jenis, "putaran": self.putaran}
        sess = bmctl.TcpSession(self.a.host, self.a.cli, self.key, self.a.timeout)
        try:
            if sess.login_reply != "OK login":
                raise ConnectionError("login sampel: %r" % sess.login_reply)
            out, ok = bmctl.metrics_pages("metrics", sess.command)
            if not ok:
                raise ConnectionError("metrics: %r" % out[-2:])
            m = {}
            for line in out:
                k, sep, v = line.partition("=")
                if sep and re.fullmatch(r"-?\d+", v):
                    m[k] = int(v)
            for c in ("mem", "wd", "tls", "config"):
                o, ok = sess.command(c)
                rec[c] = o
            mm = re.search(r"pmm bebas: (\d+) frame", "\n".join(rec["mem"]))
            if mm:
                m["pmm_bebas_frame"] = int(mm.group(1))
            rec["m"] = m
            sess.command("exit")
        finally:
            sess.close()
        up = rec["m"].get("uptime_ticks")
        if up is not None and self.last_uptime is not None and up < self.last_uptime:
            self.hasil("reboot", False, "uptime_ticks turun %d -> %d" % (self.last_uptime, up))
        self.last_uptime = up
        self.f_met.write(json.dumps(rec) + "\n")
        st = {"waktu": now_iso(), "t": self.rel(), "putaran": self.putaran,
              "langkah": self.stat, "info": self.info, "sampel_terakhir": jenis,
              "uptime_ticks": up}
        with open(os.path.join(self.a.keluar, "status.json"), "w") as f:
            json.dump(st, f, indent=1)
        m = rec["m"]
        print("%s sampel %s t=%d s putaran=%d frame_bebas=%s heap=%s pmm_netto=%s wd_gap_max=%s"
              % (rec["waktu"], jenis, rec["t"], self.putaran, m.get("pmm_bebas_frame"),
                 m.get("heap_used"), m.get("pmm_alloc", 0) - m.get("pmm_free", 0),
                 m.get("wd_gap_max")))
        time.sleep(TW_WAIT)

    def sampel_aman(self, jenis):
        for i in range(3):
            try:
                self.sampel(jenis)
                return
            except Exception as e:
                self.hasil("sampel", False, "%s: %s" % (type(e).__name__, e))
                time.sleep(10)

    def run(self):
        a = self.a
        keep_awake()
        print("soak: mulai %s, durasi %d s, sampel tiap %d s, keluar %s"
              % (now_iso(), a.durasi, a.interval, a.keluar))
        self.sampel_aman("awal")
        next_s = time.time() + a.interval
        end = self.t0 + a.durasi
        while time.time() < end:
            t = time.time()
            self.putaran_beban()
            if time.time() >= next_s:
                self.sampel_aman("berkala")
                next_s += a.interval
            rest = a.putaran - (time.time() - t)
            if rest > 0:
                time.sleep(min(rest, max(0, end - time.time())))
        print("soak: beban berhenti, tenang %d s" % a.tenang)
        time.sleep(a.tenang)
        self.sampel_aman("akhir")
        print("soak: selesai %s, putaran %d" % (now_iso(), self.putaran))
        print(json.dumps(self.stat))
        return 0 if all(s["gagal"] == 0 for s in self.stat.values()) else 1


def main():
    sys.stdout.reconfigure(line_buffering=True)   # log ke file langsung terbaca
    p = argparse.ArgumentParser(description="Soak test R8 bmahOS (beban + metrik).")
    p.add_argument("--key", required=True, help="file kunci admin (isi KEY.TXT)")
    p.add_argument("--pin", default=None, help="pin TLS (64 hex atau file); tanpa = lewati TLS")
    p.add_argument("--host", default=bmctl.DEFAULT_HOST)
    p.add_argument("--udp", type=int, default=7778)
    p.add_argument("--udp-echo", type=int, default=7777)
    p.add_argument("--echo", type=int, default=7)
    p.add_argument("--cli", type=int, default=7779)
    p.add_argument("--tls", type=int, default=7780)
    p.add_argument("--durasi", type=int, default=86400, help="detik beban (bawaan 24 jam)")
    p.add_argument("--interval", type=int, default=600, help="detik antar sampel")
    p.add_argument("--putaran", type=float, default=60, help="detik per putaran (0 = keras)")
    p.add_argument("--tenang", type=int, default=40, help="jeda sebelum sampel akhir")
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--tanpa-ping", action="store_true")
    p.add_argument("--keluar", default="soak-R8", help="folder hasil")
    return Soak(p.parse_args()).run()


if __name__ == "__main__":
    sys.exit(main())

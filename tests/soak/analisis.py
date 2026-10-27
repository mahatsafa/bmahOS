#!/usr/bin/env python3
"""R8: analisis hasil client/soak.py -> laporan Markdown + putusan.

Pakai: analisis.py DIR [--serial serial.log] [--pemanasan 3600]
DIR berisi metrik.jsonl dan klien.jsonl. Basis = sampel pertama dengan
t >= pemanasan; akhir = sampel "akhir" (beban sudah berhenti). Kode keluar
0 = semua kriteria lulus, 1 = ada yang gagal, 2 = data kurang.
"""

import argparse
import json
import os
import re
import sys

FAULT = re.compile(r"Exception|#GP|#PF|fault|panic|ERROR|FATAL|WARNING", re.I)

# Kolom tren: (judul, fungsi atas dict metrik)
TREN = (
    ("frame_bebas", lambda m: m.get("pmm_bebas_frame")),
    ("heap_used", lambda m: m.get("heap_used")),
    ("pmm_netto", lambda m: m["pmm_alloc"] - m["pmm_free"]),
    ("kmalloc_netto", lambda m: m["kmalloc"] - m["kfree"]),
    ("tcp_conn_open", lambda m: m.get("tcp_conn_open")),
    ("cli_login_ok", lambda m: m.get("cli_login_ok")),
    ("tls_hs_ok", lambda m: m.get("tls_hs_ok")),
    ("udp_src_dropped", lambda m: m.get("udp_src_dropped")),
    ("wd_gap_max", lambda m: m.get("wd_gap_max")),
    ("stack_net_used", lambda m: m.get("stack_net_used")),
)

INFO = ("tcp_conn_open", "tcp_close_ok", "tcp_timeout", "tcp_retx", "tcp_retx_giveup",
        "tcp_src_full", "tcp_conn_dropped", "tcp_rst_sent", "tcp_rx_bytes", "tcp_tx_bytes",
        "cli_login_ok", "cli_login_fail", "cli_login_timeout", "cli_cmd_ok", "cli_cmd_fail",
        "tls_hs_ok", "tls_fail", "tls_full", "udp_echo", "udp_src_dropped", "udp_dropped",
        "icmp_reply", "priv_ok", "priv_chal", "rx_frames", "rx_missed", "rx_nobuf",
        "log_serial_muted", "logdisk_written", "logdisk_lost", "ktimer_late_max",
        "cpu_busy_pct", "audit_seq")


def load(path):
    out = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("dir")
    p.add_argument("--serial", default=None)
    p.add_argument("--pemanasan", type=float, default=3600)
    a = p.parse_args()

    met = [r for r in load(os.path.join(a.dir, "metrik.jsonl")) if "m" in r]
    kli = load(os.path.join(a.dir, "klien.jsonl"))
    if len(met) < 3:
        print("data kurang: %d sampel" % len(met))
        return 2
    awal = met[0]
    akhir = [r for r in met if r["jenis"] == "akhir"]
    if not akhir:
        print("tidak ada sampel akhir (soak belum selesai?)")
        return 2
    akhir = akhir[-1]
    basis = next((r for r in met if r["t"] >= a.pemanasan and r["jenis"] == "berkala"), None)
    if basis is None:
        print("tidak ada sampel setelah pemanasan %d s" % a.pemanasan)
        return 2
    ma, mb, mz = awal["m"], basis["m"], akhir["m"]

    hasil = []

    def krit(nama, ok, rinci):
        hasil.append((nama, ok, rinci))

    # 1. Tanpa reboot: uptime naik, sejalan dengan jam dinding.
    naik = all(y["m"]["uptime_ticks"] > x["m"]["uptime_ticks"] for x, y in zip(met, met[1:]))
    dw = akhir["t"] - awal["t"]
    dt = (mz["uptime_ticks"] - ma["uptime_ticks"]) / 100.0
    krit("uptime naik terus", naik, "%d sampel" % len(met))
    krit("uptime ~ jam dinding", 0.9 <= dt / dw <= 1.1 if dw else False,
         "uptime +%.0f s, jam dinding +%.0f s" % (dt, dw))
    if a.serial:
        with open(a.serial, errors="replace") as f:
            ser = f.read().splitlines()
        pci = sum(1 for l in ser if "PCI-1:" in l)
        pan = [l for l in ser if "PANIC" in l]
        flt = [l for l in ser if FAULT.search(l)]
        krit("serial: PCI-1 = 2 (satu boot)", pci == 2, "PCI-1 %d baris" % pci)
        krit("serial: tanpa PANIC", not pan, "%d baris" % len(pan))
        krit("serial: grep fault 0", not flt,
             "%d baris%s" % (len(flt), (": " + " | ".join(flt[:3])) if flt else ""))

    # 2. Memori kembali ke basis.
    for nama, fn in TREN[:4]:
        b, z = fn(mb), fn(mz)
        krit("memori %s basis = akhir" % nama, b == z, "awal %s, basis %s, akhir %s"
             % (fn(ma), b, z))
    for k in ("pmm_fail", "kmalloc_fail", "pmm_bad_free"):
        krit("%s tidak naik" % k, mz.get(k) == ma.get(k), "awal %s, akhir %s"
             % (ma.get(k), mz.get(k)))

    # 3. Sesi bersih di akhir (sesi pemantau sendiri = 1 CLI).
    krit("tcp_conn_active akhir 1 (hanya pemantau)", mz.get("tcp_conn_active") == 1,
         str(mz.get("tcp_conn_active")))
    krit("tls_sess_active akhir 0", mz.get("tls_sess_active") == 0, str(mz.get("tls_sess_active")))
    krit("cli_sess_active akhir 1", mz.get("cli_sess_active") == 1, str(mz.get("cli_sess_active")))

    # 4. Watchdog dan stack.
    krit("wd_gap_max < 100 tick", mz.get("wd_gap_max", 1 << 30) < 100, str(mz.get("wd_gap_max")))
    krit("stack_net_used basis = akhir", mb.get("stack_net_used") == mz.get("stack_net_used"),
         "basis %s, akhir %s" % (mb.get("stack_net_used"), mz.get("stack_net_used")))

    # 5. logdisk.
    for k in ("logdisk_wfail", "logdisk_bad"):
        krit("%s tidak naik" % k, mz.get(k) == ma.get(k), "awal %s, akhir %s"
             % (ma.get(k), mz.get(k)))

    # 6. Klien.
    krit("klien: tanpa langkah gagal", not kli, "%d kegagalan" % len(kli))

    lulus = all(ok for _, ok, _ in hasil)
    print("# Hasil analisis soak R8\n")
    print("Putusan: **%s**\n" % ("LULUS" if lulus else "GAGAL"))
    print("Sampel: %d (awal %s, basis t=%.0f s, akhir %s, putaran %s)\n"
          % (len(met), awal["waktu"], basis["t"], akhir["waktu"], akhir["putaran"]))
    print("## Kriteria\n")
    print("| Kriteria | Hasil | Rincian |\n|---|---|---|")
    for nama, ok, rinci in hasil:
        print("| %s | %s | %s |" % (nama, "lulus" if ok else "GAGAL", rinci))

    print("\n## Tren (tiap sampel)\n")
    print("| t (jam) | jenis | " + " | ".join(n for n, _ in TREN) + " |")
    print("|---|---|" + "---|" * len(TREN))
    for r in met:
        vals = []
        for _, fn in TREN:
            try:
                vals.append(str(fn(r["m"])))
            except KeyError:
                vals.append("-")
        print("| %.2f | %s | %s |" % (r["t"] / 3600.0, r["jenis"], " | ".join(vals)))

    print("\n## Counter (awal -> akhir)\n")
    print("| kunci | awal | akhir | selisih |\n|---|---|---|---|")
    for k in INFO:
        if k in mz:
            print("| %s | %s | %s | %s |" % (k, ma.get(k), mz[k], mz[k] - ma.get(k, 0)))

    st = os.path.join(a.dir, "status.json")
    if os.path.exists(st):
        with open(st) as f:
            s = json.load(f)
        print("\n## Langkah klien\n")
        print("| langkah | ok | gagal |\n|---|---|---|")
        for k, v in s.get("langkah", {}).items():
            print("| %s | %d | %d |" % (k, v["ok"], v["gagal"]))
        if s.get("info"):
            print("\nInfo: " + ", ".join("%s=%s" % kv for kv in s["info"].items()))
    if kli:
        print("\n## Kegagalan klien (maks 30)\n")
        for r in kli[:30]:
            print("- %s t=%.0f putaran %s %s: %s" % (r["waktu"], r["t"], r["putaran"],
                                                   r["langkah"], r["pesan"]))
    return 0 if lulus else 1


if __name__ == "__main__":
    sys.exit(main())

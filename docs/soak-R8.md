# R8: soak test 24 jam

Status: LULUS di VMware 24 jam (2026-10-28 09:13 s.d. 2026-10-29 09:14).

## Tujuan
ROADMAP Fase 4 R8: bmahOS berjalan 24 jam di VM di bawah beban jaringan berulang (banjir paket, koneksi
berulang TCP 7 / 7779 / 7780, UDP CHAL) tanpa panic, reboot, atau kebocoran memori.

## Alat
- `client/soak.py`: generator beban + pencatat metrik (Python 3, pustaka standar + `bmctl.py`).
  Satu proses, langkah berurutan, paling banyak 2 koneksi TCP sekaligus (batas kernel 2 TCB per IP).
  Windows: menahan sleep lewat `SetThreadExecutionState` selama proses hidup.
- `client/soak-mulai.ps1 [-Durasi detik]`: mulai soak di VMware dari Windows (menolak bila soak.py masih jalan,
  Power Off/On VM, tunggu 7780, cek serial, jalankan soak.py di jendela kecil). Satu baris:
  `powershell -ExecutionPolicy Bypass -File "D:\Shared Folders VM\CentOS Terminal\soak-mulai.ps1"`.
- `tests/soak/qemu-soak.sh [durasi] [interval]`: pra-uji di QEMU (TCG, hostfwd slirp, tanpa ICMP).
- `tests/soak/analisis.py DIR [--serial LOG] [--pemanasan S]`: laporan Markdown + putusan (kode keluar 0 = lulus).

## Beban per putaran (bawaan 60 s)
| Langkah | Isi | Terhadap batas kernel |
|---|---|---|
| echo | 3 koneksi TCP 7 x 8 KB acak, SHA-256 dicek | di bawah 2000 segmen/s per koneksi |
| shell | 2 sesi 7779: uptime, mem, metrics, exit | di bawah 2 sesi CLI |
| tls | 1 sesi 7780: handshake + pin + login + uptime + exit | di bawah TLS_MAX_SESS 2 |
| udp | 5x CHAL + uptime bertanda tangan (7778) | di bawah 20 datagram/s per IP |
| uecho | 10 datagram UDP 7777, jeda 0,1 s | di bawah batas |
| ping | 10 ICMP (Windows saja) | |
| banjir | 200 datagram UDP 7777 secepatnya | sengaja melewati batas laju (udp_src_dropped) |
| tolak | 2 koneksi echo terbuka, koneksi ke-3 harus ditolak | tcp_src_full |
| login_salah | login HMAC salah di 7779 -> ERR + tutup | cli_login_fail |
| diam | tiap 5 putaran: 7779 tanpa login -> ditutup ~10 s | cli_login_timeout |

Setelah setiap sesi yang ditutup server, klien menunggu 2,5 s (TIME_WAIT server 2 s ikut dihitung batas per IP).

## Metrik
Tiap 10 menit (plus awal dan akhir) beban jeda, lalu satu sesi 7779 mengambil `metrics` (semua halaman), `mem`
(frame bebas), `wd`, `tls`, `config` -> `metrik.jsonl`. Kegagalan langkah -> `klien.jsonl`. Ringkasan -> `status.json`.

## Kriteria lulus
1. Tanpa panic/reboot: uptime naik terus dan sejalan jam dinding (0,9..1,1); serial `PCI-1:` = 2, tanpa
   `PANIC`, grep fault 0.
2. Memori: basis (sampel setelah pemanasan 1 jam) = akhir (setelah beban berhenti 40 s) untuk frame bebas,
   heap_used, pmm_alloc - pmm_free, kmalloc - kfree; pmm_fail, kmalloc_fail, pmm_bad_free tidak naik.
3. Akhir: tcp_conn_active 1 dan cli_sess_active 1 (hanya sesi pemantau), tls_sess_active 0.
4. wd_gap_max < 100 tick; stack_net_used basis = akhir.
5. logdisk_wfail dan logdisk_bad tidak naik (logdisk_lost boleh: LOG.BIN penuh membuang baris baru).
6. Klien: tanpa langkah gagal (setiap kegagalan harus dijelaskan).

## Pra-uji QEMU (2026-10-27, ISO PROD HEAD febdc5d, TCG)
`tests/soak/qemu-soak.sh 3600 300`: LULUS, 60 putaran, 13 sampel, 0 kegagalan klien. Frame bebas 118016,
heap_used 5168, pmm_netto 97, kmalloc_netto 4 sama dari awal sampai akhir; uptime +3639 s vs jam dinding +3640 s;
wd_gap_max 10; stack_net_used 4656; tcp_src_full +60 (tolak), udp_src_dropped +2701 (banjir, 20 balasan per
banjir = batas 20/s per IP). Pra-uji 10 menit pertama menemukan dua salah uji di klien (bukan kernel): hostfwd
slirp menerima connect() koneksi ke-3 di sisi host (kini dicek dengan echo 1 byte), dan jalur gagal `tolak`
melewatkan jeda TIME_WAIT sehingga `login_salah` kena batas 2 TCB per IP.

## Hasil VMware 24 jam (2026-10-28/29, ISO PROD 9711b026, kode bc84714)
Mulai `soak-mulai.ps1 -Iso bmahOS-prod.iso` 2026-10-28 09:13:25, selesai 2026-10-29 09:14:11.
`analisis.py --pemanasan 3600`: **LULUS**, 20/20 kriteria, 145 sampel tanpa celah (jarak 600..639 s).

- 1440 putaran, 0 langkah gagal: echo 4320, shell 2880, tls 1440, udp 7200, uecho 1440, ping 1440,
  banjir 1440, tolak 1440, login_salah 1440, diam 288.
- Tanpa panic/reboot: uptime +86411 s vs jam dinding +86440 s; serial `PCI-1:` 2, `PANIC` 0, fault 0.
- Memori sama dari sampel awal sampai akhir: frame bebas 121599, heap_used 5168, pmm_netto 114,
  kmalloc_netto 4; pmm_fail 0, kmalloc_fail 2 dan pmm_bad_free 1 tidak naik (sudah ada saat boot).
- Akhir: tcp_conn_active 1, cli_sess_active 1, tls_sess_active 0; stack_net_used 4656 (tetap sejak
  sampel pertama di bawah beban).
- Counter: tcp_conn_open +13392, tcp_retx 0, tcp_timeout 0, tcp_conn_dropped 0, rx_missed 0, rx_nobuf 0,
  cli_cmd_fail 0, tls_fail 0, udp_src_dropped +259200 (banjir: tepat 20 balasan per banjir),
  tcp_src_full +7200 (tolak), audit_seq +28800, logdisk_written +35279.
- wd_gap_max 2 -> 24 di 10 menit pertama, lalu 34 pada sampel 2026-10-29 04:04 (bertepatan dengan
  gangguan jaringan di host Windows yang dilaporkan pengguna; VMnet2 host-only, tidak ada langkah gagal).
  Batas kriteria 100, batas watchdog 1000.
- logdisk_lost 496 sudah ada pada sampel awal (t=3 s) dan tidak naik selama soak.

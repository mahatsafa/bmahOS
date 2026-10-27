# R7: fuzzing parser di host (libFuzzer)

Tanggal: 2026-10-27. Alat: clang 22.1.8 (CentOS), libFuzzer + ASan + UBSan
(`-fno-sanitize-recover=all`). AFL++ tidak dipakai (tidak terpasang; libFuzzer cukup).

## Cara menjalankan

    make fuzz                              # 9 target x FUZZ_TIME (bawaan 600 s)
    make fuzz FUZZ_TARGETS=net FUZZ_TIME=3600
    make fuzz-regress                      # korpus awal + tests/fuzz/regress/<target>, juga di host-test/CI

- Korpus kerja: `build/fuzz/corpus/<target>` (tidak di-commit, bertambah tiap putaran).
- Korpus awal: dibuat ulang tiap kali oleh `build/fuzz/regr_<target> -s DIR` dari pembangun
  frame/stub di `tests/host/test_*.c`.
- Temuan: `build/fuzz/crash-<target>-*`, log `build/fuzz/<target>.log`. Input temuan yang sudah
  diperbaiki disimpan di `tests/fuzz/regress/<target>/` supaya `make fuzz-regress` mengulangnya.
- Satu input: `build/fuzz/fuzz_<target> <file>` (libFuzzer) atau `build/fuzz/regr_<target> <file>`.

## Target

| Target | Pintu masuk | Bentuk input |
|---|---|---|
| net | `net_rx_dispatch` (Ethernet/ARP/IPv4/ICMP/UDP/TCP, CLI 7779, TLS 7780, echo 7) | deret `[op][len BE16][frame]`, op: betulkan checksum, ikuti seq/ack/port segmen keluar terakhir, majukan 0..30000 tick |
| auth | `auth_tcp_login`, `auth_tcp_cmd`, `auth_cmd_allowed`, `auth_tcp_exec`, `net_cmd_handle` | `[mode][param][data]`; mode 2/4 menandatangani perintah dengan kunci uji supaya parser SESUDAH HMAC teruji |
| config | `config_parse`, `config_load`, `config_execute` | `[mode][data]` |
| fat32 | probe BPB, API baca lama (`find_file`/`load_file`/`read_file`/`list_root_directory`), `fat32_root_read`, `file_map`/`map_read`/`map_write`, `fscmd` ls/baca/tulis/tambah/ganti/hapus, `fat32_replace_name` | `[n][perintah fscmd][isi jendela sektor]` atas image mkfs.vfat 64 MB: sektor 0..31, 8 sektor FAT1, 8 sektor root; tulisan di-undo tiap input |
| logdisk | `logdisk_init` (pindai), `logdisk <seq>`, tulis + poll + sync, pindai ulang | `[nsec][seq LE64][isi LOG.BIN]` |

Invarian yang dicek selain ASan/UBSan: frame keluar lolos cek panjang/checksum (`e1000_tx_send`
test_net), peran ro yang ditolak mendapat "ERR: peran read-only" dan tidak bisa reboot, nilai
config selalu di [min, max] dan file hasil `set` bisa diurai ulang, keluaran perintah <= CMD_OUT_MAX,
peta file <= FAT32_MAP_MAX, entri root <= 128.

## Hasil

Tidak ada temuan (crash, baca/tulis di luar batas, UB, kebocoran, pelanggaran invarian).

| Target | Waktu | Eksekusi | Edge (cov) | Baris sumber tercakup |
|---|---|---|---|---|
| net | 10 menit + 1 jam | 9,4 jt + 48,5 jt | 682 | net.c 82%, tls.c 60% |
| auth | 10 menit | 36,1 jt | 406 | auth.c 66% |
| config | 10 menit | 68,5 jt | 198 | config.c 91% |
| fat32 | 10 menit + 10 menit | 3,0 jt + 2,0 jt | 681 | fat32.c 63% (sebelum API baca lama ditambahkan), fscmd.c 95% |
| logdisk | 10 menit | 1,5 jt | 206 | logdisk.c 84% |

Cakupan baris diukur dengan `-fprofile-instr-generate` atas korpus akhir putaran 10 menit.

## Celah yang diketahui (tidak tercakup)

- tls.c: handshake di luar ClientHello butuh ECDHE sah; fuzzer acak tidak bisa melewatinya.
  BearSSL sendiri teruji upstream (bearssl_test_crypto di host-test) dan diuji sesi penuh di test_net.
- auth.c: jalur counter lama (`auth_verify`, hanya build LEGACYCTR=1).
- net.c: fungsi status/driver (`net_poll`, `e1000_stats_poll`, `net_tcp_*_active`) bukan parser.
- Stub test_net untuk login/perintah TCP sederhana (64 'a'/'r', digit seq); parser asli diuji di
  target auth. Perintah umum (`cmd.c`: uptime, metrics, dll.) tidak di-fuzz (di-stub).
- FAT32 hanya jendela tetap (BPB, awal FAT1, cluster root); rantai panjang di luar jendela tetap
  isi mkfs asli.

## Parser Fase 5 (2026-10-28)

THREAT_MODEL bagian 7 mewajibkan setiap parser baru masuk daftar fuzzing; parser Fase 5 (SNTP P3-2,
DNS P3-3, packet filter P4, DHCP P3-4) baru ditambahkan di sini. `FUZZ_TARGETS` kini 9 target dan
`make fuzz-regress` (host-test, CI) ikut menjalankan korpus awal keempatnya.

| Target | Pintu masuk | Bentuk input |
|---|---|---|
| dhcp | `dhcp_rx` (balasan BOOTP dari LAN), lanjut `dhcp_poll` | `[mode][isi UDP]`; mode: keadaan awal pilih/minta/perpanjang/ikat-ulang, betulkan xid/chaddr/cookie supaya option ikut teruji, lewati batas cek ARP |
| dns | `dns_rx` untuk query perintah `dns` atau query pemantau (`dns_probe_start`) | `[mode][isi UDP]`; mode: betulkan ID, salin pertanyaan, flag balasan sah |
| sntp | `sntp_rx` sesudah permintaan dengan nonce | `[mode][isi UDP]`; mode: salin nonce, byte 0 sah, stratum 2 |
| filter | `filter_parse` (FILTER.CFG), `filter_execute`, `filter_ipv4` | `[mode][data]` |

Invarian: DHCP: IP 0.0.0.0 selama belum terikat, selain itu alamat /24 sah; keadaan dalam rentang.
DNS: entri cache 1..63 byte dengan sisa TTL 5..3600 s (negatif tepat 60 s), query pemantau dilaporkan
tepat sekali dan "ada A" hanya bila entri positif tersimpan. SNTP: jam berubah hanya untuk balasan
yang lolos semua cek, dan sama dengan transmit - 2208988800. Filter: aturan <= 16, bentuk kanonik
stabil (tulis -> urai -> tulis sama), file hasil perintah terurai ulang dengan jumlah aturan sama,
SYN TCP ke 7780 selalu lolos.

Hasil 10 menit per target:

| Target | Waktu | Eksekusi | Temuan |
|---|---|---|---|
| dhcp | 10 menit | 51,3 jt | - |
| dns | 10 menit | 72,1 jt | - |
| sntp | 10 menit sesudah perbaikan (putaran pertama berhenti di temuan) | 191,9 jt | 1, diperbaiki |
| filter | 10 menit | 67,9 jt | - |

Temuan sntp: `sntp_rx` membaca byte 0 dan 1 (LI/VN/mode/stratum) sebelum mengecek panjang >= 48,
sehingga isi UDP 1 byte membuat `p[1]` terbaca di luar data (ASan heap-buffer-overflow, baca 1 byte).
Di kernel bacaan itu masih di dalam buffer RX 2 KB dan balasan tetap ditolak, jadi tanpa dampak nyata,
tapi melanggar aturan "panjang dicek dulu". Diperbaiki (cek panjang paling awal), uji host isi 0..47
byte dengan buffer seukuran persis, input temuan di `tests/fuzz/regress/sntp/isi-1-byte`.

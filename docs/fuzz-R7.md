# R7: fuzzing parser di host (libFuzzer)

Tanggal: 2026-10-27. Alat: clang 22.1.8 (CentOS), libFuzzer + ASan + UBSan
(`-fno-sanitize-recover=all`). AFL++ tidak dipakai (tidak terpasang; libFuzzer cukup).

## Cara menjalankan

    make fuzz                              # 5 target x FUZZ_TIME (bawaan 600 s)
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

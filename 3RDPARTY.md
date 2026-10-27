# Kode pihak ketiga

## BearSSL (`third_party/bearssl/`)

- Asal: https://www.bearssl.org/git/BearSSL, commit `7bea48e5e850ab4cafbe68d3765cdaba13a86d6f` (2026-04-06,
  "Fixed bug in handling incoming records with invalid length"). Dipilih di atas rilis v0.6 (2018) karena
  perbaikan sesudahnya: carry P-256 m64 (2020), overflow decode kunci privat (2019), panjang record (2026).
- Isi: `src/`, `inc/`, `LICENSE.txt`, `test/test_crypto.c`, persis seperti upstream (tidak diubah).
  Dibuat dengan: `git archive 7bea48e5e850ab4cafbe68d3765cdaba13a86d6f src inc LICENSE.txt test/test_crypto.c`
  (git 2.52), sha256 tar = `86c5b7ec15f23eacc25d7afdf9d5297a5d166aa5eb4deb62c0bfd8f7af2e28a1`.
- Sidik jari isi (tidak bergantung versi git):
  `cd third_party/bearssl && find . -type f | LC_ALL=C sort | xargs sha256sum | sha256sum`
  = `e050e8c75e42d36cbf210bbbd214f0b4315fee0f6f57509c57e3e0608130faed` (319 file).
- Lisensi: MIT (`third_party/bearssl/LICENSE.txt`), Copyright (c) 2016 Thomas Pornin.
- Build (Makefile, D9a): semua `src/*.c` -> `build/libbearssl.a`, flag arsitektur kernel (`-mno-sse`,
  `-mcmodel=kernel`) + `-O2`; `BR_SSE2/BR_AES_X86NI/BR_POWER8/BR_RDRAND = 0`, RNG/waktu OS mati, `BR_INT128 = 1`.
  `string.h` dari `kernel/compat/`. `make test` memeriksa tidak ada register xmm/ymm/zmm dan simbol luar hanya
  mem*/strlen. `make host-test` menjalankan `test_crypto` upstream untuk implementasi profil D9.
- Memperbarui: ganti seluruh direktori dari commit baru, perbarui baris di atas, jalankan `make host-test` dan
  `make test`, catat alasannya di DECISIONS.md.

## Font konsol 8x16 (`kernel/fbfont.h`, P1)

- Asal: tabel `builtin_font[]` di flanterm yang ikut Limine (`tools/limine/flanterm/src/flanterm_backends/fb.c`,
  Limine commit `fdc6d566072cc78a543cef44ef370729fe91fe2e`, 2026-07-22, sha256 fb.c `1f4b82176881534a...`).
  Komentar upstream: diambil dari `TOSH-SAT.F16` (koleksi vga-text-mode-fonts, dump font BIOS Toshiba).
- Isi: hanya glyph ASCII 0x20..0x7E (95 x 16 byte), byte tidak diubah; bit 7 = piksel kiri.
- Lisensi: BSD-2-Clause flanterm (`tools/limine/flanterm/LICENSE`), Copyright (C) 2022-2026 Mintsuki and
  contributors. Status hak cipta font BIOS aslinya tidak diketahui; bila jadi masalah, ganti dengan font
  berlisensi jelas (mis. Spleen, BSD-2) tanpa mengubah format `g_fbfont[95][16]`.
- Membuat ulang: ambil `builtin_font[0x20*16 .. 0x7F*16)` dari fb.c (skrip ekstraksi di catatan sesi
  2026-10-27, CLAUDE.md), tulis sebagai `g_fbfont`; `make host-test` (test_fbcon) memeriksa render.

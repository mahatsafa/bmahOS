# Protokol jaringan bmahOS

Dokumen ini mencatat format paket/baris yang diterima bmahOS (IP 192.168.50.200).
Kunci bersama: isi KEY.TXT di disk (16..64 byte, spasi/CR/LF di akhir dibuang).
Semua HMAC = HMAC-SHA256 dengan kunci itu, ditulis 64 hex huruf kecil.

## UDP 7778: perintah (Net-18A, B2)

1. Klien: `CHAL` -> server: `nonce: <32 hex>` (sekali pakai, berlaku 5 detik,
   maks 4 hidup per IP, tabel 16 slot).
2. Klien: `<nonce> <perintah> <hmac>` dengan hmac atas `<nonce> <perintah>`.
3. Server: keluaran perintah, atau `ERR: ...` (format, nonce tidak dikenal/dipakai,
   kedaluwarsa, hmac salah, auth nonaktif).

Jalur counter lama (`<counter> <perintah> <hmac>`) dimatikan sejak B2 (build `LEGACYCTR=1`).

## UDP 7777: echo, TCP 7: echo

Tanpa autentikasi. TCP 7: maks 4 koneksi total, 2 per IP (C5a); koneksi tanpa
kemajuan 30 detik ditutup (C5b).

## TCP 7779: CLI (D1: login; shell = D2)

Teks baris, diakhiri LF (CR sebelum LF dibuang). Baris maks 128 byte termasuk LF.

```
server -> bmahOS login
server -> nonce: <32 hex>          nonce khusus koneksi ini (DRBG, dibuat saat SYN)
klien  -> login <hmac>             hmac atas "<nonce> tcp-login"
server -> OK login                 sesi terautentikasi
       |  ERR: login gagal         format/hmac salah, lalu server menutup (FIN)
       |  ERR: auth nonaktif       kunci tidak dimuat, lalu FIN
```

- Satu percobaan login per koneksi. Login harus selesai dalam 10 detik sejak handshake,
  kalau tidak: `ERR: login timeout` lalu FIN.
- Baris lebih dari 128 byte: `ERR: baris terlalu panjang` lalu FIN.
- Baris kosong diabaikan. Setelah login (sampai D2) setiap baris dibalas
  `ERR: shell belum ada (D2)`.
- Pesan yang ditandatangani ("<nonce> tcp-login") berbeda dari perintah UDP dan nonce-nya
  tidak ada di tabel UDP, jadi bukti login tidak bisa dipakai di jalur UDP atau koneksi lain.
- Batasan: setelah login, baris berikutnya belum ditandatangani. Penyerang di jalur bisa
  menyisipkan segmen ke sesi; tidak berarti selama shell belum ada. Rencana D2: tiap perintah
  ditandatangani dengan nonce baru dari balasan sebelumnya.
- Metrics: `cli_login_ok`, `cli_login_fail`, `cli_login_timeout`, `cli_line_long`.

Contoh klien: `tests/tcp-login.py HOST PORT KEYFILE`.

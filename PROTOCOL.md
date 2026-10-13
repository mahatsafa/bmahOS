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

## TCP 7779: CLI (D1: login, D2: shell)

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
- Baris kosong diabaikan.
- Pesan yang ditandatangani ("<nonce> tcp-login") berbeda dari perintah UDP dan nonce-nya
  tidak ada di tabel UDP, jadi bukti login tidak bisa dipakai di jalur UDP atau koneksi lain.
- Metrics: `cli_login_ok`, `cli_login_fail`, `cli_login_timeout`, `cli_line_long`.

### Shell setelah login (D2)

```
klien  -> <perintah> <hmac>        hmac atas "<nonce> tcp-cmd <n> <perintah>"
server -> <keluaran perintah>      nol atau lebih baris
server -> END <n>
       |  ERR: hmac salah          hmac/nomor urut salah, lalu FIN
       |  ERR: format: <perintah> <hmac-hex64>   lalu FIN
       |  ERR: auth nonaktif       lalu FIN
```

- `n` = nomor perintah di koneksi ini: 1, 2, 3, ... Tidak dikirim; klien dan server
  menghitung sendiri. Nonce = nonce banner koneksi ini. Jadi perintah tidak bisa dipakai
  di koneksi lain, diulang, disisipkan, atau ditukar urutannya; bukti login juga tidak
  berlaku sebagai perintah (pesannya berbeda).
- Perintah 1..64 byte tanpa spasi di awal/akhir. Daftarnya sama dengan UDP 7778
  (`help`, `ping`, `uptime`, `metrics`, `pping`, `reboot`, ...), ditambah `exit`
  (balasan `bye`, `END <n>`, lalu FIN).
- `reboot`: balasan dikirim dulu, reboot setelah balasan di-ACK (paling lambat 2 detik).
- Keluaran maks 1400 byte (lebih panjang terpotong, sama seperti UDP) + baris `END`.
  Keluaran lebih besar dari buffer kirim 1024 byte dikirim bertahap; selama belum habis
  baris berikutnya tidak dibaca (tidak di-ACK, klien TCP mengirim ulang). Klien sebaiknya
  menunggu `END <n>` sebelum mengirim perintah berikutnya.
- Satu perintah salah = koneksi ditutup (fail closed); login ulang di koneksi baru.
- Balasan tidak ditandatangani dan teks polos (keaslian balasan dan kerahasiaan: D8).
- Koneksi tanpa kemajuan 30 detik tetap ditutup (batas sesi: D4).
- Metrics: `cli_cmd_ok`, `cli_cmd_fail`.

Klien: `client/bmctl.py --tcp` (sekali jalan atau interaktif) dan `client/bmtcp.ps1`
(PowerShell: `bmtcp`, `bmt <perintah>`, `bmtx`); uji: `tests/tcp-login.py HOST PORT KEYFILE`.

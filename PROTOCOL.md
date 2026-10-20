# Protokol jaringan bmahOS

Dokumen ini mencatat format paket/baris yang diterima bmahOS (IP 192.168.50.200).
Kunci bersama: isi KEY.TXT di disk (16..64 byte, spasi/CR/LF di akhir dibuang).
Semua HMAC = HMAC-SHA256 dengan kunci itu, ditulis 64 hex huruf kecil.
D4: KEYRO.TXT (opsional, aturan sama, harus beda dari KEY.TXT) = kunci peran read-only,
hanya untuk TCP 7779 dan TLS 7780.

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
server -> OK login                 sesi terautentikasi, peran admin (KEY.TXT)
       |  OK login ro              peran read-only (hmac dengan kunci KEYRO.TXT, D4)
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
       |  ERR: peran read-only     perintah tidak diizinkan untuk peran ini, lalu END <n>
                                   (sesi tetap jalan)
       |  ERR: sesi idle           300 detik tanpa perintah sah, lalu FIN
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
- hmac perintah memakai kunci peran sesi (admin: KEY.TXT, ro: KEYRO.TXT).
- Peran read-only hanya boleh: `help ping uptime mem log irq stats metrics mac ip tasks exit`
  (`metrics` dengan argumen juga, R3).
- D4: sesi yang sudah login ditutup 300 detik setelah login/perintah sah terakhir
  (`ERR: sesi idle`, lalu FIN); byte tanpa LF tidak memperpanjang. Batas diam TCP 30 detik
  tidak berlaku untuk sesi login.
- D4: maks 2 koneksi ke port 7779 sekaligus (termasuk handshake dan TIME_WAIT 2 s); SYN
  berikutnya dibalas RST bila tidak ada handshake setengah jadi yang bisa digusur.
- Metrics: `cli_cmd_ok`, `cli_cmd_fail`, `cli_login_ro`, `cli_role_denied`, `cli_sess_full`,
  `cli_idle_timeout`.

## TCP 7780: CLI lewat TLS 1.2 (D9)

Isi aplikasi = protokol baris TCP 7779 di atas, persis sama (banner, nonce, `login <hmac>`, perintah
bertanda tangan nomor urut, `END <n>`, `exit`), di dalam TLS. Login HMAC tetap wajib: TLS hanya
mengautentikasi server dan merahasiakan isi.

- TLS 1.2 saja (BearSSL tidak punya TLS 1.3; klien TLS 1.3-saja ditolak). Suite:
  `ECDHE-ECDSA-AES128-GCM-SHA256` (0xC02B) dan `ECDHE-ECDSA-CHACHA20-POLY1305` (0xCCA9), kurva P-256.
  Tanpa resumption, renegosiasi, sertifikat klien.
- Identitas server: `TLSKEY.DER` (kunci EC P-256, DER SEC1 atau PKCS#8) dan `TLSCERT.DER` (sertifikat
  self-signed DER) di root disk, dimuat saat boot; kunci publik sertifikat harus cocok dengan kunci privat.
  Serial: `TLS: aktif port 7780 pin=<sha256 sertifikat>` atau `TLS: nonaktif (<alasan>)`; nonaktif -> SYN
  7780 dibalas RST. Kedua file dilindungi dari `baca`/`tulis`/`hapus`/`ganti`.
- Klien WAJIB mem-pin sha256 sertifikat (DER) dan membandingkannya sebelum mengirim byte aplikasi apa pun;
  verifikasi CA tidak dipakai. Pin juga terlihat lewat perintah `tls`.
- Maks 2 TCB port 7780 (terpisah dari 2 sesi 7779), aturan penggusuran SYN_RCVD sama. Batas login 10 s
  dihitung sejak TCP ESTABLISHED (termasuk handshake). Error TLS (alert, record rusak, teks polos) -> RST.
  `exit`/penutupan server: `close_notify` lalu FIN; `close_notify` balasan klien dibuang (bukan RST).
- Entropi belum siap -> SYN 7780 dibuang (seperti port 7). DRBG engine di-seed 32 byte dari `entropy_get`
  per sesi.
- Perintah `tls` (admin dan read-only, juga lewat UDP): `tls: aktif port 7780`, `pin: <64 hex>`,
  `sesi: aktif= maks= ok= gagal= penuh= tanpa_entropi= err_terakhir=<kode BR_ERR_*>`,
  `stack_net: terpakai_maks=<byte> dari 32768`.

Membuat identitas (di mesin dev, kunci privat tidak pernah lewat jaringan):

```
openssl ecparam -name prime256v1 -genkey -noout -outform DER -out TLSKEY.DER
openssl req -new -x509 -key TLSKEY.DER -keyform DER -days 3650 -subj /CN=bmahOS \
    -outform DER -out TLSCERT.DER
sha256sum TLSCERT.DER        # = pin klien
```

Klien: `client/bmctl.py --tls --pin <64 hex | file> --key KEY` (port 7780 atau `BMAHOS_TLS_PORT`, pin juga
dari `BMAHOS_TLS_PIN`; pin beda -> kode keluar 2 tanpa login) dan `client/bmtcp.ps1` `bmtls` (SslStream, pin
dari `$BmPinFile`, default `%USERPROFILE%\.bmahos\tlspin.txt`). Uji: `tests/tls-login.py`, pcap di `make test`
(`tests/pcap-check.py`: payload 7780 tanpa teks polos).

## Audit log (D5)

Perintah `audit` dan `audit gagal` (hanya admin: UDP 7778 jalur nonce atau sesi TCP admin;
peran read-only -> `ERR: peran read-only`). Keluaran: header lalu entri tertua -> terbaru:

```
audit ok: total=<n> tampil=<k> ditimpa=<n-k>
#<urut> t=<tick> <ip>:<port> <tcp|udp|tls> <none|admin|ro> <kejadian>[ kode=<c>][ <perintah>]
```

- `#<urut>` naik terus untuk kedua ring sejak boot; `t` = tick (100/s) sejak boot.
- Ring ok (16 entri): `login`, `cmd` (perintah sah, termasuk `exit` dan `audit`),
  `tolak-peran` (perintah sah tetapi tidak diizinkan untuk peran ini), `idle` (sesi idle 300 s).
- Ring gagal (8 entri): `login-gagal kode=1|2|5`, `login-timeout`, `baris-panjang`,
  `cmd-gagal kode=<c>` (TCP: 1/2/5; UDP: 1..5 seperti kode tolak 7778).
- Teks perintah (maks 16 byte, selain ASCII cetak jadi `?`) hanya dicatat bila sudah lolos HMAC.
- Tidak dicatat: `CHAL`, SYN yang ditolak, jalur counter yang dimatikan (ada di metrics).
- Ring penuh: entri tertua ditimpa. Bila keluaran tidak muat 1400 byte: `...(terpotong)`.
- Tiap entri juga ke serial sebagai `AUDIT <baris>` (tidak masuk ring `log`). Isi ring hilang saat reboot.

## Berkas FAT32 (D6)

Hanya admin (UDP 7778 jalur nonce atau sesi TCP admin; read-only -> `ERR: peran read-only`).
Hanya root directory (cluster root pertama), nama 8.3 `A-Z 0-9 _ -` (huruf kecil diubah ke besar).

| Perintah | Hasil |
|---|---|
| `ls` | satu baris per entri (`NAMA.EXT <ukuran>` atau `NAMA/`), lalu `fs: mode=tulis\|baca-saja bebas_cluster=<n\|?> tulis_ok=<n> tulis_gagal=<n>` |
| `baca NAMA [offset]` | `isi NAMA ukuran=<n>:` lalu maks 1024 byte isi (selain ASCII cetak dan LF jadi `?`); sisa: `(terpotong; lanjut: baca NAMA <offset>)` |
| `tulis NAMA [teks]` | buat atau timpa, isi = `teks` + LF (tanpa teks: file kosong) -> `OK NAMA ukuran=<n>` |
| `tambah NAMA teks` | tambah satu baris `teks` + LF (file dibuat bila belum ada) -> `OK NAMA ukuran=<n>` |
| `hapus NAMA` | D7: hapus file biasa -> `OK hapus NAMA` |
| `ganti LAMA BARU` | D7: ganti nama; `BARU` tidak boleh sudah ada -> `OK ganti LAMA -> BARU` |

- Teks hanya 0x20..0x7e. Perintah TCP maks 64 byte (UDP 102), jadi teks per baris ~45 byte.
- File maks 4096 byte (yang lebih besar tidak bisa ditimpa/ditambah/dibaca). `KEY.TXT`, `KEYRO.TXT`,
  `PROG.BIN` ditolak (`ERR: fs: nama dilindungi`). Entri ber-atribut RO/hidden/system/dir tidak ditulis.
  `CONFIG.CFG`/`CONFIG.TMP` hanya boleh dibaca (diubah lewat `set`, D7). File bernama panjang (ada entri
  LFN sebelum entri 8.3) tidak bisa dihapus/diganti namanya (`ERR: fs: file bernama panjang (LFN) tidak
  didukung`), supaya tidak meninggalkan LFN yatim.
- Kesalahan: `ERR: fs: <alasan>` (tidak ada volume, volume baca saja, error disk, struktur disk rusak,
  disk penuh, direktori root penuh, file melebihi 4096 byte, bukan file biasa, file tidak ada,
  root lebih dari 1 cluster, nama tujuan sudah ada). Semua pemeriksaan selesai sebelum sektor pertama ditulis.
- Urutan tulis (flush di antaranya): data -> rantai FAT baru (FAT1, FAT2) -> sambungan ujung rantai lama ->
  entri direktori -> (timpa) bebaskan rantai lama -> FSInfo. Crash di tengah: file berisi isi lama atau
  baru, paling buruk ada lost cluster (fsck membersihkan). Error I/O saat menulis -> volume baca saja
  sampai reboot.
- `hapus`: entri ditandai 0xE5 + flush -> rantai dibebaskan (FAT1, FAT2) -> FSInfo. `ganti`: satu tulis
  sektor (11 byte nama). Crash di tengah `hapus` = lost cluster saja.
- Ganti isi atomik (dipakai `set`, D7; `fat32_replace_name`): file sementara sisa crash dihapus -> isi baru
  ditulis ke file sementara (urutan di atas) di sektor direktori yang sama dengan file tujuan -> SATU tulis
  sektor: entri tujuan menunjuk rantai baru dan entri sementara 0xE5 -> rantai lama dibebaskan -> FSInfo.
  Crash: tujuan berisi isi lama utuh (file sementara mungkin tertinggal, dibersihkan `set` berikutnya) atau
  isi baru utuh. Anggapan: satu tulis sektor 512 byte atomik. Sektor tujuan tanpa slot kosong ->
  `direktori root penuh`.
- Volume baca saja sejak boot bila mirroring FAT mati (ExtFlags bit 7) atau FSInfo tidak sah. BPB yang
  tidak lolos validasi -> volume tidak dipakai sama sekali.
- Tanggal file tetap 2026-01-01 (belum ada RTC tepercaya).

## Konfigurasi persisten (D7)

File `CONFIG.CFG` di root FAT32, dibaca sekali saat boot (serial: `CONFIG: sumber=... cli_idle=..
udp_rate=.. echo=.. cli_plain=.. udp_admin=.. netcon=.. netcon_host=.. netcon_port=..`). Teks ASCII, satu `kunci=nilai` per baris (LF; CR di akhir baris dibuang), baris
kosong dan `#...` diabaikan, maks 512 byte, angka desimal tanpa nol di depan.

| Kunci | Rentang | Default | Arti |
|---|---|---|---|
| `cli_idle` | 30..3600 | 300 | detik sesi CLI login tanpa perintah sah sebelum ditutup |
| `udp_rate` | 1..100 | 20 | datagram (dan SYN/segmen di luar koneksi) per detik per IP sumber |
| `echo` | 0..1 | 1 | 0: UDP 7777 dibuang tanpa balasan, SYN ke TCP port 7 dibalas RST |
| `cli_plain` | 0..1 | 1 | D9: 0: SYN ke CLI teks polos TCP 7779 dibalas RST (sesi yang sudah ada jalan terus) |
| `udp_admin` | 0..1 | 1 | D9: 0: UDP 7778 hanya perintah daftar baca (seperti peran read-only); lainnya `ERR: udp_admin=0: hanya perintah baca lewat UDP (pakai TLS 7780)` |
| `netcon` | 0..1 | 0 | R2: 1: baris log dikirim lewat UDP (lihat Netconsole) |
| `netcon_host` | 1..254 | 1 | R2: tujuan 192.168.50.`netcon_host` |
| `netcon_port` | 1024..65535 | 6666 | R2: port UDP tujuan |

- D9 pengaman: tanpa TLS aktif, `cli_plain=0` + `udp_admin=0` bersamaan menutup semua jalur admin jaringan.
  `set` yang menghasilkan kombinasi itu ditolak (`ERR: config: TLS nonaktif, ...`); file di disk dengan
  kombinasi itu (TLS hilang setelah ditulis) -> `cli_plain` dipaksa 1 saat boot (serial
  `CONFIG: TLS nonaktif, cli_plain dipaksa 1 (jalur admin terakhir)`).

- **Gagal tertutup**: satu baris salah (kunci tak dikenal, bukan `kunci=nilai`, kunci ganda, nilai bukan angka
  atau di luar rentang, byte bukan ASCII tercetak) atau file > 512 byte -> SELURUH file ditolak dan semua
  kunci memakai default. IP tidak bisa diatur (salah atur = bmahOS tidak bisa dihubungi).

| Perintah | Peran | Hasil |
|---|---|---|
| `config` | admin + read-only | `config: sumber=<sumber>` lalu `kunci=nilai` efektif per baris |
| `set KUNCI NILAI` | admin | simpan + terapkan langsung -> `OK KUNCI=NILAI (tersimpan)`; `NILAI` = `-` -> default |

- `sumber`: `disk`, `bawaan (tidak ada file)`, `bawaan (tanpa disk)`, `bawaan (error baca disk)`,
  `bawaan (ditolak baris N: alasan)`, `bawaan (ditolak: file > 512 byte)`.
- `set` menulis ulang file utuh (semua kunci, bentuk kanonik) lewat ganti isi atomik (`CONFIG.TMP` lalu satu
  tulis sektor, lihat di atas). Nilai di RAM hanya berubah bila penulisan berhasil; gagal ->
  `ERR: config: tidak tersimpan, nilai tidak diubah (fs: <alasan>)`. File yang ditolak saat boot ditimpa
  `set` berikutnya. Kesalahan lain: `ERR: config: kunci tak dikenal (...)`, `ERR: config: format: set KUNCI min..max|-`.

Klien: `client/bmctl.py --tcp` (sekali jalan atau interaktif) dan `client/bmtcp.ps1`
(PowerShell: `bmtcp`, `bmt <perintah>`, `bmtx`); uji: `tests/tcp-login.py HOST PORT KEYFILE [ROKEYFILE]`.
TLS 7780 (D9): `bmctl.py --tls --pin ...`, PowerShell `bmtls`; lihat bagian TCP 7780.

## Netconsole UDP (R2)

Bila `netcon=1`: datagram UDP dari 192.168.50.200:6665 ke 192.168.50.`netcon_host`:`netcon_port`
(bawaan .1:6666). Payload = satu atau lebih baris log utuh, masing-masing diakhiri LF, maks 1024 byte;
tanpa header/nomor urut. Baris = yang masuk ring `log` (tanpa `schedule(): switch`, tanpa `AUDIT`, tanpa
register umum dump panic), maks 160 karakter.
- MAC tujuan dari ARP: bmahOS mengirim ARP request ke tujuan maks 1x/detik sampai ada ARP dari IP itu.
  Sebelum itu baris ditahan di antrean (4 KB).
- Maks 20 datagram/detik. Antrean penuh -> baris baru dibuang; datagram berikutnya diawali
  `netcon: N baris dibuang`.
- Panic: antrean dikirim langsung di awal panic dan setelah dump (sebelum reboot otomatis).
- `set` berlaku langsung; `netcon_host` berubah -> ARP ulang; `netcon=0` -> antrean dikosongkan.
- Perintah `netcon` (admin + read-only): `netcon: aktif=.. tujuan=IP:port port_sumber=6665`,
  `netcon: mac=<mac|belum> arp=N`, `netcon: terkirim=N antre=<byte> dibuang=<baris> tx_gagal=N`
  (tanpa NIC: `netcon: NIC tidak ada`).
- Penerima: `nc -ul 6666` (Linux), atau UdpClient PowerShell; firewall Windows perlu izin UDP masuk.

## Perintah `metrics` (R3)

    metrics [awalan] [mulai]

- Keluaran: satu `kunci=nilai` per baris (nilai desimal tanpa tanda), urutan tetap = urutan
  tabel `g_metrics` di `kernel/metrics.c`. Kunci baru selalu ditambah di akhir; nama kunci
  `[a-z0-9_]`, maks 32 byte.
- Halaman: baris ditulis utuh selama muat di 1400 byte. Kalau masih ada kunci, baris terakhir
  `metrics_lanjut=<i>`; kirim `metrics [awalan] <i>` untuk halaman berikutnya. Halaman tanpa
  baris itu = halaman terakhir. Tidak pernah terpotong di tengah baris.
- `awalan` (opsional, `[a-z0-9_]` 1..32 byte, tidak diawali digit): hanya kunci yang namanya
  diawali teks itu, mis. `metrics tcp_`, `metrics cpu_`.
- `mulai` (opsional, desimal): indeks tabel tempat mulai (dari `metrics_lanjut`).
- Argumen salah (spasi ganda, huruf besar, `mulai` >= jumlah kunci, urutan terbalik):
  `ERR: metrics [awalan] [mulai]`. Tidak ada kunci yang cocok: `ERR: metrics: tidak ada kunci yang cocok`.
- Jalur UDP: tiap halaman = CHAL + perintah sendiri (ingat batas 20 datagram/s per IP).
- Kunci CPU: `cpu_idle_ticks` (tick timer saat task idle berjalan), `cpu_busy_pct` (persen tick
  bukan-idle di jendela 100 tick terakhir yang lengkap; build dev ~100 karena task uji).

## Log persisten `logdisk` (R4)

    logdisk          status, satu kunci=nilai per baris
    logdisk <seq>    teks rekaman mulai seq (lebih kecil dari tertua = mulai dari tertua)

- Status: `logdisk=aktif|baca-saja|nonaktif [alasan]`, lalu (bila aktif/baca-saja) `rekaman`,
  `boot`, `seq_tertua`, `seq_berikut`, `seq_boot_ini`, `seq_boot_lalu` (seq pertama boot sebelumnya,
  0 = tidak ada), `antre`, `ditulis`, `dibuang`, `gagal`, `rusak`.
- Teks: `=== boot B seq S [panic] ===` di awal halaman dan saat boot berganti, lalu baris log apa
  adanya. Rekaman robek/hilang: `=== seq S rusak/hilang ===`. Halaman <= 1400 byte; sisa -> baris akhir
  `logdisk_lanjut=<seq>`, kirim `logdisk <seq>` berikutnya (bmctl.py dan `bmlogdisk` mengikutinya).
- Salah: `ERR: logdisk [seq]`, `ERR: logdisk nonaktif`, `ERR: logdisk kosong`,
  `ERR: logdisk: seq di luar ring`. Peran read-only boleh (isi sama dengan `log`).
- Format `LOG.BIN` (sektor 512 byte, little endian): `BMLG`, versi 1, flag (bit 0 = panic),
  panjang teks u16 (<= 480), boot u32, 0 u32, seq u64, hash 8 byte (awal SHA-256 sektor dengan field
  hash nol), teks. Pembaca offline: `tools/logdump.py LOG.BIN [--boot N] [--status]`.

# bmahOS Threat Model

Status: draf awal, **2026-10-09**. Perbarui setiap kali ada permukaan serangan baru
(protokol, parser, driver, syscall).

## 1. Tujuan dokumen

Menjawab empat pertanyaan: apa yang dilindungi, dari siapa, lewat jalur mana, dan apa yang sengaja
**tidak** dilindungi. Tanpa ini, keamanan hanya berupa kumpulan tambalan.

## 2. Aset

| ID | Aset | Mengapa penting |
|---|---|---|
| S1 | Kunci HMAC perintah jarak jauh | Siapa pun yang memegangnya bisa memerintah mesin |
| S2 | Kendali atas mesin (reboot, perintah berprivilege) | Gangguan layanan atau pengambilalihan |
| S3 | Ketersediaan layanan 24/7 | Tujuan utama sebagai server |
| S4 | Integritas kernel dan memori kernel | Pecah di sini berarti semua pecah |
| S5 | Integritas data di penyimpanan (log, konfigurasi, kernel A/B) | Konfigurasi rusak atau kernel palsu |
| S6 | Kerahasiaan balasan perintah dan log | Informasi sistem bisa membantu penyerang |
| S7 | Integritas jalur update (OTA) | Update palsu = kendali penuh |

## 3. Penyerang

| ID | Penyerang | Kemampuan yang diasumsikan | Dalam cakupan? |
|---|---|---|---|
| A1 | Penyerang jaringan tanpa autentikasi | Mengirim paket apa saja ke port terbuka, termasuk paket rusak, banjir, dan IP palsu | **Ya** |
| A2 | Penyerang di jalur (on-path) | Mengintip, mengulang (replay), dan mengubah paket di LAN | **Ya** (replay dan modifikasi); intip: TLS port 7780 di D9 (keputusan D8), UDP 7778 dan TCP 7779 tetap teks polos |
| A3 | Pengguna sah berperan rendah | Punya sesi login, mencoba melampaui perannya | **Ya** (D4: kunci read-only, daftar putih perintah) |
| A4 | Program user-space yang salah atau jahat | Memanggil syscall dengan argumen buruk | **Ya** |
| A5 | Penyedia data tak tepercaya | Image disk berisi FAT32/ELF yang dirancang jahat | **Ya** (parser harus tahan) |
| A6 | Penyerang jaringan pada layanan klien (DHCP, DNS, NTP) | Membalas permintaan kernel dengan data palsu | **Ya**, mulai Fase 5 |
| A7 | Penyerang fisik | Memegang mesin, mencabut disk, memasang perangkat USB | **Tidak** (lihat bagian 8) |
| A8 | Penyerang rantai pasok | Menyisipkan kode ke dependensi atau toolchain | Sebagian: library kripto dikunci versi dan sumbernya dicatat |

## 4. Batas kepercayaan dan permukaan serangan

```
Jaringan (tidak tepercaya)
   │  frame Ethernet
   ▼
Driver NIC ──► ARP / IPv4 / ICMP / UDP / TCP ──► Protokol perintah (UDP 7778, login TCP 7779 sejak D1)
                                                       │
                                            ┌──────────┴──────────┐
                                            ▼                     ▼
                                    Perintah baca        Perintah berprivilege
                                                          (hanya setelah HMAC + nonce valid)

Penyimpanan (tidak tepercaya) ──► parser FAT32 ──► loader program ──► user mode ──► syscall ──► kernel
```

Parser adalah permukaan serangan terbesar karena memproses byte dari luar:

| Permukaan | Risiko utama | Pertahanan yang ada / direncanakan |
|---|---|---|
| Parser ARP/IP/ICMP/UDP | Baca di luar batas, panjang palsu | Validasi panjang ketat; fuzzing (R7) |
| Parser TCP + mesin keadaan | Banjir SYN, keadaan menggantung, nomor urut | Batas tabel, timeout (C5), aritmetika nomor urut bertanda, retransmisi terbatas (5x lalu RST, C3c), setiap keadaan penutupan punya batas waktu (C3d), batas 2000 segmen/s per koneksi dan 10 ACK duplikat/s (C4), tabel 4 TCB, maks 2 per IP, SYN_RCVD tertua digusur saat penuh (C5a), timeout hanya diperpanjang kemajuan, bukan ACK duplikat/keepalive/SYN ulang/RST salah (C5b) |
| Protokol perintah | Replay, penebakan nonce, banjir CHAL | HMAC-SHA256, nonce sekali pakai, tabel nonce 16 slot, maks 4 per IP, batas laju per IP dan global |
| Login + shell TCP 7779 (D1, D2) | Replay bukti login/perintah, tebak HMAC, sesi menggantung, baris raksasa, sisip segmen setelah login, keluaran besar menahan memori | Nonce per koneksi dari DRBG, pesan "<nonce> tcp-login" dan "<nonce> tcp-cmd <n> <perintah>" berbeda dari UDP dan satu sama lain, 1 percobaan login per koneksi lalu FIN, login maks 10 s, baris maks 128 byte, perbandingan ct_memeq; D2: tiap perintah ditandatangani dengan nomor urut per koneksi (perintah sisipan/diulang/diubah -> ERR lalu FIN), keluaran maks 1432 byte per koneksi (statis), baris berikut tidak dibaca sampai keluaran habis; D4: peran dari kunci (KEYRO.TXT = read-only, daftar putih perintah, perintah ditandatangani kunci peran), maks 2 koneksi 7779, sesi login ditutup 300 s tanpa perintah sah. Balasan tidak ditandatangani dan teks polos (D8) |
| Nonce | Nonce dapat ditebak melemahkan challenge-response | Modul entropi + HMAC-DRBG (F1.8); menolak jika entropi belum cukup |
| Parser FAT32 | Struktur disk rusak | D6: validasi BPB lengkap (512 B/sektor, SPC 1/2/4/8, NumFATs 1..2, reserved > 0, area data dan FAT cukup untuk jumlah cluster, RootCluster sah), setiap nomor cluster dicek 2..max, rantai melingkar dideteksi, poll AHCI ber-timeout, kode error bukan halt |
| Tulis FAT32 (D6, D7) | Perintah tulis/hapus/ganti nama merusak volume, menimpa atau menghapus kunci/program boot, crash di tengah tulis | Hanya admin (HMAC), hanya root dir, nama 8.3, KEY.TXT/KEYRO.TXT/PROG.BIN ditolak untuk semua perintah (juga sebagai nama tujuan `ganti`), CONFIG.CFG/.TMP hanya lewat `set`, file maks 4096 byte, entri ber-LFN ditolak, semua cek sebelum tulis pertama, urutan data -> FAT -> dir -> bebaskan lama -> FSInfo dengan flush; hapus: entri dulu lalu rantai; ganti isi atomik lewat file sementara + satu tulis sektor (uji crash di setiap tulisan, `make host-test`), error I/O -> baca saja |
| Konfigurasi persisten (D7) | File CONFIG.CFG rusak/dimanipulasi lewat disk, nilai yang melemahkan batas, crash saat `set` | Parser ketat: satu baris salah -> seluruh file ditolak, semua default (= nilai sebelum D7); rentang dibatasi (udp_rate maks 100 = batas global, cli_idle 30..3600); IP tidak bisa diatur; `set` hanya admin, tercatat di audit; tulis atomik lewat file sementara; nilai RAM berubah hanya bila tersimpan |
| Loader program | Biner jahat | NX, isolasi per task, validasi header sebelum dimuat |
| Syscall | Pointer jahat dari user mode | Validasi pointer (R6) |
| Klien DHCP/DNS/NTP | Balasan palsu | Validasi ID transaksi, batas ukuran, jangan percaya buta (P3) |
| Jalur OTA | Kernel palsu | Tanda tangan digital + slot A/B + rollback (P7) |

## 5. Properti keamanan yang dituju

| Properti | Status saat ini | Rencana |
|---|---|---|
| Keaslian perintah (hanya pemegang kunci yang bisa memerintah) | Ada: HMAC-SHA256 + nonce | Pertahankan |
| Anti-replay | Ada: nonce sekali pakai | Uji adversarial (R7) |
| Ketahanan terhadap banjir paket | Sebagian: batas laju, batas nonce, boot aman tanpa NIC | C5, firewall (P4) |
| Kerahasiaan balasan | **Tidak ada** (teks polos); D8 memutuskan TLS 1.2 BearSSL di port 7780 | D9 |
| Isolasi user/kernel | Ada: user mode, NX | R6, SMEP/SMAP bila CPU mendukung |
| Entropi nonce | Ada (F1.8): kolam SHA-256 + HMAC-DRBG, tolak sebelum 256 bit; rdseed/rdrand dipercaya | Nilai ulang jitter di perangkat keras asli (H0) |
| Otorisasi berbasis peran | Ada (D4): admin/read-only per kunci, hanya TCP 7779 | Kunci per pengguna (D7) |
| Audit | Ada (D5): ring RAM (ok 16, gagal 8; banjir gagal tidak menimpa ring ok), IP:port + peran + perintah + tick, juga ke serial; baca `audit` hanya admin | Waktu nyata (P3), persisten (R4) |
| Integritas update | Belum ada OTA | P7 |

## 6. Keterbatasan yang diketahui (diterima sementara)

1. Batas laju per IP bisa dikelabui dengan IP sumber palsu. Segmen yang memalsukan 4-tuple koneksi TCP
   aktif (IP + kedua port) memakai batas per koneksi 2000/s, bukan 20/s per IP (C4); balasannya dibatasi
   10 ACK/s, dan data hanya diterima bila nomor urutnya tepat.
2. Banjir CHAL dari 16 IP palsu atau lebih masih dapat menggusur nonce sah (denial of service ringan,
   bukan pembobolan autentikasi).
3. Balasan perintah berupa teks polos: penyerang di jalur bisa membaca, tetapi tidak bisa memalsukan perintah.
4. Tabel TCP 4 koneksi, maks 2 per IP (C5a): klien dari 2 IP atau lebih yang tetap aktif bisa memenuhi tabel
   (koneksi tanpa kemajuan ditutup setelah 30 s, C5b; peer yang mengirim 1 byte tiap < 30 s tetap bisa
   menahan slot karena belum ada batas umur koneksi). Banjir SYN dari banyak IP palsu hanya menggusur SYN_RCVD, tetapi
   bisa mengganggu handshake klien sah (dia mengulang SYN) sampai SYN cookie (C5c).
5. Kunci HMAC tersimpan di mesin dan di klien. Penyerang yang mendapat salah satunya mendapat kendali.
6. Entropi (F1.8): rdseed/rdrand dipercaya penuh (CPU atau hypervisor jahat bisa mengatur nonce). Tanpa
   itu, kredit jitter adalah perkiraan kasar; di VM jitter bisa diatur hypervisor.
7. Audit (D5) hanya di RAM (hilang saat reboot; salinan di serial) dan memakai tick, bukan waktu nyata.
   "Siapa" = IP:port + peran (kunci per peran, bukan per pengguna); IP UDP bisa dipalsukan, tetapi entri
   ring ok selalu butuh HMAC sah. Pemegang kunci sah (juga read-only) bisa mendorong entri lama keluar ring ok.

8. Tulis FAT32 (D6, D7): pemegang kunci admin bisa mengisi disk (maks 4096 byte per file, root dir saja) dan
   menimpa, menghapus, atau mengganti nama file biasa mana pun selain kunci dan PROG.BIN. Ganti isi atomik
   (D7) menganggap tulis satu sektor atomik.

9. Konfigurasi (D7): pemegang kunci admin bisa melonggarkan batas laju per IP (maks 100/s = batas global) dan
   memperpanjang sesi idle (maks 1 jam). Siapa pun yang bisa menulis disk secara langsung bisa mengubah
   CONFIG.CFG dalam rentang yang sah (disk tidak ditandatangani). Urutan tulis mengandalkan FLUSH CACHE perangkat;
   perangkat yang mengabaikan flush bisa mengubah urutan. Crash meninggalkan lost cluster sampai fsck.

## 7. Aturan pengembangan yang menurunkan risiko

- Semua panjang dari luar divalidasi **sebelum** dipakai untuk mengindeks atau menyalin.
- Setiap tabel atau buffer punya batas atas tertulis dan perilaku saat penuh (tolak, bukan crash).
- Gagal tertutup (fail-closed): kondisi tak jelas berarti menolak.
- Perbandingan rahasia (HMAC, nonce) waktu-konstan: selalu lewat `ct_memeq` (F1.9), yang kode mesinnya
  dicek di `make test`.
- Jangan menulis primitif kripto sendiri selain komposisi di atas HMAC-SHA256 yang sudah ada; sisanya library teruji.
- Log tidak memuat kunci, nonce penuh, atau isi rahasia. Log serial dibatasi lajunya.
- Setiap parser baru wajib punya uji unit di host dengan sanitizer dan masuk daftar fuzzing.
- Perubahan yang menyentuh bagian 4 atau 5 harus memperbarui dokumen ini di commit yang sama atau berikutnya.

## 8. Di luar cakupan (sengaja tidak dilindungi)

- **Penyerang fisik** (A7): siapa pun yang memegang mesin dapat membaca disk, mengambil kunci HMAC, atau
  memasang perangkat. Tidak ada enkripsi disk dan tidak ada boot terverifikasi (Secure Boot) saat ini.
- Serangan kanal-samping tingkat CPU (Spectre/Meltdown dan sejenisnya).
- Kompromi firmware UEFI atau bootloader.
- Serangan pada komputer klien (tempat `bmctl.py` berjalan).
- Anonimitas dan kerahasiaan metadata lalu lintas.

Jika mesin ditempatkan di lokasi yang tidak aman secara fisik, putuskan ulang bagian ini sebelum dipakai.

## 9. Pertanyaan terbuka

| Pertanyaan | Dikunci di tahap |
|---|---|
| Di mana kunci HMAC disimpan dan bagaimana diganti? | D8: file di disk, ganti saat VM mati; ganti jarak jauh setelah D9 |
| Perlukah satu kunci per pengguna/peran? | D4: satu kunci per peran (admin, read-only); per pengguna menyusul D5/D7 |
| Enkripsi lewat SSH atau lapisan sendiri di atas library teruji? | D8: TLS 1.2 BearSSL (DECISIONS 2026-10-13) |
| Perlukah Secure Boot untuk mesin yang dipakai? | H0 |
| Apakah jaringan tempat mesin berada dianggap tepercaya sebagian? | Sebelum P4 |

## 10. Peninjauan

Tinjau dokumen ini di akhir setiap fase dan setelah setiap temuan keamanan. Catat perubahan besar di
`DECISIONS.md`.

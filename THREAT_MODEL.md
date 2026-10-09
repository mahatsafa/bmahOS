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
| A2 | Penyerang di jalur (on-path) | Mengintip, mengulang (replay), dan mengubah paket di LAN | **Ya** (replay dan modifikasi); intip hanya setelah D8 |
| A3 | Pengguna sah berperan rendah | Punya sesi login, mencoba melampaui perannya | **Ya** (setelah D4) |
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
Driver NIC ──► ARP / IPv4 / ICMP / UDP / TCP ──► Protokol perintah (UDP 7778, nanti TCP)
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
| Parser TCP + mesin keadaan | Banjir SYN, keadaan menggantung, nomor urut | Batas tabel, timeout (C5), aritmetika nomor urut bertanda |
| Protokol perintah | Replay, penebakan nonce, banjir CHAL | HMAC-SHA256, nonce sekali pakai, tabel nonce 16 slot, maks 4 per IP, batas laju per IP dan global |
| Nonce | Nonce dapat ditebak melemahkan challenge-response | Modul entropi + HMAC-DRBG (F1.8); menolak jika entropi belum cukup |
| Parser FAT32 | Struktur disk rusak | Validasi BPB (RootEntryCount==0 dan FATSz16==0), batas jumlah sektor, kode error bukan halt |
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
| Kerahasiaan balasan | **Tidak ada** (teks polos) | D8 |
| Isolasi user/kernel | Ada: user mode, NX | R6, SMEP/SMAP bila CPU mendukung |
| Entropi nonce | **Belum teruji** | F1.8 |
| Otorisasi berbasis peran | Belum | D4 |
| Audit | Belum | D5 |
| Integritas update | Belum ada OTA | P7 |

## 6. Keterbatasan yang diketahui (diterima sementara)

1. Batas laju per IP bisa dikelabui dengan IP sumber palsu.
2. Banjir CHAL dari 16 IP palsu atau lebih masih dapat menggusur nonce sah (denial of service ringan,
   bukan pembobolan autentikasi).
3. Balasan perintah berupa teks polos: penyerang di jalur bisa membaca, tetapi tidak bisa memalsukan perintah.
4. Satu koneksi TCP: satu klien bisa menahan port 7 (diperbaiki di C3/C5).
5. Kunci HMAC tersimpan di mesin dan di klien. Penyerang yang mendapat salah satunya mendapat kendali.

## 7. Aturan pengembangan yang menurunkan risiko

- Semua panjang dari luar divalidasi **sebelum** dipakai untuk mengindeks atau menyalin.
- Setiap tabel atau buffer punya batas atas tertulis dan perilaku saat penuh (tolak, bukan crash).
- Gagal tertutup (fail-closed): kondisi tak jelas berarti menolak.
- Perbandingan rahasia (HMAC, nonce) waktu-konstan.
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
| Di mana kunci HMAC disimpan dan bagaimana diganti? | D7 |
| Perlukah satu kunci per pengguna/peran? | D4 |
| Enkripsi lewat SSH atau lapisan sendiri di atas library teruji? | D8 |
| Perlukah Secure Boot untuk mesin yang dipakai? | H0 |
| Apakah jaringan tempat mesin berada dianggap tepercaya sebagian? | Sebelum P4 |

## 10. Peninjauan

Tinjau dokumen ini di akhir setiap fase dan setelah setiap temuan keamanan. Catat perubahan besar di
`DECISIONS.md`.

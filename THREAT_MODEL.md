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
| A2 | Penyerang di jalur (on-path) | Mengintip, mengulang (replay), dan mengubah paket di LAN | **Ya** (replay dan modifikasi); intip: TLS 1.2 port 7780 (D9); UDP 7778 dan TCP 7779 teks polos (bisa dibatasi/dimatikan lewat `udp_admin`/`cli_plain`) |
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
Driver NIC ──► ARP / IPv4 / ICMP / UDP / TCP ──► Protokol perintah (UDP 7778, TCP 7779 sejak D1, TLS 7780 sejak D9)
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
| TLS 7780 (D9, BearSSL) | Parser record/handshake (ClientHello, alert), sertifikat palsu, downgrade, banjir handshake (CPU), kebocoran kunci sesi | Pustaka teruji (BearSSL, constant-time, tanpa alokasi), versi dipatok + test_crypto upstream di host-test; hanya TLS 1.2 dan 2 suite AEAD ECDHE (forward secrecy), tanpa renegosiasi/resumption; klien mem-pin sha256 sertifikat; maks 2 TCB 7780, slot statis dihapus saat lepas; error -> RST; login HMAC tetap di dalam TLS. Belum: batas laju handshake per IP selain batas SYN umum |
| Nonce | Nonce dapat ditebak melemahkan challenge-response | Modul entropi + HMAC-DRBG (F1.8); menolak jika entropi belum cukup |
| Parser FAT32 | Struktur disk rusak | D6: validasi BPB lengkap (512 B/sektor, SPC 1/2/4/8, NumFATs 1..2, reserved > 0, area data dan FAT cukup untuk jumlah cluster, RootCluster sah), setiap nomor cluster dicek 2..max, rantai melingkar dideteksi, poll AHCI ber-timeout, kode error bukan halt |
| Tulis FAT32 (D6, D7) | Perintah tulis/hapus/ganti nama merusak volume, menimpa atau menghapus kunci/program boot, crash di tengah tulis | Hanya admin (HMAC), hanya root dir, nama 8.3, KEY.TXT/KEYRO.TXT/PROG.BIN ditolak untuk semua perintah (juga sebagai nama tujuan `ganti`), CONFIG.CFG/.TMP hanya lewat `set`, file maks 4096 byte, entri ber-LFN ditolak, semua cek sebelum tulis pertama, urutan data -> FAT -> dir -> bebaskan lama -> FSInfo dengan flush; hapus: entri dulu lalu rantai; ganti isi atomik lewat file sementara + satu tulis sektor (uji crash di setiap tulisan, `make host-test`), error I/O -> baca saja |
| Konfigurasi persisten (D7) | File CONFIG.CFG rusak/dimanipulasi lewat disk, nilai yang melemahkan batas, crash saat `set` | Parser ketat: satu baris salah -> seluruh file ditolak, semua default (= nilai sebelum D7); rentang dibatasi (udp_rate maks 100 = batas global, cli_idle 30..3600); IP tidak bisa diatur; `set` hanya admin, tercatat di audit; tulis atomik lewat file sementara; nilai RAM berubah hanya bila tersimpan |
| Packet filter (P4) | Aturan salah mengunci admin, FILTER.CFG dimanipulasi lewat disk, aturan dilewati dengan IP palsu | Parser ketat (satu baris salah -> tanpa aturan + catatan serial), maks 16 aturan statis, hanya admin yang mengubah (tercatat di audit), tulis atomik lewat FILTER.TMP, FILTER.CFG dilindungi dari `tulis`/`hapus`; TCP 7780 selalu lolos; hanya koneksi baru yang diperiksa |
| Netconsole UDP (R2) | Log polos di LAN, tujuan dibelokkan lewat ARP palsu, banjir log | Bawaan mati; hanya baris ring log (tanpa AUDIT, tanpa register umum panic, tanpa teks perintah/kunci); tujuan hanya di /24 sendiri; antrean statis 4 KB, maks 20 datagram/s, penuh -> baris dibuang + penanda; tidak ada data masuk yang diproses selain ARP dari IP tujuan |
| Loader program | Biner jahat | NX, isolasi per task, validasi header sebelum dimuat |
| Syscall | Pointer jahat dari user mode | Validasi pointer (R6) |
| Soket UDP user (P5-1) | Program user menghabiskan soket/antrean, mengirim ke mana saja, membaca port sistem; datagram jaringan ke program | Maks 4 soket statis, antrean 4 x 1472 per soket (penuh -> buang), fd hanya milik task pembuat dan ditutup saat task mati; bind hanya 1024..49151 selain port sistem; kirim hanya ke /24 sendiri (bukan .0/.255/diri sendiri), maks 1472 byte, lewat net task; semua pointer user dicek (buf, cap, alamat 8 byte writable); datagram masuk lewat filter P4, batas laju UDP per IP + global, dan checksum seperti port sistem |
| Klien SNTP (P3-2), DNS (P3-3), DHCP (belum) | Balasan palsu menggeser jam / meracuni cache, parser nama DNS (pointer kompresi) | SNTP dan DNS hanya atas perintah admin, server di /24 sendiri, port sumber acak, SNTP: nonce 8 byte (transmit = originate), mode/versi/LI/stratum dicek; DNS: ID acak, pertanyaan harus identik, nama answer hanya dilompati (pointer tidak diikuti), batas label/panjang, cache statis 8 entri dengan TTL 5..3600 s; balasan lain diabaikan dan dihitung, batas waktu 3 s |
| Jalur OTA | Kernel palsu | Tanda tangan digital + slot A/B + rollback (P7) |

## 5. Properti keamanan yang dituju

| Properti | Status saat ini | Rencana |
|---|---|---|
| Keaslian perintah (hanya pemegang kunci yang bisa memerintah) | Ada: HMAC-SHA256 + nonce | Pertahankan |
| Anti-replay | Ada: nonce sekali pakai | Uji adversarial (R7) |
| Ketahanan terhadap banjir paket | Sebagian: batas laju, batas nonce, boot aman tanpa NIC | C5, firewall (P4) |
| Kerahasiaan balasan | Ada lewat TLS 1.2 port 7780 (D9); UDP 7778 dan TCP 7779 tetap teks polos kecuali dimatikan (`cli_plain=0`, `udp_admin=0` = UDP hanya baca) | Matikan 7779 setelah klien pindah |
| Isolasi user/kernel | Ada: user mode, NX, validasi pointer syscall + batas len (R6-1), fault user hanya menghentikan task, guard page stack kernel/user (R6-2) | SMEP/SMAP bila CPU mendukung, fuzzing (R7) |
| Entropi nonce | Ada (F1.8): kolam SHA-256 + HMAC-DRBG, tolak sebelum 256 bit; rdseed/rdrand dipercaya | Nilai ulang jitter di perangkat keras asli (H0) |
| Otorisasi berbasis peran | Ada (D4): admin/read-only per kunci, TCP 7779 dan TLS 7780 | Kunci per pengguna |
| Audit | Ada (D5): ring RAM (ok 16, gagal 8; banjir gagal tidak menimpa ring ok), IP:port + peran + perintah + tick, juga ke serial; baca `audit` hanya admin. Log persisten R4 sengaja TIDAK memuat baris AUDIT (bisa dibaca read-only) | Waktu nyata (P3); audit persisten terpisah (khusus admin) bila dibutuhkan |
| Integritas update | Belum ada OTA | P7 |

## 6. Keterbatasan yang diketahui (diterima sementara)

1. Batas laju per IP bisa dikelabui dengan IP sumber palsu. Segmen yang memalsukan 4-tuple koneksi TCP
   aktif (IP + kedua port) memakai batas per koneksi 2000/s, bukan 20/s per IP (C4); balasannya dibatasi
   10 ACK/s, dan data hanya diterima bila nomor urutnya tepat.
2. Banjir CHAL dari 16 IP palsu atau lebih masih dapat menggusur nonce sah (denial of service ringan,
   bukan pembobolan autentikasi).
3. Balasan perintah di UDP 7778 dan TCP 7779 berupa teks polos: penyerang di jalur bisa membaca, tetapi tidak
   bisa memalsukan perintah. TLS 7780 (D9) merahasiakannya; kedua jalur lama tetap aktif sampai pengguna
   mengatur `cli_plain=0`/`udp_admin=0`.
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

10. TLS 7780 (D9): hanya TLS 1.2 (tanpa TLS 1.3); sertifikat self-signed di-pin (ganti kunci = semua klien
   mengganti pin); kunci privat TLS tersimpan polos di disk (seperti KEY.TXT); handshake (ECDHE + ECDSA)
   dihitung sinkron di net task, jadi banjir handshake memperlambat semua jaringan (dibatasi 2 TCB 7780 dan
   batas SYN per IP); pengaman `cli_plain` membuat penulis disk bisa menyalakan 7779 dengan menghapus file TLS.

11. Panic (R1): exception di kernel me-reboot sistem. Sejak R6-1 exception dari user mode hanya
   menghentikan task itu (NMI/#DF/#MC tetap panic). Dump register di serial bisa memuat sisa nilai rahasia di
   register (serial = akses fisik/hypervisor, di luar cakupan penyerang jaringan). Perintah uji `panic`
   hanya ada di build dev dan hanya untuk admin.

12. Netconsole (R2, bila `netcon=1`): isi log (IP klien, port, kode tolak, alamat kernel di trace panic)
   terlihat oleh siapa pun di LAN. MAC tujuan dipelajari dari ARP tanpa autentikasi: penyerang di LAN bisa
   membelokkan log ke dirinya (yang toh bisa ia sadap) atau membuatnya hilang. Netconsole bukan saluran
   tepercaya untuk audit.
13. Watchdog (R5) perangkat lunak: net task yang macet > 10 s (loop, deadlock, I/O tak selesai) memicu
   panic + reboot, jadi penyerang yang bisa membuat net task macet mendapat reboot (bukan macet permanen).
   Macet dengan interrupt mati tidak terdeteksi (tick ikut berhenti) sampai watchdog perangkat keras (H6).
   Pekerjaan sah yang menahan net task > 10 s (mis. handshake TLS di CPU sangat lambat) juga me-reboot;
   jeda terpanjang terlihat di `wd_gap_max`.
14. Packet filter (P4): aturan berdasarkan IP sumber yang bisa dipalsukan di LAN; bawaan izinkan; TCP 7780
   tidak bisa difilter; koneksi yang sudah berjalan tidak disentuh aturan baru; FILTER.CFG rusak = tanpa
   aturan (gagal-terbuka, demi akses admin). ICMP tanpa batas laju kecuali lewat aturan `izinkan icmp ...
   laju N`.
15. SNTP (P3-2): tanpa autentikasi NTP; penyerang di LAN yang bisa membaca permintaan (nonce + port) bisa
   membalas lebih dulu dan menggeser jam. Jam hanya dipakai untuk tampilan `waktu` (belum untuk log, sertifikat,
   atau keputusan keamanan).
16. DNS (P3-3): tanpa DNSSEC; penyerang di LAN yang membaca query (ID + port) bisa memasukkan jawaban palsu ke
   cache. Hasil DNS hanya ditampilkan (belum dipakai untuk koneksi keluar).
17. Pemantau ping (P6-1): balasan echo dicocokkan dengan IP target, id, dan seq (16 bit), jadi penyerang di LAN
   yang menyadap bisa memalsukan status NAIK; status hanya informasi (tidak memicu tindakan).
18. Pantau tcp/dns + syslog (P6-2): SYN probe hanya ke /24 sendiri dan hanya diatur admin; SYN-ACK dibalas RST
   (tanpa koneksi). Hasil dns tanpa DNSSEC (sama dengan P3-3). Pesan syslog teks polos lewat UDP tanpa autentikasi:
   isinya (IP target + keadaan) terbaca di LAN dan pesan palsu bisa dikirim ke penerima, jadi penerima tidak boleh
   menganggapnya bukti. Antrean pesan terbatas 8; tanpa tujuan syslog tidak ada yang dikirim.
19. DHCP (P3-4, hanya bila `dhcp=1`): server DHCP palsu di LAN bisa memberi alamat lain atau NAK (perangkat
   pindah alamat / kehilangan alamat sampai jatuh ke IP statis 30 s kemudian); xid 32 bit acak mencegah
   pemalsuan buta, tidak mencegah penyerang yang membaca broadcast DISCOVER/REQUEST. Hanya alamat /24 yang
   diterima, router/DNS tidak dipakai, jadi lalu lintas tidak bisa dibelokkan ke luar /24 lewat DHCP.
   Kunci HMAC/TLS tetap melindungi perintah walau alamat dibajak. Bawaan `dhcp=0`.
20. Soket UDP user (P5-1): tanpa autentikasi di tingkat soket (urusan program); siapa pun di LAN bisa mengirim
   ke port program dan mengisi antreannya (4 datagram, sisanya dibuang). Program bisa mengirim UDP ke host mana
   pun di /24 dan membuat ARP request (maks 3 per kirim). Cache MAC soket bisa diracuni ARP palsu untuk alamat
   yang sedang ditunggu (sama dengan modul lain). Belum ada izin per program: setiap task user boleh membuat soket.

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

# bmahOS Roadmap

Dokumen ini adalah peta kerja resmi bmahOS. Status per **2026-10-09**.
Aturan pakai: kerjakan **satu tahap per sesi**, satu tahap = satu commit (atau beberapa commit kecil yang
semuanya milik tahap itu). Jangan lompat tahap tanpa alasan tertulis di `DECISIONS.md`.

## 1. Arah dan batasan

Target jangka panjang: server headless 24/7 untuk administrasi jarak jauh, jaringan, dan pemantauan.

Keputusan yang berlaku saat ini:

- Pengembangan dan pengujian di VM (QEMU untuk `make test`, VMware untuk uji manual).
- **HP Stream 11 tetap menjalankan Debian sebagai server.** bmahOS dipasang di perangkat keras asli
  hanya setelah ada mesin lain yang cocok. Karena itu, target perangkat keras asli **belum ditetapkan**
  dan Fase 6 ditunda sampai mesinnya ada.
- Fakta HP Stream (dari pengecekan di Debian): satu-satunya NIC adalah Wi-Fi Realtek RTL8723BE, tidak ada
  Ethernet kabel, kontroler USB hanya Intel xHCI. Artinya driver E1000 tidak berlaku di sana dan Wi-Fi
  tidak realistis ditulis sendiri.
- IoT/robotika **bukan** target untuk ditulis. bmahOS cukup mampu menjalankan beban kerja IoT lewat
  socket API dan program user-space (lihat Fase 5).
- Kripto: jangan menulis primitif sendiri selain yang sudah ada dan teruji (HMAC-SHA256). Enkripsi,
  tanda tangan, dan TLS memakai library yang sudah teruji.

## 2. Garis finis

| Kode | Arti | Bukti lulus |
|---|---|---|
| **M-A** | Server matang di VM: TCP lengkap, login aman, shell, entropi benar, panic/log/metrik | `make test` hijau di CI, soak test 24 jam di VM tanpa kebocoran memori |
| **M-B** | Platform siap dipindah: DHCP/DNS/NTP, socket API, monitor jaringan, OTA A/B | Demo ujung-ke-ujung di VM |
| **M-C** | Hidup di perangkat keras asli pertama | Ping dan login dari komputer lain ke mesin nyata |
| **M-D** | Layak 24/7 di perangkat keras asli | Soak test 7 hari tanpa campur tangan |

## 3. Status saat ini

Sudah jadi dan terbukti (QEMU `make test` + VMware): boot Limine UEFI, GDT/TSS/IDT, PMM, VMM, heap,
scheduler preemptive 100 Hz, semaphore, user mode + syscall, AHCI (baca), FAT32 (baca), `spawn()` dari disk,
E1000 (ARP, IPv4, ICMP, UDP echo 7777, interrupt RX, task idle), perintah jarak jauh UDP 7778
(HMAC-SHA256 + nonce, `pping`, `reboot`), hardening tahap B (NX, batas laju, boot aman tanpa E1000),
PMM-0, RXO-1, M1 (tabel nonce 16 slot, maks 4 per IP), M2 (README), C0 (desain TCP), C1 (parsing TCP, RST),
C2 (listen port 7, handshake, terima data + ACK).

F1.4 selesai (2026-10-11): kernel.c dipecah jadi 17 modul, peta di `ARCHITECTURE.md`. F1.5 selesai (2026-10-11): laporan fitur CPU (`kernel/cpufeat.c`, `g_cpu`). F1.6 selesai (2026-10-11): `kprintf`/`ksnprintf`/`ASSERT` (`kernel/kprintf.c`). `make test` = 55 cek. F1.7 selesai (2026-10-12): `make host-test` (4 uji host, ASan + UBSan, juga di CI). F1.8 selesai (2026-10-12): `kernel/entropy.c`, kolam entropi + HMAC-DRBG. F1.9 selesai (2026-10-12): `ct_memeq`. **Fase 1 selesai.** C3a (2026-10-12): `kernel/ktimer.c`. C3b (2026-10-12): kirim data TCP. PIT-1 + C3c (2026-10-12): tick 100 Hz benar, retransmisi TCP. C3d (2026-10-12): penutupan TCP. C4 (2026-10-13): echo TCP 1 MB. C5a (2026-10-13): tabel 4 TCB. C5b (2026-10-13): timeout hanya diperpanjang kemajuan. C5c dilewati. D1 (2026-10-13): login TCP port 7779. D2 (2026-10-13): shell TCP. D3 (2026-10-13): klien `bmctl.py --tcp`. D4 (2026-10-13): peran read-only, maks 2 sesi CLI, idle sesi 300 s. D5 (2026-10-13): audit log (ring RAM ok 16 + gagal 8, `audit` khusus admin). D6 (2026-10-13): FAT32 tulis (root dir, file <= 4096 byte, `ls`/`baca`/`tulis`/`tambah` khusus admin, urutan tulis aman saat crash). D7 (2026-10-13): konfigurasi persisten `CONFIG.CFG` (ganti isi atomik lewat file sementara, `config`/`set`, `hapus`/`ganti`). Berikutnya D8.

## 4. Templat tahap

Setiap tahap di bawah dikerjakan dengan templat yang sama:

| Bagian | Isi |
|---|---|
| Tujuan | Satu kalimat |
| Perubahan | File dan modul yang disentuh |
| Uji otomatis | Cek baru di `make test` (jumlah cek harus naik) |
| Uji manual | QEMU, VMware, atau perangkat keras |
| Batasan yang diterima | Hal yang sengaja belum ditangani, dicatat di bagian "Batasan" |
| Kriteria lulus | Daftar centang yang bisa dibuktikan |

Aturan: refactor (rapikan struktur tanpa ubah perilaku) dan fitur **tidak boleh** berada di commit yang sama.
Setiap tabel/struktur punya batas atas tertulis dan perilaku saat penuh (tolak, bukan crash).

## 5. Fase

Format ID: `Fase.Nomor`. Centang `[x]` saat lulus dan sudah di-push.

### Fase 1: Fondasi (sebelum fitur baru)

- [x] **F1.1** Commit + push C2 (37172c1, 2026-10-09).
- [x] **F1.2** `LICENSE` (pilih lisensi, catat di `DECISIONS.md`) dan `CONTRIBUTING.md` singkat.
- [x] **F1.3** CI (9b9489c, hijau di GitHub 2026-10-09) CI GitHub Actions menjalankan `make test`. Lulus: badge hijau di README.
- [x] **F1.4** (2026-10-11; modul: serial 9f672ac, cpu d9ff986, pmm d3e0017, vmm edce634, acpi 6653f1c, pic e4d4379, pci 261543d, apic 8c777e3, ahci ca8220d, fat32 8ab9e9d, e1000 6bd7884, crypto d939662, net 0d295d3, auth 3d76f29, sched c9f2891, cmd 25729d3, trap a1c8e31; peta: ARCHITECTURE.md) Pecah `kernel.c` menjadi modul, **satu modul per commit**, tanpa mengubah perilaku.
  Urutan aman: serial, cpu/gdt/idt, pmm, vmm, heap, sched, syscall, pci, ahci/fat32, net/{e1000,arp,ip,icmp,udp,tcp}, cmd.
  Lulus: `make test` tetap 50/50 setelah tiap commit.
- [x] **F1.5** (2026-10-11, make test 50 -> 53) Modul CPUID/fitur: laporan fitur CPU (rdrand, NX, SMEP/SMAP, APIC, dll.) di serial.
  Catatan: `nx_init` dan `priv_have_rdrand` masih memanggil CPUID sendiri; dialihkan ke `g_cpu` lewat refactor terpisah
  (paling lambat F1.8, yang butuh info rdrand/rdseed). Selesai di F1.8: `nx_init` memakai `g_cpu.nx`,
  `priv_have_rdrand` dihapus bersama generator nonce lama.
- [x] **F1.6** (2026-10-11, make test 53 -> 55) `kprintf` minimal (`%s %d %u %x %p`) dan `ASSERT()` yang mencetak file:baris.
  Juga `%c %%`, awalan `l` (64-bit), `ksnprintf` (semantik snprintf), atribut format printf, self-test 12 kasus,
  flag `ASSERTTEST=1`. Kode lama belum dialihkan ke `kprintf` (refactor terpisah bila perlu).
- [x] **F1.7** (2026-10-12, make host-test: crypto 18, kprintf 92, net 85, auth 56 cek) Uji unit di host Linux untuk fungsi murni (checksum, HMAC, parser paket), dikompilasi
  dengan `-fsanitize=address,undefined`. Lulus: target `make host-test` ada dan hijau.
  Juga parser perintah (`auth.c`), frame dipotong di semua panjang + fuzz acak, job CI `host-test`.
  Kernel tidak berubah (`kernel.elf` identik byte-per-byte, default dan PROD); guard `BMAHOS_HOST_TEST`
  di `kernel.h` hanya untuk cli/sti dan port I/O. Rincian di `ARCHITECTURE.md` bagian 6.
- [x] **F1.8** (2026-10-12, make test 55 -> 61 (PROD 60), host-test + test_entropy, VMware lulus) Modul entropi: pengumpul (rdrand bila CPUID mengizinkan, jitter TSC antar-interrupt, timing RX)
  ke kolam yang dicampur SHA-256, lalu HMAC-DRBG (NIST SP 800-90A) untuk nonce. Sebelum kolam cukup,
  perintah yang butuh nonce **menolak**. Lulus: nonce tidak berulang, uji statistik sederhana lulus,
  perilaku "belum cukup entropi" teruji. Catatan: di VM jitter cenderung teratur, jangan menganggap
  hasil VM mewakili perangkat keras asli.
  Hasil: `kernel/entropy.c`, self-test CAVP saat boot, flag `NOENTROPY=1` (mode tolak) dan `NORDRAND=1` (siap dari
  jitter, tick ~256 di QEMU). VMware (Zen 2): siap di tick 0 dari rdseed; estimator jitter mengkredit hampir tiap tick
  (2479 bit dalam 2478 tick), bukti bahwa kredit jitter di VM tidak bisa dipercaya sebagai ukuran entropi.
- [x] **F1.9** (2026-10-12, f5bcb5a, make test 61 -> 64, PROD 60 -> 63, VMware lulus) Audit perbandingan HMAC: pastikan waktu-konstan (tidak keluar lebih awal saat byte berbeda).
  Temuan: dua perbandingan HMAC di `auth.c` sudah akumulasi OR (waktu-konstan di sumber); pencarian nonce keluar
  (`break`) di slot yang cocok (bocor hanya posisi slot, bukan isi). Kernel dikompilasi tanpa `-O`, jadi kode mesin
  mengikuti sumber, tetapi itu tidak dijamin bila flag berubah. Perbaikan: `ct_memeq` (crypto.c; volatile, noinline,
  hasil tanpa cabang) dipakai di ketiga tempat, pencarian nonce memindai semua slot. Uji: self-test boot, cek statis
  kode mesin di `make test` (tepat 1 lompatan bersyarat, tanpa call; auth.o memanggil 3x), uji host semua panjang/bit.

### Fase 2: TCP selesai

- [x] **C3a** (2026-10-12, make test 64 -> 66, PROD 63 -> 65, VMware lulus: telat_maks 5 tick, sleep 20 -> 21) Timer API kernel (callback pada tick ke-N, bisa dibatalkan) dan `sleep`.
  `kernel/ktimer.c`: `ktimer_start/cancel/pending/run`, `ktimer_t` milik pemanggil (tanpa heap), senarai terurut
  deadline, callback di loop net task (konteks task, bukan IRQ). `sleep` sudah ada sebagai `task_sleep` (sched.c);
  C3a menambah uji ketepatannya. Self-test boot (urutan, batal, pasang ulang, telat <= 10 tick, sleep 20 -> 20..30 tick),
  metrics `ktimer_fired/cancelled/late_max`, uji host 64 cek (200 ribu operasi acak vs model).
- [x] **C3b** (2026-10-12, make test 66 -> 69, PROD 65 -> 68, VMware lulus: TcpClient Windows echo 15 + 1000 byte identik) Kirim data dari kernel dengan nomor urut. Bandingkan nomor urut dengan aritmetika bertanda
  `(int32_t)(a - b)`, bukan `a < b` (nomor berputar kembali ke 0).
  Hasil: buffer 1024 byte (`g_tcp_buf`), sumber data sementara = echo data yang diterima; jendela yang diiklankan =
  ruang kosong buffer; stop-and-wait (1 segmen belum di-ACK, <= MSS 536, <= jendela peer); ACK melewati `snd_nxt`
  dibalas ACK dan diabaikan, ACK lama diabaikan; `seq_lt`/`seq_le`. Metrics `tcp_tx_bytes`, `tcp_acked_bytes`.
  Uji host: putaran 2^32 (ISN kita dan peer), jendela 0/penuh/pembaruan, aliran 20 ribu byte utuh; rawnet: 600 byte
  -> 536 + 64. Belum: retransmisi (data hilang = macet sampai timeout 30 s), persist timer jendela 0, FIN kita.
- [x] **C3c** (2026-10-12, make test 70 -> 76, PROD 69 -> 75, VMware lulus: regresi echo 1000 byte, tcp_retx 0) Retransmisi: simpan segmen belum di-ACK, kirim ulang saat timer habis, RTO awal konstan lalu
  eksponensial. Uji dengan membuang paket sengaja.
  Hasil (aee254a): SYN-ACK dan byte `snd_una..snd_nxt` dikirim ulang langsung dari `g_tcp_buf` (tanpa salinan
  segmen), satu `ktimer_t`; RTO 100 tick, x2 sampai 800, maks 5 lalu RST; ACK yang memajukan `snd_una` mengembalikan
  RTO. Timeout diam 30 s tidak berlaku selama ada data belum di-ACK. Metrics `tcp_retx`, `tcp_retx_giveup`. Uji host
  (jeda 100/200/400/800/800, RST, ACK sebagian); rawnet membuang ACK: SYN-ACK ulang ~1 s, data ulang 1 s lalu 2 s.
  Retransmisi hanya terbukti di QEMU (Windows tidak bisa membuang ACK). Sebelumnya PIT-1 (c30e268): tick QEMU
  ternyata 200/s (PIT mode 3), kini mode 2 = 100/s. Belum: persist timer, FIN kita (C3d).
- [x] **C3d** (2026-10-12, make test 76 -> 87, PROD 75 -> 86, VMware lulus: TcpClient beruntun jeda 0,3 s, FIN setelah diam 30 s) Penutupan: FIN dua arah, TIME_WAIT pendek, RST untuk keadaan salah. Tidak ada koneksi tersangkut.
  Hasil (76ad896): FIN peer -> CLOSE_WAIT -> FIN|ACK setelah echo habis dan di-ACK (LAST_ACK) -> CLOSED, port langsung
  bebas. Diam 30 s dengan buffer kosong -> FIN (FIN_WAIT_1 -> FIN_WAIT_2 maks 10 s -> TIME_WAIT 2 s); CLOSING untuk tutup
  bersamaan. FIN dikirim ulang lewat timer C3c (5x lalu RST). Data setelah FIN peer/FIN kita -> RST; RST di TIME_WAIT
  diabaikan (RFC 1337). Setiap keadaan punya batas waktu atau retransmisi berujung RST. Metrics `tcp_close_ok`,
  `tcp_rst_state`, `tcp_state`. Belum: persist timer (data tertahan jendela 0 tetap RST setelah 30 s).
- [x] **C4** (2026-10-13, make test 87 -> 88, PROD 86 -> 87, VMware lulus: PowerShell 1 MB dalam 117 s, sha256 sama) Echo TCP port 7. Lulus: kirim 1 MB, terima 1 MB identik (bandingkan hash).
  Hasil (a1cc407): `tests/tcp-echo.py` (klien Linux lewat slirp, kirim dan terima bersamaan, SHA-256) di `make test`:
  QEMU ~31 s dev, ~11 s PROD. Segmen koneksi aktif tidak lagi kena batas UDP (20/s per IP, 100/s global), ganti batas
  per koneksi 2000 segmen/s; ACK untuk segmen yang tidak diterima maks 10/s (keputusan disetujui pengguna, DECISIONS).
  Interop: Windows TcpClient dan klien Python Linux lulus; `nc` Linux belum (CentOS tidak di VMnet2). Throughput
  rendah (stop-and-wait, satu segmen per RTT) sesuai desain C0.
- [x] **C5a** (2026-10-13, 785a7af + 5f83f7f, make test 88 -> 99, PROD 87 -> 98, VMware lulus) Batas SYN per sumber dan tabel koneksi terbatas.
  Hasil: refactor C5a-1 (785a7af, TCB jadi tabel 1 slot, perilaku sama) lalu fitur C5a-2 (5f83f7f): 4 TCB statis
  (buffer 1024 + timer per slot), maks 2 per IP sumber (lebih: RST, `tcp_src_full`), tabel penuh: SYN_RCVD tertua
  digusur tanpa RST (`tcp_synrcvd_evicted`), semua aktif: RST. Laju SYN tetap batas per IP 20/s + global 100/s
  (tabel laju SYN terpisah tidak dibuat, DECISIONS). Metrics `tcp_conn_active`. host-test net 195 -> 220.
  VMware: 2 koneksi bersamaan echo benar, ke-3 ditolak (Windows mengulang SYN 5x dalam 2,2 s). Penggusuran dan
  banjir SYN 20 IP hanya terbukti di QEMU (Windows satu IP).
- [x] **C5b** (2026-10-13, 191d616, make test 99 -> 101, PROD 98 -> 100, VMware lulus) Timeout koneksi menganggur dan setengah terbuka.
  Hasil: timeout C2/C3d sudah ada (SYN_RCVD 5 s, diam 30 s -> FIN, FIN_WAIT_2 10 s, TIME_WAIT 2 s,
  kirim ulang 5x -> RST), tetapi `last` diperbarui oleh segmen apa pun yang cocok 4-tuple, jadi ACK duplikat,
  keepalive, ACK jendela 0, SYN ulang, atau RST seq salah menahan slot tanpa batas. Kini hanya kemajuan
  (handshake, ACK memajukan snd_una, data baru, FIN peer) yang memperpanjang. make test 99 -> 101, PROD 98 -> 100,
  host-test net 220 -> 234. VMware: keepalive Windows tiap 5 s tidak menahan koneksi (FIN setelah 30 s);
  SYN ulang, RST seq salah, dan ACK jendela 0 hanya terbukti di QEMU/host-test.
- [ ] **C5c** (opsional) SYN cookie. Dilewati 2026-10-13 (disetujui pengguna; jaringan host-only, risiko kecil), lanjut Tahap D.

Keputusan yang harus tertulis sebelum C3b: segmen di luar urutan dibuang atau disimpan, dan ukuran window
yang diiklankan harus sama dengan buffer yang benar-benar ada. Uji interoperabilitas dengan Windows, `nc`
Linux, dan klien Python.

### Fase 3: Tahap D (login, shell, penyimpanan tulis)

- [x] **D1** (2026-10-13, c225ac9 + e17c168, make test 101 -> 104, PROD 100 -> 103, VMware lulus) Login challenge-response lewat TCP (memakai HMAC dan nonce yang sudah ada).
  Hasil: refactor D1-1 (c225ac9, `net_tcp_queue`) lalu fitur D1-2: port 7779, banner + nonce per koneksi, `login <hmac>`
  atas "<nonce> tcp-login", 1 percobaan, timeout 10 s, baris maks 128 byte, metrics `cli_login_*`/`cli_line_long`,
  `PROTOCOL.md`. make test 101 -> 104, PROD 100 -> 103 (`tests/tcp-login.py`), host-test net 234 -> 260, auth 59 -> 67.
- [x] **D2** (2026-10-13, 6d883fb, make test 104 -> 106, PROD 103 -> 105, VMware lulus) Shell baris perintah lewat TCP.
  Hasil: setelah login tiap baris `<perintah> <hmac>`, hmac atas "<nonce> tcp-cmd <n> <perintah>" (n = nomor urut per
  koneksi; disetujui pengguna, ganti usulan nonce per balasan). Salah -> ERR lalu FIN. Perintah sama dengan UDP + `exit`;
  keluaran per TCB (maks 1432 byte) dialirkan bertahap, diakhiri `END <n>`; `reboot` setelah keluaran di-ACK (cadangan
  2 s). host-test net 260 -> 300, auth 67 -> 86. VMware: bug reboot hilang saat Windows mengirim ACK + FIN satu segmen,
  diperbaiki sebelum commit. Reboot lewat TCP tidak diuji di QEMU (host-test + VMware).
- [x] **D3** (2026-10-13, 2fa4cc3, make test 106 -> 109, PROD 105 -> 108, VMware lulus) Klien `bmctl.py --tcp`.
  Hasil: sekali jalan (beberapa perintah dalam satu sesi lalu `exit`) dan interaktif (prompt bila tty, pipa = satu
  perintah per baris, EOF -> `exit`), kode keluar 0/1/2; `client/bmtcp.ps1` (PowerShell `bmtcp`/`bmt`/`bmtx`, HMAC .NET).
  Kernel tidak berubah. VMware: Python 3.13 di Windows + bmtcp.ps1 lulus; prompt tty belum diuji.
- [x] **D4** (2026-10-13, fb17f0c + 13b4025, make test 109 -> 117, PROD 108 -> 116, VMware lulus) Batas sesi (jumlah, idle timeout) dan peran (read-only vs admin).
  Hasil: peran = kunci (KEY.TXT admin, KEYRO.TXT read-only, hanya TCP 7779; `OK login ro`), read-only = daftar putih
  perintah (`ERR: peran read-only`, sesi tetap jalan); maks 2 TCB port 7779 (SYN_RCVD CLI tertua digusur, lainnya RST);
  sesi login ditutup 300 s setelah perintah sah terakhir, batas diam TCP 30 s tidak berlaku untuknya. host-test net
  300 -> 328, auth 86 -> 109. 13b4025 = perbaikan self-test timer C3a (commit terpisah). Batas 2 sesi dari IP berbeda
  hanya terbukti di QEMU/host-test (Windows satu IP).
- [x] **D5** Audit log: siapa menjalankan perintah apa, kapan (cap waktu menyusul di P3). (75634ee, 2026-10-13)
- [x] **D6** FAT32 tulis dengan aturan aman (validasi BPB, kode error bukan halt, urutan tulis FAT). (824aa4f + f873194 + 682969f, 2026-10-13)
- [x] **D7** (2026-10-13; KT-2 cb7f132, D7-1 8a55d19, D7-2 ae42e86, D7-3 bdc58cb; `CONFIG.CFG`, `config`/`set`, `hapus`/`ganti`) Konfigurasi persisten dengan penulisan atomik (tulis file sementara lalu rename).
- [x] **D8** (2026-10-13, f7d32ae) Keputusan kerahasiaan balasan: lapisan enkripsi dari library teruji, atau SSH. Catat di `DECISIONS.md`
  sebelum implementasi. Jangan merancang protokol kripto sendiri.
  Keputusan (2026-10-13): TLS 1.2 dengan BearSSL di port TCP 7780, sertifikat self-signed di-pin klien (DECISIONS).
- [x] **D9** (2026-10-14; D9a 9a5493e, D9b-1 5fea1d4, D9b-2 34cf14b, D9c 427d8af, D9d c83719a) TLS port 7780 (BearSSL, keputusan D8). Rencana dulu, lalu bertahap: D9a vendor BearSSL + build freestanding
  + uji host (vektor/handshake di host), D9b TLS server di net task (TCB 7780 membungkus protokol baris 7779,
  konteks statis per sesi), D9c klien `bmctl.py --tls` (pin sha256) + `bmtcp.ps1` (SslStream), D9d dokumen +
  keputusan nasib 7779/UDP. Lulus: QEMU sesi TLS dengan pin benar jalan, pin salah gagal, 7779 tetap; VMware
  Python + PowerShell; Wireshark tidak melihat teks perintah/balasan di 7780.

### Fase 4: Keandalan dan observabilitas

- [x] **R1** (2026-10-14, 3fa72c4 R1-1, 1fea8fe TSS-1, c9c5d71 R1-2; VMware lulus pf/df/ud/assert) Panic handler: cetak jenis error, RIP, register, stack trace (butuh `-fno-omit-frame-pointer`),
  lalu reboot otomatis setelah N detik. Double fault memakai IST di TSS.
- [ ] **R2** Netconsole UDP (jalur sederhana, tanpa heap).
- [ ] **R3** Registry metrik (satu tempat semua counter) dan perintah `bmctl metrics`: CPU, memori, uptime,
  statistik jaringan, jumlah koneksi.
- [ ] **R4** Log persisten berbentuk ring buffer di penyimpanan.
- [ ] **R5** Watchdog: perangkat lunak dulu. "Tepukan" dari task sehat, **bukan** dari interrupt timer.
  Watchdog perangkat keras menyusul setelah target perangkat keras diketahui.
- [ ] **R6** Validasi pointer di syscall, guard page di stack, kebijakan saat memori habis, penghitung
  alokasi vs pelepasan di metrik.
- [ ] **R7** Fuzzing parser paket di host (AFL++ atau libFuzzer) dan perbaiki temuan.
- [ ] **R8** Soak test 24 jam di VM: banjir paket, koneksi berulang, tanpa kebocoran memori. Laporan di `docs/`.

**Setelah R8 lulus: M-A tercapai.**

### Fase 5: Platform server

- [ ] **P1** Konsol framebuffer (request Limine, font bitmap 8x16, pakai `pitch` bukan lebar×4, baca mask
  warna) yang di-cermin dengan serial lewat `kprintf`. Berguna di VM dan wajib di mesin tanpa serial.
- [ ] **P2** Enumerasi PCI generik (tidak hardcode bus/dev/fn) dan parsing ACPI (RSDP, XSDT, MADT, HPET).
- [ ] **P3** DHCP client, DNS client + cache kecil, SNTP + RTC (cap waktu log yang benar).
- [ ] **P4** Packet filter: aturan port/IP/laju.
- [ ] **P5** Socket API untuk user mode agar program di disk bisa memakai TCP/UDP. Daftar syscall stabil
  dan terdokumentasi.
- [ ] **P6** Monitor jaringan sebagai task: ping, TCP-connect, DNS berkala, ambang "naik/turun", alert via syslog UDP.
- [ ] **P7** OTA A/B: dua slot kernel, verifikasi tanda tangan digital (library teruji), boot percobaan dengan
  penghitung, rollback otomatis. Syarat: R5 dan D6 selesai.

**Setelah P7 lulus: M-B tercapai.**

### Fase 6: Perangkat keras asli (ditunda sampai ada mesin)

- [ ] **H0** Tetapkan mesin target dan tulis `HARDWARE.md`. Kriteria yang disarankan: UEFI 64-bit, Ethernet
  kabel dengan chip yang umum (keluarga Intel e1000e/I210/I211/I219 atau Realtek RTL8111), penyimpanan
  SATA (AHCI sudah ada) atau NVMe, dan idealnya port serial. Cek dulu dengan Linux live USB:
  `cat /sys/firmware/efi/fw_platform_size`, `lspci -nn`, `lsusb`, `dmidecode`, `acpidump`.
- [ ] **H1** Boot Limine di mesin target dengan konsol framebuffer (P1) dan laporan CPUID.
- [ ] **H2** Driver NIC mesin target, diuji dulu dengan ping dari komputer lain.
- [ ] **H3** Driver penyimpanan mesin target jika bukan AHCI.
- [ ] **H4** APIC/timer di perangkat keras asli (LAPIC, IOAPIC, HPET) distabilkan.
- [ ] **H5** Login `bmctl.py` lewat kabel nyata. **M-C tercapai.**
- [ ] **H6** Watchdog perangkat keras (cek tabel ACPI WDAT/WDRT), pemantauan suhu, soak test 7 hari. **M-D tercapai.**

Catatan jika HP Stream 11 dipakai kelak: butuh driver xHCI + USB-Ethernet (mis. CDC-ECM atau RTL8152) dan
SDHCI untuk eMMC. Driver xHCI dan USB-Ethernet bisa dikembangkan di VM lebih dulu (QEMU menyediakan
`qemu-xhci` dan `usb-net`; VMware Workstation umumnya bisa meneruskan adaptor USB fisik ke VM).
Wi-Fi tidak direncanakan.

### Fase 7: Opsional, tanpa urutan

SSH, SMP (N2840 punya 2 core), IPv6, SMEP/SMAP bila CPU mendukung, slab allocator, prioritas task dan batas
sumber daya per task, Secure Boot, port library TLS.

## 6. Pengecualian IoT

Tidak ada tahap yang menulis driver USB-serial, MQTT, atau protokol mikrokontroler. Jika kelak ingin
menjalankan beban kerja IoT, cukup tulis program user-space di atas socket API (P5).

## 7. Batasan yang berlaku sekarang

- TCP: maks 4 koneksi, maks 2 per IP (C5a); stop-and-wait; belum persist timer dan SYN cookie (C5c).
  Timeout hanya diperpanjang kemajuan (C5b); peer yang mengirim 1 byte tiap < 30 s tetap bisa menahan slot
  (tanpa batas umur koneksi; diputuskan di D4).
- Batas laju per IP bisa dikelabui IP palsu; banjir CHAL dari 16 IP palsu atau lebih masih bisa menggusur nonce sah.
- Balasan perintah berupa teks polos (keaslian terjamin, kerahasiaan tidak) sampai D8.
- Hanya driver E1000 dan AHCI; belum berjalan di perangkat keras asli.

## 8. Dokumen pendamping

| Dokumen | Status |
|---|---|
| `THREAT_MODEL.md` | Ada |
| `DECISIONS.md` | Buat di F1.2, isi tiap keputusan: "memilih X karena Y, alternatif Z" |
| `ARCHITECTURE.md` | Ada sejak F1.4 (peta modul, alur boot, peta memori); perbarui bila modul berubah |
| `PROTOCOL.md` | Ada sejak D1 (UDP 7778, echo, login TCP 7779) |
| `HARDWARE.md` | Buat di H0 |
| `CHANGELOG.md` | Mulai saat rilis pertama |

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

F1.4 berjalan: modul 1 (serial) selesai di sisi Claude, menunggu commit. `make test` = 50 cek.

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
- [~] **F1.4** (modul selesai: serial) Pecah `kernel.c` menjadi modul, **satu modul per commit**, tanpa mengubah perilaku.
  Urutan aman: serial, cpu/gdt/idt, pmm, vmm, heap, sched, syscall, pci, ahci/fat32, net/{e1000,arp,ip,icmp,udp,tcp}, cmd.
  Lulus: `make test` tetap 50/50 setelah tiap commit.
- [ ] **F1.5** Modul CPUID/fitur: laporan fitur CPU (rdrand, NX, SMEP/SMAP, APIC, dll.) di serial.
- [ ] **F1.6** `kprintf` minimal (`%s %d %u %x %p`) dan `ASSERT()` yang mencetak file:baris.
- [ ] **F1.7** Uji unit di host Linux untuk fungsi murni (checksum, HMAC, parser paket), dikompilasi
  dengan `-fsanitize=address,undefined`. Lulus: target `make host-test` ada dan hijau.
- [ ] **F1.8** Modul entropi: pengumpul (rdrand bila CPUID mengizinkan, jitter TSC antar-interrupt, timing RX)
  ke kolam yang dicampur SHA-256, lalu HMAC-DRBG (NIST SP 800-90A) untuk nonce. Sebelum kolam cukup,
  perintah yang butuh nonce **menolak**. Lulus: nonce tidak berulang, uji statistik sederhana lulus,
  perilaku "belum cukup entropi" teruji. Catatan: di VM jitter cenderung teratur, jangan menganggap
  hasil VM mewakili perangkat keras asli.
- [ ] **F1.9** Audit perbandingan HMAC: pastikan waktu-konstan (tidak keluar lebih awal saat byte berbeda).

### Fase 2: TCP selesai

- [ ] **C3a** Timer API kernel (callback pada tick ke-N, bisa dibatalkan) dan `sleep`.
- [ ] **C3b** Kirim data dari kernel dengan nomor urut. Bandingkan nomor urut dengan aritmetika bertanda
  `(int32_t)(a - b)`, bukan `a < b` (nomor berputar kembali ke 0).
- [ ] **C3c** Retransmisi: simpan segmen belum di-ACK, kirim ulang saat timer habis, RTO awal konstan lalu
  eksponensial. Uji dengan membuang paket sengaja.
- [ ] **C3d** Penutupan: FIN dua arah, TIME_WAIT pendek, RST untuk keadaan salah. Tidak ada koneksi tersangkut.
- [ ] **C4** Echo TCP port 7. Lulus: kirim 1 MB, terima 1 MB identik (bandingkan hash).
- [ ] **C5a** Batas SYN per sumber dan tabel koneksi terbatas.
- [ ] **C5b** Timeout koneksi menganggur dan setengah terbuka.
- [ ] **C5c** (opsional) SYN cookie.

Keputusan yang harus tertulis sebelum C3b: segmen di luar urutan dibuang atau disimpan, dan ukuran window
yang diiklankan harus sama dengan buffer yang benar-benar ada. Uji interoperabilitas dengan Windows, `nc`
Linux, dan klien Python.

### Fase 3: Tahap D (login, shell, penyimpanan tulis)

- [ ] **D1** Login challenge-response lewat TCP (memakai HMAC dan nonce yang sudah ada).
- [ ] **D2** Shell baris perintah lewat TCP.
- [ ] **D3** Klien `bmctl.py --tcp`.
- [ ] **D4** Batas sesi (jumlah, idle timeout) dan peran (read-only vs admin).
- [ ] **D5** Audit log: siapa menjalankan perintah apa, kapan (cap waktu menyusul di P3).
- [ ] **D6** FAT32 tulis dengan aturan aman (validasi BPB, kode error bukan halt, urutan tulis FAT).
- [ ] **D7** Konfigurasi persisten dengan penulisan atomik (tulis file sementara lalu rename).
- [ ] **D8** Keputusan kerahasiaan balasan: lapisan enkripsi dari library teruji, atau SSH. Catat di `DECISIONS.md`
  sebelum implementasi. Jangan merancang protokol kripto sendiri.

### Fase 4: Keandalan dan observabilitas

- [ ] **R1** Panic handler: cetak jenis error, RIP, register, stack trace (butuh `-fno-omit-frame-pointer`),
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

- Satu koneksi TCP; setelah klien menutup, port 7 bebas lagi setelah timeout sementara 30 detik (diganti di C3/C5).
- Data TCP yang diterima dibuang setelah di-ACK sampai echo C4.
- Batas laju per IP bisa dikelabui IP palsu; banjir CHAL dari 16 IP palsu atau lebih masih bisa menggusur nonce sah.
- Balasan perintah berupa teks polos (keaslian terjamin, kerahasiaan tidak) sampai D8.
- Hanya driver E1000 dan AHCI; belum berjalan di perangkat keras asli.

## 8. Dokumen pendamping

| Dokumen | Status |
|---|---|
| `THREAT_MODEL.md` | Ada |
| `DECISIONS.md` | Buat di F1.2, isi tiap keputusan: "memilih X karena Y, alternatif Z" |
| `ARCHITECTURE.md` | Buat setelah F1.4 (peta modul, alur boot, peta memori) |
| `PROTOCOL.md` | Buat bersama D1 (format paket perintah) |
| `HARDWARE.md` | Buat di H0 |
| `CHANGELOG.md` | Mulai saat rilis pertama |

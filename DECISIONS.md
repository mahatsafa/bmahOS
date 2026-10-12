# DECISIONS

Format: memilih X karena Y, alternatif Z. Tambahkan di akhir; jangan menulis ulang yang lama.

## 2026-10-09 (catatan awal, dari riwayat proyek)
- **Lisensi MIT** (file LICENSE sejak 3868b98), karena proyek belajar yang ingin mudah dipakai ulang; alternatif GPL/Apache ditolak karena tidak ada kebutuhan paten atau copyleft.
- **Semua perintah jarak jauh lewat nonce (B2)**, jalur counter dimatikan, karena counter dari RTC rawan selisih jam dan tidak tahan replay setelah reboot; alternatif boot-id ditolak (round trip sama + protokol ketiga). `LEGACYCTR=1` menyalakan lagi hanya untuk uji.
- **Tabel nonce 16 slot, maks 4 per IP (M1)**, karena banjir CHAL satu IP tidak boleh menggusur klien sah; alternatif tabel per-IP terpisah ditolak (lebih kompleks). Batas: 16 IP palsu masih bisa menggusur.
- **TCP minimal (C0)**: satu koneksi, stop-and-wait, jendela 1024, MSS 536, RTO tetap, ISN dari SHA-256 pool nonce; alternatif tabel koneksi dan congestion control ditunda karena tujuan awal hanya CLI satu sesi.
- **HP Stream 11 tetap Debian**; bmahOS tidak dipasang di sana (hanya Wi-Fi RTL8723BE, xHCI, eMMC). Target perangkat keras ditetapkan di H0.
- **IoT bukan target**; beban kerja IoT lewat socket API (P5).
- **Kripto**: tidak menulis primitif baru selain SHA-256/HMAC yang sudah ada dan teruji vektor resmi; enkripsi/TLS memakai library teruji (D8).
- **Patch lewat skrip Python atomik** (assert count==1), karena penggantian teks yang tidak cocok harus gagal keras, bukan diam-diam.

## 2026-10-09 (F1.4 pola pemecahan kernel.c)
- **Satu modul = kernel/<nama>.c, deklarasi lintas-modul di kernel/kernel.h** (satu header bersama dulu; dipecah per modul bila membengkak), karena kernel.c memakai banyak helper inline bersama (port I/O, irq_save). Alternatif header per modul sejak awal ditolak: terlalu banyak file sebelum polanya terbukti.
- **Hanya simbol lintas-modul yang kehilangan `static`**; sisanya tetap static di modulnya. Bukti pemindahan murni: baris yang dihapus dari kernel.c harus sama dengan baris di file baru, kecuali `static`.
- **Makefile memakai wildcard kernel/*.c dan objek bergantung pada kernel/*.h.**
- Modul 1 (serial): serial_init/putc/write/write_hex + g_serial_mute pindah ke serial.c; outb/inb/outl/inl dan irq_save/irq_restore (static inline) ke kernel.h; log_capture tetap di kernel.c (non-static) sampai modul log/cmd.
- Modul 2 (cpu): GDT/TSS/IDT (struct gdt_entry/tss/idt_entry, bmahOS_gdt/tss/idt, gdt_init, idt_init, load, dump) pindah ke kernel/cpu.c; tipe struct dan simbol yang dipakai kernel.c (bmahOS_tss.rsp0, bmahOS_gdt, bmahOS_idt, tss_load_asm, tss_read_asm) dideklarasikan di kernel.h. exception_dispatcher/irq_handler dan fungsi trigger_* uji tetap di kernel.c (pindah bersama modul sched/uji). Deteksi simbol lintas-modul memakai skrip (patch_f14_cpu.py) yang mengabaikan komentar dan string.

## 2026-10-11 (F1.4 selesai)
- **17 modul, satu header bersama** (`kernel/kernel.h`, ~550 baris) tetap dipertahankan; pecah per modul ditunda sampai ada alasan nyata (mis. uji host F1.7 butuh header tanpa port I/O).
- **Sisa kernel.c sengaja dibiarkan** (~1140 baris): `kmain`/urutan boot, ring log, net task + idle task, `e1000_irq_service` (memakai semaphore net task), uji NX, kode uji user mode. Memindah ini hanya memindah urutan boot ke file lain tanpa manfaat.
- **Penyimpangan kecil dari "pemindahan murni"**, semuanya hanya hilangnya `static` pada simbol yang kini dipakai lintas modul (mis. `hhdm_offset`, `rsdp_request`, `crypto_selftest`, `auth_load_key`, `sem_post`) dan pemindahan makro/tipe/`extern` asm ke header. `task_wait_for` ikut non-static karena deklarasi majunya; warning "defined but not used" untuknya hilang, perilaku sama.
- **Bukti per modul**: perbandingan multiset semua baris kernel.c lama dengan kernel.c baru + modul baru + tambahan header (hanya `#include` yang bertambah), warning compiler dibandingkan, `make test` 50/50 default dan `PROD=1` (plus NOIRQ/LEGACYCTR/NXTEST sesuai modul), uji VMware per modul.
- **Push dikumpulkan** (atas permintaan pengguna, CI lama): commit per modul, push di akhir tahap.

## 2026-10-12 (F1.8 entropi)
- **HMAC-DRBG SP 800-90A (SHA-256) di atas HMAC yang sudah ada**, karena ROADMAP F1.8 memintanya dan ini komposisi HMAC (sesuai aturan THREAT_MODEL 7), bukan primitif baru. Diverifikasi 32 vektor CAVP resmi (16 kombinasi parameter, dengan/tanpa reseed) di `make host-test`, satu vektor dijalankan saat boot. Alternatif Hash-DRBG/CTR-DRBG ditolak: butuh primitif lain.
- **rdseed/rdrand dikredit penuh** (64 bit per bacaan 64 bit), seperti default Linux (`random.trust_cpu`); tanpa itu boot di VM menunggu jitter. Alternatif kredit setengah atau nol ditolak untuk sekarang; `NORDRAND=1` menguji jalur tanpa CPU RNG. Dicatat sebagai keterbatasan di THREAT_MODEL 6.
- **Estimator jitter: 1 bit per kejadian bila min(|d1|,|d2|,|d3|) >= 16 siklus**, 0 bila teratur (gaya Linux lama, dibatasi 1 bit). Ambang siap 256 bit; kolam cepat (IRQ) 256 bit, kolam SHA maks 512 bit. Bukan pengukuran entropi sungguhan; di VM tidak mewakili perangkat keras.
- **Gagal tertutup**: sebelum siap, `CHAL` dibalas `ERR: entropi belum cukup, coba lagi` tanpa menyentuh tabel nonce, dan SYN port 7 dibuang (bukan RST; peer mengulang). Port tertutup tetap RST (tidak butuh ISN).
- **Reseed paling cepat tiap 6000 tick (60 s)** saat kolam punya >= 256 bit baru (rdseed/rdrand ditambahkan saat itu); tanpa prediction resistance. Ekstraksi mengganti kolam dengan hash satu arah dari isinya.
- **Generator nonce lama dihapus** (`priv_nonce_generate`, pool di auth.c); RTC tetap dicampur ke kolam saat init tanpa kredit. `nx_init` memakai `g_cpu.nx` (refactor F1.8a, commit terpisah).

## 2026-10-12 (F1.9 perbandingan waktu-konstan)
- **Satu fungsi `ct_memeq` di crypto.c untuk semua perbandingan rahasia** (HMAC jalur counter, HMAC jalur nonce, pencarian nonce), karena tiga loop OR terpisah mudah menyimpang saat diubah. `volatile` + `noinline`, hasil akhir `1 & ((d - 1) >> 8)` tanpa cabang.
- **Pencarian nonce tanpa `break`**: semua 16 slot selalu dibandingkan. Sebelumnya hanya posisi slot yang cocok yang bocor lewat waktu (bukan isi nonce, dan nonce dikirim terbuka), tetapi biayanya kecil dan aturannya jadi sederhana.
- **Bukti di kode mesin, bukan hanya sumber**: `make test` membongkar `ct_memeq` di kernel.elf dan menuntut tepat satu lompatan bersyarat (ulangan loop) tanpa call. Sengaja ketat untuk build tanpa `-O`; dengan `-O2` gcc menambah cabang `n == 0` (masih aman) dan cek gagal, yang memaksa audit ulang. Alternatif "<= 2 lompatan" ditolak karena versi keluar-awal pada `-O2` juga lolos.
- **Tidak diubah**: penolakan format/nonce/kedaluwarsa terjadi sebelum HMAC dihitung (waktunya bergantung pada data publik penyerang sendiri); `auth_hexval` bercabang pada karakter hex kiriman (publik).

## 2026-10-12 (C3a timer kernel)
- **Callback dijalankan di loop net task, bukan di IRQ timer**, karena konsumen pertamanya (retransmisi TCP, C3c) mengirim paket dan menulis log; IRQ harus pendek. Akibat: timer hanya dilayani bila net task hidup (tanpa NIC tidak ada), dan bisa terlambat saat net task sibuk (dipantau `ktimer_late_max`). Alternatif task timer khusus ditunda sampai ada konsumen di luar jaringan.
- **`ktimer_t` milik pemanggil + senarai terurut** (sisip O(n)), tanpa heap dan tanpa tabel tetap; batas atas = jumlah `ktimer_t` di kode. Alternatif timer wheel ditolak: jumlah timer kecil.
- **`ticks = 0` dianggap 1** supaya callback yang memasang ulang dirinya tidak membuat `ktimer_run` berputar selamanya.
- **`sleep` tidak ditulis ulang**: `task_sleep` (sched.c) sudah membangunkan task lewat `wake_at_tick` di `schedule()`; C3a hanya menambah uji ketepatannya (20 tick -> 20..30; QEMU 20-21). Batas telat self-test 10 tick karena net task bergiliran round-robin dengan task lain (QEMU dev: 2 tick).

## 2026-10-12 (sebelum C3b, disetujui pengguna; mengikuti rencana C0)
- **Segmen TCP di luar urutan dibuang**, tidak disimpan; balas ACK posisi kita dan peer mengirim ulang. Alasan: tanpa buffer penyusun ulang, lebih sedikit keadaan dan permukaan serangan. Akibat: throughput turun bila ada paket hilang/tertukar.
- **Jendela yang diiklankan = ruang kosong buffer yang benar-benar ada** (`TCP_BUF_SIZE` 1024 byte dikurangi isi). Data yang melebihi jendela dipotong; jendela 0 diiklankan saat buffer penuh, dan pembaruan jendela dikirim saat ruang kembali >= MSS.

## 2026-10-12 (C3c retransmisi TCP)
- **Tidak ada salinan segmen**: yang dikirim ulang adalah byte `snd_una..snd_nxt` yang masih ada di `g_tcp_buf` (buffer baru dibebaskan saat di-ACK), atau SYN-ACK di SYN_RCVD. Satu `ktimer_t` statis untuk satu TCB, di luar `g_tcb`.
- **RTO awal tetap 100 tick (1 s), dilipatduakan sampai 800 tick, maks 5 kirim ulang lalu RST** (jeda 1, 2, 4, 8, 8 s, putus setelah ~31 s). Tanpa pengukuran RTT (Karn/Jacobson) karena satu jaringan lokal dan stop-and-wait; batas 8 s supaya total mendekati timeout menganggur 30 s yang lama. ACK yang memajukan `snd_una` (termasuk sebagian) mengembalikan RTO ke awal.
- **Timeout menganggur 30 s tidak berlaku selama ada data belum di-ACK**: koneksi seperti itu diputus oleh batas kirim ulang. SYN_RCVD tetap putus 5 s (SYN-ACK dikirim ulang pada 1 s dan 3 s).
- **Belum**: persist timer (jendela peer 0 dengan data menunggu tetap bergantung pada timeout 30 s), fast retransmit, FIN kita (C3d).

## 2026-10-12 (C3d penutupan TCP)
- **Echo menutup setelah peer menutup**: FIN peer -> CLOSE_WAIT; begitu echo habis terkirim dan di-ACK, FIN kita dikirim (LAST_ACK), ACK-nya -> CLOSED. Klien biasa (Windows TcpClient, nc) menutup duluan, jadi bmahOS tidak masuk TIME_WAIT dan port 7 langsung bebas.
- **Pemicu tutup aktif = timeout diam 30 s dengan buffer kosong** (FIN, bukan RST). Belum ada pemakai lain sampai Tahap D (`exit` shell). Data tertahan (jendela peer 0, tanpa persist timer) tetap RST.
- **FIN memakai timer retransmisi C3c** (5x lalu RST). FIN hanya dikirim saat tidak ada data menunggu, jadi yang menunggu ACK selalu data saja atau FIN saja.
- **TIME_WAIT 2 s** (C0; bukan 2*MSL) dan dimulai ulang oleh segmen apa pun dari peer; SYN lain selama itu dibalas RST (satu TCB). **FIN_WAIT_2 maks 10 s** lalu RST. Tutup bersamaan didukung (CLOSING), menyimpang dari C0 karena hanya satu keadaan tambahan.
- **RST untuk keadaan salah**: data baru setelah FIN peer (melanggar protokol) dan data setelah FIN kita (tidak ada pembaca, seperti Linux untuk soket yang sudah ditutup) -> RST dan TCB dibebaskan (`tcp_rst_state`). Segmen di luar urutan/duplikat tetap dibalas ACK.
- **RST di TIME_WAIT diabaikan** (RFC 1337, mencegah TIME_WAIT dibunuh segmen lama/palsu); keadaan itu berakhir sendiri setelah 2 s.

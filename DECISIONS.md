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

## 2026-10-12 (C4 echo TCP 1 MB, batas laju koneksi; disetujui pengguna)
- **Segmen milik koneksi TCP aktif (IP sumber + kedua port cocok TCB) tidak memakai batas UDP** (20/s per IP, 100/s global), karena echo 1 MB butuh ~4000 segmen masuk dan segmen yang dibuang memicu retransmisi dengan backoff. Penggantinya batas per koneksi 2000 segmen/s (`tcp_conn_dropped`). SYN dan segmen ke port tertutup tetap memakai batas lama. Pemilihan batas dilakukan sebelum checksum (hanya membandingkan alamat/port).
- **ACK balasan untuk segmen yang tidak diterima** (di luar urutan, duplikat, ACK melewati `snd_nxt`) **maks 10/s** (`tcp_dupack_limited`), mirip batas challenge ACK RFC 5961, supaya segmen palsu dengan 4-tuple tertebak tidak bisa memantulkan banjir balasan. ACK untuk data yang diterima tidak dibatasi.
- **Uji 1 MB memakai klien TCP Linux sungguhan lewat slirp** (`tests/tcp-echo.py`, kirim dan terima bersamaan, SHA-256), bukan rawnet: rawnet tidak punya tumpukan TCP. QEMU TCG: ~31 s (~33 KB/s, stop-and-wait).

## 2026-10-13 (D1 login TCP port 7779; desain disetujui pengguna)
- **Nonce per koneksi** (16 byte DRBG, diambil bersama ISN saat SYN; SYN dibuang bila entropi kurang), dikirim
  server langsung setelah handshake. Alternatif "CHAL" seperti UDP ditolak: satu round trip lebih dan tabel nonce
  UDP ikut terbebani.
- **Bukti login** = HMAC(kunci, "<nonce> tcp-login"): primitif dan kunci yang sama dengan UDP 7778, tanpa kripto baru.
  Akhiran "tcp-login" memisahkan domain dari perintah UDP.
- **Satu percobaan per koneksi**, gagal -> ERR lalu FIN; login maks 10 s; baris maks 128 byte. Tebak HMAC 256 bit
  tidak praktis, jadi tidak ada penguncian akun.
- **Belum**: integritas baris setelah login. Rencana D2: tiap perintah ditandatangani nonce baru dari balasan sebelumnya.
- Refactor `net_tcp_queue` (D1-1) dipisah dari fitur (D1-2).

## 2026-10-13 (C5b timeout tanpa kemajuan)
- **`last` hanya diperbarui oleh kemajuan**: handshake selesai, ACK yang memajukan snd_una, data baru dalam urutan,
  FIN peer pertama. Segmen lain (ACK duplikat, keepalive seq-1, ACK jendela 0 berulang, SYN ulang di SYN_RCVD,
  RST/segmen seq salah, FIN ulang di TIME_WAIT) tetap diproses seperti dulu tetapi tidak memperpanjang timeout
  apa pun. Alasan: sebelumnya peer, atau penebak 4-tuple tanpa melihat lalu lintas, bisa menahan slot TCB
  selamanya dengan segmen kosong (2 IP cukup untuk mengunci port 7).
- Akibat: keepalive TCP klien (Windows default 2 jam) tidak menjaga koneksi diam; koneksi tanpa data 30 s tetap
  ditutup FIN. TIME_WAIT tidak di-restart oleh FIN ulang (RFC 793 me-restart; di sini 2 s tetap).
- **Tidak dibuat**: batas umur koneksi / laju minimum (slowloris 1 byte tiap < 30 s masih menahan slot). Diputuskan
  di D4 bersama timeout sesi CLI.

## 2026-10-13 (C5a tabel koneksi TCP; 4 TCB disetujui pengguna)
- **Tabel 4 TCB statis** (`TCP_MAX_CONN`), masing-masing dengan buffer 1024 byte dan `ktimer_t` sendiri (4 KB
  buffer total, tanpa heap), menggantikan TCB tunggal C0. Dipisah jadi refactor (C5a-1, 1 slot, perilaku sama) dan
  fitur (C5a-2). Alasan: satu SYN palsu tidak lagi menahan port 7, dan Tahap D butuh sesi CLI di samping echo.
- **Maks 2 TCB per IP sumber** (`TCP_MAX_PER_IP`, keadaan apa pun termasuk SYN_RCVD/TIME_WAIT); SYN berikutnya
  dibalas RST (`tcp_src_full`). Ini "batas SYN per sumber" C5a; laju SYN tetap memakai batas per IP 20/s dan global
  100/s yang sudah ada. Tabel laju SYN terpisah (rencana awal 4/s) tidak dibuat: tidak menambah perlindungan
  karena satu IP sudah dibatasi 2 slot dan tidak bisa menggusur slot IP lain.
- **Tabel penuh: SYN_RCVD tertua digusur** (diam-diam, tanpa RST, tanpa log serial; `tcp_synrcvd_evicted`); bila
  semua slot aktif (bukan SYN_RCVD), SYN dibalas RST (`tcp_dropped_busy`). Koneksi ESTABLISHED tidak pernah
  digusur. Batas per IP dicek sebelum penggusuran. Batasan: banjir SYN dari banyak IP palsu yang cukup cepat bisa
  menggusur handshake klien sah sebelum ACK-nya tiba (klien mengulang SYN); SYN cookie = C5c.
- **Metrics**: `tcp_conn_active` (slot tidak CLOSED); `tcp_state` kini keadaan slot aktif pertama (0 = semua CLOSED).


## 2026-10-13 (D4 peran dan batas sesi CLI; rencana disetujui pengguna)
- **Peran = kunci**: `KEY.TXT` = admin, `KEYRO.TXT` (opsional) = read-only, hanya shell TCP 7779. Login mencocokkan
  bukti dengan kedua kunci (keduanya selalu dihitung); `OK login` (admin, sama seperti D1) atau `OK login ro`.
  Perintah sesi ditandatangani kunci perannya. Alternatif "login admin|ro" dengan satu kunci ditolak: pemegang kunci
  bisa mengaku admin, jadi tidak ada pemisahan. Kunci ro sama dengan kunci admin -> ditolak saat boot. UDP 7778 tetap
  kunci admin saja. Belum ada kunci per pengguna (audit siapa = D5).
- **Read-only = daftar putih** (help ping uptime mem log irq stats metrics mac ip tasks; `exit` ditangani net.c):
  perintah baru otomatis ditolak untuk ro. Ditolak -> `ERR: peran read-only` + `END <n>`, sesi tetap jalan (perintah
  sah, hanya tidak diizinkan), `cli_role_denied`.
- **Maks 2 TCB port 7779** (`TCP_CLI_MAX`, keadaan apa pun termasuk SYN_RCVD/TIME_WAIT): SYN berikutnya menggusur
  SYN_RCVD CLI tertua, tanpa itu RST (`cli_sess_full`). Echo port 7 selalu masih punya 2 slot. Alternatif "maks 1
  sesi" ditolak: sesi yang ditinggal (atau TIME_WAIT) mengunci admin sampai idle habis.
- **Idle sesi 300 s** sejak login/perintah sah terakhir (`TCP_CLI_IDLE`) -> `ERR: sesi idle` lalu FIN
  (`cli_idle_timeout`). Batas diam TCP 30 s tidak berlaku untuk sesi login dengan antrean kirim kosong (interaktif
  tidak putus tiap 30 s); data tertahan jendela 0 tetap kena batas TCP. Byte tanpa LF tidak memperpanjang sesi, jadi
  slowloris di 7779 terbatas: belum login 10 s, sudah login 300 s.
- **Tidak dibuat**: batas umur/laju minimum untuk echo port 7 (slowloris 1 byte < 30 s masih menahan slot echo).
  Port 7 hanya uji tanpa auth; slot CLI tidak terpengaruh karena 7779 punya batas sendiri dan per IP maks 2.
- **Self-test timer C3a** (commit terpisah): R dipasang ulang relatif waktu jalan, jadi urutan tetap "RRARC" salah
  bila net task telat > ~3 tick (gagal 2x berturut-turut saat D4). Kini yang diuji: 5 kejadian, menyala urut
  deadline, tidak sebelum deadline, telat maks 10.

## 2026-10-13 (D5 audit log; rencana disetujui pengguna)
- **Dua ring statis**: ok 16 entri (pihak lolos HMAC: login, perintah, tolak-peran, idle) dan gagal 8 entri
  (login gagal/timeout, baris panjang, perintah format/hmac salah). Alasan: penyerang tanpa kunci hanya bisa
  menimpa ring gagal. Penuh -> entri tertua ditimpa (bukan menolak perintah, itu DoS); nomor urut global
  memperlihatkan celah, header menampilkan `ditimpa`.
- **Teks perintah hanya bila terverifikasi** (maks 16 byte, disanitasi); baris yang gagal HMAC hanya kodenya,
  supaya penyerang tidak bisa menulis teks palsu ke audit.
- **Tidak dicatat**: CHAL, SYN ditolak, jalur counter mati (murah dibanjiri; sudah di metrics).
- **Baca: `audit` / `audit gagal` hanya admin** (bukan daftar putih ro; memperlihatkan IP dan perintah semua
  pengguna), lewat TCP admin atau UDP nonce. Ditambahkan di `priv_cmd_execute`, jadi jalur counter LEGACYCTR
  tidak bisa membacanya.
- **Serial**: tiap entri juga `AUDIT ...` ke UART lewat `serial_write_nolog` (tidak masuk ring `log`, yang boleh
  dibaca ro). Entri ok selalu ke UART; entri gagal ikut pembatas B4b.
- **Tanpa kunci metrics baru** (metrics ~1,25 KB dari batas 1400); jumlah ada di header `audit`.
- Refactor kecil (`auth_cmd_allowed` dipisah dari `auth_tcp_exec`, port sumber ke `priv_try_handle`) ikut commit
  fitur karena hanya dipakai audit (tanpa audit tidak ada gunanya).

## 2026-10-13 (D7 konfigurasi persisten; rencana disetujui pengguna)
- **Tiga kunci saja**: `cli_idle` (30..3600 s), `udp_rate` (1..100 per IP), `echo` (0/1). **IP sengaja tidak**:
  salah atur membuat bmahOS tak terjangkau dan pemulihan butuh edit disk; menunggu P3 (DHCP).
- **Satu baris salah -> seluruh file ditolak, semua default** (bukan per baris): keadaan setengah-terapkan sulit
  dinalar; default = nilai hardcode sebelum D7 yang sudah diuji. Alasan penolakan di serial dan `config`.
- **Ganti atomik = file sementara di sektor direktori yang sama + satu tulis sektor** (entri tujuan menunjuk
  rantai baru, entri sementara 0xE5). Alternatif dua tulis sektor (tujuan dulu, lalu hapus sementara) memberi
  keadaan crash dua entri berbagi rantai (cross-link, fsck mengeluh). Sektor tujuan penuh -> tolak.
- **`set` menulis ulang file utuh** dari nilai efektif (kanonik), jadi file yang ditolak saat boot pulih lewat
  `set`. Nilai RAM berubah hanya setelah tulis berhasil.
- **`config` boleh untuk read-only** (tidak rahasia); `set`, `hapus`, `ganti` hanya admin.
- **Hapus/ganti nama umum** (`hapus`, `ganti`) ditambahkan juga (disetujui pengguna). Entri ber-LFN ditolak
  supaya tidak meninggalkan LFN yatim. Hapus: entri 0xE5 dulu, lalu rantai (crash = lost cluster).
- Variabel runtime ada di net.c (pemakainya), config.c hanya mengisi; uji host net.c tidak butuh config.c.

## 2026-10-13 (D8 kerahasiaan balasan; pilihan A disetujui pengguna)
- **TLS 1.2 dengan BearSSL**, bukan SSH atau Noise. Alasan: klien bawaan di kedua sisi (Python `ssl`, .NET
  `SslStream`), tidak ada protokol kripto buatan sendiri, BearSSL tanpa alokasi dinamis, constant-time, MIT, bisa
  freestanding. Ditolak: SSH (butuh libc/POSIX, praktis menunggu P5), Noise + Monocypher (komposisi protokol oleh
  kita, klien butuh pustaka non-bawaan), tunda (A2 dalam cakupan).
- **Implementasi = tahap D9** (sebelum Fase 4; urutan diputuskan Claude atas izin pengguna). D8 hanya keputusan.
- **Versi dipatok**: sumber BearSSL di-vendor ke `third_party/bearssl` pada commit/rilis tertentu dengan sha256
  tercatat, lisensi di `3RDPARTY.md`. Tanpa SSE/AES-NI (kernel `-mno-sse`): implementasi `_ct`/`_ct64`/`ctmul`.
- **Profil TLS sempit**: hanya TLS 1.2; suite ECDHE_ECDSA_WITH_CHACHA20_POLY1305 dan ECDHE_ECDSA_WITH_AES_128_GCM;
  tanpa RSA key exchange, renegosiasi, resumption (tanpa cache sesi), sertifikat klien. TLS 1.3 tidak ada di BearSSL
  (dicatat sebagai batasan).
- **Port baru TCP 7780** = protokol baris yang sama dengan 7779 (banner, nonce, login HMAC, perintah bertanda tangan,
  `END <n>`) di dalam TLS. Login HMAC tetap (TLS hanya mengautentikasi server). 7779 teks polos tetap ada sampai klien
  pindah; menonaktifkannya lewat kunci CONFIG.CFG diputuskan di D9.
- **Identitas server**: kunci ECDSA P-256 dan sertifikat self-signed dibuat di mesin dev (openssl; BearSSL tidak
  punya penulis X.509), disimpan di disk (`TLSKEY.DER`, `TLSCERT.DER`, nama dilindungi seperti KEY.TXT). Klien
  mem-pin sha256 sertifikat (bukan CA). Tanpa file -> port 7780 tidak dibuka (gagal tertutup), 7779 tetap.
- **Keacakan**: DRBG BearSSL di-seed dari `entropy_get` per koneksi; entropi belum siap -> SYN 7780 dibuang (sama
  dengan perilaku F1.8). Server tidak memvalidasi waktu sertifikat, jadi tidak butuh RTC.
- **Memori**: konteks + buffer I/O statis per sesi CLI (TCP_CLI_MAX = 2), ukuran pasti ditetapkan di D9 (BearSSL
  bidi ~33 KB; buffer lebih kecil hanya bila klien menerima max_fragment_length).
- **UDP 7778 tetap teks polos** (keaslian saja). Pembatasan perintahnya diputuskan di D9.
- **Kunci HMAC (pertanyaan terbuka D7)**: tetap file teks di disk (KEY.TXT/KEYRO.TXT), ganti dengan menulis disk saat
  VM mati; `tulis`/`hapus`/`ganti` jarak jauh tetap menolak nama kunci. Ganti kunci jarak jauh baru masuk akal setelah
  D9 (rahasia tidak pernah lewat jalur teks polos) dan diputuskan nanti.
- Tanpa uji `make test` baru di D8 (tahap dokumen saja; aturan "jumlah cek naik" berlaku lagi di D9).

## 2026-10-14 (D9 TLS port 7780; rencana disetujui pengguna)
- **BearSSL master `7bea48e` (2026-04-06), bukan rilis v0.6 (2018)**: perbaikan sesudah v0.6 mengenai profil
  kita (carry P-256 m64 2020, overflow decode kunci privat 2019, panjang record 2026). Di-vendor tanpa
  perubahan di `third_party/bearssl` (src, inc, LICENSE, test_crypto.c), sha256 dan manifest di `3RDPARTY.md`.
- **Build**: semua `src/*.c` -> `libbearssl.a` dengan flag arsitektur kernel + `-O2` (kode kernel sendiri
  tetap tanpa `-O`, cek ct_memeq bergantung padanya). SSE2/AES-NI/POWER8/RDRAND, RNG dan waktu OS dimatikan
  lewat `-D`; `BR_INT128=1`. `make test` menuntut tanpa register xmm/ymm/zmm dan simbol luar hanya
  mem*/strlen (implementasi `kernel/klib.c`, header `kernel/compat/string.h`). `make host-test` menjalankan
  `test_crypto` upstream (ASan/UBSan, tanpa `-fsanitize=function,alignment` karena vtable BearSSL dan akses
  tak sejajar x86 memang disengaja) untuk implementasi profil.
- **Implementasi dipilih eksplisit**, bukan `*_default_*` (yang memilih SSE/AES-NI saat runtime):
  `aes_ct64` + `ghash_ctmul64`, `chacha20_ct` + `poly1305_ctmulq`, `ec_p256_m64`, ECDSA i31, SHA-256 saja.
  AES-GCM wajib karena SChannel Windows tidak punya ChaCha20.
- **Memori**: pool statis `TLS_MAX_SESS` = 2 slot (konteks 4128 + buffer masuk 16709, wajib karena klien
  tidak mengirim max_fragment_length, + keluar 1109 byte, record keluar <= 1024 byte plaintext), ~22 KB per
  slot. Slot dipegang TCB 7780 sejak SYN sampai CLOSED (juga saat digusur); karena batas TCB 7780 = jumlah
  slot, pool tidak bisa habis selama aturan itu berlaku. Slot dihapus (memset) saat dilepas.
- **Stack net task 8 -> 32 KB**, diisi pola 0xA5; puncak terukur di QEMU 4,5 KB (handshake ECDHE + ECDSA).
  `make test` menuntut < 24 KB. Handshake memblok net task (perhitungan kurva sinkron di dalam
  `recvrec_ack`); diterima, dicatat di THREAT_MODEL.
- **Integrasi net.c**: satu pintu keluaran CLI (`net_tcp_cli_write/space/flushed`, refactor D9b-1) yang
  untuk sesi TLS menulis ke engine; `net_tcp_tls_pump` memindah record keluar ke antrean TCP dan plaintext
  masuk ke parser baris yang sama. Byte TCP hanya di-ACK sebanyak yang diterima engine. Banner setelah
  handshake. Error engine -> RST; `exit`/login gagal -> `close_notify` lalu FIN; `close_notify` balasan
  klien di FIN_WAIT_1/2 di-ACK dan dibuang (dulu: data setelah FIN kita = RST).
- **Identitas**: kunci privat diperiksa cocok dengan sertifikat saat boot; tidak cocok/rusak/tidak ada ->
  TLS nonaktif (port 7780 RST), port lain jalan terus. Buffer baca kunci dihapus setelah dekode.
- **Klien Python (`ssl`)**: `CERT_NONE` + pin sha256 sertifikat sebelum data aplikasi. Tanda tangan
  ServerKeyExchange tetap diverifikasi OpenSSL dengan kunci di sertifikat yang di-pin, jadi pin = identitas.
  PowerShell: `SslStream` dengan callback pin (sha256 `GetRawCertData`).
- **Nasib 7779 dan UDP 7778**: tetap ada, diatur lewat CONFIG.CFG `cli_plain` (0 = SYN 7779 RST) dan
  `udp_admin` (0 = UDP hanya daftar perintah baca). Bawaan 1 (tidak mengubah perilaku/uji lama); pengguna
  mematikannya sendiri setelah klien pindah ke TLS. Pengaman: tanpa TLS aktif keduanya tidak boleh 0
  bersamaan (`set` menolak, boot memaksa `cli_plain=1`): kehilangan file TLS tidak boleh mengunci admin.
  Akibat: penyerang yang bisa menulis disk bisa menyalakan lagi 7779 dengan menghapus file TLS; penulis disk
  sudah di luar cakupan (THREAT_MODEL 8).
- Ganti kunci HMAC jarak jauh lewat TLS: belum (tetap pertanyaan terbuka).

## 2026-10-14 (R1 panic handler; rencana disetujui pengguna)
- **Satu jalur akhir**: semua exception (vektor 0-31; 15 dan 20-31 kini terpasang) dan `ASSERT` ->
  `panic.c`. Dump ke serial lewat `kprintf` (ikut ring log): nama exception, error (#PF diurai P/W/U/RSVD/I),
  RIP/CS/RFLAGS/RSP/SS, CR0/2/3/4, 15 GPR, tick, task, trace. Prefiks `PANIC:` di setiap baris.
- **Stack trace** lewat rantai rbp: kernel `-O0` sudah memakai frame pointer, `-fno-omit-frame-pointer`
  ditambahkan eksplisit dan juga ke BearSSL (`-O2`). Kode mesin `ct_memeq` tidak berubah (dibandingkan).
  Tiap rbp dicek sebelum dibaca (rata 8, half atas, naik ketat, jarak <= 64 KB), alamat kembali harus di
  `.text` (`__text_start/__text_end` di linker.ld), maks 16 frame. Tanpa tabel simbol di kernel:
  `tools/symbolize.sh` (addr2line) di mesin dev.
- **Reboot otomatis 10 s** (`PANIC_REBOOT_S`, konstanta; bukan kunci CONFIG.CFG). Interrupt mati, jadi waktu
  dihitung dari counter PIT ch0 yang diprogram ulang 100 Hz (tidak bergantung frekuensi TSC); PIT macet ->
  reboot langsung. Reboot lewat `machine_reboot()` (refactor R1-1 dari `priv_do_reboot`).
- **Panic bersarang**: kedalaman 2 -> satu baris + reboot langsung; 3 -> triple fault.
- **#DF lewat IST1** (stack statis 16 KB). Uji `panic df`: RSP non-kanonik lalu push -> #SS saat mengirim
  #SS -> #DF; tanpa IST ini triple fault tanpa pesan.
- **TSS-1 (bug lama, commit terpisah)**: `struct tss` punya `reserved1` 32-bit -> ist1..7 dan iopb_offset
  bergeser 4 byte. Terungkap karena uji `panic df` triple fault. Selain IST, iopb_offset yang dibaca CPU = 0
  sehingga peta izin I/O mulai di byte 0 TSS (user mode mungkin bisa I/O ke port rendah). Kini offset
  dicek `_Static_assert` dan `iopb_offset = sizeof(tss)` (tanpa peta: semua I/O ring 3 -> #GP).
- **Pemicu uji = perintah admin `panic pf|df|ud|assert`, hanya build dev** (bukan flag build): satu ISO
  untuk semua jenis, bisa diuji di VMware. Fault dijalankan ktimer 1 s kemudian supaya balasan terkirim
  (UDP, TCP, TLS). Tidak di `g_ro_cmds`. Build PROD: kode tidak ada (`make test` mengecek).
- **Di luar cakupan**: fault dari user mode tetap panic (dulu hang, kini reboot; mematikan task saja = R6),
  guard page stack (R6), dump persisten (R4).

## 2026-10-15 (R2 netconsole UDP; rencana disetujui pengguna)
- **Isi**: setiap baris yang masuk ring log `log` (baris `schedule(): switch` tetap disaring), termasuk dump
  `PANIC:`. Baris `AUDIT` tidak (sama dengan `log`, D5). Register umum dump panic (RAX..R15) tidak
  dikirim (`g_netcon_hold`), bisa memuat sisa rahasia; hanya serial. Teks perintah dan kunci memang tidak
  pernah masuk log.
- **Bawaan mati** (`netcon=0`): log teks polos ke LAN = pembocoran informasi, harus dinyalakan sengaja.
- **Tujuan = oktet** `netcon_host` 1..254 di /24 sendiri (192.168.50.x) + `netcon_port` 1024..65535 (bawaan
  .1:6666), port sumber 6665. Tanpa gateway memang tidak bisa keluar subnet. Tidak bertentangan dengan
  "IP tidak bisa diatur" (D7): salah atur tidak membuat bmahOS tak terjangkau.
- **MAC tujuan**: ARP request sendiri maks 1x/s sampai ARP (reply atau request) dari IP tujuan; disimpan
  sampai host/netcon berubah. Belum ada cache ARP umum (cukup untuk satu tujuan).
- **Tanpa heap**: antrean statis 4 KB (baris utuh) + satu halaman TX sendiri. Net task mengirim maks 1
  datagram (<= 1024 byte, baris utuh) per putaran, maks 20 datagram/s. Antrean penuh -> baris BARU
  dibuang (konteks awal tetap utuh), datagram berikutnya diawali `netcon: N baris dibuang`. Pengiriman
  tidak menulis log (tanpa umpan balik).
- **Panic**: antrean dikirim langsung (tanpa batas laju, maks 8 datagram) di awal panic dan setelah dump,
  lewat halaman TX netcon sendiri (frame net task yang terpotong tidak ditimpa). Butuh MAC sudah diketahui;
  panic bersarang hanya serial.
- **Refactor terpisah (R2-1)**: `net_udp_build()` (Eth+IPv4+UDP+checksum) dipakai echo, balasan perintah,
  dan netcon.
- **Status**: perintah `netcon` (admin + read-only), bukan kunci `metrics` (metrics dekat batas 1400 byte;
  registry = R3).

## 2026-10-15 (R3 registry metrik; rencana disetujui pengguna)
- **Satu tabel** `g_metrics` (metrics.c): nama + pointer u64/u32 atau getter. Counter tetap didefinisikan di
  modul pemiliknya (tanpa makro X/abstraksi lain). R3-1 = refactor dengan keluaran sama byte per byte.
- **Halaman, bukan buffer lebih besar**: batas 1400 byte tetap (muat satu datagram UDP). Halaman yang belum
  habis diakhiri `metrics_lanjut=<i>`; tidak ada lagi pemotongan diam-diam. Kunci lama tetap di depan
  (skrip lama yang hanya membaca halaman 1 tetap mendapat 78 kunci lama).
- **Filter = awalan nama**, bukan grup bernama (tanpa tabel grup terpisah).
- **CPU**: sampel per tick timer (task terinterupsi = idle atau bukan), jendela 1 s. Tanpa akuntansi per task.
- **Kunci baru**: uptime_s, cpu_*, mem_total_kb, heap_mapped, stack_net_used, cli/tls_sess_active, tls_*,
  netcon_* (dulu sengaja ditunda di R2), fat_wr_ok/fail, audit_seq. Read-only boleh `metrics` + argumen
  (sudah boleh `metrics` sebelumnya; tidak ada rahasia di counter).

## 2026-10-15 (R4 log persisten; rencana disetujui pengguna, pilihan rekomendasi Claude)
- **File dialokasikan di host** (`LOG.BIN` 64 KB, mtools/qemu-img), kernel hanya menimpa sektor isi lewat
  `fat32_map_write` (R4-1): FAT, entri dir, ukuran, FSInfo tidak pernah disentuh -> crash paling buruk
  merusak satu rekaman. Kernel tidak membuat file (butuh alokasi multi-cluster > 4 KB). Tanpa file = mati.
- **Rekaman mandiri** 512 byte (boot, seq global, hash 8 byte SHA-256 yang sudah ada), tanpa header global
  yang harus diperbarui; posisi tulis = sesudah seq sah terbesar (pindai 128 sektor saat boot).
- **Isi = ring `log`** (tanpa AUDIT, tanpa register umum panic). Read-only boleh `logdisk` (sama dengan `log`).
- **Antrean statis 4 KB** sejak awal boot (4 KB pertama boot tersimpan; sisanya sampai init dibuang dan
  dihitung). Net task: satu rekaman bila penuh atau tiap 5 s, maks 2 tulis/s (net task terblok saat I/O).
- **Panic/reboot**: `logdisk_sync` menulis antrean langsung (maks 8 rekaman), dilewati bila AHCI sedang
  dipakai (`g_ahci_busy`) atau bersarang. Menutup "dump persisten" yang ditunda di R1.
- **Tulis gagal** -> logdisk nonaktif + volume baca saja (gagal tertutup, sama dengan tulis file D6).

## 2026-10-20 (R5 watchdog perangkat lunak; rencana disetujui pengguna)
- **Yang ditepuk: hanya net task**, sekali per putaran loop utama (putaran normal tiap tick lewat tick-wake).
  Task idle tidak ditepuk: scheduler hanya menjalankannya bila tidak ada task READY lain, jadi saat banjir
  paket idle bisa lama tidak jalan (alarm palsu). Task uji build dev tidak diawasi.
- **Pemeriksa di IRQ timer**, hanya membaca `timer_ticks - g_wd_last`; tepukan tidak pernah dari interrupt.
  Aktif sejak tepukan pertama (waktu boot tidak dihitung; tanpa NIC tidak pernah aktif).
- **Batas tetap 1000 tick (10 s)**, tanpa kunci `CONFIG.CFG`; margin diukur lewat `wd_gap_max`.
- **Saat macet**: jalur panic R1 (`panic_begin` -> netconsole + LOG.BIN, baris `PANIC: watchdog:` + status
  task, `panic_finish` -> trace + reboot 10 s). Trace dari frame interrupt bila net task sedang berjalan,
  selain itu dari konteks yang disimpan `context_switch` (rsp[8] = rbp, rsp[15] = alamat kembali).
- **Tidak dicakup**: macet dengan interrupt mati (NMI lewat IOAPIC terlalu besar untuk R5) -> H6.
- Tanpa refactor terpisah: `panic_finish(rip, rbp)` dari R1 sudah cukup, jadi R5 satu commit.

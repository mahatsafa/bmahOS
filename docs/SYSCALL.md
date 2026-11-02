# Syscall bmahOS (daftar stabil)

Status: P5-2 (2026-10-31; P5-1 2026-10-29). Nomor, argumen, dan kode galat di bawah ini **stabil**: syscall baru hanya ditambah
dengan nomor baru, perilaku nomor lama tidak diubah. Pembungkus C: `userspace/bm.h`.

## Konvensi

- Instruksi `int 0x80` dari ring 3.
- `rax` = nomor syscall; argumen berurutan di `rdi`, `rsi`, `rdx`, `r10`, `r8` (urutan Linux x86-64).
- Hasil di `rax`. Nilai negatif = kode galat (angka sama dengan errno Linux, lihat tabel). Register lain tidak
  diubah kernel.
- Nomor tidak dikenal -> `-1` (baris "SYSCALL tidak dikenal" di serial, `sys_rejected` naik).
- Pointer dari user dicek sebelum dipakai: seluruh rentang harus halaman user yang dipetakan (dan writable
  bila kernel menulis ke sana). Pointer ditolak -> `sys_rejected` naik.
- Syscall berjalan dengan interrupt mati, kecuali saat menunggu (`sendto`, `recvfrom`, `accept`, `send`,
  `recv`): task tidur dan task lain tetap jalan.

## Program user

- Biner datar maks 4096 byte (kode + rodata), dimuat di `0x400000` (halaman read-only, bisa dieksekusi).
  Tanpa `.data`/`.bss`: semua variabel di stack (1 halaman, NX, di bawahnya halaman guard).
- Titik masuk = byte pertama biner (`_start` di section `.text.start`). Selesai dengan `exit`.
- Tanpa SSE/x87: state FPU tidak disimpan saat ganti task (`-mno-sse -mno-mmx`).
- Exception di ring 3 hanya menghentikan task itu (R6-1); soketnya ditutup otomatis.
- Build: `make` mengompilasi `userspace/<nama>.c` -> `build/user/<nama>.bin` (`USER_PROGS` di Makefile).
  Dua program ditanam di kernel dan hanya dijalankan build dev: `udpgema` (P5-1, gema UDP port 5555) dan
  `tcpgema` (P5-2, server gema TCP port 5556).

## Daftar

| No | Nama | Argumen | Hasil |
|---|---|---|---|
| 0 | test | a, b, c | `0xAAAA`; mencetak argumen ke serial (uji) |
| 1 | write | buf, len | len; menulis ke serial. len maks 1024, lebih -> `-1` |
| 2 | exit | - | tidak kembali |
| 3 | socket | type | fd 0..3, atau galat |
| 4 | bind | fd, port | 0, atau galat |
| 5 | sendto | fd, buf, len, alamat | len, atau galat |
| 6 | recvfrom | fd, buf, cap, &alamat (boleh 0), timeout | panjang yang disalin, atau galat |
| 7 | close | fd | 0, atau galat |
| 8 | listen | fd | 0, atau galat |
| 9 | accept | fd, &alamat (boleh 0), timeout | fd koneksi baru, atau galat |
| 10 | send | fd, buf, len, timeout | byte yang masuk antrean kirim, atau galat |
| 11 | recv | fd, buf, cap, timeout | byte yang dibaca; 0 = peer menutup (FIN) dan data habis |

### Alamat soket

Satu bilangan 64 bit: `(a << 40) | (b << 32) | (c << 24) | (d << 16) | port` untuk IPv4 `a.b.c.d`
(makro `BM_ADDR`). Bit 48..63 harus 0.

### socket (3)

- `type` `2` = UDP, `1` = TCP (P5-2), lainnya `-22`.
- Maksimal 4 soket terbuka di seluruh sistem (penuh -> `-24`). fd hanya bisa dipakai task pembuatnya
  (task lain -> `-9`).

### bind (4)

- Port 1024..49151 selain port sistem: 6665 (sumber netconsole), `netcon_port` (bawaan 6666), 7777..7780.
  49152..65535 dipakai kernel sebagai port sumber acak (DNS, SNTP, pantau). Di luar itu -> `-13`.
- Port sudah dipakai soket lain berjenis sama -> `-98` (port UDP dan TCP terpisah). Soket sudah terikat,
  atau fd koneksi hasil `accept` -> `-22`.
- Datagram ke port itu diterima setelah packet filter P4, batas laju UDP per IP dan global, dan cek checksum.

### sendto (5)

- Soket UDP yang sudah terikat (port sumber = port bind); belum terikat atau soket TCP -> `-22`. Port tujuan
  0 -> `-22`.
- `len` maks 1472 (tanpa fragmentasi IP) -> lebih `-90`. Pointer buruk -> `-14`.
- Tujuan harus di /24 sendiri, bukan alamat jaringan (.0), broadcast (.255), atau IP sendiri -> `-113`
  (belum ada gateway).
- Tanpa NIC atau IP (DHCP belum terikat), atau net task belum selesai inisialisasi saat boot -> `-100`.
- Data disalin, lalu net task mengirimnya. MAC tujuan dari cache 8 entri (diisi oleh datagram masuk dan
  jawaban ARP); tanpa MAC: ARP request maks 3x, tanpa jawaban -> `-113`. Pemanggil menunggu sampai selesai
  (maks 5 s, lebih -> `-5`; NIC gagal kirim -> `-5`).

### recvfrom (6)

- Soket UDP yang sudah terikat (`-22`). `cap` di atas 1472 dianggap 1472. Pointer `buf` (cap byte) dan
  `&alamat` (8 byte) harus writable -> `-14`.
- Mengambil datagram tertua dari antrean (4 datagram per soket; penuh -> datagram baru dibuang, `sock_drop`).
  Datagram lebih panjang dari `cap` dipotong, sisanya dibuang.
- `timeout` dalam tick (100 per detik). 0 = tunggu sampai ada data. Habis -> `-11`.
- Alamat pengirim ditulis ke `&alamat` bila tidak 0.

### close (7)

- Menutup soket; datagram yang masih antre dibuang. fd tidak sah -> `-9`.
- Koneksi TCP: data di antrean kirim tetap dikirim, lalu FIN. Masih ada data masuk yang belum dibaca -> RST
  (seperti Linux). Soket listen: koneksi yang belum di-`accept` di port itu di-RST.
- Semua soket task juga ditutup saat task keluar atau dihentikan karena exception.

## TCP (P5-2): server saja

Belum ada `connect` (klien TCP belakangan). Alur: `socket(1)` -> `bind(port)` -> `listen` -> `accept` -> `recv`/`send`
-> `close`. TCP-nya sama dengan layanan kernel (stop-and-wait, MSS 536, retransmisi 1-8 s maks 5 kali lalu
RST, segmen di luar urutan dibuang).

- **Batas**: 2 koneksi TCP user di seluruh sistem (slot TCB khusus, terpisah dari CLI/TLS/echo kernel), keadaan
  apa pun, termasuk yang belum di-`accept`. SYN saat penuh: koneksi SYN_RCVD tertua digusur; semuanya sudah
  ESTABLISHED -> RST. Tidak ada batas per IP (2 slot saja). fd tetap dari tabel 4 soket yang sama dengan UDP.
- **Antrean per koneksi**: ring masuk 1024 byte (= jendela yang diiklankan) dan ring keluar 1024 byte. Program
  yang tidak membaca membuat jendela 0; setelah `recv` membuka jendela dari bawah 536 byte, kernel mengirim ACK
  pembaruan jendela.
- **Batas diam**: koneksi yang belum di-`accept` ditutup kernel setelah 30 s tanpa kemajuan (seperti layanan
  kernel). Koneksi yang sudah di-`accept` dengan antrean kirim kosong tidak pernah ditutup karena diam: program
  yang memutuskan (mis. `recv` dengan timeout lalu `close`). Data yang tertahan jendela 0 peer tetap kena 30 s.

### listen (8)

- Soket TCP yang sudah terikat dan belum listen, selain itu `-22`. Mulai saat itu SYN ke port tersebut diterima.

### accept (9)

- fd harus soket listen (`-22`). `&alamat` (8 byte writable, `-14`) diisi alamat peer bila tidak 0.
- Mengambil koneksi yang handshake-nya selesai paling dulu. Belum ada: menunggu `timeout` tick (0 = selamanya),
  habis -> `-11`. Tabel fd penuh -> `-24` (koneksi tetap menunggu).

### send (10)

- fd harus koneksi hasil `accept`, selain itu `-107`. `len` di atas 1024 dianggap 1024; pointer `buf` -> `-14`.
- Menyalin sebanyak ruang ring keluar dan langsung kembali (bisa kurang dari `len`); ring penuh -> menunggu
  `timeout` tick (0 = selamanya), habis -> `-11`. `len` 0 -> 0.
- Koneksi sudah direset (RST peer, kirim ulang habis) -> `-104`; sudah ditutup baik-baik -> `-32`. Setelah FIN
  peer (setengah tertutup) kirim tetap boleh.

### recv (11)

- fd harus koneksi hasil `accept` (`-107`). `cap` di atas 1024 dianggap 1024; pointer `buf` writable (`-14`).
- Ada data -> disalin dan langsung kembali. Tanpa data: FIN peer atau koneksi tertutup baik-baik -> 0; direset
  -> `-104` (data yang sudah masuk tetap dibaca dulu); selain itu menunggu `timeout` tick (0 = selamanya), habis
  -> `-11`. `cap` 0 -> 0.

## Kode galat

| Kode | Nama | Arti di bmahOS |
|---|---|---|
| -1 | - | nomor syscall tidak dikenal, atau pointer/len `write` ditolak |
| -5 | EIO | NIC gagal kirim / net task tidak menyelesaikan kirim dalam 5 s |
| -9 | EBADF | fd tidak ada atau milik task lain |
| -11 | EAGAIN | `recvfrom`: timeout habis |
| -13 | EACCES | port di luar rentang atau port sistem |
| -14 | EFAULT | pointer user tidak sah |
| -22 | EINVAL | jenis soket, soket belum/sudah terikat, port tujuan 0, alamat > 48 bit, listen/accept pada soket yang salah, sendto/recvfrom pada soket TCP |
| -24 | EMFILE | 4 soket sudah terbuka |
| -32 | EPIPE | `send` ke koneksi TCP yang sudah ditutup baik-baik |
| -90 | EMSGSIZE | datagram > 1472 byte |
| -98 | EADDRINUSE | port sudah dipakai soket lain |
| -100 | ENETDOWN | tanpa NIC atau belum ada IP |
| -104 | ECONNRESET | koneksi TCP direset (RST peer, kirim ulang habis, timeout) |
| -107 | ENOTCONN | `send`/`recv` bukan pada koneksi TCP hasil `accept` |
| -113 | EHOSTUNREACH | tujuan di luar /24, alamat khusus, atau ARP tanpa jawaban |

## Pengamatan

- Perintah `soket` (juga peran read-only): satu baris per soket terbuka (port, task, antrean, penghitung;
  TCP: `listen`, atau peer + keadaan `terbuka`/`fin`/`tutup`/`reset`), ringkasan UDP, dan baris `tcp:` (slot
  koneksi terpakai, diterima, byte masuk/kirim, reset).
- `metrics sock_`: `sock_rx`, `sock_tx`, `sock_drop`, `sock_err` (syscall soket yang berakhir galat, UDP dan
  TCP), `sock_noarp`; P5-2: `sock_tcp_accept`, `sock_tcp_rx_bytes`, `sock_tcp_tx_bytes`, `sock_tcp_reset`
  (koneksi milik fd yang berakhir tanpa penutupan baik-baik). Pointer ditolak juga menaikkan `sys_rejected`.

## Belum ada (rencana)

- Klien TCP (`connect`).
- `bind(0)` dengan port otomatis, broadcast/multicast, gateway, `poll`/banyak soket sekaligus, program dari
  disk dengan format selain biner datar 4 KB.

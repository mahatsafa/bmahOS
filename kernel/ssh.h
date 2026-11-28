#ifndef BMAHOS_SSH_H
#define BMAHOS_SSH_H

#include <stdint.h>

// ---- ssh.c (F7 SSH-1a: inti transport SSH-2 sisi server, mesin keadaan murni) ----
// Tanpa I/O: pemanggil (net task, SSH-1b) menyuap byte TCP dengan ssh_feed() dan
// mengirim byte keluar dari ssh_out_peek()/ssh_out_consume(). Primitif dari BearSSL.
// Profil: kex curve25519-sha256, kunci host ecdsa-sha2-nistp256, cipher
// aes128-gcm@openssh.com (chacha20-poly1305 TIDAK ada: lihat ssh.c), tanpa kompresi.

#define SSH_MAX_SESS     2        // = batas TCB port 22
#define SSH_PKT_MAX      35000    // packet_length maksimum (RFC 4253 6.1)
#define SSH_IBUF_SIZE    (SSH_PKT_MAX + 4 + 16 + 24)   // 4 panjang + 16 tag + sisa banner
#define SSH_OBUF_SIZE    4096
#define SSH_OUT_RESERVE  1024     // ruang keluar minimum agar satu paket masuk diproses
// SSH-2a: respons perintah (<= SSH_CMD_OUT_MAX + prompt) TIDAK dibuat langsung di obuf, melainkan
// di buffer tunda kanal (pend) lalu dipecah ke obuf sesuai window/max packet klien dan ruang yang
// ada. Karena itu satu respons terburuk tidak perlu muat di obuf sekaligus dan SSH_OBUF_SIZE /
// SSH_OUT_RESERVE tidak perlu dinaikkan: paket kendali (PK_OK, SUCCESS, exit-status+EOF+CLOSE,
// WINDOW_ADJUST, DISCONNECT) paling besar ~250 byte, jauh di bawah cadangan 1024; paket DATA hanya
// ditulis bila masih menyisakan >= 512 byte ruang.
#define SSH_AUTH_MAX     4        // tanda tangan userauth SALAH sebelum DISCONNECT
#define SSH_UA_REQ_MAX   32       // total USERAUTH_REQUEST per koneksi sebelum DISCONNECT
#define SSH_AUTHKEY_MAX  4        // kunci pengguna per peran
#define SSH_ROLE_ADMIN   1        // = AUTH_ROLE_ADMIN (kernel.h)
#define SSH_ROLE_RO      2        // = AUTH_ROLE_RO
#define SSH_USER_MAX     32       // nama pengguna disimpan maks 32 byte
#define SSH_CMD_MAX      256      // perintah / baris shell maks 256 byte
#define SSH_CMD_OUT_MAX  1400     // keluaran satu perintah maks 1400 byte
#define SSH_WIN_IN       4096     // window masuk kanal (DECISIONS 2026-11-24: <= 4 KB)
#define SSH_MAXPKT_IN    4096     // max packet masuk kanal
#define SSH_UNIMPL_MAX   16       // UNIMPLEMENTED per sesi sebelum DISCONNECT
#define SSH_PKT_LIMIT    (1u << 28)   // paket per arah sebelum DISCONNECT
#define SSH_BYTE_LIMIT   (1ull << 30) // byte per arah sebelum DISCONNECT

// ssh_state()
#define SSH_ST_FREE      0   // slot kosong
#define SSH_ST_VERSION   1   // menunggu baris versi klien
#define SSH_ST_KEX       2   // pertukaran kunci (KEXINIT .. NEWKEYS klien)
#define SSH_ST_SERVICE   3   // kunci aktif, menunggu SERVICE_REQUEST
#define SSH_ST_AUTH      4   // ssh-userauth diterima (userauth = SSH-2)
#define SSH_ST_CLOSING   5   // selesai/gagal: kirim sisa keluaran lalu tutup
#define SSH_ST_CONN      6   // userauth sukses: lapisan koneksi (kanal session)

// ssh_open(): kode gagal
#define SSH_ERR_FULL     (-1)   // slot habis
#define SSH_ERR_NOKEY    (-2)   // kunci host belum dimuat
#define SSH_ERR_ENTROPY  (-3)   // entropi belum cukup (gagal tertutup)

// Kunci host: DER SEC1/PKCS#8 EC P-256. Return 1 bila sah (kunci, blob K_S, fingerprint
// siap), 0 bila tidak (kunci lama dihapus). Buffer der dipakai tanpa diubah.
int ssh_load_key(const uint8_t *der, uint32_t len);
int ssh_key_loaded(void);
const char *ssh_fingerprint(void);   // "SHA256:<base64 tanpa =>", "" bila belum dimuat
void ssh_unload_key(void);           // nolkan kunci host (uji)

int ssh_open(void);                  // slot (>= 0) atau SSH_ERR_*; banner + KEXINIT sudah di antrean keluar
// Suap masukan; return byte yang dikonsumsi. Keluaran hampir penuh (< SSH_OUT_RESERVE
// kosong) -> 0 (backpressure, pemanggil mengirim ulang nanti). len=0 (d boleh 0) hanya
// melanjutkan pemrosesan sisa di buffer masuk (panggil setelah ssh_out_consume()).
uint32_t ssh_feed(int s, const volatile uint8_t *d, uint32_t len);
const uint8_t *ssh_out_peek(int s, uint32_t *len);
void ssh_out_consume(int s, uint32_t n);
void ssh_close(int s);               // nolkan seluruh slot (kunci sesi, buffer)
int ssh_state(int s);
const char *ssh_why(int s);          // alasan penutupan ("" bila belum)
int ssh_done(int s);                 // 1: CLOSING dan keluaran sudah habis -> tutup TCP
int ssh_cipher_active(int s);        // 1 bila kunci cipher keluar sudah aktif (uji/metrik)


// ---- SSH-2a: userauth publickey + kanal session (RFC 4252/4254) ----
// Kunci pengguna: format authorized_keys, hanya baris "ecdsa-sha2-nistp256 <base64> [komentar]".
// Return jumlah kunci yang dimuat (maks SSH_AUTHKEY_MAX); panggil ulang mengganti isi peran itu.
int ssh_set_authkeys(int role, const uint8_t *txt, uint32_t len);
void ssh_clear_authkeys(void);
int ssh_authkey_count(int role);
// Jumlah kunci yang ada di daftar admin DAN ro. Kunci ganda berlaku sebagai ro (hak terendah);
// kernel dapat mencetak peringatan bila > 0.
int ssh_authkey_dup(void);

// Perintah: dipasang kernel. out berkapasitas max (SSH_CMD_OUT_MAX); return panjang keluaran.
// *reboot = 1: tutup kanal lalu minta reboot (ssh_take_reboot). *denied = 1: ditolak peran.
typedef uint32_t (*ssh_exec_fn)(int role, const uint8_t *cmd, uint32_t len, uint8_t *out,
                                uint32_t max, int *reboot, int *denied);
void ssh_set_exec(ssh_exec_fn f);

// Audit (callback, nama pengguna / perintah sebagai txt, bukan NUL-terminated).
#define SSH_EV_LOGIN      1   // userauth sukses (txt = nama pengguna)
#define SSH_EV_LOGIN_FAIL 2   // tanda tangan salah (txt = nama pengguna)
#define SSH_EV_CMD        3   // perintah akan dijalankan (txt = perintah)
#define SSH_EV_CMD_ROLE   4   // perintah ditolak peran (denied=1 dari callback exec)
#define SSH_EV_CMD_FAIL   5   // perintah/baris ditolak sebelum callback (terlalu panjang / tidak sah);
                              // txt = maks 16 byte pertama, non-cetak jadi '?'; cmd_count tidak naik
typedef void (*ssh_audit_fn)(int s, int ev, int role, const uint8_t *txt, uint32_t len);
void ssh_set_audit(ssh_audit_fn f);

int ssh_authed(int s);               // 1 setelah USERAUTH_SUCCESS (net.c: batas 10 s berhenti)
int ssh_role(int s);                 // SSH_ROLE_* atau 0
const char *ssh_user(int s);         // nama pengguna (sudah disanitasi), "" bila belum
uint32_t ssh_cmd_count(int s);       // naik tiap perintah dijalankan (reset idle)
// 1 sekali bila perintah meminta reboot. Panggil SEBELUM ssh_close(s) (ssh_close menolkan);
// reboot sebaiknya baru dijalankan setelah ssh_done(s) agar keluaran terkirim.
int ssh_take_reboot(int s);

#endif

# bmtcp.ps1: klien shell TCP 7779 (D3) / TLS 7780 (D9) bmahOS untuk PowerShell Windows.
# Protokol di PROTOCOL.md. Tidak bergantung pada skrip lain.
#
# Muat:   . .\bmtcp.ps1
# Kunci:  $BmKeyFile (default $env:USERPROFILE\.bmahos\key.txt); spasi/CR/LF/NUL
#         di akhir file dibuang, sama seperti kernel.
#         Peran read-only (D4): $BmKeyFile = file isi KEYRO.TXT -> "OK login ro".
# Pakai:  bmtcp              login ke 192.168.50.200:7779 (cetak "OK login")
#         bmtcp "10.0.0.5"   alamat lain
#         bmt uptime         perintah bertanda tangan, cetak keluaran sampai END <n>
#         bmtx               exit lalu tutup koneksi
#         bmmetrics [awalan] R3: semua halaman metrics (ikuti metrics_lanjut=)
#         bmlogdisk [seq]    R4: log persisten LOG.BIN mulai seq (ikuti logdisk_lanjut=)
#         bmtls              D9: sama dengan bmtcp lewat TLS 1.2 port 7780; pin
#                            (sha256 sertifikat, 64 hex) dari $BmPinFile (default
#                            $env:USERPROFILE\.bmahos\tlspin.txt). Beda -> ditutup.
# Catatan: nama variabel PowerShell tidak peka huruf besar-kecil.

if (-not $BmKeyFile) { $BmKeyFile = Join-Path $env:USERPROFILE ".bmahos\key.txt" }
if (-not $BmPinFile) { $BmPinFile = Join-Path $env:USERPROFILE ".bmahos\tlspin.txt" }

function bmhmac($msg) {
  $kb = [IO.File]::ReadAllBytes($BmKeyFile)
  $len = $kb.Length
  while ($len -gt 0 -and @(13, 10, 32, 0) -contains $kb[$len - 1]) { $len-- }
  $h = New-Object Security.Cryptography.HMACSHA256
  $h.Key = $kb[0..($len - 1)]
  $mb = $h.ComputeHash([Text.Encoding]::ASCII.GetBytes($msg))
  ($mb | ForEach-Object { $_.ToString("x2") }) -join ""
}

function bmtcp($addr = "192.168.50.200", $tport = 7779) {
  $script:BmTc = New-Object Net.Sockets.TcpClient
  $script:BmTc.Connect($addr, $tport)
  $st = $script:BmTc.GetStream()
  $st.ReadTimeout = 15000
  bmlogin $st
}

# D9: sertifikat server dibandingkan dengan pin (sha256 DER) di callback,
# sebelum byte aplikasi apa pun. Tanpa verifikasi CA (self-signed).
function bmtls($addr = "192.168.50.200", $tport = 7780) {
  $script:BmPin = (Get-Content $BmPinFile -Raw).Trim().ToLower()
  $script:BmTc = New-Object Net.Sockets.TcpClient
  $script:BmTc.Connect($addr, $tport)
  $raw = $script:BmTc.GetStream()
  $raw.ReadTimeout = 15000
  $cb = [Net.Security.RemoteCertificateValidationCallback] {
    param($snd, $cert, $chain, $err)
    $sha = [Security.Cryptography.SHA256]::Create()
    $hb = $sha.ComputeHash($cert.GetRawCertData())
    $hx = ($hb | ForEach-Object { $_.ToString("x2") }) -join ""
    $script:BmPeerPin = $hx
    return $hx -eq $script:BmPin
  }
  $ssl = New-Object Net.Security.SslStream($raw, $false, $cb)
  $tls12 = [Security.Authentication.SslProtocols]::Tls12
  try {
    $ssl.AuthenticateAsClient("bmahOS", $null, $tls12, $false)
  } catch {
    "bmtls: handshake/pin gagal (server: $($script:BmPeerPin))"
    $script:BmTc.Close()
    return
  }
  "bmtls: TLS $($ssl.SslProtocol) $($ssl.CipherAlgorithm) pin cocok"
  bmlogin $ssl
}

# Banner + login di atas stream (TCP polos atau SslStream).
function bmlogin($st) {
  $script:BmRd = New-Object IO.StreamReader($st)
  $script:BmWr = New-Object IO.StreamWriter($st)
  $script:BmWr.NewLine = "`n"
  $script:BmWr.AutoFlush = $true
  $l1 = $script:BmRd.ReadLine()
  $l2 = $script:BmRd.ReadLine()
  if ($l1 -ne "bmahOS login" -or -not $l2.StartsWith("nonce: ")) {
    "bmtcp: banner tidak dikenal: $l1 / $l2"
    $script:BmTc.Close()
    return
  }
  $script:BmNonce = $l2.Substring(7)
  $script:BmSeq = 0
  $script:BmWr.WriteLine("login " + (bmhmac "$($script:BmNonce) tcp-login"))
  $script:BmRd.ReadLine()
}

function bmt($c) {
  $script:BmSeq++
  $mac = bmhmac "$($script:BmNonce) tcp-cmd $($script:BmSeq) $c"
  $script:BmWr.WriteLine("$c $mac")
  $endl = "END $($script:BmSeq)"
  while ($true) {
    $line = $script:BmRd.ReadLine()
    if ($line -eq $null) { "bmt: koneksi ditutup server"; return }
    if ($line -eq $endl) { return }
    $line
  }
}

# R3: metrics dibagi halaman; baris terakhir "metrics_lanjut=<i>" berarti
# masih ada kunci, lanjut dengan "metrics [awalan] <i>".
function bmmetrics($awalan = "") {
  $base = "metrics"
  if ($awalan) { $base = "metrics $awalan" }
  $cmd = $base
  for ($pg = 0; $pg -lt 20; $pg++) {
    $lines = @(bmt $cmd)
    $last = ""
    if ($lines.Count -gt 0) { $last = $lines[$lines.Count - 1] }
    if ($last -notmatch '^metrics_lanjut=(\d+)$') { $lines; return }
    $nx = $Matches[1]
    if ($lines.Count -gt 1) { $lines[0..($lines.Count - 2)] }
    $cmd = "$base $nx"
  }
  "bmmetrics: halaman terlalu banyak"
}

# R4: "logdisk <seq>" berhalaman; baris akhir "logdisk_lanjut=<seq>".
# Header "=== boot N seq S[ panic] ===" diulang kernel di awal tiap halaman:
# buang bila boot sama dengan header terakhir ($hb; $hp = header itu panic).
function bmlogdisk($seq = 1) {
  $hr = '^=== boot (\d+) seq \d+( panic)? ===$'
  $hb = ""
  $hp = $false
  for ($pg = 0; $pg -lt 200; $pg++) {
    $lines = @(bmt "logdisk $seq")
    if ($pg -gt 0 -and $lines.Count -gt 0 -and $lines[0] -match $hr) {
      $np = [bool]$Matches[2]
      if ($Matches[1] -eq $hb -and (-not $np -or $hp)) {
        if ($lines.Count -gt 1) { $lines = @($lines[1..($lines.Count - 1)]) }
        else { $lines = @() }
      }
    }
    foreach ($l in $lines) {
      if ($l -match $hr) { $hb = $Matches[1]; $hp = [bool]$Matches[2] }
    }
    $last = ""
    if ($lines.Count -gt 0) { $last = $lines[$lines.Count - 1] }
    if ($last -notmatch '^logdisk_lanjut=(\d+)$') { $lines; return }
    $seq = $Matches[1]
    if ($lines.Count -gt 1) { $lines[0..($lines.Count - 2)] }
  }
  "bmlogdisk: halaman terlalu banyak"
}

function bmtx {
  bmt exit
  $script:BmTc.Close()
}

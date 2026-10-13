# bmtcp.ps1: klien shell TCP 7779 bmahOS (D3) untuk PowerShell Windows.
# Protokol di PROTOCOL.md. Tidak bergantung pada skrip lain.
#
# Muat:   . .\bmtcp.ps1
# Kunci:  $BmKeyFile (default $env:USERPROFILE\.bmahos\key.txt); spasi/CR/LF/NUL
#         di akhir file dibuang, sama seperti kernel.
# Pakai:  bmtcp              login ke 192.168.50.200:7779 (cetak "OK login")
#         bmtcp "10.0.0.5"   alamat lain
#         bmt uptime         perintah bertanda tangan, cetak keluaran sampai END <n>
#         bmtx               exit lalu tutup koneksi
# Catatan: nama variabel PowerShell tidak peka huruf besar-kecil.

if (-not $BmKeyFile) { $BmKeyFile = Join-Path $env:USERPROFILE ".bmahos\key.txt" }

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

function bmtx {
  bmt exit
  $script:BmTc.Close()
}

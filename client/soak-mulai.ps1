# soak-mulai.ps1: mulai soak test R8 (24 jam) di VMware dari Windows.
# Pakai (satu baris, dari PowerShell):
#   powershell -ExecutionPolicy Bypass -File "D:\Shared Folders VM\CentOS Terminal\soak-mulai.ps1"
# -Iso <nama file di shared folder>: disalin ke bmahOS.iso setelah VM mati (mis. ISO PROD
# untuk soak saat bmahOS.iso berisi ISO dev uji).
# Langkah: tolak bila soak.py masih jalan -> Power Off/On VM bmahOS (ISO di
# shared folder) -> tunggu port 7780 -> cek serial -> jalankan soak.py di
# jendela kecil (hasil di soak-R8\, folder lama diganti nama).
param([int]$Durasi = 86400, [string]$Iso = "")

$vmrun = "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
$vmx = "D:\Virtual Machines\bmahOS\bmahOS.vmx"
$sf = "D:\Shared Folders VM\CentOS Terminal"
$serial = "D:\bmahOS\aaa\bmahOS-serial.log.txt"
$kd = "$env:USERPROFILE\.bmahos"

$jalan = Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
  Where-Object { $_.CommandLine -match "soak\.py" }
if ($jalan) {
  "soak.py masih jalan (PID $($jalan.ProcessId -join ', ')): TIDAK dimulai ulang."
  "Hentikan dulu bila memang mau mengulang: Stop-Process -Id <PID>"
  exit 1
}

"ISO: $((Get-FileHash "$sf\bmahOS.iso").Hash.Substring(0, 8))"
& $vmrun -T ws stop $vmx hard
for ($i = 0; $i -lt 60; $i++) {
  if (-not (Test-Path "$sf\disk.vmdk.lck")) { break }
  Start-Sleep 1
}
if ($Iso) {
  Copy-Item "$sf\$Iso" "$sf\bmahOS.iso" -Force
  "ISO diganti dari $Iso -> $((Get-FileHash "$sf\bmahOS.iso").Hash.Substring(0, 8))"
}
& $vmrun -T ws start $vmx
$ok = $false
for ($k = 0; $k -lt 90; $k++) {
  $tc = New-Object Net.Sockets.TcpClient
  try {
    $ta = $tc.ConnectAsync("192.168.50.200", 7780)
    $ok = $ta.Wait(2000) -and $tc.Connected
  } catch {}
  $tc.Close()
  if ($ok) { break }
  Start-Sleep 2
}
"port 7780 siap: $ok"
if (-not $ok) { exit 1 }
Start-Sleep 10

$pat = "Exception|#GP|#PF|fault|panic|ERROR|FATAL|WARNING"
$pci = (Select-String -Path $serial -Pattern "PCI-1:").Count
$flt = (Select-String -Path $serial -Pattern $pat).Count
$hel = (Select-String -Path $serial -Pattern "^hello" -CaseSensitive).Count
"PCI-1 (2): $pci  fault (0): $flt  hello (PROD 0): $hel"

$out = "$sf\soak-R8"
if (Test-Path $out) {
  Rename-Item $out "soak-R8-lama-$(Get-Date -Format yyyyMMdd-HHmmss)"
}
New-Item -ItemType Directory $out | Out-Null
$a = "-u soak.py --key `"$kd\key.txt`" --pin `"$kd\tlspin.txt`""
$a = "$a --keluar soak-R8 --durasi $Durasi --interval 600"
$sp = @{ FilePath = (Get-Command python).Source }
$sp.ArgumentList = $a
$sp.WorkingDirectory = $sf
$sp.WindowStyle = "Minimized"
$sp.RedirectStandardOutput = "$out\konsol.txt"
$sp.RedirectStandardError = "$out\konsol-err.txt"
$proc = Start-Process @sp -PassThru
$sel = (Get-Date).AddSeconds($Durasi + 60)
"soak.py PID $($proc.Id) mulai $(Get-Date), selesai sekitar $sel"
"JANGAN jalankan skrip/blok vmrun lain, jangan tutup VMware, jangan matikan PC."
Start-Sleep 30
Get-Content "$out\konsol.txt" -Tail 3
Get-Content "$out\konsol-err.txt" -Tail 3

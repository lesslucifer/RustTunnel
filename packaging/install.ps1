# rtun installer for Windows. No toolchain, no source tree.
#
#   irm https://raw.githubusercontent.com/lesslucifer/RustTunnel/main/packaging/install.ps1 | iex
#
# RTUN_BASE     where the archives live  (default: the latest GitHub release)
# RTUN_BIN_DIR  where rtun.exe lands     (default: %LOCALAPPDATA%\rtun\bin)
$ErrorActionPreference = 'Stop'

$repo = if ($env:RTUN_REPO) { $env:RTUN_REPO } else { 'lesslucifer/RustTunnel' }
$base = if ($env:RTUN_BASE) { $env:RTUN_BASE } else { "https://github.com/$repo/releases/latest/download" }
$dir  = if ($env:RTUN_BIN_DIR) { $env:RTUN_BIN_DIR } else { "$env:LOCALAPPDATA\rtun\bin" }
$name = 'rtun-x86_64-pc-windows-msvc.zip'
$zip  = Join-Path $env:TEMP $name

Write-Host "downloading $name from $base"
Invoke-WebRequest "$base/$name" -OutFile $zip
$want = ((Invoke-WebRequest "$base/$name.sha256").Content -split '\s+')[0]
$got  = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($got -ne $want.ToUpper()) { throw "checksum mismatch: $got != $want" }

New-Item -ItemType Directory -Force $dir | Out-Null
Expand-Archive $zip -DestinationPath $dir -Force
Remove-Item $zip
Write-Host "installed $dir\rtun.exe"
& "$dir\rtun.exe" --version

if (($env:PATH -split ';') -notcontains $dir) {
  Write-Host "note: $dir is not on your PATH — add it, or run $dir\rtun.exe directly"
}

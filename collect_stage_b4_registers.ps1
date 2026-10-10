$ErrorActionPreference = 'Stop'
$root = $env:IDF_PATH
if (-not (Test-Path $root)) {
  $candidate = Get-ChildItem 'C:\Espressif\frameworks' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*6.1*' } | Select-Object -First 1
  if ($candidate) { $root = $candidate.FullName }
}
if (-not (Test-Path $root)) { throw 'ESP-IDF v6.1 directory not found. Set $root to your IDF_PATH and rerun.' }
$out = Join-Path (Get-Location) 'stage_b4_register_headers.zip'
$stage = Join-Path $env:TEMP 'stage_b4_register_headers'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item $stage -ItemType Directory | Out-Null
$paths = @(
  'components\hal\include\hal\emac_hal.h',
  'components\hal\emac_hal.c',
  'components\hal\esp32p4\include\hal\emac_ll.h',
  'components\soc\esp32p4\register\soc\emac_reg.h',
  'components\soc\esp32p4\register\soc\emac_struct.h',
  'components\soc\esp32p4\include\soc\emac_reg.h',
  'components\soc\esp32p4\include\soc\emac_struct.h'
)
$found = 0
foreach ($rel in $paths) {
  $src = Join-Path $root $rel
  if (Test-Path $src) {
    $dest = Join-Path $stage $rel
    New-Item (Split-Path $dest) -ItemType Directory -Force | Out-Null
    Copy-Item $src $dest
    $found++
  }
}
# Capture actual target-specific EMAC HAL/LL and register definitions if their layout differs.
$extras = Get-ChildItem (Join-Path $root 'components') -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match '^emac_(hal|ll|reg|struct)\.([ch])$' -and $_.FullName -match 'esp32p4|[\\/]hal[\\/]'
}
foreach ($file in $extras) {
  $rel = $file.FullName.Substring($root.Length).TrimStart('\')
  $dest = Join-Path $stage $rel
  New-Item (Split-Path $dest) -ItemType Directory -Force | Out-Null
  Copy-Item $file.FullName $dest -Force
  $found++
}
if ($found -eq 0) { throw "No EMAC register/HAL headers found beneath $root" }
if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $out
Write-Host "Created $out ($found source matches)"

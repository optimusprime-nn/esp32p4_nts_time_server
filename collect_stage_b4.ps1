param([string]$Project = 'C:\Espressif\projects\esp32p4_nts_time_server')
$ErrorActionPreference='Stop'
$paths=@(
 'components/esp_eth/src/mac/esp_eth_mac_esp.c',
 'components/esp_eth/src/mac/esp_eth_mac_esp_dma.c',
 'components/esp_eth/src/mac/include/esp_private/eth_mac_esp_dma.h',
 'components/esp_eth/include/esp_eth_rx_diag.h',
 'main/eth_service.c',
 'main/eth_service.h',
 'main/diagnostics.c'
)
$out=Join-Path (Get-Location) 'stage_b4_source_capture.zip'
$tmp=Join-Path $env:TEMP ('stage_b4_sources_'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
 foreach($rel in $paths){
  $src=Join-Path $Project ($rel -replace '/','\')
  if(Test-Path -LiteralPath $src){
   $dst=Join-Path $tmp ($rel -replace '/','\')
   New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
   Copy-Item -LiteralPath $src -Destination $dst
   Write-Host "Captured $rel"
  } else {Write-Warning "Missing: $rel"}
 }
 $dma=Get-ChildItem -Path (Join-Path $Project 'components/esp_eth') -Filter '*dma*.h' -Recurse -File -ErrorAction SilentlyContinue
 foreach($f in $dma){
  $rel=$f.FullName.Substring($Project.Length).TrimStart('\')
  $dst=Join-Path $tmp $rel
  New-Item -ItemType Directory -Path (Split-Path $dst) -Force | Out-Null
  Copy-Item $f.FullName $dst -Force
 }
 if(Test-Path $out){Remove-Item $out -Force}
 Compress-Archive -Path (Join-Path $tmp '*') -DestinationPath $out
 Write-Host "Created $out"
} finally {Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue}

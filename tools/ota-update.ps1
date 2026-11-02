param(
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$FirmwareBin
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $FirmwareBin)) { throw "Firmware image not found: $FirmwareBin" }
$base = "https://$HostName"
Write-Host "Reading OTA status..."
$before = Invoke-RestMethod -Uri "$base/api/v1/ota/status" -CertificateThumbprint $CertificateThumbprint
$before | ConvertTo-Json -Depth 5
Write-Host "Uploading $FirmwareBin to inactive OTA partition..."
$result = Invoke-RestMethod -Method Post -Uri "$base/api/v1/ota/image" -CertificateThumbprint $CertificateThumbprint -ContentType 'application/octet-stream' -InFile $FirmwareBin
$result | ConvertTo-Json -Depth 5
if (-not $result.staged) { throw 'Device did not report a staged OTA image.' }
Write-Host "OTA image staged and validated. Reboot is intentionally separate."
Write-Host "Activate with: Invoke-RestMethod -Method Post -Uri '$base/api/v1/system/reboot' -CertificateThumbprint '$CertificateThumbprint'"

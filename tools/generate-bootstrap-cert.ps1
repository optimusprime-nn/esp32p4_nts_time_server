<#
Creates main/servercert.pem and main/serverkey.pem, which the build embeds.

They are the self-signed HTTPS identity used only until the device has a
production Let's Encrypt certificate (during enrollment and first setup).
Generate them once per clone. They are git-ignored and must never be committed.
Existing files are left alone unless -Force is given.
#>
param(
    [string]$CommonName = "esp32p4-ntp",
    [int]$Days = 3650,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Resolve-OpenSsl {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @(
        "C:\Program Files\FireDaemon OpenSSL 4\bin\openssl.exe",
        "C:\Program Files\Git\mingw64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe")) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw "OpenSSL is required but was not found. Install it with: winget install --id FireDaemon.OpenSSL -e"
}

$mainDir = Join-Path (Split-Path -Parent $PSScriptRoot) "main"
$cert = Join-Path $mainDir "servercert.pem"
$key = Join-Path $mainDir "serverkey.pem"

if (((Test-Path -LiteralPath $cert) -or (Test-Path -LiteralPath $key)) -and -not $Force) {
    Write-Host "Bootstrap certificate already present in $mainDir; nothing changed. Use -Force to replace it."
    return
}

$OpenSsl = Resolve-OpenSsl
# OpenSSL writes progress to stderr, which is fatal under "Stop" in Windows PowerShell.
$ErrorActionPreference = "Continue"
& $OpenSsl req -x509 -newkey rsa:2048 -sha256 -nodes -days $Days `
    -keyout $key -out $cert -subj "/CN=$CommonName/O=ESP32-P4 GNSS NTP Bootstrap" `
    -addext "subjectAltName=DNS:$CommonName,DNS:$CommonName.local" `
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" `
    -addext "extendedKeyUsage=serverAuth" *> $null
$exit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($exit -ne 0) { throw "Bootstrap certificate generation failed." }

Write-Host "Created $cert"
Write-Host "Created $key"

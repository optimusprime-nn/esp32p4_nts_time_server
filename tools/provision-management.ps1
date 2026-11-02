param(
    [Parameter(Mandatory=$true)][string]$HostName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{32}$')][string]$ProvisioningCode,
    [string]$OutputDirectory = ".\management-credentials",
    [string]$AdministratorName = "ntp-admin"
)

$ErrorActionPreference = "Stop"

function Resolve-OpenSsl {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "C:\Program Files\FireDaemon OpenSSL 4\bin\openssl.exe",
        "C:\Program Files\Git\mingw64\bin\openssl.exe",
        "C:\Program Files\Git\usr\bin\openssl.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }

    throw @"
OpenSSL is required but was not found.
Install a supported OpenSSL CLI and restart PowerShell, or add it to PATH.
A tested Windows option is:
  winget install --id FireDaemon.OpenSSL -e
Then verify with:
  openssl version
"@
}

$OpenSsl = Resolve-OpenSsl
if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
    throw "curl.exe is required and was not found. Windows 10/11 normally includes curl.exe. Verify with: curl.exe --version"
}

$dir = [IO.Path]::GetFullPath($OutputDirectory)
$credentialNames = @(
    "management-ca.key.pem", "management-ca.crt.pem", "management-ca.srl",
    "admin-client.key.pem", "admin-client.crt.pem", "admin-client.p12"
)
if (Test-Path -LiteralPath $dir) {
    $existing = @($credentialNames | Where-Object { Test-Path -LiteralPath (Join-Path $dir $_) })
    if ($existing.Count -gt 0) {
        throw "Output directory already contains management credentials: $dir`nChoose a new -OutputDirectory for this board. Existing credentials will not be overwritten."
    }
}
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$secure = Read-Host "Choose a password for the management CA key and administrator P12" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
if ([string]::IsNullOrWhiteSpace($password)) { throw "Password must not be empty." }
$env:PROVISION_PKI_PASSWORD = $password
$password = $null

$caKey = Join-Path $dir "management-ca.key.pem"
$caCert = Join-Path $dir "management-ca.crt.pem"
$adminKey = Join-Path $dir "admin-client.key.pem"
$adminCsr = Join-Path $dir "admin-client.csr.pem"
$adminCert = Join-Path $dir "admin-client.crt.pem"
$adminP12 = Join-Path $dir "admin-client.p12"
$ext = Join-Path $dir "admin-client.ext"
$serial = Join-Path $dir "management-ca.srl"

try {
    & $OpenSsl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass env:PROVISION_PKI_PASSWORD -out $caKey
    if ($LASTEXITCODE -ne 0) { throw "CA key generation failed." }

    & $OpenSsl req -x509 -new -sha256 -days 3650 -key $caKey -passin env:PROVISION_PKI_PASSWORD -out $caCert `
        -subj "/CN=ESP32-P4 Management CA" `
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" `
        -addext "keyUsage=critical,keyCertSign,cRLSign" `
        -addext "subjectKeyIdentifier=hash"
    if ($LASTEXITCODE -ne 0) { throw "CA certificate generation failed." }

    # Keep the standalone administrator private key encrypted as well as the exported P12.
    & $OpenSsl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass env:PROVISION_PKI_PASSWORD -out $adminKey
    if ($LASTEXITCODE -ne 0) { throw "Administrator key generation failed." }
    & $OpenSsl req -new -sha256 -key $adminKey -passin env:PROVISION_PKI_PASSWORD -out $adminCsr -subj "/CN=$AdministratorName"
    if ($LASTEXITCODE -ne 0) { throw "Administrator CSR generation failed." }

    @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii $ext

    & $OpenSsl x509 -req -sha256 -days 825 -in $adminCsr -CA $caCert -CAkey $caKey `
        -passin env:PROVISION_PKI_PASSWORD -CAcreateserial -CAserial $serial -out $adminCert -extfile $ext
    if ($LASTEXITCODE -ne 0) { throw "Administrator certificate signing failed." }

    & $OpenSsl pkcs12 -export -out $adminP12 -inkey $adminKey -passin env:PROVISION_PKI_PASSWORD -in $adminCert -certfile $caCert `
        -name $AdministratorName -passout env:PROVISION_PKI_PASSWORD
    if ($LASTEXITCODE -ne 0) { throw "P12 creation failed." }

    Write-Host ""
    Write-Host "Claiming the device. The bootstrap HTTPS certificate is expected to be locally untrusted."
    & curl.exe -fsk -X PUT `
        -H "X-Provisioning-Code: $ProvisioningCode" `
        -H "Content-Type: application/x-pem-file" `
        --data-binary "@$caCert" `
        "https://${HostName}/api/v1/provisioning/claim"
    if ($LASTEXITCODE -ne 0) {
        throw "Device claim failed. Generated credentials were retained in '$dir' for diagnosis/retry; do not generate a second credential set until device state is checked."
    }

    Write-Host ""
    Write-Host "Management ownership claimed. The device will reboot."
    Write-Host "Administrator P12: $adminP12"
    Write-Host "Management CA certificate: $caCert"
    Write-Host "Management CA private key: $caKey (encrypted; keep offline/private)"
    Write-Host "Administrator private key: $adminKey (encrypted; keep private)"
    Write-Host "Import the P12 into the administrator certificate store before opening the normal web console."
    Write-Host "For additional boards, use a different -OutputDirectory and preserve each board's credentials."
} finally {
    Remove-Item Env:PROVISION_PKI_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item $adminCsr,$ext -Force -ErrorAction SilentlyContinue
}

# Manual setup

Use this page if you build the firmware yourself and flash it with `idf.py`.
If you are using the release download, follow
[Quick setup with the tool](../setup-tool/index.md) instead.

You need everything in [What you need](what-you-need.md), plus ESP-IDF v6.1 as
described in [Building from source](../building.md). Allow about an hour for the
first board.

!!! warning "Step 3 is permanent"
    The first boot burns a flash-encryption key into the chip's eFuses. This
    cannot be undone. Use the production configuration and do not interrupt it.

## 1. Build the firmware

In an ESP-IDF PowerShell or shell:

```powershell
git clone https://github.com/optimusprime-nn/esp32p4_nts_time_server.git
cd esp32p4_nts_time_server
idf.py build
```

From 3.1.11 no certificate files are needed to build. The board creates its own
bootstrap certificate at first boot.

**Check before continuing.** This must print the setting as `=y`:

=== "Windows (PowerShell)"

    ```powershell
    Select-String -Path sdkconfig -Pattern '^CONFIG_SECURE_FLASH_ENC_ENABLED'
    ```

=== "Linux"

    ```sh
    grep '^CONFIG_SECURE_FLASH_ENC_ENABLED' sdkconfig
    ```

If it does not, stop. Delete `sdkconfig` and build again.

## 2. Find the serial port

Connect the USB cable. On Windows, find the port in Device Manager under
**Ports (COM & LPT)**. On Linux it is usually `/dev/ttyUSB0` or `/dev/ttyACM0`.
The examples use `COM7`.

## 3. First flash (new board only)

```powershell
idf.py -p COM7 flash monitor
```

The bootloader encrypts the flash on first boot and resets the board at least
once. **Do not disconnect power or close the monitor until you see the
application start.** Leave the monitor running for the next step.

!!! danger "Plain `flash` is for unencrypted boards only"
    On a board that is already encrypted, `idf.py flash` writes unreadable data.
    Use `idf.py -p COM7 encrypted-flash --all` instead. See
    [Building from source](../building.md#flashing-an-encrypted-board).

## 4. Note the code, fingerprint and address

In the monitor, look for:

```text
W (...) OWNERSHIP: Device is UNPROVISIONED
W (...) OWNERSHIP: One-time management enrollment code: 0123456789ABCDEF0123456789ABCDEF
W (...) WEB: Bootstrap certificate SHA-256: 3F2A...(64 hex characters)
I (...) ETH: DHCP IPv4 acquired: 192.0.2.10
```

Note all three. A new enrollment code is generated at every boot until the board
is claimed, so always use the latest one. Five wrong attempts lock enrollment
until the next reboot.

Exit the monitor with `Ctrl+]`.

## 5. Claim the board

**Recommended: use the setup tool from the source tree.** It checks the
fingerprint for you and does steps 5 to 9 in one go:

=== "Windows"

    ```bat
    tools\setup\setup.cmd
    ```

=== "Linux"

    ```sh
    tools/setup/setup.sh
    ```

On the Firmware step, say the board is **not** new so nothing is written. The
tool resets the board, reads the details above itself, and carries on as in
[Quick setup with the tool](../setup-tool/index.md).

**Alternative on Windows: the PowerShell script.** It needs OpenSSL
(`winget install --id FireDaemon.OpenSSL -e`, then open a new PowerShell).

1. First check that you are talking to your board. Compare this output with the
   fingerprint from step 4, ignoring the colons:

    ```powershell
    $null | openssl s_client -connect 192.0.2.10:443 2>$null |
        openssl x509 -noout -fingerprint -sha256
    ```

    If it differs, stop: something on the network is answering for the board.
    The script itself does not check the certificate.

2. Claim:

    ```powershell
    .\tools\provision-management.ps1 `
        -HostName 192.0.2.10 `
        -ProvisioningCode 0123456789ABCDEF0123456789ABCDEF `
        -OutputDirectory "$HOME\Documents\management-credentials-ts1"
    ```

    The script asks for a password, creates a management CA and an
    administrator certificate, and sends **only the CA certificate** to the
    board. The board closes enrollment and reboots.

- Use a **different output folder for every board**.
- Keep that folder and its password safe and outside the repository. There is no
  remote way to recover a board if they are lost.

## 6. Install your administrator certificate

```powershell
$dir = "$HOME\Documents\management-credentials-ts1"
$password = Read-Host "P12 password" -AsSecureString
Import-PfxCertificate -FilePath "$dir\admin-client.p12" `
    -CertStoreLocation Cert:\CurrentUser\My -Password $password
```

Note the **Thumbprint** it prints; the update script uses it. On Linux, import
`admin-client.p12` into your browser as in
[Linux, setup window](../setup-tool/linux-window.md#open-the-console-in-a-browser).

## 7. Open the console

Browse to `https://192.0.2.10/`. Your browser will:

1. Warn that the certificate is not trusted. This is expected until step 9,
   because the board is still using its self-made bootstrap certificate.
2. Ask you to choose a client certificate. Choose `ntp-admin`.

If you get a connection error instead, close the browser completely and try
again. Browsers remember a "no certificate" choice.

Open **Diagnostics** and check **GNSS Receiver — Diagnostics**. A first fix can
take several minutes. On a receiver that has lost its memory, the clock can take
up to about 12.5 minutes to synchronize, because the leap-second data has to
arrive from the satellites.

## 8. Set the network address and DNS

Open **Management**.

1. If you are not using a DHCP reservation, tick **Static IPv4 address**, enter
   the address, netmask, gateway and DNS server, and click **Save Network**. It
   applies after a reboot: open **System**, click **Reboot Device**, and
   reconnect at the new address.
2. In Cloudflare, or your local DNS, create an `A` record pointing the DNS name
   at the board's address. If the address is private, set Cloudflare to
   **DNS only**, not proxied.

## 9. Commission and get a certificate

On **Management**, in **Commissioning & Certificate Setup**, in this order:

1. Enter **Device hostname**, **Certificate FQDN** and two **External NTP**
   servers. Click **Save Identity & External NTP**.
2. Click **Sync Management Time**. This gives TLS the correct date if GNSS has
   not locked yet. It never affects the time the server serves.
3. Enter **Cloudflare zone name**, **Cloudflare Zone ID** and **Cloudflare API
   token**. Click **Save/Test Cloudflare** and wait for it to finish.
4. Click **Request Certificate**. This can take a few minutes while DNS
   validation completes.

The board switches to the new certificate by itself. Reconnect using the name:
`https://ts1.example.com/`. The browser warning should be gone.

NTS starts once the certificate is available. It retries about once a minute,
so allow a few minutes, then check that **NTS Service** on the dashboard shows
**NTS-KE Running: YES**.

## 10. Finish

1. [Check that it works](verify.md).
2. [Download a backup](../using/backup-restore.md).
3. For a second board, repeat with a different hostname, DNS name, address and
   credentials folder, then see [Two servers](../using/redundancy.md).

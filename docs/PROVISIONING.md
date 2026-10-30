# Provisioning a Time Server

This guide takes a new ESP32-P4 board to a working NTP/NTS server. It assumes you
are comfortable with PowerShell but have not used this project before. Allow
about an hour for the first board.

> **Read this first: step 3 is permanent.** The first boot burns a flash-encryption
> key into the chip's eFuses. This cannot be undone. Use the correct firmware
> configuration and do not interrupt it.

## What you need

**Hardware**
- The board, with the LEA-M8T connected as in the [README](../README.md#hardware)
- A GNSS antenna with a clear view of the sky
- An Ethernet connection with DHCP, and internet access
- A USB cable to the board's serial port
- Optional: a microSD card for the log archive

**On your Windows PC**
- ESP-IDF v6.1 ([Espressif Installation Manager](https://docs.espressif.com/projects/idf-im-ui/en/latest/))
- OpenSSL: `winget install --id FireDaemon.OpenSSL -e`, then open a new PowerShell
- `curl.exe` (included with Windows 10 and 11)

**Accounts**
- A domain managed by Cloudflare
- A Cloudflare API token limited to **Zone: Read** and **DNS: Edit** on that zone
- That zone's **Zone ID**, from its Cloudflare overview page

**Decide before you start**

| Item | Example |
|---|---|
| Device hostname | `ts1` |
| Certificate FQDN | `ts1.example.com` |
| Fixed IP address, or a DHCP reservation | `192.0.2.10` |
| A safe place for credentials, outside this repository | a password manager |

The server's address must not change, because the DNS name points to it.

## 1. Build the firmware

Open an ESP-IDF PowerShell, then:

```powershell
git clone https://github.com/optimusprime-nn/esp32p4_nts_time_server.git
cd esp32p4_nts_time_server
.\tools\generate-bootstrap-cert.ps1
idf.py build
```

`generate-bootstrap-cert.ps1` creates a self-signed certificate that the board
uses only until it has a real one. It is git-ignored.

**Check before continuing.** This must print the setting as `=y`:

```powershell
Select-String -Path sdkconfig -Pattern '^CONFIG_SECURE_FLASH_ENC_ENABLED'
```

If it does not, stop. Delete `sdkconfig` and build again.

## 2. Find the serial port

Connect the USB cable and find the port in Device Manager under
**Ports (COM & LPT)**. The examples below use `COM7`.

## 3. First flash (new board only)

```powershell
idf.py -p COM7 flash monitor
```

The bootloader encrypts the flash on first boot and resets the board at least
once. **Do not disconnect power or close the monitor until you see the
application start.** Leave the monitor running for the next step.

> Use this plain `flash` command **only** on a board that has never been
> encrypted. On an encrypted board it writes unreadable data. Use the
> `encrypted-flash` command in [Maintenance](#maintenance).

## 4. Copy the enrollment code and IP address

In the monitor, look for:

```text
W (...) OWNERSHIP: Device is UNPROVISIONED
W (...) OWNERSHIP: One-time management enrollment code: 0123456789ABCDEF0123456789ABCDEF
```

Note the code and the board's IP address, which is printed when Ethernet comes
up. You can also find it in your DHCP server's lease list.

A new code is generated at every boot until the board is claimed, so always use
the latest one. Five wrong attempts lock enrollment until the next reboot.

Exit the monitor with `Ctrl+]`.

## 5. Claim the board

```powershell
.\tools\provision-management.ps1 `
    -HostName 192.0.2.10 `
    -ProvisioningCode 0123456789ABCDEF0123456789ABCDEF `
    -OutputDirectory "$HOME\Documents\management-credentials-ts1"
```

The script asks you to choose a password, creates a management certificate
authority and an administrator certificate on your PC, and sends **only the CA
certificate** to the board. The board then closes enrollment and reboots.

- Use a **different `-OutputDirectory` for every board**.
- Keep that folder and its password safe. Do **not** store it inside this
  repository. There is no remote way to recover a board if it is lost.

## 6. Install your administrator certificate

```powershell
$dir = "$HOME\Documents\management-credentials-ts1"
$password = Read-Host "P12 password" -AsSecureString
Import-PfxCertificate -FilePath "$dir\admin-client.p12" `
    -CertStoreLocation Cert:\CurrentUser\My -Password $password
```

Note the **Thumbprint** it prints. The OTA script uses it.

## 7. Open the console

Browse to `https://192.0.2.10/`. Your browser will:

1. Warn that the certificate is not trusted. This is expected until step 9.
2. Ask you to choose a client certificate. Choose `ntp-admin`.

The dashboard should appear. If you get a connection error instead, close the
browser completely and try again. Browsers remember the "no certificate" choice.

Check the **GNSS Receiver** card. A first fix can take several minutes. On a
receiver that has lost its memory, the clock can take up to about 12.5 minutes to
synchronize, because the leap-second data has to arrive from the satellites.

## 8. Set the network address and DNS

Open **Management**.

1. If you are not using a DHCP reservation, tick **Static IPv4 address**, enter
   the address, netmask, gateway and DNS server, and click **Save Network**. This
   applies after a reboot, so use **System Actions** to reboot and reconnect at
   the new address.
2. In Cloudflare, or your local DNS, create an `A` record pointing the FQDN at
   the board's address. If the address is private, set Cloudflare to **DNS only**,
   not proxied.

## 9. Commission and get a certificate

Still on **Management**, in **Commissioning & Certificate Setup**, work through
these in order:

1. Enter **Device hostname**, **Certificate FQDN** and two **External NTP**
   servers. The defaults are fine. Click **Save Identity & External NTP**.
2. Click **Sync Management Time**. This gives TLS correct time if GNSS has not
   locked yet. It never affects the time the server serves.
3. Enter **Cloudflare zone name**, **Zone ID** and **API token**. Click
   **Save/Test Cloudflare**. Wait for it to pass.
4. Click **Request Certificate**. This can take a few minutes while DNS
   validation completes.

The board activates the certificate by itself. Reconnect using the FQDN:
`https://ts1.example.com/`. The browser warning should be gone.

NTS starts once the certificate is available. The service retries about once a
minute, so allow a few minutes, then check that **NTS Service** shows it running.

## 10. Verify

The board is ready when all of these are true:

| Where | Expect |
|---|---|
| Clock and Time | `SYNCHRONIZED` |
| GNSS Receiver | 3D fix, leap status `NONE` |
| NTP Service | Stratum 1 |
| NTS Service | Running |
| Certificate & ACME | Valid, matches the FQDN |

Then test from your PC:

```powershell
w32tm /stripchart /computer:ts1.example.com /samples:3 /dataonly
```

The offsets show your PC's error against the server, so they may be large if your
PC's clock is poor. What matters is that replies arrive.

To test NTS with chrony on Linux, add the `server ... nts` line from the README,
restart chrony, and run `chronyc -N authdata`. The `NTS` mode should show a
non-zero cookie count.

## 11. Add a second board

Repeat this guide with a different hostname, FQDN, address and credentials folder.
Then on each board, in **Management**, open **Redundant Time Server**, enter the
**other** board's FQDN and click **Save Redundant Server**.

The defaults warn at 100 µs and go critical at 1 ms. Both boards remain
independent stratum-1 servers: there is no primary, and neither can change the
other's clock.

## 12. Back up

Click **Download Backup** under **Configuration Backup & Restore**.

**The backup contains your Cloudflare token.** Store it with the credentials, not
in the repository.

## Maintenance

### Update firmware (normal method)

Open **Management → Firmware**, or go to `/management/firmware`.

1. Choose `build\esp32p4_nts_time_server.bin` and click **Upload & Validate**.
2. Click **Activate Staged Image & Reboot**.
3. The board is back in about a minute. It shows as pending for 5 minutes, then
   confirmed. If it crashes before that, it rolls back by itself.

Or from PowerShell, using the thumbprint from step 6:

```powershell
.\tools\ota-update.ps1 -HostName ts1.example.com `
    -CertificateThumbprint <thumbprint> `
    -FirmwareBin .\build\esp32p4_nts_time_server.bin
```

### Roll back

On the Firmware page, click **Roll Back & Reboot**. The previous image is verified
first, then has to pass the same 5-minute soak. Rollback is unavailable while a
staged image is waiting for a reboot. Firmware older than 3.1.4 has no button.

### Reflash over USB (encrypted board)

Only needed if OTA is not possible:

```powershell
idf.py -p COM7 encrypted-flash --all
```

After flashing, the chip may stay in the bootloader. Press reset to start it. This
keeps the board's settings and ownership.

**Never** use plain `idf.py flash` on an encrypted board, and never erase the
`nvs_keys` partition: the board's stored secrets depend on it.

### Certificates

| Certificate | Lifetime | Renewal |
|---|---|---|
| Let's Encrypt server | About 90 days | Automatic, starting 30 days before expiry |
| Administrator client | 825 days | Manual, see below |
| Management CA | 10 years | Requires re-claiming the board |

Keep the Cloudflare token valid, or automatic renewal fails. Set a reminder for
the administrator certificate. To renew it, sign a new one with the CA key in your
credentials folder using the same settings as `tools/provision-management.ps1`,
then import it. **Do this before it expires.**

### Lost credentials

There is deliberately no remote reset. If the administrator certificate and CA key
are both lost, the board must be recovered over USB by clearing its stored
ownership, which also loses its settings. **This procedure has not been tested.**
Keep the credentials safe so that you never need it.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| No enrollment code | Open the monitor and reset the board. If `UNPROVISIONED` does not appear, it is already claimed |
| Claim returns 403 or 429 | Wrong code, or locked. Reboot and use the new code |
| Console will not connect | Certificate not imported or wrong one chosen. Close the browser completely and retry |
| Clock stays `ACQUIRING` | Check the antenna, the PPS wire and GNSS fix. Allow 12.5 minutes after a cold start |
| Certificate request fails | Check `Save/Test Cloudflare`, the token permissions, and that the board has internet access and valid management time |
| NTS not running | No certificate yet. Check **Certificate & ACME** |
| NTS client certificate error | Use the hostname, not the IP address |
| Stratum 16 | Clock not synchronized. This is correct behaviour, not a fault |
| Unexpected reboot | Check **Operations & Reset History**. Look for `Network watchdog` or `Ethernet RX stalled` |
| SD card not mounting | Check the card is FAT-formatted. Timing is not affected |

To read the board's log at any time without changing anything:

```powershell
idf.py -p COM7 monitor
```

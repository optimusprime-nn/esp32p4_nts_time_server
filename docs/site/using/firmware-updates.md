# Firmware updates and rollback

The board has two firmware slots. An update is written to the slot that is not
running, checked, and only used after a reboot. The previous version stays in
the other slot.

Use the image for the board's silicon from the
[release](../getting-started/download.md):

| Board's chip revision | File |
|---|---|
| v1.x | `esp32p4_nts_time_server-<version>-silicon-v1.bin` |
| v3.x | `esp32p4_nts_time_server-<version>-silicon-v3.bin` |

If you build from source, use `esp32p4_nts_time_server.bin` from `build/` (v1.x)
or `build-v3/` (v3.x).

To find the revision, look at **Hardware Profile & GPIO** on the Management page
(*Detected silicon: wafer vX.YY*). The serial console and `esptool` also show
it. A wrong image is refused at upload, before anything is staged, so it cannot
be installed by mistake.

NTP and NTS stop for about a minute while the board reboots. With
[two servers](redundancy.md), update one at a time.

## Update from the console

1. Open **OTA** (the Firmware page, `/management/firmware`).
2. Under **Stage Firmware**, choose the `.bin` file and click
   **Upload & Validate**. Wait for *Staged successfully*.
3. Under **Activation**, click **Activate Staged Image & Reboot** and confirm.
4. Reconnect after about a minute. **Firmware Status** shows the new
   **Current Version**.

## The 5-minute soak

A new image is on trial until it has run for 5 minutes (300 s) with the web
console up. Then the board confirms it and the **Confirmed** count goes up.

If the new image crashes or resets before it is confirmed, or its web console
never starts, the bootloader goes back to the previous image by itself. You do
not need to do anything.

## Roll back by hand

On the Firmware page, under **Rollback**, click **Roll Back & Reboot** and
confirm. The board verifies the image in the other slot first, then boots it.
The restored image has to pass the same 5-minute soak; if it fails, the board
returns to the image you rolled back from.

Rollback is unavailable when:

| The page says | Why |
|---|---|
| *Unavailable: a staged image is waiting for a reboot* | You uploaded an image but have not activated it. Activate it, or upload the version you want instead |
| *No previous image available* | The other slot is empty or does not hold a valid image |
| *Rollback refused* with a reason | An OTA upload, certificate operation or TLS hand-over is running (3.1.10 and later). Wait and try again |

Firmware older than 3.1.4 has no rollback button.

## Update from a script

=== "Windows (PowerShell)"

    The repository includes `tools/ota-update.ps1`. It uses the certificate
    imported into Windows, identified by its thumbprint:

    ```powershell
    .\tools\ota-update.ps1 -HostName ts1.example.com `
        -CertificateThumbprint <thumbprint> `
        -FirmwareBin .\esp32p4_nts_time_server-3.1.11-silicon-v1.bin
    ```

    It uploads and stages the image and prints the command that activates it.

=== "curl"

    ```sh
    cd ~/Documents/management-credentials-ts1
    B=https://ts1.example.com
    C="--cert admin-client.crt.pem --key admin-client.key.pem --pass $KEYPASS"

    curl -sS $C -X POST -H 'Content-Type: application/octet-stream' \
         --data-binary @esp32p4_nts_time_server-3.1.11-silicon-v1.bin $B/api/v1/ota/image
    curl -sS $C -X POST $B/api/v1/system/reboot
    curl -sS $C $B/api/v1/ota/status
    ```

    Set `KEYPASS` to the credentials folder's password first, for example with
    `read -rs KEYPASS`.

A rollback from a script needs the confirmation header:

```sh
curl -sS $C -X POST -H 'X-Confirm-Rollback: ROLLBACK' $B/api/v1/ota/rollback
```

See [Management API](../reference/api.md#firmware) for all responses.

## Reboot refusals

From 3.1.10, `POST /api/v1/system/reboot` and `POST /api/v1/ota/rollback`
answer `409 Conflict`, with the reason, while any of these is in progress:

- an OTA upload;
- a Let's Encrypt certificate operation (issue or renewal);
- a TLS hand-over to a new certificate.

Activating a staged image is not affected: the upload has finished by then.

## Reflashing over USB

Only needed if the board cannot be reached over the network. It requires the
source tree and ESP-IDF; see
[Building from source](../building.md#flashing-an-encrypted-board). Settings and
ownership are kept.

# Management API (v1)

Everything the web console does goes through this HTTPS API on port 443. Use it
for scripts and monitoring.

- **Before the board is claimed**, only two addresses exist: `GET /` (an
  information page) and `PUT /api/v1/provisioning/claim`. No client certificate
  is asked for.
- **After the claim**, every address needs a client certificate signed by your
  management CA (mutual TLS). Connections without one are refused during the
  TLS handshake, before any HTTP request is read.

Request bodies are JSON with `Content-Type: application/json` unless stated.
Errors come back as plain text with a `4xx` or `5xx` status. Responses carry
`Cache-Control: no-store`.

## Calling the API

The examples use the files in your credentials folder. The private key is
encrypted with the folder's password.

=== "curl (Linux, macOS)"

    ```sh
    cd ~/Documents/management-credentials-ts1
    read -rs KEYPASS          # type the folder's password
    curl -sS --cert admin-client.crt.pem --key admin-client.key.pem --pass "$KEYPASS" \
         https://ts1.example.com/api/v1/status
    ```

=== "PowerShell (Windows)"

    Uses the certificate imported into your Windows store. Find its thumbprint
    with `Get-ChildItem Cert:\CurrentUser\My`.

    ```powershell
    $t = "<thumbprint>"
    Invoke-RestMethod -Uri https://ts1.example.com/api/v1/status -CertificateThumbprint $t
    Invoke-RestMethod -Method Put -Uri https://ts1.example.com/api/v1/config/hostname `
        -CertificateThumbprint $t -ContentType application/json -Body '{"hostname":"ts1"}'
    ```

Use the board's DNS name once it has its Let's Encrypt certificate; normal
certificate checks then work. Before that, the board uses its own bootstrap
certificate, which no client trusts. The setup tool checks it against the
fingerprint printed on the serial console. For one-off manual calls in that
window, compare the fingerprint yourself (see
[Manual setup](../getting-started/manual-setup.md#5-claim-the-board)) and then
use `curl -k`.

## Confirmation headers

Destructive actions need a header with a fixed word. Without it the board
answers `412 Precondition Failed`.

| Header | Value | Used by |
|---|---|---|
| `X-Provisioning-Code` | The 32-character enrollment code from the serial console | `PUT /api/v1/provisioning/claim` |
| `X-Confirm-Rollback` | `ROLLBACK` | `POST /api/v1/ota/rollback` |
| `X-Confirm-Erase` | `ERASE` | `POST /api/v1/storage/erase-logs` |
| `X-Confirm-Format` | `FORMAT` | `POST /api/v1/storage/format` |

## Pages

| Method | Path | Page |
|---|---|---|
| GET | `/` | Dashboard (before the claim: the enrollment information page) |
| GET | `/system` | System |
| GET | `/management` | Management |
| GET | `/diagnostics` | Diagnostics |
| GET | `/management/firmware` | Firmware |

## Enrollment

| Method | Path | Purpose |
|---|---|---|
| PUT | `/api/v1/provisioning/claim` | Claim an unclaimed board |

The body is your management CA certificate in PEM
(`Content-Type: application/x-pem-file`), with the `X-Provisioning-Code` header.

| Status | Meaning |
|---|---|
| `202` | Claimed. `{"claimed":true,"reboot_required":true,...}`. The board reboots about a second later and from then on requires mTLS |
| `400` | The CA certificate is missing, too long or invalid |
| `401` | No `X-Provisioning-Code` header |
| `403` | Wrong code |
| `429` | Five wrong codes: enrollment is locked until the board reboots, which prints a new code |
| `404` | The board is already claimed |

## Status and health

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/status` | Everything the dashboard shows, as JSON |
| GET | `/api/v1/health` | Short readiness check |
| GET | `/metrics` | Prometheus text format. See [Metrics](metrics.md) |
| GET | `/api/v1/operations/history` | Boot count, reset counts and the retained event list |

`/api/v1/status` has these sections: `device` (hostname, IPv4, netmask,
gateway, link, MAC), `clock`, `gnss`, `pps`, `ntp`, `nts`, `peer_monitor`,
`system` (uptime, reset reason, heap figures such as `heap_internal_free`,
`heap_internal_min_free`, `heap_internal_largest_block`, `heap_psram_free`,
`heap_psram_min_free`), `console` and `readiness`.

`/api/v1/health` answers `200` with `{"status":"ok","hostname":"ts1","ntp_ready":true}`
when Ethernet has a link and an address, the NTP socket is bound and the clock
is servable. Otherwise it answers `503` with `"status":"not-ready"`.

## System

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/system/reboot` | Reboot about a second after replying. `202` `{"scheduled":true,"action":"reboot"}` |

From 3.1.10 the reboot is refused with `409` and a reason while an OTA upload, a
production certificate operation or a TLS hand-over is in progress.

## Configuration

| Method | Path | Purpose | Body |
|---|---|---|---|
| GET | `/api/v1/config` | Current settings: hostname, Cloudflare (without the token; `api_token_present` only), peer monitor, redundant server, network | |
| PUT | `/api/v1/config/hostname` | Set the hostname | `{"hostname":"ts1"}` |
| PUT | `/api/v1/config/network` | DHCP or static IPv4. Applies at the next reboot | `{"static_ipv4_enabled":true,"address":"192.0.2.10","netmask":"255.255.255.0","gateway":"192.0.2.1","dns":"192.0.2.1, 1.1.1.1"}`. `dns` holds up to two addresses separated by a comma (names are refused). With `false`, the other fields are ignored. `GET /api/v1/config` returns them as `network.dns`, and the servers in use now (including from DHCP) as `network.dns_in_use` |
| PUT | `/api/v1/config/peer-monitor` | General peer monitoring | `enabled`, `poll_interval_seconds` (4–3600), `response_timeout_ms` (250–10000), and `peer0_enabled`/`peer0` to `peer2_enabled`/`peer2` (all six required) |
| PUT | `/api/v1/config/redundant-server` | The redundant time server | `{"enabled":true,"server":"ts2.example.com","warning_ns":100000,"critical_ns":1000000}` |
| PUT | `/api/v1/config/cloudflare` | Store the Cloudflare token and zone | `{"api_token":"...","zone_name":"example.com","zone_id":"<32 hex>"}`. `zone_id` is optional: if it is left out the board looks it up with the token (needs Zone:Read), which also checks the token works from the board. A supplied `zone_id` is stored without that check |
| DELETE | `/api/v1/config/cloudflare` | Remove the Cloudflare settings and token | |
| POST | `/api/v1/config/cloudflare/verify` | Check the stored token can still see the zone. `200` `{"verified":true,...}`, `502` on failure, `404` if not configured | |
| GET | `/api/v1/config/backup` | Download a backup (a file named `esp32p4-config-backup.json`). **Contains the Cloudflare token** | |
| POST | `/api/v1/config/backup` | Restore a backup. `200` `{"restored":true,"reboot_recommended":true}`, `400` if invalid or from different silicon | The backup file |

The `PUT` configuration calls answer with the same JSON as `GET /api/v1/config`.

## Commissioning

| Method | Path | Purpose | Body |
|---|---|---|---|
| GET | `/api/v1/commissioning` | Certificate DNS name, external NTP servers, management time state | |
| PUT | `/api/v1/commissioning` | Set the certificate DNS name and the two external NTP servers | `{"certificate_fqdn":"ts1.example.com","ntp0":"time.cloudflare.com","ntp1":"time.google.com"}` |
| POST | `/api/v1/commissioning/time/sync` | Set the management clock from the fallback servers now. `502` if it fails. Never affects served time | |

## Hardware profile

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/hardware/profile` | Board family and revision, GNSS pins, CPU frequency (`requested_cpu_mhz` is always the firmware's frequency, and `configured_cpu_mhz`), and the detected wafer, eFuse block and package revisions |
| PUT | `/api/v1/hardware/profile` | Change the profile. Needs all of `board_family`, `board_revision`, `pps_gpio`, `gnss_uart`, `gnss_rx_gpio`, `gnss_tx_gpio`. `requested_cpu_mhz` is not needed and is ignored if sent. Applies after a reboot. `400` for invalid or conflicting pins |

## Certificates (Let's Encrypt)

Normal use needs only the first four rows. The board renews automatically from
30 days before expiry.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/acme/production/certificate/issue` | Get the first certificate. Body `{"hostname":"ts1.example.com"}`; the name must be inside the Cloudflare zone. Takes a few minutes. On success the board switches HTTPS and NTS to it by itself. `409` if a valid certificate already exists, Cloudflare is not configured, or another certificate operation is running; `502` if Let's Encrypt or DNS validation fails |
| POST | `/api/v1/acme/production/certificate/renew` | Renew now. `409` with `{"renewed":false,"reason":"not_due",...}` when more than 30 days remain |
| GET | `/api/v1/acme/production/certificate` | The stored certificate: name, `valid_from`, `valid_to`, `certificate_parse_valid`, `hostname_matches_certificate`, storage slots. `404` with `"stored":false` before issuance |
| GET | `/api/v1/acme/production/renewal/scheduler` | Renewal scheduler state, days remaining, last attempt |
| PUT | `/api/v1/acme/production/renewal/scheduler` | Turn automatic renewal on or off. Body `{"enabled":true}` |
| GET | `/api/v1/acme/production/certificate/lifecycle` | Expiry, days remaining and renewal policy |
| GET | `/api/v1/acme/production/certificate/export` | Download the public certificate chain (`production-chain.pem`). The private key is never exportable |
| POST | `/api/v1/acme/production/certificate/activate` | Switch management HTTPS to the stored certificate and keep it across reboots. Normally automatic |
| POST | `/api/v1/acme/certificate/rollback` | Switch management HTTPS back to the board's bootstrap certificate |

Testing and diagnostic endpoints, against the Let's Encrypt **staging**
service. They are not needed to run a server:

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/acme/account` | Staging account state |
| POST | `/api/v1/acme/account` | Register a staging account |
| POST | `/api/v1/acme/staging/probe` | Check the staging directory is reachable |
| POST | `/api/v1/acme/staging/order/discover` | Create a staging order. Body `{"hostname":"..."}` |
| POST | `/api/v1/acme/staging/dns01/validate` | Run DNS-01 validation for a staging order. Body `{"hostname":"..."}` |
| POST | `/api/v1/acme/staging/certificate/issue` | Issue a staging certificate. Body `{"hostname":"..."}` |
| GET | `/api/v1/acme/certificate` | Inspect the stored staging certificate |
| POST | `/api/v1/acme/certificate/activate-test` | Use the staging certificate for management HTTPS until the next reboot |

Manual DNS-01 record helpers, using the stored Cloudflare token:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/cloudflare/dns01` | Create an `_acme-challenge` TXT record in the zone. Body `{"value":"..."}`. Returns `record_id` |
| POST | `/api/v1/cloudflare/dns01/query` | Check a record. Body `{"record_id":"...","value":"..."}` |
| DELETE | `/api/v1/cloudflare/dns01` | Delete a record. Body `{"record_id":"...","value":"..."}` |

## SD card storage

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/storage/status` | Card state, capacity, free space and counters |
| POST | `/api/v1/storage/flush` | Write pending events to the card |
| POST | `/api/v1/storage/mount` | Mount and enable SD storage |
| POST | `/api/v1/storage/unmount` | Unmount until the next reboot |
| POST | `/api/v1/storage/disable` | Unmount and stay disabled across reboots |
| POST | `/api/v1/storage/erase-logs` | Delete all log files. Needs `X-Confirm-Erase: ERASE`. `409` during an OTA upload |
| POST | `/api/v1/storage/format` | Format the card. Needs `X-Confirm-Format: FORMAT`. `409` during an OTA upload |
| GET | `/api/v1/storage/logs` | List the boot log files |
| GET | `/api/v1/storage/log?boot=<n>` | Download one boot's log (`boot-<n>.jsonl`) |
| GET | `/api/v1/storage/logs.zip?boots=<n>,<n>` | Download several boot logs as a ZIP. Use `?all=1` for all of them |
| GET | `/api/v1/storage/diagnostics` | A JSON diagnostic bundle (`esp32p4-diagnostics.json`). Contains no secrets |

The log calls answer `503` when the card is not mounted.

## Firmware

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/ota/status` | Running and previous version, slots, counters, `pending_verify`, `rollback_available` and the rollback version |
| POST | `/api/v1/ota/image` | Upload a firmware image. Body: the `.bin` file, `Content-Type: application/octet-stream`. `202` `{"staged":true,"reboot_required":true}`; `400` if it fails validation |
| POST | `/api/v1/ota/confirm` | Confirm the running image now instead of waiting for the 5-minute soak |
| POST | `/api/v1/ota/rollback` | Verify and boot the previous image. Needs `X-Confirm-Rollback: ROLLBACK` |

To activate an uploaded image, call `POST /api/v1/system/reboot`.

Rollback responses:

| Status | Meaning |
|---|---|
| `202` | `{"scheduled":true,"action":"rollback","version":"..."}`. The board reboots about a second later |
| `412` | Missing or wrong `X-Confirm-Rollback` header |
| `409` | Busy (OTA upload, certificate operation or TLS hand-over), no previous image, or a staged image is waiting |
| `500` | The previous image failed verification |

## Examples

```sh
B=https://ts1.example.com
C="--cert admin-client.crt.pem --key admin-client.key.pem --pass $KEYPASS"

# Is it serving?
curl -sS $C $B/api/v1/health

# Set the redundant server
curl -sS $C -X PUT -H 'Content-Type: application/json' \
     -d '{"enabled":true,"server":"ts2.example.com","warning_ns":100000,"critical_ns":1000000}' \
     $B/api/v1/config/redundant-server

# Back up the configuration (contains the Cloudflare token)
curl -sS $C -o ts1-backup.json $B/api/v1/config/backup

# Erase the SD logs
curl -sS $C -X POST -H 'X-Confirm-Erase: ERASE' $B/api/v1/storage/erase-logs
```

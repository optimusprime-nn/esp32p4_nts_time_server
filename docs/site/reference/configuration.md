# Configuration settings

## Settings you can change on a running board

These are stored on the board and set on the **Management** page or through
the [API](api.md). All except the renewal switch are included in
[backups](../using/backup-restore.md).

### Identity and commissioning

| Setting | Rules | Default | Takes effect |
|---|---|---|---|
| Hostname | 1–63 letters, digits and hyphens | `esp32p4-ntp` | Immediately |
| Certificate DNS name (FQDN) | Up to 253 characters, inside the Cloudflare zone | None | At the next certificate request |
| External NTP 1 and 2 | Server names or addresses. Used only to set the management clock before GNSS locks | Set during setup, for example `time.cloudflare.com` and `time.google.com` | Immediately |

### Cloudflare

| Setting | Rules |
|---|---|
| Zone name | Your domain, for example `example.com` |
| Zone ID | Exactly 32 hexadecimal characters. Optional when the token has Zone:Read |
| API token | Stored encrypted. Never returned by the API; `GET /api/v1/config` shows only `api_token_present` |

### Network

| Setting | Rules | Default |
|---|---|---|
| Static IPv4 | On or off | Off (DHCP) |
| Address | A usable host address in the subnet | |
| Netmask | Contiguous, from /8 to /30 | |
| Gateway | Inside the subnet | |
| DNS server | Optional | |

Changes apply at the next reboot. A stored value that turns out to be invalid,
or a failure applying it, makes the board fall back to DHCP.

### Peer monitoring

| Setting | Range | Default |
|---|---|---|
| Enabled | On or off | |
| Poll interval | 4–3600 s | 16 s |
| Response timeout | 250–10000 ms | 2000 ms |
| Peers 1 to 3 | Server name or IPv4 address, each enabled separately | None |
| Redundant time server | Server name or IPv4 address | None |
| Warning threshold | 1 ns to 1 s | 100 µs |
| Critical threshold | At least the warning threshold, up to 1 s | 1 ms |

### Hardware profile

| Setting | Default |
|---|---|
| PPS GPIO | 5 |
| GNSS UART | 1 |
| GNSS RX GPIO (from the receiver's TXD) | 2 |
| GNSS TX GPIO (to the receiver's RXD) | 3 |
| Board family, board revision | Text labels |
| CPU capability profile | 360 MHz. The 400 MHz option records capability only and does not change the clock speed |

Changes apply after a reboot. The board refuses conflicting pin choices.

### Certificate renewal

| Setting | Default |
|---|---|
| Automatic renewal | On. Renewal starts 30 days before expiry, checked every 12 hours and 30 s after boot |

## Build-time settings

These are fixed in the firmware. They come from `main/Kconfig.projbuild` and
`sdkconfig.defaults`, and change only by rebuilding. See
[Building from source](../building.md).

| Setting | Value |
|---|---|
| NTP port | UDP 123 |
| NTS-KE port | TCP 4460 |
| Management port | TCP 443 |
| Per-client rate limit | 60 requests a minute, burst of 8 |
| Tracked NTP clients for rate limiting | 64 |
| Consecutive valid PPS samples for lock | 32 |
| Maximum holdover | 3600 s |
| GNSS UART baud rate | 115200 |
| Ethernet PHY address | 1 |
| SD storage | Enabled |
| SD archive files kept | 128 |
| SD free-space reserve | 64 MiB |
| Flash encryption | On, development mode |
| NVS encryption | On |
| OTA rollback | On |

!!! warning
    Build production firmware only from an unmodified `sdkconfig.defaults`. A
    hand-edited `sdkconfig` can silently turn off flash encryption.

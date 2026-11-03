# ESP32-P4 GNSS Stratum-1 NTP/NTS Time Server

A stratum-1 network time server built on the ESP32-P4. A u-blox M8 GNSS receiver
(tested with the LEA-M8T) disciplines the clock from GNSS and its PPS output, and the Ethernet
MAC's hardware timestamps keep the served time accurate at the wire. It serves
plain NTP and authenticated NTS, obtains its own Let's Encrypt certificate, and
is managed over mutual-TLS HTTPS.

**Current release: 3.1.11.** This is the final planned release of this line;
further changes are bug fixes only.

**Documentation: <https://optimusprime-nn.github.io/esp32p4_nts_time_server/>**

**To set up a board,** download the release zip from the
[Releases page](https://github.com/optimusprime-nn/esp32p4_nts_time_server/releases)
and run the setup tool in it: `setup.cmd` on Windows, `./setup.sh` on Linux. It
flashes a new board, claims it, sets its name, address and DNS, and gets its
Let's Encrypt certificate, in a window or as guided questions in a terminal
(`--cli`). See [Quick setup](https://optimusprime-nn.github.io/esp32p4_nts_time_server/setup-tool/).

## Measured performance

From a 91-hour soak of two boards on 3.1.8, with no reboots. 3.1.9 and 3.1.10
add a certificate-check fix and a reboot guard, and do not touch timing code:

| Measure | Result |
|---|---|
| PPS samples | ~327,700 per board, 0 rejected, 0 s in holdover |
| Clock phase error | Typically under 50 ns |
| Offset against an independent GPS/PPS reference | 6-hour medians between −50 and +17 µs |
| Board-to-board agreement (hardware timestamped) | Within about ±10 µs |
| NTP requests answered | 56,807 of 56,808 |
| NTS failures | 0 (light traffic: 7 authenticated requests) |

On 3.1.4, both boards also ran cleanly through a GPS leap-second table event, the same
zero-change event that previously caused a 5-hour outage.

## Features

**Timing**
- PPS captured in hardware (ETM into GPTimer, 50 ns resolution), never by a
  software interrupt timestamp.
- Integer-nanosecond clock discipline in GPS-continuous seconds, so a leap
  second steps cleanly. Every sample must advance the GNSS second by exactly the
  elapsed PPS time; a bad sample cannot move the clock.
- Only receiver-validated leap data makes the clock eligible to serve.
- Stratum 1 while synchronized, stratum 2 in holdover, stratum 16 otherwise. The
  server does not claim time it cannot support.

**NTP and NTS**
- NTPv1 to v4 on UDP/123, with per-client rate limiting and Kiss-o'-Death.
- Hardware receive timestamps and late transmit stamping with a continuously
  learned transmit latency.
- NTS (RFC 8915): TLS 1.3 key exchange on TCP/4460 with a worker pool,
  per-client limits and memory admission control. The key-exchange service
  recovers by itself from startup failures.
- NTS transmit timestamps use a learned bias, because they cannot be stamped
  after authentication.

**Reliability**
- Network watchdog on every board: reboots after 120 s of receive silence,
  stalled transmit, or frames not reaching the IP stack, and after 10 minutes of
  link up without an address. Limited to 2 reboots so an unfixable fault cannot
  loop.
- OTA with A/B slots and a 5-minute soak: a new image that crashes rolls back
  automatically. Manual rollback is on the Firmware page and in the API.
- Timing and network services run independently of the web console and SD card.

**Management**
- HTTPS on TCP/443 with mandatory client certificates. Enrollment is a one-time
  claim authorised by a code shown only on the serial console.
- Automatic Let's Encrypt issuance and renewal using Cloudflare DNS-01.
- Dashboard, diagnostics, Prometheus-format `/metrics`, event history, SD log
  archive, configuration backup and restore, static IPv4.
- Passive peer monitoring and a redundant-server view. Peers are measurement
  only and have no timing authority.

## Hardware

| Item | Value |
|---|---|
| SoC | ESP32-P4, silicon revision v1.x (360 MHz) or v3.x (400 MHz); one firmware variant for each |
| Memory | 16 MB flash, 32 MB PSRAM |
| GNSS | A u-blox M8 receiver with a timepulse (PPS) output, tested with the LEA-M8T. An outdoor or clear-sky antenna |
| Ethernet | IP101 PHY over RMII |
| SD | 4-bit SDMMC on GPIO39–44 (optional, for the log archive) |

| Signal | GPIO |
|---|---|
| GNSS PPS / TIMEPULSE | 5 |
| GNSS UART RX (from receiver TXD) | 2 |
| GNSS UART TX (to receiver RXD) | 3 |
| Ethernet MDC / MDIO / PHY reset | 31 / 52 / 51 |

The GNSS pins can be changed in the management console's hardware profile. The
ESP32-C6 found on some carrier boards is not used; all traffic is over Ethernet.

## Network ports

| Port | Purpose |
|---|---|
| UDP 123 | NTP and NTS-protected NTP |
| TCP 4460 | NTS key exchange |
| TCP 443 | Management, client certificate required |

The board also needs outbound DNS, HTTPS (Let's Encrypt and Cloudflare) and NTP.

## Using the server

Plain NTP clients only need the address. NTS clients must use the hostname,
because the certificate does not cover IP addresses. For chrony:

```text
server ts1.example.com iburst nts
server ts2.example.com iburst nts
```

## Building

Requires ESP-IDF v6.1 (commit `fff9895c`). No certificate files are needed:
each board creates its own bootstrap certificate at first boot.

ESP-IDF cannot build one image for ESP32-P4 silicon below v3.0 and v3.0 or
later, so there are two builds:

```powershell
idf.py build
idf.py -B build-v3 -D SDKCONFIG=build-v3/sdkconfig -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.v3" build
python tools/release/make_release.py dist build build-v3
```

The first builds `silicon-v1` (revisions v1.0–v1.99, 360 MHz) in `build`, the
second `silicon-v3` (revisions v3.0–v3.99, 400 MHz) in `build-v3`. The third
packages the release zip, one OTA image per variant and checksums.

`sdkconfig` is generated from `sdkconfig.defaults`, which is the complete
production configuration; the v3 build adds the overlay
`sdkconfig.defaults.v3`. Do not build production firmware from a modified local
`sdkconfig`. The app image for OTA is `esp32p4_nts_time_server.bin` in the
build folder for the board's silicon.

Flashing has different rules before and after a board is encrypted; see
[Building from source](https://optimusprime-nn.github.io/esp32p4_nts_time_server/building/).

## Repository layout

| Path | Contents |
|---|---|
| `main/` | Firmware |
| `components/esp_eth/` | Project copy of the ESP-IDF Ethernet driver with hardware-timestamp and receive-hang changes. It overrides the ESP-IDF version, so recheck it on any ESP-IDF upgrade |
| `tools/setup/` | Setup tool: window and guided command line, Windows and Linux |
| `tools/release/` | Release packaging |
| `tools/` | Older PowerShell provisioning and OTA scripts |
| `test/` | NTS AES-SIV test application |
| `docs/site/`, `mkdocs.yml` | Documentation site source |
| `docs/ENGINEERING_HISTORY.md` | Original phase-by-phase design log (historical) |

## Security notes

- **Flash encryption is in development mode and Secure Boot is off.** Someone
  with physical access to the serial port can still load firmware. Keep boards
  physically secure. Moving to release mode or enabling Secure Boot burns
  permanent eFuses and needs its own plan.
- **Each board creates its own bootstrap key.** Published firmware holds no
  private key. The setup tool checks the board's identity against the
  fingerprint it prints on the serial console before sending anything.
- **Secrets never belong in this repository.** That covers `management-credentials*/`,
  `sdkconfig`, configuration backups (which contain the Cloudflare
  token) and archives of the working tree.

## Known limitations

None of these affect served time:

- The NTP timestamp era rollover in 2036 is not handled.
- Settings spanning several stored keys are not written atomically, so a power
  loss during a save can leave a partial update.
- Unmounting the SD card during a log download can free memory still in use; the
  ZIP log export fails if the live log grows during the download.
- Monthly NTS key rotation writes flash from the NTP task, delaying one reply by
  a few milliseconds. Timestamps stay accurate.
- A small number of peer samples fall back to software timestamps, which can
  produce an occasional `DEGRADED` peer event.
- A real leap second has been reviewed in code but has not occurred during
  testing. Exact-second application and holdover across a leap are not fully
  covered.

## Licence

GNU General Public License v3.0. See [LICENSE](LICENSE).

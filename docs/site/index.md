# ESP32-P4 GNSS Time Server

A stratum-1 network time server built on the ESP32-P4. A u-blox LEA-M8T timing
receiver disciplines the clock from GNSS and its PPS output, and the Ethernet
MAC's hardware timestamps keep the served time accurate at the wire.

The server:

- answers plain NTP (versions 1 to 4) on UDP port 123;
- answers authenticated NTS (RFC 8915), with key exchange on TCP port 4460;
- gets and renews its own Let's Encrypt certificate using Cloudflare DNS;
- is managed over HTTPS on port 443, and only with a client certificate that you
  create during setup.

This guide covers release **3.1.11**.

## Measured performance

From a 91-hour soak of two boards on 3.1.8, with no reboots. Later releases up to
3.1.11 do not change timing code.

| Measure | Result |
|---|---|
| PPS samples | About 327,700 per board, 0 rejected, 0 s in holdover |
| Clock phase error | Typically under 50 ns |
| Offset against an independent GPS/PPS reference | 6-hour medians between −50 and +17 µs |
| Board-to-board agreement (hardware timestamped) | Within about ±10 µs |
| NTP requests answered | 56,807 of 56,808 |
| NTS failures | 0 (light traffic: 7 authenticated requests) |

On 3.1.4, both boards also ran cleanly through a GPS leap-second table event.

## How it behaves

- **Stratum 1** while the clock is synchronized to GNSS, **stratum 2** in
  holdover, **stratum 16** otherwise. The server does not claim time it cannot
  support.
- PPS is captured in hardware with 50 ns resolution, never by a software
  interrupt timestamp.
- Only receiver-validated leap-second data makes the clock eligible to serve.
- A network watchdog reboots the board after a network fault it cannot recover
  from, at most twice in a row.
- Firmware updates go over the network into a spare slot. A new image that fails
  in its first 5 minutes is rolled back automatically.

## Where to start

| You want to | Read |
|---|---|
| Set up a new board with the release download | [What you need](getting-started/what-you-need.md), then [Quick setup with the tool](setup-tool/index.md) |
| Build and flash from source with ESP-IDF | [Building from source](building.md), then [Manual setup](getting-started/manual-setup.md) |
| Point computers at the server | [Pointing clients at it](using/clients.md) |
| Update firmware | [Firmware updates and rollback](using/firmware-updates.md) |
| Script against the board | [Management API](reference/api.md) |
| Fix a problem | [Troubleshooting](help/troubleshooting.md) |

!!! warning "Read before setting up a board"
    Writing the firmware to a new board turns on flash encryption at its first
    boot. That burns a key into the chip's eFuses and **cannot be undone**. See
    [Security model](help/security.md).

The source code, issue tracker and releases are on
[GitHub](https://github.com/optimusprime-nn/esp32p4_nts_time_server). The project
is licensed under the GNU General Public License v3.0.

# Release notes

The 3.1 line receives bug fixes only.

## 3.1.12

- **Recovery when the GNSS receiver resets on its own.** The board's receiver
  setup is not saved in the receiver, so after a receiver-only reset (its
  watchdog, a supply glitch, a reset from u-center) the UBX messages stopped,
  and the clock failed closed after 5 minutes of holdover until the board was
  rebooted. The board now notices NAV-PVT stopping while the receiver is still
  sending, and re-sends the setup within about 10 s (at most once a minute),
  well inside holdover.
- **A silent receiver UART is reported.** No bytes for more than 10 s means a
  power or wiring problem; it is shown on Diagnostics and logged, not retried.
- New fields in the `gnss` section of `GET /api/v1/status`:
  `ubx_reconfigurations`, `last_reconfiguration_uptime_s` and `uart_silent`.
  New metrics: `esp32_ntp_gnss_receiver_reconfigurations_total` and
  `esp32_ntp_gnss_uart_silent`. Nothing is removed or renamed.
- Diagnostics, **GNSS Receiver**: new *Receiver Reconfigurations* and *UART
  Silent* rows.

## 3.1.11

- Each board now creates its own bootstrap TLS key and self-signed certificate
  at first boot (P-256), stored in the encrypted `nvs_certs` partition.
  Published firmware therefore carries no private key; earlier images all
  embedded the same one.
- The certificate's SHA-256 is printed on the serial console
  (`Bootstrap certificate SHA-256: ...`) beside the enrollment code, so the
  setup tool can check it.
- Building no longer needs certificate files. `tools/generate-bootstrap-cert.ps1`
  is removed.
- New guided setup tool for Windows and Linux, as a window or in a terminal: it
  flashes a new board (and refuses an already-encrypted one), reads the code,
  fingerprint and address from the serial console, creates the management CA
  and administrator certificate, claims the board over a fingerprint-checked
  connection, sets identity, DHCP or a static address, Cloudflare (optionally
  creating the DNS record) and the Let's Encrypt certificate, with optional GNSS
  pins and Windows certificate import.
- Two firmware variants, one per ESP32-P4 silicon generation: `silicon-v1`
  (revisions v1.x, 360 MHz) and `silicon-v3` (revisions v3.x, 400 MHz). ESP-IDF
  cannot build one image for both. The release zip holds both and the setup
  tool writes the one matching the chip. There is one OTA image per variant; a
  wrong one is refused at upload. The v3.x variant is new and has not yet
  completed a hardware soak.
- The hardware profile's CPU frequency is now information only, set by the
  firmware for the silicon. `PUT /api/v1/hardware/profile` no longer needs
  `requested_cpu_mhz` and ignores it.

## 3.1.10

- `POST /api/v1/system/reboot` and `POST /api/v1/ota/rollback` answer `409` with
  the reason while an OTA upload, a production certificate operation or a TLS
  hand-over is in progress, instead of cutting it off. Activating a staged image
  is unaffected.
- No timing or NTP/NTS changes.

## 3.1.9

- The certificate renewal scheduler meant to wake every 6 hours, but an
  overflow made it run about every 2 minutes. It now checks every 12 hours,
  plus once 30 s after boot. The scheduler status reports the real interval
  (`check_interval_seconds` 43200).

## 3.1.8

- NTS key exchange recovers by itself from startup failures (key ring,
  certificate load, port bind) instead of staying down until a reboot.
- Manual certificate issue or renewal and the automatic scheduler can no longer
  run at the same time; the console gets `409` and the scheduler records a
  skipped attempt.
- `/api/v1/status` reports internal and PSRAM heap figures, including minimums
  since boot.
- `sdkconfig.defaults` now holds the complete production configuration, so a
  fresh clone builds an encrypted image.
- 91-hour two-board soak; see [Home](../index.md#measured-performance).

## 3.1.7

- The peer monitor accepts small negative delays (down to −100 µs) as zero
  instead of rejecting the sample as `INVALID`. This removes spurious events
  while a peer is booting.

## 3.1.6

- Peer-monitor requests and replies use hardware timestamps, removing a bias
  of about 90 µs that caused spurious `WARNING` events between two boards.
- Per-peer `hw_timestamped_samples` in the status JSON.

## 3.1.5

- A damaged event-history record no longer makes the SD card unmount and
  remount repeatedly, and no longer breaks `/api/v1/operations/history` and the
  diagnostics export.

## 3.1.4

- Leap-second handling: only receiver-validated leap data makes the clock
  eligible to serve, and the clock keeps GPS-continuous seconds across a leap.
  Every PPS sample must advance the GNSS second by exactly the elapsed time.
- Network watchdog on every board: reboots after 120 s of receive silence and
  similar faults, limited to 2 reboots in a row.
- OTA images are confirmed only after 300 s with the web console up, and rolled
  back otherwise. Manual rollback with `POST /api/v1/ota/rollback`
  (`X-Confirm-Rollback: ROLLBACK`) and a Firmware page button.
- Bounded request-body reads in all handlers, and other robustness fixes.
- SD card: persistent mount across manual unmount and remount, a disable
  command, boot-log diagnostics and verified archive flushes.
- Peer monitor honours Kiss-o'-Death: `RATE` backs off for 1024 s, `DENY` or
  `RSTR` stops polling until reconfigured.
- Verified on two boards, including a rollback.

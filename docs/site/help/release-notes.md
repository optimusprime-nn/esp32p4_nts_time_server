# Release notes

The 3.1 line receives bug fixes only.

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

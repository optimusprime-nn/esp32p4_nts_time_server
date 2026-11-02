# Building from source

Most people do not need this: the [release download](getting-started/download.md)
includes the firmware. Build from source to change the firmware, or to flash a
board over USB with `idf.py`.

## Requirements

| Item | Version |
|---|---|
| ESP-IDF | v6.1, commit `fff9895c` (`fff9895c82d744c7237be8847347bdd1b07c6643`) |
| Target | `esp32p4` |
| Host | Windows (ESP-IDF PowerShell) or Linux |

Install ESP-IDF with the
[Espressif Installation Manager](https://docs.espressif.com/projects/idf-im-ui/en/latest/),
then check out the exact commit in the ESP-IDF folder if your install differs.

From 3.1.11, no certificate files or OpenSSL are needed to build.

## Build

ESP-IDF cannot build one image for ESP32-P4 silicon below v3.0 and v3.0 or
later, so there are two builds. Build the one for your chip, or both for a
release.

| Variant | Chip revisions | CPU | Configuration |
|---|---|---|---|
| `silicon-v1` | v1.0–v1.99 | 360 MHz | `sdkconfig.defaults` |
| `silicon-v3` | v3.0–v3.99 | 400 MHz | `sdkconfig.defaults` plus `sdkconfig.defaults.v3` |

```sh
git clone https://github.com/optimusprime-nn/esp32p4_nts_time_server.git
cd esp32p4_nts_time_server
idf.py build    # silicon-v1, in build/
idf.py -B build-v3 -D SDKCONFIG=build-v3/sdkconfig -D "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.v3" build    # silicon-v3, in build-v3/
```

Package a release from both builds:

```sh
python tools/release/make_release.py dist build build-v3
```

`sdkconfig` is generated from `sdkconfig.defaults` (plus the v3 overlay for the
v3 build), which is the complete production configuration, including flash
encryption. Do not build production
firmware from a modified local `sdkconfig`. If in doubt, delete `sdkconfig` and
build again.

Check that flash encryption is on before flashing a new board:

```sh
grep '^CONFIG_SECURE_FLASH_ENC_ENABLED' sdkconfig            # must print =y
grep '^CONFIG_SECURE_FLASH_ENC_ENABLED' build-v3/sdkconfig   # v3 build
```

The app image for network updates is `esp32p4_nts_time_server.bin` in `build/`
or `build-v3/`.

!!! note "Ethernet driver"
    `components/esp_eth/` is a project copy of the ESP-IDF Ethernet driver with
    hardware-timestamp and receive-hang changes. It overrides the ESP-IDF
    version, so recheck it on any ESP-IDF upgrade.

## Flashing a new board

!!! warning "Permanent"
    The first boot after this flash burns a flash-encryption key into the chip's
    eFuses. It cannot be undone. Do not disconnect power until the application
    starts.

```sh
idf.py -p COM7 flash monitor
```

For a v3.x chip, add the `-B build-v3 -D SDKCONFIG=... -D SDKCONFIG_DEFAULTS=...`
options from the build command. A mismatched image fails before anything is
written ("requires chip revision in range"), so nothing is burned.

Use plain `flash` **only** on a board that has never been encrypted. Then claim
and commission it as in [Manual setup](getting-started/manual-setup.md), or run
the setup tool from `tools/setup` and say the board is not new.

## Flashing an encrypted board

Only needed if a network update is not possible:

```sh
idf.py -p COM7 encrypted-flash --all
```

After flashing, the chip may stay in the bootloader. Press reset to start it.
This keeps the board's settings and ownership.

!!! danger
    **Never** use plain `idf.py flash` on an encrypted board: it writes
    unreadable data. Never erase the `nvs_keys` partition: the board's stored
    secrets depend on it.

## Serial monitor

```sh
idf.py -p COM7 monitor
```

Exit with `Ctrl+]`. Reading the log changes nothing on the board.

## Repository layout

| Path | Contents |
|---|---|
| `main/` | Firmware |
| `components/esp_eth/` | Patched ESP-IDF Ethernet driver |
| `tools/setup/` | The setup tool |
| `tools/provision-management.ps1` | PowerShell claim script (manual setup) |
| `tools/ota-update.ps1` | PowerShell firmware upload script |
| `test/` | NTS AES-SIV test application |
| `docs/site/` | This documentation |

## Building this documentation

```sh
pip install -r docs/requirements-docs.txt
mkdocs serve            # preview at http://127.0.0.1:8000/
mkdocs build --strict
```

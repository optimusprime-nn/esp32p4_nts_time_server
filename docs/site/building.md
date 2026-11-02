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

```sh
git clone https://github.com/optimusprime-nn/esp32p4_nts_time_server.git
cd esp32p4_nts_time_server
idf.py build
```

`sdkconfig` is generated from `sdkconfig.defaults`, which is the complete
production configuration, including flash encryption. Do not build production
firmware from a modified local `sdkconfig`. If in doubt, delete `sdkconfig` and
build again.

Check that flash encryption is on before flashing a new board:

```sh
grep '^CONFIG_SECURE_FLASH_ENC_ENABLED' sdkconfig     # must print =y
```

The app image for network updates is `build/esp32p4_nts_time_server.bin`.

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

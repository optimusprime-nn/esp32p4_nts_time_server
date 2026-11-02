# Hardware and pins

## Parts

| Item | Value |
|---|---|
| SoC | ESP32-P4, silicon revision below v3 |
| Memory | 16 MB flash, 32 MB PSRAM |
| GNSS | u-blox LEA-M8T with an outdoor or clear-sky antenna |
| Ethernet | IP101 PHY over RMII, PHY address 1 |
| SD | 4-bit SDMMC on GPIO39–44 (optional, for the log archive) |

The ESP32-C6 found on some carrier boards is not used. All traffic is over
Ethernet.

## Standard pins

| Signal | GPIO |
|---|---|
| GNSS PPS / TIMEPULSE | 5 |
| GNSS UART RX (from the receiver's TXD) | 2 |
| GNSS UART TX (to the receiver's RXD) | 3 |
| Ethernet MDC | 31 |
| Ethernet MDIO | 52 |
| Ethernet PHY reset | 51 |

The GNSS receiver is on UART 1 at 115200 baud.

## Changing the GNSS pins

The GNSS pins and UART can be changed without rebuilding, for a carrier board
wired differently:

- during setup, on the tool's Finish step; or
- later, under **Management → Hardware Profile & GPIO**, then reboot.

Wrong pins stop GNSS and PPS working, and the clock will not synchronize. The
Ethernet pins are fixed in the firmware build.

## Antenna

The receiver needs a clear view of the sky. A first fix can take several
minutes. After the receiver has lost its stored data, synchronization can take
up to about 12.5 minutes, because the leap-second data has to arrive from the
satellites.

## Flash layout

| Partition | Purpose |
|---|---|
| `nvs` | Settings (encrypted) |
| `nvs_keys` | Keys for the encrypted settings. **Never erase it** |
| `otadata` | Which firmware slot boots |
| `phy_init` | PHY calibration data |
| `factory`, `ota_0`, `ota_1` | Firmware slots |
| `nvs_certs` | Certificates, keys, NTS and ACME data (encrypted) |
| `coredump` | Crash dump (encrypted) |

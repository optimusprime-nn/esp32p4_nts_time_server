# Hardware and pins

## Parts

| Item | Value |
|---|---|
| SoC | ESP32-P4, silicon revision v1.x or v3.x |
| Memory | 16 MB flash, 32 MB PSRAM |
| GNSS | A u-blox M8 receiver with a timepulse (PPS) output, tested with the LEA-M8T. An outdoor or clear-sky antenna |
| Ethernet | IP101 PHY over RMII, PHY address 1 |
| SD | 4-bit SDMMC on GPIO39–44 (optional, for the log archive) |

The ESP32-C6 found on some carrier boards is not used. All traffic is over
Ethernet.

## GNSS receiver

Use a u-blox M8 receiver with a timepulse output. It has been tested with the
LEA-M8T; a timing model (a "-T" part) gives the most accurate pulse.

!!! note "u-blox M10 receivers are not supported yet"
    M10 receivers, such as the u-blox M10050 in the Beitian BE-882, are set up
    with a newer configuration interface and refuse the commands below. On
    this release, Diagnostics shows *UBX Config Complete* `NO` with a NAK count
    above 0, and the clock does not synchronize. Support is planned for a later
    release.

At every boot the firmware sends the receiver `UBX-CFG-MSG` commands, and waits
for each to be acknowledged, to output these once a second on its UART1:

- UBX NAV-PVT, NAV-TIMEGPS, NAV-TIMELS and TIM-TP;
- NMEA ZDA.

These settings are not saved in the receiver, so they are sent again at each
boot. The timepulse is left as the receiver is set: the default 1 pulse per
second, rising edge on the second, is what the firmware expects.

!!! warning "Set the receiver's baud rate first"
    The firmware talks to the receiver at **115200 baud** and does not change the
    receiver's baud rate. u-blox receivers start at 9600 baud, so before first
    use, connect the receiver to a computer and in u-blox u-center:

    1. In **View → Configuration View → PRT (Ports)**, choose **UART1**, set
       **Baudrate** to `115200`, leave **Protocol in** and **Protocol out** as
       **UBX+NMEA**, and click **Send**.
    2. Reconnect u-center at 115200 baud.
    3. In **CFG (Configuration)**, choose **Save current configuration** (with the
       BBR and Flash devices selected) and click **Send**.

    If the rate does not match, **Diagnostics → GNSS Receiver** shows
    *UBX Config Complete* `NO` and *UBX Frames Valid* stays at 0.

## Silicon variants

ESP-IDF treats ESP32-P4 silicon below v3.0 and v3.0 or later as incompatible, so
each release has two firmware variants. Features are identical; both use flash
encryption (development mode) and NVS encryption.

| Variant | Chip revisions | CPU |
|---|---|---|
| `silicon-v1` | v1.0–v1.99 | 360 MHz |
| `silicon-v3` | v3.0–v3.99 | 400 MHz |

The setup tool picks the variant from the chip. For a network update, upload
the image for the board's silicon; see [Firmware updates](../using/firmware-updates.md).
The Management page's **Hardware Profile & GPIO** panel shows
*Detected silicon: wafer vX.YY*.

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

# What you need

Allow about 30 minutes for the first board with the setup tool, longer if you
build from source.

## Hardware

| Item | Notes |
|---|---|
| ESP32-P4 board | Silicon revision v1.x or v3.x, 16 MB flash, 32 MB PSRAM, IP101 Ethernet PHY. See [Hardware and pins](../reference/hardware.md) |
| u-blox M8 GNSS receiver | With a timepulse (PPS) output; tested with the LEA-M8T. M10 receivers are [not supported yet](../reference/hardware.md#gnss-receiver). Set its UART1 to 115200 baud in u-center first (it starts at 9600), as in [GNSS receiver](../reference/hardware.md#gnss-receiver). Wired to the board as in [Hardware and pins](../reference/hardware.md) |
| GNSS antenna | Outdoor, or with a clear view of the sky |
| Ethernet connection | With DHCP and internet access |
| USB cable | To the board's serial port, for the first setup |
| microSD card | Optional, for the log archive. FAT-formatted |

## A computer to run setup

| | Windows | Linux |
|---|---|---|
| Python | 3.10 or newer. `winget install --id Python.Python.3.12 -e` | 3.10 or newer, plus `python3-venv`, and `python3-tk` for the window |
| Serial port access | Works by default | Your user must be in the `dialout` group |
| Internet | Needed on the first run, to install the tool's Python packages, and to reach Cloudflare | Same |

On Debian or Ubuntu:

```sh
sudo apt install python3 python3-venv python3-tk
sudo usermod -aG dialout "$USER"     # then log out and back in
```

## Accounts

1. **A domain managed by Cloudflare.** The board proves it owns its name to
   Let's Encrypt by creating a DNS record in that zone.
2. **A Cloudflare API token** limited to that zone, with exactly these two
   permissions:

    | Permission | Access |
    |---|---|
    | Zone → Zone | Read |
    | Zone → DNS | Edit |

    In the Cloudflare dashboard: **My Profile → API Tokens → Create Token →
    Create Custom Token**. Under **Zone Resources**, choose **Include → Specific
    zone →** your domain.

!!! warning "The token is a secret"
    Anyone with the token can change DNS records in your zone. The board stores
    it encrypted and never shows it again, but configuration backups contain it.
    Keep backups somewhere safe.

The manual setup also needs the zone's **Zone ID**, shown on the zone's
Cloudflare overview page. The setup tool looks it up for you.

## Decide before you start

| Item | Example |
|---|---|
| Board hostname | `ts1` |
| Full DNS name for the certificate | `ts1.example.com` |
| A fixed address: a DHCP reservation, or a static address | `192.0.2.10` |
| A safe place for the credentials folder and its password | A password manager, outside any code repository |

The board's address must not change, because its DNS name points at it.

Next: [Download](download.md).

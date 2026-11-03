# Troubleshooting

## The board

| Symptom | Likely cause and fix |
|---|---|
| No enrollment code on the serial console | Open the monitor and reset the board. If `UNPROVISIONED` does not appear, the board is already claimed |
| Claim returns 403 or 429 | Wrong code, or locked after five wrong codes. Reboot the board and use the new code |
| Console will not connect | Certificate not imported, or the wrong one chosen. Close the browser completely and try again; browsers remember a "no certificate" choice |
| Browser warns the certificate is not trusted | Normal until the Let's Encrypt certificate is issued, and when you connect by IP address. Connect by DNS name after setup |
| Diagnostics shows *UBX Config Complete* `NO` | The receiver is not at 115200 baud. Set it in u-center and save; see [GNSS receiver](../reference/hardware.md#gnss-receiver) |
| Clock stays `ACQUIRING` | Check the antenna, the PPS wire and the GNSS fix on **Diagnostics → GNSS Receiver — Diagnostics**. Allow 12.5 minutes after a cold start |
| Stratum 16 | Clock not synchronized. This is correct behaviour, not a fault |
| Certificate request fails | Check **Save/Test Cloudflare**, the token's permissions (Zone:Read, DNS:Edit), that the board has internet access, and that management time is valid (**Sync Management Time**) |
| `hostname must be the configured Cloudflare zone or a subdomain` | The certificate DNS name is not inside the Cloudflare zone you saved |
| `Production certificate already exists` (409) | The board already has a valid certificate. Renewal is automatic; use **Renew Certificate** only within 30 days of expiry |
| NTS not running | No certificate yet. Check **System → Certificate & ACME**. NTS retries about once a minute |
| NTS client reports a certificate error | Use the DNS name, not the IP address |
| Reboot or rollback refused (409) | An OTA upload, certificate operation or TLS hand-over is running. Wait and try again |
| Unexpected reboot | Check **System → Operations & Reset History**. Look for `Network watchdog` or `Ethernet RX stalled` |
| SD card not mounting | Check the card is FAT-formatted, then **Mount / Enable**. Timing is not affected |
| Console unreachable after setting a static address | The address, netmask or gateway is wrong for your network. Connect a computer to that subnet to reach the board and correct it |

To read the board's log at any time without changing anything, open a serial
monitor at 115200 baud, for example `idf.py -p COM7 monitor`. Close it before
running the setup tool.

## Setup tool messages

| Message | What to do |
|---|---|
| *Python 3.10 or newer is needed* | Install Python (`winget install --id Python.Python.3.12 -e`, or `sudo apt install python3 python3-venv python3-tk`) and open a new window |
| *Preparing the setup tool failed* | The first run could not download its packages. Check the internet connection and start again |
| *Could not create a virtual environment* | Linux: `sudo apt install python3-venv` |
| *you are not in the 'dialout' group* | `sudo usermod -aG dialout "$USER"`, then log out and back in |
| *The window needs Tkinter* | Linux: `sudo apt install python3-tk`, or carry on in the terminal |
| *No serial ports found* | Connect the USB cable, then press **Refresh** or run the tool again. Try another cable; some are charge-only |
| *Cannot open COM7 ... Close any serial monitor using it* | Another program has the port open. Close `idf.py monitor`, PuTTY or similar |
| *Firmware not found* | Keep the release's `firmware` folder next to `setup`, or start with `--firmware <folder>` |
| *esptool failed* | Check the cable and port. Hold **BOOT** while pressing **RESET** if the board will not connect, and close any serial monitor |
| *This board is already encrypted, so it must not be flashed this way* | The board already has firmware. Run setup again and say it is not a new board. Update its firmware over the network |
| *Could not read the board's flash-encryption state* | The tool could not talk to the chip, so it wrote nothing. Check the cable and port |
| *The board did not report an IP address* | Check the Ethernet cable and that the network has DHCP |
| *The board did not report ... the enrollment code* | Reset the board and try again. If it is already claimed, the tool should detect that; check the console with a serial monitor |
| *... the bootstrap certificate fingerprint (firmware older than 3.1.11?)* | The board runs older firmware. Update it to 3.1.11 or later |
| *... already holds credentials. Choose a new folder* | Credentials are never overwritten. Pick a new folder for a new board |
| *has no admin-client.key.pem* | The folder is not a credentials folder. Choose the one made when this board was claimed |
| *That password does not open these credentials* | Wrong password for that folder |
| *The board's certificate does not match the fingerprint* | Something on the network answered instead of the board, or the address belongs to another device. Nothing was sent. Check the address and your network |
| *This board is already claimed* | Run setup again; it will open the existing credentials instead |
| *The board rejected the enrollment code* | Reset the board and use the new code (run setup again) |
| *Too many wrong codes* | Enrollment is locked. Reset the board and run setup again |
| *The board at ... did not come back within 180 s* | The board did not answer after a restart. Check its power and network. After a static-address change, check that this computer can reach the new address |
| *Cannot verify this board* | The board is on its Let's Encrypt certificate but no DNS name is recorded. Open the credentials folder from the original setup |
| *The hostname must be letters, digits and hyphens* | Use a short name such as `ts1` |
| *The certificate name must be a full DNS name* | Use a name like `ts1.example.com` |
| *The address must look like 192.168.1.10* | Enter a dotted IPv4 address |
| *... is not inside the zone ...* | The DNS name must end with your Cloudflare zone, for example `ts1.example.com` in zone `example.com` |
| *The token cannot see a zone called ...* | Check the zone spelling and that the token has Zone:Read on it |
| *Cloudflare refused the request* | Check the token's permissions: Zone:Read and DNS:Edit on this zone |
| *Could not reach Cloudflare* | This computer has no internet access, or a proxy is blocking it |
| *... was refused (409): Another ACME production operation is in progress* | Wait a few minutes and try the Let's Encrypt step again |
| *The certificate was not confirmed within 600 s* | Check **System → Certificate & ACME** on the board. DNS validation can take longer |
| *Importing the certificate failed* | Import `admin-client.p12` by hand: double-click it, or use `Import-PfxCertificate` as in [Manual setup](../getting-started/manual-setup.md#6-install-your-administrator-certificate) |
| *Unexpected error* | A problem the tool did not expect. Run it again with `--cli`, which shows the full error, and report it with that output |

After any *Stopped:* message, fix the cause and run setup again. It picks up
from an already-claimed board; see
[Running it again](../setup-tool/index.md#running-it-again).

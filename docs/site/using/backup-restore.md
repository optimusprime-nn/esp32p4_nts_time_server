# Backup and restore

A backup is a JSON file of the board's management settings. Take one after
setup and after any change.

!!! warning "The backup contains your Cloudflare API token"
    Store it with the credentials folder, as a secret. Do not put it in a code
    repository, a shared drive or a ticket.

## What is in a backup

| Included | Not included |
|---|---|
| Hostname | The management CA and ownership (claiming) |
| Cloudflare zone name, Zone ID and **API token** | The Let's Encrypt certificate and its key |
| Peer monitoring settings and peers | The Let's Encrypt account key |
| Redundant time server and thresholds | NTS keys |
| Static IPv4 settings | Firmware |
| Hardware profile (GNSS pins, board family) | Logs and event history |
| Certificate DNS name and external NTP servers | |
| The silicon revision of the board it came from | |

## Download a backup

1. Open **Management**.
2. Under **Configuration Backup & Restore**, click **Download Backup**.

From a script: `GET /api/v1/config/backup`; see
[Management API](../reference/api.md#configuration).

## Restore a backup

1. Open **Management**.
2. Under **Configuration Backup & Restore**, choose the backup file. The page
   checks it.
3. Click **Restore Configuration** and confirm.
4. When it reports success, reboot from **System → Reboot Device**. The board
   recommends a reboot before you rely on the restored settings.

The board validates the whole file before it changes anything. It refuses a
backup that is damaged, has invalid values, or came from a board with
different silicon (wafer, eFuse block or package revision). Backups from older
firmware without those fields are still accepted. A backup without static IPv4
fields restores as DHCP.

!!! note
    Settings are written as several stored values, not in one atomic step. A
    power cut during a restore can leave a partial update. Restore again if
    that happens.

## Moving to a replacement board

A backup restores settings, not ownership. A replacement board must be set up
and claimed first, with its own credentials folder, then:

1. Restore the backup, if the silicon revision matches.
2. Request its certificate under **Management → Commissioning & Certificate
   Setup**.
3. Update the DNS record if the address changed.

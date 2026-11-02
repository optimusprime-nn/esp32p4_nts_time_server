# Pointing clients at it

Plain NTP clients only need the server's name or address. NTS clients must use
the **name** (for example `ts1.example.com`), because the certificate does not
cover IP addresses.

Use two servers if you have them; see [Two servers](redundancy.md).

| Client | NTS | Notes |
|---|---|---|
| chrony 4.0 or newer | Yes | Recommended on Linux |
| NTPsec | Yes | |
| ntpd (ntp.org reference) | No | Plain NTP only |
| Windows Time (`w32tm`) | No | Plain NTP only |
| systemd-timesyncd | No | Plain SNTP only |

## chrony (with NTS)

Add to `/etc/chrony/chrony.conf` (Debian, Ubuntu) or `/etc/chrony.conf`
(Fedora, RHEL):

```text
server ts1.example.com iburst nts
server ts2.example.com iburst nts
```

Restart chrony (`sudo systemctl restart chrony` or `chronyd`), then check:

```sh
chronyc sources -v       # the servers should be listed, one marked with *
chronyc -N authdata      # mode NTS, with a non-zero cookie count
```

If `authdata` shows no cookies, check that the name resolves, that TCP port 4460
is reachable, and that the board's **NTS Service** card shows NTS-KE running.

## NTPsec (with NTS)

In `/etc/ntpsec/ntp.conf`:

```text
server ts1.example.com nts iburst
server ts2.example.com nts iburst
```

## ntpd (plain NTP)

In `/etc/ntp.conf`:

```text
server ts1.example.com iburst
server ts2.example.com iburst
```

## Windows

In an administrator PowerShell:

```powershell
w32tm /config /manualpeerlist:"ts1.example.com,0x8 ts2.example.com,0x8" /syncfromflags:manual /update
Restart-Service w32time
w32tm /resync
w32tm /query /status
```

`w32tm /query /status` should show one of your servers as **Source** and
stratum 2 (one more than the server). Windows Time does not support NTS.

To test without changing settings:

```powershell
w32tm /stripchart /computer:ts1.example.com /samples:3 /dataonly
```

## systemd-timesyncd

In `/etc/systemd/timesyncd.conf`:

```ini
[Time]
NTP=ts1.example.com ts2.example.com
```

Then `sudo systemctl restart systemd-timesyncd` and check with
`timedatectl timesync-status`. timesyncd is a simple SNTP client without NTS. For
authenticated time, install chrony instead.

## Rate limits

The server limits each client address to an average of 60 requests a minute,
with a burst of 8. Clients that go over get a `RATE` Kiss-o'-Death reply or no
reply. Normal client polling (64 seconds or longer) is far below this. Many
clients behind one NAT address share the limit.

## When the server is not synchronized

The server never hands out time it cannot support:

| Server state | What clients see |
|---|---|
| Synchronized to GNSS | Stratum 1, reference ID `PPS ` |
| Holdover (GNSS lost recently) | Stratum 2, reference ID `HOLD` |
| Not synchronized | Plain NTP: stratum 16, reference ID `INIT`, no timestamps, so clients ignore the server. NTS: no reply |

A client with two or more servers keeps good time while one is unsynchronized.

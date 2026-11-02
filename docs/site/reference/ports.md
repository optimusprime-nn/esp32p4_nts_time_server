# Network ports

## Inbound

| Port | Purpose | Who needs it |
|---|---|---|
| UDP 123 | NTP and NTS-protected NTP | All time clients |
| TCP 4460 | NTS key exchange (TLS 1.3) | NTS clients |
| TCP 443 | Management HTTPS. Client certificate required after the claim | Administrators and monitoring only |

Limit TCP 443 to the machines that manage the board. It is protected by mutual
TLS, but there is no reason to expose it widely.

## Outbound

| Destination | Port | Purpose |
|---|---|---|
| DNS server | UDP/TCP 53 | Name lookups |
| Let's Encrypt (`acme-v02.api.letsencrypt.org`) | TCP 443 | Certificate issuance and renewal |
| Cloudflare API (`api.cloudflare.com`) | TCP 443 | DNS-01 validation records |
| External NTP servers and peers | UDP 123 | Management clock before GNSS locks, and peer monitoring |

The board does not need any other inbound or outbound access.

## Limits on the NTS key exchange

| Limit | Value |
|---|---|
| Worker tasks | 3, with up to 2 more connections waiting |
| Connections per client address | 2 |
| Connection deadline | 5 s from accept |
| Extra sessions | Admitted only while at least 72 KB of internal memory is free; one session is always allowed |

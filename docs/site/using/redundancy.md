# Two servers

Two boards give clients a fallback when one loses GNSS, reboots or is being
updated. Both remain independent stratum-1 servers. There is no primary, and
neither board can change the other's clock.

## Set up the second board

Set it up exactly like the first, with its own:

- hostname and DNS name (for example `ts2` and `ts2.example.com`);
- fixed address (for example `192.0.2.11`);
- credentials folder and password.

Then list both servers in every client; see [Pointing clients at it](clients.md).

## Let each board watch the other

Each board can monitor one **redundant time server** and warn when the two
disagree. This is measurement only.

On **each** board:

1. Open **Management**.
2. In **Redundant Time Server**, tick **Enable redundant-server monitoring**.
3. Enter the **other** board's DNS name in **Peer**.
4. Leave **Warn µs** at 100 and **Critical µs** at 1000 unless you have a
   reason to change them.
5. Click **Save Redundant Server**.

Within a minute the dashboard's **Redundant Time Server** card shows the peer's
stratum, reachability and the clock difference, and **Status** changes to
`HEALTHY`. More detail (delay, jitter, reference ID, poll counts) is on
**Diagnostics → Redundant Time Server — Diagnostics**.

| Status | Meaning |
|---|---|
| `HEALTHY` | Answering, difference below the warning threshold |
| `WARNING` | Difference above the warning threshold |
| `CRITICAL` | Difference above the critical threshold |
| `UNREACHABLE` | Not answering |
| `DEGRADED`, `DIVERGENT`, `INVALID` | Replies are inconsistent or unusable. An occasional `DEGRADED` is a known limitation |
| `KOD` | The peer sent Kiss-o'-Death. `RATE` backs off for 1024 s; `DENY` or `RSTR` stops polling until you save the setting again |
| `UNKNOWN`, `DISABLED` | No result yet, or not configured |

Two boards on the same network normally agree within about ±10 µs.

## General peer monitoring

**Management → Peer Monitoring — Configuration** lets each board also watch up
to three other NTP servers, for example public pool servers. Set the poll
interval (4 to 3600 s, default 16) and response timeout (250 to 10000 ms,
default 2000), tick each peer you want and click **Save Peer Configuration**.
Results appear on the dashboard's **Peer Monitoring** card.

Peers never discipline the local clock. The only timing authority is the local
GNSS receiver and PPS.

## Management time fallback

Before GNSS locks, the board needs an approximate date for TLS and certificate
checks. It tries the redundant time server first, then the two **External NTP**
servers set during commissioning. This affects management only, never served
time or stratum.

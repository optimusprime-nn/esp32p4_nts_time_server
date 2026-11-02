# Check that it works

Open the console at `https://ts1.example.com/` and choose the `ntp-admin`
certificate. The board is ready when all of these are true:

| Page and card | Expect |
|---|---|
| Header badges | `Clock: SYNCHRONIZED`, `NTP: READY`, `Certificate: VALID` |
| Dashboard → Clock and Time | State `SYNCHRONIZED`, Disciplined `YES` |
| Dashboard → NTP Service | Advertised Stratum `1` |
| Dashboard → NTS Service | NTS-KE Running `YES` |
| Diagnostics → GNSS Receiver — Diagnostics | Fix Valid `YES`, Leap State `NONE` |
| System → Certificate & ACME | Certificate Valid `YES`, Hostname matches your DNS name |

After a cold start, allow up to about 12.5 minutes for the clock to reach
`SYNCHRONIZED`. Until then the server answers with stratum 16 or not at all.
That is correct behaviour.

## Test from a computer

=== "Windows"

    ```powershell
    w32tm /stripchart /computer:ts1.example.com /samples:3 /dataonly
    ```

    The offsets show your PC's error against the server, so they may be large
    if your PC's clock is poor. What matters is that replies arrive.

=== "Linux with chrony (NTS)"

    Add to `/etc/chrony/chrony.conf` (or `/etc/chrony.conf`):

    ```text
    server ts1.example.com iburst nts
    ```

    Restart chrony, wait a minute, then:

    ```sh
    chronyc -N authdata
    chronyc sources -v
    ```

    `authdata` should show mode `NTS` with a non-zero cookie count for the
    server.

## Without a browser

`/api/v1/health` answers `200` with `"status":"ok"` when Ethernet is up, the NTP
socket is bound and the clock is servable, and `503` otherwise. It needs the
client certificate like every other management address; see
[Management API](../reference/api.md#calling-the-api).

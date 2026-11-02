# FAQ

**Do I need Cloudflare?**
For the setup described here, yes. The board gets its Let's Encrypt certificate
by creating a DNS-01 record through the Cloudflare API, and NTS needs that
certificate. Plain NTP works without it, but the setup tool and the
certificate steps expect a Cloudflare zone.

**Can the board's address be private, for example 192.168.x.x?**
Yes. Create the DNS `A` record with Cloudflare set to **DNS only**, not
proxied. The setup tool always creates the record as DNS only. Let's Encrypt
never connects to the board; it only checks the DNS record.

**Why must NTS clients use the name and not the IP address?**
The certificate is issued for the name. A client connecting by IP address cannot
match it and refuses the connection.

**Does the board need internet access?**
Yes, outbound: DNS, HTTPS to Let's Encrypt and Cloudflare, and NTP to the
fallback servers. See [Network ports](../reference/ports.md). Timing itself comes
only from GNSS.

**Can the fallback NTP servers or peers change the served time?**
No. They set the management clock for TLS before GNSS locks, and they are
measured for monitoring. The only timing authority is the local GNSS receiver
and PPS.

**What happens when the antenna is disconnected?**
The clock goes into holdover and the server reports stratum 2. If GNSS does not
come back, it stops claiming good time and answers with stratum 16 (plain NTP)
or not at all (NTS).

**How long until a new board serves time?**
A few minutes after a fix, and up to about 12.5 minutes after a cold start,
while the leap-second data arrives from the satellites.

**Can I update firmware over USB?**
Only with ESP-IDF and the encrypted-flash command; see
[Building from source](../building.md#flashing-an-encrypted-board). Normal
updates go over the network from the Firmware page.

**Can I run the setup tool on macOS?**
It is written for Windows and Linux, and only those are tested.

**I lost the credentials folder. Can I reset the board remotely?**
No. That is deliberate. See [Lost credentials](security.md#lost-credentials).

**My administrator certificate expires in 825 days. What then?**
Before it expires, sign a new administrator certificate with the CA key in your
credentials folder, with the same settings (EC P-256, client authentication), and
import it. The board accepts any client certificate signed by your CA.

**Does it handle the 2036 NTP era rollover?**
No. See [Known limitations](limitations.md).

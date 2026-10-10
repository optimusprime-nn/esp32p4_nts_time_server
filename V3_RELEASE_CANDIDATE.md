# ESP32-P4 GNSS NTP/NTS Server — V3.0 Release Candidate

Version: 3.0.0-rc1

## V3 scope

- Two-node active/active redundancy monitoring for deployments such as ts1.nicknewman.au and ts2.nicknewman.au.
- Redundant peer is configured on Management as an FQDN or IPv4 address; firmware is identical on both nodes.
- Peer monitoring is measurement-only and has zero timing authority. It cannot discipline, step, slew, qualify, or otherwise modify the local GNSS/PPS-derived clock.
- Configurable warning and critical clock-difference thresholds (defaults 100 us and 1 ms).
- Dashboard compact Redundant Time Server panel directly below Network.
- Dedicated Diagnostics page with detailed timing, GNSS/PPS, NTP/NTS, redundant-peer, network, storage and system cards plus recent state/fault history.
- Diagnostics controls include Refresh Now, Download Diagnostic Bundle, and Copy Summary.
- Redundant peer DNS resolution result, NTP reachability, stratum, LI, reference ID, offset, delay, jitter and poll statistics are exposed.
- Redundant-peer health transitions are written to operations history and therefore the asynchronous SD archive.
- SD event archival remains responsive on the 2-second worker cadence while capacity/free-space and retention housekeeping are reduced to 60 seconds. Mount retry remains 10 seconds.

## Redundant deployment

TS1: local identity `ts1.example.com`, redundant peer `ts2.example.com`.

TS2: local identity `ts2.example.com`, redundant peer `ts1.example.com`.

There is no primary/secondary role. Both servers remain independent active Stratum-1 sources.

## Frozen timing invariant

The Phase 8 timing architecture remains unchanged. Redundant-peer monitoring has zero timing authority.

## Validation required before V3.0 final

1. Build and boot both nodes.
2. Configure reciprocal redundant-peer FQDNs from Management.
3. Confirm DNS resolution and reach register progression.
4. Confirm Dashboard compact panel is under Network and clock difference is plausible.
5. Remove one peer/network path and confirm UNREACHABLE without any local timing impact; restore and confirm recovery event.
6. Exercise warning/critical thresholds with a controlled test or temporarily lowered thresholds.
7. Confirm Diagnostics page, Copy Summary and diagnostic bundle contain no secrets.
8. Confirm SD archive continues recording events and 60-second housekeeping reports capacity/free space correctly.
9. Confirm NTP/NTS service remains independent throughout peer loss and SD operations.

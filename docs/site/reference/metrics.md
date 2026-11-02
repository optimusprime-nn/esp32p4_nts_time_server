# Metrics

`GET /metrics` returns Prometheus text format (version 0.0.4). Like every
management address it needs your client certificate.

## Prometheus scrape job

```yaml
scrape_configs:
  - job_name: timeservers
    scheme: https
    scrape_interval: 60s
    tls_config:
      cert_file: /etc/prometheus/ntp-admin.crt.pem
      key_file: /etc/prometheus/ntp-admin.key.pem   # an unencrypted copy of the key
    static_configs:
      - targets: ["ts1.example.com:443", "ts2.example.com:443"]
```

Prometheus cannot read an encrypted key. If you make an unencrypted copy for it,
protect that file: anyone holding it has full management access. Do not scrape
more often than you need; every scrape is a TLS handshake on the board.

## Clock, GNSS and PPS

| Metric | Type | Meaning |
|---|---|---|
| `esp32_ntp_clock_state` | gauge | 0 unsynchronized, 1 acquiring, 2 synchronized, 3 holdover, 4 fail-closed |
| `esp32_ntp_clock_solution_valid` | gauge | 1 when the clock solution is valid |
| `esp32_ntp_clock_phase_error_ns` | gauge | Clock phase error, ns |
| `esp32_ntp_clock_frequency_ppm` | gauge | Frequency correction, ppm |
| `esp32_ntp_clock_holdover_seconds` | gauge | Time in holdover, s |
| `esp32_ntp_gnss_utc_valid` | gauge | 1 when the receiver reports valid UTC |
| `esp32_ntp_gnss_satellites` | gauge | Satellites used |
| `esp32_ntp_pps_valid` | gauge | 1 when the PPS interval is valid |
| `esp32_ntp_pps_jitter_us` | gauge | PPS jitter, µs |

## Network and NTP

| Metric | Type | Meaning |
|---|---|---|
| `esp32_ntp_ethernet_ipv4_ready` | gauge | 1 when Ethernet has an IPv4 address |
| `esp32_ntp_server_socket_bound` | gauge | 1 when the NTP socket is bound |
| `esp32_ntp_server_requests_total` | counter | NTP requests received |
| `esp32_ntp_server_responses_total` | counter | NTP responses sent |
| `esp32_ntp_server_rate_kod_total` | counter | `RATE` Kiss-o'-Death replies |
| `esp32_ntp_server_unsynchronized_drops_total` | counter | Requests not answered because the clock was not servable |
| `esp32_ntp_rate_limited_drops_total` | counter | Requests dropped by the rate limiter without a reply |
| `esp32_ntp_tx_compensation_ns` | gauge | Learned NTP transmit-latency compensation, ns |

## NTS

| Metric | Type | Meaning |
|---|---|---|
| `esp32_nts_ke_running` | gauge | 1 when NTS key exchange is running |
| `esp32_nts_ke_exchanges_total` | counter | Successful key exchanges |
| `esp32_nts_ke_exchange_failures_total` | counter | Failed key exchanges |
| `esp32_nts_ke_deadline_expirations_total` | counter | Key-exchange connections closed at the 5 s deadline |
| `esp32_nts_ke_rejections_total{reason="per_client"}` | counter | Refused: too many connections from one address |
| `esp32_nts_ke_rejections_total{reason="busy"}` | counter | Refused: all workers busy |
| `esp32_nts_ke_rejections_total{reason="low_memory"}` | counter | Refused: not enough free memory |
| `esp32_nts_ke_certificate_reloads_total` | counter | TLS certificate reloads |
| `esp32_nts_authenticated_requests_total` | counter | Authenticated NTS time requests |
| `esp32_nts_verification_failures_total` | counter | NTS requests that failed verification |
| `esp32_nts_protected_responses_total` | counter | Protected NTS responses sent |
| `esp32_nts_protection_failures_total` | counter | Responses that could not be protected |
| `esp32_nts_naks_sent_total` | counter | NTS NAK (Kiss-o'-Death `NTSN`) replies |
| `esp32_nts_tx_bias_ns` | gauge | Learned NTS transmit-timestamp bias, ns |

## Peer monitoring

| Metric | Type | Meaning |
|---|---|---|
| `esp32_ntp_peer_monitor_enabled` | gauge | 1 when peer monitoring is on |
| `esp32_ntp_peer_cross_spread_ns` | gauge | Spread of offsets across peers, ns |
| `esp32_ntp_peer_poll_cycles_total` | counter | Poll cycles |
| `esp32_ntp_peer_configured{peer="N"}` | gauge | 1 when peer N is configured |
| `esp32_ntp_peer_health{peer="N"}` | gauge | Health code, see below |
| `esp32_ntp_peer_offset_ns{peer="N"}` | gauge | Peer offset, ns |
| `esp32_ntp_peer_delay_ns{peer="N"}` | gauge | Round-trip delay, ns |
| `esp32_ntp_peer_jitter_ns{peer="N"}` | gauge | Jitter, ns |
| `esp32_ntp_peer_reachability{peer="N"}` | gauge | Reachability register (8 bits) |
| `esp32_ntp_peer_successful_polls_total{peer="N"}` | counter | Successful polls |
| `esp32_ntp_peer_failed_polls_total{peer="N"}` | counter | Failed polls |
| `esp32_ntp_peer_rejected_responses_total{peer="N"}` | counter | Rejected replies |
| `esp32_ntp_peer_duplicate_responses_total{peer="N"}` | counter | Duplicate replies |

`peer` is `0` to `2` for the general peers and `3` for the redundant time server.

Health codes: 0 disabled, 1 unknown, 2 healthy, 3 warning, 4 critical,
5 degraded, 6 unreachable, 7 divergent, 8 Kiss-o'-Death, 9 invalid.

## Operations and storage

| Metric | Type | Meaning |
|---|---|---|
| `esp32_ntp_operations_history_available` | gauge | 1 when the event history can be read |
| `esp32_ntp_operations_boot_count` | counter | Boots since the history was created |
| `esp32_ntp_operations_events` | gauge | Events currently retained |
| `esp32_ntp_operations_events_overwritten_total` | counter | Events overwritten by the bounded ring |
| `esp32_ntp_operations_reset_watchdog_total` | counter | Watchdog resets |
| `esp32_ntp_operations_reset_panic_total` | counter | Panic resets |
| `esp32_ntp_operations_reset_brownout_total` | counter | Brownout resets |
| `esp32_ntp_storage_mounted` | gauge | 1 when the SD card is mounted |
| `esp32_ntp_storage_low_space` | gauge | 1 when free space is below the reserve |
| `esp32_ntp_storage_free_bytes` | gauge | Free space on the card, bytes |
| `esp32_ntp_storage_write_failures_total` | counter | SD archive write failures |
| `esp32_ntp_storage_command_queue_drops_total` | counter | SD commands dropped because the queue was full |

## Useful alerts

| Alert when | Means |
|---|---|
| `esp32_ntp_clock_state != 2` for 15 minutes | Not synchronized to GNSS |
| `esp32_nts_ke_running == 0` for 10 minutes | NTS unavailable (check the certificate) |
| `esp32_ntp_peer_health{peer="3"}` is 3 or 4 | The two boards disagree beyond the thresholds |
| `increase(esp32_ntp_operations_reset_watchdog_total[1d]) > 0` | A watchdog reset happened |

Heap figures are in `/api/v1/status` under `system`, not in `/metrics`.

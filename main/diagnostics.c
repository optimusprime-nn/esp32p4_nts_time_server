#include "diagnostics.h"

#include <inttypes.h>
#include <stdio.h>

#include "app_config.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "nts_ke.h"
#include "operations_history.h"
#include "pps_service.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "esp_attr.h"
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "DIAG";

/* Observe-only callback inactivity threshold. Does not touch Ethernet state. */
#define ETH_RX_STALL_THRESHOLD_US (30000000LL)

/* Experimental one-shot recovery: set to 1 ONLY on the TS2 test build.
 * Keep disabled on TS1 and production firmware. */
#ifndef TS2_B5_ONE_SHOT_RECOVERY
#define TS2_B5_ONE_SHOT_RECOVERY 0
#endif


/* Ethernet RX-hang watchdog, on every board. The ESP32-P4 EMAC can stop
 * delivering received frames (first seen on TS2, then on TS1 on 24 Oct 2026,
 * when TS1 stayed dark for 56 min until power-cycled). Reboot after 120 s with
 * no RX progress while link and IPv4 are up. Boards normally receive steady
 * traffic (ARP, peer polls every 16 s, NTP clients), so 2 min of silence is
 * not ordinary idleness. RTC memory survives esp_restart(); cap consecutive
 * recovery boots so a fault that a reboot does not fix cannot loop forever.
 * The budget clears only after 10 min of sustained RX progress. */
#define RX_WATCHDOG_ENABLED 1
#define RX_WATCHDOG_REBOOT_AFTER_US (120000000LL)
/* Link up but no IPv4 for this long: DHCP has had ample time, so treat an
 * RX path that cannot complete DHCP as a hang. */
#define RX_WATCHDOG_NO_IP_AFTER_US  (600000000LL)
#define RX_WATCHDOG_STABLE_CLEAR_US (600000000LL)
#define RX_WATCHDOG_MAX_REBOOTS 2
RTC_NOINIT_ATTR static uint32_t s_rx_watchdog_magic;
RTC_NOINIT_ATTR static uint32_t s_rx_watchdog_reboots;
#define RX_WATCHDOG_MAGIC 0x54325258U


static const char *clock_state_to_string(app_clock_state_t state)
{
    switch (state) {
    case APP_CLOCK_UNSYNCHRONIZED:
        return "UNSYNCHRONIZED";

    case APP_CLOCK_ACQUIRING:
        return "ACQUIRING";

    case APP_CLOCK_SYNCHRONIZED:
        return "SYNCHRONIZED";

    case APP_CLOCK_HOLDOVER:
        return "HOLDOVER";

    case APP_CLOCK_FAIL_CLOSED:
        return "FAIL_CLOSED";

    default:
        return "UNKNOWN";
    }
}

static const char *leap_to_string(app_leap_indicator_t leap)
{
    switch (leap) {
    case APP_LEAP_NO_WARNING:
        return "NONE";

    case APP_LEAP_ADD_SECOND:
        return "ADD";

    case APP_LEAP_DELETE_SECOND:
        return "DELETE";

    case APP_LEAP_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static void diagnostics_task(void *arg)
{
    (void)arg;

    uint32_t previous_rx = 0U;
    int64_t last_rx_progress_us = 0;
    bool rx_seen = false;
    bool stall_reported = false;
    int64_t stable_rx_since_us = 0;
    if (s_rx_watchdog_magic != RX_WATCHDOG_MAGIC ||
        s_rx_watchdog_reboots > RX_WATCHDOG_MAX_REBOOTS) {
        s_rx_watchdog_magic = RX_WATCHDOG_MAGIC;
        s_rx_watchdog_reboots = 0;
    }
    int64_t last_stall_snapshot_us = 0;
#if TS2_B5_ONE_SHOT_RECOVERY
    bool recovery_attempted = false;
#endif

    while (true) {
        pps_service_status_t pps_status;
        gnss_service_status_t gnss_status;
        clock_discipline_status_t clock_status;
        eth_service_status_t eth_status;
        ntp_server_status_t ntp_status;

        (void)pps_service_get_status(&pps_status);
        (void)gnss_service_get_status(&gnss_status);
        (void)clock_discipline_get_status(&clock_status);
        (void)eth_service_get_status(&eth_status);
        (void)ntp_server_get_status(&ntp_status);

        ESP_LOGI(
            TAG,
            "clock=%s solution=%d samples=%" PRIu32 "/%" PRIu32
            " phase=%" PRId64 " ns freq=%.6f ppm holdover=%" PRIu32 " s",
            clock_state_to_string(clock_status.state),
            clock_status.solution_valid,
            clock_status.accepted_samples,
            clock_status.rejected_samples,
            clock_status.phase_error_ns,
            clock_status.frequency_ppm,
            clock_status.holdover_seconds);

        ESP_LOGI(
            TAG,
            "pps: ETM=%d valid=%d edges=%" PRIu32
            " age=%" PRId64 " us period=%" PRIu32
            " us jitter=%" PRIu32 " us drops=%" PRIu32,
            pps_status.etm_active,
            pps_status.interval_valid,
            pps_status.edge_count,
            pps_status.age_us,
            pps_status.period_us,
            pps_status.jitter_us,
            pps_status.queue_drops);

        ESP_LOGI(
            TAG,
            "gnss: utc_valid=%d ubx_pvt=%d utc=%" PRId64
            " fix=%d type=%u sv=%u resolved=%d leap=%s",
            gnss_status.utc_valid,
            gnss_status.utc_from_ubx_pvt,
            gnss_status.utc_seconds,
            gnss_status.gnss_fix_valid,
            gnss_status.fix_type,
            gnss_status.satellites_used,
            gnss_status.gnss_time_fully_resolved,
            leap_to_string(gnss_status.leap_indicator));

        ESP_LOGI(
            TAG,
            "eth: started=%d link=%d ipv4=%d mac=%02x:%02x:%02x:%02x:%02x:%02x",
            eth_status.started,
            eth_status.link_up,
            eth_status.ipv4_ready,
            eth_status.mac[0],
            eth_status.mac[1],
            eth_status.mac[2],
            eth_status.mac[3],
            eth_status.mac[4],
            eth_status.mac[5]);

        ESP_LOGI(TAG,
                 "eth-path: rx=%" PRIu32 " arp=%" PRIu32 " dhcp=%" PRIu32
                 " rx_fwd_fail=%" PRIu32 " tx_other=%" PRIu32
                 " tx_other_fail=%" PRIu32 " link_up=%" PRIu32
                 " link_down=%" PRIu32 " got_ip=%" PRIu32,
                 eth_status.diag_rx_frames,
                 eth_status.diag_rx_arp,
                 eth_status.diag_rx_dhcp,
                 eth_status.diag_rx_forward_fail,
                 eth_status.diag_tx_other_attempt,
                 eth_status.diag_tx_other_fail,
                 eth_status.diag_link_up_events,
                 eth_status.diag_link_down_events,
                 eth_status.diag_got_ip_events);

        /* Diagnose callback inactivity only when the link and IPv4 are up.
         * This runs in the existing low-priority diagnostics task, never in
         * the RX callback or the frozen NTP/PTP timing path. */
        const int64_t rx_now_us = esp_timer_get_time();
        if (!eth_status.started || !eth_status.link_up || !eth_status.ipv4_ready) {
            stable_rx_since_us = 0;
            rx_seen = false;
            stall_reported = false;
            last_stall_snapshot_us = 0;
            last_rx_progress_us = rx_now_us;
            previous_rx = eth_status.diag_rx_frames;
        } else if (!rx_seen || eth_status.diag_rx_frames != previous_rx) {
            rx_seen = eth_status.diag_rx_frames != 0U;
            last_rx_progress_us = rx_now_us;
            previous_rx = eth_status.diag_rx_frames;
            if (!stable_rx_since_us) stable_rx_since_us = rx_now_us;
            if (rx_now_us - stable_rx_since_us >= RX_WATCHDOG_STABLE_CLEAR_US &&
                s_rx_watchdog_reboots != 0) {
                ESP_LOGW(TAG, "RX watchdog: stable RX for 10min; clearing reboot budget");
                s_rx_watchdog_reboots = 0;
            }
            if (stall_reported) {
                ESP_LOGW(TAG, "eth-rx-stall: RECOVERED rx=%" PRIu32,
                         eth_status.diag_rx_frames);
            }
            stall_reported = false;
            last_stall_snapshot_us = 0;
        } else if (rx_seen && !stall_reported &&
                   rx_now_us - last_rx_progress_us >= ETH_RX_STALL_THRESHOLD_US) {
            stable_rx_since_us = 0;
            stall_reported = true;
            last_stall_snapshot_us = rx_now_us;
            ESP_LOGE(TAG,
                     "eth-rx-stall: DETECTED idle_ms=%" PRId64
                     " rx=%" PRIu32 " arp=%" PRIu32
                     " link=%d ipv4=%d tx_attempt=%" PRIu32
                     " tx_fail=%" PRIu32 " rx_fwd_fail=%" PRIu32,
                     (rx_now_us - last_rx_progress_us) / 1000,
                     eth_status.diag_rx_frames, eth_status.diag_rx_arp,
                     eth_status.link_up, eth_status.ipv4_ready,
                     eth_status.diag_tx_other_attempt,
                     eth_status.diag_tx_other_fail,
                     eth_status.diag_rx_forward_fail);
            eth_service_diag_log_emac_snapshot();
            eth_service_diag_log_phy_snapshot();
#if TS2_B5_ONE_SHOT_RECOVERY
            if (!recovery_attempted) {
                recovery_attempted = true; /* once per boot, even on failure */
                ESP_LOGW(TAG, "B5: initiating one-shot diagnostic restart after RX stall");
                esp_err_t restart_err = eth_service_diag_restart_driver();
                ESP_LOGW(TAG, "B5: restart returned %s", esp_err_to_name(restart_err));
            }
#endif
        }
#if RX_WATCHDOG_ENABLED
        /* Avoid interpreting ordinary idle traffic as failure: require an
         * established RX history and link + IPv4 up, so a cable pull or a
         * lost DHCP lease never triggers a reboot. */
        if (rx_seen && stall_reported && eth_status.started &&
            eth_status.link_up && eth_status.ipv4_ready &&
            rx_now_us - last_rx_progress_us >= RX_WATCHDOG_REBOOT_AFTER_US &&
            s_rx_watchdog_reboots < RX_WATCHDOG_MAX_REBOOTS) {
            ++s_rx_watchdog_reboots;
            ESP_LOGE(TAG, "RX watchdog: RX stalled >%llds, reboot %" PRIu32 "/%u",
                     (long long)(RX_WATCHDOG_REBOOT_AFTER_US / 1000000LL),
                     s_rx_watchdog_reboots, RX_WATCHDOG_MAX_REBOOTS);
            /* Persist recovery reason before reboot; SD writes are asynchronous. */
            char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
            (void)snprintf(detail, sizeof(detail),
                           "Ethernet RX stalled; reboot %" PRIu32 "/%u; rx=%" PRIu32,
                           s_rx_watchdog_reboots, RX_WATCHDOG_MAX_REBOOTS,
                           eth_status.diag_rx_frames);
            esp_err_t record_err = operations_history_record(
                OPERATIONS_EVENT_RECOVERY, (int32_t)s_rx_watchdog_reboots, detail);
            if (record_err != ESP_OK) {
                ESP_LOGE(TAG, "RX watchdog NVS event failed: %s", esp_err_to_name(record_err));
            }
            esp_restart();
        }

        /* The RX counter alone cannot see every whole-board outage: the
         * board can keep receiving while transmit is dead (for example the
         * MAC left stopped after a failed link-down), or while received
         * frames never reach lwIP. Watch progress on both paths, and the
         * link-up-but-no-address case where an RX hang stops DHCP. All
         * share the same reboot budget. */
        static uint32_t s_wd_last_tx_ok;
        static uint32_t s_wd_last_tx_attempt;
        static int64_t s_wd_tx_failing_since_us;
        static uint32_t s_wd_last_rx_fwd_ok;
        static uint32_t s_wd_last_rx_seen;
        static int64_t s_wd_rx_failing_since_us;
        static int64_t s_wd_link_no_ip_since_us;

        const uint32_t tx_ok = eth_status.diag_tx_other_attempt - eth_status.diag_tx_other_fail;
        const uint32_t rx_fwd_ok = eth_status.diag_rx_frames - eth_status.diag_rx_forward_fail;
        const bool link_and_ip = eth_status.started && eth_status.link_up && eth_status.ipv4_ready;

        /* A failure run starts at the first attempt that fails after a
         * success and ends at the next success. Idle windows neither start
         * nor end it, so bursty retries while a path is dead still count,
         * and a single failure after a long quiet spell does not. */
        if (!link_and_ip || tx_ok != s_wd_last_tx_ok) {
            s_wd_tx_failing_since_us = 0;
        } else if (eth_status.diag_tx_other_attempt != s_wd_last_tx_attempt &&
                   s_wd_tx_failing_since_us == 0) {
            s_wd_tx_failing_since_us = rx_now_us;
        }
        s_wd_last_tx_ok = tx_ok;
        s_wd_last_tx_attempt = eth_status.diag_tx_other_attempt;

        if (!link_and_ip || rx_fwd_ok != s_wd_last_rx_fwd_ok) {
            s_wd_rx_failing_since_us = 0;
        } else if (eth_status.diag_rx_frames != s_wd_last_rx_seen &&
                   s_wd_rx_failing_since_us == 0) {
            s_wd_rx_failing_since_us = rx_now_us;
        }
        s_wd_last_rx_fwd_ok = rx_fwd_ok;
        s_wd_last_rx_seen = eth_status.diag_rx_frames;

        /* Link up without an address. */
        if (eth_status.started && eth_status.link_up && !eth_status.ipv4_ready) {
            if (s_wd_link_no_ip_since_us == 0) s_wd_link_no_ip_since_us = rx_now_us;
        } else {
            s_wd_link_no_ip_since_us = 0;
        }

        const char *stall_reason = NULL;
        if (s_wd_tx_failing_since_us != 0 &&
            rx_now_us - s_wd_tx_failing_since_us >= RX_WATCHDOG_REBOOT_AFTER_US) {
            stall_reason = "Ethernet TX stalled";
        } else if (s_wd_rx_failing_since_us != 0 &&
                   rx_now_us - s_wd_rx_failing_since_us >= RX_WATCHDOG_REBOOT_AFTER_US) {
            stall_reason = "Ethernet RX not reaching lwIP";
        } else if (s_wd_link_no_ip_since_us != 0 &&
                   rx_now_us - s_wd_link_no_ip_since_us >= RX_WATCHDOG_NO_IP_AFTER_US) {
            stall_reason = "Ethernet link up without IPv4";
        }

        if (stall_reason != NULL && s_rx_watchdog_reboots < RX_WATCHDOG_MAX_REBOOTS) {
            ++s_rx_watchdog_reboots;
            ESP_LOGE(TAG, "Network watchdog: %s, reboot %" PRIu32 "/%u",
                     stall_reason, s_rx_watchdog_reboots, RX_WATCHDOG_MAX_REBOOTS);
            char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
            (void)snprintf(detail, sizeof(detail), "%s; reboot %" PRIu32 "/%u",
                           stall_reason, s_rx_watchdog_reboots, RX_WATCHDOG_MAX_REBOOTS);
            esp_err_t record_err = operations_history_record(
                OPERATIONS_EVENT_RECOVERY, (int32_t)s_rx_watchdog_reboots, detail);
            if (record_err != ESP_OK) {
                ESP_LOGE(TAG, "Network watchdog NVS event failed: %s", esp_err_to_name(record_err));
            }
            esp_restart();
        }
#endif
        if (rx_seen && stall_reported &&
                   rx_now_us - last_stall_snapshot_us >= 60000000LL) {
            /* Periodic read-only follow-up while RX remains stalled. */
            last_stall_snapshot_us = rx_now_us;
            ESP_LOGW(TAG, "eth-rx-stall: FOLLOWUP idle_ms=%" PRId64
                     " rx=%" PRIu32 " link=%d ipv4=%d",
                     (rx_now_us - last_rx_progress_us) / 1000,
                     eth_status.diag_rx_frames, eth_status.link_up,
                     eth_status.ipv4_ready);
            eth_service_diag_log_emac_snapshot();
            eth_service_diag_log_phy_snapshot();
        }

        ESP_LOGI(
            TAG,
            "ntp: started=%d bound=%d req=%" PRIu32
            " valid_rsp=%" PRIu32 " invalid=%" PRIu32
            " unsync_drop=%" PRIu32 " rate_kod=%" PRIu32
            " send_fail=%" PRIu32 " socket_fail=%" PRIu32
            " stratum=%u li=%u dispersion=0x%08" PRIx32,
            ntp_status.started,
            ntp_status.socket_bound,
            ntp_status.requests_received,
            ntp_status.normal_responses,
            ntp_status.invalid_requests,
            ntp_status.unsynchronized_drops,
            ntp_status.rate_kod_responses,
            ntp_status.send_failures,
            ntp_status.socket_open_failures,
            ntp_status.advertised_stratum,
            ntp_status.advertised_leap_indicator,
            ntp_status.advertised_root_dispersion);

        if (ntp_status.timing_samples > 0U) {
            ESP_LOGI(
                TAG,
                "ntp-timing: n=%" PRIu32
                " rx_start=%" PRIu32 "/%" PRIu32 "/%" PRIu32
                " us rx_clock=%" PRIu32 "/%" PRIu32 "/%" PRIu32
                " us build=%" PRIu32 "/%" PRIu32 "/%" PRIu32 " us",
                ntp_status.timing_samples,
                ntp_status.rx_timestamp_start_min_us,
                ntp_status.rx_timestamp_start_avg_us,
                ntp_status.rx_timestamp_start_max_us,
                ntp_status.rx_timestamp_call_min_us,
                ntp_status.rx_timestamp_call_avg_us,
                ntp_status.rx_timestamp_call_max_us,
                ntp_status.response_build_min_us,
                ntp_status.response_build_avg_us,
                ntp_status.response_build_max_us);

            ESP_LOGI(
                TAG,
                "ntp-timing: tx_to_send=%" PRIu32 "/%" PRIu32 "/%" PRIu32
                " us send=%" PRIu32 "/%" PRIu32 "/%" PRIu32
                " us total=%" PRIu32 "/%" PRIu32 "/%" PRIu32 " us",
                ntp_status.tx_timestamp_to_send_min_us,
                ntp_status.tx_timestamp_to_send_avg_us,
                ntp_status.tx_timestamp_to_send_max_us,
                ntp_status.send_call_min_us,
                ntp_status.send_call_avg_us,
                ntp_status.send_call_max_us,
                ntp_status.total_response_min_us,
                ntp_status.total_response_avg_us,
                ntp_status.total_response_max_us);
        }

        /* Hardware-timestamp path health: why requests may be dropped
         * (no RX stamp / mapping failed) and the learned TX corrections. */
        if (ntp_status.requests_received > 0U) {
            ESP_LOGI(
                TAG,
                "ntp-hw: rx_match=%" PRIu32 " rx_miss=%" PRIu32
                " stale=%" PRIu32 " overrun=%" PRIu32
                " map_ok=%" PRIu32 " map_fail=%" PRIu32
                " drop=%" PRIu32 " rate_drop=%" PRIu32 " bracket=%" PRIu32 " ns"
                " tx_comp=%" PRId64 " ns nts_bias=%" PRId32
                " ns nts_resid=%" PRId64 " ns (n=%" PRIu32 ")",
                eth_status.rx_hw_queue_matches,
                eth_status.rx_hw_queue_misses,
                eth_status.rx_hw_queue_stale_purges,
                eth_status.rx_hw_queue_overruns,
                eth_status.rx_hw_map_successes,
                eth_status.rx_hw_map_failures,
                ntp_status.hw_rx_authority_drops,
                ntp_status.rate_limited_drops,
                eth_status.rx_hw_last_map_bracket_ns,
                eth_status.tx_compensation_ns,
                eth_status.nts_tx_bias_ns,
                eth_status.nts_tx_last_residual_ns,
                eth_status.nts_tx_bias_samples);
        }

        nts_ke_stats_t ke_stats;
        nts_ke_get_stats(&ke_stats);
        if (ke_stats.exchanges_completed != 0U ||
            ke_stats.exchange_failures != 0U ||
            ke_stats.tls_handshake_failures != 0U) {
            ESP_LOGI(
                TAG,
                "nts-ke: ok=%" PRIu32 " fail=%" PRIu32 " tls_fail=%" PRIu32
                " deadline=%" PRIu32 " active=%" PRIu32
                " reject_client=%" PRIu32 " reject_mem=%" PRIu32
                " reject_busy=%" PRIu32 " cert_reload=%" PRIu32
                " stack_min_free=%" PRIu32 " heap_int_free=%u",
                ke_stats.exchanges_completed,
                ke_stats.exchange_failures,
                ke_stats.tls_handshake_failures,
                ke_stats.deadline_expirations,
                ke_stats.active_connections,
                ke_stats.per_client_rejections,
                ke_stats.low_memory_rejections,
                ke_stats.busy_rejections,
                ke_stats.certificate_reloads,
                ke_stats.worker_stack_min_free,
                (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        }

        vTaskDelay(pdMS_TO_TICKS(5000U));
    }
}

esp_err_t diagnostics_start(void)
{
    const BaseType_t task_created = xTaskCreate(
        diagnostics_task,
        "diagnostics",
        APP_DIAGNOSTICS_TASK_STACK_SIZE,
        NULL,
        APP_DIAGNOSTICS_TASK_PRIORITY,
        NULL);

    return task_created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}

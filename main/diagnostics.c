#include "diagnostics.h"

#include <inttypes.h>

#include "app_config.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "ntp_server.h"
#include "pps_service.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "DIAG";

/* Observe-only callback inactivity threshold. Does not touch Ethernet state. */
#define ETH_RX_STALL_THRESHOLD_US (30000000LL)

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
    int64_t last_stall_snapshot_us = 0;

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
            rx_seen = false;
            stall_reported = false;
            last_stall_snapshot_us = 0;
            last_rx_progress_us = rx_now_us;
            previous_rx = eth_status.diag_rx_frames;
        } else if (!rx_seen || eth_status.diag_rx_frames != previous_rx) {
            rx_seen = eth_status.diag_rx_frames != 0U;
            last_rx_progress_us = rx_now_us;
            previous_rx = eth_status.diag_rx_frames;
            if (stall_reported) {
                ESP_LOGW(TAG, "eth-rx-stall: RECOVERED rx=%" PRIu32,
                         eth_status.diag_rx_frames);
            }
            stall_reported = false;
            last_stall_snapshot_us = 0;
        } else if (rx_seen && !stall_reported &&
                   rx_now_us - last_rx_progress_us >= ETH_RX_STALL_THRESHOLD_US) {
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
        } else if (rx_seen && stall_reported &&
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
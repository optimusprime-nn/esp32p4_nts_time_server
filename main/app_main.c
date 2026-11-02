#include <stdbool.h>

#include "app_state.h"
#include "clock_discipline.h"
#include "commissioning.h"
#include "device_config.h"
#include "hardware_profile.h"
#include "diagnostics.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "management_ownership.h"
#include "operations_history.h"
#include "ota_manager.h"
#include "ntp_server.h"
#include "ntp_peer_monitor.h"
#include "nts_ke.h"
#include "pps_service.h"
#include "sd_storage.h"
#include "web_console.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "nvs_flash.h"

static const char *TAG = "MAIN";

/* How long a new OTA image must run before it is confirmed. Long enough to
 * cover the SD mount, the first GNSS lock and the first network-watchdog
 * window, so the failures seen in the field (SD/PSRAM boot loop, network
 * stall) happen while the image can still roll back. */
#define OTA_SOAK_SECONDS 300U

static bool s_web_console_started;

static void ota_soak_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(OTA_SOAK_SECONDS * 1000U));

    if (!s_web_console_started) {
        /* The console is the only OTA path: an image without it cannot be
         * replaced remotely, so return to the previous one if still pending. */
        const esp_err_t err =
            ota_manager_reject_running_image("web console failed to start; rolling back");
        if (err != ESP_ERR_INVALID_STATE) {
            ESP_LOGE(TAG, "OTA rollback request failed: %s", esp_err_to_name(err));
        }
    } else {
        const esp_err_t err = ota_manager_confirm_running_image();
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "OTA running-image confirmation failed: %s", esp_err_to_name(err));
        }
    }

    vTaskDelete(NULL);
}

static void enter_fail_closed(const char *component, esp_err_t err)
{
    ESP_LOGE(TAG,
             "%s initialization failed: %s (0x%x)",
             component,
             esp_err_to_name(err),
             (unsigned int)err);

    app_state_set_clock_solution(APP_CLOCK_FAIL_CLOSED,
                                 false,
                                 0,
                                 0.0,
                                 0,
                                 0,
                                 0,
                                 0);
}

void app_main(void)
{
    ESP_LOGI(TAG, "Starting GNSS-disciplined NTP server");

    esp_err_t err = nvs_flash_init();

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "NVS initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = esp_netif_init();

    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG,
                 "esp_netif initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = esp_event_loop_create_default();

    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG,
                 "event-loop initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    app_state_init();

    err = device_config_init();

    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Device configuration initialization failed: %s",
                 esp_err_to_name(err));
        return;
    }

    err = commissioning_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Commissioning configuration unavailable: %s", esp_err_to_name(err));
    }

    err = hardware_profile_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Hardware profile initialization failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "Initializing persistent operations history");
    err = operations_history_init();

    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "Persistent operations history unavailable; continuing fail-open: %s",
                 esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Persistent operations history initialized");
    }

    err = ota_manager_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "OTA manager initialization failed; continuing: %s", esp_err_to_name(err));
    }

    err = management_ownership_init();

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Management ownership initialization failed: %s", esp_err_to_name(err));
        return;
    }

    err = pps_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("PPS service", err);
        return;
    }

    err = gnss_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("GNSS service", err);
        return;
    }

    err = clock_discipline_init();

    if (err != ESP_OK) {
        enter_fail_closed("clock discipline", err);
        return;
    }

    err = diagnostics_start();

    if (err != ESP_OK) {
        enter_fail_closed("diagnostics", err);
        return;
    }

    err = eth_service_init();

    if (err != ESP_OK) {
        enter_fail_closed("Ethernet initialization", err);
        return;
    }

    err = eth_service_start();

    if (err != ESP_OK) {
        enter_fail_closed("Ethernet startup", err);
        return;
    }

    /* NTP binds INADDR_ANY, which works before the interface has an address,
     * so start it first: it answers as soon as DHCP (or the static address)
     * completes, without waiting on anything below. */
    err = ntp_server_start();

    if (err != ESP_OK) {
        enter_fail_closed("NTP server startup", err);
        return;
    }

    eth_service_wait_for_ip();

    /* Management-only wall-clock bootstrap for TLS/ACME. The manager task
     * syncs immediately and then periodically, in the background, so boot
     * no longer blocks on external NTP lookups. It does not feed
     * clock_discipline, NTP serving state, PPS/PTP correlation, or NTS. */
    const esp_err_t time_manager_err = commissioning_start_time_manager();
    if (time_manager_err != ESP_OK) {
        ESP_LOGW(TAG, "Management-time source manager did not start: %s",
                 esp_err_to_name(time_manager_err));
    }

    const esp_err_t peer_monitor_err = ntp_peer_monitor_start();

    if (peer_monitor_err != ESP_OK) {
        /* Peer monitoring is telemetry-only and must never gate NTP service. */
        ESP_LOGW(TAG,
                 "NTP peer monitor did not start: %s",
                 esp_err_to_name(peer_monitor_err));
    }

    /* SD storage is operations-plane only. Mount/write failure must never gate
     * the authoritative clock, NTP, NTS, GNSS/PPS, or management service. */
    const esp_err_t sd_err = sd_storage_start();
    if (sd_err != ESP_OK) {
        ESP_LOGW(TAG, "SD operational storage unavailable; continuing: %s",
                 esp_err_to_name(sd_err));
    }

    err = web_console_start();
    s_web_console_started = (err == ESP_OK);

    if (err != ESP_OK) {
        /*
         * The read-only console is not part of the timing or NTP trust path.
         * Keep NTP operational if the optional management console fails.
         */
        ESP_LOGW(TAG,
                 "Web console did not start: %s",
                 esp_err_to_name(err));
    }

    err = nts_ke_start();

    if (err != ESP_OK) {
        /*
         * NTS-KE is an authentication/key-establishment service and is not
         * part of the authoritative timing path. Keep conventional NTP and
         * management services operational if NTS-KE cannot start.
         */
        ESP_LOGW(TAG,
                 "NTS-KE server did not start: %s",
                 esp_err_to_name(err));
    }

    /* A newly booted OTA image is confirmed only after it has run for a soak
     * period with the management console up (see ota_soak_task). Any crash
     * or watchdog reboot before then leaves it pending, so the bootloader
     * rolls back to the previous image. */
    if (xTaskCreate(ota_soak_task, "ota_soak", 4096U, NULL, 3U, NULL) != pdPASS) {
        ESP_LOGW(TAG, "OTA soak task unavailable; confirming running image now");
        (void)ota_manager_confirm_running_image();
    }

    if (peer_monitor_err == ESP_OK) {
        ESP_LOGI(TAG,
                 "Ethernet, NTP, peer monitoring, NTS-KE, and HTTPS management services started");
    } else {
        ESP_LOGI(TAG,
                 "Ethernet, NTP, NTS-KE, and HTTPS management services started; peer monitoring unavailable");
    }
}
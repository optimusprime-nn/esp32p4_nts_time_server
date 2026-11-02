#include <sys/stat.h>
#include "web_console.h"

#include <inttypes.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "acme_client.h"
#include "app_state.h"
#include "clock_discipline.h"
#include "cloudflare_client.h"
#include "commissioning.h"
#include "device_config.h"
#include "eth_service.h"
#include "gnss_service.h"
#include "hardware_profile.h"
#include "management_ownership.h"
#include "ntp_server.h"
#include "ntp_peer_monitor.h"
#include "operations_history.h"
#include "ota_manager.h"
#include "ntp_types.h"
#include "nts_ke.h"
#include "nts_ntp_auth.h"
#include "pps_service.h"
#include "sd_storage.h"

#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "WEB";

#define APP_WEB_CONSOLE_PORT                    443U
#define APP_WEB_CONSOLE_STACK_SIZE              16384U  /* ACME issue path needs ~11 KB of frames */
#define APP_WEB_CONSOLE_MAX_HANDLERS            64U
#define APP_WEB_CONFIG_BODY_MAX                  2048U
#define APP_WEB_CONSOLE_MAX_OPEN_SOCKETS        4U
/* Kept in seconds: pdMS_TO_TICKS() multiplies in 32 bits and wraps above ~71
 * minutes, which turned the previous 6 h interval into ~125 s. */
#define APP_ACME_RENEWAL_CHECK_INTERVAL_SECONDS  (12U * 60U * 60U)
#define APP_ACME_RENEWAL_INITIAL_DELAY_MS         30000U
#define APP_ACME_RENEWAL_TASK_STACK_SIZE         12288U
#define APP_ACME_RENEWAL_TASK_PRIORITY               4U
#define APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION      1U
#define APP_TLS_ACTIVATION_OUTCOME_KEY                 "tls_out"
#define APP_TLS_HANDOFF_RECORD_VERSION                  1U
#define APP_TLS_HANDOFF_KEY                             "tls_hnd"
#define APP_TLS_HANDOFF_RETRY_SECONDS                   (6LL * 60LL * 60LL)
#define APP_ACME_RENEWAL_ATTEMPT_COOLDOWN_SECONDS   (6LL * 60LL * 60LL)

static httpd_handle_t s_server;
static bool s_started;

typedef enum {
    WEB_TLS_EMBEDDED = 0,
    WEB_TLS_STORED_TEST,
    WEB_TLS_PRODUCTION,
} web_tls_source_t;

static volatile bool s_tls_transition_pending;
static volatile bool s_tls_transition_automatic;
static portMUX_TYPE s_tls_transition_lock = portMUX_INITIALIZER_UNLOCKED;
static web_tls_source_t s_tls_source = WEB_TLS_EMBEDDED;
static acme_tls_credentials_t s_active_stored_credentials;
static char *s_management_client_ca;
static size_t s_management_client_ca_length;
static unsigned int s_provisioning_failures;
static char s_active_server_leaf_sha256[65];

typedef struct {
    uint32_t version;
    bool result_valid;
    bool success;
    bool lkg_restored;
    int64_t completed_unix;
    esp_err_t transition_result;
    char target_leaf_sha256[65];
    char running_leaf_sha256[65];
} tls_activation_outcome_record_t;

typedef struct {
    uint32_t version;
    bool in_progress;
    bool recovered_interrupted;
    uint32_t attempt_count;
    int64_t started_unix;
    int64_t retry_not_before_unix;
    char target_leaf_sha256[65];
} tls_handoff_record_t;

typedef enum {
    ACME_RENEWAL_SCHEDULER_NOT_EVALUATED = 0,
    ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE,
    ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE,
    ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE,
    ACME_RENEWAL_SCHEDULER_VALID,
    ACME_RENEWAL_SCHEDULER_DUE,
    ACME_RENEWAL_SCHEDULER_URGENT,
    ACME_RENEWAL_SCHEDULER_EXPIRED,
} acme_renewal_scheduler_state_t;

typedef struct {
    bool task_started;
    bool evaluated;
    uint32_t evaluation_count;
    int64_t last_evaluation_unix;
    int64_t seconds_remaining;
    int64_t days_remaining;
    acme_renewal_scheduler_state_t state;
    bool automatic_renewal_enabled;
    bool eligible;
    bool execution_preflight_ready;
    bool attempt_in_progress;
    uint32_t attempt_count;
    int64_t last_attempt_unix;
    int64_t retry_not_before_unix;
    bool last_attempt_result_valid;
    esp_err_t last_attempt_result;
    acme_production_transaction_stage_t last_transaction_stage;
    bool last_transaction_completed;
    bool last_dns01_prepared;
    bool last_cleanup_attempted;
    esp_err_t last_cleanup_result;
    bool attempt_state_loaded;
    bool recovered_interrupted_attempt;
    bool tls_activation_preflight_evaluated;
    bool tls_activation_preflight_ready;
    bool tls_candidate_valid;
    bool tls_candidate_hostname_match;
    bool tls_candidate_time_valid;
    bool tls_candidate_fingerprint_changed;
    bool tls_activation_in_progress;
    char tls_candidate_leaf_sha256[65];
    char tls_current_leaf_sha256[65];
    char tls_activation_preflight_result[40];
    bool tls_activation_intent_state_loaded;
    bool tls_activation_intent_pending;
    bool tls_activation_boot_reconciled;
    int64_t tls_activation_intent_created_unix;
    char tls_activation_intent_previous_leaf_sha256[65];
    char tls_activation_intent_target_leaf_sha256[65];
    char tls_activation_reconciliation_result[40];
    bool tls_activation_outcome_state_loaded;
    bool tls_activation_last_result_valid;
    bool tls_activation_last_success;
    bool tls_activation_last_lkg_restored;
    int64_t tls_activation_last_completed_unix;
    esp_err_t tls_activation_last_transition_result;
    char tls_activation_last_target_leaf_sha256[65];
    char tls_activation_last_running_leaf_sha256[65];
    bool tls_handoff_state_loaded;
    bool tls_handoff_in_progress;
    bool tls_handoff_recovered_interrupted;
    uint32_t tls_handoff_attempt_count;
    int64_t tls_handoff_started_unix;
    int64_t tls_handoff_retry_not_before_unix;
    char tls_handoff_target_leaf_sha256[65];
} acme_renewal_scheduler_status_t;

static portMUX_TYPE s_renewal_scheduler_lock = portMUX_INITIALIZER_UNLOCKED;
static acme_renewal_scheduler_status_t s_renewal_scheduler_status;
static TaskHandle_t s_renewal_scheduler_task;

static esp_err_t start_https_server(web_tls_source_t source);
static void delayed_reboot_task(void *arg);
static esp_err_t start_https_server_with_credentials(web_tls_source_t source,
                                                     acme_tls_credentials_t *credentials,
                                                     const char *known_leaf_sha256);
static bool tls_transition_try_claim(void);
static void format_dns_list(uint32_t a, uint32_t b, char *out, size_t out_size);
static void tls_transition_release(void);
static void tls_transition_task(void *arg);
static bool hostname_in_zone(const char *hostname, const char *zone);
static esp_err_t tls_activation_intent_load_and_reconcile(void);
static esp_err_t tls_activation_intent_begin(const char *previous_leaf_sha256, int64_t now);
static esp_err_t tls_activation_intent_set_target(const char *target_leaf_sha256);
static esp_err_t tls_activation_intent_clear(bool boot_reconciled);
static esp_err_t tls_activation_schedule_pending_target(void);
static void tls_activation_converge_existing_production(void);
static esp_err_t receive_request_body(httpd_req_t *request, char *body, size_t body_size);
static esp_err_t tls_activation_outcome_load(void);
static esp_err_t tls_activation_outcome_store(bool success, bool lkg_restored, esp_err_t transition_result,
                                              const char *target_leaf_sha256,
                                              const char *running_leaf_sha256);
static esp_err_t tls_handoff_load_and_reconcile(void);
static esp_err_t tls_handoff_begin(const char *target_leaf_sha256, int64_t now);
static esp_err_t tls_handoff_finish(bool success, int64_t now);

static const char *tls_source_name(web_tls_source_t source)
{
    switch (source) {
    case WEB_TLS_STORED_TEST: return "stored_staging_test";
    case WEB_TLS_PRODUCTION: return "stored_production";
    default: return "embedded_development";
    }
}

/* The bootstrap credential (WEB_TLS_EMBEDDED) is generated per board; see
 * acme_client_load_bootstrap_tls_credentials(). It is loaded once and kept
 * for the life of the process, because the HTTPS server references it. */
static acme_tls_credentials_t s_bootstrap_credentials;

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
        return "ADD_SECOND";

    case APP_LEAP_DELETE_SECOND:
        return "DELETE_SECOND";

    case APP_LEAP_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static bool clock_is_servable(app_clock_state_t state,
                              bool solution_valid)
{
    return solution_valid &&
           (state == APP_CLOCK_SYNCHRONIZED ||
            state == APP_CLOCK_HOLDOVER);
}

static bool get_current_unix_time(int64_t *out_unix_time)
{
    if (out_unix_time == NULL) {
        return false;
    }

    clock_ntp_timestamp_t ntp_time;
    clock_discipline_status_t clock_status;

    if (clock_discipline_get_status(&clock_status) && clock_status.solution_valid &&
        clock_status.state == APP_CLOCK_SYNCHRONIZED &&
        clock_discipline_get_ntp_timestamp(&ntp_time) &&
        ntp_time.seconds >= APP_NTP_EPOCH_DELTA) {
        *out_unix_time =
            (int64_t)ntp_time.seconds -
            (int64_t)APP_NTP_EPOCH_DELTA;
        return true;
    }

    /* Certificate/ACME lifecycle may use the management civil-time fallback.
     * commissioning_sync_management_time() is the only path that admits
     * External NTP into this wall clock, and it never feeds clock_discipline. */
    commissioning_time_status_t management_time;
    commissioning_get_time_status(&management_time);
    if (!management_time.management_time_valid || management_time.unix_time < 1577836800LL) {
        return false;
    }
    *out_unix_time = management_time.unix_time;
    return true;
}

static bool parse_utc_timestamp(const char *text, int64_t *out_unix)
{
    if (text == NULL || out_unix == NULL) return false;
    int y, mo, d, h, mi, sec;
    char tail = '\0';
    if (sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2dZ%c", &y, &mo, &d, &h, &mi, &sec, &tail) != 6)
        return false;
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 ||
        mi < 0 || mi > 59 || sec < 0 || sec > 60) return false;

    /* Howard Hinnant's civil-date transform, adapted to integer UTC seconds. */
    y -= mo <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned mp = (unsigned)(mo + (mo > 2 ? -3 : 9));
    const unsigned doy = (153U * mp + 2U) / 5U + (unsigned)d - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    const int64_t days = (int64_t)era * 146097LL + (int64_t)doe - 719468LL;
    *out_unix = days * 86400LL + (int64_t)h * 3600LL + (int64_t)mi * 60LL + sec;
    return true;
}

static void evaluate_tls_activation_preflight(acme_renewal_scheduler_status_t *status,
                                              const acme_certificate_inspection_t *certificate)
{
    if (status == NULL) return;

    status->tls_activation_preflight_evaluated = true;
    status->tls_activation_in_progress = s_tls_transition_pending;
    snprintf(status->tls_activation_preflight_result,
             sizeof(status->tls_activation_preflight_result), "not_ready");

    if (certificate == NULL || !certificate->certificate_parse_valid ||
        !certificate->private_key_matches_certificate) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "invalid_candidate");
        return;
    }

    status->tls_candidate_valid = true;
    status->tls_candidate_hostname_match = certificate->hostname_matches_certificate;
    snprintf(status->tls_candidate_leaf_sha256, sizeof(status->tls_candidate_leaf_sha256),
             "%s", certificate->leaf_sha256);
    snprintf(status->tls_current_leaf_sha256, sizeof(status->tls_current_leaf_sha256),
             "%s", s_active_server_leaf_sha256);

    int64_t now = 0, valid_from = 0, valid_to = 0;
    status->tls_candidate_time_valid =
        get_current_unix_time(&now) &&
        parse_utc_timestamp(certificate->valid_from, &valid_from) &&
        parse_utc_timestamp(certificate->valid_to, &valid_to) &&
        now >= valid_from && now < valid_to;

    status->tls_candidate_fingerprint_changed =
        s_active_server_leaf_sha256[0] != '\0' &&
        certificate->leaf_sha256[0] != '\0' &&
        strcmp(s_active_server_leaf_sha256, certificate->leaf_sha256) != 0;

    if (!status->tls_candidate_hostname_match) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "hostname_mismatch");
    } else if (!status->tls_candidate_time_valid) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "time_invalid");
    } else if (s_active_server_leaf_sha256[0] == '\0') {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "current_fingerprint_unavailable");
    } else if (!status->tls_candidate_fingerprint_changed) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "candidate_not_changed");
    } else if (status->tls_activation_in_progress) {
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "activation_in_progress");
    } else {
        status->tls_activation_preflight_ready = true;
        snprintf(status->tls_activation_preflight_result,
                 sizeof(status->tls_activation_preflight_result), "ready");
    }
}

static const char *renewal_scheduler_state_name(acme_renewal_scheduler_state_t state)
{
    switch (state) {
    case ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE: return "no_certificate";
    case ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE: return "time_unavailable";
    case ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE: return "invalid_certificate";
    case ACME_RENEWAL_SCHEDULER_VALID: return "valid";
    case ACME_RENEWAL_SCHEDULER_DUE: return "renewal_due";
    case ACME_RENEWAL_SCHEDULER_URGENT: return "urgent";
    case ACME_RENEWAL_SCHEDULER_EXPIRED: return "expired";
    default: return "not_evaluated";
    }
}


static const char *renewal_transaction_stage_to_string(acme_production_transaction_stage_t stage)
{
    switch (stage) {
        case ACME_PRODUCTION_TRANSACTION_STAGE_NONE: return "none";
        case ACME_PRODUCTION_TRANSACTION_STAGE_ACCOUNT: return "account";
        case ACME_PRODUCTION_TRANSACTION_STAGE_ORDER: return "order";
        case ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_PREPARE: return "dns01_prepare";
        case ACME_PRODUCTION_TRANSACTION_STAGE_CHALLENGE: return "challenge";
        case ACME_PRODUCTION_TRANSACTION_STAGE_FINALIZE: return "finalize";
        case ACME_PRODUCTION_TRANSACTION_STAGE_DNS01_CLEANUP: return "dns01_cleanup";
        case ACME_PRODUCTION_TRANSACTION_STAGE_COMPLETE: return "complete";
        default: return "unknown";
    }
}

typedef struct {
    device_config_cloudflare_credentials_t credentials;
    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    bool record_created;
} renewal_dns01_context_t;

static esp_err_t renewal_dns01_prepare(const acme_order_discovery_t *order, void *context)
{
    if (order == NULL || context == NULL) return ESP_ERR_INVALID_ARG;
    renewal_dns01_context_t *dns = (renewal_dns01_context_t *)context;
    int create_http_status = 0;
    int verify_http_status = 0;

    esp_err_t err = cloudflare_client_create_dns01_txt(
        dns->credentials.api_token, dns->credentials.zone_id,
        order->dns01_record_name, order->dns01_value,
        dns->record_id, sizeof(dns->record_id), &create_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 create failed: %s http=%d",
                 esp_err_to_name(err), create_http_status);
        return err;
    }
    dns->record_created = true;

    err = cloudflare_client_verify_dns01_txt_content(
        dns->credentials.api_token, dns->credentials.zone_id,
        dns->record_id, order->dns01_record_name, order->dns01_value,
        &verify_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 exact-content verify failed: %s http=%d",
                 esp_err_to_name(err), verify_http_status);

        /* The transaction core only invokes cleanup after a successful prepare.
         * Therefore a partial prepare must remove its own record before failing. */
        int delete_http_status = 0;
        const esp_err_t delete_err = cloudflare_client_delete_dns01_txt_content(
            dns->credentials.api_token, dns->credentials.zone_id,
            dns->record_id, order->dns01_record_name, order->dns01_value, &delete_http_status);
        if (delete_err == ESP_OK) {
            dns->record_created = false;
            memset(dns->record_id, 0, sizeof(dns->record_id));
        } else {
            ESP_LOGE(TAG, "Automatic renewal partial DNS-01 cleanup failed: %s http=%d",
                     esp_err_to_name(delete_err), delete_http_status);
        }
        return err;
    }

    /* Preserve the already-validated Phase 5B DNS-01 propagation delay. */
    vTaskDelay(pdMS_TO_TICKS(10000));
    return ESP_OK;
}

static esp_err_t renewal_dns01_cleanup(const acme_order_discovery_t *order, void *context)
{
    if (order == NULL || context == NULL) return ESP_ERR_INVALID_ARG;
    renewal_dns01_context_t *dns = (renewal_dns01_context_t *)context;
    if (!dns->record_created) return ESP_OK;

    int delete_http_status = 0;
    const esp_err_t err = cloudflare_client_delete_dns01_txt_content(
        dns->credentials.api_token, dns->credentials.zone_id,
        dns->record_id, order->dns01_record_name, order->dns01_value, &delete_http_status);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal DNS-01 cleanup failed: %s http=%d",
                 esp_err_to_name(err), delete_http_status);
        return err;
    }

    dns->record_created = false;
    memset(dns->record_id, 0, sizeof(dns->record_id));
    return ESP_OK;
}

static esp_err_t renewal_scheduler_persist_attempt_state(bool attempt_was_in_progress)
{
    acme_renewal_attempt_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_RENEWAL_ATTEMPT_RECORD_VERSION;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    record.attempt_count = s_renewal_scheduler_status.attempt_count;
    record.last_attempt_unix = s_renewal_scheduler_status.last_attempt_unix;
    record.retry_not_before_unix = s_renewal_scheduler_status.retry_not_before_unix;
    record.attempt_was_in_progress = attempt_was_in_progress;
    record.last_attempt_result_valid = s_renewal_scheduler_status.last_attempt_result_valid;
    record.last_attempt_result = s_renewal_scheduler_status.last_attempt_result;
    record.last_transaction_stage = s_renewal_scheduler_status.last_transaction_stage;
    record.last_transaction_completed = s_renewal_scheduler_status.last_transaction_completed;
    record.last_dns01_prepared = s_renewal_scheduler_status.last_dns01_prepared;
    record.last_cleanup_attempted = s_renewal_scheduler_status.last_cleanup_attempted;
    record.last_cleanup_result = s_renewal_scheduler_status.last_cleanup_result;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    return acme_client_store_renewal_attempt_record(&record);
}

static esp_err_t renewal_scheduler_load_attempt_state(void)
{
    acme_renewal_attempt_record_t record;
    const esp_err_t err = acme_client_load_renewal_attempt_record(&record);
    if (err != ESP_OK) return err;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.attempt_count = record.attempt_count;
    s_renewal_scheduler_status.last_attempt_unix = record.last_attempt_unix;
    s_renewal_scheduler_status.retry_not_before_unix = record.retry_not_before_unix;
    s_renewal_scheduler_status.last_attempt_result_valid = record.last_attempt_result_valid;
    s_renewal_scheduler_status.last_attempt_result = record.last_attempt_result;
    s_renewal_scheduler_status.last_transaction_stage = record.last_transaction_stage;
    s_renewal_scheduler_status.last_transaction_completed = record.last_transaction_completed;
    s_renewal_scheduler_status.last_dns01_prepared = record.last_dns01_prepared;
    s_renewal_scheduler_status.last_cleanup_attempted = record.last_cleanup_attempted;
    s_renewal_scheduler_status.last_cleanup_result = record.last_cleanup_result;
    s_renewal_scheduler_status.attempt_in_progress = false;
    s_renewal_scheduler_status.attempt_state_loaded = true;
    s_renewal_scheduler_status.recovered_interrupted_attempt = record.attempt_was_in_progress;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    if (record.attempt_was_in_progress)
        ESP_LOGW(TAG, "Recovered interrupted automatic renewal attempt; persisted cooldown retained");
    return ESP_OK;
}

static void tls_activation_outcome_publish(const tls_activation_outcome_record_t *record)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_outcome_state_loaded = true;
    s_renewal_scheduler_status.tls_activation_last_result_valid = record->result_valid;
    s_renewal_scheduler_status.tls_activation_last_success = record->success;
    s_renewal_scheduler_status.tls_activation_last_lkg_restored = record->lkg_restored;
    s_renewal_scheduler_status.tls_activation_last_completed_unix = record->completed_unix;
    s_renewal_scheduler_status.tls_activation_last_transition_result = record->transition_result;
    snprintf(s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256), "%s",
             record->target_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256), "%s",
             record->running_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_activation_outcome_load(void)
{
    tls_activation_outcome_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        tls_activation_outcome_publish(&record);
        return ESP_OK;
    }
    if (err != ESP_OK) return err;

    size_t length = sizeof(record);
    err = nvs_get_blob(handle, APP_TLS_ACTIVATION_OUTCOME_KEY, &record, &length);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        memset(&record, 0, sizeof(record));
        record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;
        tls_activation_outcome_publish(&record);
        return ESP_OK;
    }
    if (err != ESP_OK) return err;
    if (length != sizeof(record) || record.version != APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION ||
        record.target_leaf_sha256[64] != '\0' || record.running_leaf_sha256[64] != '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    tls_activation_outcome_publish(&record);
    return ESP_OK;
}

static esp_err_t tls_activation_outcome_store(bool success, bool lkg_restored, esp_err_t transition_result,
                                              const char *target_leaf_sha256,
                                              const char *running_leaf_sha256)
{
    tls_activation_outcome_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = APP_TLS_ACTIVATION_OUTCOME_RECORD_VERSION;
    record.result_valid = true;
    record.success = success;
    record.lkg_restored = lkg_restored;
    record.transition_result = transition_result;
    (void)get_current_unix_time(&record.completed_unix);
    if (target_leaf_sha256 != NULL)
        snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    if (running_leaf_sha256 != NULL)
        snprintf(record.running_leaf_sha256, sizeof(record.running_leaf_sha256), "%s", running_leaf_sha256);

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, APP_TLS_ACTIVATION_OUTCOME_KEY, &record, sizeof(record));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) tls_activation_outcome_publish(&record);
    return err;
}

static void tls_handoff_publish(const tls_handoff_record_t *record)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_handoff_state_loaded = true;
    s_renewal_scheduler_status.tls_handoff_in_progress = record->in_progress;
    s_renewal_scheduler_status.tls_handoff_recovered_interrupted = record->recovered_interrupted;
    s_renewal_scheduler_status.tls_handoff_attempt_count = record->attempt_count;
    s_renewal_scheduler_status.tls_handoff_started_unix = record->started_unix;
    s_renewal_scheduler_status.tls_handoff_retry_not_before_unix = record->retry_not_before_unix;
    snprintf(s_renewal_scheduler_status.tls_handoff_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_handoff_target_leaf_sha256), "%s",
             record->target_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_handoff_write(const tls_handoff_record_t *record)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(handle, APP_TLS_HANDOFF_KEY, record, sizeof(*record));
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err == ESP_OK) tls_handoff_publish(record);
    return err;
}

static esp_err_t tls_handoff_read(tls_handoff_record_t *record)
{
    if (record == NULL) return ESP_ERR_INVALID_ARG;
    memset(record, 0, sizeof(*record));
    record->version = APP_TLS_HANDOFF_RECORD_VERSION;
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open_from_partition("nvs_certs", "acme", NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_OK;
    if (err != ESP_OK) return err;
    size_t length = sizeof(*record);
    err = nvs_get_blob(handle, APP_TLS_HANDOFF_KEY, record, &length);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        memset(record, 0, sizeof(*record));
        record->version = APP_TLS_HANDOFF_RECORD_VERSION;
        return ESP_OK;
    }
    if (err != ESP_OK) return err;
    if (length != sizeof(*record) || record->version != APP_TLS_HANDOFF_RECORD_VERSION ||
        record->target_leaf_sha256[64] != '\0') return ESP_ERR_INVALID_ARG;
    return ESP_OK;
}

static esp_err_t tls_handoff_load_and_reconcile(void)
{
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    if (record.in_progress) {
        int64_t now = 0;
        (void)get_current_unix_time(&now);
        record.in_progress = false;
        record.recovered_interrupted = true;
        if (now > 0 && record.retry_not_before_unix < now + APP_TLS_HANDOFF_RETRY_SECONDS)
            record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
        err = tls_handoff_write(&record);
        if (err != ESP_OK) return err;
        ESP_LOGW(TAG, "Recovered interrupted automatic TLS handoff; retry cooldown retained");
    } else {
        tls_handoff_publish(&record);
    }
    return ESP_OK;
}

static esp_err_t tls_handoff_begin(const char *target_leaf_sha256, int64_t now)
{
    if (target_leaf_sha256 == NULL || target_leaf_sha256[0] == '\0' || now <= 0)
        return ESP_ERR_INVALID_ARG;
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    if (record.in_progress) return ESP_ERR_INVALID_STATE;
    if (record.retry_not_before_unix > 0 && now < record.retry_not_before_unix)
        return ESP_ERR_TIMEOUT;
    record.version = APP_TLS_HANDOFF_RECORD_VERSION;
    record.in_progress = true;
    record.recovered_interrupted = false;
    record.attempt_count++;
    record.started_unix = now;
    record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
    snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    return tls_handoff_write(&record);
}

static esp_err_t tls_handoff_finish(bool success, int64_t now)
{
    tls_handoff_record_t record;
    esp_err_t err = tls_handoff_read(&record);
    if (err != ESP_OK) return err;
    record.in_progress = false;
    record.recovered_interrupted = false;
    if (success) {
        record.retry_not_before_unix = 0;
        record.target_leaf_sha256[0] = '\0';
    } else if (now > 0) {
        record.retry_not_before_unix = now + APP_TLS_HANDOFF_RETRY_SECONDS;
    }
    return tls_handoff_write(&record);
}

static void tls_activation_intent_publish(const acme_tls_activation_intent_record_t *record,
                                          const char *result)
{
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_intent_state_loaded = true;
    s_renewal_scheduler_status.tls_activation_intent_pending = record->pending;
    s_renewal_scheduler_status.tls_activation_boot_reconciled = record->boot_reconciled;
    s_renewal_scheduler_status.tls_activation_intent_created_unix = record->created_unix;
    snprintf(s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256),
             "%s", record->previous_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256,
             sizeof(s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256),
             "%s", record->target_leaf_sha256);
    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
             "%s", result != NULL ? result : "none");
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
}

static esp_err_t tls_activation_intent_clear(bool boot_reconciled)
{
    acme_tls_activation_intent_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_TLS_ACTIVATION_INTENT_RECORD_VERSION;
    record.boot_reconciled = boot_reconciled;
    esp_err_t err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK)
        tls_activation_intent_publish(&record, boot_reconciled ? "resolved_on_boot" : "cleared_no_replacement");
    return err;
}

static esp_err_t tls_activation_intent_begin(const char *previous_leaf_sha256, int64_t now)
{
    if (previous_leaf_sha256 == NULL || previous_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_ARG;
    acme_tls_activation_intent_record_t record;
    memset(&record, 0, sizeof(record));
    record.version = ACME_TLS_ACTIVATION_INTENT_RECORD_VERSION;
    record.pending = true;
    record.created_unix = now;
    snprintf(record.previous_leaf_sha256, sizeof(record.previous_leaf_sha256), "%s", previous_leaf_sha256);
    esp_err_t err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK) tls_activation_intent_publish(&record, "pending_target_unknown");
    return err;
}

static esp_err_t tls_activation_intent_set_target(const char *target_leaf_sha256)
{
    if (target_leaf_sha256 == NULL || target_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_ARG;
    acme_tls_activation_intent_record_t record;
    esp_err_t err = acme_client_load_tls_activation_intent(&record);
    if (err != ESP_OK) return err;
    if (!record.pending) return ESP_ERR_INVALID_STATE;
    snprintf(record.target_leaf_sha256, sizeof(record.target_leaf_sha256), "%s", target_leaf_sha256);
    err = acme_client_store_tls_activation_intent(&record);
    if (err == ESP_OK) tls_activation_intent_publish(&record, "pending_runtime_handoff");
    return err;
}

static esp_err_t tls_activation_intent_load_and_reconcile(void)
{
    acme_tls_activation_intent_record_t record;
    esp_err_t err = acme_client_load_tls_activation_intent(&record);
    if (err != ESP_OK) return err;

    if (!record.pending) {
        tls_activation_intent_publish(&record, record.boot_reconciled ? "resolved_on_boot" : "none");
        return ESP_OK;
    }

    if (s_tls_source == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] != '\0') {
        if (record.target_leaf_sha256[0] != '\0' &&
            strcmp(record.target_leaf_sha256, s_active_server_leaf_sha256) == 0) {
            return tls_activation_intent_clear(true);
        }
        if (record.target_leaf_sha256[0] == '\0' &&
            record.previous_leaf_sha256[0] != '\0' &&
            strcmp(record.previous_leaf_sha256, s_active_server_leaf_sha256) != 0) {
            /* Power loss after dual-slot selector commit but before target fingerprint
             * was persisted. The production boot path has already loaded the new,
             * validated selected credential, so reconcile the interrupted intent. */
            return tls_activation_intent_clear(true);
        }
        if (record.target_leaf_sha256[0] == '\0' &&
            record.previous_leaf_sha256[0] != '\0' &&
            strcmp(record.previous_leaf_sha256, s_active_server_leaf_sha256) == 0) {
            return tls_activation_intent_clear(false);
        }
    }

    tls_activation_intent_publish(&record, "pending_runtime_handoff");
    return ESP_OK;
}

/* Schedule a real production TLS handoff for a persisted, fully identified
 * production target. The embedded development credential may be replaced once
 * a valid production certificate exists; staging/test TLS is never overridden. */
static esp_err_t tls_activation_schedule_pending_target(void)
{
    acme_tls_activation_intent_record_t intent;
    esp_err_t err = acme_client_load_tls_activation_intent(&intent);
    if (err != ESP_OK) return err;
    if (!intent.pending || intent.target_leaf_sha256[0] == '\0') return ESP_ERR_INVALID_STATE;
    if (s_tls_source != WEB_TLS_PRODUCTION && s_tls_source != WEB_TLS_EMBEDDED)
        return ESP_ERR_INVALID_STATE;

    /* The embedded development credential intentionally has no entry in
     * s_active_server_leaf_sha256: that fingerprint is populated only for
     * stored production credentials.  Requiring it here made every automatic
     * embedded -> production handoff fail with ESP_ERR_INVALID_STATE, leaving
     * the self-signed development certificate active indefinitely. */
    if (s_tls_source == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] == '\0')
        return ESP_ERR_INVALID_STATE;

    acme_certificate_inspection_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    err = acme_client_inspect_stored_production_certificate(&candidate);
    if (err != ESP_OK || !candidate.certificate_parse_valid ||
        !candidate.private_key_matches_certificate ||
        !candidate.hostname_matches_certificate ||
        strcmp(candidate.leaf_sha256, intent.target_leaf_sha256) != 0) {
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }

    acme_renewal_scheduler_status_t preflight;
    memset(&preflight, 0, sizeof(preflight));
    if (s_tls_source == WEB_TLS_EMBEDDED) {
        int64_t now = 0, valid_from = 0, valid_to = 0;
        preflight.tls_activation_preflight_ready =
            candidate.hostname_matches_certificate &&
            get_current_unix_time(&now) &&
            parse_utc_timestamp(candidate.valid_from, &valid_from) &&
            parse_utc_timestamp(candidate.valid_to, &valid_to) &&
            now >= valid_from && now < valid_to;
    } else {
        evaluate_tls_activation_preflight(&preflight, &candidate);
    }
    if (!preflight.tls_activation_preflight_ready) return ESP_ERR_INVALID_STATE;

    int64_t handoff_now = 0;
    if (!get_current_unix_time(&handoff_now) || handoff_now <= 0) return ESP_ERR_INVALID_STATE;
    err = tls_handoff_begin(intent.target_leaf_sha256, handoff_now);
    if (err != ESP_OK) return err;

    if (!tls_transition_try_claim()) {
        (void)tls_handoff_finish(false, handoff_now);
        return ESP_ERR_INVALID_STATE;
    }
    s_tls_transition_automatic = true;
    if (xTaskCreate(tls_transition_task, "tls_auto", 8192U,
                    (void *)(uintptr_t)WEB_TLS_PRODUCTION, 5U, NULL) != pdPASS) {
        s_tls_transition_automatic = false;
        tls_transition_release();
        (void)tls_handoff_finish(false, handoff_now);
        return ESP_ERR_NO_MEM;
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.tls_activation_in_progress = true;
    s_renewal_scheduler_status.tls_activation_preflight_ready = false;
    snprintf(s_renewal_scheduler_status.tls_activation_preflight_result,
             sizeof(s_renewal_scheduler_status.tls_activation_preflight_result),
             "activation_scheduled");
    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
             "runtime_handoff_scheduled");
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    return ESP_OK;
}


static void tls_activation_converge_existing_production(void)
{
    /* A production certificate may already be present while management time is
     * still unavailable during early boot.  The one-shot scheduler startup
     * check therefore cannot be the only commissioning convergence point.
     * Re-evaluate at scheduler cadence and, once management civil time is valid,
     * persist an activation intent and hand HTTPS over to the production
     * credential without requesting a new certificate. */
    if (s_tls_source != WEB_TLS_EMBEDDED || s_tls_transition_pending) return;
    if (!management_ownership_is_provisioned()) return;  /* enrollment stays on the bootstrap certificate */

    acme_tls_activation_intent_record_t pending;
    if (acme_client_load_tls_activation_intent(&pending) == ESP_OK &&
        pending.pending && pending.target_leaf_sha256[0] != '\0') {
        const esp_err_t retry_err = tls_activation_schedule_pending_target();
        if (retry_err != ESP_OK && retry_err != ESP_ERR_INVALID_STATE)
            ESP_LOGW(TAG, "Existing production TLS handoff retry failed: %s",
                     esp_err_to_name(retry_err));
        return;
    }

    acme_certificate_inspection_t existing;
    memset(&existing, 0, sizeof(existing));
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&existing);
    if (inspect_err != ESP_OK || !existing.certificate_parse_valid ||
        !existing.hostname_matches_certificate || !existing.private_key_matches_certificate ||
        existing.leaf_sha256[0] == '\0') return;

    int64_t now = 0, valid_from = 0, valid_to = 0;
    if (!get_current_unix_time(&now) ||
        !parse_utc_timestamp(existing.valid_from, &valid_from) ||
        !parse_utc_timestamp(existing.valid_to, &valid_to) ||
        now < valid_from || now >= valid_to) return;

    esp_err_t err = tls_activation_intent_begin("embedded_development", now);
    if (err == ESP_OK) err = tls_activation_intent_set_target(existing.leaf_sha256);
    if (err == ESP_OK) err = tls_activation_schedule_pending_target();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Existing production certificate scheduled for automatic TLS activation after management-time convergence");
        (void)operations_history_record(OPERATIONS_EVENT_SECURITY, 0,
                                        "existing_production_certificate_tls_activation_scheduled");
    } else if (err != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "Existing production certificate TLS convergence deferred: %s",
                 esp_err_to_name(err));
    }
}

static void renewal_scheduler_execute_if_ready(void)
{
    acme_renewal_scheduler_status_t snapshot;
    int64_t now = 0;

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    snapshot = s_renewal_scheduler_status;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    if (!snapshot.execution_preflight_ready || !snapshot.eligible ||
        snapshot.attempt_in_progress) {
        return;
    }
    if (!get_current_unix_time(&now) || now <= 0) {
        ESP_LOGW(TAG, "Automatic renewal execution skipped: disciplined time unavailable");
        return;
    }

    /* Atomically consume the preflight gate and acquire the attempt lock. */
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    if (!s_renewal_scheduler_status.execution_preflight_ready ||
        s_renewal_scheduler_status.attempt_in_progress ||
        (s_renewal_scheduler_status.retry_not_before_unix > 0 &&
         now < s_renewal_scheduler_status.retry_not_before_unix)) {
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        return;
    }
    s_renewal_scheduler_status.attempt_in_progress = true;
    s_renewal_scheduler_status.execution_preflight_ready = false;
    s_renewal_scheduler_status.attempt_count++;
    s_renewal_scheduler_status.last_attempt_unix = now;
    s_renewal_scheduler_status.retry_not_before_unix =
        now + APP_ACME_RENEWAL_ATTEMPT_COOLDOWN_SECONDS;
    s_renewal_scheduler_status.last_attempt_result_valid = false;
    s_renewal_scheduler_status.last_attempt_result = ESP_OK;
    s_renewal_scheduler_status.last_transaction_stage = ACME_PRODUCTION_TRANSACTION_STAGE_NONE;
    s_renewal_scheduler_status.last_transaction_completed = false;
    s_renewal_scheduler_status.last_dns01_prepared = false;
    s_renewal_scheduler_status.last_cleanup_attempted = false;
    s_renewal_scheduler_status.last_cleanup_result = ESP_OK;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    esp_err_t persist_err = renewal_scheduler_persist_attempt_state(true);
    if (persist_err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal attempt-state commit failed: %s; refusing ACME execution",
                 esp_err_to_name(persist_err));
        portENTER_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_status.attempt_in_progress = false;
        s_renewal_scheduler_status.execution_preflight_ready = false;
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        return;
    }

    esp_err_t result = ESP_FAIL;
    acme_production_transaction_status_t transaction;
    memset(&transaction, 0, sizeof(transaction));
    acme_certificate_inspection_t certificate;
    memset(&certificate, 0, sizeof(certificate));

    result = acme_client_inspect_stored_production_certificate(&certificate);
    if (result != ESP_OK || !certificate.certificate_parse_valid ||
        !certificate.hostname_matches_certificate ||
        !certificate.private_key_matches_certificate ||
        certificate.hostname[0] == '\0') {
        ESP_LOGE(TAG, "Automatic renewal aborted: production credential inspection failed: %s",
                 esp_err_to_name(result));
        if (result == ESP_OK) result = ESP_ERR_INVALID_STATE;
        goto complete;
    }

    device_config_snapshot_t config;
    result = device_config_get_snapshot(&config);
    if (result != ESP_OK || !config.cloudflare_configured ||
        !hostname_in_zone(certificate.hostname, config.cloudflare_zone_name)) {
        ESP_LOGE(TAG, "Automatic renewal aborted: Cloudflare configuration/zone preflight failed");
        if (result == ESP_OK) result = ESP_ERR_INVALID_STATE;
        goto complete;
    }

    renewal_dns01_context_t dns;
    memset(&dns, 0, sizeof(dns));
    result = device_config_get_cloudflare_credentials(&dns.credentials);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal aborted: Cloudflare credentials unavailable: %s",
                 esp_err_to_name(result));
        goto clear_dns_context;
    }

    acme_production_dns01_hooks_t hooks = {
        .prepare_dns01 = renewal_dns01_prepare,
        .cleanup_dns01 = renewal_dns01_cleanup,
        .context = &dns,
    };

    /* Persist activation intent immediately before the transaction can replace
     * the selected production slot. No TLS transition is scheduled in 5B.10f.3c. */
    result = tls_activation_intent_begin(certificate.leaf_sha256, now);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal aborted: TLS activation intent commit failed: %s",
                 esp_err_to_name(result));
        goto clear_dns_context;
    }

    ESP_LOGI(TAG, "Automatic production renewal attempt starting for %s; TLS activation disabled",
             certificate.hostname);
    result = acme_client_run_production_certificate_transaction(
        certificate.hostname, &hooks, &transaction);

    if (transaction.certificate.stored) {
        acme_certificate_inspection_t replacement;
        memset(&replacement, 0, sizeof(replacement));
        const esp_err_t inspect_replacement =
            acme_client_inspect_stored_production_certificate(&replacement);
        if (inspect_replacement == ESP_OK && replacement.certificate_parse_valid &&
            replacement.private_key_matches_certificate && replacement.leaf_sha256[0] != '\0') {
            const esp_err_t intent_err = tls_activation_intent_set_target(replacement.leaf_sha256);
            if (intent_err != ESP_OK) {
                ESP_LOGE(TAG, "Replacement stored but TLS activation target persistence failed: %s",
                         esp_err_to_name(intent_err));
            } else {
                const esp_err_t activation_err = tls_activation_schedule_pending_target();
                if (activation_err != ESP_OK) {
                    ESP_LOGE(TAG, "Replacement stored but automatic TLS handoff was not scheduled: %s",
                             esp_err_to_name(activation_err));
                } else {
                    ESP_LOGI(TAG, "Automatic production TLS handoff scheduled for replacement %s",
                             replacement.leaf_sha256);
                }
            }
        } else {
            ESP_LOGE(TAG, "Replacement stored but TLS activation target inspection failed: %s",
                     esp_err_to_name(inspect_replacement));
        }
    } else {
        const esp_err_t intent_err = tls_activation_intent_clear(false);
        if (intent_err != ESP_OK)
            ESP_LOGE(TAG, "TLS activation intent cleanup after non-replacement failed: %s",
                     esp_err_to_name(intent_err));
    }

    ESP_LOGI(TAG,
             "Automatic production renewal attempt finished: result=%s completed=%d "
             "dns_prepared=%d cleanup_attempted=%d cleanup_result=%s "
             "automatic_tls_activation=true",
             esp_err_to_name(result), transaction.completed,
             transaction.dns01_prepared, transaction.cleanup_attempted,
             esp_err_to_name(transaction.cleanup_result));

clear_dns_context:
    memset(dns.credentials.api_token, 0, sizeof(dns.credentials.api_token));
    memset(&dns, 0, sizeof(dns));

complete:
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.attempt_in_progress = false;
    s_renewal_scheduler_status.execution_preflight_ready = false;
    s_renewal_scheduler_status.last_attempt_result_valid = true;
    s_renewal_scheduler_status.last_attempt_result = result;
    s_renewal_scheduler_status.last_transaction_stage = transaction.stage;
    s_renewal_scheduler_status.last_transaction_completed = transaction.completed;
    s_renewal_scheduler_status.last_dns01_prepared = transaction.dns01_prepared;
    s_renewal_scheduler_status.last_cleanup_attempted = transaction.cleanup_attempted;
    s_renewal_scheduler_status.last_cleanup_result = transaction.cleanup_result;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    persist_err = renewal_scheduler_persist_attempt_state(false);
    if (persist_err != ESP_OK)
        ESP_LOGE(TAG, "Automatic renewal final attempt-state commit failed: %s", esp_err_to_name(persist_err));

    if (result != ESP_OK) {
        ESP_LOGE(TAG, "Automatic production renewal attempt failed: %s; cooldown remains armed",
                 esp_err_to_name(result));
    }
}

static void renewal_scheduler_evaluate(void)
{
    acme_renewal_scheduler_status_t next = {0};
    acme_certificate_inspection_t certificate;
    int64_t now = 0;
    int64_t expires = 0;

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    next.task_started = s_renewal_scheduler_status.task_started;
    next.evaluation_count = s_renewal_scheduler_status.evaluation_count + 1U;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    next.evaluated = true;

    const esp_err_t inspect_err =
        acme_client_inspect_stored_production_certificate(&certificate);
    if (inspect_err == ESP_ERR_NOT_FOUND) {
        next.state = ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE;
    } else if (inspect_err != ESP_OK && inspect_err != ESP_ERR_INVALID_STATE) {
        next.state = ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE;
    } else if (!certificate.certificate_parse_valid ||
               !certificate.hostname_matches_certificate ||
               !certificate.private_key_matches_certificate ||
               !parse_utc_timestamp(certificate.valid_to, &expires)) {
        next.state = ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE;
    } else if (!get_current_unix_time(&now)) {
        next.state = ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE;
    } else {
        next.last_evaluation_unix = now;
        next.seconds_remaining = expires - now;
        next.days_remaining = next.seconds_remaining >= 0
                                  ? next.seconds_remaining / 86400LL
                                  : -((-next.seconds_remaining + 86399LL) / 86400LL);
        if (next.seconds_remaining <= 0) {
            next.state = ACME_RENEWAL_SCHEDULER_EXPIRED;
        } else if (next.seconds_remaining <= 7LL * 86400LL) {
            next.state = ACME_RENEWAL_SCHEDULER_URGENT;
        } else if (next.seconds_remaining <= 30LL * 86400LL) {
            next.state = ACME_RENEWAL_SCHEDULER_DUE;
        } else {
            next.state = ACME_RENEWAL_SCHEDULER_VALID;
        }
    }

    bool automatic_enabled = false;
    const esp_err_t policy_err = acme_client_get_automatic_renewal_enabled(&automatic_enabled);
    if (policy_err != ESP_OK) {
        ESP_LOGE(TAG, "ACME renewal policy read failed: %s; forcing disabled", esp_err_to_name(policy_err));
        automatic_enabled = false;
    }
    next.automatic_renewal_enabled = automatic_enabled;
    next.eligible = automatic_enabled &&
                    (next.state == ACME_RENEWAL_SCHEDULER_DUE ||
                     next.state == ACME_RENEWAL_SCHEDULER_URGENT ||
                     next.state == ACME_RENEWAL_SCHEDULER_EXPIRED);

    /* Preserve execution accounting across evaluations. A genuine due/urgent/
     * expired evaluation may be consumed by the scheduler task after this
     * state is published. */
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    next.attempt_in_progress = s_renewal_scheduler_status.attempt_in_progress;
    next.attempt_count = s_renewal_scheduler_status.attempt_count;
    next.last_attempt_unix = s_renewal_scheduler_status.last_attempt_unix;
    next.retry_not_before_unix = s_renewal_scheduler_status.retry_not_before_unix;
    next.last_attempt_result_valid = s_renewal_scheduler_status.last_attempt_result_valid;
    next.last_attempt_result = s_renewal_scheduler_status.last_attempt_result;
    next.last_transaction_stage = s_renewal_scheduler_status.last_transaction_stage;
    next.last_transaction_completed = s_renewal_scheduler_status.last_transaction_completed;
    next.last_dns01_prepared = s_renewal_scheduler_status.last_dns01_prepared;
    next.last_cleanup_attempted = s_renewal_scheduler_status.last_cleanup_attempted;
    next.last_cleanup_result = s_renewal_scheduler_status.last_cleanup_result;
    next.attempt_state_loaded = s_renewal_scheduler_status.attempt_state_loaded;
    next.recovered_interrupted_attempt = s_renewal_scheduler_status.recovered_interrupted_attempt;
    next.tls_activation_intent_state_loaded = s_renewal_scheduler_status.tls_activation_intent_state_loaded;
    next.tls_activation_intent_pending = s_renewal_scheduler_status.tls_activation_intent_pending;
    next.tls_activation_boot_reconciled = s_renewal_scheduler_status.tls_activation_boot_reconciled;
    next.tls_activation_intent_created_unix = s_renewal_scheduler_status.tls_activation_intent_created_unix;
    snprintf(next.tls_activation_intent_previous_leaf_sha256,
             sizeof(next.tls_activation_intent_previous_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_intent_previous_leaf_sha256);
    snprintf(next.tls_activation_intent_target_leaf_sha256,
             sizeof(next.tls_activation_intent_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_intent_target_leaf_sha256);
    snprintf(next.tls_activation_reconciliation_result,
             sizeof(next.tls_activation_reconciliation_result), "%s",
             s_renewal_scheduler_status.tls_activation_reconciliation_result);

    /* 5B.10g.1.1: protected automatic TLS activation outcome state is loaded
     * before the scheduler task starts. Preserve it across each freshly built
     * evaluation snapshot just like attempt and activation-intent state. */
    next.tls_activation_outcome_state_loaded =
        s_renewal_scheduler_status.tls_activation_outcome_state_loaded;
    next.tls_activation_last_result_valid =
        s_renewal_scheduler_status.tls_activation_last_result_valid;
    next.tls_activation_last_success =
        s_renewal_scheduler_status.tls_activation_last_success;
    next.tls_activation_last_lkg_restored =
        s_renewal_scheduler_status.tls_activation_last_lkg_restored;
    next.tls_activation_last_completed_unix =
        s_renewal_scheduler_status.tls_activation_last_completed_unix;
    next.tls_activation_last_transition_result =
        s_renewal_scheduler_status.tls_activation_last_transition_result;
    snprintf(next.tls_activation_last_target_leaf_sha256,
             sizeof(next.tls_activation_last_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_last_target_leaf_sha256);
    snprintf(next.tls_activation_last_running_leaf_sha256,
             sizeof(next.tls_activation_last_running_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_activation_last_running_leaf_sha256);
    next.tls_handoff_state_loaded = s_renewal_scheduler_status.tls_handoff_state_loaded;
    next.tls_handoff_in_progress = s_renewal_scheduler_status.tls_handoff_in_progress;
    next.tls_handoff_recovered_interrupted = s_renewal_scheduler_status.tls_handoff_recovered_interrupted;
    next.tls_handoff_attempt_count = s_renewal_scheduler_status.tls_handoff_attempt_count;
    next.tls_handoff_started_unix = s_renewal_scheduler_status.tls_handoff_started_unix;
    next.tls_handoff_retry_not_before_unix = s_renewal_scheduler_status.tls_handoff_retry_not_before_unix;
    snprintf(next.tls_handoff_target_leaf_sha256, sizeof(next.tls_handoff_target_leaf_sha256), "%s",
             s_renewal_scheduler_status.tls_handoff_target_leaf_sha256);
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
    const bool cooldown_clear = next.last_attempt_unix == 0 || now <= 0 ||
                                now >= next.retry_not_before_unix;
    next.execution_preflight_ready = next.eligible && !next.attempt_in_progress && cooldown_clear;

    /* 5B.10f.1: observe whether the stored production credential would be a
     * safe, distinct TLS handoff candidate. This is deliberately non-activating. */
    if (inspect_err == ESP_OK || inspect_err == ESP_ERR_INVALID_STATE) {
        evaluate_tls_activation_preflight(&next, &certificate);
    } else {
        evaluate_tls_activation_preflight(&next, NULL);
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status = next;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    ESP_LOGI(TAG, "ACME renewal scheduler evaluation: state=%s days_remaining=%" PRId64
                  " enabled=%d eligible=%d automatic_execution=%d",
             renewal_scheduler_state_name(next.state), next.days_remaining,
             next.automatic_renewal_enabled, next.eligible,
             next.execution_preflight_ready);
}

_Static_assert((uint64_t)APP_ACME_RENEWAL_CHECK_INTERVAL_SECONDS * configTICK_RATE_HZ <= UINT32_MAX,
               "renewal check interval does not fit in TickType_t");

static void renewal_scheduler_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(APP_ACME_RENEWAL_INITIAL_DELAY_MS));
    for (;;) {
        renewal_scheduler_evaluate();
        renewal_scheduler_execute_if_ready();

        /* Converge an already-issued production credential after management
         * time becomes valid, and retry any persisted handoff intent. */
        tls_activation_converge_existing_production();
        vTaskDelay((TickType_t)APP_ACME_RENEWAL_CHECK_INTERVAL_SECONDS * configTICK_RATE_HZ);
    }
}

static esp_err_t start_renewal_scheduler(void)
{
    if (s_renewal_scheduler_task != NULL) return ESP_OK;

    const esp_err_t intent_err = tls_activation_intent_load_and_reconcile();
    if (intent_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS activation intent load/reconciliation failed: %s", esp_err_to_name(intent_err));
        return intent_err;
    }

    const esp_err_t outcome_err = tls_activation_outcome_load();
    if (outcome_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS activation outcome-state load failed: %s", esp_err_to_name(outcome_err));
        return outcome_err;
    }

    const esp_err_t handoff_err = tls_handoff_load_and_reconcile();
    if (handoff_err != ESP_OK) {
        ESP_LOGE(TAG, "TLS handoff-state load/reconciliation failed: %s", esp_err_to_name(handoff_err));
        return handoff_err;
    }

    const esp_err_t load_err = renewal_scheduler_load_attempt_state();
    if (load_err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal persisted attempt-state load failed: %s", esp_err_to_name(load_err));
        return load_err;
    }

    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    s_renewal_scheduler_status.task_started = true;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    BaseType_t created = xTaskCreate(renewal_scheduler_task,
                                     "acme_renewal",
                                     APP_ACME_RENEWAL_TASK_STACK_SIZE,
                                     NULL,
                                     APP_ACME_RENEWAL_TASK_PRIORITY,
                                     &s_renewal_scheduler_task);
    if (created != pdPASS) {
        portENTER_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_status.task_started = false;
        portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        s_renewal_scheduler_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    /* Commissioning handoff: a board that already has a valid production
     * certificate but is still serving the embedded development credential
     * should converge to production TLS without requiring another issuance. */
    if (s_tls_source == WEB_TLS_EMBEDDED) {
        acme_certificate_inspection_t existing;
        int64_t now = 0;
        memset(&existing, 0, sizeof(existing));
        if (acme_client_inspect_stored_production_certificate(&existing) == ESP_OK &&
            existing.certificate_parse_valid && existing.hostname_matches_certificate &&
            existing.private_key_matches_certificate && existing.leaf_sha256[0] != '\0' &&
            get_current_unix_time(&now) &&
            tls_activation_intent_begin("embedded_development", now) == ESP_OK &&
            tls_activation_intent_set_target(existing.leaf_sha256) == ESP_OK) {
            const esp_err_t activate_err = tls_activation_schedule_pending_target();
            if (activate_err == ESP_OK)
                ESP_LOGI(TAG, "Existing production certificate scheduled for automatic commissioning TLS activation");
            else
                ESP_LOGW(TAG, "Existing production certificate activation deferred: %s", esp_err_to_name(activate_err));
        }
    }
    return ESP_OK;
}

static void set_security_headers(httpd_req_t *request);

/* All handlers run in the single httpd task, so a body read that retries a
 * silent client forever freezes the whole console (and, for OTA, leaves the
 * update flagged in progress). Allow a few consecutive receive timeouts
 * (httpd's socket timeout is a few seconds each), then fail the read so the
 * caller's existing error path cleans up. */
#define WEB_RECV_MAX_CONSECUTIVE_TIMEOUTS 3

static int web_req_recv_bounded(httpd_req_t *request, char *buffer, size_t length)
{
    for (unsigned timeouts = 0U;; ++timeouts) {
        const int r = httpd_req_recv(request, buffer, length);
        if (r != HTTPD_SOCK_ERR_TIMEOUT) return r;
        if (timeouts + 1U >= WEB_RECV_MAX_CONSECUTIVE_TIMEOUTS) return HTTPD_SOCK_ERR_FAIL;
    }
}

static const char *renewal_eligibility_reason(const acme_renewal_scheduler_status_t *status)
{
    if (!status->automatic_renewal_enabled) return "disabled";
    if (!status->evaluated) return "not_evaluated";
    switch (status->state) {
    case ACME_RENEWAL_SCHEDULER_DUE: return "renewal_window";
    case ACME_RENEWAL_SCHEDULER_URGENT: return "urgent_window";
    case ACME_RENEWAL_SCHEDULER_EXPIRED: return "expired";
    case ACME_RENEWAL_SCHEDULER_TIME_UNAVAILABLE: return "time_unavailable";
    case ACME_RENEWAL_SCHEDULER_NO_CERTIFICATE: return "no_certificate";
    case ACME_RENEWAL_SCHEDULER_INVALID_CERTIFICATE: return "invalid_certificate";
    default: return "not_due";
    }
}

static esp_err_t acme_production_renewal_scheduler_handler(httpd_req_t *request)
{
    acme_renewal_scheduler_status_t status;
    portENTER_CRITICAL(&s_renewal_scheduler_lock);
    status = s_renewal_scheduler_status;
    portEXIT_CRITICAL(&s_renewal_scheduler_lock);

    /* Refresh the persisted switch for immediate management visibility without
     * changing the most recent certificate evaluation result. */
    bool persisted_enabled = false;
    if (acme_client_get_automatic_renewal_enabled(&persisted_enabled) == ESP_OK) {
        status.automatic_renewal_enabled = persisted_enabled;
        status.eligible = persisted_enabled && status.evaluated &&
            (status.state == ACME_RENEWAL_SCHEDULER_DUE ||
             status.state == ACME_RENEWAL_SCHEDULER_URGENT ||
             status.state == ACME_RENEWAL_SCHEDULER_EXPIRED);
    } else {
        status.automatic_renewal_enabled = false;
        status.eligible = false;
    }

    const int64_t next_check = status.last_evaluation_unix > 0
                                 ? status.last_evaluation_unix + (int64_t)APP_ACME_RENEWAL_CHECK_INTERVAL_SECONDS : 0LL;
    char response[3072];
    const int length = snprintf(response, sizeof(response),
        "{\"enabled\":true,\"mode\":\"automatic_execution\","
        "\"automatic_renewal_enabled\":%s,\"automatic_certificate_replacement\":true,"
        "\"automatic_tls_activation\":true,\"automatic_acme_execution\":true,"
        "\"eligible\":%s,\"eligibility_reason\":\"%s\","
        "\"execution_preflight_ready\":%s,\"attempt_in_progress\":%s,"
        "\"attempt_count\":%" PRIu32 ",\"last_attempt_unix\":%" PRId64 ","
        "\"retry_not_before_unix\":%" PRId64 ",\"attempt_cooldown_seconds\":21600,"
        "\"last_attempt_result_valid\":%s,\"last_attempt_result\":\"%s\","
        "\"last_transaction_stage\":\"%s\",\"last_transaction_completed\":%s,"
        "\"last_dns01_prepared\":%s,\"last_cleanup_attempted\":%s,"
        "\"last_cleanup_result\":\"%s\","
        "\"attempt_observability_persistent\":true,""\"attempt_state_loaded\":%s,\"recovered_interrupted_attempt\":%s,"
        "\"tls_activation_preflight_evaluated\":%s,\"tls_activation_preflight_ready\":%s,"
        "\"tls_candidate_valid\":%s,\"tls_candidate_hostname_match\":%s,"
        "\"tls_candidate_time_valid\":%s,\"tls_candidate_fingerprint_changed\":%s,"
        "\"tls_activation_in_progress\":%s,\"tls_candidate_leaf_sha256\":\"%s\","
        "\"tls_current_leaf_sha256\":\"%s\",\"tls_activation_preflight_result\":\"%s\","
        "\"tls_activation_intent_persistent\":true,\"tls_activation_intent_state_loaded\":%s,"
        "\"tls_activation_intent_pending\":%s,\"tls_activation_boot_reconciled\":%s,"
        "\"tls_activation_intent_created_unix\":%" PRId64 ","
        "\"tls_activation_intent_previous_leaf_sha256\":\"%s\","
        "\"tls_activation_intent_target_leaf_sha256\":\"%s\","
        "\"tls_activation_reconciliation_result\":\"%s\","
        "\"tls_activation_outcome_persistent\":true,\"tls_activation_outcome_state_loaded\":%s,"
        "\"tls_activation_last_result_valid\":%s,\"tls_activation_last_success\":%s,"
        "\"tls_activation_last_lkg_restored\":%s,\"tls_activation_last_completed_unix\":%" PRId64 ","
        "\"tls_activation_last_transition_result\":\"%s\","
        "\"tls_activation_last_target_leaf_sha256\":\"%s\","
        "\"tls_activation_last_running_leaf_sha256\":\"%s\","
        "\"tls_handoff_state_persistent\":true,\"tls_handoff_state_loaded\":%s,"
        "\"tls_handoff_in_progress\":%s,\"tls_handoff_recovered_interrupted\":%s,"
        "\"tls_handoff_attempt_count\":%" PRIu32 ",\"tls_handoff_started_unix\":%" PRId64 ","
        "\"tls_handoff_retry_not_before_unix\":%" PRId64 ",\"tls_handoff_target_leaf_sha256\":\"%s\","
        "\"tls_management_ca_unchanged\":true,"
        "\"task_started\":%s,\"evaluated\":%s,\"evaluation_count\":%" PRIu32 ","
        "\"check_interval_seconds\":%u,\"last_evaluation_unix\":%" PRId64 ","
        "\"next_check_unix\":%" PRId64 ",\"state\":\"%s\","
        "\"seconds_remaining\":%" PRId64 ",\"days_remaining\":%" PRId64 ","
        "\"renew_before_days\":30,\"urgent_before_days\":7}\n",
        status.automatic_renewal_enabled ? "true" : "false",
        status.eligible ? "true" : "false", renewal_eligibility_reason(&status),
        status.execution_preflight_ready ? "true" : "false",
        status.attempt_in_progress ? "true" : "false", status.attempt_count,
        status.last_attempt_unix, status.retry_not_before_unix,
        status.last_attempt_result_valid ? "true" : "false",
        status.last_attempt_result_valid ? esp_err_to_name(status.last_attempt_result) : "none",
        renewal_transaction_stage_to_string(status.last_transaction_stage),
        status.last_transaction_completed ? "true" : "false",
        status.last_dns01_prepared ? "true" : "false",
        status.last_cleanup_attempted ? "true" : "false",
        status.last_cleanup_attempted ? esp_err_to_name(status.last_cleanup_result) : "none",
        status.attempt_state_loaded ? "true" : "false",
        status.recovered_interrupted_attempt ? "true" : "false",
        status.tls_activation_preflight_evaluated ? "true" : "false",
        status.tls_activation_preflight_ready ? "true" : "false",
        status.tls_candidate_valid ? "true" : "false",
        status.tls_candidate_hostname_match ? "true" : "false",
        status.tls_candidate_time_valid ? "true" : "false",
        status.tls_candidate_fingerprint_changed ? "true" : "false",
        status.tls_activation_in_progress ? "true" : "false",
        status.tls_candidate_leaf_sha256, status.tls_current_leaf_sha256,
        status.tls_activation_preflight_result,
        status.tls_activation_intent_state_loaded ? "true" : "false",
        status.tls_activation_intent_pending ? "true" : "false",
        status.tls_activation_boot_reconciled ? "true" : "false",
        status.tls_activation_intent_created_unix,
        status.tls_activation_intent_previous_leaf_sha256,
        status.tls_activation_intent_target_leaf_sha256,
        status.tls_activation_reconciliation_result,
        status.tls_activation_outcome_state_loaded ? "true" : "false",
        status.tls_activation_last_result_valid ? "true" : "false",
        status.tls_activation_last_success ? "true" : "false",
        status.tls_activation_last_lkg_restored ? "true" : "false",
        status.tls_activation_last_completed_unix,
        status.tls_activation_last_result_valid ? esp_err_to_name(status.tls_activation_last_transition_result) : "none",
        status.tls_activation_last_target_leaf_sha256,
        status.tls_activation_last_running_leaf_sha256,
        status.tls_handoff_state_loaded ? "true" : "false",
        status.tls_handoff_in_progress ? "true" : "false",
        status.tls_handoff_recovered_interrupted ? "true" : "false",
        status.tls_handoff_attempt_count, status.tls_handoff_started_unix,
        status.tls_handoff_retry_not_before_unix, status.tls_handoff_target_leaf_sha256,
        status.task_started ? "true" : "false", status.evaluated ? "true" : "false",
        status.evaluation_count, (unsigned)APP_ACME_RENEWAL_CHECK_INTERVAL_SECONDS,
        status.last_evaluation_unix, next_check,
        renewal_scheduler_state_name(status.state), status.seconds_remaining, status.days_remaining);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_renewal_scheduler_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= 96)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected {\"enabled\":true|false}");
    char body[96]; size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int result = web_req_recv_bounded(request, body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (result <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "request body receive failed");
        received += (size_t)result;
    }
    body[received] = '\0';
    const char *key = strstr(body, "\"enabled\"");
    if (key == NULL) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");
    const char *colon = strchr(key, ':');
    if (colon == NULL) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");
    ++colon; while (*colon == ' ' || *colon == '\t' || *colon == '\r' || *colon == '\n') ++colon;
    bool enabled;
    if (strncmp(colon, "true", 4U) == 0) enabled = true;
    else if (strncmp(colon, "false", 5U) == 0) enabled = false;
    else return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected enabled boolean");

    const esp_err_t err = acme_client_set_automatic_renewal_enabled(enabled);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Automatic renewal policy commit failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "policy commit failed");
    }
    ESP_LOGI(TAG, "Automatic renewal policy %s; genuine due-window execution is %s; TLS auto-activation remains disabled",
             enabled ? "armed" : "disabled", enabled ? "armed" : "disabled");
    return acme_production_renewal_scheduler_handler(request);
}

static void set_security_headers(httpd_req_t *request)
{
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(request, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(request, "Referrer-Policy", "no-referrer");
}

static const char *reset_reason_to_string(esp_reset_reason_t reason)
{
    switch (reason) {
    case ESP_RST_POWERON:   return "POWER_ON";
    case ESP_RST_EXT:       return "EXTERNAL";
    case ESP_RST_SW:        return "SOFTWARE";
    case ESP_RST_PANIC:     return "PANIC";
    case ESP_RST_INT_WDT:   return "INTERRUPT_WATCHDOG";
    case ESP_RST_TASK_WDT:  return "TASK_WATCHDOG";
    case ESP_RST_WDT:       return "OTHER_WATCHDOG";
    case ESP_RST_DEEPSLEEP: return "DEEP_SLEEP";
    case ESP_RST_BROWNOUT:  return "BROWNOUT";
    case ESP_RST_SDIO:      return "SDIO";
    case ESP_RST_USB:       return "USB";
    case ESP_RST_JTAG:      return "JTAG";
    case ESP_RST_EFUSE:     return "EFUSE";
    case ESP_RST_PWR_GLITCH:return "POWER_GLITCH";
    case ESP_RST_CPU_LOCKUP:return "CPU_LOCKUP";
    case ESP_RST_UNKNOWN:
    default:                return "UNKNOWN";
    }
}

static esp_err_t send_status_json(httpd_req_t *request)
{
    app_state_snapshot_t app_status;
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;
    nts_ke_stats_t nts_ke_stats;
    nts_ntp_auth_stats_t nts_auth_stats;
    ntp_peer_monitor_status_t peer_status;

    (void)app_state_get_snapshot(&app_status);
    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);
    nts_ke_get_stats(&nts_ke_stats);
    nts_ntp_auth_get_stats(&nts_auth_stats);
    memset(&peer_status, 0, sizeof(peer_status));
    (void)ntp_peer_monitor_get_status(&peer_status);

    const esp_ip4_addr_t device_ip = {
        .addr = eth_status.ipv4_address,
    };

    const esp_ip4_addr_t netmask = {
        .addr = eth_status.ipv4_netmask,
    };

    const esp_ip4_addr_t gateway = {
        .addr = eth_status.ipv4_gateway,
    };

    const esp_ip4_addr_t last_client = {
        .addr = ntp_status.last_client_ipv4,
    };

    int64_t unix_now = 0;

    const bool current_time_valid =
        get_current_unix_time(&unix_now);

    const int64_t uptime_us = esp_timer_get_time();
    const uint64_t uptime_seconds =
        uptime_us > 0 ? (uint64_t)(uptime_us / 1000000LL) : 0ULL;
    const bool boot_time_valid =
        current_time_valid && unix_now >= (int64_t)uptime_seconds;
    const int64_t boot_time_unix =
        boot_time_valid ? unix_now - (int64_t)uptime_seconds : 0;
    const char *reset_reason = reset_reason_to_string(esp_reset_reason());

    const bool ntp_ready =
        eth_status.ipv4_ready &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    const size_t response_size = 12288U;
    char *response = calloc(1U, response_size);
    if (response == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");

    int length = snprintf(
        response,
        response_size,
        "{"
        "\"console\":{"
        "\"mode\":\"mtls_authenticated\","
        "\"port\":%u"
        "},"
        "\"system\":{"
        "\"uptime_seconds\":%" PRIu64 ","
        "\"boot_time_valid\":%s,"
        "\"boot_time_unix\":%" PRId64 ","
        "\"reset_reason\":\"%s\","
        "\"heap_internal_free\":%u,"
        "\"heap_internal_min_free\":%u,"
        "\"heap_internal_largest_block\":%u,"
        "\"heap_psram_free\":%u,"
        "\"heap_psram_min_free\":%u"
        "},"
        "\"readiness\":{"
        "\"ntp_ready\":%s,"
        "\"clock_now_valid\":%s,"
        "\"unix_time\":%" PRId64
        "},"
        "\"device\":{"
        "\"hostname\":\"%s\","
        "\"ipv4_ready\":%s,"
        "\"ipv4\":\"" IPSTR "\","
        "\"netmask\":\"" IPSTR "\","
        "\"gateway\":\"" IPSTR "\","
        "\"link_up\":%s,"
        "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\""
        "},"
        "\"clock\":{"
        "\"state\":\"%s\","
        "\"solution_valid\":%s,"
        "\"phase_error_ns\":%" PRId64 ","
        "\"frequency_ppm\":%.6f,"
        "\"accepted_samples\":%" PRIu32 ","
        "\"rejected_samples\":%" PRIu32 ","
        "\"holdover_seconds\":%" PRIu32 ","
        "\"root_dispersion_16_16\":%" PRIu32
        "},"
        "\"gnss\":{"
        "\"receiver_identity_valid\":%s,"
        "\"receiver_model\":\"%s\","
        "\"receiver_software_version\":\"%s\","
        "\"receiver_hardware_version\":\"%s\","
        "\"utc_valid\":%s,"
        "\"utc_seconds\":%" PRId64 ","
        "\"fix_valid\":%s,"
        "\"fix_type\":%u,"
        "\"satellites\":%u,"
        "\"fully_resolved\":%s,"
        "\"leap\":\"%s\","
        "\"current_leap_seconds\":%d,"
        "\"pending_leap_change\":%d,"
        "\"seconds_to_leap_event\":%" PRId32 ","
        "\"timing_pulse_valid\":%s,"
        "\"timing_week\":%u,"
        "\"timing_tow_ms\":%" PRIu32 ","
        "\"timing_qerr_ps\":%" PRId32 ","
        "\"utc_from_ubx_pvt\":%s,"
        "\"utc_age_us\":%" PRId64 ","
        "\"timing_pulse_age_us\":%" PRId64 ","
        "\"ubx_configuration_attempted\":%s,"
        "\"ubx_configuration_complete\":%s,"
        "\"ubx_timepulse_configuration_complete\":%s,"
        "\"ubx_ack_count\":%" PRIu32 ","
        "\"ubx_nak_count\":%" PRIu32 ","
        "\"ubx_configuration_failures\":%" PRIu32 ","
        "\"ubx_frames_valid\":%" PRIu32 ","
        "\"ubx_frames_invalid_checksum\":%" PRIu32 ","
        "\"ubx_frames_invalid_length\":%" PRIu32 ","
        "\"ubx_frames_unsupported\":%" PRIu32 ","
        "\"ubx_nav_pvt_messages\":%" PRIu32 ","
        "\"ubx_nav_timels_messages\":%" PRIu32 ","
        "\"ubx_tim_tp_messages\":%" PRIu32 ","
        "\"valid_zda_messages\":%" PRIu32 ","
        "\"invalid_messages\":%" PRIu32 ","
        "\"uart_bytes_received\":%" PRIu32
        "},"
        "\"pps\":{"
        "\"valid\":%s,"
        "\"period_us\":%" PRIu32 ","
        "\"jitter_us\":%" PRIu32 ","
        "\"age_us\":%" PRId64 ","
        "\"edge_count\":%" PRIu32 ","
        "\"queue_drops\":%" PRIu32
        "},"
        "\"ntp\":{"
        "\"started\":%s,"
        "\"socket_bound\":%s,"
        "\"requests\":%" PRIu32 ","
        "\"responses\":%" PRIu32 ","
        "\"invalid_requests\":%" PRIu32 ","
        "\"unsynchronized_drops\":%" PRIu32 ","
        "\"rate_kod\":%" PRIu32 ","
        "\"send_failures\":%" PRIu32 ","
        "\"socket_failures\":%" PRIu32 ","
        "\"advertised_stratum\":%u,"
        "\"advertised_leap\":%u,"
        "\"root_dispersion_16_16\":%" PRIu32 ","
        "\"last_client\":\"" IPSTR "\","
        "\"last_request_monotonic_us\":%" PRId64 ","
        "\"last_response_monotonic_us\":%" PRId64 ","
        "\"rate_limited_drops\":%" PRIu32 ","
        "\"hw_rx_drops\":%" PRIu32 ","
        "\"rx_stale_purges\":%" PRIu32 ","
        "\"rx_map_failures\":%" PRIu32 ","
        "\"tx_compensation_ns\":%" PRId64 ","
        "\"nts_tx_bias_ns\":%" PRId32
        "},"
        "\"nts\":{"
        "\"ke_running\":%s,"
        "\"ke_exchanges\":%" PRIu32 ","
        "\"ke_exchange_failures\":%" PRIu32 ","
        "\"ke_tls_handshake_failures\":%" PRIu32 ","
        "\"ke_alpn_rejections\":%" PRIu32 ","
        "\"ke_deadline_expirations\":%" PRIu32 ","
        "\"ke_certificate_reloads\":%" PRIu32 ","
        "\"ke_active_connections\":%" PRIu32 ","
        "\"ke_per_client_rejections\":%" PRIu32 ","
        "\"ke_busy_rejections\":%" PRIu32 ","
        "\"ke_low_memory_rejections\":%" PRIu32 ","
        "\"verification_attempts\":%" PRIu32 ","
        "\"authenticated_requests\":%" PRIu32 ","
        "\"verification_failures\":%" PRIu32 ","
        "\"protected_responses\":%" PRIu32 ","
        "\"protection_failures\":%" PRIu32 ","
        "\"naks_sent\":%" PRIu32
        "}"
        "}",
        APP_WEB_CONSOLE_PORT,
        uptime_seconds,
        boot_time_valid ? "true" : "false",
        boot_time_unix,
        reset_reason,
        /* Minimums are since boot: a steady fall over a soak means a leak. */
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
        (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM),
        ntp_ready ? "true" : "false",
        current_time_valid ? "true" : "false",
        unix_now,

        app_status.device_hostname,
        eth_status.ipv4_ready ? "true" : "false",
        IP2STR(&device_ip),
        IP2STR(&netmask),
        IP2STR(&gateway),
        eth_status.link_up ? "true" : "false",
        eth_status.mac[0],
        eth_status.mac[1],
        eth_status.mac[2],
        eth_status.mac[3],
        eth_status.mac[4],
        eth_status.mac[5],

        clock_state_to_string(clock_status.state),
        clock_status.solution_valid ? "true" : "false",
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.accepted_samples,
        clock_status.rejected_samples,
        clock_status.holdover_seconds,
        clock_status.root_dispersion_16_16,

        gnss_status.receiver_identity_valid ? "true" : "false",
        gnss_status.receiver_model,
        gnss_status.receiver_software_version,
        gnss_status.receiver_hardware_version,
        gnss_status.utc_valid ? "true" : "false",
        gnss_status.utc_seconds,
        gnss_status.gnss_fix_valid ? "true" : "false",
        gnss_status.fix_type,
        gnss_status.satellites_used,
        gnss_status.gnss_time_fully_resolved ? "true" : "false",
        leap_to_string(gnss_status.leap_indicator),
        gnss_status.current_leap_seconds,
        gnss_status.pending_leap_change,
        gnss_status.seconds_to_leap_event,
        gnss_status.timing_pulse_valid ? "true" : "false",
        gnss_status.timing_week,
        gnss_status.timing_tow_ms,
        gnss_status.timing_quantization_error_ns,
        gnss_status.utc_from_ubx_pvt ? "true" : "false",
        gnss_status.utc_age_us,
        gnss_status.timing_pulse_age_us,
        gnss_status.ubx_configuration_attempted ? "true" : "false",
        gnss_status.ubx_configuration_complete ? "true" : "false",
        gnss_status.ubx_timepulse_configuration_complete ? "true" : "false",
        gnss_status.ubx_ack_count,
        gnss_status.ubx_nak_count,
        gnss_status.ubx_configuration_failures,
        gnss_status.ubx_frames_valid,
        gnss_status.ubx_frames_invalid_checksum,
        gnss_status.ubx_frames_invalid_length,
        gnss_status.ubx_frames_unsupported,
        gnss_status.ubx_nav_pvt_messages,
        gnss_status.ubx_nav_timels_messages,
        gnss_status.ubx_tim_tp_messages,
        gnss_status.valid_zda_messages,
        gnss_status.invalid_messages,
        gnss_status.uart_bytes_received,

        pps_status.interval_valid ? "true" : "false",
        pps_status.period_us,
        pps_status.jitter_us,
        pps_status.age_us,
        pps_status.edge_count,
        pps_status.queue_drops,

        ntp_status.started ? "true" : "false",
        ntp_status.socket_bound ? "true" : "false",
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.invalid_requests,
        ntp_status.unsynchronized_drops,
        ntp_status.rate_kod_responses,
        ntp_status.send_failures,
        ntp_status.socket_open_failures,
        ntp_status.advertised_stratum,
        ntp_status.advertised_leap_indicator,
        ntp_status.advertised_root_dispersion,
        IP2STR(&last_client),
        ntp_status.last_request_monotonic_us,
        ntp_status.last_response_monotonic_us,
        ntp_status.rate_limited_drops,
        ntp_status.hw_rx_authority_drops,
        eth_status.rx_hw_queue_stale_purges,
        eth_status.rx_hw_map_failures,
        eth_status.tx_compensation_ns,
        eth_status.nts_tx_bias_ns,

        nts_ke_stats.running ? "true" : "false",
        nts_ke_stats.exchanges_completed,
        nts_ke_stats.exchange_failures,
        nts_ke_stats.tls_handshake_failures,
        nts_ke_stats.alpn_rejections,
        nts_ke_stats.deadline_expirations,
        nts_ke_stats.certificate_reloads,
        nts_ke_stats.active_connections,
        nts_ke_stats.per_client_rejections,
        nts_ke_stats.busy_rejections,
        nts_ke_stats.low_memory_rejections,
        nts_auth_stats.verification_attempts,
        nts_auth_stats.authenticated_requests,
        nts_auth_stats.verification_failures,
        nts_auth_stats.protected_responses,
        nts_auth_stats.protection_failures,
        nts_auth_stats.naks_sent);

    if (length > 0 && (size_t)length < response_size && response[length - 1] == '}') {
        response[--length] = '\0';
        int n = snprintf(response + length, response_size - (size_t)length,
                         ",\"peer_monitor\":{\"running\":%s,\"enabled\":%s,"
                         "\"poll_interval_seconds\":%" PRIu32 ",\"response_timeout_ms\":%" PRIu32 ","
                         "\"poll_cycles\":%" PRIu32 ",\"configured_peers\":%" PRIu32 ",\"healthy_peers\":%" PRIu32 ","
                         "\"cross_peer_spread_valid\":%s,\"cross_peer_spread_ns\":%" PRId64 ","
                         "\"best_observed_peer_valid\":%s,\"best_observed_peer_index\":%" PRIu32 ",\"peers\":[",
                         peer_status.running ? "true" : "false", peer_status.enabled ? "true" : "false",
                         peer_status.poll_interval_seconds, peer_status.response_timeout_ms, peer_status.poll_cycles,
                         peer_status.configured_peers, peer_status.healthy_peers,
                         peer_status.cross_peer_spread_valid ? "true" : "false", peer_status.cross_peer_spread_ns,
                         peer_status.best_observed_peer_valid ? "true" : "false", peer_status.best_observed_peer_index);
        if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT && (size_t)length < response_size; ++i) {
            const ntp_peer_status_t *peer = &peer_status.peers[i];
            n = snprintf(response + length, response_size - (size_t)length,
                         "%s{\"index\":%u,\"configured\":%s,\"server\":\"%s\",\"resolved_address\":\"%s\",\"health\":\"%s\","
                         "\"reachability\":%u,\"stratum\":%u,\"leap\":%u,\"reference_id\":\"%s\","
                         "\"offset_ns\":%" PRId64 ",\"delay_ns\":%" PRId64 ",\"jitter_ns\":%" PRId64 ","
                         "\"min_offset_ns\":%" PRId64 ",\"max_offset_ns\":%" PRId64 ",\"mean_offset_ns\":%" PRId64 ",\"rms_offset_ns\":%" PRId64 ","
                         "\"min_delay_ns\":%" PRId64 ",\"mean_delay_ns\":%" PRId64 ","
                         "\"successful_polls\":%" PRIu32 ",\"failed_polls\":%" PRIu32 ",\"rejected_responses\":%" PRIu32 ","
                         "\"duplicate_responses\":%" PRIu32 ",\"consecutive_failures\":%" PRIu32 ",\"kod_responses\":%" PRIu32 ","
                         "\"dns_failures\":%" PRIu32 ",\"timeout_failures\":%" PRIu32 ",\"samples\":%" PRIu32 ","
                         "\"rolling_samples\":%" PRIu32 ",\"last_success_age_seconds\":%" PRIu32 ","
                         "\"hw_timestamped_samples\":%" PRIu32 "}",
                         i ? "," : "", (unsigned)i, peer->configured ? "true" : "false", peer->server, peer->resolved_address,
                         ntp_peer_monitor_health_name(peer->health), peer->reachability, peer->stratum, peer->leap, peer->reference_id,
                         peer->offset_ns, peer->delay_ns, peer->jitter_ns, peer->min_offset_ns, peer->max_offset_ns,
                         peer->mean_offset_ns, peer->rms_offset_ns, peer->min_delay_ns, peer->mean_delay_ns,
                         peer->successful_polls, peer->failed_polls, peer->rejected_responses, peer->duplicate_responses,
                         peer->consecutive_failures, peer->kod_responses, peer->dns_failures, peer->timeout_failures,
                         peer->samples, peer->rolling_samples, peer->last_success_age_seconds,
                         peer->hw_timestamped_samples);
            if (n < 0 || (size_t)n >= response_size - (size_t)length) { length = (int)response_size; break; }
            length += n;
        }
        if ((size_t)length < response_size) {
            n = snprintf(response + length, response_size - (size_t)length, "]}}");
            if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
        }
    }

    if (length < 0 || (size_t)length >= response_size) {
        free(response);
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    free(response);
    return send_err;
}

static esp_err_t send_health_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;

    (void)clock_discipline_get_status(&clock_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);

    const bool healthy =
        eth_status.ipv4_ready &&
        eth_status.link_up &&
        ntp_status.socket_bound &&
        clock_is_servable(clock_status.state,
                          clock_status.solution_valid);

    app_state_snapshot_t app_status;
    (void)app_state_get_snapshot(&app_status);

    char response[256];
    const int length = snprintf(
        response,
        sizeof(response),
        "{\"status\":\"%s\",\"hostname\":\"%s\",\"ntp_ready\":%s}\n",
        healthy ? "ok" : "not-ready",
        app_status.device_hostname,
        healthy ? "true" : "false");

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "health serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);

    httpd_resp_set_status(request,
                          healthy ? "200 OK" : "503 Service Unavailable");

    return httpd_resp_send(request,
                           response,
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_metrics_response(httpd_req_t *request)
{
    clock_discipline_status_t clock_status;
    gnss_service_status_t gnss_status;
    pps_service_status_t pps_status;
    eth_service_status_t eth_status;
    ntp_server_status_t ntp_status;
    nts_ke_stats_t nts_ke_stats;
    nts_ntp_auth_stats_t nts_auth_stats;
    ntp_peer_monitor_status_t peer_status;
    operations_history_status_t operations_status;
    memset(&operations_status, 0, sizeof(operations_status));
    const bool operations_status_valid = operations_history_get_status(&operations_status) == ESP_OK;

    (void)clock_discipline_get_status(&clock_status);
    (void)gnss_service_get_status(&gnss_status);
    (void)pps_service_get_status(&pps_status);
    (void)eth_service_get_status(&eth_status);
    (void)ntp_server_get_status(&ntp_status);
    nts_ke_get_stats(&nts_ke_stats);
    nts_ntp_auth_get_stats(&nts_auth_stats);
    memset(&peer_status, 0, sizeof(peer_status));
    (void)ntp_peer_monitor_get_status(&peer_status);

    const size_t response_size = 12288U;
    char *response = calloc(1U, response_size);
    if (response == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");

    int length = snprintf(
        response,
        response_size,
        "# HELP esp32_ntp_clock_state Clock state enumeration.\n"
        "# TYPE esp32_ntp_clock_state gauge\n"
        "esp32_ntp_clock_state %d\n"
        "# HELP esp32_ntp_clock_solution_valid Clock validity.\n"
        "# TYPE esp32_ntp_clock_solution_valid gauge\n"
        "esp32_ntp_clock_solution_valid %d\n"
        "# HELP esp32_ntp_clock_phase_error_ns Clock phase error.\n"
        "# TYPE esp32_ntp_clock_phase_error_ns gauge\n"
        "esp32_ntp_clock_phase_error_ns %" PRId64 "\n"
        "# HELP esp32_ntp_clock_frequency_ppm Clock frequency estimate.\n"
        "# TYPE esp32_ntp_clock_frequency_ppm gauge\n"
        "esp32_ntp_clock_frequency_ppm %.6f\n"
        "# HELP esp32_ntp_clock_holdover_seconds Holdover duration.\n"
        "# TYPE esp32_ntp_clock_holdover_seconds gauge\n"
        "esp32_ntp_clock_holdover_seconds %" PRIu32 "\n"
        "# HELP esp32_ntp_gnss_utc_valid GNSS UTC validity.\n"
        "# TYPE esp32_ntp_gnss_utc_valid gauge\n"
        "esp32_ntp_gnss_utc_valid %d\n"
        "# HELP esp32_ntp_gnss_satellites Satellites used.\n"
        "# TYPE esp32_ntp_gnss_satellites gauge\n"
        "esp32_ntp_gnss_satellites %u\n"
        "# HELP esp32_ntp_pps_valid PPS validity.\n"
        "# TYPE esp32_ntp_pps_valid gauge\n"
        "esp32_ntp_pps_valid %d\n"
        "# HELP esp32_ntp_pps_jitter_us PPS jitter.\n"
        "# TYPE esp32_ntp_pps_jitter_us gauge\n"
        "esp32_ntp_pps_jitter_us %" PRIu32 "\n"
        "# HELP esp32_ntp_ethernet_ipv4_ready Ethernet IPv4 readiness.\n"
        "# TYPE esp32_ntp_ethernet_ipv4_ready gauge\n"
        "esp32_ntp_ethernet_ipv4_ready %d\n"
        "# HELP esp32_ntp_server_socket_bound NTP UDP socket state.\n"
        "# TYPE esp32_ntp_server_socket_bound gauge\n"
        "esp32_ntp_server_socket_bound %d\n"
        "# HELP esp32_ntp_server_requests_total NTP requests.\n"
        "# TYPE esp32_ntp_server_requests_total counter\n"
        "esp32_ntp_server_requests_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_responses_total NTP responses.\n"
        "# TYPE esp32_ntp_server_responses_total counter\n"
        "esp32_ntp_server_responses_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_rate_kod_total RATE KoD responses.\n"
        "# TYPE esp32_ntp_server_rate_kod_total counter\n"
        "esp32_ntp_server_rate_kod_total %" PRIu32 "\n"
        "# HELP esp32_ntp_server_unsynchronized_drops_total "
        "Fail-closed NTP drops.\n"
        "# TYPE esp32_ntp_server_unsynchronized_drops_total counter\n"
        "esp32_ntp_server_unsynchronized_drops_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_running NTS-KE service running state.\n"
        "# TYPE esp32_nts_ke_running gauge\n"
        "esp32_nts_ke_running %d\n"
        "# HELP esp32_nts_ke_exchanges_total Successful NTS-KE exchanges.\n"
        "# TYPE esp32_nts_ke_exchanges_total counter\n"
        "esp32_nts_ke_exchanges_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_exchange_failures_total Failed NTS-KE exchanges.\n"
        "# TYPE esp32_nts_ke_exchange_failures_total counter\n"
        "esp32_nts_ke_exchange_failures_total %" PRIu32 "\n"
        "# HELP esp32_nts_authenticated_requests_total Authenticated NTS NTP requests.\n"
        "# TYPE esp32_nts_authenticated_requests_total counter\n"
        "esp32_nts_authenticated_requests_total %" PRIu32 "\n"
        "# HELP esp32_nts_verification_failures_total NTS NTP verification failures.\n"
        "# TYPE esp32_nts_verification_failures_total counter\n"
        "esp32_nts_verification_failures_total %" PRIu32 "\n"
        "# HELP esp32_nts_protected_responses_total Protected NTS NTP responses.\n"
        "# TYPE esp32_nts_protected_responses_total counter\n"
        "esp32_nts_protected_responses_total %" PRIu32 "\n"
        "# HELP esp32_nts_protection_failures_total NTS response protection failures.\n"
        "# TYPE esp32_nts_protection_failures_total counter\n"
        "esp32_nts_protection_failures_total %" PRIu32 "\n"
        "# HELP esp32_nts_naks_sent_total NTS NAK (KoD NTSN) responses sent.\n"
        "# TYPE esp32_nts_naks_sent_total counter\n"
        "esp32_nts_naks_sent_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_deadline_expirations_total NTS-KE connections closed at the 5 s deadline.\n"
        "# TYPE esp32_nts_ke_deadline_expirations_total counter\n"
        "esp32_nts_ke_deadline_expirations_total %" PRIu32 "\n"
        "# HELP esp32_nts_ke_rejections_total NTS-KE connections refused before TLS.\n"
        "# TYPE esp32_nts_ke_rejections_total counter\n"
        "esp32_nts_ke_rejections_total{reason=\"per_client\"} %" PRIu32 "\n"
        "esp32_nts_ke_rejections_total{reason=\"busy\"} %" PRIu32 "\n"
        "esp32_nts_ke_rejections_total{reason=\"low_memory\"} %" PRIu32 "\n"
        "# HELP esp32_nts_ke_certificate_reloads_total NTS-KE TLS certificate reloads.\n"
        "# TYPE esp32_nts_ke_certificate_reloads_total counter\n"
        "esp32_nts_ke_certificate_reloads_total %" PRIu32 "\n"
        "# HELP esp32_ntp_rate_limited_drops_total Requests dropped by the rate limiter without a reply.\n"
        "# TYPE esp32_ntp_rate_limited_drops_total counter\n"
        "esp32_ntp_rate_limited_drops_total %" PRIu32 "\n"
        "# HELP esp32_ntp_tx_compensation_ns Learned NTP transmit-latency compensation.\n"
        "# TYPE esp32_ntp_tx_compensation_ns gauge\n"
        "esp32_ntp_tx_compensation_ns %" PRId64 "\n"
        "# HELP esp32_nts_tx_bias_ns Learned NTS T3-to-wire bias.\n"
        "# TYPE esp32_nts_tx_bias_ns gauge\n"
        "esp32_nts_tx_bias_ns %" PRId32 "\n",
        (int)clock_status.state,
        clock_status.solution_valid ? 1 : 0,
        clock_status.phase_error_ns,
        clock_status.frequency_ppm,
        clock_status.holdover_seconds,
        gnss_status.utc_valid ? 1 : 0,
        gnss_status.satellites_used,
        pps_status.interval_valid ? 1 : 0,
        pps_status.jitter_us,
        eth_status.ipv4_ready ? 1 : 0,
        ntp_status.socket_bound ? 1 : 0,
        ntp_status.requests_received,
        ntp_status.normal_responses,
        ntp_status.rate_kod_responses,
        ntp_status.unsynchronized_drops,
        nts_ke_stats.running ? 1 : 0,
        nts_ke_stats.exchanges_completed,
        nts_ke_stats.exchange_failures,
        nts_auth_stats.authenticated_requests,
        nts_auth_stats.verification_failures,
        nts_auth_stats.protected_responses,
        nts_auth_stats.protection_failures,
        nts_auth_stats.naks_sent,
        nts_ke_stats.deadline_expirations,
        nts_ke_stats.per_client_rejections,
        nts_ke_stats.busy_rejections,
        nts_ke_stats.low_memory_rejections,
        nts_ke_stats.certificate_reloads,
        ntp_status.rate_limited_drops,
        eth_status.tx_compensation_ns,
        eth_status.nts_tx_bias_ns);

    if (length > 0 && (size_t)length < response_size) {
        int n = snprintf(response + length, response_size - (size_t)length,
                         "# HELP esp32_ntp_peer_monitor_enabled Peer monitoring enabled.\n"
                         "# TYPE esp32_ntp_peer_monitor_enabled gauge\n"
                         "esp32_ntp_peer_monitor_enabled %d\n"
                         "# HELP esp32_ntp_peer_cross_spread_ns Cross-peer offset spread.\n"
                         "# TYPE esp32_ntp_peer_cross_spread_ns gauge\n"
                         "esp32_ntp_peer_cross_spread_ns %" PRId64 "\n"
                         "# HELP esp32_ntp_peer_poll_cycles_total Peer monitor poll cycles.\n"
                         "# TYPE esp32_ntp_peer_poll_cycles_total counter\n"
                         "esp32_ntp_peer_poll_cycles_total %" PRIu32 "\n",
                         peer_status.enabled ? 1 : 0, peer_status.cross_peer_spread_ns, peer_status.poll_cycles);
        if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT && (size_t)length < response_size; ++i) {
            const ntp_peer_status_t *peer = &peer_status.peers[i];
            n = snprintf(response + length, response_size - (size_t)length,
                         "esp32_ntp_peer_configured{peer=\"%u\"} %d\n"
                         "esp32_ntp_peer_health{peer=\"%u\"} %d\n"
                         "esp32_ntp_peer_offset_ns{peer=\"%u\"} %" PRId64 "\n"
                         "esp32_ntp_peer_delay_ns{peer=\"%u\"} %" PRId64 "\n"
                         "esp32_ntp_peer_jitter_ns{peer=\"%u\"} %" PRId64 "\n"
                         "esp32_ntp_peer_reachability{peer=\"%u\"} %u\n"
                         "esp32_ntp_peer_successful_polls_total{peer=\"%u\"} %" PRIu32 "\n"
                         "esp32_ntp_peer_failed_polls_total{peer=\"%u\"} %" PRIu32 "\n"
                         "esp32_ntp_peer_rejected_responses_total{peer=\"%u\"} %" PRIu32 "\n"
                         "esp32_ntp_peer_duplicate_responses_total{peer=\"%u\"} %" PRIu32 "\n",
                         (unsigned)i, peer->configured ? 1 : 0, (unsigned)i, (int)peer->health,
                         (unsigned)i, peer->offset_ns, (unsigned)i, peer->delay_ns, (unsigned)i, peer->jitter_ns,
                         (unsigned)i, peer->reachability, (unsigned)i, peer->successful_polls,
                         (unsigned)i, peer->failed_polls, (unsigned)i, peer->rejected_responses,
                         (unsigned)i, peer->duplicate_responses);
            if (n < 0 || (size_t)n >= response_size - (size_t)length) { length = (int)response_size; break; }
            length += n;
        }
    }

    if (length > 0 && (size_t)length < response_size) {
        const int n = snprintf(response + length, response_size - (size_t)length,
            "# HELP esp32_ntp_operations_history_available Persistent operations history availability.\n"
            "# TYPE esp32_ntp_operations_history_available gauge\n"
            "esp32_ntp_operations_history_available %d\n"
            "# HELP esp32_ntp_operations_boot_count Persistent boot counter.\n"
            "# TYPE esp32_ntp_operations_boot_count counter\n"
            "esp32_ntp_operations_boot_count %" PRIu32 "\n"
            "# HELP esp32_ntp_operations_events Current persistent operations events retained.\n"
            "# TYPE esp32_ntp_operations_events gauge\n"
            "esp32_ntp_operations_events %" PRIu32 "\n"
            "# HELP esp32_ntp_operations_events_overwritten_total Events overwritten by the bounded ring.\n"
            "# TYPE esp32_ntp_operations_events_overwritten_total counter\n"
            "esp32_ntp_operations_events_overwritten_total %" PRIu32 "\n"
            "# HELP esp32_ntp_operations_reset_watchdog_total Watchdog-classified resets.\n"
            "# TYPE esp32_ntp_operations_reset_watchdog_total counter\n"
            "esp32_ntp_operations_reset_watchdog_total %" PRIu32 "\n"
            "# HELP esp32_ntp_operations_reset_panic_total Panic-classified resets.\n"
            "# TYPE esp32_ntp_operations_reset_panic_total counter\n"
            "esp32_ntp_operations_reset_panic_total %" PRIu32 "\n"
            "# HELP esp32_ntp_operations_reset_brownout_total Brownout-classified resets.\n"
            "# TYPE esp32_ntp_operations_reset_brownout_total counter\n"
            "esp32_ntp_operations_reset_brownout_total %" PRIu32 "\n",
            operations_status_valid ? 1 : 0, operations_status.boot_count, operations_status.event_count,
            operations_status.dropped_events, operations_status.reset_watchdog_count,
            operations_status.reset_panic_count, operations_status.reset_brownout_count);
        if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
    }

    if (length > 0 && (size_t)length < response_size) {
        sd_storage_status_t storage_status;
        memset(&storage_status, 0, sizeof(storage_status));
        const bool storage_status_valid = sd_storage_get_status(&storage_status) == ESP_OK;
        const int n = snprintf(response + length, response_size - (size_t)length,
            "# HELP esp32_ntp_storage_mounted SD operational storage mount state.\n"
            "# TYPE esp32_ntp_storage_mounted gauge\n"
            "esp32_ntp_storage_mounted %d\n"
            "# HELP esp32_ntp_storage_low_space SD operational storage low-space state.\n"
            "# TYPE esp32_ntp_storage_low_space gauge\n"
            "esp32_ntp_storage_low_space %d\n"
            "# HELP esp32_ntp_storage_free_bytes SD operational storage free bytes.\n"
            "# TYPE esp32_ntp_storage_free_bytes gauge\n"
            "esp32_ntp_storage_free_bytes %" PRIu64 "\n"
            "# HELP esp32_ntp_storage_write_failures_total SD archive write failures.\n"
            "# TYPE esp32_ntp_storage_write_failures_total counter\n"
            "esp32_ntp_storage_write_failures_total %" PRIu32 "\n"
            "# HELP esp32_ntp_storage_command_queue_drops_total Non-blocking SD command queue drops.\n"
            "# TYPE esp32_ntp_storage_command_queue_drops_total counter\n"
            "esp32_ntp_storage_command_queue_drops_total %" PRIu32 "\n",
            storage_status_valid && storage_status.mounted ? 1 : 0,
            storage_status_valid && storage_status.low_space ? 1 : 0,
            storage_status.free_bytes, storage_status.write_failures, storage_status.command_queue_drops);
        if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
    }

    if (length < 0 || (size_t)length >= response_size) {
        free(response);
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "metrics serialization failed");
    }

    httpd_resp_set_type(request,
                        "text/plain; version=0.0.4; charset=utf-8");
    set_security_headers(request);

    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    free(response);
    return send_err;
}

static esp_err_t send_config_json(httpd_req_t *request)
{
    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    char response[2048];
    int length = snprintf(response, sizeof(response),
        "{\"schema_version\":%" PRIu32 ",\"generation\":%" PRIu32 ",\"hostname\":\"%s\"," 
        "\"cloudflare\":{\"configured\":%s,\"zone_name\":\"%s\",\"zone_id\":\"%s\",\"api_token_present\":%s},"
        "\"peer_monitor\":{\"enabled\":%s,\"poll_interval_seconds\":%" PRIu32 ",\"response_timeout_ms\":%" PRIu32 ",\"warning_ns\":%" PRIu32 ",\"critical_ns\":%" PRIu32 ",\"peers\":[",
        config.schema_version, config.generation, config.hostname,
        config.cloudflare_configured ? "true" : "false",
        config.cloudflare_configured ? config.cloudflare_zone_name : "",
        config.cloudflare_configured ? config.cloudflare_zone_id : "",
        config.cloudflare_configured ? "true" : "false",
        config.ntp_peer_monitor_enabled ? "true" : "false",
        config.ntp_peer_poll_interval_seconds, config.ntp_peer_response_timeout_ms,
        config.redundant_peer_warning_ns, config.redundant_peer_critical_ns);
    for (size_t i = 0; i < APP_NTP_GENERAL_PEER_COUNT && length > 0 && length < (int)sizeof(response); ++i) {
        int n = snprintf(response + length, sizeof(response) - (size_t)length,
                         "%s{\"index\":%u,\"enabled\":%s,\"server\":\"%s\"}",
                         i ? "," : "", (unsigned)i, config.ntp_peers[i].enabled ? "true" : "false",
                         config.ntp_peers[i].server);
        if (n < 0 || n >= (int)(sizeof(response) - (size_t)length)) { length = (int)sizeof(response); break; }
        length += n;
    }
    if (length > 0 && length < (int)sizeof(response)) {
        const esp_ip4_addr_t net_addr = {.addr = config.static_ipv4_address};
        const esp_ip4_addr_t net_mask = {.addr = config.static_ipv4_netmask};
        const esp_ip4_addr_t net_gw = {.addr = config.static_ipv4_gateway};
        char net_dns[40], dns_in_use[40];
        uint32_t use_main = 0U, use_backup = 0U;
        format_dns_list(config.static_ipv4_dns, config.static_ipv4_dns2, net_dns, sizeof(net_dns));
        eth_service_get_dns_in_use(&use_main, &use_backup);
        format_dns_list(use_main, use_backup, dns_in_use, sizeof(dns_in_use));
        int n = snprintf(response + length, sizeof(response) - (size_t)length, "],\"redundant_server\":{\"enabled\":%s,\"server\":\"%s\",\"warning_ns\":%" PRIu32 ",\"critical_ns\":%" PRIu32 "}},"
                         "\"network\":{\"static_ipv4_enabled\":%s,\"address\":\"" IPSTR "\",\"netmask\":\"" IPSTR "\",\"gateway\":\"" IPSTR "\",\"dns\":\"%s\",\"dns_in_use\":\"%s\"}}\n",
                         config.ntp_peers[APP_REDUNDANT_PEER_INDEX].enabled ? "true" : "false", config.ntp_peers[APP_REDUNDANT_PEER_INDEX].server, config.redundant_peer_warning_ns, config.redundant_peer_critical_ns,
                         config.static_ipv4_enabled ? "true" : "false",
                         IP2STR(&net_addr), IP2STR(&net_mask), IP2STR(&net_gw), net_dns, dns_in_use);
        if (n < 0 || n >= (int)(sizeof(response) - (size_t)length)) length = (int)sizeof(response); else length += n;
    }
    if (length < 0 || length >= (int)sizeof(response)) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration serialization failed");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static bool parse_hostname_json(const char *body,
                                char *hostname,
                                size_t hostname_size)
{
    if (body == NULL || hostname == NULL || hostname_size == 0U) {
        return false;
    }

    const char *key = strstr(body, "\"hostname\"");
    if (key == NULL) {
        return false;
    }

    const char *p = key + strlen("\"hostname\"");
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p++ != ':') {
        return false;
    }
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }
    if (*p++ != '"') {
        return false;
    }

    size_t n = 0U;
    while (*p != '\0' && *p != '"') {
        /* Hostnames never require JSON escapes; reject them explicitly. */
        if (*p == '\\' || n + 1U >= hostname_size) {
            return false;
        }
        hostname[n++] = *p++;
    }

    if (*p != '"' || n == 0U) {
        return false;
    }

    hostname[n] = '\0';
    return device_config_hostname_is_valid(hostname);
}

static esp_err_t config_get_handler(httpd_req_t *request)
{
    return send_config_json(request);
}

static const char *json_value_after_key(const char *body, const char *key)
{
    static char pattern[64];

    if (body == NULL || key == NULL || strlen(key) > 48U) {
        return NULL;
    }

    (void)snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = strstr(body, pattern);
    if (p == NULL) {
        return NULL;
    }

    p += strlen(pattern);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }

    if (*p != ':') {
        return NULL;
    }
    ++p;

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
        ++p;
    }

    return p;
}

static bool json_get_bool(const char *body, const char *key, bool *out)
{
    if (out == NULL) {
        return false;
    }

    const char *p = json_value_after_key(body, key);
    if (p == NULL) {
        return false;
    }

    if (strncmp(p, "true", 4U) == 0) {
        *out = true;
        return true;
    }
    if (strncmp(p, "false", 5U) == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool json_get_u32(const char *body, const char *key, uint32_t *out)
{
    if (out == NULL) {
        return false;
    }

    const char *p = json_value_after_key(body, key);
    if (p == NULL || *p < '0' || *p > '9') {
        return false;
    }

    char *end = NULL;
    const unsigned long v = strtoul(p, &end, 10);
    if (end == p || v > UINT32_MAX) {
        return false;
    }

    *out = (uint32_t)v;
    return true;
}

static bool json_get_string(const char *body, const char *key, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0U) {
        return false;
    }

    const char *p = json_value_after_key(body, key);
    if (p == NULL || *p != '"') {
        return false;
    }
    ++p;

    size_t n = 0U;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' || n + 1U >= out_size) {
            return false;
        }
        out[n++] = *p++;
    }

    if (*p != '"') {
        return false;
    }

    out[n] = '\0';
    return true;
}

static esp_err_t peer_monitor_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= APP_WEB_CONFIG_BODY_MAX)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char body[APP_WEB_CONFIG_BODY_MAX]; size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int r = web_req_recv_bounded(request, body + received, (size_t)request->content_len - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "request body receive failed");
        received += (size_t)r;
    }
    body[received] = '\0';
    bool enabled = false; uint32_t poll = 0U, timeout = 0U;
    if (!json_get_bool(body, "enabled", &enabled) || !json_get_u32(body, "poll_interval_seconds", &poll) ||
        !json_get_u32(body, "response_timeout_ms", &timeout))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "enabled, poll_interval_seconds and response_timeout_ms are required");
    if (poll < APP_NTP_PEER_POLL_MIN_SECONDS || poll > APP_NTP_PEER_POLL_MAX_SECONDS ||
        timeout < APP_NTP_PEER_TIMEOUT_MIN_MS || timeout > APP_NTP_PEER_TIMEOUT_MAX_MS)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "poll interval or timeout out of range");
    device_config_snapshot_t current;
    if (device_config_get_snapshot(&current) != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    device_config_ntp_peer_t peers[APP_NTP_PEER_MAX_COUNT]; memcpy(peers, current.ntp_peers, sizeof(peers));
    for (size_t i = 0; i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
        char key_enabled[24], key_server[16]; snprintf(key_enabled, sizeof(key_enabled), "peer%u_enabled", (unsigned)i); snprintf(key_server, sizeof(key_server), "peer%u", (unsigned)i);
        if (!json_get_bool(body, key_enabled, &peers[i].enabled) || !json_get_string(body, key_server, peers[i].server, sizeof(peers[i].server)))
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "all peerN_enabled and peerN fields are required");
        if (peers[i].enabled && !device_config_ntp_peer_server_is_valid(peers[i].server))
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid enabled peer server");
        if (!peers[i].enabled) peers[i].server[0] = '\0';
    }
    const esp_err_t err = device_config_set_ntp_peer_monitor(enabled, poll, timeout, current.redundant_peer_warning_ns, current.redundant_peer_critical_ns, peers);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "peer monitor configuration commit failed");
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "peer_monitor_updated");
    return send_config_json(request);
}

static esp_err_t redundant_server_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= APP_WEB_CONFIG_BODY_MAX)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char body[APP_WEB_CONFIG_BODY_MAX]; size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int r = web_req_recv_bounded(request, body + received, (size_t)request->content_len - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "request body receive failed");
        received += (size_t)r;
    }
    body[received] = '\0';
    bool enabled = false; char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U] = {0}; uint32_t warning_ns = 0U, critical_ns = 0U;
    if (!json_get_bool(body, "enabled", &enabled) || !json_get_string(body, "server", server, sizeof(server)) ||
        !json_get_u32(body, "warning_ns", &warning_ns) || !json_get_u32(body, "critical_ns", &critical_ns))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "enabled, server, warning_ns and critical_ns are required");
    if ((enabled && !device_config_ntp_peer_server_is_valid(server)) || warning_ns == 0U ||
        warning_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS || critical_ns < warning_ns || critical_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid redundant-server configuration");
    device_config_snapshot_t current;
    if (device_config_get_snapshot(&current) != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    device_config_ntp_peer_t peers[APP_NTP_PEER_MAX_COUNT]; memcpy(peers, current.ntp_peers, sizeof(peers));
    peers[APP_REDUNDANT_PEER_INDEX].enabled = enabled;
    snprintf(peers[APP_REDUNDANT_PEER_INDEX].server, sizeof(peers[APP_REDUNDANT_PEER_INDEX].server), "%s", enabled ? server : "");
    const esp_err_t err = device_config_set_ntp_peer_monitor(current.ntp_peer_monitor_enabled, current.ntp_peer_poll_interval_seconds,
        current.ntp_peer_response_timeout_ms, warning_ns, critical_ns, peers);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "redundant-server configuration commit failed");
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "redundant_server_updated");
    return send_config_json(request);
}

/* Dotted-quad to network-order u32; "" or "0.0.0.0" gives 0. */
static bool parse_ipv4_text(const char *text, uint32_t *out_addr)
{
    if (text == NULL || out_addr == NULL) return false;
    if (text[0] == '\0') { *out_addr = 0U; return true; }
    esp_ip4_addr_t addr = {0};
    if (esp_netif_str_to_ip4(text, &addr) != ESP_OK) return false;
    *out_addr = addr.addr;
    return true;
}

/* One or two DNS servers, separated by commas, spaces or semicolons. Empty is
 * allowed (no static DNS). Names are not accepted: the board needs a DNS
 * server's address before it can look anything up. */
static bool parse_dns_list(const char *text, uint32_t *out_main, uint32_t *out_backup)
{
    *out_main = 0U;
    *out_backup = 0U;
    uint32_t *slots[2] = {out_main, out_backup};
    size_t count = 0U;
    const char *p = text;
    while (*p != '\0') {
        while (*p == ' ' || *p == ',' || *p == ';') ++p;
        if (*p == '\0') break;
        char item[16];
        size_t n = 0U;
        while (*p != '\0' && *p != ' ' && *p != ',' && *p != ';') {
            if (n + 1U >= sizeof(item)) return false;
            item[n++] = *p++;
        }
        item[n] = '\0';
        if (count >= 2U || !parse_ipv4_text(item, slots[count]) || *slots[count] == 0U) return false;
        ++count;
    }
    return true;
}

/* Format up to two DNS servers as "a, b" (empty when none). */
static void format_dns_list(uint32_t a, uint32_t b, char *out, size_t out_size)
{
    const esp_ip4_addr_t ea = {.addr = a}, eb = {.addr = b};
    if (a != 0U && b != 0U) snprintf(out, out_size, IPSTR ", " IPSTR, IP2STR(&ea), IP2STR(&eb));
    else if (a != 0U) snprintf(out, out_size, IPSTR, IP2STR(&ea));
    else if (b != 0U) snprintf(out, out_size, IPSTR, IP2STR(&eb));
    else if (out_size > 0U) out[0] = '\0';
}

/* Static IPv4 takes effect at the next reboot, so a mistake can be undone
 * from the console before it applies; an invalid stored value boots DHCP. */
static esp_err_t network_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= APP_WEB_CONFIG_BODY_MAX)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char body[APP_WEB_CONFIG_BODY_MAX]; size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int r = web_req_recv_bounded(request, body + received, (size_t)request->content_len - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "request body receive failed");
        received += (size_t)r;
    }
    body[received] = '\0';
    bool enabled = false;
    char addr_text[16] = {0}, mask_text[16] = {0}, gw_text[16] = {0}, dns_text[48] = {0};
    uint32_t addr = 0U, mask = 0U, gw = 0U, dns = 0U, dns2 = 0U;
    if (!json_get_bool(body, "static_ipv4_enabled", &enabled))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "static_ipv4_enabled is required");
    if (enabled) {
        if (!json_get_string(body, "address", addr_text, sizeof(addr_text)) ||
            !json_get_string(body, "netmask", mask_text, sizeof(mask_text)) ||
            !json_get_string(body, "gateway", gw_text, sizeof(gw_text)) ||
            !json_get_string(body, "dns", dns_text, sizeof(dns_text)) ||
            !parse_ipv4_text(addr_text, &addr) || !parse_ipv4_text(mask_text, &mask) ||
            !parse_ipv4_text(gw_text, &gw))
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "address, netmask and gateway must be IPv4 dotted quads");
        if (!parse_dns_list(dns_text, &dns, &dns2))
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                       "dns must be up to two IPv4 addresses separated by a comma (names cannot be used)");
        if (!device_config_static_ipv4_is_valid(addr, mask, gw, dns))
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid static IPv4 configuration (address, mask or gateway)");
    }
    const esp_err_t err = device_config_set_static_ipv4(enabled, addr, mask, gw, dns, dns2);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "network configuration commit failed");
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, enabled ? "static_ipv4_set" : "dhcp_selected");
    return send_config_json(request);
}

static esp_err_t hostname_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 ||
        request->content_len >= APP_WEB_CONFIG_BODY_MAX) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "invalid request body");
    }

    char body[APP_WEB_CONFIG_BODY_MAX];
    size_t received = 0U;

    while (received < (size_t)request->content_len) {
        const int result = web_req_recv_bounded(request,
                                          body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (result <= 0) {
            return httpd_resp_send_err(request,
                                       HTTPD_400_BAD_REQUEST,
                                       "request body receive failed");
        }
        received += (size_t)result;
    }
    body[received] = '\0';

    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    if (!parse_hostname_json(body, hostname, sizeof(hostname))) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "expected valid JSON hostname");
    }

    const esp_err_t err = device_config_set_hostname(hostname);
    if (err == ESP_ERR_INVALID_ARG) {
        return httpd_resp_send_err(request,
                                   HTTPD_400_BAD_REQUEST,
                                   "invalid hostname");
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Authenticated hostname update failed: %s",
                 esp_err_to_name(err));
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }

    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "hostname_updated");
    ESP_LOGI(TAG, "Authenticated hostname update accepted");
    return send_config_json(request);
}

static bool extract_json_string(const char *body, const char *name,
                                char *output, size_t output_size)
{
    if (body == NULL || name == NULL || output == NULL || output_size == 0U) return false;
    char key[80];
    const int key_len = snprintf(key, sizeof(key), "\"%s\"", name);
    if (key_len < 0 || key_len >= (int)sizeof(key)) return false;
    const char *p = strstr(body, key);
    if (p == NULL) return false;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != ':') return false;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (*p++ != '"') return false;
    size_t n = 0U;
    while (*p != '\0' && *p != '"') {
        if (*p == '\\' || (unsigned char)*p < 0x20U || n + 1U >= output_size) return false;
        output[n++] = *p++;
    }
    if (*p != '"' || n == 0U) return false;
    output[n] = '\0';
    return true;
}

static esp_err_t receive_request_body(httpd_req_t *request, char *body, size_t body_size)
{
    if (request == NULL || body == NULL || body_size < 2U || request->content_len <= 0 ||
        (size_t)request->content_len >= body_size) return ESP_ERR_INVALID_ARG;
    size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int result = web_req_recv_bounded(request, body + received,
                                          (size_t)request->content_len - received);
        if (result == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (result <= 0) return ESP_FAIL;
        received += (size_t)result;
    }
    body[received] = '\0';
    return ESP_OK;
}

static bool cloudflare_zone_id_is_valid(const char *value)
{
    if (value == NULL || strlen(value) != APP_CLOUDFLARE_ZONE_ID_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < APP_CLOUDFLARE_ZONE_ID_LENGTH; ++i) {
        if (!isxdigit((unsigned char)value[i])) {
            return false;
        }
    }
    return true;
}

static esp_err_t cloudflare_put_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }

    char token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U] = {0};
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U] = {0};
    char supplied_zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U] = {0};

    const bool have_token = extract_json_string(body, "api_token", token, sizeof(token));
    const bool have_zone_name = extract_json_string(body, "zone_name", zone_name, sizeof(zone_name));
    const bool have_zone_id = extract_json_string(body, "zone_id", supplied_zone_id,
                                                   sizeof(supplied_zone_id));
    memset(body, 0, sizeof(body));

    if (!have_token || !have_zone_name || !device_config_cloudflare_zone_is_valid(zone_name)) {
        memset(token, 0, sizeof(token));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected api_token and valid zone_name");
    }

    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U] = {0};
    int http_status = 0;
    esp_err_t err;

    if (have_zone_id && supplied_zone_id[0] != '\0') {
        if (!cloudflare_zone_id_is_valid(supplied_zone_id)) {
            memset(token, 0, sizeof(token));
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                       "zone_id must be exactly 32 hexadecimal characters");
        }

        memcpy(zone_id, supplied_zone_id, sizeof(zone_id));
        ESP_LOGI(TAG, "Using explicitly supplied Cloudflare Zone ID for zone '%s'", zone_name);

        /*
         * Do not perform zone-name discovery here. Existing installations may
         * use a DNS-scoped token that can operate on a known immutable Zone ID
         * but cannot enumerate zones. DNS-01 operations below use zone_id.
         */
        err = ESP_OK;
    } else {
        err = cloudflare_client_resolve_zone(token, zone_name, zone_id,
                                             sizeof(zone_id), &http_status);
        if (err != ESP_OK) {
            memset(token, 0, sizeof(token));
            ESP_LOGW(TAG, "Cloudflare zone discovery failed: err=%s http=%d",
                     esp_err_to_name(err), http_status);
            return httpd_resp_send_err(
                request, HTTPD_400_BAD_REQUEST,
                "Cloudflare zone-name discovery failed. Supply the immutable 32-character Zone ID "
                "when using a token that does not permit zone enumeration.");
        }
    }

    err = device_config_set_cloudflare(token, zone_name, zone_id);
    memset(token, 0, sizeof(token));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Cloudflare configuration commit failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }

    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0,
                                    "cloudflare_updated");
    return send_config_json(request);
}

static esp_err_t cloudflare_delete_handler(httpd_req_t *request)
{
    const esp_err_t err = device_config_clear_cloudflare();
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration commit failed");
    }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "cloudflare_cleared");
    return send_config_json(request);
}

static esp_err_t cloudflare_verify_handler(httpd_req_t *request)
{
    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "Cloudflare is not configured");
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }
    char resolved_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    int http_status = 0;
    err = cloudflare_client_resolve_zone(credentials.api_token, credentials.zone_name,
                                         resolved_id, sizeof(resolved_id), &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK || strcmp(resolved_id, credentials.zone_id) != 0) {
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Cloudflare verification failed",
                               HTTPD_RESP_USE_STRLEN);
    }
    char response[384];
    const int length = snprintf(response, sizeof(response),
                                "{\"verified\":true,\"zone_name\":\"%s\","
                                "\"zone_id\":\"%s\",\"http_status\":%d}\n",
                                credentials.zone_name, credentials.zone_id, http_status);
    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static bool dns_record_id_is_valid(const char *record_id)
{
    if (record_id == NULL || strlen(record_id) != CLOUDFLARE_DNS_RECORD_ID_LENGTH) return false;
    for (size_t i = 0; i < CLOUDFLARE_DNS_RECORD_ID_LENGTH; ++i) {
        const char c = record_id[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

static esp_err_t build_dns01_name(const char *zone_name, char *output, size_t output_size)
{
    if (zone_name == NULL || output == NULL) return ESP_ERR_INVALID_ARG;
    const int n = snprintf(output, output_size, "_acme-challenge.%s", zone_name);
    return (n < 0 || n >= (int)output_size) ? ESP_ERR_INVALID_SIZE : ESP_OK;
}

static esp_err_t dns01_create_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "value", value, sizeof(value))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected DNS-01 value");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        memset(value, 0, sizeof(value));
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        memset(value, 0, sizeof(value));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        memset(value, 0, sizeof(value));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "DNS-01 name too long");
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    int http_status = 0;
    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                             record_name, value, record_id,
                                             sizeof(record_id), &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    memset(value, 0, sizeof(value));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT creation failed: err=%s http=%d", esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "Cloudflare DNS-01 creation failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[512];
    const int length = snprintf(response, sizeof(response),
                                "{\"created\":true,\"record_name\":\"%s\","
                                "\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_name, record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t dns01_query_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    char expected_value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id) ||
        !extract_json_string(body, "value", expected_value, sizeof(expected_value)) ||
        expected_value[0] == '\0') {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected valid record_id and exact value");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "DNS-01 name too long");
    }

    int http_status = 0;
    err = cloudflare_client_verify_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                     record_id, record_name, expected_value, &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT query failed: err=%s http=%d",
                 esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "404 Not Found");
        return httpd_resp_send(request, "Expected Cloudflare DNS-01 record not found",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[384];
    const int length = snprintf(response, sizeof(response),
                                "{\"verified\":true,\"record_name\":\"%s\"," 
                                "\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_name, record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t dns01_delete_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U];
    char expected_value[CLOUDFLARE_DNS01_VALUE_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "record_id", record_id, sizeof(record_id)) ||
        !dns_record_id_is_valid(record_id) ||
        !extract_json_string(body, "value", expected_value, sizeof(expected_value)) ||
        expected_value[0] == '\0') {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected valid record_id and exact value");
    }
    memset(body, 0, sizeof(body));

    device_config_cloudflare_credentials_t credentials;
    esp_err_t err = device_config_get_cloudflare_credentials(&credentials);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    }

    char record_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 32U];
    if (build_dns01_name(credentials.zone_name, record_name, sizeof(record_name)) != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "DNS-01 name too long");
    }

    int http_status = 0;
    err = cloudflare_client_delete_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                     record_id, record_name, expected_value, &http_status);
    memset(credentials.api_token, 0, sizeof(credentials.api_token));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS-01 TXT deletion failed/refused: err=%s http=%d", esp_err_to_name(err), http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "Cloudflare DNS-01 deletion failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[256];
    const int length = snprintf(response, sizeof(response),
                                "{\"deleted\":true,\"record_id\":\"%s\",\"http_status\":%d}\n",
                                record_id, http_status);
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static esp_err_t acme_account_status_handler(httpd_req_t *request)
{
    acme_account_status_t status;
    const esp_err_t err = acme_client_get_account_status(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME account status failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "503 Service Unavailable");
        return httpd_resp_send(request,
                               "ACME account storage unavailable",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1100];
    const int length = snprintf(
        response, sizeof(response),
        "{\"environment\":\"staging\",\"key_present\":%s,"
        "\"registered\":%s,\"account_url\":\"%s\","
        "\"jwk_thumbprint\":\"%s\"}\n",
        status.key_present ? "true" : "false",
        status.registered ? "true" : "false",
        status.account_url,
        status.jwk_thumbprint);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_account_provision_handler(httpd_req_t *request)
{
    acme_account_status_t status;
    const esp_err_t err =
        acme_client_provision_staging_account(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging account provisioning failed: %s http=%d",
                 esp_err_to_name(err), status.http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging account provisioning failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1100];
    const int length = snprintf(
        response, sizeof(response),
        "{\"environment\":\"staging\",\"key_present\":%s,"
        "\"registered\":%s,\"http_status\":%d,"
        "\"account_url\":\"%s\",\"jwk_thumbprint\":\"%s\"}\n",
        status.key_present ? "true" : "false",
        status.registered ? "true" : "false",
        status.http_status,
        status.account_url,
        status.jwk_thumbprint);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME account serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_staging_probe_handler(httpd_req_t *request)
{
    acme_directory_status_t status;
    const esp_err_t err = acme_client_probe_staging(&status);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging probe failed: %s http=%d",
                 esp_err_to_name(err), status.http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging ACME directory probe failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char response[1400];
    const int length = snprintf(
        response,
        sizeof(response),
        "{\"environment\":\"staging\",\"reachable\":true,"
        "\"http_status\":%d,\"new_nonce\":\"%s\","
        "\"new_account\":\"%s\",\"new_order\":\"%s\"}\n",
        status.http_status,
        status.new_nonce_url,
        status.new_account_url,
        status.new_order_url);

    if (length < 0 || length >= (int)sizeof(response)) {
        return httpd_resp_send_err(request,
                                   HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME status serialization failed");
    }

    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static bool hostname_in_zone(const char *hostname, const char *zone)
{
    if (hostname == NULL || zone == NULL) return false;
    if (strcmp(hostname, zone) == 0) return true;
    const size_t hlen = strlen(hostname);
    const size_t zlen = strlen(zone);
    return hlen > zlen + 1U && hostname[hlen - zlen - 1U] == '.' &&
           strcmp(hostname + hlen - zlen, zone) == 0;
}

static esp_err_t acme_staging_order_discover_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "expected hostname");
    }
    memset(body, 0, sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "configuration unavailable");
    }
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name)) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");
    }

    acme_order_discovery_t status;
    err = acme_client_discover_staging_order(hostname, &status);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "ACME staging order discovery failed: %s newOrder=%d auth=%d",
                 esp_err_to_name(err), status.new_order_http_status,
                 status.authorization_http_status);
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request,
                               "Let's Encrypt staging order discovery failed",
                               HTTPD_RESP_USE_STRLEN);
    }

    char *response = calloc(1U, 3072U);
    if (response == NULL) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "out of memory");
    }
    const int length = snprintf(
        response, 3072U,
        "{\"environment\":\"staging\",\"discovered\":true,"
        "\"identifier\":\"%s\",\"new_order_http_status\":%d,"
        "\"authorization_http_status\":%d,\"order_url\":\"%s\","
        "\"authorization_url\":\"%s\",\"finalize_url\":\"%s\","
        "\"challenge\":{\"type\":\"dns-01\",\"status\":\"%s\","
        "\"url\":\"%s\",\"token\":\"%s\"},"
        "\"dns01\":{\"record_name\":\"%s\",\"value\":\"%s\"},"
        "\"challenge_triggered\":false,\"dns_record_created\":false}\n",
        status.identifier, status.new_order_http_status,
        status.authorization_http_status, status.order_url,
        status.authorization_url, status.finalize_url,
        status.challenge_status, status.challenge_url, status.challenge_token,
        status.dns01_record_name, status.dns01_value);
    if (length < 0 || length >= 3072) {
        memset(response, 0, 3072U); free(response);
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME order serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    memset(response, 0, 3072U);
    free(response);
    return send_err;
}

static esp_err_t acme_staging_dns01_validate_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    }
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body, 0, sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected hostname");
    }
    memset(body, 0, sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "configuration unavailable");
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name)) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");
    }

    device_config_cloudflare_credentials_t credentials;
    err = device_config_get_cloudflare_credentials(&credentials);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "Cloudflare credentials unavailable");

    acme_order_discovery_t order;
    err = acme_client_discover_staging_order(hostname, &order);
    if (err != ESP_OK) {
        memset(credentials.api_token, 0, sizeof(credentials.api_token));
        httpd_resp_set_status(request, "502 Bad Gateway");
        return httpd_resp_send(request, "ACME order discovery failed", HTTPD_RESP_USE_STRLEN);
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U] = {0};
    int cf_create_status = 0;
    int cf_verify_status = 0;
    int cf_delete_status = 0;
    bool dns_created = false;
    bool dns_content_verified = false;
    bool dns_deleted = false;

    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                              order.dns01_record_name, order.dns01_value,
                                              record_id, sizeof(record_id), &cf_create_status);
    if (err == ESP_OK) dns_created = true;
    if (err == ESP_OK) {
        err = cloudflare_client_verify_dns01_txt_content(
            credentials.api_token, credentials.zone_id, record_id,
            order.dns01_record_name, order.dns01_value, &cf_verify_status);
        if (err == ESP_OK) dns_content_verified = true;
    }

    acme_challenge_validation_t validation;
    memset(&validation, 0, sizeof(validation));
    esp_err_t validation_err = err;
    if (dns_content_verified) {
        /* Controlled propagation interval before notifying the CA. */
        vTaskDelay(pdMS_TO_TICKS(10000));
        validation_err = acme_client_validate_staging_dns01(&order, &validation);
    }

    /* Cleanup is attempted on success, invalid challenge, timeout, or local error. */
    if (dns_created) {
        const esp_err_t delete_err = cloudflare_client_delete_dns01_txt_content(
            credentials.api_token, credentials.zone_id, record_id,
            order.dns01_record_name, order.dns01_value, &cf_delete_status);
        dns_deleted = (delete_err == ESP_OK);
        if (delete_err != ESP_OK) {
            ESP_LOGE(TAG, "ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                     esp_err_to_name(delete_err), cf_delete_status, record_id);
        }
    }
    memset(credentials.api_token, 0, sizeof(credentials.api_token));

    char *response = calloc(1U, 4096U);
    if (response == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                      "out of memory");
    const int length = snprintf(
        response, 4096U,
        "{\"environment\":\"staging\",\"identifier\":\"%s\"," 
        "\"order_url\":\"%s\",\"authorization_url\":\"%s\"," 
        "\"challenge_url\":\"%s\"," 
        "\"dns01\":{\"record_name\":\"%s\",\"value\":\"%s\"," 
        "\"record_id\":\"%s\",\"created\":%s,\"content_verified\":%s," 
        "\"create_http_status\":%d,\"verify_http_status\":%d,\"deleted\":%s," 
        "\"delete_http_status\":%d}," 
        "\"challenge\":{\"triggered\":%s,\"valid\":%s," 
        "\"trigger_http_status\":%d,\"poll_http_status\":%d,\"poll_count\":%u," 
        "\"authorization_status\":\"%s\",\"status\":\"%s\"}}\n",
        order.identifier, order.order_url, order.authorization_url, order.challenge_url,
        order.dns01_record_name, order.dns01_value, record_id,
        dns_created ? "true" : "false", dns_content_verified ? "true" : "false",
        cf_create_status, cf_verify_status, dns_deleted ? "true" : "false", cf_delete_status,
        validation.triggered ? "true" : "false", validation.valid ? "true" : "false",
        validation.trigger_http_status, validation.poll_http_status, validation.poll_count,
        validation.authorization_status, validation.challenge_status);
    if (length < 0 || length >= 4096) {
        memset(response, 0, 4096U); free(response);
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "ACME validation serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (validation_err != ESP_OK || !validation.valid || !dns_deleted) {
        httpd_resp_set_status(request, "502 Bad Gateway");
    }
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    memset(response, 0, 4096U); free(response);
    return send_err;
}


static esp_err_t acme_staging_certificate_issue_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body,0,sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected hostname");
    }
    memset(body,0,sizeof(body));

    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");

    device_config_cloudflare_credentials_t credentials;
    err = device_config_get_cloudflare_credentials(&credentials);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "Cloudflare credentials unavailable");

    acme_order_discovery_t order;
    err = acme_client_discover_staging_order(hostname, &order);
    if (err != ESP_OK) {
        memset(credentials.api_token,0,sizeof(credentials.api_token));
        httpd_resp_set_status(request,"502 Bad Gateway");
        return httpd_resp_send(request,"ACME order discovery failed",HTTPD_RESP_USE_STRLEN);
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U] = {0};
    int cf_create_status=0, cf_verify_status=0, cf_delete_status=0;
    bool dns_created=false, dns_verified=false, dns_deleted=false;
    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                              order.dns01_record_name, order.dns01_value,
                                              record_id, sizeof(record_id), &cf_create_status);
    if (err == ESP_OK) dns_created=true;
    if (err == ESP_OK) {
        err = cloudflare_client_verify_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                          record_id, order.dns01_record_name,
                                                          order.dns01_value, &cf_verify_status);
        if (err == ESP_OK) dns_verified=true;
    }

    acme_challenge_validation_t validation; memset(&validation,0,sizeof(validation));
    esp_err_t validation_err=err;
    if (dns_verified) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        validation_err=acme_client_validate_staging_dns01(&order,&validation);
    }

    if (dns_created) {
        const esp_err_t delete_err=cloudflare_client_delete_dns01_txt_content(credentials.api_token,
            credentials.zone_id, record_id, order.dns01_record_name, order.dns01_value, &cf_delete_status);
        dns_deleted=(delete_err==ESP_OK);
        if (delete_err != ESP_OK) ESP_LOGE(TAG,"ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                                           esp_err_to_name(delete_err),cf_delete_status,record_id);
    }
    memset(credentials.api_token,0,sizeof(credentials.api_token));

    acme_certificate_issue_status_t certificate; memset(&certificate,0,sizeof(certificate));
    esp_err_t certificate_err = validation_err;
    if (validation_err == ESP_OK && validation.valid && dns_deleted)
        certificate_err = acme_client_finalize_staging_order(&order, &certificate);

    char *response=calloc(1U,4096U);
    if (response==NULL) return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"out of memory");
    const int length=snprintf(response,4096U,
        "{\"environment\":\"staging\",\"identifier\":\"%s\"," 
        "\"order_url\":\"%s\"," 
        "\"dns01\":{\"record_name\":\"%s\",\"record_id\":\"%s\","
        "\"created\":%s,\"content_verified\":%s,\"deleted\":%s,"
        "\"create_http_status\":%d,\"verify_http_status\":%d,\"delete_http_status\":%d},"
        "\"challenge\":{\"valid\":%s,\"authorization_status\":\"%s\"},"
        "\"certificate\":{\"finalized\":%s,\"retrieved\":%s,\"stored\":%s,"
        "\"finalize_http_status\":%d,\"order_poll_http_status\":%d,\"order_poll_count\":%u,"
        "\"order_status\":\"%s\",\"certificate_http_status\":%d,"
        "\"certificate_url\":\"%s\",\"pem_length\":%u},"
        "\"active_management_tls_changed\":false}\n",
        order.identifier,order.order_url,order.dns01_record_name,record_id,
        dns_created?"true":"false",dns_verified?"true":"false",dns_deleted?"true":"false",
        cf_create_status,cf_verify_status,cf_delete_status,
        validation.valid?"true":"false",validation.authorization_status,
        certificate.finalized?"true":"false",certificate.certificate_retrieved?"true":"false",
        certificate.stored?"true":"false",certificate.finalize_http_status,
        certificate.order_poll_http_status,certificate.order_poll_count,certificate.order_status,
        certificate.certificate_http_status,certificate.certificate_url,
        (unsigned)certificate.certificate_pem_length);
    if (length<0 || length>=4096) { memset(response,0,4096U); free(response); return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"ACME certificate serialization failed"); }
    httpd_resp_set_type(request,"application/json"); set_security_headers(request);
    if (certificate_err != ESP_OK || !certificate.stored) httpd_resp_set_status(request,"502 Bad Gateway");
    const esp_err_t send_err=httpd_resp_send(request,response,HTTPD_RESP_USE_STRLEN);
    memset(response,0,4096U); free(response); return send_err;
}


static esp_err_t production_certificate_issue_for_hostname_locked(httpd_req_t *request, const char *hostname);

/* Manual issuance and the automatic renewal scheduler both rewrite the
 * production slot and the DNS-01 TXT record; only one may run at a time. */
static esp_err_t production_certificate_issue_for_hostname(httpd_req_t *request, const char *hostname)
{
    if (!acme_client_production_operation_begin()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Another ACME production operation is in progress",
                               HTTPD_RESP_USE_STRLEN);
    }
    const esp_err_t err = production_certificate_issue_for_hostname_locked(request, hostname);
    acme_client_production_operation_end();
    return err;
}

static esp_err_t production_certificate_issue_for_hostname_locked(httpd_req_t *request, const char *hostname)
{
    device_config_snapshot_t config;
    esp_err_t err = device_config_get_snapshot(&config);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration unavailable");
    if (!config.cloudflare_configured) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Cloudflare is not configured", HTTPD_RESP_USE_STRLEN);
    }
    if (!hostname_in_zone(hostname, config.cloudflare_zone_name))
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                                   "hostname must be the configured Cloudflare zone or a subdomain");

    device_config_cloudflare_credentials_t credentials;
    err = device_config_get_cloudflare_credentials(&credentials);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                                   "Cloudflare credentials unavailable");

    acme_account_status_t production_account; memset(&production_account,0,sizeof(production_account));
    err = acme_client_provision_production_account(&production_account);
    if (err != ESP_OK || !production_account.registered) {
        memset(credentials.api_token,0,sizeof(credentials.api_token));
        httpd_resp_set_status(request,"502 Bad Gateway");
        return httpd_resp_send(request,"ACME production account provisioning failed",HTTPD_RESP_USE_STRLEN);
    }

    acme_order_discovery_t order;
    err = acme_client_discover_production_order(hostname, &order);
    if (err != ESP_OK) {
        memset(credentials.api_token,0,sizeof(credentials.api_token));
        httpd_resp_set_status(request,"502 Bad Gateway");
        return httpd_resp_send(request,"ACME order discovery failed",HTTPD_RESP_USE_STRLEN);
    }

    char record_id[CLOUDFLARE_DNS_RECORD_ID_LENGTH + 1U] = {0};
    int cf_create_status=0, cf_verify_status=0, cf_delete_status=0;
    bool dns_created=false, dns_verified=false, dns_deleted=false;
    err = cloudflare_client_create_dns01_txt(credentials.api_token, credentials.zone_id,
                                              order.dns01_record_name, order.dns01_value,
                                              record_id, sizeof(record_id), &cf_create_status);
    if (err == ESP_OK) dns_created=true;
    if (err == ESP_OK) {
        err = cloudflare_client_verify_dns01_txt_content(credentials.api_token, credentials.zone_id,
                                                          record_id, order.dns01_record_name,
                                                          order.dns01_value, &cf_verify_status);
        if (err == ESP_OK) dns_verified=true;
    }

    acme_challenge_validation_t validation; memset(&validation,0,sizeof(validation));
    esp_err_t validation_err=err;
    if (dns_verified) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        validation_err=acme_client_validate_production_dns01(&order,&validation);
    }

    if (dns_created) {
        const esp_err_t delete_err=cloudflare_client_delete_dns01_txt_content(credentials.api_token,
            credentials.zone_id, record_id, order.dns01_record_name, order.dns01_value, &cf_delete_status);
        dns_deleted=(delete_err==ESP_OK);
        if (delete_err != ESP_OK) ESP_LOGE(TAG,"ACME DNS-01 cleanup failed: %s http=%d record_id=%s",
                                           esp_err_to_name(delete_err),cf_delete_status,record_id);
    }
    memset(credentials.api_token,0,sizeof(credentials.api_token));

    acme_certificate_issue_status_t certificate; memset(&certificate,0,sizeof(certificate));
    esp_err_t certificate_err = validation_err;
    if (validation_err == ESP_OK && validation.valid && dns_deleted)
        certificate_err = acme_client_finalize_production_order(&order, &certificate);

    bool activation_scheduled = false;
    if (certificate_err == ESP_OK && certificate.stored) {
        acme_certificate_inspection_t issued;
        memset(&issued, 0, sizeof(issued));
        int64_t activation_now = 0;
        if (acme_client_inspect_stored_production_certificate(&issued) == ESP_OK &&
            issued.certificate_parse_valid && issued.hostname_matches_certificate &&
            issued.private_key_matches_certificate && issued.leaf_sha256[0] != '\0' &&
            get_current_unix_time(&activation_now) &&
            tls_activation_intent_begin(s_active_server_leaf_sha256[0] != '\0' ?
                                        s_active_server_leaf_sha256 : "embedded_development",
                                        activation_now) == ESP_OK &&
            tls_activation_intent_set_target(issued.leaf_sha256) == ESP_OK &&
            tls_activation_schedule_pending_target() == ESP_OK) {
            activation_scheduled = true;
            (void)operations_history_record(OPERATIONS_EVENT_SECURITY, 0, "production_certificate_issued_tls_activation_scheduled");
        } else {
            ESP_LOGW(TAG, "Production certificate stored but automatic initial TLS activation was not scheduled");
            (void)operations_history_record(OPERATIONS_EVENT_FAULT, ESP_ERR_INVALID_STATE, "production_certificate_stored_activation_not_scheduled");
        }
    }

    char *response=calloc(1U,4096U);
    if (response==NULL) return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"out of memory");
    const int length=snprintf(response,4096U,
        "{\"environment\":\"production\",\"account_url\":\"%s\",\"identifier\":\"%s\"," 
        "\"order_url\":\"%s\"," 
        "\"dns01\":{\"record_name\":\"%s\",\"record_id\":\"%s\","
        "\"created\":%s,\"content_verified\":%s,\"deleted\":%s,"
        "\"create_http_status\":%d,\"verify_http_status\":%d,\"delete_http_status\":%d},"
        "\"challenge\":{\"valid\":%s,\"authorization_status\":\"%s\"},"
        "\"certificate\":{\"finalized\":%s,\"retrieved\":%s,\"stored\":%s,"
        "\"finalize_http_status\":%d,\"order_poll_http_status\":%d,\"order_poll_count\":%u,"
        "\"order_status\":\"%s\",\"certificate_http_status\":%d,"
        "\"certificate_url\":\"%s\",\"pem_length\":%u},"
        "\"automatic_tls_activation_scheduled\":%s}\n",
        production_account.account_url,order.identifier,order.order_url,order.dns01_record_name,record_id,
        dns_created?"true":"false",dns_verified?"true":"false",dns_deleted?"true":"false",
        cf_create_status,cf_verify_status,cf_delete_status,
        validation.valid?"true":"false",validation.authorization_status,
        certificate.finalized?"true":"false",certificate.certificate_retrieved?"true":"false",
        certificate.stored?"true":"false",certificate.finalize_http_status,
        certificate.order_poll_http_status,certificate.order_poll_count,certificate.order_status,
        certificate.certificate_http_status,certificate.certificate_url,
        (unsigned)certificate.certificate_pem_length, activation_scheduled ? "true" : "false");
    if (length<0 || length>=4096) { memset(response,0,4096U); free(response); return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"ACME certificate serialization failed"); }
    httpd_resp_set_type(request,"application/json"); set_security_headers(request);
    if (certificate_err != ESP_OK || !certificate.stored) httpd_resp_set_status(request,"502 Bad Gateway");
    const esp_err_t send_err=httpd_resp_send(request,response,HTTPD_RESP_USE_STRLEN);
    memset(response,0,4096U); free(response); return send_err;

}

static esp_err_t acme_production_certificate_issue_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    if (!extract_json_string(body, "hostname", hostname, sizeof(hostname))) {
        memset(body,0,sizeof(body));
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "expected hostname");
    }
    memset(body,0,sizeof(body));

    acme_certificate_inspection_t existing;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&existing);
    if (inspect_err == ESP_OK && existing.certificate_parse_valid &&
        existing.hostname_matches_certificate && existing.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request,
            "Production certificate already exists; use the controlled renewal endpoint",
            HTTPD_RESP_USE_STRLEN);
    }
    if (inspect_err != ESP_OK && inspect_err != ESP_ERR_NOT_FOUND)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Production certificate inspection failed");

    return production_certificate_issue_for_hostname(request, hostname);
}

static esp_err_t acme_production_certificate_renew_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&status);
    if (inspect_err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "No production certificate exists; use initial issuance",
                               HTTPD_RESP_USE_STRLEN);
    }
    if (inspect_err != ESP_OK || !status.certificate_parse_valid ||
        !status.hostname_matches_certificate || !status.private_key_matches_certificate)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Stored production certificate is not valid for renewal");

    int64_t now = 0, expires = 0;
    if (!get_current_unix_time(&now) || !parse_utc_timestamp(status.valid_to, &expires)) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Management civil time unavailable; renewal decision refused",
                               HTTPD_RESP_USE_STRLEN);
    }

    const int64_t seconds_remaining = expires - now;
    if (seconds_remaining > 30LL * 86400LL) {
        char response[256];
        const int64_t days_remaining = seconds_remaining / 86400LL;
        const int length = snprintf(response, sizeof(response),
            "{\"renewed\":false,\"reason\":\"not_due\",\"days_remaining\":%" PRId64 ","
            "\"renew_before_days\":30,\"automatic_renewal\":true}\n", days_remaining);
        if (length < 0 || length >= (int)sizeof(response))
            return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
        httpd_resp_set_status(request, "409 Conflict");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    }

    /* Operator-requested renewal reuses the production issuance path. The automatic
     * scheduler uses the guarded transaction path and production TLS handoff state. */
    return production_certificate_issue_for_hostname(request, status.hostname);
}



static esp_err_t acme_certificate_inspection_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        return httpd_resp_send(request, "No stored ACME certificate", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Stored certificate inspection failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "500 Internal Server Error");
        return httpd_resp_send(request, "Stored certificate inspection failed", HTTPD_RESP_USE_STRLEN);
    }

    char response[1024];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"hostname\":\"%s\"," 
        "\"key_present\":%s,\"certificate_present\":%s,\"hostname_present\":%s,"
        "\"certificate_parse_valid\":%s,\"hostname_matches_certificate\":%s,"
        "\"private_key_matches_certificate\":%s,\"chain_certificate_count\":%u,"
        "\"pem_length\":%u,\"valid_from\":\"%s\",\"valid_to\":\"%s\","
        "\"leaf_sha256\":\"%s\",\"active_management_tls_changed\":%s,"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        status.key_present ? "true" : "false",
        status.certificate_present ? "true" : "false",
        status.hostname_present ? "true" : "false",
        status.certificate_parse_valid ? "true" : "false",
        status.hostname_matches_certificate ? "true" : "false",
        status.private_key_matches_certificate ? "true" : "false",
        status.chain_certificate_count,
        (unsigned)status.certificate_pem_length,
        status.valid_from, status.valid_to, status.leaf_sha256,
        s_tls_source != WEB_TLS_EMBEDDED ? "true" : "false",
        tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (err == ESP_ERR_INVALID_STATE) httpd_resp_set_status(request, "409 Conflict");
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_inspection_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_production_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request,
                               "{\"stored\":false,\"environment\":\"production\",\"active_management_tls_changed\":false,\"active_tls_source\":\"embedded_development\"}\n",
                               HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "Stored production certificate inspection failed: %s", esp_err_to_name(err));
        httpd_resp_set_status(request, "500 Internal Server Error");
        return httpd_resp_send(request, "Stored production certificate inspection failed", HTTPD_RESP_USE_STRLEN);
    }

    char active_slot = '?';
    bool slot_a_valid = false, slot_b_valid = false, legacy_material_present = false;
    const esp_err_t storage_err = acme_client_get_production_storage_status(
        &active_slot, &slot_a_valid, &slot_b_valid, &legacy_material_present);
    if (storage_err != ESP_OK) {
        ESP_LOGE(TAG, "Production dual-slot status failed: %s", esp_err_to_name(storage_err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Production dual-slot status failed");
    }

    char response[1280];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"environment\":\"production\",\"hostname\":\"%s\","
        "\"key_present\":%s,\"certificate_present\":%s,\"hostname_present\":%s,"
        "\"certificate_parse_valid\":%s,\"hostname_matches_certificate\":%s,"
        "\"private_key_matches_certificate\":%s,\"chain_certificate_count\":%u,"
        "\"pem_length\":%u,\"valid_from\":\"%s\",\"valid_to\":\"%s\","
        "\"leaf_sha256\":\"%s\",\"production_storage\":{\"mode\":\"dual_slot\","
        "\"active_slot\":\"%c\",\"slot_a_valid\":%s,\"slot_b_valid\":%s,"
        "\"legacy_material_present\":%s},\"active_management_tls_changed\":%s,"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        status.key_present ? "true" : "false",
        status.certificate_present ? "true" : "false",
        status.hostname_present ? "true" : "false",
        status.certificate_parse_valid ? "true" : "false",
        status.hostname_matches_certificate ? "true" : "false",
        status.private_key_matches_certificate ? "true" : "false",
        status.chain_certificate_count,
        (unsigned)status.certificate_pem_length,
        status.valid_from, status.valid_to, status.leaf_sha256,
        active_slot,
        slot_a_valid ? "true" : "false",
        slot_b_valid ? "true" : "false",
        legacy_material_present ? "true" : "false",
        s_tls_source != WEB_TLS_EMBEDDED ? "true" : "false",
        tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (err == ESP_ERR_INVALID_STATE) httpd_resp_set_status(request, "409 Conflict");
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}


static esp_err_t acme_production_certificate_lifecycle_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t status;
    const esp_err_t err = acme_client_inspect_stored_production_certificate(&status);
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_set_status(request, "404 Not Found");
        httpd_resp_set_type(request, "application/json");
        set_security_headers(request);
        return httpd_resp_send(request,
            "{\"stored\":false,\"environment\":\"production\",\"renewal_policy\":{\"mode\":\"manual\",\"renew_before_days\":30,\"urgent_before_days\":7,\"automatic_renewal\":false}}\n",
            HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "Production certificate inspection failed");

    int64_t now = 0, expires = 0;
    const bool now_valid = get_current_unix_time(&now);
    const bool expiry_valid = parse_utc_timestamp(status.valid_to, &expires);
    int64_t seconds_remaining = 0;
    int64_t days_remaining = 0;
    const char *state = "time_unavailable";
    bool renewal_due = false;
    bool urgent = false;
    bool expired = false;
    bool automatic_renewal = false;
    (void)acme_client_get_automatic_renewal_enabled(&automatic_renewal);

    if (now_valid && expiry_valid) {
        seconds_remaining = expires - now;
        days_remaining = seconds_remaining >= 0 ? seconds_remaining / 86400LL : -((-seconds_remaining + 86399LL) / 86400LL);
        expired = seconds_remaining <= 0;
        urgent = !expired && seconds_remaining <= 7LL * 86400LL;
        renewal_due = !expired && seconds_remaining <= 30LL * 86400LL;
        state = expired ? "expired" : (urgent ? "urgent" : (renewal_due ? "renewal_due" : "valid"));
    }

    char response[1400];
    const int length = snprintf(response, sizeof(response),
        "{\"stored\":true,\"environment\":\"production\",\"hostname\":\"%s\"," 
        "\"certificate_valid\":%s,\"valid_from\":\"%s\",\"valid_to\":\"%s\"," 
        "\"clock_now_valid\":%s,\"unix_time\":%" PRId64 ",\"expiry_unix_time\":%" PRId64 ","
        "\"seconds_remaining\":%" PRId64 ",\"days_remaining\":%" PRId64 ","
        "\"lifecycle_state\":\"%s\",\"renewal_due\":%s,\"urgent\":%s,\"expired\":%s,"
        "\"renewal_policy\":{\"mode\":\"automatic\",\"renew_before_days\":30,\"urgent_before_days\":7,"
        "\"automatic_renewal\":%s,\"private_key_exportable\":false,\"acme_account_key_exportable\":false},"
        "\"active_tls_source\":\"%s\"}\n",
        status.hostname,
        (status.certificate_parse_valid && status.hostname_matches_certificate && status.private_key_matches_certificate) ? "true" : "false",
        status.valid_from, status.valid_to,
        now_valid ? "true" : "false", now_valid ? now : 0,
        expiry_valid ? expires : 0, seconds_remaining, days_remaining, state,
        renewal_due ? "true" : "false", urgent ? "true" : "false", expired ? "true" : "false",
        automatic_renewal ? "true" : "false", tls_source_name(s_tls_source));
    if (length < 0 || length >= (int)sizeof(response))
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_export_handler(httpd_req_t *request)
{
    char *pem = NULL;
    size_t pem_length = 0U;
    char hostname[ACME_DNS_NAME_MAX_LENGTH + 1U];
    const esp_err_t err = acme_client_load_production_certificate_pem(&pem, &pem_length,
                                                                      hostname, sizeof(hostname));
    if (err == ESP_ERR_NOT_FOUND) {
        return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "Production certificate not stored");
    }
    if (err != ESP_OK || pem == NULL) {
        ESP_LOGE(TAG, "Production certificate export failed: %s", esp_err_to_name(err));
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "Production certificate export failed");
    }

    httpd_resp_set_type(request, "application/x-pem-file");
    httpd_resp_set_hdr(request, "Content-Disposition", "attachment; filename=production-chain.pem");
    httpd_resp_set_hdr(request, "X-Private-Key-Exportable", "false");
    httpd_resp_set_hdr(request, "X-ACME-Account-Key-Exportable", "false");
    httpd_resp_set_hdr(request, "X-Certificate-Private-Key-Policy", "non-exportable");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, pem, (ssize_t)pem_length);
    memset(pem, 0, pem_length + 1U);
    free(pem);
    return send_err;
}

static bool tls_transition_try_claim(void)
{
    /* Every HTTPS credential change passes through here. An unclaimed board
     * stays on its bootstrap certificate, whose fingerprint is on the serial
     * console for the setup tool to pin; switching it to a production
     * certificate that survived a settings reset would defeat that. */
    if (!management_ownership_is_provisioned()) return false;
    bool claimed = false;
    taskENTER_CRITICAL(&s_tls_transition_lock);
    if (!s_tls_transition_pending) {
        s_tls_transition_pending = true;
        claimed = true;
    }
    taskEXIT_CRITICAL(&s_tls_transition_lock);
    return claimed;
}

static void tls_transition_release(void)
{
    taskENTER_CRITICAL(&s_tls_transition_lock);
    s_tls_transition_pending = false;
    taskEXIT_CRITICAL(&s_tls_transition_lock);
}

static esp_err_t acme_certificate_activate_test_handler(httpd_req_t *request)
{
    if (s_tls_source == WEB_TLS_STORED_TEST) {
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"stored_staging_test\"}\n", HTTPD_RESP_USE_STRLEN);
    }
    acme_certificate_inspection_t inspection;
    const esp_err_t inspect_err = acme_client_inspect_stored_certificate(&inspection);
    if (inspect_err != ESP_OK || !inspection.certificate_parse_valid ||
        !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Stored certificate is not eligible for test activation", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_switch", 8192U,
                    (void *)(uintptr_t)WEB_TLS_STORED_TEST, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule TLS transition");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"stored_staging_test\",\"persistent\":false,\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_production_certificate_activate_handler(httpd_req_t *request)
{
    acme_certificate_inspection_t inspection;
    const esp_err_t inspect_err = acme_client_inspect_stored_production_certificate(&inspection);
    if (inspect_err != ESP_OK || !inspection.certificate_parse_valid ||
        !inspection.hostname_matches_certificate || !inspection.private_key_matches_certificate) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "Production certificate is not eligible for activation", HTTPD_RESP_USE_STRLEN);
    }
    if (s_tls_source == WEB_TLS_PRODUCTION) {
        esp_err_t err = acme_client_set_production_boot_selected(true);
        if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to persist production TLS boot selection");
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"stored_production\",\"persistent\":true}\n", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_prod", 8192U,
                    (void *)(uintptr_t)WEB_TLS_PRODUCTION, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule production TLS activation");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"stored_production\",\"persistent\":true,\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t acme_certificate_rollback_handler(httpd_req_t *request)
{
    if (s_tls_source == WEB_TLS_EMBEDDED) {
        const esp_err_t pref_err = acme_client_set_production_boot_selected(false);
        if (pref_err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to persist embedded TLS boot selection");
        httpd_resp_set_type(request, "application/json"); set_security_headers(request);
        return httpd_resp_send(request, "{\"scheduled\":false,\"active_tls_source\":\"embedded_development\",\"persistent\":true}\n", HTTPD_RESP_USE_STRLEN);
    }
    if (!tls_transition_try_claim()) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "TLS transition already pending", HTTPD_RESP_USE_STRLEN);
    }
    if (xTaskCreate(tls_transition_task, "tls_rollback", 8192U,
                    (void *)(uintptr_t)WEB_TLS_EMBEDDED, 5U, NULL) != pdPASS) {
        tls_transition_release();
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to schedule TLS rollback");
    }
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request,
        "{\"scheduled\":true,\"target_tls_source\":\"embedded_development\",\"management_client_ca_unchanged\":true}\n",
        HTTPD_RESP_USE_STRLEN);
}


static void delayed_reboot_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1200U));
    esp_restart();
}

/* True when a reboot now would cut off an OTA upload, a production certificate
 * operation or a TLS hand-over; answers 409 and sets *out_result. A request
 * that passes can still race work starting a moment later, which is why the
 * ACME and TLS paths also recover from an interrupted run at boot. */
static bool reboot_refused_busy(httpd_req_t *request, esp_err_t *out_result)
{
    const char *reason = NULL;
    ota_manager_status_t ota;
    if (ota_manager_get_status(&ota) == ESP_OK && ota.update_in_progress) {
        reason = "An OTA update is in progress";
    } else if (!acme_client_production_operation_begin()) {
        reason = "A production certificate operation is in progress";
    } else {
        acme_client_production_operation_end();
        if (s_tls_transition_pending) reason = "A TLS hand-over is in progress";
    }
    if (reason == NULL) return false;
    httpd_resp_set_status(request, "409 Conflict");
    set_security_headers(request);
    *out_result = httpd_resp_send(request, reason, HTTPD_RESP_USE_STRLEN);
    return true;
}

static esp_err_t system_reboot_handler(httpd_req_t *request)
{
    esp_err_t busy_result = ESP_OK;
    if (reboot_refused_busy(request, &busy_result)) return busy_result;

    if (xTaskCreate(delayed_reboot_task, "web_reboot", 2048U,
                    NULL, 5U, NULL) != pdPASS) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "unable to schedule reboot");
    }

    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request,
                           "{\"scheduled\":true,\"action\":\"reboot\"}\n",
                           HTTPD_RESP_USE_STRLEN);
}

static esp_err_t firmware_page_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Firmware Update</title><style>"
        ":root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0d141b;color:#e9f0f5;font-family:Arial,sans-serif}header,main{max-width:1000px;margin:auto;padding:20px}nav{display:flex;gap:10px;flex-wrap:wrap}.btn,button{border:1px solid #3d6175;background:#203b4b;color:#e9f0f5;border-radius:7px;padding:10px 14px;font-weight:bold;text-decoration:none;cursor:pointer}.danger{background:#4c2226;border-color:#81434a}.card{background:#14212d;border:1px solid #294252;border-radius:10px;padding:18px;margin:14px 0}h1{color:#58c7ff}h2{color:#8fdb75}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.row{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid #203440}.v{font-family:Consolas,monospace;text-align:right}.status{white-space:pre-wrap;color:#a8bac7;margin-top:12px}input{width:100%;padding:10px;background:#0d141b;color:#e9f0f5;border:1px solid #3d6175;border-radius:6px}@media(max-width:650px){.grid{grid-template-columns:1fr}.row{display:block}.v{text-align:left}}</style></head><body>"
        "<header><nav><a class=\"btn\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/system\">System</a><a class=\"btn\" href=\"/management\">Management</a><a class=\"btn\" href=\"/diagnostics\">Diagnostics</a></nav><h1>OTA Firmware Update</h1><p>Authenticated A/B OTA. Upload is staged to the inactive partition and activation is a separate reboot action.</p></header><main>"
        "<section class=\"card\"><h2>Firmware Status</h2><div class=\"grid\"><div id=\"versions\"></div><div id=\"lifecycle\"></div></div></section>"
        "<section class=\"card\"><h2>Stage Firmware</h2><input id=\"fw\" type=\"file\" accept=\".bin,application/octet-stream\"><p id=\"selected\">No image selected.</p><button id=\"upload\" onclick=\"upload()\">Upload &amp; Validate</button><div id=\"msg\" class=\"status\"></div></section>"
        "<section class=\"card\"><h2>Activation</h2><p>The currently running image remains authoritative until a complete image has been validated and selected for boot.</p><button class=\"danger\" onclick=\"reboot()\">Activate Staged Image &amp; Reboot</button></section>"
        "<section class=\"card\"><h2>Rollback</h2><p>Boots the image in the other OTA slot after verifying it. The restored image must pass the same 5-minute soak; if it fails, the bootloader returns to the current image.</p><p id=\"rbinfo\">Checking previous image...</p><button id=\"rbbtn\" class=\"danger\" onclick=\"rollback()\" disabled>Roll Back &amp; Reboot</button></section></main>"
        "<script>const E=x=>String(x == null ? '--' : x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));const R=(k,v)=>'<div class=\"row\"><span>'+E(k)+'</span><span class=\"v\">'+E(v)+'</span></div>';async function status(){const r=await fetch('/api/v1/ota/status',{cache:'no-store'}),o=await r.json();versions.innerHTML=R('Current Version',o.running_version)+R('Previous Version',o.previous_version||'--')+R('Running',o.running_partition)+R('Next Target',o.next_partition);lifecycle.innerHTML=R('Last Result',o.last_result)+R('Uploads',o.attempts)+R('Staged',o.successes)+R('Confirmed',o.confirmations)+R('Failures',o.failures)+R('Rollbacks',o.rollbacks_detected);rbbtn.disabled=!o.rollback_available;rbinfo.textContent=o.rollback_available?'Previous image: '+o.rollback_version+' on '+o.rollback_partition:(o.boot_partition!==o.running_partition?'Unavailable: a staged image is waiting for a reboot.':'No previous image available.')}async function rollback(){if(!confirm('Roll back to the previous firmware and reboot now? NTP and NTS will be unavailable for about a minute.'))return;rbbtn.disabled=true;msg.textContent='Verifying previous image...';try{const r=await fetch('/api/v1/ota/rollback',{method:'POST',headers:{'X-Confirm-Rollback':'ROLLBACK'}});msg.textContent=(r.ok?'Rollback scheduled. ':'Rollback refused. ')+await r.text()}catch(x){msg.textContent='Rollback request: '+x.message}}fw.onchange=()=>selected.textContent=fw.files[0]?fw.files[0].name+' ('+fw.files[0].size+' bytes)':'No image selected.';async function upload(){const f=fw.files[0];if(!f){msg.textContent='Choose a firmware .bin first.';return}upload.disabled=true;msg.textContent='Uploading and validating...';try{const r=await fetch('/api/v1/ota/image',{method:'POST',headers:{'Content-Type':'application/octet-stream'},body:f});const t=await r.text();msg.textContent=(r.ok?'Staged successfully. ':'Rejected. ')+t;await status()}catch(x){msg.textContent='Upload failed: '+x.message}upload.disabled=false}async function reboot(){if(!confirm('Activate the staged image and reboot now?'))return;msg.textContent='Reboot scheduled...';try{const r=await fetch('/api/v1/system/reboot',{method:'POST'});msg.textContent=await r.text()}catch(x){msg.textContent='Reboot request: '+x.message}}status();setInterval(status,5000);</script></body></html>";
    httpd_resp_set_type(request, "text/html; charset=utf-8"); set_security_headers(request);
    return httpd_resp_send(request, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t management_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html>\n"
        "<html lang=\"en\"><head>\n"
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        "<title>ESP32-P4 GNSS NTP/NTS Server</title>\n"
        "<style>\n"
        ":root{color-scheme:dark}*{box-sizing:border-box}\n"
        "body{margin:0;background:#0d141b;color:#e9f0f5;font-family:Arial,sans-serif}\n"
        "header{padding:22px 28px;background:#14212d;border-bottom:1px solid #294252}\n"
        ".headerline{display:flex;align-items:center;gap:20px}.headertitle{min-width:max-content}.headerstatus{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;flex:1;margin-left:auto}\n"
        "h1{margin:0;color:#58c7ff;font-size:1.55rem}header p{margin:7px 0 0;color:#a8bac7;font-size:.92rem}\n"
        "main{padding:22px;max-width:1500px;margin:auto;overflow:hidden}\n"
        ".summary{display:flex;gap:10px;flex-wrap:wrap}\n"
        ".badge{padding:8px 12px;border-radius:999px;font-weight:bold;font-size:.82rem}\n"
        ".ok{background:#173f2b;color:#9bea75}.warn{background:#493b18;color:#ffd569}\n"
        ".bad{background:#4c2226;color:#ff9292}.neutral{background:#223643;color:#a9d8ef}\n"
        ".cardcolumns{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;align-items:start}.cardcol{display:flex;flex-direction:column;gap:16px;min-width:0}\n"
        ".card{background:#14212d;border:1px solid #294252;border-radius:10px;padding:17px;min-width:0;max-width:100%;overflow:hidden}\n"
        ".card h2{margin:0 0 13px;color:#8fdb75;font-size:1.02rem}\n"
        ".row{display:grid;grid-template-columns:minmax(0,44%) minmax(0,56%);gap:14px;padding:9px 0;border-bottom:1px solid #203440;align-items:start}\n"
        ".row:last-child{border-bottom:0}.key{color:#9eb2c0;line-height:1.35;min-width:0}\n"
        ".value{font-family:ui-monospace,Consolas,monospace;text-align:right;line-height:1.35;min-width:0;max-width:100%;overflow-wrap:anywhere;word-break:break-word;white-space:normal}.nowrap{white-space:nowrap;overflow-wrap:normal;word-break:normal;font-size:clamp(.72rem,.85vw,.92rem)}\n"
        ".actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}\n"
        ".backupbar{margin-top:16px}.backupgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.backupnote{color:#ffd569;font-size:.86rem;line-height:1.45}.backupfile{margin-top:10px}.backupstatus{margin-top:10px;color:#a8bac7;white-space:pre-wrap;overflow-wrap:anywhere}\n"
        "button{border:1px solid #3d6175;background:#203b4b;color:#e9f0f5;border-radius:7px;padding:10px 14px;font-weight:bold;cursor:pointer}\n"
        "input{width:100%;background:#0d141b;color:#e9f0f5;border:1px solid #3d6175;border-radius:6px;padding:8px}label.check{display:flex;gap:8px;align-items:center}.peerform{display:grid;gap:8px;margin-top:10px}.peerline{display:grid;grid-template-columns:80px 1fr;gap:8px;align-items:center}button:hover{background:#294d61}button.danger{border-color:#81434a;background:#4c2226}button:disabled{opacity:.55;cursor:not-allowed}\n"
        ".actionmsg{margin-top:12px;color:#a8bac7;overflow-wrap:anywhere}.peers{display:grid;gap:10px;margin-top:12px}.peerbox{border:1px solid #294252;border-radius:8px;padding:11px;background:#101b24}.peerhead{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:7px}.peername{font-weight:bold;color:#c9e8f8}.peerhealth{font-weight:bold;font-size:.78rem;padding:4px 8px;border-radius:999px}.peerhealth.healthy{background:#173f2b;color:#9bea75}.peerhealth.warning,.peerhealth.degraded,.peerhealth.divergent,.peerhealth.kod{background:#493b18;color:#ffd569}.peerhealth.critical,.peerhealth.unreachable,.peerhealth.invalid{background:#4c2226;color:#ff9292}.peerhealth.unknown{background:#223643;color:#a9d8ef}.peerstats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:14px}.peerstats .row{grid-template-columns:minmax(0,46%) minmax(0,54%);padding:6px 0;font-size:.84rem}.peerstats .row>*{min-width:0;overflow-wrap:anywhere;word-break:break-word}.peerstats .row .value,.peerstats .row .v{white-space:normal}.peerstats .row.server-field,.peerstats .row.polls-field{display:flex;flex-direction:column;gap:3px}.peerstats .row.server-field .value,.peerstats .row.polls-field .value{text-align:left;overflow-wrap:normal;word-break:normal}.diag-event{min-width:0;overflow:hidden}.diag-event .peerhead{display:flex;flex-direction:column;align-items:stretch;gap:3px;min-width:0}.diag-event .peername{font-size:.79rem;overflow-wrap:anywhere;min-width:0}.diag-event .event-time{display:block;font-size:.68rem;line-height:1.4;overflow-wrap:anywhere;word-break:break-word;text-align:left;min-width:0;max-width:100%}.diag-event .event-detail{font-size:.78rem;overflow-wrap:anywhere;word-break:break-word}.peernote{margin-top:8px;color:#8ca1ae;font-size:.78rem}\n"
        "footer{padding:22px 0 4px;color:#8ca1ae;font-size:.82rem}code{color:#9bea75;overflow-wrap:anywhere}\n"
        "@media(max-width:1200px){.cardcolumns{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){.cardcolumns,.backupgrid{grid-template-columns:1fr}main{padding:12px}.row{grid-template-columns:1fr;gap:4px}.value{text-align:left}.peerstats{grid-template-columns:1fr}header{padding:18px}.headerline{align-items:flex-start;flex-direction:column}.headerstatus{justify-content:flex-start;margin-left:0}}\n"
        "</style></head><body>\n"
        "<header><div class=\"headerline\"><div class=\"headertitle\"><h1 id=\"pagetitle\">ESP32-P4 GNSS NTP/NTS Server</h1>\n"
        "<p><a href=\"/\" style=\"color:#58c7ff\">Dashboard</a> &middot; <a href=\"/system\" style=\"color:#58c7ff\">System</a> &middot; <a href=\"/management\" style=\"color:#58c7ff\">Management</a> &middot; <a href=\"/diagnostics\" style=\"color:#58c7ff\">Diagnostics</a> &middot; <a href=\"/management/firmware\" style=\"color:#58c7ff\">OTA</a> &middot; mTLS authenticated</p></div>\n"
        "<div class=\"headerstatus\" id=\"summary\"></div></div></header>\n"
        "<main><div id=\"cards\"></div>\n"
        "<section class=\"card backupbar\" id=\"commission-panel\"><h2>Commissioning &amp; Certificate Setup</h2>\n"
        "<div class=\"backupgrid\"><div><label>Device hostname<input id=\"cmhost\" maxlength=\"63\"></label><label>Certificate FQDN<input id=\"cmfqdn\" maxlength=\"253\"></label><label>External NTP 1<input id=\"cmntp0\"></label><label>External NTP 2<input id=\"cmntp1\"></label></div><div><label>Cloudflare zone name<input id=\"cmzone\" maxlength=\"253\" placeholder=\"example.com\"></label><label>Cloudflare Zone ID<input id=\"cmzoneid\" maxlength=\"32\" placeholder=\"32-character Zone ID\"></label><label>Cloudflare API token<input id=\"cmtoken\" type=\"password\" autocomplete=\"new-password\" placeholder=\"Enter only to configure/replace\"></label><p class=\"backupnote\">The token is stored in encrypted NVS and is never returned by the status API.</p><div id=\"cmtime\" class=\"backupstatus\">Management time: loading...</div></div></div>\n"
        "<div class=\"backupgrid\"><div><label><input id=\"netstatic\" type=\"checkbox\"> Static IPv4 address (takes effect after reboot; DHCP when off)</label><label>Address<input id=\"netaddr\" maxlength=\"15\" placeholder=\"192.168.2.55\"></label><label>Netmask<input id=\"netmask\" maxlength=\"15\" placeholder=\"255.255.255.0\"></label></div><div><label>Gateway<input id=\"netgw\" maxlength=\"15\" placeholder=\"192.168.2.254\"></label><label>DNS servers<input id=\"netdns\" maxlength=\"40\" placeholder=\"optional, up to two: 192.168.1.1, 1.1.1.1\"></label><div id=\"netdnsuse\" class=\"backupstatus\"></div><button onclick=\"saveNetwork()\">Save Network</button><div id=\"netmsg\" class=\"backupstatus\"></div></div></div>\n"
        "<div class=\"actions\"><button onclick=\"saveCommissioning()\">Save Identity &amp; External NTP</button><button onclick=\"syncManagementTime()\">Sync Management Time</button><button onclick=\"saveCloudflare()\">Save/Test Cloudflare</button><button onclick=\"requestCertificate()\">Request Certificate</button></div><div id=\"cmmsg\" class=\"backupstatus\"></div>\n"
        "<p class=\"backupnote\">GNSS/GPS is the master civil-time source. If it is unavailable, the dedicated Redundant Time Server is tried first, then External NTP 1 and External NTP 2, for management TLS/ACME wall time only. It never disciplines the Phase 8 clock and cannot make NTP/NTS timing ready or change stratum/LI.</p></section>\n"
        "<section class=\"card backupbar\" id=\"backup-panel\"><h2>Configuration Backup &amp; Restore</h2>\n"
        "<div class=\"backupgrid\"><div><p>Download a complete management configuration backup to this computer.</p><p class=\"backupnote\">Security: the backup can contain the Cloudflare API token. Store it as a secret.</p><div class=\"actions\"><button id=\"backupbtn\" onclick=\"downloadBackup()\">Download Backup</button></div></div>\n"
        "<div><p>Select a backup JSON file. It is validated before the device commits the replacement configuration.</p><input class=\"backupfile\" id=\"restorefile\" type=\"file\" accept=\"application/json,.json\" onchange=\"inspectBackupFile()\"><div class=\"actions\"><button id=\"restorebtn\" class=\"danger\" onclick=\"restoreBackup()\" disabled>Restore Configuration</button></div></div></div><div id=\"backupstatus\" class=\"backupstatus\">No backup operation in progress.</div></section>\n"
        "<section class=\"card backupbar\" id=\"hardware-panel\"><h2>Hardware Profile &amp; GPIO</h2>\n"
        "<p>Carrier-board identity is selected; silicon and eFuse revisions are detected from the ESP32-P4 itself. GPIO changes activate after reboot.</p>\n"
        "<div class=\"backupgrid\"><div><label>Board family<input id=\"hwfamily\" maxlength=\"31\"></label><label>Board revision<input id=\"hwrev\" maxlength=\"15\"></label><label>PPS GPIO<input id=\"hwpps\" type=\"number\"></label></div><div><label>GNSS UART<input id=\"hwuart\" type=\"number\" min=\"0\" max=\"9\"></label><label>GNSS RX GPIO<input id=\"hwrx\" type=\"number\"></label><label>GNSS TX GPIO<input id=\"hwtx\" type=\"number\"></label><label>CPU capability profile<select id=\"hwcpu\"><option value=\"360\">360 MHz compatibility</option><option value=\"400\">400 MHz capable revision</option></select></label></div></div>\n"
        "<p id=\"hwdetected\" class=\"backupstatus\">Detected silicon: loading...</p><div class=\"actions\"><button onclick=\"saveHardware()\">Save Hardware Profile</button></div><div id=\"hwmsg\" class=\"backupstatus\"></div>\n"
        "<p class=\"backupnote\">400 MHz is not enabled by this control. It records revision capability only until that board/silicon combination passes timing qualification. Incorrect GPIO wiring can disable GNSS/PPS, so changes require reboot.</p></section>\n"
        "</main>\n"
        "<script>\n"
        "const pageMode=location.pathname==='/system'?'system':(location.pathname==='/management'?'management':(location.pathname==='/diagnostics'?'diagnostics':'dashboard'));\n"
        "document.getElementById('pagetitle').textContent=pageMode==='dashboard'?'ESP32-P4 GNSS NTP/NTS Server — Dashboard':(pageMode==='system'?'ESP32-P4 GNSS NTP/NTS Server — System':(pageMode==='management'?'ESP32-P4 GNSS NTP/NTS Server — Management':'ESP32-P4 GNSS NTP/NTS Server — Diagnostics'));\n"
        "for(const id of ['commission-panel','backup-panel','hardware-panel'])document.getElementById(id).style.display=pageMode==='management'?'block':'none';\n"
        "function esc(v){return String(v==null||v===''?'--':v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
        "function attr(v){return String(v==null?'':v).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
        "function row(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+'</span><span class=\"value\">'+esc(v)+'</span></div>';}\n"
        "function rowNowrap(k,v){return '<div class=\"row\"><span class=\"key\">'+esc(k)+'</span><span class=\"value nowrap\">'+esc(v)+'</span></div>';}\n"
        "function card(t,r,extra=''){return '<section class=\"card\"><h2>'+esc(t)+'</h2>'+r.join('')+extra+'</section>';}\n"
        "function badge(t,c){return '<span class=\"badge '+c+'\">'+esc(t)+'</span>';}\n"
        "function yesNo(v){return v?'YES':'NO';}\n"
        "function utc(v,valid=true){if(!valid||!v)return '--';try{return new Date(Number(v)*1000).toISOString();}catch(e){return '--';}}\n"
        "function hst(v,valid=true){if(!valid||!v)return '--';try{const d=new Date((Number(v)-36000)*1000);const p=n=>String(n).padStart(2,'0');return d.getUTCFullYear()+'-'+p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds())+' HST';}catch(e){return '--';}}\n"
        "function duration(v){v=Math.max(0,Math.floor(Number(v)||0));const d=Math.floor(v/86400);v%=86400;const h=Math.floor(v/3600);v%=3600;const m=Math.floor(v/60);const sec=v%60;return (d?d+'d ':'')+String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');}\n"
        "function stateClass(s){if(s==='SYNCHRONIZED'||s==='valid')return'ok';if(s==='HOLDOVER'||s==='ACQUIRING'||s==='renewal_due'||s==='urgent')return'warn';return'bad';}\n"
        "async function getJson(url){const r=await fetch(url,{cache:'no-store'});if(!r.ok)throw new Error(url+' HTTP '+r.status);return r.json();}\n"
        "async function getOptionalJson(url,allowedStatus){const r=await fetch(url,{cache:'no-store'});if(r.ok||allowedStatus.includes(r.status))return r.json();throw new Error(url+' HTTP '+r.status);}\n"
        "async function action(url,label){\n"
        " const b=document.getElementById(label);if(b)b.disabled=true;\n"
        " const m=document.getElementById('actionmsg');m.textContent='Working...';\n"
        " try{const r=await fetch(url,{method:'POST',cache:'no-store'});const t=await r.text();\n"
        " m.textContent=(r.ok?'Accepted: ':'Refused: ')+(t||('HTTP '+r.status));}\n"
        " catch(e){m.textContent='Request error: '+e.message;}\n"
        " if(b)b.disabled=false;\n"
        "}\n"
        "function renew(){if(confirm('Request production certificate renewal now? The existing 30-day renewal policy is still enforced.'))action('/api/v1/acme/production/certificate/renew','renewbtn');}\n"
        "function reboot(){if(confirm('Reboot the NTP server now? NTP and management HTTPS will be temporarily unavailable.'))action('/api/v1/system/reboot','rebootbtn');}\n"
        "let selectedBackupText='';\n"
        "async function loadCommissioning(){try{const [c,d]=await Promise.all([getJson('/api/v1/commissioning'),getJson('/api/v1/config')]);document.getElementById('cmhost').value=d.hostname||'';document.getElementById('cmfqdn').value=c.certificate_fqdn||'';for(let i=0;i<2;i++)document.getElementById('cmntp'+i).value=c.ntp_servers[i]||'';document.getElementById('cmzone').value=d.cloudflare_zone_name||'';document.getElementById('cmzoneid').value=d.cloudflare_zone_id||'';if(d.network){const n=d.network,z=v=>v&&v!=='0.0.0.0'?v:'';document.getElementById('netstatic').checked=!!n.static_ipv4_enabled;document.getElementById('netaddr').value=z(n.address);document.getElementById('netmask').value=z(n.netmask);document.getElementById('netgw').value=z(n.gateway);document.getElementById('netdns').value=n.dns||'';document.getElementById('netdnsuse').textContent='In use now: '+(n.dns_in_use||'none')+(n.static_ipv4_enabled?'':' (from DHCP; these fields apply only with a static address)');}document.getElementById('cmtime').textContent='Management time: '+(c.management_time_valid?'VALID via '+c.management_time_source+' / '+c.management_time_server:'NOT VALID');}catch(e){document.getElementById('cmmsg').textContent='Commissioning status error: '+e.message;}}\n"
        "async function saveNetwork(){const m=document.getElementById('netmsg'),en=document.getElementById('netstatic').checked;const body={static_ipv4_enabled:en,address:document.getElementById('netaddr').value.trim(),netmask:document.getElementById('netmask').value.trim(),gateway:document.getElementById('netgw').value.trim(),dns:document.getElementById('netdns').value.trim()};if(en&&!confirm('Save static IPv4 '+body.address+'? It applies at the next reboot; a wrong address makes the console unreachable until it is changed back over the network or serial.'))return;try{const r=await fetch('/api/v1/config/network',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const t=await r.text();if(!r.ok)throw new Error(t);m.textContent=en?'Static IPv4 saved; reboot to apply.':'DHCP selected; reboot to apply.';await loadCommissioning();}catch(e){m.textContent='Save refused: '+e.message;}}\n"
        "async function saveCommissioning(){const m=document.getElementById('cmmsg');try{const h=document.getElementById('cmhost').value.trim(),body={certificate_fqdn:document.getElementById('cmfqdn').value.trim(),ntp0:document.getElementById('cmntp0').value.trim(),ntp1:document.getElementById('cmntp1').value.trim()};let r=await fetch('/api/v1/config/hostname',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({hostname:h})});if(!r.ok)throw new Error('hostname: '+await r.text());r=await fetch('/api/v1/commissioning',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error(await r.text());m.textContent='Identity and External NTP fallback configuration saved.';await loadCommissioning();}catch(e){m.textContent='Save refused: '+e.message;}}\n"
        "async function syncManagementTime(){const m=document.getElementById('cmmsg');m.textContent='Synchronizing management wall time...';try{const r=await fetch('/api/v1/commissioning/time/sync',{method:'POST'});const t=await r.text();if(!r.ok)throw new Error(t);m.textContent='Management wall time synchronized. Timing authority remains GNSS/PPS only.';await loadCommissioning();}catch(e){m.textContent='Management time synchronization failed: '+e.message;}}\n"
        "async function saveCloudflare(){const m=document.getElementById('cmmsg'),token=document.getElementById('cmtoken').value,zone=document.getElementById('cmzone').value.trim(),zoneid=document.getElementById('cmzoneid').value.trim();if(!token){m.textContent='Enter a Cloudflare API token to configure or replace it.';return;}if(!zone){m.textContent='Enter the Cloudflare zone name (for example example.com).';return;}if(zoneid&&!/^[0-9a-fA-F]{32}$/.test(zoneid)){m.textContent='Cloudflare Zone ID must be exactly 32 hexadecimal characters.';return;}try{const r=await fetch('/api/v1/config/cloudflare',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({api_token:token,zone_name:zone,zone_id:zoneid})});const t=await r.text();document.getElementById('cmtoken').value='';if(!r.ok)throw new Error(t);m.textContent='Cloudflare credentials verified and stored.';await loadCommissioning();}catch(e){m.textContent='Cloudflare setup failed: '+e.message;}}\n"
        "async function requestCertificate(){const m=document.getElementById('cmmsg'),h=document.getElementById('cmfqdn').value.trim();if(!h){m.textContent='Set the certificate FQDN first.';return;}m.textContent='Requesting production certificate...';try{const r=await fetch('/api/v1/acme/production/certificate/issue',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hostname:h})});const t=await r.text();if(!r.ok)throw new Error(t);m.textContent='Certificate request completed: '+t;}catch(e){m.textContent='Certificate request failed: '+e.message;}}\n"
        "async function downloadBackup(){const b=document.getElementById('backupbtn'),m=document.getElementById('backupstatus');b.disabled=true;m.textContent='Preparing configuration export...';try{const r=await fetch('/api/v1/config/backup',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status+' '+await r.text());const blob=await r.blob();const cd=r.headers.get('Content-Disposition')||'';const mm=/filename=([^;]+)/i.exec(cd);const name=mm?mm[1].replace(/[\"']/g,''):'esp32p4-config-backup.json';const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);m.textContent='Backup downloaded. Treat the file as a secret because it may contain credentials.';}catch(e){m.textContent='Backup failed: '+e.message;}finally{b.disabled=false;}}\n"
        "async function inspectBackupFile(){const f=document.getElementById('restorefile').files[0],b=document.getElementById('restorebtn'),m=document.getElementById('backupstatus');selectedBackupText='';b.disabled=true;if(!f){m.textContent='No backup selected.';return;}if(f.size<=0||f.size>=8192){m.textContent='Rejected locally: backup size must be between 1 and 8191 bytes.';return;}try{const t=await f.text();const j=JSON.parse(t);const req=['backup_schema_version','hostname','cloudflare_configured','cloudflare_zone_name','cloudflare_zone_id','cloudflare_api_token','peer_monitor_enabled','peer_poll_interval_seconds','peer_response_timeout_ms','redundant_peer_warning_ns','redundant_peer_critical_ns'];for(const k of req)if(!(k in j))throw new Error('missing '+k);for(let i=0;i<3;i++){if(!('peer'+i+'_enabled' in j)||!('peer'+i in j))throw new Error('missing peer '+i+' fields');}if(!('peer4_enabled' in j)||!('peer4' in j))throw new Error('missing redundant peer fields');selectedBackupText=t;b.disabled=false;m.textContent='Backup parsed locally: '+f.name+'. Ready for device-side validation. No changes have been applied.';}catch(e){m.textContent='Rejected locally: '+e.message;}}\n"
        "async function restoreBackup(){const b=document.getElementById('restorebtn'),m=document.getElementById('backupstatus');if(!selectedBackupText){m.textContent='Select and validate a backup first.';return;}if(!confirm('Restore this configuration backup? Current management configuration will be replaced after device-side validation. A reboot is recommended after success.'))return;b.disabled=true;m.textContent='Validating and restoring configuration...';try{const r=await fetch('/api/v1/config/backup',{method:'POST',headers:{'Content-Type':'application/json'},body:selectedBackupText,cache:'no-store'});const t=await r.text();if(!r.ok){m.textContent='Restore rejected: '+(t||('HTTP '+r.status));return;}let j=null;try{j=JSON.parse(t);}catch(e){}m.textContent='Restore committed successfully.'+(j&&j.reboot_recommended?' Reboot is recommended before relying on the restored configuration.':'');}catch(e){m.textContent='Restore request failed: '+e.message;}finally{b.disabled=false;}}\n"
        "let peerFormDirty=false;\n"
        "function peerFieldTarget(e){const x=e.target;if(!x||!x.id)return false;return x.id==='pen'||x.id==='ppoll'||x.id==='ptimeout'||x.id==='pwarn'||x.id==='pcrit'||/^pe[0-3]$/.test(x.id)||/^ps[0-3]$/.test(x.id);}\n"
        "document.addEventListener('focusin',e=>{if(!peerFieldTarget(e))return;const x=e.target;if(/^ps[0-3]$/.test(x.id)&&x.value.trim()==='--'){x.value='';peerFormDirty=true;}});\n"
        "document.addEventListener('input',e=>{if(peerFieldTarget(e))peerFormDirty=true;});\n"
        "document.addEventListener('change',e=>{if(peerFieldTarget(e))peerFormDirty=true;});\n"
        "async function loadHardware(){try{const h=await getJson('/api/v1/hardware/profile');document.getElementById('hwfamily').value=h.board_family;document.getElementById('hwrev').value=h.board_revision;document.getElementById('hwpps').value=h.pps_gpio;document.getElementById('hwuart').value=h.gnss_uart;document.getElementById('hwrx').value=h.gnss_rx_gpio;document.getElementById('hwtx').value=h.gnss_tx_gpio;document.getElementById('hwcpu').value=String(h.requested_cpu_mhz);const wr=h.wafer_revision,er=h.efuse_block_revision;document.getElementById('hwdetected').textContent='Detected silicon: wafer v'+Math.floor(wr/100)+'.'+String(wr%100).padStart(2,'0')+' | eFuse block v'+Math.floor(er/100)+'.'+String(er%100).padStart(2,'0')+' | package '+h.package_version+' | configured CPU '+h.configured_cpu_mhz+' MHz';}catch(e){document.getElementById('hwdetected').textContent='Hardware identity unavailable: '+e.message;}}\n"
        "async function saveHardware(){const m=document.getElementById('hwmsg');const body={board_family:document.getElementById('hwfamily').value.trim(),board_revision:document.getElementById('hwrev').value.trim(),pps_gpio:Number(document.getElementById('hwpps').value),gnss_uart:Number(document.getElementById('hwuart').value),gnss_rx_gpio:Number(document.getElementById('hwrx').value),gnss_tx_gpio:Number(document.getElementById('hwtx').value),requested_cpu_mhz:Number(document.getElementById('hwcpu').value)};if(!confirm('Save this hardware profile? GPIO mapping changes require reboot and incorrect physical wiring can disable GNSS/PPS input.'))return;try{const r=await fetch('/api/v1/hardware/profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const t=await r.text();m.textContent=r.ok?'Saved. Reboot required to activate GPIO mapping.':'Refused: '+t;if(r.ok)loadHardware();}catch(e){m.textContent='Request error: '+e.message;}}\n"
        "async function savePeers(){const m=document.getElementById('peermsg');try{const body={enabled:document.getElementById('pen').checked,poll_interval_seconds:Number(document.getElementById('ppoll').value),response_timeout_ms:Number(document.getElementById('ptimeout').value)};for(let i=0;i<3;i++){body['peer'+i+'_enabled']=document.getElementById('pe'+i).checked;const v=document.getElementById('ps'+i).value.trim();body['peer'+i]=(v==='--'?'':v);}const r=await fetch('/api/v1/config/peer-monitor',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const t=await r.text();m.textContent=(r.ok?'Saved: ':'Refused: ')+(t||('HTTP '+r.status));if(r.ok){peerFormDirty=false;setTimeout(refresh,300);}}catch(e){m.textContent='Request error: '+e.message;}}\n"
        "async function saveRedundant(){const m=document.getElementById('redmsg');try{const body={enabled:document.getElementById('ren').checked,server:document.getElementById('rserver').value.trim(),warning_ns:Math.round(Number(document.getElementById('rwarn').value)*1000),critical_ns:Math.round(Number(document.getElementById('rcrit').value)*1000)};const r=await fetch('/api/v1/config/redundant-server',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const t=await r.text();m.textContent=(r.ok?'Saved: ':'Refused: ')+(t||('HTTP '+r.status));if(r.ok){peerFormDirty=false;setTimeout(refresh,300);}}catch(e){m.textContent='Request error: '+e.message;}}\n"
        "async function storageAction(a,msg,headers){const m=document.getElementById('sdmsg');if(m)m.textContent=msg;try{const r=await fetch('/api/v1/storage/'+a,{method:'POST',headers:headers||{}});const t=await r.text();if(!r.ok)throw new Error(t);if(m)m.textContent=t;setTimeout(refresh,750);}catch(e){if(m)m.textContent='Storage action failed: '+e.message;} }\n"
        "function flushStorage(){storageAction('flush','Queueing archive flush...');}\n"
        "function mountStorage(){storageAction('mount','Requesting mount/retry...');}\n"
        "function unmountStorage(){if(confirm('Safely unmount the SD card? The card will remount on reboot while SD storage is enabled.'))storageAction('unmount','Requesting safe unmount...');}\n"
        "function disableStorage(){if(confirm('Disable SD storage persistently? It will stay disabled after reboot until Mount / Enable is selected.'))storageAction('disable','Disabling SD storage...');}\n"
        "function eraseStorageLogs(){const v=prompt('Erase ALL operational log files from the SD card. Type ERASE to continue:');if(v!=='ERASE'){const m=document.getElementById('sdmsg');if(m)m.textContent='Erase cancelled.';return;}storageAction('erase-logs','Erasing operational logs...',{'X-Confirm-Erase':'ERASE'});}\n"
        "function formatStorage(){const v=prompt('Formatting destroys ALL data on the SD card. Type FORMAT to continue:');if(v!=='FORMAT'){const m=document.getElementById('sdmsg');if(m)m.textContent='Format cancelled.';return;}storageAction('format','Formatting SD card...',{'X-Confirm-Format':'FORMAT'});}\n"
        "async function downloadSDLogs(){try{const r=await fetch('/api/v1/storage/logs',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const data=await r.json();const files=(data.files||[]).map(f=>typeof f==='string'?{name:f,size:null}:f).sort((a,b)=>b.name.localeCompare(a.name));if(!files.length){alert('No SD logs available');return;}let old=document.getElementById('sdlogpicker');if(old)old.remove();const panel=document.createElement('div');panel.id='sdlogpicker';panel.style.cssText='position:fixed;top:5%;bottom:5%;left:50%;transform:translateX(-50%);width:min(760px,90vw);box-sizing:border-box;z-index:10000;background:#152332;color:white;padding:20px;overflow:auto;border:2px solid #8ca6b8;border-radius:8px';const title=document.createElement('h3');title.textContent='SD Operational Logs';panel.appendChild(title);const info=document.createElement('p');info.textContent='Select logs to include in ZIP. Empty files are retained for diagnosis.';panel.appendChild(info);const list=document.createElement('div');panel.appendChild(list);const selected=[];for(const f of files){const line=document.createElement('div');line.style.cssText='display:grid;grid-template-columns:24px minmax(0,1fr) auto;align-items:center;gap:12px;padding:8px 4px;border-bottom:1px solid #53677a';const cb=document.createElement('input');cb.type='checkbox';cb.checked=true;cb.style.cssText='width:16px;height:16px;margin:0;min-width:16px;justify-self:start;';selected.push({cb,f});line.appendChild(cb);const name=document.createElement('span');name.textContent=f.name+' ('+(f.size===null?'size unknown':f.size+' bytes')+')'+(f.size===0?' \u2014 EMPTY':'');name.style.cssText='min-width:0;overflow-wrap:anywhere;text-align:left;';line.appendChild(name);const one=document.createElement('button');one.textContent='Download';one.style.cssText='width:auto;min-width:86px;justify-self:end;';one.onclick=()=>{const boot=Number(f.name.slice(5,13));window.location='/api/v1/storage/log?boot='+boot;};line.appendChild(one);list.appendChild(line);}const controls=document.createElement('div');controls.style.cssText='display:flex;gap:10px;flex-wrap:wrap;margin-top:16px';const add=(text,fn)=>{const b=document.createElement('button');b.textContent=text;b.onclick=fn;controls.appendChild(b);};const downloadZip=all=>{const chosen=all?selected:selected.filter(x=>x.cb.checked);if(!chosen.length){alert('Select at least one log');return;}const boots=chosen.map(x=>String(Number(x.f.name.slice(5,13))));const q=all?'all=1':'boots='+boots.join(',');window.location='/api/v1/storage/logs.zip?'+q;};add('Download Selected (ZIP)',()=>downloadZip(false));add('Download All (ZIP)',()=>downloadZip(true));add('Select All',()=>selected.forEach(x=>x.cb.checked=true));add('Select None',()=>selected.forEach(x=>x.cb.checked=false));add('Close',()=>panel.remove());panel.appendChild(controls);document.body.appendChild(panel);}catch(e){alert('SD log listing failed: '+e.message);}}\n"
        "function downloadStorageDiagnostics(){window.location='/api/v1/storage/diagnostics';}\n"
        "async function copyDiagnosticSummary(){try{const [d,cfg,sd]=await Promise.all([getJson('/api/v1/status'),getJson('/api/v1/config'),getOptionalJson('/api/v1/storage/status',[404])]);const p=d.peer_monitor&&d.peer_monitor.peers?d.peer_monitor.peers[0]:null;const lines=['ESP32-P4 GNSS NTP/NTS Server diagnostic summary','Host: '+(cfg.hostname||'--'),'Uptime: '+(d.system?d.system.uptime_seconds:'--')+' s','GNSS: '+(d.gnss?JSON.stringify(d.gnss):'--'),'PPS: '+(d.pps?JSON.stringify(d.pps):'--'),'NTP: '+(d.ntp?JSON.stringify(d.ntp):'--'),'Redundant peer: '+(p&&p.configured?p.server+' '+p.health+' offset='+p.offset_ns+'ns reach=0x'+Number(p.reachability).toString(16):'disabled'),'Storage: '+(sd?sd.state+' free='+sd.free_bytes:'--'),'Peer timing authority: NONE'];await navigator.clipboard.writeText(lines.join('\\n'));alert('Sanitized diagnostic summary copied.');}catch(e){alert('Copy failed: '+e.message);}}\n"
        "let lastCardInteraction=0;\n"
        "document.addEventListener('pointerdown',e=>{if(e.target.closest('#cards'))lastCardInteraction=Date.now();},true);\n"
        "document.addEventListener('focusin',e=>{if(e.target.closest('#cards'))lastCardInteraction=Date.now();},true);\n"
        "async function refresh(){\n"
        " if(peerFormDirty||Date.now()-lastCardInteraction<8000||document.querySelector('#cards input:focus,#cards button:focus,#cards select:focus,#cards textarea:focus'))return;\n"
        " try{\n"
        /* Sequential on purpose: parallel fetches make the browser open one TLS
         * connection per request, more than the server keeps open, so every
         * refresh forced fresh mTLS handshakes that compete with NTS for the
         * crypto hardware. One request at a time reuses one kept-alive
         * connection. */
        "  const d=await getJson('/api/v1/status');\n"
        "  const cert=await getOptionalJson('/api/v1/acme/production/certificate',[404]);\n"
        "  const sched=await getJson('/api/v1/acme/production/renewal/scheduler');\n"
        "  const cfg=await getJson('/api/v1/config');\n"
        "  const ops=await getJson('/api/v1/operations/history');\n"
        "  const storage=await getOptionalJson('/api/v1/storage/status',[404]);\n"
        "  const summary=[\n"
        "   badge('Clock: '+d.clock.state,stateClass(d.clock.state)),\n"
        "   badge('NTP: '+(d.readiness.ntp_ready?'READY':'NOT READY'),d.readiness.ntp_ready?'ok':'bad'),\n"
        "   badge('GNSS: '+(d.gnss.receiver_model||'IDENTITY PENDING'),d.gnss.receiver_identity_valid?'ok':'warn'),\n"
        "   badge('Certificate: '+(!cert.stored?'NOT CONFIGURED':(cert.certificate_parse_valid?'VALID':'INVALID')),!cert.stored?'warn':(cert.certificate_parse_valid?'ok':'bad')),\n"
        "   badge('Renewal: '+sched.state,stateClass(sched.state))\n"
        "  ];\n"
        "  document.getElementById('summary').innerHTML=summary.join('');\n"
        "  const col1=[]; const col2=[]; const col3=[]; const col4=[];\n"
        "  const certValid=cert.certificate_parse_valid&&cert.hostname_matches_certificate&&cert.private_key_matches_certificate;\n"
        "  col1.push(card('Clock and Time',[\n"
        "   row('State',d.clock.state),row('Disciplined',yesNo(d.clock.solution_valid)),\n"
        "   row('UTC Time',utc(d.readiness.unix_time,d.readiness.clock_now_valid)),\n"
        "   row('Phase Error',d.clock.phase_error_ns+' ns'),row('Frequency',d.clock.frequency_ppm+' ppm'),\n"
        "   row('Samples',d.clock.accepted_samples+' accepted / '+d.clock.rejected_samples+' rejected'),\n"
        "   row('Holdover',d.clock.holdover_seconds+' s')]));\n"
        "  col1.push(card('PPS Capture',[\n"
        "   row('Interval Valid',yesNo(d.pps.valid)),row('Period',d.pps.period_us+' us'),\n"
        "   row('Jitter',d.pps.jitter_us+' us'),row('Last Edge Age',d.pps.age_us+' us'),\n"
        "   row('Captured Edges',d.pps.edge_count),row('Queue Drops',d.pps.queue_drops)]));\n"
        "  col1.push(card('GNSS Receiver',[\n"
        "   row('Receiver Model',d.gnss.receiver_model),\n"
        "   row('Receiver SW',d.gnss.receiver_software_version),\n"
        "   row('Receiver HW',d.gnss.receiver_hardware_version),\n"
        "   row('Identity From UBX',yesNo(d.gnss.receiver_identity_valid)),\n"
        "   row('UTC Valid',yesNo(d.gnss.utc_valid)),row('Fix Valid',yesNo(d.gnss.fix_valid)),\n"
        "   row('Fix Type',d.gnss.fix_type),row('Satellites',d.gnss.satellites),\n"
        "   row('Time Fully Resolved',yesNo(d.gnss.fully_resolved)),\n"
        "   row('Leap State',d.gnss.leap),row('Current Leap Offset',d.gnss.current_leap_seconds+' s'),\n"
        "   row('TIM-TP qErr',d.gnss.timing_qerr_ps+' ps')]));\n"
        "  col4.push(card('Certificate & ACME',[\n"
        "   row('Certificate Valid',yesNo(certValid)),rowNowrap('Hostname',cert.hostname),\n"
        "   row('Valid From',cert.valid_from),row('Valid To',cert.valid_to),\n"
        "   row('Days Remaining',sched.days_remaining),row('Renew Before','30 days'),\n"
        "   row('Scheduler State',sched.state),row('Automatic Renewal',yesNo(sched.automatic_renewal_enabled)),\n"
        "   row('Automatic TLS Activation',yesNo(sched.automatic_tls_activation)),\n"
        "   row('Last Renewal Attempt',utc(sched.last_attempt_unix,sched.last_attempt_unix>0)),\n"
        "   row('Last Attempt Result',sched.last_attempt_result_valid?sched.last_attempt_result:'none'),\n"
        "   row('Last TLS Activation',utc(sched.tls_activation_last_completed_unix,sched.tls_activation_last_result_valid)),\n"
        "   row('Active Slot',cert.production_storage?cert.production_storage.active_slot:'--'),\n"
        "   row('Slot A Valid',cert.production_storage?yesNo(cert.production_storage.slot_a_valid):'--'),\n"
        "   row('Slot B Valid',cert.production_storage?yesNo(cert.production_storage.slot_b_valid):'--'),\n"
        "   row('Leaf SHA-256',cert.leaf_sha256),\n"
        "   row('Running SHA-256',sched.tls_current_leaf_sha256),\n"
        "   row('Activation Intent Pending',yesNo(sched.tls_activation_intent_pending)),\n"
        "   row('Handoff In Progress',yesNo(sched.tls_handoff_in_progress))\n"
        "  ]));\n"
        "  col2.push(card('NTP Service',[\n"
        "   row('UDP Socket Bound',yesNo(d.ntp.socket_bound)),row('Advertised Stratum',d.ntp.advertised_stratum),\n"
        "   row('Leap Indicator',d.ntp.advertised_leap),row('Requests Received',d.ntp.requests),\n"
        "   row('Responses Sent',d.ntp.responses),row('Invalid Requests',d.ntp.invalid_requests),\n"
        "   row('Fail-Closed Drops',d.ntp.unsynchronized_drops),row('RATE KoD Responses',d.ntp.rate_kod),\n"
        "   row('Last Client',d.ntp.last_client)]));\n"
        "  col2.push(card('NTS Service',[\n"
        "   row('NTS-KE Running',yesNo(d.nts.ke_running)),row('NTS-KE Exchanges',d.nts.ke_exchanges),\n"
        "   row('NTS-KE Failures',d.nts.ke_exchange_failures),row('TLS Handshake Failures',d.nts.ke_tls_handshake_failures),\n"
        "   row('ALPN Rejections',d.nts.ke_alpn_rejections),row('Verification Attempts',d.nts.verification_attempts),\n"
        "   row('Authenticated Requests',d.nts.authenticated_requests),row('Verification Failures',d.nts.verification_failures),\n"
        "   row('Protected Responses',d.nts.protected_responses),row('Protection Failures',d.nts.protection_failures)]));\n"
        "  col3.push(card('Network',[\n"
        "   row('Hostname',d.device.hostname),row('IPv4 Address',d.device.ipv4),row('Netmask',d.device.netmask),\n"
        "   row('Gateway',d.device.gateway),row('Ethernet Link',yesNo(d.device.link_up)),row('Ethernet MAC',d.device.mac)]));\n"
        "  const pm=d.peer_monitor,pc=cfg.peer_monitor,rcfg=pc.redundant_server||{},rp=pm.peers&&pm.peers[3]?pm.peers[3]:null,rc=rp?String(rp.health||'UNKNOWN').toLowerCase():'disabled';\n"
        "  const redRows=[row('Peer',rp&&rp.configured?rp.server:(rcfg.server||'Not configured')),row('Reachability',rp&&rp.configured?'0x'+Number(rp.reachability).toString(16).padStart(2,'0'):'--'),row('Resolved IP',rp&&rp.resolved_address?rp.resolved_address:'--'),row('Peer NTP',rp&&rp.configured&&rp.successful_polls>0?(rp.leap===0?'SYNCED':'UNSYNC'):'UNKNOWN'),row('Peer Stratum',rp&&rp.configured?rp.stratum:'--'),row('Clock Difference',rp&&rp.configured&&rp.samples>0?rp.offset_ns+' ns':'--'),row('Last Response',rp&&rp.configured&&rp.successful_polls>0?rp.last_success_age_seconds+' s ago':'--'),row('Status',rp&&rp.configured?rp.health:'DISABLED')];\n"
        "  const redCompact=card('Redundant Time Server',redRows,'<div class=\"peernote\">Independent monitor only — peer has zero timing authority.</div>');\n"
        "  const redDiag=card('Redundant Time Server — Diagnostics',redRows,(rp&&rp.configured?'<div class=\"peerstats\">'+row('Delay',rp.delay_ns+' ns')+row('Jitter',rp.jitter_ns+' ns')+row('Reference ID',rp.reference_id)+row('Rolling Samples',rp.rolling_samples)+row('Polls',rp.successful_polls+' ok / '+rp.failed_polls+' failed')+'</div>':'')+'<div class=\"peernote\">Timing authority: LOCAL GNSS/PPS ONLY — peer timing authority: NONE.</div>');\n"
        "  let pr=[row('Running',yesNo(pm.running)),row('Enabled',yesNo(pm.enabled)),row('Poll Interval',pm.poll_interval_seconds+' s'),row('Response Timeout',pm.response_timeout_ms+' ms'),row('Poll Cycles',pm.poll_cycles),row('Healthy Peers',pm.healthy_peers+' / '+pm.configured_peers),row('Cross-Peer Spread',pm.cross_peer_spread_valid?pm.cross_peer_spread_ns+' ns':'--'),row('Best Observed Peer',pm.best_observed_peer_valid?'Peer '+(pm.best_observed_peer_index+1):'--')];let peerHtml='<div class=\"peers\">';for(const p of (pm.peers||[]).slice(0,3)){if(!p.configured)continue;const hc=String(p.health||'UNKNOWN').toLowerCase();peerHtml+='<div class=\"peerbox\"><div class=\"peerhead\"><span class=\"peername\">Peer '+(p.index+1)+'</span><span class=\"peerhealth '+attr(hc)+'\">'+esc(p.health)+'</span></div><div class=\"peerstats\">'+'<div class=\"row server-field\"><span class=\"key\">Server</span><span class=\"value\">'+esc(p.server)+'</span></div>'+row('Offset',p.offset_ns+' ns')+row('Delay',p.delay_ns+' ns')+row('Jitter',p.jitter_ns+' ns')+row('Reachability','0x'+Number(p.reachability).toString(16).padStart(2,'0'))+row('Stratum',p.stratum)+row('Reference ID',p.reference_id)+row('Rolling Samples',p.rolling_samples)+row('Last Success',p.last_success_age_seconds+' s ago')+'<div class=\"row polls-field\"><span class=\"key\">Polls</span><span class=\"value\">'+esc(p.successful_polls+' ok / '+p.failed_polls+' failed')+'</span></div>'+row('Rejected',p.rejected_responses)+row('Duplicates',p.duplicate_responses)+'</div></div>';}peerHtml+='</div>';let form='<div class=\"peerform\"><label class=\"check\"><input id=\"pen\" type=\"checkbox\" '+(pc.enabled?'checked':'')+'> Enable peer monitoring</label><div class=\"peerline\"><span>Poll (s)</span><input id=\"ppoll\" type=\"number\" min=\"4\" max=\"3600\" value=\"'+pc.poll_interval_seconds+'\"></div><div class=\"peerline\"><span>Timeout</span><input id=\"ptimeout\" type=\"number\" min=\"250\" max=\"10000\" value=\"'+pc.response_timeout_ms+'\"></div>';for(let i=0;i<3;i++){const p=pc.peers[i];form+='<div class=\"peerline\"><label class=\"check\"><input id=\"pe'+i+'\" type=\"checkbox\" '+(p.enabled?'checked':'')+'> Peer '+(i+1)+'</label><input id=\"ps'+i+'\" value=\"'+attr(p.server||'')+'\" placeholder=\"server name or IPv4\"></div>';}form+='<div class=\"actions\"><button onclick=\"savePeers()\">Save Peer Configuration</button></div><div id=\"peermsg\" class=\"actionmsg\">Measurement only; never disciplines the local clock.</div></div>';const peerLive=card('Peer Monitoring',pr,peerHtml);col3.push(card('Peer Monitoring — Configuration',[],form));\n"
        "  const redActive=!!rcfg.enabled&&!!pm.running;const redIndicator='<div class=\"peerhead\"><span>Monitoring status</span><span class=\"peerhealth '+(redActive?'healthy':'unreachable')+'\">'+(redActive?'ACTIVE':'INACTIVE')+'</span></div>';const redForm='<div class=\"peerform\"><label class=\"check\"><input id=\"ren\" type=\"checkbox\" '+(rcfg.enabled?'checked':'')+'> Enable redundant-server monitoring</label><div class=\"peerline\"><span>Peer</span><input id=\"rserver\" value=\"'+attr(rcfg.server||'')+'\" placeholder=\"FQDN or IPv4 address\"></div><div class=\"peerline\"><span>Warn µs</span><input id=\"rwarn\" type=\"number\" min=\"1\" value=\"'+Math.round((rcfg.warning_ns||100000)/1000)+'\"></div><div class=\"peerline\"><span>Critical µs</span><input id=\"rcrit\" type=\"number\" min=\"1\" value=\"'+Math.round((rcfg.critical_ns||1000000)/1000)+'\"></div><div class=\"actions\"><button onclick=\"saveRedundant()\">Save Redundant Server</button></div><div id=\"redmsg\" class=\"actionmsg\">Peer has zero timing authority.</div></div>';col3.push(card('Redundant Time Server',[],redIndicator+redForm));\n"

        "  col2.push(card('API Locations',[\n"
        "   row('Status','/api/v1/status'),row('Health','/api/v1/health'),row('Metrics','/metrics'),row('Operations History','/api/v1/operations/history'),\n"
        "   row('Configuration','GET /api/v1/config'),row('Backup / Restore','GET/POST /api/v1/config/backup'),row('Hostname','PUT /api/v1/config/hostname'),\n"
        "   row('Cloudflare','PUT/DELETE /api/v1/config/cloudflare'),row('Peer Monitor','PUT /api/v1/config/peer-monitor'),row('SD Storage','GET /api/v1/storage/status'),row('OTA Status','GET /api/v1/ota/status'),row('OTA Upload','POST /api/v1/ota/image'),row('OTA Rollback','POST /api/v1/ota/rollback (X-Confirm-Rollback: ROLLBACK)')]));\n"
        "  const resetc=ops.reset_counts||{};let recent='';for(const e of (ops.events||[]).slice(-6).reverse()){recent+='<div class=\"peerbox\"><div class=\"peerhead\"><span class=\"peername\">#'+esc(e.sequence)+' '+esc(e.type)+'</span><span class=\"peerhealth\">boot '+esc(e.boot_id)+'</span></div><div class=\"peerstats\">'+row('Detail',e.detail)+row('Uptime',e.uptime_seconds+' s')+'</div></div>';};\n"
        "  col4.push(card('Operations & Reset History',[row('Boot Count',ops.boot_count),row('Retained Events',ops.event_count+' / '+ops.capacity),row('Overwritten',ops.overwritten_events),row('History Write Failures',ops.storage_write_failures||0),row('History Read Failures',ops.storage_read_failures||0),row('Last Storage Error',ops.last_storage_error||0),row('Last Reset Class',ops.last_reset_class),row('Raw Reset Reason',ops.last_reset_reason),row('Power-on Resets',resetc.power_on||0),row('Software Resets',resetc.software||0),row('Watchdog Resets',resetc.watchdog||0),row('Panic Resets',resetc.panic||0),row('Brownout Resets',resetc.brownout||0)],'<div class=\"peers\">'+recent+'</div>'));\n"
        "  const sd=storage||{};col4.push(card('SD Card / Operational Storage',[row('State',sd.state||'--'),row('Configured',yesNo(!!sd.configured)),row('Mounted',yesNo(!!sd.mounted)),row('Desired Mounted',yesNo(!!sd.desired_mounted)),row('Archive Worker',yesNo(!!sd.worker_running)),row('Card',sd.card_name||'--'),row('Capacity',sd.capacity_bytes?Math.round(sd.capacity_bytes/1048576)+' MiB':'--'),row('Free',sd.free_bytes?Math.round(sd.free_bytes/1048576)+' MiB':'--'),row('Free-space Reserve',sd.reserve_bytes?Math.round(sd.reserve_bytes/1048576)+' MiB':'--'),row('Low Space',yesNo(!!sd.low_space)),row('Archived Events',sd.archived_events||0),row('Bytes Written',sd.bytes_written||0),row('Mount Successes',sd.mount_successes||0),row('Mount Failures',sd.mount_failures||0),row('Remount Attempts',sd.remount_attempts||0),row('Write Failures',sd.write_failures||0),row('Command Queue Drops',sd.command_queue_drops||0),row('Retention Deletes',sd.retention_deleted_files||0),row('Formats',sd.format_count||0),row('Format Failures',sd.format_failures||0),row('Log Erases',sd.erase_count||0),row('Last Error',sd.last_error_name||String(sd.last_error||'OK'))],'<div class=\"actions\"><button onclick=\"flushStorage()\">Flush Archive</button><button onclick=\"mountStorage()\">Mount / Enable</button><button class=\"danger\" onclick=\"unmountStorage()\">Safe Unmount</button><button class=\"danger\" onclick=\"disableStorage()\">Disable SD Storage</button><button onclick=\"downloadStorageDiagnostics()\">Download Diagnostic Bundle</button><button onclick=\"downloadSDLogs()\">Download SD Logs</button><button class=\"danger\" onclick=\"eraseStorageLogs()\">Erase Operational Logs</button></div><h3>Danger Zone</h3><div class=\"actions\"><button class=\"danger\" onclick=\"formatStorage()\">Format SD Card</button></div><div id=\"sdmsg\" class=\"actionmsg\">Operations storage only; never timing authority. Formatting requires explicit FORMAT confirmation.</div>'));\n"
        "  col4.push(card('System Actions',[\n"
        "   row('Uptime',duration(d.system.uptime_seconds)),row('Last Reset',hst(d.system.boot_time_unix,d.system.boot_time_valid)),\n"
        "   row('Reset Reason',d.system.reset_reason),row('Management TLS',d.console.mode),row('Renewal Eligible Now',yesNo(sched.eligible))\n"
        "  ],'<div class=\"actions\"><button id=\"renewbtn\" onclick=\"renew()\">Renew Certificate</button><button id=\"rebootbtn\" class=\"danger\" onclick=\"reboot()\">Reboot Device</button></div><div id=\"actionmsg\" class=\"actionmsg\">Actions require this authenticated mTLS session.</div>'));\n"
        "  const gn=d.gnss||{};const diagGnss=card('GNSS Receiver — Diagnostics',[row('Receiver Model',gn.receiver_model||'--'),row('Receiver SW',gn.receiver_software_version||'--'),row('Receiver HW',gn.receiver_hardware_version||'--'),row('Identity Valid',yesNo(!!gn.receiver_identity_valid)),row('UTC Source',gn.utc_from_ubx_pvt?'UBX-NAV-PVT':'Fallback / unavailable'),row('UTC Valid',yesNo(!!gn.utc_valid)),row('UTC Age',gn.utc_age_us>=0?gn.utc_age_us+' us':'--'),row('Fix Valid',yesNo(!!gn.fix_valid)),row('Fix Type',gn.fix_type),row('Satellites Used',gn.satellites),row('Fully Resolved',yesNo(!!gn.fully_resolved)),row('Leap State',gn.leap),row('Leap Offset',gn.current_leap_seconds+' s'),row('Timing Pulse Valid',yesNo(!!gn.timing_pulse_valid)),row('TIM-TP Age',gn.timing_pulse_age_us>=0?gn.timing_pulse_age_us+' us':'--'),row('TIM-TP qErr',gn.timing_qerr_ps+' ps'),row('UART Bytes',gn.uart_bytes_received||0),row('UBX Frames Valid',gn.ubx_frames_valid||0),row('Bad Checksums',gn.ubx_frames_invalid_checksum||0),row('Bad Lengths',gn.ubx_frames_invalid_length||0),row('Unsupported UBX',gn.ubx_frames_unsupported||0),row('NAV-PVT Messages',gn.ubx_nav_pvt_messages||0),row('NAV-TIMELS Messages',gn.ubx_nav_timels_messages||0),row('TIM-TP Messages',gn.ubx_tim_tp_messages||0),row('Valid ZDA',gn.valid_zda_messages||0),row('Invalid Messages',gn.invalid_messages||0),row('UBX Config Complete',yesNo(!!gn.ubx_configuration_complete)),row('Timepulse Config Complete',yesNo(!!gn.ubx_timepulse_configuration_complete)),row('UBX ACK / NAK',(gn.ubx_ack_count||0)+' / '+(gn.ubx_nak_count||0)),row('Config Failures',gn.ubx_configuration_failures||0)]);\n"
        "  const diagTiming=card('Timing Capture — Diagnostics',[row('Clock State',d.clock.state),row('Solution Valid',yesNo(d.clock.solution_valid)),row('Phase Error',d.clock.phase_error_ns+' ns'),row('Frequency',d.clock.frequency_ppm+' ppm'),row('Accepted / Rejected',d.clock.accepted_samples+' / '+d.clock.rejected_samples),row('Holdover',d.clock.holdover_seconds+' s'),row('PPS Valid',yesNo(d.pps.valid)),row('PPS Period',d.pps.period_us+' us'),row('PPS Jitter',d.pps.jitter_us+' us'),row('PPS Age',d.pps.age_us+' us'),row('PPS Edges',d.pps.edge_count),row('PPS Queue Drops',d.pps.queue_drops)]);\n"
        "  const diagServices=card('NTP / NTS — Diagnostics',[row('NTP Requests',d.ntp.requests),row('NTP Responses',d.ntp.responses),row('Invalid NTP',d.ntp.invalid_requests),row('Unsync Drops',d.ntp.unsynchronized_drops),row('RATE KoD',d.ntp.rate_kod),row('Send Failures',d.ntp.send_failures),row('Socket Failures',d.ntp.socket_failures),row('NTS-KE Exchanges',d.nts.ke_exchanges),row('NTS-KE Failures',d.nts.ke_exchange_failures),row('NTS TLS Failures',d.nts.ke_tls_handshake_failures),row('NTS Verify Failures',d.nts.verification_failures),row('NTS Protection Failures',d.nts.protection_failures),row('NTS NAKs Sent',d.nts.naks_sent),row('Rate-Limited Drops',d.ntp.rate_limited_drops),row('HW RX Drops',d.ntp.hw_rx_drops),row('NTS-KE Deadline Expiries',d.nts.ke_deadline_expirations),row('NTS-KE Rejected (per client / busy / memory)',d.nts.ke_per_client_rejections+' / '+d.nts.ke_busy_rejections+' / '+d.nts.ke_low_memory_rejections),row('NTS-KE Active',d.nts.ke_active_connections),row('TLS Certificate Reloads',d.nts.ke_certificate_reloads),row('TX Compensation',(d.ntp.tx_compensation_ns/1000).toFixed(1)+' \\u00b5s'),row('NTS T3 Bias',(d.ntp.nts_tx_bias_ns/1000).toFixed(1)+' \\u00b5s')]);\n"
        "  const recentDiag=(ops&&ops.events?ops.events.slice(-20).reverse():[]);let recentHtml='<div class=\"peers\">';for(const e of recentDiag){recentHtml+='<div class=\"peerbox diag-event\"><div class=\"peerhead\"><span class=\"peername\">'+esc(e.type)+' #'+e.sequence+'</span><span class=\"event-time\">'+esc(e.unix_time_valid?new Date(e.unix_time*1000).toISOString():'uptime '+e.uptime_seconds+'s')+'</span></div><div class=\"event-detail\">'+esc(e.detail||'')+'</div></div>';}recentHtml+='</div><div class=\"actions\"><button onclick=\"refresh()\">Refresh Now</button><button onclick=\"downloadStorageDiagnostics()\">Download Diagnostic Bundle</button><button onclick=\"copyDiagnosticSummary()\">Copy Summary</button></div>';const diagRecent=card('Recent Faults / State Changes',[row('Events retained',ops?ops.event_count:'--'),row('Overwritten',ops?ops.overwritten_events:'--')],recentHtml);\n"
        "  let pageCols; if(pageMode==='dashboard'){pageCols=[[col1[0],col1[1]],[col2[0],col2[1]],[col3[0],redCompact],[peerLive]];}else if(pageMode==='system'){pageCols=[[col4[3],col2[2]],[col4[1]],[col4[2]],[col4[0]]];}else if(pageMode==='management'){pageCols=[[col3[1]],[col3[2]],[],[]];}else{pageCols=[[diagGnss],[diagTiming],[diagServices,redDiag],[diagRecent]];}\n"
        "  if(Date.now()-lastCardInteraction<8000||document.querySelector('#cards input:focus,#cards button:focus,#cards select:focus,#cards textarea:focus'))return;\n"
        "  document.getElementById('cards').innerHTML=pageCols.length?'<div class=\"cardcolumns\">'+pageCols.map(x=>'<div class=\"cardcol\">'+x.join('')+'</div>').join('')+'</div>':'';\n"
        " }catch(e){\n"
        "  document.getElementById('summary').innerHTML=badge('Console: STATUS UNAVAILABLE','bad');\n"
        "  document.getElementById('cards').innerHTML='<section class=\"card\"><h2>Console Error</h2><p>'+esc(e.message)+'</p></section>';\n"
        " }\n"
        "}\n"
        "if(pageMode==='management'){loadHardware();loadCommissioning();}else{for(const id of ['commission-panel','backup-panel','hardware-panel']){const e=document.getElementById(id);if(e)e.style.display='none';}}\n"
        "let refreshBusy=false;async function refreshTick(){if(refreshBusy)return;refreshBusy=true;try{await refresh();}finally{refreshBusy=false;}}\n"
        "refreshTick();setInterval(refreshTick,3000);\n"
        "</script></body></html>\n";

    httpd_resp_set_type(request, "text/html");
    set_security_headers(request);
    return httpd_resp_send(request, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t provisioning_index_handler(httpd_req_t *request)
{
    static const char html[] =
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP32-P4 Management Enrollment</title></head><body>"
        "<h1>Management enrollment required</h1>"
        "<p>This device has not yet been claimed. Normal management is disabled.</p>"
        "<p>Run the supplied provisioning utility from the computer used to flash the device. "
        "The one-time enrollment code is printed only on the local serial console.</p>"
        "<p>After enrollment the device reboots and this endpoint closes. Normal management then requires mTLS.</p>"
        "</body></html>";
    httpd_resp_set_type(request, "text/html; charset=utf-8");
    set_security_headers(request);
    return httpd_resp_send(request, html, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t provisioning_claim_handler(httpd_req_t *request)
{
    if (management_ownership_is_provisioned())
        return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "not found");
    if (request->content_len <= 0 || request->content_len > MANAGEMENT_OWNERSHIP_CA_MAX_LENGTH)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid CA length");

    char token[MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH + 1U];
    if (httpd_req_get_hdr_value_str(request, "X-Provisioning-Code", token, sizeof(token)) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_401_UNAUTHORIZED, "provisioning code required");
    }
    if (!management_ownership_token_matches(token)) {
        s_provisioning_failures++;
        if (s_provisioning_failures >= 5U) {
            ESP_LOGW(TAG, "Too many invalid ownership enrollment attempts; reboot required for a new code");
            httpd_resp_set_status(request, "429 Too Many Requests");
            return httpd_resp_send(request, "enrollment locked until reboot", HTTPD_RESP_USE_STRLEN);
        }
        return httpd_resp_send_err(request, HTTPD_403_FORBIDDEN, "invalid provisioning code");
    }

    char *body = calloc(1U, (size_t)request->content_len + 1U);
    if (body == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
    size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int r = web_req_recv_bounded(request, body + received, (size_t)request->content_len - received);
        if (r <= 0) { memset(body, 0, (size_t)request->content_len + 1U); free(body); return ESP_FAIL; }
        received += (size_t)r;
    }

    const esp_err_t err = management_ownership_claim(token, body, received);
    memset(body, 0, (size_t)request->content_len + 1U);
    free(body);
    memset(token, 0, sizeof(token));
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid management CA");

    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request,
        "{\"claimed\":true,\"reboot_required\":true,\"management_mode_after_reboot\":\"mtls_authenticated\"}\n",
        HTTPD_RESP_USE_STRLEN);
    if (xTaskCreate(delayed_reboot_task, "claim_reboot", 2048U, NULL, 5U, NULL) != pdPASS)
        ESP_LOGE(TAG, "Ownership claimed but automatic reboot task could not be created");
    return send_err;
}

static const char *operations_event_type_name(uint8_t type)
{
    switch ((operations_event_type_t)type) {
        case OPERATIONS_EVENT_BOOT: return "boot";
        case OPERATIONS_EVENT_CONFIG_CHANGE: return "config_change";
        case OPERATIONS_EVENT_CERTIFICATE: return "certificate";
        case OPERATIONS_EVENT_SECURITY: return "security";
        case OPERATIONS_EVENT_FAULT: return "fault";
        case OPERATIONS_EVENT_RECOVERY: return "recovery";
        default: return "unknown";
    }
}

static size_t json_escape_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0U) return 0U;
    size_t out = 0U;
    if (src == NULL) src = "";
    while (*src != '\0' && out + 1U < dst_size) {
        const unsigned char c = (unsigned char)*src++;
        const char *escape = NULL;
        char unicode_escape[7];
        switch (c) {
            case '"': escape = "\\\""; break;
            case '\\': escape = "\\\\"; break;
            case '\b': escape = "\\b"; break;
            case '\f': escape = "\\f"; break;
            case '\n': escape = "\\n"; break;
            case '\r': escape = "\\r"; break;
            case '\t': escape = "\\t"; break;
            default:
                if (c < 0x20U) {
                    (void)snprintf(unicode_escape, sizeof(unicode_escape), "\\u%04x", (unsigned)c);
                    escape = unicode_escape;
                }
                break;
        }
        if (escape != NULL) {
            const size_t n = strlen(escape);
            if (n >= dst_size - out) break;
            memcpy(dst + out, escape, n);
            out += n;
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
    return out;
}

static esp_err_t operations_history_handler(httpd_req_t *request)
{
    operations_history_status_t status;
    operations_event_t events[OPERATIONS_HISTORY_CAPACITY];
    size_t event_count = 0U;
    esp_err_t err = operations_history_get_status(&status);
    if (err == ESP_OK) err = operations_history_read(events, OPERATIONS_HISTORY_CAPACITY, &event_count);
    if (err != ESP_OK) {
        httpd_resp_set_status(request, "503 Service Unavailable");
        httpd_resp_set_type(request, "text/plain");
        return httpd_resp_send(request, "operations history unavailable", HTTPD_RESP_USE_STRLEN);
    }

    const size_t response_size = 12288U;
    char *response = calloc(1U, response_size);
    if (response == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");

    int length = snprintf(response, response_size,
        "{\"capacity\":%u,\"boot_count\":%" PRIu32 ",\"next_sequence\":%" PRIu32
        ",\"event_count\":%" PRIu32 ",\"overwritten_events\":%" PRIu32
        ",\"storage_write_failures\":%" PRIu32 ",\"storage_read_failures\":%" PRIu32
        ",\"last_storage_error\":%" PRId32
        ",\"last_reset_reason\":%" PRId32 ",\"last_reset_class\":\"%s\""
        ",\"reset_counts\":{\"power_on\":%" PRIu32 ",\"external\":%" PRIu32
        ",\"software\":%" PRIu32 ",\"panic\":%" PRIu32 ",\"watchdog\":%" PRIu32
        ",\"deep_sleep\":%" PRIu32 ",\"brownout\":%" PRIu32 ",\"other\":%" PRIu32 "},\"events\":[",
        (unsigned)OPERATIONS_HISTORY_CAPACITY, status.boot_count, status.next_sequence,
        status.event_count, status.dropped_events, status.write_failures,
        status.read_failures, status.last_storage_error, status.last_reset_reason,
        operations_reset_class_name(status.last_reset_class), status.reset_power_on_count,
        status.reset_external_count, status.reset_software_count, status.reset_panic_count,
        status.reset_watchdog_count, status.reset_deep_sleep_count, status.reset_brownout_count,
        status.reset_other_count);

    for (size_t i = 0U; length >= 0 && (size_t)length < response_size && i < event_count; ++i) {
        char detail[(OPERATIONS_EVENT_DETAIL_MAX * 6U) + 1U];
        (void)json_escape_string(detail, sizeof(detail), events[i].detail);
        const int n = snprintf(response + length, response_size - (size_t)length,
            "%s{\"sequence\":%" PRIu32 ",\"boot_id\":%" PRIu32 ",\"uptime_seconds\":%" PRIu32
            ",\"unix_time\":%" PRId64 ",\"unix_time_valid\":%s,\"type\":\"%s\",\"type_code\":%u,"
            "\"code\":%" PRId32 ",\"detail\":\"%s\"}",
            i ? "," : "", events[i].sequence, events[i].boot_id, events[i].uptime_seconds,
            events[i].unix_time, events[i].unix_time_valid ? "true" : "false",
            operations_event_type_name(events[i].type), (unsigned)events[i].type, events[i].code, detail);
        if (n < 0 || (size_t)n >= response_size - (size_t)length) { length = (int)response_size; break; }
        length += n;
    }
    if (length >= 0 && (size_t)length < response_size) {
        const int n = snprintf(response + length, response_size - (size_t)length, "]}\n");
        if (n < 0 || (size_t)n >= response_size - (size_t)length) length = (int)response_size; else length += n;
    }
    if (length < 0 || (size_t)length >= response_size) {
        free(response);
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "operations history serialization failed");
    }
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    free(response);
    return send_err;
}

typedef struct {
    device_config_backup_t backup;
    char hostname[(APP_DEVICE_HOSTNAME_MAX_LENGTH * 6U) + 1U];
    char zone[(APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH * 6U) + 1U];
    char zone_id[(APP_CLOUDFLARE_ZONE_ID_LENGTH * 6U) + 1U];
    char token[(APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH * 6U) + 1U];
    char fqdn[(COMMISSIONING_FQDN_MAX * 6U) + 1U];
    char ext1[(COMMISSIONING_NTP_SERVER_MAX * 6U) + 1U];
    char ext2[(COMMISSIONING_NTP_SERVER_MAX * 6U) + 1U];
} backup_scratch_t;

static void backup_scratch_free(backup_scratch_t *sc)
{
    if (sc == NULL) return;
    volatile uint8_t *p = (volatile uint8_t *)sc;
    for (size_t i = 0U; i < sizeof(*sc); ++i) p[i] = 0U;
    free(sc);
}

static esp_err_t config_backup_get_handler(httpd_req_t *request)
{
    /* Everything large lives in one heap block: as locals these buffers
     * made a 12.7 KB frame on the 12 KB httpd stack. The block holds the
     * Cloudflare token, so it is wiped before it is freed. */
    backup_scratch_t *sc = calloc(1U, sizeof(*sc));
    if (sc == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
    const esp_err_t err = device_config_export_backup(&sc->backup);
    if (err != ESP_OK) { backup_scratch_free(sc); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration backup unavailable"); }

    (void)json_escape_string(sc->hostname, sizeof(sc->hostname), sc->backup.config.hostname);
    (void)json_escape_string(sc->zone, sizeof(sc->zone), sc->backup.config.cloudflare_zone_name);
    (void)json_escape_string(sc->zone_id, sizeof(sc->zone_id), sc->backup.config.cloudflare_zone_id);
    (void)json_escape_string(sc->token, sizeof(sc->token), sc->backup.cloudflare_api_token);

    char *response = calloc(1U, 8192U);
    if (response == NULL) { backup_scratch_free(sc); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory"); }
    int length = snprintf(response, 8192U,
        "{\"backup_schema_version\":%u,\"device_config_schema_version\":%" PRIu32
        ",\"hostname\":\"%s\",\"cloudflare_configured\":%s,\"cloudflare_zone_name\":\"%s\""
        ",\"cloudflare_zone_id\":\"%s\",\"cloudflare_api_token\":\"%s\""
        ",\"peer_monitor_enabled\":%s,\"peer_poll_interval_seconds\":%" PRIu32
        ",\"peer_response_timeout_ms\":%" PRIu32 ",\"redundant_peer_warning_ns\":%" PRIu32 ",\"redundant_peer_critical_ns\":%" PRIu32,
        (unsigned)sc->backup.backup_schema_version, sc->backup.config.schema_version, sc->hostname,
        sc->backup.config.cloudflare_configured ? "true" : "false", sc->zone, sc->zone_id, sc->token,
        sc->backup.config.ntp_peer_monitor_enabled ? "true" : "false",
        sc->backup.config.ntp_peer_poll_interval_seconds, sc->backup.config.ntp_peer_response_timeout_ms,
        sc->backup.config.redundant_peer_warning_ns, sc->backup.config.redundant_peer_critical_ns);
    if (length >= 0 && length < 8192) {
        const esp_ip4_addr_t b_addr = {.addr = sc->backup.config.static_ipv4_address};
        const esp_ip4_addr_t b_mask = {.addr = sc->backup.config.static_ipv4_netmask};
        const esp_ip4_addr_t b_gw = {.addr = sc->backup.config.static_ipv4_gateway};
        const esp_ip4_addr_t b_dns = {.addr = sc->backup.config.static_ipv4_dns};
        const esp_ip4_addr_t b_dns2 = {.addr = sc->backup.config.static_ipv4_dns2};
        const int n = snprintf(response + length, 8192U - (size_t)length,
            ",\"static_ipv4_enabled\":%s,\"static_ipv4_address\":\"" IPSTR "\",\"static_ipv4_netmask\":\"" IPSTR "\""
            ",\"static_ipv4_gateway\":\"" IPSTR "\",\"static_ipv4_dns\":\"" IPSTR "\",\"static_ipv4_dns2\":\"" IPSTR "\"",
            sc->backup.config.static_ipv4_enabled ? "true" : "false",
            IP2STR(&b_addr), IP2STR(&b_mask), IP2STR(&b_gw), IP2STR(&b_dns), IP2STR(&b_dns2));
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) length = 8192; else length += n;
    }
    hardware_profile_status_t hw_status;
    if (hardware_profile_get_status(&hw_status) != ESP_OK) { free(response); backup_scratch_free(sc); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "hardware profile backup unavailable"); }
    hardware_profile_config_t hw = hw_status.config;
    if (length >= 0 && length < 8192) {
        const int n = snprintf(response + length, 8192U - (size_t)length,
            ",\"hardware_profile_schema_version\":%" PRIu32 ",\"board_family\":\"%s\",\"board_revision\":\"%s\""
            ",\"pps_gpio\":%d,\"gnss_uart\":%d,\"gnss_rx_gpio\":%d,\"gnss_tx_gpio\":%d,\"requested_cpu_mhz\":%" PRIu32
            ",\"source_wafer_revision\":%" PRIu32 ",\"source_efuse_block_revision\":%" PRIu32 ",\"source_package_version\":%" PRIu32,
            hw.schema_version, hw.board_family, hw.board_revision, hw.pps_gpio, hw.gnss_uart_num,
            hw.gnss_rx_gpio, hw.gnss_tx_gpio, hw.requested_cpu_mhz, hw_status.wafer_revision,
            hw_status.efuse_block_revision, hw_status.package_version);
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) length = 8192; else length += n;
    }
    commissioning_config_t cm_backup;
    if (commissioning_get_config(&cm_backup) != ESP_OK) { free(response); backup_scratch_free(sc); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "commissioning backup unavailable"); }
    if (length >= 0 && length < 8192) {
        (void)json_escape_string(sc->fqdn, sizeof(sc->fqdn), cm_backup.certificate_fqdn);
        (void)json_escape_string(sc->ext1, sizeof(sc->ext1), cm_backup.ntp_servers[0]);
        (void)json_escape_string(sc->ext2, sizeof(sc->ext2), cm_backup.ntp_servers[1]);
        const int n = snprintf(response + length, 8192U - (size_t)length,
            ",\"certificate_fqdn\":\"%s\",\"external_ntp_1\":\"%s\",\"external_ntp_2\":\"%s\"",
            sc->fqdn, sc->ext1, sc->ext2);
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) length = 8192; else length += n;
    }
    for (size_t i = 0; length >= 0 && length < 8192 && i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
        char peer[(APP_NTP_PEER_SERVER_MAX_LENGTH * 6U) + 1U];
        (void)json_escape_string(peer, sizeof(peer), sc->backup.config.ntp_peers[i].server);
        const int n = snprintf(response + length, 8192U - (size_t)length,
                               ",\"peer%u_enabled\":%s,\"peer%u\":\"%s\"",
                               (unsigned)i, sc->backup.config.ntp_peers[i].enabled ? "true" : "false",
                               (unsigned)i, peer);
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) { length = 8192; break; }
        length += n;
    }
    if (length >= 0 && length < 8192) {
        char peer[(APP_NTP_PEER_SERVER_MAX_LENGTH * 6U) + 1U];
        const device_config_ntp_peer_t *redundant = &sc->backup.config.ntp_peers[APP_REDUNDANT_PEER_INDEX];
        (void)json_escape_string(peer, sizeof(peer), redundant->server);
        const int n = snprintf(response + length, 8192U - (size_t)length,
                               ",\"peer4_enabled\":%s,\"peer4\":\"%s\"",
                               redundant->enabled ? "true" : "false", peer);
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) length = 8192; else length += n;
    }
    if (length >= 0 && length < 8192) {
        const int n = snprintf(response + length, 8192U - (size_t)length, "}\n");
        if (n < 0 || (size_t)n >= 8192U - (size_t)length) length = 8192; else length += n;
    }
    if (length < 0 || length >= 8192) { free(response); backup_scratch_free(sc); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "backup serialization failed"); }
    (void)operations_history_record(OPERATIONS_EVENT_SECURITY, 0, "config_backup_exported");
    httpd_resp_set_type(request, "application/json");
    httpd_resp_set_hdr(request, "Content-Disposition", "attachment; filename=esp32p4-config-backup.json");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    set_security_headers(request);
    const esp_err_t send_err = httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
    free(response);
    backup_scratch_free(sc);
    return send_err;
}

static esp_err_t config_backup_restore_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= 8192) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid backup body");
    char *body = calloc(1U, (size_t)request->content_len + 1U);
    if (body == NULL) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
    size_t received = 0U;
    while (received < (size_t)request->content_len) {
        const int r = web_req_recv_bounded(request, body + received, (size_t)request->content_len - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) { free(body); return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "backup receive failed"); }
        received += (size_t)r;
    }

    device_config_backup_t backup;
    memset(&backup, 0, sizeof(backup));
    uint32_t backup_schema = 0U;
    bool cf_configured = false;
    bool peer_enabled = false;
    bool valid = json_get_u32(body, "backup_schema_version", &backup_schema) &&
                 json_get_string(body, "hostname", backup.config.hostname, sizeof(backup.config.hostname)) &&
                 json_get_bool(body, "cloudflare_configured", &cf_configured) &&
                 json_get_string(body, "cloudflare_zone_name", backup.config.cloudflare_zone_name, sizeof(backup.config.cloudflare_zone_name)) &&
                 json_get_string(body, "cloudflare_zone_id", backup.config.cloudflare_zone_id, sizeof(backup.config.cloudflare_zone_id)) &&
                 json_get_string(body, "cloudflare_api_token", backup.cloudflare_api_token, sizeof(backup.cloudflare_api_token)) &&
                 json_get_bool(body, "peer_monitor_enabled", &peer_enabled) &&
                 json_get_u32(body, "peer_poll_interval_seconds", &backup.config.ntp_peer_poll_interval_seconds) &&
                 json_get_u32(body, "peer_response_timeout_ms", &backup.config.ntp_peer_response_timeout_ms) &&
                 json_get_u32(body, "redundant_peer_warning_ns", &backup.config.redundant_peer_warning_ns) &&
                 json_get_u32(body, "redundant_peer_critical_ns", &backup.config.redundant_peer_critical_ns);
    backup.backup_schema_version = backup_schema;
    backup.config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    backup.config.cloudflare_configured = cf_configured;
    backup.config.ntp_peer_monitor_enabled = peer_enabled;
    for (size_t i = 0; valid && i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
        char enabled_key[24]; char peer_key[16];
        (void)snprintf(enabled_key, sizeof(enabled_key), "peer%u_enabled", (unsigned)i);
        (void)snprintf(peer_key, sizeof(peer_key), "peer%u", (unsigned)i);
        valid = json_get_bool(body, enabled_key, &backup.config.ntp_peers[i].enabled) &&
                json_get_string(body, peer_key, backup.config.ntp_peers[i].server, sizeof(backup.config.ntp_peers[i].server));
    }
    if (valid && strstr(body, "\"peer4_enabled\"") != NULL) {
        valid = json_get_bool(body, "peer4_enabled", &backup.config.ntp_peers[APP_REDUNDANT_PEER_INDEX].enabled) &&
                json_get_string(body, "peer4", backup.config.ntp_peers[APP_REDUNDANT_PEER_INDEX].server,
                                sizeof(backup.config.ntp_peers[APP_REDUNDANT_PEER_INDEX].server));
    }
    if (valid && strstr(body, "\"static_ipv4_enabled\"") != NULL) {
        char ip_text[4][16] = {{0}};
        valid = json_get_bool(body, "static_ipv4_enabled", &backup.config.static_ipv4_enabled) &&
                json_get_string(body, "static_ipv4_address", ip_text[0], sizeof(ip_text[0])) &&
                json_get_string(body, "static_ipv4_netmask", ip_text[1], sizeof(ip_text[1])) &&
                json_get_string(body, "static_ipv4_gateway", ip_text[2], sizeof(ip_text[2])) &&
                json_get_string(body, "static_ipv4_dns", ip_text[3], sizeof(ip_text[3])) &&
                parse_ipv4_text(ip_text[0], &backup.config.static_ipv4_address) &&
                parse_ipv4_text(ip_text[1], &backup.config.static_ipv4_netmask) &&
                parse_ipv4_text(ip_text[2], &backup.config.static_ipv4_gateway) &&
                parse_ipv4_text(ip_text[3], &backup.config.static_ipv4_dns);
        char dns2_text[16] = {0};
        /* Optional: backups from before 3.1.11 have no backup DNS server. */
        if (valid && json_get_string(body, "static_ipv4_dns2", dns2_text, sizeof(dns2_text)))
            valid = parse_ipv4_text(dns2_text, &backup.config.static_ipv4_dns2);
    }
    hardware_profile_config_t hw;
    memset(&hw, 0, sizeof(hw));
    uint32_t hw_schema=0U, pps=0U, uart=0U, rx=0U, tx=0U, cpu=0U;
    valid = valid && json_get_u32(body, "hardware_profile_schema_version", &hw_schema) &&
            json_get_string(body, "board_family", hw.board_family, sizeof(hw.board_family)) &&
            json_get_string(body, "board_revision", hw.board_revision, sizeof(hw.board_revision)) &&
            json_get_u32(body, "pps_gpio", &pps) && json_get_u32(body, "gnss_uart", &uart) &&
            json_get_u32(body, "gnss_rx_gpio", &rx) && json_get_u32(body, "gnss_tx_gpio", &tx) &&
            json_get_u32(body, "requested_cpu_mhz", &cpu);
    hw.schema_version=hw_schema; hw.pps_gpio=(int)pps; hw.gnss_uart_num=(int)uart;
    hw.gnss_rx_gpio=(int)rx; hw.gnss_tx_gpio=(int)tx; hw.requested_cpu_mhz=cpu;
    if (valid && (hw.schema_version != APP_HW_PROFILE_SCHEMA_VERSION || hardware_profile_validate(&hw) != ESP_OK)) valid=false;

    commissioning_config_t cm_restore;
    memset(&cm_restore, 0, sizeof(cm_restore));
    const bool has_cm = strstr(body, "\"certificate_fqdn\"") != NULL;
    if (has_cm) {
        valid = valid && json_get_string(body, "certificate_fqdn", cm_restore.certificate_fqdn, sizeof(cm_restore.certificate_fqdn)) &&
                json_get_string(body, "external_ntp_1", cm_restore.ntp_servers[0], sizeof(cm_restore.ntp_servers[0])) &&
                json_get_string(body, "external_ntp_2", cm_restore.ntp_servers[1], sizeof(cm_restore.ntp_servers[1]));
    }

    /* New backups carry detected silicon identity. Reject a blind restore onto
     * different silicon; legacy backups remain accepted for compatibility. */
    if (valid && strstr(body, "\"source_wafer_revision\"") != NULL) {
        uint32_t src_wafer=0U, src_efuse=0U, src_package=0U;
        hardware_profile_status_t current_hw;
        valid = json_get_u32(body, "source_wafer_revision", &src_wafer) &&
                json_get_u32(body, "source_efuse_block_revision", &src_efuse) &&
                json_get_u32(body, "source_package_version", &src_package) &&
                hardware_profile_get_status(&current_hw) == ESP_OK &&
                src_wafer == current_hw.wafer_revision &&
                src_efuse == current_hw.efuse_block_revision &&
                src_package == current_hw.package_version;
        if (!valid)
            (void)operations_history_record(OPERATIONS_EVENT_SECURITY, ESP_ERR_INVALID_ARG, "config_restore_rejected_hardware_identity");
    }
    free(body);
    if (!valid) {
        (void)operations_history_record(OPERATIONS_EVENT_SECURITY, ESP_ERR_INVALID_ARG, "config_restore_rejected_parse");
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid configuration backup");
    }
    const esp_err_t err = device_config_restore_backup(&backup);
    if (err == ESP_ERR_INVALID_ARG) {
        (void)operations_history_record(OPERATIONS_EVENT_SECURITY, err, "config_restore_rejected_validation");
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "configuration backup validation failed");
    }
    if (err != ESP_OK) {
        (void)operations_history_record(OPERATIONS_EVENT_FAULT, err, "config_restore_commit_failed");
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "configuration restore commit failed");
    }
    const esp_err_t hw_err = hardware_profile_set_config(&hw);
    if (hw_err != ESP_OK) {
        (void)operations_history_record(OPERATIONS_EVENT_FAULT, hw_err, "hardware_profile_restore_commit_failed");
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "management configuration restored but hardware profile commit failed");
    }
    if (has_cm) {
        const esp_err_t cm_err = commissioning_set_config(&cm_restore);
        if (cm_err != ESP_OK) {
            (void)operations_history_record(OPERATIONS_EVENT_FAULT, cm_err, "commissioning_restore_commit_failed");
            return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "management configuration restored but commissioning fallback commit failed");
        }
    }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "config_backup_restored_with_hardware_profile_and_commissioning");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, "{\"restored\":true,\"reboot_recommended\":true}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t status_handler(httpd_req_t *request)
{
    return send_status_json(request);
}

static esp_err_t storage_status_handler(httpd_req_t *request)
{
    sd_storage_status_t st;
    const esp_err_t err = sd_storage_get_status(&st);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "storage status unavailable");
    char json[1280];
    const int n = snprintf(json, sizeof(json),
        "{\"configured\":%s,\"mounted\":%s,\"worker_running\":%s,\"desired_mounted\":%s,\"low_space\":%s,"
        "\"state\":\"%s\",\"capacity_bytes\":%" PRIu64 ",\"free_bytes\":%" PRIu64 ",\"reserve_bytes\":%" PRIu64 ","
        "\"bytes_written\":%" PRIu64 ",\"archived_events\":%" PRIu32 ",\"write_failures\":%" PRIu32 ","
        "\"command_queue_drops\":%" PRIu32 ",\"mount_failures\":%" PRIu32 ",\"mount_successes\":%" PRIu32 ",\"remount_attempts\":%" PRIu32 ","
        "\"retention_deleted_files\":%" PRIu32 ",\"format_count\":%" PRIu32 ",\"format_failures\":%" PRIu32 ","
        "\"erase_count\":%" PRIu32 ",\"last_format_result\":%" PRId32 ",\"last_error\":%" PRId32 ",\"last_error_name\":\"%s\","
        "\"card_name\":\"%s\",\"mount_point\":\"%s\"}\n",
        st.configured ? "true" : "false", st.mounted ? "true" : "false", st.worker_running ? "true" : "false",
        st.desired_mounted ? "true" : "false", st.low_space ? "true" : "false", sd_storage_state_name(st.state),
        st.capacity_bytes, st.free_bytes, st.reserve_bytes, st.bytes_written, st.archived_events, st.write_failures,
        st.command_queue_drops, st.mount_failures, st.mount_successes, st.remount_attempts, st.retention_deleted_files,
        st.format_count, st.format_failures, st.erase_count, st.last_format_result, st.last_error,
        esp_err_to_name((esp_err_t)st.last_error), st.card_name, st.mount_point);
    if (n < 0 || (size_t)n >= sizeof(json)) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "storage status serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, json, n);
}

static esp_err_t storage_flush_handler(httpd_req_t *request)
{
    const esp_err_t err = sd_storage_request_flush();
    if (err != ESP_OK) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "SD storage command queue unavailable", HTTPD_RESP_USE_STRLEN);
    }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_archive_flush_requested");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"flush\"}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t storage_mount_handler(httpd_req_t *request)
{
    const esp_err_t err = sd_storage_request_mount();
    if (err != ESP_OK) { httpd_resp_set_status(request, "409 Conflict"); return httpd_resp_send(request, "mount request not accepted", HTTPD_RESP_USE_STRLEN); }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_mount_requested");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"mount\"}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t storage_unmount_handler(httpd_req_t *request)
{
    const esp_err_t err = sd_storage_request_unmount();
    if (err != ESP_OK) { httpd_resp_set_status(request, "409 Conflict"); return httpd_resp_send(request, "unmount request not accepted", HTTPD_RESP_USE_STRLEN); }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_safe_unmount_requested");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"unmount\"}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t storage_disable_handler(httpd_req_t *request)
{
    const esp_err_t err = sd_storage_request_disable();
    if (err != ESP_OK) { httpd_resp_set_status(request, "409 Conflict"); return httpd_resp_send(request, "disable request not accepted", HTTPD_RESP_USE_STRLEN); }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_disable_requested");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"disable\"}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t storage_erase_logs_handler(httpd_req_t *request)
{
    char confirm[16] = {0};
    if (httpd_req_get_hdr_value_str(request, "X-Confirm-Erase", confirm, sizeof(confirm)) != ESP_OK || strcmp(confirm, "ERASE") != 0) {
        httpd_resp_set_status(request, "412 Precondition Failed");
        return httpd_resp_send(request, "explicit ERASE confirmation required", HTTPD_RESP_USE_STRLEN);
    }
    ota_manager_status_t ota;
    if (ota_manager_get_status(&ota) == ESP_OK && ota.update_in_progress) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "storage erase unavailable during OTA upload", HTTPD_RESP_USE_STRLEN);
    }
    const esp_err_t err = sd_storage_request_erase_logs();
    if (err != ESP_OK) { httpd_resp_set_status(request, "409 Conflict"); return httpd_resp_send(request, "erase request not accepted", HTTPD_RESP_USE_STRLEN); }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_operational_logs_erase_requested");
    httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"erase_logs\"}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t storage_format_handler(httpd_req_t *request)
{
    ota_manager_status_t ota;
    if (ota_manager_get_status(&ota) == ESP_OK && ota.update_in_progress) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "storage format unavailable during OTA upload", HTTPD_RESP_USE_STRLEN);
    }
    char confirm[16] = {0};
    if (httpd_req_get_hdr_value_str(request, "X-Confirm-Format", confirm, sizeof(confirm)) != ESP_OK || strcmp(confirm, "FORMAT") != 0) {
        httpd_resp_set_status(request, "412 Precondition Failed");
        return httpd_resp_send(request, "explicit FORMAT confirmation required", HTTPD_RESP_USE_STRLEN);
    }
    const esp_err_t err = sd_storage_request_format();
    if (err != ESP_OK) { httpd_resp_set_status(request, "409 Conflict"); return httpd_resp_send(request, "format request not accepted", HTTPD_RESP_USE_STRLEN); }
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "sd_format_requested_by_authenticated_admin");
    httpd_resp_set_status(request, "202 Accepted"); httpd_resp_set_type(request, "application/json"); set_security_headers(request);
    return httpd_resp_send(request, "{\"accepted\":true,\"action\":\"format\",\"destructive\":true}\n", HTTPD_RESP_USE_STRLEN);
}

/* Authenticated HTTPS management endpoint: bounded SD log listing and download.
 * The URI is fixed and the boot identifier is parsed as a decimal integer;
 * clients cannot supply a filesystem path. No log file is buffered in RAM.
 */
#define SD_LOG_EXPORT_MAX 64U

typedef struct { uint32_t boot; uint32_t size; } sd_export_file_t;

static bool parse_sd_log_name(const char *name, uint32_t *boot)
{
    if (strlen(name) != 19 || strncmp(name, "boot-", 5) != 0 || strcmp(name + 13, ".jsonl") != 0) return false;
    uint32_t n = 0;
    for (int i = 5; i < 13; ++i) {
        if (name[i] < '0' || name[i] > '9') return false;
        n = n * 10U + (uint32_t)(name[i] - '0');
    }
    *boot = n;
    return true;
}

static esp_err_t storage_logs_handler(httpd_req_t *request)
{
    sd_storage_status_t st;
    if (sd_storage_get_status(&st) != ESP_OK || !st.mounted) {
        httpd_resp_set_status(request, "503 Service Unavailable");
        return httpd_resp_send(request, "SD card not mounted", HTTPD_RESP_USE_STRLEN);
    }
    DIR *dir = opendir("/sdcard/logs");
    if (!dir) return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "No SD logs");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    if (httpd_resp_send_chunk(request, "{\"files\":[", 10) != ESP_OK) { closedir(dir); return ESP_FAIL; }
    bool first = true;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        uint32_t boot;
        if (!parse_sd_log_name(entry->d_name, &boot)) continue;
        char path[96];
        snprintf(path, sizeof(path), "/sdcard/logs/boot-%08" PRIu32 ".jsonl", boot);
        struct stat statbuf;
        if (stat(path, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) continue;
        char item[144];
        int n = snprintf(item, sizeof(item), "%s{\"name\":\"boot-%08" PRIu32 ".jsonl\",\"size\":%" PRIu64 "}",
                         first ? "" : ",", boot, (uint64_t)statbuf.st_size);
        if (n < 0 || n >= (int)sizeof(item) || httpd_resp_send_chunk(request, item, n) != ESP_OK) {
            closedir(dir); return ESP_FAIL;
        }
        first = false;
    }
    closedir(dir);
    if (httpd_resp_send_chunk(request, "]}\n", 3) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(request, NULL, 0);
}

/* ZIP32 store-only streaming with data descriptors: no SD log buffering in RAM. */
static uint32_t sd_zip_crc32(uint32_t crc, const uint8_t *data, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return crc;
}

static void sd_zip_le16(uint8_t *p, uint16_t n) { p[0] = n & 255; p[1] = n >> 8; }
static void sd_zip_le32(uint8_t *p, uint32_t n) { sd_zip_le16(p, n & 65535U); sd_zip_le16(p + 2, n >> 16); }
static esp_err_t sd_zip_send(httpd_req_t *req, const void *p, size_t n, uint32_t *offset)
{
    if (UINT32_MAX - *offset < n) return ESP_FAIL;
    esp_err_t err = httpd_resp_send_chunk(req, p, n);
    if (err == ESP_OK) *offset += (uint32_t)n;
    return err;
}

static esp_err_t storage_logs_zip_handler(httpd_req_t *request)
{
    sd_storage_status_t st;
    if (sd_storage_get_status(&st) != ESP_OK || !st.mounted) {
        httpd_resp_set_status(request, "503 Service Unavailable");
        return httpd_resp_send(request, "SD card not mounted", HTTPD_RESP_USE_STRLEN);
    }
    char query[512] = {0}, chosen[440] = {0};
    bool all = false;
    if (httpd_req_get_url_query_str(request, query, sizeof(query)) == ESP_OK) {
        char v[8];
        all = httpd_query_key_value(query, "all", v, sizeof(v)) == ESP_OK && strcmp(v, "1") == 0;
        if (!all && httpd_query_key_value(query, "boots", chosen, sizeof(chosen)) != ESP_OK)
            return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "boots or all required");
    } else return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "query required");
    uint32_t requested[SD_LOG_EXPORT_MAX]; size_t requested_count = 0;
    if (!all) {
        char *cursor = chosen;
        while (*cursor) {
            if (requested_count == SD_LOG_EXPORT_MAX) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "too many logs");
            errno = 0; char *end; unsigned long n = strtoul(cursor, &end, 10);
            if (errno || end == cursor || n > UINT32_MAX || (*end != ',' && *end != '\0'))
                return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid boot list");
            requested[requested_count++] = (uint32_t)n;
            cursor = *end ? end + 1 : end;
        }
        if (!requested_count) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "empty selection");
    }
    sd_export_file_t *files = calloc(SD_LOG_EXPORT_MAX, sizeof(*files));
    if (!files) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
    size_t count = 0;
    DIR *dir = opendir("/sdcard/logs");
    if (!dir) { free(files); return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "No SD logs"); }
    struct dirent *de;
    bool overflow = false;
    while ((de = readdir(dir))) {
        uint32_t boot;
        if (!parse_sd_log_name(de->d_name, &boot)) continue;
        bool include = all;
        for (size_t i = 0; !include && i < requested_count; ++i) include = requested[i] == boot;
        if (!include) continue;
        char path[96]; snprintf(path, sizeof(path), "/sdcard/logs/boot-%08" PRIu32 ".jsonl", boot);
        struct stat sb;
        if (stat(path, &sb) || !S_ISREG(sb.st_mode) || sb.st_size < 0 || (uint64_t)sb.st_size > UINT32_MAX) continue;
        if (count == SD_LOG_EXPORT_MAX) { overflow = true; break; }
        files[count++] = (sd_export_file_t){.boot = boot, .size = (uint32_t)sb.st_size};
    }
    closedir(dir);
    if (overflow || count == 0) {
        free(files);
        return httpd_resp_send_err(request, overflow ? HTTPD_500_INTERNAL_SERVER_ERROR : HTTPD_404_NOT_FOUND,
                                   overflow ? "Too many logs for ZIP export" : "No matching logs");
    }
    /* Sort for reproducible ZIP entry order. */
    for (size_t i = 0; i < count; ++i)
        for (size_t j = i + 1; j < count; ++j)
            if (files[j].boot < files[i].boot) { sd_export_file_t tmp = files[i]; files[i] = files[j]; files[j] = tmp; }
    /* Preflight all files before sending headers, to avoid a silently partial ZIP. */
    for (size_t i = 0; i < count; ++i) {
        char path[96]; snprintf(path, sizeof(path), "/sdcard/logs/boot-%08" PRIu32 ".jsonl", files[i].boot);
        FILE *fp = fopen(path, "rb");
        if (!fp) { free(files); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "Log unavailable"); }
        fclose(fp);
    }
    httpd_resp_set_type(request, "application/zip");
    httpd_resp_set_hdr(request, "Content-Disposition", "attachment; filename=ts2-sd-logs.zip");
    set_security_headers(request);
    uint32_t offset = 0;
    uint32_t *positions = calloc(count, sizeof(uint32_t));
    uint32_t *crcs = calloc(count, sizeof(uint32_t));
    if (!positions || !crcs) { free(positions); free(crcs); free(files); return ESP_ERR_NO_MEM; }
    esp_err_t err = ESP_OK;
    uint8_t header[46], buf[1024];
    for (size_t i = 0; i < count && err == ESP_OK; ++i) {
        char name[32], path[96];
        int len = snprintf(name, sizeof(name), "boot-%08" PRIu32 ".jsonl", files[i].boot);
        snprintf(path, sizeof(path), "/sdcard/logs/%s", name);
        FILE *fp = fopen(path, "rb");
        if (!fp) { err = ESP_FAIL; break; }
        positions[i] = offset;
        memset(header, 0, 30); sd_zip_le32(header, 0x04034b50U);
        sd_zip_le16(header + 4, 20); sd_zip_le16(header + 6, 8); /* descriptor */
        sd_zip_le16(header + 26, (uint16_t)len);
        err = sd_zip_send(request, header, 30, &offset);
        if (err == ESP_OK) err = sd_zip_send(request, name, len, &offset);
        uint32_t crc = 0xffffffffU, bytes = 0;
        size_t n;
        while (err == ESP_OK && (n = fread(buf, 1, sizeof(buf), fp)) > 0) {
            crc = sd_zip_crc32(crc, buf, n);
            bytes += (uint32_t)n;
            err = sd_zip_send(request, buf, n, &offset);
        }
        if (ferror(fp)) err = ESP_FAIL;
        fclose(fp);
        if (bytes != files[i].size) err = ESP_FAIL; /* log changed while downloading */
        crcs[i] = crc ^ 0xffffffffU;
        if (err != ESP_OK) break;
        uint8_t dd[16]; sd_zip_le32(dd, 0x08074b50U); sd_zip_le32(dd + 4, crcs[i]);
        sd_zip_le32(dd + 8, bytes); sd_zip_le32(dd + 12, bytes);
        err = sd_zip_send(request, dd, sizeof(dd), &offset);
    }
    uint32_t central_start = offset;
    for (size_t i = 0; i < count && err == ESP_OK; ++i) {
        char name[32]; int len = snprintf(name, sizeof(name), "boot-%08" PRIu32 ".jsonl", files[i].boot);
        memset(header, 0, sizeof(header)); sd_zip_le32(header, 0x02014b50U);
        sd_zip_le16(header + 4, 20); sd_zip_le16(header + 6, 20); sd_zip_le16(header + 8, 8);
        sd_zip_le32(header + 16, crcs[i]); sd_zip_le32(header + 20, files[i].size);
        sd_zip_le32(header + 24, files[i].size); sd_zip_le16(header + 28, (uint16_t)len);
        sd_zip_le32(header + 42, positions[i]);
        err = sd_zip_send(request, header, sizeof(header), &offset);
        if (err == ESP_OK) err = sd_zip_send(request, name, len, &offset);
    }
    if (err == ESP_OK) {
        uint8_t eocd[22] = {0}; sd_zip_le32(eocd, 0x06054b50U);
        sd_zip_le16(eocd + 8, (uint16_t)count); sd_zip_le16(eocd + 10, (uint16_t)count);
        sd_zip_le32(eocd + 12, offset - central_start); sd_zip_le32(eocd + 16, central_start);
        err = sd_zip_send(request, eocd, sizeof(eocd), &offset);
    }
    if (err == ESP_OK) err = httpd_resp_send_chunk(request, NULL, 0);
    free(positions); free(crcs); free(files);
    return err;
}

static esp_err_t storage_log_download_handler(httpd_req_t *request)
{
    sd_storage_status_t st;
    if (sd_storage_get_status(&st) != ESP_OK || !st.mounted)
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "SD card not mounted");
    char query[64];
    char boot_str[20];
    if (httpd_req_get_url_query_str(request, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "boot", boot_str, sizeof(boot_str)) != ESP_OK)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "boot query required");
    if (!boot_str[0]) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid boot");
    for (const char *p = boot_str; *p; ++p)
        if (*p < '0' || *p > '9') return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid boot");
    errno = 0;
    char *end = NULL;
    unsigned long boot = strtoul(boot_str, &end, 10);
    if (errno != 0 || *end || boot > UINT32_MAX)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid boot");
    char path[96], disposition[96];
    snprintf(path, sizeof(path), "/sdcard/logs/boot-%08" PRIu32 ".jsonl", (uint32_t)boot);
    FILE *fp = fopen(path, "rb");
    if (!fp) return httpd_resp_send_err(request, HTTPD_404_NOT_FOUND, "log not found");
    snprintf(disposition, sizeof(disposition), "attachment; filename=boot-%08" PRIu32 ".jsonl", (uint32_t)boot);
    httpd_resp_set_type(request, "application/x-ndjson");
    httpd_resp_set_hdr(request, "Content-Disposition", disposition);
    set_security_headers(request);
    char buf[1024];
    size_t n;
    esp_err_t result = ESP_OK;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (httpd_resp_send_chunk(request, buf, n) != ESP_OK) { result = ESP_FAIL; break; }
    }
    if (ferror(fp)) result = ESP_FAIL;
    fclose(fp);
    if (result == ESP_OK) result = httpd_resp_send_chunk(request, NULL, 0);
    return result;
}

static esp_err_t storage_diagnostics_handler(httpd_req_t *request)
{
    sd_storage_status_t st;
    operations_history_status_t hs;
    device_config_snapshot_t cfg;
    operations_event_t events[OPERATIONS_HISTORY_CAPACITY];
    size_t count = 0;
    if (sd_storage_get_status(&st) != ESP_OK || operations_history_get_status(&hs) != ESP_OK ||
        device_config_get_snapshot(&cfg) != ESP_OK || operations_history_read(events, OPERATIONS_HISTORY_CAPACITY, &count) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "diagnostics unavailable");
    }
    httpd_resp_set_type(request, "application/json");
    httpd_resp_set_hdr(request, "Content-Disposition", "attachment; filename=esp32p4-diagnostics.json");
    set_security_headers(request);
    char b[768];
    int n = snprintf(b, sizeof(b), "{\"schema\":1,\"sanitized\":true,\"secrets_included\":false,"
        "\"storage\":{\"state\":\"%s\",\"mounted\":%s,\"capacity_bytes\":%" PRIu64 ",\"free_bytes\":%" PRIu64
        ",\"archived_events\":%" PRIu32 ",\"write_failures\":%" PRIu32 ",\"mount_failures\":%" PRIu32
        ",\"format_count\":%" PRIu32 ",\"format_failures\":%" PRIu32 ",\"erase_count\":%" PRIu32 "},"
        "\"config\":{\"schema_version\":%" PRIu32 ",\"generation\":%" PRIu32 ",\"hostname\":\"%s\","
        "\"cloudflare_configured\":%s,\"cloudflare_zone_name\":\"%s\",\"peer_monitor_enabled\":%s},"
        "\"operations\":{\"boot_count\":%" PRIu32 ",\"event_count\":%u},\"events\":[",
        sd_storage_state_name(st.state), st.mounted ? "true" : "false", st.capacity_bytes, st.free_bytes,
        st.archived_events, st.write_failures, st.mount_failures, st.format_count, st.format_failures, st.erase_count,
        cfg.schema_version, cfg.generation, cfg.hostname, cfg.cloudflare_configured ? "true" : "false", cfg.cloudflare_zone_name,
        cfg.ntp_peer_monitor_enabled ? "true" : "false", hs.boot_count, (unsigned)count);
    if (n < 0 || (size_t)n >= sizeof(b) || httpd_resp_send_chunk(request, b, n) != ESP_OK) return ESP_FAIL;
    for (size_t i = 0; i < count; ++i) {
        char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U]; snprintf(detail, sizeof(detail), "%s", events[i].detail);
        for (char *q = detail; *q; ++q) if ((unsigned char)*q < 0x20U || *q == '"' || *q == '\\') *q = '_';
        n = snprintf(b, sizeof(b), "%s{\"sequence\":%" PRIu32 ",\"boot_id\":%" PRIu32 ",\"uptime_seconds\":%" PRIu32
            ",\"unix_time\":%" PRId64 ",\"unix_time_valid\":%u,\"type\":%u,\"code\":%" PRId32 ",\"detail\":\"%s\"}",
            i ? "," : "", events[i].sequence, events[i].boot_id, events[i].uptime_seconds, events[i].unix_time,
            (unsigned)events[i].unix_time_valid, (unsigned)events[i].type, events[i].code, detail);
        if (n < 0 || (size_t)n >= sizeof(b) || httpd_resp_send_chunk(request, b, n) != ESP_OK) return ESP_FAIL;
    }
    if (httpd_resp_send_chunk(request, "]}\n", 3) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(request, NULL, 0);
}

static esp_err_t health_handler(httpd_req_t *request)
{
    return send_health_response(request);
}

static esp_err_t metrics_handler(httpd_req_t *request)
{
    return send_metrics_response(request);
}

static const httpd_uri_t s_provisioning_index_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = provisioning_index_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_provisioning_claim_uri = {
    .uri = "/api/v1/provisioning/claim",
    .method = HTTP_PUT,
    .handler = provisioning_claim_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_system_reboot_uri = {
    .uri = "/api/v1/system/reboot",
    .method = HTTP_POST,
    .handler = system_reboot_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_index_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = management_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_management_uri = {
    .uri = "/management", .method = HTTP_GET, .handler = management_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_system_page_uri = {
    .uri = "/system", .method = HTTP_GET, .handler = management_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_diagnostics_page_uri = {
    .uri = "/diagnostics", .method = HTTP_GET, .handler = management_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_firmware_page_uri = {
    .uri = "/management/firmware", .method = HTTP_GET, .handler = firmware_page_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_status_uri = {
    .uri = "/api/v1/status",
    .method = HTTP_GET,
    .handler = status_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_health_uri = {
    .uri = "/api/v1/health",
    .method = HTTP_GET,
    .handler = health_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_metrics_uri = {
    .uri = "/metrics",
    .method = HTTP_GET,
    .handler = metrics_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_operations_history_uri = {
    .uri = "/api/v1/operations/history",
    .method = HTTP_GET,
    .handler = operations_history_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_storage_status_uri = {
    .uri = "/api/v1/storage/status", .method = HTTP_GET, .handler = storage_status_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_flush_uri = {
    .uri = "/api/v1/storage/flush", .method = HTTP_POST, .handler = storage_flush_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_mount_uri = {
    .uri = "/api/v1/storage/mount", .method = HTTP_POST, .handler = storage_mount_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_unmount_uri = {
    .uri = "/api/v1/storage/unmount", .method = HTTP_POST, .handler = storage_unmount_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_disable_uri = {
    .uri = "/api/v1/storage/disable", .method = HTTP_POST, .handler = storage_disable_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_erase_logs_uri = {
    .uri = "/api/v1/storage/erase-logs", .method = HTTP_POST, .handler = storage_erase_logs_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_format_uri = {
    .uri = "/api/v1/storage/format", .method = HTTP_POST, .handler = storage_format_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_logs_uri = {
    .uri = "/api/v1/storage/logs", .method = HTTP_GET, .handler = storage_logs_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_log_download_uri = {
    .uri = "/api/v1/storage/log", .method = HTTP_GET, .handler = storage_log_download_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_logs_zip_uri = {
    .uri = "/api/v1/storage/logs.zip", .method = HTTP_GET, .handler = storage_logs_zip_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_storage_diagnostics_uri = {
    .uri = "/api/v1/storage/diagnostics", .method = HTTP_GET, .handler = storage_diagnostics_handler, .user_ctx = NULL,
};


static esp_err_t hardware_profile_get_handler(httpd_req_t *request)
{
    hardware_profile_status_t st;
    const esp_err_t err = hardware_profile_get_status(&st);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "hardware profile unavailable");
    char json[768];
    const int n = snprintf(json, sizeof(json),
        "{\"schema_version\":%" PRIu32 ",\"generation\":%" PRIu32
        ",\"board_family\":\"%s\",\"board_revision\":\"%s\""
        ",\"pps_gpio\":%d,\"gnss_uart\":%d,\"gnss_rx_gpio\":%d,\"gnss_tx_gpio\":%d"
        ",\"requested_cpu_mhz\":%" PRIu32 ",\"configured_cpu_mhz\":%" PRIu32
        ",\"wafer_revision\":%" PRIu32 ",\"efuse_block_revision\":%" PRIu32
        ",\"package_version\":%" PRIu32 ",\"reboot_required_for_changes\":true}",
        st.config.schema_version, st.config.generation, st.config.board_family, st.config.board_revision,
        st.config.pps_gpio, st.config.gnss_uart_num, st.config.gnss_rx_gpio, st.config.gnss_tx_gpio,
        st.config.requested_cpu_mhz, st.configured_cpu_mhz, st.wafer_revision,
        st.efuse_block_revision, st.package_version);
    if (n < 0 || (size_t)n >= sizeof(json)) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "hardware profile serialization failed");
    httpd_resp_set_type(request, "application/json");
    httpd_resp_set_hdr(request, "Cache-Control", "no-store");
    return httpd_resp_send(request, json, n);
}

static esp_err_t hardware_profile_put_handler(httpd_req_t *request)
{
    if (request->content_len <= 0 || request->content_len >= APP_WEB_CONFIG_BODY_MAX)
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    char body[APP_WEB_CONFIG_BODY_MAX]; size_t received=0U;
    while (received < (size_t)request->content_len) {
        const int r=web_req_recv_bounded(request,body+received,(size_t)request->content_len-received);
        if (r==HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r<=0) return httpd_resp_send_err(request,HTTPD_400_BAD_REQUEST,"request body receive failed");
        received+=(size_t)r;
    }
    body[received]='\0';
    hardware_profile_config_t c; memset(&c,0,sizeof(c));
    uint32_t pps=0,uart=0,rx=0,tx=0,cpu=0;
    if (!json_get_string(body,"board_family",c.board_family,sizeof(c.board_family)) ||
        !json_get_string(body,"board_revision",c.board_revision,sizeof(c.board_revision)) ||
        !json_get_u32(body,"pps_gpio",&pps) || !json_get_u32(body,"gnss_uart",&uart) ||
        !json_get_u32(body,"gnss_rx_gpio",&rx) || !json_get_u32(body,"gnss_tx_gpio",&tx) ||
        !json_get_u32(body,"requested_cpu_mhz",&cpu))
        return httpd_resp_send_err(request,HTTPD_400_BAD_REQUEST,"complete hardware profile required");
    c.schema_version=APP_HW_PROFILE_SCHEMA_VERSION;c.pps_gpio=(int)pps;c.gnss_uart_num=(int)uart;
    c.gnss_rx_gpio=(int)rx;c.gnss_tx_gpio=(int)tx;c.requested_cpu_mhz=cpu;
    esp_err_t err=hardware_profile_set_config(&c);
    if (err==ESP_ERR_INVALID_ARG) return httpd_resp_send_err(request,HTTPD_400_BAD_REQUEST,"invalid or conflicting hardware profile");
    if (err!=ESP_OK) return httpd_resp_send_err(request,HTTPD_500_INTERNAL_SERVER_ERROR,"hardware profile commit failed");
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE,0,"hardware_profile_updated_reboot_required");
    return hardware_profile_get_handler(request);
}


static esp_err_t commissioning_get_handler(httpd_req_t *request)
{
    commissioning_config_t cfg;
    commissioning_time_status_t ts;
    if (commissioning_get_config(&cfg) != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "commissioning configuration unavailable");
    }
    commissioning_get_time_status(&ts);
    char response[1400];
    int n = snprintf(response, sizeof(response),
        "{\"certificate_fqdn\":\"%s\",\"ntp_servers\":[\"%s\",\"%s\"],"
        "\"management_time_valid\":%s,\"management_time_source\":\"%s\","
        "\"management_time_server\":\"%s\",\"management_unix_time\":%lld,\"last_error\":%d}",
        cfg.certificate_fqdn, cfg.ntp_servers[0], cfg.ntp_servers[1],
        ts.management_time_valid ? "true" : "false", ts.source, ts.server,
        (long long)ts.unix_time, (int)ts.last_error);
    if (n < 0 || n >= (int)sizeof(response)) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "serialization failed");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t commissioning_put_handler(httpd_req_t *request)
{
    char body[APP_WEB_CONFIG_BODY_MAX];
    if (receive_request_body(request, body, sizeof(body)) != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid request body");
    commissioning_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (!extract_json_string(body, "certificate_fqdn", cfg.certificate_fqdn, sizeof(cfg.certificate_fqdn)) ||
        !extract_json_string(body, "ntp0", cfg.ntp_servers[0], sizeof(cfg.ntp_servers[0])) ||
        !extract_json_string(body, "ntp1", cfg.ntp_servers[1], sizeof(cfg.ntp_servers[1]))) {
        return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "certificate_fqdn, ntp0 and ntp1 are required");
    }
    esp_err_t err = commissioning_set_config(&cfg);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "invalid commissioning configuration");
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "commissioning_identity_ntp_updated");
    return commissioning_get_handler(request);
}

static esp_err_t commissioning_sync_handler(httpd_req_t *request)
{
    esp_err_t err = commissioning_sync_management_time();
    (void)operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, (int32_t)err,
                                    err == ESP_OK ? "management_time_sync_ok" : "management_time_sync_failed");
    if (err != ESP_OK) {
        httpd_resp_set_status(request, "502 Bad Gateway");
    }
    return commissioning_get_handler(request);
}

static const httpd_uri_t s_commissioning_get_uri = {
    .uri="/api/v1/commissioning", .method=HTTP_GET, .handler=commissioning_get_handler, .user_ctx=NULL,
};
static const httpd_uri_t s_commissioning_put_uri = {
    .uri="/api/v1/commissioning", .method=HTTP_PUT, .handler=commissioning_put_handler, .user_ctx=NULL,
};
static const httpd_uri_t s_commissioning_sync_uri = {
    .uri="/api/v1/commissioning/time/sync", .method=HTTP_POST, .handler=commissioning_sync_handler, .user_ctx=NULL,
};

static const httpd_uri_t s_hardware_profile_get_uri = {
    .uri="/api/v1/hardware/profile", .method=HTTP_GET, .handler=hardware_profile_get_handler, .user_ctx=NULL,
};
static const httpd_uri_t s_hardware_profile_put_uri = {
    .uri="/api/v1/hardware/profile", .method=HTTP_PUT, .handler=hardware_profile_put_handler, .user_ctx=NULL,
};

static const httpd_uri_t s_config_backup_get_uri = {
    .uri = "/api/v1/config/backup", .method = HTTP_GET,
    .handler = config_backup_get_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_config_backup_restore_uri = {
    .uri = "/api/v1/config/backup", .method = HTTP_POST,
    .handler = config_backup_restore_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_config_get_uri = {
    .uri = "/api/v1/config",
    .method = HTTP_GET,
    .handler = config_get_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_peer_monitor_put_uri = {
    .uri = "/api/v1/config/peer-monitor",
    .method = HTTP_PUT,
    .handler = peer_monitor_put_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_redundant_server_put_uri = {
    .uri = "/api/v1/config/redundant-server",
    .method = HTTP_PUT,
    .handler = redundant_server_put_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_network_put_uri = {
    .uri = "/api/v1/config/network",
    .method = HTTP_PUT,
    .handler = network_put_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_hostname_put_uri = {
    .uri = "/api/v1/config/hostname",
    .method = HTTP_PUT,
    .handler = hostname_put_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_put_uri = {
    .uri = "/api/v1/config/cloudflare", .method = HTTP_PUT,
    .handler = cloudflare_put_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_delete_uri = {
    .uri = "/api/v1/config/cloudflare", .method = HTTP_DELETE,
    .handler = cloudflare_delete_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_cloudflare_verify_uri = {
    .uri = "/api/v1/config/cloudflare/verify", .method = HTTP_POST,
    .handler = cloudflare_verify_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_create_uri = {
    .uri = "/api/v1/cloudflare/dns01", .method = HTTP_POST,
    .handler = dns01_create_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_query_uri = {
    .uri = "/api/v1/cloudflare/dns01/query", .method = HTTP_POST,
    .handler = dns01_query_handler, .user_ctx = NULL,
};

static const httpd_uri_t s_dns01_delete_uri = {
    .uri = "/api/v1/cloudflare/dns01", .method = HTTP_DELETE,
    .handler = dns01_delete_handler, .user_ctx = NULL,
};


static const httpd_uri_t s_acme_account_status_uri = {
    .uri = "/api/v1/acme/account",
    .method = HTTP_GET,
    .handler = acme_account_status_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_account_provision_uri = {
    .uri = "/api/v1/acme/account",
    .method = HTTP_POST,
    .handler = acme_account_provision_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_staging_probe_uri = {
    .uri = "/api/v1/acme/staging/probe",
    .method = HTTP_POST,
    .handler = acme_staging_probe_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_staging_order_discover_uri = {
    .uri = "/api/v1/acme/staging/order/discover",
    .method = HTTP_POST,
    .handler = acme_staging_order_discover_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_staging_dns01_validate_uri = {
    .uri = "/api/v1/acme/staging/dns01/validate",
    .method = HTTP_POST,
    .handler = acme_staging_dns01_validate_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_staging_certificate_issue_uri = {
    .uri = "/api/v1/acme/staging/certificate/issue",
    .method = HTTP_POST,
    .handler = acme_staging_certificate_issue_handler,
    .user_ctx = NULL,
};



static const httpd_uri_t s_acme_production_certificate_issue_uri = {
    .uri = "/api/v1/acme/production/certificate/issue",
    .method = HTTP_POST,
    .handler = acme_production_certificate_issue_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_renew_uri = {
    .uri = "/api/v1/acme/production/certificate/renew",
    .method = HTTP_POST,
    .handler = acme_production_certificate_renew_handler,
    .user_ctx = NULL,
};


static const httpd_uri_t s_acme_certificate_inspection_uri = {
    .uri = "/api/v1/acme/certificate",
    .method = HTTP_GET,
    .handler = acme_certificate_inspection_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_inspection_uri = {
    .uri = "/api/v1/acme/production/certificate",
    .method = HTTP_GET,
    .handler = acme_production_certificate_inspection_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_lifecycle_uri = {
    .uri = "/api/v1/acme/production/certificate/lifecycle",
    .method = HTTP_GET,
    .handler = acme_production_certificate_lifecycle_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_renewal_scheduler_uri = {
    .uri = "/api/v1/acme/production/renewal/scheduler",
    .method = HTTP_GET,
    .handler = acme_production_renewal_scheduler_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_renewal_scheduler_put_uri = {
    .uri = "/api/v1/acme/production/renewal/scheduler",
    .method = HTTP_PUT,
    .handler = acme_production_renewal_scheduler_put_handler,
    .user_ctx = NULL,
};




static const httpd_uri_t s_acme_production_certificate_export_uri = {
    .uri = "/api/v1/acme/production/certificate/export",
    .method = HTTP_GET,
    .handler = acme_production_certificate_export_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_certificate_activate_test_uri = {
    .uri = "/api/v1/acme/certificate/activate-test",
    .method = HTTP_POST,
    .handler = acme_certificate_activate_test_handler,
    .user_ctx = NULL,
};

static const httpd_uri_t s_acme_production_certificate_activate_uri = {
    .uri = "/api/v1/acme/production/certificate/activate",
    .method = HTTP_POST,
    .handler = acme_production_certificate_activate_handler,
};

static const httpd_uri_t s_acme_certificate_rollback_uri = {
    .uri = "/api/v1/acme/certificate/rollback",
    .method = HTTP_POST,
    .handler = acme_certificate_rollback_handler,
    .user_ctx = NULL,
};


static esp_err_t ota_status_handler(httpd_req_t *request)
{
    ota_manager_status_t status;
    esp_err_t err = ota_manager_get_status(&status);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA status unavailable");
    char rollback_partition[17];
    char rollback_version[33];
    const bool rollback_available =
        ota_manager_get_rollback_target(rollback_partition, sizeof(rollback_partition),
                                        rollback_version, sizeof(rollback_version)) == ESP_OK &&
        !status.update_in_progress;
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"rollback_available\":%s,\"rollback_partition\":\"%s\",\"rollback_version\":\"%s\","
             "\"initialized\":%s,\"update_in_progress\":%s,\"pending_verify\":%s,"
             "\"last_boot_confirmed\":%s,\"attempts\":%" PRIu32 ",\"successes\":%" PRIu32 ","
             "\"failures\":%" PRIu32 ",\"confirmations\":%" PRIu32 ",\"rollbacks_detected\":%" PRIu32 ","
             "\"bytes_written\":%u,\"running_partition\":\"%s\","
             "\"boot_partition\":\"%s\",\"next_partition\":\"%s\",\"running_version\":\"%s\","
             "\"previous_version\":\"%s\",\"running_project\":\"%s\",\"last_result\":\"%s\"}\n",
             rollback_available ? "true" : "false", rollback_available ? rollback_partition : "",
             rollback_available ? rollback_version : "",
             status.initialized ? "true" : "false", status.update_in_progress ? "true" : "false",
             status.pending_verify ? "true" : "false", status.last_boot_confirmed ? "true" : "false",
             status.attempts, status.successes, status.failures, status.confirmations,
             status.rollbacks_detected, (unsigned)status.bytes_written, status.running_partition, status.boot_partition, status.next_partition,
             status.running_version, status.previous_version, status.running_project, status.last_result);
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t ota_upload_handler(httpd_req_t *request)
{
    if (request->content_len <= 0) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "firmware image required");
    esp_err_t err = ota_manager_begin((size_t)request->content_len);
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "unable to begin OTA");
    uint8_t buffer[4096];
    int remaining = request->content_len;
    while (remaining > 0) {
        const size_t want = remaining > (int)sizeof(buffer) ? sizeof(buffer) : (size_t)remaining;
        int received = web_req_recv_bounded(request, (char *)buffer, want);
        if (received == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (received <= 0) { ota_manager_abort(); return ESP_FAIL; }
        err = ota_manager_write(buffer, (size_t)received);
        if (err != ESP_OK) { ota_manager_abort(); return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed"); }
        remaining -= received;
    }
    err = ota_manager_finish();
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "firmware validation/staging failed");
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, "{\"staged\":true,\"reboot_required\":true}\n", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t ota_confirm_handler(httpd_req_t *request)
{
    const esp_err_t err = ota_manager_confirm_running_image();
    if (err != ESP_OK) return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "unable to confirm running image");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, "{\"confirmed\":true}\n", HTTPD_RESP_USE_STRLEN);
}

/* Boots the image in the other OTA slot. Requires an explicit confirmation
 * header like the other destructive actions; the reboot is deferred so the
 * response reaches the client. */
static esp_err_t ota_rollback_handler(httpd_req_t *request)
{
    char confirm[16] = {0};
    if (httpd_req_get_hdr_value_str(request, "X-Confirm-Rollback", confirm, sizeof(confirm)) != ESP_OK ||
        strcmp(confirm, "ROLLBACK") != 0) {
        httpd_resp_set_status(request, "412 Precondition Failed");
        return httpd_resp_send(request, "explicit ROLLBACK confirmation required", HTTPD_RESP_USE_STRLEN);
    }
    esp_err_t busy_result = ESP_OK;
    if (reboot_refused_busy(request, &busy_result)) return busy_result;
    char version[33];
    if (ota_manager_get_rollback_target(NULL, 0, version, sizeof(version)) != ESP_OK) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "no previous image available for rollback", HTTPD_RESP_USE_STRLEN);
    }
    const esp_err_t err = ota_manager_rollback_to_previous();
    if (err == ESP_ERR_INVALID_STATE || err == ESP_ERR_NOT_FOUND || err == ESP_ERR_TIMEOUT) {
        httpd_resp_set_status(request, "409 Conflict");
        return httpd_resp_send(request, "rollback unavailable (OTA busy or no previous image)", HTTPD_RESP_USE_STRLEN);
    }
    if (err != ESP_OK) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR, "previous image failed verification");
    }
    if (xTaskCreate(delayed_reboot_task, "web_reboot", 2048U, NULL, 5U, NULL) != pdPASS) {
        return httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "rollback staged; reboot to activate");
    }
    char body[128];
    snprintf(body, sizeof(body), "{\"scheduled\":true,\"action\":\"rollback\",\"version\":\"%s\"}\n", version);
    httpd_resp_set_status(request, "202 Accepted");
    httpd_resp_set_type(request, "application/json");
    set_security_headers(request);
    return httpd_resp_send(request, body, HTTPD_RESP_USE_STRLEN);
}

static const httpd_uri_t s_ota_status_uri = {
    .uri = "/api/v1/ota/status", .method = HTTP_GET, .handler = ota_status_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_ota_upload_uri = {
    .uri = "/api/v1/ota/image", .method = HTTP_POST, .handler = ota_upload_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_ota_confirm_uri = {
    .uri = "/api/v1/ota/confirm", .method = HTTP_POST, .handler = ota_confirm_handler, .user_ctx = NULL,
};
static const httpd_uri_t s_ota_rollback_uri = {
    .uri = "/api/v1/ota/rollback", .method = HTTP_POST, .handler = ota_rollback_handler, .user_ctx = NULL,
};

static esp_err_t register_provisioning_handlers(httpd_handle_t server)
{
    esp_err_t err = httpd_register_uri_handler(server, &s_provisioning_index_uri);
    if (err == ESP_OK) err = httpd_register_uri_handler(server, &s_provisioning_claim_uri);
    return err;
}

static esp_err_t register_all_handlers(httpd_handle_t server)
{
    const httpd_uri_t *handlers[] = {
        &s_index_uri, &s_system_page_uri, &s_management_uri, &s_diagnostics_page_uri, &s_firmware_page_uri, &s_status_uri, &s_health_uri, &s_metrics_uri,
        &s_operations_history_uri, &s_storage_status_uri, &s_storage_flush_uri, &s_storage_mount_uri, &s_storage_unmount_uri, &s_storage_disable_uri, &s_storage_erase_logs_uri, &s_storage_format_uri, &s_storage_diagnostics_uri, &s_storage_logs_uri, &s_storage_log_download_uri, &s_storage_logs_zip_uri, &s_system_reboot_uri, &s_hardware_profile_get_uri, &s_hardware_profile_put_uri,
        &s_commissioning_get_uri, &s_commissioning_put_uri, &s_commissioning_sync_uri,
        &s_config_get_uri, &s_config_backup_get_uri, &s_config_backup_restore_uri, &s_peer_monitor_put_uri, &s_redundant_server_put_uri, &s_hostname_put_uri, &s_network_put_uri, &s_cloudflare_put_uri,
        &s_cloudflare_delete_uri, &s_cloudflare_verify_uri,
        &s_dns01_create_uri, &s_dns01_query_uri, &s_dns01_delete_uri,
        &s_acme_staging_probe_uri, &s_acme_account_status_uri,
        &s_acme_account_provision_uri, &s_acme_staging_order_discover_uri,
        &s_acme_staging_dns01_validate_uri, &s_acme_staging_certificate_issue_uri,
        &s_acme_production_certificate_issue_uri, &s_acme_production_certificate_renew_uri,
        &s_acme_certificate_inspection_uri,
        &s_acme_production_certificate_inspection_uri, &s_acme_production_certificate_lifecycle_uri,
        &s_acme_production_renewal_scheduler_uri, &s_acme_production_renewal_scheduler_put_uri,
        &s_acme_production_certificate_export_uri,
        &s_acme_certificate_activate_test_uri,
        &s_acme_production_certificate_activate_uri,
        &s_acme_certificate_rollback_uri,
        &s_ota_status_uri, &s_ota_upload_uri, &s_ota_confirm_uri, &s_ota_rollback_uri,
    };
    _Static_assert((sizeof(handlers) / sizeof(handlers[0])) <= APP_WEB_CONSOLE_MAX_HANDLERS,
                   "APP_WEB_CONSOLE_MAX_HANDLERS is too small for registered management URI handlers");
    for (size_t i = 0U; i < sizeof(handlers) / sizeof(handlers[0]); ++i) {
        const esp_err_t err = httpd_register_uri_handler(server, handlers[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

static esp_err_t start_https_server(web_tls_source_t source)
{
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    acme_tls_credentials_t candidate;
    memset(&candidate, 0, sizeof(candidate));

    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    if (management_ownership_is_provisioned()) {
        config.cacert_pem = (const uint8_t *)s_management_client_ca;
        config.cacert_len = s_management_client_ca_length;
    } else {
        config.cacert_pem = NULL;
        config.cacert_len = 0U;
    }

    if (source == WEB_TLS_STORED_TEST || source == WEB_TLS_PRODUCTION) {
        esp_err_t err = source == WEB_TLS_PRODUCTION
                            ? acme_client_load_production_tls_credentials(&candidate)
                            : acme_client_load_stored_tls_credentials(&candidate);
        if (err != ESP_OK) return err;
        config.servercert = (const uint8_t *)candidate.certificate_pem;
        config.servercert_len = candidate.certificate_pem_length;
        config.prvtkey_pem = (const uint8_t *)candidate.private_key_pem;
        config.prvtkey_len = candidate.private_key_pem_length;
    } else {
        if (s_bootstrap_credentials.certificate_pem == NULL) {
            esp_err_t err = acme_client_load_bootstrap_tls_credentials(&s_bootstrap_credentials);
            if (err != ESP_OK) return err;
        }
        config.servercert = (const uint8_t *)s_bootstrap_credentials.certificate_pem;
        config.servercert_len = s_bootstrap_credentials.certificate_pem_length;
        config.prvtkey_pem = (const uint8_t *)s_bootstrap_credentials.private_key_pem;
        config.prvtkey_len = s_bootstrap_credentials.private_key_pem_length;
    }

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &config);
    if (err == ESP_OK) {
        err = management_ownership_is_provisioned()
                  ? register_all_handlers(server)
                  : register_provisioning_handlers(server);
    }
    if (err != ESP_OK) {
        if (server != NULL) (void)httpd_ssl_stop(server);
        acme_client_free_tls_credentials(&candidate);
        return err;
    }

    s_server = server;
    s_started = true;
    s_tls_source = source;
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));
    if (source == WEB_TLS_PRODUCTION) {
        acme_certificate_inspection_t active_inspection;
        if (acme_client_inspect_stored_production_certificate(&active_inspection) == ESP_OK) {
            snprintf(s_active_server_leaf_sha256, sizeof(s_active_server_leaf_sha256),
                     "%s", active_inspection.leaf_sha256);
        }
    }
    if (source == WEB_TLS_STORED_TEST || source == WEB_TLS_PRODUCTION) {
        s_active_stored_credentials = candidate;
        memset(&candidate, 0, sizeof(candidate));
    }
    if (management_ownership_is_provisioned()) {
        ESP_LOGW(TAG, "mTLS management console active on TCP/%u; server credential=%s; client certificate required",
                 APP_WEB_CONSOLE_PORT, tls_source_name(source));
    } else {
        ESP_LOGW(TAG, "UNPROVISIONED enrollment-only HTTPS active on TCP/%u; normal management handlers are disabled",
                 APP_WEB_CONSOLE_PORT);
    }
    if (source == WEB_TLS_EMBEDDED) {
        char fingerprint[65];
        if (acme_client_bootstrap_certificate_sha256(fingerprint) == ESP_OK) {
            /* The setup tool reads this from the serial console and pins it,
             * for enrollment and for commissioning before the board has a
             * Let's Encrypt certificate. */
            ESP_LOGW(TAG, "Bootstrap certificate SHA-256: %s", fingerprint);
        }
    } else if (source == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] != '\0') {
        /* Lets the setup tool pin a claimed board that already holds a
         * production certificate, for example after a settings reset. */
        ESP_LOGW(TAG, "Server certificate SHA-256: %s", s_active_server_leaf_sha256);
    }
    return ESP_OK;
}

static esp_err_t start_https_server_with_credentials(web_tls_source_t source,
                                                     acme_tls_credentials_t *credentials,
                                                     const char *known_leaf_sha256)
{
    if (source == WEB_TLS_EMBEDDED) return start_https_server(WEB_TLS_EMBEDDED);
    if (credentials == NULL || credentials->certificate_pem == NULL ||
        credentials->private_key_pem == NULL) return ESP_ERR_INVALID_ARG;

    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.stack_size = APP_WEB_CONSOLE_STACK_SIZE;
    config.httpd.max_uri_handlers = APP_WEB_CONSOLE_MAX_HANDLERS;
    config.httpd.max_open_sockets = APP_WEB_CONSOLE_MAX_OPEN_SOCKETS;
    config.httpd.lru_purge_enable = true;
    config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    config.port_secure = APP_WEB_CONSOLE_PORT;
    if (management_ownership_is_provisioned()) {
        config.cacert_pem = (const uint8_t *)s_management_client_ca;
        config.cacert_len = s_management_client_ca_length;
    } else {
        config.cacert_pem = NULL;
        config.cacert_len = 0U;
    }
    config.servercert = (const uint8_t *)credentials->certificate_pem;
    config.servercert_len = credentials->certificate_pem_length;
    config.prvtkey_pem = (const uint8_t *)credentials->private_key_pem;
    config.prvtkey_len = credentials->private_key_pem_length;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_ssl_start(&server, &config);
    if (err == ESP_OK) {
        err = management_ownership_is_provisioned()
                  ? register_all_handlers(server)
                  : register_provisioning_handlers(server);
    }
    if (err != ESP_OK) {
        if (server != NULL) (void)httpd_ssl_stop(server);
        return err;
    }

    s_server = server;
    s_started = true;
    s_tls_source = source;
    s_active_stored_credentials = *credentials;
    memset(credentials, 0, sizeof(*credentials));
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));
    if (known_leaf_sha256 != NULL) {
        snprintf(s_active_server_leaf_sha256, sizeof(s_active_server_leaf_sha256), "%s", known_leaf_sha256);
    }
    ESP_LOGW(TAG, "mTLS management console restored on TCP/%u; server credential=%s; client certificate required",
             APP_WEB_CONSOLE_PORT, tls_source_name(source));
    return ESP_OK;
}

static void tls_transition_task(void *arg)
{
    const web_tls_source_t target = (web_tls_source_t)(uintptr_t)arg;
    const bool automatic_transition = s_tls_transition_automatic;
    const web_tls_source_t previous_source = s_tls_source;
    acme_tls_credentials_t previous_credentials;
    char previous_leaf_sha256[65];
    char automatic_target_leaf_sha256[65];
    memset(automatic_target_leaf_sha256, 0, sizeof(automatic_target_leaf_sha256));
    if (automatic_transition) {
        acme_tls_activation_intent_record_t intent_snapshot;
        if (acme_client_load_tls_activation_intent(&intent_snapshot) == ESP_OK && intent_snapshot.pending)
            snprintf(automatic_target_leaf_sha256, sizeof(automatic_target_leaf_sha256), "%s",
                     intent_snapshot.target_leaf_sha256);
    }
    memset(&previous_credentials, 0, sizeof(previous_credentials));
    snprintf(previous_leaf_sha256, sizeof(previous_leaf_sha256), "%s", s_active_server_leaf_sha256);

    vTaskDelay(pdMS_TO_TICKS(750));

    if (previous_source != WEB_TLS_EMBEDDED) {
        previous_credentials = s_active_stored_credentials;
        memset(&s_active_stored_credentials, 0, sizeof(s_active_stored_credentials));
    }
    if (s_server != NULL) {
        (void)httpd_ssl_stop(s_server);
        s_server = NULL;
        s_started = false;
    }
    memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));

    esp_err_t err = start_https_server(target);
    if (err == ESP_OK) {
        if (target == WEB_TLS_PRODUCTION) {
            err = acme_client_set_production_boot_selected(true);
        } else if (target == WEB_TLS_EMBEDDED) {
            err = acme_client_set_production_boot_selected(false);
        }
    }

    if (err == ESP_OK) {
        acme_client_free_tls_credentials(&previous_credentials);
        if (target == WEB_TLS_PRODUCTION && s_active_server_leaf_sha256[0] != '\0') {
            acme_tls_activation_intent_record_t intent;
            const esp_err_t intent_load_err = acme_client_load_tls_activation_intent(&intent);
            if (intent_load_err == ESP_OK && intent.pending &&
                intent.target_leaf_sha256[0] != '\0' &&
                strcmp(intent.target_leaf_sha256, s_active_server_leaf_sha256) == 0) {
                const esp_err_t clear_err = tls_activation_intent_clear(false);
                if (clear_err == ESP_OK) {
                    portENTER_CRITICAL(&s_renewal_scheduler_lock);
                    snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
                             sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
                             "activated_runtime");
                    portEXIT_CRITICAL(&s_renewal_scheduler_lock);
                } else {
                    ESP_LOGE(TAG, "TLS handoff succeeded but activation-intent clear failed: %s",
                             esp_err_to_name(clear_err));
                }
            }
        }
        if (target == WEB_TLS_PRODUCTION && automatic_transition) {
            const esp_err_t outcome_err = tls_activation_outcome_store(true, false, ESP_OK,
                                                                       automatic_target_leaf_sha256,
                                                                       s_active_server_leaf_sha256);
            if (outcome_err != ESP_OK)
                ESP_LOGE(TAG, "TLS activation succeeded but outcome persistence failed: %s", esp_err_to_name(outcome_err));
            int64_t handoff_done = 0; (void)get_current_unix_time(&handoff_done);
            const esp_err_t handoff_err = tls_handoff_finish(true, handoff_done);
            if (handoff_err != ESP_OK) ESP_LOGE(TAG, "TLS handoff success-state persistence failed: %s", esp_err_to_name(handoff_err));
        }
        ESP_LOGI(TAG, "TLS transition completed: %s -> %s",
                 tls_source_name(previous_source), tls_source_name(target));
    } else {
        ESP_LOGE(TAG, "TLS transition to %s failed: %s; restoring last-known-good %s credential",
                 tls_source_name(target), esp_err_to_name(err), tls_source_name(previous_source));

        if (s_server != NULL) {
            (void)httpd_ssl_stop(s_server);
            s_server = NULL;
            s_started = false;
        }
        if (s_tls_source != WEB_TLS_EMBEDDED) {
            acme_client_free_tls_credentials(&s_active_stored_credentials);
        }
        memset(s_active_server_leaf_sha256, 0, sizeof(s_active_server_leaf_sha256));

        esp_err_t rollback_err;
        if (previous_source == WEB_TLS_EMBEDDED) {
            rollback_err = start_https_server(WEB_TLS_EMBEDDED);
        } else {
            rollback_err = start_https_server_with_credentials(previous_source,
                                                               &previous_credentials,
                                                               previous_leaf_sha256);
        }

        if (rollback_err == ESP_OK) {
            const bool previous_production = previous_source == WEB_TLS_PRODUCTION;
            const esp_err_t pref_err = acme_client_set_production_boot_selected(previous_production);
            if (pref_err != ESP_OK) {
                ESP_LOGE(TAG, "Last-known-good TLS restored but boot preference restore failed: %s",
                         esp_err_to_name(pref_err));
            }
        } else {
            ESP_LOGE(TAG, "Last-known-good TLS restore failed: %s; attempting embedded emergency fallback",
                     esp_err_to_name(rollback_err));
            acme_client_free_tls_credentials(&previous_credentials);
            (void)acme_client_set_production_boot_selected(false);
            rollback_err = start_https_server(WEB_TLS_EMBEDDED);
            if (rollback_err != ESP_OK) {
                ESP_LOGE(TAG, "Management HTTPS emergency fallback failed: %s", esp_err_to_name(rollback_err));
            }
        }
        if (target == WEB_TLS_PRODUCTION && automatic_transition) {
            const bool lkg_restored = rollback_err == ESP_OK;
            const esp_err_t outcome_err = tls_activation_outcome_store(false, lkg_restored, err,
                                                                       automatic_target_leaf_sha256, s_active_server_leaf_sha256);
            if (outcome_err != ESP_OK)
                ESP_LOGE(TAG, "TLS activation failure outcome persistence failed: %s", esp_err_to_name(outcome_err));
            int64_t handoff_done = 0; (void)get_current_unix_time(&handoff_done);
            const esp_err_t handoff_err = tls_handoff_finish(false, handoff_done);
            if (handoff_err != ESP_OK) ESP_LOGE(TAG, "TLS handoff failure-state persistence failed: %s", esp_err_to_name(handoff_err));
        }
        acme_tls_activation_intent_record_t failed_intent;
        if (acme_client_load_tls_activation_intent(&failed_intent) == ESP_OK && failed_intent.pending) {
            portENTER_CRITICAL(&s_renewal_scheduler_lock);
            snprintf(s_renewal_scheduler_status.tls_activation_reconciliation_result,
                     sizeof(s_renewal_scheduler_status.tls_activation_reconciliation_result),
                     "activation_failed_lkg_restored");
            portEXIT_CRITICAL(&s_renewal_scheduler_lock);
        }
    }

    if (automatic_transition) s_tls_transition_automatic = false;
    tls_transition_release();
    vTaskDelete(NULL);
}

static esp_err_t web_console_start_https(void)
{
    if (s_started) return ESP_OK;
    /* Enrollment always uses this board's bootstrap certificate, whose
     * fingerprint is on the serial console for the setup tool to pin, even if
     * a production certificate survives from an earlier claim. */
    if (!management_ownership_is_provisioned()) return start_https_server(WEB_TLS_EMBEDDED);
    if (management_ownership_is_provisioned() && s_management_client_ca == NULL) {
        esp_err_t ca_err = management_ownership_load_ca(&s_management_client_ca, &s_management_client_ca_length);
        if (ca_err != ESP_OK) {
            ESP_LOGE(TAG, "Provisioned management CA could not be loaded: %s", esp_err_to_name(ca_err));
            return ca_err;
        }
    }
    esp_err_t err = acme_client_prepare_production_storage();
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Production credential store preparation failed: %s; using embedded credential",
                 esp_err_to_name(err));
        (void)acme_client_set_production_boot_selected(false);
        return start_https_server(WEB_TLS_EMBEDDED);
    }

    bool production_selected = false;
    err = acme_client_get_production_boot_selected(&production_selected);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "TLS boot selection read failed: %s; using embedded credential", esp_err_to_name(err));
        (void)acme_client_set_production_boot_selected(false);
        return start_https_server(WEB_TLS_EMBEDDED);
    }
    if (!production_selected) return start_https_server(WEB_TLS_EMBEDDED);

    err = start_https_server(WEB_TLS_PRODUCTION);
    if (err == ESP_OK) return ESP_OK;

    ESP_LOGE(TAG, "Production TLS boot failed: %s; clearing selection and falling back to embedded credential",
             esp_err_to_name(err));
    (void)acme_client_set_production_boot_selected(false);
    return start_https_server(WEB_TLS_EMBEDDED);
}

esp_err_t web_console_start(void)
{
    const esp_err_t err = web_console_start_https();
    if (err != ESP_OK) return err;

    const esp_err_t scheduler_err = start_renewal_scheduler();
    if (scheduler_err != ESP_OK) {
        ESP_LOGE(TAG, "ACME renewal scheduler start failed: %s", esp_err_to_name(scheduler_err));
        /* Management HTTPS remains available; scheduler failure never changes TLS/timing/NTP state. */
    }
    return ESP_OK;
}

bool web_console_is_running(void)
{
    return s_started;
}

#include "ota_manager.h"

#include <string.h>
#include <stdio.h>
#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "operations_history.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"

static const char *TAG = "OTA";
static const char *OTA_NS = "ota_hist";
static SemaphoreHandle_t s_lock;
static esp_ota_handle_t s_handle;
static const esp_partition_t *s_target;
static ota_manager_status_t s_status;

#define KEY_ATTEMPTS "attempts"
#define KEY_SUCCESSES "successes"
#define KEY_FAILURES "failures"
#define KEY_CONFIRMS "confirms"
#define KEY_ROLLBACKS "rollbacks"
#define KEY_PENDING "pending"
#define KEY_PREVVER "prevver"

static void copy_label(char *dst, size_t n, const esp_partition_t *p)
{
    if (n == 0) return;
    if (p == NULL) { dst[0] = '\0'; return; }
    snprintf(dst, n, "%s", p->label);
}

static void set_result(const char *result)
{
    snprintf(s_status.last_result, sizeof(s_status.last_result), "%s", result ? result : "unknown");
}

static esp_err_t load_history(char pending[17])
{
    pending[0] = '\0';
    nvs_handle_t h;
    esp_err_t err = nvs_open(OTA_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    (void)nvs_get_u32(h, KEY_ATTEMPTS, &s_status.attempts);
    (void)nvs_get_u32(h, KEY_SUCCESSES, &s_status.successes);
    (void)nvs_get_u32(h, KEY_FAILURES, &s_status.failures);
    (void)nvs_get_u32(h, KEY_CONFIRMS, &s_status.confirmations);
    (void)nvs_get_u32(h, KEY_ROLLBACKS, &s_status.rollbacks_detected);
    size_t n = 17;
    if (nvs_get_str(h, KEY_PENDING, pending, &n) != ESP_OK) pending[0] = '\0';
    n = sizeof(s_status.previous_version);
    if (nvs_get_str(h, KEY_PREVVER, s_status.previous_version, &n) != ESP_OK) s_status.previous_version[0] = '\0';
    nvs_close(h);
    return ESP_OK;
}

static esp_err_t persist_history(const char *pending)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(OTA_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    if (err == ESP_OK) err = nvs_set_u32(h, KEY_ATTEMPTS, s_status.attempts);
    if (err == ESP_OK) err = nvs_set_u32(h, KEY_SUCCESSES, s_status.successes);
    if (err == ESP_OK) err = nvs_set_u32(h, KEY_FAILURES, s_status.failures);
    if (err == ESP_OK) err = nvs_set_u32(h, KEY_CONFIRMS, s_status.confirmations);
    if (err == ESP_OK) err = nvs_set_u32(h, KEY_ROLLBACKS, s_status.rollbacks_detected);
    if (err == ESP_OK && s_status.previous_version[0]) err = nvs_set_str(h, KEY_PREVVER, s_status.previous_version);
    if (err == ESP_OK) {
        if (pending && pending[0]) err = nvs_set_str(h, KEY_PENDING, pending);
        else {
            esp_err_t erase_err = nvs_erase_key(h, KEY_PENDING);
            if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        }
    }
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t ota_manager_init(void)
{
    if (s_lock == NULL) s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;
    memset(&s_status, 0, sizeof(s_status));
    s_status.initialized = true;

    char pending[17];
    esp_err_t hist_err = load_history(pending);
    if (hist_err != ESP_OK) {
        ESP_LOGW(TAG, "persistent OTA lifecycle history unavailable: %s", esp_err_to_name(hist_err));
        pending[0] = '\0';
    }

    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    copy_label(s_status.running_partition, sizeof(s_status.running_partition), running);
    copy_label(s_status.boot_partition, sizeof(s_status.boot_partition), boot);
    copy_label(s_status.next_partition, sizeof(s_status.next_partition), next);
    esp_app_desc_t desc;
    if (running && esp_ota_get_partition_description(running, &desc) == ESP_OK) {
        snprintf(s_status.running_version, sizeof(s_status.running_version), "%s", desc.version);
        snprintf(s_status.running_project, sizeof(s_status.running_project), "%s", desc.project_name);
    }
    esp_ota_img_states_t state;
    if (running && esp_ota_get_state_partition(running, &state) == ESP_OK) {
        s_status.pending_verify = (state == ESP_OTA_IMG_PENDING_VERIFY);
    }
    s_status.last_boot_confirmed = !s_status.pending_verify;

    /* A persisted target that is not the partition now running means the
     * bootloader recovered from the staged image before application-level
     * confirmation. Count that as a detected rollback and clear the marker. */
    if (pending[0] && strcmp(pending, s_status.running_partition) != 0) {
        s_status.rollbacks_detected++;
        s_status.failures++;
        set_result("rollback_detected");
        (void)persist_history(NULL);
        operations_history_record(OPERATIONS_EVENT_RECOVERY, 0, "OTA bootloader rollback detected");
        ESP_LOGW(TAG, "OTA rollback detected: staged=%s running=%s", pending, s_status.running_partition);
    } else {
        set_result(s_status.pending_verify ? "pending_verification" : "ready");
    }

    ESP_LOGI(TAG, "running=%s boot=%s next=%s state=%s attempts=%" PRIu32
                  " staged=%" PRIu32 " confirmed=%" PRIu32 " failures=%" PRIu32
                  " rollbacks=%" PRIu32,
             s_status.running_partition, s_status.boot_partition, s_status.next_partition,
             s_status.pending_verify ? "pending_verify" : "valid", s_status.attempts,
             s_status.successes, s_status.confirmations, s_status.failures,
             s_status.rollbacks_detected);
    return ESP_OK;
}

esp_err_t ota_manager_begin(size_t image_size)
{
    if (!s_status.initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) != pdTRUE) return ESP_ERR_TIMEOUT;
    if (s_status.update_in_progress) { xSemaphoreGive(s_lock); return ESP_ERR_INVALID_STATE; }
    s_target = esp_ota_get_next_update_partition(NULL);
    if (s_target == NULL || s_target->type != ESP_PARTITION_TYPE_APP) {
        set_result("no_update_partition"); xSemaphoreGive(s_lock); return ESP_ERR_NOT_FOUND;
    }
    if (image_size == 0 || image_size > s_target->size) {
        set_result("invalid_image_size"); xSemaphoreGive(s_lock); return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t err = esp_ota_begin(s_target, image_size, &s_handle);
    if (err == ESP_OK) {
        s_status.update_in_progress = true;
        s_status.bytes_written = 0;
        s_status.attempts++;
        set_result("receiving");
        (void)persist_history(NULL);
        operations_history_record(OPERATIONS_EVENT_CONFIG_CHANGE, 0, "OTA upload started");
    } else {
        s_status.failures++; set_result("begin_failed"); (void)persist_history(NULL);
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t ota_manager_write(const void *data, size_t length)
{
    if (!data || length == 0) return ESP_ERR_INVALID_ARG;
    if (!s_status.update_in_progress) return ESP_ERR_INVALID_STATE;
    esp_err_t err = esp_ota_write(s_handle, data, length);
    if (err == ESP_OK) s_status.bytes_written += length;
    else { s_status.failures++; set_result("write_failed"); (void)persist_history(NULL); }
    return err;
}

void ota_manager_abort(void)
{
    if (!s_status.update_in_progress) return;
    esp_ota_abort(s_handle);
    s_status.update_in_progress = false;
    s_status.failures++;
    set_result("aborted");
    (void)persist_history(NULL);
    operations_history_record(OPERATIONS_EVENT_FAULT, 0, "OTA upload aborted");
}

esp_err_t ota_manager_finish(void)
{
    if (!s_status.update_in_progress || s_target == NULL) return ESP_ERR_INVALID_STATE;
    esp_err_t err = esp_ota_end(s_handle);
    if (err == ESP_OK) err = esp_ota_set_boot_partition(s_target);
    s_status.update_in_progress = false;
    if (err == ESP_OK) {
        s_status.successes++;
        const esp_partition_t *running = esp_ota_get_running_partition();
        esp_app_desc_t running_desc;
        if (running && esp_ota_get_partition_description(running, &running_desc) == ESP_OK) {
            snprintf(s_status.previous_version, sizeof(s_status.previous_version), "%s", running_desc.version);
        }
        copy_label(s_status.boot_partition, sizeof(s_status.boot_partition), s_target);
        set_result("staged_reboot_required");
        (void)persist_history(s_target->label);
        operations_history_record(OPERATIONS_EVENT_RECOVERY, 0, "OTA image validated and staged");
        ESP_LOGI(TAG, "OTA image staged on %s (%u bytes); reboot required", s_target->label,
                 (unsigned)s_status.bytes_written);
    } else {
        s_status.failures++; set_result("validation_or_stage_failed");
        (void)persist_history(NULL);
        operations_history_record(OPERATIONS_EVENT_FAULT, (int32_t)err, "OTA image validation/staging failed");
    }
    s_target = NULL;
    return err;
}

esp_err_t ota_manager_confirm_running_image(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) return ESP_ERR_NOT_FOUND;
    esp_ota_img_states_t state;
    esp_err_t err = esp_ota_get_state_partition(running, &state);
    if (err != ESP_OK) return err;
    if (state != ESP_OTA_IMG_PENDING_VERIFY) {
        s_status.pending_verify = false;
        s_status.last_boot_confirmed = true;
        /* Clear a stale marker if this image was already confirmed before the
         * current boot (for example after a normal software reboot). */
        (void)persist_history(NULL);
        return ESP_OK;
    }
    err = esp_ota_mark_app_valid_cancel_rollback();
    if (err == ESP_OK) {
        s_status.pending_verify = false;
        s_status.last_boot_confirmed = true;
        s_status.confirmations++;
        set_result("running_image_confirmed");
        (void)persist_history(NULL);
        operations_history_record(OPERATIONS_EVENT_RECOVERY, 0, "OTA running image confirmed");
        ESP_LOGI(TAG, "Running OTA image confirmed valid");
    }
    return err;
}

esp_err_t ota_manager_get_status(ota_manager_status_t *status)
{
    if (!status) return ESP_ERR_INVALID_ARG;
    *status = s_status;
    return ESP_OK;
}

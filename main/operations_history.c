#include "operations_history.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"

static const char *TAG = "OPS_HISTORY";

#define OPS_NS "ops_hist"
#define KEY_BOOT "boot_count"
#define KEY_NEXT "next_seq"
#define KEY_COUNT "event_count"
#define KEY_DROPPED "dropped"
#define KEY_RST_PWR "rst_pwr"
#define KEY_RST_EXT "rst_ext"
#define KEY_RST_SW "rst_sw"
#define KEY_RST_PANIC "rst_panic"
#define KEY_RST_WDT "rst_wdt"
#define KEY_RST_SLEEP "rst_sleep"
#define KEY_RST_BROWN "rst_brown"
#define KEY_RST_OTHER "rst_other"
#define KEY_RST_LAST "rst_last"
#define KEY_RST_CLASS "rst_class"

static SemaphoreHandle_t s_lock;
static operations_history_status_t s_status;
static bool s_initialized;

static void event_key(uint32_t sequence, char key[16])
{
    (void)snprintf(key, 16, "e%02u", (unsigned)(sequence % OPERATIONS_HISTORY_CAPACITY));
}

const char *operations_reset_class_name(uint8_t reset_class)
{
    switch ((operations_reset_class_t)reset_class) {
        case OPERATIONS_RESET_POWER_ON: return "power_on";
        case OPERATIONS_RESET_EXTERNAL: return "external";
        case OPERATIONS_RESET_SOFTWARE: return "software";
        case OPERATIONS_RESET_PANIC: return "panic";
        case OPERATIONS_RESET_WATCHDOG: return "watchdog";
        case OPERATIONS_RESET_DEEP_SLEEP: return "deep_sleep";
        case OPERATIONS_RESET_BROWNOUT: return "brownout";
        case OPERATIONS_RESET_OTHER: return "other";
        case OPERATIONS_RESET_UNKNOWN:
        default: return "unknown";
    }
}

static operations_reset_class_t classify_reset(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON: return OPERATIONS_RESET_POWER_ON;
        case ESP_RST_EXT: return OPERATIONS_RESET_EXTERNAL;
        case ESP_RST_SW: return OPERATIONS_RESET_SOFTWARE;
        case ESP_RST_PANIC: return OPERATIONS_RESET_PANIC;
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT: return OPERATIONS_RESET_WATCHDOG;
        case ESP_RST_DEEPSLEEP: return OPERATIONS_RESET_DEEP_SLEEP;
        case ESP_RST_BROWNOUT: return OPERATIONS_RESET_BROWNOUT;
        case ESP_RST_UNKNOWN: return OPERATIONS_RESET_UNKNOWN;
        default: return OPERATIONS_RESET_OTHER;
    }
}

static void increment_reset_counter(operations_reset_class_t reset_class)
{
    switch (reset_class) {
        case OPERATIONS_RESET_POWER_ON: s_status.reset_power_on_count++; break;
        case OPERATIONS_RESET_EXTERNAL: s_status.reset_external_count++; break;
        case OPERATIONS_RESET_SOFTWARE: s_status.reset_software_count++; break;
        case OPERATIONS_RESET_PANIC: s_status.reset_panic_count++; break;
        case OPERATIONS_RESET_WATCHDOG: s_status.reset_watchdog_count++; break;
        case OPERATIONS_RESET_DEEP_SLEEP: s_status.reset_deep_sleep_count++; break;
        case OPERATIONS_RESET_BROWNOUT: s_status.reset_brownout_count++; break;
        case OPERATIONS_RESET_OTHER:
        case OPERATIONS_RESET_UNKNOWN:
        default: s_status.reset_other_count++; break;
    }
}

static esp_err_t persist_meta(nvs_handle_t handle)
{
    esp_err_t err = nvs_set_u32(handle, KEY_BOOT, s_status.boot_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_NEXT, s_status.next_sequence);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_COUNT, s_status.event_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_DROPPED, s_status.dropped_events);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_PWR, s_status.reset_power_on_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_EXT, s_status.reset_external_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_SW, s_status.reset_software_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_PANIC, s_status.reset_panic_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_WDT, s_status.reset_watchdog_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_SLEEP, s_status.reset_deep_sleep_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_BROWN, s_status.reset_brownout_count);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_RST_OTHER, s_status.reset_other_count);
    if (err == ESP_OK) err = nvs_set_i32(handle, KEY_RST_LAST, s_status.last_reset_reason);
    if (err == ESP_OK) err = nvs_set_u8(handle, KEY_RST_CLASS, s_status.last_reset_class);
    return err;
}

static void load_meta(nvs_handle_t handle)
{
    (void)nvs_get_u32(handle, KEY_BOOT, &s_status.boot_count);
    (void)nvs_get_u32(handle, KEY_NEXT, &s_status.next_sequence);
    (void)nvs_get_u32(handle, KEY_COUNT, &s_status.event_count);
    (void)nvs_get_u32(handle, KEY_DROPPED, &s_status.dropped_events);
    (void)nvs_get_u32(handle, KEY_RST_PWR, &s_status.reset_power_on_count);
    (void)nvs_get_u32(handle, KEY_RST_EXT, &s_status.reset_external_count);
    (void)nvs_get_u32(handle, KEY_RST_SW, &s_status.reset_software_count);
    (void)nvs_get_u32(handle, KEY_RST_PANIC, &s_status.reset_panic_count);
    (void)nvs_get_u32(handle, KEY_RST_WDT, &s_status.reset_watchdog_count);
    (void)nvs_get_u32(handle, KEY_RST_SLEEP, &s_status.reset_deep_sleep_count);
    (void)nvs_get_u32(handle, KEY_RST_BROWN, &s_status.reset_brownout_count);
    (void)nvs_get_u32(handle, KEY_RST_OTHER, &s_status.reset_other_count);
    (void)nvs_get_i32(handle, KEY_RST_LAST, &s_status.last_reset_reason);
    (void)nvs_get_u8(handle, KEY_RST_CLASS, &s_status.last_reset_class);
}

static void fill_time(operations_event_t *event)
{
    const int64_t uptime_us = esp_timer_get_time();
    event->uptime_seconds = uptime_us > 0 ? (uint32_t)(uptime_us / 1000000LL) : 0U;
    const time_t now = time(NULL);
    if (now > (time_t)1700000000) {
        event->unix_time = (int64_t)now;
        event->unix_time_valid = 1U;
    }
}

esp_err_t operations_history_init(void)
{
    if (s_initialized) return ESP_OK;
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(OPS_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        return err;
    }

    memset(&s_status, 0, sizeof(s_status));
    load_meta(handle);
    if (s_status.event_count > OPERATIONS_HISTORY_CAPACITY) s_status.event_count = OPERATIONS_HISTORY_CAPACITY;

    const esp_reset_reason_t reason = esp_reset_reason();
    const operations_reset_class_t reset_class = classify_reset(reason);
    s_status.boot_count++;
    s_status.last_reset_reason = (int32_t)reason;
    s_status.last_reset_class = (uint8_t)reset_class;
    increment_reset_counter(reset_class);

    err = persist_meta(handle);
    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    if (err != ESP_OK) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        memset(&s_status, 0, sizeof(s_status));
        return err;
    }

    s_initialized = true;
    char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
    (void)snprintf(detail, sizeof(detail), "reset=%d class=%s", (int)reason,
                   operations_reset_class_name((uint8_t)reset_class));
    err = operations_history_record(OPERATIONS_EVENT_BOOT, (int32_t)reason, detail);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Persistent operations history ready: boot=%u events=%u reset=%d class=%s",
                 (unsigned)s_status.boot_count, (unsigned)s_status.event_count, (int)reason,
                 operations_reset_class_name((uint8_t)reset_class));
    } else {
        ESP_LOGW(TAG, "Failed to record boot event: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t operations_history_record(operations_event_type_t type, int32_t code, const char *detail)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) return ESP_FAIL;

    operations_event_t event = {0};
    event.sequence = s_status.next_sequence;
    event.boot_id = s_status.boot_count;
    event.type = (uint8_t)type;
    event.code = code;
    fill_time(&event);
    if (detail != NULL) {
        (void)strncpy(event.detail, detail, OPERATIONS_EVENT_DETAIL_MAX);
        event.detail[OPERATIONS_EVENT_DETAIL_MAX] = '\0';
    }

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(OPS_NS, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        char key[16];
        event_key(event.sequence, key);
        err = nvs_set_blob(handle, key, &event, sizeof(event));
    }
    /* Publish updated metadata only after NVS commit succeeds. */
    const operations_history_status_t committed_status = s_status;
    if (err == ESP_OK) {
        s_status.next_sequence++;
        if (s_status.event_count < OPERATIONS_HISTORY_CAPACITY) s_status.event_count++;
        else s_status.dropped_events++;
        err = persist_meta(handle);
    }
    if (err == ESP_OK) err = nvs_commit(handle);
    if (err != ESP_OK) {
        s_status = committed_status;
        s_status.write_failures++;
        s_status.last_storage_error = (int32_t)err;
        ESP_LOGW(TAG, "History event persistence failed: %s", esp_err_to_name(err));
    }
    if (handle != 0) nvs_close(handle);
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t operations_history_get_status(operations_history_status_t *out_status)
{
    if (out_status == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) return ESP_FAIL;
    *out_status = s_status;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t operations_history_read(operations_event_t *events, size_t capacity, size_t *out_count)
{
    if (events == NULL || out_count == NULL || capacity == 0U) return ESP_ERR_INVALID_ARG;
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) return ESP_FAIL;

    uint32_t count = s_status.event_count;
    if (count > capacity) count = (uint32_t)capacity;
    uint32_t first = s_status.next_sequence - s_status.event_count;
    if (s_status.event_count > count) first = s_status.next_sequence - count;

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(OPS_NS, NVS_READONLY, &handle);
    size_t got = 0U;
    if (err == ESP_OK) {
        for (uint32_t sequence = first; sequence < s_status.next_sequence && got < count; sequence++) {
            char key[16];
            event_key(sequence, key);
            size_t length = sizeof(events[got]);
            const esp_err_t read_err = nvs_get_blob(handle, key, &events[got], &length);
            if (read_err == ESP_OK && length == sizeof(events[got]) && events[got].sequence == sequence) {
                got++;
            } else {
                s_status.read_failures++;
                s_status.last_storage_error = (int32_t)(read_err == ESP_OK ? ESP_ERR_INVALID_SIZE : read_err);
                err = read_err == ESP_OK ? ESP_ERR_INVALID_SIZE : read_err;
                ESP_LOGW(TAG, "History event read failed: seq=%" PRIu32 " error=%s",
                         sequence, esp_err_to_name(err));
                break;
            }
        }
        nvs_close(handle);
    } else {
        s_status.read_failures++;
        s_status.last_storage_error = (int32_t)err;
    }
    *out_count = got;
    xSemaphoreGive(s_lock);
    return err;
}

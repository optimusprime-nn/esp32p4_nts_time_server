#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
#define OPERATIONS_HISTORY_CAPACITY 32U
#define OPERATIONS_EVENT_DETAIL_MAX 63U
typedef enum {
    OPERATIONS_EVENT_BOOT = 1,
    OPERATIONS_EVENT_CONFIG_CHANGE,
    OPERATIONS_EVENT_CERTIFICATE,
    OPERATIONS_EVENT_SECURITY,
    OPERATIONS_EVENT_FAULT,
    OPERATIONS_EVENT_RECOVERY,
} operations_event_type_t;
typedef enum {
    OPERATIONS_RESET_UNKNOWN = 0,
    OPERATIONS_RESET_POWER_ON,
    OPERATIONS_RESET_EXTERNAL,
    OPERATIONS_RESET_SOFTWARE,
    OPERATIONS_RESET_PANIC,
    OPERATIONS_RESET_WATCHDOG,
    OPERATIONS_RESET_DEEP_SLEEP,
    OPERATIONS_RESET_BROWNOUT,
    OPERATIONS_RESET_OTHER,
} operations_reset_class_t;
typedef struct {
    uint32_t sequence;
    uint32_t boot_id;
    uint32_t uptime_seconds;
    int64_t unix_time;
    uint8_t unix_time_valid;
    uint8_t type;
    int32_t code;
    char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
} operations_event_t;
typedef struct {
    uint32_t boot_count;
    uint32_t next_sequence;
    uint32_t event_count;
    uint32_t dropped_events;
    uint32_t reset_power_on_count;
    uint32_t reset_external_count;
    uint32_t reset_software_count;
    uint32_t reset_panic_count;
    uint32_t reset_watchdog_count;
    uint32_t reset_deep_sleep_count;
    uint32_t reset_brownout_count;
    uint32_t reset_other_count;
    int32_t last_reset_reason;
    uint8_t last_reset_class;
} operations_history_status_t;
esp_err_t operations_history_init(void);
esp_err_t operations_history_record(operations_event_type_t type, int32_t code, const char *detail);
esp_err_t operations_history_get_status(operations_history_status_t *out_status);
esp_err_t operations_history_read(operations_event_t *events, size_t capacity, size_t *out_count);
const char *operations_reset_class_name(uint8_t reset_class);
#ifdef __cplusplus
}
#endif

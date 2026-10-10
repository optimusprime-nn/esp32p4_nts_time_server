#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SD_STORAGE_STATE_DISABLED = 0,
    SD_STORAGE_STATE_STARTING,
    SD_STORAGE_STATE_UNMOUNTED,
    SD_STORAGE_STATE_MOUNTING,
    SD_STORAGE_STATE_MOUNTED,
    SD_STORAGE_STATE_DEGRADED,
} sd_storage_state_t;

typedef struct {
    bool configured;
    bool mounted;
    bool worker_running;
    bool desired_mounted;
    bool low_space;
    uint64_t capacity_bytes;
    uint64_t free_bytes;
    uint64_t reserve_bytes;
    uint64_t bytes_written;
    uint32_t write_failures;
    uint32_t command_queue_drops;
    uint32_t mount_failures;
    uint32_t mount_successes;
    uint32_t remount_attempts;
    uint32_t archived_events;
    uint32_t retention_deleted_files;
    uint32_t format_count;
    uint32_t format_failures;
    uint32_t erase_count;
    int32_t last_format_result;
    int32_t last_error;
    sd_storage_state_t state;
    char card_name[24];
    char mount_point[24];
} sd_storage_status_t;

/* Optional operations-plane storage. Failure is always fail-open to timing. */
esp_err_t sd_storage_start(void);
esp_err_t sd_storage_get_status(sd_storage_status_t *out);
esp_err_t sd_storage_request_flush(void);
esp_err_t sd_storage_request_mount(void);
esp_err_t sd_storage_request_unmount(void);
esp_err_t sd_storage_request_format(void);
esp_err_t sd_storage_request_erase_logs(void);
const char *sd_storage_state_name(sd_storage_state_t state);

#ifdef __cplusplus
}
#endif

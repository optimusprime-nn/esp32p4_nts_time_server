#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool initialized;
    bool update_in_progress;
    bool pending_verify;
    bool last_boot_confirmed;
    uint32_t attempts;
    uint32_t successes;
    uint32_t failures;
    uint32_t confirmations;
    uint32_t rollbacks_detected;
    size_t bytes_written;
    char running_partition[17];
    char boot_partition[17];
    char next_partition[17];
    char running_version[33];
    char previous_version[33];
    char running_project[33];
    char last_result[48];
} ota_manager_status_t;

esp_err_t ota_manager_init(void);
esp_err_t ota_manager_begin(size_t image_size);
esp_err_t ota_manager_write(const void *data, size_t length);
esp_err_t ota_manager_finish(void);
void ota_manager_abort(void);
esp_err_t ota_manager_confirm_running_image(void);
/* Marks a still-pending running image invalid and reboots into the previous
 * one. Returns ESP_ERR_INVALID_STATE (and does nothing) if the image is not
 * pending. */
esp_err_t ota_manager_reject_running_image(const char *reason);
esp_err_t ota_manager_get_status(ota_manager_status_t *status);

/* Describes the image in the other OTA slot that a manual rollback would boot.
 * Returns ESP_ERR_NOT_FOUND when that slot holds no usable application (empty,
 * erased by a failed upload, or marked invalid by the bootloader). */
esp_err_t ota_manager_get_rollback_target(char *partition, size_t partition_len,
                                          char *version, size_t version_len);
/* Verifies the other OTA slot's image and selects it for the next boot. The
 * caller reboots. With bootloader rollback enabled the restored image boots
 * pending-verify, so it must pass the same soak as a fresh upload. */
esp_err_t ota_manager_rollback_to_previous(void);

#ifdef __cplusplus
}
#endif

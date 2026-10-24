#include "sd_storage.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "driver/gpio.h"
#include "driver/sdmmc_host.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "operations_history.h"
#include "sdmmc_cmd.h"
#include "sd_pwr_ctrl_by_on_chip_ldo.h"

static const char *TAG = "SD_STORAGE";
static const char *MOUNT = "/sdcard";
static const char *LOG_DIR = "/sdcard/logs";

#define SD_STORAGE_TASK_STACK       6144U
#define SD_STORAGE_TASK_PRIORITY       2U
#define SD_STORAGE_POLL_MS          2000U
#define SD_STORAGE_HOUSEKEEPING_MS  60000U
#define SD_STORAGE_RETRY_MS        10000U
#define SD_STORAGE_CMD_DEPTH           8U

typedef enum {
    SD_CMD_FLUSH = 1,
    SD_CMD_MOUNT,
    SD_CMD_UNMOUNT,
    SD_CMD_FORMAT,
    SD_CMD_ERASE_LOGS,
} sd_command_t;

static SemaphoreHandle_t s_lock;
static QueueHandle_t s_commands;
static sd_storage_status_t s_status;
static sdmmc_card_t *s_card;
static sd_pwr_ctrl_handle_t s_pwr_ctrl;
static bool s_started;
static FILE *s_log;
static uint32_t s_boot_id;
static uint32_t s_last_sequence;
static bool s_have_sequence;
static TickType_t s_next_mount_attempt;

static void status_lock(void) { if (s_lock != NULL) (void)xSemaphoreTake(s_lock, portMAX_DELAY); }
static void status_unlock(void) { if (s_lock != NULL) xSemaphoreGive(s_lock); }

const char *sd_storage_state_name(sd_storage_state_t state)
{
    switch (state) {
        case SD_STORAGE_STATE_DISABLED: return "disabled";
        case SD_STORAGE_STATE_STARTING: return "starting";
        case SD_STORAGE_STATE_UNMOUNTED: return "unmounted";
        case SD_STORAGE_STATE_MOUNTING: return "mounting";
        case SD_STORAGE_STATE_MOUNTED: return "mounted";
        case SD_STORAGE_STATE_DEGRADED: return "degraded";
        default: return "unknown";
    }
}

static void refresh_space(void)
{
    uint64_t capacity_bytes = 0;
    uint64_t free_bytes = 0;
    const esp_err_t err = esp_vfs_fat_info(MOUNT, &capacity_bytes, &free_bytes);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Unable to query FAT capacity/free space: %s", esp_err_to_name(err));
        return;
    }

    status_lock();
    s_status.capacity_bytes = capacity_bytes;
    s_status.free_bytes = free_bytes;
    s_status.low_space = free_bytes < s_status.reserve_bytes;
    status_unlock();
}

static void close_log(void)
{
    if (s_log != NULL) {
        (void)fflush(s_log);
        (void)fclose(s_log);
        s_log = NULL;
    }
}

static void unmount_card(bool faulted)
{
#if CONFIG_APP_SD_STORAGE_ENABLE
    close_log();
    if (s_card != NULL) {
        (void)esp_vfs_fat_sdcard_unmount(MOUNT, s_card);
        s_card = NULL;
    }
    /*
     * Keep LDO4 acquired for the lifetime of the storage subsystem.
     * Mount failure, safe unmount, card removal, and retry must not cycle the
     * ESP32-P4 SD I/O power domain.  Only the SDMMC/VFS/card state is torn down.
     */
#endif
    status_lock();
    s_status.mounted = false;
    s_status.card_name[0] = '\0';
    s_status.capacity_bytes = 0;
    s_status.free_bytes = 0;
    s_status.low_space = false;
    s_status.state = faulted ? SD_STORAGE_STATE_DEGRADED : SD_STORAGE_STATE_UNMOUNTED;
    status_unlock();
}

static esp_err_t open_boot_log(void)
{
    operations_history_status_t hs;
    esp_err_t err = operations_history_get_status(&hs);
    if (err != ESP_OK) return err;

    s_boot_id = hs.boot_count;
    if (mkdir(LOG_DIR, 0755) != 0 && errno != EEXIST) return ESP_FAIL;

    char path[96];
    snprintf(path, sizeof(path), "%s/boot-%08" PRIu32 ".jsonl", LOG_DIR, s_boot_id);
    s_log = fopen(path, "a");
    if (s_log == NULL) return ESP_FAIL;

    if (fseek(s_log, 0, SEEK_END) != 0) { close_log(); return ESP_FAIL; }
    const long size = ftell(s_log);
    if (size < 0) { close_log(); return ESP_FAIL; }
    if (size == 0) {
        const int n = fprintf(s_log,
            "{\"record\":\"boot\",\"boot_id\":%" PRIu32 ",\"storage_schema\":2}\n",
            s_boot_id);
        if (n < 0 || fflush(s_log) != 0) { close_log(); return ESP_FAIL; }
        status_lock(); s_status.bytes_written += (uint64_t)n; status_unlock();
    }
    return ESP_OK;
}

static bool find_oldest_archive(char *out_name, size_t out_size, size_t *out_count)
{
    DIR *dir = opendir(LOG_DIR);
    if (dir == NULL) return false;
    size_t count = 0;
    char oldest[NAME_MAX + 1U] = {0};
    char current[40];
    snprintf(current, sizeof(current), "boot-%08" PRIu32 ".jsonl", s_boot_id);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "boot-", 5) != 0 || strstr(de->d_name, ".jsonl") == NULL) continue;
        count++;
        if (strcmp(de->d_name, current) == 0) continue;
        if (oldest[0] == '\0' || strcmp(de->d_name, oldest) < 0) {
            const size_t name_len = strnlen(de->d_name, sizeof(oldest));
            if (name_len >= sizeof(oldest)) continue;
            memcpy(oldest, de->d_name, name_len + 1U);
        }
    }
    closedir(dir);
    if (out_count != NULL) *out_count = count;
    if (oldest[0] == '\0') return false;
    const size_t oldest_len = strlen(oldest);
    if (out_size == 0U || oldest_len >= out_size) return false;
    memcpy(out_name, oldest, oldest_len + 1U);
    return true;
}

static bool delete_oldest_archive(void)
{
    char name[NAME_MAX + 1U];
    if (!find_oldest_archive(name, sizeof(name), NULL)) return false;
    char path[PATH_MAX];
    const int path_len = snprintf(path, sizeof(path), "%s/%s", LOG_DIR, name);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) return false;
    if (unlink(path) != 0) return false;
    status_lock(); s_status.retention_deleted_files++; status_unlock();
    return true;
}

static void enforce_retention(void)
{
#if CONFIG_APP_SD_STORAGE_ENABLE
    size_t count = 0;
    char oldest[NAME_MAX + 1U];
    while (find_oldest_archive(oldest, sizeof(oldest), &count) && count > CONFIG_APP_SD_MAX_ARCHIVE_FILES) {
        if (!delete_oldest_archive()) break;
    }
    /* Enforce the reserve fully, not one archive per poll. Never delete the
     * current boot archive; if it is the only file left, report low-space and
     * stop rather than spinning. */
    for (;;) {
        refresh_space();
        status_lock(); const bool low = s_status.low_space; status_unlock();
        if (!low || !delete_oldest_archive()) break;
    }
    refresh_space();
#endif
}

static esp_err_t mount_card(bool explicit_format_if_needed)
{
#if !CONFIG_APP_SD_STORAGE_ENABLE
    (void)explicit_format_if_needed;
    return ESP_ERR_NOT_SUPPORTED;
#else
    status_lock();
    s_status.state = SD_STORAGE_STATE_MOUNTING;
    s_status.remount_attempts++;
    status_unlock();

    /*
     * JC-ESP32P4-M3 dedicated SD interface:
     *   D0=GPIO39 D1=GPIO40 D2=GPIO41 D3=GPIO42 CLK=GPIO43 CMD=GPIO44.
     * The schematic connects ESP_LDO_VO4 to TF_VCC, so initialize on-chip
     * LDO channel 4 before SDMMC communication.  Keep the bus at 20 MHz / 3.3 V;
     * UHS-I voltage switching is intentionally not enabled for operations storage.
     */
    esp_err_t err = ESP_OK;
    if (s_pwr_ctrl == NULL) {
        sd_pwr_ctrl_ldo_config_t ldo_cfg = {
            .ldo_chan_id = 4,
        };
        err = sd_pwr_ctrl_new_on_chip_ldo(&ldo_cfg, &s_pwr_ctrl);
        if (err != ESP_OK) {
            s_pwr_ctrl = NULL;
            return err;
        }

        /* Allow the SD I/O/card supply domain to settle before driving SDMMC. */
        vTaskDelay(pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "SD LDO4 power domain enabled and retained across mount retries");
    }

    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    host.slot = SDMMC_HOST_SLOT_0;
    host.max_freq_khz = SDMMC_FREQ_DEFAULT;
    host.pwr_ctrl_handle = s_pwr_ctrl;

    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = 4;
    slot.clk = GPIO_NUM_43;
    slot.cmd = GPIO_NUM_44;
    slot.d0 = GPIO_NUM_39;
    slot.d1 = GPIO_NUM_40;
    slot.d2 = GPIO_NUM_41;
    slot.d3 = GPIO_NUM_42;
    slot.cd = GPIO_NUM_NC;
    slot.wp = GPIO_NUM_NC;

    esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        /* Only true for an explicit authenticated FORMAT request. */
        .format_if_mount_failed = explicit_format_if_needed,
        .max_files = 6,
        .allocation_unit_size = 16 * 1024,
    };
    err = esp_vfs_fat_sdmmc_mount(MOUNT, &host, &slot, &mount_cfg, &s_card);
    if (err != ESP_OK) {
        /* Keep LDO4 enabled; retries must not cycle the ESP32-P4 SD power domain. */
        s_card = NULL;
        return err;
    }

    err = open_boot_log();
    if (err != ESP_OK) {
        unmount_card(true);
        return err;
    }

    status_lock();
    s_status.mounted = true;
    s_status.mount_successes++;
    s_status.last_error = ESP_OK;
    s_status.state = SD_STORAGE_STATE_MOUNTED;
    if (s_card != NULL) snprintf(s_status.card_name, sizeof(s_status.card_name), "%s", s_card->cid.name);
    status_unlock();
    refresh_space();
    enforce_retention();
    ESP_LOGI(TAG, "SDMMC 4-bit operational storage mounted at %s (GPIO39-44, LDO4); timing path remains independent", MOUNT);
    return ESP_OK;
#endif
}

static esp_err_t archive_current_boot_events(void)
{
    if (s_log == NULL) return ESP_ERR_INVALID_STATE;

    /* This runs every 2 s. Reading the whole NVS ring each time costs ~150
     * flash reads, each of which disables the cache and stalls the other
     * core, so only read when a new event has been recorded. */
    static uint32_t s_seen_next_sequence;
    static bool s_seen_valid;
    operations_history_status_t hist;
    const bool hist_ok = operations_history_get_status(&hist) == ESP_OK;
    if (hist_ok && s_seen_valid && hist.next_sequence == s_seen_next_sequence) return ESP_OK;

    /* Static: 3 KB would otherwise sit on this task's 6 KB stack while the
     * file I/O below runs. Only this task calls this function. */
    static operations_event_t events[OPERATIONS_HISTORY_CAPACITY];
    size_t count = 0;
    esp_err_t err = operations_history_read(events, OPERATIONS_HISTORY_CAPACITY, &count);
    if (err != ESP_OK) return err;

    uint32_t committed_sequence = s_last_sequence;
    bool wrote_any = false;
    uint32_t written_events = 0;
    uint64_t written_bytes = 0;
    for (size_t i = 0; i < count; ++i) {
        const operations_event_t *e = &events[i];
        if (e->boot_id != s_boot_id) continue;
        if (s_have_sequence && e->sequence <= s_last_sequence) continue;
        char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
        snprintf(detail, sizeof(detail), "%s", e->detail);
        for (char *p = detail; *p != '\0'; ++p) if ((unsigned char)*p < 0x20U || *p == '"' || *p == '\\') *p = '_';

        const int n = fprintf(s_log,
            "{\"record\":\"event\",\"sequence\":%" PRIu32
            ",\"boot_id\":%" PRIu32 ",\"uptime_seconds\":%" PRIu32
            ",\"unix_time\":%" PRId64 ",\"unix_time_valid\":%u"
            ",\"type\":%u,\"code\":%" PRId32 ",\"detail\":\"%s\"}\n",
            e->sequence, e->boot_id, e->uptime_seconds, e->unix_time,
            (unsigned)e->unix_time_valid, (unsigned)e->type, e->code, detail);
        if (n < 0) return ESP_FAIL;
        committed_sequence = e->sequence;
        wrote_any = true;
        written_events++;
        written_bytes += (uint64_t)n;
    }
    if (!wrote_any) { if (hist_ok) { s_seen_next_sequence = hist.next_sequence; s_seen_valid = true; } return ESP_OK; }
    if (fflush(s_log) != 0) return ESP_FAIL;

    s_last_sequence = committed_sequence;
    s_have_sequence = true;
    status_lock();
    s_status.bytes_written += written_bytes;
    s_status.archived_events += written_events;
    status_unlock();
    if (hist_ok) { s_seen_next_sequence = hist.next_sequence; s_seen_valid = true; }
    return ESP_OK;
}

static void record_io_failure(esp_err_t err)
{
    status_lock();
    s_status.write_failures++;
    s_status.last_error = (int32_t)err;
    status_unlock();
    ESP_LOGW(TAG, "SD I/O failed: %s; unmounting storage, timing services unaffected", esp_err_to_name(err));
    unmount_card(true);
    s_next_mount_attempt = xTaskGetTickCount() + pdMS_TO_TICKS(SD_STORAGE_RETRY_MS);
}


static esp_err_t erase_log_files(void)
{
    close_log();
    DIR *dir = opendir(LOG_DIR);
    if (dir != NULL) {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL) {
            if (strncmp(de->d_name, "boot-", 5) != 0 || strstr(de->d_name, ".jsonl") == NULL) continue;
            char path[PATH_MAX];
            const int path_len = snprintf(path, sizeof(path), "%s/%s", LOG_DIR, de->d_name);
            if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
                closedir(dir);
                return ESP_ERR_INVALID_SIZE;
            }
            if (unlink(path) != 0) { closedir(dir); return ESP_FAIL; }
        }
        closedir(dir);
    } else if (errno != ENOENT) {
        return ESP_FAIL;
    }
    s_have_sequence = false;
    s_last_sequence = 0;
    esp_err_t err = open_boot_log();
    if (err == ESP_OK) {
        status_lock(); s_status.erase_count++; status_unlock();
        refresh_space();
    }
    return err;
}

static esp_err_t format_card(void)
{
#if !CONFIG_APP_SD_STORAGE_ENABLE
    return ESP_ERR_NOT_SUPPORTED;
#else
    status_lock(); const bool mounted = s_status.mounted; status_unlock();

    /*
     * Explicit administrator action only. If a blank/unformatted card cannot be
     * mounted normally, retry the mount with format_if_mount_failed=true here --
     * and nowhere else. This makes Web UI formatting useful for new cards while
     * preserving the no-auto-format boot/recovery policy.
     */
    if (!mounted || s_card == NULL) {
        /* This explicit request may initialize/format a card that normal mount rejected. */
        esp_err_t mount_err = mount_card(true);
        if (mount_err != ESP_OK) {
            status_lock();
            s_status.last_format_result = (int32_t)mount_err;
            s_status.format_failures++;
            status_unlock();
            return mount_err;
        }
    }

    /* Always perform the requested destructive format, even if the card was already FAT-formatted. */
    close_log();
    esp_err_t err = esp_vfs_fat_sdcard_format(MOUNT, s_card);
    status_lock();
    s_status.last_format_result = (int32_t)err;
    if (err == ESP_OK) s_status.format_count++; else s_status.format_failures++;
    status_unlock();
    if (err != ESP_OK) {
        unmount_card(true);
        return err;
    }

    s_have_sequence = false;
    s_last_sequence = 0;
    err = open_boot_log();
    if (err != ESP_OK) {
        unmount_card(true);
        return err;
    }
    refresh_space();
    ESP_LOGW(TAG, "SD card formatted by authenticated management request");
    return ESP_OK;
#endif
}

static void storage_task(void *arg)
{
    (void)arg;
    status_lock(); s_status.worker_running = true; status_unlock();
    TickType_t last_housekeeping = 0;

    for (;;) {
        sd_command_t cmd;
        while (xQueueReceive(s_commands, &cmd, 0) == pdTRUE) {
            if (cmd == SD_CMD_UNMOUNT) {
                status_lock(); s_status.desired_mounted = false; status_unlock();
                unmount_card(false);
                ESP_LOGI(TAG, "SD safely unmounted by management request");
            } else if (cmd == SD_CMD_MOUNT) {
                status_lock(); s_status.desired_mounted = true; status_unlock();
                s_next_mount_attempt = 0;
            } else if (cmd == SD_CMD_FLUSH) {
                status_lock(); const bool is_mounted = s_status.mounted; status_unlock();
                if (!is_mounted) continue;
                const esp_err_t err = archive_current_boot_events();
                if (err != ESP_OK) record_io_failure(err);
            } else if (cmd == SD_CMD_ERASE_LOGS) {
                status_lock(); const bool is_mounted = s_status.mounted; status_unlock();
                if (!is_mounted) continue;
                const esp_err_t err = erase_log_files();
                if (err != ESP_OK) record_io_failure(err);
            } else if (cmd == SD_CMD_FORMAT) {
                const esp_err_t err = format_card();
                if (err != ESP_OK) {
                    status_lock(); s_status.last_error = (int32_t)err; status_unlock();
                    ESP_LOGE(TAG, "Explicit SD format failed: %s; timing services unaffected", esp_err_to_name(err));
                }
            }
        }

        status_lock();
        const bool want_mount = s_status.desired_mounted;
        const bool mounted = s_status.mounted;
        status_unlock();

        const TickType_t now = xTaskGetTickCount();
        const bool retry_due = (s_next_mount_attempt == 0) ||
                               ((int32_t)(now - s_next_mount_attempt) >= 0);
        if (want_mount && !mounted && retry_due) {
            const esp_err_t err = mount_card(false);
            if (err != ESP_OK) {
                status_lock(); s_status.mount_failures++; s_status.last_error = (int32_t)err; s_status.state = SD_STORAGE_STATE_DEGRADED; status_unlock();
                ESP_LOGW(TAG, "SD mount failed: %s; retrying later, timing services unaffected", esp_err_to_name(err));
                s_next_mount_attempt = xTaskGetTickCount() + pdMS_TO_TICKS(SD_STORAGE_RETRY_MS);
            }
        } else if (mounted) {
            const esp_err_t err = archive_current_boot_events();
            if (err != ESP_OK) record_io_failure(err);
            else {
                const TickType_t hk_now = xTaskGetTickCount();
                if (last_housekeeping == 0 || (TickType_t)(hk_now - last_housekeeping) >= pdMS_TO_TICKS(SD_STORAGE_HOUSEKEEPING_MS)) {
                    refresh_space();
                    enforce_retention();
                    last_housekeeping = hk_now;
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(SD_STORAGE_POLL_MS));
    }
}

static esp_err_t queue_command(sd_command_t cmd)
{
    if (s_commands == NULL) return ESP_ERR_INVALID_STATE;
    if (xQueueSend(s_commands, &cmd, 0) == pdTRUE) return ESP_OK;
    status_lock();
    s_status.command_queue_drops++;
    status_unlock();
    return ESP_ERR_TIMEOUT;
}

esp_err_t sd_storage_start(void)
{
    if (s_started) return ESP_OK;

    memset(&s_status, 0, sizeof(s_status));
    snprintf(s_status.mount_point, sizeof(s_status.mount_point), "%s", MOUNT);
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;

#if !CONFIG_APP_SD_STORAGE_ENABLE
    s_status.state = SD_STORAGE_STATE_DISABLED;
    s_started = true;
    ESP_LOGI(TAG, "SD operational storage disabled by configuration");
    return ESP_OK;
#else
    s_status.configured = true;
    s_status.desired_mounted = true;
    s_status.state = SD_STORAGE_STATE_STARTING;
    s_status.reserve_bytes = (uint64_t)CONFIG_APP_SD_MIN_FREE_MIB * 1024ULL * 1024ULL;

    s_commands = xQueueCreate(SD_STORAGE_CMD_DEPTH, sizeof(sd_command_t));
    if (s_commands == NULL) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        memset(&s_status, 0, sizeof(s_status));
        snprintf(s_status.mount_point, sizeof(s_status.mount_point), "%s", MOUNT);
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(storage_task, "sd_storage", SD_STORAGE_TASK_STACK, NULL, SD_STORAGE_TASK_PRIORITY, NULL) != pdPASS) {
        vQueueDelete(s_commands);
        s_commands = NULL;
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        memset(&s_status, 0, sizeof(s_status));
        snprintf(s_status.mount_point, sizeof(s_status.mount_point), "%s", MOUNT);
        return ESP_ERR_NO_MEM;
    }

    /* Publish started only after every required RTOS object and the worker exist.
     * A failed start therefore remains retryable instead of becoming a false
     * success on subsequent calls. */
    s_started = true;
    return ESP_OK;
#endif
}

esp_err_t sd_storage_get_status(sd_storage_status_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (s_lock == NULL) { memset(out, 0, sizeof(*out)); snprintf(out->mount_point, sizeof(out->mount_point), "%s", MOUNT); return ESP_OK; }
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(250)) != pdTRUE) return ESP_ERR_TIMEOUT;
    *out = s_status;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t sd_storage_request_flush(void) { return queue_command(SD_CMD_FLUSH); }
esp_err_t sd_storage_request_mount(void) { return queue_command(SD_CMD_MOUNT); }
esp_err_t sd_storage_request_unmount(void) { return queue_command(SD_CMD_UNMOUNT); }
esp_err_t sd_storage_request_format(void) { return queue_command(SD_CMD_FORMAT); }
esp_err_t sd_storage_request_erase_logs(void) { return queue_command(SD_CMD_ERASE_LOGS); }

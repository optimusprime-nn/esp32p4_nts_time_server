#include "hardware_profile.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "app_config.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"
#include "hal/efuse_hal.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "HW_PROFILE";
static const char *NS = "hw_profile";
static SemaphoreHandle_t s_lock;
static hardware_profile_config_t s_cfg;
static bool s_ready;

static void defaults(hardware_profile_config_t *c)
{
    memset(c, 0, sizeof(*c));
    c->schema_version = APP_HW_PROFILE_SCHEMA_VERSION;
    c->generation = 1;
    snprintf(c->board_family, sizeof(c->board_family), "%s", "legacy-current");
    snprintf(c->board_revision, sizeof(c->board_revision), "%s", "validated");
    c->pps_gpio = APP_PPS_GPIO;
    c->gnss_uart_num = APP_GNSS_UART_NUM;
    c->gnss_rx_gpio = APP_GNSS_UART_RX_GPIO;
    c->gnss_tx_gpio = APP_GNSS_UART_TX_GPIO;
    c->requested_cpu_mhz = 360U;
}

static bool name_ok(const char *s, size_t max)
{
    if (s == NULL || *s == '\0' || strlen(s) > max) {
        return false;
    }

    for (const char *p = s; *p != '\0'; ++p) {
        const char ch = *p;
        const bool valid =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.';

        if (!valid) {
            return false;
        }
    }

    return true;
}

esp_err_t hardware_profile_validate(const hardware_profile_config_t *c)
{
    if (c == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!name_ok(c->board_family, APP_HW_BOARD_FAMILY_MAX) ||
        !name_ok(c->board_revision, APP_HW_BOARD_REV_MAX)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!GPIO_IS_VALID_GPIO(c->pps_gpio) ||
        !GPIO_IS_VALID_GPIO(c->gnss_rx_gpio) ||
        !GPIO_IS_VALID_OUTPUT_GPIO(c->gnss_tx_gpio)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (c->pps_gpio == c->gnss_rx_gpio ||
        c->pps_gpio == c->gnss_tx_gpio ||
        c->gnss_rx_gpio == c->gnss_tx_gpio) {
        return ESP_ERR_INVALID_ARG;
    }

    if (c->gnss_uart_num < 0 || c->gnss_uart_num > 9) {
        return ESP_ERR_INVALID_ARG;
    }

    if (c->requested_cpu_mhz != 360U && c->requested_cpu_mhz != 400U) {
        return ESP_ERR_INVALID_ARG;
    }

    /*
     * 400 MHz is recorded as a requested capability only until that
     * silicon/profile combination has completed timing qualification.
     */
    return ESP_OK;
}

static esp_err_t save(const hardware_profile_config_t *c)
{
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_u32(h, "schema", c->schema_version);
    if (err == ESP_OK) {
        err = nvs_set_u32(h, "gen", c->generation);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "family", c->board_family);
    }
    if (err == ESP_OK) {
        err = nvs_set_str(h, "rev", c->board_revision);
    }
    if (err == ESP_OK) {
        err = nvs_set_i32(h, "pps", c->pps_gpio);
    }
    if (err == ESP_OK) {
        err = nvs_set_i32(h, "guart", c->gnss_uart_num);
    }
    if (err == ESP_OK) {
        err = nvs_set_i32(h, "grx", c->gnss_rx_gpio);
    }
    if (err == ESP_OK) {
        err = nvs_set_i32(h, "gtx", c->gnss_tx_gpio);
    }
    if (err == ESP_OK) {
        err = nvs_set_u32(h, "cpu", c->requested_cpu_mhz);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }

    nvs_close(h);
    return err;
}

static void load_optional_profile_fields(nvs_handle_t h, hardware_profile_config_t *c)
{
    size_t length = sizeof(c->board_family);
    (void)nvs_get_str(h, "family", c->board_family, &length);

    length = sizeof(c->board_revision);
    (void)nvs_get_str(h, "rev", c->board_revision, &length);

    int32_t value = 0;
    if (nvs_get_i32(h, "pps", &value) == ESP_OK) {
        c->pps_gpio = value;
    }
    if (nvs_get_i32(h, "guart", &value) == ESP_OK) {
        c->gnss_uart_num = value;
    }
    if (nvs_get_i32(h, "grx", &value) == ESP_OK) {
        c->gnss_rx_gpio = value;
    }
    if (nvs_get_i32(h, "gtx", &value) == ESP_OK) {
        c->gnss_tx_gpio = value;
    }

    (void)nvs_get_u32(h, "cpu", &c->requested_cpu_mhz);
}

esp_err_t hardware_profile_init(void)
{
    if (s_ready) {
        return ESP_OK;
    }

    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    hardware_profile_config_t config;
    defaults(&config);

    nvs_handle_t h = 0;
    esp_err_t open_err = nvs_open(NS, NVS_READONLY, &h);
    if (open_err == ESP_OK) {
        uint32_t schema = 0;
        if (nvs_get_u32(h, "schema", &schema) == ESP_OK &&
            schema == APP_HW_PROFILE_SCHEMA_VERSION) {
            config.schema_version = schema;
            (void)nvs_get_u32(h, "gen", &config.generation);
            load_optional_profile_fields(h, &config);
        }
        nvs_close(h);
    }

    if (hardware_profile_validate(&config) != ESP_OK) {
        ESP_LOGW(TAG, "Stored profile invalid; reverting to compiled safe defaults");
        defaults(&config);

        esp_err_t err = save(&config);
        if (err != ESP_OK) {
            vSemaphoreDelete(s_lock);
            s_lock = NULL;
            return err;
        }
    } else if (open_err == ESP_ERR_NVS_NOT_FOUND ||
               open_err == ESP_ERR_NVS_NOT_INITIALIZED) {
        esp_err_t err = save(&config);
        if (err != ESP_OK) {
            vSemaphoreDelete(s_lock);
            s_lock = NULL;
            return err;
        }
    } else if (open_err != ESP_OK) {
        vSemaphoreDelete(s_lock);
        s_lock = NULL;
        return open_err;
    }

    s_cfg = config;
    s_ready = true;

    const uint32_t wafer_revision = efuse_hal_chip_revision();
    const uint32_t efuse_block_revision = efuse_hal_blk_version();

    ESP_LOGI(TAG,
             "Profile=%s/%s PPS=%d GNSS=UART%d RX=%d TX=%d "
             "requested_cpu=%" PRIu32 "MHz wafer=v%" PRIu32 ".%02" PRIu32
             " efuse-block=v%" PRIu32 ".%02" PRIu32,
             config.board_family,
             config.board_revision,
             config.pps_gpio,
             config.gnss_uart_num,
             config.gnss_rx_gpio,
             config.gnss_tx_gpio,
             config.requested_cpu_mhz,
             wafer_revision / 100U,
             wafer_revision % 100U,
             efuse_block_revision / 100U,
             efuse_block_revision % 100U);

    return ESP_OK;
}

esp_err_t hardware_profile_get_config(hardware_profile_config_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    *out = s_cfg;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t hardware_profile_get_status(hardware_profile_status_t *out)
{
    if (out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));
    ESP_RETURN_ON_ERROR(hardware_profile_get_config(&out->config), TAG, "get config");

    out->wafer_revision = efuse_hal_chip_revision();
    out->efuse_block_revision = efuse_hal_blk_version();
    out->package_version = efuse_hal_get_chip_ver_pkg();
    out->configured_cpu_mhz = (uint32_t)CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    return ESP_OK;
}

esp_err_t hardware_profile_set_config(const hardware_profile_config_t *candidate)
{
    ESP_RETURN_ON_ERROR(hardware_profile_validate(candidate), TAG, "validate");

    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) {
        return ESP_FAIL;
    }

    hardware_profile_config_t config = *candidate;
    config.schema_version = APP_HW_PROFILE_SCHEMA_VERSION;
    config.generation = s_cfg.generation + 1U;
    if (config.generation == 0U) {
        config.generation = 1U;
    }

    esp_err_t err = save(&config);
    if (err == ESP_OK) {
        s_cfg = config;
    }

    xSemaphoreGive(s_lock);
    return err;
}

int hardware_profile_pps_gpio(void)
{
    return s_ready ? s_cfg.pps_gpio : APP_PPS_GPIO;
}

int hardware_profile_gnss_uart_num(void)
{
    return s_ready ? s_cfg.gnss_uart_num : APP_GNSS_UART_NUM;
}

int hardware_profile_gnss_rx_gpio(void)
{
    return s_ready ? s_cfg.gnss_rx_gpio : APP_GNSS_UART_RX_GPIO;
}

int hardware_profile_gnss_tx_gpio(void)
{
    return s_ready ? s_cfg.gnss_tx_gpio : APP_GNSS_UART_TX_GPIO;
}

#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#ifdef __cplusplus
extern "C" {
#endif
#define APP_HW_PROFILE_SCHEMA_VERSION 1U
#define APP_HW_BOARD_FAMILY_MAX 31U
#define APP_HW_BOARD_REV_MAX 15U

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    char board_family[APP_HW_BOARD_FAMILY_MAX + 1U];
    char board_revision[APP_HW_BOARD_REV_MAX + 1U];
    int pps_gpio;
    int gnss_uart_num;
    int gnss_rx_gpio;
    int gnss_tx_gpio;
    uint32_t requested_cpu_mhz;
} hardware_profile_config_t;

typedef struct {
    uint32_t wafer_revision;
    uint32_t efuse_block_revision;
    uint32_t package_version;
    uint32_t configured_cpu_mhz;
    hardware_profile_config_t config;
} hardware_profile_status_t;

esp_err_t hardware_profile_init(void);
esp_err_t hardware_profile_get_status(hardware_profile_status_t *out);
esp_err_t hardware_profile_get_config(hardware_profile_config_t *out);
esp_err_t hardware_profile_set_config(const hardware_profile_config_t *candidate);
esp_err_t hardware_profile_validate(const hardware_profile_config_t *candidate);
int hardware_profile_pps_gpio(void);
int hardware_profile_gnss_uart_num(void);
int hardware_profile_gnss_rx_gpio(void);
int hardware_profile_gnss_tx_gpio(void);
#ifdef __cplusplus
}
#endif

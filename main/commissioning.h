#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#define COMMISSIONING_FQDN_MAX 253U
#define COMMISSIONING_NTP_SERVER_MAX 253U
#define COMMISSIONING_NTP_SERVER_COUNT 2U

typedef struct {
    char certificate_fqdn[COMMISSIONING_FQDN_MAX + 1U];
    char ntp_servers[COMMISSIONING_NTP_SERVER_COUNT][COMMISSIONING_NTP_SERVER_MAX + 1U];
} commissioning_config_t;

typedef struct {
    bool management_time_valid;
    char source[24];
    char server[COMMISSIONING_NTP_SERVER_MAX + 1U];
    int64_t unix_time;
    esp_err_t last_error;
} commissioning_time_status_t;

esp_err_t commissioning_init(void);
esp_err_t commissioning_get_config(commissioning_config_t *out);
esp_err_t commissioning_set_config(const commissioning_config_t *cfg);
bool commissioning_fqdn_valid(const char *fqdn);
esp_err_t commissioning_sync_management_time(void);
esp_err_t commissioning_start_time_manager(void);
void commissioning_get_time_status(commissioning_time_status_t *out);

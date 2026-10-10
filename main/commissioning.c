#include "commissioning.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "esp_log.h"
#include "clock_discipline.h"
#include "device_config.h"
#include "ntp_types.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

#define NS "commission"
#define NTP_UNIX_DELTA 2208988800UL
#define NTP_TIMEOUT_MS 2500
static const char *TAG = "COMMISSION";
static SemaphoreHandle_t s_lock;
static commissioning_config_t s_cfg;
static commissioning_time_status_t s_status;
static TaskHandle_t s_time_manager_task;

static bool server_valid(const char *s) {
    if (!s) {
        return false;
    }
    size_t n=strlen(s); if (n == 0 || n > COMMISSIONING_NTP_SERVER_MAX) {
        return false;
    }
    for(size_t i=0;i<n;i++){ unsigned char c=(unsigned char)s[i]; if (c <= 0x20U || c == 0x7fU) {
            return false;
        } }
    return true;
}
bool commissioning_fqdn_valid(const char *s) {
    if (!s) {
        return false;
    }
    size_t n = strlen(s);
    if (n < 3 || n > COMMISSIONING_FQDN_MAX || strchr(s, '.') == NULL) {
        return false;
    }
    size_t label=0; for(size_t i=0;i<n;i++){ char c=s[i]; if(c=='.'){ if (label == 0 || label > 63 || s[i - 1U] == '-') { return false; }
            label = 0;
            continue; }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) { return false; }
        if (label == 0 && c == '-') { return false; }
        label++; }
    return label>0 && label<=63 && s[n-1]!='-';
}
static void defaults(void)
{
    memset(&s_cfg, 0, sizeof(s_cfg));
    snprintf(s_cfg.ntp_servers[0], sizeof(s_cfg.ntp_servers[0]), "time.cloudflare.com");
    snprintf(s_cfg.ntp_servers[1], sizeof(s_cfg.ntp_servers[1]), "time.google.com");
}

static esp_err_t save_locked(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_str(h, "fqdn", s_cfg.certificate_fqdn);
    for (unsigned i = 0; err == ESP_OK && i < COMMISSIONING_NTP_SERVER_COUNT; ++i) {
        char key[8];
        snprintf(key, sizeof(key), "ntp%u", i);
        err = nvs_set_str(h, key, s_cfg.ntp_servers[i]);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

esp_err_t commissioning_init(void)
{
    if (s_lock != NULL) return ESP_OK;
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;
    defaults();
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        size_t size = sizeof(s_cfg.certificate_fqdn);
        (void)nvs_get_str(h, "fqdn", s_cfg.certificate_fqdn, &size);
        for (unsigned i = 0; i < COMMISSIONING_NTP_SERVER_COUNT; ++i) {
            char key[8];
            snprintf(key, sizeof(key), "ntp%u", i);
            size = sizeof(s_cfg.ntp_servers[i]);
            (void)nvs_get_str(h, key, s_cfg.ntp_servers[i], &size);
        }
        nvs_close(h);
    }
    memset(&s_status, 0, sizeof(s_status));
    s_status.last_error = ESP_ERR_NOT_FINISHED;
    return ESP_OK;
}

esp_err_t commissioning_get_config(commissioning_config_t *out)
{
    if (out == NULL || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_cfg;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

esp_err_t commissioning_set_config(const commissioning_config_t *cfg)
{
    if (cfg == NULL || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (cfg->certificate_fqdn[0] != '\0' && !commissioning_fqdn_valid(cfg->certificate_fqdn)) return ESP_ERR_INVALID_ARG;
    for (unsigned i = 0; i < COMMISSIONING_NTP_SERVER_COUNT; ++i) {
        if (!server_valid(cfg->ntp_servers[i])) return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    commissioning_config_t old = s_cfg;
    s_cfg = *cfg;
    esp_err_t err = save_locked();
    if (err != ESP_OK) {
        s_cfg = old;
    }
    xSemaphoreGive(s_lock);
    return err;
}

static esp_err_t query_ntp(const char *server, int64_t *unix_out)
{
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(server, "123", &hints, &res) != 0 || res == NULL) return ESP_ERR_NOT_FOUND;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return ESP_FAIL;
    }
    struct timeval timeout = {.tv_sec = NTP_TIMEOUT_MS / 1000, .tv_usec = (NTP_TIMEOUT_MS % 1000) * 1000};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close(fd);
        return ESP_FAIL;
    }
    freeaddrinfo(res);
    uint8_t packet[48] = {0};
    packet[0] = 0x23; /* LI=0, VN=4, client mode. */
    ssize_t sent = send(fd, packet, sizeof(packet), 0);
    if (sent != (ssize_t)sizeof(packet)) {
        close(fd);
        return ESP_FAIL;
    }
    ssize_t received = recv(fd, packet, sizeof(packet), 0);
    close(fd);
    if (received < (ssize_t)sizeof(packet)) return ESP_ERR_TIMEOUT;
    const uint8_t li = (packet[0] >> 6) & 0x03U;
    const uint8_t mode = packet[0] & 0x07U;
    const uint8_t stratum = packet[1];
    if (li == 3U || mode != 4U || stratum == 0U || stratum > 15U)
        return ESP_ERR_INVALID_RESPONSE;
    uint32_t seconds = ((uint32_t)packet[40] << 24) | ((uint32_t)packet[41] << 16) |
                       ((uint32_t)packet[42] << 8) | packet[43];
    if (seconds <= NTP_UNIX_DELTA) return ESP_ERR_INVALID_RESPONSE;
    *unix_out = (int64_t)(seconds - NTP_UNIX_DELTA);
    return ESP_OK;
}

static bool gnss_master_time(clock_ntp_timestamp_t *out)
{
    clock_discipline_status_t status;
    if (out == NULL || !clock_discipline_get_status(&status) ||
        !status.solution_valid || status.state != APP_CLOCK_SYNCHRONIZED)
        return false;
    return clock_discipline_get_ntp_timestamp(out) && out->seconds >= APP_NTP_EPOCH_DELTA;
}

esp_err_t commissioning_sync_management_time(void)
{
    /* GNSS/PPS disciplined UTC is always preferred when available.  Mirroring
     * it into the POSIX wall clock is management-plane plumbing only; it does
     * not alter the Phase-8 discipline solution. */
    clock_ntp_timestamp_t master_now;
    if (gnss_master_time(&master_now)) {
        const int64_t unix_time = (int64_t)master_now.seconds - (int64_t)APP_NTP_EPOCH_DELTA;
        struct timeval tv = {.tv_sec = (time_t)unix_time, .tv_usec = 0};
        if (settimeofday(&tv, NULL) == 0) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_status.management_time_valid = true;
            snprintf(s_status.source, sizeof(s_status.source), "gnss_gps");
            s_status.server[0] = '\0';
            s_status.unix_time = unix_time;
            s_status.last_error = ESP_OK;
            xSemaphoreGive(s_lock);
            ESP_LOGI(TAG, "Management wall time sourced from synchronized GNSS/GPS master");
            return ESP_OK;
        }
    }

    /* If local GNSS/PPS is unavailable, the dedicated redundant appliance is
     * the first management/civil-time fallback.  This is intentionally a
     * separate NTP query used only to set the POSIX wall clock: it never feeds
     * clock_discipline and therefore cannot make this server Stratum 2 in V3. */
    device_config_snapshot_t device_cfg;
    esp_err_t last = ESP_FAIL;
    if (device_config_get_snapshot(&device_cfg) == ESP_OK) {
        const device_config_ntp_peer_t *redundant = &device_cfg.ntp_peers[APP_REDUNDANT_PEER_INDEX];
        if (redundant->enabled && redundant->server[0] != '\0') {
            int64_t unix_time = 0;
            last = query_ntp(redundant->server, &unix_time);
            if (last == ESP_OK) {
                struct timeval tv = {.tv_sec = (time_t)unix_time, .tv_usec = 0};
                if (settimeofday(&tv, NULL) == 0) {
                    xSemaphoreTake(s_lock, portMAX_DELAY);
                    s_status.management_time_valid = true;
                    snprintf(s_status.source, sizeof(s_status.source), "redundant_server");
                    snprintf(s_status.server, sizeof(s_status.server), "%s", redundant->server);
                    s_status.unix_time = unix_time;
                    s_status.last_error = ESP_OK;
                    xSemaphoreGive(s_lock);
                    ESP_LOGI(TAG, "Management wall time fallback from redundant server (%s); timing authority unchanged", redundant->server);
                    return ESP_OK;
                }
                last = ESP_FAIL;
            }
        }
    }

    commissioning_config_t cfg;
    if (commissioning_get_config(&cfg) != ESP_OK) return ESP_ERR_INVALID_STATE;
    for (unsigned i = 0; i < COMMISSIONING_NTP_SERVER_COUNT; ++i) {
        int64_t unix_time = 0;
        last = query_ntp(cfg.ntp_servers[i], &unix_time);
        if (last != ESP_OK) continue;
        struct timeval tv = {.tv_sec = (time_t)unix_time, .tv_usec = 0};
        if (settimeofday(&tv, NULL) != 0) {
            last = ESP_FAIL;
            continue;
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.management_time_valid = true;
        snprintf(s_status.source, sizeof(s_status.source), "external_ntp_%u", i + 1U);
        snprintf(s_status.server, sizeof(s_status.server), "%s", cfg.ntp_servers[i]);
        s_status.unix_time = unix_time;
        s_status.last_error = ESP_OK;
        xSemaphoreGive(s_lock);
        ESP_LOGI(TAG, "Management wall time fallback from External NTP %u (%s); timing authority unchanged", i + 1U, cfg.ntp_servers[i]);
        return ESP_OK;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.management_time_valid = false;
    s_status.source[0] = '\0';
    s_status.server[0] = '\0';
    s_status.last_error = last;
    xSemaphoreGive(s_lock);
    ESP_LOGW(TAG, "Redundant/external management-time fallback failed: %s", esp_err_to_name(last));
    return last;
}

static void management_time_task(void *arg)
{
    (void)arg;
    for (;;) {
        (void)commissioning_sync_management_time();
        vTaskDelay(pdMS_TO_TICKS(60000U));
    }
}

esp_err_t commissioning_start_time_manager(void)
{
    if (s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (s_time_manager_task != NULL) return ESP_OK;
    if (xTaskCreate(management_time_task, "mgmt_time", 6144U, NULL, 3U,
                    &s_time_manager_task) != pdPASS) {
        s_time_manager_task = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

void commissioning_get_time_status(commissioning_time_status_t *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (s_lock == NULL) return;
    clock_ntp_timestamp_t master_now;
    if (gnss_master_time(&master_now)) {
        out->management_time_valid = true;
        snprintf(out->source, sizeof(out->source), "gnss_gps");
        out->server[0] = '\0';
        out->unix_time = (int64_t)master_now.seconds - (int64_t)APP_NTP_EPOCH_DELTA;
        out->last_error = ESP_OK;
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_status;
    if (out->management_time_valid) {
        struct timeval tv;
        if (gettimeofday(&tv, NULL) == 0) out->unix_time = tv.tv_sec;
    }
    xSemaphoreGive(s_lock);
}

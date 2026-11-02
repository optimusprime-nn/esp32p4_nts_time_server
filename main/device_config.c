#include "device_config.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "app_state.h"
#include "esp_err.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "DEVICE_CFG";

#define CFG_NS              "device_cfg"
#define KEY_HOSTNAME        "hostname"
#define KEY_SCHEMA          "schema"
#define KEY_GENERATION      "generation"
#define KEY_CF_ZONE_NAME    "cf_zone"
#define KEY_CF_ZONE_ID      "cf_zone_id"
#define KEY_CF_API_TOKEN    "cf_token"
#define KEY_PEER_ENABLED    "peer_en"
#define KEY_PEER_POLL       "peer_poll"
#define KEY_PEER_TIMEOUT    "peer_to"
#define KEY_PEER_WARN       "peer_warn"
#define KEY_PEER_CRIT       "peer_crit"
#define KEY_PEER0           "peer0"
#define KEY_PEER1           "peer1"
#define KEY_PEER2           "peer2"
#define KEY_PEER3           "redundant"
/* Optional static IPv4; absent keys mean DHCP. Older firmware ignores them. */
#define KEY_IP_STATIC       "ip_static"
#define KEY_IP_ADDR         "ip_addr"
#define KEY_IP_MASK         "ip_mask"
#define KEY_IP_GW           "ip_gw"
#define KEY_IP_DNS          "ip_dns"
#define KEY_IP_DNS2         "ip_dns2"

typedef struct {
    device_config_snapshot_t public_config;
    char cloudflare_api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
} stored_config_t;

static SemaphoreHandle_t s_lock;
static bool s_initialized;
static stored_config_t s_config;

static bool lock_config(void)
{
    return s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_config(void)
{
    (void)xSemaphoreGive(s_lock);
}

bool device_config_hostname_is_valid(const char *hostname)
{
    if (hostname == NULL) return false;
    const size_t length = strlen(hostname);
    if (length == 0U || length > APP_DEVICE_HOSTNAME_MAX_LENGTH) return false;
    if (!isalnum((unsigned char)hostname[0]) ||
        !isalnum((unsigned char)hostname[length - 1U])) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)hostname[i];
        if (!isalnum(c) && c != '-') return false;
    }
    return true;
}

bool device_config_cloudflare_zone_is_valid(const char *zone_name)
{
    if (zone_name == NULL) return false;
    const size_t length = strlen(zone_name);
    if (length == 0U || length > APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH) return false;
    if (zone_name[0] == '.' || zone_name[length - 1U] == '.') return false;

    size_t label_len = 0U;
    bool label_first = true;
    char previous = '\0';
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)zone_name[i];
        if (c == '.') {
            if (label_len == 0U || previous == '-') return false;
            label_len = 0U;
            label_first = true;
            previous = '.';
            continue;
        }
        if (!isalnum(c) && c != '-') return false;
        if (label_first && c == '-') return false;
        label_first = false;
        if (++label_len > 63U) return false;
        previous = (char)c;
    }
    return label_len > 0U && previous != '-';
}

bool device_config_ntp_peer_server_is_valid(const char *server)
{
    if (server == NULL) return false;
    const size_t length = strlen(server);
    if (length == 0U || length > APP_NTP_PEER_SERVER_MAX_LENGTH) return false;
    if (server[0] == '.' || server[length - 1U] == '.') return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)server[i];
        if (!isalnum(c) && c != '-' && c != '.') return false;
    }
    return true;
}

static bool api_token_is_valid(const char *token)
{
    if (token == NULL) return false;
    const size_t length = strlen(token);
    if (length < 20U || length > APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)token[i];
        if (c <= 0x20U || c >= 0x7fU) return false;
    }
    return true;
}

static bool zone_id_is_valid(const char *zone_id)
{
    if (zone_id == NULL || strlen(zone_id) != APP_CLOUDFLARE_ZONE_ID_LENGTH) return false;
    for (size_t i = 0; i < APP_CLOUDFLARE_ZONE_ID_LENGTH; ++i) {
        if (!isxdigit((unsigned char)zone_id[i])) return false;
    }
    return true;
}

static void lowercase(char *value)
{
    for (size_t i = 0; value[i] != '\0'; ++i) {
        value[i] = (char)tolower((unsigned char)value[i]);
    }
}

bool device_config_static_ipv4_is_valid(uint32_t address,
                                        uint32_t netmask,
                                        uint32_t gateway,
                                        uint32_t dns)
{
    (void)dns;
    const uint32_t addr = ntohl(address);
    const uint32_t mask = ntohl(netmask);
    const uint32_t gw = ntohl(gateway);

    /* Contiguous mask between /8 and /30. */
    if ((~mask & (~mask + 1U)) != 0U ||
        mask < 0xFF000000U || mask > 0xFFFFFFFCU) return false;
    const uint32_t host = addr & ~mask;
    if (host == 0U || host == ~mask) return false;
    const uint8_t first_octet = (uint8_t)(addr >> 24);
    if (first_octet == 0U || first_octet == 127U || first_octet >= 224U) return false;
    if (gw != 0U && ((gw & mask) != (addr & mask) || gw == addr)) return false;
    return true;
}

static void make_default_config(stored_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    config->public_config.generation = 1U;
    (void)snprintf(config->public_config.hostname,
                   sizeof(config->public_config.hostname), "%s",
                   APP_DEVICE_HOSTNAME_DEFAULT);
    lowercase(config->public_config.hostname);
    config->public_config.ntp_peer_monitor_enabled = false;
    config->public_config.ntp_peer_poll_interval_seconds = APP_NTP_PEER_POLL_DEFAULT_SECONDS;
    config->public_config.ntp_peer_response_timeout_ms = APP_NTP_PEER_TIMEOUT_DEFAULT_MS;
    config->public_config.redundant_peer_warning_ns = APP_REDUNDANT_PEER_WARN_DEFAULT_NS;
    config->public_config.redundant_peer_critical_ns = APP_REDUNDANT_PEER_CRITICAL_DEFAULT_NS;
}

static esp_err_t persist_config(const stored_config_t *config)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(CFG_NS, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    err = nvs_set_u32(handle, KEY_SCHEMA, config->public_config.schema_version);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_GENERATION, config->public_config.generation);
    if (err == ESP_OK) err = nvs_set_str(handle, KEY_HOSTNAME, config->public_config.hostname);

    if (err == ESP_OK && config->public_config.cloudflare_configured) {
        err = nvs_set_str(handle, KEY_CF_ZONE_NAME, config->public_config.cloudflare_zone_name);
        if (err == ESP_OK) err = nvs_set_str(handle, KEY_CF_ZONE_ID, config->public_config.cloudflare_zone_id);
        if (err == ESP_OK) err = nvs_set_str(handle, KEY_CF_API_TOKEN, config->cloudflare_api_token);
    } else if (err == ESP_OK) {
        esp_err_t erase_err = nvs_erase_key(handle, KEY_CF_ZONE_NAME);
        if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        erase_err = nvs_erase_key(handle, KEY_CF_ZONE_ID);
        if (err == ESP_OK && erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        erase_err = nvs_erase_key(handle, KEY_CF_API_TOKEN);
        if (err == ESP_OK && erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
    }

    if (err == ESP_OK) err = nvs_set_u8(handle, KEY_PEER_ENABLED,
                                           config->public_config.ntp_peer_monitor_enabled ? 1U : 0U);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_PEER_POLL,
                                         config->public_config.ntp_peer_poll_interval_seconds);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_PEER_TIMEOUT,
                                         config->public_config.ntp_peer_response_timeout_ms);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_PEER_WARN, config->public_config.redundant_peer_warning_ns);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_PEER_CRIT, config->public_config.redundant_peer_critical_ns);
    static const char *const peer_keys[APP_NTP_PEER_MAX_COUNT] = {
        KEY_PEER0, KEY_PEER1, KEY_PEER2, KEY_PEER3
    };
    for (size_t i = 0; err == ESP_OK && i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (config->public_config.ntp_peers[i].enabled &&
            config->public_config.ntp_peers[i].server[0] != '\0') {
            err = nvs_set_str(handle, peer_keys[i], config->public_config.ntp_peers[i].server);
        } else {
            esp_err_t erase_err = nvs_erase_key(handle, peer_keys[i]);
            if (erase_err != ESP_OK && erase_err != ESP_ERR_NVS_NOT_FOUND) err = erase_err;
        }
    }

    if (err == ESP_OK) err = nvs_set_u8(handle, KEY_IP_STATIC,
                                         config->public_config.static_ipv4_enabled ? 1U : 0U);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_IP_ADDR, config->public_config.static_ipv4_address);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_IP_MASK, config->public_config.static_ipv4_netmask);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_IP_GW, config->public_config.static_ipv4_gateway);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_IP_DNS, config->public_config.static_ipv4_dns);
    if (err == ESP_OK) err = nvs_set_u32(handle, KEY_IP_DNS2, config->public_config.static_ipv4_dns2);

    if (err == ESP_OK) err = nvs_commit(handle);
    nvs_close(handle);
    return err;
}

static esp_err_t read_string(nvs_handle_t handle, const char *key,
                             char *buffer, size_t buffer_size)
{
    size_t required = buffer_size;
    return nvs_get_str(handle, key, buffer, &required);
}

static esp_err_t load_config(stored_config_t *config, bool *out_needs_default)
{
    if (config == NULL || out_needs_default == NULL) return ESP_ERR_INVALID_ARG;
    *out_needs_default = false;
    memset(config, 0, sizeof(*config));

    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(CFG_NS, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        *out_needs_default = true;
        return ESP_OK;
    }
    if (err != ESP_OK) return err;

    uint32_t schema = 0U;
    err = nvs_get_u32(handle, KEY_SCHEMA, &schema);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        size_t hostname_size = sizeof(config->public_config.hostname);
        err = nvs_get_str(handle, KEY_HOSTNAME, config->public_config.hostname, &hostname_size);
        nvs_close(handle);
        if (err != ESP_OK || !device_config_hostname_is_valid(config->public_config.hostname)) {
            *out_needs_default = true;
            return ESP_OK;
        }
        lowercase(config->public_config.hostname);
        config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
        config->public_config.generation = 1U;
        config->public_config.ntp_peer_monitor_enabled = false;
        config->public_config.ntp_peer_poll_interval_seconds = APP_NTP_PEER_POLL_DEFAULT_SECONDS;
        config->public_config.ntp_peer_response_timeout_ms = APP_NTP_PEER_TIMEOUT_DEFAULT_MS;
        config->public_config.redundant_peer_warning_ns = APP_REDUNDANT_PEER_WARN_DEFAULT_NS;
        config->public_config.redundant_peer_critical_ns = APP_REDUNDANT_PEER_CRITICAL_DEFAULT_NS;
        ESP_LOGI(TAG, "Migrating legacy device configuration to schema 4");
        return persist_config(config);
    }
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (schema != 1U && schema != 2U && schema != 3U && schema != APP_DEVICE_CONFIG_SCHEMA_VERSION) {
        nvs_close(handle);
        ESP_LOGE(TAG, "Unsupported device-config schema %" PRIu32, schema);
        return ESP_ERR_INVALID_VERSION;
    }

    err = nvs_get_u32(handle, KEY_GENERATION, &config->public_config.generation);
    if (err == ESP_OK) {
        err = read_string(handle, KEY_HOSTNAME, config->public_config.hostname,
                          sizeof(config->public_config.hostname));
    }
    if (err != ESP_OK || config->public_config.generation == 0U ||
        !device_config_hostname_is_valid(config->public_config.hostname)) {
        nvs_close(handle);
        *out_needs_default = true;
        return ESP_OK;
    }
    lowercase(config->public_config.hostname);
    config->public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    config->public_config.ntp_peer_monitor_enabled = false;
    config->public_config.ntp_peer_poll_interval_seconds = APP_NTP_PEER_POLL_DEFAULT_SECONDS;
    config->public_config.ntp_peer_response_timeout_ms = APP_NTP_PEER_TIMEOUT_DEFAULT_MS;
    config->public_config.redundant_peer_warning_ns = APP_REDUNDANT_PEER_WARN_DEFAULT_NS;
    config->public_config.redundant_peer_critical_ns = APP_REDUNDANT_PEER_CRITICAL_DEFAULT_NS;

    if (schema == 1U) {
        nvs_close(handle);
        ESP_LOGI(TAG, "Migrating device configuration schema 1 -> 4");
        return persist_config(config);
    }

    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U] = {0};
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U] = {0};
    char token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U] = {0};
    esp_err_t zone_err = read_string(handle, KEY_CF_ZONE_NAME, zone_name, sizeof(zone_name));
    esp_err_t id_err = read_string(handle, KEY_CF_ZONE_ID, zone_id, sizeof(zone_id));
    esp_err_t token_err = read_string(handle, KEY_CF_API_TOKEN, token, sizeof(token));
    nvs_close(handle);

    if (zone_err == ESP_OK && id_err == ESP_OK && token_err == ESP_OK &&
        device_config_cloudflare_zone_is_valid(zone_name) &&
        zone_id_is_valid(zone_id) && api_token_is_valid(token)) {
        lowercase(zone_name);
        config->public_config.cloudflare_configured = true;
        (void)snprintf(config->public_config.cloudflare_zone_name,
                       sizeof(config->public_config.cloudflare_zone_name), "%s", zone_name);
        (void)snprintf(config->public_config.cloudflare_zone_id,
                       sizeof(config->public_config.cloudflare_zone_id), "%s", zone_id);
        (void)snprintf(config->cloudflare_api_token,
                       sizeof(config->cloudflare_api_token), "%s", token);
    }

    if (schema == 2U) {
        ESP_LOGI(TAG, "Migrating device configuration schema 2 -> 4");
        return persist_config(config);
    }

    uint8_t peer_enabled = 0U;
    uint32_t peer_poll = APP_NTP_PEER_POLL_DEFAULT_SECONDS;
    uint32_t peer_timeout = APP_NTP_PEER_TIMEOUT_DEFAULT_MS;
    uint32_t peer_warn = APP_REDUNDANT_PEER_WARN_DEFAULT_NS;
    uint32_t peer_crit = APP_REDUNDANT_PEER_CRITICAL_DEFAULT_NS;
    if (nvs_open(CFG_NS, NVS_READONLY, &handle) == ESP_OK) {
        (void)nvs_get_u8(handle, KEY_PEER_ENABLED, &peer_enabled);
        (void)nvs_get_u32(handle, KEY_PEER_POLL, &peer_poll);
        (void)nvs_get_u32(handle, KEY_PEER_TIMEOUT, &peer_timeout);
        (void)nvs_get_u32(handle, KEY_PEER_WARN, &peer_warn);
        (void)nvs_get_u32(handle, KEY_PEER_CRIT, &peer_crit);
        static const char *const peer_keys[APP_NTP_PEER_MAX_COUNT] = {
            KEY_PEER0, KEY_PEER1, KEY_PEER2, KEY_PEER3
        };
        for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
            size_t required = sizeof(config->public_config.ntp_peers[i].server);
            if (nvs_get_str(handle, peer_keys[i], config->public_config.ntp_peers[i].server, &required) == ESP_OK &&
                device_config_ntp_peer_server_is_valid(config->public_config.ntp_peers[i].server)) {
                config->public_config.ntp_peers[i].enabled = true;
                lowercase(config->public_config.ntp_peers[i].server);
            } else {
                config->public_config.ntp_peers[i].server[0] = '\0';
                config->public_config.ntp_peers[i].enabled = false;
            }
        }
        uint8_t ip_static = 0U;
        uint32_t ip_addr = 0U, ip_mask = 0U, ip_gw = 0U, ip_dns = 0U, ip_dns2 = 0U;
        (void)nvs_get_u8(handle, KEY_IP_STATIC, &ip_static);
        (void)nvs_get_u32(handle, KEY_IP_ADDR, &ip_addr);
        (void)nvs_get_u32(handle, KEY_IP_MASK, &ip_mask);
        (void)nvs_get_u32(handle, KEY_IP_GW, &ip_gw);
        (void)nvs_get_u32(handle, KEY_IP_DNS, &ip_dns);
        (void)nvs_get_u32(handle, KEY_IP_DNS2, &ip_dns2);
        /* A stored but invalid static configuration falls back to DHCP so a
         * bad value can never leave the device unreachable. */
        if (ip_static != 0U &&
            device_config_static_ipv4_is_valid(ip_addr, ip_mask, ip_gw, ip_dns)) {
            config->public_config.static_ipv4_enabled = true;
        } else if (ip_static != 0U) {
            ESP_LOGW(TAG, "Stored static IPv4 configuration is invalid; using DHCP");
        }
        config->public_config.static_ipv4_address = ip_addr;
        config->public_config.static_ipv4_netmask = ip_mask;
        config->public_config.static_ipv4_gateway = ip_gw;
        config->public_config.static_ipv4_dns = ip_dns;
        config->public_config.static_ipv4_dns2 = ip_dns2;
        nvs_close(handle);
    }
    config->public_config.ntp_peer_monitor_enabled = peer_enabled != 0U;
    if (peer_poll >= APP_NTP_PEER_POLL_MIN_SECONDS && peer_poll <= APP_NTP_PEER_POLL_MAX_SECONDS)
        config->public_config.ntp_peer_poll_interval_seconds = peer_poll;
    if (peer_timeout >= APP_NTP_PEER_TIMEOUT_MIN_MS && peer_timeout <= APP_NTP_PEER_TIMEOUT_MAX_MS)
        config->public_config.ntp_peer_response_timeout_ms = peer_timeout;
    if (peer_warn > 0U && peer_warn <= APP_REDUNDANT_PEER_THRESHOLD_MAX_NS) config->public_config.redundant_peer_warning_ns = peer_warn;
    if (peer_crit >= config->public_config.redundant_peer_warning_ns && peer_crit <= APP_REDUNDANT_PEER_THRESHOLD_MAX_NS) config->public_config.redundant_peer_critical_ns = peer_crit;
    if (schema == 3U) { ESP_LOGI(TAG, "Migrating device configuration schema 3 -> 4"); return persist_config(config); }
    return ESP_OK;
}

esp_err_t device_config_init(void)
{
    if (s_initialized) return ESP_OK;
    if (!device_config_hostname_is_valid(APP_DEVICE_HOSTNAME_DEFAULT)) return ESP_ERR_INVALID_ARG;
    s_lock = xSemaphoreCreateMutex();
    if (s_lock == NULL) return ESP_ERR_NO_MEM;

    stored_config_t loaded;
    bool needs_default = false;
    esp_err_t err = load_config(&loaded, &needs_default);
    if (err != ESP_OK) goto fail;
    if (needs_default) {
        make_default_config(&loaded);
        err = persist_config(&loaded);
        if (err != ESP_OK) goto fail;
    }
    if (!lock_config()) { err = ESP_FAIL; goto fail; }
    s_config = loaded;
    s_initialized = true;
    unlock_config();
    app_state_set_device_hostname(loaded.public_config.hostname);
    ESP_LOGI(TAG, "Device configuration ready: schema=%" PRIu32 " generation=%" PRIu32
             " hostname=%s cloudflare=%s",
             loaded.public_config.schema_version, loaded.public_config.generation,
             loaded.public_config.hostname,
             loaded.public_config.cloudflare_configured ? "configured" : "not-configured");
    return ESP_OK;
fail:
    if (s_lock != NULL) vSemaphoreDelete(s_lock);
    s_lock = NULL;
    return err;
}

esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot)
{
    if (out_snapshot == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    *out_snapshot = s_config.public_config;
    unlock_config();
    return ESP_OK;
}

esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size)
{
    if (buffer == NULL || buffer_size == 0U) return ESP_ERR_INVALID_ARG;
    device_config_snapshot_t snapshot;
    esp_err_t err = device_config_get_snapshot(&snapshot);
    if (err != ESP_OK) return err;
    const size_t required = strlen(snapshot.hostname) + 1U;
    if (buffer_size < required) return ESP_ERR_INVALID_SIZE;
    memcpy(buffer, snapshot.hostname, required);
    return ESP_OK;
}

esp_err_t device_config_get_cloudflare_credentials(device_config_cloudflare_credentials_t *out_credentials)
{
    if (out_credentials == NULL) return ESP_ERR_INVALID_ARG;
    memset(out_credentials, 0, sizeof(*out_credentials));
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    if (!s_config.public_config.cloudflare_configured) {
        unlock_config();
        return ESP_ERR_NOT_FOUND;
    }
    (void)snprintf(out_credentials->api_token, sizeof(out_credentials->api_token), "%s",
                   s_config.cloudflare_api_token);
    (void)snprintf(out_credentials->zone_name, sizeof(out_credentials->zone_name), "%s",
                   s_config.public_config.cloudflare_zone_name);
    (void)snprintf(out_credentials->zone_id, sizeof(out_credentials->zone_id), "%s",
                   s_config.public_config.cloudflare_zone_id);
    unlock_config();
    return ESP_OK;
}

static uint32_t next_generation(uint32_t generation)
{
    generation++;
    return generation == 0U ? 1U : generation;
}

esp_err_t device_config_set_hostname(const char *hostname)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!device_config_hostname_is_valid(hostname)) return ESP_ERR_INVALID_ARG;
    char normalized[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    (void)snprintf(normalized, sizeof(normalized), "%s", hostname);
    lowercase(normalized);
    if (!lock_config()) return ESP_FAIL;
    if (strcmp(normalized, s_config.public_config.hostname) == 0) {
        unlock_config();
        return ESP_OK;
    }
    stored_config_t candidate = s_config;
    (void)snprintf(candidate.public_config.hostname,
                   sizeof(candidate.public_config.hostname), "%s", normalized);
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err != ESP_OK) return err;
    app_state_set_device_hostname(candidate.public_config.hostname);
    ESP_LOGI(TAG, "Device configuration committed: generation=%" PRIu32 " hostname=%s",
             candidate.public_config.generation, candidate.public_config.hostname);
    return ESP_OK;
}

esp_err_t device_config_set_cloudflare(const char *api_token,
                                       const char *zone_name,
                                       const char *zone_id)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!api_token_is_valid(api_token) ||
        !device_config_cloudflare_zone_is_valid(zone_name) ||
        !zone_id_is_valid(zone_id)) return ESP_ERR_INVALID_ARG;

    char normalized_zone[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    (void)snprintf(normalized_zone, sizeof(normalized_zone), "%s", zone_name);
    lowercase(normalized_zone);
    if (!lock_config()) return ESP_FAIL;
    stored_config_t candidate = s_config;
    candidate.public_config.cloudflare_configured = true;
    (void)snprintf(candidate.public_config.cloudflare_zone_name,
                   sizeof(candidate.public_config.cloudflare_zone_name), "%s", normalized_zone);
    (void)snprintf(candidate.public_config.cloudflare_zone_id,
                   sizeof(candidate.public_config.cloudflare_zone_id), "%s", zone_id);
    (void)snprintf(candidate.cloudflare_api_token,
                   sizeof(candidate.cloudflare_api_token), "%s", api_token);
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Cloudflare configuration committed: generation=%" PRIu32 " zone=%s",
                 candidate.public_config.generation,
                 candidate.public_config.cloudflare_zone_name);
    }
    return err;
}

esp_err_t device_config_clear_cloudflare(void)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    if (!s_config.public_config.cloudflare_configured) {
        unlock_config();
        return ESP_OK;
    }
    stored_config_t candidate = s_config;
    candidate.public_config.cloudflare_configured = false;
    candidate.public_config.cloudflare_zone_name[0] = '\0';
    candidate.public_config.cloudflare_zone_id[0] = '\0';
    memset(candidate.cloudflare_api_token, 0, sizeof(candidate.cloudflare_api_token));
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK) ESP_LOGI(TAG, "Cloudflare configuration cleared");
    return err;
}


esp_err_t device_config_set_ntp_peer_monitor(bool enabled,
                                             uint32_t poll_interval_seconds,
                                             uint32_t response_timeout_ms,
                                             uint32_t warning_ns,
                                             uint32_t critical_ns,
                                             const device_config_ntp_peer_t peers[APP_NTP_PEER_MAX_COUNT])
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (peers == NULL) return ESP_ERR_INVALID_ARG;
    if (poll_interval_seconds < APP_NTP_PEER_POLL_MIN_SECONDS ||
        poll_interval_seconds > APP_NTP_PEER_POLL_MAX_SECONDS ||
        response_timeout_ms < APP_NTP_PEER_TIMEOUT_MIN_MS ||
        response_timeout_ms > APP_NTP_PEER_TIMEOUT_MAX_MS || warning_ns == 0U ||
        warning_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS || critical_ns < warning_ns ||
        critical_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (peers[i].enabled && !device_config_ntp_peer_server_is_valid(peers[i].server))
            return ESP_ERR_INVALID_ARG;
    }
    if (!lock_config()) return ESP_FAIL;
    stored_config_t candidate = s_config;
    candidate.public_config.ntp_peer_monitor_enabled = enabled;
    candidate.public_config.ntp_peer_poll_interval_seconds = poll_interval_seconds;
    candidate.public_config.ntp_peer_response_timeout_ms = response_timeout_ms;
    candidate.public_config.redundant_peer_warning_ns = warning_ns;
    candidate.public_config.redundant_peer_critical_ns = critical_ns;
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        candidate.public_config.ntp_peers[i].enabled = peers[i].enabled;
        if (peers[i].enabled) {
            (void)snprintf(candidate.public_config.ntp_peers[i].server,
                           sizeof(candidate.public_config.ntp_peers[i].server), "%s", peers[i].server);
            lowercase(candidate.public_config.ntp_peers[i].server);
        } else {
            candidate.public_config.ntp_peers[i].server[0] = '\0';
        }
    }
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK)
        ESP_LOGI(TAG, "NTP peer-monitor configuration committed: generation=%" PRIu32 " enabled=%s",
                 candidate.public_config.generation, enabled ? "yes" : "no");
    return err;
}

esp_err_t device_config_set_static_ipv4(bool enabled,
                                        uint32_t address,
                                        uint32_t netmask,
                                        uint32_t gateway,
                                        uint32_t dns,
                                        uint32_t dns2)
{
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (enabled && !device_config_static_ipv4_is_valid(address, netmask, gateway, dns))
        return ESP_ERR_INVALID_ARG;
    if (!lock_config()) return ESP_FAIL;
    stored_config_t candidate = s_config;
    candidate.public_config.static_ipv4_enabled = enabled;
    /* Keep the last addresses when disabling, so re-enabling is easy. */
    if (enabled) {
        candidate.public_config.static_ipv4_address = address;
        candidate.public_config.static_ipv4_netmask = netmask;
        candidate.public_config.static_ipv4_gateway = gateway;
        candidate.public_config.static_ipv4_dns = dns;
        candidate.public_config.static_ipv4_dns2 = dns2;
    }
    candidate.public_config.generation = next_generation(candidate.public_config.generation);
    esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Network configuration committed: generation=%" PRIu32 " static_ipv4=%s (applies at reboot)",
                 candidate.public_config.generation, enabled ? "yes" : "no");
    return err;
}

esp_err_t device_config_export_backup(device_config_backup_t *out_backup)
{
    if (out_backup == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!lock_config()) return ESP_FAIL;
    memset(out_backup, 0, sizeof(*out_backup));
    out_backup->backup_schema_version = APP_DEVICE_CONFIG_BACKUP_SCHEMA_VERSION;
    out_backup->config = s_config.public_config;
    if (s_config.public_config.cloudflare_configured) {
        (void)snprintf(out_backup->cloudflare_api_token,
                       sizeof(out_backup->cloudflare_api_token), "%s",
                       s_config.cloudflare_api_token);
    }
    unlock_config();
    return ESP_OK;
}

esp_err_t device_config_restore_backup(const device_config_backup_t *backup)
{
    if (backup == NULL || backup->backup_schema_version != APP_DEVICE_CONFIG_BACKUP_SCHEMA_VERSION) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_initialized || s_lock == NULL) return ESP_ERR_INVALID_STATE;
    if (!device_config_hostname_is_valid(backup->config.hostname)) return ESP_ERR_INVALID_ARG;
    if (backup->config.ntp_peer_poll_interval_seconds < APP_NTP_PEER_POLL_MIN_SECONDS ||
        backup->config.ntp_peer_poll_interval_seconds > APP_NTP_PEER_POLL_MAX_SECONDS ||
        backup->config.ntp_peer_response_timeout_ms < APP_NTP_PEER_TIMEOUT_MIN_MS ||
        backup->config.ntp_peer_response_timeout_ms > APP_NTP_PEER_TIMEOUT_MAX_MS ||
        backup->config.redundant_peer_warning_ns == 0U ||
        backup->config.redundant_peer_warning_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS ||
        backup->config.redundant_peer_critical_ns < backup->config.redundant_peer_warning_ns ||
        backup->config.redundant_peer_critical_ns > APP_REDUNDANT_PEER_THRESHOLD_MAX_NS) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (backup->config.ntp_peers[i].enabled &&
            !device_config_ntp_peer_server_is_valid(backup->config.ntp_peers[i].server)) return ESP_ERR_INVALID_ARG;
    }
    if (backup->config.static_ipv4_enabled &&
        !device_config_static_ipv4_is_valid(backup->config.static_ipv4_address,
                                            backup->config.static_ipv4_netmask,
                                            backup->config.static_ipv4_gateway,
                                            backup->config.static_ipv4_dns)) return ESP_ERR_INVALID_ARG;
    if (backup->config.cloudflare_configured &&
        (!device_config_cloudflare_zone_is_valid(backup->config.cloudflare_zone_name) ||
         !zone_id_is_valid(backup->config.cloudflare_zone_id) ||
         !api_token_is_valid(backup->cloudflare_api_token))) return ESP_ERR_INVALID_ARG;

    if (!lock_config()) return ESP_FAIL;
    stored_config_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.public_config = backup->config;
    candidate.public_config.schema_version = APP_DEVICE_CONFIG_SCHEMA_VERSION;
    candidate.public_config.generation = next_generation(s_config.public_config.generation);
    lowercase(candidate.public_config.hostname);
    if (candidate.public_config.cloudflare_configured) {
        lowercase(candidate.public_config.cloudflare_zone_name);
        (void)snprintf(candidate.cloudflare_api_token, sizeof(candidate.cloudflare_api_token), "%s",
                       backup->cloudflare_api_token);
    } else {
        candidate.public_config.cloudflare_zone_name[0] = '\0';
        candidate.public_config.cloudflare_zone_id[0] = '\0';
    }
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        if (candidate.public_config.ntp_peers[i].enabled) lowercase(candidate.public_config.ntp_peers[i].server);
        else candidate.public_config.ntp_peers[i].server[0] = '\0';
    }
    const esp_err_t err = persist_config(&candidate);
    if (err == ESP_OK) s_config = candidate;
    unlock_config();
    if (err == ESP_OK) ESP_LOGI(TAG, "Configuration backup restored transactionally: generation=%" PRIu32,
                                candidate.public_config.generation);
    return err;
}


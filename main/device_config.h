#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_config.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_DEVICE_CONFIG_SCHEMA_VERSION             4U
#define APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH          253U
#define APP_CLOUDFLARE_ZONE_ID_LENGTH                32U
#define APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH          512U

#define APP_NTP_GENERAL_PEER_COUNT                   3U
#define APP_NTP_PEER_MAX_COUNT                       4U
#define APP_REDUNDANT_PEER_INDEX                      3U
#define APP_NTP_PEER_SERVER_MAX_LENGTH               253U
#define APP_NTP_PEER_POLL_MIN_SECONDS                4U
#define APP_NTP_PEER_POLL_MAX_SECONDS                3600U
#define APP_NTP_PEER_POLL_DEFAULT_SECONDS            16U
#define APP_NTP_PEER_TIMEOUT_MIN_MS                  250U
#define APP_NTP_PEER_TIMEOUT_MAX_MS                  10000U
#define APP_NTP_PEER_TIMEOUT_DEFAULT_MS              2000U
#define APP_REDUNDANT_PEER_WARN_DEFAULT_NS            100000U
#define APP_REDUNDANT_PEER_CRITICAL_DEFAULT_NS        1000000U
#define APP_REDUNDANT_PEER_THRESHOLD_MAX_NS           1000000000U

typedef struct {
    bool enabled;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U];
} device_config_ntp_peer_t;

typedef struct {
    uint32_t schema_version;
    uint32_t generation;
    char hostname[APP_DEVICE_HOSTNAME_MAX_LENGTH + 1U];
    bool cloudflare_configured;
    char cloudflare_zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char cloudflare_zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
    bool ntp_peer_monitor_enabled;
    uint32_t ntp_peer_poll_interval_seconds;
    uint32_t ntp_peer_response_timeout_ms;
    uint32_t redundant_peer_warning_ns;
    uint32_t redundant_peer_critical_ns;
    device_config_ntp_peer_t ntp_peers[APP_NTP_PEER_MAX_COUNT];
    /* Static IPv4 (applied at boot; DHCP when disabled). Addresses are in
     * network byte order, as in esp_ip4_addr_t.addr. dns may be 0. */
    bool static_ipv4_enabled;
    uint32_t static_ipv4_address;
    uint32_t static_ipv4_netmask;
    uint32_t static_ipv4_gateway;
    uint32_t static_ipv4_dns;
    uint32_t static_ipv4_dns2;   /* backup DNS server; 0 = none */
} device_config_snapshot_t;


typedef struct {
    uint32_t backup_schema_version;
    device_config_snapshot_t config;
    char cloudflare_api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
} device_config_backup_t;

#define APP_DEVICE_CONFIG_BACKUP_SCHEMA_VERSION 2U

typedef struct {
    char api_token[APP_CLOUDFLARE_API_TOKEN_MAX_LENGTH + 1U];
    char zone_name[APP_CLOUDFLARE_ZONE_NAME_MAX_LENGTH + 1U];
    char zone_id[APP_CLOUDFLARE_ZONE_ID_LENGTH + 1U];
} device_config_cloudflare_credentials_t;

esp_err_t device_config_init(void);
bool device_config_hostname_is_valid(const char *hostname);
bool device_config_cloudflare_zone_is_valid(const char *zone_name);
bool device_config_ntp_peer_server_is_valid(const char *server);
esp_err_t device_config_get_snapshot(device_config_snapshot_t *out_snapshot);
esp_err_t device_config_export_backup(device_config_backup_t *out_backup);
esp_err_t device_config_restore_backup(const device_config_backup_t *backup);
esp_err_t device_config_get_hostname(char *buffer, size_t buffer_size);
esp_err_t device_config_get_cloudflare_credentials(device_config_cloudflare_credentials_t *out_credentials);
esp_err_t device_config_set_hostname(const char *hostname);
esp_err_t device_config_set_cloudflare(const char *api_token,
                                       const char *zone_name,
                                       const char *zone_id);
esp_err_t device_config_clear_cloudflare(void);
/* Validates a static IPv4 configuration: usable host address, contiguous
 * netmask, gateway (if set) inside the subnet. Addresses in network order. */
bool device_config_static_ipv4_is_valid(uint32_t address,
                                        uint32_t netmask,
                                        uint32_t gateway,
                                        uint32_t dns);
/* Takes effect at the next boot. dns2 is an optional backup server. */
esp_err_t device_config_set_static_ipv4(bool enabled,
                                        uint32_t address,
                                        uint32_t netmask,
                                        uint32_t gateway,
                                        uint32_t dns,
                                        uint32_t dns2);
esp_err_t device_config_set_ntp_peer_monitor(bool enabled,
                                             uint32_t poll_interval_seconds,
                                             uint32_t response_timeout_ms,
                                             uint32_t warning_ns,
                                             uint32_t critical_ns,
                                             const device_config_ntp_peer_t peers[APP_NTP_PEER_MAX_COUNT]);

#ifdef __cplusplus
}
#endif

#include "nts_ke.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "acme_client.h"
#include "nts_aes_siv.h"
#include "nts_cookie.h"
#include "nts_storage.h"

#include "esp_err.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/portmacro.h"

#include "lwip/sockets.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include "psa/crypto.h"

static const char *TAG = "NTS_KE";

#define NTS_KE_PORT                         "4460"
#define NTS_KE_TASK_STACK_SIZE              24576U
#define NTS_KE_TASK_PRIORITY                    5U
#define NTS_KE_REQUEST_MAX                  2048U
#define NTS_KE_RESPONSE_MAX                 4096U
#define NTS_KE_COOKIE_COUNT                    8U
#define NTS_KE_COOKIE_LIFETIME_SECONDS     86400ULL
/* Absolute budget for one connection: handshake, request, response and
 * close_notify together. Connections are served one at a time, so this
 * bounds how long a slow or hostile client can deny NTS-KE to others. */
#define NTS_KE_CONNECTION_DEADLINE_MS       5000U
/* How often the stored ACME certificate is compared with the one in use,
 * and how long accept() may block before the loop re-checks. */
#define NTS_KE_CERT_RELOAD_CHECK_SECONDS     600U
#define NTS_KE_ACCEPT_WAKE_SECONDS            30
#define NTS_KE_CERT_DIGEST_LEN                32U

#define NTS_KE_CRITICAL_BIT                0x8000U
#define NTS_KE_RECORD_END_OF_MESSAGE       0x0000U
#define NTS_KE_RECORD_NEXT_PROTOCOL        0x0001U
#define NTS_KE_RECORD_ERROR                0x0002U
#define NTS_KE_RECORD_WARNING              0x0003U
#define NTS_KE_RECORD_AEAD_ALGORITHM       0x0004U
#define NTS_KE_RECORD_NEW_COOKIE           0x0005U
#define NTS_KE_RECORD_NTP_SERVER           0x0006U
#define NTS_KE_RECORD_NTP_PORT             0x0007U

#define NTS_KE_PROTOCOL_NTPV4              0x0000U
#define NTS_KE_AEAD_AES_SIV_CMAC_256       0x000FU

#define NTS_KE_ERROR_UNRECOGNIZED_CRITICAL 0x0000U
#define NTS_KE_ERROR_BAD_REQUEST           0x0001U
#define NTS_KE_ERROR_INTERNAL_SERVER       0x0002U

static const char NTS_EXPORTER_LABEL[] = "EXPORTER-network-time-security";
static const unsigned char NTS_C2S_CONTEXT[5] = {0x00U, 0x00U, 0x00U, 0x0FU, 0x00U};
static const unsigned char NTS_S2C_CONTEXT[5] = {0x00U, 0x00U, 0x00U, 0x0FU, 0x01U};
static const char *const NTS_ALPN_PROTOCOLS[] = {"ntske/1", NULL};

typedef struct {
    bool next_protocol_seen;
    bool aead_seen;
    bool end_seen;
    bool ntpv4_offered;
    bool aes_siv_offered;
    uint16_t protocol_error;
} nts_ke_request_state_t;

typedef struct {
    mbedtls_net_context *net;
    int64_t deadline_us;
} nts_ke_connection_t;

typedef struct {
    mbedtls_ssl_config config;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context private_key;
    uint8_t certificate_digest[NTS_KE_CERT_DIGEST_LEN];
} nts_ke_tls_bundle_t;

static TaskHandle_t s_task;
static volatile bool s_running;
static portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;
static nts_ke_stats_t s_stats;

static void stats_increment(uint32_t *counter)
{
    portENTER_CRITICAL(&s_stats_lock);
    (*counter)++;
    portEXIT_CRITICAL(&s_stats_lock);
}

void nts_ke_get_stats(nts_ke_stats_t *stats)
{
    if (stats == NULL) {
        return;
    }

    portENTER_CRITICAL(&s_stats_lock);
    *stats = s_stats;
    stats->running = s_running;
    portEXIT_CRITICAL(&s_stats_lock);
}

static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void write_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xFFU);
}

static esp_err_t append_record(uint8_t *buffer,
                               size_t buffer_size,
                               size_t *used,
                               uint16_t type,
                               bool critical,
                               const uint8_t *body,
                               size_t body_len)
{
    if (buffer == NULL || used == NULL ||
        body_len > UINT16_MAX ||
        (body_len > 0U && body == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (*used > buffer_size || body_len + 4U > buffer_size - *used) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint16_t wire_type = (uint16_t)(type & 0x7FFFU);
    if (critical) {
        wire_type |= NTS_KE_CRITICAL_BIT;
    }

    write_u16(buffer + *used, wire_type);
    write_u16(buffer + *used + 2U, (uint16_t)body_len);
    *used += 4U;

    if (body_len > 0U) {
        memcpy(buffer + *used, body, body_len);
        *used += body_len;
    }

    return ESP_OK;
}

static bool list_contains_u16(const uint8_t *body,
                              size_t body_len,
                              uint16_t wanted)
{
    if (body == NULL || body_len == 0U || (body_len & 1U) != 0U) {
        return false;
    }

    for (size_t offset = 0U; offset < body_len; offset += 2U) {
        if (read_u16(body + offset) == wanted) {
            return true;
        }
    }

    return false;
}

static esp_err_t parse_request(const uint8_t *request,
                               size_t request_len,
                               nts_ke_request_state_t *state)
{
    if (request == NULL || state == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(state, 0, sizeof(*state));

    size_t offset = 0U;

    while (offset + 4U <= request_len) {
        const uint16_t wire_type = read_u16(request + offset);
        const bool critical = (wire_type & NTS_KE_CRITICAL_BIT) != 0U;
        const uint16_t type = (uint16_t)(wire_type & 0x7FFFU);
        const uint16_t body_len = read_u16(request + offset + 2U);
        offset += 4U;

        if ((size_t)body_len > request_len - offset) {
            state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
            return ESP_ERR_INVALID_RESPONSE;
        }

        const uint8_t *body = request + offset;

        switch (type) {
        case NTS_KE_RECORD_END_OF_MESSAGE:
            if (!critical || body_len != 0U || state->end_seen) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            state->end_seen = true;
            offset += body_len;
            if (offset != request_len) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            break;

        case NTS_KE_RECORD_NEXT_PROTOCOL:
            if (!critical || state->next_protocol_seen ||
                body_len == 0U || (body_len & 1U) != 0U) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            state->next_protocol_seen = true;
            state->ntpv4_offered =
                list_contains_u16(body, body_len, NTS_KE_PROTOCOL_NTPV4);
            offset += body_len;
            break;

        case NTS_KE_RECORD_AEAD_ALGORITHM:
            if (state->aead_seen ||
                body_len == 0U || (body_len & 1U) != 0U) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            state->aead_seen = true;
            state->aes_siv_offered =
                list_contains_u16(body, body_len,
                                  NTS_KE_AEAD_AES_SIV_CMAC_256);
            offset += body_len;
            break;

        case NTS_KE_RECORD_ERROR:
        case NTS_KE_RECORD_WARNING:
            state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
            return ESP_ERR_INVALID_RESPONSE;

        case NTS_KE_RECORD_NTP_SERVER:
            if (body_len == 0U) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            offset += body_len;
            break;

        case NTS_KE_RECORD_NTP_PORT:
            if (body_len != 2U) {
                state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
                return ESP_ERR_INVALID_RESPONSE;
            }
            offset += body_len;
            break;

        default:
            if (critical) {
                state->protocol_error =
                    NTS_KE_ERROR_UNRECOGNIZED_CRITICAL;
                return ESP_ERR_NOT_SUPPORTED;
            }
            offset += body_len;
            break;
        }

        if (state->end_seen) {
            break;
        }
    }

    if (!state->end_seen ||
        !state->next_protocol_seen ||
        !state->ntpv4_offered ||
        !state->aead_seen ||
        !state->aes_siv_offered) {
        state->protocol_error = NTS_KE_ERROR_BAD_REQUEST;
        return ESP_ERR_INVALID_RESPONSE;
    }

    return ESP_OK;
}

static esp_err_t build_error_response(uint16_t error_code,
                                      uint8_t *response,
                                      size_t response_size,
                                      size_t *response_len)
{
    if (response == NULL || response_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *response_len = 0U;

    uint8_t error_body[2];
    write_u16(error_body, error_code);

    esp_err_t err = append_record(response, response_size, response_len,
                                  NTS_KE_RECORD_ERROR, true,
                                  error_body, sizeof(error_body));
    if (err != ESP_OK) {
        return err;
    }

    return append_record(response, response_size, response_len,
                         NTS_KE_RECORD_END_OF_MESSAGE, true,
                         NULL, 0U);
}

static esp_err_t export_traffic_keys(mbedtls_ssl_context *ssl,
                                     nts_cookie_keys_t *keys)
{
    if (ssl == NULL || keys == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(keys, 0, sizeof(*keys));

    int ret = mbedtls_ssl_export_keying_material(
        ssl,
        keys->c2s_key,
        sizeof(keys->c2s_key),
        NTS_EXPORTER_LABEL,
        sizeof(NTS_EXPORTER_LABEL) - 1U,
        NTS_C2S_CONTEXT,
        sizeof(NTS_C2S_CONTEXT),
        1);

    if (ret != 0) {
        nts_storage_zeroize(keys, sizeof(*keys));
        ESP_LOGE(TAG, "C2S TLS exporter failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_export_keying_material(
        ssl,
        keys->s2c_key,
        sizeof(keys->s2c_key),
        NTS_EXPORTER_LABEL,
        sizeof(NTS_EXPORTER_LABEL) - 1U,
        NTS_S2C_CONTEXT,
        sizeof(NTS_S2C_CONTEXT),
        1);

    if (ret != 0) {
        nts_storage_zeroize(keys, sizeof(*keys));
        ESP_LOGE(TAG, "S2C TLS exporter failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t build_success_response(mbedtls_ssl_context *ssl,
                                        uint8_t *response,
                                        size_t response_size,
                                        size_t *response_len)
{
    if (ssl == NULL || response == NULL || response_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *response_len = 0U;

    nts_cookie_keys_t keys;
    esp_err_t err = export_traffic_keys(ssl, &keys);
    if (err != ESP_OK) {
        return err;
    }

    nts_cookie_keys_t metadata;
    err = nts_cookie_generate_keys(&metadata,
                                   NTS_KE_COOKIE_LIFETIME_SECONDS);
    if (err != ESP_OK) {
        nts_storage_zeroize(&keys, sizeof(keys));
        return err;
    }

    keys.master_key_id = metadata.master_key_id;
    keys.issued_ntp_seconds = metadata.issued_ntp_seconds;
    keys.expires_ntp_seconds = metadata.expires_ntp_seconds;
    nts_storage_zeroize(metadata.c2s_key, sizeof(metadata.c2s_key));
    nts_storage_zeroize(metadata.s2c_key, sizeof(metadata.s2c_key));
    nts_storage_zeroize(&metadata, sizeof(metadata));

    const uint8_t protocol_body[2] = {0x00U, 0x00U};
    const uint8_t aead_body[2] = {0x00U, 0x0FU};

    err = append_record(response, response_size, response_len,
                        NTS_KE_RECORD_NEXT_PROTOCOL, true,
                        protocol_body, sizeof(protocol_body));
    if (err == ESP_OK) {
        err = append_record(response, response_size, response_len,
                            NTS_KE_RECORD_AEAD_ALGORITHM, false,
                            aead_body, sizeof(aead_body));
    }

    for (unsigned i = 0U; err == ESP_OK && i < NTS_KE_COOKIE_COUNT; ++i) {
        uint8_t cookie[NTS_COOKIE_MAX_LEN];
        size_t cookie_len = sizeof(cookie);

        err = nts_cookie_create(&keys, cookie, &cookie_len);
        if (err == ESP_OK) {
            err = append_record(response, response_size, response_len,
                                NTS_KE_RECORD_NEW_COOKIE, false,
                                cookie, cookie_len);
        }

        nts_storage_zeroize(cookie, sizeof(cookie));
    }

    if (err == ESP_OK) {
        err = append_record(response, response_size, response_len,
                            NTS_KE_RECORD_END_OF_MESSAGE, true,
                            NULL, 0U);
    }

    nts_storage_zeroize(&keys, sizeof(keys));
    return err;
}

static bool connection_expired(const nts_ke_connection_t *connection)
{
    return esp_timer_get_time() >= connection->deadline_us;
}

static uint32_t connection_remaining_ms(const nts_ke_connection_t *connection)
{
    const int64_t remaining_us =
        connection->deadline_us - esp_timer_get_time();

    if (remaining_us <= 0) {
        return 0U;
    }

    /* Round up so a sub-millisecond remainder is not treated as "block
     * forever" (0) by mbedtls_net_recv_timeout(). */
    return (uint32_t)((remaining_us + 999) / 1000);
}

/* BIO send: refuse once the connection deadline has passed, and bound each
 * blocking send to the remaining budget so a peer that never drains its
 * receive window cannot hold the task past the deadline. */
static int connection_send(void *ctx, const unsigned char *buf, size_t len)
{
    nts_ke_connection_t *connection = (nts_ke_connection_t *)ctx;
    const uint32_t remaining_ms = connection_remaining_ms(connection);

    if (remaining_ms == 0U) {
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    const struct timeval timeout = {
        .tv_sec = remaining_ms / 1000U,
        .tv_usec = (remaining_ms % 1000U) * 1000U,
    };
    (void)setsockopt(connection->net->fd, SOL_SOCKET, SO_SNDTIMEO,
                     &timeout, sizeof(timeout));

    return mbedtls_net_send(connection->net, buf, len);
}

/* BIO receive: never wait past the connection deadline, whatever per-read
 * timeout mbedTLS asks for. */
static int connection_recv_timeout(void *ctx,
                                   unsigned char *buf,
                                   size_t len,
                                   uint32_t timeout_ms)
{
    nts_ke_connection_t *connection = (nts_ke_connection_t *)ctx;
    const uint32_t remaining_ms = connection_remaining_ms(connection);

    if (remaining_ms == 0U) {
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    if (timeout_ms == 0U || timeout_ms > remaining_ms) {
        timeout_ms = remaining_ms;
    }

    return mbedtls_net_recv_timeout(connection->net, buf, len, timeout_ms);
}

static void connection_set_socket_timeouts(mbedtls_net_context *client)
{
    const struct timeval timeout = {
        .tv_sec = NTS_KE_CONNECTION_DEADLINE_MS / 1000U,
        .tv_usec = (NTS_KE_CONNECTION_DEADLINE_MS % 1000U) * 1000U,
    };

    (void)setsockopt(client->fd, SOL_SOCKET, SO_SNDTIMEO,
                     &timeout, sizeof(timeout));
    (void)setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO,
                     &timeout, sizeof(timeout));
}

static esp_err_t tls_write_all(mbedtls_ssl_context *ssl,
                               const nts_ke_connection_t *connection,
                               const uint8_t *data,
                               size_t length)
{
    size_t sent = 0U;

    while (sent < length) {
        if (connection_expired(connection)) {
            stats_increment(&s_stats.deadline_expirations);
            ESP_LOGW(TAG, "TLS write abandoned: connection deadline expired");
            return ESP_ERR_TIMEOUT;
        }

        const int ret = mbedtls_ssl_write(ssl, data + sent, length - sent);

        if (ret > 0) {
            sent += (size_t)ret;
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            stats_increment(&s_stats.deadline_expirations);
            ESP_LOGW(TAG, "TLS write abandoned: connection deadline expired");
            return ESP_ERR_TIMEOUT;
        }

        ESP_LOGE(TAG, "TLS write failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t tls_read_request(mbedtls_ssl_context *ssl,
                                  const nts_ke_connection_t *connection,
                                  uint8_t *request,
                                  size_t request_size,
                                  size_t *request_len)
{
    if (ssl == NULL || connection == NULL ||
        request == NULL || request_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *request_len = 0U;

    while (*request_len < request_size) {
        if (connection_expired(connection)) {
            stats_increment(&s_stats.deadline_expirations);
            ESP_LOGW(TAG, "TLS read abandoned: connection deadline expired");
            return ESP_ERR_TIMEOUT;
        }

        const int ret = mbedtls_ssl_read(
            ssl,
            request + *request_len,
            request_size - *request_len);

        if (ret > 0) {
            *request_len += (size_t)ret;

            size_t offset = 0U;
            while (offset + 4U <= *request_len) {
                const uint16_t wire_type = read_u16(request + offset);
                const uint16_t type = (uint16_t)(wire_type & 0x7FFFU);
                const uint16_t body_len = read_u16(request + offset + 2U);

                if ((size_t)body_len > *request_len - offset - 4U) {
                    break;
                }

                offset += 4U + (size_t)body_len;

                if (type == NTS_KE_RECORD_END_OF_MESSAGE) {
                    if (offset != *request_len) {
                        return ESP_ERR_INVALID_RESPONSE;
                    }
                    return ESP_OK;
                }
            }

            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return ESP_ERR_INVALID_RESPONSE;
        }

        if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            stats_increment(&s_stats.deadline_expirations);
            ESP_LOGW(TAG, "TLS read abandoned: connection deadline expired");
            return ESP_ERR_TIMEOUT;
        }

        ESP_LOGW(TAG, "TLS read failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    return ESP_ERR_INVALID_SIZE;
}

/* close_notify is a courtesy: send it only while the connection still has
 * budget, and never spin on a peer that will not drain its receive window. */
static void close_tls_session(mbedtls_ssl_context *ssl,
                              const nts_ke_connection_t *connection)
{
    if (ssl == NULL || connection == NULL) {
        return;
    }

    int ret;
    do {
        if (connection_expired(connection)) {
            return;
        }
        ret = mbedtls_ssl_close_notify(ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE);
}

static void handle_client(mbedtls_net_context *client,
                          mbedtls_ssl_config *config)
{
    nts_ke_connection_t connection = {
        .net = client,
        .deadline_us = esp_timer_get_time() +
                       ((int64_t)NTS_KE_CONNECTION_DEADLINE_MS * 1000LL),
    };

    connection_set_socket_timeouts(client);

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    int ret = mbedtls_ssl_setup(&ssl, config);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ssl_setup failed: -0x%x", -ret);
        mbedtls_ssl_free(&ssl);
        return;
    }

    mbedtls_ssl_set_bio(&ssl, &connection,
                        connection_send,
                        NULL,
                        connection_recv_timeout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if ((ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE) &&
            !connection_expired(&connection)) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_TIMEOUT ||
            ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            stats_increment(&s_stats.deadline_expirations);
            ESP_LOGW(TAG, "TLS handshake abandoned: connection deadline expired");
        } else {
            ESP_LOGW(TAG, "TLS handshake failed: -0x%x", -ret);
        }
        stats_increment(&s_stats.tls_handshake_failures);
        mbedtls_ssl_free(&ssl);
        return;
    }

    const char *alpn = mbedtls_ssl_get_alpn_protocol(&ssl);
    if (alpn == NULL || strcmp(alpn, "ntske/1") != 0) {
        ESP_LOGW(TAG, "Rejecting connection without ntske/1 ALPN");
        stats_increment(&s_stats.alpn_rejections);
        close_tls_session(&ssl, &connection);
        mbedtls_ssl_free(&ssl);
        return;
    }

    uint8_t request[NTS_KE_REQUEST_MAX];
    size_t request_len = 0U;
    esp_err_t err = tls_read_request(&ssl, &connection, request, sizeof(request),
                                     &request_len);

    uint8_t response[NTS_KE_RESPONSE_MAX];
    size_t response_len = 0U;

    if (err == ESP_OK) {
        nts_ke_request_state_t state;
        err = parse_request(request, request_len, &state);

        if (err == ESP_OK) {
            err = build_success_response(&ssl, response,
                                         sizeof(response),
                                         &response_len);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "NTS-KE response construction failed: %s",
                         esp_err_to_name(err));
                (void)build_error_response(
                    NTS_KE_ERROR_INTERNAL_SERVER,
                    response, sizeof(response), &response_len);
            }
        } else {
            const uint16_t protocol_error =
                state.protocol_error <= NTS_KE_ERROR_INTERNAL_SERVER
                    ? state.protocol_error
                    : NTS_KE_ERROR_BAD_REQUEST;
            (void)build_error_response(protocol_error,
                                       response, sizeof(response),
                                       &response_len);
        }
    } else {
        (void)build_error_response(NTS_KE_ERROR_BAD_REQUEST,
                                   response, sizeof(response),
                                   &response_len);
    }

    if (response_len > 0U) {
        const esp_err_t write_err =
            tls_write_all(&ssl, &connection, response, response_len);

        if (write_err == ESP_OK) {
            stats_increment(&s_stats.exchanges_completed);
            ESP_LOGI(TAG,
                     "NTS-KE exchange complete: request=%u response=%u",
                     (unsigned)request_len,
                     (unsigned)response_len);
        } else {
            stats_increment(&s_stats.exchange_failures);
        }
    } else {
        stats_increment(&s_stats.exchange_failures);
    }

    nts_storage_zeroize(request, sizeof(request));
    nts_storage_zeroize(response, sizeof(response));

    close_tls_session(&ssl, &connection);
    mbedtls_ssl_free(&ssl);
}

static void tls_bundle_free(nts_ke_tls_bundle_t *bundle)
{
    if (bundle == NULL) {
        return;
    }

    mbedtls_ssl_config_free(&bundle->config);
    mbedtls_pk_free(&bundle->private_key);
    mbedtls_x509_crt_free(&bundle->certificate);
    free(bundle);
}

static esp_err_t certificate_digest(const acme_tls_credentials_t *credentials,
                                    uint8_t digest[NTS_KE_CERT_DIGEST_LEN])
{
    size_t digest_len = 0U;
    const psa_status_t status = psa_hash_compute(
        PSA_ALG_SHA_256,
        (const uint8_t *)credentials->certificate_pem,
        credentials->certificate_pem_length,
        digest,
        NTS_KE_CERT_DIGEST_LEN,
        &digest_len);

    return (status == PSA_SUCCESS && digest_len == NTS_KE_CERT_DIGEST_LEN)
               ? ESP_OK
               : ESP_FAIL;
}

static esp_err_t configure_tls(mbedtls_ssl_config *config,
                               mbedtls_x509_crt *certificate,
                               mbedtls_pk_context *private_key,
                               const acme_tls_credentials_t *credentials)
{
    int ret = mbedtls_x509_crt_parse(
        certificate,
        (const unsigned char *)credentials->certificate_pem,
        credentials->certificate_pem_length + 1U);

    if (ret < 0) {
        ESP_LOGE(TAG, "Production certificate parse failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    ret = mbedtls_pk_parse_key(
    private_key,
    (const unsigned char *)credentials->private_key_pem,
    credentials->private_key_pem_length,
    NULL,
    0U);

    if (ret != 0) {
        ESP_LOGE(TAG, "Production private-key parse failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_config_defaults(
        config,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0) {
        ESP_LOGE(TAG, "TLS configuration defaults failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    mbedtls_ssl_conf_min_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(config, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(config, MBEDTLS_SSL_VERIFY_NONE);
    /* Per-read cap; connection_recv_timeout() further limits every read to
     * what remains of the per-connection deadline. */
    mbedtls_ssl_conf_read_timeout(config, NTS_KE_CONNECTION_DEADLINE_MS);

    ret = mbedtls_ssl_conf_alpn_protocols(config, NTS_ALPN_PROTOCOLS);
    if (ret != 0) {
        ESP_LOGE(TAG, "ALPN configuration failed: -0x%x", -ret);
        return ESP_FAIL;
    }

    ret = mbedtls_ssl_conf_own_cert(config, certificate, private_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "Server certificate configuration failed: -0x%x",
                 -ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/*
 * Loads the current production ACME credential into a new heap-allocated
 * TLS bundle. When `current_digest` is given and the stored certificate is
 * unchanged, returns ESP_ERR_NOT_FINISHED without building anything. The
 * bundle lives on the heap because the SSL config holds pointers to the
 * certificate and key inside it.
 */
static esp_err_t tls_bundle_load(const uint8_t *current_digest,
                                 nts_ke_tls_bundle_t **out_bundle)
{
    *out_bundle = NULL;

    acme_tls_credentials_t credentials;
    memset(&credentials, 0, sizeof(credentials));

    esp_err_t err =
        acme_client_load_production_tls_credentials(&credentials);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Production TLS credential load failed: %s",
                 esp_err_to_name(err));
        return err;
    }

    uint8_t digest[NTS_KE_CERT_DIGEST_LEN];
    err = certificate_digest(&credentials, digest);
    if (err != ESP_OK) {
        acme_client_free_tls_credentials(&credentials);
        return err;
    }

    if (current_digest != NULL &&
        memcmp(digest, current_digest, sizeof(digest)) == 0) {
        acme_client_free_tls_credentials(&credentials);
        return ESP_ERR_NOT_FINISHED;
    }

    nts_ke_tls_bundle_t *bundle = calloc(1U, sizeof(*bundle));
    if (bundle == NULL) {
        acme_client_free_tls_credentials(&credentials);
        return ESP_ERR_NO_MEM;
    }

    mbedtls_ssl_config_init(&bundle->config);
    mbedtls_x509_crt_init(&bundle->certificate);
    mbedtls_pk_init(&bundle->private_key);
    memcpy(bundle->certificate_digest, digest, sizeof(digest));

    err = configure_tls(&bundle->config, &bundle->certificate,
                        &bundle->private_key, &credentials);
    acme_client_free_tls_credentials(&credentials);

    if (err != ESP_OK) {
        tls_bundle_free(bundle);
        return err;
    }

    *out_bundle = bundle;
    return ESP_OK;
}

/* ACME renewals replace the stored production certificate without telling
 * this task. Re-check periodically, between connections, and swap in a new
 * TLS config when the certificate has changed. On any failure the current
 * (still valid until expiry) bundle stays in service. */
static void tls_bundle_maybe_reload(nts_ke_tls_bundle_t **active)
{
    nts_ke_tls_bundle_t *replacement = NULL;
    const esp_err_t err =
        tls_bundle_load((*active)->certificate_digest, &replacement);

    if (err == ESP_ERR_NOT_FINISHED) {
        return;
    }

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "TLS credential reload failed; keeping current: %s",
                 esp_err_to_name(err));
        return;
    }

    tls_bundle_free(*active);
    *active = replacement;
    stats_increment(&s_stats.certificate_reloads);
    ESP_LOGI(TAG, "NTS-KE TLS certificate reloaded after renewal");
}

static void nts_ke_task(void *arg)
{
    (void)arg;

    mbedtls_net_context listener;
    mbedtls_net_init(&listener);

    nts_ke_tls_bundle_t *tls = NULL;

    esp_err_t err = nts_aes_siv_self_test();
    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "AES-SIV self-test FAILED (%s); NTS disabled for this boot",
                 esp_err_to_name(err));
        goto exit;
    }
    ESP_LOGI(TAG, "AES-SIV self-test passed");

    bool waiting_logged = false;
    for (;;) {
        err = nts_storage_ensure_cookie_keyring();
        if (err == ESP_OK) break;
        if (err != ESP_ERR_INVALID_STATE) {
            ESP_LOGE(TAG, "Cookie keyring unavailable: %s", esp_err_to_name(err));
            goto exit;
        }
        if (!waiting_logged) {
            ESP_LOGW(TAG, "NTS-KE waiting for GNSS/PPS authoritative time before cookie-key initialization");
            waiting_logged = true;
        }
        vTaskDelay(pdMS_TO_TICKS(1000U));
    }
    if (waiting_logged)
        ESP_LOGI(TAG, "GNSS/PPS authoritative time available; continuing NTS-KE startup");

    err = tls_bundle_load(NULL, &tls);
    if (err != ESP_OK) {
        goto exit;
    }

    int ret = mbedtls_net_bind(
        &listener, NULL, NTS_KE_PORT, MBEDTLS_NET_PROTO_TCP);

    if (ret != 0) {
        ESP_LOGE(TAG, "TCP/%s bind failed: -0x%x", NTS_KE_PORT, -ret);
        goto exit;
    }

    s_running = true;
    ESP_LOGI(TAG,
             "NTS-KE active on TCP/%s; TLS 1.3; ALPN=ntske/1; production ACME credential",
             NTS_KE_PORT);

    int64_t last_reload_check_us = esp_timer_get_time();

    for (;;) {
        const int64_t now_us = esp_timer_get_time();
        if (now_us - last_reload_check_us >=
            (int64_t)NTS_KE_CERT_RELOAD_CHECK_SECONDS * 1000000LL) {
            last_reload_check_us = now_us;
            tls_bundle_maybe_reload(&tls);
        }

        /* Wait for a connection with a timeout so certificate renewals are
         * picked up even when no client connects. */
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener.fd, &readable);
        struct timeval accept_wait = {
            .tv_sec = NTS_KE_ACCEPT_WAKE_SECONDS,
            .tv_usec = 0,
        };
        const int ready =
            select(listener.fd + 1, &readable, NULL, NULL, &accept_wait);
        if (ready <= 0) {
            if (ready < 0) {
                /* Avoid a tight loop if select() itself is failing. */
                vTaskDelay(pdMS_TO_TICKS(100U));
            }
            continue;
        }

        mbedtls_net_context client;
        mbedtls_net_init(&client);

        ret = mbedtls_net_accept(&listener, &client, NULL, 0U, NULL);
        if (ret != 0) {
            ESP_LOGW(TAG, "TCP accept failed: -0x%x", -ret);
            mbedtls_net_free(&client);
            continue;
        }

        handle_client(&client, &tls->config);
        mbedtls_net_free(&client);
    }

exit:
    s_running = false;
    s_task = NULL;

    mbedtls_net_free(&listener);
    tls_bundle_free(tls);

    vTaskDelete(NULL);
}

esp_err_t nts_ke_start(void)
{
    if (s_task != NULL || s_running) {
        return ESP_OK;
    }

    BaseType_t created = xTaskCreate(
        nts_ke_task,
        "nts_ke",
        NTS_KE_TASK_STACK_SIZE,
        NULL,
        NTS_KE_TASK_PRIORITY,
        &s_task);

    if (created != pdPASS) {
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

bool nts_ke_is_running(void)
{
    return s_running;
}

#include "management_ownership.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"

static const char *TAG = "OWNERSHIP";
#define OWNERSHIP_NS "mgmt_owner"
#define KEY_CLAIMED  "claimed"
#define KEY_CA_PEM   "client_ca"

static bool s_initialized;
static bool s_provisioned;
static char s_token[MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH + 1U];

static void make_token(void)
{
    uint8_t random_bytes[MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH / 2U];
    esp_fill_random(random_bytes, sizeof(random_bytes));
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        s_token[i * 2U] = hex[random_bytes[i] >> 4U];
        s_token[i * 2U + 1U] = hex[random_bytes[i] & 0x0fU];
    }
    s_token[MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH] = '\0';
    memset(random_bytes, 0, sizeof(random_bytes));
}

static bool constant_time_equal(const char *a, const char *b, size_t n)
{
    unsigned char diff = 0U;
    for (size_t i = 0; i < n; ++i) diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0U;
}

static esp_err_t validate_ca(const char *pem, size_t length)
{
    if (pem == NULL || length < 64U || length > MANAGEMENT_OWNERSHIP_CA_MAX_LENGTH) return ESP_ERR_INVALID_ARG;
    if (memchr(pem, '\0', length) != NULL) return ESP_ERR_INVALID_ARG;
    if (strstr(pem, "-----BEGIN CERTIFICATE-----") == NULL ||
        strstr(pem, "-----END CERTIFICATE-----") == NULL) return ESP_ERR_INVALID_ARG;

    char *terminated = calloc(1U, length + 1U);
    if (terminated == NULL) return ESP_ERR_NO_MEM;
    memcpy(terminated, pem, length);

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    const int rc = mbedtls_x509_crt_parse(&cert, (const unsigned char *)terminated, length + 1U);
    bool is_ca = false;
    if (rc == 0) {
        for (mbedtls_x509_crt *p = &cert; p != NULL; p = p->next) {
            if (mbedtls_x509_crt_check_key_usage(
                    p, MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0) {
                is_ca = true;
                break;
            }
        }
    }
    mbedtls_x509_crt_free(&cert);
    memset(terminated, 0, length + 1U);
    free(terminated);
    return (rc == 0 && is_ca) ? ESP_OK : ESP_ERR_INVALID_ARG;
}

esp_err_t management_ownership_init(void)
{
    if (s_initialized) return ESP_OK;
    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(OWNERSHIP_NS, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_provisioned = false;
        make_token();
        s_initialized = true;
        ESP_LOGW(TAG, "Device is UNPROVISIONED");
        ESP_LOGW(TAG, "One-time management enrollment code: %s", s_token);
        ESP_LOGW(TAG, "Enrollment is permitted only until a management CA is claimed");
        return ESP_OK;
    }
    if (err != ESP_OK) return err;

    uint8_t claimed = 0U;
    err = nvs_get_u8(h, KEY_CLAIMED, &claimed);
    if (err == ESP_OK && claimed == 1U) {
        size_t required = 0U;
        err = nvs_get_str(h, KEY_CA_PEM, NULL, &required);
        if (err == ESP_OK && required > 1U && required <= MANAGEMENT_OWNERSHIP_CA_MAX_LENGTH + 1U)
            s_provisioned = true;
        else
            err = ESP_ERR_INVALID_STATE;
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;
        s_provisioned = false;
    }
    nvs_close(h);
    if (err != ESP_OK) return err;

    if (!s_provisioned) {
        make_token();
        ESP_LOGW(TAG, "Device is UNPROVISIONED");
        ESP_LOGW(TAG, "One-time management enrollment code: %s", s_token);
    } else {
        memset(s_token, 0, sizeof(s_token));
        ESP_LOGI(TAG, "Management ownership is provisioned; mTLS client authentication required");
    }
    s_initialized = true;
    return ESP_OK;
}

bool management_ownership_is_provisioned(void) { return s_initialized && s_provisioned; }
const char *management_ownership_enrollment_token(void) { return s_provisioned ? "" : s_token; }

bool management_ownership_token_matches(const char *candidate)
{
    if (!s_initialized || s_provisioned || candidate == NULL) return false;
    if (strlen(candidate) != MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH) return false;
    return constant_time_equal(candidate, s_token, MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH);
}

esp_err_t management_ownership_claim(const char *token, const char *ca_pem, size_t ca_pem_length)
{
    if (!s_initialized || s_provisioned) return ESP_ERR_INVALID_STATE;
    if (!management_ownership_token_matches(token)) return ESP_ERR_INVALID_ARG;
    esp_err_t err = validate_ca(ca_pem, ca_pem_length);
    if (err != ESP_OK) return err;

    char *terminated = calloc(1U, ca_pem_length + 1U);
    if (terminated == NULL) return ESP_ERR_NO_MEM;
    memcpy(terminated, ca_pem, ca_pem_length);

    nvs_handle_t h = 0;
    err = nvs_open(OWNERSHIP_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) err = nvs_set_str(h, KEY_CA_PEM, terminated);
    if (err == ESP_OK) err = nvs_set_u8(h, KEY_CLAIMED, 1U);
    if (err == ESP_OK) err = nvs_commit(h);
    if (h != 0) nvs_close(h);
    memset(terminated, 0, ca_pem_length + 1U);
    free(terminated);

    if (err == ESP_OK) {
        s_provisioned = true;
        memset(s_token, 0, sizeof(s_token));
        ESP_LOGI(TAG, "Management ownership claimed; provisioning path permanently closed until NVS ownership state is erased");
    }
    return err;
}

esp_err_t management_ownership_load_ca(char **out_pem, size_t *out_length)
{
    if (out_pem == NULL || out_length == NULL) return ESP_ERR_INVALID_ARG;
    *out_pem = NULL; *out_length = 0U;
    if (!s_initialized || !s_provisioned) return ESP_ERR_INVALID_STATE;

    nvs_handle_t h = 0;
    esp_err_t err = nvs_open(OWNERSHIP_NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t required = 0U;
    err = nvs_get_str(h, KEY_CA_PEM, NULL, &required);
    if (err != ESP_OK || required < 2U || required > MANAGEMENT_OWNERSHIP_CA_MAX_LENGTH + 1U) {
        nvs_close(h); return err == ESP_OK ? ESP_ERR_INVALID_SIZE : err;
    }
    char *pem = calloc(1U, required);
    if (pem == NULL) { nvs_close(h); return ESP_ERR_NO_MEM; }
    err = nvs_get_str(h, KEY_CA_PEM, pem, &required);
    nvs_close(h);
    if (err != ESP_OK) { memset(pem, 0, required); free(pem); return err; }
    *out_pem = pem;
    *out_length = required;
    return ESP_OK;
}

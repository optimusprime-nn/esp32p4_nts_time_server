#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "nts_cookie.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NTS_NTP_MAX_PACKET_SIZE 1280U
#define NTS_NTP_MAX_UID_LEN      256U
#define NTS_NTP_MAX_PLACEHOLDERS   7U

typedef struct {
    uint8_t unique_id[NTS_NTP_MAX_UID_LEN];
    size_t unique_id_len;
    uint16_t valid_placeholders;
    size_t request_length;
    nts_cookie_keys_t keys;
    bool authenticated;
    /* Set by nts_ntp_auth_prepare_response(): the fresh-cookie plaintext is
     * staged in the module's static buffer (single NTP task owner). */
    bool response_prepared;
    size_t prepared_plaintext_len;
} nts_ntp_auth_context_t;

typedef struct {
    uint32_t verification_attempts;
    uint32_t authenticated_requests;
    uint32_t verification_failures;
    uint32_t protected_responses;
    uint32_t protection_failures;
} nts_ntp_auth_stats_t;

bool nts_ntp_auth_request_present(const uint8_t *packet, size_t packet_len);

esp_err_t nts_ntp_auth_verify_request(
    const uint8_t *packet,
    size_t packet_len,
    nts_ntp_auth_context_t *context);

/* Generates the 1+k fresh cookies for an authenticated request. Call before
 * the response transmit timestamp is sampled: this is the costly part of
 * response protection and does not depend on the NTP header. */
esp_err_t nts_ntp_auth_prepare_response(nts_ntp_auth_context_t *context);

/* Appends the UID and Authenticator over the already-built NTP header. The
 * context must have been prepared with nts_ntp_auth_prepare_response(). */
esp_err_t nts_ntp_auth_protect_response(
    const nts_ntp_auth_context_t *context,
    uint8_t *packet,
    size_t base_packet_len,
    size_t packet_capacity,
    size_t *packet_len);

void nts_ntp_auth_clear_context(nts_ntp_auth_context_t *context);
void nts_ntp_auth_get_stats(nts_ntp_auth_stats_t *stats);

#ifdef __cplusplus
}
#endif

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MANAGEMENT_OWNERSHIP_TOKEN_HEX_LENGTH 32U
#define MANAGEMENT_OWNERSHIP_CA_MAX_LENGTH    6144U

esp_err_t management_ownership_init(void);
bool management_ownership_is_provisioned(void);
const char *management_ownership_enrollment_token(void);
bool management_ownership_token_matches(const char *candidate);
esp_err_t management_ownership_claim(const char *token, const char *ca_pem, size_t ca_pem_length);
esp_err_t management_ownership_load_ca(char **out_pem, size_t *out_length);

#ifdef __cplusplus
}
#endif

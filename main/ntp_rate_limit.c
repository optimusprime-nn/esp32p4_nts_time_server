#include "ntp_rate_limit.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_timer.h"

/* Distinct client addresses tracked; least-recently-seen is evicted. */
#define APP_NTP_MAX_CLIENTS                     128U
#define APP_NTP_RATE_BURST                      8U
#define APP_NTP_RATE_PER_MINUTE                 30U
#define APP_NTP_CLIENT_IDLE_US                  900000000LL
/* A rate-limited client gets at most one RATE KoD per interval; further
 * excess requests are dropped silently so KoD replies cannot themselves be
 * used to generate a steady reply stream. */
#define APP_NTP_KOD_INTERVAL_US                 5000000LL

typedef struct {
    bool in_use;
    uint32_t client_ipv4;

    uint32_t tokens;
    int64_t last_refill_us;
    int64_t last_seen_us;
    int64_t last_kod_us;
} ntp_rate_client_t;

static ntp_rate_client_t s_clients[APP_NTP_MAX_CLIENTS];

static void refill_client(ntp_rate_client_t *client,
                          int64_t now_us)
{
    if (client == NULL) {
        return;
    }

    if (client->last_refill_us == 0) {
        client->last_refill_us = now_us;
        client->tokens = APP_NTP_RATE_BURST;
        return;
    }

    const int64_t elapsed_us = now_us - client->last_refill_us;

    if (elapsed_us <= 0) {
        return;
    }

    const uint64_t tokens_to_add =
        ((uint64_t)elapsed_us *
         APP_NTP_RATE_PER_MINUTE) /
        60000000ULL;

    if (tokens_to_add == 0U) {
        return;
    }

    uint64_t updated_tokens =
        (uint64_t)client->tokens + tokens_to_add;

    if (updated_tokens > APP_NTP_RATE_BURST) {
        updated_tokens = APP_NTP_RATE_BURST;
    }

    client->tokens = (uint32_t)updated_tokens;
    client->last_refill_us = now_us;
}

static ntp_rate_client_t *find_or_allocate_client(uint32_t client_ipv4,
                                                   int64_t now_us)
{
    ntp_rate_client_t *oldest = &s_clients[0];

    for (size_t index = 0U; index < APP_NTP_MAX_CLIENTS; ++index) {
        ntp_rate_client_t *candidate = &s_clients[index];

        if (candidate->in_use &&
            candidate->client_ipv4 == client_ipv4) {
            return candidate;
        }

        if (!candidate->in_use) {
            candidate->in_use = true;
            candidate->client_ipv4 = client_ipv4;
            candidate->tokens = APP_NTP_RATE_BURST;
            candidate->last_refill_us = now_us;
            candidate->last_seen_us = now_us;
            candidate->last_kod_us = 0;
            return candidate;
        }

        if (candidate->last_seen_us < oldest->last_seen_us) {
            oldest = candidate;
        }
    }

    oldest->in_use = true;
    oldest->client_ipv4 = client_ipv4;
    oldest->tokens = APP_NTP_RATE_BURST;
    oldest->last_refill_us = now_us;
    oldest->last_seen_us = now_us;
    oldest->last_kod_us = 0;

    return oldest;
}

void ntp_rate_limit_init(void)
{
    memset(s_clients, 0, sizeof(s_clients));
}

bool ntp_rate_limit_allow(uint32_t client_ipv4,
                          bool *out_send_kod)
{
    if (out_send_kod != NULL) {
        *out_send_kod = false;
    }

    const int64_t now_us = esp_timer_get_time();

    ntp_rate_client_t *client =
        find_or_allocate_client(client_ipv4, now_us);

    refill_client(client, now_us);

    client->last_seen_us = now_us;

    if (client->tokens > 0U) {
        client->tokens--;
        return true;
    }

    if (out_send_kod != NULL &&
        (client->last_kod_us == 0 ||
         now_us - client->last_kod_us >= APP_NTP_KOD_INTERVAL_US)) {
        client->last_kod_us = now_us;
        *out_send_kod = true;
    }

    return false;
}
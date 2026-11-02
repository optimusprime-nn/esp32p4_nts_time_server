#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool running;
    uint32_t tls_handshake_failures;
    uint32_t alpn_rejections;
    uint32_t exchanges_completed;
    uint32_t exchange_failures;
    uint32_t deadline_expirations;
    uint32_t certificate_reloads;
    /* Connections closed before TLS: client already at its concurrent
     * limit, internal heap too low for another session, or every worker
     * busy with the backlog full. */
    uint32_t per_client_rejections;
    uint32_t low_memory_rejections;
    uint32_t busy_rejections;
    uint32_t active_connections;
    /* Smallest free stack seen in any worker after a connection, bytes. */
    uint32_t worker_stack_min_free;
} nts_ke_stats_t;

esp_err_t nts_ke_start(void);
bool nts_ke_is_running(void);
void nts_ke_get_stats(nts_ke_stats_t *stats);

#ifdef __cplusplus
}
#endif

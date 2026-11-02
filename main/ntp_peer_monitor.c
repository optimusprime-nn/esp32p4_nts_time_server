#include "ntp_peer_monitor.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "clock_discipline.h"
#include "eth_service.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "operations_history.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "NTP_PEER";

#define NTP_PORT                         123
#define NTP_PACKET_SIZE                  48U
#define NTP_VERSION                      4U
#define NTP_MODE_CLIENT                  3U
#define NTP_MODE_SERVER                  4U
#define NTP_PEER_TASK_STACK_SIZE         12288U
#define NTP_PEER_TASK_PRIORITY           4U
#define NTP_PEER_START_DELAY_MS          2000U
#define NTP_PEER_DIVERGENT_NS            10000000LL
#define NTP_PEER_DEGRADED_DELAY_NS       100000000LL
#define NTP_PEER_DEGRADED_JITTER_NS      5000000LL
#define NTP_PEER_UNREACHABLE_FAILURES    3U
#define NTP_PEER_ROLLING_WINDOW          16U
#define NTP_PEER_CONFIG_CHECK_MS         1000U

typedef struct {
    int sock;
    bool active;
    bool completed;
    struct sockaddr_in address;
    clock_ntp_timestamp_t t1;
    int64_t deadline_us;
    bool local_time_valid;
    uint16_t local_port; /* host order; 0 if unknown */
} poll_context_t;

typedef struct {
    int64_t offset[NTP_PEER_ROLLING_WINDOW];
    int64_t delay[NTP_PEER_ROLLING_WINDOW];
    uint32_t count;
    uint32_t next;
    uint64_t last_server_t3;
    bool last_server_t3_valid;
    int64_t last_success_us;
    bool config_valid;
    bool enabled;
    int64_t kod_suppress_until_us; /* 0=none, INT64_MAX=DENY/RSTR */
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U];
} peer_runtime_t;

static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static bool s_initialized;
static bool s_running;
static ntp_peer_monitor_status_t s_status;
static peer_runtime_t s_runtime[APP_NTP_PEER_MAX_COUNT];

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint64_t timestamp_to_fixed(clock_ntp_timestamp_t t)
{
    return ((uint64_t)t.seconds << 32) | (uint64_t)t.fraction;
}

/* Hardware stamps may sit slightly the "wrong" side of the software ones
 * (PTP/UTC mapping error); beyond that they are rejected. */
#define PEER_HW_STAMP_TOLERANCE_NS INT64_C(50000)
#define PEER_HW_STAMP_MAX_SKEW_NS  INT64_C(20000000)
/* Negative round-trip delay accepted as zero; below this a reply is invalid. */
#define PEER_NEGATIVE_DELAY_TOLERANCE_NS INT64_C(100000)

/* NTP-era nanoseconds to NTP 32.32. */
static uint64_t ns_to_fixed(uint64_t ns)
{
    const uint64_t seconds = ns / UINT64_C(1000000000);
    const uint64_t nanos = ns % UINT64_C(1000000000);
    return (seconds << 32) | (((nanos << 32) + UINT64_C(500000000)) / UINT64_C(1000000000));
}

static int64_t fixed_delta_ns(uint64_t a, uint64_t b)
{
    /* Integer conversion from signed NTP 32.32 delta to nanoseconds. */
    const int64_t delta = (int64_t)(a - b);
    const int64_t whole_seconds = delta / INT64_C(4294967296);
    const int64_t fractional = delta % INT64_C(4294967296);
    return whole_seconds * INT64_C(1000000000) +
           (fractional * INT64_C(1000000000)) / INT64_C(4294967296);
}

static int64_t abs_i64(int64_t value)
{
    if (value == INT64_MIN) return INT64_MAX;
    return value < 0 ? -value : value;
}

static uint64_t isqrt_u64(uint64_t value)
{
    uint64_t result = 0U;
    uint64_t bit = UINT64_C(1) << 62;
    while (bit > value) bit >>= 2;
    while (bit != 0U) {
        if (value >= result + bit) {
            value -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    return result;
}

static int64_t div_round_i64(int64_t numerator, int64_t denominator)
{
    if (denominator <= 0) return 0;
    if (numerator >= 0) return (numerator + denominator / 2) / denominator;
    return -(((-numerator) + denominator / 2) / denominator);
}

static bool lock_status(void)
{
    return s_lock != NULL && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE;
}

static void unlock_status(void)
{
    (void)xSemaphoreGive(s_lock);
}

const char *ntp_peer_monitor_health_name(ntp_peer_health_t health)
{
    switch (health) {
    case NTP_PEER_HEALTH_DISABLED: return "DISABLED";
    case NTP_PEER_HEALTH_UNKNOWN: return "UNKNOWN";
    case NTP_PEER_HEALTH_HEALTHY: return "HEALTHY";
    case NTP_PEER_HEALTH_WARNING: return "WARNING";
    case NTP_PEER_HEALTH_CRITICAL: return "CRITICAL";
    case NTP_PEER_HEALTH_DEGRADED: return "DEGRADED";
    case NTP_PEER_HEALTH_UNREACHABLE: return "UNREACHABLE";
    case NTP_PEER_HEALTH_DIVERGENT: return "DIVERGENT";
    case NTP_PEER_HEALTH_KOD: return "KOD";
    case NTP_PEER_HEALTH_INVALID: return "INVALID";
    default: return "UNKNOWN";
    }
}


/* Audit-only hysteresis: instantaneous telemetry is intentionally unchanged. */
#define PEER_AUDIT_CONFIRM_POLLS 3U
#define PEER_AUDIT_REPEAT_US (15LL * 60LL * 1000000LL)
typedef struct {
    ntp_peer_health_t committed;
    ntp_peer_health_t candidate;
    uint8_t candidate_count;
    int64_t last_emit_us;
    bool initialized;
} peer_audit_state_t;
static peer_audit_state_t s_peer_audit[APP_NTP_PEER_MAX_COUNT];

static void record_health_transition(size_t index, const char *server,
                                     ntp_peer_health_t old_health, ntp_peer_health_t new_health)
{
    if (index >= APP_NTP_PEER_MAX_COUNT) return;
    peer_audit_state_t *state = &s_peer_audit[index];
    if (!state->initialized) {
        state->initialized = true;
        state->committed = old_health;
        state->candidate = new_health;
        state->candidate_count = 0U;
    }
    if (new_health == NTP_PEER_HEALTH_DISABLED || new_health == NTP_PEER_HEALTH_UNKNOWN) {
        state->committed = new_health;
        state->candidate = new_health;
        state->candidate_count = 0U;
        return;
    }
    if (new_health == state->committed) {
        state->candidate_count = 0U;
        state->candidate = new_health;
        return;
    }
    if (new_health != state->candidate) {
        state->candidate = new_health;
        state->candidate_count = 1U;
    } else if (state->candidate_count < PEER_AUDIT_CONFIRM_POLLS) {
        state->candidate_count++;
    }
    /* Security-relevant invalid responses and KoD remain immediately auditable. */
    const bool urgent = new_health == NTP_PEER_HEALTH_KOD ||
                        new_health == NTP_PEER_HEALTH_INVALID;
    if (!urgent && state->candidate_count < PEER_AUDIT_CONFIRM_POLLS) return;
    const int64_t now = esp_timer_get_time();
    const bool rate_limited = state->last_emit_us > 0 && now >= state->last_emit_us &&
                              now - state->last_emit_us < PEER_AUDIT_REPEAT_US;
    const ntp_peer_health_t previous = state->committed;
    state->committed = new_health;
    state->candidate_count = 0U;
    if (previous == NTP_PEER_HEALTH_UNKNOWN || previous == NTP_PEER_HEALTH_DISABLED || rate_limited) return;
    char detail[OPERATIONS_EVENT_DETAIL_MAX + 1U];
    (void)snprintf(detail, sizeof(detail), "redundant_peer:%.32s:%s", server,
                   ntp_peer_monitor_health_name(new_health));
    const operations_event_type_t type = new_health == NTP_PEER_HEALTH_HEALTHY
                                             ? OPERATIONS_EVENT_RECOVERY : OPERATIONS_EVENT_FAULT;
    (void)operations_history_record(type, (int32_t)new_health, detail);
    state->last_emit_us = now;
}
static void reference_id_to_text(const uint8_t *packet, uint8_t stratum, char out[9])
{
    if (stratum <= 1U) {
        for (size_t i = 0; i < 4U; ++i) {
            const uint8_t c = packet[12U + i];
            /* This text is embedded unescaped in the status JSON, so keep
             * to characters that can never break it ('"' or '\\' from one
             * odd upstream reply would take the whole dashboard down). */
            const bool safe = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                              (c >= 'a' && c <= 'z') || c == ' ' || c == '.' ||
                              c == '-' || c == '_';
            out[i] = safe ? (char)c : '.';
        }
        out[4] = '\0';
        return;
    }
    (void)snprintf(out, 9U, "%08" PRIX32, read_be32(packet + 12U));
}

static void reset_peer_slot(size_t index, bool configured, const char *server)
{
    memset(&s_runtime[index], 0, sizeof(s_runtime[index]));
    memset(&s_peer_audit[index], 0, sizeof(s_peer_audit[index]));
    s_runtime[index].config_valid = true;
    s_runtime[index].enabled = configured;
    if (server != NULL) {
        (void)snprintf(s_runtime[index].server, sizeof(s_runtime[index].server), "%s", server);
    }

    if (!lock_status()) return;
    memset(&s_status.peers[index], 0, sizeof(s_status.peers[index]));
    s_status.peers[index].configured = configured;
    s_status.peers[index].health = configured ? NTP_PEER_HEALTH_UNKNOWN : NTP_PEER_HEALTH_DISABLED;
    if (server != NULL) {
        (void)snprintf(s_status.peers[index].server, sizeof(s_status.peers[index].server), "%s", server);
    }
    unlock_status();
}

static bool sync_config(const device_config_snapshot_t *config)
{
    bool changed = false;
    uint32_t configured_count = 0U;

    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        const bool configured = config->ntp_peers[i].enabled && config->ntp_peers[i].server[0] != '\0';
        if (configured && i < APP_NTP_GENERAL_PEER_COUNT) configured_count++;
        if (!s_runtime[i].config_valid || s_runtime[i].enabled != configured ||
            strcmp(s_runtime[i].server, config->ntp_peers[i].server) != 0) {
            reset_peer_slot(i, configured, config->ntp_peers[i].server);
            changed = true;
        }
    }

    if (lock_status()) {
        if (s_status.enabled != config->ntp_peer_monitor_enabled ||
            s_status.poll_interval_seconds != config->ntp_peer_poll_interval_seconds ||
            s_status.response_timeout_ms != config->ntp_peer_response_timeout_ms) changed = true;
        s_status.enabled = config->ntp_peer_monitor_enabled;
        s_status.poll_interval_seconds = config->ntp_peer_poll_interval_seconds;
        s_status.response_timeout_ms = config->ntp_peer_response_timeout_ms;
        s_status.configured_peers = configured_count;
        unlock_status();
    }
    return changed;
}

static bool resolve_peer(const char *server, struct sockaddr_in *out_addr)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *result = NULL;
    const int rc = getaddrinfo(server, "123", &hints, &result);
    if (rc != 0 || result == NULL) {
        if (result != NULL) freeaddrinfo(result);
        return false;
    }
    memcpy(out_addr, result->ai_addr, sizeof(*out_addr));
    out_addr->sin_port = htons(NTP_PORT);
    freeaddrinfo(result);
    return true;
}

static void update_failure(size_t index, ntp_peer_health_t requested,
                           bool timeout, bool dns, bool rejected, bool duplicate)
{
    if (!lock_status()) return;
    ntp_peer_status_t *peer = &s_status.peers[index];
    const ntp_peer_health_t old_health = peer->health;
    peer->reachability = (uint8_t)(peer->reachability << 1);
    peer->failed_polls++;
    peer->consecutive_failures++;
    if (timeout) peer->timeout_failures++;
    if (dns) peer->dns_failures++;
    if (rejected) peer->rejected_responses++;
    if (duplicate) peer->duplicate_responses++;
    if (requested == NTP_PEER_HEALTH_KOD || requested == NTP_PEER_HEALTH_INVALID) {
        peer->health = requested;
    } else if (peer->consecutive_failures >= NTP_PEER_UNREACHABLE_FAILURES) {
        peer->health = NTP_PEER_HEALTH_UNREACHABLE;
    } else {
        peer->health = NTP_PEER_HEALTH_DEGRADED;
    }
    const ntp_peer_health_t new_health = peer->health;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U]; (void)snprintf(server, sizeof(server), "%s", peer->server);
    unlock_status();
    record_health_transition(index, server, old_health, new_health);
}

static void compute_rolling_stats(size_t index, ntp_peer_status_t *peer)
{
    peer_runtime_t *rt = &s_runtime[index];
    if (rt->count == 0U) return;

    int64_t min_offset = rt->offset[0];
    int64_t max_offset = rt->offset[0];
    int64_t min_delay = rt->delay[0];
    int64_t offset_sum = 0;
    int64_t delay_sum = 0;
    uint64_t offset_sq_sum = 0U;
    uint64_t diff_sq_sum = 0U;

    for (uint32_t i = 0; i < rt->count; ++i) {
        const int64_t o = rt->offset[i];
        const int64_t d = rt->delay[i];
        offset_sum += o;
        delay_sum += d;
        if (o < min_offset) min_offset = o;
        if (o > max_offset) max_offset = o;
        if (d < min_delay) min_delay = d;

        const uint64_t ao = (uint64_t)abs_i64(o);
        const uint64_t osq = (ao != 0U && ao > UINT64_MAX / ao) ? UINT64_MAX : ao * ao;
        offset_sq_sum = UINT64_MAX - offset_sq_sum < osq ? UINT64_MAX : offset_sq_sum + osq;

        if (i > 0U) {
            const int64_t diff = o - rt->offset[i - 1U];
            const uint64_t ad = (uint64_t)abs_i64(diff);
            const uint64_t dsq = (ad != 0U && ad > UINT64_MAX / ad) ? UINT64_MAX : ad * ad;
            diff_sq_sum = UINT64_MAX - diff_sq_sum < dsq ? UINT64_MAX : diff_sq_sum + dsq;
        }
    }

    const int64_t n = (int64_t)rt->count;
    peer->rolling_samples = rt->count;
    peer->min_offset_ns = min_offset;
    peer->max_offset_ns = max_offset;
    peer->mean_offset_ns = div_round_i64(offset_sum, n);
    peer->rms_offset_ns = (int64_t)isqrt_u64(offset_sq_sum / (uint64_t)rt->count);
    peer->min_delay_ns = min_delay;
    peer->mean_delay_ns = div_round_i64(delay_sum, n);
    peer->jitter_ns = rt->count > 1U
                          ? (int64_t)isqrt_u64(diff_sq_sum / (uint64_t)(rt->count - 1U))
                          : 0;
}

static void update_success(size_t index, const uint8_t *packet, uint64_t server_t3,
                           int64_t offset_ns, int64_t delay_ns)
{
    peer_runtime_t *rt = &s_runtime[index];
    rt->offset[rt->next] = offset_ns;
    rt->delay[rt->next] = delay_ns;
    rt->next = (rt->next + 1U) % NTP_PEER_ROLLING_WINDOW;
    if (rt->count < NTP_PEER_ROLLING_WINDOW) rt->count++;

    /* Keep the rolling arrays in chronological order after wrap. */
    if (rt->count == NTP_PEER_ROLLING_WINDOW && rt->next != 0U) {
        int64_t ordered_offset[NTP_PEER_ROLLING_WINDOW];
        int64_t ordered_delay[NTP_PEER_ROLLING_WINDOW];
        for (uint32_t i = 0; i < NTP_PEER_ROLLING_WINDOW; ++i) {
            const uint32_t src = (rt->next + i) % NTP_PEER_ROLLING_WINDOW;
            ordered_offset[i] = rt->offset[src];
            ordered_delay[i] = rt->delay[src];
        }
        memcpy(rt->offset, ordered_offset, sizeof(ordered_offset));
        memcpy(rt->delay, ordered_delay, sizeof(ordered_delay));
        rt->next = 0U;
    }

    rt->last_server_t3 = server_t3;
    rt->last_server_t3_valid = true;
    rt->last_success_us = esp_timer_get_time();

    if (!lock_status()) return;
    ntp_peer_status_t *peer = &s_status.peers[index];
    const ntp_peer_health_t old_health = peer->health;
    peer->reachability = (uint8_t)((peer->reachability << 1) | 1U);
    peer->successful_polls++;
    peer->consecutive_failures = 0U;
    peer->samples++;
    peer->stratum = packet[1];
    peer->leap = (uint8_t)(packet[0] >> 6);
    peer->root_delay_16_16 = (int32_t)read_be32(packet + 4U);
    peer->root_dispersion_16_16 = read_be32(packet + 8U);
    reference_id_to_text(packet, peer->stratum, peer->reference_id);
    peer->offset_ns = offset_ns;
    peer->delay_ns = delay_ns;
    peer->last_success_age_seconds = 0U;
    compute_rolling_stats(index, peer);
    device_config_snapshot_t cfg;
    const bool cfg_ok = device_config_get_snapshot(&cfg) == ESP_OK;
    const int64_t abs_offset = abs_i64(offset_ns);
    if (index == APP_REDUNDANT_PEER_INDEX && cfg_ok && abs_offset >= (int64_t)cfg.redundant_peer_critical_ns)
        peer->health = NTP_PEER_HEALTH_CRITICAL;
    else if (index == APP_REDUNDANT_PEER_INDEX && cfg_ok && abs_offset >= (int64_t)cfg.redundant_peer_warning_ns)
        peer->health = NTP_PEER_HEALTH_WARNING;
    else if (delay_ns > NTP_PEER_DEGRADED_DELAY_NS || peer->jitter_ns > NTP_PEER_DEGRADED_JITTER_NS)
        peer->health = NTP_PEER_HEALTH_DEGRADED;
    else
        peer->health = NTP_PEER_HEALTH_HEALTHY;
    const ntp_peer_health_t new_health = peer->health;
    char server[APP_NTP_PEER_SERVER_MAX_LENGTH + 1U]; (void)snprintf(server, sizeof(server), "%s", peer->server);
    unlock_status();
    record_health_transition(index, server, old_health, new_health);
}

static bool begin_poll(size_t index, const device_config_ntp_peer_t *config,
                       uint32_t timeout_ms, poll_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->sock = -1;
    if (!resolve_peer(config->server, &ctx->address)) {
        ESP_LOGW(TAG, "Peer %u DNS resolution failed", (unsigned)index);
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, true, false, false);
        return false;
    }
    if (lock_status()) {
        (void)inet_ntop(AF_INET, &ctx->address.sin_addr, s_status.peers[index].resolved_address, sizeof(s_status.peers[index].resolved_address));
        unlock_status();
    }

    ctx->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->sock < 0) {
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
        return false;
    }

    uint8_t request[NTP_PACKET_SIZE] = {0};
    request[0] = (uint8_t)((NTP_VERSION << 3) | NTP_MODE_CLIENT);
    ctx->local_time_valid = clock_discipline_get_ntp_timestamp(&ctx->t1);
    if (!ctx->local_time_valid) {
        /* Originate nonce only: no clock offset may be inferred from it.
         * Allows peer reachability and remote LI/stratum monitoring with no GNSS. */
        const uint64_t nonce = (uint64_t)esp_timer_get_time();
        ctx->t1.seconds = (uint32_t)(nonce >> 32) ^ 0xA53D127BU;
        ctx->t1.fraction = (uint32_t)nonce ^ 0x6B8294E1U;
    }
    write_be32(request + 40U, ctx->t1.seconds);
    write_be32(request + 44U, ctx->t1.fraction);

    const ssize_t sent = sendto(ctx->sock, request, sizeof(request), 0,
                                (const struct sockaddr *)&ctx->address, sizeof(ctx->address));
    if (sent != (ssize_t)sizeof(request)) {
        close(ctx->sock);
        ctx->sock = -1;
        update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
        return false;
    }

    /* The ephemeral port lwIP bound at sendto() keys the hardware stamps. */
    struct sockaddr_in local = {0};
    socklen_t local_len = sizeof(local);
    if (getsockname(ctx->sock, (struct sockaddr *)&local, &local_len) == 0) {
        ctx->local_port = ntohs(local.sin_port);
    }

    ctx->active = true;
    ctx->deadline_us = esp_timer_get_time() + (int64_t)timeout_ms * 1000LL;
    return true;
}

static void finish_context(poll_context_t *ctx)
{
    if (ctx->sock >= 0) close(ctx->sock);
    ctx->sock = -1;
    ctx->active = false;
    ctx->completed = true;
}

static void process_response(size_t index, poll_context_t *ctx)
{
    uint8_t response[256];
    struct sockaddr_in source = {0};
    socklen_t source_len = sizeof(source);
    const ssize_t received = recvfrom(ctx->sock, response, sizeof(response), 0,
                                      (struct sockaddr *)&source, &source_len);
    clock_ntp_timestamp_t t4;
    const bool t4_valid = clock_discipline_get_ntp_timestamp(&t4);

    if (received < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            update_failure(index, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
            finish_context(ctx);
        }
        return;
    }
    finish_context(ctx);

    if (received < (ssize_t)NTP_PACKET_SIZE ||
        source.sin_addr.s_addr != ctx->address.sin_addr.s_addr ||
        source.sin_port != ctx->address.sin_port) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }

    const uint8_t li = response[0] >> 6;
    const uint8_t version = (response[0] >> 3) & 0x07U;
    const uint8_t mode = response[0] & 0x07U;
    const uint8_t stratum = response[1];

    if (version < 3U || mode != NTP_MODE_SERVER ||
        read_be32(response + 24U) != ctx->t1.seconds ||
        read_be32(response + 28U) != ctx->t1.fraction) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }

    if (li == 3U && stratum != 0U) {
        /* The remote endpoint responded but explicitly reports unsynchronised. */
        if (lock_status()) {
            ntp_peer_status_t *peer = &s_status.peers[index];
            peer->reachability = (uint8_t)((peer->reachability << 1) | 1U);
            peer->successful_polls++;
            peer->consecutive_failures = 0U;
            peer->leap = li;
            peer->stratum = stratum;
            reference_id_to_text(response, stratum, peer->reference_id);
            peer->health = NTP_PEER_HEALTH_DEGRADED;
            peer->last_success_age_seconds = 0U;
            s_runtime[index].last_success_us = esp_timer_get_time();
            unlock_status();
        }
        return;
    }

    if (stratum == 0U) {
        char kod[9] = {0};
        reference_id_to_text(response, 0U, kod);
        if (lock_status()) {
            s_status.peers[index].kod_responses++;
            (void)snprintf(s_status.peers[index].reference_id,
                           sizeof(s_status.peers[index].reference_id), "%s", kod);
            unlock_status();
        }
        /* KoD is not a normal peer failure. RATE must suppress traffic to
         * this peer; DENY/RSTR must not be retried until configuration changes.
         * Other peers continue at their configured monitoring interval. */
        if (strcmp(kod, "RATE") == 0) {
            s_runtime[index].kod_suppress_until_us = esp_timer_get_time() + INT64_C(1024) * 1000000;
        } else if (strcmp(kod, "DENY") == 0 || strcmp(kod, "RSTR") == 0) {
            s_runtime[index].kod_suppress_until_us = INT64_MAX;
        }
        ESP_LOGW(TAG, "Peer %u returned KoD %.4s", (unsigned)index, kod);
        update_failure(index, NTP_PEER_HEALTH_KOD, false, false, true, false);
        return;
    }

    if (version < 3U || mode != NTP_MODE_SERVER || li == 3U || stratum > 15U ||
        read_be32(response + 24U) != ctx->t1.seconds ||
        read_be32(response + 28U) != ctx->t1.fraction ||
        (read_be32(response + 32U) == 0U && read_be32(response + 36U) == 0U) ||
        (read_be32(response + 40U) == 0U && read_be32(response + 44U) == 0U)) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
        return;
    }

    if (!ctx->local_time_valid || !t4_valid) {
        /* Reachable, synchronized peer; local GNSS is unavailable, so no
         * meaningful offset/delay sample can be calculated. */
        if (lock_status()) {
            ntp_peer_status_t *peer = &s_status.peers[index];
            peer->reachability = (uint8_t)((peer->reachability << 1) | 1U);
            peer->successful_polls++;
            peer->consecutive_failures = 0U;
            peer->leap = li;
            peer->stratum = stratum;
            reference_id_to_text(response, stratum, peer->reference_id);
            peer->health = NTP_PEER_HEALTH_UNKNOWN;
            peer->last_success_age_seconds = 0U;
            s_runtime[index].last_success_us = esp_timer_get_time();
            unlock_status();
        }
        return;
    }

    uint64_t f1 = timestamp_to_fixed(ctx->t1);
    const uint64_t f2 = ((uint64_t)read_be32(response + 32U) << 32) | read_be32(response + 36U);
    const uint64_t f3 = ((uint64_t)read_be32(response + 40U) << 32) | read_be32(response + 44U);
    uint64_t f4 = timestamp_to_fixed(t4);

    /* Prefer the EMAC's wire times. T1 is read before sendto() and T4 after
     * the task wakes from select(), so software stamps carry each path's
     * stack latency; the receive side is much slower, which biased offsets
     * by about -90 us. A hardware stamp must fall just after the software
     * T1 and just before the software T4, or it belongs to something else. */
    bool hw_stamped = false;
    uint64_t hw_t1_ns = 0U;
    uint64_t hw_t4_ns = 0U;
    if (ctx->local_port != 0U &&
        eth_service_take_peer_timestamps(ctx->address.sin_addr.s_addr, ctx->local_port,
                                         &hw_t1_ns, &hw_t4_ns)) {
        const uint64_t h1 = ns_to_fixed(hw_t1_ns);
        const uint64_t h4 = ns_to_fixed(hw_t4_ns);
        const int64_t t1_lag_ns = fixed_delta_ns(h1, f1);
        const int64_t t4_lead_ns = fixed_delta_ns(f4, h4);
        if (t1_lag_ns >= -PEER_HW_STAMP_TOLERANCE_NS && t1_lag_ns <= PEER_HW_STAMP_MAX_SKEW_NS &&
            t4_lead_ns >= -PEER_HW_STAMP_TOLERANCE_NS && t4_lead_ns <= PEER_HW_STAMP_MAX_SKEW_NS &&
            fixed_delta_ns(h4, h1) > 0) {
            f1 = h1;
            f4 = h4;
            hw_stamped = true;
        }
    }

    if (s_runtime[index].last_server_t3_valid && s_runtime[index].last_server_t3 == f3) {
        update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, true);
        return;
    }

    const int64_t a = fixed_delta_ns(f2, f1);
    const int64_t b = fixed_delta_ns(f3, f4);
    const int64_t offset_ns = (a / 2) + (b / 2) + ((a % 2) + (b % 2)) / 2;
    int64_t delay_ns = fixed_delta_ns(f4, f1) - fixed_delta_ns(f3, f2);
    /* On a LAN the true delay is only microseconds, so the peer's own
     * timestamp error (e.g. a booting server's TX compensation still
     * converging) can make it slightly negative. Treat that as zero, as
     * RFC 5905 does by flooring delay at the precision; a large negative
     * delay still means an inconsistent reply. */
    if (delay_ns < 0) {
        if (delay_ns < -PEER_NEGATIVE_DELAY_TOLERANCE_NS) {
            update_failure(index, NTP_PEER_HEALTH_INVALID, false, false, true, false);
            return;
        }
        delay_ns = 0;
    }
    update_success(index, response, f3, offset_ns, delay_ns);
    if (hw_stamped && lock_status()) {
        s_status.peers[index].hw_timestamped_samples++;
        unlock_status();
    }
}

static void poll_all_peers(const device_config_snapshot_t *config)
{
    /* Phase-8 invariant: peer observation is deliberately sequential.  At
     * most one peer-monitor UDP socket may exist at any time.  Slots 0..2 are
     * general observation peers; slot 3 is the dedicated redundant server. */
    for (size_t i = 0; i < APP_NTP_PEER_MAX_COUNT; ++i) {
        const bool slot_active = (i == APP_REDUNDANT_PEER_INDEX) || config->ntp_peer_monitor_enabled;
        if (!slot_active || !config->ntp_peers[i].enabled || config->ntp_peers[i].server[0] == '\0') continue;
        /* Only a peer's explicit KoD can suppress its requests. */
        const int64_t suppress_until = s_runtime[i].kod_suppress_until_us;
        if (suppress_until != 0 && esp_timer_get_time() < suppress_until) continue;
        if (suppress_until != 0) s_runtime[i].kod_suppress_until_us = 0;

        poll_context_t context;
        memset(&context, 0, sizeof(context));
        context.sock = -1;
        if (!begin_poll(i, &config->ntp_peers[i], config->ntp_peer_response_timeout_ms, &context)) continue;

        while (context.active) {
            const int64_t now_us = esp_timer_get_time();
            if (now_us >= context.deadline_us) {
                update_failure(i, NTP_PEER_HEALTH_DEGRADED, true, false, false, false);
                finish_context(&context);
                break;
            }
            int64_t wait_us = context.deadline_us - now_us;
            struct timeval tv = {
                .tv_sec = (time_t)(wait_us / 1000000LL),
                .tv_usec = (suseconds_t)(wait_us % 1000000LL),
            };
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(context.sock, &readfds);
            const int rc = select(context.sock + 1, &readfds, NULL, NULL, &tv);
            if (rc < 0) {
                if (errno == EINTR) continue;
                update_failure(i, NTP_PEER_HEALTH_DEGRADED, false, false, false, false);
                finish_context(&context);
                break;
            }
            if (rc == 0) continue;
            if (FD_ISSET(context.sock, &readfds)) process_response(i, &context);
        }
    }
}

static void refresh_aggregate_health(void)
{
    if (!lock_status()) return;
    int64_t min_offset = 0;
    int64_t max_offset = 0;
    bool have_offset = false;
    uint32_t sampled = 0U;
    uint32_t healthy = 0U;
    const int64_t now_us = esp_timer_get_time();

    s_status.best_observed_peer_valid = false;
    s_status.best_observed_peer_index = 0U;
    int64_t best_score = INT64_MAX;

    for (size_t i = 0; i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
        ntp_peer_status_t *peer = &s_status.peers[i];
        if (!peer->configured) continue;
        if (s_runtime[i].last_success_us > 0) {
            const int64_t age_us = now_us - s_runtime[i].last_success_us;
            peer->last_success_age_seconds = age_us > 0 ? (uint32_t)(age_us / 1000000LL) : 0U;
        }
        if (peer->samples == 0U || peer->health == NTP_PEER_HEALTH_UNREACHABLE ||
            peer->health == NTP_PEER_HEALTH_KOD || peer->health == NTP_PEER_HEALTH_INVALID) continue;

        sampled++;
        if (!have_offset) {
            min_offset = max_offset = peer->offset_ns;
            have_offset = true;
        } else {
            if (peer->offset_ns < min_offset) min_offset = peer->offset_ns;
            if (peer->offset_ns > max_offset) max_offset = peer->offset_ns;
        }

        /* Telemetry-only observation score: |offset| + jitter + delay/4. */
        const int64_t offset_score = abs_i64(peer->offset_ns);
        const int64_t jitter_score = abs_i64(peer->jitter_ns);
        const int64_t delay_score = peer->delay_ns > 0 ? peer->delay_ns / 4 : 0;
        int64_t score = offset_score;
        score = score > INT64_MAX - jitter_score ? INT64_MAX : score + jitter_score;
        score = score > INT64_MAX - delay_score ? INT64_MAX : score + delay_score;
        if (!s_status.best_observed_peer_valid || score < best_score) {
            best_score = score;
            s_status.best_observed_peer_valid = true;
            s_status.best_observed_peer_index = (uint32_t)i;
        }
    }

    s_status.cross_peer_spread_valid = sampled >= 2U;
    s_status.cross_peer_spread_ns = sampled >= 2U ? max_offset - min_offset : 0;
    if (s_status.cross_peer_spread_valid && s_status.cross_peer_spread_ns > NTP_PEER_DIVERGENT_NS) {
        for (size_t i = 0; i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
            ntp_peer_status_t *peer = &s_status.peers[i];
            if (peer->configured && peer->samples > 0U &&
                peer->health != NTP_PEER_HEALTH_UNREACHABLE &&
                peer->health != NTP_PEER_HEALTH_KOD &&
                peer->health != NTP_PEER_HEALTH_INVALID) {
                peer->health = NTP_PEER_HEALTH_DIVERGENT;
            }
        }
    }
    for (size_t i = 0; i < APP_NTP_GENERAL_PEER_COUNT; ++i) {
        if (s_status.peers[i].health == NTP_PEER_HEALTH_HEALTHY) healthy++;
    }
    s_status.healthy_peers = healthy;
    ntp_peer_status_t *redundant = &s_status.peers[APP_REDUNDANT_PEER_INDEX];
    if (redundant->configured && s_runtime[APP_REDUNDANT_PEER_INDEX].last_success_us > 0) {
        const int64_t age_us = now_us - s_runtime[APP_REDUNDANT_PEER_INDEX].last_success_us;
        redundant->last_success_age_seconds = age_us > 0 ? (uint32_t)(age_us / 1000000LL) : 0U;
    }
    unlock_status();
}

static void monitor_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(NTP_PEER_START_DELAY_MS));

    for (;;) {
        device_config_snapshot_t config;
        if (device_config_get_snapshot(&config) != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(NTP_PEER_CONFIG_CHECK_MS));
            continue;
        }
        (void)sync_config(&config);

        if (config.ntp_peer_monitor_enabled || config.ntp_peers[APP_REDUNDANT_PEER_INDEX].enabled) {
            poll_all_peers(&config);
            if (lock_status()) {
                s_status.poll_cycles++;
                unlock_status();
            }
            refresh_aggregate_health();
        } else {
            refresh_aggregate_health();
        }

        const uint32_t interval = config.ntp_peer_poll_interval_seconds >= APP_NTP_PEER_POLL_MIN_SECONDS
                                      ? config.ntp_peer_poll_interval_seconds
                                      : APP_NTP_PEER_POLL_DEFAULT_SECONDS;
        uint32_t waited_ms = 0U;
        const bool any_monitor_enabled = config.ntp_peer_monitor_enabled || config.ntp_peers[APP_REDUNDANT_PEER_INDEX].enabled;
        const uint32_t target_ms = any_monitor_enabled ? interval * 1000U : NTP_PEER_CONFIG_CHECK_MS;
        while (waited_ms < target_ms) {
            const uint32_t slice = (target_ms - waited_ms) > NTP_PEER_CONFIG_CHECK_MS
                                       ? NTP_PEER_CONFIG_CHECK_MS : (target_ms - waited_ms);
            vTaskDelay(pdMS_TO_TICKS(slice));
            waited_ms += slice;

            device_config_snapshot_t latest;
            if (device_config_get_snapshot(&latest) == ESP_OK && sync_config(&latest)) break;
        }
    }
}

esp_err_t ntp_peer_monitor_start(void)
{
    if (s_running) return ESP_OK;
    if (!s_initialized) {
        s_lock = xSemaphoreCreateMutex();
        if (s_lock == NULL) return ESP_ERR_NO_MEM;
        memset(&s_status, 0, sizeof(s_status));
        memset(s_runtime, 0, sizeof(s_runtime));
        s_status.initialized = true;
        s_initialized = true;
    }
    if (xTaskCreate(monitor_task, "ntp_peer", NTP_PEER_TASK_STACK_SIZE, NULL,
                    NTP_PEER_TASK_PRIORITY, &s_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    s_running = true;
    if (lock_status()) {
        s_status.running = true;
        unlock_status();
    }
    ESP_LOGI(TAG, "Independent NTP peer monitor started (telemetry-only; no timing authority)");
    return ESP_OK;
}

bool ntp_peer_monitor_is_running(void)
{
    return s_running;
}

bool ntp_peer_monitor_get_status(ntp_peer_monitor_status_t *out_status)
{
    if (out_status == NULL || !s_initialized || !lock_status()) return false;
    *out_status = s_status;
    unlock_status();
    return true;
}

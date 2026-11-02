/* Project-local, observation-only EMAC RX instrumentation. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_eth_mac.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t rx_irq;
    uint32_t rx_poll_timeout; /* B6B: timeout checks in RX task, not interrupts */
    uint32_t rx_wakeup;
    uint32_t rx_frame;
    uint32_t rx_alloc_fail;
    uint32_t rx_copy_fail;
    uint32_t rx_truncated;
    uint32_t rx_callback_attempt;
    uint32_t rx_frames_remain;
    uint32_t rx_desc_free;
} esp_eth_rx_diag_t;
/* Stage B4: read-only ESP32-P4 EMAC register snapshot. No W1C reads/writes. */
typedef struct {
    /* TS2_B6D: read-only MAC debug snapshot, no descriptor reads. */
    uint32_t mac_debug;
    uint32_t tx_frame_ctrl_state;
    uint32_t rx_fifo_read_state;
    uint32_t mac_config;
    uint32_t dma_status;
    uint32_t dma_operation_mode;
    uint32_t dma_interrupt_enable;
    uint32_t rx_descriptor_list;
    uint32_t rx_current_descriptor;
    uint32_t rx_current_buffer;
} esp_eth_rx_hw_diag_t;

/* Live MAC instance required; diagnostic task context only. */
bool esp_eth_rx_hw_diag_snapshot(esp_eth_mac_t *mac, esp_eth_rx_hw_diag_t *out);
/* Reads software counters only. MAC must be a live ESP32 EMAC instance. */
bool esp_eth_rx_diag_snapshot(esp_eth_mac_t *mac, esp_eth_rx_diag_t *out);
#ifdef __cplusplus
}
#endif

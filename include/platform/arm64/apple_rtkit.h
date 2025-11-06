/* apple_rtkit.h - Apple RTKit IPC Protocol
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * RTKit (Real-Time Kit) is Apple's RTOS running on co-processors.
 * Provides mailbox-based IPC for NVMe, GPU, DCP, and other subsystems.
 * Based on Linux kernel implementation by Sven Peter (Asahi Linux).
 */

#ifndef __FUTURA_ARM64_APPLE_RTKIT_H__
#define __FUTURA_ARM64_APPLE_RTKIT_H__

#include <stdint.h>
#include <stdbool.h>

/* ============================================================
 *   RTKit Message Format (64-bit)
 * ============================================================ */

/* Message type is encoded in bits [59:52] */
#define APPLE_RTKIT_MSG_TYPE_SHIFT      52
#define APPLE_RTKIT_MSG_TYPE_MASK       0xFF
#define APPLE_RTKIT_MSG_TYPE(msg)       (((msg) >> APPLE_RTKIT_MSG_TYPE_SHIFT) & APPLE_RTKIT_MSG_TYPE_MASK)

/* Message payload is in lower bits [51:0] */
#define APPLE_RTKIT_MSG_PAYLOAD_MASK    0x000FFFFFFFFFFFFFULL

/* ============================================================
 *   RTKit Management Messages (Endpoint 0)
 * ============================================================ */

/* Management message types */
#define APPLE_RTKIT_MGMT_MSG_HELLO              0x01
#define APPLE_RTKIT_MGMT_MSG_HELLO_REPLY        0x02
#define APPLE_RTKIT_MGMT_MSG_STARTEP            0x05
#define APPLE_RTKIT_MGMT_MSG_STARTEP_ACK        0x06
#define APPLE_RTKIT_MGMT_MSG_EPMAP              0x08
#define APPLE_RTKIT_MGMT_MSG_EPMAP_REPLY        0x09
#define APPLE_RTKIT_MGMT_MSG_IOP_PWR_STATE      0x0A
#define APPLE_RTKIT_MGMT_MSG_IOP_PWR_ACK        0x0B
#define APPLE_RTKIT_MGMT_MSG_AP_PWR_STATE       0x0C
#define APPLE_RTKIT_MGMT_MSG_AP_PWR_ACK         0x0D

/* ============================================================
 *   RTKit Endpoints
 * ============================================================ */

/* System endpoints (0-31) */
#define APPLE_RTKIT_EP_MGMT         0x00    /* Management */
#define APPLE_RTKIT_EP_CRASHLOG     0x01    /* Crash logging */
#define APPLE_RTKIT_EP_SYSLOG       0x02    /* System logging */
#define APPLE_RTKIT_EP_DEBUG        0x03    /* Debug */
#define APPLE_RTKIT_EP_IOREPORT     0x04    /* I/O reporting */
#define APPLE_RTKIT_EP_OSLOG        0x08    /* OS logging */

/* Application endpoints start at 0x20 */
#define APPLE_RTKIT_EP_APP_START    0x20
#define APPLE_RTKIT_EP_APP_END      0xFF

/* Maximum number of endpoints */
#define APPLE_RTKIT_MAX_ENDPOINTS   256

/* ============================================================
 *   RTKit Protocol Version
 * ============================================================ */

#define APPLE_RTKIT_MIN_VERSION     11
#define APPLE_RTKIT_MAX_VERSION     12

/* ============================================================
 *   RTKit Power States
 * ============================================================ */

#define APPLE_RTKIT_PWR_STATE_OFF       0x00
#define APPLE_RTKIT_PWR_STATE_SLEEP     0x01
#define APPLE_RTKIT_PWR_STATE_QUIESCED  0x10
#define APPLE_RTKIT_PWR_STATE_ON        0x20

/* ============================================================
 *   RTKit Context Structure
 * ============================================================ */

typedef struct apple_rtkit_ctx apple_rtkit_ctx_t;

/* RTKit message handler callback */
typedef void (*apple_rtkit_msg_handler_t)(void *cookie, uint8_t endpoint, uint64_t msg);

/* RTKit endpoint descriptor */
typedef struct {
    uint8_t endpoint;
    bool started;
    apple_rtkit_msg_handler_t handler;
    void *cookie;
} apple_rtkit_endpoint_t;

/* RTKit mailbox context */
struct apple_rtkit_ctx {
    /* Mailbox MMIO base */
    volatile uint8_t *mailbox_base;
    uint64_t mailbox_phys;

    /* Protocol state */
    uint32_t version;
    bool initialized;
    uint8_t iop_power_state;
    uint8_t ap_power_state;

    /* Endpoint map */
    uint32_t endpoint_bitmap[8];   /* 256 bits for 256 endpoints */
    apple_rtkit_endpoint_t endpoints[APPLE_RTKIT_MAX_ENDPOINTS];

    /* Crashlog buffer (if provided by firmware) */
    uint64_t crashlog_addr;
    uint32_t crashlog_size;

    /* Syslog buffer (if provided by firmware) */
    uint64_t syslog_addr;
    uint32_t syslog_size;
};

/* ============================================================
 *   RTKit Mailbox Operations
 * ============================================================ */

/**
 * Initialize RTKit context.
 * Sets up mailbox communication with co-processor.
 * @param mailbox_base: Physical address of mailbox MMIO registers
 * @return: RTKit context, or NULL on failure
 */
apple_rtkit_ctx_t *apple_rtkit_init(uint64_t mailbox_base);

/**
 * Boot RTKit co-processor.
 * Performs HELLO handshake, endpoint discovery, and system endpoint startup.
 * @param ctx: RTKit context
 * @return: true on success, false on failure
 */
bool apple_rtkit_boot(apple_rtkit_ctx_t *ctx);

/**
 * Send a message to RTKit.
 * @param ctx: RTKit context
 * @param endpoint: Target endpoint (0-255)
 * @param msg: 64-bit message
 * @return: true on success, false on failure
 */
bool apple_rtkit_send_message(apple_rtkit_ctx_t *ctx, uint8_t endpoint, uint64_t msg);

/**
 * Receive a message from RTKit.
 * Non-blocking poll for incoming messages.
 * @param ctx: RTKit context
 * @param endpoint_out: Output endpoint number
 * @param msg_out: Output message
 * @return: true if message received, false if no message
 */
bool apple_rtkit_recv_message(apple_rtkit_ctx_t *ctx, uint8_t *endpoint_out, uint64_t *msg_out);

/**
 * Register an endpoint handler.
 * Callback is invoked when messages arrive for this endpoint.
 * @param ctx: RTKit context
 * @param endpoint: Endpoint number
 * @param handler: Message handler callback
 * @param cookie: User data passed to handler
 * @return: true on success, false on failure
 */
bool apple_rtkit_register_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint,
                                    apple_rtkit_msg_handler_t handler, void *cookie);

/**
 * Start an application endpoint.
 * Sends STARTEP message to RTKit.
 * @param ctx: RTKit context
 * @param endpoint: Endpoint number (0x20-0xFF)
 * @return: true on success, false on failure
 */
bool apple_rtkit_start_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint);

/**
 * Process pending RTKit messages.
 * Polls mailbox and dispatches to registered handlers.
 * @param ctx: RTKit context
 * @return: Number of messages processed
 */
int apple_rtkit_process_messages(apple_rtkit_ctx_t *ctx);

/**
 * Set AP power state.
 * Informs RTKit of application processor power state.
 * @param ctx: RTKit context
 * @param state: Power state (OFF/SLEEP/QUIESCED/ON)
 * @return: true on success, false on failure
 */
bool apple_rtkit_set_ap_power_state(apple_rtkit_ctx_t *ctx, uint8_t state);

/**
 * Set IOP power state.
 * Requests IO processor to transition to power state.
 * @param ctx: RTKit context
 * @param state: Power state (OFF/SLEEP/QUIESCED/ON)
 * @return: true on success, false on failure
 */
bool apple_rtkit_set_iop_power_state(apple_rtkit_ctx_t *ctx, uint8_t state);

/* ============================================================
 *   RTKit Message Construction Helpers
 * ============================================================ */

/**
 * Build RTKit message with type and payload.
 * @param type: Message type (8 bits)
 * @param payload: Message payload (52 bits)
 * @return: 64-bit message
 */
static inline uint64_t apple_rtkit_build_message(uint8_t type, uint64_t payload) {
    return ((uint64_t)type << APPLE_RTKIT_MSG_TYPE_SHIFT) | (payload & APPLE_RTKIT_MSG_PAYLOAD_MASK);
}

/**
 * Extract message payload.
 * @param msg: 64-bit message
 * @return: Payload (52 bits)
 */
static inline uint64_t apple_rtkit_get_payload(uint64_t msg) {
    return msg & APPLE_RTKIT_MSG_PAYLOAD_MASK;
}

/* ============================================================
 *   RTKit Shutdown
 * ============================================================ */

/**
 * Shutdown RTKit co-processor.
 * Transitions to OFF power state and frees resources.
 * @param ctx: RTKit context
 */
void apple_rtkit_shutdown(apple_rtkit_ctx_t *ctx);

#endif /* __FUTURA_ARM64_APPLE_RTKIT_H__ */

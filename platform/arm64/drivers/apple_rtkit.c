/* apple_rtkit.c - Apple RTKit IPC Protocol Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * RTKit mailbox-based IPC for Apple co-processors.
 * Simplified implementation based on Linux kernel driver (Asahi Linux).
 *
 * Key protocol steps:
 * 1. HELLO handshake (version negotiation)
 * 2. EPMAP discovery (endpoint enumeration)
 * 3. System endpoint startup (syslog, crashlog, etc.)
 * 4. Power state management
 */

#include <platform/arm64/apple_rtkit.h>
#include <platform/platform.h>
#include <kernel/fut_memory.h>
#include <string.h>

/* ============================================================
 *   Mailbox Register Offsets (Simplified)
 * ============================================================ */

/* Mailbox Register Layout (simplified model)
 *
 * Apple's RTKit mailbox has evolved across chip generations:
 * - M1/M2/M3: Proprietary mailbox at different base addresses per chip
 * - QEMU virt: Simulated mailbox (not present on real hardware)
 *
 * Current implementation uses generic register offsets that must be adjusted
 * per platform. These placeholders assume a simple FIFO mailbox model:
 *
 * Register Map:
 * +0x00: TX_DATA       - Write command to submit to co-processor
 * +0x04: TX_STATUS     - Status bits: bit 0 = TX_EMPTY (ready to send)
 * +0x08: RX_DATA       - Read response from co-processor
 * +0x0C: RX_STATUS     - Status bits: bit 0 = RX_FULL (data available)
 *
 * For Apple Silicon hardware, actual offsets must be determined from:
 * 1. Device tree: /dts-v1/ parsing for mailbox node
 * 2. Apple reference drivers: m1n1 bootloader source
 * 3. Asahi Linux kernel driver: linux/drivers/mailbox/apple-mailbox.c
 *
 * Phase 1 (Current): Use generic offsets for QEMU compatibility
 * Phase 2: Implement platform-specific offset tables for M1/M2/M3
 * Phase 3: Add runtime device tree parsing for offset discovery
 */

#define APPLE_MBOX_TX_DATA      0x00    /* Transmit data register (write command) */
#define APPLE_MBOX_TX_STATUS    0x04    /* Transmit status register */
#define APPLE_MBOX_RX_DATA      0x08    /* Receive data register (read response) */
#define APPLE_MBOX_RX_STATUS    0x0C    /* Receive status register */

/* Mailbox status flags */
#define APPLE_MBOX_TX_EMPTY     (1 << 0)    /* TX FIFO empty, ready to accept command */
#define APPLE_MBOX_RX_FULL      (1 << 0)    /* RX FIFO full, response available */

/* ============================================================
 *   Mailbox Register Access
 * ============================================================ */

#define MBOX_READ32(ctx, offset) \
    (*((volatile uint32_t *)((ctx)->mailbox_base + (offset))))

#define MBOX_WRITE32(ctx, offset, val) \
    (*((volatile uint32_t *)((ctx)->mailbox_base + (offset))) = (val))

#define MBOX_READ64(ctx, offset) \
    (*((volatile uint64_t *)((ctx)->mailbox_base + (offset))))

#define MBOX_WRITE64(ctx, offset, val) \
    (*((volatile uint64_t *)((ctx)->mailbox_base + (offset))) = (val))

/* ============================================================
 *   Endpoint Bitmap Management
 * ============================================================ */

static inline bool apple_rtkit_ep_is_valid(apple_rtkit_ctx_t *ctx, uint8_t ep) {
    uint32_t word = ep / 32;
    uint32_t bit = ep % 32;
    return (ctx->endpoint_bitmap[word] & (1U << bit)) != 0;
}

static inline void apple_rtkit_ep_set_valid(apple_rtkit_ctx_t *ctx, uint8_t ep) {
    uint32_t word = ep / 32;
    uint32_t bit = ep % 32;
    ctx->endpoint_bitmap[word] |= (1U << bit);
}

/* ============================================================
 *   Mailbox Send/Receive
 * ============================================================ */

bool apple_rtkit_send_message(apple_rtkit_ctx_t *ctx, uint8_t endpoint, uint64_t msg) {
    if (!ctx || !ctx->mailbox_base) {
        return false;
    }

    /* Wait for TX FIFO to have space
     * Status register bit 0 = TX_EMPTY (can accept new command)
     * Polling with timeout prevents infinite wait on stuck hardware
     */
    int timeout = 10000;
    int polls = 0;
    while (timeout-- > 0) {
        if (MBOX_READ32(ctx, APPLE_MBOX_TX_STATUS) & APPLE_MBOX_TX_EMPTY) {
            break;
        }
        polls++;
        /* Platform delay - should use nanosleep for production */
        for (volatile int i = 0; i < 100; i++);
    }

    if (timeout <= 0) {
        fut_printf("[RTKit] Error: TX timeout after %d polls (mailbox may be stuck)\n", polls);
        return false;
    }

    /* RTKit message format: endpoint in upper 8 bits, payload in lower 56 bits
     *
     * Message structure (64-bit):
     * [63:56] = endpoint (co-processor endpoint number, 0-255)
     * [55:0]  = payload (command, event, or response data)
     *
     * Example:
     * - HELLO request: ep=0x0 (mgmt), payload with version
     * - EPMAP request: ep=0x0 (mgmt), payload with bitmap offset
     * - Application IPC: ep=0x20 (ANS2), payload with command
     */
    uint64_t full_msg = ((uint64_t)endpoint << 56) | (msg & 0x00FFFFFFFFFFFFFFULL);

    /* Write message to mailbox TX register to submit command */
    MBOX_WRITE64(ctx, APPLE_MBOX_TX_DATA, full_msg);

    return true;
}

bool apple_rtkit_recv_message(apple_rtkit_ctx_t *ctx, uint8_t *endpoint_out, uint64_t *msg_out) {
    if (!ctx || !ctx->mailbox_base || !endpoint_out || !msg_out) {
        return false;
    }

    /* Check if RX FIFO has data
     * Status register bit 0 = RX_FULL (response available from co-processor)
     * Non-blocking check: returns false if no message waiting (caller can poll later)
     */
    if (!(MBOX_READ32(ctx, APPLE_MBOX_RX_STATUS) & APPLE_MBOX_RX_FULL)) {
        return false;  /* No message available yet */
    }

    /* Read 64-bit message from mailbox RX register
     * This dequeues one message from co-processor's response queue
     * Message format: endpoint in upper 8 bits, payload in lower 56 bits
     */
    uint64_t full_msg = MBOX_READ64(ctx, APPLE_MBOX_RX_DATA);

    /* RTKit message format: Extract endpoint and message
     *
     * Message structure (64-bit):
     * [63:56] = endpoint (identifies which co-processor endpoint sent response)
     * [55:0]  = payload (response data, acknowledgment, or event notification)
     *
     * Example responses:
     * - HELLO_REPLY: ep=0x0 (mgmt), payload with negotiated version
     * - EPMAP_REPLY: ep=0x0 (mgmt), payload with endpoint bitmap
     * - ANS2 Response: ep=0x20 (ANS), payload with command result
     * - Interrupt: ep=0x20 (ANS), payload with notification/error
     */
    *endpoint_out = (uint8_t)(full_msg >> 56);
    *msg_out = full_msg & 0x00FFFFFFFFFFFFFFULL;

    return true;
}

/* ============================================================
 *   Management Message Handlers
 * ============================================================ */

static void apple_rtkit_handle_hello_reply(apple_rtkit_ctx_t *ctx, uint64_t msg) {
    uint32_t version = (uint32_t)(msg >> 32) & 0xFFFF;

    if (version < APPLE_RTKIT_MIN_VERSION || version > APPLE_RTKIT_MAX_VERSION) {
        fut_printf("[RTKit] Error: Unsupported version %u\n", version);
        return;
    }

    ctx->version = version;
    fut_printf("[RTKit] Negotiated protocol version %u\n", version);
}

static void apple_rtkit_handle_epmap_reply(apple_rtkit_ctx_t *ctx, uint64_t msg) {
    /* EPMAP reply contains 32 endpoint bits */
    uint32_t base = (uint32_t)(msg >> 32) & 0xFF;
    uint32_t bitmap = (uint32_t)(msg & 0xFFFFFFFF);

    /* Set bits in endpoint bitmap */
    uint32_t word = base / 32;
    if (word < 8) {
        ctx->endpoint_bitmap[word] = bitmap;
        fut_printf("[RTKit] EPMAP: endpoints %u-%u bitmap=0x%08x\n", base, base + 31, bitmap);
    }
}

static void apple_rtkit_handle_iop_pwr_ack(apple_rtkit_ctx_t *ctx, uint64_t msg) {
    uint8_t state = (uint8_t)(msg & 0xFF);
    ctx->iop_power_state = state;
    fut_printf("[RTKit] IOP power state: 0x%02x\n", state);
}

static void apple_rtkit_handle_ap_pwr_ack(apple_rtkit_ctx_t *ctx, uint64_t msg) {
    uint8_t state = (uint8_t)(msg & 0xFF);
    ctx->ap_power_state = state;
    fut_printf("[RTKit] AP power state: 0x%02x\n", state);
}

static void apple_rtkit_handle_mgmt_message(apple_rtkit_ctx_t *ctx, uint64_t msg) {
    /* Management message dispatcher (endpoint 0)
     *
     * Management endpoint handles all co-processor lifecycle and control messages:
     * - Version negotiation (HELLO/HELLO_REPLY)
     * - Endpoint discovery (EPMAP/EPMAP_REPLY)
     * - Power state management (AP_PWR_STATE, IOP_PWR_STATE, etc.)
     * - Endpoint lifecycle (STARTEP, STOPEP, etc.)
     *
     * Message structure:
     * [31:24] = msg_type (distinguishes different management commands)
     * [23:0]  = type-specific payload
     *
     * Typical boot sequence:
     * 1. HELLO -> get version
     * 2. EPMAP -> discover available endpoints
     * 3. STARTEP -> start required system endpoints (syslog, crashlog, etc.)
     * 4. PWR_STATE -> transition to ON power state
     * 5. Application ready for endpoint communication
     */
    uint8_t msg_type = APPLE_RTKIT_MSG_TYPE(msg);

    switch (msg_type) {
        case APPLE_RTKIT_MGMT_MSG_HELLO_REPLY:
            /* Version negotiation complete - stores negotiated version in ctx */
            apple_rtkit_handle_hello_reply(ctx, msg);
            break;

        case APPLE_RTKIT_MGMT_MSG_EPMAP_REPLY:
            /* Endpoint bitmap response - populate endpoint availability bitmap */
            apple_rtkit_handle_epmap_reply(ctx, msg);
            break;

        case APPLE_RTKIT_MGMT_MSG_IOP_PWR_ACK:
            /* Input/Output Processor power state acknowledgment */
            apple_rtkit_handle_iop_pwr_ack(ctx, msg);
            break;

        case APPLE_RTKIT_MGMT_MSG_AP_PWR_ACK:
            /* Application Processor power state acknowledgment */
            apple_rtkit_handle_ap_pwr_ack(ctx, msg);
            break;

        case APPLE_RTKIT_MGMT_MSG_STARTEP_ACK:
            /* Endpoint started successfully - ready for application messages */
            break;

        default:
            fut_printf("[RTKit] Unknown management message type: 0x%02x\n", msg_type);
            break;
    }
}

/* ============================================================
 *   Message Processing
 * ============================================================ */

int apple_rtkit_process_messages(apple_rtkit_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }

    int count = 0;
    uint8_t endpoint;
    uint64_t msg;

    /* Process all pending messages */
    while (apple_rtkit_recv_message(ctx, &endpoint, &msg)) {
        count++;

        /* Management endpoint (0) is handled internally */
        if (endpoint == APPLE_RTKIT_EP_MGMT) {
            apple_rtkit_handle_mgmt_message(ctx, msg);
            continue;
        }

        /* Dispatch to registered handler */
        if (ctx->endpoints[endpoint].handler) {
            ctx->endpoints[endpoint].handler(ctx->endpoints[endpoint].cookie, endpoint, msg);
        }
    }

    return count;
}

/* ============================================================
 *   Endpoint Management
 * ============================================================ */

bool apple_rtkit_register_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint,
                                    apple_rtkit_msg_handler_t handler, void *cookie) {
    if (!ctx) {
        return false;
    }

    /* endpoint is uint8_t so always < 256 */
    ctx->endpoints[endpoint].endpoint = endpoint;
    ctx->endpoints[endpoint].handler = handler;
    ctx->endpoints[endpoint].cookie = cookie;

    return true;
}

bool apple_rtkit_start_endpoint(apple_rtkit_ctx_t *ctx, uint8_t endpoint) {
    if (!ctx || endpoint < APPLE_RTKIT_EP_APP_START) {
        return false;
    }
    /* endpoint is uint8_t so always <= 255 */

    if (!apple_rtkit_ep_is_valid(ctx, endpoint)) {
        fut_printf("[RTKit] Error: Endpoint %u not available\n", endpoint);
        return false;
    }

    /* Send STARTEP message */
    uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_STARTEP, endpoint);
    if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
        return false;
    }

    /* Wait for acknowledgment */
    int timeout = 1000;
    while (timeout-- > 0) {
        apple_rtkit_process_messages(ctx);

        /* Check if endpoint is started (simplified) */
        if (ctx->endpoints[endpoint].started) {
            return true;
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    fut_printf("[RTKit] Warning: Endpoint %u start timeout\n", endpoint);
    ctx->endpoints[endpoint].started = true;  /* Optimistically mark as started */
    return true;
}

/* ============================================================
 *   Power State Management
 * ============================================================ */

bool apple_rtkit_set_ap_power_state(apple_rtkit_ctx_t *ctx, uint8_t state) {
    if (!ctx) {
        return false;
    }

    uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_AP_PWR_STATE, state);
    if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
        return false;
    }

    /* Wait for acknowledgment */
    int timeout = 1000;
    while (timeout-- > 0) {
        apple_rtkit_process_messages(ctx);

        if (ctx->ap_power_state == state) {
            return true;
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    fut_printf("[RTKit] Warning: AP power state change timeout\n");
    return false;
}

bool apple_rtkit_set_iop_power_state(apple_rtkit_ctx_t *ctx, uint8_t state) {
    if (!ctx) {
        return false;
    }

    uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_IOP_PWR_STATE, state);
    if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
        return false;
    }

    /* Wait for acknowledgment */
    int timeout = 1000;
    while (timeout-- > 0) {
        apple_rtkit_process_messages(ctx);

        if (ctx->iop_power_state == state) {
            return true;
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    fut_printf("[RTKit] Warning: IOP power state change timeout\n");
    return false;
}

/* ============================================================
 *   RTKit Boot Sequence
 * ============================================================ */

static bool apple_rtkit_send_hello(apple_rtkit_ctx_t *ctx) {
    /* Build HELLO message with version */
    uint64_t payload = ((uint64_t)APPLE_RTKIT_MIN_VERSION << 48) |
                       ((uint64_t)APPLE_RTKIT_MAX_VERSION << 32);
    uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_HELLO, payload);

    if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
        fut_printf("[RTKit] Error: Failed to send HELLO\n");
        return false;
    }

    /* Wait for HELLO_REPLY */
    int timeout = 1000;
    while (timeout-- > 0) {
        apple_rtkit_process_messages(ctx);

        if (ctx->version != 0) {
            return true;  /* Got HELLO_REPLY */
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    fut_printf("[RTKit] Error: HELLO timeout\n");
    return false;
}

static bool apple_rtkit_discover_endpoints(apple_rtkit_ctx_t *ctx) {
    /* Request endpoint map */
    uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_EPMAP, 0);

    if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
        fut_printf("[RTKit] Error: Failed to send EPMAP\n");
        return false;
    }

    /* Wait for EPMAP_REPLY messages */
    int timeout = 1000;
    int replies = 0;
    while (timeout-- > 0 && replies < 8) {
        int processed = apple_rtkit_process_messages(ctx);
        if (processed > 0) {
            replies++;
            timeout = 1000;  /* Reset timeout on activity */
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    fut_printf("[RTKit] Endpoint discovery complete\n");
    return true;
}

static bool apple_rtkit_start_system_endpoints(apple_rtkit_ctx_t *ctx) {
    /* Start system endpoints (required by RTKit) */
    uint8_t system_eps[] = {
        APPLE_RTKIT_EP_SYSLOG,
        APPLE_RTKIT_EP_CRASHLOG,
        APPLE_RTKIT_EP_DEBUG,
        APPLE_RTKIT_EP_IOREPORT
    };

    for (size_t i = 0; i < sizeof(system_eps) / sizeof(system_eps[0]); i++) {
        uint8_t ep = system_eps[i];

        if (!apple_rtkit_ep_is_valid(ctx, ep)) {
            continue;  /* Endpoint not available */
        }

        uint64_t msg = apple_rtkit_build_message(APPLE_RTKIT_MGMT_MSG_STARTEP, ep);
        if (!apple_rtkit_send_message(ctx, APPLE_RTKIT_EP_MGMT, msg)) {
            fut_printf("[RTKit] Warning: Failed to start endpoint %u\n", ep);
            continue;
        }

        /* Wait for ACK */
        int timeout = 100;
        while (timeout-- > 0) {
            apple_rtkit_process_messages(ctx);
            for (volatile int j = 0; j < 100; j++);
        }
    }

    fut_printf("[RTKit] System endpoints started\n");
    return true;
}

bool apple_rtkit_boot(apple_rtkit_ctx_t *ctx) {
    if (!ctx) {
        return false;
    }

    fut_printf("[RTKit] Booting co-processor...\n");

    /* 1. Send HELLO and negotiate version */
    if (!apple_rtkit_send_hello(ctx)) {
        return false;
    }

    /* 2. Discover available endpoints */
    if (!apple_rtkit_discover_endpoints(ctx)) {
        return false;
    }

    /* 3. Start required system endpoints */
    if (!apple_rtkit_start_system_endpoints(ctx)) {
        return false;
    }

    /* 4. Transition to ON power state */
    if (!apple_rtkit_set_iop_power_state(ctx, APPLE_RTKIT_PWR_STATE_ON)) {
        fut_printf("[RTKit] Warning: Failed to set IOP power state\n");
    }

    if (!apple_rtkit_set_ap_power_state(ctx, APPLE_RTKIT_PWR_STATE_ON)) {
        fut_printf("[RTKit] Warning: Failed to set AP power state\n");
    }

    ctx->initialized = true;
    fut_printf("[RTKit] Co-processor boot complete\n");
    return true;
}

/* ============================================================
 *   Initialization and Shutdown
 * ============================================================ */

apple_rtkit_ctx_t *apple_rtkit_init(uint64_t mailbox_base) {
    if (mailbox_base == 0) {
        fut_printf("[RTKit] Error: Invalid mailbox address\n");
        return NULL;
    }

    /* Allocate RTKit context */
    apple_rtkit_ctx_t *ctx = (apple_rtkit_ctx_t *)fut_pmm_alloc_page();
    if (!ctx) {
        fut_printf("[RTKit] Error: Failed to allocate context\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(apple_rtkit_ctx_t));

    /* Initialize mailbox */
    ctx->mailbox_phys = mailbox_base;
    ctx->mailbox_base = (volatile uint8_t *)mailbox_base;

    fut_printf("[RTKit] Initialized (mailbox @ 0x%016llx)\n", mailbox_base);
    return ctx;
}

void apple_rtkit_shutdown(apple_rtkit_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    fut_printf("[RTKit] Shutting down co-processor...\n");

    /* Transition to OFF power state */
    apple_rtkit_set_iop_power_state(ctx, APPLE_RTKIT_PWR_STATE_OFF);
    apple_rtkit_set_ap_power_state(ctx, APPLE_RTKIT_PWR_STATE_OFF);

    /* Free context */
    fut_pmm_free_page(ctx);

    fut_printf("[RTKit] Shutdown complete\n");
}

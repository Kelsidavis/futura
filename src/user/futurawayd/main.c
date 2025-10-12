/* main.c - FuturaWay Display Compositor (futurawayd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Wayland-compatible compositor for Futura OS.
 * Manages surfaces, composites framebuffers, routes input events via FIPC.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <user/futura_way.h>

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;

/* Framebuffer info */
static struct {
    void *base;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint32_t bpp;
} framebuffer;

/**
 * Handle surface creation request.
 */
static void handle_create_surface(struct fut_fipc_msg *msg, struct fut_fipc_channel *client_channel) {
    (void)msg;
    (void)client_channel;

    /* Phase 3: Parse create surface request:
     * struct fway_create_surface_req *req = (void *)msg->payload;
     *
     * 1. Allocate surface ID
     * 2. Create shared memory region for framebuffer
     * 3. Initialize surface metadata (width, height, format)
     * 4. Add to surface list
     * 5. Send response with surface_id and buffer_region_id
     */
}

/**
 * Handle surface destruction request.
 */
static void handle_destroy_surface(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse destroy surface request:
     * struct fway_destroy_surface_req *req = (void *)msg->payload;
     *
     * 1. Find surface by ID
     * 2. Release shared memory region
     * 3. Remove from surface list
     * 4. Send confirmation
     */
}

/**
 * Handle surface commit (double-buffer flip).
 */
static void handle_commit(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse commit request:
     * struct fway_commit_req *req = (void *)msg->payload;
     *
     * 1. Find surface by ID
     * 2. Mark surface as needing redraw
     * 3. Schedule composite pass
     */
}

/**
 * Handle surface damage notification.
 */
static void handle_damage(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse damage request:
     * struct fway_damage_req *req = (void *)msg->payload;
     *
     * 1. Find surface by ID
     * 2. Add damaged region to dirty rect list
     * 3. Schedule repaint
     */
}

/**
 * Composite all surfaces into final framebuffer.
 * This is the main rendering function.
 */
static void composite_frame(void) {
    /* Phase 3: Compositing algorithm:
     * 1. Clear framebuffer or copy background
     * 2. Iterate surfaces in Z-order (back to front)
     * 3. For each visible surface:
     *    a. Get surface buffer from shared memory
     *    b. Blit surface pixels to framebuffer
     *    c. Handle transparency/alpha blending
     * 4. Draw window decorations (title bars)
     * 5. Draw cursor
     * 6. Flush to display hardware
     */

    /* Stub: Clear framebuffer to Futura Blue */
    if (framebuffer.base) {
        uint32_t *pixels = (uint32_t *)framebuffer.base;
        uint32_t futura_blue = 0xFF2962FF;  /* #2962FF */
        for (uint32_t i = 0; i < framebuffer.width * framebuffer.height; i++) {
            pixels[i] = futura_blue;
        }
    }
}

/**
 * Handle input event from kernel (keyboard, mouse, touch).
 */
static void __attribute__((unused)) handle_input_event(uint32_t type, uint32_t code, int32_t value) {
    (void)type;
    (void)code;
    (void)value;

    /* Phase 3: Input routing:
     * 1. Determine focused surface (based on pointer position or focus)
     * 2. Convert event to FuturaWay format
     * 3. Send FWAY_MSG_INPUT_EVENT via surface's FIPC channel
     */
}

/**
 * Main event loop for futurawayd.
 */
static void futurawayd_main_loop(void) {
    uint8_t msg_buffer[8192];
    bool need_redraw = true;

    while (running) {
        /* Composite frame if needed */
        if (need_redraw) {
            composite_frame();
            need_redraw = false;
        }

        /* Wait for incoming client requests */
        if (listen_channel) {
            ssize_t received = fut_fipc_recv(listen_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;

                /* Route based on message type */
                switch (msg->type) {
                case FWAY_MSG_CREATE_SURFACE:
                    handle_create_surface(msg, NULL);
                    break;
                case FWAY_MSG_DESTROY_SURFACE:
                    handle_destroy_surface(msg);
                    break;
                case FWAY_MSG_COMMIT:
                    handle_commit(msg);
                    need_redraw = true;
                    break;
                case FWAY_MSG_DAMAGE:
                    handle_damage(msg);
                    need_redraw = true;
                    break;
                default:
                    /* Unknown request */
                    break;
                }
            }
        }

        /* Phase 3: Would poll for input events from kernel */
    }
}

/**
 * Initialize framebuffer.
 */
static int init_framebuffer(void) {
    /* Phase 3: Would query kernel for framebuffer info:
     * - Memory-mapped framebuffer region
     * - Resolution (width, height)
     * - Pixel format (usually RGB888 or RGBA8888)
     */

    /* Stub: Assume 1024x768 RGBA8888 */
    framebuffer.width = 1024;
    framebuffer.height = 768;
    framebuffer.bpp = 32;
    framebuffer.pitch = framebuffer.width * 4;
    framebuffer.base = NULL;  /* Would be mapped memory */

    return 0;
}

/**
 * Initialize futurawayd compositor.
 */
static int futurawayd_init(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Phase 3: Would initialize:
     * - Framebuffer access
     * - Surface list
     * - FIPC listen channel (for clients)
     * - Input device connections
     * - Font rendering (FreeType or similar)
     */

    /* Initialize framebuffer */
    if (init_framebuffer() < 0) {
        return -1;
    }

    /* Create initial display (clear to Futura Blue) */
    composite_frame();

    return 0;
}

/**
 * Cleanup and shutdown.
 */
static void futurawayd_shutdown(void) {
    /* Phase 3: Would cleanup:
     * - Close all client channels
     * - Release all surfaces
     * - Unmap framebuffer
     */
}

/**
 * Main entry point for futurawayd.
 */
int main(int argc, char **argv) {
    /* Initialize compositor */
    if (futurawayd_init(argc, argv) < 0) {
        return 1;
    }

    /* Enter main loop */
    futurawayd_main_loop();

    /* Shutdown */
    futurawayd_shutdown();

    return 0;
}

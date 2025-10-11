/* main.c - Filesystem Daemon (fsd)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * User-space filesystem daemon - manages VFS, mount points, and file operations.
 * Provides filesystem services via FIPC.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <kernel/fut_vfs.h>

/* Message types for fsd (internal - not in public header yet) */
#define FSD_MSG_MOUNT       0x4001
#define FSD_MSG_UNMOUNT     0x4002
#define FSD_MSG_OPEN        0x4003
#define FSD_MSG_CLOSE       0x4004
#define FSD_MSG_READ        0x4005
#define FSD_MSG_WRITE       0x4006
#define FSD_MSG_STAT        0x4007

/* Global state */
static bool running = true;
static struct fut_fipc_channel *listen_channel = NULL;

/**
 * Handle mount request.
 */
static void handle_mount(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse mount request:
     * struct {
     *     char device[256];
     *     char mountpoint[256];
     *     char fstype[64];
     *     uint32_t flags;
     * } *req = (void *)msg->payload;
     *
     * 1. Validate mount point
     * 2. Load filesystem driver
     * 3. Call kernel fut_vfs_mount()
     * 4. Send response
     */
}

/**
 * Handle file open request.
 */
static void handle_open(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse open request:
     * 1. Resolve path to vnode
     * 2. Check permissions
     * 3. Call kernel fut_vfs_open()
     * 4. Return file descriptor
     */
}

/**
 * Handle file read request.
 */
static void handle_read(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse read request:
     * 1. Validate file descriptor
     * 2. Get shared buffer region from request
     * 3. Call kernel fut_vfs_read() into shared buffer
     * 4. Send response with bytes read
     */
}

/**
 * Handle file write request.
 */
static void handle_write(struct fut_fipc_msg *msg) {
    (void)msg;

    /* Phase 3: Parse write request:
     * 1. Validate file descriptor
     * 2. Get data from shared buffer region
     * 3. Call kernel fut_vfs_write()
     * 4. Send response with bytes written
     */
}

/**
 * Main event loop for fsd.
 */
static void fsd_main_loop(void) {
    uint8_t msg_buffer[8192];

    while (running) {
        /* Wait for incoming requests */
        if (listen_channel) {
            ssize_t received = fut_fipc_recv(listen_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;

                /* Route based on message type */
                switch (msg->type) {
                case FSD_MSG_MOUNT:
                    handle_mount(msg);
                    break;
                case FSD_MSG_UNMOUNT:
                    /* Phase 3: Handle unmount */
                    break;
                case FSD_MSG_OPEN:
                    handle_open(msg);
                    break;
                case FSD_MSG_CLOSE:
                    /* Phase 3: Handle close */
                    break;
                case FSD_MSG_READ:
                    handle_read(msg);
                    break;
                case FSD_MSG_WRITE:
                    handle_write(msg);
                    break;
                case FSD_MSG_STAT:
                    /* Phase 3: Handle stat */
                    break;
                default:
                    /* Unknown request */
                    break;
                }
            }
        }

        /* Phase 3: Would implement proper event waiting */
    }
}

/**
 * Initialize fsd daemon.
 */
static int fsd_init(void) {
    /* Phase 3: Would initialize:
     * - VFS subsystem (fut_vfs_init())
     * - Register built-in filesystems (ramfs, devfs, etc.)
     * - Mount root filesystem
     * - Create FIPC listen channel
     */

    /* Initialize VFS */
    fut_vfs_init();

    /* Phase 3: Mount root filesystem */
    /* fut_vfs_mount(NULL, "/", "ramfs", 0, NULL); */

    return 0;
}

/**
 * Cleanup and shutdown.
 */
static void fsd_shutdown(void) {
    /* Phase 3: Would cleanup:
     * - Unmount all filesystems
     * - Close FIPC channels
     * - Release resources
     */
}

/**
 * Main entry point for fsd.
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Initialize daemon */
    if (fsd_init() < 0) {
        return 1;
    }

    /* Enter main loop */
    fsd_main_loop();

    /* Shutdown */
    fsd_shutdown();

    return 0;
}

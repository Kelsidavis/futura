/* main.c - Futura OS Init System (PID 1)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Init system for Futura OS - manages system services and orchestrates boot.
 * Communicates via FIPC channels.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <user/futura_init.h>

/* Forward declarations */
extern int init_config_parse(const char *path);
extern int init_service_start_all(void);
extern void init_service_monitor(void);
extern void init_handle_message(struct fut_fipc_msg *msg);

/* Global state */
static bool running = true;
static struct fut_fipc_channel *control_channel = NULL;

/**
 * Early initialization - set up logging and core subsystems.
 */
static int init_early_setup(void) {
    /* Phase 3: Stub - would initialize:
     * - Basic memory allocator
     * - Logging infrastructure
     * - FIPC control channel
     */
    return 0;
}

/**
 * Print banner to show init is starting.
 */
static void print_banner(void) {
    /* Phase 3: Would output to serial/console:
     * "Futura OS Init System v0.3.0"
     * "Starting system services..."
     */
}

/**
 * Main event loop for init system.
 * Monitors FIPC channels for service messages and handles events.
 */
static void init_main_loop(void) {
    uint8_t msg_buffer[4096];

    while (running) {
        /* Monitor all running services */
        init_service_monitor();

        /* Check for messages on control channel */
        if (control_channel) {
            ssize_t received = fut_fipc_recv(control_channel, msg_buffer, sizeof(msg_buffer));
            if (received > 0) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;
                init_handle_message(msg);
            }
        }

        /* Phase 3: Would implement proper event waiting:
         * - Wait on multiple FIPC channels
         * - Handle signals (SIGCHLD for process exits)
         * - Timeout for periodic service checks
         */
    }
}

/**
 * Shutdown sequence - stop all services in reverse dependency order.
 */
static void init_shutdown(void) {
    /* Phase 3: Would implement:
     * - Send STOP messages to all services
     * - Wait for graceful shutdown (with timeout)
     * - Force kill remaining processes
     * - Sync filesystems
     * - Reboot/halt system
     */
}

/**
 * Init entry point (PID 1).
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Early setup */
    if (init_early_setup() < 0) {
        /* Fatal error - can't continue */
        return 1;
    }

    /* Print banner */
    print_banner();

    /* Parse configuration */
    const char *config_path = "/etc/futura/init.conf";
    if (init_config_parse(config_path) < 0) {
        /* Non-fatal - continue with defaults */
    }

    /* Start all configured services */
    if (init_service_start_all() < 0) {
        /* Some services failed - but continue */
    }

    /* Enter main event loop */
    init_main_loop();

    /* Shutdown (only reached on explicit shutdown request) */
    init_shutdown();

    return 0;
}

/**
 * Handle messages received on control channel.
 */
void init_handle_message(struct fut_fipc_msg *msg) {
    if (!msg) {
        return;
    }

    /* Parse message type */
    switch (msg->type) {
    case INIT_MSG_START:
        /* Request to start a service */
        /* Phase 3: Parse service name from payload and start it */
        break;

    case INIT_MSG_STOP:
        /* Request to stop a service */
        /* Phase 3: Parse service name and stop it gracefully */
        break;

    case INIT_MSG_RESTART:
        /* Request to restart a service */
        /* Phase 3: Stop then start service */
        break;

    case INIT_MSG_STATUS:
        /* Query service status */
        /* Phase 3: Send status response */
        break;

    case INIT_MSG_SHUTDOWN:
        /* System shutdown request */
        running = false;
        break;

    default:
        /* Unknown message type - ignore */
        break;
    }
}

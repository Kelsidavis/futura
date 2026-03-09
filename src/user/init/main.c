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
#include <user/sys.h>
#include <user/stdio.h>
#include <shared/fut_timespec.h>

/* Forward declarations */
extern int init_config_parse(const char *path);
extern int init_service_start_all(void);
extern void init_service_monitor(void);
extern void init_handle_message(struct fut_fipc_msg *msg);

/* Global state */
static bool running = true;
static struct fut_fipc_channel *control_channel = NULL;

/**
 * Set up stdio file descriptors bound to /dev/console.
 */
static void init_setup_stdio(void) {
    int console_fd = sys_open("/dev/console", 2 /* O_RDWR */, 0);
    if (console_fd >= 0) {
        if (console_fd != 0) sys_dup2_call(console_fd, 0);
        if (console_fd != 1) sys_dup2_call(console_fd, 1);
        if (console_fd != 2) sys_dup2_call(console_fd, 2);
        if (console_fd > 2) sys_close(console_fd);
    }
}

/**
 * Main event loop for init system.
 * Monitors services, reaps children, handles control messages.
 */
static void init_main_loop(void) {
    uint8_t msg_buffer[4096];
    fut_timespec_t poll_interval = { .tv_sec = 0, .tv_nsec = 100000000 }; /* 100ms */

    while (running) {
        /* Reap any exited children and update service states */
        init_service_monitor();

        /* Check for messages on control channel */
        if (control_channel) {
            ssize_t received = fut_fipc_recv(control_channel, msg_buffer, sizeof(msg_buffer));
            if (received >= (ssize_t)sizeof(struct fut_fipc_msg)) {
                struct fut_fipc_msg *msg = (struct fut_fipc_msg *)msg_buffer;
                init_handle_message(msg);
            }
        }

        /* Sleep between polls to avoid busy-waiting */
        sys_nanosleep_call(&poll_interval, NULL);
    }
}

/**
 * Shutdown sequence - stop all services.
 */
static void init_shutdown(void) {
    printf("[INIT] Shutting down...\n");
    /* Future: send SIGTERM to all services, wait, then SIGKILL */
}

/**
 * Init entry point (PID 1).
 */
int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Set up stdio */
    init_setup_stdio();

    printf("[INIT] Futura OS Init System starting\n");

    /* Parse configuration - registers services */
    const char *config_path = "/etc/futura/init.conf";
    if (init_config_parse(config_path) < 0) {
        printf("[INIT] Config parse failed, continuing with defaults\n");
    }

    /* Create /tmp directory for runtime files */
    sys_mkdir_call("/tmp", 0755);

    /* Start all configured services in priority order */
    if (init_service_start_all() < 0) {
        printf("[INIT] Some services failed to start\n");
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
    if (!msg) return;

    switch (msg->type) {
    case INIT_MSG_START:
        break;
    case INIT_MSG_STOP:
        break;
    case INIT_MSG_RESTART:
        break;
    case INIT_MSG_STATUS:
        break;
    case INIT_MSG_SHUTDOWN:
        running = false;
        break;
    default:
        break;
    }
}

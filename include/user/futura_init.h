/* futura_init.h - Futura Init System
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Service orchestration and management for Futura OS userland.
 * PID 1 process responsible for spawning and monitoring services.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>

/* pid_t is provided by sys/types.h */
#ifndef __pid_t_defined
#define __pid_t_defined 1
typedef int32_t pid_t;
#endif

/* ============================================================
 *   Service States
 * ============================================================ */

enum fui_service_state {
    SERVICE_STOPPED = 0,
    SERVICE_STARTING,
    SERVICE_RUNNING,
    SERVICE_STOPPING,
    SERVICE_FAILED,
};

/* ============================================================
 *   Service Structure
 * ============================================================ */

struct fui_service {
    char *name;                 /* Service name */
    char *exec_path;            /* Executable path */
    char **args;                /* Arguments (NULL-terminated) */
    char **env;                 /* Environment (NULL-terminated) */

    pid_t pid;                  /* Process ID (0 if not running) */
    int priority;               /* Start priority (lower = earlier) */
    bool respawn;               /* Restart on crash */
    int respawn_limit;          /* Max respawn attempts */
    int respawn_count;          /* Current respawn count */

    char **depends;             /* Dependency list (service names) */
    size_t num_depends;

    enum fui_service_state state;
    int exit_code;              /* Last exit code */
    uint64_t start_time;        /* Start timestamp */

    struct fut_fipc_channel *channel;  /* FIPC channel to service */
};

/* ============================================================
 *   Init Configuration
 * ============================================================ */

struct fui_init_config {
    struct fui_service **services;
    size_t num_services;

    /* Global settings */
    int default_respawn_limit;
    int shutdown_timeout_ms;
    char *hostname;
};

/* ============================================================
 *   Init Message Protocol
 * ============================================================ */

/* Message type range: 0x1000 - 0x1FFF */
#define INIT_MSG_START          0x1001
#define INIT_MSG_STOP           0x1002
#define INIT_MSG_RESTART        0x1003
#define INIT_MSG_STATUS         0x1004
#define INIT_MSG_READY          0x1005  /* Service → Init */
#define INIT_MSG_PING           0x1006
#define INIT_MSG_PONG           0x1007
#define INIT_MSG_SHUTDOWN       0x1008
#define INIT_MSG_REBOOT         0x1009

struct init_msg_start {
    char service_name[256];
};

struct init_msg_stop {
    char service_name[256];
    int signal;                 /* Signal to send (SIGTERM, SIGKILL) */
};

struct init_msg_status_req {
    char service_name[256];
};

struct init_msg_status_resp {
    enum fui_service_state state;
    pid_t pid;
    int exit_code;
    uint64_t start_time;
    uint64_t uptime_ms;
};

struct init_msg_ready {
    pid_t pid;
    char service_name[256];
};

/* ============================================================
 *   Init API (Internal)
 * ============================================================ */

/**
 * Parse init configuration from file.
 *
 * @param path Path to init.conf
 * @return Configuration structure, or NULL on error
 */
struct fui_init_config *fui_init_parse_config(const char *path);

/**
 * Free init configuration.
 *
 * @param config Configuration to free
 */
void fui_init_free_config(struct fui_init_config *config);

/**
 * Start a service.
 *
 * @param service Service to start
 * @return 0 on success, negative on error
 */
int fui_init_start_service(struct fui_service *service);

/**
 * Stop a service.
 *
 * @param service Service to stop
 * @param signal Signal to send (SIGTERM, SIGKILL)
 * @return 0 on success, negative on error
 */
int fui_init_stop_service(struct fui_service *service, int signal);

/**
 * Check service dependencies.
 *
 * @param service Service to check
 * @param services All services list
 * @param num_services Number of services
 * @return true if all dependencies are running
 */
bool fui_init_check_dependencies(struct fui_service *service,
                                 struct fui_service **services,
                                 size_t num_services);

/**
 * Wait for child process (non-blocking).
 *
 * @param pid Pointer to store child PID
 * @param status Pointer to store exit status
 * @return true if child exited, false if no child
 */
bool fui_init_wait_child(pid_t *pid, int *status);

/**
 * Handle service exit.
 *
 * @param service Service that exited
 * @param status Exit status
 */
void fui_init_handle_exit(struct fui_service *service, int status);

/**
 * Main init loop.
 *
 * @param config Init configuration
 * @return Exit code
 */
int fui_init_main_loop(struct fui_init_config *config);

/* ============================================================
 *   Service Control API (for service programs)
 * ============================================================ */

/**
 * Notify init that service is ready.
 * Services should call this after initialization.
 *
 * @return 0 on success, negative on error
 */
int fui_service_ready(void);

/**
 * Request service stop.
 *
 * @param service_name Service to stop
 * @return 0 on success, negative on error
 */
int fui_service_stop(const char *service_name);

/**
 * Get service status.
 *
 * @param service_name Service to query
 * @param status Status structure (out)
 * @return 0 on success, negative on error
 */
int fui_service_get_status(const char *service_name,
                           struct init_msg_status_resp *status);

/* ============================================================
 *   Configuration File Format
 * ============================================================ */

/*
 * /etc/futura/init.conf format:
 *
 * [global]
 * hostname=futura-os
 * respawn_limit=5
 * shutdown_timeout=30000
 *
 * [service:fsd]
 * exec=/sbin/fsd
 * args=--root=/
 * priority=1
 * respawn=yes
 * depends=
 *
 * [service:posixd]
 * exec=/sbin/posixd
 * args=
 * priority=2
 * respawn=yes
 * depends=
 *
 * [service:futurawayd]
 * exec=/sbin/futurawayd
 * args=--display=:0
 * env=DISPLAY=:0
 * priority=3
 * respawn=yes
 * depends=fsd
 *
 * [service:sessiond]
 * exec=/sbin/sessiond
 * args=
 * priority=4
 * respawn=yes
 * depends=futurawayd,posixd
 */

/* ============================================================
 *   Signals
 * ============================================================ */

#define SIGTERM     15          /* Termination signal */
#define SIGKILL     9           /* Kill signal (cannot be caught) */
#define SIGHUP      1           /* Hangup */
#define SIGINT      2           /* Interrupt */
#define SIGCHLD     17          /* Child status changed */

/* ============================================================
 *   Exit Codes
 * ============================================================ */

#define EXIT_SUCCESS            0
#define EXIT_FAILURE            1
#define EXIT_CONFIG_ERROR       2
#define EXIT_DEPENDENCY_ERROR   3
#define EXIT_RESPAWN_LIMIT      4

/* service.c - Init System Service Management
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Service lifecycle management, dependency resolution, and monitoring.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>
#include <user/futura_init.h>

/* Maximum number of services */
#define MAX_SERVICES 64

/* Service registry */
static struct fui_service *services[MAX_SERVICES];
static int num_services = 0;

/* Service respawn tracking */
struct respawn_tracker {
    int count;          /* Number of respawns */
    uint64_t last_time; /* Last respawn timestamp */
    uint64_t window;    /* Time window for respawn limit */
};

static struct respawn_tracker respawn_trackers[MAX_SERVICES];

/**
 * Register a service with the init system.
 */
int init_service_register(struct fui_service *service) {
    if (!service || num_services >= MAX_SERVICES) {
        return -1;
    }

    services[num_services] = service;
    respawn_trackers[num_services].count = 0;
    respawn_trackers[num_services].last_time = 0;
    respawn_trackers[num_services].window = 60000;  /* 60 seconds */
    num_services++;

    return 0;
}

/**
 * Find a service by name.
 */
static struct fui_service *find_service(const char *name) {
    if (!name) return NULL;

    for (int i = 0; i < num_services; i++) {
        if (services[i] && services[i]->name) {
            /* Simple string comparison */
            const char *a = services[i]->name;
            const char *b = name;
            while (*a && *b && *a == *b) {
                a++;
                b++;
            }
            if (*a == *b) {
                return services[i];
            }
        }
    }

    return NULL;
}

/**
 * Check if all dependencies of a service are running.
 */
static bool check_dependencies(struct fui_service *service) {
    if (!service || !service->depends) {
        return true;  /* No dependencies */
    }

    /* Phase 3: Would iterate through depends array and check each service state */
    for (int i = 0; service->depends[i] != NULL; i++) {
        struct fui_service *dep = find_service(service->depends[i]);
        if (!dep || dep->state != FUI_STATE_RUNNING) {
            return false;
        }
    }

    return true;
}

/**
 * Spawn a service process.
 */
static int spawn_service(struct fui_service *service) {
    if (!service) return -1;

    /* Phase 3: Would use POSIX fork/exec via posixd:
     * 1. Send FORK request to posixd
     * 2. In child process, send EXEC request with exec_path and args
     * 3. Set up FIPC channel for service communication
     * 4. Store child PID in service->pid
     */

    /* Stub implementation */
    service->pid = 0;  /* Would be actual PID */
    service->state = FUI_STATE_RUNNING;

    return 0;
}

/**
 * Start a service (and its dependencies if needed).
 */
int init_service_start(const char *name) {
    struct fui_service *service = find_service(name);
    if (!service) {
        return -1;  /* Service not found */
    }

    /* Check if already running */
    if (service->state == FUI_STATE_RUNNING) {
        return 0;  /* Already running */
    }

    /* Check if already starting */
    if (service->state == FUI_STATE_STARTING) {
        return 0;  /* Start in progress */
    }

    /* Start dependencies first */
    if (service->depends) {
        for (int i = 0; service->depends[i] != NULL; i++) {
            int ret = init_service_start(service->depends[i]);
            if (ret < 0) {
                return -1;  /* Dependency failed to start */
            }
        }
    }

    /* Wait for dependencies to be fully running */
    if (!check_dependencies(service)) {
        return -1;  /* Dependencies not satisfied */
    }

    /* Update state */
    service->state = FUI_STATE_STARTING;

    /* Spawn the service process */
    int ret = spawn_service(service);
    if (ret < 0) {
        service->state = FUI_STATE_FAILED;
        return -1;
    }

    /* Service is now running */
    service->state = FUI_STATE_RUNNING;

    return 0;
}

/**
 * Stop a service gracefully.
 */
int init_service_stop(const char *name) {
    struct fui_service *service = find_service(name);
    if (!service) {
        return -1;
    }

    if (service->state != FUI_STATE_RUNNING) {
        return 0;  /* Not running */
    }

    /* Update state */
    service->state = FUI_STATE_STOPPING;

    /* Phase 3: Would send STOP message via FIPC channel:
     * 1. Send FUI_MSG_SERVICE_STOP to service
     * 2. Wait for graceful shutdown (timeout)
     * 3. If timeout, send SIGTERM
     * 4. If still not dead, send SIGKILL
     */

    /* Stub: Mark as stopped */
    service->state = FUI_STATE_STOPPED;
    service->pid = 0;

    return 0;
}

/**
 * Restart a service.
 */
int init_service_restart(const char *name) {
    int ret = init_service_stop(name);
    if (ret < 0) {
        return ret;
    }

    return init_service_start(name);
}

/**
 * Start all services in priority order.
 */
int init_service_start_all(void) {
    /* Sort services by priority (bubble sort - simple) */
    for (int i = 0; i < num_services - 1; i++) {
        for (int j = 0; j < num_services - i - 1; j++) {
            if (services[j]->priority > services[j + 1]->priority) {
                struct fui_service *temp = services[j];
                services[j] = services[j + 1];
                services[j + 1] = temp;
            }
        }
    }

    /* Start each service in order */
    for (int i = 0; i < num_services; i++) {
        if (services[i]) {
            init_service_start(services[i]->name);
        }
    }

    return 0;
}

/**
 * Monitor running services and respawn if needed.
 */
void init_service_monitor(void) {
    /* Phase 3: Would check for dead processes:
     * 1. Use waitpid(-1, WNOHANG) to check for exited children
     * 2. Find corresponding service by PID
     * 3. If service has respawn=true, respawn it
     * 4. Track respawn count to prevent restart loops
     */

    for (int i = 0; i < num_services; i++) {
        struct fui_service *service = services[i];
        if (!service) continue;

        /* Check if service died unexpectedly */
        if (service->state == FUI_STATE_RUNNING && service->pid == 0) {
            /* Process died */
            if (service->respawn) {
                /* Check respawn limit */
                struct respawn_tracker *tracker = &respawn_trackers[i];
                /* Phase 3: Would check time window and respawn count */
                tracker->count++;

                /* Respawn the service */
                service->state = FUI_STATE_STOPPED;
                init_service_start(service->name);
            } else {
                /* Don't respawn - mark as failed */
                service->state = FUI_STATE_FAILED;
            }
        }
    }
}

/**
 * Get service status.
 */
enum fui_service_state init_service_get_state(const char *name) {
    struct fui_service *service = find_service(name);
    if (!service) {
        return FUI_STATE_STOPPED;
    }
    return service->state;
}

/* fipc_host_shim.c - Host glue for kernel FIPC core
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides libc-backed implementations of freestanding kernel APIs so we
 * can reuse kernel/ipc/fut_fipc.c inside host-side tooling and tests.
 */

#define _POSIX_C_SOURCE 200809L

#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

void *fut_malloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    return malloc(size);
}

void fut_free(void *ptr) {
    free(ptr);
}

void *fut_realloc(void *ptr, size_t new_size) {
    return realloc(ptr, new_size);
}

void *fut_malloc_pages(size_t num_pages) {
    size_t total = num_pages * FUT_PAGE_SIZE;
    void *buffer = NULL;
#if defined(_ISOC11_SOURCE) || (__STDC_VERSION__ >= 201112L)
    buffer = aligned_alloc(FUT_PAGE_SIZE, total);
#endif
    if (!buffer) {
        buffer = malloc(total);
    }
    return buffer;
}

void fut_free_pages(void *ptr, size_t num_pages) {
    (void)num_pages;
    free(ptr);
}

uint64_t fut_get_ticks(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

void fut_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
}

/* Stubs not required for host exercising */
void fut_pmm_init(uint64_t mem_size_bytes, uintptr_t phys_base) {
    (void)mem_size_bytes;
    (void)phys_base;
}

void *fut_pmm_alloc_page(void) {
    return fut_malloc_pages(1);
}

void fut_pmm_free_page(void *addr) {
    fut_free_pages(addr, 1);
}

uint64_t fut_pmm_total_pages(void) {
    return 0;
}

uint64_t fut_pmm_free_pages(void) {
    return 0;
}

void fut_heap_init(uintptr_t heap_start, uintptr_t heap_end) {
    (void)heap_start;
    (void)heap_end;
}

void fut_mem_print_stats(void) {
}

void fut_timer_subsystem_init(void) {
}

void fut_timer_tick(void) {
}

void fut_sleep_until(fut_thread_t *thread, uint64_t millis) {
    (void)thread;
    (void)millis;
}

/* ------------------------------------------------------------ */
/* Host timer implementation                                    */

typedef struct host_timer_node {
    struct host_timer_node *next;
    uint64_t ticks;
    void (*cb)(void *);
    void *arg;
    int cancelled;
    pthread_t thread;
} host_timer_node_t;

static pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
static host_timer_node_t *timer_list = NULL;

static void host_timer_remove_locked(host_timer_node_t *node) {
    if (timer_list == node) {
        timer_list = node->next;
        return;
    }
    host_timer_node_t *curr = timer_list;
    while (curr && curr->next != node) {
        curr = curr->next;
    }
    if (curr) {
        curr->next = node->next;
    }
}

static void *host_timer_thread_entry(void *arg) {
    host_timer_node_t *node = (host_timer_node_t *)arg;
    struct timespec ts = {
        .tv_sec = (time_t)(node->ticks / 1000ULL),
        .tv_nsec = (long)((node->ticks % 1000ULL) * 1000000ULL)
    };
    nanosleep(&ts, NULL);

    pthread_mutex_lock(&timer_lock);
    int cancelled = node->cancelled;
    host_timer_remove_locked(node);
    pthread_mutex_unlock(&timer_lock);

    if (!cancelled && node->cb) {
        node->cb(node->arg);
    }
    fut_free(node);
    return NULL;
}

int fut_timer_start(uint64_t ticks_from_now, void (*cb)(void *), void *arg) {
    if (!cb) {
        return -1;
    }
    if (ticks_from_now == 0) {
        cb(arg);
        return 0;
    }

    host_timer_node_t *node = (host_timer_node_t *)fut_malloc(sizeof(host_timer_node_t));
    if (!node) {
        return -1;
    }
    node->ticks = ticks_from_now;
    node->cb = cb;
    node->arg = arg;
    node->cancelled = 0;
    node->next = NULL;

    pthread_mutex_lock(&timer_lock);
    node->next = timer_list;
    timer_list = node;
    pthread_mutex_unlock(&timer_lock);

    if (pthread_create(&node->thread, NULL, host_timer_thread_entry, node) != 0) {
        pthread_mutex_lock(&timer_lock);
        host_timer_remove_locked(node);
        pthread_mutex_unlock(&timer_lock);
        fut_free(node);
        return -1;
    }
    pthread_detach(node->thread);
    return 0;
}

int fut_timer_cancel(void (*cb)(void *), void *arg) {
    if (!cb) {
        return -1;
    }
    pthread_mutex_lock(&timer_lock);
    for (host_timer_node_t *node = timer_list; node; node = node->next) {
        if (node->cb == cb && node->arg == arg) {
            node->cancelled = 1;
            pthread_mutex_unlock(&timer_lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&timer_lock);
    return -1;
}

/* ------------------------------------------------------------ */
/* Minimal thread registry for tests                            */

#define HOST_THREAD_REG_MAX 32
static fut_thread_t *host_thread_registry[HOST_THREAD_REG_MAX];
static size_t host_thread_reg_count = 0;
static fut_thread_t *host_current_thread = NULL;

static void host_register_thread(fut_thread_t *thread) {
    if (!thread) {
        return;
    }
    for (size_t i = 0; i < host_thread_reg_count; ++i) {
        if (host_thread_registry[i] == thread) {
            return;
        }
    }
    if (host_thread_reg_count < HOST_THREAD_REG_MAX) {
        host_thread_registry[host_thread_reg_count++] = thread;
    }
}

fut_thread_t *fut_thread_current(void) {
    return host_current_thread;
}

void fut_thread_set_current(fut_thread_t *thread) {
    host_current_thread = thread;
    if (thread) {
        if (thread->base_priority == 0) {
            thread->base_priority = thread->priority;
            thread->pi_saved_priority = thread->priority;
        }
        host_register_thread(thread);
    }
}

fut_thread_t *fut_thread_find(uint64_t tid) {
    for (size_t i = 0; i < host_thread_reg_count; ++i) {
        if (host_thread_registry[i] && host_thread_registry[i]->tid == tid) {
            return host_thread_registry[i];
        }
    }
    return NULL;
}

void fut_thread_set_deadline(uint64_t abs_tick) {
    if (host_current_thread) {
        host_current_thread->deadline_tick = abs_tick;
    }
}

uint64_t fut_thread_get_deadline(void) {
    return host_current_thread ? host_current_thread->deadline_tick : 0;
}

int fut_thread_priority_raise(fut_thread_t *thread, int new_priority) {
    if (!thread) {
        return -1;
    }
    if (new_priority <= thread->priority) {
        return 0;
    }
    thread->pi_saved_priority = thread->priority;
    thread->priority = new_priority;
    thread->pi_boosted = true;
    return 0;
}

int fut_thread_priority_restore(fut_thread_t *thread) {
    if (!thread) {
        return -1;
    }
    if (!thread->pi_boosted) {
        return 0;
    }
    thread->priority = thread->pi_saved_priority;
    thread->pi_boosted = false;
    return 0;
}

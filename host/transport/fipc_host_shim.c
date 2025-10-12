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

void fut_timer_init(void) {
}

void fut_timer_tick(void) {
}

void fut_sleep_until(fut_thread_t *thread, uint64_t millis) {
    (void)thread;
    (void)millis;
}

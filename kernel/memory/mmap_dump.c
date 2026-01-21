/* kernel/memory/mmap_dump.c - Memory map debugging utilities
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides utilities for tracking and dumping memory map entries for debugging.
 */

#include <kernel/fut_memory.h>

#include <stddef.h>

#include <kernel/kprintf.h>

#define FUT_MMAP_MAX_ENTRIES 32

static fut_mmap_entry_t g_entries[FUT_MMAP_MAX_ENTRIES];
static size_t g_entry_count = 0;

void fut_mmap_reset(void) {
    g_entry_count = 0;
}

void fut_mmap_add(uint64_t base, uint64_t length, uint32_t type) {
    if (length == 0) {
        return;
    }
    if (g_entry_count >= FUT_MMAP_MAX_ENTRIES) {
        return;
    }
    g_entries[g_entry_count++] = (fut_mmap_entry_t){
        .base = base,
        .length = length,
        .type = type
    };
}

const fut_mmap_entry_t *fut_mmap_entries(size_t *count) {
    if (count) {
        *count = g_entry_count;
    }
    return g_entries;
}

static const char *fut_mmap_type_name(uint32_t type) {
    switch (type) {
        case 1: return "usable";
        case 2: return "reserved";
        case 3: return "ACPI reclaim";
        case 4: return "ACPI NVS";
        case 5: return "bad";
        default: return "other";
    }
}

void fut_mmap_dump(void) {
    size_t count = 0;
    const fut_mmap_entry_t *entries = fut_mmap_entries(&count);

    if (!entries || count == 0) {
        fut_printf("  <memory map unavailable>\n");
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        const fut_mmap_entry_t *e = &entries[i];
        uint64_t end = e->base + e->length;
        unsigned long long size_mib = (unsigned long long)(e->length >> 20);
        fut_printf("  [0x%016llx - 0x%016llx)  %s  (%llu MiB)\n",
                   (unsigned long long)e->base,
                   (unsigned long long)end,
                   fut_mmap_type_name(e->type),
                   size_mib);
    }
}

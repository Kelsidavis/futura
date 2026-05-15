/* kernel/chrdev.c - Character device registry
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides registration and lookup for character device drivers (major/minor numbers).
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>

/* Maximum number of character devices that can be registered */
#define CHRDEV_MAX_ENTRIES 32

typedef struct {
    unsigned major;
    unsigned minor;
    const struct fut_file_ops *fops;
    void *driver_data;
    const char *name;
} chr_entry_t;

static chr_entry_t g_chr_table[CHRDEV_MAX_ENTRIES];
static size_t g_chr_count = 0;

int chrdev_register(unsigned major, unsigned minor, const struct fut_file_ops *fops,
                    const char *name, void *driver_data) {
    if (!fops) {
        return -EINVAL;
    }
    /* CAS-loop reservation so concurrent registrations (driver init
     * + dynamic device addition) don't both pick the same g_chr_table
     * index. See project_slot_claim_pattern.md. */
    size_t idx;
    {
        size_t cur, next;
        do {
            cur = __atomic_load_n(&g_chr_count, __ATOMIC_ACQUIRE);
            if (cur >= CHRDEV_MAX_ENTRIES) return -ENOSPC;
            next = cur + 1;
        } while (!__atomic_compare_exchange_n(&g_chr_count, &cur, next,
                                              false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
        idx = cur;
    }

    g_chr_table[idx] = (chr_entry_t){
        .major = major,
        .minor = minor,
        .fops = fops,
        .driver_data = driver_data,
        .name = name,
    };
    return 0;
}

const struct fut_file_ops *chrdev_lookup(unsigned major, unsigned minor, void **out_drv) {
    /* Acquire-load pairs with the release-CAS in chrdev_register so we
     * never observe an entry past the published count (which would
     * read stale memory). */
    size_t count = __atomic_load_n(&g_chr_count, __ATOMIC_ACQUIRE);
    for (size_t i = 0; i < count; ++i) {
        if (g_chr_table[i].major == major && g_chr_table[i].minor == minor) {
            if (out_drv) {
                *out_drv = g_chr_table[i].driver_data;
            }
            return g_chr_table[i].fops;
        }
    }
    return NULL;
}

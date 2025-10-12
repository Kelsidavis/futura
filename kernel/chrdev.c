// SPDX-License-Identifier: MPL-2.0
/*
 * chrdev.c - Minimal character device registry
 */

#include <kernel/chrdev.h>
#include <kernel/errno.h>

typedef struct {
    unsigned major;
    unsigned minor;
    const struct fut_file_ops *fops;
    void *driver_data;
    const char *name;
} chr_entry_t;

static chr_entry_t g_chr_table[32];
static size_t g_chr_count = 0;

int chrdev_register(unsigned major, unsigned minor, const struct fut_file_ops *fops,
                    const char *name, void *driver_data) {
    if (!fops) {
        return -EINVAL;
    }
    if (g_chr_count >= (sizeof(g_chr_table) / sizeof(g_chr_table[0]))) {
        return -ENOSPC;
    }

    g_chr_table[g_chr_count++] = (chr_entry_t){
        .major = major,
        .minor = minor,
        .fops = fops,
        .driver_data = driver_data,
        .name = name,
    };
    return 0;
}

const struct fut_file_ops *chrdev_lookup(unsigned major, unsigned minor, void **out_drv) {
    for (size_t i = 0; i < g_chr_count; ++i) {
        if (g_chr_table[i].major == major && g_chr_table[i].minor == minor) {
            if (out_drv) {
                *out_drv = g_chr_table[i].driver_data;
            }
            return g_chr_table[i].fops;
        }
    }
    return NULL;
}

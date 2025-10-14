// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <futura/fb_ioctl.h>

struct fut_fb_hwinfo {
    uint64_t phys;          /* Physical base address */
    uint64_t length;        /* Total bytes mapped */
    struct fut_fb_info info;/* Public geometry */
};

int fb_probe_from_multiboot(const void *mb_info);
int fb_get_info(struct fut_fb_hwinfo *out);
bool fb_is_available(void);
void fb_boot_splash(void);
void fb_char_init(void);

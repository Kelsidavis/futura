/* qemu_exit.h - helpers to exit QEMU via isa-debug-exit
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

static inline void qemu_exit(uint16_t code) {
    __asm__ volatile("outw %0, %1" :: "a"(code), "Nd"(0xF4));
    for (;;) {
        __asm__ volatile("hlt");
    }
}

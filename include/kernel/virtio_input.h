// SPDX-License-Identifier: MPL-2.0
/*
 * virtio_input.h - Kernel interface for the Rust virtio-input driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>

/**
 * virtio_input_hw_init - Register virtio-backed /dev/input/kbd0 + mouse0.
 *
 * Called from kernel_main.c on ARM64.  Returns 0 on success, negative errno
 * on failure (device nodes not created).
 */
int virtio_input_hw_init(void);

/**
 * virtio_input_post_event - Deliver one virtio-input event to the kernel.
 *
 * Called from the Rust virtio-input driver via C FFI.  @type uses Linux
 * evdev EV_* codes; @code and @value follow the same evdev conventions.
 */
void virtio_input_post_event(uint16_t type, uint16_t code, int32_t value);

// SPDX-License-Identifier: MPL-2.0
/*
 * posix_shm.h - Tiny POSIX shared memory helper wrappers.
 *
 * Userland code in the Wayland prototype relies on shared memory buffers
 * to exchange wl_shm surfaces.  Providing a small wrapper keeps the rest
 * of the codebase freestanding-friendly while avoiding repeated #ifdef
 * clutter around shm_open/ftruncate.
 *
 * Implementation details:
 *  - Shared memory objects are mapped onto /tmp/fut-shm-*.bin files until the
 *    kernel grows native shm primitives.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

int fut_shm_open(const char *name, int oflag, int mode);
int fut_shm_create(const char *name, size_t size, int oflag, int mode);
int fut_shm_unlink(const char *name);
int fut_shm_resize(int fd, size_t size);

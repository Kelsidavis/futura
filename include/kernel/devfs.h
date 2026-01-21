/* include/kernel/devfs.h - Device filesystem registry interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides device node registration and lookup for /dev filesystem.
 */

#pragma once

#include <stddef.h>

int devfs_create_chr(const char *path, unsigned major, unsigned minor);
int devfs_lookup_chr(const char *path, unsigned *major, unsigned *minor);

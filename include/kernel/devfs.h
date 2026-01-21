// SPDX-License-Identifier: MPL-2.0
/*
 * devfs.h - Device filesystem registry interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides device node registration and lookup for the /dev filesystem.
 * Devfs exposes hardware devices and pseudo-devices to userspace as
 * files that can be opened, read, written, and memory-mapped.
 *
 * Architecture:
 *   - Device nodes are identified by path (e.g., "/dev/tty0")
 *   - Each node is associated with major/minor numbers
 *   - The major/minor numbers link to chrdev or blkdev drivers
 *   - Opening a devfs node invokes the registered driver's callbacks
 *
 * Typical workflow:
 *   1. Driver registers with chrdev_register(major, minor, ops, ...)
 *   2. Device node created with devfs_create_chr("/dev/foo", major, minor)
 *   3. Userspace opens "/dev/foo", kernel looks up and calls driver
 *
 * Common device paths:
 *   /dev/null, /dev/zero     - Pseudo-devices
 *   /dev/tty, /dev/console   - Terminal devices
 *   /dev/fb0                 - Framebuffer
 *   /dev/input/event0        - Input devices
 */

#pragma once

#include <stddef.h>

/**
 * Create a character device node in devfs.
 *
 * Creates an entry at the given path that refers to the character
 * device identified by the major/minor number pair. The path should
 * start with "/" and is relative to the devfs root.
 *
 * @param path   Device path (e.g., "null" for /dev/null)
 * @param major  Major device number (identifies driver)
 * @param minor  Minor device number (identifies instance)
 * @return 0 on success, negative errno on failure
 */
int devfs_create_chr(const char *path, unsigned major, unsigned minor);

/**
 * Look up a character device by path.
 *
 * Retrieves the major/minor numbers for a device node. Used by
 * the VFS when opening device files.
 *
 * @param path   Device path to look up
 * @param major  Output: major device number (may be NULL)
 * @param minor  Output: minor device number (may be NULL)
 * @return 0 on success, -ENOENT if not found
 */
int devfs_lookup_chr(const char *path, unsigned *major, unsigned *minor);

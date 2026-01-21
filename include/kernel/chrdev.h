// SPDX-License-Identifier: MPL-2.0
/*
 * chrdev.h - Character device registration interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the character device driver interface used by device drivers
 * to register with the kernel and expose device files. Character devices
 * provide byte-stream access (as opposed to block devices).
 *
 * Architecture:
 *   - Drivers implement fut_file_ops callbacks (open, read, write, etc.)
 *   - Registration associates major/minor numbers with a driver
 *   - Device lookup returns the file_ops for a given major/minor pair
 *   - File descriptors are allocated via chrdev_alloc_fd()
 *
 * Example devices: /dev/null, /dev/tty, /dev/fb0, /dev/input/event0
 *
 * Major numbers identify the driver type, minor numbers identify
 * specific device instances (e.g., major=4 for TTY, minor=0-63 for
 * individual TTY devices).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef long off_t;
#endif

/**
 * File operations for character devices.
 *
 * Drivers implement these callbacks to handle file operations on their
 * device. All callbacks are optional; unimplemented operations return
 * -ENOTSUP to userspace.
 */
struct fut_file_ops {
    /**
     * Open the device.
     * @param inode         Device inode (driver-specific)
     * @param flags         Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
     * @param private_data  Output: driver-private data for this open instance
     * @return 0 on success, negative errno on failure
     */
    int     (*open)(void *inode, int flags, void **private_data);

    /**
     * Close the device (release resources).
     * @param inode         Device inode
     * @param private_data  Driver-private data from open()
     * @return 0 on success, negative errno on failure
     */
    int     (*release)(void *inode, void *private_data);

    /**
     * Read from the device.
     * @param inode         Device inode
     * @param private_data  Driver-private data from open()
     * @param u_buf         Kernel buffer to read into
     * @param n             Maximum bytes to read
     * @param pos           File position (updated on success)
     * @return Bytes read on success, negative errno on failure
     */
    ssize_t (*read)(void *inode, void *private_data, void *u_buf, size_t n, off_t *pos);

    /**
     * Write to the device.
     * @param inode         Device inode
     * @param private_data  Driver-private data from open()
     * @param u_buf         Kernel buffer containing data to write
     * @param n             Number of bytes to write
     * @param pos           File position (updated on success)
     * @return Bytes written on success, negative errno on failure
     */
    ssize_t (*write)(void *inode, void *private_data, const void *u_buf, size_t n, off_t *pos);

    /**
     * Device-specific control operations.
     * @param inode         Device inode
     * @param private_data  Driver-private data from open()
     * @param req           Request code (device-specific)
     * @param arg           Request argument (interpretation varies by req)
     * @return 0 on success, negative errno on failure
     */
    int     (*ioctl)(void *inode, void *private_data, unsigned long req, unsigned long arg);

    /**
     * Map device memory into userspace.
     * @param inode         Device inode
     * @param private_data  Driver-private data from open()
     * @param u_addr        Requested userspace address (or NULL for kernel choice)
     * @param len           Length of mapping
     * @param off           Offset into device
     * @param prot          Protection flags (PROT_READ, PROT_WRITE)
     * @param flags         Mapping flags (MAP_SHARED, MAP_PRIVATE)
     * @return Mapped address on success, NULL on failure
     */
    void   *(*mmap)(void *inode, void *private_data, void *u_addr, size_t len, off_t off, int prot, int flags);
};

/**
 * Register a character device driver.
 *
 * Associates a major/minor number pair with a set of file operations.
 * The device can then be accessed via devfs after devfs_create_chr().
 *
 * @param major        Major device number (driver class)
 * @param minor        Minor device number (specific instance)
 * @param fops         File operations for this device
 * @param name         Human-readable device name (for debugging)
 * @param driver_data  Driver-private data passed to open()
 * @return 0 on success, negative errno on failure
 */
int  chrdev_register(unsigned major, unsigned minor, const struct fut_file_ops *fops,
                     const char *name, void *driver_data);

/**
 * Look up a character device by major/minor number.
 *
 * Returns the file operations for a registered device, or NULL if
 * no device is registered with the given numbers.
 *
 * @param major    Major device number to look up
 * @param minor    Minor device number to look up
 * @param out_drv  Output: driver-private data (may be NULL)
 * @return File operations pointer, or NULL if not found
 */
const struct fut_file_ops *chrdev_lookup(unsigned major, unsigned minor, void **out_drv);

/**
 * Allocate a file descriptor for an open character device.
 *
 * Creates a new file descriptor in the current process's file table
 * pointing to the given device.
 *
 * @param ops    File operations for the device
 * @param inode  Device inode (passed to callbacks)
 * @param priv   Private data for this open instance
 * @return File descriptor number (>= 0) on success, negative errno on failure
 */
int  chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);

// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/console.h>
#include <platform/platform.h>

#define CONSOLE_MAJOR 4
#define CONSOLE_MINOR 0

static int console_open(void *inode, int flags, void **priv) {
    (void)inode;
    (void)flags;
    if (priv) {
        *priv = NULL;
    }
    return 0;
}

static ssize_t console_read(void *inode, void *priv, void *buf, size_t len, off_t *pos) {
    (void)inode;
    (void)priv;

    if (len == 0) {
        return 0;
    }

    uint8_t *bytes = (uint8_t *)buf;
    size_t bytes_read = 0;

    /* Read characters from serial port */
    while (bytes_read < len) {
        int c = fut_serial_getc_blocking();
        if (c < 0) {
            break;  /* Should not happen with blocking read, but be safe */
        }

        /* Handle special characters */
        if (c == '\r') {
            c = '\n';  /* Convert CR to LF */
        }

        bytes[bytes_read++] = (uint8_t)c;

        /* Echo character back to console */
        fut_serial_putc((char)c);
        if (c == '\n') {
            fut_serial_putc('\r');  /* Echo CR after LF */
        }

        /* Stop reading after newline */
        if (c == '\n') {
            break;
        }
    }

    if (pos) {
        *pos += (off_t)bytes_read;
    }

    return (ssize_t)bytes_read;
}

static ssize_t console_write(void *inode, void *priv, const void *buf, size_t len, off_t *pos) {
    (void)inode;
    (void)priv;

    const uint8_t *bytes = (const uint8_t *)buf;
    for (size_t i = 0; i < len; ++i) {
        char c = (char)bytes[i];
        if (c == '\n') {
            fut_serial_putc('\r');
        }
        fut_serial_putc(c);
    }

    if (pos) {
        *pos += (off_t)len;
    }
    return (ssize_t)len;
}

static const struct fut_file_ops console_fops = {
    .open = console_open,
    .release = NULL,
    .read = console_read,
    .write = console_write,
    .ioctl = NULL,
    .mmap = NULL,
};

void fut_console_init(void) {
    (void)chrdev_register(CONSOLE_MAJOR, CONSOLE_MINOR, &console_fops, "console", NULL);
    (void)devfs_create_chr("/dev/console", CONSOLE_MAJOR, CONSOLE_MINOR);
}

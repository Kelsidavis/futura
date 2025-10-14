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
    .read = NULL,
    .write = console_write,
    .ioctl = NULL,
    .mmap = NULL,
};

void fut_console_init(void) {
    (void)chrdev_register(CONSOLE_MAJOR, CONSOLE_MINOR, &console_fops, "console", NULL);
    (void)devfs_create_chr("/dev/console", CONSOLE_MAJOR, CONSOLE_MINOR);
}

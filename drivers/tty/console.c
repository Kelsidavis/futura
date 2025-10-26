// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>

#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/console.h>
#include <kernel/tty.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/signal.h>
#include <platform/platform.h>

#define CONSOLE_MAJOR 4
#define CONSOLE_MINOR 0

/* Global line discipline for the console */
static tty_ldisc_t console_ldisc;

extern void fut_printf(const char *fmt, ...);
extern void fut_task_signal_exit(int sig);

/**
 * Echo callback - outputs a character to the serial port.
 */
static void console_echo(char c) {
    fut_serial_putc(c);
}

/**
 * Signal callback - sends signal to current task.
 */
static void console_signal(int sig) {
    fut_printf("[CONSOLE] Received signal %d\n", sig);
    fut_task_signal_exit(sig);
}

/**
 * Input thread - continuously reads from serial and feeds line discipline.
 * TEMPORARILY DISABLED for DMA race condition debugging.
 */
#if 0
static void console_input_thread(void *arg) {
    (void)arg;

    fut_printf("[CONSOLE] Input thread started\n");

    while (1) {
        /* Read character from serial (blocking) */
        int c = fut_serial_getc_blocking();
        if (c >= 0) {
            /* Feed to line discipline */
            tty_ldisc_input(&console_ldisc, (char)c);
        }
    }
}
#endif

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

    /* Read from line discipline - handles blocking and line buffering */
    ssize_t bytes_read = tty_ldisc_read(&console_ldisc, buf, len);

    if (bytes_read > 0 && pos) {
        *pos += (off_t)bytes_read;
    }

    return bytes_read;
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
    /* Initialize line discipline with echo and signal callbacks */
    tty_ldisc_init(&console_ldisc, console_echo, console_signal);

    /* TEMPORARY: Disable console input thread to debug DMA corruption */
    fut_printf("[CONSOLE] Input thread temporarily disabled for debugging\n");

#if 0
    /* Create a task for the input thread */
    fut_task_t *console_task = fut_task_create();
    if (!console_task) {
        fut_printf("[CONSOLE] ERROR: Failed to create console task\n");
        return;
    }

    /* Create input thread that feeds characters from serial to line discipline */
    fut_thread_t *input_thread = fut_thread_create(
        console_task,
        console_input_thread,
        NULL,
        8192,  // 8KB stack
        100    // Medium priority
    );

    if (!input_thread) {
        fut_printf("[CONSOLE] ERROR: Failed to create input thread\n");
        return;
    }
#endif

    /* Register character device */
    (void)chrdev_register(CONSOLE_MAJOR, CONSOLE_MINOR, &console_fops, "console", NULL);
    (void)devfs_create_chr("/dev/console", CONSOLE_MAJOR, CONSOLE_MINOR);

    fut_printf("[CONSOLE] Initialized with line discipline (canonical mode, echo enabled)\n");
}

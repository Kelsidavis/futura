/* kernel/sys_syslog.c - Kernel log buffer access
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syslog() for reading and managing the kernel log buffer.
 * Used by dmesg(1) and system logging daemons.
 */

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

/* syslog command constants (Linux ABI) */
#define SYSLOG_ACTION_CLOSE          0  /* Close the log (no-op) */
#define SYSLOG_ACTION_OPEN           1  /* Open the log (no-op) */
#define SYSLOG_ACTION_READ           2  /* Read from the log */
#define SYSLOG_ACTION_READ_ALL       3  /* Read all messages in buffer */
#define SYSLOG_ACTION_READ_CLEAR     4  /* Read and clear all */
#define SYSLOG_ACTION_CLEAR          5  /* Clear the ring buffer */
#define SYSLOG_ACTION_CONSOLE_OFF    6  /* Disable console logging */
#define SYSLOG_ACTION_CONSOLE_ON     7  /* Enable console logging */
#define SYSLOG_ACTION_CONSOLE_LEVEL  8  /* Set console log level */
#define SYSLOG_ACTION_SIZE_UNREAD    9  /* Return unread count */
#define SYSLOG_ACTION_SIZE_BUFFER   10  /* Return total buffer size */

/* Kernel log ring buffer */
#define KLOG_BUF_SIZE  (64 * 1024)  /* 64KB ring buffer */
static char klog_buf[KLOG_BUF_SIZE];
static size_t klog_write_pos = 0;   /* Next write position */
static size_t klog_read_pos = 0;    /* Next read position for ACTION_READ */
static size_t klog_count = 0;       /* Total bytes in buffer */
static int klog_console_level = 7;  /* Default: show all but debug */

/**
 * klog_write - Append data to the kernel log buffer
 *
 * Called by kprintf infrastructure to record kernel messages.
 * This is a ring buffer — old data is overwritten when full.
 */
void klog_write(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        klog_buf[klog_write_pos] = data[i];
        klog_write_pos = (klog_write_pos + 1) % KLOG_BUF_SIZE;
        if (klog_count < KLOG_BUF_SIZE) {
            klog_count++;
        } else {
            /* Buffer full — advance read position */
            klog_read_pos = (klog_read_pos + 1) % KLOG_BUF_SIZE;
        }
    }
}

/**
 * sys_syslog - Read and manage kernel log buffer
 *
 * @param type: Command (SYSLOG_ACTION_*)
 * @param buf:  User buffer for read operations
 * @param len:  Buffer length
 *
 * Returns:
 *   - Number of bytes read (for read operations)
 *   - Buffer/unread size (for size queries)
 *   - 0 on success for other operations
 *   - -EINVAL for unknown type
 *   - -EPERM for unprivileged access to restricted operations
 */
long sys_syslog(int type, char *buf, int len) {
    fut_task_t *task = fut_task_current();

    switch (type) {
    case SYSLOG_ACTION_CLOSE:
    case SYSLOG_ACTION_OPEN:
        /* No-op — log is always available */
        return 0;

    case SYSLOG_ACTION_READ: {
        /* Read and consume from log */
        if (!buf || len <= 0) {
            return -EINVAL;
        }

        size_t to_read = (size_t)len;
        size_t available = klog_count - (klog_write_pos >= klog_read_pos ?
            klog_write_pos - klog_read_pos : KLOG_BUF_SIZE - klog_read_pos + klog_write_pos);

        /* If nothing to read, return 0 (would block in real implementation) */
        if (klog_read_pos == klog_write_pos) {
            return 0;
        }

        (void)available;  /* Used implicitly via ring buffer positions */
        size_t bytes_read = 0;
        char kbuf[256];

        while (bytes_read < to_read && klog_read_pos != klog_write_pos) {
            size_t chunk = to_read - bytes_read;
            if (chunk > sizeof(kbuf)) chunk = sizeof(kbuf);

            size_t i;
            for (i = 0; i < chunk && klog_read_pos != klog_write_pos; i++) {
                kbuf[i] = klog_buf[klog_read_pos];
                klog_read_pos = (klog_read_pos + 1) % KLOG_BUF_SIZE;
            }

            if (fut_copy_to_user(buf + bytes_read, kbuf, i) != 0) {
                return bytes_read > 0 ? (long)bytes_read : -EFAULT;
            }
            bytes_read += i;
        }

        return (long)bytes_read;
    }

    case SYSLOG_ACTION_READ_ALL:
    case SYSLOG_ACTION_READ_CLEAR: {
        /* Read entire buffer (non-destructive for READ_ALL) */
        if (!buf || len <= 0) {
            return -EINVAL;
        }

        size_t to_read = ((size_t)len < klog_count) ? (size_t)len : klog_count;
        size_t start = (klog_write_pos >= to_read) ?
            klog_write_pos - to_read :
            KLOG_BUF_SIZE - (to_read - klog_write_pos);

        char kbuf[256];
        size_t bytes_written = 0;

        while (bytes_written < to_read) {
            size_t chunk = to_read - bytes_written;
            if (chunk > sizeof(kbuf)) chunk = sizeof(kbuf);

            for (size_t i = 0; i < chunk; i++) {
                kbuf[i] = klog_buf[(start + bytes_written + i) % KLOG_BUF_SIZE];
            }

            if (fut_copy_to_user(buf + bytes_written, kbuf, chunk) != 0) {
                return bytes_written > 0 ? (long)bytes_written : -EFAULT;
            }
            bytes_written += chunk;
        }

        if (type == SYSLOG_ACTION_READ_CLEAR) {
            klog_count = 0;
            klog_read_pos = klog_write_pos;
        }

        return (long)bytes_written;
    }

    case SYSLOG_ACTION_CLEAR:
        /* Clear the ring buffer */
        if (task && task->uid != 0) {
            return -EPERM;
        }
        klog_count = 0;
        klog_read_pos = klog_write_pos;
        return 0;

    case SYSLOG_ACTION_CONSOLE_OFF:
        klog_console_level = 0;
        return 0;

    case SYSLOG_ACTION_CONSOLE_ON:
        klog_console_level = 7;
        return 0;

    case SYSLOG_ACTION_CONSOLE_LEVEL:
        if (len < 1 || len > 8) {
            return -EINVAL;
        }
        klog_console_level = len;
        return 0;

    case SYSLOG_ACTION_SIZE_UNREAD: {
        /* Return bytes available to read */
        if (klog_write_pos >= klog_read_pos) {
            return (long)(klog_write_pos - klog_read_pos);
        }
        return (long)(KLOG_BUF_SIZE - klog_read_pos + klog_write_pos);
    }

    case SYSLOG_ACTION_SIZE_BUFFER:
        return KLOG_BUF_SIZE;

    default:
        return -EINVAL;
    }
}

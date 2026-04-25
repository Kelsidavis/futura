/* kernel/sys_syslog.c - Kernel log buffer access
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements syslog() for reading and managing the kernel log buffer.
 * Used by dmesg(1) and system logging daemons.
 *
 * Ring buffer design:
 *   - klog_buf[KLOG_BUF_SIZE]: circular buffer holding kernel messages
 *   - klog_head: index of oldest byte in the ring (start of valid data)
 *   - klog_tail: index where the next byte will be written
 *   - klog_count: total valid bytes in the buffer (0..KLOG_BUF_SIZE)
 *   - klog_read_pos: consumer cursor for SYSLOG_ACTION_READ (advances on read)
 *
 * When the buffer is full, new writes overwrite the oldest data by advancing
 * klog_head (and klog_read_pos if it falls behind klog_head).
 */

#include <kernel/fut_task.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/fut_timer.h>
#include <stdint.h>
#include <stddef.h>

#include <platform/platform.h>

static inline int syslog_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* syslog command constants (Linux ABI) */
#define SYSLOG_ACTION_CLOSE          0  /* Close the log (no-op) */
#define SYSLOG_ACTION_OPEN           1  /* Open the log (no-op) */
#define SYSLOG_ACTION_READ           2  /* Read from the log (consume) */
#define SYSLOG_ACTION_READ_ALL       3  /* Read all messages without consuming */
#define SYSLOG_ACTION_READ_CLEAR     4  /* Read and clear all */
#define SYSLOG_ACTION_CLEAR          5  /* Clear the ring buffer */
#define SYSLOG_ACTION_CONSOLE_OFF    6  /* Disable console logging */
#define SYSLOG_ACTION_CONSOLE_ON     7  /* Enable console logging */
#define SYSLOG_ACTION_CONSOLE_LEVEL  8  /* Set console log level */
#define SYSLOG_ACTION_SIZE_UNREAD    9  /* Return unread count */
#define SYSLOG_ACTION_SIZE_BUFFER   10  /* Return total buffer size */

/* ============================================================
 *   64KB Kernel Log Ring Buffer
 * ============================================================ */

#define KLOG_BUF_SIZE  (64 * 1024)  /* 64KB ring buffer */

/* Non-static so /dev/kmsg and /proc/kmsg can access */
char klog_buf[KLOG_BUF_SIZE];
size_t klog_head = 0;        /* Index of oldest valid byte */
size_t klog_tail = 0;        /* Index where next byte is written */
size_t klog_count = 0;       /* Total valid bytes in buffer (0..KLOG_BUF_SIZE) */

/* Kept for ABI compatibility with existing /dev/kmsg code */
size_t klog_write_pos = 0;

/* Consumer read cursor for SYSLOG_ACTION_READ (2) — advances on read */
static size_t klog_read_pos = 0;

static int klog_console_level = 7;  /* Default: show all but debug */

/* Track whether we're at the start of a new line for timestamp injection */
static int klog_at_line_start = 1;

/**
 * klog_unread - Return bytes between read cursor and tail
 *
 * This is the number of bytes available for SYSLOG_ACTION_READ (consume).
 * After a clear, read_pos == tail so unread == 0.
 * If the ring overflows past read_pos, read_pos is clamped to head.
 */
static size_t klog_unread(void) {
    /* If read cursor fell behind head (ring overflow), snap to oldest data */
    if (klog_count == KLOG_BUF_SIZE && klog_read_pos != klog_head) {
        /* Check if read_pos is in the overwritten region.
         * In a full buffer, the only valid range is [head..tail) mod size.
         * If read_pos != head and buffer is full, read_pos may be stale. */
        size_t dist_from_head;
        if (klog_read_pos >= klog_head)
            dist_from_head = klog_read_pos - klog_head;
        else
            dist_from_head = KLOG_BUF_SIZE - klog_head + klog_read_pos;
        if (dist_from_head > klog_count) {
            /* read_pos was overwritten — reset to head */
            klog_read_pos = klog_head;
        }
    }

    if (klog_tail >= klog_read_pos)
        return klog_tail - klog_read_pos;
    return KLOG_BUF_SIZE - klog_read_pos + klog_tail;
}

/* Write a single byte to the ring buffer */
static void klog_put(char c) {
    klog_buf[klog_tail] = c;
    klog_tail = (klog_tail + 1) % KLOG_BUF_SIZE;
    klog_write_pos = klog_tail;  /* Keep alias in sync */

    if (klog_count < KLOG_BUF_SIZE) {
        klog_count++;
    } else {
        /* Buffer full — oldest byte is overwritten, advance head */
        klog_head = (klog_head + 1) % KLOG_BUF_SIZE;
        /* If the consumer read cursor was pointing at the overwritten byte,
         * advance it too so it stays within valid data. */
        if (klog_read_pos == ((klog_tail + KLOG_BUF_SIZE - 1) % KLOG_BUF_SIZE)) {
            klog_read_pos = klog_head;
        }
    }
}

/**
 * klog_write - Append data to the kernel log buffer
 *
 * Called by kprintf infrastructure (via fut_serial_putc) to record kernel
 * messages.  This is a ring buffer — old data is overwritten when full.
 * Prepends [seconds.microseconds] timestamp at the start of each line.
 */
void klog_write(const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (klog_at_line_start && data[i] != '\n') {
            /* Inject timestamp: [secs.usecs] */
            uint64_t ticks = fut_get_ticks();
            uint32_t hz = FUT_TIMER_HZ;
            uint64_t secs = ticks / hz;
            uint64_t usecs = ((ticks % hz) * 1000000ULL) / hz;

            klog_put('[');
            /* Write seconds */
            char numbuf[12];
            int pos = 0;
            uint64_t tmp = secs;
            if (tmp == 0) { numbuf[pos++] = '0'; }
            else {
                char rev[12]; int rp = 0;
                while (tmp > 0) { rev[rp++] = '0' + (tmp % 10); tmp /= 10; }
                while (rp > 0) { numbuf[pos++] = rev[--rp]; }
            }
            for (int j = 0; j < pos; j++) klog_put(numbuf[j]);
            klog_put('.');
            /* Write microseconds (6 digits, zero-padded) */
            for (int d = 5; d >= 0; d--) {
                uint64_t div = 1;
                for (int k = 0; k < d; k++) div *= 10;
                klog_put('0' + (char)((usecs / div) % 10));
            }
            klog_put(']');
            klog_put(' ');
            klog_at_line_start = 0;
        }

        klog_put(data[i]);

        if (data[i] == '\n') {
            klog_at_line_start = 1;
        }
    }
}

/**
 * klog_read_buffer - Read data from the ring buffer without consuming
 *
 * Copies up to @len bytes from the ring buffer into @dst, starting from
 * the oldest data (klog_head).  Used by READ_ALL and /proc/kmsg.
 *
 * @dst:    Destination buffer (kernel pointer)
 * @len:    Maximum bytes to copy
 * @return: Actual bytes copied
 */
size_t klog_read_buffer(char *dst, size_t len) {
    if (klog_count == 0 || len == 0) return 0;
    size_t to_copy = (len < klog_count) ? len : klog_count;
    size_t src = klog_head;
    for (size_t i = 0; i < to_copy; i++) {
        dst[i] = klog_buf[(src + i) % KLOG_BUF_SIZE];
    }
    return to_copy;
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

    /* Linux: syslog(2) requires CAP_SYSLOG (or CAP_SYS_ADMIN, which is
     * accepted for backward compat) for every action except CLOSE/OPEN
     * and SIZE_BUFFER. Without this gate any process can dump the whole
     * kernel ring buffer (kernel pointers, addresses printed by drivers,
     * boot-time secrets) and silence the console. */
    int needs_cap = 0;
    switch (type) {
        case SYSLOG_ACTION_READ:
        case SYSLOG_ACTION_READ_ALL:
        case SYSLOG_ACTION_READ_CLEAR:
        case SYSLOG_ACTION_CLEAR:
        case SYSLOG_ACTION_CONSOLE_OFF:
        case SYSLOG_ACTION_CONSOLE_ON:
        case SYSLOG_ACTION_CONSOLE_LEVEL:
        case SYSLOG_ACTION_SIZE_UNREAD:
            needs_cap = 1;
            break;
        default:
            break;
    }
    if (needs_cap && task && task->uid != 0 &&
        !(task->cap_effective & (1ULL << 34 /* CAP_SYSLOG */)) &&
        !(task->cap_effective & (1ULL << 21 /* CAP_SYS_ADMIN */))) {
        return -EPERM;
    }

    switch (type) {
    case SYSLOG_ACTION_CLOSE:
    case SYSLOG_ACTION_OPEN:
        /* No-op — log is always available */
        return 0;

    case SYSLOG_ACTION_READ: {
        /* Read and consume from log (advances read cursor) */
        if (!buf || len <= 0) {
            return -EINVAL;
        }

        size_t unread = klog_unread();
        if (unread == 0) {
            return 0;  /* Nothing to read */
        }

        size_t to_read = (size_t)len;
        if (to_read > unread) to_read = unread;

        size_t bytes_read = 0;
        char kbuf[256];

        while (bytes_read < to_read) {
            size_t chunk = to_read - bytes_read;
            if (chunk > sizeof(kbuf)) chunk = sizeof(kbuf);

            for (size_t i = 0; i < chunk; i++) {
                kbuf[i] = klog_buf[klog_read_pos];
                klog_read_pos = (klog_read_pos + 1) % KLOG_BUF_SIZE;
            }

            if (syslog_copy_to_user(buf + bytes_read, kbuf, chunk) != 0) {
                return bytes_read > 0 ? (long)bytes_read : -EFAULT;
            }
            bytes_read += chunk;
        }

        return (long)bytes_read;
    }

    case SYSLOG_ACTION_READ_ALL:
    case SYSLOG_ACTION_READ_CLEAR: {
        /* Read entire buffer contents (oldest to newest).
         * READ_ALL (3): non-destructive, does not advance any cursor.
         * READ_CLEAR (4): reads everything then clears the buffer. */
        if (!buf || len <= 0) {
            return -EINVAL;
        }

        size_t to_read = ((size_t)len < klog_count) ? (size_t)len : klog_count;
        /* Start from oldest data (klog_head) */
        size_t start = klog_head;
        /* If user buffer is smaller than klog_count, skip oldest to show
         * the most recent to_read bytes (same as Linux dmesg behavior). */
        if (to_read < klog_count) {
            size_t skip = klog_count - to_read;
            start = (klog_head + skip) % KLOG_BUF_SIZE;
        }

        char kbuf[256];
        size_t bytes_written = 0;

        while (bytes_written < to_read) {
            size_t chunk = to_read - bytes_written;
            if (chunk > sizeof(kbuf)) chunk = sizeof(kbuf);

            for (size_t i = 0; i < chunk; i++) {
                kbuf[i] = klog_buf[(start + bytes_written + i) % KLOG_BUF_SIZE];
            }

            if (syslog_copy_to_user(buf + bytes_written, kbuf, chunk) != 0) {
                return bytes_written > 0 ? (long)bytes_written : -EFAULT;
            }
            bytes_written += chunk;
        }

        if (type == SYSLOG_ACTION_READ_CLEAR) {
            klog_count = 0;
            klog_head = klog_tail;
            klog_read_pos = klog_tail;
        }

        return (long)bytes_written;
    }

    case SYSLOG_ACTION_CLEAR:
        /* Clear the ring buffer (capability checked above). */
        klog_count = 0;
        klog_head = klog_tail;
        klog_read_pos = klog_tail;
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

    case SYSLOG_ACTION_SIZE_UNREAD:
        /* Return bytes available to the consume-read cursor */
        return (long)klog_unread();

    case SYSLOG_ACTION_SIZE_BUFFER:
        return KLOG_BUF_SIZE;

    default:
        return -EINVAL;
    }
}

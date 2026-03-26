/* kernel/dev_watchdog.c - Software watchdog timer (/dev/watchdog)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a Linux-compatible software watchdog timer device.
 * When a process opens /dev/watchdog, it must write to it periodically
 * (default: every 60 seconds). If the watchdog is not fed in time,
 * the system reboots automatically.
 *
 * This is critical for router/server deployments where a hung process
 * should trigger an automatic recovery.
 *
 * Supported operations:
 *   - open(): starts the watchdog timer
 *   - write(): feeds the watchdog (any data, or 'V' for magic close)
 *   - ioctl(WDIOC_SETTIMEOUT): set timeout in seconds
 *   - ioctl(WDIOC_GETTIMEOUT): get current timeout
 *   - ioctl(WDIOC_KEEPALIVE): feed the watchdog
 *   - close(): stops watchdog only if magic close ('V') was written
 */

#include <kernel/chrdev.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Watchdog ioctls (Linux compatible) */
#define WDIOC_GETSUPPORT    0x80285700
#define WDIOC_SETTIMEOUT    0xC0045706
#define WDIOC_GETTIMEOUT    0x80045707
#define WDIOC_KEEPALIVE     0x80045705
#define WDIOC_GETTIMELEFT   0x80045709

/* Watchdog state */
static struct {
    bool     active;            /* Watchdog is running */
    bool     expect_close;      /* Magic close character 'V' was written */
    uint32_t timeout_sec;       /* Timeout in seconds (default 60) */
    uint64_t last_fed_ticks;    /* Tick count when last fed */
    int      owner_pid;         /* PID of process that opened watchdog */
} g_watchdog = {
    .active = false,
    .timeout_sec = 60,
};

/* Check if watchdog has expired (called from timer tick) */
void watchdog_check(void) {
    if (!g_watchdog.active) return;

    uint64_t now = fut_get_ticks();
    uint64_t deadline = g_watchdog.last_fed_ticks +
                        (uint64_t)g_watchdog.timeout_sec * 100;  /* ticks = sec * 100 Hz */

    if (now > deadline) {
        fut_printf("\n[WATCHDOG] *** WATCHDOG TIMEOUT *** (not fed for %u seconds)\n",
                   g_watchdog.timeout_sec);
        fut_printf("[WATCHDOG] Initiating emergency reboot...\n");

        /* Trigger reboot via ACPI/PSCI */
#ifdef __x86_64__
        /* QEMU debug exit port */
        __asm__ volatile("outw %0, %1" :: "a"((uint16_t)0x2000), "Nd"((uint16_t)0x604));
        /* Triple fault fallback */
        struct { uint16_t limit; uint64_t base; } __attribute__((packed)) null_idt = {0, 0};
        __asm__ volatile("lidt %0; int3" :: "m"(null_idt));
#elif defined(__aarch64__)
        {
            register uint64_t x0 __asm__("x0") = 0x84000009ULL;
            __asm__ volatile("hvc #0" :: "r"(x0));
        }
#endif
        for (;;) {
#ifdef __x86_64__
            __asm__ volatile("cli; hlt");
#elif defined(__aarch64__)
            __asm__ volatile("wfi");
#endif
        }
    }
}

/* Character device operations */
static ssize_t watchdog_read(void *inode, void *priv, void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    /* Return time left until expiry */
    if (n < sizeof(uint32_t)) return -EINVAL;
    if (!g_watchdog.active) return 0;

    uint64_t now = fut_get_ticks();
    uint64_t deadline = g_watchdog.last_fed_ticks +
                        (uint64_t)g_watchdog.timeout_sec * 100;
    uint32_t left = 0;
    if (deadline > now) {
        left = (uint32_t)((deadline - now) / 100);
    }
    memcpy(buf, &left, sizeof(left));
    return sizeof(left);
}

static ssize_t watchdog_write(void *inode, void *priv, const void *buf, size_t n, off_t *pos) {
    (void)inode; (void)priv; (void)pos;
    if (n == 0) return 0;

    /* First write starts the watchdog if not already active */
    if (!g_watchdog.active) {
        g_watchdog.active = true;
        g_watchdog.expect_close = false;
        g_watchdog.last_fed_ticks = fut_get_ticks();
        fut_task_t *task = fut_task_current();
        g_watchdog.owner_pid = task ? (int)task->pid : 0;
        fut_printf("[WATCHDOG] Started (timeout=%us, pid=%d)\n",
                   g_watchdog.timeout_sec, g_watchdog.owner_pid);
    }

    /* Any write feeds the watchdog */
    g_watchdog.last_fed_ticks = fut_get_ticks();

    /* Check for magic close character 'V' */
    const char *data = (const char *)buf;
    for (size_t i = 0; i < n; i++) {
        if (data[i] == 'V') {
            g_watchdog.expect_close = true;
        }
    }

    return (ssize_t)n;
}

static int watchdog_ioctl(void *inode, void *priv, unsigned long request,
                          unsigned long arg) {
    (void)inode; (void)priv;
    switch (request) {
        case WDIOC_SETTIMEOUT: {
            uint32_t timeout = (uint32_t)arg;
            if (timeout < 1 || timeout > 3600) return -EINVAL;
            g_watchdog.timeout_sec = timeout;
            g_watchdog.last_fed_ticks = fut_get_ticks();  /* Reset timer */
            return 0;
        }
        case WDIOC_GETTIMEOUT: {
            /* arg is pointer to uint32_t */
            if (!arg) return -EFAULT;
            *(uint32_t *)(uintptr_t)arg = g_watchdog.timeout_sec;
            return 0;
        }
        case WDIOC_KEEPALIVE:
            g_watchdog.last_fed_ticks = fut_get_ticks();
            return 0;
        case WDIOC_GETTIMELEFT: {
            if (!arg) return -EFAULT;
            uint64_t now = fut_get_ticks();
            uint64_t deadline = g_watchdog.last_fed_ticks +
                                (uint64_t)g_watchdog.timeout_sec * 100;
            uint32_t left = (deadline > now) ? (uint32_t)((deadline - now) / 100) : 0;
            *(uint32_t *)(uintptr_t)arg = left;
            return 0;
        }
        default:
            return -ENOTTY;
    }
}

static struct fut_file_ops watchdog_ops;

void watchdog_init(void) {
    watchdog_ops.read  = watchdog_read;
    watchdog_ops.write = watchdog_write;
    watchdog_ops.ioctl = watchdog_ioctl;

    extern int chrdev_register(unsigned, unsigned, const struct fut_file_ops *,
                               const char *, void *);
    extern int devfs_create_chr(const char *, unsigned, unsigned);

    /* major 10, minor 130 = /dev/watchdog (Linux standard) */
    chrdev_register(10, 130, &watchdog_ops, "watchdog", NULL);
    devfs_create_chr("/dev/watchdog", 10, 130);

    fut_printf("[WATCHDOG] Software watchdog initialized (timeout=%us)\n",
               g_watchdog.timeout_sec);
}

/* Called when /dev/watchdog is opened — start the timer */
void watchdog_on_open(void) {
    if (g_watchdog.active) return;  /* Already active */
    g_watchdog.active = true;
    g_watchdog.expect_close = false;
    g_watchdog.last_fed_ticks = fut_get_ticks();
    fut_task_t *task = fut_task_current();
    g_watchdog.owner_pid = task ? (int)task->pid : 0;
    fut_printf("[WATCHDOG] Started (timeout=%us, pid=%d)\n",
               g_watchdog.timeout_sec, g_watchdog.owner_pid);
}

/* Called when /dev/watchdog is closed */
void watchdog_on_close(void) {
    if (!g_watchdog.active) return;
    if (g_watchdog.expect_close) {
        /* Magic close — stop the watchdog */
        g_watchdog.active = false;
        fut_printf("[WATCHDOG] Stopped (magic close)\n");
    } else {
        /* No magic close — watchdog keeps running!
         * This is Linux behavior: closing without writing 'V' means
         * the watchdog will eventually expire and reboot. */
        fut_printf("[WATCHDOG] Device closed without magic close — timer continues!\n");
    }
}

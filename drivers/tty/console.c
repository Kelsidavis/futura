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
#include <shared/termios.h>

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

#if 1
/**
 * Input thread - continuously reads from serial and feeds line discipline.
 */
static void console_input_thread(void *arg) {
    (void)arg;

    /* Note: This message may appear multiple times due to scheduler thread switching.
     * The thread only executes once when created, but may be preempted and rescheduled.
     * This is normal behavior - only one instance of the thread actually runs continuously. */
    static bool started = false;
    if (!started) {
        started = true;
        fut_printf("[CONSOLE] Input thread started\n");
    }

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

    /* Write to both serial console AND framebuffer console */
    extern void fb_console_write(const char *str, size_t len);
    fb_console_write((const char *)buf, len);

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

/**
 * Console ioctl - handles terminal control operations.
 */
static int console_ioctl(void *inode, void *priv, unsigned long req, unsigned long arg) {
    (void)inode;
    (void)priv;

    switch (req) {
        case TCGETS: {
            /* Get terminal settings */
            struct termios *tp = (struct termios *)arg;
            if (!tp) {
                return -EFAULT;
            }
            return tty_ldisc_get_termios(&console_ldisc, tp);
        }

        case TCSETS:
        case TCSETSW:
        case TCSETSF: {
            /* Set terminal settings (TCSETSW/F: after drain/flush - not fully implemented) */
            const struct termios *tp = (const struct termios *)arg;
            if (!tp) {
                return -EFAULT;
            }
            return tty_ldisc_set_termios(&console_ldisc, tp);
        }

        case TIOCGWINSZ: {
            /* Get window size */
            struct winsize *ws = (struct winsize *)arg;
            if (!ws) {
                return -EFAULT;
            }
            return tty_ldisc_get_winsize(&console_ldisc, ws);
        }

        case TIOCSWINSZ: {
            /* Set window size */
            const struct winsize *ws = (const struct winsize *)arg;
            if (!ws) {
                return -EFAULT;
            }
            return tty_ldisc_set_winsize(&console_ldisc, ws);
        }

        case FIONREAD: {
            /* Get bytes available to read */
            int *count = (int *)arg;
            if (!count) {
                return -EFAULT;
            }
            *count = (int)tty_ldisc_bytes_available(&console_ldisc);
            return 0;
        }

        default:
            fut_printf("[CONSOLE] Unsupported ioctl: 0x%lx\n", req);
            return -ENOTTY;
    }
}

/* Console file operations - initialized at runtime to avoid relocation issues on ARM64 */
static struct fut_file_ops console_fops;

/* Global console task for input thread - created after scheduler init */
static fut_task_t *g_console_task = NULL;
static fut_thread_t *g_console_input_thread = NULL;

void fut_console_init(void) {
    /* Initialize console file operations at runtime */
    console_fops.open = console_open;
    console_fops.release = NULL;
    console_fops.read = console_read;
    console_fops.write = console_write;
    console_fops.ioctl = console_ioctl;
    console_fops.mmap = NULL;

    /* Initialize line discipline with echo and signal callbacks */
    tty_ldisc_init(&console_ldisc, console_echo, console_signal);

    /* Register character device - do this early, before scheduler */
    int ret1 = chrdev_register(CONSOLE_MAJOR, CONSOLE_MINOR, &console_fops, "console", NULL);
    int ret2 = devfs_create_chr("/dev/console", CONSOLE_MAJOR, CONSOLE_MINOR);

    if (ret1 < 0 || ret2 < 0) {
        fut_printf("[CONSOLE] ERROR: Failed to register device (chrdev=%d devfs=%d)\n", ret1, ret2);
    } else {
        fut_printf("[CONSOLE] Successfully registered /dev/console (major=%d minor=%d)\n",
                   CONSOLE_MAJOR, CONSOLE_MINOR);
    }

    fut_printf("[CONSOLE] Initialized with line discipline (canonical mode, echo enabled)\n");
    fut_printf("[CONSOLE] Input thread will be started after scheduler initialization\n");
}

/**
 * Start the console input thread. Must be called AFTER scheduler initialization.
 * This is called from kernel_main after fut_sched_init().
 */
void fut_console_start_input_thread(void) {
    /* Create a task for the input thread */
    g_console_task = fut_task_create();
    if (!g_console_task) {
        fut_printf("[CONSOLE] ERROR: Failed to create console task\n");
        return;
    }

    /* Create input thread that feeds characters from serial to line discipline */
    g_console_input_thread = fut_thread_create(
        g_console_task,
        console_input_thread,
        NULL,
        8192,  // 8KB stack
        100    // Medium priority
    );

    if (!g_console_input_thread) {
        fut_printf("[CONSOLE] ERROR: Failed to create input thread\n");
        return;
    }

    fut_printf("[CONSOLE] Input thread created and ready\n");
}

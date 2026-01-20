// SPDX-License-Identifier: MPL-2.0
/*
 * tty_ldisc.c - TTY line discipline implementation
 *
 * Provides canonical mode (line buffering), echo, line editing,
 * and control character handling for terminal devices.
 */

#include <kernel/tty.h>
#include <kernel/fut_waitq.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/signal.h>
#include <string.h>

extern void fut_printf(const char *fmt, ...);

/**
 * Initialize a TTY line discipline.
 */
void tty_ldisc_init(tty_ldisc_t *ldisc, void (*echo)(char), void (*signal)(int)) {
    memset(ldisc->input_buf, 0, sizeof(ldisc->input_buf));
    ldisc->read_pos = 0;
    ldisc->write_pos = 0;
    ldisc->line_start = 0;

    /* Enable canonical mode and echo by default */
    ldisc->flags = TTY_CANONICAL | TTY_ECHO | TTY_SIGNAL;

    /* Initialize POSIX termios with sensible defaults */
    memset(&ldisc->termios, 0, sizeof(ldisc->termios));
    ldisc->termios.c_iflag = TERMIOS_DEFAULT_IFLAG;
    ldisc->termios.c_oflag = TERMIOS_DEFAULT_OFLAG;
    ldisc->termios.c_cflag = TERMIOS_DEFAULT_CFLAG;
    ldisc->termios.c_lflag = TERMIOS_DEFAULT_LFLAG;
    ldisc->termios.c_line = 0;  /* N_TTY line discipline */

    /* Initialize control characters with defaults */
    ldisc->termios.c_cc[VINTR] = CINTR;
    ldisc->termios.c_cc[VQUIT] = CQUIT;
    ldisc->termios.c_cc[VERASE] = CERASE;
    ldisc->termios.c_cc[VKILL] = CKILL;
    ldisc->termios.c_cc[VEOF] = CEOF;
    ldisc->termios.c_cc[VTIME] = 0;
    ldisc->termios.c_cc[VMIN] = 1;
    ldisc->termios.c_cc[VSTART] = CSTART;
    ldisc->termios.c_cc[VSTOP] = CSTOP;
    ldisc->termios.c_cc[VSUSP] = CSUSP;
    ldisc->termios.c_cc[VEOL] = 0;
    ldisc->termios.c_cc[VREPRINT] = CREPRINT;
    ldisc->termios.c_cc[VDISCARD] = CDISCARD;
    ldisc->termios.c_cc[VWERASE] = CWERASE;
    ldisc->termios.c_cc[VLNEXT] = CLNEXT;

    /* Default baud rate */
    ldisc->termios.c_ispeed = B115200;
    ldisc->termios.c_ospeed = B115200;

    /* Initialize window size with sensible defaults */
    ldisc->winsize.ws_row = TTY_DEFAULT_ROWS;
    ldisc->winsize.ws_col = TTY_DEFAULT_COLS;
    ldisc->winsize.ws_xpixel = 0;
    ldisc->winsize.ws_ypixel = 0;

    /* Initialize spinlock for synchronizing buffer access */
    fut_spinlock_init(&ldisc->lock);

    /* Allocate wait queue */
    ldisc->read_waitq = (fut_waitq_t *)fut_pmm_alloc_page();
    if (ldisc->read_waitq) {
        fut_waitq_init(ldisc->read_waitq);
    }

    ldisc->echo = echo;
    ldisc->signal = signal;
}

/**
 * Echo a character (internal helper).
 */
static void ldisc_echo_char(tty_ldisc_t *ldisc, char c) {
    if (!ldisc->echo || !(ldisc->flags & TTY_ECHO)) {
        return;
    }

    ldisc->echo(c);
}

/**
 * Echo a string (internal helper).
 */
static void ldisc_echo_string(tty_ldisc_t *ldisc, const char *str) {
    if (!ldisc->echo || !(ldisc->flags & TTY_ECHO)) {
        return;
    }

    while (*str) {
        ldisc->echo(*str++);
    }
}

/**
 * Get the current buffer usage.
 */
static size_t buffer_used(const tty_ldisc_t *ldisc) {
    if (ldisc->write_pos >= ldisc->read_pos) {
        return ldisc->write_pos - ldisc->read_pos;
    } else {
        return TTY_INPUT_BUFFER_SIZE - ldisc->read_pos + ldisc->write_pos;
    }
}

/**
 * Get the current line length (from line_start to write_pos).
 * Currently unused but kept for potential future use.
 */
__attribute__((unused))
static size_t current_line_length(const tty_ldisc_t *ldisc) {
    if (ldisc->write_pos >= ldisc->line_start) {
        return ldisc->write_pos - ldisc->line_start;
    } else {
        return TTY_INPUT_BUFFER_SIZE - ldisc->line_start + ldisc->write_pos;
    }
}

/**
 * Check if buffer has a complete line (ends with \n).
 */
static bool has_complete_line(const tty_ldisc_t *ldisc) {
    size_t pos = ldisc->read_pos;
    size_t end = ldisc->write_pos;

    while (pos != end) {
        if (ldisc->input_buf[pos] == '\n') {
            return true;
        }
        pos = (pos + 1) % TTY_INPUT_BUFFER_SIZE;
    }

    return false;
}

/**
 * Erase the last character from the current line.
 */
static void erase_last_char(tty_ldisc_t *ldisc) {
    /* Can't erase beyond line start */
    if (ldisc->write_pos == ldisc->line_start) {
        return;
    }

    /* Move write position back */
    if (ldisc->write_pos == 0) {
        ldisc->write_pos = TTY_INPUT_BUFFER_SIZE - 1;
    } else {
        ldisc->write_pos--;
    }

    /* Echo backspace sequence to visually erase: backspace, space, backspace */
    if (ldisc->flags & TTY_ECHO && ldisc->echo) {
        ldisc->echo('\b');
        ldisc->echo(' ');
        ldisc->echo('\b');
    }
}

/**
 * Erase the entire current line.
 */
static void erase_line(tty_ldisc_t *ldisc) {
    while (ldisc->write_pos != ldisc->line_start) {
        erase_last_char(ldisc);
    }
}

/**
 * Process an input character through the line discipline.
 */
void tty_ldisc_input(tty_ldisc_t *ldisc, char c) {
    if (!ldisc) {
        return;  /* Safety check */
    }

    /* Acquire lock for buffer modification */
    fut_spinlock_acquire(&ldisc->lock);

    /* Handle special characters first */

    /* Backspace / Delete - erase last character */
    if (c == BS || c == DEL) {
        erase_last_char(ldisc);
        fut_spinlock_release(&ldisc->lock);
        return;
    }

    /* Ctrl+U - erase entire line */
    if (c == CTRL_U) {
        erase_line(ldisc);
        if (ldisc->flags & TTY_ECHO && ldisc->echo) {
            ldisc_echo_string(ldisc, "^U\r\n");
        }
        fut_spinlock_release(&ldisc->lock);
        return;
    }

    /* Ctrl+C - send SIGINT */
    if (c == CTRL_C) {
        if (ldisc->flags & TTY_SIGNAL && ldisc->signal) {
            if (ldisc->flags & TTY_ECHO) {
                ldisc_echo_string(ldisc, "^C\r\n");
            }
            ldisc->signal(SIGINT);
        }
        /* Clear current line */
        erase_line(ldisc);
        ldisc->line_start = ldisc->write_pos;
        fut_spinlock_release(&ldisc->lock);
        return;
    }

    /* Ctrl+D - EOF (return buffered data) */
    if (c == CTRL_D) {
        if (ldisc->flags & TTY_CANONICAL) {
            /* In canonical mode, Ctrl+D causes pending line to be returned */
            /* We insert a newline to complete the line */
            c = '\n';
        }
    }

    /* Ctrl+Z - send SIGTSTP */
    if (c == CTRL_Z) {
        if (ldisc->flags & TTY_SIGNAL && ldisc->signal) {
            if (ldisc->flags & TTY_ECHO) {
                ldisc_echo_string(ldisc, "^Z\r\n");
            }
            ldisc->signal(SIGTSTP);
        }
        /* Clear current line */
        erase_line(ldisc);
        ldisc->line_start = ldisc->write_pos;
        fut_spinlock_release(&ldisc->lock);
        return;
    }

    /* Convert CR to LF */
    if (c == '\r') {
        c = '\n';
    }

    /* Check for buffer overflow */
    size_t next_write = (ldisc->write_pos + 1) % TTY_INPUT_BUFFER_SIZE;
    if (next_write == ldisc->read_pos) {
        /* Buffer full - ring bell or ignore */
        if (ldisc->flags & TTY_ECHO && ldisc->echo) {
            ldisc->echo('\a');  /* Bell */
        }
        fut_spinlock_release(&ldisc->lock);
        return;
    }

    /* Insert character into buffer */
    ldisc->input_buf[ldisc->write_pos] = c;
    ldisc->write_pos = next_write;

    /* Echo the character */
    if (ldisc->flags & TTY_ECHO) {
        if (c == '\n') {
            ldisc_echo_char(ldisc, '\r');
            ldisc_echo_char(ldisc, '\n');
        } else if (c >= 32 && c < 127) {
            /* Printable character */
            ldisc_echo_char(ldisc, c);
        } else {
            /* Control character - echo as ^X */
            ldisc_echo_char(ldisc, '^');
            ldisc_echo_char(ldisc, c + '@');
        }
    }

    /* If newline, wake up readers in canonical mode */
    if (c == '\n' && (ldisc->flags & TTY_CANONICAL)) {
        if (ldisc->read_waitq) {
            fut_waitq_wake_all(ldisc->read_waitq);
        }
        ldisc->line_start = ldisc->write_pos;  /* Start new line */
    }

    /* In non-canonical mode, wake readers for any character */
    if (!(ldisc->flags & TTY_CANONICAL)) {
        if (ldisc->read_waitq) {
            fut_waitq_wake_all(ldisc->read_waitq);
        }
    }

    /* Release lock before returning */
    fut_spinlock_release(&ldisc->lock);
}

/**
 * Check if data is available to read.
 */
bool tty_ldisc_data_available(const tty_ldisc_t *ldisc) {
    if (ldisc->flags & TTY_CANONICAL) {
        /* In canonical mode, need a complete line */
        return has_complete_line(ldisc);
    } else {
        /* In raw mode, any data is available */
        return buffer_used(ldisc) > 0;
    }
}

/**
 * Get the number of bytes available to read.
 */
size_t tty_ldisc_bytes_available(const tty_ldisc_t *ldisc) {
    if (ldisc->flags & TTY_CANONICAL) {
        /* Count bytes up to and including first newline */
        size_t pos = ldisc->read_pos;
        size_t end = ldisc->write_pos;
        size_t count = 0;

        while (pos != end) {
            count++;
            if (ldisc->input_buf[pos] == '\n') {
                break;
            }
            pos = (pos + 1) % TTY_INPUT_BUFFER_SIZE;
        }

        return count;
    } else {
        /* In raw mode, all buffered data is available */
        return buffer_used(ldisc);
    }
}

/**
 * Read from the line discipline buffer.
 */
ssize_t tty_ldisc_read(tty_ldisc_t *ldisc, void *buf, size_t len) {
    if (len == 0) {
        return 0;
    }

    char *output = (char *)buf;
    size_t bytes_read = 0;

    /* Acquire lock before accessing buffer */
    fut_spinlock_acquire(&ldisc->lock);

    /* In canonical mode, block until a complete line is available */
    if (ldisc->flags & TTY_CANONICAL) {
        while (!tty_ldisc_data_available(ldisc)) {
            if (ldisc->read_waitq) {
                /* Sleep on wait queue - lock will be released during sleep */
                fut_waitq_sleep_locked(ldisc->read_waitq, &ldisc->lock, FUT_THREAD_BLOCKED);
                /* Lock is automatically re-acquired after waking up */
            } else {
                /* No wait queue - error condition */
                fut_spinlock_release(&ldisc->lock);
                fut_printf("[LDISC] ERROR: No wait queue available in tty_ldisc_read\n");
                return -EAGAIN;
            }
        }
    }

    /* Read available bytes */
    while (bytes_read < len && ldisc->read_pos != ldisc->write_pos) {
        char c = ldisc->input_buf[ldisc->read_pos];
        ldisc->read_pos = (ldisc->read_pos + 1) % TTY_INPUT_BUFFER_SIZE;

        output[bytes_read++] = c;

        /* In canonical mode, stop at newline */
        if ((ldisc->flags & TTY_CANONICAL) && c == '\n') {
            break;
        }
    }

    /* Release lock */
    fut_spinlock_release(&ldisc->lock);

    return (ssize_t)bytes_read;
}

/**
 * Set TTY flags.
 */
void tty_ldisc_set_flags(tty_ldisc_t *ldisc, uint32_t flags) {
    ldisc->flags = flags;
}

/**
 * Get current TTY flags.
 */
uint32_t tty_ldisc_get_flags(const tty_ldisc_t *ldisc) {
    return ldisc->flags;
}

/**
 * Helper to sync legacy flags from termios.
 */
static void sync_flags_from_termios(tty_ldisc_t *ldisc) {
    ldisc->flags = 0;
    if (ldisc->termios.c_lflag & ICANON) {
        ldisc->flags |= TTY_CANONICAL;
    }
    if (ldisc->termios.c_lflag & ECHO) {
        ldisc->flags |= TTY_ECHO;
    }
    if (ldisc->termios.c_lflag & ISIG) {
        ldisc->flags |= TTY_SIGNAL;
    }
}

/**
 * Get termios settings.
 */
int tty_ldisc_get_termios(const tty_ldisc_t *ldisc, struct termios *termios) {
    if (!ldisc || !termios) {
        return -EINVAL;
    }

    memcpy(termios, &ldisc->termios, sizeof(struct termios));
    return 0;
}

/**
 * Set termios settings.
 */
int tty_ldisc_set_termios(tty_ldisc_t *ldisc, const struct termios *termios) {
    if (!ldisc || !termios) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&ldisc->lock);
    memcpy(&ldisc->termios, termios, sizeof(struct termios));

    /* Sync legacy flags from new termios settings */
    sync_flags_from_termios(ldisc);

    fut_spinlock_release(&ldisc->lock);
    return 0;
}

/**
 * Get window size.
 */
int tty_ldisc_get_winsize(const tty_ldisc_t *ldisc, struct winsize *ws) {
    if (!ldisc || !ws) {
        return -EINVAL;
    }

    memcpy(ws, &ldisc->winsize, sizeof(struct winsize));
    return 0;
}

/**
 * Set window size.
 */
int tty_ldisc_set_winsize(tty_ldisc_t *ldisc, const struct winsize *ws) {
    if (!ldisc || !ws) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&ldisc->lock);
    memcpy(&ldisc->winsize, ws, sizeof(struct winsize));
    fut_spinlock_release(&ldisc->lock);

    /* Send SIGWINCH to foreground process group */
    if (ldisc->signal) {
        ldisc->signal(SIGWINCH);
    }
    return 0;
}

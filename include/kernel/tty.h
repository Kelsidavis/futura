// SPDX-License-Identifier: MPL-2.0
/*
 * tty.h - TTY line discipline interface
 *
 * Provides canonical mode, line editing, echo, and control character handling
 * for terminal devices.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <kernel/fut_sched.h>
#include <shared/termios.h>

#ifndef __ssize_t_defined
#define __ssize_t_defined 1
typedef long ssize_t;
#endif

/* Legacy TTY flags (kept for backwards compatibility) */
#define TTY_CANONICAL  0x0001  /* Canonical mode (line-buffered input) */
#define TTY_ECHO       0x0002  /* Echo input characters */
#define TTY_SIGNAL     0x0004  /* Generate signals on control characters */

/* Control character aliases */
#define CTRL_C  0x03  /* SIGINT */
#define CTRL_D  0x04  /* EOF */
#define CTRL_Z  0x1A  /* SIGTSTP */
#define CTRL_U  0x15  /* Erase line */
#define BS      0x08  /* Backspace */
#define DEL     0x7F  /* Delete */

/* Input buffer size */
#define TTY_INPUT_BUFFER_SIZE 4096

/* Default window size */
#define TTY_DEFAULT_ROWS    24
#define TTY_DEFAULT_COLS    80

typedef struct tty_ldisc {
    /* Input buffer (circular) */
    char input_buf[TTY_INPUT_BUFFER_SIZE];
    size_t read_pos;    /* Where to read from */
    size_t write_pos;   /* Where to write to */
    size_t line_start;  /* Start of current line in canonical mode */

    /* Legacy flags (mapped from termios) */
    uint32_t flags;

    /* POSIX termios settings */
    struct termios termios;

    /* Window size */
    struct winsize winsize;

    /* Wait queue for blocking reads */
    struct fut_waitq *read_waitq;

    /* Spinlock for synchronizing access between input thread and readers */
    fut_spinlock_t lock;

    /* Echo function pointer */
    void (*echo)(char c);

    /* Signal function pointer */
    void (*signal)(int sig);
} tty_ldisc_t;

/**
 * Initialize a TTY line discipline.
 *
 * @param ldisc Line discipline structure to initialize
 * @param echo Echo function (NULL for no echo)
 * @param signal Signal function (NULL for no signals)
 */
void tty_ldisc_init(tty_ldisc_t *ldisc, void (*echo)(char), void (*signal)(int));

/**
 * Process an input character through the line discipline.
 * Handles echo, line editing, and control characters.
 *
 * @param ldisc Line discipline
 * @param c Input character
 */
void tty_ldisc_input(tty_ldisc_t *ldisc, char c);

/**
 * Read from the line discipline buffer.
 * In canonical mode, blocks until a complete line is available.
 *
 * @param ldisc Line discipline
 * @param buf Output buffer
 * @param len Maximum bytes to read
 * @return Number of bytes read, or negative error code
 */
ssize_t tty_ldisc_read(tty_ldisc_t *ldisc, void *buf, size_t len);

/**
 * Check if data is available to read.
 * In canonical mode, returns true only if a complete line is available.
 *
 * @param ldisc Line discipline
 * @return true if data is available
 */
bool tty_ldisc_data_available(const tty_ldisc_t *ldisc);

/**
 * Get the number of bytes available to read.
 *
 * @param ldisc Line discipline
 * @return Number of bytes available
 */
size_t tty_ldisc_bytes_available(const tty_ldisc_t *ldisc);

/**
 * Set TTY flags (canonical, echo, signal).
 *
 * @param ldisc Line discipline
 * @param flags New flags to set
 */
void tty_ldisc_set_flags(tty_ldisc_t *ldisc, uint32_t flags);

/**
 * Get current TTY flags.
 *
 * @param ldisc Line discipline
 * @return Current flags
 */
uint32_t tty_ldisc_get_flags(const tty_ldisc_t *ldisc);

/**
 * Get termios settings.
 *
 * @param ldisc Line discipline
 * @param termios Output termios structure
 * @return 0 on success
 */
int tty_ldisc_get_termios(const tty_ldisc_t *ldisc, struct termios *termios);

/**
 * Set termios settings.
 *
 * @param ldisc Line discipline
 * @param termios New termios settings
 * @return 0 on success
 */
int tty_ldisc_set_termios(tty_ldisc_t *ldisc, const struct termios *termios);

/**
 * Get window size.
 *
 * @param ldisc Line discipline
 * @param ws Output winsize structure
 * @return 0 on success
 */
int tty_ldisc_get_winsize(const tty_ldisc_t *ldisc, struct winsize *ws);

/**
 * Set window size.
 *
 * @param ldisc Line discipline
 * @param ws New window size
 * @return 0 on success
 */
int tty_ldisc_set_winsize(tty_ldisc_t *ldisc, const struct winsize *ws);

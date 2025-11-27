/* user/termios.h - Terminal I/O interface for userland
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <shared/termios.h>
#include <user/sys.h>

/* POSIX-style termios functions */

/**
 * Get terminal attributes.
 *
 * @param fd File descriptor (must refer to a terminal)
 * @param termios_p Pointer to termios structure to fill
 * @return 0 on success, -1 on error
 */
static inline int tcgetattr(int fd, struct termios *termios_p) {
    return sys_ioctl(fd, TCGETS, termios_p);
}

/**
 * Set terminal attributes.
 *
 * @param fd File descriptor (must refer to a terminal)
 * @param optional_actions When to apply changes:
 *        - TCSANOW: Change immediately
 *        - TCSADRAIN: After all output has been transmitted
 *        - TCSAFLUSH: After all output has been transmitted, flush pending input
 * @param termios_p Pointer to termios structure with new settings
 * @return 0 on success, -1 on error
 */
static inline int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    unsigned long cmd;
    switch (optional_actions) {
        case 0:  /* TCSANOW */
            cmd = TCSETS;
            break;
        case 1:  /* TCSADRAIN */
            cmd = TCSETSW;
            break;
        case 2:  /* TCSAFLUSH */
            cmd = TCSETSF;
            break;
        default:
            return -1;
    }
    return sys_ioctl(fd, cmd, (void *)termios_p);
}

/* Optional actions for tcsetattr */
#define TCSANOW   0  /* Change immediately */
#define TCSADRAIN 1  /* Change after all output transmitted */
#define TCSAFLUSH 2  /* Change after all output transmitted, flush pending input */

/**
 * Make a terminal the controlling terminal.
 * (Stub - not yet implemented)
 */
static inline int tcsetsid(int fd, int pgid) {
    (void)fd;
    (void)pgid;
    return 0;  /* Stub */
}

/**
 * Get foreground process group ID.
 * (Stub - not yet implemented)
 */
static inline int tcgetpgrp(int fd) {
    (void)fd;
    return 1;  /* Stub - return init's PGRP */
}

/**
 * Set foreground process group ID.
 * (Stub - not yet implemented)
 */
static inline int tcsetpgrp(int fd, int pgrp) {
    (void)fd;
    (void)pgrp;
    return 0;  /* Stub */
}

/* Helper macros for flag manipulation */
#define cfmakeraw(termios_p) do { \
    (termios_p)->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON); \
    (termios_p)->c_oflag &= ~OPOST; \
    (termios_p)->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN); \
    (termios_p)->c_cflag &= ~(CSIZE | PARENB); \
    (termios_p)->c_cflag |= CS8; \
    (termios_p)->c_cc[VMIN] = 1; \
    (termios_p)->c_cc[VTIME] = 0; \
} while (0)

/* Speed functions (stubs - serial port speed is fixed) */
static inline speed_t cfgetispeed(const struct termios *termios_p) {
    return termios_p->c_ispeed;
}

static inline speed_t cfgetospeed(const struct termios *termios_p) {
    return termios_p->c_ospeed;
}

static inline int cfsetispeed(struct termios *termios_p, speed_t speed) {
    termios_p->c_ispeed = speed;
    return 0;
}

static inline int cfsetospeed(struct termios *termios_p, speed_t speed) {
    termios_p->c_ospeed = speed;
    return 0;
}

static inline int cfsetspeed(struct termios *termios_p, speed_t speed) {
    termios_p->c_ispeed = speed;
    termios_p->c_ospeed = speed;
    return 0;
}

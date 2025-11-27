/* shared/termios.h - Terminal I/O interface definitions
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * POSIX-compatible terminal I/O settings structure and constants.
 */

#pragma once

#include <stdint.h>

/* ======================================================================
 * TERMIOS FLAGS
 * ====================================================================== */

/* Input modes (c_iflag) */
#define IGNBRK  0x0001  /* Ignore BREAK condition */
#define BRKINT  0x0002  /* Signal interrupt on BREAK */
#define IGNPAR  0x0004  /* Ignore parity errors */
#define PARMRK  0x0008  /* Mark parity errors */
#define INPCK   0x0010  /* Enable input parity check */
#define ISTRIP  0x0020  /* Strip 8th bit off characters */
#define INLCR   0x0040  /* Translate NL to CR on input */
#define IGNCR   0x0080  /* Ignore carriage return on input */
#define ICRNL   0x0100  /* Translate CR to NL on input */
#define IUCLC   0x0200  /* Map uppercase to lowercase on input */
#define IXON    0x0400  /* Enable start/stop output control */
#define IXANY   0x0800  /* Enable any character to restart output */
#define IXOFF   0x1000  /* Enable start/stop input control */
#define IMAXBEL 0x2000  /* Ring bell when input queue is full */
#define IUTF8   0x4000  /* Input is UTF8 */

/* Output modes (c_oflag) */
#define OPOST   0x0001  /* Post-process output */
#define OLCUC   0x0002  /* Map lowercase to uppercase on output */
#define ONLCR   0x0004  /* Translate NL to CR-NL on output */
#define OCRNL   0x0008  /* Translate CR to NL on output */
#define ONOCR   0x0010  /* Don't output CR at column 0 */
#define ONLRET  0x0020  /* NL performs CR function */
#define OFILL   0x0040  /* Use fill characters for delay */
#define OFDEL   0x0080  /* Fill is DEL, else NUL */

/* Control modes (c_cflag) */
#define CSIZE   0x0030  /* Character size mask */
#define CS5     0x0000  /* 5 bits */
#define CS6     0x0010  /* 6 bits */
#define CS7     0x0020  /* 7 bits */
#define CS8     0x0030  /* 8 bits */
#define CSTOPB  0x0040  /* 2 stop bits (else 1) */
#define CREAD   0x0080  /* Enable receiver */
#define PARENB  0x0100  /* Enable parity generation/checking */
#define PARODD  0x0200  /* Parity is odd (else even) */
#define HUPCL   0x0400  /* Hang up on last close */
#define CLOCAL  0x0800  /* Ignore modem control lines */

/* Local modes (c_lflag) */
#define ISIG    0x0001  /* Enable signals (SIGINT, SIGQUIT, SIGSUSP) */
#define ICANON  0x0002  /* Canonical mode (line-by-line input) */
#define XCASE   0x0004  /* Canonical upper/lower presentation */
#define ECHO    0x0008  /* Echo input characters */
#define ECHOE   0x0010  /* Echo ERASE as backspace-space-backspace */
#define ECHOK   0x0020  /* Echo KILL by erasing each character */
#define ECHONL  0x0040  /* Echo NL even if ECHO is off */
#define NOFLSH  0x0080  /* Don't flush after interrupt */
#define TOSTOP  0x0100  /* Send SIGTTOU for background output */
#define ECHOCTL 0x0200  /* Echo control chars as ^X */
#define ECHOPRT 0x0400  /* Hardcopy echo */
#define ECHOKE  0x0800  /* Visual erase for KILL */
#define IEXTEN  0x8000  /* Enable implementation-defined input processing */

/* ======================================================================
 * CONTROL CHARACTERS
 * ====================================================================== */

/* Size of control character array */
#define NCCS    32

/* c_cc indices */
#define VINTR    0   /* Interrupt character (^C) */
#define VQUIT    1   /* Quit character (^\) */
#define VERASE   2   /* Erase character (Backspace) */
#define VKILL    3   /* Kill line character (^U) */
#define VEOF     4   /* End-of-file character (^D) */
#define VTIME    5   /* Timeout in deciseconds (raw mode) */
#define VMIN     6   /* Minimum chars (raw mode) */
#define VSWTC    7   /* Switch character */
#define VSTART   8   /* Start output character (^Q) */
#define VSTOP    9   /* Stop output character (^S) */
#define VSUSP   10   /* Suspend character (^Z) */
#define VEOL    11   /* End-of-line character */
#define VREPRINT 12  /* Reprint line character (^R) */
#define VDISCARD 13  /* Discard character (^O) */
#define VWERASE  14  /* Word erase character (^W) */
#define VLNEXT   15  /* Literal next character (^V) */
#define VEOL2   16   /* Second end-of-line character */

/* Default control characters */
#define CINTR   '\003'  /* ^C */
#define CQUIT   '\034'  /* ^\ */
#define CERASE  '\177'  /* DEL */
#define CKILL   '\025'  /* ^U */
#define CEOF    '\004'  /* ^D */
#define CSTART  '\021'  /* ^Q */
#define CSTOP   '\023'  /* ^S */
#define CSUSP   '\032'  /* ^Z */
#define CREPRINT '\022' /* ^R */
#define CDISCARD '\017' /* ^O */
#define CWERASE '\027'  /* ^W */
#define CLNEXT  '\026'  /* ^V */

/* ======================================================================
 * BAUD RATES
 * ====================================================================== */

#define B0      0       /* Hang up */
#define B50     50
#define B75     75
#define B110    110
#define B134    134
#define B150    150
#define B200    200
#define B300    300
#define B600    600
#define B1200   1200
#define B1800   1800
#define B2400   2400
#define B4800   4800
#define B9600   9600
#define B19200  19200
#define B38400  38400
#define B57600  57600
#define B115200 115200
#define B230400 230400

/* ======================================================================
 * IOCTL COMMANDS
 * ====================================================================== */

#define TCGETS      0x5401  /* Get terminal settings */
#define TCSETS      0x5402  /* Set terminal settings immediately */
#define TCSETSW     0x5403  /* Set terminal settings after output drained */
#define TCSETSF     0x5404  /* Set terminal settings, flush input */
#define TCGETA      0x5405  /* Get terminal settings (old format) */
#define TCSETA      0x5406  /* Set terminal settings (old format) */
#define TCSETAW     0x5407  /* Set after wait (old format) */
#define TCSETAF     0x5408  /* Set after flush (old format) */
#define TCSBRK      0x5409  /* Send break */
#define TCXONC      0x540A  /* Flow control */
#define TCFLSH      0x540B  /* Flush input/output */
#define TIOCGWINSZ  0x5413  /* Get window size */
#define TIOCSWINSZ  0x5414  /* Set window size */
#define TIOCGPGRP   0x540F  /* Get process group */
#define TIOCSPGRP   0x5410  /* Set process group */
#define FIONREAD    0x541B  /* Bytes available to read */

/* ======================================================================
 * STRUCTURES
 * ====================================================================== */

typedef unsigned int tcflag_t;
typedef unsigned char cc_t;
typedef unsigned int speed_t;

/**
 * Terminal I/O settings structure (POSIX termios)
 */
struct termios {
    tcflag_t c_iflag;       /* Input modes */
    tcflag_t c_oflag;       /* Output modes */
    tcflag_t c_cflag;       /* Control modes */
    tcflag_t c_lflag;       /* Local modes */
    cc_t c_line;            /* Line discipline */
    cc_t c_cc[NCCS];        /* Control characters */
    speed_t c_ispeed;       /* Input speed */
    speed_t c_ospeed;       /* Output speed */
};

/**
 * Window size structure (for TIOCGWINSZ/TIOCSWINSZ)
 */
struct winsize {
    unsigned short ws_row;    /* Rows in characters */
    unsigned short ws_col;    /* Columns in characters */
    unsigned short ws_xpixel; /* Horizontal size in pixels */
    unsigned short ws_ypixel; /* Vertical size in pixels */
};

/* ======================================================================
 * DEFAULT SETTINGS
 * ====================================================================== */

/* Default input flags: CR->NL translation, enable XON/XOFF */
#define TERMIOS_DEFAULT_IFLAG   (ICRNL | IXON)

/* Default output flags: post-process, NL->CR-NL */
#define TERMIOS_DEFAULT_OFLAG   (OPOST | ONLCR)

/* Default control flags: 8-bit, enable receiver, local */
#define TERMIOS_DEFAULT_CFLAG   (CS8 | CREAD | CLOCAL)

/* Default local flags: canonical, echo, signals */
#define TERMIOS_DEFAULT_LFLAG   (ICANON | ECHO | ECHOE | ECHOK | ISIG | IEXTEN)

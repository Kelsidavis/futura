/* nano.c - Minimal text editor for Futura OS
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * A simple nano-like terminal text editor with:
 * - ANSI escape sequence display
 * - Line-by-line editing with insert/delete
 * - Ctrl+O to save, Ctrl+X to exit
 * - Ctrl+K to cut line, Ctrl+G for help
 * - Arrow key navigation
 */

#include <user/sys.h>
#include <user/libfutura.h>
#include <stdint.h>
typedef long ssize_t;

/* Syscall numbers (x86_64 compat) */
#define __NR_read   0
#define __NR_write  1
#define __NR_open   2
#define __NR_close  3
#define __NR_ioctl  16
#define __NR_exit   60

/* Terminal ioctl */
#define TCGETS  0x5401
#define TCSETS  0x5402

/* File flags from libfutura.h */

/* Editor limits */
#define MAX_LINES   256
#define MAX_LINE_LEN 256
#define MAX_FILENAME 128

/* Screen dimensions */
static int screen_rows = 24;
static int screen_cols = 80;

/* Editor state */
static char lines[MAX_LINES][MAX_LINE_LEN];
static int num_lines = 0;
static int cursor_row = 0;  /* Line in buffer */
static int cursor_col = 0;  /* Column in current line */
static int scroll_offset = 0;
static char filename[MAX_FILENAME] = "";
static int modified = 0;

/* I/O helpers */
static void write_str(const char *s) {
    int len = 0;
    while (s[len]) len++;
    sys_write(1, s, len);
}

static void write_char(char c) {
    sys_write(1, &c, 1);
}

static void write_num(int n) {
    char buf[16];
    int i = 0;
    if (n == 0) { write_char('0'); return; }
    if (n < 0) { write_char('-'); n = -n; }
    while (n > 0) { buf[i++] = '0' + (n % 10); n /= 10; }
    while (i > 0) write_char(buf[--i]);
}

static int str_len(const char *s) {
    int l = 0;
    while (s[l]) l++;
    return l;
}

static void str_cpy(char *dst, const char *src) {
    while (*src) *dst++ = *src++;
    *dst = '\0';
}

/* ANSI escape sequences */
static void term_clear(void) { write_str("\033[2J"); }
static void term_home(void) { write_str("\033[H"); }
static void term_goto(int row, int col) {
    write_str("\033[");
    write_num(row + 1);
    write_char(';');
    write_num(col + 1);
    write_char('H');
}
static void term_clear_line(void) { write_str("\033[K"); }
static void term_reverse(void) { write_str("\033[7m"); }
static void term_normal(void) { write_str("\033[0m"); }

/* Raw mode termios (60-byte Linux struct) */
static char saved_termios[60];
static int raw_mode = 0;

static void enable_raw_mode(void) {
    char termios[60];
    /* Get current termios */
    if (sys_call3(__NR_ioctl, 0, TCGETS, (long)termios) < 0) return;

    /* Save for restore */
    for (int i = 0; i < 60; i++) saved_termios[i] = termios[i];

    /* Modify: disable ICANON, ECHO, ISIG (c_lflag at offset 12) */
    uint32_t *c_lflag = (uint32_t *)(termios + 12);
    *c_lflag &= ~(0x00000002 | 0x00000008 | 0x00000001);  /* ~(ICANON|ECHO|ISIG) */

    /* Set VMIN=1, VTIME=0 (c_cc at offset 17) */
    termios[17 + 6] = 1;   /* VMIN */
    termios[17 + 5] = 0;   /* VTIME */

    sys_call3(__NR_ioctl, 0, TCSETS, (long)termios);
    raw_mode = 1;
}

static void disable_raw_mode(void) {
    if (raw_mode) {
        sys_call3(__NR_ioctl, 0, TCSETS, (long)saved_termios);
        raw_mode = 0;
    }
}

/* Read a single key (handles escape sequences for arrow keys) */
static int read_key(void) {
    char c;
    if (sys_read(0, &c, 1) <= 0) return -1;

    if (c == '\033') {
        /* Escape sequence */
        char seq[2];
        if (sys_read(0, &seq[0], 1) <= 0) return '\033';
        if (sys_read(0, &seq[1], 1) <= 0) return '\033';
        if (seq[0] == '[') {
            switch (seq[1]) {
                case 'A': return 1000; /* Up */
                case 'B': return 1001; /* Down */
                case 'C': return 1002; /* Right */
                case 'D': return 1003; /* Left */
                case 'H': return 1004; /* Home */
                case 'F': return 1005; /* End */
                case '3': sys_read(0, &c, 1); return 1006; /* Delete */
            }
        }
        return '\033';
    }
    return (unsigned char)c;
}

/* Load file into buffer */
static void load_file(const char *path) {
    int fd = sys_open(path, O_RDONLY, 0);
    num_lines = 0;
    lines[0][0] = '\0';

    if (fd >= 0) {
        char buf[512];
        int col = 0;
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n' || col >= MAX_LINE_LEN - 1) {
                    lines[num_lines][col] = '\0';
                    num_lines++;
                    col = 0;
                    if (num_lines >= MAX_LINES) goto done;
                } else {
                    lines[num_lines][col++] = buf[i];
                }
            }
        }
done:
        if (col > 0) {
            lines[num_lines][col] = '\0';
            num_lines++;
        }
        sys_close(fd);
    }

    if (num_lines == 0) {
        lines[0][0] = '\0';
        num_lines = 1;
    }
}

/* Save file */
static int save_file(const char *path) {
    int fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    for (int i = 0; i < num_lines; i++) {
        int len = str_len(lines[i]);
        if (len > 0) sys_write(fd, lines[i], len);
        sys_write(fd, "\n", 1);
    }
    sys_close(fd);
    modified = 0;
    return 0;
}

/* Draw the screen */
static void draw_screen(void) {
    term_home();

    /* Status bar */
    term_reverse();
    write_str("  Futura nano  ");
    if (filename[0]) write_str(filename);
    else write_str("[New File]");
    if (modified) write_str(" [Modified]");
    /* Pad to screen width */
    int used = 15 + (filename[0] ? str_len(filename) : 10) + (modified ? 11 : 0);
    for (int i = used; i < screen_cols; i++) write_char(' ');
    term_normal();
    write_str("\r\n");

    /* Content area */
    for (int i = 0; i < screen_rows - 3; i++) {
        int line_idx = scroll_offset + i;
        term_clear_line();
        if (line_idx < num_lines) {
            write_str(lines[line_idx]);
        } else {
            write_char('~');
        }
        write_str("\r\n");
    }

    /* Help bar */
    term_reverse();
    write_str(" ^O Save  ^X Exit  ^K Cut  ^G Help ");
    for (int i = 36; i < screen_cols; i++) write_char(' ');
    term_normal();

    /* Position cursor */
    int screen_row = 1 + (cursor_row - scroll_offset);
    term_goto(screen_row, cursor_col);
}

/* Insert character at cursor */
static void insert_char(char c) {
    int len = str_len(lines[cursor_row]);
    if (len >= MAX_LINE_LEN - 1) return;

    /* Shift right */
    for (int i = len + 1; i > cursor_col; i--)
        lines[cursor_row][i] = lines[cursor_row][i-1];
    lines[cursor_row][cursor_col] = c;
    cursor_col++;
    modified = 1;
}

/* Delete character at cursor */
static void delete_char(void) {
    int len = str_len(lines[cursor_row]);
    if (cursor_col >= len) {
        /* Join with next line */
        if (cursor_row < num_lines - 1) {
            int cur_len = str_len(lines[cursor_row]);
            int next_len = str_len(lines[cursor_row + 1]);
            if (cur_len + next_len < MAX_LINE_LEN) {
                for (int i = 0; i <= next_len; i++)
                    lines[cursor_row][cur_len + i] = lines[cursor_row + 1][i];
                /* Shift lines up */
                for (int i = cursor_row + 1; i < num_lines - 1; i++)
                    str_cpy(lines[i], lines[i+1]);
                num_lines--;
                modified = 1;
            }
        }
        return;
    }
    /* Shift left */
    for (int i = cursor_col; i < len; i++)
        lines[cursor_row][i] = lines[cursor_row][i+1];
    modified = 1;
}

/* Backspace */
static void backspace(void) {
    if (cursor_col > 0) {
        cursor_col--;
        delete_char();
    } else if (cursor_row > 0) {
        /* Join with previous line */
        cursor_col = str_len(lines[cursor_row - 1]);
        cursor_row--;
        delete_char();
    }
}

/* Enter/newline — split line */
static void newline(void) {
    if (num_lines >= MAX_LINES) return;

    /* Shift lines down */
    for (int i = num_lines; i > cursor_row + 1; i--)
        str_cpy(lines[i], lines[i-1]);
    num_lines++;

    /* Split current line at cursor */
    str_cpy(lines[cursor_row + 1], &lines[cursor_row][cursor_col]);
    lines[cursor_row][cursor_col] = '\0';

    cursor_row++;
    cursor_col = 0;
    modified = 1;
}

/* Cut line (Ctrl+K) */
static void cut_line(void) {
    if (num_lines <= 1) {
        lines[0][0] = '\0';
        cursor_col = 0;
        modified = 1;
        return;
    }
    for (int i = cursor_row; i < num_lines - 1; i++)
        str_cpy(lines[i], lines[i+1]);
    num_lines--;
    if (cursor_row >= num_lines) cursor_row = num_lines - 1;
    int len = str_len(lines[cursor_row]);
    if (cursor_col > len) cursor_col = len;
    modified = 1;
}

int main(int argc, char **argv) {
    /* Open /dev/console for stdin/stdout if not set */
    long flags = sys_call3(__NR_ioctl, 0, TCGETS, 0);
    if (flags < 0) {
        int fd = sys_open("/dev/console", O_RDWR, 0);
        if (fd >= 0 && fd != 0) {
            sys_dup2_call(fd, 0);
            sys_dup2_call(fd, 1);
            sys_dup2_call(fd, 2);
            if (fd > 2) sys_close(fd);
        }
    }

    if (argc >= 2) {
        /* Copy filename */
        int i = 0;
        while (argv[1][i] && i < MAX_FILENAME - 1) { filename[i] = argv[1][i]; i++; }
        filename[i] = '\0';
        load_file(filename);
    } else {
        num_lines = 1;
        lines[0][0] = '\0';
    }

    enable_raw_mode();
    draw_screen();

    int running = 1;
    while (running) {
        int key = read_key();
        if (key < 0) break;

        switch (key) {
            case 24: /* Ctrl+X — Exit */
                running = 0;
                break;

            case 15: /* Ctrl+O — Save */
                if (filename[0]) {
                    if (save_file(filename) == 0) {
                        term_goto(screen_rows - 2, 0);
                        term_reverse();
                        write_str(" Wrote ");
                        write_num(num_lines);
                        write_str(" lines ");
                        term_normal();
                    }
                }
                break;

            case 11: /* Ctrl+K — Cut line */
                cut_line();
                draw_screen();
                break;

            case 7: /* Ctrl+G — Help */
                term_goto(screen_rows - 2, 0);
                term_reverse();
                write_str(" ^O=Save ^X=Exit ^K=Cut Arrows=Move Enter=Newline ");
                term_normal();
                break;

            case 1000: /* Up */
                if (cursor_row > 0) {
                    cursor_row--;
                    int len = str_len(lines[cursor_row]);
                    if (cursor_col > len) cursor_col = len;
                }
                if (cursor_row < scroll_offset) scroll_offset = cursor_row;
                draw_screen();
                break;

            case 1001: /* Down */
                if (cursor_row < num_lines - 1) {
                    cursor_row++;
                    int len = str_len(lines[cursor_row]);
                    if (cursor_col > len) cursor_col = len;
                }
                if (cursor_row >= scroll_offset + screen_rows - 3)
                    scroll_offset = cursor_row - screen_rows + 4;
                draw_screen();
                break;

            case 1002: /* Right */
                if (cursor_col < str_len(lines[cursor_row])) cursor_col++;
                else if (cursor_row < num_lines - 1) { cursor_row++; cursor_col = 0; }
                draw_screen();
                break;

            case 1003: /* Left */
                if (cursor_col > 0) cursor_col--;
                else if (cursor_row > 0) { cursor_row--; cursor_col = str_len(lines[cursor_row]); }
                draw_screen();
                break;

            case 1004: /* Home */
                cursor_col = 0;
                draw_screen();
                break;

            case 1005: /* End */
                cursor_col = str_len(lines[cursor_row]);
                draw_screen();
                break;

            case 1006: /* Delete */
                delete_char();
                draw_screen();
                break;

            case 127: /* Backspace */
            case 8:
                backspace();
                draw_screen();
                break;

            case '\r':
            case '\n':
                newline();
                draw_screen();
                break;

            default:
                if (key >= 32 && key < 127) {
                    insert_char((char)key);
                    draw_screen();
                }
                break;
        }
    }

    disable_raw_mode();
    term_clear();
    term_home();

    (void)argc;
    sys_exit(0);
    return 0;
}

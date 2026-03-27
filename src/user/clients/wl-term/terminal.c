/* terminal.c - Terminal emulator implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include "terminal.h"
#include "font.h"
#include <string.h>
#include <user/sys.h>

/* Default colors */
#define COLOR_BLACK     0xFF000000u
#define COLOR_WHITE     0xFFFFFFFFu
#define COLOR_GREEN     0xFF00FF00u

void term_init(struct terminal *term) {
    memset(term, 0, sizeof(*term));

    /* Initialize grid with spaces */
    for (int y = 0; y < TERM_ROWS; y++) {
        for (int x = 0; x < TERM_COLS; x++) {
            term->grid[y][x].ch = ' ';
            term->grid[y][x].fg_color = COLOR_WHITE;
            term->grid[y][x].bg_color = COLOR_BLACK;
        }
    }

    term->cursor_x = 0;
    term->cursor_y = 0;
    term->fg_color = COLOR_WHITE;
    term->bg_color = COLOR_BLACK;
    term->cursor_visible = true;
    term->parser_state = TERM_STATE_NORMAL;
    term->escape_len = 0;

    term->shell_stdin_fd = -1;
    term->shell_stdout_fd = -1;
    term->shell_pid = -1;
}

void term_scroll(struct terminal *term) {
    /* Move all rows up by one */
    for (int y = 0; y < TERM_ROWS - 1; y++) {
        for (int x = 0; x < TERM_COLS; x++) {
            term->grid[y][x] = term->grid[y + 1][x];
        }
    }

    /* Clear bottom row */
    for (int x = 0; x < TERM_COLS; x++) {
        term->grid[TERM_ROWS - 1][x].ch = ' ';
        term->grid[TERM_ROWS - 1][x].fg_color = term->fg_color;
        term->grid[TERM_ROWS - 1][x].bg_color = term->bg_color;
    }
}

void term_clear(struct terminal *term) {
    for (int y = 0; y < TERM_ROWS; y++) {
        for (int x = 0; x < TERM_COLS; x++) {
            term->grid[y][x].ch = ' ';
            term->grid[y][x].fg_color = term->fg_color;
            term->grid[y][x].bg_color = term->bg_color;
        }
    }
    term->cursor_x = 0;
    term->cursor_y = 0;
}

/* ANSI 16-color palette */
static const uint32_t ansi_colors[16] = {
    0xFF000000u, /* 0: black */
    0xFFCC0000u, /* 1: red */
    0xFF00CC00u, /* 2: green */
    0xFFCCCC00u, /* 3: yellow */
    0xFF0000CCu, /* 4: blue */
    0xFFCC00CCu, /* 5: magenta */
    0xFF00CCCCu, /* 6: cyan */
    0xFFCCCCCCu, /* 7: white */
    0xFF666666u, /* 8: bright black (gray) */
    0xFFFF3333u, /* 9: bright red */
    0xFF33FF33u, /* 10: bright green */
    0xFFFFFF33u, /* 11: bright yellow */
    0xFF3333FFu, /* 12: bright blue */
    0xFFFF33FFu, /* 13: bright magenta */
    0xFF33FFFFu, /* 14: bright cyan */
    0xFFFFFFFFu, /* 15: bright white */
};

/* Parse CSI parameter numbers: ESC[n1;n2;...X */
static int parse_csi_params(const char *buf, int len, int *params, int max_params) {
    int count = 0, val = 0, has_val = 0;
    for (int i = 1; i < len - 1; i++) {  /* skip [ and final char */
        if (buf[i] >= '0' && buf[i] <= '9') {
            val = val * 10 + (buf[i] - '0');
            has_val = 1;
        } else if (buf[i] == ';') {
            if (count < max_params) params[count++] = has_val ? val : 0;
            val = 0; has_val = 0;
        } else if (buf[i] == '?') {
            /* Private mode prefix — skip */
        }
    }
    if (has_val || count > 0) {
        if (count < max_params) params[count++] = val;
    }
    return count;
}

static void term_handle_escape(struct terminal *term) {
    if (term->escape_len == 0 || term->escape_buf[0] != '[') return;

    char final = term->escape_buf[term->escape_len - 1];
    int params[8] = {0};
    int nparams = parse_csi_params(term->escape_buf, term->escape_len, params, 8);

    switch (final) {
    case 'A': { /* Cursor Up */
        int n = (nparams > 0 && params[0] > 0) ? params[0] : 1;
        term->cursor_y -= n;
        if (term->cursor_y < 0) term->cursor_y = 0;
        break;
    }
    case 'B': { /* Cursor Down */
        int n = (nparams > 0 && params[0] > 0) ? params[0] : 1;
        term->cursor_y += n;
        if (term->cursor_y >= TERM_ROWS) term->cursor_y = TERM_ROWS - 1;
        break;
    }
    case 'C': { /* Cursor Forward (Right) */
        int n = (nparams > 0 && params[0] > 0) ? params[0] : 1;
        term->cursor_x += n;
        if (term->cursor_x >= TERM_COLS) term->cursor_x = TERM_COLS - 1;
        break;
    }
    case 'D': { /* Cursor Back (Left) */
        int n = (nparams > 0 && params[0] > 0) ? params[0] : 1;
        term->cursor_x -= n;
        if (term->cursor_x < 0) term->cursor_x = 0;
        break;
    }
    case 'H': case 'f': { /* Cursor Position: ESC[row;colH */
        int row = (nparams > 0 && params[0] > 0) ? params[0] - 1 : 0;
        int col = (nparams > 1 && params[1] > 0) ? params[1] - 1 : 0;
        if (row < 0) row = 0; if (row >= TERM_ROWS) row = TERM_ROWS - 1;
        if (col < 0) col = 0; if (col >= TERM_COLS) col = TERM_COLS - 1;
        term->cursor_y = row;
        term->cursor_x = col;
        break;
    }
    case 'J': { /* Erase in Display */
        int mode = (nparams > 0) ? params[0] : 0;
        if (mode == 0) { /* Cursor to end */
            for (int x = term->cursor_x; x < TERM_COLS; x++) {
                term->grid[term->cursor_y][x].ch = ' ';
                term->grid[term->cursor_y][x].fg_color = term->fg_color;
                term->grid[term->cursor_y][x].bg_color = term->bg_color;
            }
            for (int y = term->cursor_y + 1; y < TERM_ROWS; y++)
                for (int x = 0; x < TERM_COLS; x++) {
                    term->grid[y][x].ch = ' ';
                    term->grid[y][x].fg_color = term->fg_color;
                    term->grid[y][x].bg_color = term->bg_color;
                }
        } else if (mode == 1) { /* Start to cursor */
            for (int y = 0; y < term->cursor_y; y++)
                for (int x = 0; x < TERM_COLS; x++) {
                    term->grid[y][x].ch = ' ';
                    term->grid[y][x].fg_color = term->fg_color;
                    term->grid[y][x].bg_color = term->bg_color;
                }
            for (int x = 0; x <= term->cursor_x; x++) {
                term->grid[term->cursor_y][x].ch = ' ';
                term->grid[term->cursor_y][x].fg_color = term->fg_color;
                term->grid[term->cursor_y][x].bg_color = term->bg_color;
            }
        } else if (mode == 2) { /* Entire screen */
            term_clear(term);
        }
        break;
    }
    case 'K': { /* Erase in Line */
        int mode = (nparams > 0) ? params[0] : 0;
        int y = term->cursor_y;
        if (mode == 0) { /* Cursor to end of line */
            for (int x = term->cursor_x; x < TERM_COLS; x++) {
                term->grid[y][x].ch = ' ';
                term->grid[y][x].fg_color = term->fg_color;
                term->grid[y][x].bg_color = term->bg_color;
            }
        } else if (mode == 1) { /* Start of line to cursor */
            for (int x = 0; x <= term->cursor_x; x++) {
                term->grid[y][x].ch = ' ';
                term->grid[y][x].fg_color = term->fg_color;
                term->grid[y][x].bg_color = term->bg_color;
            }
        } else if (mode == 2) { /* Entire line */
            for (int x = 0; x < TERM_COLS; x++) {
                term->grid[y][x].ch = ' ';
                term->grid[y][x].fg_color = term->fg_color;
                term->grid[y][x].bg_color = term->bg_color;
            }
        }
        break;
    }
    case 'm': { /* SGR — Select Graphic Rendition (colors, bold, etc.) */
        if (nparams == 0) { /* ESC[m = reset */
            term->fg_color = COLOR_WHITE;
            term->bg_color = COLOR_BLACK;
            break;
        }
        for (int i = 0; i < nparams; i++) {
            int p = params[i];
            if (p == 0) { /* Reset */
                term->fg_color = COLOR_WHITE;
                term->bg_color = COLOR_BLACK;
            } else if (p == 1) { /* Bold — use bright colors */
                /* Map normal to bright: if fg is ansi 0-7, shift to 8-15 */
                for (int c = 0; c < 8; c++) {
                    if (term->fg_color == ansi_colors[c]) {
                        term->fg_color = ansi_colors[c + 8];
                        break;
                    }
                }
            } else if (p == 7) { /* Reverse video */
                uint32_t tmp = term->fg_color;
                term->fg_color = term->bg_color;
                term->bg_color = tmp;
            } else if (p >= 30 && p <= 37) { /* FG color */
                term->fg_color = ansi_colors[p - 30];
            } else if (p >= 40 && p <= 47) { /* BG color */
                term->bg_color = ansi_colors[p - 40];
            } else if (p == 39) { /* Default FG */
                term->fg_color = COLOR_WHITE;
            } else if (p == 49) { /* Default BG */
                term->bg_color = COLOR_BLACK;
            } else if (p >= 90 && p <= 97) { /* Bright FG */
                term->fg_color = ansi_colors[p - 90 + 8];
            } else if (p >= 100 && p <= 107) { /* Bright BG */
                term->bg_color = ansi_colors[p - 100 + 8];
            }
        }
        break;
    }
    case 'h': { /* Set Mode */
        /* ESC[?25h — Show cursor */
        if (term->escape_len >= 4 && term->escape_buf[1] == '?' &&
            term->escape_buf[2] == '2' && term->escape_buf[3] == '5') {
            term->cursor_visible = true;
        }
        break;
    }
    case 'l': { /* Reset Mode */
        /* ESC[?25l — Hide cursor */
        if (term->escape_len >= 4 && term->escape_buf[1] == '?' &&
            term->escape_buf[2] == '2' && term->escape_buf[3] == '5') {
            term->cursor_visible = false;
        }
        break;
    }
    case 'G': { /* Cursor Horizontal Absolute */
        int col = (nparams > 0 && params[0] > 0) ? params[0] - 1 : 0;
        if (col >= TERM_COLS) col = TERM_COLS - 1;
        term->cursor_x = col;
        break;
    }
    case 'd': { /* Cursor Vertical Absolute */
        int row = (nparams > 0 && params[0] > 0) ? params[0] - 1 : 0;
        if (row >= TERM_ROWS) row = TERM_ROWS - 1;
        term->cursor_y = row;
        break;
    }
    case 'n': { /* Device Status Report */
        if (nparams > 0 && params[0] == 6 && term->shell_stdin_fd >= 0) {
            /* Report cursor position: ESC[row;colR */
            char resp[16];
            int rp = 0;
            resp[rp++] = '\033'; resp[rp++] = '[';
            int r = term->cursor_y + 1, c = term->cursor_x + 1;
            if (r >= 10) resp[rp++] = '0' + (char)(r / 10);
            resp[rp++] = '0' + (char)(r % 10);
            resp[rp++] = ';';
            if (c >= 10) resp[rp++] = '0' + (char)(c / 10);
            resp[rp++] = '0' + (char)(c % 10);
            resp[rp++] = 'R';
            sys_write(term->shell_stdin_fd, resp, rp);
        }
        break;
    }
    default:
        break; /* Ignore unknown sequences */
    }
}

void term_putchar(struct terminal *term, char ch) {
    /* Handle escape sequences */
    if (term->parser_state == TERM_STATE_ESC) {
        if (term->escape_len < (int)sizeof(term->escape_buf) - 1) {
            term->escape_buf[term->escape_len++] = ch;
        }

        /* Check if sequence is complete (ends with letter) */
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            term_handle_escape(term);
            term->parser_state = TERM_STATE_NORMAL;
            term->escape_len = 0;
        }
        return;
    }

    /* Special characters */
    if (ch == '\033') {  /* ESC */
        term->parser_state = TERM_STATE_ESC;
        term->escape_len = 0;
        return;
    }

    if (ch == '\n') {
        term->cursor_y++;
        term->cursor_x = 0;
        if (term->cursor_y >= TERM_ROWS) {
            term->cursor_y = TERM_ROWS - 1;
            term_scroll(term);
        }
        return;
    }

    if (ch == '\r') {
        term->cursor_x = 0;
        return;
    }

    if (ch == '\b') {
        if (term->cursor_x > 0) {
            term->cursor_x--;
        }
        return;
    }

    if (ch == '\t') {
        /* Tab to next 8-column boundary */
        term->cursor_x = (term->cursor_x + 8) & ~7;
        if (term->cursor_x >= TERM_COLS) {
            term->cursor_x = 0;
            term->cursor_y++;
            if (term->cursor_y >= TERM_ROWS) {
                term->cursor_y = TERM_ROWS - 1;
                term_scroll(term);
            }
        }
        return;
    }

    /* Printable character */
    if (ch >= 32 && ch < 127) {
        term->grid[term->cursor_y][term->cursor_x].ch = ch;
        term->grid[term->cursor_y][term->cursor_x].fg_color = term->fg_color;
        term->grid[term->cursor_y][term->cursor_x].bg_color = term->bg_color;

        term->cursor_x++;
        if (term->cursor_x >= TERM_COLS) {
            term->cursor_x = 0;
            term->cursor_y++;
            if (term->cursor_y >= TERM_ROWS) {
                term->cursor_y = TERM_ROWS - 1;
                term_scroll(term);
            }
        }
    }
}

void term_write(struct terminal *term, const char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        term_putchar(term, data[i]);
    }
}

int term_read_shell(struct terminal *term) {
    if (term->shell_stdout_fd < 0) {
        return 0;  /* No shell - return 0 (no data) instead of -1 (closed) */
    }

    char buf[256];
    long n = sys_read(term->shell_stdout_fd, buf, sizeof(buf));
    if (n > 0) {
        term_write(term, buf, (size_t)n);
        return (int)n;
    }
    /* EAGAIN (-11) means no data available on non-blocking pipe, not an error */
    if (n == -11 /* EAGAIN */ || n == -4 /* EINTR */) {
        return 0;
    }
    if (n != 0) {
        /* Unexpected read error from shell pipe */
    }
    return (int)n;
}

void term_send_key(struct terminal *term, char ch) {
    if (term->shell_stdin_fd < 0) {
        return;
    }

    sys_write(term->shell_stdin_fd, &ch, 1);
}

void term_render(struct terminal *term, uint32_t *pixels, int32_t width, int32_t height, int32_t stride) {

    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!term || !pixels || (uintptr_t)pixels < 0x10000) {
        return;
    }

    /* Validate stride and dimensions to prevent buffer overflow */
    if (stride <= 0 || stride > 10000 || width <= 0 || height <= 0) {
        return;
    }

    /* Clear background - use min of expected size and actual buffer size */
    int32_t clear_height = TERM_ROWS * FONT_HEIGHT;
    int32_t clear_width = TERM_COLS * FONT_WIDTH;
    if (clear_height > height) clear_height = height;
    if (clear_width > width) clear_width = width;

    for (int y = 0; y < clear_height; y++) {
        uint32_t *line = pixels + (size_t)y * (size_t)stride;
        for (int x = 0; x < clear_width; x++) {
            line[x] = COLOR_BLACK;
        }
    }

    /* Render each character */
    for (int row = 0; row < TERM_ROWS; row++) {
        for (int col = 0; col < TERM_COLS; col++) {
            struct term_cell *cell = &term->grid[row][col];
            int px = col * FONT_WIDTH;
            int py = row * FONT_HEIGHT;

            font_render_char(cell->ch, pixels, px, py, stride, width, height,
                           cell->fg_color, cell->bg_color);
        }
    }

    /* Render cursor (simple block cursor) */
    if (term->cursor_visible && term->cursor_x >= 0 && term->cursor_x < TERM_COLS &&
        term->cursor_y >= 0 && term->cursor_y < TERM_ROWS) {
        int cx = term->cursor_x * FONT_WIDTH;
        int cy = term->cursor_y * FONT_HEIGHT;

        for (int y = 0; y < FONT_HEIGHT; y++) {
            int32_t line_y = cy + y;
            if (line_y >= height) break;  /* Bounds check */

            uint32_t *line = pixels + (size_t)line_y * (size_t)stride + cx;
            int32_t max_x = FONT_WIDTH;
            if (cx + max_x > width) max_x = width - cx;

            for (int x = 0; x < max_x; x++) {
                line[x] = COLOR_GREEN;  /* Green cursor */
            }
        }
    }
}

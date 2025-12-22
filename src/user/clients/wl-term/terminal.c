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

static void term_handle_escape(struct terminal *term) {
    /* Simple ANSI escape sequence parser */
    if (term->escape_len == 0) {
        return;
    }

    /* Clear screen: ESC[2J */
    if (term->escape_len >= 2 && term->escape_buf[0] == '[' &&
        term->escape_buf[1] == '2' && term->escape_len >= 3 &&
        term->escape_buf[2] == 'J') {
        term_clear(term);
        return;
    }

    /* Cursor home: ESC[H */
    if (term->escape_len >= 1 && term->escape_buf[0] == '[' &&
        term->escape_len >= 2 && term->escape_buf[1] == 'H') {
        term->cursor_x = 0;
        term->cursor_y = 0;
        return;
    }

    /* Ignore other escape sequences for now */
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
        return -1;
    }

    char buf[256];
    long n = sys_read(term->shell_stdout_fd, buf, sizeof(buf));
    if (n > 0) {
        term_write(term, buf, (size_t)n);
        return (int)n;
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
    (void)width;
    (void)height;

    /* Defensive check: reject NULL or suspiciously low pointer values */
    if (!term || !pixels || (uintptr_t)pixels < 0x10000) {
        return;
    }

    /* Validate stride to prevent buffer overflow */
    if (stride <= 0 || stride > 10000) {
        return;
    }

    /* Clear background */
    for (int y = 0; y < TERM_ROWS * FONT_HEIGHT; y++) {
        uint32_t *line = pixels + (size_t)y * (size_t)stride;
        for (int x = 0; x < TERM_COLS * FONT_WIDTH; x++) {
            line[x] = COLOR_BLACK;
        }
    }

    /* Render each character */
    for (int row = 0; row < TERM_ROWS; row++) {
        for (int col = 0; col < TERM_COLS; col++) {
            struct term_cell *cell = &term->grid[row][col];
            int px = col * FONT_WIDTH;
            int py = row * FONT_HEIGHT;

            font_render_char(cell->ch, pixels, px, py, stride,
                           cell->fg_color, cell->bg_color);
        }
    }

    /* Render cursor (simple block cursor) */
    if (term->cursor_visible && term->cursor_x >= 0 && term->cursor_x < TERM_COLS &&
        term->cursor_y >= 0 && term->cursor_y < TERM_ROWS) {
        int cx = term->cursor_x * FONT_WIDTH;
        int cy = term->cursor_y * FONT_HEIGHT;

        for (int y = 0; y < FONT_HEIGHT; y++) {
            uint32_t *line = pixels + (size_t)(cy + y) * (size_t)stride + cx;
            for (int x = 0; x < FONT_WIDTH; x++) {
                line[x] = COLOR_GREEN;  /* Green cursor */
            }
        }
    }
}

/* terminal.h - Terminal emulator state and operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef WL_TERM_TERMINAL_H
#define WL_TERM_TERMINAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Terminal dimensions */
#define TERM_COLS 80
#define TERM_ROWS 25
#define SCROLLBACK_LINES 200  /* Lines of scrollback history */

/* Character cell structure */
struct term_cell {
    char ch;
    uint32_t fg_color;
    uint32_t bg_color;
};

/* Terminal state */
struct terminal {
    struct term_cell grid[TERM_ROWS][TERM_COLS];
    int cursor_x;
    int cursor_y;
    uint32_t fg_color;
    uint32_t bg_color;
    bool cursor_visible;

    /* Scrollback buffer (circular) */
    struct term_cell scrollback[SCROLLBACK_LINES][TERM_COLS];
    int scrollback_count;   /* Number of lines stored (0..SCROLLBACK_LINES) */
    int scrollback_head;    /* Next write position (circular) */
    int scroll_offset;      /* Lines scrolled back (0 = at bottom, >0 = viewing history) */

    /* Shell process pipes */
    int shell_stdin_fd;     /* Write to shell */
    int shell_stdout_fd;    /* Read from shell */
    int shell_pid;

    /* Escape sequence parser state */
    enum {
        TERM_STATE_NORMAL,
        TERM_STATE_ESC,
        TERM_STATE_CSI,
    } parser_state;

    char escape_buf[64];
    int escape_len;
};

/* Initialize terminal state */
void term_init(struct terminal *term);

/* Write character to terminal (handles escape sequences) */
void term_putchar(struct terminal *term, char ch);

/* Write string to terminal */
void term_write(struct terminal *term, const char *data, size_t len);

/* Read from shell and update terminal */
int term_read_shell(struct terminal *term);

/* Send input to shell */
void term_send_key(struct terminal *term, char ch);

/* Render terminal to pixel buffer */
void term_render(struct terminal *term, uint32_t *pixels, int32_t width, int32_t height, int32_t stride);

/* Clear terminal screen */
void term_clear(struct terminal *term);

/* Scroll terminal up by one line (pushes top line to scrollback) */
void term_scroll(struct terminal *term);

/* Scroll view into history (positive = back, negative = forward) */
void term_scroll_view(struct terminal *term, int delta);

/* Reset scroll to bottom (live view) */
void term_scroll_to_bottom(struct terminal *term);

#endif /* WL_TERM_TERMINAL_H */

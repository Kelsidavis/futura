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

/* Terminal dimensions — defaults and compile-time maximums */
#define TERM_COLS 80           /* Default columns */
#define TERM_ROWS 25           /* Default rows */
#define TERM_MAX_COLS 128      /* Max columns (1024px / 8px font) */
#define TERM_MAX_ROWS 48       /* Max rows (768px / 16px font) */
#define SCROLLBACK_LINES 1000  /* Lines of scrollback history */

/* Tab stop interval */
#define TAB_STOP_WIDTH 8

/* Maximum window title length */
#define TERM_TITLE_MAX 256

/* Cursor blink interval in milliseconds */
#define CURSOR_BLINK_MS 500

/* Character cell structure */
struct term_cell {
    char ch;
    uint32_t fg_color;
    uint32_t bg_color;
};

/* Terminal state */
struct terminal {
    struct term_cell (*grid)[TERM_MAX_COLS];  /* mmap-allocated [MAX_ROWS][MAX_COLS] */
    int cols;  /* current column count (dynamic, <= TERM_MAX_COLS) */
    int rows;  /* current row count (dynamic, <= TERM_MAX_ROWS) */
    int cursor_x;
    int cursor_y;
    int saved_cursor_x;  /* For ESC[s / ESC[u (SCO save/restore cursor) */
    int saved_cursor_y;
    uint32_t fg_color;
    uint32_t bg_color;
    bool cursor_visible;

    /* Cursor blink state */
    bool cursor_blink_on;        /* Current blink phase (on/off) */
    uint64_t cursor_blink_time;  /* Last blink toggle timestamp (ms) */

    /* Scrollback buffer (circular, dynamically allocated) */
    struct term_cell (*scrollback)[TERM_MAX_COLS];
    int scrollback_count;   /* Number of lines stored (0..SCROLLBACK_LINES) */
    int scrollback_head;    /* Next write position (circular) */
    int scroll_offset;      /* Lines scrolled back (0 = at bottom, >0 = viewing history) */

    /* Tab stops (one bool per column) */
    bool tab_stops[TERM_MAX_COLS];

    /* Window title (set by OSC 0/2) */
    char title[TERM_TITLE_MAX];
    bool title_changed;  /* Flag for main.c to pick up title updates */

    /* Shell process pipes */
    int shell_stdin_fd;     /* Write to shell */
    int shell_stdout_fd;    /* Read from shell */
    int shell_pid;

    /* Escape sequence parser state */
    enum {
        TERM_STATE_NORMAL,
        TERM_STATE_ESC,
        TERM_STATE_CSI,
        TERM_STATE_OSC,
    } parser_state;

    char escape_buf[64];
    int escape_len;

    /* OSC sequence buffer */
    char osc_buf[TERM_TITLE_MAX + 16];
    int osc_len;
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
void term_render(struct terminal *term, uint32_t *pixels, int32_t width, int32_t height, int32_t stride,
                 int32_t pad_x, int32_t pad_y);

/* Resize terminal grid (clamps to MAX dimensions, updates cursor) */
void term_resize(struct terminal *term, int new_cols, int new_rows);

/* Clear terminal screen */
void term_clear(struct terminal *term);

/* Scroll terminal up by one line (pushes top line to scrollback) */
void term_scroll(struct terminal *term);

/* Scroll view into history (positive = back, negative = forward) */
void term_scroll_view(struct terminal *term, int delta);

/* Reset scroll to bottom (live view) */
void term_scroll_to_bottom(struct terminal *term);

/* Get current window title (set by OSC 0/2 sequences) */
const char *term_get_title(struct terminal *term);

/* Update cursor blink state; call each frame. Returns true if redraw needed. */
bool term_update_blink(struct terminal *term, uint64_t now_ms);

/* Free dynamically allocated scrollback buffer */
void term_destroy(struct terminal *term);

#endif /* WL_TERM_TERMINAL_H */

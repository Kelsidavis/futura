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
    term->cursor_blink_on = true;
    term->cursor_blink_time = 0;
    term->parser_state = TERM_STATE_NORMAL;
    term->escape_len = 0;
    term->osc_len = 0;

    /* Initialize tab stops every TAB_STOP_WIDTH columns */
    for (int x = 0; x < TERM_COLS; x++) {
        term->tab_stops[x] = (x % TAB_STOP_WIDTH == 0);
    }

    /* Set default title */
    const char *default_title = "Futura Terminal";
    for (int i = 0; default_title[i] && i < TERM_TITLE_MAX - 1; i++) {
        term->title[i] = default_title[i];
    }
    term->title_changed = false;

    /* Allocate scrollback buffer via mmap (too large for stack) */
    size_t sb_size = (size_t)SCROLLBACK_LINES * TERM_COLS * sizeof(struct term_cell);
    void *sb = (void *)sys_mmap(NULL, (long)sb_size, 0x3 /* PROT_READ|PROT_WRITE */,
                                 0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
    if (sb && (long)sb > 0 && (uintptr_t)sb >= 0x10000) {
        term->scrollback = (struct term_cell (*)[TERM_COLS])sb;
    } else {
        term->scrollback = NULL;  /* Scrollback unavailable */
    }

    term->shell_stdin_fd = -1;
    term->shell_stdout_fd = -1;
    term->shell_pid = -1;
}

void term_destroy(struct terminal *term) {
    if (term->scrollback) {
        size_t sb_size = (size_t)SCROLLBACK_LINES * TERM_COLS * sizeof(struct term_cell);
        sys_munmap_call(term->scrollback, (long)sb_size);
        term->scrollback = NULL;
    }
}

void term_scroll(struct terminal *term) {
    /* Save top row to scrollback before discarding */
    if (term->scrollback) {
        for (int x = 0; x < TERM_COLS; x++) {
            term->scrollback[term->scrollback_head][x] = term->grid[0][x];
        }
        term->scrollback_head = (term->scrollback_head + 1) % SCROLLBACK_LINES;
        if (term->scrollback_count < SCROLLBACK_LINES) term->scrollback_count++;
    }

    /* If viewing history, auto-scroll to keep position stable */
    if (term->scroll_offset > 0 && term->scroll_offset < term->scrollback_count)
        term->scroll_offset++;

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

void term_scroll_view(struct terminal *term, int delta) {
    term->scroll_offset += delta;
    if (term->scroll_offset < 0) term->scroll_offset = 0;
    if (term->scroll_offset > term->scrollback_count) term->scroll_offset = term->scrollback_count;
}

void term_scroll_to_bottom(struct terminal *term) {
    term->scroll_offset = 0;
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

/* Handle OSC (Operating System Command) sequences.
 * Format: ESC ] Ps ; Pt BEL   (or ESC ] Ps ; Pt ST)
 * Ps=0: Set icon name and window title to Pt
 * Ps=2: Set window title to Pt
 */
static void term_handle_osc(struct terminal *term) {
    if (term->osc_len < 1) return;

    /* Parse the numeric parameter (before the semicolon) */
    int param = 0;
    int i = 0;
    while (i < term->osc_len && term->osc_buf[i] >= '0' && term->osc_buf[i] <= '9') {
        param = param * 10 + (term->osc_buf[i] - '0');
        i++;
    }

    /* Skip the semicolon separator */
    if (i < term->osc_len && term->osc_buf[i] == ';') {
        i++;
    } else {
        return;  /* Malformed: no semicolon */
    }

    /* Remaining text is the string parameter */
    const char *text = &term->osc_buf[i];
    int text_len = term->osc_len - i;

    switch (param) {
    case 0: /* Set icon name and window title */
    case 2: /* Set window title */
        if (text_len > 0) {
            int copy_len = text_len;
            if (copy_len >= TERM_TITLE_MAX) copy_len = TERM_TITLE_MAX - 1;
            for (int j = 0; j < copy_len; j++) {
                term->title[j] = text[j];
            }
            term->title[copy_len] = '\0';
            term->title_changed = true;
        }
        break;
    default:
        break;  /* Ignore unknown OSC parameters */
    }
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
        if (row < 0) row = 0;
        if (row >= TERM_ROWS) row = TERM_ROWS - 1;
        if (col < 0) col = 0;
        if (col >= TERM_COLS) col = TERM_COLS - 1;
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
    /* Handle OSC sequences: accumulate until BEL (\007) or ST (ESC \) */
    if (term->parser_state == TERM_STATE_OSC) {
        if (ch == '\007') {
            /* BEL terminates OSC */
            term->osc_buf[term->osc_len] = '\0';
            term_handle_osc(term);
            term->parser_state = TERM_STATE_NORMAL;
            term->osc_len = 0;
        } else if (ch == '\033') {
            /* Could be ST (ESC \) — peek ahead: for now, treat bare ESC
             * during OSC as terminator (ST second byte handled next call) */
            term->osc_buf[term->osc_len] = '\0';
            term_handle_osc(term);
            term->parser_state = TERM_STATE_ESC;
            term->osc_len = 0;
            term->escape_len = 0;
        } else if (term->osc_len < (int)sizeof(term->osc_buf) - 1) {
            term->osc_buf[term->osc_len++] = ch;
        }
        return;
    }

    /* Handle CSI escape sequences */
    if (term->parser_state == TERM_STATE_ESC) {
        /* First byte after ESC: check for OSC introducer ']' */
        if (term->escape_len == 0 && ch == ']') {
            term->parser_state = TERM_STATE_OSC;
            term->osc_len = 0;
            return;
        }

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
        /* Advance to the next tab stop.  Walk forward from current position
         * and stop at the first column that has a tab stop set.  If none is
         * found before the right margin, clamp to the last column. */
        int start = term->cursor_x + 1;
        bool found = false;
        for (int x = start; x < TERM_COLS; x++) {
            if (term->tab_stops[x]) {
                term->cursor_x = x;
                found = true;
                break;
            }
        }
        if (!found) {
            /* No tab stop before right margin: wrap to next line */
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

    /* Render each character — show scrollback if offset > 0 */
    for (int row = 0; row < TERM_ROWS; row++) {
        struct term_cell *cell_row;
        struct term_cell scrollback_row[TERM_COLS]; /* temp for scrollback rows */

        if (term->scrollback && term->scroll_offset > 0 && row < term->scroll_offset &&
            row < term->scrollback_count) {
            /* This row shows a scrollback line */
            int sb_line = term->scroll_offset - row;
            int sb_idx = (term->scrollback_head - sb_line + SCROLLBACK_LINES) % SCROLLBACK_LINES;
            for (int c = 0; c < TERM_COLS; c++) scrollback_row[c] = term->scrollback[sb_idx][c];
            cell_row = scrollback_row;
        } else {
            /* Normal grid row (offset by scrollback lines shown) */
            int grid_row = row - (term->scroll_offset < TERM_ROWS ? term->scroll_offset : TERM_ROWS - 1);
            if (grid_row < 0) grid_row = 0;
            if (grid_row >= TERM_ROWS) grid_row = TERM_ROWS - 1;
            cell_row = term->grid[grid_row];
        }

        for (int col = 0; col < TERM_COLS; col++) {
            int px = col * FONT_WIDTH;
            int py = row * FONT_HEIGHT;
            font_render_char(cell_row[col].ch, pixels, px, py, stride, width, height,
                           cell_row[col].fg_color, cell_row[col].bg_color);
        }
    }

    /* Render blinking block cursor.
     * When blink phase is off, render the character under the cursor normally
     * (i.e., skip the cursor overlay) so the cursor appears to vanish. */
    if (term->cursor_visible && term->cursor_blink_on &&
        term->cursor_x >= 0 && term->cursor_x < TERM_COLS &&
        term->cursor_y >= 0 && term->cursor_y < TERM_ROWS) {
        int cx = term->cursor_x * FONT_WIDTH;
        int cy = term->cursor_y * FONT_HEIGHT;
        char under_ch = term->grid[term->cursor_y][term->cursor_x].ch;
        uint32_t cursor_fg = COLOR_BLACK;
        uint32_t cursor_bg = COLOR_GREEN;

        /* Draw the block: fill background with cursor color, then render
         * the character on top in inverted colors so it remains readable. */
        for (int y = 0; y < FONT_HEIGHT; y++) {
            int32_t line_y = cy + y;
            if (line_y >= height) break;

            uint32_t *line = pixels + (size_t)line_y * (size_t)stride + cx;
            int32_t max_x = FONT_WIDTH;
            if (cx + max_x > width) max_x = width - cx;

            for (int x = 0; x < max_x; x++) {
                line[x] = cursor_bg;
            }
        }

        /* Re-render the character under the cursor in inverted colors */
        if (under_ch >= 32 && under_ch < 127) {
            font_render_char(under_ch, pixels, cx, cy, stride, width, height,
                           cursor_fg, cursor_bg);
        }
    }
}

const char *term_get_title(struct terminal *term) {
    return term->title;
}

bool term_update_blink(struct terminal *term, uint64_t now_ms) {
    if (!term->cursor_visible) return false;

    if (now_ms - term->cursor_blink_time >= CURSOR_BLINK_MS) {
        term->cursor_blink_on = !term->cursor_blink_on;
        term->cursor_blink_time = now_ms;
        return true;  /* Redraw needed */
    }
    return false;
}

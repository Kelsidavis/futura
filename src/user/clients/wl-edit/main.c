/* wl-edit - Minimal Wayland text editor for Horizon DE
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Usage:  wl-edit [file]
 *
 * Controls:
 *   Arrows / PgUp / PgDn   Navigate
 *   Home / End             Jump to line start / end
 *   Backspace / Delete     Edit
 *   Enter                  Split line
 *   Ctrl+S                 Save
 *   Ctrl+Q                 Quit
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <errno.h>
#include <futura/compat/posix_shm.h>
#include <user/stdio.h>
#include <user/signal.h>
#include <user/sys.h>
#include <shared/fut_timespec.h>

#include <wayland-client-core.h>
#include <wayland-client-protocol.h>
#include "xdg-shell-client-protocol.h"
#include "font.h"

#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define PROT_READ   0x0001
#define PROT_WRITE  0x0002
#define MAP_SHARED  0x0001

/* Visual layout */
#define ED_PAD        8
#define ED_STATUS_H   18
#define ED_MARGIN_X   4
#define ED_VIS_COLS   80
#define ED_VIS_ROWS   24
#define ED_GUTTER_W   (4 * FONT_WIDTH + 4)
/* Width must include the line-number gutter and both content margins,
 * otherwise the visible text column count is gutter-bytes shorter than
 * ED_VIS_COLS and long lines get clipped. */
#define ED_WIDTH      (ED_GUTTER_W + 2 * ED_MARGIN_X + ED_VIS_COLS * FONT_WIDTH)
#define ED_HEIGHT     (ED_VIS_ROWS * FONT_HEIGHT + 2 * ED_PAD + ED_STATUS_H)

/* Buffer limits */
#define ED_MAX_LINES  256
#define ED_MAX_COL    128

/* Colors (Catppuccin Mocha-inspired) */
#define COL_BG        0xFF1E1E2Eu
#define COL_TEXT      0xFFCDD6F4u
#define COL_CURSOR    0xFF89B4FAu
#define COL_GUTTER    0xFF313244u
#define COL_GUTTER_FG 0xFF6C7086u
#define COL_STATUS_BG 0xFF11111Bu
#define COL_STATUS_FG 0xFFA6ADC8u
#define COL_STATUS_HI 0xFFF38BA8u  /* dirty indicator */

/* Editor state (in BSS — ~33KB) */
static char ed_lines[ED_MAX_LINES][ED_MAX_COL + 1];
static int  ed_line_len[ED_MAX_LINES];
static int  ed_line_count = 1;
static int  ed_cursor_row = 0;
static int  ed_cursor_col = 0;
static int  ed_scroll_y   = 0;
static int  ed_scroll_x   = 0;
static bool ed_dirty      = false;
/* Set when load_file saw an error other than -ENOENT — saving back to
 * the same path would clobber the original (e.g. a directory) with our
 * empty buffer. Cleared once the user explicitly recovers (currently:
 * never; saving from this state is just refused). */
static bool ed_load_failed = false;
static char ed_filename[256] = "/tmp/scratch.txt";
static char ed_status_msg[64] = "";
static uint64_t ed_status_expire_ms = 0;

/* Forward decl for tick_ms — defined later with the keyboard-repeat state. */
static uint64_t tick_ms;

/* Client state */
struct client_state {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct xdg_wm_base *xdg_wm_base;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;

    bool configured;
    uint32_t configure_serial;
    struct wl_callback *frame_cb;
    bool frame_done;
    bool needs_redraw;

    void *shm_data;
    size_t shm_size;
    int shm_fd;
    struct wl_shm_pool *pool;
    struct wl_buffer *buffer;

    int32_t pixel_width;
    int32_t pixel_height;

    bool running;
};

/* ─── Helpers ─── */

static size_t ed_strlen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void ed_set_status(const char *msg, uint64_t now_ms) {
    int i = 0;
    while (msg[i] && i < (int)sizeof(ed_status_msg) - 1) {
        ed_status_msg[i] = msg[i];
        i++;
    }
    ed_status_msg[i] = '\0';
    ed_status_expire_ms = now_ms + 2500;
}

/* Ensure cursor visible by adjusting scroll */
static void ed_ensure_visible(void) {
    if (ed_cursor_row < ed_scroll_y) ed_scroll_y = ed_cursor_row;
    if (ed_cursor_row >= ed_scroll_y + ED_VIS_ROWS)
        ed_scroll_y = ed_cursor_row - ED_VIS_ROWS + 1;
    if (ed_scroll_y < 0) ed_scroll_y = 0;

    /* Horizontal: keep the cursor inside the visible columns. Without
     * this the cursor (and any text past column ED_VIS_COLS) just
     * disappears off the right edge while the user is still typing. */
    if (ed_cursor_col < ed_scroll_x) ed_scroll_x = ed_cursor_col;
    if (ed_cursor_col >= ed_scroll_x + ED_VIS_COLS)
        ed_scroll_x = ed_cursor_col - ED_VIS_COLS + 1;
    if (ed_scroll_x < 0) ed_scroll_x = 0;
}

/* ─── File I/O ─── */

static void ed_load_file(const char *path) {
    ed_line_count = 1;
    ed_line_len[0] = 0;
    ed_lines[0][0] = '\0';

    ed_load_failed = false;
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        /* -ENOENT means the file genuinely doesn't exist yet — that's
         * the "open as a fresh blank buffer" path. Other errors
         * (-EACCES on a real-but-unreadable file, -EIO, …) shouldn't
         * be papered over as "(new file)" because Ctrl+S would then
         * clobber the original on disk. Surface the real outcome so
         * the user sees something is wrong before they save. */
        if (fd == -2 /* -ENOENT */) {
            ed_set_status("(new file)", 0);
        } else if (fd == -13 /* -EACCES */) {
            ed_set_status("permission denied", 0);
            ed_load_failed = true;
        } else {
            ed_set_status("open failed", 0);
            ed_load_failed = true;
        }
        return;
    }

    char buf[512];
    int row = 0, col = 0;
    long n;
    bool truncated = false;
    bool read_error = false;
    int read_errno = 0;
    while ((n = sys_read(fd, buf, sizeof(buf))) != 0) {
        if (n < 0) {
            /* Distinguish "this isn't readable as a file" (EISDIR on a
             * directory passed in by accident from wl-files Enter on
             * a symlink-to-dir) from generic IO failure. Without the
             * branch the user sees an empty buffer and might Ctrl+S,
             * clobbering whatever sys_open creates at that path. */
            read_error = true;
            read_errno = (int)n;
            break;
        }
        for (long i = 0; i < n; i++) {
            if (row >= ED_MAX_LINES) {
                /* Saw at least one more byte past the buffer cap. */
                truncated = true;
                break;
            }
            unsigned char ch = (unsigned char)buf[i];
            if (ch == '\n') {
                ed_lines[row][col] = '\0';
                ed_line_len[row] = col;
                row++;
                col = 0;
                if (row < ED_MAX_LINES) {
                    ed_line_len[row] = 0;
                    ed_lines[row][0] = '\0';
                }
            } else if (ch == '\r') {
                /* skip */
            } else if (ch == '\t') {
                /* expand tab to up to 4 spaces */
                for (int k = 0; k < 4 && col < ED_MAX_COL; k++) {
                    ed_lines[row][col++] = ' ';
                }
            } else if (ch >= 32 && ch < 127) {
                if (col < ED_MAX_COL) {
                    ed_lines[row][col++] = (char)ch;
                } else {
                    /* Line longer than ED_MAX_COL — silently dropping
                     * the tail and letting the user save would chop
                     * everything past col 128 off the file. Flag it
                     * the same way as the row overflow. */
                    truncated = true;
                }
            } else if (ch == 0) {
                /* NUL byte — almost certainly a binary file, not text.
                 * Saving the parsed buffer back over a binary would
                 * corrupt it (every NUL/control byte gets dropped on
                 * load). Flag the load as failed so Ctrl+S refuses. */
                read_error = true;
                read_errno = -22 /* -EINVAL */;
                break;
            }
        }
        if (read_error || truncated) break;
    }
    if (col > 0 || row == 0) {
        ed_lines[row][col] = '\0';
        ed_line_len[row] = col;
        row++;
    }
    ed_line_count = row > 0 ? row : 1;
    sys_close(fd);
    ed_dirty = false;
    if (read_error) {
        if (read_errno == -21) {
            ed_set_status("not a regular file", 0);
        } else if (read_errno == -22) {
            ed_set_status("binary file - save refused", 0);
        } else {
            ed_set_status("read failed", 0);
        }
        ed_load_failed = true;
    } else if (truncated) {
        /* Warn the user: saving from this state would silently DROP
         * the unloaded tail. Refuse the save too — same reason as
         * the binary-file path: writing back the partial buffer
         * would lose data. */
        ed_set_status("file truncated to fit buffer", 0);
        ed_load_failed = true;
    }
}

/* Writes the full buffer, looping past short writes. Returns false on any
 * error so the caller can surface a "save failed" status instead of
 * silently truncating the file. */
static bool ed_write_all(int fd, const char *data, long len) {
    long off = 0;
    while (off < len) {
        long w = sys_write(fd, data + off, len - off);
        if (w <= 0) return false;
        off += w;
    }
    return true;
}

static bool ed_save_file(const char *path) {
    /* Write to a sibling .tmp file and rename. Atomically replaces the
     * target so a write failure (disk full, signal, etc.) leaves the
     * original file intact instead of truncated and half-written. */
    char tmp_path[sizeof(ed_filename) + 16];
    int tlen = 0;
    while (path[tlen] && tlen < (int)sizeof(tmp_path) - 8) {
        tmp_path[tlen] = path[tlen];
        tlen++;
    }
    const char *suffix = ".wled.tmp";
    while (*suffix && tlen < (int)sizeof(tmp_path) - 1) {
        tmp_path[tlen++] = *suffix++;
    }
    tmp_path[tlen] = '\0';

    int fd = sys_open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    /* Always terminate every line with \n. Without this, trailing empty
     * lines are lost on save (saving N empty lines wrote only N-1 newlines,
     * which reloads as N-1 lines). The loader treats a trailing \n as a
     * line terminator, so this round-trips correctly. */
    bool ok = true;
    for (int r = 0; r < ed_line_count && ok; r++) {
        if (ed_line_len[r] > 0) {
            if (!ed_write_all(fd, ed_lines[r], ed_line_len[r])) {
                ok = false;
                break;
            }
        }
        if (!ed_write_all(fd, "\n", 1)) {
            ok = false;
            break;
        }
    }
    sys_close(fd);
    if (!ok) {
        /* Clean up the half-written temp file — leaving it behind
         * pollutes the directory each failed save and the bytes weren't
         * useful to inspect anyway (we already reported "save failed"). */
        sys_unlink(tmp_path);
        return false;
    }
    if (sys_rename_call(tmp_path, path) < 0) {
        /* Rename failed (e.g. target is a dir, cross-device, EACCES on
         * the parent). The temp file is fully written but stranded —
         * unlink so it doesn't accumulate every retry. */
        sys_unlink(tmp_path);
        return false;
    }
    ed_dirty = false;
    return true;
}

/* ─── Edit ops ─── */

static void ed_insert_char(char ch) {
    if (ed_line_len[ed_cursor_row] >= ED_MAX_COL) {
        /* Line full — silently dropping the keystroke looked like a stuck
         * editor. (Only fires once per keystroke, so the noise is bounded.) */
        ed_set_status("line full", tick_ms);
        return;
    }
    /* Defensive: clamp cursor inside the line. If the cursor were past
     * the end, the shift loop would no-op and the insert would land in
     * uninitialized bytes between line_len and cursor_col, leaking
     * stack/garbage into the saved file. */
    if (ed_cursor_col > ed_line_len[ed_cursor_row]) {
        ed_cursor_col = ed_line_len[ed_cursor_row];
    }
    char *line = ed_lines[ed_cursor_row];
    int len = ed_line_len[ed_cursor_row];
    for (int i = len; i > ed_cursor_col; i--) line[i] = line[i - 1];
    line[ed_cursor_col] = ch;
    line[len + 1] = '\0';
    ed_line_len[ed_cursor_row] = len + 1;
    ed_cursor_col++;
    ed_dirty = true;
}

static void ed_split_line(void) {
    if (ed_line_count >= ED_MAX_LINES) {
        /* Buffer full — silently dropping Enter looked like a hung editor. */
        ed_set_status("buffer full", tick_ms);
        return;
    }
    /* Defensive: clamp cursor inside the current line. The navigation
     * paths already do this, but if any future code path leaves the
     * cursor past line_len then `tail` below would go negative and
     * next[tail] would be a wild write before the buffer. */
    if (ed_cursor_col > ed_line_len[ed_cursor_row]) {
        ed_cursor_col = ed_line_len[ed_cursor_row];
    }
    /* Shift lines below down by one */
    for (int i = ed_line_count; i > ed_cursor_row + 1; i--) {
        memcpy(ed_lines[i], ed_lines[i - 1], ED_MAX_COL + 1);
        ed_line_len[i] = ed_line_len[i - 1];
    }
    /* New line gets tail of current line */
    char *cur = ed_lines[ed_cursor_row];
    char *next = ed_lines[ed_cursor_row + 1];
    int tail = ed_line_len[ed_cursor_row] - ed_cursor_col;
    for (int i = 0; i < tail; i++) next[i] = cur[ed_cursor_col + i];
    next[tail] = '\0';
    ed_line_len[ed_cursor_row + 1] = tail;
    cur[ed_cursor_col] = '\0';
    ed_line_len[ed_cursor_row] = ed_cursor_col;
    ed_cursor_row++;
    ed_cursor_col = 0;
    ed_line_count++;
    ed_dirty = true;
}

static void ed_backspace(void) {
    if (ed_cursor_col > 0) {
        char *line = ed_lines[ed_cursor_row];
        int len = ed_line_len[ed_cursor_row];
        for (int i = ed_cursor_col - 1; i < len - 1; i++) line[i] = line[i + 1];
        line[len - 1] = '\0';
        ed_line_len[ed_cursor_row] = len - 1;
        ed_cursor_col--;
        ed_dirty = true;
    } else if (ed_cursor_row > 0) {
        /* Merge with previous line. Refuse if it would truncate. */
        int prev_len = ed_line_len[ed_cursor_row - 1];
        int cur_len = ed_line_len[ed_cursor_row];
        if (prev_len + cur_len > ED_MAX_COL) {
            ed_set_status("line too long to join", tick_ms);
            return;
        }
        int new_len = prev_len + cur_len;
        char *prev = ed_lines[ed_cursor_row - 1];
        char *cur = ed_lines[ed_cursor_row];
        for (int i = 0; i < cur_len; i++) prev[prev_len + i] = cur[i];
        prev[new_len] = '\0';
        ed_line_len[ed_cursor_row - 1] = new_len;
        /* Shift lines up */
        for (int i = ed_cursor_row; i < ed_line_count - 1; i++) {
            memcpy(ed_lines[i], ed_lines[i + 1], ED_MAX_COL + 1);
            ed_line_len[i] = ed_line_len[i + 1];
        }
        ed_line_count--;
        ed_cursor_row--;
        ed_cursor_col = prev_len;
        ed_dirty = true;
    }
}

static void ed_delete_forward(void) {
    int len = ed_line_len[ed_cursor_row];
    if (ed_cursor_col < len) {
        char *line = ed_lines[ed_cursor_row];
        for (int i = ed_cursor_col; i < len - 1; i++) line[i] = line[i + 1];
        line[len - 1] = '\0';
        ed_line_len[ed_cursor_row] = len - 1;
        ed_dirty = true;
    } else if (ed_cursor_row < ed_line_count - 1) {
        /* Join next line. Refuse if the merged line would exceed
         * ED_MAX_COL — silently truncating discards the user's text
         * with no warning. Better to leave the lines split. */
        int next_len = ed_line_len[ed_cursor_row + 1];
        if (len + next_len > ED_MAX_COL) {
            ed_set_status("line too long to join", tick_ms);
            return;
        }
        int new_len = len + next_len;
        char *cur = ed_lines[ed_cursor_row];
        char *next = ed_lines[ed_cursor_row + 1];
        for (int i = 0; i < next_len; i++) cur[len + i] = next[i];
        cur[new_len] = '\0';
        ed_line_len[ed_cursor_row] = new_len;
        for (int i = ed_cursor_row + 1; i < ed_line_count - 1; i++) {
            memcpy(ed_lines[i], ed_lines[i + 1], ED_MAX_COL + 1);
            ed_line_len[i] = ed_line_len[i + 1];
        }
        ed_line_count--;
        ed_dirty = true;
    }
}

/* ─── Rendering ─── */

/* Defensive: clip the rect against the surface dims so a caller passing
 * a negative origin or a too-wide width can't write past the framebuffer
 * row. The caller passes stride = pixel_width, and we treat stride as
 * the row width upper-bound for x and as the surface height for y. */
static void fill_rect(uint32_t *px, int stride, int x0, int y0, int w, int h, uint32_t color) {
    if (w <= 0 || h <= 0) return;
    int x1 = x0 + w;
    int y1 = y0 + h;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > stride) x1 = stride;
    /* y bound: not directly known here; fill_rect callers always pass a
     * rect that should be inside the buffer height — clamp negative top
     * and let the caller's other guards handle bottom. */
    if (x1 <= x0 || y1 <= y0) return;
    for (int y = y0; y < y1; y++) {
        uint32_t *row = px + y * stride;
        for (int x = x0; x < x1; x++) row[x] = color;
    }
}

static void draw_text_run(uint32_t *px, int32_t w, int32_t h, int32_t stride,
                          int x, int y, const char *s, int len,
                          uint32_t fg, uint32_t bg) {
    for (int i = 0; i < len; i++) {
        font_render_char(s[i], px, x + i * FONT_WIDTH, y, stride, w, h, fg, bg);
    }
}

static void render_int(char *out, int v, int width_min) {
    char tmp[12];
    int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else {
        int neg = v < 0;
        if (neg) v = -v;
        while (v > 0) { tmp[n++] = '0' + (v % 10); v /= 10; }
        if (neg) tmp[n++] = '-';
    }
    while (n < width_min) tmp[n++] = ' ';
    int o = 0;
    for (int i = n - 1; i >= 0; i--) out[o++] = tmp[i];
    out[o] = '\0';
}

static void redraw_all(struct client_state *state) {
    if (!state->buffer || !state->shm_data) return;
    if ((uintptr_t)state->shm_data < 0x10000) return;

    uint32_t *px = (uint32_t *)state->shm_data;
    int32_t w = state->pixel_width;
    int32_t h = state->pixel_height;
    int32_t stride = w;

    /* Background */
    fill_rect(px, stride, 0, 0, w, h, COL_BG);

    /* Gutter (line numbers) — width must match ED_GUTTER_W so window
     * sizing and rendering stay in sync. */
    int gutter_w = ED_GUTTER_W;
    fill_rect(px, stride, 0, 0, gutter_w, h - ED_STATUS_H, COL_GUTTER);

    /* Visible rows */
    int vis_rows = (h - ED_STATUS_H - 2 * ED_PAD) / FONT_HEIGHT;
    int vis_cols = (w - gutter_w - 2 * ED_MARGIN_X) / FONT_WIDTH;
    if (vis_rows < 1) vis_rows = 1;
    if (vis_cols < 1) vis_cols = 1;

    /* Text + line numbers */
    for (int vr = 0; vr < vis_rows; vr++) {
        int row = ed_scroll_y + vr;
        int py = ED_PAD + vr * FONT_HEIGHT;

        /* Line number (1-based) */
        char num[6];
        if (row < ed_line_count) {
            render_int(num, row + 1, 4);
            draw_text_run(px, w, h, stride, 2, py, num, 4,
                          COL_GUTTER_FG, COL_GUTTER);
        }

        if (row < ed_line_count) {
            int line_len = ed_line_len[row];
            int start = ed_scroll_x;
            if (start > line_len) start = line_len;
            int avail = line_len - start;
            int len = avail < vis_cols ? avail : vis_cols;
            if (len > 0) {
                draw_text_run(px, w, h, stride,
                              gutter_w + ED_MARGIN_X, py,
                              ed_lines[row] + start, len,
                              COL_TEXT, COL_BG);
            }
        }
    }

    /* Cursor */
    if (ed_cursor_row >= ed_scroll_y && ed_cursor_row < ed_scroll_y + vis_rows &&
        ed_cursor_col >= ed_scroll_x && ed_cursor_col <= ed_scroll_x + vis_cols) {
        int cx = gutter_w + ED_MARGIN_X + (ed_cursor_col - ed_scroll_x) * FONT_WIDTH;
        int cy = ED_PAD + (ed_cursor_row - ed_scroll_y) * FONT_HEIGHT;
        if (cx + 2 <= w && cy + FONT_HEIGHT <= h - ED_STATUS_H) {
            fill_rect(px, stride, cx, cy, 2, FONT_HEIGHT, COL_CURSOR);
            /* Underline existing char — clamp to remaining row width so the
             * underline doesn't write past the buffer when the cursor sits
             * near the right edge. */
            int ul_w = FONT_WIDTH;
            if (cx + ul_w > w) ul_w = w - cx;
            if (ul_w > 0)
                fill_rect(px, stride, cx, cy + FONT_HEIGHT - 2, ul_w, 2, COL_CURSOR);
        }
    }

    /* Status bar */
    int sy = h - ED_STATUS_H;
    fill_rect(px, stride, 0, sy, w, ED_STATUS_H, COL_STATUS_BG);

    /* Filename + dirty marker */
    int x = 6;
    int ty = sy + (ED_STATUS_H - FONT_HEIGHT) / 2;

    /* Show just the basename */
    const char *base = ed_filename;
    for (const char *p = ed_filename; *p; p++) {
        if (*p == '/') base = p + 1;
    }
    int base_len = (int)ed_strlen(base);
    if (base_len > 32) base_len = 32;
    draw_text_run(px, w, h, stride, x, ty, base, base_len, COL_STATUS_FG, COL_STATUS_BG);
    x += base_len * FONT_WIDTH + 6;

    if (ed_dirty) {
        draw_text_run(px, w, h, stride, x, ty, "*", 1, COL_STATUS_HI, COL_STATUS_BG);
        x += FONT_WIDTH + 6;
    }

    /* Line/col indicator on the right */
    char pos[48];
    int pi = 0;
    const char *lbl = " L";
    while (*lbl) pos[pi++] = *lbl++;
    char tmp[12];
    render_int(tmp, ed_cursor_row + 1, 0);
    for (int k = 0; tmp[k]; k++) pos[pi++] = tmp[k];
    const char *lbl2 = " C";
    while (*lbl2) pos[pi++] = *lbl2++;
    render_int(tmp, ed_cursor_col + 1, 0);
    for (int k = 0; tmp[k]; k++) pos[pi++] = tmp[k];
    const char *lbl3 = "  ^S save  ^Q quit";
    while (*lbl3) pos[pi++] = *lbl3++;
    pos[pi] = '\0';
    int px_right = w - pi * FONT_WIDTH - 6;
    if (px_right < x + 6) px_right = x + 6;
    draw_text_run(px, w, h, stride, px_right, ty, pos, pi, COL_STATUS_FG, COL_STATUS_BG);

    /* Transient status message (centered, replaces line/col when set) */
    if (ed_status_msg[0]) {
        int mlen = (int)ed_strlen(ed_status_msg);
        int mx = (w - mlen * FONT_WIDTH) / 2;
        /* Erase a slot so it doesn't overlap */
        fill_rect(px, stride, mx - 4, sy + 1, mlen * FONT_WIDTH + 8, ED_STATUS_H - 2, COL_STATUS_BG);
        draw_text_run(px, w, h, stride, mx, ty, ed_status_msg, mlen, COL_STATUS_HI, COL_STATUS_BG);
    }

    /* Present */
    if (state->frame_cb) {
        wl_callback_destroy(state->frame_cb);
        state->frame_cb = NULL;
    }
    state->frame_done = false;
    state->frame_cb = wl_surface_frame(state->surface);
    if (!state->frame_cb) state->frame_done = true;

    wl_surface_attach(state->surface, state->buffer, 0, 0);
    wl_surface_damage_buffer(state->surface, 0, 0, w, h);
    wl_surface_commit(state->surface);
    wl_display_flush(state->display);
    state->needs_redraw = false;
}

static void frame_done_cb(void *data, struct wl_callback *cb, uint32_t time) {
    (void)time;
    struct client_state *s = data;
    s->frame_done = true;
    if (s->frame_cb == cb) {
        wl_callback_destroy(cb);
        s->frame_cb = NULL;
    }
}
static const struct wl_callback_listener frame_listener = { .done = frame_done_cb };

/* ─── Wayland plumbing ─── */

static void handle_ping(void *d, struct xdg_wm_base *b, uint32_t s) {
    (void)d; xdg_wm_base_pong(b, s);
}
static const struct xdg_wm_base_listener wm_base_listener = { .ping = handle_ping };

static void xdg_surface_configure(void *d, struct xdg_surface *xs, uint32_t serial) {
    (void)xs;
    struct client_state *s = d;
    s->configure_serial = serial;
    s->configured = true;
}
static const struct xdg_surface_listener xdg_surface_listener = {
    .configure = xdg_surface_configure,
};

static void xdg_toplevel_configure(void *d, struct xdg_toplevel *t,
                                   int32_t w, int32_t h, struct wl_array *a) {
    (void)d; (void)t; (void)w; (void)h; (void)a;
}
static void xdg_toplevel_close(void *d, struct xdg_toplevel *t) {
    (void)t;
    struct client_state *s = d;
    /* Mirror Ctrl+Q's two-step confirmation: don't lose unsaved edits
     * silently when the user clicks the close button or hits Alt+F4. */
    static const char close_warn[] = "unsaved changes - close again to confirm";
    if (ed_dirty) {
        /* Match the Ctrl+Q path: only honour the second click as
         * confirmation while the warning is still visible. Otherwise
         * a stale buffer state from minutes ago would silently
         * accept a single close click. */
        bool armed = (ed_status_msg[0] == close_warn[0] &&
                      ed_strlen(ed_status_msg) == ed_strlen(close_warn) &&
                      tick_ms < ed_status_expire_ms);
        if (!armed) {
            ed_set_status(close_warn, tick_ms);
            s->needs_redraw = true;
            return;
        }
    }
    s->running = false;
}
static const struct xdg_toplevel_listener xdg_toplevel_listener = {
    .configure = xdg_toplevel_configure,
    .close = xdg_toplevel_close,
};

/* Modifier state */
static uint32_t kbd_mods = 0;
static uint64_t tick_ms = 0;  /* tentative def above; this is the real one */
static uint32_t repeat_key = 0;
static uint64_t repeat_deadline_ms = 0;
static uint64_t repeat_start_ms = 0;
#define REPEAT_DELAY_MS    400
#define REPEAT_INTERVAL_MS 40
#define REPEAT_MAX_MS      2000

static char key_to_ascii(uint32_t key, bool shift) {
    if (key >= 2 && key <= 11) {
        const char n[] = "1234567890";
        const char ns[] = "!@#$%^&*()";
        return shift ? ns[key - 2] : n[key - 2];
    }
    if (key >= 16 && key <= 25) {
        const char k[] = "qwertyuiop";
        char c = k[key - 16];
        return shift ? (char)(c - 32) : c;
    }
    if (key >= 30 && key <= 38) {
        const char k[] = "asdfghjkl";
        char c = k[key - 30];
        return shift ? (char)(c - 32) : c;
    }
    if (key >= 44 && key <= 50) {
        const char k[] = "zxcvbnm";
        char c = k[key - 44];
        return shift ? (char)(c - 32) : c;
    }
    switch (key) {
        case 57: return ' ';
        case 12: return shift ? '_' : '-';
        case 13: return shift ? '+' : '=';
        case 26: return shift ? '{' : '[';
        case 27: return shift ? '}' : ']';
        case 39: return shift ? ':' : ';';
        case 40: return shift ? '"' : '\'';
        case 41: return shift ? '~' : '`';
        case 43: return shift ? '|' : '\\';
        case 51: return shift ? '<' : ',';
        case 52: return shift ? '>' : '.';
        case 53: return shift ? '?' : '/';
        default: return 0;
    }
}

static void process_key(struct client_state *s, uint32_t key) {
    bool shift = (kbd_mods & 1) != 0;
    bool ctrl  = (kbd_mods & 4) != 0;

    /* Navigation */
    if (key == 103) { if (ed_cursor_row > 0) { ed_cursor_row--;
        if (ed_cursor_col > ed_line_len[ed_cursor_row]) ed_cursor_col = ed_line_len[ed_cursor_row]; }
        ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 108) { if (ed_cursor_row < ed_line_count - 1) { ed_cursor_row++;
        if (ed_cursor_col > ed_line_len[ed_cursor_row]) ed_cursor_col = ed_line_len[ed_cursor_row]; }
        ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 105) { if (ed_cursor_col > 0) ed_cursor_col--;
        else if (ed_cursor_row > 0) { ed_cursor_row--; ed_cursor_col = ed_line_len[ed_cursor_row]; }
        ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 106) { if (ed_cursor_col < ed_line_len[ed_cursor_row]) ed_cursor_col++;
        else if (ed_cursor_row < ed_line_count - 1) { ed_cursor_row++; ed_cursor_col = 0; }
        ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 102) { ed_cursor_col = 0; ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 107) { ed_cursor_col = ed_line_len[ed_cursor_row]; ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 104) {
        ed_cursor_row -= ED_VIS_ROWS - 1;
        if (ed_cursor_row < 0) ed_cursor_row = 0;
        if (ed_cursor_col > ed_line_len[ed_cursor_row]) ed_cursor_col = ed_line_len[ed_cursor_row];
        ed_ensure_visible(); s->needs_redraw = true; return;
    }
    if (key == 109) {
        ed_cursor_row += ED_VIS_ROWS - 1;
        if (ed_cursor_row >= ed_line_count) ed_cursor_row = ed_line_count - 1;
        if (ed_cursor_col > ed_line_len[ed_cursor_row]) ed_cursor_col = ed_line_len[ed_cursor_row];
        ed_ensure_visible(); s->needs_redraw = true; return;
    }

    if (key == 111) { ed_delete_forward(); ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 14)  { ed_backspace(); ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 28)  { ed_split_line(); ed_ensure_visible(); s->needs_redraw = true; return; }
    if (key == 15)  {
        /* Tab = 4 spaces */
        for (int k = 0; k < 4; k++) ed_insert_char(' ');
        ed_ensure_visible(); s->needs_redraw = true; return;
    }

    /* Ctrl combos */
    if (ctrl) {
        char c = key_to_ascii(key, false);
        if (c == 's') {
            /* Refuse to save if the original load already errored out
             * (e.g. the path is a directory or unreadable for reasons
             * other than ENOENT). Saving would clobber whatever the
             * path actually points to with our blank buffer. */
            if (ed_load_failed) {
                ed_set_status("save refused: original unreadable", tick_ms);
            } else if (ed_save_file(ed_filename)) {
                ed_set_status("saved", tick_ms);
            } else {
                ed_set_status("save failed", tick_ms);
            }
            s->needs_redraw = true;
            return;
        }
        if (c == 'q') {
            /* Don't lose unsaved edits silently. First Ctrl+Q with a
             * dirty buffer arms the warning; a second Ctrl+Q within
             * the status's 2.5s expiry confirms and quits. The
             * "armed" state piggybacks on a dedicated status string. */
            static const char quit_warn[] = "unsaved changes - Ctrl+Q again to quit";
            if (ed_dirty) {
                /* The armed window must also still be unexpired — once
                 * the status fades, the user has visually moved on and
                 * shouldn't lose their work to a stale buffer match. */
                bool armed = (ed_status_msg[0] == quit_warn[0] &&
                              ed_strlen(ed_status_msg) == ed_strlen(quit_warn) &&
                              tick_ms < ed_status_expire_ms);
                if (!armed) {
                    ed_set_status(quit_warn, tick_ms);
                    s->needs_redraw = true;
                    return;
                }
            }
            s->running = false;
            return;
        }
        /* ignore other ctrl combos */
        return;
    }

    /* Regular char */
    char c = key_to_ascii(key, shift);
    if (c >= 32 && c < 127) {
        ed_insert_char(c);
        ed_ensure_visible();
        s->needs_redraw = true;
    }
}

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz) {
    (void)d; (void)k; (void)f; (void)sz;
    if (fd >= 0) sys_close(fd);
}
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s,
                     struct wl_surface *sf, struct wl_array *a) {
    (void)d; (void)k; (void)s; (void)sf; (void)a;
}
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf) {
    (void)d; (void)k; (void)s; (void)sf;
    repeat_key = 0;
}
static void kb_key(void *d, struct wl_keyboard *k, uint32_t ser, uint32_t t,
                   uint32_t key, uint32_t ks) {
    (void)k; (void)ser; (void)t;
    struct client_state *s = d;
    if (!s) return;
    if (ks == WL_KEYBOARD_KEY_STATE_RELEASED) {
        if (key == repeat_key) repeat_key = 0;
        return;
    }
    process_key(s, key);
    /* Don't auto-repeat modifier keys, or any key pressed with ctrl/alt held —
     * otherwise Ctrl+S would re-save every 40ms, and releasing Ctrl mid-repeat
     * would start inserting 's' as a regular character. */
    bool ctrl_or_alt = (kbd_mods & 0xCu) != 0;
    if (ctrl_or_alt ||
        key == 42 || key == 54 || key == 29 || key == 97 ||
        key == 56 || key == 100) {
        repeat_key = 0;
    } else {
        repeat_key = key;
        repeat_deadline_ms = tick_ms + REPEAT_DELAY_MS;
        repeat_start_ms = tick_ms;
    }
}
static void kb_mods(void *d, struct wl_keyboard *k, uint32_t s,
                    uint32_t md, uint32_t ml, uint32_t mlk, uint32_t g) {
    (void)d; (void)k; (void)s; (void)ml; (void)mlk; (void)g;
    kbd_mods = md;
}
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t r, int32_t dl) {
    (void)d; (void)k; (void)r; (void)dl;
}
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap = kb_keymap,
    .enter = kb_enter,
    .leave = kb_leave,
    .key = kb_key,
    .modifiers = kb_mods,
    .repeat_info = kb_repeat,
};

static void seat_caps(void *d, struct wl_seat *s, uint32_t caps) {
    struct client_state *st = d;
    if (!st) return;
    bool wk = (caps & WL_SEAT_CAPABILITY_KEYBOARD) != 0;
    if (wk && !st->keyboard) {
        st->keyboard = wl_seat_get_keyboard(s);
        if (st->keyboard) wl_keyboard_add_listener(st->keyboard, &keyboard_listener, st);
    } else if (!wk && st->keyboard) {
        wl_keyboard_destroy(st->keyboard);
        st->keyboard = NULL;
    }
}
static void seat_name(void *d, struct wl_seat *s, const char *n) {
    (void)d; (void)s; (void)n;
}
static const struct wl_seat_listener seat_listener = {
    .capabilities = seat_caps,
    .name = seat_name,
};

static void reg_global(void *d, struct wl_registry *r, uint32_t name,
                       const char *iface, uint32_t ver) {
    struct client_state *s = d;
    if (strcmp(iface, wl_compositor_interface.name) == 0) {
        uint32_t v = ver < 4 ? ver : 4;
        s->compositor = wl_registry_bind(r, name, &wl_compositor_interface, v);
    } else if (strcmp(iface, wl_shm_interface.name) == 0) {
        s->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    } else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        uint32_t v = ver < 2 ? ver : 2;
        s->xdg_wm_base = wl_registry_bind(r, name, &xdg_wm_base_interface, v);
        xdg_wm_base_add_listener(s->xdg_wm_base, &wm_base_listener, s);
    } else if (strcmp(iface, wl_seat_interface.name) == 0) {
        uint32_t v = ver < 7 ? ver : 7;
        s->seat = wl_registry_bind(r, name, &wl_seat_interface, v);
        if (s->seat) wl_seat_add_listener(s->seat, &seat_listener, s);
    }
}
static void reg_global_remove(void *d, struct wl_registry *r, uint32_t n) {
    (void)d; (void)r; (void)n;
}
static const struct wl_registry_listener registry_listener = {
    .global = reg_global,
    .global_remove = reg_global_remove,
};

int main(int argc, char **argv) {
    /* Ignore SIGPIPE */
    {
        struct sigaction sa = {0};
        sa.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &sa, NULL);
        (void)sa;
    }

    /* Parse filename arg. If argv[1] is longer than ed_filename can
     * hold, refuse to load instead of silently truncating — Ctrl+S
     * would later write to the truncated path. */
    if (argc > 1 && argv[1] && argv[1][0]) {
        int i = 0;
        while (argv[1][i]) i++;
        if (i >= (int)sizeof(ed_filename)) {
            ed_filename[0] = '\0';
            ed_load_failed = true;
            ed_set_status("path too long", 0);
        } else {
            for (int j = 0; j < i; j++) ed_filename[j] = argv[1][j];
            ed_filename[i] = '\0';
        }
    }
    if (!ed_load_failed) {
        ed_load_file(ed_filename);
    }

    struct client_state state = {0};
    state.running = true;
    state.frame_done = true;

    state.display = wl_display_connect(NULL);
    if (!state.display) return -1;
    state.registry = wl_display_get_registry(state.display);
    wl_registry_add_listener(state.registry, &registry_listener, &state);
    wl_display_roundtrip(state.display);

    if (!state.compositor || !state.shm || !state.xdg_wm_base) {
        wl_display_disconnect(state.display);
        return -1;
    }

    state.surface = wl_compositor_create_surface(state.compositor);
    state.xdg_surface = xdg_wm_base_get_xdg_surface(state.xdg_wm_base, state.surface);
    xdg_surface_add_listener(state.xdg_surface, &xdg_surface_listener, &state);
    state.toplevel = xdg_surface_get_toplevel(state.xdg_surface);
    xdg_toplevel_add_listener(state.toplevel, &xdg_toplevel_listener, &state);
    /* Show the file's basename in the title bar so users can tell
     * which document a window belongs to when several editors are
     * open. Falls back to the literal "Text Editor" when no path
     * is set. */
    {
        char title[64];
        const char *base = ed_filename;
        for (int i = 0; ed_filename[i]; i++) {
            if (ed_filename[i] == '/' && ed_filename[i + 1]) {
                base = &ed_filename[i + 1];
            }
        }
        if (!*base) {
            xdg_toplevel_set_title(state.toplevel, "Text Editor");
        } else {
            int ti = 0;
            const char *prefix = "Edit: ";  /* ASCII only — the dock's
                                              * bitmap font renders one
                                              * glyph per byte. */
            while (*prefix && ti < (int)sizeof(title) - 1) title[ti++] = *prefix++;
            for (int i = 0; base[i] && ti < (int)sizeof(title) - 1; i++) {
                title[ti++] = base[i];
            }
            title[ti] = '\0';
            xdg_toplevel_set_title(state.toplevel, title);
        }
    }
    xdg_toplevel_set_app_id(state.toplevel, "wl-edit");
    /* Fixed-size: this client doesn't handle resize. Pinning min == max
     * tells the compositor to suppress resize handles. */
    xdg_toplevel_set_min_size(state.toplevel, ED_WIDTH, ED_HEIGHT);
    xdg_toplevel_set_max_size(state.toplevel, ED_WIDTH, ED_HEIGHT);
    wl_surface_commit(state.surface);

    int waited = 0;
    while (!state.configured && waited < 200) {
        wl_display_roundtrip(state.display);
        waited++;
    }
    if (!state.configured) {
        wl_display_disconnect(state.display);
        return -1;
    }
    xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
    /* Clear the pending-configure latch so the main loop's ack-pending block
     * doesn't re-ack the same serial on the very first iteration. */
    state.configured = false;
    state.configure_serial = 0;

    state.pixel_width = ED_WIDTH;
    state.pixel_height = ED_HEIGHT;
    state.shm_size = (size_t)ED_WIDTH * ED_HEIGHT * 4u;

    char shm_name[32];
    {
        long pid = sys_getpid_call();
        int si = 0;
        const char *pfx = "/wl-edit-";
        while (*pfx) shm_name[si++] = *pfx++;
        if (pid < 0) pid = 0;
        char dg[12]; int nd = 0; long t = pid;
        do { dg[nd++] = '0' + (char)(t % 10); t /= 10; } while (t > 0);
        for (int d = nd - 1; d >= 0; d--) shm_name[si++] = dg[d];
        shm_name[si] = '\0';
    }
    state.shm_fd = fut_shm_create(shm_name, state.shm_size, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (state.shm_fd < 0) { wl_display_disconnect(state.display); return -1; }
    state.shm_data = (void *)sys_mmap(NULL, (long)state.shm_size,
                                      PROT_READ | PROT_WRITE, MAP_SHARED,
                                      state.shm_fd, 0);
    if (state.shm_data == NULL || (long)state.shm_data < 0 ||
        (uintptr_t)state.shm_data < 0x10000) {
        sys_close(state.shm_fd);
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Fault pages */
    {
        volatile uint32_t *p = (volatile uint32_t *)state.shm_data;
        for (size_t i = 0; i < state.shm_size / 4; i++) p[i] = COL_BG;
    }

    state.pool = wl_shm_create_pool(state.shm, state.shm_fd, (int32_t)state.shm_size);
    state.buffer = wl_shm_pool_create_buffer(state.pool, 0,
                                             state.pixel_width, state.pixel_height,
                                             state.pixel_width * 4, WL_SHM_FORMAT_ARGB8888);
    if (!state.pool || !state.buffer) {
        wl_display_disconnect(state.display);
        return -1;
    }

    /* Install frame listener once for future callbacks */
    state.needs_redraw = true;
    redraw_all(&state);
    if (state.frame_cb) {
        wl_callback_add_listener(state.frame_cb, &frame_listener, &state);
    }

    /* Set socket non-blocking */
    {
        int wfd = wl_display_get_fd(state.display);
        if (wfd >= 0) sys_fcntl_call(wfd, 4 /*F_SETFL*/, 0x0800 /*O_NONBLOCK*/);
    }

    while (state.running) {
        tick_ms += 10;

        /* Ack pending configure */
        if (state.configured && state.configure_serial != 0) {
            xdg_surface_ack_configure(state.xdg_surface, state.configure_serial);
            state.configured = false;
            state.needs_redraw = true;
        }

        /* Clear expired status */
        if (ed_status_msg[0] && tick_ms >= ed_status_expire_ms) {
            ed_status_msg[0] = '\0';
            state.needs_redraw = true;
        }

        /* Key repeat */
        if (repeat_key != 0) {
            if (tick_ms - repeat_start_ms > REPEAT_MAX_MS) {
                repeat_key = 0;
            } else if (tick_ms >= repeat_deadline_ms) {
                process_key(&state, repeat_key);
                repeat_deadline_ms = tick_ms + REPEAT_INTERVAL_MS;
            }
        }

        /* Frame-callback timeout: if the compositor stops sending frame.done
         * (e.g. surface fully outside damage region, dropped event), force
         * frame_done so we don't deadlock with needs_redraw=true forever.
         * Match wl-term's ~500ms threshold (50 ticks @ ~10ms). */
        static int ed_frame_wait = 0;
        if (!state.frame_done) {
            if (++ed_frame_wait >= 50) {
                state.frame_done = true;
                ed_frame_wait = 0;
            }
        } else {
            ed_frame_wait = 0;
        }

        if (state.needs_redraw && state.frame_done) {
            redraw_all(&state);
            if (state.frame_cb) {
                wl_callback_add_listener(state.frame_cb, &frame_listener, &state);
            }
        }

        wl_display_flush(state.display);
        {
            int tries = 0;
            while (wl_display_prepare_read(state.display) != 0) {
                wl_display_dispatch_pending(state.display);
                if (++tries > 1000) break;
            }
            if (tries <= 1000) wl_display_read_events(state.display);
        }
        wl_display_dispatch_pending(state.display);

        sys_sched_yield();
        struct fut_timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
        sys_nanosleep_call(&ts, NULL);
    }

    /* Cleanup */
    if (state.frame_cb) wl_callback_destroy(state.frame_cb);
    if (state.buffer) wl_buffer_destroy(state.buffer);
    if (state.pool) wl_shm_pool_destroy(state.pool);
    if (state.shm_data) sys_munmap_call(state.shm_data, (long)state.shm_size);
    if (state.shm_fd >= 0) { sys_close(state.shm_fd); fut_shm_unlink(shm_name); }
    if (state.keyboard) wl_keyboard_destroy(state.keyboard);
    if (state.seat) wl_seat_destroy(state.seat);
    if (state.toplevel) xdg_toplevel_destroy(state.toplevel);
    if (state.xdg_surface) xdg_surface_destroy(state.xdg_surface);
    if (state.surface) wl_surface_destroy(state.surface);
    if (state.xdg_wm_base) xdg_wm_base_destroy(state.xdg_wm_base);
    wl_display_disconnect(state.display);
    return 0;
}

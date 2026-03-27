// SPDX-License-Identifier: MPL-2.0
//
// Framebuffer Text Console Driver for Futura OS (x86-64)
//
// A TTY-style text console that sits above the vesa_fb framebuffer driver.
// Provides ANSI/VT100 escape sequence parsing, a scrollback buffer, and
// full 16-color support.  Delegates actual pixel drawing to the framebuffer
// driver through callback function pointers.
//
// Features:
//   - ANSI/VT100 escape sequence parsing (SGR colors, cursor movement, clear)
//   - Scrollback ring buffer (up to 1000 lines of character+attribute pairs)
//   - 16 standard ANSI colors mapped to 32-bit RGB
//   - Cursor position tracking with show/hide support
//   - Tab stops every 8 columns
//   - Automatic line wrapping and scrolling

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ── Callback function types (provided by vesa_fb) ──

type FbPutcharFn = unsafe extern "C" fn(ch: u8, fg: u32, bg: u32);
type FbScrollFn = unsafe extern "C" fn(lines: u32);
type FbSetCursorFn = unsafe extern "C" fn(col: u32, row: u32);
type FbClearFn = unsafe extern "C" fn(color: u32);

// ── Console size (C-compatible) ──

#[repr(C)]
pub struct ConsoleSize {
    pub cols: u32,
    pub rows: u32,
}

// ── Character + attribute pair ──
//
// Attribute byte layout:
//   bits 3:0 = foreground color (0-15)
//   bits 6:4 = background color (0-7)
//   bit    7 = bold flag

#[derive(Copy, Clone)]
struct Cell {
    ch: u8,
    attr: u8,
}

impl Cell {
    const BLANK: Self = Self { ch: b' ', attr: 0x07 }; // light gray on black
}

fn make_attr(fg: u8, bg: u8, bold: bool) -> u8 {
    (fg & 0x0F) | ((bg & 0x07) << 4) | (if bold { 0x80 } else { 0 })
}

fn attr_fg(attr: u8) -> u8 {
    attr & 0x0F
}

fn attr_bg(attr: u8) -> u8 {
    (attr >> 4) & 0x07
}

fn attr_bold(attr: u8) -> bool {
    attr & 0x80 != 0
}

// ── 16 standard ANSI colors (32-bit 0x00RRGGBB) ──

static ANSI_COLORS: [u32; 16] = [
    0x00000000, // 0  black
    0x00AA0000, // 1  red
    0x0000AA00, // 2  green
    0x00AA5500, // 3  yellow / brown
    0x000000AA, // 4  blue
    0x00AA00AA, // 5  magenta
    0x0000AAAA, // 6  cyan
    0x00AAAAAA, // 7  white (light gray)
    0x00555555, // 8  bright black (dark gray)
    0x00FF5555, // 9  bright red
    0x0055FF55, // 10 bright green
    0x00FFFF55, // 11 bright yellow
    0x005555FF, // 12 bright blue
    0x00FF55FF, // 13 bright magenta
    0x0055FFFF, // 14 bright cyan
    0x00FFFFFF, // 15 bright white
];

// ── Scrollback buffer ──

const MAX_SCROLLBACK_LINES: usize = 1000;
const MAX_COLS: usize = 256;

// Each scrollback line stores up to MAX_COLS cells.
type ScrollLine = [Cell; MAX_COLS];

const BLANK_LINE: ScrollLine = [Cell::BLANK; MAX_COLS];

struct ScrollbackBuffer {
    lines: [ScrollLine; MAX_SCROLLBACK_LINES],
    head: usize,  // index of next line to write
    count: usize,  // total lines stored
}

impl ScrollbackBuffer {
    const fn new() -> Self {
        Self {
            lines: [BLANK_LINE; MAX_SCROLLBACK_LINES],
            head: 0,
            count: 0,
        }
    }

    fn push_line(&mut self, line: &ScrollLine) {
        self.lines[self.head] = *line;
        self.head = (self.head + 1) % MAX_SCROLLBACK_LINES;
        if self.count < MAX_SCROLLBACK_LINES {
            self.count += 1;
        }
    }
}

// ── ANSI escape parser state machine ──

#[derive(Copy, Clone, PartialEq)]
enum ParseState {
    Normal,
    Escape,      // saw ESC
    Csi,         // saw ESC[
    CsiParam,    // collecting CSI numeric parameters
    CsiQuestion, // saw ESC[?
}

const MAX_CSI_PARAMS: usize = 8;

// ── Console state ──

struct ConsoleState {
    // Screen dimensions (in character cells)
    cols: u32,
    rows: u32,

    // Cursor position
    cursor_col: u32,
    cursor_row: u32,
    cursor_visible: bool,

    // Current text attributes
    fg_color: u8,
    bg_color: u8,
    bold: bool,

    // Default attributes (for SGR reset)
    default_fg: u8,
    default_bg: u8,

    // Screen buffer (visible area)
    screen: [ScrollLine; 128], // up to 128 rows on screen

    // Scrollback
    scrollback: ScrollbackBuffer,

    // ANSI escape parser
    parse_state: ParseState,
    csi_params: [u32; MAX_CSI_PARAMS],
    csi_param_count: usize,
    csi_private: u8, // '?' marker

    // Framebuffer callbacks
    fb_putchar: Option<FbPutcharFn>,
    fb_scroll: Option<FbScrollFn>,
    fb_set_cursor: Option<FbSetCursorFn>,
    fb_clear: Option<FbClearFn>,

    initialized: bool,
}

impl ConsoleState {
    const fn new() -> Self {
        Self {
            cols: 0,
            rows: 0,
            cursor_col: 0,
            cursor_row: 0,
            cursor_visible: true,
            fg_color: 7,  // light gray
            bg_color: 0,  // black
            bold: false,
            default_fg: 7,
            default_bg: 0,
            screen: [BLANK_LINE; 128],
            scrollback: ScrollbackBuffer::new(),
            parse_state: ParseState::Normal,
            csi_params: [0; MAX_CSI_PARAMS],
            csi_param_count: 0,
            csi_private: 0,
            fb_putchar: None,
            fb_scroll: None,
            fb_set_cursor: None,
            fb_clear: None,
            initialized: false,
        }
    }

    fn current_attr(&self) -> u8 {
        make_attr(self.fg_color, self.bg_color, self.bold)
    }

    fn fg_rgb(&self) -> u32 {
        ANSI_COLORS[self.fg_color as usize & 0x0F]
    }

    fn bg_rgb(&self) -> u32 {
        ANSI_COLORS[self.bg_color as usize & 0x07]
    }

    // ── Cursor helpers ──

    fn update_hw_cursor(&self) {
        if let Some(set_cursor) = self.fb_set_cursor {
            if self.cursor_visible {
                unsafe { set_cursor(self.cursor_col, self.cursor_row); }
            }
        }
    }

    fn clamp_cursor(&mut self) {
        if self.cursor_col >= self.cols {
            self.cursor_col = self.cols.saturating_sub(1);
        }
        if self.cursor_row >= self.rows {
            self.cursor_row = self.rows.saturating_sub(1);
        }
    }

    // ── Scroll the screen up by one line ──

    fn scroll_up(&mut self, count: u32) {
        let count = count.min(self.rows);
        if count == 0 {
            return;
        }

        let rows = self.rows as usize;
        let cols = self.cols as usize;

        // Save lines going off-screen into scrollback
        for i in 0..count as usize {
            if i < rows {
                self.scrollback.push_line(&self.screen[i]);
            }
        }

        // Shift screen buffer up
        let shift = count as usize;
        for i in 0..rows.saturating_sub(shift) {
            self.screen[i] = self.screen[i + shift];
        }

        // Clear newly exposed lines at bottom
        for i in rows.saturating_sub(shift)..rows {
            for c in 0..cols {
                self.screen[i][c] = Cell { ch: b' ', attr: self.current_attr() };
            }
        }

        // Tell framebuffer to scroll
        if let Some(fb_scroll) = self.fb_scroll {
            unsafe { fb_scroll(count); }
        }
    }

    // ── Put a single visible character at cursor position ──

    fn put_visible_char(&mut self, ch: u8) {
        if !self.initialized {
            return;
        }

        // Handle line wrap
        if self.cursor_col >= self.cols {
            self.cursor_col = 0;
            self.cursor_row += 1;
        }

        // Handle scroll
        if self.cursor_row >= self.rows {
            self.scroll_up(1);
            self.cursor_row = self.rows - 1;
        }

        let row = self.cursor_row as usize;
        let col = self.cursor_col as usize;
        let attr = self.current_attr();

        // Store in screen buffer
        self.screen[row][col] = Cell { ch, attr };

        // Draw via framebuffer callback
        if let Some(fb_set_cursor) = self.fb_set_cursor {
            unsafe { fb_set_cursor(self.cursor_col, self.cursor_row); }
        }
        if let Some(fb_putchar) = self.fb_putchar {
            unsafe { fb_putchar(ch, self.fg_rgb(), self.bg_rgb()); }
        }

        self.cursor_col += 1;
    }

    // ── Process a single byte through the ANSI parser ──

    fn process_byte(&mut self, byte: u8) {
        match self.parse_state {
            ParseState::Normal => self.process_normal(byte),
            ParseState::Escape => self.process_escape(byte),
            ParseState::Csi | ParseState::CsiParam | ParseState::CsiQuestion => {
                self.process_csi(byte);
            }
        }
    }

    fn process_normal(&mut self, byte: u8) {
        match byte {
            0x1B => {
                // ESC - start escape sequence
                self.parse_state = ParseState::Escape;
            }
            b'\n' => {
                // Line feed
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= self.rows {
                    self.scroll_up(1);
                    self.cursor_row = self.rows - 1;
                }
                self.update_hw_cursor();
            }
            b'\r' => {
                // Carriage return
                self.cursor_col = 0;
                self.update_hw_cursor();
            }
            b'\t' => {
                // Tab - advance to next 8-column boundary
                let next_tab = (self.cursor_col + 8) & !7;
                let target = next_tab.min(self.cols);
                while self.cursor_col < target {
                    self.put_visible_char(b' ');
                }
                self.update_hw_cursor();
            }
            0x08 => {
                // Backspace
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.update_hw_cursor();
                }
            }
            0x07 => {
                // BEL - ignore (no speaker)
            }
            0x00..=0x06 | 0x0E..=0x1A | 0x1C..=0x1F => {
                // Other control characters - ignore
            }
            _ => {
                // Printable character
                self.put_visible_char(byte);
                self.update_hw_cursor();
            }
        }
    }

    fn process_escape(&mut self, byte: u8) {
        match byte {
            b'[' => {
                // CSI introducer
                self.parse_state = ParseState::Csi;
                self.csi_params = [0; MAX_CSI_PARAMS];
                self.csi_param_count = 0;
                self.csi_private = 0;
            }
            b'c' => {
                // RIS - reset to initial state
                self.reset_attrs();
                self.cursor_col = 0;
                self.cursor_row = 0;
                self.clear_screen(2);
                self.parse_state = ParseState::Normal;
            }
            _ => {
                // Unknown escape - drop and return to normal
                self.parse_state = ParseState::Normal;
            }
        }
    }

    fn process_csi(&mut self, byte: u8) {
        match byte {
            b'?' => {
                // Private mode marker
                self.csi_private = b'?';
                self.parse_state = ParseState::CsiQuestion;
            }
            b'0'..=b'9' => {
                // Numeric parameter digit
                self.parse_state = ParseState::CsiParam;
                if self.csi_param_count == 0 {
                    self.csi_param_count = 1;
                }
                let idx = self.csi_param_count - 1;
                if idx < MAX_CSI_PARAMS {
                    self.csi_params[idx] = self.csi_params[idx]
                        .saturating_mul(10)
                        .saturating_add((byte - b'0') as u32);
                }
            }
            b';' => {
                // Parameter separator
                if self.csi_param_count < MAX_CSI_PARAMS {
                    self.csi_param_count += 1;
                }
                self.parse_state = ParseState::CsiParam;
            }
            // Final bytes - execute the CSI command
            b'A' => { self.csi_cursor_up(); self.parse_state = ParseState::Normal; }
            b'B' => { self.csi_cursor_down(); self.parse_state = ParseState::Normal; }
            b'C' => { self.csi_cursor_forward(); self.parse_state = ParseState::Normal; }
            b'D' => { self.csi_cursor_back(); self.parse_state = ParseState::Normal; }
            b'H' | b'f' => { self.csi_cursor_position(); self.parse_state = ParseState::Normal; }
            b'J' => { self.csi_clear_screen(); self.parse_state = ParseState::Normal; }
            b'K' => { self.csi_clear_line(); self.parse_state = ParseState::Normal; }
            b'm' => { self.csi_sgr(); self.parse_state = ParseState::Normal; }
            b'h' => { self.csi_set_mode(); self.parse_state = ParseState::Normal; }
            b'l' => { self.csi_reset_mode(); self.parse_state = ParseState::Normal; }
            _ => {
                // Unknown CSI command - drop
                self.parse_state = ParseState::Normal;
            }
        }
    }

    // ── CSI command implementations ──

    fn csi_param(&self, index: usize, default: u32) -> u32 {
        if index < self.csi_param_count {
            let v = self.csi_params[index];
            if v == 0 { default } else { v }
        } else {
            default
        }
    }

    fn csi_cursor_up(&mut self) {
        let n = self.csi_param(0, 1);
        self.cursor_row = self.cursor_row.saturating_sub(n);
        self.update_hw_cursor();
    }

    fn csi_cursor_down(&mut self) {
        let n = self.csi_param(0, 1);
        self.cursor_row = (self.cursor_row + n).min(self.rows.saturating_sub(1));
        self.update_hw_cursor();
    }

    fn csi_cursor_forward(&mut self) {
        let n = self.csi_param(0, 1);
        self.cursor_col = (self.cursor_col + n).min(self.cols.saturating_sub(1));
        self.update_hw_cursor();
    }

    fn csi_cursor_back(&mut self) {
        let n = self.csi_param(0, 1);
        self.cursor_col = self.cursor_col.saturating_sub(n);
        self.update_hw_cursor();
    }

    fn csi_cursor_position(&mut self) {
        // ESC[n;mH - 1-based row;col
        let row = self.csi_param(0, 1).saturating_sub(1);
        let col = self.csi_param(1, 1).saturating_sub(1);
        self.cursor_row = row.min(self.rows.saturating_sub(1));
        self.cursor_col = col.min(self.cols.saturating_sub(1));
        self.update_hw_cursor();
    }

    fn csi_clear_screen(&mut self) {
        let mode = if self.csi_param_count > 0 { self.csi_params[0] } else { 0 };
        self.clear_screen(mode);
    }

    fn clear_screen(&mut self, mode: u32) {
        let rows = self.rows as usize;
        let cols = self.cols as usize;
        let attr = self.current_attr();
        let blank = Cell { ch: b' ', attr };

        match mode {
            0 => {
                // Clear from cursor to end of screen
                let row = self.cursor_row as usize;
                let col = self.cursor_col as usize;
                // Clear rest of current line
                for c in col..cols {
                    self.screen[row][c] = blank;
                }
                // Clear all lines below
                for r in (row + 1)..rows {
                    for c in 0..cols {
                        self.screen[r][c] = blank;
                    }
                }
            }
            1 => {
                // Clear from start of screen to cursor
                let row = self.cursor_row as usize;
                let col = self.cursor_col as usize;
                // Clear all lines above
                for r in 0..row {
                    for c in 0..cols {
                        self.screen[r][c] = blank;
                    }
                }
                // Clear current line up to and including cursor
                for c in 0..=col.min(cols.saturating_sub(1)) {
                    self.screen[row][c] = blank;
                }
            }
            2 => {
                // Clear entire screen
                for r in 0..rows {
                    for c in 0..cols {
                        self.screen[r][c] = blank;
                    }
                }
                if let Some(fb_clear) = self.fb_clear {
                    unsafe { fb_clear(self.bg_rgb()); }
                }
            }
            _ => {}
        }

        // For mode 0 and 1, redraw affected area via putchar callbacks
        if mode == 0 || mode == 1 {
            self.redraw_screen();
        }
    }

    fn csi_clear_line(&mut self) {
        let mode = if self.csi_param_count > 0 { self.csi_params[0] } else { 0 };
        self.clear_line(mode);
    }

    fn clear_line(&mut self, mode: u32) {
        let row = self.cursor_row as usize;
        let col = self.cursor_col as usize;
        let cols = self.cols as usize;
        let attr = self.current_attr();
        let blank = Cell { ch: b' ', attr };

        match mode {
            0 => {
                // Clear from cursor to end of line
                for c in col..cols {
                    self.screen[row][c] = blank;
                }
            }
            1 => {
                // Clear from start of line to cursor
                for c in 0..=col.min(cols.saturating_sub(1)) {
                    self.screen[row][c] = blank;
                }
            }
            2 => {
                // Clear entire line
                for c in 0..cols {
                    self.screen[row][c] = blank;
                }
            }
            _ => {}
        }

        // Redraw the affected line
        self.redraw_line(row);
    }

    fn csi_sgr(&mut self) {
        // If no parameters, treat as reset (SGR 0)
        if self.csi_param_count == 0 {
            self.reset_attrs();
            return;
        }

        for i in 0..self.csi_param_count {
            let code = self.csi_params[i];
            match code {
                0 => self.reset_attrs(),
                1 => {
                    self.bold = true;
                    // Bold often brightens foreground
                    if self.fg_color < 8 {
                        self.fg_color += 8;
                    }
                }
                22 => {
                    self.bold = false;
                    if self.fg_color >= 8 {
                        self.fg_color -= 8;
                    }
                }
                // Standard foreground colors (30-37)
                30..=37 => {
                    self.fg_color = (code - 30) as u8;
                    if self.bold {
                        self.fg_color += 8;
                    }
                }
                // Default foreground
                39 => {
                    self.fg_color = self.default_fg;
                    if self.bold {
                        self.fg_color |= 8;
                    }
                }
                // Standard background colors (40-47)
                40..=47 => {
                    self.bg_color = (code - 40) as u8;
                }
                // Default background
                49 => {
                    self.bg_color = self.default_bg;
                }
                // Bright foreground colors (90-97)
                90..=97 => {
                    self.fg_color = (code - 90 + 8) as u8;
                }
                // Bright background colors (100-107)
                100..=107 => {
                    self.bg_color = (code - 100 + 8) as u8;
                }
                _ => {
                    // Unsupported SGR code - ignore
                }
            }
        }
    }

    fn csi_set_mode(&mut self) {
        if self.csi_private == b'?' {
            let param = if self.csi_param_count > 0 { self.csi_params[0] } else { 0 };
            match param {
                25 => {
                    // Show cursor
                    self.cursor_visible = true;
                    self.update_hw_cursor();
                }
                _ => {}
            }
        }
    }

    fn csi_reset_mode(&mut self) {
        if self.csi_private == b'?' {
            let param = if self.csi_param_count > 0 { self.csi_params[0] } else { 0 };
            match param {
                25 => {
                    // Hide cursor
                    self.cursor_visible = false;
                }
                _ => {}
            }
        }
    }

    fn reset_attrs(&mut self) {
        self.fg_color = self.default_fg;
        self.bg_color = self.default_bg;
        self.bold = false;
    }

    // ── Redraw helpers ──

    fn redraw_line(&self, row: usize) {
        if row >= self.rows as usize {
            return;
        }
        let cols = self.cols as usize;
        // Position cursor at start of line, draw each cell
        if let Some(fb_set_cursor) = self.fb_set_cursor {
            unsafe { fb_set_cursor(0, row as u32); }
        }
        if let Some(fb_putchar) = self.fb_putchar {
            for c in 0..cols {
                let cell = self.screen[row][c];
                let fg = ANSI_COLORS[attr_fg(cell.attr) as usize & 0x0F];
                let bg = ANSI_COLORS[attr_bg(cell.attr) as usize & 0x07];
                unsafe { fb_putchar(cell.ch, fg, bg); }
            }
        }
        // Restore hardware cursor
        self.update_hw_cursor();
    }

    fn redraw_screen(&self) {
        let rows = self.rows as usize;
        for r in 0..rows {
            self.redraw_line(r);
        }
    }
}

static STATE: StaticCell<ConsoleState> = StaticCell::new(ConsoleState::new());

// ── Exported C API ──

/// Initialize the framebuffer console.
///
/// `cols`, `rows` - screen dimensions in character cells.
/// The four function pointers are callbacks into the framebuffer driver.
/// Returns 0 on success, -1 on invalid parameters.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_init(
    cols: u32,
    rows: u32,
    putchar: FbPutcharFn,
    scroll: FbScrollFn,
    set_cursor: FbSetCursorFn,
    clear: FbClearFn,
) -> i32 {
    if cols == 0 || rows == 0 || cols > MAX_COLS as u32 || rows > 128 {
        return -1;
    }

    let s = unsafe { &mut *STATE.get() };

    s.cols = cols;
    s.rows = rows;
    s.cursor_col = 0;
    s.cursor_row = 0;
    s.cursor_visible = true;
    s.fg_color = 7;
    s.bg_color = 0;
    s.bold = false;
    s.default_fg = 7;
    s.default_bg = 0;

    // Clear screen buffer
    let blank = Cell { ch: b' ', attr: make_attr(7, 0, false) };
    for r in 0..rows as usize {
        for c in 0..cols as usize {
            s.screen[r][c] = blank;
        }
    }

    s.scrollback = ScrollbackBuffer::new();

    s.parse_state = ParseState::Normal;
    s.csi_params = [0; MAX_CSI_PARAMS];
    s.csi_param_count = 0;
    s.csi_private = 0;

    s.fb_putchar = Some(putchar);
    s.fb_scroll = Some(scroll);
    s.fb_set_cursor = Some(set_cursor);
    s.fb_clear = Some(clear);

    s.initialized = true;

    // Clear the physical screen
    unsafe { clear(ANSI_COLORS[0]); }
    unsafe { set_cursor(0, 0); }

    unsafe {
        fut_printf(b"fb_console: initialized %ux%u text console\n\0".as_ptr(), cols, rows);
    }

    0
}

/// Write a byte string to the console with ANSI escape parsing.
/// Returns the number of bytes consumed, or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_write(data: *const u8, len: u32) -> i32 {
    if data.is_null() {
        return -1;
    }

    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return -1;
    }

    for i in 0..len as usize {
        let byte = unsafe { *data.add(i) };
        s.process_byte(byte);
    }

    len as i32
}

/// Write a single character to the console.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_putc(ch: u8) {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return;
    }
    s.process_byte(ch);
}

/// Clear the entire console screen.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_clear() {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return;
    }
    s.clear_screen(2);
    s.cursor_col = 0;
    s.cursor_row = 0;
    s.update_hw_cursor();
}

/// Set the current foreground and background colors (ANSI color indices 0-15).
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_set_color(fg: u8, bg: u8) {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return;
    }
    s.fg_color = fg & 0x0F;
    s.bg_color = bg & 0x07;
}

/// Get the current cursor position.
/// Writes column and row to the provided pointers.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_get_cursor(col: *mut u32, row: *mut u32) {
    let s = unsafe { &*STATE.get() };
    if !col.is_null() {
        unsafe { *col = s.cursor_col; }
    }
    if !row.is_null() {
        unsafe { *row = s.cursor_row; }
    }
}

/// Set the cursor position (0-based column and row).
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_set_cursor_pos(col: u32, row: u32) {
    let s = unsafe { &mut *STATE.get() };
    if !s.initialized {
        return;
    }
    s.cursor_col = col.min(s.cols.saturating_sub(1));
    s.cursor_row = row.min(s.rows.saturating_sub(1));
    s.update_hw_cursor();
}

/// Get the console size in character cells.
#[unsafe(no_mangle)]
pub extern "C" fn fb_console_get_size(size: *mut ConsoleSize) {
    if size.is_null() {
        return;
    }
    let s = unsafe { &*STATE.get() };
    unsafe {
        (*size).cols = s.cols;
        (*size).rows = s.rows;
    }
}

/* futura_ui.h - FuturaUI Widget Toolkit
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Modern widget toolkit for Futura OS with clean futuristic design.
 * Built on top of FuturaWay compositor using FIPC.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <user/futura_way.h>

/* ============================================================
 *   FuturaUI Design Constants
 * ============================================================ */

/* Color Palette */
#define FUI_COLOR_PRIMARY       0xFF2962FF  /* Futura Blue */
#define FUI_COLOR_BG_DARK       0xFF121212  /* Dark background */
#define FUI_COLOR_BG_SURFACE    0xFF1E1E1E  /* Surface (gray 900) */
#define FUI_COLOR_BG_ELEVATED   0xFF2D2D2D  /* Elevated surface (gray 800) */
#define FUI_COLOR_TEXT_PRIMARY  0xFFF5F5F5  /* Primary text */
#define FUI_COLOR_TEXT_SECONDARY 0xFFB0B0B0 /* Secondary text */
#define FUI_COLOR_BORDER        0xFF3D3D3D  /* Borders (gray 700) */
#define FUI_COLOR_SUCCESS       0xFF00C853  /* Success green */
#define FUI_COLOR_WARNING       0xFFFF6D00  /* Warning orange */
#define FUI_COLOR_ERROR         0xFFD50000  /* Error red */

/* Typography */
#define FUI_FONT_DISPLAY_SIZE   32
#define FUI_FONT_H1_SIZE        24
#define FUI_FONT_H2_SIZE        20
#define FUI_FONT_H3_SIZE        18
#define FUI_FONT_BODY_SIZE      14
#define FUI_FONT_CAPTION_SIZE   12

/* Spacing (8px grid) */
#define FUI_SPACING_NONE        0
#define FUI_SPACING_XS          4
#define FUI_SPACING_SM          8
#define FUI_SPACING_MD          16
#define FUI_SPACING_LG          24
#define FUI_SPACING_XL          32

/* Border Radius */
#define FUI_RADIUS_NONE         0
#define FUI_RADIUS_SM           4
#define FUI_RADIUS_MD           8
#define FUI_RADIUS_LG           12
#define FUI_RADIUS_XL           16
#define FUI_RADIUS_ROUND        9999

/* Window Metrics */
#define FUI_TITLEBAR_HEIGHT     40
#define FUI_MIN_WINDOW_WIDTH    400
#define FUI_MIN_WINDOW_HEIGHT   300

/* ============================================================
 *   Basic Types
 * ============================================================ */

struct fui_rect {
    int32_t x, y;
    int32_t width, height;
};

struct fui_color {
    uint8_t r, g, b, a;
};

struct fui_point {
    int32_t x, y;
};

/* ============================================================
 *   Rendering Context
 * ============================================================ */

struct fui_context {
    uint64_t surface_id;
    void *framebuffer;          /* Shared buffer from FuturaWay */
    uint32_t width, height;
    enum fway_surface_format format;

    /* Drawing state */
    struct fui_color fg_color;
    struct fui_color bg_color;
    int32_t stroke_width;
    struct fui_rect clip_rect;
};

/* ============================================================
 *   Widget System
 * ============================================================ */

/* Forward declarations */
struct fui_widget;
struct fui_window;
struct fui_event;

/* Widget flags */
#define FUI_WIDGET_VISIBLE      (1 << 0)
#define FUI_WIDGET_ENABLED      (1 << 1)
#define FUI_WIDGET_FOCUSED      (1 << 2)
#define FUI_WIDGET_HOVERED      (1 << 3)
#define FUI_WIDGET_PRESSED      (1 << 4)

/* Widget type enum */
enum fui_widget_type {
    FUI_WIDGET_CUSTOM = 0,
    FUI_WIDGET_WINDOW,
    FUI_WIDGET_BUTTON,
    FUI_WIDGET_LABEL,
    FUI_WIDGET_TEXTINPUT,
    FUI_WIDGET_PANEL,
    FUI_WIDGET_SCROLL,
    FUI_WIDGET_LIST,
};

/* Event types */
enum fui_event_type {
    FUI_EVENT_NONE = 0,
    FUI_EVENT_MOUSE_ENTER,
    FUI_EVENT_MOUSE_LEAVE,
    FUI_EVENT_MOUSE_MOVE,
    FUI_EVENT_MOUSE_DOWN,
    FUI_EVENT_MOUSE_UP,
    FUI_EVENT_MOUSE_CLICK,
    FUI_EVENT_KEY_DOWN,
    FUI_EVENT_KEY_UP,
    FUI_EVENT_FOCUS_IN,
    FUI_EVENT_FOCUS_OUT,
    FUI_EVENT_RESIZE,
    FUI_EVENT_CLOSE,
};

/* Event structure */
struct fui_event {
    enum fui_event_type type;
    struct fui_widget *target;
    uint64_t timestamp;

    union {
        struct {
            int32_t x, y;
            uint32_t buttons;
        } mouse;

        struct {
            uint32_t keycode;
            uint32_t modifiers;
        } key;

        struct {
            int32_t width, height;
        } resize;
    } data;
};

/* Widget base structure */
struct fui_widget {
    enum fui_widget_type type;
    uint64_t id;
    struct fui_rect bounds;
    uint32_t flags;

    /* Hierarchy */
    struct fui_widget *parent;
    struct fui_widget **children;
    size_t num_children;

    /* Styling */
    struct fui_color bg_color;
    struct fui_color fg_color;
    int32_t border_radius;
    int32_t padding;

    /* Callbacks */
    void (*on_render)(struct fui_widget *, struct fui_context *);
    void (*on_event)(struct fui_widget *, struct fui_event *);
    void (*on_destroy)(struct fui_widget *);

    /* User data */
    void *user_data;
};

/* ============================================================
 *   Window Widget
 * ============================================================ */

struct fui_window {
    struct fui_widget base;

    /* FuturaWay integration */
    struct fut_fipc_channel *channel;
    uint64_t surface_id;
    struct fut_fipc_region *buffer_region;

    /* Window properties */
    char *title;
    bool decorated;             /* Has title bar */
    bool resizable;
    bool modal;

    /* Rendering */
    struct fui_context *context;
};

/* ============================================================
 *   Button Widget
 * ============================================================ */

struct fui_button {
    struct fui_widget base;

    char *label;
    void (*on_click)(struct fui_button *);
};

/* ============================================================
 *   Label Widget
 * ============================================================ */

struct fui_label {
    struct fui_widget base;

    char *text;
    uint32_t font_size;
    uint32_t text_color;
    enum {
        FUI_ALIGN_LEFT,
        FUI_ALIGN_CENTER,
        FUI_ALIGN_RIGHT
    } align;
};

/* ============================================================
 *   Text Input Widget
 * ============================================================ */

struct fui_textinput {
    struct fui_widget base;

    char *buffer;
    size_t buffer_size;
    size_t cursor_pos;
    bool password_mode;         /* Show asterisks */
    char *placeholder;
};

/* ============================================================
 *   Panel Widget (Container)
 * ============================================================ */

enum fui_layout {
    FUI_LAYOUT_NONE,
    FUI_LAYOUT_VERTICAL,
    FUI_LAYOUT_HORIZONTAL,
    FUI_LAYOUT_GRID,
};

struct fui_panel {
    struct fui_widget base;

    enum fui_layout layout;
    int32_t spacing;            /* Space between children */
};

/* ============================================================
 *   FuturaUI API
 * ============================================================ */

/**
 * Initialize FuturaUI library.
 *
 * @return 0 on success, negative on error
 */
int fui_init(void);

/**
 * Shutdown FuturaUI library.
 */
void fui_shutdown(void);

/**
 * Run main event loop.
 * Blocks until all windows are closed.
 */
void fui_run(void);

/**
 * Process events without blocking.
 *
 * @return Number of events processed
 */
int fui_poll_events(void);

/* ============================================================
 *   Window API
 * ============================================================ */

/**
 * Create a new window.
 *
 * @param title Window title
 * @param width Window width
 * @param height Window height
 * @return Window instance, or NULL on error
 */
struct fui_window *fui_window_create(const char *title, uint32_t width, uint32_t height);

/**
 * Destroy a window.
 *
 * @param window Window to destroy
 */
void fui_window_destroy(struct fui_window *window);

/**
 * Show a window.
 *
 * @param window Window to show
 */
void fui_window_show(struct fui_window *window);

/**
 * Hide a window.
 *
 * @param window Window to hide
 */
void fui_window_hide(struct fui_window *window);

/**
 * Set window title.
 *
 * @param window Window instance
 * @param title New title string
 */
void fui_window_set_title(struct fui_window *window, const char *title);

/**
 * Add child widget to window.
 *
 * @param window Parent window
 * @param child Child widget
 */
void fui_window_add_child(struct fui_window *window, struct fui_widget *child);

/* ============================================================
 *   Widget Creation API
 * ============================================================ */

/**
 * Create a button widget.
 *
 * @param label Button text
 * @param on_click Click callback
 * @return Button instance, or NULL on error
 */
struct fui_button *fui_button_create(const char *label, void (*on_click)(struct fui_button *));

/**
 * Create a label widget.
 *
 * @param text Label text
 * @return Label instance, or NULL on error
 */
struct fui_label *fui_label_create(const char *text);

/**
 * Create a text input widget.
 *
 * @param buffer_size Maximum text length
 * @return Text input instance, or NULL on error
 */
struct fui_textinput *fui_textinput_create(size_t buffer_size);

/**
 * Create a panel widget.
 *
 * @param layout Panel layout mode
 * @return Panel instance, or NULL on error
 */
struct fui_panel *fui_panel_create(enum fui_layout layout);

/* ============================================================
 *   Widget Manipulation API
 * ============================================================ */

/**
 * Set widget bounds.
 *
 * @param widget Widget instance
 * @param x, y Position
 * @param width, height Size
 */
void fui_widget_set_bounds(struct fui_widget *widget, int32_t x, int32_t y,
                           int32_t width, int32_t height);

/**
 * Set widget visibility.
 *
 * @param widget Widget instance
 * @param visible Visibility flag
 */
void fui_widget_set_visible(struct fui_widget *widget, bool visible);

/**
 * Set widget enabled state.
 *
 * @param widget Widget instance
 * @param enabled Enabled flag
 */
void fui_widget_set_enabled(struct fui_widget *widget, bool enabled);

/**
 * Add child widget.
 *
 * @param parent Parent widget
 * @param child Child widget
 */
void fui_widget_add_child(struct fui_widget *parent, struct fui_widget *child);

/**
 * Remove child widget.
 *
 * @param parent Parent widget
 * @param child Child widget
 */
void fui_widget_remove_child(struct fui_widget *parent, struct fui_widget *child);

/**
 * Destroy widget and all children.
 *
 * @param widget Widget to destroy
 */
void fui_widget_destroy(struct fui_widget *widget);

/* ============================================================
 *   Rendering API
 * ============================================================ */

/**
 * Create rendering context from window.
 *
 * @param window Window instance
 * @return Rendering context, or NULL on error
 */
struct fui_context *fui_context_create(struct fui_window *window);

/**
 * Destroy rendering context.
 *
 * @param ctx Context to destroy
 */
void fui_context_destroy(struct fui_context *ctx);

/**
 * Clear entire surface with color.
 *
 * @param ctx Rendering context
 * @param color Color to fill
 */
void fui_clear(struct fui_context *ctx, struct fui_color color);

/**
 * Draw filled rectangle.
 *
 * @param ctx Rendering context
 * @param rect Rectangle bounds
 * @param color Fill color
 * @param radius Border radius (0 for sharp corners)
 */
void fui_draw_rect(struct fui_context *ctx, struct fui_rect rect,
                   struct fui_color color, int32_t radius);

/**
 * Draw text.
 *
 * @param ctx Rendering context
 * @param text Text string
 * @param x, y Position
 * @param font_size Font size
 * @param color Text color
 */
void fui_draw_text(struct fui_context *ctx, const char *text,
                   int32_t x, int32_t y, uint32_t font_size,
                   struct fui_color color);

/**
 * Draw line.
 *
 * @param ctx Rendering context
 * @param x1, y1 Start point
 * @param x2, y2 End point
 * @param width Line width
 * @param color Line color
 */
void fui_draw_line(struct fui_context *ctx, int32_t x1, int32_t y1,
                   int32_t x2, int32_t y2, int32_t width,
                   struct fui_color color);

/* ============================================================
 *   Color Utilities
 * ============================================================ */

/**
 * Create RGBA color from components.
 *
 * @param r, g, b, a Color components (0-255)
 * @return Color structure
 */
static inline struct fui_color fui_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    return (struct fui_color){ .r = r, .g = g, .b = b, .a = a };
}

/**
 * Create RGB color (fully opaque).
 *
 * @param r, g, b Color components (0-255)
 * @return Color structure
 */
static inline struct fui_color fui_rgb(uint8_t r, uint8_t g, uint8_t b) {
    return fui_rgba(r, g, b, 255);
}

/**
 * Convert 32-bit hex color to struct.
 *
 * @param hex Color in 0xAARRGGBB format
 * @return Color structure
 */
static inline struct fui_color fui_color_from_hex(uint32_t hex) {
    return (struct fui_color){
        .a = (hex >> 24) & 0xFF,
        .r = (hex >> 16) & 0xFF,
        .g = (hex >> 8) & 0xFF,
        .b = hex & 0xFF
    };
}

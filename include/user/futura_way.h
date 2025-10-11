/* futura_way.h - FuturaWay Compositor Protocol
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Wayland-inspired compositor protocol using FIPC channels.
 * This is the public interface for applications to communicate
 * with the futurawayd display server.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <kernel/fut_fipc.h>

/* ============================================================
 *   FuturaWay Message Types
 * ============================================================ */

/* Message type range: 0x2000 - 0x2FFF */
#define FWAY_MSG_CREATE_SURFACE    0x2001
#define FWAY_MSG_DESTROY_SURFACE   0x2002
#define FWAY_MSG_ATTACH_BUFFER     0x2003
#define FWAY_MSG_DETACH_BUFFER     0x2004
#define FWAY_MSG_COMMIT            0x2005
#define FWAY_MSG_DAMAGE            0x2006
#define FWAY_MSG_SET_TITLE         0x2007
#define FWAY_MSG_SET_SIZE          0x2008
#define FWAY_MSG_SET_POSITION      0x2009
#define FWAY_MSG_SHOW              0x200A
#define FWAY_MSG_HIDE              0x200B
#define FWAY_MSG_FOCUS             0x200C

/* Server → Client messages */
#define FWAY_MSG_CONFIGURE         0x2101
#define FWAY_MSG_FRAME_DONE        0x2102
#define FWAY_MSG_INPUT_EVENT       0x2103
#define FWAY_MSG_CLOSE_REQUEST     0x2104

/* ============================================================
 *   Surface Formats
 * ============================================================ */

enum fway_surface_format {
    FWAY_FORMAT_INVALID = 0,
    FWAY_FORMAT_RGBA8888,       /* 32-bit RGBA */
    FWAY_FORMAT_RGB888,         /* 24-bit RGB */
    FWAY_FORMAT_RGB565,         /* 16-bit RGB */
    FWAY_FORMAT_BGRA8888,       /* 32-bit BGRA */
};

/* ============================================================
 *   Surface Flags
 * ============================================================ */

#define FWAY_SURFACE_VISIBLE         (1 << 0)
#define FWAY_SURFACE_FULLSCREEN      (1 << 1)
#define FWAY_SURFACE_TRANSPARENT     (1 << 2)
#define FWAY_SURFACE_RESIZABLE       (1 << 3)
#define FWAY_SURFACE_DECORATED       (1 << 4)  /* Has title bar */
#define FWAY_SURFACE_MODAL           (1 << 5)
#define FWAY_SURFACE_ALWAYS_ON_TOP   (1 << 6)

/* ============================================================
 *   Input Event Types
 * ============================================================ */

enum fway_input_type {
    FWAY_INPUT_KEY = 1,
    FWAY_INPUT_MOUSE_BUTTON,
    FWAY_INPUT_MOUSE_MOTION,
    FWAY_INPUT_MOUSE_WHEEL,
    FWAY_INPUT_TOUCH,
};

enum fway_key_state {
    FWAY_KEY_RELEASED = 0,
    FWAY_KEY_PRESSED = 1,
};

enum fway_mouse_button {
    FWAY_MOUSE_LEFT = 1,
    FWAY_MOUSE_MIDDLE = 2,
    FWAY_MOUSE_RIGHT = 3,
};

/* ============================================================
 *   Protocol Messages
 * ============================================================ */

/**
 * Create surface request
 */
struct fway_create_surface_req {
    uint32_t width;
    uint32_t height;
    enum fway_surface_format format;
    uint32_t flags;
};

/**
 * Create surface response
 */
struct fway_create_surface_resp {
    uint64_t surface_id;
    uint64_t buffer_region_id;  /* FIPC shared memory region */
    size_t buffer_size;
    int32_t result;             /* 0 on success, negative on error */
};

/**
 * Destroy surface request
 */
struct fway_destroy_surface_req {
    uint64_t surface_id;
};

/**
 * Attach buffer to surface
 */
struct fway_attach_buffer_req {
    uint64_t surface_id;
    uint64_t buffer_region_id;
    int32_t x;                  /* Offset within surface */
    int32_t y;
};

/**
 * Detach buffer from surface
 */
struct fway_detach_buffer_req {
    uint64_t surface_id;
    uint64_t buffer_region_id;
};

/**
 * Commit surface changes (double-buffering)
 */
struct fway_commit_req {
    uint64_t surface_id;
    uint32_t serial;            /* Frame serial number */
};

/**
 * Mark damaged region for repaint
 */
struct fway_damage_req {
    uint64_t surface_id;
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

/**
 * Set window title
 */
struct fway_set_title_req {
    uint64_t surface_id;
    char title[256];
};

/**
 * Set window size
 */
struct fway_set_size_req {
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
};

/**
 * Set window position
 */
struct fway_set_position_req {
    uint64_t surface_id;
    int32_t x;
    int32_t y;
};

/**
 * Configure event (server → client)
 */
struct fway_configure_event {
    uint64_t surface_id;
    uint32_t width;
    uint32_t height;
    uint32_t serial;
};

/**
 * Frame done event (server → client)
 */
struct fway_frame_done_event {
    uint64_t surface_id;
    uint32_t serial;
    uint64_t timestamp;
};

/**
 * Input event (server → client)
 */
struct fway_input_event {
    uint64_t surface_id;
    enum fway_input_type type;
    uint64_t timestamp;

    union {
        struct {
            uint32_t keycode;
            enum fway_key_state state;
            uint32_t modifiers;     /* Shift, Ctrl, Alt, etc. */
        } key;

        struct {
            enum fway_mouse_button button;
            enum fway_key_state state;
            int32_t x, y;           /* Surface-relative */
        } mouse_button;

        struct {
            int32_t x, y;           /* Surface-relative */
            uint32_t buttons;       /* Button state mask */
        } mouse_motion;

        struct {
            int32_t delta_x;        /* Horizontal scroll */
            int32_t delta_y;        /* Vertical scroll */
        } mouse_wheel;

        struct {
            int32_t id;             /* Touch point ID */
            int32_t x, y;
            enum fway_key_state state;
        } touch;
    } data;
};

/**
 * Close request (server → client)
 */
struct fway_close_request_event {
    uint64_t surface_id;
};

/* ============================================================
 *   Client API
 * ============================================================ */

/**
 * Connect to FuturaWay compositor.
 *
 * @return FIPC channel to compositor, or NULL on error
 */
struct fut_fipc_channel *fway_connect(void);

/**
 * Disconnect from compositor.
 *
 * @param channel Channel to close
 */
void fway_disconnect(struct fut_fipc_channel *channel);

/**
 * Create a surface.
 *
 * @param channel Channel to compositor
 * @param width   Surface width in pixels
 * @param height  Surface height in pixels
 * @param format  Pixel format
 * @param flags   Surface flags
 * @param resp    Response structure (out)
 * @return 0 on success, negative on error
 */
int fway_create_surface(struct fut_fipc_channel *channel,
                         uint32_t width, uint32_t height,
                         enum fway_surface_format format,
                         uint32_t flags,
                         struct fway_create_surface_resp *resp);

/**
 * Destroy a surface.
 *
 * @param channel    Channel to compositor
 * @param surface_id Surface ID
 * @return 0 on success, negative on error
 */
int fway_destroy_surface(struct fut_fipc_channel *channel,
                          uint64_t surface_id);

/**
 * Commit surface changes.
 *
 * @param channel    Channel to compositor
 * @param surface_id Surface ID
 * @return 0 on success, negative on error
 */
int fway_commit(struct fut_fipc_channel *channel,
                uint64_t surface_id);

/**
 * Mark damaged region.
 *
 * @param channel    Channel to compositor
 * @param surface_id Surface ID
 * @param x, y       Damaged region origin
 * @param width, height Damaged region size
 * @return 0 on success, negative on error
 */
int fway_damage(struct fut_fipc_channel *channel,
                uint64_t surface_id,
                int32_t x, int32_t y,
                int32_t width, int32_t height);

/**
 * Set window title.
 *
 * @param channel    Channel to compositor
 * @param surface_id Surface ID
 * @param title      Window title string
 * @return 0 on success, negative on error
 */
int fway_set_title(struct fut_fipc_channel *channel,
                   uint64_t surface_id,
                   const char *title);

/**
 * Poll for events from compositor.
 *
 * @param channel Channel to compositor
 * @param event   Event structure to fill (out)
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return 1 if event received, 0 if no event, negative on error
 */
int fway_poll_event(struct fut_fipc_channel *channel,
                    struct fway_input_event *event,
                    uint32_t timeout_ms);

/* ============================================================
 *   Helper Macros
 * ============================================================ */

#define FWAY_BYTES_PER_PIXEL(format) \
    ((format) == FWAY_FORMAT_RGBA8888 ? 4 : \
     (format) == FWAY_FORMAT_RGB888 ? 3 : \
     (format) == FWAY_FORMAT_RGB565 ? 2 : \
     (format) == FWAY_FORMAT_BGRA8888 ? 4 : 0)

#define FWAY_BUFFER_SIZE(width, height, format) \
    ((width) * (height) * FWAY_BYTES_PER_PIXEL(format))

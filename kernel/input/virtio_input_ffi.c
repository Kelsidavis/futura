// SPDX-License-Identifier: MPL-2.0
/* Forward-declared Rust entry point */
extern int virtio_input_rust_init(void);
/*
 * virtio_input_ffi.c - Kernel-side C shim for the Rust virtio-input driver
 *
 * Creates /dev/input/kbd0 and /dev/input/mouse0 backed by virtio-input
 * event queues.  The Rust driver calls virtio_input_post_event() when
 * events arrive from the hardware; this file routes them to the
 * appropriate chrdev queue and (for key events) also wakes the console
 * line discipline.
 *
 * Major 30 is shared with the PS/2 drivers, but ps2_kbd_init() and
 * ps2_mouse_init() are only called on x86_64 where PS/2 exists.  On
 * ARM64 this file owns major 30.
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <kernel/input.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/kprintf.h>

/* Same major as PS/2 drivers so /dev/input/kbd0 and /dev/input/mouse0
 * look identical to consumers regardless of the underlying driver.    */
#define VINPUT_MAJOR  30u
#define VINPUT_KBD_MINOR   0u
#define VINPUT_MOUSE_MINOR 1u

/* Linux evdev event type codes used by virtio-input */
#define EVTYPE_SYN  0u   /* sync / separator          */
#define EVTYPE_KEY  1u   /* key press / release        */
#define EVTYPE_REL  2u   /* relative pointer movement  */
#define EVTYPE_ABS  3u   /* absolute position (tablet) */

/* Linux evdev REL_* axis codes */
#define REL_X  0u
#define REL_Y  1u

/* Linux evdev BTN_* codes for mouse buttons */
#define BTN_LEFT   0x110u
#define BTN_RIGHT  0x111u
#define BTN_MIDDLE 0x112u

/* ── Device state ──────────────────────────────────────────────── */

struct vinput_dev {
    fut_input_queue_t queue;
    uint32_t open_count;
};

static struct vinput_dev g_vkbd   = { .open_count = 0 };
static struct vinput_dev g_vmouse = { .open_count = 0 };

/* ── Keyboard console integration ──────────────────────────────── */

/* Defined in drivers/tty/console.c (also called by ps2_kbd_init).
 * Passes key events into the console line discipline.               */
extern void kbd_console_handle_key(uint16_t scancode, bool pressed);

/* ── chrdev file operations ────────────────────────────────────── */

struct vinput_file {
    struct vinput_dev *dev;
    int flags;
};

static int vinput_open(void *inode, int flags, void **priv)
{
    (void)inode;
    struct vinput_dev *dev = NULL;

    /* Distinguish kbd from mouse by minor number stored in inode ptr */
    uintptr_t minor = (uintptr_t)inode;
    if (minor == VINPUT_KBD_MINOR)
        dev = &g_vkbd;
    else
        dev = &g_vmouse;

    struct vinput_file *f = fut_malloc(sizeof(*f));
    if (!f)
        return -ENOMEM;

    f->dev   = dev;
    f->flags = flags;
    dev->open_count++;
    if (priv)
        *priv = f;
    return 0;
}

static int vinput_release(void *inode, void *priv)
{
    (void)inode;
    struct vinput_file *f = priv;
    if (!f)
        return 0;
    if (f->dev && f->dev->open_count > 0)
        f->dev->open_count--;
    fut_free(f);
    return 0;
}

static ssize_t vinput_read(void *inode, void *priv,
                           void *u_buf, size_t n, off_t *pos)
{
    (void)inode;
    (void)pos;
    struct vinput_file *f = priv;
    if (!f || !f->dev)
        return -ENODEV;
    return fut_input_queue_read(&f->dev->queue, f->flags, u_buf, n);
}

static bool vinput_poll(void *inode, void *priv, uint32_t req, uint32_t *ready)
{
    (void)inode;
    struct vinput_file *f = priv;
    if (!f || !f->dev) return false;
    *ready = 0;
    if ((req & 0x001 /* EPOLLIN */) && !fut_input_queue_empty(&f->dev->queue))
        *ready |= 0x001;
    return true;
}

static struct fut_file_ops vkbd_fops;
static struct fut_file_ops vmouse_fops;

/* ── Public API called from the Rust driver ────────────────────── */

/**
 * virtio_input_post_event - Route a virtio-input event to the right queue.
 *
 * @type:  Linux evdev EV_KEY / EV_REL / EV_ABS / EV_SYN
 * @code:  Key / axis / button code (Linux evdev numbering)
 * @value: 1 = press, 0 = release; axis delta for EV_REL/EV_ABS
 *
 * EV_SYN events are silently dropped (they are just batch separators).
 * EV_KEY with code < BTN_LEFT is a keyboard key; >= BTN_LEFT is a mouse
 * button.  EV_REL / EV_ABS are mouse movement events.
 */
/*
 * On x86_64, PS/2 already owns /dev/input/mouse0. Route VirtIO mouse events
 * to the PS/2 mouse queue so both hardware paths share one device node.
 */
#ifdef __x86_64__
extern void ps2_mouse_inject_event(const struct fut_input_event *ev);
#define PUSH_MOUSE_EVENT(evp) ps2_mouse_inject_event(evp)
#else
#define PUSH_MOUSE_EVENT(evp) fut_input_queue_push(&g_vmouse.queue, (evp))
#endif

void virtio_input_post_event(uint16_t type, uint16_t code, int32_t value)
{
    if (type == EVTYPE_SYN)
        return;

    if (type == EVTYPE_KEY) {
        if (code < BTN_LEFT) {
            /* Keyboard key */
            bool pressed = (value != 0);
            kbd_console_handle_key(code, pressed);

            struct fut_input_event ev = {
                .ts_ns  = fut_input_now_ns(),
                .type   = FUT_EV_KEY,
                .code   = (int16_t)code,
                .value  = pressed ? 1 : 0,
            };
            fut_input_queue_push(&g_vkbd.queue, &ev);
        } else {
            /* Mouse button */
            struct fut_input_event ev = {
                .ts_ns  = fut_input_now_ns(),
                .type   = FUT_EV_MOUSE_BTN,
                .code   = (int16_t)code,
                .value  = (value != 0) ? 1 : 0,
            };
            PUSH_MOUSE_EVENT(&ev);
        }
        return;
    }

    if (type == EVTYPE_REL) {
        /* Only forward X/Y motion. REL_WHEEL (8) and REL_HWHEEL (6)
         * would otherwise fall through and be coerced to REL_Y, making
         * the cursor drift vertically every time the user scrolled. */
        int16_t out_code;
        if (code == REL_X) {
            out_code = FUT_REL_X;
        } else if (code == REL_Y) {
            out_code = FUT_REL_Y;
        } else {
            return;
        }
        struct fut_input_event ev = {
            .ts_ns  = fut_input_now_ns(),
            .type   = FUT_EV_MOUSE_MOVE,
            .code   = out_code,
            .value  = value,
        };
        PUSH_MOUSE_EVENT(&ev);
        return;
    }

    if (type == EVTYPE_ABS) {
        /* virtio-tablet reports ABSOLUTE positions in a wide logical range
         * (typically 0..32767), not deltas. Convert to pixel coordinates
         * (assume 1024x768 framebuffer for now) and emit the per-axis
         * pixel-level delta. Tracking the last *pixel* position rather
         * than the last raw value means sub-pixel jitter cumulatively
         * still moves the cursor instead of being lost to integer
         * truncation. The first event per axis primes silently. */
        #define ABS_LOGICAL_MAX 32767
        #define FB_W_PX         1024
        #define FB_H_PX         768

        static int32_t last_px_x = 0;
        static int32_t last_px_y = 0;
        static int have_px_x = 0;
        static int have_px_y = 0;

        int32_t cur_px;
        int32_t delta;
        int16_t out_code;

        if (code == 0) {
            cur_px = (int32_t)((int64_t)value * FB_W_PX / ABS_LOGICAL_MAX);
            out_code = FUT_REL_X;
            if (!have_px_x) {
                last_px_x = cur_px;
                have_px_x = 1;
                return;
            }
            delta = cur_px - last_px_x;
            last_px_x = cur_px;
        } else if (code == 1) {
            cur_px = (int32_t)((int64_t)value * FB_H_PX / ABS_LOGICAL_MAX);
            out_code = FUT_REL_Y;
            if (!have_px_y) {
                last_px_y = cur_px;
                have_px_y = 1;
                return;
            }
            delta = cur_px - last_px_y;
            last_px_y = cur_px;
        } else {
            return;
        }
        if (delta == 0) {
            return;
        }

        struct fut_input_event ev = {
            .ts_ns  = fut_input_now_ns(),
            .type   = FUT_EV_MOUSE_MOVE,
            .code   = out_code,
            .value  = delta,
        };
        PUSH_MOUSE_EVENT(&ev);
        return;
    }
}

/* ── Initialization ────────────────────────────────────────────── */

/**
 * virtio_input_hw_init - Register virtio-backed kbd0 / mouse0 chrdevs.
 *
 * Called from kernel_main.c on ARM64 (replaces PS/2 init).  Returns 0
 * on success; negative errno on failure.
 */
int virtio_input_hw_init(void)
{
    static int vinput_fops_inited = 0;
    if (!vinput_fops_inited) {
        vkbd_fops.open = vinput_open;
        vkbd_fops.release = vinput_release;
        vkbd_fops.read = vinput_read;
        vkbd_fops.poll = vinput_poll;

        vmouse_fops.open = vinput_open;
        vmouse_fops.release = vinput_release;
        vmouse_fops.read = vinput_read;
        vmouse_fops.poll = vinput_poll;

        vinput_fops_inited = 1;
    }

    fut_input_queue_init(&g_vkbd.queue);
    fut_input_queue_init(&g_vmouse.queue);

    /* Register keyboard chrdev */
    int rc = chrdev_register(VINPUT_MAJOR, VINPUT_KBD_MINOR,
                             &vkbd_fops, "kbd0",
                             (void *)(uintptr_t)VINPUT_KBD_MINOR);
    if (rc != 0) {
        fut_printf("[VINPUT] chrdev_register kbd0 failed: %d\n", rc);
        return rc;
    }
    rc = devfs_create_chr("/dev/input/kbd0", VINPUT_MAJOR, VINPUT_KBD_MINOR);
    if (rc != 0) {
        fut_printf("[VINPUT] devfs_create_chr kbd0 failed: %d\n", rc);
        return rc;
    }

    /* Register mouse chrdev */
    rc = chrdev_register(VINPUT_MAJOR, VINPUT_MOUSE_MINOR,
                         &vmouse_fops, "mouse0",
                         (void *)(uintptr_t)VINPUT_MOUSE_MINOR);
    if (rc != 0) {
        fut_printf("[VINPUT] chrdev_register mouse0 failed: %d\n", rc);
        return rc;
    }
    rc = devfs_create_chr("/dev/input/mouse0",
                          VINPUT_MAJOR, VINPUT_MOUSE_MINOR);
    if (rc != 0) {
        fut_printf("[VINPUT] devfs_create_chr mouse0 failed: %d\n", rc);
        return rc;
    }

    /* input devices ready */

    /* Start the Rust virtio-input driver (probe devices, start poll thread) */
    virtio_input_rust_init();

    return 0;
}

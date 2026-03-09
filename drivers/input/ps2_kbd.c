// SPDX-License-Identifier: MPL-2.0
/*
 * ps2_kbd.c - PS/2 keyboard driver exposing /dev/input/kbd0
 */

#include <kernel/input.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>

#define KBD_MAJOR 30u
#define KBD_MINOR 0u

#ifdef DEBUG_INPUT
#define INPUT_KDBG(fmt, ...) fut_printf("[KBD] " fmt, ##__VA_ARGS__)
#else
#define INPUT_KDBG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

struct ps2_kbd_device;

struct ps2_kbd_file {
    struct ps2_kbd_device *dev;
    int flags;
};

struct ps2_kbd_device {
    fut_input_queue_t queue;
    uint32_t open_count;
    bool active;
    bool extended;
};

static struct ps2_kbd_device g_ps2_kbd = {0};

static uint16_t translate_scancode(uint8_t code, bool extended) {
    if (!extended) {
        return code;
    }
    switch (code) {
    case 0x1D: return FUT_KEY_RIGHTCTRL;
    case 0x38: return FUT_KEY_RIGHTALT;
    case 0x5B: return FUT_KEY_LEFTMETA;
    case 0x5C: return FUT_KEY_RIGHTMETA;
    default:
        return code;
    }
}

/* Forward declaration for keyboard-to-console integration */
extern void kbd_console_handle_key(uint16_t scancode, bool pressed);

static void emit_key_event(struct ps2_kbd_device *dev, uint16_t keycode, bool pressed) {
    if (!dev || !keycode) {
        return;
    }

    /* Feed key events to console line discipline for terminal input */
    kbd_console_handle_key(keycode, pressed);

    /* Also queue the raw event for applications that want raw input (like Wayland) */
    struct fut_input_event ev = {
        .ts_ns = fut_input_now_ns(),
        .type = FUT_EV_KEY,
        .code = (int16_t)keycode,
        .value = pressed ? 1 : 0,
    };
    fut_input_queue_push(&dev->queue, &ev);
}

void ps2_kbd_handle_byte(uint8_t data) {
    struct ps2_kbd_device *dev = &g_ps2_kbd;

    if (!dev->active) {
        return;
    }

    if (data == 0xE0) {
        dev->extended = true;
        return;
    }
    if (data == 0xE1) {
        /* Pause/BREAK sequence - ignore for now */
        dev->extended = false;
        return;
    }

    bool extended = dev->extended;
    dev->extended = false;
    bool released = (data & 0x80u) != 0;
    uint8_t code = data & 0x7Fu;
    uint16_t keycode = translate_scancode(code, extended);
    INPUT_KDBG("scancode=0x%02X keycode=%u %s\n", code, keycode, released ? "release" : "press");
    emit_key_event(dev, keycode, !released);
}

static int ps2_kbd_open(void *inode, int flags, void **priv) {
    (void)inode;
    struct ps2_kbd_file *file = fut_malloc(sizeof(*file));
    if (!file) {
        return -ENOMEM;
    }
    file->dev = &g_ps2_kbd;
    file->flags = flags;
    g_ps2_kbd.open_count++;
    if (priv) {
        *priv = file;
    }
    return 0;
}

static int ps2_kbd_release(void *inode, void *priv) {
    (void)inode;
    struct ps2_kbd_file *file = (struct ps2_kbd_file *)priv;
    if (!file) {
        return 0;
    }
    if (file->dev && file->dev->open_count > 0) {
        file->dev->open_count--;
    }
    fut_free(file);
    return 0;
}

static ssize_t ps2_kbd_read(void *inode, void *priv, void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    struct ps2_kbd_file *file = (struct ps2_kbd_file *)priv;
    if (!file || !file->dev) {
        return -ENODEV;
    }
    return fut_input_queue_read(&file->dev->queue, file->flags, u_buf, n);
}

static const struct fut_file_ops kbd_fops = {
    .open = ps2_kbd_open,
    .release = ps2_kbd_release,
    .read = ps2_kbd_read,
    .write = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

int ps2_kbd_init(void) {
    fut_input_queue_init(&g_ps2_kbd.queue);
    g_ps2_kbd.open_count = 0;
    g_ps2_kbd.active = true;
    g_ps2_kbd.extended = false;

    int rc = chrdev_register(KBD_MAJOR, KBD_MINOR, &kbd_fops, "kbd0", NULL);
    if (rc != 0) {
        fut_printf("[KBD] chrdev_register failed: %d\n", rc);
        return rc;
    }
    rc = devfs_create_chr("/dev/input/kbd0", KBD_MAJOR, KBD_MINOR);
    if (rc != 0) {
        fut_printf("[KBD] devfs_create_chr failed: %d\n", rc);
        return rc;
    }

    fut_printf("[KBD] ready (/dev/input/kbd0)\n");
    return 0;
}

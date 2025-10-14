// SPDX-License-Identifier: MPL-2.0
/*
 * ps2_mouse.c - PS/2 mouse driver exposing /dev/input/mouse0
 */

#include <kernel/input.h>
#include <kernel/chrdev.h>
#include <kernel/devfs.h>
#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>

#define MOUSE_MAJOR 30u
#define MOUSE_MINOR 1u

#ifdef DEBUG_INPUT
#define INPUT_MDBG(fmt, ...) fut_printf("[MOUSE] " fmt, ##__VA_ARGS__)
#else
#define INPUT_MDBG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

struct ps2_mouse_device;

struct ps2_mouse_file {
    struct ps2_mouse_device *dev;
    int flags;
};

struct ps2_mouse_device {
    fut_input_queue_t queue;
    uint32_t open_count;
    bool active;
    uint8_t packet[3];
    uint8_t index;
    uint8_t buttons;
};

static struct ps2_mouse_device g_ps2_mouse = {0};

static void emit_move_event(struct ps2_mouse_device *dev, int rel_x, int rel_y) {
    if (!rel_x && !rel_y) {
        return;
    }
    if (rel_x) {
        struct fut_input_event ev = {
            .ts_ns = fut_input_now_ns(),
            .type = FUT_EV_MOUSE_MOVE,
            .code = FUT_REL_X,
            .value = rel_x,
        };
        fut_input_queue_push(&dev->queue, &ev);
    }
    if (rel_y) {
        struct fut_input_event ev = {
            .ts_ns = fut_input_now_ns(),
            .type = FUT_EV_MOUSE_MOVE,
            .code = FUT_REL_Y,
            .value = rel_y,
        };
        fut_input_queue_push(&dev->queue, &ev);
    }
}

static void emit_button_event(struct ps2_mouse_device *dev, uint16_t code, bool pressed) {
    struct fut_input_event ev = {
        .ts_ns = fut_input_now_ns(),
        .type = FUT_EV_MOUSE_BTN,
        .code = (int16_t)code,
        .value = pressed ? 1 : 0,
    };
    fut_input_queue_push(&dev->queue, &ev);
}

void ps2_mouse_handle_byte(uint8_t data) {
    struct ps2_mouse_device *dev = &g_ps2_mouse;
    if (!dev->active) {
        return;
    }

    /* Synchronize packets: the first byte always has bit 3 set. */
    if (dev->index == 0 && (data & 0x08u) == 0) {
        INPUT_MDBG("dropping out-of-sync byte 0x%02x\n", data);
        return;
    }

    dev->packet[dev->index++] = data;
    if (dev->index < 3) {
        return;
    }
    dev->index = 0;

    uint8_t status = dev->packet[0];
    int rel_x = (int8_t)dev->packet[1];
    int rel_y = (int8_t)dev->packet[2];
    /* PS/2 Y is inverted (positive is upward). Flip to screen coordinates. */
    rel_y = -rel_y;
    emit_move_event(dev, rel_x, rel_y);

    uint8_t buttons = status & 0x07u;
    uint8_t changed = buttons ^ dev->buttons;
    if (changed & 0x01u) {
        emit_button_event(dev, FUT_BTN_LEFT, (buttons & 0x01u) != 0);
    }
    if (changed & 0x02u) {
        emit_button_event(dev, FUT_BTN_RIGHT, (buttons & 0x02u) != 0);
    }
    if (changed & 0x04u) {
        emit_button_event(dev, FUT_BTN_MIDDLE, (buttons & 0x04u) != 0);
    }
    dev->buttons = buttons;
}

static int ps2_mouse_open(void *inode, int flags, void **priv) {
    (void)inode;
    struct ps2_mouse_file *file = fut_malloc(sizeof(*file));
    if (!file) {
        return -ENOMEM;
    }
    file->dev = &g_ps2_mouse;
    file->flags = flags;
    g_ps2_mouse.open_count++;
    if (priv) {
        *priv = file;
    }
    return 0;
}

static int ps2_mouse_release(void *inode, void *priv) {
    (void)inode;
    struct ps2_mouse_file *file = (struct ps2_mouse_file *)priv;
    if (!file) {
        return 0;
    }
    if (file->dev && file->dev->open_count > 0) {
        file->dev->open_count--;
    }
    fut_free(file);
    return 0;
}

static ssize_t ps2_mouse_read(void *inode, void *priv, void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    struct ps2_mouse_file *file = (struct ps2_mouse_file *)priv;
    if (!file || !file->dev) {
        return -ENODEV;
    }
    return fut_input_queue_read(&file->dev->queue, file->flags, u_buf, n);
}

static const struct fut_file_ops mouse_fops = {
    .open = ps2_mouse_open,
    .release = ps2_mouse_release,
    .read = ps2_mouse_read,
    .write = NULL,
    .ioctl = NULL,
    .mmap = NULL,
};

int ps2_mouse_init(void) {
    fut_input_queue_init(&g_ps2_mouse.queue);
    g_ps2_mouse.open_count = 0;
    g_ps2_mouse.active = true;
    g_ps2_mouse.index = 0;
    g_ps2_mouse.buttons = 0;

    int rc = chrdev_register(MOUSE_MAJOR, MOUSE_MINOR, &mouse_fops, "mouse0", NULL);
    if (rc != 0) {
        return rc;
    }
    rc = devfs_create_chr("/dev/input/mouse0", MOUSE_MAJOR, MOUSE_MINOR);
    if (rc != 0) {
        INPUT_MDBG("devfs registration failed: %d\n", rc);
        return rc;
    }

    INPUT_MDBG("ready (/dev/input/mouse0)\n");
    return 0;
}

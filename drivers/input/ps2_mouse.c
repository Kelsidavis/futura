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

/* Pipeline-stage atomic counters.  Bumped from IRQ + syscall contexts
 * without locks; surfaced via ps2_mouse_get_stats() so the timer-tick
 * heartbeat in ps2.c can print whichever stage stopped advancing.
 *
 * Walking from byte arrival to cursor pixel:
 *   irq_bytes_recv    - bytes ps2_mouse_handle_byte received from ISR
 *   irq_bytes_dropped - bytes rejected by the bit-3 sync check
 *   irq_packets       - 3-byte packets fully assembled
 *   irq_events_pushed - events pushed into the input queue
 *   reads_serviced    - successful ps2_mouse_read syscalls (compositor)
 *   opens             - times /dev/input/mouse0 was opened
 */
static uint32_t g_stat_bytes_recv;
static uint32_t g_stat_bytes_dropped;
static uint32_t g_stat_packets;
static uint32_t g_stat_events_pushed;
static uint32_t g_stat_reads_serviced;
static uint32_t g_stat_opens;

void ps2_mouse_get_stats(uint32_t *bytes_recv, uint32_t *bytes_dropped,
                         uint32_t *packets, uint32_t *events_pushed,
                         uint32_t *reads_serviced, uint32_t *opens) {
    if (bytes_recv)     *bytes_recv     = __atomic_load_n(&g_stat_bytes_recv,     __ATOMIC_RELAXED);
    if (bytes_dropped)  *bytes_dropped  = __atomic_load_n(&g_stat_bytes_dropped,  __ATOMIC_RELAXED);
    if (packets)        *packets        = __atomic_load_n(&g_stat_packets,        __ATOMIC_RELAXED);
    if (events_pushed)  *events_pushed  = __atomic_load_n(&g_stat_events_pushed,  __ATOMIC_RELAXED);
    if (reads_serviced) *reads_serviced = __atomic_load_n(&g_stat_reads_serviced, __ATOMIC_RELAXED);
    if (opens)          *opens          = __atomic_load_n(&g_stat_opens,          __ATOMIC_RELAXED);
}

/* Raw byte capture for diagnosing L490-style mouse-pipeline bugs.
 * We don't know the byte format the L490 actually emits; the only way
 * to find out without a serial console is to log the first 64 bytes
 * received and surface them in the boot-time framebuffer console. */
#define PS2_BYTE_CAP_MAX 64u
static volatile uint8_t g_byte_capture[PS2_BYTE_CAP_MAX];
static volatile uint32_t g_byte_capture_count;

void ps2_mouse_get_byte_capture(uint8_t *out, uint32_t *out_count) {
    uint32_t c = __atomic_load_n(&g_byte_capture_count, __ATOMIC_RELAXED);
    if (c > PS2_BYTE_CAP_MAX) c = PS2_BYTE_CAP_MAX;
    for (uint32_t i = 0; i < c; i++) {
        out[i] = g_byte_capture[i];
    }
    *out_count = c;
}

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
        __atomic_add_fetch(&g_stat_events_pushed, 1, __ATOMIC_RELAXED);
    }
    if (rel_y) {
        struct fut_input_event ev = {
            .ts_ns = fut_input_now_ns(),
            .type = FUT_EV_MOUSE_MOVE,
            .code = FUT_REL_Y,
            .value = rel_y,
        };
        fut_input_queue_push(&dev->queue, &ev);
        __atomic_add_fetch(&g_stat_events_pushed, 1, __ATOMIC_RELAXED);
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
    __atomic_add_fetch(&g_stat_events_pushed, 1, __ATOMIC_RELAXED);
}

/* Allow VirtIO input driver to inject events into the PS/2 mouse queue.
 * This lets both PS/2 hardware and VirtIO mouse share /dev/input/mouse0. */
void ps2_mouse_inject_event(const struct fut_input_event *ev) {
    if (g_ps2_mouse.active) {
        fut_input_queue_push(&g_ps2_mouse.queue, ev);
    }
}

void ps2_mouse_handle_byte(uint8_t data) {
    struct ps2_mouse_device *dev = &g_ps2_mouse;
    if (!dev->active) {
        return;
    }
    __atomic_add_fetch(&g_stat_bytes_recv, 1, __ATOMIC_RELAXED);

    /* Capture the first 64 bytes we see for the diagnostic dump.
     * Doing it before any parser logic means we record exactly what
     * the device sent, independent of how (mis-)interpreted bytes
     * affect the synced state.  Stop after 64 so we don't churn a
     * ring buffer; that's enough to identify the packet format
     * (standard 3-byte vs IntelliMouse 4-byte vs Synaptics 6-byte). */
    {
        uint32_t c = __atomic_load_n(&g_byte_capture_count, __ATOMIC_RELAXED);
        if (c < PS2_BYTE_CAP_MAX) {
            g_byte_capture[c] = data;
            __atomic_store_n(&g_byte_capture_count, c + 1, __ATOMIC_RELAXED);
        }
    }

    /* Synchronize packets: the first byte always has bit 3 set. */
    if (dev->index == 0 && (data & 0x08u) == 0) {
        __atomic_add_fetch(&g_stat_bytes_dropped, 1, __ATOMIC_RELAXED);
        INPUT_MDBG("dropping out-of-sync byte 0x%02x\n", data);
        return;
    }

    dev->packet[dev->index++] = data;
    if (dev->index < 3) {
        return;
    }
    dev->index = 0;
    __atomic_add_fetch(&g_stat_packets, 1, __ATOMIC_RELAXED);

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
    __atomic_add_fetch(&g_stat_opens, 1, __ATOMIC_RELAXED);
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
    ssize_t rc = fut_input_queue_read(&file->dev->queue, file->flags, u_buf, n);
    if (rc > 0) {
        __atomic_add_fetch(&g_stat_reads_serviced, 1, __ATOMIC_RELAXED);
    }
    return rc;
}

static bool ps2_mouse_poll(void *inode, void *priv, uint32_t req, uint32_t *ready) {
    (void)inode;
    struct ps2_mouse_file *file = (struct ps2_mouse_file *)priv;
    if (!file || !file->dev) return false;
    *ready = 0;
    if ((req & 0x001 /* EPOLLIN */) && !fut_input_queue_empty(&file->dev->queue))
        *ready |= 0x001;
    return true;
}

static struct fut_file_ops mouse_fops;

/* Timer-tick drain hook (called weakly from fut_timer_tick on x86_64).
 * Pairs with the deferred-wake path in fut_input_queue_push: mouse-move
 * events on a non-empty queue set wake_pending instead of waking
 * directly from IRQ context, and this drain converts that flag into a
 * waitq wake at the 100 Hz tick rate.  See input.h for the policy. */
void ps2_mouse_drain_deferred_wake(void) {
    if (g_ps2_mouse.active) {
        fut_input_queue_drain_wake(&g_ps2_mouse.queue);
    }
}

int ps2_mouse_init(void) {
    fut_input_queue_init(&g_ps2_mouse.queue);
    g_ps2_mouse.open_count = 0;
    g_ps2_mouse.active = true;
    g_ps2_mouse.index = 0;
    g_ps2_mouse.buttons = 0;

    if (!mouse_fops.open) {
        mouse_fops.open = ps2_mouse_open;
        mouse_fops.release = ps2_mouse_release;
        mouse_fops.read = ps2_mouse_read;
        mouse_fops.write = NULL;
        mouse_fops.ioctl = NULL;
        mouse_fops.mmap = NULL;
        mouse_fops.poll = ps2_mouse_poll;
    }

    int rc = chrdev_register(MOUSE_MAJOR, MOUSE_MINOR, &mouse_fops, "mouse0", NULL);
    if (rc != 0) {
        fut_printf("[MOUSE] chrdev_register failed: %d\n", rc);
        return rc;
    }
    rc = devfs_create_chr("/dev/input/mouse0", MOUSE_MAJOR, MOUSE_MINOR);
    if (rc != 0) {
        fut_printf("[MOUSE] devfs_create_chr failed: %d\n", rc);
        return rc;
    }

    fut_printf("[MOUSE] ready (/dev/input/mouse0)\n");
    return 0;
}

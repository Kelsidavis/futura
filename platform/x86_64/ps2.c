// SPDX-License-Identifier: MPL-2.0
/*
 * ps2.c - Minimal i8042 controller support for PS/2 keyboard/mouse
 */

#include <platform/platform.h>
#include <platform/x86_64/regs.h>
#include <kernel/errno.h>

#include <stdbool.h>
#include <stdint.h>

extern int ps2_kbd_init(void);
extern int ps2_mouse_init(void);
extern void ps2_kbd_handle_byte(uint8_t byte);
extern void ps2_mouse_handle_byte(uint8_t byte);

#define PS2_DATA_PORT    0x60
#define PS2_STATUS_PORT  0x64
#define PS2_CMD_PORT     0x64

#define PS2_CMD_DISABLE_FIRST   0xAD
#define PS2_CMD_ENABLE_FIRST    0xAE
#define PS2_CMD_DISABLE_SECOND  0xA7
#define PS2_CMD_ENABLE_SECOND   0xA8
#define PS2_CMD_READ_CONFIG     0x20
#define PS2_CMD_WRITE_CONFIG    0x60
#define PS2_CMD_WRITE_SECOND    0xD4

#define PS2_CONFIG_FIRST_IRQ    0x01
#define PS2_CONFIG_SECOND_IRQ   0x02
#define PS2_CONFIG_TRANSLATE    0x40

#define PS2_ACK                 0xFA
#define PS2_RESEND              0xFE

#ifdef DEBUG_INPUT
#define PS2_DBG(fmt, ...) fut_printf("[PS2] " fmt, ##__VA_ARGS__)
#else
#define PS2_DBG(fmt, ...) do { (void)sizeof(fmt); } while (0)
#endif

static bool g_ps2_keyboard_enabled = false;
static bool g_ps2_mouse_enabled = false;
static bool g_ps2_ready = false;

static void ps2_wait_input_clear(void) {
    for (int i = 0; i < 100000; ++i) {
        if ((hal_inb(PS2_STATUS_PORT) & 0x02u) == 0) {
            return;
        }
    }
    PS2_DBG("timeout waiting for input buffer\n");
}

static bool ps2_wait_output_full(void) {
    for (int i = 0; i < 100000; ++i) {
        if (hal_inb(PS2_STATUS_PORT) & 0x01u) {
            return true;
        }
    }
    return false;
}

static void ps2_write_cmd(uint8_t cmd) {
    ps2_wait_input_clear();
    hal_outb(PS2_CMD_PORT, cmd);
}

static void ps2_write_data(uint8_t data) {
    ps2_wait_input_clear();
    hal_outb(PS2_DATA_PORT, data);
}

static uint8_t ps2_read_data(void) {
    if (!ps2_wait_output_full()) {
        return 0xFFu;
    }
    return hal_inb(PS2_DATA_PORT);
}

static void ps2_flush_output(void) {
    while (hal_inb(PS2_STATUS_PORT) & 0x01u) {
        (void)hal_inb(PS2_DATA_PORT);
    }
}

static void ps2_write_second(uint8_t value) {
    ps2_write_cmd(PS2_CMD_WRITE_SECOND);
    ps2_write_data(value);
}

static int ps2_expect_ack(void) {
    uint8_t resp = ps2_read_data();
    if (resp == PS2_ACK) {
        return 0;
    }
    if (resp == PS2_RESEND) {
        return -EAGAIN;
    }
    return -EIO;
}

static void ps2_irq_keyboard(void) {
    if (!g_ps2_keyboard_enabled) {
        fut_irq_send_eoi(1);
        return;
    }

    for (;;) {
        uint8_t status = hal_inb(PS2_STATUS_PORT);
        if ((status & 0x01u) == 0) {
            break;
        }
        uint8_t data = hal_inb(PS2_DATA_PORT);
        if (status & 0x20u) {
            ps2_mouse_handle_byte(data);
        } else {
            ps2_kbd_handle_byte(data);
        }
    }

    fut_irq_send_eoi(1);
}

static void ps2_irq_mouse(void) {
    if (!g_ps2_mouse_enabled) {
        fut_irq_send_eoi(12);
        return;
    }

    for (;;) {
        uint8_t status = hal_inb(PS2_STATUS_PORT);
        if ((status & 0x01u) == 0) {
            break;
        }
        uint8_t data = hal_inb(PS2_DATA_PORT);
        if (status & 0x20u) {
            ps2_mouse_handle_byte(data);
        } else {
            ps2_kbd_handle_byte(data);
        }
    }

    fut_irq_send_eoi(12);
}

int ps2_controller_init(bool enable_keyboard, bool enable_mouse) {
    if (g_ps2_ready) {
        g_ps2_keyboard_enabled = enable_keyboard;
        g_ps2_mouse_enabled = enable_mouse;
        return 0;
    }

    ps2_flush_output();
    ps2_write_cmd(PS2_CMD_DISABLE_FIRST);
    ps2_write_cmd(PS2_CMD_DISABLE_SECOND);
    ps2_flush_output();

    ps2_write_cmd(PS2_CMD_READ_CONFIG);
    uint8_t config = ps2_read_data();
    config &= ~(PS2_CONFIG_FIRST_IRQ | PS2_CONFIG_SECOND_IRQ);
    if (enable_keyboard) {
        config |= PS2_CONFIG_FIRST_IRQ;
        /* Enable hardware translation from Set 2 to Set 1 scancodes */
        config |= PS2_CONFIG_TRANSLATE;
    }
    if (enable_mouse) {
        config |= PS2_CONFIG_SECOND_IRQ;
    }

    ps2_write_cmd(PS2_CMD_WRITE_CONFIG);
    ps2_write_data(config);

    if (enable_keyboard) {
        ps2_write_cmd(PS2_CMD_ENABLE_FIRST);
        g_ps2_keyboard_enabled = true;
        fut_irq_enable(1);
        fut_printf("[PS2] Keyboard IRQ 1 enabled\n");
    } else {
        fut_irq_disable(1);
    }

    if (enable_mouse) {
        ps2_write_cmd(PS2_CMD_ENABLE_SECOND);
        ps2_write_second(0xF6); /* defaults */
        (void)ps2_expect_ack();
        ps2_write_second(0xF4); /* enable streaming */
        (void)ps2_expect_ack();
        g_ps2_mouse_enabled = true;
        fut_irq_enable(12);
    } else {
        fut_irq_disable(12);
    }

    g_ps2_ready = true;
    PS2_DBG("controller ready (kbd=%d mouse=%d)\n", enable_keyboard, enable_mouse);
    return 0;
}

void fut_irq_handler(void *frame_ptr) {
    fut_interrupt_frame_t *frame = (fut_interrupt_frame_t *)frame_ptr;
    uint8_t vector = (uint8_t)frame->vector;
    if (vector < 32 || vector > 47) {
        return;
    }
    uint8_t irq = (uint8_t)(vector - 32u);
    switch (irq) {
    case 1:
        ps2_irq_keyboard();
        break;
    case 12:
        ps2_irq_mouse();
        break;
    default:
        fut_irq_send_eoi(irq);
        break;
    }
}

int fut_input_hw_init(bool want_keyboard, bool want_mouse) {
    int rc = 0;
    if (want_keyboard) {
        rc = ps2_kbd_init();
        if (rc != 0) {
            PS2_DBG("keyboard init failed: %d\n", rc);
            want_keyboard = false;
        }
    }
    if (want_mouse) {
        int mouse_rc = ps2_mouse_init();
        if (mouse_rc != 0) {
            PS2_DBG("mouse init failed: %d\n", mouse_rc);
            want_mouse = false;
            if (rc == 0) {
                rc = mouse_rc;
            }
        }
    }

    if (!want_keyboard && !want_mouse) {
        fut_irq_disable(1);
        fut_irq_disable(12);
        return rc;
    }

    ps2_controller_init(want_keyboard, want_mouse);
    return rc;
}

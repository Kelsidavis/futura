// SPDX-License-Identifier: MPL-2.0
/*
 * ps2.c - Minimal i8042 controller support for PS/2 keyboard/mouse
 */

#include <platform/platform.h>
#include <platform/x86_64/regs.h>
#include <kernel/errno.h>
#include <kernel/boot_args.h>

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

/* IRQ counters — incremented from the ISRs without printing, then
 * read by ps2_irq_stats_poll() at timer-tick context for the boot-log
 * heartbeat.  Printing from inside the ISR is unsafe on HEADFUL
 * builds: fut_printf -> fb_console_putc walks the framebuffer, which
 * is tens of milliseconds of pixel work with interrupts disabled, and
 * sustained mouse IRQs pile up faster than each one drains → timer
 * IRQs starve → clock stops → whole machine locks.  Counters alone
 * are atomic and cheap. */
static uint32_t g_ps2_irq1_count = 0;
static uint32_t g_ps2_irq12_count = 0;
static uint32_t g_ps2_irq1_last_logged = 0;
static uint32_t g_ps2_irq12_last_logged = 0;

static inline bool ps2_irq_log_threshold(uint32_t c) {
    return c == 1 || c == 4 || c == 16 || c == 64 || c == 256 || c == 1024 ||
           c == 4096 || c == 16384;
}

/* Called from fut_timer_tick (weak link) at 100 Hz.  Picks up any
 * threshold crossings since the last tick and prints them safely in
 * thread/interrupt-context-without-CLI. */
void ps2_irq_stats_poll(void) {
    uint32_t c1 = __atomic_load_n(&g_ps2_irq1_count, __ATOMIC_RELAXED);
    if (c1 != g_ps2_irq1_last_logged && ps2_irq_log_threshold(c1)) {
        fut_printf("[PS2] IRQ1 count=%u\n", c1);
        g_ps2_irq1_last_logged = c1;
    }
    uint32_t c12 = __atomic_load_n(&g_ps2_irq12_count, __ATOMIC_RELAXED);
    if (c12 != g_ps2_irq12_last_logged && ps2_irq_log_threshold(c12)) {
        fut_printf("[PS2] IRQ12 count=%u\n", c12);
        g_ps2_irq12_last_logged = c12;
    }
}

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

void ps2_irq_keyboard(void) {
    if (!g_ps2_keyboard_enabled) {
        fut_irq_send_eoi(1);
        return;
    }

    __atomic_add_fetch(&g_ps2_irq1_count, 1, __ATOMIC_RELAXED);
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

    /* Send PIC EOI first so the legacy PIC clears its ISR bit and
     * deasserts the IRQ line.  This allows the IOAPIC (edge-triggered)
     * to detect a new rising edge for the next keystroke.  In QEMU's
     * i440FX emulation the i8042 routes through the PIC even when the
     * IOAPIC is active. */
    hal_outb(0x20, 0x20);  /* PIC1 EOI */

    fut_irq_send_eoi(1);
}

void ps2_irq_mouse(void) {
    if (!g_ps2_mouse_enabled) {
        fut_irq_send_eoi(12);
        return;
    }

    __atomic_add_fetch(&g_ps2_irq12_count, 1, __ATOMIC_RELAXED);
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

    /* Send PIC EOI (both slave and master) so the legacy PIC deasserts
     * the IRQ line, enabling the IOAPIC to detect the next edge. */
    hal_outb(0xA0, 0x20);  /* PIC2 EOI (slave) */
    hal_outb(0x20, 0x20);  /* PIC1 EOI (master cascade) */

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
        extern uint64_t fut_rdtsc(void);
        ps2_write_cmd(PS2_CMD_ENABLE_SECOND);
        /* Drain anything the firmware/BIOS left in the AUX buffer so
         * our reset ACK isn't confused with a pre-existing byte. */
        ps2_flush_output();

        /* Reset the mouse (0xFF).  The device returns ACK (0xFA)
         * within microseconds, then runs Basic Assurance Test for
         * 500-700 ms before sending the BAT result (0xAA) and the
         * device ID (0x00 for a standard PS/2 mouse).  The original
         * implementation tried to read BAT/ID synchronously with the
         * short ps2_wait_output_full timeout (~100 µs), got 0xFF
         * back from a timeout, and proceeded into F3/F6/F4 while
         * the device was still BAT'ing — those commands rode on top
         * of the eventual BAT+ID bytes, the packet parser saw 0xAA
         * (bit-3 set!) as a packet header on the next IRQ, and the
         * cursor sat dead because every "packet" was misaligned. */
        ps2_write_second(0xFF);
        int rc = ps2_expect_ack();
        fut_printf("[PS2] mouse reset (0xFF): ack=%d\n", rc);

        /* Wait ~1 s for BAT to complete.  Three billion TSC cycles is
         * 1 s at 3 GHz, ~770 ms at 3.9 GHz (L490 turbo), and 3 s on
         * a slow 1 GHz core — all comfortably past the 700 ms BAT
         * spec ceiling.  This is a busy loop, but it runs once per
         * boot, before scheduler start, so nothing else cares. */
        uint64_t t0 = fut_rdtsc();
        while (fut_rdtsc() - t0 < 3000000000ULL) {
            __asm__ volatile("pause" ::: "memory");
        }

        /* Drain whatever the mouse posted during BAT — should be BAT
         * pass (0xAA) followed by device ID (0x00).  Print it so the
         * boot log confirms the device responded; on real hardware
         * the BAT/ID values reveal Synaptics passthrough, Elan
         * extensions, etc., even if we don't act on them yet. */
        uint8_t drained[8] = {0};
        int n_drained = 0;
        while (n_drained < (int)sizeof(drained) &&
               (hal_inb(PS2_STATUS_PORT) & 0x01u) != 0) {
            drained[n_drained++] = hal_inb(PS2_DATA_PORT);
        }
        fut_printf("[PS2] mouse post-reset drained %d byte(s): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   n_drained,
                   drained[0], drained[1], drained[2], drained[3],
                   drained[4], drained[5], drained[6], drained[7]);

        ps2_write_second(0xF6);
        rc = ps2_expect_ack();
        fut_printf("[PS2] mouse set defaults (0xF6): ack=%d\n", rc);

        ps2_write_second(0xF4);
        rc = ps2_expect_ack();
        fut_printf("[PS2] mouse enable streaming (0xF4): ack=%d\n", rc);

        /* Final settle + drain.  The mouse may post a stray byte or
         * two between F4 ACK and entering streaming mode; flushing
         * here guarantees the IRQ12 path sees a clean byte boundary
         * and ps2_mouse_handle_byte's bit-3 sync check locks onto the
         * very first real movement packet instead of treating leftover
         * garbage as packet headers. */
        t0 = fut_rdtsc();
        while (fut_rdtsc() - t0 < 50000000ULL) {  /* ~16 ms @ 3 GHz */
            __asm__ volatile("pause" ::: "memory");
        }
        ps2_flush_output();

        g_ps2_mouse_enabled = true;
        fut_irq_enable(12);
        fut_printf("[PS2] mouse IRQ 12 enabled\n");
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

/* Forward declarations for symbols defined later in this file but
 * used by the diagnostic dump below. */
extern void hal_outb(uint16_t port, uint8_t value);
extern uint8_t hal_inb(uint16_t port);

/* One-shot diagnostic: after PS/2 init, pause for ~30 s while we
 * manually poll the i8042 output buffer.  Goals:
 *   - Slow the boot log enough to read the [ACPI]/[IOAPIC]/[PS2]
 *     lines that scroll past instantaneously on a live framebuffer.
 *   - Tell whether the controller has any data at all (port 0x60 /
 *     STATUS bit 0) without depending on IRQ delivery -- if data is
 *     present here but IRQ counters stay at zero, the bug is in
 *     IRQ routing / vector setup.  If no data appears at all, the
 *     controller or the AUX device itself isn't producing anything.
 *   - Report IRQ1/IRQ12 counters every second so a stray IRQ that
 *     does land becomes immediately visible.
 *
 * Tap from outside in the meantime: every loop iteration is one
 * status read + maybe one data read, all from a busy-loop with IRQs
 * *enabled* (we want IRQs to be able to fire so the counters move).
 *
 * Enable by passing input_diag on the boot command line.  Stays off
 * by default so production boots aren't gated on a 30 s pause. */
static void ps2_diag_pause_and_poll(void) {
    if (!fut_boot_arg_flag("input_diag")) {
        return;
    }
    extern uint64_t fut_rdtsc(void);
    fut_printf("\n");
    fut_printf("####################################################################\n");
    fut_printf("##  [PS2 DIAG] 30 s pause -- read the input init log above        ##\n");
    fut_printf("##  Polling port 0x60 directly; any IRQ1/IRQ12 firing shows in    ##\n");
    fut_printf("##  the per-second counter dump below.                            ##\n");
    fut_printf("####################################################################\n");

    /* 30 one-second steps so we get fresh counters/data each second. */
    for (int sec = 0; sec < 30; ++sec) {
        /* Drain whatever the controller has in its output buffer
         * right now.  Note: this races with the IRQ handler -- if an
         * IRQ fires while we're polling, it'll grab bytes first.
         * That's fine: we only print what we manage to grab here,
         * and the counter dump tells us what the IRQ side saw. */
        uint8_t snap[8] = {0};
        int n = 0;
        while (n < (int)sizeof(snap) && (hal_inb(PS2_STATUS_PORT) & 0x01u)) {
            snap[n++] = hal_inb(PS2_DATA_PORT);
        }
        fut_printf("[PS2 DIAG t=%2ds] IRQ1=%u IRQ12=%u STATUS=0x%02x polled=%d: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                   sec,
                   __atomic_load_n(&g_ps2_irq1_count, __ATOMIC_RELAXED),
                   __atomic_load_n(&g_ps2_irq12_count, __ATOMIC_RELAXED),
                   hal_inb(PS2_STATUS_PORT),
                   n,
                   snap[0], snap[1], snap[2], snap[3],
                   snap[4], snap[5], snap[6], snap[7]);

        /* Busy-wait ~1 s via TSC -- safe before scheduler start, and
         * we want IRQs to be able to fire during the wait. */
        uint64_t t0 = fut_rdtsc();
        while (fut_rdtsc() - t0 < 3000000000ULL) {
            __asm__ volatile("pause" ::: "memory");
        }
    }
    fut_printf("[PS2 DIAG] pause complete, continuing boot\n");
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
    /* IRQs are now unmasked.  Fire the diagnostic pause AFTER unmask
     * so any IRQs the controller wants to deliver have a chance to
     * land and bump our counters.  Enabled only with input_diag=1
     * on the boot command line. */
    ps2_diag_pause_and_poll();
    return rc;
}

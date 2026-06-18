/* apple_audio_tests.c - NULL/init guards for apple_audio public API
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_audio drives the MCA I2S engine plus the I2C codec.  On QEMU
 * virt (test harness) the Apple-platform branch of platform_init is
 * skipped, so g_audio.initialized stays false.  Every public
 * function should return -1 (or refuse a NULL arg) rather than
 * touch uninitialised state.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_audio.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define AUD_PASS(name) \
    do { \
        fut_printf("[AUDIO-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define AUD_FAIL(name, code) \
    do { \
        fut_printf("[AUDIO-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_audio_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[AUDIO-TEST] starting apple_audio guard tests\n");

    /* T1: init(NULL info) → -1 */
    {
        if (apple_audio_init(NULL) == -1) AUD_PASS("init(NULL info)");
        else { AUD_FAIL("init(NULL)", 1); return; }
    }

    /* T2: configure() without init → -1 */
    {
        int rc = apple_audio_configure(48000, 2, 0);
        if (rc == -1) AUD_PASS("configure(no init)");
        else { AUD_FAIL("configure(no init)", 2); return; }
    }

    /* T3: play_start() without init → -1 */
    {
        if (apple_audio_play_start() == -1) AUD_PASS("play_start(no init)");
        else { AUD_FAIL("play_start(no init)", 3); return; }
    }

    /* T4: play_stop() without init → -1 */
    {
        if (apple_audio_play_stop() == -1) AUD_PASS("play_stop(no init)");
        else { AUD_FAIL("play_stop(no init)", 4); return; }
    }

    /* T5: write() without init → -1 */
    {
        uint8_t buf[16] = {0};
        if (apple_audio_write(buf, sizeof(buf)) == -1) {
            AUD_PASS("write(no init)");
        } else {
            AUD_FAIL("write(no init)", 5);
            return;
        }
    }

    /* T6: set_volume() without init → -1 */
    {
        if (apple_audio_set_volume(50) == -1) AUD_PASS("set_volume(no init)");
        else { AUD_FAIL("set_volume(no init)", 6); return; }
    }

    /* T7: get_state(NULL out) → -1 */
    {
        if (apple_audio_get_state(NULL) == -1) AUD_PASS("get_state(NULL)");
        else { AUD_FAIL("get_state(NULL)", 7); return; }
    }

    /* T8: platform_init(NULL info) → -1 */
    {
        if (apple_audio_platform_init(NULL) == -1) {
            AUD_PASS("platform_init(NULL info)");
        } else {
            AUD_FAIL("platform_init(NULL)", 8);
            return;
        }
    }

    /* T9-T12: configure input validation (these all fail at the
     * !initialized guard first, but exercise the call paths) */
    {
        if (apple_audio_configure(7999, 2, 0) == -1) {
            AUD_PASS("configure(rate too low)");
        } else {
            AUD_FAIL("configure(rate too low)", 9);
            return;
        }
    }
    {
        if (apple_audio_configure(400000, 2, 0) == -1) {
            AUD_PASS("configure(rate too high)");
        } else {
            AUD_FAIL("configure(rate too high)", 10);
            return;
        }
    }
    {
        if (apple_audio_configure(48000, 0, 0) == -1) {
            AUD_PASS("configure(channels=0)");
        } else {
            AUD_FAIL("configure(channels=0)", 11);
            return;
        }
    }
    {
        if (apple_audio_configure(48000, 9, 0) == -1) {
            AUD_PASS("configure(channels>8)");
        } else {
            AUD_FAIL("configure(channels>8)", 12);
            return;
        }
    }

    /* T13: get_volume without init → 0xFF sentinel */
    {
        if (apple_audio_get_volume() == 0xFF) {
            AUD_PASS("get_volume(no init)");
        } else {
            AUD_FAIL("get_volume(no init)", 13);
            return;
        }
    }

    /* T14: capture_start() without init → -1 */
    {
        if (apple_audio_capture_start() == -1) {
            AUD_PASS("capture_start(no init)");
        } else {
            AUD_FAIL("capture_start(no init)", 14);
            return;
        }
    }

    /* T15: capture_stop() without init → -1 */
    {
        if (apple_audio_capture_stop() == -1) {
            AUD_PASS("capture_stop(no init)");
        } else {
            AUD_FAIL("capture_stop(no init)", 15);
            return;
        }
    }

    /* T16: read(NULL, len) → -1 (NULL-arg + no-init reject) */
    {
        if (apple_audio_read(NULL, 64) == -1) {
            AUD_PASS("read(NULL)");
        } else {
            AUD_FAIL("read(NULL)", 16);
            return;
        }
    }

    fut_printf("[AUDIO-TEST] all apple_audio guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_audio_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */

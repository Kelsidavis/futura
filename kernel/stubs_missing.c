/* Minimal stubs for missing linker symbols */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Test framework stubs */
void fut_test_plan(int count __attribute__((unused))) {}
void fut_test_pass(void) {}
void fut_test_fail(void) {}
int fut_tests_completed(void) { return 1; }

/* Framebuffer stubs */
int fb_is_available(void) { return 0; }
int fb_boot_splash(void) { return 0; }
int fb_char_init(void) { return 0; }
void *fb_get_info(void) { return (void *)0; }
int fb_probe_from_multiboot(void *mbi __attribute__((unused))) { return -1; }

/* PS2 input stubs */
void ps2_kbd_init(void) {}
void ps2_mouse_init(void) {}
void ps2_kbd_handle_byte(uint8_t byte __attribute__((unused))) {}
void ps2_mouse_handle_byte(uint8_t byte __attribute__((unused))) {}

/* Block device stubs */
int fut_blk_register(void) { return 0; }
int fut_blk_async_selftest_schedule(void) { return 0; }

/* Filesystem stubs */
int fut_futfs_selftest_schedule(void) { return 0; }

/* Network stubs */
int fut_net_selftest_schedule(void) { return 0; }

/* Performance stubs */
int fut_perf_selftest_schedule(void) { return 0; }

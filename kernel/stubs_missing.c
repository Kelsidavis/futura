/* Minimal stubs for missing linker symbols */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Test framework stubs */
void fut_test_plan(int count __attribute__((unused))) {}
void fut_test_pass(void) {}
void fut_test_fail(void) {}
int fut_tests_completed(void) { return 1; }

/* Block device stubs - async test (not implemented) */
int fut_blk_async_selftest_schedule(void) { return 0; }

/* Filesystem stubs - async test (not implemented) */
int fut_futfs_selftest_schedule(void) { return 0; }

/* Network stubs - async test (not implemented) */
int fut_net_selftest_schedule(void) { return 0; }

/* Note: Framebuffer, PS2, Block register, and Perf stubs are now implemented in their respective source files */

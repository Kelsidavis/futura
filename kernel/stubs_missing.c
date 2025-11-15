/* Minimal stubs for missing linker symbols */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <kernel/fut_task.h>

/* Test framework stubs */
void fut_test_plan(int count __attribute__((unused))) {}
void fut_test_pass(void) {}
void fut_test_fail(void) {}
int fut_tests_completed(void) { return 1; }

/* Filesystem stubs - async test (not implemented) */
void fut_futfs_selftest_schedule(struct fut_task *task __attribute__((unused))) {}

/* Note: Framebuffer, PS2, Block register, and Perf stubs are now implemented in their respective source files */

/* kernel/oops.c - Non-fatal kernel error (oops) framework
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides kernel_oops() for logging non-fatal kernel errors with
 * backtrace and register state, without halting the system.
 * The oops counter is exposed via /proc/sys/kernel/oops_count.
 */

#include <kernel/kprintf.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <stdint.h>
#include <stdatomic.h>

#if defined(__x86_64__)
#include <platform/x86_64/memory/paging.h>
#endif

/* Global oops counter — incremented on each kernel_oops() call.
 * Exposed to userspace via /proc/sys/kernel/oops_count (read-only). */
_Atomic uint64_t g_oops_count = 0;

/* External: kernel log buffer write (defined in kernel/sys_syslog.c) */
extern void klog_write(const char *data, size_t len);

/* External: crash task printer (defined in kernel/threading/fut_task.c) */
extern void fut_crash_print_task(void);

/**
 * oops_backtrace - Walk frame pointers and print a stack backtrace.
 *
 * Captures the current RBP and walks the frame pointer chain,
 * printing return addresses for up to @max_frames levels.
 */
static void oops_backtrace(int max_frames) {
#if defined(__x86_64__)
    uint64_t rbp_val;
    __asm__ volatile("mov %%rbp, %0" : "=r"(rbp_val));

    uint64_t *rbp = (uint64_t *)(uintptr_t)rbp_val;
    int frame = 0;

    fut_printf("  Backtrace:\n");

    while (frame < max_frames && rbp != NULL) {
        /* Validate rbp is within kernel address space and aligned */
        if ((uintptr_t)rbp < KERNEL_VIRTUAL_BASE ||
            ((uintptr_t)rbp & 0x7) != 0) {
            break;
        }

        uint64_t ret_addr = rbp[1];    /* Return address at [RBP+8] */
        uint64_t next_rbp = rbp[0];    /* Saved RBP at [RBP+0] */

        if (ret_addr == 0)
            break;

        fut_printf("    #%d  0x%016llx\n", frame, (unsigned long long)ret_addr);
        frame++;

        /* Detect cycles or backward movement */
        if (next_rbp == 0 || (uint64_t *)(uintptr_t)next_rbp <= rbp)
            break;

        rbp = (uint64_t *)(uintptr_t)next_rbp;
    }

    if (frame == 0) {
        fut_printf("    <no frame pointer chain available>\n");
    }
#else
    (void)max_frames;
    fut_printf("    <backtrace not available on this architecture>\n");
#endif
}

/**
 * kernel_oops - Report a non-fatal kernel error.
 *
 * @msg: Human-readable description of the oops condition.
 *
 * Unlike panic(), kernel_oops() does NOT halt the system. It:
 *   1. Increments the global oops counter (atomic).
 *   2. Prints the oops message, current task info, and a backtrace
 *      to the serial console and kernel log buffer.
 *   3. Returns to the caller so execution can continue.
 *
 * The oops count is readable from /proc/sys/kernel/oops_count.
 */
void kernel_oops(const char *msg) {
    uint64_t count = atomic_fetch_add_explicit(&g_oops_count, 1, memory_order_relaxed) + 1;

    fut_printf("\n");
    fut_printf("========================================\n");
    fut_printf("  KERNEL OOPS #%llu\n", (unsigned long long)count);
    fut_printf("========================================\n");
    fut_printf("  %s\n", msg ? msg : "(no message)");

    /* Print current task context */
    fut_crash_print_task();

    /* Print backtrace from the oops call site */
    oops_backtrace(16);

    fut_printf("========================================\n");
    fut_printf("\n");

    /* The message is already in the kernel log buffer via fut_printf/klog_write.
     * dmesg(1) and /dev/kmsg consumers will see the oops output. */
}

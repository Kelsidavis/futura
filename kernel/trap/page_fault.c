// SPDX-License-Identifier: MPL-2.0
/*
 * page_fault.c - Page fault handling helpers
 */

#include "../../include/kernel/trap.h"

#include "../../include/kernel/uaccess.h"
#include "../../include/kernel/errno.h"
#include "../../include/kernel/fut_task.h"
#include "../../include/kernel/signal.h"

#ifdef __x86_64__
#include <arch/x86_64/regs.h>
#endif

#include <stdbool.h>
#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

#ifdef __x86_64__

bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    const uint64_t fault_addr = fut_read_cr2();
    const struct fut_uaccess_window *window = fut_uaccess_window_current();

    if (window && window->resume && window->length != 0) {
        const uintptr_t start = (uintptr_t)window->user_ptr;
        const uintptr_t end = start + window->length;
        if (fault_addr >= start && fault_addr < end) {
            fut_uaccess_window_fault(-EFAULT);
            frame->rip = (uint64_t)window->resume;
            frame->rax = (uint64_t)(-EFAULT);
            return true;
        }
    }

    if ((frame->cs & 0x3u) != 0) {
        fut_printf("[#PF] user fault addr=0x%016llx err=0x%llx rip=0x%016llx\n",
                   (unsigned long long)fault_addr,
                   (unsigned long long)frame->error_code,
                   (unsigned long long)frame->rip);
        fut_task_signal_exit(SIGSEGV);
    }

    return false;
}

#elif defined(__aarch64__)

/* ARM64 page fault handler stub - not yet implemented */
bool fut_trap_handle_page_fault(fut_interrupt_frame_t *frame) {
    (void)frame;
    return false;
}

#else
#error "Unsupported architecture for page fault handling"
#endif

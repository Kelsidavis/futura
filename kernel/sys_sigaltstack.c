/* kernel/sys_sigaltstack.c - Set/get signal alternate stack
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements sigaltstack() to set up or query signal handler alternate stack.
 * Critical for handling signals on full stacks or in memory-constrained environments.
 */

#include <kernel/fut_task.h>
#include <kernel/signal.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>

#include <kernel/kprintf.h>
extern fut_task_t *fut_task_current(void);

/**
 * sigaltstack() - Set/get signal handler alternate stack
 *
 * Establishes an alternate stack for signal handlers, allowing signals to be
 * delivered even when the normal stack is exhausted. Critical for applications
 * that need to handle stack overflow conditions or use large amounts of stack
 * space in the main execution flow.
 *
 * The alternate stack is typically used for handling SIGSTACK or other
 * signals when the normal stack is full. Without an alternate stack, a
 * stack overflow condition cannot be recovered.
 *
 * @param ss     Pointer to new stack definition (may be NULL to query only)
 * @param old_ss Pointer to receive old stack definition (may be NULL)
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if no current task context
 *   - -EFAULT if ss or old_ss points to invalid memory
 *   - -EINVAL if ss_size is too small (< MINSIGSTKSZ)
 *   - -EINVAL if ss_flags has invalid flags
 *
 * Behavior:
 *   1. If ss != NULL:
 *      - Validate ss_size >= MINSIGSTKSZ (minimum 4096 bytes)
 *      - Validate ss_sp pointer alignment (16-byte recommended)
 *      - Validate ss_flags (only SS_DISABLE and SS_ONSTACK valid)
 *      - Store ss in current task's sig_altstack
 *   2. If old_ss != NULL:
 *      - Return current alternate stack to user
 *   3. Does not modify signal mask or pending signals
 *
 * Stack architecture:
 *   - Signal handlers run on designated alternate stack if set
 *   - Normal stack exhaustion can still occur in handler (handler's responsibility)
 *   - SS_DISABLE disables the alternate stack
 *   - SS_ONSTACK indicates we're currently executing on alternate stack
 *
 * Typical usage patterns:
 *
 * Establish alternate stack for SIGSEGV handling:
 *   char alt_stack[SIGSTKSZ];
 *   stack_t ss, oss;
 *
 *   ss.ss_sp = (void *)alt_stack;
 *   ss.ss_size = SIGSTKSZ;
 *   ss.ss_flags = 0;  // Not disabled initially
 *
 *   sigaltstack(&ss, &oss);
 *
 *   signal(SIGSEGV, stack_overflow_handler);
 *
 * Query current alternate stack:
 *   stack_t current;
 *   sigaltstack(NULL, &current);
 *   printf("Alternate stack: %p, size: %zu\\n",
 *          current.ss_sp, current.ss_size);
 *
 * Disable alternate stack:
 *   stack_t ss;
 *   ss.ss_flags = SS_DISABLE;
 *   sigaltstack(&ss, NULL);
 *
 * Relationship with other signal functions:
 *   - sigaltstack(): Establish alternate signal stack
 *   - sigaction(): Install signal handlers (can specify SA_ONSTACK)
 *   - sigprocmask(): Change signal mask
 *   - sigsuspend(): Atomically change mask and wait
 *
 * MINSIGSTKSZ (typical 4096):
 *   Minimum stack size for signal handlers. Must be large enough for:
 *   - Handler entry/exit code
 *   - Local variables
 *   - Library function calls (printf, etc.)
 *   - System calls from handler
 *
 * Stack usage pattern:
 *   Normal thread stack:        Alternate signal stack:
 *   ┌─────────────────────┐    ┌──────────────────────┐
 *   │ Thread code         │    │ Dedicated space      │
 *   │ (app execution)     │    │ for signal handlers  │
 *   │ ... grows down      │    │ (size: SIGSTKSZ)     │
 *   │ │                   │    │ (separate from main) │
 *   │ ▼                   │    │                      │
 *   │ (stack exhausted)   │    │ Allocated by app     │
 *   └─────────────────────┘    │ Not managed by OS    │
 *                              └──────────────────────┘
 *
 * If normal stack is full, signal cannot be delivered unless
 * alternate stack is available (handler runs on separate stack).
 *
 * Implementation notes:
 *   - Phase 1: Store ss/old_ss with validation
 *   - Phase 2: Signal delivery integration (use alt stack in signal.c)
 *   - Phase 3: Stack pointer selection in rt_sigframe creation
 *   - Atomicity: Not required (only one thread per task in this implementation)
 */
long sys_sigaltstack(const struct sigaltstack *ss, struct sigaltstack *old_ss) {
    fut_task_t *current = fut_task_current();

    if (!current) {
        fut_printf("[SIGALTSTACK] sigaltstack(ss=%p, old_ss=%p) -> EINVAL (no current task)\n", ss, old_ss);
        return -EINVAL;
    }

    /* Copy old stack to user if requested */
    if (old_ss) {
        if (fut_copy_to_user(old_ss, &current->sig_altstack, sizeof(struct sigaltstack)) != 0) {
            fut_printf("[SIGALTSTACK] sigaltstack -> EFAULT (invalid old_ss pointer)\n");
            return -EFAULT;
        }
    }

    /* If new stack specified, validate and install it */
    if (ss) {
        struct sigaltstack new_stack;

        /* Copy new stack from userspace */
        if (fut_copy_from_user(&new_stack, ss, sizeof(struct sigaltstack)) != 0) {
            fut_printf("[SIGALTSTACK] sigaltstack(ss=%p) -> EFAULT (invalid ss pointer)\n", ss);
            return -EFAULT;
        }

        /* Validate flags */
        if (new_stack.ss_flags & ~(SS_DISABLE | SS_ONSTACK)) {
            fut_printf("[SIGALTSTACK] sigaltstack(flags=0x%x) -> EINVAL (invalid flags)\n",
                      new_stack.ss_flags);
            return -EINVAL;
        }

        /* Validate size if not disabled */
        if (!(new_stack.ss_flags & SS_DISABLE)) {
            if (new_stack.ss_size < MINSIGSTKSZ) {
                fut_printf("[SIGALTSTACK] sigaltstack(size=%zu) -> EINVAL (size < MINSIGSTKSZ=%u)\n",
                          new_stack.ss_size, MINSIGSTKSZ);
                return -EINVAL;
            }

            /* Validate pointer is not NULL */
            if (!new_stack.ss_sp) {
                fut_printf("[SIGALTSTACK] sigaltstack(ss_sp=NULL) -> EINVAL (null stack pointer)\n");
                return -EINVAL;
            }
        }

        /* Install new stack */
        current->sig_altstack = new_stack;

        fut_printf("[SIGALTSTACK] sigaltstack(ss=%p, size=%zu, flags=0x%x) -> 0 (pid=%u)\n",
                  new_stack.ss_sp, new_stack.ss_size, new_stack.ss_flags, current->pid);
    } else {
        fut_printf("[SIGALTSTACK] sigaltstack(NULL, old_ss=%p) -> 0 (query, pid=%u)\n",
                  old_ss, current->pid);
    }

    return 0;
}

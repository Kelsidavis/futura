/* kernel/sys_ptrace.c - ptrace() stub
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a minimal ptrace() stub. Futura does not support process
 * tracing; this stub returns EPERM for all operations except
 * PTRACE_TRACEME (which returns 0 so debugger-launched children do not
 * abort before execve).
 */

#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/* PTRACE_TRACEME: child requests to be traced (Linux 0). */
#define PTRACE_TRACEME  0
/* PTRACE_ATTACH: attach to a running process (Linux 16). */
#define PTRACE_ATTACH   16
/* PTRACE_SEIZE: seize process without stopping it (Linux 16902). */
#define PTRACE_SEIZE    16902

/**
 * sys_ptrace - Process tracing (stub)
 *
 * @param request  ptrace operation (PTRACE_TRACEME, PTRACE_PEEKDATA, …)
 * @param pid      Target PID
 * @param addr     Address argument (operation-specific)
 * @param data     Data argument (operation-specific)
 *
 * Returns:
 *   0        for PTRACE_TRACEME (let the child proceed; actual attach fails)
 *  -EPERM    for all other operations (ptrace not supported)
 */
long sys_ptrace(int request, int pid, void *addr, void *data) {
    (void)pid; (void)addr; (void)data;

    if (request == PTRACE_TRACEME) {
        /* Called by a child to request tracing by its parent.
         * Return 0 so gdb/sanitizer-launched children don't crash immediately;
         * the actual PTRACE_ATTACH from the parent will return EPERM. */
        return 0;
    }
    return -EPERM;
}

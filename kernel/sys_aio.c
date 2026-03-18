/* kernel/sys_aio.c - Linux AIO syscall stubs
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Stub implementations for the Linux Asynchronous I/O interface (libaio).
 * These syscalls return -ENOSYS so that libaio-based applications (e.g.
 * PostgreSQL, MySQL) receive a clean fallback to synchronous I/O.
 *
 * Syscall numbers (Linux x86_64):
 *   io_setup         206
 *   io_destroy       207
 *   io_getevents     208
 *   io_submit        209
 *   io_cancel        210
 *
 * A real implementation would require a per-context completion ring
 * (aio_context_t), worker threads or interrupt-driven completion, and
 * shared-memory event notification.  That infrastructure is deferred.
 */

#include <kernel/errno.h>
#include <stdint.h>
#include <stddef.h>

/**
 * io_setup() - Initialize an AIO context.
 * @nr_events: Maximum number of in-flight requests.
 * @ctxp:      User pointer to store the context handle.
 * Returns -ENOSYS; callers fall back to synchronous I/O.
 */
long sys_io_setup(unsigned int nr_events, void *ctxp) {
    (void)nr_events; (void)ctxp;
    return -ENOSYS;
}

/**
 * io_destroy() - Release an AIO context.
 * @ctx_id: Context handle returned by io_setup().
 * Returns -ENOSYS.
 */
long sys_io_destroy(unsigned long ctx_id) {
    (void)ctx_id;
    return -ENOSYS;
}

/**
 * io_getevents() - Retrieve completed AIO events.
 * Returns -ENOSYS.
 */
long sys_io_getevents(unsigned long ctx_id, long min_nr, long nr,
                      void *events, const void *timeout) {
    (void)ctx_id; (void)min_nr; (void)nr; (void)events; (void)timeout;
    return -ENOSYS;
}

/**
 * io_submit() - Submit AIO requests.
 * Returns -ENOSYS.
 */
long sys_io_submit(unsigned long ctx_id, long nr, void **iocbpp) {
    (void)ctx_id; (void)nr; (void)iocbpp;
    return -ENOSYS;
}

/**
 * io_cancel() - Cancel an in-flight AIO request.
 * Returns -ENOSYS.
 */
long sys_io_cancel(unsigned long ctx_id, void *iocb, void *result) {
    (void)ctx_id; (void)iocb; (void)result;
    return -ENOSYS;
}

/**
 * io_uring_setup() - Set up an io_uring submission/completion queue pair.
 * Returns -ENOSYS; callers (tokio, liburing, curl) fall back to epoll/poll.
 */
long sys_io_uring_setup(unsigned int entries, void *params) {
    (void)entries; (void)params;
    return -ENOSYS;
}

/**
 * io_uring_enter() - Submit and/or wait for completions on an io_uring fd.
 * Returns -ENOSYS.
 */
long sys_io_uring_enter(unsigned int fd, unsigned int to_submit,
                        unsigned int min_complete, unsigned int flags,
                        const void *sig, size_t sigsz) {
    (void)fd; (void)to_submit; (void)min_complete;
    (void)flags; (void)sig; (void)sigsz;
    return -ENOSYS;
}

/**
 * io_uring_register() - Register buffers/files with an io_uring instance.
 * Returns -ENOSYS.
 */
long sys_io_uring_register(unsigned int fd, unsigned int opcode,
                           void *arg, unsigned int nr_args) {
    (void)fd; (void)opcode; (void)arg; (void)nr_args;
    return -ENOSYS;
}

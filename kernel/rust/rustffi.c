// SPDX-License-Identifier: MPL-2.0
/*
 * rustffi.c - Kernel wrappers exposed to Rust drivers
 */

#include <futura/rustffi.h>

#include <kernel/fut_memory.h>

int memcmp(const void *lhs, const void *rhs, size_t n);

extern void fut_printf(const char *fmt, ...);

void fut_log(const char *msg) {
    if (!msg) {
        return;
    }
    fut_printf("%s\n", msg);
}

void *fut_alloc(size_t size) {
    if (size == 0) {
        return NULL;
    }
    return fut_malloc(size);
}

int bcmp(const void *lhs, const void *rhs, size_t n) {
    return memcmp(lhs, rhs, n);
}

void rust_eh_personality(void) {
    /* Abort-only panic handler does not unwind. */
}

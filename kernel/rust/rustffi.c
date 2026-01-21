// SPDX-License-Identifier: MPL-2.0
/*
 * rustffi.c - Kernel wrappers exposed to Rust drivers
 */

#include <futura/rustffi.h>

#include <kernel/fut_memory.h>

int memcmp(const void *lhs, const void *rhs, size_t n);

#include <kernel/kprintf.h>

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

/* getauxval stub for Rust compiler-builtins on ARM64 */
unsigned long getauxval(unsigned long type) {
    (void)type;
    return 0;  /* Disable CPU feature detection */
}

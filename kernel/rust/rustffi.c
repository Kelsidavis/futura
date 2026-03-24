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
    /* Suppress verbose Rust driver init messages for clean boot.
     * Keep errors and final "initialized OK" / "successful" messages. */
    if ((msg[0] == 'v' && msg[1] == 'i' && msg[2] == 'r' && msg[3] == 't') ||
        (msg[0] == '[' && msg[1] == 'V' && msg[2] == 'I' && msg[3] == 'N')) {
        const char *p = msg;
        int is_important = 0;
        while (*p) {
            if ((*p == 'E' || *p == 'e') && p[1] == 'r' && p[2] == 'r') { is_important = 1; break; }
            if ((*p == 'F' || *p == 'f') && p[1] == 'a' && p[2] == 'i' && p[3] == 'l' && p[4] == 'e' && p[5] == 'd') {
                /* Suppress "registration failed" (expected with empty disk) */
                const char *q = msg;
                int is_reg = 0;
                while (*q) { if (*q == 'r' && q[1] == 'e' && q[2] == 'g') { is_reg = 1; break; } q++; }
                if (!is_reg) { is_important = 1; break; }
                break;  /* Skip "registration failed" */
            }
            if (*p == 'O' && p[1] == 'K') { is_important = 1; break; }
            if (*p == 's' && p[1] == 'u' && p[2] == 'c' && p[3] == 'c') { is_important = 1; break; }
            p++;
        }
        if (!is_important) return;
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

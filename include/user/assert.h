// SPDX-License-Identifier: MPL-2.0
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Glibc-compatible name so third-party code that pulls in <assert.h>
 * for assert(...) and links via libfutura.a finds the same symbol it
 * would on Linux. */
__attribute__((noreturn))
void __assert_fail(const char *expr, const char *file,
                   unsigned int line, const char *func);

#ifdef __cplusplus
}
#endif

#ifdef NDEBUG
#  define assert(expr) ((void)0)
#else
#  define assert(expr) \
    ((expr) ? (void)0 : __assert_fail(#expr, __FILE__, __LINE__, __func__))
#endif

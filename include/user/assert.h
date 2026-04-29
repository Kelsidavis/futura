// SPDX-License-Identifier: MPL-2.0
#pragma once

#ifdef NDEBUG
#  define assert(expr) ((void)0)
#else
#  define assert(expr) \
    ((expr) ? (void)0 : __futura_assert_fail(#expr, __FILE__, __LINE__, __func__))

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((noreturn))
void __futura_assert_fail(const char *expr, const char *file, int line, const char *func);
#ifdef __cplusplus
}
#endif
#endif

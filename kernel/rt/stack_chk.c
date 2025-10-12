// SPDX-License-Identifier: MPL-2.0
/*
 * Futura OS - Minimal stack protector stubs for freestanding kernel builds.
 *
 * The compiler may emit calls to __stack_chk_fail when stack protection is
 * enabled (either explicitly or via toolchain defaults). Provide a kernel-side
 * implementation so freestanding links do not pull in libc.
 */

#include <platform/platform.h>

__attribute__((noreturn)) void __stack_chk_fail(void)
{
    fut_platform_panic("__stack_chk_fail");

    /* Fallback guard in case panic returns unexpectedly. */
    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
}

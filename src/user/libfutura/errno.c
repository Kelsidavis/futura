// SPDX-License-Identifier: MPL-2.0

#include <user/errno.h>

static int __fut_errno_storage;

int *__errno_location(void) {
    return &__fut_errno_storage;
}

#if defined(__GNUC__) && !defined(__APPLE__)
__asm__(".symver __errno_location,__errno_location@GLIBC_2.2.5");
#endif

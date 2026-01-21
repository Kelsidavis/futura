// SPDX-License-Identifier: MPL-2.0
/*
 * sys/un.h - Unix domain socket address
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides sockaddr_un for Unix domain socket addresses.
 */

#pragma once

/* In hosted environment with system headers available, use them */
#if defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1 && __has_include_next(<sys/un.h>)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include_next <sys/un.h>
#pragma GCC diagnostic pop
#else

#include <stdint.h>

/* Unix domain socket address */
#ifndef _STRUCT_SOCKADDR_UN
#define _STRUCT_SOCKADDR_UN
struct sockaddr_un {
    uint16_t sun_family;        /* AF_UNIX */
    char     sun_path[108];     /* Pathname */
};
#endif

/* Helper macro for socket address length */
#ifndef SUN_LEN
#define SUN_LEN(su) \
    (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#endif /* !has_include_next */

// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sockaddr_un {
    sa_family_t sun_family;
    char        sun_path[108];
};

#ifdef __cplusplus
}
#endif

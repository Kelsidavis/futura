// SPDX-License-Identifier: MPL-2.0
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

int flock(int fd, int operation);

#ifdef __cplusplus
}
#endif

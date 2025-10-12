// SPDX-License-Identifier: MPL-2.0
/*
 * rustffi.h - C ↔ Rust interoperability surface
 *
 * Provides the minimal kernel entry points that Rust drivers rely on for
 * logging, memory allocation, and blkcore registration.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <futura/blkdev.h>
#include <kernel/fut_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

void fut_log(const char *msg);
void *fut_alloc(size_t size);
void fut_free(void *ptr);

#ifdef __cplusplus
}
#endif

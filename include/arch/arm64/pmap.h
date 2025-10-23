/* pmap.h - ARM64 Physical Memory Mapping (stub for x86_64 compatibility)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Stub for ARM64 to provide minimal pmap interface matching x86_64
 */

#pragma once

#include <arch/arm64/paging.h>
#include <stdint.h>

typedef uint64_t phys_addr_t;

/* Stub function declarations matching x86_64/pmap.h */
int pmap_map_user(struct fut_vmem_context *ctx, uint64_t uaddr, phys_addr_t paddr,
                  uint64_t size, uint64_t flags);

#endif

/* apple_dart.h - Apple DART IOMMU C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * C declarations for the Rust DART IOMMU driver (drivers/rust/apple_dart).
 */

#ifndef __FUTURA_APPLE_DART_H__
#define __FUTURA_APPLE_DART_H__

#include <stdint.h>

/* Protection flags */
#define DART_PROT_READ   (1 << 0)
#define DART_PROT_WRITE  (1 << 1)
#define DART_PROT_EXEC   (1 << 2)

/* Opaque DART handle */
typedef struct AppleDart AppleDart;

/**
 * Initialize the Apple DART IOMMU.
 * @param base: MMIO base address
 * @param num_streams: number of DMA streams (1-16)
 * @param variant: 0 = T8020 (M1/M2), 1 = T8110 (M1 Pro/Max)
 * @return: non-null handle on success, NULL on failure
 */
AppleDart *rust_dart_init(uint64_t base, uint32_t num_streams, uint32_t variant);

/** Release DART resources. */
void rust_dart_free(AppleDart *dart);

/** Enable IOVA translation for stream. Returns 0 on success. */
int32_t rust_dart_enable_stream(AppleDart *dart, uint32_t sid);

/** Disable translation for stream (restore bypass). Returns 0 on success. */
int32_t rust_dart_disable_stream(AppleDart *dart, uint32_t sid);

/**
 * Map physical address into IOVA space.
 * @param dart: DART handle
 * @param sid: stream ID
 * @param iova: device-visible virtual address
 * @param paddr: physical address
 * @param len: mapping length in bytes
 * @param prot: DART_PROT_* bitmask
 * @return: 0 on success, negative errno on failure
 */
int32_t rust_dart_map(AppleDart *dart, uint32_t sid, uint64_t iova,
                      uint64_t paddr, uint64_t len, uint32_t prot);

/** Unmap IOVA region. Returns 0 on success. */
int32_t rust_dart_unmap(AppleDart *dart, uint32_t sid, uint64_t iova, uint64_t len);

/** Translate IOVA to physical address. Returns 0 if not mapped. */
uint64_t rust_dart_iova_to_phys(const AppleDart *dart, uint32_t sid, uint64_t iova);

/** Flush all TLB entries. */
void rust_dart_flush_tlb_all(const AppleDart *dart);

/** Flush TLB entries for a specific stream. */
void rust_dart_flush_tlb_stream(const AppleDart *dart, uint32_t sid);

#endif /* __FUTURA_APPLE_DART_H__ */

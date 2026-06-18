/* apple_ans2.h - Apple ANS2 NVMe Controller Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple ANS2 (Apple NVMe Storage) controller for M1/M2/M3 SoCs.
 * Based on Linux kernel driver by Sven Peter and Asahi Linux contributors.
 *
 * The actual driver (NVMMU + TCB programming, admin / IO queues,
 * doorbells, IDENTIFY parsing, polled READ/WRITE state machine, the
 * per-message RTKit handler) lives in drivers/rust/apple_ans2.  This
 * header exposes the Rust FFI surface plus the single C platform
 * entry point used by platform_init.c.
 *
 * Key differences from standard NVMe:
 * - Not PCIe-attached (embedded in SoC)
 * - Requires RTKit co-processor communication
 * - Uses NVMMU (NVMe MMU) with TCBs for all commands
 * - Limited to 64 total tags (admin + I/O combined)
 * - Single admin queue + single I/O queue
 */

#ifndef __FUTURA_ARM64_APPLE_ANS2_H__
#define __FUTURA_ARM64_APPLE_ANS2_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* ============================================================
 *   Platform Integration
 * ============================================================ */

/**
 * Platform integration: initialise Apple ANS2 NVMe.
 * High-level entry point called from platform_init.c.  Gates on
 * info->has_aic so non-Apple ARM64 builds (RPi / QEMU virt) skip
 * straight through.
 * @param info: Platform information
 * @return: true on success, false on failure or not-applicable
 */
bool fut_apple_ans2_platform_init(const fut_platform_info_t *info);

/* ============================================================
 *   Public C I/O API
 *
 * Reachable wrappers over the retained controller handle.  All return
 * a sentinel (-1 / false / 0) when the controller never initialised,
 * which is the case on every non-Apple ARM64 boot.  On Apple hardware
 * the namespace is also published to the generic block layer as
 * "nvme0" once IDENTIFY completes, so most callers go through
 * fut_blockdev_* instead of these directly.
 * ============================================================ */

/** Read @count sectors from @lba into @buf.  Returns sectors-read, or
 *  -1 on error / uninitialised / NULL buffer. */
int apple_ans2_read(uint64_t lba, uint32_t count, void *buf);

/** Write @count sectors from @buf to @lba.  Returns sectors-written,
 *  or -1 on error / uninitialised / NULL buffer. */
int apple_ans2_write(uint64_t lba, uint32_t count, const void *buf);

/** True once the controller has reset and identified its namespace. */
bool apple_ans2_is_ready(void);

/** Maximum LBA, or 0 when uninitialised / not yet identified. */
uint64_t apple_ans2_max_lba(void);

/** Logical sector size in bytes, or 0 when uninitialised. */
uint32_t apple_ans2_sector_size(void);

/** Pump the RTKit RX FIFO so in-flight completions are dispatched. */
void apple_ans2_poll(void);

/* ============================================================
 *   Rust driver FFI (drivers/rust/apple_ans2)
 * ============================================================ */

typedef struct Ans2Ctrl Ans2Ctrl;

/** Allocate and initialise ANS2 controller at @mmio_base with RTKit
 *  mailbox at @mailbox_base.  Returns non-null on success, null on failure. */
Ans2Ctrl *rust_ans2_init(uint64_t mmio_base, uint64_t mailbox_base);

/** Free an Ans2Ctrl previously returned by rust_ans2_init. */
void rust_ans2_free(Ans2Ctrl *ctrl);

/** Read @count sectors from @lba into @buf.
 *  Returns sectors-read on success, -1 on error. */
int rust_ans2_read(Ans2Ctrl *ctrl, uint64_t lba, uint32_t count, uint8_t *buf);

/** Write @count sectors from @buf to @lba.
 *  Returns sectors-written on success, -1 on error. */
int rust_ans2_write(Ans2Ctrl *ctrl, uint64_t lba, uint32_t count, const uint8_t *buf);

/** Returns 1 if the controller initialised successfully. */
int rust_ans2_is_ready(const Ans2Ctrl *ctrl);

/** Return the maximum LBA (0 if not yet identified). */
uint64_t rust_ans2_max_lba(const Ans2Ctrl *ctrl);

/** Return the logical sector size in bytes (0 if not yet identified). */
uint32_t rust_ans2_sector_size(const Ans2Ctrl *ctrl);

/** Poll the RTKit RX FIFO and dispatch pending ANS2 messages. */
void rust_ans2_poll(Ans2Ctrl *ctrl);

#endif /* __FUTURA_ARM64_APPLE_ANS2_H__ */

/* apple_ans2.c - Apple ANS2 NVMe controller — Rust-backed wrapper
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple's ANS2 (Apple NVMe Storage) controller is an embedded NVMe
 * variant on M1/M2/M3 SoCs that talks to the AP through a co-processor
 * over RTKit IPC.  The full driver — NVMMU + TCB programming, admin
 * and I/O submission/completion queues, doorbell management, tag
 * allocation, IDENTIFY parsing, polled READ/WRITE state machine, and
 * the per-message RTKit handler — lives in the Rust apple_ans2 crate
 * under drivers/rust/apple_ans2.  This C file is now a thin glue
 * layer that:
 *
 *   1. Extracts the ans_nvme_base and ans_mailbox_base addresses
 *      from the platform DTB info struct.
 *   2. Hands them to rust_ans2_init(), which internally builds the
 *      RTKit context via rust_rtkit_init/boot/register_handler/
 *      start_endpoint, then performs the NVMe controller reset and
 *      queue setup.
 *   3. Logs ready state + namespace capacity.
 *
 * Compat note: fut_apple_ans2_platform_init() gates on
 * info->has_aic so RPi / QEMU virt boots (which leave has_aic = false)
 * never reach the Rust ANS2 driver.
 */

#include <platform/arm64/apple_ans2.h>
#include <platform/platform.h>

bool fut_apple_ans2_platform_init(const fut_platform_info_t *info) {
    if (!info || !info->has_aic) {
        return false;
    }
    if (info->ans_nvme_base == 0 || info->ans_mailbox_base == 0) {
        /* DTB parsing has not surfaced the ANS2 MMIO / mailbox bases
         * yet — driver stays probed-but-inactive, same behaviour as
         * the original C path when these were zero. */
        fut_printf("[ANS2] ANS2 base addresses not configured in DTB\n");
        return false;
    }

    Ans2Ctrl *ctrl = rust_ans2_init(info->ans_nvme_base,
                                     info->ans_mailbox_base);
    if (!ctrl) {
        fut_printf("[ANS2] rust_ans2_init(nvme=0x%lx, mbox=0x%lx) failed\n",
                   (unsigned long)info->ans_nvme_base,
                   (unsigned long)info->ans_mailbox_base);
        return false;
    }

    if (rust_ans2_is_ready(ctrl)) {
        fut_printf("[ANS2] Ready: max_lba=%lu sector_size=%u\n",
                   (unsigned long)rust_ans2_max_lba(ctrl),
                   (unsigned int)rust_ans2_sector_size(ctrl));
    } else {
        fut_printf("[ANS2] Controller initialised, identify pending\n");
    }
    return true;
}

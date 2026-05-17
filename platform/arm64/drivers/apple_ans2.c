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
#include <platform/arm64/apple_pmgr.h>
#include <platform/arm64/memory/pmap.h>
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

    /* Pull ANS2 out of pmgr reset / clock-gate via the DT
     * power-domains property + phandle resolution.  Asahi DTBs list
     * the ANS2 / NVMe-host / SART domains under /soc/ans@…. Skipped
     * if pmgr isn't up or DT doesn't carry power-domains for ANS2
     * (m1n1 usually already deasserted reset). */
    extern uint64_t fut_platform_get_dtb(void);
    uint64_t dtb = fut_platform_get_dtb();
    if (dtb != 0) {
        static const char *const ans_paths[] = {
            "/soc/ans@27bcc4000",
            "/soc/ans",
            "/arm-io/ans",
            NULL,
        };
        for (int i = 0; ans_paths[i]; i++) {
            int rc = apple_pmgr_enable_domains_for(dtb, ans_paths[i]);
            if (rc > 0) {
                fut_printf("[ANS2] pmgr: %d domains enabled via %s\n",
                           rc, ans_paths[i]);
                break;
            }
        }
    }

    /* Convert peripheral PAs to kernel VAs through boot.S's
     * kernel_l1[8..15] mapping window — the Rust crate reads MMIO
     * via raw read_volatile and would translation-fault on the PA. */
    uint64_t nvme_va = fut_kernel_peripheral_va(info->ans_nvme_base);
    uint64_t mbox_va = fut_kernel_peripheral_va(info->ans_mailbox_base);

    Ans2Ctrl *ctrl = rust_ans2_init(nvme_va, mbox_va);
    if (!ctrl) {
        fut_printf("[ANS2] rust_ans2_init(nvme=PA 0x%lx VA 0x%lx, "
                   "mbox=PA 0x%lx VA 0x%lx) failed\n",
                   (unsigned long)info->ans_nvme_base, (unsigned long)nvme_va,
                   (unsigned long)info->ans_mailbox_base, (unsigned long)mbox_va);
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

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
 * under drivers/rust/apple_ans2.  This C file is the glue layer that:
 *
 *   1. Extracts the ans_nvme_base and ans_mailbox_base addresses
 *      from the platform DTB info struct.
 *   2. Hands them to rust_ans2_init(), which internally builds the
 *      RTKit context via rust_rtkit_init/boot/register_handler/
 *      start_endpoint, then performs the NVMe controller reset and
 *      queue setup.
 *   3. Retains the controller handle so the polled READ/WRITE path is
 *      reachable, exposes a public C I/O API (apple_ans2_read/write/…),
 *      and — once the controller has identified its namespace —
 *      registers it with the generic block layer so the disk is
 *      mountable as "nvme0".
 *
 * Compat note: fut_apple_ans2_platform_init() gates on
 * info->has_aic so RPi / QEMU virt boots (which leave has_aic = false)
 * never reach the Rust ANS2 driver.
 */

#include <platform/arm64/apple_ans2.h>
#include <platform/arm64/apple_pmgr.h>
#include <platform/arm64/memory/pmap.h>
#include <platform/platform.h>
#include <kernel/fut_blockdev.h>
#include <string.h>

/* C-side state — the controller handle (previously dropped on the
 * stack, which made every read/write/poll entry point unreachable and
 * leaked the Rust allocation) plus the block-device node we publish. */
static struct {
    Ans2Ctrl          *ctrl;
    struct fut_blockdev blockdev;
    bool               registered;
} g_ans2;

/* ============================================================
 *   Public C I/O API
 *
 * Thin guards over the Rust polled state machine.  All refuse with a
 * sentinel when the controller never came up (g_ans2.ctrl == NULL),
 * which is the case on every non-Apple ARM64 boot.
 * ============================================================ */

int apple_ans2_read(uint64_t lba, uint32_t count, void *buf)
{
    if (!g_ans2.ctrl || !buf || count == 0) return -1;
    return rust_ans2_read(g_ans2.ctrl, lba, count, (uint8_t *)buf);
}

int apple_ans2_write(uint64_t lba, uint32_t count, const void *buf)
{
    if (!g_ans2.ctrl || !buf || count == 0) return -1;
    return rust_ans2_write(g_ans2.ctrl, lba, count, (const uint8_t *)buf);
}

bool apple_ans2_is_ready(void)
{
    if (!g_ans2.ctrl) return false;
    return rust_ans2_is_ready(g_ans2.ctrl) != 0;
}

uint64_t apple_ans2_max_lba(void)
{
    if (!g_ans2.ctrl) return 0;
    return rust_ans2_max_lba(g_ans2.ctrl);
}

uint32_t apple_ans2_sector_size(void)
{
    if (!g_ans2.ctrl) return 0;
    return rust_ans2_sector_size(g_ans2.ctrl);
}

void apple_ans2_poll(void)
{
    if (!g_ans2.ctrl) return;
    rust_ans2_poll(g_ans2.ctrl);
}

/* ============================================================
 *   Generic block-layer ops
 *
 * The Rust READ/WRITE primitives return sectors-transferred (or -1);
 * the block layer wants 0 on full success / negative errno, so map
 * a short transfer to BLOCKDEV_EIO.
 * ============================================================ */

static int ans2_bd_read(struct fut_blockdev *dev, uint64_t block_num,
                        uint64_t num_blocks, void *buffer)
{
    (void)dev;
    if (!g_ans2.ctrl || !buffer || num_blocks == 0) return BLOCKDEV_EINVAL;
    if (num_blocks > 0xFFFFFFFFull) return BLOCKDEV_EINVAL;
    int rc = rust_ans2_read(g_ans2.ctrl, block_num,
                            (uint32_t)num_blocks, (uint8_t *)buffer);
    return (rc == (int)num_blocks) ? 0 : BLOCKDEV_EIO;
}

static int ans2_bd_write(struct fut_blockdev *dev, uint64_t block_num,
                         uint64_t num_blocks, const void *buffer)
{
    (void)dev;
    if (!g_ans2.ctrl || !buffer || num_blocks == 0) return BLOCKDEV_EINVAL;
    if (num_blocks > 0xFFFFFFFFull) return BLOCKDEV_EINVAL;
    int rc = rust_ans2_write(g_ans2.ctrl, block_num,
                             (uint32_t)num_blocks, (const uint8_t *)buffer);
    return (rc == (int)num_blocks) ? 0 : BLOCKDEV_EIO;
}

static int ans2_bd_flush(struct fut_blockdev *dev)
{
    /* The polled command path waits for each command's completion
     * before returning, so there is no write-back cache to drain. */
    (void)dev;
    return 0;
}

static const struct fut_blockdev_ops g_ans2_blockdev_ops = {
    .read    = ans2_bd_read,
    .write   = ans2_bd_write,
    .flush   = ans2_bd_flush,
    .get_info = NULL,
};

/* Publish the identified namespace to the block layer.  Idempotent —
 * a second call (e.g. re-probe) is a no-op once registered. */
static void ans2_register_blockdev(void)
{
    if (g_ans2.registered) return;

    uint32_t sec     = rust_ans2_sector_size(g_ans2.ctrl);
    uint64_t max_lba = rust_ans2_max_lba(g_ans2.ctrl);
    if (sec == 0 || max_lba == 0) return;  /* identify not complete */

    memset(&g_ans2.blockdev, 0, sizeof(g_ans2.blockdev));
    memcpy(g_ans2.blockdev.name, "nvme0", sizeof("nvme0"));  /* incl. NUL */
    g_ans2.blockdev.type       = BLOCKDEV_NVME;
    g_ans2.blockdev.block_size = sec;
    g_ans2.blockdev.num_blocks = max_lba + 1;       /* LBA is inclusive */
    g_ans2.blockdev.capacity   = (max_lba + 1) * (uint64_t)sec;
    g_ans2.blockdev.ops        = &g_ans2_blockdev_ops;

    int rc = fut_blockdev_register(&g_ans2.blockdev);
    if (rc == 0) {
        g_ans2.registered = true;
        fut_printf("[ANS2] Registered block device nvme0: "
                   "%lu blocks x %u bytes\n",
                   (unsigned long)g_ans2.blockdev.num_blocks, sec);
    } else {
        fut_printf("[ANS2] fut_blockdev_register failed: %d\n", rc);
    }
}

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
    static const char *const ans_paths[] = {
        "/soc/ans@27bcc4000",
        "/soc/ans",
        "/arm-io/ans",
        NULL,
    };
    int ans_pmgr = apple_pmgr_enable_domains_any(fut_platform_get_dtb(),
                                                  ans_paths);
    if (ans_pmgr > 0) {
        fut_printf("[ANS2] pmgr: %d domains enabled\n", ans_pmgr);
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

    /* Retain the handle — without this the controller would be
     * unreachable (and leaked) the moment this function returns. */
    g_ans2.ctrl = ctrl;

    if (rust_ans2_is_ready(ctrl)) {
        fut_printf("[ANS2] Ready: max_lba=%lu sector_size=%u\n",
                   (unsigned long)rust_ans2_max_lba(ctrl),
                   (unsigned int)rust_ans2_sector_size(ctrl));
        ans2_register_blockdev();
    } else {
        fut_printf("[ANS2] Controller initialised, identify pending\n");
    }
    return true;
}

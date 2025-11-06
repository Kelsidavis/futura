/* apple_ans2.h - Apple ANS2 NVMe Controller Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Apple ANS2 (Apple NVMe Storage) controller for M1/M2/M3 SoCs.
 * Based on Linux kernel driver by Sven Peter and Asahi Linux contributors.
 *
 * Key differences from standard NVMe:
 * - Not PCIe-attached (embedded in SoC)
 * - Requires RTKit co-processor communication
 * - Uses NVMMU (NVMe MMU) with TCBs for all commands
 * - Linear submission via MMIO register writes
 * - Limited to 64 total tags (admin + I/O combined)
 * - Single admin queue + single I/O queue
 */

#ifndef __FUTURA_ARM64_APPLE_ANS2_H__
#define __FUTURA_ARM64_APPLE_ANS2_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* ============================================================
 *   ANS2 Register Offsets
 * ============================================================ */

/* Boot and control registers */
#define APPLE_ANS_BOOT_STATUS           0x1300
#define APPLE_ANS_BOOT_STATUS_OK        0xde71ce55

#define APPLE_ANS_COPROC_CPU_CONTROL    0x44
#define APPLE_ANS_COPROC_CPU_CONTROL_RUN (1 << 4)

/* Linear submission queue control */
#define APPLE_ANS_LINEAR_SQ_CTRL        0x24908
#define APPLE_ANS_LINEAR_SQ_EN          (1 << 0)

/* Doorbell registers */
#define APPLE_ANS_LINEAR_ASQ_DB         0x2490c  /* Admin queue doorbell */
#define APPLE_ANS_LINEAR_IOSQ_DB        0x24910  /* I/O queue doorbell */

/* NVMMU (NVMe Memory Management Unit) registers */
#define APPLE_NVMMU_NUM_TCBS            0x28100  /* TCB count */
#define APPLE_NVMMU_ASQ_TCB_BASE        0x28108  /* Admin queue TCB base */
#define APPLE_NVMMU_IOSQ_TCB_BASE       0x28110  /* I/O queue TCB base */
#define APPLE_NVMMU_TCB_INVAL           0x28118  /* TCB invalidation */
#define APPLE_NVMMU_TCB_STAT            0x28120  /* TCB status */

/* Standard NVMe controller registers (subset supported) */
#define APPLE_NVME_REG_CAP              0x00     /* Controller capabilities */
#define APPLE_NVME_REG_VS               0x08     /* Version */
#define APPLE_NVME_REG_CC               0x14     /* Controller configuration */
#define APPLE_NVME_REG_CSTS             0x1c     /* Controller status */
#define APPLE_NVME_REG_AQA              0x24     /* Admin queue attributes */
#define APPLE_NVME_REG_ASQ              0x28     /* Admin submission queue */
#define APPLE_NVME_REG_ACQ              0x30     /* Admin completion queue */

/* Controller configuration bits */
#define APPLE_NVME_CC_ENABLE            (1 << 0)
#define APPLE_NVME_CC_CSS_NVM           (0 << 4)
#define APPLE_NVME_CC_MPS_SHIFT         7
#define APPLE_NVME_CC_AMS_RR            (0 << 11)
#define APPLE_NVME_CC_SHN_NONE          (0 << 14)
#define APPLE_NVME_CC_IOSQES_SHIFT      16
#define APPLE_NVME_CC_IOCQES_SHIFT      20

/* Controller status bits */
#define APPLE_NVME_CSTS_RDY             (1 << 0)
#define APPLE_NVME_CSTS_CFS             (1 << 1)  /* Controller fatal status */
#define APPLE_NVME_CSTS_SHST_NORMAL     (0 << 2)
#define APPLE_NVME_CSTS_SHST_OCCURRING  (1 << 2)
#define APPLE_NVME_CSTS_SHST_COMPLETE   (2 << 2)

/* ============================================================
 *   ANS2 Queue Limits
 * ============================================================ */

#define APPLE_ANS_MAX_QUEUE_DEPTH       64      /* Max combined admin + I/O tags */
#define APPLE_ANS_ADMIN_QUEUE_DEPTH     2       /* Minimal admin queue */
#define APPLE_ANS_IO_QUEUE_DEPTH        62      /* Remaining tags for I/O */
#define APPLE_ANS_MAX_PCIE_QUEUES       1       /* Single I/O queue */

/* ============================================================
 *   TCB (Translation Control Block) Structure
 * ============================================================ */

/**
 * TCB - Translation Control Block (128 bytes)
 *
 * Apple's custom structure that must be programmed alongside
 * standard NVMe submission queue entries. Contains DMA info,
 * PRPs (duplicating SQ), and reserved space for AES-IV.
 */
typedef struct {
    uint8_t opcode;                     /* NVMe opcode */
    uint8_t flags;                      /* Command flags */
    uint16_t command_id;                /* Command identifier */
    uint32_t nsid;                      /* Namespace ID */

    uint64_t rsvd1;
    uint64_t metadata;

    /* DMA direction flags */
    uint32_t dma_flags;
#define APPLE_ANS_TCB_DMA_TO_DEVICE     (1 << 0)
#define APPLE_ANS_TCB_DMA_FROM_DEVICE   (1 << 1)

    uint32_t length;                    /* Transfer length */

    /* PRP entries (duplicate of submission queue PRPs) */
    uint64_t prp1;
    uint64_t prp2;

    /* Command-specific dwords */
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;

    /* Reserved for AES-IV (64 bytes) */
    uint8_t aes_iv[64];
} __attribute__((packed, aligned(128))) apple_ans_tcb_t;

/* ============================================================
 *   NVMe Command Structure (Standard)
 * ============================================================ */

typedef struct {
    uint8_t opcode;
    uint8_t flags;
    uint16_t command_id;
    uint32_t nsid;
    uint64_t rsvd1;
    uint64_t metadata;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} __attribute__((packed)) nvme_command_t;

/* NVMe completion queue entry */
typedef struct {
    uint32_t result;
    uint32_t rsvd;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t command_id;
    uint16_t status;
} __attribute__((packed)) nvme_completion_t;

/* Forward declaration */
typedef struct apple_rtkit_ctx apple_rtkit_ctx_t;

/* ============================================================
 *   ANS2 Controller State
 * ============================================================ */

typedef struct {
    /* MMIO base addresses */
    volatile uint8_t *mmio_base;        /* Main register base */
    uint64_t mmio_phys;                 /* Physical address */
    uint64_t mailbox_phys;              /* RTKit mailbox address */

    /* Admin queue */
    nvme_command_t *admin_sq;           /* Admin submission queue */
    nvme_completion_t *admin_cq;        /* Admin completion queue */
    apple_ans_tcb_t *admin_tcbs;        /* Admin TCB array */
    uint32_t admin_sq_head;
    uint32_t admin_sq_tail;
    uint32_t admin_cq_head;
    uint8_t admin_cq_phase;

    /* I/O queue */
    nvme_command_t *io_sq;              /* I/O submission queue */
    nvme_completion_t *io_cq;           /* I/O completion queue */
    apple_ans_tcb_t *io_tcbs;           /* I/O TCB array */
    uint32_t io_sq_head;
    uint32_t io_sq_tail;
    uint32_t io_cq_head;
    uint8_t io_cq_phase;

    /* Controller capabilities */
    uint64_t cap;                       /* CAP register value */
    uint32_t page_size;                 /* Controller page size */
    uint32_t max_hw_sectors;            /* Max sectors per command */

    /* Tag management (combined admin + I/O space) */
    uint64_t tag_bitmap;                /* Bitmap of used tags (64 bits) */

    /* RTKit co-processor IPC */
    apple_rtkit_ctx_t *rtkit;           /* RTKit context */
    uint8_t ans2_endpoint;              /* ANS2 application endpoint */

    /* Device identification */
    char serial[20];
    char model[40];
    char firmware[8];
    uint32_t max_lba;
    uint32_t sector_size;
} apple_ans2_ctrl_t;

/* ============================================================
 *   ANS2 Driver Functions
 * ============================================================ */

/**
 * Initialize Apple ANS2 NVMe controller.
 * Sets up NVMMU, allocates queues, performs controller reset.
 * @param info: Platform information
 * @return: Pointer to controller state, or NULL on failure
 */
apple_ans2_ctrl_t *fut_apple_ans2_init(const fut_platform_info_t *info);

/**
 * Reset the ANS2 controller.
 * Performs soft reset via controller configuration register.
 * @param ctrl: Controller state
 * @return: true on success, false on failure
 */
bool fut_apple_ans2_reset(apple_ans2_ctrl_t *ctrl);

/**
 * Enable the ANS2 controller.
 * Sets CC.EN bit and waits for CSTS.RDY.
 * @param ctrl: Controller state
 * @return: true on success, false on failure
 */
bool fut_apple_ans2_enable(apple_ans2_ctrl_t *ctrl);

/**
 * Submit a command to admin queue.
 * Programs both SQ entry and TCB, then rings doorbell.
 * @param ctrl: Controller state
 * @param cmd: NVMe command to submit
 * @return: Command ID, or -1 on failure
 */
int fut_apple_ans2_submit_admin(apple_ans2_ctrl_t *ctrl, const nvme_command_t *cmd);

/**
 * Submit a command to I/O queue.
 * Programs both SQ entry and TCB, then rings doorbell.
 * @param ctrl: Controller state
 * @param cmd: NVMe command to submit
 * @return: Command ID, or -1 on failure
 */
int fut_apple_ans2_submit_io(apple_ans2_ctrl_t *ctrl, const nvme_command_t *cmd);

/**
 * Poll admin completion queue.
 * Checks for completed commands and processes them.
 * @param ctrl: Controller state
 * @param cqe_out: Output buffer for completion entry
 * @return: true if completion found, false otherwise
 */
bool fut_apple_ans2_poll_admin_cq(apple_ans2_ctrl_t *ctrl, nvme_completion_t *cqe_out);

/**
 * Poll I/O completion queue.
 * Checks for completed commands and processes them.
 * @param ctrl: Controller state
 * @param cqe_out: Output buffer for completion entry
 * @return: true if completion found, false otherwise
 */
bool fut_apple_ans2_poll_io_cq(apple_ans2_ctrl_t *ctrl, nvme_completion_t *cqe_out);

/**
 * Identify controller.
 * Issues IDENTIFY command to get controller information.
 * @param ctrl: Controller state
 * @return: true on success, false on failure
 */
bool fut_apple_ans2_identify_controller(apple_ans2_ctrl_t *ctrl);

/**
 * Identify namespace.
 * Issues IDENTIFY command to get namespace 1 information.
 * @param ctrl: Controller state
 * @param nsid: Namespace ID (typically 1)
 * @return: true on success, false on failure
 */
bool fut_apple_ans2_identify_namespace(apple_ans2_ctrl_t *ctrl, uint32_t nsid);

/**
 * Read sectors from NVMe device.
 * @param ctrl: Controller state
 * @param lba: Starting logical block address
 * @param count: Number of sectors to read
 * @param buffer: Output buffer (must be page-aligned)
 * @return: Number of sectors read, or -1 on error
 */
int fut_apple_ans2_read(apple_ans2_ctrl_t *ctrl, uint64_t lba, uint32_t count, void *buffer);

/**
 * Write sectors to NVMe device.
 * @param ctrl: Controller state
 * @param lba: Starting logical block address
 * @param count: Number of sectors to write
 * @param buffer: Input buffer (must be page-aligned)
 * @return: Number of sectors written, or -1 on error
 */
int fut_apple_ans2_write(apple_ans2_ctrl_t *ctrl, uint64_t lba, uint32_t count, const void *buffer);

/**
 * Platform integration: Initialize Apple ANS2 NVMe.
 * High-level entry point called from platform init.
 * @param info: Platform information
 * @return: true on success, false on failure
 */
bool fut_apple_ans2_platform_init(const fut_platform_info_t *info);

/* ============================================================
 *   Internal Helper Functions
 * ============================================================ */

/**
 * Allocate a tag from the combined tag space.
 * @param ctrl: Controller state
 * @return: Tag number (0-63), or -1 if none available
 */
int apple_ans2_alloc_tag(apple_ans2_ctrl_t *ctrl);

/**
 * Free a tag back to the pool.
 * @param ctrl: Controller state
 * @param tag: Tag number to free
 */
void apple_ans2_free_tag(apple_ans2_ctrl_t *ctrl, int tag);

/**
 * Program a TCB for a command.
 * @param tcb: TCB structure to program
 * @param cmd: NVMe command
 * @param tag: Command tag
 */
void apple_ans2_program_tcb(apple_ans_tcb_t *tcb, const nvme_command_t *cmd, int tag);

/**
 * Ring the admin queue doorbell.
 * @param ctrl: Controller state
 * @param tag: Command tag to trigger
 */
void apple_ans2_ring_admin_doorbell(apple_ans2_ctrl_t *ctrl, int tag);

/**
 * Ring the I/O queue doorbell.
 * @param ctrl: Controller state
 * @param tag: Command tag to trigger
 */
void apple_ans2_ring_io_doorbell(apple_ans2_ctrl_t *ctrl, int tag);

#endif /* __FUTURA_ARM64_APPLE_ANS2_H__ */

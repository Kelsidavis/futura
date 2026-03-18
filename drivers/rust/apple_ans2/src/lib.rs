// SPDX-License-Identifier: MPL-2.0
//! Apple ANS2 NVMe storage controller driver for Futura OS
//!
//! Apple ANS2 (Apple NVMe Storage 2nd gen) is the embedded NVMe controller
//! in Apple M1/M2/M3 SoCs.  It differs from standard PCIe-NVMe:
//!
//! - Not PCIe-attached — embedded in the SoC MMIO map
//! - Co-processor (RTKit) bootstraps the storage firmware
//! - All commands require both a standard NVMe SQ entry AND a TCB
//!   (Transaction Control Block) programmed into the NVMMU
//! - Submission via doorbell write to a tag register, not SQ tail pointer
//! - Max 64 concurrent tags shared across admin + I/O queues
//!
//! Reference: Asahi Linux `drivers/nvme/host/apple.c` (Sven Peter),
//!            `drivers/nvme/host/core.c`, m1n1 `hv/nvme.py`

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Kernel heap / RTKit bindings
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut u8;
    fn fut_free(ptr: *mut u8);
    /// Rust RTKit driver — init a context at the given mailbox MMIO base.
    fn rust_rtkit_init(base: u64) -> *mut ();
    /// Run the RTKit boot sequence.
    fn rust_rtkit_boot(ctx: *mut ()) -> i32;
    /// Register an endpoint message handler.
    fn rust_rtkit_register_handler(
        ctx: *mut (),
        endpoint: u8,
        handler: Option<unsafe extern "C" fn(*mut (), u8, u64)>,
        cookie: *mut (),
    );
    /// Send a message to an endpoint.
    fn rust_rtkit_send(ctx: *mut (), endpoint: u8, msg: u64) -> i32;
    /// Poll RX FIFO and dispatch.
    fn rust_rtkit_poll(ctx: *mut ()) -> i32;
}

// ---------------------------------------------------------------------------
// Register offsets (from Asahi Linux `apple.c`)
// ---------------------------------------------------------------------------

// Boot / co-processor control
const ANS_BOOT_STATUS:           usize = 0x1300;
const ANS_BOOT_STATUS_OK:        u32   = 0xde71ce55;
const ANS_COPROC_CPU_CTRL:       usize = 0x44;
const ANS_COPROC_CPU_CTRL_RUN:   u32   = 1 << 4;

// Linear SQ control
const ANS_LINEAR_SQ_CTRL:        usize = 0x24908;
const ANS_LINEAR_SQ_EN:          u32   = 1 << 0;

// Doorbell registers
const ANS_LINEAR_ASQ_DB:         usize = 0x2490c;
const ANS_LINEAR_IOSQ_DB:        usize = 0x24910;

// NVMMU registers
const NVMMU_NUM_TCBS:            usize = 0x28100;
const NVMMU_ASQ_TCB_BASE:        usize = 0x28108;
const NVMMU_IOSQ_TCB_BASE:       usize = 0x28110;
const NVMMU_TCB_INVAL:           usize = 0x28118;

// Standard NVMe subset
const NVME_REG_CAP:              usize = 0x00;
const NVME_REG_CC:               usize = 0x14;
const NVME_REG_CSTS:             usize = 0x1C;
const NVME_REG_AQA:              usize = 0x24;
const NVME_REG_ASQ:              usize = 0x28;
const NVME_REG_ACQ:              usize = 0x30;

// NVMe CC bits
const NVME_CC_ENABLE:            u32   = 1 << 0;
const NVME_CC_CSS_NVM:           u32   = 0 << 4;
const NVME_CC_MPS_4K:            u32   = 0 << 7;   // 2^(12+0) = 4K
const NVME_CC_AMS_RR:            u32   = 0 << 11;
const NVME_CC_IOSQES:            u32   = 6 << 16;  // 2^6 = 64 bytes
const NVME_CC_IOCQES:            u32   = 4 << 20;  // 2^4 = 16 bytes

// NVMe CSTS bits
const NVME_CSTS_RDY:             u32   = 1 << 0;
const NVME_CSTS_CFS:             u32   = 1 << 1;

// ANS2 application endpoint (device-tree value, fixed for M1/M2)
const ANS2_ENDPOINT: u8 = 0x20;

// Queue / tag limits
const MAX_TAGS:        usize = 64;
const ADMIN_Q_DEPTH:   usize = 2;
const IO_Q_DEPTH:      usize = MAX_TAGS - ADMIN_Q_DEPTH;

// NVMe opcodes
const NVME_OP_WRITE:    u8 = 0x01;
const NVME_OP_READ:     u8 = 0x02;
const NVME_OP_IDENTIFY: u8 = 0x06;
const NVME_OP_SET_FEAT: u8 = 0x09;
const NVME_OP_GET_FEAT: u8 = 0x0A;

// TCB DMA flags
const TCB_DMA_TO_DEV:   u32 = 1 << 0;
const TCB_DMA_FROM_DEV: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// NVMe SQ command (64 bytes, standard)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct NvmeCmd {
    opcode:     u8,
    flags:      u8,
    command_id: u16,
    nsid:       u32,
    rsvd1:      u64,
    metadata:   u64,
    prp1:       u64,
    prp2:       u64,
    cdw10:      u32,
    cdw11:      u32,
    cdw12:      u32,
    cdw13:      u32,
    cdw14:      u32,
    cdw15:      u32,
}

// NVMe CQ entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct NvmeCqe {
    result:     u32,
    rsvd:       u32,
    sq_head:    u16,
    sq_id:      u16,
    command_id: u16,
    status:     u16,
}

// ---------------------------------------------------------------------------
// Apple ANS TCB (128 bytes, 128-byte aligned — mandatory for NVMMU)
// ---------------------------------------------------------------------------

#[repr(C, align(128))]
#[derive(Clone, Copy)]
struct AnsTcb {
    opcode:     u8,
    flags:      u8,
    command_id: u16,
    nsid:       u32,
    rsvd1:      u64,
    metadata:   u64,
    dma_flags:  u32,
    length:     u32,
    prp1:       u64,
    prp2:       u64,
    cdw10:      u32,
    cdw11:      u32,
    cdw12:      u32,
    cdw13:      u32,
    cdw14:      u32,
    cdw15:      u32,
    /// Reserved for AES-IV (hardware may use these bytes for inline encryption).
    /// 56 bytes: pads the 72-byte payload to the 128-byte TCB size.
    _aes_iv:    [u8; 56],
}

const _: () = assert!(core::mem::size_of::<AnsTcb>() == 128,
    "AnsTcb must be exactly 128 bytes");

impl AnsTcb {
    const fn zeroed() -> Self {
        Self {
            opcode: 0, flags: 0, command_id: 0, nsid: 0,
            rsvd1: 0, metadata: 0, dma_flags: 0, length: 0,
            prp1: 0, prp2: 0,
            cdw10: 0, cdw11: 0, cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
            _aes_iv: [0u8; 56],
        }
    }

    fn fill_from(&mut self, cmd: &NvmeCmd, len: u32) {
        self.opcode     = cmd.opcode;
        self.flags      = cmd.flags;
        self.command_id = cmd.command_id;
        self.nsid       = cmd.nsid;
        self.rsvd1      = 0;
        self.metadata   = 0;
        self.length     = len;
        self.prp1       = cmd.prp1;
        self.prp2       = cmd.prp2;
        self.cdw10      = cmd.cdw10;
        self.cdw11      = cmd.cdw11;
        self.cdw12      = cmd.cdw12;
        self.cdw13      = cmd.cdw13;
        self.cdw14      = cmd.cdw14;
        self.cdw15      = cmd.cdw15;
        // DMA direction
        self.dma_flags  = if cmd.opcode == NVME_OP_WRITE {
            TCB_DMA_TO_DEV
        } else {
            TCB_DMA_FROM_DEV
        };
    }
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

struct Queue {
    /// Kernel-virtual address of the SQ array.
    sq:       *mut NvmeCmd,
    /// Kernel-virtual address of the CQ array.
    cq:       *mut NvmeCqe,
    /// Kernel-virtual address of the TCB array (128-byte aligned).
    tcbs:     *mut AnsTcb,
    head:     u16,
    tail:     u16,
    cq_head:  u16,
    cq_phase: u8,
    depth:    u16,
}

impl Queue {
    fn new(sq: *mut NvmeCmd, cq: *mut NvmeCqe, tcbs: *mut AnsTcb, depth: u16) -> Self {
        Self { sq, cq, tcbs, head: 0, tail: 0, cq_head: 0, cq_phase: 1, depth }
    }
}

// ---------------------------------------------------------------------------
// Ans2Ctrl — main driver state
// ---------------------------------------------------------------------------

pub struct Ans2Ctrl {
    base:        usize,         // MMIO virtual base
    rtkit:       *mut (),       // Rust RTKit context
    admin:       Queue,
    io_q:        Queue,
    tag_bitmap:  u64,           // 1-bit per tag; bit=1 means in-use
    max_lba:     u64,
    sector_size: u32,
    ready:       AtomicBool,
}

// SAFETY: single-threaded access via kernel spinlock (caller responsibility).
unsafe impl Send for Ans2Ctrl {}
unsafe impl Sync for Ans2Ctrl {}

impl Ans2Ctrl {
    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }
    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }
    fn r64(&self, off: usize) -> u64 {
        unsafe { read_volatile((self.base + off) as *const u64) }
    }
    fn w64(&self, off: usize, v: u64) {
        unsafe { write_volatile((self.base + off) as *mut u64, v) }
    }

    // ---- Tag management ----

    fn alloc_tag(&mut self) -> Option<u8> {
        for i in 0u8..MAX_TAGS as u8 {
            if self.tag_bitmap & (1u64 << i) == 0 {
                self.tag_bitmap |= 1u64 << i;
                return Some(i);
            }
        }
        None
    }

    fn free_tag(&mut self, tag: u8) {
        if (tag as usize) < MAX_TAGS {
            self.tag_bitmap &= !(1u64 << tag);
        }
    }

    // ---- Controller reset / enable ----

    /// Spin until CSTS.RDY matches `want_ready`, with a budget of ~500k spins.
    fn wait_ready(&self, want_ready: bool) -> bool {
        let mut budget = 500_000u32;
        loop {
            let csts = self.r32(NVME_REG_CSTS);
            if (csts & NVME_CSTS_RDY != 0) == want_ready {
                return true;
            }
            if csts & NVME_CSTS_CFS != 0 {
                return false; // fatal status
            }
            if budget == 0 {
                return false;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    fn reset(&self) -> bool {
        // Release CC.EN, wait for !CSTS.RDY
        let cc = self.r32(NVME_REG_CC);
        self.w32(NVME_REG_CC, cc & !NVME_CC_ENABLE);
        self.wait_ready(false)
    }

    fn enable(&mut self) -> bool {
        // Program AQA, ASQ, ACQ
        let aqa = ((ADMIN_Q_DEPTH as u32 - 1) << 16) | (ADMIN_Q_DEPTH as u32 - 1);
        self.w32(NVME_REG_AQA, aqa);
        self.w64(NVME_REG_ASQ, self.admin.sq as u64);
        self.w64(NVME_REG_ACQ, self.admin.cq as u64);

        // Configure NVMMU TCB base + count
        self.w32(NVMMU_NUM_TCBS as usize, MAX_TAGS as u32);
        self.w64(NVMMU_ASQ_TCB_BASE as usize, self.admin.tcbs as u64);
        self.w64(NVMMU_IOSQ_TCB_BASE as usize, self.io_q.tcbs as u64);

        // Enable linear SQ
        self.w32(ANS_LINEAR_SQ_CTRL, ANS_LINEAR_SQ_EN);

        // Set CC and enable
        let cc = NVME_CC_ENABLE | NVME_CC_CSS_NVM | NVME_CC_MPS_4K
               | NVME_CC_AMS_RR | NVME_CC_IOSQES | NVME_CC_IOCQES;
        self.w32(NVME_REG_CC, cc);

        self.wait_ready(true)
    }

    // ---- Co-processor boot ----

    fn boot_coproc(&self) -> bool {
        // Release the ANS2 co-processor CPU from reset.
        let ctrl = self.r32(ANS_COPROC_CPU_CTRL);
        self.w32(ANS_COPROC_CPU_CTRL, ctrl | ANS_COPROC_CPU_CTRL_RUN);

        // Wait for the firmware to signal ready.
        let mut budget = 200_000u32;
        loop {
            if self.r32(ANS_BOOT_STATUS) == ANS_BOOT_STATUS_OK {
                return true;
            }
            if budget == 0 {
                return false;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    // ---- Submit / complete ----

    /// Submit a command to the admin queue.
    /// Returns the tag (command-id) on success, or -1 on failure.
    fn submit_admin(&mut self, cmd: &NvmeCmd, len: u32) -> i32 {
        let tag = match self.alloc_tag() {
            Some(t) => t,
            None    => return -1,
        };
        // Write TCB
        let tcb = unsafe { &mut *self.admin.tcbs.add(tag as usize) };
        tcb.fill_from(cmd, len);
        // Write SQ entry (command_id tracks the tag)
        let slot = unsafe { &mut *self.admin.sq.add(tag as usize) };
        *slot = *cmd;
        slot.command_id = tag as u16;
        // Ring doorbell: write tag
        self.w32(ANS_LINEAR_ASQ_DB, tag as u32);
        tag as i32
    }

    /// Submit a command to the I/O queue.
    fn submit_io(&mut self, cmd: &NvmeCmd, len: u32) -> i32 {
        let tag = match self.alloc_tag() {
            Some(t) => t,
            None    => return -1,
        };
        let tcb = unsafe { &mut *self.io_q.tcbs.add(tag as usize) };
        tcb.fill_from(cmd, len);
        let slot = unsafe { &mut *self.io_q.sq.add(tag as usize) };
        *slot = *cmd;
        slot.command_id = tag as u16;
        self.w32(ANS_LINEAR_IOSQ_DB, tag as u32);
        tag as i32
    }

    /// Poll admin CQ for a completion.  Returns `Some(tag, status)` or `None`.
    fn poll_admin_cq(&mut self) -> Option<(u16, u16)> {
        let cqe = unsafe { &*self.admin.cq.add(self.admin.cq_head as usize) };
        // Phase bit in status word bit[0]
        if (cqe.status & 1) as u8 != self.admin.cq_phase {
            return None;
        }
        let tag    = cqe.command_id;
        let status = cqe.status >> 1;
        self.admin.cq_head += 1;
        if self.admin.cq_head >= self.admin.depth {
            self.admin.cq_head  = 0;
            self.admin.cq_phase ^= 1;
        }
        // Invalidate TCB after completion
        self.w32(NVMMU_TCB_INVAL, tag as u32);
        self.free_tag(tag as u8);
        Some((tag, status))
    }

    /// Poll I/O CQ for a completion.
    fn poll_io_cq(&mut self) -> Option<(u16, u16)> {
        let cqe = unsafe { &*self.io_q.cq.add(self.io_q.cq_head as usize) };
        if (cqe.status & 1) as u8 != self.io_q.cq_phase {
            return None;
        }
        let tag    = cqe.command_id;
        let status = cqe.status >> 1;
        self.io_q.cq_head += 1;
        if self.io_q.cq_head >= self.io_q.depth {
            self.io_q.cq_head  = 0;
            self.io_q.cq_phase ^= 1;
        }
        self.w32(NVMMU_TCB_INVAL, tag as u32);
        self.free_tag(tag as u8);
        Some((tag, status))
    }

    /// Blocking admin submit-and-wait (up to ~200k polls ≈ a few ms).
    fn admin_cmd(&mut self, cmd: &NvmeCmd, len: u32) -> bool {
        let tag = self.submit_admin(cmd, len);
        if tag < 0 {
            return false;
        }
        let mut budget = 200_000u32;
        loop {
            if let Some((_t, status)) = self.poll_admin_cq() {
                return status == 0;
            }
            if budget == 0 {
                return false;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    // ---- Identify ----

    /// Run IDENTIFY CONTROLLER (CNS=1) to populate serial/model/firmware.
    fn identify_controller(&mut self) -> bool {
        // Allocate a 4K page-aligned identify buffer.
        let buf = unsafe { fut_alloc(4096) };
        if buf.is_null() {
            return false;
        }
        // Zero-fill.
        unsafe { core::ptr::write_bytes(buf, 0, 4096) };

        let mut cmd = NvmeCmd::default();
        cmd.opcode = NVME_OP_IDENTIFY;
        cmd.nsid   = 0;
        cmd.prp1   = buf as u64;
        cmd.prp2   = 0;
        cmd.cdw10  = 1; // CNS=1 (controller)

        let ok = self.admin_cmd(&cmd, 4096);

        if ok {
            // Identify data layout (NVMe 1.4 spec §5.15):
            //   bytes   0-19:  serial number (ASCII, right-padded with spaces)
            //   bytes  20-59:  model number
            //   bytes  64-71:  firmware revision
            // (Nothing else needed for now.)
            // We don't store strings here to keep the struct small.
            let _ = buf; // data read by upper layers if needed
        }

        unsafe { fut_free(buf) };
        ok
    }

    /// Run IDENTIFY NAMESPACE (CNS=0, nsid=1) to get capacity and LBA format.
    fn identify_namespace(&mut self) -> bool {
        let buf = unsafe { fut_alloc(4096) };
        if buf.is_null() {
            return false;
        }
        unsafe { core::ptr::write_bytes(buf, 0, 4096) };

        let mut cmd = NvmeCmd::default();
        cmd.opcode = NVME_OP_IDENTIFY;
        cmd.nsid   = 1;
        cmd.prp1   = buf as u64;
        cmd.cdw10  = 0; // CNS=0 (namespace)

        let ok = self.admin_cmd(&cmd, 4096);

        if ok {
            // Namespace identify layout (§5.15.2):
            //   bytes   0-7:  NSZE (namespace size in logical blocks)
            //   bytes   8-15: NCAP
            //   bytes 128-131: FLBAS (formatted LBA size selector, bits[3:0])
            //   bytes 132-: LBA format array (each 4 bytes: LBAF)
            //   LBAF = { LBADS (bits[23:16]), MS (bits[15:0]), RP (bits[25:24]) }
            let nsze = unsafe { *(buf as *const u64) };
            self.max_lba = nsze.saturating_sub(1);
            // Read LBA format from FLBAS selector.
            let flbas = unsafe { *(buf.add(26) as *const u8) } & 0xF;
            let lbaf_off = 128 + (flbas as usize) * 4;
            let lbaf = unsafe { *(buf.add(lbaf_off) as *const u32) };
            let lbads = ((lbaf >> 16) & 0xFF) as u32;
            if lbads >= 9 {
                self.sector_size = 1u32 << lbads; // typically 512 or 4096
            } else {
                self.sector_size = 512;
            }
        }

        unsafe { fut_free(buf) };
        ok
    }

    // ---- Read / write ----

    /// Read `count` sectors (each `sector_size` bytes) from `lba` into `buf`.
    /// Returns number of sectors read on success, -1 on error.
    pub fn read(&mut self, lba: u64, count: u32, buf: *mut u8) -> i32 {
        if buf.is_null() || count == 0 || count > IO_Q_DEPTH as u32 {
            return -1;
        }
        let len = (count as usize).saturating_mul(self.sector_size as usize);
        let mut cmd = NvmeCmd::default();
        cmd.opcode = NVME_OP_READ;
        cmd.nsid   = 1;
        cmd.prp1   = buf as u64;
        cmd.prp2   = 0; // single PRP for now
        cmd.cdw10  = lba as u32;
        cmd.cdw11  = (lba >> 32) as u32;
        cmd.cdw12  = count - 1;  // NLB is 0-based

        let tag = self.submit_io(&cmd, len as u32);
        if tag < 0 {
            return -1;
        }

        let mut budget = 500_000u32;
        loop {
            if let Some((_t, status)) = self.poll_io_cq() {
                return if status == 0 { count as i32 } else { -1 };
            }
            if budget == 0 {
                return -1;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    /// Write `count` sectors from `buf` starting at `lba`.
    pub fn write(&mut self, lba: u64, count: u32, buf: *const u8) -> i32 {
        if buf.is_null() || count == 0 || count > IO_Q_DEPTH as u32 {
            return -1;
        }
        let len = (count as usize).saturating_mul(self.sector_size as usize);
        let mut cmd = NvmeCmd::default();
        cmd.opcode = NVME_OP_WRITE;
        cmd.nsid   = 1;
        cmd.prp1   = buf as u64;
        cmd.prp2   = 0;
        cmd.cdw10  = lba as u32;
        cmd.cdw11  = (lba >> 32) as u32;
        cmd.cdw12  = count - 1;

        let tag = self.submit_io(&cmd, len as u32);
        if tag < 0 {
            return -1;
        }

        let mut budget = 500_000u32;
        loop {
            if let Some((_t, status)) = self.poll_io_cq() {
                return if status == 0 { count as i32 } else { -1 };
            }
            if budget == 0 {
                return -1;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    // ---- Full init ----

    /// Allocate and initialise the ANS2 controller at `base` with RTKit
    /// mailbox at `mailbox_base`.  Returns `None` on failure.
    pub fn init(base: usize, mailbox_base: u64) -> Option<*mut Self> {
        // 1. Boot RTKit co-processor.
        let rtkit = unsafe { rust_rtkit_init(mailbox_base) };
        if rtkit.is_null() {
            return None;
        }
        if unsafe { rust_rtkit_boot(rtkit) } == 0 {
            return None;
        }

        // 2. Boot ANS2 co-processor firmware (separate from RTKit).
        //    Use a temporary stack context for the MMIO check.
        let boot_ok = {
            let ctrl_ptr = base as *const u32;
            let mut budget = 200_000u32;
            loop {
                let status = unsafe { read_volatile((base + ANS_BOOT_STATUS) as *const u32) };
                if status == ANS_BOOT_STATUS_OK {
                    break true;
                }
                if budget == 0 {
                    break false;
                }
                budget -= 1;
                core::hint::spin_loop();
                let _ = ctrl_ptr; // silence unused warning
            }
        };
        if !boot_ok {
            return None;
        }

        // 3. Allocate queue memory.
        //    SQ/CQ entries don't need special alignment beyond natural.
        //    TCBs must be 128-byte aligned; allocate with padding.
        let sq_size  = MAX_TAGS * core::mem::size_of::<NvmeCmd>();
        let cq_size  = MAX_TAGS * core::mem::size_of::<NvmeCqe>();
        let tcb_size = MAX_TAGS * core::mem::size_of::<AnsTcb>(); // already 128-aligned

        let admin_sq   = unsafe { fut_alloc(sq_size) as *mut NvmeCmd };
        let admin_cq   = unsafe { fut_alloc(cq_size) as *mut NvmeCqe };
        let admin_tcbs = unsafe { fut_alloc(tcb_size) as *mut AnsTcb };
        let io_sq      = unsafe { fut_alloc(sq_size) as *mut NvmeCmd };
        let io_cq      = unsafe { fut_alloc(cq_size) as *mut NvmeCqe };
        let io_tcbs    = unsafe { fut_alloc(tcb_size) as *mut AnsTcb };

        if admin_sq.is_null() || admin_cq.is_null() || admin_tcbs.is_null()
            || io_sq.is_null() || io_cq.is_null() || io_tcbs.is_null()
        {
            // Free what was allocated
            if !admin_sq.is_null()   { unsafe { fut_free(admin_sq as *mut u8) } }
            if !admin_cq.is_null()   { unsafe { fut_free(admin_cq as *mut u8) } }
            if !admin_tcbs.is_null() { unsafe { fut_free(admin_tcbs as *mut u8) } }
            if !io_sq.is_null()      { unsafe { fut_free(io_sq as *mut u8) } }
            if !io_cq.is_null()      { unsafe { fut_free(io_cq as *mut u8) } }
            if !io_tcbs.is_null()    { unsafe { fut_free(io_tcbs as *mut u8) } }
            return None;
        }

        // Zero-fill all queue memory.
        unsafe {
            core::ptr::write_bytes(admin_sq   as *mut u8, 0, sq_size);
            core::ptr::write_bytes(admin_cq   as *mut u8, 0, cq_size);
            core::ptr::write_bytes(admin_tcbs as *mut u8, 0, tcb_size);
            core::ptr::write_bytes(io_sq      as *mut u8, 0, sq_size);
            core::ptr::write_bytes(io_cq      as *mut u8, 0, cq_size);
            core::ptr::write_bytes(io_tcbs    as *mut u8, 0, tcb_size);
        }

        // 4. Build the controller struct on the heap.
        let ctrl_mem = unsafe { fut_alloc(core::mem::size_of::<Self>()) as *mut Self };
        if ctrl_mem.is_null() {
            return None;
        }

        let ctrl = unsafe { &mut *ctrl_mem };
        ctrl.base        = base;
        ctrl.rtkit       = rtkit;
        ctrl.tag_bitmap  = 0;
        ctrl.max_lba     = 0;
        ctrl.sector_size = 512;
        ctrl.ready       = AtomicBool::new(false);
        ctrl.admin = Queue::new(admin_sq, admin_cq, admin_tcbs, ADMIN_Q_DEPTH as u16);
        ctrl.io_q  = Queue::new(io_sq, io_cq, io_tcbs, IO_Q_DEPTH as u16);

        // 5. Reset + enable NVMe controller.
        if !ctrl.reset() || !ctrl.enable() {
            return None;
        }

        // 6. Identify controller + namespace 1.
        if !ctrl.identify_controller() || !ctrl.identify_namespace() {
            return None;
        }

        ctrl.ready.store(true, Ordering::Release);
        Some(ctrl_mem)
    }
}

// ---------------------------------------------------------------------------
// RTKit message handler (called from rust_rtkit_poll)
// ---------------------------------------------------------------------------

unsafe extern "C" fn ans2_rtkit_handler(cookie: *mut (), _endpoint: u8, _msg: u64) {
    // cookie points to the Ans2Ctrl.  For now we just ack; a full
    // implementation would parse msg and wake waiting I/O requests.
    let _ctrl = unsafe { &mut *(cookie as *mut Ans2Ctrl) };
    // TODO: parse msg type and signal completions
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Initialise the ANS2 controller at `mmio_base` with RTKit mailbox at
/// `mailbox_base`.  Returns a non-null opaque pointer on success, null on
/// failure.
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_init(mmio_base: u64, mailbox_base: u64) -> *mut Ans2Ctrl {
    match Ans2Ctrl::init(mmio_base as usize, mailbox_base) {
        Some(p) => {
            // Register RTKit message handler for the ANS2 endpoint.
            let ctrl = unsafe { &mut *p };
            unsafe {
                rust_rtkit_register_handler(
                    ctrl.rtkit,
                    ANS2_ENDPOINT,
                    Some(ans2_rtkit_handler),
                    p as *mut (),
                )
            };
            p
        }
        None => null_mut(),
    }
}

/// Free an Ans2Ctrl allocated by `rust_ans2_init`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_free(ctrl: *mut Ans2Ctrl) {
    if ctrl.is_null() {
        return;
    }
    unsafe { fut_free(ctrl as *mut u8) };
}

/// Read `count` sectors from `lba` into `buf`.
/// Returns sectors-read on success, -1 on error.
///
/// # Safety
/// `buf` must be valid for `count * sector_size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_ans2_read(
    ctrl: *mut Ans2Ctrl,
    lba: u64,
    count: u32,
    buf: *mut u8,
) -> i32 {
    if ctrl.is_null() {
        return -1;
    }
    unsafe { (*ctrl).read(lba, count, buf) }
}

/// Write `count` sectors from `buf` to `lba`.
/// Returns sectors-written on success, -1 on error.
///
/// # Safety
/// `buf` must be valid for `count * sector_size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_ans2_write(
    ctrl: *mut Ans2Ctrl,
    lba: u64,
    count: u32,
    buf: *const u8,
) -> i32 {
    if ctrl.is_null() {
        return -1;
    }
    unsafe { (*ctrl).write(lba, count, buf) }
}

/// Returns 1 if the controller initialised successfully, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_is_ready(ctrl: *const Ans2Ctrl) -> i32 {
    if ctrl.is_null() {
        return 0;
    }
    unsafe { (*ctrl).ready.load(Ordering::Acquire) as i32 }
}

/// Return the maximum LBA index (0 if not yet identified).
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_max_lba(ctrl: *const Ans2Ctrl) -> u64 {
    if ctrl.is_null() {
        return 0;
    }
    unsafe { (*ctrl).max_lba }
}

/// Return the sector size in bytes (0 if not yet identified).
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_sector_size(ctrl: *const Ans2Ctrl) -> u32 {
    if ctrl.is_null() {
        return 0;
    }
    unsafe { (*ctrl).sector_size }
}

/// Poll the RTKit RX FIFO and dispatch any pending ANS2 messages.
/// Call this from the AIC interrupt handler or a polling loop.
#[unsafe(no_mangle)]
pub extern "C" fn rust_ans2_poll(ctrl: *mut Ans2Ctrl) {
    if ctrl.is_null() {
        return;
    }
    let rtkit = unsafe { (*ctrl).rtkit };
    if !rtkit.is_null() {
        while unsafe { rust_rtkit_poll(rtkit) } != 0 {}
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

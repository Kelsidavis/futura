// SPDX-License-Identifier: MPL-2.0
//
// NVMe (Non-Volatile Memory Express) Storage Controller Driver
//
// Implements the NVMe 1.4 specification for PCIe-attached SSDs,
// the primary storage interface on AMD Ryzen AM4/AM5 platforms.
//
// Architecture:
//   - Admin queue pair (SQ0/CQ0) for controller management
//   - One I/O queue pair (SQ1/CQ1) for read/write commands
//   - 4 KiB page-aligned memory for queues and PRP lists
//   - Polling-based completion (interrupt support planned)
//
// PCI class: 01h (Mass Storage), subclass 08h (NVM), prog-if 02h (NVMe)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::{c_char, c_void};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering, fence};

use common::{
    alloc, alloc_page, free, log, map_mmio_region, register, thread_yield,
    unmap_mmio_region, FutBlkBackend, FutBlkDev, FutStatus,
    FUT_BLK_ADMIN, FUT_BLK_READ, FUT_BLK_WRITE, MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// ── PCI device structure (mirrors kernel/pci.h) ──

#[repr(C)]
struct PciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    revision: u8,
    header_type: u8,
    subsys_vendor: u16,
    subsys_id: u16,
    irq_line: u8,
}

// ── PCI configuration space I/O ──

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") val);
        val
    }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

// ── NVMe Controller Registers (MMIO BAR0) ──

const NVME_REG_CAP: usize = 0x00;      // Controller Capabilities (64-bit)
const NVME_REG_VS: usize = 0x08;       // Version
const NVME_REG_INTMS: usize = 0x0C;    // Interrupt Mask Set
const NVME_REG_INTMC: usize = 0x10;    // Interrupt Mask Clear
const NVME_REG_CC: usize = 0x14;       // Controller Configuration
const NVME_REG_CSTS: usize = 0x1C;     // Controller Status
const NVME_REG_AQA: usize = 0x24;      // Admin Queue Attributes
const NVME_REG_ASQ: usize = 0x28;      // Admin Submission Queue Base (64-bit)
const NVME_REG_ACQ: usize = 0x30;      // Admin Completion Queue Base (64-bit)

// CC register fields
const NVME_CC_EN: u32 = 1 << 0;        // Enable
const NVME_CC_CSS_NVM: u32 = 0 << 4;   // NVM command set
const NVME_CC_MPS_4K: u32 = 0 << 7;    // Memory Page Size = 4 KiB (2^(12+0))
const NVME_CC_AMS_RR: u32 = 0 << 11;   // Round-robin arbitration
const NVME_CC_SHN_NONE: u32 = 0 << 14; // No shutdown
const NVME_CC_IOSQES: u32 = 6 << 16;   // I/O SQ entry size = 2^6 = 64 bytes
const NVME_CC_IOCQES: u32 = 4 << 20;   // I/O CQ entry size = 2^4 = 16 bytes

// CSTS register fields
const NVME_CSTS_RDY: u32 = 1 << 0;     // Ready
const NVME_CSTS_CFS: u32 = 1 << 1;     // Controller Fatal Status
const NVME_CSTS_SHST_MASK: u32 = 3 << 2;

// Queue sizes
const ADMIN_QUEUE_SIZE: u16 = 64;
const IO_QUEUE_SIZE: u16 = 256;

// NVMe admin opcodes
const NVME_ADMIN_IDENTIFY: u8 = 0x06;
const NVME_ADMIN_CREATE_IO_CQ: u8 = 0x05;
const NVME_ADMIN_CREATE_IO_SQ: u8 = 0x01;

// NVMe I/O opcodes
const NVME_IO_READ: u8 = 0x02;
const NVME_IO_WRITE: u8 = 0x01;
const NVME_IO_FLUSH: u8 = 0x00;

// ── NVMe Submission Queue Entry (64 bytes) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct NvmeSubmCmd {
    opcode: u8,
    flags: u8,
    command_id: u16,
    nsid: u32,
    reserved: u64,
    mptr: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

const _: () = assert!(core::mem::size_of::<NvmeSubmCmd>() == 64);

impl NvmeSubmCmd {
    const fn zeroed() -> Self {
        Self {
            opcode: 0, flags: 0, command_id: 0, nsid: 0,
            reserved: 0, mptr: 0, prp1: 0, prp2: 0,
            cdw10: 0, cdw11: 0, cdw12: 0, cdw13: 0, cdw14: 0, cdw15: 0,
        }
    }
}

// ── NVMe Completion Queue Entry (16 bytes) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct NvmeCplEntry {
    dw0: u32,           // Command-specific result
    dw1: u32,           // Reserved
    sq_head: u16,       // SQ head pointer
    sq_id: u16,         // SQ identifier
    command_id: u16,    // Command identifier
    status: u16,        // Status field (phase bit in bit 0)
}

const _: () = assert!(core::mem::size_of::<NvmeCplEntry>() == 16);

// ── Controller state ──

struct NvmeController {
    bar0: *mut u8,
    bar0_size: usize,
    doorbell_stride: u32,
    // PCI location
    bus: u8,
    dev: u8,
    func: u8,
    // Admin queue
    admin_sq: *mut NvmeSubmCmd,
    admin_cq: *mut NvmeCplEntry,
    admin_sq_tail: u16,
    admin_cq_head: u16,
    admin_cq_phase: bool,
    admin_cmd_id: u16,
    // I/O queue
    io_sq: *mut NvmeSubmCmd,
    io_cq: *mut NvmeCplEntry,
    io_sq_tail: u16,
    io_cq_head: u16,
    io_cq_phase: bool,
    io_cmd_id: u16,
    // Namespace info
    ns_block_count: u64,
    ns_block_size: u32,
    nsid: u32,
    // Identify data page
    identify_buf: *mut u8,
}

static mut NVME: Option<NvmeController> = None;

// ── MMIO helpers ──

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

fn mmio_read64(base: *mut u8, offset: usize) -> u64 {
    // NVMe spec says 64-bit registers may need two 32-bit reads
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: *mut u8, offset: usize, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

// ── Doorbell writes ──

fn write_sq_doorbell(ctrl: &NvmeController, qid: u16, tail: u16) {
    let offset = 0x1000 + ((2 * qid as usize) * (ctrl.doorbell_stride as usize));
    mmio_write32(ctrl.bar0, offset, tail as u32);
}

fn write_cq_doorbell(ctrl: &NvmeController, qid: u16, head: u16) {
    let offset = 0x1000 + ((2 * qid as usize + 1) * (ctrl.doorbell_stride as usize));
    mmio_write32(ctrl.bar0, offset, head as u32);
}

// ── Admin command submission ──

fn admin_submit(ctrl: &mut NvmeController, cmd: &NvmeSubmCmd) -> u16 {
    let idx = ctrl.admin_sq_tail as usize;
    unsafe {
        write_volatile(ctrl.admin_sq.add(idx), *cmd);
    }
    ctrl.admin_sq_tail = (ctrl.admin_sq_tail + 1) % ADMIN_QUEUE_SIZE;
    fence(Ordering::SeqCst);
    write_sq_doorbell(ctrl, 0, ctrl.admin_sq_tail);
    cmd.command_id
}

fn admin_wait_completion(ctrl: &mut NvmeController, cmd_id: u16) -> Result<u32, u16> {
    for _ in 0..1_000_000u32 {
        let idx = ctrl.admin_cq_head as usize;
        let entry = unsafe { read_volatile(ctrl.admin_cq.add(idx)) };
        let phase = (entry.status & 1) != 0;
        if phase == ctrl.admin_cq_phase {
            ctrl.admin_cq_head = (ctrl.admin_cq_head + 1) % ADMIN_QUEUE_SIZE;
            if ctrl.admin_cq_head == 0 {
                ctrl.admin_cq_phase = !ctrl.admin_cq_phase;
            }
            write_cq_doorbell(ctrl, 0, ctrl.admin_cq_head);

            let status_code = (entry.status >> 1) & 0x7FF;
            if status_code != 0 {
                return Err(status_code);
            }
            return Ok(entry.dw0);
        }
        thread_yield();
    }
    Err(0xFFFF)
}

// ── I/O command submission ──

fn io_submit(ctrl: &mut NvmeController, cmd: &NvmeSubmCmd) -> u16 {
    let idx = ctrl.io_sq_tail as usize;
    unsafe {
        write_volatile(ctrl.io_sq.add(idx), *cmd);
    }
    ctrl.io_sq_tail = (ctrl.io_sq_tail + 1) % IO_QUEUE_SIZE;
    fence(Ordering::SeqCst);
    write_sq_doorbell(ctrl, 1, ctrl.io_sq_tail);
    cmd.command_id
}

fn io_wait_completion(ctrl: &mut NvmeController, _cmd_id: u16) -> Result<u32, u16> {
    for _ in 0..10_000_000u32 {
        let idx = ctrl.io_cq_head as usize;
        let entry = unsafe { read_volatile(ctrl.io_cq.add(idx)) };
        let phase = (entry.status & 1) != 0;
        if phase == ctrl.io_cq_phase {
            ctrl.io_cq_head = (ctrl.io_cq_head + 1) % IO_QUEUE_SIZE;
            if ctrl.io_cq_head == 0 {
                ctrl.io_cq_phase = !ctrl.io_cq_phase;
            }
            write_cq_doorbell(ctrl, 1, ctrl.io_cq_head);

            let status_code = (entry.status >> 1) & 0x7FF;
            if status_code != 0 {
                return Err(status_code);
            }
            return Ok(entry.dw0);
        }
        thread_yield();
    }
    Err(0xFFFF)
}

// ── Physical address helper ──

unsafe extern "C" {
    fn fut_virt_to_phys(vaddr: *const c_void) -> u64;
}

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { fut_virt_to_phys(ptr as *const c_void) }
}

// ── Controller initialization ──

fn find_nvme_pci() -> Option<(u8, u8, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        // NVMe: class=01 subclass=08 prog_if=02
        if dev.class_code == 0x01 && dev.subclass == 0x08 && dev.prog_if == 0x02 {
            return Some((dev.bus, dev.dev, dev.func));
        }
    }
    None
}

fn controller_disable(bar0: *mut u8) {
    let cc = mmio_read32(bar0, NVME_REG_CC);
    mmio_write32(bar0, NVME_REG_CC, cc & !NVME_CC_EN);
    // Wait for !RDY
    for _ in 0..1_000_000u32 {
        let csts = mmio_read32(bar0, NVME_REG_CSTS);
        if csts & NVME_CSTS_RDY == 0 {
            return;
        }
        thread_yield();
    }
}

fn controller_enable(bar0: *mut u8) -> bool {
    let cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_MPS_4K
           | NVME_CC_AMS_RR | NVME_CC_SHN_NONE | NVME_CC_IOSQES | NVME_CC_IOCQES;
    mmio_write32(bar0, NVME_REG_CC, cc);

    for _ in 0..1_000_000u32 {
        let csts = mmio_read32(bar0, NVME_REG_CSTS);
        if csts & NVME_CSTS_CFS != 0 {
            log("nvme: controller fatal status during enable");
            return false;
        }
        if csts & NVME_CSTS_RDY != 0 {
            return true;
        }
        thread_yield();
    }
    log("nvme: timeout waiting for controller ready");
    false
}

// ── Block device backend callbacks ──

unsafe extern "C" fn nvme_read(
    ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *mut c_void,
) -> FutStatus {
    let ctrl = unsafe { &mut *(ctx as *mut NvmeController) };
    let buf_phys = virt_to_phys(buf as *const u8);

    ctrl.io_cmd_id = ctrl.io_cmd_id.wrapping_add(1);
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_IO_READ;
    cmd.command_id = ctrl.io_cmd_id;
    cmd.nsid = ctrl.nsid;
    cmd.prp1 = buf_phys;
    // For transfers > 4 KiB, prp2 = next page (simplified single-page for now)
    if nsectors * ctrl.ns_block_size as usize > 4096 {
        cmd.prp2 = buf_phys + 4096;
    }
    cmd.cdw10 = lba as u32;            // Starting LBA low
    cmd.cdw11 = (lba >> 32) as u32;    // Starting LBA high
    cmd.cdw12 = (nsectors as u32).saturating_sub(1); // Number of logical blocks (0-based)

    let cid = io_submit(ctrl, &cmd);
    match io_wait_completion(ctrl, cid) {
        Ok(_) => 0,
        Err(e) => -(e as i32),
    }
}

unsafe extern "C" fn nvme_write(
    ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *const c_void,
) -> FutStatus {
    let ctrl = unsafe { &mut *(ctx as *mut NvmeController) };
    let buf_phys = virt_to_phys(buf as *const u8);

    ctrl.io_cmd_id = ctrl.io_cmd_id.wrapping_add(1);
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_IO_WRITE;
    cmd.command_id = ctrl.io_cmd_id;
    cmd.nsid = ctrl.nsid;
    cmd.prp1 = buf_phys;
    if nsectors * ctrl.ns_block_size as usize > 4096 {
        cmd.prp2 = buf_phys + 4096;
    }
    cmd.cdw10 = lba as u32;
    cmd.cdw11 = (lba >> 32) as u32;
    cmd.cdw12 = (nsectors as u32).saturating_sub(1);

    let cid = io_submit(ctrl, &cmd);
    match io_wait_completion(ctrl, cid) {
        Ok(_) => 0,
        Err(e) => -(e as i32),
    }
}

unsafe extern "C" fn nvme_flush(ctx: *mut c_void) -> FutStatus {
    let ctrl = unsafe { &mut *(ctx as *mut NvmeController) };

    ctrl.io_cmd_id = ctrl.io_cmd_id.wrapping_add(1);
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_IO_FLUSH;
    cmd.command_id = ctrl.io_cmd_id;
    cmd.nsid = ctrl.nsid;

    let cid = io_submit(ctrl, &cmd);
    match io_wait_completion(ctrl, cid) {
        Ok(_) => 0,
        Err(e) => -(e as i32),
    }
}

static NVME_BACKEND: FutBlkBackend = FutBlkBackend {
    read: Some(nvme_read),
    write: Some(nvme_write),
    flush: Some(nvme_flush),
};

// ── FFI exports ──

/// Initialize the NVMe controller
/// Scans PCI for NVMe devices, sets up admin + I/O queues, identifies namespace.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn nvme_init() -> i32 {
    log("nvme: scanning PCI for NVMe controllers...");

    let (bus, dev, func) = match find_nvme_pci() {
        Some(bdf) => bdf,
        None => {
            log("nvme: no NVMe controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(b"nvme: found controller at PCI %02x:%02x.%x\n\0".as_ptr(),
                   bus as u32, dev as u32, func as u32);
    }

    // Enable bus mastering and memory space
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06); // Memory Space + Bus Master

    // Read BAR0 (64-bit MMIO)
    let bar0_lo = pci_read32(bus, dev, func, 0x10) & !0xF;
    let bar0_hi = pci_read32(bus, dev, func, 0x14);
    let bar0_phys = (bar0_lo as u64) | ((bar0_hi as u64) << 32);

    if bar0_phys == 0 {
        log("nvme: BAR0 not configured");
        return -2;
    }

    // Map BAR0 MMIO region (at least 0x2000 for registers + doorbells)
    let bar0_size = 0x4000usize;
    let bar0 = unsafe { map_mmio_region(bar0_phys, bar0_size, MMIO_DEFAULT_FLAGS) };
    if bar0.is_null() {
        log("nvme: failed to map BAR0");
        return -3;
    }

    // Read capabilities
    let cap = mmio_read64(bar0, NVME_REG_CAP);
    let mqes = (cap & 0xFFFF) as u16 + 1;  // Maximum Queue Entries Supported
    let dstrd = ((cap >> 32) & 0xF) as u32; // Doorbell Stride (2^(2+dstrd) bytes)
    let doorbell_stride = 4u32 << dstrd;

    let vs = mmio_read32(bar0, NVME_REG_VS);
    unsafe {
        fut_printf(b"nvme: version %d.%d, MQES=%d, doorbell stride=%d\n\0".as_ptr(),
                   (vs >> 16) & 0xFF, (vs >> 8) & 0xFF, mqes as u32, doorbell_stride);
    }

    // Disable controller before configuring queues
    controller_disable(bar0);

    // Allocate admin submission queue (64 entries * 64 bytes = 4 KiB = 1 page)
    let admin_sq = unsafe { alloc_page() as *mut NvmeSubmCmd };
    let admin_cq = unsafe { alloc_page() as *mut NvmeCplEntry };
    if admin_sq.is_null() || admin_cq.is_null() {
        log("nvme: failed to allocate admin queues");
        return -4;
    }

    // Zero the queues
    unsafe {
        core::ptr::write_bytes(admin_sq, 0, ADMIN_QUEUE_SIZE as usize);
        core::ptr::write_bytes(admin_cq, 0, ADMIN_QUEUE_SIZE as usize);
    }

    // Configure admin queue attributes
    let aqa = ((ADMIN_QUEUE_SIZE as u32 - 1) << 16) | (ADMIN_QUEUE_SIZE as u32 - 1);
    mmio_write32(bar0, NVME_REG_AQA, aqa);

    // Set admin queue base addresses (physical)
    let asq_phys = virt_to_phys(admin_sq as *const u8);
    let acq_phys = virt_to_phys(admin_cq as *const u8);
    mmio_write64(bar0, NVME_REG_ASQ, asq_phys);
    mmio_write64(bar0, NVME_REG_ACQ, acq_phys);

    // Mask all interrupts (we poll)
    mmio_write32(bar0, NVME_REG_INTMS, 0xFFFFFFFF);

    // Enable the controller
    if !controller_enable(bar0) {
        return -5;
    }
    log("nvme: controller enabled");

    // Allocate identify buffer (4 KiB)
    let identify_buf = unsafe { alloc_page() };
    if identify_buf.is_null() {
        log("nvme: failed to allocate identify buffer");
        return -6;
    }

    let mut ctrl = NvmeController {
        bar0,
        bar0_size,
        doorbell_stride,
        bus, dev, func,
        admin_sq, admin_cq,
        admin_sq_tail: 0,
        admin_cq_head: 0,
        admin_cq_phase: true,
        admin_cmd_id: 0,
        io_sq: core::ptr::null_mut(),
        io_cq: core::ptr::null_mut(),
        io_sq_tail: 0,
        io_cq_head: 0,
        io_cq_phase: true,
        io_cmd_id: 0,
        ns_block_count: 0,
        ns_block_size: 0,
        nsid: 1,
        identify_buf,
    };

    // ── Identify Controller (CNS=01) ──
    unsafe { core::ptr::write_bytes(identify_buf, 0, 4096); }
    ctrl.admin_cmd_id += 1;
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_ADMIN_IDENTIFY;
    cmd.command_id = ctrl.admin_cmd_id;
    cmd.nsid = 0;
    cmd.prp1 = virt_to_phys(identify_buf);
    cmd.cdw10 = 1; // CNS = 01 (Identify Controller)
    let cid = ctrl.admin_cmd_id;
    admin_submit(&mut ctrl, &cmd);
    if let Err(e) = admin_wait_completion(&mut ctrl, cid) {
        unsafe { fut_printf(b"nvme: identify controller failed: 0x%x\n\0".as_ptr(), e as u32); }
        return -7;
    }
    log("nvme: identify controller OK");

    // ── Identify Namespace (CNS=00, NSID=1) ──
    unsafe { core::ptr::write_bytes(identify_buf, 0, 4096); }
    ctrl.admin_cmd_id += 1;
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_ADMIN_IDENTIFY;
    cmd.command_id = ctrl.admin_cmd_id;
    cmd.nsid = 1;
    cmd.prp1 = virt_to_phys(identify_buf);
    cmd.cdw10 = 0; // CNS = 00 (Identify Namespace)
    let cid = ctrl.admin_cmd_id;
    admin_submit(&mut ctrl, &cmd);
    if let Err(e) = admin_wait_completion(&mut ctrl, cid) {
        unsafe { fut_printf(b"nvme: identify namespace failed: 0x%x\n\0".as_ptr(), e as u32); }
        return -8;
    }

    // Parse namespace capacity and LBA format
    let nsze = unsafe {
        let p = identify_buf as *const u64;
        read_volatile(p) // Namespace Size (bytes 0-7)
    };
    let flbas = unsafe { read_volatile(identify_buf.add(26)) }; // FLBAS (byte 26)
    let lba_format_idx = (flbas & 0x0F) as usize;
    // LBA Format array starts at byte 128, each entry is 4 bytes
    let lbaf = unsafe {
        read_volatile((identify_buf.add(128 + lba_format_idx * 4)) as *const u32)
    };
    let lba_ds = (lbaf >> 16) & 0xFF; // LBA Data Size (power of 2)
    let block_size = if lba_ds >= 9 { 1u32 << lba_ds } else { 512 };

    ctrl.ns_block_count = nsze;
    ctrl.ns_block_size = block_size;

    let size_mb = (nsze * block_size as u64) / (1024 * 1024);
    unsafe {
        fut_printf(b"nvme: ns1: %llu blocks x %u bytes (%llu MiB)\n\0".as_ptr(),
                   nsze, block_size, size_mb);
    }

    // ── Create I/O Completion Queue (QID=1) ──
    let io_cq = unsafe { alloc_page() as *mut NvmeCplEntry };
    let io_sq = unsafe { alloc_page() as *mut NvmeSubmCmd };
    if io_cq.is_null() || io_sq.is_null() {
        log("nvme: failed to allocate I/O queues");
        return -9;
    }
    unsafe {
        core::ptr::write_bytes(io_cq, 0, IO_QUEUE_SIZE as usize);
        core::ptr::write_bytes(io_sq, 0, IO_QUEUE_SIZE as usize);
    }

    // Create I/O CQ
    ctrl.admin_cmd_id += 1;
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_ADMIN_CREATE_IO_CQ;
    cmd.command_id = ctrl.admin_cmd_id;
    cmd.prp1 = virt_to_phys(io_cq as *const u8);
    cmd.cdw10 = ((IO_QUEUE_SIZE as u32 - 1) << 16) | 1;  // QID=1, size
    cmd.cdw11 = 1; // Physically contiguous
    let cid = ctrl.admin_cmd_id;
    admin_submit(&mut ctrl, &cmd);
    if let Err(e) = admin_wait_completion(&mut ctrl, cid) {
        unsafe { fut_printf(b"nvme: create I/O CQ failed: 0x%x\n\0".as_ptr(), e as u32); }
        return -10;
    }

    // Create I/O SQ
    ctrl.admin_cmd_id += 1;
    let mut cmd = NvmeSubmCmd::zeroed();
    cmd.opcode = NVME_ADMIN_CREATE_IO_SQ;
    cmd.command_id = ctrl.admin_cmd_id;
    cmd.prp1 = virt_to_phys(io_sq as *const u8);
    cmd.cdw10 = ((IO_QUEUE_SIZE as u32 - 1) << 16) | 1;  // QID=1, size
    cmd.cdw11 = (1 << 16) | 1; // CQID=1, physically contiguous
    let cid = ctrl.admin_cmd_id;
    admin_submit(&mut ctrl, &cmd);
    if let Err(e) = admin_wait_completion(&mut ctrl, cid) {
        unsafe { fut_printf(b"nvme: create I/O SQ failed: 0x%x\n\0".as_ptr(), e as u32); }
        return -11;
    }

    ctrl.io_sq = io_sq;
    ctrl.io_cq = io_cq;

    log("nvme: I/O queues created");

    // ── Register as block device ──
    let ctrl_ptr = unsafe {
        let p = alloc(core::mem::size_of::<NvmeController>()) as *mut NvmeController;
        core::ptr::write(p, ctrl);
        NVME = Some(core::ptr::read(p));
        p
    };

    let blkdev = unsafe { alloc(core::mem::size_of::<FutBlkDev>()) as *mut FutBlkDev };
    if blkdev.is_null() {
        log("nvme: failed to allocate blkdev");
        return -12;
    }
    unsafe {
        (*blkdev).name = b"nvme0n1\0".as_ptr() as *const c_char;
        (*blkdev).block_size = block_size;
        (*blkdev).block_count = nsze;
        (*blkdev).allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
        (*blkdev).backend = &NVME_BACKEND;
        (*blkdev).backend_ctx = ctrl_ptr as *mut c_void;
        (*blkdev).core = core::ptr::null_mut();
    }

    let mut blkdev_ref = unsafe { &mut *blkdev };
    match register(blkdev_ref) {
        Ok(()) => {
            log("nvme: registered as block device nvme0n1");
            0
        }
        Err(e) => {
            unsafe { fut_printf(b"nvme: blk_register failed: %d\n\0".as_ptr(), e); }
            e
        }
    }
}

/// Get the NVMe namespace block count
#[unsafe(no_mangle)]
pub extern "C" fn nvme_get_block_count() -> u64 {
    unsafe { (*(&raw const NVME)).as_ref().map_or(0, |c| c.ns_block_count) }
}

/// Get the NVMe namespace block size
#[unsafe(no_mangle)]
pub extern "C" fn nvme_get_block_size() -> u32 {
    unsafe { (*(&raw const NVME)).as_ref().map_or(0, |c| c.ns_block_size) }
}

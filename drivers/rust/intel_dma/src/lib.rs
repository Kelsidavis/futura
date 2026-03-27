// SPDX-License-Identifier: MPL-2.0
//
// Intel DMA Engine Driver (IOAT / IDXD / DSA) for Gen 10+
//
// Implements hardware-accelerated DMA copy and fill operations using
// Intel I/O Acceleration Technology (Crystal Beach DMA / CBDMA).
//
// Architecture:
//   - PCI discovery for IOAT (vendor 8086h, device 0B00h-0B0Fh) and
//     DSA/IDXD (device 0CFEh SPR, 1194h MTL), class 08h/01h
//   - BAR0 MMIO for channel registers
//   - Per-channel descriptor ring with completion polling
//   - DMA-accelerated memcpy (opcode 0x00) and memset/fill (opcode 0x01)
//   - Completion writeback with status polling
//
// IOAT DMA Register Map (BAR0):
//   0x00  CHANCNT    Channel Count (8-bit)
//   0x02  XFERCAP    Transfer Capability (8-bit, log2 max size)
//   0x08  INTRDELAY  Interrupt Delay
//   0x10  ATTNSTATUS Attention Status
//
// Per-channel registers at base 0x80 + channel * 0x80:
//   +0x00  CHANCTRL   Channel Control
//   +0x02  CHANSTS    Channel Status (bits[2:0] = active/idle/suspended/halted)
//   +0x04  CHAINADDR  Descriptor Chain Address (64-bit)
//   +0x0C  CHANCMP    Completion Address (64-bit)
//   +0x14  CHANERR    Channel Error
//   +0x18  CHANERRMSK Channel Error Mask
//   +0x1C  DMACOUNT   DMA Count (remaining bytes)
//
// IOAT Descriptor (64 bytes):
//   0x00  size       Transfer size (32-bit)
//   0x04  ctl        Control (INT_EN, SNOOP, COMPL_WRITE, opcode)
//   0x08  src_addr   Source physical address (64-bit)
//   0x10  dst_addr   Destination physical address (64-bit)
//   0x18  next       Next descriptor physical address (64-bit)
//   0x20  reserved   (fill pattern stored here for FILL ops)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{self, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use common::{
    alloc_page, free_page, log, map_mmio_region, thread_yield,
    unmap_mmio_region, MMIO_DEFAULT_FLAGS,
};

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn fut_virt_to_phys(vaddr: *const c_void) -> u64;
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

// ── Static state wrapper ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
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

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { fut_virt_to_phys(ptr as *const c_void) }
}

// ── MMIO helpers ──

fn mmio_read8(base: *mut u8, offset: usize) -> u8 {
    unsafe { read_volatile(base.add(offset)) }
}

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

fn mmio_read64(base: *mut u8, offset: usize) -> u64 {
    let lo = mmio_read32(base, offset) as u64;
    let hi = mmio_read32(base, offset + 4) as u64;
    lo | (hi << 32)
}

fn mmio_write64(base: *mut u8, offset: usize, val: u64) {
    mmio_write32(base, offset, val as u32);
    mmio_write32(base, offset + 4, (val >> 32) as u32);
}

// ── Intel DMA PCI identification ──

const INTEL_VENDOR_ID: u16 = 0x8086;

// IOAT / CBDMA device IDs (Gen 10 Xeon Scalable / Ice Lake)
const IOAT_DEV_ID_MIN: u16 = 0x0B00;
const IOAT_DEV_ID_MAX: u16 = 0x0B0F;

// DSA / IDXD device IDs (Gen 12+)
const DSA_DEV_ID_SPR: u16 = 0x0CFE;  // Sapphire Rapids
const DSA_DEV_ID_MTL: u16 = 0x1194;  // Meteor Lake

// PCI class/subclass for DMA controllers
const PCI_CLASS_SYSTEM: u8    = 0x08;
const PCI_SUBCLASS_DMA: u8   = 0x01;

// PCI command register bits
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;
const PCI_CMD_MEM_SPACE: u16  = 1 << 1;

// ── IOAT Global Registers (BAR0) ──

const REG_CHANCNT: usize     = 0x00;  // Channel Count (8-bit)
const REG_XFERCAP: usize     = 0x02;  // Transfer Capability (8-bit, log2)
const REG_INTRDELAY: usize   = 0x08;  // Interrupt Delay (16-bit)
const REG_ATTNSTATUS: usize  = 0x10;  // Attention Status (32-bit)

// ── IOAT Per-Channel Registers (base = 0x80 + chan * 0x80) ──

const CHAN_REG_BASE: usize    = 0x80;
const CHAN_REG_STRIDE: usize  = 0x80;

const CHAN_CHANCTRL: usize    = 0x00;  // Channel Control (16-bit)
const CHAN_CHANSTS: usize     = 0x02;  // Channel Status (16-bit) -- note: 8-bit status in low bits
const CHAN_CHAINADDR: usize   = 0x04;  // Descriptor Chain Address (64-bit)
const CHAN_CHANCMP: usize     = 0x0C;  // Completion Address (64-bit)
const CHAN_CHANERR: usize     = 0x14;  // Channel Error (32-bit)
const CHAN_CHANERRMSK: usize  = 0x18;  // Channel Error Mask (32-bit)
const CHAN_DMACOUNT: usize    = 0x1C;  // DMA Count (32-bit)

// CHANCTRL bits
const CHANCTRL_ERR_ABORT: u16 = 1 << 0;  // Any-Error-Abort enable
const CHANCTRL_ERR_CMP: u16   = 1 << 2;  // Error completion enable
const CHANCTRL_RESET: u16     = 1 << 5;  // Channel reset

// CHANSTS status field (bits [2:0])
const CHANSTS_ACTIVE: u8      = 0x00;
const CHANSTS_IDLE: u8        = 0x01;
const CHANSTS_SUSPENDED: u8   = 0x02;
const CHANSTS_HALTED: u8      = 0x03;
const CHANSTS_ARMED: u8       = 0x04;

// ── IOAT DMA Descriptor (64 bytes) ──

const DESC_SIZE: usize = 64;

// Descriptor control bits
const CTL_INT_EN: u32          = 1 << 0;   // Interrupt enable
const CTL_SRC_SNOOP_DIS: u32  = 1 << 2;   // Source snoop disable
const CTL_DEST_SNOOP_DIS: u32 = 1 << 4;   // Destination snoop disable
const CTL_COMPL_WRITE: u32    = 1 << 24;  // Completion writeback enable
const CTL_FENCE: u32          = 1 << 25;  // Fence (ordering)
const CTL_NULL: u32            = 1 << 26;  // Null descriptor (no-op)

// Opcode field (bits [27:24] of ctl, but actually shifted into upper nibble)
// In IOAT v3+ the opcode is in bits [31:24] of the control word
const OP_COPY: u32  = 0x00 << 24;  // Memory copy
const OP_FILL: u32  = 0x01 << 24;  // Memory fill
const OP_CRC: u32   = 0x08 << 24;  // CRC generation
const OP_MCRC: u32  = 0x10 << 24;  // Memcpy + CRC

/// IOAT DMA hardware descriptor, 64 bytes, naturally aligned.
/// All addresses are physical.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct IoatDesc {
    size: u32,          // 0x00: transfer size in bytes
    ctl: u32,           // 0x04: control word (opcode, flags)
    src_addr: u64,      // 0x08: source physical address
    dst_addr: u64,      // 0x10: destination physical address
    next: u64,          // 0x18: next descriptor physical address
    fill_pattern: u64,  // 0x20: fill pattern (for FILL ops, otherwise reserved)
    _rsvd1: u64,        // 0x28: reserved / user1
    _rsvd2: u64,        // 0x30: reserved / user2
    _rsvd3: u64,        // 0x38: reserved
}

const _: () = assert!(core::mem::size_of::<IoatDesc>() == 64);

impl IoatDesc {
    const fn zeroed() -> Self {
        Self {
            size: 0,
            ctl: 0,
            src_addr: 0,
            dst_addr: 0,
            next: 0,
            fill_pattern: 0,
            _rsvd1: 0,
            _rsvd2: 0,
            _rsvd3: 0,
        }
    }
}

// ── Completion record ──
//
// The IOAT engine writes a 64-bit completion value to the address
// programmed in CHANCMP.  Bits [2:0] contain the channel status
// and the upper bits contain the physical address of the last
// completed descriptor.

const COMPL_STATUS_MASK: u64 = 0x07;

// ── Driver constants ──

const PAGE_SIZE: usize        = 4096;
const MAX_CHANNELS: usize     = 8;
const DESCS_PER_CHANNEL: usize = 64;  // ring of 64 descriptors per page
const POLL_TIMEOUT: u32       = 100_000;  // max poll iterations

// ── Per-channel driver state ──

struct DmaChannel {
    active: bool,
    chan_base: usize,           // MMIO offset for this channel's registers
    desc_page: *mut u8,        // virtual address of descriptor page
    desc_phys: u64,            // physical address of descriptor page
    compl_page: *mut u8,       // virtual address of completion page
    compl_phys: u64,           // physical address of completion record
    desc_idx: u32,             // next descriptor index to use
    pending: bool,             // descriptor submitted, awaiting completion
}

impl DmaChannel {
    const fn empty() -> Self {
        Self {
            active: false,
            chan_base: 0,
            desc_page: ptr::null_mut(),
            desc_phys: 0,
            compl_page: ptr::null_mut(),
            compl_phys: 0,
            desc_idx: 0,
            pending: false,
        }
    }
}

// ── Controller state ──

struct IoatController {
    present: bool,
    bar0: *mut u8,
    bar0_size: usize,
    bus: u8,
    dev: u8,
    func: u8,
    device_id: u16,
    chan_count: u32,
    xfer_cap: u32,              // max transfer size (1 << xfercap)
    channels: [DmaChannel; MAX_CHANNELS],
}

impl IoatController {
    const fn empty() -> Self {
        Self {
            present: false,
            bar0: ptr::null_mut(),
            bar0_size: 0,
            bus: 0,
            dev: 0,
            func: 0,
            device_id: 0,
            chan_count: 0,
            xfer_cap: 0,
            channels: [
                DmaChannel::empty(), DmaChannel::empty(),
                DmaChannel::empty(), DmaChannel::empty(),
                DmaChannel::empty(), DmaChannel::empty(),
                DmaChannel::empty(), DmaChannel::empty(),
            ],
        }
    }
}

// ── Global state ──

static STATE: StaticCell<IoatController> = StaticCell::new(IoatController::empty());

// ── PCI helpers ──

/// Check whether a PCI device is an Intel IOAT DMA engine.
fn is_ioat_device(pci: &PciDevice) -> bool {
    if pci.vendor_id != INTEL_VENDOR_ID {
        return false;
    }
    // Check class/subclass for DMA controller
    if pci.class_code == PCI_CLASS_SYSTEM && pci.subclass == PCI_SUBCLASS_DMA {
        return true;
    }
    // Also match by known device IDs
    if pci.device_id >= IOAT_DEV_ID_MIN && pci.device_id <= IOAT_DEV_ID_MAX {
        return true;
    }
    if pci.device_id == DSA_DEV_ID_SPR || pci.device_id == DSA_DEV_ID_MTL {
        return true;
    }
    false
}

/// Read BAR0 base address from PCI config space (64-bit capable).
fn pci_read_bar0(bus: u8, dev: u8, func: u8) -> u64 {
    let bar0_lo = pci_read32(bus, dev, func, 0x10);
    // Check if 64-bit BAR (type bits [2:1] == 0b10)
    let is_64bit = (bar0_lo & 0x06) == 0x04;
    let base_lo = (bar0_lo & 0xFFFF_FFF0) as u64;
    if is_64bit {
        let bar0_hi = pci_read32(bus, dev, func, 0x14) as u64;
        base_lo | (bar0_hi << 32)
    } else {
        base_lo
    }
}

/// Determine BAR0 size by writing all-ones and reading back.
fn pci_size_bar0(bus: u8, dev: u8, func: u8) -> usize {
    let orig = pci_read32(bus, dev, func, 0x10);
    pci_write32(bus, dev, func, 0x10, 0xFFFF_FFFF);
    let mask = pci_read32(bus, dev, func, 0x10);
    pci_write32(bus, dev, func, 0x10, orig);
    let size = !(mask & 0xFFFF_FFF0) as usize + 1;
    if size < PAGE_SIZE { PAGE_SIZE } else { size }
}

/// Enable bus-mastering and memory space in PCI command register.
fn pci_enable_device(bus: u8, dev: u8, func: u8) {
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | PCI_CMD_BUS_MASTER | PCI_CMD_MEM_SPACE);
}

// ── Channel register helpers ──

fn chan_base(chan: u32) -> usize {
    CHAN_REG_BASE + (chan as usize) * CHAN_REG_STRIDE
}

fn chan_read16(bar0: *mut u8, chan: u32, reg: usize) -> u16 {
    let offset = chan_base(chan) + reg;
    unsafe { read_volatile(bar0.add(offset) as *const u16) }
}

fn chan_write16(bar0: *mut u8, chan: u32, reg: usize, val: u16) {
    let offset = chan_base(chan) + reg;
    unsafe { write_volatile(bar0.add(offset) as *mut u16, val) }
}

fn chan_read32(bar0: *mut u8, chan: u32, reg: usize) -> u32 {
    mmio_read32(bar0, chan_base(chan) + reg)
}

fn chan_write32(bar0: *mut u8, chan: u32, reg: usize, val: u32) {
    mmio_write32(bar0, chan_base(chan) + reg, val)
}

fn chan_read64(bar0: *mut u8, chan: u32, reg: usize) -> u64 {
    mmio_read64(bar0, chan_base(chan) + reg)
}

fn chan_write64(bar0: *mut u8, chan: u32, reg: usize, val: u64) {
    mmio_write64(bar0, chan_base(chan) + reg, val)
}

// ── Channel management ──

/// Reset a single DMA channel and wait for idle.
fn channel_reset(bar0: *mut u8, chan: u32) -> i32 {
    // Assert channel reset
    chan_write16(bar0, chan, CHAN_CHANCTRL, CHANCTRL_RESET);

    // Wait for reset to complete (channel returns to idle)
    let mut timeout = POLL_TIMEOUT;
    loop {
        let sts = chan_read16(bar0, chan, CHAN_CHANSTS) & 0x07;
        if sts == CHANSTS_IDLE as u16 {
            break;
        }
        if timeout == 0 {
            log("intel_dma: channel reset timeout");
            return -1;
        }
        timeout -= 1;
        thread_yield();
    }

    // Clear errors
    chan_write32(bar0, chan, CHAN_CHANERR, 0xFFFF_FFFF);

    // Configure: enable error-abort and error-completion
    chan_write16(bar0, chan, CHAN_CHANCTRL, CHANCTRL_ERR_ABORT | CHANCTRL_ERR_CMP);

    0
}

/// Initialise a single channel: allocate descriptor and completion pages,
/// set up hardware registers.
fn channel_init(ctrl: &mut IoatController, chan: u32) -> i32 {
    if chan as usize >= MAX_CHANNELS {
        return -1;
    }

    let ch = &mut ctrl.channels[chan as usize];

    // Allocate descriptor page (holds 64 descriptors x 64 bytes = 4096)
    let desc_page = unsafe { alloc_page() };
    if desc_page.is_null() {
        log("intel_dma: failed to alloc descriptor page");
        return -1;
    }
    unsafe { ptr::write_bytes(desc_page, 0, PAGE_SIZE); }
    let desc_phys = virt_to_phys(desc_page);

    // Allocate completion page
    let compl_page = unsafe { alloc_page() };
    if compl_page.is_null() {
        log("intel_dma: failed to alloc completion page");
        unsafe { free_page(desc_page); }
        return -1;
    }
    unsafe { ptr::write_bytes(compl_page, 0, PAGE_SIZE); }
    let compl_phys = virt_to_phys(compl_page);

    ch.desc_page = desc_page;
    ch.desc_phys = desc_phys;
    ch.compl_page = compl_page;
    ch.compl_phys = compl_phys;
    ch.desc_idx = 0;
    ch.chan_base = chan_base(chan);
    ch.pending = false;

    // Reset the channel
    if channel_reset(ctrl.bar0, chan) != 0 {
        unsafe { free_page(desc_page); }
        unsafe { free_page(compl_page); }
        return -1;
    }

    // Program completion address register
    chan_write64(ctrl.bar0, chan, CHAN_CHANCMP, compl_phys);

    ch.active = true;

    unsafe {
        fut_printf(
            b"intel_dma: channel %u ready (desc @ 0x%llx, compl @ 0x%llx)\n\0".as_ptr(),
            chan,
            desc_phys,
            compl_phys,
        );
    }

    0
}

/// Build and submit a DMA copy descriptor on channel 0.
fn submit_copy(ctrl: &mut IoatController, chan: u32, dst: u64, src: u64, len: u32) -> i32 {
    if chan as usize >= ctrl.chan_count as usize {
        return -1;
    }
    let ch = &mut ctrl.channels[chan as usize];
    if !ch.active {
        return -1;
    }

    let idx = ch.desc_idx as usize;
    let desc_ptr = unsafe { ch.desc_page.add(idx * DESC_SIZE) } as *mut IoatDesc;

    // Next descriptor wraps around the ring
    let next_idx = (idx + 1) % DESCS_PER_CHANNEL;
    let next_phys = ch.desc_phys + (next_idx as u64) * (DESC_SIZE as u64);

    let desc = IoatDesc {
        size: len,
        ctl: OP_COPY | CTL_COMPL_WRITE | CTL_FENCE,
        src_addr: src,
        dst_addr: dst,
        next: next_phys,
        fill_pattern: 0,
        _rsvd1: 0,
        _rsvd2: 0,
        _rsvd3: 0,
    };

    // Write descriptor to the ring
    unsafe { ptr::write_volatile(desc_ptr, desc); }
    fence(Ordering::SeqCst);

    // Clear the completion record
    unsafe { write_volatile(ch.compl_page as *mut u64, 0); }
    fence(Ordering::SeqCst);

    // Write the descriptor chain address to start the transfer
    let desc_phys_addr = ch.desc_phys + (idx as u64) * (DESC_SIZE as u64);
    chan_write64(ctrl.bar0, chan, CHAN_CHAINADDR, desc_phys_addr);
    fence(Ordering::SeqCst);

    ch.desc_idx = next_idx as u32;
    ch.pending = true;

    0
}

/// Build and submit a DMA fill descriptor on channel 0.
fn submit_fill(ctrl: &mut IoatController, chan: u32, dst: u64, pattern: u64, len: u32) -> i32 {
    if chan as usize >= ctrl.chan_count as usize {
        return -1;
    }
    let ch = &mut ctrl.channels[chan as usize];
    if !ch.active {
        return -1;
    }

    let idx = ch.desc_idx as usize;
    let desc_ptr = unsafe { ch.desc_page.add(idx * DESC_SIZE) } as *mut IoatDesc;

    let next_idx = (idx + 1) % DESCS_PER_CHANNEL;
    let next_phys = ch.desc_phys + (next_idx as u64) * (DESC_SIZE as u64);

    // For FILL operations, src_addr holds the fill pattern (64-bit)
    let desc = IoatDesc {
        size: len,
        ctl: OP_FILL | CTL_COMPL_WRITE | CTL_FENCE,
        src_addr: pattern,    // fill pattern goes in src_addr field for FILL ops
        dst_addr: dst,
        next: next_phys,
        fill_pattern: pattern,
        _rsvd1: 0,
        _rsvd2: 0,
        _rsvd3: 0,
    };

    unsafe { ptr::write_volatile(desc_ptr, desc); }
    fence(Ordering::SeqCst);

    // Clear completion record
    unsafe { write_volatile(ch.compl_page as *mut u64, 0); }
    fence(Ordering::SeqCst);

    // Submit
    let desc_phys_addr = ch.desc_phys + (idx as u64) * (DESC_SIZE as u64);
    chan_write64(ctrl.bar0, chan, CHAN_CHAINADDR, desc_phys_addr);
    fence(Ordering::SeqCst);

    ch.desc_idx = next_idx as u32;
    ch.pending = true;

    0
}

/// Poll completion status for a channel.
/// Returns: 0 = done, 1 = busy, negative = error.
fn poll_channel(ctrl: &IoatController, chan: u32) -> i32 {
    if chan as usize >= ctrl.chan_count as usize {
        return -2;
    }
    let ch = &ctrl.channels[chan as usize];
    if !ch.active {
        return -2;
    }
    if !ch.pending {
        return 0;  // nothing pending, consider done
    }

    // Read the completion record (64-bit value written by hardware)
    fence(Ordering::SeqCst);
    let compl_val = unsafe { read_volatile(ch.compl_page as *const u64) };

    let status = (compl_val & COMPL_STATUS_MASK) as u8;

    match status {
        CHANSTS_IDLE => 0,       // completed, channel idle
        CHANSTS_ACTIVE => 1,     // still running
        CHANSTS_ARMED => 1,      // armed, about to start
        CHANSTS_HALTED => -1,    // halted on error
        CHANSTS_SUSPENDED => -1, // suspended
        _ => {
            // Also check the hardware status register directly
            let hw_sts = chan_read16(ctrl.bar0, chan, CHAN_CHANSTS) & 0x07;
            if hw_sts == CHANSTS_IDLE as u16 {
                0
            } else if hw_sts == CHANSTS_ACTIVE as u16 || hw_sts == CHANSTS_ARMED as u16 {
                1
            } else {
                -1
            }
        }
    }
}

// ── Exported C API ──

/// Initialise the Intel DMA engine driver.
///
/// Scans PCI for IOAT/DSA devices, maps BAR0, detects channels, and
/// prepares descriptor rings. Call once at boot.
///
/// Returns: 0 on success, -1 if no device found, -2 on init error
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_init() -> i32 {
    let ctrl = unsafe { &mut *STATE.get() };

    if ctrl.present {
        log("intel_dma: already initialised");
        return 0;
    }

    // ── PCI discovery ──

    let count = unsafe { pci_device_count() };
    let mut found = false;

    for i in 0..count {
        let pci = unsafe { &*pci_get_device(i) };
        if !is_ioat_device(pci) {
            continue;
        }

        unsafe {
            fut_printf(
                b"intel_dma: found device %04x:%04x at %02x:%02x.%x (class %02x/%02x)\n\0"
                    .as_ptr(),
                pci.vendor_id as u32,
                pci.device_id as u32,
                pci.bus as u32,
                pci.dev as u32,
                pci.func as u32,
                pci.class_code as u32,
                pci.subclass as u32,
            );
        }

        ctrl.bus = pci.bus;
        ctrl.dev = pci.dev;
        ctrl.func = pci.func;
        ctrl.device_id = pci.device_id;
        found = true;
        break;
    }

    if !found {
        log("intel_dma: no IOAT/DSA device found");
        return -1;
    }

    // ── Enable PCI device ──

    pci_enable_device(ctrl.bus, ctrl.dev, ctrl.func);

    // ── Map BAR0 ──

    let bar0_phys = pci_read_bar0(ctrl.bus, ctrl.dev, ctrl.func);
    if bar0_phys == 0 {
        log("intel_dma: BAR0 not configured");
        return -2;
    }

    let bar0_size = pci_size_bar0(ctrl.bus, ctrl.dev, ctrl.func);
    ctrl.bar0_size = bar0_size;

    unsafe {
        fut_printf(
            b"intel_dma: BAR0 phys=0x%llx size=0x%x\n\0".as_ptr(),
            bar0_phys,
            bar0_size as u32,
        );
    }

    let bar0 = unsafe { map_mmio_region(bar0_phys, bar0_size, MMIO_DEFAULT_FLAGS) };
    if bar0.is_null() {
        log("intel_dma: failed to map BAR0");
        return -2;
    }
    ctrl.bar0 = bar0;

    // ── Read global registers ──

    let chancnt = mmio_read8(ctrl.bar0, REG_CHANCNT);
    let xfercap = mmio_read8(ctrl.bar0, REG_XFERCAP);

    ctrl.chan_count = if chancnt == 0 { 1 } else { chancnt as u32 };
    if ctrl.chan_count > MAX_CHANNELS as u32 {
        ctrl.chan_count = MAX_CHANNELS as u32;
    }
    ctrl.xfer_cap = if xfercap == 0 { 32 } else { xfercap as u32 };

    unsafe {
        fut_printf(
            b"intel_dma: %u channels, max transfer 2^%u bytes\n\0".as_ptr(),
            ctrl.chan_count,
            ctrl.xfer_cap,
        );
    }

    // ── Initialise channels ──

    let mut init_count: u32 = 0;
    for c in 0..ctrl.chan_count {
        if channel_init(ctrl, c) == 0 {
            init_count += 1;
        }
    }

    if init_count == 0 {
        log("intel_dma: no channels initialised");
        unsafe { unmap_mmio_region(ctrl.bar0, ctrl.bar0_size); }
        ctrl.bar0 = ptr::null_mut();
        return -2;
    }

    ctrl.present = true;

    unsafe {
        fut_printf(
            b"intel_dma: initialised %u/%u channels\n\0".as_ptr(),
            init_count,
            ctrl.chan_count,
        );
    }

    0
}

/// Return the number of available DMA channels.
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_channel_count() -> u32 {
    let ctrl = unsafe { &*STATE.get() };
    if !ctrl.present {
        return 0;
    }
    ctrl.chan_count
}

/// Perform a DMA-accelerated memory copy.
///
/// Both `dst_phys` and `src_phys` must be physical addresses accessible
/// to the DMA engine.  Uses channel 0.
///
/// Returns: 0 on success, negative on error
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_memcpy(dst_phys: u64, src_phys: u64, len: u32) -> i32 {
    let ctrl = unsafe { &mut *STATE.get() };
    if !ctrl.present || len == 0 {
        return -1;
    }

    // Validate transfer size against hardware capability
    let max_size = 1u64 << ctrl.xfer_cap;
    if (len as u64) > max_size {
        log("intel_dma: transfer exceeds hardware max");
        return -1;
    }

    // Submit on channel 0
    let rc = submit_copy(ctrl, 0, dst_phys, src_phys, len);
    if rc != 0 {
        return rc;
    }

    // Poll for completion
    let mut timeout = POLL_TIMEOUT;
    loop {
        let status = poll_channel(ctrl, 0);
        if status == 0 {
            ctrl.channels[0].pending = false;
            return 0;
        }
        if status < 0 {
            let err = chan_read32(ctrl.bar0, 0, CHAN_CHANERR);
            unsafe {
                fut_printf(
                    b"intel_dma: memcpy error, chanerr=0x%08x\n\0".as_ptr(),
                    err,
                );
            }
            // Reset channel for next use
            channel_reset(ctrl.bar0, 0);
            chan_write64(ctrl.bar0, 0, CHAN_CHANCMP, ctrl.channels[0].compl_phys);
            ctrl.channels[0].pending = false;
            return -1;
        }
        if timeout == 0 {
            log("intel_dma: memcpy timeout");
            channel_reset(ctrl.bar0, 0);
            chan_write64(ctrl.bar0, 0, CHAN_CHANCMP, ctrl.channels[0].compl_phys);
            ctrl.channels[0].pending = false;
            return -1;
        }
        timeout -= 1;
        thread_yield();
    }
}

/// Perform a DMA-accelerated memory fill (memset).
///
/// Fills `len` bytes at `dst_phys` with the byte value `val`.
/// Uses channel 0.
///
/// Returns: 0 on success, negative on error
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_memset(dst_phys: u64, val: u8, len: u32) -> i32 {
    let ctrl = unsafe { &mut *STATE.get() };
    if !ctrl.present || len == 0 {
        return -1;
    }

    let max_size = 1u64 << ctrl.xfer_cap;
    if (len as u64) > max_size {
        log("intel_dma: fill exceeds hardware max");
        return -1;
    }

    // Build 64-bit fill pattern by repeating the byte
    let b = val as u64;
    let pattern = b
        | (b << 8)
        | (b << 16)
        | (b << 24)
        | (b << 32)
        | (b << 40)
        | (b << 48)
        | (b << 56);

    let rc = submit_fill(ctrl, 0, dst_phys, pattern, len);
    if rc != 0 {
        return rc;
    }

    // Poll for completion
    let mut timeout = POLL_TIMEOUT;
    loop {
        let status = poll_channel(ctrl, 0);
        if status == 0 {
            ctrl.channels[0].pending = false;
            return 0;
        }
        if status < 0 {
            let err = chan_read32(ctrl.bar0, 0, CHAN_CHANERR);
            unsafe {
                fut_printf(
                    b"intel_dma: fill error, chanerr=0x%08x\n\0".as_ptr(),
                    err,
                );
            }
            channel_reset(ctrl.bar0, 0);
            chan_write64(ctrl.bar0, 0, CHAN_CHANCMP, ctrl.channels[0].compl_phys);
            ctrl.channels[0].pending = false;
            return -1;
        }
        if timeout == 0 {
            log("intel_dma: fill timeout");
            channel_reset(ctrl.bar0, 0);
            chan_write64(ctrl.bar0, 0, CHAN_CHANCMP, ctrl.channels[0].compl_phys);
            ctrl.channels[0].pending = false;
            return -1;
        }
        timeout -= 1;
        thread_yield();
    }
}

/// Poll completion status for a DMA channel.
///
/// Returns: 0 = done, 1 = busy, negative = error
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_poll(channel: u32) -> i32 {
    let ctrl = unsafe { &*STATE.get() };
    if !ctrl.present {
        return -2;
    }
    poll_channel(ctrl, channel)
}

/// Check whether an Intel DMA engine is present and initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_dma_is_present() -> bool {
    let ctrl = unsafe { &*STATE.get() };
    ctrl.present
}

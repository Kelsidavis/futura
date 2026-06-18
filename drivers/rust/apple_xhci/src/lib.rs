// SPDX-License-Identifier: MPL-2.0
//! Apple Silicon xHCI USB host controller for Futura OS.
//!
//! What this crate does
//! --------------------
//! Owns the xHCI controller bring-up and transfer engine for the
//! xHCI block hanging off the Apple PCIe root complex.  The caller
//! (apple_xhci.c) does:
//!
//!   * PCIe BAR discovery via rust_apple_pcie_cfg_read32() / link_up()
//!   * Page allocation for the command ring, event ring, and DCBAA
//!     (Device Context Base Address Array) via fut_malloc_pages()
//!   * Plumbing the public C API (apple_xhci_init / enumerate /
//!     control_transfer / bulk_transfer / get_device) through this
//!     crate's FFI surface
//!
//! This crate owns everything once the BAR and the ring buffers are
//! known: register MMIO, controller reset, ring cycle bits, doorbell
//! kicks, Enable Slot enumeration, control / bulk transfer TRBs, and
//! event-ring polling for completion codes.
//!
//! Compatibility note
//! ------------------
//! ARM64 / Apple Silicon only.  The kernel ships a separate x86 xHCI
//! crate at drivers/rust/xhci that uses legacy port-I/O for PCI
//! config — those two crates do the same job for different platforms
//! and may converge later.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// xHCI register layout — capability registers (relative to BAR0 / cap_base)
// ---------------------------------------------------------------------------

const XHCI_CAPLENGTH:  usize = 0x00;
const XHCI_HCSPARAMS1: usize = 0x04;
const XHCI_DBOFF:      usize = 0x14;
const XHCI_RTSOFF:     usize = 0x18;

// Operational registers (relative to op_base = cap_base + CAPLENGTH)
const XHCI_USBCMD:  usize = 0x00;
const XHCI_USBSTS:  usize = 0x04;
const XHCI_CRCR:    usize = 0x18;
const XHCI_DCBAAP:  usize = 0x30;
const XHCI_CONFIG:  usize = 0x38;

// USBCMD bits
const XHCI_CMD_RUN:   u32 = 1 << 0;
const XHCI_CMD_HCRST: u32 = 1 << 1;
const XHCI_CMD_INTE:  u32 = 1 << 2;

// USBSTS bits
const XHCI_STS_HCH:  u32 = 1 << 0;   // HC halted
const XHCI_STS_CNR:  u32 = 1 << 11;  // Controller not ready

// TRB types
const TRB_NORMAL:       u32 = 1;
const TRB_SETUP:        u32 = 2;
const TRB_DATA:         u32 = 3;
const TRB_STATUS:       u32 = 4;
const TRB_LINK:         u32 = 6;
const TRB_ENABLE_SLOT:  u32 = 9;
const TRB_ADDRESS_DEV:  u32 = 11;
const TRB_CMD_COMPLETE: u32 = 33;
const TRB_PORT_STATUS:  u32 = 34;

// TRB flags
const TRB_FLAG_CYCLE: u32 = 1 << 0;
const TRB_FLAG_IOC:   u32 = 1 << 5;

// Completion codes
const CC_SUCCESS:      u8 = 1;
const CC_SHORT_PACKET: u8 = 13;

// Ring sizing — must match the C-side page allocation (1 page = 4 KiB ÷ 16 B
// per TRB = 256 entries, but the controller's wrap-link semantics need a
// power-of-two budget; we cap at 64 entries to match the original C driver
// and leave most of the page unused as scratch).
const CMD_RING_SIZE: usize = 64;
const EVT_RING_SIZE: usize = 64;

// PORTSC: bit 0 = CCS (Current Connect Status), bit 1 = PED (Port Enabled)
const PORTSC_CCS: u32 = 1 << 0;
const PORTSC_PED: u32 = 1 << 1;

const XHCI_MAX_SLOTS: u32 = 32;

// ---------------------------------------------------------------------------
// Transfer Request Block — 16 bytes, little-endian, matches the xHCI spec
// and the C-side xhci_trb_t.
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Trb {
    param:   u64,
    status:  u32,
    control: u32,
}

// ---------------------------------------------------------------------------
// Controller state — one of these per host controller.  Singleton in
// practice on Apple Silicon (one xHCI per PCIe RC) but the FFI is
// instance-based for symmetry with the rest of the apple_* crates.
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct AppleXhci {
    cap_base: *mut u8,
    op_base:  *mut u8,
    rt_base:  *mut u8,
    db_base:  *mut u8,

    // Ring buffers — allocated by the C caller, never freed by this crate.
    // Each carries BOTH a kernel VA (used by Rust to read/write TRBs and
    // DCBAA entries from CPU code) AND a physical address (written into
    // CRCR / DCBAAP / TRB.param so the xHCI controller can DMA the right
    // pages).  On QEMU virt the two values happen to be equal because the
    // boot identity map covers low-PA DRAM; on Apple Silicon they differ
    // because m1n1 drops the kernel image high in DRAM and PMM allocates
    // physically-high pages that the kernel reaches through the high-half
    // VA mapping.
    cmd_ring:    *mut Trb,
    cmd_ring_pa: u64,
    evt_ring:    *mut Trb,
    evt_ring_pa: u64,
    dcbaa:       *mut u64,
    dcbaa_pa:    u64,

    max_slots: u32,
    max_ports: u32,

    cmd_enqueue: u32,
    evt_dequeue: u32,
    cmd_cycle:   u8,
    evt_cycle:   u8,
}

// SAFETY: AppleXhci holds raw MMIO pointers; the C side is single-threaded
// per controller and this crate never touches it concurrently.
unsafe impl Send for AppleXhci {}
unsafe impl Sync for AppleXhci {}

// Singleton — one xHCI per PCIe RC on Apple Silicon.  Stored as a static
// so the C caller does not need to know the Rust struct size.
static mut G_XHCI: AppleXhci = AppleXhci {
    cap_base:    core::ptr::null_mut(),
    op_base:     core::ptr::null_mut(),
    rt_base:     core::ptr::null_mut(),
    db_base:     core::ptr::null_mut(),
    cmd_ring:    core::ptr::null_mut(),
    cmd_ring_pa: 0,
    evt_ring:    core::ptr::null_mut(),
    evt_ring_pa: 0,
    dcbaa:       core::ptr::null_mut(),
    dcbaa_pa:    0,
    max_slots:   0,
    max_ports:   0,
    cmd_enqueue: 0,
    evt_dequeue: 0,
    cmd_cycle:   1,
    evt_cycle:   1,
};

// ---------------------------------------------------------------------------
// MMIO helpers — volatile, byte-offset addressing.
// ---------------------------------------------------------------------------

#[inline(always)]
fn r32(base: *mut u8, off: usize) -> u32 {
    unsafe { read_volatile(base.add(off) as *const u32) }
}

#[inline(always)]
fn w32(base: *mut u8, off: usize, val: u32) {
    unsafe { write_volatile(base.add(off) as *mut u32, val) }
}

#[inline(always)]
fn w64(base: *mut u8, off: usize, val: u64) {
    unsafe {
        write_volatile(base.add(off) as *mut u64, val);
    }
}

// ---------------------------------------------------------------------------
// Controller reset / bring-up
// ---------------------------------------------------------------------------

fn reset_controller(ctrl: &AppleXhci) -> bool {
    // Halt
    let cmd = r32(ctrl.op_base, XHCI_USBCMD);
    w32(ctrl.op_base, XHCI_USBCMD, cmd & !XHCI_CMD_RUN);

    for _ in 0..100_000 {
        if r32(ctrl.op_base, XHCI_USBSTS) & XHCI_STS_HCH != 0 {
            break;
        }
    }

    // Reset
    w32(ctrl.op_base, XHCI_USBCMD, XHCI_CMD_HCRST);
    for _ in 0..100_000 {
        if r32(ctrl.op_base, XHCI_USBCMD) & XHCI_CMD_HCRST == 0 {
            break;
        }
    }

    // Wait for controller ready
    for _ in 0..100_000 {
        if r32(ctrl.op_base, XHCI_USBSTS) & XHCI_STS_CNR == 0 {
            return true;
        }
    }
    false
}

fn start_controller(ctrl: &AppleXhci) -> bool {
    let slots = if ctrl.max_slots < XHCI_MAX_SLOTS { ctrl.max_slots } else { XHCI_MAX_SLOTS };
    w32(ctrl.op_base, XHCI_CONFIG, slots);

    /* DCBAAP and CRCR take PHYSICAL addresses — the controller DMAs
     * the device context array and command-ring TRBs directly without
     * going through the CPU's page tables.  Use the cached _pa
     * fields, not the kernel VAs the CPU reads/writes through. */
    w64(ctrl.op_base, XHCI_DCBAAP, ctrl.dcbaa_pa);

    let crcr = ctrl.cmd_ring_pa | (ctrl.cmd_cycle as u64);
    w64(ctrl.op_base, XHCI_CRCR, crcr);

    let cmd = r32(ctrl.op_base, XHCI_USBCMD);
    w32(ctrl.op_base, XHCI_USBCMD, cmd | XHCI_CMD_RUN | XHCI_CMD_INTE);

    for _ in 0..100_000 {
        if r32(ctrl.op_base, XHCI_USBSTS) & XHCI_STS_HCH == 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Command / event ring helpers
// ---------------------------------------------------------------------------

fn ring_cmd_doorbell(ctrl: &AppleXhci) {
    w32(ctrl.db_base, 0, 0);
}

fn ring_slot_doorbell(ctrl: &AppleXhci, slot_id: u8, dci: u32) {
    w32(ctrl.db_base, (slot_id as usize) * 4, dci);
}

fn next_event(ctrl: &mut AppleXhci) -> Option<Trb> {
    for _ in 0..100_000 {
        let trb = unsafe { read_volatile(ctrl.evt_ring.add(ctrl.evt_dequeue as usize)) };
        let cycle = trb.control & TRB_FLAG_CYCLE;
        if (cycle != 0) == (ctrl.evt_cycle != 0) {
            ctrl.evt_dequeue += 1;
            if ctrl.evt_dequeue as usize >= EVT_RING_SIZE {
                ctrl.evt_dequeue = 0;
                ctrl.evt_cycle ^= 1;
            }
            return Some(trb);
        }
        // Tiny stall between polls
        for _ in 0..100 {
            unsafe { core::arch::asm!("nop") };
        }
    }
    None
}

fn enqueue_trb(ctrl: &mut AppleXhci, trb: Trb) {
    unsafe {
        write_volatile(ctrl.cmd_ring.add(ctrl.cmd_enqueue as usize), trb);
    }
    ctrl.cmd_enqueue += 1;
    // Reserve the last slot for a LINK TRB that points the controller back to
    // the start of the ring and toggles the cycle state. Without it the
    // enqueue pointer (and the controller's dequeue pointer, which only wraps
    // on a LINK TRB) would walk off the 64-entry command ring after a handful
    // of transfers and eventually past the backing page.
    if ctrl.cmd_enqueue as usize >= CMD_RING_SIZE - 1 {
        let cycle_bit = if ctrl.cmd_cycle != 0 { TRB_FLAG_CYCLE } else { 0 };
        let link = Trb {
            param:   ctrl.cmd_ring_pa,
            status:  0,
            // LINK TRB with Toggle Cycle (TC, bit 1) set so the controller
            // flips its consumer cycle bit when it follows the link.
            control: (TRB_LINK << 10) | (1 << 1) | cycle_bit,
        };
        unsafe {
            write_volatile(ctrl.cmd_ring.add(CMD_RING_SIZE - 1), link);
        }
        ctrl.cmd_enqueue = 0;
        ctrl.cmd_cycle ^= 1;
    }
}

// ---------------------------------------------------------------------------
// Enumeration — issue Enable Slot for every connected+enabled port
// ---------------------------------------------------------------------------

fn enable_slot(ctrl: &mut AppleXhci) -> Option<u8> {
    let cycle_bit = if ctrl.cmd_cycle != 0 { TRB_FLAG_CYCLE } else { 0 };
    let trb = Trb {
        param: 0,
        status: 0,
        control: (TRB_ENABLE_SLOT << 10) | cycle_bit,
    };
    enqueue_trb(ctrl, trb);
    ring_cmd_doorbell(ctrl);

    let evt = next_event(ctrl)?;
    let trb_type = (evt.control >> 10) & 0x3F;
    if trb_type != TRB_CMD_COMPLETE {
        return None;
    }
    let slot_id  = ((evt.control >> 24) & 0xFF) as u8;
    let comp_code = ((evt.status >> 24) & 0xFF) as u8;
    if comp_code == CC_SUCCESS && slot_id > 0 {
        Some(slot_id)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

fn control_transfer_inner(
    ctrl: &mut AppleXhci,
    slot_id: u8,
    bm_req_type: u8,
    b_req: u8,
    w_value: u16,
    w_index: u16,
    data_pa: u64,
    w_length: u16,
) -> i32 {
    if slot_id == 0 {
        return -1;
    }

    let cycle_bit = if ctrl.cmd_cycle != 0 { TRB_FLAG_CYCLE } else { 0 };
    let dir_in    = (bm_req_type & 0x80) != 0;

    // Setup stage
    let setup_param = (bm_req_type as u64)
        | ((b_req as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((w_length as u64) << 48);
    let setup = Trb {
        param:   setup_param,
        status:  8,
        control: (TRB_SETUP << 10) | cycle_bit | (3 << 16), // IDT
    };
    enqueue_trb(ctrl, setup);

    // Data stage (if any) — TRB.param is a PHYSICAL address that the
    // xHCI controller DMAs from/to; the caller must hand us the PA,
    // not a kernel VA.
    if w_length > 0 && data_pa != 0 {
        let dir_bit = if dir_in { 1u32 << 16 } else { 0 };
        let data_trb = Trb {
            param:   data_pa,
            status:  w_length as u32,
            control: (TRB_DATA << 10) | cycle_bit | dir_bit,
        };
        enqueue_trb(ctrl, data_trb);
    }

    // Status stage — direction is opposite of data direction (or IN if no data)
    let status_dir_bit = if dir_in { 0 } else { 1u32 << 16 };
    let status = Trb {
        param:   0,
        status:  0,
        control: (TRB_STATUS << 10) | TRB_FLAG_IOC | cycle_bit | status_dir_bit,
    };
    enqueue_trb(ctrl, status);

    // Ring control endpoint (EP0 = DCI 1)
    ring_slot_doorbell(ctrl, slot_id, 1);

    let evt = match next_event(ctrl) { Some(e) => e, None => return -1 };
    let comp_code = ((evt.status >> 24) & 0xFF) as u8;
    if comp_code == CC_SUCCESS { w_length as i32 } else { -1 }
}

fn bulk_transfer_inner(
    ctrl: &mut AppleXhci,
    slot_id: u8,
    endpoint: u8,
    data_pa: u64,
    length: u32,
) -> i32 {
    if slot_id == 0 || data_pa == 0 || length == 0 {
        return -1;
    }

    let cycle_bit = if ctrl.cmd_cycle != 0 { TRB_FLAG_CYCLE } else { 0 };
    let trb = Trb {
        /* PHYSICAL address — xHCI DMAs the bulk-data buffer directly
         * (no IOMMU on the Apple PCIe xHCI variant), so the caller
         * must hand us the PA, not a kernel VA. */
        param:   data_pa,
        status:  length,
        control: (TRB_NORMAL << 10) | TRB_FLAG_IOC | cycle_bit,
    };
    enqueue_trb(ctrl, trb);

    // DCI = ep_num * 2 + direction
    let ep_num = endpoint & 0x0F;
    let dir    = if endpoint & 0x80 != 0 { 1 } else { 0 };
    let dci    = (ep_num as u32) * 2 + dir;
    ring_slot_doorbell(ctrl, slot_id, dci);

    let evt = match next_event(ctrl) { Some(e) => e, None => return -1 };
    let comp_code = ((evt.status >> 24) & 0xFF) as u8;
    let residual  = evt.status & 0x00FF_FFFF;
    if comp_code == CC_SUCCESS || comp_code == CC_SHORT_PACKET {
        (length - residual) as i32
    } else {
        -1
    }
}

// ===========================================================================
//   FFI surface
// ===========================================================================

/// Bind the singleton controller to a discovered BAR plus three
/// page-aligned buffers allocated by the C caller (cmd ring, event
/// ring, DCBAA).  Each must be at least 4 KiB and pre-zeroed.  Each
/// ring takes BOTH a kernel VA (used by Rust for CPU read/write of
/// TRBs and DCBAA entries) AND a physical address (written into the
/// controller's CRCR / DCBAAP registers for DMA — the controller
/// does not consult the CPU's page tables).
///
/// Returns the singleton handle pointer for use in subsequent calls,
/// or NULL on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_new(
    cap_base:    u64,
    cmd_ring:    *mut u8,
    cmd_ring_pa: u64,
    evt_ring:    *mut u8,
    evt_ring_pa: u64,
    dcbaa:       *mut u8,
    dcbaa_pa:    u64,
) -> *mut AppleXhci {
    if cap_base == 0
        || cmd_ring.is_null() || cmd_ring_pa == 0
        || evt_ring.is_null() || evt_ring_pa == 0
        || dcbaa.is_null()    || dcbaa_pa    == 0
    {
        return core::ptr::null_mut();
    }
    let cap_base = cap_base as *mut u8;
    let caplen = unsafe { read_volatile(cap_base) } as usize;
    let op_base = unsafe { cap_base.add(caplen) };

    let rtsoff = (r32(cap_base, XHCI_RTSOFF) & !0x1F) as usize;
    let rt_base = unsafe { cap_base.add(rtsoff) };

    let dboff = (r32(cap_base, XHCI_DBOFF) & !0x3) as usize;
    let db_base = unsafe { cap_base.add(dboff) };

    let hcs1 = r32(cap_base, XHCI_HCSPARAMS1);
    let max_slots = hcs1 & 0xFF;
    let max_ports = (hcs1 >> 24) & 0xFF;

    let ctrl = unsafe { &mut *(&raw mut G_XHCI) };
    ctrl.cap_base    = cap_base;
    ctrl.op_base     = op_base;
    ctrl.rt_base     = rt_base;
    ctrl.db_base     = db_base;
    ctrl.cmd_ring    = cmd_ring as *mut Trb;
    ctrl.cmd_ring_pa = cmd_ring_pa;
    ctrl.evt_ring    = evt_ring as *mut Trb;
    ctrl.evt_ring_pa = evt_ring_pa;
    ctrl.dcbaa       = dcbaa as *mut u64;
    ctrl.dcbaa_pa    = dcbaa_pa;
    ctrl.max_slots   = max_slots;
    ctrl.max_ports   = max_ports;
    ctrl.cmd_enqueue = 0;
    ctrl.evt_dequeue = 0;
    ctrl.cmd_cycle   = 1;
    ctrl.evt_cycle   = 1;
    ctrl as *mut AppleXhci
}

/// Reset and start the controller.  Returns 0 on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_reset_and_start(ctrl: *mut AppleXhci) -> i32 {
    if ctrl.is_null() {
        return -1;
    }
    let c = unsafe { &mut *ctrl };
    if !reset_controller(c) {
        return -2;
    }
    if !start_controller(c) {
        return -3;
    }
    0
}

/// Read MaxSlots from HCSPARAMS1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_max_slots(ctrl: *const AppleXhci) -> u32 {
    if ctrl.is_null() { return 0; }
    unsafe { (*ctrl).max_slots }
}

/// Read MaxPorts from HCSPARAMS1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_max_ports(ctrl: *const AppleXhci) -> u32 {
    if ctrl.is_null() { return 0; }
    unsafe { (*ctrl).max_ports }
}

/// Walk each root-hub port, look for a connected+enabled device, and if
/// found issue Enable Slot.  Writes the resulting `(port, slot_id)`
/// pairs into the caller-supplied arrays.  Returns the number of
/// devices found, or a negative errno.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_enumerate(
    ctrl:      *mut AppleXhci,
    out_ports: *mut u8,
    out_slots: *mut u8,
    max_devs:  u32,
) -> i32 {
    if ctrl.is_null() || out_ports.is_null() || out_slots.is_null() {
        return -1;
    }
    let c = unsafe { &mut *ctrl };
    let mut found = 0u32;

    for port in 0..c.max_ports {
        if found >= max_devs { break; }
        let portsc_off = 0x400 + (port as usize) * 0x10;
        let portsc = r32(c.op_base, portsc_off);
        let connected = portsc & PORTSC_CCS != 0;
        let enabled   = portsc & PORTSC_PED != 0;
        if !(connected && enabled) {
            continue;
        }
        if let Some(slot) = enable_slot(c) {
            unsafe {
                write_volatile(out_ports.add(found as usize), port as u8);
                write_volatile(out_slots.add(found as usize), slot);
            }
            found += 1;
        }
    }

    found as i32
}

/// USB control transfer on EP0.  `data_pa` is the PHYSICAL address of
/// the data buffer (may be 0 when `w_length == 0`); the controller
/// DMAs from/to it without consulting the CPU page tables.  Returns
/// bytes transferred on success, or a negative errno.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_control_transfer(
    ctrl:        *mut AppleXhci,
    slot_id:     u8,
    bm_req_type: u8,
    b_req:       u8,
    w_value:     u16,
    w_index:     u16,
    data_pa:     u64,
    w_length:    u16,
) -> i32 {
    if ctrl.is_null() { return -1; }
    let c = unsafe { &mut *ctrl };
    control_transfer_inner(c, slot_id, bm_req_type, b_req, w_value, w_index, data_pa, w_length)
}

/// USB bulk transfer.  `data_pa` is the PHYSICAL address of the bulk
/// buffer.  Returns bytes transferred on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_xhci_bulk_transfer(
    ctrl:     *mut AppleXhci,
    slot_id:  u8,
    endpoint: u8,
    data_pa:  u64,
    length:   u32,
) -> i32 {
    if ctrl.is_null() { return -1; }
    let c = unsafe { &mut *ctrl };
    bulk_transfer_inner(c, slot_id, endpoint, data_pa, length)
}

// ---------------------------------------------------------------------------
// Panic handler — required for a no_std staticlib.  Spin forever; the
// kernel side will notice via watchdog rather than via stack unwinding.
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// SPDX-License-Identifier: MPL-2.0
//
// xHCI (eXtensible Host Controller Interface) USB 3.x Host Controller Driver
//
// Implements the xHCI 1.2 specification for USB host controllers,
// the standard USB interface on AMD Ryzen AM4/AM5 platforms.
//
// Architecture:
//   - Capability, Operational, Runtime, and Doorbell register spaces
//   - Device Context Base Address Array (DCBAA)
//   - Command Ring (producer) and Event Ring (consumer) with TRBs
//   - Scratchpad buffer allocation per controller request
//   - Root hub port power-on, reset, and speed detection
//   - Polling-based event handling (interrupt support planned)
//
// PCI class: 0Ch (Serial Bus), subclass 03h (USB), prog-if 30h (xHCI)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ffi::{c_char, c_void};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{
    alloc, alloc_page, free, free_page, log, map_mmio_region, thread_sleep, thread_yield,
    unmap_mmio_region, MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
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

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

// ── MMIO helpers ──

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

// ── xHCI Capability Registers (offset from BAR0) ──

const XHCI_CAP_CAPLENGTH: usize = 0x00;   // 1 byte: Capability Register Length
const XHCI_CAP_HCIVERSION: usize = 0x02;  // 2 bytes: Interface Version Number
const XHCI_CAP_HCSPARAMS1: usize = 0x04;  // Structural Parameters 1
const XHCI_CAP_HCSPARAMS2: usize = 0x08;  // Structural Parameters 2
const XHCI_CAP_HCSPARAMS3: usize = 0x0C;  // Structural Parameters 3
const XHCI_CAP_HCCPARAMS1: usize = 0x10;  // Capability Parameters 1
const XHCI_CAP_DBOFF: usize = 0x14;       // Doorbell Offset
const XHCI_CAP_RTSOFF: usize = 0x18;      // Runtime Register Space Offset
const XHCI_CAP_HCCPARAMS2: usize = 0x1C;  // Capability Parameters 2

// ── xHCI Operational Registers (offset from BAR0 + CAPLENGTH) ──

const XHCI_OP_USBCMD: usize = 0x00;      // USB Command
const XHCI_OP_USBSTS: usize = 0x04;      // USB Status
const XHCI_OP_PAGESIZE: usize = 0x08;    // Page Size
const XHCI_OP_DNCTRL: usize = 0x14;      // Device Notification Control
const XHCI_OP_CRCR: usize = 0x18;        // Command Ring Control (64-bit)
const XHCI_OP_DCBAAP: usize = 0x30;      // Device Context Base Address Array Pointer (64-bit)
const XHCI_OP_CONFIG: usize = 0x38;      // Configure

// Port register set starts at operational base + 0x400
const XHCI_OP_PORTS_BASE: usize = 0x400;
const XHCI_PORT_REG_SIZE: usize = 0x10;   // Each port occupies 16 bytes

// Port register offsets within a port register set
const XHCI_PORTSC: usize = 0x00;          // Port Status and Control
const XHCI_PORTPMSC: usize = 0x04;        // Port Power Management Status and Control
const XHCI_PORTLI: usize = 0x08;          // Port Link Info
const XHCI_PORTHLPMC: usize = 0x0C;       // Port Hardware LPM Control

// ── USBCMD register bits ──

const USBCMD_RUN: u32 = 1 << 0;           // Run/Stop (RS)
const USBCMD_HCRST: u32 = 1 << 1;         // Host Controller Reset (HCRST)
const USBCMD_INTE: u32 = 1 << 2;          // Interrupter Enable (INTE)
const USBCMD_HSEE: u32 = 1 << 3;          // Host System Error Enable

// ── USBSTS register bits ──

const USBSTS_HCH: u32 = 1 << 0;           // HC Halted
const USBSTS_HSE: u32 = 1 << 2;           // Host System Error
const USBSTS_EINT: u32 = 1 << 3;          // Event Interrupt
const USBSTS_PCD: u32 = 1 << 4;           // Port Change Detect
const USBSTS_CNR: u32 = 1 << 11;          // Controller Not Ready

// ── PORTSC register bits ──

const PORTSC_CCS: u32 = 1 << 0;           // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;           // Port Enabled/Disabled
const PORTSC_OCA: u32 = 1 << 3;           // Over-current Active
const PORTSC_PR: u32 = 1 << 4;            // Port Reset
const PORTSC_PLS_MASK: u32 = 0xF << 5;    // Port Link State
const PORTSC_PLS_SHIFT: u32 = 5;
const PORTSC_PP: u32 = 1 << 9;            // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed
const PORTSC_SPEED_SHIFT: u32 = 10;
const PORTSC_PIC_MASK: u32 = 0x3 << 14;   // Port Indicator Control
const PORTSC_LWS: u32 = 1 << 16;          // Port Link State Write Strobe
const PORTSC_CSC: u32 = 1 << 17;          // Connect Status Change
const PORTSC_PEC: u32 = 1 << 18;          // Port Enabled/Disabled Change
const PORTSC_WRC: u32 = 1 << 19;          // Warm Port Reset Change
const PORTSC_OCC: u32 = 1 << 20;          // Over-current Change
const PORTSC_PRC: u32 = 1 << 21;          // Port Reset Change
const PORTSC_PLC: u32 = 1 << 22;          // Port Link State Change
const PORTSC_CEC: u32 = 1 << 23;          // Port Config Error Change
const PORTSC_CAS: u32 = 1 << 24;          // Cold Attach Status
const PORTSC_WCE: u32 = 1 << 25;          // Wake on Connect Enable
const PORTSC_WDE: u32 = 1 << 26;          // Wake on Disconnect Enable
const PORTSC_WOE: u32 = 1 << 27;          // Wake on Over-current Enable
const PORTSC_DR: u32 = 1 << 30;           // Device Removable
const PORTSC_WPR: u32 = 1u32 << 31;       // Warm Port Reset

// Bits that are RW1C in PORTSC - must be preserved (not accidentally cleared)
const PORTSC_CHANGE_BITS: u32 =
    PORTSC_CSC | PORTSC_PEC | PORTSC_WRC | PORTSC_OCC | PORTSC_PRC | PORTSC_PLC | PORTSC_CEC;

// Port Link State values
const PLS_U0: u32 = 0;                    // U0 (active)
const PLS_U3: u32 = 3;                    // U3 (suspended)
const PLS_DISABLED: u32 = 4;              // Disabled
const PLS_RXDETECT: u32 = 5;              // RxDetect
const PLS_POLLING: u32 = 7;               // Polling
const PLS_RECOVERY: u32 = 8;              // Recovery
const PLS_COMPLIANCE: u32 = 10;           // Compliance Mode
const PLS_RESUME: u32 = 15;               // Resume

// Port speed values (PORTSC bits [13:10])
const SPEED_FULL: u32 = 1;                // Full Speed (12 Mb/s)
const SPEED_LOW: u32 = 2;                 // Low Speed (1.5 Mb/s)
const SPEED_HIGH: u32 = 3;                // High Speed (480 Mb/s)
const SPEED_SUPER: u32 = 4;               // SuperSpeed (5 Gb/s)
const SPEED_SUPER_PLUS: u32 = 5;          // SuperSpeedPlus (10 Gb/s)

// ── Runtime Register offsets (from RTSOFF) ──

const XHCI_RT_MFINDEX: usize = 0x00;      // Microframe Index
// Interrupter Register Set 0 starts at RTSOFF + 0x20
const XHCI_RT_IR0: usize = 0x20;
const XHCI_IR_IMAN: usize = 0x00;         // Interrupter Management
const XHCI_IR_IMOD: usize = 0x04;         // Interrupter Moderation
const XHCI_IR_ERSTSZ: usize = 0x08;       // Event Ring Segment Table Size
const XHCI_IR_ERSTBA: usize = 0x10;       // Event Ring Segment Table Base Address (64-bit)
const XHCI_IR_ERDP: usize = 0x18;         // Event Ring Dequeue Pointer (64-bit)

// ── CRCR (Command Ring Control Register) bits ──

const CRCR_RCS: u64 = 1 << 0;             // Ring Cycle State
const CRCR_CS: u64 = 1 << 1;              // Command Stop
const CRCR_CA: u64 = 1 << 2;              // Command Abort
const CRCR_CRR: u64 = 1 << 3;            // Command Ring Running

// ── TRB (Transfer Request Block) ── 16 bytes ──

#[repr(C)]
#[derive(Clone, Copy)]
struct Trb {
    param: u64,       // Parameter (TRB-type specific)
    status: u32,      // Status (TRB-type specific)
    control: u32,     // Control: cycle bit, TRB type, flags
}

const _: () = assert!(core::mem::size_of::<Trb>() == 16);

impl Trb {
    const fn zeroed() -> Self {
        Self {
            param: 0,
            status: 0,
            control: 0,
        }
    }
}

// TRB Control field layout
const TRB_CYCLE: u32 = 1 << 0;            // Cycle bit
const TRB_TC: u32 = 1 << 1;               // Toggle Cycle (for Link TRBs)
const TRB_ENT: u32 = 1 << 1;              // Evaluate Next TRB
const TRB_ISP: u32 = 1 << 2;              // Interrupt on Short Packet
const TRB_CH: u32 = 1 << 4;               // Chain bit
const TRB_IOC: u32 = 1 << 5;              // Interrupt On Completion
const TRB_IDT: u32 = 1 << 6;              // Immediate Data
const TRB_BSR: u32 = 1 << 9;              // Block Set Address Request

// TRB Type field: bits [15:10]
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_TYPE_MASK: u32 = 0x3F << TRB_TYPE_SHIFT;

// Transfer TRB types
const TRB_TYPE_NORMAL: u32 = 1;
const TRB_TYPE_SETUP: u32 = 2;
const TRB_TYPE_DATA: u32 = 3;
const TRB_TYPE_STATUS: u32 = 4;
const TRB_TYPE_ISOCH: u32 = 5;
const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_EVENT_DATA: u32 = 7;
const TRB_TYPE_NOOP: u32 = 8;

// Command TRB types
const TRB_TYPE_ENABLE_SLOT: u32 = 9;
const TRB_TYPE_DISABLE_SLOT: u32 = 10;
const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
const TRB_TYPE_CONFIG_EP: u32 = 12;
const TRB_TYPE_EVAL_CONTEXT: u32 = 13;
const TRB_TYPE_RESET_EP: u32 = 14;
const TRB_TYPE_STOP_EP: u32 = 15;
const TRB_TYPE_SET_TR_DEQUEUE: u32 = 16;
const TRB_TYPE_RESET_DEVICE: u32 = 17;
const TRB_TYPE_FORCE_EVENT: u32 = 18;
const TRB_TYPE_NEGOTIATE_BW: u32 = 19;
const TRB_TYPE_SET_LATENCY: u32 = 20;
const TRB_TYPE_GET_PORT_BW: u32 = 21;
const TRB_TYPE_FORCE_HEADER: u32 = 22;
const TRB_TYPE_NOOP_CMD: u32 = 23;

// Event TRB types
const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
const TRB_TYPE_CMD_COMPLETION: u32 = 33;
const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;
const TRB_TYPE_BW_REQUEST: u32 = 35;
const TRB_TYPE_DOORBELL_EVENT: u32 = 36;
const TRB_TYPE_HOST_CONTROLLER: u32 = 37;
const TRB_TYPE_DEVICE_NOTIFICATION: u32 = 38;
const TRB_TYPE_MFINDEX_WRAP: u32 = 39;

// Completion codes (from event TRB status field)
const TRB_CC_SUCCESS: u32 = 1;
const TRB_CC_DATA_BUFFER_ERROR: u32 = 2;
const TRB_CC_BABBLE: u32 = 3;
const TRB_CC_USB_TRANSACTION_ERROR: u32 = 4;
const TRB_CC_TRB_ERROR: u32 = 5;
const TRB_CC_STALL: u32 = 6;
const TRB_CC_SHORT_PACKET: u32 = 13;
const TRB_CC_EVENT_RING_FULL: u32 = 21;
const TRB_CC_COMMAND_RING_STOPPED: u32 = 24;
const TRB_CC_COMMAND_ABORTED: u32 = 25;
const TRB_CC_NO_SLOTS_AVAILABLE: u32 = 9;
const TRB_CC_SLOT_NOT_ENABLED: u32 = 11;

// Helper to extract TRB type from control word
fn trb_type(control: u32) -> u32 {
    (control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT
}

// Helper to extract completion code from event TRB status
fn trb_completion_code(status: u32) -> u32 {
    (status >> 24) & 0xFF
}

// Helper to extract slot ID from event TRB control
fn trb_slot_id(control: u32) -> u32 {
    (control >> 24) & 0xFF
}

// ── Event Ring Segment Table Entry ──

#[repr(C)]
#[derive(Clone, Copy)]
struct ErstEntry {
    ring_segment_base: u64,  // 64-byte aligned physical address
    ring_segment_size: u16,  // Number of TRBs in this segment
    _reserved1: u16,
    _reserved2: u32,
}

const _: () = assert!(core::mem::size_of::<ErstEntry>() == 16);

// ── Ring sizes ──

const COMMAND_RING_SIZE: usize = 64;       // 64 TRBs (last is link TRB)
const EVENT_RING_SIZE: usize = 64;         // 64 TRBs per segment
const MAX_PORTS: usize = 256;              // xHCI supports up to 256 ports
const MAX_SLOTS: usize = 256;              // xHCI supports up to 256 device slots
const MAX_SCRATCHPAD_BUFS: usize = 1024;   // Max scratchpad buffers

// ── Command Ring ──

struct CommandRing {
    trbs: *mut Trb,           // Virtual address of TRB array (page-aligned)
    enqueue: usize,           // Current enqueue index
    cycle: bool,              // Producer Cycle State
}

impl CommandRing {
    fn phys_base(&self) -> u64 {
        virt_to_phys(self.trbs as *const u8)
    }

    /// Enqueue a command TRB. The caller sets param/status/control but
    /// must NOT set the cycle bit — this function manages it.
    fn enqueue_trb(&mut self, trb: &Trb) {
        let idx = self.enqueue;

        let mut control = trb.control;
        if self.cycle {
            control |= TRB_CYCLE;
        } else {
            control &= !TRB_CYCLE;
        }

        let slot = unsafe { &mut *self.trbs.add(idx) };
        unsafe {
            // Write param and status first, then control (with cycle) last
            // so the HC sees a consistent TRB when the cycle bit flips
            write_volatile(&mut slot.param as *mut u64, trb.param);
            write_volatile(&mut slot.status as *mut u32, trb.status);
            fence(Ordering::Release);
            write_volatile(&mut slot.control as *mut u32, control);
        }

        self.enqueue += 1;
        // If we reach the link TRB slot, wrap around
        if self.enqueue >= COMMAND_RING_SIZE - 1 {
            // The last TRB is a Link TRB pointing back to the start
            let link_ctrl = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC
                | if self.cycle { TRB_CYCLE } else { 0 };
            let link = unsafe { &mut *self.trbs.add(COMMAND_RING_SIZE - 1) };
            unsafe {
                write_volatile(&mut link.param as *mut u64, self.phys_base());
                write_volatile(&mut link.status as *mut u32, 0);
                fence(Ordering::Release);
                write_volatile(&mut link.control as *mut u32, link_ctrl);
            }
            self.cycle = !self.cycle;
            self.enqueue = 0;
        }
    }
}

// ── Event Ring ──

struct EventRing {
    trbs: *mut Trb,           // Virtual address of TRB segment
    erst: *mut ErstEntry,     // Event Ring Segment Table (physical addr in HC)
    dequeue: usize,           // Current dequeue index
    cycle: bool,              // Consumer Cycle State
}

impl EventRing {
    /// Check if the next event TRB is ready (cycle bit matches our CCS).
    fn has_event(&self) -> bool {
        let trb = unsafe { read_volatile(self.trbs.add(self.dequeue)) };
        let owner = (trb.control & TRB_CYCLE) != 0;
        owner == self.cycle
    }

    /// Dequeue the next event TRB. Caller must check has_event() first.
    fn dequeue_trb(&mut self) -> Trb {
        let trb = unsafe { read_volatile(self.trbs.add(self.dequeue)) };
        self.dequeue += 1;
        if self.dequeue >= EVENT_RING_SIZE {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        trb
    }

    /// Physical address of current dequeue pointer (for writing to ERDP).
    fn dequeue_phys(&self) -> u64 {
        virt_to_phys(self.trbs as *const u8) + (self.dequeue as u64 * 16)
    }
}

// ── Controller state ──

struct XhciController {
    bar0: *mut u8,
    bar0_size: usize,
    // PCI location
    bus: u8,
    dev: u8,
    func: u8,
    // Register space offsets (from BAR0)
    cap_base: usize,           // Always 0
    op_base: usize,            // BAR0 + CAPLENGTH
    rt_base: usize,            // BAR0 + RTSOFF
    db_base: usize,            // BAR0 + DBOFF
    // Capability parameters
    max_slots: u8,
    max_ports: u8,
    max_intrs: u16,
    page_size: u32,            // xHCI page size in bytes
    context_size: usize,       // 32 or 64 bytes depending on CSZ
    // DCBAA
    dcbaa: *mut u64,           // Device Context Base Address Array
    // Rings
    cmd_ring: CommandRing,
    evt_ring: EventRing,
    // Scratchpad
    scratchpad_array: *mut u64,  // Array of physical addresses
    scratchpad_bufs: *mut *mut u8, // Virtual pointers for cleanup
    scratchpad_count: usize,
}

unsafe impl Send for XhciController {}
unsafe impl Sync for XhciController {}

static mut XHCI: Option<XhciController> = None;

// ── PCI discovery ──

fn find_xhci_pci() -> Option<(u8, u8, u8, u16, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        // xHCI: class=0C subclass=03 prog_if=30
        if dev.class_code == 0x0C && dev.subclass == 0x03 && dev.prog_if == 0x30 {
            return Some((dev.bus, dev.dev, dev.func, dev.vendor_id, dev.device_id));
        }
    }
    None
}

// ── Port register access ──

fn port_reg_offset(op_base: usize, port: u32) -> usize {
    // Port numbers are 1-based in the spec, but we store 0-based externally
    op_base + XHCI_OP_PORTS_BASE + (port as usize) * XHCI_PORT_REG_SIZE
}

/// Read PORTSC for a given port (0-based index).
fn read_portsc(bar0: *mut u8, op_base: usize, port: u32) -> u32 {
    mmio_read32(bar0, port_reg_offset(op_base, port) + XHCI_PORTSC)
}

/// Write PORTSC preserving RW1C bits. Only bits explicitly set in `set_bits`
/// are ORed in; change bits are masked out to avoid accidental clearing.
fn write_portsc(bar0: *mut u8, op_base: usize, port: u32, set_bits: u32) {
    let current = read_portsc(bar0, op_base, port);
    // Preserve everything except RW1C change bits, then OR in requested bits
    let val = (current & !PORTSC_CHANGE_BITS) | set_bits;
    mmio_write32(bar0, port_reg_offset(op_base, port) + XHCI_PORTSC, val);
}

/// Clear specific RW1C change bits by writing 1 to them.
fn clear_portsc_changes(bar0: *mut u8, op_base: usize, port: u32, bits: u32) {
    let current = read_portsc(bar0, op_base, port);
    // Only write 1 to the specific change bits we want to clear,
    // preserve other state, mask out all other change bits
    let val = (current & !PORTSC_CHANGE_BITS) | (bits & PORTSC_CHANGE_BITS);
    mmio_write32(bar0, port_reg_offset(op_base, port) + XHCI_PORTSC, val);
}

// ── Host controller reset ──

fn hc_reset(bar0: *mut u8, op_base: usize) -> bool {
    // First, halt the controller if running
    let cmd = mmio_read32(bar0, op_base + XHCI_OP_USBCMD);
    if cmd & USBCMD_RUN != 0 {
        mmio_write32(bar0, op_base + XHCI_OP_USBCMD, cmd & !USBCMD_RUN);
        // Wait for HCHalted
        for _ in 0..100_000u32 {
            let sts = mmio_read32(bar0, op_base + XHCI_OP_USBSTS);
            if sts & USBSTS_HCH != 0 {
                break;
            }
            thread_yield();
        }
        let sts = mmio_read32(bar0, op_base + XHCI_OP_USBSTS);
        if sts & USBSTS_HCH == 0 {
            log("xhci: timeout waiting for halt");
            return false;
        }
    }

    // Issue reset
    mmio_write32(bar0, op_base + XHCI_OP_USBCMD, USBCMD_HCRST);

    // Wait for HCRST to self-clear
    for _ in 0..1_000_000u32 {
        let cmd = mmio_read32(bar0, op_base + XHCI_OP_USBCMD);
        if cmd & USBCMD_HCRST == 0 {
            break;
        }
        thread_yield();
    }
    let cmd = mmio_read32(bar0, op_base + XHCI_OP_USBCMD);
    if cmd & USBCMD_HCRST != 0 {
        log("xhci: HCRST did not clear");
        return false;
    }

    // Wait for Controller Not Ready to clear
    for _ in 0..1_000_000u32 {
        let sts = mmio_read32(bar0, op_base + XHCI_OP_USBSTS);
        if sts & USBSTS_CNR == 0 {
            return true;
        }
        thread_yield();
    }
    log("xhci: timeout waiting for CNR to clear after reset");
    false
}

// ── Ring doorbell ──

fn ring_doorbell(bar0: *mut u8, db_base: usize, slot: u32, target: u32) {
    mmio_write32(bar0, db_base + (slot as usize) * 4, target);
}

/// Ring the Host Controller doorbell (slot 0) for command ring
fn ring_cmd_doorbell(bar0: *mut u8, db_base: usize) {
    ring_doorbell(bar0, db_base, 0, 0);
}

// ── Event ring polling ──

/// Wait for a command completion event. Returns the event TRB or None on timeout.
fn wait_cmd_completion(ctrl: &mut XhciController) -> Option<Trb> {
    for _ in 0..1_000_000u32 {
        if ctrl.evt_ring.has_event() {
            let trb = ctrl.evt_ring.dequeue_trb();

            // Update ERDP so the HC knows we consumed the event
            let erdp = ctrl.evt_ring.dequeue_phys() | (1 << 3); // EHB bit
            mmio_write64(
                ctrl.bar0,
                ctrl.rt_base + XHCI_RT_IR0 + XHCI_IR_ERDP,
                erdp,
            );

            let tt = trb_type(trb.control);
            if tt == TRB_TYPE_CMD_COMPLETION {
                return Some(trb);
            }
            // For port status change events and others, just consume and continue
            // waiting for the command completion
            if tt == TRB_TYPE_PORT_STATUS_CHANGE {
                continue;
            }
            // Unknown event type during command wait; still continue
            continue;
        }
        thread_yield();
    }
    None
}

// ── Allocate page-aligned zeroed memory ──

fn alloc_page_zeroed() -> *mut u8 {
    let p = unsafe { alloc_page() };
    if !p.is_null() {
        unsafe { core::ptr::write_bytes(p, 0, 4096); }
    }
    p
}

// ── Allocate DCBAA ──

fn setup_dcbaa(ctrl: &mut XhciController) -> bool {
    // DCBAA needs (MaxSlots + 1) entries of 8 bytes each, 64-byte aligned.
    // A page is always sufficient (4096 / 8 = 512 entries).
    let dcbaa = alloc_page_zeroed() as *mut u64;
    if dcbaa.is_null() {
        log("xhci: failed to allocate DCBAA");
        return false;
    }
    ctrl.dcbaa = dcbaa;

    let dcbaa_phys = virt_to_phys(dcbaa as *const u8);
    mmio_write64(ctrl.bar0, ctrl.op_base + XHCI_OP_DCBAAP, dcbaa_phys);
    true
}

// ── Allocate Scratchpad Buffers ──

fn setup_scratchpad(ctrl: &mut XhciController) -> bool {
    let hcs2 = mmio_read32(ctrl.bar0, XHCI_CAP_HCSPARAMS2);

    // Max Scratchpad Buffers = HCSPARAMS2[31:27] (Hi) : HCSPARAMS2[25:21] (Lo)
    let hi = ((hcs2 >> 21) & 0x1F) as usize;
    let lo = ((hcs2 >> 27) & 0x1F) as usize;
    let count = (hi << 5) | lo;

    if count == 0 {
        ctrl.scratchpad_count = 0;
        ctrl.scratchpad_array = core::ptr::null_mut();
        ctrl.scratchpad_bufs = core::ptr::null_mut();
        return true;
    }

    unsafe {
        fut_printf(
            b"xhci: controller requests %d scratchpad buffers\n\0".as_ptr(),
            count as u32,
        );
    }

    if count > MAX_SCRATCHPAD_BUFS {
        log("xhci: too many scratchpad buffers requested");
        return false;
    }

    // Allocate the scratchpad buffer array (array of 64-bit physical addresses)
    // Must be page-aligned
    let array_page = alloc_page_zeroed() as *mut u64;
    if array_page.is_null() {
        log("xhci: failed to allocate scratchpad array");
        return false;
    }

    // Allocate virtual pointer tracking array
    let virt_array = unsafe {
        alloc(count * core::mem::size_of::<*mut u8>()) as *mut *mut u8
    };
    if virt_array.is_null() {
        log("xhci: failed to allocate scratchpad virt array");
        return false;
    }

    // Allocate each scratchpad buffer page
    for i in 0..count {
        let buf = alloc_page_zeroed();
        if buf.is_null() {
            log("xhci: failed to allocate scratchpad buffer");
            return false;
        }
        unsafe {
            write_volatile(virt_array.add(i), buf);
            write_volatile(array_page.add(i), virt_to_phys(buf));
        }
    }

    ctrl.scratchpad_array = array_page;
    ctrl.scratchpad_bufs = virt_array;
    ctrl.scratchpad_count = count;

    // DCBAA[0] points to the scratchpad buffer array
    let array_phys = virt_to_phys(array_page as *const u8);
    unsafe {
        write_volatile(ctrl.dcbaa, array_phys);
    }
    true
}

// ── Command Ring setup ──

fn setup_command_ring(ctrl: &mut XhciController) -> bool {
    let trbs = alloc_page_zeroed() as *mut Trb;
    if trbs.is_null() {
        log("xhci: failed to allocate command ring");
        return false;
    }

    ctrl.cmd_ring = CommandRing {
        trbs,
        enqueue: 0,
        cycle: true,
    };

    // Write the command ring base to CRCR
    let crcr_val = virt_to_phys(trbs as *const u8) | CRCR_RCS;
    mmio_write64(ctrl.bar0, ctrl.op_base + XHCI_OP_CRCR, crcr_val);
    true
}

// ── Event Ring setup ──

fn setup_event_ring(ctrl: &mut XhciController) -> bool {
    // Allocate event ring segment (one page = 256 TRBs max, we use 64)
    let trbs = alloc_page_zeroed() as *mut Trb;
    if trbs.is_null() {
        log("xhci: failed to allocate event ring");
        return false;
    }

    // Allocate Event Ring Segment Table (one entry, 16 bytes, 64-byte aligned)
    let erst = alloc_page_zeroed() as *mut ErstEntry;
    if erst.is_null() {
        log("xhci: failed to allocate ERST");
        return false;
    }

    // Fill in the single ERST entry
    let entry = ErstEntry {
        ring_segment_base: virt_to_phys(trbs as *const u8),
        ring_segment_size: EVENT_RING_SIZE as u16,
        _reserved1: 0,
        _reserved2: 0,
    };
    unsafe { write_volatile(erst, entry); }

    ctrl.evt_ring = EventRing {
        trbs,
        erst,
        dequeue: 0,
        cycle: true,
    };

    let ir_base = ctrl.rt_base + XHCI_RT_IR0;

    // Set ERSTSZ = 1 (one segment)
    mmio_write32(ctrl.bar0, ir_base + XHCI_IR_ERSTSZ, 1);

    // Set ERDP to start of event ring segment
    let erdp = virt_to_phys(trbs as *const u8);
    mmio_write64(ctrl.bar0, ir_base + XHCI_IR_ERDP, erdp);

    // Set ERSTBA (this enables the event ring; must be written after ERSTSZ and ERDP)
    let erstba = virt_to_phys(erst as *const u8);
    mmio_write64(ctrl.bar0, ir_base + XHCI_IR_ERSTBA, erstba);

    // Enable interrupter 0 (IMAN bit 1 = IE)
    let iman = mmio_read32(ctrl.bar0, ir_base + XHCI_IR_IMAN);
    mmio_write32(ctrl.bar0, ir_base + XHCI_IR_IMAN, iman | 0x2);

    // Set interrupt moderation interval (default: 4000 = 1ms at 250ns per count)
    mmio_write32(ctrl.bar0, ir_base + XHCI_IR_IMOD, 4000);

    true
}

// ── Port power-on and reset ──

fn port_power_on(ctrl: &XhciController, port: u32) {
    let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
    if portsc & PORTSC_PP == 0 {
        write_portsc(ctrl.bar0, ctrl.op_base, port, PORTSC_PP);
        // Wait 20ms for power to stabilize (USB spec TATTDB)
        thread_sleep(20);
    }
}

fn port_reset(ctrl: &XhciController, port: u32) -> bool {
    let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);

    // Only reset if a device is connected
    if portsc & PORTSC_CCS == 0 {
        return false;
    }

    // Issue port reset
    write_portsc(ctrl.bar0, ctrl.op_base, port, PORTSC_PP | PORTSC_PR);

    // Wait for reset to complete (PRC = Port Reset Change)
    for _ in 0..100_000u32 {
        let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
        if portsc & PORTSC_PRC != 0 {
            // Clear the PRC bit
            clear_portsc_changes(ctrl.bar0, ctrl.op_base, port, PORTSC_PRC);
            return true;
        }
        thread_yield();
    }
    log("xhci: port reset timeout");
    false
}

fn get_port_speed(ctrl: &XhciController, port: u32) -> u32 {
    let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
    (portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT
}

fn get_port_link_state(portsc: u32) -> u32 {
    (portsc & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT
}

// ── Initialization ──

fn init_ports(ctrl: &XhciController) {
    for port in 0..ctrl.max_ports as u32 {
        port_power_on(ctrl, port);
    }

    // Allow time for devices to connect and signal (100ms)
    thread_sleep(100);

    for port in 0..ctrl.max_ports as u32 {
        let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
        if portsc & PORTSC_CCS != 0 {
            let speed = (portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT;
            let speed_str = match speed {
                SPEED_FULL => b"Full Speed (12 Mb/s)\0".as_ptr(),
                SPEED_LOW => b"Low Speed (1.5 Mb/s)\0".as_ptr(),
                SPEED_HIGH => b"High Speed (480 Mb/s)\0".as_ptr(),
                SPEED_SUPER => b"SuperSpeed (5 Gb/s)\0".as_ptr(),
                SPEED_SUPER_PLUS => b"SuperSpeedPlus (10 Gb/s)\0".as_ptr(),
                _ => b"Unknown\0".as_ptr(),
            };
            unsafe {
                fut_printf(
                    b"xhci: port %d: device connected - %s\n\0".as_ptr(),
                    port + 1,
                    speed_str,
                );
            }

            // Reset the port to move it to Enabled state
            if port_reset(ctrl, port) {
                let portsc_after = read_portsc(ctrl.bar0, ctrl.op_base, port);
                if portsc_after & PORTSC_PED != 0 {
                    unsafe {
                        fut_printf(
                            b"xhci: port %d: enabled after reset\n\0".as_ptr(),
                            port + 1,
                        );
                    }
                }
            }
        }
    }
}

// ── USB device enumeration ─────────────────────────────────────────────────
//
// Below this line is the bring-up path that takes a port from "device
// connected, port enabled after reset" to "device addressed, EP0 control
// transfers working, device + configuration descriptors read, class
// driver dispatched". It is layered on top of the host controller setup
// the rest of this file provides.
//
// Stages:
//   1. Enable Slot          → allocate a slot id in the DCBAA
//   2. setup_input_context  → fill in Slot + EP0 contexts (Add flags A0|A1)
//   3. Address Device       → HC issues USB SetAddress, EP0 becomes live
//   4. control_transfer     → Setup/Data/Status TRBs on EP0 transfer ring
//   5. GET_DESCRIPTOR(dev)  → 18 bytes, identifies vendor/product/class
//   6. GET_DESCRIPTOR(cfg)  → walk interface/endpoint descriptors
//   7. Class dispatch       → log; future stages call usb_storage_attach,
//                             usb_hub_attach, etc.
//
// Per-slot state lives in the SLOT_TABLE (one entry per slot id, 1-based).
// Each slot owns an Input Context page, an Output Context page (the latter
// also pointed to by DCBAA[slot_id]), and a Transfer Ring for EP0.

const EP0_TRING_SIZE: usize = 64; // TRBs (last is Link TRB)

/// Endpoint types for the EP Context type field [5:3].
const EP_TYPE_CONTROL:    u8 = 4;
const _EP_TYPE_BULK_OUT:  u8 = 2;
const _EP_TYPE_BULK_IN:   u8 = 6;

/// Speed encoding used by Slot Context and PORTSC (identical values).
const _USB_SPEED_FS: u32 = 1;
const _USB_SPEED_LS: u32 = 2;
const USB_SPEED_HS: u32 = 3;
const USB_SPEED_SS: u32 = 4;
const _USB_SPEED_SSP: u32 = 5;

/// Default EP0 max packet size by speed. SuperSpeed is always 512; HS is 64.
/// FS/LS devices can advertise 8/16/32/64 (FS) or always 8 (LS) — we start
/// with 64 for FS to match what most devices use, and fix up via Evaluate
/// Context if the first 8 bytes of the device descriptor disagree.
fn default_max_packet_ep0(speed: u32) -> u16 {
    match speed {
        USB_SPEED_SS | _USB_SPEED_SSP => 512,
        _USB_SPEED_LS => 8,
        _ => 64,
    }
}

#[derive(Copy, Clone)]
struct DeviceSlot {
    in_use: bool,
    root_hub_port: u32,        // 1-based
    speed: u32,
    max_packet_ep0: u16,
    input_ctx_virt: usize,     // virtual address of 4 KiB input ctx page
    input_ctx_phys: u64,
    output_ctx_virt: usize,    // virtual address of 4 KiB output ctx page
    output_ctx_phys: u64,
    ep0_tring_virt: usize,     // virtual address of 4 KiB EP0 TRB ring
    ep0_tring_phys: u64,
    ep0_enqueue: u16,
    ep0_cycle: bool,
}

impl DeviceSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            root_hub_port: 0,
            speed: 0,
            max_packet_ep0: 0,
            input_ctx_virt: 0,
            input_ctx_phys: 0,
            output_ctx_virt: 0,
            output_ctx_phys: 0,
            ep0_tring_virt: 0,
            ep0_tring_phys: 0,
            ep0_enqueue: 0,
            ep0_cycle: false,
        }
    }
}

static mut SLOT_TABLE: [DeviceSlot; MAX_SLOTS + 1] = [DeviceSlot::empty(); MAX_SLOTS + 1];

/// Borrow a mutable reference to a slot's state. Returns None if the
/// slot id is out of range. Callers must avoid aliasing -- one
/// slot-mutable borrow at a time across the whole driver.
unsafe fn slot_mut(slot_id: u32) -> Option<&'static mut DeviceSlot> {
    if slot_id == 0 || slot_id as usize > MAX_SLOTS {
        return None;
    }
    unsafe {
        let table = core::ptr::addr_of_mut!(SLOT_TABLE);
        Some(&mut (*table)[slot_id as usize])
    }
}

/// Send an Enable Slot command and wait for completion. Returns the
/// allocated slot ID on success, or 0 on failure (slot IDs are 1-based
/// in xHCI, so 0 unambiguously signals an error).
fn enable_slot(ctrl: &mut XhciController) -> u32 {
    let trb = Trb {
        param: 0,
        status: 0,
        control: TRB_TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT,
    };
    ctrl.cmd_ring.enqueue_trb(&trb);
    ring_cmd_doorbell(ctrl.bar0, ctrl.db_base);

    match wait_cmd_completion(ctrl) {
        Some(event) => {
            let cc = trb_completion_code(event.status);
            if cc == TRB_CC_SUCCESS {
                trb_slot_id(event.control)
            } else {
                unsafe {
                    fut_printf(
                        b"xhci: Enable Slot failed, completion code = %u\n\0".as_ptr(),
                        cc,
                    );
                }
                0
            }
        }
        None => {
            log("xhci: Enable Slot timed out waiting for command completion");
            0
        }
    }
}

/// Compute offsets into the input or output context page for a given DCI,
/// honoring the controller's context_size (32 or 64 bytes per context).
/// Input context layout:    0 = Input Control Ctx, 1 = Slot Ctx, 2 = EP0 Ctx, ...
/// Output context layout:   0 = Slot Ctx,          1 = EP0 Ctx,  ...
/// We always pass the input-context index (so 1 = Slot, 2 = EP0). For
/// output context offsets, subtract 1 from the index manually.
#[inline]
fn ctx_offset(context_size: usize, idx: usize) -> usize {
    idx * context_size
}

/// Initialize a slot's per-slot state: allocate input ctx, output ctx,
/// and EP0 transfer ring; populate Slot + EP0 contexts for Address Device;
/// register the output context in DCBAA[slot_id]. On success the slot is
/// marked in_use and is ready for an Address Device command.
fn setup_slot_for_address(
    ctrl: &mut XhciController,
    slot_id: u32,
    root_hub_port: u32,
    speed: u32,
) -> bool {
    if slot_id == 0 || slot_id as usize > MAX_SLOTS {
        return false;
    }

    let input_ctx = alloc_page_zeroed();
    let output_ctx = alloc_page_zeroed();
    let ep0_tring = alloc_page_zeroed();
    if input_ctx.is_null() || output_ctx.is_null() || ep0_tring.is_null() {
        log("xhci: setup_slot_for_address: page alloc failed");
        return false;
    }

    let input_ctx_phys = virt_to_phys(input_ctx);
    let output_ctx_phys = virt_to_phys(output_ctx);
    let ep0_tring_phys = virt_to_phys(ep0_tring);

    // Install Link TRB at the last slot of the EP0 transfer ring so the
    // HC wraps cleanly back to the start. Toggle Cycle (TC) flips the
    // expected cycle bit on each pass.
    unsafe {
        let trbs = ep0_tring as *mut Trb;
        let link = trbs.add(EP0_TRING_SIZE - 1);
        let link_ctrl = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC;
        write_volatile(&mut (*link).param as *mut u64, ep0_tring_phys);
        write_volatile(&mut (*link).status as *mut u32, 0);
        write_volatile(&mut (*link).control as *mut u32, link_ctrl);
    }

    let max_packet = default_max_packet_ep0(speed);
    let cs = ctrl.context_size;

    // Input Control Context: Add flag for Slot Ctx (A0) and EP0 Ctx (A1).
    unsafe {
        let icc = input_ctx;
        // bytes 0..3 = Drop flags (0); bytes 4..7 = Add flags
        write_volatile(icc.add(4) as *mut u32, 0x3); // A0 | A1
    }

    // Slot Context at input ctx offset ctx_offset(cs, 1).
    unsafe {
        let slot = input_ctx.add(ctx_offset(cs, 1));
        let dw0: u32 = (speed << 20) | (1u32 << 27); // Context Entries = 1
        let dw1: u32 = (root_hub_port & 0xFF) << 16;
        write_volatile(slot as *mut u32, dw0);
        write_volatile(slot.add(4) as *mut u32, dw1);
        write_volatile(slot.add(8) as *mut u32, 0);
        write_volatile(slot.add(12) as *mut u32, 0);
    }

    // EP0 Context at input ctx offset ctx_offset(cs, 2).
    // DW0 = 0 (HC will set State). DW1 = (EP_TYPE_CONTROL << 3) | (CErr=3 << 1)
    //   | (Max Packet Size << 16). DW2/3 = TR Dequeue Pointer | DCS(=1).
    // DW4 = Average TRB Length = 8 (Control).
    unsafe {
        let ep0 = input_ctx.add(ctx_offset(cs, 2));
        let dw1: u32 = ((EP_TYPE_CONTROL as u32) << 3)
            | (3u32 << 1) // CErr = 3
            | ((max_packet as u32) << 16);
        write_volatile(ep0 as *mut u32, 0);
        write_volatile(ep0.add(4) as *mut u32, dw1);
        // Dequeue pointer: low 4 bits are reserved/DCS. We start with cycle=1
        // (matches a freshly-zeroed ring), so set DCS=1.
        let dq = ep0_tring_phys | 1;
        write_volatile(ep0.add(8) as *mut u32, dq as u32);
        write_volatile(ep0.add(12) as *mut u32, (dq >> 32) as u32);
        // Average TRB length
        write_volatile(ep0.add(16) as *mut u32, 8);
    }

    // Install the output context in DCBAA[slot_id]. The HC reads this on
    // Address Device and writes the assigned address back into it.
    unsafe {
        let entry = ctrl.dcbaa.add(slot_id as usize);
        write_volatile(entry, output_ctx_phys);
    }

    // Stash per-slot state.
    unsafe {
        *slot_mut(slot_id).unwrap() = DeviceSlot {
            in_use: true,
            root_hub_port,
            speed,
            max_packet_ep0: max_packet,
            input_ctx_virt: input_ctx as usize,
            input_ctx_phys,
            output_ctx_virt: output_ctx as usize,
            output_ctx_phys,
            ep0_tring_virt: ep0_tring as usize,
            ep0_tring_phys,
            ep0_enqueue: 0,
            ep0_cycle: true,
        };
    }
    true
}

/// Issue Address Device command. After completion the HC has put the
/// device through SET_ADDRESS and the EP0 default control pipe is live
/// at the bus address equal to slot_id. Returns true on success.
fn address_device(ctrl: &mut XhciController, slot_id: u32) -> bool {
    let in_ctx_phys = unsafe { slot_mut(slot_id).unwrap().input_ctx_phys };
    let trb = Trb {
        param: in_ctx_phys,
        status: 0,
        control: (TRB_TYPE_ADDRESS_DEVICE << TRB_TYPE_SHIFT)
            | ((slot_id & 0xFF) << 24),
    };
    ctrl.cmd_ring.enqueue_trb(&trb);
    ring_cmd_doorbell(ctrl.bar0, ctrl.db_base);

    match wait_cmd_completion(ctrl) {
        Some(event) => {
            let cc = trb_completion_code(event.status);
            if cc == TRB_CC_SUCCESS {
                true
            } else {
                unsafe {
                    fut_printf(
                        b"xhci: Address Device failed (slot %u), completion code = %u\n\0".as_ptr(),
                        slot_id, cc,
                    );
                }
                false
            }
        }
        None => {
            log("xhci: Address Device timed out");
            false
        }
    }
}

/// Wait for a Transfer Event on the event ring matching the given slot id
/// and endpoint DCI. Returns the event TRB on success.
fn wait_transfer_event(ctrl: &mut XhciController, slot_id: u32, _ep_id: u32) -> Option<Trb> {
    for _ in 0..1_000_000u32 {
        if ctrl.evt_ring.has_event() {
            let trb = ctrl.evt_ring.dequeue_trb();
            let erdp = ctrl.evt_ring.dequeue_phys() | (1 << 3);
            mmio_write64(
                ctrl.bar0,
                ctrl.rt_base + XHCI_RT_IR0 + XHCI_IR_ERDP,
                erdp,
            );
            let tt = trb_type(trb.control);
            if tt == TRB_TYPE_TRANSFER_EVENT && trb_slot_id(trb.control) == slot_id {
                return Some(trb);
            }
            // Drain unrelated events (port status changes, command
            // completions from earlier work, etc.) until we see ours.
            continue;
        }
        thread_yield();
    }
    None
}

/// Push one TRB onto a slot's EP0 transfer ring, handling cycle bit and
/// Link TRB wrap. Mirrors CommandRing::enqueue_trb but for control rings.
fn ep0_enqueue(slot: &mut DeviceSlot, trb_in: &Trb) {
    let mut control = trb_in.control;
    if slot.ep0_cycle {
        control |= TRB_CYCLE;
    } else {
        control &= !TRB_CYCLE;
    }
    unsafe {
        let trbs = slot.ep0_tring_virt as *mut Trb;
        let dst = trbs.add(slot.ep0_enqueue as usize);
        write_volatile(&mut (*dst).param as *mut u64, trb_in.param);
        write_volatile(&mut (*dst).status as *mut u32, trb_in.status);
        fence(Ordering::Release);
        write_volatile(&mut (*dst).control as *mut u32, control);
    }
    slot.ep0_enqueue += 1;
    if slot.ep0_enqueue as usize >= EP0_TRING_SIZE - 1 {
        // Update the Link TRB's cycle bit then wrap.
        unsafe {
            let trbs = slot.ep0_tring_virt as *mut Trb;
            let link = trbs.add(EP0_TRING_SIZE - 1);
            let link_ctrl = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | TRB_TC
                | if slot.ep0_cycle { TRB_CYCLE } else { 0 };
            write_volatile(&mut (*link).control as *mut u32, link_ctrl);
        }
        slot.ep0_cycle = !slot.ep0_cycle;
        slot.ep0_enqueue = 0;
    }
}

/// Execute a USB control transfer on the default control pipe of `slot_id`.
/// The caller supplies the 8-byte Setup packet fields plus an optional data
/// buffer. Returns Ok(actual_bytes_transferred) or Err(completion_code).
///
/// Layout:
///   - Setup Stage TRB     (immediate data: bmRequestType, bRequest, wValue,
///                          wIndex, wLength); TRT = 2 (OUT) or 3 (IN) or 0 (none)
///   - Optional Data Stage TRB (buffer phys, length, DIR = IN/OUT)
///   - Status Stage TRB    (DIR = opposite of data, IOC = 1)
fn control_transfer(
    ctrl: &mut XhciController,
    slot_id: u32,
    bm_request_type: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    data: *mut u8,
    data_len: u16,
) -> Result<u16, u32> {
    let slot = match unsafe { slot_mut(slot_id) } {
        Some(s) if s.in_use => s,
        _ => return Err(0xFF),
    };

    let is_in = (bm_request_type & 0x80) != 0;
    let trt: u32 = if data_len == 0 {
        0
    } else if is_in {
        3
    } else {
        2
    };

    // Setup Stage TRB with Immediate Data.
    let setup_param: u64 = (bm_request_type as u64)
        | ((b_request as u64) << 8)
        | ((w_value as u64) << 16)
        | ((w_index as u64) << 32)
        | ((data_len as u64) << 48);
    let setup_status: u32 = 8; // TRB Transfer Length = 8 (Setup payload)
    let setup_control: u32 = (TRB_TYPE_SETUP << TRB_TYPE_SHIFT)
        | TRB_IDT
        | TRB_IOC // request completion for the setup stage too (helps debugging)
        | (trt << 16);
    ep0_enqueue(slot, &Trb { param: setup_param, status: setup_status, control: setup_control });

    // Optional Data Stage TRB.
    if data_len > 0 {
        let data_phys = virt_to_phys(data);
        let status: u32 = data_len as u32;
        let control: u32 = (TRB_TYPE_DATA << TRB_TYPE_SHIFT)
            | TRB_IOC
            | if is_in { 1 << 16 } else { 0 };
        ep0_enqueue(slot, &Trb { param: data_phys, status, control });
    }

    // Status Stage TRB: direction is opposite of Data Stage (or IN if no data).
    let status_dir_in = !is_in || data_len == 0;
    let status_control: u32 = (TRB_TYPE_STATUS << TRB_TYPE_SHIFT)
        | TRB_IOC
        | if status_dir_in { 1 << 16 } else { 0 };
    ep0_enqueue(slot, &Trb { param: 0, status: 0, control: status_control });

    // Doorbell EP0 (DCI = 1).
    ring_doorbell(ctrl.bar0, ctrl.db_base, slot_id, 1);

    // Drain transfer events: one per TRB with IOC set. We set IOC on
    // Setup, Data (if any), and Status. So expect 3 events with a data
    // stage, 2 without.
    let expected_events = if data_len > 0 { 3 } else { 2 };
    let mut data_residual: u32 = 0;
    for _ in 0..expected_events {
        match wait_transfer_event(ctrl, slot_id, 1) {
            Some(ev) => {
                let cc = trb_completion_code(ev.status);
                if cc != TRB_CC_SUCCESS && cc != TRB_CC_SHORT_PACKET {
                    return Err(cc);
                }
                data_residual = ev.status & 0x00FFFFFF;
            }
            None => {
                return Err(0xFE);
            }
        }
    }
    Ok(data_len.saturating_sub(data_residual as u16))
}

const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;
const _USB_REQ_SET_ADDRESS:    u8 = 0x05;
const USB_REQ_SET_CONFIG:      u8 = 0x09;
const USB_DESC_DEVICE:         u16 = 0x0100;
const USB_DESC_CONFIG:         u16 = 0x0200;

/// USB device descriptor (18 bytes). Fields we care about for class dispatch
/// are vendor/product id and (more commonly) the per-interface class bytes
/// in the configuration descriptor below.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct UsbDeviceDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    bcd_usb: u16,
    b_device_class: u8,
    b_device_subclass: u8,
    b_device_protocol: u8,
    b_max_packet_size0: u8,
    id_vendor: u16,
    id_product: u16,
    bcd_device: u16,
    i_manufacturer: u8,
    i_product: u8,
    i_serial_number: u8,
    b_num_configurations: u8,
}

const _: () = assert!(core::mem::size_of::<UsbDeviceDescriptor>() == 18);

/// Read the 18-byte device descriptor. Caller supplies an 18-byte aligned
/// buffer (we use a static page; descriptor is small).
fn get_device_descriptor(
    ctrl: &mut XhciController,
    slot_id: u32,
    out: &mut UsbDeviceDescriptor,
) -> bool {
    // Use a temporary page-aligned buffer the HC can DMA into.
    let buf = alloc_page_zeroed();
    if buf.is_null() {
        return false;
    }
    let rc = control_transfer(
        ctrl,
        slot_id,
        0x80, // bmRequestType: device-to-host, standard, device
        USB_REQ_GET_DESCRIPTOR,
        USB_DESC_DEVICE,
        0,
        buf,
        18,
    );
    if let Ok(n) = rc {
        if n >= 18 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf as *const u8,
                    out as *mut _ as *mut u8,
                    18,
                );
            }
            unsafe { free_page(buf); }
            return true;
        }
    }
    unsafe { free_page(buf); }
    false
}

/// Read up to `max_len` bytes of the first configuration descriptor (which
/// includes the interface + endpoint descriptors concatenated). Returns the
/// number of bytes actually returned by the device.
fn get_config_descriptor(
    ctrl: &mut XhciController,
    slot_id: u32,
    buf_virt: *mut u8,
    max_len: u16,
) -> u16 {
    match control_transfer(
        ctrl, slot_id,
        0x80,
        USB_REQ_GET_DESCRIPTOR,
        USB_DESC_CONFIG,
        0,
        buf_virt,
        max_len,
    ) {
        Ok(n) => n,
        Err(_) => 0,
    }
}

/// Set device configuration. After this, the endpoints listed in the chosen
/// configuration become active.
fn set_configuration(ctrl: &mut XhciController, slot_id: u32, config_value: u8) -> bool {
    match control_transfer(
        ctrl, slot_id,
        0x00, // host-to-device, standard, device
        USB_REQ_SET_CONFIG,
        config_value as u16,
        0,
        core::ptr::null_mut(),
        0,
    ) {
        Ok(_) => true,
        Err(cc) => {
            unsafe {
                fut_printf(
                    b"xhci: slot %u: SET_CONFIGURATION(%u) cc=%u\n\0".as_ptr(),
                    slot_id, config_value as u32, cc,
                );
            }
            false
        }
    }
}

/// Walk every connected/enabled root-hub port and enumerate the device
/// behind it: Enable Slot → setup input ctx → Address Device → GET_DESCRIPTOR
/// (device) → GET_DESCRIPTOR (config). The output is logged; future stages
/// will wire each interface to a class driver based on the bInterfaceClass.
fn enumerate_devices(ctrl: &mut XhciController) {
    for port in 0..ctrl.max_ports as u32 {
        let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
        if (portsc & PORTSC_CCS) == 0 || (portsc & PORTSC_PED) == 0 {
            continue;
        }
        let speed = (portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT;
        let slot_id = enable_slot(ctrl);
        if slot_id == 0 {
            continue;
        }
        unsafe {
            fut_printf(
                b"xhci: port %u: slot %u allocated (speed=%u)\n\0".as_ptr(),
                port + 1, slot_id, speed,
            );
        }
        if !setup_slot_for_address(ctrl, slot_id, port + 1, speed) {
            unsafe {
                fut_printf(
                    b"xhci: port %u: input ctx setup failed\n\0".as_ptr(),
                    port + 1,
                );
            }
            continue;
        }
        if !address_device(ctrl, slot_id) {
            continue;
        }
        let mut dev = UsbDeviceDescriptor {
            b_length: 0, b_descriptor_type: 0, bcd_usb: 0,
            b_device_class: 0, b_device_subclass: 0, b_device_protocol: 0,
            b_max_packet_size0: 0, id_vendor: 0, id_product: 0,
            bcd_device: 0, i_manufacturer: 0, i_product: 0,
            i_serial_number: 0, b_num_configurations: 0,
        };
        if !get_device_descriptor(ctrl, slot_id, &mut dev) {
            unsafe {
                fut_printf(
                    b"xhci: slot %u: GET_DESCRIPTOR(device) failed\n\0".as_ptr(),
                    slot_id,
                );
            }
            continue;
        }
        let id_vendor = dev.id_vendor;
        let id_product = dev.id_product;
        let dev_class = dev.b_device_class;
        let dev_sub = dev.b_device_subclass;
        let dev_proto = dev.b_device_protocol;
        let mps0 = dev.b_max_packet_size0;
        let n_cfg = dev.b_num_configurations;
        unsafe {
            fut_printf(
                b"xhci: slot %u: USB device %04x:%04x class=%02x:%02x:%02x mps0=%u cfg=%u\n\0".as_ptr(),
                slot_id, id_vendor as u32, id_product as u32,
                dev_class as u32, dev_sub as u32, dev_proto as u32,
                mps0 as u32, n_cfg as u32,
            );
        }

        // Read the configuration descriptor (first 9 bytes give total length).
        let cfg_buf = alloc_page_zeroed();
        if cfg_buf.is_null() {
            continue;
        }
        let n = get_config_descriptor(ctrl, slot_id, cfg_buf, 9);
        if n < 9 {
            unsafe {
                fut_printf(
                    b"xhci: slot %u: GET_DESCRIPTOR(config) header failed (got %u)\n\0".as_ptr(),
                    slot_id, n as u32,
                );
                free_page(cfg_buf);
            }
            continue;
        }
        let total = unsafe {
            (*(cfg_buf.add(2) as *const u16))
        };
        let total = core::cmp::min(total, 4096) as u16;
        let n2 = get_config_descriptor(ctrl, slot_id, cfg_buf, total);
        if n2 < total {
            unsafe {
                fut_printf(
                    b"xhci: slot %u: GET_DESCRIPTOR(config) short read %u/%u\n\0".as_ptr(),
                    slot_id, n2 as u32, total as u32,
                );
            }
        }
        // Walk descriptors looking for interface (type 4) entries.
        let mut off = 0usize;
        let buf_end = n2 as usize;
        let cfg_value = unsafe { *cfg_buf.add(5) };
        while off + 2 <= buf_end {
            let dlen = unsafe { *cfg_buf.add(off) } as usize;
            let dtype = unsafe { *cfg_buf.add(off + 1) };
            if dlen == 0 || off + dlen > buf_end {
                break;
            }
            if dtype == 4 && dlen >= 9 {
                let if_num = unsafe { *cfg_buf.add(off + 2) };
                let if_class = unsafe { *cfg_buf.add(off + 5) };
                let if_sub = unsafe { *cfg_buf.add(off + 6) };
                let if_proto = unsafe { *cfg_buf.add(off + 7) };
                let n_ep = unsafe { *cfg_buf.add(off + 4) };
                let class_label: *const u8 = match if_class {
                    0x03 => b"HID\0".as_ptr(),
                    0x08 => b"Mass Storage\0".as_ptr(),
                    0x09 => b"Hub\0".as_ptr(),
                    0x0e => b"Video\0".as_ptr(),
                    _    => b"-\0".as_ptr(),
                };
                unsafe {
                    fut_printf(
                        b"xhci: slot %u: interface %u class=%02x:%02x:%02x (%s) endpoints=%u\n\0".as_ptr(),
                        slot_id, if_num as u32,
                        if_class as u32, if_sub as u32, if_proto as u32,
                        class_label, n_ep as u32,
                    );
                }
            }
            off += dlen;
        }
        // Activate the configuration so endpoints become valid for future
        // bulk-transfer work.
        if !set_configuration(ctrl, slot_id, cfg_value) {
            unsafe {
                fut_printf(
                    b"xhci: slot %u: SET_CONFIGURATION(%u) failed\n\0".as_ptr(),
                    slot_id, cfg_value as u32,
                );
            }
        }
        unsafe { free_page(cfg_buf); }
    }
}

/// Send a No-Op command to verify command/event ring operation.
fn test_cmd_ring(ctrl: &mut XhciController) -> bool {
    let trb = Trb {
        param: 0,
        status: 0,
        control: TRB_TYPE_NOOP_CMD << TRB_TYPE_SHIFT,
    };
    ctrl.cmd_ring.enqueue_trb(&trb);
    fence(Ordering::SeqCst);
    ring_cmd_doorbell(ctrl.bar0, ctrl.db_base);

    match wait_cmd_completion(ctrl) {
        Some(evt) => {
            let cc = trb_completion_code(evt.status);
            if cc == TRB_CC_SUCCESS {
                log("xhci: command ring verified (No-Op success)");
                true
            } else {
                unsafe {
                    fut_printf(
                        b"xhci: No-Op command failed with code %d\n\0".as_ptr(),
                        cc,
                    );
                }
                false
            }
        }
        None => {
            log("xhci: timeout waiting for No-Op completion");
            false
        }
    }
}

// ── FFI exports ──

/// Initialize the xHCI host controller.
/// Scans PCI for xHCI devices, performs controller reset, sets up DCBAA,
/// command/event rings, scratchpad buffers, and initializes root hub ports.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn xhci_init() -> i32 {
    log("xhci: scanning PCI for xHCI host controllers...");

    let (bus, dev, func, vendor, device) = match find_xhci_pci() {
        Some(bdf) => bdf,
        None => {
            log("xhci: no xHCI controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"xhci: found controller at PCI %02x:%02x.%x (vendor=%04x device=%04x)\n\0".as_ptr(),
            bus as u32, dev as u32, func as u32, vendor as u32, device as u32,
        );
    }

    // Enable bus mastering and memory space in PCI command register
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06);

    // Read BAR0 (64-bit MMIO)
    let bar0_lo = pci_read32(bus, dev, func, 0x10) & !0xF;
    let bar0_hi = pci_read32(bus, dev, func, 0x14);
    let bar0_phys = (bar0_lo as u64) | ((bar0_hi as u64) << 32);

    if bar0_phys == 0 {
        log("xhci: BAR0 not configured");
        return -2;
    }

    unsafe {
        fut_printf(b"xhci: BAR0 physical address: 0x%llx\n\0".as_ptr(), bar0_phys);
    }

    // Determine BAR0 size by writing all 1s and reading back
    // For safety, use a generous fixed size (64 KiB covers most xHCI controllers)
    let bar0_size = 0x10000usize;
    let bar0 = unsafe { map_mmio_region(bar0_phys, bar0_size, MMIO_DEFAULT_FLAGS) };
    if bar0.is_null() {
        log("xhci: failed to map BAR0");
        return -3;
    }

    // ── Parse Capability Registers ──

    let caplength = mmio_read32(bar0, XHCI_CAP_CAPLENGTH) & 0xFF;
    let hciversion = (mmio_read32(bar0, XHCI_CAP_CAPLENGTH) >> 16) & 0xFFFF;
    let hcsparams1 = mmio_read32(bar0, XHCI_CAP_HCSPARAMS1);
    let hcsparams2 = mmio_read32(bar0, XHCI_CAP_HCSPARAMS2);
    let hccparams1 = mmio_read32(bar0, XHCI_CAP_HCCPARAMS1);
    let dboff = mmio_read32(bar0, XHCI_CAP_DBOFF) & !0x3;
    let rtsoff = mmio_read32(bar0, XHCI_CAP_RTSOFF) & !0x1F;

    let max_slots = (hcsparams1 & 0xFF) as u8;
    let max_intrs = ((hcsparams1 >> 8) & 0x7FF) as u16;
    let max_ports = ((hcsparams1 >> 24) & 0xFF) as u8;

    // CSZ (Context Size) flag - bit 2 of HCCPARAMS1
    // 0 = 32-byte contexts, 1 = 64-byte contexts
    let csz = (hccparams1 >> 2) & 1;
    let context_size = if csz != 0 { 64 } else { 32 };

    let op_base = caplength as usize;
    let rt_base = rtsoff as usize;
    let db_base = dboff as usize;

    unsafe {
        fut_printf(
            b"xhci: version %x.%x, %d slots, %d ports, %d interrupters\n\0".as_ptr(),
            (hciversion >> 8) & 0xFF,
            hciversion & 0xFF,
            max_slots as u32,
            max_ports as u32,
            max_intrs as u32,
        );
        fut_printf(
            b"xhci: CAPLENGTH=%d DBOFF=0x%x RTSOFF=0x%x CSZ=%d\n\0".as_ptr(),
            caplength,
            dboff,
            rtsoff,
            csz,
        );
    }

    // Read xHCI page size register
    let pagesize_reg = mmio_read32(bar0, op_base + XHCI_OP_PAGESIZE);
    // Bits [15:0]: each bit n means page size 2^(n+12) is supported
    // Bit 0 = 4 KiB (always set)
    let page_size = if pagesize_reg & 1 != 0 { 4096u32 } else { 4096u32 };

    unsafe {
        fut_printf(b"xhci: page size: %d bytes\n\0".as_ptr(), page_size);
    }

    // ── Reset the controller ──

    if !hc_reset(bar0, op_base) {
        log("xhci: controller reset failed");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -4;
    }
    log("xhci: controller reset complete");

    // ── Program MaxSlotsEn in CONFIG register ──

    mmio_write32(bar0, op_base + XHCI_OP_CONFIG, max_slots as u32);

    // ── Build controller state ──

    let mut ctrl = XhciController {
        bar0,
        bar0_size,
        bus, dev, func,
        cap_base: 0,
        op_base,
        rt_base,
        db_base,
        max_slots,
        max_ports,
        max_intrs,
        page_size,
        context_size,
        dcbaa: core::ptr::null_mut(),
        cmd_ring: CommandRing {
            trbs: core::ptr::null_mut(),
            enqueue: 0,
            cycle: true,
        },
        evt_ring: EventRing {
            trbs: core::ptr::null_mut(),
            erst: core::ptr::null_mut(),
            dequeue: 0,
            cycle: true,
        },
        scratchpad_array: core::ptr::null_mut(),
        scratchpad_bufs: core::ptr::null_mut(),
        scratchpad_count: 0,
    };

    // ── Setup DCBAA ──

    if !setup_dcbaa(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -5;
    }
    log("xhci: DCBAA configured");

    // ── Setup Scratchpad Buffers ──

    if !setup_scratchpad(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -6;
    }
    if ctrl.scratchpad_count > 0 {
        unsafe {
            fut_printf(
                b"xhci: %d scratchpad buffers allocated\n\0".as_ptr(),
                ctrl.scratchpad_count as u32,
            );
        }
    }

    // ── Setup Command Ring ──

    if !setup_command_ring(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -7;
    }
    log("xhci: command ring configured");

    // ── Setup Event Ring ──

    if !setup_event_ring(&mut ctrl) {
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -8;
    }
    log("xhci: event ring configured");

    // ── Enable Device Notification Control ──
    // Enable all notification types (bits [15:0])
    mmio_write32(bar0, op_base + XHCI_OP_DNCTRL, 0xFFFF);

    // ── Start the controller ──

    let usbcmd = mmio_read32(bar0, op_base + XHCI_OP_USBCMD);
    mmio_write32(bar0, op_base + XHCI_OP_USBCMD, usbcmd | USBCMD_RUN | USBCMD_INTE);

    // Wait for HCHalted to clear
    for _ in 0..1_000_000u32 {
        let sts = mmio_read32(bar0, op_base + XHCI_OP_USBSTS);
        if sts & USBSTS_HCH == 0 {
            break;
        }
        thread_yield();
    }
    let sts = mmio_read32(bar0, op_base + XHCI_OP_USBSTS);
    if sts & USBSTS_HCH != 0 {
        log("xhci: controller failed to start (still halted)");
        unsafe { unmap_mmio_region(bar0, bar0_size); }
        return -9;
    }
    log("xhci: controller running");

    // ── Verify command ring with No-Op ──

    if !test_cmd_ring(&mut ctrl) {
        // Non-fatal: log and continue
        log("xhci: warning: command ring test failed");
    }

    // ── Initialize root hub ports ──

    init_ports(&ctrl);

    // ── Enumerate connected devices ──
    //
    // After port power+reset, each connected device sits in the Default
    // address state. Walk every Enabled port and bring it through
    // Enable Slot / Address Device / GET_DESCRIPTOR so the boot log
    // shows what's actually on the USB bus and so subsequent class
    // drivers (usb_storage, usb_hub, …) have an addressed device to
    // attach to. enumerate_devices is best-effort: a failure on one
    // port doesn't block the others.
    enumerate_devices(&mut ctrl);

    // ── Store global state ──

    unsafe {
        core::ptr::addr_of_mut!(XHCI).write(Some(ctrl));
    }

    log("xhci: initialization complete");
    0
}

/// Return the number of root hub ports on the xHCI controller.
#[unsafe(no_mangle)]
pub extern "C" fn xhci_port_count() -> u32 {
    unsafe { (*core::ptr::addr_of!(XHCI)).as_ref().map_or(0, |c| c.max_ports as u32) }
}

/// Return the raw PORTSC register value for a given port (0-based).
/// Returns 0 if the controller is not initialized or port is out of range.
#[unsafe(no_mangle)]
pub extern "C" fn xhci_port_status(port: u32) -> u32 {
    unsafe {
        match (*core::ptr::addr_of!(XHCI)).as_ref() {
            Some(ctrl) => {
                if port >= ctrl.max_ports as u32 {
                    return 0;
                }
                read_portsc(ctrl.bar0, ctrl.op_base, port)
            }
            None => 0,
        }
    }
}

/// Return the speed of a device on the given port (0-based).
/// Returns: 1=Full Speed, 2=Low Speed, 3=High Speed, 4=SuperSpeed, 5=SuperSpeedPlus.
/// Returns 0 if no device is connected or controller is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn xhci_port_speed(port: u32) -> u32 {
    unsafe {
        match (*core::ptr::addr_of!(XHCI)).as_ref() {
            Some(ctrl) => {
                if port >= ctrl.max_ports as u32 {
                    return 0;
                }
                let portsc = read_portsc(ctrl.bar0, ctrl.op_base, port);
                if portsc & PORTSC_CCS == 0 {
                    return 0;
                }
                (portsc & PORTSC_SPEED_MASK) >> PORTSC_SPEED_SHIFT
            }
            None => 0,
        }
    }
}

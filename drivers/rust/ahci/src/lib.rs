// SPDX-License-Identifier: MPL-2.0
//
// AHCI (Advanced Host Controller Interface) SATA Controller Driver
//
// Implements the AHCI 1.3.1 specification for SATA-attached storage,
// targeting AMD Ryzen AM4/AM5 chipsets (AMD FCH AHCI controller).
//
// Architecture:
//   - PCI class 01h/06h/01h discovery for AHCI 1.0 controllers
//   - ABAR (BAR5) MMIO register access for HBA and per-port registers
//   - Per-port command list (32 slots x 32 bytes) and received FIS (256 bytes)
//   - Polling-based command completion (interrupt support planned)
//   - READ/WRITE DMA EXT (48-bit LBA) via command tables with PRDT
//   - Block device registration through blkcore as "sata0"
//
// PCI class: 01h (Mass Storage), subclass 06h (SATA), prog-if 01h (AHCI 1.0)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use common::{
    alloc, alloc_page, log, map_mmio_region, register, thread_yield,
    unmap_mmio_region, FutBlkBackend, FutBlkDev, FutStatus,
    FUT_BLK_ADMIN, FUT_BLK_READ, FUT_BLK_WRITE, MMIO_DEFAULT_FLAGS,
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

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    /// Returns a raw pointer to the inner value.
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

// ── HBA Generic Host Control Registers (MMIO from BAR5 / ABAR) ──

const HBA_REG_CAP: usize       = 0x00;  // Host Capabilities
const HBA_REG_GHC: usize       = 0x04;  // Global HBA Control
const HBA_REG_IS: usize        = 0x08;  // Interrupt Status
const HBA_REG_PI: usize        = 0x0C;  // Ports Implemented
const HBA_REG_VS: usize        = 0x10;  // AHCI Version
const HBA_REG_CCC_CTL: usize   = 0x14;  // Command Completion Coalescing Control
const HBA_REG_CCC_PORTS: usize = 0x18;  // Command Completion Coalescing Ports
const HBA_REG_EM_LOC: usize    = 0x1C;  // Enclosure Management Location
const HBA_REG_EM_CTL: usize    = 0x20;  // Enclosure Management Control
const HBA_REG_CAP2: usize      = 0x24;  // Host Capabilities Extended
const HBA_REG_BOHC: usize      = 0x28;  // BIOS/OS Handoff Control and Status

// GHC register bits
const GHC_AE: u32  = 1 << 31;  // AHCI Enable
const GHC_IE: u32  = 1 << 1;   // Interrupt Enable
const GHC_HR: u32  = 1 << 0;   // HBA Reset

// CAP register fields
const CAP_NP_MASK: u32 = 0x1F;        // Number of Ports (0-based)
const CAP_NCS_SHIFT: u32 = 8;         // Number of Command Slots shift
const CAP_NCS_MASK: u32 = 0x1F << 8;  // Number of Command Slots (0-based)
const CAP_S64A: u32 = 1 << 31;        // Supports 64-bit Addressing
const CAP_SNCQ: u32 = 1 << 30;        // Supports Native Command Queuing
const CAP_SSS: u32 = 1 << 27;         // Supports Staggered Spin-up

// ── Port Registers (base = ABAR + 0x100 + port * 0x80) ──

const PORT_REG_CLB: usize   = 0x00;  // Command List Base Address (lower 32 bits)
const PORT_REG_CLBU: usize  = 0x04;  // Command List Base Address (upper 32 bits)
const PORT_REG_FB: usize    = 0x08;  // FIS Base Address (lower 32 bits)
const PORT_REG_FBU: usize   = 0x0C;  // FIS Base Address (upper 32 bits)
const PORT_REG_IS: usize    = 0x10;  // Interrupt Status
const PORT_REG_IE: usize    = 0x14;  // Interrupt Enable
const PORT_REG_CMD: usize   = 0x18;  // Command and Status
const PORT_REG_TFD: usize   = 0x20;  // Task File Data
const PORT_REG_SIG: usize   = 0x24;  // Signature
const PORT_REG_SSTS: usize  = 0x28;  // SATA Status (SCR0: SStatus)
const PORT_REG_SCTL: usize  = 0x2C;  // SATA Control (SCR2: SControl)
const PORT_REG_SERR: usize  = 0x30;  // SATA Error (SCR1: SError)
const PORT_REG_SACT: usize  = 0x34;  // SATA Active (SCR3: SActive)
const PORT_REG_CI: usize    = 0x38;  // Command Issue
const PORT_REG_SNTF: usize  = 0x3C;  // SATA Notification (SCR4: SNotification)
const PORT_REG_FBS: usize   = 0x40;  // FIS-based Switching Control

// PxCMD register bits
const PORT_CMD_ST: u32   = 1 << 0;   // Start
const PORT_CMD_SUD: u32  = 1 << 1;   // Spin-Up Device
const PORT_CMD_POD: u32  = 1 << 2;   // Power On Device
const PORT_CMD_FRE: u32  = 1 << 4;   // FIS Receive Enable
const PORT_CMD_FR: u32   = 1 << 14;  // FIS Receive Running
const PORT_CMD_CR: u32   = 1 << 15;  // Command List Running
const PORT_CMD_CPS: u32  = 1 << 16;  // Cold Presence State
const PORT_CMD_PMA: u32  = 1 << 17;  // Port Multiplier Attached
const PORT_CMD_HPCP: u32 = 1 << 18;  // Hot Plug Capable Port
const PORT_CMD_MPSP: u32 = 1 << 19;  // Mechanical Presence Switch
const PORT_CMD_CPD: u32  = 1 << 20;  // Cold Presence Detection
const PORT_CMD_ESP: u32  = 1 << 21;  // External SATA Port
const PORT_CMD_ATAPI: u32 = 1 << 24; // Device is ATAPI
const PORT_CMD_DLAE: u32 = 1 << 25;  // Drive LED on ATAPI Enable
const PORT_CMD_ALPE: u32 = 1 << 26;  // Aggressive Link Power Mgmt Enable
const PORT_CMD_ASP: u32  = 1 << 27;  // Aggressive Slumber/Partial
const PORT_CMD_ICC_MASK: u32 = 0xF << 28; // Interface Communication Control
const PORT_CMD_ICC_ACTIVE: u32 = 1 << 28; // ICC = Active

// PxIS (Interrupt Status) bits
const PORT_IS_DHRS: u32 = 1 << 0;    // Device to Host Register FIS
const PORT_IS_PSS: u32  = 1 << 1;    // PIO Setup FIS
const PORT_IS_DSS: u32  = 1 << 2;    // DMA Setup FIS
const PORT_IS_SDBS: u32 = 1 << 3;    // Set Device Bits
const PORT_IS_DPS: u32  = 1 << 5;    // Descriptor Processed
const PORT_IS_TFES: u32 = 1 << 30;   // Task File Error Status

// PxTFD (Task File Data) bits
const PORT_TFD_ERR: u32 = 1 << 0;    // Error
const PORT_TFD_DRQ: u32 = 1 << 3;    // Data Request
const PORT_TFD_BSY: u32 = 1 << 7;    // Busy

// PxSSTS (SStatus) fields
const SSTS_DET_MASK: u32 = 0xF;         // Device Detection
const SSTS_DET_DEV_PHY: u32 = 0x3;      // Device present + Phy established
const SSTS_SPD_MASK: u32 = 0xF0;        // Current Interface Speed
const SSTS_IPM_MASK: u32 = 0xF00;       // Interface Power Management
const SSTS_IPM_ACTIVE: u32 = 0x100;     // Interface in active state

// SATA device signatures
const SATA_SIG_ATA: u32   = 0x00000101; // SATA drive
const SATA_SIG_ATAPI: u32 = 0xEB140101; // SATAPI drive
const SATA_SIG_SEMB: u32  = 0xC33C0101; // Enclosure management bridge
const SATA_SIG_PM: u32    = 0x96690101; // Port multiplier

// ATA commands
const ATA_CMD_IDENTIFY: u8     = 0xEC;  // IDENTIFY DEVICE
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;  // READ DMA EXT (48-bit LBA)
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35; // WRITE DMA EXT (48-bit LBA)

// FIS types (Serial ATA revision 3.0)
const FIS_TYPE_REG_H2D: u8 = 0x27;  // Register FIS - Host to Device
const FIS_TYPE_REG_D2H: u8 = 0x34;  // Register FIS - Device to Host
const FIS_TYPE_DMA_ACT: u8 = 0x39;  // DMA Activate FIS
const FIS_TYPE_DMA_SETUP: u8 = 0x41; // DMA Setup FIS
const FIS_TYPE_DATA: u8    = 0x46;  // Data FIS
const FIS_TYPE_BIST: u8    = 0x58;  // BIST Activate FIS
const FIS_TYPE_PIO_SETUP: u8 = 0x5F; // PIO Setup FIS
const FIS_TYPE_DEV_BITS: u8 = 0xA1; // Set Device Bits FIS

// ── Command Header (32 bytes per slot, 32 slots per port) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct AhciCmdHeader {
    /// DW0: Description Information
    ///   [4:0]  CFL - Command FIS Length in DWORDs (2..16)
    ///   [5]    A - ATAPI
    ///   [6]    W - Write (1 = H2D data transfer)
    ///   [7]    P - Prefetchable
    ///   [8]    R - Reset
    ///   [9]    B - BIST
    ///   [10]   C - Clear Busy upon R_OK
    ///   [15:12] PMP - Port Multiplier Port
    ///   [31:16] PRDTL - Physical Region Descriptor Table Length (entries)
    dw0: u32,
    /// DW1: PRD Byte Count (updated by HBA after transfer)
    prdbc: u32,
    /// DW2: Command Table Base Address (lower 32 bits, 128-byte aligned)
    ctba: u32,
    /// DW3: Command Table Base Address (upper 32 bits)
    ctbau: u32,
    /// DW4-7: Reserved
    _reserved: [u32; 4],
}

const _: () = assert!(core::mem::size_of::<AhciCmdHeader>() == 32);

impl AhciCmdHeader {
    const fn zeroed() -> Self {
        Self {
            dw0: 0,
            prdbc: 0,
            ctba: 0,
            ctbau: 0,
            _reserved: [0; 4],
        }
    }
}

// ── Physical Region Descriptor Table Entry (16 bytes) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct AhciPrdtEntry {
    /// DW0: Data Base Address (lower 32 bits, word-aligned)
    dba: u32,
    /// DW1: Data Base Address (upper 32 bits)
    dbau: u32,
    /// DW2: Reserved
    _reserved: u32,
    /// DW3: Description Information
    ///   [21:0]  DBC - Data Byte Count (0-based, max 4 MiB, must be odd = even byte count - 1)
    ///   [31]    I - Interrupt on Completion
    dw3: u32,
}

const _: () = assert!(core::mem::size_of::<AhciPrdtEntry>() == 16);

// ── Command Table ──
// Layout: CFIS (64 bytes) + ACMD (16 bytes) + Reserved (48 bytes) + PRDT entries
// Minimum size: 128 bytes (header) + n * 16 bytes (PRDT)
// Must be 128-byte aligned.

const CMD_TABLE_HEADER_SIZE: usize = 128; // CFIS(64) + ACMD(16) + Reserved(48)
const MAX_PRDT_ENTRIES: usize = 8;        // Sufficient for typical I/O (8 * 4 MiB = 32 MiB max)

#[repr(C)]
#[derive(Clone, Copy)]
struct AhciCmdTable {
    /// Command FIS (up to 64 bytes, typically 20 bytes for H2D register FIS)
    cfis: [u8; 64],
    /// ATAPI Command (16 bytes, used for ATAPI devices only)
    acmd: [u8; 16],
    /// Reserved (48 bytes)
    _reserved: [u8; 48],
    /// Physical Region Descriptor Table
    prdt: [AhciPrdtEntry; MAX_PRDT_ENTRIES],
}

const _: () = assert!(core::mem::size_of::<AhciCmdTable>() == CMD_TABLE_HEADER_SIZE + MAX_PRDT_ENTRIES * 16);

impl AhciCmdTable {
    const fn zeroed() -> Self {
        Self {
            cfis: [0; 64],
            acmd: [0; 16],
            _reserved: [0; 48],
            prdt: [AhciPrdtEntry { dba: 0, dbau: 0, _reserved: 0, dw3: 0 }; MAX_PRDT_ENTRIES],
        }
    }
}

// ── Register FIS - Host to Device (20 bytes, padded to 5 DWORDs) ──

#[repr(C)]
#[derive(Clone, Copy)]
struct FisRegH2D {
    fis_type: u8,      // FIS_TYPE_REG_H2D (0x27)
    flags: u8,         // [7] C - Command/Control, [3:0] PM Port
    command: u8,       // ATA command register
    feature_lo: u8,    // Feature register (7:0)
    lba0: u8,          // LBA (7:0)
    lba1: u8,          // LBA (15:8)
    lba2: u8,          // LBA (23:16)
    device: u8,        // Device register
    lba3: u8,          // LBA (31:24)
    lba4: u8,          // LBA (39:32)
    lba5: u8,          // LBA (47:40)
    feature_hi: u8,    // Feature register (15:8)
    count_lo: u8,      // Sector count (7:0)
    count_hi: u8,      // Sector count (15:8)
    icc: u8,           // Isochronous Command Completion
    control: u8,       // Control register
    _reserved: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<FisRegH2D>() == 20);

// ── Received FIS structure (256 bytes per port) ──

#[repr(C)]
struct AhciRecvFis {
    dsfis: [u8; 28],       // DMA Setup FIS (0x00)
    _pad0: [u8; 4],
    psfis: [u8; 20],       // PIO Setup FIS (0x20)
    _pad1: [u8; 12],
    rfis: [u8; 20],        // D2H Register FIS (0x40)
    _pad2: [u8; 4],
    sdbfis: [u8; 8],       // Set Device Bits FIS (0x58)
    ufis: [u8; 64],        // Unknown FIS (0x60)
    _reserved: [u8; 96],   // Reserved (0xA0)
}

const _: () = assert!(core::mem::size_of::<AhciRecvFis>() == 256);

// ── Per-port state ──

const AHCI_MAX_PORTS: usize = 32;
const CMD_SLOTS: usize = 32;

struct AhciPort {
    /// Port number (0-31)
    port_num: u32,
    /// MMIO base for this port's registers (ABAR + 0x100 + port * 0x80)
    regs: *mut u8,
    /// Command list (32 command headers, 1 KiB, 1 KiB aligned)
    cmd_list: *mut AhciCmdHeader,
    /// Received FIS area (256 bytes, 256-byte aligned)
    recv_fis: *mut AhciRecvFis,
    /// Command tables (one per slot)
    cmd_tables: [*mut AhciCmdTable; CMD_SLOTS],
    /// Device present and identified
    present: bool,
    /// SATA device signature
    signature: u32,
    /// Drive capacity in sectors (from IDENTIFY)
    sector_count: u64,
    /// Sector size in bytes (from IDENTIFY, typically 512)
    sector_size: u32,
    /// Model string from IDENTIFY (40 chars + NUL)
    model: [u8; 41],
    /// Serial string from IDENTIFY (20 chars + NUL)
    serial: [u8; 21],
}

impl AhciPort {
    const fn empty() -> Self {
        Self {
            port_num: 0,
            regs: core::ptr::null_mut(),
            cmd_list: core::ptr::null_mut(),
            recv_fis: core::ptr::null_mut(),
            cmd_tables: [core::ptr::null_mut(); CMD_SLOTS],
            present: false,
            signature: 0,
            sector_count: 0,
            sector_size: 512,
            model: [0; 41],
            serial: [0; 21],
        }
    }
}

// ── HBA Controller state ──

struct AhciController {
    /// ABAR virtual address (BAR5 mapped)
    abar: *mut u8,
    /// ABAR MMIO region size
    abar_size: usize,
    /// PCI location
    bus: u8,
    dev: u8,
    func: u8,
    /// Number of ports supported by the HBA (from CAP.NP + 1)
    num_ports: u32,
    /// Number of command slots (from CAP.NCS + 1)
    num_cmd_slots: u32,
    /// Ports Implemented bitmask
    ports_impl: u32,
    /// Supports 64-bit addressing
    s64a: bool,
    /// Port states
    ports: [AhciPort; AHCI_MAX_PORTS],
    /// Index of first active SATA port (for block device)
    active_port: i32,
}

// Global controller state
static AHCI: StaticCell<Option<AhciController>> = StaticCell::new(None);

// ── Port register access helpers ──

fn port_base(abar: *mut u8, port: u32) -> *mut u8 {
    // AHCI spec: port registers at ABAR + 0x100 + (port * 0x80)
    unsafe { abar.add(0x100 + (port as usize) * 0x80) }
}

fn port_read32(port_regs: *mut u8, offset: usize) -> u32 {
    mmio_read32(port_regs, offset)
}

fn port_write32(port_regs: *mut u8, offset: usize, val: u32) {
    mmio_write32(port_regs, offset, val);
}

// ── PCI discovery ──

fn find_ahci_pci() -> Option<(u8, u8, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        // AHCI: class=01h (Mass Storage), subclass=06h (SATA), prog_if=01h (AHCI 1.0)
        if dev.class_code == 0x01 && dev.subclass == 0x06 && dev.prog_if == 0x01 {
            return Some((dev.bus, dev.dev, dev.func));
        }
    }
    None
}

// ── HBA reset ──

/// Perform an HBA reset as specified in AHCI 1.3.1 section 10.4.3.
/// Sets GHC.HR and waits for the HBA to clear it (max 1 second).
fn hba_reset(abar: *mut u8) -> bool {
    // 1. Set GHC.HR to 1
    let ghc = mmio_read32(abar, HBA_REG_GHC);
    mmio_write32(abar, HBA_REG_GHC, ghc | GHC_HR);

    // 2. Wait for GHC.HR to be cleared by hardware (up to 1 second per spec)
    for _ in 0..1_000_000u32 {
        let ghc = mmio_read32(abar, HBA_REG_GHC);
        if ghc & GHC_HR == 0 {
            // 3. Re-enable AHCI mode after reset
            mmio_write32(abar, HBA_REG_GHC, mmio_read32(abar, HBA_REG_GHC) | GHC_AE);
            return true;
        }
        thread_yield();
    }
    log("ahci: HBA reset timeout");
    false
}

// ── Port command engine start/stop ──

/// Stop the command engine for a port (AHCI 1.3.1 section 10.3.2).
/// Clears CMD.ST, then waits for CMD.CR to clear.
/// Also clears CMD.FRE and waits for CMD.FR to clear.
fn port_stop_cmd(port_regs: *mut u8) {
    let cmd = port_read32(port_regs, PORT_REG_CMD);

    // If ST is not set, engine is already stopped
    if cmd & PORT_CMD_ST != 0 {
        // Clear ST
        port_write32(port_regs, PORT_REG_CMD, cmd & !PORT_CMD_ST);

        // Wait for CR (Command List Running) to clear (up to 500ms per spec)
        for _ in 0..500_000u32 {
            if port_read32(port_regs, PORT_REG_CMD) & PORT_CMD_CR == 0 {
                break;
            }
            thread_yield();
        }
    }

    // Clear FRE
    let cmd = port_read32(port_regs, PORT_REG_CMD);
    if cmd & PORT_CMD_FRE != 0 {
        port_write32(port_regs, PORT_REG_CMD, cmd & !PORT_CMD_FRE);

        // Wait for FR (FIS Receive Running) to clear
        for _ in 0..500_000u32 {
            if port_read32(port_regs, PORT_REG_CMD) & PORT_CMD_FR == 0 {
                break;
            }
            thread_yield();
        }
    }
}

/// Start the command engine for a port (AHCI 1.3.1 section 10.3.1).
/// Enables FIS reception (CMD.FRE), then sets CMD.ST.
fn port_start_cmd(port_regs: *mut u8) {
    // Wait until CR is cleared before starting
    for _ in 0..500_000u32 {
        if port_read32(port_regs, PORT_REG_CMD) & PORT_CMD_CR == 0 {
            break;
        }
        thread_yield();
    }

    let cmd = port_read32(port_regs, PORT_REG_CMD);
    // Enable FIS Receive first, then Start
    port_write32(port_regs, PORT_REG_CMD, cmd | PORT_CMD_FRE);

    // Small delay for FRE to take effect
    for _ in 0..1000u32 { thread_yield(); }

    let cmd = port_read32(port_regs, PORT_REG_CMD);
    port_write32(port_regs, PORT_REG_CMD, cmd | PORT_CMD_ST);
}

// ── Port initialisation (allocate command list, received FIS, command tables) ──

/// Initialise a port's memory structures.
/// Returns true on success.
fn port_init(port: &mut AhciPort, abar: *mut u8, port_num: u32, s64a: bool) -> bool {
    port.port_num = port_num;
    port.regs = port_base(abar, port_num);

    // Stop command engine before reconfiguring
    port_stop_cmd(port.regs);

    // Clear any pending interrupt status and error bits
    port_write32(port.regs, PORT_REG_IS, 0xFFFFFFFF);
    port_write32(port.regs, PORT_REG_SERR, 0xFFFFFFFF);

    // Allocate command list (32 headers * 32 bytes = 1024 bytes, 1 KiB aligned)
    // Using a full page (4 KiB) for alignment guarantee
    let cmd_list = unsafe { alloc_page() as *mut AhciCmdHeader };
    if cmd_list.is_null() {
        log("ahci: failed to allocate command list");
        return false;
    }
    unsafe { core::ptr::write_bytes(cmd_list, 0, CMD_SLOTS); }
    port.cmd_list = cmd_list;

    // Set CLB/CLBU
    let clb_phys = virt_to_phys(cmd_list as *const u8);
    port_write32(port.regs, PORT_REG_CLB, clb_phys as u32);
    port_write32(port.regs, PORT_REG_CLBU, if s64a { (clb_phys >> 32) as u32 } else { 0 });

    // Allocate received FIS area (256 bytes, 256-byte aligned)
    // Using a full page for alignment guarantee
    let recv_fis = unsafe { alloc_page() as *mut AhciRecvFis };
    if recv_fis.is_null() {
        log("ahci: failed to allocate received FIS");
        return false;
    }
    unsafe { core::ptr::write_bytes(recv_fis as *mut u8, 0, 4096); }
    port.recv_fis = recv_fis;

    // Set FB/FBU
    let fb_phys = virt_to_phys(recv_fis as *const u8);
    port_write32(port.regs, PORT_REG_FB, fb_phys as u32);
    port_write32(port.regs, PORT_REG_FBU, if s64a { (fb_phys >> 32) as u32 } else { 0 });

    // Allocate command tables (one per slot)
    // Each command table: 128 bytes header + 8 * 16 bytes PRDT = 256 bytes
    // Must be 128-byte aligned; we allocate from pages for alignment
    for slot in 0..CMD_SLOTS {
        let ct = unsafe { alloc_page() as *mut AhciCmdTable };
        if ct.is_null() {
            log("ahci: failed to allocate command table");
            return false;
        }
        unsafe { core::ptr::write_bytes(ct as *mut u8, 0, 4096); }
        port.cmd_tables[slot] = ct;

        // Write command table address into the command header
        let ct_phys = virt_to_phys(ct as *const u8);
        unsafe {
            let hdr = &mut *cmd_list.add(slot);
            hdr.ctba = ct_phys as u32;
            hdr.ctbau = if s64a { (ct_phys >> 32) as u32 } else { 0 };
        }
    }

    true
}

// ── Device detection ──

/// Check if a SATA device is present on a port by examining SStatus.DET.
/// Returns true if a device is detected and Phy communication is established.
fn port_device_present(port_regs: *mut u8) -> bool {
    let ssts = port_read32(port_regs, PORT_REG_SSTS);
    let det = ssts & SSTS_DET_MASK;
    let ipm = ssts & SSTS_IPM_MASK;
    // DET = 3 (device present + Phy established) and IPM = 1 (active)
    det == SSTS_DET_DEV_PHY && ipm == SSTS_IPM_ACTIVE
}

/// Wait for the port's task file to become not-busy.
/// Returns true if BSY and DRQ clear within the timeout.
fn port_wait_ready(port_regs: *mut u8) -> bool {
    for _ in 0..1_000_000u32 {
        let tfd = port_read32(port_regs, PORT_REG_TFD);
        if tfd & (PORT_TFD_BSY | PORT_TFD_DRQ) == 0 {
            return true;
        }
        thread_yield();
    }
    false
}

// ── Build Register FIS - Host to Device ──

fn build_h2d_fis(
    cfis: &mut [u8; 64],
    command: u8,
    lba: u64,
    count: u16,
    device: u8,
    features: u16,
) {
    // Zero the CFIS area
    cfis.fill(0);

    let fis = cfis.as_mut_ptr() as *mut FisRegH2D;
    unsafe {
        (*fis).fis_type = FIS_TYPE_REG_H2D;
        (*fis).flags = 0x80; // C bit = 1 (command update)
        (*fis).command = command;
        (*fis).feature_lo = features as u8;
        (*fis).feature_hi = (features >> 8) as u8;
        (*fis).lba0 = lba as u8;
        (*fis).lba1 = (lba >> 8) as u8;
        (*fis).lba2 = (lba >> 16) as u8;
        (*fis).device = device;
        (*fis).lba3 = (lba >> 24) as u8;
        (*fis).lba4 = (lba >> 32) as u8;
        (*fis).lba5 = (lba >> 40) as u8;
        (*fis).count_lo = count as u8;
        (*fis).count_hi = (count >> 8) as u8;
        (*fis).icc = 0;
        (*fis).control = 0;
    }
}

// ── Issue a command on a port (slot 0, polling) ──

/// Issue a command using slot 0 and poll for completion.
/// `write` indicates a host-to-device data transfer.
/// `buf_phys` is the physical address of the data buffer, `byte_count` is the total size.
/// Returns 0 on success, negative on error.
fn port_issue_cmd(
    port: &mut AhciPort,
    cfis: &[u8; 64],
    cfl_dwords: u8,
    write: bool,
    buf_phys: u64,
    byte_count: u32,
) -> i32 {
    let slot = 0usize;

    // Wait for slot 0 to be free (CI bit cleared)
    for _ in 0..1_000_000u32 {
        if port_read32(port.regs, PORT_REG_CI) & (1 << slot) == 0 {
            break;
        }
        thread_yield();
    }
    if port_read32(port.regs, PORT_REG_CI) & (1 << slot) != 0 {
        return -1; // Slot busy timeout
    }

    // Wait for port not busy
    if !port_wait_ready(port.regs) {
        return -2;
    }

    // Fill in the command table
    let ct = port.cmd_tables[slot];
    if ct.is_null() {
        return -3;
    }
    unsafe {
        let ct_ref = &mut *ct;
        // Copy the CFIS
        ct_ref.cfis.copy_from_slice(cfis);

        // Set up PRDT entries for the data buffer
        if byte_count > 0 && buf_phys != 0 {
            // Calculate number of PRDT entries needed
            // Each PRDT entry can address up to 4 MiB, but we keep it simpler:
            // use 4 KiB per entry to handle page boundaries correctly
            let mut remaining = byte_count as u64;
            let mut offset = 0u64;
            let mut prdt_idx = 0usize;

            while remaining > 0 && prdt_idx < MAX_PRDT_ENTRIES {
                // Size for this entry (up to 4 MiB, but cap at remaining)
                let chunk = if remaining > 0x400000 { 0x400000u64 } else { remaining };

                ct_ref.prdt[prdt_idx].dba = (buf_phys + offset) as u32;
                ct_ref.prdt[prdt_idx].dbau = ((buf_phys + offset) >> 32) as u32;
                ct_ref.prdt[prdt_idx]._reserved = 0;
                // DBC is 0-based byte count: actual_bytes - 1
                // Bit 31 = Interrupt on Completion (set on last entry)
                let is_last = remaining <= chunk;
                ct_ref.prdt[prdt_idx].dw3 = ((chunk as u32) - 1)
                    | if is_last { 1u32 << 31 } else { 0 };

                remaining -= chunk;
                offset += chunk;
                prdt_idx += 1;
            }

            // Fill command header
            let hdr = &mut *port.cmd_list.add(slot);
            // DW0: CFL, Write flag, PRDTL
            let mut dw0 = cfl_dwords as u32;      // CFL (Command FIS Length in DWORDs)
            if write { dw0 |= 1 << 6; }           // W bit
            dw0 |= 1 << 10;                       // C bit - clear BSY on R_OK
            dw0 |= (prdt_idx as u32) << 16;       // PRDTL
            hdr.dw0 = dw0;
            hdr.prdbc = 0;  // Cleared by software, updated by HBA
        } else {
            // No data transfer
            let hdr = &mut *port.cmd_list.add(slot);
            hdr.dw0 = (cfl_dwords as u32) | (1 << 10); // CFL + C bit
            hdr.prdbc = 0;
        }
    }

    // Ensure writes are visible
    fence(Ordering::SeqCst);

    // Clear any pending interrupt status
    port_write32(port.regs, PORT_REG_IS, 0xFFFFFFFF);

    // Issue the command
    port_write32(port.regs, PORT_REG_CI, 1 << slot);

    // Poll for completion
    for _ in 0..10_000_000u32 {
        let is = port_read32(port.regs, PORT_REG_IS);

        // Check for task file error
        if is & PORT_IS_TFES != 0 {
            let tfd = port_read32(port.regs, PORT_REG_TFD);
            let err = (tfd >> 8) & 0xFF;
            unsafe {
                fut_printf(
                    b"ahci: port %u cmd error: TFD=0x%08x err=0x%02x\n\0".as_ptr(),
                    port.port_num, tfd, err,
                );
            }
            // Clear error state
            port_write32(port.regs, PORT_REG_IS, PORT_IS_TFES);
            port_write32(port.regs, PORT_REG_SERR, port_read32(port.regs, PORT_REG_SERR));
            return -4;
        }

        // Check if command has completed (CI bit cleared by HBA)
        if port_read32(port.regs, PORT_REG_CI) & (1 << slot) == 0 {
            // Clear interrupt status
            port_write32(port.regs, PORT_REG_IS, is);
            return 0;
        }

        thread_yield();
    }

    // Timeout
    log("ahci: command timeout");
    -5
}

// ── IDENTIFY DEVICE ──

/// Issue ATA IDENTIFY DEVICE (0xEC) to the specified port.
/// `buf` must point to at least 512 bytes of accessible memory.
/// Returns 0 on success.
fn port_identify(port: &mut AhciPort, buf: *mut u8) -> i32 {
    let buf_phys = virt_to_phys(buf);

    // Build H2D register FIS for IDENTIFY DEVICE
    let mut cfis = [0u8; 64];
    build_h2d_fis(
        &mut cfis,
        ATA_CMD_IDENTIFY,
        0,        // LBA = 0
        1,        // Count = 1 sector (not used by IDENTIFY but set anyway)
        0,        // Device = 0
        0,        // Features = 0
    );

    // CFL = 5 DWORDs (20 bytes for Register H2D FIS)
    let rc = port_issue_cmd(port, &cfis, 5, false, buf_phys, 512);
    if rc != 0 {
        return rc;
    }

    // Parse IDENTIFY data
    let data = buf as *const u16;
    unsafe {
        // Words 60-61: Total addressable sectors (28-bit LBA)
        let lba28 = read_volatile(data.add(60)) as u64
                  | ((read_volatile(data.add(61)) as u64) << 16);

        // Words 100-103: Total addressable sectors (48-bit LBA)
        let lba48 = read_volatile(data.add(100)) as u64
                  | ((read_volatile(data.add(101)) as u64) << 16)
                  | ((read_volatile(data.add(102)) as u64) << 32)
                  | ((read_volatile(data.add(103)) as u64) << 48);

        // Use 48-bit count if nonzero and larger (indicates 48-bit LBA support)
        port.sector_count = if lba48 > 0 { lba48 } else { lba28 };

        // Word 106: Physical/Logical sector size
        let w106 = read_volatile(data.add(106));
        if w106 & (1 << 14) != 0 && w106 & (1 << 12) != 0 {
            // Logical sector size is in words 117-118
            let lss = read_volatile(data.add(117)) as u32
                    | ((read_volatile(data.add(118)) as u32) << 16);
            port.sector_size = lss * 2; // Words to bytes
        } else {
            port.sector_size = 512;
        }

        // Words 27-46: Model number (40 ASCII chars, byte-swapped per word)
        for i in 0..20 {
            let w = read_volatile(data.add(27 + i));
            port.model[i * 2] = (w >> 8) as u8;
            port.model[i * 2 + 1] = w as u8;
        }
        port.model[40] = 0;
        // Trim trailing spaces
        let mut end = 39;
        while end > 0 && (port.model[end] == b' ' || port.model[end] == 0) {
            port.model[end] = 0;
            end -= 1;
        }

        // Words 10-19: Serial number (20 ASCII chars, byte-swapped per word)
        for i in 0..10 {
            let w = read_volatile(data.add(10 + i));
            port.serial[i * 2] = (w >> 8) as u8;
            port.serial[i * 2 + 1] = w as u8;
        }
        port.serial[20] = 0;
        let mut end = 19;
        while end > 0 && (port.serial[end] == b' ' || port.serial[end] == 0) {
            port.serial[end] = 0;
            end -= 1;
        }
    }

    0
}

// ── READ DMA EXT / WRITE DMA EXT ──

fn port_rw_dma(port: &mut AhciPort, lba: u64, nsectors: usize, buf_phys: u64, write: bool) -> i32 {
    let cmd = if write { ATA_CMD_WRITE_DMA_EXT } else { ATA_CMD_READ_DMA_EXT };
    let byte_count = nsectors as u32 * port.sector_size;

    let mut cfis = [0u8; 64];
    build_h2d_fis(
        &mut cfis,
        cmd,
        lba,
        nsectors as u16,
        1 << 6,   // LBA mode (bit 6 of device register)
        0,        // Features = 0
    );

    port_issue_cmd(port, &cfis, 5, write, buf_phys, byte_count)
}

// ── BIOS/OS Handoff (AHCI 1.3.1 section 10.6) ──

fn perform_bios_handoff(abar: *mut u8) {
    let cap2 = mmio_read32(abar, HBA_REG_CAP2);
    if cap2 & 1 == 0 {
        // BOH not supported
        return;
    }

    let bohc = mmio_read32(abar, HBA_REG_BOHC);
    // If BIOS doesn't own, nothing to do
    if bohc & (1 << 1) == 0 {
        return;
    }

    // Set OOS (OS Ownership Semaphore)
    mmio_write32(abar, HBA_REG_BOHC, bohc | (1 << 1));

    // Wait for BIOS to release (BB bit cleared, up to 2 seconds)
    for _ in 0..2_000_000u32 {
        let bohc = mmio_read32(abar, HBA_REG_BOHC);
        if bohc & 1 == 0 {
            // BIOS released ownership
            return;
        }
        thread_yield();
    }

    // If BIOS is still busy after 2 seconds, wait another 2 seconds per spec
    for _ in 0..2_000_000u32 {
        thread_yield();
    }
    log("ahci: BIOS handoff timeout (proceeding anyway)");
}

// ── Block device backend callbacks ──

unsafe extern "C" fn ahci_read_cb(
    _ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *mut c_void,
) -> FutStatus {
    let ctrl = unsafe { &mut *AHCI.get() };
    let ctrl = match ctrl.as_mut() {
        Some(c) => c,
        None => return -1,
    };
    if ctrl.active_port < 0 {
        return -1;
    }
    let port = &mut ctrl.ports[ctrl.active_port as usize];
    let buf_phys = virt_to_phys(buf as *const u8);
    port_rw_dma(port, lba, nsectors, buf_phys, false)
}

unsafe extern "C" fn ahci_write_cb(
    _ctx: *mut c_void,
    lba: u64,
    nsectors: usize,
    buf: *const c_void,
) -> FutStatus {
    let ctrl = unsafe { &mut *AHCI.get() };
    let ctrl = match ctrl.as_mut() {
        Some(c) => c,
        None => return -1,
    };
    if ctrl.active_port < 0 {
        return -1;
    }
    let port = &mut ctrl.ports[ctrl.active_port as usize];
    let buf_phys = virt_to_phys(buf as *const u8);
    port_rw_dma(port, lba, nsectors, buf_phys, true)
}

unsafe extern "C" fn ahci_flush_cb(_ctx: *mut c_void) -> FutStatus {
    // AHCI does not require explicit flush for DMA commands;
    // the controller handles write posting. Return success.
    0
}

static AHCI_BACKEND: FutBlkBackend = FutBlkBackend {
    read: Some(ahci_read_cb),
    write: Some(ahci_write_cb),
    flush: Some(ahci_flush_cb),
};

// ── FFI exports ──

/// Initialise the AHCI SATA controller.
/// Scans PCI for AHCI devices, resets the HBA, initialises ports,
/// identifies attached SATA drives, and registers the first drive as "sata0".
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn rust_ahci_init() -> i32 {
    log("ahci: scanning PCI for AHCI controllers...");

    let (bus, dev, func) = match find_ahci_pci() {
        Some(bdf) => bdf,
        None => {
            log("ahci: no AHCI controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"ahci: found controller at PCI %02x:%02x.%x\n\0".as_ptr(),
            bus as u32, dev as u32, func as u32,
        );
    }

    // Enable PCI bus mastering and memory space access
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06); // Memory Space + Bus Master

    // Read BAR5 (AHCI Base Memory Register / ABAR)
    // BAR5 is at PCI config offset 0x24 for header type 0
    let bar5_lo = pci_read32(bus, dev, func, 0x24);
    let bar5_type = (bar5_lo >> 1) & 0x3;
    let bar5_addr = bar5_lo & !0xF;

    let bar5_phys = if bar5_type == 0x02 {
        // 64-bit BAR: upper 32 bits in next register
        let bar5_hi = pci_read32(bus, dev, func, 0x28);
        (bar5_addr as u64) | ((bar5_hi as u64) << 32)
    } else {
        bar5_addr as u64
    };

    if bar5_phys == 0 {
        log("ahci: BAR5 (ABAR) not configured");
        return -2;
    }

    unsafe {
        fut_printf(b"ahci: ABAR at physical 0x%llx\n\0".as_ptr(), bar5_phys);
    }

    // Map ABAR MMIO region
    // AHCI generic registers: 0x00-0x2B (44 bytes)
    // Port registers: 0x100 + 32 * 0x80 = 0x1100 max
    // Map 8 KiB to cover all 32 ports comfortably
    let abar_size = 0x2000usize;
    let abar = unsafe { map_mmio_region(bar5_phys, abar_size, MMIO_DEFAULT_FLAGS) };
    if abar.is_null() {
        log("ahci: failed to map ABAR");
        return -3;
    }

    // Perform BIOS/OS handoff if supported
    perform_bios_handoff(abar);

    // Enable AHCI mode (GHC.AE = 1)
    let ghc = mmio_read32(abar, HBA_REG_GHC);
    if ghc & GHC_AE == 0 {
        mmio_write32(abar, HBA_REG_GHC, ghc | GHC_AE);
    }

    // Read version
    let vs = mmio_read32(abar, HBA_REG_VS);
    let vs_major = (vs >> 16) & 0xFFFF;
    let vs_minor_hi = (vs >> 8) & 0xFF;
    let vs_minor_lo = vs & 0xFF;
    unsafe {
        fut_printf(
            b"ahci: version %d.%d%d\n\0".as_ptr(),
            vs_major, vs_minor_hi, vs_minor_lo,
        );
    }

    // Perform HBA reset
    if !hba_reset(abar) {
        unsafe { unmap_mmio_region(abar, abar_size); }
        return -4;
    }
    log("ahci: HBA reset complete");

    // Re-enable AHCI mode after reset (already done in hba_reset, but be safe)
    mmio_write32(abar, HBA_REG_GHC, mmio_read32(abar, HBA_REG_GHC) | GHC_AE);

    // Read capabilities
    let cap = mmio_read32(abar, HBA_REG_CAP);
    let num_ports = (cap & CAP_NP_MASK) + 1;
    let num_cmd_slots = ((cap & CAP_NCS_MASK) >> CAP_NCS_SHIFT) + 1;
    let s64a = cap & CAP_S64A != 0;
    let sncq = cap & CAP_SNCQ != 0;

    let pi = mmio_read32(abar, HBA_REG_PI);

    unsafe {
        fut_printf(
            b"ahci: CAP=0x%08x ports=%d cmd_slots=%d 64bit=%d NCQ=%d PI=0x%08x\n\0".as_ptr(),
            cap, num_ports, num_cmd_slots, s64a as u32, sncq as u32, pi,
        );
    }

    // Build controller state
    let mut ctrl = AhciController {
        abar,
        abar_size,
        bus,
        dev,
        func,
        num_ports,
        num_cmd_slots,
        ports_impl: pi,
        s64a,
        ports: [const { AhciPort::empty() }; AHCI_MAX_PORTS],
        active_port: -1,
    };

    // Allocate identify buffer (reusable, 512 bytes but use a page for alignment)
    let identify_buf = unsafe { alloc_page() };
    if identify_buf.is_null() {
        log("ahci: failed to allocate identify buffer");
        unsafe { unmap_mmio_region(abar, abar_size); }
        return -5;
    }

    // Scan and initialise implemented ports
    let mut first_sata_port: i32 = -1;

    for port_num in 0..AHCI_MAX_PORTS as u32 {
        if pi & (1 << port_num) == 0 {
            continue; // Port not implemented
        }

        let port = &mut ctrl.ports[port_num as usize];

        // Initialise port memory structures
        if !port_init(port, abar, port_num, s64a) {
            continue;
        }

        // Start the command engine
        port_start_cmd(port.regs);

        // Check for device presence
        if !port_device_present(port.regs) {
            continue;
        }

        // Read device signature
        port.signature = port_read32(port.regs, PORT_REG_SIG);

        let ssts = port_read32(port.regs, PORT_REG_SSTS);
        let spd = (ssts & SSTS_SPD_MASK) >> 4;
        let gen_str = match spd {
            1 => b"Gen1 (1.5 Gbps)\0".as_ptr(),
            2 => b"Gen2 (3.0 Gbps)\0".as_ptr(),
            3 => b"Gen3 (6.0 Gbps)\0".as_ptr(),
            _ => b"unknown\0".as_ptr(),
        };

        unsafe {
            fut_printf(
                b"ahci: port %u: device detected (SIG=0x%08x, speed=%s)\n\0".as_ptr(),
                port_num, port.signature, gen_str,
            );
        }

        // Only handle SATA drives (not ATAPI, SEMB, or port multipliers)
        if port.signature != SATA_SIG_ATA {
            unsafe {
                fut_printf(
                    b"ahci: port %u: not a SATA drive (SIG=0x%08x), skipping\n\0".as_ptr(),
                    port_num, port.signature,
                );
            }
            continue;
        }

        // Issue IDENTIFY DEVICE
        unsafe { core::ptr::write_bytes(identify_buf, 0, 512); }
        let rc = port_identify(port, identify_buf);
        if rc != 0 {
            unsafe {
                fut_printf(
                    b"ahci: port %u: IDENTIFY DEVICE failed (%d)\n\0".as_ptr(),
                    port_num, rc,
                );
            }
            continue;
        }

        port.present = true;

        let size_mib = (port.sector_count * port.sector_size as u64) / (1024 * 1024);
        let size_gib = size_mib / 1024;

        unsafe {
            fut_printf(
                b"ahci: port %u: %s\n\0".as_ptr(),
                port_num, port.model.as_ptr(),
            );
            fut_printf(
                b"ahci: port %u: serial=%s sectors=%llu sector_size=%u (%llu MiB / %llu GiB)\n\0".as_ptr(),
                port_num, port.serial.as_ptr(), port.sector_count,
                port.sector_size, size_mib, size_gib,
            );
        }

        if first_sata_port < 0 {
            first_sata_port = port_num as i32;
        }
    }

    // Free the temporary identify buffer
    unsafe { common::free_page(identify_buf); }

    if first_sata_port < 0 {
        log("ahci: no SATA drives detected");
        unsafe { unmap_mmio_region(abar, abar_size); }
        return -6;
    }

    ctrl.active_port = first_sata_port;

    // Store controller state globally
    unsafe { *AHCI.get() = Some(ctrl); }

    // Register first SATA drive as block device "sata0"
    let ctrl_ref = unsafe { (*AHCI.get()).as_ref().unwrap() };
    let port = &ctrl_ref.ports[first_sata_port as usize];

    let blkdev = unsafe { alloc(core::mem::size_of::<FutBlkDev>()) as *mut FutBlkDev };
    if blkdev.is_null() {
        log("ahci: failed to allocate blkdev");
        return -7;
    }

    unsafe {
        (*blkdev).name = b"sata0\0".as_ptr() as *const c_char;
        (*blkdev).block_size = port.sector_size;
        (*blkdev).block_count = port.sector_count;
        (*blkdev).allowed_rights = FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN;
        (*blkdev).backend = &AHCI_BACKEND;
        (*blkdev).backend_ctx = AHCI.get() as *mut c_void;
        (*blkdev).core = core::ptr::null_mut();
    }

    let blkdev_ref = unsafe { &mut *blkdev };
    match register(blkdev_ref) {
        Ok(()) => {
            log("ahci: registered block device sata0");
            0
        }
        Err(e) => {
            unsafe {
                fut_printf(b"ahci: blk_register failed: %d\n\0".as_ptr(), e);
            }
            e
        }
    }
}

/// Return the number of implemented AHCI ports.
#[unsafe(no_mangle)]
pub extern "C" fn ahci_port_count() -> u32 {
    let ctrl = unsafe { &*AHCI.get() };
    match ctrl.as_ref() {
        Some(c) => c.num_ports,
        None => 0,
    }
}

/// Issue IDENTIFY DEVICE on the given port and copy the 512-byte result to `buf`.
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn ahci_identify(port: u32, buf: *mut u8) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let ctrl = unsafe { &mut *AHCI.get() };
    let ctrl = match ctrl.as_mut() {
        Some(c) => c,
        None => return -2,
    };

    if port >= AHCI_MAX_PORTS as u32 {
        return -3;
    }

    let p = &mut ctrl.ports[port as usize];
    if !p.present {
        return -4;
    }

    // Allocate a DMA-safe page-aligned buffer for IDENTIFY
    let tmp = unsafe { alloc_page() };
    if tmp.is_null() {
        return -5;
    }
    unsafe { core::ptr::write_bytes(tmp, 0, 512); }

    let rc = port_identify(p, tmp);
    if rc == 0 {
        // Copy 512 bytes of IDENTIFY data to caller's buffer
        unsafe { core::ptr::copy_nonoverlapping(tmp, buf, 512); }
    }

    unsafe { common::free_page(tmp); }
    rc
}

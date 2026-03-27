// SPDX-License-Identifier: MPL-2.0
//
// Intel LPSS (Low Power Subsystem) I2C/SPI/UART Controller Driver for Futura OS
//
// Implements PCI-based discovery and initialisation of the Synopsys DesignWare
// I2C/SPI controllers found in the Intel Platform Controller Hub on Gen 10+
// (Ice Lake, Tiger Lake, Alder Lake, Raptor Lake, Meteor Lake) platforms.
//
// Architecture:
//   - PCI device discovery (vendor 8086h, multiple device IDs per generation)
//   - BAR0 MMIO for DesignWare controller registers
//   - BAR1 MMIO for LPSS private registers (clock gating, LTR, reset)
//   - Up to 8 independent I2C controllers discovered via PCI scan
//   - Synopsys DesignWare APB I2C compatible register set (shared with amd_i2c)
//   - Polling-based transfers with timeout
//   - Standard (100 kHz), fast (400 kHz), fast-plus (1 MHz), high (3.4 MHz)
//   - FIFO depth auto-detected from IC_COMP_PARAM_1
//   - SPI controller basic initialisation (if SPI device found)
//
// References:
//   - Synopsys DesignWare DW_apb_i2c Databook
//   - Intel PCH datasheets (ICL/TGL/ADL/RPL/MTL)
//   - Linux drivers/mfd/intel-lpss-pci.c
//   - Linux drivers/i2c/busses/i2c-designware-core.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// ---------------------------------------------------------------------------
// PCI device structure (mirrors kernel/pci.h)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// StaticCell -- interior-mutable global without `static mut`
// ---------------------------------------------------------------------------

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ---------------------------------------------------------------------------
// PCI configuration space I/O
// ---------------------------------------------------------------------------

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

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

// ---------------------------------------------------------------------------
// Intel vendor and LPSS I2C/SPI device IDs
// ---------------------------------------------------------------------------

const INTEL_VENDOR_ID: u16 = 0x8086;

/// Known Intel LPSS I2C PCI device IDs (Gen 10+).
const LPSS_I2C_DEVICE_IDS: [u16; 22] = [
    // Ice Lake (ICL)
    0x34E8, 0x34E9, 0x34EA, 0x34EB, // I2C0-3
    0x34C5, 0x34C6, // I2C4-5
    // Tiger Lake (TGL)
    0xA0E8, 0xA0E9, 0xA0EA, 0xA0EB, // I2C0-3
    0xA0C5, 0xA0C6, // I2C4-5
    // Alder Lake / Raptor Lake (ADL/RPL)
    0x51E8, 0x51E9, 0x51EA, 0x51EB, // I2C0-3
    0x51C5, 0x51C6, // I2C4-5
    // Meteor Lake (MTL)
    0x7E50, 0x7E51, 0x7E52, 0x7E53, // I2C0-3 (via SOC-M)
];

/// Known Intel LPSS SPI PCI device IDs (Gen 10+).
const LPSS_SPI_DEVICE_IDS: [u16; 3] = [
    0x34AA, // ICL
    0xA0AA, // TGL
    0x51AA, // ADL/RPL
];

/// PCI class code for serial bus controllers.
const PCI_CLASS_SERIAL_BUS: u8 = 0x0C;
/// PCI subclass for "other" serial bus (used by LPSS I2C/SPI).
const PCI_SUBCLASS_OTHER: u8 = 0x80;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of LPSS I2C controllers we track.
const MAX_I2C_CONTROLLERS: usize = 8;

/// Maximum number of LPSS SPI controllers we track.
const MAX_SPI_CONTROLLERS: usize = 4;

/// Size of BAR0 MMIO region (DW controller registers).
const BAR0_MMIO_SIZE: usize = 0x1000;

/// Size of BAR1 MMIO region (LPSS private registers).
const BAR1_MMIO_SIZE: usize = 0x1000;

// ---------------------------------------------------------------------------
// LPSS Private Registers (BAR1 offsets)
// ---------------------------------------------------------------------------

/// LPSS general configuration register.
const LPSS_GENERAL: usize = 0x200;
/// LPSS software latency tolerance reporting.
const LPSS_SW_LTR: usize = 0x204;
/// LPSS remap address register.
const LPSS_REMAP_ADDR: usize = 0x210;

// LPSS_GENERAL bits
/// Clock gating enable.
const LPSS_GENERAL_LTR_MODE_SW: u32 = 1 << 2;
/// LPSS I/O enable.
const LPSS_GENERAL_IO_EN: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// DW I2C Register offsets (BAR0, Synopsys DesignWare)
// ---------------------------------------------------------------------------

/// Control register.
const IC_CON: usize = 0x00;
/// Target address register.
const IC_TAR: usize = 0x04;
/// Data command register.
const IC_DATA_CMD: usize = 0x10;
/// Standard speed SCL high count.
const IC_SS_SCL_HCNT: usize = 0x14;
/// Standard speed SCL low count.
const IC_SS_SCL_LCNT: usize = 0x18;
/// Fast speed SCL high count.
const IC_FS_SCL_HCNT: usize = 0x1C;
/// Fast speed SCL low count.
const IC_FS_SCL_LCNT: usize = 0x20;
/// High speed SCL high count.
const IC_HS_SCL_HCNT: usize = 0x24;
/// High speed SCL low count.
const IC_HS_SCL_LCNT: usize = 0x28;
/// Interrupt status (read-only, masked).
const IC_INTR_STAT: usize = 0x2C;
/// Interrupt mask.
const IC_INTR_MASK: usize = 0x30;
/// Raw interrupt status (read-only).
const IC_RAW_INTR_STAT: usize = 0x34;
/// Clear combined and individual interrupt (read to clear).
const IC_CLR_INTR: usize = 0x3C;
/// Clear TX_ABRT interrupt (read to clear).
const IC_CLR_TX_ABRT: usize = 0x54;
/// Enable register.
const IC_ENABLE: usize = 0x6C;
/// Status register.
const IC_STATUS: usize = 0x70;
/// TX FIFO level.
const IC_TXFLR: usize = 0x78;
/// RX FIFO level.
const IC_RXFLR: usize = 0x7C;
/// SDA hold time.
const IC_SDA_HOLD: usize = 0x80;
/// TX abort source.
const IC_TX_ABRT_SOURCE: usize = 0x84;
/// Enable status (reflects actual enable state).
const IC_ENABLE_STATUS: usize = 0x9C;
/// Component parameter register 1 (read-only, FIFO depth etc.).
const IC_COMP_PARAM_1: usize = 0xF4;

// ---------------------------------------------------------------------------
// IC_CON bit definitions
// ---------------------------------------------------------------------------

/// Master mode enable.
const IC_CON_MASTER_MODE: u32 = 1 << 0;
/// Speed field mask (bits [2:1]).
const IC_CON_SPEED_MASK: u32 = 0x3 << 1;
/// Standard mode (100 kHz).
const IC_CON_SPEED_STD: u32 = 0x1 << 1;
/// Fast mode (400 kHz) / fast-plus (1 MHz).
const IC_CON_SPEED_FAST: u32 = 0x2 << 1;
/// High speed mode (3.4 MHz).
const IC_CON_SPEED_HIGH: u32 = 0x3 << 1;
/// 10-bit addressing for master (bit 4 = 1 means 10-bit, 0 means 7-bit).
const IC_CON_10BIT_ADDR_MASTER: u32 = 1 << 4;
/// IC_RESTART_EN -- allow RESTART conditions.
const IC_CON_RESTART_EN: u32 = 1 << 5;
/// Disable slave mode.
const IC_CON_SLAVE_DISABLE: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// IC_DATA_CMD bit definitions
// ---------------------------------------------------------------------------

/// Write command (CMD bit = 0).
const DATA_CMD_WRITE: u32 = 0 << 8;
/// Read command (CMD bit = 1).
const DATA_CMD_READ: u32 = 1 << 8;
/// STOP condition after this byte.
const DATA_CMD_STOP: u32 = 1 << 9;
/// RESTART condition before this byte.
const DATA_CMD_RESTART: u32 = 1 << 10;

// ---------------------------------------------------------------------------
// IC_STATUS bit definitions
// ---------------------------------------------------------------------------

/// Controller activity.
const IC_STATUS_ACTIVITY: u32 = 1 << 0;
/// TX FIFO not full.
const IC_STATUS_TFNF: u32 = 1 << 1;
/// TX FIFO completely empty.
const IC_STATUS_TFE: u32 = 1 << 2;
/// RX FIFO not empty.
const IC_STATUS_RFNE: u32 = 1 << 3;
/// RX FIFO completely full.
const IC_STATUS_RFF: u32 = 1 << 4;
/// Master FSM activity.
const IC_STATUS_MST_ACTIVITY: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// IC_RAW_INTR_STAT bit definitions
// ---------------------------------------------------------------------------

/// TX abort interrupt.
const IC_INTR_TX_ABRT: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

/// Maximum poll iterations for FIFO / status polling.
const POLL_TIMEOUT: u32 = 500_000;

/// Maximum poll iterations for enable/disable status confirmation.
const ENABLE_TIMEOUT: u32 = 100_000;

// ---------------------------------------------------------------------------
// SCL timing constants (for ~120 MHz LPSS input clock, typical on Intel PCH)
// ---------------------------------------------------------------------------

/// Standard mode (100 kHz): SCL high count.
const SS_SCL_HCNT: u32 = 0x0244;
/// Standard mode (100 kHz): SCL low count.
const SS_SCL_LCNT: u32 = 0x02DA;
/// Fast mode (400 kHz): SCL high count.
const FS_SCL_HCNT: u32 = 0x006A;
/// Fast mode (400 kHz): SCL low count.
const FS_SCL_LCNT: u32 = 0x00D2;
/// Fast-plus mode (1 MHz): SCL high count.
const FP_SCL_HCNT: u32 = 0x0020;
/// Fast-plus mode (1 MHz): SCL low count.
const FP_SCL_LCNT: u32 = 0x004A;
/// High speed mode (3.4 MHz): SCL high count.
const HS_SCL_HCNT: u32 = 0x0006;
/// High speed mode (3.4 MHz): SCL low count.
const HS_SCL_LCNT: u32 = 0x0010;
/// SDA hold time value.
const SDA_HOLD_DEFAULT: u32 = 0x001C;

// ---------------------------------------------------------------------------
// I2C speed selection (in kHz)
// ---------------------------------------------------------------------------

/// Standard mode: 100 kHz.
const SPEED_STANDARD: u32 = 100;
/// Fast mode: 400 kHz.
const SPEED_FAST: u32 = 400;
/// Fast-plus mode: 1000 kHz.
const SPEED_FAST_PLUS: u32 = 1000;
/// High speed mode: 3400 kHz.
const SPEED_HIGH: u32 = 3400;

// ---------------------------------------------------------------------------
// PCI BAR offsets
// ---------------------------------------------------------------------------

/// PCI command register offset.
const PCI_COMMAND: u8 = 0x04;
/// PCI BAR0 offset.
const PCI_BAR0: u8 = 0x10;
/// PCI BAR1 offset.
const PCI_BAR1: u8 = 0x14;

/// PCI command: memory space enable.
const PCI_CMD_MEMORY: u16 = 1 << 1;
/// PCI command: bus master enable.
const PCI_CMD_BUS_MASTER: u16 = 1 << 2;

// ---------------------------------------------------------------------------
// Per-controller state
// ---------------------------------------------------------------------------

/// Type of LPSS controller.
#[derive(Clone, Copy, PartialEq)]
enum LpssType {
    None,
    I2c,
    Spi,
}

struct LpssController {
    /// Type of controller.
    ctrl_type: LpssType,
    /// Virtual base address of BAR0 (DW controller registers). 0 = not mapped.
    bar0_base: usize,
    /// Virtual base address of BAR1 (LPSS private registers). 0 = not mapped.
    bar1_base: usize,
    /// PCI bus/dev/func for this controller.
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    /// PCI device ID.
    device_id: u16,
    /// TX FIFO depth (detected from IC_COMP_PARAM_1).
    tx_fifo_depth: u32,
    /// RX FIFO depth (detected from IC_COMP_PARAM_1).
    rx_fifo_depth: u32,
    /// Current speed setting in kHz.
    speed_khz: u32,
    /// Whether this controller has been initialised.
    inited: bool,
}

impl LpssController {
    const fn new() -> Self {
        Self {
            ctrl_type: LpssType::None,
            bar0_base: 0,
            bar1_base: 0,
            pci_bus: 0,
            pci_dev: 0,
            pci_func: 0,
            device_id: 0,
            tx_fifo_depth: 0,
            rx_fifo_depth: 0,
            speed_khz: 0,
            inited: false,
        }
    }
}

struct DriverState {
    /// I2C controllers discovered via PCI scan.
    i2c: [LpssController; MAX_I2C_CONTROLLERS],
    /// Number of I2C controllers discovered.
    i2c_count: u32,
    /// SPI controllers discovered via PCI scan.
    spi: [LpssController; MAX_SPI_CONTROLLERS],
    /// Number of SPI controllers discovered.
    spi_count: u32,
    /// Whether the driver has been initialised.
    inited: bool,
}

impl DriverState {
    const fn new() -> Self {
        Self {
            i2c: [
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
            ],
            i2c_count: 0,
            spi: [
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
                LpssController::new(),
            ],
            spi_count: 0,
            inited: false,
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit register at the given offset from a base address.
#[inline]
fn reg_read(base: usize, offset: usize) -> u32 {
    unsafe { read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit register at the given offset from a base address.
#[inline]
fn reg_write(base: usize, offset: usize, val: u32) {
    unsafe { write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// I/O delay helper
// ---------------------------------------------------------------------------

/// Small delay by reading a dummy I/O port (standard x86 technique).
fn io_delay() {
    unsafe {
        let _val: u8;
        core::arch::asm!("in al, dx", in("dx") 0x80u16, out("al") _val);
    }
}

// ---------------------------------------------------------------------------
// PCI BAR reading
// ---------------------------------------------------------------------------

/// Read a 32-bit PCI BAR and return the physical base address (masked).
fn pci_read_bar(bus: u8, dev: u8, func: u8, bar_offset: u8) -> u64 {
    let raw = pci_read32(bus, dev, func, bar_offset);
    // Memory BAR: bit 0 = 0 for memory.
    if raw & 1 != 0 {
        // I/O BAR, not expected for LPSS.
        return 0;
    }
    // Check if 64-bit BAR (type bits [2:1] == 0b10).
    let bar_type = (raw >> 1) & 0x3;
    if bar_type == 0x2 {
        // 64-bit BAR: read the upper 32 bits from the next BAR register.
        let upper = pci_read32(bus, dev, func, bar_offset + 4);
        let addr = ((upper as u64) << 32) | ((raw & 0xFFFF_FFF0) as u64);
        return addr;
    }
    // 32-bit BAR.
    (raw & 0xFFFF_FFF0) as u64
}

/// Enable memory space access and bus mastering on a PCI device.
fn pci_enable_device(bus: u8, dev: u8, func: u8) {
    let cmd = pci_read32(bus, dev, func, PCI_COMMAND) as u16;
    let new_cmd = cmd | PCI_CMD_MEMORY | PCI_CMD_BUS_MASTER;
    if new_cmd != cmd {
        pci_write16(bus, dev, func, PCI_COMMAND, new_cmd);
    }
}

// ---------------------------------------------------------------------------
// Device ID matching
// ---------------------------------------------------------------------------

fn is_lpss_i2c_device(vendor: u16, device: u16) -> bool {
    if vendor != INTEL_VENDOR_ID {
        return false;
    }
    for &id in &LPSS_I2C_DEVICE_IDS {
        if device == id {
            return true;
        }
    }
    false
}

fn is_lpss_spi_device(vendor: u16, device: u16) -> bool {
    if vendor != INTEL_VENDOR_ID {
        return false;
    }
    for &id in &LPSS_SPI_DEVICE_IDS {
        if device == id {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// LPSS private register initialisation
// ---------------------------------------------------------------------------

/// Initialise LPSS private registers (BAR1).
/// Enables I/O, sets software LTR mode, and deasserts reset.
fn lpss_private_init(bar1_base: usize) {
    // Read current general register value.
    let general = reg_read(bar1_base, LPSS_GENERAL);

    // Enable I/O and set software LTR mode.
    let new_general = general | LPSS_GENERAL_IO_EN | LPSS_GENERAL_LTR_MODE_SW;
    reg_write(bar1_base, LPSS_GENERAL, new_general);
    fence(Ordering::SeqCst);

    // Set a reasonable software LTR value (low latency).
    // Bits [9:0] = latency value, bit 10 = scale (0=ns, 1=us).
    // Set to ~32 us latency tolerance.
    reg_write(bar1_base, LPSS_SW_LTR, (1 << 10) | 32);
    fence(Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Controller enable / disable
// ---------------------------------------------------------------------------

/// Disable the I2C controller and wait for IC_ENABLE_STATUS to confirm.
/// Returns 0 on success, -110 on timeout.
fn controller_disable(base: usize) -> i32 {
    reg_write(base, IC_ENABLE, 0);
    fence(Ordering::SeqCst);

    for _ in 0..ENABLE_TIMEOUT {
        let status = reg_read(base, IC_ENABLE_STATUS);
        if status & 0x1 == 0 {
            return 0;
        }
        io_delay();
    }

    -110 // ETIMEDOUT
}

/// Enable the I2C controller and wait for IC_ENABLE_STATUS to confirm.
/// Returns 0 on success, -110 on timeout.
fn controller_enable(base: usize) -> i32 {
    reg_write(base, IC_ENABLE, 1);
    fence(Ordering::SeqCst);

    for _ in 0..ENABLE_TIMEOUT {
        let status = reg_read(base, IC_ENABLE_STATUS);
        if status & 0x1 != 0 {
            return 0;
        }
        io_delay();
    }

    -110 // ETIMEDOUT
}

// ---------------------------------------------------------------------------
// FIFO depth detection
// ---------------------------------------------------------------------------

/// Detect TX and RX FIFO depths from IC_COMP_PARAM_1.
///
/// IC_COMP_PARAM_1 layout:
///   bits [7:4]  = TX buffer depth (encoded as depth - 1)
///   bits [11:8] = RX buffer depth (encoded as depth - 1)
fn detect_fifo_depth(base: usize) -> (u32, u32) {
    let param = reg_read(base, IC_COMP_PARAM_1);

    // Sanity: if the register reads as all-ones, default to 64 (common on LPSS).
    if param == 0xFFFF_FFFF {
        return (64, 64);
    }

    let tx_depth = ((param >> 4) & 0xF) + 1;
    let rx_depth = ((param >> 8) & 0xF) + 1;

    // Clamp to reasonable range.
    let tx = if tx_depth == 0 || tx_depth > 256 { 64 } else { tx_depth };
    let rx = if rx_depth == 0 || rx_depth > 256 { 64 } else { rx_depth };

    (tx, rx)
}

// ---------------------------------------------------------------------------
// Speed configuration
// ---------------------------------------------------------------------------

/// Configure SCL timing for the given speed mode.
/// The controller must be disabled before calling this.
fn configure_speed(base: usize, speed_khz: u32) {
    // Always programme standard and fast mode timings; the controller
    // uses whichever set matches the speed bits in IC_CON.
    reg_write(base, IC_SS_SCL_HCNT, SS_SCL_HCNT);
    reg_write(base, IC_SS_SCL_LCNT, SS_SCL_LCNT);
    reg_write(base, IC_FS_SCL_HCNT, FS_SCL_HCNT);
    reg_write(base, IC_FS_SCL_LCNT, FS_SCL_LCNT);

    // For fast-plus, we reuse the fast-mode registers but with tighter timings.
    if speed_khz >= SPEED_FAST_PLUS && speed_khz < SPEED_HIGH {
        reg_write(base, IC_FS_SCL_HCNT, FP_SCL_HCNT);
        reg_write(base, IC_FS_SCL_LCNT, FP_SCL_LCNT);
    }

    // High speed mode uses dedicated registers.
    if speed_khz >= SPEED_HIGH {
        reg_write(base, IC_HS_SCL_HCNT, HS_SCL_HCNT);
        reg_write(base, IC_HS_SCL_LCNT, HS_SCL_LCNT);
    }

    // SDA hold time.
    reg_write(base, IC_SDA_HOLD, SDA_HOLD_DEFAULT);

    // Determine speed bits for IC_CON.
    let speed_bits = if speed_khz >= SPEED_HIGH {
        IC_CON_SPEED_HIGH
    } else if speed_khz >= SPEED_FAST {
        IC_CON_SPEED_FAST
    } else {
        IC_CON_SPEED_STD
    };

    let con = IC_CON_MASTER_MODE
        | speed_bits
        | IC_CON_RESTART_EN
        | IC_CON_SLAVE_DISABLE;

    reg_write(base, IC_CON, con);
}

// ---------------------------------------------------------------------------
// TX abort handling
// ---------------------------------------------------------------------------

/// Clear a TX abort condition. Reads IC_CLR_TX_ABRT to acknowledge the
/// abort and returns the abort source bits for diagnostics.
fn clear_tx_abort(base: usize) -> u32 {
    let source = reg_read(base, IC_TX_ABRT_SOURCE);
    let _ = reg_read(base, IC_CLR_TX_ABRT);
    source
}

/// Check for TX abort condition. Returns 0 if no abort, or a negative
/// error code if an abort has occurred (and clears it).
fn check_tx_abort(base: usize) -> i32 {
    let raw_intr = reg_read(base, IC_RAW_INTR_STAT);
    if raw_intr & IC_INTR_TX_ABRT != 0 {
        let source = clear_tx_abort(base);
        // Bit 0: 7-bit address NACK.
        if source & (1 << 0) != 0 {
            return -6; // ENXIO -- no device at address
        }
        // Bit 1: 10-bit addr1 NACK, Bit 2: 10-bit addr2 NACK.
        if source & ((1 << 1) | (1 << 2)) != 0 {
            return -6; // ENXIO
        }
        // Bit 3: TX data NACK.
        if source & (1 << 3) != 0 {
            return -5; // EIO
        }
        // Any other abort source.
        return -5; // EIO
    }
    0
}

/// Perform full abort recovery: disable controller, clear abort and
/// interrupts, re-enable.
fn abort_recovery(base: usize, speed_khz: u32) {
    let _ = controller_disable(base);
    let _ = clear_tx_abort(base);
    let _ = reg_read(base, IC_CLR_INTR);
    configure_speed(base, speed_khz);
    let _ = controller_enable(base);
}

// ---------------------------------------------------------------------------
// Wait helpers
// ---------------------------------------------------------------------------

/// Wait until the TX FIFO has space (TFNF bit set).
/// Returns 0 on success, negative error on abort or timeout.
fn wait_tx_not_full(base: usize) -> i32 {
    for _ in 0..POLL_TIMEOUT {
        let rc = check_tx_abort(base);
        if rc != 0 {
            return rc;
        }
        let status = reg_read(base, IC_STATUS);
        if status & IC_STATUS_TFNF != 0 {
            return 0;
        }
        io_delay();
    }
    -110 // ETIMEDOUT
}

/// Wait until the RX FIFO has data (RFNE bit set).
/// Returns 0 on success, negative error on abort or timeout.
fn wait_rx_not_empty(base: usize) -> i32 {
    for _ in 0..POLL_TIMEOUT {
        let rc = check_tx_abort(base);
        if rc != 0 {
            return rc;
        }
        let status = reg_read(base, IC_STATUS);
        if status & IC_STATUS_RFNE != 0 {
            return 0;
        }
        io_delay();
    }
    -110 // ETIMEDOUT
}

/// Wait for the controller to become idle (no master activity and TX FIFO
/// empty). Returns 0 on success, -110 on timeout.
fn wait_idle(base: usize) -> i32 {
    for _ in 0..POLL_TIMEOUT {
        let status = reg_read(base, IC_STATUS);
        if status & IC_STATUS_MST_ACTIVITY == 0 && status & IC_STATUS_TFE != 0 {
            return 0;
        }
        io_delay();
    }
    -110 // ETIMEDOUT
}

// ---------------------------------------------------------------------------
// Target address setup
// ---------------------------------------------------------------------------

/// Set the target address. The controller must be disabled to change
/// IC_TAR, so we disable, write IC_TAR, then re-enable.
fn set_target_addr(base: usize, addr: u8, speed_khz: u32) -> i32 {
    let rc = controller_disable(base);
    if rc != 0 {
        return rc;
    }

    // Write 7-bit address (bits [9:0]).
    reg_write(base, IC_TAR, (addr & 0x7F) as u32);

    // Re-configure speed (IC_CON must be set while disabled).
    configure_speed(base, speed_khz);

    controller_enable(base)
}

// ---------------------------------------------------------------------------
// Transfer operations
// ---------------------------------------------------------------------------

/// Write `len` bytes from `data` to the I2C bus.
/// Sends STOP after the last byte.
fn do_write(base: usize, data: *const u8, len: u32) -> i32 {
    if data.is_null() || len == 0 {
        return -22; // EINVAL
    }

    // Clear any stale interrupts.
    let _ = reg_read(base, IC_CLR_INTR);

    for i in 0..len {
        let rc = wait_tx_not_full(base);
        if rc != 0 {
            return rc;
        }

        let byte = unsafe { read_volatile(data.add(i as usize)) } as u32;
        let mut cmd = byte | DATA_CMD_WRITE;

        // STOP on the last byte.
        if i == len - 1 {
            cmd |= DATA_CMD_STOP;
        }

        reg_write(base, IC_DATA_CMD, cmd);
    }

    // Wait for transfer to complete.
    let rc = wait_idle(base);
    if rc != 0 {
        return rc;
    }

    // Check for abort after completion.
    check_tx_abort(base)
}

/// Read `len` bytes into `buf` from the I2C bus.
/// Issues read commands and collects responses. Sends STOP after the last
/// read command.
fn do_read(base: usize, buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    // Clear any stale interrupts.
    let _ = reg_read(base, IC_CLR_INTR);

    for i in 0..len {
        // Issue a read command.
        let rc = wait_tx_not_full(base);
        if rc != 0 {
            return rc;
        }

        let mut cmd = DATA_CMD_READ;
        if i == len - 1 {
            cmd |= DATA_CMD_STOP;
        }

        reg_write(base, IC_DATA_CMD, cmd);

        // Wait for the response byte.
        let rc = wait_rx_not_empty(base);
        if rc != 0 {
            return rc;
        }

        let val = reg_read(base, IC_DATA_CMD) as u8;
        unsafe { write_volatile(buf.add(i as usize), val) };
    }

    // Wait for bus idle.
    let rc = wait_idle(base);
    if rc != 0 {
        return rc;
    }

    check_tx_abort(base)
}

/// Combined write-then-read transaction (register read pattern).
/// Writes `wr_len` bytes, issues a RESTART, then reads `rd_len` bytes.
fn do_write_read(
    base: usize,
    wr_data: *const u8,
    wr_len: u32,
    rd_buf: *mut u8,
    rd_len: u32,
) -> i32 {
    if wr_data.is_null() || wr_len == 0 || rd_buf.is_null() || rd_len == 0 {
        return -22; // EINVAL
    }

    // Clear any stale interrupts.
    let _ = reg_read(base, IC_CLR_INTR);

    // --- Write phase ---
    for i in 0..wr_len {
        let rc = wait_tx_not_full(base);
        if rc != 0 {
            return rc;
        }

        let byte = unsafe { read_volatile(wr_data.add(i as usize)) } as u32;
        let cmd = byte | DATA_CMD_WRITE;
        reg_write(base, IC_DATA_CMD, cmd);
    }

    // --- Read phase (with RESTART before first byte) ---
    for i in 0..rd_len {
        let rc = wait_tx_not_full(base);
        if rc != 0 {
            return rc;
        }

        let mut cmd = DATA_CMD_READ;

        // RESTART before the first read byte to switch direction.
        if i == 0 {
            cmd |= DATA_CMD_RESTART;
        }

        // STOP after the last read byte.
        if i == rd_len - 1 {
            cmd |= DATA_CMD_STOP;
        }

        reg_write(base, IC_DATA_CMD, cmd);

        // Wait for the response byte.
        let rc = wait_rx_not_empty(base);
        if rc != 0 {
            return rc;
        }

        let val = reg_read(base, IC_DATA_CMD) as u8;
        unsafe { write_volatile(rd_buf.add(i as usize), val) };
    }

    // Wait for bus idle.
    let rc = wait_idle(base);
    if rc != 0 {
        return rc;
    }

    check_tx_abort(base)
}

// ---------------------------------------------------------------------------
// Internal accessor
// ---------------------------------------------------------------------------

/// Get a reference to an initialised I2C controller, or return an error code.
fn get_i2c_controller(idx: u32) -> Result<&'static LpssController, i32> {
    let st = unsafe { &*STATE.get() };

    if idx >= st.i2c_count || (idx as usize) >= MAX_I2C_CONTROLLERS {
        return Err(-22); // EINVAL
    }

    let ctrl = &st.i2c[idx as usize];

    if !ctrl.inited || ctrl.bar0_base == 0 {
        return Err(-19); // ENODEV
    }

    Ok(ctrl)
}

// ---------------------------------------------------------------------------
// I2C controller initialisation
// ---------------------------------------------------------------------------

/// Initialise a single LPSS I2C controller after BAR mapping.
fn init_i2c_controller(ctrl: &mut LpssController) -> i32 {
    let base = ctrl.bar0_base;

    // Initialise LPSS private registers if BAR1 is mapped.
    if ctrl.bar1_base != 0 {
        lpss_private_init(ctrl.bar1_base);
    }

    // Disable the controller before configuring.
    let rc = controller_disable(base);
    if rc != 0 {
        log("intel_lpss: timeout disabling I2C controller");
        return rc;
    }

    // Mask all interrupts (we use polling).
    reg_write(base, IC_INTR_MASK, 0);

    // Clear any pending interrupts.
    let _ = reg_read(base, IC_CLR_INTR);

    // Detect FIFO depth.
    let (tx_depth, rx_depth) = detect_fifo_depth(base);
    ctrl.tx_fifo_depth = tx_depth;
    ctrl.rx_fifo_depth = rx_depth;

    unsafe {
        fut_printf(
            b"intel_lpss: I2C dev %04x FIFO depth: TX=%u RX=%u\n\0".as_ptr(),
            ctrl.device_id as u32,
            tx_depth,
            rx_depth,
        );
    }

    // Configure for fast mode (400 kHz) by default.
    configure_speed(base, SPEED_FAST);
    ctrl.speed_khz = SPEED_FAST;

    // Enable the controller.
    let rc = controller_enable(base);
    if rc != 0 {
        log("intel_lpss: timeout enabling I2C controller");
        return rc;
    }

    ctrl.ctrl_type = LpssType::I2c;
    ctrl.inited = true;
    fence(Ordering::SeqCst);

    0
}

// ---------------------------------------------------------------------------
// SPI controller basic initialisation
// ---------------------------------------------------------------------------

/// Basic initialisation of an LPSS SPI controller.
/// Sets up LPSS private registers and marks the controller as ready.
fn init_spi_controller(ctrl: &mut LpssController) -> i32 {
    // Initialise LPSS private registers if BAR1 is mapped.
    if ctrl.bar1_base != 0 {
        lpss_private_init(ctrl.bar1_base);
    }

    // SPI controller uses a different register set (Synopsys DW_apb_ssi).
    // For now, just ensure it is powered up and accessible via LPSS private
    // registers. Full SPI transfer support is left for future implementation.

    let base = ctrl.bar0_base;

    // Read the SSI component version at offset 0x5C (DW_apb_ssi).
    let version = reg_read(base, 0x5C);

    unsafe {
        fut_printf(
            b"intel_lpss: SPI dev %04x SSI version 0x%08x\n\0".as_ptr(),
            ctrl.device_id as u32,
            version,
        );
    }

    ctrl.ctrl_type = LpssType::Spi;
    ctrl.inited = true;
    fence(Ordering::SeqCst);

    0
}

// ---------------------------------------------------------------------------
// PCI discovery and BAR mapping
// ---------------------------------------------------------------------------

/// Map BAR0 and BAR1 for an LPSS controller.
/// Returns 0 on success, negative error on failure.
fn map_lpss_bars(ctrl: &mut LpssController) -> i32 {
    let bus = ctrl.pci_bus;
    let dev = ctrl.pci_dev;
    let func = ctrl.pci_func;

    // Enable PCI memory space and bus mastering.
    pci_enable_device(bus, dev, func);

    // Read BAR0 physical address.
    let bar0_phys = pci_read_bar(bus, dev, func, PCI_BAR0);
    if bar0_phys == 0 {
        log("intel_lpss: BAR0 is zero or invalid");
        return -5; // EIO
    }

    // Read BAR1 physical address.
    let bar1_phys = pci_read_bar(bus, dev, func, PCI_BAR1);

    unsafe {
        fut_printf(
            b"intel_lpss: %02x:%02x.%x dev %04x BAR0=0x%08llx BAR1=0x%08llx\n\0".as_ptr(),
            bus as u32,
            dev as u32,
            func as u32,
            ctrl.device_id as u32,
            bar0_phys,
            bar1_phys,
        );
    }

    // Map BAR0 (controller registers).
    let bar0_vaddr = unsafe { map_mmio_region(bar0_phys, BAR0_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if bar0_vaddr.is_null() {
        log("intel_lpss: failed to map BAR0");
        return -12; // ENOMEM
    }
    ctrl.bar0_base = bar0_vaddr as usize;

    // Map BAR1 (LPSS private registers) if present.
    if bar1_phys != 0 {
        let bar1_vaddr =
            unsafe { map_mmio_region(bar1_phys, BAR1_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
        if bar1_vaddr.is_null() {
            log("intel_lpss: failed to map BAR1 (continuing without private regs)");
            // Not fatal; we can still use the controller without LPSS private regs.
        } else {
            ctrl.bar1_base = bar1_vaddr as usize;
        }
    }

    0
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Discover and initialise all Intel LPSS I2C and SPI controllers.
///
/// Scans the PCI bus for known Intel LPSS device IDs, maps their BARs,
/// initialises LPSS private registers, and configures the DesignWare I2C
/// controllers for fast mode (400 kHz).
///
/// Returns 0 on success (even if no devices found), negative error on
/// fatal failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_init() -> i32 {
    log("intel_lpss: scanning for Intel LPSS controllers...");

    let st = unsafe { &mut *STATE.get() };
    if st.inited {
        log("intel_lpss: already initialised");
        return 0;
    }

    let count = unsafe { pci_device_count() };
    if count <= 0 {
        log("intel_lpss: no PCI devices found");
        st.inited = true;
        return 0;
    }

    let mut i2c_idx: usize = 0;
    let mut spi_idx: usize = 0;

    for i in 0..count {
        let pci_dev = unsafe { pci_get_device(i) };
        if pci_dev.is_null() {
            continue;
        }

        let pdev = unsafe { &*pci_dev };

        // Check for I2C controllers.
        if i2c_idx < MAX_I2C_CONTROLLERS && is_lpss_i2c_device(pdev.vendor_id, pdev.device_id) {
            let ctrl = &mut st.i2c[i2c_idx];
            ctrl.pci_bus = pdev.bus;
            ctrl.pci_dev = pdev.dev;
            ctrl.pci_func = pdev.func;
            ctrl.device_id = pdev.device_id;

            let rc = map_lpss_bars(ctrl);
            if rc != 0 {
                unsafe {
                    fut_printf(
                        b"intel_lpss: failed to map BARs for I2C %02x:%02x.%x\n\0".as_ptr(),
                        pdev.bus as u32,
                        pdev.dev as u32,
                        pdev.func as u32,
                    );
                }
                continue;
            }

            let rc = init_i2c_controller(ctrl);
            if rc != 0 {
                unsafe {
                    fut_printf(
                        b"intel_lpss: failed to init I2C %02x:%02x.%x (err %d)\n\0".as_ptr(),
                        pdev.bus as u32,
                        pdev.dev as u32,
                        pdev.func as u32,
                        rc,
                    );
                }
                // Unmap on failure.
                if ctrl.bar0_base != 0 {
                    unsafe {
                        unmap_mmio_region(ctrl.bar0_base as *mut u8, BAR0_MMIO_SIZE);
                    }
                    ctrl.bar0_base = 0;
                }
                if ctrl.bar1_base != 0 {
                    unsafe {
                        unmap_mmio_region(ctrl.bar1_base as *mut u8, BAR1_MMIO_SIZE);
                    }
                    ctrl.bar1_base = 0;
                }
                continue;
            }

            unsafe {
                fut_printf(
                    b"intel_lpss: I2C[%u] at %02x:%02x.%x dev %04x ready\n\0".as_ptr(),
                    i2c_idx as u32,
                    pdev.bus as u32,
                    pdev.dev as u32,
                    pdev.func as u32,
                    pdev.device_id as u32,
                );
            }

            i2c_idx += 1;
            continue;
        }

        // Check for SPI controllers.
        if spi_idx < MAX_SPI_CONTROLLERS && is_lpss_spi_device(pdev.vendor_id, pdev.device_id) {
            let ctrl = &mut st.spi[spi_idx];
            ctrl.pci_bus = pdev.bus;
            ctrl.pci_dev = pdev.dev;
            ctrl.pci_func = pdev.func;
            ctrl.device_id = pdev.device_id;

            let rc = map_lpss_bars(ctrl);
            if rc != 0 {
                unsafe {
                    fut_printf(
                        b"intel_lpss: failed to map BARs for SPI %02x:%02x.%x\n\0".as_ptr(),
                        pdev.bus as u32,
                        pdev.dev as u32,
                        pdev.func as u32,
                    );
                }
                continue;
            }

            let rc = init_spi_controller(ctrl);
            if rc != 0 {
                unsafe {
                    fut_printf(
                        b"intel_lpss: failed to init SPI %02x:%02x.%x (err %d)\n\0".as_ptr(),
                        pdev.bus as u32,
                        pdev.dev as u32,
                        pdev.func as u32,
                        rc,
                    );
                }
                if ctrl.bar0_base != 0 {
                    unsafe {
                        unmap_mmio_region(ctrl.bar0_base as *mut u8, BAR0_MMIO_SIZE);
                    }
                    ctrl.bar0_base = 0;
                }
                if ctrl.bar1_base != 0 {
                    unsafe {
                        unmap_mmio_region(ctrl.bar1_base as *mut u8, BAR1_MMIO_SIZE);
                    }
                    ctrl.bar1_base = 0;
                }
                continue;
            }

            unsafe {
                fut_printf(
                    b"intel_lpss: SPI[%u] at %02x:%02x.%x dev %04x ready\n\0".as_ptr(),
                    spi_idx as u32,
                    pdev.bus as u32,
                    pdev.dev as u32,
                    pdev.func as u32,
                    pdev.device_id as u32,
                );
            }

            spi_idx += 1;
        }
    }

    st.i2c_count = i2c_idx as u32;
    st.spi_count = spi_idx as u32;
    st.inited = true;
    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"intel_lpss: discovered %u I2C + %u SPI controllers\n\0".as_ptr(),
            st.i2c_count,
            st.spi_count,
        );
    }

    0
}

/// Return the number of discovered LPSS I2C controllers.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_i2c_count() -> u32 {
    let st = unsafe { &*STATE.get() };
    st.i2c_count
}

/// Read data from an I2C device on an LPSS I2C controller.
///
/// `idx`: controller index (0 to i2c_count-1).
/// `addr`: 7-bit I2C target address.
/// `buf`: pointer to buffer for received data.
/// `len`: number of bytes to read.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_i2c_read(
    idx: u32,
    addr: u8,
    buf: *mut u8,
    len: u32,
) -> i32 {
    let ctrl = match get_i2c_controller(idx) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.bar0_base;

    let rc = set_target_addr(base, addr, ctrl.speed_khz);
    if rc != 0 {
        return rc;
    }

    let rc = do_read(base, buf, len);
    if rc != 0 {
        abort_recovery(base, ctrl.speed_khz);
    }
    rc
}

/// Write data to an I2C device on an LPSS I2C controller.
///
/// `idx`: controller index (0 to i2c_count-1).
/// `addr`: 7-bit I2C target address.
/// `data`: pointer to bytes to write.
/// `len`: number of bytes to write.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_i2c_write(
    idx: u32,
    addr: u8,
    data: *const u8,
    len: u32,
) -> i32 {
    let ctrl = match get_i2c_controller(idx) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if data.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.bar0_base;

    let rc = set_target_addr(base, addr, ctrl.speed_khz);
    if rc != 0 {
        return rc;
    }

    let rc = do_write(base, data, len);
    if rc != 0 {
        abort_recovery(base, ctrl.speed_khz);
    }
    rc
}

/// Combined write-then-read transaction on an LPSS I2C controller.
///
/// `idx`: controller index (0 to i2c_count-1).
/// `addr`: 7-bit I2C target address.
/// `wr`: pointer to bytes to write (typically a register address).
/// `wr_len`: number of bytes to write.
/// `rd`: pointer to buffer for received data.
/// `rd_len`: number of bytes to read.
///
/// Uses a RESTART between the write and read phases so the bus is not
/// released (allowing atomic register reads on most I2C devices).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_i2c_write_read(
    idx: u32,
    addr: u8,
    wr: *const u8,
    wr_len: u32,
    rd: *mut u8,
    rd_len: u32,
) -> i32 {
    let ctrl = match get_i2c_controller(idx) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if wr.is_null() || wr_len == 0 || rd.is_null() || rd_len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.bar0_base;

    let rc = set_target_addr(base, addr, ctrl.speed_khz);
    if rc != 0 {
        return rc;
    }

    let rc = do_write_read(base, wr, wr_len, rd, rd_len);
    if rc != 0 {
        abort_recovery(base, ctrl.speed_khz);
    }
    rc
}

/// Set the I2C bus speed for an LPSS I2C controller.
///
/// `idx`: controller index (0 to i2c_count-1).
/// `speed_khz`: desired speed in kHz:
///   - 100  = standard mode
///   - 400  = fast mode
///   - 1000 = fast-plus mode
///   - 3400 = high speed mode
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_lpss_i2c_set_speed(idx: u32, speed_khz: u32) -> i32 {
    let st = unsafe { &mut *STATE.get() };

    if idx >= st.i2c_count || (idx as usize) >= MAX_I2C_CONTROLLERS {
        return -22; // EINVAL
    }

    let ctrl = &mut st.i2c[idx as usize];

    if !ctrl.inited || ctrl.bar0_base == 0 {
        return -19; // ENODEV
    }

    let base = ctrl.bar0_base;

    // Normalise speed to a supported tier.
    let speed = if speed_khz >= SPEED_HIGH {
        SPEED_HIGH
    } else if speed_khz >= SPEED_FAST_PLUS {
        SPEED_FAST_PLUS
    } else if speed_khz >= SPEED_FAST {
        SPEED_FAST
    } else {
        SPEED_STANDARD
    };

    // Must disable to change configuration.
    let rc = controller_disable(base);
    if rc != 0 {
        return rc;
    }

    configure_speed(base, speed);

    let rc = controller_enable(base);
    if rc != 0 {
        return rc;
    }

    ctrl.speed_khz = speed;
    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"intel_lpss: I2C[%u] speed set to %u kHz\n\0".as_ptr(),
            idx,
            speed,
        );
    }

    0
}

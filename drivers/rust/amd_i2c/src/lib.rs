// SPDX-License-Identifier: MPL-2.0
//
// AMD FCH I2C Controller Driver for Futura OS
//
// Implements the Synopsys DesignWare APB I2C (DW_apb_i2c) controllers found
// in the AMD Fusion Controller Hub on AM4 (X370-X570) and AM5 (X670-X870)
// Ryzen platforms.  These are dedicated I2C controllers, separate from the
// legacy SMBus controller.
//
// Architecture:
//   - MMIO-based register access (ACPI MMIO block)
//   - Default ACPI MMIO base: 0xFED8_0000
//   - I2C controller offsets: +0x2000, +0x2100, +0x2200, +0x2300
//   - Up to 4 independent I2C controllers (I2C0-I2C3)
//   - Synopsys DesignWare APB I2C compatible register set
//   - Polling-based transfers with timeout
//   - Standard mode (100 kHz) and fast mode (400 kHz)
//   - FIFO depth auto-detected from IC_COMP_PARAM_1
//
// References:
//   - Synopsys DesignWare DW_apb_i2c Databook
//   - AMD PPR (Processor Programming Reference) for Ryzen
//   - Linux drivers/i2c/busses/i2c-designware-core.c
//   - coreboot src/soc/amd/common/block/i2c/

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
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
// ACPI MMIO and I2C controller constants
// ---------------------------------------------------------------------------

/// Default ACPI MMIO base address on AMD FCH platforms.
const ACPI_MMIO_BASE: u64 = 0xFED8_0000;

/// I2C controller MMIO offsets from ACPI MMIO base.
const I2C_OFFSETS: [u64; MAX_CONTROLLERS] = [0x2000, 0x2100, 0x2200, 0x2300];

/// Maximum number of I2C controllers on AMD FCH.
const MAX_CONTROLLERS: usize = 4;

/// Size of each controller's MMIO register block (256 bytes is sufficient).
const I2C_MMIO_SIZE: usize = 0x100;

// ---------------------------------------------------------------------------
// DW I2C Register offsets
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
/// Fast mode (400 kHz).
const IC_CON_SPEED_FAST: u32 = 0x2 << 1;
/// High speed mode (3.4 MHz).
const IC_CON_SPEED_HIGH: u32 = 0x3 << 1;
/// 7-bit addressing for master (bit 4 = 0 means 7-bit).
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
// SCL timing constants (for a ~133 MHz input clock typical on AMD FCH)
// ---------------------------------------------------------------------------

/// Standard mode (100 kHz): SCL high count.
const SS_SCL_HCNT: u32 = 0x0264;
/// Standard mode (100 kHz): SCL low count.
const SS_SCL_LCNT: u32 = 0x02C2;
/// Fast mode (400 kHz): SCL high count.
const FS_SCL_HCNT: u32 = 0x0087;
/// Fast mode (400 kHz): SCL low count.
const FS_SCL_LCNT: u32 = 0x00F3;
/// SDA hold time value (suitable for both standard and fast).
const SDA_HOLD_DEFAULT: u32 = 0x0048;

// ---------------------------------------------------------------------------
// I2C speed selection
// ---------------------------------------------------------------------------

/// Standard mode: 100 kHz.
const SPEED_STANDARD: u32 = 100;
/// Fast mode: 400 kHz.
const SPEED_FAST: u32 = 400;

// ---------------------------------------------------------------------------
// Per-controller state
// ---------------------------------------------------------------------------

struct DwI2cController {
    /// Virtual base address of the register block (0 = not mapped).
    base: usize,
    /// TX FIFO depth (detected from IC_COMP_PARAM_1).
    tx_fifo_depth: u32,
    /// RX FIFO depth (detected from IC_COMP_PARAM_1).
    rx_fifo_depth: u32,
    /// Current speed setting in kHz (100 or 400).
    speed_khz: u32,
    /// Whether this controller has been initialised.
    inited: bool,
}

impl DwI2cController {
    const fn new() -> Self {
        Self {
            base: 0,
            tx_fifo_depth: 0,
            rx_fifo_depth: 0,
            speed_khz: 0,
            inited: false,
        }
    }
}

struct DriverState {
    controllers: [DwI2cController; MAX_CONTROLLERS],
}

impl DriverState {
    const fn new() -> Self {
        Self {
            controllers: [
                DwI2cController::new(),
                DwI2cController::new(),
                DwI2cController::new(),
                DwI2cController::new(),
            ],
        }
    }
}

static STATE: StaticCell<DriverState> = StaticCell::new(DriverState::new());

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit register at the given offset from controller base.
#[inline]
fn reg_read(base: usize, offset: usize) -> u32 {
    unsafe { read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit register at the given offset from controller base.
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
// Controller enable / disable
// ---------------------------------------------------------------------------

/// Disable the I2C controller and wait for IC_ENABLE_STATUS to confirm.
/// The controller must be disabled before changing configuration registers.
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

    let tx_depth = ((param >> 4) & 0xF) + 1;
    let rx_depth = ((param >> 8) & 0xF) + 1;

    // Sanity: if the register reads as all-ones, default to 8 (common).
    if param == 0xFFFF_FFFF {
        return (8, 8);
    }

    // Clamp to reasonable range.
    let tx = if tx_depth == 0 || tx_depth > 256 { 8 } else { tx_depth };
    let rx = if rx_depth == 0 || rx_depth > 256 { 8 } else { rx_depth };

    (tx, rx)
}

// ---------------------------------------------------------------------------
// Speed configuration
// ---------------------------------------------------------------------------

/// Configure SCL timing for the given speed mode.
/// The controller must be disabled before calling this.
fn configure_speed(base: usize, speed_khz: u32) {
    match speed_khz {
        SPEED_FAST => {
            reg_write(base, IC_FS_SCL_HCNT, FS_SCL_HCNT);
            reg_write(base, IC_FS_SCL_LCNT, FS_SCL_LCNT);
        }
        _ => {
            // Default to standard mode.
            reg_write(base, IC_SS_SCL_HCNT, SS_SCL_HCNT);
            reg_write(base, IC_SS_SCL_LCNT, SS_SCL_LCNT);
        }
    }

    // SDA hold time.
    reg_write(base, IC_SDA_HOLD, SDA_HOLD_DEFAULT);

    // Set IC_CON: master mode, selected speed, restart enable, slave disable,
    // 7-bit addressing.
    let speed_bits = if speed_khz >= SPEED_FAST {
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

/// Clear a TX abort condition.  Reads IC_CLR_TX_ABRT to acknowledge the
/// abort and returns the abort source bits for diagnostics.
fn clear_tx_abort(base: usize) -> u32 {
    let source = reg_read(base, IC_TX_ABRT_SOURCE);
    // Reading IC_CLR_TX_ABRT clears the TX_ABRT interrupt.
    let _ = reg_read(base, IC_CLR_TX_ABRT);
    source
}

/// Check for TX abort condition.  Returns 0 if no abort, or a negative
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
/// empty).  Returns 0 on success, -110 on timeout.
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

/// Set the target address.  The controller must be disabled to change
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
/// Issues read commands and collects responses.  Sends STOP after the last
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

/// Get a reference to an initialised controller, or return an error code.
fn get_controller(idx: u32) -> Result<&'static DwI2cController, i32> {
    if idx as usize >= MAX_CONTROLLERS {
        return Err(-22); // EINVAL
    }

    let st = unsafe { &*STATE.get() };
    let ctrl = &st.controllers[idx as usize];

    if !ctrl.inited || ctrl.base == 0 {
        return Err(-19); // ENODEV
    }

    Ok(ctrl)
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialise an AMD FCH I2C controller.
///
/// `controller`: controller index (0-3).
///
/// Maps the MMIO registers, detects FIFO depth, configures the controller
/// for fast mode (400 kHz) by default, and enables it.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_i2c_init(controller: u32) -> i32 {
    if controller as usize >= MAX_CONTROLLERS {
        log("amd_i2c: invalid controller index");
        return -22; // EINVAL
    }

    unsafe {
        fut_printf(
            b"amd_i2c: initialising controller %u...\n\0".as_ptr(),
            controller,
        );
    }

    let phys_addr = ACPI_MMIO_BASE + I2C_OFFSETS[controller as usize];

    unsafe {
        fut_printf(
            b"amd_i2c: controller %u MMIO at 0x%08llx\n\0".as_ptr(),
            controller,
            phys_addr,
        );
    }

    // Map the register block.
    let vaddr = unsafe { map_mmio_region(phys_addr, I2C_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if vaddr.is_null() {
        log("amd_i2c: failed to map MMIO region");
        return -12; // ENOMEM
    }

    let base = vaddr as usize;

    // Disable the controller before configuring.
    let rc = controller_disable(base);
    if rc != 0 {
        log("amd_i2c: timeout disabling controller");
        unsafe { unmap_mmio_region(vaddr, I2C_MMIO_SIZE) };
        return rc;
    }

    // Mask all interrupts (we use polling).
    reg_write(base, IC_INTR_MASK, 0);

    // Clear any pending interrupts.
    let _ = reg_read(base, IC_CLR_INTR);

    // Detect FIFO depth.
    let (tx_depth, rx_depth) = detect_fifo_depth(base);

    unsafe {
        fut_printf(
            b"amd_i2c: controller %u FIFO depth: TX=%u RX=%u\n\0".as_ptr(),
            controller,
            tx_depth,
            rx_depth,
        );
    }

    // Configure for fast mode (400 kHz) by default.
    configure_speed(base, SPEED_FAST);

    // Enable the controller.
    let rc = controller_enable(base);
    if rc != 0 {
        log("amd_i2c: timeout enabling controller");
        unsafe { unmap_mmio_region(vaddr, I2C_MMIO_SIZE) };
        return rc;
    }

    // Store controller state.
    let st = unsafe { &mut *STATE.get() };
    let ctrl = &mut st.controllers[controller as usize];
    ctrl.base = base;
    ctrl.tx_fifo_depth = tx_depth;
    ctrl.rx_fifo_depth = rx_depth;
    ctrl.speed_khz = SPEED_FAST;
    ctrl.inited = true;

    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"amd_i2c: controller %u ready (fast mode, 400 kHz)\n\0".as_ptr(),
            controller,
        );
    }

    0
}

/// Set the I2C bus speed for a controller.
///
/// `controller`: controller index (0-3).
/// `speed_khz`: desired speed in kHz (100 for standard, 400 for fast).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_i2c_set_speed(controller: u32, speed_khz: u32) -> i32 {
    if controller as usize >= MAX_CONTROLLERS {
        return -22; // EINVAL
    }

    let st = unsafe { &mut *STATE.get() };
    let ctrl = &mut st.controllers[controller as usize];

    if !ctrl.inited || ctrl.base == 0 {
        return -19; // ENODEV
    }

    let base = ctrl.base;

    // Normalise speed.
    let speed = if speed_khz >= SPEED_FAST {
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
            b"amd_i2c: controller %u speed set to %u kHz\n\0".as_ptr(),
            controller,
            speed,
        );
    }

    0
}

/// Write data to an I2C device.
///
/// `controller`: controller index (0-3).
/// `addr`: 7-bit I2C target address.
/// `data`: pointer to bytes to write.
/// `len`: number of bytes to write.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_i2c_write(
    controller: u32,
    addr: u8,
    data: *const u8,
    len: u32,
) -> i32 {
    let ctrl = match get_controller(controller) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if data.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.base;

    // Set target address (requires disable/re-enable cycle).
    let rc = set_target_addr(base, addr, ctrl.speed_khz);
    if rc != 0 {
        return rc;
    }

    let rc = do_write(base, data, len);
    if rc != 0 {
        // Attempt recovery on failure.
        abort_recovery(base, ctrl.speed_khz);
    }
    rc
}

/// Read data from an I2C device.
///
/// `controller`: controller index (0-3).
/// `addr`: 7-bit I2C target address.
/// `buf`: pointer to buffer for received data.
/// `len`: number of bytes to read.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_i2c_read(
    controller: u32,
    addr: u8,
    buf: *mut u8,
    len: u32,
) -> i32 {
    let ctrl = match get_controller(controller) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.base;

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

/// Combined write-then-read transaction (common register read pattern).
///
/// `controller`: controller index (0-3).
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
pub extern "C" fn amd_i2c_write_read(
    controller: u32,
    addr: u8,
    wr: *const u8,
    wr_len: u32,
    rd: *mut u8,
    rd_len: u32,
) -> i32 {
    let ctrl = match get_controller(controller) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if wr.is_null() || wr_len == 0 || rd.is_null() || rd_len == 0 {
        return -22; // EINVAL
    }

    let base = ctrl.base;

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

/// Return the number of available I2C controllers (always 4 on AMD FCH).
#[unsafe(no_mangle)]
pub extern "C" fn amd_i2c_controller_count() -> u32 {
    MAX_CONTROLLERS as u32
}

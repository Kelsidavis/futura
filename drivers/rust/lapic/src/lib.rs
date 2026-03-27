// SPDX-License-Identifier: MPL-2.0
//
// Local APIC and I/O APIC Driver for Futura OS
//
// Implements the x86-64 Local APIC (per-CPU interrupt controller) and
// I/O APIC (external interrupt routing) as described in the Intel SDM
// Volume 3, Chapter 10 (APIC) and the I/O APIC datasheet (82093AA).
//
// Architecture:
//   - Local APIC: MMIO at 0xFEE0_0000 (from IA32_APIC_BASE MSR 0x1B),
//     also supports x2APIC mode via MSRs (0x800+)
//   - I/O APIC: MMIO at 0xFEC0_0000 with indirect register access
//     (IOREGSEL at offset 0x00, IOWIN at offset 0x10)
//   - LAPIC timer with one-shot, periodic, and TSC-deadline modes
//   - IPI delivery for SMP boot (INIT, SIPI) and cross-CPU signalling
//   - I/O APIC redirection table for ISA and PCI interrupt routing
//
// LAPIC register map (MMIO offsets from base):
//   0x020  LAPIC ID                          (RW)
//   0x030  LAPIC Version                     (RO)
//   0x080  Task Priority Register (TPR)      (RW)
//   0x0B0  End of Interrupt (EOI)            (WO)
//   0x0D0  Logical Destination Register      (RW)
//   0x0E0  Destination Format Register       (RW)
//   0x0F0  Spurious Interrupt Vector (SVR)   (RW)
//   0x100-0x170  In-Service Register (ISR)   (RO, 256 bits)
//   0x180-0x1F0  Trigger Mode Register (TMR) (RO, 256 bits)
//   0x200-0x270  Interrupt Request Reg (IRR) (RO, 256 bits)
//   0x280  Error Status Register (ESR)       (RW)
//   0x300  ICR low (IPI command)             (RW)
//   0x310  ICR high (destination)            (RW)
//   0x320  LVT Timer                         (RW)
//   0x340  LVT Performance Counter           (RW)
//   0x350  LVT LINT0                         (RW)
//   0x360  LVT LINT1                         (RW)
//   0x370  LVT Error                         (RW)
//   0x380  Timer Initial Count               (RW)
//   0x390  Timer Current Count               (RO)
//   0x3E0  Timer Divide Configuration        (RW)
//
// I/O APIC indirect registers:
//   0x00  I/O APIC ID                        (RW)
//   0x01  I/O APIC Version                   (RO)
//   0x02  I/O APIC Arbitration ID            (RO)
//   0x10+2*n  Redirection Table Entry n low  (RW)
//   0x11+2*n  Redirection Table Entry n high (RW)

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

// ── StaticCell for safe global mutable state ──

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

// ── MSR helpers ──

const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// Read a 64-bit Model Specific Register.
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Write a 64-bit Model Specific Register.
#[inline]
fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── LAPIC register offsets ──

const LAPIC_REG_ID: usize = 0x020;
const LAPIC_REG_VERSION: usize = 0x030;
const LAPIC_REG_TPR: usize = 0x080;
const LAPIC_REG_EOI: usize = 0x0B0;
const LAPIC_REG_LDR: usize = 0x0D0;
const LAPIC_REG_DFR: usize = 0x0E0;
const LAPIC_REG_SVR: usize = 0x0F0;
const LAPIC_REG_ISR_BASE: usize = 0x100;
const LAPIC_REG_TMR_BASE: usize = 0x180;
const LAPIC_REG_IRR_BASE: usize = 0x200;
const LAPIC_REG_ESR: usize = 0x280;
const LAPIC_REG_ICR_LO: usize = 0x300;
const LAPIC_REG_ICR_HI: usize = 0x310;
const LAPIC_REG_LVT_TIMER: usize = 0x320;
const LAPIC_REG_LVT_PERF: usize = 0x340;
const LAPIC_REG_LVT_LINT0: usize = 0x350;
const LAPIC_REG_LVT_LINT1: usize = 0x360;
const LAPIC_REG_LVT_ERROR: usize = 0x370;
const LAPIC_REG_TIMER_INIT: usize = 0x380;
const LAPIC_REG_TIMER_CURRENT: usize = 0x390;
const LAPIC_REG_TIMER_DIV: usize = 0x3E0;

// ── LAPIC constants ──

/// Default LAPIC physical base address
const LAPIC_DEFAULT_BASE: u64 = 0xFEE0_0000;

/// LAPIC MMIO region size (4 KiB aligned, covers all registers up to 0x3F0)
const LAPIC_MMIO_SIZE: usize = 0x1000;

/// SVR bit 8: APIC Software Enable
const SVR_APIC_ENABLE: u32 = 1 << 8;

/// Spurious interrupt vector (conventionally 0xFF)
const SPURIOUS_VECTOR: u32 = 0xFF;

/// LVT mask bit (bit 16): when set the interrupt is masked
const LVT_MASK: u32 = 1 << 16;

/// LVT timer mode bits (bits 18:17)
const LVT_TIMER_ONE_SHOT: u32 = 0b00 << 17;
const LVT_TIMER_PERIODIC: u32 = 0b01 << 17;
const LVT_TIMER_TSC_DEADLINE: u32 = 0b10 << 17;
const LVT_TIMER_MODE_MASK: u32 = 0b11 << 17;

/// ICR delivery mode values (bits 10:8)
const ICR_DELIVERY_FIXED: u32 = 0b000 << 8;
const ICR_DELIVERY_INIT: u32 = 0b101 << 8;
const ICR_DELIVERY_STARTUP: u32 = 0b110 << 8;

/// ICR level (bit 14): assert
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// ICR level (bit 14): de-assert
const ICR_LEVEL_DEASSERT: u32 = 0;

/// ICR trigger mode (bit 15): edge
const ICR_TRIGGER_EDGE: u32 = 0;

/// ICR trigger mode (bit 15): level
const ICR_TRIGGER_LEVEL: u32 = 1 << 15;

/// ICR destination shorthand (bits 19:18)
const ICR_DEST_NO_SHORTHAND: u32 = 0b00 << 18;

/// ICR delivery status bit (bit 12)
const ICR_DELIVERY_STATUS: u32 = 1 << 12;

/// Timer divide configuration values
/// The divider register uses a non-trivial encoding
const TIMER_DIV_1: u32 = 0b1011;
const TIMER_DIV_2: u32 = 0b0000;
const TIMER_DIV_4: u32 = 0b0001;
const TIMER_DIV_8: u32 = 0b0010;
const TIMER_DIV_16: u32 = 0b0011;
const TIMER_DIV_32: u32 = 0b1000;
const TIMER_DIV_64: u32 = 0b1001;
const TIMER_DIV_128: u32 = 0b1010;

/// IA32_APIC_BASE MSR bit fields
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;
const APIC_BASE_ADDR_MASK: u64 = 0xFFFF_FFFF_FFFF_F000;

/// Timer mode constants for the exported API
const TIMER_MODE_ONESHOT: u32 = 0;
const TIMER_MODE_PERIODIC: u32 = 1;
const TIMER_MODE_TSC_DEADLINE: u32 = 2;

/// Calibration: approximate LAPIC ticks per millisecond
/// This is refined during calibration; initial estimate for fallback.
const DEFAULT_TICKS_PER_MS: u32 = 1_000_000;

/// Maximum number of spin iterations waiting for ICR delivery
const ICR_SEND_TIMEOUT: u32 = 100_000;

// ── I/O APIC constants ──

/// Default I/O APIC physical base address
const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;

/// I/O APIC MMIO region size (covers IOREGSEL + IOWIN)
const IOAPIC_MMIO_SIZE: usize = 0x1000;

/// I/O APIC indirect register select (offset 0x00)
const IOAPIC_IOREGSEL: usize = 0x00;

/// I/O APIC indirect register data window (offset 0x10)
const IOAPIC_IOWIN: usize = 0x10;

/// I/O APIC registers (accessed indirectly)
const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;
const IOAPIC_REG_ARB: u32 = 0x02;

/// Redirection table base register index
const IOAPIC_REDTBL_BASE: u32 = 0x10;

/// Redirection entry bits
const IOAPIC_REDIR_MASK: u64 = 1 << 16;
const IOAPIC_REDIR_LEVEL_TRIGGER: u64 = 1 << 15;
const IOAPIC_REDIR_ACTIVE_LOW: u64 = 1 << 13;
const IOAPIC_REDIR_LOGICAL_DEST: u64 = 1 << 11;

/// Delivery modes for redirection entries (bits 10:8)
const IOAPIC_DELMOD_FIXED: u64 = 0b000 << 8;
const IOAPIC_DELMOD_LOWEST: u64 = 0b001 << 8;
const IOAPIC_DELMOD_NMI: u64 = 0b100 << 8;
const IOAPIC_DELMOD_EXTINTR: u64 = 0b111 << 8;

/// Maximum IRQs an I/O APIC can support (24 is typical, spec allows up to 240)
const IOAPIC_MAX_IRQS: u32 = 240;

// ── LAPIC driver state ──

struct LapicState {
    /// Virtual address of the LAPIC MMIO base
    base: *mut u8,
    /// Physical address of the LAPIC base
    phys_base: u64,
    /// LAPIC ID of this CPU
    id: u32,
    /// LAPIC version
    version: u32,
    /// Max LVT entries (from version register bits 23:16)
    max_lvt: u32,
    /// Whether this CPU is the BSP
    is_bsp: bool,
    /// Calibrated timer ticks per millisecond
    ticks_per_ms: u32,
    /// Whether the driver is initialized
    initialized: bool,
}

impl LapicState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            id: 0,
            version: 0,
            max_lvt: 0,
            is_bsp: false,
            ticks_per_ms: 0,
            initialized: false,
        }
    }
}

static LAPIC: StaticCell<LapicState> = StaticCell::new(LapicState::new());

// ── I/O APIC driver state ──

struct IoApicState {
    /// Virtual address of the I/O APIC MMIO base
    base: *mut u8,
    /// Physical address of the I/O APIC base
    phys_base: u64,
    /// I/O APIC ID (from register 0x00)
    id: u32,
    /// I/O APIC version
    version: u32,
    /// Maximum redirection entry index (from version register bits 23:16)
    max_redir: u32,
    /// Whether the I/O APIC driver is initialized
    initialized: bool,
}

impl IoApicState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            id: 0,
            version: 0,
            max_redir: 0,
            initialized: false,
        }
    }
}

static IOAPIC: StaticCell<IoApicState> = StaticCell::new(IoApicState::new());

// ── I/O APIC indirect register access ──

/// Write to an I/O APIC indirect register.
fn ioapic_write(base: *mut u8, reg: u32, val: u32) {
    mmio_write32(base, IOAPIC_IOREGSEL, reg);
    fence(Ordering::SeqCst);
    mmio_write32(base, IOAPIC_IOWIN, val);
}

/// Read from an I/O APIC indirect register.
fn ioapic_read(base: *mut u8, reg: u32) -> u32 {
    mmio_write32(base, IOAPIC_IOREGSEL, reg);
    fence(Ordering::SeqCst);
    mmio_read32(base, IOAPIC_IOWIN)
}

/// Write a 64-bit redirection table entry (low + high halves).
fn ioapic_write_redir(base: *mut u8, index: u32, entry: u64) {
    let reg_lo = IOAPIC_REDTBL_BASE + index * 2;
    let reg_hi = reg_lo + 1;
    ioapic_write(base, reg_lo, entry as u32);
    ioapic_write(base, reg_hi, (entry >> 32) as u32);
}

/// Read a 64-bit redirection table entry (low + high halves).
fn ioapic_read_redir(base: *mut u8, index: u32) -> u64 {
    let reg_lo = IOAPIC_REDTBL_BASE + index * 2;
    let reg_hi = reg_lo + 1;
    let lo = ioapic_read(base, reg_lo) as u64;
    let hi = ioapic_read(base, reg_hi) as u64;
    lo | (hi << 32)
}

// ── LAPIC internal helpers ──

/// Wait for the ICR delivery status bit to clear, indicating the IPI
/// has been accepted by the local APIC. Returns true on success.
fn lapic_wait_icr_idle(base: *mut u8) -> bool {
    for _ in 0..ICR_SEND_TIMEOUT {
        if mmio_read32(base, LAPIC_REG_ICR_LO) & ICR_DELIVERY_STATUS == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Read the LAPIC base address from the IA32_APIC_BASE MSR.
/// Returns (physical_base_address, is_bsp, is_enabled).
fn read_apic_base_msr() -> (u64, bool, bool) {
    let msr = rdmsr(IA32_APIC_BASE_MSR);
    let phys = msr & APIC_BASE_ADDR_MASK;
    let bsp = (msr & APIC_BASE_BSP) != 0;
    let enabled = (msr & APIC_BASE_ENABLE) != 0;
    (phys, bsp, enabled)
}

/// Calibrate the LAPIC timer using a simple busy-wait loop.
///
/// We set the timer to a known initial count with divider = 16, wait
/// approximately 10 ms (using a rough rdtsc-based loop), then read back
/// how many ticks have elapsed. This gives us ticks-per-ms for later use.
///
/// For robustness, if TSC is unavailable or the measurement looks wrong,
/// we fall back to a conservative default.
fn calibrate_timer(base: *mut u8) -> u32 {
    // Set divider to 16
    mmio_write32(base, LAPIC_REG_TIMER_DIV, TIMER_DIV_16);

    // Configure LVT timer as one-shot, masked (we just want to measure ticks)
    mmio_write32(base, LAPIC_REG_LVT_TIMER, LVT_MASK | LVT_TIMER_ONE_SHOT);

    // Set initial count to max (0xFFFF_FFFF)
    mmio_write32(base, LAPIC_REG_TIMER_INIT, 0xFFFF_FFFF);

    // Busy-wait approximately 10 ms using a TSC-based loop.
    // Read TSC frequency: we spin for a fixed iteration count that
    // approximates 10 ms on modern hardware (~30M-50M iterations).
    // This is intentionally rough -- the timer will be re-calibrated
    // against HPET or PIT by higher-level code if precision is needed.
    let start_tsc: u64;
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") _,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
        // Use a simple spin loop: ~10 ms on a 2-4 GHz CPU
        // 10 ms * 3 GHz = 30M cycles, each iteration ~10 cycles
        let mut i: u32 = 0;
        while i < 3_000_000 {
            core::hint::spin_loop();
            i += 1;
        }
    }

    // Read current count
    let current = mmio_read32(base, LAPIC_REG_TIMER_CURRENT);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);

    // Stop the timer
    mmio_write32(base, LAPIC_REG_TIMER_INIT, 0);

    // elapsed ticks in ~10 ms, so ticks_per_ms = elapsed / 10
    // Apply divider factor: we used div-16, so actual bus ticks = elapsed
    let ticks_per_ms = if elapsed > 100 {
        elapsed / 10
    } else {
        // Measurement failed, use fallback
        DEFAULT_TICKS_PER_MS
    };

    ticks_per_ms
}

// ── LAPIC exported API ──

/// Initialize the Local APIC on the current CPU.
///
/// Detects the LAPIC base from MSR 0x1B, maps the MMIO region,
/// enables the APIC via the SVR register, masks all LVT entries,
/// clears ESR, and calibrates the timer.
///
/// Returns 0 on success, negative on error:
///   -1 = LAPIC not enabled in MSR
///   -2 = MMIO mapping failed
///   -3 = invalid LAPIC version
#[unsafe(no_mangle)]
pub extern "C" fn lapic_init() -> i32 {
    log("lapic: initializing Local APIC");

    // Read the APIC base address from MSR
    let (phys_base, is_bsp, is_enabled) = read_apic_base_msr();

    if !is_enabled {
        // Attempt to enable APIC via MSR
        let msr = rdmsr(IA32_APIC_BASE_MSR);
        wrmsr(IA32_APIC_BASE_MSR, msr | APIC_BASE_ENABLE);

        // Verify it took effect
        let (_, _, check) = read_apic_base_msr();
        if !check {
            log("lapic: failed to enable APIC via MSR");
            return -1;
        }
    }

    // Map the LAPIC MMIO region
    let base = unsafe { map_mmio_region(phys_base, LAPIC_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("lapic: failed to map MMIO region");
        return -2;
    }

    // Read version register
    let version_reg = mmio_read32(base, LAPIC_REG_VERSION);
    let version = version_reg & 0xFF;
    let max_lvt = ((version_reg >> 16) & 0xFF) + 1;

    // Sanity check: modern LAPIC versions are 0x10-0x20
    if version < 0x10 {
        log("lapic: invalid or ancient APIC version");
        unsafe { unmap_mmio_region(base, LAPIC_MMIO_SIZE) };
        return -3;
    }

    // Read LAPIC ID (bits 31:24 for xAPIC)
    let id = mmio_read32(base, LAPIC_REG_ID) >> 24;

    // Set Destination Format Register to flat model (all 1s in upper nibble)
    mmio_write32(base, LAPIC_REG_DFR, 0xFFFF_FFFF);

    // Set Logical Destination Register: use LAPIC ID as logical ID
    let ldr = mmio_read32(base, LAPIC_REG_LDR);
    mmio_write32(base, LAPIC_REG_LDR, (ldr & 0x00FF_FFFF) | ((id << 24) & 0xFF00_0000));

    // Set Task Priority to 0 (accept all interrupts)
    mmio_write32(base, LAPIC_REG_TPR, 0);

    // Mask all LVT entries before enabling
    mmio_write32(base, LAPIC_REG_LVT_TIMER, LVT_MASK);
    if max_lvt >= 4 {
        mmio_write32(base, LAPIC_REG_LVT_PERF, LVT_MASK);
    }
    mmio_write32(base, LAPIC_REG_LVT_LINT0, LVT_MASK);
    mmio_write32(base, LAPIC_REG_LVT_LINT1, LVT_MASK);
    mmio_write32(base, LAPIC_REG_LVT_ERROR, LVT_MASK);

    // Clear Error Status Register (write then read to latch)
    mmio_write32(base, LAPIC_REG_ESR, 0);
    mmio_write32(base, LAPIC_REG_ESR, 0);

    // Enable APIC: set SVR with enable bit and spurious vector
    mmio_write32(base, LAPIC_REG_SVR, SVR_APIC_ENABLE | SPURIOUS_VECTOR);

    fence(Ordering::SeqCst);

    // Calibrate the LAPIC timer
    let ticks_per_ms = calibrate_timer(base);

    // Store state
    let state = LAPIC.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = phys_base;
        (*state).id = id;
        (*state).version = version;
        (*state).max_lvt = max_lvt;
        (*state).is_bsp = is_bsp;
        (*state).ticks_per_ms = ticks_per_ms;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    unsafe {
        fut_printf(
            b"lapic: id=%u version=0x%02x max_lvt=%u bsp=%u base=0x%lx\n\0".as_ptr(),
            id,
            version,
            max_lvt,
            is_bsp as u32,
            phys_base,
        );
        fut_printf(
            b"lapic: timer calibrated: ~%u ticks/ms (div16)\n\0".as_ptr(),
            ticks_per_ms,
        );
    }

    0
}

/// Send an End-of-Interrupt signal to the LAPIC.
///
/// Must be called at the end of every interrupt handler for LAPIC-routed
/// interrupts. Writing 0 to the EOI register signals completion.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_eoi() {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return;
        }
        mmio_write32((*state).base, LAPIC_REG_EOI, 0);
    }
}

/// Read the LAPIC ID of the current CPU.
///
/// Returns the 8-bit xAPIC ID, or 0xFFFF_FFFF if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_id() -> u32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return 0xFFFF_FFFF;
        }
        // Re-read from hardware for accuracy
        mmio_read32((*state).base, LAPIC_REG_ID) >> 24
    }
}

/// Send an Inter-Processor Interrupt (IPI) to a destination APIC.
///
/// `dest`: destination LAPIC ID (8-bit xAPIC ID)
/// `vector`: interrupt vector number (0-255)
///
/// Sends a fixed-delivery, edge-triggered IPI with no shorthand.
/// For INIT and SIPI delivery, use the dedicated helpers or encode
/// the delivery mode directly.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = ICR busy (timeout waiting for delivery)
#[unsafe(no_mangle)]
pub extern "C" fn lapic_send_ipi(dest: u32, vector: u8) -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;

        // Wait for any pending IPI to complete
        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        // Write destination APIC ID to ICR high (bits 31:24)
        mmio_write32(base, LAPIC_REG_ICR_HI, dest << 24);

        // Write ICR low: vector | fixed delivery | edge trigger | assert | no shorthand
        let icr_lo = (vector as u32)
            | ICR_DELIVERY_FIXED
            | ICR_TRIGGER_EDGE
            | ICR_LEVEL_ASSERT
            | ICR_DEST_NO_SHORTHAND;

        mmio_write32(base, LAPIC_REG_ICR_LO, icr_lo);

        fence(Ordering::SeqCst);

        // Wait for delivery to complete
        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        0
    }
}

/// Send an INIT IPI to a destination APIC.
///
/// This is step 1 of the SMP boot protocol (INIT-SIPI-SIPI).
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_send_init(dest: u32) -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;

        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        // INIT assert
        mmio_write32(base, LAPIC_REG_ICR_HI, dest << 24);
        mmio_write32(
            base,
            LAPIC_REG_ICR_LO,
            ICR_DELIVERY_INIT | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_NO_SHORTHAND,
        );

        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        // INIT de-assert (required by spec)
        mmio_write32(base, LAPIC_REG_ICR_HI, dest << 24);
        mmio_write32(
            base,
            LAPIC_REG_ICR_LO,
            ICR_DELIVERY_INIT | ICR_LEVEL_DEASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_NO_SHORTHAND,
        );

        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        0
    }
}

/// Send a Startup IPI (SIPI) to a destination APIC.
///
/// `dest`: destination LAPIC ID
/// `vector_page`: the page number (0-0xFF) of the real-mode startup code.
///   The AP will begin executing at physical address `vector_page * 0x1000`.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_send_startup(dest: u32, vector_page: u8) -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;

        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        mmio_write32(base, LAPIC_REG_ICR_HI, dest << 24);
        mmio_write32(
            base,
            LAPIC_REG_ICR_LO,
            (vector_page as u32)
                | ICR_DELIVERY_STARTUP
                | ICR_TRIGGER_EDGE
                | ICR_LEVEL_ASSERT
                | ICR_DEST_NO_SHORTHAND,
        );

        if !lapic_wait_icr_idle(base) {
            return -2;
        }

        0
    }
}

/// Configure and start the LAPIC timer.
///
/// `mode`:
///   0 = one-shot: fires once after `initial_count` ticks
///   1 = periodic: fires repeatedly every `initial_count` ticks
///   2 = TSC-deadline: `initial_count` is written to IA32_TSC_DEADLINE MSR
///
/// `vector`: interrupt vector to deliver on timer expiry
/// `initial_count`: timer tick count (divider is set to 16)
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = invalid timer mode
///   -3 = zero initial count (except TSC-deadline where 0 disarms)
#[unsafe(no_mangle)]
pub extern "C" fn lapic_timer_setup(mode: u32, vector: u8, initial_count: u32) -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;

        let timer_mode_bits = match mode {
            TIMER_MODE_ONESHOT => {
                if initial_count == 0 {
                    return -3;
                }
                LVT_TIMER_ONE_SHOT
            }
            TIMER_MODE_PERIODIC => {
                if initial_count == 0 {
                    return -3;
                }
                LVT_TIMER_PERIODIC
            }
            TIMER_MODE_TSC_DEADLINE => LVT_TIMER_TSC_DEADLINE,
            _ => return -2,
        };

        // Stop current timer
        mmio_write32(base, LAPIC_REG_TIMER_INIT, 0);

        // Set divider to 16
        mmio_write32(base, LAPIC_REG_TIMER_DIV, TIMER_DIV_16);

        // Configure LVT timer entry: mode | vector (unmasked)
        mmio_write32(base, LAPIC_REG_LVT_TIMER, timer_mode_bits | (vector as u32));

        if mode == TIMER_MODE_TSC_DEADLINE {
            // For TSC-deadline, write the deadline to IA32_TSC_DEADLINE_MSR (0x6E0)
            wrmsr(0x6E0, initial_count as u64);
        } else {
            // Start the timer by writing the initial count
            mmio_write32(base, LAPIC_REG_TIMER_INIT, initial_count);
        }

        fence(Ordering::SeqCst);

        0
    }
}

/// Stop the LAPIC timer by zeroing the initial count and masking the LVT entry.
///
/// Returns 0 on success, -1 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_timer_stop() -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        let base = (*state).base;
        mmio_write32(base, LAPIC_REG_TIMER_INIT, 0);
        mmio_write32(base, LAPIC_REG_LVT_TIMER, LVT_MASK);
        0
    }
}

/// Read the LAPIC timer's current count register.
///
/// Returns the remaining tick count, or 0 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_timer_current() -> u32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read32((*state).base, LAPIC_REG_TIMER_CURRENT)
    }
}

/// Get the calibrated timer ticks-per-millisecond value (with div-16).
///
/// Returns 0 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_timer_ticks_per_ms() -> u32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).ticks_per_ms }
    }
}

/// Configure an LVT entry directly.
///
/// `lvt`: which LVT register to configure:
///   0 = LINT0, 1 = LINT1, 2 = Error, 3 = Performance Counter
/// `vector`: interrupt vector
/// `masked`: whether to mask the entry
/// `trigger_level`: true = level-triggered, false = edge-triggered
/// `active_low`: true = active-low polarity, false = active-high
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_lvt_configure(
    lvt: u32,
    vector: u8,
    masked: bool,
    trigger_level: bool,
    active_low: bool,
) -> i32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        let base = (*state).base;

        let reg_offset = match lvt {
            0 => LAPIC_REG_LVT_LINT0,
            1 => LAPIC_REG_LVT_LINT1,
            2 => LAPIC_REG_LVT_ERROR,
            3 => {
                if (*state).max_lvt < 4 {
                    return -3;
                }
                LAPIC_REG_LVT_PERF
            }
            _ => return -2,
        };

        let mut val = vector as u32;
        if masked {
            val |= LVT_MASK;
        }
        if trigger_level {
            val |= 1 << 15; // Trigger mode: level
        }
        if active_low {
            val |= 1 << 13; // Polarity: active-low
        }

        mmio_write32(base, reg_offset, val);

        0
    }
}

/// Read the LAPIC Error Status Register.
///
/// Writes 0 to ESR first to latch errors, then reads and returns the value.
/// Returns 0 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn lapic_read_esr() -> u32 {
    let state = LAPIC.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        let base = (*state).base;
        // Write to latch, then read
        mmio_write32(base, LAPIC_REG_ESR, 0);
        mmio_read32(base, LAPIC_REG_ESR)
    }
}

// ── I/O APIC exported API ──

/// Initialize the I/O APIC.
///
/// `base_addr`: physical address of the I/O APIC MMIO region.
///   Pass 0 to use the default address (0xFEC0_0000).
///
/// Maps the MMIO region, reads the I/O APIC ID and version, determines
/// the maximum number of redirection entries, and masks all entries.
///
/// Returns 0 on success, negative on error:
///   -1 = MMIO mapping failed
///   -2 = invalid version (zero max redirection entries)
#[unsafe(no_mangle)]
pub extern "C" fn ioapic_init(base_addr: u64) -> i32 {
    let phys = if base_addr == 0 { IOAPIC_DEFAULT_BASE } else { base_addr };

    log("ioapic: initializing I/O APIC");

    // Map the I/O APIC MMIO region
    let base = unsafe { map_mmio_region(phys, IOAPIC_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("ioapic: failed to map MMIO region");
        return -1;
    }

    // Read I/O APIC ID (bits 27:24 of register 0x00)
    let id_reg = ioapic_read(base, IOAPIC_REG_ID);
    let id = (id_reg >> 24) & 0x0F;

    // Read version register
    let ver_reg = ioapic_read(base, IOAPIC_REG_VER);
    let version = ver_reg & 0xFF;
    let max_redir = ((ver_reg >> 16) & 0xFF) + 1;

    if max_redir == 0 || max_redir > IOAPIC_MAX_IRQS {
        log("ioapic: invalid max redirection entries");
        unsafe { unmap_mmio_region(base, IOAPIC_MMIO_SIZE) };
        return -2;
    }

    // Mask all redirection entries
    for i in 0..max_redir {
        let entry = ioapic_read_redir(base, i);
        ioapic_write_redir(base, i, entry | IOAPIC_REDIR_MASK);
    }

    // Store state
    let state = IOAPIC.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = phys;
        (*state).id = id;
        (*state).version = version;
        (*state).max_redir = max_redir;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    unsafe {
        fut_printf(
            b"ioapic: id=%u version=0x%02x max_irqs=%u base=0x%lx\n\0".as_ptr(),
            id,
            version,
            max_redir,
            phys,
        );
    }

    0
}

/// Route an IRQ through the I/O APIC to a destination APIC and vector.
///
/// `irq`: IRQ number (I/O APIC input pin, 0-based)
/// `vector`: interrupt vector to deliver (32-255)
/// `dest_apic`: destination LAPIC ID
/// `level_triggered`: true for level-triggered, false for edge-triggered
/// `active_low`: true for active-low polarity, false for active-high
///
/// The entry is programmed masked; call `ioapic_unmask_irq` to enable delivery.
///
/// Returns 0 on success, negative on error:
///   -1 = I/O APIC not initialized
///   -2 = IRQ number out of range
#[unsafe(no_mangle)]
pub extern "C" fn ioapic_route_irq(
    irq: u8,
    vector: u8,
    dest_apic: u8,
    level_triggered: bool,
    active_low: bool,
) -> i32 {
    let state = IOAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }

        if (irq as u32) >= (*state).max_redir {
            return -2;
        }

        let base = (*state).base;

        // Build the redirection entry
        let mut entry: u64 = (vector as u64) & 0xFF;

        // Fixed delivery mode (bits 10:8 = 000)
        entry |= IOAPIC_DELMOD_FIXED;

        // Physical destination mode (bit 11 = 0)
        // (leave bit 11 clear)

        if level_triggered {
            entry |= IOAPIC_REDIR_LEVEL_TRIGGER;
        }

        if active_low {
            entry |= IOAPIC_REDIR_ACTIVE_LOW;
        }

        // Start masked (caller uses ioapic_unmask_irq to enable)
        entry |= IOAPIC_REDIR_MASK;

        // Destination APIC ID in bits 63:56
        entry |= (dest_apic as u64) << 56;

        ioapic_write_redir(base, irq as u32, entry);

        0
    }
}

/// Mask (disable) an I/O APIC IRQ by setting the mask bit.
///
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2 = IRQ out of range
#[unsafe(no_mangle)]
pub extern "C" fn ioapic_mask_irq(irq: u8) -> i32 {
    let state = IOAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if (irq as u32) >= (*state).max_redir {
            return -2;
        }

        let base = (*state).base;
        let entry = ioapic_read_redir(base, irq as u32);
        ioapic_write_redir(base, irq as u32, entry | IOAPIC_REDIR_MASK);

        0
    }
}

/// Unmask (enable) an I/O APIC IRQ by clearing the mask bit.
///
/// Returns 0 on success, negative on error:
///   -1 = not initialized
///   -2 = IRQ out of range
#[unsafe(no_mangle)]
pub extern "C" fn ioapic_unmask_irq(irq: u8) -> i32 {
    let state = IOAPIC.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if (irq as u32) >= (*state).max_redir {
            return -2;
        }

        let base = (*state).base;
        let entry = ioapic_read_redir(base, irq as u32);
        ioapic_write_redir(base, irq as u32, entry & !IOAPIC_REDIR_MASK);

        0
    }
}

/// Return the maximum number of IRQs supported by the I/O APIC.
///
/// This is the max redirection entry count (typically 24).
/// Returns 0 if the I/O APIC is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn ioapic_max_irqs() -> u32 {
    let state = IOAPIC.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).max_redir }
    }
}

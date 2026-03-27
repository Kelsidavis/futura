// SPDX-License-Identifier: MPL-2.0
//
// HPET (High Precision Event Timer) Driver for Futura OS
//
// Implements the IA-PC HPET Specification Rev 1.0a (Intel, 2004) for
// x86_64 AMD Ryzen AM4/AM5 platforms. The HPET provides a monotonic,
// high-resolution free-running counter and up to 32 programmable
// comparator timers for one-shot or periodic interrupts.
//
// Architecture:
//   - Memory-mapped register block (typically at 0xFED0_0000)
//   - 64-bit main counter with femtosecond-resolution clock period
//   - Per-timer configuration: one-shot, periodic, 32/64-bit, routing
//   - Nanosecond-precision timestamp and busy-wait delay functions
//   - Discoverable via ACPI HPET table (base address passed at init)
//
// Register map (per IA-PC HPET Spec):
//   0x000  General Capabilities and ID          (64-bit, RO)
//   0x010  General Configuration                (64-bit, RW)
//   0x020  General Interrupt Status             (64-bit, R/WC)
//   0x0F0  Main Counter Value                   (64-bit, RW)
//   0x100 + N*0x20  Timer N Config/Capabilities (64-bit, RW)
//   0x108 + N*0x20  Timer N Comparator Value    (64-bit, RW)
//   0x110 + N*0x20  Timer N FSB Interrupt Route (64-bit, RW)

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

// ── HPET register offsets (IA-PC HPET Spec, Table 2) ──

/// General Capabilities and ID Register (RO)
/// Bits 63:32 = COUNTER_CLK_PERIOD (femtoseconds per tick)
/// Bits 31:16 = VENDOR_ID
/// Bit  15    = LEG_RT_CAP (legacy replacement routing capable)
/// Bit  13    = COUNT_SIZE_CAP (1 = 64-bit counter, 0 = 32-bit)
/// Bits 12:8  = NUM_TIM_CAP (number of timers minus one)
/// Bits  7:0  = REV_ID
const HPET_REG_CAP: usize = 0x000;

/// General Configuration Register (RW)
/// Bit 1 = LEG_RT_CNF (legacy replacement route)
/// Bit 0 = ENABLE_CNF (overall counter enable)
const HPET_REG_CFG: usize = 0x010;

/// General Interrupt Status Register (R/WC)
/// Bit N = Timer N interrupt status (write 1 to clear)
const HPET_REG_INT_STS: usize = 0x020;

/// Main Counter Value Register (RW when counter disabled, RO when enabled)
const HPET_REG_COUNTER: usize = 0x0F0;

// ── Timer N register offsets (base = 0x100 + N*0x20) ──

/// Timer N Configuration and Capabilities Register (RW)
/// Bit 14    = Tn_FSB_EN_CNF (FSB interrupt enable)
/// Bit 13    = Tn_FSB_INT_DEL_CAP (FSB interrupt capable, RO)
/// Bit  8    = Tn_32MODE_CNF (force 32-bit mode)
/// Bit  6    = Tn_VAL_SET_CNF (set accumulator, self-clears)
/// Bit  5    = Tn_SIZE_CAP (1 = 64-bit capable, RO)
/// Bit  4    = Tn_PER_INT_CAP (periodic capable, RO)
/// Bit  3    = Tn_TYPE_CNF (1 = periodic, 0 = one-shot)
/// Bit  2    = Tn_INT_ENB_CNF (interrupt enable)
/// Bit  1    = Tn_INT_TYPE_CNF (0 = edge, 1 = level triggered)
/// Bits 13:9 = Tn_INT_ROUTE_CNF (APIC routing)
/// Bits 63:32 = Tn_INT_ROUTE_CAP (allowed routes, RO)
const HPET_TIMER_CFG_OFFSET: usize = 0x00;

/// Timer N Comparator Value Register (RW)
const HPET_TIMER_CMP_OFFSET: usize = 0x08;

/// Timer N FSB Interrupt Route Register (RW)
const HPET_TIMER_FSB_OFFSET: usize = 0x10;

/// Stride between timer register blocks
const HPET_TIMER_STRIDE: usize = 0x20;

/// Base offset of timer 0 registers
const HPET_TIMER_BASE: usize = 0x100;

// ── General Configuration bits ──

const HPET_CFG_ENABLE: u64 = 1 << 0;
const HPET_CFG_LEGACY_RT: u64 = 1 << 1;

// ── Timer Configuration bits ──

const HPET_TN_INT_TYPE_LEVEL: u64 = 1 << 1;
const HPET_TN_INT_ENB: u64 = 1 << 2;
const HPET_TN_TYPE_PERIODIC: u64 = 1 << 3;
const HPET_TN_PER_INT_CAP: u64 = 1 << 4;
const HPET_TN_SIZE_CAP: u64 = 1 << 5;
const HPET_TN_VAL_SET: u64 = 1 << 6;
const HPET_TN_32MODE: u64 = 1 << 8;
const HPET_TN_FSB_INT_DEL_CAP: u64 = 1 << 13;
const HPET_TN_FSB_EN: u64 = 1 << 14;

// ── Capabilities field extraction ──

/// Extract COUNTER_CLK_PERIOD in femtoseconds from capabilities register
const fn cap_clk_period(cap: u64) -> u32 {
    (cap >> 32) as u32
}

/// Extract number of timers (NUM_TIM_CAP + 1) from capabilities register
const fn cap_num_timers(cap: u64) -> u32 {
    (((cap >> 8) & 0x1F) as u32) + 1
}

/// Extract 64-bit counter capability from capabilities register
const fn cap_count_size_64(cap: u64) -> bool {
    (cap & (1 << 13)) != 0
}

/// Extract revision ID from capabilities register
const fn cap_rev_id(cap: u64) -> u8 {
    (cap & 0xFF) as u8
}

/// Extract vendor ID from capabilities register
const fn cap_vendor_id(cap: u64) -> u16 {
    ((cap >> 16) & 0xFFFF) as u16
}

/// Extract legacy replacement routing capability
const fn cap_legacy_rt(cap: u64) -> bool {
    (cap & (1 << 15)) != 0
}

// ── Default HPET MMIO base address ──

const HPET_DEFAULT_BASE: u64 = 0xFED0_0000;

/// Size of the HPET MMIO register block (1 KiB covers all timers)
const HPET_MMIO_SIZE: usize = 0x400;

/// Maximum number of HPET timers per spec (indices 0..31)
const HPET_MAX_TIMERS: u32 = 32;

/// Femtoseconds per nanosecond
const FEMTOS_PER_NANO: u64 = 1_000_000;

/// Maximum valid clock period per spec: must not exceed 0x05F5_E100 (100 ns)
const HPET_MAX_CLK_PERIOD: u32 = 0x05F5_E100;

// ── Driver state ──

struct HpetState {
    /// Virtual address of MMIO register base
    base: *mut u8,
    /// Physical address of MMIO register base
    phys_base: u64,
    /// Counter clock period in femtoseconds
    clk_period_fs: u32,
    /// Number of timers (1..32)
    num_timers: u32,
    /// Whether the main counter is 64-bit capable
    counter_64bit: bool,
    /// Whether legacy replacement routing is supported
    legacy_rt_cap: bool,
    /// Counter value latched at init (used as epoch for nanos)
    counter_at_init: u64,
    /// Calculated frequency in Hz
    frequency_hz: u64,
    /// Revision ID
    rev_id: u8,
    /// Vendor ID
    vendor_id: u16,
    /// Whether the driver has been initialized
    initialized: bool,
}

impl HpetState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            clk_period_fs: 0,
            num_timers: 0,
            counter_64bit: false,
            legacy_rt_cap: false,
            counter_at_init: 0,
            frequency_hz: 0,
            rev_id: 0,
            vendor_id: 0,
            initialized: false,
        }
    }
}

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    /// Returns a raw pointer to the inner value.
    fn get(&self) -> *mut T { self.0.get() }
}

static HPET: StaticCell<HpetState> = StaticCell::new(HpetState::new());

// ── MMIO helpers ──

/// Read a 64-bit MMIO register at the given offset from the HPET base.
#[inline]
fn mmio_read64(base: *mut u8, offset: usize) -> u64 {
    unsafe { read_volatile(base.add(offset) as *const u64) }
}

/// Write a 64-bit MMIO register at the given offset from the HPET base.
#[inline]
fn mmio_write64(base: *mut u8, offset: usize, val: u64) {
    unsafe { write_volatile(base.add(offset) as *mut u64, val) }
}

/// Read a 32-bit MMIO register at the given offset from the HPET base.
#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

/// Write a 32-bit MMIO register at the given offset from the HPET base.
#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Internal helpers ──

/// Calculate the register offset for timer N's configuration register.
#[inline]
const fn timer_cfg_offset(n: u32) -> usize {
    HPET_TIMER_BASE + (n as usize) * HPET_TIMER_STRIDE + HPET_TIMER_CFG_OFFSET
}

/// Calculate the register offset for timer N's comparator register.
#[inline]
const fn timer_cmp_offset(n: u32) -> usize {
    HPET_TIMER_BASE + (n as usize) * HPET_TIMER_STRIDE + HPET_TIMER_CMP_OFFSET
}

/// Calculate the register offset for timer N's FSB interrupt route register.
#[inline]
const fn timer_fsb_offset(n: u32) -> usize {
    HPET_TIMER_BASE + (n as usize) * HPET_TIMER_STRIDE + HPET_TIMER_FSB_OFFSET
}

/// Convert a tick count to nanoseconds given the clock period in femtoseconds.
/// Uses 64-bit arithmetic: ns = ticks * clk_period_fs / 1_000_000
/// To avoid overflow for large tick values, we split the multiplication.
#[inline]
fn ticks_to_nanos(ticks: u64, clk_period_fs: u32) -> u64 {
    let period = clk_period_fs as u64;
    // Use 128-bit multiplication to avoid overflow
    let product = (ticks as u128) * (period as u128);
    (product / (FEMTOS_PER_NANO as u128)) as u64
}

/// Convert nanoseconds to tick count given the clock period in femtoseconds.
#[inline]
fn nanos_to_ticks(ns: u64, clk_period_fs: u32) -> u64 {
    let period = clk_period_fs as u64;
    if period == 0 { return 0; }
    // ns * 1_000_000 / clk_period_fs, using 128-bit to avoid overflow
    let product = (ns as u128) * (FEMTOS_PER_NANO as u128);
    (product / (period as u128)) as u64
}

/// Halt the main counter by clearing ENABLE_CNF in the General Configuration register.
fn hpet_halt_counter(base: *mut u8) {
    let cfg = mmio_read64(base, HPET_REG_CFG);
    mmio_write64(base, HPET_REG_CFG, cfg & !HPET_CFG_ENABLE);
    fence(Ordering::SeqCst);
}

/// Start the main counter by setting ENABLE_CNF in the General Configuration register.
fn hpet_start_counter(base: *mut u8) {
    let cfg = mmio_read64(base, HPET_REG_CFG);
    mmio_write64(base, HPET_REG_CFG, cfg | HPET_CFG_ENABLE);
    fence(Ordering::SeqCst);
}

// ── FFI exports ──

/// Initialize the HPET driver.
///
/// `base_addr`: physical address of the HPET MMIO register block.
///   Pass 0 to use the default address (0xFED0_0000).
///
/// Returns 0 on success, negative on error:
///   -1 = MMIO mapping failed
///   -2 = invalid clock period (zero or exceeds spec maximum)
///   -3 = no timers reported
#[unsafe(no_mangle)]
pub extern "C" fn hpet_init(base_addr: u64) -> i32 {
    let phys = if base_addr == 0 { HPET_DEFAULT_BASE } else { base_addr };

    log("hpet: initializing HPET timer");

    // Map the HPET MMIO region
    let base = unsafe { map_mmio_region(phys, HPET_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("hpet: failed to map MMIO region");
        return -1;
    }

    // Read General Capabilities and ID register
    let cap = mmio_read64(base, HPET_REG_CAP);
    let clk_period = cap_clk_period(cap);
    let num_timers = cap_num_timers(cap);
    let counter_64 = cap_count_size_64(cap);
    let legacy_rt = cap_legacy_rt(cap);
    let rev_id = cap_rev_id(cap);
    let vendor_id = cap_vendor_id(cap);

    // Validate clock period per IA-PC HPET Spec section 2.3.9.7.2:
    // Must be > 0 and <= 0x05F5_E100 (100 ns = 10 MHz minimum frequency)
    if clk_period == 0 || clk_period > HPET_MAX_CLK_PERIOD {
        log("hpet: invalid clock period");
        unsafe { unmap_mmio_region(base, HPET_MMIO_SIZE); }
        return -2;
    }

    if num_timers == 0 || num_timers > HPET_MAX_TIMERS {
        log("hpet: invalid timer count");
        unsafe { unmap_mmio_region(base, HPET_MMIO_SIZE); }
        return -3;
    }

    // Calculate frequency: freq = 10^15 / clk_period_fs
    let frequency = 1_000_000_000_000_000u64 / (clk_period as u64);

    // Halt counter before configuration (IA-PC HPET Spec section 2.3.9.1)
    hpet_halt_counter(base);

    // Disable legacy replacement routing
    let cfg = mmio_read64(base, HPET_REG_CFG);
    mmio_write64(base, HPET_REG_CFG, cfg & !HPET_CFG_LEGACY_RT);

    // Clear main counter
    mmio_write64(base, HPET_REG_COUNTER, 0);

    // Disable all timers and clear pending interrupts
    for i in 0..num_timers {
        let tcfg = mmio_read64(base, timer_cfg_offset(i));
        // Clear interrupt enable and type bits, preserve read-only capabilities
        mmio_write64(base, timer_cfg_offset(i),
            tcfg & !(HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC | HPET_TN_INT_TYPE_LEVEL));
    }

    // Clear all pending interrupts in the General Interrupt Status register
    // Writing 1 to each bit clears it (W1C)
    mmio_write64(base, HPET_REG_INT_STS, mmio_read64(base, HPET_REG_INT_STS));

    // Start the counter
    hpet_start_counter(base);

    // Read initial counter value (should be near zero since we just cleared it)
    let counter_init = mmio_read64(base, HPET_REG_COUNTER);

    // Store state
    let state = HPET.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = phys;
        (*state).clk_period_fs = clk_period;
        (*state).num_timers = num_timers;
        (*state).counter_64bit = counter_64;
        (*state).legacy_rt_cap = legacy_rt;
        (*state).counter_at_init = counter_init;
        (*state).frequency_hz = frequency;
        (*state).rev_id = rev_id;
        (*state).vendor_id = vendor_id;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    unsafe {
        fut_printf(
            b"hpet: rev %u, vendor 0x%04x, %u timers, %s counter\n\0".as_ptr(),
            rev_id as u32,
            vendor_id as u32,
            num_timers,
            if counter_64 { b"64-bit\0".as_ptr() } else { b"32-bit\0".as_ptr() },
        );
        fut_printf(
            b"hpet: clock period %u fs, frequency %llu Hz\n\0".as_ptr(),
            clk_period,
            frequency,
        );
    }

    // Log per-timer capabilities
    for i in 0..num_timers {
        let tcfg = mmio_read64(base, timer_cfg_offset(i));
        let periodic_cap = (tcfg & HPET_TN_PER_INT_CAP) != 0;
        let size_64 = (tcfg & HPET_TN_SIZE_CAP) != 0;
        let fsb_cap = (tcfg & HPET_TN_FSB_INT_DEL_CAP) != 0;
        let route_cap = (tcfg >> 32) as u32;
        unsafe {
            fut_printf(
                b"hpet: timer %u: %s %s%sroute_cap=0x%08x\n\0".as_ptr(),
                i,
                if size_64 { b"64-bit\0".as_ptr() } else { b"32-bit\0".as_ptr() },
                if periodic_cap { b"periodic \0".as_ptr() } else { b"\0".as_ptr() },
                if fsb_cap { b"fsb \0".as_ptr() } else { b"\0".as_ptr() },
                route_cap,
            );
        }
    }

    0
}

/// Read the raw HPET main counter value.
///
/// Returns the current 64-bit counter value, or 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_read_counter() -> u64 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        mmio_read64((*state).base, HPET_REG_COUNTER)
    }
}

/// Get the number of nanoseconds elapsed since HPET initialization.
///
/// Uses 128-bit arithmetic internally to avoid overflow.
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_nanos() -> u64 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }
        let now = mmio_read64((*state).base, HPET_REG_COUNTER);
        let elapsed = now.wrapping_sub((*state).counter_at_init);
        ticks_to_nanos(elapsed, (*state).clk_period_fs)
    }
}

/// Get the HPET counter frequency in Hz.
///
/// Calculated as 10^15 / COUNTER_CLK_PERIOD (femtoseconds).
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_frequency() -> u64 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).frequency_hz }
    }
}

/// Busy-wait for the specified number of nanoseconds.
///
/// Spins reading the HPET main counter until the requested duration has elapsed.
/// Accurate to one counter tick (typically ~40-70 ns on modern systems).
///
/// Does nothing if the driver is not initialized or ns is 0.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_delay_ns(ns: u64) {
    if ns == 0 { return; }

    let state = HPET.get();
    unsafe {
        if !(*state).initialized { return; }

        let base = (*state).base;
        let clk_period = (*state).clk_period_fs;
        let ticks_needed = nanos_to_ticks(ns, clk_period);
        if ticks_needed == 0 { return; }

        let start = mmio_read64(base, HPET_REG_COUNTER);
        loop {
            let now = mmio_read64(base, HPET_REG_COUNTER);
            if now.wrapping_sub(start) >= ticks_needed {
                break;
            }
            core::hint::spin_loop();
        }
    }
}

/// Busy-wait for the specified number of microseconds.
///
/// Convenience wrapper around `hpet_delay_ns`.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_delay_us(us: u64) {
    hpet_delay_ns(us.saturating_mul(1000));
}

/// Get the number of available HPET timers.
///
/// Returns 0 if the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_timer_count() -> u32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).num_timers }
    }
}

/// Configure a one-shot timer to fire after `ns_from_now` nanoseconds.
///
/// Programs timer `timer` in non-periodic (one-shot) mode by writing
/// the comparator to main_counter + ticks(ns_from_now). The timer's
/// interrupt is enabled with edge-triggered signalling on IOAPIC route 0
/// (or the lowest available route).
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = timer index out of range
///   -3 = requested delay too small (rounds to zero ticks)
#[unsafe(no_mangle)]
pub extern "C" fn hpet_setup_oneshot(timer: u32, ns_from_now: u64) -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if timer >= (*state).num_timers {
            return -2;
        }

        let base = (*state).base;
        let clk_period = (*state).clk_period_fs;
        let ticks = nanos_to_ticks(ns_from_now, clk_period);
        if ticks == 0 {
            return -3;
        }

        // Read current timer configuration (preserving read-only capability bits)
        let tcfg = mmio_read64(base, timer_cfg_offset(timer));

        // Determine available interrupt routes from Tn_INT_ROUTE_CAP
        let route_cap = (tcfg >> 32) as u32;
        let route: u64 = if route_cap != 0 {
            // Use the lowest available IOAPIC input
            let bit = route_cap.trailing_zeros();
            (bit as u64) << 9
        } else {
            0 // Route 0
        };

        // Configure: one-shot, edge-triggered, interrupt enabled
        // Clear periodic, level-trigger, 32-bit-force, FSB, and val-set bits
        // Set interrupt enable and routing
        let new_cfg = (tcfg & !(HPET_TN_TYPE_PERIODIC
                                | HPET_TN_INT_TYPE_LEVEL
                                | HPET_TN_32MODE
                                | HPET_TN_FSB_EN
                                | HPET_TN_VAL_SET
                                | (0x1F << 9)))  // Clear existing route
                     | HPET_TN_INT_ENB
                     | route;

        mmio_write64(base, timer_cfg_offset(timer), new_cfg);

        // Write comparator value = current counter + requested ticks
        let current = mmio_read64(base, HPET_REG_COUNTER);
        let target = current.wrapping_add(ticks);
        mmio_write64(base, timer_cmp_offset(timer), target);

        // Ensure the write is visible
        fence(Ordering::SeqCst);

        0
    }
}

/// Configure a periodic timer with the given interval in nanoseconds.
///
/// Programs timer `timer` in periodic mode if the hardware supports it
/// (Tn_PER_INT_CAP must be set). The comparator is programmed with the
/// period in ticks, and the accumulator is initialised to fire at
/// current_counter + ticks.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = timer index out of range
///   -3 = timer does not support periodic mode
///   -4 = requested period too small (rounds to zero ticks)
#[unsafe(no_mangle)]
pub extern "C" fn hpet_setup_periodic(timer: u32, interval_ns: u64) -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if timer >= (*state).num_timers {
            return -2;
        }

        let base = (*state).base;
        let clk_period = (*state).clk_period_fs;

        // Check periodic capability
        let tcfg = mmio_read64(base, timer_cfg_offset(timer));
        if (tcfg & HPET_TN_PER_INT_CAP) == 0 {
            return -3;
        }

        let ticks = nanos_to_ticks(interval_ns, clk_period);
        if ticks == 0 {
            return -4;
        }

        // Determine interrupt route
        let route_cap = (tcfg >> 32) as u32;
        let route: u64 = if route_cap != 0 {
            let bit = route_cap.trailing_zeros();
            (bit as u64) << 9
        } else {
            0
        };

        // Configure: periodic, edge-triggered, interrupt enabled, set accumulator
        let new_cfg = (tcfg & !(HPET_TN_INT_TYPE_LEVEL
                                | HPET_TN_32MODE
                                | HPET_TN_FSB_EN
                                | (0x1F << 9)))
                     | HPET_TN_INT_ENB
                     | HPET_TN_TYPE_PERIODIC
                     | HPET_TN_VAL_SET
                     | route;

        mmio_write64(base, timer_cfg_offset(timer), new_cfg);

        // Per IA-PC HPET Spec section 2.3.9.2.2:
        // For periodic mode, the first write to the comparator with
        // Tn_VAL_SET_CNF=1 sets the accumulator (initial fire time).
        // The second write sets the period.
        let current = mmio_read64(base, HPET_REG_COUNTER);
        let initial_target = current.wrapping_add(ticks);
        mmio_write64(base, timer_cmp_offset(timer), initial_target);

        // Second write sets the period (hardware auto-clears VAL_SET)
        mmio_write64(base, timer_cmp_offset(timer), ticks);

        fence(Ordering::SeqCst);

        0
    }
}

/// Disable a specific timer by clearing its interrupt enable bit.
///
/// Returns 0 on success, negative on error:
///   -1 = driver not initialized
///   -2 = timer index out of range
#[unsafe(no_mangle)]
pub extern "C" fn hpet_timer_disable(timer: u32) -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized {
            return -1;
        }
        if timer >= (*state).num_timers {
            return -2;
        }

        let base = (*state).base;
        let tcfg = mmio_read64(base, timer_cfg_offset(timer));
        mmio_write64(base, timer_cfg_offset(timer),
            tcfg & !(HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC));

        // Clear pending interrupt for this timer
        mmio_write64(base, HPET_REG_INT_STS, 1u64 << timer);

        fence(Ordering::SeqCst);
        0
    }
}

/// Enable the HPET main counter.
///
/// Returns 0 on success, -1 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_enable() -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { return -1; }
        hpet_start_counter((*state).base);
        0
    }
}

/// Disable (halt) the HPET main counter.
///
/// Returns 0 on success, -1 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_disable() -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { return -1; }
        hpet_halt_counter((*state).base);
        0
    }
}

/// Get the clock period in femtoseconds.
///
/// Returns 0 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_clock_period_fs() -> u32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).clk_period_fs }
    }
}

/// Check whether the HPET main counter is 64-bit.
///
/// Returns 1 if 64-bit, 0 if 32-bit or not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn hpet_is_64bit() -> i32 {
    let state = HPET.get();
    unsafe {
        if !(*state).initialized { 0 } else { (*state).counter_64bit as i32 }
    }
}

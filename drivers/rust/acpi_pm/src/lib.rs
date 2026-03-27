// SPDX-License-Identifier: MPL-2.0
//
// ACPI Power Management Driver for Futura OS (x86-64)
//
// Implements ACPI PM1, PM Timer, GPE, and sleep-state control via
// standard x86 I/O ports as described in the ACPI specification.
//
// Architecture:
//   - PM1 Status/Enable registers at PM1a_EVT_BLK (I/O port, 16-bit)
//   - PM1 Control register at PM1a_CNT_BLK (I/O port, 16-bit)
//   - PM Timer at PM_TMR_BLK (I/O port, 32-bit, 3.579545 MHz)
//   - GPE0 Status/Enable at GPE0_BLK (I/O port, byte-addressable)
//   - Sleep state entry via SLP_TYP + SLP_EN in PM1_CNT
//
// Register map (offsets from respective base ports):
//   PM1a_EVT_BLK + 0x00  PM1_STS   (16-bit, R/WC)
//   PM1a_EVT_BLK + 0x02  PM1_EN    (16-bit, RW)
//   PM1a_CNT_BLK + 0x00  PM1_CNT   (16-bit, RW)
//   PM_TMR_BLK   + 0x00  PM_TMR    (32-bit, RO)
//   GPE0_BLK     + 0x00  GPE0_STS  (variable width, R/WC)
//   GPE0_BLK     + N/2   GPE0_EN   (variable width, RW)
//
// PM1_STS bits:
//   Bit  8  = PWRBTN_STS  (power button pressed)
//   Bit 10  = RTC_STS     (RTC alarm)
//   Bit 15  = WAK_STS     (wake event)
//
// PM1_EN bits:
//   Bit  8  = PWRBTN_EN   (power button event enable)
//   Bit 10  = RTC_EN      (RTC alarm enable)
//
// PM1_CNT bits:
//   Bit  0      = SCI_EN    (SCI interrupt enable)
//   Bits [12:10] = SLP_TYP  (sleep type, platform-specific)
//   Bit  13     = SLP_EN    (triggers sleep state transition)
//
// PM Timer:
//   3.579545 MHz free-running counter (24 or 32 bits).
//   ~279.365 ns per tick.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::sync::atomic::{fence, Ordering};

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── StaticCell wrapper (avoids `static mut`) ──

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

// ── PM1 Status Register bits (PM1_STS, 16-bit at PM1a_EVT_BLK + 0x00) ──

/// Timer carry status — PM timer overflowed.
const PM1_STS_TMR: u16 = 1 << 0;

/// Bus master status.
const _PM1_STS_BM: u16 = 1 << 4;

/// Global lock status.
const _PM1_STS_GBL: u16 = 1 << 5;

/// Power button pressed.
const PM1_STS_PWRBTN: u16 = 1 << 8;

/// Sleep button pressed.
const _PM1_STS_SLPBTN: u16 = 1 << 9;

/// RTC alarm status.
const PM1_STS_RTC: u16 = 1 << 10;

/// Processor event (PCIEXP_WAKE on newer ACPI).
const _PM1_STS_PCIEXP_WAKE: u16 = 1 << 14;

/// Wake status — a wake event occurred.
const PM1_STS_WAK: u16 = 1 << 15;

// ── PM1 Enable Register bits (PM1_EN, 16-bit at PM1a_EVT_BLK + 0x02) ──

/// Timer carry enable.
const _PM1_EN_TMR: u16 = 1 << 0;

/// Global lock enable.
const _PM1_EN_GBL: u16 = 1 << 5;

/// Power button enable.
const PM1_EN_PWRBTN: u16 = 1 << 8;

/// Sleep button enable.
const _PM1_EN_SLPBTN: u16 = 1 << 9;

/// RTC alarm enable.
const _PM1_EN_RTC: u16 = 1 << 10;

// ── PM1 Control Register bits (PM1_CNT, 16-bit at PM1a_CNT_BLK) ──

/// SCI interrupt enable.
const PM1_CNT_SCI_EN: u16 = 1 << 0;

/// Bus master reload.
const _PM1_CNT_BM_RLD: u16 = 1 << 1;

/// Global lock release.
const _PM1_CNT_GBL_RLS: u16 = 1 << 2;

/// Sleep type field mask (bits [12:10]).
const PM1_CNT_SLP_TYP_MASK: u16 = 0x07 << 10;

/// Sleep type field shift.
const PM1_CNT_SLP_TYP_SHIFT: u16 = 10;

/// Sleep enable — writing 1 triggers the sleep transition.
const PM1_CNT_SLP_EN: u16 = 1 << 13;

// ── PM Timer ──

/// PM Timer frequency: 3.579545 MHz (ACPI spec mandated).
const PM_TMR_FREQUENCY: u32 = 3_579_545;

/// 24-bit timer mask (for 24-bit PM timers).
const PM_TMR_24BIT_MASK: u32 = 0x00FF_FFFF;

/// Nanoseconds per PM timer tick: 10^9 / 3579545 ~ 279.365 ns.
/// For precise conversion we use: ns = ticks * 1_000_000_000 / 3_579_545.

// ── Sleep type values ──

/// S5 (soft-off) sleep type value.
/// Platform-specific; common values are 5 or 7. Configurable at init.
const DEFAULT_S5_SLP_TYP: u8 = 5;

// ── GPE register layout ──

/// GPE0 enable register offset from GPE0_BLK base.
/// Per ACPI spec, GPE0_EN starts at GPE0_BLK + GPE0_BLK_LEN/2.
/// We default to 0x20 (for a 64-byte GPE0 block, common on AMD).
const GPE0_EN_OFFSET: u16 = 0x20;

// ── Driver state ──

struct AcpiPmState {
    /// I/O port base for PM1 event registers (PM1_STS, PM1_EN).
    pm1a_evt_blk: u16,
    /// I/O port for PM1 control register.
    pm1a_cnt_blk: u16,
    /// I/O port for PM timer.
    pm_tmr_blk: u16,
    /// I/O port base for GPE0 registers.
    gpe0_blk: u16,
    /// S5 sleep type value (platform-specific).
    s5_slp_typ: u8,
    /// Timer value latched at init (epoch for elapsed calculations).
    timer_at_init: u32,
    /// Whether the PM timer is 32-bit (vs 24-bit).
    timer_32bit: bool,
    /// Whether the driver has been initialized.
    initialized: bool,
}

impl AcpiPmState {
    const fn new() -> Self {
        Self {
            pm1a_evt_blk: 0,
            pm1a_cnt_blk: 0,
            pm_tmr_blk: 0,
            gpe0_blk: 0,
            s5_slp_typ: DEFAULT_S5_SLP_TYP,
            timer_at_init: 0,
            timer_32bit: false,
            initialized: false,
        }
    }
}

static STATE: StaticCell<AcpiPmState> = StaticCell::new(AcpiPmState::new());

// ── x86 I/O port helpers ──

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

fn io_outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val);
    }
}

fn io_inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") val);
    }
    val
}

fn io_ind(port: u16) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") val);
    }
    val
}

fn io_outd(port: u16, val: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val);
    }
}

// ── Internal register access helpers ──

/// Read PM1 Status register (16-bit at PM1a_EVT_BLK + 0x00).
#[inline]
fn pm1_sts_read(base: u16) -> u16 {
    io_inw(base)
}

/// Write PM1 Status register (write-1-to-clear semantics).
#[inline]
fn pm1_sts_write(base: u16, val: u16) {
    io_outw(base, val);
}

/// Read PM1 Enable register (16-bit at PM1a_EVT_BLK + 0x02).
#[inline]
fn pm1_en_read(base: u16) -> u16 {
    io_inw(base + 2)
}

/// Write PM1 Enable register.
#[inline]
fn pm1_en_write(base: u16, val: u16) {
    io_outw(base + 2, val);
}

/// Read PM1 Control register (16-bit at PM1a_CNT_BLK).
#[inline]
fn pm1_cnt_read(port: u16) -> u16 {
    io_inw(port)
}

/// Write PM1 Control register.
#[inline]
fn pm1_cnt_write(port: u16, val: u16) {
    io_outw(port, val);
}

/// Read PM Timer (32-bit at PM_TMR_BLK).
#[inline]
fn pm_tmr_read(port: u16) -> u32 {
    io_ind(port)
}

/// Read a GPE0 status byte at offset from GPE0_BLK.
#[inline]
fn gpe0_sts_read(base: u16, byte_offset: u16) -> u8 {
    io_inb(base + byte_offset)
}

/// Write a GPE0 status byte (write-1-to-clear).
#[inline]
fn gpe0_sts_write(base: u16, byte_offset: u16, val: u8) {
    io_outb(base + byte_offset, val);
}

/// Read a GPE0 enable byte at offset from GPE0_BLK.
#[inline]
fn gpe0_en_read(base: u16, byte_offset: u16) -> u8 {
    io_inb(base + GPE0_EN_OFFSET + byte_offset)
}

/// Write a GPE0 enable byte.
#[inline]
fn gpe0_en_write(base: u16, byte_offset: u16, val: u8) {
    io_outb(base + GPE0_EN_OFFSET + byte_offset, val);
}

// ── Tick-to-nanosecond conversion ──

/// Convert PM timer ticks to nanoseconds.
/// ns = ticks * 1_000_000_000 / 3_579_545
/// Uses 64-bit arithmetic to avoid overflow for up to ~2^32 ticks.
#[inline]
fn ticks_to_nanos(ticks: u32) -> u64 {
    let product = (ticks as u64) * 1_000_000_000u64;
    product / (PM_TMR_FREQUENCY as u64)
}

/// Compute elapsed ticks between two timer readings, handling wraparound.
/// `mask` should be PM_TMR_24BIT_MASK or 0xFFFF_FFFF for 32-bit timers.
#[inline]
fn elapsed_ticks(start: u32, now: u32, mask: u32) -> u32 {
    now.wrapping_sub(start) & mask
}

// ── FFI exports ──

/// Initialize the ACPI Power Management driver.
///
/// Parameters (I/O port bases from ACPI FADT):
///   `pm1a_evt`: PM1a Event Block base (PM1_STS at +0, PM1_EN at +2)
///   `pm1a_cnt`: PM1a Control Block base
///   `pm_tmr`:   PM Timer Block base
///   `gpe0`:     GPE0 Block base (0 to disable GPE support)
///
/// Returns 0 on success, negative on error:
///   -1 = invalid port configuration (pm1a_evt or pm1a_cnt is 0)
///   -2 = PM timer not responding
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_init(pm1a_evt: u16, pm1a_cnt: u16, pm_tmr: u16, gpe0: u16) -> i32 {
    log("acpi_pm: initializing ACPI power management");

    if pm1a_evt == 0 || pm1a_cnt == 0 {
        log("acpi_pm: invalid PM1 port configuration");
        return -1;
    }

    // Read the PM timer to verify it is responding.
    let tmr0 = if pm_tmr != 0 {
        let t = pm_tmr_read(pm_tmr);
        // Read twice with a small gap to check the timer is ticking.
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
        let t2 = pm_tmr_read(pm_tmr);
        if t == t2 {
            // Timer might be stuck or not present; warn but do not fail
            // since some reads may alias on fast CPUs.
            log("acpi_pm: WARNING — PM timer may not be ticking");
        }
        t
    } else {
        0
    };

    // Detect whether the PM timer is 32-bit.
    // A 24-bit timer will have bits [31:24] read as zero.
    // We read several times to see if any upper bits are set.
    let mut timer_32bit = false;
    if pm_tmr != 0 {
        for _ in 0..16u32 {
            let t = pm_tmr_read(pm_tmr);
            if t & !PM_TMR_24BIT_MASK != 0 {
                timer_32bit = true;
                break;
            }
            // Spin briefly to let the counter advance.
            for _ in 0..1000u32 {
                core::hint::spin_loop();
            }
        }
    }

    // Read and log current PM1 status.
    let sts = pm1_sts_read(pm1a_evt);
    let cnt = pm1_cnt_read(pm1a_cnt);
    let sci_en = (cnt & PM1_CNT_SCI_EN) != 0;

    unsafe {
        fut_printf(
            b"acpi_pm: PM1a_EVT=0x%04x PM1a_CNT=0x%04x PM_TMR=0x%04x GPE0=0x%04x\n\0".as_ptr(),
            pm1a_evt as u32,
            pm1a_cnt as u32,
            pm_tmr as u32,
            gpe0 as u32,
        );
        fut_printf(
            b"acpi_pm: PM1_STS=0x%04x PM1_CNT=0x%04x SCI_EN=%u timer=%s\n\0".as_ptr(),
            sts as u32,
            cnt as u32,
            sci_en as u32,
            if timer_32bit {
                b"32-bit\0".as_ptr()
            } else {
                b"24-bit\0".as_ptr()
            },
        );
    }

    if pm_tmr != 0 {
        unsafe {
            fut_printf(
                b"acpi_pm: PM timer frequency %u Hz (~279 ns/tick)\n\0".as_ptr(),
                PM_TMR_FREQUENCY,
            );
        }
    }

    // Clear any pending status bits by writing 1s to the write-1-to-clear register.
    pm1_sts_write(pm1a_evt, sts);

    // Store driver state.
    let state = STATE.get();
    unsafe {
        (*state).pm1a_evt_blk = pm1a_evt;
        (*state).pm1a_cnt_blk = pm1a_cnt;
        (*state).pm_tmr_blk = pm_tmr;
        (*state).gpe0_blk = gpe0;
        (*state).s5_slp_typ = DEFAULT_S5_SLP_TYP;
        (*state).timer_at_init = tmr0;
        (*state).timer_32bit = timer_32bit;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    log("acpi_pm: driver initialized");
    0
}

/// Read the raw PM timer value.
///
/// Returns the current 24- or 32-bit counter value, or 0 if not initialized
/// or the PM timer port was not configured.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_read_timer() -> u32 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized || (*state).pm_tmr_blk == 0 {
            return 0;
        }
        pm_tmr_read((*state).pm_tmr_blk)
    }
}

/// Get the number of nanoseconds elapsed since driver initialization,
/// as measured by the PM timer.
///
/// The PM timer runs at exactly 3.579545 MHz. This function handles
/// 24-bit and 32-bit timer wraparound correctly for a single wrap
/// (up to ~4.69 seconds for 24-bit, ~1199 seconds for 32-bit).
///
/// Returns 0 if not initialized or PM timer is not configured.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_timer_ns() -> u64 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized || (*state).pm_tmr_blk == 0 {
            return 0;
        }
        let now = pm_tmr_read((*state).pm_tmr_blk);
        let mask = if (*state).timer_32bit {
            0xFFFF_FFFFu32
        } else {
            PM_TMR_24BIT_MASK
        };
        let ticks = elapsed_ticks((*state).timer_at_init, now, mask);
        ticks_to_nanos(ticks)
    }
}

/// Attempt to enter S5 (soft-off / shutdown) sleep state.
///
/// Writes SLP_TYP for S5 and sets SLP_EN in the PM1 control register.
/// This function should not return on success; the system powers off.
///
/// Returns 0 if not initialized, -1 if the shutdown sequence failed
/// (i.e., we returned from the sleep attempt).
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_shutdown() -> i32 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return 0;
        }

        let cnt_port = (*state).pm1a_cnt_blk;
        let slp_typ = (*state).s5_slp_typ;

        log("acpi_pm: entering S5 (soft-off) sleep state");

        // Read current PM1_CNT, preserve reserved bits but clear SLP_TYP and SLP_EN.
        let cnt = pm1_cnt_read(cnt_port);
        let new_cnt = (cnt & !PM1_CNT_SLP_TYP_MASK & !PM1_CNT_SLP_EN)
            | ((slp_typ as u16) << PM1_CNT_SLP_TYP_SHIFT);

        // First write: set SLP_TYP without SLP_EN.
        pm1_cnt_write(cnt_port, new_cnt);
        fence(Ordering::SeqCst);

        // Second write: set SLP_EN to trigger the transition.
        pm1_cnt_write(cnt_port, new_cnt | PM1_CNT_SLP_EN);
        fence(Ordering::SeqCst);

        // If we reach here, the shutdown did not take effect.
        // Spin briefly in case of delay.
        for _ in 0..1_000_000u32 {
            core::hint::spin_loop();
        }

        log("acpi_pm: WARNING — S5 shutdown did not take effect");
        -1
    }
}

/// Check whether the power button has been pressed.
///
/// Reads the PWRBTN_STS bit in PM1_STS. Does NOT clear the status bit;
/// call `acpi_pm_clear_power_button()` to acknowledge.
///
/// Returns `true` if the power button status bit is set.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_power_button_pressed() -> bool {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return false;
        }
        let sts = pm1_sts_read((*state).pm1a_evt_blk);
        (sts & PM1_STS_PWRBTN) != 0
    }
}

/// Clear (acknowledge) the power button status.
///
/// Writes 1 to the PWRBTN_STS bit in PM1_STS (write-1-to-clear).
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_clear_power_button() {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return;
        }
        pm1_sts_write((*state).pm1a_evt_blk, PM1_STS_PWRBTN);
    }
}

/// Enable power button events.
///
/// Sets the PWRBTN_EN bit in PM1_EN so that a power button press
/// generates an SCI (if SCI_EN is set in PM1_CNT).
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_enable_power_button() {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized {
            return;
        }
        let en = pm1_en_read((*state).pm1a_evt_blk);
        pm1_en_write((*state).pm1a_evt_blk, en | PM1_EN_PWRBTN);
    }
}

/// Read GPE0 status for a given 8-bit block.
///
/// `block` selects the byte offset into the GPE0_STS register space.
/// Block 0 covers GPE bits 0-7, block 1 covers 8-15, etc.
///
/// Returns the 8-bit status value for the requested block,
/// promoted to u32 for C ABI convenience. Returns 0 if not initialized
/// or GPE0 is not configured.
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_gpe_status(block: u32) -> u32 {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized || (*state).gpe0_blk == 0 {
            return 0;
        }
        gpe0_sts_read((*state).gpe0_blk, block as u16) as u32
    }
}

/// Clear a specific GPE0 status bit.
///
/// `block` selects the byte offset (same as `acpi_pm_gpe_status`).
/// `bit` is the bit position within that byte (0-7).
///
/// Writes 1 to the specified bit in GPE0_STS (write-1-to-clear).
#[unsafe(no_mangle)]
pub extern "C" fn acpi_pm_gpe_clear(block: u32, bit: u8) {
    let state = STATE.get();
    unsafe {
        if !(*state).initialized || (*state).gpe0_blk == 0 {
            return;
        }
        if bit > 7 {
            return;
        }
        gpe0_sts_write((*state).gpe0_blk, block as u16, 1u8 << bit);
    }
}

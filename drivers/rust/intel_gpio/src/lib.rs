// SPDX-License-Identifier: MPL-2.0
//
// Intel PCH GPIO Controller Driver for Futura OS
//
// Implements the Intel Platform Controller Hub (PCH) GPIO controller found on
// Gen 10+ (Cannon Lake / Comet Lake / Tiger Lake / Alder Lake / Raptor Lake)
// platforms.
//
// Architecture:
//   - GPIO pads are memory-mapped via the PCH Sideband Register BAR (SBREG_BAR)
//   - P2SB bridge at PCI 00:1F.1 exposes SBREG_BAR in BAR0
//   - Each GPIO community (COM0-COM5) has its own offset from SBREG_BAR
//   - Within a community, each pad has a 16-byte register block
//
// Pad register layout (16 bytes per pad):
//   +0x00: PAD_CFG_DW0 (Pad Configuration DWord 0)
//     bit  0      - GPIOTXSTATE (output value)
//     bit  1      - GPIORXSTATE (input value, read-only)
//     bit  4      - GPIOTXDIS (TX disable = input-only mode)
//     bit  5      - GPIORXDIS (RX disable)
//     bits [9:8]  - PMODE (pad mode: 0=GPIO, 1-3=native function)
//     bit  10     - GPIROUTNMI
//     bit  11     - GPIROUTSMI
//     bit  12     - GPIROUTSCI
//     bit  13     - GPIROUTAPIC (route to IOAPIC)
//     bits [17:14]- RXEVCFG (RX event: 00=level, 01=edge, 10=disabled)
//     bit  18     - RXINV (invert RX)
//     bits [22:20]- INTSEL (interrupt select/vector)
//     bit  23     - PREGFRXSEL
//     bit  24     - RXRAW1
//     bit  25     - RXPADSTSEL
//     bits [27:26]- PADRSTCFG (pad reset config)
//
//   +0x04: PAD_CFG_DW1 (Pad Configuration DWord 1)
//     bits [3:0]  - INTSEL (interrupt line select)
//     bits [13:10]- TERM (termination: pull-up/down configuration)
//     bits [19:16]- IOSTATE (I/O standby state)
//     bits [23:20]- IOSTERM (I/O standby termination)
//
// References:
//   - Intel PCH EDS (External Design Specification) for CNL/CML/TGL/ADL/RPL
//   - coreboot src/soc/intel/common/block/gpio/gpio.c
//   - Linux drivers/pinctrl/intel/pinctrl-intel.c

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
// PAD_CFG_DW0 bit definitions
// ---------------------------------------------------------------------------

/// Output value (bit 0). When pad is in output mode, drives the pin.
const DW0_GPIOTXSTATE: u32 = 1 << 0;

/// Input value (bit 1, read-only). Reflects current pad state.
const DW0_GPIORXSTATE: u32 = 1 << 1;

/// TX disable (bit 4). When set, pad is input-only (TX buffer disabled).
const DW0_GPIOTXDIS: u32 = 1 << 4;

/// RX disable (bit 5). When set, RX buffer is disabled.
const DW0_GPIORXDIS: u32 = 1 << 5;

/// Pad mode field -- bits [9:8]. 0 = GPIO, 1-3 = native function.
const DW0_PMODE_MASK: u32 = 0x3 << 8;
const DW0_PMODE_SHIFT: u32 = 8;

/// GPI route to NMI (bit 10).
const DW0_GPIROUTNMI: u32 = 1 << 10;

/// GPI route to SMI (bit 11).
const DW0_GPIROUTSMI: u32 = 1 << 11;

/// GPI route to SCI (bit 12).
const DW0_GPIROUTSCI: u32 = 1 << 12;

/// GPI route to IOAPIC (bit 13).
const DW0_GPIROUTAPIC: u32 = 1 << 13;

/// Mask for all interrupt routing bits.
const DW0_ROUTE_MASK: u32 =
    DW0_GPIROUTNMI | DW0_GPIROUTSMI | DW0_GPIROUTSCI | DW0_GPIROUTAPIC;

/// RX event configuration -- bits [17:14].
/// 00 = level, 01 = edge, 10 = disabled, 11 = reserved.
const DW0_RXEVCFG_MASK: u32 = 0xF << 14;
const DW0_RXEVCFG_SHIFT: u32 = 14;
const DW0_RXEVCFG_LEVEL: u32 = 0x0 << 14;
const DW0_RXEVCFG_EDGE: u32 = 0x1 << 14;
const DW0_RXEVCFG_DISABLED: u32 = 0x2 << 14;

/// RX invert (bit 18).
const DW0_RXINV: u32 = 1 << 18;

/// Pad reset configuration -- bits [27:26].
const DW0_PADRSTCFG_MASK: u32 = 0x3 << 26;

// ---------------------------------------------------------------------------
// PAD_CFG_DW1 bit definitions
// ---------------------------------------------------------------------------

/// Interrupt line select -- bits [3:0].
const DW1_INTSEL_MASK: u32 = 0xF;

/// Termination field -- bits [13:10].
/// Encoding (Intel PCH Gen 10+):
///   0000 = none
///   0010 = 5k pull-down
///   0100 = 20k pull-down
///   1001 = 1k pull-up (native only)
///   1010 = 5k pull-up
///   1011 = 2k pull-up (native only)
///   1100 = 20k pull-up
///   1101 = 667 ohm pull-up (native only)
///   1111 = native function default
const DW1_TERM_MASK: u32 = 0xF << 10;
const DW1_TERM_SHIFT: u32 = 10;

/// Termination encodings.
const TERM_NONE: u32 = 0x0;
const TERM_20K_PU: u32 = 0xC;
const TERM_5K_PU: u32 = 0xA;
const TERM_20K_PD: u32 = 0x4;

// ---------------------------------------------------------------------------
// Pad register layout
// ---------------------------------------------------------------------------

/// Each pad occupies 16 bytes in the MMIO space.
const PAD_REG_STRIDE: usize = 16;

/// Offset of PAD_CFG_DW0 within the per-pad register block.
const PAD_CFG_DW0_OFF: usize = 0x00;

/// Offset of PAD_CFG_DW1 within the per-pad register block.
const PAD_CFG_DW1_OFF: usize = 0x04;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct IntelGpioState {
    /// Virtual address of the GPIO community MMIO region.
    base: usize,
    /// Number of pads in this community.
    num_pads: u32,
    /// Whether the driver has been initialised.
    inited: bool,
}

impl IntelGpioState {
    const fn new() -> Self {
        Self {
            base: 0,
            num_pads: 0,
            inited: false,
        }
    }
}

static STATE: StaticCell<IntelGpioState> = StaticCell::new(IntelGpioState::new());

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Compute the virtual address of a pad register.
#[inline]
fn pad_addr(base: usize, pad: u32, dw_offset: usize) -> usize {
    base + (pad as usize) * PAD_REG_STRIDE + dw_offset
}

/// Read PAD_CFG_DW0 for the given pad.
#[inline]
fn pad_read_dw0(base: usize, pad: u32) -> u32 {
    unsafe { read_volatile(pad_addr(base, pad, PAD_CFG_DW0_OFF) as *const u32) }
}

/// Write PAD_CFG_DW0 for the given pad.
#[inline]
fn pad_write_dw0(base: usize, pad: u32, val: u32) {
    unsafe { write_volatile(pad_addr(base, pad, PAD_CFG_DW0_OFF) as *mut u32, val) }
}

/// Read PAD_CFG_DW1 for the given pad.
#[inline]
fn pad_read_dw1(base: usize, pad: u32) -> u32 {
    unsafe { read_volatile(pad_addr(base, pad, PAD_CFG_DW1_OFF) as *const u32) }
}

/// Write PAD_CFG_DW1 for the given pad.
#[inline]
fn pad_write_dw1(base: usize, pad: u32, val: u32) {
    unsafe { write_volatile(pad_addr(base, pad, PAD_CFG_DW1_OFF) as *mut u32, val) }
}

/// Read-modify-write on DW0: clear `clear_bits`, then set `set_bits`.
#[inline]
fn pad_rmw_dw0(base: usize, pad: u32, clear_bits: u32, set_bits: u32) {
    let old = pad_read_dw0(base, pad);
    let new = (old & !clear_bits) | set_bits;
    pad_write_dw0(base, pad, new);
}

/// Read-modify-write on DW1: clear `clear_bits`, then set `set_bits`.
#[inline]
fn pad_rmw_dw1(base: usize, pad: u32, clear_bits: u32, set_bits: u32) {
    let old = pad_read_dw1(base, pad);
    let new = (old & !clear_bits) | set_bits;
    pad_write_dw1(base, pad, new);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return (base, num_pads) if the driver is initialised, or None.
fn with_state() -> Option<(usize, u32)> {
    let st = unsafe { &*STATE.get() };
    if st.inited && st.base != 0 {
        Some((st.base, st.num_pads))
    } else {
        None
    }
}

/// Validate that `pad` is within the configured range.
#[inline]
fn valid_pad(pad: u32, num_pads: u32) -> bool {
    pad < num_pads
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialise the Intel PCH GPIO controller for a single community.
///
/// `base`: physical address of the GPIO community pad configuration region.
///     This is typically SBREG_BAR + community_offset + pad_cfg_base.
///     The caller (kernel / ACPI) is responsible for discovering this address.
/// `num_pads`: number of pads in this community.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_init(base: u64, num_pads: u32) -> i32 {
    log("intel_gpio: initialising Intel PCH GPIO controller...");

    if base == 0 || num_pads == 0 {
        log("intel_gpio: invalid base address or pad count");
        return -22; // EINVAL
    }

    unsafe {
        fut_printf(
            b"intel_gpio: community phys base = 0x%08llx, pads = %u\n\0".as_ptr(),
            base,
            num_pads,
        );
    }

    // Map the pad configuration MMIO region.
    // Each pad has 16 bytes, so total size = num_pads * 16.
    let mmio_size = (num_pads as usize) * PAD_REG_STRIDE;

    let vaddr = unsafe { map_mmio_region(base, mmio_size, MMIO_DEFAULT_FLAGS) };
    if vaddr.is_null() {
        log("intel_gpio: failed to map GPIO MMIO region");
        return -12; // ENOMEM
    }

    let mapped_base = vaddr as usize;

    unsafe {
        fut_printf(
            b"intel_gpio: mapped at vaddr 0x%p (%u pads, %u bytes)\n\0".as_ptr(),
            vaddr,
            num_pads,
            mmio_size as u32,
        );
    }

    // Sanity-check: read DW0 of pad 0 to confirm MMIO is accessible.
    let probe = pad_read_dw0(mapped_base, 0);
    if probe == 0xFFFF_FFFF {
        log("intel_gpio: WARNING: pad 0 DW0 reads 0xFFFFFFFF (bus float / no decode)");
        // Continue anyway -- could be a valid state if all bits happen to be set,
        // but more likely indicates a mapping issue. The caller should verify.
    }

    unsafe {
        fut_printf(
            b"intel_gpio: pad 0 DW0 = 0x%08x, DW1 = 0x%08x\n\0".as_ptr(),
            probe,
            pad_read_dw1(mapped_base, 0),
        );
    }

    // Store state.
    let st = unsafe { &mut *STATE.get() };
    st.base = mapped_base;
    st.num_pads = num_pads;
    st.inited = true;

    fence(Ordering::SeqCst);

    unsafe {
        fut_printf(
            b"intel_gpio: controller ready (%u pads)\n\0".as_ptr(),
            num_pads,
        );
    }

    0
}

/// Set the direction of a GPIO pad.
///
/// `pad`: pad number within the community.
/// `output`: true = output mode (GPIOTXDIS cleared), false = input mode (GPIOTXDIS set).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_set_direction(pad: u32, output: bool) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) {
        return -22; // EINVAL
    }

    if output {
        // Output mode: clear GPIOTXDIS, set GPIORXDIS (typical output-only config).
        // Caller can enable RX separately if bidirectional sensing is needed.
        pad_rmw_dw0(base, pad, DW0_GPIOTXDIS, 0);
    } else {
        // Input mode: set GPIOTXDIS to disable the output buffer.
        pad_rmw_dw0(base, pad, 0, DW0_GPIOTXDIS);
    }

    0
}

/// Set the output value of a GPIO pad.
///
/// `pad`: pad number within the community.
/// `high`: true = drive high, false = drive low.
///
/// Returns 0 on success, negative error code on failure.
/// The pad must be configured as output (GPIOTXDIS cleared) for this to take effect.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_set_value(pad: u32, high: bool) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) {
        return -22; // EINVAL
    }

    if high {
        pad_rmw_dw0(base, pad, 0, DW0_GPIOTXSTATE);
    } else {
        pad_rmw_dw0(base, pad, DW0_GPIOTXSTATE, 0);
    }

    0
}

/// Read the current input value of a GPIO pad.
///
/// Returns 0 (low), 1 (high), or negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_get_value(pad: u32) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) {
        return -22; // EINVAL
    }

    let dw0 = pad_read_dw0(base, pad);
    if dw0 & DW0_GPIORXSTATE != 0 { 1 } else { 0 }
}

/// Set the pad mode (GPIO vs native function).
///
/// `pad`: pad number within the community.
/// `mode`: 0 = GPIO mode, 1-3 = native function 1-3.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_set_mode(pad: u32, mode: u32) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) || mode > 3 {
        return -22; // EINVAL
    }

    let mode_bits = (mode & 0x3) << DW0_PMODE_SHIFT;
    pad_rmw_dw0(base, pad, DW0_PMODE_MASK, mode_bits);

    0
}

/// Configure the pull-up/pull-down termination for a GPIO pad.
///
/// `pad`: pad number within the community.
/// `pull`: termination configuration:
///     0 = none (high-Z)
///     1 = 20k ohm pull-up
///     2 = 5k ohm pull-up
///     3 = 20k ohm pull-down
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_set_pull(pad: u32, pull: u32) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) {
        return -22; // EINVAL
    }

    let term = match pull {
        0 => TERM_NONE,     // No pull
        1 => TERM_20K_PU,   // 20k pull-up
        2 => TERM_5K_PU,    // 5k pull-up
        3 => TERM_20K_PD,   // 20k pull-down
        _ => return -22,    // EINVAL
    };

    let term_bits = (term & 0xF) << DW1_TERM_SHIFT;
    pad_rmw_dw1(base, pad, DW1_TERM_MASK, term_bits);

    0
}

/// Configure interrupt routing for a GPIO pad.
///
/// `pad`: pad number within the community.
/// `route`: interrupt routing target bitmask:
///     bit 0 = NMI
///     bit 1 = SMI
///     bit 2 = SCI
///     bit 3 = IOAPIC
///   Only one routing bit should be set at a time (hardware constraint).
/// `edge`: true = edge-triggered, false = level-triggered.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_configure_interrupt(pad: u32, route: u32, edge: bool) -> i32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return -19, // ENODEV
    };
    if !valid_pad(pad, num_pads) || route > 0xF {
        return -22; // EINVAL
    }

    // Build the routing bits from the route bitmask.
    let mut route_bits: u32 = 0;
    if route & 0x1 != 0 {
        route_bits |= DW0_GPIROUTNMI;
    }
    if route & 0x2 != 0 {
        route_bits |= DW0_GPIROUTSMI;
    }
    if route & 0x4 != 0 {
        route_bits |= DW0_GPIROUTSCI;
    }
    if route & 0x8 != 0 {
        route_bits |= DW0_GPIROUTAPIC;
    }

    // Set RX event configuration: edge or level.
    let rxevcfg_bits = if edge { DW0_RXEVCFG_EDGE } else { DW0_RXEVCFG_LEVEL };

    // Clear all routing and event config bits, then set the new values.
    let clear_mask = DW0_ROUTE_MASK | DW0_RXEVCFG_MASK;
    let set_mask = route_bits | rxevcfg_bits;

    pad_rmw_dw0(base, pad, clear_mask, set_mask);

    0
}

/// Return the number of pads in the current community.
///
/// Returns 0 if the driver has not been initialised.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_pad_count() -> u32 {
    match with_state() {
        Some((_, num_pads)) => num_pads,
        None => 0,
    }
}

/// Read the raw PAD_CFG_DW0 register for a pad (for diagnostics).
///
/// Returns the register value, or 0xFFFF_FFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_read_dw0(pad: u32) -> u32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return 0xFFFF_FFFF,
    };
    if !valid_pad(pad, num_pads) {
        return 0xFFFF_FFFF;
    }

    pad_read_dw0(base, pad)
}

/// Read the raw PAD_CFG_DW1 register for a pad (for diagnostics).
///
/// Returns the register value, or 0xFFFF_FFFF on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_gpio_read_dw1(pad: u32) -> u32 {
    let (base, num_pads) = match with_state() {
        Some(s) => s,
        None => return 0xFFFF_FFFF,
    };
    if !valid_pad(pad, num_pads) {
        return 0xFFFF_FFFF;
    }

    pad_read_dw1(base, pad)
}

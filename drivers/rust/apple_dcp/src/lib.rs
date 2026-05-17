// SPDX-License-Identifier: MPL-2.0
//! Apple Display Co-Processor (DCP) state + protocol layer for Futura OS.
//!
//! What this crate owns
//! --------------------
//! * The surface table — IOVAs and dimensions for up to 4 swap-chain
//!   surfaces.  The backing pages themselves are allocated by the C
//!   wrapper (apple_dcp.c) and mapped through DART; this crate only
//!   stores the IOVAs it should send to the co-processor.
//! * The swap pending / complete state machine.
//! * Current mode, backlight, power tracking.
//! * Message builders for SWAP_START / BACKLIGHT / POWER and the
//!   receive-side dispatcher that updates state on SWAP_COMPLETE.
//!
//! What stays on the C wrapper
//! ---------------------------
//! Page allocation, DART map / unmap, RTKit context boot, endpoint
//! registration / start, and the actual `apple_rtkit_send_message`
//! call.  The wrapper consults this crate to build the right 64-bit
//! payload and to learn whether a swap is still in flight.
//!
//! Reference
//! ---------
//! Asahi Linux drivers/gpu/drm/apple/dcp.c and the DCP message
//! types catalogued in apple_dcp.h.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ptr::write_volatile;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Protocol constants (mirror APPLE_DCP_MSG_* in apple_dcp.h)
// ---------------------------------------------------------------------------

const DCP_MSG_SET_MODE:      u8 = 0x01;
const DCP_MSG_SWAP_START:    u8 = 0x02;
const DCP_MSG_SWAP_COMPLETE: u8 = 0x03;
const DCP_MSG_BACKLIGHT:     u8 = 0x04;
const DCP_MSG_POWER:         u8 = 0x05;

// Pixel format constants (mirror APPLE_DCP_FMT_*)
const FMT_BGRA8888: u32 = 0x00000001;
const FMT_RGBA8888: u32 = 0x00000002;
const FMT_RGB565:   u32 = 0x00000003;

// Power states
pub const PWR_OFF:     u8 = 0;
pub const PWR_ON:      u8 = 1;
pub const PWR_STANDBY: u8 = 2;

// ---------------------------------------------------------------------------
// Surface table — fixed-size, 4 entries (matches APPLE_DCP_MAX_SURFACES).
// ---------------------------------------------------------------------------

const MAX_SURFACES: usize = 4;

#[derive(Copy, Clone)]
struct Surface {
    iova:      u64,
    width:     u32,
    height:    u32,
    stride:    u32,
    format:    u32,
    allocated: bool,
}

impl Surface {
    const fn empty() -> Self {
        Self { iova: 0, width: 0, height: 0, stride: 0, format: 0, allocated: false }
    }
}

// ---------------------------------------------------------------------------
// Mode descriptor (mirrors apple_dcp_mode_t in C)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone)]
pub struct AppleDcpMode {
    pub width:        u32,
    pub height:       u32,
    pub refresh_rate: u32,
    pub pixel_format: u32,
    pub stride:       u32,
}

impl AppleDcpMode {
    const fn empty() -> Self {
        Self { width: 0, height: 0, refresh_rate: 0, pixel_format: 0, stride: 0 }
    }
}

// ---------------------------------------------------------------------------
// DCP controller — singleton (one display per AP on M1-class hardware).
// ---------------------------------------------------------------------------

pub struct AppleDcp {
    surfaces:        [Surface; MAX_SURFACES],
    num_surfaces:    u32,
    current_surface: u32,
    next_surface:    u32,

    mode_set: bool,
    mode:     AppleDcpMode,

    power_state: u8,
    backlight:   u8,

    swap_pending:  AtomicBool,
    swap_complete: AtomicBool,

    swaps_completed: AtomicU64,
    frames_dropped:  AtomicU64,
}

// SAFETY: the wrapper accesses this from a single thread (the apple_dcp.c
// callers) plus the rtkit handler thunk; atomics guard the swap-state
// fields the handler touches.
unsafe impl Send for AppleDcp {}
unsafe impl Sync for AppleDcp {}

static mut G_DCP: AppleDcp = AppleDcp {
    surfaces:        [Surface::empty(); MAX_SURFACES],
    num_surfaces:    0,
    current_surface: 0,
    next_surface:    0,
    mode_set:        false,
    mode:            AppleDcpMode::empty(),
    power_state:     PWR_OFF,
    backlight:       0,
    swap_pending:    AtomicBool::new(false),
    swap_complete:   AtomicBool::new(false),
    swaps_completed: AtomicU64::new(0),
    frames_dropped:  AtomicU64::new(0),
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bpp_for_format(format: u32) -> u32 {
    match format {
        FMT_RGB565 => 2,
        FMT_BGRA8888 | FMT_RGBA8888 => 4,
        _ => 4,
    }
}

/// Build the 64-bit RTKit payload that asks the co-processor to swap to
/// the given surface.  Layout matches the legacy C builder:
///   bits [ 7: 0] msg type     = DCP_MSG_SWAP_START
///   bits [15: 8] surface idx
///   bits [39:16] iova lo 24 bits
///   bits [63:40] iova hi 24 bits
fn build_swap_msg(surface_idx: u8, iova: u64) -> u64 {
    (DCP_MSG_SWAP_START as u64)
        | ((surface_idx as u64) << 8)
        | (((iova >> 0) & 0xFFFFFF) << 16)
        | (((iova >> 24) & 0xFFFFFF) << 40)
}

fn build_backlight_msg(level: u8) -> u64 {
    (DCP_MSG_BACKLIGHT as u64) | ((level as u64) << 8)
}

fn build_power_msg(state: u8) -> u64 {
    (DCP_MSG_POWER as u64) | ((state as u64) << 8)
}

// ===========================================================================
//   FFI surface
// ===========================================================================

/// Return the singleton DCP handle and reset its state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_new() -> *mut AppleDcp {
    let dcp = unsafe { &mut *(&raw mut G_DCP) };
    dcp.surfaces        = [Surface::empty(); MAX_SURFACES];
    dcp.num_surfaces    = 0;
    dcp.current_surface = 0;
    dcp.next_surface    = 0;
    dcp.mode_set        = false;
    dcp.mode            = AppleDcpMode::empty();
    dcp.power_state     = PWR_OFF;
    dcp.backlight       = 0;
    dcp.swap_pending.store(false, Ordering::Release);
    dcp.swap_complete.store(false, Ordering::Release);
    dcp.swaps_completed.store(0, Ordering::Release);
    dcp.frames_dropped.store(0, Ordering::Release);
    dcp as *mut AppleDcp
}

/// Register a DART-mapped surface in the table.  Returns the assigned
/// slot index, or -1 if all slots are taken.  Caller has already
/// allocated pages and mapped the IOVA through DART (or established an
/// identity mapping for non-DART builds).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_register_surface(
    dcp:    *mut AppleDcp,
    iova:   u64,
    width:  u32,
    height: u32,
    stride: u32,
    format: u32,
) -> i32 {
    if dcp.is_null() { return -1; }
    let d = unsafe { &mut *dcp };
    for i in 0..MAX_SURFACES {
        if !d.surfaces[i].allocated {
            d.surfaces[i] = Surface {
                iova, width, height, stride, format, allocated: true,
            };
            d.num_surfaces += 1;
            return i as i32;
        }
    }
    -1
}

/// Drop a surface from the table.  Caller is responsible for DART
/// unmap and page free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_unregister_surface(
    dcp: *mut AppleDcp,
    idx: i32,
) {
    if dcp.is_null() || idx < 0 || (idx as usize) >= MAX_SURFACES { return; }
    let d = unsafe { &mut *dcp };
    if d.surfaces[idx as usize].allocated {
        d.surfaces[idx as usize] = Surface::empty();
        d.num_surfaces = d.num_surfaces.saturating_sub(1);
    }
}

/// Return the IOVA recorded for a surface, or 0 if unknown.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_surface_iova(
    dcp: *const AppleDcp,
    idx: i32,
) -> u64 {
    if dcp.is_null() || idx < 0 || (idx as usize) >= MAX_SURFACES { return 0; }
    let d = unsafe { &*dcp };
    if d.surfaces[idx as usize].allocated { d.surfaces[idx as usize].iova } else { 0 }
}

/// Set the current display mode.  Computes stride from width × bpp and
/// caches the mode for `rust_apple_dcp_get_mode` callers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_set_mode(
    dcp:          *mut AppleDcp,
    width:        u32,
    height:       u32,
    refresh_rate: u32,
    pixel_format: u32,
) {
    if dcp.is_null() { return; }
    let d = unsafe { &mut *dcp };
    let stride = width * bpp_for_format(pixel_format);
    d.mode = AppleDcpMode {
        width, height, refresh_rate, pixel_format, stride,
    };
    d.mode_set = true;
}

/// Copy the current mode into `out` and return 1; return 0 if no mode
/// has been set yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_get_mode(
    dcp: *const AppleDcp,
    out: *mut AppleDcpMode,
) -> i32 {
    if dcp.is_null() || out.is_null() { return 0; }
    let d = unsafe { &*dcp };
    if !d.mode_set { return 0; }
    unsafe { write_volatile(out, d.mode); }
    1
}

/// Build a SWAP_START message for `surface_idx` and bookkeep the
/// pending state.  Returns the 64-bit RTKit payload, or 0 if the
/// surface isn't registered or a swap is already in flight (in which
/// case `frames_dropped` is incremented).  Caller sends the returned
/// payload via `apple_rtkit_send_message`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_swap_submit_build(
    dcp:         *mut AppleDcp,
    surface_idx: i32,
) -> u64 {
    if dcp.is_null() || surface_idx < 0 || (surface_idx as usize) >= MAX_SURFACES {
        return 0;
    }
    let d = unsafe { &mut *dcp };
    let surf = d.surfaces[surface_idx as usize];
    if !surf.allocated { return 0; }
    if d.swap_pending.load(Ordering::Acquire) {
        d.frames_dropped.fetch_add(1, Ordering::Relaxed);
        return 0;
    }
    d.next_surface = surface_idx as u32;
    d.swap_pending.store(true, Ordering::Release);
    d.swap_complete.store(false, Ordering::Release);
    build_swap_msg(surface_idx as u8, surf.iova)
}

/// 1 if the most recent swap_submit_build is still in flight, 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_swap_pending(dcp: *const AppleDcp) -> i32 {
    if dcp.is_null() { return 0; }
    let d = unsafe { &*dcp };
    if d.swap_pending.load(Ordering::Acquire) { 1 } else { 0 }
}

/// 1 if the last swap completed (and clears the latch); 0 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_swap_take_complete(dcp: *mut AppleDcp) -> i32 {
    if dcp.is_null() { return 0; }
    let d = unsafe { &mut *dcp };
    if d.swap_complete.swap(false, Ordering::AcqRel) {
        d.current_surface = d.next_surface;
        1
    } else {
        0
    }
}

/// Build a BACKLIGHT message and cache the new level.  Caller sends.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_set_backlight_msg(
    dcp:   *mut AppleDcp,
    level: u8,
) -> u64 {
    if dcp.is_null() { return 0; }
    let d = unsafe { &mut *dcp };
    d.backlight = level;
    build_backlight_msg(level)
}

/// Build a POWER message and cache the new state.  Caller sends.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_set_power_msg(
    dcp:   *mut AppleDcp,
    state: u8,
) -> u64 {
    if dcp.is_null() { return 0; }
    let d = unsafe { &mut *dcp };
    d.power_state = state;
    build_power_msg(state)
}

/// Dispatch an RTKit message received on the DCP endpoint.  Updates
/// swap state on SWAP_COMPLETE; other notifications (power / error /
/// vsync) are ignored (the C side logs them).  Returns the message
/// type byte so the wrapper can log unknowns without re-parsing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_handle_msg(
    dcp: *mut AppleDcp,
    msg: u64,
) -> u8 {
    if dcp.is_null() { return 0xFF; }
    let d = unsafe { &mut *dcp };
    let msg_type = ((msg >> 8) & 0xFF) as u8;
    if msg_type == DCP_MSG_SWAP_COMPLETE {
        d.swap_pending.store(false, Ordering::Release);
        d.swap_complete.store(true, Ordering::Release);
        d.swaps_completed.fetch_add(1, Ordering::Relaxed);
    }
    msg_type
}

/// Convenience accessor used by the C wrapper to fill out
/// `fut_fb_hwinfo` after a successful set_mode + alloc_surface +
/// swap_submit on the primary surface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_mode_width(dcp: *const AppleDcp) -> u32 {
    if dcp.is_null() { return 0; }
    unsafe { (*dcp).mode.width }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_mode_height(dcp: *const AppleDcp) -> u32 {
    if dcp.is_null() { return 0; }
    unsafe { (*dcp).mode.height }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_mode_stride(dcp: *const AppleDcp) -> u32 {
    if dcp.is_null() { return 0; }
    unsafe { (*dcp).mode.stride }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_mode_format(dcp: *const AppleDcp) -> u32 {
    if dcp.is_null() { return 0; }
    unsafe { (*dcp).mode.pixel_format }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_apple_dcp_mode_is_set(dcp: *const AppleDcp) -> i32 {
    if dcp.is_null() { return 0; }
    if unsafe { (*dcp).mode_set } { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

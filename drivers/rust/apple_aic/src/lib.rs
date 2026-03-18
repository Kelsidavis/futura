// SPDX-License-Identifier: MPL-2.0
//! Apple Interrupt Controller (AIC) driver for Futura OS
//!
//! AIC is the central interrupt controller in Apple M1/M2/M3 SoCs.  It
//! routes hardware IRQs from peripherals (NVMe, USB, PCIe, mailboxes, …)
//! to CPU cores and handles inter-processor interrupts (IPIs).
//!
//! Architecture notes
//! ------------------
//! - Up to 896 hardware IRQs, 32 per 32-bit MASK/EVENT register
//! - ARM Generic Timer interrupt bypasses AIC — delivered as FIQ directly
//! - Interrupt handlers are registered per-IRQ as function pointers
//! - IRQ routing: write target CPU mask to AIC_TARGET_CPU register
//!
//! Reference: Asahi Linux `drivers/irqchip/irq-apple-aic.c` (Hector Martin)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const AIC_INFO:         usize = 0x0004;
const AIC_CONFIG:       usize = 0x0010;

const AIC_WHOAMI:       usize = 0x2000;  // CPU-local: current CPU ID
const AIC_EVENT:        usize = 0x2000;  // HW IRQ event bitmap (per-32)
const AIC_EVENT_TYPE:   usize = 0x2800;  // Event type: 0=IRQ, 1=FIQ

const AIC_MASK_SET:     usize = 0x4000;  // Write 1 → mask IRQ
const AIC_MASK_CLR:     usize = 0x4080;  // Write 1 → unmask IRQ

const AIC_IPI_SEND:     usize = 0x6000;  // Write IPI command
const AIC_IPI_ACK:      usize = 0x6004;  // Write IPI number to ack
const AIC_IPI_MASK_SET: usize = 0x6008;  // Mask IPI sources
const AIC_IPI_MASK_CLR: usize = 0x600C;  // Unmask IPI sources

const AIC_TARGET_CPU:   usize = 0x7000;  // IRQ → CPU routing (8 IRQs/u32)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_IRQS:  usize = 896;
const MAX_IPIS:  usize = 32;
const MAX_CPUS:  usize = 16;

/// ARM Generic Timer virtual interrupt (delivered as FIQ, not via AIC).
const APPLE_TIMER_IRQ: u32 = 27;

// ---------------------------------------------------------------------------
// IRQ handler table
// ---------------------------------------------------------------------------

/// C-callable IRQ handler: fn(irq_num, cookie).
type IrqHandlerFn = unsafe extern "C" fn(irq: u32, cookie: *mut ());

#[derive(Copy, Clone)]
struct IrqSlot {
    handler: Option<IrqHandlerFn>,
    cookie:  *mut (),
}

// SAFETY: handlers and cookies are only accessed from the IRQ path under the
// implicit single-hart serialisation that IRQ delivery provides.
unsafe impl Send for IrqSlot {}
unsafe impl Sync for IrqSlot {}

impl IrqSlot {
    const fn empty() -> Self {
        Self { handler: None, cookie: core::ptr::null_mut() }
    }
}

// ---------------------------------------------------------------------------
// AppleAic — driver state
// ---------------------------------------------------------------------------

pub struct AppleAic {
    base:     usize,
    num_irqs: u32,
    version:  u8,
    ready:    AtomicBool,
    handlers: [IrqSlot; MAX_IRQS],
}

impl AppleAic {
    // ---- MMIO helpers ----

    fn r32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }
    fn w32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    // ---- IRQ bitmap helpers ----

    /// Return `(register_offset_from_MASK_BASE, bit)` for `irq`.
    fn irq_reg_bit(irq: u32) -> (usize, u32) {
        let word = (irq / 32) as usize;
        let bit  = irq % 32;
        (word * 4, bit)
    }

    // ---- Public operations ----

    /// Initialise the AIC: mask all IRQs, unmask all IPIs.
    pub fn init(&mut self) -> bool {
        // Read version and IRQ count from INFO register.
        let info    = self.r32(AIC_INFO);
        self.version  = ((info >> 16) & 0xFF) as u8;
        self.num_irqs = info & 0xFFFF;

        // Mask all hardware IRQs.
        let words = (MAX_IRQS + 31) / 32;
        for i in 0..words {
            self.w32(AIC_MASK_SET + i * 4, 0xFFFF_FFFF);
        }

        // Unmask all IPI sources.
        self.w32(AIC_IPI_MASK_CLR, 0xFFFF_FFFF);

        self.ready.store(true, Ordering::Release);
        true
    }

    /// Enable (unmask) hardware IRQ `irq`.
    pub fn enable(&self, irq: u32) {
        if irq >= MAX_IRQS as u32 {
            return;
        }
        let (off, bit) = Self::irq_reg_bit(irq);
        self.w32(AIC_MASK_CLR + off, 1u32 << bit);
    }

    /// Disable (mask) hardware IRQ `irq`.
    pub fn disable(&self, irq: u32) {
        if irq >= MAX_IRQS as u32 {
            return;
        }
        let (off, bit) = Self::irq_reg_bit(irq);
        self.w32(AIC_MASK_SET + off, 1u32 << bit);
    }

    /// Check if IRQ `irq` has a pending event.
    pub fn is_pending(&self, irq: u32) -> bool {
        if irq >= MAX_IRQS as u32 {
            return false;
        }
        let (off, bit) = Self::irq_reg_bit(irq);
        self.r32(AIC_EVENT + off) & (1u32 << bit) != 0
    }

    /// Send IPI `ipi` to `target_cpu`.
    pub fn send_ipi(&self, target_cpu: u32, ipi: u32) {
        if target_cpu >= MAX_CPUS as u32 || ipi >= MAX_IPIS as u32 {
            return;
        }
        let cmd = (ipi << 24) | (1u32 << target_cpu);
        self.w32(AIC_IPI_SEND, cmd);
    }

    /// Acknowledge IPI `ipi`.
    pub fn ack_ipi(&self, ipi: u32) {
        if ipi < MAX_IPIS as u32 {
            self.w32(AIC_IPI_ACK, ipi);
        }
    }

    /// Return the current CPU ID from the WHOAMI register.
    pub fn whoami(&self) -> u32 {
        self.r32(AIC_WHOAMI) & 0xFF
    }

    /// Route IRQ `irq` to the CPU indicated by `cpu_mask` (bitmask).
    pub fn set_target_cpu(&self, irq: u32, cpu_mask: u32) {
        if irq >= MAX_IRQS as u32 {
            return;
        }
        // AIC_TARGET_CPU packs 4 bytes of cpu-masks, one per IRQ, at
        // base + AIC_TARGET_CPU + irq * 4 (each entry is a u32 cpu mask).
        let off = AIC_TARGET_CPU + (irq as usize) * 4;
        self.w32(off, cpu_mask);
    }

    /// Register a C-callable handler for IRQ `irq`.
    pub fn register_handler(&mut self, irq: u32, handler: IrqHandlerFn, cookie: *mut ()) {
        if irq < MAX_IRQS as u32 {
            self.handlers[irq as usize].handler = Some(handler);
            self.handlers[irq as usize].cookie  = cookie;
        }
    }

    /// Unregister the handler for IRQ `irq`.
    pub fn unregister_handler(&mut self, irq: u32) {
        if irq < MAX_IRQS as u32 {
            self.handlers[irq as usize] = IrqSlot::empty();
        }
    }

    /// Top-level IRQ dispatch — call from the ARM64 IRQ exception vector.
    ///
    /// Scans all pending events and dispatches to registered handlers.
    /// Processes at most one IRQ per call (matches the C driver behaviour).
    pub fn handle_irq(&self) {
        let words = (MAX_IRQS + 31) / 32;
        for w in 0..words {
            let ev = self.r32(AIC_EVENT + w * 4);
            if ev == 0 {
                continue;
            }
            // Find lowest set bit.
            let bit = ev.trailing_zeros();
            let irq = (w as u32) * 32 + bit;
            if irq >= MAX_IRQS as u32 {
                return;
            }
            let slot = &self.handlers[irq as usize];
            if let Some(h) = slot.handler {
                // SAFETY: handler registered with correct cookie type.
                unsafe { h(irq, slot.cookie) };
            }
            // AIC clears the event automatically on read.  Return after one.
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Heap allocation shim
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut u8;
    fn fut_free(ptr: *mut u8);

    /// Timer tick (called from the AIC FIQ path for APPLE_TIMER_IRQ).
    fn fut_timer_tick();
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Allocate and initialise an AIC context at `base`.
/// Returns non-null on success, null on failure.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_init(base: u64) -> *mut AppleAic {
    if base == 0 {
        return core::ptr::null_mut();
    }
    let ptr = unsafe { fut_alloc(core::mem::size_of::<AppleAic>()) } as *mut AppleAic;
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    // Initialise in place.
    let aic = unsafe { &mut *ptr };
    aic.base     = base as usize;
    aic.num_irqs = 0;
    aic.version  = 0;
    aic.ready    = AtomicBool::new(false);
    aic.handlers = [IrqSlot::empty(); MAX_IRQS];

    if !aic.init() {
        unsafe { fut_free(ptr as *mut u8) };
        return core::ptr::null_mut();
    }
    ptr
}

/// Free an AIC context returned by `rust_aic_init`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_free(aic: *mut AppleAic) {
    if !aic.is_null() {
        unsafe { fut_free(aic as *mut u8) };
    }
}

/// Enable hardware IRQ `irq`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_enable_irq(aic: *const AppleAic, irq: u32) {
    if !aic.is_null() {
        unsafe { (*aic).enable(irq) };
    }
}

/// Disable hardware IRQ `irq`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_disable_irq(aic: *const AppleAic, irq: u32) {
    if !aic.is_null() {
        unsafe { (*aic).disable(irq) };
    }
}

/// Returns 1 if IRQ `irq` is pending, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_is_pending(aic: *const AppleAic, irq: u32) -> i32 {
    if aic.is_null() {
        return 0;
    }
    unsafe { (*aic).is_pending(irq) as i32 }
}

/// Send IPI `ipi` to `target_cpu`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_send_ipi(aic: *const AppleAic, target_cpu: u32, ipi: u32) {
    if !aic.is_null() {
        unsafe { (*aic).send_ipi(target_cpu, ipi) };
    }
}

/// Acknowledge IPI `ipi`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_ack_ipi(aic: *const AppleAic, ipi: u32) {
    if !aic.is_null() {
        unsafe { (*aic).ack_ipi(ipi) };
    }
}

/// Return the current CPU ID.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_whoami(aic: *const AppleAic) -> u32 {
    if aic.is_null() {
        return 0;
    }
    unsafe { (*aic).whoami() }
}

/// Route IRQ `irq` to the CPU(s) in `cpu_mask`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_set_target_cpu(aic: *const AppleAic, irq: u32, cpu_mask: u32) {
    if !aic.is_null() {
        unsafe { (*aic).set_target_cpu(irq, cpu_mask) };
    }
}

/// Register a C handler for IRQ `irq`.
///
/// # Safety
/// `handler` must be valid; `cookie` must remain live until unregistered.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_aic_register_handler(
    aic:     *mut AppleAic,
    irq:     u32,
    handler: Option<unsafe extern "C" fn(irq: u32, cookie: *mut ())>,
    cookie:  *mut (),
) {
    if aic.is_null() {
        return;
    }
    if let Some(h) = handler {
        unsafe { (*aic).register_handler(irq, h, cookie) };
    }
}

/// Unregister the handler for IRQ `irq`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_unregister_handler(aic: *mut AppleAic, irq: u32) {
    if !aic.is_null() {
        unsafe { (*aic).unregister_handler(irq) };
    }
}

/// Top-level IRQ dispatch — call from the ARM64 IRQ/FIQ exception vector.
/// Processes at most one IRQ per call.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_handle_irq(aic: *const AppleAic) {
    if aic.is_null() {
        return;
    }
    unsafe { (*aic).handle_irq() };
}

/// Returns the negotiated IRQ count (0 if not yet initialised).
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_num_irqs(aic: *const AppleAic) -> u32 {
    if aic.is_null() {
        return 0;
    }
    unsafe { (*aic).num_irqs }
}

/// Returns 1 if the AIC was successfully initialised.
#[unsafe(no_mangle)]
pub extern "C" fn rust_aic_is_ready(aic: *const AppleAic) -> i32 {
    if aic.is_null() {
        return 0;
    }
    unsafe { (*aic).ready.load(Ordering::Acquire) as i32 }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

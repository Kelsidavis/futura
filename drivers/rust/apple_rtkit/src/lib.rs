// SPDX-License-Identifier: MPL-2.0
//! Apple RTKit co-processor IPC driver for Futura OS
//!
//! RTKit (Real-Time Kit) is Apple's RTOS running on embedded co-processors
//! in M1/M2/M3 SoCs (ANS NVMe, DCP display, AOP, SMC, etc.).  Communication
//! uses a mailbox-based 64-bit message protocol over MMIO registers.
//!
//! Boot sequence
//! -------------
//! 1. AP sends HELLO (type=0x01, min_version..max_version)
//! 2. Co-processor replies HELLO_REPLY (type=0x02) with negotiated version
//! 3. AP requests endpoint map (EPMAP, type=0x08) for each 32-ep chunk
//! 4. Co-processor replies EPMAP_REPLY with a bitmap of available endpoints
//! 5. AP starts required system endpoints (STARTEP, type=0x05): crashlog,
//!    syslog, ioreport, oslog
//! 6. AP sets IOP power state to ON (IOP_PWR_STATE, type=0x0A, state=0x20)
//! 7. Co-processor acknowledges (IOP_PWR_ACK, type=0x0B)
//!
//! Mailbox register layout (Apple MMIO variant, as used by ANS/DCP/AOP)
//! --------------------------------------------------------------------
//! All registers are 32-bit; a 64-bit message is split into DATA0 (low) +
//! DATA1 (high).  The TX/RX FIFOs are 8 entries deep on M1.
//!
//! TX path:
//!   base + 0x800  TX_DATA0   write low 32 bits
//!   base + 0x804  TX_DATA1   write high 32 bits → triggers send
//!   base + 0x808  TX_STATUS  bit[16] = count, bit[0] = full
//!
//! RX path:
//!   base + 0x810  RX_DATA0   read low 32 bits
//!   base + 0x814  RX_DATA1   read high 32 bits → pops entry
//!   base + 0x818  RX_STATUS  bit[16] = count, bit[0] = empty
//!
//! RTKit message encoding
//! ----------------------
//! Bits [63:56] endpoint number  (u8)
//! Bits [55:52] message type     (4 bits, shifts vary per endpoint)
//! Bits [51:0]  payload
//!
//! For management endpoint (0x00):
//!   type = bits [59:52] (8 bits)
//!   payload = bits [51:0]
//!
//! Reference: Asahi Linux drivers/mailbox/apple-mailbox.c,
//!            drivers/soc/apple/rtkit.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// Mailbox register offsets (real Apple MMIO layout)
// ---------------------------------------------------------------------------

const MBOX_TX_DATA0:   usize = 0x800;
const MBOX_TX_DATA1:   usize = 0x804;
const MBOX_TX_STATUS:  usize = 0x808;
const MBOX_RX_DATA0:   usize = 0x810;
const MBOX_RX_DATA1:   usize = 0x814;
const MBOX_RX_STATUS:  usize = 0x818;

const MBOX_TX_FULL:    u32 = 1 << 0;
const MBOX_RX_EMPTY:   u32 = 1 << 0;

// TX/RX FIFO depth for spin-wait budget (hardware max is 8)
const MBOX_FIFO_DEPTH: u32 = 8;

// ---------------------------------------------------------------------------
// RTKit message format
// ---------------------------------------------------------------------------

/// Endpoint field: bits [63:56]
const EP_SHIFT: u32  = 56;
const EP_MASK: u64   = 0xFF;

/// Management endpoint message type: bits [59:52]
const MGMT_TYPE_SHIFT: u32 = 52;
const MGMT_TYPE_MASK:  u64 = 0xFF;

/// Build a management message from (type, payload).
#[inline(always)]
fn mgmt_msg(mtype: u8, payload: u64) -> u64 {
    ((APPLE_RTKIT_EP_MGMT as u64) << EP_SHIFT)
        | ((mtype as u64) << MGMT_TYPE_SHIFT)
        | (payload & MGMT_PAYLOAD_MASK)
}

const MGMT_PAYLOAD_MASK: u64 = (1u64 << 52) - 1;

// ---------------------------------------------------------------------------
// RTKit protocol constants
// ---------------------------------------------------------------------------

const APPLE_RTKIT_EP_MGMT:      u8 = 0x00;
const APPLE_RTKIT_EP_CRASHLOG:  u8 = 0x01;
const APPLE_RTKIT_EP_SYSLOG:    u8 = 0x02;
const APPLE_RTKIT_EP_IOREPORT:  u8 = 0x04;
const APPLE_RTKIT_EP_OSLOG:     u8 = 0x08;

const MGMT_HELLO:         u8 = 0x01;
const MGMT_HELLO_REPLY:   u8 = 0x02;
const MGMT_STARTEP:       u8 = 0x05;
const MGMT_STARTEP_ACK:   u8 = 0x06;
const MGMT_EPMAP:         u8 = 0x08;
const MGMT_EPMAP_REPLY:   u8 = 0x09;
const MGMT_IOP_PWR_STATE: u8 = 0x0A;
const MGMT_IOP_PWR_ACK:   u8 = 0x0B;

const RTKIT_MIN_VERSION: u64 = 11;
const RTKIT_MAX_VERSION: u64 = 12;

/// IOP power states
const PWR_STATE_OFF:  u8 = 0x00;
#[allow(dead_code)]
const PWR_STATE_SLEEP: u8 = 0x01;
#[allow(dead_code)]
const PWR_STATE_QUIESCED: u8 = 0x10;
const PWR_STATE_ON:   u8 = 0x20;

// ---------------------------------------------------------------------------
// Endpoint slots (fixed-size, no heap allocation for the array itself)
// ---------------------------------------------------------------------------

const MAX_ENDPOINTS: usize = 256;

/// Per-endpoint callback (C function pointer).
type MsgHandlerFn = unsafe extern "C" fn(cookie: *mut (), endpoint: u8, msg: u64);

#[derive(Copy, Clone)]
struct EndpointSlot {
    started: bool,
    handler: Option<MsgHandlerFn>,
    cookie:  *mut (),
}

// SAFETY: raw pointers are only accessed under the lock embedded in RtkitCtx.
unsafe impl Send for EndpointSlot {}
unsafe impl Sync for EndpointSlot {}

impl EndpointSlot {
    const fn empty() -> Self {
        Self { started: false, handler: None, cookie: core::ptr::null_mut() }
    }
}

// ---------------------------------------------------------------------------
// RtkitCtx — the main driver state
// ---------------------------------------------------------------------------

/// RTKit co-processor context.  Heap-allocated by `rtkit_init`; returned to
/// callers as a raw pointer.
pub struct RtkitCtx {
    /// MMIO virtual base address of the mailbox registers.
    base:       usize,
    /// Negotiated protocol version (set during HELLO handshake).
    version:    u32,
    /// True once the boot sequence (HELLO → EPMAP → STARTEP → ON) completes.
    ready:      AtomicBool,
    /// 256-bit endpoint bitmap (set by EPMAP replies).
    ep_bitmap:  [u32; 8],
    /// Per-endpoint state.
    endpoints:  [EndpointSlot; MAX_ENDPOINTS],
    /// Current IOP power state.
    iop_pwr:    u8,
}

impl RtkitCtx {
    fn new(base: usize) -> Self {
        Self {
            base,
            version:   0,
            ready:     AtomicBool::new(false),
            ep_bitmap: [0u32; 8],
            endpoints: [EndpointSlot::empty(); MAX_ENDPOINTS],
            iop_pwr:   PWR_STATE_OFF,
        }
    }

    // ---- MMIO helpers ----

    fn read32(&self, off: usize) -> u32 {
        unsafe { read_volatile((self.base + off) as *const u32) }
    }

    fn write32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.base + off) as *mut u32, v) }
    }

    // ---- Mailbox primitives ----

    /// Send a 64-bit message.  Returns `false` on TX timeout.
    fn send(&self, msg: u64) -> bool {
        // Spin until TX FIFO is not full (max FIFO_DEPTH * 1000 iterations).
        let mut budget = MBOX_FIFO_DEPTH * 1000;
        loop {
            if self.read32(MBOX_TX_STATUS) & MBOX_TX_FULL == 0 {
                break;
            }
            if budget == 0 {
                return false;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
        // Write low word first, then high word (which triggers the send).
        self.write32(MBOX_TX_DATA0, msg as u32);
        self.write32(MBOX_TX_DATA1, (msg >> 32) as u32);
        true
    }

    /// Receive a 64-bit message (non-blocking).  Returns `None` if FIFO empty.
    fn recv(&self) -> Option<u64> {
        if self.read32(MBOX_RX_STATUS) & MBOX_RX_EMPTY != 0 {
            return None;
        }
        // Read low word first, then high word (which pops the entry).
        let lo = self.read32(MBOX_RX_DATA0) as u64;
        let hi = self.read32(MBOX_RX_DATA1) as u64;
        Some(lo | (hi << 32))
    }

    /// Blocking receive with spin-wait budget (~100 k iterations ≈ a few ms).
    fn recv_blocking(&self) -> Option<u64> {
        let mut budget = 100_000u32;
        loop {
            if let Some(m) = self.recv() {
                return Some(m);
            }
            if budget == 0 {
                return None;
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    // ---- Endpoint bitmap ----

    fn ep_available(&self, ep: u8) -> bool {
        let word = (ep as usize) / 32;
        let bit  = (ep as usize) % 32;
        self.ep_bitmap[word] & (1u32 << bit) != 0
    }

    fn ep_set_available(&mut self, ep: u8) {
        let word = (ep as usize) / 32;
        let bit  = (ep as usize) % 32;
        self.ep_bitmap[word] |= 1u32 << bit;
    }

    // ---- Management message helpers ----

    fn send_mgmt(&self, mtype: u8, payload: u64) -> bool {
        self.send(mgmt_msg(mtype, payload))
    }

    /// Extract management type from a received management-endpoint message.
    fn mgmt_type(msg: u64) -> u8 {
        ((msg >> MGMT_TYPE_SHIFT) & MGMT_TYPE_MASK) as u8
    }

    fn msg_payload(msg: u64) -> u64 {
        msg & MGMT_PAYLOAD_MASK
    }

    // ---- Boot sequence ----

    /// Phase 1: HELLO handshake — negotiate protocol version.
    fn boot_hello(&mut self) -> bool {
        // Send HELLO with our supported version range.
        let hello_payload = (RTKIT_MIN_VERSION << 16) | RTKIT_MAX_VERSION;
        if !self.send_mgmt(MGMT_HELLO, hello_payload) {
            return false;
        }

        // Wait for HELLO_REPLY.
        for _ in 0..10 {
            if let Some(msg) = self.recv_blocking() {
                let ep = ((msg >> EP_SHIFT) & EP_MASK) as u8;
                if ep != APPLE_RTKIT_EP_MGMT {
                    continue;
                }
                if Self::mgmt_type(msg) == MGMT_HELLO_REPLY {
                    // Reply encodes negotiated version in payload bits [3:0].
                    self.version = (Self::msg_payload(msg) & 0xF) as u32;
                    return true;
                }
            }
        }
        false
    }

    /// Phase 2: EPMAP — discover available endpoints (256 total, 32 per chunk).
    fn boot_epmap(&mut self) -> bool {
        for chunk in 0u8..8u8 {
            // Request the bitmap for endpoints [chunk*32 .. chunk*32+31].
            let payload = (chunk as u64) << 32;
            if !self.send_mgmt(MGMT_EPMAP, payload) {
                return false;
            }

            // Wait for EPMAP_REPLY.
            let reply = match self.recv_blocking() {
                Some(m) => m,
                None    => return false,
            };
            let ep = ((reply >> EP_SHIFT) & EP_MASK) as u8;
            if ep != APPLE_RTKIT_EP_MGMT || Self::mgmt_type(reply) != MGMT_EPMAP_REPLY {
                return false;
            }

            // EPMAP_REPLY payload: bits [63:32] chunk index, bits [31:0] bitmap.
            let bitmap = Self::msg_payload(reply) as u32;
            self.ep_bitmap[chunk as usize] = bitmap;

            // Mark each available endpoint.
            for bit in 0u8..32u8 {
                if bitmap & (1u32 << bit) != 0 {
                    let ep_num = chunk * 32 + bit;
                    self.ep_set_available(ep_num);
                }
            }

            // Last chunk flag: bit 31 of reply payload upper word.
            if (reply >> 63) & 1 == 1 {
                break;
            }
        }
        true
    }

    /// Phase 3: Start system endpoints (crashlog, syslog, ioreport, oslog).
    fn boot_start_system_endpoints(&mut self) -> bool {
        const SYSTEM_EPS: [u8; 4] = [
            APPLE_RTKIT_EP_CRASHLOG,
            APPLE_RTKIT_EP_SYSLOG,
            APPLE_RTKIT_EP_IOREPORT,
            APPLE_RTKIT_EP_OSLOG,
        ];

        for &ep in &SYSTEM_EPS {
            if !self.ep_available(ep) {
                continue;
            }
            // STARTEP payload: endpoint number in bits [35:32].
            let payload = (ep as u64) << 32;
            if !self.send_mgmt(MGMT_STARTEP, payload) {
                return false;
            }

            // Wait for STARTEP_ACK (or skip on timeout — some EPs are optional).
            for _ in 0..5 {
                if let Some(msg) = self.recv_blocking() {
                    let ep_field = ((msg >> EP_SHIFT) & EP_MASK) as u8;
                    if ep_field == APPLE_RTKIT_EP_MGMT
                        && Self::mgmt_type(msg) == MGMT_STARTEP_ACK
                    {
                        self.endpoints[ep as usize].started = true;
                        break;
                    }
                }
            }
        }
        true
    }

    /// Phase 4: Set IOP power state to ON.
    fn boot_power_on(&mut self) -> bool {
        let payload = PWR_STATE_ON as u64;
        if !self.send_mgmt(MGMT_IOP_PWR_STATE, payload) {
            return false;
        }

        // Wait for IOP_PWR_ACK.
        for _ in 0..10 {
            if let Some(msg) = self.recv_blocking() {
                let ep = ((msg >> EP_SHIFT) & EP_MASK) as u8;
                if ep == APPLE_RTKIT_EP_MGMT
                    && Self::mgmt_type(msg) == MGMT_IOP_PWR_ACK
                {
                    self.iop_pwr = PWR_STATE_ON;
                    return true;
                }
            }
        }
        false
    }

    /// Run the complete boot sequence.
    pub fn boot(&mut self) -> bool {
        if !self.boot_hello()                    { return false; }
        if !self.boot_epmap()                    { return false; }
        if !self.boot_start_system_endpoints()   { return false; }
        if !self.boot_power_on()                 { return false; }
        self.ready.store(true, Ordering::Release);
        true
    }

    // ---- Message dispatch ----

    /// Send an application-endpoint message.
    pub fn send_ep(&self, endpoint: u8, msg: u64) -> bool {
        let full = ((endpoint as u64) << EP_SHIFT) | (msg & ((1u64 << EP_SHIFT) - 1));
        self.send(full)
    }

    /// Poll the RX FIFO and dispatch one message to the registered handler,
    /// if any.  Returns `true` if a message was dispatched, `false` if FIFO
    /// was empty.
    pub fn poll(&self) -> bool {
        let msg = match self.recv() {
            Some(m) => m,
            None    => return false,
        };
        let ep = ((msg >> EP_SHIFT) & EP_MASK) as u8;
        let slot = &self.endpoints[ep as usize];
        if let Some(handler) = slot.handler {
            // SAFETY: `handler` was validated at registration time.
            unsafe { handler(slot.cookie, ep, msg) };
        }
        true
    }

    /// Register an application-endpoint handler.
    pub fn register_handler(&mut self, endpoint: u8, handler: MsgHandlerFn, cookie: *mut ()) {
        self.endpoints[endpoint as usize].handler = Some(handler);
        self.endpoints[endpoint as usize].cookie  = cookie;
    }
}

// ---------------------------------------------------------------------------
// Heap allocator shim (kernel-provided)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn fut_alloc(size: usize) -> *mut ();
    fn fut_free(ptr: *mut ());
}

// ---------------------------------------------------------------------------
// C FFI
// ---------------------------------------------------------------------------

/// Allocate and initialise an RTKit context for the mailbox at `base`.
/// Returns a non-null opaque pointer on success, null on failure.
///
/// The caller owns the context and must eventually call `rust_rtkit_free`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_init(base: u64) -> *mut RtkitCtx {
    if base == 0 {
        return core::ptr::null_mut();
    }
    // Allocate context on the kernel heap.
    let ptr = unsafe { fut_alloc(core::mem::size_of::<RtkitCtx>()) };
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    let ctx = ptr as *mut RtkitCtx;
    // Initialise in place (avoids copying a large struct off the stack).
    unsafe { ctx.write(RtkitCtx::new(base as usize)) };
    ctx
}

/// Run the full RTKit boot sequence (HELLO → EPMAP → STARTEP → ON).
/// Returns 1 on success, 0 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_boot(ctx: *mut RtkitCtx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    if unsafe { (*ctx).boot() } { 1 } else { 0 }
}

/// Free an RTKit context previously allocated by `rust_rtkit_init`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_free(ctx: *mut RtkitCtx) {
    if ctx.is_null() {
        return;
    }
    unsafe { fut_free(ctx as *mut ()) };
}

/// Send a message to the given endpoint.
/// Returns 1 on success, 0 on TX timeout.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_send(ctx: *mut RtkitCtx, endpoint: u8, msg: u64) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    if unsafe { (*ctx).send_ep(endpoint, msg) } { 1 } else { 0 }
}

/// Poll the RX FIFO and dispatch one message.
/// Returns 1 if a message was dispatched, 0 if FIFO was empty.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_poll(ctx: *mut RtkitCtx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    if unsafe { (*ctx).poll() } { 1 } else { 0 }
}

/// Register an application-endpoint message handler.
///
/// # Safety
/// `handler` must be a valid function pointer; `cookie` must remain valid
/// until the handler is unregistered or the context is freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_rtkit_register_handler(
    ctx:      *mut RtkitCtx,
    endpoint: u8,
    handler:  Option<unsafe extern "C" fn(cookie: *mut (), endpoint: u8, msg: u64)>,
    cookie:   *mut (),
) {
    if ctx.is_null() {
        return;
    }
    if let Some(h) = handler {
        unsafe { (*ctx).register_handler(endpoint, h, cookie) };
    }
}

/// Returns the negotiated RTKit protocol version (0 if not yet booted).
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_version(ctx: *const RtkitCtx) -> u32 {
    if ctx.is_null() {
        return 0;
    }
    unsafe { (*ctx).version }
}

/// Returns 1 if the boot sequence completed successfully, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn rust_rtkit_is_ready(ctx: *const RtkitCtx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    unsafe { (*ctx).ready.load(Ordering::Acquire) as i32 }
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

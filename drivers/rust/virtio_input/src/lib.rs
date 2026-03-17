// SPDX-License-Identifier: MPL-2.0
/*
 * virtio-input driver for Futura OS
 *
 * Discovers virtio-input MMIO (ARM64) and PCI (x86_64) devices, sets up
 * the eventq with pre-allocated writable buffers, and polls for events in
 * a background kernel thread.  Each received event is delivered to the C
 * kernel via virtio_input_post_event().
 *
 * Architecture:
 *   ARM64  — scans virtio-mmio via virtio_mmio_find_device()/get_device()
 *   x86_64 — scans PCI bus for vendor 0x1AF4 device 0x1052 (input)
 *
 * Queue management:
 *   Only the eventq (queue 0) is used.  The statusq (queue 1) for LED /
 *   rumble feedback is not initialised.  The driver pre-populates the
 *   available ring with QUEUE_SIZE writable descriptors so the device can
 *   fill them with virtio_input_event structs.  After draining the used
 *   ring, each processed descriptor is recycled back into the available
 *   ring.
 */

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering, fence};
use core::ffi::c_void;

use common::{alloc_page, free_page, log, thread_sleep, SpinLock};

// ── FFI ─────────────────────────────────────────────────────────────────────

// Opaque kernel types
#[repr(C)]
struct FutTask { _private: [u8; 0] }
#[repr(C)]
struct FutThread { _private: [u8; 0] }

unsafe extern "C" {
    /// Deliver one virtio-input event to the kernel.  Defined in
    /// kernel/input/virtio_input_ffi.c.
    fn virtio_input_post_event(ev_type: u16, code: u16, value: i32);

    fn fut_task_create() -> *mut FutTask;
    fn fut_thread_create(
        task: *mut FutTask,
        entry: extern "C" fn(*mut c_void),
        arg: *mut c_void,
        stack_size: usize,
        priority: i32,
    ) -> *mut FutThread;
}

// ARM64 virtio-mmio helpers (defined in platform/arm64/drivers/virtio_mmio.c)
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn virtio_mmio_find_device(device_type: u32) -> i32;
    fn virtio_mmio_get_device(idx: i32) -> *mut c_void;
    fn virtio_mmio_get_base_addr(dev: *mut c_void) -> u64;
}

// x86_64 PCI helpers
#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    fn pci_find_device(vendor_id: u16, device_id: u16) -> i32;
    fn pci_get_bar_addr(bus: u8, dev: u8, func: u8, bar: u8) -> u64;
    fn pci_get_irq(bus: u8, dev: u8, func: u8) -> u8;
}

// ── Virtio MMIO register offsets ────────────────────────────────────────────

const MMIO_MAGIC:              u32 = 0x000;
const MMIO_DEVICE_ID:          u32 = 0x008;
const MMIO_DEVICE_FEATURES:    u32 = 0x010;
const MMIO_DEVICE_FEATURES_SEL:u32 = 0x014;
const MMIO_DRIVER_FEATURES:    u32 = 0x020;
const MMIO_DRIVER_FEATURES_SEL:u32 = 0x024;
const MMIO_QUEUE_SEL:          u32 = 0x030;
const MMIO_QUEUE_NUM_MAX:      u32 = 0x034;
const MMIO_QUEUE_NUM:          u32 = 0x038;
const MMIO_QUEUE_READY:        u32 = 0x044;
const MMIO_QUEUE_NOTIFY:       u32 = 0x050;
const MMIO_INTERRUPT_STATUS:   u32 = 0x060;
const MMIO_INTERRUPT_ACK:      u32 = 0x064;
const MMIO_STATUS:             u32 = 0x070;
const MMIO_QUEUE_DESC_LOW:     u32 = 0x080;
const MMIO_QUEUE_DESC_HIGH:    u32 = 0x084;
const MMIO_QUEUE_DRIVER_LOW:   u32 = 0x090;
const MMIO_QUEUE_DRIVER_HIGH:  u32 = 0x094;
const MMIO_QUEUE_DEVICE_LOW:   u32 = 0x0a0;
const MMIO_QUEUE_DEVICE_HIGH:  u32 = 0x0a4;

const VIRTIO_MAGIC: u32 = 0x74726976; // 'virt'
const VIRTIO_DEV_INPUT: u32 = 18;

// VirtIO status bits
const STATUS_ACKNOWLEDGE:  u32 = 1;
const STATUS_DRIVER:       u32 = 2;
const STATUS_DRIVER_OK:    u32 = 4;
const STATUS_FEATURES_OK:  u32 = 8;

// Descriptor flags
const DESC_F_WRITE: u16 = 2; // Buffer is write-only (device writes to it)

// Queue size — small, input events are tiny
const QUEUE_SIZE: usize = 32;

// ── virtio_input_event (8 bytes, matches the virtio spec) ───────────────────

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioInputEvent {
    ev_type: u16,
    code:    u16,
    value:   i32,
}

// ── Split virtqueue structures ───────────────────────────────────────────────

#[repr(C, packed)]
struct VirtqDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, packed)]
struct VirtqAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QUEUE_SIZE],
    // used_event omitted
}

#[repr(C, packed)]
struct VirtqUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, packed)]
struct VirtqUsed {
    flags: u16,
    idx:   u16,
    ring:  [VirtqUsedElem; QUEUE_SIZE],
    // avail_event omitted
}

// ── Per-device state ─────────────────────────────────────────────────────────

struct InputDevice {
    /// Mapped MMIO base (virtual address on ARM64)
    mmio_base: u64,

    /// Pre-allocated event buffers (one per descriptor slot)
    event_bufs: [*mut VirtioInputEvent; QUEUE_SIZE],

    /// Physical addresses of event buffers (= virtual on ARM64)
    event_phys: [u64; QUEUE_SIZE],

    /// Descriptor ring
    desc: *mut VirtqDesc,
    /// Available ring (driver → device)
    avail: *mut VirtqAvail,
    /// Used ring (device → driver)
    used: *mut VirtqUsed,

    /// Last processed used.idx
    last_used: u16,

    /// Next available.idx to fill
    avail_idx: u16,
}

unsafe impl Send for InputDevice {}

// Global device list (up to 4 input devices)
static DEVICES: SpinLock<[Option<InputDevice>; 4]> = SpinLock::new([None, None, None, None]);
static POLL_RUNNING: AtomicBool = AtomicBool::new(false);

// ── MMIO helpers ─────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn mmio_read32(base: u64, off: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)); }
    let v = unsafe { read_volatile((base + off as u64) as *const u32) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)); }
    v
}

#[inline(always)]
unsafe fn mmio_write32(base: u64, off: u32, val: u32) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)); }
    unsafe { write_volatile((base + off as u64) as *mut u32, val) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy", options(nostack, nomem)); }
}

#[inline(always)]
unsafe fn mmio_write64_pair(base: u64, off_lo: u32, val: u64) {
    unsafe {
        mmio_write32(base, off_lo,     (val & 0xFFFF_FFFF) as u32);
        mmio_write32(base, off_lo + 4, (val >> 32) as u32);
    }
}

// ── Device initialisation ─────────────────────────────────────────────────────

impl InputDevice {
    /// Initialise a virtio-input device at `mmio_base`.
    /// Returns `Some(device)` on success, `None` on failure.
    unsafe fn init(mmio_base: u64) -> Option<Self> {
        // Validate magic
        if unsafe { mmio_read32(mmio_base, MMIO_MAGIC) } != VIRTIO_MAGIC {
            log("[VINPUT] bad magic\n");
            return None;
        }

        // Reset
        unsafe { mmio_write32(mmio_base, MMIO_STATUS, 0) };

        // Acknowledge + Driver
        unsafe { mmio_write32(mmio_base, MMIO_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER) };

        // Negotiate features — no special features needed for input
        unsafe {
            mmio_write32(mmio_base, MMIO_DEVICE_FEATURES_SEL, 0);
            mmio_write32(mmio_base, MMIO_DRIVER_FEATURES_SEL, 0);
            mmio_write32(mmio_base, MMIO_DRIVER_FEATURES, 0);
        }

        // Features OK
        unsafe { mmio_write32(mmio_base, MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK) };

        let status = unsafe { mmio_read32(mmio_base, MMIO_STATUS) };
        if (status & STATUS_FEATURES_OK) == 0 {
            log("[VINPUT] FEATURES_OK not set\n");
            unsafe { mmio_write32(mmio_base, MMIO_STATUS, 0x80) }; // FAILED
            return None;
        }

        // ── Eventq (queue 0) setup ──────────────────────────────────────────

        unsafe { mmio_write32(mmio_base, MMIO_QUEUE_SEL, 0) };
        let max_size = unsafe { mmio_read32(mmio_base, MMIO_QUEUE_NUM_MAX) };
        if max_size == 0 {
            log("[VINPUT] queue 0 not available\n");
            return None;
        }
        let queue_size = QUEUE_SIZE.min(max_size as usize);
        unsafe { mmio_write32(mmio_base, MMIO_QUEUE_NUM, queue_size as u32) };

        // Allocate descriptor ring (one page is enough for 32 descs)
        let desc_page = unsafe { alloc_page() };
        if desc_page.is_null() {
            log("[VINPUT] alloc desc failed\n");
            return None;
        }
        unsafe { core::ptr::write_bytes(desc_page, 0, 4096) };

        let avail_page = unsafe { alloc_page() };
        if avail_page.is_null() {
            unsafe { free_page(desc_page) };
            log("[VINPUT] alloc avail failed\n");
            return None;
        }
        unsafe { core::ptr::write_bytes(avail_page, 0, 4096) };

        let used_page = unsafe { alloc_page() };
        if used_page.is_null() {
            unsafe { free_page(desc_page); free_page(avail_page) };
            log("[VINPUT] alloc used failed\n");
            return None;
        }
        unsafe { core::ptr::write_bytes(used_page, 0, 4096) };

        let desc_phys  = desc_page as u64;
        let avail_phys = avail_page as u64;
        let used_phys  = used_page as u64;

        // Tell device the queue ring physical addresses
        unsafe {
            mmio_write64_pair(mmio_base, MMIO_QUEUE_DESC_LOW,   desc_phys);
            mmio_write64_pair(mmio_base, MMIO_QUEUE_DRIVER_LOW, avail_phys);
            mmio_write64_pair(mmio_base, MMIO_QUEUE_DEVICE_LOW, used_phys);
            mmio_write32(mmio_base, MMIO_QUEUE_READY, 1);
        }

        // ── Pre-populate the available ring with writable descriptors ───────

        let desc  = desc_page  as *mut VirtqDesc;
        let avail = avail_page as *mut VirtqAvail;
        let used  = used_page  as *mut VirtqUsed;

        let mut event_bufs  = [core::ptr::null_mut::<VirtioInputEvent>(); QUEUE_SIZE];
        let mut event_phys  = [0u64; QUEUE_SIZE];

        for i in 0..queue_size {
            let buf = unsafe { alloc_page() } as *mut VirtioInputEvent;
            if buf.is_null() {
                // Partial init — free what we have and bail
                for j in 0..i {
                    unsafe { free_page(event_bufs[j] as *mut u8) };
                }
                unsafe { free_page(desc_page); free_page(avail_page); free_page(used_page) };
                log("[VINPUT] alloc event buf failed\n");
                return None;
            }
            unsafe { core::ptr::write_bytes(buf, 0, 4096) };

            let phys = buf as u64;
            event_bufs[i] = buf;
            event_phys[i] = phys;

            // Descriptor: writable, device fills it with a virtio_input_event
            unsafe {
                (*desc.add(i)).addr  = phys;
                (*desc.add(i)).len   = core::mem::size_of::<VirtioInputEvent>() as u32;
                (*desc.add(i)).flags = DESC_F_WRITE;
                (*desc.add(i)).next  = 0;
            }

            // Add to available ring
            unsafe {
                (*avail).ring[i] = i as u16;
            }
        }

        fence(Ordering::Release);

        // Advance avail.idx to tell device N buffers are available
        unsafe {
            core::ptr::write_unaligned(
                core::ptr::addr_of_mut!((*avail).idx),
                queue_size as u16,
            );
        }

        fence(Ordering::Release);

        // Set DRIVER_OK
        unsafe { mmio_write32(mmio_base, MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK) };

        // Notify device queue 0 has new buffers
        unsafe { mmio_write32(mmio_base, MMIO_QUEUE_NOTIFY, 0) };

        log("[VINPUT] device ready\n");

        Some(InputDevice {
            mmio_base,
            event_bufs,
            event_phys,
            desc,
            avail,
            used,
            last_used:  0,
            avail_idx:  queue_size as u16,
        })
    }

    /// Drain the used ring and return the number of events processed.
    unsafe fn drain_events(&mut self) {
        fence(Ordering::Acquire);

        // Read used.idx via raw pointer to avoid packed-struct alignment UB
        let used_idx = unsafe {
            core::ptr::read_unaligned(
                core::ptr::addr_of!((*self.used).idx)
            )
        };

        while self.last_used != used_idx {
            let slot = (self.last_used as usize) % QUEUE_SIZE;

            // Read used ring element via unaligned reads
            let elem_id = unsafe {
                core::ptr::read_unaligned(
                    core::ptr::addr_of!((*self.used).ring[slot].id)
                )
            };
            let desc_idx = (elem_id as usize) % QUEUE_SIZE;

            fence(Ordering::Acquire);

            // Read the event the device wrote into the buffer (unaligned)
            let buf = self.event_bufs[desc_idx];
            let ev_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*buf).ev_type)) };
            let code    = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*buf).code)) };
            let value   = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*buf).value)) };

            // Deliver to kernel
            unsafe { virtio_input_post_event(ev_type, code, value) };

            // Recycle this descriptor into the available ring
            let avail_slot = (self.avail_idx as usize) % QUEUE_SIZE;
            unsafe {
                core::ptr::write_unaligned(
                    core::ptr::addr_of_mut!((*self.avail).ring[avail_slot]),
                    desc_idx as u16,
                );
            }
            fence(Ordering::Release);
            self.avail_idx = self.avail_idx.wrapping_add(1);
            unsafe {
                core::ptr::write_unaligned(
                    core::ptr::addr_of_mut!((*self.avail).idx),
                    self.avail_idx,
                );
            }
            fence(Ordering::Release);

            // Notify device that one more buffer is available
            unsafe { mmio_write32(self.mmio_base, MMIO_QUEUE_NOTIFY, 0) };

            self.last_used = self.last_used.wrapping_add(1);
        }

        // Acknowledge interrupt
        let isr = unsafe { mmio_read32(self.mmio_base, MMIO_INTERRUPT_STATUS) };
        if isr != 0 {
            unsafe { mmio_write32(self.mmio_base, MMIO_INTERRUPT_ACK, isr) };
        }
    }
}

// ── Background poll thread ────────────────────────────────────────────────────

extern "C" fn poll_thread(_arg: *mut c_void) {
    loop {
        DEVICES.with(|devs| {
            for slot in devs.iter_mut() {
                if let Some(dev) = slot {
                    unsafe { dev.drain_events() };
                }
            }
        });

        // Poll every 10 ms — sufficient for HID input latency
        thread_sleep(10);
    }
}

/// Spawn the background polling thread.
unsafe fn spawn_poll_thread() {
    let task = unsafe { fut_task_create() };
    if task.is_null() {
        log("[VINPUT] failed to create poll task\n");
        return;
    }
    let thread = unsafe {
        fut_thread_create(task, poll_thread, core::ptr::null_mut(), 8192, 50)
    };
    if thread.is_null() {
        log("[VINPUT] failed to create poll thread\n");
    } else {
        log("[VINPUT] poll thread started\n");
    }
}

// ── ARM64 MMIO probe ──────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
unsafe fn probe_mmio_devices() {
    let mut found = 0usize;

    // There may be multiple virtio-input devices (keyboard + mouse)
    for _ in 0..4 {
        let idx = unsafe { virtio_mmio_find_device(VIRTIO_DEV_INPUT) };
        if idx < 0 {
            break;
        }
        let dev_ptr = unsafe { virtio_mmio_get_device(idx) };
        if dev_ptr.is_null() {
            break;
        }
        let mmio_base = unsafe { virtio_mmio_get_base_addr(dev_ptr) };
        if mmio_base == 0 {
            break;
        }

        match unsafe { InputDevice::init(mmio_base) } {
            Some(dev) => {
                DEVICES.with(|devs| {
                    if found < 4 {
                        devs[found] = Some(dev);
                    }
                });
                found += 1;
            }
            None => {
                log("[VINPUT] device init failed\n");
            }
        }
    }

    if found == 0 {
        log("[VINPUT] no virtio-input devices found\n");
    }
}

// ── x86_64: PS/2 handles input; virtio-input PCI is not yet wired ─────────────

#[cfg(target_arch = "x86_64")]
unsafe fn probe_mmio_devices() {
    // On x86_64 the PS/2 keyboard/mouse driver handles input.
    // virtio-input-pci support can be added here when needed.
    log("[VINPUT] x86_64: using PS/2 input; virtio-input-pci not active\n");
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Probe virtio-input devices and start the polling thread.
///
/// Called from `virtio_input_hw_init()` in virtio_input_ffi.c.
/// Returns 0 on success, negative errno on failure.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_input_rust_init() -> i32 {
    log("[VINPUT] Rust virtio-input driver starting\n");

    unsafe { probe_mmio_devices() };

    // Spawn the poll thread only once
    if !POLL_RUNNING.swap(true, Ordering::AcqRel) {
        unsafe { spawn_poll_thread() };
    }

    0
}

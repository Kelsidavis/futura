// SPDX-License-Identifier: MPL-2.0
/*
 * VirtIO console/serial device driver for Futura OS
 *
 * Implements a single-port VirtIO console (device type 3) using PCI transport
 * with standard VirtIO PCI capability discovery. Provides character-level and
 * buffer-level read/write, plus emergency write via the device config register.
 *
 * VirtIO queues:
 *   Queue 0 - receiveq  (port 0 input  - device writes data for us to read)
 *   Queue 1 - transmitq (port 0 output - we write data for device to consume)
 */

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::cmp::min;
use core::ffi::c_void;
use core::ptr::{self, write_volatile, read_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering, fence};

use common::{
    alloc_page, free_page, log, map_mmio_region, thread_yield,
    MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
}

// ── PCI device structure (mirrors kernel/pci.h) ──

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

// ── Static state wrapper ──

struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── Error codes ──

const ENODEV: i32 = -19;
const EIO: i32 = -5;
const ENOMEM: i32 = -12;

// ── VirtIO constants ──

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_DEVICE_ID_CONSOLE_LEGACY: u16 = 0x1003;
const VIRTIO_DEVICE_ID_CONSOLE_MODERN: u16 = 0x1043;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

// VirtIO console feature bits
const VIRTIO_CONSOLE_F_SIZE: u32 = 1 << 0;
#[allow(dead_code)]
const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1 << 1;
const VIRTIO_CONSOLE_F_EMERG_WRITE: u32 = 1 << 2;

// Virtqueue descriptor flags
#[allow(dead_code)]
const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

// PCI capability IDs
const PCI_CAP_ID_VNDR: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
#[allow(dead_code)]
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_MEMORY: u16 = 0x2;
const PCI_COMMAND_BUS_MASTER: u16 = 0x4;

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const PAGE_SIZE: usize = 4096;
const QUEUE_SIZE: u16 = 16;
const RX_BUF_SIZE: usize = 512;

const RX_QUEUE_IDX: u16 = 0;
const TX_QUEUE_IDX: u16 = 1;

#[cfg(target_arch = "x86_64")]
const PMAP_DIRECT_VIRT_BASE: usize = 0xFFFFFFFF80000000;
const MMIO_PTE_FLAGS: u64 = MMIO_DEFAULT_FLAGS;

// ── VirtIO PCI structures ──

#[repr(C, packed)]
#[allow(dead_code)]
struct VirtioPciCap {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    padding: [u8; 3],
    offset: u32,
    length: u32,
}

#[repr(C, packed)]
#[allow(dead_code)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: u32,
}

#[repr(C, packed)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_reserved: u16,
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_avail_lo: u32,
    queue_avail_hi: u32,
    queue_used_lo: u32,
    queue_used_hi: u32,
}

// VirtIO console device-specific config (at device config BAR offset)
#[repr(C, packed)]
#[allow(dead_code)]
struct VirtioConsoleConfig {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
}

// ── Virtqueue data structures ──

#[repr(C, packed)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE as usize],
}

// ── PCI address ──

#[repr(C)]
struct PciAddress {
    bus: u8,
    device: u8,
    function: u8,
}

// ── Virtqueue implementation ──

struct VirtQueue {
    size: u16,
    desc: *mut VirtqDesc,
    avail: *mut VirtqAvail,
    used: *mut VirtqUsed,
    desc_phys: u64,
    avail_phys: u64,
    used_phys: u64,
    notify_off: u16,
    next_avail: AtomicU16,
    last_used: AtomicU16,
    free_list: [bool; QUEUE_SIZE as usize],
}

impl VirtQueue {
    const fn new() -> Self {
        Self {
            size: 0,
            desc: ptr::null_mut(),
            avail: ptr::null_mut(),
            used: ptr::null_mut(),
            desc_phys: 0,
            avail_phys: 0,
            used_phys: 0,
            notify_off: 0,
            next_avail: AtomicU16::new(0),
            last_used: AtomicU16::new(0),
            free_list: [true; QUEUE_SIZE as usize],
        }
    }

    fn setup(&mut self, requested: u16) -> Result<(), i32> {
        unsafe {
            let desc = alloc_page() as *mut VirtqDesc;
            let avail = alloc_page() as *mut VirtqAvail;
            let used = alloc_page() as *mut VirtqUsed;

            if desc.is_null() || avail.is_null() || used.is_null() {
                if !desc.is_null() { free_page(desc.cast()); }
                if !avail.is_null() { free_page(avail.cast()); }
                if !used.is_null() { free_page(used.cast()); }
                return Err(ENOMEM);
            }

            ptr::write_bytes(desc.cast::<u8>(), 0, PAGE_SIZE);
            ptr::write_bytes(avail.cast::<u8>(), 0, PAGE_SIZE);
            ptr::write_bytes(used.cast::<u8>(), 0, PAGE_SIZE);

            self.size = requested;
            self.desc = desc;
            self.avail = avail;
            self.used = used;
            self.desc_phys = virt_to_phys(desc as usize);
            self.avail_phys = virt_to_phys(avail as usize);
            self.used_phys = virt_to_phys(used as usize);
            self.next_avail.store(0, Ordering::Relaxed);
            self.last_used.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    fn alloc_desc(&mut self) -> Option<u16> {
        for i in 0..self.size {
            if self.free_list[i as usize] {
                self.free_list[i as usize] = false;
                return Some(i);
            }
        }
        None
    }

    fn free_desc(&mut self, idx: u16) {
        if (idx as usize) < self.free_list.len() {
            self.free_list[idx as usize] = true;
        }
    }

    /// Enqueue a buffer for transmission (device reads from it).
    fn enqueue_tx(&mut self, data_phys: u64, data_len: usize) -> Result<(), i32> {
        if self.desc.is_null() || self.avail.is_null() {
            return Err(ENODEV);
        }

        let desc_idx = self.alloc_desc().ok_or(ENOMEM)?;

        unsafe {
            write_volatile(self.desc.add(desc_idx as usize), VirtqDesc {
                addr: data_phys,
                len: data_len as u32,
                flags: 0, // device-readable
                next: 0,
            });

            let avail = &mut *self.avail;
            let slot = avail.idx % self.size;
            avail.ring[slot as usize] = desc_idx;
            fence(Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.next_avail.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Enqueue a buffer for reception (device writes into it).
    fn enqueue_rx(&mut self, buf_phys: u64, buf_len: usize) -> Result<(), i32> {
        if self.desc.is_null() || self.avail.is_null() {
            return Err(ENODEV);
        }

        let desc_idx = self.alloc_desc().ok_or(ENOMEM)?;

        unsafe {
            write_volatile(self.desc.add(desc_idx as usize), VirtqDesc {
                addr: buf_phys,
                len: buf_len as u32,
                flags: VIRTQ_DESC_F_WRITE, // device-writable
                next: 0,
            });

            let avail = &mut *self.avail;
            let slot = avail.idx % self.size;
            avail.ring[slot as usize] = desc_idx;
            fence(Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.next_avail.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn has_used(&self) -> bool {
        let last = self.last_used.load(Ordering::Acquire);
        let used_idx = unsafe { read_volatile(ptr::addr_of!((*self.used).idx)) };
        used_idx != last
    }

    fn pop_used(&mut self) -> Option<(u16, u32)> {
        if !self.has_used() {
            return None;
        }

        let last = self.last_used.load(Ordering::Acquire);
        let slot = last % self.size;

        unsafe {
            let elem = (*self.used).ring[slot as usize];
            self.last_used.store(last.wrapping_add(1), Ordering::Release);
            self.free_desc(elem.id as u16);
            Some((elem.id as u16, elem.len))
        }
    }
}

// ── Main driver state ──

struct VirtioConsoleDevice {
    pci: PciAddress,
    bars: [u64; 6],
    common: *mut VirtioPciCommonCfg,
    notify_base: *mut u8,
    notify_off_multiplier: u32,
    device_cfg: *mut VirtioConsoleConfig,
    has_emerg_write: bool,

    rx_queue: VirtQueue,
    tx_queue: VirtQueue,

    // Pre-allocated RX buffers posted to receiveq
    rx_buffers: [*mut u8; QUEUE_SIZE as usize],
    rx_buffers_phys: [u64; QUEUE_SIZE as usize],

    // Single TX bounce buffer
    tx_buffer: *mut u8,
    tx_buffer_phys: u64,
}

unsafe impl Send for VirtioConsoleDevice {}
unsafe impl Sync for VirtioConsoleDevice {}

impl VirtioConsoleDevice {
    const fn uninit() -> Self {
        const NULL_PTR: *mut u8 = ptr::null_mut();
        Self {
            pci: PciAddress { bus: 0, device: 0, function: 0 },
            bars: [0; 6],
            common: ptr::null_mut(),
            notify_base: ptr::null_mut(),
            notify_off_multiplier: 0,
            device_cfg: ptr::null_mut(),
            has_emerg_write: false,

            rx_queue: VirtQueue::new(),
            tx_queue: VirtQueue::new(),
            rx_buffers: [NULL_PTR; QUEUE_SIZE as usize],
            rx_buffers_phys: [0; QUEUE_SIZE as usize],
            tx_buffer: ptr::null_mut(),
            tx_buffer_phys: 0,
        }
    }

    fn probe() -> Result<Self, i32> {
        let pci = find_device().ok_or(ENODEV)?;

        let mut dev = Self::uninit();
        dev.pci = pci;

        dev.setup_bars();

        if !dev.parse_capabilities() {
            log("virtio-console: capability parsing failed");
            return Err(ENODEV);
        }

        dev.enable_bus_master();
        dev.negotiate_features()?;
        dev.init_queues()?;
        dev.alloc_buffers()?;
        dev.post_rx_buffers()?;

        // Set DRIVER_OK to tell the device we are ready
        unsafe {
            let common = dev.common;
            let status = read_volatile(ptr::addr_of!((*common).device_status));
            write_volatile(
                ptr::addr_of_mut!((*common).device_status),
                status | VIRTIO_STATUS_DRIVER_OK,
            );
        }

        log("virtio-console: device ready");
        Ok(dev)
    }

    // ── BAR setup ──

    fn setup_bars(&mut self) {
        for idx in 0..6u8 {
            let offset = 0x10 + idx * 4;
            let value = pci_read32(self.pci.bus, self.pci.device, self.pci.function, offset);
            if (value & 0x1) != 0 {
                continue; // I/O BAR, skip
            }

            let ty = (value >> 1) & 0x3;
            let mut base = (value & 0xFFFF_FFF0) as u64;

            if ty == 0x2 && idx + 1 < 6 {
                // 64-bit BAR
                let hi = pci_read32(self.pci.bus, self.pci.device, self.pci.function, offset + 4);
                base |= (hi as u64) << 32;
            }

            self.bars[idx as usize] = base;
        }
    }

    // ── PCI capability parsing ──

    fn parse_capabilities(&mut self) -> bool {
        let status = pci_read8(self.pci.bus, self.pci.device, self.pci.function, 0x06);
        if (status & 0x10) == 0 {
            log("virtio-console: no capability list in status register");
            return false;
        }

        let mut cap_ptr = pci_read8(self.pci.bus, self.pci.device, self.pci.function, 0x34);
        if cap_ptr < 0x40 {
            log("virtio-console: capability pointer too low");
            return false;
        }

        while cap_ptr >= 0x40 && cap_ptr < 0xFF {
            let cap_id = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr);
            let next = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 1);

            if cap_id == PCI_CAP_ID_VNDR {
                self.handle_virtio_cap(cap_ptr);
            }

            if next == 0 || next == cap_ptr {
                break;
            }
            cap_ptr = next;
        }

        let ok = !self.common.is_null() && !self.notify_base.is_null();
        if !ok {
            log("virtio-console: missing required capabilities (common or notify)");
        }
        ok
    }

    fn handle_virtio_cap(&mut self, cap_ptr: u8) {
        let cfg_type = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 3);
        let bar = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 4);
        let offset = pci_read32(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 8);
        let length = pci_read32(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 12);

        if (bar as usize) >= self.bars.len() {
            return;
        }
        if self.bars[bar as usize] == 0 {
            return;
        }

        let phys = self.bars[bar as usize] + offset as u64;
        let virt = unsafe { map_mmio_region(phys, length as usize, MMIO_PTE_FLAGS) };

        match cfg_type {
            VIRTIO_PCI_CAP_COMMON_CFG => {
                self.common = virt as *mut VirtioPciCommonCfg;
                log("virtio-console: found common config");
            }
            VIRTIO_PCI_CAP_NOTIFY_CFG => {
                self.notify_base = virt;
                self.notify_off_multiplier = pci_read32(
                    self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 16,
                );
                log("virtio-console: found notify config");
            }
            VIRTIO_PCI_CAP_DEVICE_CFG => {
                self.device_cfg = virt as *mut VirtioConsoleConfig;
                log("virtio-console: found device config");
            }
            _ => {}
        }
    }

    // ── Bus master enable ──

    fn enable_bus_master(&self) {
        let mut cmd = pci_read16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND);
        cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
        pci_write16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND, cmd);
    }

    // ── Feature negotiation ──

    fn negotiate_features(&mut self) -> Result<(), i32> {
        unsafe {
            let common = self.common;

            // Reset then acknowledge
            write_volatile(ptr::addr_of_mut!((*common).device_status), 0);
            // Small delay for reset
            for _ in 0..100 { fence(Ordering::SeqCst); }

            write_volatile(
                ptr::addr_of_mut!((*common).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
            );

            // Read device features (low 32 bits)
            write_volatile(ptr::addr_of_mut!((*common).device_feature_select), 0);
            let device_features = read_volatile(ptr::addr_of!((*common).device_feature));

            // We accept SIZE and EMERG_WRITE but not MULTIPORT
            let mut driver_features = 0u32;
            if (device_features & VIRTIO_CONSOLE_F_SIZE) != 0 {
                driver_features |= VIRTIO_CONSOLE_F_SIZE;
            }
            if (device_features & VIRTIO_CONSOLE_F_EMERG_WRITE) != 0 {
                driver_features |= VIRTIO_CONSOLE_F_EMERG_WRITE;
                self.has_emerg_write = true;
            }

            write_volatile(ptr::addr_of_mut!((*common).driver_feature_select), 0);
            write_volatile(ptr::addr_of_mut!((*common).driver_feature), driver_features);

            // Set FEATURES_OK
            write_volatile(
                ptr::addr_of_mut!((*common).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
            );

            let status = read_volatile(ptr::addr_of!((*common).device_status));
            if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
                log("virtio-console: device rejected features, retrying with none");
                write_volatile(ptr::addr_of_mut!((*common).driver_feature), 0);
                write_volatile(
                    ptr::addr_of_mut!((*common).device_status),
                    VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
                );
                let status2 = read_volatile(ptr::addr_of!((*common).device_status));
                if (status2 & VIRTIO_STATUS_FEATURES_OK) == 0 {
                    log("virtio-console: feature negotiation failed");
                    return Err(EIO);
                }
                self.has_emerg_write = false;
            }

            // Log console geometry if SIZE feature accepted
            if (driver_features & VIRTIO_CONSOLE_F_SIZE) != 0 && !self.device_cfg.is_null() {
                let _cols = read_volatile(ptr::addr_of!((*self.device_cfg).cols));
                let _rows = read_volatile(ptr::addr_of!((*self.device_cfg).rows));
                log("virtio-console: console size available");
            }
        }

        log("virtio-console: feature negotiation complete");
        Ok(())
    }

    // ── Queue initialisation ──

    fn init_queues(&mut self) -> Result<(), i32> {
        unsafe {
            let common = self.common;

            // RX queue (queue 0)
            write_volatile(ptr::addr_of_mut!((*common).queue_select), RX_QUEUE_IDX);
            let max_size = read_volatile(ptr::addr_of!((*common).queue_size));
            let rx_size = min(QUEUE_SIZE, max_size);
            self.rx_queue.setup(rx_size)?;
            write_volatile(ptr::addr_of_mut!((*common).queue_size), rx_size);
            write_volatile(
                ptr::addr_of_mut!((*common).queue_desc_lo),
                (self.rx_queue.desc_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_desc_hi),
                (self.rx_queue.desc_phys >> 32) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_avail_lo),
                (self.rx_queue.avail_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_avail_hi),
                (self.rx_queue.avail_phys >> 32) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_used_lo),
                (self.rx_queue.used_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_used_hi),
                (self.rx_queue.used_phys >> 32) as u32,
            );
            write_volatile(ptr::addr_of_mut!((*common).queue_enable), 1u16);
            self.rx_queue.notify_off =
                read_volatile(ptr::addr_of!((*common).queue_notify_off));

            // TX queue (queue 1)
            write_volatile(ptr::addr_of_mut!((*common).queue_select), TX_QUEUE_IDX);
            let max_size = read_volatile(ptr::addr_of!((*common).queue_size));
            let tx_size = min(QUEUE_SIZE, max_size);
            self.tx_queue.setup(tx_size)?;
            write_volatile(ptr::addr_of_mut!((*common).queue_size), tx_size);
            write_volatile(
                ptr::addr_of_mut!((*common).queue_desc_lo),
                (self.tx_queue.desc_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_desc_hi),
                (self.tx_queue.desc_phys >> 32) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_avail_lo),
                (self.tx_queue.avail_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_avail_hi),
                (self.tx_queue.avail_phys >> 32) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_used_lo),
                (self.tx_queue.used_phys & 0xFFFF_FFFF) as u32,
            );
            write_volatile(
                ptr::addr_of_mut!((*common).queue_used_hi),
                (self.tx_queue.used_phys >> 32) as u32,
            );
            write_volatile(ptr::addr_of_mut!((*common).queue_enable), 1u16);
            self.tx_queue.notify_off =
                read_volatile(ptr::addr_of!((*common).queue_notify_off));
        }

        log("virtio-console: queues initialised");
        Ok(())
    }

    // ── Buffer allocation ──

    fn alloc_buffers(&mut self) -> Result<(), i32> {
        // Allocate RX buffers
        for i in 0..QUEUE_SIZE as usize {
            let buf = unsafe { alloc_page() };
            if buf.is_null() {
                log("virtio-console: failed to allocate RX buffer");
                return Err(ENOMEM);
            }
            let phys = virt_to_phys(buf as usize);
            self.rx_buffers[i] = buf;
            self.rx_buffers_phys[i] = phys;
        }

        // Allocate TX bounce buffer
        let tx_buf = unsafe { alloc_page() };
        if tx_buf.is_null() {
            log("virtio-console: failed to allocate TX buffer");
            return Err(ENOMEM);
        }
        self.tx_buffer = tx_buf;
        self.tx_buffer_phys = virt_to_phys(tx_buf as usize);

        Ok(())
    }

    /// Post all RX buffers to the receive queue so the device can write into them.
    fn post_rx_buffers(&mut self) -> Result<(), i32> {
        for i in 0..QUEUE_SIZE as usize {
            if self.rx_buffers[i].is_null() {
                continue;
            }
            self.rx_queue.enqueue_rx(self.rx_buffers_phys[i], RX_BUF_SIZE)?;
        }
        // Notify device that RX buffers are available
        self.notify_queue(RX_QUEUE_IDX, self.rx_queue.notify_off);
        Ok(())
    }

    // ── Notify ──

    fn notify_queue(&self, _queue_idx: u16, notify_off: u16) {
        if self.notify_base.is_null() {
            return;
        }
        let offset = notify_off as usize * self.notify_off_multiplier as usize;
        unsafe {
            write_volatile(self.notify_base.add(offset) as *mut u16, _queue_idx);
        }
    }

    // ── Write (transmit) ──

    /// Write up to `len` bytes from `data` through the TX queue.
    /// Returns number of bytes written on success.
    fn write(&mut self, data: *const u8, len: usize) -> Result<usize, i32> {
        if data.is_null() || len == 0 {
            return Ok(0);
        }

        let chunk = min(len, PAGE_SIZE);

        // Copy data into TX bounce buffer
        unsafe {
            ptr::copy_nonoverlapping(data, self.tx_buffer, chunk);
        }

        // Enqueue the TX buffer
        self.tx_queue.enqueue_tx(self.tx_buffer_phys, chunk)?;

        // Notify the device
        self.notify_queue(TX_QUEUE_IDX, self.tx_queue.notify_off);

        // Wait for the device to consume the buffer (poll used ring)
        let mut waited = 0u32;
        while !self.tx_queue.has_used() {
            waited += 1;
            if waited > 100_000 {
                log("virtio-console: TX timeout");
                return Err(EIO);
            }
            thread_yield();
        }

        // Reclaim used descriptor
        let _ = self.tx_queue.pop_used();

        Ok(chunk)
    }

    // ── Read (receive) ──

    /// Read up to `max_len` bytes into `buf` from the RX queue.
    /// Returns number of bytes read (0 if no data available).
    fn read(&mut self, buf: *mut u8, max_len: usize) -> usize {
        if buf.is_null() || max_len == 0 {
            return 0;
        }

        if !self.rx_queue.has_used() {
            return 0;
        }

        let (desc_id, used_len) = match self.rx_queue.pop_used() {
            Some(v) => v,
            None => return 0,
        };

        let idx = desc_id as usize;
        if idx >= QUEUE_SIZE as usize || self.rx_buffers[idx].is_null() {
            return 0;
        }

        let copy_len = min(used_len as usize, min(max_len, RX_BUF_SIZE));
        unsafe {
            ptr::copy_nonoverlapping(self.rx_buffers[idx], buf, copy_len);
        }

        // Re-post the RX buffer for the device to reuse
        let _ = self.rx_queue.enqueue_rx(self.rx_buffers_phys[idx], RX_BUF_SIZE);
        self.notify_queue(RX_QUEUE_IDX, self.rx_queue.notify_off);

        copy_len
    }

    /// Check whether there is data waiting in the RX used ring.
    fn data_ready(&self) -> bool {
        self.rx_queue.has_used()
    }

    // ── Emergency write ──

    /// Write a single character via the emergency write register (no queue needed).
    fn emergency_putc(&self, ch: u8) {
        if !self.has_emerg_write || self.device_cfg.is_null() {
            return;
        }
        unsafe {
            write_volatile(
                ptr::addr_of_mut!((*self.device_cfg).emerg_wr),
                ch as u32,
            );
        }
    }

    /// Put a single character via the TX queue.
    fn putc(&mut self, ch: u8) {
        unsafe {
            write_volatile(self.tx_buffer, ch);
        }
        self.tx_queue.enqueue_tx(self.tx_buffer_phys, 1).ok();
        self.notify_queue(TX_QUEUE_IDX, self.tx_queue.notify_off);

        // Brief poll for completion
        let mut waited = 0u32;
        while !self.tx_queue.has_used() {
            waited += 1;
            if waited > 50_000 {
                break;
            }
            thread_yield();
        }
        let _ = self.tx_queue.pop_used();
    }

    /// Try to get a single character from the RX queue.
    /// Returns -1 if no data is available.
    fn getc(&mut self) -> i32 {
        if !self.rx_queue.has_used() {
            return -1;
        }

        let (desc_id, used_len) = match self.rx_queue.pop_used() {
            Some(v) => v,
            None => return -1,
        };

        if used_len == 0 {
            // Re-post and return no data
            let idx = desc_id as usize;
            if idx < QUEUE_SIZE as usize {
                let _ = self.rx_queue.enqueue_rx(self.rx_buffers_phys[idx], RX_BUF_SIZE);
                self.notify_queue(RX_QUEUE_IDX, self.rx_queue.notify_off);
            }
            return -1;
        }

        let idx = desc_id as usize;
        if idx >= QUEUE_SIZE as usize || self.rx_buffers[idx].is_null() {
            return -1;
        }

        let ch = unsafe { read_volatile(self.rx_buffers[idx]) } as i32;

        // Re-post the buffer
        let _ = self.rx_queue.enqueue_rx(self.rx_buffers_phys[idx], RX_BUF_SIZE);
        self.notify_queue(RX_QUEUE_IDX, self.rx_queue.notify_off);

        ch
    }
}

// ── Global device holder ──

struct Holder {
    ready: AtomicBool,
    device: UnsafeCell<VirtioConsoleDevice>,
}

unsafe impl Sync for Holder {}

impl Holder {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            device: UnsafeCell::new(VirtioConsoleDevice::uninit()),
        }
    }
}

static DEVICE: Holder = Holder::new();

// ── Exported C API ──

#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_init() -> i32 {
    if DEVICE.ready.load(Ordering::SeqCst) {
        return 0; // already initialised
    }

    log("virtio-console: probing for hardware...");

    let device = match VirtioConsoleDevice::probe() {
        Ok(dev) => dev,
        Err(e) => {
            log("virtio-console: probe failed");
            return e;
        }
    };

    unsafe {
        let dev_ptr = DEVICE.device.get();
        ptr::write(dev_ptr, device);
    }

    DEVICE.ready.store(true, Ordering::SeqCst);
    log("virtio-console: initialisation complete");
    0
}

/// Write `len` bytes from `data` to the console. Returns bytes written or negative error.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_write(data: *const u8, len: u32) -> i32 {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return ENODEV;
    }

    let device = unsafe { &mut *DEVICE.device.get() };
    let mut remaining = len as usize;
    let mut offset = 0usize;

    while remaining > 0 {
        let src = unsafe { data.add(offset) };
        match device.write(src, remaining) {
            Ok(n) => {
                offset += n;
                remaining -= n;
                if n == 0 {
                    break; // avoid infinite loop on zero-length write
                }
            }
            Err(e) => return e,
        }
    }

    offset as i32
}

/// Read up to `max_len` bytes into `buf`. Returns bytes read (0 = no data) or negative error.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_read(buf: *mut u8, max_len: u32) -> i32 {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return ENODEV;
    }

    let device = unsafe { &mut *DEVICE.device.get() };
    device.read(buf, max_len as usize) as i32
}

/// Write a single character to the console via the TX queue.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_putc(ch: u8) {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return;
    }
    let device = unsafe { &mut *DEVICE.device.get() };
    device.putc(ch);
}

/// Read a single character from the console. Returns -1 if no data available.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_getc() -> i32 {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return -1;
    }
    let device = unsafe { &mut *DEVICE.device.get() };
    device.getc()
}

/// Returns true if there is data waiting to be read.
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_data_ready() -> bool {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return false;
    }
    let device = unsafe { &*DEVICE.device.get() };
    device.data_ready()
}

/// Emergency write: single character via device config register (no queue).
#[unsafe(no_mangle)]
pub extern "C" fn virtio_console_emerg_write(ch: u8) {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return;
    }
    let device = unsafe { &*DEVICE.device.get() };
    device.emergency_putc(ch);
}

// ── Helper: virtual-to-physical address translation ──

#[cfg(target_arch = "x86_64")]
fn virt_to_phys(virt: usize) -> u64 {
    (virt - PMAP_DIRECT_VIRT_BASE) as u64
}

#[cfg(target_arch = "aarch64")]
fn virt_to_phys(virt: usize) -> u64 {
    const KERN_VA_BASE: usize = 0xFFFFFF80_00000000;
    if virt >= KERN_VA_BASE {
        (virt - KERN_VA_BASE) as u64
    } else {
        virt as u64
    }
}

// ── PCI device discovery ──

#[cfg(target_arch = "aarch64")]
fn find_device() -> Option<PciAddress> {
    // Console device not yet supported on ARM64 MMIO transport
    log("virtio-console: ARM64 not yet supported");
    None
}

#[cfg(target_arch = "x86_64")]
fn find_device() -> Option<PciAddress> {
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let vendor = pci_read16(bus, device, function, 0x00);
                let dev_id = pci_read16(bus, device, function, 0x02);

                if vendor == VIRTIO_VENDOR_ID
                    && (dev_id == VIRTIO_DEVICE_ID_CONSOLE_LEGACY
                        || dev_id == VIRTIO_DEVICE_ID_CONSOLE_MODERN)
                {
                    log("virtio-console: found device on PCI bus");
                    return Some(PciAddress { bus, device, function });
                }
            }
        }
    }
    None
}

// ── PCI configuration space access ──

// ARM64: use C-side ECAM helpers
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn arm64_pci_read32(bus: u8, dev: u8, func: u8, reg: u16) -> u32;
    fn arm64_pci_read16(bus: u8, dev: u8, func: u8, reg: u16) -> u16;
    fn arm64_pci_read8(bus: u8, dev: u8, func: u8, reg: u16) -> u8;
    fn arm64_pci_write16(bus: u8, dev: u8, func: u8, reg: u16, value: u16);
}

#[cfg(target_arch = "aarch64")]
fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    unsafe { arm64_pci_read8(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "aarch64")]
fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    unsafe { arm64_pci_read16(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "aarch64")]
fn pci_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe { arm64_pci_read32(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "aarch64")]
fn pci_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    unsafe { arm64_pci_write16(bus, device, function, offset as u16, value) }
}

// x86_64: inline asm port I/O
#[cfg(target_arch = "x86_64")]
fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        (inl(PCI_CONFIG_DATA) >> ((offset & 3) * 8)) as u8
    }
}

#[cfg(target_arch = "x86_64")]
fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        (inl(PCI_CONFIG_DATA) >> ((offset & 2) * 8)) as u16
    }
}

#[cfg(target_arch = "x86_64")]
fn pci_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | (offset as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

#[cfg(target_arch = "x86_64")]
fn pci_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset & 0xFC) as u32);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        let old = inl(PCI_CONFIG_DATA);
        let shift = (offset & 2) * 8;
        let mask = !(0xFFFFu32 << shift);
        let new_val = (old & mask) | ((value as u32) << shift);
        outl(PCI_CONFIG_DATA, new_val);
    }
}

// ── Port I/O primitives ──

#[cfg(target_arch = "x86_64")]
unsafe fn outl(port: u16, val: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inl(port: u16) -> u32 {
    let ret: u32;
    unsafe {
        asm!("in eax, dx", out("eax") ret, in("dx") port, options(nostack, preserves_flags));
    }
    ret
}

// SPDX-License-Identifier: MPL-2.0
/*
 * Virtio-net driver for Futura OS
 *
 * Full hardware virtio-net implementation with TX/RX virtqueues
 */

#![no_std]
#![allow(unexpected_cfgs)]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{self, write_volatile, addr_of_mut, addr_of};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use common::net::{self, FutNetDev, FutNetDevOps};
use common::{alloc_page, free_page, log, map_mmio_region, thread_yield, FutStatus, RawSpinLock, MMIO_DEFAULT_FLAGS};

#[cfg(target_arch = "aarch64")]
use common::transport::MmioTransport;

#[cfg(target_arch = "x86_64")]
use common::transport::PciTransport;

// Kernel thread functions
#[repr(C)]
struct FutTask {
    _private: [u8; 0],
}

#[repr(C)]
struct FutThread {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn fut_task_create() -> *mut FutTask;
    fn fut_thread_create(
        task: *mut FutTask,
        entry: extern "C" fn(*mut c_void),
        arg: *mut c_void,
        stack_size: usize,
        priority: i32,
    ) -> *mut FutThread;
}

// Error codes
const EINVAL: FutStatus = -22;
const EMSGSIZE: FutStatus = -90;
const ENODEV: FutStatus = -19;
const ENOMEM: FutStatus = -12;
const EIO: FutStatus = -5;
const ETIMEDOUT: FutStatus = -110;

// Virtio constants
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_DEVICE_ID_NET_LEGACY: u16 = 0x1000;
const VIRTIO_DEVICE_ID_NET_MODERN: u16 = 0x1041;
const VIRTIO_DEV_NET: u32 = 1;  // VirtIO device type for network

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;
const PCI_CAP_ID_VNDR: u8 = 0x09;
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_MEMORY: u16 = 0x2;
const PCI_COMMAND_BUS_MASTER: u16 = 0x4;

const PAGE_SIZE: usize = 4096;
const QUEUE_SIZE: u16 = 16;
const MAX_FRAME: usize = 2048;
const FALLBACK_MTU: u32 = 1500;
#[cfg(target_arch = "x86_64")]
const PMAP_DIRECT_VIRT_BASE: usize = 0xFFFFFFFF80000000;
const MMIO_PTE_FLAGS: u64 = MMIO_DEFAULT_FLAGS;

const RX_QUEUE_IDX: u16 = 0;
const TX_QUEUE_IDX: u16 = 1;

const VIRTIO_NET_HDR_SIZE: usize = 12;

static DEVICE_NAME: &[u8] = b"virtio-net0\0";

// Virtio structures
#[repr(C, packed)]
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

#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
    mtu: u16,
}

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

#[repr(C, packed)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

impl VirtioNetHdr {
    const fn zero() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        }
    }
}

#[repr(C)]
struct PciAddress {
    bus: u8,
    device: u8,
    function: u8,
}

// Virtqueue implementation
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

    fn setup(&mut self, requested: u16) -> Result<(), FutStatus> {
        unsafe {
            let desc = alloc_page() as *mut VirtqDesc;
            let avail = alloc_page() as *mut VirtqAvail;
            let used = alloc_page() as *mut VirtqUsed;

            if desc.is_null() || avail.is_null() || used.is_null() {
                if !desc.is_null() {
                    free_page(desc.cast());
                }
                if !avail.is_null() {
                    free_page(avail.cast());
                }
                if !used.is_null() {
                    free_page(used.cast());
                }
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

    fn enqueue_tx(&mut self, data_phys: u64, data_len: usize) -> Result<(), FutStatus> {
        if self.desc.is_null() || self.avail.is_null() {
            return Err(ENODEV);
        }

        let desc_idx = self.alloc_desc().ok_or(ENOMEM)?;

        unsafe {
            // Single descriptor for TX (no virtio-net header needed with modern device)
            write_volatile(self.desc.add(desc_idx as usize), VirtqDesc {
                addr: data_phys,
                len: data_len as u32,
                flags: 0, // No flags - read-only descriptor
                next: 0,
            });

            let avail = &mut *self.avail;
            let slot = avail.idx % self.size;
            avail.ring[slot as usize] = desc_idx;
            core::sync::atomic::fence(Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.next_avail.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn enqueue_rx(&mut self, buf_phys: u64, buf_len: usize) -> Result<(), FutStatus> {
        if self.desc.is_null() || self.avail.is_null() {
            return Err(ENODEV);
        }

        let desc_idx = self.alloc_desc().ok_or(ENOMEM)?;

        unsafe {
            // Single write-only descriptor for RX
            write_volatile(self.desc.add(desc_idx as usize), VirtqDesc {
                addr: buf_phys,
                len: buf_len as u32,
                flags: VIRTQ_DESC_F_WRITE, // Write-only for device
                next: 0,
            });

            let avail = &mut *self.avail;
            let slot = avail.idx % self.size;
            avail.ring[slot as usize] = desc_idx;
            core::sync::atomic::fence(Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
        }

        self.next_avail.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn has_used(&self) -> bool {
        let last = self.last_used.load(Ordering::Acquire);
        let used_idx = unsafe { (*self.used).idx };
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

// Main driver state
struct VirtioNetDevice {
    pci: PciAddress,
    bars: [u64; 6],
    common: *mut VirtioPciCommonCfg,
    notify_base: *mut u8,
    notify_off_multiplier: u32,
    config: *mut VirtioNetConfig,
    rx_queue: VirtQueue,
    tx_queue: VirtQueue,
    rx_buffers: [*mut u8; QUEUE_SIZE as usize],
    rx_buffers_phys: [u64; QUEUE_SIZE as usize],
    tx_buffer: *mut u8,
    tx_buffer_phys: u64,
    io_lock: RawSpinLock,
    dev: FutNetDev,
    ops: FutNetDevOps,
}

unsafe impl Send for VirtioNetDevice {}
unsafe impl Sync for VirtioNetDevice {}

impl VirtioNetDevice {
    const fn uninit() -> Self {
        const NULL_PTR: *mut u8 = ptr::null_mut();
        Self {
            pci: PciAddress { bus: 0, device: 0, function: 0 },
            bars: [0; 6],
            common: ptr::null_mut(),
            notify_base: ptr::null_mut(),
            notify_off_multiplier: 0,
            config: ptr::null_mut(),
            rx_queue: VirtQueue::new(),
            tx_queue: VirtQueue::new(),
            rx_buffers: [NULL_PTR; QUEUE_SIZE as usize],
            rx_buffers_phys: [0; QUEUE_SIZE as usize],
            tx_buffer: ptr::null_mut(),
            tx_buffer_phys: 0,
            io_lock: RawSpinLock::new(),
            dev: FutNetDev {
                name: ptr::null(),
                mtu: 0,
                features: 0,
                driver_ctx: ptr::null_mut(),
                ops: ptr::null(),
                handle: 0,
                next: ptr::null_mut(),
            },
            ops: FutNetDevOps { tx: None, irq_ack: None },
        }
    }

    fn probe() -> Result<Self, FutStatus> {
        let pci = find_device().ok_or(ENODEV)?;

        let mut dev = Self::uninit();
        dev.pci = pci;

        // Platform-specific device initialization
        #[cfg(target_arch = "x86_64")]
        {
            dev.setup_bars();
            log("virtio-net: All BARs after setup (nonzero only):");

            if !dev.parse_capabilities() {
                log("virtio-net: capability parsing failed");
                return Err(ENODEV);
            }

            dev.enable_bus_master();
        }

        #[cfg(target_arch = "aarch64")]
        {
            log("virtio-net: ARM64 MMIO initialization - skipping PCI setup");
            // MMIO device setup is handled by C layer (virtio_mmio_setup_device)
            // No BARs, capabilities, or bus mastering on MMIO devices
        }

        dev.negotiate_features()?;
        dev.init_queues()?;
        dev.alloc_buffers()?;
        dev.setup_rx_buffers()?;

        Ok(dev)
    }

    fn setup_bars(&mut self) {
        // On ARM64, assign all BARs first, then read them
        #[cfg(target_arch = "aarch64")]
        {
            for idx in 0..6u8 {
                let assigned = unsafe { arm64_pci_assign_bar(self.pci.bus, self.pci.device, self.pci.function, idx) };
                self.bars[idx as usize] = assigned;
            }
            return;
        }

        // x86_64: BARs already assigned by BIOS, just read them
        #[cfg(target_arch = "x86_64")]
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

    fn parse_capabilities(&mut self) -> bool {
        let status = pci_read8(self.pci.bus, self.pci.device, self.pci.function, 0x06);
        if (status & 0x10) == 0 {
            log("virtio-net: No capability list in status register");
            return false; // No capability list
        }

        let mut cap_ptr = pci_read8(self.pci.bus, self.pci.device, self.pci.function, 0x34);
        if cap_ptr < 0x40 {
            log("virtio-net: Capability pointer too low");
            return false;
        }

        let mut cap_count = 0;
        while cap_ptr >= 0x40 && cap_ptr < 0xFF {
            let cap_id = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr);
            let next = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 1);

            if cap_id == PCI_CAP_ID_VNDR {
                cap_count += 1;
                self.handle_virtio_cap(cap_ptr);
            }

            if next == 0 || next == cap_ptr {
                break;
            }
            cap_ptr = next;
        }

        let result = !self.common.is_null() && !self.notify_base.is_null();
        if !result {
            log("virtio-net: Missing required capabilities (common or notify)");
        }
        result
    }

    fn handle_virtio_cap(&mut self, cap_ptr: u8) {
        let cfg_type = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 3);
        let bar = pci_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 4);
        let offset = pci_read32(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 8);
        let length = pci_read32(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 12);

        if (bar as usize) >= self.bars.len() {
            return; // Invalid BAR index, skip this capability
        }

        if self.bars[bar as usize] == 0 {
            return; // BAR not assigned, skip this capability
        }

        let phys = self.bars[bar as usize] + offset as u64;

        // On ARM64 with MMU disabled, physical addresses are virtual addresses
        #[cfg(target_arch = "aarch64")]
        let virt = phys as *mut u8;

        // On x86_64, we need to map the MMIO region
        #[cfg(target_arch = "x86_64")]
        let virt = unsafe { map_mmio_region(phys, length as usize, MMIO_PTE_FLAGS) };

        match cfg_type {
            VIRTIO_PCI_CAP_COMMON_CFG => {
                self.common = virt as *mut VirtioPciCommonCfg;
                log("virtio-net: Found common config");
            }
            VIRTIO_PCI_CAP_NOTIFY_CFG => {
                self.notify_base = virt;
                self.notify_off_multiplier = pci_read32(self.pci.bus, self.pci.device, self.pci.function, cap_ptr + 16);
                log("virtio-net: Found notify");
            }
            VIRTIO_PCI_CAP_DEVICE_CFG => {
                self.config = virt as *mut VirtioNetConfig;
                log("virtio-net: Found device config");
            }
            _ => {}
        }
    }

    fn enable_bus_master(&self) {
        let mut cmd = pci_read16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND);
        cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
        pci_write16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND, cmd);
    }

    fn negotiate_features(&mut self) -> Result<(), FutStatus> {
        unsafe {
            let common = self.common;

            // Acknowledge device
            write_volatile(addr_of_mut!((*common).device_status), VIRTIO_STATUS_ACKNOWLEDGE);

            // Announce driver
            write_volatile(addr_of_mut!((*common).device_status), VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

            // Read device features
            write_volatile(addr_of_mut!((*common).device_feature_select), 0);
            let device_features = ptr::read_volatile(addr_of!((*common).device_feature));

            log("virtio-net: Device offers features");

            // Accept all offered features for now
            write_volatile(addr_of_mut!((*common).driver_feature_select), 0);
            write_volatile(addr_of_mut!((*common).driver_feature), device_features);

            write_volatile(addr_of_mut!((*common).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

            let status = ptr::read_volatile(addr_of!((*common).device_status));
            if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
                log("virtio-net: WARNING - Device rejected our feature selection");
                // Try again with no features
                write_volatile(addr_of_mut!((*common).driver_feature), 0);
                write_volatile(addr_of_mut!((*common).device_status),
                    VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
                let status2 = ptr::read_volatile(addr_of!((*common).device_status));
                if (status2 & VIRTIO_STATUS_FEATURES_OK) == 0 {
                    return Err(EIO);
                }
            }
        }
        Ok(())
    }

    fn init_queues(&mut self) -> Result<(), FutStatus> {
        unsafe {
            let common = self.common;

            // Setup RX queue
            write_volatile(addr_of_mut!((*common).queue_select), RX_QUEUE_IDX);
            self.rx_queue.setup(QUEUE_SIZE)?;
            write_volatile(addr_of_mut!((*common).queue_size), QUEUE_SIZE);
            write_volatile(addr_of_mut!((*common).queue_desc_lo), (self.rx_queue.desc_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_desc_hi), (self.rx_queue.desc_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_avail_lo), (self.rx_queue.avail_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_avail_hi), (self.rx_queue.avail_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_used_lo), (self.rx_queue.used_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_used_hi), (self.rx_queue.used_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_enable), 1);
            self.rx_queue.notify_off = ptr::read_volatile(addr_of!((*common).queue_notify_off));

            // Setup TX queue
            write_volatile(addr_of_mut!((*common).queue_select), TX_QUEUE_IDX);
            self.tx_queue.setup(QUEUE_SIZE)?;
            write_volatile(addr_of_mut!((*common).queue_size), QUEUE_SIZE);
            write_volatile(addr_of_mut!((*common).queue_desc_lo), (self.tx_queue.desc_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_desc_hi), (self.tx_queue.desc_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_avail_lo), (self.tx_queue.avail_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_avail_hi), (self.tx_queue.avail_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_used_lo), (self.tx_queue.used_phys & 0xFFFFFFFF) as u32);
            write_volatile(addr_of_mut!((*common).queue_used_hi), (self.tx_queue.used_phys >> 32) as u32);
            write_volatile(addr_of_mut!((*common).queue_enable), 1);
            self.tx_queue.notify_off = ptr::read_volatile(addr_of!((*common).queue_notify_off));
        }
        Ok(())
    }

    fn alloc_buffers(&mut self) -> Result<(), FutStatus> {
        // Allocate RX buffers
        for i in 0..QUEUE_SIZE as usize {
            let buf = unsafe { alloc_page() };
            if buf.is_null() {
                return Err(ENOMEM);
            }
            self.rx_buffers[i] = buf;
            self.rx_buffers_phys[i] = virt_to_phys(buf as usize);
        }

        // Allocate TX buffer
        self.tx_buffer = unsafe { alloc_page() };
        if self.tx_buffer.is_null() {
            return Err(ENOMEM);
        }
        self.tx_buffer_phys = virt_to_phys(self.tx_buffer as usize);

        Ok(())
    }

    fn setup_rx_buffers(&mut self) -> Result<(), FutStatus> {
        // Populate RX queue with all buffers
        for i in 0..QUEUE_SIZE as usize {
            self.rx_queue.enqueue_rx(self.rx_buffers_phys[i], MAX_FRAME)?;
        }
        self.notify_queue(RX_QUEUE_IDX);

        // Mark driver OK - device can now start DMA
        unsafe {
            let common = self.common;
            write_volatile(addr_of_mut!((*common).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
        }

        Ok(())
    }

    fn notify_queue(&self, queue_idx: u16) {
        let notify_off = if queue_idx == RX_QUEUE_IDX {
            self.rx_queue.notify_off
        } else {
            self.tx_queue.notify_off
        };

        let offset = notify_off as u32 * self.notify_off_multiplier;
        unsafe {
            let notify_addr = self.notify_base.add(offset as usize) as *mut u16;
            write_volatile(notify_addr, queue_idx);
        }
    }

    fn transmit(&mut self, frame: *const c_void, len: usize) -> FutStatus {
        if frame.is_null() || len == 0 || len > MAX_FRAME {
            return EINVAL;
        }

        self.io_lock.lock();

        // Write zero-filled virtio-net header (12 bytes)
        unsafe {
            ptr::write_bytes(self.tx_buffer, 0, VIRTIO_NET_HDR_SIZE);
        }

        // Copy frame after the header
        unsafe {
            ptr::copy_nonoverlapping(
                frame as *const u8,
                self.tx_buffer.add(VIRTIO_NET_HDR_SIZE),
                len
            );
        }

        // Enqueue to TX virtqueue (header + frame)
        let total_len = VIRTIO_NET_HDR_SIZE + len;
        if let Err(e) = self.tx_queue.enqueue_tx(self.tx_buffer_phys, total_len) {
            self.io_lock.unlock();
            return e;
        }

        // Notify device
        self.notify_queue(TX_QUEUE_IDX);

        // Wait for completion (simple polling)
        let mut retries = 0;
        while !self.tx_queue.has_used() {
            if retries > 1000 {
                self.io_lock.unlock();
                return ETIMEDOUT;
            }
            thread_yield();
            retries += 1;
        }

        // Pop the used descriptor
        let _ = self.tx_queue.pop_used();

        self.io_lock.unlock();
        0
    }

    fn poll_rx(&mut self) -> Option<(&[u8], usize)> {
        if !self.rx_queue.has_used() {
            return None;
        }

        let (desc_idx, len) = self.rx_queue.pop_used()?;
        if (desc_idx as usize) >= self.rx_buffers.len() {
            return None;
        }

        // Packet includes virtio-net header at the beginning
        if len < VIRTIO_NET_HDR_SIZE as u32 {
            // Invalid packet - too small
            let buf_phys = self.rx_buffers_phys[desc_idx as usize];
            let _ = self.rx_queue.enqueue_rx(buf_phys, MAX_FRAME);
            self.notify_queue(RX_QUEUE_IDX);
            return None;
        }

        let buf = self.rx_buffers[desc_idx as usize];
        // Skip virtio-net header, return only packet data
        let packet_len = (len as usize) - VIRTIO_NET_HDR_SIZE;
        let data = unsafe { core::slice::from_raw_parts(buf.add(VIRTIO_NET_HDR_SIZE), packet_len) };

        // Re-queue the buffer for next RX
        let buf_phys = self.rx_buffers_phys[desc_idx as usize];
        let _ = self.rx_queue.enqueue_rx(buf_phys, MAX_FRAME);
        self.notify_queue(RX_QUEUE_IDX);

        Some((data, packet_len))
    }
}

// Global device instance
struct Holder {
    ready: AtomicBool,
    device: UnsafeCell<VirtioNetDevice>,
}

unsafe impl Sync for Holder {}

impl Holder {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            device: UnsafeCell::new(VirtioNetDevice::uninit()),
        }
    }
}

static DEVICE: Holder = Holder::new();

// RX polling thread
extern "C" fn rx_poll_thread(_arg: *mut c_void) {
    log("virtio-net: RX polling thread started");

    // Wait for device to be ready
    let mut wait_count = 0;
    while !DEVICE.ready.load(Ordering::SeqCst) {
        wait_count += 1;
        if wait_count % 1000 == 0 {
            log("virtio-net: RX thread waiting for device ready");
        }
        thread_yield();
    }

    log("virtio-net: RX thread device is ready, starting polling loop");

    let mut poll_count = 0u64;
    let mut rx_count = 0u64;
    let mut first_iter = true;

    loop {
        let device = unsafe { &mut *DEVICE.device.get() };
        let dev_ptr = &mut device.dev as *mut FutNetDev;

        // Poll for received packets
        poll_count += 1;

        if let Some((data, len)) = device.poll_rx() {
            rx_count += 1;

            // Log first 10 packets with details
            if rx_count <= 10 {
                log("virtio-net: RX packet from hardware");

                // Log first 14 bytes (Ethernet header)
                if len >= 14 {
                    unsafe {
                        let dst_mac = core::slice::from_raw_parts(data.as_ptr(), 6);
                        let src_mac = core::slice::from_raw_parts(data.as_ptr().add(6), 6);

                        log("  Dst MAC: ");
                        log("  Src MAC: ");
                    }
                }
            }

            // Submit to network stack
            unsafe {
                net::submit_rx(dev_ptr, data.as_ptr(), len);
            }
        } else {
            // No packets, yield to other threads
            thread_yield();
        }
    }
}

// Driver callbacks
unsafe extern "C" fn tx_callback(_dev: *mut FutNetDev, frame: *const c_void, len: usize) -> FutStatus {
    if !DEVICE.ready.load(Ordering::SeqCst) {
        return ENODEV;
    }

    let device = unsafe { &mut *DEVICE.device.get() };
    device.transmit(frame, len)
}

// Public init function
#[unsafe(no_mangle)]
pub extern "C" fn virtio_net_init() -> FutStatus {
    if DEVICE.ready.load(Ordering::SeqCst) {
        return 0;
    }

    log("virtio-net: probing for hardware...");

    let device = match VirtioNetDevice::probe() {
        Ok(dev) => dev,
        Err(e) => {
            log("virtio-net: probe failed, using loopback fallback");
            return e;
        }
    };

    unsafe {
        let dev_ptr = DEVICE.device.get();
        ptr::write(dev_ptr, device);

        let device = &mut *dev_ptr;

        // Setup device ops
        device.ops = FutNetDevOps {
            tx: Some(tx_callback),
            irq_ack: None,
        };

        // Setup net device
        device.dev = FutNetDev {
            name: DEVICE_NAME.as_ptr().cast(),
            mtu: FALLBACK_MTU,
            features: 0,
            driver_ctx: device as *mut _ as *mut c_void,
            ops: &device.ops,
            handle: 0,
            next: ptr::null_mut(),
        };

        // Register with network subsystem
        match net::register(&mut device.dev) {
            Ok(()) => {
                DEVICE.ready.store(true, Ordering::SeqCst);
                log("virtio-net: hardware initialization successful");

                // Start RX polling thread
                let task = fut_task_create();
                if task.is_null() {
                    log("virtio-net: WARNING: Failed to create task for RX thread");
                } else {
                    let rx_thread = fut_thread_create(
                        task,
                        rx_poll_thread,
                        ptr::null_mut(),
                        8192,  // stack size
                        100,   // priority
                    );

                    if !rx_thread.is_null() {
                        // Note: fut_thread_create() already adds thread to scheduler
                        log("virtio-net: RX polling thread created");
                    } else {
                        log("virtio-net: WARNING: Failed to create RX thread");
                    }
                }

                0
            }
            Err(e) => {
                log("virtio-net: registration failed");
                e
            }
        }
    }
}

// Helper functions
#[cfg(target_arch = "x86_64")]
fn virt_to_phys(virt: usize) -> u64 {
    (virt - PMAP_DIRECT_VIRT_BASE) as u64
}

#[cfg(target_arch = "aarch64")]
fn virt_to_phys(virt: usize) -> u64 {
    // ARM64: MMU disabled, addresses are already physical
    virt as u64
}

// Platform-conditional device detection
#[cfg(target_arch = "aarch64")]
fn find_device() -> Option<PciAddress> {
    // On ARM64, use MMIO transport via C layer
    if let Some(_transport) = MmioTransport::find_device(VIRTIO_DEV_NET) {
        log("virtio-net: found device via MMIO transport");
        // Return placeholder PciAddress - actual MMIO operations will bypass PCI layer
        return Some(PciAddress { bus: 0xFF, device: 0xFF, function: 0xFF });
    }
    None
}

#[cfg(target_arch = "x86_64")]
fn find_device() -> Option<PciAddress> {
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                let vendor = pci_read16(bus, device, function, 0x00);
                let dev_id = pci_read16(bus, device, function, 0x02);

                if vendor == VIRTIO_VENDOR_ID &&
                   (dev_id == VIRTIO_DEVICE_ID_NET_LEGACY || dev_id == VIRTIO_DEVICE_ID_NET_MODERN) {
                    log("virtio-net: found device at PCI");
                    return Some(PciAddress { bus, device, function });
                }
            }
        }
    }
    None
}

// Platform-specific PCI access
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

#[cfg(target_arch = "aarch64")]
fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    unsafe { arm64_pci_read8(bus, device, function, offset as u16) }
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

#[cfg(target_arch = "aarch64")]
fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    unsafe { arm64_pci_read16(bus, device, function, offset as u16) }
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

#[cfg(target_arch = "aarch64")]
fn pci_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe { arm64_pci_read32(bus, device, function, offset as u16) }
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
        let new = (old & mask) | ((value as u32) << shift);
        outl(PCI_CONFIG_DATA, new);
    }
}

#[cfg(target_arch = "aarch64")]
fn pci_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    unsafe { arm64_pci_write16(bus, device, function, offset as u16, value) }
}

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

// ARM64 PCI ECAM functions
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn arm64_pci_read32(bus: u8, dev: u8, func: u8, reg: u16) -> u32;
    fn arm64_pci_read16(bus: u8, dev: u8, func: u8, reg: u16) -> u16;
    fn arm64_pci_read8(bus: u8, dev: u8, func: u8, reg: u16) -> u8;
    fn arm64_pci_write16(bus: u8, dev: u8, func: u8, reg: u16, value: u16);
    fn arm64_pci_assign_bar(bus: u8, dev: u8, func: u8, bar_num: u8) -> u64;
}

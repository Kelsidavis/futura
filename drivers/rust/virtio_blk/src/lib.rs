// SPDX-License-Identifier: MPL-2.0
/*
 * rust virtio-blk driver for Futura OS blkcore
 */

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

// # QEMU runline for testing:
// #   qemu-system-x86_64 \
// #      -serial stdio \
// #      -drive if=virtio,file=disk.img,format=raw \
// #      -m 512 -cdrom futura.iso

use core::arch::asm;
use core::cmp::min;
use core::ffi::{c_char, c_void};
use core::mem::{size_of, MaybeUninit};
use core::ptr::{self, write_volatile, read_volatile};
use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

use common::{
    alloc, alloc_page, free, free_page, log, map_mmio_region, register, thread_yield, unmap_mmio_region,
    FutBlkBackend, FutBlkDev, FutStatus, RawSpinLock, SpinLock, FUT_BLK_ADMIN, FUT_BLK_READ,
    FUT_BLK_WRITE, MMIO_DEFAULT_FLAGS,
};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_idt_set_entry(vector: u8, handler: u64, selector: u16, type_attr: u8, ist: u8);
}

const GDT_KERNEL_CODE: u16 = 0x08;     // Kernel code segment
const IDT_TYPE_INTERRUPT: u8 = 0x8E;   // Interrupt gate
const INT_IRQ_BASE: u8 = 32;           // IRQ vectors start at 32

// IRQ vector is determined dynamically from PCI interrupt line
static VIRTIO_BLK_IRQ_VECTOR: AtomicU8 = AtomicU8::new(0);

// Global completion flag for interrupt handler
static IO_COMPLETED: AtomicU8 = AtomicU8::new(0);

// MSI-X table entry structure
#[repr(C, packed)]
struct MsixTableEntry {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_control: u32,
}

// MSI-X constants
const MSIX_VECTOR_MASKED: u32 = 0x1;
const APIC_BASE_ADDR: u32 = 0xFEE00000;  // Local APIC base address for MSI-X

// Interrupt handler for virtio-blk I/O completion
#[unsafe(naked)]
unsafe extern "C" fn virtio_blk_irq_handler() {
    core::arch::naked_asm!(
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "call {handler}",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "iretq",
        handler = sym virtio_blk_irq_handler_inner,
    );
}

// Inner interrupt handler logic
extern "C" fn virtio_blk_irq_handler_inner() {
    // Signal I/O completion
    IO_COMPLETED.store(1, Ordering::Release);

    // Send EOI to PIC (End of Interrupt)
    unsafe {
        let irq = VIRTIO_BLK_IRQ_VECTOR.load(Ordering::Relaxed).saturating_sub(INT_IRQ_BASE);

        // If IRQ >= 8, send EOI to slave PIC first
        if irq >= 8 {
            outb(0xA0, 0x20);  // EOI to slave PIC
        }

        // Always send EOI to master PIC
        outb(0x20, 0x20);  // EOI to master PIC
    }
}

unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    value
}

// Unmask an IRQ in the PIC
unsafe fn pic_unmask_irq(irq: u8) {
    unsafe {
        let port = if irq < 8 { 0x21 } else { 0xA1 };  // PIC1 or PIC2 data port
        let irq_bit = irq % 8;

        let mask = inb(port);
        let new_mask = mask & !(1 << irq_bit);  // Clear the bit to unmask
        outb(port, new_mask);

        fut_printf(b"[virtio-blk] Unmasked IRQ %d: old_mask=0x%x new_mask=0x%x port=0x%x\n\0".as_ptr(),
            irq as u32, mask as u32, new_mask as u32, port as u32);
    }
}

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const PCI_CAP_ID_VNDR: u8 = 0x09;
const PCI_CAP_ID_MSIX: u8 = 0x11;
const PCI_EXT_CAP_ID_VSEC: u16 = 0x000B;
const PCI_EXT_CAP_OFFSET: u32 = 0x100;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_DEVICE_ID_BLOCK_LEGACY: u16 = 0x1001;
const VIRTIO_DEVICE_ID_BLOCK_MODERN: u16 = 0x1042;

const PCI_COMMAND: u8 = 0x04;
const PCI_COMMAND_IO: u16 = 0x1;
const PCI_COMMAND_MEMORY: u16 = 0x2;
const PCI_COMMAND_BUS_MASTER: u16 = 0x4;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const PAGE_SIZE: usize = 4096;
const QUEUE_SIZE: u16 = 8;
const DMA_STATUS_OFFSET: u64 = size_of::<VirtioBlkReqHeader>() as u64;
const PMAP_DIRECT_VIRT_BASE: usize = 0xFFFFFFFF80000000;

const MMIO_PTE_FLAGS: u64 = MMIO_DEFAULT_FLAGS;
const MAX_CAP_LENGTH: usize = 64;
const MAX_VSEC_LENGTH: usize = 256;

const PCI_ECAM_BASE: u64 = 0xE000_0000;
const PCI_ECAM_BUS_STRIDE: u64 = 1 << 20;
const PCI_ECAM_DEVICE_STRIDE: u64 = 1 << 15;
const PCI_ECAM_FUNCTION_STRIDE: u64 = 1 << 12;
const PCI_ECAM_FN_SIZE: usize = 0x1000;

const ENODEV: FutStatus = -19;
const EIO: FutStatus = -5;
const ENOMEM: FutStatus = -12;
const EINVAL: FutStatus = -22;
const ENOTSUP: FutStatus = -95;
const ETIMEDOUT: FutStatus = -110;

#[cfg(debug_blk)]
const DEBUG_BLK_TRACE: bool = true;
#[cfg(not(debug_blk))]
const DEBUG_BLK_TRACE: bool = false;

#[repr(C)]
#[derive(Clone, Copy)]
struct PciAddress {
    bus: u8,
    device: u8,
    function: u8,
}

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
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    cylinders: u16,
    heads: u8,
    sectors: u8,
    blk_size: u32,
    topology: u32,
    writeback: u8,
    unused0: [u8; 3],
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    unused1: [u8; 3],
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
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

#[repr(C, align(16))]
struct VirtioBlkDma {
    header: VirtioBlkReqHeader,
    status: u8,
    pad: [u8; 7],
}

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
        }
    }

    fn setup(&mut self, requested: u16) -> Result<(), FutStatus> {
        unsafe {
            /* QEMU requires 64KB alignment for descriptor tables.
             * Allocate 16 pages and manually align to 64KB boundary. */
            const ALIGN_64KB: usize = 0x10000;
            let desc_raw = alloc_page() as usize;
            let avail = alloc_page() as *mut VirtqAvail;
            let used = alloc_page() as *mut VirtqUsed;

            /* Align desc to 64KB */
            let desc_aligned = (desc_raw + ALIGN_64KB - 1) & !(ALIGN_64KB - 1);
            let desc = desc_aligned as *mut VirtqDesc;

            if desc_raw == 0 || avail.is_null() || used.is_null() {
                if desc_raw != 0 {
                    free_page(desc_raw as *mut u8);
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
            self.desc_phys = virt_to_phys_addr(desc as usize);
            self.avail_phys = virt_to_phys_addr(avail as usize);
            self.used_phys = virt_to_phys_addr(used as usize);
            self.next_avail.store(0, Ordering::Relaxed);
            self.last_used.store(0, Ordering::Relaxed);
        }
        Ok(())
    }

    fn enqueue(
        &self,
        header_phys: u64,
        data_phys: u64,
        status_phys: u64,
        req_type: u32,
        data_len: usize,
        write: bool,
    ) -> Result<(), FutStatus> {
        if self.desc.is_null() || self.avail.is_null() {
            return Err(ENODEV);
        }
        let slot = self.next_avail.load(Ordering::Relaxed) % self.size;

        // Each slot uses 3 descriptors (header, data, status)
        const DESCS_PER_REQ: u16 = 3;
        let desc_head = (slot * DESCS_PER_REQ) % self.size;
        let desc_data = (desc_head + 1) % self.size;
        let desc_status = (desc_head + 2) % self.size;

        unsafe {
            // Header descriptor
            write_volatile(self.desc.add(desc_head as usize), VirtqDesc {
                addr: header_phys,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: if req_type == VIRTIO_BLK_T_FLUSH { desc_status } else { desc_data },
            });
            fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=%d flags=0x%x next=%d\n\0".as_ptr(),
                desc_head as u32, header_phys, size_of::<VirtioBlkReqHeader>() as u32,
                VIRTQ_DESC_F_NEXT as u32,
                if req_type == VIRTIO_BLK_T_FLUSH { desc_status } else { desc_data } as u32);

            if req_type != VIRTIO_BLK_T_FLUSH {
                let mut flags = VIRTQ_DESC_F_NEXT;
                if !write {
                    flags |= VIRTQ_DESC_F_WRITE;
                }
                write_volatile(self.desc.add(desc_data as usize), VirtqDesc {
                    addr: data_phys,
                    len: data_len as u32,
                    flags,
                    next: desc_status,
                });
                fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=%d flags=0x%x next=%d\n\0".as_ptr(),
                    desc_data as u32, data_phys, data_len as u32, flags as u32, desc_status as u32);
            }

            // Status descriptor
            write_volatile(self.desc.add(desc_status as usize), VirtqDesc {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            });
            fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=1 flags=0x%x next=0\n\0".as_ptr(),
                desc_status as u32, status_phys, VIRTQ_DESC_F_WRITE as u32);

            let avail = &mut *self.avail;
            avail.ring[slot as usize] = desc_head;  // Point to the head descriptor for this chain
            core::sync::atomic::fence(Ordering::SeqCst);
            let old_idx = avail.idx;
            avail.idx = avail.idx.wrapping_add(1);
            fut_printf(b"[virtio-blk] enqueue: slot=%d desc_head=%d avail.idx %d -> %d avail.flags=%d\n\0".as_ptr(),
                slot as u32, desc_head as u32, old_idx as u32, avail.idx as u32, avail.flags as u32);
        }
        self.next_avail.fetch_add(1, Ordering::Release);
        Ok(())
    }

    fn poll_completion(&self, isr_ptr: *const u8) -> FutStatus {
        let mut waited = 0u32;
        const TIMEOUT_ITERATIONS: u32 = 1_000_000;  // Increased timeout for interrupt-driven I/O

        let irq_vector = VIRTIO_BLK_IRQ_VECTOR.load(Ordering::Relaxed);
        unsafe {
            fut_printf(b"[virtio-blk] waiting for interrupt (vector=%d)...\n\0".as_ptr(),
                irq_vector as u32);
        }

        loop {
            // Read ISR register - this is critical in Virtio 1.0!
            // Reading it acknowledges the interrupt and may trigger device processing
            let mut isr_status = 0u8;
            if !isr_ptr.is_null() {
                unsafe {
                    isr_status = *isr_ptr;
                }
            }

            // Check used ring directly (device might update it without interrupt)
            let last = self.last_used.load(Ordering::Acquire);
            let used_idx = unsafe { (*self.used).idx };

            // Check if interrupt handler signaled completion
            let int_flag = IO_COMPLETED.load(Ordering::Acquire);
            if int_flag != 0 || used_idx != last {
                // Clear the flag for next I/O
                IO_COMPLETED.store(0, Ordering::Release);

                unsafe {
                    if int_flag != 0 {
                        fut_printf(b"[virtio-blk] interrupt received! last_used=%d used_idx=%d isr=0x%x\n\0".as_ptr(),
                            last as u32, used_idx as u32, isr_status as u32);
                    } else {
                        fut_printf(b"[virtio-blk] completion without interrupt! last_used=%d used_idx=%d isr=0x%x\n\0".as_ptr(),
                            last as u32, used_idx as u32, isr_status as u32);
                    }
                }

                if used_idx != last {
                    self.last_used.store(last.wrapping_add(1), Ordering::Release);
                    return 0;
                } else {
                    unsafe {
                        fut_printf(b"[virtio-blk] WARNING: interrupt but no used ring update\n\0".as_ptr());
                    }
                }
            }

            if waited == 10000 {
                unsafe {
                    fut_printf(b"[virtio-blk] still waiting after 10k iterations... (used=%d last=%d isr=0x%x)\n\0".as_ptr(),
                        used_idx as u32, last as u32, isr_status as u32);
                }
            }

            if waited > TIMEOUT_ITERATIONS {
                unsafe {
                    fut_printf(b"[virtio-blk] TIMEOUT: no interrupt received (last=%d used=%d isr=0x%x)\n\0".as_ptr(),
                        last as u32, used_idx as u32, isr_status as u32);
                }
                return ETIMEDOUT;
            }

            core::hint::spin_loop();
            waited += 1;
        }
    }
}

struct VirtioBlkDevice {
    pci: PciAddress,
    bars: [u64; 6],
    common: *mut VirtioPciCommonCfg,
    isr: *mut u8,
    config: *mut VirtioBlkConfig,
    notify_base: *mut u8,
    notify_off_multiplier: u32,
    msix_table_bar: u8,
    msix_table_offset: u32,
    msix_pba_bar: u8,
    msix_pba_offset: u32,
    msix_table_size: u16,
    msix_enabled: bool,
    msix_table: *mut u8,
    queue: VirtQueue,
    dma: *mut VirtioBlkDma,
    dma_phys: u64,
    capacity_sectors: u64,
    block_size: u32,
    has_flush: bool,
    io_lock: RawSpinLock,
    blk_dev: MaybeUninit<FutBlkDev>,
}

unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    fn probe(pci_hint: u64) -> Result<Self, FutStatus> {
        let pci = match find_device(pci_hint) {
            Some(addr) => addr,
            None => {
                log("virtio-blk: no virtio device found");
                return Err(ENODEV);
            }
        };

        let mut dev = Self {
            pci,
            bars: [0; 6],
            common: ptr::null_mut(),
            isr: ptr::null_mut(),
            config: ptr::null_mut(),
            notify_base: ptr::null_mut(),
            notify_off_multiplier: 0,
            msix_table_bar: 0,
            msix_table_offset: 0,
            msix_pba_bar: 0,
            msix_pba_offset: 0,
            msix_table_size: 0,
            msix_enabled: false,
            msix_table: ptr::null_mut(),
            queue: VirtQueue::new(),
            dma: ptr::null_mut(),
            dma_phys: 0,
            capacity_sectors: 0,
            block_size: 512,
            has_flush: false,
            io_lock: RawSpinLock::new(),
            blk_dev: MaybeUninit::uninit(),
        };

        dev.setup_bars();
        if !dev.parse_capabilities() {
            log("virtio-blk: capability discovery failed");
            return Err(ENODEV);
        }
        dev.enable_bus_master();
        dev.negotiate_features()?;
        dev.init_queue()?;
        dev.init_dma()?;
        dev.setup_interrupt()?;
        dev.read_geometry();

        /* Set DRIVER_OK after all setup is complete (required by virtio spec) */
        unsafe {
            (*dev.common).device_status |= VIRTIO_STATUS_DRIVER_OK;
            let final_status = (*dev.common).device_status;
            let queue_enabled = (*dev.common).queue_enable;
            fut_printf(b"[virtio-blk] DRIVER_OK set: status=0x%x queue_enable=%d\n\0".as_ptr(),
                final_status as u32, queue_enabled as u32);
        }

        Ok(dev)
    }

    fn setup_bars(&mut self) {
        let mut idx = 0u8;
        while idx < 6 {
            let offset = 0x10 + idx * 4;
            let value = pci_config_read32(self.pci.bus, self.pci.device, self.pci.function, offset);
            if (value & 0x1) != 0 {
                self.bars[idx as usize] = 0;
                idx += 1;
                continue;
            }

            let ty = (value >> 1) & 0x3;
            let mut base = (value & 0xFFFF_FFF0) as u64;
            let current = idx;

            if ty == 0x2 && idx + 1 < 6 {
                let hi = pci_config_read32(self.pci.bus, self.pci.device, self.pci.function, offset + 4);
                base |= (hi as u64) << 32;
                self.bars[(idx + 1) as usize] = 0;
                idx += 2;
            } else {
                idx += 1;
            }

            self.bars[current as usize] = base;
            log_bar(current, value, base);
        }
    }

    fn map_cap(&self, cap: &VirtioPciCap) -> *mut u8 {
        if cap.bar as usize >= self.bars.len() {
            return ptr::null_mut();
        }
        let base = self.bars[cap.bar as usize];
        if base == 0 || cap.length == 0 {
            return ptr::null_mut();
        }
        let phys = base + cap.offset as u64;
        unsafe { map_mmio_region(phys, cap.length as usize, MMIO_PTE_FLAGS) }
    }

    fn parse_capabilities(&mut self) -> bool {
        let mut found_vendor = self.parse_standard_capabilities();
        if !found_vendor {
            found_vendor = self.parse_extended_capabilities();
        }
        if !found_vendor {
            log("virtio-blk: no virtio vendor capabilities discovered");
        }
        !self.common.is_null() && !self.config.is_null() && !self.notify_base.is_null()
    }

    fn parse_standard_capabilities(&mut self) -> bool {
        let status = pci_config_read8(self.pci.bus, self.pci.device, self.pci.function, 0x06);
        if (status & 0x10) == 0 {
            return false;
        }

        let mut cap_ptr = pci_config_read8(self.pci.bus, self.pci.device, self.pci.function, 0x34);
        if cap_ptr < 0x40 {
            return false;
        }

        log_cap_ptr(cap_ptr);
        let mut found_vendor = false;
        let mut guard = 0u32;

        while cap_ptr >= 0x40 {
            let mut raw = [0u8; MAX_CAP_LENGTH];
            let slice = match read_standard_capability(self.pci, cap_ptr, &mut raw) {
                Some(data) => data,
                None => break,
            };
            if slice.is_empty() {
                log("virtio-blk: empty capability entry");
                break;
            }
            let cap_id = slice[0];
            let next = pci_config_read8(self.pci.bus, self.pci.device, self.pci.function, cap_ptr.wrapping_add(1));
            let cfg_type = if cap_id == PCI_CAP_ID_VNDR && slice.len() >= size_of::<VirtioPciCap>() {
                slice[3]
            } else {
                0
            };
            log_cap_info(u16::from(cap_ptr), u16::from(cap_id), cfg_type, u16::from(next));

            match cap_id {
                PCI_CAP_ID_MSIX => {
                    self.handle_msix_cap(cap_ptr);
                }
                PCI_CAP_ID_VNDR => {
                    if slice.len() < size_of::<VirtioPciCap>() {
                        log("virtio-blk: vendor capability too short, skipping");
                    } else if self.consume_virtio_cap_from_slice(slice) {
                        found_vendor = true;
                    }
                }
                _ => {}
            }

            if next < 0x40 || next == cap_ptr {
                break;
            }
            cap_ptr = next;
            guard += 1;
            if guard > 64 {
                break;
            }
        }

        found_vendor
    }

    fn parse_extended_capabilities(&mut self) -> bool {
        let mut offset = PCI_EXT_CAP_OFFSET;
        let mut found_vendor = false;
        let mut guard = 0u32;

        loop {
            let header = match read_ecam_u32(self.pci, offset) {
                Some(value) => value,
                None => break,
            };
            if header == 0 {
                break;
            }

            let cap_id = (header & 0xFFFF) as u16;
            let next = ((header >> 20) & 0xFFF) as u32 * 4;
            log_cap_info(offset as u16, cap_id, 0, next as u16);

            match cap_id {
                PCI_EXT_CAP_ID_VSEC => {
                    if let Some(status) = self.process_vsec_capability(offset) {
                        if status {
                            found_vendor = true;
                        }
                    }
                }
                _ => {}
            }

            if next == 0 || next == offset {
                break;
            }
            offset = next;
            guard += 1;
            if guard > 128 {
                break;
            }
        }

        found_vendor
    }

    fn consume_virtio_cap_from_slice(&mut self, data: &[u8]) -> bool {
        if data.len() < size_of::<VirtioPciCap>() {
            log("virtio-blk: capability slice too small");
            return false;
        }

        let mut cap_bytes = [0u8; size_of::<VirtioPciCap>()];
        cap_bytes.copy_from_slice(&data[..size_of::<VirtioPciCap>()]);
        let cap = unsafe { core::ptr::read_unaligned(cap_bytes.as_ptr() as *const VirtioPciCap) };

        match cap.cfg_type {
            VIRTIO_PCI_CAP_COMMON_CFG => {
                let mapped = self.map_cap(&cap);
                log_cap(cap.cfg_type, cap.bar, cap.offset, cap.length, mapped as u64);
                if mapped.is_null() {
                    log("virtio-blk: failed to map common config capability");
                    return false;
                }
                self.common = mapped as *mut VirtioPciCommonCfg;
                true
            }
            VIRTIO_PCI_CAP_DEVICE_CFG => {
                let mapped = self.map_cap(&cap);
                log_cap(cap.cfg_type, cap.bar, cap.offset, cap.length, mapped as u64);
                if mapped.is_null() {
                    log("virtio-blk: failed to map device config capability");
                    return false;
                }
                self.config = mapped as *mut VirtioBlkConfig;
                true
            }
            VIRTIO_PCI_CAP_ISR_CFG => {
                let mapped = self.map_cap(&cap);
                log_cap(cap.cfg_type, cap.bar, cap.offset, cap.length, mapped as u64);
                if mapped.is_null() {
                    log("virtio-blk: failed to map ISR capability");
                    return false;
                }
                self.isr = mapped as *mut u8;
                true
            }
            VIRTIO_PCI_CAP_NOTIFY_CFG => {
                if data.len() < size_of::<VirtioPciNotifyCap>() {
                    log("virtio-blk: notify capability truncated");
                    return false;
                }
                let mut notify_bytes = [0u8; size_of::<VirtioPciNotifyCap>()];
                notify_bytes.copy_from_slice(&data[..size_of::<VirtioPciNotifyCap>()]);
                let notify_cap =
                    unsafe { core::ptr::read_unaligned(notify_bytes.as_ptr() as *const VirtioPciNotifyCap) };
                let mapped = self.map_cap(&notify_cap.cap);
                log_cap(
                    notify_cap.cap.cfg_type,
                    notify_cap.cap.bar,
                    notify_cap.cap.offset,
                    notify_cap.cap.length,
                    mapped as u64,
                );
                if mapped.is_null() {
                    log("virtio-blk: failed to map notify capability");
                    return false;
                }
                self.notify_off_multiplier = notify_cap.notify_off_multiplier;
                self.notify_base = mapped;
                true
            }
            _ => false,
        }
    }

    fn handle_msix_cap(&mut self, offset: u8) {
        let control =
            pci_config_read16(self.pci.bus, self.pci.device, self.pci.function, offset.wrapping_add(2));
        self.msix_table_size = (control & 0x07FF) + 1;
        let table =
            pci_config_read32(self.pci.bus, self.pci.device, self.pci.function, offset.wrapping_add(4));
        self.msix_table_bar = (table & 0x7) as u8;
        self.msix_table_offset = table & !0x7;
        let pba =
            pci_config_read32(self.pci.bus, self.pci.device, self.pci.function, offset.wrapping_add(8));
        self.msix_pba_bar = (pba & 0x7) as u8;
        self.msix_pba_offset = pba & !0x7;

        // Map the MSI-X table for configuration
        if self.msix_table_bar < 6 {
            let bar_base = self.bars[self.msix_table_bar as usize];
            if bar_base != 0 {
                let table_phys = bar_base + self.msix_table_offset as u64;
                let table_size = (self.msix_table_size as usize) * size_of::<MsixTableEntry>();
                unsafe {
                    self.msix_table = map_mmio_region(table_phys, table_size, MMIO_PTE_FLAGS);
                    if !self.msix_table.is_null() {
                        fut_printf(b"[virtio-blk] MSI-X table mapped: phys=0x%lx virt=%p size=%d entries\n\0".as_ptr(),
                            table_phys, self.msix_table, self.msix_table_size as u32);
                    }
                }
            }
        }

        // Explicitly disable MSI-X to use legacy INTx
        let disable_mask = (1u16 << 15) | (1u16 << 14);  // MSI-X enable and mask bits
        let new_control = control & !disable_mask;        // Clear both bits to disable
        pci_config_write16(
            self.pci.bus,
            self.pci.device,
            self.pci.function,
            offset.wrapping_add(2),
            new_control,
        );

        let readback = pci_config_read16(self.pci.bus, self.pci.device, self.pci.function, offset.wrapping_add(2));
        self.msix_enabled = false;
        unsafe {
            fut_printf(b"[virtio-blk] MSI-X explicitly disabled: control=0x%x->0x%x (enable=%d mask=%d)\n\0".as_ptr(),
                control as u32, readback as u32, ((readback >> 15) & 1) as u32, ((readback >> 14) & 1) as u32);
        }
    }

    fn process_vsec_capability(&mut self, offset: u32) -> Option<bool> {
        let header = read_ecam_u32(self.pci, offset + 4)?;
        let length_dw = ((header >> 20) & 0xFFF) as usize;
        if length_dw == 0 {
            log("virtio-blk: VSEC advertises zero length");
            return Some(false);
        }
        let length_bytes = length_dw * 4;
        if length_bytes < size_of::<VirtioPciCap>() {
            log("virtio-blk: VSEC payload too small for virtio capability");
            return Some(false);
        }
        if length_bytes > MAX_VSEC_LENGTH {
            log("virtio-blk: VSEC payload exceeds driver limit");
            return Some(false);
        }

        let buf_ptr = unsafe { alloc(length_bytes) };
        if buf_ptr.is_null() {
            log("virtio-blk: failed to allocate buffer for VSEC");
            return Some(false);
        }

        let mut success = false;
        unsafe {
            let buffer = core::slice::from_raw_parts_mut(buf_ptr, length_bytes);
            if !read_ecam_bytes(self.pci, offset + 8, buffer) {
                log("virtio-blk: failed to read VSEC payload");
                free(buf_ptr);
                return Some(false);
            }

            let mut cursor = 0usize;
            while cursor + size_of::<VirtioPciCap>() <= length_bytes {
                let cap_len = buffer[cursor + 2] as usize;
                if cap_len < size_of::<VirtioPciCap>() || cap_len > length_bytes - cursor {
                    break;
                }
                if self.consume_virtio_cap_from_slice(&buffer[cursor..cursor + cap_len]) {
                    success = true;
                }
                if cap_len == 0 {
                    break;
                }
                cursor += cap_len;
            }

            free(buf_ptr);
        }

        Some(success)
    }

    fn enable_bus_master(&self) {
        let mut command = pci_config_read16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND);
        unsafe {
            fut_printf(b"[virtio-blk] PCI command before: 0x%x\n\0".as_ptr(), command as u32);
        }
        // Enable bus mastering, memory, and I/O
        command |= PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER | PCI_COMMAND_IO;

        // Ensure INTx is NOT disabled (bit 10 = 0 enables legacy INTx)
        const PCI_COMMAND_INTX_DISABLE: u16 = 0x400;
        command &= !PCI_COMMAND_INTX_DISABLE;

        pci_config_write16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND, command);

        let readback = pci_config_read16(self.pci.bus, self.pci.device, self.pci.function, PCI_COMMAND);
        unsafe {
            fut_printf(b"[virtio-blk] PCI command after: 0x%x (BM=%d MEM=%d IO=%d INTx_dis=%d)\n\0".as_ptr(),
                readback as u32,
                (readback & PCI_COMMAND_BUS_MASTER) as u32,
                (readback & PCI_COMMAND_MEMORY) as u32,
                (readback & PCI_COMMAND_IO) as u32,
                ((readback & PCI_COMMAND_INTX_DISABLE) >> 10) as u32);
        }
    }

    fn setup_interrupt(&mut self) -> Result<(), FutStatus> {
        // Read PCI interrupt line register (offset 0x3C)
        let interrupt_line = pci_config_read8(self.pci.bus, self.pci.device, self.pci.function, 0x3C);

        if interrupt_line == 0xFF || interrupt_line == 0 {
            unsafe {
                fut_printf(b"[virtio-blk] No valid interrupt line (read 0x%x)\n\0".as_ptr(),
                    interrupt_line as u32);
            }
            return Err(ENODEV);
        }

        // Calculate IRQ vector (IRQ lines start at vector 32)
        let irq_vector = INT_IRQ_BASE + interrupt_line;
        VIRTIO_BLK_IRQ_VECTOR.store(irq_vector, Ordering::Relaxed);

        unsafe {
            fut_printf(b"[virtio-blk] Using legacy INTx: IRQ line=%d vector=%d\n\0".as_ptr(),
                interrupt_line as u32, irq_vector as u32);
        }

        // Register interrupt handler with IDT
        unsafe {
            let handler_addr = virtio_blk_irq_handler as u64;
            fut_idt_set_entry(
                irq_vector,
                handler_addr,
                GDT_KERNEL_CODE,
                IDT_TYPE_INTERRUPT,
                0  // IST = 0 (use default stack)
            );
            fut_printf(b"[virtio-blk] IDT entry registered: vector=%d handler=0x%lx\n\0".as_ptr(),
                irq_vector as u32, handler_addr);

            // Unmask the IRQ in the PIC
            pic_unmask_irq(interrupt_line);
        }

        Ok(())
    }

    fn negotiate_features(&mut self) -> Result<(), FutStatus> {
        unsafe {
            (*self.common).device_status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
            (*self.common).device_feature_select = 0;
            let feat_low = (*self.common).device_feature;
            (*self.common).device_feature_select = 1;
            let feat_high = (*self.common).device_feature;
            let features = ((feat_high as u64) << 32) | feat_low as u64;

            fut_printf(b"[virtio-blk] device features: 0x%lx\n\0".as_ptr(), features);

            /* Accept only minimum required features for basic operation.
             * VIRTIO_F_VERSION_1 (bit 32) is required for modern virtio devices.
             * VIRTIO_F_RING_INDIRECT_DESC (bit 28) and VIRTIO_F_RING_EVENT_IDX (bit 29)
             * can cause issues if not properly supported. Accept only VERSION_1. */
            const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;
            const VIRTIO_F_ANY_LAYOUT: u64 = 1u64 << 27;

            // Accept VERSION_1 and ANY_LAYOUT (helps with buffer handling)
            let driver_features = VIRTIO_F_VERSION_1 | (features & VIRTIO_F_ANY_LAYOUT);

            (*self.common).driver_feature_select = 0;
            (*self.common).driver_feature = driver_features as u32;
            (*self.common).driver_feature_select = 1;
            (*self.common).driver_feature = (driver_features >> 32) as u32;

            fut_printf(b"[virtio-blk] driver features: 0x%lx (minimal set)\n\0".as_ptr(),
                driver_features);

            (*self.common).device_status |= VIRTIO_STATUS_FEATURES_OK;
            let status_check = (*self.common).device_status;
            fut_printf(b"[virtio-blk] device_status after FEATURES_OK: 0x%x\n\0".as_ptr(), status_check as u32);

            if (status_check & VIRTIO_STATUS_FEATURES_OK) == 0 {
                log("virtio-blk: feature negotiation failed");
                return Err(ENODEV);
            }
            /* DO NOT set DRIVER_OK here - must wait until after queue setup */
        }
        Ok(())
    }

    fn init_queue(&mut self) -> Result<(), FutStatus> {
        unsafe {
            (*self.common).queue_select = 0;
            let device_qsize = (*self.common).queue_size;
            if device_qsize == 0 {
                return Err(ENODEV);
            }
            let qsize = min(device_qsize, QUEUE_SIZE);
            self.queue.setup(qsize)?;
            (*self.common).queue_size = qsize;

            /* Disable MSI-X to use legacy INTx interrupts */
            (*self.common).queue_msix_vector = 0xFFFF;  // NO_VECTOR - use legacy INTx
            (*self.common).msix_config = 0xFFFF;        // NO_VECTOR for config

            fut_printf(b"[virtio-blk] MSI-X disabled, using legacy INTx\n\0".as_ptr());

            let desc_lo = (self.queue.desc_phys & 0xFFFF_FFFF) as u32;
            let desc_hi = (self.queue.desc_phys >> 32) as u32;
            fut_printf(b"[virtio-blk] writing queue_desc: lo=0x%x hi=0x%x\n\0".as_ptr(), desc_lo, desc_hi);

            (*self.common).queue_desc_lo = desc_lo;
            (*self.common).queue_desc_hi = desc_hi;
            (*self.common).queue_avail_lo = (self.queue.avail_phys & 0xFFFF_FFFF) as u32;
            (*self.common).queue_avail_hi = (self.queue.avail_phys >> 32) as u32;
            (*self.common).queue_used_lo = (self.queue.used_phys & 0xFFFF_FFFF) as u32;
            (*self.common).queue_used_hi = (self.queue.used_phys >> 32) as u32;
            (*self.common).queue_enable = 1;
            self.queue.notify_off = (*self.common).queue_notify_off;

            fut_printf(b"[virtio-blk] queue setup: desc_phys=0x%lx avail_phys=0x%lx used_phys=0x%lx\n\0".as_ptr(),
                self.queue.desc_phys, self.queue.avail_phys, self.queue.used_phys);

            /* Verify queue addresses were written correctly */
            let readback_select = (*self.common).queue_select;
            let readback_desc_lo = (*self.common).queue_desc_lo;
            let readback_desc_hi = (*self.common).queue_desc_hi;
            let readback_desc = ((readback_desc_hi as u64) << 32) | (readback_desc_lo as u64);
            let readback_enabled = (*self.common).queue_enable;
            fut_printf(b"[virtio-blk] readback: queue_select=%d desc=0x%lx enabled=%d\n\0".as_ptr(),
                readback_select as u32, readback_desc, readback_enabled as u32);

            if readback_desc != self.queue.desc_phys {
                fut_printf(b"[virtio-blk] ERROR: desc address mismatch! wrote=0x%lx read=0x%lx\n\0".as_ptr(),
                    self.queue.desc_phys, readback_desc);
            }
        }
        Ok(())
    }

    fn init_dma(&mut self) -> Result<(), FutStatus> {
        unsafe {
            let page = alloc_page() as *mut VirtioBlkDma;
            if page.is_null() {
                return Err(ENOMEM);
            }
            ptr::write_bytes(page.cast::<u8>(), 0, PAGE_SIZE);
            self.dma = page;
            self.dma_phys = virt_to_phys_addr(page as usize);
        }
        Ok(())
    }

    fn read_geometry(&mut self) {
        unsafe {
            if self.config.is_null() {
                return;
            }
            self.capacity_sectors = (*self.config).capacity;
            let blk_size = (*self.config).blk_size;
            self.block_size = if blk_size == 0 { 512 } else { blk_size };
            self.has_flush = (*self.config).writeback != 0;
        }
    }

    fn notify_queue(&self) {
        unsafe {
            let off = (self.queue.notify_off as u32 * self.notify_off_multiplier) as usize;
            let ptr = self.notify_base.add(off) as *mut u16;

            /* Write the queue index to notify QEMU */
            write_volatile(ptr, 0);  // Queue 0

            /* Verify write succeeded by reading back (may help trigger QEMU too) */
            let _readback = read_volatile(ptr as *const u16);

            fut_printf(b"[virtio-blk] notified queue 0 at ptr=%p\n\0".as_ptr(), ptr);
        }
    }

    fn perform_io(
        &self,
        req_type: u32,
        lba: u64,
        nsectors: usize,
        buf: *mut u8,
        write: bool,
    ) -> FutStatus {
        log("virtio-blk: perform_io called");
        if self.dma.is_null() {
            log("virtio-blk: DMA is null!");
            return ENODEV;
        }

        // Clear interrupt flag before starting I/O
        IO_COMPLETED.store(0, Ordering::Release);

        let data_bytes = nsectors * self.block_size as usize;
        let mut bounce = ptr::null_mut();
        let mut data_phys = 0u64;

        unsafe {
            (*self.dma).header.req_type = req_type;
            (*self.dma).header.reserved = 0;
            (*self.dma).header.sector = lba;
            (*self.dma).status = 0xFF;

            fut_printf(b"[virtio-blk] request: type=%d lba=%ld nsectors=%d\n\0".as_ptr(),
                req_type, lba, nsectors as u32);

            if req_type != VIRTIO_BLK_T_FLUSH {
                if buf.is_null() {
                    return EINVAL;
                }
                if (buf as usize) >= PMAP_DIRECT_VIRT_BASE {
                    data_phys = virt_to_phys_addr(buf as usize);
                } else {
                    bounce = alloc(data_bytes) as *mut u8;
                    if bounce.is_null() {
                        return ENOMEM;
                    }
                    if write {
                        ptr::copy_nonoverlapping(buf, bounce, data_bytes);
                    }
                    data_phys = virt_to_phys_addr(bounce as usize);
                }
            }
        }

        let header_phys = self.dma_phys;
        let status_phys = self.dma_phys + DMA_STATUS_OFFSET;

        unsafe {
            fut_printf(b"[virtio-blk] I/O: header_phys=0x%lx data_phys=0x%lx status_phys=0x%lx\n\0".as_ptr(),
                header_phys, data_phys, status_phys);
        }

        if let Err(err) = self.queue.enqueue(header_phys, data_phys, status_phys, req_type, data_bytes, write) {
            if !bounce.is_null() {
                unsafe { free(bounce); }
            }
            return err;
        }
        /* Ensure all descriptor/avail ring writes are visible before notifying device */
        core::sync::atomic::fence(Ordering::SeqCst);
        self.notify_queue();

        let rc = self.queue.poll_completion(self.isr as *const u8);
        unsafe {
            let status_byte = (*self.dma).status;
            fut_printf(b"[virtio-blk] after poll: rc=%d status_byte=%d\n\0".as_ptr(), rc, status_byte as u32);
        }
        if rc != 0 {
            if !bounce.is_null() {
                unsafe { free(bounce); }
            }
            return rc;
        }

        unsafe {
            match (*self.dma).status {
                VIRTIO_BLK_S_OK => {
                    if req_type == VIRTIO_BLK_T_IN && !bounce.is_null() {
                        ptr::copy_nonoverlapping(bounce, buf, data_bytes);
                    }
                    if !bounce.is_null() {
                        free(bounce);
                    }
                    0
                }
                VIRTIO_BLK_S_UNSUPP => {
                    if !bounce.is_null() {
                        free(bounce);
                    }
                    ENOTSUP
                }
                _ => {
                    if !bounce.is_null() {
                        free(bounce);
                    }
                    EIO
                }
            }
        }
    }
}

struct DeviceHolder {
    state: MaybeUninit<VirtioBlkDevice>,
    ready: bool,
}

unsafe impl Send for DeviceHolder {}
unsafe impl Sync for DeviceHolder {}

static DEVICE: SpinLock<DeviceHolder> = SpinLock::new(DeviceHolder {
    state: MaybeUninit::uninit(),
    ready: false,
});

static DEVICE_NAME: &[u8] = b"blk:vda\0";

static BACKEND: FutBlkBackend = FutBlkBackend {
    read: Some(backend_read),
    write: Some(backend_write),
    flush: Some(backend_flush),
};

#[unsafe(no_mangle)]
pub extern "C" fn virtio_blk_init(pci_addr: u64) -> FutStatus {
    let mut rc = 0;
    DEVICE.with(|holder| {
        if holder.ready {
            rc = 0;
            return;
        }
        match VirtioBlkDevice::probe(pci_addr) {
            Ok(device) => unsafe {
                holder.state.as_mut_ptr().write(device);
                let dev_ptr = holder.state.as_mut_ptr();
                let dev = &mut *dev_ptr;
                dev.blk_dev.as_mut_ptr().write(FutBlkDev {
                    name: DEVICE_NAME.as_ptr() as *const c_char,
                    block_size: dev.block_size,
                    block_count: dev.capacity_sectors,
                    allowed_rights: FUT_BLK_READ | FUT_BLK_WRITE | FUT_BLK_ADMIN,
                    backend: &BACKEND,
                    backend_ctx: dev_ptr.cast::<c_void>(),
                    core: ptr::null_mut(),
                });
                if let Err(err) = register(dev.blk_dev.assume_init_mut()) {
                    rc = err;
                    log("virtio-blk: registration failed");
                    return;
                }
                holder.ready = true;
                log("virtio-blk: initialized OK");
                log_capacity(dev.capacity_sectors, dev.block_size);
                rc = 0;
            },
            Err(err) => {
                rc = err;
            }
        }
    });
    rc
}

fn log_capacity(sectors: u64, block_size: u32) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 96];
    let mut idx = 0;
    let prefix = b"virtio-blk: /dev/vda capacity=";
    buf[..prefix.len()].copy_from_slice(prefix);
    idx += prefix.len();
    idx += write_decimal(&mut buf[idx..], sectors);
    let mid = b" sectors (block=";
    buf[idx..idx + mid.len()].copy_from_slice(mid);
    idx += mid.len();
    idx += write_decimal(&mut buf[idx..], block_size as u64);
    buf[idx] = b')';
    idx += 1;
    log(unsafe { core::str::from_utf8_unchecked(&buf[..idx]) });
}

fn write_decimal(buf: &mut [u8], mut value: u64) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    if value == 0 {
        tmp[0] = b'0';
        i = 1;
    } else {
        while value > 0 && i < tmp.len() {
            tmp[i] = b'0' + (value % 10) as u8;
            value /= 10;
            i += 1;
        }
    }
    let written = min(i, buf.len());
    for j in 0..written {
        buf[j] = tmp[written - 1 - j];
    }
    written
}

fn log_bar(index: u8, raw: u32, base: u64) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 96];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: BAR";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], index as u64);

    const RAW_LABEL: &[u8] = b" raw=";
    buf[pos..pos + RAW_LABEL.len()].copy_from_slice(RAW_LABEL);
    pos += RAW_LABEL.len();
    pos += write_decimal(&mut buf[pos..], raw as u64);

    const BASE_LABEL: &[u8] = b" base=";
    buf[pos..pos + BASE_LABEL.len()].copy_from_slice(BASE_LABEL);
    pos += BASE_LABEL.len();
    pos += write_decimal(&mut buf[pos..], base);

    buf[pos] = 0;
    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

fn log_cap(cfg_type: u8, bar: u8, offset: u32, length: u32, mapped: u64) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 128];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: cap type=";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], cfg_type as u64);

    const BAR_LABEL: &[u8] = b" bar=";
    buf[pos..pos + BAR_LABEL.len()].copy_from_slice(BAR_LABEL);
    pos += BAR_LABEL.len();
    pos += write_decimal(&mut buf[pos..], bar as u64);

    const OFF_LABEL: &[u8] = b" off=";
    buf[pos..pos + OFF_LABEL.len()].copy_from_slice(OFF_LABEL);
    pos += OFF_LABEL.len();
    pos += write_decimal(&mut buf[pos..], offset as u64);

    const LEN_LABEL: &[u8] = b" len=";
    buf[pos..pos + LEN_LABEL.len()].copy_from_slice(LEN_LABEL);
    pos += LEN_LABEL.len();
    pos += write_decimal(&mut buf[pos..], length as u64);

    const MAP_LABEL: &[u8] = b" map=";
    buf[pos..pos + MAP_LABEL.len()].copy_from_slice(MAP_LABEL);
    pos += MAP_LABEL.len();
    pos += write_decimal(&mut buf[pos..], mapped);

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

fn log_vendor(bus: u8, device: u8, function: u8, device_id: u16, hinted: bool) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 128];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: pci ";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], bus as u64);

    buf[pos] = b':';
    pos += 1;
    pos += write_decimal(&mut buf[pos..], device as u64);
    buf[pos] = b'.';
    pos += 1;
    pos += write_decimal(&mut buf[pos..], function as u64);

    const DEV_LABEL: &[u8] = b" dev=";
    buf[pos..pos + DEV_LABEL.len()].copy_from_slice(DEV_LABEL);
    pos += DEV_LABEL.len();
    pos += write_decimal(&mut buf[pos..], device_id as u64);

    if hinted {
        const HINT: &[u8] = b" (hint)";
        buf[pos..pos + HINT.len()].copy_from_slice(HINT);
        pos += HINT.len();
    }

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

fn log_cap_ptr(ptr: u8) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 48];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: cap_ptr=";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], ptr as u64);

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

fn log_cap_info(ptr: u16, vendor: u16, cfg_type: u8, next: u16) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 96];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: cap @";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], ptr as u64);

    const VNDR: &[u8] = b" vndr=";
    buf[pos..pos + VNDR.len()].copy_from_slice(VNDR);
    pos += VNDR.len();
    pos += write_decimal(&mut buf[pos..], vendor as u64);

    const TYPE_LABEL: &[u8] = b" type=";
    buf[pos..pos + TYPE_LABEL.len()].copy_from_slice(TYPE_LABEL);
    pos += TYPE_LABEL.len();
    pos += write_decimal(&mut buf[pos..], cfg_type as u64);

    const NEXT_LABEL: &[u8] = b" next=";
    buf[pos..pos + NEXT_LABEL.len()].copy_from_slice(NEXT_LABEL);
    pos += NEXT_LABEL.len();
    pos += write_decimal(&mut buf[pos..], next as u64);

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

unsafe extern "C" fn backend_read(ctx: *mut c_void, lba: u64, nsectors: usize, buf: *mut c_void) -> FutStatus {
    if ctx.is_null() {
        return ENODEV;
    }
    let dev = unsafe { &*(ctx as *mut VirtioBlkDevice) };
    dev.io_lock.lock();
    let status = dev.perform_io(VIRTIO_BLK_T_IN, lba, nsectors, buf as *mut u8, false);
    dev.io_lock.unlock();
    status
}

unsafe extern "C" fn backend_write(ctx: *mut c_void, lba: u64, nsectors: usize, buf: *const c_void) -> FutStatus {
    if ctx.is_null() {
        return ENODEV;
    }
    let dev = unsafe { &*(ctx as *mut VirtioBlkDevice) };
    dev.io_lock.lock();
    let status = dev.perform_io(VIRTIO_BLK_T_OUT, lba, nsectors, buf as *mut u8, true);
    dev.io_lock.unlock();
    status
}

unsafe extern "C" fn backend_flush(ctx: *mut c_void) -> FutStatus {
    if ctx.is_null() {
        return ENODEV;
    }
    let dev = unsafe { &*(ctx as *mut VirtioBlkDevice) };
    if !dev.has_flush {
        return ENOTSUP;
    }
    dev.io_lock.lock();
    let status = dev.perform_io(VIRTIO_BLK_T_FLUSH, 0, 1, dev.dma.cast::<u8>(), true);
    dev.io_lock.unlock();
    status
}

fn find_device(pci_hint: u64) -> Option<PciAddress> {
    if let Some(addr) = decode_pci_hint(pci_hint) {
        let vendor = pci_config_read16(addr.bus, addr.device, addr.function, 0x00);
        if vendor == VIRTIO_VENDOR_ID {
            let device_id = pci_config_read16(addr.bus, addr.device, addr.function, 0x02);
            if device_id == VIRTIO_DEVICE_ID_BLOCK_LEGACY || device_id == VIRTIO_DEVICE_ID_BLOCK_MODERN {
                log_vendor(addr.bus, addr.device, addr.function, device_id, true);
                return Some(addr);
            }
        }
    }
    for bus in 0u8..=1 {
        for device in 0u8..32 {
            for function in 0u8..8 {
                let vendor = pci_config_read16(bus, device, function, 0x00);
                if vendor != VIRTIO_VENDOR_ID {
                    continue;
                }
                let device_id = pci_config_read16(bus, device, function, 0x02);
                if device_id == VIRTIO_DEVICE_ID_BLOCK_LEGACY || device_id == VIRTIO_DEVICE_ID_BLOCK_MODERN {
                    log_vendor(bus, device, function, device_id, false);
                    return Some(PciAddress { bus, device, function });
                }
            }
        }
    }
    None
}

fn decode_pci_hint(hint: u64) -> Option<PciAddress> {
    if hint == 0 {
        return None;
    }
    let bus = ((hint >> 16) & 0xFF) as u8;
    let device = ((hint >> 8) & 0xFF) as u8;
    let function = (hint & 0xFF) as u8;
    Some(PciAddress { bus, device, function })
}

fn read_standard_capability<'a>(
    pci: PciAddress,
    offset: u8,
    buffer: &'a mut [u8; MAX_CAP_LENGTH],
) -> Option<&'a [u8]> {
    let cap_len = pci_config_read8(pci.bus, pci.device, pci.function, offset.wrapping_add(2));
    if cap_len == 0 || cap_len as usize > MAX_CAP_LENGTH {
        log("virtio-blk: capability length out of range");
        return None;
    }
    log_cap_len(offset, cap_len);
    if u16::from(offset) + cap_len as u16 > 256 {
        log("virtio-blk: capability crosses config space boundary");
        return None;
    }
    let mut written = 0usize;
    while written < cap_len as usize {
        let byte_offset = offset.wrapping_add(written as u8);
        let aligned = byte_offset & !0x3;
        let word = pci_config_read32(pci.bus, pci.device, pci.function, aligned);
        let bytes = word.to_le_bytes();
        let start = (byte_offset & 0x3) as usize;
        let available = 4 - start;
        let remaining = cap_len as usize - written;
        let copy = min(available, remaining);
        buffer[written..written + copy].copy_from_slice(&bytes[start..start + copy]);
        written += copy;
    }
    Some(&buffer[..cap_len as usize])
}

fn log_cap_len(offset: u8, len: u8) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 64];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: cap_len off=";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], offset as u64);

    const LEN_LABEL: &[u8] = b" len=";
    buf[pos..pos + LEN_LABEL.len()].copy_from_slice(LEN_LABEL);
    pos += LEN_LABEL.len();
    pos += write_decimal(&mut buf[pos..], len as u64);

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

struct EcamWindow {
    map_base: *mut u8,
    size: usize,
    cursor: *mut u8,
}

impl EcamWindow {
    fn map(pci: PciAddress, offset: u32, len: usize) -> Option<Self> {
        if len == 0 {
            return None;
        }
        if offset as usize + len > PCI_ECAM_FN_SIZE {
            return None;
        }
        let start = ecam_phys_addr(pci, offset)?;
        let end = ecam_phys_addr(pci, offset + len as u32 - 1)?;
        let map_start = start & !0xFFF;
        let map_end = (end & !0xFFF) + 0x1000;
        let size = (map_end - map_start) as usize;
        unsafe {
            let mapped = map_mmio_region(map_start, size, MMIO_PTE_FLAGS);
            if mapped.is_null() {
                return None;
            }
            let cursor = mapped.add((start - map_start) as usize);
            Some(Self { map_base: mapped, size, cursor })
        }
    }

    fn ptr(&self) -> *mut u8 {
        self.cursor
    }
}

impl Drop for EcamWindow {
    fn drop(&mut self) {
        unsafe { unmap_mmio_region(self.map_base, self.size); }
    }
}

fn ecam_phys_addr(pci: PciAddress, offset: u32) -> Option<u64> {
    if offset as usize >= PCI_ECAM_FN_SIZE {
        return None;
    }
    Some(
        PCI_ECAM_BASE
            + (pci.bus as u64) * PCI_ECAM_BUS_STRIDE
            + (pci.device as u64) * PCI_ECAM_DEVICE_STRIDE
            + (pci.function as u64) * PCI_ECAM_FUNCTION_STRIDE
            + offset as u64,
    )
}

fn read_ecam_bytes(pci: PciAddress, offset: u32, buf: &mut [u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if offset as usize + buf.len() > PCI_ECAM_FN_SIZE {
        return false;
    }
    if let Some(window) = EcamWindow::map(pci, offset, buf.len()) {
        unsafe { ptr::copy_nonoverlapping(window.ptr(), buf.as_mut_ptr(), buf.len()); }
        true
    } else {
        log_ecam_failure(offset, buf.len());
        false
    }
}

fn log_ecam_failure(offset: u32, len: usize) {
    if !DEBUG_BLK_TRACE {
        return;
    }
    let mut buf = [0u8; 96];
    let mut pos = 0usize;

    const PREFIX: &[u8] = b"virtio-blk: ECAM map failed off=";
    buf[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    pos += write_decimal(&mut buf[pos..], offset as u64);

    const LEN_LABEL: &[u8] = b" len=";
    buf[pos..pos + LEN_LABEL.len()].copy_from_slice(LEN_LABEL);
    pos += LEN_LABEL.len();
    pos += write_decimal(&mut buf[pos..], len as u64);

    log(unsafe { core::str::from_utf8_unchecked(&buf[..pos]) });
}

fn read_ecam_u32(pci: PciAddress, offset: u32) -> Option<u32> {
    let mut bytes = [0u8; 4];
    if !read_ecam_bytes(pci, offset, &mut bytes) {
        return None;
    }
    Some(u32::from_le_bytes(bytes))
}

fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset & 0xFC)
        | 0x8000_0000;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

fn pci_config_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    ((value >> shift) & 0xFFFF) as u16
}

fn pci_config_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    ((value >> shift) & 0xFF) as u8
}

fn pci_config_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let mut current = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    current &= !(0xFFFF << shift);
    current |= u32::from(value) << shift;
    pci_config_write32(bus, device, function, offset & 0xFC, current);
}

fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = (u32::from(bus) << 16)
        | (u32::from(device) << 11)
        | (u32::from(function) << 8)
        | u32::from(offset & 0xFC)
        | 0x8000_0000;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, value);
    }
}

unsafe fn outl(port: u16, value: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags)); }
}

unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe { asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, preserves_flags)); }
    value
}
#[inline(always)]
fn virt_to_phys_addr(addr: usize) -> u64 {
    debug_assert!(addr >= PMAP_DIRECT_VIRT_BASE);
    (addr - PMAP_DIRECT_VIRT_BASE) as u64
}

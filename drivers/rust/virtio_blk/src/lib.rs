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
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};

use common::{
    alloc, alloc_page, free, free_page, log, map_mmio_region, register, thread_yield, unmap_mmio_region,
    FutBlkBackend, FutBlkDev, FutStatus, RawSpinLock, SpinLock, FUT_BLK_ADMIN, FUT_BLK_READ,
    FUT_BLK_WRITE, MMIO_DEFAULT_FLAGS,
};

#[cfg(target_arch = "aarch64")]
use common::MmioTransport;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn fut_idt_set_entry(vector: u8, handler: u64, selector: u16, type_attr: u8, ist: u8);
    #[cfg(target_arch = "aarch64")]
    fn virtio_mmio_get_base_addr(dev: *mut core::ffi::c_void) -> u64;
}

const GDT_KERNEL_CODE: u16 = 0x08;     // Kernel code segment
const IDT_TYPE_INTERRUPT: u8 = 0x8E;   // Interrupt gate
const INT_IRQ_BASE: u8 = 32;           // IRQ vectors start at 32

// IRQ vector is determined dynamically from PCI interrupt line
static VIRTIO_BLK_IRQ_VECTOR: AtomicU8 = AtomicU8::new(0);

// Global completion flag for interrupt handler
static IO_COMPLETED: AtomicU8 = AtomicU8::new(0);

// Global ISR register pointer for interrupt acknowledgment
static VIRTIO_ISR_PTR: AtomicU64 = AtomicU64::new(0);

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
const MSIX_CONTROL_ENABLE: u16 = 1u16 << 15;  // MSI-X enable bit
const MSIX_CONTROL_MASK: u16 = 1u16 << 14;    // MSI-X function mask bit

// APIC Interrupt Command Register (ICR) format for MSI-X message address
// ICR = 0xFEE0 | (D7:D4 = delivery mode) | (D9:D8 = destination mode) | ...
// For MSI-X: msg_addr_lo = 0xFEE00000 | (vector destination info)
const APIC_MSG_ADDR_BASE: u32 = 0xFEE00000;
const APIC_DESTINATION_MODE_LOGICAL: u32 = 1 << 11;  // Logical destination

// Interrupt handler for virtio-blk I/O completion - x86_64
#[cfg(target_arch = "x86_64")]
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

// Interrupt handler for virtio-blk I/O completion - ARM64
#[cfg(target_arch = "aarch64")]
extern "C" fn virtio_blk_irq_handler() {
    virtio_blk_irq_handler_inner();
}

// Inner interrupt handler logic
extern "C" fn virtio_blk_irq_handler_inner() {
    // CRITICAL: Read ISR status register to acknowledge interrupt to VirtIO device
    // According to VirtIO spec, this read is REQUIRED for the device to send more interrupts
    unsafe {
        let isr_ptr = VIRTIO_ISR_PTR.load(Ordering::Relaxed) as *mut u8;
        if !isr_ptr.is_null() {
            let _isr_status = core::ptr::read_volatile(isr_ptr);
            // Reading the ISR register acknowledges the interrupt to the device
        }
    }

    // Signal I/O completion
    IO_COMPLETED.store(1, Ordering::Release);

    // Send EOI to PIC (End of Interrupt) - x86_64 only
    #[cfg(target_arch = "x86_64")]
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

// x86_64 I/O port operations
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    value
}

// Unmask an IRQ in the PIC - x86_64 only
#[cfg(target_arch = "x86_64")]
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

// VirtIO MMIO register offsets (for ARM64)
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_MAGIC_VALUE: u32 = 0x000;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_VERSION: u32 = 0x004;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DEVICE_ID: u32 = 0x008;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_VENDOR_ID: u32 = 0x00c;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DEVICE_FEATURES: u32 = 0x010;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u32 = 0x014;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DRIVER_FEATURES: u32 = 0x020;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u32 = 0x024;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_SEL: u32 = 0x030;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_NUM_MAX: u32 = 0x034;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_NUM: u32 = 0x038;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_READY: u32 = 0x044;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_NOTIFY: u32 = 0x050;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_INTERRUPT_STATUS: u32 = 0x060;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_INTERRUPT_ACK: u32 = 0x064;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_STATUS: u32 = 0x070;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DESC_LOW: u32 = 0x080;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DESC_HIGH: u32 = 0x084;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DRIVER_LOW: u32 = 0x090;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DRIVER_HIGH: u32 = 0x094;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DEVICE_LOW: u32 = 0x0a0;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_QUEUE_DEVICE_HIGH: u32 = 0x0a4;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_CONFIG_GENERATION: u32 = 0x0fc;
#[cfg(target_arch = "aarch64")]
const VIRTIO_MMIO_CONFIG: u32 = 0x100;

// VirtIO device type for block devices
#[cfg(target_arch = "aarch64")]
const VIRTIO_DEV_BLOCK: u32 = 2;

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
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_avail_lo: u32,
    queue_avail_hi: u32,
    queue_used_lo: u32,
    queue_used_hi: u32,
}

// VirtIO PCI Common Config offsets (for offset-based access)
const VIRTIO_PCI_COMMON_DFSELECT: usize = 0x00;    // device_feature_select
const VIRTIO_PCI_COMMON_DF: usize = 0x04;          // device_feature
const VIRTIO_PCI_COMMON_GFSELECT: usize = 0x08;    // driver_feature_select
const VIRTIO_PCI_COMMON_GF: usize = 0x0C;          // driver_feature
const VIRTIO_PCI_COMMON_MSIX: usize = 0x10;        // msix_config
const VIRTIO_PCI_COMMON_NUM_QUEUES: usize = 0x12;  // num_queues
const VIRTIO_PCI_COMMON_STATUS: usize = 0x14;      // device_status
const VIRTIO_PCI_COMMON_CFG_GEN: usize = 0x15;     // config_generation
const VIRTIO_PCI_COMMON_Q_SELECT: usize = 0x16;    // queue_select
const VIRTIO_PCI_COMMON_Q_SIZE: usize = 0x18;      // queue_size
const VIRTIO_PCI_COMMON_Q_MSIX: usize = 0x1A;      // queue_msix_vector
const VIRTIO_PCI_COMMON_Q_ENABLE: usize = 0x1C;    // queue_enable
const VIRTIO_PCI_COMMON_Q_NOTIFYOFF: usize = 0x1E; // queue_notify_off
const VIRTIO_PCI_COMMON_Q_DESCLO: usize = 0x20;    // queue_desc_lo
const VIRTIO_PCI_COMMON_Q_DESCHI: usize = 0x24;    // queue_desc_hi
const VIRTIO_PCI_COMMON_Q_AVAILLO: usize = 0x28;   // queue_avail_lo
const VIRTIO_PCI_COMMON_Q_AVAILHI: usize = 0x2C;   // queue_avail_hi
const VIRTIO_PCI_COMMON_Q_USEDLO: usize = 0x30;    // queue_used_lo
const VIRTIO_PCI_COMMON_Q_USEDHI: usize = 0x34;    // queue_used_hi

// Common config MMIO access helpers with ARM64 memory barriers
// These helpers ensure proper ordering of MMIO operations by placing
// DSB (Data Synchronization Barrier) instructions before and after accesses

#[inline(always)]
unsafe fn common_read8(base: *mut u8, offset: usize) -> u8 {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u8) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write8(base: *mut u8, offset: usize, value: u8) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u8, value); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_read16(base: *mut u8, offset: usize) -> u16 {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u16) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write16(base: *mut u8, offset: usize, value: u16) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u16, value); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_read32(base: *mut u8, offset: usize) -> u32 {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    let val = unsafe { read_volatile(base.add(offset) as *const u32) };
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    val
}

#[inline(always)]
unsafe fn common_write32(base: *mut u8, offset: usize, value: u32) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u32, value); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
}

#[inline(always)]
unsafe fn common_write64(base: *mut u8, offset: usize, value: u64) {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
    unsafe { write_volatile(base.add(offset) as *mut u64, value); }
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("dsb sy"); }
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
    queue_mem_base: *mut u8,  // Base pointer for cleanup of 64KB-aligned allocation
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
            queue_mem_base: ptr::null_mut(),
        }
    }

    fn setup(&mut self, requested: u16) -> Result<(), FutStatus> {
        unsafe {
            /* QEMU modern VirtIO requires 64KB alignment for ALL queue structures.
             * Allocate one large contiguous block and subdivide it to avoid overlap.
             * Need: 3×64KB = 192KB for structures + 64KB for alignment slack = 256KB */
            const ALIGN_64KB: usize = 0x10000;
            const BLOCK_SIZE: usize = 0x40000; // 256KB

            let base_ptr = alloc(BLOCK_SIZE);
            if base_ptr.is_null() {
                return Err(ENOMEM);
            }

            let base_addr = base_ptr as usize;

            // Find first 64KB-aligned address in the allocated block
            let aligned_base = (base_addr + ALIGN_64KB - 1) & !(ALIGN_64KB - 1);

            // Place three structures at 64KB intervals within the aligned region
            let desc_base = aligned_base;
            let avail_base = aligned_base + ALIGN_64KB;
            let used_base = aligned_base + 2 * ALIGN_64KB;

            let desc = desc_base as *mut VirtqDesc;
            let avail = avail_base as *mut VirtqAvail;
            let used = used_base as *mut VirtqUsed;

            // Store base pointer for cleanup
            self.queue_mem_base = base_ptr;

            // Verify no overlap (should be impossible with our fixed spacing)
            if desc_base == avail_base || desc_base == used_base || avail_base == used_base {
                fut_printf(b"[virtio-blk] ERROR: Queue structures overlap after alignment!\n\0".as_ptr());
                fut_printf(b"[virtio-blk]   desc=0x%lx avail=0x%lx used=0x%lx\n\0".as_ptr(),
                    desc_base, avail_base, used_base);
                free(base_ptr);
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

            /* CRITICAL: Verify all queue regions are page-aligned for QEMU */
            fut_printf(b"[virtio-blk] queue addrs: desc=0x%lx avail=0x%lx used=0x%lx\n\0".as_ptr(),
                self.desc_phys, self.avail_phys, self.used_phys);

            if (self.desc_phys % 4096) != 0 {
                fut_printf(b"[virtio-blk] ERROR: desc_phys not page-aligned! (0x%lx)\n\0".as_ptr(), self.desc_phys);
            }
            if (self.avail_phys % 4096) != 0 {
                fut_printf(b"[virtio-blk] ERROR: avail_phys not page-aligned! (0x%lx)\n\0".as_ptr(), self.avail_phys);
            }
            if (self.used_phys % 4096) != 0 {
                fut_printf(b"[virtio-blk] ERROR: used_phys not page-aligned! (0x%lx)\n\0".as_ptr(), self.used_phys);
            }

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
            // Header descriptor - write each field separately for packed struct visibility
            let desc_ptr = self.desc.add(desc_head as usize);
            let addr_ptr = core::ptr::addr_of_mut!((*desc_ptr).addr);
            write_volatile(addr_ptr, header_phys);
            let len_ptr = core::ptr::addr_of_mut!((*desc_ptr).len);
            write_volatile(len_ptr, size_of::<VirtioBlkReqHeader>() as u32);
            let flags_ptr = core::ptr::addr_of_mut!((*desc_ptr).flags);
            write_volatile(flags_ptr, VIRTQ_DESC_F_NEXT);
            let next_ptr = core::ptr::addr_of_mut!((*desc_ptr).next);
            let next_val = if req_type == VIRTIO_BLK_T_FLUSH { desc_status } else { desc_data };
            write_volatile(next_ptr, next_val);
            fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=%d flags=0x%x next=%d\n\0".as_ptr(),
                desc_head as u32, header_phys, size_of::<VirtioBlkReqHeader>() as u32,
                VIRTQ_DESC_F_NEXT as u32, next_val as u32);

            if req_type != VIRTIO_BLK_T_FLUSH {
                let mut flags = VIRTQ_DESC_F_NEXT;
                if !write {
                    flags |= VIRTQ_DESC_F_WRITE;
                }
                // Data descriptor - write each field separately
                let desc_ptr = self.desc.add(desc_data as usize);
                let addr_ptr = core::ptr::addr_of_mut!((*desc_ptr).addr);
                write_volatile(addr_ptr, data_phys);
                let len_ptr = core::ptr::addr_of_mut!((*desc_ptr).len);
                write_volatile(len_ptr, data_len as u32);
                let flags_ptr = core::ptr::addr_of_mut!((*desc_ptr).flags);
                write_volatile(flags_ptr, flags);
                let next_ptr = core::ptr::addr_of_mut!((*desc_ptr).next);
                write_volatile(next_ptr, desc_status);
                fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=%d flags=0x%x next=%d\n\0".as_ptr(),
                    desc_data as u32, data_phys, data_len as u32, flags as u32, desc_status as u32);
            }

            // Status descriptor - write each field separately
            let desc_ptr = self.desc.add(desc_status as usize);
            let addr_ptr = core::ptr::addr_of_mut!((*desc_ptr).addr);
            write_volatile(addr_ptr, status_phys);
            let len_ptr = core::ptr::addr_of_mut!((*desc_ptr).len);
            write_volatile(len_ptr, 1);
            let flags_ptr = core::ptr::addr_of_mut!((*desc_ptr).flags);
            write_volatile(flags_ptr, VIRTQ_DESC_F_WRITE);
            let next_ptr = core::ptr::addr_of_mut!((*desc_ptr).next);
            write_volatile(next_ptr, 0);
            fut_printf(b"[virtio-blk] desc[%d]: addr=0x%lx len=1 flags=0x%x next=0\n\0".as_ptr(),
                desc_status as u32, status_phys, VIRTQ_DESC_F_WRITE as u32);

            // CRITICAL: Memory fence to ensure ALL descriptor writes are visible before updating available ring
            core::sync::atomic::fence(Ordering::SeqCst);

            let avail = &mut *self.avail;
            // CRITICAL: Use volatile write for ring array (shared memory with device)
            let ring_ptr = core::ptr::addr_of_mut!(avail.ring[slot as usize]);
            write_volatile(ring_ptr, desc_head);
            // CRITICAL: Use addr_of_mut! for packed struct field to avoid alignment issues
            let idx_ptr = core::ptr::addr_of_mut!(avail.idx);
            let old_idx = read_volatile(idx_ptr);
            let new_idx = old_idx.wrapping_add(1);
            write_volatile(idx_ptr, new_idx);  // CRITICAL: Volatile write for device visibility
            fut_printf(b"[virtio-blk] enqueue: slot=%d desc_head=%d avail.idx %d -> %d avail.flags=%d\n\0".as_ptr(),
                slot as u32, desc_head as u32, old_idx as u32, new_idx as u32, avail.flags as u32);
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
                    isr_status = core::ptr::read_volatile(isr_ptr);
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
    common: *mut u8,  // Changed from *mut VirtioPciCommonCfg to *mut u8 for offset-based access
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
    #[cfg(target_arch = "aarch64")]
    mmio_base: u64,  // MMIO base address for ARM64
}

// ARM64: Store MMIO device handle globally for access in probe()
#[cfg(target_arch = "aarch64")]
static mut MMIO_DEVICE_HANDLE: *mut c_void = ptr::null_mut();

unsafe impl Send for VirtioBlkDevice {}
unsafe impl Sync for VirtioBlkDevice {}

impl VirtioBlkDevice {
    /// Configure a single MSI-X table entry for device interrupt delivery.
    ///
    /// For MSI-X, the message address encodes the APIC destination and delivery mode,
    /// while the message data contains the interrupt vector number.
    ///
    /// # Parameters:
    /// - table_index: Index into the MSI-X table (0 for I/O queue, 1 for config changes)
    /// - vector: Interrupt vector number (typically 32-255)
    fn configure_msix_vector(&mut self, table_index: u16, vector: u8) {
        if self.msix_table.is_null() || table_index >= self.msix_table_size {
            return;
        }

        unsafe {
            // Use byte offset arithmetic to avoid alignment issues with packed struct
            // MsixTableEntry is 16 bytes (4 u32 fields): msg_addr_lo, msg_addr_hi, msg_data, vector_control
            let entry_offset = (table_index as usize) * size_of::<MsixTableEntry>();
            let base_ptr = self.msix_table.add(entry_offset) as *mut u32;

            // Message address: APIC physical address with destination encoding
            let msg_addr = APIC_MSG_ADDR_BASE;  // 0xFEE00000 (physical mode, APIC 0)

            // Message data: contains the interrupt vector
            let msg_data = vector as u32;

            // Vector control: bit 0 is mask bit (1=masked, 0=enabled)
            let vector_control = 0u32;

            // Write to MSI-X table using byte-offset pointers
            // Field offsets within MsixTableEntry: 0=msg_addr_lo, 4=msg_addr_hi, 8=msg_data, 12=vector_control
            write_volatile(base_ptr.add(0), msg_addr);                // msg_addr_lo
            write_volatile(base_ptr.add(1), 0);                       // msg_addr_hi
            write_volatile(base_ptr.add(2), msg_data);                // msg_data
            write_volatile(base_ptr.add(3), vector_control);          // vector_control

            // Memory fence to ensure writes are visible to device
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            fut_printf(b"[virtio-blk] MSI-X table[%d]: configured with vector=%d (addr=0x%x data=0x%x)\n\0".as_ptr(),
                table_index as u32, vector as u32, msg_addr, msg_data);
        }
    }

    // ARM64 MMIO helper methods
    #[cfg(target_arch = "aarch64")]
    fn mmio_read32(&self, offset: u32) -> u32 {
        unsafe {
            let reg = (self.mmio_base + offset as u64) as *const u32;
            core::ptr::read_volatile(reg)
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn mmio_write32(&mut self, offset: u32, value: u32) {
        unsafe {
            let reg = (self.mmio_base + offset as u64) as *mut u32;
            core::ptr::write_volatile(reg, value);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

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
            #[cfg(target_arch = "aarch64")]
            mmio_base: 0,
        };

        // ARM64: Initialize MMIO base address
        #[cfg(target_arch = "aarch64")]
        {
            unsafe {
                if !MMIO_DEVICE_HANDLE.is_null() {
                    dev.mmio_base = virtio_mmio_get_base_addr(MMIO_DEVICE_HANDLE);
                    log("virtio-blk: MMIO base address configured");
                } else {
                    log("virtio-blk: ERROR - No MMIO device handle");
                    return Err(ENODEV);
                }
            }
        }

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
            let current_status = common_read8(dev.common, VIRTIO_PCI_COMMON_STATUS);
            common_write8(dev.common, VIRTIO_PCI_COMMON_STATUS, current_status | VIRTIO_STATUS_DRIVER_OK);

            let final_status = common_read8(dev.common, VIRTIO_PCI_COMMON_STATUS);
            let queue_enabled = common_read16(dev.common, VIRTIO_PCI_COMMON_Q_ENABLE);
            fut_printf(b"[virtio-blk] DRIVER_OK set: status=0x%x queue_enable=%d\n\0".as_ptr(),
                final_status as u32, queue_enabled as u32);
        }

        Ok(dev)
    }

    fn setup_bars(&mut self) {
        // ARM64: OS must assign BARs explicitly via ECAM
        #[cfg(target_arch = "aarch64")]
        {
            for idx in 0..6u8 {
                let assigned = unsafe {
                    arm64_pci_assign_bar(self.pci.bus, self.pci.device, self.pci.function, idx)
                };
                self.bars[idx as usize] = assigned;
                if assigned != 0 {
                    log_bar(idx, assigned as u32, assigned);
                }
            }
            return;
        }

        // x86_64: Read BARs already assigned by BIOS
        #[cfg(target_arch = "x86_64")]
        {
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

        // ARM64: MMU disabled, physical addresses are virtual addresses
        #[cfg(target_arch = "aarch64")]
        let virt = phys as *mut u8;

        // x86_64: Need to map MMIO region
        #[cfg(target_arch = "x86_64")]
        let virt = unsafe { map_mmio_region(phys, cap.length as usize, MMIO_PTE_FLAGS) };

        virt
    }

    fn parse_capabilities(&mut self) -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            // ARM64 MMIO: Skip PCI capability parsing, use direct MMIO access
            log("virtio-blk: ARM64 MMIO mode, skipping PCI capability parsing");
            return true;
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut found_vendor = self.parse_standard_capabilities();
            if !found_vendor {
                found_vendor = self.parse_extended_capabilities();
            }
            if !found_vendor {
                log("virtio-blk: no virtio vendor capabilities discovered");
            }
            !self.common.is_null() && !self.config.is_null() && !self.notify_base.is_null()
        }
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
                self.common = mapped;  // Store as raw *mut u8 for offset-based access
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
                // Store ISR pointer globally for interrupt handler to access
                VIRTIO_ISR_PTR.store(self.isr as u64, Ordering::Release);
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

                // ARM64: MMU disabled, physical addresses are virtual addresses
                #[cfg(target_arch = "aarch64")]
                let msix_virt = table_phys as *mut u8;

                // x86_64: Need to map MMIO region
                #[cfg(target_arch = "x86_64")]
                let msix_virt = unsafe { map_mmio_region(table_phys, table_size, MMIO_PTE_FLAGS) };

                self.msix_table = msix_virt;
                if !self.msix_table.is_null() {
                    unsafe {
                        fut_printf(b"[virtio-blk] MSI-X table mapped: phys=0x%lx virt=%p size=%d entries\n\0".as_ptr(),
                            table_phys, self.msix_table, self.msix_table_size as u32);
                    }
                }
            }
        }

        // Enable MSI-X for modern virtio device operation
        // Set MSI-X enable bit (bit 15) and clear function mask bit (bit 14)
        // This allows the device to deliver interrupts via MSI-X
        let enable_mask = MSIX_CONTROL_ENABLE;           // Set bit 15 (enable)
        let function_mask = MSIX_CONTROL_MASK;           // Bit 14 (mask all vectors)
        let new_control = (control | enable_mask) & !function_mask;  // Enable, unmask

        pci_config_write16(
            self.pci.bus,
            self.pci.device,
            self.pci.function,
            offset.wrapping_add(2),
            new_control,
        );

        let readback = pci_config_read16(self.pci.bus, self.pci.device, self.pci.function, offset.wrapping_add(2));
        self.msix_enabled = (readback & MSIX_CONTROL_ENABLE) != 0;

        unsafe {
            fut_printf(b"[virtio-blk] MSI-X enabled: control=0x%x->0x%x (enable=%d mask=%d)\n\0".as_ptr(),
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

            // Unmask the IRQ in the PIC - x86_64 only
            #[cfg(target_arch = "x86_64")]
            pic_unmask_irq(interrupt_line);
        }

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn negotiate_features(&mut self) -> Result<(), FutStatus> {
        unsafe {
            // Set ACKNOWLEDGE | DRIVER status
            common_write8(self.common, VIRTIO_PCI_COMMON_STATUS, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

            // Read device features - word 0 (bits 0-31)
            common_write32(self.common, VIRTIO_PCI_COMMON_DFSELECT, 0);
            let feat_low = common_read32(self.common, VIRTIO_PCI_COMMON_DF);

            // Read device features - word 1 (bits 32-63)
            common_write32(self.common, VIRTIO_PCI_COMMON_DFSELECT, 1);
            let feat_high = common_read32(self.common, VIRTIO_PCI_COMMON_DF);

            let features = ((feat_high as u64) << 32) | feat_low as u64;
            fut_printf(b"[virtio-blk] device features: 0x%lx\n\0".as_ptr(), features);

            /* CRITICAL: We use modern VirtIO transport (PCI capabilities) so we MUST
             * negotiate VIRTIO_F_VERSION_1 (bit 32). Without this, QEMU won't process
             * requests from modern drivers! */
            const VIRTIO_F_VERSION_1: u64 = 1u64 << 32;
            const VIRTIO_F_ANY_LAYOUT: u64 = 1u64 << 27;

            // For modern mode: MUST negotiate VERSION_1, optionally accept ANY_LAYOUT
            let mut driver_features = 0u64;
            if (features & VIRTIO_F_VERSION_1) != 0 {
                driver_features |= VIRTIO_F_VERSION_1;
            }
            if (features & VIRTIO_F_ANY_LAYOUT) != 0 {
                driver_features |= VIRTIO_F_ANY_LAYOUT;
            }

            // Write driver features - word 0 (bits 0-31)
            common_write32(self.common, VIRTIO_PCI_COMMON_GFSELECT, 0);
            common_write32(self.common, VIRTIO_PCI_COMMON_GF, driver_features as u32);

            // Write driver features - word 1 (bits 32-63)
            common_write32(self.common, VIRTIO_PCI_COMMON_GFSELECT, 1);
            common_write32(self.common, VIRTIO_PCI_COMMON_GF, (driver_features >> 32) as u32);

            fut_printf(b"[virtio-blk] driver features: 0x%lx (minimal set)\n\0".as_ptr(),
                driver_features);

            // Set FEATURES_OK status bit
            let current_status = common_read8(self.common, VIRTIO_PCI_COMMON_STATUS);
            common_write8(self.common, VIRTIO_PCI_COMMON_STATUS, current_status | VIRTIO_STATUS_FEATURES_OK);

            // Read back status to verify FEATURES_OK was accepted
            let status_check = common_read8(self.common, VIRTIO_PCI_COMMON_STATUS);
            fut_printf(b"[virtio-blk] device_status after FEATURES_OK: 0x%x\n\0".as_ptr(), status_check as u32);

            if (status_check & VIRTIO_STATUS_FEATURES_OK) == 0 {
                log("virtio-blk: feature negotiation failed");
                return Err(ENODEV);
            }
            /* DO NOT set DRIVER_OK here - must wait until after queue setup */
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn negotiate_features(&mut self) -> Result<(), FutStatus> {
        log("virtio-blk: MMIO feature negotiation");

        // Acknowledge device
        self.mmio_write32(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE as u32);

        // Announce driver
        self.mmio_write32(VIRTIO_MMIO_STATUS, (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER) as u32);

        // Read device features
        self.mmio_write32(VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
        let device_features = self.mmio_read32(VIRTIO_MMIO_DEVICE_FEATURES);

        log("virtio-blk: Device offers features");

        // Accept all offered features for now
        self.mmio_write32(VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
        self.mmio_write32(VIRTIO_MMIO_DRIVER_FEATURES, device_features);

        self.mmio_write32(VIRTIO_MMIO_STATUS,
            (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK) as u32);

        let status = self.mmio_read32(VIRTIO_MMIO_STATUS);
        if (status & VIRTIO_STATUS_FEATURES_OK as u32) == 0 {
            log("virtio-blk: WARNING - Device rejected our feature selection");
            // Try again with no features
            self.mmio_write32(VIRTIO_MMIO_DRIVER_FEATURES, 0);
            self.mmio_write32(VIRTIO_MMIO_STATUS,
                (VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK) as u32);
            let status2 = self.mmio_read32(VIRTIO_MMIO_STATUS);
            if (status2 & VIRTIO_STATUS_FEATURES_OK as u32) == 0 {
                return Err(EIO);
            }
        }

        log("virtio-blk: Feature negotiation complete");
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn init_queue(&mut self) -> Result<(), FutStatus> {
        unsafe {
            // Select queue 0
            common_write16(self.common, VIRTIO_PCI_COMMON_Q_SELECT, 0);

            // Read max queue size from device
            let device_qsize = common_read16(self.common, VIRTIO_PCI_COMMON_Q_SIZE);
            if device_qsize == 0 {
                return Err(ENODEV);
            }
            let qsize = min(device_qsize, QUEUE_SIZE);
            self.queue.setup(qsize)?;

            // Write queue size
            common_write16(self.common, VIRTIO_PCI_COMMON_Q_SIZE, qsize);

            /* Configure MSI-X vectors if enabled, otherwise use legacy INTx */
            if self.msix_enabled && !self.msix_table.is_null() && self.msix_table_size > 0 {
                // Configure MSI-X table entries for I/O completion and config changes
                // Vector 0 for I/O queue, Vector 1 for config changes
                let io_vector: u8 = 0x2A;   // Arbitrary vector (42), assigned to queue I/O
                let cfg_vector: u8 = 0x2B;  // Arbitrary vector (43), assigned to config changes

                // Configure MSI-X table entries with the chosen vectors
                self.configure_msix_vector(0, io_vector);
                if self.msix_table_size > 1 {
                    self.configure_msix_vector(1, cfg_vector);
                }

                // Tell device to use MSI-X vectors (instead of NO_VECTOR)
                common_write16(self.common, VIRTIO_PCI_COMMON_Q_MSIX, 0);  // Vector 0 for queue I/O
                common_write16(self.common, VIRTIO_PCI_COMMON_MSIX, 1);    // Vector 1 for config

                fut_printf(b"[virtio-blk] MSI-X enabled with vectors I/O=%d config=%d\n\0".as_ptr(),
                    io_vector as u32, cfg_vector as u32);

                // Register the MSI-X interrupt vectors with the IDT
                let handler_addr = virtio_blk_irq_handler as u64;
                fut_idt_set_entry(io_vector, handler_addr, GDT_KERNEL_CODE, IDT_TYPE_INTERRUPT, 0);
                fut_printf(b"[virtio-blk] Registered MSI-X I/O vector %d with IDT\n\0".as_ptr(),
                    io_vector as u32);

                // Store the MSI-X vector for handler reference
                VIRTIO_BLK_IRQ_VECTOR.store(io_vector, Ordering::Relaxed);
            } else {
                // Fall back to legacy INTx interrupts
                common_write16(self.common, VIRTIO_PCI_COMMON_Q_MSIX, 0xFFFF);  // NO_VECTOR - use legacy INTx
                common_write16(self.common, VIRTIO_PCI_COMMON_MSIX, 0xFFFF);    // NO_VECTOR for config
                fut_printf(b"[virtio-blk] MSI-X not available, using legacy INTx\n\0".as_ptr());
            }

            // Modern VirtIO 1.0+ uses byte addresses in queue address registers
            // Write queue addresses as 64-bit values (like virtio-gpu)
            fut_printf(b"[virtio-blk] queue addrs: desc=0x%lx avail=0x%lx used=0x%lx\n\0".as_ptr(),
                self.queue.desc_phys, self.queue.avail_phys, self.queue.used_phys);

            // Write descriptor table address (64-bit write with barriers)
            common_write64(self.common, VIRTIO_PCI_COMMON_Q_DESCLO, self.queue.desc_phys);

            // Write available ring address (64-bit write with barriers)
            common_write64(self.common, VIRTIO_PCI_COMMON_Q_AVAILLO, self.queue.avail_phys);

            // Write used ring address (64-bit write with barriers)
            common_write64(self.common, VIRTIO_PCI_COMMON_Q_USEDLO, self.queue.used_phys);

            // Enable the queue
            common_write16(self.common, VIRTIO_PCI_COMMON_Q_ENABLE, 1);

            // Read notify offset
            self.queue.notify_off = common_read16(self.common, VIRTIO_PCI_COMMON_Q_NOTIFYOFF);

            fut_printf(b"[virtio-blk] queue setup complete (notify_off=%d)\n\0".as_ptr(),
                self.queue.notify_off as u32);
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn init_queue(&mut self) -> Result<(), FutStatus> {
        log("virtio-blk: MMIO queue initialization");

        // Setup queue
        self.mmio_write32(VIRTIO_MMIO_QUEUE_SEL, 0);
        self.queue.setup(QUEUE_SIZE)?;
        self.mmio_write32(VIRTIO_MMIO_QUEUE_NUM, QUEUE_SIZE as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DESC_LOW, (self.queue.desc_phys & 0xFFFFFFFF) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DESC_HIGH, (self.queue.desc_phys >> 32) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DRIVER_LOW, (self.queue.avail_phys & 0xFFFFFFFF) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DRIVER_HIGH, (self.queue.avail_phys >> 32) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DEVICE_LOW, (self.queue.used_phys & 0xFFFFFFFF) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_DEVICE_HIGH, (self.queue.used_phys >> 32) as u32);
        self.mmio_write32(VIRTIO_MMIO_QUEUE_READY, 1);
        self.queue.notify_off = 0; // MMIO uses direct queue_notify register

        log("virtio-blk: Queue configured");
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

    #[cfg(target_arch = "x86_64")]
    fn notify_queue(&self) {
        unsafe {
            let off = (self.queue.notify_off as u32 * self.notify_off_multiplier) as usize;
            let ptr = self.notify_base.add(off) as *mut u16;

            fut_printf(b"[virtio-blk] notify: queue_notify_off=%u multiplier=%u offset=%u base=%p final_ptr=%p\n\0".as_ptr(),
                self.queue.notify_off as u32,
                self.notify_off_multiplier,
                off as u32,
                self.notify_base,
                ptr);

            /* Write the queue index to notify QEMU */
            write_volatile(ptr, 0);  // Queue 0

            /* Verify write succeeded by reading back (may help trigger QEMU too) */
            let _readback = read_volatile(ptr as *const u16);

            fut_printf(b"[virtio-blk] notified queue 0 (wrote to ptr=%p)\n\0".as_ptr(), ptr);
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn notify_queue(&self) {
        // MMIO: write queue index to QUEUE_NOTIFY register
        unsafe {
            let reg = (self.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY as u64) as *mut u32;
            write_volatile(reg, 0);
            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
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
            // CRITICAL: Use volatile writes for DMA buffer (shared with device)
            // Write each field separately to ensure visibility to device
            let req_type_ptr = core::ptr::addr_of_mut!((*self.dma).header.req_type);
            write_volatile(req_type_ptr, req_type);
            let reserved_ptr = core::ptr::addr_of_mut!((*self.dma).header.reserved);
            write_volatile(reserved_ptr, 0);
            let sector_ptr = core::ptr::addr_of_mut!((*self.dma).header.sector);
            write_volatile(sector_ptr, lba);
            let status_ptr = core::ptr::addr_of_mut!((*self.dma).status);
            write_volatile(status_ptr, 0xFF);

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

// ARM64: Find VirtIO block device via MMIO transport
#[cfg(target_arch = "aarch64")]
fn find_device(_pci_hint: u64) -> Option<PciAddress> {
    const VIRTIO_DEV_BLOCK: u32 = 2;
    if let Some(transport) = MmioTransport::find_device(VIRTIO_DEV_BLOCK) {
        log("virtio-blk: found device via MMIO transport");
        unsafe {
            MMIO_DEVICE_HANDLE = transport.as_ptr();
        }
        // Return dummy PCI address for compatibility
        return Some(PciAddress { bus: 0xFF, device: 0xFF, function: 0xFF });
    }
    log("virtio-blk: no virtio device found");
    None
}

// x86-64: Find VirtIO block device via PCI
#[cfg(target_arch = "x86_64")]
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

        // ARM64: MMU disabled, physical addresses are virtual addresses
        #[cfg(target_arch = "aarch64")]
        let mapped = map_start as *mut u8;

        // x86_64: Need to map MMIO region
        #[cfg(target_arch = "x86_64")]
        let mapped = unsafe { map_mmio_region(map_start, size, MMIO_PTE_FLAGS) };

        if mapped.is_null() {
            return None;
        }

        unsafe {
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
        // x86_64: Unmap MMIO region
        #[cfg(target_arch = "x86_64")]
        unsafe {
            unmap_mmio_region(self.map_base, self.size);
        }

        // ARM64: No unmapping needed (physical addresses used directly)
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

// Platform-specific PCI access functions
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "aarch64")]
fn pci_config_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe { arm64_pci_read32(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "x86_64")]
fn pci_config_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    ((value >> shift) & 0xFFFF) as u16
}

#[cfg(target_arch = "aarch64")]
fn pci_config_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    unsafe { arm64_pci_read16(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "x86_64")]
fn pci_config_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    ((value >> shift) & 0xFF) as u8
}

#[cfg(target_arch = "aarch64")]
fn pci_config_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    unsafe { arm64_pci_read8(bus, device, function, offset as u16) }
}

#[cfg(target_arch = "x86_64")]
fn pci_config_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let mut current = pci_config_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    current &= !(0xFFFF << shift);
    current |= u32::from(value) << shift;
    pci_config_write32(bus, device, function, offset & 0xFC, current);
}

#[cfg(target_arch = "aarch64")]
fn pci_config_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    unsafe { arm64_pci_write16(bus, device, function, offset as u16, value) }
}

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "aarch64")]
fn pci_config_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    unsafe { arm64_pci_write32(bus, device, function, offset as u16, value) }
}

// x86_64 I/O port access
#[cfg(target_arch = "x86_64")]
unsafe fn outl(port: u16, value: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags)); }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    unsafe { asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, preserves_flags)); }
    value
}

// ARM64 PCI ECAM functions
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn arm64_pci_read32(bus: u8, dev: u8, func: u8, reg: u16) -> u32;
    fn arm64_pci_read16(bus: u8, dev: u8, func: u8, reg: u16) -> u16;
    fn arm64_pci_read8(bus: u8, dev: u8, func: u8, reg: u16) -> u8;
    fn arm64_pci_write32(bus: u8, dev: u8, func: u8, reg: u16, value: u32);
    fn arm64_pci_write16(bus: u8, dev: u8, func: u8, reg: u16, value: u16);
    fn arm64_pci_assign_bar(bus: u8, dev: u8, func: u8, bar_num: u8) -> u64;
}
#[inline(always)]
#[cfg(target_arch = "x86_64")]
fn virt_to_phys_addr(addr: usize) -> u64 {
    debug_assert!(addr >= PMAP_DIRECT_VIRT_BASE);
    (addr - PMAP_DIRECT_VIRT_BASE) as u64
}

#[inline(always)]
#[cfg(target_arch = "aarch64")]
fn virt_to_phys_addr(addr: usize) -> u64 {
    // ARM64: MMU disabled, addresses are already physical
    addr as u64
}

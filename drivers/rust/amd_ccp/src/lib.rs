// SPDX-License-Identifier: MPL-2.0
//
// AMD Cryptographic Coprocessor (CCP) Driver for Futura OS
//
// Implements hardware-accelerated cryptographic operations using the AMD
// Platform Security Processor's CCP engine found on Ryzen AM4/AM5 CPUs.
//
// Architecture:
//   - PCI device discovery (vendor 1022h, device 1456h/1468h/15DFh)
//   - BAR2 MMIO for CCP command queue access
//   - Command descriptors are 32 bytes, submitted via a hardware queue
//   - Queue registers at offset 0x100 from BAR2 base
//   - Supported engines: AES (0), SHA (2), RNG (7)
//
// The CCP exposes command queues through MMIO. Each command descriptor
// describes a cryptographic operation (engine, key, source, destination,
// lengths). Commands are enqueued by advancing the tail pointer; the
// hardware processes them and advances the head pointer.
//
// Supported operations:
//   - SHA-256 hashing
//   - AES-256-CBC encryption/decryption
//   - Hardware random number generation

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{alloc_page, free_page, log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn fut_virt_to_phys(vaddr: *const c_void) -> u64;
}

// -- PCI device structure (mirrors kernel/pci.h) --

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

// -- Static state wrapper --

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// -- PCI configuration space I/O --

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;

fn pci_config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        let val: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") val);
        val
    }
}

fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, dev, func, offset & 0xFC);
    ((val32 >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

fn pci_write16(bus: u8, dev: u8, func: u8, offset: u8, val: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let mut val32 = pci_read32(bus, dev, func, aligned);
    val32 &= !(0xFFFF << shift);
    val32 |= (val as u32) << shift;
    pci_write32(bus, dev, func, aligned, val32);
}

// -- Virtual-to-physical address translation --

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { fut_virt_to_phys(ptr as *const c_void) }
}

// -- AMD CCP PCI identification --

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// CCP device IDs across Ryzen generations.
/// Ryzen 1000/2000 (Zen/Zen+) CCP.
const CCP_DEVICE_ZEN: u16 = 0x1456;
/// Ryzen 3000 (Zen2) CCP.
const CCP_DEVICE_ZEN2: u16 = 0x1468;
/// Ryzen 5000/7000 (Zen3/Zen4) CCP.
const CCP_DEVICE_ZEN3: u16 = 0x15DF;

/// PCI class for CCP: Encryption/Decryption controller.
const CCP_CLASS: u8 = 0x10;
/// PCI subclass: other crypto device.
const CCP_SUBCLASS: u8 = 0x80;

fn is_ccp_device(dev: &PciDevice) -> bool {
    dev.vendor_id == AMD_VENDOR_ID
        && (dev.device_id == CCP_DEVICE_ZEN
            || dev.device_id == CCP_DEVICE_ZEN2
            || dev.device_id == CCP_DEVICE_ZEN3)
        && dev.class_code == CCP_CLASS
        && dev.subclass == CCP_SUBCLASS
}

// -- CCP Queue Register Offsets (relative to queue base at BAR2 + 0x100) --

/// Queue mechanism control register.
const Q_CTRL: usize = 0x00;
/// Queue head pointer (read-only, hardware advances this).
const Q_HEAD: usize = 0x04;
/// Queue tail pointer (software advances this to submit commands).
const Q_TAIL: usize = 0x08;
/// Queue size (number of descriptor entries minus 1).
const Q_SIZE: usize = 0x0C;
/// Queue base address low 32 bits.
const Q_BASE_LO: usize = 0x10;
/// Queue base address high 32 bits.
const Q_BASE_HI: usize = 0x14;

/// Offset of queue 0 registers from BAR2 base.
const QUEUE0_REG_BASE: usize = 0x100;

// -- Q_CTRL register bits --

/// Queue run bit: set to 1 to enable the queue.
const Q_CTRL_RUN: u32 = 1 << 0;
/// Queue halt bit: set when queue is halted after an error.
const Q_CTRL_HALT: u32 = 1 << 1;
/// Queue error interrupt enable.
const Q_CTRL_ERR_IE: u32 = 1 << 2;
/// Queue completion interrupt enable.
const Q_CTRL_CPL_IE: u32 = 1 << 3;

// -- CCP Command Descriptor (32 bytes) --

/// Number of command descriptors in our queue.
const QUEUE_DEPTH: usize = 16;

/// Size of one CCP5 command descriptor in bytes.
const CMD_DESC_SIZE: usize = 32;

// -- CCP5 command descriptor word layout --
// Word 0: engine, function, flags (SOC, EOC, PROT, INIT, EOM)
// Word 1: length of data to process
// Word 2: source address low
// Word 3: source address high [15:0] + source memory type [17:16]
// Word 4: destination address low
// Word 5: destination address high [15:0] + destination memory type [17:16]
// Word 6: key/context address low
// Word 7: key/context address high [15:0] + key memory type [17:16]

// Engine IDs.
const ENGINE_AES: u32 = 0;
const ENGINE_SHA: u32 = 2;
const ENGINE_RNG: u32 = 7;

// AES function codes.
const AES_FUNC_DECRYPT: u32 = 0;
const AES_FUNC_ENCRYPT: u32 = 1;

// AES modes (stored in bits [4:3] of function field for AES engine).
const AES_MODE_CBC: u32 = 1;

// AES key sizes (bits [7:6] of function field for AES engine).
const AES_SIZE_256: u32 = 2;

// SHA types (function field for SHA engine).
const SHA_TYPE_256: u32 = 2;

// Command descriptor flags.
/// Start of command chain.
const CMD_SOC: u32 = 1 << 16;
/// End of command chain.
const CMD_EOC: u32 = 1 << 17;
/// Init flag (for SHA: initialise intermediate state).
const CMD_INIT: u32 = 1 << 18;
/// End-of-message flag (for SHA: finalise hash).
const CMD_EOM: u32 = 1 << 19;
/// Protected memory bit.
const CMD_PROT: u32 = 1 << 20;

// Memory types for address fields.
const MEM_TYPE_SYSTEM: u32 = 0;
const MEM_TYPE_LOCAL: u32 = 2;

// -- BAR2 MMIO size --

/// We map 64 KiB for the CCP BAR2 region to cover queue registers and LSBs.
const BAR2_MMIO_SIZE: usize = 0x10000;

// -- Polling timeout --

/// Maximum number of iterations to wait for the CCP to complete a command.
const POLL_TIMEOUT: u32 = 1_000_000;

// -- Driver state --

struct AmdCcp {
    /// Virtual address of BAR2 MMIO base.
    bar2_base: *mut u8,
    /// Physical address of BAR2.
    bar2_phys: u64,
    /// Virtual address of the command queue descriptor ring (page-aligned).
    queue_ring: *mut u8,
    /// Physical address of the command queue descriptor ring.
    queue_ring_phys: u64,
    /// Current tail index (next slot to write).
    tail: u32,
    /// PCI BDF for the CCP device.
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    /// Device ID (for logging).
    device_id: u16,
}

static CCP: StaticCell<Option<AmdCcp>> = StaticCell::new(None);

// -- MMIO register helpers --

impl AmdCcp {
    /// Read a 32-bit queue register.
    fn read_queue_reg(&self, offset: usize) -> u32 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.bar2_base.add(QUEUE0_REG_BASE + offset) as *const u32) }
    }

    /// Write a 32-bit queue register.
    fn write_queue_reg(&self, offset: usize, val: u32) {
        unsafe { write_volatile(self.bar2_base.add(QUEUE0_REG_BASE + offset) as *mut u32, val) };
        fence(Ordering::SeqCst);
    }

    /// Build and submit a single CCP5 command descriptor.
    ///
    /// Returns 0 on success, negative on error.
    fn submit_command(&mut self, words: &[u32; 8]) -> i32 {
        // Write the descriptor into the ring at the current tail position.
        let desc_offset = (self.tail as usize) * CMD_DESC_SIZE;
        let desc_ptr = unsafe { self.queue_ring.add(desc_offset) };

        for i in 0..8 {
            unsafe {
                write_volatile(desc_ptr.add(i * 4) as *mut u32, words[i]);
            }
        }

        fence(Ordering::SeqCst);

        // Advance the tail pointer (wraps around at QUEUE_DEPTH).
        self.tail = (self.tail + 1) % (QUEUE_DEPTH as u32);
        self.write_queue_reg(Q_TAIL, self.tail);

        // Poll until the head catches up to the tail (command completed).
        let mut timeout = POLL_TIMEOUT;
        loop {
            let head = self.read_queue_reg(Q_HEAD);
            if head == self.tail {
                break;
            }

            // Check for halt (error condition).
            let ctrl = self.read_queue_reg(Q_CTRL);
            if ctrl & Q_CTRL_HALT != 0 {
                log("amd_ccp: queue halted due to error");
                // Attempt to restart the queue.
                self.reset_queue();
                return -5; // EIO
            }

            timeout -= 1;
            if timeout == 0 {
                log("amd_ccp: command timed out");
                self.reset_queue();
                return -110; // ETIMEDOUT
            }
        }

        0
    }

    /// Reset and restart the command queue after an error.
    fn reset_queue(&mut self) {
        // Stop the queue.
        self.write_queue_reg(Q_CTRL, 0);
        fence(Ordering::SeqCst);

        // Clear the ring memory.
        let ring_size = QUEUE_DEPTH * CMD_DESC_SIZE;
        unsafe {
            core::ptr::write_bytes(self.queue_ring, 0, ring_size);
        }

        // Reset head/tail.
        self.tail = 0;
        self.write_queue_reg(Q_HEAD, 0);
        self.write_queue_reg(Q_TAIL, 0);

        // Re-program queue base address and size.
        self.write_queue_reg(Q_BASE_LO, self.queue_ring_phys as u32);
        self.write_queue_reg(Q_BASE_HI, (self.queue_ring_phys >> 32) as u32);
        self.write_queue_reg(Q_SIZE, (QUEUE_DEPTH - 1) as u32);

        // Re-enable the queue.
        self.write_queue_reg(Q_CTRL, Q_CTRL_RUN);
        fence(Ordering::SeqCst);
    }

    /// Build word 0 of a CCP5 command descriptor.
    ///
    /// Layout: bits [3:0] = engine, bits [8:4] = function, bits [20:16] = flags
    fn build_word0(engine: u32, function: u32, flags: u32) -> u32 {
        (engine & 0x0F) | ((function & 0x1F) << 4) | flags
    }

    /// Build an address high word with memory type.
    ///
    /// bits [15:0] = high 16 bits of address, bits [17:16] = memory type
    fn build_addr_hi(addr: u64, mem_type: u32) -> u32 {
        ((addr >> 32) as u32 & 0xFFFF) | ((mem_type & 0x3) << 16)
    }
}

// -- PCI BAR2 reading --

/// Read BAR2 (64-bit MMIO) from PCI config space.
/// BAR2 is at PCI config offset 0x18 (BAR0=0x10, BAR1=0x14, BAR2=0x18).
fn read_bar2(bus: u8, dev: u8, func: u8) -> u64 {
    let bar2_lo = pci_read32(bus, dev, func, 0x18) & !0xF;
    let bar2_hi = pci_read32(bus, dev, func, 0x1C);
    (bar2_lo as u64) | ((bar2_hi as u64) << 32)
}

// -- PCI device discovery --

/// Find an AMD CCP device on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_ccp() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if is_ccp_device(dev) {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

// -- SHA-256 initial hash values (H0..H7) --

const SHA256_INIT: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// -- FFI exports --

/// Initialise the AMD CCP driver.
///
/// Scans PCI for an AMD CCP device, maps BAR2, allocates a command queue
/// descriptor ring, and starts the hardware queue.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_ccp_init() -> i32 {
    log("amd_ccp: scanning PCI for AMD CCP device...");

    let (bus, dev, func, device_id) = match find_ccp() {
        Some(bdf) => bdf,
        None => {
            log("amd_ccp: no AMD CCP device found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_ccp: found CCP (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable PCI memory space access and bus mastering.
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06);

    // Read BAR2 (64-bit MMIO).
    let bar2_phys = read_bar2(bus, dev, func);
    if bar2_phys == 0 {
        log("amd_ccp: BAR2 not configured");
        return -2;
    }

    unsafe {
        fut_printf(
            b"amd_ccp: BAR2 phys = 0x%016lx\n\0".as_ptr(),
            bar2_phys,
        );
    }

    // Map the BAR2 MMIO region.
    let bar2_base = unsafe { map_mmio_region(bar2_phys, BAR2_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if bar2_base.is_null() {
        log("amd_ccp: failed to map BAR2 MMIO region");
        return -3;
    }

    // Verify MMIO is accessible (read queue control; should not be all-ones).
    fence(Ordering::SeqCst);
    let probe = unsafe { read_volatile(bar2_base.add(QUEUE0_REG_BASE + Q_CTRL) as *const u32) };
    if probe == 0xFFFF_FFFF {
        log("amd_ccp: MMIO region not responding (all-ones read)");
        unsafe { unmap_mmio_region(bar2_base, BAR2_MMIO_SIZE) };
        return -4;
    }

    // Allocate a page-aligned command descriptor ring.
    // QUEUE_DEPTH * 32 bytes = 512 bytes; fits in a single 4 KiB page.
    let queue_ring = unsafe { alloc_page() };
    if queue_ring.is_null() {
        log("amd_ccp: failed to allocate command queue ring");
        unsafe { unmap_mmio_region(bar2_base, BAR2_MMIO_SIZE) };
        return -12; // ENOMEM
    }

    // Zero the ring.
    unsafe { core::ptr::write_bytes(queue_ring, 0, 4096) };

    let queue_ring_phys = virt_to_phys(queue_ring);

    // Stop the queue if it was previously running.
    unsafe {
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_CTRL) as *mut u32,
            0,
        );
    }
    fence(Ordering::SeqCst);

    // Program queue base address.
    unsafe {
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_BASE_LO) as *mut u32,
            queue_ring_phys as u32,
        );
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_BASE_HI) as *mut u32,
            (queue_ring_phys >> 32) as u32,
        );
    }

    // Set queue size (number of entries minus 1).
    unsafe {
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_SIZE) as *mut u32,
            (QUEUE_DEPTH - 1) as u32,
        );
    }

    // Reset head and tail.
    unsafe {
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_HEAD) as *mut u32,
            0,
        );
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_TAIL) as *mut u32,
            0,
        );
    }

    // Enable the queue (polling mode, no interrupts).
    unsafe {
        write_volatile(
            bar2_base.add(QUEUE0_REG_BASE + Q_CTRL) as *mut u32,
            Q_CTRL_RUN,
        );
    }
    fence(Ordering::SeqCst);

    // Verify the queue is running.
    let ctrl = unsafe { read_volatile(bar2_base.add(QUEUE0_REG_BASE + Q_CTRL) as *const u32) };
    if ctrl & Q_CTRL_HALT != 0 {
        log("amd_ccp: queue halted immediately after start");
        unsafe {
            free_page(queue_ring);
            unmap_mmio_region(bar2_base, BAR2_MMIO_SIZE);
        }
        return -5;
    }

    let ccp = AmdCcp {
        bar2_base,
        bar2_phys,
        queue_ring,
        queue_ring_phys,
        tail: 0,
        pci_bus: bus,
        pci_dev: dev,
        pci_func: func,
        device_id,
    };

    unsafe {
        (*CCP.get()) = Some(ccp);
    }

    unsafe {
        fut_printf(
            b"amd_ccp: queue ring phys = 0x%016lx, depth = %u\n\0".as_ptr(),
            queue_ring_phys,
            QUEUE_DEPTH as u32,
        );
    }

    log("amd_ccp: driver initialised successfully");
    0
}

/// Compute a SHA-256 hash of the given data using the CCP hardware.
///
/// `data` - Pointer to input data.
/// `len`  - Length of input data in bytes.
/// `hash` - Pointer to a 32-byte buffer to receive the SHA-256 digest.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_ccp_sha256(data: *const u8, len: u32, hash: *mut u8) -> i32 {
    if data.is_null() || hash.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let ccp = match unsafe { (*CCP.get()).as_mut() } {
        Some(c) => c,
        None => return -19, // ENODEV
    };

    // Allocate a scratch page for the SHA context/state (256 bits = 32 bytes).
    // The CCP uses this as the intermediate hash state buffer.
    let ctx_page = unsafe { alloc_page() };
    if ctx_page.is_null() {
        return -12; // ENOMEM
    }
    unsafe { core::ptr::write_bytes(ctx_page, 0, 4096) };

    // Write SHA-256 initial hash values into the context buffer (big-endian).
    for i in 0..8 {
        let be_val = SHA256_INIT[i].to_be();
        unsafe {
            write_volatile(ctx_page.add(i * 4) as *mut u32, be_val);
        }
    }

    let ctx_phys = virt_to_phys(ctx_page);
    let src_phys = virt_to_phys(data);

    // SHA function field: SHA type in bits [3:0].
    let function = SHA_TYPE_256;

    // Build the command descriptor.
    // For SHA: SOC + EOC + INIT + EOM (single-shot hash).
    let word0 = AmdCcp::build_word0(ENGINE_SHA, function, CMD_SOC | CMD_EOC | CMD_INIT | CMD_EOM);
    let word1 = len;
    let word2 = src_phys as u32;
    let word3 = AmdCcp::build_addr_hi(src_phys, MEM_TYPE_SYSTEM);
    // Destination is unused for SHA (result goes to context).
    let word4 = 0u32;
    let word5 = 0u32;
    // Key/context address points to our hash state buffer.
    let word6 = ctx_phys as u32;
    let word7 = AmdCcp::build_addr_hi(ctx_phys, MEM_TYPE_SYSTEM);

    let words = [word0, word1, word2, word3, word4, word5, word6, word7];
    let ret = ccp.submit_command(&words);

    if ret == 0 {
        // Read the completed hash from the context buffer and copy to output.
        fence(Ordering::SeqCst);
        unsafe {
            core::ptr::copy_nonoverlapping(ctx_page, hash, 32);
        }
    }

    unsafe { free_page(ctx_page) };
    ret
}

/// Perform AES-256-CBC encryption or decryption using the CCP hardware.
///
/// `input`   - Pointer to input data (must be 16-byte aligned in length).
/// `output`  - Pointer to output buffer (same size as input).
/// `len`     - Length of data in bytes (must be a multiple of 16).
/// `key`     - Pointer to the 256-bit (32-byte) AES key.
/// `iv`      - Pointer to the 128-bit (16-byte) initialisation vector.
/// `encrypt` - true for encryption, false for decryption.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_ccp_aes256_cbc(
    input: *const u8,
    output: *mut u8,
    len: u32,
    key: *const u8,
    iv: *const u8,
    encrypt: bool,
) -> i32 {
    if input.is_null() || output.is_null() || key.is_null() || iv.is_null() {
        return -22; // EINVAL
    }
    if len == 0 || (len % 16) != 0 {
        return -22; // EINVAL
    }

    let ccp = match unsafe { (*CCP.get()).as_mut() } {
        Some(c) => c,
        None => return -19, // ENODEV
    };

    // Allocate a scratch page for key + IV context.
    // Layout: [0..31] = 256-bit key, [32..47] = 128-bit IV.
    let key_page = unsafe { alloc_page() };
    if key_page.is_null() {
        return -12; // ENOMEM
    }
    unsafe { core::ptr::write_bytes(key_page, 0, 4096) };

    // Copy key and IV into the scratch page.
    unsafe {
        core::ptr::copy_nonoverlapping(key, key_page, 32);
        core::ptr::copy_nonoverlapping(iv, key_page.add(32), 16);
    }

    let key_phys = virt_to_phys(key_page);
    let iv_phys = virt_to_phys(unsafe { key_page.add(32) });
    let src_phys = virt_to_phys(input);
    let dst_phys = virt_to_phys(output as *const u8);

    // AES function field:
    //   bit 0: direction (0=decrypt, 1=encrypt)
    //   bits [4:3]: mode (1=CBC)
    //   bits [7:6]: key size (2=256-bit)
    let direction = if encrypt { AES_FUNC_ENCRYPT } else { AES_FUNC_DECRYPT };
    let function = direction | (AES_MODE_CBC << 3) | (AES_SIZE_256 << 6);

    // Build the command descriptor.
    let word0 = AmdCcp::build_word0(ENGINE_AES, function, CMD_SOC | CMD_EOC);
    let word1 = len;
    let word2 = src_phys as u32;
    let word3 = AmdCcp::build_addr_hi(src_phys, MEM_TYPE_SYSTEM);
    let word4 = dst_phys as u32;
    let word5 = AmdCcp::build_addr_hi(dst_phys, MEM_TYPE_SYSTEM);
    // Key address points to our key buffer. The CCP reads key from here.
    let word6 = key_phys as u32;
    let word7 = AmdCcp::build_addr_hi(key_phys, MEM_TYPE_SYSTEM);

    let words = [word0, word1, word2, word3, word4, word5, word6, word7];
    let ret = ccp.submit_command(&words);

    unsafe { free_page(key_page) };
    ret
}

/// Generate cryptographically secure random bytes using the CCP hardware RNG.
///
/// `buf` - Pointer to output buffer.
/// `len` - Number of random bytes to generate.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_ccp_random(buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let ccp = match unsafe { (*CCP.get()).as_mut() } {
        Some(c) => c,
        None => return -19, // ENODEV
    };

    // Allocate a scratch page for RNG output.
    // We generate up to 4096 bytes at a time and copy to the caller.
    let rng_page = unsafe { alloc_page() };
    if rng_page.is_null() {
        return -12; // ENOMEM
    }

    let mut remaining = len;
    let mut offset: u32 = 0;

    while remaining > 0 {
        let chunk = if remaining > 4096 { 4096 } else { remaining };

        unsafe { core::ptr::write_bytes(rng_page, 0, 4096) };

        let dst_phys = virt_to_phys(rng_page);

        // RNG engine: function field is 0 (TRNG), no special flags needed.
        let word0 = AmdCcp::build_word0(ENGINE_RNG, 0, CMD_SOC | CMD_EOC);
        let word1 = chunk;
        // Source is unused for RNG.
        let word2 = 0u32;
        let word3 = 0u32;
        // Destination is our scratch buffer.
        let word4 = dst_phys as u32;
        let word5 = AmdCcp::build_addr_hi(dst_phys, MEM_TYPE_SYSTEM);
        let word6 = 0u32;
        let word7 = 0u32;

        let words = [word0, word1, word2, word3, word4, word5, word6, word7];
        let ret = ccp.submit_command(&words);

        if ret != 0 {
            unsafe { free_page(rng_page) };
            return ret;
        }

        // Copy generated random data to the caller's buffer.
        fence(Ordering::SeqCst);
        unsafe {
            core::ptr::copy_nonoverlapping(rng_page, buf.add(offset as usize), chunk as usize);
        }

        remaining -= chunk;
        offset += chunk;
    }

    unsafe { free_page(rng_page) };
    0
}

/// Check whether an AMD CCP device is present and initialised.
///
/// Returns true if the driver has been successfully initialised, false otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn amd_ccp_is_present() -> bool {
    unsafe { (*CCP.get()).is_some() }
}

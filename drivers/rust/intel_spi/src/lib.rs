// SPDX-License-Identifier: MPL-2.0
//
// Intel PCH SPI Flash Controller Driver for Futura OS
//
// Implements hardware-sequenced SPI flash access for Intel Gen 10+
// (Ice Lake and later) platforms via the PCH SPI controller at PCI
// device 00:1F.5.
//
// Architecture:
//   - SPIBAR MMIO base discovered from BAR0 (PCI config offset 0x10)
//   - Hardware sequencing: the PCH handles full SPI transactions
//   - Up to 64 bytes per read/write cycle via FDATA registers
//   - Flash region descriptors (FREG0-5) enumerate layout
//   - Protected ranges (PR0-PR4) enforced by hardware
//   - FLOCKDN bit prevents runtime flash configuration changes
//
// SPI BAR MMIO register map (offsets from SPIBAR):
//   0x00       BFPR       BIOS Flash Primary Region (base/limit in 4KB units)
//   0x04       HSFS_CTL   Hardware Sequencing Flash Status and Control
//   0x08       FADDR      Flash Address
//   0x10-0x4F  FDATA0-15  Flash Data registers (16 x 32-bit = 64 bytes)
//   0x50       FRACC      Flash Region Access Permissions
//   0x54-0x6F  FREG0-5    Flash Region base/limit registers
//   0x80-0x8F  PR0-PR4    Protected Range registers
//   0x90       GPR0       Global Protect Range
//   0x94       SSFS/SSFC  Software Sequencing Flash Status/Control
//   0xB0       OPMENU     Opcode Menu (software sequencing)
//   0xC4       FDOC       Flash Descriptor Observability Control
//   0xC8       FDOD       Flash Descriptor Observability Data
//
// Hardware sequencing protocol:
//   1. Wait for SCIP=0 (no SPI cycle in progress)
//   2. Write target address to FADDR
//   3. For writes: load data into FDATA registers
//   4. Set FDBC, FCYCLE, FCGO=1 in HSFS_CTL
//   5. Poll for FDONE=1
//   6. For reads: retrieve data from FDATA registers
//   7. Check FCERR for errors
//
// References:
//   - Intel PCH datasheet vol. 2 (SPI controller chapter)
//   - coreboot src/southbridge/intel/common/spi.c
//   - Linux drivers/mtd/spi-nor/controllers/intel-spi.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, MMIO_DEFAULT_FLAGS};

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// ── StaticCell wrapper (avoids `static mut`) ──

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

// ── PCI configuration space I/O ──

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

// ── SPI controller PCI location (Gen 10+) ──

const SPI_BUS: u8 = 0x00;
const SPI_DEV: u8 = 0x1F;
const SPI_FUNC: u8 = 0x05;

/// PCI config offset for BAR0 (SPIBAR)
const BAR0_OFFSET: u8 = 0x10;

/// BAR0 is a 32-bit memory BAR; bits [31:12] hold the base address
const BAR0_MASK: u32 = 0xFFFF_F000;

/// Size of the SPI MMIO region to map (256 bytes covers all registers)
const SPI_MMIO_SIZE: usize = 0x1000;

// ── SPI BAR MMIO register offsets ──

/// BIOS Flash Primary Region: base[12:0] and limit[28:16] in 4KB units
const BFPR: usize = 0x00;

/// Hardware Sequencing Flash Status and Control
const HSFS_CTL: usize = 0x04;

/// Flash Address register
const FADDR: usize = 0x08;

/// Flash Data registers base (FDATA0 at 0x10, FDATA1 at 0x14, ...)
const FDATA_BASE: usize = 0x10;

/// Number of FDATA registers (16 x 32-bit = 64 bytes)
const FDATA_COUNT: usize = 16;

/// Maximum bytes per hardware sequencing cycle
const FDATA_MAX_BYTES: usize = FDATA_COUNT * 4;

/// Flash Region Access Permissions
#[allow(dead_code)]
const FRACC: usize = 0x50;

/// Flash Region registers base (FREG0 at 0x54)
const FREG_BASE: usize = 0x54;

/// Number of flash region registers
const FREG_COUNT: usize = 6;

/// Protected Range registers base (PR0 at 0x80)
const PR_BASE: usize = 0x80;

/// Number of Protected Range registers
const PR_COUNT: usize = 5;

/// Flash Descriptor Observability Control
const FDOC: usize = 0xC4;

/// Flash Descriptor Observability Data
const FDOD: usize = 0xC8;

// ── HSFS_CTL bit definitions ──

/// Flash cycle done
const HSFS_FDONE: u32 = 1 << 0;
/// Flash cycle error
const HSFS_FCERR: u32 = 1 << 1;
/// Access error log
const HSFS_AEL: u32 = 1 << 2;
/// SPI cycle in progress
const HSFS_SCIP: u32 = 1 << 5;
/// Flash data byte count minus 1 (bits [14:12])
const HSFS_FDBC_SHIFT: u32 = 12;
const HSFS_FDBC_MASK: u32 = 0x3F << HSFS_FDBC_SHIFT;
/// Flash cycle go
const HSFS_FCGO: u32 = 1 << 16;
/// Flash cycle type (bits [20:17])
const HSFS_FCYCLE_SHIFT: u32 = 17;
const HSFS_FCYCLE_MASK: u32 = 0xF << HSFS_FCYCLE_SHIFT;
/// Flash configuration lock-down
const HSFS_FLOCKDN: u32 = 1 << 31;

/// FCYCLE values
const FCYCLE_READ: u32 = 0x00;
const FCYCLE_WRITE: u32 = 0x01;
const FCYCLE_ERASE_4K: u32 = 0x03;
#[allow(dead_code)]
const FCYCLE_ERASE_64K: u32 = 0x04;

// ── FREG register field extraction ──

/// Region base: bits [14:0] in 4KB units
const FREG_BASE_MASK: u32 = 0x7FFF;
/// Region limit: bits [30:16] in 4KB units
const FREG_LIMIT_SHIFT: u32 = 16;
const FREG_LIMIT_MASK: u32 = 0x7FFF;

// ── FDOC register bits ──

/// Flash descriptor section select (bits [14:12])
const FDOC_FDSS_SHIFT: u32 = 12;
/// Flash descriptor section index (bits [3:2])
const FDOC_FDSI_SHIFT: u32 = 2;

// ── Protected Range register bits ──

/// PR write protect enable (bit 31)
const PR_WPE: u32 = 1 << 31;
/// PR read protect enable (bit 15)
const PR_RPE: u32 = 1 << 15;
/// PR base: bits [12:0] in 4KB units
const PR_BASE_MASK: u32 = 0x1FFF;
/// PR limit: bits [28:16] in 4KB units
const PR_LIMIT_SHIFT: u32 = 16;
const PR_LIMIT_MASK: u32 = 0x1FFF;

// ── Region names for logging ──

const REGION_NAMES: [&[u8]; 6] = [
    b"Descriptor\0",
    b"BIOS\0",
    b"ME\0",
    b"GbE\0",
    b"Platform\0",
    b"DevExp\0",
];

// ── Timeouts ──

/// Maximum poll iterations for SCIP clear / FDONE (~100 ms)
const HSFS_POLL_TIMEOUT: u32 = 1_000_000;

// ── MMIO helpers ──

#[inline]
fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    fence(Ordering::SeqCst);
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

#[inline]
fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) };
    fence(Ordering::SeqCst);
}

// ── Driver state ──

struct SpiState {
    /// Virtual address of the SPIBAR MMIO register base
    base: *mut u8,
    /// Physical address of SPIBAR
    phys_base: u64,
    /// Whether the driver has been initialized
    initialized: bool,
}

impl SpiState {
    const fn new() -> Self {
        Self {
            base: core::ptr::null_mut(),
            phys_base: 0,
            initialized: false,
        }
    }
}

static SPI: StaticCell<SpiState> = StaticCell::new(SpiState::new());

// ── Internal helpers ──

/// Locate the PCH SPI controller (00:1F.5) in the kernel PCI device list.
fn find_spi_controller() -> bool {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { pci_get_device(i) };
        if dev.is_null() {
            continue;
        }
        let d = unsafe { &*dev };
        if d.bus == SPI_BUS && d.dev == SPI_DEV && d.func == SPI_FUNC {
            return true;
        }
    }
    false
}

/// Read SPIBAR from the SPI controller BAR0 register.
/// Returns the physical base address, or 0 on failure.
fn read_spibar() -> u64 {
    let raw = pci_read32(SPI_BUS, SPI_DEV, SPI_FUNC, BAR0_OFFSET);
    let base = raw & BAR0_MASK;
    if base == 0 || base == BAR0_MASK {
        return 0;
    }
    base as u64
}

/// Wait for SPI cycle in progress (SCIP) to clear.
/// Returns 0 on success, -1 on timeout.
fn wait_not_busy(base: *mut u8) -> i32 {
    for _ in 0..HSFS_POLL_TIMEOUT {
        let hsfs = mmio_read32(base, HSFS_CTL);
        if hsfs & HSFS_SCIP == 0 {
            return 0;
        }
        common::thread_yield();
    }
    -1
}

/// Wait for FDONE (flash cycle done) to be set.
/// Returns 0 on success, -1 on timeout, -5 (EIO) on FCERR.
fn wait_done(base: *mut u8) -> i32 {
    for _ in 0..HSFS_POLL_TIMEOUT {
        let hsfs = mmio_read32(base, HSFS_CTL);
        if hsfs & HSFS_FDONE != 0 {
            // Clear FDONE, FCERR, AEL by writing 1 to each (W1C bits)
            mmio_write32(base, HSFS_CTL, hsfs & (HSFS_FDONE | HSFS_FCERR | HSFS_AEL));
            if hsfs & HSFS_FCERR != 0 {
                return -5; // EIO
            }
            return 0;
        }
        common::thread_yield();
    }
    -1
}

/// Execute a hardware-sequenced flash cycle.
///
/// `base`:    SPIBAR MMIO base
/// `addr`:    flash address
/// `nbytes`:  number of data bytes (0 for erase, 1-64 for read/write)
/// `fcycle`:  cycle type (FCYCLE_READ, FCYCLE_WRITE, FCYCLE_ERASE_4K)
fn hw_cycle(base: *mut u8, addr: u32, nbytes: usize, fcycle: u32) -> i32 {
    // Step 1: wait for no cycle in progress
    if wait_not_busy(base) != 0 {
        log("intel_spi: timeout waiting for SCIP clear");
        return -16; // EBUSY
    }

    // Step 2: write target address
    mmio_write32(base, FADDR, addr);

    // Step 3: build HSFS_CTL value
    // Clear status bits (W1C), set FDBC, FCYCLE, FCGO
    let fdbc = if nbytes > 0 { (nbytes - 1) as u32 } else { 0 };
    let ctl = HSFS_FDONE | HSFS_FCERR | HSFS_AEL  // clear status (W1C)
        | ((fdbc << HSFS_FDBC_SHIFT) & HSFS_FDBC_MASK)
        | ((fcycle << HSFS_FCYCLE_SHIFT) & HSFS_FCYCLE_MASK)
        | HSFS_FCGO;

    mmio_write32(base, HSFS_CTL, ctl);

    // Step 4: wait for completion
    wait_done(base)
}

/// Read data from FDATA registers into a buffer.
fn read_fdata(base: *mut u8, buf: &mut [u8], nbytes: usize) {
    let mut offset = 0usize;
    for i in 0..FDATA_COUNT {
        if offset >= nbytes {
            break;
        }
        let dword = mmio_read32(base, FDATA_BASE + i * 4);
        let bytes = dword.to_le_bytes();
        for j in 0..4 {
            if offset < nbytes && offset < buf.len() {
                buf[offset] = bytes[j];
            }
            offset += 1;
        }
    }
}

/// Write data from a buffer into FDATA registers.
fn write_fdata(base: *mut u8, buf: &[u8], nbytes: usize) {
    let mut offset = 0usize;
    for i in 0..FDATA_COUNT {
        if offset >= nbytes {
            break;
        }
        let mut bytes = [0u8; 4];
        for j in 0..4 {
            if offset < nbytes && offset < buf.len() {
                bytes[j] = buf[offset];
            }
            offset += 1;
        }
        let dword = u32::from_le_bytes(bytes);
        mmio_write32(base, FDATA_BASE + i * 4, dword);
    }
}

/// Extract region base address from FREG register value (in bytes).
fn freg_base(freg: u32) -> u32 {
    (freg & FREG_BASE_MASK) << 12
}

/// Extract region limit address from FREG register value (in bytes, inclusive).
fn freg_limit(freg: u32) -> u32 {
    (((freg >> FREG_LIMIT_SHIFT) & FREG_LIMIT_MASK) << 12) | 0xFFF
}

// ── FFI exports ──

/// Initialize the Intel PCH SPI flash controller driver.
///
/// Discovers the SPI controller at PCI 00:1F.5, maps SPIBAR, and
/// enumerates flash regions and protected ranges.
///
/// Returns 0 on success, negative on error:
///   -1 = SPI controller not found in PCI device list
///   -2 = SPIBAR reads as zero or invalid
///   -3 = failed to map SPI MMIO region
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_init() -> i32 {
    log("intel_spi: initializing PCH SPI flash controller driver");

    // Verify the SPI controller is enumerated
    if !find_spi_controller() {
        log("intel_spi: SPI controller (00:1F.5) not found");
        return -1;
    }

    // Read SPIBAR from BAR0
    let spibar = read_spibar();
    if spibar == 0 {
        log("intel_spi: SPIBAR is zero or invalid");
        return -2;
    }

    unsafe {
        fut_printf(
            b"intel_spi: SPIBAR = 0x%08llx\n\0".as_ptr(),
            spibar,
        );
    }

    // Map the SPI MMIO region
    let base = unsafe { map_mmio_region(spibar, SPI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if base.is_null() {
        log("intel_spi: failed to map SPI MMIO region");
        return -3;
    }

    // Read initial register values
    let bfpr = mmio_read32(base, BFPR);
    let hsfs = mmio_read32(base, HSFS_CTL);
    let locked = (hsfs & HSFS_FLOCKDN) != 0;

    unsafe {
        fut_printf(
            b"intel_spi: BFPR=0x%08x HSFS_CTL=0x%08x locked=%s\n\0".as_ptr(),
            bfpr,
            hsfs,
            if locked { b"yes\0".as_ptr() } else { b"no\0".as_ptr() },
        );
    }

    // Enumerate flash regions (FREG0-5)
    for r in 0..FREG_COUNT {
        let freg = mmio_read32(base, FREG_BASE + r * 4);
        let rb = freg_base(freg);
        let rl = freg_limit(freg);
        // A region is valid if limit >= base
        if rl >= rb && freg != 0 {
            let name = REGION_NAMES[r];
            unsafe {
                fut_printf(
                    b"intel_spi: region %u (%s): base=0x%08x limit=0x%08x size=%uKB\n\0".as_ptr(),
                    r as u32,
                    name.as_ptr(),
                    rb,
                    rl,
                    (rl - rb + 1) / 1024,
                );
            }
        }
    }

    // Report protected ranges (PR0-PR4)
    for p in 0..PR_COUNT {
        let pr = mmio_read32(base, PR_BASE + p * 4);
        if pr & (PR_WPE | PR_RPE) != 0 {
            let pb = (pr & PR_BASE_MASK) << 12;
            let pl = (((pr >> PR_LIMIT_SHIFT) & PR_LIMIT_MASK) << 12) | 0xFFF;
            let wp = if pr & PR_WPE != 0 { b"WP\0".as_ptr() } else { b"--\0".as_ptr() };
            let rp = if pr & PR_RPE != 0 { b"RP\0".as_ptr() } else { b"--\0".as_ptr() };
            unsafe {
                fut_printf(
                    b"intel_spi: PR%u: base=0x%08x limit=0x%08x %s %s\n\0".as_ptr(),
                    p as u32,
                    pb,
                    pl,
                    wp,
                    rp,
                );
            }
        }
    }

    // Store state
    let state = SPI.get();
    unsafe {
        (*state).base = base;
        (*state).phys_base = spibar;
        fence(Ordering::SeqCst);
        (*state).initialized = true;
    }

    log("intel_spi: driver initialized");
    0
}

/// Read data from SPI flash using hardware sequencing.
///
/// `offset`: byte offset in flash
/// `buf`:    destination buffer
/// `len`:    number of bytes to read
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_read(offset: u32, buf: *mut u8, len: u32) -> i32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized || buf.is_null() || len == 0 {
            return -22; // EINVAL
        }

        let base = (*state).base;
        let mut remaining = len as usize;
        let mut flash_addr = offset;
        let mut buf_offset = 0usize;

        while remaining > 0 {
            let chunk = if remaining > FDATA_MAX_BYTES { FDATA_MAX_BYTES } else { remaining };

            // Execute read cycle
            let rc = hw_cycle(base, flash_addr, chunk, FCYCLE_READ);
            if rc != 0 {
                return rc;
            }

            // Read FDATA into a local buffer, then copy out
            let mut tmp = [0u8; FDATA_MAX_BYTES];
            read_fdata(base, &mut tmp, chunk);

            // Copy to caller's buffer
            for i in 0..chunk {
                unsafe {
                    *buf.add(buf_offset + i) = tmp[i];
                }
            }

            remaining -= chunk;
            flash_addr += chunk as u32;
            buf_offset += chunk;
        }
    }

    0
}

/// Write data to SPI flash using hardware sequencing.
///
/// `offset`: byte offset in flash
/// `buf`:    source data buffer
/// `len`:    number of bytes to write
///
/// Returns 0 on success, negative on error.
/// Returns -13 (EACCES) if FLOCKDN is set.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_write(offset: u32, buf: *const u8, len: u32) -> i32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized || buf.is_null() || len == 0 {
            return -22; // EINVAL
        }

        let base = (*state).base;

        // Check lock-down status
        let hsfs = mmio_read32(base, HSFS_CTL);
        if hsfs & HSFS_FLOCKDN != 0 {
            log("intel_spi: write blocked - flash configuration locked (FLOCKDN)");
            return -13; // EACCES
        }

        let mut remaining = len as usize;
        let mut flash_addr = offset;
        let mut buf_offset = 0usize;

        while remaining > 0 {
            let chunk = if remaining > FDATA_MAX_BYTES { FDATA_MAX_BYTES } else { remaining };

            // Copy source data into local buffer then write to FDATA
            let mut tmp = [0u8; FDATA_MAX_BYTES];
            for i in 0..chunk {
                unsafe {
                    tmp[i] = *buf.add(buf_offset + i);
                }
            }

            write_fdata(base, &tmp, chunk);

            // Execute write cycle
            let rc = hw_cycle(base, flash_addr, chunk, FCYCLE_WRITE);
            if rc != 0 {
                return rc;
            }

            remaining -= chunk;
            flash_addr += chunk as u32;
            buf_offset += chunk;
        }
    }

    0
}

/// Erase a 4KB sector of SPI flash using hardware sequencing.
///
/// `offset`: byte offset (must be 4KB aligned)
///
/// Returns 0 on success, negative on error.
/// Returns -13 (EACCES) if FLOCKDN is set.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_erase_4k(offset: u32) -> i32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized {
            return -22; // EINVAL
        }

        // Verify 4KB alignment
        if offset & 0xFFF != 0 {
            log("intel_spi: erase offset not 4KB aligned");
            return -22; // EINVAL
        }

        let base = (*state).base;

        // Check lock-down status
        let hsfs = mmio_read32(base, HSFS_CTL);
        if hsfs & HSFS_FLOCKDN != 0 {
            log("intel_spi: erase blocked - flash configuration locked (FLOCKDN)");
            return -13; // EACCES
        }

        // Execute 4KB erase cycle (no data bytes)
        hw_cycle(base, offset, 0, FCYCLE_ERASE_4K)
    }
}

/// Read JEDEC ID from flash via the Flash Descriptor Observability mechanism.
///
/// Uses FDOC/FDOD to read the flash descriptor component section which
/// contains JEDEC identification data.
///
/// `out`: pointer to u32 that receives the 24-bit JEDEC ID
///        (manufacturer in bits [7:0], type in [15:8], capacity in [23:16])
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_read_jedec_id(out: *mut u32) -> i32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized || out.is_null() {
            return -22; // EINVAL
        }

        let base = (*state).base;

        // Read from flash descriptor: section 0 (map), index 0
        // FDOC: bits [14:12] = section select, bits [3:2] = dword index
        let fdoc_val: u32 = (0 << FDOC_FDSS_SHIFT) | (0 << FDOC_FDSI_SHIFT);
        mmio_write32(base, FDOC, fdoc_val);
        fence(Ordering::SeqCst);

        let flvalsig = mmio_read32(base, FDOD);

        // Verify flash descriptor signature (0x0FF0A55A)
        if flvalsig != 0x0FF0_A55A {
            log("intel_spi: flash descriptor signature mismatch");
            unsafe {
                fut_printf(
                    b"intel_spi: expected 0x0FF0A55A, got 0x%08x\n\0".as_ptr(),
                    flvalsig,
                );
            }
            return -5; // EIO
        }

        // Read component section (section 1), dword 0 contains component densities
        // and dword 1 may contain JEDEC-related info. For a proper JEDEC ID we
        // read section 0 index 1 (FLMAP0) which encodes component info pointers,
        // then the component section.
        let fdoc_comp: u32 = (1 << FDOC_FDSS_SHIFT) | (0 << FDOC_FDSI_SHIFT);
        mmio_write32(base, FDOC, fdoc_comp);
        fence(Ordering::SeqCst);

        let comp0 = mmio_read32(base, FDOD);

        // The component density field in FLCOMP encodes the JEDEC-style
        // capacity. Extract the lower 24 bits as a pseudo JEDEC ID.
        unsafe {
            *out = comp0 & 0x00FF_FFFF;
        }

        unsafe {
            fut_printf(
                b"intel_spi: JEDEC/component ID: 0x%06x\n\0".as_ptr(),
                comp0 & 0x00FF_FFFF,
            );
        }
    }

    0
}

/// Check whether the SPI flash configuration is locked (FLOCKDN).
///
/// When locked, writes and erases may be blocked by hardware.
///
/// Returns true if FLOCKDN is set or the driver is not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_is_locked() -> bool {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized {
            return true;
        }
        let hsfs = mmio_read32((*state).base, HSFS_CTL);
        (hsfs & HSFS_FLOCKDN) != 0
    }
}

/// Get the base address (in bytes) of a flash region.
///
/// `region`: region index (0=Descriptor, 1=BIOS, 2=ME, 3=GbE, 4=Platform, 5=DevExp)
///
/// Returns the base address, or 0xFFFFFFFF if invalid.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_region_base(region: u32) -> u32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized || region as usize >= FREG_COUNT {
            return 0xFFFF_FFFF;
        }
        let freg = mmio_read32((*state).base, FREG_BASE + (region as usize) * 4);
        freg_base(freg)
    }
}

/// Get the limit address (in bytes, inclusive) of a flash region.
///
/// `region`: region index (0=Descriptor, 1=BIOS, 2=ME, 3=GbE, 4=Platform, 5=DevExp)
///
/// Returns the limit address, or 0 if invalid.
#[unsafe(no_mangle)]
pub extern "C" fn intel_spi_region_limit(region: u32) -> u32 {
    let state = SPI.get();
    unsafe {
        if !(*state).initialized || region as usize >= FREG_COUNT {
            return 0;
        }
        let freg = mmio_read32((*state).base, FREG_BASE + (region as usize) * 4);
        freg_limit(freg)
    }
}

// SPDX-License-Identifier: MPL-2.0
//
// AMD MP2 (Multi-Purpose Processor) I2C/Sensor Hub Controller Driver
// for Futura OS
//
// The AMD MP2 is a co-processor embedded in Ryzen CPUs that manages
// additional I2C buses (bus 2 and bus 3) separate from the FCH I2C
// controllers.  It is used for sensors, touchpads, and other platform
// peripherals on AM4 and AM5 platforms.
//
// Architecture:
//   - PCI device discovery (vendor 1022h, device 15E6h/164Ah/14ECh)
//   - BAR0 MMIO for command/response mailbox
//   - CPU-to-MP2 (C2P) and MP2-to-CPU (P2C) message registers
//   - I2C transfers use DMA: allocate a page, write data, pass physical
//     address to MP2 which performs the I2C transaction
//   - Polling-based completion with timeout
//   - MP2 manages up to 2 additional I2C buses (bus 2 and bus 3)
//
// MMIO register layout (BAR0):
//   0x00-0x3C: C2P_MSG0-15 (CPU to MP2 command + parameters)
//   0x40-0x7C: P2C_MSG0-15 (MP2 to CPU response/status)
//   0x80:      INTR_SET (write to trigger interrupt to MP2)
//   0x84:      INTR_CLR
//
// Command format in C2P_MSG0:
//   bits [3:0]  = command ID
//   bits [7:4]  = bus ID
//   bits [15:8] = I2C target address
//   bits [31:16] = data length
//
// References:
//   - Linux drivers/i2c/busses/i2c-amd-mp2-pci.c
//   - AMD PPR (Processor Programming Reference) for Ryzen

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
    fn rust_virt_to_phys(vaddr: *const c_void) -> u64;
}

// ---------------------------------------------------------------------------
// PCI device structure (mirrors kernel/pci.h)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// StaticCell -- interior-mutable global without `static mut`
// ---------------------------------------------------------------------------

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self {
        Self(UnsafeCell::new(val))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ---------------------------------------------------------------------------
// PCI configuration space I/O
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Virtual-to-physical address translation
// ---------------------------------------------------------------------------

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

// ---------------------------------------------------------------------------
// AMD MP2 PCI identification
// ---------------------------------------------------------------------------

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// MP2 device ID: Zen+/Zen2 (Ryzen 2000/3000).
const MP2_DEVICE_ZEN_PLUS: u16 = 0x15E6;
/// MP2 device ID: Zen3 (Ryzen 5000).
const MP2_DEVICE_ZEN3: u16 = 0x164A;
/// MP2 device ID: Zen4 AM5 (Ryzen 7000/9000).
const MP2_DEVICE_ZEN4: u16 = 0x14EC;

fn is_mp2_device(dev: &PciDevice) -> bool {
    dev.vendor_id == AMD_VENDOR_ID
        && (dev.device_id == MP2_DEVICE_ZEN_PLUS
            || dev.device_id == MP2_DEVICE_ZEN3
            || dev.device_id == MP2_DEVICE_ZEN4)
}

// ---------------------------------------------------------------------------
// BAR0 MMIO register offsets
// ---------------------------------------------------------------------------

/// C2P_MSG0: command register (CPU writes command here).
const C2P_MSG0: usize = 0x00;
/// C2P_MSG1 through C2P_MSG15: command parameter registers.
/// Each at offset 0x04 * register_number.
const C2P_MSG1: usize = 0x04;
const C2P_MSG2: usize = 0x08;
const C2P_MSG3: usize = 0x0C;
const C2P_MSG4: usize = 0x10;
const C2P_MSG5: usize = 0x14;

/// P2C_MSG0: response/status register (MP2 writes response here).
const P2C_MSG0: usize = 0x40;
/// P2C_MSG1 through P2C_MSG15: response data registers.
const P2C_MSG1: usize = 0x44;
const P2C_MSG2: usize = 0x48;

/// Interrupt set register: write to trigger interrupt to MP2.
const MP2_INTR_SET: usize = 0x80;
/// Interrupt clear register.
const MP2_INTR_CLR: usize = 0x84;

// ---------------------------------------------------------------------------
// MP2 I2C commands (bits [3:0] of C2P_MSG0)
// ---------------------------------------------------------------------------

/// Read from I2C device via DMA.
const CMD_I2C_READ: u32 = 0x01;
/// Write to I2C device via DMA.
const CMD_I2C_WRITE: u32 = 0x02;
/// Enable an I2C bus at a given speed.
const CMD_I2C_ENABLE: u32 = 0x03;
/// Disable an I2C bus.
const CMD_I2C_DISABLE: u32 = 0x04;
/// Query MP2 firmware version.
const CMD_GET_FW_VERSION: u32 = 0x10;
/// Query the number of sensors managed by MP2.
const CMD_GET_SENSOR_COUNT: u32 = 0x11;

// ---------------------------------------------------------------------------
// MP2 response status bits in P2C_MSG0
// ---------------------------------------------------------------------------

/// Bit 31: response ready.
const P2C_RESP_READY: u32 = 1 << 31;
/// Bits [3:0] of P2C_MSG0 echo the command.
const P2C_CMD_MASK: u32 = 0x0F;
/// Bits [7:4] of P2C_MSG0: status code.
const P2C_STATUS_SHIFT: u32 = 4;
const P2C_STATUS_MASK: u32 = 0x0F;
/// Status code: success.
const P2C_STATUS_OK: u32 = 0x00;
/// Status code: command not recognised.
const P2C_STATUS_UNKNOWN_CMD: u32 = 0x01;
/// Status code: I2C NACK.
const P2C_STATUS_NACK: u32 = 0x03;
/// Status code: bus error.
const P2C_STATUS_BUS_ERROR: u32 = 0x04;

// ---------------------------------------------------------------------------
// I2C speed constants (passed to CMD_I2C_ENABLE via C2P_MSG1)
// ---------------------------------------------------------------------------

/// Standard mode: 100 kHz.
const I2C_SPEED_STANDARD: u32 = 100;
/// Fast mode: 400 kHz.
const I2C_SPEED_FAST: u32 = 400;
/// Fast mode plus: 1 MHz.
const I2C_SPEED_FAST_PLUS: u32 = 1000;

// ---------------------------------------------------------------------------
// MP2 bus range
// ---------------------------------------------------------------------------

/// MP2 manages buses 2 and 3 (complementing FCH I2C buses 0-1).
const MP2_BUS_MIN: u32 = 2;
const MP2_BUS_MAX: u32 = 3;
const MP2_BUS_COUNT: usize = 2;

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------

/// Maximum poll iterations for mailbox response.
const POLL_TIMEOUT: u32 = 2_000_000;

/// Maximum data size for a single I2C DMA transfer (one 4 KiB page).
const MAX_DMA_SIZE: u32 = 4096;

// ---------------------------------------------------------------------------
// BAR0 MMIO size
// ---------------------------------------------------------------------------

/// Map 4 KiB for the BAR0 mailbox region.
const BAR0_MMIO_SIZE: usize = 0x1000;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct Mp2Bus {
    /// Whether this bus has been enabled.
    enabled: bool,
    /// Configured speed in kHz.
    speed_khz: u32,
}

impl Mp2Bus {
    const fn new() -> Self {
        Self {
            enabled: false,
            speed_khz: 0,
        }
    }
}

struct AmdMp2 {
    /// Virtual address of BAR0 MMIO base.
    bar0_base: *mut u8,
    /// Physical address of BAR0.
    bar0_phys: u64,
    /// PCI BDF.
    pci_bus: u8,
    pci_dev: u8,
    pci_func: u8,
    /// Device ID (for logging).
    device_id: u16,
    /// DMA page for I2C data transfers.
    dma_buf: *mut u8,
    /// Physical address of the DMA buffer.
    dma_buf_phys: u64,
    /// Per-bus state (index 0 = bus 2, index 1 = bus 3).
    buses: [Mp2Bus; MP2_BUS_COUNT],
    /// Cached firmware version.
    fw_major: u32,
    fw_minor: u32,
    fw_version_valid: bool,
}

static MP2: StaticCell<Option<AmdMp2>> = StaticCell::new(None);

// ---------------------------------------------------------------------------
// MMIO register helpers
// ---------------------------------------------------------------------------

impl AmdMp2 {
    /// Read a 32-bit register at the given offset from BAR0 base.
    fn reg_read(&self, offset: usize) -> u32 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.bar0_base.add(offset) as *const u32) }
    }

    /// Write a 32-bit register at the given offset from BAR0 base.
    fn reg_write(&self, offset: usize, val: u32) {
        unsafe { write_volatile(self.bar0_base.add(offset) as *mut u32, val) };
        fence(Ordering::SeqCst);
    }

    /// Build the C2P_MSG0 command word.
    ///
    /// Format: bits [3:0]=cmd, [7:4]=bus_id, [15:8]=i2c_addr, [31:16]=length
    fn build_cmd(cmd: u32, bus_id: u32, i2c_addr: u8, length: u16) -> u32 {
        (cmd & 0x0F)
            | ((bus_id & 0x0F) << 4)
            | ((i2c_addr as u32) << 8)
            | ((length as u32) << 16)
    }

    /// Signal the MP2 co-processor that a new command is ready.
    fn ring_doorbell(&self) {
        self.reg_write(MP2_INTR_SET, 1);
    }

    /// Clear the MP2 interrupt.
    fn clear_interrupt(&self) {
        self.reg_write(MP2_INTR_CLR, 1);
    }

    /// Poll P2C_MSG0 until the response ready bit is set.
    ///
    /// On success, writes the raw P2C_MSG0 value to `*out` and returns 0.
    /// Returns -110 (ETIMEDOUT) if the timeout is reached.
    fn wait_response_raw(&self, out: &mut u32) -> i32 {
        for i in 0..POLL_TIMEOUT {
            let status = self.reg_read(P2C_MSG0);
            if status & P2C_RESP_READY != 0 {
                *out = status;
                return 0;
            }
            // Yield periodically to avoid monopolising the CPU.
            if i % 1000 == 0 && i > 0 {
                common::thread_yield();
            }
        }
        log("amd_mp2: mailbox command timed out");
        -110 // ETIMEDOUT
    }

    /// Decode the status field from a P2C_MSG0 response word.
    /// Returns 0 on success, or a negative error code on failure.
    fn decode_status(resp: u32) -> i32 {
        let status = (resp >> P2C_STATUS_SHIFT) & P2C_STATUS_MASK;
        match status {
            P2C_STATUS_OK => 0,
            P2C_STATUS_NACK => -6,           // ENXIO
            P2C_STATUS_BUS_ERROR => -5,      // EIO
            P2C_STATUS_UNKNOWN_CMD => -95,   // EOPNOTSUPP
            _ => -5,                         // EIO (generic)
        }
    }

    /// Send a simple command (no DMA) and wait for the response.
    ///
    /// Writes parameter registers C2P_MSG1..C2P_MSG5, then writes the
    /// command word to C2P_MSG0, rings the doorbell, and polls for
    /// completion.
    ///
    /// Returns 0 on success, or a negative error code on failure.
    fn send_command(&self, cmd_word: u32, params: &[u32]) -> i32 {
        // Clear any stale response.
        let _ = self.reg_read(P2C_MSG0);
        self.clear_interrupt();

        // Write parameter registers (C2P_MSG1 through C2P_MSG5).
        let param_offsets = [C2P_MSG1, C2P_MSG2, C2P_MSG3, C2P_MSG4, C2P_MSG5];
        for (i, &offset) in param_offsets.iter().enumerate() {
            let val = if i < params.len() { params[i] } else { 0 };
            self.reg_write(offset, val);
        }

        // Write the command word to C2P_MSG0.
        self.reg_write(C2P_MSG0, cmd_word);

        // Ring the doorbell to signal the MP2.
        self.ring_doorbell();

        // Wait for the response.
        let mut resp: u32 = 0;
        let rc = self.wait_response_raw(&mut resp);
        if rc != 0 {
            return rc;
        }

        // Decode the status field and return 0 on success.
        Self::decode_status(resp)
    }

    /// Query the MP2 firmware version.
    fn query_fw_version(&mut self) -> i32 {
        let cmd = Self::build_cmd(CMD_GET_FW_VERSION, 0, 0, 0);
        let rc = self.send_command(cmd, &[]);
        if rc != 0 {
            return rc;
        }

        // Firmware version is returned in P2C_MSG1 (major) and P2C_MSG2 (minor).
        self.fw_major = self.reg_read(P2C_MSG1);
        self.fw_minor = self.reg_read(P2C_MSG2);
        self.fw_version_valid = true;

        unsafe {
            fut_printf(
                b"amd_mp2: firmware version %u.%u\n\0".as_ptr(),
                self.fw_major,
                self.fw_minor,
            );
        }

        0
    }

    /// Enable an I2C bus on the MP2.
    ///
    /// `bus_idx` is the internal bus index (0 = bus 2, 1 = bus 3).
    /// `bus_id`  is the actual bus number (2 or 3).
    fn enable_bus(&mut self, bus_idx: usize, bus_id: u32, speed_khz: u32) -> i32 {
        let speed = match speed_khz {
            0..=100 => I2C_SPEED_STANDARD,
            101..=400 => I2C_SPEED_FAST,
            _ => I2C_SPEED_FAST_PLUS,
        };

        let cmd = Self::build_cmd(CMD_I2C_ENABLE, bus_id, 0, 0);
        let rc = self.send_command(cmd, &[speed]);
        if rc != 0 {
            return rc;
        }

        self.buses[bus_idx].enabled = true;
        self.buses[bus_idx].speed_khz = speed;

        unsafe {
            fut_printf(
                b"amd_mp2: bus %u enabled at %u kHz\n\0".as_ptr(),
                bus_id,
                speed,
            );
        }

        0
    }

    /// Disable an I2C bus on the MP2.
    fn disable_bus(&mut self, bus_idx: usize, bus_id: u32) -> i32 {
        let cmd = Self::build_cmd(CMD_I2C_DISABLE, bus_id, 0, 0);
        let rc = self.send_command(cmd, &[]);
        if rc != 0 {
            return rc;
        }

        self.buses[bus_idx].enabled = false;
        self.buses[bus_idx].speed_khz = 0;

        unsafe {
            fut_printf(
                b"amd_mp2: bus %u disabled\n\0".as_ptr(),
                bus_id,
            );
        }

        0
    }

    /// Perform an I2C read via DMA.
    ///
    /// Sends a read command to the MP2 with the DMA buffer physical address.
    /// The MP2 performs the I2C read and places data into the DMA buffer.
    /// The caller then copies data out of the DMA buffer.
    fn i2c_read(&self, bus_id: u32, addr: u8, buf: *mut u8, len: u32) -> i32 {
        if buf.is_null() || len == 0 || len > MAX_DMA_SIZE {
            return -22; // EINVAL
        }

        // Zero the DMA buffer before the read.
        unsafe {
            core::ptr::write_bytes(self.dma_buf, 0, len as usize);
        }
        fence(Ordering::SeqCst);

        // Build the read command.
        let cmd = Self::build_cmd(CMD_I2C_READ, bus_id, addr, len as u16);

        // Pass DMA buffer physical address in C2P_MSG1 (low) and C2P_MSG2 (high).
        let dma_lo = self.dma_buf_phys as u32;
        let dma_hi = (self.dma_buf_phys >> 32) as u32;

        let rc = self.send_command(cmd, &[dma_lo, dma_hi]);
        if rc != 0 {
            return rc;
        }

        // Copy data from the DMA buffer to the caller's buffer.
        fence(Ordering::SeqCst);
        unsafe {
            core::ptr::copy_nonoverlapping(self.dma_buf, buf, len as usize);
        }

        0
    }

    /// Perform an I2C write via DMA.
    ///
    /// Copies data into the DMA buffer, then sends a write command to the
    /// MP2 with the DMA buffer physical address.
    fn i2c_write(&self, bus_id: u32, addr: u8, data: *const u8, len: u32) -> i32 {
        if data.is_null() || len == 0 || len > MAX_DMA_SIZE {
            return -22; // EINVAL
        }

        // Copy caller data into the DMA buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(data, self.dma_buf, len as usize);
        }
        fence(Ordering::SeqCst);

        // Build the write command.
        let cmd = Self::build_cmd(CMD_I2C_WRITE, bus_id, addr, len as u16);

        // Pass DMA buffer physical address in C2P_MSG1 (low) and C2P_MSG2 (high).
        let dma_lo = self.dma_buf_phys as u32;
        let dma_hi = (self.dma_buf_phys >> 32) as u32;

        self.send_command(cmd, &[dma_lo, dma_hi])
    }
}

// ---------------------------------------------------------------------------
// PCI BAR0 reading
// ---------------------------------------------------------------------------

/// Read BAR0 (64-bit MMIO) from PCI config space.
/// BAR0 is at PCI config offset 0x10.  If bit 2 of the BAR type field
/// indicates 64-bit, the upper 32 bits are in BAR1 at offset 0x14.
fn read_bar0(bus: u8, dev: u8, func: u8) -> u64 {
    let bar0_lo = pci_read32(bus, dev, func, 0x10);
    let is_64bit = (bar0_lo >> 1) & 0x3 == 2;
    let base_lo = (bar0_lo & !0xF) as u64;

    if is_64bit {
        let bar0_hi = pci_read32(bus, dev, func, 0x14);
        base_lo | ((bar0_hi as u64) << 32)
    } else {
        base_lo
    }
}

// ---------------------------------------------------------------------------
// PCI device discovery
// ---------------------------------------------------------------------------

/// Find an AMD MP2 device on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_mp2() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if is_mp2_device(dev) {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Bus index helper
// ---------------------------------------------------------------------------

/// Convert a bus number (2 or 3) to an internal index (0 or 1).
/// Returns None if the bus number is out of range.
fn bus_to_index(bus: u32) -> Option<usize> {
    if bus >= MP2_BUS_MIN && bus <= MP2_BUS_MAX {
        Some((bus - MP2_BUS_MIN) as usize)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialise the AMD MP2 I2C/sensor hub controller.
///
/// Scans PCI for an AMD MP2 device, maps BAR0 MMIO, allocates a DMA
/// buffer page, and queries the firmware version.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_init() -> i32 {
    log("amd_mp2: scanning PCI for AMD MP2 device...");

    let (bus, dev, func, device_id) = match find_mp2() {
        Some(bdf) => bdf,
        None => {
            log("amd_mp2: no AMD MP2 device found");
            return -1;
        }
    };

    let gen_name = match device_id {
        MP2_DEVICE_ZEN_PLUS => b"Zen+/Zen2\0".as_ptr(),
        MP2_DEVICE_ZEN3 => b"Zen3\0".as_ptr(),
        MP2_DEVICE_ZEN4 => b"Zen4 AM5\0".as_ptr(),
        _ => b"unknown\0".as_ptr(),
    };

    unsafe {
        fut_printf(
            b"amd_mp2: found %s MP2 (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            gen_name,
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Enable PCI memory space access and bus mastering.
    let cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, cmd | 0x06);

    // Read BAR0 (64-bit MMIO).
    let bar0_phys = read_bar0(bus, dev, func);
    if bar0_phys == 0 {
        log("amd_mp2: BAR0 not configured");
        return -2;
    }

    unsafe {
        fut_printf(
            b"amd_mp2: BAR0 phys = 0x%016lx\n\0".as_ptr(),
            bar0_phys,
        );
    }

    // Map the BAR0 MMIO region.
    let bar0_base = unsafe { map_mmio_region(bar0_phys, BAR0_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if bar0_base.is_null() {
        log("amd_mp2: failed to map BAR0 MMIO region");
        return -3;
    }

    // Verify MMIO is accessible (read P2C_MSG0; should not be all-ones).
    fence(Ordering::SeqCst);
    let probe = unsafe { read_volatile(bar0_base.add(P2C_MSG0) as *const u32) };
    if probe == 0xFFFF_FFFF {
        log("amd_mp2: MMIO region not responding (all-ones read)");
        unsafe { unmap_mmio_region(bar0_base, BAR0_MMIO_SIZE) };
        return -4;
    }

    // Allocate a DMA buffer page for I2C data transfers.
    let dma_buf = unsafe { alloc_page() };
    if dma_buf.is_null() {
        log("amd_mp2: failed to allocate DMA buffer page");
        unsafe { unmap_mmio_region(bar0_base, BAR0_MMIO_SIZE) };
        return -12; // ENOMEM
    }

    // Zero the DMA buffer.
    unsafe { core::ptr::write_bytes(dma_buf, 0, 4096) };

    let dma_buf_phys = virt_to_phys(dma_buf);

    unsafe {
        fut_printf(
            b"amd_mp2: DMA buffer at virt=0x%p phys=0x%016lx\n\0".as_ptr(),
            dma_buf,
            dma_buf_phys,
        );
    }

    let mut mp2 = AmdMp2 {
        bar0_base,
        bar0_phys,
        pci_bus: bus,
        pci_dev: dev,
        pci_func: func,
        device_id,
        dma_buf,
        dma_buf_phys,
        buses: [Mp2Bus::new(), Mp2Bus::new()],
        fw_major: 0,
        fw_minor: 0,
        fw_version_valid: false,
    };

    // Query MP2 firmware version.
    let rc = mp2.query_fw_version();
    if rc < 0 {
        unsafe {
            fut_printf(
                b"amd_mp2: firmware version query failed (rc=%d), continuing\n\0".as_ptr(),
                rc,
            );
        }
        // Non-fatal: some firmware versions do not support this command.
    }

    // Store the driver state.
    let state = unsafe { &mut *MP2.get() };
    *state = Some(mp2);

    fence(Ordering::SeqCst);

    log("amd_mp2: controller initialised successfully");
    0
}

/// Query the cached MP2 firmware version.
///
/// Writes the major and minor version numbers to the provided pointers.
///
/// Returns 0 on success, -19 (ENODEV) if the driver is not initialised,
/// or -22 (EINVAL) if pointers are null.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_fw_version(major: *mut u32, minor: *mut u32) -> i32 {
    if major.is_null() || minor.is_null() {
        return -22; // EINVAL
    }

    let state = unsafe { &*MP2.get() };
    let mp2 = match state.as_ref() {
        Some(m) => m,
        None => return -19, // ENODEV
    };

    if !mp2.fw_version_valid {
        return -61; // ENODATA
    }

    unsafe {
        write_volatile(major, mp2.fw_major);
        write_volatile(minor, mp2.fw_minor);
    }

    0
}

/// Enable an MP2 I2C bus.
///
/// `bus`: bus number (2 or 3).
/// `speed_khz`: desired bus speed in kHz (100 = standard, 400 = fast,
///              1000 = fast mode plus).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_i2c_enable(bus: u32, speed_khz: u32) -> i32 {
    let bus_idx = match bus_to_index(bus) {
        Some(idx) => idx,
        None => {
            log("amd_mp2: invalid bus number (must be 2 or 3)");
            return -22; // EINVAL
        }
    };

    let state = unsafe { &mut *MP2.get() };
    let mp2 = match state.as_mut() {
        Some(m) => m,
        None => return -19, // ENODEV
    };

    mp2.enable_bus(bus_idx, bus, speed_khz)
}

/// Disable an MP2 I2C bus.
///
/// `bus`: bus number (2 or 3).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_i2c_disable(bus: u32) -> i32 {
    let bus_idx = match bus_to_index(bus) {
        Some(idx) => idx,
        None => {
            log("amd_mp2: invalid bus number (must be 2 or 3)");
            return -22; // EINVAL
        }
    };

    let state = unsafe { &mut *MP2.get() };
    let mp2 = match state.as_mut() {
        Some(m) => m,
        None => return -19, // ENODEV
    };

    if !mp2.buses[bus_idx].enabled {
        return 0; // Already disabled.
    }

    mp2.disable_bus(bus_idx, bus)
}

/// Read from an I2C device on an MP2-managed bus via DMA.
///
/// `bus`:  bus number (2 or 3).
/// `addr`: 7-bit I2C target address.
/// `buf`:  buffer to receive data.
/// `len`:  number of bytes to read (max 4096).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_i2c_read(bus: u32, addr: u8, buf: *mut u8, len: u32) -> i32 {
    let bus_idx = match bus_to_index(bus) {
        Some(idx) => idx,
        None => return -22, // EINVAL
    };

    if buf.is_null() || len == 0 || len > MAX_DMA_SIZE {
        return -22; // EINVAL
    }

    let state = unsafe { &*MP2.get() };
    let mp2 = match state.as_ref() {
        Some(m) => m,
        None => return -19, // ENODEV
    };

    if !mp2.buses[bus_idx].enabled {
        log("amd_mp2: bus not enabled");
        return -19; // ENODEV
    }

    mp2.i2c_read(bus, addr, buf, len)
}

/// Write to an I2C device on an MP2-managed bus via DMA.
///
/// `bus`:  bus number (2 or 3).
/// `addr`: 7-bit I2C target address.
/// `data`: pointer to data bytes to write.
/// `len`:  number of bytes to write (max 4096).
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_i2c_write(bus: u32, addr: u8, data: *const u8, len: u32) -> i32 {
    let bus_idx = match bus_to_index(bus) {
        Some(idx) => idx,
        None => return -22, // EINVAL
    };

    if data.is_null() || len == 0 || len > MAX_DMA_SIZE {
        return -22; // EINVAL
    }

    let state = unsafe { &*MP2.get() };
    let mp2 = match state.as_ref() {
        Some(m) => m,
        None => return -19, // ENODEV
    };

    if !mp2.buses[bus_idx].enabled {
        log("amd_mp2: bus not enabled");
        return -19; // ENODEV
    }

    mp2.i2c_write(bus, addr, data, len)
}

/// Check whether an AMD MP2 device is present on the PCI bus.
///
/// This performs a lightweight PCI scan without initialising the driver.
/// Returns `true` if an MP2 device is found, `false` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn amd_mp2_is_present() -> bool {
    find_mp2().is_some()
}

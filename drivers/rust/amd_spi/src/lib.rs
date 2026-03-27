// SPDX-License-Identifier: MPL-2.0
//
// AMD FCH SPI Flash Controller Driver for Futura OS
//
// Implements the AMD Fusion Controller Hub (FCH) SPI controller found on
// AM4 (X370-X570) and AM5 (X670-X870) Ryzen platforms.
//
// Architecture:
//   - MMIO-based register access via ACPI MMIO region
//   - ACPI MMIO base: 0xFED80000, SPI block offset: 0x0A00
//   - Controls the SPI flash chip holding BIOS/UEFI firmware
//   - Discoverable via AMD FCH LPC/ISA bridge (vendor 1022h)
//   - Supports standard SPI NOR flash commands: read, write, erase, JEDEC ID
//   - Polling-based command completion with timeout
//
// SPI Register Map (relative to SPI MMIO base):
//   0x00  SPI_CNTRL0  - Main control: SpiArbEnable, exec, TX/RX byte counts
//   0x0C  SPI_CNTRL1  - Reserved/config
//   0x1C  SPI_CMD_CODE - SPI opcode to send
//   0x1D+ SPI_FIFO    - TX/RX FIFO data bytes (up to 64 bytes)
//   0x45  ALT_SPI_CS   - Chip select
//   0x47  SPI_STATUS   - Busy, write enable latch status
//
// References:
//   - AMD BIOS and Kernel Developer's Guide (BKDG) for Family 17h
//   - AMD PPR (Processor Programming Reference) for Ryzen
//   - coreboot src/soc/amd/common/block/spi/
//   - Linux drivers/spi/spi-amd.c

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{log, map_mmio_region, unmap_mmio_region, MMIO_DEFAULT_FLAGS};

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
}

// ---------------------------------------------------------------------------
// StaticCell -- interior-mutable global without `static mut`
// ---------------------------------------------------------------------------

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

#[allow(dead_code)]
fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr = pci_config_addr(bus, dev, func, offset);
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDR, in("eax") addr);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") val);
    }
}

// ---------------------------------------------------------------------------
// x86 I/O port helpers
// ---------------------------------------------------------------------------

fn io_outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val);
    }
}

fn io_inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val);
    }
    val
}

/// Small delay by reading a dummy I/O port (standard x86 technique).
fn io_delay() {
    io_inb(0x80);
}

// ---------------------------------------------------------------------------
// AMD FCH PCI identification
// ---------------------------------------------------------------------------

/// AMD vendor ID.
const AMD_VENDOR_ID: u16 = 0x1022;

/// AMD FCH LPC/ISA bridge device IDs (these contain the ACPI MMIO base).
/// AM4 platforms (Zen/Zen2/Zen3): FCH ISA bridge.
const AMD_ISA_BRIDGE_AM4: u16 = 0x790E;
/// AM5 platforms (Zen4/Zen5): FCH ISA bridge.
const AMD_ISA_BRIDGE_AM5: u16 = 0x790E;
/// Alternate AM5 ISA bridge device ID (some Ryzen 7000/9000 boards).
const AMD_ISA_BRIDGE_AM5_ALT: u16 = 0x14D8;

/// PCI class: ISA bridge.
const PCI_CLASS_BRIDGE: u8 = 0x06;
/// PCI subclass: ISA bridge.
const PCI_SUBCLASS_ISA: u8 = 0x01;

// ---------------------------------------------------------------------------
// ACPI MMIO region constants
// ---------------------------------------------------------------------------

/// Default AMD FCH ACPI MMIO base address.
const ACPI_MMIO_DEFAULT_BASE: u64 = 0xFED8_0000;

/// PCI config register in the ISA bridge that holds the ACPI MMIO base.
/// Bits [31:13] contain the base address (8 KiB aligned).
const ISA_BRIDGE_ACPI_MMIO_REG: u8 = 0x24;

/// PM I/O port index register (alternate discovery method).
const PM_IO_INDEX: u16 = 0xCD6;
/// PM I/O port data register.
const PM_IO_DATA: u16 = 0xCD7;

/// PM register indices for ACPI MMIO base address (bytes 0-3).
const PM_ACPI_MMIO_BASE0: u8 = 0x24;
const PM_ACPI_MMIO_BASE1: u8 = 0x25;
const PM_ACPI_MMIO_BASE2: u8 = 0x26;
const PM_ACPI_MMIO_BASE3: u8 = 0x27;

/// Offset of the SPI register block within the ACPI MMIO region.
const SPI_MMIO_OFFSET: u64 = 0x0A00;

/// Size of the SPI MMIO block (we map a full page for safety).
const SPI_MMIO_SIZE: usize = 0x1000;

// ---------------------------------------------------------------------------
// SPI Register Offsets (relative to SPI MMIO base)
// ---------------------------------------------------------------------------

/// SPI Control Register 0 (32-bit).
/// Bit 31: SpiArbEnable — arbitration enable.
/// Bit 17: ExecuteOpCode — triggers SPI transaction.
/// Bits [11:8]: TxByteCount — number of TX bytes after opcode.
/// Bits [15:12]: RxByteCount — number of RX bytes to read back.
const SPI_CNTRL0: usize = 0x00;

/// SPI Control Register 1 (32-bit) — reserved/config.
#[allow(dead_code)]
const SPI_CNTRL1: usize = 0x0C;

/// SPI Command Code register (8-bit) — the SPI opcode to transmit.
const SPI_CMD_CODE: usize = 0x1C;

/// SPI FIFO base — TX/RX data bytes start here (up to 64 bytes).
/// Byte at offset 0x1D is FIFO[0], 0x1E is FIFO[1], etc.
const SPI_FIFO_BASE: usize = 0x1D;

/// Maximum FIFO depth in bytes.
const SPI_FIFO_SIZE: usize = 64;

/// Alternate SPI Chip Select register.
const ALT_SPI_CS: usize = 0x45;

/// SPI Status register (8-bit).
/// Bit 0: SpiBusy — controller is executing a command.
/// Bit 2: WriteEnableLatch — flash WEL status.
const SPI_STATUS: usize = 0x47;

// ---------------------------------------------------------------------------
// SPI_CNTRL0 bit definitions
// ---------------------------------------------------------------------------

/// SPI arbitration enable — must be set for software-initiated transfers.
const CNTRL0_SPI_ARB_ENABLE: u32 = 1 << 31;

/// Execute opcode — write 1 to trigger the SPI transaction.
const CNTRL0_EXEC_OPCODE: u32 = 1 << 17;

/// TX byte count field: bits [11:8].
const CNTRL0_TX_COUNT_SHIFT: u32 = 8;
const CNTRL0_TX_COUNT_MASK: u32 = 0xF << 8;

/// RX byte count field: bits [15:12].
const CNTRL0_RX_COUNT_SHIFT: u32 = 12;
const CNTRL0_RX_COUNT_MASK: u32 = 0xF << 12;

// ---------------------------------------------------------------------------
// SPI_STATUS bit definitions
// ---------------------------------------------------------------------------

/// SPI controller is busy executing a command.
const STATUS_SPI_BUSY: u8 = 1 << 0;

/// Flash write enable latch is set.
#[allow(dead_code)]
const STATUS_WRITE_ENABLE_LATCH: u8 = 1 << 2;

// ---------------------------------------------------------------------------
// Standard SPI NOR flash commands
// ---------------------------------------------------------------------------

/// Read data (up to device limit, here limited by FIFO).
const SPI_CMD_READ: u8 = 0x03;
/// Read status register.
const SPI_CMD_READ_STATUS: u8 = 0x05;
/// Write enable (set WEL bit in flash status register).
const SPI_CMD_WRITE_ENABLE: u8 = 0x06;
/// Page program (write up to 256 bytes within a page).
const SPI_CMD_PAGE_PROGRAM: u8 = 0x02;
/// Sector erase (4 KiB sector).
const SPI_CMD_SECTOR_ERASE: u8 = 0x20;
/// Read JEDEC ID (manufacturer, memory type, capacity).
const SPI_CMD_JEDEC_ID: u8 = 0x9F;
/// Chip erase (erase entire flash).
#[allow(dead_code)]
const SPI_CMD_CHIP_ERASE: u8 = 0xC7;

// ---------------------------------------------------------------------------
// Flash status register bits
// ---------------------------------------------------------------------------

/// Flash is busy (write/erase in progress).
const FLASH_STATUS_BUSY: u8 = 1 << 0;
/// Write enable latch is set.
const FLASH_STATUS_WEL: u8 = 1 << 1;

// ---------------------------------------------------------------------------
// Timeout and limits
// ---------------------------------------------------------------------------

/// Maximum poll iterations for SPI controller busy wait (~50 ms).
const SPI_POLL_TIMEOUT: u32 = 500_000;

/// Maximum poll iterations for flash write/erase completion (~10 seconds).
const FLASH_POLL_TIMEOUT: u32 = 10_000_000;

/// SPI flash page size (standard for most NOR flash).
const FLASH_PAGE_SIZE: u32 = 256;

/// Maximum bytes per SPI FIFO transfer (limited by 4-bit count fields).
/// The TX/RX count fields are 4 bits each, allowing 0-8 bytes.
/// However, the FIFO itself is 64 bytes. For read/write operations we
/// send a 3-byte address in TX plus data, so effective data per transfer
/// is limited. We use conservative limits.
const SPI_MAX_DATA_PER_XFER: usize = 8;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct AmdSpi {
    /// Virtual address of the SPI MMIO register block.
    mmio_base: *mut u8,
    /// Physical address of the ACPI MMIO region.
    acpi_mmio_phys: u64,
    /// JEDEC ID read during init (0 if not yet read).
    jedec_id: u32,
    /// PCI location of the ISA bridge used for discovery.
    bridge_bus: u8,
    bridge_dev: u8,
    bridge_func: u8,
}

static SPI: StaticCell<Option<AmdSpi>> = StaticCell::new(None);

// ---------------------------------------------------------------------------
// MMIO register access
// ---------------------------------------------------------------------------

impl AmdSpi {
    /// Read a 32-bit SPI register.
    fn read32(&self, offset: usize) -> u32 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.mmio_base.add(offset) as *const u32) }
    }

    /// Write a 32-bit SPI register.
    fn write32(&self, offset: usize, val: u32) {
        unsafe { write_volatile(self.mmio_base.add(offset) as *mut u32, val) };
        fence(Ordering::SeqCst);
    }

    /// Read an 8-bit SPI register.
    fn read8(&self, offset: usize) -> u8 {
        fence(Ordering::SeqCst);
        unsafe { read_volatile(self.mmio_base.add(offset) as *const u8) }
    }

    /// Write an 8-bit SPI register.
    fn write8(&self, offset: usize, val: u8) {
        unsafe { write_volatile(self.mmio_base.add(offset) as *mut u8, val) };
        fence(Ordering::SeqCst);
    }

    // -----------------------------------------------------------------------
    // SPI controller operations
    // -----------------------------------------------------------------------

    /// Wait for the SPI controller to become idle (not busy).
    /// Returns 0 on success, -1 on timeout.
    fn wait_ready(&self) -> i32 {
        for _ in 0..SPI_POLL_TIMEOUT {
            let status = self.read8(SPI_STATUS);
            if status & STATUS_SPI_BUSY == 0 {
                return 0;
            }
            io_delay();
        }
        -1
    }

    /// Select chip select 0 (primary flash).
    fn select_cs0(&self) {
        // ALT_SPI_CS: bits [1:0] select the chip. CS0 = 0.
        self.write8(ALT_SPI_CS, 0x00);
    }

    /// Execute a SPI transaction.
    ///
    /// `opcode`: SPI command byte.
    /// `tx_buf`: bytes to transmit after the opcode (address + data).
    /// `tx_len`: number of TX bytes (0-8, loaded into FIFO).
    /// `rx_len`: number of RX bytes to read back (0-8).
    ///
    /// Returns 0 on success, negative error on failure.
    /// RX data is left in the FIFO starting at SPI_FIFO_BASE + tx_len.
    fn execute(&self, opcode: u8, tx_buf: &[u8], tx_len: usize, rx_len: usize) -> i32 {
        if tx_len > SPI_MAX_DATA_PER_XFER || rx_len > SPI_MAX_DATA_PER_XFER {
            return -22; // EINVAL
        }

        // Wait for controller idle.
        if self.wait_ready() != 0 {
            log("amd_spi: controller busy timeout before execute");
            return -16; // EBUSY
        }

        // Select CS0.
        self.select_cs0();

        // Write the opcode.
        self.write8(SPI_CMD_CODE, opcode);

        // Load TX data into the FIFO.
        for i in 0..tx_len {
            if i < tx_buf.len() {
                self.write8(SPI_FIFO_BASE + i, tx_buf[i]);
            } else {
                self.write8(SPI_FIFO_BASE + i, 0x00);
            }
        }

        // Configure CNTRL0: set TX/RX byte counts and execute.
        let mut cntrl0 = self.read32(SPI_CNTRL0);

        // Preserve SpiArbEnable and clear TX/RX count fields.
        cntrl0 &= !(CNTRL0_TX_COUNT_MASK | CNTRL0_RX_COUNT_MASK | CNTRL0_EXEC_OPCODE);

        // Set TX byte count (number of bytes after opcode).
        cntrl0 |= ((tx_len as u32) & 0xF) << CNTRL0_TX_COUNT_SHIFT;

        // Set RX byte count.
        cntrl0 |= ((rx_len as u32) & 0xF) << CNTRL0_RX_COUNT_SHIFT;

        // Ensure SPI arbitration is enabled.
        cntrl0 |= CNTRL0_SPI_ARB_ENABLE;

        // Set the execute bit to trigger the transaction.
        cntrl0 |= CNTRL0_EXEC_OPCODE;

        self.write32(SPI_CNTRL0, cntrl0);

        // Wait for the transaction to complete.
        if self.wait_ready() != 0 {
            log("amd_spi: transaction completion timeout");
            return -110; // ETIMEDOUT
        }

        0
    }

    /// Read RX data from the FIFO after a transaction.
    /// `tx_len`: number of TX bytes sent (RX data starts after them in FIFO).
    /// `buf`: destination buffer for RX data.
    /// `rx_len`: number of bytes to read.
    fn read_fifo(&self, tx_len: usize, buf: &mut [u8], rx_len: usize) {
        for i in 0..rx_len {
            if i < buf.len() {
                buf[i] = self.read8(SPI_FIFO_BASE + tx_len + i);
            }
        }
    }

    // -----------------------------------------------------------------------
    // SPI flash operations
    // -----------------------------------------------------------------------

    /// Send the WRITE_ENABLE command to the flash (sets WEL bit).
    fn flash_write_enable(&self) -> i32 {
        self.execute(SPI_CMD_WRITE_ENABLE, &[], 0, 0)
    }

    /// Read the flash status register.
    /// Returns the status byte, or negative error.
    fn flash_read_status(&self) -> i32 {
        let rc = self.execute(SPI_CMD_READ_STATUS, &[], 0, 1);
        if rc != 0 {
            return rc;
        }
        let mut status: [u8; 1] = [0];
        self.read_fifo(0, &mut status, 1);
        status[0] as i32
    }

    /// Wait for the flash to complete a write or erase operation.
    /// Polls the flash status register until the BUSY bit clears.
    /// Returns 0 on success, negative error on timeout.
    fn flash_wait_ready(&self) -> i32 {
        for _ in 0..FLASH_POLL_TIMEOUT {
            let status = self.flash_read_status();
            if status < 0 {
                return status;
            }
            if (status as u8) & FLASH_STATUS_BUSY == 0 {
                return 0;
            }
            io_delay();
        }
        log("amd_spi: flash busy timeout");
        -110 // ETIMEDOUT
    }

    /// Read the JEDEC ID from the SPI flash.
    /// Returns the 3-byte JEDEC ID packed into a u32 (MSB = manufacturer).
    fn read_jedec_id(&self) -> Result<u32, i32> {
        let rc = self.execute(SPI_CMD_JEDEC_ID, &[], 0, 3);
        if rc != 0 {
            return Err(rc);
        }
        let mut id_bytes: [u8; 3] = [0; 3];
        self.read_fifo(0, &mut id_bytes, 3);

        // Pack as: [manufacturer][memory_type][capacity]
        let jedec_id = ((id_bytes[0] as u32) << 16)
            | ((id_bytes[1] as u32) << 8)
            | (id_bytes[2] as u32);

        Ok(jedec_id)
    }

    /// Read data from the SPI flash at the given offset.
    /// Performs multiple FIFO-sized transactions as needed.
    fn flash_read(&self, offset: u32, buf: &mut [u8], len: usize) -> i32 {
        let mut pos: usize = 0;

        while pos < len {
            // Each transfer: 3 address bytes in TX, up to 8 data bytes in RX.
            // But we are limited to 8 RX bytes total due to 4-bit count field.
            // With 3 TX bytes for address, we can read up to 5 bytes per xfer
            // (FIFO positions: 3 TX + 5 RX = 8 bytes in the FIFO window).
            // To be safe and efficient, read up to 5 bytes per iteration.
            let chunk = core::cmp::min(len - pos, 5);
            let addr = offset + pos as u32;

            // Build 3-byte address (big-endian, 24-bit addressing).
            let tx: [u8; 3] = [
                ((addr >> 16) & 0xFF) as u8,
                ((addr >> 8) & 0xFF) as u8,
                (addr & 0xFF) as u8,
            ];

            let rc = self.execute(SPI_CMD_READ, &tx, 3, chunk);
            if rc != 0 {
                return rc;
            }

            // Read RX data from FIFO (starts after 3 TX bytes).
            self.read_fifo(3, &mut buf[pos..], chunk);
            pos += chunk;
        }

        0
    }

    /// Program data to the SPI flash at the given offset.
    /// Handles page boundaries and write-enable for each page program.
    fn flash_write(&self, offset: u32, data: &[u8], len: usize) -> i32 {
        let mut pos: usize = 0;

        while pos < len {
            let addr = offset + pos as u32;

            // Calculate how many bytes remain in the current page.
            let page_offset = addr % FLASH_PAGE_SIZE;
            let page_remain = (FLASH_PAGE_SIZE - page_offset) as usize;

            // Each page program transfer: 3 address bytes + up to 5 data bytes in TX.
            // TX count field is 4 bits, max 8 bytes total. With 3 address bytes,
            // that leaves 5 bytes for data.
            let chunk = core::cmp::min(len - pos, core::cmp::min(page_remain, 5));

            // Enable writing.
            let rc = self.flash_write_enable();
            if rc != 0 {
                return rc;
            }

            // Verify WEL is set.
            let status = self.flash_read_status();
            if status < 0 {
                return status;
            }
            if (status as u8) & FLASH_STATUS_WEL == 0 {
                log("amd_spi: write enable failed (WEL not set)");
                return -5; // EIO
            }

            // Build TX buffer: 3-byte address + data.
            let mut tx: [u8; 8] = [0; 8];
            tx[0] = ((addr >> 16) & 0xFF) as u8;
            tx[1] = ((addr >> 8) & 0xFF) as u8;
            tx[2] = (addr & 0xFF) as u8;
            for i in 0..chunk {
                tx[3 + i] = data[pos + i];
            }

            let tx_len = 3 + chunk;
            let rc = self.execute(SPI_CMD_PAGE_PROGRAM, &tx[..tx_len], tx_len, 0);
            if rc != 0 {
                return rc;
            }

            // Wait for the page program to complete.
            let rc = self.flash_wait_ready();
            if rc != 0 {
                return rc;
            }

            pos += chunk;
        }

        0
    }

    /// Erase a 4 KiB sector at the given offset.
    /// The offset must be sector-aligned (multiple of 4096).
    fn flash_erase_sector(&self, offset: u32) -> i32 {
        // Verify sector alignment.
        if offset & 0xFFF != 0 {
            return -22; // EINVAL
        }

        // Enable writing.
        let rc = self.flash_write_enable();
        if rc != 0 {
            return rc;
        }

        // Verify WEL is set.
        let status = self.flash_read_status();
        if status < 0 {
            return status;
        }
        if (status as u8) & FLASH_STATUS_WEL == 0 {
            log("amd_spi: write enable failed before erase");
            return -5; // EIO
        }

        // Send sector erase command with 3-byte address.
        let tx: [u8; 3] = [
            ((offset >> 16) & 0xFF) as u8,
            ((offset >> 8) & 0xFF) as u8,
            (offset & 0xFF) as u8,
        ];

        let rc = self.execute(SPI_CMD_SECTOR_ERASE, &tx, 3, 0);
        if rc != 0 {
            return rc;
        }

        // Wait for the erase to complete (can take seconds).
        self.flash_wait_ready()
    }
}

// ---------------------------------------------------------------------------
// PCI discovery
// ---------------------------------------------------------------------------

/// Find the AMD FCH ISA/LPC bridge on the PCI bus.
/// Returns (bus, dev, func, device_id) if found.
fn find_isa_bridge() -> Option<(u8, u8, u8, u16)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == AMD_VENDOR_ID
            && (dev.device_id == AMD_ISA_BRIDGE_AM4
                || dev.device_id == AMD_ISA_BRIDGE_AM5
                || dev.device_id == AMD_ISA_BRIDGE_AM5_ALT)
            && dev.class_code == PCI_CLASS_BRIDGE
            && dev.subclass == PCI_SUBCLASS_ISA
        {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id));
        }
    }
    None
}

/// Read the ACPI MMIO base address from the ISA bridge PCI config space.
/// Register 0x24 bits [31:13] contain the base address (8 KiB aligned).
/// Bit 0 indicates whether the ACPI MMIO region is enabled.
fn read_acpi_mmio_base_pci(bus: u8, dev: u8, func: u8) -> Option<u64> {
    let reg = pci_read32(bus, dev, func, ISA_BRIDGE_ACPI_MMIO_REG);

    // Bit 0: AcpiMmioEn — ACPI MMIO decode enable.
    if reg & 0x01 == 0 {
        return None;
    }

    // Bits [31:13] are the base address.
    let base = (reg & 0xFFFF_E000) as u64;
    if base == 0 {
        return None;
    }

    Some(base)
}

/// Alternate discovery: read the ACPI MMIO base via PM I/O index/data ports.
fn read_acpi_mmio_base_pmio() -> Option<u64> {
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE0);
    let b0 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE1);
    let b1 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE2);
    let b2 = io_inb(PM_IO_DATA) as u32;
    io_outb(PM_IO_INDEX, PM_ACPI_MMIO_BASE3);
    let b3 = io_inb(PM_IO_DATA) as u32;

    let reg = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);

    if reg & 0x01 == 0 {
        return None;
    }

    let base = (reg & 0xFFFF_E000) as u64;
    if base == 0 {
        return None;
    }

    Some(base)
}

/// Discover the ACPI MMIO base address using all available methods.
/// Priority: PCI config > PM I/O > default fallback.
fn discover_acpi_mmio_base(bus: u8, dev: u8, func: u8) -> u64 {
    // Method 1: PCI config space of the ISA bridge.
    if let Some(base) = read_acpi_mmio_base_pci(bus, dev, func) {
        unsafe {
            fut_printf(
                b"amd_spi: ACPI MMIO base from PCI config: 0x%08lx\n\0".as_ptr(),
                base,
            );
        }
        return base;
    }

    // Method 2: PM I/O index/data ports.
    if let Some(base) = read_acpi_mmio_base_pmio() {
        unsafe {
            fut_printf(
                b"amd_spi: ACPI MMIO base from PM I/O: 0x%08lx\n\0".as_ptr(),
                base,
            );
        }
        return base;
    }

    // Method 3: Use the well-known default.
    log("amd_spi: using default ACPI MMIO base 0xFED80000");
    ACPI_MMIO_DEFAULT_BASE
}

/// Verify the SPI MMIO region is accessible by reading CNTRL0.
/// A valid controller should not return all-ones (bus float).
fn verify_spi_mmio(base: *mut u8) -> bool {
    let cntrl0 = unsafe { read_volatile(base.add(SPI_CNTRL0) as *const u32) };
    cntrl0 != 0xFFFF_FFFF
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

/// Initialise the AMD FCH SPI flash controller.
///
/// Discovers the ACPI MMIO region via the FCH ISA bridge, maps the SPI
/// register block, verifies hardware accessibility, and reads the JEDEC ID
/// of the attached SPI flash chip.
///
/// Returns 0 on success, negative error on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_init() -> i32 {
    log("amd_spi: scanning PCI for AMD FCH ISA bridge...");

    let (bus, dev, func, device_id) = match find_isa_bridge() {
        Some(bdf) => bdf,
        None => {
            log("amd_spi: no AMD FCH ISA bridge found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_spi: found ISA bridge (device %04x) at PCI %02x:%02x.%x\n\0".as_ptr(),
            device_id as u32,
            bus as u32,
            dev as u32,
            func as u32,
        );
    }

    // Discover the ACPI MMIO base address.
    let acpi_mmio_phys = discover_acpi_mmio_base(bus, dev, func);

    // The SPI register block is at offset 0x0A00 within the ACPI MMIO region.
    let spi_phys = acpi_mmio_phys + SPI_MMIO_OFFSET;

    unsafe {
        fut_printf(
            b"amd_spi: SPI MMIO phys = 0x%08lx\n\0".as_ptr(),
            spi_phys,
        );
    }

    // Map the SPI MMIO region into virtual address space.
    let mmio_base = unsafe { map_mmio_region(spi_phys, SPI_MMIO_SIZE, MMIO_DEFAULT_FLAGS) };
    if mmio_base.is_null() {
        log("amd_spi: failed to map SPI MMIO region");
        return -2;
    }

    // Verify the SPI controller is accessible.
    if !verify_spi_mmio(mmio_base) {
        log("amd_spi: SPI MMIO region not responding (all-ones read)");
        unsafe { unmap_mmio_region(mmio_base, SPI_MMIO_SIZE) };
        return -3;
    }

    let mut spi = AmdSpi {
        mmio_base,
        acpi_mmio_phys,
        jedec_id: 0,
        bridge_bus: bus,
        bridge_dev: dev,
        bridge_func: func,
    };

    // Read current CNTRL0 for diagnostics.
    let cntrl0 = spi.read32(SPI_CNTRL0);
    let status = spi.read8(SPI_STATUS);

    unsafe {
        fut_printf(
            b"amd_spi: CNTRL0=0x%08x STATUS=0x%02x\n\0".as_ptr(),
            cntrl0,
            status as u32,
        );
    }

    // Ensure SPI arbitration is enabled for software access.
    if cntrl0 & CNTRL0_SPI_ARB_ENABLE == 0 {
        log("amd_spi: enabling SPI arbitration");
        spi.write32(SPI_CNTRL0, cntrl0 | CNTRL0_SPI_ARB_ENABLE);
    }

    // Attempt to read the JEDEC ID of the attached SPI flash.
    match spi.read_jedec_id() {
        Ok(id) => {
            spi.jedec_id = id;
            let mfr = (id >> 16) & 0xFF;
            let mem_type = (id >> 8) & 0xFF;
            let capacity = id & 0xFF;
            unsafe {
                fut_printf(
                    b"amd_spi: JEDEC ID = 0x%06x (mfr=0x%02x type=0x%02x cap=0x%02x)\n\0"
                        .as_ptr(),
                    id,
                    mfr,
                    mem_type,
                    capacity,
                );
            }

            // Decode known manufacturers.
            let mfr_name = match mfr as u8 {
                0xEF => b"Winbond\0".as_ptr(),
                0xC2 => b"Macronix\0".as_ptr(),
                0x01 => b"Spansion/Cypress\0".as_ptr(),
                0x20 => b"Micron/Numonyx\0".as_ptr(),
                0x1F => b"Adesto/Atmel\0".as_ptr(),
                0xBF => b"SST/Microchip\0".as_ptr(),
                0x9D => b"ISSI\0".as_ptr(),
                0xC8 => b"GigaDevice\0".as_ptr(),
                _ => b"Unknown\0".as_ptr(),
            };
            unsafe {
                fut_printf(
                    b"amd_spi: flash manufacturer: %s\n\0".as_ptr(),
                    mfr_name,
                );
            }
        }
        Err(_) => {
            log("amd_spi: WARNING - failed to read JEDEC ID (no flash or access denied)");
        }
    }

    // Store the driver state.
    unsafe {
        (*SPI.get()) = Some(spi);
    }

    log("amd_spi: controller initialised successfully");
    0
}

/// Read the JEDEC ID of the attached SPI flash chip.
///
/// `out` - Pointer to a u32 that receives the 3-byte JEDEC ID:
///         bits [23:16] = manufacturer, [15:8] = memory type, [7:0] = capacity.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_read_jedec_id(out: *mut u32) -> i32 {
    if out.is_null() {
        return -22; // EINVAL
    }

    let spi = match unsafe { (*SPI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    // If we already have a cached JEDEC ID, return it.
    if spi.jedec_id != 0 {
        unsafe { write_volatile(out, spi.jedec_id) };
        return 0;
    }

    // Otherwise read it fresh from the flash.
    match spi.read_jedec_id() {
        Ok(id) => {
            unsafe { write_volatile(out, id) };
            0
        }
        Err(e) => e,
    }
}

/// Read data from the SPI flash.
///
/// `offset` - Byte offset in the flash to read from (24-bit address).
/// `buf`    - Destination buffer.
/// `len`    - Number of bytes to read.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_read(offset: u32, buf: *mut u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let spi = match unsafe { (*SPI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    spi.flash_read(offset, slice, len as usize)
}

/// Write data to the SPI flash (page program).
///
/// `offset` - Byte offset in the flash to write to (24-bit address).
/// `buf`    - Source data buffer.
/// `len`    - Number of bytes to write.
///
/// The flash region must be erased (0xFF) before writing. This function
/// handles page boundary alignment automatically.
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_write(offset: u32, buf: *const u8, len: u32) -> i32 {
    if buf.is_null() || len == 0 {
        return -22; // EINVAL
    }

    let spi = match unsafe { (*SPI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    spi.flash_write(offset, slice, len as usize)
}

/// Erase a 4 KiB sector of the SPI flash.
///
/// `offset` - Byte offset of the sector to erase. Must be aligned to 4096 (0x1000).
///
/// Returns 0 on success, negative error code on failure.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_erase_sector(offset: u32) -> i32 {
    let spi = match unsafe { (*SPI.get()).as_ref() } {
        Some(s) => s,
        None => return -19, // ENODEV
    };

    spi.flash_erase_sector(offset)
}

/// Query the current SPI controller and flash status.
///
/// Returns a bitmask:
///   bit 0: SPI controller is busy
///   bit 1: flash write-in-progress (from flash status register)
///   bit 2: flash write enable latch is set
///   bit 8: SPI arbitration is enabled
///   bits [31:16]: cached JEDEC ID manufacturer byte (for quick identification)
///
/// Returns 0 if the driver is not initialised.
#[unsafe(no_mangle)]
pub extern "C" fn amd_spi_status() -> u32 {
    let spi = match unsafe { (*SPI.get()).as_ref() } {
        Some(s) => s,
        None => return 0,
    };

    let mut result: u32 = 0;

    // Read SPI controller status.
    let ctrl_status = spi.read8(SPI_STATUS);
    if ctrl_status & STATUS_SPI_BUSY != 0 {
        result |= 1 << 0;
    }

    // Read flash status register.
    let flash_status = spi.flash_read_status();
    if flash_status >= 0 {
        let fs = flash_status as u8;
        if fs & FLASH_STATUS_BUSY != 0 {
            result |= 1 << 1;
        }
        if fs & FLASH_STATUS_WEL != 0 {
            result |= 1 << 2;
        }
    }

    // Check SPI arbitration enable.
    let cntrl0 = spi.read32(SPI_CNTRL0);
    if cntrl0 & CNTRL0_SPI_ARB_ENABLE != 0 {
        result |= 1 << 8;
    }

    // Pack manufacturer byte into upper bits for quick identification.
    let mfr = (spi.jedec_id >> 16) & 0xFF;
    result |= mfr << 16;

    result
}

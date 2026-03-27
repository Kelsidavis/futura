// SPDX-License-Identifier: MPL-2.0
//
// AMD XGBE 10 Gigabit Ethernet Driver
//
// Supports the AMD/Synopsys DesignWare XGMAC 10GbE controller found in
// AMD Ryzen Pro APUs (e.g. Ryzen 5 Pro 2400GE, Ryzen 7 Pro 2700U) on
// AM4 Pro platforms with integrated Ethernet.
//
// Architecture:
//   - MMIO register access via PCI BAR0 (XGMAC registers)
//   - BAR2 maps XPCS (PCS PHY) registers (used for link status)
//   - 256-entry TX/RX descriptor rings with 2 KiB packet buffers
//   - Polling-based operation (DMA interrupts not enabled)
//   - Enhanced normal TX/RX descriptors (16 bytes each)
//   - MAC address read from XGMAC MAC_ADDR registers
//
// PCI vendor: 1022h (AMD), device 1458h (XGBE controller)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use common::{
    alloc, alloc_page, free, log, map_mmio_region, unmap_mmio_region,
    MMIO_DEFAULT_FLAGS,
};

// ── FFI imports ──

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
    fn pci_device_count() -> i32;
    fn pci_get_device(index: i32) -> *const PciDevice;
    fn fut_net_rx_packet(iface: *mut c_void, data: *const u8, len: u32);
    fn fut_virt_to_phys(vaddr: *const c_void) -> u64;
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

// ── PCI vendor/device IDs ──

const AMD_VENDOR_ID: u16 = 0x1022;
const XGBE_DEVICE_ID: u16 = 0x1458;  // AMD XGBE 10GbE controller
const XGBE_PHY_DEVICE_ID: u16 = 0x1459; // AMD XGBE KR PHY (companion)

// ── XGMAC Register Map (BAR0 MMIO offsets) ──

// MAC configuration registers
const MAC_CR: usize         = 0x0000;  // MAC Configuration
const MAC_ECR: usize        = 0x0004;  // MAC Extended Configuration
const MAC_PFR: usize        = 0x0008;  // MAC Packet Filter
const MAC_WTR: usize        = 0x000C;  // MAC Watchdog Timeout
const MAC_RQC0R: usize      = 0x0040;  // RX Queue Control 0
const MAC_ADDR_HIGH0: usize = 0x0050;  // MAC Address 0 High
const MAC_ADDR_LOW0: usize  = 0x0054;  // MAC Address 0 Low
const MAC_HASH_TABLE0: usize = 0x0070; // Multicast Hash Table 0
const MAC_ISR: usize        = 0x00D8;  // MAC Interrupt Status
const MAC_IER: usize        = 0x00DC;  // MAC Interrupt Enable
const MAC_VER: usize        = 0x0110;  // MAC Version

// MTL (MAC Transaction Layer) registers
const MTL_OMR: usize        = 0x0C00;  // MTL Operation Mode
const MTL_TXQ0_OMR: usize   = 0x0D00; // MTL TX Queue 0 Operation Mode
const MTL_TXQ0_UR: usize    = 0x0D04; // MTL TX Queue 0 Underflow
const MTL_RXQ0_OMR: usize   = 0x0D30; // MTL RX Queue 0 Operation Mode
const MTL_RXQ0_FLOW: usize  = 0x0D34; // MTL RX Queue 0 Flow Control

// DMA registers
const DMA_MR: usize         = 0x1000;  // DMA Mode
const DMA_SBMR: usize       = 0x1004;  // DMA System Bus Mode
const DMA_ISR: usize        = 0x1008;  // DMA Interrupt Status

// DMA Channel 0 registers
const DMA_CH0_CR: usize     = 0x1100;  // Channel 0 Control
const DMA_CH0_TCR: usize    = 0x1104;  // TX Control
const DMA_CH0_RCR: usize    = 0x1108;  // RX Control
const DMA_CH0_TDLR_LO: usize = 0x1114; // TX Descriptor List Address Low
const DMA_CH0_TDLR_HI: usize = 0x1118; // TX Descriptor List Address High
const DMA_CH0_RDLR_LO: usize = 0x111C; // RX Descriptor List Address Low
const DMA_CH0_RDLR_HI: usize = 0x1120; // RX Descriptor List Address High
const DMA_CH0_TDTR: usize   = 0x1128;  // TX Descriptor Tail Pointer
const DMA_CH0_RDTR: usize   = 0x1130;  // RX Descriptor Tail Pointer
const DMA_CH0_TDRLR: usize  = 0x1134;  // TX Descriptor Ring Length
const DMA_CH0_RDRLR: usize  = 0x1138;  // RX Descriptor Ring Length
const DMA_CH0_IER: usize    = 0x1138;  // Channel 0 Interrupt Enable (offset shared)
const DMA_CH0_SR: usize     = 0x1160;  // Channel 0 Status

// ── MAC_CR register bits ──

const MAC_CR_TE: u32        = 1 << 0;   // Transmitter Enable
const MAC_CR_RE: u32        = 1 << 1;   // Receiver Enable
const MAC_CR_PS: u32        = 1 << 15;  // Port Select (0 = GMII, 1 = MII)
const MAC_CR_FES: u32       = 1 << 14;  // Speed (1 = 100 Mbps when PS=1)
const MAC_CR_DM: u32        = 1 << 13;  // Duplex Mode (1 = Full)
const MAC_CR_JE: u32        = 1 << 16;  // Jumbo Packet Enable
const MAC_CR_JD: u32        = 1 << 17;  // Jabber Disable
const MAC_CR_WD: u32        = 1 << 19;  // Watchdog Disable
const MAC_CR_CST: u32       = 1 << 21;  // CRC Stripping for Type Packets
const MAC_CR_ACS: u32       = 1 << 20;  // Automatic Pad/CRC Stripping
const MAC_CR_GPSLCE: u32    = 1 << 23;  // Giant Packet Size Limit Control
const MAC_CR_IPC: u32       = 1 << 27;  // Checksum Offload

// ── MAC_ECR register bits ──

const MAC_ECR_DCRCC: u32    = 1 << 16;  // Disable CRC Checking

// ── MAC_PFR register bits ──

const MAC_PFR_PR: u32       = 1 << 0;   // Promiscuous Mode
const MAC_PFR_HUC: u32      = 1 << 1;   // Hash Unicast
const MAC_PFR_HMC: u32      = 1 << 2;   // Hash Multicast
const MAC_PFR_PM: u32       = 1 << 4;   // Pass All Multicast
const MAC_PFR_DBF: u32      = 1 << 5;   // Disable Broadcast Frames
const MAC_PFR_HPF: u32      = 1 << 10;  // Hash or Perfect Filter
const MAC_PFR_RA: u32       = 1 << 31;  // Receive All

// ── MAC_RQC0R register bits ──

const MAC_RQC0R_RXQ0EN_AV: u32 = 0x02; // RX Queue 0 enabled for AV

// ── MAC_ADDR_HIGH0 register bits ──

const MAC_ADDR_HIGH_AE: u32 = 1 << 31;  // Address Enable

// ── DMA_MR register bits ──

const DMA_MR_SWR: u32       = 1 << 0;   // Software Reset
const DMA_MR_INTM_MASK: u32 = 0x30000;  // Interrupt Mode mask

// ── DMA_SBMR register bits ──

const DMA_SBMR_FB: u32      = 1 << 0;   // Fixed Burst Length
const DMA_SBMR_AAL: u32     = 1 << 12;  // Address-Aligned Beats
const DMA_SBMR_BLEN4: u32   = 1 << 1;   // AXI Burst Length 4
const DMA_SBMR_BLEN8: u32   = 1 << 2;   // AXI Burst Length 8
const DMA_SBMR_BLEN16: u32  = 1 << 3;   // AXI Burst Length 16

// ── DMA_CH0_TCR register bits ──

const DMA_CH0_TCR_ST: u32   = 1 << 0;   // Start Transmission
const DMA_CH0_TCR_OSP: u32  = 1 << 4;   // Operate on Second Packet
const DMA_CH0_TCR_TSE: u32  = 1 << 12;  // TCP Segmentation Enable

// ── DMA_CH0_RCR register bits ──

const DMA_CH0_RCR_SR: u32   = 1 << 0;   // Start Receive
const DMA_CH0_RCR_RBSZ_SHIFT: u32 = 1;  // RX Buffer Size shift
const DMA_CH0_RCR_RBSZ_MASK: u32 = 0x3FFF << 1; // RX Buffer Size mask
const DMA_CH0_RCR_PBL_SHIFT: u32 = 16;  // Programmable Burst Length shift

// ── DMA_CH0_CR register bits ──

const DMA_CH0_CR_PBLX8: u32 = 1 << 16;  // 8xPBL Mode

// ── MTL operation mode bits ──

const MTL_OMR_DTXSTS: u32   = 1 << 1;   // Drop TX Status
const MTL_TXQ0_OMR_TSF: u32 = 1 << 1;   // TX Store and Forward
const MTL_TXQ0_OMR_TXQEN: u32 = 1 << 3; // TX Queue Enable
const MTL_TXQ0_OMR_TQS_SHIFT: u32 = 16; // TX Queue Size shift
const MTL_RXQ0_OMR_RSF: u32 = 1 << 5;   // RX Store and Forward
const MTL_RXQ0_OMR_FEP: u32 = 1 << 4;   // Forward Error Packets
const MTL_RXQ0_OMR_FUP: u32 = 1 << 3;   // Forward Undersized Good Packets
const MTL_RXQ0_OMR_RQS_SHIFT: u32 = 16; // RX Queue Size shift

// ── TX/RX descriptor formats ──

const DESC_RING_SIZE: usize = 256;     // Number of descriptors per ring
const DESC_SIZE: usize      = 16;      // Bytes per descriptor
const TX_BUF_SIZE: usize    = 2048;    // TX buffer size per descriptor
const RX_BUF_SIZE: usize    = 2048;    // RX buffer size per descriptor

/// Enhanced Normal TX/RX Descriptor (16 bytes).
///
/// TX (read by DMA):
///   desc0/desc1: buffer physical address (low/high 32 bits)
///   desc2: buffer length (bits 13:0), VTIR (bits 15:14), header len (bits 31:16)
///   desc3: OWN (bit 31), FD (bit 29), LD (bit 28), CIC (bits 17:16),
///          CPC (bits 27:26), packet length (bits 14:0)
///
/// RX (read by DMA):
///   desc0/desc1: buffer physical address (low/high 32 bits)
///   desc2: reserved (set to 0)
///   desc3: OWN (bit 31), IOC (bit 30), BUF1V (bit 24)
///
/// RX write-back (written by DMA after receive):
///   desc0: reserved
///   desc1: reserved
///   desc2: packet length (bits 30:16)
///   desc3: OWN=0, FD (bit 29), LD (bit 28), ES (bit 15)
#[repr(C)]
#[derive(Clone, Copy)]
struct XgbeDesc {
    desc0: u32,
    desc1: u32,
    desc2: u32,
    desc3: u32,
}

const _: () = assert!(core::mem::size_of::<XgbeDesc>() == DESC_SIZE);

// TX descriptor desc3 bits
const TX_DESC3_OWN: u32     = 1 << 31;  // Owned by DMA
const TX_DESC3_FD: u32      = 1 << 29;  // First Descriptor
const TX_DESC3_LD: u32      = 1 << 28;  // Last Descriptor
const TX_DESC3_CIC_FULL: u32 = 0x03 << 16; // Checksum Insertion: IP hdr + payload

// TX descriptor desc2 bits
const TX_DESC2_BUF1_LEN_MASK: u32 = 0x3FFF; // Buffer 1 Length (bits 13:0)

// RX descriptor desc3 bits (read format)
const RX_DESC3_OWN: u32     = 1 << 31;  // Owned by DMA
const RX_DESC3_IOC: u32     = 1 << 30;  // Interrupt on Completion
const RX_DESC3_BUF1V: u32   = 1 << 24;  // Buffer 1 Address Valid

// RX descriptor desc3 write-back bits
const RX_WB_DESC3_OWN: u32  = 1 << 31;  // OWN = 0 when DMA is done
const RX_WB_DESC3_FD: u32   = 1 << 29;  // First Descriptor
const RX_WB_DESC3_LD: u32   = 1 << 28;  // Last Descriptor
const RX_WB_DESC3_ES: u32   = 1 << 15;  // Error Summary
const RX_WB_DESC3_PL_MASK: u32 = 0x3FFF; // Packet Length (bits 13:0)

// RX descriptor desc2 write-back bits
const RX_WB_DESC2_PL_SHIFT: u32 = 16;   // Packet length shift in desc2
const RX_WB_DESC2_PL_MASK: u32 = 0x3FFF; // Packet length mask (14 bits)

// ── XPCS register offsets (BAR2, indirect via MDIO-like interface) ──

// The XPCS PCS status register can be read to determine link state.
// For simplicity we read link status from the MAC configuration registers
// and the DMA channel status register.

// ── StaticCell wrapper (avoids static mut) ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    /// Returns a raw pointer to the inner value.
    fn get(&self) -> *mut T { self.0.get() }
}

// ── Controller state ──

struct Xgbe {
    /// XGMAC MMIO base address (mapped virtual address from BAR0)
    mmio: *mut u8,
    /// MMIO region size for unmapping
    mmio_size: usize,
    /// PCI bus/device/function
    bus: u8,
    dev: u8,
    func: u8,
    /// IRQ line
    irq: u8,
    /// MAC address
    mac: [u8; 6],

    // TX descriptor ring
    tx_ring: *mut XgbeDesc,
    tx_ring_phys: u64,
    tx_bufs: *mut u8,
    tx_bufs_phys: u64,
    tx_tail: usize,             // Next descriptor to fill

    // RX descriptor ring
    rx_ring: *mut XgbeDesc,
    rx_ring_phys: u64,
    rx_bufs: *mut u8,
    rx_bufs_phys: u64,
    rx_cur: usize,              // Next descriptor to check

    // Interface pointer for fut_net_rx_packet callback
    iface: *mut c_void,
}

unsafe impl Send for Xgbe {}
unsafe impl Sync for Xgbe {}

static NIC: StaticCell<Option<Xgbe>> = StaticCell::new(None);

// ── MMIO helpers ──

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { fut_virt_to_phys(ptr as *const c_void) }
}

// ── PCI discovery ──

/// Scan PCI bus for an AMD XGBE 10GbE controller (vendor 1022h, device 1458h).
/// Returns (bus, dev, func, device_id, irq) or None.
fn find_xgbe_pci() -> Option<(u8, u8, u8, u16, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == AMD_VENDOR_ID && dev.device_id == XGBE_DEVICE_ID {
            return Some((dev.bus, dev.dev, dev.func, dev.device_id, dev.irq_line));
        }
    }
    None
}

// ── DMA software reset ──

/// Perform a DMA software reset via DMA_MR.SWR and wait for completion.
/// The hardware clears the SWR bit when the reset is finished.
fn dma_reset(mmio: *mut u8) -> bool {
    // Issue DMA software reset
    mmio_write32(mmio, DMA_MR, DMA_MR_SWR);

    // Small delay for reset to propagate
    for _ in 0..1000u32 {
        core::hint::spin_loop();
    }

    // Wait for SWR bit to self-clear
    for _ in 0..100_000u32 {
        let val = mmio_read32(mmio, DMA_MR);
        if val & DMA_MR_SWR == 0 {
            // Post-reset stabilization delay
            for _ in 0..10_000u32 {
                core::hint::spin_loop();
            }
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// ── MAC address reading ──

/// Read the MAC address from the XGMAC MAC_ADDR registers.
/// The firmware/BIOS programs these during platform init.
fn read_mac_address(mmio: *mut u8) -> [u8; 6] {
    let high = mmio_read32(mmio, MAC_ADDR_HIGH0);
    let low = mmio_read32(mmio, MAC_ADDR_LOW0);

    [
        (low & 0xFF) as u8,
        ((low >> 8) & 0xFF) as u8,
        ((low >> 16) & 0xFF) as u8,
        ((low >> 24) & 0xFF) as u8,
        (high & 0xFF) as u8,
        ((high >> 8) & 0xFF) as u8,
    ]
}

// ── Descriptor ring initialization ──

/// Allocate and initialize the TX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_tx_ring() -> Option<(*mut XgbeDesc, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut XgbeDesc };
    if ring.is_null() {
        return None;
    }
    let ring_phys = virt_to_phys(ring as *const u8);

    // Allocate TX buffers: 256 * 2048 = 524288 bytes
    let total_buf_size = DESC_RING_SIZE * TX_BUF_SIZE;
    let bufs = unsafe { alloc(total_buf_size) };
    if bufs.is_null() {
        return None;
    }
    let bufs_phys = virt_to_phys(bufs);

    // Zero all descriptors (OWN bit clear = driver owns)
    for i in 0..DESC_RING_SIZE {
        let desc = XgbeDesc {
            desc0: 0,
            desc1: 0,
            desc2: 0,
            desc3: 0,
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

/// Allocate and initialize the RX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_rx_ring() -> Option<(*mut XgbeDesc, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut XgbeDesc };
    if ring.is_null() {
        return None;
    }
    let ring_phys = virt_to_phys(ring as *const u8);

    // Allocate RX buffers
    let total_buf_size = DESC_RING_SIZE * RX_BUF_SIZE;
    let bufs = unsafe { alloc(total_buf_size) };
    if bufs.is_null() {
        return None;
    }
    let bufs_phys = virt_to_phys(bufs);

    // Initialize descriptors: set buffer addresses, set OWN+IOC+BUF1V for HW
    for i in 0..DESC_RING_SIZE {
        let buf_phys = bufs_phys + (i * RX_BUF_SIZE) as u64;
        let desc = XgbeDesc {
            desc0: buf_phys as u32,              // Buffer address low
            desc1: (buf_phys >> 32) as u32,      // Buffer address high
            desc2: 0,
            desc3: RX_DESC3_OWN | RX_DESC3_IOC | RX_DESC3_BUF1V,
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

// ── FFI exports ──

/// Initialize the AMD XGBE 10 Gigabit Ethernet controller.
///
/// Scans PCI for the AMD XGBE device (1022:1458), maps BAR0 MMIO registers,
/// performs a DMA software reset, reads the MAC address, configures the MTL
/// and DMA channels, sets up TX/RX descriptor rings, and enables the MAC
/// transmitter and receiver in polling mode.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn amd_xgbe_init() -> i32 {
    log("amd_xgbe: scanning PCI for AMD XGBE 10GbE controller...");

    let (bus, dev, func, device_id, irq) = match find_xgbe_pci() {
        Some(info) => info,
        None => {
            log("amd_xgbe: no AMD XGBE controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"amd_xgbe: found device %04x:%04x at PCI %02x:%02x.%x IRQ %d\n\0".as_ptr(),
            AMD_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32, irq as u32,
        );
    }

    // Enable bus mastering and memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // Read BAR0 for XGMAC MMIO registers
    let bar0_lo = pci_read32(bus, dev, func, 0x10);

    if bar0_lo & 0x01 != 0 {
        log("amd_xgbe: BAR0 is I/O space, expected MMIO");
        return -2;
    }

    // Determine if 64-bit BAR
    let is_64bit = (bar0_lo & 0x06) == 0x04;
    let bar_phys_lo = bar0_lo & !0xF;
    let bar_phys_hi = if is_64bit {
        pci_read32(bus, dev, func, 0x14)
    } else {
        0
    };
    let bar_phys = (bar_phys_lo as u64) | ((bar_phys_hi as u64) << 32);

    if bar_phys == 0 {
        log("amd_xgbe: BAR0 not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"amd_xgbe: MMIO BAR0 at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map MMIO region (XGMAC register space spans up to 64 KiB)
    let mmio_size: usize = 0x10000; // 64 KiB
    let mmio = unsafe { map_mmio_region(bar_phys, mmio_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("amd_xgbe: failed to map MMIO region");
        return -4;
    }

    // Read MAC version for identification
    let ver = mmio_read32(mmio, MAC_VER);
    unsafe {
        fut_printf(
            b"amd_xgbe: XGMAC version 0x%08x\n\0".as_ptr(),
            ver,
        );
    }

    // Perform DMA software reset
    if !dma_reset(mmio) {
        log("amd_xgbe: DMA software reset timeout");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -5;
    }
    log("amd_xgbe: DMA software reset complete");

    // Read MAC address
    let mac = read_mac_address(mmio);

    unsafe {
        fut_printf(
            b"amd_xgbe: MAC address %02x:%02x:%02x:%02x:%02x:%02x\n\0".as_ptr(),
            mac[0] as u32, mac[1] as u32, mac[2] as u32,
            mac[3] as u32, mac[4] as u32, mac[5] as u32,
        );
    }

    // Validate MAC address
    let all_zero = mac.iter().all(|&b| b == 0x00);
    let all_ff = mac.iter().all(|&b| b == 0xFF);
    if all_zero || all_ff {
        log("amd_xgbe: invalid MAC address read from hardware");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -6;
    }

    // Program the MAC address into MAC_ADDR registers
    let addr_low = (mac[0] as u32)
        | ((mac[1] as u32) << 8)
        | ((mac[2] as u32) << 16)
        | ((mac[3] as u32) << 24);
    let addr_high = (mac[4] as u32)
        | ((mac[5] as u32) << 8)
        | MAC_ADDR_HIGH_AE;
    mmio_write32(mmio, MAC_ADDR_LOW0, addr_low);
    mmio_write32(mmio, MAC_ADDR_HIGH0, addr_high);

    // Clear multicast hash table (8 entries, 256-bit hash)
    for i in 0..8 {
        mmio_write32(mmio, MAC_HASH_TABLE0 + i * 4, 0);
    }

    // Set up TX descriptor ring
    let (tx_ring, tx_ring_phys, tx_bufs, tx_bufs_phys) = match init_tx_ring() {
        Some(v) => v,
        None => {
            log("amd_xgbe: failed to allocate TX descriptor ring");
            unsafe { unmap_mmio_region(mmio, mmio_size); }
            return -7;
        }
    };

    // Set up RX descriptor ring
    let (rx_ring, rx_ring_phys, rx_bufs, rx_bufs_phys) = match init_rx_ring() {
        Some(v) => v,
        None => {
            log("amd_xgbe: failed to allocate RX descriptor ring");
            unsafe {
                free(tx_bufs);
                unmap_mmio_region(mmio, mmio_size);
            }
            return -8;
        }
    };

    // ── Configure DMA system bus mode ──

    // Set fixed burst, address-aligned beats, burst length 16
    let sbmr = DMA_SBMR_FB | DMA_SBMR_AAL | DMA_SBMR_BLEN16;
    mmio_write32(mmio, DMA_SBMR, sbmr);

    // ── Configure MTL (MAC Transaction Layer) ──

    // TX queue 0: store-and-forward mode, enable queue, set queue size
    let txq_omr = MTL_TXQ0_OMR_TSF | MTL_TXQ0_OMR_TXQEN
        | (15u32 << MTL_TXQ0_OMR_TQS_SHIFT); // TX queue size = 16 KiB
    mmio_write32(mmio, MTL_TXQ0_OMR, txq_omr);

    // RX queue 0: store-and-forward mode, forward error and undersized packets
    let rxq_omr = MTL_RXQ0_OMR_RSF | MTL_RXQ0_OMR_FEP | MTL_RXQ0_OMR_FUP
        | (15u32 << MTL_RXQ0_OMR_RQS_SHIFT); // RX queue size = 16 KiB
    mmio_write32(mmio, MTL_RXQ0_OMR, rxq_omr);

    // Enable RX queue 0 in MAC
    mmio_write32(mmio, MAC_RQC0R, MAC_RQC0R_RXQ0EN_AV);

    // ── Configure DMA Channel 0 ──

    // Set 8xPBL mode for larger burst transfers
    mmio_write32(mmio, DMA_CH0_CR, DMA_CH0_CR_PBLX8);

    // ── Configure TX DMA channel ──

    // Program TX descriptor ring base address
    mmio_write32(mmio, DMA_CH0_TDLR_LO, tx_ring_phys as u32);
    mmio_write32(mmio, DMA_CH0_TDLR_HI, (tx_ring_phys >> 32) as u32);

    // Set TX descriptor ring length (number of descriptors minus 1)
    mmio_write32(mmio, DMA_CH0_TDRLR, (DESC_RING_SIZE - 1) as u32);

    // Set TX descriptor tail pointer to 0 (ring empty)
    // Tail pointer is the address of the descriptor *past* the last valid one
    let tx_tail_addr = tx_ring_phys;
    mmio_write32(mmio, DMA_CH0_TDTR, tx_tail_addr as u32);

    // Enable TX DMA with operate-on-second-packet
    let tcr = mmio_read32(mmio, DMA_CH0_TCR);
    mmio_write32(mmio, DMA_CH0_TCR, tcr | DMA_CH0_TCR_ST | DMA_CH0_TCR_OSP);

    // ── Configure RX DMA channel ──

    // Program RX descriptor ring base address
    mmio_write32(mmio, DMA_CH0_RDLR_LO, rx_ring_phys as u32);
    mmio_write32(mmio, DMA_CH0_RDLR_HI, (rx_ring_phys >> 32) as u32);

    // Set RX descriptor ring length (number of descriptors minus 1)
    mmio_write32(mmio, DMA_CH0_RDRLR, (DESC_RING_SIZE - 1) as u32);

    // Configure RX buffer size and enable RX DMA
    let rcr = DMA_CH0_RCR_SR
        | ((RX_BUF_SIZE as u32) << DMA_CH0_RCR_RBSZ_SHIFT)
        | (8u32 << DMA_CH0_RCR_PBL_SHIFT); // PBL = 8
    mmio_write32(mmio, DMA_CH0_RCR, rcr);

    // Set RX descriptor tail pointer to last descriptor (all available to HW)
    let rx_tail_addr = rx_ring_phys
        + ((DESC_RING_SIZE - 1) as u64) * (DESC_SIZE as u64);
    mmio_write32(mmio, DMA_CH0_RDTR, rx_tail_addr as u32);

    // ── Configure MAC ──

    // Set packet filter: accept broadcast, no promiscuous
    let pfr = 0u32; // Default: accept unicast for our address + broadcast
    mmio_write32(mmio, MAC_PFR, pfr);

    // Configure MAC: enable TX+RX, full duplex, CRC stripping, checksum offload
    // XGBE always operates at 10 Gbps in XGMII mode (no PS/FES speed bits)
    let mac_cr = MAC_CR_TE | MAC_CR_RE
        | MAC_CR_DM       // Full duplex
        | MAC_CR_ACS      // Automatic pad/CRC stripping
        | MAC_CR_CST      // CRC stripping for type packets
        | MAC_CR_JD       // Jabber disable (10G does not need jabber timer)
        | MAC_CR_IPC;     // IP checksum offload
    mmio_write32(mmio, MAC_CR, mac_cr);

    fence(Ordering::SeqCst);

    // Check initial link status
    let mac_cr_read = mmio_read32(mmio, MAC_CR);
    if mac_cr_read & MAC_CR_RE != 0 {
        log("amd_xgbe: MAC receiver enabled, link assumed up at 10 Gbps full-duplex");
    } else {
        log("amd_xgbe: MAC receiver not active, link may be down");
    }

    // Store controller state
    let nic = Xgbe {
        mmio,
        mmio_size,
        bus,
        dev,
        func,
        irq,
        mac,
        tx_ring,
        tx_ring_phys,
        tx_bufs,
        tx_bufs_phys,
        tx_tail: 0,
        rx_ring,
        rx_ring_phys,
        rx_bufs,
        rx_bufs_phys,
        rx_cur: 0,
        iface: core::ptr::null_mut(),
    };

    unsafe { *NIC.get() = Some(nic); }

    log("amd_xgbe: driver initialized successfully");
    0
}

/// Transmit a packet.
///
/// Copies `len` bytes from `data` into the next available TX descriptor
/// buffer, sets up the enhanced normal TX descriptor with OWN/FD/LD/CIC
/// flags, and advances the tail pointer to notify the DMA engine.
///
/// Returns 0 on success, -1 if no TX descriptors available,
/// -2 if the packet exceeds the buffer size, -3 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn amd_xgbe_send(data: *const u8, len: u32) -> i32 {
    let nic = match unsafe { &mut *NIC.get() } {
        Some(n) => n,
        None => return -3, // Not initialized
    };

    if data.is_null() || len == 0 {
        return -4;
    }

    if len as usize > TX_BUF_SIZE {
        return -2; // Packet too large
    }

    let idx = nic.tx_tail;

    // Check if the descriptor at this index has been reclaimed (OWN clear)
    let desc = unsafe { read_volatile(nic.tx_ring.add(idx)) };
    if desc.desc3 & TX_DESC3_OWN != 0 {
        return -1; // TX ring full, DMA still owns descriptor
    }

    // Copy packet data into the TX buffer
    let buf_offset = idx * TX_BUF_SIZE;
    let buf_ptr = unsafe { nic.tx_bufs.add(buf_offset) };
    unsafe {
        core::ptr::copy_nonoverlapping(data, buf_ptr, len as usize);
    }

    // Set up enhanced normal TX descriptor
    let buf_phys = nic.tx_bufs_phys + buf_offset as u64;

    let new_desc = XgbeDesc {
        desc0: buf_phys as u32,                          // Buffer address low
        desc1: (buf_phys >> 32) as u32,                  // Buffer address high
        desc2: (len as u32) & TX_DESC2_BUF1_LEN_MASK,   // Buffer length
        desc3: TX_DESC3_OWN | TX_DESC3_FD | TX_DESC3_LD  // OWN + First + Last
            | TX_DESC3_CIC_FULL                           // Full checksum insertion
            | (len as u32 & 0x3FFF),                      // Packet length
    };

    fence(Ordering::SeqCst);
    unsafe { write_volatile(nic.tx_ring.add(idx), new_desc); }
    fence(Ordering::SeqCst);

    // Advance TX tail and notify DMA engine
    nic.tx_tail = (idx + 1) % DESC_RING_SIZE;

    // The XGMAC tail pointer register takes the address of the descriptor
    // *after* the last valid one (i.e., the next empty slot)
    let tail_addr = nic.tx_ring_phys
        + (nic.tx_tail as u64) * (DESC_SIZE as u64);
    mmio_write32(nic.mmio, DMA_CH0_TDTR, tail_addr as u32);

    0
}

/// Poll for received packets.
///
/// Checks the RX descriptor ring for completed descriptors (OWN bit cleared
/// by DMA), calls `fut_net_rx_packet` for each received frame, then re-arms
/// the descriptor for the hardware.
///
/// Returns the number of packets processed (0 if none available).
#[unsafe(no_mangle)]
pub extern "C" fn amd_xgbe_poll() -> i32 {
    let nic = match unsafe { &mut *NIC.get() } {
        Some(n) => n,
        None => return -1, // Not initialized
    };

    let mut count: i32 = 0;

    loop {
        let idx = nic.rx_cur;
        let desc = unsafe { read_volatile(nic.rx_ring.add(idx)) };

        // Check OWN bit: if set, DMA still owns this descriptor
        if desc.desc3 & RX_WB_DESC3_OWN != 0 {
            break; // No more completed descriptors
        }

        // Check that this is a complete frame (FD + LD set, no error)
        let is_fd = desc.desc3 & RX_WB_DESC3_FD != 0;
        let is_ld = desc.desc3 & RX_WB_DESC3_LD != 0;
        let has_error = desc.desc3 & RX_WB_DESC3_ES != 0;

        // Extract packet length from desc3 (bits 13:0 in write-back)
        let pkt_len = desc.desc3 & RX_WB_DESC3_PL_MASK;

        if is_fd && is_ld && !has_error && pkt_len > 0 && pkt_len <= RX_BUF_SIZE as u32 {
            let buf_offset = idx * RX_BUF_SIZE;
            let buf_ptr = unsafe { nic.rx_bufs.add(buf_offset) };

            // Deliver packet to network stack
            unsafe {
                fut_net_rx_packet(nic.iface, buf_ptr, pkt_len);
            }
            count += 1;
        }

        // Re-arm the descriptor: set buffer address, OWN+IOC+BUF1V for HW
        let buf_phys = nic.rx_bufs_phys + (idx * RX_BUF_SIZE) as u64;
        let new_desc = XgbeDesc {
            desc0: buf_phys as u32,
            desc1: (buf_phys >> 32) as u32,
            desc2: 0,
            desc3: RX_DESC3_OWN | RX_DESC3_IOC | RX_DESC3_BUF1V,
        };

        fence(Ordering::SeqCst);
        unsafe { write_volatile(nic.rx_ring.add(idx), new_desc); }

        // Advance to next descriptor
        nic.rx_cur = (idx + 1) % DESC_RING_SIZE;

        // Update RX tail to return the descriptor to hardware
        let tail_addr = nic.rx_ring_phys
            + (idx as u64) * (DESC_SIZE as u64);
        mmio_write32(nic.mmio, DMA_CH0_RDTR, tail_addr as u32);
    }

    count
}

/// Copy the 6-byte MAC address to the provided buffer.
///
/// `out` must point to a buffer of at least 6 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn amd_xgbe_get_mac(out: *mut u8) {
    if out.is_null() {
        return;
    }

    let mac = match unsafe { &*NIC.get() } {
        Some(n) => n.mac,
        None => [0u8; 6],
    };

    unsafe {
        core::ptr::copy_nonoverlapping(mac.as_ptr(), out, 6);
    }
}

/// Query link status.
///
/// Returns a bitmask:
///   bit 0:    1 = link up, 0 = link down
///   bits 3:1: speed: 001=10M, 010=100M, 100=1G, 101=10G
///   bit 4:    1 = full-duplex, 0 = half-duplex
///
/// The AMD XGBE controller operates at 10 Gbps full-duplex when the link is
/// established. The link status is inferred from the MAC configuration and
/// DMA channel status registers.
#[unsafe(no_mangle)]
pub extern "C" fn amd_xgbe_link_status() -> u32 {
    let nic = match unsafe { &*NIC.get() } {
        Some(n) => n,
        None => return 0,
    };

    // Read MAC configuration to check if TX/RX are enabled
    let mac_cr = mmio_read32(nic.mmio, MAC_CR);

    // If both TX and RX are enabled, the link is considered up
    if mac_cr & (MAC_CR_TE | MAC_CR_RE) != (MAC_CR_TE | MAC_CR_RE) {
        return 0; // Link down (MAC not fully enabled)
    }

    let mut result: u32 = 1; // Bit 0: link up

    // XGBE operates at 10 Gbps: bits 3:1 = 101
    result |= 0x0A;

    // Full duplex is always set for 10GbE
    if mac_cr & MAC_CR_DM != 0 {
        result |= 0x10; // bit 4: full-duplex
    }

    result
}

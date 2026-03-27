// SPDX-License-Identifier: MPL-2.0
//
// Realtek RTL8111/RTL8168 Gigabit Ethernet Controller Driver
//
// Supports the Realtek RTL8111/8168/8169/8136 family of PCIe Gigabit
// Ethernet controllers, commonly found on AMD Ryzen AM4/AM5 motherboards.
//
// Architecture:
//   - MMIO register access via PCI BAR2 (256-byte register space)
//   - 256-entry TX/RX descriptor rings with 2 KiB packet buffers
//   - Polling-based operation (interrupt handler registration planned)
//   - Auto-negotiation for 1000/100/10 Mbps link speeds
//
// PCI vendor: 10ECh (Realtek), class 02h/00h (Ethernet controller)

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]
#![allow(dead_code)]

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

// ── Realtek RTL8111 Register Map (MMIO offsets) ──

// MAC address registers
const REG_IDR0: usize = 0x00;         // ID Register 0 (MAC byte 0)
const REG_IDR1: usize = 0x01;         // ID Register 1 (MAC byte 1)
const REG_IDR2: usize = 0x02;         // ID Register 2 (MAC byte 2)
const REG_IDR3: usize = 0x03;         // ID Register 3 (MAC byte 3)
const REG_IDR4: usize = 0x04;         // ID Register 4 (MAC byte 4)
const REG_IDR5: usize = 0x05;         // ID Register 5 (MAC byte 5)

// Multicast address registers
const REG_MAR0: usize = 0x08;         // Multicast Address Register 0-3
const REG_MAR4: usize = 0x0C;         // Multicast Address Register 4-7

// TX descriptor start address (64-bit)
const REG_TNPDS_LO: usize = 0x20;    // Transmit Normal Priority Descriptors (low 32)
const REG_TNPDS_HI: usize = 0x24;    // Transmit Normal Priority Descriptors (high 32)

// Command register
const REG_CHIPCMD: usize = 0x37;      // Chip Command register

// TX poll register
const REG_TPPOLL: usize = 0x38;       // Transmit Priority Polling register

// Interrupt registers
const REG_IMR: usize = 0x3C;          // Interrupt Mask Register (16-bit)
const REG_ISR: usize = 0x3E;          // Interrupt Status Register (16-bit)

// TX configuration
const REG_TXCONFIG: usize = 0x40;     // Transmit Configuration Register

// RX configuration
const REG_RXCONFIG: usize = 0x44;     // Receive Configuration Register

// Timer/counter
const REG_TCTR: usize = 0x48;         // Timer Count Register

// MPC (Missed Packet Counter)
const REG_MPC: usize = 0x4C;          // Missed Packet Counter

// 93C46/93C56 EEPROM command register
const REG_9346CR: usize = 0x50;       // 93C46 Command Register

// Configuration registers
const REG_CONFIG0: usize = 0x51;
const REG_CONFIG1: usize = 0x52;
const REG_CONFIG2: usize = 0x53;
const REG_CONFIG3: usize = 0x54;
const REG_CONFIG4: usize = 0x55;
const REG_CONFIG5: usize = 0x56;

// PHY Access register (32-bit)
const REG_PHYAR: usize = 0x60;        // PHY Access Register

// PHY Status register
const REG_PHYSTAT: usize = 0x6C;      // PHY Status Register

// RX maximum packet size
const REG_RXMAXSIZE: usize = 0xDA;    // RX packet maximum size (16-bit)

// Countdown timer interrupt
const REG_TIMER_INT: usize = 0x58;    // Timer Interrupt Register

// RX descriptor start address (64-bit)
const REG_RDSAR_LO: usize = 0xE4;    // Receive Descriptor Start Address (low 32)
const REG_RDSAR_HI: usize = 0xE8;    // Receive Descriptor Start Address (high 32)

// Max TX packet size
const REG_MTPS: usize = 0xEC;         // Max Transmit Packet Size (8-bit)

// C+ Command register
const REG_CPLUSCMD: usize = 0xE0;     // C+ Command Register (16-bit)

// ── ChipCmd register bits ──

const CMD_RESET: u8 = 0x10;           // Software reset
const CMD_TX_ENABLE: u8 = 0x04;       // Transmitter enable
const CMD_RX_ENABLE: u8 = 0x08;       // Receiver enable

// ── TPPoll register bits ──

const TPPOLL_NPQ: u8 = 0x40;         // Normal Priority Queue polling

// ── Interrupt bits (IMR/ISR) ──

const INT_ROK: u16 = 0x0001;          // Receive OK
const INT_RER: u16 = 0x0002;          // Receive Error
const INT_TOK: u16 = 0x0004;          // Transmit OK
const INT_TER: u16 = 0x0008;          // Transmit Error
const INT_RDU: u16 = 0x0010;          // RX Descriptor Unavailable
const INT_LINKCHG: u16 = 0x0020;      // Link Change
const INT_FOVW: u16 = 0x0040;         // RX FIFO Overflow
const INT_TDU: u16 = 0x0080;          // TX Descriptor Unavailable
const INT_SWINT: u16 = 0x0100;        // Software Interrupt
const INT_TIMEOUT: u16 = 0x4000;      // Timer timeout

// Mask for all interrupts we care about
const INT_MASK_DEFAULT: u16 = INT_ROK | INT_RER | INT_TOK | INT_TER
    | INT_RDU | INT_LINKCHG | INT_FOVW;

// ── TxConfig register bits ──

const TX_IFG_STANDARD: u32 = 0x03 << 24;  // Standard inter-frame gap (96-bit time)
const TX_DMA_BURST_1024: u32 = 0x06 << 8; // Max DMA burst = 1024 bytes (110b)

// ── RxConfig register bits ──

const RX_ACCEPT_BROADCAST: u32 = 1 << 3;      // Accept Broadcast packets
const RX_ACCEPT_MULTICAST: u32 = 1 << 2;      // Accept Multicast packets
const RX_ACCEPT_MY_PHYS: u32 = 1 << 1;        // Accept packets matching MAC
const RX_ACCEPT_ALL_PHYS: u32 = 1 << 0;       // Accept all packets (promiscuous)
const RX_DMA_BURST_1024: u32 = 0x06 << 8;     // Max DMA burst = 1024 bytes
const RX_ACCEPT_ERR: u32 = 1 << 5;            // Accept Error packets
const RX_ACCEPT_RUNT: u32 = 1 << 4;           // Accept Runt packets
const RX_NO_THRESHOLD: u32 = 0x07 << 13;      // No early-RX threshold (7 = unlimited)
const RX_FETCH_MULTI_DESC: u32 = 1 << 11;     // Fetch multiple descriptors

// ── C+ Command register bits ──

const CPLUS_RX_VLAN: u16 = 1 << 6;            // VLAN de-tagging
const CPLUS_RX_CHKSUM: u16 = 1 << 5;          // RX checksum offload enable
const CPLUS_PCI_MULRW: u16 = 1 << 3;          // PCI Multiple R/W Enable

// ── 93C46 Command Register bits ──

const C9346_LOCK: u8 = 0x00;          // Config write protect
const C9346_UNLOCK: u8 = 0xC0;        // Config write enable

// ── PHY Access Register bits ──

const PHYAR_FLAG: u32 = 1 << 31;      // Read/Write flag: 1=write complete, 0=read data valid
const PHYAR_WRITE: u32 = 1 << 31;     // PHY write operation

// ── PHY Status register bits ──

const PHYSTAT_FULLDUP: u32 = 0x0002;   // Full-duplex
const PHYSTAT_LINK: u32 = 0x0004;      // Link status (set = up)
const PHYSTAT_10M: u32 = 0x0008;       // 10 Mbps
const PHYSTAT_100M: u32 = 0x0010;      // 100 Mbps
const PHYSTAT_1000M: u32 = 0x0020;     // 1000 Mbps

// ── PHY register addresses (MII standard) ──

const PHY_BMCR: u32 = 0x00;           // Basic Mode Control Register
const PHY_BMSR: u32 = 0x01;           // Basic Mode Status Register
const PHY_ANAR: u32 = 0x04;           // Auto-Negotiation Advertisement Register
const PHY_GBCR: u32 = 0x09;           // 1000BASE-T Control Register

// BMCR bits
const BMCR_RESET: u16 = 1 << 15;      // PHY software reset
const BMCR_SPEED_1000: u16 = 1 << 6;  // Speed Select (MSB) = 1000 Mbps
const BMCR_AUTONEG_EN: u16 = 1 << 12; // Auto-Negotiation Enable
const BMCR_RESTART_AN: u16 = 1 << 9;  // Restart Auto-Negotiation
const BMCR_FULL_DUPLEX: u16 = 1 << 8; // Full Duplex Mode

// ANAR bits (Auto-Negotiation Advertisement)
const ANAR_10_HD: u16 = 1 << 5;       // 10BASE-T Half Duplex
const ANAR_10_FD: u16 = 1 << 6;       // 10BASE-T Full Duplex
const ANAR_100_HD: u16 = 1 << 7;      // 100BASE-TX Half Duplex
const ANAR_100_FD: u16 = 1 << 8;      // 100BASE-TX Full Duplex
const ANAR_PAUSE: u16 = 1 << 10;      // Pause capability
const ANAR_ASYM_PAUSE: u16 = 1 << 11; // Asymmetric Pause
const ANAR_SELECTOR: u16 = 0x0001;    // IEEE 802.3 selector field

// GBCR bits (1000BASE-T Control)
const GBCR_1000_FD: u16 = 1 << 9;     // Advertise 1000BASE-T Full Duplex
const GBCR_1000_HD: u16 = 1 << 8;     // Advertise 1000BASE-T Half Duplex

// ── TX/RX descriptor format ──

const DESC_RING_SIZE: usize = 256;     // Number of descriptors in each ring
const DESC_SIZE: usize = 16;           // Bytes per descriptor
const TX_BUF_SIZE: usize = 2048;       // TX buffer size per descriptor
const RX_BUF_SIZE: usize = 2048;       // RX buffer size per descriptor

/// Hardware TX/RX descriptor (16 bytes, little-endian)
///
/// opts1 bit layout:
///   [31]    OWN  - Owned by NIC (1) or driver (0)
///   [30]    EOR  - End of Ring (wrap back to first descriptor)
///   [29]    FS   - First Segment of packet
///   [28]    LS   - Last Segment of packet
///   [15:0]  Frame length / buffer size
///
/// opts2 bit layout (TX):
///   [17]    UDP checksum offload
///   [18]    TCP checksum offload
///   [19]    IP checksum offload
///   [31:16] VLAN tag (if enabled)
///
/// opts2 bit layout (RX):
///   [24]    IP checksum valid
///   [25]    UDP checksum valid
///   [26]    TCP checksum valid
#[repr(C)]
#[derive(Clone, Copy)]
struct RtlDescriptor {
    opts1: u32,
    opts2: u32,
    addr_lo: u32,
    addr_hi: u32,
}

const _: () = assert!(core::mem::size_of::<RtlDescriptor>() == DESC_SIZE);

// Descriptor flag bits
const DESC_OWN: u32 = 1 << 31;        // NIC owns this descriptor
const DESC_EOR: u32 = 1 << 30;        // End Of Ring - wrap to first descriptor
const DESC_FS: u32 = 1 << 29;         // First Segment
const DESC_LS: u32 = 1 << 28;         // Last Segment

// RX descriptor status bits (in opts1 after receive)
const RX_RES: u32 = 1 << 21;          // Receive Error Summary
const RX_CRC: u32 = 1 << 19;          // CRC Error
const RX_RUNT: u32 = 1 << 22;         // Runt Packet

// TX descriptor flag bits
const TX_IPCS: u32 = 1 << 18;         // IP checksum offload (opts2)
const TX_UDPCS: u32 = 1 << 17;        // UDP checksum offload (opts2)
const TX_TCPCS: u32 = 1 << 16;        // TCP checksum offload (opts2) [opts2 bit 18 actual]

// ── PCI vendor/device IDs ──

const RTL_VENDOR_ID: u16 = 0x10EC;

const RTL_DEVICE_IDS: &[u16] = &[
    0x8168,     // RTL8111/8168/8411 PCI Express Gigabit Ethernet
    0x8111,     // RTL8111 (alternate ID)
    0x8169,     // RTL8169 PCI Gigabit Ethernet
    0x8136,     // RTL8101E/RTL8102E PCI Express Fast Ethernet
];

// ── Controller state ──

struct Rtl8111 {
    /// MMIO base address (mapped virtual address)
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
    tx_ring: *mut RtlDescriptor,
    tx_ring_phys: u64,
    tx_bufs: *mut u8,
    tx_bufs_phys: u64,
    tx_head: usize,            // Next descriptor to reclaim (completed by HW)
    tx_tail: usize,            // Next descriptor to fill (submitted by driver)

    // RX descriptor ring
    rx_ring: *mut RtlDescriptor,
    rx_ring_phys: u64,
    rx_bufs: *mut u8,
    rx_bufs_phys: u64,
    rx_cur: usize,             // Next descriptor to check for received packets

    // Interface pointer for fut_net_rx_packet callback
    iface: *mut c_void,
}

unsafe impl Send for Rtl8111 {}
unsafe impl Sync for Rtl8111 {}

static mut RTL: Option<Rtl8111> = None;

// ── MMIO helpers ──

fn mmio_read8(base: *mut u8, offset: usize) -> u8 {
    unsafe { read_volatile(base.add(offset)) }
}

fn mmio_write8(base: *mut u8, offset: usize, val: u8) {
    unsafe { write_volatile(base.add(offset), val) }
}

fn mmio_read16(base: *mut u8, offset: usize) -> u16 {
    unsafe { read_volatile(base.add(offset) as *const u16) }
}

fn mmio_write16(base: *mut u8, offset: usize, val: u16) {
    unsafe { write_volatile(base.add(offset) as *mut u16, val) }
}

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

// ── PHY register access ──

/// Read a PHY register via the PHYAR indirect access register.
/// Returns the 16-bit register value.
fn phy_read(mmio: *mut u8, reg: u32) -> u16 {
    // Write register address (bits 20:16), clear write flag
    mmio_write32(mmio, REG_PHYAR, (reg & 0x1F) << 16);

    // Poll for completion (bit 31 set = data valid)
    for _ in 0..2000u32 {
        let val = mmio_read32(mmio, REG_PHYAR);
        if val & PHYAR_FLAG != 0 {
            return (val & 0xFFFF) as u16;
        }
        // Short delay between polls
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }
    0xFFFF // Timeout
}

/// Write a PHY register via the PHYAR indirect access register.
fn phy_write(mmio: *mut u8, reg: u32, val: u16) {
    // Write: set bit 31, register in bits 20:16, data in bits 15:0
    mmio_write32(mmio, REG_PHYAR,
        PHYAR_WRITE | ((reg & 0x1F) << 16) | (val as u32));

    // Poll for completion (bit 31 clear = write done)
    for _ in 0..2000u32 {
        let v = mmio_read32(mmio, REG_PHYAR);
        if v & PHYAR_FLAG == 0 {
            return;
        }
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }
}

// ── PCI discovery ──

fn find_rtl_pci() -> Option<(u8, u8, u8, u16, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == RTL_VENDOR_ID {
            for &did in RTL_DEVICE_IDS {
                if dev.device_id == did {
                    return Some((dev.bus, dev.dev, dev.func, dev.device_id, dev.irq_line));
                }
            }
        }
    }
    None
}

// ── Chip reset ──

/// Perform a software reset and wait for completion.
/// The RTL8111 clears the Reset bit when the reset is complete.
fn chip_reset(mmio: *mut u8) -> bool {
    mmio_write8(mmio, REG_CHIPCMD, CMD_RESET);

    // Wait for reset to complete (bit should clear within ~100 us)
    for _ in 0..100_000u32 {
        if mmio_read8(mmio, REG_CHIPCMD) & CMD_RESET == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// ── MAC address reading ──

fn read_mac_address(mmio: *mut u8) -> [u8; 6] {
    [
        mmio_read8(mmio, REG_IDR0),
        mmio_read8(mmio, REG_IDR1),
        mmio_read8(mmio, REG_IDR2),
        mmio_read8(mmio, REG_IDR3),
        mmio_read8(mmio, REG_IDR4),
        mmio_read8(mmio, REG_IDR5),
    ]
}

// ── PHY configuration ──

/// Configure PHY for auto-negotiation at all supported speeds.
fn configure_phy(mmio: *mut u8) {
    // Advertise 10/100 Mbps capabilities
    let anar = ANAR_SELECTOR | ANAR_10_HD | ANAR_10_FD
        | ANAR_100_HD | ANAR_100_FD | ANAR_PAUSE | ANAR_ASYM_PAUSE;
    phy_write(mmio, PHY_ANAR, anar);

    // Advertise 1000 Mbps capabilities
    let gbcr = GBCR_1000_FD | GBCR_1000_HD;
    phy_write(mmio, PHY_GBCR, gbcr);

    // Enable auto-negotiation and restart
    let bmcr = BMCR_AUTONEG_EN | BMCR_RESTART_AN;
    phy_write(mmio, PHY_BMCR, bmcr);
}

// ── Descriptor ring initialization ──

/// Allocate and initialize the TX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_tx_ring() -> Option<(*mut RtlDescriptor, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut RtlDescriptor };
    if ring.is_null() {
        return None;
    }
    let ring_phys = virt_to_phys(ring as *const u8);

    // Allocate TX buffers: 256 * 2048 = 524288 bytes = 128 pages
    // We allocate as a contiguous block via alloc()
    let total_buf_size = DESC_RING_SIZE * TX_BUF_SIZE;
    let bufs = unsafe { alloc(total_buf_size) };
    if bufs.is_null() {
        return None;
    }
    let bufs_phys = virt_to_phys(bufs);

    // Initialize descriptors
    for i in 0..DESC_RING_SIZE {
        let buf_phys = bufs_phys + (i * TX_BUF_SIZE) as u64;
        let mut opts1: u32 = 0; // Driver owns, length = 0 (unused until send)
        if i == DESC_RING_SIZE - 1 {
            opts1 |= DESC_EOR; // Mark last descriptor with End Of Ring
        }
        let desc = RtlDescriptor {
            opts1,
            opts2: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

/// Allocate and initialize the RX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_rx_ring() -> Option<(*mut RtlDescriptor, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut RtlDescriptor };
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

    // Initialize descriptors: all owned by NIC, ready to receive
    for i in 0..DESC_RING_SIZE {
        let buf_phys = bufs_phys + (i * RX_BUF_SIZE) as u64;
        let mut opts1: u32 = DESC_OWN | (RX_BUF_SIZE as u32 & 0x3FFF);
        if i == DESC_RING_SIZE - 1 {
            opts1 |= DESC_EOR; // End Of Ring on last descriptor
        }
        let desc = RtlDescriptor {
            opts1,
            opts2: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

// ── FFI exports ──

/// Initialize the RTL8111 Gigabit Ethernet controller.
///
/// Scans PCI for supported Realtek devices, maps MMIO registers,
/// performs a chip reset, reads the MAC address, configures the PHY
/// for auto-negotiation, sets up TX/RX descriptor rings, and enables
/// the transmitter and receiver.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn rtl8111_init() -> i32 {
    log("rtl8111: scanning PCI for Realtek Ethernet controllers...");

    let (bus, dev, func, device_id, irq) = match find_rtl_pci() {
        Some(info) => info,
        None => {
            log("rtl8111: no supported Realtek controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"rtl8111: found device %04x:%04x at PCI %02x:%02x.%x IRQ %d\n\0".as_ptr(),
            RTL_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32, irq as u32,
        );
    }

    // Enable bus mastering and memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // Read BAR2 for MMIO (RTL8111 typically uses BAR2 for memory-mapped registers)
    // BAR2 is at PCI config offset 0x18 (BAR0=0x10, BAR1=0x14, BAR2=0x18)
    let bar2_raw = pci_read32(bus, dev, func, 0x18);
    let is_mmio = (bar2_raw & 0x01) == 0;

    if !is_mmio {
        // Fall back to BAR0 if BAR2 is I/O space
        let bar0_raw = pci_read32(bus, dev, func, 0x10);
        if bar0_raw & 0x01 != 0 {
            log("rtl8111: no MMIO BAR found, I/O port mode not supported");
            return -2;
        }
    }

    // Determine which BAR to use: prefer BAR2 (MMIO), fall back to BAR0
    let (bar_offset, bar_raw) = if is_mmio {
        (0x18u8, bar2_raw)
    } else {
        (0x10u8, pci_read32(bus, dev, func, 0x10))
    };

    // Determine if 64-bit BAR
    let is_64bit = (bar_raw & 0x06) == 0x04;
    let bar_lo = bar_raw & !0xF;
    let bar_hi = if is_64bit {
        pci_read32(bus, dev, func, bar_offset + 4)
    } else {
        0
    };
    let bar_phys = (bar_lo as u64) | ((bar_hi as u64) << 32);

    if bar_phys == 0 {
        log("rtl8111: BAR not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"rtl8111: MMIO BAR at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map MMIO region (RTL8111 register space is 256 bytes, map a full page)
    let mmio_size = 0x1000usize;
    let mmio = unsafe { map_mmio_region(bar_phys, mmio_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("rtl8111: failed to map MMIO region");
        return -4;
    }

    // Perform software reset
    if !chip_reset(mmio) {
        log("rtl8111: chip reset timeout");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -5;
    }
    log("rtl8111: chip reset complete");

    // Unlock configuration registers (9346CR)
    mmio_write8(mmio, REG_9346CR, C9346_UNLOCK);

    // Read MAC address from IDR0-IDR5
    let mac = read_mac_address(mmio);

    unsafe {
        fut_printf(
            b"rtl8111: MAC address %02x:%02x:%02x:%02x:%02x:%02x\n\0".as_ptr(),
            mac[0] as u32, mac[1] as u32, mac[2] as u32,
            mac[3] as u32, mac[4] as u32, mac[5] as u32,
        );
    }

    // Validate MAC address (should not be all zeros or all FF)
    let all_zero = mac.iter().all(|&b| b == 0x00);
    let all_ff = mac.iter().all(|&b| b == 0xFF);
    if all_zero || all_ff {
        log("rtl8111: invalid MAC address read from hardware");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -6;
    }

    // Disable TX and RX before configuring
    mmio_write8(mmio, REG_CHIPCMD, 0x00);

    // Set up TX descriptor ring
    let (tx_ring, tx_ring_phys, tx_bufs, tx_bufs_phys) = match init_tx_ring() {
        Some(v) => v,
        None => {
            log("rtl8111: failed to allocate TX ring");
            unsafe { unmap_mmio_region(mmio, mmio_size); }
            return -7;
        }
    };

    // Set up RX descriptor ring
    let (rx_ring, rx_ring_phys, rx_bufs, rx_bufs_phys) = match init_rx_ring() {
        Some(v) => v,
        None => {
            log("rtl8111: failed to allocate RX ring");
            unsafe {
                free(tx_bufs);
                unmap_mmio_region(mmio, mmio_size);
            }
            return -8;
        }
    };

    // Program TX descriptor ring address
    mmio_write32(mmio, REG_TNPDS_LO, tx_ring_phys as u32);
    mmio_write32(mmio, REG_TNPDS_HI, (tx_ring_phys >> 32) as u32);

    // Program RX descriptor ring address
    mmio_write32(mmio, REG_RDSAR_LO, rx_ring_phys as u32);
    mmio_write32(mmio, REG_RDSAR_HI, (rx_ring_phys >> 32) as u32);

    // Set RX maximum packet size
    mmio_write16(mmio, REG_RXMAXSIZE, RX_BUF_SIZE as u16);

    // Set max TX packet size (in 128-byte units for RTL8111)
    mmio_write8(mmio, REG_MTPS, (TX_BUF_SIZE / 128) as u8);

    // Configure C+ Command: enable PCI multiple R/W, RX checksum offload
    let cplus = CPLUS_PCI_MULRW | CPLUS_RX_CHKSUM;
    mmio_write16(mmio, REG_CPLUSCMD, cplus);

    // Configure TX: standard inter-frame gap, max DMA burst
    let txconfig = TX_IFG_STANDARD | TX_DMA_BURST_1024;
    mmio_write32(mmio, REG_TXCONFIG, txconfig);

    // Configure RX: accept broadcast + our MAC, max DMA burst, no threshold
    let rxconfig = RX_ACCEPT_BROADCAST | RX_ACCEPT_MY_PHYS
        | RX_DMA_BURST_1024 | RX_NO_THRESHOLD | RX_FETCH_MULTI_DESC;
    mmio_write32(mmio, REG_RXCONFIG, rxconfig);

    // Accept all multicast (set multicast filter to all-ones)
    mmio_write32(mmio, REG_MAR0, 0xFFFFFFFF);
    mmio_write32(mmio, REG_MAR4, 0xFFFFFFFF);

    // Configure PHY for auto-negotiation
    configure_phy(mmio);

    // Set up interrupt mask (even if polling, so status register reflects events)
    mmio_write16(mmio, REG_IMR, INT_MASK_DEFAULT);

    // Clear any pending interrupt status
    mmio_write16(mmio, REG_ISR, 0xFFFF);

    // Lock configuration registers
    mmio_write8(mmio, REG_9346CR, C9346_LOCK);

    // Enable TX and RX
    mmio_write8(mmio, REG_CHIPCMD, CMD_TX_ENABLE | CMD_RX_ENABLE);
    fence(Ordering::SeqCst);

    // Verify TX/RX are enabled
    let cmd = mmio_read8(mmio, REG_CHIPCMD);
    if cmd & (CMD_TX_ENABLE | CMD_RX_ENABLE) != (CMD_TX_ENABLE | CMD_RX_ENABLE) {
        log("rtl8111: failed to enable TX/RX");
        unsafe {
            free(tx_bufs);
            free(rx_bufs);
            unmap_mmio_region(mmio, mmio_size);
        }
        return -9;
    }

    // Check initial link status
    let phy_stat = mmio_read32(mmio, REG_PHYSTAT);
    if phy_stat & PHYSTAT_LINK != 0 {
        let speed = if phy_stat & PHYSTAT_1000M != 0 {
            "1000"
        } else if phy_stat & PHYSTAT_100M != 0 {
            "100"
        } else {
            "10"
        };
        let duplex = if phy_stat & PHYSTAT_FULLDUP != 0 {
            "full"
        } else {
            "half"
        };
        // Build combined status message
        let mut buf = [0u8; 80];
        let prefix = b"rtl8111: link up at ";
        buf[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        for &b in speed.as_bytes() {
            buf[pos] = b;
            pos += 1;
        }
        let mid = b" Mbps ";
        buf[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        for &b in duplex.as_bytes() {
            buf[pos] = b;
            pos += 1;
        }
        let suffix = b"-duplex";
        buf[pos..pos + suffix.len()].copy_from_slice(suffix);
        pos += suffix.len();
        buf[pos] = 0;
        unsafe {
            fut_printf(b"%s\n\0".as_ptr(), buf.as_ptr());
        }
    } else {
        log("rtl8111: link down (auto-negotiation in progress)");
    }

    // Store controller state
    let nic = Rtl8111 {
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
        tx_head: 0,
        tx_tail: 0,
        rx_ring,
        rx_ring_phys,
        rx_bufs,
        rx_bufs_phys,
        rx_cur: 0,
        iface: core::ptr::null_mut(),
    };

    unsafe { core::ptr::addr_of_mut!(RTL).write(Some(nic)); }

    log("rtl8111: driver initialized successfully");
    0
}

/// Transmit a packet.
///
/// Copies `len` bytes from `data` into the next available TX descriptor
/// buffer, sets the OWN/FS/LS flags, and triggers the NIC to poll.
///
/// Returns 0 on success, -1 if no TX descriptors are available,
/// -2 if the packet exceeds the buffer size.
#[unsafe(no_mangle)]
pub extern "C" fn rtl8111_send(data: *const u8, len: u32) -> i32 {
    let nic = match unsafe { &mut *core::ptr::addr_of_mut!(RTL) } {
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

    // Check if the descriptor is still owned by the NIC (ring full)
    let desc = unsafe { read_volatile(nic.tx_ring.add(idx)) };
    if desc.opts1 & DESC_OWN != 0 {
        return -1; // TX ring full, try again later
    }

    // Copy packet data into the TX buffer
    let buf_offset = idx * TX_BUF_SIZE;
    let buf_ptr = unsafe { nic.tx_bufs.add(buf_offset) };
    unsafe {
        core::ptr::copy_nonoverlapping(data, buf_ptr, len as usize);
    }

    // Set up the descriptor: OWN + FS + LS + length
    let buf_phys = nic.tx_bufs_phys + buf_offset as u64;
    let mut opts1 = DESC_OWN | DESC_FS | DESC_LS | (len as u32 & 0x3FFF);
    if idx == DESC_RING_SIZE - 1 {
        opts1 |= DESC_EOR;
    }

    let new_desc = RtlDescriptor {
        opts1,
        opts2: 0, // No checksum offload for now
        addr_lo: buf_phys as u32,
        addr_hi: (buf_phys >> 32) as u32,
    };

    fence(Ordering::SeqCst);
    unsafe { write_volatile(nic.tx_ring.add(idx), new_desc); }
    fence(Ordering::SeqCst);

    // Advance TX tail
    nic.tx_tail = (idx + 1) % DESC_RING_SIZE;

    // Notify NIC to poll the TX descriptor ring
    mmio_write8(nic.mmio, REG_TPPOLL, TPPOLL_NPQ);

    0
}

/// Poll for received packets.
///
/// Checks the RX descriptor ring for completed descriptors (OWN bit clear),
/// calls `fut_net_rx_packet` for each received frame, then re-arms the
/// descriptor for the NIC.
///
/// Returns the number of packets processed (0 if none available).
#[unsafe(no_mangle)]
pub extern "C" fn rtl8111_poll() -> i32 {
    let nic = match unsafe { &mut *core::ptr::addr_of_mut!(RTL) } {
        Some(n) => n,
        None => return -1, // Not initialized
    };

    let mut count: i32 = 0;

    loop {
        let idx = nic.rx_cur;
        let desc = unsafe { read_volatile(nic.rx_ring.add(idx)) };

        // If OWN is set, NIC still owns this descriptor - no more packets
        if desc.opts1 & DESC_OWN != 0 {
            break;
        }

        // Extract frame length from opts1 bits [13:0]
        let frame_len = desc.opts1 & 0x3FFF;

        // Check for errors
        let has_error = desc.opts1 & (RX_RES | RX_CRC | RX_RUNT) != 0;

        // Only deliver valid, complete frames (FS + LS set)
        let is_complete = desc.opts1 & (DESC_FS | DESC_LS) == (DESC_FS | DESC_LS);

        if !has_error && is_complete && frame_len > 0 && frame_len <= RX_BUF_SIZE as u32 {
            // Compute buffer address for this descriptor
            let buf_offset = idx * RX_BUF_SIZE;
            let buf_ptr = unsafe { nic.rx_bufs.add(buf_offset) };

            // Deliver packet to network stack
            unsafe {
                fut_net_rx_packet(nic.iface, buf_ptr, frame_len);
            }
            count += 1;
        }

        // Re-arm the descriptor for the NIC
        let buf_phys = nic.rx_bufs_phys + (idx * RX_BUF_SIZE) as u64;
        let mut opts1 = DESC_OWN | (RX_BUF_SIZE as u32 & 0x3FFF);
        if idx == DESC_RING_SIZE - 1 {
            opts1 |= DESC_EOR;
        }

        let new_desc = RtlDescriptor {
            opts1,
            opts2: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };

        fence(Ordering::SeqCst);
        unsafe { write_volatile(nic.rx_ring.add(idx), new_desc); }

        // Advance to next descriptor
        nic.rx_cur = (idx + 1) % DESC_RING_SIZE;
    }

    // Acknowledge any pending RX interrupts
    let isr = mmio_read16(nic.mmio, REG_ISR);
    if isr & (INT_ROK | INT_RER | INT_RDU | INT_FOVW) != 0 {
        mmio_write16(nic.mmio, REG_ISR, isr & (INT_ROK | INT_RER | INT_RDU | INT_FOVW));
    }

    count
}

/// Copy the 6-byte MAC address to the provided buffer.
///
/// `out` must point to a buffer of at least 6 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn rtl8111_get_mac(out: *mut u8) {
    if out.is_null() {
        return;
    }

    let mac = match unsafe { &*core::ptr::addr_of!(RTL) } {
        Some(n) => n.mac,
        None => [0u8; 6],
    };

    unsafe {
        core::ptr::copy_nonoverlapping(mac.as_ptr(), out, 6);
    }
}

/// Query link status.
///
/// Returns 1 if link is up, 0 if link is down.
/// Also returns speed/duplex information encoded in upper bits:
///   bits [3:1]: 001=10M, 010=100M, 100=1000M
///   bit [4]:    1=full-duplex, 0=half-duplex
#[unsafe(no_mangle)]
pub extern "C" fn rtl8111_link_status() -> u32 {
    let nic = match unsafe { &*core::ptr::addr_of!(RTL) } {
        Some(n) => n,
        None => return 0,
    };

    let phy_stat = mmio_read32(nic.mmio, REG_PHYSTAT);

    if phy_stat & PHYSTAT_LINK == 0 {
        return 0; // Link down
    }

    let mut result: u32 = 1; // Bit 0: link up

    // Speed bits
    if phy_stat & PHYSTAT_1000M != 0 {
        result |= 0x08; // bit 3
    } else if phy_stat & PHYSTAT_100M != 0 {
        result |= 0x04; // bit 2
    } else {
        result |= 0x02; // bit 1 (10 Mbps)
    }

    // Duplex bit
    if phy_stat & PHYSTAT_FULLDUP != 0 {
        result |= 0x10; // bit 4
    }

    result
}

// SPDX-License-Identifier: MPL-2.0
//
// Intel I225-V / I226-V 2.5 Gigabit Ethernet (igc) Driver
//
// Supports the Intel I225/I226 family of PCIe 2.5GbE controllers,
// found on AMD Ryzen AM5 motherboards (e.g. B650/X670 chipsets).
//
// Architecture:
//   - MMIO register access via PCI BAR0 (128 KiB register space)
//   - 256-entry TX/RX advanced descriptor rings with 2 KiB packet buffers
//   - Polling-based operation (interrupts disabled via IMC)
//   - Auto-negotiation for 2.5G/1G/100M link speeds via MDIC PHY access
//   - EEPROM MAC address read via EERD, fallback to RAL0/RAH0
//
// PCI vendor: 8086h (Intel), class 02h/00h (Ethernet controller)

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

// ── Intel igc Register Map (MMIO BAR0 offsets) ──

// Device control and status
const IGC_CTRL: usize     = 0x0000;  // Device Control
const IGC_STATUS: usize   = 0x0008;  // Device Status
const IGC_EECD: usize     = 0x0010;  // EEPROM/Flash Control
const IGC_EERD: usize     = 0x0014;  // EEPROM Read
const IGC_CTRL_EXT: usize = 0x00C0;  // Extended Device Control
const IGC_MDIC: usize     = 0x0020;  // MDI Control (PHY register access)

// Interrupt registers
const IGC_ICR: usize      = 0x01500; // Interrupt Cause Read (I225/I226 uses 0x1500)
const IGC_IMS: usize      = 0x01508; // Interrupt Mask Set
const IGC_IMC: usize      = 0x0150C; // Interrupt Mask Clear
const IGC_ICR_LEGACY: usize = 0x00C0; // Legacy ICR fallback
const IGC_IAM: usize      = 0x00E0;  // Interrupt Acknowledge Auto-Mask

// Receive control
const IGC_RCTL: usize     = 0x0100;  // Receive Control
const IGC_SRRCTL0: usize  = 0x0C00;  // Split Receive Control (queue 0)

// Transmit control
const IGC_TCTL: usize     = 0x0400;  // Transmit Control

// RX descriptor ring (queue 0)
const IGC_RDBAL0: usize   = 0xC000;  // RX Descriptor Base Address Low
const IGC_RDBAH0: usize   = 0xC004;  // RX Descriptor Base Address High
const IGC_RDLEN0: usize   = 0xC008;  // RX Descriptor Length
const IGC_RDH0: usize     = 0xC010;  // RX Descriptor Head
const IGC_RDT0: usize     = 0xC018;  // RX Descriptor Tail
const IGC_RXDCTL0: usize  = 0xC028;  // RX Descriptor Control

// TX descriptor ring (queue 0)
const IGC_TDBAL0: usize   = 0xE000;  // TX Descriptor Base Address Low
const IGC_TDBAH0: usize   = 0xE004;  // TX Descriptor Base Address High
const IGC_TDLEN0: usize   = 0xE008;  // TX Descriptor Length
const IGC_TDH0: usize     = 0xE010;  // TX Descriptor Head
const IGC_TDT0: usize     = 0xE018;  // TX Descriptor Tail
const IGC_TXDCTL0: usize  = 0xE028;  // TX Descriptor Control

// Receive address (MAC filter)
const IGC_RAL0: usize     = 0x5400;  // Receive Address Low (bytes 0-3)
const IGC_RAH0: usize     = 0x5404;  // Receive Address High (bytes 4-5 + AV)

// Multicast table array
const IGC_MTA_BASE: usize = 0x5200;  // Multicast Table Array (128 entries)

// ── CTRL register bits ──

const CTRL_FD: u32        = 1 << 0;   // Full Duplex
const CTRL_GIO_MASTER_DIS: u32 = 1 << 2; // GIO Master Disable
const CTRL_SLU: u32       = 1 << 6;   // Set Link Up
const CTRL_FRCSPD: u32    = 1 << 11;  // Force Speed
const CTRL_FRCDPLX: u32   = 1 << 12;  // Force Duplex
const CTRL_RST: u32       = 1 << 26;  // Device Reset
const CTRL_PHY_RST: u32   = 1 << 31;  // PHY Reset

// ── STATUS register bits ──

const STATUS_FD: u32      = 1 << 0;   // Full Duplex
const STATUS_LU: u32      = 1 << 1;   // Link Up
const STATUS_SPEED_MASK: u32 = 0x00C0; // Speed indication (bits 7:6)
const STATUS_SPEED_10: u32  = 0x0000;
const STATUS_SPEED_100: u32 = 0x0040;
const STATUS_SPEED_1000: u32 = 0x0080;
const STATUS_SPEED_2500: u32 = 0x00C0; // I225/I226: 2.5 Gbps

// ── EERD register bits ──

const EERD_START: u32     = 1 << 0;   // Start Read
const EERD_DONE: u32      = 1 << 1;   // Read Done
const EERD_ADDR_SHIFT: u32 = 2;       // Address field shift
const EERD_DATA_SHIFT: u32 = 16;      // Data field shift

// ── MDIC register bits ──

const MDIC_DATA_MASK: u32  = 0x0000FFFF;
const MDIC_REG_SHIFT: u32  = 16;       // PHY register address shift
const MDIC_PHY_SHIFT: u32  = 21;       // PHY address shift
const MDIC_OP_READ: u32    = 0x08000000; // Read operation
const MDIC_OP_WRITE: u32   = 0x04000000; // Write operation
const MDIC_READY: u32      = 0x10000000; // Ready bit
const MDIC_ERROR: u32      = 0x40000000; // Error bit

// ── RCTL register bits ──

const RCTL_EN: u32        = 1 << 1;   // Receiver Enable
const RCTL_SBP: u32       = 1 << 2;   // Store Bad Packets
const RCTL_UPE: u32       = 1 << 3;   // Unicast Promiscuous Enable
const RCTL_MPE: u32       = 1 << 4;   // Multicast Promiscuous Enable
const RCTL_LPE: u32       = 1 << 5;   // Long Packet Enable
const RCTL_BAM: u32       = 1 << 15;  // Broadcast Accept Mode
const RCTL_BSIZE_2048: u32 = 0 << 16; // Buffer size = 2048 bytes
const RCTL_BSIZE_1024: u32 = 1 << 16; // Buffer size = 1024 bytes
const RCTL_SECRC: u32     = 1 << 26;  // Strip Ethernet CRC

// ── TCTL register bits ──

const TCTL_EN: u32        = 1 << 1;   // Transmitter Enable
const TCTL_PSP: u32       = 1 << 3;   // Pad Short Packets
const TCTL_CT_SHIFT: u32  = 4;        // Collision Threshold shift
const TCTL_CT_VAL: u32    = 15 << 4;  // Collision Threshold = 15
const TCTL_COLD_SHIFT: u32 = 12;      // Collision Distance shift
const TCTL_COLD_FD: u32   = 0x3F << 12; // Collision Distance = 63 (full duplex)
const TCTL_MULR: u32      = 1 << 28;  // Multiple Request Support

// ── RXDCTL / TXDCTL register bits ──

const RXDCTL_ENABLE: u32  = 1 << 25;  // Queue Enable
const TXDCTL_ENABLE: u32  = 1 << 25;  // Queue Enable

// ── RAH register bits ──

const RAH_AV: u32         = 1 << 31;  // Address Valid

// ── SRRCTL register bits ──

const SRRCTL_BSIZEPACKET_SHIFT: u32 = 0;
const SRRCTL_DESCTYPE_ADV_ONE_BUF: u32 = 1 << 25; // Advanced descriptor, one buffer

// ── PHY register addresses (MII standard + extended) ──

const PHY_ADDR: u32       = 0;        // Default PHY address on I225/I226
const PHY_BMCR: u32       = 0x00;     // Basic Mode Control Register
const PHY_BMSR: u32       = 0x01;     // Basic Mode Status Register
const PHY_ANAR: u32       = 0x04;     // Auto-Negotiation Advertisement
const PHY_ANLPAR: u32     = 0x05;     // Auto-Negotiation Link Partner Ability
const PHY_GBCR: u32       = 0x09;     // 1000BASE-T Control Register

// BMCR bits
const BMCR_RESET: u16     = 1 << 15;  // PHY software reset
const BMCR_SPEED_1000: u16 = 1 << 6;  // Speed Select MSB = 1000 Mbps
const BMCR_AUTONEG_EN: u16 = 1 << 12; // Auto-Negotiation Enable
const BMCR_RESTART_AN: u16 = 1 << 9;  // Restart Auto-Negotiation
const BMCR_FULL_DUPLEX: u16 = 1 << 8; // Full Duplex Mode

// ANAR bits (Auto-Negotiation Advertisement)
const ANAR_SELECTOR: u16  = 0x0001;   // IEEE 802.3 selector
const ANAR_10_HD: u16     = 1 << 5;   // 10BASE-T Half Duplex
const ANAR_10_FD: u16     = 1 << 6;   // 10BASE-T Full Duplex
const ANAR_100_HD: u16    = 1 << 7;   // 100BASE-TX Half Duplex
const ANAR_100_FD: u16    = 1 << 8;   // 100BASE-TX Full Duplex
const ANAR_PAUSE: u16     = 1 << 10;  // Pause capability
const ANAR_ASYM_PAUSE: u16 = 1 << 11; // Asymmetric Pause

// GBCR bits (1000BASE-T Control)
const GBCR_1000_HD: u16   = 1 << 8;   // Advertise 1000BASE-T Half Duplex
const GBCR_1000_FD: u16   = 1 << 9;   // Advertise 1000BASE-T Full Duplex

// I225/I226 supports 2.5GBASE-T via Multi-GBT AN Control Register (MGBANAR)
// PHY register 0x07, MMD device address 7, register 0x20
// For simplicity, we use auto-negotiation which includes 2.5G when supported.

// ── TX/RX descriptor formats ──

const DESC_RING_SIZE: usize = 256;    // Number of descriptors per ring
const RX_DESC_SIZE: usize   = 16;     // Bytes per advanced RX descriptor
const TX_DESC_SIZE: usize   = 16;     // Bytes per advanced TX descriptor
const TX_BUF_SIZE: usize    = 2048;   // TX buffer size per descriptor
const RX_BUF_SIZE: usize    = 2048;   // RX buffer size per descriptor

/// Advanced Receive Descriptor (read format: 16 bytes)
///
/// Read format (given to hardware):
///   addr: physical address of receive buffer
///   hdr_addr: header buffer address (unused, set to 0)
///
/// Write-back format (after receive completion):
///   status_error (lower 32 bits of info): bit 0 = DD, bit 1 = EOP
///   length (bits 47:32 of info): packet length
///   vlan (bits 63:48 of info): VLAN tag
#[repr(C)]
#[derive(Clone, Copy)]
struct IgcRxDesc {
    addr: u64,      // Buffer physical address / RSS hash (write-back)
    info: u64,      // Header address (read) / status+length+vlan (write-back)
}

const _: () = assert!(core::mem::size_of::<IgcRxDesc>() == RX_DESC_SIZE);

// RX descriptor write-back status bits (in lower 32 bits of info)
const RXD_STAT_DD: u32    = 1 << 0;   // Descriptor Done
const RXD_STAT_EOP: u32   = 1 << 1;   // End of Packet

/// Advanced Transmit Descriptor (16 bytes)
///
/// addr: physical address of data buffer
/// cmd_type_len: DTYP (bits 23:20), DCMD (bits 31:24), data length (bits 15:0)
/// olinfo_status: DD bit for completion, payload length (bits 13:0 << 14 shift)
#[repr(C)]
#[derive(Clone, Copy)]
struct IgcTxDesc {
    addr: u64,
    cmd_type_len: u32,
    olinfo_status: u32,
}

const _: () = assert!(core::mem::size_of::<IgcTxDesc>() == TX_DESC_SIZE);

// TX descriptor command/type bits
const TXD_DTYP_ADV: u32   = 0x00300000; // Advanced data descriptor type
const TXD_DCMD_EOP: u32   = 1 << 24;    // End of Packet
const TXD_DCMD_IFCS: u32  = 1 << 25;    // Insert FCS (CRC)
const TXD_DCMD_RS: u32    = 1 << 27;    // Report Status (set DD on completion)
const TXD_DCMD_DEXT: u32  = 1 << 29;    // Descriptor Extension (advanced format)

// TX write-back status bits
const TXD_STAT_DD: u32    = 1 << 0;     // Descriptor Done

// ── PCI vendor/device IDs ──

const INTEL_VENDOR_ID: u16 = 0x8086;

const IGC_DEVICE_IDS: &[u16] = &[
    0x15F3,     // I225-V
    0x125C,     // I226-V
    0x15F2,     // I225-LM
    0x125B,     // I226-LM
];

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

struct Igc {
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
    tx_ring: *mut IgcTxDesc,
    tx_ring_phys: u64,
    tx_bufs: *mut u8,
    tx_bufs_phys: u64,
    tx_tail: usize,            // Next descriptor to fill

    // RX descriptor ring
    rx_ring: *mut IgcRxDesc,
    rx_ring_phys: u64,
    rx_bufs: *mut u8,
    rx_bufs_phys: u64,
    rx_cur: usize,             // Next descriptor to check

    // Interface pointer for fut_net_rx_packet callback
    iface: *mut c_void,
}

unsafe impl Send for Igc {}
unsafe impl Sync for Igc {}

static NIC: StaticCell<Option<Igc>> = StaticCell::new(None);

// ── MMIO helpers ──

fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    unsafe { read_volatile(base.add(offset) as *const u32) }
}

fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    unsafe { write_volatile(base.add(offset) as *mut u32, val) }
}

// ── Physical address helper ──

fn virt_to_phys(ptr: *const u8) -> u64 {
    unsafe { rust_virt_to_phys(ptr as *const c_void) }
}

// ── EEPROM read ──

/// Read a 16-bit word from the EEPROM at the given address via EERD.
/// Returns the 16-bit value, or 0xFFFF on timeout.
fn eeprom_read(mmio: *mut u8, addr: u8) -> u16 {
    // Write address and start bit
    mmio_write32(mmio, IGC_EERD, ((addr as u32) << EERD_ADDR_SHIFT) | EERD_START);

    // Poll for completion
    for _ in 0..10_000u32 {
        let val = mmio_read32(mmio, IGC_EERD);
        if val & EERD_DONE != 0 {
            return ((val >> EERD_DATA_SHIFT) & 0xFFFF) as u16;
        }
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }
    0xFFFF // Timeout
}

// ── PHY register access via MDIC ──

/// Read a PHY register via the MDIC indirect access register.
/// Returns the 16-bit register value, or 0xFFFF on timeout/error.
fn phy_read(mmio: *mut u8, reg: u32) -> u16 {
    let mdic = ((reg & 0x1F) << MDIC_REG_SHIFT)
        | ((PHY_ADDR & 0x1F) << MDIC_PHY_SHIFT)
        | MDIC_OP_READ;
    mmio_write32(mmio, IGC_MDIC, mdic);

    // Poll for completion
    for _ in 0..5000u32 {
        let val = mmio_read32(mmio, IGC_MDIC);
        if val & MDIC_ERROR != 0 {
            return 0xFFFF;
        }
        if val & MDIC_READY != 0 {
            return (val & MDIC_DATA_MASK) as u16;
        }
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }
    0xFFFF // Timeout
}

/// Write a PHY register via the MDIC indirect access register.
fn phy_write(mmio: *mut u8, reg: u32, val: u16) {
    let mdic = (val as u32 & MDIC_DATA_MASK)
        | ((reg & 0x1F) << MDIC_REG_SHIFT)
        | ((PHY_ADDR & 0x1F) << MDIC_PHY_SHIFT)
        | MDIC_OP_WRITE;
    mmio_write32(mmio, IGC_MDIC, mdic);

    // Poll for completion
    for _ in 0..5000u32 {
        let v = mmio_read32(mmio, IGC_MDIC);
        if v & (MDIC_READY | MDIC_ERROR) != 0 {
            return;
        }
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }
}

// ── PCI discovery ──

/// Scan PCI bus for a supported Intel I225/I226 controller.
/// Returns (bus, dev, func, device_id, irq) or None.
fn find_igc_pci() -> Option<(u8, u8, u8, u16, u8)> {
    let count = unsafe { pci_device_count() };
    for i in 0..count {
        let dev = unsafe { &*pci_get_device(i) };
        if dev.vendor_id == INTEL_VENDOR_ID {
            for &did in IGC_DEVICE_IDS {
                if dev.device_id == did {
                    return Some((dev.bus, dev.dev, dev.func, dev.device_id, dev.irq_line));
                }
            }
        }
    }
    None
}

// ── Device reset ──

/// Perform a device reset via CTRL.RST and wait for completion.
/// The hardware clears the RST bit when the reset is complete.
fn device_reset(mmio: *mut u8) -> bool {
    // Disable interrupts first
    mmio_write32(mmio, IGC_IMC, 0xFFFFFFFF);

    // Issue device reset
    let ctrl = mmio_read32(mmio, IGC_CTRL);
    mmio_write32(mmio, IGC_CTRL, ctrl | CTRL_RST);

    // Small delay for reset to propagate
    for _ in 0..1000u32 {
        core::hint::spin_loop();
    }

    // Wait for reset to complete (RST bit should self-clear)
    for _ in 0..100_000u32 {
        let val = mmio_read32(mmio, IGC_CTRL);
        if val & CTRL_RST == 0 {
            // Post-reset delay to let hardware stabilize
            for _ in 0..10_000u32 {
                core::hint::spin_loop();
            }
            // Disable interrupts again after reset
            mmio_write32(mmio, IGC_IMC, 0xFFFFFFFF);
            // Clear any pending interrupt causes
            let _ = mmio_read32(mmio, IGC_ICR);
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

// ── MAC address reading ──

/// Read the MAC address from the EEPROM via EERD.
/// Falls back to RAL0/RAH0 if EEPROM read fails.
fn read_mac_address(mmio: *mut u8) -> [u8; 6] {
    // Try EEPROM first (words 0, 1, 2 contain the MAC address)
    let word0 = eeprom_read(mmio, 0);
    let word1 = eeprom_read(mmio, 1);
    let word2 = eeprom_read(mmio, 2);

    if word0 != 0xFFFF && word1 != 0xFFFF && word2 != 0xFFFF {
        let mac = [
            (word0 & 0xFF) as u8,
            ((word0 >> 8) & 0xFF) as u8,
            (word1 & 0xFF) as u8,
            ((word1 >> 8) & 0xFF) as u8,
            (word2 & 0xFF) as u8,
            ((word2 >> 8) & 0xFF) as u8,
        ];
        // Validate: not all zeros and not all FFs
        let all_zero = mac.iter().all(|&b| b == 0x00);
        let all_ff = mac.iter().all(|&b| b == 0xFF);
        if !all_zero && !all_ff {
            return mac;
        }
    }

    // Fallback: read from RAL0/RAH0 (programmed by firmware/BIOS)
    let ral = mmio_read32(mmio, IGC_RAL0);
    let rah = mmio_read32(mmio, IGC_RAH0);

    [
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ]
}

// ── PHY configuration ──

/// Configure the PHY for auto-negotiation at all supported speeds
/// including 2.5G/1G/100M/10M.
fn configure_phy(mmio: *mut u8) {
    // Reset PHY first
    phy_write(mmio, PHY_BMCR, BMCR_RESET);
    for _ in 0..100_000u32 {
        let val = phy_read(mmio, PHY_BMCR);
        if val & BMCR_RESET == 0 {
            break;
        }
        for _ in 0..100u32 {
            core::hint::spin_loop();
        }
    }

    // Advertise 10/100 Mbps capabilities
    let anar = ANAR_SELECTOR | ANAR_10_HD | ANAR_10_FD
        | ANAR_100_HD | ANAR_100_FD | ANAR_PAUSE | ANAR_ASYM_PAUSE;
    phy_write(mmio, PHY_ANAR, anar);

    // Advertise 1000 Mbps capabilities
    let gbcr = GBCR_1000_FD | GBCR_1000_HD;
    phy_write(mmio, PHY_GBCR, gbcr);

    // The I225/I226 PHY supports 2.5GBASE-T auto-negotiation natively;
    // it is advertised by default when the PHY capabilities include it.
    // No additional register writes are needed for 2.5G advertisement
    // on these controllers as the firmware enables it during init.

    // Enable auto-negotiation and restart
    let bmcr = BMCR_AUTONEG_EN | BMCR_RESTART_AN;
    phy_write(mmio, PHY_BMCR, bmcr);
}

// ── Descriptor ring initialization ──

/// Allocate and initialize the TX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_tx_ring() -> Option<(*mut IgcTxDesc, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut IgcTxDesc };
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

    // Zero all descriptors (DD bit clear = driver owns)
    for i in 0..DESC_RING_SIZE {
        let desc = IgcTxDesc {
            addr: 0,
            cmd_type_len: 0,
            olinfo_status: 0,
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

/// Allocate and initialize the RX descriptor ring and buffers.
/// Returns (ring_virt, ring_phys, bufs_virt, bufs_phys) or None on failure.
fn init_rx_ring() -> Option<(*mut IgcRxDesc, u64, *mut u8, u64)> {
    // Allocate descriptor ring: 256 * 16 = 4096 bytes = 1 page
    let ring = unsafe { alloc_page() as *mut IgcRxDesc };
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

    // Initialize descriptors: set buffer addresses, clear status
    for i in 0..DESC_RING_SIZE {
        let buf_phys = bufs_phys + (i * RX_BUF_SIZE) as u64;
        let desc = IgcRxDesc {
            addr: buf_phys,
            info: 0, // Header buffer address = 0 (not used)
        };
        unsafe { write_volatile(ring.add(i), desc); }
    }

    Some((ring, ring_phys, bufs, bufs_phys))
}

// ── FFI exports ──

/// Initialize the Intel I225-V/I226-V 2.5GbE Ethernet controller.
///
/// Scans PCI for supported Intel igc devices, maps MMIO registers,
/// performs a device reset, reads the MAC address, configures the PHY
/// for auto-negotiation, sets up TX/RX descriptor rings, and enables
/// the transmitter and receiver in polling mode.
///
/// Returns 0 on success, negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn igc_init() -> i32 {
    log("igc: scanning PCI for Intel I225/I226 Ethernet controllers...");

    let (bus, dev, func, device_id, irq) = match find_igc_pci() {
        Some(info) => info,
        None => {
            log("igc: no supported Intel I225/I226 controller found");
            return -1;
        }
    };

    unsafe {
        fut_printf(
            b"igc: found device %04x:%04x at PCI %02x:%02x.%x IRQ %d\n\0".as_ptr(),
            INTEL_VENDOR_ID as u32, device_id as u32,
            bus as u32, dev as u32, func as u32, irq as u32,
        );
    }

    // Enable bus mastering and memory space access in PCI command register
    let pci_cmd = pci_read16(bus, dev, func, 0x04);
    pci_write16(bus, dev, func, 0x04, pci_cmd | 0x06); // Memory Space + Bus Master

    // Read BAR0 for MMIO (Intel igc uses BAR0)
    let bar0_lo = pci_read32(bus, dev, func, 0x10);

    if bar0_lo & 0x01 != 0 {
        log("igc: BAR0 is I/O space, expected MMIO");
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
        log("igc: BAR0 not configured");
        return -3;
    }

    unsafe {
        fut_printf(
            b"igc: MMIO BAR0 at physical 0x%llx\n\0".as_ptr(),
            bar_phys,
        );
    }

    // Map MMIO region (I225/I226 register space is up to 128 KiB)
    let mmio_size: usize = 0x20000; // 128 KiB
    let mmio = unsafe { map_mmio_region(bar_phys, mmio_size, MMIO_DEFAULT_FLAGS) };
    if mmio.is_null() {
        log("igc: failed to map MMIO region");
        return -4;
    }

    // Perform device reset
    if !device_reset(mmio) {
        log("igc: device reset timeout");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -5;
    }
    log("igc: device reset complete");

    // Disable all interrupts (polling mode)
    mmio_write32(mmio, IGC_IMC, 0xFFFFFFFF);

    // Read MAC address
    let mac = read_mac_address(mmio);

    unsafe {
        fut_printf(
            b"igc: MAC address %02x:%02x:%02x:%02x:%02x:%02x\n\0".as_ptr(),
            mac[0] as u32, mac[1] as u32, mac[2] as u32,
            mac[3] as u32, mac[4] as u32, mac[5] as u32,
        );
    }

    // Validate MAC address
    let all_zero = mac.iter().all(|&b| b == 0x00);
    let all_ff = mac.iter().all(|&b| b == 0xFF);
    if all_zero || all_ff {
        log("igc: invalid MAC address read from hardware");
        unsafe { unmap_mmio_region(mmio, mmio_size); }
        return -6;
    }

    // Program the MAC address into RAL0/RAH0
    let ral = (mac[0] as u32)
        | ((mac[1] as u32) << 8)
        | ((mac[2] as u32) << 16)
        | ((mac[3] as u32) << 24);
    let rah = (mac[4] as u32) | ((mac[5] as u32) << 8) | RAH_AV;
    mmio_write32(mmio, IGC_RAL0, ral);
    mmio_write32(mmio, IGC_RAH0, rah);

    // Clear multicast table array (128 entries)
    for i in 0..128 {
        mmio_write32(mmio, IGC_MTA_BASE + i * 4, 0);
    }

    // Set up TX descriptor ring
    let (tx_ring, tx_ring_phys, tx_bufs, tx_bufs_phys) = match init_tx_ring() {
        Some(v) => v,
        None => {
            log("igc: failed to allocate TX descriptor ring");
            unsafe { unmap_mmio_region(mmio, mmio_size); }
            return -7;
        }
    };

    // Set up RX descriptor ring
    let (rx_ring, rx_ring_phys, rx_bufs, rx_bufs_phys) = match init_rx_ring() {
        Some(v) => v,
        None => {
            log("igc: failed to allocate RX descriptor ring");
            unsafe {
                free(tx_bufs);
                unmap_mmio_region(mmio, mmio_size);
            }
            return -8;
        }
    };

    // ── Configure transmit path ──

    // Disable TX queue before programming
    mmio_write32(mmio, IGC_TXDCTL0, 0);

    // Program TX descriptor ring base and length
    mmio_write32(mmio, IGC_TDBAL0, tx_ring_phys as u32);
    mmio_write32(mmio, IGC_TDBAH0, (tx_ring_phys >> 32) as u32);
    mmio_write32(mmio, IGC_TDLEN0, (DESC_RING_SIZE * TX_DESC_SIZE) as u32);

    // Set head and tail to 0
    mmio_write32(mmio, IGC_TDH0, 0);
    mmio_write32(mmio, IGC_TDT0, 0);

    // Enable TX queue
    let mut txdctl = mmio_read32(mmio, IGC_TXDCTL0);
    txdctl |= TXDCTL_ENABLE;
    mmio_write32(mmio, IGC_TXDCTL0, txdctl);

    // Wait for TX queue enable
    for _ in 0..10_000u32 {
        if mmio_read32(mmio, IGC_TXDCTL0) & TXDCTL_ENABLE != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // Configure TCTL: enable transmitter, pad short packets, set thresholds
    let tctl = TCTL_EN | TCTL_PSP | TCTL_CT_VAL | TCTL_COLD_FD | TCTL_MULR;
    mmio_write32(mmio, IGC_TCTL, tctl);

    // ── Configure receive path ──

    // Disable RX queue before programming
    mmio_write32(mmio, IGC_RXDCTL0, 0);

    // Configure SRRCTL: buffer size in KiB units, advanced descriptor type
    let srrctl = ((RX_BUF_SIZE / 1024) as u32) << SRRCTL_BSIZEPACKET_SHIFT
        | SRRCTL_DESCTYPE_ADV_ONE_BUF;
    mmio_write32(mmio, IGC_SRRCTL0, srrctl);

    // Program RX descriptor ring base and length
    mmio_write32(mmio, IGC_RDBAL0, rx_ring_phys as u32);
    mmio_write32(mmio, IGC_RDBAH0, (rx_ring_phys >> 32) as u32);
    mmio_write32(mmio, IGC_RDLEN0, (DESC_RING_SIZE * RX_DESC_SIZE) as u32);

    // Set head to 0, tail to N-1 (all descriptors available to HW)
    mmio_write32(mmio, IGC_RDH0, 0);
    mmio_write32(mmio, IGC_RDT0, (DESC_RING_SIZE - 1) as u32);

    // Enable RX queue
    let mut rxdctl = mmio_read32(mmio, IGC_RXDCTL0);
    rxdctl |= RXDCTL_ENABLE;
    mmio_write32(mmio, IGC_RXDCTL0, rxdctl);

    // Wait for RX queue enable
    for _ in 0..10_000u32 {
        if mmio_read32(mmio, IGC_RXDCTL0) & RXDCTL_ENABLE != 0 {
            break;
        }
        core::hint::spin_loop();
    }

    // Configure RCTL: enable receiver, accept broadcast, 2 KiB buffers, strip CRC
    let rctl = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC;
    mmio_write32(mmio, IGC_RCTL, rctl);

    // ── Configure PHY and link ──

    configure_phy(mmio);

    // Set link up in device control
    let ctrl = mmio_read32(mmio, IGC_CTRL);
    mmio_write32(mmio, IGC_CTRL, ctrl | CTRL_SLU);

    fence(Ordering::SeqCst);

    // Check initial link status
    let status = mmio_read32(mmio, IGC_STATUS);
    if status & STATUS_LU != 0 {
        let speed_str = match status & STATUS_SPEED_MASK {
            STATUS_SPEED_2500 => "2500",
            STATUS_SPEED_1000 => "1000",
            STATUS_SPEED_100 => "100",
            _ => "10",
        };
        let duplex_str = if status & STATUS_FD != 0 { "full" } else { "half" };
        let mut buf = [0u8; 80];
        let prefix = b"igc: link up at ";
        buf[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        for &b in speed_str.as_bytes() {
            buf[pos] = b;
            pos += 1;
        }
        let mid = b" Mbps ";
        buf[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        for &b in duplex_str.as_bytes() {
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
        log("igc: link down (auto-negotiation in progress)");
    }

    // Store controller state
    let nic = Igc {
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

    log("igc: driver initialized successfully");
    0
}

/// Transmit a packet.
///
/// Copies `len` bytes from `data` into the next available TX descriptor
/// buffer, sets up the advanced TX descriptor with EOP/IFCS/RS flags,
/// and advances the tail pointer to notify the hardware.
///
/// Returns 0 on success, -1 if no TX descriptors available,
/// -2 if the packet exceeds the buffer size, -3 if not initialized.
#[unsafe(no_mangle)]
pub extern "C" fn igc_send(data: *const u8, len: u32) -> i32 {
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

    // Check if the previous descriptor at this index has completed
    let desc = unsafe { read_volatile(nic.tx_ring.add(idx)) };
    if desc.cmd_type_len != 0 && desc.olinfo_status & TXD_STAT_DD == 0 {
        return -1; // TX ring full, descriptor not yet done
    }

    // Copy packet data into the TX buffer
    let buf_offset = idx * TX_BUF_SIZE;
    let buf_ptr = unsafe { nic.tx_bufs.add(buf_offset) };
    unsafe {
        core::ptr::copy_nonoverlapping(data, buf_ptr, len as usize);
    }

    // Set up advanced TX descriptor
    let buf_phys = nic.tx_bufs_phys + buf_offset as u64;
    let cmd_type_len = (len as u32)
        | TXD_DTYP_ADV
        | TXD_DCMD_EOP
        | TXD_DCMD_IFCS
        | TXD_DCMD_RS
        | TXD_DCMD_DEXT;

    // Payload length in olinfo_status (bits 31:14)
    let olinfo_status = (len as u32) << 14;

    let new_desc = IgcTxDesc {
        addr: buf_phys,
        cmd_type_len,
        olinfo_status,
    };

    fence(Ordering::SeqCst);
    unsafe { write_volatile(nic.tx_ring.add(idx), new_desc); }
    fence(Ordering::SeqCst);

    // Advance TX tail and notify hardware
    nic.tx_tail = (idx + 1) % DESC_RING_SIZE;
    mmio_write32(nic.mmio, IGC_TDT0, nic.tx_tail as u32);

    0
}

/// Poll for received packets.
///
/// Checks the RX descriptor ring for completed descriptors (DD bit set),
/// calls `fut_net_rx_packet` for each received frame, then re-arms the
/// descriptor for the hardware.
///
/// Returns the number of packets processed (0 if none available).
#[unsafe(no_mangle)]
pub extern "C" fn igc_poll() -> i32 {
    let nic = match unsafe { &mut *NIC.get() } {
        Some(n) => n,
        None => return -1, // Not initialized
    };

    let mut count: i32 = 0;

    loop {
        let idx = nic.rx_cur;
        let desc = unsafe { read_volatile(nic.rx_ring.add(idx)) };

        // Check DD (Descriptor Done) in the write-back status field
        let status = desc.info as u32;
        if status & RXD_STAT_DD == 0 {
            break; // No more completed descriptors
        }

        // Extract packet length from write-back info (bits 47:32)
        let pkt_len = ((desc.info >> 32) & 0xFFFF) as u32;

        // Only deliver complete packets (EOP set) with valid length
        let is_eop = status & RXD_STAT_EOP != 0;

        if is_eop && pkt_len > 0 && pkt_len <= RX_BUF_SIZE as u32 {
            let buf_offset = idx * RX_BUF_SIZE;
            let buf_ptr = unsafe { nic.rx_bufs.add(buf_offset) };

            // Deliver packet to network stack
            unsafe {
                fut_net_rx_packet(nic.iface, buf_ptr, pkt_len);
            }
            count += 1;
        }

        // Re-arm the descriptor: set buffer address, clear info
        let buf_phys = nic.rx_bufs_phys + (idx * RX_BUF_SIZE) as u64;
        let new_desc = IgcRxDesc {
            addr: buf_phys,
            info: 0,
        };

        fence(Ordering::SeqCst);
        unsafe { write_volatile(nic.rx_ring.add(idx), new_desc); }

        // Advance to next descriptor
        nic.rx_cur = (idx + 1) % DESC_RING_SIZE;

        // Update RX tail to return the descriptor to hardware
        mmio_write32(nic.mmio, IGC_RDT0, idx as u32);
    }

    count
}

/// Copy the 6-byte MAC address to the provided buffer.
///
/// `out` must point to a buffer of at least 6 bytes.
#[unsafe(no_mangle)]
pub extern "C" fn igc_get_mac(out: *mut u8) {
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
///   bits 3:1: speed: 001=10M, 010=100M, 100=1000M, 101=2500M
///   bit 4:    1 = full-duplex, 0 = half-duplex
#[unsafe(no_mangle)]
pub extern "C" fn igc_link_status() -> u32 {
    let nic = match unsafe { &*NIC.get() } {
        Some(n) => n,
        None => return 0,
    };

    let status = mmio_read32(nic.mmio, IGC_STATUS);

    if status & STATUS_LU == 0 {
        return 0; // Link down
    }

    let mut result: u32 = 1; // Bit 0: link up

    // Speed bits
    match status & STATUS_SPEED_MASK {
        STATUS_SPEED_2500 => result |= 0x0A, // bits 3:1 = 101
        STATUS_SPEED_1000 => result |= 0x08,  // bits 3:1 = 100
        STATUS_SPEED_100 => result |= 0x04,   // bits 3:1 = 010
        _ => result |= 0x02,                  // bits 3:1 = 001 (10 Mbps)
    }

    // Duplex bit
    if status & STATUS_FD != 0 {
        result |= 0x10; // bit 4
    }

    result
}

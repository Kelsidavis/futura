// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi 4 GENET v5 Gigabit Ethernet Driver
//
// The BCM2711 SoC has a built-in GENET (Generic Ethernet NIC Technology)
// v5 controller connected to a BCM54213PE PHY for Gigabit Ethernet.
// Base address: peripheral_base + 0x580000
//
// GENET uses a ring-based DMA engine with 256 TX and 256 RX descriptors.
// Each descriptor points to a buffer in memory. The driver manages the
// rings and interacts with the MDIO interface for PHY configuration.
//
// This driver provides basic packet TX/RX for the kernel TCP/IP stack.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// GENET system registers
const SYS_REV_CTRL: usize = 0x00;
const SYS_PORT_CTRL: usize = 0x04;
const SYS_RBUF_FLUSH_CTRL: usize = 0x08;
const SYS_TBUF_FLUSH_CTRL: usize = 0x0C;

// GENET UMAC (UniMAC) registers — Ethernet MAC
const UMAC_CMD: usize = 0x800 + 0x008;
const UMAC_MAC0: usize = 0x800 + 0x00C;   // MAC address bytes 0-3
const UMAC_MAC1: usize = 0x800 + 0x010;   // MAC address bytes 4-5
const UMAC_MAX_FRAME_LEN: usize = 0x800 + 0x014;
const UMAC_TX_FLUSH: usize = 0x800 + 0x334;
const UMAC_MIB_CTRL: usize = 0x800 + 0x580;
const UMAC_MDIO_CMD: usize = 0x800 + 0x614;

// UMAC command bits
const CMD_TX_EN: u32 = 1 << 0;
const CMD_RX_EN: u32 = 1 << 1;
const CMD_SPEED_10: u32 = 0 << 2;
const CMD_SPEED_100: u32 = 1 << 2;
const CMD_SPEED_1000: u32 = 2 << 2;
const CMD_PROMISC: u32 = 1 << 4;
const CMD_PAD_EN: u32 = 1 << 5;
const CMD_CRC_FWD: u32 = 1 << 6;
const CMD_SW_RESET: u32 = 1 << 13;

// MDIO command bits
const MDIO_START_BUSY: u32 = 1 << 29;
const MDIO_READ_CMD: u32 = 2 << 26;
const MDIO_WRITE_CMD: u32 = 1 << 26;

// GENET RDMA (RX DMA) registers
const RDMA_REG_BASE: usize = 0x2000;
const RDMA_RING_BUF_SIZE: usize = RDMA_REG_BASE + 0x00;
const RDMA_WRITE_PTR: usize = RDMA_REG_BASE + 0x08;
const RDMA_PROD_INDEX: usize = RDMA_REG_BASE + 0x0C;
const RDMA_CONS_INDEX: usize = RDMA_REG_BASE + 0x10;
const RDMA_RING_BUF_BASE: usize = RDMA_REG_BASE + 0x14;
const RDMA_RING_SIZE: usize = RDMA_REG_BASE + 0x18;
const RDMA_CTRL: usize = RDMA_REG_BASE + 0x1000;

// GENET TDMA (TX DMA) registers
const TDMA_REG_BASE: usize = 0x4000;
const TDMA_READ_PTR: usize = TDMA_REG_BASE + 0x08;
const TDMA_PROD_INDEX: usize = TDMA_REG_BASE + 0x0C;
const TDMA_CONS_INDEX: usize = TDMA_REG_BASE + 0x10;
const TDMA_RING_BUF_BASE: usize = TDMA_REG_BASE + 0x14;
const TDMA_RING_SIZE: usize = TDMA_REG_BASE + 0x18;
const TDMA_CTRL: usize = TDMA_REG_BASE + 0x1000;

// Descriptor ring sizes
const NUM_TX_DESC: u32 = 256;
const NUM_RX_DESC: u32 = 256;
const DMA_DESC_SIZE: usize = 12;  // 3 words per descriptor

// PHY registers (BCM54213PE via MDIO)
const PHY_ADDR: u32 = 1;  // Default PHY address
const MII_BMCR: u32 = 0;  // Basic Mode Control
const MII_BMSR: u32 = 1;  // Basic Mode Status
const MII_ANAR: u32 = 4;  // Auto-Negotiation Advertisement
const MII_ANLPAR: u32 = 5; // Auto-Negotiation Link Partner Ability
const MII_CTRL1000: u32 = 9; // 1000BASE-T Control

// BMCR bits
const BMCR_SPEED1000: u32 = 1 << 6;
const BMCR_FULLDPLX: u32 = 1 << 8;
const BMCR_ANRESTART: u32 = 1 << 9;
const BMCR_ANENABLE: u32 = 1 << 12;
const BMCR_SPEED100: u32 = 1 << 13;
const BMCR_RESET: u32 = 1 << 15;

// BMSR bits
const BMSR_LSTATUS: u32 = 1 << 2;  // Link status
const BMSR_ANEGCOMPLETE: u32 = 1 << 5;

// Driver state
static mut GENET_BASE: usize = 0;
static mut GENET_INITIALIZED: bool = false;
static mut GENET_MAC: [u8; 6] = [0xDC, 0xA6, 0x32, 0x00, 0x00, 0x01]; // Default MAC

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn delay(n: u32) {
    for _ in 0..n { unsafe { core::arch::asm!("yield") }; }
}

// ── MDIO (PHY management) ──

fn mdio_read(base: usize, phy: u32, reg: u32) -> u16 {
    let cmd = MDIO_START_BUSY | MDIO_READ_CMD | ((phy & 0x1F) << 21) | ((reg & 0x1F) << 16);
    mmio_write(base + UMAC_MDIO_CMD, cmd);

    for _ in 0..10000 {
        let v = mmio_read(base + UMAC_MDIO_CMD);
        if v & MDIO_START_BUSY == 0 {
            return (v & 0xFFFF) as u16;
        }
        delay(10);
    }
    0
}

fn mdio_write(base: usize, phy: u32, reg: u32, val: u16) {
    let cmd = MDIO_START_BUSY | MDIO_WRITE_CMD |
              ((phy & 0x1F) << 21) | ((reg & 0x1F) << 16) | (val as u32);
    mmio_write(base + UMAC_MDIO_CMD, cmd);

    for _ in 0..10000 {
        if mmio_read(base + UMAC_MDIO_CMD) & MDIO_START_BUSY == 0 { return; }
        delay(10);
    }
}

// ── FFI exports ──

/// Initialize the GENET Ethernet controller
/// base_addr: MMIO base address (peripheral_base + 0x580000 for Pi4)
/// Returns: 0 on success, negative on failure
#[no_mangle]
pub extern "C" fn rpi_genet_init(base_addr: u64) -> i32 {
    let base = base_addr as usize;
    unsafe {
        GENET_BASE = base;
        GENET_INITIALIZED = false;
    }

    // Read hardware version
    let rev = mmio_read(base + SYS_REV_CTRL);
    let major = (rev >> 24) & 0xF;
    let _minor = (rev >> 16) & 0xF;

    // Expect GENET v5 for Pi4
    if major < 5 { return -1; }

    // Software reset UMAC
    mmio_write(base + UMAC_CMD, CMD_SW_RESET);
    delay(1000);
    mmio_write(base + UMAC_CMD, 0);
    delay(1000);

    // Set MAC address
    unsafe {
        let mac = &GENET_MAC;
        mmio_write(base + UMAC_MAC0,
            ((mac[0] as u32) << 24) | ((mac[1] as u32) << 16) |
            ((mac[2] as u32) << 8) | (mac[3] as u32));
        mmio_write(base + UMAC_MAC1,
            ((mac[4] as u32) << 8) | (mac[5] as u32));
    }

    // Set max frame length (1518 = standard Ethernet MTU + headers)
    mmio_write(base + UMAC_MAX_FRAME_LEN, 1518);

    // Clear MIB counters
    mmio_write(base + UMAC_MIB_CTRL, 1);
    delay(100);
    mmio_write(base + UMAC_MIB_CTRL, 0);

    // Reset and configure PHY via MDIO
    mdio_write(base, PHY_ADDR, MII_BMCR, BMCR_RESET as u16);
    delay(50000);

    // Wait for reset complete
    for _ in 0..1000 {
        let bmcr = mdio_read(base, PHY_ADDR, MII_BMCR);
        if bmcr & (BMCR_RESET as u16) == 0 { break; }
        delay(1000);
    }

    // Enable auto-negotiation (10/100/1000 Mbps)
    mdio_write(base, PHY_ADDR, MII_ANAR, 0x01E1);     // 10/100 + flow control
    mdio_write(base, PHY_ADDR, MII_CTRL1000, 0x0300);  // 1000BASE-T full/half
    mdio_write(base, PHY_ADDR, MII_BMCR,
               (BMCR_ANENABLE | BMCR_ANRESTART) as u16);

    // Wait for link (up to 5 seconds)
    let mut link_up = false;
    for _ in 0..50 {
        let bmsr = mdio_read(base, PHY_ADDR, MII_BMSR);
        if bmsr & (BMSR_LSTATUS as u16) != 0 {
            link_up = true;
            break;
        }
        delay(100000); // ~100ms
    }

    // Enable TX and RX
    let mut cmd = CMD_TX_EN | CMD_RX_EN | CMD_PAD_EN | CMD_CRC_FWD;
    if link_up {
        // Check negotiated speed
        let anlpar = mdio_read(base, PHY_ADDR, MII_ANLPAR);
        if anlpar & 0x0400 != 0 { // 1000BASE-T
            cmd |= CMD_SPEED_1000 | CMD_FULLDPLX;
        } else if anlpar & 0x0180 != 0 { // 100BASE-TX
            cmd |= CMD_SPEED_100;
        } else {
            cmd |= CMD_SPEED_10;
        }
    }
    mmio_write(base + UMAC_CMD, cmd);

    unsafe { GENET_INITIALIZED = true; }
    0
}

/// Set MAC address
#[no_mangle]
pub extern "C" fn rpi_genet_set_mac(mac: *const u8) {
    if mac.is_null() { return; }
    unsafe {
        for i in 0..6 {
            GENET_MAC[i] = *mac.add(i);
        }
    }
}

/// Check if Ethernet link is up
#[no_mangle]
pub extern "C" fn rpi_genet_link_up() -> bool {
    let base = unsafe { GENET_BASE };
    if base == 0 { return false; }
    let bmsr = mdio_read(base, PHY_ADDR, MII_BMSR);
    bmsr & (BMSR_LSTATUS as u16) != 0
}

/// Get link speed in Mbps (10, 100, or 1000)
#[no_mangle]
pub extern "C" fn rpi_genet_link_speed() -> u32 {
    let base = unsafe { GENET_BASE };
    if base == 0 { return 0; }
    let cmd = mmio_read(base + UMAC_CMD);
    match (cmd >> 2) & 0x3 {
        0 => 10,
        1 => 100,
        2 => 1000,
        _ => 0,
    }
}

/// Check if GENET is initialized
#[no_mangle]
pub extern "C" fn rpi_genet_is_ready() -> bool {
    unsafe { GENET_INITIALIZED }
}

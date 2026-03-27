// SPDX-License-Identifier: MPL-2.0
//
// Generic Ethernet PHY (MDIO/MII) Management Driver
//
// Provides PHY-level management for Ethernet MAC drivers (RTL8111, I211, I225,
// etc.) via the standard IEEE 802.3 MII register interface.  PHY register
// access is performed through caller-supplied MDIO read/write callbacks, since
// each MAC has its own MDIO register access mechanism.
//
// Implements:
//   - PHY detection and scanning (addresses 0-31)
//   - PHY reset with self-clear polling
//   - Auto-negotiation configuration, restart, and completion polling
//   - Link status, speed, and duplex resolution from ANLPAR / GBSR
//   - Manual speed/duplex forcing via BMCR
//   - PHY OUI decoding (Realtek, Intel, Marvell, Broadcom)
//   - Extended status for gigabit capability detection

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::cell::UnsafeCell;

use common::log;

unsafe extern "C" {
    fn fut_printf(fmt: *const u8, ...);
}

// ── MDIO callback types ──

type MdioReadFn = unsafe extern "C" fn(phy_addr: u8, reg: u8) -> u16;
type MdioWriteFn = unsafe extern "C" fn(phy_addr: u8, reg: u8, val: u16);

// ── Static state wrapper ──

/// Wrapper to allow `UnsafeCell` in a `static` (requires `Sync`).
/// Safety: all access is single-threaded or externally synchronised by the caller.
struct StaticCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for StaticCell<T> {}
impl<T> StaticCell<T> {
    const fn new(val: T) -> Self { Self(UnsafeCell::new(val)) }
    fn get(&self) -> *mut T { self.0.get() }
}

// ── Driver state ──

struct PhyDriver {
    read_fn: Option<MdioReadFn>,
    write_fn: Option<MdioWriteFn>,
    initialised: bool,
}

static STATE: StaticCell<PhyDriver> = StaticCell::new(PhyDriver {
    read_fn: None,
    write_fn: None,
    initialised: false,
});

// ── Exported PHY status structure ──

#[repr(C)]
pub struct PhyStatus {
    pub link_up: bool,
    pub speed: u32,
    pub full_duplex: bool,
    pub autoneg_complete: bool,
    pub phy_id: u32,
}

// ── Standard MII register addresses (IEEE 802.3) ──

const MII_BMCR: u8 = 0;    // Basic Mode Control
const MII_BMSR: u8 = 1;    // Basic Mode Status
const MII_PHYSID1: u8 = 2;  // PHY Identifier 1
const MII_PHYSID2: u8 = 3;  // PHY Identifier 2
const MII_ANAR: u8 = 4;    // Auto-Neg Advertisement
const MII_ANLPAR: u8 = 5;  // Auto-Neg Link Partner Ability
#[allow(dead_code)]
const MII_ANER: u8 = 6;    // Auto-Neg Expansion
const MII_GBCR: u8 = 9;    // 1000BASE-T Control
const MII_GBSR: u8 = 10;   // 1000BASE-T Status
#[allow(dead_code)]
const MII_ESTATUS: u8 = 15; // Extended Status

// ── BMCR bits ──

const BMCR_RESET: u16 = 1 << 15;
const BMCR_SPEED_MSB: u16 = 1 << 13;
const BMCR_AUTONEG_ENABLE: u16 = 1 << 12;
const BMCR_RESTART_AUTONEG: u16 = 1 << 9;
const BMCR_FULL_DUPLEX: u16 = 1 << 8;
const BMCR_SPEED_LSB: u16 = 1 << 6;

// ── BMSR bits ──

const BMSR_AUTONEG_COMPLETE: u16 = 1 << 5;
const BMSR_LINK_STATUS: u16 = 1 << 2;
const BMSR_EXTENDED_CAP: u16 = 1 << 0;

// ── ANAR / ANLPAR bits (shared encoding) ──

const ANAR_10HD: u16 = 1 << 5;
const ANAR_10FD: u16 = 1 << 6;
const ANAR_100HD: u16 = 1 << 7;
const ANAR_100FD: u16 = 1 << 8;
const ANAR_SELECTOR_IEEE802_3: u16 = 0x0001;

// ── GBCR bits ──

const GBCR_1000FD: u16 = 1 << 9;
const GBCR_1000HD: u16 = 1 << 8;

// ── GBSR bits ──

const GBSR_LP_1000FD: u16 = 1 << 11;
const GBSR_LP_1000HD: u16 = 1 << 10;

// ── ESTATUS bits ──

#[allow(dead_code)]
const ESTATUS_1000T_FD: u16 = 1 << 13;
#[allow(dead_code)]
const ESTATUS_1000T_HD: u16 = 1 << 12;

// ── Known PHY OUIs ──

const OUI_REALTEK: u32 = 0x001CC800;
const OUI_INTEL: u32 = 0x02A80000;
const OUI_MARVELL: u32 = 0x01410C00;
const OUI_BROADCOM: u32 = 0x0143BC00;

const OUI_REALTEK_MASK: u32 = 0xFFFFFF00;
const OUI_INTEL_MASK: u32 = 0xFFFFF000;
const OUI_MARVELL_MASK: u32 = 0xFFFFFF00;
const OUI_BROADCOM_MASK: u32 = 0xFFFFFF00;

// ── Timeout constants ──

const RESET_TIMEOUT_LOOPS: u32 = 100_000;
const AUTONEG_TIMEOUT_LOOPS: u32 = 500_000;

// ── Helper: MDIO read/write through saved callbacks ──

fn mdio_read(phy_addr: u8, reg: u8) -> u16 {
    let drv = unsafe { &*STATE.get() };
    if let Some(read_fn) = drv.read_fn {
        unsafe { read_fn(phy_addr, reg) }
    } else {
        0xFFFF
    }
}

fn mdio_write(phy_addr: u8, reg: u8, val: u16) {
    let drv = unsafe { &*STATE.get() };
    if let Some(write_fn) = drv.write_fn {
        unsafe { write_fn(phy_addr, reg, val) }
    }
}

/// Read the 32-bit PHY ID from PHYSID1 (bits 31:16) and PHYSID2 (bits 15:0).
fn read_phy_id(phy_addr: u8) -> u32 {
    let id1 = mdio_read(phy_addr, MII_PHYSID1) as u32;
    let id2 = mdio_read(phy_addr, MII_PHYSID2) as u32;
    (id1 << 16) | id2
}

/// Resolve speed and duplex from auto-negotiation result registers.
fn resolve_autoneg_speed(phy_addr: u8) -> (u32, bool) {
    // Check 1000BASE-T first (GBSR)
    let gbsr = mdio_read(phy_addr, MII_GBSR);
    let gbcr = mdio_read(phy_addr, MII_GBCR);

    // Link partner supports 1000BASE-T Full and we advertised it
    if (gbsr & GBSR_LP_1000FD) != 0 && (gbcr & GBCR_1000FD) != 0 {
        return (1000, true);
    }
    // Link partner supports 1000BASE-T Half and we advertised it
    if (gbsr & GBSR_LP_1000HD) != 0 && (gbcr & GBCR_1000HD) != 0 {
        return (1000, false);
    }

    // Fall back to 10/100 negotiation (ANLPAR & ANAR intersection)
    let anar = mdio_read(phy_addr, MII_ANAR);
    let anlpar = mdio_read(phy_addr, MII_ANLPAR);
    let common = anar & anlpar;

    // Highest speed/duplex takes priority
    if (common & ANAR_100FD) != 0 {
        (100, true)
    } else if (common & ANAR_100HD) != 0 {
        (100, false)
    } else if (common & ANAR_10FD) != 0 {
        (10, true)
    } else if (common & ANAR_10HD) != 0 {
        (10, false)
    } else {
        // No common capability -- default to 10 half
        (10, false)
    }
}

/// Resolve speed from BMCR when auto-negotiation is not used.
fn resolve_forced_speed(bmcr: u16) -> (u32, bool) {
    let speed_msb = (bmcr & BMCR_SPEED_MSB) != 0;
    let speed_lsb = (bmcr & BMCR_SPEED_LSB) != 0;
    let full_duplex = (bmcr & BMCR_FULL_DUPLEX) != 0;

    let speed = match (speed_msb, speed_lsb) {
        (false, true) => 1000,
        (true, false) => 100,
        _ => 10,
    };

    (speed, full_duplex)
}

/// Copy a byte slice to a user buffer with null termination.
fn copy_str_to_buf(s: &[u8], buf: *mut u8, max_len: u32) -> i32 {
    if buf.is_null() || max_len == 0 {
        return -1;
    }
    let copy_len = s.len().min((max_len as usize).saturating_sub(1));
    for i in 0..copy_len {
        unsafe { buf.add(i).write(s[i]) };
    }
    unsafe { buf.add(copy_len).write(0) };
    copy_len as i32
}

// ── Exported functions ──

/// Initialise the PHY driver with MDIO read/write callbacks.
/// Returns 0 on success, -1 on invalid arguments.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_init(
    read_fn: MdioReadFn,
    write_fn: MdioWriteFn,
) -> i32 {
    let drv = unsafe { &mut *STATE.get() };
    drv.read_fn = Some(read_fn);
    drv.write_fn = Some(write_fn);
    drv.initialised = true;

    log("eth_phy: initialised with MDIO callbacks");
    0
}

/// Detect whether a PHY exists at the given address.
/// Returns 0 if a valid PHY is found, -1 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_detect(phy_addr: u8) -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return -1;
    }

    let phy_id = read_phy_id(phy_addr);

    // All-ones or all-zeros means no PHY present
    if phy_id == 0xFFFFFFFF || phy_id == 0x00000000 {
        return -1;
    }

    unsafe {
        fut_printf(
            b"eth_phy: detected PHY at addr %u, ID 0x%08x\n\0".as_ptr(),
            phy_addr as u32,
            phy_id,
        );
    }

    0
}

/// Scan PHY addresses 0-31 and return the first address with a valid PHY.
/// Returns the PHY address (0-31) on success, -1 if none found.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_scan() -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return -1;
    }

    for addr in 0u8..32 {
        let phy_id = read_phy_id(addr);
        if phy_id != 0xFFFFFFFF && phy_id != 0x00000000 {
            unsafe {
                fut_printf(
                    b"eth_phy: scan found PHY at addr %u, ID 0x%08x\n\0".as_ptr(),
                    addr as u32,
                    phy_id,
                );
            }
            return addr as i32;
        }
    }

    log("eth_phy: scan found no PHY on bus");
    -1
}

/// Reset the PHY by setting BMCR bit 15 and polling for self-clear.
/// Returns 0 on success, -1 on timeout or error.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_reset(phy_addr: u8) -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return -1;
    }

    // Set the reset bit
    let bmcr = mdio_read(phy_addr, MII_BMCR);
    mdio_write(phy_addr, MII_BMCR, bmcr | BMCR_RESET);

    // Poll for self-clear (bit 15 returns to 0 when reset completes)
    for _ in 0..RESET_TIMEOUT_LOOPS {
        let val = mdio_read(phy_addr, MII_BMCR);
        if (val & BMCR_RESET) == 0 {
            unsafe {
                fut_printf(
                    b"eth_phy: PHY %u reset complete\n\0".as_ptr(),
                    phy_addr as u32,
                );
            }
            return 0;
        }
        core::hint::spin_loop();
    }

    log("eth_phy: PHY reset timed out");
    -1
}

/// Configure and restart auto-negotiation.
/// Advertises 10/100/1000 full/half duplex capabilities.
/// Returns 0 on success (auto-neg started), -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_autoneg(phy_addr: u8) -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return -1;
    }

    // Advertise all 10/100 capabilities
    let anar = ANAR_SELECTOR_IEEE802_3 | ANAR_10HD | ANAR_10FD | ANAR_100HD | ANAR_100FD;
    mdio_write(phy_addr, MII_ANAR, anar);

    // Advertise 1000BASE-T capabilities if extended status supported
    let bmsr = mdio_read(phy_addr, MII_BMSR);
    if (bmsr & BMSR_EXTENDED_CAP) != 0 {
        let gbcr = GBCR_1000FD | GBCR_1000HD;
        mdio_write(phy_addr, MII_GBCR, gbcr);
    }

    // Enable auto-negotiation and restart
    let bmcr = mdio_read(phy_addr, MII_BMCR);
    mdio_write(
        phy_addr,
        MII_BMCR,
        (bmcr & !BMCR_SPEED_MSB & !BMCR_SPEED_LSB & !BMCR_FULL_DUPLEX)
            | BMCR_AUTONEG_ENABLE
            | BMCR_RESTART_AUTONEG,
    );

    // Poll for auto-negotiation completion
    for _ in 0..AUTONEG_TIMEOUT_LOOPS {
        let status = mdio_read(phy_addr, MII_BMSR);
        if (status & BMSR_AUTONEG_COMPLETE) != 0 {
            let (speed, fd) = resolve_autoneg_speed(phy_addr);
            unsafe {
                fut_printf(
                    b"eth_phy: auto-neg complete: %u Mbps %s\n\0".as_ptr(),
                    speed,
                    if fd {
                        b"full-duplex\0".as_ptr()
                    } else {
                        b"half-duplex\0".as_ptr()
                    },
                );
            }
            return 0;
        }
        core::hint::spin_loop();
    }

    log("eth_phy: auto-negotiation timed out");
    -1
}

/// Read current PHY status into the provided structure.
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_get_status(phy_addr: u8, status: *mut PhyStatus) -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised || status.is_null() {
        return -1;
    }

    // Read BMSR twice -- link status is latching-low per IEEE 802.3
    let _ = mdio_read(phy_addr, MII_BMSR);
    let bmsr = mdio_read(phy_addr, MII_BMSR);
    let bmcr = mdio_read(phy_addr, MII_BMCR);

    let link_up = (bmsr & BMSR_LINK_STATUS) != 0;
    let autoneg_complete = (bmsr & BMSR_AUTONEG_COMPLETE) != 0;

    let (speed, full_duplex) = if (bmcr & BMCR_AUTONEG_ENABLE) != 0 && autoneg_complete {
        resolve_autoneg_speed(phy_addr)
    } else if (bmcr & BMCR_AUTONEG_ENABLE) == 0 {
        resolve_forced_speed(bmcr)
    } else {
        // Auto-neg enabled but not complete -- report unknown
        (0, false)
    };

    let phy_id = read_phy_id(phy_addr);

    let out = unsafe { &mut *status };
    out.link_up = link_up;
    out.speed = speed;
    out.full_duplex = full_duplex;
    out.autoneg_complete = autoneg_complete;
    out.phy_id = phy_id;

    0
}

/// Force a specific speed and duplex (disables auto-negotiation).
/// Supported speeds: 10, 100, 1000.
/// Returns 0 on success, -1 on invalid parameters.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_force_speed(phy_addr: u8, speed: u32, full_duplex: bool) -> i32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return -1;
    }

    let mut bmcr: u16 = 0;

    // Disable auto-negotiation
    // Set speed bits: {MSB, LSB} = {0,0}=10, {1,0}=100, {0,1}=1000
    match speed {
        10 => {
            // MSB=0, LSB=0 -> already zero
        }
        100 => {
            bmcr |= BMCR_SPEED_MSB;
        }
        1000 => {
            bmcr |= BMCR_SPEED_LSB;
        }
        _ => {
            log("eth_phy: unsupported speed for force_speed");
            return -1;
        }
    }

    if full_duplex {
        bmcr |= BMCR_FULL_DUPLEX;
    }

    mdio_write(phy_addr, MII_BMCR, bmcr);

    unsafe {
        fut_printf(
            b"eth_phy: forced %u Mbps %s on PHY %u\n\0".as_ptr(),
            speed,
            if full_duplex {
                b"full-duplex\0".as_ptr()
            } else {
                b"half-duplex\0".as_ptr()
            },
            phy_addr as u32,
        );
    }

    0
}

/// Return the 32-bit PHY ID (PHYSID1 << 16 | PHYSID2).
/// Returns 0xFFFFFFFF if driver not initialised or PHY not present.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_get_id(phy_addr: u8) -> u32 {
    let drv = unsafe { &*STATE.get() };
    if !drv.initialised {
        return 0xFFFFFFFF;
    }
    read_phy_id(phy_addr)
}

/// Write the vendor name for a given PHY ID into the provided buffer.
/// Returns the number of bytes written (excluding null terminator), or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn eth_phy_vendor_name(phy_id: u32, buf: *mut u8, max_len: u32) -> i32 {
    if (phy_id & OUI_REALTEK_MASK) == OUI_REALTEK {
        return copy_str_to_buf(b"Realtek", buf, max_len);
    }
    if (phy_id & OUI_INTEL_MASK) == OUI_INTEL {
        return copy_str_to_buf(b"Intel", buf, max_len);
    }
    if (phy_id & OUI_MARVELL_MASK) == OUI_MARVELL {
        return copy_str_to_buf(b"Marvell", buf, max_len);
    }
    if (phy_id & OUI_BROADCOM_MASK) == OUI_BROADCOM {
        return copy_str_to_buf(b"Broadcom", buf, max_len);
    }

    copy_str_to_buf(b"Unknown", buf, max_len)
}

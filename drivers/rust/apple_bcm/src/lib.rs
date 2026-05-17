// apple_bcm — Apple Silicon Broadcom WiFi+Bluetooth discovery
//
// Copyright (c) 2026 Kelsi Davis
// Licensed under the MPL v2.0 — see LICENSE for details.
//
// Apple Silicon Macs use a Broadcom combo chip for both WiFi (802.11
// ax/n/ac) and Bluetooth (LE + Classic) on the same PCIe device.  The
// chip appears as a multi-function PCIe endpoint behind the Apple PCIe
// root complex:
//
//   function 0 → WiFi    (class 0x028000, "Network controller / Other")
//   function 1 → Bluetooth (class 0xFE0000 or vendor-specific)
//
// Across the M1/M2/M3/M4 generations the device IDs change but the
// vendor (0x14e4 Broadcom) and PCIe layout stay the same:
//
//   BCM4377  → device 0x4425 (rev A0, pre-M1 reference)
//   BCM4377B → device 0x4425 (rev B0)
//   BCM4378  → device 0x4433 / 0x4434 (M1 family)
//   BCM4387  → device 0x4433 / 0x4438 (M2/M3 family)
//   BCM4388  → device 0x4434 (M4 family — provisional)
//
// This crate is intentionally bring-up-stage.  It only:
//   1. Classifies a (vendor, device) pair into a known chip.
//   2. Provides a `ChipInfo` record callers can log + persist.
//   3. Exposes the chip's expected firmware base name so a future
//      slice can wire up firmware loading.
//
// Real bring-up (PCIe MSI setup, BAR mapping, NVRAM parse, firmware
// upload via the M2M DMA path, HCI bridge for Bluetooth, brcmfmac-
// style command channel) lives in follow-up work and stays out of
// this crate until the discovery side is proven on real hardware.

#![no_std]
#![allow(clippy::missing_safety_doc)]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("wfe") };
    }
}

pub const BCM_VENDOR_ID: u16 = 0x14e4;

/// Known Broadcom WiFi+BT combo chips Apple Silicon ships.  The
/// `firmware_base` field is the prefix Asahi Linux uses for the
/// per-chip firmware blob set (e.g. `brcmfmac4378b1-pcie.apple,*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcmChip {
    Bcm4377,
    Bcm4378,
    Bcm4387,
    Bcm4388,
    Unknown,
}

impl BcmChip {
    /// Chip family name as a NUL-terminated byte slice so it can be
    /// passed back through the FFI as `*const u8` and treated as a
    /// C string.  Rust `&str` would not have the trailing NUL.
    pub const fn name(self) -> &'static [u8] {
        match self {
            BcmChip::Bcm4377 => b"BCM4377\0",
            BcmChip::Bcm4378 => b"BCM4378\0",
            BcmChip::Bcm4387 => b"BCM4387\0",
            BcmChip::Bcm4388 => b"BCM4388\0",
            BcmChip::Unknown => b"unknown-bcm\0",
        }
    }

    /// Firmware blob base name as used by Asahi Linux (without the
    /// `.bin`/`.txt`/`.clm_blob` extensions).  Returned in C-string
    /// form so the C side can pass it to a future loader.
    pub const fn firmware_base(self) -> &'static [u8] {
        match self {
            BcmChip::Bcm4377 => b"brcmfmac4377-pcie.apple\0",
            BcmChip::Bcm4378 => b"brcmfmac4378-pcie.apple\0",
            BcmChip::Bcm4387 => b"brcmfmac4387-pcie.apple\0",
            BcmChip::Bcm4388 => b"brcmfmac4388-pcie.apple\0",
            BcmChip::Unknown => b"unknown\0",
        }
    }

    /// Bluetooth firmware base name (HCI patchram).  Apple ships
    /// these as `*.dat` plus a per-machine `*.ptb` patchram blob.
    pub const fn bt_firmware_base(self) -> &'static [u8] {
        match self {
            BcmChip::Bcm4377 => b"BCM4377B3\0",
            BcmChip::Bcm4378 => b"BCM4378B1\0",
            BcmChip::Bcm4387 => b"BCM4387C2\0",
            BcmChip::Bcm4388 => b"BCM4388A0\0",
            BcmChip::Unknown => b"unknown\0",
        }
    }
}

/// Resolve a (vendor, device) PCI ID to a known chip.  Anything that
/// isn't a Broadcom WiFi/BT combo we recognise becomes
/// `BcmChip::Unknown`; the caller still gets to log it.
pub fn classify(vendor: u16, device: u16) -> BcmChip {
    if vendor != BCM_VENDOR_ID {
        return BcmChip::Unknown;
    }
    match device {
        0x4425 => BcmChip::Bcm4377,
        0x4433 => BcmChip::Bcm4378,
        0x4434 => BcmChip::Bcm4378,
        0x4438 => BcmChip::Bcm4387,
        0x4490 => BcmChip::Bcm4388,
        _      => BcmChip::Unknown,
    }
}

/// Snapshot of a discovered chip — populated by the C side after a
/// PCIe walk and handed back so subsequent slices (firmware load,
/// brcmfmac IPC, HCI transport) can pick up from a known state.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BcmDiscovery {
    pub chip:        u32, /* BcmChip discriminant, see chip_from_u32 */
    pub vendor:      u16,
    pub device:      u16,
    pub revision:    u8,
    pub bus:         u8,
    pub function:    u8,
    pub _pad:        u8,
    pub bar0:        u64,
    pub bar2:        u64,
    pub class_code:  u32, /* 24-bit class:subclass:progif */
}

const fn chip_to_u32(c: BcmChip) -> u32 {
    match c {
        BcmChip::Bcm4377 => 1,
        BcmChip::Bcm4378 => 2,
        BcmChip::Bcm4387 => 3,
        BcmChip::Bcm4388 => 4,
        BcmChip::Unknown => 0,
    }
}

const fn chip_from_u32(v: u32) -> BcmChip {
    match v {
        1 => BcmChip::Bcm4377,
        2 => BcmChip::Bcm4378,
        3 => BcmChip::Bcm4387,
        4 => BcmChip::Bcm4388,
        _ => BcmChip::Unknown,
    }
}

/* ============================================================
 *   FFI exports
 * ============================================================ */

/// Classify a (vendor, device) pair, returning the encoded chip id
/// (see `BcmChip` for the mapping).  Non-Broadcom IDs return 0.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_bcm_classify(vendor: u16, device: u16) -> u32 {
    chip_to_u32(classify(vendor, device))
}

/// Pointer to a NUL-terminated string with the human-readable chip
/// name ("BCM4378", "BCM4387", …).  The lifetime is `'static`.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_bcm_chip_name(chip_id: u32) -> *const u8 {
    chip_from_u32(chip_id).name().as_ptr()
}

/// Pointer to a NUL-terminated firmware base name for the WiFi side.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_bcm_wifi_fw_base(chip_id: u32) -> *const u8 {
    chip_from_u32(chip_id).firmware_base().as_ptr()
}

/// Pointer to a NUL-terminated firmware base name for the Bluetooth
/// HCI patchram.
#[unsafe(no_mangle)]
pub extern "C" fn rust_apple_bcm_bt_fw_base(chip_id: u32) -> *const u8 {
    chip_from_u32(chip_id).bt_firmware_base().as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_chips() {
        assert_eq!(classify(0x14e4, 0x4425), BcmChip::Bcm4377);
        assert_eq!(classify(0x14e4, 0x4433), BcmChip::Bcm4378);
        assert_eq!(classify(0x14e4, 0x4434), BcmChip::Bcm4378);
        assert_eq!(classify(0x14e4, 0x4438), BcmChip::Bcm4387);
    }

    #[test]
    fn classify_wrong_vendor() {
        assert_eq!(classify(0x10ec, 0x4378), BcmChip::Unknown);
    }
}

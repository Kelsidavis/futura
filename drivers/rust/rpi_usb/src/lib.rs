// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi 4/5 USB Host Controller Driver (xHCI)
//
// Pi4 (BCM2711): USB 3.0 via PCIe-attached VL805 xHCI controller
//   - 4 USB ports (2x USB 3.0 + 2x USB 2.0)
//   - VL805 firmware loaded by VideoCore at boot
//   - xHCI base after PCIe init: 0x600000000
//
// Pi5 (BCM2712): USB 3.0 via RP1 south bridge xHCI
//   - 2x USB 3.0 + 2x USB 2.0 ports
//   - RP1 at PCIe BAR 0x1F00000000
//
// This driver implements basic xHCI initialization and device detection.
// Full USB enumeration (descriptors, HID, mass storage) requires
// the USB stack in kernel/usb/ (future work).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// xHCI Capability Registers (offset 0x00)
const CAPLENGTH: usize = 0x00;      // Capability length (1 byte)
const HCIVERSION: usize = 0x02;     // Interface version (2 bytes)
const HCSPARAMS1: usize = 0x04;     // Structural params 1
const HCSPARAMS2: usize = 0x08;     // Structural params 2
const HCSPARAMS3: usize = 0x0C;     // Structural params 3
const HCCPARAMS1: usize = 0x10;     // Capability params 1
const DBOFF: usize = 0x14;          // Doorbell offset
const RTSOFF: usize = 0x18;         // Runtime register space offset

// xHCI Operational Registers (offset = CAPLENGTH)
const USBCMD: usize = 0x00;         // USB Command
const USBSTS: usize = 0x04;         // USB Status
const PAGESIZE: usize = 0x08;       // Page Size
const DNCTRL: usize = 0x14;         // Device Notification Control
const CRCR: usize = 0x18;           // Command Ring Control
const DCBAAP: usize = 0x30;         // Device Context Base Address Array Pointer
const CONFIG: usize = 0x38;         // Configure

// xHCI Port Register Set (offset per port)
const PORTSC: usize = 0x00;         // Port Status and Control
const PORTPMSC: usize = 0x04;       // Port Power Management Status and Control
const PORTLI: usize = 0x08;         // Port Link Info
const PORTHLPMC: usize = 0x0C;      // Port Hardware LPM Control

// USBCMD bits
const CMD_RUN: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;      // Host Controller Reset
const CMD_INTE: u32 = 1 << 2;       // Interrupter Enable
const CMD_HSEE: u32 = 1 << 3;       // Host System Error Enable

// USBSTS bits
const STS_HCH: u32 = 1 << 0;       // HC Halted
const STS_HSE: u32 = 1 << 2;       // Host System Error
const STS_CNR: u32 = 1 << 11;      // Controller Not Ready

// PORTSC bits
const PORT_CCS: u32 = 1 << 0;      // Current Connect Status
const PORT_PED: u32 = 1 << 1;      // Port Enabled/Disabled
const PORT_PR: u32 = 1 << 4;       // Port Reset
const PORT_PLS_MASK: u32 = 0xF << 5; // Port Link State
const PORT_PP: u32 = 1 << 9;       // Port Power
const PORT_SPEED_MASK: u32 = 0xF << 10; // Port Speed
const PORT_CSC: u32 = 1 << 17;     // Connect Status Change
const PORT_WRC: u32 = 1 << 19;     // Warm Port Reset Change

// Port speeds
const SPEED_FULL: u32 = 1;  // USB 1.1 (12 Mbps)
const SPEED_LOW: u32 = 2;   // USB 1.0 (1.5 Mbps)
const SPEED_HIGH: u32 = 3;  // USB 2.0 (480 Mbps)
const SPEED_SUPER: u32 = 4; // USB 3.0 (5 Gbps)

// Driver state
static mut XHCI_BASE: usize = 0;
static mut XHCI_OP_BASE: usize = 0;
static mut XHCI_PORT_BASE: usize = 0;
static mut XHCI_NUM_PORTS: u32 = 0;
static mut XHCI_INITIALIZED: bool = false;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

fn delay(n: u32) {
    for _ in 0..n { unsafe { core::arch::asm!("yield") }; }
}

// ── FFI exports ──

/// Initialize the xHCI USB host controller
/// base_addr: MMIO base of xHCI registers
/// Returns: number of ports detected, or negative on failure
#[no_mangle]
pub extern "C" fn rpi_usb_init(base_addr: u64) -> i32 {
    let base = base_addr as usize;
    unsafe {
        XHCI_BASE = base;
        XHCI_INITIALIZED = false;
    }

    // Read capability length to find operational registers
    let caplength = (mmio_read(base + CAPLENGTH) & 0xFF) as usize;
    let hciversion = (mmio_read(base + HCIVERSION) >> 16) & 0xFFFF;
    let op_base = base + caplength;

    // Verify xHCI version (should be >= 1.0 = 0x0100)
    if hciversion < 0x0100 { return -1; }

    // Get number of ports from HCSPARAMS1
    let hcs1 = mmio_read(base + HCSPARAMS1);
    let max_ports = (hcs1 >> 24) & 0xFF;
    let max_slots = hcs1 & 0xFF;

    unsafe {
        XHCI_OP_BASE = op_base;
        XHCI_PORT_BASE = op_base + 0x400; // Port register sets start at op_base + 0x400
        XHCI_NUM_PORTS = max_ports;
    }

    // Stop the controller if running
    let cmd = mmio_read(op_base + USBCMD);
    if cmd & CMD_RUN != 0 {
        mmio_write(op_base + USBCMD, cmd & !CMD_RUN);
        // Wait for halted
        for _ in 0..10000 {
            if mmio_read(op_base + USBSTS) & STS_HCH != 0 { break; }
            delay(100);
        }
    }

    // Reset controller
    mmio_write(op_base + USBCMD, CMD_HCRST);
    for _ in 0..100000 {
        let sts = mmio_read(op_base + USBSTS);
        let cmd = mmio_read(op_base + USBCMD);
        if (sts & STS_CNR) == 0 && (cmd & CMD_HCRST) == 0 { break; }
        delay(100);
    }

    // Configure max device slots
    let slots = if max_slots > 16 { 16 } else { max_slots };
    mmio_write(op_base + CONFIG, slots);

    // Power on all ports
    for port in 0..max_ports {
        let port_reg = unsafe { XHCI_PORT_BASE } + (port as usize * 0x10);
        let portsc = mmio_read(port_reg + PORTSC);
        if portsc & PORT_PP == 0 {
            mmio_write(port_reg + PORTSC, portsc | PORT_PP);
            delay(20000); // 20ms for power stabilization
        }
    }

    unsafe { XHCI_INITIALIZED = true; }
    max_ports as i32
}

/// Get the connection status of a USB port
/// port: port number (0-based)
/// Returns: 1 if device connected, 0 if not, -1 if invalid
#[no_mangle]
pub extern "C" fn rpi_usb_port_connected(port: u32) -> i32 {
    unsafe {
        if !XHCI_INITIALIZED || port >= XHCI_NUM_PORTS { return -1; }
        let port_reg = XHCI_PORT_BASE + (port as usize * 0x10);
        let portsc = mmio_read(port_reg + PORTSC);
        if portsc & PORT_CCS != 0 { 1 } else { 0 }
    }
}

/// Get the speed of a connected USB device
/// Returns: 1=Full(12M), 2=Low(1.5M), 3=High(480M), 4=Super(5G), 0=none
#[no_mangle]
pub extern "C" fn rpi_usb_port_speed(port: u32) -> u32 {
    unsafe {
        if !XHCI_INITIALIZED || port >= XHCI_NUM_PORTS { return 0; }
        let port_reg = XHCI_PORT_BASE + (port as usize * 0x10);
        let portsc = mmio_read(port_reg + PORTSC);
        if portsc & PORT_CCS == 0 { return 0; }
        (portsc & PORT_SPEED_MASK) >> 10
    }
}

/// Get the number of USB ports
#[no_mangle]
pub extern "C" fn rpi_usb_num_ports() -> u32 {
    unsafe { XHCI_NUM_PORTS }
}

/// Check if USB controller is initialized
#[no_mangle]
pub extern "C" fn rpi_usb_is_ready() -> bool {
    unsafe { XHCI_INITIALIZED }
}

/// Get speed name string for a speed value
#[no_mangle]
pub extern "C" fn rpi_usb_speed_name(speed: u32) -> *const u8 {
    match speed {
        1 => b"Full-Speed (12 Mbps)\0".as_ptr(),
        2 => b"Low-Speed (1.5 Mbps)\0".as_ptr(),
        3 => b"High-Speed (480 Mbps)\0".as_ptr(),
        4 => b"SuperSpeed (5 Gbps)\0".as_ptr(),
        5 => b"SuperSpeedPlus (10 Gbps)\0".as_ptr(),
        _ => b"Unknown\0".as_ptr(),
    }
}

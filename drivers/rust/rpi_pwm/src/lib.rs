// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi PWM Controller Driver
//
// BCM2711 PWM: peripheral_base + 0x20C000
// Two independent PWM channels for audio output, fan control,
// LED brightness, and servo motor control.
//
// PWM clock: derived from oscillator (19.2 MHz) or PLLD (500 MHz)
// Each channel has independent range, data, and mode settings.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// PWM register offsets
const PWM_CTL: usize = 0x00;    // Control
const PWM_STA: usize = 0x04;    // Status
const PWM_DMAC: usize = 0x08;   // DMA Configuration
const PWM_RNG1: usize = 0x10;   // Channel 1 Range
const PWM_DAT1: usize = 0x14;   // Channel 1 Data
const PWM_FIF1: usize = 0x18;   // FIFO Input
const PWM_RNG2: usize = 0x20;   // Channel 2 Range
const PWM_DAT2: usize = 0x24;   // Channel 2 Data

// CTL bits
const CTL_PWEN1: u32 = 1 << 0;   // Channel 1 Enable
const CTL_MODE1: u32 = 1 << 1;   // Channel 1 Mode (0=PWM, 1=serialiser)
const CTL_RPTL1: u32 = 1 << 2;   // Channel 1 Repeat Last Data
const CTL_SBIT1: u32 = 1 << 3;   // Channel 1 Silence Bit
const CTL_POLA1: u32 = 1 << 4;   // Channel 1 Polarity
const CTL_USEF1: u32 = 1 << 5;   // Channel 1 Use FIFO
const CTL_MSEN1: u32 = 1 << 7;   // Channel 1 M/S Enable
const CTL_PWEN2: u32 = 1 << 8;   // Channel 2 Enable
const CTL_MODE2: u32 = 1 << 9;
const CTL_MSEN2: u32 = 1 << 15;

// STA bits
const STA_FULL1: u32 = 1 << 0;
const STA_EMPT1: u32 = 1 << 1;
const STA_BERR: u32 = 1 << 8;

// Clock manager registers (for PWM clock)
const CM_PWMCTL: usize = 0xA0;   // Offset from clock manager base
const CM_PWMDIV: usize = 0xA4;
const CM_PASSWORD: u32 = 0x5A000000;

static mut PWM_BASE: usize = 0;
static mut CLK_BASE: usize = 0;

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

/// Initialize PWM controller
/// pwm_base: MMIO base of PWM (peripheral_base + 0x20C000)
/// clk_base: MMIO base of clock manager (peripheral_base + 0x101000)
#[no_mangle]
pub extern "C" fn rpi_pwm_init(pwm_base: u64, clk_base: u64) {
    unsafe {
        PWM_BASE = pwm_base as usize;
        CLK_BASE = clk_base as usize;
    }

    // Disable PWM
    let base = pwm_base as usize;
    mmio_write(base + PWM_CTL, 0);
    delay(100);

    // Set default range (1024 for ~18.75 kHz at 19.2 MHz clock)
    mmio_write(base + PWM_RNG1, 1024);
    mmio_write(base + PWM_RNG2, 1024);

    // Clear status
    mmio_write(base + PWM_STA, 0xFFFFFFFF);
}

/// Set PWM clock divider
/// divider: integer divider (2-4095), higher = slower PWM frequency
#[no_mangle]
pub extern "C" fn rpi_pwm_set_clock(divider: u32) {
    let clk = unsafe { CLK_BASE };
    if clk == 0 { return; }
    let base = unsafe { PWM_BASE };

    // Stop PWM
    mmio_write(base + PWM_CTL, 0);
    delay(100);

    // Stop clock
    mmio_write(clk + CM_PWMCTL, CM_PASSWORD | 0x01); // Kill clock
    delay(100);

    // Wait for not busy
    for _ in 0..1000 {
        if mmio_read(clk + CM_PWMCTL) & (1 << 7) == 0 { break; }
        delay(10);
    }

    // Set divider
    let div = divider.clamp(2, 4095);
    mmio_write(clk + CM_PWMDIV, CM_PASSWORD | (div << 12));

    // Enable clock (source = oscillator = 19.2 MHz)
    mmio_write(clk + CM_PWMCTL, CM_PASSWORD | 0x11); // Enable + OSC source
    delay(100);

    // Wait for busy (clock running)
    for _ in 0..1000 {
        if mmio_read(clk + CM_PWMCTL) & (1 << 7) != 0 { break; }
        delay(10);
    }
}

/// Enable a PWM channel in M/S mode (mark-space)
/// channel: 0 or 1
/// range: PWM period (in clock ticks)
/// duty: duty cycle (0 to range)
#[no_mangle]
pub extern "C" fn rpi_pwm_set_channel(channel: u8, range: u32, duty: u32) {
    let base = unsafe { PWM_BASE };
    if base == 0 { return; }

    let mut ctl = mmio_read(base + PWM_CTL);

    match channel {
        0 => {
            mmio_write(base + PWM_RNG1, range);
            mmio_write(base + PWM_DAT1, duty);
            ctl |= CTL_PWEN1 | CTL_MSEN1;
        }
        1 => {
            mmio_write(base + PWM_RNG2, range);
            mmio_write(base + PWM_DAT2, duty);
            ctl |= CTL_PWEN2 | CTL_MSEN2;
        }
        _ => return,
    }

    mmio_write(base + PWM_CTL, ctl);
}

/// Disable a PWM channel
#[no_mangle]
pub extern "C" fn rpi_pwm_disable_channel(channel: u8) {
    let base = unsafe { PWM_BASE };
    if base == 0 { return; }

    let mut ctl = mmio_read(base + PWM_CTL);
    match channel {
        0 => ctl &= !(CTL_PWEN1 | CTL_MSEN1),
        1 => ctl &= !(CTL_PWEN2 | CTL_MSEN2),
        _ => return,
    }
    mmio_write(base + PWM_CTL, ctl);
}

/// Set fan speed (Pi4 uses PWM for case fan via GPIO18/ALT5)
/// speed_percent: 0-100
#[no_mangle]
pub extern "C" fn rpi_pwm_set_fan_speed(speed_percent: u32) {
    let pct = speed_percent.min(100);
    let range = 1024u32;
    let duty = (range * pct) / 100;
    rpi_pwm_set_channel(0, range, duty);
}

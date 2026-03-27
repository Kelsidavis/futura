// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi Audio Output Driver
//
// Supports two audio output paths on RPi4/5:
//
// 1. PWM audio (3.5mm headphone jack):
//    GPIO40/41 → ALT0 → PWM0/PWM1 → analog output
//    Quality: 11-bit effective, ~48 kHz sample rate
//    Simple but limited dynamic range
//
// 2. HDMI audio (via VideoCore):
//    Uses mailbox VCHIQ interface to VideoCore GPU
//    Quality: 16/24-bit stereo, 44.1/48 kHz
//    Requires HDMI connection
//
// This driver implements PWM-based audio for headphone output.
// HDMI audio requires the VCHIQ protocol (future work).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

use core::ptr::{read_volatile, write_volatile};

// PWM register offsets (same controller as rpi_pwm)
const PWM_CTL: usize = 0x00;
const PWM_STA: usize = 0x04;
const PWM_DMAC: usize = 0x08;
const PWM_RNG1: usize = 0x10;
const PWM_DAT1: usize = 0x14;
const PWM_FIF1: usize = 0x18;
const PWM_RNG2: usize = 0x20;
const PWM_DAT2: usize = 0x24;

// CTL bits for audio mode
const CTL_PWEN1: u32 = 1 << 0;
const CTL_USEF1: u32 = 1 << 5;   // Use FIFO
const CTL_CLRF1: u32 = 1 << 6;   // Clear FIFO
const CTL_MSEN1: u32 = 1 << 7;   // M/S enable
const CTL_PWEN2: u32 = 1 << 8;
const CTL_USEF2: u32 = 1 << 13;
const CTL_MSEN2: u32 = 1 << 15;

// DMAC bits
const DMAC_ENAB: u32 = 1 << 31;
const DMAC_PANIC: u32 = 7 << 8;
const DMAC_DREQ: u32 = 7 << 0;

// STA bits
const STA_STA1: u32 = 1 << 9;    // Channel 1 state
const STA_FULL1: u32 = 1 << 0;   // FIFO full
const STA_EMPT1: u32 = 1 << 1;   // FIFO empty

// Audio state
static mut AUDIO_PWM_BASE: usize = 0;
static mut AUDIO_SAMPLE_RATE: u32 = 44100;
static mut AUDIO_INITIALIZED: bool = false;
static mut AUDIO_PLAYING: bool = false;

fn mmio_read(addr: usize) -> u32 {
    unsafe { read_volatile(addr as *const u32) }
}

fn mmio_write(addr: usize, val: u32) {
    unsafe { write_volatile(addr as *mut u32, val) }
}

// ── FFI exports ──

/// Initialize PWM audio output
/// pwm_base: PWM controller base (peripheral_base + 0x20C000)
/// sample_rate: audio sample rate (44100 or 48000)
#[no_mangle]
pub extern "C" fn rpi_audio_init(pwm_base: u64, sample_rate: u32) -> i32 {
    let base = pwm_base as usize;
    unsafe {
        AUDIO_PWM_BASE = base;
        AUDIO_SAMPLE_RATE = if sample_rate == 0 { 44100 } else { sample_rate };
        AUDIO_INITIALIZED = false;
        AUDIO_PLAYING = false;
    }

    // Disable PWM
    mmio_write(base + PWM_CTL, 0);

    // Clear FIFO
    mmio_write(base + PWM_CTL, CTL_CLRF1);

    // Set range for both channels (determines bit depth)
    // Range = PWM_CLK / sample_rate
    // With 19.2 MHz / 2 = 9.6 MHz PWM clock:
    // Range = 9600000 / 44100 ≈ 217 (~8 bit effective)
    // With higher clock: Range = 19200000 / 44100 ≈ 435 (~9 bit)
    let range = 19_200_000 / unsafe { AUDIO_SAMPLE_RATE };
    mmio_write(base + PWM_RNG1, range);
    mmio_write(base + PWM_RNG2, range);

    // Configure DMA (for future DMA-fed audio)
    mmio_write(base + PWM_DMAC, DMAC_ENAB | DMAC_PANIC | DMAC_DREQ);

    unsafe { AUDIO_INITIALIZED = true; }
    0
}

/// Start audio playback (enables PWM channels in FIFO mode)
#[no_mangle]
pub extern "C" fn rpi_audio_start() {
    let base = unsafe { AUDIO_PWM_BASE };
    if base == 0 { return; }

    // Enable both channels in M/S mode with FIFO
    let ctl = CTL_PWEN1 | CTL_USEF1 | CTL_MSEN1 |
              CTL_PWEN2 | CTL_USEF2 | CTL_MSEN2;
    mmio_write(base + PWM_CTL, ctl);

    unsafe { AUDIO_PLAYING = true; }
}

/// Stop audio playback
#[no_mangle]
pub extern "C" fn rpi_audio_stop() {
    let base = unsafe { AUDIO_PWM_BASE };
    if base == 0 { return; }

    mmio_write(base + PWM_CTL, 0);
    unsafe { AUDIO_PLAYING = false; }
}

/// Write a stereo sample pair to the PWM FIFO
/// left: left channel sample (0 to range)
/// right: right channel sample (0 to range)
/// Returns: 0 if written, -1 if FIFO full
#[no_mangle]
pub extern "C" fn rpi_audio_write_sample(left: u32, right: u32) -> i32 {
    let base = unsafe { AUDIO_PWM_BASE };
    if base == 0 { return -1; }

    let sta = mmio_read(base + PWM_STA);
    if sta & STA_FULL1 != 0 { return -1; } // FIFO full

    // Write left then right to FIFO (interleaved stereo)
    mmio_write(base + PWM_FIF1, left);
    mmio_write(base + PWM_FIF1, right);
    0
}

/// Write a buffer of signed 16-bit PCM samples (interleaved stereo)
/// samples: pointer to int16_t pairs [L, R, L, R, ...]
/// num_samples: number of sample PAIRS (not individual samples)
/// Returns: number of sample pairs actually written
#[no_mangle]
pub extern "C" fn rpi_audio_write_pcm16(samples: *const i16, num_samples: u32) -> u32 {
    if samples.is_null() { return 0; }
    let base = unsafe { AUDIO_PWM_BASE };
    if base == 0 { return 0; }

    let range = mmio_read(base + PWM_RNG1);
    let half = range / 2;
    let mut written = 0u32;

    for i in 0..num_samples {
        let sta = mmio_read(base + PWM_STA);
        if sta & STA_FULL1 != 0 { break; }

        // Convert signed 16-bit PCM to unsigned PWM range
        let left = unsafe { *samples.add((i * 2) as usize) };
        let right = unsafe { *samples.add((i * 2 + 1) as usize) };

        let l_pwm = ((left as i32 + 32768) * range as i32 / 65536) as u32;
        let r_pwm = ((right as i32 + 32768) * range as i32 / 65536) as u32;

        mmio_write(base + PWM_FIF1, l_pwm);
        mmio_write(base + PWM_FIF1, r_pwm);
        written += 1;
    }

    written
}

/// Generate a simple beep tone (for system notifications)
/// freq_hz: tone frequency (e.g., 440 for A4, 1000 for standard beep)
/// duration_ms: duration in milliseconds
#[no_mangle]
pub extern "C" fn rpi_audio_beep(freq_hz: u32, duration_ms: u32) {
    let base = unsafe { AUDIO_PWM_BASE };
    if base == 0 { return; }
    let sample_rate = unsafe { AUDIO_SAMPLE_RATE };
    let range = mmio_read(base + PWM_RNG1);
    let half = range / 2;

    rpi_audio_start();

    let total_samples = (sample_rate * duration_ms) / 1000;
    let period = sample_rate / freq_hz.max(1);

    for i in 0..total_samples {
        // Simple square wave
        let val = if (i % period) < (period / 2) {
            half + half / 4 // 75% duty
        } else {
            half - half / 4 // 25% duty
        };

        // Wait for FIFO space
        for _ in 0..10000 {
            if mmio_read(base + PWM_STA) & STA_FULL1 == 0 { break; }
        }

        mmio_write(base + PWM_FIF1, val); // Left
        mmio_write(base + PWM_FIF1, val); // Right (mono beep)
    }

    rpi_audio_stop();
}

/// Check if audio is initialized
#[no_mangle]
pub extern "C" fn rpi_audio_is_ready() -> bool {
    unsafe { AUDIO_INITIALIZED }
}

/// Check if audio is currently playing
#[no_mangle]
pub extern "C" fn rpi_audio_is_playing() -> bool {
    unsafe { AUDIO_PLAYING }
}

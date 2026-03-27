// SPDX-License-Identifier: MPL-2.0
//
// Raspberry Pi Thermal Monitoring & CPU Frequency Management
//
// Uses the VideoCore mailbox to monitor SoC temperature and manage
// CPU clock frequency for thermal throttling and performance scaling.
//
// Pi4 (BCM2711): Cortex-A72 @ 1.5 GHz (max 1.8 GHz with over_voltage)
//   Throttle at 80°C, shutdown at 85°C
//
// Pi5 (BCM2712): Cortex-A76 @ 2.4 GHz
//   Throttle at 80°C, shutdown at 85°C
//
// Provides /sys/class/thermal/ compatible interface for userspace tools.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

// Clock IDs (mailbox protocol)
const CLOCK_ARM: u32 = 3;
const CLOCK_CORE: u32 = 4;
const CLOCK_V3D: u32 = 5;

// Temperature thresholds (millidegrees C)
const THROTTLE_TEMP: u32 = 80000;  // 80°C — start throttling
const CRITICAL_TEMP: u32 = 85000;  // 85°C — emergency shutdown

// CPU frequency presets (Hz)
const FREQ_MIN: u32 = 600_000_000;    // 600 MHz (low power)
const FREQ_NORMAL: u32 = 1_500_000_000; // 1.5 GHz (Pi4 default)
const FREQ_MAX_PI4: u32 = 1_800_000_000; // 1.8 GHz (Pi4 turbo)
const FREQ_MAX_PI5: u32 = 2_400_000_000; // 2.4 GHz (Pi5 default)

// Thermal governor modes
#[repr(u32)]
#[derive(Clone, Copy, PartialEq)]
pub enum ThermalGovernor {
    Performance = 0,  // Always max frequency
    Powersave = 1,    // Always min frequency
    OnDemand = 2,     // Scale based on load (default)
    Conservative = 3, // Gradual scaling
}

// Driver state
static mut CURRENT_TEMP: u32 = 0;        // millidegrees C
static mut CURRENT_FREQ: u32 = 0;        // Hz
static mut MAX_FREQ: u32 = FREQ_MAX_PI4; // Hz
static mut GOVERNOR: ThermalGovernor = ThermalGovernor::OnDemand;
static mut INITIALIZED: bool = false;

// Mailbox FFI (calls into rpi_mbox Rust crate)
extern "C" {
    fn rpi_mbox_get_temperature() -> u32;
    fn rpi_mbox_get_clock_rate(clock_id: u32) -> u32;
    fn rpi_mbox_set_clock_rate(clock_id: u32, rate: u32) -> u32;
}

// ── FFI exports ──

/// Initialize thermal monitoring
/// is_pi5: true for Pi5 (2.4 GHz max), false for Pi4 (1.8 GHz max)
#[no_mangle]
pub extern "C" fn rpi_thermal_init(is_pi5: bool) -> i32 {
    unsafe {
        MAX_FREQ = if is_pi5 { FREQ_MAX_PI5 } else { FREQ_MAX_PI4 };
        GOVERNOR = ThermalGovernor::OnDemand;

        // Read initial temperature and frequency
        CURRENT_TEMP = rpi_mbox_get_temperature();
        CURRENT_FREQ = rpi_mbox_get_clock_rate(CLOCK_ARM);
        INITIALIZED = true;
    }
    0
}

/// Get current SoC temperature in millidegrees Celsius
#[no_mangle]
pub extern "C" fn rpi_thermal_get_temp() -> u32 {
    unsafe {
        if INITIALIZED {
            CURRENT_TEMP = rpi_mbox_get_temperature();
        }
        CURRENT_TEMP
    }
}

/// Get current SoC temperature in degrees Celsius (integer)
#[no_mangle]
pub extern "C" fn rpi_thermal_get_temp_c() -> u32 {
    rpi_thermal_get_temp() / 1000
}

/// Get current ARM CPU frequency in Hz
#[no_mangle]
pub extern "C" fn rpi_thermal_get_freq() -> u32 {
    unsafe {
        if INITIALIZED {
            CURRENT_FREQ = rpi_mbox_get_clock_rate(CLOCK_ARM);
        }
        CURRENT_FREQ
    }
}

/// Get current ARM CPU frequency in MHz
#[no_mangle]
pub extern "C" fn rpi_thermal_get_freq_mhz() -> u32 {
    rpi_thermal_get_freq() / 1_000_000
}

/// Set ARM CPU frequency (Hz)
/// Clamped to [FREQ_MIN, MAX_FREQ]
#[no_mangle]
pub extern "C" fn rpi_thermal_set_freq(freq_hz: u32) -> u32 {
    let max = unsafe { MAX_FREQ };
    let target = freq_hz.clamp(FREQ_MIN, max);
    unsafe {
        let actual = rpi_mbox_set_clock_rate(CLOCK_ARM, target);
        CURRENT_FREQ = actual;
        actual
    }
}

/// Set thermal governor mode
#[no_mangle]
pub extern "C" fn rpi_thermal_set_governor(gov: u32) {
    unsafe {
        GOVERNOR = match gov {
            0 => ThermalGovernor::Performance,
            1 => ThermalGovernor::Powersave,
            2 => ThermalGovernor::OnDemand,
            3 => ThermalGovernor::Conservative,
            _ => ThermalGovernor::OnDemand,
        };
    }
}

/// Run one thermal management tick (call periodically, e.g., every 1 second)
/// Adjusts CPU frequency based on temperature and governor policy
/// Returns: current temperature in millidegrees
#[no_mangle]
pub extern "C" fn rpi_thermal_tick() -> u32 {
    let temp = rpi_thermal_get_temp();
    let governor = unsafe { GOVERNOR };
    let max = unsafe { MAX_FREQ };

    match governor {
        ThermalGovernor::Performance => {
            // Always max, but respect thermal limits
            if temp >= CRITICAL_TEMP {
                rpi_thermal_set_freq(FREQ_MIN);
            } else if temp >= THROTTLE_TEMP {
                rpi_thermal_set_freq(max / 2);
            } else {
                rpi_thermal_set_freq(max);
            }
        }
        ThermalGovernor::Powersave => {
            rpi_thermal_set_freq(FREQ_MIN);
        }
        ThermalGovernor::OnDemand | ThermalGovernor::Conservative => {
            if temp >= CRITICAL_TEMP {
                rpi_thermal_set_freq(FREQ_MIN);
            } else if temp >= THROTTLE_TEMP {
                // Linear scale down: 80°C→75%, 82.5°C→50%
                let scale = ((CRITICAL_TEMP - temp) * 100) / (CRITICAL_TEMP - THROTTLE_TEMP);
                let freq = FREQ_MIN + ((max - FREQ_MIN) * scale) / 100;
                rpi_thermal_set_freq(freq);
            } else {
                rpi_thermal_set_freq(max);
            }
        }
    }

    temp
}

/// Check if thermal throttling is active
#[no_mangle]
pub extern "C" fn rpi_thermal_is_throttled() -> bool {
    unsafe { CURRENT_TEMP >= THROTTLE_TEMP }
}

/// Get maximum allowed frequency for this platform
#[no_mangle]
pub extern "C" fn rpi_thermal_get_max_freq() -> u32 {
    unsafe { MAX_FREQ }
}

/// Check if driver is initialized
#[no_mangle]
pub extern "C" fn rpi_thermal_is_ready() -> bool {
    unsafe { INITIALIZED }
}

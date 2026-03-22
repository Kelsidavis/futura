/* apple_power.h - Apple Silicon Power Management Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Battery monitoring, thermal sensing, and fan control via Apple SMC.
 */

#ifndef __FUTURA_APPLE_POWER_H__
#define __FUTURA_APPLE_POWER_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

/* Thermal zone identifiers */
#define APPLE_THERMAL_CPU    0
#define APPLE_THERMAL_GPU    1
#define APPLE_THERMAL_AMBIENT 2

/* Power state */
typedef struct {
    /* Battery */
    bool     ac_present;       /* AC adapter connected */
    uint16_t battery_charge;   /* Battery charge remaining (mAh) */
    uint16_t battery_full;     /* Battery full capacity (mAh) */
    uint8_t  battery_pct;      /* Battery percentage (0-100) */

    /* Thermal (millidegrees Celsius) */
    int32_t  cpu_temp_mc;      /* CPU die temperature */
    int32_t  gpu_temp_mc;      /* GPU die temperature */
    int32_t  ambient_temp_mc;  /* Ambient temperature */

    /* Fan */
    uint32_t fan_rpm;          /* Fan 0 actual speed (RPM) */
    uint32_t fan_target_rpm;   /* Fan 0 target speed (RPM) */
    uint32_t fan_count;        /* Number of fans present */
} apple_power_state_t;

/**
 * Initialize power management subsystem.
 * @param info: Platform information with SMC base address
 * @return: 0 on success, negative on failure
 */
int apple_power_init(const fut_platform_info_t *info);

/**
 * Update power state by reading all sensors.
 * @param state: Output power state structure
 * @return: 0 on success
 */
int apple_power_update(apple_power_state_t *state);

/**
 * Get CPU temperature in millidegrees Celsius.
 */
int32_t apple_power_cpu_temp(void);

/**
 * Get GPU temperature in millidegrees Celsius.
 */
int32_t apple_power_gpu_temp(void);

/**
 * Check if AC adapter is present.
 */
bool apple_power_ac_present(void);

/**
 * Get battery charge percentage (0-100).
 */
uint8_t apple_power_battery_pct(void);

/**
 * Set fan target speed in RPM.
 * @param rpm: Target RPM (0 = automatic)
 * @return: 0 on success
 */
int apple_power_set_fan_rpm(uint32_t rpm);

/**
 * Platform integration entry point.
 */
int apple_power_platform_init(const fut_platform_info_t *info);

#endif /* __FUTURA_APPLE_POWER_H__ */

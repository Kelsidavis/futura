/* apple_power.c - Apple Silicon Power Management Driver
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Battery monitoring, thermal sensing, and fan control via Apple SMC.
 */

#include <platform/arm64/apple_power.h>
#include <platform/arm64/apple_smc.h>
#include <platform/platform.h>
#include <string.h>

/* SMC key constants (matching Rust driver definitions) */
#define SMC_KEY(a,b,c,d) ((uint32_t)(a) | ((uint32_t)(b) << 8) | \
                           ((uint32_t)(c) << 16) | ((uint32_t)(d) << 24))

#define KEY_TC0E  SMC_KEY('T','C','0','E')  /* CPU die temp */
#define KEY_TG0P  SMC_KEY('T','G','0','P')  /* GPU temp */
#define KEY_TA0P  SMC_KEY('T','A','0','P')  /* Ambient temp */
#define KEY_FNUM  SMC_KEY('F','N','u','m')  /* Fan count */
#define KEY_F0AC  SMC_KEY('F','0','A','c')  /* Fan 0 actual RPM */
#define KEY_F0TG  SMC_KEY('F','0','T','g')  /* Fan 0 target RPM */
#define KEY_BCHG  SMC_KEY('B','C','H','G')  /* Battery charge */
#define KEY_BFCG  SMC_KEY('B','F','C','G')  /* Battery full capacity */
#define KEY_ACIN  SMC_KEY('A','C','I','N')  /* AC adapter present */

static AppleSmc *g_smc = NULL;
static bool g_power_initialized = false;

int apple_power_init(const fut_platform_info_t *info) {
    if (!info || info->smc_base == 0) {
        fut_printf("[POWER] SMC base address not available\n");
        return -1;
    }

    g_smc = rust_smc_init(info->smc_base);
    if (!g_smc) {
        fut_printf("[POWER] Failed to initialize SMC\n");
        return -1;
    }

    g_power_initialized = true;

    /* Log initial state */
    int32_t cpu_temp = rust_smc_cpu_temp_mc(g_smc);
    uint32_t fan_rpm = rust_smc_fan0_rpm(g_smc);
    int32_t ac = rust_smc_ac_present(g_smc);

    fut_printf("[POWER] SMC initialized at 0x%lx\n", (unsigned long)info->smc_base);
    if (cpu_temp != (int32_t)0x80000000) {
        fut_printf("[POWER] CPU temp: %d.%03d°C\n",
                   cpu_temp / 1000, (cpu_temp % 1000 < 0 ? -cpu_temp % 1000 : cpu_temp % 1000));
    }
    fut_printf("[POWER] Fan 0: %u RPM\n", fan_rpm);
    fut_printf("[POWER] AC adapter: %s\n", ac ? "present" : "not present");

    return 0;
}

int apple_power_update(apple_power_state_t *state) {
    if (!g_power_initialized || !g_smc || !state) return -1;

    memset(state, 0, sizeof(*state));

    state->cpu_temp_mc = rust_smc_cpu_temp_mc(g_smc);
    state->fan_rpm = rust_smc_fan0_rpm(g_smc);
    state->ac_present = rust_smc_ac_present(g_smc) != 0;

    /* Read GPU and ambient temps */
    uint8_t buf[2];
    if (rust_smc_read_key(g_smc, KEY_TG0P, buf, 2) == 2) {
        uint16_t raw = ((uint16_t)buf[0] << 8) | buf[1];
        state->gpu_temp_mc = (int32_t)((raw * 1000) / 4);
    }
    if (rust_smc_read_key(g_smc, KEY_TA0P, buf, 2) == 2) {
        uint16_t raw = ((uint16_t)buf[0] << 8) | buf[1];
        state->ambient_temp_mc = (int32_t)((raw * 1000) / 4);
    }

    /* Battery */
    if (rust_smc_read_key(g_smc, KEY_BCHG, buf, 2) == 2) {
        state->battery_charge = ((uint16_t)buf[0] << 8) | buf[1];
    }
    if (rust_smc_read_key(g_smc, KEY_BFCG, buf, 2) == 2) {
        state->battery_full = ((uint16_t)buf[0] << 8) | buf[1];
    }
    if (state->battery_full > 0) {
        state->battery_pct = (uint8_t)((state->battery_charge * 100) / state->battery_full);
    }

    /* Fan count */
    if (rust_smc_read_key(g_smc, KEY_FNUM, buf, 1) == 1) {
        state->fan_count = buf[0];
    }

    return 0;
}

int32_t apple_power_cpu_temp(void) {
    if (!g_power_initialized || !g_smc) return 0x80000000;
    return rust_smc_cpu_temp_mc(g_smc);
}

int32_t apple_power_gpu_temp(void) {
    if (!g_power_initialized || !g_smc) return 0x80000000;
    uint8_t buf[2];
    if (rust_smc_read_key(g_smc, KEY_TG0P, buf, 2) != 2) return 0x80000000;
    uint16_t raw = ((uint16_t)buf[0] << 8) | buf[1];
    return (int32_t)((raw * 1000) / 4);
}

bool apple_power_ac_present(void) {
    if (!g_power_initialized || !g_smc) return false;
    return rust_smc_ac_present(g_smc) != 0;
}

uint8_t apple_power_battery_pct(void) {
    if (!g_power_initialized || !g_smc) return 0;
    uint8_t buf[2];
    uint16_t charge = 0, full = 0;
    if (rust_smc_read_key(g_smc, KEY_BCHG, buf, 2) == 2)
        charge = ((uint16_t)buf[0] << 8) | buf[1];
    if (rust_smc_read_key(g_smc, KEY_BFCG, buf, 2) == 2)
        full = ((uint16_t)buf[0] << 8) | buf[1];
    if (full == 0) return 0;
    return (uint8_t)((charge * 100) / full);
}

int apple_power_set_fan_rpm(uint32_t rpm) {
    if (!g_power_initialized || !g_smc) return -1;
    uint8_t buf[2] = { (uint8_t)(rpm >> 8), (uint8_t)(rpm & 0xFF) };
    return rust_smc_write_key(g_smc, KEY_F0TG, buf, 2);
}

int apple_power_platform_init(const fut_platform_info_t *info) {
    if (!info) return -1;

    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    if (info->smc_base == 0) {
        return 0;  /* No SMC found in DTB */
    }

    return apple_power_init(info);
}

/* apple_smc.h - Apple SMC (System Management Controller) C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef __FUTURA_APPLE_SMC_H__
#define __FUTURA_APPLE_SMC_H__

#include <stdint.h>
#include <stddef.h>

typedef struct AppleSmc AppleSmc;

typedef struct {
    uint8_t  size;
    uint32_t dtype;
    uint8_t  attr;
} SmcKeyInfo;

AppleSmc *rust_smc_init(uint64_t base);
void rust_smc_free(AppleSmc *smc);
int32_t rust_smc_read_key(AppleSmc *smc, uint32_t key, uint8_t *buf, size_t len);
int32_t rust_smc_write_key(AppleSmc *smc, uint32_t key, const uint8_t *data, size_t len);
int32_t rust_smc_cpu_temp_mc(AppleSmc *smc);
uint32_t rust_smc_fan0_rpm(AppleSmc *smc);
int32_t rust_smc_ac_present(AppleSmc *smc);
uint32_t rust_smc_key_count(AppleSmc *smc);
int32_t rust_smc_key_info(AppleSmc *smc, uint32_t key, SmcKeyInfo *info);

#endif /* __FUTURA_APPLE_SMC_H__ */

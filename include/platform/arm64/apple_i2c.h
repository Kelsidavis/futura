/* apple_i2c.h - Apple I2C Controller C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef __FUTURA_APPLE_I2C_H__
#define __FUTURA_APPLE_I2C_H__

#include <stdint.h>

typedef struct AppleI2c AppleI2c;

AppleI2c *rust_i2c_init(uint64_t base);
void rust_i2c_free(AppleI2c *i2c);
int32_t rust_i2c_write(const AppleI2c *i2c, uint8_t addr, const uint8_t *buf, size_t len);
int32_t rust_i2c_read(const AppleI2c *i2c, uint8_t addr, uint8_t *buf, size_t len);
int32_t rust_i2c_write_read(const AppleI2c *i2c, uint8_t addr,
                             const uint8_t *tx_buf, size_t tx_len,
                             uint8_t *rx_buf, size_t rx_len);
uint32_t rust_i2c_status(const AppleI2c *i2c);

#endif /* __FUTURA_APPLE_I2C_H__ */

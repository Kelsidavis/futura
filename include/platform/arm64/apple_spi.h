/* apple_spi.h - Apple SPI Controller C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef __FUTURA_APPLE_SPI_H__
#define __FUTURA_APPLE_SPI_H__

#include <stdint.h>
#include <stddef.h>

typedef struct AppleSpi AppleSpi;

AppleSpi *rust_spi_init(uint64_t base, uint32_t pclk_hz, uint8_t mode, uint32_t hz);
void rust_spi_free(AppleSpi *spi);
void rust_spi_cs_assert(AppleSpi *spi, uint8_t cs);
void rust_spi_cs_deassert(AppleSpi *spi, uint8_t cs);
int32_t rust_spi_transfer(AppleSpi *spi, const uint8_t *tx_buf, uint8_t *rx_buf, size_t len);
int32_t rust_spi_write(AppleSpi *spi, const uint8_t *buf, size_t len);
int32_t rust_spi_read(AppleSpi *spi, uint8_t *buf, size_t len);
uint32_t rust_spi_handle_irq(AppleSpi *spi);

#endif /* __FUTURA_APPLE_SPI_H__ */

/* apple_spi_i2c_tests.c - NULL-guard tests for apple_spi + apple_i2c
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_spi drives the SPI controller (keyboard HID transport).
 * apple_i2c drives the I2C controller (trackpad HID transport).
 * Both check is_null on every public FFI; these tests assert the
 * sentinels documented in their headers.
 */

#ifdef __aarch64__

#include <platform/arm64/apple_spi.h>
#include <platform/arm64/apple_i2c.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define SPI_PASS(name) \
    do { \
        fut_printf("[SPI-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define SPI_FAIL(name, code) \
    do { \
        fut_printf("[SPI-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

void fut_apple_spi_i2c_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[SPI-TEST] starting apple_spi + apple_i2c guard tests\n");

    /* ---------------- apple_spi ---------------- */

    /* T1: spi_init(base=0) → NULL */
    {
        if (rust_spi_init(0, 50000000, 0, 1000000) == NULL) {
            SPI_PASS("spi_init(base=0)");
        } else { SPI_FAIL("spi_init(base=0)", 1); return; }
    }

    /* T2: spi_free(NULL) → no-op */
    {
        rust_spi_free(NULL);
        SPI_PASS("spi_free(NULL) no-op");
    }

    /* T3: spi_cs_assert(NULL, ...) → no-op */
    {
        rust_spi_cs_assert(NULL, 0);
        SPI_PASS("spi_cs_assert(NULL) no-op");
    }

    /* T4: spi_transfer(NULL, ...) → negative errno */
    {
        uint8_t tx[4] = {0}, rx[4] = {0};
        int32_t rc = rust_spi_transfer(NULL, tx, rx, 4);
        if (rc < 0) SPI_PASS("spi_transfer(NULL)");
        else { SPI_FAIL("spi_transfer(NULL)", 4); return; }
    }

    /* T5: spi_handle_irq(NULL) → 0 */
    {
        if (rust_spi_handle_irq(NULL) == 0) SPI_PASS("spi_handle_irq(NULL)");
        else { SPI_FAIL("spi_handle_irq(NULL)", 5); return; }
    }

    /* ---------------- apple_i2c ---------------- */

    /* T6: i2c_init(base=0) → NULL */
    {
        if (rust_i2c_init(0) == NULL) SPI_PASS("i2c_init(base=0)");
        else { SPI_FAIL("i2c_init(base=0)", 6); return; }
    }

    /* T7: i2c_free(NULL) → no-op */
    {
        rust_i2c_free(NULL);
        SPI_PASS("i2c_free(NULL) no-op");
    }

    /* T8: i2c_write(NULL, ...) → negative errno */
    {
        uint8_t data[2] = {0xDE, 0xAD};
        int32_t rc = rust_i2c_write(NULL, 0x4F, data, 2);
        if (rc < 0) SPI_PASS("i2c_write(NULL)");
        else { SPI_FAIL("i2c_write(NULL)", 8); return; }
    }

    /* T9: i2c_read(NULL, ...) → negative errno */
    {
        uint8_t buf[2] = {0};
        int32_t rc = rust_i2c_read(NULL, 0x4F, buf, 2);
        if (rc < 0) SPI_PASS("i2c_read(NULL)");
        else { SPI_FAIL("i2c_read(NULL)", 9); return; }
    }

    /* T10: i2c_status(NULL) → 0 */
    {
        if (rust_i2c_status(NULL) == 0) SPI_PASS("i2c_status(NULL)");
        else { SPI_FAIL("i2c_status(NULL)", 10); return; }
    }

    fut_printf("[SPI-TEST] all apple_spi + apple_i2c guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_spi_i2c_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */

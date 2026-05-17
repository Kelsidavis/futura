/* apple_mca_tests.c - NULL-guard tests for apple_mca Rust FFI
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * apple_mca drives the Multi-Channel Audio I2S engine.  No C header
 * exposes the FFI; apple_audio.c uses the symbols directly.  These
 * tests declare the FFI inline and assert the is_null guards return
 * the documented -22 (EINVAL) sentinel or no-op.
 */

#ifdef __aarch64__

#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>

extern void fut_test_pass(void);
extern void fut_test_fail(uint16_t code);

#define MCA_PASS(name) \
    do { \
        fut_printf("[MCA-TEST] PASS: %s\n", name); \
        fut_test_pass(); \
    } while (0)

#define MCA_FAIL(name, code) \
    do { \
        fut_printf("[MCA-TEST] FAIL: %s (code=%u)\n", name, (unsigned)(code)); \
        fut_test_fail((uint16_t)(code)); \
    } while (0)

typedef struct AppleMca AppleMca;
typedef void (*MyDmaCb)(void *cookie, uint32_t bytes_done, int32_t status);

extern AppleMca *rust_mca_init(uint64_t base, uint32_t num_clusters);
extern void      rust_mca_free(AppleMca *mca);
extern int32_t   rust_mca_setup_playback(AppleMca *mca, uint32_t cluster,
                                          uint32_t mclk_sel, uint32_t mclk_hz,
                                          uint32_t sample_hz);
extern int32_t   rust_mca_setup_capture(AppleMca *mca, uint32_t cluster,
                                         uint32_t mclk_sel, uint32_t mclk_hz,
                                         uint32_t sample_hz);
extern int32_t   rust_mca_start_tx_dma(AppleMca *mca, uint32_t cluster,
                                        uint64_t phys, uint32_t len,
                                        MyDmaCb cb, void *cookie);
extern int32_t   rust_mca_stop(AppleMca *mca, uint32_t cluster);
extern void      rust_mca_handle_irq(AppleMca *mca, uint32_t cluster);

void fut_apple_mca_test_thread(void *arg)
{
    (void)arg;
    fut_printf("[MCA-TEST] starting apple_mca NULL-guard tests\n");

    /* T1: init(base=0) → NULL */
    {
        if (rust_mca_init(0, 1) == NULL) MCA_PASS("init(base=0)");
        else { MCA_FAIL("init(base=0)", 1); return; }
    }

    /* T2: free(NULL) → no-op */
    {
        rust_mca_free(NULL);
        MCA_PASS("free(NULL) no-op");
    }

    /* T3: setup_playback(NULL, ...) → -22 */
    {
        int32_t rc = rust_mca_setup_playback(NULL, 0, 0, 0, 48000);
        if (rc == -22) MCA_PASS("setup_playback(NULL)");
        else { MCA_FAIL("setup_playback(NULL)", 3); return; }
    }

    /* T4: setup_capture(NULL, ...) → -22 */
    {
        int32_t rc = rust_mca_setup_capture(NULL, 0, 0, 0, 48000);
        if (rc == -22) MCA_PASS("setup_capture(NULL)");
        else { MCA_FAIL("setup_capture(NULL)", 4); return; }
    }

    /* T5: start_tx_dma(NULL, ...) → -22 */
    {
        int32_t rc = rust_mca_start_tx_dma(NULL, 0, 0x10000, 1024, NULL, NULL);
        if (rc == -22) MCA_PASS("start_tx_dma(NULL)");
        else { MCA_FAIL("start_tx_dma(NULL)", 5); return; }
    }

    /* T6: stop(NULL, ...) → -22 */
    {
        if (rust_mca_stop(NULL, 0) == -22) MCA_PASS("stop(NULL)");
        else { MCA_FAIL("stop(NULL)", 6); return; }
    }

    /* T7: handle_irq(NULL, ...) → no-op */
    {
        rust_mca_handle_irq(NULL, 0);
        MCA_PASS("handle_irq(NULL) no-op");
    }

    fut_printf("[MCA-TEST] all apple_mca NULL-guard tests passed\n");
}

#else /* !__aarch64__ */

void fut_apple_mca_test_thread(void *arg) { (void)arg; }

#endif /* __aarch64__ */

/* apple_bcm.h - Apple Silicon Broadcom WiFi+Bluetooth combo header
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Discovery-only first slice for Apple Silicon WiFi+BT (BCM4377 /
 * BCM4378 / BCM4387 / BCM4388 combo chips).  All chips sit on the
 * Apple PCIe root complex as a multi-function endpoint (WiFi on
 * function 0, Bluetooth on function 1).
 */

#ifndef __FUTURA_APPLE_BCM_H__
#define __FUTURA_APPLE_BCM_H__

#include <stdint.h>
#include <stdbool.h>
#include <platform/arm64/dtb.h>

#define BCM_VENDOR_ID         0x14E4u

/* Chip discriminants — must mirror chip_to_u32() in lib.rs */
#define BCM_CHIP_UNKNOWN      0u
#define BCM_CHIP_BCM4377      1u
#define BCM_CHIP_BCM4378      2u
#define BCM_CHIP_BCM4387      3u
#define BCM_CHIP_BCM4388      4u

/* PCI class encodings the Broadcom chip uses on Apple PCIe. */
#define BCM_PCI_CLASS_WIFI    0x028000u  /* Network / Other */
#define BCM_PCI_CLASS_BT      0xFE0000u  /* Wireless / Vendor-specific */

typedef struct {
    uint32_t chip;        /* BCM_CHIP_* */
    uint16_t vendor;
    uint16_t device;
    uint8_t  revision;
    uint8_t  bus;
    uint8_t  function;
    uint8_t  _pad;
    uint64_t bar0;
    uint64_t bar2;
    uint32_t class_code;
    uint16_t msi_cap;     /* PCI Cap 0x05 offset, 0 if absent */
    uint16_t msix_cap;    /* PCI Cap 0x11 offset, 0 if absent */
    uint16_t msi_vectors; /* 1, 2, 4, 8, 16, or 32 — only valid when msi_cap != 0 */
    uint16_t msix_table_size; /* MSI-X table size, only valid when msix_cap != 0 */
} apple_bcm_discovery_t;

/* Walk the Apple PCIe root complex looking for the Broadcom combo
 * chip.  Populates `out_wifi` / `out_bt` with whatever functions we
 * find; returns the number of populated entries.
 *
 * No-ops (returns 0) when the platform isn't Apple Silicon or PCIe
 * isn't present in the device tree.  This is safe to call on RPi /
 * QEMU virt — it just won't find anything. */
int apple_bcm_init(const fut_platform_info_t *info,
                   apple_bcm_discovery_t *out_wifi,
                   apple_bcm_discovery_t *out_bt);

/* Platform-init entry point — gated on PLATFORM_APPLE_M[1-4].
 * Mirrors the apple_xhci_platform_init pattern so the call site in
 * platform_init.c stays uniform. */
int apple_bcm_platform_init(const fut_platform_info_t *info);

/* Accessors for what discovery cached, intended for follow-up slices
 * that actually bring the radios up. */
bool                          apple_bcm_wifi_present(void);
bool                          apple_bcm_bt_present(void);
const apple_bcm_discovery_t  *apple_bcm_wifi_info(void);
const apple_bcm_discovery_t  *apple_bcm_bt_info(void);

/* BAR access: return the kernel VA mapping the corresponding BAR, or
 * 0 if the chip wasn't discovered.  Backed by the existing Apple
 * peripheral mapping window (`fut_kernel_peripheral_va`) — no extra
 * page-table work needed. */
uint64_t apple_bcm_wifi_bar0_va(void);
uint64_t apple_bcm_wifi_bar2_va(void);
uint64_t apple_bcm_bt_bar0_va(void);
uint64_t apple_bcm_bt_bar2_va(void);

/* Chip lifecycle stubs.  Today they only validate state + log; the
 * actual GPIO toggle for WL_REG_ON and the PCIe Function-Level Reset
 * land in follow-up slices.  Returns 0 on success, negative errno on
 * failure (no chip present, etc.). */
int apple_bcm_chip_power_on(void);
int apple_bcm_chip_reset(void);

/* Rust FFI surface (apple_bcm crate). */
uint32_t     rust_apple_bcm_classify(uint16_t vendor, uint16_t device);
const char  *rust_apple_bcm_chip_name(uint32_t chip_id);
const char  *rust_apple_bcm_wifi_fw_base(uint32_t chip_id);
const char  *rust_apple_bcm_bt_fw_base(uint32_t chip_id);

#endif /* __FUTURA_APPLE_BCM_H__ */

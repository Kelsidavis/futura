/* apple_pcie.h - Apple PCIe Root Complex C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef __FUTURA_APPLE_PCIE_H__
#define __FUTURA_APPLE_PCIE_H__

#include <stdint.h>

typedef struct ApplePcie ApplePcie;

ApplePcie *rust_apple_pcie_init(uint64_t base, uint32_t num_ports, uint64_t cfg_base);
void rust_apple_pcie_free(ApplePcie *pcie);
int32_t rust_apple_pcie_port_link_up(const ApplePcie *pcie, uint32_t port);
uint32_t rust_apple_pcie_port_speed(const ApplePcie *pcie, uint32_t port);
uint32_t rust_apple_pcie_port_width(const ApplePcie *pcie, uint32_t port);
uint32_t rust_apple_pcie_cfg_read32(const ApplePcie *pcie, uint8_t bus, uint8_t dev, uint8_t fn_, uint16_t reg);
void rust_apple_pcie_cfg_write32(ApplePcie *pcie, uint8_t bus, uint8_t dev, uint8_t fn_, uint16_t reg, uint32_t val);
uint16_t rust_apple_pcie_cfg_read16(const ApplePcie *pcie, uint8_t bus, uint8_t dev, uint8_t fn_, uint16_t reg);
uint8_t rust_apple_pcie_cfg_read8(const ApplePcie *pcie, uint8_t bus, uint8_t dev, uint8_t fn_, uint16_t reg);
void rust_apple_pcie_setup_msi(ApplePcie *pcie, uint32_t port, uint64_t msi_addr, uint32_t irq_base);
void rust_apple_pcie_handle_irq(const ApplePcie *pcie, uint32_t port);
uint32_t rust_apple_pcie_scan_devices(const ApplePcie *pcie);

#endif /* __FUTURA_APPLE_PCIE_H__ */

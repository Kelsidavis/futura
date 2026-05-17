# Apple Silicon WiFi + Bluetooth (Broadcom BCM4377 / BCM4378 / BCM4387)

**Status (2026-05-17)**: chip discovery, classification, FLR, power rails, and request-firmware plumbing are all wired in tree. Radio bring-up (firmware upload + brcmfmac msgbuf rings + HCI Bluetooth transport) is **not** yet implemented.

Apple Silicon Macs ship a Broadcom combo chip that integrates both 802.11ax WiFi and Bluetooth (LE + Classic) on a single PCIe endpoint. The chip varies by SoC generation but the host-side architecture is identical: a multi-function PCIe device hanging off the Apple PCIe root complex.

## Hardware topology

```
Apple PCIe Root Complex (apple,t8103-pcie / apple,t6000-pcie / etc.)
        ↓  one downstream port
PCIe Switch
        ↓
Broadcom BCM4377 / BCM4378 / BCM4387 / BCM4388
   ├─ Function 0  →  WiFi  (PCI class 0x028000)
   └─ Function 1  →  Bluetooth (PCI class 0xFE0000)
```

Both functions share the same physical silicon and the same firmware bundle; the OS uploads firmware via the WiFi function and the Bluetooth function comes up as a side-effect of the WiFi side being booted.

Power for the chip is gated by two GPIO lines driven by the Apple pinctrl block:

| Pin name      | Driven by                  | Effect           |
|---------------|----------------------------|------------------|
| `WL_REG_ON`   | `apple_bcm_chip_power_on`  | Active-high — chip is in reset when low |
| `BT_REG_ON`   | `apple_bcm_chip_power_on`  | Active-high — Bluetooth in reset when low |

Pin numbers come from the `apple,bootstrap-gpios` property on the WiFi / Bluetooth DT nodes. See "DT walker" below.

## In-tree layers

```
┌─────────────────────────────────────────────────────┐
│  apple_bcm  (drivers/rust/apple_bcm + C wrapper)    │
│  • PCIe discovery (vendor=0x14E4, fn 0+1)           │
│  • Chip classification (BCM4377/4378/4387/4388)     │
│  • BAR0/BAR2 mapping into kernel VA                 │
│  • PCIe Function-Level Reset via Cap 0x10           │
│  • WL_REG_ON / BT_REG_ON toggle via apple_gpio      │
│  • Firmware-name lookup (Asahi blob base names)     │
│  • Calls fut_firmware_load on init (currently fails │
│    -ENOENT; logs the missing blob name clearly)     │
└─────────────────────────────────────────────────────┘
                ↓ uses
┌─────────────────────────────────────────────────────┐
│  apple_pcie    (PCIe config-space, link, MSI)       │
│  • rust_apple_pcie_init / cfg_read32 / cfg_write32  │
│  • rust_apple_pcie_find_cap (cap walker — reusable) │
│  • rust_apple_pcie_setup_msi (BCM not yet using)    │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│  apple_gpio    (pinctrl GPIO controller)            │
│  • rust_gpio_set_direction / set_output             │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│  kernel firmware loader (kernel/firmware.c)         │
│  • fut_firmware_load(name, &data, &size)            │
│  • fut_firmware_embed(name, blob, size)             │
│  • Provider registration; embedded provider built-in│
│  • FS-backed provider NOT YET implemented           │
└─────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────┐
│  arm64 DT parser (kernel/dtb/arm64_dtb.c)           │
│  • fut_dtb_find_compat_u32_cell — extracts pin      │
│    number from apple,bootstrap-gpios on the WiFi /  │
│    Bluetooth DT nodes                               │
└─────────────────────────────────────────────────────┘
```

## Boot sequence on real hardware (intended end state)

1. m1n1 loads the kernel and provides a flattened DT.
2. `fut_dtb_parse` walks DT, populates `info->wlan_reset_gpio` and `info->bt_reset_gpio` from `apple,bootstrap-gpios`.
3. `apple_bcm_platform_init` runs as part of Apple-platform driver init.
4. `apple_bcm_init` walks PCIe, identifies fn 0 + fn 1 by vendor ID 0x14E4, classifies the chip by device ID, reads BAR0 / BAR2.
5. `apple_bcm_chip_power_on` drives `WL_REG_ON` and `BT_REG_ON` high, waits 150 ms for rails to settle.
6. (*future*) `apple_bcm_chip_reset` issues PCIe FLR to start from a known state.
7. (*future*) Firmware blob is loaded via `fut_firmware_load("brcmfmac4378-pcie.apple", ...)`. The FS-backed provider reads it from `/lib/firmware/brcm/...` on the boot disk.
8. (*future*) brcmfmac M2M DMA driver uploads firmware to chip RAM, programs the chip's command/event/RX/TX rings, allocates MSI vectors, and hands off to the WiFi stack.
9. (*future*) HCI transport for the Bluetooth function comes up as a side-effect; BCM patchram blob is loaded.

## What's wired today vs. outstanding

| Step | Status | Notes |
|------|--------|-------|
| DT walker | ✅ | `apple,bootstrap-gpios` cell 1 → `wlan_reset_gpio` / `bt_reset_gpio` |
| PCIe discovery | ✅ | vendor/device classification across all four chip families |
| BAR mapping | ✅ | BAR0/BAR2 accessible via `apple_bcm_*_bar0_va` / `bar2_va` |
| PCIe FLR | ✅ | uses `rust_apple_pcie_find_cap(0x10)`; chip survival verified by re-reading vendor ID |
| WL_REG_ON / BT_REG_ON | ✅ | LOW → wait → HIGH cycle via `apple_gpio` |
| Auto-power-on at init | ✅ | called from `apple_bcm_platform_init` after discovery |
| Firmware loader API | ✅ | `fut_firmware_load` + embedded provider; 10 unit tests |
| Apple FS firmware provider | ❌ | Blocked on filesystem mount during platform init |
| PCIe MSI vector allocation | ❌ | `apple_pcie` has the primitives; not yet exposed to `apple_bcm` |
| brcmfmac M2M DMA upload | ❌ | Substantial — requires chip-RAM map + DMA descriptor setup |
| brcmfmac msgbuf rings | ❌ | TX/RX/CMD/EVT ring setup + command marshalling |
| HCI transport | ❌ | BCM4378 BT lives on fn 1; needs the BlueZ HCI layer first |

## Chip / firmware naming reference

| Chip       | Device ID(s)    | Apple SoC          | Firmware base name             |
|------------|-----------------|--------------------|--------------------------------|
| BCM4377    | 0x4425          | early M1 prototype | `brcmfmac4377-pcie.apple`      |
| BCM4378    | 0x4433 / 0x4434 | M1 family          | `brcmfmac4378-pcie.apple`      |
| BCM4387    | 0x4438          | M2 / M3 family     | `brcmfmac4387-pcie.apple`      |
| BCM4388    | 0x4490 (prov.)  | M4 (provisional)   | `brcmfmac4388-pcie.apple`      |

Bluetooth patchram blobs are named `BCM4377B3`, `BCM4378B1`, `BCM4387C2`, `BCM4388A0` respectively.

## Code pointers

- Rust crate: `drivers/rust/apple_bcm/`
- C wrapper: `platform/arm64/drivers/apple_bcm.c`
- Public header: `include/platform/arm64/apple_bcm.h`
- DT walker: `fut_dtb_find_compat_u32_cell` in `kernel/dtb/arm64_dtb.c`
- Firmware loader: `kernel/firmware.c` + `include/kernel/firmware.h`
- Firmware tests: `kernel/tests/firmware_tests.c`
- PCIe cap walker: `rust_apple_pcie_find_cap` in `drivers/rust/apple_pcie/src/lib.rs`

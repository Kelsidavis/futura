/* apple_bcm.c - Apple Silicon Broadcom WiFi+BT — discovery wrapper
 *
 * Copyright (c) 2026 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * First slice of Apple Silicon WiFi+Bluetooth support.  The combo
 * chip (BCM4377 on early M1 prototypes, BCM4378 on M1 / M1 Pro /
 * M1 Max / M1 Ultra, BCM4387 on M2/M3, provisionally BCM4388 on M4)
 * lives on the Apple PCIe root complex as a multi-function endpoint:
 *
 *   function 0 — WiFi    (PCI class 0x028000)
 *   function 1 — Bluetooth (PCI class 0xFE0000 / vendor specific)
 *
 * What this file does:
 *   1. Brings up the Apple PCIe driver (idempotent — apple_xhci has
 *      already done so by the time we run, this is a safety net).
 *   2. Walks every link-up port, reading vendor/device at fn 0 and
 *      fn 1, and stashes anything with vendor=0x14e4.
 *   3. Reads BAR0 + BAR2 for each match so a follow-up slice can DMA
 *      firmware in and map the doorbell window.
 *   4. Caches the results in static state for accessor functions.
 *
 * What this file does NOT do (deferred to follow-up slices):
 *   - PCIe MSI vector allocation for the chip
 *   - Firmware blob loading from `apple_bcm_wifi_fw_base` path
 *   - NVRAM (per-machine WiFi calibration) parse out of DT
 *   - brcmfmac-style command/event ring setup
 *   - HCI transport over the BT function
 *   - Power-rail bring-up via SMC / GPIO (WL_REG_ON-style poke)
 *
 * Compat note: apple_bcm_platform_init() gates on
 * info->type == PLATFORM_APPLE_M[1-4] so RPi and QEMU virt boots
 * never touch the Broadcom code path.
 */

#include <platform/arm64/apple_bcm.h>
#include <platform/arm64/apple_pcie.h>
#include <platform/arm64/apple_gpio.h>
#include <platform/platform.h>
#include <kernel/firmware.h>
#include <kernel/errno.h>
#include <string.h>

#define BCM_MAX_FUNCTIONS  2  /* fn 0 (WiFi) + fn 1 (Bluetooth) */

/* Forward declarations for the rust_apple_pcie FFI we reuse. */
extern struct ApplePcie *rust_apple_pcie_init(uint64_t base,
                                              uint32_t num_ports,
                                              uint64_t cfg_base);
extern int      rust_apple_pcie_port_link_up(const struct ApplePcie *p,
                                             uint32_t port);
extern uint32_t rust_apple_pcie_cfg_read32(const struct ApplePcie *p,
                                           uint8_t bus, uint8_t dev,
                                           uint8_t fn, uint16_t reg);
extern uint16_t rust_apple_pcie_cfg_read16(const struct ApplePcie *p,
                                           uint8_t bus, uint8_t dev,
                                           uint8_t fn, uint16_t reg);
extern void     rust_apple_pcie_cfg_write32(struct ApplePcie *p,
                                            uint8_t bus, uint8_t dev,
                                            uint8_t fn, uint16_t reg,
                                            uint32_t val);
extern uint16_t rust_apple_pcie_find_cap(const struct ApplePcie *p,
                                          uint8_t bus, uint8_t dev,
                                          uint8_t fn, uint8_t cap_id);

/* PCI / PCIe capability IDs we care about here. */
#define PCI_CAP_ID_PCIE      0x10u

/* PCI Express device-capabilities register: bit 28 = FLR Capable. */
#define PCIE_DEVCAP_FLR_CAP  (1u << 28)
/* PCI Express device-control register: bit 15 = Initiate FLR. */
#define PCIE_DEVCTL_FLR      (1u << 15)

/* Cache the PCIe handle so chip_reset can use it without re-running
 * the PCIe init dance.  Populated by apple_bcm_init on success. */
static struct ApplePcie *g_bcm_pcie;

/* GPIO state cached from platform info so chip_power_on can drive
 * WL_REG_ON / BT_REG_ON without re-parsing the DT. */
static AppleGpio *g_bcm_gpio;
static int32_t    g_bcm_wlan_reset_gpio = -1;
static int32_t    g_bcm_bt_reset_gpio   = -1;
static uint64_t   g_bcm_gpio_base_pa;

/* Cached discovery state for accessor functions. */
static struct {
    apple_bcm_discovery_t wifi;
    apple_bcm_discovery_t bt;
    bool wifi_present;
    bool bt_present;
} g_bcm;

static uint64_t read_bar64(const struct ApplePcie *p, uint8_t bus,
                           uint8_t fn, uint16_t reg)
{
    uint32_t lo = rust_apple_pcie_cfg_read32(p, bus, 0, fn, reg);
    uint32_t hi = rust_apple_pcie_cfg_read32(p, bus, 0, fn, reg + 4);
    /* 64-bit memory BAR: low 4 bits hold flags (type + prefetch); the
     * remaining bits are the base address. */
    return ((uint64_t)hi << 32) | (lo & ~0xFULL);
}

int apple_bcm_init(const fut_platform_info_t *info,
                   apple_bcm_discovery_t *out_wifi,
                   apple_bcm_discovery_t *out_bt)
{
    if (!info || info->pcie_base == 0 || info->pcie_cfg_base == 0) {
        return 0;
    }

    uint64_t pcie_va     = fut_kernel_peripheral_va(info->pcie_base);
    uint64_t pcie_cfg_va = fut_kernel_peripheral_va(info->pcie_cfg_base);
    struct ApplePcie *pcie = rust_apple_pcie_init(pcie_va,
                                                  info->pcie_num_ports,
                                                  pcie_cfg_va);
    if (!pcie) {
        fut_printf("[bcm] PCIe init failed (pa pcie=0x%lx cfg=0x%lx)\n",
                   (unsigned long)info->pcie_base,
                   (unsigned long)info->pcie_cfg_base);
        return 0;
    }
    g_bcm_pcie             = pcie;
    g_bcm_gpio_base_pa     = info->gpio_base_apple;
    g_bcm_wlan_reset_gpio  = info->wlan_reset_gpio;
    g_bcm_bt_reset_gpio    = info->bt_reset_gpio;

    int found = 0;
    for (uint32_t port = 0; port < info->pcie_num_ports; port++) {
        if (!rust_apple_pcie_port_link_up(pcie, port)) continue;

        uint8_t bus = (uint8_t)(port + 1);

        for (uint8_t fn = 0; fn < BCM_MAX_FUNCTIONS; fn++) {
            uint32_t vid_did = rust_apple_pcie_cfg_read32(pcie, bus, 0, fn, 0x00);
            uint16_t vid = (uint16_t)(vid_did & 0xFFFFu);
            uint16_t did = (uint16_t)((vid_did >> 16) & 0xFFFFu);

            if (vid == 0xFFFFu || vid == 0x0000u) continue;
            if (vid != BCM_VENDOR_ID) continue;

            uint32_t class_rev = rust_apple_pcie_cfg_read32(pcie, bus, 0, fn, 0x08);
            uint32_t class_code = class_rev >> 8;
            uint8_t  revision   = (uint8_t)(class_rev & 0xFFu);

            apple_bcm_discovery_t d;
            memset(&d, 0, sizeof(d));
            d.chip       = rust_apple_bcm_classify(vid, did);
            d.vendor     = vid;
            d.device     = did;
            d.revision   = revision;
            d.bus        = bus;
            d.function   = fn;
            d.class_code = class_code;
            d.bar0       = read_bar64(pcie, bus, fn, 0x10);
            d.bar2       = read_bar64(pcie, bus, fn, 0x18);

            /* Enable MEM access + bus mastering so subsequent slices
             * can poke registers and DMA without re-running this. */
            uint16_t cmd = rust_apple_pcie_cfg_read16(pcie, bus, 0, fn, 0x04);
            rust_apple_pcie_cfg_write32(pcie, bus, 0, fn, 0x04,
                                         (uint32_t)(cmd | 0x06u));

            const char *chip_name = rust_apple_bcm_chip_name(d.chip);
            fut_printf("[bcm] fn%u %s VID=0x%04x DID=0x%04x rev=0x%02x "
                       "class=0x%06x BAR0=0x%lx BAR2=0x%lx\n",
                       (unsigned)fn, chip_name,
                       (unsigned)vid, (unsigned)did, (unsigned)revision,
                       (unsigned)class_code,
                       (unsigned long)d.bar0, (unsigned long)d.bar2);

            if (fn == 0) {
                if (out_wifi) *out_wifi = d;
                g_bcm.wifi = d;
                g_bcm.wifi_present = true;
            } else {
                if (out_bt) *out_bt = d;
                g_bcm.bt = d;
                g_bcm.bt_present = true;
            }
            found++;
        }

        /* Apple's BCM combo always sits on a single downstream port;
         * once we've found a WiFi function on a bus we can stop. */
        if (g_bcm.wifi_present) break;
    }

    if (found == 0) {
        fut_printf("[bcm] no Broadcom WiFi/BT combo chip found on PCIe\n");
        return 0;
    }

    const char *wifi_fw = g_bcm.wifi_present
        ? rust_apple_bcm_wifi_fw_base(g_bcm.wifi.chip) : "(none)";
    const char *bt_fw = g_bcm.bt_present
        ? rust_apple_bcm_bt_fw_base(g_bcm.bt.chip) : "(none)";
    fut_printf("[bcm] discovery complete: wifi_fw=%s bt_fw=%s\n",
               wifi_fw, bt_fw);

    /* Attempt to load the firmware blobs through the kernel firmware
     * loader.  We expect this to fail with -ENOENT today — there is
     * no FS-backed provider on Apple yet, and the blobs are too large
     * to embed in the kernel image.  Logging the attempt + failure
     * makes it obvious on real-hardware boot what's still missing. */
    if (g_bcm.wifi_present) {
        const void *data = NULL;
        size_t size = 0;
        int rc = fut_firmware_load(wifi_fw, &data, &size);
        if (rc == 0) {
            fut_printf("[bcm] wifi firmware loaded: %s (%lu bytes)\n",
                       wifi_fw, (unsigned long)size);
        } else {
            fut_printf("[bcm] wifi firmware unavailable: %s rc=%d "
                       "(install /lib/firmware/%s* and provide an FS "
                       "firmware provider — radio stays down)\n",
                       wifi_fw, rc, wifi_fw);
        }
    }
    if (g_bcm.bt_present) {
        const void *data = NULL;
        size_t size = 0;
        int rc = fut_firmware_load(bt_fw, &data, &size);
        if (rc == 0) {
            fut_printf("[bcm] bt patchram loaded: %s (%lu bytes)\n",
                       bt_fw, (unsigned long)size);
        } else {
            fut_printf("[bcm] bt patchram unavailable: %s rc=%d "
                       "(HCI transport stays down)\n", bt_fw, rc);
        }
    }

    fut_printf("[bcm] radio bring-up is a separate slice — chip is "
               "registered but no firmware has been loaded\n");
    return found;
}

int apple_bcm_platform_init(const fut_platform_info_t *info)
{
    if (!info) return -1;

    if (info->type != PLATFORM_APPLE_M1 &&
        info->type != PLATFORM_APPLE_M2 &&
        info->type != PLATFORM_APPLE_M3 &&
        info->type != PLATFORM_APPLE_M4) {
        return 0;
    }

    if (info->pcie_base == 0) {
        return 0;
    }

    memset(&g_bcm, 0, sizeof(g_bcm));
    int found = apple_bcm_init(info, NULL, NULL);

    /* Bring the chip out of reset right after discovery so the rails
     * have settled by the time later code wants to bring the radios
     * up.  Failures are non-fatal — they're informational and the
     * caller can retry once the missing piece lands (DT pin numbers,
     * etc.). */
    if (found > 0) {
        int rc = apple_bcm_chip_power_on();
        if (rc == 0) {
            fut_printf("[bcm] chip rails up\n");
        }
        /* chip_power_on already logged the specific failure mode. */
    }

    return found;
}

bool apple_bcm_wifi_present(void) { return g_bcm.wifi_present; }
bool apple_bcm_bt_present(void)   { return g_bcm.bt_present; }

const apple_bcm_discovery_t *apple_bcm_wifi_info(void)
{
    return g_bcm.wifi_present ? &g_bcm.wifi : NULL;
}

const apple_bcm_discovery_t *apple_bcm_bt_info(void)
{
    return g_bcm.bt_present ? &g_bcm.bt : NULL;
}

uint64_t apple_bcm_wifi_bar0_va(void)
{
    if (!g_bcm.wifi_present || g_bcm.wifi.bar0 == 0) return 0;
    return fut_kernel_peripheral_va(g_bcm.wifi.bar0);
}

uint64_t apple_bcm_wifi_bar2_va(void)
{
    if (!g_bcm.wifi_present || g_bcm.wifi.bar2 == 0) return 0;
    return fut_kernel_peripheral_va(g_bcm.wifi.bar2);
}

uint64_t apple_bcm_bt_bar0_va(void)
{
    if (!g_bcm.bt_present || g_bcm.bt.bar0 == 0) return 0;
    return fut_kernel_peripheral_va(g_bcm.bt.bar0);
}

uint64_t apple_bcm_bt_bar2_va(void)
{
    if (!g_bcm.bt_present || g_bcm.bt.bar2 == 0) return 0;
    return fut_kernel_peripheral_va(g_bcm.bt.bar2);
}

int apple_bcm_chip_power_on(void)
{
    if (!g_bcm.wifi_present) {
        fut_printf("[bcm] power_on: no chip discovered\n");
        return -ENODEV;
    }
    if (g_bcm_gpio_base_pa == 0) {
        fut_printf("[bcm] power_on: gpio_base_apple not set in DT\n");
        return -ENODEV;
    }
    if (g_bcm_wlan_reset_gpio < 0 && g_bcm_bt_reset_gpio < 0) {
        fut_printf("[bcm] power_on: no reset GPIOs known — DT walk for "
                   "apple,bootstrap-gpios on /soc/wifi and "
                   "/soc/bluetooth is the next slice\n");
        return -ENOSYS;
    }

    if (!g_bcm_gpio) {
        uint64_t gpio_va = fut_kernel_peripheral_va(g_bcm_gpio_base_pa);
        g_bcm_gpio = rust_gpio_init(gpio_va, 256);
        if (!g_bcm_gpio) {
            fut_printf("[bcm] power_on: rust_gpio_init failed at va 0x%lx\n",
                       (unsigned long)gpio_va);
            return -EIO;
        }
    }

    /* WL_REG_ON / BT_REG_ON are active high: HIGH = chip powered,
     * LOW = held in reset.  Cycle them low→high to guarantee a clean
     * start, then wait ~150ms for internal rails to stabilize.
     *
     * We don't have a precision delay helper yet, so the busy-loops
     * here are coarse.  Each iteration is a few cycles; 5M iterations
     * is comfortably > 150ms even on a 3.5 GHz Firestorm. */
    if (g_bcm_wlan_reset_gpio >= 0) {
        rust_gpio_set_direction(g_bcm_gpio,
                                 (uint32_t)g_bcm_wlan_reset_gpio, 1);
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_wlan_reset_gpio, 0);
        for (volatile int i = 0; i < 500000; i++) { /* ~10ms */ }
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_wlan_reset_gpio, 1);
        fut_printf("[bcm] power_on: WL_REG_ON pin %d driven HIGH\n",
                   g_bcm_wlan_reset_gpio);
    }
    if (g_bcm_bt_reset_gpio >= 0) {
        rust_gpio_set_direction(g_bcm_gpio,
                                 (uint32_t)g_bcm_bt_reset_gpio, 1);
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_bt_reset_gpio, 0);
        for (volatile int i = 0; i < 500000; i++) { /* ~10ms */ }
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_bt_reset_gpio, 1);
        fut_printf("[bcm] power_on: BT_REG_ON pin %d driven HIGH\n",
                   g_bcm_bt_reset_gpio);
    }

    /* Settle delay after both rails are up. */
    for (volatile int i = 0; i < 5000000; i++) { /* ~150ms */ }
    return 0;
}

int apple_bcm_chip_reset(void)
{
    if (!g_bcm.wifi_present) {
        fut_printf("[bcm] reset: no chip discovered\n");
        return -ENODEV;
    }
    if (!g_bcm_pcie) {
        fut_printf("[bcm] reset: PCIe handle missing\n");
        return -ENODEV;
    }

    uint8_t bus = g_bcm.wifi.bus;
    uint8_t fn  = g_bcm.wifi.function;

    uint16_t cap = rust_apple_pcie_find_cap(g_bcm_pcie, bus, 0, fn,
                                            PCI_CAP_ID_PCIE);
    if (cap == 0) {
        fut_printf("[bcm] reset: PCIe capability not found on "
                   "bus=%u fn=%u\n", bus, fn);
        return -EIO;
    }

    /* PCIe Capability layout (PCIe Base Spec §7.5.3):
     *   cap+0x00: cap_id (u8) + next_ptr (u8) + cap_flags (u16)
     *   cap+0x04: Device Capabilities (u32)
     *   cap+0x08: Device Control (u16) + Device Status (u16) */
    uint32_t devcap = rust_apple_pcie_cfg_read32(g_bcm_pcie, bus, 0, fn,
                                                  cap + 0x04);
    if ((devcap & PCIE_DEVCAP_FLR_CAP) == 0) {
        fut_printf("[bcm] reset: chip is not FLR-capable "
                   "(devcap=0x%08x)\n", (unsigned)devcap);
        return -EIO;
    }

    /* Read-modify-write the device control register, setting bit 15
     * to initiate FLR.  The spec guarantees the chip will accept the
     * write and complete reset within 100ms; per Broadcom's
     * brcmfmac driver, a 200ms wait is the safe choice. */
    uint32_t devctl_sts = rust_apple_pcie_cfg_read32(g_bcm_pcie, bus, 0, fn,
                                                     cap + 0x08);
    rust_apple_pcie_cfg_write32(g_bcm_pcie, bus, 0, fn, cap + 0x08,
                                 devctl_sts | PCIE_DEVCTL_FLR);

    /* Busy-wait 200ms.  We don't have a precise delay yet on Apple
     * (timer is up but a sleep helper is on the TODO list), so this
     * is a coarse loop.  Each iteration is roughly one config read
     * (a few hundred ns); 1M iterations is comfortably > 200ms. */
    for (volatile int i = 0; i < 1000000; i++) {
        (void)rust_apple_pcie_cfg_read32(g_bcm_pcie, bus, 0, fn, 0x00);
    }

    /* Verify the chip came back — vendor ID should still read 0x14e4
     * after FLR (the device-IDs themselves survive reset). */
    uint32_t vid_did = rust_apple_pcie_cfg_read32(g_bcm_pcie, bus, 0, fn, 0x00);
    uint16_t vid = (uint16_t)(vid_did & 0xFFFFu);
    if (vid != BCM_VENDOR_ID) {
        fut_printf("[bcm] reset: chip didn't return after FLR "
                   "(vid=0x%04x)\n", vid);
        return -EIO;
    }

    fut_printf("[bcm] reset: FLR successful via PCIe cap at 0x%02x\n",
               (unsigned)cap);
    return 0;
}

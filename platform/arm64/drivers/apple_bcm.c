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
#include <kernel/hci.h>
#include <kernel/errno.h>
#include <string.h>

/* From platform/arm64/platform_init.c — ARM Generic Timer-backed
 * microsecond delay used here for the chip-reset / power-on settle
 * timings the chip datasheet specifies. */
extern void fut_platform_udelay(uint32_t usec);

#define BCM_MAX_FUNCTIONS  2  /* fn 0 (WiFi) + fn 1 (Bluetooth) */

/* PCIe FFI is declared in include/platform/arm64/apple_pcie.h. */

/* PCI / PCIe capability IDs we care about here. */
#define PCI_CAP_ID_MSI       0x05u
#define PCI_CAP_ID_PCIE      0x10u
#define PCI_CAP_ID_MSIX      0x11u

/* PCIe MSI Capability layout (PCI Local Bus Spec §6.8):
 *   cap+0x00: cap_id (u8) + next_ptr (u8) + Message Control (u16)
 *   cap+0x04: Message Address (lower 32 bits)
 *   cap+0x08: Message Address (upper 32 bits, if 64-bit Address Capable)
 * Message Control bits:
 *   0:     MSI enable
 *   1-3:   Multiple Message Capable (vectors requested, log2 — 0=1, 1=2, ..., 5=32)
 *   4-6:   Multiple Message Enable (vectors actually enabled, log2)
 *   7:     64-bit Address Capable
 *   8:     Per-Vector Masking Capable
 */
#define PCI_MSI_MMC_SHIFT    1
#define PCI_MSI_MMC_MASK     0x000Eu
#define PCI_MSI_64BIT        (1u << 7)
#define PCI_MSI_PVM          (1u << 8)

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

/* HCI device index assigned to the BT function (or -1 if not registered). */
static int g_bcm_hci_index = -1;

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

/* ============================================================
 *   HCI transport stubs
 * ============================================================
 *
 * The BCM4378/4387 BT function is HCI over the chip's PCIe interface
 * using a vendor-specific msgbuf protocol — the WiFi function uploads
 * the firmware, then the BT function comes up as a side-effect with
 * a small set of doorbell registers for HCI command/event/ACL
 * transfer.
 *
 * None of that ring/doorbell handling exists yet; these callbacks
 * return -ENOSYS so consumers know the transport is registered but
 * not yet live.  Registration itself is useful: the HCI subsystem
 * has a real device to enumerate, and future radio bring-up just
 * replaces these callbacks with the real msgbuf implementation. */

static int bcm_hci_send_cmd(void *cookie, const uint8_t *pkt, size_t len)
{
    (void)cookie;
    (void)pkt;
    (void)len;
    /* TODO: marshal into the BT msgbuf TX ring + ring the doorbell. */
    return -ENOSYS;
}

static int bcm_hci_send_acl(void *cookie, const uint8_t *pkt, size_t len)
{
    (void)cookie;
    (void)pkt;
    (void)len;
    return -ENOSYS;
}

static int bcm_hci_open(void *cookie)
{
    (void)cookie;
    /* Real implementation: load BT patchram, send HCI_Reset, wait for
     * cmd_complete.  All blocked on firmware-load slice + msgbuf ring
     * setup. */
    return -ENOSYS;
}

static void bcm_hci_close(void *cookie)
{
    (void)cookie;
    /* No-op until open works. */
}

static const fut_hci_ops_t bcm_hci_ops = {
    .send_cmd = bcm_hci_send_cmd,
    .send_acl = bcm_hci_send_acl,
    .open     = bcm_hci_open,
    .close    = bcm_hci_close,
};

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

            /* Probe MSI / MSI-X capabilities so a follow-up slice
             * can program them.  Apple's PCIe IP requires MSI for
             * interrupts; INTx is not routed.  Cache the offsets and
             * vector counts into the discovery record so the future
             * MSI-allocation slice doesn't have to re-walk. */
            d.msi_cap  = rust_apple_pcie_find_cap(pcie, bus, 0, fn,
                                                  PCI_CAP_ID_MSI);
            d.msix_cap = rust_apple_pcie_find_cap(pcie, bus, 0, fn,
                                                  PCI_CAP_ID_MSIX);
            if (d.msi_cap != 0) {
                uint16_t mc = rust_apple_pcie_cfg_read16(pcie, bus, 0, fn,
                                                          d.msi_cap + 0x02);
                uint32_t mmc = (mc & PCI_MSI_MMC_MASK) >> PCI_MSI_MMC_SHIFT;
                d.msi_vectors = (uint16_t)(1u << mmc);
                fut_printf("[bcm] fn%u MSI cap@0x%02x: %u vectors, "
                           "%s addr, %s per-vector mask\n",
                           (unsigned)fn, (unsigned)d.msi_cap,
                           (unsigned)d.msi_vectors,
                           (mc & PCI_MSI_64BIT) ? "64-bit" : "32-bit",
                           (mc & PCI_MSI_PVM) ? "yes" : "no");
            }
            if (d.msix_cap != 0) {
                uint16_t mc = rust_apple_pcie_cfg_read16(pcie, bus, 0, fn,
                                                          d.msix_cap + 0x02);
                /* MSI-X table size is bits 0-10 of Message Control, encoded
                 * as N-1 (so 0 means 1 vector, 0x7FF means 2048). */
                d.msix_table_size = (uint16_t)((mc & 0x7FFu) + 1u);
                fut_printf("[bcm] fn%u MSI-X cap@0x%02x: %u-entry table\n",
                           (unsigned)fn, (unsigned)d.msix_cap,
                           (unsigned)d.msix_table_size);
            }
            if (d.msi_cap == 0 && d.msix_cap == 0) {
                fut_printf("[bcm] fn%u no MSI/MSI-X capability "
                           "(unexpected for Apple PCIe)\n",
                           (unsigned)fn);
            }

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

    /* Register the BT function as an HCI transport.  Callbacks are
     * stubs returning -ENOSYS until the msgbuf ring path is wired,
     * but registration alone gives the HCI layer a real device to
     * enumerate and shows in the boot log on real hardware. */
    if (found > 0 && g_bcm.bt_present && g_bcm_hci_index < 0) {
        int idx = fut_hci_register("bcm-bt",
                                    FUT_HCI_TYPE_PCIE,
                                    &bcm_hci_ops,
                                    NULL);
        if (idx >= 0) {
            g_bcm_hci_index = idx;
            fut_printf("[bcm] HCI transport registered as hci%d "
                       "(callbacks stubbed pending firmware load)\n",
                       idx);
        } else {
            fut_printf("[bcm] HCI register failed: rc=%d\n", idx);
        }
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
     * start, then wait for internal rails to stabilize.
     *
     * Order matters: set the OUT bit BEFORE flipping OE to OUTPUT.
     * Apple pinctrl latches OUT in a separate register; if we did
     * set_direction(OUTPUT) first and the OUT register still held
     * 1 from a previous boot, the pin would briefly go HIGH before
     * we drove it LOW — a glitch the BCM chip can latch onto. */
    if (g_bcm_wlan_reset_gpio >= 0) {
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_wlan_reset_gpio, 0);
        rust_gpio_set_direction(g_bcm_gpio,
                                 (uint32_t)g_bcm_wlan_reset_gpio, 1);
        fut_platform_udelay(10u * 1000u);
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_wlan_reset_gpio, 1);
        fut_printf("[bcm] power_on: WL_REG_ON pin %d driven HIGH\n",
                   g_bcm_wlan_reset_gpio);
    }
    if (g_bcm_bt_reset_gpio >= 0) {
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_bt_reset_gpio, 0);
        rust_gpio_set_direction(g_bcm_gpio,
                                 (uint32_t)g_bcm_bt_reset_gpio, 1);
        fut_platform_udelay(10u * 1000u);
        rust_gpio_set_output(g_bcm_gpio,
                             (uint32_t)g_bcm_bt_reset_gpio, 1);
        fut_printf("[bcm] power_on: BT_REG_ON pin %d driven HIGH\n",
                   g_bcm_bt_reset_gpio);
    }

    /* Asahi waits ~150 ms after deassert for the chip's internal
     * voltage rails to settle before any further bus traffic. */
    fut_platform_udelay(150u * 1000u);
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

    fut_printf("[bcm] reset: initiating FLR via PCIe cap 0x%02x\n",
               (unsigned)cap);

    /* Read-modify-write the device control register, setting bit 15
     * to initiate FLR.  The spec guarantees the chip will accept the
     * write and complete reset within 100ms; per Broadcom's brcmfmac
     * driver, 200ms is the safe initial wait. */
    uint32_t devctl_sts = rust_apple_pcie_cfg_read32(g_bcm_pcie, bus, 0, fn,
                                                     cap + 0x08);
    rust_apple_pcie_cfg_write32(g_bcm_pcie, bus, 0, fn, cap + 0x08,
                                 devctl_sts | PCIE_DEVCTL_FLR);

    /* Initial settle delay matching brcmfmac. */
    fut_platform_udelay(200u * 1000u);

    /* Poll vendor ID up to an additional 300ms for slower chips.
     * Total budget = 200ms initial + 30 × 10ms = 500ms, well above
     * the 100ms PCIe spec guarantees for FLR completion. */
    uint16_t vid = 0;
    for (int attempt = 0; attempt < 31; attempt++) {
        uint32_t vid_did = rust_apple_pcie_cfg_read32(g_bcm_pcie,
                                                       bus, 0, fn, 0x00);
        vid = (uint16_t)(vid_did & 0xFFFFu);
        if (vid == BCM_VENDOR_ID) {
            /* PCIe spec: FLR clears the Command register on EVERY
             * function of the chip (it's chip-wide for shared logic),
             * so Bus Master Enable (bit 2) and Memory Space Enable
             * (bit 1) are now zero on BOTH fn 0 (WiFi) and fn 1
             * (Bluetooth).  Restore them on every discovered
             * function or the BT side would be silently broken
             * after a reset. */
            for (uint8_t f = 0; f < BCM_MAX_FUNCTIONS; f++) {
                uint32_t v = rust_apple_pcie_cfg_read32(g_bcm_pcie,
                                                         bus, 0, f, 0x00);
                if ((v & 0xFFFFu) != BCM_VENDOR_ID) continue;
                uint16_t cmd = rust_apple_pcie_cfg_read16(g_bcm_pcie,
                                                           bus, 0, f, 0x04);
                rust_apple_pcie_cfg_write32(g_bcm_pcie, bus, 0, f, 0x04,
                                             (uint32_t)(cmd | 0x06u));
            }
            fut_printf("[bcm] reset: FLR successful at attempt %d "
                       "(vid=0x%04x), MEM+BME restored on all functions\n",
                       attempt, vid);
            return 0;
        }
        fut_platform_udelay(10u * 1000u);
    }

    fut_printf("[bcm] reset: chip didn't return within 500ms after FLR "
               "(last vid=0x%04x)\n", vid);
    return -EIO;
}

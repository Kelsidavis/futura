# Futura OS Drivers Manifest (Updated Mar 27 2026)

This manifest reflects **what is actually present in the tree** and whether the code is **integrated into the kernel build**. Driver design/roadmap documents are listed separately.

## Kernel-Integrated Drivers (C)

These are compiled into the kernel today.

### Core devices
- `drivers/tty/` — console, line discipline, keyboard console glue
- `drivers/input/` — PS/2 keyboard + mouse
- `drivers/video/` — framebuffer device + console overlay

### Display + GPU (kernel)
- `kernel/video/virtio_gpu.c` — virtio-gpu (PCI/ECAM paths)
- `kernel/video/cirrus_vga.c` — Cirrus VGA
- `kernel/video/pci_vga.c` — PCI VGA discovery
- `kernel/video/fb_mmio.c` — MMIO framebuffer plumbing

### Storage (platform-specific)
- `platform/x86_64/drivers/ahci/` — AHCI/SATA (C implementation)
- `kernel/blockdev/` + `kernel/blk/blkcore.c` — block core + bridges

### Platform-specific drivers
- `platform/x86_64/` — APIC/LAPIC/IOAPIC, PS/2, paging, context switch, etc.
- `platform/arm64/drivers/` — Apple UART, RTKit IPC, ANS2 NVMe, DCP scaffolding, virtio-mmio

## Rust Drivers (Integrated)

Built as static libraries and linked into the kernel. Init functions called from `kernel_main.c`.

Use `make rust-drivers` to build these.

### VirtIO (both architectures)
- `virtio_blk` — block storage
- `virtio_net` — network
- `virtio_gpu` — graphics (ARM64)
- `virtio_input` — input devices
- `virtio_console` — serial console (x86_64)

### x86_64 Early Platform
- `x86_cpuid` — CPU feature identification
- `x86_tsc` — timestamp counter calibration
- `hpet` — High Precision Event Timer
- `cmos_rtc` — CMOS real-time clock
- `uart16550` — 16550 UART serial
- `i8042` — PS/2 keyboard/mouse controller

### x86_64 PCI Infrastructure
- `pcie_ecam` — PCIe ECAM configuration space
- `pci_msix` — MSI-X interrupt support
- `dma_pool` — DMA buffer allocator

### AMD Chipset (x86_64)
- `amd_smn` — System Management Network
- `amd_df` — Data Fabric
- `amd_nbio` — North Bridge I/O
- `amd_smbus` — SMBus controller
- `amd_gpio` — GPIO controller
- `amd_spi` — SPI flash controller
- `amd_i2c` — I2C controller
- `amd_iommu` — IOMMU (AMD-Vi)
- `amd_ccp` — Cryptographic Co-Processor
- `amd_psp` — Platform Security Processor
- `amd_sev` — Secure Encrypted Virtualization
- `amd_pstate` — CPU frequency scaling
- `amd_sbtsi` — SB-TSI temperature sensor
- `amd_wdt` — Watchdog timer
- `amd_mp2` — Sensor Fusion Hub
- `amd_umc` — Unified Memory Controller
- `amd_xgbe` — 10GbE Ethernet

### Intel Chipset (x86_64)
- `intel_vtd` — VT-d IOMMU
- `intel_pmc` — Power Management Controller
- `intel_gpio` — GPIO controller
- `intel_lpss` — Low Power Subsystem (UART/SPI/I2C)
- `intel_smbus` — SMBus controller
- `intel_spi` — SPI flash controller
- `intel_p2sb` — Primary-to-Sideband Bridge
- `intel_dma` — DMA engine
- `intel_hwp` — Hardware P-states (SpeedStep)
- `intel_thermal` — CPU thermal management
- `intel_wdt` — Watchdog timer
- `intel_mei` — Management Engine Interface
- `intel_tbt` — Thunderbolt controller
- `intel_sst` — Smart Sound Technology
- `intel_gna` — Gaussian & Neural Accelerator
- `intel_cnvi` — Connectivity Integration (WiFi)
- `intel_ipu` — Image Processing Unit
- `intel_hda_hdmi` — HDMI audio over HDA

### Storage (x86_64)
- `nvme` — NVMe 1.4 PCIe SSD controller

### USB (x86_64)
- `xhci` — xHCI USB 3.x host controller
- `usb_hub` — USB hub driver
- `usb_hid` — USB HID (keyboard/mouse)
- `usb_storage` — USB mass storage
- `usb_net` — USB network adapters
- `usb_audio` — USB audio class

### Network (x86_64)
- `rtl8111` — Realtek RTL8111 GbE
- `igc` — Intel I225-V 2.5GbE
- `i211` — Intel I211 GbE

### Audio (x86_64)
- `hda` — Intel HD Audio controller
- `hda_realtek` — Realtek HDA codec

### ACPI (x86_64)
- `acpi_pm` — ACPI power management
- `acpi_ec` — Embedded Controller
- `acpi_thermal` — ACPI thermal zones
- `acpi_button` — Power/sleep buttons

### Security (x86_64)
- `tpm_crb` — TPM 2.0 Command Response Buffer
- `x86_mce` — Machine Check Exception handler

### Display (x86_64)
- `vesa_fb` — VESA framebuffer

### ARM64 Apple Silicon
- `apple_aic` — Apple Interrupt Controller
- `apple_uart` — Apple UART
- `apple_rtkit` — RTKit IPC
- `apple_ans2` — ANS2 NVMe
- `apple_dart` — Device Address Resolution Table (IOMMU)
- `apple_gpio` — GPIO controller
- `apple_i2c` — I2C controller
- `apple_pcie` — PCIe host bridge
- `apple_smc` — System Management Controller
- `apple_spi` — SPI controller
- `apple_mca` — MCA audio

## Rust Drivers (Linked but NOT initialized)

These are compiled and linked but their init functions are not yet called from kernel_main.c, either due to symbol conflicts with C implementations or because they require callback arguments not yet available:

- `ahci` — conflicts with C AHCI driver (`platform/x86_64/drivers/ahci/`)
- `lapic` — conflicts with C LAPIC init (takes different signature)
- `pci_aer` — requires ECAM read callback argument
- `pci_sriov` — requires ECAM read callback argument
- `pci_pm` — PCI power management (pending integration)
- `eth_phy` — requires MDIO read/write callbacks
- `fb_console` — requires framebuffer geometry arguments
- `edid` — utility library, no standalone init

## Rust Driver Library (Scaffolding / Not Integrated)

`drivers/src/` contains **placeholder APIs and data structures** for Raspberry Pi-oriented drivers (mailbox, GPU, WiFi, Bluetooth, USB, etc.). These modules are **not wired into the kernel** and should be treated as **design scaffolding**, not production drivers.

RPi drivers in `drivers/rust/rpi_*/` are compiled but not initialized (ARM64 RPi platform init not yet implemented).

## Design & Roadmap Documents (Not Implementation)

The following docs describe targets and design intent, not shipped driver implementations:

- `drivers/GPU_DRIVER_README.md`
- `docs/GPU_DRIVER_STACK.md`
- `docs/OPENGL_ES_32_DRIVER.md`
- `docs/GPU_AUDIO_DRIVER.md`
- `docs/ETHERNET_DRIVER.md`
- `docs/WIFI_DRIVER.md`
- `docs/BLUETOOTH_DRIVER.md`
- `docs/USB_DRIVER.md`
- `docs/USB_IMPLEMENTATION_SUMMARY.md`

If any of these documents are later updated to reflect real implementations, this manifest should be updated in the same commit.

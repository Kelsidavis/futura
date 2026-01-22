# Futura OS Drivers Manifest (Audited Jan 22 2026)

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
- `platform/x86_64/drivers/ahci/` — AHCI/SATA
- `kernel/blockdev/` + `kernel/blk/blkcore.c` — block core + bridges

### Platform-specific drivers
- `platform/x86_64/` — APIC/LAPIC/IOAPIC, PS/2, paging, context switch, etc.
- `platform/arm64/drivers/` — Apple UART, RTKit IPC, ANS2 NVMe, DCP scaffolding, virtio-mmio

## Rust Virtio Drivers (Integrated)

Built as static libraries and linked into the kernel when the Rust toolchain is available:

- `drivers/rust/virtio_blk/`
- `drivers/rust/virtio_net/`
- `drivers/rust/virtio_gpu/`

Use `make rust-drivers` to build these.

## Rust Driver Library (Scaffolding / Not Integrated)

`drivers/src/` contains **placeholder APIs and data structures** for Raspberry Pi–oriented drivers (mailbox, GPU, WiFi, Bluetooth, USB, etc.). These modules are **not wired into the kernel** and should be treated as **design scaffolding**, not production drivers.

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

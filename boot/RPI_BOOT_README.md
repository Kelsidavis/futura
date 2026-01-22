# Raspberry Pi Bootloader Configuration

This directory contains bootloader configuration files and documentation for bringing up Futura OS on Raspberry Pi 3, 4, and 5 platforms.

## Overview

Raspberry Pi boards use a two-stage bootloader:
1. **GPU Firmware** (proprietary, pre-installed): Initializes hardware, loads kernel
2. **Kernel Bootloader**: Our ARM64 kernel entry point

This boot configuration bridges these two stages for all three RPi variants.

## Boot Process

### Stage 1: GPU Firmware

The GPU firmware (stored in `/boot/bootcode.bin` on the SD card) handles:
- Clock and DRAM initialization
- Loading the device tree blob (DTB)
- Loading the kernel binary (default: `kernel8.img` for 64-bit)
- Setting up initial stack and CPU registers
- Jumping to kernel entry point at EL1

### Stage 2: Kernel Entry

The kernel receives control at `kernel_main` with:
- **X0**: Physical address of device tree blob
- **X1-X3**: Reserved (must be 0)
- **Mode**: EL1 (Kernel mode)
- **Stack**: Initialized by firmware

### Stage 3: Kernel Initialization

1. **Early boot** (`platform/arm64/boot.S`):
   - Set up exception handlers (exception vectors)
   - Initialize CPU state (MAIR, TTBR registers)
   - Create page tables and enable MMU
   - Call `kernel_main()` in C code

2. **Platform detection** (`kernel/dtb/arm64_dtb.c`):
   - Parse device tree to detect RPi variant
   - Extract platform-specific information (CPU frequency, memory size)
   - Load platform-specific configuration

3. **Platform initialization** (`kernel/dtb/rpi_init.c`):
   - Initialize UART for debug output
   - Initialize interrupt controller (GIC or legacy)
   - Initialize GPIO and timers
   - Ready for multi-CPU boot

## Building for RPi

### Prerequisites

```bash
# ARM64 cross-compilation toolchain
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu gdb-multiarch

# Rust for embedded (optional, for driver development)
rustup target add aarch64-unknown-none
```

### Build Kernel

```bash
# Build for ARM64
make PLATFORM=arm64 -j4

# Output: build/kernel8.elf (for RPi64-bit boot)
```

## Memory Layout

### Raspberry Pi 3
```
0x00000000 - 0x40000000  | 1 GB RAM
0x00000000 - 0x0007FFFF  | Reserved (firmware)
0x00080000 - 0x00FFFFFF  | Kernel text/data (default)
0x01000000 - ...         | Heap/Stack
```

### Raspberry Pi 4/5
```
0x00000000 - 0x100000000 | 4-8 GB RAM
0x00000000 - 0x000FFFFF  | Reserved (firmware)
0x00080000 - 0x01FFFFFF  | Kernel text/data (default)
0x02000000 - ...         | Heap/Stack
```

## Hardware Boot

### Prerequisites

- Raspberry Pi board (3, 4, or 5)
- Micro SD card (8GB minimum)
- USB serial adapter (3.3V TTL, RX=GPIO14, TX=GPIO15)
- Power adapter (5V, appropriate amperage)

### Steps

1. **Prepare SD Card**:
   ```bash
   # Copy official firmware files to FAT32 partition
   # Download from: https://github.com/raspberrypi/firmware/tree/master/boot

   cp bootcode.bin /media/pi/boot/
   cp start*.elf /media/pi/boot/
   cp fixup*.dat /media/pi/boot/
   cp bcm*.dat /media/pi/boot/  # Optional, for clock calibration
   ```

2. **Copy Futura Kernel**:
   ```bash
   # Build kernel
   make PLATFORM=arm64 -j4

   # Copy to SD card
   cp build/kernel8.elf /media/pi/boot/kernel8.img
   ```

3. **Optional: Device Tree**:
   ```bash
   # Copy custom DTB if using modified device tree
   cp build/rpi3.dtb /media/pi/boot/  # for RPi3
   cp build/rpi4.dtb /media/pi/boot/  # for RPi4
   ```

4. **Boot Configuration** (`config.txt`):
   ```ini
   # Add to /boot/config.txt on SD card
   arm_64bit=1
   kernel=kernel8.img

   # Optional overrides
   dtoverlay=disable-bt        # Disable Bluetooth if not needed
   dtoverlay=disable-wifi      # Disable WiFi if not needed
   disable_commandline_tags=1  # Disable kernel command line if not supported
   ```

5. **Connect Serial Console**:
   ```bash
   # GPIO14/GPIO15 to USB serial adapter
   # Use minicom or screen to monitor boot output
   minicom -D /dev/ttyUSB0 -b 115200
   ```

6. **Insert SD Card and Power On**
   - Monitor serial output for kernel boot messages
   - Check for DTB parsing and platform initialization messages

## QEMU Testing

Test the kernel on QEMU before deploying to hardware:

```bash
# Build kernel
make PLATFORM=arm64 -j4

# Raspberry Pi 3 emulation
qemu-system-aarch64 \
    -M raspi3b \
    -cpu cortex-a53 \
    -m 1G \
    -kernel build/kernel8.elf \
    -dtb build/rpi3.dtb \
    -serial stdio

# Raspberry Pi 4 emulation
qemu-system-aarch64 \
    -M raspi4b \
    -cpu cortex-a72 \
    -m 4G \
    -kernel build/kernel8.elf \
    -dtb build/rpi4.dtb \
    -serial stdio
```

## Boot Configuration Files

- **`rpi.ld`**: Linker script defining kernel memory layout for RPi variants
- **`rpi_boot.h`**: Boot protocol definitions and memory configuration macros
- **`RPI_BOOT_README.md`**: This file

## Troubleshooting

### Kernel doesn't boot
- Check DTB is in correct memory location (usually low address)
- Verify kernel binary is at correct offset (0x80000)
- Check UART is initialized (serial console will show boot messages)

### DTB parsing fails
- Ensure DTB magic (0xd00dfeed) is correct
- Check DTB is valid FDT format
- Verify boot firmware passes correct address in X0

### Platform detection fails
- Check device tree "compatible" property matches RPi variant
- Verify platform detection code covers all variants
- Add debug output to DTB parser

### Serial console no output
- Check baud rate (default 115200)
- Verify GPIO14/GPIO15 wiring
- Enable UART in config.txt: `enable_uart=1`

## References

- [Raspberry Pi Architecture Documentation](https://github.com/raspberrypi/firmware/wiki)
- [ARM64 EBBR Boot Specification](https://github.com/ARM-software/ebbr)
- [ARM GIC Interrupt Controller](https://developer.arm.com/documentation/ihi0048/latest)
- [ARM Generic Timer](https://developer.arm.com/documentation/ddi0467/latest)

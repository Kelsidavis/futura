#!/usr/bin/env bash
# create-m1n1-payload.sh - Create m1n1-compatible kernel payload
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Converts Futura kernel ELF to m1n1-compatible ARM64 Linux Image format.
# m1n1 is the Asahi Linux bootloader for Apple Silicon Macs.
#
# Usage:
#   ./scripts/create-m1n1-payload.sh [kernel.elf] [output-dir]
#
# Outputs:
#   - Image      : Raw kernel binary with ARM64 Linux header
#   - Image.gz   : Gzipped kernel image (recommended for m1n1)
#
# Loading with m1n1:
#   1. Tethered boot (development):
#      python3 -m m1n1.run m1n1.macho -b 'Image.gz;fdt.dtb' kernel.macho
#
#   2. Concatenate payloads (production):
#      cat m1n1.macho Image.gz fdt.dtb > m1n1-payload.macho
#      Then install to /boot partition
#
# References:
#   - https://github.com/AsahiLinux/m1n1
#   - https://asahilinux.org/docs/sw/m1n1-user-guide/

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths
KERNEL_ELF="${1:-build/bin/futura_kernel.elf}"
OUTPUT_DIR="${2:-build/m1n1}"

# Check if kernel ELF exists
if [ ! -f "$KERNEL_ELF" ]; then
    echo -e "${RED}Error: Kernel ELF not found: $KERNEL_ELF${NC}"
    echo "Usage: $0 [kernel.elf] [output-dir]"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}=== Futura OS - m1n1 Payload Builder ===${NC}"
echo -e "Kernel ELF: ${GREEN}$KERNEL_ELF${NC}"
echo -e "Output dir: ${GREEN}$OUTPUT_DIR${NC}"
echo ""

# Step 1: Extract raw binary from ELF
echo -e "${YELLOW}[1/3]${NC} Extracting raw kernel binary (Image)..."

# Try to find objcopy (prefer aarch64-specific, fallback to system)
OBJCOPY=""
for tool in aarch64-elf-objcopy aarch64-linux-gnu-objcopy llvm-objcopy objcopy; do
    if command -v $tool &> /dev/null; then
        OBJCOPY=$tool
        break
    fi
done

if [ -z "$OBJCOPY" ]; then
    echo -e "${RED}Error: objcopy not found${NC}"
    echo "Please install binutils or llvm toolchain"
    echo "  macOS: brew install aarch64-elf-binutils"
    echo "  Linux: apt install binutils-aarch64-linux-gnu"
    exit 1
fi

$OBJCOPY -O binary "$KERNEL_ELF" "$OUTPUT_DIR/Image"

if [ ! -f "$OUTPUT_DIR/Image" ]; then
    echo -e "${RED}Error: Failed to create Image${NC}"
    exit 1
fi

IMAGE_SIZE=$(stat -f%z "$OUTPUT_DIR/Image" 2>/dev/null || stat -c%s "$OUTPUT_DIR/Image")
echo -e "   ${GREEN}✓${NC} Image created: $(numfmt --to=iec-i --suffix=B $IMAGE_SIZE 2>/dev/null || echo $IMAGE_SIZE bytes)"

# Verify ARM64 Linux header magic
MAGIC=$(xxd -p -l 4 -s 0x38 "$OUTPUT_DIR/Image" | tr -d '\n')
if [ "$MAGIC" != "4152 4d64" ] && [ "$MAGIC" != "41524d64" ]; then
    echo -e "${YELLOW}Warning: ARM64 Linux magic not found at offset 0x38${NC}"
    echo -e "   Expected: 0x644d5241 (\"ARM\\x64\")"
    echo -e "   Found:    0x$(echo $MAGIC | sed 's/ //g')"
    echo -e "   ${YELLOW}This may cause issues with some bootloaders${NC}"
else
    echo -e "   ${GREEN}✓${NC} ARM64 Linux header verified (magic: 0x644d5241)"
fi

# Step 2: Compress to Image.gz
echo -e "${YELLOW}[2/3]${NC} Compressing kernel image (Image.gz)..."
gzip -9 -c "$OUTPUT_DIR/Image" > "$OUTPUT_DIR/Image.gz"

if [ ! -f "$OUTPUT_DIR/Image.gz" ]; then
    echo -e "${RED}Error: Failed to create Image.gz${NC}"
    exit 1
fi

GZ_SIZE=$(stat -f%z "$OUTPUT_DIR/Image.gz" 2>/dev/null || stat -c%s "$OUTPUT_DIR/Image.gz")
RATIO=$(awk "BEGIN {printf \"%.1f\", ($IMAGE_SIZE - $GZ_SIZE) / $IMAGE_SIZE * 100}")
echo -e "   ${GREEN}✓${NC} Image.gz created: $(numfmt --to=iec-i --suffix=B $GZ_SIZE 2>/dev/null || echo $GZ_SIZE bytes) (${RATIO}% reduction)"

# Step 3: Generate usage instructions
echo -e "${YELLOW}[3/3]${NC} Generating usage instructions..."

cat > "$OUTPUT_DIR/README.txt" <<EOF
Futura OS - m1n1 Payload Instructions
=====================================

Generated: $(date)
Kernel: $KERNEL_ELF

Files:
------
- Image      : Raw kernel binary with ARM64 Linux header
- Image.gz   : Gzipped kernel image (RECOMMENDED for m1n1)

Loading with m1n1:
------------------

## Method 1: Tethered Boot (Development)

Use m1n1's Python tools for rapid iteration during development:

    # Boot kernel only (m1n1 provides device tree)
    python3 -m m1n1.run m1n1.macho -b Image.gz kernel.macho

    # Boot with custom device tree
    python3 -m m1n1.run m1n1.macho -b 'Image.gz;custom.dtb' kernel.macho

    # Debug with UART console
    python3 -m m1n1.run m1n1.macho -b Image.gz kernel.macho -s /dev/ttyACM0

## Method 2: Concatenated Payload (Production)

Create a single bootable image for installation:

    # Concatenate m1n1 + kernel + device tree
    cat m1n1.macho Image.gz fdt.dtb > m1n1-payload.macho

    # Or just kernel (m1n1 auto-detects DTB from system)
    cat m1n1.macho Image.gz > m1n1-payload.macho

    # Install to /boot partition (requires root on macOS)
    sudo kmutil configure-boot -c m1n1-payload.macho -v /Volumes/BOOTVOLUME

## Method 3: U-Boot Chainload (Advanced)

Use m1n1 to chainload U-Boot, then boot kernel:

    cat m1n1.macho u-boot-nodtb.bin > m1n1-uboot.macho
    # Then use U-Boot 'booti' command to load Image.gz

Device Tree Blob (DTB):
-----------------------

m1n1 passes the Apple device tree in X0 at boot. Futura's device tree
parser (kernel/dtb/arm64_dtb.c) will:
  - Detect Apple M1/M2/M3 platforms
  - Extract hardware addresses (UART, AIC, ANS mailbox, NVMe)
  - Initialize platform-specific drivers

If you need a custom DTB:
  1. Extract from m1n1: python3 -m m1n1.run m1n1.macho --dump-fdt fdt.dtb
  2. Decompile: dtc -I dtb -O dts fdt.dtb > fdt.dts
  3. Modify and recompile: dtc -I dts -O dtb fdt.dts > custom.dtb
  4. Boot with: python3 -m m1n1.run m1n1.macho -b 'Image.gz;custom.dtb' kernel.macho

Troubleshooting:
----------------

### Kernel doesn't boot
- Check UART output for early boot messages
- Verify ARM64 Linux header: xxd -l 64 Image
- Ensure m1n1.macho is from Asahi Linux release (not development build)

### No console output
- Apple UART requires USB-C connection and special activation
- Try HDMI output if Display Coprocessor (DCP) driver is loaded
- Check m1n1 hypervisor console for kernel panic messages

### Device tree issues
- Verify DTB magic: xxd -l 4 fdt.dtb (should be d0 0d fe ed)
- Check m1n1 passes DTB in X0 (enable DEBUG_DTB in kernel)
- Ensure compatible strings match (apple,t8112 for M2)

References:
-----------
- m1n1 GitHub: https://github.com/AsahiLinux/m1n1
- User Guide: https://asahilinux.org/docs/sw/m1n1-user-guide/
- Futura Docs: docs/APPLE_SILICON_ROADMAP.md

EOF

echo -e "   ${GREEN}✓${NC} README.txt created"

# Summary
echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo -e "Output files:"
echo -e "  ${BLUE}Image${NC}      : $OUTPUT_DIR/Image"
echo -e "  ${BLUE}Image.gz${NC}   : $OUTPUT_DIR/Image.gz  ${YELLOW}<-- Use this with m1n1${NC}"
echo -e "  ${BLUE}README.txt${NC} : $OUTPUT_DIR/README.txt"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Get m1n1.macho from Asahi Linux: ${BLUE}https://github.com/AsahiLinux/m1n1/releases${NC}"
echo -e "  2. Tethered boot for testing:"
echo -e "     ${GREEN}python3 -m m1n1.run m1n1.macho -b $OUTPUT_DIR/Image.gz kernel.macho${NC}"
echo -e "  3. Create bootable payload:"
echo -e "     ${GREEN}cat m1n1.macho $OUTPUT_DIR/Image.gz > m1n1-payload.macho${NC}"
echo ""

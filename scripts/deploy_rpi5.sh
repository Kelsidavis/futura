#!/bin/bash
# Deploy Futura OS ARM64 kernel to Raspberry Pi 5 USB device
# Usage: sudo bash deploy_to_usb.sh /dev/sdd

set -e

TARGET_DEVICE="${1:-/dev/sdd}"
FUTURA_ROOT="/home/k/futura"
KERNEL_ELF="${FUTURA_ROOT}/build/bin/futura_kernel.elf"
IMAGE_FILE="/tmp/futura_rpi5.img"
IMAGE_SIZE=4G

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Futura OS - Raspberry Pi 5 USB Deployment${NC}"
echo "Target Device: $TARGET_DEVICE"
echo "Kernel: $KERNEL_ELF"
echo ""

# Safety checks
if [[ ! -b "$TARGET_DEVICE" ]]; then
    echo -e "${RED}ERROR: $TARGET_DEVICE is not a valid block device${NC}"
    echo "Available USB devices:"
    lsblk -d -o NAME,SIZE,MODEL | grep -E "sd[a-z]"
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}ERROR: This script requires root privileges${NC}"
    echo "Run with: sudo bash $0 $TARGET_DEVICE"
    exit 1
fi

if [[ ! -f "$KERNEL_ELF" ]]; then
    echo -e "${YELLOW}WARNING: Kernel not found at $KERNEL_ELF${NC}"
    echo "Building ARM64 kernel..."
    cd "$FUTURA_ROOT"
    make clean PLATFORM=arm64
    make PLATFORM=arm64 -j4
fi

echo -e "${YELLOW}Creating bootable image...${NC}"

# 1. Unmount any existing partitions
echo "[1/7] Unmounting existing partitions..."
for partition in ${TARGET_DEVICE}*; do
    if mountpoint -q "$partition" 2>/dev/null; then
        echo "  Unmounting $partition..."
        umount "$partition" || true
    fi
done

# 2. Create image file (sparse allocation for speed)
echo "[2/7] Creating 4GB image file..."
truncate -s 4G "$IMAGE_FILE"

# 3. Create partition table
echo "[3/7] Creating partition table..."
parted -s "$IMAGE_FILE" mklabel msdos
parted -s "$IMAGE_FILE" mkpart primary fat32 1MiB 512MiB
parted -s "$IMAGE_FILE" mkpart primary ext4 512MiB 100%
parted -s "$IMAGE_FILE" set 1 boot on

# 4. Format with loop device (using kpartx for better partition handling)
echo "[4/7] Formatting partitions..."
kpartx -a "$IMAGE_FILE" 2>/dev/null || true
sleep 2

# Get the device mapper paths
LOOP_BOOT="/dev/mapper/$(basename "$IMAGE_FILE")p1"
LOOP_ROOT="/dev/mapper/$(basename "$IMAGE_FILE")p2"

# If kpartx didn't work, try direct loop device
if [[ ! -e "$LOOP_BOOT" ]]; then
    echo "  Using direct loop device..."
    LOOP=$(losetup -f)
    losetup "$LOOP" "$IMAGE_FILE"
    LOOP_BOOT="${LOOP}p1"
    LOOP_ROOT="${LOOP}p2"
fi

# Format partitions
mkfs.vfat -F 32 "$LOOP_BOOT" 2>/dev/null || true
mkfs.ext4 -F "$LOOP_ROOT" 2>/dev/null || true

# 5. Mount and populate boot partition
echo "[5/7] Installing boot files..."
BOOT_MNT=$(mktemp -d)
mount "$LOOP_BOOT" "$BOOT_MNT"

# Raspberry Pi 5 boot configuration
cat > "$BOOT_MNT/config.txt" << 'EOF'
[pi5]
# Raspberry Pi 5 Configuration
kernel=futura_kernel.elf
arm_64bit=1
enable_uart=1
uart_2ndstage=1
dtoverlay=disable-bt
dtoverlay=disable-wifi
EOF

# Copy kernel if built
if [[ -f "$KERNEL_ELF" ]]; then
    cp "$KERNEL_ELF" "$BOOT_MNT/futura_kernel.elf"
    echo "  ✓ Copied kernel to boot partition"
fi

# Create boot marker file
echo "Futura OS ARM64 - $(date)" > "$BOOT_MNT/FUTURA_BOOT"

umount "$BOOT_MNT"
rmdir "$BOOT_MNT"

# 6. Create root filesystem
echo "[6/7] Creating root filesystem..."
ROOT_MNT=$(mktemp -d)
mount "$LOOP_ROOT" "$ROOT_MNT"

# Minimal directory structure
for dir in bin sbin lib lib64 usr usr/bin usr/sbin usr/lib usr/local \
           etc tmp var var/log proc sys dev home root boot; do
    mkdir -p "$ROOT_MNT/$dir"
done

# Create basic files
echo "Futura OS" > "$ROOT_MNT/etc/hostname"
cat > "$ROOT_MNT/etc/os-release" << 'EOF'
NAME="Futura OS"
VERSION="1.0-arm64"
PRETTY_NAME="Futura OS (ARM64)"
ID=futura
HOME_URL="https://github.com/kelsi-davis/futura"
PLATFORM="Raspberry Pi 5"
EOF

umount "$ROOT_MNT"
rmdir "$ROOT_MNT"

# 7. Deploy to USB device
echo "[7/7] Deploying image to $TARGET_DEVICE..."
echo -e "${RED}WARNING: This will overwrite $TARGET_DEVICE!${NC}"
echo "Press Ctrl+C to cancel, or press Enter to continue..."
read -r

# Clean existing partition table
dd if=/dev/zero of="$TARGET_DEVICE" bs=512 count=2048 2>/dev/null

# Write image to device
dd if="$IMAGE_FILE" of="$TARGET_DEVICE" bs=4M status=progress
sync

# Cleanup
kpartx -d "$IMAGE_FILE" 2>/dev/null || true
rm -f "$IMAGE_FILE"

echo -e "${GREEN}✓ Successfully deployed to $TARGET_DEVICE${NC}"
echo ""
echo "Next steps:"
echo "1. Eject the USB device: sudo eject $TARGET_DEVICE"
echo "2. Insert into Raspberry Pi 5"
echo "3. Boot from USB (may require EEPROM configuration)"
echo ""
echo "For more details, visit:"
echo "  https://www.raspberrypi.com/documentation/computers/raspberry-pi.html"

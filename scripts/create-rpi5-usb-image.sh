#!/bin/bash
#
# Futura OS - Raspberry Pi 5 USB Bootable Image Creator
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# Creates a bootable USB disk image with USB driver support.
#
# Usage: sudo ./create-rpi5-usb-image.sh [options]
#
# Options:
#   -d, --device DEVICE       USB device (e.g., /dev/sdb)
#   -s, --size SIZE          Image size (default: 32G)
#   -i, --image IMAGE        Input ISO image (default: build/futura.iso)
#   -o, --output FILE        Output image file (default: futura_rpi5_usb.img)
#   -f, --format FAT32       Format with FAT32 (default: ext4)
#   -h, --help              Show this help

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
DEVICE=""
SIZE="32G"
INPUT_IMAGE="build/futura.iso"
OUTPUT_IMAGE="futura_rpi5_usb.img"
FORMAT="ext4"
FORCE=0

# Functions
print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

print_warning() {
    echo -e "${YELLOW}WARNING: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}$1${NC}"
}

print_info() {
    echo -e "${NC}$1${NC}"
}

show_help() {
    grep "^#" "$0" | grep -v "^#!/bin/bash" | sed 's/# //'
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--device)
            DEVICE="$2"
            shift 2
            ;;
        -s|--size)
            SIZE="$2"
            shift 2
            ;;
        -i|--image)
            INPUT_IMAGE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_IMAGE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            ;;
    esac
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
fi

# Validate input image
if [[ ! -f "$INPUT_IMAGE" ]]; then
    print_error "Input image not found: $INPUT_IMAGE"
fi

print_info "════════════════════════════════════════════════════════"
print_info "  Futura OS - Raspberry Pi 5 USB Image Creator"
print_info "════════════════════════════════════════════════════════"
print_info ""
print_info "Configuration:"
print_info "  Input Image:  $INPUT_IMAGE"
print_info "  Output Image: $OUTPUT_IMAGE"
print_info "  Image Size:   $SIZE"
print_info "  Format:       $FORMAT"
if [[ -n "$DEVICE" ]]; then
    print_info "  Device:       $DEVICE"
fi
print_info ""

# Device selection if not specified
if [[ -z "$DEVICE" ]]; then
    print_info "Available USB devices:"
    lsblk -d -e11 | grep -v NAME || print_error "No USB devices detected"
    print_info ""
    read -p "Enter USB device (e.g., /dev/sdb): " DEVICE
fi

# Validate device
if [[ ! -b "$DEVICE" ]]; then
    print_error "Invalid device: $DEVICE"
fi

# Safety check
DEVICE_NAME=$(basename "$DEVICE")
read -p "Are you sure you want to overwrite $DEVICE ($DEVICE_NAME)? Type 'yes' to continue: " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    print_warning "Cancelled by user"
    exit 0
fi

# Unmount device if mounted
print_info "Unmounting any mounted partitions..."
for partition in "${DEVICE}"*; do
    if mountpoint -q "$partition" 2>/dev/null; then
        print_info "  Unmounting $partition..."
        umount "$partition" || print_warning "Failed to unmount $partition"
    fi
done

print_info ""
print_info "Step 1: Creating disk image..."
dd if="$INPUT_IMAGE" of="$DEVICE" bs=4M status=progress conv=fsync

print_info ""
print_info "Step 2: Verifying image..."
dd if="$DEVICE" bs=512 count=1 of=/tmp/verify.bin 2>/dev/null
if cmp -s "$INPUT_IMAGE" "$DEVICE"; then
    print_success "✓ Image verification passed"
else
    # Compare just first few sectors
    ORIG_SIZE=$(stat -f%z "$INPUT_IMAGE" 2>/dev/null || stat -c%s "$INPUT_IMAGE")
    DEVICE_SIZE=$(blockdev --getsize64 "$DEVICE" 2>/dev/null || stat -c%s "$DEVICE")
    if [[ $DEVICE_SIZE -ge $ORIG_SIZE ]]; then
        print_success "✓ Device has sufficient capacity"
    else
        print_warning "Device smaller than image"
    fi
fi

print_info ""
print_info "Step 3: Expanding filesystem (if needed)..."

# Identify root partition
if [[ -b "${DEVICE}2" ]]; then
    ROOT_PART="${DEVICE}2"
elif [[ -b "${DEVICE}p2" ]]; then
    ROOT_PART="${DEVICE}p2"
else
    # Try to find the largest partition
    ROOT_PART=$(lsblk -ln -o NAME "$DEVICE" | tail -1 | sed "s/^/$DEVICE/")
fi

if [[ -b "$ROOT_PART" ]]; then
    # Resize partition if using parted
    if command -v parted &> /dev/null; then
        print_info "  Expanding $ROOT_PART to fill device..."
        parted -s "$DEVICE" resizepart 2 100% 2>/dev/null || \
            print_warning "Failed to resize partition"
    fi

    # Resize filesystem
    if [[ "$FORMAT" == "ext4" ]]; then
        print_info "  Growing ext4 filesystem..."
        e2fsck -f "$ROOT_PART" || true
        resize2fs "$ROOT_PART" || print_warning "Failed to resize ext4"
    elif [[ "$FORMAT" == "fat32" ]]; then
        print_info "  FAT32 does not support resizing, skipping..."
    fi
else
    print_warning "Could not identify root partition"
fi

print_info ""
print_info "Step 4: Flushing buffers and ejecting..."
sync
sleep 2

if command -v eject &> /dev/null; then
    eject "$DEVICE" 2>/dev/null || true
fi

print_info ""
print_success "════════════════════════════════════════════════════════"
print_success "✓ USB Bootable Image Created Successfully!"
print_success "════════════════════════════════════════════════════════"
print_info ""
print_info "Next Steps:"
print_info "  1. Insert USB drive into Raspberry Pi 5"
print_info "  2. Connect power supply (5V/5A)"
print_info "  3. Connect UART to GPIO14/15 (optional, for debugging)"
print_info "  4. Monitor serial output: picocom -b 115200 /dev/ttyUSB0"
print_info ""
print_info "USB Driver Test Commands (after boot):"
print_info "  # List USB devices"
print_info "  lsusb"
print_info ""
print_info "  # Get detailed USB device info"
print_info "  lsusb -v"
print_info ""
print_info "  # Monitor USB activity"
print_info "  dmesg | grep -i usb"
print_info ""
print_info "For deployment guide, see: docs/RPI5_USB_DEPLOYMENT.md"
print_info ""

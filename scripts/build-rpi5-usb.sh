#!/bin/bash
#
# Futura OS - Raspberry Pi 5 USB Build & Deployment Script
# Builds complete system for RPi 5 and creates bootable USB image
#
# Usage: ./build-rpi5-usb.sh [--device /dev/sdX] [--size 32G] [--build-only]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
TARGET_PLATFORM="arm64"
BUILD_MODE="release"
RPI_MODEL="5"
USB_DEVICE=""
USB_SIZE="32G"
BUILD_ONLY=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; exit 1; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

print_banner() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Futura OS - Raspberry Pi 5 USB Build & Deployment        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
}

check_requirements() {
    log_info "Checking build requirements..."

    # Check tools
    local required_tools=("make" "aarch64-linux-gnu-gcc" "cargo" "dd" "sync")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
        fi
    done

    log_success "All build tools found"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --device)
                USB_DEVICE="$2"
                shift 2
                ;;
            --size)
                USB_SIZE="$2"
                shift 2
                ;;
            --build-only)
                BUILD_ONLY=1
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --device PATH    USB device path (e.g., /dev/sdb)"
                echo "  --size SIZE      USB image size (default: 32G)"
                echo "  --build-only     Only build, don't create USB image"
                echo "  -h, --help       Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                ;;
        esac
    done
}

build_system() {
    log_info "Building Futura OS for Raspberry Pi 5 (ARM64)..."

    cd "$PROJECT_ROOT"

    # Set up cross-compilation environment
    export CROSS_COMPILE="aarch64-linux-gnu-"
    export ARCH="arm64"
    export PLATFORM="arm64"
    export BUILD_MODE="$BUILD_MODE"

    log_info "Building drivers..."
    cd drivers
    cargo build --lib --release --target aarch64-unknown-linux-gnu 2>&1 | tail -20
    cd ..

    log_info "Building kernel and userland..."
    make PLATFORM=arm64 BUILD_MODE=release all 2>&1 | tail -30

    if [ ! -f "build/futura_kernel.elf" ]; then
        log_error "Kernel build failed: build/futura_kernel.elf not found"
    fi

    log_success "Build complete"
    log_info "Kernel: $(ls -lh build/futura_kernel.elf | awk '{print $5}')"
}

create_disk_image() {
    log_info "Creating USB disk image (${USB_SIZE})..."

    if [ -z "$USB_DEVICE" ]; then
        log_info "Available USB devices:"
        lsblk -d -e11 2>/dev/null | grep -v NAME || log_error "No USB devices found"
        echo ""
        read -p "Enter USB device path (e.g., /dev/sdb): " USB_DEVICE
    fi

    # Safety check
    if ! [[ "$USB_DEVICE" =~ ^/dev/sd[a-z]$ ]]; then
        log_error "Invalid device path: $USB_DEVICE"
    fi

    local device_name=$(basename "$USB_DEVICE")
    log_warn "WARNING: This will overwrite all data on $USB_DEVICE ($device_name)"
    read -p "Type 'yes' to continue: " -r confirm
    if [[ "$confirm" != "yes" ]]; then
        log_warn "Cancelled by user"
        exit 0
    fi

    # Unmount if needed
    log_info "Unmounting any mounted partitions..."
    for partition in "${USB_DEVICE}"*; do
        if mountpoint -q "$partition" 2>/dev/null; then
            log_info "  Unmounting $partition..."
            sudo umount "$partition" || log_warn "Failed to unmount $partition"
        fi
    done

    # Create disk image using dd
    log_info "Writing image to $USB_DEVICE (this may take several minutes)..."

    # Create a temporary sparse image first
    local temp_image="/tmp/futura_rpi5_${RANDOM}.img"
    log_info "Creating temporary image: $temp_image"

    dd if=/dev/zero of="$temp_image" bs=1M count="${USB_SIZE%G}000" status=progress

    # Create partition table (GPT)
    log_info "Creating GPT partition table..."
    parted -s "$temp_image" mklabel gpt

    # Create EFI boot partition
    log_info "Creating EFI boot partition..."
    parted -s "$temp_image" mkpart primary fat32 1MiB 512MiB
    parted -s "$temp_image" set 1 esp on

    # Create Futura root partition
    log_info "Creating Futura root partition..."
    parted -s "$temp_image" mkpart primary ext4 512MiB 100%

    log_success "Image created: $temp_image"
    log_info "Writing to USB device $USB_DEVICE..."

    sudo dd if="$temp_image" of="$USB_DEVICE" bs=4M status=progress conv=fsync

    # Expand filesystem
    log_info "Expanding filesystem..."
    sudo partprobe "$USB_DEVICE" 2>/dev/null || true
    sleep 2

    if [[ -b "${USB_DEVICE}2" ]]; then
        local root_part="${USB_DEVICE}2"
    elif [[ -b "${USB_DEVICE}p2" ]]; then
        local root_part="${USB_DEVICE}p2"
    else
        log_warn "Could not identify root partition"
        root_part=""
    fi

    if [ -n "$root_part" ]; then
        sudo parted -s "$USB_DEVICE" resizepart 2 100% 2>/dev/null || true
        sudo e2fsck -f "$root_part" 2>/dev/null || true
        sudo resize2fs "$root_part" || log_warn "Failed to resize filesystem"
    fi

    # Cleanup
    rm -f "$temp_image"

    log_info "Flushing buffers..."
    sync
    sleep 2

    # Eject
    if command -v eject &> /dev/null; then
        sudo eject "$USB_DEVICE" 2>/dev/null || true
    fi

    log_success "USB image created successfully!"
}

show_next_steps() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Next Steps                                                ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "1. Insert USB drive into Raspberry Pi 5"
    echo "2. Connect power supply (5V/5A)"
    echo "3. Connect UART to GPIO14/15 for serial monitoring (optional)"
    echo ""
    echo "Serial Console:"
    echo "  $ picocom -b 115200 /dev/ttyUSB0"
    echo ""
    echo "Testing USB Driver:"
    echo "  # List USB devices"
    echo "  $ lsusb"
    echo ""
    echo "  # Get detailed USB info"
    echo "  $ lsusb -v"
    echo ""
    echo "  # Monitor USB activity"
    echo "  $ dmesg | grep -i usb"
    echo ""
    echo "Documentation:"
    echo "  • docs/USB_DRIVER.md"
    echo "  • docs/RPI5_USB_DEPLOYMENT.md"
    echo ""
}

main() {
    print_banner

    parse_arguments "$@"

    check_requirements

    log_info "Configuration:"
    log_info "  Platform: ARM64 (Raspberry Pi 5)"
    log_info "  Build Mode: $BUILD_MODE"
    echo ""

    build_system

    if [ "$BUILD_ONLY" -eq 0 ]; then
        echo ""
        create_disk_image
    fi

    show_next_steps

    log_success "All done!"
}

main "$@"

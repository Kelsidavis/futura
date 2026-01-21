#!/bin/bash
# Asahi Linux External Drive Setup Script
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# WARNING: This will ERASE /dev/disk4 completely!

set -e

echo "=== Asahi Linux External Drive Setup ==="
echo "Target: /dev/disk4 (256.1 GB)"
echo ""
echo "This will ERASE ALL DATA on /dev/disk4!"
read -p "Press Enter to continue or Ctrl+C to abort..."

# Step 1: Partition the drive
echo ""
echo "[1/5] Partitioning external drive..."
sudo diskutil partitionDisk /dev/disk4 GPT APFS "AsahiBoot" 500M ExFAT "AsahiLinux" 0b

# Step 2: Install m1n1 bootloader
echo ""
echo "[2/5] Installing m1n1 bootloader..."
sudo kmutil configure-boot -c m1n1.macho -v /Volumes/AsahiBoot

# Step 3: Download Asahi Linux components
echo ""
echo "[3/5] Downloading Asahi Linux components..."
echo "Fetching latest kernel and U-Boot..."

# Create temporary directory
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Download Asahi Linux kernel package (using Fedora Asahi Remix repos)
echo "Downloading kernel package..."
curl -L -o kernel.tar.gz "https://cdn.asahilinux.org/installer/kernel.tar.gz" 2>/dev/null || {
    echo "Note: Using alternative download method..."
    # Alternative: download from GitHub releases
    curl -L -o kernel.tar.gz "https://github.com/AsahiLinux/linux/releases/latest/download/kernel.tar.gz" 2>/dev/null || {
        echo "ERROR: Could not download kernel package"
        echo "You may need to manually download from: https://asahilinux.org/downloads/"
        exit 1
    }
}

# Step 4: Format Linux partition as ext4
echo ""
echo "[4/5] Formatting Linux partition..."
# First, identify the Linux partition
LINUX_PARTITION=$(diskutil list /dev/disk4 | grep "AsahiLinux" | awk '{print $NF}')
echo "Linux partition: /dev/$LINUX_PARTITION"

# Unmount it first
diskutil unmount /dev/$LINUX_PARTITION || true

# Format as ext4 (need to use diskutil eraseVolume with a different approach)
# Note: macOS doesn't natively support ext4 formatting, so we'll leave it for Linux installer
echo "Note: Linux partition will need to be formatted from a Linux environment"
echo "The partition is ready at /dev/$LINUX_PARTITION"

# Step 5: Summary
echo ""
echo "[5/5] Setup Summary"
echo "===================="
echo "✓ Boot partition (APFS): /Volumes/AsahiBoot"
echo "✓ m1n1 bootloader: Installed"
echo "✓ Linux partition: /dev/$LINUX_PARTITION (needs ext4 formatting)"
echo ""
echo "Next steps:"
echo "1. Download Asahi Linux rootfs: https://fedora-asahi-remix.org/"
echo "2. Boot from external drive (hold power button, select AsahiBoot)"
echo "3. Install Linux to /dev/$LINUX_PARTITION"
echo ""
echo "Temporary files in: $TMPDIR"

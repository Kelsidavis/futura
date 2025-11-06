#!/usr/bin/env bash
# test-on-m2.sh - Quick tethered boot testing for Apple Silicon M2
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# This script automates tethered boot testing on MacBook Pro A2338 (M2).
# Completely non-destructive - no installation or storage modification.
#
# Requirements:
#   - MacBook Pro M2 in DFU mode
#   - USB-C cable connecting to this Mac
#   - m1n1 bootloader (m1n1.macho)
#   - Python 3 with m1n1 module installed
#
# Usage:
#   ./scripts/test-on-m2.sh [options]
#
# Options:
#   --build        Build kernel before testing
#   --verbose      Enable verbose m1n1 output
#   --console      Connect to serial console after boot
#   --help         Show this help message

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
M1N1_MACHO="${M1N1_MACHO:-$PROJECT_ROOT/m1n1.macho}"
KERNEL_IMAGE="$PROJECT_ROOT/build/m1n1/Image.gz"

# Options
BUILD=false
VERBOSE=false
CONSOLE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --console)
            CONSOLE=true
            shift
            ;;
        --help)
            head -n 30 "$0" | grep "^#" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}=====================================${NC}"
echo -e "${CYAN}  Futura OS - M2 Tethered Boot Test${NC}"
echo -e "${CYAN}=====================================${NC}"
echo ""

# Step 1: Build kernel if requested
if [ "$BUILD" = true ]; then
    echo -e "${BLUE}[1/5]${NC} Building ARM64 kernel..."
    cd "$PROJECT_ROOT"
    make PLATFORM=arm64 kernel
    make m1n1-payload
    echo -e "   ${GREEN}✓${NC} Build complete"
else
    echo -e "${BLUE}[1/5]${NC} Skipping build (use --build to rebuild)"
fi
echo ""

# Step 2: Check for m1n1 bootloader
echo -e "${BLUE}[2/5]${NC} Checking for m1n1 bootloader..."
if [ ! -f "$M1N1_MACHO" ]; then
    echo -e "   ${YELLOW}⚠${NC}  m1n1.macho not found at: $M1N1_MACHO"
    echo ""
    echo -e "   ${CYAN}Download m1n1.macho:${NC}"
    echo -e "   ${GREEN}curl -L https://github.com/AsahiLinux/m1n1/releases/latest/download/m1n1.macho -o m1n1.macho${NC}"
    echo ""
    exit 1
fi
echo -e "   ${GREEN}✓${NC} m1n1.macho found: $M1N1_MACHO"
echo ""

# Step 3: Check for kernel image
echo -e "${BLUE}[3/5]${NC} Checking for Futura kernel..."
if [ ! -f "$KERNEL_IMAGE" ]; then
    echo -e "   ${RED}✗${NC} Kernel image not found: $KERNEL_IMAGE"
    echo -e "   Run with ${GREEN}--build${NC} to build the kernel"
    exit 1
fi
KERNEL_SIZE=$(stat -f%z "$KERNEL_IMAGE" 2>/dev/null || stat -c%s "$KERNEL_IMAGE")
echo -e "   ${GREEN}✓${NC} Kernel image found: $(numfmt --to=iec-i --suffix=B $KERNEL_SIZE 2>/dev/null || echo $KERNEL_SIZE bytes)"
echo ""

# Step 4: Check for Python m1n1 module
echo -e "${BLUE}[4/5]${NC} Checking for m1n1 Python module..."
if python3 -c "import m1n1" 2>/dev/null; then
    M1N1_VERSION=$(python3 -c "import m1n1; print(m1n1.__version__ if hasattr(m1n1, '__version__') else 'installed')" 2>/dev/null || echo "installed")
    echo -e "   ${GREEN}✓${NC} m1n1 Python module: $M1N1_VERSION"
else
    echo -e "   ${YELLOW}⚠${NC}  m1n1 Python module not found"
    echo ""
    echo -e "   ${CYAN}Install m1n1 Python module:${NC}"
    echo -e "   ${GREEN}pip3 install --user m1n1${NC}"
    echo ""
    echo -e "   ${CYAN}Or clone from source:${NC}"
    echo -e "   ${GREEN}git clone https://github.com/AsahiLinux/m1n1.git${NC}"
    echo -e "   ${GREEN}cd m1n1 && pip3 install --user -e .${NC}"
    echo ""
    exit 1
fi
echo ""

# Step 5: Check for target Mac in DFU mode
echo -e "${BLUE}[5/5]${NC} Checking for target Mac in DFU mode..."
if system_profiler SPUSBDataType 2>/dev/null | grep -q "DFU"; then
    echo -e "   ${GREEN}✓${NC} Target Mac detected in DFU mode"
else
    echo -e "   ${YELLOW}⚠${NC}  No Mac in DFU mode detected"
    echo ""
    echo -e "   ${CYAN}To enter DFU mode on MacBook Pro M2:${NC}"
    echo -e "   1. Shut down the MacBook Pro completely"
    echo -e "   2. Press and hold the ${YELLOW}Power button${NC}"
    echo -e "   3. Keep holding until \"Loading startup options\" appears"
    echo -e "   4. ${YELLOW}Continue holding${NC} the power button"
    echo -e "   5. Screen will go black - ${YELLOW}keep holding${NC}"
    echo -e "   6. After 10-15 seconds, release"
    echo -e "   7. Connect USB-C cable to this Mac"
    echo ""
    echo -e "   ${CYAN}Then run this script again${NC}"
    echo ""
    exit 1
fi
echo ""

# Build m1n1 command
M1N1_CMD="python3 -m m1n1.run $M1N1_MACHO -b $KERNEL_IMAGE kernel.macho"
if [ "$VERBOSE" = true ]; then
    M1N1_CMD="$M1N1_CMD -v"
fi

# Step 6: Boot kernel
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Starting Tethered Boot${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo -e "${CYAN}Command:${NC} $M1N1_CMD"
echo ""
echo -e "${YELLOW}Uploading bootloader and kernel to target Mac...${NC}"
echo ""

# Execute m1n1
if $M1N1_CMD; then
    echo ""
    echo -e "${GREEN}✓ Tethered boot initiated successfully${NC}"
else
    echo ""
    echo -e "${RED}✗ Tethered boot failed${NC}"
    exit 1
fi

# Step 7: Console connection (if requested)
if [ "$CONSOLE" = true ]; then
    echo ""
    echo -e "${BLUE}Searching for serial console...${NC}"

    # Find debug console device
    CONSOLE_DEV=$(ls /dev/cu.* 2>/dev/null | grep -i "debug\|serial" | head -1)

    if [ -n "$CONSOLE_DEV" ]; then
        echo -e "${GREEN}✓ Found console: $CONSOLE_DEV${NC}"
        echo ""
        echo -e "${CYAN}Connecting to serial console (115200 baud)...${NC}"
        echo -e "${YELLOW}Press Ctrl-A then K to exit${NC}"
        echo ""
        sleep 2

        # Use screen for console
        screen "$CONSOLE_DEV" 115200
    else
        echo -e "${YELLOW}⚠ No serial console device found${NC}"
        echo ""
        echo -e "${CYAN}Manually connect with:${NC}"
        echo -e "  ${GREEN}screen /dev/cu.debug-console 115200${NC}"
        echo -e "  ${GREEN}minicom -D /dev/cu.debug-console -b 115200${NC}"
        echo -e "  ${GREEN}python3 -m serial.tools.miniterm /dev/cu.debug-console 115200${NC}"
    fi
fi

# Final instructions
echo ""
echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  Tethered Boot Complete${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo -e "${CYAN}Your MacBook Pro M2 is now running Futura OS!${NC}"
echo ""
echo -e "${YELLOW}To monitor console output:${NC}"
echo -e "  ${GREEN}screen /dev/cu.debug-console 115200${NC}"
echo ""
echo -e "${YELLOW}To shutdown and return to macOS:${NC}"
echo -e "  1. Send shutdown command (if available)"
echo -e "  2. Or hold Power button for 10 seconds"
echo -e "  3. Press Power button normally to boot macOS"
echo ""
echo -e "${CYAN}No changes made to storage - completely reversible!${NC}"
echo ""

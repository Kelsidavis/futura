#!/bin/bash
# Run Futura OS with Horizon Desktop in QEMU
# Boot messages appear on serial (this terminal), GUI in QEMU window
set -e

ISO="${1:-futura.iso}"
if [ ! -f "$ISO" ]; then
    echo "ISO not found. Build first: ./scripts/build-desktop.sh"
    exit 1
fi

echo "Starting Futura OS — Horizon Desktop"
echo "  Serial console: this terminal"
echo "  GUI: QEMU window"
echo "  Ctrl+Alt+T in GUI to open new terminals"
echo ""

qemu-system-x86_64 \
    -m 256M \
    -cdrom "$ISO" \
    -boot d \
    -serial stdio \
    -no-reboot

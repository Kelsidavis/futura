#!/bin/bash
# Run Futura OS in headless server mode (text console only)
set -e

ISO="${1:-futura.iso}"
if [ ! -f "$ISO" ]; then
    echo "ISO not found. Build first: ./scripts/build-server.sh"
    exit 1
fi

echo "Starting Futura OS — Server Mode (text console)"
echo ""

qemu-system-x86_64 \
    -m 256M \
    -cdrom "$ISO" \
    -boot d \
    -serial stdio \
    -nographic \
    -no-reboot

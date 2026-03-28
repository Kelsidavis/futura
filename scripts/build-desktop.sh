#!/bin/bash
# Build Futura OS with Horizon Desktop
set -e
echo "Building Futura OS 0.6.0 — Horizon Desktop..."
make -j$(nproc) PROFILE=desktop DRIVERS=qemu iso
echo ""
echo "Build complete! Run with:"
echo "  ./scripts/run-desktop.sh"

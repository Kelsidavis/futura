#!/bin/bash
# Build Futura OS in headless server mode (no GUI)
set -e
echo "Building Futura OS 0.6.0 — Server Mode..."
make -j$(nproc) PROFILE=server DRIVERS=qemu iso
echo ""
echo "Build complete! Run with:"
echo "  ./scripts/run-server.sh"

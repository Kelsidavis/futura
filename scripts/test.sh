#!/bin/bash
# Run the full kernel selftest suite (currently 2654 reachable tests).
# Counts and pass totals are tracked in docs/CURRENT_STATUS.md.
set -e
echo "Running Futura OS kernel tests..."
make test ENABLE_WAYLAND=0 DRIVERS=qemu

#!/bin/bash
# Run all 2348 kernel tests
set -e
echo "Running Futura OS kernel tests..."
make test ENABLE_WAYLAND=0 DRIVERS=qemu

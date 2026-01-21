#!/bin/bash
# Test script for Futura OS shell
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.
#
# This uses the CORRECT QEMU flags for serial console.

echo "=== Testing Futura OS Shell ==="
echo ""
echo "IMPORTANT: Use -serial stdio (NOT -serial mon:stdio)"
echo "The 'mon:' prefix multiplexes QEMU monitor with stdio and"
echo "can introduce control sequences that corrupt serial input."
echo ""

# Test with programmatic input (with delay to let shell initialize)
(sleep 2 && printf "help\nuname\nwhoami\necho Test Message\nexit\n") | \
    timeout 15 qemu-system-x86_64 \
        -kernel build/bin/futura_kernel.elf \
        -serial stdio \
        -display none \
        -m 1024 \
        -no-reboot \
        -no-shutdown 2>&1 | \
    grep -A60 "futura>"

echo ""
echo "=== Test Complete ==="
echo ""
echo "To run interactively, use ONE of these commands:"
echo ""
echo "  Option 1 (recommended): Use -nographic alone"
echo "    qemu-system-x86_64 -kernel build/bin/futura_kernel.elf -nographic -m 1024"
echo ""
echo "  Option 2: Use -serial stdio with -display none"
echo "    qemu-system-x86_64 -kernel build/bin/futura_kernel.elf -serial stdio -display none -m 1024"
echo ""
echo "NOTE: Do NOT use both -nographic and -serial stdio together!"
echo "      They conflict because -nographic already uses stdio for serial."
echo ""

#!/bin/bash
# Test script for Futura OS shell
# This uses the CORRECT QEMU flags for serial console

echo "=== Testing Futura OS Shell ==="
echo ""
echo "IMPORTANT: Use -serial stdio (NOT -serial mon:stdio)"
echo "The 'mon:' prefix multiplexes QEMU monitor with stdio and"
echo "can introduce control sequences that corrupt serial input."
echo ""

# Test with programmatic input
printf "\nhelp\nuname\nwhoami\necho Test Message\nexit\n" | \
    timeout 10 qemu-system-x86_64 \
        -kernel build/bin/futura_kernel.elf \
        -serial stdio \
        -display none \
        -m 1024 \
        -no-reboot \
        -no-shutdown 2>&1 | \
    grep -A60 "futura>"

echo ""
echo "=== Test Complete ===" echo ""
echo "To run interactively, use:"
echo "  qemu-system-x86_64 -kernel build/bin/futura_kernel.elf -serial stdio -nographic -m 1024"
echo ""

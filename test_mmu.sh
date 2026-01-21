#!/bin/bash
# Test with MMU debugging enabled
#
# Copyright (c) 2025 Kelsi Davis
# Licensed under the MPL v2.0 — see LICENSE for details.

qemu-system-aarch64 -M virt -cpu cortex-a53 \
    -kernel build/bin/futura_kernel.elf \
    -nographic \
    -d mmu,int,guest_errors \
    -D mmu_debug.log &
QEMU_PID=$!
echo "QEMU PID: $QEMU_PID"
sleep 3
kill $QEMU_PID 2>/dev/null

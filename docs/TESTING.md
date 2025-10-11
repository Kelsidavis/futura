# Futura OS Testing Guide

## ⚠️ IMPORTANT: Use GRUB, Not Direct Kernel Boot

**The Futura kernel MUST be booted via GRUB**, not QEMU's direct `-kernel` option.

### ❌ WRONG - Will Triple-Fault
```bash
qemu-system-x86_64 -kernel build/bin/futura_kernel.elf -serial stdio -m 256M
```

### ✅ CORRECT - Build and Boot ISO
```bash
# 1. Build kernel
make clean && make kernel

# 2. Copy to ISO directory
cp build/bin/futura_kernel.elf iso/boot/

# 3. Build bootable ISO with GRUB
grub-mkrescue -o futura.iso iso/

# 4. Boot with QEMU
qemu-system-x86_64 -cdrom futura.iso -serial stdio -display none -m 256M
```

## Why GRUB is Required

The Futura kernel uses:
- **Higher-half addressing** (0xFFFFFFFF80000000+)
- **Multiboot2 protocol** with specific header placement requirements
- **64-bit long mode** with proper page table setup

QEMU's direct `-kernel` boot doesn't properly set up the Multiboot2 environment for higher-half kernels. GRUB handles:
- Multiboot2 header parsing and validation
- Memory map setup
- Proper loading of higher-half ELF sections
- Correct handoff to 64-bit long mode entry point

## Boot Sequence Markers

When booting correctly via GRUB, you'll see these serial debug markers:

```
SPAEGJFHKSCIN
```

- **S** = Boot started (32-bit protected mode)
- **P** = CR3 loaded (page tables installed)
- **A** = PAE enabled
- **E** = EFER set (long mode enabled)
- **G** = Paging enabled
- **J** = Far jump to 64-bit code
- **F** = 64-bit long mode active
- **H** = Higher-half jump successful
- **K** = Before stack operations
- **S** = Stack ready
- **C** = Calling platform init
- **I** = Inside fut_platform_init
- **N** = After serial init

If you see **repeating "SPAEGJFHKSC"** without 'I' or 'N', you're using direct kernel boot (wrong method).

## Expected Test Output

### FIPC Tests (dcac1ee)
```
[FIPC-SENDER] Starting sender thread
[FIPC-RECEIVER] Starting receiver thread
[FIPC-SENDER] Sending message 0
[FIPC-RECEIVER] Received message: type=0x1000, len=5, payload='MSG0'
[FIPC-SENDER] Sending message 1
[FIPC-RECEIVER] Received message: type=0x1000, len=5, payload='MSG1'
[FIPC-SENDER] Sending message 2
[FIPC-RECEIVER] Received message: type=0x1000, len=5, payload='MSG2'
[FIPC-SENDER] All messages sent, exiting
```

### VFS Tests (current HEAD)
```
[VFS-TEST] ✓ Root accessible (inode 1, mode 0...)
[VFS-TEST] ✓ Directory created: /testdir
[VFS-TEST] ✓ File created: /test.txt
[VFS-TEST] ✓ Wrote 28 bytes
[VFS-TEST] ✓ Read 28 bytes: 'Hello, VFS! This is a test.'
[VFS-TEST] ✓ Data verification PASSED
```

### Block Device Tests (current HEAD)
```
[BLOCKDEV-TEST] ✓ Ramdisk created: ramdisk0
[BLOCKDEV-TEST] ✓ Wrote 1 block (512 bytes)
[BLOCKDEV-TEST] ✓ Read 1 block (512 bytes)
[BLOCKDEV-TEST] ✓ Data verification PASSED
```

## Common Issues

### Issue: Triple-fault loop (repeating SPAEGJFHKSC)
**Cause**: Using `-kernel` direct boot instead of GRUB ISO
**Solution**: Follow the correct ISO build process above

### Issue: GRUB menu doesn't appear
**Cause**: grub-mkrescue not installed or ISO corrupted
**Solution**: `sudo apt install grub-pc-bin xorriso`

### Issue: Kernel doesn't load
**Cause**: Kernel not copied to iso/boot/ or wrong path in grub.cfg
**Solution**: Verify `iso/boot/futura_kernel.elf` exists

## Quick Test Script

```bash
#!/bin/bash
# test-kernel.sh - One-command kernel test

set -e

echo "Building kernel..."
make clean && make kernel

echo "Creating bootable ISO..."
cp build/bin/futura_kernel.elf iso/boot/
grub-mkrescue -o futura.iso iso/ 2>&1 | grep "completed"

echo "Booting kernel (Ctrl+C to exit)..."
qemu-system-x86_64 \
    -cdrom futura.iso \
    -serial stdio \
    -display none \
    -m 256M
```

## CI/CD Integration

For automated testing:
```bash
# Build ISO
make kernel
cp build/bin/futura_kernel.elf iso/boot/
grub-mkrescue -o futura.iso iso/

# Run with timeout and capture output
timeout 30 qemu-system-x86_64 \
    -cdrom futura.iso \
    -serial file:test-output.txt \
    -display none \
    -m 256M || true

# Verify expected markers in output
grep "SPAEGJFHKSCIN" test-output.txt && \
grep "VFS-TEST.*PASSED" test-output.txt && \
echo "✓ Tests passed"
```

## Additional QEMU Options

### Enable KVM (faster on Linux)
```bash
qemu-system-x86_64 -cdrom futura.iso -enable-kvm -cpu host -m 256M
```

### Add virtual disk for filesystem testing
```bash
qemu-img create -f raw disk.img 100M
qemu-system-x86_64 -cdrom futura.iso -drive file=disk.img,format=raw -m 256M
```

### Debugging with GDB
```bash
# Terminal 1: Start QEMU with GDB server
qemu-system-x86_64 -cdrom futura.iso -s -S -m 256M

# Terminal 2: Connect GDB
gdb build/bin/futura_kernel.elf
(gdb) target remote :1234
(gdb) break fut_kernel_main
(gdb) continue
```

## See Also

- `docs/FIPC_SPEC.md` - FIPC subsystem specification
- `docs/ARCHITECTURE.md` - Overall system architecture
- `platform/x86_64/boot.S` - Boot sequence implementation
- `iso/boot/grub/grub.cfg` - GRUB configuration

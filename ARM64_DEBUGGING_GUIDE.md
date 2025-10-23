# ARM64 Kernel Debugging Guide

## Overview
Debugging the ARM64 kernel without output is challenging. This guide covers multiple approaches for different scenarios.

---

## Option 1: QEMU ARM64 Emulation (Recommended for Testing)

**Best for:** Rapid iteration and early boot debugging

### Test in QEMU
```bash
bash /tmp/test_arm64_qemu.sh
```

This runs the kernel in emulated ARM64 environment where you can see:
- All boot messages
- CPU state at failure points
- Memory access patterns
- Unimplemented instruction errors

### QEMU Output Analysis
The script saves output to `/tmp/qemu_arm64_output.log`:
```bash
tail -100 /tmp/qemu_arm64_output.log
```

Look for:
- **Exception messages**: Indicates instruction/operation failures
- **Unimplemented features**: `QEMU: Unimplemented` warnings
- **CPU state**: If kernel hangs or crashes

---

## Option 2: Serial Console (Real Hardware)

**Best for:** Production deployment and long-term debugging

### Hardware Setup Required:
1. USB-to-UART adapter (CP2102, CH340, or similar)
2. Raspberry Pi 5 GPIO pins:
   - GPIO14 (UART TX) → Adapter RX
   - GPIO15 (UART RX) → Adapter TX
   - GND → Adapter GND

### Connect to Console:
```bash
# On development machine
screen /dev/ttyUSB0 115200

# Or with picocom
picocom -b 115200 /dev/ttyUSB0

# Or with minicom
minicom -D /dev/ttyUSB0 -b 115200
```

### Boot Messages You'll See:
```
Futura OS ARM64 Booting...
fut_paging_init()
fut_scheduler_init()
fut_register_irq_handler()
fut_gic_init()
Device Tree: [platform detection]
Futura OS Initialized
```

### Common Issues & Solutions:

**Problem: No output appears**
- Check UART connection (swap TX/RX if needed)
- Verify baud rate is 115200
- Ensure config.txt has `enable_uart=1`

**Problem: Garbage characters**
- Baud rate mismatch - try different rates
- Power issue - ensure Pi has good power supply

**Problem: Output stops mid-boot**
- Kernel crashed/panicked
- Unimplemented syscall
- Memory access violation

---

## Option 3: Add Debug Output to Kernel

**Best for:** Identifying specific failure points

### Add Printf Logging
Edit `platform/arm64/arm64_minimal_stubs.c`:

```c
#include <kernel/fut_printf.h>

void fut_paging_init(void) {
    fut_printf("[DEBUG] fut_paging_init() called\n");
    /* Stub: ARM64 uses hardware MMU directly */
    fut_printf("[DEBUG] fut_paging_init() complete\n");
}

void fut_scheduler_init(void) {
    fut_printf("[DEBUG] fut_scheduler_init() called\n");
    /* Stub implementation */
    fut_printf("[DEBUG] fut_scheduler_init() complete\n");
}
```

Rebuild:
```bash
make clean PLATFORM=arm64 && make PLATFORM=arm64 -j4 kernel
```

Test in QEMU to see debug output:
```bash
bash /tmp/test_arm64_qemu.sh
```

---

## Option 4: Progress Indicators with LEDs/Framebuffer

**Best for:** Silent operation with visual feedback**

### LED Blink Pattern Debug
```c
void fut_paging_init(void) {
    /* Blink pattern: 3 short, 2 long = paging init phase */
    for(int i = 0; i < 5; i++) {
        if(i < 3) gpio_blink(50);   /* 50ms blink */
        else gpio_blink(200);        /* 200ms blink */
    }
    msleep(500);
}
```

Pattern meanings:
- 1 blink: Paging init
- 2 blinks: Scheduler init
- 3 blinks: IRQ handler setup
- 4 blinks: GIC init
- 5 blinks: Device tree processing
- Continuous: Boot successful

---

## Recommended Debugging Strategy

### Phase 1: Development (Fastest)
```
1. Make code changes
2. Test in QEMU: bash /tmp/test_arm64_qemu.sh
3. Check output for errors/crashes
4. Fix issues
5. Repeat
```

### Phase 2: Pre-Hardware Testing
```
1. All QEMU tests pass
2. Add serial console debug output
3. Rebuild for real hardware
```

### Phase 3: Real Hardware Testing
```
1. Have USB-UART adapter connected
2. Run: screen /dev/ttyUSB0 115200
3. Deploy: sudo bash /tmp/deploy_to_usb_fixed.sh /dev/sdd
4. Insert USB into Raspberry Pi 5
5. Watch serial console for boot messages
```

---

## Debugging Tools Reference

### QEMU Commands
```bash
# Verbose output with guest errors
qemu-system-aarch64 -M virt -cpu cortex-a72 \
  -kernel kernel.elf -serial stdio -nographic \
  -d guest_errors,unimp,int

# With GDB debugging
qemu-system-aarch64 -M virt -cpu cortex-a72 \
  -kernel kernel.elf -serial stdio -nographic \
  -S -gdb tcp::1234

# Then in another terminal:
aarch64-linux-gnu-gdb build/bin/futura_kernel.elf
(gdb) target remote localhost:1234
(gdb) b fut_paging_init
(gdb) c
```

### Serial Console Tools
```bash
# screen (simple)
screen /dev/ttyUSB0 115200

# picocom (recommended)
picocom -b 115200 /dev/ttyUSB0

# minicom (feature-rich)
minicom -D /dev/ttyUSB0 -b 115200
```

---

## Expected Boot Sequence

If everything works correctly, you should see:

```
Futura OS ARM64 Boot
CPU: ARM64 Cortex-A72
Memory: 1GB (or 8GB on RPi5)
Kernel Entry: 0xXXXXXXXX

[DEBUG] kernel_main() starting
[DEBUG] fut_paging_init() called
[DEBUG] fut_paging_init() complete
[DEBUG] fut_scheduler_init() called
[DEBUG] fut_scheduler_init() complete
[DEBUG] fut_register_irq_handler() called
[DEBUG] fut_register_irq_handler() complete
[DEBUG] fut_gic_init() called
[DEBUG] fut_gic_init() complete
[DEBUG] Device Tree: RPi5 detected
[DEBUG] fut_rpi_irq_init() complete

Futura OS ARM64 Ready
```

---

## File Locations

- QEMU test script: `/tmp/test_arm64_qemu.sh`
- Deployment script: `/tmp/deploy_to_usb_fixed.sh`
- Kernel binary: `/home/k/futura/build/bin/futura_kernel.elf`
- Debug stubs: `/home/k/futura/platform/arm64/arm64_minimal_stubs.c`
- QEMU output log: `/tmp/qemu_arm64_output.log`

---

## Next Steps

1. **Immediate**: Test in QEMU
   ```bash
   bash /tmp/test_arm64_qemu.sh
   ```

2. **If QEMU works**: Add debug output and redeploy

3. **For hardware**: Get USB-UART adapter and serial console setup

4. **Issues found**: Fix in code, retest in QEMU, then deploy

---

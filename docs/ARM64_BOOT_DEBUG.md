# ARM64 Boot Debugging Notes

**Date**: 2025-11-03
**Status**: Build complete, systematic boot debugging in progress
**Latest**: Kernel reaches DRAM L2 setup (output: "A123")

## Latest Debug Session Progress

### Systematic Boot Debugging (2025-11-03 evening)

**Serial Output: "A123"** indicates:
- ✅ **A** = Kernel started, BSS cleared
- ✅ **1** = Page tables zeroed (4 tables, 2048 entries)
- ✅ **2** = Peripheral L2 setup complete (128 x 2MB blocks)
- ✅ **3** = About to setup DRAM L2 (entering loop)
- ❌ Hangs during DRAM L2 loop (should map 512 x 2MB blocks)

### Issues Fixed This Session

1. **Peripheral Region Mapping Added**
   - Added boot_l2_peripherals table
   - Maps 0x00000000-0x10000000 (includes UART and GIC)
   - Uses device memory attributes (Attr1)

2. **ARM64 Immediate Encoding Fixes**
   - `mov x10, #0x09000000` → `movz x10, #0x0900, lsl #16`
   - `mov x1, #0x40000000` → `movz x1, #0x4000, lsl #16`
   - `add x1, x1, #0x200000` → `add x1, x1, x5` (with x5 = 0x200000)

3. **Block Descriptor Flags Corrected**
   - Peripheral: 0x25 (Valid | AttrIndx=1 | AF)
   - DRAM: 0x601 (Valid | AttrIndx=0 | AF | Inner Shareable)

### Next Debug Steps

1. Add debug marker after DRAM L2 loop completes ('4')
2. Check if loop counter reaches 512 or hangs mid-loop
3. Verify block descriptor construction (phys | flags)
4. Check for page table write errors

## Current State

### ✅ Build System - COMPLETE
- Kernel builds successfully: 1.3 MB binary
- All linker errors resolved
- ELF structure verified and correct
- Entry point: 0x40000000 (_start)
- Load address: 0x40000000 (QEMU virt machine DRAM)

### 🔍 Boot Status - INVESTIGATING

**Symptom**: No serial output when booting in QEMU

**QEMU Command**:
```bash
qemu-system-aarch64 -M virt -cpu cortex-a53 \
    -kernel build/bin/futura_kernel.elf -nographic
```

### Verification Steps Completed

1. **ELF Entry Point** ✅
   ```
   $ aarch64-elf-readelf -h futura_kernel.elf | grep Entry
   Entry point address: 0x40000000
   ```

2. **Load Address** ✅
   ```
   $ aarch64-elf-readelf -l futura_kernel.elf
   LOAD 0x40000000 0x40000000 RWE
   ```

3. **Symbol Location** ✅
   ```
   $ aarch64-elf-nm futura_kernel.elf | grep _start
   0000000040000000 T _start
   ```

4. **Disassembly** ✅
   ```
   40000000 <_start>:
       40000000:   aa0003f4    mov x20, x0         # Save DTB
       40000004:   d5384240    mrs x0, currentel   # Check EL
       ...
   ```

   Boot code correctly implements:
   - EL3→EL2→EL1 transition
   - Exception vector setup
   - FPU initialization
   - Stack setup
   - BSS clearing
   - MMU configuration and enablement

5. **Serial Console Configuration** ✅
   - UART0_BASE: 0x09000000 (correct for QEMU virt)
   - PL011 UART implementation
   - Initialization in fut_platform_early_init()

### Boot Sequence (Expected)

```
_start (boot.S:21)
  ↓
EL transition (if needed)
  ↓
setup_el1
  ↓
MMU setup and enable
  ↓
fut_platform_init (platform_init.c:833)
  ↓
fut_platform_early_init (platform_init.c:800)
  ↓
fut_serial_init()
  ↓
Serial output: "Futura OS ARM64 Platform Initialization"
```

### Possible Causes (To Investigate)

1. **CPU State**
   - QEMU debug log showed PC=0 initially
   - May indicate kernel not being loaded
   - Or CPU not starting at entry point

2. **UART Initialization**
   - PL011 may require specific initialization sequence
   - UART base address mismatch unlikely (verified 0x09000000)
   - Check if UART needs explicit enable before use

3. **MMU Issues**
   - Kernel enables MMU early in boot
   - Identity mapping covers 0x40000000-0x80000000
   - Potential issues:
     - UART not mapped (it's at 0x09000000, not in identity map!)
     - Page table configuration errors
     - Missing memory barriers after MMU enable

4. **Exception During Boot**
   - CPU might be taking an exception before serial init
   - No exception handler output
   - Check exception vector setup

5. **Stack Issues**
   - Stack configured at _stack_top
   - BSS cleared before use
   - Unlikely but possible

## Critical Discovery: UART Not Mapped!

**UART is at 0x09000000, but identity mapping only covers 0x40000000-0x80000000!**

This is likely the root cause. After MMU is enabled, accessing UART at 0x09000000 would cause a page fault, and without exception handlers printing output, we get silent failure.

### Fix Required

Add identity mapping for peripheral region in boot.S:

```asm
/* Map peripherals (0x00000000-0x10000000) */
/* Required for UART at 0x09000000 */
```

Current identity mapping (boot.S ~line 120):
- Only maps DRAM: 0x40000000-0x80000000
- UART at 0x09000000 is NOT mapped
- GIC at 0x08000000 is NOT mapped

After MMU enable, any access to unmapped regions triggers a page fault.

## Next Steps

### Priority 1: Fix UART Mapping
1. Add identity mapping for 0x00000000-0x10000000 in boot.S
2. This covers:
   - GIC: 0x08000000-0x08020000
   - UART: 0x09000000-0x09001000
   - Other peripherals

### Priority 2: Boot Testing
1. Rebuild kernel with peripheral mapping
2. Test in QEMU
3. Verify serial output appears

### Priority 3: Debug Infrastructure
1. Add early debug output (before MMU enable)
2. Implement exception handlers that work without serial
3. Add LED/GPIO debugging if available

### Priority 4: Exception Handling
1. Verify exception vectors are installed
2. Add exception handlers that can output to serial
3. Test page fault handling

## Debugging Commands

### Run with Debug Logging
```bash
qemu-system-aarch64 -M virt -cpu cortex-a53 \
    -kernel build/bin/futura_kernel.elf \
    -nographic -d guest_errors,cpu_reset \
    -D qemu_debug.log
```

### Check CPU State
```bash
qemu-system-aarch64 -M virt -cpu cortex-a53 \
    -kernel build/bin/futura_kernel.elf \
    -nographic -d int,cpu_reset -D debug.log
# Check debug.log for exception state
```

### Verify Memory Map
```bash
qemu-system-aarch64 -M virt -cpu cortex-a53 \
    -kernel build/bin/futura_kernel.elf \
    -nographic -d guest_errors,mmu \
    -D mmu_debug.log
```

## Memory Map (QEMU virt Machine)

```
0x00000000 - 0x08000000   Flash/ROM
0x08000000 - 0x08010000   GIC Distributor (GICD)
0x08010000 - 0x08020000   GIC CPU Interface (GICC)
0x09000000 - 0x09001000   UART0 (PL011)
0x09010000 - 0x09011000   RTC
0x0a000000 - 0x0a000200   GPIO
...
0x40000000 - 0xC0000000   DRAM (size varies, default 128MB)
```

**Current Mapping**: Only DRAM (0x40000000+)
**Needed**: Peripherals (0x00000000-0x10000000)

## References

- boot.S: MMU setup (lines 113-209)
- platform_init.c: Serial initialization (lines 161-225)
- link.ld: Memory layout
- ARM64_BUILD_STATUS.md: Build system fixes
- ARM64_MMU_IMPLEMENTATION.md: MMU technical details

---

**Next Session Goal**: Add peripheral mapping to boot.S and achieve first serial output

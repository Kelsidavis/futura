# ARM64 MMU Implementation - Completed

## Overview

The ARM64 MMU has been successfully implemented and enabled in the boot sequence. This document describes what was implemented and how to verify it works.

## What Was Implemented

### 1. Boot Page Tables (`platform/arm64/boot.S:536-546`)

Three 4KB-aligned page table levels allocated in `.bss`:
- **boot_l0_table**: Level 0 page table (512GB per entry)
- **boot_l1_table**: Level 1 page table (1GB per entry)
- **boot_l2_table**: Level 2 page table (2MB per entry)

### 2. Page Table Setup (`platform/arm64/boot.S:112-171`)

**Identity Mapping Strategy**:
- Maps 1GB of physical RAM: `0x40000000 - 0x80000000` (QEMU virt machine DRAM)
- Uses 2MB block entries at Level 2 (512 entries × 2MB = 1GB)
- Page table hierarchy:
  - L0[0] → L1 table
  - L1[1] → L2 table (covers 2nd GB of address space)
  - L2[0-511] → 512 × 2MB physical blocks

**Block Descriptor Flags**:
- Valid (`bit 0 = 1`)
- Block entry (`bit 1 = 0`)
- Access Flag (`bit 5 = 1`)
- Inner Shareable (`bits 9:8 = 11`)
- AttrIndx 0 (Normal memory)

### 3. MMU Control Registers (`platform/arm64/boot.S:173-209`)

**MAIR_EL1** (Memory Attribute Indirection Register):
```asm
Attr0 = 0xFF  /* Normal memory: Inner/Outer Write-Back Cacheable */
```

**TCR_EL1** (Translation Control Register):
```
T0SZ  = 25    /* User VA: 39 bits (512GB) */
T1SZ  = 25    /* Kernel VA: 39 bits (512GB) */
TG0   = 00    /* 4KB granule for TTBR0 */
TG1   = 00    /* 4KB granule for TTBR1 */
IPS   = 001   /* Physical address: 36 bits (64GB) */
```

**TTBR0_EL1 / TTBR1_EL1**:
- Both point to `boot_l0_table` initially
- Future: TTBR0 will hold user page tables, TTBR1 kernel page tables

**SCTLR_EL1** (System Control Register):
```
M  = 1   /* MMU enabled */
C  = 1   /* Data cache enabled */
I  = 1   /* Instruction cache enabled */
```

## Memory Map

### Current (Identity Mapped)

| Virtual Address | Physical Address | Size | Description |
|----------------|------------------|------|-------------|
| 0x40000000     | 0x40000000       | 1GB  | Kernel code/data/heap |

### Future (Higher-Half Kernel)

| Virtual Address Range | Usage |
|----------------------|-------|
| 0x0000_0000_0000_0000 - 0x0000_007F_FFFF_FFFF | User space (TTBR0_EL1) |
| 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF | Kernel space (TTBR1_EL1) |

## Verification Steps

### 1. Check MMU is Enabled

Add debug output after MMU enable:
```c
uint64_t sctlr;
asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
if (sctlr & 1) {
    fut_printf("[BOOT] MMU is ENABLED\n");
} else {
    fut_printf("[BOOT] MMU is DISABLED\n");
}
```

### 2. Verify Page Table Base

```c
uint64_t ttbr1;
asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
fut_printf("[BOOT] TTBR1_EL1 = 0x%llx\n", ttbr1);
```

Expected: Address of `boot_l0_table` (in 0x40000000-0x80000000 range)

### 3. Test Memory Access

The kernel should boot normally. If it does, MMU is working correctly:
- Serial output appears
- Heap allocation works
- No data aborts or instruction aborts

### 4. QEMU Debug Mode

Run with MMU debugging:
```bash
qemu-system-aarch64 -M virt-10.0 -cpu cortex-a53 -m 512M \
    -kernel build/bin/futura_kernel.bin \
    -serial stdio -nographic \
    -d int,mmu,cpu_reset \
    -D qemu.log
```

Check `qemu.log` for:
- MMU translation entries
- TLB misses/hits
- Page table walks

## Known Limitations

1. **Identity Mapping Only**: Currently maps physical = virtual
   - Need to transition to higher-half kernel layout
   - Requires updating linker script and early boot code

2. **Single Address Space**: TTBR0 = TTBR1
   - No user/kernel separation yet
   - Need per-task TTBR0 for user processes

3. **Limited Coverage**: Only 1GB mapped
   - Sufficient for QEMU with `-m 1024`
   - Need to map full physical memory for production

4. **No Large Page Support**: Uses 2MB blocks only
   - Could use 1GB blocks at L1 for kernel
   - Could use 4KB pages for finer granularity

## Next Steps

### Phase 1: Higher-Half Kernel
1. Update linker script to place kernel at `0xFFFFFF8000000000`
2. Map kernel code/data at higher-half addresses
3. Update early boot to transition from identity → higher-half mapping
4. Keep identity map for device MMIO

### Phase 2: User Address Space
1. Allocate separate page tables per task
2. Load user page table into TTBR0_EL1 on context switch
3. Map user code/data/stack in lower half (0x0 - 0x7FFFFFFFFFFF)
4. Implement demand paging and COW

### Phase 3: Advanced Features
1. ASID (Address Space ID) for TLB efficiency
2. Huge page support (1GB blocks for kernel)
3. Device memory mapping with proper attributes
4. Memory barriers for DMA coherency

## Testing Commands

### Build ARM64 Kernel
```bash
cd /path/to/futura
make PLATFORM=arm64
```

### Run in QEMU
```bash
make PLATFORM=arm64 run
# or with debugging:
make PLATFORM=arm64 run-debug
```

### Expected Boot Output
```
[BOOT] ARM64 boot starting...
[BOOT] Exception level: EL1
[BOOT] MMU is ENABLED
[BOOT] TTBR1_EL1 = 0x40XXXXXX
[INIT] Initializing physical memory manager...
[INIT] PMM initialized: XXXX pages total, XXXX pages free
```

## Troubleshooting

### Symptom: Immediate crash after MMU enable

**Cause**: Page tables not properly initialized or PC not mapped

**Fix**: Verify:
- Page table entries have Valid bit set
- L0[0] → L1, L1[1] → L2 chain is correct
- L2 entries cover 0x40000000-0x80000000
- Boot code is within mapped region

### Symptom: Data abort on heap access

**Cause**: Heap memory not covered by page tables

**Fix**: Ensure 1GB mapping covers heap region (check kernel_end address)

### Symptom: Instruction abort in kernel code

**Cause**: Execute permission not set, or code not mapped

**Fix**: Check block descriptor doesn't have UXN/PXN bits set incorrectly

## References

- ARM Architecture Reference Manual ARMv8-A (DDI 0487)
- Section D5: The AArch64 Virtual Memory System Architecture
- ARM Cortex-A Series Programmer's Guide for ARMv8-A
- Linux kernel: `arch/arm64/mm/proc.S` (example MMU enable sequence)

## Implementation Credits

Implemented: 2025-11-03
Platform: ARM64 (AArch64)
Target: QEMU virt machine with cortex-a57

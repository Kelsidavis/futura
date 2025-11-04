# ARM64 MMU Enablement Plan

## Current State

The ARM64 port currently has MMU **disabled** (`boot.S:88` explicitly disables it). All code runs with identity mapping in physical memory. While syscall infrastructure is complete, userspace cannot run without MMU-based memory protection.

## Why MMU is Required

1. **User/Kernel Separation**: EL0 (userspace) needs isolated address space from EL1 (kernel)
2. **Memory Protection**: Page-level permissions (read/write/execute) enforce security
3. **Virtual Memory**: Enables demand paging, COW fork, mmap
4. **POSIX Compatibility**: Required for proper process isolation

## Implementation Plan

### Phase 1: Early Boot MMU Setup (`platform/arm64/boot.S`)

**Location**: After BSS clear, before `fut_platform_init` call

**Steps**:
1. **Allocate static page tables** in `.bss` section:
   ```asm
   .section .bss
   .align 12
   boot_pgd:      .space 4096  /* L0 page table */
   boot_pud:      .space 4096  /* L1 page table */
   boot_pmd:      .space 4096  /* L2 page table */
   ```

2. **Identity map first 1GB** (for kernel code/data):
   - Map `0x40000000 - 0x80000000` (QEMU virt machine DRAM)
   - Use 2MB block entries at L2 for simplicity
   - Attributes: Normal memory, Inner/Outer Shareable, Cacheable

3. **Configure MMU registers**:
   ```asm
   /* MAIR_EL1: Memory Attribute Indirection Register */
   ldr x0, =0x44FF  /* Attr0=Normal, Attr1=Device-nGnRnE */
   msr mair_el1, x0

   /* TCR_EL1: Translation Control Register */
   ldr x0, =0x80803520  /* 4KB granule, 39-bit VA, TTBR1 higher half */
   msr tcr_el1, x0

   /* TTBR0_EL1: User space page table (unused for now) */
   mov x0, xzr
   msr ttbr0_el1, x0

   /* TTBR1_EL1: Kernel space page table */
   adrp x0, boot_pgd
   msr ttbr1_el1, x0
   ```

4. **Enable MMU in SCTLR_EL1**:
   ```asm
   mrs x0, sctlr_el1
   orr x0, x0, #(1 << 0)   /* M bit: Enable MMU */
   orr x0, x0, #(1 << 2)   /* C bit: Enable data cache */
   orr x0, x0, #(1 << 12)  /* I bit: Enable instruction cache */
   msr sctlr_el1, x0
   isb
   ```

### Phase 2: Dynamic Page Table Management (`kernel/mm/arm64_paging.c`)

**Functions to implement**:

```c
/**
 * Initialize ARM64 paging subsystem.
 * Called early from platform_init before kernel_main.
 * Sets up kernel page tables and enables MMU.
 */
void arm64_paging_init(void);

/**
 * Setup initial identity mapping for kernel.
 * Maps physical DRAM region to virtual addresses.
 */
static int arm64_setup_kernel_mappings(void);

/**
 * Enable the MMU with configured page tables.
 * Must be called with caches disabled, enables them on success.
 */
static void arm64_enable_mmu(void);
```

**Memory Map Strategy**:
- **Kernel**: Higher-half (`0xFFFF_8000_0000_0000` +) via TTBR1_EL1
- **User**: Lower half (`0x0000_0000_0000_0000` - `0x0000_7FFF_FFFF_FFFF`) via TTBR0_EL1
- **Direct Map**: Physical memory at fixed offset for kernel access

### Phase 3: EL0 Context Switching

**Required for userspace execution**:

1. **Implement `arm64_switch_to_user()`**:
   ```c
   void arm64_switch_to_user(uint64_t entry_point, uint64_t user_sp, uint64_t ttbr0);
   ```
   - Load user page table into TTBR0_EL1
   - Set SP_EL0 to user stack pointer
   - Use ERET to drop from EL1 → EL0

2. **Update exception handlers**:
   - Sync exceptions (syscalls) already save/restore all registers
   - Ensure TTBR0_EL1 is saved/restored on context switch

3. **Modify task creation** (`kernel/exec.c`):
   - Allocate user page table (TTBR0) for each task
   - Map user code/data/stack
   - Set entry point to user function

### Phase 4: Testing

**Minimal Test Case**:
```c
/* Simple userspace program that makes a syscall */
void user_test_main(void) {
    syscall(__NR_write, 1, "Hello from EL0\n", 15);
    syscall(__NR_exit, 0);
}
```

**Verification**:
1. Kernel boots with MMU enabled (check `SCTLR_EL1.M`)
2. Can allocate/free pages via PMM
3. Can map user pages into TTBR0
4. User code executes at EL0
5. Syscalls transition EL0 → EL1 → EL0 correctly

## Critical Constraints

1. **Identity Mapping Period**: During MMU enable, PC must point to identity-mapped code
2. **Cache Coherency**: Must invalidate I-cache after enabling MMU
3. **TLB Management**: Invalidate TLBs when changing page tables
4. **Alignment**: Page tables must be 4KB-aligned

## Register Configuration Details

### MAIR_EL1 (Memory Attribute Indirection Register)
```
Attr0 (Normal Memory):  0xFF (Outer/Inner Write-Back Cacheable)
Attr1 (Device Memory):  0x00 (Device-nGnRnE)
Attr2-7: Unused
```

### TCR_EL1 (Translation Control Register)
```
TG0 = 00 (4KB granule for TTBR0)
TG1 = 10 (4KB granule for TTBR1)
T0SZ = 25 (39-bit VA for user space)
T1SZ = 25 (39-bit VA for kernel space)
IPS = 001 (36-bit PA space, 64GB)
```

### TTBR Format
```
TTBR0_EL1: [63:48] ASID, [47:1] BADDR (page table base), [0] CnP
TTBR1_EL1: Same format
```

## References

- ARM Architecture Reference Manual (ARMv8-A)
- Linux kernel: `arch/arm64/mm/proc.S` (MMU enable sequence)
- Linux kernel: `arch/arm64/include/asm/pgtable*.h` (page table layout)

## Implementation Priority

1. **CRITICAL**: Static identity mapping in boot.S (enables kernel to run)
2. **HIGH**: Dynamic kernel page table allocation (enables heap/PMM)
3. **MEDIUM**: User page table support (enables userspace)
4. **LOW**: Optimizations (huge pages, ASID management)

## Notes

- Start with simple 2MB block mappings to minimize complexity
- Defer 4KB page support until basic MMU is working
- Use QEMU `-d int,mmu` for debugging page faults
- ARM64 uses TTBR0/TTBR1 split (unlike x86_64 single CR3)

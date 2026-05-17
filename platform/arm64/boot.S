/*
 * Futura OS - ARM64 Boot Code
 * Copyright (C) 2025 Futura OS Project
 *
 * Early boot code for ARM64 architecture.
 * Configures the CPU and jumps to platform initialization.
 *
 * Linux ARM64 Image Header
 * ------------------------
 * This header makes the kernel compatible with m1n1 and other
 * ARM64 bootloaders that expect the Linux ARM64 boot image format.
 *
 * Reference: Documentation/arm64/booting.txt in Linux kernel
 */

.section .text.boot

/*
 * Linux ARM64 Image Header (64 bytes)
 *
 * Offset | Field         | Size | Description
 * -------+---------------+------+-------------------------------------
 * 0x00   | code0         | 4    | Branch instruction to _start
 * 0x04   | code1         | 4    | Branch instruction (part 2)
 * 0x08   | text_offset   | 8    | Image load offset (0 = load anywhere)
 * 0x10   | image_size    | 8    | Effective kernel image size
 * 0x18   | flags         | 8    | Kernel flags
 * 0x20   | res2          | 8    | Reserved
 * 0x28   | res3          | 8    | Reserved
 * 0x30   | res4          | 8    | Reserved
 * 0x38   | magic         | 4    | Magic: 0x644d5241 ("ARM\x64")
 * 0x3c   | res5          | 4    | Reserved
 */
.global _start
_start:
    /* 0x00: Branch to kernel entry point (skip header) */
    b       _kernel_entry           /* code0: branch to actual entry */
    .long   0                       /* code1: reserved */

    /* 0x08: text_offset - Image load offset from start of RAM */
    .quad   0                       /* 0 = can be loaded anywhere */

    /* 0x10: image_size - Effective size of kernel image */
    .quad   _kernel_end - _start    /* Total kernel size */

    /* 0x18: flags - Kernel flags */
    .quad   0                       /* bit 0: LE=0, bits 1-2: 4K pages */

    /* 0x20-0x30: Reserved fields */
    .quad   0                       /* res2 */
    .quad   0                       /* res3 */
    .quad   0                       /* res4 */

    /* 0x38: magic - ARM64 Linux magic number */
    .long   0x644d5241              /* "ARM\x64" in little-endian */

    /* 0x3c: res5 */
    .long   0

/*
 * _kernel_entry - Actual ARM64 boot entry point (after header)
 *
 * Called by bootloader with:
 *   x0 = device tree blob address (or 0)
 *   x1 = 0
 *   x2 = 0
 *   x3 = 0
 */
.global _kernel_entry
_kernel_entry:
    /* Save device tree address (m1n1 and QEMU both pass DTB in x0). */
    mov     x20, x0

    /* Stash the implementer field of MIDR_EL1 in x19 so later setup
     * can branch on platform without re-reading the register after
     * various clobbers.  Apple Silicon (M1/M2/M3/M4) reports
     * implementer = 0x61 ('a').  QEMU cortex-a53 reports 0x41 ('A',
     * ARM Ltd).
     *
     * Apple Silicon bring-up is essentially done on the kernel side
     * (dynamic load-PA, 48-bit VA + runtime KERN_PA_BASE, s5l-uart
     * post-MMU backend, AIC dispatch backend) — see
     * docs/APPLE_SILICON_BRINGUP_PLAN.md.  The remaining sliver is
     * a pre-MMU early-debug shim for hangs that fire before the page
     * tables come up; until that's needed, this register stash is
     * read but not branched on. */
    mrs     x19, midr_el1
    lsr     x19, x19, #24             /* implementer = MIDR_EL1[31:24] */
    and     x19, x19, #0xff

    /* Check current exception level */
    mrs     x0, CurrentEL
    and     x0, x0, #(3 << 2)
    cmp     x0, #(1 << 2)             /* Check if EL1 */
    beq     setup_el1

    /* If EL2 or EL3, drop to EL1 */
    cmp     x0, #(2 << 2)             /* Check if EL2 */
    beq     el2_to_el1

    cmp     x0, #(3 << 2)             /* Check if EL3 */
    beq     el3_to_el2

    /* Unknown EL, halt */
    b       .

el3_to_el2:
    /* Configure EL3 to drop to EL2 */
    mov     x0, #0x5b1                /* RES1 bits + EL2h */
    msr     scr_el3, x0

    mov     x0, #0x3c9                /* EL2h with interrupts masked */
    msr     spsr_el3, x0

    adr     x0, el2_to_el1
    msr     elr_el3, x0

    eret

el2_to_el1:
    /* Configure HCR_EL2 for EL1 execution */
    mov     x0, #(1 << 31)            /* RW=1: EL1 is AArch64 */
    msr     hcr_el2, x0

    /* Disable FP/SIMD trapping from EL1 to EL2 */
    mrs     x0, cptr_el2
    bic     x0, x0, #(1 << 10)        /* Clear TFP bit: don't trap FP/SIMD */
    msr     cptr_el2, x0

    /* Configure SPSR_EL2 for EL1h mode */
    mov     x0, #0x3c5                /* EL1h with interrupts masked */
    msr     spsr_el2, x0

    /* Set ELR_EL2 to setup_el1 */
    adr     x0, setup_el1
    msr     elr_el2, x0

    eret

setup_el1:
    /* We're now at EL1 */

    /* Set up exception vector table */
    adr     x0, exception_vectors
    msr     vbar_el1, x0

    /* Enable FP/SIMD - required for varargs functions */
    mov     x0, #(3 << 20)            /* FPEN = 11b: No trap to EL1 */
    msr     cpacr_el1, x0
    isb

    /* Configure SCTLR_EL1 */
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)         /* Disable MMU */
    bic     x0, x0, #(1 << 2)         /* Disable data cache */
    bic     x0, x0, #(1 << 12)        /* Disable instruction cache */
    bic     x0, x0, #(1 << 1)         /* Disable alignment checking */
    bic     x0, x0, #(1 << 3)         /* Disable stack alignment check for now */
    msr     sctlr_el1, x0
    isb

    /* Set up stack pointer */
    adrp    x0, _stack_top
    add     x0, x0, :lo12:_stack_top
    mov     sp, x0

    /* Clear BSS */
    adrp    x0, _bss_start
    add     x0, x0, :lo12:_bss_start
    adrp    x1, _bss_end
    add     x1, x1, :lo12:_bss_end
clear_bss:
    cmp     x0, x1
    bge     bss_cleared
    str     xzr, [x0], #8
    b       clear_bss

bss_cleared:
    /* Pre-MMU early-debug UART base, platform-aware.
     *
     * x19 was stashed at _kernel_entry with the MIDR_EL1 implementer
     * field (line 84 above).  Use it to pick the right UART PA so an
     * uncommented diagnostic write below lands somewhere real on
     * both QEMU virt and Apple Silicon.
     *
     *   implementer 0x61 ('a' = Apple) → s5l-uart at PA 0x235200000
     *   anything else                  → PL011 at PA 0x09000000
     *
     * The actual character write stays commented out by default —
     * uncomment when debugging a hang before MMU comes up.  The
     * s5l-uart data register is at base + 0x20 (UTXH), unlike PL011
     * which uses base + 0x00, so the stores below differ between
     * the two paths.
     */
    cmp     x19, #0x61
    b.ne    1f
    /* Apple s5l-uart at PA 0x235200000 — bits [35:32]=0x2,
     * [31:16]=0x3520, [15:0]=0x0000.  Three movk steps build it. */
    movz    x10, #0x0000
    movk    x10, #0x3520, lsl #16
    movk    x10, #0x0002, lsl #32
    // mov     x11, #0x41
    // strb    w11, [x10, #0x20]         /* s5l-uart UTXH = base + 0x20 */
    b       2f
1:  /* QEMU virt PL011 at PA 0x09000000 */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    // mov     x11, #0x41
    // strb    w11, [x10]                /* PL011 data reg = base + 0x00 */
2:

    /* Compute the kernel's actual load PA so the page tables below
     * are relocatable.  Saved in callee-saved registers x21-x23:
     *   x21 = _start PA, 2 MiB-aligned-down  (high-VA L2 target PA)
     *   x22 = x21 1 GiB-aligned-down         (identity 1 GiB block base)
     *   x23 = x22 >> 30                      (L1 index for that block)
     *
     * For QEMU virt with kernel loaded at PA 0x40200000:
     *   x21 = 0x40200000, x22 = 0x40000000, x23 = 1 — exactly the
     *   values that used to be hardcoded.  For loaders that drop the
     *   image at a different PA (m1n1-style relocation within the
     *   48-bit VA window), the kernel still gets a correct identity
     *   map and high-VA mapping.  All five kernel-side Apple Silicon
     *   bring-up blockers are done — see
     *   docs/APPLE_SILICON_BRINGUP_PLAN.md for the status sheet. */
    adr     x21, _start
    bic     x21, x21, #0x1FFFFF       /* 2 MB align down */
    bic     x22, x21, #0x3FFFFFFF     /* 1 GB align down */
    lsr     x23, x22, #30             /* L1 entry index */

    /* Publish the discovered values to C-readable globals so the rest
     * of the kernel can support relocated boots once the runtime
     * KERN_PA_BASE conversion lands (bring-up blocker #3). */
    adrp    x9, g_kernel_load_pa
    add     x9, x9, :lo12:g_kernel_load_pa
    str     x21, [x9]
    adrp    x9, g_kernel_dram_pa
    add     x9, x9, :lo12:g_kernel_dram_pa
    str     x22, [x9]
    adrp    x9, g_kernel_l1_index
    add     x9, x9, :lo12:g_kernel_l1_index
    str     x23, [x9]

    /* ========================================
     *   MMU Initialization
     * ======================================== */

    /* Setup identity mapping for first 1GB of RAM
     * QEMU virt machine has DRAM at 0x40000000-0x80000000
     * We'll use 2MB block mappings at level 2 for simplicity
     */

    /* Get base address of boot L1 table.
     *
     * We use 48-bit VA (T0SZ = T1SZ = 16) so the walk starts at L0,
     * which is set up below as a wrapper that points at this L1
     * table.  L1/L2 contents still mirror the original 39-bit
     * layout (peripherals at L1[0], DRAM at L1[load_PA >> 30]),
     * which means the existing 2654/2654 selftest is bit-identical
     * to the pre-48-bit-VA flow.  ARM64 4 KiB-granule walk depth by
     * VA size:
     *   48-bit VA: L0 (T0SZ=16) ← We use this
     *   39-bit VA: L1 (T0SZ=25)
     *   30-bit VA: L2 (T0SZ=34) */
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table

    /* Zero out all page tables first */
    mov     x1, #0
    mov     x2, #(4096 * 3 / 8)       /* 3 tables: L1, L2_peripherals, L2_dram */
1:  str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, x2
    blt     1b

    /* Debug: Tables zeroed */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x31                
    // strb    w11, [x10] 

    /* Setup L1 table (L0 root above wraps this — see MMU enable comment)
     * L1 entry 0 (VA 0x00000000-0x3FFFFFFF): Point to L2_peripherals
     * L1 entry 1 (VA 0x40000000-0x7FFFFFFF): Point to L2_dram
     */
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table

    /* L1[0] -> L2_peripherals (for VA 0x00000000-0x3FFFFFFF) */
    adrp    x1, boot_l2_table_peripherals
    add     x1, x1, :lo12:boot_l2_table_peripherals
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]

    /* L1[load-PA >> 30] -> L2_dram.  Dynamic so the kernel stays
     * relocatable; for QEMU virt (load PA = 0x40200000) x23 == 1 so
     * this lands in L1[1] just like the previous hardcoded entry. */
    adrp    x1, boot_l2_table_dram
    add     x1, x1, :lo12:boot_l2_table_dram
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, x23, lsl #3]     /* L1[x23] = entry */

    /* L1[256] -> PCIe ECAM 1GB block (for VA 0x4000000000-0x403FFFFFFF) */
    /* 1GB block base PA = 0x4000000000 (maps ECAM at 0x4010000000 via offset) */
    movz    x1, #0x40, lsl #32        /* PA = 0x4000000000 (1GB block base) */
    mov     x2, #0x405                /* Valid | Block | AttrIndx=1 (device) | AF */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x1, x1, x2                /* Combine PA with flags */
    str     x1, [x0, #(256 * 8)]      /* L1[256] */

    /* Debug: L1 table configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x32                
    // strb    w11, [x10] 

    /* Setup L2_peripherals: 256 x 2MB blocks for 0x00000000-0x20000000 (512MB peripherals)
     * Each 2MB block, device memory
     * NOTE: UART at 0x09000000, virtio-mmio at 0x0a000000, PCI MMIO at 0x10000000-0x3EFF0000
     */
    adrp    x0, boot_l2_table_peripherals
    add     x0, x0, :lo12:boot_l2_table_peripherals
    mov     x1, #0x00000000           /* Start PA */
    mov     x3, #512                  /* Map full 1GB to cover PCI MMIO + ECAM window */
    movz    x5, #0x0020, lsl #16      /* 2MB block size = 0x200000 */
2:  mov     x2, #0x405                /* Valid (bit 0) | Block (bit 1=0) | AttrIndx=1 (bit 2) | AF (bit 10) */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store entry and advance pointer */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     2b

    /* Debug: L2 peripherals configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x33                
    // strb    w11, [x10] 

    /* Setup L2_dram: 512 x 2MB blocks for 0x40000000-0x80000000 (1GB DRAM)
     * Each 2MB block, normal memory
     */
    adrp    x0, boot_l2_table_dram
    add     x0, x0, :lo12:boot_l2_table_dram
    /* Boot table: identity mapping PA=VA starting from the 1 GiB-
     * aligned region containing the kernel.  For QEMU virt
     * (kernel at PA 0x40200000) this is 0x40000000 — same as the
     * previous hardcoded literal — and covers the DTB at 0x40000000
     * too.  For a relocated load PA the identity window slides with
     * the kernel so we still execute from valid VA = PA mappings
     * across the MMU-enable transition. */
    mov     x1, x22                   /* Start PA = 1 GiB-aligned load PA (was hardcoded 0x40000000) */
    mov     x3, #512                  /* 512 entries = 1GB */
    movz    x5, #0x0020, lsl #16      /* 2MB block size = 0x200000 */
3:  mov     x2, #0x401                /* Valid (bit 0) | Block (bit 1=0) | AttrIndx=0 | AF (bit 10) */
    orr     x2, x2, #(3 << 8)         /* SH=11: Inner Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store entry and advance pointer */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     3b

    /* Debug: L2 DRAM configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x34                
    // strb    w11, [x10] 

    /* ========================================
     *   Setup Kernel Page Tables (TTBR1_EL1)
     *   Maps high VA to same physical addresses as boot tables
     * ======================================== */

    /* Zero out kernel page tables */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table
    mov     x1, #0
    mov     x2, #(4096 * 3 / 8)       /* 3 tables: L1, L2_peripherals, L2_dram */
4:  str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, x2
    blt     4b

    /* Setup kernel_l1_table for high VA
     * L1[0] (VA 0xFFFF000000000000) -> kernel_l2_table_peripherals
     * L1[1] (VA 0xFFFF000040000000) -> kernel_l2_table_dram
     */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table

    /* kernel_l1[0] -> kernel_l2_table_peripherals */
    adrp    x1, kernel_l2_table_peripherals
    add     x1, x1, :lo12:kernel_l2_table_peripherals
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #0]

    /* kernel_l1[1] -> kernel_l2_table_dram */
    adrp    x1, kernel_l2_table_dram
    add     x1, x1, :lo12:kernel_l2_table_dram
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #8]

    /* kernel_l1[8..39] -> 32 GiB of Apple peripheral PA range
     *
     * Maps VA 0xFFFFFF8200000000 - 0xFFFFFF89FFFFFFFF (32 GiB) to
     * PA 0x200000000 - 0x9FFFFFFFF using 1 GiB block descriptors
     * with device-nGnRE memory attributes.
     *
     * Apple Silicon places its on-die peripherals at PA 0x200000000+
     * which the boot identity map (low 1 GiB) and kernel DRAM
     * mapping (1 GiB at the kernel load PA) both miss.  Without this
     * range, Rust drivers passing DTB-discovered PAs (s5l-uart at
     * 0x235200000, AIC at 0x23B100000, ANS mailbox at 0x277400000,
     * DCP at 0x231100000, SMC at 0x23E400000, MCA at 0x2D5200000,
     * PCIe root complex at 0x690000000, PCIe ECAM at 0x6a0000000,
     * ...) as VAs would translation-fault on the first MMIO touch.
     *
     * The 32 GiB window was sized to cover PCIe (PA 0x690000000 on
     * M1) along with the lower SoC peripheral block — an 8 GiB
     * window would have stopped at PA 0x3FFFFFFFF and missed PCIe
     * by ~22 GiB.  M1 Pro / Max push PCIe higher still (PA
     * 0xc00000000); those configurations will need an extended
     * window once we have a real machine to test against.
     *
     * C callers convert PA→VA via the helper that ORs in
     * 0xFFFFFF8000000000 (declared in include/platform/arm64/memory/pmap.h).
     *
     * On QEMU virt these L1 entries point at unbacked PA — harmless
     * because no QEMU-side code accesses VAs in the 0xFFFFFF8200000000+
     * range. */
    adrp    x0, kernel_l1_table
    add     x0, x0, :lo12:kernel_l1_table
    add     x0, x0, #(8 * 8)          /* L1[8] */
    movz    x1, #0x0002, lsl #32      /* Start PA = 0x2_0000_0000 (8 GiB) */
    mov     x3, #32                   /* 32 entries × 1 GiB = 32 GiB */
    mov     x4, #0x40000000           /* 1 GiB stride */
9:  movz    x2, #0x0605               /* Valid|Block|AttrIdx=1(dev)|AF|SH=10 */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store and advance */
    add     x1, x1, x4                /* Next 1 GiB block */
    subs    x3, x3, #1
    bne     9b

    /* Setup kernel_l2_table_peripherals: Same as boot, but for high VA */
    adrp    x0, kernel_l2_table_peripherals
    add     x0, x0, :lo12:kernel_l2_table_peripherals
    mov     x1, #0x00000000           /* Start PA */
    mov     x3, #512                  /* 512 x 2MB = 1GB (match boot table) */
    movz    x5, #0x0020, lsl #16      /* 2MB block size */
5:  mov     x2, #0x405                /* Valid | Block | AttrIndx=1 (device) | AF */
    orr     x2, x2, #(2 << 8)         /* SH=10: Outer Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store and advance */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     5b

    /* Setup kernel_l2_table_dram: Map high VA to kernel physical address.
     * High-VA target is KERN_VA_BASE (0xFFFFFF8040000000); PA is the
     * 2 MiB-aligned-down load PA computed above (x21).  For QEMU virt
     * x21 == 0x40200000 — identical to the previous hardcoded value —
     * so the mapping VA 0xFFFFFF8040000000 → PA 0x40200000 is
     * preserved.  Once dynamic KERN_PA_BASE lands (see
     * docs/APPLE_SILICON_BRINGUP_PLAN.md item 3) loaders can drop the
     * kernel anywhere in DRAM and this path will still be correct. */
    adrp    x0, kernel_l2_table_dram
    add     x0, x0, :lo12:kernel_l2_table_dram
    mov     x1, x21                   /* Start PA = 2 MiB-aligned load PA */
    mov     x3, #512                  /* 512 x 2MB = 1GB */
    movz    x5, #0x0020, lsl #16      /* 2MB block size */
6:  mov     x2, #0x401                /* Valid | Block | AttrIndx=0 (normal) | AF */
    orr     x2, x2, #(3 << 8)         /* SH=11: Inner Shareable */
    orr     x2, x1, x2                /* Combine PA with flags */
    str     x2, [x0], #8              /* Store and advance */
    add     x1, x1, x5                /* Next 2MB block */
    subs    x3, x3, #1
    bne     6b

    /* Debug: Kernel tables configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x4B                
    // strb    w11, [x10] 

    /* Configure MAIR_EL1 (Memory Attribute Indirection Register)
     * Index 0 = 0xFF (Normal memory, Inner/Outer Write-Back, Read/Write Allocate)
     *           Used by boot page tables and PTE_ATTR_NORMAL
     * Index 1 = 0x00 (Device-nGnRnE - for UART, GIC, framebuffer MMIO)
     *           Used by PTE_ATTR_DEVICE_nGnRnE
     * Combined value: 0x00000000_000000FF
     */
    movz    x0, #0x00FF               /* Idx0=0xFF(Normal), Idx1=0x00(Device) */
    msr     mair_el1, x0

    /* Debug: MAIR configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x35                
    // strb    w11, [x10] 

    /* ========================================
     *   Setup L0 page tables (48-bit VA root)
     *
     * The existing boot_l1_table / kernel_l1_table chains were
     * designed for 39-bit VA where ARM64 starts the walk at L1.
     * Wrap them in an L0 root so the kernel can address PAs above
     * the 512 GB / 39-bit window — Apple Silicon DRAM lives in that
     * region.  The wrap is cost-free for QEMU virt: L0 has one
     * populated entry per TTBR, indexes 0 and 511 respectively.
     * ======================================== */

    /* Zero L0 tables */
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table
    mov     x1, #0
.Lzero_boot_l0:
    str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, #512
    blt     .Lzero_boot_l0

    adrp    x0, kernel_l0_table
    add     x0, x0, :lo12:kernel_l0_table
    mov     x1, #0
.Lzero_kernel_l0:
    str     xzr, [x0, x1, lsl #3]
    add     x1, x1, #1
    cmp     x1, #512
    blt     .Lzero_kernel_l0

    /* boot_l0_table[L0_idx] -> boot_l1_table.  L0 idx = bits 47:39 of
     * the identity DRAM base (x22).  For QEMU virt x22 < 2^39 so
     * L0_idx = 0; for Apple Silicon with kernel above 512 GB it lands
     * in the appropriate higher slot. */
    lsr     x24, x22, #39
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table
    adrp    x1, boot_l1_table
    add     x1, x1, :lo12:boot_l1_table
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, x24, lsl #3]

    /* kernel_l0_table[511] -> kernel_l1_table.  KERN_VA_BASE
     * (0xFFFFFF8040000000) sits at the top of the 256 TB upper-half
     * VA range, which puts it in L0 index 511 regardless of load PA. */
    adrp    x0, kernel_l0_table
    add     x0, x0, :lo12:kernel_l0_table
    adrp    x1, kernel_l1_table
    add     x1, x1, :lo12:kernel_l1_table
    orr     x1, x1, #3                /* Valid table descriptor */
    str     x1, [x0, #(511 * 8)]

    /* Configure TCR_EL1 (Translation Control Register).
     * T0SZ / T1SZ = 16: 48-bit VA, walk starts at L0.
     * TG0 = 00, TG1 = 10: 4KB granule.
     * SH0/SH1 = 11: Inner shareable.
     * IRGN/ORGN = 01: Normal, WB RA WA.
     * IPS = 010: 40-bit PA space (sufficient for QEMU virt 1 GiB
     * DRAM and the early Apple Silicon bring-up window).
     *
     * 48-bit VA is the long-term layout — covers Apple Silicon DRAM
     * past the old 39-bit / 512 GB window — and is a strict superset
     * of the 39-bit space the QEMU virt path used before, so existing
     * kernel/user VAs translate identically. */
    movz    x0, #0x3510               /* Bits [15:0]: T0SZ=16, IRGN0=01, ORGN0=01, SH0=11, TG0=00 */
    movk    x0, #0xB510, lsl #16     /* Bits [31:16]: T1SZ=16, IRGN1=01, ORGN1=01, SH1=11, TG1=10 */

    /* IPS: pin the CPU's hardware-reported max PA range so we don't
     * advertise more PA addressability than the chip supports.  Apple
     * Silicon M1/M2 report PARange=0b101 (48-bit PA / 256 TB), which
     * we want to honour — the old hardcoded IPS=010 (40-bit PA / 1 TB)
     * could clip Apple DRAM that lives above the 1 TB boundary.  Read
     * ID_AA64MMFR0_EL1.PARange (bits [3:0]) and copy into IPS (bits
     * [34:32]).  QEMU cortex-a53 reports PARange=0b010, so the QEMU
     * virt path gets the same value it had before. */
    mrs     x1, id_aa64mmfr0_el1
    and     x1, x1, #0xF              /* PARange field (bits 3:0) */
    lsl     x1, x1, #32               /* Move to TCR IPS slot (bits 34:32) */
    orr     x0, x0, x1
    msr     tcr_el1, x0

    /* Debug: TCR configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x36
    // strb    w11, [x10]

    /* Set TTBR0_EL1 to boot L0 table (identity mapping for early boot) */
    adrp    x0, boot_l0_table
    add     x0, x0, :lo12:boot_l0_table
    msr     ttbr0_el1, x0

    /* Set TTBR1_EL1 to kernel L0 table (high VA mapping for kernel) */
    adrp    x0, kernel_l0_table
    add     x0, x0, :lo12:kernel_l0_table
    msr     ttbr1_el1, x0

    /* Debug: TTBR configured */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x37                
    // strb    w11, [x10] 

    /* Verify L2_dram[0] descriptor (debug) */
    adrp    x0, boot_l2_table_dram
    add     x0, x0, :lo12:boot_l2_table_dram
    ldr     x1, [x0, #0]              /* Load first L2 entry */
    /* Expected: 0x40000701 - we'll continue regardless */

    /* Invalidate TLBs and caches before enabling MMU */
    tlbi    vmalle1                   /* Invalidate all TLB entries for EL1 */
    ic      iallu                     /* Invalidate all instruction caches to PoU */
    dsb     sy                        /* Ensure all invalidations complete */
    isb                               /* Synchronize instruction stream */

    /* Debug: About to enable MMU */
    movz    x10, #0x0900, lsl #16
    // mov     x11, #0x38                
    // strb    w11, [x10] 

    /* Enable MMU.
     *
     * Page table layout (48-bit VA, T0SZ=T1SZ=16, L0 root since
     * commit ffd99e31 — see docs/APPLE_SILICON_BRINGUP_PLAN.md):
     *
     * - TTBR0/TTBR1 → L0 table (root for 48-bit VA)
     * - L0[load_PA >> 39]  → boot_l1_table (identity DRAM)
     * - L0[511]            → kernel_l1_table (high-VA kernel)
     * - L1[0]              → L2_peripherals (1 GiB of UART / GIC / MMIO)
     * - L1[load_PA >> 30]  → L2_dram (1 GiB of identity DRAM)
     * - L2 entries are 2 MiB blocks
     *
     * For QEMU virt the load PA is 0x40200000 so L0 idx = 0 and
     * L1 idx = 1, exactly matching the pre-48-bit-VA layout. */
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)    /* M: Enable MMU */
    orr     x0, x0, #(1 << 2)    /* C: Enable data cache */
    orr     x0, x0, #(1 << 12)   /* I: Enable instruction cache */
    bic     x0, x0, #(1 << 1)    /* A: Disable alignment checking */
    bic     x0, x0, #(1 << 3)    /* SA: Disable stack alignment EL1 */
    bic     x0, x0, #(1 << 4)    /* SA0: Disable stack alignment EL0 */
    msr     sctlr_el1, x0
    isb

    /* Debug: Write 'B' to UART after MMU enable (proves MMU worked!) */
    movz    x10, #0x0900, lsl #16     /* UART0 base = 0x09000000 */
    // mov     x11, #0x42                
    // strb    w11, [x10]                /* Write to UART data register */ 

    /* Jump to high VA kernel address
     * Currently executing at low VA (identity mapped via TTBR0)
     * Need to switch to high VA (mapped via TTBR1)
     *
     * QEMU loads kernel at PA 0x40200000, but linker expects PA 0x40000000
     * Page tables map VA 0xFFFFFF8040000000 → PA 0x40200000
     * So: PA 0x40200xxx → VA 0xFFFFFF8040000xxx (subtract PA base, add VA base)
     */
    adr     x0, .Lhigh_va_entry       /* Get actual PA (PC-relative, ~0x4020xxxx) */
    movz    x1, #0x4020, lsl #16      /* PA base = 0x40200000 (QEMU kernel load address) */
    sub     x0, x0, x1                /* x0 = offset from PA base */
    movz    x1, #0xFFFF, lsl #48      /* VA base (high 16 bits) */
    movk    x1, #0xFF80, lsl #32      /* VA base (bits 47:32) */
    movk    x1, #0x4000, lsl #16      /* VA base (bits 31:16) = 0xFFFFFF8040000000 */
    add     x0, x0, x1                /* x0 = VA base + offset */
    br      x0                        /* Jump to high VA */

.Lhigh_va_entry:
    /* Now executing at high VA! All addresses from here on are high VA */

    /* Debug: Write 'H' to UART (now at high VA)
     * UART at PA 0x09000000 is mapped at VA 0xFFFFFF8009000000
     * (kernel_l1[0] -> peripherals at 0xFFFFFF8000000000+)
     */
    movz    x10, #0xFFFF, lsl #48     /* High VA base (0xFFFF000000000000) */
    movk    x10, #0xFF80, lsl #32     /* Add kernel offset (0xFFFFFF8000000000) */
    movk    x10, #0x0900, lsl #16     /* Add UART offset (0x09000000) */
    // mov     x11, #0x48                
    // strb    w11, [x10] 

    /* Update VBAR_EL1 to high VA exception vectors
     * The exception vector table is now at high VA, so update VBAR
     */
    adrp    x0, exception_vectors
    add     x0, x0, :lo12:exception_vectors
    msr     vbar_el1, x0
    isb

    /* Debug: VBAR updated */
    movz    x10, #0xFFFF, lsl #48
    movk    x10, #0xFF80, lsl #32
    movk    x10, #0x0900, lsl #16
    // mov     x11, #0x56                
    // strb    w11, [x10] 

    /* Clear TTBR0_EL1 now that we're running at high VA
     * User processes will set their own TTBR0 page tables later
     */
    mov     x0, #0
    msr     ttbr0_el1, x0
    isb

    /* Debug: TTBR0 cleared */
    movz    x10, #0xFFFF, lsl #48
    movk    x10, #0xFF80, lsl #32
    movk    x10, #0x0900, lsl #16
    // mov     x11, #0x54                
    // strb    w11, [x10] 

    /* Fix stack pointer for high VA execution.
     *
     * SP_EL1 was set to the PA of _stack_top at line 148 (MMU off, adrp
     * resolved to PA). Now that the MMU is on and we're executing at
     * high VA, reload SP directly from the symbol — adrp here resolves
     * to the symbol's high-VA address since the linker placed the kernel
     * at KERN_VA_BASE.
     *
     * The previous code added a hard-coded offset of 0xFFFFFF8000000000
     * (computed as KERN_VA_BASE - 0x40000000), but the kernel actually
     * loads at PA 0x40200000 (QEMU ARM64 Image format places the kernel
     * 2 MiB above DRAM base), so the correct offset is 0xFFFFFF7FFFE00000.
     * The 2 MiB error pushed SP _above_ the linked stack region (past
     * _stack_top) into the kernel heap. Once buddy_malloc handed out a
     * 64 KiB chunk that happened to span the live SP, the slab init
     * loop's writes to obj->next clobbered the local `slab` pointer on
     * the stack, producing the long-running "[SLAB-VALIDATE] Slab has
     * corrupted magic" / "[SLAB-MALLOC] data range [0,0]" reports during
     * early boot.
     *
     * Reloading from the symbol sidesteps the offset bug entirely: the
     * page tables and the linker agree on where _stack_top lives. */
    adrp    x0, _stack_top
    add     x0, x0, :lo12:_stack_top
    mov     sp, x0

    /* Debug: Stack pointer updated */
    movz    x10, #0xFFFF, lsl #48
    movk    x10, #0xFF80, lsl #32
    movk    x10, #0x0900, lsl #16
    // mov     x11, #0x53                
    // strb    w11, [x10] 

    /* Restore device tree address and call platform init */
    mov     x0, #0                    /* boot_magic = 0 */
    mov     x1, x20                   /* boot_info = device tree address */

    /* Debug: Write 'C' before calling platform_init */
    movz    x10, #0xFFFF, lsl #48     /* High VA base */
    movk    x10, #0xFF80, lsl #32     /* Add kernel offset */
    movk    x10, #0x0900, lsl #16     /* Add UART offset */
    // mov     x11, #0x43                
    // strb    w11, [x10] 

    bl      fut_platform_init

    /* Should never return */
    b       .

/*
 * Exception vector table
 * ARM64 has 16 exception vectors (4 types × 4 exception levels)
 */
.align 11
.global exception_vectors
exception_vectors:
    /* Current EL with SP0 */
    .align 7
    b       sync_sp0_handler
    .align 7
    b       irq_sp0_handler
    .align 7
    b       fiq_sp0_handler
    .align 7
    b       serror_sp0_handler

    /* Current EL with SPx */
    .align 7
    b       sync_spx_handler
    .align 7
    b       irq_spx_handler
    .align 7
    b       fiq_spx_handler
    .align 7
    b       serror_spx_handler

    /* Lower EL using AArch64 */
    .align 7
    b       sync_aarch64_handler
    .align 7
    b       irq_aarch64_handler
    .align 7
    b       fiq_aarch64_handler
    .align 7
    b       serror_aarch64_handler

    /* Lower EL using AArch32 */
    .align 7
    b       sync_aarch32_handler
    .align 7
    b       irq_aarch32_handler
    .align 7
    b       fiq_aarch32_handler
    .align 7
    b       serror_aarch32_handler

/*
 * Exception handlers
 */

/* Synchronous exception from current EL with SP0 */
sync_sp0_handler:
    b       sync_exception_entry

/* IRQ from current EL with SP0 */
irq_sp0_handler:
    b       irq_handler_entry

/* FIQ from current EL with SP0 */
fiq_sp0_handler:
    b       fiq_handler_entry

/* SError from current EL with SP0 */
serror_sp0_handler:
    b       generic_exception_handler

/* Synchronous exception from current EL with SPx */
sync_spx_handler:
    b       sync_exception_entry

/* IRQ from current EL with SPx */
irq_spx_handler:
    b       irq_handler_entry

/* FIQ from current EL with SPx */
fiq_spx_handler:
    b       fiq_handler_entry

/* SError from current EL with SPx */
serror_spx_handler:
    b       generic_exception_handler

/* Synchronous exception from lower EL (AArch64) */
sync_aarch64_handler:
    b       sync_exception_entry

/* IRQ from lower EL (AArch64) */
irq_aarch64_handler:
    b       irq_handler_entry

/* FIQ from lower EL (AArch64) */
fiq_aarch64_handler:
    b       fiq_handler_entry

/* SError from lower EL (AArch64) */
serror_aarch64_handler:
    b       generic_exception_handler

/* Synchronous exception from lower EL (AArch32) */
sync_aarch32_handler:
    b       sync_exception_entry

/* IRQ from lower EL (AArch32) */
irq_aarch32_handler:
    b       irq_handler_entry

/* FIQ from lower EL (AArch32) */
fiq_aarch32_handler:
    b       generic_exception_handler

/* SError from lower EL (AArch32) */
serror_aarch32_handler:
    b       generic_exception_handler

/*
 * Generic exception handler
 */
.align 4
generic_exception_handler:
    /* Save all registers for debugging */
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x28, x29, [sp, #-16]!
    stp     x30, xzr, [sp, #-16]!

    /* Print exception message */
    adr     x0, exception_msg
    bl      fut_serial_puts

    /* Print ESR_EL1 (Exception Syndrome Register) */
    adr     x0, esr_msg
    bl      fut_serial_puts
    mrs     x0, esr_el1
    bl      print_hex64

    /* Print FAR_EL1 (Fault Address Register) */
    adr     x0, far_msg
    bl      fut_serial_puts
    mrs     x0, far_el1
    bl      print_hex64

    /* Print ELR_EL1 (Exception Link Register - return address) */
    adr     x0, elr_msg
    bl      fut_serial_puts
    mrs     x0, elr_el1
    bl      print_hex64

    /* Print SP */
    adr     x0, sp_msg
    bl      fut_serial_puts
    mov     x0, sp
    bl      print_hex64

    /* Halt */
1:  wfi
    b       1b

exception_msg:
    .asciz  "\n[EXCEPTION] ARM64 exception occurred!\n"
esr_msg:
    .asciz  "ESR_EL1: 0x"
far_msg:
    .asciz  "\nFAR_EL1: 0x"
elr_msg:
    .asciz  "\nELR_EL1: 0x"
sp_msg:
    .asciz  "\nSP:      0x"

/* Helper function to print 64-bit hex value */
.align 4
print_hex64:
    stp     x29, x30, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!

    mov     x19, x0               /* Save value */
    mov     x20, #60              /* Start with highest nibble (15 * 4 = 60) */

1:  /* Print each nibble */
    lsr     x0, x19, x20          /* Shift right by bit position */
    and     x0, x0, #0xf          /* Mask to get 4 bits */

    /* Convert to hex character */
    cmp     x0, #10
    blt     2f
    add     x0, x0, #('a' - 10)
    b       3f
2:  add     x0, x0, #'0'
3:
    bl      fut_serial_putc

    /* Next nibble */
    subs    x20, x20, #4
    bge     1b

    /* Print newline */
    mov     x0, #'\n'
    bl      fut_serial_putc

    ldp     x19, x20, [sp], #16
    ldp     x29, x30, [sp], #16
    ret

/*
 * FIQ handler entry point — same register-save dance as IRQ.
 *
 * Apple Silicon delivers the ARM Generic Timer via FIQ rather than
 * IRQ, so the FIQ vectors need a real dispatcher.  Routes through
 * fut_fiq_handler → fut_fiq_main (platform_init.c) → the FIQ
 * dispatch backend that apple_aic_init installs.  On QEMU virt no
 * peripheral delivers FIQ and the backend stays NULL — fut_fiq_main
 * returns silently, the asm restores registers and erets.
 */
.align 4
fiq_handler_entry:
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x28, x29, [sp, #-16]!
    stp     x30, xzr, [sp, #-16]!

    bl      fut_fiq_handler

    ldp     x30, xzr, [sp], #16
    ldp     x28, x29, [sp], #16
    ldp     x26, x27, [sp], #16
    ldp     x24, x25, [sp], #16
    ldp     x22, x23, [sp], #16
    ldp     x20, x21, [sp], #16
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16

    eret

/*
 * IRQ handler entry point
 */
.align 4
irq_handler_entry:
    /* Save all registers */
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x4, x5, [sp, #-16]!
    stp     x6, x7, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x10, x11, [sp, #-16]!
    stp     x12, x13, [sp, #-16]!
    stp     x14, x15, [sp, #-16]!
    stp     x16, x17, [sp, #-16]!
    stp     x18, x19, [sp, #-16]!
    stp     x20, x21, [sp, #-16]!
    stp     x22, x23, [sp, #-16]!
    stp     x24, x25, [sp, #-16]!
    stp     x26, x27, [sp, #-16]!
    stp     x28, x29, [sp, #-16]!
    stp     x30, xzr, [sp, #-16]!

    /* Call IRQ handler */
    bl      fut_irq_handler

    /* Restore all registers */
    ldp     x30, xzr, [sp], #16
    ldp     x28, x29, [sp], #16
    ldp     x26, x27, [sp], #16
    ldp     x24, x25, [sp], #16
    ldp     x22, x23, [sp], #16
    ldp     x20, x21, [sp], #16
    ldp     x18, x19, [sp], #16
    ldp     x16, x17, [sp], #16
    ldp     x14, x15, [sp], #16
    ldp     x12, x13, [sp], #16
    ldp     x10, x11, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x6, x7, [sp], #16
    ldp     x4, x5, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16

    eret

/*
 * IRQ handler (C function)
 *
 * Simplified handler that only dispatches timer IRQs properly.
 * Other IRQs (like UART) are handled via registered handlers in arm64_irq.c,
 * but require proper interrupt frame setup which is currently simplified.
 *
 * Handler Dispatch Implementation Plan:
 *
 * Phase 1 (Current): Timer-only dispatch
 * - Timer IRQ (30) routed to dedicated handler with full frame context
 * - All other IRQs: acknowledge and return (no dispatch framework)
 * - Rationale: Timer is critical for scheduler; other IRQs not yet needed
 * - Status: Functional but limited
 *
 * Phase 2 (Planned): Registered handler framework
 * - Build IRQ dispatch table indexed by IRQ number
 * - For each IRQ: save full context frame, dispatch to registered handler
 * - Handlers registered via arm64_irq_register_handler(irq, fn)
 * - Frame structure passed to handler function (like exception handlers)
 * - EOI sent after handler returns (unless handler defers it)
 * - Rationale: Enables UART, virtio, PCI, and device driver interrupts
 * - Requirements: Handler table allocation, handler function signature
 *
 * Phase 3 (Future): Context-preserving dispatch with return values
 * - Handlers can modify interrupt frame (like signal delivery)
 * - Handler return value indicates: handled, deferred, error
 * - Integrate with scheduler for handler preemption
 * - Nested interrupt support with interrupt stack
 * - Rationale: Complex interrupt handling scenarios
 * - Requirements: Handler priority levels, nested interrupt stacks
 *
 * Current Limitations:
 * - No IRQ handler dispatch for devices (UART, VirtIO, etc.)
 * - Each device must work around this or be timer-polled
 * - No mechanism to register device-specific handlers
 * - Devices that need interrupts are not yet supported on ARM64
 *
 * Handler Frame Structure (to be used in Phase 2):
 * - Identical to exception frame from arm64_exception_entry.S
 * - Registers X0-X30 preserved for handler inspection
 * - X0-X7 available for handler arguments/return values
 * - Handler can modify PC (similar to signal delivery)
 * - SP, PSTATE preserved for correct return-to-interrupted context
 *
 * UART Interrupt Example (Phase 2):
 * 1. UART IRQ asserted (IRQ 33 on virt machine)
 * 2. CPU vectors to IRQ handler, saves context
 * 3. fut_irq_handler reads GIC, gets IRQ 33
 * 4. Dispatch table[33] = uart_irq_handler
 * 5. Call uart_irq_handler(frame) with full context
 * 6. Handler processes UART FIFO, signals reading task
 * 7. Return and send EOI to GIC
 * 8. Check reschedule flag (like timer does)
 * 9. ERET returns to interrupted context
 *
 * VirtIO Block/Net Example (Phase 2):
 * 1. Device completion interrupt asserted
 * 2. fut_irq_handler routes to registered virtio_handler
 * 3. Handler processes completion descriptors
 * 4. Wakes up blocked I/O waiters
 * 5. EOI sent, context restored
 * 6. I/O tasks scheduled if needed
 *
 * Design Decision (Current):
 * - Keep Phase 1 simple: only timer works
 * - No partial device interrupt support
 * - Better to have working timer than broken device interrupts
 * - Phase 2 requires design decisions: priority levels, handler contexts
 * - Wait for real device usage to drive requirements
 */
.type fut_irq_handler, @function
fut_irq_handler:
    /* Thin trampoline to the C dispatcher (platform_init.c:
     * fut_irq_dispatch).  The C function holds the GIC IAR/EOI flow
     * and the timer-vs-other branch — both of which are easier to
     * keep right in C than in asm — and can transparently delegate
     * to apple_aic_handle_irq() once the AIC backend is installed by
     * the platform-init path on Apple Silicon (blocker #5 in
     * docs/APPLE_SILICON_BRINGUP_PLAN.md). */
    stp     x29, x30, [sp, #-16]!
    bl      fut_irq_main
    ldp     x29, x30, [sp], #16
    ret

.global fut_fiq_handler
.type fut_fiq_handler, @function
fut_fiq_handler:
    /* FIQ trampoline mirror of fut_irq_handler.  fut_fiq_main has
     * its own backend slot, set on Apple Silicon by apple_aic_init.
     * On QEMU virt the slot stays NULL and this is a fast no-op. */
    stp     x29, x30, [sp, #-16]!
    bl      fut_fiq_main
    ldp     x29, x30, [sp], #16
    ret

/*
 * External symbols defined by linker script
 */
.extern _stack_top
.extern _bss_start
.extern _bss_end
.extern fut_in_interrupt

/* ============================================================
 *   Runtime kernel-load metadata
 *
 * boot.S writes the discovered load PA into these symbols right after
 * the dynamic-PA computation but before any C code runs.  C-side
 * helpers (e.g. \`fut_kernel_load_pa()\` in platform_init.c) can read
 * them to support Apple-Silicon-style relocated boots once the
 * runtime KERN_PA_BASE conversion lands (Apple Silicon bring-up
 * blocker #3 in docs/APPLE_SILICON_BRINGUP_PLAN.md).
 *
 * On QEMU virt with the kernel loaded at PA 0x40200000 these end up
 * as 0x40200000 / 0x40000000 / 1 — matching the previously-hardcoded
 * literals — so existing #define-based code paths are still correct.
 * ============================================================ */

.section .bss
.align 8
.global g_kernel_load_pa
g_kernel_load_pa:
    .quad   0                         /* 2 MiB-aligned-down _start PA */
.global g_kernel_dram_pa
g_kernel_dram_pa:
    .quad   0                         /* 1 GiB-aligned-down identity region base */
.global g_kernel_l1_index
g_kernel_l1_index:
    .quad   0                         /* L1 entry index = g_kernel_dram_pa >> 30 */

/* ============================================================
 *   Boot Page Tables (in BSS)
 * ============================================================ */

.align 12                         /* 4KB alignment required for page tables */

/* Page tables for 48-bit VA space (T0SZ=16, T1SZ=16).
 * ARM64 with 48-bit VA + 4 KiB granule walks L0 → L1 → L2 → L3 (or
 * L2 block).  Each L0 entry covers 512 GB, each L1 covers 1 GB, each
 * L2 covers 2 MB.  We use 2 MB L2 blocks for kernel & identity DRAM
 * — the L3 table is never populated. */

/* Boot page tables - TTBR0_EL1 (identity mapping for early boot) */
.global boot_l0_table
boot_l0_table:
    .space 4096                   /* Level 0 (48-bit VA root, 512 x 512 GB entries) */

.global boot_l1_table
boot_l1_table:
    .space 4096                   /* Level 1 (512 x 1 GB per entry) */

boot_l2_table_peripherals:
    .space 4096                   /* Level 2 for peripherals (512 x 2MB = 1GB) */

boot_l2_table_dram:
    .space 4096                   /* Level 2 for DRAM (512 x 2MB = 1GB) */

/* Kernel page tables - TTBR1_EL1 (high VA mapping for kernel)
 * Maps high VA 0xFFFF000000000000+ to physical addresses
 * This allows kernel to run at high VA while user space uses low VA
 */
.global kernel_l0_table
kernel_l0_table:
    .space 4096                   /* Level 0 for high VA (entry 511 points to L1) */

.global kernel_l1_table
kernel_l1_table:
    .space 4096                   /* Level 1 for high VA */

kernel_l2_table_peripherals:
    .space 4096                   /* Level 2 for high VA peripherals */

kernel_l2_table_dram:
    .space 4096                   /* Level 2 for high VA kernel */

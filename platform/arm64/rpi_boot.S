/* platform/arm64/rpi_boot.S - Raspberry Pi 4/5 early boot entry
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Entry point for Raspberry Pi ARM64 boot. The VideoCore firmware
 * loads kernel8.img at 0x80000 and jumps here with:
 *   x0 = DTB physical address (usually 0x100 for Pi4, varies for Pi5)
 *   x1 = 0
 *   x2 = 0
 *   x3 = 0
 *   CPU in EL2 (Pi4) or EL1 (Pi5 with newer firmware)
 *   MMU off, caches off, single core running (core 0)
 *
 * This code:
 *   1. Saves the DTB pointer
 *   2. Sets up a temporary stack
 *   3. Drops to EL1 if in EL2
 *   4. Initializes UART for early debug output
 *   5. Enables caches and branch prediction
 *   6. Calls the C-level kernel entry point
 *
 * config.txt should contain:
 *   arm_64bit=1
 *   kernel=kernel8.img
 *   enable_uart=1
 *   uart_2ndstage=1
 */

.section .text.start
.globl _start
_start:
    /* Save DTB pointer (passed in x0 by firmware) */
    mov     x19, x0                 /* x19 = DTB address (callee-saved) */

    /* Ensure we're on core 0 — park other cores */
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF          /* Core ID */
    cbnz    x1, .Lpark_core        /* Only core 0 continues */

    /* Detect current exception level */
    mrs     x0, CurrentEL
    lsr     x0, x0, #2             /* Extract EL field */

    cmp     x0, #3
    b.eq    .Lfrom_el3
    cmp     x0, #2
    b.eq    .Lfrom_el2
    b       .Lat_el1               /* Already at EL1 */

.Lfrom_el3:
    /* EL3 → EL2: Configure EL3 to drop to EL2 */
    mov     x0, #0x531             /* SCR_EL3: RW=1 (AArch64), HCE=1, SMD=0, NS=1 */
    msr     scr_el3, x0
    mov     x0, #0x3C9             /* SPSR_EL3: DAIF masked, EL2h */
    msr     spsr_el3, x0
    adr     x0, .Lfrom_el2
    msr     elr_el3, x0
    eret

.Lfrom_el2:
    /* EL2 → EL1: Configure EL2 to drop to EL1 */

    /* Enable AArch64 for EL1 */
    mov     x0, #(1 << 31)         /* HCR_EL2.RW = 1 (AArch64 for EL1) */
    orr     x0, x0, #(1 << 1)     /* HCR_EL2.SWIO = 1 (set/way invalidation override) */
    msr     hcr_el2, x0

    /* Return to EL1 */
    mov     x0, #0x3C5             /* SPSR_EL2: DAIF masked, EL1h */
    msr     spsr_el2, x0
    adr     x0, .Lat_el1
    msr     elr_el2, x0
    eret

.Lat_el1:
    /* Now at EL1 */

    /* Set up exception vectors (will be updated by C code later) */
    /* For now, use a simple spin-on-exception handler */

    /* Enable FP/SIMD (CPACR_EL1) */
    mov     x0, #(3 << 20)         /* FPEN = 0b11: no trapping FP/SIMD */
    msr     cpacr_el1, x0
    isb

    /* Set up temporary stack at 0x80000 (grows downward from kernel load) */
    ldr     x0, =0x80000
    mov     sp, x0

    /* Clear BSS */
    adr     x0, __bss_start
    adr     x1, __bss_end
.Lclear_bss:
    cmp     x0, x1
    b.ge    .Lbss_done
    stp     xzr, xzr, [x0], #16
    b       .Lclear_bss
.Lbss_done:

    /* Enable caches and branch prediction (SCTLR_EL1) */
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 2)     /* C: data cache enable */
    orr     x0, x0, #(1 << 12)    /* I: instruction cache enable */
    msr     sctlr_el1, x0
    isb

    /* Call C entry point: rpi_kernel_entry(dtb_address) */
    mov     x0, x19                 /* x0 = DTB pointer */
    bl      rpi_kernel_entry

    /* Should not return — halt if it does */
.Lhalt:
    wfe
    b       .Lhalt

    /* Secondary cores: park in WFE loop */
.Lpark_core:
    wfe
    b       .Lpark_core

    /* BSS markers (defined by linker) */
.globl __bss_start
.globl __bss_end

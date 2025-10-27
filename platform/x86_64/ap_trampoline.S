/* ap_trampoline.S - Application Processor startup trampoline
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This code is copied to low memory (below 1MB) and executed by APs.
 * APs start in 16-bit real mode and must transition to 64-bit long mode.
 */

.code16
.section .text
.align 4096

.globl ap_trampoline_start
.globl ap_trampoline_end
.globl ap_trampoline_gdt64
.globl ap_trampoline_pml4
.globl ap_trampoline_stack
.globl ap_trampoline_target
.globl ap_trampoline_cpu_id

/* Entry point for APs (16-bit real mode)
 * The SIPI vector points to this code (physical address >> 12)
 */
ap_trampoline_start:
    cli                         /* Disable interrupts */
    cld                         /* Clear direction flag */

    /* Set up segments for real mode */
    xor     %ax, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    mov     %ax, %fs
    mov     %ax, %gs

    /* Load temporary GDT for protected mode transition */
    lgdtl   (ap_gdt32_desc - ap_trampoline_start)

    /* Enable protected mode (CR0.PE = 1) */
    mov     %cr0, %eax
    or      $1, %eax
    mov     %eax, %cr0

    /* Jump to 32-bit protected mode code */
    ljmpl   $0x08, $(ap_protected_mode - ap_trampoline_start)

/* 32-bit protected mode code */
.code32
ap_protected_mode:
    /* Set up segments for protected mode */
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    mov     %ax, %fs
    mov     %ax, %gs

    /* Enable PAE (CR4.PAE = 1) and PSE (CR4.PSE = 1) */
    mov     %cr4, %eax
    or      $(1 << 5) | (1 << 4), %eax  /* PAE | PSE */
    mov     %eax, %cr4

    /* Load PML4 (page table root) */
    mov     (ap_trampoline_pml4 - ap_trampoline_start), %eax
    mov     %eax, %cr3

    /* Enable long mode (EFER.LME = 1) and NXE */
    mov     $0xC0000080, %ecx       /* EFER MSR */
    rdmsr
    or      $(1 << 8) | (1 << 11), %eax  /* LME | NXE */
    wrmsr

    /* Enable paging (CR0.PG = 1) */
    mov     %cr0, %eax
    or      $(1 << 31), %eax        /* PG */
    mov     %eax, %cr0

    /* Load 64-bit GDT */
    lgdt    (ap_trampoline_gdt64 - ap_trampoline_start)

    /* Jump to 64-bit long mode code */
    ljmpl   $0x08, $(ap_long_mode - ap_trampoline_start)

/* 64-bit long mode code */
.code64
ap_long_mode:
    /* Set up segments for long mode */
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    xor     %ax, %ax
    mov     %ax, %fs
    mov     %ax, %gs

    /* Load per-CPU stack */
    mov     (ap_trampoline_stack - ap_trampoline_start), %rsp

    /* Get CPU ID */
    mov     (ap_trampoline_cpu_id - ap_trampoline_start), %rdi

    /* Jump to C code */
    mov     (ap_trampoline_target - ap_trampoline_start), %rax
    call    *%rax

    /* Should never return, but halt if it does */
ap_halt:
    cli
    hlt
    jmp     ap_halt

/* Temporary 32-bit GDT for protected mode transition */
.align 8
ap_gdt32:
    .quad   0x0000000000000000      /* Null descriptor */
    .quad   0x00CF9A000000FFFF      /* Code segment (32-bit) */
    .quad   0x00CF92000000FFFF      /* Data segment (32-bit) */

ap_gdt32_desc:
    .word   (ap_gdt32_desc - ap_gdt32 - 1)
    .long   (ap_gdt32 - ap_trampoline_start)

/* Variables filled in by BSP before starting APs */
.align 8
ap_trampoline_gdt64:
    .word   0                       /* GDT limit */
    .quad   0                       /* GDT base */
    .byte   0                       /* Padding to 8-byte align */

ap_trampoline_pml4:
    .quad   0                       /* Physical address of PML4 */

ap_trampoline_stack:
    .quad   0                       /* Virtual address of per-CPU stack */

ap_trampoline_target:
    .quad   0                       /* Virtual address of C entry point */

ap_trampoline_cpu_id:
    .quad   0                       /* APIC ID of this CPU */

ap_trampoline_end:

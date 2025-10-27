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

    /* Debug: Write 'T' to serial to show trampoline started */
    movw    $0x3F8, %dx
    movb    $'T', %al
    outb    %al, %dx

    /* We're executing at 0x8000 (SIPI vector * 4096) */
    /* Set CS:IP explicitly for addressing */
    ljmp    $0x800, $1f - ap_trampoline_start
1:
    /* Debug: Write '1' after ljmp */
    movw    $0x3F8, %dx
    movb    $'1', %al
    outb    %al, %dx

    /* Now CS=0x800, so our data segment calculations work */
    mov     %cs, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    xor     %ax, %ax
    mov     %ax, %fs
    mov     %ax, %gs

    /* Debug: Write '2' after segment setup */
    movw    $0x3F8, %dx
    movb    $'2', %al
    outb    %al, %dx

    /* Load temporary GDT (now DS=CS=0x800, so offsets work) */
    lgdtl   %cs:(ap_gdt32_desc - ap_trampoline_start)

    /* Debug: Write '3' after lgdt */
    movw    $0x3F8, %dx
    movb    $'3', %al
    outb    %al, %dx

    /* Enable protected mode (CR0.PE = 1) */
    mov     %cr0, %eax
    or      $1, %eax
    mov     %eax, %cr0

    /* Far jump to 32-bit protected mode using indirect jump */
    .byte   0x66                    /* 32-bit operand override */
    ljmp    *%cs:(ap_pm_far_ptr - ap_trampoline_start)

/* 32-bit protected mode code */
.code32
ap_protected_mode:
    /* Debug: Write '4' to serial */
    mov     $0x3F8, %dx
    mov     $'4', %al
    outb    %al, %dx

    /* Set up segments for protected mode */
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    mov     %ax, %fs
    mov     %ax, %gs

    /* Debug: Write '5' after segments */
    mov     $0x3F8, %dx
    mov     $'5', %al
    outb    %al, %dx

    /* Enable PAE (CR4.PAE = 1) and PSE (CR4.PSE = 1) */
    mov     %cr4, %eax
    or      $(1 << 5) | (1 << 4), %eax  /* PAE | PSE */
    mov     %eax, %cr4

    /* Debug: Write '6' after CR4 */
    mov     $0x3F8, %dx
    mov     $'6', %al
    outb    %al, %dx

    /* Load PML4 (page table root) - must load full 64-bit value even in 32-bit mode */
    mov     $(0x8000 + ap_trampoline_pml4 - ap_trampoline_start), %eax
    mov     (%eax), %eax        /* Load low 32 bits */
    mov     %eax, %cr3          /* CR3 only uses low 32 bits of PML4 addr (PML4 must be below 4GB) */

    /* Debug: Write '7' after CR3 */
    mov     $0x3F8, %dx
    mov     $'7', %al
    outb    %al, %dx

    /* Enable long mode (EFER.LME = 1) and NXE */
    mov     $0xC0000080, %ecx       /* EFER MSR */
    rdmsr
    or      $(1 << 8) | (1 << 11), %eax  /* LME | NXE */
    wrmsr

    /* Debug: Write '8' after EFER */
    mov     $0x3F8, %dx
    mov     $'8', %al
    outb    %al, %dx

    /* Enable paging (CR0.PG = 1) */
    mov     %cr0, %eax
    or      $(1 << 31), %eax        /* PG */
    mov     %eax, %cr0

    /* Debug: Write '9' after paging enabled */
    mov     $0x3F8, %dx
    mov     $'9', %al
    outb    %al, %dx

    /* NOTE: We keep using the 32-bit GDT for the transition to 64-bit mode.
     * The kernel's 64-bit GDT has a high virtual address base that won't work in 32-bit mode.
     * We'll load the real kernel GDT once we're in 64-bit mode. */

    /* Jump to 64-bit long mode using far jump */
    /* Debug: Write 'X' before far jump */
    mov     $0x3F8, %dx
    mov     $'X', %al
    outb    %al, %dx

    /* Far jump to 64-bit code using indirect far pointer */
    /* In 32-bit mode, we can use absolute addressing */
    ljmp    *(0x8000 + ap_64_far_ptr - ap_trampoline_start)

/* 64-bit long mode code - MUST stay within identity-mapped region */
.code64
ap_long_mode:
    /* Debug: Write 'B' to show we reached 64-bit mode */
    mov     $0x3F8, %dx
    mov     $'B', %al
    outb    %al, %dx

    /* Set up segments for long mode */
    mov     $0x10, %ax
    mov     %ax, %ds
    mov     %ax, %es
    mov     %ax, %ss
    xor     %ax, %ax
    mov     %ax, %fs
    mov     %ax, %gs

    /* Load per-CPU stack using identity-mapped trampoline address */
    movabs  $0x8000, %rax
    add     $(ap_trampoline_stack - ap_trampoline_start), %rax
    mov     (%rax), %rsp

    /* Get CPU ID using identity-mapped trampoline address */
    movabs  $0x8000, %rax
    add     $(ap_trampoline_cpu_id - ap_trampoline_start), %rax
    mov     (%rax), %rdi

    /* Get C entry point using identity-mapped trampoline address */
    movabs  $0x8000, %rax
    add     $(ap_trampoline_target - ap_trampoline_start), %rax
    mov     (%rax), %rax

    /* Now jump to the kernel virtual address (should be 0xffffffff...) */
    /* This works because the kernel's page tables map kernel code at high addresses */
    call    *%rax

    /* Should never return, but halt if it does */
ap_halt:
    cli
    hlt
    jmp     ap_halt

/* Far pointer for protected mode jump */
.align 4
ap_pm_far_ptr:
    .long   (0x8000 + ap_protected_mode - ap_trampoline_start)  /* Offset */
    .word   0x08                                                 /* Selector */

/* Far pointer for 64-bit mode jump */
.align 4
ap_64_far_ptr:
    .long   (0x8000 + ap_long_mode - ap_trampoline_start)       /* Offset (32-bit) */
    .word   0x18                                                 /* Selector (64-bit code) */

/* Temporary GDT for mode transitions */
.align 8
ap_gdt32:
    .quad   0x0000000000000000      /* 0x00: Null descriptor */
    .quad   0x00CF9A000000FFFF      /* 0x08: Code segment (32-bit, for protected mode) */
    .quad   0x00CF92000000FFFF      /* 0x10: Data segment (32-bit) */
    .quad   0x00AF9A000000FFFF      /* 0x18: Code segment (64-bit: L=1, D=0, for long mode) */

ap_gdt32_desc:
    .word   (ap_gdt32_desc - ap_gdt32 - 1)
    .long   (0x8000 + ap_gdt32 - ap_trampoline_start)

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

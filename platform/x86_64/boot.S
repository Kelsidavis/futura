/*
 * Futura OS - x86_64 Boot Code
 * Copyright (C) 2025 Futura OS Project
 *
 * 64-bit long mode boot entry point with Multiboot2 support
 */

.section .multiboot2
.align 8
multiboot2_header:
    .long 0xE85250D6                    /* Multiboot2 magic */
    .long 0                             /* Architecture: i386 (protected mode) */
    .long multiboot2_header_end - multiboot2_header  /* Header length */
    .long -(0xE85250D6 + 0 + (multiboot2_header_end - multiboot2_header))  /* Checksum */

    /* Framebuffer tag (optional) */
    .align 8
    .short 5                            /* Type: framebuffer */
    .short 0                            /* Flags */
    .long 20                            /* Size */
    .long 1024                          /* Width */
    .long 768                           /* Height */
    .long 32                            /* Depth */

    /* End tag */
    .align 8
    .short 0                            /* Type: end */
    .short 0                            /* Flags */
    .long 8                             /* Size */
multiboot2_header_end:

/* Boot-time BSS (page tables and stack) in low memory but outside 8KB boot limit */
.section .boot.bss
.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_pd:
    .skip 4096

.align 16
boot_stack_bottom:
    .skip 16384                         /* 16KB stack */
boot_stack_top:

.section .boot.text
.code32                                 /* Start in 32-bit protected mode */

.global _start
.type _start, @function
_start:
    cli                                 /* Disable interrupts */

    /* Save Multiboot2 info pointer */
    movl %eax, %edi                     /* Multiboot2 magic in eax */
    movl %ebx, %esi                     /* Multiboot2 info pointer in ebx */

    /* Set up page tables for long mode */
    /* PML4[0] -> PDPT */
    movl $boot_pdpt, %eax
    orl $0x3, %eax                      /* Present + Writable */
    movl %eax, boot_pml4

    /* PDPT[0] -> PD */
    movl $boot_pd, %eax
    orl $0x3, %eax
    movl %eax, boot_pdpt

    /* Identity map first 2MB (PD[0] -> 2MB page) */
    movl $0x83, %eax                    /* Present + Writable + Huge (2MB) */
    movl %eax, boot_pd

    /* Map higher half kernel (PML4[511] -> PDPT) */
    movl $boot_pdpt, %eax
    orl $0x3, %eax
    movl %eax, boot_pml4 + (511 * 8)

    /* Load PML4 address into CR3 */
    movl $boot_pml4, %eax
    movl %eax, %cr3

    /* Enable PAE (Physical Address Extension) */
    movl %cr4, %eax
    orl $0x20, %eax                     /* Set PAE bit */
    movl %eax, %cr4

    /* Enable long mode in EFER MSR */
    movl $0xC0000080, %ecx              /* EFER MSR */
    rdmsr
    orl $0x100, %eax                    /* Set LME (Long Mode Enable) */
    wrmsr

    /* Enable paging and protected mode */
    movl %cr0, %eax
    orl $0x80000001, %eax               /* Set PG (Paging) and PE (Protected Mode) */
    movl %eax, %cr0

    /* Load 64-bit GDT */
    lgdt gdt64_pointer

    /* Far jump to 64-bit code segment */
    ljmp $0x08, $long_mode_start

.code64
long_mode_start:
    /* Clear segment registers */
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    /* Set up 64-bit stack */
    movq $boot_stack_top, %rsp
    movq $boot_stack_top, %rbp

    /* Clear RFLAGS */
    pushq $0
    popfq

    /* Prepare arguments for platform init */
    /* RDI = Multiboot2 magic (already set) */
    /* RSI = Multiboot2 info pointer (already set) */

    /* Jump to platform initialization using absolute address */
    /* We need to use movabs because fut_platform_init is in higher-half */
    movabs $fut_platform_init, %rax
    call *%rax

    /* Should never return, but halt if it does */
halt_loop:
    cli
    hlt
    jmp halt_loop

.size _start, . - _start

/* Temporary 64-bit GDT for boot (in low memory) */
.section .boot.data
.align 16
gdt64:
    .quad 0x0000000000000000            /* Null descriptor */
    .quad 0x00AF9A000000FFFF            /* 64-bit code segment */
    .quad 0x00AF92000000FFFF            /* 64-bit data segment */
gdt64_end:

gdt64_pointer:
    .word gdt64_end - gdt64 - 1         /* Limit */
    .long gdt64                         /* Base */

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits

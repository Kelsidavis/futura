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

/* Boot GDT in .boot.data (small, stays within 8KB) */
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

/* Page tables in .boot.data (pre-populated with values) */
.section .boot.data
.align 4096
boot_pml4:
    .quad 0x0000000000102003            /* PML4[0]: Present + Writable, points to boot_pdpt */
    .skip 4080                          /* Skip to offset 4088 (511*8) */
    .quad 0x0000000000102003            /* PML4[511]: Present + Writable, points to boot_pdpt */

.align 4096
boot_pdpt:
    .quad 0x0000000000103003            /* PDPT[0]: Present + Writable, points to boot_pd */
    .skip 4072                          /* Skip to offset 4080 (510*8) */
    .quad 0x0000000000103003            /* PDPT[510]: Present + Writable, points to boot_pd */
    .skip 8                             /* Pad to 4096 */

.align 4096
boot_pd:
    .quad 0x0000000000000083            /* PD[0] -> 2MB huge page at 0MB (Present + Writable + Huge) */
    .quad 0x0000000000200083            /* PD[1] -> 2MB huge page at 2MB */
    .quad 0x0000000000400083            /* PD[2] -> 2MB huge page at 4MB */
    .quad 0x0000000000600083            /* PD[3] -> 2MB huge page at 6MB */
    .skip 4064                          /* Rest of page table */

/* Boot stack in .boot.bss (this can stay as BSS since we just need zero-initialized space) */
.section .boot.bss
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

    /* Early debug: Write 'S' to serial COM1 in 32-bit mode */
    movw $0x3F8, %dx
    movb $'S', %al
    outb %al, %dx

    /* Save Multiboot2 info pointer */
    movl %eax, %edi                     /* Multiboot2 magic in eax */
    movl %ebx, %esi                     /* Multiboot2 info pointer in ebx */

    /* Page tables are pre-populated in .boot.data section */
    /* Just load PML4 address into CR3 */
    movl $boot_pml4, %eax
    movl %eax, %cr3

    /* Debug: Write 'P' after CR3 loaded */
    movw $0x3F8, %dx
    movb $'P', %al
    outb %al, %dx

    /* Enable PAE (Physical Address Extension) and PSE (Page Size Extension) */
    movl %cr4, %eax
    orl $0x30, %eax                     /* Set PAE bit (5) and PSE bit (4) */
    movl %eax, %cr4

    /* Debug: Write 'A' after PAE enabled */
    movw $0x3F8, %dx
    movb $'A', %al
    outb %al, %dx

    /* Enable long mode in EFER MSR */
    movl $0xC0000080, %ecx              /* EFER MSR */
    rdmsr
    orl $0x900, %eax                    /* Set LME (bit 8) and NXE (bit 11) */
    wrmsr

    /* Debug: Write 'E' after EFER set */
    movw $0x3F8, %dx
    movb $'E', %al
    outb %al, %dx

    /* Enable paging and protected mode */
    movl %cr0, %eax
    orl $0x80000001, %eax               /* Set PG (Paging) and PE (Protected Mode) */
    movl %eax, %cr0

    /* Debug: Write 'G' after paging enabled */
    movw $0x3F8, %dx
    movb $'G', %al
    outb %al, %dx

    /* Load 64-bit GDT */
    lgdt gdt64_pointer

    /* Debug: Write 'J' before far jump */
    movw $0x3F8, %dx
    movb $'J', %al
    outb %al, %dx

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

    /* Set up 64-bit stack - use boot_stack (identity-mapped and loaded) */
    movq $boot_stack_top, %rsp
    movq $boot_stack_top, %rbp

    /* Clear RFLAGS first */
    pushq $0
    popfq

    /* Early debug: Write 'F' to serial port COM1 (0x3F8) to show we're alive */
    movw $0x3F8, %dx
    movb $'F', %al
    outb %al, %dx

    /* Jump to higher-half code before calling higher-half functions */
    movabs $higher_half_entry, %rax
    jmp *%rax

higher_half_entry:
    /* Now executing in higher-half! */

    /* Debug: Write 'H' to show we're in higher-half */
    movw $0x3F8, %dx
    movb $'H', %al
    outb %al, %dx

    /* Debug: Write 'L' before loading address */
    movw $0x3F8, %dx
    movb $'L', %al
    outb %al, %dx

    /* Prepare arguments for platform init */
    /* RDI = Multiboot2 magic (already set from boot) */
    /* RSI = Multiboot2 info pointer (already set from boot) */

    /* Workaround: Call via identity-mapped address instead of higher-half */
    /* fut_platform_init is at virtual 0xffffffff8000c94b, physical 0xc94b */
    movl $0xc94b, %ecx           /* Save address in ECX */

    /* Debug: Write 'M' after loading address */
    movw $0x3F8, %dx
    movb $'M', %al
    outb %al, %dx

    /* Call the platform init function via identity mapping */
    call *%rcx

    /* Debug: Write 'R' if call returns */
    movw $0x3F8, %dx
    movb $'R', %al
    outb %al, %dx

    /* Should never return, but write 'X' if we do */
    movw $0x3F8, %dx
    movb $'X', %al
    outb %al, %dx

    /* Should never return, but halt if it does */
halt_loop:
    cli
    hlt
    jmp halt_loop

.size _start, . - _start

/* PVH ELF Note for QEMU -kernel direct boot */
.section .note.Xen, "a"
.align 4
    .long 2f - 1f                           /* namesz */
    .long 4f - 3f                           /* descsz */
    .long 18                                /* type = XEN_ELFNOTE_PHYS32_ENTRY */
1:
    .asciz "Xen"                            /* name */
2:
    .align 4
3:
    .long _start                            /* desc: entry point */
4:
    .align 4

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits

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

/* Page tables in .boot.data (zero-initialized, will be populated at runtime) */
.section .boot.data
.align 4096
.global boot_pml4
boot_pml4:
    .skip 4096                          /* 512 entries * 8 bytes */

.align 4096
.global boot_pdpt
boot_pdpt:
    .skip 4096                          /* 512 entries * 8 bytes */

.align 4096
.global boot_pd
boot_pd:
    .skip 4096                          /* 512 entries * 8 bytes */

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

    /* Initialize page tables at runtime with correct physical addresses */

    /* Setup PML4: identity map low 2MB and higher-half kernel */
    movl $boot_pdpt, %eax               /* Get physical address of PDPT */
    orl $0x03, %eax                     /* Present + Writable */
    movl %eax, boot_pml4                /* PML4[0] low dword */
    movl $0, boot_pml4 + 4              /* PML4[0] high dword */
    movl %eax, boot_pml4 + 4088         /* PML4[511] low dword */
    movl $0, boot_pml4 + 4092           /* PML4[511] high dword */

    /* Setup PDPT: map first and second-to-last entries */
    movl $boot_pd, %eax                 /* Get physical address of PD */
    orl $0x03, %eax                     /* Present + Writable */
    movl %eax, boot_pdpt                /* PDPT[0] low dword */
    movl $0, boot_pdpt + 4              /* PDPT[0] high dword */
    movl %eax, boot_pdpt + 4080         /* PDPT[510] low dword */
    movl $0, boot_pdpt + 4084           /* PDPT[510] high dword */

    /* Setup PD: identity map first 32MB with 2MB huge pages */
    movl $0x00000083, boot_pd           /* PD[0] low dword: 0MB-2MB */
    movl $0, boot_pd + 4                /* PD[0] high dword */
    movl $0x00200083, boot_pd + 8       /* PD[1] low dword: 2MB-4MB */
    movl $0, boot_pd + 12               /* PD[1] high dword */
    movl $0x00400083, boot_pd + 16      /* PD[2] low dword: 4MB-6MB */
    movl $0, boot_pd + 20               /* PD[2] high dword */
    movl $0x00600083, boot_pd + 24      /* PD[3] low dword: 6MB-8MB */
    movl $0, boot_pd + 28               /* PD[3] high dword */
    movl $0x00800083, boot_pd + 32      /* PD[4] low dword: 8MB-10MB */
    movl $0, boot_pd + 36               /* PD[4] high dword */
    movl $0x00A00083, boot_pd + 40      /* PD[5] low dword: 10MB-12MB */
    movl $0, boot_pd + 44               /* PD[5] high dword */
    movl $0x00C00083, boot_pd + 48      /* PD[6] low dword: 12MB-14MB */
    movl $0, boot_pd + 52               /* PD[6] high dword */
    movl $0x00E00083, boot_pd + 56      /* PD[7] low dword: 14MB-16MB */
    movl $0, boot_pd + 60               /* PD[7] high dword */
    movl $0x01000083, boot_pd + 64      /* PD[8] low dword: 16MB-18MB */
    movl $0, boot_pd + 68               /* PD[8] high dword */
    movl $0x01200083, boot_pd + 72      /* PD[9] low dword: 18MB-20MB */
    movl $0, boot_pd + 76               /* PD[9] high dword */
    movl $0x01400083, boot_pd + 80      /* PD[10] low dword: 20MB-22MB */
    movl $0, boot_pd + 84               /* PD[10] high dword */
    movl $0x01600083, boot_pd + 88      /* PD[11] low dword: 22MB-24MB */
    movl $0, boot_pd + 92               /* PD[11] high dword */
    movl $0x01800083, boot_pd + 96      /* PD[12] low dword: 24MB-26MB */
    movl $0, boot_pd + 100              /* PD[12] high dword */
    movl $0x01A00083, boot_pd + 104     /* PD[13] low dword: 26MB-28MB */
    movl $0, boot_pd + 108              /* PD[13] high dword */
    movl $0x01C00083, boot_pd + 112     /* PD[14] low dword: 28MB-30MB */
    movl $0, boot_pd + 116              /* PD[14] high dword */
    movl $0x01E00083, boot_pd + 120     /* PD[15] low dword: 30MB-32MB */
    movl $0, boot_pd + 124              /* PD[15] high dword */

    /* Load PML4 address into CR3 */
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

    /* Debug: Write 'K' before stack switch */
    movw $0x3F8, %dx
    movb $'K', %al
    outb %al, %dx

    /* Switch to higher-half kernel stack before calling C code */
    /* The boot stack is identity-mapped at low addresses, */
    /* but we need a higher-half stack for C function calls */
    movabs $_stack_top, %rsp
    movabs $_stack_top, %rbp

    /* Debug: Write 'S' after stack switch */
    movw $0x3F8, %dx
    movb $'S', %al
    outb %al, %dx

    /* Prepare arguments for platform init */
    /* EDI/RDI = Multiboot2 magic (saved from boot in 32-bit mode) */
    /* ESI/RSI = Multiboot2 info pointer (saved from boot in 32-bit mode) */
    /* Zero-extend to 64-bit */
    movl %edi, %edi
    movl %esi, %esi

    /* Debug: Write 'C' before call */
    movw $0x3F8, %dx
    movb $'C', %al
    outb %al, %dx

    /* Load absolute address of fut_platform_init and call it */
    /* Can't use relative call because function is too far away */
    movabs $fut_platform_init, %rax

    /* Call the platform initialization function */
    call *%rax

    /* Debug: Write 'R' if call returns (should never happen) */
    movw $0x3F8, %dx
    movb $'R', %al
    outb %al, %dx

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

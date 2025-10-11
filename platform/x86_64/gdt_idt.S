/*
 * Futura OS - x86_64 GDT/IDT Setup
 * Copyright (C) 2025 Futura OS Project
 *
 * Global Descriptor Table and Interrupt Descriptor Table for 64-bit mode
 */

.section .data

/* Global Descriptor Table (GDT) */
.align 16
.global gdt64_table
gdt64_table:
    /* Entry 0: Null descriptor */
    .quad 0x0000000000000000

    /* Entry 1: 64-bit kernel code segment (selector 0x08) */
    .quad 0x00AF9A000000FFFF            /* P=1, DPL=0, S=1, Type=1010 (code), L=1 */

    /* Entry 2: 64-bit kernel data segment (selector 0x10) */
    .quad 0x00AF92000000FFFF            /* P=1, DPL=0, S=1, Type=0010 (data) */

    /* Entry 3: 64-bit user code segment (selector 0x18) */
    .quad 0x00AFFA000000FFFF            /* P=1, DPL=3, S=1, Type=1010 (code), L=1 */

    /* Entry 4: 64-bit user data segment (selector 0x20) */
    .quad 0x00AFF2000000FFFF            /* P=1, DPL=3, S=1, Type=0010 (data) */

    /* Entry 5: TSS descriptor (selector 0x28) - will be filled at runtime */
    .quad 0x0000000000000000
    .quad 0x0000000000000000            /* TSS is 16 bytes in 64-bit mode */

gdt64_table_end:

.global gdt64_ptr
gdt64_ptr:
    .word gdt64_table_end - gdt64_table - 1  /* Limit */
    .quad gdt64_table                        /* Base */

/* Interrupt Descriptor Table (IDT) */
.align 16
.global idt64_table
idt64_table:
    .skip 256 * 16                      /* 256 entries, 16 bytes each */
idt64_table_end:

.global idt64_ptr
idt64_ptr:
    .word idt64_table_end - idt64_table - 1  /* Limit */
    .quad idt64_table                        /* Base */

.section .text

/* Function to load GDT */
.global fut_gdt_load
.type fut_gdt_load, @function
fut_gdt_load:
    /* Load GDT pointer */
    lgdt gdt64_ptr

    /* Reload code segment with far return */
    pushq $0x08                         /* Kernel code segment */
    leaq .reload_cs(%rip), %rax
    pushq %rax
    lretq

.reload_cs:
    /* Reload data segments */
    movw $0x10, %ax                     /* Kernel data segment */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    ret

.size fut_gdt_load, . - fut_gdt_load

/* Function to load IDT */
.global fut_idt_load
.type fut_idt_load, @function
fut_idt_load:
    lidt idt64_ptr
    ret

.size fut_idt_load, . - fut_idt_load

/* Function to set an IDT entry */
/* Parameters:
 * RDI = interrupt number
 * RSI = handler address
 * RDX = selector (segment)
 * RCX = flags (type and attributes)
 */
.global fut_idt_set_entry
.type fut_idt_set_entry, @function
fut_idt_set_entry:
    /* Calculate entry address: idt64_table + (vector * 16) */
    leaq idt64_table(%rip), %rax
    shlq $4, %rdi                       /* vector * 16 */
    addq %rdi, %rax

    /* Set offset low (bits 0-15) */
    movw %si, (%rax)

    /* Set selector (bits 16-31) */
    movw %dx, 2(%rax)

    /* Set IST and zero (bits 32-39) */
    movb $0, 4(%rax)

    /* Set type and attributes (bits 40-47) */
    movb %cl, 5(%rax)

    /* Set offset middle (bits 48-63) */
    shrq $16, %rsi
    movw %si, 6(%rax)

    /* Set offset high (bits 64-95) */
    shrq $16, %rsi
    movl %esi, 8(%rax)

    /* Set reserved (bits 96-127) */
    movl $0, 12(%rax)

    ret

.size fut_idt_set_entry, . - fut_idt_set_entry

/* Function to disable interrupts */
.global fut_disable_interrupts
.type fut_disable_interrupts, @function
fut_disable_interrupts:
    cli
    ret

.size fut_disable_interrupts, . - fut_disable_interrupts

/* Function to enable interrupts */
.global fut_enable_interrupts
.type fut_enable_interrupts, @function
fut_enable_interrupts:
    sti
    ret

.size fut_enable_interrupts, . - fut_enable_interrupts

/* Function to get interrupt status */
.global fut_save_interrupts
.type fut_save_interrupts, @function
fut_save_interrupts:
    pushfq
    popq %rax
    andq $0x200, %rax                   /* Test IF flag */
    ret

.size fut_save_interrupts, . - fut_save_interrupts

/* Function to restore interrupt status */
.global fut_restore_interrupts
.type fut_restore_interrupts, @function
fut_restore_interrupts:
    testq %rdi, %rdi
    jz .no_enable
    sti
    ret
.no_enable:
    cli
    ret

.size fut_restore_interrupts, . - fut_restore_interrupts

/* Mark stack as non-executable */
.section .note.GNU-stack,"",@progbits

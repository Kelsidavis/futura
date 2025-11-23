/* fut_isr.S - Futura OS ISR Stubs (x86-64)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Interrupt Service Routine stubs for x86-64 platform.
 * Handles timer, keyboard, and other hardware interrupts.
 */

.section .text

/* IRQ0 (Timer) stub - Build interrupt frame and call C handler */
.global irq0_stub
.type irq0_stub, @function
irq0_stub:
    /* CPU has already pushed: RIP, CS, RFLAGS (and possibly SS, RSP for ring change) */

    /* Save registers in order matching fut_interrupt_frame struct */
    /* Stack grows DOWN, so LAST pushed register is at LOWEST address (offset 0) */
    /* We need: gs(0), fs(8), es(16), ds(24), rax(32), rbx(40), rcx(48), rdx(56),
     *          rsi(64), rdi(72), rbp(80), r8(88)...r15(144) */

    /* Push in REVERSE order so layout matches struct */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax

    /* Save segment registers (pushed last, so at lowest addresses) */
    pushq %ds
    pushq %es
    pushq %fs
    pushq %gs
    /* Note: SS is saved by hardware (CPU) during interrupt, not by software */

    /* RSP now points to complete interrupt frame (gs is at lowest address) */

    /* Set up kernel data segments */
    mov $0x10, %ax      /* Kernel data segment is 0x10, not 0x18 */
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    /* Note: Do NOT modify SS in ISR - it's managed by hardware/IRETQ */

    /* Output 'T' to serial to show timer interrupt fired */
    mov $0x3F8, %dx
    mov $'T', %al
    out %al, %dx

    /* Set interrupt context flag: fut_in_interrupt = true */
    movl $1, fut_in_interrupt

    /* Save pointer to interrupt frame: fut_current_frame = RSP (64-bit!) */
    movq %rsp, fut_current_frame

    /* Call C handler with frame pointer as argument */
    movq %rsp, %rdi     /* First argument in RDI (System V ABI) */
    call irq0_handler

    /* Clear interrupt context flag: fut_in_interrupt = false */
    movl $0, fut_in_interrupt

    /* Restore segment registers (pop in reverse order of push) */
    popq %gs
    popq %fs
    popq %es
    popq %ds

    /* Restore general-purpose registers (pop in reverse order of push) */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    /* Return from interrupt (pops RIP, CS, RFLAGS, and possibly RSP, SS) */
    iretq

/* IRQ1 (Keyboard) stub - for future use */
.global irq1_stub
.type irq1_stub, @function
irq1_stub:
    /* Save registers matching fut_interrupt_frame struct layout */
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax
    pushq %ds
    pushq %es
    pushq %fs
    pushq %gs

    /* Set up kernel data segments */
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    call irq1_handler

    /* Restore segment registers */
    popq %gs
    popq %fs
    popq %es
    popq %ds

    /* Restore general-purpose registers */
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    iretq

/* Spurious IRQ7 stub - for PIC spurious interrupts */
.global irq7_stub
.type irq7_stub, @function
irq7_stub:
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax
    pushq %ds
    pushq %es
    pushq %fs
    pushq %gs

    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    call irq7_handler

    popq %gs
    popq %fs
    popq %es
    popq %ds
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    iretq

/* Software interrupt stub for deferred rescheduling (INT 0x81) */
.global irq_resched_stub
.type irq_resched_stub, @function
irq_resched_stub:
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax
    pushq %ds
    pushq %es
    pushq %fs
    pushq %gs

    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    call irq_resched_handler

    popq %gs
    popq %fs
    popq %es
    popq %ds
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15

    iretq

/* Default exception/interrupt handler - catches unhandled vectors */
.global default_isr_stub
.type default_isr_stub, @function
default_isr_stub:
    /* Just send EOI and return - don't call any C code */
    /* Send EOI to master PIC */
    mov $0x20, %al
    out %al, $0x20
    iretq

/* C handlers are external - defined in C code and found by the linker */

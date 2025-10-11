/* idt.h - Futura OS x86_64 Interrupt Descriptor Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * IDT definitions for x86_64 long mode.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   IDT Entry Structure (64-bit)
 * ============================================================ */

/**
 * IDT entry (gate descriptor) for x86_64.
 * 16 bytes per entry in long mode.
 */
typedef struct idt_entry {
    uint16_t offset_low;        /* Offset bits 0-15 */
    uint16_t selector;          /* Code segment selector */
    uint8_t  ist;               /* Interrupt Stack Table offset (bits 0-2) */
    uint8_t  type_attr;         /* Type and attributes */
    uint16_t offset_mid;        /* Offset bits 16-31 */
    uint32_t offset_high;       /* Offset bits 32-63 */
    uint32_t reserved;          /* Must be zero */
} __attribute__((packed)) idt_entry_t;

static_assert(sizeof(idt_entry_t) == 16, "IDT entry must be 16 bytes");

/* ============================================================
 *   IDT Pointer (IDTR)
 * ============================================================ */

typedef struct idt_ptr {
    uint16_t limit;             /* Size of IDT - 1 */
    uint64_t base;              /* Base address of IDT */
} __attribute__((packed)) idt_ptr_t;

static_assert(sizeof(idt_ptr_t) == 10, "IDT pointer must be 10 bytes");

/* ============================================================
 *   Gate Types
 * ============================================================ */

#define IDT_TYPE_INTERRUPT      0x8E    /* Interrupt gate (IF=0) */
#define IDT_TYPE_TRAP           0x8F    /* Trap gate (IF=1) */
#define IDT_TYPE_TASK           0x85    /* Task gate (not used in 64-bit) */

/* Type/Attribute field breakdown:
 * Bits 0-3: Gate type (1110 = interrupt, 1111 = trap)
 * Bit 4: Zero
 * Bits 5-6: DPL (Descriptor Privilege Level)
 * Bit 7: Present bit (must be 1)
 */

#define IDT_ATTR_PRESENT        0x80    /* Present bit */
#define IDT_ATTR_DPL0           0x00    /* Ring 0 */
#define IDT_ATTR_DPL3           0x60    /* Ring 3 */
#define IDT_ATTR_INTERRUPT_GATE 0x0E    /* Interrupt gate (clears IF) */
#define IDT_ATTR_TRAP_GATE      0x0F    /* Trap gate (preserves IF) */

/* Complete type bytes */
#define IDT_TYPE_KERNEL_INTERRUPT   (IDT_ATTR_PRESENT | IDT_ATTR_DPL0 | IDT_ATTR_INTERRUPT_GATE)
#define IDT_TYPE_KERNEL_TRAP        (IDT_ATTR_PRESENT | IDT_ATTR_DPL0 | IDT_ATTR_TRAP_GATE)
#define IDT_TYPE_USER_INTERRUPT     (IDT_ATTR_PRESENT | IDT_ATTR_DPL3 | IDT_ATTR_INTERRUPT_GATE)
#define IDT_TYPE_USER_TRAP          (IDT_ATTR_PRESENT | IDT_ATTR_DPL3 | IDT_ATTR_TRAP_GATE)

/* ============================================================
 *   Interrupt Vector Numbers
 * ============================================================ */

/* CPU Exceptions (0-31) */
#define INT_DIVIDE_ERROR        0
#define INT_DEBUG               1
#define INT_NMI                 2
#define INT_BREAKPOINT          3
#define INT_OVERFLOW            4
#define INT_BOUND_RANGE         5
#define INT_INVALID_OPCODE      6
#define INT_DEVICE_NOT_AVAIL    7
#define INT_DOUBLE_FAULT        8
#define INT_COPROCESSOR         9
#define INT_INVALID_TSS         10
#define INT_SEGMENT_NOT_PRESENT 11
#define INT_STACK_FAULT         12
#define INT_GENERAL_PROTECTION  13
#define INT_PAGE_FAULT          14
#define INT_RESERVED_15         15
#define INT_FPU_ERROR           16
#define INT_ALIGNMENT_CHECK     17
#define INT_MACHINE_CHECK       18
#define INT_SIMD_FP_EXCEPTION   19
#define INT_VIRTUALIZATION      20
#define INT_CONTROL_PROTECTION  21

/* IRQs (32-47) - Remapped from PIC */
#define INT_IRQ_BASE            32
#define INT_IRQ0_TIMER          32
#define INT_IRQ1_KEYBOARD       33
#define INT_IRQ2_CASCADE        34
#define INT_IRQ3_COM2           35
#define INT_IRQ4_COM1           36
#define INT_IRQ5_LPT2           37
#define INT_IRQ6_FLOPPY         38
#define INT_IRQ7_LPT1           39
#define INT_IRQ8_RTC            40
#define INT_IRQ9_ACPI           41
#define INT_IRQ10_AVAILABLE     42
#define INT_IRQ11_AVAILABLE     43
#define INT_IRQ12_MOUSE         44
#define INT_IRQ13_FPU           45
#define INT_IRQ14_PRIMARY_ATA   46
#define INT_IRQ15_SECONDARY_ATA 47

/* System calls and software interrupts */
#define INT_SYSCALL             128     /* System call vector */

/* APIC vectors (if using APIC instead of PIC) */
#define INT_APIC_TIMER          32
#define INT_APIC_SPURIOUS       255

/* ============================================================
 *   IDT Management Functions
 * ============================================================ */

/**
 * Load IDT register.
 * Implemented in gdt_idt.S.
 */
extern void fut_idt_load(void);

/**
 * Set an IDT entry.
 * Implemented in gdt_idt.S.
 *
 * @param vector Interrupt vector number (0-255)
 * @param handler Address of interrupt handler
 * @param selector Code segment selector (usually GDT_KERNEL_CODE)
 * @param type_attr Type and attribute byte
 * @param ist Interrupt Stack Table index (0 = use current stack)
 */
extern void fut_idt_set_entry(uint8_t vector, uint64_t handler,
                               uint16_t selector, uint8_t type_attr, uint8_t ist);

/**
 * Initialize IDT with default handlers.
 * Sets up exception handlers (0-31), IRQ handlers (32-47), and syscall (128).
 */
void fut_idt_init(void);

/**
 * Enable interrupts (STI).
 */
extern void fut_enable_interrupts(void);

/**
 * Disable interrupts (CLI).
 */
extern void fut_disable_interrupts(void);

/**
 * Save interrupt state and disable interrupts.
 * @return Previous RFLAGS value
 */
extern uint64_t fut_save_interrupts(void);

/**
 * Restore interrupt state.
 * @param flags Previous RFLAGS value from fut_save_interrupts()
 */
extern void fut_restore_interrupts(uint64_t flags);

/* ============================================================
 *   Exception Error Codes
 * ============================================================ */

/* Page fault error code bits */
#define PF_ERROR_PRESENT        (1 << 0)    /* Page not present */
#define PF_ERROR_WRITE          (1 << 1)    /* Write access */
#define PF_ERROR_USER           (1 << 2)    /* User mode access */
#define PF_ERROR_RESERVED       (1 << 3)    /* Reserved bit violation */
#define PF_ERROR_INSTRUCTION    (1 << 4)    /* Instruction fetch */
#define PF_ERROR_PROTECTION     (1 << 5)    /* Protection key violation */
#define PF_ERROR_SHADOW_STACK   (1 << 6)    /* Shadow stack access */

/* General protection fault error code */
#define GP_ERROR_EXTERNAL       (1 << 0)    /* External event */
#define GP_ERROR_IDT            (1 << 1)    /* IDT reference */
#define GP_ERROR_TI             (1 << 2)    /* LDT vs GDT */
#define GP_SEGMENT_INDEX(err)   ((err) >> 3) /* Segment selector index */

/* ============================================================
 *   Interrupt Handlers (weak symbols)
 * ============================================================ */

/**
 * Generic ISR handler called from assembly stubs.
 * @param frame Pointer to interrupt frame on stack
 */
void fut_isr_handler(void *frame) __attribute__((weak));

/**
 * Generic IRQ handler called from assembly stubs.
 * @param frame Pointer to interrupt frame on stack
 * @param irq IRQ number (0-15)
 */
void fut_irq_handler(void *frame, uint8_t irq) __attribute__((weak));

/**
 * Timer IRQ handler (IRQ0).
 * @param frame Pointer to interrupt frame on stack
 */
void fut_timer_irq(void *frame) __attribute__((weak));

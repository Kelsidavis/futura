/* exception_handlers.c - ARM64 Exception Handlers
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * C-level exception handlers for ARM64 synchronous exceptions, IRQ, FIQ, etc.
 */

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
extern void fut_serial_puts(const char *str);
extern void fut_serial_putc(char c);
extern int64_t arm64_syscall_dispatch(uint64_t syscall_num,
                                      uint64_t arg0, uint64_t arg1,
                                      uint64_t arg2, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5);

/* Exception frame structure (matches arm64_exception_entry.S) */
typedef struct {
    uint64_t x[31];             /* x0-x30 */
    uint64_t sp;                /* Stack pointer */
    uint64_t pc;                /* Program counter (ELR_EL1) */
    uint64_t pstate;            /* Processor state (SPSR_EL1) */
    uint64_t esr;               /* Exception syndrome register */
    uint64_t far;               /* Fault address register */
    uint64_t fpu_state[64];     /* FPU/SIMD registers */
    uint32_t fpsr;              /* FP status register */
    uint32_t fpcr;              /* FP control register */
} fut_interrupt_frame_t;

/* Global interrupt frame pointer (used by fork to clone context) */
extern fut_interrupt_frame_t *fut_current_frame;

/* ESR_EL1 exception class codes */
#define ESR_EC_SHIFT        26
#define ESR_EC_MASK         0x3F
#define ESR_EC_SVC64        0x15    /* SVC from AArch64 state */
#define ESR_EC_UNKNOWN      0x00    /* Unknown exception */
#define ESR_EC_DABT_EL0     0x24    /* Data abort from lower EL */
#define ESR_EC_DABT_EL1     0x25    /* Data abort from same EL */
#define ESR_EC_IABT_EL0     0x20    /* Instruction abort from lower EL */
#define ESR_EC_IABT_EL1     0x21    /* Instruction abort from same EL */

/* Extract exception class from ESR */
static inline uint32_t esr_get_ec(uint64_t esr) {
    return (esr >> ESR_EC_SHIFT) & ESR_EC_MASK;
}

/* Handle SVC (syscall) from EL0 */
static void handle_svc(fut_interrupt_frame_t *frame) {
    /* Save frame pointer for fork (needs to clone parent's register state) */
    fut_current_frame = frame;

    /* Extract syscall number and arguments from frame */
    uint64_t syscall_num = frame->x[8];  /* x8 contains syscall number */
    uint64_t arg0 = frame->x[0];
    uint64_t arg1 = frame->x[1];
    uint64_t arg2 = frame->x[2];
    uint64_t arg3 = frame->x[3];
    uint64_t arg4 = frame->x[4];
    uint64_t arg5 = frame->x[5];

    /* Dispatch to syscall handler */
    int64_t result = arm64_syscall_dispatch(syscall_num, arg0, arg1, arg2, arg3, arg4, arg5);

    /* Store return value in x0 */
    frame->x[0] = (uint64_t)result;

    /* Clear frame pointer after syscall completes */
    fut_current_frame = NULL;

    /* PC already points to instruction after SVC, so just return
     * ERET will return to EL0 to continue execution
     */
}

/* Handle unknown exception */
static void handle_unknown(fut_interrupt_frame_t *frame) {
    fut_serial_puts("[EXCEPTION] Unknown exception!\n");
    fut_serial_puts("[EXCEPTION] ESR: ");
    /* Simple hex printing */
    uint64_t esr = frame->esr;
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (esr >> i) & 0xF;
        char c = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
        fut_serial_putc(c);
    }
    fut_serial_putc('\n');

    fut_serial_puts("[EXCEPTION] PC: ");
    uint64_t pc = frame->pc;
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (pc >> i) & 0xF;
        char c = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
        fut_serial_putc(c);
    }
    fut_serial_putc('\n');

    fut_serial_puts("[EXCEPTION] FAR (Fault Address): ");
    uint64_t far = frame->far;
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (far >> i) & 0xF;
        char c = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
        fut_serial_putc(c);
    }
    fut_serial_putc('\n');

    fut_serial_puts("[EXCEPTION] Hanging...\n");

    while (1) {
        __asm__ volatile("wfi");
    }
}

/* Main exception dispatcher */
void arm64_exception_dispatch(fut_interrupt_frame_t *frame) {
    uint64_t esr = frame->esr;
    uint32_t ec = esr_get_ec(esr);

    switch (ec) {
        case ESR_EC_SVC64:
            handle_svc(frame);
            break;

        case ESR_EC_DABT_EL0:
        case ESR_EC_DABT_EL1:
            if (ec == ESR_EC_DABT_EL0) {
                fut_serial_puts("[EXCEPTION] Data abort from lower EL (userspace)\n");
            } else {
                fut_serial_puts("[EXCEPTION] Data abort from same EL (kernel)\n");
            }
            /* Decode ISS field for more info */
            {
                uint32_t iss = esr & 0x1FFFFFF;
                uint32_t dfsc = iss & 0x3F;  /* Data Fault Status Code */
                fut_serial_puts("[EXCEPTION] DFSC=0x");
                for (int i = 4; i >= 0; i -= 4) {
                    uint8_t nibble = (dfsc >> i) & 0xF;
                    char c = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
                    fut_serial_putc(c);
                }
                fut_serial_puts(" (");
                if (dfsc == 0x21) fut_serial_puts("Alignment fault");
                else if (dfsc == 0x04) fut_serial_puts("Translation fault L0");
                else if (dfsc == 0x05) fut_serial_puts("Translation fault L1");
                else if (dfsc == 0x06) fut_serial_puts("Translation fault L2");
                else if (dfsc == 0x07) fut_serial_puts("Translation fault L3");
                else if (dfsc == 0x09) fut_serial_puts("Access flag fault L1");
                else if (dfsc == 0x0a) fut_serial_puts("Access flag fault L2");
                else if (dfsc == 0x0b) fut_serial_puts("Access flag fault L3");
                else if (dfsc == 0x0d) fut_serial_puts("Permission fault L1");
                else if (dfsc == 0x0e) fut_serial_puts("Permission fault L2");
                else if (dfsc == 0x0f) fut_serial_puts("Permission fault L3");
                else fut_serial_puts("Unknown");
                fut_serial_puts(")\n");
            }
            handle_unknown(frame);
            break;

        case ESR_EC_IABT_EL0:
        case ESR_EC_IABT_EL1:
            if (ec == ESR_EC_IABT_EL0) {
                fut_serial_puts("[EXCEPTION] Instruction abort from lower EL (userspace)\n");
            } else {
                fut_serial_puts("[EXCEPTION] Instruction abort from same EL (kernel)\n");
            }
            handle_unknown(frame);
            break;

        default:
            fut_serial_puts("[EXCEPTION] Unknown exception class: ");
            handle_unknown(frame);
            break;
    }
}

/* Safe idle loop to return to after SVC */
void kernel_idle_loop(void) {
    fut_serial_puts("[KERNEL] Kernel idle loop active\n");

    while (1) {
        __asm__ volatile("wfi");
    }
}

/* ============================================================
 *   IRQ and Interrupt Handling
 * ============================================================ */

extern void fut_timer_tick(void);  /* Timer interrupt handler */
extern void gic_handle_irq(void);   /* GIC interrupt dispatcher */

/* ARM64 IRQ Handler - called from IRQ exception vector */
void arm64_handle_irq(fut_interrupt_frame_t *frame) {
    (void)frame;  /* Frame available if needed for context */

    /* Acknowledge and handle IRQ via GIC */
    /* The GIC will determine which interrupt fired and dispatch to appropriate handler */
    gic_handle_irq();
}

/* ARM64 SError (System Error) Handler */
void arm64_handle_serror(fut_interrupt_frame_t *frame) {
    fut_serial_puts("[EXCEPTION] SError (System Error)!\n");
    fut_serial_puts("[EXCEPTION] PC: ");

    uint64_t pc = frame->pc;
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (pc >> i) & 0xF;
        char c = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
        fut_serial_putc(c);
    }
    fut_serial_putc('\n');

    /* Halt on system error */
    while (1) {
        __asm__ volatile("wfi");
    }
}

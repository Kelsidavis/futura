/* regs.h - ARM64 Register Definitions and Context Structures
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 (AArch64) register definitions for context switching and interrupt handling.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   CPU Context for Cooperative Context Switching
 * ============================================================ */

/**
 * ARM64 CPU context saved during cooperative context switches.
 * Contains callee-saved registers according to ARM64 ABI.
 */
typedef struct fut_cpu_context {
    /* Callee-saved registers (x19-x28) */
    uint64_t x19;
    uint64_t x20;
    uint64_t x21;
    uint64_t x22;
    uint64_t x23;
    uint64_t x24;
    uint64_t x25;
    uint64_t x26;
    uint64_t x27;
    uint64_t x28;

    /* Frame pointer and link register */
    uint64_t x29_fp;            /* Frame pointer */
    uint64_t x30_lr;            /* Link register (return address) */

    /* Stack pointer */
    uint64_t sp;                /* Stack pointer */

    /* Program counter (for new threads) */
    uint64_t pc;                /* Program counter */

    /* Processor state */
    uint64_t pstate;            /* Processor state (PSTATE/CPSR) */

    /* FPU/SIMD state (optional, can be lazy-saved) */
    uint64_t fpu_state[64];     /* v0-v31 (128-bit each = 2x64-bit) */
    uint32_t fpsr;              /* Floating-point status register */
    uint32_t fpcr;              /* Floating-point control register */
} fut_cpu_context_t;

/* ============================================================
 *   Interrupt Frame for Preemptive Context Switching
 * ============================================================ */

/**
 * ARM64 interrupt frame pushed by hardware and software during exceptions.
 * This structure matches the layout expected by exception handlers.
 */
typedef struct fut_interrupt_frame {
    /* General purpose registers x0-x30 */
    uint64_t x[31];             /* x0-x30 (x30 is LR) */

    /* Special registers */
    uint64_t sp;                /* Stack pointer */
    uint64_t pc;                /* Program counter (ELR_EL1) */
    uint64_t pstate;            /* Processor state (SPSR_EL1) */

    /* Exception information */
    uint64_t esr;               /* Exception syndrome register */
    uint64_t far;               /* Fault address register */

    /* FPU/SIMD context (saved on demand) */
    uint64_t fpu_state[64];     /* v0-v31 (SIMD/FP registers) */
    uint32_t fpsr;              /* Floating-point status register */
    uint32_t fpcr;              /* Floating-point control register */
} fut_interrupt_frame_t;

/* ============================================================
 *   System Register Definitions
 * ============================================================ */

/* Exception Level (EL) definitions */
#define ARM64_EL0  0    /* User mode */
#define ARM64_EL1  1    /* Kernel mode */
#define ARM64_EL2  2    /* Hypervisor */
#define ARM64_EL3  3    /* Secure monitor */

/* PSTATE bits */
#define PSTATE_MODE_EL0t    0x00
#define PSTATE_MODE_EL1t    0x04
#define PSTATE_MODE_EL1h    0x05
#define PSTATE_MODE_EL2t    0x08
#define PSTATE_MODE_EL2h    0x09

#define PSTATE_F_BIT        (1 << 6)    /* FIQ mask */
#define PSTATE_I_BIT        (1 << 7)    /* IRQ mask */
#define PSTATE_A_BIT        (1 << 8)    /* SError mask */
#define PSTATE_D_BIT        (1 << 9)    /* Debug mask */

/* SCTLR_EL1 - System Control Register */
#define SCTLR_M_BIT         (1 << 0)    /* MMU enable */
#define SCTLR_A_BIT         (1 << 1)    /* Alignment check enable */
#define SCTLR_C_BIT         (1 << 2)    /* Data cache enable */
#define SCTLR_SA_BIT        (1 << 3)    /* Stack alignment check */
#define SCTLR_I_BIT         (1 << 12)   /* Instruction cache enable */

/* ============================================================
 *   Exception Vector Table Offsets
 * ============================================================ */

/* Exception vector table has 4 types × 4 exception levels */
#define ARM64_VEC_SYNC_SP0      0x000   /* Synchronous from SP0 */
#define ARM64_VEC_IRQ_SP0       0x080   /* IRQ from SP0 */
#define ARM64_VEC_FIQ_SP0       0x100   /* FIQ from SP0 */
#define ARM64_VEC_SERROR_SP0    0x180   /* SError from SP0 */

#define ARM64_VEC_SYNC_SPx      0x200   /* Synchronous from SPx */
#define ARM64_VEC_IRQ_SPx       0x280   /* IRQ from SPx */
#define ARM64_VEC_FIQ_SPx       0x300   /* FIQ from SPx */
#define ARM64_VEC_SERROR_SPx    0x380   /* SError from SPx */

#define ARM64_VEC_SYNC_A64      0x400   /* Synchronous from AArch64 lower EL */
#define ARM64_VEC_IRQ_A64       0x480   /* IRQ from AArch64 lower EL */
#define ARM64_VEC_FIQ_A64       0x500   /* FIQ from AArch64 lower EL */
#define ARM64_VEC_SERROR_A64    0x580   /* SError from AArch64 lower EL */

#define ARM64_VEC_SYNC_A32      0x600   /* Synchronous from AArch32 lower EL */
#define ARM64_VEC_IRQ_A32       0x680   /* IRQ from AArch32 lower EL */
#define ARM64_VEC_FIQ_A32       0x700   /* FIQ from AArch32 lower EL */
#define ARM64_VEC_SERROR_A32    0x780   /* SError from AArch32 lower EL */

/* ============================================================
 *   Exception Syndrome Register (ESR) Definitions
 * ============================================================ */

/* Exception Class (EC) field in ESR */
#define ESR_EC_UNKNOWN          0x00    /* Unknown exception */
#define ESR_EC_WFI_WFE          0x01    /* WFI/WFE instruction */
#define ESR_EC_SVC_AARCH64      0x15    /* SVC instruction (AArch64) */
#define ESR_EC_IABT_LOWER       0x20    /* Instruction abort from lower EL */
#define ESR_EC_IABT_CURRENT     0x21    /* Instruction abort from current EL */
#define ESR_EC_DABT_LOWER       0x24    /* Data abort from lower EL */
#define ESR_EC_DABT_CURRENT     0x25    /* Data abort from current EL */

#define ESR_EC_SHIFT            26
#define ESR_EC_MASK             (0x3F << ESR_EC_SHIFT)
#define ESR_EC(esr)             (((esr) & ESR_EC_MASK) >> ESR_EC_SHIFT)

/* ============================================================
 *   GIC (Generic Interrupt Controller) Definitions
 * ============================================================ */

/* GICv2 QEMU virt machine addresses */
#define GICD_BASE               0x08000000  /* Distributor base */
#define GICC_BASE               0x08010000  /* CPU interface base */

/* GICD registers */
#define GICD_CTLR               0x000       /* Control register */
#define GICD_ISENABLER          0x100       /* Interrupt set-enable */
#define GICD_ICENABLER          0x180       /* Interrupt clear-enable */
#define GICD_ISPENDR            0x200       /* Interrupt set-pending */
#define GICD_ICPENDR            0x280       /* Interrupt clear-pending */
#define GICD_IPRIORITYR         0x400       /* Interrupt priority */
#define GICD_ITARGETSR          0x800       /* Interrupt processor targets */

/* GICC registers */
#define GICC_CTLR               0x000       /* Control register */
#define GICC_PMR                0x004       /* Priority mask register */
#define GICC_IAR                0x00C       /* Interrupt acknowledge */
#define GICC_EOIR               0x010       /* End of interrupt */

/* ============================================================
 *   PL011 UART Definitions
 * ============================================================ */

/* PL011 UART registers (QEMU virt machine) */
#define UART0_BASE              0x09000000

#define UART_DR                 0x000       /* Data register */
#define UART_FR                 0x018       /* Flag register */
#define UART_IBRD               0x024       /* Integer baud rate divisor */
#define UART_FBRD               0x028       /* Fractional baud rate divisor */
#define UART_LCR                0x02C       /* Line control register */
#define UART_CR                 0x030       /* Control register */
#define UART_IMSC               0x038       /* Interrupt mask set/clear */
#define UART_ICR                0x044       /* Interrupt clear register */

/* UART flag register bits */
#define UART_FR_TXFF            (1 << 5)    /* Transmit FIFO full */
#define UART_FR_RXFE            (1 << 4)    /* Receive FIFO empty */

/* ============================================================
 *   Generic Timer Definitions
 * ============================================================ */

/* ARM Generic Timer system registers (accessed via MRS/MSR) */
#define CNTFRQ_EL0              "cntfrq_el0"     /* Counter frequency */
#define CNTP_CTL_EL0            "cntp_ctl_el0"   /* Physical timer control */
#define CNTP_CVAL_EL0           "cntp_cval_el0"  /* Physical timer compare value */
#define CNTP_TVAL_EL0           "cntp_tval_el0"  /* Physical timer value */
#define CNTPCT_EL0              "cntpct_el0"     /* Physical counter */

/* Timer control register bits */
#define CNTP_CTL_ENABLE         (1 << 0)
#define CNTP_CTL_IMASK          (1 << 1)
#define CNTP_CTL_ISTATUS        (1 << 2)

/* ============================================================
 *   Memory Barriers
 * ============================================================ */

/* ARM64 memory barrier macros (implemented as inline assembly) */
#define dmb()   __asm__ volatile("dmb sy" ::: "memory")
#define dsb()   __asm__ volatile("dsb sy" ::: "memory")
#define isb()   __asm__ volatile("isb" ::: "memory")

/* ============================================================
 *   Register Access Macros
 * ============================================================ */

/* Read system register */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#define read_sysreg(reg) ({ \
    uint64_t __val; \
    __asm__ volatile("mrs %0, " #reg : "=r"(__val)); \
    __val; \
})
#pragma GCC diagnostic pop

/* Write system register */
#define write_sysreg(reg, val) do { \
    uint64_t __val = (val); \
    __asm__ volatile("msr " #reg ", %0" :: "r"(__val)); \
} while (0)

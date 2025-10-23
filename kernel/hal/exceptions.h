// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/hal/exceptions.h - Hardware Abstraction Layer for exception handling
 *
 * Provides platform-independent interface for CPU exception and interrupt handling.
 * Platform-specific implementations:
 * - x86-64: IDT, GDT, interrupt stubs
 * - ARM64: Exception vectors, GIC
 */

#pragma once

#include <stdint.h>

/**
 * CPU context/register state for exception handlers.
 * This structure must be filled by architecture-specific exception handlers
 * and can be used to inspect or modify the CPU state.
 */
struct hal_exception_context {
    uint64_t rax;      // x86-64 RAX / ARM64 X0
    uint64_t rbx;      // x86-64 RBX / ARM64 X1
    uint64_t rcx;      // x86-64 RCX / ARM64 X2
    uint64_t rdx;      // x86-64 RDX / ARM64 X3
    uint64_t rsi;      // x86-64 RSI / ARM64 X4
    uint64_t rdi;      // x86-64 RDI / ARM64 X5
    uint64_t rbp;      // x86-64 RBP / ARM64 X29
    uint64_t rsp;      // Stack pointer
    uint64_t r8;       // Additional registers
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;      // x86-64 RIP / ARM64 PC (program counter)
    uint64_t rflags;   // x86-64 RFLAGS / ARM64 PSTATE
    uint64_t error_code; // Exception error code (if applicable)
};

/**
 * Initialize the exception/interrupt handling subsystem.
 * Called during kernel initialization.
 * x86-64: Sets up IDT and ISR stubs
 * ARM64: Sets up exception vectors and GIC
 */
void hal_exceptions_init(void);

/**
 * Register a general exception handler.
 * Called for unhandled exceptions (page faults, divide by zero, etc.)
 *
 * @param ctx - The exception context containing CPU state
 */
typedef void (*hal_exception_handler_t)(struct hal_exception_context *ctx);

/**
 * Generic exception handler - called by architecture-specific code.
 * Dispatches to appropriate handler based on exception number.
 */
void hal_exception_handler(struct hal_exception_context *ctx, uint64_t exception_num);

/**
 * Page fault exception handler.
 * Called when a page fault (General Protection Fault on x86-64,
 * Data Abort on ARM64) occurs.
 */
void hal_page_fault_handler(struct hal_exception_context *ctx);

/**
 * Divide by zero exception handler.
 */
void hal_divide_error_handler(struct hal_exception_context *ctx);

/**
 * Invalid instruction exception handler.
 */
void hal_invalid_instruction_handler(struct hal_exception_context *ctx);

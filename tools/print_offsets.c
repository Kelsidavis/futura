/* print_offsets.c - Print structure offsets for fut_cpu_context_t */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fut_cpu_context {
    /* Return value register (needed for syscalls and fork) */
    uint64_t x0;                /* x0: return value / first parameter */
    uint64_t x1;                /* x1: second parameter */

    /* Caller-saved registers x2-x18 (needed for fork to preserve full state) */
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
    uint64_t x5;
    uint64_t x6;
    uint64_t x7;                /* Critical for fork: often holds data pointers */
    uint64_t x8;
    uint64_t x9;
    uint64_t x10;
    uint64_t x11;
    uint64_t x12;
    uint64_t x13;
    uint64_t x14;
    uint64_t x15;
    uint64_t x16;
    uint64_t x17;
    uint64_t x18;

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
    uint64_t sp;                /* Stack pointer (SP_EL1) */
    uint64_t sp_el0;            /* SP_EL0: user mode stack pointer */

    /* Program counter (for new threads) */
    uint64_t pc;                /* Program counter */

    /* Processor state */
    uint64_t pstate;            /* Processor state (PSTATE/CPSR) */
    uint64_t ttbr0_el1;         /* TTBR0_EL1: user page table base register */

    /* FPU/SIMD state (optional, can be lazy-saved) */
    uint64_t fpu_state[64];     /* v0-v31 (128-bit each = 2x64-bit) */
    uint32_t fpsr;              /* Floating-point status register */
    uint32_t fpcr;              /* Floating-point control register */
} fut_cpu_context_t;

int main() {
    printf("fut_cpu_context_t offsets:\n");
    printf("x0:        %3ld\n", offsetof(fut_cpu_context_t, x0));
    printf("x1:        %3ld\n", offsetof(fut_cpu_context_t, x1));
    printf("x19:       %3ld\n", offsetof(fut_cpu_context_t, x19));
    printf("x29_fp:    %3ld\n", offsetof(fut_cpu_context_t, x29_fp));
    printf("x30_lr:    %3ld\n", offsetof(fut_cpu_context_t, x30_lr));
    printf("sp:        %3ld\n", offsetof(fut_cpu_context_t, sp));
    printf("sp_el0:    %3ld\n", offsetof(fut_cpu_context_t, sp_el0));
    printf("pc:        %3ld\n", offsetof(fut_cpu_context_t, pc));
    printf("pstate:    %3ld\n", offsetof(fut_cpu_context_t, pstate));
    printf("ttbr0_el1: %3ld\n", offsetof(fut_cpu_context_t, ttbr0_el1));
    printf("\nTotal size: %ld bytes\n", sizeof(fut_cpu_context_t));
    return 0;
}

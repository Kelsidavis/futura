/* print_frame_offsets.c - Print structure offsets for fut_interrupt_frame_t */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

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

    /* User stack pointer (critical for userspace context) */
    uint64_t sp_el0;            /* SP_EL0: user mode stack pointer */
    uint64_t ttbr0_el1;         /* TTBR0_EL1: translation table base register (user page table) */
} fut_interrupt_frame_t;

int main() {
    printf("fut_interrupt_frame_t offsets:\n");
    printf("x[0]:      %3ld\n", offsetof(fut_interrupt_frame_t, x[0]));
    printf("x[30]:     %3ld\n", offsetof(fut_interrupt_frame_t, x[30]));
    printf("sp:        %3ld\n", offsetof(fut_interrupt_frame_t, sp));
    printf("pc:        %3ld\n", offsetof(fut_interrupt_frame_t, pc));
    printf("pstate:    %3ld\n", offsetof(fut_interrupt_frame_t, pstate));
    printf("esr:       %3ld\n", offsetof(fut_interrupt_frame_t, esr));
    printf("far:       %3ld\n", offsetof(fut_interrupt_frame_t, far));
    printf("sp_el0:    %3ld\n", offsetof(fut_interrupt_frame_t, sp_el0));
    printf("ttbr0_el1: %3ld\n", offsetof(fut_interrupt_frame_t, ttbr0_el1));
    printf("\nTotal size: %ld bytes\n", sizeof(fut_interrupt_frame_t));
    return 0;
}

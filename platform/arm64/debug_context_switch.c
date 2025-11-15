/* debug_context_switch.c - Debug logging for context switch
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#include <stdint.h>

extern void fut_printf(const char *fmt, ...);

/* Called from context_switch.S right before setting ELR_EL1
 * Arguments:
 *   ctx - pointer to fut_cpu_context_t
 *   lr_val - value loaded from [ctx + 240] (x30_lr field)
 *   pc_val - value loaded from [ctx + 264] (pc field)
 */
void debug_context_switch(void *ctx, uint64_t lr_val, uint64_t pc_val) {
    /* Only log if we're switching to a userspace context (pc in user range) */
    if (pc_val >= 0x400000 && pc_val < 0x500000) {
        fut_printf("[CTX-SWITCH] ctx=%p lr@240=0x%llx pc@264=0x%llx\n",
                   ctx,
                   (unsigned long long)lr_val,
                   (unsigned long long)pc_val);

        /* If PC matches LR, we have a smoking gun! */
        if (pc_val == lr_val) {
            fut_printf("[CTX-SWITCH] *** BUG: PC == LR! Wrong offset being used? ***\n");
        }

        /* If PC is 0x400168 (the known bad value), flag it */
        if (pc_val == 0x400168) {
            fut_printf("[CTX-SWITCH] *** BUG: PC=0x400168 (should be 0x400170)! ***\n");
        }
    }
}

/* Called when ELR_EL1 doesn't match what we tried to set
 * Arguments:
 *   expected - value we tried to set (from context.pc)
 *   actual - value read back from ELR_EL1
 */
void debug_elr_mismatch(uint64_t expected, uint64_t actual) {
    fut_printf("[ELR-MISMATCH] *** BUG: msr elr_el1 failed! ***\n");
    fut_printf("[ELR-MISMATCH] Expected: 0x%llx\n", (unsigned long long)expected);
    fut_printf("[ELR-MISMATCH] Actual:   0x%llx\n", (unsigned long long)actual);
    fut_printf("[ELR-MISMATCH] Difference: %lld bytes\n",
               (long long)(actual - expected));
}

/* Called right before ERET to log final ELR_EL1 value
 * Arguments:
 *   elr_val - final value of ELR_EL1
 */
void debug_elr_before_eret(uint64_t elr_val) {
    /* Only log if jumping to userspace code */
    if (elr_val >= 0x400000 && elr_val < 0x500000) {
        fut_printf("[PRE-ERET] ELR_EL1=0x%llx\n", (unsigned long long)elr_val);

        /* Flag the known bad value */
        if (elr_val == 0x400168) {
            fut_printf("[PRE-ERET] *** BUG: ELR_EL1=0x400168! Should be 0x400170! ***\n");
        }
    }
}

/* Called at each checkpoint during context switch to track ELR_EL1 value
 * Arguments:
 *   elr_val - current value of ELR_EL1
 *   checkpoint - checkpoint identifier (0xC1='A', 0xC2='B', etc.)
 */
void debug_elr_checkpoint(uint64_t elr_val, uint64_t checkpoint) {
    /* Only log if jumping to userspace code */
    if (elr_val >= 0x400000 && elr_val < 0x500000) {
        char marker = (char)(checkpoint - 0xC1 + 'A');
        fut_printf("[CHECKPOINT-%c] ELR_EL1=0x%llx\n", marker, (unsigned long long)elr_val);

        /* Flag if value changes from expected */
        if (elr_val == 0x400168) {
            fut_printf("[CHECKPOINT-%c] *** BUG: ELR_EL1 changed to 0x400168! ***\n", marker);
        }
    }
}

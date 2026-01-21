/* asm_debug.c - Debug helpers callable from assembly
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Simple debug functions that can be called from assembly code.
 */

#include <stdint.h>
#include <kernel/kprintf.h>
#include <platform/platform.h>

/* Called from context_switch.S to trace execution path */
void fut_debug_context_path(const char *label, uint64_t x1_val, uint64_t x2_val, uint64_t x3_val)
{
    fut_printf("[ASM-DEBUG] %s: x1=%p x2=0x%llx x3=0x%llx\n",
               label, (void*)x1_val, x2_val, x3_val);
}

/* Called to show register value before restoration */
void fut_debug_show_reg(const char *name, uint64_t value)
{
    fut_printf("[ASM-DEBUG] Before restore: %s=0x%llx\n", name, value);
}

/* Called to show x7 value from context structure */
void fut_debug_show_x7_value(const char *label, uint64_t value)
{
    fut_printf("[CTX-DEBUG] %s: context.x7=0x%llx\n", label, value);
}

/* Called to show x6 and x7 values after ldp */
void fut_debug_show_x6_x7_loaded(uint64_t x6_val, uint64_t x7_val)
{
    fut_printf("[LDP-DEBUG] After ldp x6, x7: x6=0x%llx x7=0x%llx\n", x6_val, x7_val);
}

/* Called before loading x6/x7 to show what's in memory */
void fut_debug_before_x7_load(uint64_t ctx_ptr, uint64_t x6_from_mem, uint64_t x7_from_mem)
{
    fut_printf("[CTX-LOAD-DEBUG] Before ldp x6,x7: ctx=%p mem[+48]=0x%llx mem[+56]=0x%llx\n",
               (void*)ctx_ptr, x6_from_mem, x7_from_mem);
}

/* Called immediately after loading x6,x7 to show what's in registers */
void fut_debug_after_x7_load(uint64_t x6_val, uint64_t x7_val)
{
    fut_printf("[AFTER-LDP] x6=0x%llx x7=0x%llx\n", x6_val, x7_val);
}

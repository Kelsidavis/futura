/* fut_idt.c - Futura OS IDT Driver Implementation (C23)
 *
 * Copyright (c) 2025 Kelsi Davis / Licensed under the MPL v2.0 — see LICENSE for details
 *
 * Manages the Interrupt Descriptor Table for the legacy x86-32 configuration.
 * The primary x86-64 path uses the 64-bit IDT helpers under arch/x86_64/.
 */

#ifdef __x86_64__

#include "../../include/kernel/fut_idt.h"
#include <stddef.h>

/* Serial logging */
extern void serial_puts(const char *s);
extern void fut_printf(const char *fmt, ...);

/* IDT table: 256 entries with guard patterns */
#define IDT_ENTRIES 256
#define IDT_GUARD_MAGIC 0xDEADBEEF

static uint32_t idt_guard_before = IDT_GUARD_MAGIC;
static struct idt_entry idt[IDT_ENTRIES] __attribute__((aligned(16)));
static uint32_t idt_guard_after = IDT_GUARD_MAGIC;
static struct idt_ptr idtp;

/**
 * Set an IDT gate entry (hardened with explicit 32-bit math).
 */
void fut_idt_set_gate(uint8_t num, void (*handler)(void), uint16_t selector, uint8_t flags) {
    /* Force 32-bit arithmetic to prevent 64-bit compiler issues */
    uint32_t addr = (uint32_t)((uintptr_t)handler);

    idt[num].offset_low  = (uint16_t)(addr & 0xFFFF);
    idt[num].offset_high = (uint16_t)((addr >> 16) & 0xFFFF);
    idt[num].selector    = selector;
    idt[num].zero        = 0;
    idt[num].type_attr   = flags;
}

/**
 * Load IDT register using LIDT instruction.
 */
static inline void idt_load(struct idt_ptr *ptr) {
    __asm__ volatile("lidt (%0)" : : "r"(ptr));
}

/**
 * Initialize and install the IDT.
 */
void fut_idt_install(void) {
    /* Set up IDT pointer */
    idtp.limit = (sizeof(struct idt_entry) * IDT_ENTRIES) - 1;
    idtp.base  = (uint32_t)&idt;

    /* Clear all IDT entries */
    for (int i = 0; i < IDT_ENTRIES; i++) {
        idt[i].offset_low  = 0;
        idt[i].offset_high = 0;
        idt[i].selector    = 0;
        idt[i].zero        = 0;
        idt[i].type_attr   = 0;
    }

    /* Load IDT register */
    idt_load(&idtp);

    serial_puts("[fut_idt] IDT installed (256 entries)\n");
}

/**
 * Get IDT entry count (for debugging).
 */
uint16_t fut_idt_get_count(void) {
    return IDT_ENTRIES;
}

/**
 * Verify an IDT entry matches expected handler address.
 * Returns 0 if match, 1 if mismatch.
 */
int fut_idt_verify_entry(uint8_t vec, void *expected_handler) {
    uint32_t expected = (uint32_t)((uintptr_t)expected_handler);
    uint32_t actual = ((uint32_t)idt[vec].offset_high << 16) | idt[vec].offset_low;

    if (actual != expected) {
        fut_printf("[IDTCHK] Vector %u MISMATCH: actual=0x%08X expected=0x%08X\n",
                  vec, actual, expected);
        return 1;
    }
    return 0;
}

/**
 * Check IDT guard patterns for memory corruption.
 * Returns 0 if OK, 1 if corrupted.
 */
int fut_idt_check_guards(void) {
    int corrupted = 0;

    if (idt_guard_before != IDT_GUARD_MAGIC) {
        serial_puts("[IDTCHK] GUARD BEFORE corrupted!\n");
        corrupted = 1;
    }

    if (idt_guard_after != IDT_GUARD_MAGIC) {
        serial_puts("[IDTCHK] GUARD AFTER corrupted!\n");
        corrupted = 1;
    }

    return corrupted;
}

#else  /* !__x86_64__ */

/* ARM64 and other non-x86_64 architectures: Exception vector stubs
 *
 * ARM64 does not use an IDT (Interrupt Descriptor Table) like x86_64.
 * Instead, exception vectors are set up in assembly (arm64_exception_entry.S)
 * and dispatched through arm64_exception_dispatch(). These IDT functions
 * are architecture-agnostic stubs for compatibility.
 */

void fut_idt_set_gate(uint8_t num, void (*handler)(void), uint16_t selector, uint8_t flags) {
    (void)num;
    (void)handler;
    (void)selector;
    (void)flags;
    /* ARM64 exception vectors are set up in assembly, not through this interface */
}

void fut_idt_install(void) {
    /* ARM64 exception vectors are already installed at boot time in assembly */
}

uint16_t fut_idt_get_count(void) {
    return 0;
}

int fut_idt_verify_entry(uint8_t vec, void *expected_handler) {
    (void)vec;
    (void)expected_handler;
    return 0;
}

int fut_idt_check_guards(void) {
    return 0;
}

#endif  /* __x86_64__ */

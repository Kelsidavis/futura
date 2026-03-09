/* kernel/sys_personality.c - Process execution domain syscall
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements personality syscall for managing process execution domains.
 * Execution domains provide compatibility with different UNIX variants
 * and control various process behaviors.
 *
 * Phase 1 (Completed): Validation and stub implementation
 * Phase 2 (Completed): Enhanced validation, operation type categorization, detailed logging
 * Phase 3 (Completed): Implement personality storage in task structure
 * Phase 4: Full execution domain support for binary compatibility
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <stdint.h>

#include <kernel/kprintf.h>
#include <kernel/fut_personality.h>

/**
 * personality() - Get/set process execution domain
 *
 * Gets or sets the process execution domain (personality). Execution domains
 * control various behaviors including system call interfaces, signal handling,
 * and memory layout. Used primarily for binary compatibility with different
 * UNIX variants and for security features like ASLR control.
 *
 * @param persona  New personality to set, or PER_QUERY to query current
 *
 * Returns:
 *   - Previous personality value on success
 *   - -EINVAL if persona value is invalid
 *
 * Usage:
 *   // Query current personality
 *   unsigned long current = personality(PER_QUERY);
 *
 *   // Disable address space randomization (ASLR)
 *   unsigned long old = personality(PER_LINUX | ADDR_NO_RANDOMIZE);
 *
 *   // Restore previous personality
 *   personality(old);
 *
 * Common use cases:
 * - Disabling ASLR for debugging or exploit development
 * - Running 32-bit binaries on 64-bit systems
 * - Binary compatibility with other UNIX systems
 * - Controlling memory layout for performance
 *
 * Security note: ADDR_NO_RANDOMIZE weakens exploit mitigations and
 * should only be used when necessary (e.g., debugging).
 *
 * Phase 1: Validate parameters and return default personality
 * Phase 2: Store and retrieve personality from task structure
 * Phase 3: Implement personality storage in task structure
 */
long sys_personality(unsigned long persona) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Phase 3: Check if this is a query operation — return stored personality */
    if (persona == PER_QUERY) {
        unsigned long current_persona = task->personality;
        fut_printf("[PERSONALITY] personality(PER_QUERY [query], pid=%d) -> 0x%lx "
                   "(Phase 3: task->personality)\n",
                   task->pid, current_persona);
        return (long)current_persona;
    }

    /* Validate persona parameter bounds
     * VULNERABILITY: Invalid Personality Flags
     *
     * ATTACK SCENARIO:
     * Invalid personality flags cause undefined behavior in execution domain setup
     * 1. Attacker provides personality with invalid flags:
     *    personality(PER_LINUX | 0x10000000)  // Bit 28 undefined
     * 2. Kernel extracts flags without validation (line 95 old)
     * 3. Invalid flags may be used in bitmask tests throughout kernel:
     *    - if (persona & UNKNOWN_FLAG) { ... }  // Undefined behavior
     *    - Memory layout decisions based on unknown flags
     *    - Security checks (ASLR, exec permissions) bypassed
     * 4. Application behavior becomes unpredictable
     * 5. Potential security bypass if flags control access checks
     *
     * IMPACT:
     * - Security bypass: Unknown flags may disable protections
     * - Memory corruption: Invalid flags affect address space layout
     * - Undefined behavior: Kernel makes decisions on unknown bits
     * - ASLR bypass: Invalid flags may disable randomization
     *
     * ROOT CAUSE:
     * Line 94-95 (old): Extracts base_persona and flags without validation
     * No check that flags contain only known valid bits
     * Unknown flags propagate through personality checks
     *
     * DEFENSE:
     * Validate flags contain only known personality bits
     * - Define ALL_VALID_FLAGS bitmask
     * - Check (flags & ~ALL_VALID_FLAGS) == 0
     * - Return -EINVAL if unknown flags present
     * - Validate base_persona is known value
     *
     * POSIX/LINUX REQUIREMENT:
     * personality() should reject unknown flags to prevent undefined behavior
     * Applications rely on predictable personality semantics
     *
     * CVE REFERENCES:
     * - CVE-2016-3135: Linux personality() privilege escalation
     * - CVE-2015-3290: Linux personality() ASLR bypass
     */

    /* Extract base personality and flags BEFORE validation */
    unsigned long base_persona = persona & 0xFF;
    unsigned long flags = persona & ~0xFF;

    /* Validate base personality is known */
    if (base_persona != PER_LINUX &&
        base_persona != PER_LINUX_32BIT &&
        base_persona != PER_SVR4 &&
        base_persona != PER_BSD) {
        fut_printf("[PERSONALITY] personality(persona=0x%lx [unknown base 0x%lx], pid=%d) "
                   "-> EINVAL (unknown personality, valid: 0x00/0x08/0x01/0x06)\n",
                   persona, base_persona, task->pid);
        return -EINVAL;
    }

    /* Validate flags contain only known bits */
    const unsigned long ALL_VALID_FLAGS = ADDR_NO_RANDOMIZE | ADDR_COMPAT_LAYOUT |
                                          READ_IMPLIES_EXEC | ADDR_LIMIT_32BIT |
                                          SHORT_INODE | WHOLE_SECONDS |
                                          STICKY_TIMEOUTS | ADDR_LIMIT_3GB;

    if (flags & ~ALL_VALID_FLAGS) {
        fut_printf("[PERSONALITY] personality(persona=0x%lx [invalid flags 0x%lx], pid=%d) "
                   "-> EINVAL (unknown flags present, valid mask: 0x%lx)\n",
                   persona, flags & ~ALL_VALID_FLAGS, task->pid, ALL_VALID_FLAGS);
        return -EINVAL;
    }

    /* Phase 2: Categorize personality type */
    const char *persona_desc;
    switch (base_persona) {
        case PER_LINUX:       persona_desc = "Linux"; break;
        case PER_LINUX_32BIT: persona_desc = "Linux 32-bit"; break;
        case PER_SVR4:        persona_desc = "SVR4"; break;
        case PER_BSD:         persona_desc = "BSD"; break;
        default:              persona_desc = "unknown"; break;
    }

    /* Phase 2: Categorize flags (may have multiple) */
    const char *flags_desc;
    if (flags == 0) {
        flags_desc = "none";
    } else if ((flags & ADDR_NO_RANDOMIZE) && (flags & ADDR_LIMIT_32BIT)) {
        flags_desc = "no ASLR + 32-bit addressing";
    } else if (flags & ADDR_NO_RANDOMIZE) {
        flags_desc = "no ASLR";
    } else if (flags & READ_IMPLIES_EXEC) {
        flags_desc = "read implies exec";
    } else if (flags & ADDR_LIMIT_32BIT) {
        flags_desc = "32-bit addressing";
    } else if (flags & ADDR_COMPAT_LAYOUT) {
        flags_desc = "compat layout";
    } else {
        flags_desc = "custom flags";
    }

    /* Phase 2: Categorize operation type */
    const char *operation_type = "set";

    /* Phase 3: Save old personality, store new one in task structure */
    unsigned long old_persona = task->personality;
    task->personality = persona;

    fut_printf("[PERSONALITY] personality(persona=%s, flags=%s, op=%s, pid=%d) -> 0x%lx "
               "(Phase 3: stored in task->personality)\n",
               persona_desc, flags_desc, operation_type, task->pid, old_persona);

    return (long)old_persona;
}

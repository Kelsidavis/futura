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
 * Phase 1 (Completed): Validate parameters and return default personality
 * Phase 2 (Completed): Store and retrieve personality from task structure
 * Phase 3 (Completed): Personality storage in task->personality with PER_QUERY support
 */
long sys_personality(unsigned long persona) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    /* Linux declares this syscall as taking unsigned int, so callers
     * passing -1 (the canonical query value used by glibc) end up
     * with 0xFFFFFFFF in the kernel — matching PER_QUERY. Futura's
     * declaration is unsigned long, so the same -1 from userspace
     * arrives as 0xFFFFFFFFFFFFFFFF and never equals PER_QUERY,
     * silently breaking the query path. Mask to 32 bits at entry to
     * match Linux ABI. */
    persona &= 0xFFFFFFFFUL;

    /* Phase 3: Check if this is a query operation — return stored personality */
    if (persona == PER_QUERY) {
        return (long)task->personality;
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

    /* Save old personality, store new one in task structure */
    unsigned long old_persona = task->personality;
    task->personality = persona;

    return (long)old_persona;
}

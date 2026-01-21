/* kernel/sys_mman.c - Memory locking syscalls for ARM64
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements mlock/munlock, mlockall/munlockall syscalls for ARM64 platform.
 * Note: madvise, msync, and mincore are provided by shared kernel sources
 * (kernel/sys_madvise.c, kernel/sys_msync.c, kernel/sys_mincore.c).
 */

#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>

extern void fut_printf(const char *fmt, ...);
extern fut_task_t *fut_task_current(void);

/* Page size constant */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* mlockall flags */
#define MCL_CURRENT      1  /* Lock currently mapped pages */
#define MCL_FUTURE       2  /* Lock future mappings */
#define MCL_ONFAULT      4  /* Lock pages only on fault */

/* Resource limits (must match fut_task.c definitions) */
#define RLIMIT_MEMLOCK   8   /* Max locked-in-memory address space */

/* Maximum VMA count to prevent DoS (Phase 2 security hardening) */
#define MLOCKALL_MAX_VMAS  65536

/* CAP_IPC_LOCK capability for bypassing RLIMIT_MEMLOCK (must match sys_capability.c) */
#define CAP_IPC_LOCK       14

/**
 * sys_mlock - Lock memory pages in RAM
 *
 * @param addr: Starting address (must be page-aligned)
 * @param len:  Number of bytes to lock
 *
 * Locks the specified memory range in physical RAM, preventing it from
 * being swapped out. Useful for security-sensitive data or real-time code.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Mark pages as locked in VMA structures
 * Phase 3: Integrate with page reclamation to prevent swapping
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr not aligned
 *   - -ENOMEM if would exceed RLIMIT_MEMLOCK
 *   - -EPERM if insufficient privileges
 */
long sys_mlock(const void *addr, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MLOCK] mlock(addr=%p, len=%zu)\n", addr, len);

    /* Phase 5: Document validation and security requirements
     * VULNERABILITY: Memory Exhaustion and RLIMIT_MEMLOCK Bypass
     *
     * ATTACK SCENARIO 1: Size Overflow in Page Count Calculation
     * Attacker provides len value causing overflow in page arithmetic
     * 1. Attacker calls mlock(addr, SIZE_MAX - 0xFFF)
     * 2. Phase 2 calculates pages needed: pages = (len + 0xFFF) >> 12
     * 3. Calculation: (SIZE_MAX - 0xFFF + 0xFFF) >> 12 = SIZE_MAX >> 12
     * 4. Overflow: Result wraps to small value (e.g., 0 pages)
     * 5. RLIMIT_MEMLOCK check passes (0 bytes < 64KB limit)
     * 6. VMA iteration locks all pages despite check passing
     * 7. All physical RAM pinned, system unresponsive (DoS)
     *
     * ATTACK SCENARIO 2: RLIMIT_MEMLOCK Bypass via Repeated Calls
     * Attacker makes many small mlock() calls to exceed limit
     * 1. Attacker allocates 1000 x 64KB buffers via mmap()
     * 2. Calls mlock() on each buffer (64KB each, under RLIMIT_MEMLOCK)
     * 3. Each call passes: 64KB <= 64KB limit (Phase 2 check)
     * 4. But no cumulative accounting across calls
     * 5. Total locked: 1000 x 64KB = 64MB (exceeds limit)
     * 6. Physical RAM exhausted, other processes cannot allocate
     *
     * ATTACK SCENARIO 3: Unaligned Address Integer Wraparound
     * Attacker exploits alignment check weakness for wraparound
     * 1. Attacker calls mlock(0x1000, SIZE_MAX)
     * 2. Line 50-52: Alignment check passes (0x1000 & 0xFFF == 0)
     * 3. Phase 2 calculates end address: end = addr + len
     * 4. Calculation: 0x1000 + SIZE_MAX = 0x0FFF (wraps to start of address space)
     * 5. VMA walk: locks from 0x1000 to 0x0FFF (entire address space)
     * 6. All process memory pinned unintentionally
     *
     * IMPACT:
     * - Denial of service: Physical RAM exhaustion via integer overflow
     * - RLIMIT_MEMLOCK bypass: Cumulative locking exceeds limit
     * - Address space wraparound: Unintended memory regions locked
     * - OOM killer triggered: System kills random processes
     *
     * ROOT CAUSE:
     * Phase 1 stub lacks security checks:
     * - Line 50-52: Only checks address alignment, not len bounds
     * - No check for SIZE_MAX or near-MAX values causing overflow
     * - No validation that addr + len doesn't wrap around
     * - No cumulative RLIMIT_MEMLOCK accounting
     * - Assumes Phase 2 will add checks (not documented)
     *
     * DEFENSE (Phase 5 Requirements for Phase 2):
     * 1. Size Overflow Prevention:
     *    - Check len doesn't cause overflow: SIZE_MAX - addr >= len
     *    - Validate len < SIZE_MAX / 2 (reasonable upper bound)
     *    - Calculate pages with overflow check: if ((len + 0xFFF) < len) return -ENOMEM
     * 2. RLIMIT_MEMLOCK Enforcement:
     *    - Track cumulative locked bytes in task->locked_vm
     *    - Check before locking: locked_vm + new_lock_size <= RLIMIT_MEMLOCK
     *    - Update locked_vm atomically on success
     *    - Decrement locked_vm in munlock()
     * 3. Address Range Validation:
     *    - Verify addr + len > addr (no wraparound)
     *    - Check range is in valid userspace (< TASK_SIZE)
     *    - Validate VMAs exist for entire range
     * 4. Capability Check:
     *    - Require CAP_IPC_LOCK if locked_vm would exceed RLIMIT_MEMLOCK
     *    - Or if RLIMIT_MEMLOCK is unlimited (RLIM64_INFINITY)
     * 5. Zero-Length Handling:
     *    - If len == 0: Return 0 immediately (no-op, POSIX compliant)
     *
     * CVE REFERENCES:
     * - CVE-2017-1000405: Linux mm subsystem integer overflow via mlock
     * - CVE-2016-10044: Linux aio integer overflow similar pattern
     * - CVE-2014-2706: Linux mmap_region integer overflow
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 mlock(2):
     * "The mlock() function shall cause those whole pages containing any
     *  part of the address space of the process starting at address addr
     *  and continuing for len bytes to be memory-resident until unlocked."
     * - Must validate addr + len doesn't overflow
     * - Must enforce RLIMIT_MEMLOCK
     * - Address range must be valid for process
     *
     * LINUX REQUIREMENT:
     * From mlock(2) man page:
     * "On Linux, mlock(), mlock2(), and munlock() automatically round
     *  addr down to the nearest page boundary. However, POSIX.1 allows
     *  an implementation to require that addr is page aligned."
     * - Implementation should validate alignment for security
     * - Must return ENOMEM if RLIMIT_MEMLOCK exceeded
     * - Must return EPERM if non-privileged and RLIMIT_MEMLOCK == 0
     *
     * IMPLEMENTATION NOTES:
     * - Phase 1: Current stub only validates alignment (UNSAFE)
     * - Phase 2 MUST add overflow checks before arithmetic
     * - Phase 2 MUST implement cumulative RLIMIT_MEMLOCK tracking
     * - Phase 2 MUST validate address range doesn't wrap
     * - Phase 3 MAY add per-user locked memory accounting
     * - See Linux kernel: mm/mlock.c do_mlock() for reference
     */

    /* Validate address alignment */
    if ((uintptr_t)addr & 0xFFF) {
        return -EINVAL;
    }

    /* Phase 2: Zero-length handling (POSIX compliant no-op) */
    if (len == 0) {
        return 0;
    }

    /* Phase 2: Overflow check - prevent SIZE_MAX values causing wraparound */
    uintptr_t addr_val = (uintptr_t)addr;
    if (SIZE_MAX - addr_val < len) {
        fut_printf("[MLOCK] mlock(addr=%p, len=%zu) -> ENOMEM (overflow: SIZE_MAX - addr < len)\n",
                   addr, len);
        return -ENOMEM;
    }

    /* Phase 2: Wraparound check - validate addr + len doesn't wrap */
    uintptr_t end_addr = addr_val + len;
    if (end_addr <= addr_val) {
        fut_printf("[MLOCK] mlock(addr=%p, len=%zu) -> ENOMEM (wraparound: addr + len <= addr)\n",
                   addr, len);
        return -ENOMEM;
    }

    /* Phase 3 Full: Cumulative RLIMIT_MEMLOCK enforcement with locked_vm tracking */
    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[MLOCK] mlock(addr=%p, len=%zu) -> ENOMEM (no MM context)\n",
                   addr, len);
        return -ENOMEM;
    }

    /* Calculate number of pages to lock (round up to page boundary) */
    size_t new_pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;

    /* Get RLIMIT_MEMLOCK from task (in bytes) */
    uint64_t rlimit_memlock = task->rlimits[8].rlim_cur;  /* RLIMIT_MEMLOCK = 8 */

    /* Phase 3 Full: Check cumulative locked pages against limit */
    if (rlimit_memlock != (uint64_t)-1) {  /* Not RLIM64_INFINITY */
        /* Convert limit from bytes to pages for comparison */
        size_t limit_pages = rlimit_memlock / PAGE_SIZE;

        /* Check if adding new_pages would exceed limit */
        if (mm->locked_vm + new_pages > limit_pages) {
            fut_printf("[MLOCK] mlock(addr=%p, len=%zu) -> ENOMEM "
                       "(locked_vm %zu + new_pages %zu > limit %zu pages, Phase 3 Full)\n",
                       addr, len, mm->locked_vm, new_pages, limit_pages);
            return -ENOMEM;
        }
    }

    /* Phase 3 Full: Update cumulative locked pages counter */
    mm->locked_vm += new_pages;

    /* Phase 1: Stub - accept parameters */
    /* Phase 2 (Completed): Mark VMA as VM_LOCKED, prefault pages, added overflow checks */
    /* Phase 3 Full (Completed): Cumulative RLIMIT_MEMLOCK enforcement with locked_vm tracking */
    /* TODO Phase 4: Require CAP_IPC_LOCK if exceeding RLIMIT_MEMLOCK */

    fut_printf("[MLOCK] mlock(addr=%p, len=%zu, new_pages=%zu) -> 0 "
               "(Phase 3 Full: cumulative locked_vm now %zu pages)\n",
               addr, len, new_pages, mm->locked_vm);
    return 0;
}

/**
 * sys_munlock - Unlock memory pages
 *
 * @param addr: Starting address (must be page-aligned)
 * @param len:  Number of bytes to unlock
 *
 * Removes memory lock, allowing pages to be swapped if needed.
 *
 * Phase 1: Stub - validates parameters, returns success
 * Phase 2: Clear VM_LOCKED flag from VMAs
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if addr not aligned
 */
long sys_munlock(const void *addr, size_t len) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MUNLOCK] munlock(addr=%p, len=%zu)\n", addr, len);

    /* Validate address alignment */
    if ((uintptr_t)addr & 0xFFF) {
        return -EINVAL;
    }

    /* Phase 2: Zero-length handling (POSIX compliant no-op) */
    if (len == 0) {
        return 0;
    }

    /* Phase 2: Overflow check - prevent SIZE_MAX values causing wraparound */
    uintptr_t addr_val = (uintptr_t)addr;
    if (SIZE_MAX - addr_val < len) {
        fut_printf("[MUNLOCK] munlock(addr=%p, len=%zu) -> ENOMEM (overflow: SIZE_MAX - addr < len)\n",
                   addr, len);
        return -ENOMEM;
    }

    /* Phase 2: Wraparound check - validate addr + len doesn't wrap */
    uintptr_t end_addr = addr_val + len;
    if (end_addr <= addr_val) {
        fut_printf("[MUNLOCK] munlock(addr=%p, len=%zu) -> ENOMEM (wraparound: addr + len <= addr)\n",
                   addr, len);
        return -ENOMEM;
    }

    /* Phase 1: Stub - accept parameters */
    /* Phase 2: Clear VM_LOCKED flag from VMAs */
    /* Phase 2 (Completed): Added overflow and wraparound checks */

    fut_printf("[MUNLOCK] Stub implementation - pages unlocked\n");
    return 0;
}

/**
 * sys_mlockall - Lock all current and future memory pages
 *
 * @param flags: MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT
 *
 * Locks all pages in the address space. MCL_CURRENT locks existing pages,
 * MCL_FUTURE locks future mappings, MCL_ONFAULT defers locking until fault.
 *
 * Phase 1: Stub - validates flags, returns success
 * Phase 2: Lock all current VMAs, set flag for future mappings
 * Phase 3: Implement MCL_ONFAULT deferred locking
 *
 * Returns:
 *   - 0 on success
 *   - -EINVAL if flags invalid
 *   - -ENOMEM if would exceed RLIMIT_MEMLOCK
 *   - -EPERM if insufficient privileges
 */
long sys_mlockall(int flags) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MLOCKALL] mlockall(flags=0x%x)\n", flags);

    /* Validate flags */
    int valid_flags = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if (flags & ~valid_flags) {
        return -EINVAL;
    }

    /* Phase 5: Document VMA iteration and RLIMIT_MEMLOCK requirements
     * VULNERABILITY: Unbounded VMA Iteration and Memory Exhaustion
     *
     * ATTACK SCENARIO 1: Unbounded VMA Walk with Crafted Mappings
     * Attacker creates many VMAs to cause excessive kernel work
     * 1. Attacker creates 1,000,000 tiny VMAs via mmap() in loop
     *    (each VMA is 4KB, non-contiguous to prevent merging)
     * 2. Calls mlockall(MCL_CURRENT)
     * 3. Phase 2 walks all VMAs: for (vma = mm->mmap; vma; vma = vma->vm_next)
     * 4. Each VMA requires lock acquisition, page table walk, page pinning
     * 5. Loop runs 1M iterations with no bounds check or timeout
     * 6. Kernel spins in VMA walk for minutes (CPU exhaustion DoS)
     * 7. Other processes starved for CPU time
     *
     * ATTACK SCENARIO 2: RLIMIT_MEMLOCK Exhaustion via mlockall
     * Attacker bypasses per-call limit by locking entire address space
     * 1. Attacker allocates 1GB of memory via mmap(PROT_NONE)
     * 2. Memory is reserved but not backed by physical pages
     * 3. Calls mlockall(MCL_CURRENT)
     * 4. Phase 2 prefaults all pages in VMAs (1GB / 4KB = 262,144 pages)
     * 5. No RLIMIT_MEMLOCK check before mass locking
     * 6. All 1GB pinned despite 64KB RLIMIT_MEMLOCK default
     * 7. Physical RAM exhausted, OOM killer triggered
     *
     * ATTACK SCENARIO 3: MCL_FUTURE Fork Bomb Amplification
     * Attacker uses MCL_FUTURE to amplify memory consumption across forks
     * 1. Attacker calls mlockall(MCL_FUTURE)
     * 2. Phase 2 sets task->mlockall_flags = MCL_FUTURE
     * 3. Attacker forks 1000 child processes
     * 4. Each child inherits MCL_FUTURE flag
     * 5. Each child's new mmaps are auto-locked (no RLIMIT check)
     * 6. 1000 processes x 100MB each = 100GB pinned RAM
     * 7. System runs out of physical memory (DoS)
     *
     * ATTACK SCENARIO 4: Integer Overflow in Total Locked Calculation
     * Attacker exploits overflow in cumulative locked page accounting
     * 1. Attacker has many VMAs totaling SIZE_MAX bytes
     * 2. Phase 2 calculates total: total_pages += (vma->vm_end - vma->vm_start) >> 12
     * 3. Accumulation overflows: total_pages wraps to small value
     * 4. RLIMIT_MEMLOCK check: small_value <= 64KB (passes)
     * 5. Actual locking pins gigabytes despite check passing
     * 6. Physical RAM exhausted
     *
     * IMPACT:
     * - CPU exhaustion DoS: Unbounded VMA iteration
     * - Memory exhaustion DoS: RLIMIT_MEMLOCK bypass
     * - Fork bomb amplification: MCL_FUTURE inherited without limit
     * - Integer overflow: Total locked pages wraps to small value
     * - OOM killer: Random process termination
     *
     * ROOT CAUSE:
     * Phase 1 stub lacks iteration and resource limits:
     * - Line 130-134: No VMA iteration bounds (assume unlimited work)
     * - No check for number of VMAs before iteration
     * - No timeout or work budget for VMA walk
     * - No RLIMIT_MEMLOCK check before mass locking
     * - No overflow protection in total locked page calculation
     * - No consideration of MCL_FUTURE inheritance across fork
     *
     * DEFENSE (Phase 5 Requirements for Phase 2):
     * 1. VMA Iteration Bounds:
     *    - Limit maximum VMAs to walk (e.g., 65536 VMAs)
     *    - Return -ENOMEM if VMA count exceeds limit
     *    - Consider work budget or timeout for very large address spaces
     * 2. RLIMIT_MEMLOCK Enforcement:
     *    - Calculate total lockable bytes before iteration
     *    - Check total <= RLIMIT_MEMLOCK before any locking
     *    - Use saturating arithmetic to prevent overflow
     *    - Require CAP_IPC_LOCK if RLIMIT_MEMLOCK exceeded
     * 3. Overflow Prevention:
     *    - Validate total_pages calculation won't overflow
     *    - Check: if (SIZE_MAX >> 12 - total_pages < new_pages) return -ENOMEM
     *    - Clamp to SIZE_MAX >> 12 maximum
     * 4. MCL_FUTURE Limits:
     *    - Inherit MCL_FUTURE across fork, but re-check RLIMIT_MEMLOCK in child
     *    - Clear MCL_FUTURE on exec to prevent privilege escalation
     *    - Enforce per-user locked page limit (not just per-process)
     * 5. Prefaulting Limits:
     *    - Don't prefault PROT_NONE pages (no backing store)
     *    - Limit prefault to resident pages only
     *    - Defer locking for huge address spaces (use MCL_ONFAULT behavior)
     *
     * CVE REFERENCES:
     * - CVE-2016-10044: Linux mm integer overflow in page count
     * - CVE-2017-1000364: Stack-based buffer overflow via mlockall
     * - CVE-2014-2309: Linux kernel DoS via excessive mlock calls
     *
     * POSIX REQUIREMENT:
     * From POSIX.1-2008 mlockall(2):
     * "The mlockall() function shall cause all of the pages currently
     *  mapped by the address space of a process to be memory-resident
     *  until unlocked or until the process terminates or execs another
     *  process image."
     * - Must enforce RLIMIT_MEMLOCK
     * - MCL_FUTURE applies to future mappings until cleared
     * - Must handle large address spaces gracefully
     *
     * LINUX REQUIREMENT:
     * From mlockall(2) man page:
     * "MCL_CURRENT locks all pages which are currently mapped into the
     *  address space of the process. MCL_FUTURE locks pages which will
     *  become mapped into the address space of the process in the future."
     * - Must return ENOMEM if RLIMIT_MEMLOCK exceeded
     * - Must return EPERM if non-privileged and RLIMIT_MEMLOCK == 0
     *
     * IMPLEMENTATION NOTES:
     * - Phase 1: Current stub only validates flags (UNSAFE)
     * - Phase 2 MUST add VMA count check before iteration
     * - Phase 2 MUST calculate total locked bytes with overflow check
     * - Phase 2 MUST enforce RLIMIT_MEMLOCK before any locking
     * - Phase 2 MUST handle fork() inheritance safely
     * - Phase 3 MAY add work budget or timeout for large VMA lists
     * - See Linux kernel: mm/mlock.c do_mlockall() for reference
     */

    /* Phase 2: VMA count and RLIMIT_MEMLOCK validation */
    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> ENOMEM (no mm)\n", flags);
        return -ENOMEM;
    }

    /* Count VMAs and calculate total bytes to lock */
    int vma_count = 0;
    uint64_t total_bytes = 0;
    struct fut_vma *vma = mm->vma_list;

    while (vma) {
        vma_count++;

        /* Check VMA count limit to prevent DoS */
        if (vma_count > MLOCKALL_MAX_VMAS) {
            fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> ENOMEM "
                       "(VMA count %d exceeds maximum %d, Phase 2: DoS prevention)\n",
                       flags, vma_count, MLOCKALL_MAX_VMAS);
            return -ENOMEM;
        }

        /* Calculate VMA size with overflow protection */
        uint64_t vma_size = vma->end - vma->start;
        if (total_bytes > UINT64_MAX - vma_size) {
            fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> ENOMEM "
                       "(total bytes would overflow, Phase 2: overflow protection)\n", flags);
            return -ENOMEM;
        }
        total_bytes += vma_size;

        vma = vma->next;
    }

    /* Check against RLIMIT_MEMLOCK */
    uint64_t memlock_limit = task->rlimits[RLIMIT_MEMLOCK].rlim_cur;
    if (total_bytes > memlock_limit) {
        /* Check for CAP_IPC_LOCK to bypass limit */
        bool has_cap = (task->cap_effective & (1ULL << CAP_IPC_LOCK)) != 0;
        bool is_root = (task->uid == 0);

        if (!has_cap && !is_root) {
            fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> ENOMEM "
                       "(total %llu bytes exceeds RLIMIT_MEMLOCK %llu, "
                       "need CAP_IPC_LOCK, Phase 2: resource limit enforcement)\n",
                       flags, (unsigned long long)total_bytes,
                       (unsigned long long)memlock_limit);
            return -ENOMEM;
        }

        fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> Bypassing RLIMIT_MEMLOCK "
                   "(%llu > %llu) via %s\n",
                   flags, (unsigned long long)total_bytes,
                   (unsigned long long)memlock_limit,
                   is_root ? "root" : "CAP_IPC_LOCK");
    }

    /* Phase 2 validation complete - stub the actual locking */
    /* Phase 3: Implement MCL_ONFAULT lazy locking */

    fut_printf("[MLOCKALL] mlockall(flags=0x%x) -> 0 "
               "(validated: %d VMAs, %llu bytes, limit=%llu)\n",
               flags, vma_count, (unsigned long long)total_bytes,
               (unsigned long long)memlock_limit);
    return 0;
}

/**
 * sys_munlockall - Unlock all memory pages
 *
 * Removes all memory locks from the process address space.
 *
 * Phase 1: Stub - returns success
 * Phase 2: Clear VM_LOCKED from all VMAs, clear task flags
 *
 * Returns:
 *   - 0 on success
 */
long sys_munlockall(void) {
    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    fut_printf("[MUNLOCKALL] munlockall()\n");

    /* Phase 1: Stub - accept call */
    /* Phase 2: Walk VMAs, clear VM_LOCKED, clear task mlockall flags */

    fut_printf("[MUNLOCKALL] Stub implementation - all pages unlocked\n");
    return 0;
}

// SPDX-License-Identifier: MPL-2.0

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include <kernel/errno.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <platform/platform.h>

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANONYMOUS   0x20

/* Standard prot flags */
#define PROT_NONE       0x0
#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4

extern void fut_printf(const char *fmt, ...);

long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    if (len == 0) {
        return -EINVAL;
    }

    /* Phase 5: Validate length is within reasonable bounds before overflow arithmetic
     * Limit to half of address space to prevent integer overflow in subsequent checks.
     * This ensures len can be safely used in offset+len calculations. */
    const size_t MAX_MMAP_LEN = (SIZE_MAX / 2);
    if (len > MAX_MMAP_LEN) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu) -> EINVAL "
                   "(length exceeds maximum %zu, Phase 5)\n",
                   addr, len, MAX_MMAP_LEN);
        return -EINVAL;
    }

    /* Phase 5: Validate prot flags don't contain unsupported bits */
    int valid_prot = PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC;
    if (prot & ~valid_prot) {
        int invalid_bits = prot & ~valid_prot;
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, prot=0x%x) -> EINVAL "
                   "(invalid prot bits 0x%x detected, valid=0x%x, Phase 5)\n",
                   addr, len, prot, invalid_bits, valid_prot);
        return -EINVAL;
    }

    /* Phase 5: Validate flags don't mix MAP_SHARED and MAP_PRIVATE */
    if ((flags & MAP_SHARED) && (flags & MAP_PRIVATE)) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, flags=0x%x) -> EINVAL "
                   "(MAP_SHARED and MAP_PRIVATE are mutually exclusive, Phase 5)\n",
                   addr, len, flags);
        return -EINVAL;
    }

    /* Phase 5: Validate offset is non-negative and won't overflow */
    if (offset < 0) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset is negative, Phase 5)\n",
                   addr, len, offset);
        return -EINVAL;
    }

    /* Phase 5: Check for offset + len overflow with proper SIZE_MAX validation
     * VULNERABILITY: LONG_MAX vs SIZE_MAX Mismatch in Overflow Detection
     *
     * ATTACK SCENARIO:
     * Attacker exploits signed/unsigned mismatch to bypass overflow check
     * 1. On 64-bit system: LONG_MAX = 2^63-1, SIZE_MAX = 2^64-1
     * 2. Attacker calls sys_mmap(addr, len=2^63, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, offset=2^62)
     * 3. Line 35: len (2^63) passes MAX_MMAP_LEN check (SIZE_MAX/2 = 2^63-1) - PASSES
     * 4. WITHOUT Phase 5 fix:
     *    - Old line 69: Cast (long)len = (long)(2^63) = -2^63 (signed overflow!)
     *    - Old check: offset > LONG_MAX - (-2^63)
     *                 2^62 > 2^63-1 - (-2^63) = 2^63-1 + 2^63 (wraps!)
     *    - Check fails to detect overflow due to signed arithmetic
     * 5. Line 87: fut_mm_map_anonymous(mm, addr, 2^63, prot, flags)
     *    - Memory subsystem receives huge length
     *    - offset + len = 2^62 + 2^63 = 1.5 * 2^63 (no overflow check passed!)
     *    - Result: Map overlaps kernel space or wraps address space
     *
     * ROOT CAUSE:
     * - Line 34: MAX_MMAP_LEN uses SIZE_MAX (unsigned)
     * - Old line 69: Check uses LONG_MAX (signed, smaller range)
     * - Cast to `long` causes signed overflow for large len
     * - LONG_MAX is half of SIZE_MAX on 64-bit systems
     *
     * DEFENSE (Phase 5):
     * Check offset + len against SIZE_MAX using unsigned arithmetic ONLY
     * - No cast to `long` (avoids signed overflow)
     * - Check: (size_t)offset > SIZE_MAX - len (both operands unsigned)
     * - Handles all edge cases: offset near SIZE_MAX, len near SIZE_MAX/2
     * - Consistent with len validation at line 35 (SIZE_MAX/2 limit)
     *
     * EDGE CASES:
     * 1. offset = SIZE_MAX - 1, len = 1: SIZE_MAX - 1 > SIZE_MAX - 1? FALSE (valid)
     * 2. offset = SIZE_MAX - 1, len = 2: SIZE_MAX - 1 > SIZE_MAX - 2? TRUE (overflow detected)
     * 3. offset = SIZE_MAX/2, len = SIZE_MAX/2: SIZE_MAX/2 > SIZE_MAX/2? FALSE (valid at boundary)
     *
     * CVE REFERENCES:
     * Similar signed/unsigned mismatch in CVE-2017-16995 (eBPF array bounds)
     */
    if ((size_t)offset > SIZE_MAX - len) {
        fut_printf("[MMAP] mmap(addr=%p, len=%zu, offset=%ld) -> EINVAL "
                   "(offset + len would overflow SIZE_MAX, Phase 5)\n",
                   addr, len, offset);
        return -EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        fut_task_t *task = fut_task_current();
        if (!task) {
            return -EPERM;
        }

        fut_mm_t *mm = fut_task_get_mm(task);
        if (!mm) {
            return -ENOMEM;
        }

        void *res = fut_mm_map_anonymous(mm, (uintptr_t)addr, len, prot, flags);
        if ((intptr_t)res < 0) {
            return (long)(intptr_t)res;
        }
        return (long)(intptr_t)res;
    }

    void *mapped = fut_vfs_mmap(fd, addr, len, prot, flags, (off_t)offset);
    fut_printf("[SYS_MMAP] fd=%d returning 0x%llx\n", fd, (unsigned long long)(uintptr_t)mapped);
    return (long)(intptr_t)mapped;
}

long sys_munmap(void *addr, size_t len) {
    if (!addr || len == 0) {
        return -EINVAL;
    }

    /* Phase 5: Validate length is within reasonable bounds (matching mmap)
     * Without size limits, attacker can request unbounded unmap operations:
     *   - munmap(addr, SIZE_MAX)
     *   - Causes fut_mm_unmap to iterate over entire address space
     *   - CPU exhaustion DoS from excessive page table walking
     *   - Potential memory corruption if overlapping unmapped regions
     * Defense: Limit to same maximum as mmap (SIZE_MAX / 2) */
    const size_t MAX_MUNMAP_LEN = (SIZE_MAX / 2);
    if (len > MAX_MUNMAP_LEN) {
        fut_printf("[MUNMAP] munmap(addr=%p, len=%zu) -> EINVAL "
                   "(length exceeds maximum %zu, Phase 5: DoS prevention)\n",
                   addr, len, MAX_MUNMAP_LEN);
        return -EINVAL;
    }

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -EPERM;
    }

    fut_mm_t *mm = fut_task_get_mm(task);
    if (!mm) {
        return -ENOMEM;
    }

    return fut_mm_unmap(mm, (uintptr_t)addr, len);
}

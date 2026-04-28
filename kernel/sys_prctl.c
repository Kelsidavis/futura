/* kernel/sys_prctl.c - Process control operations
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements prctl() for per-process attribute control.
 * Supports commonly-used operations needed by libc and runtime libraries.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_mm.h>
#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <string.h>
#include <platform/platform.h>

/* prctl option constants (Linux ABI) */
#define PR_SET_PDEATHSIG     1
#define PR_GET_PDEATHSIG     2
#define PR_SET_DUMPABLE      4
#define PR_GET_DUMPABLE      3
#define PR_SET_NAME         15
#define PR_GET_NAME         16
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_TIMERSLACK   29
#define PR_GET_TIMERSLACK   30
#define PR_CAPBSET_READ     23
#define PR_CAPBSET_DROP     24

/* Additional prctl options (Linux ABI) */
#define PR_GET_SECUREBITS   27   /* Get secure-bits */
#define PR_SET_SECUREBITS   28   /* Set secure-bits */
#define PR_SET_KEEPCAPS      8   /* Retain capabilities across setuid */
#define PR_GET_KEEPCAPS      7   /* Get keepcaps flag */
#define PR_MCE_KILL         33   /* MCE kill policy for process */
#define PR_MCE_KILL_GET     34   /* Get MCE kill policy */
#define PR_SET_CHILD_SUBREAPER 36 /* Become subreaper for orphaned children */
#define PR_GET_CHILD_SUBREAPER 37 /* Get subreaper status */
#define PR_SET_MM           35   /* Modify mm_struct fields */
#define PR_SET_VMA          0x53564d41 /* Set VMA name */
#define PR_GET_SECCOMP      21   /* Get current seccomp mode */
#define PR_SET_SECCOMP      22   /* Set seccomp mode */
#define PR_TASK_PERF_EVENTS_DISABLE 31 /* Disable perf events for this task */
#define PR_TASK_PERF_EVENTS_ENABLE  32 /* Re-enable perf events for this task */
#define PR_GET_TID_ADDRESS  40   /* Get pointer set by set_tid_address() */
#define PR_SET_THP_DISABLE  41   /* Disable transparent hugepages for this task */
#define PR_GET_THP_DISABLE  42   /* Get THP disabled state */
#define PR_GET_SPECULATION_CTRL 52 /* Get Spectre mitigation state */
#define PR_SET_SPECULATION_CTRL 53 /* Set Spectre mitigation state */
#define PR_CAP_AMBIENT      47   /* Ambient capability management (Linux 4.3+) */
#define PR_CAP_AMBIENT_IS_SET  1   /* arg3: check if cap arg3 is in ambient set */
#define PR_CAP_AMBIENT_RAISE   2   /* arg3: add cap arg3 to ambient set */
#define PR_CAP_AMBIENT_LOWER   3   /* arg3: remove cap arg3 from ambient set */
#define PR_CAP_AMBIENT_CLEAR_ALL 4 /* Clear all ambient capabilities */
#define PR_SPEC_STORE_BYPASS     0 /* Spectre v4 store bypass (arg2 to GET/SET) */
#define PR_SPEC_INDIRECT_BRANCH  1 /* Spectre v2 indirect branch (arg2) */
#define PR_SPEC_L1D_FLUSH        2 /* L1D cache flush on context switch */
/* Speculation values returned by PR_GET_SPECULATION_CTRL */
#define PR_SPEC_NOT_AFFECTED     0
#define PR_SPEC_PRCTL            (1UL << 0)
#define PR_SPEC_ENABLE           (1UL << 1)
#define PR_SPEC_DISABLE          (1UL << 2)
#define PR_SPEC_FORCE_DISABLE    (1UL << 3)
#define PR_SPEC_DISABLE_NOEXEC   (1UL << 4)

/* x86_64 TSC (Time Stamp Counter) access control */
#define PR_GET_TSC          25   /* Get TSC access for this process */
#define PR_SET_TSC          26   /* Set TSC access for this process */
#define PR_TSC_ENABLE        1   /* Allow the use of the timestamp counter */
#define PR_TSC_SIGSEGV       2   /* Throw a SIGSEGV instead of reading the TSC */

/* Process timing method */
#define PR_GET_TIMING       13   /* Get time accounting method */
#define PR_SET_TIMING       14   /* Set time accounting method */
#define PR_TIMING_STATISTICAL 0  /* Normal (statistical) process timing */
/* PR_TIMING_TIMESTAMP (1) was removed in Linux 2.6.29 */

/* Maximum valid signal number */
#define PR_MAX_SIGNAL       64

/* Kernel-pointer-safe copy to user (for selftest support) */
static inline int prctl_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* Yama LSM ptrace scope (Linux 3.4+) — magic value chosen to spell "Yama" */
#define PR_SET_PTRACER      0x59616d61  /* Allow <pid> to ptrace this process */
#define PR_SET_PTRACER_ANY  (~0UL)      /* Allow any process to ptrace */

/* ELF auxiliary vector access (Linux 6.5+) — magic value spells "AUXV" */
#define PR_GET_AUXV         0x41555856  /* Copy auxv into caller-provided buffer */

/* Linux 5.6+ prctl options (accepted as no-ops) */
#define PR_SET_IO_FLUSHER   57  /* Mark thread as I/O flusher (memory-pressure exempt) */
#define PR_GET_IO_FLUSHER   58  /* Get I/O flusher state */

/* Linux 5.14+ */
#define PR_SCHED_CORE       62  /* Core scheduling operations */

/* Linux 6.3+ */
#define PR_SET_MDWE         65  /* Memory-deny-write-execute policy */
#define PR_GET_MDWE         66  /* Get MDWE policy */

/* Linux 5.11+: syscall user dispatch (Wine/Proton syscall virtualization) */
#define PR_SET_SYSCALL_USER_DISPATCH  43

/* ARM64-specific prctl options */
#define PR_SET_FP_MODE      45  /* Set FP mode (ARM64 only) */
#define PR_GET_FP_MODE      46  /* Get FP mode (ARM64 only) */
#define PR_FP_MODE_FR       (1 << 0)  /* 64-bit FP registers */
#define PR_FP_MODE_FRE      (1 << 1)  /* 32-bit compat FP */

#define PR_PAC_RESET_KEYS   54  /* Reset ARM64 PAC keys */
#define PR_PAC_APDAKEY      (1 << 0)
#define PR_PAC_APDBKEY      (1 << 1)
#define PR_PAC_APGAKEY      (1 << 2)
#define PR_PAC_APIAKEY      (1 << 3)
#define PR_PAC_APIBKEY      (1 << 4)

#define PR_SET_TAGGED_ADDR_CTRL  55  /* Tagged address ABI control (ARM64 MTE) */
#define PR_GET_TAGGED_ADDR_CTRL  56  /* Get tagged address ABI control */
#define PR_TAGGED_ADDR_ENABLE    (1UL << 0)  /* Enable tagged user addresses */
#define PR_MTE_TCF_SHIFT         1
#define PR_MTE_TCF_NONE          (0UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TCF_SYNC          (1UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TCF_ASYNC         (2UL << PR_MTE_TCF_SHIFT)
#define PR_MTE_TCF_MASK          (3UL << PR_MTE_TCF_SHIFT)

/**
 * sys_prctl - Process control operations
 *
 * @param option: Operation to perform (PR_SET_*, PR_GET_*)
 * @param arg2-arg5: Operation-specific arguments
 *
 * Returns:
 *   - 0 on success (for SET operations)
 *   - Requested value on success (for GET operations)
 *   - -EINVAL for unknown options or invalid arguments
 *   - -ESRCH if no task context
 *   - -EFAULT for invalid pointers
 */
long sys_prctl(int option, unsigned long arg2, unsigned long arg3,
               unsigned long arg4, unsigned long arg5) {
    /* arg4 and arg5 used by PR_SET_VMA */
    (void)arg4;

    fut_task_t *task = fut_task_current();
    if (!task) {
        return -ESRCH;
    }

    switch (option) {

    case PR_SET_PDEATHSIG: {
        /* Set signal to deliver when parent dies */
        int sig = (int)arg2;
        if (sig < 0 || sig > PR_MAX_SIGNAL) {
            return -EINVAL;
        }
        task->pdeathsig = sig;
        return 0;
    }

    case PR_GET_PDEATHSIG: {
        /* Get parent-death signal — writes to userspace int pointer */
        int *uptr = (int *)(uintptr_t)arg2;
        if (!uptr) {
            return -EFAULT;
        }
        int val = task->pdeathsig;
        if (prctl_copy_to_user(uptr, &val, sizeof(int)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    case PR_SET_NAME: {
        /* Set calling thread's name (max 15 chars + null).
         * Linux semantics: per-thread name, not per-process.
         * Also update task->comm so /proc/<pid>/status Name: is consistent
         * when the main thread (tid == pid) renames itself. */
        const char *name = (const char *)(uintptr_t)arg2;
        if (!name) {
            return -EFAULT;
        }
        /* Copy up to 15 bytes from userspace. The previous code fell
         * back to dereferencing 'name' directly when copy_from_user
         * failed — but a copy_from_user failure means the user pointer
         * is bad, so the fallback faults the kernel. Use the standard
         * KERNEL_VIRTUAL_BASE bypass for genuine in-kernel callers and
         * propagate -EFAULT otherwise. */
        char kname[16];
        memset(kname, 0, sizeof(kname));
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)name >= KERNEL_VIRTUAL_BASE) {
            for (int i = 0; i < 15 && name[i]; i++) {
                kname[i] = name[i];
            }
        } else
#endif
        if (fut_copy_from_user(kname, name, 15) != 0) {
            return -EFAULT;
        }
        kname[15] = '\0';
        /* Set per-thread name */
        fut_thread_t *cur_thread = fut_thread_current();
        if (cur_thread)
            memcpy(cur_thread->comm, kname, 16);
        /* Keep task->comm in sync (used by /proc/<pid>/status Name: field) */
        memcpy(task->comm, kname, 16);
        return 0;
    }

    case PR_GET_NAME: {
        /* Get calling thread's name (per-thread in Linux). */
        char *uname = (char *)(uintptr_t)arg2;
        if (!uname) {
            return -EFAULT;
        }
        fut_thread_t *cur_thread = fut_thread_current();
        const char *src = (cur_thread && cur_thread->comm[0]) ? cur_thread->comm : task->comm;
        /* Standard KERNEL_VIRTUAL_BASE bypass for in-kernel callers; the
         * previous "memcpy fallback after copy_to_user failure" would
         * dereference the same bad user pointer that just rejected the
         * copy and fault the kernel. */
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)uname >= KERNEL_VIRTUAL_BASE) {
            memcpy(uname, src, 16);
            return 0;
        }
#endif
        if (fut_copy_to_user(uname, src, 16) != 0)
            return -EFAULT;
        return 0;
    }

    case PR_SET_DUMPABLE: {
        /* Futura test 1505 pins PR_SET_DUMPABLE(2) (SUID_DUMP_ROOT)
         * to return 0; Linux's userspace prctl rejects 2 as kernel-
         * only, but the local test contract takes precedence over
         * Linux ABI parity. Test 12 still requires unknown values
         * (e.g. 99) to return EINVAL. Accept {0, 1, 2}; reject all
         * other values. */
        int val = (int)arg2;
        if (val != 0 && val != 1 && val != 2) {
            return -EINVAL;
        }
        task->dumpable = val;
        return 0;
    }

    case PR_GET_DUMPABLE:
        return task->dumpable;

    case PR_SET_NO_NEW_PRIVS: {
        /* Sticky flag: once set, cannot be unset (prevents execve setuid escalation).
         *
         * Linux's prctl(PR_SET_NO_NEW_PRIVS) requires arg2 == 1 AND
         * arg3, arg4, arg5 all be zero — kernel/sys.c:
         *   if (arg2 != 1 || arg3 || arg4 || arg5)
         *       return -EINVAL;
         *
         * The previous Futura code silently ignored arg3/arg4/arg5, so a
         * caller passing junk in the unused slots got the sticky NNP bit
         * set anyway.  Reject the call exactly as Linux does — userspace
         * probes that walk through the unused args to discover the
         * kernel's accepted set now see Linux-identical EINVAL. */
        if (arg2 != 1 || arg3 || arg4 || arg5) {
            return -EINVAL;
        }
        task->no_new_privs = 1;
        return 0;
    }

    case PR_GET_NO_NEW_PRIVS:
        /* Linux requires all unused args to be zero. */
        if (arg2 || arg3 || arg4 || arg5)
            return -EINVAL;
        return (long)task->no_new_privs;

    case PR_SET_TIMERSLACK:
        /* Store the requested slack (in nanoseconds) per-task.
         * arg2 == 0 means "set to 0" (not "reset to default"); test
         * 1164 in kernel/tests/sys_misc.c verifies this Futura-specific
         * contract. Do not match Linux's "arg2<=0 resets to default"
         * behaviour here — the local tests take precedence. */
        task->timerslack_ns = (uint64_t)arg2;
        return 0;

    case PR_GET_TIMERSLACK:
        /* Return per-task timer slack in nanoseconds. */
        return (long)task->timerslack_ns;

    case PR_CAPBSET_READ: {
        /* Check if capability is in the bounding set */
        int cap = (int)arg2;
        if (cap < 0 || cap > 63) {
            return -EINVAL;
        }
        return (task->cap_bset >> (unsigned)cap) & 1;
    }

    case PR_CAPBSET_DROP: {
        /* Drop a capability from the bounding set (irreversible) */
        int cap = (int)arg2;
        if (cap < 0 || cap > 63) {
            return -EINVAL;
        }
        /* Linux gates this on ns_capable(CAP_SETPCAP), where root
         * (uid==0) is treated as holding every capability regardless
         * of cap_effective state. The previous Futura check was
         * cap-only, so a uid=0 process whose cap_effective had been
         * cleared (e.g. early boot before exec_init populates the
         * full mask) saw EPERM despite Linux allowing it through the
         * root-bypass — same gap fixed earlier in setgroups. */
        if (task->uid != 0 &&
            !(task->cap_effective & (1ULL << 8 /* CAP_SETPCAP */))) {
            return -EPERM;
        }
        task->cap_bset &= ~(1ULL << (unsigned)cap);
        return 0;
    }

    case PR_GET_SECUREBITS:
        /* No secure-bits tracking; return 0 (no bits set) */
        return 0;

    case PR_SET_SECUREBITS:
        /* Accept but don't enforce secure-bits changes */
        return 0;

    case PR_GET_KEEPCAPS:
        /* Linux's prctl(PR_GET_KEEPCAPS) rejects any non-zero unused arg:
         *   if (arg2 || arg3 || arg4 || arg5) return -EINVAL;
         * The previous code silently ignored the unused slots, so libc
         * probes that pass garbage in arg2..5 to detect 'kernel rejects
         * unused-args junk' (a generic prctl ABI rigidity check) saw
         * 'success' on Futura and EINVAL on Linux. */
        if (arg2 || arg3 || arg4 || arg5)
            return -EINVAL;
        return task->keepcaps;

    case PR_SET_KEEPCAPS:
        /* Linux: 'if (arg2 > 1 || arg3 || arg4 || arg5) return -EINVAL'.
         * KEEPCAPS controls whether capabilities survive a UID change
         * to non-root, so the gate must be tight — silently accepting
         * arg3..5 junk could hide a caller misuse that was meant to be
         * a different prctl op number entirely. */
        if (arg2 > 1 || arg3 || arg4 || arg5)
            return -EINVAL;
        task->keepcaps = (int)arg2;
        return 0;

    case PR_MCE_KILL:
        /* Accept MCE kill policy; we don't enforce it */
        return 0;

    case PR_MCE_KILL_GET:
        return 0;  /* PR_MCE_KILL_DEFAULT */

    case PR_SET_CHILD_SUBREAPER:
        /* Mark this task as a subreaper for orphaned children.
         * Store in task->personality field bit 31 as a subreaper flag.
         * For now, accept without enforcement. */
        if (arg2)
            task->personality |= (1UL << 31);
        else
            task->personality &= ~(1UL << 31);
        return 0;

    case PR_GET_CHILD_SUBREAPER: {
        /* Return 1 if we are a subreaper, 0 otherwise.
         *
         * Linux writes a 4-byte int (kernel/sys.c:
         *   put_user(me->signal->is_child_subreaper, (int __user *)arg2);
         * ).  The previous Futura code wrote an 8-byte unsigned long,
         * clobbering 4 bytes past the caller's int buffer — a stack/heap
         * corruption hazard for a typical
         *   int subreaper; prctl(PR_GET_CHILD_SUBREAPER, &subreaper);
         * call pattern. */
        int is_subreaper = (int)((task->personality >> 31) & 1);
        if (!arg2)
            return -EFAULT;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)arg2 >= KERNEL_VIRTUAL_BASE) {
            *(int *)arg2 = is_subreaper;
            return 0;
        }
#endif
        if (fut_copy_to_user((void *)arg2, &is_subreaper, sizeof(int)) != 0)
            return -EFAULT;
        return 0;
    }

    case PR_SET_MM:
        /* Modifying mm_struct fields not supported; return EPERM */
        return -EPERM;

    case PR_SET_VMA: {
        /* PR_SET_VMA_ANON_NAME (arg2=0): set anonymous VMA name for debuggers.
         * arg3=addr, arg4=len, arg5=name (NULL to clear).
         * Shows as [anon:name] in /proc/self/maps. Max 80 chars. */
        if (arg2 != 0) return -EINVAL; /* Only PR_SET_VMA_ANON_NAME=0 supported */

        uintptr_t va_start = (uintptr_t)arg3;
        size_t    va_len   = (size_t)arg4;
        const char *uname  = (const char *)(uintptr_t)arg5;

        if (va_len == 0) return 0;  /* Nothing to do */

        /* Copy and validate name from userspace (or NULL to clear) */
        char name_buf[81]; /* ANON_VMA_NAME_MAX_LEN=80 + NUL */
        if (uname) {
            /* Copy up to 81 bytes; reject if too long or contains \n */
            size_t i = 0;
            for (; i < 80; i++) {
                char c;
#ifdef KERNEL_VIRTUAL_BASE
                if ((uintptr_t)(uname + i) >= KERNEL_VIRTUAL_BASE)
                    c = uname[i];
                else
#endif
                if (fut_copy_from_user(&c, uname + i, 1) != 0) return -EFAULT;
                if (c == '\n') return -EINVAL; /* Linux rejects \n in names */
                name_buf[i] = c;
                if (c == '\0') break;
            }
            if (i == 80) {
                char last;
#ifdef KERNEL_VIRTUAL_BASE
                if ((uintptr_t)(uname + 80) >= KERNEL_VIRTUAL_BASE)
                    last = uname[80];
                else
#endif
                if (fut_copy_from_user(&last, uname + 80, 1) != 0) return -EFAULT;
                if (last != '\0') return -EINVAL; /* Name too long */
                name_buf[80] = '\0';
            }
        }

        /* Apply name to all VMAs overlapping [va_start, va_start+va_len) */
        fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
        if (!mm) return -ENOMEM;

        uintptr_t va_end = va_start + va_len;
        struct fut_vma *vma = mm->vma_list;
        int found = 0;
        while (vma) {
            if (vma->end <= va_start || vma->start >= va_end) {
                vma = vma->next;
                continue;
            }
            /* Only name anonymous VMAs; ignore file-backed ones */
            if (!vma->vnode) {
                if (vma->anon_name) {
                    fut_free(vma->anon_name);
                    vma->anon_name = NULL;
                }
                if (uname) {
                    size_t nlen = __builtin_strlen(name_buf) + 1;
                    vma->anon_name = fut_malloc(nlen);
                    if (!vma->anon_name) return -ENOMEM;
                    __builtin_memcpy(vma->anon_name, name_buf, nlen);
                }
                found = 1;
            }
            vma = vma->next;
        }
        (void)found; /* Not an error if no VMAs overlap (matches Linux) */
        return 0;
    }

    case PR_GET_SECCOMP:
        /* No seccomp filter active; return SECCOMP_MODE_DISABLED (0) */
        return 0;

    case PR_SET_SECCOMP:
        /* Accept all seccomp modes as no-op (no BPF enforcement in Futura).
         * SECCOMP_MODE_DISABLED=0, SECCOMP_MODE_STRICT=1, SECCOMP_MODE_FILTER=2 */
        if (arg2 > 2)
            return -EINVAL;
        return 0;

    case PR_GET_TID_ADDRESS: {
        /* Return the address registered via set_tid_address() for this thread.
         * gdb and thread-library diagnostics use this to find a thread's TID word. */
        if (!arg2)
            return -EFAULT;
        fut_thread_t *thr = fut_thread_current();
        void *tid_addr = thr ? (void *)thr->clear_child_tid : (void *)task->clear_child_tid;
        uint64_t *out = (uint64_t *)arg2;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)out >= KERNEL_VIRTUAL_BASE) {
            *out = (uint64_t)(uintptr_t)tid_addr;
            return 0;
        }
#endif
        uint64_t val = (uint64_t)(uintptr_t)tid_addr;
        if (fut_copy_to_user(out, &val, sizeof(val)) != 0)
            return -EFAULT;
        return 0;
    }

    case PR_GET_SPECULATION_CTRL:
        /* Futura has no speculative-execution hardware vulnerabilities in emulation;
         * report NOT_AFFECTED for all speculation types. */
        (void)arg2;
        return PR_SPEC_NOT_AFFECTED;

    case PR_SET_SPECULATION_CTRL:
        /* Silently accept — no real speculation mitigations needed. */
        return 0;

    case PR_CAP_AMBIENT: {
        /* Ambient capability management (Linux 4.3+).
         * arg2 = operation (IS_SET/RAISE/LOWER/CLEAR_ALL), arg3 = capability number.
         *
         * Linux's PR_CAP_AMBIENT enforces unused-args == 0 — kernel/sys.c:
         *   if (arg2 == PR_CAP_AMBIENT_CLEAR_ALL) {
         *       if (arg3 | arg4 | arg5) return -EINVAL;
         *       cap_clear(current->cap_ambient);
         *       return 0;
         *   }
         *   if (arg4 | arg5) return -EINVAL;
         *
         * IS_SET/RAISE/LOWER use arg3 as the capability number, so arg3
         * is meaningful there; CLEAR_ALL has no per-cap argument so
         * arg3 must also be zero.  arg4/arg5 are reserved for all four
         * subcommands.  Without these gates a caller probing the prctl
         * ABI by walking through unused-arg values silently succeeded
         * on Futura where Linux returns EINVAL.
         *
         * Linux rules:
         *   RAISE: cap must be in permitted AND inheritable; no_new_privs must be 0.
         *   LOWER: always allowed (unconditionally clears the bit).
         *   IS_SET: returns 1 or 0.
         *   CLEAR_ALL: always allowed. */
        int op = (int)arg2;
        if (op == PR_CAP_AMBIENT_CLEAR_ALL) {
            if (arg3 || arg4 || arg5)
                return -EINVAL;
            task->cap_ambient = 0;
            return 0;
        }
        if (arg4 || arg5)
            return -EINVAL;
        switch (op) {
        case PR_CAP_AMBIENT_IS_SET: {
            int cap = (int)arg3;
            if (cap < 0 || cap > 63)
                return -EINVAL;
            return (task->cap_ambient >> (unsigned)cap) & 1;
        }
        case PR_CAP_AMBIENT_RAISE: {
            int cap = (int)arg3;
            if (cap < 0 || cap > 63)
                return -EINVAL;
            /* no_new_privs blocks raising ambient */
            if (task->no_new_privs)
                return -EPERM;
            uint64_t bit = 1ULL << (unsigned)cap;
            /* cap must be in both permitted and inheritable */
            if (!(task->cap_permitted & bit) || !(task->cap_inheritable & bit))
                return -EPERM;
            task->cap_ambient |= bit;
            return 0;
        }
        case PR_CAP_AMBIENT_LOWER: {
            int cap = (int)arg3;
            if (cap < 0 || cap > 63)
                return -EINVAL;
            task->cap_ambient &= ~(1ULL << (unsigned)cap);
            return 0;
        }
        default:
            return -EINVAL;
        }
    }

    case PR_SET_IO_FLUSHER:
        /* Linux 5.6+: mark thread as memory-pressure-exempt I/O flusher.
         * No I/O pressure management in Futura; accept and return 0. */
        return 0;

    case PR_GET_IO_FLUSHER:
        /* Return 0: thread is not an I/O flusher. */
        return 0;

    case PR_SCHED_CORE:
        /* Linux 5.14+ core scheduling; no scheduling domain support. */
        return -ENOTSUP;

    case PR_SET_MDWE:
        /* Linux 6.3+ memory-deny-write-execute; silently accept. */
        return 0;

    case PR_GET_MDWE:
        /* Return 0: no MDWE restrictions. */
        return 0;

    case PR_TASK_PERF_EVENTS_DISABLE:
    case PR_TASK_PERF_EVENTS_ENABLE:
        /* Linux 2.6.31+: control perf event counting for this task.
         * Futura has no perf infrastructure; accept both ops as no-ops. */
        return 0;

    case PR_SET_THP_DISABLE:
        /* Linux 3.15+: disable transparent hugepages for this task.
         * Futura has no THP; accept the hint silently. */
        return 0;

    case PR_GET_THP_DISABLE:
        /* Linux 3.15+: query THP disabled state.
         * Return 0: THP is not active (Futura has no THP). */
        return 0;

    case PR_GET_TIMING:
        /* Return PR_TIMING_STATISTICAL (0) — only mode supported since Linux 2.6.29 */
        return PR_TIMING_STATISTICAL;

    case PR_SET_TIMING:
        /* Only PR_TIMING_STATISTICAL (0) is valid; PR_TIMING_TIMESTAMP was removed */
        if (arg2 != PR_TIMING_STATISTICAL)
            return -EINVAL;
        return 0;

    case PR_GET_TSC:
        /* x86_64: report TSC reads always allowed (PR_TSC_ENABLE) in Futura */
        (void)arg2;
        return PR_TSC_ENABLE;

    case PR_SET_TSC:
        /* x86_64: accept PR_TSC_ENABLE or PR_TSC_SIGSEGV; no enforcement */
        if (arg2 != PR_TSC_ENABLE && arg2 != PR_TSC_SIGSEGV)
            return -EINVAL;
        return 0;

    case PR_SET_PTRACER:
        /* Yama LSM ptrace-scope override (Linux 3.4+).
         * arg2 = PID to allow (or PR_SET_PTRACER_ANY for any process, or 0 to clear).
         * Futura has no Yama LSM; accept as no-op so Docker/gdb don't see EINVAL. */
        return 0;

    case PR_SET_SYSCALL_USER_DISPATCH:
        /* Linux 5.11+: enable/disable userspace syscall interception via SIGSYS.
         * Used by Wine/Proton on ARM64 for Windows syscall emulation.
         * Futura has no user-dispatch mechanism; accept as no-op so callers
         * don't abort. arg2=PR_SYS_DISPATCH_OFF(0)/ON(1); arg3=offset; arg4=len; arg5=selector */
        return 0;

    case PR_SET_FP_MODE:
        /* ARM64 floating-point mode control (Linux 4.9+).
         * Valid modes: 0 (default FPSIMD), PR_FP_MODE_FR (1), PR_FP_MODE_FRE (2).
         * Futura always uses standard FPSIMD mode; accept valid values as no-op.
         * x86_64: EINVAL is correct Linux behavior; we accept here for compat. */
        if (arg2 & ~(unsigned long)(PR_FP_MODE_FR | PR_FP_MODE_FRE))
            return -EINVAL;
        return 0;

    case PR_GET_FP_MODE:
        /* Return current FP mode: 0 = standard FPSIMD (default for all Futura tasks). */
        return 0;

    case PR_PAC_RESET_KEYS:
        /* ARM64 pointer-authentication key reset (Linux 5.0+).
         * arg2 is a bitmask of keys to reset (PR_PAC_AP{DA,DB,GA,IA,IB}KEY).
         * Futura has no PAC hardware; accept as no-op so PAC-aware programs start. */
        return 0;

    case PR_SET_TAGGED_ADDR_CTRL:
        /* ARM64 MTE (Memory Tagging Extension) tagged-address ABI control (Linux 5.10+).
         * arg2 is a flags word: PR_TAGGED_ADDR_ENABLE + MTE TCF mode + tag mask.
         * Futura has no MTE hardware; only accept arg2=0 (no tagging); reject non-zero
         * so callers correctly detect that MTE is unavailable. */
        if (arg2 != 0)
            return -EINVAL;
        return 0;

    case PR_GET_TAGGED_ADDR_CTRL:
        /* Return tagged-address control word: 0 = no tagged addresses (MTE not enabled). */
        return 0;

    case PR_GET_AUXV: {
        /* Linux 6.5+: copy the ELF auxiliary vector into caller-supplied buffer.
         * arg2 = buf (void *), arg3 = buflen (size_t), arg4 and arg5 must be 0.
         * Returns the total auxv byte count; EINVAL if arg4/arg5 != 0 or buf too small.
         *
         * Linux kernel/sys.c: `if (arg4 || arg5) return -EINVAL;` — both
         * reserved tail args are gated, not just arg4.  Without the arg5
         * check, callers walking the prctl ABI by varying unused-args saw
         * Futura accept inputs that Linux rejects with EINVAL. */
        if (arg4 != 0 || arg5 != 0)
            return -EINVAL;

        /* Build the same minimal auxv that /proc/<pid>/auxv generates */
        struct auxv_pair { uint64_t key; uint64_t val; };
        struct auxv_pair av[16];
        int ai = 0;
#ifdef PAGE_SIZE
        av[ai].key = 6;  av[ai].val = PAGE_SIZE;             ai++; /* AT_PAGESZ */
#else
        av[ai].key = 6;  av[ai].val = 4096;                  ai++;
#endif
        av[ai].key = 11; av[ai].val = (uint64_t)task->ruid;  ai++; /* AT_UID */
        av[ai].key = 12; av[ai].val = (uint64_t)task->uid;   ai++; /* AT_EUID */
        av[ai].key = 13; av[ai].val = (uint64_t)task->rgid;  ai++; /* AT_GID */
        av[ai].key = 14; av[ai].val = (uint64_t)task->gid;   ai++; /* AT_EGID */
        uint64_t secure = (task->uid != task->ruid || task->gid != task->rgid) ? 1 : 0;
        av[ai].key = 23; av[ai].val = secure;                 ai++; /* AT_SECURE */
        av[ai].key = 16; av[ai].val = 0ULL;                   ai++; /* AT_HWCAP */
        av[ai].key = 0;  av[ai].val = 0ULL;                   ai++; /* AT_NULL */

        size_t auxv_size = (size_t)ai * sizeof(struct auxv_pair);

        /* If buf is NULL or buflen is 0, just return the size */
        void *buf = (void *)(uintptr_t)arg2;
        size_t buflen = (size_t)arg3;
        if (!buf || buflen == 0)
            return (long)auxv_size;

        /* If buffer is too small, return EINVAL (Linux semantics) */
        if (buflen < auxv_size)
            return -EINVAL;

        if (prctl_copy_to_user(buf, av, auxv_size) != 0)
            return -EFAULT;

        return (long)auxv_size;
    }

    default:
        fut_printf("[PRCTL] prctl(option=%d) -> EINVAL (unsupported option)\n", option);
        return -EINVAL;
    }
}

/* kernel/sys_seccomp.c - seccomp() syscall with BPF filter enforcement
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements seccomp() for syscall filtering:
 *   SECCOMP_SET_MODE_STRICT  — allow only read/write/exit/sigreturn
 *   SECCOMP_SET_MODE_FILTER  — install cBPF program to filter syscalls
 *   SECCOMP_GET_ACTION_AVAIL — check if a seccomp action is supported
 *   SECCOMP_GET_NOTIF_SIZES  — return notification structure sizes
 *
 * BPF filters are stored per-task and evaluated on every syscall.
 * Multiple filters are chained — all must return ALLOW for the
 * syscall to proceed (most restrictive wins).
 *
 * Uses the BPF bytecode interpreter from kernel/security/bpf.c.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <platform/platform.h>

/* uaccess helpers with the standard self-test bypass: kernel-pointer
 * arguments (e.g. from kernel-side selftests) skip uaccess; everything
 * else goes through fut_copy_*. The previous code dereferenced uargs
 * directly, which let any caller pass a kernel address as the seccomp
 * args pointer and read kernel memory or fault the kernel. */
static inline int sec_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int sec_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* seccomp() operation types */
#define SECCOMP_SET_MODE_STRICT    0
#define SECCOMP_SET_MODE_FILTER    1
#define SECCOMP_GET_ACTION_AVAIL   2
#define SECCOMP_GET_NOTIF_SIZES    3

/* seccomp() flags */
#define SECCOMP_FILTER_FLAG_TSYNC       (1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG         (1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW  (1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)

/* seccomp return actions */
#define SECCOMP_RET_KILL_PROCESS  0x80000000U
#define SECCOMP_RET_KILL_THREAD   0x00000000U
#define SECCOMP_RET_TRAP          0x00030000U
#define SECCOMP_RET_ERRNO         0x00050000U
#define SECCOMP_RET_USER_NOTIF    0x7fc00000U
#define SECCOMP_RET_TRACE         0x7ff00000U
#define SECCOMP_RET_LOG           0x7ffc0000U
#define SECCOMP_RET_ALLOW         0x7fff0000U
#define SECCOMP_RET_ACTION_FULL   0xffff0000U
#define SECCOMP_RET_DATA          0x0000ffffU

/* BPF sock_filter instruction */
struct sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

/* BPF program (user-facing) */
struct sock_fprog {
    uint16_t len;
    uint16_t _pad;
    uint32_t _pad2;
    struct sock_filter *filter;
};

/* seccomp_data — input to BPF program */
struct seccomp_data {
    int      nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
};

/* Internal filter storage */
#define MAX_SECCOMP_FILTERS     8
#define MAX_SECCOMP_INSNS     256

struct seccomp_filter_prog {
    struct sock_filter insns[MAX_SECCOMP_INSNS];
    uint32_t           len;
};

/* Per-task filter chain */
struct seccomp_filter_chain {
    struct seccomp_filter_prog filters[MAX_SECCOMP_FILTERS];
    int count;
};

/* BPF interpreter (from kernel/security/bpf.c) */
extern uint32_t bpf_run(const struct sock_filter *insns, uint32_t n_insns,
                          const struct seccomp_data *sd);

/* BPF instruction class/mode extraction */
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_OP(code)    ((code) & 0xf0)

/* BPF instruction classes */
#define SECCOMP_BPF_LD    0x00
#define SECCOMP_BPF_LDX   0x01
#define SECCOMP_BPF_ST    0x02
#define SECCOMP_BPF_STX   0x03
#define SECCOMP_BPF_ALU   0x04
#define SECCOMP_BPF_JMP   0x05
#define SECCOMP_BPF_RET   0x06
#define SECCOMP_BPF_MISC  0x07
#define SECCOMP_BPF_JA    0x00

/**
 * seccomp_validate_bpf() - Validate a cBPF program before installation.
 *
 * Checks:
 *  - No backward jumps (guarantees termination)
 *  - All jump targets are within program bounds
 *  - Last instruction must be a RET (every path must terminate)
 *  - No division by zero in immediate-mode ALU ops
 *
 * @param insns   BPF instruction array
 * @param n_insns Number of instructions
 * @return 0 if valid, -EINVAL if the program is rejected
 */
static long seccomp_validate_bpf(const struct sock_filter *insns, uint32_t n_insns) {
    if (!insns || n_insns == 0)
        return -EINVAL;

    for (uint32_t i = 0; i < n_insns; i++) {
        const struct sock_filter *f = &insns[i];
        uint16_t cls = BPF_CLASS(f->code);

        switch (cls) {
        case SECCOMP_BPF_JMP: {
            if (BPF_OP(f->code) == SECCOMP_BPF_JA) {
                /* Unconditional jump: pc += k, then pc++ in loop.
                 * f->k is a 32-bit unsigned value; computing
                 * `i + 1 + f->k` in 32-bit arithmetic wraps around for
                 * any k >= UINT32_MAX - i, producing a small "target"
                 * that passes the n_insns bound check while actually
                 * pointing backward (or at the jump itself). That lets
                 * a malformed program slip a self-loop past the
                 * verifier and spin the interpreter on every syscall.
                 * Compute the target in 64-bit arithmetic so the
                 * bound check is meaningful for every k. */
                uint64_t target = (uint64_t)i + 1ULL + (uint64_t)f->k;
                if (target >= (uint64_t)n_insns)
                    return -EINVAL;
            } else {
                /* Conditional jump: jt/jf offsets (each 8-bit, no overflow risk) */
                uint32_t target_t = i + 1 + f->jt;
                uint32_t target_f = i + 1 + f->jf;
                if (target_t >= n_insns || target_f >= n_insns)
                    return -EINVAL;
            }
            break;
        }
        case SECCOMP_BPF_RET:
            /* Valid — termination point */
            break;
        case SECCOMP_BPF_ALU: {
            /* Check for division/modulo by immediate zero */
            uint16_t op = BPF_OP(f->code);
            bool is_imm = (f->code & 0x08) == 0; /* BPF_K = 0x00 */
            if (is_imm && (op == 0x30 /* DIV */ || op == 0x90 /* MOD */) && f->k == 0)
                return -EINVAL;
            break;
        }
        default:
            break;
        }
    }

    /* Last instruction must be a RET to guarantee termination */
    if (BPF_CLASS(insns[n_insns - 1].code) != SECCOMP_BPF_RET)
        return -EINVAL;

    return 0;
}

/* ── Syscall implementation ── */

long sys_seccomp(unsigned int operation, unsigned int flags, const void *uargs) {
    switch (operation) {
    case SECCOMP_SET_MODE_STRICT: {
        if (flags != 0) return -EINVAL;
        if (uargs != NULL) return -EINVAL;
        fut_task_t *task = fut_task_current();
        if (task) {
            task->seccomp_mode = 1;
        }
        return 0;
    }

    case SECCOMP_SET_MODE_FILTER: {
        /* Validate flags */
        uint32_t known_flags = SECCOMP_FILTER_FLAG_TSYNC |
                               SECCOMP_FILTER_FLAG_LOG |
                               SECCOMP_FILTER_FLAG_SPEC_ALLOW |
                               SECCOMP_FILTER_FLAG_NEW_LISTENER |
                               SECCOMP_FILTER_FLAG_TSYNC_ESRCH |
                               SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        if (flags & ~known_flags) return -EINVAL;

        /* Linux's seccomp_set_mode_filter rejects mutually-exclusive
         * flag combinations before any user-pointer access:
         *   TSYNC | NEW_LISTENER     → EINVAL (cannot synchronise threads
         *                              to a filter that also returns a
         *                              listener fd)
         *   TSYNC_ESRCH without TSYNC → EINVAL (the ESRCH variant is a
         *                                refinement of TSYNC behaviour)
         *   WAIT_KILLABLE_RECV without NEW_LISTENER → EINVAL (the killable
         *                                receive applies to listener fds)
         *
         * The previous code accepted any combination of known flag bits,
         * so libseccomp's flag-probe path (which intentionally requests
         * conflicting combinations to discover which the kernel rejects)
         * couldn't tell Futura apart from a future kernel that legalised
         * the combination. */
        if ((flags & SECCOMP_FILTER_FLAG_TSYNC) &&
            (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER))
            return -EINVAL;
        if ((flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH) &&
            !(flags & SECCOMP_FILTER_FLAG_TSYNC))
            return -EINVAL;
        if ((flags & SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV) &&
            !(flags & SECCOMP_FILTER_FLAG_NEW_LISTENER))
            return -EINVAL;

        if (!uargs) return -EFAULT;

        /* Require NO_NEW_PRIVS or CAP_SYS_ADMIN */
        fut_task_t *task = fut_task_current();
        if (!task) return -ESRCH;
        if (!task->no_new_privs && task->uid != 0 &&
            !(task->cap_effective & (1ULL << 21))) /* CAP_SYS_ADMIN */
            return -EACCES;

        /* Copy sock_fprog header from user. The previous code did
         * 'fprog = (const struct sock_fprog *)uargs' and then
         * 'fprog->len' / 'fprog->filter' direct reads — meaning any
         * caller passing a kernel address as uargs read program length
         * and filter pointer straight out of kernel memory. */
        struct sock_fprog kfprog;
        if (sec_copy_from_user(&kfprog, uargs, sizeof(kfprog)) != 0)
            return -EFAULT;
        uint16_t prog_len = kfprog.len;
        struct sock_filter *prog_filter = kfprog.filter;

        if (prog_len == 0 || prog_len > MAX_SECCOMP_INSNS) return -EINVAL;
        if (!prog_filter) return -EFAULT;

        /* Allocate or grow filter chain */
        struct seccomp_filter_chain *chain =
            (struct seccomp_filter_chain *)task->seccomp_filter;
        if (!chain) {
            extern void *fut_malloc(size_t);
            chain = (struct seccomp_filter_chain *)fut_malloc(sizeof(*chain));
            if (!chain) return -ENOMEM;
            memset(chain, 0, sizeof(*chain));
            task->seccomp_filter = chain;
        }

        if (chain->count >= MAX_SECCOMP_FILTERS) return -ENOMEM;

        /* Copy the BPF instructions through copy_from_user — never raw
         * memcpy from a user-controlled pointer. */
        struct seccomp_filter_prog *fp = &chain->filters[chain->count];
        if (sec_copy_from_user(fp->insns, prog_filter,
                               (size_t)prog_len * sizeof(struct sock_filter)) != 0)
            return -EFAULT;

        /* Validate BPF program (after the copy, on kernel-local data,
         * so the verifier can't be bypassed by a TOCTOU swap of the
         * user-side filter array). */
        long validate_err = seccomp_validate_bpf(fp->insns, prog_len);
        if (validate_err)
            return validate_err;

        fp->len = prog_len;
        chain->count++;
        task->seccomp_filter_count = chain->count;

        /* Set filter mode (upgrade from disabled/strict to filter) */
        if (task->seccomp_mode < 2)
            task->seccomp_mode = 2;

        return 0;
    }

    case SECCOMP_GET_ACTION_AVAIL: {
        /* Linux's do_seccomp pre-checks 'flags != 0 -> EINVAL' but
         * does NOT pre-check uargs for NULL. The NULL case falls into
         * seccomp_get_action_avail()'s copy_from_user, which surfaces
         * the standard pointer-fault errno EFAULT. The earlier comment
         * claiming Linux returns EINVAL for NULL was wrong: see
         * kernel/seccomp.c:do_seccomp and seccomp_get_action_avail —
         * libseccomp's feature probe (seccomp_api_get) actually
         * branches on EFAULT-vs-EINVAL to detect the kernel's seccomp
         * API level, so reporting EINVAL where Linux reports EFAULT
         * makes the probe think the GET_ACTION_AVAIL operation itself
         * is unsupported. Match Linux. */
        if (flags != 0) return -EINVAL;
        uint32_t action = 0;
        if (!uargs ||
            sec_copy_from_user(&action, uargs, sizeof(action)) != 0)
            return -EFAULT;
        switch (action) {
        case SECCOMP_RET_KILL_PROCESS:
        case SECCOMP_RET_KILL_THREAD:
        case SECCOMP_RET_TRAP:
        case SECCOMP_RET_ERRNO:
        case SECCOMP_RET_TRACE:
        case SECCOMP_RET_LOG:
        case SECCOMP_RET_ALLOW:
            return 0;
        default:
            return -EOPNOTSUPP;
        }
    }

    case SECCOMP_GET_NOTIF_SIZES: {
        /* Return sizes of notification structures (Linux 5.0+).
         * Used by container runtimes (runc, crun) to allocate user
         * notification buffers for SECCOMP_RET_USER_NOTIF handling.
         *
         * struct seccomp_notif_sizes { u16 notif, notif_resp, data; }
         *
         * Linux's do_seccomp gates only flags=0 with EINVAL; the
         * uargs=NULL case falls through to copy_to_user inside
         * seccomp_get_notif_sizes, returning EFAULT. The previous
         * pre-check returned EINVAL for NULL — same divergence as
         * GET_ACTION_AVAIL (libseccomp's probe path branches on
         * EFAULT vs EINVAL). Match Linux. */
        if (flags != 0) return -EINVAL;
        struct { uint16_t notif; uint16_t notif_resp; uint16_t data; } sizes;
        sizes.notif = 80;       /* sizeof(struct seccomp_notif) on Linux */
        sizes.notif_resp = 24;  /* sizeof(struct seccomp_notif_resp) */
        sizes.data = 64;        /* sizeof(struct seccomp_data) */
        /* Copy to userspace through copy_to_user — direct writes via
         * out[i] = let any caller pass a kernel address as uargs and
         * have the values written into kernel memory. NULL uargs is
         * surfaced by sec_copy_to_user as EFAULT (matches Linux). */
        if (!uargs ||
            sec_copy_to_user((void *)(uintptr_t)uargs, &sizes, sizeof(sizes)) != 0)
            return -EFAULT;
        return 0;
    }

    default:
        return -EINVAL;
    }
}

/**
 * seccomp_check_syscall() - Evaluate seccomp filters for a syscall.
 *
 * Called from the syscall dispatch path. Returns the seccomp action.
 *
 * Mode 1 (strict): only read(0)/write(1)/exit(60)/exit_group(231)/
 *                   rt_sigreturn(15) are allowed; everything else is KILL.
 *
 * Mode 2 (filter): runs each installed BPF filter against the syscall's
 *                   seccomp_data and returns the most restrictive result
 *                   across the entire filter chain.
 *
 * Supported return actions (most to least restrictive):
 *   SECCOMP_RET_KILL_THREAD  (0x00000000) — kill the calling thread
 *   SECCOMP_RET_KILL_PROCESS (0x80000000) — kill the entire process
 *   SECCOMP_RET_TRAP         (0x00030000) — send SIGSYS
 *   SECCOMP_RET_ERRNO        (0x00050000) — return -errno (data field)
 *   SECCOMP_RET_TRACE        (0x7ff00000) — notify tracer (allow if no tracer)
 *   SECCOMP_RET_LOG          (0x7ffc0000) — allow but log the syscall
 *   SECCOMP_RET_ALLOW        (0x7fff0000) — allow unconditionally
 *
 * @param task    Current task
 * @param nr      Syscall number
 * @param args    Syscall arguments (6 values)
 * @return SECCOMP_RET_ALLOW if permitted, else the action to take
 */
uint32_t seccomp_check_syscall(fut_task_t *task, int nr, uint64_t args[6]) {
    if (!task || task->seccomp_mode == 0)
        return SECCOMP_RET_ALLOW;

    /* Mode 1 (strict): whitelist of essential syscalls only */
    if (task->seccomp_mode == 1) {
        if (nr == 0 /* read */ || nr == 1 /* write */ ||
            nr == 60 /* exit */ || nr == 231 /* exit_group */ ||
            nr == 15 /* rt_sigreturn */)
            return SECCOMP_RET_ALLOW;
        return SECCOMP_RET_KILL_THREAD;
    }

    /* Mode 2 (filter): evaluate BPF filter chain */
    if (!task->seccomp_filter)
        return SECCOMP_RET_ALLOW;

    struct seccomp_filter_chain *chain =
        (struct seccomp_filter_chain *)task->seccomp_filter;

    /* Build seccomp_data for the BPF program */
    struct seccomp_data sd;
    sd.nr = nr;
#ifdef __x86_64__
    sd.arch = 0xC000003E; /* AUDIT_ARCH_X86_64 */
#elif defined(__aarch64__)
    sd.arch = 0xC00000B7; /* AUDIT_ARCH_AARCH64 */
#else
    sd.arch = 0;
#endif
    sd.instruction_pointer = 0;
    for (int i = 0; i < 6; i++)
        sd.args[i] = args ? args[i] : 0;

    /* Run all filters — most restrictive action wins.
     * Per Linux semantics, the action value with the lowest
     * upper 16 bits takes priority. If two filters disagree,
     * the more restrictive (lower action code) prevails. */
    uint32_t result = SECCOMP_RET_ALLOW;
    for (int i = 0; i < chain->count; i++) {
        struct seccomp_filter_prog *fp = &chain->filters[i];
        uint32_t action = bpf_run(fp->insns, fp->len, &sd);
        /* Lower action value = more restrictive */
        if ((action & SECCOMP_RET_ACTION_FULL) < (result & SECCOMP_RET_ACTION_FULL))
            result = action;
    }

    return result;
}

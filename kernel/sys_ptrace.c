/* kernel/sys_ptrace.c - ptrace() process tracing implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements Linux-compatible ptrace for process debugging and tracing.
 * Supports: TRACEME, ATTACH, DETACH, PEEKDATA, POKEDATA, GETREGS, SETREGS,
 * CONT, SYSCALL, SINGLESTEP, GETEVENTMSG, SETOPTIONS, KILL.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_mm.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __x86_64__
#include <platform/x86_64/regs.h>
#include <platform/x86_64/memory/paging.h>
#include <platform/x86_64/memory/pmap.h>
#elif defined(__aarch64__)
#include <platform/arm64/regs.h>
#include <platform/arm64/memory/paging.h>
#include <platform/arm64/memory/pmap.h>
#endif

/* Forward declarations */
extern int fut_signal_send(fut_task_t *, int);

/* ── ptrace request codes (Linux ABI) ── */
#define PTRACE_TRACEME       0
#define PTRACE_PEEKTEXT      1
#define PTRACE_PEEKDATA      2
#define PTRACE_POKETEXT      4
#define PTRACE_POKEDATA      5
#define PTRACE_CONT          7
#define PTRACE_KILL          8
#define PTRACE_SINGLESTEP    9
#define PTRACE_GETREGS      12
#define PTRACE_SETREGS      13
#define PTRACE_GETFPREGS    14
#define PTRACE_SETFPREGS    15
#define PTRACE_ATTACH       16
#define PTRACE_DETACH       17
#define PTRACE_SYSCALL      24
#define PTRACE_SETOPTIONS   0x4200
#define PTRACE_GETEVENTMSG  0x4201
#define PTRACE_GETSIGINFO   0x4202
#define PTRACE_SETSIGINFO   0x4203
#define PTRACE_GETREGSET    0x4204
#define PTRACE_SETREGSET    0x4205
#define PTRACE_SEIZE        0x4206
#define PTRACE_INTERRUPT     0x4207
#define PTRACE_LISTEN       0x4208
#define PTRACE_PEEKUSR       3
#define PTRACE_POKEUSR       6

/* ptrace options (PTRACE_SETOPTIONS) */
#define PTRACE_O_TRACESYSGOOD  0x01
#define PTRACE_O_TRACEFORK     0x02
#define PTRACE_O_TRACEVFORK    0x04
#define PTRACE_O_TRACECLONE    0x08
#define PTRACE_O_TRACEEXEC     0x10
#define PTRACE_O_TRACEEXIT     0x20
#define PTRACE_O_TRACESECCOMP  0x80
#define PTRACE_O_EXITKILL      0x100000
#define PTRACE_O_SUSPEND_SECCOMP 0x200000
#define PTRACE_O_MASK          0x3000ff

/* Per-task ptrace state — stored in task fields:
 *   ptrace_tracer:  PID of tracer (0 = not being traced)
 *   ptrace_options: PTRACE_O_* bitmask set by PTRACE_SETOPTIONS
 *   ptrace_eventmsg: event message for PTRACE_GETEVENTMSG
 *   ptrace_flags:   internal flags (PTRACE_FL_*)
 */
#define PTRACE_FL_TRACEME    0x01  /* Child called TRACEME */
#define PTRACE_FL_SEIZED     0x02  /* Attached via SEIZE (not ATTACH) */
#define PTRACE_FL_SYSCALL    0x04  /* Stop at next syscall entry/exit */

/* Linux x86_64 user_regs_struct layout (for PTRACE_GETREGS/SETREGS) */
#ifdef __x86_64__
struct user_regs_struct {
    uint64_t r15, r14, r13, r12;
    uint64_t rbp, rbx;
    uint64_t r11, r10, r9, r8;
    uint64_t rax, rcx, rdx, rsi, rdi;
    uint64_t orig_rax;
    uint64_t rip, cs, eflags;
    uint64_t rsp, ss;
    uint64_t fs_base, gs_base;
    uint64_t ds, es, fs, gs;
};
#endif

/* ── Helper: validate tracee relationship ── */
static fut_task_t *ptrace_get_tracee(int pid, fut_task_t *tracer) {
    fut_task_t *tracee = fut_task_by_pid((uint64_t)pid);
    if (!tracee)
        return NULL;

    /* Must be our tracee */
    if (tracee->ptrace_tracer != tracer->pid)
        return NULL;

    return tracee;
}

/* ── Helper: read a word from another process's address space ── */
static long ptrace_peek(fut_task_t *tracee, uintptr_t addr) {
    fut_mm_t *mm = fut_task_get_mm(tracee);
    if (!mm)
        return -EIO;

    fut_vmem_context_t *ctx = fut_mm_context(mm);
    if (!ctx)
        return -EIO;

    /* Probe the page table to get the physical address */
    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, addr & ~(uintptr_t)7, &pte) != 0)
        return -EIO;

    if (!(pte & PTE_PRESENT))
        return -EIO;

    phys_addr_t phys = pte & PTE_PHYS_ADDR_MASK;
    uintptr_t page_offset = addr & (PAGE_SIZE - 1);

    /* Map physical to kernel virtual and read */
    void *kvirt = (void *)pmap_phys_to_virt(phys);
    if (!kvirt)
        return -EIO;

    uint64_t value;
    memcpy(&value, (char *)kvirt + page_offset, sizeof(value));
    return (long)value;
}

/* ── Helper: write a word to another process's address space ── */
static int ptrace_poke(fut_task_t *tracee, uintptr_t addr, uint64_t value) {
    fut_mm_t *mm = fut_task_get_mm(tracee);
    if (!mm)
        return -EIO;

    fut_vmem_context_t *ctx = fut_mm_context(mm);
    if (!ctx)
        return -EIO;

    uint64_t pte = 0;
    if (pmap_probe_pte(ctx, addr & ~(uintptr_t)7, &pte) != 0)
        return -EIO;

    if (!(pte & PTE_PRESENT))
        return -EIO;

    phys_addr_t phys = pte & PTE_PHYS_ADDR_MASK;
    uintptr_t page_offset = addr & (PAGE_SIZE - 1);

    void *kvirt = (void *)pmap_phys_to_virt(phys);
    if (!kvirt)
        return -EIO;

    memcpy((char *)kvirt + page_offset, &value, sizeof(value));
    return 0;
}

#ifdef __x86_64__
/* ── Helper: fill user_regs_struct from tracee's saved context ── */
static int ptrace_getregs(fut_task_t *tracee, struct user_regs_struct *regs) {
    if (!tracee->threads)
        return -ESRCH;

    fut_cpu_context_t *ctx = &tracee->threads->context;

    memset(regs, 0, sizeof(*regs));
    regs->r15 = ctx->r15;
    regs->r14 = ctx->r14;
    regs->r13 = ctx->r13;
    regs->r12 = ctx->r12;
    regs->rbp = ctx->rbp;
    regs->rbx = ctx->rbx;
    regs->rax = ctx->rax;
    regs->rcx = ctx->rcx;
    regs->rdx = ctx->rdx;
    regs->rsi = ctx->rsi;
    regs->rdi = ctx->rdi;
    regs->orig_rax = ctx->rax;  /* Best approximation */
    regs->rip = ctx->rip;
    regs->cs = ctx->cs;
    regs->eflags = ctx->rflags;
    regs->rsp = ctx->rsp;
    regs->ss = ctx->ss;
    regs->ds = ctx->ds;
    regs->es = ctx->es;
    regs->fs = ctx->fs;
    regs->gs = ctx->gs;

    return 0;
}

/* ── Helper: restore user_regs_struct into tracee's saved context ── */
static int ptrace_setregs(fut_task_t *tracee, const struct user_regs_struct *regs) {
    if (!tracee->threads)
        return -ESRCH;

    fut_cpu_context_t *ctx = &tracee->threads->context;

    ctx->r15 = regs->r15;
    ctx->r14 = regs->r14;
    ctx->r13 = regs->r13;
    ctx->r12 = regs->r12;
    ctx->rbp = regs->rbp;
    ctx->rbx = regs->rbx;
    ctx->rax = regs->rax;
    ctx->rcx = regs->rcx;
    ctx->rdx = regs->rdx;
    ctx->rsi = regs->rsi;
    ctx->rdi = regs->rdi;
    ctx->rip = regs->rip;
    ctx->rflags = regs->eflags;
    ctx->rsp = regs->rsp;

    return 0;
}
#endif

/* ── Main ptrace syscall ── */
long sys_ptrace(int request, int pid, void *addr, void *data) {
    fut_task_t *current = fut_task_current();
    if (!current)
        return -ESRCH;

    switch (request) {

    /* ── PTRACE_TRACEME: child requests to be traced by parent ── */
    case PTRACE_TRACEME: {
        if (current->ptrace_tracer != 0)
            return -EPERM;  /* Already being traced */
        if (!current->parent)
            return -EPERM;

        current->ptrace_tracer = current->parent->pid;
        current->ptrace_flags |= PTRACE_FL_TRACEME;
        return 0;
    }

    /* ── PTRACE_ATTACH: attach to a running process ── */
    case PTRACE_ATTACH: {
        fut_task_t *tracee = fut_task_by_pid((uint64_t)pid);
        if (!tracee)
            return -ESRCH;
        if (tracee == current)
            return -EPERM;  /* Can't trace self */
        if (tracee->ptrace_tracer != 0)
            return -EPERM;  /* Already being traced */

        /* Permission check: must be same UID or root */
        if (current->uid != 0 && current->uid != tracee->uid)
            return -EPERM;

        /* Check no_new_privs and dumpable */
        if (tracee->no_new_privs && current->uid != 0)
            return -EPERM;

        tracee->ptrace_tracer = current->pid;
        tracee->ptrace_flags = 0;

        /* Send SIGSTOP to the tracee (Linux behavior) */
        fut_signal_send(tracee, 19 /* SIGSTOP */);

        return 0;
    }

    /* ── PTRACE_SEIZE: attach without stopping ── */
    case PTRACE_SEIZE: {
        fut_task_t *tracee = fut_task_by_pid((uint64_t)pid);
        if (!tracee)
            return -ESRCH;
        if (tracee == current)
            return -EPERM;
        if (tracee->ptrace_tracer != 0)
            return -EPERM;
        if (current->uid != 0 && current->uid != tracee->uid)
            return -EPERM;

        tracee->ptrace_tracer = current->pid;
        tracee->ptrace_flags = PTRACE_FL_SEIZED;

        /* SEIZE does NOT send SIGSTOP (unlike ATTACH) */
        return 0;
    }

    /* ── PTRACE_DETACH: detach from tracee and let it continue ── */
    case PTRACE_DETACH: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        tracee->ptrace_tracer = 0;
        tracee->ptrace_flags = 0;
        tracee->ptrace_options = 0;
        tracee->ptrace_eventmsg = 0;

        /* Resume tracee if it was stopped */
        if (tracee->state == FUT_TASK_STOPPED) {
            tracee->state = FUT_TASK_RUNNING;
            /* Deliver signal if one was specified */
            int sig = (int)(uintptr_t)data;
            if (sig > 0 && sig < 32) {
                extern int fut_signal_send(fut_task_t *, int);
                fut_signal_send(tracee, sig);
            }
        }

        return 0;
    }

    /* ── PTRACE_PEEKTEXT/PEEKDATA: read word from tracee's memory ── */
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        long value = ptrace_peek(tracee, (uintptr_t)addr);
        /* Linux returns the value directly (or -EIO on error) */
        return value;
    }

    /* ── PTRACE_POKETEXT/POKEDATA: write word to tracee's memory ── */
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        return ptrace_poke(tracee, (uintptr_t)addr, (uint64_t)(uintptr_t)data);
    }

    /* ── PTRACE_PEEKUSR: read from USER area (register offset) ── */
    case PTRACE_PEEKUSR: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

#ifdef __x86_64__
        struct user_regs_struct regs;
        if (ptrace_getregs(tracee, &regs) != 0)
            return -EIO;

        uintptr_t offset = (uintptr_t)addr;
        if (offset >= sizeof(struct user_regs_struct))
            return -EIO;

        /* Return the value at the given byte offset in the regs struct */
        uint64_t value;
        memcpy(&value, (char *)&regs + offset, sizeof(value));
        return (long)value;
#else
        return -EIO;
#endif
    }

    /* ── PTRACE_POKEUSR: write to USER area (register offset) ── */
    case PTRACE_POKEUSR: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        /* Not commonly needed; return EIO for now */
        (void)addr; (void)data;
        return -EIO;
    }

    /* ── PTRACE_GETREGS: get all general-purpose registers ── */
    case PTRACE_GETREGS: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        if (!data)
            return -EFAULT;

#ifdef __x86_64__
        struct user_regs_struct regs;
        int rc = ptrace_getregs(tracee, &regs);
        if (rc != 0)
            return rc;
        memcpy(data, &regs, sizeof(regs));
        return 0;
#else
        /* ARM64: GETREGS not supported (use GETREGSET with NT_PRSTATUS instead) */
        return -EIO;
#endif
    }

    /* ── PTRACE_SETREGS: set all general-purpose registers ── */
    case PTRACE_SETREGS: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        if (!data)
            return -EFAULT;

#ifdef __x86_64__
        struct user_regs_struct regs;
        memcpy(&regs, data, sizeof(regs));
        return ptrace_setregs(tracee, &regs);
#else
        return -EIO;
#endif
    }

    /* ── PTRACE_GETFPREGS/SETFPREGS: FPU register access ── */
    case PTRACE_GETFPREGS: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee || !data)
            return -ESRCH;

#ifdef __x86_64__
        /* Copy FXSAVE area from tracee's context */
        if (!tracee->threads)
            return -ESRCH;
        memcpy(data, tracee->threads->context.fx_area, 512);
        return 0;
#else
        return -EIO;
#endif
    }

    case PTRACE_SETFPREGS: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee || !data)
            return -ESRCH;

#ifdef __x86_64__
        if (!tracee->threads)
            return -ESRCH;
        memcpy(tracee->threads->context.fx_area, data, 512);
        return 0;
#else
        return -EIO;
#endif
    }

    /* ── PTRACE_CONT: continue execution of stopped tracee ── */
    case PTRACE_CONT: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        tracee->ptrace_flags &= ~PTRACE_FL_SYSCALL;

        if (tracee->state == FUT_TASK_STOPPED) {
            tracee->state = FUT_TASK_RUNNING;
        }

        /* Deliver signal if specified */
        int sig = (int)(uintptr_t)data;
        if (sig > 0 && sig < 32) {
            fut_signal_send(tracee, sig);
        }

        return 0;
    }

    /* ── PTRACE_SYSCALL: continue but stop at next syscall entry/exit ── */
    case PTRACE_SYSCALL: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        tracee->ptrace_flags |= PTRACE_FL_SYSCALL;

        if (tracee->state == FUT_TASK_STOPPED) {
            tracee->state = FUT_TASK_RUNNING;
        }

        int sig = (int)(uintptr_t)data;
        if (sig > 0 && sig < 32) {
            fut_signal_send(tracee, sig);
        }

        return 0;
    }

    /* ── PTRACE_SINGLESTEP: execute one instruction then stop ── */
    case PTRACE_SINGLESTEP: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        /* x86_64: set TF (trap flag) in EFLAGS to trigger debug exception
         * after one instruction. For now, just resume — real single-step
         * requires debug exception handler integration. */
        if (tracee->state == FUT_TASK_STOPPED) {
            tracee->state = FUT_TASK_RUNNING;
        }

        int sig = (int)(uintptr_t)data;
        if (sig > 0 && sig < 32) {
            fut_signal_send(tracee, sig);
        }

        return 0;
    }

    /* ── PTRACE_KILL: send SIGKILL to tracee ── */
    case PTRACE_KILL: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        fut_signal_send(tracee, 9 /* SIGKILL */);

        if (tracee->state == FUT_TASK_STOPPED) {
            tracee->state = FUT_TASK_RUNNING;
        }

        return 0;
    }

    /* ── PTRACE_SETOPTIONS: set ptrace options ── */
    case PTRACE_SETOPTIONS: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        uint64_t opts = (uint64_t)(uintptr_t)data;
        if (opts & ~(uint64_t)PTRACE_O_MASK)
            return -EINVAL;

        tracee->ptrace_options = (uint32_t)opts;
        return 0;
    }

    /* ── PTRACE_GETEVENTMSG: get event message from last ptrace event ── */
    case PTRACE_GETEVENTMSG: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        if (!data)
            return -EFAULT;

        *(uint64_t *)data = tracee->ptrace_eventmsg;
        return 0;
    }

    /* ── PTRACE_GETSIGINFO: get siginfo for current signal ── */
    case PTRACE_GETSIGINFO: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        if (!data)
            return -EFAULT;

        /* Return a minimal siginfo */
        memset(data, 0, 128);  /* sizeof(siginfo_t) = 128 on Linux */
        return 0;
    }

    /* ── PTRACE_SETSIGINFO: set siginfo for current signal ── */
    case PTRACE_SETSIGINFO: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        /* Accept and ignore — the signal info is consumed on delivery */
        return 0;
    }

    /* ── PTRACE_GETREGSET/SETREGSET: register set access (iovec-based) ── */
    case PTRACE_GETREGSET:
    case PTRACE_SETREGSET: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;

        /* NT_PRSTATUS (1) = general regs, NT_PRFPREG (2) = FP regs */
        uint64_t regset_type __attribute__((unused)) = (uint64_t)(uintptr_t)addr;

        if (!data)
            return -EFAULT;

        /* iovec: { void *base; size_t len; } */
        struct { void *base; uint64_t len; } *iov = data;
        if (!iov->base || iov->len == 0)
            return -EFAULT;

#ifdef __x86_64__
        if (regset_type == 1 /* NT_PRSTATUS */) {
            struct user_regs_struct regs;
            if (request == PTRACE_GETREGSET) {
                if (ptrace_getregs(tracee, &regs) != 0)
                    return -EIO;
                uint64_t copy_len = iov->len < sizeof(regs) ? iov->len : sizeof(regs);
                memcpy(iov->base, &regs, copy_len);
                iov->len = copy_len;
                return 0;
            } else {
                uint64_t copy_len = iov->len < sizeof(regs) ? iov->len : sizeof(regs);
                memset(&regs, 0, sizeof(regs));
                memcpy(&regs, iov->base, copy_len);
                return ptrace_setregs(tracee, &regs);
            }
        }
#elif defined(__aarch64__)
        if (regset_type == 1 /* NT_PRSTATUS */) {
            /* ARM64 user_pt_regs: x0-x30, sp, pc, pstate = 34 uint64_t */
            if (!tracee->threads) return -ESRCH;
            fut_cpu_context_t *ctx = &tracee->threads->context;
            uint64_t pt_regs[34];
            if (request == PTRACE_GETREGSET) {
                /* Fill x0-x28 */
                pt_regs[0] = ctx->x0; pt_regs[1] = ctx->x1;
                pt_regs[2] = ctx->x2; pt_regs[3] = ctx->x3;
                pt_regs[4] = ctx->x4; pt_regs[5] = ctx->x5;
                pt_regs[6] = ctx->x6; pt_regs[7] = ctx->x7;
                pt_regs[8] = ctx->x8; pt_regs[9] = ctx->x9;
                pt_regs[10] = ctx->x10; pt_regs[11] = ctx->x11;
                pt_regs[12] = ctx->x12; pt_regs[13] = ctx->x13;
                pt_regs[14] = ctx->x14; pt_regs[15] = ctx->x15;
                pt_regs[16] = ctx->x16; pt_regs[17] = ctx->x17;
                pt_regs[18] = ctx->x18; pt_regs[19] = ctx->x19;
                pt_regs[20] = ctx->x20; pt_regs[21] = ctx->x21;
                pt_regs[22] = ctx->x22; pt_regs[23] = ctx->x23;
                pt_regs[24] = ctx->x24; pt_regs[25] = ctx->x25;
                pt_regs[26] = ctx->x26; pt_regs[27] = ctx->x27;
                pt_regs[28] = ctx->x28;
                pt_regs[29] = ctx->x29_fp; pt_regs[30] = ctx->x30_lr;
                pt_regs[31] = ctx->sp_el0;  /* sp */
                pt_regs[32] = ctx->pc;
                pt_regs[33] = ctx->pstate;
                uint64_t copy_len = iov->len < sizeof(pt_regs) ? iov->len : sizeof(pt_regs);
                memcpy(iov->base, pt_regs, copy_len);
                iov->len = copy_len;
                return 0;
            } else {
                /* SETREGSET: write registers back */
                uint64_t copy_len = iov->len < sizeof(pt_regs) ? iov->len : sizeof(pt_regs);
                memset(pt_regs, 0, sizeof(pt_regs));
                memcpy(pt_regs, iov->base, copy_len);
                ctx->x0 = pt_regs[0]; ctx->x1 = pt_regs[1];
                ctx->x19 = pt_regs[19]; ctx->x20 = pt_regs[20];
                ctx->x21 = pt_regs[21]; ctx->x22 = pt_regs[22];
                ctx->x23 = pt_regs[23]; ctx->x24 = pt_regs[24];
                ctx->x25 = pt_regs[25]; ctx->x26 = pt_regs[26];
                ctx->x27 = pt_regs[27]; ctx->x28 = pt_regs[28];
                ctx->x29_fp = pt_regs[29]; ctx->x30_lr = pt_regs[30];
                ctx->sp_el0 = pt_regs[31];
                ctx->pc = pt_regs[32];
                return 0;
            }
        }
#endif
        return -EINVAL;
    }

    /* ── PTRACE_INTERRUPT: interrupt a SEIZE'd tracee ── */
    case PTRACE_INTERRUPT: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        if (!(tracee->ptrace_flags & PTRACE_FL_SEIZED))
            return -EIO;

        /* Send SIGSTOP to interrupt the tracee */
        fut_signal_send(tracee, 19 /* SIGSTOP */);
        return 0;
    }

    /* ── PTRACE_LISTEN: let stopped tracee listen for group-stop ── */
    case PTRACE_LISTEN: {
        fut_task_t *tracee = ptrace_get_tracee(pid, current);
        if (!tracee)
            return -ESRCH;
        /* Accept — used for group-stop management, minimal impact */
        return 0;
    }

    default:
        return -EIO;  /* Unknown request */
    }
}

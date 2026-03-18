/* kernel/sys_semaphore.c - SysV semaphore set implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements semget(), semop(), semctl() for POSIX/Linux SysV IPC compatibility.
 * Supports up to SEMMNI semaphore sets, each with up to SEMMSL semaphores.
 *
 * Phase 3 (Completed): semget/semop/semctl with GETVAL/SETVAL/GETALL/SETALL/
 *                      GETNCNT/GETZCNT/GETPID/IPC_STAT/IPC_SET/IPC_RMID.
 *                      semop: non-blocking + EAGAIN for blocking operations.
 * Phase 4 (Completed): semtimedop — timed variant of semop (Linux 2.5.52+).
 */

#include <kernel/fut_task.h>
#include <kernel/fut_timer.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <shared/fut_timespec.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* ============================================================
 *   IPC Constants
 * ============================================================ */

#define IPC_PRIVATE  0L
#define IPC_CREAT    0x0200
#define IPC_EXCL     0x0400
#define IPC_RMID     0
#define IPC_SET      1
#define IPC_STAT     2

/* semctl commands */
#define SEM_GETPID   11
#define SEM_GETVAL   12
#define SEM_GETALL   13
#define SEM_GETNCNT  14
#define SEM_GETZCNT  15
#define SEM_SETVAL   16
#define SEM_SETALL   17

/* semop flags */
#define IPC_NOWAIT   0x0800
#define SEM_UNDO     0x1000

/* limits */
#define SEMMNI  64      /* max semaphore sets */
#define SEMMSL  64      /* max semaphores per set */
#define SEMVMX  32767   /* max semaphore value */
#define SEM_E2BIG_NSOPS 512  /* max ops per semop call (Linux uses SEMOPM=500) */

/* ============================================================
 *   Data Structures
 * ============================================================ */

struct sem_entry {
    int semval;   /* current value (0..SEMVMX) */
    int sempid;   /* pid of last operation */
};

struct sem_set {
    int           used;
    long          key;
    int           id;
    int           nsems;
    unsigned int  mode;
    struct sem_entry sems[SEMMSL];
};

/* struct sembuf: operation descriptor passed by user */
struct sem_sembuf {
    unsigned short sem_num;
    short          sem_op;
    short          sem_flg;
};

/* struct semid_ds: returned by IPC_STAT (simplified, matches Linux layout) */
struct sem_ipc_perm {
    int           key;
    unsigned int  uid, gid, cuid, cgid;
    unsigned int  mode;
    unsigned short seq;
    unsigned short pad;
};

struct sem_semid_ds {
    struct sem_ipc_perm sem_perm;
    unsigned long       sem_otime;
    unsigned long       sem_ctime;
    unsigned long       sem_nsems;
};

/* ============================================================
 *   Globals
 * ============================================================ */

static struct sem_set semtable[SEMMNI];
static int sem_next_id = 1;

/* ============================================================
 *   Kernel-pointer bypass helpers
 * ============================================================ */

static inline int sem_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int sem_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_to_user(dst, src, n);
}

/* ============================================================
 *   Internal helpers
 * ============================================================ */

static struct sem_set *semtable_find_by_id(int semid) {
    for (int i = 0; i < SEMMNI; i++) {
        if (semtable[i].used && semtable[i].id == semid)
            return &semtable[i];
    }
    return NULL;
}

static struct sem_set *semtable_find_by_key(long key) {
    for (int i = 0; i < SEMMNI; i++) {
        if (semtable[i].used && semtable[i].key == key)
            return &semtable[i];
    }
    return NULL;
}

/* ============================================================
 *   semget(2) - get/create a semaphore set
 * ============================================================ */

/**
 * semget - Get or create a SysV semaphore set.
 *
 * @param key     IPC key (IPC_PRIVATE or user-chosen)
 * @param nsems   Number of semaphores (1..SEMMSL); ignored when looking up existing
 * @param semflg  Flags (IPC_CREAT, IPC_EXCL, permissions)
 * @return semaphore set ID on success, -errno on error
 */
long sys_semget(long key, int nsems, int semflg) {
    /* Key-based lookup */
    if (key != IPC_PRIVATE) {
        struct sem_set *s = semtable_find_by_key(key);
        if (s) {
            /* Already exists */
            if ((semflg & IPC_CREAT) && (semflg & IPC_EXCL))
                return -EEXIST;
            /* nsems=0 means "don't check size", positive means must not exceed */
            if (nsems > 0 && nsems > s->nsems)
                return -EINVAL;
            return s->id;
        }
        /* Key not found: must have IPC_CREAT */
        if (!(semflg & IPC_CREAT))
            return -ENOENT;
    }

    /* Create new set */
    if (nsems <= 0 || nsems > SEMMSL)
        return -EINVAL;

    for (int i = 0; i < SEMMNI; i++) {
        if (!semtable[i].used) {
            semtable[i].used  = 1;
            semtable[i].key   = key;
            semtable[i].id    = sem_next_id++;
            semtable[i].nsems = nsems;
            semtable[i].mode  = (unsigned int)(semflg & 0777);
            __builtin_memset(semtable[i].sems, 0,
                             (size_t)nsems * sizeof(struct sem_entry));
            return semtable[i].id;
        }
    }
    return -ENOSPC;
}

/* ============================================================
 *   semop(2) - perform operations on semaphores
 * ============================================================ */

/**
 * semop - Atomically perform operations on a semaphore set.
 *
 * For non-blocking operations (IPC_NOWAIT or sem_op > 0 or resulting val >= 0):
 *   applies all ops atomically.
 * For operations that would block: returns -EAGAIN.
 *
 * @param semid  Semaphore set ID
 * @param sops   Array of struct sembuf operations
 * @param nsops  Number of operations
 * @return 0 on success, -errno on error
 */
long sys_semop(int semid, void *sops, unsigned int nsops) {
    if (!sops)
        return -EFAULT;
    if (nsops == 0)
        return -EINVAL;
    if (nsops > SEM_E2BIG_NSOPS)
        return -E2BIG;

    struct sem_set *s = semtable_find_by_id(semid);
    if (!s)
        return -EINVAL;

    /* Copy operations from user */
    struct sem_sembuf ops[SEM_E2BIG_NSOPS > SEMMSL ? SEMMSL : SEM_E2BIG_NSOPS];
    unsigned int copy_n = nsops < (unsigned int)SEMMSL ? nsops : (unsigned int)SEMMSL;
    if (sem_copy_from_user(ops, sops, copy_n * sizeof(struct sem_sembuf)) != 0)
        return -EFAULT;

    /* Validate semaphore indices */
    for (unsigned int i = 0; i < copy_n; i++) {
        if (ops[i].sem_num >= (unsigned short)s->nsems)
            return -E2BIG;
    }

    /* Check whether all operations can proceed without blocking */
    for (unsigned int i = 0; i < copy_n; i++) {
        int cur = s->sems[ops[i].sem_num].semval;
        int op  = ops[i].sem_op;
        if (op > 0) {
            /* Increment: always succeeds unless overflow */
            if (cur + op > SEMVMX)
                return -ERANGE;
        } else if (op < 0) {
            /* Decrement: blocks if result would be negative */
            if (cur + op < 0) {
                return (ops[i].sem_flg & IPC_NOWAIT) ? -EAGAIN : -EAGAIN;
            }
        } else {
            /* sem_op == 0: wait for value to be zero */
            if (cur != 0) {
                return (ops[i].sem_flg & IPC_NOWAIT) ? -EAGAIN : -EAGAIN;
            }
        }
    }

    /* All operations can proceed — apply atomically */
    extern fut_task_t *fut_task_current(void);
    fut_task_t *task = fut_task_current();
    int pid = task ? (int)task->pid : 1;

    for (unsigned int i = 0; i < copy_n; i++) {
        s->sems[ops[i].sem_num].semval += ops[i].sem_op;
        s->sems[ops[i].sem_num].sempid  = pid;
    }

    return 0;
}

/* ============================================================
 *   semctl(2) - control operations on semaphore sets
 * ============================================================ */

/**
 * semctl - Control a semaphore set.
 *
 * @param semid   Semaphore set ID
 * @param semnum  Semaphore index within set (for GETVAL/SETVAL/GETPID/GETNCNT/GETZCNT)
 * @param cmd     Command (IPC_RMID, IPC_STAT, GETVAL, SETVAL, GETALL, SETALL, ...)
 * @param arg     Fourth argument: value for SETVAL, pointer for GETALL/SETALL/IPC_STAT
 * @return Value (GETVAL/GETPID/GETNCNT/GETZCNT) or 0 on success, -errno on error
 */
long sys_semctl(int semid, int semnum, int cmd, unsigned long arg) {
    /* IPC_RMID doesn't require semid to have a particular semnum */
    if (cmd == IPC_RMID) {
        struct sem_set *s = semtable_find_by_id(semid);
        if (!s)
            return -EINVAL;
        s->used = 0;
        return 0;
    }

    struct sem_set *s = semtable_find_by_id(semid);
    if (!s)
        return -EINVAL;

    switch (cmd) {
    case SEM_GETVAL:
        if (semnum < 0 || semnum >= s->nsems)
            return -EINVAL;
        return (long)s->sems[semnum].semval;

    case SEM_SETVAL:
        if (semnum < 0 || semnum >= s->nsems)
            return -EINVAL;
        if ((int)arg < 0 || (int)arg > SEMVMX)
            return -ERANGE;
        s->sems[semnum].semval = (int)arg;
        return 0;

    case SEM_GETPID:
        if (semnum < 0 || semnum >= s->nsems)
            return -EINVAL;
        return (long)s->sems[semnum].sempid;

    case SEM_GETNCNT:
    case SEM_GETZCNT:
        /* Simplified: no blocked-process accounting */
        if (semnum < 0 || semnum >= s->nsems)
            return -EINVAL;
        return 0;

    case SEM_GETALL: {
        if (!arg)
            return -EFAULT;
        unsigned short vals[SEMMSL];
        for (int i = 0; i < s->nsems; i++)
            vals[i] = (unsigned short)s->sems[i].semval;
        if (sem_copy_to_user((void *)(uintptr_t)arg, vals,
                             (size_t)s->nsems * sizeof(unsigned short)) != 0)
            return -EFAULT;
        return 0;
    }

    case SEM_SETALL: {
        if (!arg)
            return -EFAULT;
        unsigned short vals[SEMMSL];
        if (sem_copy_from_user(vals, (const void *)(uintptr_t)arg,
                               (size_t)s->nsems * sizeof(unsigned short)) != 0)
            return -EFAULT;
        for (int i = 0; i < s->nsems; i++) {
            if (vals[i] > SEMVMX)
                return -ERANGE;
            s->sems[i].semval = (int)vals[i];
        }
        return 0;
    }

    case IPC_STAT: {
        if (!arg)
            return -EFAULT;
        struct sem_semid_ds ds;
        __builtin_memset(&ds, 0, sizeof(ds));
        ds.sem_perm.key  = (int)s->key;
        ds.sem_perm.mode = s->mode;
        ds.sem_nsems     = (unsigned long)s->nsems;
        if (sem_copy_to_user((void *)(uintptr_t)arg, &ds, sizeof(ds)) != 0)
            return -EFAULT;
        return 0;
    }

    case IPC_SET: {
        /* Only updates mode (permissions) */
        if (!arg)
            return -EFAULT;
        struct sem_semid_ds ds;
        if (sem_copy_from_user(&ds, (const void *)(uintptr_t)arg, sizeof(ds)) != 0)
            return -EFAULT;
        s->mode = ds.sem_perm.mode & 0777;
        return 0;
    }

    default:
        return -EINVAL;
    }
}

/* ============================================================
 *   semtimedop(2) - semop with timeout (Linux 2.5.52+, syscall 220)
 * ============================================================ */

/**
 * semtimedop - Atomically perform operations on a semaphore set with timeout.
 *
 * Like semop(), but if the operation would block, waits at most @timeout
 * before returning -EAGAIN (POSIX: -ETIMEDOUT). If @timeout is NULL, behaves
 * like semop() without IPC_NOWAIT (blocks indefinitely — Futura returns EAGAIN
 * since true blocking semop is not yet implemented). If @timeout is {0,0},
 * returns EAGAIN immediately if the operation would block (same as IPC_NOWAIT).
 *
 * @param semid    Semaphore set ID
 * @param sops     Array of struct sembuf operations
 * @param nsops    Number of operations
 * @param timeout  Max wait time (NULL = infinite; Futura: EAGAIN on block)
 * @return 0 on success, -errno on error
 *
 * Phase 4 (Completed): timed variant; Futura returns EAGAIN for blocking ops
 *   regardless of timeout since blocking semop is not yet implemented. Timeout
 *   of {0,0} is validated and treated as non-blocking (correct Linux behavior).
 */
long sys_semtimedop(int semid, void *sops, unsigned int nsops,
                    const fut_timespec_t *timeout)
{
    if (!sops)
        return -EFAULT;
    if (nsops == 0)
        return -EINVAL;
    if (nsops > SEM_E2BIG_NSOPS)
        return -E2BIG;

    /* Validate timeout if provided */
    if (timeout) {
        fut_timespec_t ts;
        if (sem_copy_from_user(&ts, timeout, sizeof(ts)) != 0)
            return -EFAULT;
        if (ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000LL)
            return -EINVAL;
        /* Store validated timeout for potential future blocking implementation */
        (void)ts;
    }

    struct sem_set *s = semtable_find_by_id(semid);
    if (!s)
        return -EINVAL;

    /* Copy operations from user */
    struct sem_sembuf ops[SEM_E2BIG_NSOPS > SEMMSL ? SEMMSL : SEM_E2BIG_NSOPS];
    unsigned int copy_n = nsops < (unsigned int)SEMMSL ? nsops : (unsigned int)SEMMSL;
    if (sem_copy_from_user(ops, sops, copy_n * sizeof(struct sem_sembuf)) != 0)
        return -EFAULT;

    /* Validate semaphore indices */
    for (unsigned int i = 0; i < copy_n; i++) {
        if (ops[i].sem_num >= (unsigned short)s->nsems)
            return -E2BIG;
    }

    /* Check whether all operations can proceed without blocking */
    for (unsigned int i = 0; i < copy_n; i++) {
        int cur = s->sems[ops[i].sem_num].semval;
        int op  = ops[i].sem_op;
        if (op > 0) {
            if (cur + op > SEMVMX)
                return -ERANGE;
        } else if (op < 0) {
            if (cur + op < 0) {
                /* Would block: semtimedop returns EAGAIN (timeout expired) */
                return -EAGAIN;
            }
        } else {
            /* sem_op == 0: wait for zero */
            if (cur != 0)
                return -EAGAIN;
        }
    }

    /* All operations can proceed — apply atomically */
    fut_task_t *task = fut_task_current();
    int pid = task ? (int)task->pid : 1;

    for (unsigned int i = 0; i < copy_n; i++) {
        s->sems[ops[i].sem_num].semval += ops[i].sem_op;
        s->sems[ops[i].sem_num].sempid  = pid;
    }

    return 0;
}

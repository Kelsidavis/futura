// SPDX-License-Identifier: MPL-2.0
/*
 * linux/futex.h - Fast userspace locking
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides the futex interface for userspace synchronization primitives.
 * Futexes are the foundation for pthread mutexes, condition variables,
 * semaphores, and other synchronization primitives.
 */

#pragma once

#include <stdint.h>

/* ============================================================
 *   Futex Operations
 * ============================================================ */

#ifndef FUTEX_WAIT
#define FUTEX_WAIT              0   /* Wait if *uaddr == val */
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE              1   /* Wake up to val waiters */
#endif
#ifndef FUTEX_FD
#define FUTEX_FD                2   /* Create futex file descriptor (deprecated) */
#endif
#ifndef FUTEX_REQUEUE
#define FUTEX_REQUEUE           3   /* Requeue waiters from uaddr to uaddr2 */
#endif
#ifndef FUTEX_CMP_REQUEUE
#define FUTEX_CMP_REQUEUE       4   /* Requeue if *uaddr == val3 */
#endif
#ifndef FUTEX_WAKE_OP
#define FUTEX_WAKE_OP           5   /* Wake and perform op atomically */
#endif
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI           6   /* Lock priority-inheritance futex */
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI         7   /* Unlock priority-inheritance futex */
#endif
#ifndef FUTEX_TRYLOCK_PI
#define FUTEX_TRYLOCK_PI        8   /* Try to lock PI futex */
#endif
#ifndef FUTEX_WAIT_BITSET
#define FUTEX_WAIT_BITSET       9   /* Wait with bitset mask */
#endif
#ifndef FUTEX_WAKE_BITSET
#define FUTEX_WAKE_BITSET       10  /* Wake with bitset mask */
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI   11  /* Wait on uaddr, requeue to PI futex */
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI    12  /* Requeue to PI futex if val3 matches */
#endif

/* ============================================================
 *   Futex Flags
 * ============================================================ */

#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG      128 /* Process-private futex (optimization) */
#endif
#ifndef FUTEX_CLOCK_REALTIME
#define FUTEX_CLOCK_REALTIME    256 /* Use CLOCK_REALTIME for timeout */
#endif

/* Combined operation + private flag macros */
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE      (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE      (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_REQUEUE_PRIVATE
#define FUTEX_REQUEUE_PRIVATE   (FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_CMP_REQUEUE_PRIVATE
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_OP_PRIVATE
#define FUTEX_WAKE_OP_PRIVATE   (FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_LOCK_PI_PRIVATE
#define FUTEX_LOCK_PI_PRIVATE   (FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_UNLOCK_PI_PRIVATE
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_TRYLOCK_PI_PRIVATE
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAIT_BITSET_PRIVATE
#define FUTEX_WAIT_BITSET_PRIVATE (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_BITSET_PRIVATE
#define FUTEX_WAKE_BITSET_PRIVATE (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#endif

/* ============================================================
 *   FUTEX_WAKE_OP Constants
 * ============================================================ */

/* Operations for FUTEX_WAKE_OP (for val3 encoding) */
#define FUTEX_OP_SET        0   /* *uaddr2 = oparg */
#define FUTEX_OP_ADD        1   /* *uaddr2 += oparg */
#define FUTEX_OP_OR         2   /* *uaddr2 |= oparg */
#define FUTEX_OP_ANDN       3   /* *uaddr2 &= ~oparg */
#define FUTEX_OP_XOR        4   /* *uaddr2 ^= oparg */

/* Comparison operations for FUTEX_WAKE_OP */
#define FUTEX_OP_CMP_EQ     0   /* old == cmparg */
#define FUTEX_OP_CMP_NE     1   /* old != cmparg */
#define FUTEX_OP_CMP_LT     2   /* old < cmparg */
#define FUTEX_OP_CMP_LE     3   /* old <= cmparg */
#define FUTEX_OP_CMP_GT     4   /* old > cmparg */
#define FUTEX_OP_CMP_GE     5   /* old >= cmparg */

/* Encode FUTEX_WAKE_OP val3 argument */
#define FUTEX_OP(op, oparg, cmp, cmparg) \
    (((op) & 0xf) | (((cmp) & 0xf) << 4) | \
     (((oparg) & 0xfff) << 8) | (((cmparg) & 0xfff) << 20))

/* ============================================================
 *   Bitset Constants
 * ============================================================ */

/* Match all bits (default for WAIT_BITSET/WAKE_BITSET) */
#ifndef FUTEX_BITSET_MATCH_ANY
#define FUTEX_BITSET_MATCH_ANY  0xffffffffU
#endif

/* ============================================================
 *   Robust List Structures
 * ============================================================ */

#ifndef _STRUCT_ROBUST_LIST
#define _STRUCT_ROBUST_LIST
struct robust_list {
    struct robust_list *next;
};

struct robust_list_head {
    struct robust_list list;
    long futex_offset;
    struct robust_list *list_op_pending;
};
#endif

/* ============================================================
 *   Function Declarations
 * ============================================================ */

/**
 * futex - Fast userspace locking syscall
 *
 * @uaddr   Address of futex word
 * @op      Operation (FUTEX_WAIT, FUTEX_WAKE, etc.)
 * @val     Operation-specific value
 * @timeout Timeout for FUTEX_WAIT (NULL for infinite)
 * @uaddr2  Second futex address (for REQUEUE)
 * @val3    Operation-specific value
 *
 * Returns operation-specific result, or -1 on error.
 */
extern long futex(uint32_t *uaddr, int op, uint32_t val,
                  const void *timeout, uint32_t *uaddr2, uint32_t val3);

/**
 * set_robust_list - Register robust futex list
 *
 * @head  Pointer to robust list head
 * @len   Size of robust_list_head structure
 *
 * Returns 0 on success, -1 on error.
 */
extern long set_robust_list(struct robust_list_head *head, size_t len);

/**
 * get_robust_list - Get robust futex list
 *
 * @pid       Target process (0 for self)
 * @head_ptr  Pointer to store list head address
 * @len_ptr   Pointer to store list length
 *
 * Returns 0 on success, -1 on error.
 */
extern long get_robust_list(int pid, struct robust_list_head **head_ptr,
                            size_t *len_ptr);


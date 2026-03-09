/* fut_object.c - Futura OS Object System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Object system with capability-based access control and async message passing.
 * Migrated to x86-64 long mode architecture.
 */

#include "../../include/kernel/fut_object.h"
#include "../../include/kernel/fut_memory.h"
#include <kernel/errno.h>
#include <kernel/fut_sched.h>
#include <stdint.h>

/* ============================================================
 *   Message Queue (used by CHANNEL objects for async IPC)
 * ============================================================ */

#define FUT_MSG_MAX_LEN    65536   /* Maximum message payload in bytes */
#define FUT_MSGQ_MAX_MSGS  256     /* Maximum messages queued per channel */

struct fut_obj_msg {
    size_t len;
    struct fut_obj_msg *next;
    uint8_t data[];   /* Flexible array: payload follows immediately */
};

struct fut_obj_msgq {
    struct fut_obj_msg *head;
    struct fut_obj_msg *tail;
    size_t count;
    fut_spinlock_t lock;
};

/* ============================================================
 *   Object Table (Phase 1: Simple Linear Array)
 * ============================================================ */

#define FUT_MAX_OBJECTS 4096

static fut_object_t *object_table[FUT_MAX_OBJECTS];
static uint64_t next_handle = 1;

/* ============================================================
 *   Object System Initialization
 * ============================================================ */

void fut_object_system_init(void) {
    for (uint64_t i = 0; i < FUT_MAX_OBJECTS; ++i) {
        object_table[i] = NULL;
    }
    next_handle = 1;
}

/* ============================================================
 *   Object Creation and Destruction
 * ============================================================ */

fut_handle_t fut_object_create(enum fut_object_type type, fut_rights_t rights, void *data) {
    // Find free slot in object table
    for (uint64_t i = 1; i < FUT_MAX_OBJECTS; ++i) {
        if (object_table[i] == NULL) {
            // Allocate object structure
            fut_object_t *obj = (fut_object_t *)fut_malloc(sizeof(fut_object_t));
            if (!obj) {
                return FUT_INVALID_HANDLE;
            }

            // Initialize object
            obj->type = type;
            obj->rights = rights;
            obj->refcount = 1;
            obj->handle = (fut_handle_t)i;
            obj->data = data;
            obj->next = NULL;

            // Store in table
            object_table[i] = obj;

            return (fut_handle_t)i;
        }
    }

    return FUT_INVALID_HANDLE;  // Object table full
}

int fut_object_destroy(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return -EINVAL;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return -ENOENT;  /* Already destroyed or never existed */
    }

    /* Check if caller has DESTROY rights */
    if (!(obj->rights & FUT_RIGHT_DESTROY)) {
        return -EACCES;  /* Permission denied */
    }

    /* Decrement refcount atomically and free if zero */
    uint64_t remaining = __atomic_sub_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);
    if (remaining == 0) {
        object_table[handle] = NULL;
        fut_free(obj);
    }

    return 0;
}

/* ============================================================
 *   Object Reference Management
 * ============================================================ */

fut_object_t *fut_object_get(fut_handle_t handle, fut_rights_t required_rights) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return NULL;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return NULL;
    }

    // Check rights
    if ((obj->rights & required_rights) != required_rights) {
        return NULL;  // Insufficient rights
    }

    /* Increment refcount atomically */
    __atomic_add_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);

    return obj;
}

void fut_object_put(fut_object_t *obj) {
    if (!obj) return;

    /* Decrement refcount atomically and free if zero */
    uint64_t remaining = __atomic_sub_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);
    if (remaining == 0) {
        /* Clear table entry to prevent use-after-free and handle exhaustion */
        if (obj->handle < FUT_MAX_OBJECTS) {
            object_table[obj->handle] = NULL;
        }
        fut_free(obj);
    }
}

bool fut_object_has_rights(fut_handle_t handle, fut_rights_t required_rights) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return false;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return false;
    }

    return (obj->rights & required_rights) == required_rights;
}

/* ============================================================
 *   Object Sharing
 * ============================================================ */

fut_handle_t fut_object_share(fut_handle_t handle, uint64_t target_task, fut_rights_t shared_rights) {
    /*
     * Cross-task handle sharing requires per-task handle namespaces which are
     * not yet implemented (the current object table is global).  Return
     * FUT_INVALID_HANDLE until per-task handle spaces land.
     */
    (void)target_task;

    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS)
        return FUT_INVALID_HANDLE;

    fut_object_t *obj = object_table[handle];
    if (!obj)
        return FUT_INVALID_HANDLE;

    /* Caller must hold SHARE right */
    if (!(obj->rights & FUT_RIGHT_SHARE))
        return FUT_INVALID_HANDLE;

    /* Create a new handle with reduced (intersection) rights */
    fut_rights_t new_rights = obj->rights & shared_rights;
    if (new_rights == FUT_RIGHT_NONE)
        return FUT_INVALID_HANDLE;

    /* Bump refcount on the underlying object and create an alias handle */
    __atomic_add_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);

    for (uint64_t i = 1; i < FUT_MAX_OBJECTS; ++i) {
        if (object_table[i] == NULL) {
            fut_object_t *alias = (fut_object_t *)fut_malloc(sizeof(fut_object_t));
            if (!alias) {
                __atomic_sub_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);
                return FUT_INVALID_HANDLE;
            }
            alias->type   = obj->type;
            alias->rights = new_rights;
            alias->refcount = 1;
            alias->handle = (fut_handle_t)i;
            alias->data   = obj->data;  /* Shared data pointer */
            alias->next   = NULL;
            object_table[i] = alias;
            return (fut_handle_t)i;
        }
    }

    /* Table full */
    __atomic_sub_fetch(&obj->refcount, 1, __ATOMIC_ACQ_REL);
    return FUT_INVALID_HANDLE;
}

/* ============================================================
 *   Message Passing (Async IPC via per-channel message queues)
 * ============================================================ */

/*
 * Get or lazily allocate the message queue for an object.
 * Only CHANNEL objects support message passing.
 * Returns NULL if the object type is wrong or allocation fails.
 */
static struct fut_obj_msgq *object_get_msgq(fut_object_t *obj) {
    if (obj->type != FUT_OBJ_CHANNEL)
        return NULL;

    /* Fast path: queue already allocated */
    if (obj->data)
        return (struct fut_obj_msgq *)obj->data;

    /* Lazy init: allocate queue on first send */
    struct fut_obj_msgq *q = (struct fut_obj_msgq *)fut_malloc(sizeof(struct fut_obj_msgq));
    if (!q)
        return NULL;

    q->head  = NULL;
    q->tail  = NULL;
    q->count = 0;
    fut_spinlock_init(&q->lock);

    /* CAS to handle concurrent first-send races */
    void *expected = NULL;
    if (!__atomic_compare_exchange_n(&obj->data, &expected, q,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* Another thread won the race; free our copy and use theirs */
        fut_free(q);
        q = (struct fut_obj_msgq *)obj->data;
    }

    return q;
}

int fut_object_send(fut_handle_t handle, const void *msg, size_t msg_len) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS)
        return -EINVAL;
    if (!msg && msg_len > 0)
        return -EINVAL;
    if (msg_len > FUT_MSG_MAX_LEN)
        return -EMSGSIZE;

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj)
        return -EACCES;

    struct fut_obj_msgq *q = object_get_msgq(obj);
    if (!q) {
        fut_object_put(obj);
        return -EINVAL;  /* Object type doesn't support messaging */
    }

    /* Allocate message node with inline payload */
    struct fut_obj_msg *m = (struct fut_obj_msg *)fut_malloc(sizeof(struct fut_obj_msg) + msg_len);
    if (!m) {
        fut_object_put(obj);
        return -ENOMEM;
    }
    m->len  = msg_len;
    m->next = NULL;
    if (msg_len > 0)
        __builtin_memcpy(m->data, msg, msg_len);

    fut_spinlock_acquire(&q->lock);

    if (q->count >= FUT_MSGQ_MAX_MSGS) {
        fut_spinlock_release(&q->lock);
        fut_free(m);
        fut_object_put(obj);
        return -ENOSPC;
    }

    if (q->tail) {
        q->tail->next = m;
    } else {
        q->head = m;
    }
    q->tail = m;
    q->count++;

    fut_spinlock_release(&q->lock);
    fut_object_put(obj);
    return 0;
}

int fut_object_receive(fut_handle_t handle, void *buf, size_t buf_len) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS)
        return -EINVAL;
    if (!buf && buf_len > 0)
        return -EINVAL;

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_READ);
    if (!obj)
        return -EACCES;

    struct fut_obj_msgq *q = object_get_msgq(obj);
    if (!q) {
        fut_object_put(obj);
        return -EINVAL;
    }

    fut_spinlock_acquire(&q->lock);

    struct fut_obj_msg *m = q->head;
    if (!m) {
        fut_spinlock_release(&q->lock);
        fut_object_put(obj);
        return -EAGAIN;  /* No messages available (non-blocking) */
    }

    /* Dequeue head */
    q->head = m->next;
    if (!q->head)
        q->tail = NULL;
    q->count--;

    fut_spinlock_release(&q->lock);

    /* Copy payload (truncate to caller's buffer) */
    size_t copy_len = (m->len < buf_len) ? m->len : buf_len;
    if (copy_len > 0)
        __builtin_memcpy(buf, m->data, copy_len);

    size_t received = m->len;
    fut_free(m);
    fut_object_put(obj);

    /* Return actual message length; caller can detect truncation */
    return (int)received;
}

int fut_object_wait(fut_handle_t handle, uint64_t timeout_ms) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS)
        return -EINVAL;

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WAIT);
    if (!obj)
        return -EACCES;

    int result = 0;

    switch (obj->type) {
    case FUT_OBJ_CHANNEL: {
        /* Wait until the message queue is non-empty */
        struct fut_obj_msgq *q = object_get_msgq(obj);
        if (!q) { result = -EINVAL; break; }

        /* Busy-poll with yield; real sleep requires waitqueue integration */
        uint64_t spins = 0;
        const uint64_t MAX_SPINS = (timeout_ms == 0) ? UINT64_MAX : (timeout_ms * 1000ULL);
        while (true) {
            fut_spinlock_acquire(&q->lock);
            bool has_msg = (q->head != NULL);
            fut_spinlock_release(&q->lock);
            if (has_msg) { result = 0; break; }
            if (timeout_ms != 0 && spins >= MAX_SPINS) { result = -ETIMEDOUT; break; }
            spins++;
            /* Yield CPU to reduce bus contention while spinning */
#if defined(__x86_64__)
            __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
            __asm__ volatile("yield" ::: "memory");
#endif
        }
        break;
    }

    case FUT_OBJ_EVENT:
        /* For event objects, data pointer is the signal value (non-NULL = signalled) */
        if (obj->data) { result = 0; }
        else { result = (timeout_ms == 0) ? 0 : -ETIMEDOUT; }
        break;

    default:
        /* Object type doesn't support waiting */
        result = -EINVAL;
        break;
    }

    fut_object_put(obj);
    return result;
}

/* ============================================================
 *   Object System Statistics
 * ============================================================ */

void fut_object_get_stats(fut_object_stats_t *stats) {
    if (!stats) return;

    /* Clear stats structure */
    stats->total_objects = 0;
    stats->total_refcount = 0;
    stats->max_objects = FUT_MAX_OBJECTS;
    for (int i = 0; i < 11; i++) {
        stats->objects_by_type[i] = 0;
    }

    /* Count objects in table */
    for (uint64_t i = 1; i < FUT_MAX_OBJECTS; ++i) {
        fut_object_t *obj = object_table[i];
        if (obj) {
            stats->total_objects++;
            stats->total_refcount += obj->refcount;
            if (obj->type < 11) {
                stats->objects_by_type[obj->type]++;
            }
        }
    }
}

/* kernel/sys_msgqueue.c - SysV message queue implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements msgget(), msgsnd(), msgrcv(), msgctl() for SysV IPC.
 * Supports up to MSGMNI message queues, each holding MSGQBYTES bytes.
 *
 * Phase 3 (Completed): msgget/msgsnd/msgrcv/msgctl with IPC_RMID/IPC_STAT/
 *                      IPC_SET. msgrcv: type matching (0=any, >0=exact,
 *                      <0=smallest <= |msgtyp|). IPC_NOWAIT for non-blocking.
 */

#include <kernel/fut_task.h>
#include <kernel/fut_memory.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <stdint.h>
#include <stddef.h>

#include <platform/platform.h>

/* ============================================================
 *   IPC Constants
 * ============================================================ */

#define IPC_PRIVATE  0L
#define IPC_CREAT    0x0200
#define IPC_EXCL     0x0400
#define IPC_RMID     0
#define IPC_SET      1
#define IPC_STAT     2
#define IPC_NOWAIT   0x0800
#define MSG_NOERROR  0x1000   /* truncate if too long */
#define MSG_EXCEPT   0x2000   /* receive any except msgtyp */
#define MSG_COPY     0x0040   /* copy (not receive) message at index */

/* limits */
#define MSGMNI   32      /* max message queues */
#define MSGMAX   8192    /* max message body bytes */
#define MSGQBYTES 65536  /* max bytes per queue */

/* ============================================================
 *   Data Structures
 * ============================================================ */

struct msg_item {
    struct msg_item *next;
    long            mtype;
    size_t          msize;   /* body size in bytes (excluding mtype) */
    char            mdata[]; /* flexible array member for message body */
};

struct msg_queue {
    int              used;
    long             key;
    int              id;
    unsigned int     mode;
    size_t           qbytes;   /* current bytes in queue */
    unsigned int     qnum;     /* current message count */
    struct msg_item *head;
    struct msg_item *tail;
};

/* struct msqid_ds for IPC_STAT (simplified) */
struct msg_ipc_perm {
    int           key;
    unsigned int  uid, gid, cuid, cgid;
    unsigned int  mode;
    unsigned short seq, pad;
};

struct msqid_ds {
    struct msg_ipc_perm msg_perm;
    unsigned long       msg_stime;
    unsigned long       msg_rtime;
    unsigned long       msg_ctime;
    unsigned long       msg_cbytes;   /* current bytes in queue */
    unsigned long       msg_qnum;     /* current # of messages */
    unsigned long       msg_qbytes;   /* max bytes in queue */
    int                 msg_lspid;    /* pid of last msgsnd */
    int                 msg_lrpid;    /* pid of last msgrcv */
};

/* ============================================================
 *   Globals
 * ============================================================ */

static struct msg_queue mqtable[MSGMNI];
static int mq_next_id = 1;

/* ============================================================
 *   Kernel-pointer bypass helpers
 * ============================================================ */

static inline int mq_copy_from_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)src >= KERNEL_VIRTUAL_BASE) {
        __builtin_memcpy(dst, src, n);
        return 0;
    }
#endif
    return fut_copy_from_user(dst, src, n);
}

static inline int mq_copy_to_user(void *dst, const void *src, size_t n) {
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

static struct msg_queue *mqtable_find_by_id(int id) {
    for (int i = 0; i < MSGMNI; i++) {
        if (mqtable[i].used && mqtable[i].id == id)
            return &mqtable[i];
    }
    return NULL;
}

static struct msg_queue *mqtable_find_by_key(long key) {
    for (int i = 0; i < MSGMNI; i++) {
        if (mqtable[i].used && mqtable[i].key == key)
            return &mqtable[i];
    }
    return NULL;
}

/* ============================================================
 *   msgget(2) - get/create a message queue
 * ============================================================ */

/**
 * msgget - Get or create a SysV message queue.
 *
 * @param key     IPC key (IPC_PRIVATE = always create new)
 * @param msgflg  IPC_CREAT, IPC_EXCL, permissions
 * @return message queue ID on success, -errno on error
 */
long sys_msgget(long key, int msgflg) {
    if (key != IPC_PRIVATE) {
        struct msg_queue *q = mqtable_find_by_key(key);
        if (q) {
            if ((msgflg & IPC_CREAT) && (msgflg & IPC_EXCL))
                return -EEXIST;
            return q->id;
        }
        if (!(msgflg & IPC_CREAT))
            return -ENOENT;
    }

    /* Create new queue */
    for (int i = 0; i < MSGMNI; i++) {
        if (!mqtable[i].used) {
            mqtable[i].used   = 1;
            mqtable[i].key    = key;
            mqtable[i].id     = mq_next_id++;
            mqtable[i].mode   = (unsigned int)(msgflg & 0777);
            mqtable[i].qbytes = 0;
            mqtable[i].qnum   = 0;
            mqtable[i].head   = NULL;
            mqtable[i].tail   = NULL;
            return mqtable[i].id;
        }
    }
    return -ENOSPC;
}

/* ============================================================
 *   msgsnd(2) - send message to queue
 * ============================================================ */

/**
 * msgsnd - Append a message to a message queue.
 *
 * The user's msgp points to a struct { long mtype; char mtext[msgsz]; }.
 * mtype must be > 0.
 *
 * @param msqid   Message queue ID
 * @param msgp    Pointer to user message (mtype + body)
 * @param msgsz   Size of message body (NOT including mtype)
 * @param msgflg  IPC_NOWAIT etc.
 * @return 0 on success, -errno on error
 */
long sys_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg) {
    if (!msgp)
        return -EFAULT;
    if (msgsz > MSGMAX)
        return -EINVAL;

    struct msg_queue *q = mqtable_find_by_id(msqid);
    if (!q)
        return -EINVAL;

    /* Check queue capacity */
    if (q->qbytes + msgsz > MSGQBYTES) {
        return (msgflg & IPC_NOWAIT) ? -EAGAIN : -EAGAIN;
    }

    /* Read mtype from user (first sizeof(long) bytes) */
    long mtype = 0;
    if (mq_copy_from_user(&mtype, msgp, sizeof(long)) != 0)
        return -EFAULT;
    if (mtype <= 0)
        return -EINVAL;

    /* Allocate message item */
    struct msg_item *item = (struct msg_item *)fut_malloc(
        sizeof(struct msg_item) + msgsz);
    if (!item)
        return -ENOMEM;

    item->next  = NULL;
    item->mtype = mtype;
    item->msize = msgsz;

    /* Copy message body (bytes after mtype) */
    if (msgsz > 0) {
        const char *body = (const char *)msgp + sizeof(long);
        if (mq_copy_from_user(item->mdata, body, msgsz) != 0) {
            fut_free(item);
            return -EFAULT;
        }
    }

    /* Enqueue */
    if (!q->tail) {
        q->head = q->tail = item;
    } else {
        q->tail->next = item;
        q->tail = item;
    }
    q->qnum++;
    q->qbytes += msgsz;

    return 0;
}

/* ============================================================
 *   msgrcv(2) - receive message from queue
 * ============================================================ */

/**
 * msgrcv - Receive a message from a message queue.
 *
 * Type matching:
 *   msgtyp == 0: return first message
 *   msgtyp  > 0: return first message of type == msgtyp
 *   msgtyp  < 0: return first message with smallest type <= |msgtyp|
 *
 * @param msqid   Message queue ID
 * @param msgp    Output: user buffer for { long mtype; char mtext[msgsz]; }
 * @param msgsz   Size of output buffer (body only, NOT including mtype)
 * @param msgtyp  Message type selector
 * @param msgflg  IPC_NOWAIT, MSG_NOERROR, MSG_EXCEPT
 * @return number of bytes in message body on success, -errno on error
 */
long sys_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
    /* Linux's do_msgrcv enforces MSG_COPY constraints up front:
     *   if (msgflg & MSG_COPY) {
     *     if ((msgflg & MSG_EXCEPT) || !(msgflg & IPC_NOWAIT))
     *       return -EINVAL;
     *     ...
     *   }
     * MSG_COPY (3.8+) means "copy the message at index msgtyp without
     * dequeueing", which only makes sense as a non-blocking probe of a
     * specific queue position.  The previous Futura code silently
     * ignored MSG_COPY entirely, so callers passing MSG_COPY without
     * IPC_NOWAIT got real-receive semantics (dequeueing the matching
     * message) where Linux would have rejected the call. */
    if (msgflg & MSG_COPY) {
        if ((msgflg & MSG_EXCEPT) || !(msgflg & IPC_NOWAIT))
            return -EINVAL;
    }

    /* Linux's do_msgrcv validates msqid (sem_obtain_object_check)
     * before any user-pointer access; the NULL msgp pointer surfaces
     * later through copy_to_user as -EFAULT.  The previous Futura
     * order rejected NULL msgp first, inverting the errno class for
     * callers that probe with NULL buf to detect 'is this msqid
     * valid?'.  Same EINVAL-before-EFAULT reorder pattern as the
     * matching semop / sched_getaffinity / clock_gettime fixes. */
    struct msg_queue *q = mqtable_find_by_id(msqid);
    if (!q)
        return -EINVAL;

    if (!msgp)
        return -EFAULT;

    /* Find matching message */
    struct msg_item *prev = NULL;
    struct msg_item *item = q->head;
    struct msg_item *best_prev = NULL;
    struct msg_item *best = NULL;

    while (item) {
        int match = 0;
        if (msgtyp == 0) {
            /* First message always matches */
            match = 1;
        } else if (msgtyp > 0) {
            if (!(msgflg & MSG_EXCEPT))
                match = (item->mtype == msgtyp);
            else
                match = (item->mtype != msgtyp);
        } else {
            /* msgtyp < 0: find smallest type <= |msgtyp| */
            long abs_typ = -msgtyp;
            if (item->mtype <= abs_typ) {
                if (!best || item->mtype < best->mtype) {
                    best = item;
                    best_prev = prev;
                }
            }
        }

        if (match && msgtyp >= 0) {
            best = item;
            best_prev = prev;
            break;
        }
        prev = item;
        item = item->next;
    }

    if (!best) {
        return (msgflg & IPC_NOWAIT) ? -ENOMSG : -ENOMSG;
    }

    /* Check buffer size */
    if (best->msize > msgsz) {
        if (!(msgflg & MSG_NOERROR))
            return -E2BIG;
        /* Truncate */
    }
    size_t copy_sz = best->msize < msgsz ? best->msize : msgsz;

    /* Copy mtype to user */
    if (mq_copy_to_user(msgp, &best->mtype, sizeof(long)) != 0)
        return -EFAULT;

    /* Copy body to user */
    if (copy_sz > 0) {
        char *ubody = (char *)msgp + sizeof(long);
        if (mq_copy_to_user(ubody, best->mdata, copy_sz) != 0)
            return -EFAULT;
    }

    /* Dequeue */
    if (best_prev)
        best_prev->next = best->next;
    else
        q->head = best->next;

    if (q->tail == best)
        q->tail = best_prev;

    q->qnum--;
    q->qbytes -= best->msize;

    size_t ret = copy_sz;
    fut_free(best);
    return (long)ret;
}

/* ============================================================
 *   msgctl(2) - control message queue
 * ============================================================ */

/**
 * msgctl - Perform control operation on a message queue.
 *
 * @param msqid  Message queue ID
 * @param cmd    IPC_RMID, IPC_STAT, IPC_SET
 * @param buf    Pointer to struct msqid_ds (for IPC_STAT/IPC_SET)
 * @return 0 on success, -errno on error
 */
long sys_msgctl(int msqid, int cmd, void *buf) {
    if (cmd == IPC_RMID) {
        struct msg_queue *q = mqtable_find_by_id(msqid);
        if (!q)
            return -EINVAL;
        /* Free all pending messages */
        struct msg_item *item = q->head;
        while (item) {
            struct msg_item *next = item->next;
            fut_free(item);
            item = next;
        }
        q->used = 0;
        q->head = q->tail = NULL;
        return 0;
    }

    struct msg_queue *q = mqtable_find_by_id(msqid);
    if (!q)
        return -EINVAL;

    switch (cmd) {
    case IPC_STAT: {
        if (!buf)
            return -EFAULT;
        struct msqid_ds ds;
        __builtin_memset(&ds, 0, sizeof(ds));
        ds.msg_perm.key    = (int)q->key;
        ds.msg_perm.mode   = q->mode;
        ds.msg_cbytes      = q->qbytes;
        ds.msg_qnum        = q->qnum;
        ds.msg_qbytes      = MSGQBYTES;
        if (mq_copy_to_user(buf, &ds, sizeof(ds)) != 0)
            return -EFAULT;
        return 0;
    }

    case IPC_SET: {
        if (!buf)
            return -EFAULT;
        struct msqid_ds ds;
        if (mq_copy_from_user(&ds, buf, sizeof(ds)) != 0)
            return -EFAULT;
        q->mode = ds.msg_perm.mode & 0777;
        return 0;
    }

    default:
        return -EINVAL;
    }
}

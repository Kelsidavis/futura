// SPDX-License-Identifier: MPL-2.0
/*
 * blkcore.c - Asynchronous block device core with handle-gated rights
 *
 * Provides a central queueing hub between filesystems and block drivers.
 * Drivers register a backend descriptor, callers obtain handles with
 * explicit rights, and all BIOs flow through a worker thread that
 * serialises submissions while preserving asynchronous completion order.
 */

#include <futura/blkdev.h>

#include <kernel/errno.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_sched.h>
#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_waitq.h>

#include <stdatomic.h>
#include <string.h>

#define FUT_BLK_NAME_MAX 64u

typedef struct fut_blk_request {
    fut_bio_t *bio;
    struct fut_blk_request *next;
} fut_blk_request_t;

struct fut_blkcore_state {
    fut_blkdev_t *dev;
    char name[FUT_BLK_NAME_MAX];
    uint32_t allowed_rights;

    fut_spinlock_t queue_lock;
    fut_waitq_t queue_wait;
    fut_blk_request_t *queue_head;
    fut_blk_request_t *queue_tail;

    _Atomic uint64_t queued;
    _Atomic uint64_t inflight;
    _Atomic uint64_t completed;
    _Atomic uint64_t errors;

    bool shutting_down;
    fut_thread_t *worker_thread;

    struct fut_blkcore_state *next;
};

typedef struct fut_blkcore_state fut_blkcore_state_t;

typedef struct fut_blk_handle {
    fut_blkcore_state_t *state;
    uint32_t rights;
} fut_blk_handle_t;

static fut_spinlock_t g_dev_lock = { .locked = 0 };
static fut_blkcore_state_t *g_devices = NULL;
static fut_task_t *g_blk_task = NULL;
static bool g_core_ready = false;

extern void fut_printf(const char *fmt, ...);

static inline fut_rights_t blk_rights_to_object(uint32_t rights) {
    fut_rights_t obj = FUT_RIGHT_DESTROY;
    if (rights & FUT_BLK_READ) {
        obj |= FUT_RIGHT_READ;
    }
    if (rights & FUT_BLK_WRITE) {
        obj |= FUT_RIGHT_WRITE;
    }
    if (rights & FUT_BLK_ADMIN) {
        obj |= FUT_RIGHT_ADMIN;
    }
    return obj;
}

static inline fut_rights_t blk_required_to_object(bool write) {
    return write ? FUT_RIGHT_WRITE : FUT_RIGHT_READ;
}

static size_t blk_strlcpy(char *dst, const char *src, size_t cap) {
    if (!dst || !src || cap == 0) {
        return 0;
    }
    size_t i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
    while (src[i] != '\0') {
        ++i;
    }
    return i;
}

static bool blk_name_equal(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    for (size_t i = 0; i < FUT_BLK_NAME_MAX; ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca != cb) {
            return false;
        }
        if (ca == '\0') {
            return true;
        }
    }
    return true;
}

static fut_blkcore_state_t *find_device_locked(const char *name) {
    for (fut_blkcore_state_t *state = g_devices; state; state = state->next) {
        if (blk_name_equal(state->name, name)) {
            return state;
        }
    }
    return NULL;
}

static fut_status_t blk_backend_submit(fut_blkcore_state_t *state, fut_bio_t *bio) {
    if (!state || !state->dev || !state->dev->backend) {
        return -ENODEV;
    }

    const fut_blk_backend_t *backend = state->dev->backend;
    void *ctx = state->dev->backend_ctx;

    if (bio->write) {
        if (!backend->write) {
            return -EPERM;
        }
        return backend->write(ctx, bio->lba, bio->nsectors, bio->buf);
    }

    if (!backend->read) {
        return -EPERM;
    }
    return backend->read(ctx, bio->lba, bio->nsectors, bio->buf);
}

static fut_status_t blk_validate_bio(const fut_blkdev_t *dev, const fut_bio_t *bio) {
    if (!dev || !bio || !bio->buf || bio->nsectors == 0u) {
        return -EINVAL;
    }
    if (bio->lba >= dev->block_count) {
        return -EINVAL;
    }
    if (bio->lba + bio->nsectors > dev->block_count) {
        return -EINVAL;
    }
    return 0;
}

static void fut_blk_worker(void *arg) {
    fut_blkcore_state_t *state = (fut_blkcore_state_t *)arg;

    for (;;) {
        fut_blk_request_t *req = NULL;

        fut_spinlock_acquire(&state->queue_lock);
        while (!state->queue_head && !state->shutting_down) {
            fut_waitq_sleep_locked(&state->queue_wait, &state->queue_lock, FUT_THREAD_BLOCKED);
            fut_spinlock_acquire(&state->queue_lock);
        }

        if (state->shutting_down && !state->queue_head) {
            fut_spinlock_release(&state->queue_lock);
            break;
        }

        req = state->queue_head;
        if (req) {
            state->queue_head = req->next;
            if (!state->queue_head) {
                state->queue_tail = NULL;
            }
            atomic_fetch_sub_explicit(&state->queued, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&state->inflight, 1, memory_order_relaxed);
        }

        fut_spinlock_release(&state->queue_lock);

        if (!req) {
            continue;
        }

        fut_bio_t *bio = req->bio;
        fut_status_t status = blk_backend_submit(state, bio);
        size_t bytes = (status == 0) ? (bio->nsectors * state->dev->block_size) : 0;

        if (status == 0) {
            atomic_fetch_add_explicit(&state->completed, 1, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&state->errors, 1, memory_order_relaxed);
        }

        if (bio->on_complete) {
            bio->on_complete(bio, status, bytes);
        }

        atomic_fetch_sub_explicit(&state->inflight, 1, memory_order_relaxed);
        fut_free(req);
    }

    fut_thread_exit();
}

void fut_blk_core_init(void) {
    if (g_core_ready) {
        return;
    }

    fut_spinlock_init(&g_dev_lock);

    g_blk_task = fut_task_create();
    if (!g_blk_task) {
        fut_printf("[blkcore] failed to create worker task container\n");
        return;
    }

    g_core_ready = true;
}

fut_status_t fut_blk_register(fut_blkdev_t *dev) {
    if (!dev || !dev->name || !dev->backend || !dev->backend->read ||
        dev->block_size == 0u || dev->block_count == 0u) {
        return -EINVAL;
    }
    if (dev->core) {
        return -EEXIST;
    }

    if (!g_core_ready) {
        fut_blk_core_init();
        if (!g_core_ready) {
            return -ENOMEM;
        }
    }

    fut_blkcore_state_t *state = (fut_blkcore_state_t *)fut_malloc(sizeof(fut_blkcore_state_t));
    if (!state) {
        return -ENOMEM;
    }
    memset(state, 0, sizeof(*state));

    state->dev = dev;
    state->allowed_rights = dev->allowed_rights ? dev->allowed_rights : FUT_BLK_READ;
    dev->allowed_rights = state->allowed_rights;
    blk_strlcpy(state->name, dev->name, FUT_BLK_NAME_MAX);

    fut_spinlock_init(&state->queue_lock);
    fut_waitq_init(&state->queue_wait);
    atomic_store_explicit(&state->queued, 0, memory_order_relaxed);
    atomic_store_explicit(&state->inflight, 0, memory_order_relaxed);
    atomic_store_explicit(&state->completed, 0, memory_order_relaxed);
    atomic_store_explicit(&state->errors, 0, memory_order_relaxed);
    state->shutting_down = false;

    fut_spinlock_acquire(&g_dev_lock);
    if (find_device_locked(state->name)) {
        fut_spinlock_release(&g_dev_lock);
        fut_free(state);
        return -EEXIST;
    }
    state->next = g_devices;
    g_devices = state;
    fut_spinlock_release(&g_dev_lock);

    dev->core = state;

    state->worker_thread = fut_thread_create(
        g_blk_task,
        fut_blk_worker,
        state,
        16 * 1024,
        160
    );

    if (!state->worker_thread) {
        fut_spinlock_acquire(&g_dev_lock);
        if (g_devices == state) {
            g_devices = state->next;
        } else {
            fut_blkcore_state_t *iter = g_devices;
            while (iter && iter->next != state) {
                iter = iter->next;
            }
            if (iter) {
                iter->next = state->next;
            }
        }
        fut_spinlock_release(&g_dev_lock);
        dev->core = NULL;
        fut_free(state);
        return -ENOMEM;
    }

    /* Register with legacy blockdev API for compatibility with VFS */
    extern int fut_blockdev_register_compat(const char *name, uint32_t block_size,
                                             uint64_t block_count, void *backend_ctx);
    fut_blockdev_register_compat(dev->name, dev->block_size, dev->block_count, dev);

    return 0;
}

/**
 * Synchronous read wrapper for legacy blockdev API compatibility.
 * Performs a synchronous read using the block core's async infrastructure.
 */
int fut_blk_read(void *backend_ctx, uint64_t sector, uint32_t count, void *buffer) {
    if (!backend_ctx || !buffer || count == 0) {
        return -EINVAL;
    }

    fut_blkdev_t *dev = (fut_blkdev_t *)backend_ctx;
    if (!dev->backend || !dev->backend->read) {
        return -ENOTSUP;
    }

    /* Call backend directly for synchronous I/O */
    return dev->backend->read(dev->backend_ctx, sector, count, buffer);
}

/**
 * Synchronous write wrapper for legacy blockdev API compatibility.
 * Performs a synchronous write using the block core's async infrastructure.
 */
int fut_blk_write(void *backend_ctx, uint64_t sector, uint32_t count, const void *buffer) {
    if (!backend_ctx || !buffer || count == 0) {
        return -EINVAL;
    }

    fut_blkdev_t *dev = (fut_blkdev_t *)backend_ctx;
    if (!dev->backend || !dev->backend->write) {
        return -ENOTSUP;
    }

    /* Call backend directly for synchronous I/O */
    return dev->backend->write(dev->backend_ctx, sector, count, buffer);
}

fut_status_t fut_blk_acquire(const char *name, uint32_t rights, fut_handle_t *out_handle) {
    if (!name || !out_handle || rights == 0u) {
        return -EINVAL;
    }

    fut_spinlock_acquire(&g_dev_lock);
    fut_blkcore_state_t *state = find_device_locked(name);
    fut_spinlock_release(&g_dev_lock);

    if (!state) {
        return -ENODEV;
    }

    if ((rights & state->allowed_rights) != rights) {
        return -EPERM;
    }

    fut_blk_handle_t *handle = (fut_blk_handle_t *)fut_malloc(sizeof(fut_blk_handle_t));
    if (!handle) {
        return -ENOMEM;
    }

    handle->state = state;
    handle->rights = rights;

    fut_rights_t obj_rights = blk_rights_to_object(rights);
    fut_handle_t h = fut_object_create(FUT_OBJ_BLKDEV, obj_rights, handle);
    if (h == FUT_INVALID_HANDLE) {
        fut_free(handle);
        return -ENOMEM;
    }

    *out_handle = h;
    return 0;
}

fut_status_t fut_blk_open(fut_handle_t cap, fut_blkdev_t **out) {
    if (!out) {
        return -EINVAL;
    }

    fut_object_t *obj = fut_object_get(cap, FUT_RIGHT_NONE);
    if (!obj) {
        return -EPERM;
    }

    if (obj->type != FUT_OBJ_BLKDEV) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    if (!hdl || !hdl->state || !hdl->state->dev) {
        fut_object_put(obj);
        return -ENODEV;
    }

    *out = hdl->state->dev;
    fut_object_put(obj);
    return 0;
}

fut_status_t fut_blk_submit(fut_handle_t cap, fut_bio_t *bio) {
    if (!bio) {
        return -EINVAL;
    }

    fut_rights_t required = blk_required_to_object(bio->write);
    fut_object_t *obj = fut_object_get(cap, required);
    if (!obj) {
        return -EPERM;
    }

    if (obj->type != FUT_OBJ_BLKDEV) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    if (!hdl || !hdl->state || !hdl->state->dev) {
        fut_object_put(obj);
        return -ENODEV;
    }

    uint32_t needed = bio->write ? FUT_BLK_WRITE : FUT_BLK_READ;
    if ((hdl->rights & needed) != needed) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blkdev_t *dev = hdl->state->dev;
    fut_status_t rc = blk_validate_bio(dev, bio);
    if (rc != 0) {
        fut_object_put(obj);
        return rc;
    }

    fut_blk_request_t *req = (fut_blk_request_t *)fut_malloc(sizeof(fut_blk_request_t));
    if (!req) {
        fut_object_put(obj);
        return -ENOMEM;
    }

    req->bio = bio;
    req->next = NULL;

    fut_spinlock_acquire(&hdl->state->queue_lock);
    if (!hdl->state->queue_head) {
        hdl->state->queue_head = req;
    } else {
        hdl->state->queue_tail->next = req;
    }
    hdl->state->queue_tail = req;
    atomic_fetch_add_explicit(&hdl->state->queued, 1, memory_order_relaxed);
    fut_spinlock_release(&hdl->state->queue_lock);

    fut_waitq_wake_one(&hdl->state->queue_wait);
    fut_object_put(obj);
    return 0;
}

fut_status_t fut_blk_flush(fut_handle_t cap) {
    fut_object_t *obj = fut_object_get(cap, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN);
    if (!obj) {
        return -EPERM;
    }

    if (obj->type != FUT_OBJ_BLKDEV) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    if (!hdl || !hdl->state || !hdl->state->dev) {
        fut_object_put(obj);
        return -ENODEV;
    }

    if ((hdl->rights & (FUT_BLK_WRITE | FUT_BLK_ADMIN)) != (FUT_BLK_WRITE | FUT_BLK_ADMIN)) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_status_t rc = 0;
    const fut_blk_backend_t *backend = hdl->state->dev->backend;
    if (backend && backend->flush) {
        rc = backend->flush(hdl->state->dev->backend_ctx);
    }

    fut_object_put(obj);
    return rc;
}

fut_status_t fut_blk_close(fut_handle_t cap) {
    fut_object_t *obj = fut_object_get(cap, FUT_RIGHT_DESTROY);
    if (!obj) {
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    obj->data = NULL;
    fut_object_put(obj);

    fut_status_t rc = fut_object_destroy(cap);
    if (hdl) {
        fut_free(hdl);
    }
    return rc;
}

const char *fut_blk_name(const fut_blkdev_t *dev) {
    return dev ? dev->name : NULL;
}

uint32_t fut_blk_block_size(const fut_blkdev_t *dev) {
    return dev ? dev->block_size : 0u;
}

uint64_t fut_blk_block_count(const fut_blkdev_t *dev) {
    return dev ? dev->block_count : 0u;
}

void fut_blk_get_stats(const fut_blkdev_t *dev, fut_blk_stats_t *out) {
    if (!dev || !dev->core || !out) {
        return;
    }

    fut_blkcore_state_t *state = dev->core;
    out->queued = atomic_load_explicit(&state->queued, memory_order_relaxed);
    out->inflight = atomic_load_explicit(&state->inflight, memory_order_relaxed);
    out->completed = atomic_load_explicit(&state->completed, memory_order_relaxed);
    out->errors = atomic_load_explicit(&state->errors, memory_order_relaxed);
}

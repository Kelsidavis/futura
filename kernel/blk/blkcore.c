// SPDX-License-Identifier: MPL-2.0
/*
 * blkcore.c - Asynchronous block device core with handle-gated rights
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

#define FUT_BLK_NAME_MAX 32

typedef struct fut_blk_request {
    fut_bio_t *bio;
    struct fut_blk_request *next;
} fut_blk_request_t;

struct fut_blkdev {
    char name[FUT_BLK_NAME_MAX];
    uint32_t block_size;
    uint64_t block_count;
    uint32_t allowed_rights;
    const fut_blk_backend_t *backend;
    void *backend_ctx;

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
    struct fut_blkdev *next;
};

typedef struct fut_blk_handle {
    fut_blkdev_t *dev;
    uint32_t rights;
} fut_blk_handle_t;

static fut_spinlock_t g_dev_lock = { .locked = 0 };
static fut_blkdev_t *g_devices = NULL;
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

static bool blk_name_equal(const char *a, const char *b) {
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

static fut_blkdev_t *find_device_locked(const char *name) {
    for (fut_blkdev_t *dev = g_devices; dev; dev = dev->next) {
        if (blk_name_equal(dev->name, name)) {
            return dev;
        }
    }
    return NULL;
}

static int blk_backend_rw(fut_blkdev_t *dev, fut_bio_t *bio) {
    if (bio->write) {
        if (!dev->backend->write) {
            return -EPERM;
        }
        return dev->backend->write(dev->backend_ctx, bio->lba, bio->nsectors, bio->buf);
    }
    if (!dev->backend->read) {
        return -EPERM;
    }
    return dev->backend->read(dev->backend_ctx, bio->lba, bio->nsectors, bio->buf);
}

static void fut_blk_worker(void *arg) {
    fut_blkdev_t *dev = (fut_blkdev_t *)arg;

    for (;;) {
        fut_blk_request_t *req = NULL;

        fut_spinlock_acquire(&dev->queue_lock);
        while (!dev->queue_head && !dev->shutting_down) {
            fut_waitq_sleep_locked(&dev->queue_wait, &dev->queue_lock, FUT_THREAD_BLOCKED);
            fut_spinlock_acquire(&dev->queue_lock);
        }

        if (dev->shutting_down && !dev->queue_head) {
            fut_spinlock_release(&dev->queue_lock);
            break;
        }

        req = dev->queue_head;
        if (req) {
            dev->queue_head = req->next;
            if (!dev->queue_head) {
                dev->queue_tail = NULL;
            }
            atomic_fetch_sub_explicit(&dev->queued, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&dev->inflight, 1, memory_order_relaxed);
        }

        fut_spinlock_release(&dev->queue_lock);

        if (!req) {
            continue;
        }

        fut_bio_t *bio = req->bio;
        int status = blk_backend_rw(dev, bio);
        size_t bytes = (status == 0) ? (bio->nsectors * dev->block_size) : 0;

        if (status == 0) {
            atomic_fetch_add_explicit(&dev->completed, 1, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&dev->errors, 1, memory_order_relaxed);
        }

        if (bio->on_complete) {
            bio->on_complete(bio, status, bytes);
        }

        atomic_fetch_sub_explicit(&dev->inflight, 1, memory_order_relaxed);
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
        fut_printf("[BLK] failed to create worker task container\n");
        return;
    }

    g_core_ready = true;
}

int fut_blk_register(const char *name,
                     uint32_t block_size,
                     uint64_t block_count,
                     uint32_t allowed_rights,
                     const fut_blk_backend_t *backend,
                     void *backend_ctx,
                     fut_blkdev_t **out_dev) {
    if (!name || !backend || !backend->read || block_size == 0 || block_count == 0) {
        return -EINVAL;
    }

    if (!g_core_ready) {
        fut_blk_core_init();
        if (!g_core_ready) {
            return -ENOMEM;
        }
    }

    fut_blkdev_t *dev = (fut_blkdev_t *)fut_malloc(sizeof(fut_blkdev_t));
    if (!dev) {
        return -ENOMEM;
    }
    memset(dev, 0, sizeof(*dev));

    size_t name_len = 0;
    while (name_len < FUT_BLK_NAME_MAX - 1 && name[name_len] != '\0') {
        dev->name[name_len] = name[name_len];
        ++name_len;
    }
    dev->name[name_len] = '\0';

    if (allowed_rights == 0) {
        allowed_rights = FUT_BLK_READ;
    }

    dev->block_size = block_size;
    dev->block_count = block_count;
    dev->allowed_rights = allowed_rights;
    dev->backend = backend;
    dev->backend_ctx = backend_ctx;
    fut_spinlock_init(&dev->queue_lock);
    fut_waitq_init(&dev->queue_wait);
    dev->queue_head = NULL;
    dev->queue_tail = NULL;
    atomic_store_explicit(&dev->queued, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->inflight, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->completed, 0, memory_order_relaxed);
    atomic_store_explicit(&dev->errors, 0, memory_order_relaxed);
    dev->shutting_down = false;
    dev->worker_thread = NULL;

    fut_spinlock_acquire(&g_dev_lock);
    if (find_device_locked(dev->name)) {
        fut_spinlock_release(&g_dev_lock);
        fut_free(dev);
        return -EEXIST;
    }

    dev->next = g_devices;
    g_devices = dev;
    fut_spinlock_release(&g_dev_lock);

    dev->worker_thread = fut_thread_create(
        g_blk_task,
        fut_blk_worker,
        dev,
        16 * 1024,
        160
    );

    if (!dev->worker_thread) {
        fut_spinlock_acquire(&g_dev_lock);
        if (g_devices == dev) {
            g_devices = dev->next;
        } else {
            fut_blkdev_t *iter = g_devices;
            while (iter && iter->next != dev) {
                iter = iter->next;
            }
            if (iter) {
                iter->next = dev->next;
            }
        }
        fut_spinlock_release(&g_dev_lock);
        fut_free(dev);
        return -ENOMEM;
    }

    if (out_dev) {
        *out_dev = dev;
    }

    return 0;
}

int fut_blk_open(const char *name, uint32_t rights, fut_handle_t *out_handle) {
    if (!name || !out_handle) {
        return -EINVAL;
    }
    if (rights == 0) {
        return -EPERM;
    }

    fut_spinlock_acquire(&g_dev_lock);
    fut_blkdev_t *dev = find_device_locked(name);
    fut_spinlock_release(&g_dev_lock);

    if (!dev) {
        return -ENODEV;
    }

    if ((rights & dev->allowed_rights) != rights) {
        return -EPERM;
    }

    fut_blk_handle_t *handle = (fut_blk_handle_t *)fut_malloc(sizeof(fut_blk_handle_t));
    if (!handle) {
        return -ENOMEM;
    }

    handle->dev = dev;
    handle->rights = rights;

    fut_rights_t obj_rights = blk_rights_to_object(rights);
    fut_handle_t handle_id = fut_object_create(FUT_OBJ_BLKDEV, obj_rights, handle);
    if (handle_id == FUT_INVALID_HANDLE) {
        fut_free(handle);
        return -ENOMEM;
    }

    *out_handle = handle_id;
    return 0;
}

static int blk_validate_bio(fut_blkdev_t *dev, const fut_bio_t *bio) {
    if (!bio || !bio->buf || bio->nsectors == 0) {
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

int fut_blk_submit(fut_handle_t handle, fut_bio_t *bio) {
    if (!bio) {
        return -EINVAL;
    }

    fut_rights_t required = blk_required_to_object(bio->write);
    fut_object_t *obj = fut_object_get(handle, required);
    if (!obj) {
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    if (!hdl || !hdl->dev) {
        fut_object_put(obj);
        return -ENODEV;
    }

    uint32_t needed = bio->write ? FUT_BLK_WRITE : FUT_BLK_READ;
    if ((hdl->rights & needed) != needed) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blkdev_t *dev = hdl->dev;
    int rc = blk_validate_bio(dev, bio);
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

    fut_spinlock_acquire(&dev->queue_lock);
    if (!dev->queue_head) {
        dev->queue_head = req;
    } else {
        dev->queue_tail->next = req;
    }
    dev->queue_tail = req;
    atomic_fetch_add_explicit(&dev->queued, 1, memory_order_relaxed);
    fut_spinlock_release(&dev->queue_lock);

    fut_waitq_wake_one(&dev->queue_wait);
    fut_object_put(obj);
    return 0;
}

int fut_blk_flush(fut_handle_t handle) {
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN);
    if (!obj) {
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    if (!hdl || !hdl->dev) {
        fut_object_put(obj);
        return -ENODEV;
    }

    if ((hdl->rights & (FUT_BLK_WRITE | FUT_BLK_ADMIN)) != (FUT_BLK_WRITE | FUT_BLK_ADMIN)) {
        fut_object_put(obj);
        return -EPERM;
    }

    fut_blkdev_t *dev = hdl->dev;
    int rc = 0;
    if (dev->backend->flush) {
        rc = dev->backend->flush(dev->backend_ctx);
    }
    fut_object_put(obj);
    return rc;
}

int fut_blk_close(fut_handle_t handle) {
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_DESTROY);
    if (!obj) {
        return -EPERM;
    }

    fut_blk_handle_t *hdl = (fut_blk_handle_t *)obj->data;
    obj->data = NULL;
    fut_object_put(obj);

    int rc = fut_object_destroy(handle);
    if (hdl) {
        fut_free(hdl);
    }
    return rc;
}

const char *fut_blk_name(const fut_blkdev_t *dev) {
    return dev ? dev->name : NULL;
}

uint32_t fut_blk_block_size(const fut_blkdev_t *dev) {
    return dev ? dev->block_size : 0;
}

uint64_t fut_blk_block_count(const fut_blkdev_t *dev) {
    return dev ? dev->block_count : 0;
}

void fut_blk_get_stats(const fut_blkdev_t *dev, fut_blk_stats_t *out) {
    if (!dev || !out) {
        return;
    }
    out->queued = atomic_load_explicit(&dev->queued, memory_order_relaxed);
    out->inflight = atomic_load_explicit(&dev->inflight, memory_order_relaxed);
    out->completed = atomic_load_explicit(&dev->completed, memory_order_relaxed);
    out->errors = atomic_load_explicit(&dev->errors, memory_order_relaxed);
}

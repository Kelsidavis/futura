# FuturaFS Async Operations Design

## Overview

This document describes the design for converting FuturaFS operations to fully asynchronous, callback-based I/O. This is Phase 3 of the capability-based I/O transition.

## Current State (Phase 2)

The current implementation uses synchronous wrappers around async block I/O:

```c
/* Phase 2: Sync wrappers that block on wait queues */
static inline int futurafs_blk_read(struct futurafs_mount *mnt,
                                    uint64_t block_num, uint64_t num_blocks, void *buffer) {
    if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
        return fut_blk_read_sync(mnt->block_device_handle, block_num, num_blocks, buffer);
    } else {
        return fut_blockdev_read(mnt->dev, block_num, num_blocks, buffer);
    }
}
```

**Characteristics:**
- Each operation blocks the calling thread
- Simple to reason about and test
- One I/O operation per thread at a time
- CPU can context switch to other threads while waiting

## Target State (Phase 3)

Fully asynchronous operations using callbacks:

```c
/* Phase 3: Fully async with callbacks */
typedef void (*futurafs_completion_t)(int result, void *ctx);

struct futurafs_async_ctx {
    futurafs_completion_t callback;
    void *user_ctx;
    void *operation_data;  /* Operation-specific data */
};

static int futurafs_read_superblock_async(struct futurafs_mount *mount,
                                          struct futurafs_superblock *sb,
                                          futurafs_completion_t callback,
                                          void *ctx);
```

**Characteristics:**
- Operations return immediately
- Completion signaled via callback
- Single thread can have multiple I/O operations in flight
- Better I/O pipelining and throughput
- More complex code and error handling

## Async Operation Framework

### 1. Completion Callback Type

```c
/**
 * Filesystem operation completion callback.
 *
 * @param result  Operation result (0 on success, negative error code on failure)
 * @param ctx     User context pointer passed to async function
 */
typedef void (*futurafs_completion_t)(int result, void *ctx);
```

### 2. Async Context Structure

Each async operation needs a context structure to track state:

```c
/**
 * Generic async operation context.
 * Specific operations extend this with operation-specific fields.
 */
struct futurafs_async_ctx {
    /* Completion callback */
    futurafs_completion_t callback;
    void *callback_ctx;

    /* Operation state */
    struct futurafs_mount *mount;
    int result;

    /* Next in completion queue */
    struct futurafs_async_ctx *next;
};
```

### 3. Operation-Specific Contexts

Each operation type has its own context structure:

```c
/* Superblock read context */
struct futurafs_sb_read_ctx {
    struct futurafs_async_ctx base;
    struct futurafs_superblock *sb;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/* Inode read context */
struct futurafs_inode_read_ctx {
    struct futurafs_async_ctx base;
    uint64_t ino;
    struct futurafs_inode *inode;
    uint8_t block_buffer[FUTURAFS_BLOCK_SIZE];
};

/* Data block read context */
struct futurafs_block_read_ctx {
    struct futurafs_async_ctx base;
    uint64_t block_num;
    void *buffer;
};
```

## Implementation Status

### Phase 3a: Async Primitive Operations ✅ COMPLETE

**Status**: Completed
**Duration**: Implemented over 3 sessions
**Commits**: 3 commits (6a5cf05, cc62d43, ced9cc2)

**Implemented Operations:**
1. ✅ **Superblock operations** (`futurafs_read_superblock_async`, `futurafs_write_superblock_async`)
   - Simple async pattern with validation in callback
   - Magic number and version validation

2. ✅ **Inode operations** (`futurafs_read_inode_async`, `futurafs_write_inode_async`)
   - Read: Simple async read with extraction from block buffer
   - Write: Demonstrates callback chaining (read-modify-write pattern)
   - Two-stage write: read block → modify inode → write block

3. ✅ **Data block operations** (`futurafs_read_block_async`, `futurafs_write_block_async`)
   - Direct block-level async I/O
   - Block number validation
   - Building blocks for file I/O

**Key Patterns Established:**
- Heap-allocated async contexts
- Callback-based completion notification
- Memory management: context freed in callback
- Error propagation: block I/O errors → filesystem errors
- Callback chaining for read-modify-write sequences

**Files Modified:**
- `include/kernel/fut_futurafs.h` - Async API definitions
- `kernel/fs/futurafs.c` - Async operation implementations

**Kernel Size**: 1,339,592 bytes (1.3MB)

## Implementation Strategy

### Phase 3a: Async Primitive Operations (2-3 weeks) ✅

Implement async versions of primitive I/O operations:

1. **Superblock operations**
   - `futurafs_read_superblock_async()`
   - `futurafs_write_superblock_async()`

2. **Inode operations**
   - `futurafs_read_inode_async()`
   - `futurafs_write_inode_async()`

3. **Data block operations**
   - `futurafs_read_block_async()`
   - `futurafs_write_block_async()`

4. **Directory entry operations**
   - `futurafs_read_dirent_async()`
   - `futurafs_write_dirent_async()`

**Pattern:**
```c
static void futurafs_read_inode_callback(int result, void *ctx) {
    struct futurafs_inode_read_ctx *inode_ctx = ctx;

    if (result >= 0) {
        /* Extract inode from block buffer */
        uint64_t inode_index = inode_ctx->ino - 1;
        uint64_t block_offset = (inode_index % inode_ctx->base.mount->inodes_per_block)
                                * FUTURAFS_INODE_SIZE;
        fut_memcpy(inode_ctx->inode,
                   inode_ctx->block_buffer + block_offset,
                   FUTURAFS_INODE_SIZE);
    }

    /* Call user callback */
    inode_ctx->base.callback(result, inode_ctx->base.callback_ctx);

    /* Free context */
    fut_free(inode_ctx);
}

static int futurafs_read_inode_async(struct futurafs_mount *mount, uint64_t ino,
                                     struct futurafs_inode *inode,
                                     futurafs_completion_t callback, void *ctx) {
    /* Allocate async context */
    struct futurafs_inode_read_ctx *inode_ctx = fut_malloc(sizeof(*inode_ctx));
    if (!inode_ctx) {
        return -12;  /* ENOMEM */
    }

    /* Initialize context */
    inode_ctx->base.callback = callback;
    inode_ctx->base.callback_ctx = ctx;
    inode_ctx->base.mount = mount;
    inode_ctx->ino = ino;
    inode_ctx->inode = inode;

    /* Calculate block number */
    uint64_t inode_index = ino - 1;
    uint64_t block_num = mount->sb->inode_table_block +
                         (inode_index / mount->inodes_per_block);

    /* Submit async read */
    return fut_blk_read_async(mount->block_device_handle, block_num, 1,
                             inode_ctx->block_buffer,
                             futurafs_read_inode_callback, inode_ctx);
}
```

### Phase 3b: Async Composite Operations (2-3 weeks)

Convert higher-level operations that combine multiple I/O operations:

1. **File read/write**
   - `futurafs_read_impl_async()`
   - `futurafs_write_impl_async()`

2. **Directory operations**
   - `futurafs_readdir_impl_async()`
   - `futurafs_lookup_impl_async()`

3. **File creation/deletion**
   - `futurafs_create_impl_async()`
   - `futurafs_unlink_impl_async()`

**Challenge:** These operations involve multiple sequential I/O operations that depend on each other. This requires callback chaining:

```c
/* Example: File read with indirect block */
static void file_read_data_callback(int result, void *ctx) {
    /* Data block read complete */
    struct file_read_ctx *read_ctx = ctx;
    /* ... handle completion ... */
}

static void file_read_indirect_callback(int result, void *ctx) {
    struct file_read_ctx *read_ctx = ctx;

    if (result < 0) {
        /* Error reading indirect block */
        read_ctx->base.callback(result, read_ctx->base.callback_ctx);
        fut_free(read_ctx);
        return;
    }

    /* Parse indirect block to get data block number */
    uint64_t *indirect_table = (uint64_t *)read_ctx->indirect_buffer;
    uint64_t data_block = indirect_table[read_ctx->indirect_offset];

    /* Issue second I/O: read data block */
    int ret = fut_blk_read_async(read_ctx->base.mount->block_device_handle,
                                 data_block, 1, read_ctx->data_buffer,
                                 file_read_data_callback, read_ctx);
    if (ret < 0) {
        read_ctx->base.callback(ret, read_ctx->base.callback_ctx);
        fut_free(read_ctx);
    }
}

static int futurafs_read_impl_async(/* ... */) {
    /* First I/O: read inode */
    /* ... */
    /* Second I/O: read indirect block (if needed) */
    fut_blk_read_async(/* ... */, file_read_indirect_callback, ctx);
    /* Third I/O: read data block */
    /* Chained in callback above */
}
```

### Phase 3c: VFS Integration (1 week)

Update VFS layer to support async operations:

```c
/* VFS async operation signatures */
struct fut_vnode_ops {
    /* Sync versions (deprecated) */
    ssize_t (*read)(struct fut_vnode *vnode, void *buffer, size_t size, uint64_t offset);
    ssize_t (*write)(struct fut_vnode *vnode, const void *buffer, size_t size, uint64_t offset);

    /* Async versions */
    int (*read_async)(struct fut_vnode *vnode, void *buffer, size_t size, uint64_t offset,
                      futurafs_completion_t callback, void *ctx);
    int (*write_async)(struct fut_vnode *vnode, const void *buffer, size_t size, uint64_t offset,
                       futurafs_completion_t callback, void *ctx);
};
```

### Phase 3d: Cleanup (1 week)

1. Remove legacy sync wrappers (`futurafs_blk_read`, `futurafs_blk_write`)
2. Remove fallback to legacy block device API
3. Remove `dev` pointer from `struct futurafs_mount`
4. Mark old sync API as deprecated
5. Update all test code to use async API

## Benefits

1. **Performance:**
   - Multiple concurrent I/O operations per thread
   - Better I/O pipelining (e.g., read metadata while previous data block completes)
   - Reduced latency for complex operations

2. **Scalability:**
   - More efficient use of thread pool
   - Better resource utilization

3. **Future-proof:**
   - Natural fit for async syscall interface
   - Enables advanced features like AIO, io_uring-style batching

## Challenges

1. **Code Complexity:**
   - Callback chaining for multi-step operations
   - Error handling across async boundaries
   - Memory management for async contexts

2. **Debugging:**
   - Stack traces less useful
   - Harder to reason about execution flow

3. **Testing:**
   - Need comprehensive async testing framework
   - Race conditions and timing issues

## Memory Management

All async contexts are heap-allocated:

```c
/* Context allocation */
ctx = fut_malloc(sizeof(*ctx));

/* Context freed in completion callback */
fut_free(ctx);
```

**Important:** The completion callback MUST free the context, or memory leaks will occur.

## Error Handling

Errors can occur at two points:

1. **Submission errors:** Returned immediately from async function
   ```c
   int ret = futurafs_read_inode_async(...);
   if (ret < 0) {
       /* Handle submission error */
   }
   ```

2. **Completion errors:** Passed to callback
   ```c
   void my_callback(int result, void *ctx) {
       if (result < 0) {
           /* Handle I/O error */
       }
   }
   ```

## Testing Strategy

1. **Unit tests:** Test each async operation individually
2. **Integration tests:** Test callback chaining
3. **Stress tests:** Many concurrent async operations
4. **Failure injection:** Test error handling paths

## Timeline

- Phase 3a: Async primitive operations - 2-3 weeks
- Phase 3b: Async composite operations - 2-3 weeks
- Phase 3c: VFS integration - 1 week
- Phase 3d: Cleanup - 1 week

**Total: 6-8 weeks**

## References

- Block device async API: `include/kernel/fut_blockdev.h` (lines 218-295)
- FuturaFS implementation: `kernel/fs/futurafs.c`
- VFS integration: `kernel/vfs/fut_vfs.c`
- Capability system: `include/kernel/fut_object.h`

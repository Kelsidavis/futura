# FuturaFS Capability-Based I/O Transition Plan

## Current Status

The capability propagation infrastructure is now complete. FuturaFS has been extended with dual-mode support:

```c
struct futurafs_mount {
    /* Capability-based block device access */
    fut_handle_t block_device_handle;   /* Block device capability handle */

    /* Legacy block device pointer (for sync I/O during transition) */
    struct fut_blockdev *dev;           /* Block device (deprecated) */

    /* ... other fields ... */
};
```

## Capability Flow

```
Client/Kernel
    ↓ (passes fut_handle_t)
FSD Mount Handler
    ↓ (validates FUT_RIGHT_READ | FUT_RIGHT_WRITE)
VFS Layer
    ↓ (stores in fut_mount->block_device_handle)
Filesystem (FuturaFS)
    ↓ (stores in futurafs_mount->block_device_handle)
Block I/O Operations
```

## Transition Phases

### Phase 1: Infrastructure (✅ COMPLETE)
- [x] Extended `fut_mount` with `block_device_handle` field
- [x] Extended filesystem mount signature to accept capability handles
- [x] Updated VFS to propagate capabilities to filesystems
- [x] Added capability validation in FSD mount handler
- [x] Extended `futurafs_mount` with dual-mode support

### Phase 2: Async I/O API Integration (PENDING)

The next phase involves converting synchronous I/O operations to use the new async API.

**Current Synchronous API:**
```c
int fut_blockdev_read(struct fut_blockdev *dev, uint64_t block, void *buffer);
int fut_blockdev_write(struct fut_blockdev *dev, uint64_t block, const void *buffer);
int fut_blockdev_read_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, void *buffer);
int fut_blockdev_write_bytes(struct fut_blockdev *dev, uint64_t offset, size_t size, const void *buffer);
```

**Target Async API (to be implemented):**
```c
/* Submit async block I/O request using capability handle */
int fut_blk_read_async(fut_handle_t blk_handle, uint64_t block, void *buffer,
                       fut_blk_callback_t callback, void *ctx);
int fut_blk_write_async(fut_handle_t blk_handle, uint64_t block, const void *buffer,
                        fut_blk_callback_t callback, void *ctx);

/* Callback signature */
typedef void (*fut_blk_callback_t)(int result, void *ctx);
```

**Migration Strategy:**

1. **Implement async block I/O API** in block device core
   - Add capability-based async read/write functions
   - Implement callback mechanism for I/O completion
   - Support both direct capability handles and legacy pointers during transition

2. **Create transition wrappers** for gradual migration:
   ```c
   /* Temporary sync wrapper using capability handle */
   static int futurafs_blk_read_sync(struct futurafs_mount *mnt,
                                     uint64_t block, void *buffer) {
       if (mnt->block_device_handle != FUT_INVALID_HANDLE) {
           /* Use capability-based async I/O with blocking wait */
           return fut_blk_read_sync(mnt->block_device_handle, block, buffer);
       } else {
           /* Fall back to legacy sync I/O */
           return fut_blockdev_read(mnt->dev, block, buffer);
       }
   }
   ```

3. **Convert FuturaFS operations incrementally:**
   - Phase 2a: Replace direct `fut_blockdev_*` calls with wrappers
   - Phase 2b: Implement async versions of filesystem operations
   - Phase 2c: Remove legacy sync I/O code paths

### Phase 3: Full Async Conversion (FUTURE)

Convert all FuturaFS operations to fully asynchronous:

**Operations to convert:**
- `futurafs_read_superblock()` - Superblock I/O (futurafs.c:27)
- `futurafs_write_superblock()` - Superblock sync (futurafs.c:71)
- `futurafs_read_inode()` - Inode reads (futurafs.c:101)
- `futurafs_write_inode()` - Inode writes (futurafs.c:113)
- `futurafs_read_block()` - Data block reads (futurafs.c:364)
- `futurafs_write_block()` - Data block writes (futurafs.c:421)
- `futurafs_read_dirent()` - Directory entry reads (futurafs.c:598)
- `futurafs_write_dirent()` - Directory entry writes (futurafs.c:672)

**Example async conversion:**
```c
/* Current sync version */
static int futurafs_read_inode(struct futurafs_mount *mnt, uint64_t ino,
                               struct futurafs_inode *inode) {
    uint64_t block = /* calculate block */;
    uint8_t buffer[FUTURAFS_BLOCK_SIZE];
    int ret = fut_blockdev_read(mnt->dev, block, buffer);
    if (ret < 0) return ret;
    /* copy inode from buffer */
    return 0;
}

/* Future async version */
struct futurafs_read_inode_ctx {
    struct futurafs_inode *inode;
    fut_completion_t *completion;
    uint8_t buffer[FUTURAFS_BLOCK_SIZE];
};

static void futurafs_read_inode_callback(int result, void *ctx) {
    struct futurafs_read_inode_ctx *inode_ctx = ctx;
    if (result >= 0) {
        /* copy inode from buffer */
    }
    fut_complete(inode_ctx->completion, result);
    fut_free(inode_ctx);
}

static int futurafs_read_inode_async(struct futurafs_mount *mnt, uint64_t ino,
                                     struct futurafs_inode *inode,
                                     fut_completion_t *completion) {
    struct futurafs_read_inode_ctx *ctx = fut_malloc(sizeof(*ctx));
    ctx->inode = inode;
    ctx->completion = completion;

    uint64_t block = /* calculate block */;
    return fut_blk_read_async(mnt->block_device_handle, block, ctx->buffer,
                             futurafs_read_inode_callback, ctx);
}
```

### Phase 4: Cleanup (FUTURE)

Once all I/O is converted to async:
- Remove legacy `dev` pointer from `struct futurafs_mount`
- Remove all `fut_blockdev_*` sync API calls from FuturaFS
- Mark old sync I/O API as deprecated
- Update all callers to use async versions

## I/O Call Sites in FuturaFS

Current locations using synchronous I/O that need conversion:

**Block-level reads (fut_blockdev_read):**
- futurafs.c:27 - Superblock read in `futurafs_read_superblock()`
- futurafs.c:101 - Inode read in `futurafs_read_inode()`
- futurafs.c:364 - Data block read in `futurafs_read_block()`
- futurafs.c:454 - Indirect block read in `futurafs_get_block()`
- futurafs.c:598 - Directory block read in `futurafs_read_dirent()`
- futurafs.c:726 - Directory enumeration in `futurafs_readdir_impl()`
- futurafs.c:807 - File read in `futurafs_read_impl()`
- futurafs.c:874 - File write (read-modify-write) in `futurafs_write_impl()`
- futurafs.c:1014 - Unlink operation in `futurafs_unlink_impl()`

**Block-level writes (fut_blockdev_write):**
- futurafs.c:71 - Superblock write in `futurafs_write_superblock()`
- futurafs.c:113 - Inode write in `futurafs_write_inode()`
- futurafs.c:421 - Data block allocation in `futurafs_alloc_block()`
- futurafs.c:503 - Indirect block allocation in `futurafs_get_block()`
- futurafs.c:672 - Directory entry write in `futurafs_write_dirent()`
- futurafs.c:739 - Directory entry creation in `futurafs_create_dirent()`
- futurafs.c:874 - File write in `futurafs_write_impl()`
- futurafs.c:1014 - Unlink cleanup in `futurafs_unlink_impl()`

**Byte-level I/O (fut_blockdev_read_bytes/write_bytes):**
- futurafs.c:274 - Bitmap sync in `futurafs_sync_bitmaps()`
- futurafs.c:1329 - Inode bitmap read in `futurafs_mount_impl()`
- futurafs.c:1348 - Data bitmap read in `futurafs_mount_impl()`
- futurafs.c:1569 - Directory name write in `futurafs_mkdir_impl()`
- futurafs.c:1588 - Root directory entry write in `futurafs_format()`
- futurafs.c:1607 - Root directory entry write (continued)

**Total: ~24 I/O call sites to convert**

## Benefits of Async I/O

1. **Performance**: Non-blocking I/O allows CPU to perform other work while waiting for disk
2. **Scalability**: Multiple concurrent I/O operations can be in flight
3. **Security**: Capability-based access ensures only authorized operations
4. **Flexibility**: Easier to implement I/O prioritization and QoS

## Testing Strategy

1. **Phase 1 Testing** (Current):
   - Verify capability propagation through all layers
   - Test mount with valid/invalid capabilities
   - Ensure legacy I/O still works

2. **Phase 2 Testing**:
   - Test wrapper functions maintain correctness
   - Verify capability-based I/O produces same results as legacy
   - Performance benchmarks comparing sync vs async

3. **Phase 3 Testing**:
   - Comprehensive filesystem operations test suite
   - Concurrent I/O stress tests
   - Failure injection and error handling tests

## Implementation Notes

- **Backward Compatibility**: During transition, support both legacy and capability modes
- **Error Handling**: Async errors must be propagated through callback chain
- **Memory Management**: Careful allocation/deallocation of async context structures
- **Synchronization**: May need locks/atomics for async operation state
- **Completion Mechanism**: Need robust completion primitive (futex, condvar, or similar)

## Timeline Estimate

- Phase 1: ✅ Complete (capability propagation infrastructure)
- Phase 2: 2-3 weeks (async API + wrappers)
- Phase 3: 4-6 weeks (full async conversion of ~24 call sites)
- Phase 4: 1 week (cleanup and deprecation)

Total estimated time: 7-10 weeks for complete migration

## References

- Block device capability API: `include/kernel/fut_blockdev.h`
- FuturaFS implementation: `kernel/fs/futurafs.c`
- VFS integration: `kernel/vfs/fut_vfs.c`
- Capability system: `include/kernel/fut_object.h`

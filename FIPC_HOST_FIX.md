# FIPC Host Build Fix - Wait Queue Stubs

## Summary

Fixed linker errors in the host FIPC transport library (`libfipc_host.a`) by adding wait queue stub implementations to the host shim layer.

## Problem

The kernel FIPC core (`kernel/ipc/fut_fipc.c`) now uses wait queue primitives for blocking operations, but the host shim layer (`host/transport/fipc_host_shim.c`) didn't provide stub implementations. This caused undefined reference errors when building the host library:

```
undefined reference to `fut_waitq_init'
undefined reference to `fut_waitq_sleep_locked'
undefined reference to `fut_waitq_wake_one'
```

## Solution

Added wait queue stub implementations to `host/transport/fipc_host_shim.c`:

### Changes Made

**File:** `host/transport/fipc_host_shim.c`

1. **Added header include** (line 14):
   ```c
   #include <kernel/fut_waitq.h>
   ```

2. **Added wait queue stub implementations** (lines 294-316):
   ```c
   /* ------------------------------------------------------------ */
   /* Wait queue stubs for host build                             */

   void fut_waitq_init(fut_waitq_t *wq) {
       if (wq) {
           wq->head = NULL;
       }
   }

   void fut_waitq_sleep_locked(fut_waitq_t *wq, fut_spinlock_t *lock, enum fut_thread_state state) {
       /* Host build doesn't have proper scheduler, so just unlock and return */
       (void)wq;
       (void)state;
       if (lock) {
           fut_spinlock_release(lock);
       }
   }

   void fut_waitq_wake_one(fut_waitq_t *wq) {
       /* No-op in host build since we don't have a real scheduler */
       (void)wq;
   }
   ```

## Implementation Details

### Wait Queue Stub Semantics

- **`fut_waitq_init`**: Initializes wait queue by setting head to NULL
- **`fut_waitq_sleep_locked`**: In the kernel, this blocks the thread. In the host build, we don't have a real scheduler, so we simply release the lock and return (no-op blocking)
- **`fut_waitq_wake_one`**: In the kernel, this wakes a waiting thread. In the host build, this is a no-op since we don't actually block threads

### Why This Works

The host FIPC library is used for testing and tooling, not for production kernel execution. The wait queue operations are used in the kernel for:
1. Blocking when FIPC channels are full (back-pressure)
2. Waking threads when space becomes available

In the host environment:
- We run single-threaded tests
- We don't need actual blocking behavior
- The stubs provide correct API compatibility without scheduler integration

### Key Discoveries During Implementation

1. **Spinlock function naming**: The correct function is `fut_spinlock_release()`, not `fut_spinlock_unlock()`
2. **Function signature**: `fut_waitq_sleep_locked()` takes 3 parameters: `(fut_waitq_t *wq, fut_spinlock_t *lock, enum fut_thread_state state)`
3. **Inline functions**: Spinlock functions are defined as inline in `include/kernel/fut_sched.h`

## Verification

Successfully built the host FIPC library:

```bash
$ make -C host/transport clean
$ make -C host/transport
AR build/lib/libfipc_host.a
```

Verified wait queue symbols are present:

```bash
$ nm build/lib/libfipc_host.a | grep fut_waitq
00000000000006b0 T fut_waitq_init
00000000000006d0 T fut_waitq_sleep_locked
00000000000006f0 T fut_waitq_wake_one
```

## Related Files

- `host/transport/fipc_host_shim.c` - Host shim implementation (modified)
- `include/kernel/fut_waitq.h` - Wait queue type definitions
- `include/kernel/fut_sched.h` - Spinlock definitions
- `kernel/ipc/fut_fipc.c` - Kernel FIPC core (uses wait queues)
- `host/transport/Makefile` - Host library build configuration

## Testing

The host FIPC library is used by:
- FIPC unit tests in `tests/`
- Host-side tooling
- Development utilities

The fix allows these components to link against the updated kernel FIPC code that uses wait queues.

## Future Work

- Add host-side unit tests for FIPC blocking behavior
- Consider implementing basic multi-threaded host tests with pthread-based wait queues
- Document host shim requirements when adding new kernel primitives

## Notes

This fix maintains backward compatibility while allowing the kernel FIPC core to use wait queues for proper blocking behavior. The host shim continues to provide a simplified environment for testing FIPC protocol logic without requiring a full kernel scheduler.

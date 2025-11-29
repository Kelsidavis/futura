# Futura OS - Phase 2/3 TODO Implementation Plan

This document outlines a structured plan for implementing the remaining Phase 2 and Phase 3 TODOs in the Futura OS kernel.

## Overview

The codebase has completed most *at() syscall directory FD resolution (Phase 2) and basic parameter validation. Remaining work falls into these categories:

1. **Memory Access Validation** - Implement fut_access_ok() for userspace pointer validation
2. **Resource Limits** - Add RLIMIT enforcement infrastructure
3. **VFS Enhancements** - Filesystem sync, atomic operations, symlink support
4. **Permission Checking** - Implement actual permission validation beyond stubs
5. **Memory Management** - Overflow checks, VMA limits, lock accounting

## Priority 1: Memory Access Validation (Foundation) - ✅ ALREADY IMPLEMENTED

**Status:** fut_access_ok() already exists in kernel/uaccess.c (line 135)!

### Existing Implementation
- **File:** `kernel/uaccess.c`
- **Function:** `int fut_access_ok(const void *u_ptr, size_t len, int write)`
- **Features:**
  - Validates address is in userspace range via `__range_user_ok()`
  - Checks for wraparound and zero-length access
  - Walks page tables to verify present, user-accessible pages
  - Checks PTE_WRITABLE flag if write=1
  - Returns 0 on success, -EFAULT on invalid access

### TODOs This Already Unlocks
The existing fut_access_ok() can be used immediately for:
- sys_select.c:204 - Validate readfds/writefds/exceptfds pointers
- sys_futex.c:178 - Validate uaddr for atomic operations
- sys_futex.c:345 - Validate robust_list head pointer
- sys_prlimit.c:374 - Validate old_limit/new_limit pointers

**Action Required:** Use existing fut_access_ok() from kernel/uaccess.c
**Estimated Effort:** None - infrastructure already complete

---

## Priority 2: Resource Limits Infrastructure

**Why Second:** Enables many security validations and DoS prevention.

### Files to Modify
- `include/kernel/fut_task.h` - Add rlimits[] array to fut_task
- `kernel/threading/fut_task.c` - Initialize default limits
- `kernel/sys_prlimit.c` - Complete Phase 2 validation and storage

### Implementation Steps

1. **Add rlimits to fut_task structure**
   ```c
   struct fut_task {
       // ... existing fields ...

       /* Resource limits (POSIX rlimits) */
       struct rlimit64 rlimits[16];  // RLIMIT_NOFILE, RLIMIT_MEMLOCK, etc.
   };
   ```

2. **Define rlimit constants** (if not already defined)
   ```c
   #define RLIMIT_NOFILE    7   // Max open files
   #define RLIMIT_MEMLOCK   8   // Max locked memory
   #define RLIMIT_NPROC     6   // Max processes
   #define RLIMIT_AS        9   // Virtual memory limit
   ```

3. **Initialize default limits in fut_task_create()**
   - RLIMIT_NOFILE: 1024 (soft), 4096 (hard)
   - RLIMIT_MEMLOCK: 64KB (soft), 64KB (hard)
   - RLIMIT_NPROC: 1024 (soft), 2048 (hard)

4. **Implement sys_prlimit Phase 2 TODOs**
   - Validate new_limit values against system maximums
   - Add capability checks (CAP_SYS_RESOURCE for raising hard limits)
   - Reject RLIM64_INFINITY for RLIMIT_MEMLOCK and RLIMIT_NPROC
   - Store validated limits in task->rlimits[]

### TODOs This Unlocks
- sys_prlimit.c:375-379 - All Phase 2 prlimit validations
- sys_mman.c:156 - Check cumulative locked_vm vs RLIMIT_MEMLOCK
- sys_mman.c:350-351 - Memory lock limit enforcement
- sys_fcntl.c - F_DUPFD resource limit checks

**Estimated Complexity:** Medium (3-4 hours)
**Files Modified:** 3 files, ~300 lines of code

---

## Priority 3: Memory Management Safety

**Why Third:** Prevents integer overflow and DoS attacks in memory operations.

### Files to Modify
- `kernel/sys_mman.c` - Add overflow checks and VMA limits

### Implementation Steps

1. **Add integer overflow validation**
   ```c
   // Check: SIZE_MAX - (uintptr_t)addr >= len
   if (len > SIZE_MAX - (uintptr_t)addr) {
       return -EINVAL;  // Would wrap around
   }

   // Check: addr + len > addr
   if ((uintptr_t)addr + len <= (uintptr_t)addr) {
       return -EINVAL;  // Wraparound detected
   }
   ```

2. **Add VMA count limits**
   ```c
   // In mmap/munmap: check task VMA count < 65536
   if (task->mm->vma_count >= 65536) {
       return -ENOMEM;  // Too many VMAs
   }
   ```

3. **Add memory lock accounting**
   - Track locked_vm pages in fut_mm structure
   - Check against RLIMIT_MEMLOCK before mlock()
   - Require CAP_IPC_LOCK if exceeding limit

### TODOs This Unlocks
- sys_mman.c:154-157 - All mlock overflow checks
- sys_mman.c:348-351 - VMA and lock limit enforcement

**Estimated Complexity:** Low-Medium (2-3 hours)
**Files Modified:** 1-2 files, ~150 lines of code

---

## Priority 4: VFS Filesystem Sync Support

**Why Fourth:** Enables proper filesystem synchronization for data integrity.

### Files to Modify
- `kernel/vfs/fut_vfs.c` - Add VFS sync operations
- `kernel/sys_sync.c` - Implement Phase 2 actual sync
- `kernel/sys_syncfs.c` - Implement Phase 2 FD-specific sync
- `kernel/vfs/ramfs.c` - Add sync operation (no-op for RAM)
- `subsystems/futura_fs/` - Add journal commit support

### Implementation Steps

1. **Add sync operation to vnode_ops**
   ```c
   struct fut_vnode_ops {
       // ... existing ops ...
       int (*sync)(struct fut_vnode *vnode);  // Flush dirty data
   };
   ```

2. **Implement VFS-level sync**
   ```c
   int fut_vfs_sync_all(void);  // Sync all mounted filesystems
   int fut_vfs_sync_fs(int fd);  // Sync filesystem containing fd
   ```

3. **Mount table support**
   - Add global mount table tracking all mounted filesystems
   - Iterate mounts in sys_sync()
   - Resolve FD to mount point in sys_syncfs()

4. **RamFS sync implementation**
   - No-op (data already in memory)
   - Return 0 immediately

### TODOs This Unlocks
- sys_sync.c:119-122 - All Phase 2 sync operations
- sys_syncfs.c:144-148 - All Phase 2 syncfs operations
- sys_fdatasync.c:228 - Add datasync to vnode_ops

**Estimated Complexity:** High (5-6 hours)
**Files Modified:** 5+ files, ~400 lines of code

---

## Priority 5: Permission Checking Infrastructure

**Why Fifth:** Completes access control beyond basic validation.

### Files to Modify
- `kernel/sys_faccessat.c` - Implement actual permission checks
- `kernel/vfs/fut_vfs.c` - Add VFS permission checking helpers

### Implementation Steps

1. **Add VFS permission check helper**
   ```c
   int fut_vfs_check_permission(struct fut_vnode *vnode,
                                 uint32_t uid, uint32_t gid,
                                 int mode);  // R_OK, W_OK, X_OK
   ```

2. **Implement in sys_faccessat**
   - Use check_uid/check_gid from AT_EACCESS flag
   - Call VFS permission checker
   - Return EACCES if permission denied

3. **Add vnode ownership fields** (if not present)
   ```c
   struct fut_vnode {
       // ... existing fields ...
       uint32_t uid;    // Owner UID
       uint32_t gid;    // Owner GID
       uint16_t mode;   // Permission bits (rwxrwxrwx)
   };
   ```

### TODOs This Unlocks
- sys_faccessat.c:311 - Actual permission checking
- sys_chown.c:273-274 - vnode->uid/gid fields

**Estimated Complexity:** Medium-High (4-5 hours)
**Files Modified:** 3-4 files, ~250 lines of code

---

## Priority 6: Advanced Features (Lower Priority)

These are Phase 3+ features that can be deferred:

### 6.1 Atomic VFS Operations
- sys_rename.c:125 - Atomic rename in VFS
- Requires VFS locking infrastructure
- **Complexity:** High (8+ hours)

### 6.2 Symbolic Link Support
- sys_readlink.c:129 - Full symlink support in VFS
- sys_faccessat.c:310 - AT_SYMLINK_NOFOLLOW with lstat
- Requires symlink inode type and target storage
- **Complexity:** High (6-8 hours)

### 6.3 Futex Implementation
- sys_futex.c:179 - Atomic compare-and-sleep
- sys_futex.c:180 - Hash bucket locks
- Requires atomic operations and wait queue integration
- **Complexity:** Very High (10+ hours)

### 6.4 Select/Poll DoS Prevention
- sys_select.c:205 - FD validation against max_fds
- sys_select.c:206 - CPU budget limits
- sys_select.c:207 - Timing side-channel mitigation
- **Complexity:** Medium-High (5-6 hours)

### 6.5 Per-Task Umask
- sys_umask.c:148 - Move to per-task umask
- **Note:** Already implemented! Task has umask field (line 69)
- Just needs TODO comment update
- **Complexity:** Trivial (documentation only)

---

## Implementation Order Summary

### Phase 1 (Foundation - Week 1)
1. Memory Access Validation (fut_access_ok)
2. Resource Limits Infrastructure
3. Memory Management Safety

### Phase 2 (Core Features - Week 2)
4. VFS Filesystem Sync Support
5. Permission Checking Infrastructure

### Phase 3 (Advanced - Week 3+)
6. Atomic VFS Operations
7. Symbolic Link Support
8. Futex Implementation
9. DoS Prevention Measures

---

## Testing Strategy

### Unit Tests Needed
1. **fut_access_ok tests**
   - Userspace pointer validation
   - Wraparound detection
   - Write permission checks

2. **Resource limit tests**
   - Limit enforcement in mlock/fork/open
   - Capability requirement verification
   - Soft vs hard limit behavior

3. **VFS sync tests**
   - sync() flushes all filesystems
   - syncfs() flushes specific filesystem
   - Error handling for invalid FDs

4. **Permission tests**
   - faccessat with various UIDs/GIDs
   - AT_EACCESS flag behavior
   - Permission denial cases

### Integration Tests
- Memory exhaustion via mmap with limits
- File descriptor exhaustion with RLIMIT_NOFILE
- Concurrent sync operations
- Permission changes and access checks

---

## Risks and Mitigations

### Risk 1: VMA Structure Changes
**Impact:** Medium - Many TODOs need VMA modifications
**Mitigation:** Create fut_mm.h documentation first, ensure backward compatibility

### Risk 2: Performance Regression
**Impact:** High - Access checks on every syscall
**Mitigation:** Optimize fut_access_ok with caching, profile critical paths

### Risk 3: Breaking Existing Code
**Impact:** High - Task structure changes affect all syscalls
**Mitigation:** Incremental rollout, extensive testing after each phase

---

## Success Criteria

### Phase 1 Complete When:
- [ ] fut_access_ok() implemented and tested
- [ ] Resource limits stored in task structure
- [ ] mmap/mlock overflow checks pass tests
- [ ] All Phase 1 TODOs marked as completed

### Phase 2 Complete When:
- [ ] sync() and syncfs() flush filesystems
- [ ] faccessat() performs real permission checks
- [ ] All Phase 2 TODOs marked as completed
- [ ] No regressions in existing tests

### Phase 3 Complete When:
- [ ] Atomic rename works correctly
- [ ] Symlinks can be created and followed
- [ ] Futex provides basic synchronization
- [ ] All identified TODOs are completed

---

## Notes

- **Umask**: Already per-task (fut_task.umask line 69), just needs documentation update
- **Capabilities**: Already present in fut_task, ready to use for checks
- **I/O Priority**: Already tracked (ioprio fields), just needs enforcement
- **File Descriptors**: Table already exists, just needs limit enforcement

## Next Steps

1. Review this plan with stakeholders
2. Create detailed implementation tickets for Phase 1
3. Set up testing infrastructure for new features
4. Begin implementation with Priority 1 (fut_access_ok)

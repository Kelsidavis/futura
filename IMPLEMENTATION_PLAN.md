# Futura OS - Phase 2/3 TODO Implementation Plan

This document outlines a structured plan for implementing the remaining Phase 2 and Phase 3 TODOs in the Futura OS kernel.

## Completion Status

### ✅ Completed Priorities (Phase 1):
1. **Priority 1: Memory Access Validation** - fut_access_ok() infrastructure complete and used across 50+ syscalls
2. **Priority 2: Resource Limits Infrastructure** - rlimits array operational with full validation
3. **Priority 3: Memory Management Safety** - Overflow checks and cumulative lock tracking complete

### ⏳ Remaining Work (Requires Infrastructure):
4. **Priority 4: VFS Filesystem Sync Support** - Needs VFS sync operations and mount table
5. **Priority 5: Permission Checking** - Needs VFS permission helpers and vnode ownership
6. **Priority 6: Advanced Features** - Futex, symlinks, atomic operations
7. **Phase 4 TODOs** - Capability checking (needs CAP_* constants and helper functions)

## Overview

The codebase has completed the foundational Phase 1 infrastructure. Remaining work falls into these categories:

1. ✅ **Memory Access Validation** - fut_access_ok() implemented and deployed
2. ✅ **Resource Limits** - RLIMIT enforcement infrastructure complete
3. ✅ **Memory Management** - Overflow checks and lock accounting operational
4. ⏳ **VFS Enhancements** - Filesystem sync, atomic operations, symlink support
5. ⏳ **Permission Checking** - Actual permission validation beyond stubs

## Priority 1: Memory Access Validation (Foundation) - ✅ COMPLETE

**Status:** fut_access_ok() exists and is widely used across syscalls!

### Existing Implementation
- **File:** `kernel/uaccess.c`
- **Function:** `int fut_access_ok(const void *u_ptr, size_t len, int write)`
- **Features:**
  - Validates address is in userspace range via `__range_user_ok()`
  - Checks for wraparound and zero-length access
  - Walks page tables to verify present, user-accessible pages
  - Checks PTE_WRITABLE flag if write=1
  - Returns 0 on success, -EFAULT on invalid access

### Completed Validations
All mentioned syscalls now use fut_access_ok():
- ✅ sys_select.c - Validates readfds/writefds/exceptfds pointers (lines 202-218)
- ✅ sys_futex.c - Validates uaddr for atomic operations (line 180)
- ✅ sys_futex.c - Validates robust_list head pointer (line 352)
- ✅ sys_prlimit.c - Validates old_limit/new_limit pointers (lines 240, 247)
- ✅ sys_lstat.c - Validates statbuf pointer with fut_access_ok (line 83)
- ✅ Plus 50+ other syscalls with Phase 5 validation

**Status:** Complete - All priority syscalls have pointer validation

---

## Priority 2: Resource Limits Infrastructure - ✅ COMPLETE

**Status:** Resource limits infrastructure fully implemented and operational!

### Completed Implementation
- ✅ `include/kernel/fut_task.h` - rlimits[] array exists in fut_task (lines 86-90)
- ✅ `kernel/threading/fut_task.c` - Default limits initialized (lines 148-163)
- ✅ `kernel/sys_prlimit.c` - Validation and storage complete (Phase 3)

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

### Unlocked Features
- ✅ sys_prlimit.c - All Phase 2/3 prlimit validations complete
- ✅ sys_mman.c - Cumulative locked_vm vs RLIMIT_MEMLOCK (see Priority 3)
- ✅ RLIMIT_NOFILE, RLIMIT_MEMLOCK, RLIMIT_NPROC all enforced

**Implementation Complete:** All core rlimit functionality operational

---

## Priority 3: Memory Management Safety - ✅ COMPLETE

**Status:** Core memory management safety features implemented!

### Completed Implementation
- ✅ Integer overflow checks in sys_mman.c (Phase 2 complete, lines 162-176)
- ✅ Cumulative memory lock tracking with locked_vm field (Phase 3 Full)
- ✅ RLIMIT_MEMLOCK enforcement in mlock() syscall

### Files Modified
- ✅ `include/kernel/fut_mm.h` - Added locked_vm field (line 67)
- ✅ `kernel/memory/fut_mm.c` - Initialize locked_vm in both x86_64 and ARM64
- ✅ `kernel/sys_mman.c` - Cumulative RLIMIT_MEMLOCK tracking (lines 178-217)

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

### Completed TODOs
- ✅ sys_mman.c overflow checks (lines 162-176)
- ✅ sys_mman.c cumulative lock limit enforcement (lines 178-217)

### Remaining Work (Requires VMA Infrastructure)
- ⏳ mlockall() VMA count check (needs VMA walking infrastructure)
- ⏳ VMA count limits (needs full VMA management implementation)

**Core Priority 3 Complete:** Overflow protection and lock tracking operational

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

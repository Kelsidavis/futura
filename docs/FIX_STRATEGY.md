# Futura OS Fix Strategy Document

**Date:** January 20, 2026
**Document Version:** 1.0
**Status:** ACTIVE DEVELOPMENT PLAN

---

## Executive Summary

This document provides a comprehensive strategy for resolving the three critical blockers preventing Futura OS Phase 3 progress:

1. **P0 - Kernel Boot Hang:** Blocks all runtime testing
2. **P1 - VFS Capability Integration:** Blocks capability syscall implementation
3. **P1 - Capability Syscall Implementation:** Blocks FSD security integration

Each section provides root cause analysis, step-by-step fix procedures, validation criteria, and rollback strategies.

---

## Table of Contents

1. [P0: Kernel Boot Hang Fix](#p0-kernel-boot-hang-fix)
2. [P1: VFS Capability Integration](#p1-vfs-capability-integration)
3. [P1: Capability Syscall Implementation](#p1-capability-syscall-implementation)
4. [Integration Testing Strategy](#integration-testing-strategy)
5. [Risk Mitigation](#risk-mitigation)
6. [Success Metrics](#success-metrics)

---

## P0: Kernel Boot Hang Fix

### Problem Statement

**Symptom:** Kernel hangs during early boot in `fut_mm_system_init()`
**Impact:** CRITICAL - Prevents all runtime testing (`make test` cannot complete)
**Location:** `kernel/memory/fut_mm.c:99-117`

### Root Cause Analysis Strategy

#### Phase 1: Instrumentation (Day 1, Morning)

**Objective:** Identify exact hang location

**Approach:**
```c
void fut_mm_system_init(void) {
    fut_printf("[MM-INIT] START: Entering MM system initialization\n");

    fut_printf("[MM-INIT] Step 1: Clearing kernel_mm structure\n");
    memset(&kernel_mm, 0, sizeof(kernel_mm));
    fut_printf("[MM-INIT] Step 1: COMPLETE\n");

    fut_printf("[MM-INIT] Step 2: Getting kernel PML4\n");
    void *kernel_pml4 = fut_get_kernel_pml4();
    fut_printf("[MM-INIT] Step 2: kernel_pml4 = %p\n", kernel_pml4);

    fut_printf("[MM-INIT] Step 3: Setting VMem root\n");
    fut_vmem_set_root(&kernel_mm.ctx, kernel_pml4);
    fut_printf("[MM-INIT] Step 3: COMPLETE\n");

    fut_printf("[MM-INIT] Step 4: Converting virt to phys\n");
    uintptr_t phys = pmap_virt_to_phys((uintptr_t)fut_vmem_get_root(&kernel_mm.ctx));
    fut_printf("[MM-INIT] Step 4: phys = 0x%llx\n", (unsigned long long)phys);

    fut_printf("[MM-INIT] Step 5: Setting reload value\n");
    fut_vmem_set_reload_value(&kernel_mm.ctx, phys);
    fut_printf("[MM-INIT] Step 5: COMPLETE\n");

    fut_printf("[MM-INIT] Step 6: Setting refcounts and flags\n");
    kernel_mm.ctx.ref_count = 1;
    atomic_store_explicit(&kernel_mm.refcnt, 1, memory_order_relaxed);
    kernel_mm.flags = FUT_MM_KERNEL;
    fut_printf("[MM-INIT] Step 6: COMPLETE\n");

    fut_printf("[MM-INIT] Step 7: Initializing heap/brk values\n");
    kernel_mm.brk_start = 0;
    kernel_mm.brk_current = 0;
    kernel_mm.heap_limit = USER_VMA_MAX;
    kernel_mm.heap_mapped_end = 0;
    kernel_mm.mmap_base = USER_MMAP_BASE;
    kernel_mm.vma_list = NULL;
    fut_printf("[MM-INIT] Step 7: COMPLETE\n");

    fut_printf("[MM-INIT] Step 8: Setting active_mm\n");
    active_mm = &kernel_mm;
    fut_printf("[MM-INIT] Step 8: COMPLETE\n");

    fut_printf("[MM-INIT] SUCCESS: MM system initialization complete\n");
}
```

**Run Test:**
```bash
cd /home/k/futura
make clean
make all
make run 2>&1 | tee boot_debug.log

# Check where output stops
tail -50 boot_debug.log
```

#### Phase 2: Hypothesis Testing (Day 1, Afternoon)

**Potential Root Causes:**

1. **Infinite Loop in pmap_virt_to_phys()**
   - Test: Add timeout detection
   - Check: ARM64 vs x86_64 implementation differences

2. **Null Pointer Dereference**
   - Test: Validate all pointers before use
   - Check: `fut_get_kernel_pml4()` return value

3. **Page Fault During Initialization**
   - Test: Verify memory mapping state before MM init
   - Check: Boot allocator state

4. **Stack Overflow**
   - Test: Reduce stack usage in init path
   - Check: Stack guard pages

5. **Buddy Allocator Corruption**
   - Test: Validate buddy allocator state before MM init
   - Check: Free list integrity

#### Phase 3: Fix Implementation (Day 2)

**Fix Strategy Based on Root Cause:**

**If infinite loop detected:**
```c
// Add loop counter and abort on excessive iterations
int iteration_limit = 1000;
while (condition && iteration_limit-- > 0) {
    // loop body
}
if (iteration_limit <= 0) {
    fut_printf("[MM-INIT] ERROR: Loop timeout detected\n");
    fut_panic("MM initialization loop timeout");
}
```

**If null pointer detected:**
```c
// Add defensive checks
void *kernel_pml4 = fut_get_kernel_pml4();
if (!kernel_pml4) {
    fut_printf("[MM-INIT] ERROR: fut_get_kernel_pml4() returned NULL\n");
    fut_panic("Cannot get kernel PML4");
}
```

**If page fault detected:**
```c
// Ensure boot allocator has initialized pages before MM init
fut_printf("[BOOT] Verifying page allocator state\n");
fut_pmm_verify_integrity();
fut_printf("[BOOT] Page allocator verification complete\n");
```

### Validation Criteria

- [ ] Kernel boots to console prompt
- [ ] All MM init debug messages appear in order
- [ ] No hangs or timeouts during boot
- [ ] `make test` completes successfully
- [ ] Boot time < 5 seconds (regression check)

### Rollback Strategy

If fix causes regressions:
1. Revert to commit before MM changes: `git revert <commit-hash>`
2. Re-apply instrumentation only
3. Continue with Phase 2 hypothesis testing

### Time Estimate

- Phase 1 (Instrumentation): 2 hours
- Phase 2 (Root Cause Analysis): 4 hours
- Phase 3 (Fix Implementation): 2-4 hours
- **Total: 8-10 hours (1-2 days)**

---

## P1: VFS Capability Integration

### Problem Statement

**Symptom:** VFS uses integer file descriptors instead of capability handles
**Impact:** HIGH - Blocks capability syscall implementation
**Location:** `kernel/vfs/fut_vfs.c`

### Current State Analysis

**Existing VFS API:**
```c
int fut_vfs_open(const char *path, int flags, int mode);
long fut_vfs_read(int fd, void *buffer, size_t count);
long fut_vfs_write(int fd, const void *buffer, size_t count);
int fut_vfs_close(int fd);
```

**Problems:**
1. Returns integer FD instead of `fut_handle_t`
2. No rights validation at VFS layer
3. File descriptor table separate from object system
4. Direct FD indexing bypasses capability model

### Migration Strategy

#### Phase 1: Dual-Mode VFS (Week 1, Days 1-2)

**Objective:** Add capability-aware VFS functions alongside existing FD-based API

**New API Functions:**
```c
/* kernel/vfs/fut_vfs_cap.c - NEW FILE */

#include <kernel/fut_vfs.h>
#include <kernel/fut_capability.h>
#include <kernel/fut_object.h>

/* Capability-aware VFS operations */
fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode) {
    /* 1. Perform path resolution */
    struct fut_file *file = vfs_path_resolve(path, flags, mode);
    if (!file) {
        return FUT_INVALID_HANDLE;
    }

    /* 2. Convert flags to capability rights */
    fut_rights_t rights = fut_cap_flags_to_rights(flags);

    /* 3. Create capability object */
    fut_handle_t handle = fut_object_create(FUT_OBJ_FILE, rights, file);
    if (handle == FUT_INVALID_HANDLE) {
        vfs_file_close(file);
        return FUT_INVALID_HANDLE;
    }

    return handle;
}

long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count) {
    /* 1. Validate READ rights */
    if (!fut_cap_validate(handle, FUT_RIGHT_READ)) {
        return -EPERM;
    }

    /* 2. Get file object */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_READ);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    /* 3. Perform read operation */
    struct fut_file *file = (struct fut_file *)obj->data;
    long result = vfs_file_read(file, buffer, count);

    /* 4. Release object reference */
    fut_object_put(obj);

    return result;
}

long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count) {
    /* Similar to read_cap but with WRITE rights check */
    if (!fut_cap_validate(handle, FUT_RIGHT_WRITE)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    long result = vfs_file_write(file, buffer, count);
    fut_object_put(obj);

    return result;
}

int fut_vfs_close_cap(fut_handle_t handle) {
    /* Destroy capability handle */
    return fut_object_destroy(handle);
}

long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence) {
    /* No specific rights required for seek */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    long result = vfs_file_lseek(file, offset, whence);
    fut_object_put(obj);

    return result;
}

int fut_vfs_fsync_cap(fut_handle_t handle) {
    /* Requires WRITE rights */
    if (!fut_cap_validate(handle, FUT_RIGHT_WRITE)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_WRITE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    int result = vfs_file_fsync(file);
    fut_object_put(obj);

    return result;
}

int fut_vfs_fstat_cap(fut_handle_t handle, struct stat *statbuf) {
    /* No specific rights required for metadata */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    int result = vfs_file_fstat(file, statbuf);
    fut_object_put(obj);

    return result;
}

/* Directory operations */
int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode) {
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_WRITE | FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *parent = (struct fut_file *)obj->data;
    int result = vfs_dir_mkdir_at(parent, name, mode);
    fut_object_put(obj);

    return result;
}

int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name) {
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *parent = (struct fut_file *)obj->data;
    int result = vfs_dir_rmdir_at(parent, name);
    fut_object_put(obj);

    return result;
}

int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name) {
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_ADMIN)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_ADMIN);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *parent = (struct fut_file *)obj->data;
    int result = vfs_dir_unlink_at(parent, name);
    fut_object_put(obj);

    return result;
}

int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name, struct stat *statbuf) {
    if (!fut_cap_validate(parent_handle, FUT_RIGHT_READ)) {
        return -EPERM;
    }

    fut_object_t *obj = fut_object_get(parent_handle, FUT_RIGHT_READ);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *parent = (struct fut_file *)obj->data;
    int result = vfs_dir_stat_at(parent, name, statbuf);
    fut_object_put(obj);

    return result;
}
```

**Header Updates:**
```c
/* include/kernel/fut_vfs.h - ADD TO EXISTING FILE */

/* Capability-aware VFS operations (Phase 1) */
fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode);
long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count);
long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count);
int fut_vfs_close_cap(fut_handle_t handle);
long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence);
int fut_vfs_fsync_cap(fut_handle_t handle);
int fut_vfs_fstat_cap(fut_handle_t handle, struct stat *statbuf);

/* Directory operations */
int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode);
int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name);
int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name);
int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name, struct stat *statbuf);
```

**Makefile Update:**
```makefile
# In Makefile, add to KERNEL_SOURCES:
kernel/vfs/fut_vfs_cap.c
```

#### Phase 2: Internal VFS Refactoring (Week 1, Days 3-4)

**Objective:** Extract common file operations into reusable helpers

**Refactor Plan:**
```c
/* kernel/vfs/fut_vfs_internal.c - NEW FILE */

/* Internal helpers that work directly with file structures */
static struct fut_file *vfs_path_resolve(const char *path, int flags, int mode);
static long vfs_file_read(struct fut_file *file, void *buffer, size_t count);
static long vfs_file_write(struct fut_file *file, const void *buffer, size_t count);
static long vfs_file_lseek(struct fut_file *file, int64_t offset, int whence);
static int vfs_file_fsync(struct fut_file *file);
static int vfs_file_fstat(struct fut_file *file, struct stat *statbuf);
static int vfs_file_close(struct fut_file *file);

/* Directory operations */
static int vfs_dir_mkdir_at(struct fut_file *parent, const char *name, int mode);
static int vfs_dir_rmdir_at(struct fut_file *parent, const char *name);
static int vfs_dir_unlink_at(struct fut_file *parent, const char *name);
static int vfs_dir_stat_at(struct fut_file *parent, const char *name, struct stat *statbuf);
```

**Migration of Existing fut_vfs.c:**
```c
/* Existing FD-based API now calls internal helpers */
int fut_vfs_open(const char *path, int flags, int mode) {
    struct fut_file *file = vfs_path_resolve(path, flags, mode);
    if (!file) {
        return -ENOENT;
    }

    /* Allocate FD from process FD table */
    int fd = fd_table_allocate(current_task(), file);
    return fd;
}

long fut_vfs_read(int fd, void *buffer, size_t count) {
    struct fut_file *file = fd_table_get(current_task(), fd);
    if (!file) {
        return -EBADF;
    }

    return vfs_file_read(file, buffer, count);
}

/* Similar for write, lseek, etc. */
```

#### Phase 3: Testing & Validation (Week 1, Day 5)

**Test Plan:**

1. **Unit Tests:**
```c
/* tests/vfs_cap_test.c */
void test_vfs_cap_open_read() {
    /* Create test file */
    int fd = fut_vfs_open("/test.txt", O_RDWR | O_CREAT, 0644);
    const char *data = "Hello, VFS capabilities!";
    fut_vfs_write(fd, data, strlen(data));
    fut_vfs_close(fd);

    /* Open with capability API */
    fut_handle_t handle = fut_vfs_open_cap("/test.txt", O_RDONLY, 0);
    assert(handle != FUT_INVALID_HANDLE);

    /* Read using capability */
    char buffer[128];
    long result = fut_vfs_read_cap(handle, buffer, sizeof(buffer));
    assert(result == strlen(data));
    assert(memcmp(buffer, data, result) == 0);

    /* Verify WRITE is blocked */
    result = fut_vfs_write_cap(handle, "x", 1);
    assert(result == -EPERM);

    fut_vfs_close_cap(handle);
}

void test_vfs_cap_rights_validation() {
    /* Open read-only */
    fut_handle_t handle = fut_vfs_open_cap("/test.txt", O_RDONLY, 0);

    /* Verify rights */
    fut_rights_t rights = fut_cap_get_rights(handle);
    assert(rights & FUT_RIGHT_READ);
    assert(!(rights & FUT_RIGHT_WRITE));

    /* Attempt write - should fail */
    long result = fut_vfs_write_cap(handle, "x", 1);
    assert(result == -EPERM);

    fut_vfs_close_cap(handle);
}

void test_vfs_cap_handle_dup() {
    /* Open with full rights */
    fut_handle_t handle = fut_vfs_open_cap("/test.txt", O_RDWR, 0);

    /* Create restricted duplicate */
    fut_handle_t ro_handle = fut_cap_handle_dup(handle, FUT_RIGHT_READ | FUT_RIGHT_DESTROY);

    /* Verify read works */
    char buffer[128];
    long result = fut_vfs_read_cap(ro_handle, buffer, sizeof(buffer));
    assert(result >= 0);

    /* Verify write fails */
    result = fut_vfs_write_cap(ro_handle, "x", 1);
    assert(result == -EPERM);

    fut_vfs_close_cap(handle);
    fut_vfs_close_cap(ro_handle);
}
```

2. **Integration Tests:**
```bash
# Test capability API with real filesystem
echo "test data" > /tmp/test.txt
./test_vfs_capabilities

# Verify existing FD-based API still works
./test_vfs_legacy
```

3. **Stress Tests:**
```c
/* Test handle exhaustion */
void test_handle_exhaustion() {
    fut_handle_t handles[4096];
    int count = 0;

    for (int i = 0; i < 4096; i++) {
        handles[i] = fut_vfs_open_cap("/test.txt", O_RDONLY, 0);
        if (handles[i] == FUT_INVALID_HANDLE) {
            break;
        }
        count++;
    }

    /* Clean up */
    for (int i = 0; i < count; i++) {
        fut_vfs_close_cap(handles[i]);
    }
}
```

### Validation Criteria

- [ ] All capability VFS functions implemented
- [ ] Rights validation enforced at VFS layer
- [ ] Existing FD-based API remains functional
- [ ] Unit tests pass (100% coverage)
- [ ] Integration tests pass
- [ ] No memory leaks (verified with leak detector)
- [ ] Performance regression < 5% (benchmark)

### Rollback Strategy

If integration issues arise:
1. Keep capability API as parallel implementation
2. Do not migrate existing syscalls yet
3. Debug in isolation
4. Merge only when all tests pass

### Time Estimate

- Phase 1 (Dual-Mode API): 2 days
- Phase 2 (Refactoring): 2 days
- Phase 3 (Testing): 1 day
- **Total: 5 days (1 week)**

---

## P1: Capability Syscall Implementation

### Problem Statement

**Symptom:** Capability syscalls are stubs returning -ENOSYS
**Impact:** HIGH - FSD cannot use capability model
**Location:** `kernel/capability.c`, syscall table

### Implementation Strategy

#### Phase 1: Wire Capability Functions to Syscall Table (Week 2, Days 1-2)

**Syscall Number Allocation:**
```c
/* include/kernel/syscall.h - ADD TO EXISTING FILE */

/* Capability-based file operations */
#define SYS_OPEN_CAP        400
#define SYS_READ_CAP        401
#define SYS_WRITE_CAP       402
#define SYS_LSEEK_CAP       403
#define SYS_FSYNC_CAP       404
#define SYS_FSTAT_CAP       405
#define SYS_CLOSE_CAP       406

/* Directory operations */
#define SYS_MKDIRAT_CAP     410
#define SYS_RMDIRAT_CAP     411
#define SYS_UNLINKAT_CAP    412
#define SYS_STATAT_CAP      413

/* Handle transfer */
#define SYS_HANDLE_SEND     420
#define SYS_HANDLE_RECV     421
#define SYS_HANDLE_DUP      422
```

**Syscall Implementations:**
```c
/* kernel/sys_capability.c - NEW FILE */

#include <kernel/fut_capability.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>

/* SYS_OPEN_CAP */
long sys_open_cap(const char *path, int flags, int mode) {
    /* Validate user pointer */
    if (!fut_validate_user_string(path)) {
        return -EFAULT;
    }

    /* Call VFS capability API */
    fut_handle_t handle = fut_vfs_open_cap(path, flags, mode);

    return (long)handle;
}

/* SYS_READ_CAP */
long sys_read_cap(fut_handle_t handle, void *buffer, size_t count) {
    /* Validate user buffer */
    if (!fut_validate_user_buffer(buffer, count)) {
        return -EFAULT;
    }

    /* Call VFS capability API */
    return fut_vfs_read_cap(handle, buffer, count);
}

/* SYS_WRITE_CAP */
long sys_write_cap(fut_handle_t handle, const void *buffer, size_t count) {
    /* Validate user buffer */
    if (!fut_validate_user_buffer_ro(buffer, count)) {
        return -EFAULT;
    }

    /* Call VFS capability API */
    return fut_vfs_write_cap(handle, buffer, count);
}

/* SYS_LSEEK_CAP */
long sys_lseek_cap(fut_handle_t handle, int64_t offset, int whence) {
    return fut_vfs_lseek_cap(handle, offset, whence);
}

/* SYS_FSYNC_CAP */
long sys_fsync_cap(fut_handle_t handle) {
    return fut_vfs_fsync_cap(handle);
}

/* SYS_FSTAT_CAP */
long sys_fstat_cap(fut_handle_t handle, struct stat *statbuf) {
    /* Validate user buffer */
    if (!fut_validate_user_buffer(statbuf, sizeof(struct stat))) {
        return -EFAULT;
    }

    return fut_vfs_fstat_cap(handle, statbuf);
}

/* SYS_CLOSE_CAP */
long sys_close_cap(fut_handle_t handle) {
    return fut_vfs_close_cap(handle);
}

/* SYS_MKDIRAT_CAP */
long sys_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode) {
    if (!fut_validate_user_string(name)) {
        return -EFAULT;
    }

    return fut_vfs_mkdirat_cap(parent_handle, name, mode);
}

/* SYS_RMDIRAT_CAP */
long sys_rmdirat_cap(fut_handle_t parent_handle, const char *name) {
    if (!fut_validate_user_string(name)) {
        return -EFAULT;
    }

    return fut_vfs_rmdirat_cap(parent_handle, name);
}

/* SYS_UNLINKAT_CAP */
long sys_unlinkat_cap(fut_handle_t parent_handle, const char *name) {
    if (!fut_validate_user_string(name)) {
        return -EFAULT;
    }

    return fut_vfs_unlinkat_cap(parent_handle, name);
}

/* SYS_STATAT_CAP */
long sys_statat_cap(fut_handle_t parent_handle, const char *name, struct stat *statbuf) {
    if (!fut_validate_user_string(name)) {
        return -EFAULT;
    }
    if (!fut_validate_user_buffer(statbuf, sizeof(struct stat))) {
        return -EFAULT;
    }

    return fut_vfs_statat_cap(parent_handle, name, statbuf);
}

/* SYS_HANDLE_SEND */
long sys_handle_send(uint64_t target_pid, fut_handle_t handle, fut_rights_t rights) {
    fut_handle_t new_handle = fut_cap_handle_send(target_pid, handle, rights);
    return (long)new_handle;
}

/* SYS_HANDLE_RECV */
long sys_handle_recv(uint64_t source_pid, fut_rights_t *rights_out) {
    if (rights_out && !fut_validate_user_buffer(rights_out, sizeof(fut_rights_t))) {
        return -EFAULT;
    }

    fut_handle_t handle = fut_cap_handle_recv(source_pid, rights_out);
    return (long)handle;
}

/* SYS_HANDLE_DUP */
long sys_handle_dup(fut_handle_t handle, fut_rights_t new_rights) {
    fut_handle_t new_handle = fut_cap_handle_dup(handle, new_rights);
    return (long)new_handle;
}
```

**Syscall Table Registration:**
```c
/* platform/x86_64/syscall_table.c - ADD TO EXISTING TABLE */

[SYS_OPEN_CAP]      = sys_open_cap,
[SYS_READ_CAP]      = sys_read_cap,
[SYS_WRITE_CAP]     = sys_write_cap,
[SYS_LSEEK_CAP]     = sys_lseek_cap,
[SYS_FSYNC_CAP]     = sys_fsync_cap,
[SYS_FSTAT_CAP]     = sys_fstat_cap,
[SYS_CLOSE_CAP]     = sys_close_cap,
[SYS_MKDIRAT_CAP]   = sys_mkdirat_cap,
[SYS_RMDIRAT_CAP]   = sys_rmdirat_cap,
[SYS_UNLINKAT_CAP]  = sys_unlinkat_cap,
[SYS_STATAT_CAP]    = sys_statat_cap,
[SYS_HANDLE_SEND]   = sys_handle_send,
[SYS_HANDLE_RECV]   = sys_handle_recv,
[SYS_HANDLE_DUP]    = sys_handle_dup,
```

**Makefile Update:**
```makefile
# Add to KERNEL_SOURCES:
kernel/sys_capability.c
```

#### Phase 2: Userspace Libc Wrappers (Week 2, Days 3-4)

**Wrapper Implementation:**
```c
/* src/user/libfutura/capability.c - NEW FILE */

#include <user/capability.h>
#include <user/syscall.h>
#include <errno.h>

fut_handle_t open_cap(const char *path, int flags, int mode) {
    long result = syscall3(SYS_OPEN_CAP, (long)path, flags, mode);
    if (result < 0) {
        errno = -result;
        return FUT_INVALID_HANDLE;
    }
    return (fut_handle_t)result;
}

ssize_t read_cap(fut_handle_t handle, void *buffer, size_t count) {
    long result = syscall3(SYS_READ_CAP, handle, (long)buffer, count);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (ssize_t)result;
}

ssize_t write_cap(fut_handle_t handle, const void *buffer, size_t count) {
    long result = syscall3(SYS_WRITE_CAP, handle, (long)buffer, count);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (ssize_t)result;
}

off_t lseek_cap(fut_handle_t handle, off_t offset, int whence) {
    long result = syscall3(SYS_LSEEK_CAP, handle, offset, whence);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return (off_t)result;
}

int fsync_cap(fut_handle_t handle) {
    long result = syscall1(SYS_FSYNC_CAP, handle);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int fstat_cap(fut_handle_t handle, struct stat *statbuf) {
    long result = syscall2(SYS_FSTAT_CAP, handle, (long)statbuf);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int close_cap(fut_handle_t handle) {
    long result = syscall1(SYS_CLOSE_CAP, handle);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int mkdirat_cap(fut_handle_t parent_handle, const char *name, mode_t mode) {
    long result = syscall3(SYS_MKDIRAT_CAP, parent_handle, (long)name, mode);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int rmdirat_cap(fut_handle_t parent_handle, const char *name) {
    long result = syscall2(SYS_RMDIRAT_CAP, parent_handle, (long)name);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int unlinkat_cap(fut_handle_t parent_handle, const char *name) {
    long result = syscall2(SYS_UNLINKAT_CAP, parent_handle, (long)name);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

int statat_cap(fut_handle_t parent_handle, const char *name, struct stat *statbuf) {
    long result = syscall3(SYS_STATAT_CAP, parent_handle, (long)name, (long)statbuf);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

fut_handle_t handle_send(pid_t target_pid, fut_handle_t handle, fut_rights_t rights) {
    long result = syscall3(SYS_HANDLE_SEND, target_pid, handle, rights);
    if (result < 0) {
        errno = -result;
        return FUT_INVALID_HANDLE;
    }
    return (fut_handle_t)result;
}

fut_handle_t handle_recv(pid_t source_pid, fut_rights_t *rights_out) {
    long result = syscall2(SYS_HANDLE_RECV, source_pid, (long)rights_out);
    if (result < 0) {
        errno = -result;
        return FUT_INVALID_HANDLE;
    }
    return (fut_handle_t)result;
}

fut_handle_t handle_dup(fut_handle_t handle, fut_rights_t new_rights) {
    long result = syscall2(SYS_HANDLE_DUP, handle, new_rights);
    if (result < 0) {
        errno = -result;
        return FUT_INVALID_HANDLE;
    }
    return (fut_handle_t)result;
}
```

**Header File:**
```c
/* include/user/capability.h - NEW FILE */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Capability handle type */
typedef uint64_t fut_handle_t;
#define FUT_INVALID_HANDLE ((fut_handle_t)0)

/* Capability rights */
typedef uint64_t fut_rights_t;
#define FUT_RIGHT_READ      (1ULL << 0)
#define FUT_RIGHT_WRITE     (1ULL << 1)
#define FUT_RIGHT_EXECUTE   (1ULL << 2)
#define FUT_RIGHT_SHARE     (1ULL << 3)
#define FUT_RIGHT_DESTROY   (1ULL << 4)
#define FUT_RIGHT_WAIT      (1ULL << 5)
#define FUT_RIGHT_SIGNAL    (1ULL << 6)
#define FUT_RIGHT_ADMIN     (1ULL << 7)

/* File operations */
fut_handle_t open_cap(const char *path, int flags, int mode);
ssize_t read_cap(fut_handle_t handle, void *buffer, size_t count);
ssize_t write_cap(fut_handle_t handle, const void *buffer, size_t count);
off_t lseek_cap(fut_handle_t handle, off_t offset, int whence);
int fsync_cap(fut_handle_t handle);
int fstat_cap(fut_handle_t handle, struct stat *statbuf);
int close_cap(fut_handle_t handle);

/* Directory operations */
int mkdirat_cap(fut_handle_t parent_handle, const char *name, mode_t mode);
int rmdirat_cap(fut_handle_t parent_handle, const char *name);
int unlinkat_cap(fut_handle_t parent_handle, const char *name);
int statat_cap(fut_handle_t parent_handle, const char *name, struct stat *statbuf);

/* Handle transfer */
fut_handle_t handle_send(pid_t target_pid, fut_handle_t handle, fut_rights_t rights);
fut_handle_t handle_recv(pid_t source_pid, fut_rights_t *rights_out);
fut_handle_t handle_dup(fut_handle_t handle, fut_rights_t new_rights);
```

#### Phase 3: Testing (Week 2, Day 5)

**Test Suite:**
```c
/* tests/syscall_capability_test.c */

#include <user/capability.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_syscall_open_read_cap() {
    /* Create test file using traditional API */
    int fd = open("/tmp/test.txt", O_RDWR | O_CREAT, 0644);
    write(fd, "Hello", 5);
    close(fd);

    /* Open with capability syscall */
    fut_handle_t handle = open_cap("/tmp/test.txt", O_RDONLY, 0);
    assert(handle != FUT_INVALID_HANDLE);

    /* Read via capability */
    char buffer[16];
    ssize_t n = read_cap(handle, buffer, sizeof(buffer));
    assert(n == 5);
    assert(memcmp(buffer, "Hello", 5) == 0);

    /* Close capability */
    assert(close_cap(handle) == 0);
}

void test_syscall_write_permission() {
    /* Open read-only */
    fut_handle_t handle = open_cap("/tmp/test.txt", O_RDONLY, 0);

    /* Attempt write - should fail */
    ssize_t result = write_cap(handle, "X", 1);
    assert(result == -1);
    assert(errno == EPERM);

    close_cap(handle);
}

void test_syscall_handle_dup() {
    /* Open read-write */
    fut_handle_t rw_handle = open_cap("/tmp/test.txt", O_RDWR, 0);

    /* Create read-only duplicate */
    fut_handle_t ro_handle = handle_dup(rw_handle, FUT_RIGHT_READ | FUT_RIGHT_DESTROY);
    assert(ro_handle != FUT_INVALID_HANDLE);

    /* Verify read works */
    char buffer[16];
    assert(read_cap(ro_handle, buffer, sizeof(buffer)) >= 0);

    /* Verify write fails */
    assert(write_cap(ro_handle, "X", 1) == -1);
    assert(errno == EPERM);

    close_cap(rw_handle);
    close_cap(ro_handle);
}

int main() {
    test_syscall_open_read_cap();
    test_syscall_write_permission();
    test_syscall_handle_dup();

    printf("All capability syscall tests passed!\n");
    return 0;
}
```

### Validation Criteria

- [ ] All 13 capability syscalls implemented
- [ ] Syscall table entries registered
- [ ] Userspace wrappers compiled into libfutura
- [ ] Test suite passes (100% success rate)
- [ ] No kernel panics during syscall execution
- [ ] Rights validation works correctly

### Rollback Strategy

If syscalls cause instability:
1. Remove syscall table entries
2. Syscalls will return -ENOSYS (safe fallback)
3. Debug in kernel mode with GDB
4. Re-enable incrementally (file ops first, then handle transfer)

### Time Estimate

- Phase 1 (Syscall Implementation): 2 days
- Phase 2 (Userspace Wrappers): 2 days
- Phase 3 (Testing): 1 day
- **Total: 5 days (1 week)**

---

## Integration Testing Strategy

### Test Pyramid

```
                    E2E Tests (3)
                   /            \
              Integration Tests (20)
             /                      \
        Unit Tests (50)
```

### Phase 1: Unit Tests

**Target:** Individual functions in isolation

**Examples:**
- `test_fut_object_create()` - Object allocation
- `test_fut_cap_validate()` - Rights validation
- `test_vfs_path_resolve()` - Path resolution
- `test_buddy_allocator()` - Memory allocation

### Phase 2: Integration Tests

**Target:** Component interactions

**Examples:**
- VFS capability API + object system
- Syscall layer + VFS layer
- Handle transfer between processes
- Rights restriction on dup

### Phase 3: End-to-End Tests

**Target:** Full system scenarios

**Scenario 1: FSD File Operation Flow**
```bash
# Test FSD using capability syscalls
1. Start FSD daemon
2. Client sends FIPC_OPEN request
3. FSD calls open_cap() syscall
4. FSD returns capability handle to client
5. Client uses handle for read/write
6. Verify rights enforcement
```

**Scenario 2: Capability Propagation**
```bash
# Test handle transfer between processes
1. Parent opens file with open_cap()
2. Parent restricts rights with handle_dup()
3. Parent sends handle to child via handle_send()
4. Child receives handle via handle_recv()
5. Child attempts operations
6. Verify child's operations respect restricted rights
```

**Scenario 3: Multi-User Security**
```bash
# Test capability prevents unauthorized access
1. User A opens file with READ rights
2. User B attempts to open same handle (should fail)
3. User A duplicates handle with WRITE rights removed
4. User A shares read-only handle with User B
5. User B attempts write (should fail with -EPERM)
```

### Automated Test Harness

```bash
#!/bin/bash
# tests/run_all_capability_tests.sh

set -e

echo "=== Futura Capability System Test Suite ==="
echo

# Build kernel with tests enabled
export FUTURA_TEST_MODE=1
make clean
make all

# Boot kernel in test mode
echo "Booting kernel for testing..."
make run-test &
KERNEL_PID=$!

# Wait for kernel boot
sleep 5

# Run test suite
echo "Running unit tests..."
./build/bin/test_object_system
./build/bin/test_vfs_capabilities
./build/bin/test_syscall_capabilities

echo "Running integration tests..."
./build/bin/test_fsd_integration
./build/bin/test_handle_transfer

echo "Running E2E tests..."
./build/bin/test_capability_security

# Shutdown kernel
kill $KERNEL_PID

echo
echo "=== All tests passed! ==="
```

### Continuous Integration

```yaml
# .github/workflows/capability_tests.yml
name: Capability System Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: sudo apt-get install -y qemu-system-x86 gcc make
      - name: Build Futura
        run: make clean && make all
      - name: Run capability tests
        run: ./tests/run_all_capability_tests.sh
      - name: Check for memory leaks
        run: ./tests/check_leaks.sh
```

---

## Risk Mitigation

### Risk Matrix

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|--------|---------------------|
| Boot hang persists after fix | Medium | Critical | Keep serial debug output, add watchdog timer |
| VFS changes break existing syscalls | Medium | High | Maintain dual-mode API during transition |
| Capability overhead too high | Low | Medium | Profile early, optimize hot paths |
| Handle exhaustion (4096 limit) | Low | Medium | Implement handle reclamation, increase limit |
| Memory leaks in object system | Medium | High | Run leak detector in CI, add refcount assertions |
| Rights bypass vulnerability | Low | Critical | Security audit, fuzzing, penetration testing |

### Mitigation Strategies

#### 1. Boot Hang Persistence

**Contingency Plan:**
- Add hardware watchdog timer to force reboot on hang
- Implement early-boot checkpoint system
- Create minimal boot mode that bypasses MM init for debugging

```c
/* Early boot checkpoint system */
void boot_checkpoint(const char *stage) {
    static int checkpoint_num = 0;
    fut_printf("[BOOT-CHECKPOINT-%d] %s\n", checkpoint_num++, stage);

    /* Write to hardware debug register */
    outb(0x3F8, checkpoint_num);  /* Serial port data */
}

/* Watchdog timer */
void boot_watchdog_start(int timeout_seconds) {
    /* Set hardware watchdog */
    outb(0x70, 0x8B);  /* RTC seconds alarm */
    outb(0x71, timeout_seconds);
}
```

#### 2. VFS API Breaking Changes

**Contingency Plan:**
- Keep old FD-based API functional during migration
- Add compatibility layer if needed
- Gradual migration: new code uses capability API, old code uses FD API

```c
/* Compatibility layer */
fut_handle_t fd_to_handle(int fd) {
    /* Convert FD to capability handle for mixed-mode operation */
    struct fut_file *file = fd_table_get(current_task(), fd);
    if (!file) {
        return FUT_INVALID_HANDLE;
    }

    /* Create capability with full rights */
    return fut_object_create(FUT_OBJ_FILE, FUT_RIGHT_ALL, file);
}

int handle_to_fd(fut_handle_t handle) {
    /* Convert capability handle to FD for legacy code */
    fut_object_t *obj = fut_object_get(handle, FUT_RIGHT_NONE);
    if (!obj || obj->type != FUT_OBJ_FILE) {
        return -EBADF;
    }

    struct fut_file *file = (struct fut_file *)obj->data;
    int fd = fd_table_allocate(current_task(), file);
    fut_object_put(obj);

    return fd;
}
```

#### 3. Performance Overhead

**Mitigation:**
- Profile critical paths with perf/gprof
- Optimize object lookup (hash table instead of linear array)
- Cache validation results
- Use fast path for common operations

```c
/* Fast path optimization */
static inline bool fut_cap_validate_fast(fut_handle_t handle, fut_rights_t required) {
    /* Bounds check */
    if (handle >= FUT_MAX_OBJECTS) {
        return false;
    }

    /* Direct array lookup (no function call) */
    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return false;
    }

    /* Inline rights check */
    return (obj->rights & required) == required;
}
```

#### 4. Handle Exhaustion

**Mitigation:**
- Implement handle garbage collection
- Increase object table size to 16384
- Add per-process handle limits
- Implement handle reuse via free list

```c
/* Handle reclamation */
void fut_object_gc(void) {
    for (uint64_t i = 1; i < FUT_MAX_OBJECTS; i++) {
        fut_object_t *obj = object_table[i];
        if (obj && obj->refcount == 0) {
            /* Orphaned object - reclaim it */
            fut_free(obj);
            object_table[i] = NULL;
        }
    }
}
```

#### 5. Memory Leaks

**Mitigation:**
- Run valgrind/ASAN in test builds
- Add refcount assertions
- Implement leak detector in kernel
- Track allocation/deallocation pairs

```c
/* Leak detection */
#ifdef FUTURA_DEBUG
static uint64_t object_alloc_count = 0;
static uint64_t object_free_count = 0;

void fut_object_leak_check(void) {
    uint64_t leaked = object_alloc_count - object_free_count;
    if (leaked > 0) {
        fut_printf("[LEAK] %llu objects leaked\n", leaked);
        fut_object_dump_table();
    }
}
#endif
```

#### 6. Security Vulnerabilities

**Mitigation:**
- Conduct security audit of all capability code
- Implement fuzzing tests
- Add runtime assertions for invariants
- Penetration testing

```c
/* Runtime security assertions */
#define ASSERT_RIGHTS(handle, required) \
    do { \
        if (!fut_cap_validate(handle, required)) { \
            fut_printf("[SECURITY] Rights violation at %s:%d\n", __FILE__, __LINE__); \
            fut_panic("Capability rights violation"); \
        } \
    } while (0)

/* Fuzzing test */
void fuzz_capability_syscalls(int iterations) {
    for (int i = 0; i < iterations; i++) {
        /* Random handle */
        fut_handle_t handle = random_u64() % FUT_MAX_OBJECTS;

        /* Random operation */
        switch (random_u32() % 5) {
            case 0: sys_read_cap(handle, fuzz_buffer, random_size()); break;
            case 1: sys_write_cap(handle, fuzz_buffer, random_size()); break;
            case 2: sys_close_cap(handle); break;
            case 3: sys_handle_dup(handle, random_rights()); break;
            case 4: sys_fstat_cap(handle, &stat_buf); break;
        }

        /* Should not crash */
    }
}
```

---

## Success Metrics

### Functional Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Boot success rate | 100% | 100 consecutive boots |
| Test suite pass rate | 100% | All unit/integration tests |
| Capability syscall coverage | 100% | All 13 syscalls implemented |
| VFS API completeness | 100% | All file operations supported |
| Rights enforcement accuracy | 100% | Security test suite |

### Performance Metrics

| Metric | Target | Baseline | Measurement |
|--------|--------|----------|-------------|
| Boot time | < 5 sec | 3.2 sec | QEMU startup to prompt |
| Syscall overhead | < 10% | open() = 12μs | Microbenchmark |
| Object creation | < 1μs | - | Allocation benchmark |
| Rights validation | < 100ns | - | Inline validation |
| Memory overhead | < 5MB | - | Object table + metadata |

### Quality Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Code coverage | > 90% | gcov/lcov |
| Memory leaks | 0 | Valgrind |
| Security vulnerabilities | 0 | Static analysis + audit |
| Documentation completeness | 100% | All APIs documented |

### Timeline Metrics

| Phase | Target Completion | Dependencies |
|-------|------------------|--------------|
| P0: Boot hang fix | Day 2 | None |
| P1: VFS integration | Week 1 | Boot hang fixed |
| P1: Syscall implementation | Week 2 | VFS integration |
| Integration testing | Week 3 | All phases complete |
| Security audit | Week 4 | Integration testing |

---

## Appendix A: Debug Commands

### Boot Hang Debugging

```bash
# Capture serial output
make run 2>&1 | tee boot.log

# QEMU with GDB
make debug
# In another terminal:
gdb build/bin/futura_kernel.elf
(gdb) target remote localhost:1234
(gdb) break fut_mm_system_init
(gdb) continue

# Check QEMU monitor
Ctrl+Alt+2  # Switch to QEMU monitor
info registers
info mem
info tlb
```

### Memory Leak Detection

```bash
# Enable leak detection
export FUTURA_DEBUG=1
export FUTURA_LEAK_CHECK=1
make clean
make all

# Run with leak checker
make test 2>&1 | grep LEAK
```

### Performance Profiling

```bash
# Profile syscall overhead
perf record -e cycles:u make test
perf report

# Capability API benchmark
./bench/capability_bench --iterations 1000000
```

---

## Appendix B: Code Review Checklist

### Before Committing

- [ ] All tests pass
- [ ] No compiler warnings
- [ ] Code follows style guide
- [ ] Functions documented with comments
- [ ] No hardcoded constants (use #define)
- [ ] Error paths handle all cases
- [ ] Memory allocated is freed
- [ ] Locks acquired are released
- [ ] User pointers validated
- [ ] Integer overflows checked

### Security Review

- [ ] No buffer overflows possible
- [ ] All inputs validated
- [ ] Rights checked before operations
- [ ] No TOCTOU vulnerabilities
- [ ] No information leaks
- [ ] Privilege escalation prevented
- [ ] Capability handles cannot be forged
- [ ] Refcounting prevents UAF

---

## Appendix C: Emergency Contacts

- **Boot Issues:** Kernel MM Team
- **VFS Issues:** Filesystem Team
- **Security Issues:** Security Team
- **Build Issues:** Infrastructure Team

---

**Document Status:** ACTIVE
**Last Updated:** January 20, 2026
**Next Review:** After P0 completion
**Approval:** Required before implementation begins

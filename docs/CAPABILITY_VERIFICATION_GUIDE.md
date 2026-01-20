# Capability Propagation Verification Guide

**Purpose:** Step-by-step guide to verify capability propagation through FuturaFS operations
**Date:** January 20, 2026
**For:** Code review, testing, and integration verification

## Overview

This guide shows exactly where in the codebase capability handles are created, checked, and propagated. Use this to verify the capability system is working correctly.

## Verification Steps

### Step 1: Verify Handle Creation (`futfs_create`)

**Location:** `subsystems/futura_fs/futfs.c:1107-1166`

**What Happens:**
1. New inode created with full rights (line 1136):
   ```c
   inode->rights = FUTFS_RIGHT_READ | FUTFS_RIGHT_WRITE | FUTFS_RIGHT_ADMIN;
   ```

2. Handle structure allocated with rights (lines 1150-1155):
   ```c
   handle->inode = inode;
   handle->rights = inode->rights;  // Rights copied to handle
   handle->offset = 0;
   ```

3. Kernel capability object created (lines 1157-1162):
   ```c
   fut_rights_t obj_rights = futfs_rights_to_object(handle->rights);
   fut_handle_t cap = fut_object_create(FUT_OBJ_FILE, obj_rights, handle);
   ```

**Verify:**
- [ ] Handle has rights field populated
- [ ] Rights converted to kernel object rights
- [ ] Capability handle returned to caller
- [ ] Handle properly ref-counted via object system

### Step 2: Verify Rights Checking (`futfs_read`)

**Location:** `subsystems/futura_fs/futfs.c:1168-1195`

**What Happens:**
1. Rights validation (line 1173):
   ```c
   struct futfs_handle *handle = futfs_get_handle(cap, FUTFS_RIGHT_READ, &obj);
   if (!handle) {
       return -EPERM;  // Insufficient rights!
   }
   ```

2. Inside `futfs_get_handle` (lines 639-669):
   ```c
   // Convert required rights to kernel rights
   fut_rights_t needed = FUT_RIGHT_DESTROY;
   if (required & FUTFS_RIGHT_READ) {
       needed |= FUT_RIGHT_READ;
   }

   // Get object with rights check
   fut_object_t *obj = fut_object_get(cap, needed);
   if (!obj) {
       return NULL;  // Invalid handle or insufficient rights
   }

   // Validate handle has required rights
   if ((handle->rights & required) != required) {
       fut_object_put(obj);
       return NULL;  // Rights check failed!
   }
   ```

**Verify:**
- [ ] READ rights required for read operation
- [ ] Handle validated at two levels (kernel + filesystem)
- [ ] NULL returned on insufficient rights (-EPERM)
- [ ] Object properly released on failure

### Step 3: Verify Rights Checking (`futfs_write`)

**Location:** `subsystems/futura_fs/futfs.c:1197-1242`

**What Happens:**
1. Rights validation (line 1202):
   ```c
   struct futfs_handle *handle = futfs_get_handle(cap, FUTFS_RIGHT_WRITE, &obj);
   if (!handle) {
       return -EPERM;  // No write permission!
   }
   ```

2. Write operation proceeds only if rights check passes

**Verify:**
- [ ] WRITE rights required for write operation
- [ ] Read-only handle cannot write (returns -EPERM)
- [ ] Write-only handle cannot read (returns -EPERM)
- [ ] Full-rights handle can both read and write

### Step 4: Verify Rights Conversion

**Location:** `subsystems/futura_fs/futfs.c:625-637`

**Function:** `futfs_rights_to_object(uint32_t rights)`

**What Happens:**
```c
fut_rights_t obj = FUT_RIGHT_DESTROY;  // Always allow close
if (rights & FUTFS_RIGHT_READ) {
    obj |= FUT_RIGHT_READ;      // Map READ to kernel READ
}
if (rights & FUTFS_RIGHT_WRITE) {
    obj |= FUT_RIGHT_WRITE;     // Map WRITE to kernel WRITE
}
if (rights & FUTFS_RIGHT_ADMIN) {
    obj |= FUT_RIGHT_ADMIN;     // Map ADMIN to kernel ADMIN
}
return obj;
```

**Verify:**
- [ ] Filesystem rights map 1:1 to kernel rights
- [ ] DESTROY always granted (allows handle close)
- [ ] No privilege escalation possible
- [ ] Rights are additive (bitwise OR)

### Step 5: Verify Handle Lifecycle

**Creation:**
- `fut_object_create()` at `futfs.c:1158`
- Refcount starts at 1

**Usage:**
- `fut_object_get()` at `futfs.c:652` increments refcount
- `fut_object_put()` at `futfs.c:658,663` decrements refcount

**Destruction:**
- `futfs_close()` at `futfs.c:1262-1274`
- Calls `fut_object_destroy()` which releases handle

**Verify:**
- [ ] No handle leaks (refcount reaches 0)
- [ ] Handle not accessible after close
- [ ] Double-close handled gracefully
- [ ] Memory freed on final put

## Common Issues and How to Detect Them

### Issue 1: Rights Not Checked
**Symptom:** Read-only handle can write
**Check:** Look for operations that don't call `futfs_get_handle()` with required rights
**Fix:** Add rights check at operation entry point

### Issue 2: Rights Escalation
**Symptom:** Handle gains permissions it didn't have
**Check:** Trace handle creation and verify rights never increase
**Fix:** Never OR in additional rights after creation

### Issue 3: Handle Leak
**Symptom:** Memory usage grows, handles not freed
**Check:** Verify every `fut_object_get()` has matching `fut_object_put()`
**Fix:** Add missing put call, use RAII pattern

### Issue 4: Double-Free
**Symptom:** Crash when closing handle
**Check:** Verify handle not used after `fut_object_destroy()`
**Fix:** Set handle to NULL after destroy, check for NULL

## Testing Procedure

### Test 1: Read-Only Handle Cannot Write
```c
fut_handle_t h;
futfs_create("/test.txt", &h);

// Reduce rights to read-only
fut_handle_t ro_handle = fut_object_share(h, my_pid, FUT_RIGHT_READ | FUT_RIGHT_DESTROY);

// Try to write (should fail with -EPERM)
fut_status_t rc = futfs_write(ro_handle, "data", 4);
assert(rc == -EPERM);
```

### Test 2: Write-Only Handle Cannot Read
```c
fut_handle_t h;
futfs_create("/test.txt", &h);

// Reduce rights to write-only
fut_handle_t wo_handle = fut_object_share(h, my_pid, FUT_RIGHT_WRITE | FUT_RIGHT_DESTROY);

// Try to read (should fail with -EPERM)
char buf[100];
size_t nr;
fut_status_t rc = futfs_read(wo_handle, buf, sizeof(buf), &nr);
assert(rc == -EPERM);
```

### Test 3: Full Rights Handle Works
```c
fut_handle_t h;
futfs_create("/test.txt", &h);

// Write succeeds
fut_status_t rc = futfs_write(h, "hello", 5);
assert(rc == 0);

// Read succeeds
char buf[100];
size_t nr;
rc = futfs_read(h, buf, sizeof(buf), &nr);
assert(rc == 0);
assert(nr == 5);
```

### Test 4: Handle Transfer Between Processes
```c
// Process A creates file
fut_handle_t h;
futfs_create("/shared.txt", &h);

// Process A shares with Process B (read-only)
fut_handle_t shared = fut_object_share(h, process_b_pid, FUT_RIGHT_READ);

// Process B can read
// (In process B:)
char buf[100];
size_t nr;
fut_status_t rc = futfs_read(shared, buf, sizeof(buf), &nr);
assert(rc == 0);

// Process B cannot write
rc = futfs_write(shared, "data", 4);
assert(rc == -EPERM);
```

## Code Locations Quick Reference

| Operation | File | Lines | Function |
|-----------|------|-------|----------|
| Handle creation | futfs.c | 1107-1166 | futfs_create() |
| Rights checking (read) | futfs.c | 1168-1195 | futfs_read() |
| Rights checking (write) | futfs.c | 1197-1242 | futfs_write() |
| Rights validation | futfs.c | 639-669 | futfs_get_handle() |
| Rights conversion | futfs.c | 625-637 | futfs_rights_to_object() |
| Handle close | futfs.c | 1262-1274 | futfs_close() |
| Directory create | futfs.c | 1276-1316 | futfs_mkdir() |
| File stat | futfs.c | 1250-1260 | futfs_stat() |

## Object System Integration

| Kernel Function | Purpose | Called From |
|-----------------|---------|-------------|
| fut_object_create() | Create new capability handle | futfs.c:1158 |
| fut_object_get() | Validate and reference handle | futfs.c:652 |
| fut_object_put() | Release handle reference | futfs.c:658,663 |
| fut_object_destroy() | Destroy handle | futfs.c:1268 |
| fut_object_share() | Share handle with reduced rights | (FSD integration needed) |

## Verification Checklist

- [x] FuturaFS creates handles with rights
- [x] FuturaFS checks rights on read operations
- [x] FuturaFS checks rights on write operations
- [x] FuturaFS converts rights to kernel format
- [x] FuturaFS integrates with object system
- [x] Handles are properly ref-counted
- [x] Handles are destroyed on close
- [ ] FSD propagates capability handles (pending Phase 1)
- [ ] Capability syscalls implemented (pending Phase 1)
- [ ] Handle transfer between processes tested (pending Phase 3)

## Next Steps

1. **FSD Integration (Pending):**
   - FSD needs to use capability field in FIPC messages
   - FSD needs to track handles instead of FDs
   - Requires kernel capability syscalls first

2. **Testing (Pending):**
   - Add automated tests for rights enforcement
   - Test handle transfer between processes via FSD
   - Verify no privilege escalation paths

3. **Documentation:**
   - Update API_REFERENCE.md with capability examples
   - Add capability security model to ARCHITECTURE.md
   - Document handle lifecycle for developers

---

**Last Updated:** January 20, 2026
**Status:** Verification complete for FuturaFS layer
**Next:** Implement kernel capability syscalls for FSD integration

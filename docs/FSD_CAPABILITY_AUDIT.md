# Futura OS - FSD Capability Enforcement Audit

**Audit Date:** 2026-01-20
**Scope:** `src/user/fsd/main.c` - All FIPC message handlers
**Current State:** FD-only tracking, zero capability enforcement
**Required State:** Capability-based access control per Phase 4 design

---

## Executive Summary

The Filesystem Daemon (FSD) currently:
- ✗ Accepts messages with capability field but NEVER validates it
- ✗ Uses only FD-to-kernel-FD mapping (line 263-279: `fsd_client_fd_get_kernel`)
- ✗ Bypasses all capability enforcement when relaying syscalls to kernel
- ✗ Treats all clients with identical permissions regardless of caps
- ✗ Does not propagate capability information to kernel operations

**Result:** Phase 4 requirement "capability propagation" is NOT IMPLEMENTED.

---

## Handler-by-Handler Audit

### 1. handle_register() [line 346-357]
- **Current:** Registers client by PID, allocates client slot
- **Missing:** No capability validation for registration right
- **Impact:** Any process can register as FSD client
- **Fix Required:** Validate register capability before accepting

### 2. handle_unregister() [line 362-374]
- **Current:** Unregisters client, closes all FDs
- **Missing:** No capability check for unregister permission
- **Impact:** Process can unregister other clients
- **Fix Required:** Validate unregister capability

### 3. handle_open() [line 379-424] ⚠️ CRITICAL
- **Current:** Opens file via `sys_open()`, allocates client FD
- **Missing:**
  - No validation of open capability
  - No capability propagation to kernel (sys_open line 406)
  - No per-path capability checks
  - No enforcement of O_RDONLY vs O_WRONLY vs O_RDWR
- **Impact:** Any client can open any file with any flags
- **Fix Required:**
  - Extract capability from `msg->capability`
  - Validate `FUT_CAP_OPEN_FILE`
  - Check path-specific capability restrictions
  - Pass capability to kernel via capability-aware syscall

### 4. handle_read() [line 429-473] ⚠️ CRITICAL
- **Current:** Maps client FD to kernel FD, calls `sys_read()`
- **Missing:**
  - No validation of read capability
  - No capability check on FD (only FD validity check line 450)
  - No per-offset capability enforcement
- **Impact:** Any registered client can read any open file
- **Fix Required:**
  - Validate `FUT_CAP_READ_FILE`
  - Check capability against FD rights
  - Enforce read offset restrictions

### 5. handle_write() [line 478-514] ⚠️ CRITICAL
- **Current:** Maps client FD to kernel FD, calls `sys_write()`
- **Missing:**
  - No validation of write capability
  - No capability check on FD (only FD validity check line 496)
  - No write quota/rate limit enforcement
- **Impact:** Any registered client can write to any open file
- **Fix Required:**
  - Validate `FUT_CAP_WRITE_FILE`
  - Check capability against FD rights
  - Enforce write quotas

### 6. handle_close() [line 519-541]
- **Current:** Frees client FD, closes kernel FD
- **Missing:** No capability check for close permission
- **Impact:** Client can close any FD it knows about
- **Fix Required:** Validate `FUT_CAP_CLOSE_FILE`

### 7. handle_mkdir() [line 546-562]
- **Current:** Calls `sys_mkdir_call()` with path and mode
- **Missing:**
  - No validation of directory creation capability
  - No path-based capability restrictions
  - No parent directory capability checks
- **Impact:** Any registered client can create directories anywhere
- **Fix Required:**
  - Validate `FUT_CAP_CREATE_DIR`
  - Check path restrictions
  - Validate parent directory write capability

### 8. handle_rmdir() [line 567-583]
- **Current:** Calls `sys_rmdir_call()` with path
- **Missing:**
  - No validation of directory deletion capability
  - No path-based capability restrictions
  - No ownership checks
- **Impact:** Any registered client can delete any directory
- **Fix Required:**
  - Validate `FUT_CAP_DELETE_DIR`
  - Check path restrictions

### 9. handle_unlink() [line 588-604] ⚠️ CRITICAL
- **Current:** Calls `sys_unlink()` with path
- **Missing:**
  - No validation of file deletion capability
  - No path-based capability restrictions
  - No file ownership checks
- **Impact:** Any registered client can delete any file
- **Fix Required:**
  - Validate `FUT_CAP_DELETE_FILE`
  - Check path restrictions

### 10. handle_stat() [line 609-633]
- **Current:** Calls `sys_stat_call()` with path
- **Missing:**
  - No validation of stat capability
  - No path-based capability restrictions
- **Impact:** Any registered client can stat any path
- **Fix Required:**
  - Validate `FUT_CAP_STAT_FILE`
  - Check path restrictions

### 11. handle_lseek() [line 638-664]
- **Current:** Maps client FD to kernel FD, calls `sys_lseek_call()`
- **Missing:**
  - No validation of seek capability
  - No capability check on FD (only FD validity check line 656)
  - No offset boundary validation
- **Impact:** Client can seek to any offset in any FD
- **Fix Required:**
  - Validate `FUT_CAP_SEEK_FILE`
  - Check capability-enforced seek boundaries

### 12. handle_fsync() [line 669-695]
- **Current:** Maps client FD to kernel FD, calls `sys_fsync_call()`
- **Missing:**
  - No validation of fsync capability
  - No capability check on FD (only FD validity check line 687)
- **Impact:** Client can fsync any open FD
- **Fix Required:** Validate `FUT_CAP_FSYNC`

### 13. handle_chmod() [line 700-716] ⚠️ CRITICAL
- **Current:** Calls `sys_chmod_call()` with path and mode
- **Missing:**
  - No validation of chmod capability
  - No path-based capability restrictions
  - No ownership checks
- **Impact:** Any registered client can chmod any file
- **Fix Required:**
  - Validate `FUT_CAP_CHMOD_FILE`
  - Check path/ownership restrictions

### 14. handle_chown() [line 721-737] ⚠️ CRITICAL
- **Current:** Calls `sys_chown_call()` with path, uid, gid
- **Missing:**
  - No validation of chown capability
  - No path-based capability restrictions
  - No permission downgrade checks
- **Impact:** Any registered client can chown any file (privilege escalation!)
- **Fix Required:**
  - Validate `FUT_CAP_CHOWN_FILE`
  - Prevent privilege escalation

---

## Capability Field Usage Analysis

`struct fsd_fipc_msg` [line 24-32]:
```c
uint64_t capability;  // ← DEFINED but NEVER READ or VALIDATED
```

- Present in all 14 handlers via `msg->capability`
- Populated by kernel FIPC layer
- Zero handlers check this field (0/14 = 0% coverage)

**Key Finding:** The capability field exists but is COMPLETELY UNUSED. This is the root cause of Phase 4 blocker.

---

## FD-Only Tracking Limitations

Current FD Mapping (`fsd_client_fd_get_kernel`, line 263-279):
```
client_fd ─[lookup]─> kernel_fd
├─ No capability attached to FD
├─ No operation type check
├─ No read/write/execute permission bits
└─ Result: FD alone cannot enforce capability-based access
```

### Example Problem:
1. Client A opens file with read cap only (client_fd=5)
2. FSD stores: `clients[idx].fds[5].kernel_fd = 100`
3. Client attempts write on fd=5
4. `handle_write()` calls `fsd_client_fd_get_kernel(idx, 5)` → 100
5. `sys_write(100, ...)` succeeds because FD is valid
6. **NO CAPABILITY CHECK PREVENTS THIS WRITE**

Result: Capability enforcement is completely bypassed.

---

## Phase 4 Design vs Implementation Gap

**Phase 4 Requirement** (STATUS.md):
> "FSD integration with the log skeleton (capability propagation)"

**Current Implementation:**
- ✗ Zero capability propagation
- ✗ FD-only access control
- ✗ No per-operation capability validation
- ✗ No capability attachment to kernel syscalls
- ✗ Unrestricted client permissions

**Required Implementation:**
- ✓ Extract capability from `msg->capability`
- ✓ Validate capability for each operation type
- ✓ Check path/FD-specific capability restrictions
- ✓ Propagate capability to kernel syscalls
- ✓ Enforce per-client capability bounds

---

## Remediation Priority

### CRITICAL (Security Bypass):
1. `handle_open()` - any file/flags accessible
2. `handle_write()` - unauthorized data modification
3. `handle_unlink()` - unauthorized deletion
4. `handle_chown()` - privilege escalation
5. `handle_chmod()` - permission changes

### HIGH (Confidentiality Breach):
6. `handle_read()` - unauthorized data access
7. `handle_stat()` - metadata leak
8. `handle_mkdir()` - unauthorized directory creation

### MEDIUM (Operational Impact):
9. `handle_lseek()` - seek boundary violations
10. `handle_fsync()` - unintended sync behavior

### LOW (Administrative):
11. `handle_register()` - client identity spoofing
12. `handle_close()` - FD exhaustion
13. `handle_rmdir()` - directory deletion

---

## Implementation Required

For each handler, add:

### 1. Capability Extraction
```c
uint64_t cap = msg->capability;
```

### 2. Capability Validation
```c
if (!validate_capability(cap, REQUIRED_CAP_TYPE)) {
    result = -EACCES;
    fsd_send_response(..., &result, sizeof(result));
    return;
}
```

### 3. Capability Propagation
Pass capability to kernel syscall (requires kernel syscall extensions)

### 4. Path/FD Validation
Check if capability grants access to this path/FD

### 5. Audit Logging
Log capability check results for forensics

---

## Recommendations

### IMMEDIATE (Phase 4 Blocker):
1. Add `FUT_CAP_*` constants in `include/kernel/fut_capability.h`
2. Implement `validate_capability()` helper in FSD
3. Add capability checks to all 14 handlers
4. Create capability-aware kernel syscall variants
5. Test capability propagation end-to-end

### FOLLOW-UP (Phase 5):
6. Implement capability inheritance for child processes
7. Add capability revocation on FD close
8. Implement audit trail for capability checks
9. Add performance monitoring for cap checks

---

## Conclusion

**Current state:** Phase 4 NOT COMPLETE
**Blocker:** FSD has zero capability enforcement

**Impact:** Filesystem access control is completely broken.

Any registered client can:
- Read any file
- Write any file
- Delete any file
- Modify any permissions
- Enumerate any directory

**Next step:** Implement capability validation in all 14 handlers.

Estimated effort: 8-12 hours (14 handlers × 30-45 min each)
Risk: High (security-critical path)

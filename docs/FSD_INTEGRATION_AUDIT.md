# FSD Integration with FuturaFS - Capability Propagation Audit

**Date:** 2026-01-20
**Milestone:** Phase 2 - Userland Foundations
**Status:** ✅ Analysis Complete, Implementation Pending

## Executive Summary

The FuturaFS log-structured filesystem has a complete capability-aware handle system in place. The Filesystem Daemon (FSD) relays operations from userspace clients to the kernel but currently does NOT propagate capability handles through its IPC interface. This audit documents the current state and required integration work.

## Current Implementation Status

### ✅ FuturaFS Capability System (Complete)

**Location:** `subsystems/futura_fs/futfs.c`, `subsystems/futura_fs/futfs.h`

FuturaFS implements a full capability-based access control system:

1. **Handle Structure** (`futfs.c:31-35`):
   ```c
   struct futfs_handle {
       struct futfs_inode_mem *inode;
       uint32_t rights;          // FUTFS_RIGHT_READ|WRITE|ADMIN
       size_t offset;
   };
   ```

2. **Rights System** (`futfs.h:41-45`):
   ```c
   enum futfs_rights_bits {
       FUTFS_RIGHT_READ  = 1u << 0,
       FUTFS_RIGHT_WRITE = 1u << 1,
       FUTFS_RIGHT_ADMIN = 1u << 2,
   };
   ```

3. **Rights Checking** (`futfs.c:639-669`):
   - `futfs_get_handle()` validates rights on every operation
   - Converts FuturaFS rights to kernel object rights via `futfs_rights_to_object()`
   - Returns NULL if insufficient rights

4. **Capability Propagation** (`futfs.c:1107-1166`, `1197-1217`):
   - `futfs_create()` creates file with capability handle
   - `futfs_read()` checks READ rights before allowing operation
   - `futfs_write()` checks WRITE rights before allowing operation
   - All handles created through `fut_object_create(FUT_OBJ_FILE, rights, handle)`

### 🚧 FSD Daemon (Incomplete Capability Propagation)

**Location:** `src/user/fsd/main.c`

The FSD daemon has capability infrastructure but doesn't use it:

1. **FIPC Message Structure** (`main.c:24-32`):
   ```c
   struct fsd_fipc_msg {
       uint32_t type;
       uint32_t length;
       uint64_t timestamp;
       uint32_t src_pid;
       uint32_t dst_pid;
       uint64_t capability;      // ⚠️ PRESENT BUT UNUSED
       uint8_t payload[];
   };
   ```

2. **Current Operation Flow** (Example: `handle_open`, `main.c:379-424`):
   ```c
   // Opens file via syscall
   long kernel_fd = sys_open(req->path, req->flags, req->mode);

   // Maps kernel FD to client FD
   int client_fd = fsd_client_fd_alloc(client_idx, kernel_fd, req->flags);

   // Returns client FD
   fsd_send_response(FSD_MSG_OPEN, &result, sizeof(result));
   ```

   **Problem:** Returns integer FD, not a capability handle!

3. **FD Mapping System** (`main.c:68-73`):
   ```c
   struct fsd_client_fd {
       int kernel_fd;      // FD from kernel syscall
       int client_fd;      // FD as seen by client
       int flags;          // Open flags
       bool valid;
   };
   ```

   **Problem:** Tracks FDs, not capability handles with rights!

## Integration Gaps

### Gap 1: FSD Message Capability Field Unused

**Current:** `msg->capability` field exists but is never populated or checked
**Required:**
- On file operations, extract capability from message
- Pass capability handle to kernel instead of using path-based operations
- Validate capability rights match requested operation

### Gap 2: FD-Based vs Handle-Based Operations

**Current:** FSD uses traditional POSIX FD model (integer indices)
**Required:**
- Track `fut_handle_t` capability handles instead of integer FDs
- Convert between client capability handles and kernel capability handles
- Propagate rights restrictions through FSD layer

### Gap 3: Rights Propagation Missing

**Current:** FSD opens files with full kernel privileges
**Required:**
- Honor client's capability rights on file operations
- Restrict operations based on handle rights (e.g., deny write on read-only handle)
- Implement `fut_object_share()` to transfer handles between tasks

### Gap 4: No Capability-Aware Syscalls

**Current:** Uses legacy syscalls (`sys_open`, `sys_read`, `sys_write`)
**Required:**
- Use capability-aware syscalls that accept `fut_handle_t`
- Example: `sys_read_cap(fut_handle_t handle, void *buf, size_t len)`
- Validate handle rights in kernel before performing operation

## Implementation Roadmap

### Phase 1: Kernel Capability Syscalls (Required First)

1. Add capability-aware syscall variants:
   - `sys_read_cap(fut_handle_t h, void *buf, size_t len) -> ssize_t`
   - `sys_write_cap(fut_handle_t h, const void *buf, size_t len) -> ssize_t`
   - `sys_fsync_cap(fut_handle_t h) -> int`
   - `sys_lseek_cap(fut_handle_t h, off_t offset, int whence) -> off_t`

2. Implement handle transfer syscalls:
   - `sys_handle_send(pid_t target, fut_handle_t h, fut_rights_t rights) -> int`
   - `sys_handle_recv(pid_t from, fut_rights_t *rights) -> fut_handle_t`

### Phase 2: FSD Capability Integration

1. Update FSD message handlers to use capability field:
   ```c
   // In handle_read():
   fut_handle_t cap = msg->capability;
   long bytes_read = sys_read_cap(cap, resp.data, read_size);
   ```

2. Replace FD tracking with handle tracking:
   ```c
   struct fsd_client_handle {
       fut_handle_t kernel_handle;  // Capability handle from kernel
       fut_handle_t client_handle;  // Client's view of handle
       fut_rights_t rights;          // Rights associated with handle
       bool valid;
   };
   ```

3. Implement handle sharing on open:
   ```c
   fut_handle_t cap = sys_open_cap(req->path, req->flags, req->mode);
   fut_handle_t shared = sys_handle_send(msg->src_pid, cap, rights);
   fsd_send_response(FSD_MSG_OPEN, &shared, sizeof(shared));
   ```

### Phase 3: VFS Integration

1. Update VFS layer to expose capability operations
2. Add `vfs_open_cap()`, `vfs_read_cap()`, `vfs_write_cap()` variants
3. Validate rights at VFS layer before dispatching to filesystem

### Phase 4: Testing & Verification

1. Add capability propagation tests in `tests/`
2. Verify rights restrictions work correctly:
   - Read-only handle cannot write
   - Write-only handle cannot read
   - Admin rights required for chmod/chown
3. Test handle transfer between processes via FSD
4. Verify capability revocation on handle close

## Verification Checklist

- [ ] Kernel capability syscalls implemented
- [ ] FSD uses capability field in FIPC messages
- [ ] FSD tracks handles with rights, not just FDs
- [ ] File operations validate handle rights
- [ ] Handle transfer between processes works
- [ ] Rights restrictions enforced (read-only cannot write)
- [ ] Tests added for capability propagation
- [ ] Documentation updated in STATUS.md

## Security Implications

**Current Risk:** FSD operates with full kernel privileges, defeating capability model

**Mitigated Risk:** Once complete, FSD will:
- Honor client capability restrictions
- Prevent privilege escalation through FSD
- Enable fine-grained access control (e.g., read-only file shares)
- Support capability delegation and revocation

## Performance Impact

**Minimal:** Handle lookup is O(1) with hash table, same as FD lookup
**Benefit:** Eliminates path-based access checks, improving security without performance cost

## References

- FuturaFS implementation: `subsystems/futura_fs/futfs.c`
- FSD daemon: `src/user/fsd/main.c`
- Object system: `kernel/ipc/fut_object.c`, `include/kernel/fut_object.h`
- STATUS.md: Current milestone tracking

## Next Actions

1. ✅ Complete this audit (DONE)
2. ⏭️ Implement kernel capability syscalls (Phase 1)
3. ⏭️ Update FSD to use capability syscalls (Phase 2)
4. ⏭️ Add integration tests
5. ⏭️ Update STATUS.md to mark FSD integration complete

---

**Auditor:** Claude Code
**Reviewed:** Phase 2 FSD integration task
**Conclusion:** FuturaFS capability system is complete and robust. FSD integration requires kernel syscall additions and FSD message handling updates. No changes needed to FuturaFS itself.

# Next Priorities and Blockers

**Date:** January 21, 2026
**Phase:** Phase 2 → Phase 3 Transition

---

## Resolved Blockers

### ~~1. Kernel Boot Hang~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Previous Location:** `fut_mm_system_init()` in memory management subsystem
**Resolution:** Boot hang no longer occurs. Kernel successfully boots through:
- PMM initialization
- Heap initialization
- MM subsystem initialization
- Timer, signal, ACPI subsystems
- VFS mount and scheduler start

The kernel now boots to scheduler start and enters preemptive scheduling mode.

---

## Current Blockers

### 1. Phase 1 Capability Syscalls (BLOCKING FSD INTEGRATION)

**Status:** HIGH
**Location:** Kernel syscall layer
**Impact:** FSD cannot propagate capability handles without these syscalls

**Required Syscalls:**
```
File Operations:
  [ ] sys_open_cap(path, flags, mode) → fut_handle_t
  [ ] sys_read_cap(handle, buffer, count)
  [ ] sys_write_cap(handle, buffer, count)
  [ ] sys_lseek_cap(handle, offset, whence)
  [ ] sys_fsync_cap(handle)
  [ ] sys_fstat_cap(handle, statbuf)
  [ ] sys_close_cap(handle)

Directory Operations:
  [ ] sys_mkdirat_cap(parent_handle, name, mode)
  [ ] sys_rmdirat_cap(parent_handle, name)
  [ ] sys_unlinkat_cap(parent_handle, name)
  [ ] sys_statat_cap(parent_handle, name, statbuf)

Handle Transfer:
  [ ] sys_handle_send(target_pid, handle, rights)
  [ ] sys_handle_recv(source_pid, rights_out)
```

**Dependencies:**
- VFS must return capability handles instead of integer FDs
- Syscall table updates for new syscall numbers
- Userspace libc wrappers

**Reference:** `include/kernel/fut_capability.h` (API defined, stubs implemented)

---

### 3. VFS Capability Integration (BLOCKING CAPABILITY SYSCALLS)

**Status:** HIGH
**Location:** `kernel/vfs/fut_vfs.c`
**Impact:** Capability syscalls cannot function without VFS support

**Required Changes:**
1. `fut_vfs_open()` must return `fut_handle_t` instead of `int fd`
2. `fut_vfs_read/write()` must accept `fut_handle_t` and validate rights
3. Add `fut_vfs_fstat()` capability-aware variant
4. File structure must store capability object reference

**Current State:**
- VFS uses integer file descriptors throughout
- No rights validation at VFS layer
- File operations bypass capability model

---

## Priority Order

| Priority | Task | Blocker For | Status |
|----------|------|-------------|--------|
| ~~P0~~ | ~~Fix kernel boot hang~~ | ~~All runtime testing~~ | ✓ RESOLVED |
| P1 | VFS capability integration | Phase 1 syscalls | IN PROGRESS |
| P1 | Phase 1 capability syscalls | FSD integration | PENDING |
| P2 | FSD handler updates | Phase 4 completion | PENDING |
| P3 | Capability integration tests | Validation | PENDING |

---

## Completed Work (Reference)

### Infrastructure Ready
- [x] `fut_capability.h` - Capability API defined
- [x] `kernel/capability.c` - Stub implementations ready
- [x] `fut_object.h` - Object system operational
- [x] FuturaFS capability system - Verified working
- [x] Process group signal delivery - Working
- [x] TTY SIGWINCH delivery - Implemented

### Documentation Complete
- [x] `docs/FSD_CAPABILITY_AUDIT.txt` - Security audit
- [x] `docs/FSD_INTEGRATION_AUDIT.md` - Technical gaps
- [x] `docs/CAPABILITY_VERIFICATION_GUIDE.md` - Test procedures
- [x] `PHASE_2_COMPLETION_REPORT.md` - Milestone status

---

## Immediate Next Steps

1. **Begin VFS capability integration** (P1 - CURRENT)
   - Add capability-aware VFS functions (`fut_vfs_open_cap`, `fut_vfs_read_cap`, etc.)
   - Keep existing integer FD functions for compatibility
   - Add rights validation to capability paths

2. **Implement capability syscalls** (P1 - NEXT)
   - Wire capability VFS functions to syscall table
   - Syscall numbers: SYS_OPEN_CAP = 400, etc.
   - Add userspace libc wrappers

3. **Run integration tests**
   ```bash
   make test
   ```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| VFS changes break existing code | Medium | Medium | Keep old FD functions, add new capability functions |
| Capability overhead too high | Low | Medium | Profile early, optimize later |
| FSD integration takes longer | Medium | Low | Stub fallbacks available |

---

## Contacts

- **VFS Team:** Capability integration
- **Userspace Team:** FSD handler updates
- **QA:** Integration test development

---

**Last Updated:** January 21, 2026

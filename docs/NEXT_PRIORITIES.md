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

## Resolved P1 Blockers

### ~~1. Phase 1 Capability Syscalls~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Commit:** c6951ed

**Implemented Syscalls (500-510):**
```
File Operations:
  [x] sys_open_cap(path, flags, mode) → fut_handle_t    (500)
  [x] sys_read_cap(handle, buffer, count)               (501)
  [x] sys_write_cap(handle, buffer, count)              (502)
  [x] sys_close_cap(handle)                             (503)
  [x] sys_lseek_cap(handle, offset, whence)             (504)
  [x] sys_fstat_cap(handle, statbuf)                    (505)
  [x] sys_fsync_cap(handle)                             (506)

Directory Operations:
  [x] sys_mkdirat_cap(parent_handle, name, mode)        (507)
  [x] sys_unlinkat_cap(parent_handle, name)             (508)
  [x] sys_rmdirat_cap(parent_handle, name)              (509)
  [x] sys_statat_cap(parent_handle, name, statbuf)      (510)
```

---

### ~~2. VFS Capability Integration~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Commit:** bd3c960
**Location:** `kernel/vfs/fut_vfs_cap.c`

**Implemented:**
- `fut_vfs_open_cap()` returns `fut_handle_t` capability handles
- `fut_vfs_read_cap/write_cap()` validate rights before operations
- `fut_vfs_fstat_cap()` capability-aware file stat
- All directory operations with parent handle support
- Rights validation (READ, WRITE, ADMIN, DESTROY) at VFS layer

---

## Current Blockers

### 1. FSD Handler Updates (P2)

**Status:** HIGH
**Location:** Userspace FSD (FuturaFS Daemon)
**Impact:** FSD must use capability syscalls instead of integer FDs

**Required Changes:**
1. Update FSD message handlers to use capability handles
2. Replace integer FD operations with capability operations
3. Propagate capabilities through FSD protocol
4. Update client library to use capability syscalls

---

## Priority Order

| Priority | Task | Blocker For | Status |
|----------|------|-------------|--------|
| ~~P0~~ | ~~Fix kernel boot hang~~ | ~~All runtime testing~~ | ✓ RESOLVED |
| ~~P1~~ | ~~VFS capability integration~~ | ~~Phase 1 syscalls~~ | ✓ RESOLVED |
| ~~P1~~ | ~~Phase 1 capability syscalls~~ | ~~FSD integration~~ | ✓ RESOLVED |
| P2 | FSD handler updates | Phase 4 completion | IN PROGRESS |
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

1. **Update FSD handlers** (P2 - CURRENT)
   - Locate FSD message handlers in userspace
   - Update handlers to use capability syscalls (sys_open_cap, etc.)
   - Replace integer FD operations with capability operations

2. **Update FSD client library** (P2 - NEXT)
   - Add capability handle types to client API
   - Implement wrappers for capability syscalls
   - Update existing clients to use new API

3. **Run integration tests** (P3)
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

# Next Priorities and Blockers

**Date:** January 20, 2026
**Phase:** Phase 2 → Phase 3 Transition

---

## Critical Blockers

### 1. Kernel Boot Hang (BLOCKING ALL RUNTIME TESTS)

**Status:** CRITICAL
**Location:** `fut_mm_system_init()` in memory management subsystem
**Impact:** Prevents `make test` from completing; no runtime validation possible

**Symptoms:**
- Kernel hangs during early boot
- Memory management initialization does not complete
- No console output after MM init begins

**Required Actions:**
1. Add debug output before/after each MM init step
2. Identify which allocation or mapping causes hang
3. Check for infinite loops in buddy allocator or page table setup
4. Verify ARM64 vs x86_64 parity in MM code paths

**Priority:** P0 - Must fix before any other testing can proceed

---

### 2. Phase 1 Capability Syscalls (BLOCKING FSD INTEGRATION)

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

| Priority | Task | Blocker For | Estimated Effort |
|----------|------|-------------|------------------|
| P0 | Fix kernel boot hang | All runtime testing | 1-2 days |
| P1 | VFS capability integration | Phase 1 syscalls | 1 week |
| P1 | Phase 1 capability syscalls | FSD integration | 1 week |
| P2 | FSD handler updates | Phase 4 completion | 1 week |
| P3 | Capability integration tests | Validation | 3 days |

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

1. **Debug kernel boot hang**
   ```bash
   # Add debug output to kernel/memory/fut_mm.c
   # Run with serial console capture
   make run 2>&1 | tee boot_debug.log
   ```

2. **Once boot fixed, run tests**
   ```bash
   make test
   ```

3. **Begin VFS capability integration**
   - Start with `fut_vfs_open()` returning handles
   - Update file structure with capability reference
   - Add rights validation to read/write paths

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Boot hang is deep MM bug | Medium | High | Add extensive debug logging |
| VFS changes break existing code | Medium | Medium | Incremental changes with tests |
| Capability overhead too high | Low | Medium | Profile early, optimize later |
| FSD integration takes longer | Medium | Low | Stub fallbacks available |

---

## Contacts

- **Kernel MM:** Debug boot hang
- **VFS Team:** Capability integration
- **Userspace Team:** FSD handler updates
- **QA:** Integration test development

---

**Last Updated:** January 20, 2026

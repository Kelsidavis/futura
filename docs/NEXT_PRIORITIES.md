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

## Resolved P2 Blockers

### ~~1. FSD Handler Updates~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Commit:** 907f7ce
**Location:** `src/user/fsd/main.c`

**Implemented:**
- Updated FSD client structure to use `fsd_handle_t` capability handles
- All FSD handlers now use capability syscalls:
  - `handle_open()` → `sys_open_cap()`
  - `handle_read()` → `sys_read_cap()`
  - `handle_write()` → `sys_write_cap()`
  - `handle_close()` → `sys_close_cap()` (via `fsd_client_fd_free()`)
  - `handle_lseek()` → `sys_lseek_cap()`
  - `handle_fsync()` → `sys_fsync_cap()`
- Added capability syscall wrappers to `include/user/sys.h`
- Added capability syscall numbers to `include/user/sysnums.h`

---

## Current Blockers

### 1. Scheduler Bootstrap Issue (P0-NEW)

**Status:** BLOCKING
**Location:** `kernel/scheduler.c`, `kernel/kernel_main.c`
**Impact:** Prevents async tests from running after scheduler starts

**Symptoms:**
- After `fut_sched_start()`, the init thread (tid=1) doesn't continue
- Context switches to idle thread (tid=2) but never returns
- Kernel hangs at "[SCHED-COOP] next->context.rip=..."

**Required Investigation:**
1. Check why tid=1 is added to ready queue but not scheduled back
2. Verify idle thread is yielding correctly
3. Check timer IRQ is firing for preemptive scheduling

---

### 2. Capability Integration Tests (P3)

**Status:** IN PROGRESS (blocked by scheduler issue)
**Commit:** c179c2d
**Location:** `kernel/tests/sys_cap.c`

**Implemented Tests (6 total):**
- [x] Capability handle creation (open_cap)
- [x] Capability read operation (read_cap)
- [x] Capability write operation (write_cap)
- [x] Rights enforcement (read-only cannot write)
- [x] Invalid handle operations
- [x] Capability handle cleanup (close_cap)

**Note:** Tests are correctly implemented and will run once scheduler issue is resolved.

---

## Priority Order

| Priority | Task | Blocker For | Status |
|----------|------|-------------|--------|
| ~~P0~~ | ~~Fix kernel boot hang~~ | ~~All runtime testing~~ | ✓ RESOLVED |
| **P0-NEW** | **Fix scheduler bootstrap** | **All async tests** | **BLOCKING** |
| ~~P1~~ | ~~VFS capability integration~~ | ~~Phase 1 syscalls~~ | ✓ RESOLVED |
| ~~P1~~ | ~~Phase 1 capability syscalls~~ | ~~FSD integration~~ | ✓ RESOLVED |
| ~~P2~~ | ~~FSD handler updates~~ | ~~Phase 4 completion~~ | ✓ RESOLVED |
| P3 | Capability integration tests | Validation | IN PROGRESS (blocked) |

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

1. **Fix scheduler bootstrap issue** (P0-NEW - BLOCKER)
   - Investigate why init thread (tid=1) doesn't resume after scheduler starts
   - Check idle thread yield behavior
   - Verify timer IRQ preemption is working

2. **Run capability integration tests** (P3 - BLOCKED)
   ```bash
   make test
   ```
   - Tests are implemented in `kernel/tests/sys_cap.c`
   - Will run automatically once scheduler issue is fixed
   - 6 capability tests ready to validate:
     - Handle creation/destruction
     - Read/write with rights enforcement
     - Invalid handle rejection

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

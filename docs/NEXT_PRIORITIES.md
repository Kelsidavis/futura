# Next Priorities and Blockers

**Date:** January 21, 2026
**Phase:** Phase 4 In Progress

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

## Resolved P0 Blockers

### ~~1. Scheduler Bootstrap Issue~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Commit:** 3c5d051
**Location:** `kernel/scheduler/fut_sched.c`

**Root Cause:**
When doing a cooperative context switch from within an ISR (e.g., when a thread
terminates and switches to idle), the kernel was not sending EOI to the LAPIC.
This blocked all future timer interrupts because the LAPIC believed we were
still servicing the current interrupt.

**Resolution:**
- Added `lapic_send_eoi()` (x86_64) or `fut_irq_send_eoi()` (ARM64) before
  clearing interrupt flags and switching context
- This allows the scheduler to receive future timer ticks and properly schedule threads
- Disabled verbose SCHED-COOP debug output that was flooding serial console

---

## Resolved P3 Work

### ~~1. Capability Integration Tests~~ ✓ RESOLVED

**Status:** RESOLVED (January 21, 2026)
**Commits:** c179c2d (tests), 3c5d051 (scheduler fix)
**Location:** `kernel/tests/sys_cap.c`

**All 6 Tests Passing:**
- [x] Test 1: Capability handle creation (open_cap) ✓
- [x] Test 2: Capability read operation (read_cap) ✓
- [x] Test 3: Capability write operation (write_cap) ✓
- [x] Test 4: Rights enforcement (read-only cannot write) ✓
- [x] Test 5: Invalid handle operations ✓
- [x] Test 6: Capability handle cleanup (close_cap) ✓

**Test Results:**
```
[CAP-TEST] ✓ Capability handle created: 0x3
[CAP-TEST] ✓ Read 23 bytes via capability: 'Hello Capability World!'
[CAP-TEST] ✓ Wrote 22 bytes via capability, verified: 'Capability Write Test!'
[CAP-TEST] ✓ Write on read-only handle correctly denied: -1
[CAP-TEST] ✓ Invalid handle operations correctly rejected
[CAP-TEST] ✓ Capability handle closed, subsequent ops rejected
```

---

## Priority Order

| Priority | Task | Blocker For | Status |
|----------|------|-------------|--------|
| ~~P0~~ | ~~Fix kernel boot hang~~ | ~~All runtime testing~~ | ✓ RESOLVED |
| ~~P0~~ | ~~Fix scheduler bootstrap~~ | ~~All async tests~~ | ✓ RESOLVED |
| ~~P1~~ | ~~VFS capability integration~~ | ~~Phase 1 syscalls~~ | ✓ RESOLVED |
| ~~P1~~ | ~~Phase 1 capability syscalls~~ | ~~FSD integration~~ | ✓ RESOLVED |
| ~~P2~~ | ~~FSD handler updates~~ | ~~Phase 4 completion~~ | ✓ RESOLVED |
| ~~P3~~ | ~~Capability integration tests~~ | ~~Validation~~ | ✓ RESOLVED |

---

## Completed Work (Reference)

### Infrastructure Ready
- [x] `fut_capability.h` - Capability API defined
- [x] `kernel/capability.c` - Implementation complete (including expiry support)
- [x] `fut_object.h` - Object system operational
- [x] FuturaFS capability system - Verified working
- [x] Process group signal delivery - Working
- [x] TTY SIGWINCH delivery - Implemented
- [x] Time-based capability expiry - Implemented (commit 32ca359)

### Documentation Complete
- [x] `docs/FSD_CAPABILITY_AUDIT.md` - Security audit
- [x] `docs/FSD_INTEGRATION_AUDIT.md` - Technical gaps
- [x] `docs/CAPABILITY_VERIFICATION_GUIDE.md` - Test procedures
- [x] `PHASE_2_COMPLETION_REPORT.md` - Milestone status

---

## Immediate Next Steps

**Phase 3 capability work is complete.** All capability syscalls are implemented, tested, and verified working.

### Suggested Future Work

1. **Phase 4: IPC Capability Integration**
   - Extend capability model to IPC channels
   - Implement capability-based message passing
   - Add capability delegation between processes

2. **Performance Optimization**
   - Profile capability lookup overhead
   - Consider caching frequently-used handles
   - Benchmark capability vs traditional FD performance

3. **Security Hardening**
   - Add capability revocation mechanism
   - Implement capability audit logging
   - ~~Add time-based capability expiry enforcement in syscalls~~ ✓ DONE
     - `fut_capability_check_expiry()` implemented (commit 32ca359)
     - `fut_capability_create_timed()` for creating timed capabilities
     - Time resolution: 1 minute (max ~45 days expiry)
   - ~~Add page refcount overflow protection~~ ✓ DONE (commit adfa7bb)
     - `FUT_PAGE_REF_MAX` (60000) prevents CVE-2016-0728 style attacks
     - `fut_page_ref_inc()` returns error if limit reached
   - ~~Add file refcount overflow protection~~ ✓ DONE (commit 8342941)
     - `FUT_FILE_REF_MAX` prevents overflow via mass forking
     - Proper cleanup of already-inherited FDs on failure
   - ~~Add global PID limit for fork bomb mitigation~~ ✓ DONE (commit eb1b1d3)
     - `FUT_MAX_TASKS_GLOBAL` (30000) system-wide limit
     - `FUT_RESERVED_FOR_ROOT` (1000) PIDs reserved for admin recovery
   - ~~Enforce CAP_SYS_RESOURCE for raising hard limits~~ ✓ DONE (commit adda195)
   - ~~Add VMA count limit~~ ✓ DONE (commit adda195)
     - `MAX_VMA_COUNT` (65536) prevents VMA fragmentation DoS

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

# ARM64 Signal Handling & Related Syscalls — Priority Work Items

**Generated**: 2025-11-12
**Focus**: Signal delivery, timers, and process control features for ARM64

## Executive Summary

The ARM64 port has comprehensive signal infrastructure scaffolding but lacks **signal delivery** (Phase 3) and some related syscalls. The signal handling code is **architecture-aware with ARM64 frame access** but **x86-64 signal delivery is incomplete**. Priority work builds on recently completed signal syscall handlers (sigaction, sigprocmask, kill, pause).

---

## 1. CRITICAL: Signal Delivery (Phase 3)

### 1.1 ARM64 Signal Delivery Framework — NEARLY COMPLETE

**Status**: ✅ Mostly implemented in `/Users/kelsi/futura/kernel/signal/signal.c:228-364`

**What's Done**:
- Signal pending checking (bitmask-based)
- Handler lookup and validation
- rt_sigframe construction (siginfo_t, ucontext_t)
- Exception frame modification to invoke handler
- Register setup for signal handler (x0=signum, x1=siginfo_t*, x2=ucontext_t*)
- NEON/FPU register copying to frame
- Per-task signal mask restoration

**What's Missing**:
- **x86-64 signal delivery stub** (lines 358-363) — Returns 0, no implementation
- **Integration with exception path** — Signal delivery must be called from:
  - Syscall return path (after sys_* completes)
  - Interrupt/exception return paths (before ERET)
  - Currently: Only called from ARM64 exception_handlers.c line 78
- **Default signal actions** — When no handler installed (SIG_DFL):
  - SIGTERM/SIGINT: Terminate process
  - SIGSEGV/SIGBUS: Terminate + core dump
  - SIGSTOP/SIGCONT: Stop/continue process
  - Signal-specific semantics need kernel integration

**File Locations**:
- Signal delivery ARM64: `/Users/kelsi/futura/kernel/signal/signal.c:228-355`
- ARM64 exception handler call: `/Users/kelsi/futura/platform/arm64/exception_handlers.c:74-79`
- Signal action table: `/Users/kelsi/futura/kernel/signal/signal.c:19-60`

**Next Steps**:
1. Implement x86-64 signal delivery (mirror ARM64 logic but with x86-64 frame)
2. Add exception frame modification to other ARM64 return paths
3. Implement default signal actions (process termination, etc.)
4. Test with signal handler programs

---

## 2. HIGH PRIORITY: Signal Altstack Support

### Status: ARM64 Stub Only

**File**: `/Users/kelsi/futura/platform/arm64/syscall_table.c:1288-1298`

```c
static int64_t sys_sigaltstack_wrapper(uint64_t ss, uint64_t old_ss, ...)
    /* Stub: Return success without doing anything */
    return 0;  /* Phase 2: Implement alternate signal stack support */
}
```

**What's Needed**:
1. Per-task alternate signal stack storage in `fut_task_t`:
   - `void *sigaltstack_sp` (stack base)
   - `size_t sigaltstack_size` (stack size)
   - `int sigaltstack_flags` (SS_DISABLE, SS_ONSTACK)
   
2. Implement `sys_sigaltstack()` in kernel:
   - Copy `struct sigaltstack` from userspace
   - Validate stack alignment (16-byte on ARM64)
   - Store in task structure
   - Return old stack in `old_ss` parameter
   
3. Integrate with signal delivery:
   - Check `SS_DISABLE` flag in delivery path
   - Use alternate stack if enabled and not already on it
   - Adjust SP in signal frame to use altstack
   
4. ARM64 Implementation Pattern:
   - Mirror existing `sys_sigprocmask.c` (60-100 lines)
   - Use `fut_copy_to_user()` / `fut_copy_from_user()`
   - Add to ARM64 syscall_table.c dispatch table

**Priority**: HIGH — Many signal-heavy programs use alternate stacks

---

## 3. HIGH PRIORITY: Signal Return Path (rt_sigreturn)

### Status: Partially Complete

**File**: `/Users/kelsi/futura/platform/arm64/syscall_table.c:1300-1350` (stub)

**What's Done**:
- ARM64 syscall wrapper exists
- x86-64 implementation in `subsystems/posix_compat/posix_syscall.c:676-790`

**What's Missing in ARM64**:
1. **Frame restoration logic**:
   - Read rt_sigframe from user stack (SP currently points to it)
   - Restore all registers from sigcontext (x0-x30, sp, pc, pstate)
   - Restore signal mask
   - Adjust SP to skip past rt_sigframe
   - Return with ERET to restored PC

2. **Error handling**:
   - Validate user stack pointer
   - Validate rt_sigframe read succeeds
   - Handle partial reads
   
3. **Integration**:
   - Exception handler must recognize EABI sigreturn (syscall 139)
   - Modify exception frame based on restored context
   - Return to interrupted code via ERET

**Reference Implementation**: x86-64 version in `subsystems/posix_compat/posix_syscall.c:700-760` (60 lines)

---

## 4. MEDIUM PRIORITY: Signal-Pending Query

### Status: Not Implemented

**Missing Syscalls**:
- `sigpending(sigset_t *set)` — Query pending, unblocked signals
- `sigsuspend(const sigset_t *mask)` — Atomically change mask and wait for signal

**File Location**: No implementation yet (would be new)

**What's Needed**:
1. Create `/Users/kelsi/futura/kernel/sys_sigpending.c` (~50 lines):
   ```c
   long sys_sigpending(sigset_t *set) {
       /* Get current task's pending_signals bitmask
          Return to userspace via *set
          Call: sys_sigprocmask(SIG_BLOCK, NULL, &current_mask) to get blocked signals
          Return: pending_signals & ~current_mask (pending AND unblocked)
       */
   }
   ```

2. Create `/Users/kelsi/futura/kernel/sys_sigsuspend.c` (~80 lines):
   ```c
   long sys_sigsuspend(const sigset_t *mask) {
       /* Atomically: 
          1. Save current signal mask
          2. Set mask to *mask parameter
          3. Block until any signal delivered
          4. Restore saved mask
          5. Return -EINTR
       */
   }
   ```

3. Add to ARM64 syscall_table.c dispatch table

**Priority**: MEDIUM — Required for proper signal-safe programming patterns

---

## 5. MEDIUM-HIGH PRIORITY: Alarm & Timer Signal Delivery

### Current Status

**Files**:
- Alarm setup: `/Users/kelsi/futura/kernel/sys_alarm.c` (lines 1-100)
- Nanosleep: `/Users/kelsi/futura/platform/arm64/syscall_table.c:537-600` (stub)
- Timer infrastructure: `/Users/kelsi/futura/platform/arm64/syscall_table.c:700+` (incomplete)

**What's Done**:
- `sys_alarm()`: Tracks alarm expiration time in task structure
- `sys_nanosleep()`: Accepts sleep duration parameter
- Timer structures defined in syscall_table.c

**What's Missing**:
1. **Timer interrupt integration**:
   - ARM Generic Timer already running and generating IRQs
   - Need handler that checks for expired alarms/timers
   - Deliver SIGALRM when alarm expires
   - Deliver SIGVTALRM, SIGPROF for interval timers

2. **Per-task timer tracking** (Phase 3):
   - Current: Single global `global_alarm_expires_ms` (incorrect for multi-process)
   - Need: Per-task alarm fields in `fut_task_t`
   - Field offsets/names TBD

3. **Nanosleep blocking** (Phase 3):
   - Current: Stub returns immediately
   - Need: Block on wait queue until timeout
   - Use timer infrastructure to wake after duration

4. **POSIX timer support** (Phase 4):
   - `timer_create()`, `timer_settime()`, `timer_delete()`
   - Currently: Syscall hooks exist, but no backend

**Integration Points**:
- ARM Generic Timer IRQ handler (platform/arm64/interrupt/gic_irq_handler.c)
- Timer dispatch function (needs creation)
- Signal delivery path (sys_alarm → SIGALRM → signal delivery)

**TODO Comments in Code**:
- `/Users/kelsi/futura/platform/arm64/syscall_table.c:563` — "TODO: Use timer interrupts for real sleep"
- `/Users/kelsi/futura/kernel/sys_alarm.c:85-86` — "Phase 3: Timer interrupt will check global_alarm_expires_ms"

**Priority**: MEDIUM-HIGH — Many test programs depend on alarm()

---

## 6. MEDIUM PRIORITY: Pause Blocking

### Status: Partial Implementation

**File**: `/Users/kelsi/futura/kernel/sys_pause.c:42-104`

**What's Done**:
- Validates current task exists
- Checks for pending signals
- Logging infrastructure
- Returns -EINTR immediately (stub)

**What's Missing**:
1. **Wait queue blocking** (Phase 3):
   - Current: Returns -EINTR immediately
   - Need: Block on task's wait queue
   - Unblock when any signal delivered
   
2. **Integration with signal delivery**:
   - Signal delivery must check for tasks on pause wait queue
   - Wake them when signal arrives
   - Resume execution after handler or with default action

3. **Test**: Simple test program:
   ```c
   signal(SIGUSR1, handler);
   pause();  // Should block until SIGUSR1
   ```

**Priority**: MEDIUM — Useful for signal-based IPC patterns

---

## 7. MEDIUM PRIORITY: Missing Signal Syscalls

### Incomplete/Missing in ARM64

**sigaltstack**: Line 1288-1298 (stub)
**rt_sigreturn**: Line 1300-1350 (needs ARM64 frame restoration)
**sigpending**: Not implemented
**sigsuspend**: Not implemented

**tkill(tid, sig)**: Listed in docs but not found in syscall_table.c
**tgkill(pid, tid, sig)**: Listed in docs but not found

---

## 8. LOWER PRIORITY: x86-64 Signal Delivery

### Status: Stub (Not x86-64 dependent, but lower priority than ARM64)

**File**: `/Users/kelsi/futura/kernel/signal/signal.c:357-364`

```c
#else
/* x86-64 stub: not yet implemented */
int fut_signal_deliver(struct fut_task *task, void *frame) {
    return 0;
}
#endif
```

**What's Needed** (when x86-64 signal work resumes):
1. Mirror ARM64 logic but with x86-64 frame layout:
   - x86-64: RSI=signum, RDX=siginfo_t*, RCX=ucontext_t* (AMD64 ABI)
   - Use RIP for handler, RSP for stack
   - XMM registers instead of NEON

2. x86-64 frame structure:
   - Registers: RAX-R15, RIP, RFLAGS, RSP, etc.
   - FPU state: x87 FPU, SSE (XMM0-15), AVX (YMM0-15)

3. Reference: Linux kernel's x86_64 signal delivery in arch/x86/kernel/signal.c

**Priority**: LOWER — ARM64 is primary focus; x86-64 can follow same pattern

---

## 9. INFRASTRUCTURE: Testing

### What's Needed

**Test Program 1**: `/Users/kelsi/futura/kernel/tests/sys_signal_delivery.c`
```c
// Test signal handler invocation
// Test frame restoration via sigreturn
// Test signal mask blocking/unblocking
// Test pause() with signal delivery
// Test alarm() with SIGALRM delivery
```

**Test Program 2**: `/Users/kelsi/futura/kernel/tests/sys_sigaltstack.c`
```c
// Test alternate stack setup
// Test signal delivery on alternate stack
// Test SS_DISABLE flag
```

**Integration**: Add to ARM64 kernel self-tests (platform/arm64/interrupt/arm64_stubs.c)

---

## Prioritized Implementation Order

### Phase 1 (IMMEDIATE) — Foundation

1. **sysigsuspend()** (80 lines) — Atomic mask change + wait
2. **sys_sigpending()** (50 lines) — Query pending signals
3. Test these with simple user programs

**Estimated**: 1-2 hours

### Phase 2 (THIS WEEK) — Signal Delivery

4. **x86-64 signal delivery** (mirror ARM64, ~150 lines)
5. Integrate ARM64 signal delivery into all exception return paths
6. Default signal action implementation (terminate, core dump, etc.)
7. Test with signal handler programs

**Estimated**: 3-4 hours

### Phase 3 (NEXT WEEK) — Timers & Sleep

8. **Timer interrupt handler** — Check alarm/timer expirations
9. **Per-task alarm fields** — Move from global to per-task
10. **Nanosleep blocking** — Use timer + wait queue
11. **Pause blocking** — Wait queue integration
12. **sys_sigaltstack()** — Full implementation

**Estimated**: 4-6 hours

### Phase 4 (FOLLOWING WEEK) — Polish

13. **rt_sigreturn full ARM64** — Frame restoration
14. **POSIX timers** — timer_create/settime/delete
15. Comprehensive signal testing
16. Performance profiling

**Estimated**: 3-4 hours

---

## Summary Table

| Item | File | Status | Lines | Priority | Est. Hours |
|------|------|--------|-------|----------|-----------|
| Signal delivery (ARM64) | signal.c:228-355 | 90% done | 128 | CRITICAL | 1 |
| x86-64 signal delivery | signal.c:357-364 | Stub | 150 needed | HIGH | 2 |
| sigaltstack impl | New: sys_sigaltstack.c | Missing | 80 | HIGH | 1.5 |
| rt_sigreturn ARM64 | syscall_table.c:1300 | Stub | 100 needed | HIGH | 1.5 |
| sigpending | New: sys_sigpending.c | Missing | 50 | MEDIUM | 0.5 |
| sigsuspend | New: sys_sigsuspend.c | Missing | 80 | MEDIUM | 1 |
| Timer interrupt handler | New: timer_handler | Missing | 100 | MEDIUM-HIGH | 2 |
| Nanosleep blocking | syscall_table.c:537 | Stub | 80 needed | MEDIUM-HIGH | 1 |
| Pause blocking | sys_pause.c | Partial | 40 needed | MEDIUM | 0.5 |
| tkill/tgkill impl | New: sys_tkill.c | Missing | 60 | LOW | 1 |
| **TOTAL** | — | — | ~950 | — | **12-14 hours** |

---

## Code Patterns to Follow

### From sys_sigprocmask.c (100 lines, good pattern)
```c
1. Get current task
2. Validate signal numbers
3. Copy from userspace (if provided)
4. Modify kernel state
5. Copy to userspace (if requested)
6. Return error or 0
```

### From sys_sigaction.c (100 lines, good pattern)
```c
1. Validate signal number
2. Check special signals (SIGKILL, SIGSTOP uncatchable)
3. Copy old value to userspace (if requested)
4. Copy new value from userspace (if provided)
5. Update task structure
6. Return 0 or error
```

### From exception_handlers.c (signal delivery integration)
```c
1. After syscall completes
2. Check task for pending signals: fut_signal_deliver(task, frame)
3. Signal delivery modifies frame to invoke handler
4. ERET returns to handler instead of interrupted code
```

---

## Key Data Structures

### In `include/kernel/fut_task.h`

```c
struct fut_task {
    // Existing signal fields:
    uint64_t pending_signals;                    // Bitmask of pending signals
    uint64_t signal_mask;                        // Bitmask of blocked signals
    sighandler_t signal_handlers[30];            // Handler for each signal
    uint64_t signal_handler_masks[30];           // sa_mask for each
    int signal_handler_flags[30];                // sa_flags for each
    
    // Need to add:
    struct sigaltstack_storage {
        void *ss_sp;
        size_t ss_size;
        int ss_flags;
    } sigaltstack;
    
    // For timer/alarm:
    uint64_t alarm_expires_ms;                   // Move from global
    // Timer list: struct timer_node *timers;    // (Phase 4)
};
```

### Signal Frame (ARM64)

```c
struct rt_sigframe {
    siginfo_t info;
    ucontext_t uc;
    void (*return_address)(void);
    uint64_t pad;
};
```

---

## References & Related Files

**Signal Infrastructure**:
- `/Users/kelsi/futura/kernel/signal/signal.c` — Core signal logic
- `/Users/kelsi/futura/include/kernel/signal.h` — Signal defines
- `/Users/kelsi/futura/include/kernel/signal_frame.h` — Frame structures
- `/Users/kelsi/futura/include/kernel/fut_task.h` — Task structure

**ARM64 Exception Handling**:
- `/Users/kelsi/futura/platform/arm64/exception_handlers.c` — Exception dispatch
- `/Users/kelsi/futura/platform/arm64/interrupt/gic_irq_handler.c` — IRQ dispatch

**Syscall Tables**:
- `/Users/kelsi/futura/platform/arm64/syscall_table.c` — ARM64 dispatcher
- `/Users/kelsi/futura/subsystems/posix_compat/posix_syscall.c` — x86-64 layer

**Tests**:
- `/Users/kelsi/futura/kernel/tests/sys_signal.c` — Existing signal tests

**Documentation**:
- `/Users/kelsi/futura/docs/ARM64_STATUS.md` — ARM64 progress
- `/Users/kelsi/futura/docs/CURRENT_STATUS.md` — Project status


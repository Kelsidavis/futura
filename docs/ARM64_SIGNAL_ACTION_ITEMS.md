# ARM64 Signal Work — Action Items by Priority

**Generated**: 2025-11-12
**Status**: Ready to implement

---

## IMMEDIATE (Next 1-2 hours)

### 1. Test ARM64 Signal Delivery (Almost Complete)
**File**: `/Users/kelsi/futura/kernel/signal/signal.c:228-355`
**Status**: 90% implemented, needs testing

**What to do**:
- Write simple test: `signal(SIGUSR1, handler); kill(pid, SIGUSR1);`
- Verify rt_sigframe is created
- Verify handler is called with correct arguments
- Verify sigreturn restores context

**Expected**: Signal delivery works end-to-end

---

### 2. Implement sys_sigaltstack() Stub
**File**: `/Users/kelsi/futura/platform/arm64/syscall_table.c:1288-1298`
**Current**: Returns 0 without doing anything

**What to do** (~1.5 hours):
1. Create `/Users/kelsi/futura/kernel/sys_sigaltstack.c` (80 lines)
   - Copy userspace `struct sigaltstack` 
   - Validate stack (16-byte alignment, size > MINSIGSTKSZ)
   - Store in current task
   - Return old stack

2. Add to `include/kernel/syscalls.h`:
   ```c
   long sys_sigaltstack(const struct sigaltstack *ss, struct sigaltstack *old_ss);
   ```

3. Update ARM64 syscall_table.c dispatcher to call it

**Pattern**: Mirror `/Users/kelsi/futura/kernel/sys_sigprocmask.c` (100 lines)

---

## HIGH PRIORITY (Next 2-3 hours)

### 3. Implement sys_sigpending()
**File**: Need to create `/Users/kelsi/futura/kernel/sys_sigpending.c`
**Current**: Not implemented

**What to do** (~0.5 hours):
```c
long sys_sigpending(sigset_t *set) {
    fut_task_t *task = fut_task_current();
    sigset_t pending;
    
    /* Return pending_signals that are NOT blocked */
    pending.__mask = task->pending_signals & ~task->signal_mask;
    
    if (fut_copy_to_user(set, &pending, sizeof(sigset_t)))
        return -EFAULT;
    return 0;
}
```

**Integration**:
- Add forward declare to `include/kernel/syscalls.h`
- Add to ARM64 syscall_table.c dispatch

---

### 4. Implement sys_sigsuspend()
**File**: Need to create `/Users/kelsi/futura/kernel/sys_sigsuspend.c`
**Current**: Not implemented

**What to do** (~1 hour):
```c
long sys_sigsuspend(const sigset_t *mask) {
    fut_task_t *task = fut_task_current();
    sigset_t oldmask;
    
    if (!mask) return -EFAULT;
    
    /* Atomically: save old mask and install new one */
    sigset_t newmask;
    if (fut_copy_from_user(&newmask, mask, sizeof(sigset_t)))
        return -EFAULT;
    
    oldmask.__mask = task->signal_mask;
    task->signal_mask = newmask.__mask;
    
    /* Now wait for signal (Phase 3: block on wait queue)
       For now, just restore mask and return */
    task->signal_mask = oldmask.__mask;
    
    return -EINTR;
}
```

---

### 5. Add x86-64 Signal Delivery
**File**: `/Users/kelsi/futura/kernel/signal/signal.c:357-364`
**Current**: Stub returns 0

**What to do** (~2 hours):
- Mirror ARM64 logic (signal.c:228-355) for x86-64 registers
- Replace registers (x[0-31] → rax-r15, pc → rip, sp → rsp)
- Use x86-64 ABI (rsi=signum, rdx=siginfo_t*, rcx=ucontext_t*)
- Handle XMM (SSE) + x87 FPU state instead of NEON

**Reference**: `subsystems/posix_compat/posix_syscall.c:676-790`

---

## MEDIUM PRIORITY (Next 4-6 hours)

### 6. Complete rt_sigreturn ARM64
**File**: `/Users/kelsi/futura/platform/arm64/syscall_table.c:1300-1350`
**Current**: Stub, needs frame restoration

**What to do** (~1.5 hours):
- Read rt_sigframe from user SP
- Restore all registers from sigcontext
- Restore signal mask
- Modify exception frame for context restoration
- ERET returns to interrupted code

**Reference**: x86-64 version in `posix_syscall.c:700-760`

---

### 7. Move Alarm from Global to Per-Task
**File**: `/Users/kelsi/futura/kernel/sys_alarm.c:22-28`
**Current**: 
```c
static uint64_t global_alarm_expires_ms = 0;
static uint64_t global_alarm_pid = 0;
```

**What to do** (~0.5 hours):
1. Add to `struct fut_task` in `include/kernel/fut_task.h`:
   ```c
   uint64_t alarm_expires_ms;  /* Alarm expiration time (0 = none) */
   ```

2. Update `sys_alarm()` to use `task->alarm_expires_ms` instead of global

3. Remove global variables

**Benefit**: Proper multi-process alarm isolation

---

### 8. Timer Interrupt Handler
**File**: New `/Users/kelsi/futura/platform/arm64/interrupt/timer_handler.c`
**Current**: Not implemented

**What to do** (~2 hours):
1. Create timer expiration check function
2. Hook into ARM Generic Timer IRQ handler
3. Check each task's alarm_expires_ms
4. When expired: send SIGALRM to task
5. For interval timers: reschedule

**Integration point**: `platform/arm64/interrupt/gic_irq_handler.c`

---

### 9. Nanosleep Blocking
**File**: `/Users/kelsi/futura/platform/arm64/syscall_table.c:537-600`
**Current**: Accepts duration but returns immediately

**What to do** (~1 hour):
- Block on timer until duration expires
- Use same timer infrastructure as alarm
- Return 0 if completed, -EINTR if signal interrupts
- Return remaining time in *rem_ptr if interrupted

---

## LOWER PRIORITY (Can be deferred)

### 10. sys_pause() — Full Wait Queue Blocking
**File**: `/Users/kelsi/futura/kernel/sys_pause.c:42-104`
**Current**: Returns -EINTR immediately

**What to do**: Block on wait queue until signal delivered

---

### 11. tkill()/tgkill() — Thread Signals
**Files**: New `sys_tkill.c` and `sys_tgkill.c`
**Current**: Not in ARM64 syscall table

**What to do**: Send signals to specific threads (for multi-threaded future work)

---

## Testing Checklist

### Signal Handler Test
- [ ] Install signal handler with sigaction
- [ ] Send signal with kill
- [ ] Verify handler is called
- [ ] Verify handler receives correct signum
- [ ] Verify handler can modify registers
- [ ] Verify sigreturn restores context

### Alternate Stack Test
- [ ] Set alternate stack with sigaltstack
- [ ] Trigger signal while normal stack full
- [ ] Verify handler runs on alternate stack
- [ ] Test SS_DISABLE flag

### Timer Tests
- [ ] alarm(5) then pause() — should wake after 5s
- [ ] Multiple signals arriving (should deliver in order)
- [ ] Signal during blocked syscall — should return -EINTR

---

## Summary

| Task | File | Est. Hours | Impact |
|------|------|-----------|--------|
| Test ARM64 signal delivery | signal.c | 0.5 | Validate 90% implementation |
| sys_sigaltstack() | New | 1.5 | Signal-heavy programs |
| sys_sigpending() | New | 0.5 | Signal queries |
| sys_sigsuspend() | New | 1 | Atomic signal mask change |
| x86-64 signal delivery | signal.c | 2 | x86-64 compatibility |
| rt_sigreturn ARM64 | syscall_table.c | 1.5 | Frame restoration |
| Move alarm to per-task | sys_alarm.c | 0.5 | Multi-process safety |
| Timer interrupt handler | New | 2 | SIGALRM delivery |
| Nanosleep blocking | syscall_table.c | 1 | Actual sleep behavior |
| **CRITICAL PATH** | — | **3-4** | **Signal delivery working** |
| **ALL ITEMS** | — | **12-14** | **Full signal system** |

---

## Files to Create/Modify

**Create**:
- `/Users/kelsi/futura/kernel/sys_sigaltstack.c` (80 lines)
- `/Users/kelsi/futura/kernel/sys_sigpending.c` (50 lines)
- `/Users/kelsi/futura/kernel/sys_sigsuspend.c` (80 lines)
- `/Users/kelsi/futura/kernel/tests/sys_signal_delivery.c` (200 lines)
- `/Users/kelsi/futura/platform/arm64/interrupt/timer_handler.c` (100 lines)

**Modify**:
- `/Users/kelsi/futura/kernel/signal/signal.c` (x86-64 delivery)
- `/Users/kelsi/futura/platform/arm64/syscall_table.c` (rt_sigreturn)
- `/Users/kelsi/futura/include/kernel/fut_task.h` (add sigaltstack fields)
- `/Users/kelsi/futura/kernel/sys_alarm.c` (use per-task field)
- `/Users/kelsi/futura/include/kernel/syscalls.h` (declarations)

---

## See Also

- Full details: `/Users/kelsi/futura/docs/ARM64_SIGNAL_WORK.md`
- ARM64 status: `/Users/kelsi/futura/docs/ARM64_STATUS.md`
- Project status: `/Users/kelsi/futura/docs/CURRENT_STATUS.md`


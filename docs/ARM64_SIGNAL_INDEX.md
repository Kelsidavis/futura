# ARM64 Signal Handling & Timers — Complete Index

**Generated**: 2025-11-12
**Status**: Priority work identified, documentation complete

## Quick Links

- **Full Analysis**: `ARM64_SIGNAL_WORK.md` — 465 lines, comprehensive breakdown
- **Action Items**: `ARM64_SIGNAL_ACTION_ITEMS.md` — 280 lines, ready to implement
- **This Index**: `ARM64_SIGNAL_INDEX.md` — Navigation guide

---

## What's Complete ✓

1. **Signal Handlers (sigaction)** — Full implementation
   - File: `kernel/sys_sigaction.c`
   - Features: Handler install, masking, flags (SA_RESTART, etc.)

2. **Signal Masking (sigprocmask)** — Full implementation
   - File: `kernel/sys_sigprocmask.c`
   - Features: Block, unblock, setmask operations

3. **Signal Sending (kill)** — Full implementation
   - File: `kernel/sys_kill.c`
   - Features: Send to process, group, broadcast

4. **ARM64 Signal Delivery Framework** — 90% complete
   - File: `kernel/signal/signal.c:228-355`
   - Features: Frame construction, handler invocation, register setup
   - Gap: Integration into all exception return paths

---

## What Needs Work (Prioritized)

### CRITICAL (3-4 hours to working state)

| # | Task | File | Status | Est. | Priority |
|---|------|------|--------|------|----------|
| 1 | Test ARM64 delivery | signal.c:228-355 | 90% | 0.5h | TEST NOW |
| 2 | x86-64 delivery | signal.c:357-364 | Stub | 2h | HIGH |
| 3 | sys_sigaltstack | syscall_table.c:1288 | Stub | 1.5h | HIGH |
| 4 | sys_rt_sigreturn | syscall_table.c:1300 | Partial | 1.5h | HIGH |

### HIGH PRIORITY (Next 3-5 hours)

| # | Task | File | Status | Est. | Priority |
|---|------|------|--------|------|----------|
| 5 | sys_sigpending | NEW | Missing | 0.5h | HIGH |
| 6 | sys_sigsuspend | NEW | Missing | 1h | HIGH |
| 7 | Alarm → per-task | sys_alarm.c | Global | 0.5h | HIGH |
| 8 | Integrate delivery | exception_handlers.c | Partial | 1h | HIGH |

### MEDIUM-HIGH PRIORITY (4-6 hours)

| # | Task | File | Status | Est. | Priority |
|---|------|------|--------|------|----------|
| 9 | Timer interrupt | NEW | Missing | 2h | MED-HIGH |
| 10 | Nanosleep block | syscall_table.c:537 | Stub | 1h | MED-HIGH |
| 11 | Pause blocking | sys_pause.c:42 | Partial | 0.5h | MEDIUM |

---

## File Map

### Core Signal Infrastructure

```
kernel/signal/
├── signal.c                    # Core logic: handlers, masks, delivery
│   ├── fut_signal_init()
│   ├── fut_signal_get_default_action()
│   ├── fut_signal_is_pending()
│   ├── fut_signal_send()
│   ├── fut_signal_set_handler()
│   ├── fut_signal_get_handler()
│   ├── fut_signal_procmask()
│   ├── fut_signal_deliver() [ARM64 IMPL] ← 90% DONE
│   └── fut_signal_deliver() [x86-64 STUB] ← NEEDS WORK

kernel/sys_sigaction.c         # Install signal handler
kernel/sys_sigprocmask.c       # Block/unblock signals
kernel/sys_kill.c              # Send signal to process
kernel/sys_pause.c             # Wait for signal
kernel/sys_alarm.c             # Schedule alarm
```

### ARM64 Exception & Syscall Dispatch

```
platform/arm64/
├── syscall_table.c            # Syscall dispatcher (2800+ lines)
│   ├── sys_nanosleep() [line 537] — sleep stub
│   ├── sys_sigaltstack_wrapper() [line 1288] — STUB
│   ├── sys_rt_sigreturn_wrapper() [line 1300] — INCOMPLETE
│   └── Main dispatch table (handles 177 syscalls)
│
├── exception_handlers.c        # Exception entry point
│   └── handle_svc() — calls signal_deliver() after syscalls
│
└── interrupt/
    ├── gic_irq_handler.c       # IRQ dispatch (timer integration point)
    └── arm64_stubs.c           # Stub functions
```

### Related Syscalls

```
kernel/
├── sys_getpid.c
├── sys_getppid.c
├── sys_exit.c
├── sys_fork.c
├── sys_waitpid.c
├── sys_execve.c
└── ...
```

### Test Infrastructure

```
kernel/tests/
├── sys_signal.c               # Existing signal tests
└── (need to add:)
    ├── sys_signal_delivery.c   # Handler invocation tests
    └── sys_sigaltstack.c       # Altstack tests
```

### Headers

```
include/kernel/
├── signal.h                   # Signal defines (SIGHUP, SIGKILL, etc.)
├── signal_frame.h             # rt_sigframe structure
├── fut_task.h                 # Task structure (needs sigaltstack fields)
└── syscalls.h                 # Syscall declarations

include/sys/
└── signal.h                   # POSIX signal definitions
```

---

## Implementation Patterns

### Pattern 1: Simple Query Syscall
From `sys_sigprocmask.c` — Used for queries that just read state

```c
long sys_sigpending(sigset_t *set) {
    fut_task_t *task = fut_task_current();
    if (\!task) return -ESRCH;
    
    sigset_t pending;
    pending.__mask = task->pending_signals & ~task->signal_mask;
    
    if (fut_copy_to_user(set, &pending, sizeof(sigset_t)))
        return -EFAULT;
    return 0;
}
```

**Applies to**: sigpending

### Pattern 2: Get/Set Syscall
From `sys_sigaction.c` — Used for configuration with get/set semantics

```c
long sys_sigaltstack(struct sigaltstack *ss, struct sigaltstack *old_ss) {
    fut_task_t *task = fut_task_current();
    if (\!task) return -ESRCH;
    
    /* Return old value */
    if (old_ss) {
        /* Copy current from task */
        if (fut_copy_to_user(old_ss, &current, sizeof(...)))
            return -EFAULT;
    }
    
    /* Set new value */
    if (ss) {
        /* Copy from user */
        if (fut_copy_from_user(&new, ss, sizeof(...)))
            return -EFAULT;
        /* Store in task */
    }
    
    return 0;
}
```

**Applies to**: sigaltstack

### Pattern 3: Frame Modification for Signal Delivery
From `signal.c:228-355` — Used to modify exception frame and invoke handler

```c
int fut_signal_deliver(struct fut_task *task, void *frame) {
    /* Find pending signal */
    int signum = ...;
    
    /* Get handler */
    sighandler_t handler = fut_signal_get_handler(task, signum);
    
    /* Build rt_sigframe on user stack */
    struct rt_sigframe sframe = {...};
    
    /* Copy to user stack */
    if (fut_copy_to_user((void *)sp, &sframe, ...))
        return -EFAULT;
    
    /* Modify frame to invoke handler */
    f->pc = (uint64_t)handler;
    f->sp = sp;
    f->x[0] = signum;      /* ARM64 ABI */
    f->x[1] = sp + offsetof(...);
    f->x[2] = sp + offsetof(...);
    
    return signum;
}
```

**Applies to**: Signal delivery, both ARM64 and x86-64

---

## Data Structures Needing Changes

### struct fut_task (include/kernel/fut_task.h)

**Current Fields**:
```c
uint64_t pending_signals;           /* Bitmask of queued signals */
uint64_t signal_mask;               /* Bitmask of blocked signals */
sighandler_t signal_handlers[30];   /* Handler for each signal */
uint64_t signal_handler_masks[30];  /* Mask for each handler */
int signal_handler_flags[30];       /* Flags for each handler */
```

**Need to Add**:
```c
/* Alternate signal stack */
void *sigaltstack_sp;
size_t sigaltstack_size;
int sigaltstack_flags;

/* Per-task alarm */
uint64_t alarm_expires_ms;
```

### struct rt_sigframe (include/kernel/signal_frame.h)

**Already Defined**: Properly structures siginfo_t, ucontext_t, registers

---

## Testing Strategy

### Smoke Tests (5 minutes)
```bash
# Build with test
make clean && make PLATFORM=arm64

# Signal handler should print during boot
# Look for "[SIGNAL]" log messages
```

### Unit Tests (15 minutes)

Test each syscall independently:

```c
// Test sigaction installation
signal(SIGUSR1, handler);
assert(signal_handlers[10] == handler);

// Test sigprocmask blocking
sigprocmask(SIG_BLOCK, &set, NULL);
assert(signal_mask == bitmask);

// Test kill sending
kill(getpid(), SIGUSR1);
assert(pending_signals & (1 << 9));  // SIGUSR1 = signal 10
```

### Integration Tests (30 minutes)

```c
// Full signal delivery
signal(SIGUSR1, handler);
kill(getpid(), SIGUSR1);
// Handler should execute
assert(handler_called == 1);

// Sigreturn
// (handler returns, sigreturn restores context)
assert(registers_restored == 1);

// Pause with signal
pause();  // Should block
// (signal delivery wakes it)
```

### Functional Tests (depends on implementation)

```c
// Alternate stack
sigaltstack(&ss, NULL);
// Trigger signal while main stack full
// Handler should run on alternate stack

// Timer alarm
alarm(2);
pause();  // Should wake after ~2 seconds
```

---

## Integration Points

### Exception Return Path
- **File**: `platform/arm64/exception_handlers.c:handle_svc()`
- **Line**: 74-79
- **Current**: Calls `fut_signal_deliver(task, frame)` after syscall
- **Status**: CORRECT — signal delivery integrated
- **Gap**: Need to add to other exception handlers (IRQ, FIQ, Data Abort)

### Timer Interrupt
- **File**: `platform/arm64/interrupt/gic_irq_handler.c`
- **Current**: Handles generic timer IRQ
- **Need**: Check for expired alarms, send SIGALRM
- **Integration**: Create `timer_handler()` function, call from IRQ dispatch

### Task Initialization
- **File**: `kernel/threading/fut_task.c` — `fut_task_create()`
- **Current**: Initializes signal fields
- **Need**: Initialize sigaltstack fields to disabled state

---

## Build & Test Commands

```bash
# Build ARM64 kernel
make PLATFORM=arm64 clean kernel

# Run with boot messages
make PLATFORM=arm64 run

# Look for signal delivery logs
# Should see "[SIGNAL] OK" during init
# Should see "[SIGACTION]" when handlers installed
# Should see "[SIGNAL] Delivered signal" when sent

# Run specific tests (when implemented)
make PLATFORM=arm64 test
./build/arm64/tests/sys_signal_delivery
```

---

## Reference Commits

Recent ARM64 work:
- VirtIO GPU working (Nov 10)
- Fork/wait fixed (Nov 8)
- User-mode transition (Nov 6)
- MMU enabled (Nov 5)

Signal work started: This session

---

## Glossary

- **rt_sigframe**: Runtime signal frame containing siginfo_t, ucontext_t, handler state
- **sigaltstack**: Alternate stack for signal handlers (prevents stack overflow)
- **sigprocmask**: Mask of blocked signals
- **sigaction**: Structure containing handler, mask, and flags
- **EABI**: ARM64 calling convention (x0-x7 arguments, x0 return)
- **ERET**: ARM64 return from exception (to userspace or lower EL)

---

## Progress Tracking

Start: 2025-11-12 (this session)

### Target: End of Week

- [ ] ARM64 signal delivery tested and working
- [ ] sys_sigaltstack implemented
- [ ] sys_sigpending implemented
- [ ] sys_sigsuspend implemented
- [ ] Basics passing simple test programs

### Target: Next Week

- [ ] x86-64 signal delivery complete
- [ ] rt_sigreturn fully working
- [ ] Timer interrupt integration
- [ ] Nanosleep blocking
- [ ] Comprehensive signal test suite

---

## Notes

1. **ARM64 is primary focus** — x86-64 signal work follows same patterns
2. **Signal delivery is 90% done** — Best ROI is testing and integration
3. **Most new work is boilerplate** — Follow existing patterns in sys_sigprocmask.c
4. **Testing is critical** — Simple signal handler test validates whole system
5. **Timer integration is separate** — Can be done in parallel


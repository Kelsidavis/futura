# ARM64 Timer Interrupt and alarm() Syscall Implementation Status

**Generated**: 2025-11-12
**Analysis Focus**: Timer interrupt routing, alarm() syscall, and SIGALRM delivery on ARM64

---

## Executive Summary

The ARM64 timer and alarm() implementation is **PARTIALLY COMPLETE but has a CRITICAL GAP**: 

1. ✅ **alarm() syscall is fully implemented** (Phase 2 complete)
2. ✅ **ARM Generic Timer is initialized** and running
3. ✅ **Timer interrupt handler is called** via GIC (IRQ 27)
4. ✅ **SIGALRM delivery is integrated** in the timer tick handler
5. ⚠️ **BUT: Timer IRQ is MASKED during initialization** and never unmasked!

This means:
- `alarm()` calls successfully set `task->alarm_expires_ms` 
- Timer tick handler checks for expired alarms and queues SIGALRM
- **However, timer interrupts never actually fire**, so the checks never execute
- Result: **Alarms are set but never delivered**

---

## 1. alarm() Syscall Implementation ✅

### Location
`/Users/kelsi/futura/kernel/sys_alarm.c` (lines 1-88)

### Status: COMPLETE (Phase 2)

The syscall is fully implemented with:

```c
long sys_alarm(unsigned int seconds) {
    fut_task_t *task = fut_task_current();
    if (!task) return -ESRCH;

    uint64_t current_ms = fut_get_ticks();
    
    /* Calculate remaining from previous alarm */
    unsigned int remaining_seconds = 0;
    if (task->alarm_expires_ms > 0) {
        if (task->alarm_expires_ms > current_ms) {
            uint64_t remaining_ms = task->alarm_expires_ms - current_ms;
            remaining_seconds = (unsigned int)((remaining_ms + 999) / 1000);
        }
    }
    
    if (seconds > 0) {
        /* Schedule new alarm */
        task->alarm_expires_ms = current_ms + ((uint64_t)seconds * 1000);
        fut_printf("[ALARM] alarm(%u) set by task %llu, expires at %llu ms\n",
                   seconds, task->pid, task->alarm_expires_ms);
    } else {
        /* Cancel alarm */
        task->alarm_expires_ms = 0;
    }
    
    return (long)remaining_seconds;
}
```

**Key Features**:
- Calculates remaining time from previous alarm
- Stores expiration time in per-task field: `task->alarm_expires_ms`
- Cancels with `alarm(0)`
- Returns remaining seconds (POSIX compliant)
- Includes diagnostic printf logging

**Data Structure**:
- Field defined in `include/kernel/fut_task.h:63`:
  ```c
  uint64_t alarm_expires_ms;  // Alarm expiration time in milliseconds (0 = no alarm)
  ```

### Phase Status Notes
- **Phase 1 (Completed)**: Basic stub ✅
- **Phase 2 (Current/Completed)**: Track alarm expiration time ✅
- **Phase 3 (Current)**: Integrate with timer interrupt to deliver SIGALRM ⚠️ (PARTIAL)
- **Phase 4 (Future)**: Sub-second precision with setitimer()

---

## 2. ARM64 Generic Timer Initialization

### Location
`/Users/kelsi/futura/platform/arm64/platform_init.c:612-660`

### Status: INITIALIZED BUT MASKED ⚠️

```c
void fut_timer_init(uint32_t frequency) {
    /* Read timer frequency from system register */
    timer_frequency = read_sysreg(cntfrq_el0);
    
    fut_serial_puts("[TIMER] ARM Generic Timer frequency: \n");
    
    /* Calculate timer value for desired frequency */
    uint32_t timer_interval = timer_frequency / frequency;  // FUT_TIMER_HZ = 100
    
    /* Set timer compare value */
    write_sysreg(cntp_tval_el0, timer_interval);
    
    /* CRITICAL FIX: Timer IRQs must be disabled during early boot.
     * Timer IRQ handler calls fut_printf(), which creates reentrancy issues
     * when printf is called from both main thread and IRQ context during
     * early boot initialization. This causes serial output corruption and deadlocks.
     *
     * Timer IRQs will be enabled later after:
     * 1. Console input thread is created and running
     * 2. TCP/IP stack is initialized
     * 3. All early boot printf-heavy initialization completes
     */
    
    /* Enable timer: ENABLE=1, IMASK=1 (MASKED - interrupts disabled) */
    write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE | CNTP_CTL_IMASK);
    
    /* Do NOT enable timer interrupt during early boot */
    // fut_irq_enable(30);  // ← THIS IS COMMENTED OUT!
}
```

**Key Points**:
- Timer is **ENABLED** for counting (`CNTP_CTL_ENABLE`)
- Timer interrupts are **MASKED** (`CNTP_CTL_IMASK`)
- GIC enable call is **COMMENTED OUT** and never executed
- Comment indicates intent to enable later, but no code does this

**Register Details**:
- `cntp_tval_el0`: Timer compare value (auto-reloads when counter reaches it)
- `cntp_ctl_el0`: 
  - Bit 0 (ENABLE): Timer counting enabled ✅
  - Bit 1 (IMASK): Interrupt masked (bit=1, so interrupts disabled) ⚠️
  - Bit 2 (ISTATUS): Interrupt status (read-only)

### Problem: Timer IRQ Never Unmasks

Looking at kernel initialization:

**`kernel/kernel_main.c:1507-1513`** (ARM64 branch):
```c
#elif defined(__aarch64__)
    /* ARM64: Timer interrupts already enabled in platform_init.c */
    /* Enable interrupts and start scheduling */
    /* This comment is MISLEADING - timer IRQs are NOT enabled! */
    fut_enable_interrupts();
    fut_schedule();
```

There is **NO CALL** to `fut_irq_enable(27)` for the ARM Generic Timer on ARM64.

Contrast with **x86-64** (`kernel/kernel_main.c:1497`):
```c
fut_irq_enable(0);  /* Unmask PIC IRQ 0 (timer) */
```

---

## 3. Timer Interrupt Handler ✅

### Location
`/Users/kelsi/futura/platform/arm64/interrupt/gic_irq_handler.c` (lines 1-61)

### Status: IMPLEMENTED (but never called because IRQ masked)

```c
void gic_handle_irq(void) {
    if (!gic_cpu_base) return;
    
    /* Read Interrupt Acknowledge Register */
    uint32_t iar = gic_cpu_base[GICC_IAR / sizeof(uint32_t)];
    uint32_t irq_id = iar & 0x3FF;
    
    /* Spurious interrupt check */
    if (irq_id == 1023) return;
    
    /* Dispatch to appropriate handler */
    switch (irq_id) {
        case ARM_TIMER_IRQ:  /* ARM_TIMER_IRQ = 27 (Virtual timer) */
            fut_timer_tick();  /* Call common timer handler */
            break;
        default:
            break;
    }
    
    /* Send End of Interrupt */
    gic_cpu_base[GICC_EOIR / sizeof(uint32_t)] = iar;
}
```

**Key Details**:
- `ARM_TIMER_IRQ = 27` (ARM Generic Timer virtual timer interrupt on QEMU virt)
- Calls `fut_timer_tick()` to handle the interrupt
- Properly sends EOI (End of Interrupt) to GIC

---

## 4. Timer Tick Handler - SIGALRM Integration ✅

### Location
`/Users/kelsi/futura/kernel/timer/fut_timer.c:166-199`

### Status: FULLY IMPLEMENTED

The handler checks **all tasks** for expired alarms every millisecond:

```c
void fut_timer_tick(void) {
    /* Increment tick counter */
    atomic_fetch_add_explicit(&system_ticks, 1, memory_order_relaxed);
    
    /* Wake sleeping threads */
    wake_sleeping_threads();
    
    /* Process timer events */
    process_timer_events();
    
    /* ALARM DELIVERY: Check for expired alarms on all tasks */
    extern fut_task_t *fut_task_list;
    uint64_t current_ms = atomic_load_explicit(&system_ticks, memory_order_relaxed);
    
    for (fut_task_t *task = fut_task_list; task != nullptr; task = task->next) {
        if (task->alarm_expires_ms > 0 && current_ms >= task->alarm_expires_ms) {
            /* Alarm has expired - queue SIGALRM for this task */
            fut_signal_send(task, SIGALRM);
            
            /* Clear alarm (only one alarm per task) */
            task->alarm_expires_ms = 0;
        }
    }
    
    /* Trigger preemptive scheduling if scheduler has started */
    extern fut_thread_t *fut_thread_current(void);
    fut_thread_t *current = fut_thread_current();
    if (current != nullptr) {
        fut_schedule();  /* Preemptive context switch */
    }
}
```

**Integration Points**:
1. Checks `task->alarm_expires_ms` for each task
2. Compares against current system ticks (milliseconds)
3. Calls `fut_signal_send(task, SIGALRM)` to queue the signal
4. Clears the alarm field

---

## 5. SIGALRM Signal Delivery ✅

### Location
`/Users/kelsi/futura/kernel/signal/signal.c:120-139`

### Status: IMPLEMENTED

```c
int fut_signal_send(struct fut_task *task, int signum) {
    if (!task || signum < 1 || signum >= _NSIG) {
        return -EINVAL;
    }
    
    uint64_t signal_bit = (1ULL << (signum - 1));
    
    /* Queue the signal in pending_signals bitmask */
    task->pending_signals |= signal_bit;
    
    /* Wake task if blocked on pause() syscall */
    extern void fut_waitq_wake_one(void *waitq);
    fut_waitq_wake_one(&task->signal_waitq);
    
    fut_printf("[SIGNAL] Queued signal %d for task %llu\n", signum, task->pid);
    return 0;
}
```

**Signal Definition**:
- `SIGALRM = 14` (defined in `include/kernel/signal.h:25`)
- Default action: `SIG_ACTION_TERM` (terminate process)

---

## 6. CRITICAL GAP: Timer IRQ Not Enabled!

### The Problem

The ARM Generic Timer is initialized with interrupts **masked**:

**File**: `platform/arm64/platform_init.c:635-639`
```c
/* Enable timer: ENABLE=1, IMASK=1 (MASKED - interrupts disabled) */
write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE | CNTP_CTL_IMASK);

/* Do NOT enable timer interrupt during early boot */
// fut_irq_enable(30);  // ← COMMENTED OUT, NEVER CALLED
```

### Missing: GIC Interrupt Enable

The GIC needs to be told to route timer interrupts to the CPU:

```c
fut_irq_enable(ARM_TIMER_IRQ);  /* Enable GIC IRQ 27 */
```

This should be called somewhere in the initialization sequence, but it's not.

### Impact

**Flow when timer expires**:
1. ARM Generic Timer decrements counter
2. Counter reaches 0 → internally asserts interrupt signal
3. **GIC has IRQ 27 disabled** → does not forward to CPU
4. **CPU never receives interrupt** 
5. **gic_handle_irq() never called**
6. **fut_timer_tick() never called**
7. **Alarm check never runs**
8. **SIGALRM never sent**

---

## 7. Current Data Flow (What Actually Happens)

### alarm(5) call on ARM64:

```
Task calls alarm(5)
    ↓
sys_alarm() in kernel/sys_alarm.c
    ↓
task->alarm_expires_ms = current_ms + 5000;
    ↓
fut_printf logs: "[ALARM] alarm(5) set by task X, expires at Y ms"
    ↓
Returns 0 (success)
    ↓
Task continues... timer never fires... signal never sent
```

### Expected (when fixed):

```
Task calls alarm(5)
    ↓
task->alarm_expires_ms = current_ms + 5000
    ↓
[5000 ms pass, ARM Generic Timer counts down]
    ↓
Timer counter reaches 0 → asserts interrupt
    ↓
GIC routes IRQ 27 to CPU (IF ENABLED)
    ↓
CPU receives IRQ exception
    ↓
arm64_handle_irq() → gic_handle_irq() → fut_timer_tick()
    ↓
Checks all tasks' alarm_expires_ms
    ↓
If current_ms >= task->alarm_expires_ms:
    fut_signal_send(task, SIGALRM)
    ↓
Signal queued in task->pending_signals bitmask
    ↓
On syscall return or signal delivery path:
    fut_signal_deliver() invokes handler or default action
    ↓
Handler executed in userspace OR process terminates (default)
```

---

## 8. What's Missing (TODO Items)

### 1. CRITICAL: Enable Timer IRQ in GIC

**File**: `platform/arm64/platform_init.c` or `kernel/kernel_main.c`

**What to add**:
```c
/* For ARM64, after interrupts enabled in kernel_main */
fut_irq_enable(27);  /* Enable ARM Generic Timer interrupt */
```

**Options for where**:
- Option A: In `fut_timer_init()` at line 640 (replace the commented line)
- Option B: In `kernel/kernel_main.c` in the ARM64 branch (around line 1510)
- Option C: In `fut_platform_late_init()` after system stabilizes

### 2: MEDIUM: Unmask Timer Interrupts in Control Register

**File**: `platform/arm64/platform_init.c:636`

The register has `CNTP_CTL_IMASK` set (interrupts masked). This needs to be cleared at the appropriate time:

```c
/* After GIC is ready, unmask timer interrupts in the control register */
uint64_t ctl = read_sysreg(cntp_ctl_el0);
ctl &= ~CNTP_CTL_IMASK;  /* Clear mask bit */
write_sysreg(cntp_ctl_el0, ctl);
```

**Current code just sets it**:
```c
write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE | CNTP_CTL_IMASK);
```

Should be updated to only set ENABLE:
```c
write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE);  /* No IMASK = interrupts enabled */
```

### 3: MINOR: Update Misleading Comment

**File**: `kernel/kernel_main.c:1508`

```c
    /* ARM64: Timer interrupts already enabled in platform_init.c */
```

This comment is **FALSE**. Timer interrupts are NOT enabled. Update to:

```c
    /* ARM64: Timer subsystem initialized in platform_init.c, 
     * but IRQ enabled here after other subsystems ready */
```

---

## 9. Architecture-Specific Timer IRQ Numbers

### ARM64 (QEMU virt + GICv2)

From `platform/arm64/interrupt/gic_irq_handler.c:24`:
```c
#define ARM_TIMER_IRQ   27  /* Virtual timer interrupt */
```

**Other timer options**:
- IRQ 26: Physical timer (EL1)
- IRQ 27: Virtual timer (EL1) - **Currently configured**
- IRQ 30: Hypervisor physical timer (EL2) - x86 PIC IRQ 0 equivalent

### x86-64 (QEMU + APIC)

From `kernel/kernel_main.c:1497`:
```c
fut_irq_enable(0);  /* Unmask PIC IRQ 0 (timer) */
```

**Note**: On x86-64, the PIT (Programmable Interval Timer) is programmed separately in `kernel/timer/fut_timer.c:310-331`.

---

## 10. Summary Table

| Component | File | Status | Works? |
|-----------|------|--------|--------|
| alarm() syscall | kernel/sys_alarm.c | Complete ✅ | Yes, sets alarm |
| alarm_expires_ms field | include/kernel/fut_task.h | Complete ✅ | Yes, stores expiration |
| ARM Generic Timer init | platform/arm64/platform_init.c | Complete but masked ⚠️ | Timer runs but masked |
| GIC IRQ dispatcher | platform/arm64/interrupt/gic_irq_handler.c | Complete ✅ | Never called (IRQ masked) |
| Timer tick handler | kernel/timer/fut_timer.c | Complete ✅ | Never called (IRQ masked) |
| Alarm expiration check | kernel/timer/fut_timer.c:180-187 | Complete ✅ | Never executes (IRQ masked) |
| SIGALRM delivery | kernel/signal/signal.c | Complete ✅ | Never queued (check never runs) |
| GIC enable for timer | *MISSING* | Missing ❌ | **CRITICAL BUG** |
| Timer IRQ unmask register | platform/arm64/platform_init.c | Masked | Timer firing blocked |

---

## 11. Testing Status

### What Works
- ✅ Calling `alarm(5)` succeeds
- ✅ Returns correct remaining time from previous alarm
- ✅ `task->alarm_expires_ms` properly stored
- ✅ Canceling with `alarm(0)` works

### What Doesn't Work  
- ❌ Alarms never fire
- ❌ SIGALRM never delivered
- ❌ Timer interrupts never reach CPU
- ❌ Signal handlers for SIGALRM never executed

### Test Case
```c
signal(SIGALRM, handler);  /* Install handler */
alarm(1);                   /* Set 1-second alarm */
pause();                    /* Wait for signal */
/* Handler never called! */
```

---

## 12. Recommended Fix

### Minimal Fix (enable timer IRQ)

1. **In `kernel/kernel_main.c` after line 1510**:
```c
#elif defined(__aarch64__)
    /* ARM64: Timer subsystem initialized, now enable timer IRQ */
    extern void fut_irq_enable(uint8_t irq);
    fut_irq_enable(27);  /* Enable ARM Generic Timer virtual timer */
    
    fut_enable_interrupts();
    fut_schedule();
```

2. **Optional: Update `platform/arm64/platform_init.c:636`**:
```c
/* Enable timer: ENABLE=1 (interrupts NOT masked) */
write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE);  /* Remove CNTP_CTL_IMASK */
```

### Complete Fix (also unmask control register)

Follow minimal fix above, but also change the control register write:
```c
/* Line 636 in platform_init.c */
write_sysreg(cntp_ctl_el0, CNTP_CTL_ENABLE);  /* No IMASK bit - interrupts enabled */
```

---

## 13. References

### Source Files
- Alarm syscall: `/Users/kelsi/futura/kernel/sys_alarm.c`
- Task structure: `/Users/kelsi/futura/include/kernel/fut_task.h:63`
- Timer tick: `/Users/kelsi/futura/kernel/timer/fut_timer.c:166-199`
- Signal send: `/Users/kelsi/futura/kernel/signal/signal.c:120-139`
- Timer init: `/Users/kelsi/futura/platform/arm64/platform_init.c:612-660`
- GIC IRQ: `/Users/kelsi/futura/platform/arm64/interrupt/gic_irq_handler.c`
- Kernel main: `/Users/kelsi/futura/kernel/kernel_main.c:1493-1520`

### Signal Handling Docs
- `/Users/kelsi/futura/docs/ARM64_SIGNAL_WORK.md` (Section 5: Alarm & Timer Signal Delivery)

### ARM64 Architecture
- ARM Generic Timer control registers in `include/arch/arm64/regs.h:220-234`
- GICv2 configuration in `platform/arm64/platform_init.c:532-603`


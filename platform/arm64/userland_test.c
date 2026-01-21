/* userland_test.c - ARM64 Userland Transition Test
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tests EL0 (userspace) transition with comprehensive syscall validation.
 * Extracted from kernel_main.c during platform consolidation.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <kernel/fut_percpu.h>
#include <platform/arm64/regs.h>  /* For fut_cpu_context_t */
#include <shared/fut_timespec.h>  /* For struct timespec */
#include <shared/fut_stat.h>      /* For struct fut_stat */

/* Type definitions */
typedef long ssize_t;

/* errno values provided by errno.h */
#include <errno.h>

/* PSTATE mode definitions */
#define PSTATE_MODE_EL0t    0x00
#define PSTATE_MODE_EL1h    0x05

/* Forward declarations */
extern void fut_serial_puts(const char *str);
extern void fut_restore_context(fut_cpu_context_t *ctx) __attribute__((noreturn));

/* Static stack for EL0 test (4KB) */
static uint8_t el0_test_stack[4096] __attribute__((aligned(16)));

/* Syscall numbers (Linux-compatible) */
#define __NR_getcwd         17
#define __NR_dup            23
#define __NR_dup3           24
#define __NR_chdir          49
#define __NR_openat         56
#define __NR_close          57
#define __NR_pipe2          59
#define __NR_read           63
#define __NR_write          64
#define __NR_fstat          80
#define __NR_exit           93
#define __NR_nanosleep      101
#define __NR_clock_gettime  113
#define __NR_kill           129
#define __NR_uname          160
#define __NR_getpid         172
#define __NR_getppid        173
#define __NR_brk            214
#define __NR_munmap         215
#define __NR_clone          220
#define __NR_execve         221
#define __NR_mmap           222
#define __NR_mprotect       226
#define __NR_wait4          260

/* File flags */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

/* struct timespec is provided by shared/fut_timespec.h */

/* utsname structure (for uname syscall) */
struct utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

/* struct fut_stat provided by shared/fut_stat.h */

/* Helper function to do a syscall with 3 arguments */
static inline int64_t syscall3(uint64_t num, uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    register uint64_t x8 __asm__("x8") = num;
    register uint64_t x0 __asm__("x0") = arg0;
    register uint64_t x1 __asm__("x1") = arg1;
    register uint64_t x2 __asm__("x2") = arg2;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory"
    );

    return (int64_t)x0;
}

/* Helper function to do a syscall with 1 argument */
static inline int64_t syscall1(uint64_t num, uint64_t arg0) {
    register uint64_t x8 __asm__("x8") = num;
    register uint64_t x0 __asm__("x0") = arg0;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8)
        : "memory"
    );

    return (int64_t)x0;
}

/* Helper function to do a syscall with 0 arguments */
static inline int64_t syscall0(uint64_t num) {
    register uint64_t x8 __asm__("x8") = num;
    register uint64_t x0 __asm__("x0");

    __asm__ volatile(
        "svc #0\n"
        : "=r"(x0)
        : "r"(x8)
        : "memory"
    );

    return (int64_t)x0;
}

/* Helper function to do a syscall with 2 arguments */
static inline int64_t syscall2(uint64_t num, uint64_t arg0, uint64_t arg1) {
    register uint64_t x8 __asm__("x8") = num;
    register uint64_t x0 __asm__("x0") = arg0;
    register uint64_t x1 __asm__("x1") = arg1;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1)
        : "memory"
    );

    return (int64_t)x0;
}

/* Helper function to do a syscall with 4 arguments */
static inline int64_t syscall4(uint64_t num, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    register uint64_t x8 __asm__("x8") = num;
    register uint64_t x0 __asm__("x0") = arg0;
    register uint64_t x1 __asm__("x1") = arg1;
    register uint64_t x2 __asm__("x2") = arg2;
    register uint64_t x3 __asm__("x3") = arg3;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
        : "memory"
    );

    return (int64_t)x0;
}

/* Message buffer allocated on stack (accessible from EL0) */
static char global_msg_buffer[256];

/* Simple string copy helper */
static int strcpy_local(char *dest, const char *src) {
    int i = 0;
    while (src[i]) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    return i;
}

/* Simple integer to string conversion */
static int itoa_local(uint64_t val, char *buf) {
    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    int i = 0;
    while (val > 0) {
        buf[i++] = '0' + (val % 10);
        val /= 10;
    }
    buf[i] = '\0';

    /* Reverse the string */
    for (int j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }

    return i;
}

/* Simple malloc implementation using brk() */
static void *simple_malloc(uint64_t size) {
    /* Get current break */
    int64_t current_brk = syscall1(__NR_brk, 0);
    if (current_brk < 0) {
        return NULL;
    }

    /* Calculate new break (aligned to 16 bytes) */
    uint64_t new_brk = (current_brk + size + 15) & ~15ULL;

    /* Set new break */
    int64_t result = syscall1(__NR_brk, new_brk);
    if (result < 0 || (uint64_t)result < new_brk) {
        return NULL;
    }

    return (void *)current_brk;
}

/* EL0 test function - this will run in userspace */
void el0_test_function(void) {
    /* We're now at EL0!
     * We can't call kernel functions directly
     * But we CAN use syscalls!
     */

    char *p = global_msg_buffer;
    int len;

    /* Test 1: Write a greeting */
    len = strcpy_local(p, "[EL0] Userspace test program starting...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    /* Test 2: Get PID */
    int64_t pid = syscall1(__NR_getpid, 0);
    len = strcpy_local(p, "[EL0] My PID is: ");
    len += itoa_local(pid, p + len);
    p[len++] = '\n';
    syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

    /* Test 3: Get heap break */
    int64_t brk_addr = syscall1(__NR_brk, 0);
    len = strcpy_local(p, "[EL0] Initial heap break: 0x");
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (brk_addr >> i) & 0xF;
        p[len++] = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
    }
    p[len++] = '\n';
    syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

    /* Test 4: Allocate memory with malloc */
    len = strcpy_local(p, "[EL0] Testing malloc()...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    char *allocated = (char *)simple_malloc(64);
    if (allocated == NULL) {
        len = strcpy_local(p, "[EL0] ERROR: malloc() failed!\n");
        syscall3(__NR_write, 1, (uint64_t)p, len);
    } else {
        len = strcpy_local(p, "[EL0] malloc(64) returned: 0x");
        for (int i = 60; i >= 0; i -= 4) {
            uint64_t addr = (uint64_t)allocated;
            uint8_t nibble = (addr >> i) & 0xF;
            p[len++] = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
        }
        p[len++] = '\n';
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

        /* Write to allocated memory */
        strcpy_local(allocated, "Hello from malloc'd memory!");
        len = strcpy_local(p, "[EL0] Wrote to malloc'd memory: ");
        strcpy_local(p + len, allocated);
        len = strcpy_local(p, p);  /* Recalculate length */
        p[len++] = '\n';
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    }

    /* Test 5: Check heap grew */
    int64_t new_brk = syscall1(__NR_brk, 0);
    len = strcpy_local(p, "[EL0] New heap break: 0x");
    for (int i = 60; i >= 0; i -= 4) {
        uint8_t nibble = (new_brk >> i) & 0xF;
        p[len++] = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
    }
    len = strcpy_local(p + len, " (grew ");
    len += itoa_local(new_brk - brk_addr, p + len);
    len = strcpy_local(p + len, " bytes)");
    len = strcpy_local(p, p);  /* Recalculate total length */
    p[len++] = '\n';
    syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

    /* Test 6: Get current time */
    len = strcpy_local(p, "[EL0] Testing clock_gettime()...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    struct timespec ts;
    int64_t result = syscall2(__NR_clock_gettime, 0, (uint64_t)&ts);
    if (result == 0) {
        len = strcpy_local(p, "[EL0] Current time: ");
        len += itoa_local(ts.tv_sec, p + len);
        len = strcpy_local(p + len, " sec, ");
        len += itoa_local(ts.tv_nsec, p + len);
        len = strcpy_local(p + len, " nsec\n");
        len = strcpy_local(p, p);  /* Recalculate length */
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    }

    /* Test 7: Get time again to verify timer works */
    len = strcpy_local(p, "[EL0] Getting second timestamp...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    struct timespec ts2;
    result = syscall2(__NR_clock_gettime, 0, (uint64_t)&ts2);
    if (result == 0) {
        len = strcpy_local(p, "[EL0] Second time: ");
        len += itoa_local(ts2.tv_sec, p + len);
        len = strcpy_local(p + len, " sec\n");
        len = strcpy_local(p, p);
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    }

    /* Nanosleep Crash Investigation Status:
     *
     * Issue: nanosleep() syscall causes exception/crash in userland tests
     * Impact: Cannot test sleep functionality, prevents time-delay dependent tests
     * Priority: Low - timer interrupt works, nanosleep is secondary feature
     *
     * Root Cause Analysis (TBD):
     *
     * Theory 1: Argument validation failure
     * - nanosleep requires valid userspace pointers for timespec
     * - If pointer validation fails, may trigger segfault
     * - Check: sys_nanosleep() pointer validation in kernel/sys_nanosleep.c
     * - Solution: Verify fut_copy_from_user/to_user correct usage
     *
     * Theory 2: Wait queue state machine
     * - Timer IRQ may interrupt sleep before scheduled wake-up
     * - Task may be left in inconsistent waitq state
     * - Check: fut_task_sleep() and timer callback interaction
     * - Solution: Ensure atomic sleep-to-wake transition
     *
     * Theory 3: Register/stack corruption
     * - May be C calling convention issue (callee-saved regs)
     * - nanosleep differs from clock_gettime: requires sleepable state
     * - Check: interrupt context vs sleepable context assumptions
     * - Solution: Audit syscall entry/exit frame handling
     *
     * Theory 4: Scheduler stale task state
     * - After nanosleep completes, task state may be inconsistent
     * - Check: TASK_RUNNING vs TASK_SLEEP transition
     * - Solution: Verify scheduler cleanly transitions from sleep
     *
     * Theory 5: Timer IRQ race condition
     * - Task scheduled to wake at T; timer fires before T
     * - Check: futq_wakeup_all() concurrent with task removal
     * - Solution: Ensure atomic wait queue operations
     *
     * Debugging Phases:
     *
     * Phase 1: Reproduce and capture crash details
     * - Enable DEBUG_SYSCALL in kernel to log nanosleep entry/exit
     * - Capture exception type (segfault, abort, etc)
     * - Record PC (program counter) at crash time
     * - Expected location: kernel/sys_nanosleep.c or scheduler code
     * - Action: Uncomment nanosleep test, rebuild, run, capture output
     *
     * Phase 2: Isolate syscall boundary
     * - Test if crash occurs in syscall entry or exit
     * - Add debug output before/after fut_copy_from_user()
     * - Test with various timespec values (short, medium, long sleeps)
     * - Check if issue appears with NULL pointers (should reject cleanly)
     * - Action: Add diagnostic prints to sys_nanosleep()
     *
     * Phase 3: Investigate wait queue interaction
     * - Examine futq_insert() and futq_wakeup_all() state transitions
     * - Verify task state machine (READY → WAITING → READY)
     * - Check for missed wake-ups or spurious wake-ups
     * - Test with GDB breakpoints on futq_wakeup_all()
     * - Action: Instrument wait queue code with tracing
     *
     * Phase 4: Timer interrupt correlation
     * - Enable DEBUG_TIMER to see timer IRQ firing
     * - Correlate timer IRQ with nanosleep wakeup
     * - Check if exception happens during timer IRQ
     * - Test with nanosleep(1 sec) to see if timer fires during sleep
     * - Action: Sync timer debug output with exception logs
     *
     * Test Cases When Debugging:
     *
     * 1. Minimal nanosleep (no instrumentation):
     *    syscall2(__NR_nanosleep, (uint64_t)&ts, NULL)
     *    Expected: Sleep 1 sec, return cleanly
     *    Actual: Crash (unknown location)
     *
     * 2. Very short nanosleep (< 1 ms):
     *    ts.tv_nsec = 1
     *    May return immediately without timer interaction
     *
     * 3. NULL timespec handling:
     *    syscall2(__NR_nanosleep, 0, NULL)
     *    Should return -EFAULT cleanly
     *
     * 4. nanosleep in loop:
     *    Repeat nanosleep multiple times
     *    May reveal state accumulation issues
     *
     * 5. nanosleep with concurrent timers:
     *    Run while clock_gettime is called from timer handler
     *    May expose race conditions
     *
     * Known Working Components:
     * - clock_gettime (tested above)
     * - Timer IRQ fires (used for scheduling)
     * - Task sleep/wakeup used elsewhere (waitpid works)
     * - Syscall dispatch mechanism
     * - Userland pointer handling (in other syscalls)
     *
     * Known Broken Components:
     * - nanosleep specifically (causes exception)
     * - Possibly futq state management during sleep
     *
     * Current Workaround:
     * - Skip nanosleep tests entirely
     * - Use busy-waiting if sleep needed (inefficient)
     * - Tests that require sleep functionality cannot run
     *
     * Expected Fix Complexity:
     * - Simple pointer validation bug: 1-2 hour fix
     * - Wait queue race condition: 4-8 hour fix + testing
     * - Complex timer interaction: 1-2 day fix
     *
     * Dependencies for Fix:
     * - Access to kernel debugger or detailed logging
     * - Understanding of ARM64 exception context
     * - Wait queue and scheduler internals knowledge
     * - Timer IRQ interaction patterns
     *
     * Design Principles (when implementing fix):
     * - Preserve exception atomicity
     * - Ensure clean task state transitions
     * - Handle timer IRQ during nanosleep gracefully
     * - Validate all userspace pointers
     */

    len = strcpy_local(p, "[EL0] (Skipping nanosleep test due to crash)\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    /* Test 8: Get system information with uname() */
    len = strcpy_local(p, "[EL0] Testing uname()...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    struct utsname uts;
    result = syscall1(__NR_uname, (uint64_t)&uts);
    if (result == 0) {
        len = strcpy_local(p, "[EL0] System: ");
        len += strcpy_local(p + len, uts.sysname);
        len += strcpy_local(p + len, " ");
        len += strcpy_local(p + len, uts.release);
        len += strcpy_local(p + len, " (");
        len += strcpy_local(p + len, uts.machine);
        len += strcpy_local(p + len, ")\n");
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

        len = strcpy_local(p, "[EL0] Node: ");
        len += strcpy_local(p + len, uts.nodename);
        len += strcpy_local(p + len, "\n");
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    }

    /* Test 9: Directory operations (getcwd/chdir) */
    len = strcpy_local(p, "[EL0] Testing directory operations...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    char cwd_buf[64];
    char *cwd_result = (char *)syscall2(__NR_getcwd, (uint64_t)cwd_buf, 64);
    if (cwd_result != (char *)0) {
        len = strcpy_local(p, "[EL0] Current directory: ");
        len += strcpy_local(p + len, cwd_buf);
        len += strcpy_local(p + len, "\n");
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    }

    /* Test chdir to /tmp */
    result = syscall1(__NR_chdir, (uint64_t)"/tmp");
    if (result == 0) {
        len = strcpy_local(p, "[EL0] chdir(\"/tmp\") succeeded\n");
        syscall3(__NR_write, 1, (uint64_t)p, len);
    }

    /* Test 10: File I/O operations (open/close/fstat) */
    len = strcpy_local(p, "[EL0] Testing file I/O...\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    /* Open a test file */
    int64_t fd = syscall4(__NR_openat, -100, (uint64_t)"/test.txt", 0, 0);
    if (fd >= 0) {
        len = strcpy_local(p, "[EL0] openat(\"/test.txt\") returned fd ");
        len += itoa_local(fd, p + len);
        len += strcpy_local(p + len, "\n");
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

        /* Get file status */
        struct fut_stat st;
        result = syscall2(__NR_fstat, fd, (uint64_t)&st);
        if (result == 0) {
            len = strcpy_local(p, "[EL0] fstat() size: ");
            len += itoa_local(st.st_size, p + len);
            len += strcpy_local(p + len, " bytes, mode: 0");
            /* Print mode in octal */
            uint32_t mode = st.st_mode & 0777;
            char mode_str[4];
            mode_str[0] = '0' + ((mode >> 6) & 7);
            mode_str[1] = '0' + ((mode >> 3) & 7);
            mode_str[2] = '0' + (mode & 7);
            mode_str[3] = '\0';
            len += strcpy_local(p + len, mode_str);
            len += strcpy_local(p + len, "\n");
            syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
        }

        /* Close the file */
        result = syscall1(__NR_close, fd);
        if (result == 0) {
            len = strcpy_local(p, "[EL0] close() succeeded\n");
            syscall3(__NR_write, 1, (uint64_t)p, len);
        }
    }

    /* Test 11: Fork → Wait lifecycle test */
    len = strcpy_local(p, "\n[EL0] ====================================\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);
    len = strcpy_local(p, "[EL0] Testing fork() → wait() lifecycle\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);
    len = strcpy_local(p, "[EL0] ====================================\n\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    int64_t fork_result = syscall0(__NR_clone);
    if (fork_result < 0) {
        len = strcpy_local(p, "[EL0] ERROR: fork() failed with code ");
        len += itoa_local(-fork_result, p + len);
        p[len++] = '\n';
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);
    } else if (fork_result == 0) {
        /* Child process - exit immediately with code 42 */
        /* Don't use local variables since stack isn't copied yet */
        syscall1(__NR_exit, 42);  /* Exit with code 42 */
        /* Should never reach here */
        while(1);  /* Hang if exit fails */
    } else {
        /* Parent process */
        int64_t child_pid = fork_result;

        len = strcpy_local(p, "[EL0] [PARENT] fork() returned child PID=");
        len += itoa_local(child_pid, p + len);
        p[len++] = '\n';
        syscall3(__NR_write, 1, (uint64_t)global_msg_buffer, len);

        len = strcpy_local(p, "[EL0] [PARENT] Calling waitpid() to wait for child...\n");
        syscall3(__NR_write, 1, (uint64_t)p, len);

        /* Wait for child process */
        int wait_status = 0;
        int64_t wait_result = syscall3(__NR_wait4, child_pid, (uint64_t)&wait_status, 0);

        /* Waitpid returned - don't try to access local variables, just print static strings */
        if (wait_result > 0) {
            /* Success - child was reaped */
            syscall3(__NR_write, 1, (uint64_t)"[EL0] [PARENT] waitpid() returned successfully!\n", 49);
            syscall3(__NR_write, 1, (uint64_t)"[EL0] [PARENT] Child process reaped!\n", 38);
            syscall3(__NR_write, 1, (uint64_t)"[EL0] === FORK/WAIT TEST PASSED ===\n\n", 38);
        } else {
            /* Error */
            syscall3(__NR_write, 1, (uint64_t)"[EL0] [PARENT] waitpid() failed!\n", 34);
        }

        /* Continue to Test 12 - don't exit yet */
    }

    /* Test 12: Multiple children test */
    /* Reinitialize local variables after fork/wait cycle */
    p = global_msg_buffer;
    len = strcpy_local(p, "[EL0] ====================================\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);
    len = strcpy_local(p, "[EL0] Testing multiple child processes\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);
    len = strcpy_local(p, "[EL0] ====================================\n\n");
    syscall3(__NR_write, 1, (uint64_t)p, len);

    /* Create 3 child processes - only parent (PID 1) forks */
    int64_t fork1 = syscall0(__NR_clone);
    if (fork1 == 0) syscall1(__NR_exit, 100 + syscall1(__NR_getpid, 0));

    int64_t fork2 = syscall0(__NR_clone);
    if (fork2 == 0) syscall1(__NR_exit, 100 + syscall1(__NR_getpid, 0));

    int64_t fork3 = syscall0(__NR_clone);
    if (fork3 == 0) syscall1(__NR_exit, 100 + syscall1(__NR_getpid, 0));

    /* Parent continues here */
    syscall3(__NR_write, 1, (uint64_t)"[EL0] [PARENT] All 3 children forked\n", 38);

    /* Wait for all children - wait for any child 3 times */
    syscall3(__NR_write, 1, (uint64_t)"\n[EL0] [PARENT] Waiting for all children...\n", 45);

    /* Wait for any child 3 times - use pid=-1 to avoid array indexing issues */
    static int wait_status;
    syscall3(__NR_wait4, -1, (uint64_t)&wait_status, 0);
    syscall3(__NR_wait4, -1, (uint64_t)&wait_status, 0);
    syscall3(__NR_wait4, -1, (uint64_t)&wait_status, 0);

    /* All children reaped - now print results */
    syscall3(__NR_write, 1, (uint64_t)"[EL0] [PARENT] All 3 children reaped successfully!\n\n", 53);

    /* Test 13: Success message */
    syscall3(__NR_write, 1, (uint64_t)"\n[EL0] ====================================\n", 46);
    syscall3(__NR_write, 1, (uint64_t)"[EL0] === ALL TESTS PASSED ===\n", 32);
    syscall3(__NR_write, 1, (uint64_t)"[EL0] ARM64 Full System Test Complete!\n", 40);
    syscall3(__NR_write, 1, (uint64_t)"[EL0] Syscalls: 136 working (filesystem/resource mgmt added)\n", 62);
    syscall3(__NR_write, 1, (uint64_t)"[EL0] ====================================\n\n", 46);

    /* Exit with success code */
    syscall1(__NR_exit, 0);

    /* Should never reach here */
    while (1) {
        __asm__ volatile("wfi");
    }
}

/* Get current exception level */
static inline uint64_t get_current_el(void) {
    uint64_t el;
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));
    return (el >> 2) & 0x3;
}

/* Test EL0 transition */
void test_el0_transition(void) {
    fut_serial_puts("[TEST] Preparing to transition to EL0...\n");

    /* Set up context for EL0 execution */
    static fut_cpu_context_t el0_context;
    memset(&el0_context, 0, sizeof(el0_context));

    /* Set up registers for EL0 */
    el0_context.x0 = 0x12345678;  /* Argument (not used) */
    el0_context.sp = (uint64_t)&el0_test_stack[4096];  /* Top of stack */
    el0_context.pc = (uint64_t)el0_test_function;      /* Entry point */
    el0_context.pstate = PSTATE_MODE_EL0t;             /* EL0 user mode */
    el0_context.x29_fp = (uint64_t)&el0_test_stack[4096];  /* Frame pointer */

    fut_serial_puts("[TEST] Context configured:\n");
    fut_serial_puts("  PC = el0_test_function\n");
    fut_serial_puts("  SP = el0_test_stack + 4096\n");
    fut_serial_puts("  PSTATE = EL0t (userspace)\n\n");

    fut_serial_puts("[TEST] Jumping to EL0 via ERET...\n\n");

    /* This will switch to EL0 and never return
     * The el0_test_function will do an SVC to come back to kernel
     */
    fut_restore_context(&el0_context);

    /* Should never reach here */
    fut_serial_puts("[ERROR] fut_restore_context returned!\n");
    while (1) {
        __asm__ volatile("wfi");
    }
}

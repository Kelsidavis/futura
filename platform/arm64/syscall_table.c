/* syscall_table.c - ARM64 System Call Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 syscall table and dispatcher.
 * Uses Linux-compatible ABI: x8 = syscall number, x0-x7 = arguments
 */

#include <stdint.h>
#include <stddef.h>

/* Forward declarations */
extern void fut_serial_puts(const char *str);
extern void fut_serial_putc(char c);
extern uint64_t fut_rdtsc(void);
extern uint64_t fut_cycles_to_ns(uint64_t cycles);
extern uint64_t fut_cycles_per_ms(void);

/* Syscall return values */
#define SYSCALL_SUCCESS     0
#define SYSCALL_ERROR      -1
#define ENOSYS             38      /* Function not implemented */
#define EINVAL             22      /* Invalid argument */

/* ============================================================
 *   System Call Implementations
 * ============================================================ */

/* sys_write - write to file descriptor
 * x0 = fd, x1 = buf, x2 = count
 * For now, only supports fd=1 (stdout) and fd=2 (stderr)
 */
static int64_t sys_write(uint64_t fd, uint64_t buf, uint64_t count,
                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;

    /* Only support stdout (1) and stderr (2) for now */
    if (fd != 1 && fd != 2) {
        fut_serial_puts("[SYSCALL] write() failed: invalid fd\n");
        return -EINVAL;
    }

    /* Validate buffer pointer (simple check) */
    if (buf == 0) {
        fut_serial_puts("[SYSCALL] write() failed: null buffer\n");
        return -EINVAL;
    }

    if (count == 0) {
        return 0;  /* Writing 0 bytes is success */
    }

    /* Write each character to serial console */
    const char *buffer = (const char *)buf;
    for (size_t i = 0; i < count; i++) {
        fut_serial_putc(buffer[i]);
    }

    return (int64_t)count;
}

/* sys_exit - terminate current process
 * x0 = exit_code
 */
static int64_t sys_exit(uint64_t exit_code, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    fut_serial_puts("[SYSCALL] Process exiting with code: ");
    if (exit_code == 0) {
        fut_serial_puts("0 (success)\n");
    } else {
        fut_serial_puts("non-zero\n");
    }

    /* For now, just loop forever
     * TODO: Implement proper process termination
     */
    while (1) {
        __asm__ volatile("wfi");
    }

    return 0;  /* Never reached */
}

/* sys_getpid - get process ID
 * Returns: current process ID
 */
static int64_t sys_getpid(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* For now, return a dummy PID */
    return 1;
}

/* sys_getppid - get parent process ID
 * Returns: parent process ID
 */
static int64_t sys_getppid(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                           uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* For now, return a dummy PPID */
    return 0;
}

/* sys_brk - change data segment size
 * x0 = new_brk
 * Returns: new break on success, current break if new_brk is 0
 */
static int64_t sys_brk(uint64_t new_brk, uint64_t arg1, uint64_t arg2,
                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Simple implementation: maintain a per-"process" heap
     * For now, use a static heap region since we only have one test process
     * In a real implementation, this would be per-task
     */
    static uint8_t heap[256 * 1024];  /* 256KB heap */
    static uint64_t current_brk = 0;

    /* Initialize on first call */
    if (current_brk == 0) {
        current_brk = (uint64_t)&heap[0];
    }

    /* If new_brk is 0, return current break */
    if (new_brk == 0) {
        return (int64_t)current_brk;
    }

    /* Validate new_brk is within heap bounds */
    uint64_t heap_start = (uint64_t)&heap[0];
    uint64_t heap_end = (uint64_t)&heap[sizeof(heap)];

    if (new_brk < heap_start || new_brk > heap_end) {
        return (int64_t)current_brk;  /* Return current break on error */
    }

    /* Set new break */
    current_brk = new_brk;
    return (int64_t)current_brk;
}

/* sys_read - read from file descriptor
 * x0 = fd, x1 = buf, x2 = count
 * For now, only supports fd=0 (stdin)
 */
static int64_t sys_read(uint64_t fd, uint64_t buf, uint64_t count,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;

    /* Only support stdin (0) for now */
    if (fd != 0) {
        return -EINVAL;
    }

    /* Validate buffer pointer */
    if (buf == 0) {
        return -EINVAL;
    }

    /* For now, return EOF (0) since we don't have interrupt-driven input
     * TODO: In a real implementation, this would block waiting for UART input
     */
    (void)count;
    return 0;  /* EOF */
}

/* Timespec structure (for clock_gettime and nanosleep) */
struct timespec {
    int64_t tv_sec;      /* Seconds */
    int64_t tv_nsec;     /* Nanoseconds */
};

/* sys_clock_gettime - get time
 * x0 = clockid, x1 = timespec*
 */
static int64_t sys_clock_gettime(uint64_t clockid, uint64_t ts_ptr,
                                  uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (ts_ptr == 0) {
        return -EINVAL;
    }

    /* Get current cycle count */
    uint64_t cycles = fut_rdtsc();
    uint64_t ns = fut_cycles_to_ns(cycles);

    /* Convert to seconds and nanoseconds */
    struct timespec *ts = (struct timespec *)ts_ptr;
    ts->tv_sec = ns / 1000000000ULL;
    ts->tv_nsec = ns % 1000000000ULL;

    (void)clockid;  /* Ignore clockid for now */
    return 0;
}

/* sys_nanosleep - sleep for specified time
 * x0 = req (timespec*), x1 = rem (timespec*)
 */
static int64_t sys_nanosleep(uint64_t req_ptr, uint64_t rem_ptr,
                             uint64_t arg2, uint64_t arg3,
                             uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (req_ptr == 0) {
        return -EINVAL;
    }

    struct timespec *req = (struct timespec *)req_ptr;

    /* Convert requested time to nanoseconds */
    uint64_t sleep_ns = req->tv_sec * 1000000000ULL + req->tv_nsec;

    /* Get start time */
    uint64_t start_cycles = fut_rdtsc();

    /* Busy wait (simple implementation)
     * TODO: Use timer interrupts for real sleep
     */
    while (1) {
        uint64_t current_cycles = fut_rdtsc();
        uint64_t elapsed_cycles = current_cycles - start_cycles;
        uint64_t elapsed_ns = fut_cycles_to_ns(elapsed_cycles);

        if (elapsed_ns >= sleep_ns) {
            break;
        }
    }

    /* No remaining time */
    if (rem_ptr != 0) {
        struct timespec *rem = (struct timespec *)rem_ptr;
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }

    return 0;
}

/* ============================================================
 *   System Call Table
 * ============================================================ */

/* Syscall function pointer type */
typedef int64_t (*syscall_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* Syscall table entry */
struct syscall_entry {
    syscall_fn_t handler;
    const char *name;
};

/* ARM64 syscall numbers (Linux-compatible subset) */
#define __NR_read           63
#define __NR_write          64
#define __NR_exit           93
#define __NR_exit_group     94
#define __NR_nanosleep      101
#define __NR_getpid         172
#define __NR_getppid        173
#define __NR_clock_gettime  113
#define __NR_brk            214

/* Maximum syscall number */
#define MAX_SYSCALL         300

/* Syscall table - sparse array indexed by syscall number */
static struct syscall_entry syscall_table[MAX_SYSCALL] = {
    [__NR_read]         = { (syscall_fn_t)sys_read,       "read" },
    [__NR_write]        = { (syscall_fn_t)sys_write,      "write" },
    [__NR_exit]         = { (syscall_fn_t)sys_exit,       "exit" },
    [__NR_exit_group]   = { (syscall_fn_t)sys_exit,       "exit_group" },
    [__NR_nanosleep]    = { (syscall_fn_t)sys_nanosleep,  "nanosleep" },
    [__NR_clock_gettime]= { (syscall_fn_t)sys_clock_gettime, "clock_gettime" },
    [__NR_getpid]       = { (syscall_fn_t)sys_getpid,     "getpid" },
    [__NR_getppid]      = { (syscall_fn_t)sys_getppid,    "getppid" },
    [__NR_brk]          = { (syscall_fn_t)sys_brk,        "brk" },
};

/* ============================================================
 *   System Call Dispatcher
 * ============================================================ */

/**
 * arm64_syscall_dispatch - Dispatch system call
 * @syscall_num: Syscall number (from x8)
 * @arg0-arg5: Syscall arguments (from x0-x5)
 *
 * Returns: Syscall return value (placed in x0 of exception frame)
 */
int64_t arm64_syscall_dispatch(uint64_t syscall_num,
                               uint64_t arg0, uint64_t arg1,
                               uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5) {
    /* Validate syscall number */
    if (syscall_num >= MAX_SYSCALL) {
        fut_serial_puts("[SYSCALL] Invalid syscall number: ");
        return -ENOSYS;
    }

    /* Get syscall handler */
    struct syscall_entry *entry = &syscall_table[syscall_num];

    if (entry->handler == NULL) {
        fut_serial_puts("[SYSCALL] Unimplemented syscall: ");
        return -ENOSYS;
    }

    /* Log syscall (optional - can be disabled for production) */
    fut_serial_puts("[SYSCALL] ");
    fut_serial_puts(entry->name);
    fut_serial_puts("()\n");

    /* Call syscall handler */
    return entry->handler(arg0, arg1, arg2, arg3, arg4, arg5);
}

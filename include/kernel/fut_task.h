/* fut_task.h - Futura OS Task (Process) Subsystem (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Tasks are containers for threads, representing processes.
 * Each task has its own address space (future VMM integration).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "fut_thread.h"
#include "fut_waitq.h"
#include "signal.h"
#include "signal_frame.h"

struct net_iface;
struct net_route;

struct fut_mm;

/* Maximum POSIX timers per process */
#define FUT_POSIX_TIMER_MAX 8

/* Per-process POSIX timer */
typedef struct fut_posix_timer {
    int active;             /* Slot in use */
    int armed;              /* Timer is armed (counting down) */
    int clockid;            /* CLOCK_REALTIME, CLOCK_MONOTONIC */
    int signo;              /* Signal to deliver */
    int notify;             /* SIGEV_NONE, SIGEV_SIGNAL, or SIGEV_THREAD_ID */
    int overrun;            /* Overrun count since last signal delivery */
    uint64_t expiry_ms;     /* Absolute expiration time in ms (0 = disarmed) */
    uint64_t interval_ms;   /* Repeat interval in ms (0 = one-shot) */
    long sigev_value;       /* sigev_value.sival_int/ptr (passed to SA_SIGINFO handler as si_value) */
    uint64_t target_tid;    /* Target thread TID for SIGEV_THREAD_ID delivery */
} fut_posix_timer_t;

/* Forward declaration */
typedef struct fut_task fut_task_t;

/* ============================================================
 *   Task Configuration Constants
 * ============================================================ */

/* Initial file descriptor table size for new tasks */
#define FUT_FD_TABLE_INITIAL_SIZE 64

/* Default file creation mask (umask) for new tasks.
 * 0022 = owner read/write, group/others read-only.
 * Files created with mode 0666 become 0644 (rw-r--r--)
 * Directories created with mode 0777 become 0755 (rwxr-xr-x) */
#define FUT_UMASK_DEFAULT 0022

/* ============================================================
 *   Task Structure (Process Container)
 * ============================================================ */

struct fut_task {
    uint64_t pid;                      // Process ID (64-bit)

    struct fut_mm *mm;                 // Address space

    struct fut_task *parent;           // Parent task
    struct fut_task *first_child;      // Child list head
    struct fut_task *sibling;          // Next sibling in parent list
    fut_waitq_t child_waiters;         // Wait queue for waitpid callers
    /* pidfd exit notification: up to 4 epoll/poll/select waitqs to wake on exit */
#define FUT_PIDFD_NOTIFY_MAX 4
    fut_waitq_t *pidfd_notify[FUT_PIDFD_NOTIFY_MAX];
    fut_spinlock_t pidfd_notify_lock;

    enum {
        FUT_TASK_RUNNING = 0,
        FUT_TASK_ZOMBIE,
        FUT_TASK_STOPPED,    /* stopped by SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU */
    } state;

    int exit_code;                     // Exit status (8-bit in low byte)
    int term_signal;                   // Terminating signal (0 if normal exit)

    fut_thread_t *threads;             // Linked list of threads
    uint64_t thread_count;             // Number of threads in task

    /* Process credentials (POSIX three-tier UID/GID model)
     *
     * Real UID/GID: Original process owner, used for accounting
     * Effective UID/GID: Used for permission checks (file access, signals, etc.)
     * Saved UID/GID: Backup of previous effective UID/GID for privilege swapping
     *
     * Privilege model:
     * - Superuser (uid 0): Can set any UID/GID values
     * - Regular user: Can only set to current real, effective, or saved UID/GID
     */
    uint32_t uid;                      // Effective UID (used for permission checks)
    uint32_t gid;                      // Effective GID (used for permission checks)
    uint32_t ruid;                     // Real UID (original process owner)
    uint32_t rgid;                     // Real GID (original process group)
    uint32_t suid;                     // Saved UID (backup for privilege swapping)
    uint32_t sgid;                     // Saved GID (backup for privilege swapping)

    /* Supplementary groups (POSIX getgroups/setgroups) */
    int ngroups;                       // Number of supplementary groups (0-32)
    uint32_t groups[32];               // Supplementary group IDs (NGROUPS_MAX=32)

    /* Process group and session (job control) */
    uint64_t pgid;                     // Process group ID (for job control)
    uint64_t sid;                      // Session ID (controlling terminal session)
    uint32_t tty_nr;                   // Controlling terminal dev_t (0 = none; Linux: MKDEV(136,n) for /dev/pts/n)

    /* Signal handling */
    sighandler_t signal_handlers[_NSIG];  // Array of signal handlers (index 1-30)
    uint64_t signal_mask;                 // Mask of currently blocked signals
    uint64_t signal_handler_masks[_NSIG]; // Per-handler masks (signals to block during handler)
    unsigned long signal_handler_flags[_NSIG]; // Per-handler flags (SA_RESTART, SA_RESETHAND, etc.)
    void (*signal_handler_restorers[_NSIG])(void); // sa_restorer: trampoline (SA_RESTORER flag)
    uint64_t pending_signals;          // Bitmask of pending signals awaiting delivery
    fut_waitq_t signal_waitq;          // Wait queue for pause() blocking until signal
    struct sigaltstack sig_altstack;   // Alternate signal stack configuration
    fut_waitq_t stop_waitq;            // Wait queue for SIGSTOP/SIGCONT
    int stop_signal;                   // Signal that caused the stop (SIGSTOP, SIGTSTP, etc.)
    int stop_reported;                 // 1 after waitpid(WUNTRACED) consumed the stop event
    int exit_signal;                   // Signal to send to parent on exit (SIGCHLD=17 for fork, 0 for threads)

    /* Alarm timer (also used as ITIMER_REAL one-shot backing store) */
    uint64_t alarm_expires_ms;         // Alarm expiration time in milliseconds (0 = no alarm)

    /* Interval timers (setitimer/getitimer) */
    uint64_t itimer_real_interval_ms;  // ITIMER_REAL repeat interval (0 = one-shot)
    uint64_t itimer_virt_value_ms;     // ITIMER_VIRTUAL remaining value (ms)
    uint64_t itimer_virt_interval_ms;  // ITIMER_VIRTUAL repeat interval (ms)
    uint64_t itimer_prof_value_ms;     // ITIMER_PROF remaining value (ms)
    uint64_t itimer_prof_interval_ms;  // ITIMER_PROF repeat interval (ms)

    /* POSIX per-process timers (timer_create/timer_settime/timer_delete) */
    fut_posix_timer_t posix_timers[FUT_POSIX_TIMER_MAX];

    /* Thread cleanup (for NPTL/pthread support) */
    int *clear_child_tid;              // Address to clear and wake on thread exit (set_tid_address)

    /* File system context */
    uint64_t current_dir_ino;          // Current working directory inode (root=1)
    char *cwd_cache;                   // Cached current working directory path (points to cwd_cache_buf)
    char cwd_cache_buf[256];           // Buffer for caching current working directory path
    uint32_t umask;                    // File creation mask (per-task, not global)
    unsigned long personality;         // Execution personality (PER_LINUX etc.)
    int nice;                          // Nice value: -20 (highest) to +19 (lowest), default 0
    uint64_t sched_flags;              // Scheduling flags (e.g. SCHED_FLAG_RESET_ON_FORK)

    /* prctl state */
    char comm[16];                     // Process name (PR_SET_NAME/PR_GET_NAME, max 15 chars + null)
    char exe_path[256];                // Path to executable image (/proc/self/exe target)
    char proc_cmdline[512];            // /proc/self/cmdline: null-separated argv (Linux format)
    uint16_t proc_cmdline_len;         // Number of valid bytes in proc_cmdline
    char proc_environ[2048];           // /proc/self/environ: null-separated envp (Linux format)
    uint16_t proc_environ_len;         // Number of valid bytes in proc_environ
    int pdeathsig;                     // Signal to send on parent death (PR_SET_PDEATHSIG, 0=none)
    unsigned long no_new_privs;        // PR_SET_NO_NEW_PRIVS flag (sticky, prevents execve setuid)
    int dumpable;                      // PR_SET_DUMPABLE (1=dumpable, 0=not, default 1)
    int seccomp_mode;                  // 0=disabled, 1=strict, 2=filter (BPF)
    void *seccomp_filter;              // Pointer to seccomp_filter chain (struct seccomp_filter_prog *)
    int seccomp_filter_count;          // Number of installed BPF filters
    int did_exec;                      // Set after first execve (blocks setpgid from parent)
    int keepcaps;                      // PR_SET_KEEPCAPS: retain caps across setuid 0→non-0
    int auto_reap;                     // 1 = parent had SIGCHLD=SIG_IGN or SA_NOCLDWAIT; reap on thread exit
    int oom_score_adj;                 // /proc/<pid>/oom_score_adj: OOM killer bias (-1000..1000)
    int suppress_sigpipe;              // Transient: suppress SIGPIPE during MSG_NOSIGNAL send
    int msg_dontwait;                  // Transient: per-call MSG_DONTWAIT (avoids mutating sock->flags)
    int vfs_no_symlinks;               // Transient: openat2 RESOLVE_NO_SYMLINKS — reject symlink traversal

    /* ptrace state (process tracing / debugging) */
    uint64_t ptrace_tracer;            // PID of tracer process (0 = not being traced)
    uint32_t ptrace_options;           // PTRACE_O_* option mask (set by PTRACE_SETOPTIONS)
    uint32_t ptrace_flags;             // Internal flags (PTRACE_FL_TRACEME, _SEIZED, _SYSCALL)
    uint64_t ptrace_eventmsg;          // Event message (read by PTRACE_GETEVENTMSG)
    uint64_t timerslack_ns;            // PR_SET/GET_TIMERSLACK: timer expiry slack (ns); default 50000

    /* I/O priority */
    int ioprio;                        // I/O priority (class + level encoded)
    int ioprio_class;                  // I/O priority class (0=none, 1=RT, 2=BE, 3=IDLE)
    int ioprio_level;                  // I/O priority level (0-7 for BE/RT, ignored for IDLE)

    /* Per-task I/O accounting (/proc/<pid>/io) */
    uint64_t io_rchar;                 // Bytes read via read()/pread()/readv() syscalls
    uint64_t io_wchar;                 // Bytes written via write()/pwrite()/writev() syscalls
    uint64_t io_syscr;                 // Number of read-family syscall invocations
    uint64_t io_syscw;                 // Number of write-family syscall invocations

    /* Virtual memory high-water marks (/proc/[pid]/status: VmPeak, VmHWM) */
    uint64_t hiwater_vm;               // Peak VmSize in kB (total virtual address space)
    uint64_t hiwater_rss;              // Peak VmRSS in kB (resident set size)

    /* Page fault counters (Linux compat: getrusage, /proc/pid/stat fields 10-13) */
    uint64_t minflt;                   // Minor (soft) page faults — COW, demand paging
    uint64_t majflt;                   // Major (hard) page faults — would require I/O
    uint64_t child_minflt;             // Accumulated minflt from reaped children
    uint64_t child_majflt;             // Accumulated majflt from reaped children

    /* POSIX capabilities */
    uint64_t cap_effective;            // Effective capability set
    uint64_t cap_permitted;            // Permitted capability set
    uint64_t cap_inheritable;          // Inheritable capability set
    uint64_t cap_bset;                 // Capability bounding set (all caps set at init)
    uint64_t cap_ambient;              // Ambient capability set (Linux 4.3+)

    /* File descriptor table (per-task, for process isolation) */
    struct fut_file **fd_table;        // Array of file pointers
    int *fd_flags;                     // Per-FD flags (FD_CLOEXEC), parallel to fd_table
    int max_fds;                       // Allocated size of fd_table
    int next_fd;                       // Next FD index to allocate

    /* Resource limits (POSIX rlimits) */
    struct rlimit64 {
        uint64_t rlim_cur;             // Soft limit
        uint64_t rlim_max;             // Hard limit (ceiling for rlim_cur)
    } rlimits[16];                     // RLIMIT_NLIMITS = 16

    /* I/O Budget Tracking (Phase 4 - Rate Limiting) */
    uint64_t io_bytes_per_sec;         // Bytes allowed per second (0 = unlimited)
    uint64_t io_ops_per_sec;           // I/O operations allowed per second (0 = unlimited)
    uint64_t io_bytes_current;         // Current second's bytes consumed (resets every 1000ms)
    uint64_t io_ops_current;           // Current second's operations consumed (resets every 1000ms)
    uint64_t io_budget_reset_time_ms;  // Last time budget counters were reset (milliseconds)
    uint64_t io_budget_limit_wait_ms;  // Time to wait before allowing next large I/O (0 = not waiting)

    /* F_DUPFD Rate Limiting (- Security Hardening) */
    uint64_t dupfd_ops_per_sec;        // F_DUPFD operations allowed per second (0 = unlimited, default 1000)
    uint64_t dupfd_ops_current;        // Current second's F_DUPFD operations consumed (resets every 1000ms)
    uint64_t dupfd_reset_time_ms;      // Last time F_DUPFD counter was reset (milliseconds)

    /* chroot(2) filesystem isolation */
    struct fut_vnode *chroot_vnode;    // chroot jail root vnode (NULL = use global VFS root)

    /* Accumulated stats from reaped children (for RUSAGE_CHILDREN / tms_cutime) */
    uint64_t child_cpu_ticks;
    uint64_t child_stime_ticks;     /* Child system-mode ticks (for cstime in /proc/pid/stat) */
    uint64_t child_context_switches;
    uint64_t child_maxrss_kb;

    /* Monotonic tick count when the task was created (for /proc/pid/stat starttime field) */
    uint64_t start_ticks;

    /* RLIMIT_CPU enforcement: last CPU-second at which SIGXCPU was sent */
    uint64_t rlimit_cpu_last_sec;

    /* Per-signal siginfo_t storage for rt_sigqueueinfo / SA_SIGINFO delivery.
     * Indexed by signal number (0 unused; valid range 1..._NSIG-1).
     * Filled by fut_signal_send_with_info(); defaulted to SI_USER by fut_signal_send(). */
    siginfo_t sig_queue_info[_NSIG];

    /* Capability handle receive queue (for fut_cap_handle_recv / fut_cap_handle_send IPC) */
#define FUT_CAP_RECV_QUEUE_SIZE 8
    struct {
        uint64_t handle;      // Handle index in global object table
        uint64_t sender_pid;  // PID of sender (0 = unset)
    } cap_recv_queue[FUT_CAP_RECV_QUEUE_SIZE];
    int cap_recv_head;         // Queue head (dequeue index)
    int cap_recv_tail;         // Queue tail (enqueue index)
    fut_spinlock_t cap_recv_lock;
    fut_waitq_t cap_recv_waitq;

    /* Namespace support (container isolation) */
    struct pid_namespace *pid_ns;      // PID namespace (NULL = init namespace)
    uint64_t ns_pid;                   // PID within the namespace (== pid for init ns)
    struct mount_namespace *mnt_ns;    // Mount namespace (NULL = init namespace)
    struct uts_namespace *uts_ns;      // UTS namespace (hostname/domainname)
    struct net_namespace *net_ns;      // Network namespace
    struct user_namespace *user_ns;    // User namespace (UID/GID mapping)

    fut_task_t *next;                  // Next task in system list
};

/* User namespace structure (UID/GID mapping for unprivileged containers) */
#define USERNS_MAP_MAX 5
struct id_map_entry {
    uint32_t ns_id;      /* First ID in namespace */
    uint32_t host_id;    /* First ID on host */
    uint32_t count;      /* Number of IDs mapped */
};
struct user_namespace {
    uint64_t id;
    int refcount;
    struct user_namespace *parent;
    int uid_map_count;
    int gid_map_count;
    struct id_map_entry uid_map[USERNS_MAP_MAX];
    struct id_map_entry gid_map[USERNS_MAP_MAX];
};

/* Network namespace structure */
struct net_namespace {
    uint64_t id;
    int refcount;
    int next_ifindex;
    fut_spinlock_t netif_lock;
    fut_spinlock_t route_lock;
    struct net_iface *ifaces;
    struct net_route *routes;
};

/* UTS namespace structure */
struct uts_namespace {
    uint64_t id;
    int refcount;
    char nodename[65];                 // hostname
    char domainname[65];               // NIS domain name
};

/* Mount namespace structure */
struct mount_namespace {
    uint64_t id;                       // Namespace ID
    int refcount;
    struct fut_mount *mount_list;      // Per-namespace mount list
};

/* PID namespace structure */
struct pid_namespace {
    uint64_t id;                       // Namespace ID (for /proc/<pid>/ns/pid)
    uint64_t next_pid;                 // Next PID to allocate in this namespace
    struct fut_task *init_task;        // PID 1 in this namespace (child subreaper)
    struct pid_namespace *parent;      // Parent namespace (NULL for init)
    int level;                         // Nesting depth (0 = init)
    int refcount;                      // Reference count
};

/* ============================================================
 *   Task API
 * ============================================================ */

/**
 * Create a new task (process).
 *
 * @return Task handle, or nullptr on failure
 */
[[nodiscard]] fut_task_t *fut_task_create(void);

/**
 * Add a thread to a task's thread list.
 *
 * @param task    Task to add thread to
 * @param thread  Thread to add
 */
void fut_task_add_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Remove a thread from a task's thread list.
 *
 * @param task    Task to remove thread from
 * @param thread  Thread to remove
 */
void fut_task_remove_thread(fut_task_t *task, fut_thread_t *thread);

/**
 * Destroy a task and all its threads.
 *
 * @param task  Task to destroy
 */
void fut_task_destroy(fut_task_t *task);

/**
 * Assign an address space to a task.
 */
void fut_task_set_mm(fut_task_t *task, struct fut_mm *mm);

/**
 * Fetch the address space associated with a task.
 */
struct fut_mm *fut_task_get_mm(const fut_task_t *task);

fut_task_t *fut_task_current(void);
void fut_task_exit_current(int status);
/* child_ticks_out: if non-NULL, receives child's total CPU ticks at reap time
 * (used by wait4 to populate struct rusage ru_utime). */
int fut_task_waitpid(int pid, int *status_out, int flags, uint64_t *child_ticks_out);
int fut_task_waitpid_ex(int pid, int *status_out, int flags, uint32_t *uid_out);
void fut_task_signal_exit(int signal);
void fut_task_do_stop(fut_task_t *task, int sig);
void fut_task_do_cont(fut_task_t *task);
void fut_task_reparent(fut_task_t *child, fut_task_t *new_parent);
fut_task_t *fut_task_find_new_parent(fut_task_t *dying_task);

/**
 * Look up a task by PID.
 *
 * @param pid Process ID to find
 * @return Task with that PID, or NULL if not found
 *
 * NOTE: Caller must hold task_list_lock or accept potential races.
 */
fut_task_t *fut_task_by_pid(uint64_t pid);

/**
 * Iterate all tasks in a process group and call callback for each.
 *
 * @param pgid Process group ID
 * @param callback Function to call for each task in the group
 * @param data User data passed to callback
 * @return Number of tasks in the group
 */
int fut_task_foreach_pgid(uint64_t pgid, void (*callback)(fut_task_t *task, void *data), void *data);

/**
 * Iterate all non-zombie tasks except init (pid 1) and one excluded PID.
 * Used by kill(pid=-1) for broadcast signal delivery.
 *
 * @param exclude_pid  PID to skip (caller's PID)
 * @param callback     Called for each matching task (NULL = count only)
 * @param data         Forwarded to callback
 * @return Number of tasks visited
 */
int fut_task_foreach_all(uint64_t exclude_pid,
                         void (*callback)(fut_task_t *task, void *data),
                         void *data);

/**
 * Count processes owned by a specific UID.
 *
 * @param uid User ID to count processes for
 * @return Number of non-zombie processes owned by the UID
 */
int fut_task_count_by_uid(uint32_t uid);

/**
 * Get total number of active tasks system-wide.
 *
 * @return Current global task count
 */
uint32_t fut_task_get_global_count(void);

/**
 * Check if a new process can be created (global limit check).
 *
 * @param is_root Whether the caller is root (UID 0)
 * @return 1 if fork is allowed, 0 if system is at limit
 */
int fut_task_can_fork(int is_root);

/**
 * Get the effective UID of a task.
 *
 * @param task Task (NULL for current task)
 * @return Effective UID
 */
uint32_t fut_task_get_uid(fut_task_t *task);

/**
 * Get the effective GID of a task.
 *
 * @param task Task (NULL for current task)
 * @return Effective GID
 */
uint32_t fut_task_get_gid(fut_task_t *task);

/**
 * Set the effective UID and GID of a task.
 *
 * @param task Task to modify (NULL for current task)
 * @param uid  New effective UID
 * @param gid  New effective GID
 */
void fut_task_set_credentials(fut_task_t *task, uint32_t uid, uint32_t gid);

/**
 * Write a process accounting record for a task on exit.
 * No-op when accounting is disabled (acct(2) not called).
 *
 * @param task    Exiting task (threads still attached)
 * @param status  Exit status code
 * @param signal  Termination signal (0 = normal exit)
 */
void acct_write_record(fut_task_t *task, int status, int signal);

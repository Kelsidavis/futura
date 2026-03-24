/* syscall_table.c - ARM64 System Call Table
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * ARM64 syscall table and dispatcher.
 * Uses Linux-compatible ABI: x8 = syscall number, x0-x7 = arguments
 */

/* Disable override-init warning - we intentionally override Linux syscall numbers with Futura numbers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <shared/fut_timeval.h>
#include <shared/fut_timespec.h>
#include <kernel/fut_vfs.h>
#include <kernel/uaccess.h>
#include <kernel/signal_frame.h>
#include <kernel/signal.h>
#include <kernel/fut_task.h>
#include <kernel/kprintf.h>
#include <shared/fut_sigevent.h>  /* For struct sigevent, timer_t */
/* struct fut_stat is provided by kernel/fut_vfs.h (included above) */
#include <sys/uio.h>              /* For struct iovec */
#include <sys/resource.h>         /* For struct rlimit, RLIMIT_* */
#include <fcntl.h>                /* For AT_FDCWD and file control flags */
#define _GNU_SOURCE               /* Enable domainname in struct utsname */
#include <sys/utsname.h>          /* For struct utsname */

/* Debug control - set to 0 to disable verbose syscall logging */
#define DEBUG_SYSCALL 0

/* Forward declarations */
extern void fut_serial_puts(const char *str);
extern void fut_serial_putc(char c);
extern uint64_t fut_rdtsc(void);
extern uint64_t fut_cycles_to_ns(uint64_t cycles);
extern uint64_t fut_cycles_per_ms(void);

/* Kernel syscall implementations */
extern long sys_fork(void);
extern long sys_execve(const char *pathname, char *const argv[], char *const envp[]);
extern long sys_waitpid(int pid, int *u_status, int flags);
extern long sys_pipe(int pipefd[2]);
extern long sys_dup(int oldfd);
extern long sys_dup2(int oldfd, int newfd);
extern long sys_kill(int pid, int sig);
extern long sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
extern long sys_munmap(void *addr, size_t len);
extern long sys_mprotect(void *addr, size_t len, int prot);
extern long sys_socket(int domain, int type, int protocol);
extern long sys_bind(int sockfd, const void *addr, uint32_t addrlen);
extern long sys_listen(int sockfd, int backlog);
extern long sys_accept(int sockfd, void *addr, uint32_t *addrlen);
extern long sys_connect(int sockfd, const void *addr, uint32_t addrlen);
extern long sys_shutdown(int sockfd, int how);
extern long sys_setsockopt(int sockfd, int level, int optname, const void *optval, uint32_t optlen);
extern long sys_getsockopt(int sockfd, int level, int optname, void *optval, uint32_t *optlen);
extern long sys_sendto(int sockfd, const void *buf, size_t len, int flags, const void *dest_addr, uint32_t addrlen);
extern long sys_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr, uint32_t *addrlen);
extern long sys_mkdir(const char *path, uint32_t mode);
extern long sys_rmdir(const char *path);
extern long sys_unlink(const char *path);
extern long sys_rename(const char *oldpath, const char *newpath);
extern long sys_stat(const char *path, void *statbuf);
extern long sys_chmod(const char *pathname, uint32_t mode);
extern long sys_access(const char *pathname, int mode);
extern long sys_link(const char *oldpath, const char *newpath);
extern long sys_symlink(const char *target, const char *linkpath);
extern long sys_readlink(const char *pathname, char *buf, size_t bufsiz);
extern long sys_epoll_create1(int flags);
extern long sys_epoll_ctl(int epfd, int op, int fd, void *event);
extern long sys_epoll_pwait(int epfd, void *events, int maxevents, int timeout, const void *sigmask);
extern long sys_ppoll(void *fds, unsigned int nfds, void *tmo_p, const void *sigmask);
extern long sys_pselect6(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout, void *sigmask);
extern int64_t sys_lseek(int fd, int64_t offset, int whence);
extern long sys_pread64(unsigned int fd, void *buf, size_t count, int64_t offset);
extern long sys_pwrite64(unsigned int fd, const void *buf, size_t count, int64_t offset);
extern long sys_open(const char *pathname, int flags, int mode);
extern long sys_openat(int dirfd, const char *pathname, int flags, int mode);
extern long sys_fstat(int fd, void *statbuf);
extern long sys_getcwd(char *buf, size_t size);
extern long sys_chdir(const char *pathname);
extern long sys_echo(const char *u_in, char *u_out, size_t n);

/* struct iovec provided by sys/uio.h */

extern long sys_readv(int fd, const struct iovec *iov, int iovcnt);
extern long sys_writev(int fd, const struct iovec *iov, int iovcnt);
extern long sys_preadv(int fd, const struct iovec *iov, int iovcnt, int64_t offset);
extern long sys_pwritev(int fd, const struct iovec *iov, int iovcnt, int64_t offset);

/* Forward declarations for signal types (fully defined in signal.h) */
struct sigaltstack;

/* Signal syscalls (definitions in signal.h) */
extern long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
extern long sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
extern long sys_sigpending(sigset_t *set);
extern long sys_sigsuspend(const sigset_t *mask);
extern long sys_sigaltstack(const struct sigaltstack *ss, struct sigaltstack *old_ss);

/* struct timespec is provided by shared/fut_timespec.h */
/* struct sigevent, timer_t provided by user/signal.h */
/* struct itimerspec is provided by shared/fut_timespec.h */

extern long sys_timer_create(int clockid, struct sigevent *sevp, timer_t *timerid);
extern long sys_timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
extern long sys_timer_gettime(timer_t timerid, struct itimerspec *curr_value);
extern long sys_timer_getoverrun(timer_t timerid);
extern long sys_timer_delete(timer_t timerid);
extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);

/* Futex structures provided by linux/futex.h */
#include <sys/futex.h>

extern long sys_futex(uint32_t *uaddr, int op, uint32_t val, const void *timeout, uint32_t *uaddr2, uint32_t val3);
extern long sys_set_robust_list(struct robust_list_head *head, size_t len);
extern long sys_get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);

/* Event notification syscalls (eventfd, signalfd, timerfd) */
extern long sys_eventfd2(unsigned int initval, int flags);
extern long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags);
extern long sys_timerfd_create(int clockid, int flags);
extern long sys_timerfd_settime(int ufd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
extern long sys_timerfd_gettime(int ufd, struct itimerspec *curr_value);

/* Memory management syscalls (madvise, mlock, msync) */
extern long sys_madvise(void *addr, size_t length, int advice);
extern long sys_mlock(const void *addr, size_t len);
extern long sys_munlock(const void *addr, size_t len);
extern long sys_mlockall(int flags);
extern long sys_munlockall(void);
extern long sys_mincore(void *addr, size_t len, unsigned char *vec);
extern long sys_msync(void *addr, size_t len, int flags);

/* Process credential syscalls (UID/GID management) */
extern long sys_getuid(void);
extern long sys_geteuid(void);
extern long sys_getgid(void);
extern long sys_getegid(void);
extern long sys_setuid(uint32_t uid);
extern long sys_setgid(uint32_t gid);
extern long sys_seteuid(uint32_t euid);
extern long sys_setegid(uint32_t egid);
extern long sys_setreuid(uint32_t ruid, uint32_t euid);
extern long sys_setregid(uint32_t rgid, uint32_t egid);
extern long sys_setresuid(uint32_t ruid, uint32_t euid, uint32_t suid);
extern long sys_getresuid(uint32_t *ruid, uint32_t *euid, uint32_t *suid);
extern long sys_setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid);
extern long sys_getresgid(uint32_t *rgid, uint32_t *egid, uint32_t *sgid);

/* Resource limit structures are provided by sys/resource.h */

/* Resource limit syscalls */
extern long sys_getrlimit(int resource, struct rlimit *rlim);
extern long sys_setrlimit(int resource, const struct rlimit *rlim);
extern long sys_prlimit64(int pid, int resource, const struct rlimit64 *new_limit, struct rlimit64 *old_limit);

/* Process group and session syscalls */
extern long sys_getpgid(uint64_t pid);
extern long sys_setpgid(uint64_t pid, uint64_t pgid);
extern long sys_getpgrp(void);
extern long sys_getsid(uint64_t pid);
extern long sys_setsid(void);

/* Scheduling parameter structure */
struct sched_param {
    int sched_priority;
};

/* Scheduling and priority syscalls */
extern long sys_sched_setparam(int pid, const struct sched_param *param);
extern long sys_sched_getparam(int pid, struct sched_param *param);
extern long sys_sched_setscheduler(int pid, int policy, const struct sched_param *param);
extern long sys_sched_getscheduler(int pid);
extern long sys_sched_yield(void);
extern long sys_sched_get_priority_max(int policy);
extern long sys_sched_get_priority_min(int policy);
extern long sys_sched_rr_get_interval(int pid, void *interval);
extern long sys_getpriority(int which, int who);
extern long sys_setpriority(int which, int who, int prio);

/* Interval timer structure for getitimer/setitimer
 * May already be provided by sys/time.h (pulled in via sys/resource.h) */
#ifndef _STRUCT_ITIMERVAL
#define _STRUCT_ITIMERVAL
struct itimerval {
    fut_timeval_t it_interval;
    fut_timeval_t it_value;
};
#endif

/* Time adjustment structure for adjtimex */
#ifndef _STRUCT_TIMEX
#define _STRUCT_TIMEX
struct timex {
    unsigned int modes;
    long offset;
    long freq;
    long maxerror;
    long esterror;
    int status;
    long constant;
    long precision;
    long tolerance;
    fut_timeval_t time;
    long tick;
};
#endif

/* Time and clock syscalls */
extern long sys_gettimeofday(fut_timeval_t *tv, void *tz);
extern long sys_settimeofday(const fut_timeval_t *tv, const void *tz);
extern long sys_times(void *buf);
extern long sys_clock_settime(int clock_id, const fut_timespec_t *tp);
extern long sys_clock_getres(int clock_id, fut_timespec_t *res);
extern long sys_clock_nanosleep(int clock_id, int flags, const fut_timespec_t *req, fut_timespec_t *rem);
extern long sys_getitimer(int which, struct itimerval *value);
extern long sys_setitimer(int which, const struct itimerval *value, struct itimerval *ovalue);
extern long sys_adjtimex(struct timex *txc);

/* File and I/O control syscalls */
extern long sys_fcntl(int fd, int cmd, uint64_t arg);
extern long sys_ioctl(int fd, unsigned long request, void *argp);
extern long sys_chroot(const char *path);
extern long sys_sendfile(int out_fd, int in_fd, uint64_t *offset, size_t count);
extern long sys_sync(void);
extern long sys_fsync(int fd);
extern long sys_fdatasync(int fd);

/* Filesystem and resource management syscalls */
extern long sys_statfs(const char *path, struct fut_linux_statfs *buf);
extern long sys_fstatfs(int fd, struct fut_linux_statfs *buf);
extern long sys_truncate(const char *path, int64_t length);
extern long sys_ftruncate(int fd, int64_t length);
extern long sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len);
extern long sys_getrusage(int who, void *usage);
extern long sys_umask(uint32_t mask);
extern long sys_sysinfo(struct fut_linux_sysinfo *info);

/* File metadata and directory operations */
extern long sys_fchownat(int dirfd, const char *pathname, uint32_t uid, uint32_t gid, int flags);
extern long sys_fchown(int fd, uint32_t uid, uint32_t gid);
extern long sys_getdents64(unsigned int fd, void *dirent, unsigned int count);
extern long sys_utimensat(int dirfd, const char *pathname, const fut_timespec_t *times, int flags);

/* Extended attributes (xattr) */
extern long sys_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
extern long sys_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
extern long sys_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);
extern long sys_getxattr(const char *path, const char *name, void *value, size_t size);
extern long sys_lgetxattr(const char *path, const char *name, void *value, size_t size);
extern long sys_fgetxattr(int fd, const char *name, void *value, size_t size);
extern long sys_listxattr(const char *path, char *list, size_t size);
extern long sys_llistxattr(const char *path, char *list, size_t size);
extern long sys_flistxattr(int fd, char *list, size_t size);
extern long sys_removexattr(const char *path, const char *name);
extern long sys_lremovexattr(const char *path, const char *name);
extern long sys_fremovexattr(int fd, const char *name);

/* File monitoring (inotify) */
extern long sys_inotify_init1(int flags);
extern long sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
extern long sys_inotify_rm_watch(int fd, int wd);

/* Zero-copy I/O (splice family) */
extern long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out, size_t len, unsigned int flags);
extern long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags);
extern long sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags);
extern long sys_sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags);

/* I/O priority and capabilities */
extern long sys_ioprio_set(int which, int who, int ioprio);
extern long sys_ioprio_get(int which, int who);
extern long sys_capget(void *hdrp, void *datap);
extern long sys_capset(void *hdrp, const void *datap);
extern long sys_personality(unsigned long persona);
extern long sys_prctl(int option, unsigned long a2, unsigned long a3,
                      unsigned long a4, unsigned long a5);
extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
extern long sys_fadvise64(int fd, int64_t offset, int64_t len, int advice);
extern long sys_syslog(int type, char *buf, int len);
extern long sys_membarrier(int cmd, unsigned int flags, int cpu_id);
extern long sys_copy_file_range(int fd_in, int64_t *off_in,
                                 int fd_out, int64_t *off_out,
                                 size_t len, unsigned int flags);
extern long sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig);
extern long sys_sched_setaffinity(int pid, unsigned int len, const void *user_mask);
extern long sys_sched_getaffinity(int pid, unsigned int len, void *user_mask);
extern long sys_statx(int dirfd, const char *pathname, int flags,
                      unsigned int mask, void *statxbuf);
extern long sys_tgkill(int tgid, int tid, int sig);
extern long sys_tkill(int tid, int sig);
extern long sys_getcpu(unsigned int *cpup, unsigned int *nodep, void *unused);
extern long sys_readahead(int fd, int64_t offset, size_t count);
extern long sys_getgroups(int size, uint32_t *list);
extern long sys_setgroups(int size, const uint32_t *list);
extern long sys_socketpair(int domain, int type, int protocol, int *sv);
extern long sys_unshare(unsigned long flags);

/* Process accounting and thread management */
extern long sys_acct(const char *filename);
extern long sys_waitid(int idtype, int id, void *infop, int options, void *rusage);
extern long sys_set_tid_address(int *tidptr);

/* File locking and directory operations */
extern long sys_flock(int fd, int operation);
extern long sys_mknodat(int dirfd, const char *pathname, uint32_t mode, uint32_t dev);
extern long sys_fchdir(int fd);
extern long sys_fchmod(int fd, uint32_t mode);

/* Mount operations and root management */
extern long sys_umount2(const char *target, int flags);
extern long sys_mount(const char *source, const char *target, const char *filesystemtype,
                      unsigned long mountflags, const void *data);
extern long sys_pivot_root(const char *new_root, const char *put_old);
extern long sys_chroot(const char *path);

/* Terminal and quota operations */
extern long sys_vhangup(void);

/* FIPC (Futura IPC) syscalls */
extern long sys_fipc_create(uint32_t flags, size_t queue_size);
extern long sys_fipc_send(uint64_t channel_id, uint32_t type, const void *data, size_t size);
extern long sys_fipc_recv(uint64_t channel_id, void *buf, size_t buf_size);
extern long sys_fipc_close(uint64_t channel_id);
extern long sys_fipc_poll(uint64_t channel_id, uint32_t event_mask);
extern long sys_fipc_connect(uint64_t channel_id);
extern long sys_quotactl(unsigned int cmd, const char *special, int id, void *addr);

/* Syscall return values */
#define SYSCALL_SUCCESS     0
#define SYSCALL_ERROR      -1
/* errno values provided by errno.h */

/* AT_FDCWD provided by fcntl.h */

/* ============================================================
 *   System Call Implementations
 * ============================================================ */

/* sys_write wrapper - use kernel implementation from kernel/sys_write.c
 * The kernel implementation properly uses fut_copy_from_user to safely
 * access userspace memory, which is required on ARM64.
 */
extern ssize_t sys_write(int fd, const void *buf, size_t count);

static int64_t sys_write_wrapper(uint64_t fd, uint64_t buf, uint64_t count,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    /* Validate user buffer pointer — reject kernel addresses and sentinel values */
    if (buf == 0 || buf >= 0xFFFFFF8000000000ULL) {
        return -14;  /* -EFAULT */
    }
    return (int64_t)sys_write((int)fd, (const void *)buf, (size_t)count);
}

/* Forward declaration of kernel exit function */
extern void fut_task_exit_current(int status) __attribute__((noreturn));

/* sys_exit - terminate current process
 * x0 = exit_code
 */
static int64_t sys_exit(uint64_t exit_code, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Call kernel exit function - marks task as zombie and reschedules */
    fut_task_exit_current((int)exit_code);

    /* Should never reach here */
    while (1) {
        __asm__ volatile("wfi");
    }

    return 0;  /* Never reached */
}

/* Use real kernel implementations for getpid/getppid/exit_group */
extern long sys_getpid(void);
extern long sys_getppid(void);
extern long sys_exit_group(int status);

/* sys_exit_group wrapper - terminate all threads */
static int64_t sys_exit_group_wrapper(uint64_t exit_code, uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_exit_group((int)exit_code);
}

/* sys_getpid - get process ID wrapper
 * Returns: current process ID
 */
static int64_t sys_getpid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getpid();
}

/* sys_getppid - get parent process ID wrapper
 * Returns: parent process ID
 */
static int64_t sys_getppid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getppid();
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

/* sys_read_wrapper - read from file descriptor
 * x0 = fd, x1 = buf, x2 = count
 * Wraps kernel sys_read() for ARM64 syscall ABI
 */
extern ssize_t sys_read(int fd, void *buf, size_t count);
static int64_t sys_read_wrapper(uint64_t fd, uint64_t buf, uint64_t count,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    if (buf == 0 || buf >= 0xFFFFFF8000000000ULL) {
        return -14;  /* -EFAULT */
    }
    return (int64_t)sys_read((int)fd, (void *)buf, (size_t)count);
}

/* sys_echo - echo syscall with case flip wrapper
 * x0 = u_in, x1 = u_out, x2 = n
 * Returns: number of bytes processed on success, negative errno on failure
 */
static int64_t sys_echo_wrapper(uint64_t u_in, uint64_t u_out, uint64_t n,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_echo((const char *)u_in, (char *)u_out, (size_t)n);
}

/* sys_clock_gettime - get time
 * x0 = clockid, x1 = timespec*
 */
static int64_t sys_clock_gettime(uint64_t clockid, uint64_t ts_ptr,
                                  uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (ts_ptr == 0 || ts_ptr >= 0xFFFFFF8000000000ULL) {
        return -EFAULT;
    }

    /* Get current cycle count */
    uint64_t cycles = fut_rdtsc();
    uint64_t ns = fut_cycles_to_ns(cycles);

    /* Build result on kernel stack, then copy to userspace safely */
    struct timespec kts;
    kts.tv_sec = ns / 1000000000ULL;
    kts.tv_nsec = ns % 1000000000ULL;

    if (fut_copy_to_user((void *)ts_ptr, &kts, sizeof(kts)) != 0) {
        return -EFAULT;
    }

    (void)clockid;  /* Ignore clockid for now */
    return 0;
}

/* sys_nanosleep - sleep for specified time
 * x0 = req (timespec*), x1 = rem (timespec*)
 * Delegates to the main kernel implementation in kernel/sys_nanosleep.c
 */
static int64_t sys_nanosleep_wrapper(uint64_t req_ptr, uint64_t rem_ptr,
                                     uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* Call the main kernel implementation */
    return sys_nanosleep((const fut_timespec_t *)req_ptr, (fut_timespec_t *)rem_ptr);
}

/* utsname structure is provided by sys/utsname.h */

/* sys_uname - get system information
 * x0 = utsname*
 */
static int64_t sys_uname(uint64_t buf_ptr, uint64_t arg1, uint64_t arg2,
                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    if (buf_ptr == 0) {
        return -EINVAL;
    }

    /* Build utsname on kernel stack, then copy to userspace safely */
    struct utsname kbuf;

    /* Clear the structure */
    for (int i = 0; i < (int)sizeof(struct utsname); i++) {
        ((char *)&kbuf)[i] = 0;
    }

    /* Fill in system information */
    const char *sysname = "Futura";
    const char *nodename = "futura";
    const char *release = "0.3.1";
    const char *version = "Futura OS ARM64 SMP";
    const char *machine = "aarch64";
    const char *domainname = "(none)";

    /* Copy strings with bounds checking */
    int i;
    for (i = 0; sysname[i] && i < 64; i++) kbuf.sysname[i] = sysname[i];
    for (i = 0; nodename[i] && i < 64; i++) kbuf.nodename[i] = nodename[i];
    for (i = 0; release[i] && i < 64; i++) kbuf.release[i] = release[i];
    for (i = 0; version[i] && i < 64; i++) kbuf.version[i] = version[i];
    for (i = 0; machine[i] && i < 64; i++) kbuf.machine[i] = machine[i];
    for (i = 0; domainname[i] && i < 64; i++) kbuf.domainname[i] = domainname[i];

    if (fut_copy_to_user((void *)buf_ptr, &kbuf, sizeof(kbuf)) != 0) {
        return -EFAULT;
    }

    return 0;
}

/* sys_getcwd_wrapper - get current working directory (ARM64 syscall ABI)
 * x0 = buf, x1 = size
 * Wraps kernel sys_getcwd() for ARM64 calling convention
 */
static int64_t sys_getcwd_wrapper(uint64_t buf_ptr, uint64_t size, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* ARM64: Stabilize parameters */
    char * const buf_stable = (char *)(uintptr_t)buf_ptr;
    const size_t size_stable = (size_t)size;
    return (int64_t)sys_getcwd(buf_stable, size_stable);
}

/* sys_chdir_wrapper - change current working directory (ARM64 syscall ABI)
 * x0 = path
 * Wraps kernel sys_chdir() for ARM64 calling convention
 *
 * ARM64 FIX: Stabilize register-passed parameters immediately to prevent
 * corruption when blocking operations occur. Register parameters may be
 * clobbered upon scheduler resumption if not copied to stack-based locals.
 */
static int64_t sys_chdir_wrapper(uint64_t path_ptr, uint64_t arg1, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* Stabilize pointer parameter to prevent register aliasing corruption */
    const char * const path_stable = (const char *)(uintptr_t)path_ptr;
    return (int64_t)sys_chdir(path_stable);
}

/* struct fut_stat and S_IF* constants provided by shared/fut_stat.h */

/* sys_openat_wrapper - open file (ARM64 syscall ABI)
 * x0 = dirfd, x1 = pathname, x2 = flags, x3 = mode
 * Wraps kernel sys_openat() for ARM64 calling convention
 */
static int64_t sys_openat_wrapper(uint64_t dirfd, uint64_t path_ptr, uint64_t flags,
                                  uint64_t mode, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    /* ARM64: Stabilize parameters */
    const int dirfd_stable = (int)dirfd;
    const char * const path_stable = (const char *)(uintptr_t)path_ptr;
    const int flags_stable = (int)flags;
    const int mode_stable = (int)mode;
    return (int64_t)sys_openat(dirfd_stable, path_stable, flags_stable, mode_stable);
}

/* sys_close_wrapper - close file descriptor
 * x0 = fd
 * Wraps kernel sys_close() for ARM64 syscall ABI
 */
extern long sys_close(int fd);
static int64_t sys_close_wrapper(uint64_t fd, uint64_t arg1, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_close((int)fd);
}

/* sys_fstat_wrapper - get file status (ARM64 syscall ABI)
 * x0 = fd, x1 = statbuf
 * Wraps kernel sys_fstat() for ARM64 calling convention
 */
static int64_t sys_fstat_wrapper(uint64_t fd, uint64_t buf_ptr, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_fstat((int)fd, (void *)buf_ptr);
}

/* sys_fork_wrapper - fork current process
 * ARM64 note: Uses clone syscall number but implements fork semantics
 */
static int64_t sys_fork_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fork();
}

/* sys_execve_wrapper - execute program
 * x0 = pathname, x1 = argv, x2 = envp
 */
static int64_t sys_execve_wrapper(uint64_t pathname, uint64_t argv, uint64_t envp,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    /* ARM64: Stabilize parameters - critical for exec */
    const char * const pathname_stable = (const char *)(uintptr_t)pathname;
    char * const * const argv_stable = (char * const *)(uintptr_t)argv;
    char * const * const envp_stable = (char * const *)(uintptr_t)envp;
    return sys_execve(pathname_stable, argv_stable, envp_stable);
}

/* sys_waitpid_wrapper - wait for process to change state
 * x0 = pid, x1 = status pointer, x2 = options
 */
static int64_t sys_waitpid_wrapper(uint64_t pid, uint64_t wstatus, uint64_t options,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_waitpid((int)pid, (int *)wstatus, (int)options);
}

/* sys_pipe_wrapper - create pipe
 * x0 = pipefd array pointer
 */
static int64_t sys_pipe_wrapper(uint64_t pipefd, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pipe((int *)pipefd);
}

/* sys_pipe2_wrapper - create pipe with flags
 * x0 = pipefd array pointer, x1 = flags (O_CLOEXEC, O_NONBLOCK, O_DIRECT)
 */
extern long sys_pipe2(int pipefd[2], int flags);
static int64_t sys_pipe2_wrapper(uint64_t pipefd, uint64_t flags, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pipe2((int *)pipefd, (int)flags);
}

/* sys_dup_wrapper - duplicate file descriptor
 * x0 = oldfd
 */
static int64_t sys_dup_wrapper(uint64_t oldfd, uint64_t arg1, uint64_t arg2,
                               uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_dup((int)oldfd);
}

/* sys_dup2_wrapper - duplicate file descriptor to specific fd
 * x0 = oldfd, x1 = newfd
 */
static int64_t sys_dup2_wrapper(uint64_t oldfd, uint64_t newfd, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_dup2((int)oldfd, (int)newfd);
}

/* sys_dup3_wrapper - duplicate fd with flags (O_CLOEXEC)
 * x0 = oldfd, x1 = newfd, x2 = flags
 * NOTE: dup3 returns EINVAL when oldfd==newfd (unlike dup2 which is no-op)
 */
extern long sys_dup3(int oldfd, int newfd, int flags);
static int64_t sys_dup3_wrapper(uint64_t oldfd, uint64_t newfd, uint64_t flags,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_dup3((int)oldfd, (int)newfd, (int)flags);
}

/* sys_kill_wrapper - send signal to process
 * x0 = pid, x1 = sig
 */
static int64_t sys_kill_wrapper(uint64_t pid, uint64_t sig, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_kill((int)pid, (int)sig);
}

/* sys_munmap_wrapper - unmap memory region
 * x0 = addr, x1 = len
 */
static int64_t sys_munmap_wrapper(uint64_t addr, uint64_t len, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_munmap((void *)addr, (size_t)len);
}

/* sys_mmap_wrapper - map files or devices into memory
 * x0 = addr, x1 = len, x2 = prot, x3 = flags, x4 = fd, x5 = offset
 */
static int64_t sys_mmap_wrapper(uint64_t addr, uint64_t len, uint64_t prot,
                                uint64_t flags, uint64_t fd, uint64_t offset) {
    return sys_mmap((void *)addr, (size_t)len, (int)prot, (int)flags,
                    (int)fd, (long)offset);
}

/* sys_mprotect_wrapper - change memory protection
 * x0 = addr, x1 = len, x2 = prot
 */
static int64_t sys_mprotect_wrapper(uint64_t addr, uint64_t len, uint64_t prot,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_mprotect((void *)addr, (size_t)len, (int)prot);
}

/* sys_socket_wrapper - create socket
 * x0 = domain, x1 = type, x2 = protocol
 */
static int64_t sys_socket_wrapper(uint64_t domain, uint64_t type, uint64_t protocol,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_socket((int)domain, (int)type, (int)protocol);
}

/* sys_bind_wrapper - bind socket to address
 * x0 = sockfd, x1 = addr, x2 = addrlen
 */
static int64_t sys_bind_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_bind((int)sockfd, (const void *)addr, (uint32_t)addrlen);
}

/* sys_listen_wrapper - listen for connections
 * x0 = sockfd, x1 = backlog
 */
static int64_t sys_listen_wrapper(uint64_t sockfd, uint64_t backlog, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_listen((int)sockfd, (int)backlog);
}

/* sys_accept_wrapper - accept connection
 * x0 = sockfd, x1 = addr, x2 = addrlen
 */
static int64_t sys_accept_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_accept((int)sockfd, (void *)addr, (uint32_t *)addrlen);
}

/* sys_accept4_wrapper - accept connection with flags (SOCK_CLOEXEC, SOCK_NONBLOCK) */
extern long sys_accept4(int sockfd, void *addr, uint32_t *addrlen, int flags);
static int64_t sys_accept4_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                    uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_accept4((int)sockfd, (void *)addr, (uint32_t *)addrlen, (int)flags);
}

/* sys_connect_wrapper - connect socket
 * x0 = sockfd, x1 = addr, x2 = addrlen
 */
static int64_t sys_connect_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_connect((int)sockfd, (const void *)addr, (uint32_t)addrlen);
}

/* sys_shutdown_wrapper - shutdown socket
 * x0 = sockfd, x1 = how
 */
static int64_t sys_shutdown_wrapper(uint64_t sockfd, uint64_t how, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_shutdown((int)sockfd, (int)how);
}

/* sys_sendto_wrapper - send message on socket
 * x0 = sockfd, x1 = buf, x2 = len, x3 = flags, x4 = dest_addr, x5 = addrlen
 */
static int64_t sys_sendto_wrapper(uint64_t sockfd, uint64_t buf, uint64_t len,
                                   uint64_t flags, uint64_t dest_addr, uint64_t addrlen) {
    return sys_sendto((int)sockfd, (const void *)buf, (size_t)len, (int)flags,
                      (const void *)dest_addr, (uint32_t)addrlen);
}

/* sys_recvfrom_wrapper - receive message from socket
 * x0 = sockfd, x1 = buf, x2 = len, x3 = flags, x4 = src_addr, x5 = addrlen
 */
static int64_t sys_recvfrom_wrapper(uint64_t sockfd, uint64_t buf, uint64_t len,
                                     uint64_t flags, uint64_t src_addr, uint64_t addrlen) {
    return sys_recvfrom((int)sockfd, (void *)buf, (size_t)len, (int)flags,
                        (void *)src_addr, (uint32_t *)addrlen);
}

/* sys_setsockopt_wrapper - set socket options
 * x0 = sockfd, x1 = level, x2 = optname, x3 = optval, x4 = optlen
 */
static int64_t sys_setsockopt_wrapper(uint64_t sockfd, uint64_t level, uint64_t optname,
                                       uint64_t optval, uint64_t optlen, uint64_t arg5) {
    (void)arg5;
    return sys_setsockopt((int)sockfd, (int)level, (int)optname,
                          (const void *)optval, (uint32_t)optlen);
}

/* sys_getsockopt_wrapper - get socket options
 * x0 = sockfd, x1 = level, x2 = optname, x3 = optval, x4 = optlen
 */
static int64_t sys_getsockopt_wrapper(uint64_t sockfd, uint64_t level, uint64_t optname,
                                       uint64_t optval, uint64_t optlen, uint64_t arg5) {
    (void)arg5;
    return sys_getsockopt((int)sockfd, (int)level, (int)optname,
                          (void *)optval, (uint32_t *)optlen);
}

/* sys_mkdir_wrapper - create directory (Futura 2-arg version)
 * x0 = pathname, x1 = mode
 * Wraps kernel sys_mkdir() for Futura syscall ABI
 */
static int64_t sys_mkdir_wrapper(uint64_t pathname, uint64_t mode, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* ARM64: Stabilize parameters */
    const char * const pathname_stable = (const char *)(uintptr_t)pathname;
    const uint32_t mode_stable = (uint32_t)mode;
    return sys_mkdir(pathname_stable, mode_stable);
}

/* sys_rmdir_wrapper - remove directory (Futura 1-arg version)
 * x0 = pathname
 * Wraps kernel sys_rmdir() for Futura syscall ABI
 */
static int64_t sys_rmdir_wrapper(uint64_t pathname, uint64_t arg1, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* ARM64: Stabilize pathname parameter */
    const char * const pathname_stable = (const char *)(uintptr_t)pathname;
    return sys_rmdir(pathname_stable);
}

/* sys_unlink_wrapper - delete file (Futura 1-arg version)
 * x0 = pathname
 * Wraps kernel sys_unlink() for Futura syscall ABI
 */
static int64_t sys_unlink_wrapper(uint64_t pathname, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* ARM64: Stabilize pathname parameter */
    const char * const pathname_stable = (const char *)(uintptr_t)pathname;
    return sys_unlink(pathname_stable);
}

/* sys_mkdirat_wrapper - create directory (POSIX 3-arg version)
 * x0 = dirfd, x1 = pathname, x2 = mode
 * For ARM64, only AT_FDCWD is supported (acts like mkdir)
 */
extern long sys_mkdirat(int dirfd, const char *pathname, uint32_t mode);
static int64_t sys_mkdirat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_mkdirat((int)dirfd, (const char *)pathname, (uint32_t)mode);
}

extern long sys_unlinkat(int dirfd, const char *pathname, int flags);
static int64_t sys_unlinkat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_unlinkat((int)dirfd, (const char *)pathname, (int)flags);
}

extern long sys_renameat(int olddirfd, const char *oldpath,
                         int newdirfd, const char *newpath);
static int64_t sys_renameat_wrapper(uint64_t olddirfd, uint64_t oldpath,
                                     uint64_t newdirfd, uint64_t newpath,
                                     uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_renameat((int)olddirfd, (const char *)oldpath,
                        (int)newdirfd, (const char *)newpath);
}

extern long sys_fstatat(int dirfd, const char *pathname, void *statbuf, int flags);
static int64_t sys_fstatat_wrapper(uint64_t dirfd, uint64_t pathname,
                                    uint64_t statbuf, uint64_t flags,
                                    uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fstatat((int)dirfd, (const char *)pathname, (void *)statbuf, (int)flags);
}

extern long sys_fchmodat(int dirfd, const char *pathname, uint32_t mode, int flags);
static int64_t sys_fchmodat_wrapper(uint64_t dirfd, uint64_t pathname,
                                     uint64_t mode, uint64_t flags,
                                     uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fchmodat((int)dirfd, (const char *)pathname, (uint32_t)mode, (int)flags);
}

/* sys_faccessat_wrapper - check file access permissions
 * x0 = dirfd, x1 = pathname, x2 = mode, x3 = flags
 */
extern long sys_faccessat(int dirfd, const char *pathname, int mode, int flags);
static int64_t sys_faccessat_wrapper(uint64_t dirfd, uint64_t pathname,
                                      uint64_t mode, uint64_t flags,
                                      uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_faccessat((int)dirfd, (const char *)pathname, (int)mode, (int)flags);
}

extern long sys_linkat(int olddirfd, const char *oldpath,
                       int newdirfd, const char *newpath, int flags);
static int64_t sys_linkat_wrapper(uint64_t olddirfd, uint64_t oldpath,
                                   uint64_t newdirfd, uint64_t newpath,
                                   uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_linkat((int)olddirfd, (const char *)oldpath,
                      (int)newdirfd, (const char *)newpath, (int)flags);
}

extern long sys_symlinkat(const char *target, int newdirfd, const char *linkpath);
static int64_t sys_symlinkat_wrapper(uint64_t target, uint64_t newdirfd,
                                      uint64_t linkpath, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_symlinkat((const char *)target, (int)newdirfd, (const char *)linkpath);
}

extern long sys_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
static int64_t sys_readlinkat_wrapper(uint64_t dirfd, uint64_t pathname,
                                       uint64_t buf, uint64_t bufsiz,
                                       uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_readlinkat((int)dirfd, (const char *)pathname, (char *)buf, (size_t)bufsiz);
}

/* sys_epoll_create1_wrapper - create epoll file descriptor
 * x0 = flags
 */
static int64_t sys_epoll_create1_wrapper(uint64_t flags, uint64_t arg1, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_epoll_create1((int)flags);
}

/* sys_epoll_ctl_wrapper - control epoll file descriptor
 * x0 = epfd, x1 = op, x2 = fd, x3 = event
 */
static int64_t sys_epoll_ctl_wrapper(uint64_t epfd, uint64_t op, uint64_t fd,
                                      uint64_t event, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_epoll_ctl((int)epfd, (int)op, (int)fd, (void *)event);
}

/* sys_epoll_pwait_wrapper - wait for epoll events (with signal mask)
 * x0 = epfd, x1 = events, x2 = maxevents, x3 = timeout, x4 = sigmask
 * Note: ARM64 uses epoll_pwait instead of epoll_wait
 */
static int64_t sys_epoll_pwait_wrapper(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                        uint64_t timeout, uint64_t sigmask, uint64_t arg5) {
    (void)arg5;
    return sys_epoll_pwait((int)epfd, (void *)events, (int)maxevents,
                           (int)timeout, (const void *)sigmask);
}

/* sys_ppoll_wrapper - wait for events on multiple file descriptors
 * x0 = fds, x1 = nfds, x2 = tmo_p, x3 = sigmask
 * Note: ARM64 uses ppoll instead of poll
 */
static int64_t sys_ppoll_wrapper(uint64_t fds, uint64_t nfds, uint64_t tmo_p,
                                  uint64_t sigmask, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_ppoll((void *)fds, (unsigned int)nfds, (void *)tmo_p, (const void *)sigmask);
}

/* sys_pselect6_wrapper - synchronous I/O multiplexing
 * x0 = nfds, x1 = readfds, x2 = writefds, x3 = exceptfds, x4 = timeout, x5 = sigmask
 * Note: ARM64 uses pselect6 instead of select
 */
static int64_t sys_pselect6_wrapper(uint64_t nfds, uint64_t readfds, uint64_t writefds,
                                     uint64_t exceptfds, uint64_t timeout, uint64_t sigmask) {
    return sys_pselect6((int)nfds, (void *)readfds, (void *)writefds,
                        (void *)exceptfds, (void *)timeout, (void *)sigmask);
}

/* sys_open_wrapper - open file
 * x0 = pathname, x1 = flags, x2 = mode
 */
static int64_t sys_open_wrapper(uint64_t pathname, uint64_t flags, uint64_t mode,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_open((const char *)pathname, (int)flags, (int)mode);
}

/* sys_stat_wrapper - get file status
 * x0 = path, x1 = statbuf
 */
static int64_t sys_stat_wrapper(uint64_t path, uint64_t statbuf, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_stat((const char *)path, (void *)statbuf);
}

/* sys_lseek_wrapper - change file position
 * x0 = fd, x1 = offset, x2 = whence
 */
static int64_t sys_lseek_wrapper(uint64_t fd, uint64_t offset, uint64_t whence,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_lseek((int)fd, (int64_t)offset, (int)whence);
}

/* sys_pread64_wrapper - read from file at given offset
 * x0 = fd, x1 = buf, x2 = count, x3 = offset
 */
static int64_t sys_pread64_wrapper(uint64_t fd, uint64_t buf, uint64_t count,
                                    uint64_t offset, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_pread64((unsigned int)fd, (void *)buf, (size_t)count, (int64_t)offset);
}

/* sys_pwrite64_wrapper - write to file at given offset
 * x0 = fd, x1 = buf, x2 = count, x3 = offset
 */
static int64_t sys_pwrite64_wrapper(uint64_t fd, uint64_t buf, uint64_t count,
                                     uint64_t offset, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_pwrite64((unsigned int)fd, (const void *)buf, (size_t)count, (int64_t)offset);
}

/* sys_readv_wrapper - read into multiple buffers (vectored I/O)
 * x0 = fd, x1 = iov, x2 = iovcnt
 */
static int64_t sys_readv_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_readv((int)fd, (const struct iovec *)iov, (int)iovcnt);
}

/* sys_writev_wrapper - write from multiple buffers (vectored I/O)
 * x0 = fd, x1 = iov, x2 = iovcnt
 */
static int64_t sys_writev_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_writev((int)fd, (const struct iovec *)iov, (int)iovcnt);
}

/* sys_preadv_wrapper - read into multiple buffers at given offset
 * x0 = fd, x1 = iov, x2 = iovcnt, x3 = offset
 */
static int64_t sys_preadv_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                   uint64_t offset, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_preadv((int)fd, (const struct iovec *)iov, (int)iovcnt, (int64_t)offset);
}

/* sys_pwritev_wrapper - write from multiple buffers at given offset
 * x0 = fd, x1 = iov, x2 = iovcnt, x3 = offset
 */
static int64_t sys_pwritev_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                    uint64_t offset, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_pwritev((int)fd, (const struct iovec *)iov, (int)iovcnt, (int64_t)offset);
}

/* sys_rt_sigaction_wrapper - examine and change signal action
 * x0 = signum, x1 = act, x2 = oldact, x3 = sigsetsize
 * Note: ARM64 uses rt_sigaction instead of sigaction (adds sigsetsize parameter)
 */
static int64_t sys_rt_sigaction_wrapper(uint64_t signum, uint64_t act, uint64_t oldact,
                                         uint64_t sigsetsize, uint64_t arg4, uint64_t arg5) {
    (void)sigsetsize; (void)arg4; (void)arg5;
    /* For now, ignore sigsetsize and delegate to standard sigaction */
    return sys_sigaction((int)signum, (const struct sigaction *)act, (struct sigaction *)oldact);
}

/* sys_rt_sigprocmask_wrapper - examine and change blocked signals
 * x0 = how, x1 = set, x2 = oldset, x3 = sigsetsize
 * Note: ARM64 uses rt_sigprocmask instead of sigprocmask (adds sigsetsize parameter)
 */
static int64_t sys_rt_sigprocmask_wrapper(uint64_t how, uint64_t set, uint64_t oldset,
                                           uint64_t sigsetsize, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    /* Linux requires sigsetsize == sizeof(sigset_t) */
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    return sys_sigprocmask((int)how, (const sigset_t *)set, (sigset_t *)oldset);
}

/* sys_rt_sigpending_wrapper - get set of pending signals
 * x0 = set, x1 = sigsetsize
 * Note: ARM64 uses rt_sigpending instead of sigpending (adds sigsetsize parameter)
 */
static int64_t sys_rt_sigpending_wrapper(uint64_t set, uint64_t sigsetsize, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* Linux requires sigsetsize == sizeof(sigset_t) */
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    return sys_sigpending((sigset_t *)set);
}

/* sys_rt_sigsuspend_wrapper - atomically change signal mask and suspend
 * x0 = mask, x1 = sigsetsize
 * Note: ARM64 uses rt_sigsuspend instead of sigsuspend (adds sigsetsize parameter)
 */
static int64_t sys_rt_sigsuspend_wrapper(uint64_t mask, uint64_t sigsetsize, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* Linux requires sigsetsize == sizeof(sigset_t) */
    if (sigsetsize != sizeof(sigset_t))
        return -EINVAL;
    return sys_sigsuspend((const sigset_t *)mask);
}

/* sys_sigaltstack_wrapper - set/get signal stack context
 * x0 = ss, x1 = old_ss
 * Note: ARM64 uses sigaltstack instead of rt_sigaltstack (no sigsetsize parameter)
 */
static int64_t sys_sigaltstack_wrapper(uint64_t ss, uint64_t old_ss, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sigaltstack((const struct sigaltstack *)ss, (struct sigaltstack *)old_ss);
}

/* sys_rt_sigreturn_wrapper - return from signal handler
 * No arguments (SP points to rt_sigframe on user stack)
 * Restores processor state from signal frame and returns to interrupted code
 */
static int64_t sys_rt_sigreturn_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;

    /* rt_sigreturn doesn't actually return a value in the normal sense.
     * Instead, it modifies the exception frame that will be restored by
     * the exception entry code. The return value is ignored.
     *
     * The exception frame (fut_interrupt_frame_t) is available globally
     * and has been set by the exception handler before syscall dispatch.
     */
    extern fut_interrupt_frame_t *fut_current_frame;
    extern int fut_copy_from_user(void *to, const void *from, size_t size);
    extern int fut_signal_procmask(struct fut_task *task, int how,
                                   const sigset_t *set, sigset_t *oldset);
    extern struct fut_task *fut_task_current(void);

    if (!fut_current_frame) {
        return -EFAULT;  /* No frame available - shouldn't happen */
    }

    /* The signal frame was pushed onto the user stack.
     * The SP register in the current frame points to the rt_sigframe.
     */
    uint64_t user_sp = fut_current_frame->sp;
    struct rt_sigframe {
        siginfo_t info;
        ucontext_t uc;
        void (*return_address)(void);
        uint64_t pad;
    };

    /* Read the signal frame from user space */
    struct rt_sigframe local_frame;
    if (fut_copy_from_user(&local_frame, (void *)user_sp, sizeof(local_frame)) != 0) {
        return -EFAULT;  /* Bad address */
    }

    /* Restore general purpose registers x0-x30 from saved context */
    for (int i = 0; i < 31; i++) {
        fut_current_frame->x[i] = local_frame.uc.uc_mcontext.gregs.x[i];
    }

    /* Restore special registers */
    fut_current_frame->sp = local_frame.uc.uc_mcontext.gregs.sp;
    fut_current_frame->pc = local_frame.uc.uc_mcontext.gregs.pc;
    fut_current_frame->pstate = local_frame.uc.uc_mcontext.gregs.pstate;
    fut_current_frame->far = local_frame.uc.uc_mcontext.gregs.fault_address;

    /* Restore NEON/SIMD registers v0-v31 */
    for (int i = 0; i < 32; i++) {
        fut_current_frame->fpu_state[2*i] = (uint64_t)(local_frame.uc.uc_mcontext.gregs.v[i] & 0xFFFFFFFFFFFFFFFFULL);
        fut_current_frame->fpu_state[2*i+1] = (uint64_t)((local_frame.uc.uc_mcontext.gregs.v[i] >> 64) & 0xFFFFFFFFFFFFFFFFULL);
    }

    /* Restore floating point control registers */
    fut_current_frame->fpsr = local_frame.uc.uc_mcontext.gregs.fpsr;
    fut_current_frame->fpcr = local_frame.uc.uc_mcontext.gregs.fpcr;

    /* Restore signal mask */
    struct fut_task *current = fut_task_current();
    if (current) {
        /* Restore the original signal mask that was in effect before handler */
        fut_signal_procmask(current, SIGPROCMASK_SETMASK,
                           (const sigset_t *)&local_frame.uc.uc_sigmask, NULL);
    }

    /* Clear the signal from pending_signals to indicate it's been handled */
    /* Note: This is simplified; a full implementation would track which signal
     * was being handled and clear its bit from pending_signals */
    if (current && local_frame.info.si_signum > 0 && local_frame.info.si_signum < 32) {
        uint64_t signal_bit = (1ULL << (local_frame.info.si_signum - 1));
        current->pending_signals &= ~signal_bit;
    }

    /* Return 0 to indicate successful context restoration.
     * The exception entry code will use the modified frame to restore
     * registers and return to user code via ERET.
     */
    return 0;
}

/* sys_tkill_wrapper - send signal to specific thread */
static int64_t sys_tkill_wrapper(uint64_t tid, uint64_t sig, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_tkill((int)tid, (int)sig);
}

/* sys_tgkill_wrapper - send signal to specific thread in thread group */
static int64_t sys_tgkill_wrapper(uint64_t tgid, uint64_t tid, uint64_t sig,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_tgkill((int)tgid, (int)tid, (int)sig);
}

/* sys_timer_create_wrapper - create a POSIX per-process timer
 * x0 = clockid, x1 = sevp (sigevent*), x2 = timerid (timer_t*)
 */
static int64_t sys_timer_create_wrapper(uint64_t clockid, uint64_t sevp, uint64_t timerid,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_timer_create((int)clockid, (struct sigevent *)sevp, (timer_t *)timerid);
}

/* sys_timer_settime_wrapper - arm/disarm a POSIX per-process timer
 * x0 = timerid, x1 = flags, x2 = new_value (itimerspec*), x3 = old_value (itimerspec*)
 */
static int64_t sys_timer_settime_wrapper(uint64_t timerid, uint64_t flags,
                                          uint64_t new_value, uint64_t old_value,
                                          uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_timer_settime((timer_t)timerid, (int)flags,
                             (const struct itimerspec *)new_value,
                             (struct itimerspec *)old_value);
}

/* sys_timer_gettime_wrapper - get current setting of a timer
 * x0 = timerid, x1 = curr_value (itimerspec*)
 */
static int64_t sys_timer_gettime_wrapper(uint64_t timerid, uint64_t curr_value, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_timer_gettime((timer_t)timerid, (struct itimerspec *)curr_value);
}

/* sys_timer_getoverrun_wrapper - get overrun count for a timer
 * x0 = timerid
 */
static int64_t sys_timer_getoverrun_wrapper(uint64_t timerid, uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_timer_getoverrun((timer_t)timerid);
}

/* sys_timer_delete_wrapper - delete a POSIX per-process timer
 * x0 = timerid
 */
static int64_t sys_timer_delete_wrapper(uint64_t timerid, uint64_t arg1, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_timer_delete((timer_t)timerid);
}

/* sys_futex_wrapper - fast userspace locking
 * x0 = uaddr, x1 = op, x2 = val, x3 = timeout, x4 = uaddr2, x5 = val3
 */
static int64_t sys_futex_wrapper(uint64_t uaddr, uint64_t op, uint64_t val,
                                  uint64_t timeout, uint64_t uaddr2, uint64_t val3) {
    return sys_futex((uint32_t *)uaddr, (int)op, (uint32_t)val,
                     (const void *)timeout, (uint32_t *)uaddr2, (uint32_t)val3);
}

/* sys_set_robust_list_wrapper - set robust futex list head
 * x0 = head, x1 = len
 */
static int64_t sys_set_robust_list_wrapper(uint64_t head, uint64_t len, uint64_t arg2,
                                            uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_set_robust_list((struct robust_list_head *)head, (size_t)len);
}

/* sys_get_robust_list_wrapper - get robust futex list head
 * x0 = pid, x1 = head_ptr, x2 = len_ptr
 */
static int64_t sys_get_robust_list_wrapper(uint64_t pid, uint64_t head_ptr, uint64_t len_ptr,
                                            uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_get_robust_list((int)pid, (struct robust_list_head **)head_ptr, (size_t *)len_ptr);
}

/* sys_eventfd2_wrapper - create event notification file descriptor
 * x0 = initval, x1 = flags
 */
static int64_t sys_eventfd2_wrapper(uint64_t initval, uint64_t flags, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_eventfd2((unsigned int)initval, (int)flags);
}

/* sys_signalfd4_wrapper - create signal notification file descriptor
 * x0 = ufd, x1 = mask, x2 = sizemask, x3 = flags
 */
static int64_t sys_signalfd4_wrapper(uint64_t ufd, uint64_t mask, uint64_t sizemask,
                                      uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_signalfd4((int)ufd, (const void *)mask, (size_t)sizemask, (int)flags);
}

/* sys_timerfd_create_wrapper - create timer file descriptor
 * x0 = clockid, x1 = flags
 */
static int64_t sys_timerfd_create_wrapper(uint64_t clockid, uint64_t flags, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_timerfd_create((int)clockid, (int)flags);
}

/* sys_timerfd_settime_wrapper - arm/disarm timer file descriptor
 * x0 = ufd, x1 = flags, x2 = new_value, x3 = old_value
 */
static int64_t sys_timerfd_settime_wrapper(uint64_t ufd, uint64_t flags,
                                             uint64_t new_value, uint64_t old_value,
                                             uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_timerfd_settime((int)ufd, (int)flags,
                               (const struct itimerspec *)new_value,
                               (struct itimerspec *)old_value);
}

/* sys_timerfd_gettime_wrapper - get timer file descriptor settings
 * x0 = ufd, x1 = curr_value
 */
static int64_t sys_timerfd_gettime_wrapper(uint64_t ufd, uint64_t curr_value, uint64_t arg2,
                                            uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_timerfd_gettime((int)ufd, (struct itimerspec *)curr_value);
}

/* sys_madvise_wrapper - give advice about memory usage patterns
 * x0 = addr, x1 = length, x2 = advice
 */
static int64_t sys_madvise_wrapper(uint64_t addr, uint64_t length, uint64_t advice,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_madvise((void *)addr, (size_t)length, (int)advice);
}

/* sys_mlock_wrapper - lock memory pages in RAM
 * x0 = addr, x1 = len
 */
static int64_t sys_mlock_wrapper(uint64_t addr, uint64_t len, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_mlock((const void *)addr, (size_t)len);
}

/* sys_munlock_wrapper - unlock memory pages
 * x0 = addr, x1 = len
 */
static int64_t sys_munlock_wrapper(uint64_t addr, uint64_t len, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_munlock((const void *)addr, (size_t)len);
}

/* sys_mlockall_wrapper - lock all memory pages
 * x0 = flags
 */
static int64_t sys_mlockall_wrapper(uint64_t flags, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_mlockall((int)flags);
}

/* sys_munlockall_wrapper - unlock all memory pages
 * No arguments
 */
static int64_t sys_munlockall_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_munlockall();
}

/* sys_mincore_wrapper - determine memory residency
 * x0 = addr, x1 = len, x2 = vec
 */
static int64_t sys_mincore_wrapper(uint64_t addr, uint64_t len, uint64_t vec,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_mincore((void *)addr, (size_t)len, (unsigned char *)vec);
}

/* NUMA memory policy wrappers */
extern long sys_mbind(unsigned long addr, unsigned long len, int mode,
                      const unsigned long *nodemask, unsigned long maxnode,
                      unsigned int flags);
static int64_t sys_mbind_wrapper(uint64_t addr, uint64_t len, uint64_t mode,
                                  uint64_t nodemask, uint64_t maxnode, uint64_t flags) {
    return sys_mbind((unsigned long)addr, (unsigned long)len, (int)mode,
                     (const unsigned long *)nodemask, (unsigned long)maxnode,
                     (unsigned int)flags);
}
extern long sys_get_mempolicy(int *mode_out, unsigned long *nodemask_out,
                               unsigned long maxnode, unsigned long addr,
                               unsigned int flags);
static int64_t sys_get_mempolicy_wrapper(uint64_t mode_out, uint64_t nodemask_out,
                                          uint64_t maxnode, uint64_t addr, uint64_t flags,
                                          uint64_t arg5) {
    (void)arg5;
    return sys_get_mempolicy((int *)mode_out, (unsigned long *)nodemask_out,
                              (unsigned long)maxnode, (unsigned long)addr,
                              (unsigned int)flags);
}
extern long sys_set_mempolicy(int mode, const unsigned long *nodemask,
                               unsigned long maxnode);
static int64_t sys_set_mempolicy_wrapper(uint64_t mode, uint64_t nodemask,
                                          uint64_t maxnode, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_set_mempolicy((int)mode, (const unsigned long *)nodemask,
                              (unsigned long)maxnode);
}

/* perf/fanotify/userfaultfd/bpf ENOSYS/EPERM stubs */
extern long sys_perf_event_open(const void *attr, int pid, int cpu,
                                 int group_fd, unsigned long flags);
static int64_t sys_perf_event_open_wrapper(uint64_t attr, uint64_t pid, uint64_t cpu,
                                            uint64_t group_fd, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_perf_event_open((const void *)attr, (int)pid, (int)cpu,
                                (int)group_fd, (unsigned long)flags);
}
extern long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);
static int64_t sys_fanotify_init_wrapper(uint64_t flags, uint64_t event_f_flags,
                                          uint64_t arg2, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fanotify_init((unsigned int)flags, (unsigned int)event_f_flags);
}
extern long sys_fanotify_mark(int fanotify_fd, unsigned int flags,
                               unsigned long mask, int dirfd, const char *pathname);
static int64_t sys_fanotify_mark_wrapper(uint64_t fanotify_fd, uint64_t flags,
                                          uint64_t mask, uint64_t dirfd,
                                          uint64_t pathname, uint64_t arg5) {
    (void)arg5;
    return sys_fanotify_mark((int)fanotify_fd, (unsigned int)flags,
                              (unsigned long)mask, (int)dirfd, (const char *)pathname);
}
extern long sys_userfaultfd(int flags);
static int64_t sys_userfaultfd_wrapper(uint64_t flags, uint64_t arg1, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_userfaultfd((int)flags);
}
extern long sys_bpf(int cmd, const void *attr, unsigned int size);
static int64_t sys_bpf_wrapper(uint64_t cmd, uint64_t attr, uint64_t size,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_bpf((int)cmd, (const void *)attr, (unsigned int)size);
}

/* sys_msync_wrapper - synchronize memory-mapped file
 * x0 = addr, x1 = len, x2 = flags
 */
static int64_t sys_msync_wrapper(uint64_t addr, uint64_t len, uint64_t flags,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_msync((void *)addr, (size_t)len, (int)flags);
}

/* sys_getuid_wrapper - get real user ID
 * No arguments
 */
static int64_t sys_getuid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getuid();
}

/* sys_geteuid_wrapper - get effective user ID
 * No arguments
 */
static int64_t sys_geteuid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_geteuid();
}

/* sys_getgid_wrapper - get real group ID
 * No arguments
 */
static int64_t sys_getgid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getgid();
}

/* sys_getegid_wrapper - get effective group ID
 * No arguments
 */
static int64_t sys_getegid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getegid();
}

/* sys_setuid_wrapper - set user ID
 * x0 = uid
 */
static int64_t sys_setuid_wrapper(uint64_t uid, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setuid((uint32_t)uid);
}

/* sys_setgid_wrapper - set group ID
 * x0 = gid
 */
static int64_t sys_setgid_wrapper(uint64_t gid, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setgid((uint32_t)gid);
}

/* sys_seteuid_wrapper - set effective user ID
 * x0 = euid
 */
static int64_t sys_seteuid_wrapper(uint64_t euid, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_seteuid((uint32_t)euid);
}

/* sys_setegid_wrapper - set effective group ID
 * x0 = egid
 */
static int64_t sys_setegid_wrapper(uint64_t egid, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setegid((uint32_t)egid);
}

/* sys_setreuid_wrapper - set real and effective user ID
 * x0 = ruid, x1 = euid
 */
static int64_t sys_setreuid_wrapper(uint64_t ruid, uint64_t euid, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setreuid((uint32_t)ruid, (uint32_t)euid);
}

/* sys_setregid_wrapper - set real and effective group ID
 * x0 = rgid, x1 = egid
 */
static int64_t sys_setregid_wrapper(uint64_t rgid, uint64_t egid, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setregid((uint32_t)rgid, (uint32_t)egid);
}

/* sys_setresuid_wrapper - set real, effective, and saved user ID
 * x0 = ruid, x1 = euid, x2 = suid
 */
static int64_t sys_setresuid_wrapper(uint64_t ruid, uint64_t euid, uint64_t suid,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_setresuid((uint32_t)ruid, (uint32_t)euid, (uint32_t)suid);
}

/* sys_getresuid_wrapper - get real, effective, and saved user ID
 * x0 = ruid, x1 = euid, x2 = suid
 */
static int64_t sys_getresuid_wrapper(uint64_t ruid, uint64_t euid, uint64_t suid,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getresuid((uint32_t *)ruid, (uint32_t *)euid, (uint32_t *)suid);
}

/* sys_setresgid_wrapper - set real, effective, and saved group ID
 * x0 = rgid, x1 = egid, x2 = sgid
 */
static int64_t sys_setresgid_wrapper(uint64_t rgid, uint64_t egid, uint64_t sgid,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_setresgid((uint32_t)rgid, (uint32_t)egid, (uint32_t)sgid);
}

/* sys_getresgid_wrapper - get real, effective, and saved group ID
 * x0 = rgid, x1 = egid, x2 = sgid
 */
static int64_t sys_getresgid_wrapper(uint64_t rgid, uint64_t egid, uint64_t sgid,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getresgid((uint32_t *)rgid, (uint32_t *)egid, (uint32_t *)sgid);
}

/* sys_getrlimit_wrapper - get resource limits
 * x0 = resource, x1 = rlim
 */
static int64_t sys_getrlimit_wrapper(uint64_t resource, uint64_t rlim, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getrlimit((int)resource, (struct rlimit *)rlim);
}

/* sys_setrlimit_wrapper - set resource limits
 * x0 = resource, x1 = rlim
 */
static int64_t sys_setrlimit_wrapper(uint64_t resource, uint64_t rlim, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setrlimit((int)resource, (const struct rlimit *)rlim);
}

/* sys_prlimit64_wrapper - get/set process resource limits
 * x0 = pid, x1 = resource, x2 = new_limit, x3 = old_limit
 */
static int64_t sys_prlimit64_wrapper(uint64_t pid, uint64_t resource, uint64_t new_limit,
                                      uint64_t old_limit, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_prlimit64((int)pid, (int)resource,
                         (const struct rlimit64 *)new_limit,
                         (struct rlimit64 *)old_limit);
}

/* sys_getpgid_wrapper - get process group ID
 * x0 = pid
 */
static int64_t sys_getpgid_wrapper(uint64_t pid, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getpgid(pid);
}

/* sys_setpgid_wrapper - set process group ID
 * x0 = pid, x1 = pgid
 */
static int64_t sys_setpgid_wrapper(uint64_t pid, uint64_t pgid, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setpgid(pid, pgid);
}

/* sys_getsid_wrapper - get session ID
 * x0 = pid
 */
static int64_t sys_getsid_wrapper(uint64_t pid, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getsid(pid);
}

/* sys_setsid_wrapper - create new session
 * No arguments
 */
static int64_t sys_setsid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setsid();
}

/* sys_getpgrp_wrapper - get process group ID
 * No arguments
 */
static int64_t sys_getpgrp_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getpgrp();
}

/* ============================================================
 *   FIPC (Futura IPC) System Call Wrappers
 * ============================================================ */

/* sys_fipc_create_wrapper - create FIPC channel
 * x0 = flags, x1 = queue_size
 */
static int64_t sys_fipc_create_wrapper(uint64_t flags, uint64_t queue_size, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fipc_create((uint32_t)flags, (size_t)queue_size);
}

/* sys_fipc_send_wrapper - send message on FIPC channel
 * x0 = channel_id, x1 = type, x2 = data, x3 = size
 */
static int64_t sys_fipc_send_wrapper(uint64_t channel_id, uint64_t type, uint64_t data,
                                      uint64_t size, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fipc_send(channel_id, (uint32_t)type, (const void *)data, (size_t)size);
}

/* sys_fipc_recv_wrapper - receive message from FIPC channel
 * x0 = channel_id, x1 = buf, x2 = buf_size
 */
static int64_t sys_fipc_recv_wrapper(uint64_t channel_id, uint64_t buf, uint64_t buf_size,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_fipc_recv(channel_id, (void *)buf, (size_t)buf_size);
}

/* sys_fipc_close_wrapper - close FIPC channel
 * x0 = channel_id
 */
static int64_t sys_fipc_close_wrapper(uint64_t channel_id, uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fipc_close(channel_id);
}

/* sys_fipc_poll_wrapper - poll FIPC channel for events
 * x0 = channel_id, x1 = event_mask
 */
static int64_t sys_fipc_poll_wrapper(uint64_t channel_id, uint64_t event_mask, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fipc_poll(channel_id, (uint32_t)event_mask);
}

/* sys_fipc_connect_wrapper - connect to existing FIPC channel
 * x0 = channel_id
 */
static int64_t sys_fipc_connect_wrapper(uint64_t channel_id, uint64_t arg1, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fipc_connect(channel_id);
}

/* sys_sched_setparam_wrapper - set scheduling parameters
 * x0 = pid, x1 = param
 */
static int64_t sys_sched_setparam_wrapper(uint64_t pid, uint64_t param, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_setparam((int)pid, (const struct sched_param *)param);
}

/* sys_sched_getparam_wrapper - get scheduling parameters
 * x0 = pid, x1 = param
 */
static int64_t sys_sched_getparam_wrapper(uint64_t pid, uint64_t param, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_getparam((int)pid, (struct sched_param *)param);
}

/* sys_sched_setscheduler_wrapper - set scheduling policy and parameters
 * x0 = pid, x1 = policy, x2 = param
 */
static int64_t sys_sched_setscheduler_wrapper(uint64_t pid, uint64_t policy, uint64_t param,
                                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_setscheduler((int)pid, (int)policy, (const struct sched_param *)param);
}

/* sys_sched_getscheduler_wrapper - get scheduling policy
 * x0 = pid
 */
static int64_t sys_sched_getscheduler_wrapper(uint64_t pid, uint64_t arg1, uint64_t arg2,
                                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_getscheduler((int)pid);
}

/* sys_sched_yield_wrapper - yield the processor
 * No arguments
 */
static int64_t sys_sched_yield_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_yield();
}

/* sys_sched_get_priority_max_wrapper - get maximum priority for policy
 * x0 = policy
 */
static int64_t sys_sched_get_priority_max_wrapper(uint64_t policy, uint64_t arg1, uint64_t arg2,
                                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_get_priority_max((int)policy);
}

/* sys_sched_get_priority_min_wrapper - get minimum priority for policy
 * x0 = policy
 */
static int64_t sys_sched_get_priority_min_wrapper(uint64_t policy, uint64_t arg1, uint64_t arg2,
                                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_get_priority_min((int)policy);
}

/* sys_getgroups_wrapper */
static int64_t sys_getgroups_wrapper(uint64_t size, uint64_t list, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getgroups((int)size, (uint32_t *)list);
}

/* sys_setgroups_wrapper */
static int64_t sys_setgroups_wrapper(uint64_t size, uint64_t list, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setgroups((int)size, (const uint32_t *)list);
}

/* sys_gettid_wrapper - get thread ID */
extern long sys_gettid(void);
static int64_t sys_gettid_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_gettid();
}

/* sys_sethostname_wrapper */
extern long sys_sethostname(const char *name, int len);
static int64_t sys_sethostname_wrapper(uint64_t name, uint64_t len, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sethostname((const char *)name, (int)len);
}

/* sys_setdomainname_wrapper */
extern long sys_setdomainname(const char *name, int len);
static int64_t sys_setdomainname_wrapper(uint64_t name, uint64_t len, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setdomainname((const char *)name, (int)len);
}

/* sys_reboot_wrapper */
extern long sys_reboot(unsigned int magic1, unsigned int magic2,
                       unsigned int cmd, void *arg);
static int64_t sys_reboot_wrapper(uint64_t magic1, uint64_t magic2, uint64_t cmd,
                                   uint64_t arg, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_reboot((unsigned int)magic1, (unsigned int)magic2,
                      (unsigned int)cmd, (void *)arg);
}

/* sys_rt_sigtimedwait_wrapper */
extern long sys_rt_sigtimedwait(const uint64_t *uthese, void *uinfo,
                                const void *uts, size_t sigsetsize);
static int64_t sys_rt_sigtimedwait_wrapper(uint64_t uthese, uint64_t uinfo,
                                            uint64_t uts, uint64_t sigsetsize,
                                            uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_rt_sigtimedwait((const uint64_t *)uthese, (void *)uinfo,
                               (const void *)uts, (size_t)sigsetsize);
}

/* sys_mremap_wrapper */
extern long sys_mremap(void *old_address, size_t old_size, size_t new_size,
                       int flags, void *new_address);
static int64_t sys_mremap_wrapper(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                                   uint64_t flags, uint64_t new_addr, uint64_t arg5) {
    (void)arg5;
    return sys_mremap((void *)old_addr, (size_t)old_size, (size_t)new_size,
                      (int)flags, (void *)new_addr);
}

/* sys_sendmsg_wrapper */
extern ssize_t sys_sendmsg(int sockfd, const void *msg, int flags);
static int64_t sys_sendmsg_wrapper(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_sendmsg((int)sockfd, (const void *)msg, (int)flags);
}

/* sys_recvmsg_wrapper */
extern ssize_t sys_recvmsg(int sockfd, void *msg, int flags);
static int64_t sys_recvmsg_wrapper(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return (int64_t)sys_recvmsg((int)sockfd, (void *)msg, (int)flags);
}

/* sys_getsockname_wrapper */
extern long sys_getsockname(int sockfd, void *addr, socklen_t *addrlen);
static int64_t sys_getsockname_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getsockname((int)sockfd, (void *)addr, (socklen_t *)addrlen);
}

/* sys_getpeername_wrapper */
extern long sys_getpeername(int sockfd, void *addr, socklen_t *addrlen);
static int64_t sys_getpeername_wrapper(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getpeername((int)sockfd, (void *)addr, (socklen_t *)addrlen);
}

/* sys_memfd_create_wrapper */
extern long sys_memfd_create(const char *uname, unsigned int flags);
static int64_t sys_memfd_create_wrapper(uint64_t uname, uint64_t flags, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_memfd_create((const char *)uname, (unsigned int)flags);
}

/* sys_syncfs_wrapper */
extern long sys_syncfs(int fd);
static int64_t sys_syncfs_wrapper(uint64_t fd, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_syncfs((int)fd);
}

/* sys_close_range_wrapper */
extern long sys_close_range(unsigned int first, unsigned int last, unsigned int flags);
static int64_t sys_close_range_wrapper(uint64_t first, uint64_t last, uint64_t flags,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_close_range((unsigned int)first, (unsigned int)last, (unsigned int)flags);
}

/* sys_pidfd_open_wrapper */
extern long sys_pidfd_open(int pid, unsigned int flags);
static int64_t sys_pidfd_open_wrapper(uint64_t pid, uint64_t flags,
                                      uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pidfd_open((int)pid, (unsigned int)flags);
}

/* sys_pidfd_send_signal_wrapper */
extern long sys_pidfd_send_signal(int pidfd, int sig, const void *info, unsigned int flags);
static int64_t sys_pidfd_send_signal_wrapper(uint64_t pidfd, uint64_t sig, uint64_t info,
                                              uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_pidfd_send_signal((int)pidfd, (int)sig, (const void *)info, (unsigned int)flags);
}

/* sys_pidfd_getfd_wrapper */
extern long sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
static int64_t sys_pidfd_getfd_wrapper(uint64_t pidfd, uint64_t targetfd, uint64_t flags,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_pidfd_getfd((int)pidfd, (int)targetfd, (unsigned int)flags);
}

/* sys_renameat2_wrapper */
extern long sys_renameat2(int olddirfd, const char *oldpath,
                          int newdirfd, const char *newpath, unsigned int flags);
static int64_t sys_renameat2_wrapper(uint64_t olddirfd, uint64_t oldpath, uint64_t newdirfd,
                                      uint64_t newpath, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    return sys_renameat2((int)olddirfd, (const char *)oldpath,
                         (int)newdirfd, (const char *)newpath, (unsigned int)flags);
}

/* sys_socketpair_wrapper */
static int64_t sys_socketpair_wrapper(uint64_t domain, uint64_t type, uint64_t protocol,
                                       uint64_t sv, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    return sys_socketpair((int)domain, (int)type, (int)protocol, (int *)sv);
}

/* POSIX message queue wrappers (180-185) */
struct arm64_mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
    long __pad[4];
};

extern long sys_mq_open(const char *name, int oflag, unsigned int mode,
                        const struct arm64_mq_attr *attr);
extern long sys_mq_unlink(const char *name);
extern long sys_mq_timedsend(int mqdes, const char *msg_ptr, size_t msg_len,
                             unsigned msg_prio, const void *abs_timeout);
extern long sys_mq_timedreceive(int mqdes, char *msg_ptr, size_t msg_len,
                                unsigned *msg_prio, const void *abs_timeout);
extern long sys_mq_notify(int mqdes, const void *sevp);
extern long sys_mq_getsetattr(int mqdes, const struct arm64_mq_attr *newattr,
                              struct arm64_mq_attr *oldattr);

static int64_t sys_mq_open_wrapper(uint64_t name, uint64_t oflag, uint64_t mode,
                                   uint64_t attr, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    return sys_mq_open((const char *)(uintptr_t)name, (int)oflag,
                       (unsigned int)mode,
                       (const struct arm64_mq_attr *)(uintptr_t)attr);
}

static int64_t sys_mq_unlink_wrapper(uint64_t name, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_unlink((const char *)(uintptr_t)name);
}

static int64_t sys_mq_timedsend_wrapper(uint64_t mqdes, uint64_t msg_ptr, uint64_t msg_len,
                                        uint64_t msg_prio, uint64_t abs_timeout, uint64_t arg6) {
    (void)arg6;
    return sys_mq_timedsend((int)mqdes, (const char *)(uintptr_t)msg_ptr,
                            (size_t)msg_len, (unsigned)msg_prio,
                            (const void *)(uintptr_t)abs_timeout);
}

static int64_t sys_mq_timedreceive_wrapper(uint64_t mqdes, uint64_t msg_ptr, uint64_t msg_len,
                                           uint64_t msg_prio, uint64_t abs_timeout, uint64_t arg6) {
    (void)arg6;
    return sys_mq_timedreceive((int)mqdes, (char *)(uintptr_t)msg_ptr,
                               (size_t)msg_len, (unsigned *)(uintptr_t)msg_prio,
                               (const void *)(uintptr_t)abs_timeout);
}

static int64_t sys_mq_notify_wrapper(uint64_t mqdes, uint64_t sevp, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_notify((int)mqdes, (const void *)(uintptr_t)sevp);
}

static int64_t sys_mq_getsetattr_wrapper(uint64_t mqdes, uint64_t newattr, uint64_t oldattr,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_getsetattr((int)mqdes,
                             (const struct arm64_mq_attr *)(uintptr_t)newattr,
                             (struct arm64_mq_attr *)(uintptr_t)oldattr);
}

/* sys_readahead_wrapper - read-ahead hint */
static int64_t sys_readahead_wrapper(uint64_t fd, uint64_t offset, uint64_t count,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_readahead((int)fd, (int64_t)offset, (size_t)count);
}

/* sys_getcpu_wrapper - get current CPU and NUMA node */
static int64_t sys_getcpu_wrapper(uint64_t cpup, uint64_t nodep, uint64_t unused,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getcpu((unsigned int *)cpup, (unsigned int *)nodep, (void *)unused);
}

/* sys_sched_rr_get_interval_wrapper - get RR time quantum */
static int64_t sys_sched_rr_get_interval_wrapper(uint64_t pid, uint64_t interval, uint64_t arg2,
                                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_rr_get_interval((int)pid, (void *)interval);
}

/* sys_getpriority_wrapper - get process priority (nice value)
 * x0 = which, x1 = who
 */
static int64_t sys_getpriority_wrapper(uint64_t which, uint64_t who, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getpriority((int)which, (int)who);
}

/* sys_setpriority_wrapper - set process priority (nice value)
 * x0 = which, x1 = who, x2 = prio
 */
static int64_t sys_setpriority_wrapper(uint64_t which, uint64_t who, uint64_t prio,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_setpriority((int)which, (int)who, (int)prio);
}

/* sys_getitimer_wrapper - get interval timer value
 * x0 = which, x1 = value
 */
static int64_t sys_getitimer_wrapper(uint64_t which, uint64_t value, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getitimer((int)which, (struct itimerval *)value);
}

/* sys_setitimer_wrapper - set interval timer value
 * x0 = which, x1 = value, x2 = ovalue
 */
static int64_t sys_setitimer_wrapper(uint64_t which, uint64_t value, uint64_t ovalue,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_setitimer((int)which, (const struct itimerval *)value, (struct itimerval *)ovalue);
}

/* sys_clock_settime_wrapper - set clock time
 * x0 = clock_id, x1 = tp
 */
static int64_t sys_clock_settime_wrapper(uint64_t clock_id, uint64_t tp, uint64_t arg2,
                                           uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_clock_settime((int)clock_id, (const fut_timespec_t *)tp);
}

/* sys_clock_getres_wrapper - get clock resolution
 * x0 = clock_id, x1 = res
 */
static int64_t sys_clock_getres_wrapper(uint64_t clock_id, uint64_t res, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_clock_getres((int)clock_id, (fut_timespec_t *)res);
}

/* sys_clock_nanosleep_wrapper - high-resolution sleep on specific clock
 * x0 = clock_id, x1 = flags, x2 = req, x3 = rem
 */
static int64_t sys_clock_nanosleep_wrapper(uint64_t clock_id, uint64_t flags, uint64_t req,
                                             uint64_t rem, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_clock_nanosleep((int)clock_id, (int)flags, (const fut_timespec_t *)req, (fut_timespec_t *)rem);
}

/* sys_gettimeofday_wrapper - get time of day
 * x0 = tv, x1 = tz
 */
static int64_t sys_gettimeofday_wrapper(uint64_t tv, uint64_t tz, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_gettimeofday((fut_timeval_t *)tv, (void *)tz);
}

/* sys_settimeofday_wrapper - set time of day
 * x0 = tv, x1 = tz
 */
static int64_t sys_settimeofday_wrapper(uint64_t tv, uint64_t tz, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_settimeofday((const fut_timeval_t *)tv, (const void *)tz);
}

/* sys_times_wrapper - get process times
 * x0 = buf
 */
static int64_t sys_times_wrapper(uint64_t buf, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    /* tms structure declared in kernel/sys_times.c */
    return sys_times((void *)buf);
}

/* sys_adjtimex_wrapper - adjust kernel clock
 * x0 = txc
 */
static int64_t sys_adjtimex_wrapper(uint64_t txc, uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_adjtimex((struct timex *)txc);
}

/* sys_fcntl_wrapper - file control operations
 * x0 = fd, x1 = cmd, x2 = arg
 */
static int64_t sys_fcntl_wrapper(uint64_t fd, uint64_t cmd, uint64_t arg,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_fcntl((int)fd, (int)cmd, arg);
}

/* sys_ioctl_wrapper - I/O control
 * x0 = fd, x1 = request, x2 = argp
 */
static int64_t sys_ioctl_wrapper(uint64_t fd, uint64_t request, uint64_t argp,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_ioctl((int)fd, (unsigned long)request, (void *)argp);
}

/* sys_chroot_wrapper - change root directory
 * x0 = path
 */
static int64_t sys_chroot_wrapper(uint64_t path, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_chroot((const char *)path);
}

/* sys_sendfile_wrapper - copy data between file descriptors
 * x0 = out_fd, x1 = in_fd, x2 = offset, x3 = count
 */
static int64_t sys_sendfile_wrapper(uint64_t out_fd, uint64_t in_fd, uint64_t offset,
                                      uint64_t count, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_sendfile((int)out_fd, (int)in_fd, (uint64_t *)offset, (size_t)count);
}

/* sys_sync_wrapper - synchronize all filesystems
 * No arguments
 */
static int64_t sys_sync_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sync();
}

/* sys_fsync_wrapper - synchronize file to storage
 * x0 = fd
 */
static int64_t sys_fsync_wrapper(uint64_t fd, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fsync((int)fd);
}

/* sys_fdatasync_wrapper - synchronize file data to storage
 * x0 = fd
 */
static int64_t sys_fdatasync_wrapper(uint64_t fd, uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fdatasync((int)fd);
}

/* sys_statfs_wrapper - get filesystem statistics
 * x0 = path, x1 = buf
 */
static int64_t sys_statfs_wrapper(uint64_t path, uint64_t buf, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_statfs((const char *)path, (struct fut_linux_statfs *)buf);
}

/* sys_fstatfs_wrapper - get filesystem statistics by fd
 * x0 = fd, x1 = buf
 */
static int64_t sys_fstatfs_wrapper(uint64_t fd, uint64_t buf, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fstatfs((int)fd, (struct fut_linux_statfs *)buf);
}

/* sys_truncate_wrapper - truncate file to specified length
 * x0 = path, x1 = length
 */
static int64_t sys_truncate_wrapper(uint64_t path, uint64_t length, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_truncate((const char *)path, (int64_t)length);
}

/* sys_ftruncate_wrapper - truncate open file to specified length
 * x0 = fd, x1 = length
 */
static int64_t sys_ftruncate_wrapper(uint64_t fd, uint64_t length, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_ftruncate((int)fd, (int64_t)length);
}

/* sys_fallocate_wrapper - preallocate file space
 * x0 = fd, x1 = mode, x2 = offset, x3 = len
 */
static int64_t sys_fallocate_wrapper(uint64_t fd, uint64_t mode, uint64_t offset,
                                       uint64_t len, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fallocate((int)fd, (int)mode, offset, len);
}

/* sys_getrusage_wrapper - get resource usage
 * x0 = who, x1 = usage
 */
static int64_t sys_getrusage_wrapper(uint64_t who, uint64_t usage, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_getrusage((int)who, (void *)usage);
}

/* sys_umask_wrapper - set file mode creation mask
 * x0 = mask
 */
static int64_t sys_umask_wrapper(uint64_t mask, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_umask((uint32_t)mask);
}

/* sys_sysinfo_wrapper - get system information
 * x0 = info
 */
static int64_t sys_sysinfo_wrapper(uint64_t info, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_sysinfo((struct fut_linux_sysinfo *)info);
}

/* sys_fchownat_wrapper - change file ownership with dirfd
 * x0 = dirfd, x1 = pathname, x2 = uid, x3 = gid, x4 = flags
 */
static int64_t sys_fchownat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t uid,
                                      uint64_t gid, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_fchownat((int)dirfd, (const char *)pathname, (uint32_t)uid, (uint32_t)gid, (int)flags);
}

/* sys_fchown_wrapper - change file ownership via fd
 * x0 = fd, x1 = uid, x2 = gid
 */
static int64_t sys_fchown_wrapper(uint64_t fd, uint64_t uid, uint64_t gid,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_fchown((int)fd, (uint32_t)uid, (uint32_t)gid);
}

/* sys_getdents64_wrapper - read directory entries
 * x0 = fd, x1 = dirent, x2 = count
 */
static int64_t sys_getdents64_wrapper(uint64_t fd, uint64_t dirent, uint64_t count,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getdents64((unsigned int)fd, (void *)dirent, (unsigned int)count);
}

/* sys_utimensat_wrapper - change file timestamps with dirfd
 * x0 = dirfd, x1 = pathname, x2 = times, x3 = flags
 */
static int64_t sys_utimensat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t times,
                                       uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_utimensat((int)dirfd, (const char *)pathname, (const fut_timespec_t *)times, (int)flags);
}

/* Extended attributes (xattr) wrappers */

/* sys_setxattr_wrapper - set extended attribute
 * x0 = path, x1 = name, x2 = value, x3 = size, x4 = flags
 */
static int64_t sys_setxattr_wrapper(uint64_t path, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_setxattr((const char *)path, (const char *)name, (const void *)value,
                        (size_t)size, (int)flags);
}

/* sys_lsetxattr_wrapper - set extended attribute (no symlink follow)
 * x0 = path, x1 = name, x2 = value, x3 = size, x4 = flags
 */
static int64_t sys_lsetxattr_wrapper(uint64_t path, uint64_t name, uint64_t value,
                                      uint64_t size, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_lsetxattr((const char *)path, (const char *)name, (const void *)value,
                         (size_t)size, (int)flags);
}

/* sys_fsetxattr_wrapper - set extended attribute via fd
 * x0 = fd, x1 = name, x2 = value, x3 = size, x4 = flags
 */
static int64_t sys_fsetxattr_wrapper(uint64_t fd, uint64_t name, uint64_t value,
                                      uint64_t size, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_fsetxattr((int)fd, (const char *)name, (const void *)value,
                         (size_t)size, (int)flags);
}

/* sys_getxattr_wrapper - get extended attribute
 * x0 = path, x1 = name, x2 = value, x3 = size
 */
static int64_t sys_getxattr_wrapper(uint64_t path, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_getxattr((const char *)path, (const char *)name, (void *)value, (size_t)size);
}

/* sys_lgetxattr_wrapper - get extended attribute (no symlink follow)
 * x0 = path, x1 = name, x2 = value, x3 = size
 */
static int64_t sys_lgetxattr_wrapper(uint64_t path, uint64_t name, uint64_t value,
                                      uint64_t size, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_lgetxattr((const char *)path, (const char *)name, (void *)value, (size_t)size);
}

/* sys_fgetxattr_wrapper - get extended attribute via fd
 * x0 = fd, x1 = name, x2 = value, x3 = size
 */
static int64_t sys_fgetxattr_wrapper(uint64_t fd, uint64_t name, uint64_t value,
                                      uint64_t size, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fgetxattr((int)fd, (const char *)name, (void *)value, (size_t)size);
}

/* sys_listxattr_wrapper - list extended attributes
 * x0 = path, x1 = list, x2 = size
 */
static int64_t sys_listxattr_wrapper(uint64_t path, uint64_t list, uint64_t size,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_listxattr((const char *)path, (char *)list, (size_t)size);
}

/* sys_llistxattr_wrapper - list extended attributes (no symlink follow)
 * x0 = path, x1 = list, x2 = size
 */
static int64_t sys_llistxattr_wrapper(uint64_t path, uint64_t list, uint64_t size,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_llistxattr((const char *)path, (char *)list, (size_t)size);
}

/* sys_flistxattr_wrapper - list extended attributes via fd
 * x0 = fd, x1 = list, x2 = size
 */
static int64_t sys_flistxattr_wrapper(uint64_t fd, uint64_t list, uint64_t size,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_flistxattr((int)fd, (char *)list, (size_t)size);
}

/* sys_removexattr_wrapper - remove extended attribute
 * x0 = path, x1 = name
 */
static int64_t sys_removexattr_wrapper(uint64_t path, uint64_t name, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_removexattr((const char *)path, (const char *)name);
}

/* sys_lremovexattr_wrapper - remove extended attribute (no symlink follow)
 * x0 = path, x1 = name
 */
static int64_t sys_lremovexattr_wrapper(uint64_t path, uint64_t name, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_lremovexattr((const char *)path, (const char *)name);
}

/* sys_fremovexattr_wrapper - remove extended attribute via fd
 * x0 = fd, x1 = name
 */
static int64_t sys_fremovexattr_wrapper(uint64_t fd, uint64_t name, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fremovexattr((int)fd, (const char *)name);
}

/* File monitoring (inotify) wrappers */

/* sys_inotify_init1_wrapper - create inotify instance
 * x0 = flags
 */
static int64_t sys_inotify_init1_wrapper(uint64_t flags, uint64_t arg1, uint64_t arg2,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_inotify_init1((int)flags);
}

/* sys_inotify_add_watch_wrapper - add watch to inotify instance
 * x0 = fd, x1 = pathname, x2 = mask
 */
static int64_t sys_inotify_add_watch_wrapper(uint64_t fd, uint64_t pathname, uint64_t mask,
                                               uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_inotify_add_watch((int)fd, (const char *)pathname, (uint32_t)mask);
}

/* sys_inotify_rm_watch_wrapper - remove watch from inotify instance
 * x0 = fd, x1 = wd
 */
static int64_t sys_inotify_rm_watch_wrapper(uint64_t fd, uint64_t wd, uint64_t arg2,
                                              uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_inotify_rm_watch((int)fd, (int)wd);
}

/* Zero-copy I/O (splice family) wrappers */

/* sys_splice_wrapper - splice data between file descriptors
 * x0 = fd_in, x1 = off_in, x2 = fd_out, x3 = off_out, x4 = len, x5 = flags
 */
static int64_t sys_splice_wrapper(uint64_t fd_in, uint64_t off_in, uint64_t fd_out,
                                    uint64_t off_out, uint64_t len, uint64_t flags) {
    return sys_splice((int)fd_in, (int64_t *)off_in, (int)fd_out,
                      (int64_t *)off_out, (size_t)len, (unsigned int)flags);
}

/* sys_vmsplice_wrapper - splice user memory into pipe
 * x0 = fd, x1 = iov, x2 = nr_segs, x3 = flags
 */
static int64_t sys_vmsplice_wrapper(uint64_t fd, uint64_t iov, uint64_t nr_segs,
                                      uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_vmsplice((int)fd, (const void *)iov, (size_t)nr_segs, (unsigned int)flags);
}

/* sys_tee_wrapper - duplicate pipe content
 * x0 = fd_in, x1 = fd_out, x2 = len, x3 = flags
 */
static int64_t sys_tee_wrapper(uint64_t fd_in, uint64_t fd_out, uint64_t len,
                                 uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_tee((int)fd_in, (int)fd_out, (size_t)len, (unsigned int)flags);
}

/* sys_sync_file_range_wrapper - sync file region to disk
 * x0 = fd, x1 = offset, x2 = nbytes, x3 = flags
 */
static int64_t sys_sync_file_range_wrapper(uint64_t fd, uint64_t offset, uint64_t nbytes,
                                             uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_sync_file_range((int)fd, (int64_t)offset, (int64_t)nbytes, (unsigned int)flags);
}

/* sys_ioprio_set_wrapper - set I/O scheduling priority
 * x0 = which, x1 = who, x2 = ioprio
 */
static int64_t sys_ioprio_set_wrapper(uint64_t which, uint64_t who, uint64_t ioprio,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_ioprio_set((int)which, (int)who, (int)ioprio);
}

/* sys_ioprio_get_wrapper - get I/O scheduling priority
 * x0 = which, x1 = who
 */
static int64_t sys_ioprio_get_wrapper(uint64_t which, uint64_t who, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_ioprio_get((int)which, (int)who);
}

/* sys_capget_wrapper - get process capabilities
 * x0 = hdrp, x1 = datap
 */
static int64_t sys_capget_wrapper(uint64_t hdrp, uint64_t datap, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_capget((void *)hdrp, (void *)datap);
}

/* sys_capset_wrapper - set process capabilities
 * x0 = hdrp, x1 = datap
 */
static int64_t sys_capset_wrapper(uint64_t hdrp, uint64_t datap, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_capset((void *)hdrp, (const void *)datap);
}

/* sys_personality_wrapper - get/set process execution domain
 * x0 = persona
 */
static int64_t sys_personality_wrapper(uint64_t persona, uint64_t arg1, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_personality((unsigned long)persona);
}

/* sys_unshare_wrapper - disassociate parts of process context
 * x0 = flags
 */
static int64_t sys_unshare_wrapper(uint64_t flags, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_unshare((unsigned long)flags);
}

/* sys_acct_wrapper - enable/disable process accounting
 * x0 = filename
 */
static int64_t sys_acct_wrapper(uint64_t filename, uint64_t arg1, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_acct((const char *)filename);
}

/* sys_waitid_wrapper - wait for child process state change
 * x0 = idtype, x1 = id, x2 = infop, x3 = options, x4 = rusage
 */
static int64_t sys_waitid_wrapper(uint64_t idtype, uint64_t id, uint64_t infop,
                                    uint64_t options, uint64_t rusage, uint64_t arg5) {
    (void)arg5;
    return sys_waitid((int)idtype, (int)id, (void *)infop, (int)options, (void *)rusage);
}

/* sys_set_tid_address_wrapper - set thread ID address
 * x0 = tidptr
 */
static int64_t sys_set_tid_address_wrapper(uint64_t tidptr, uint64_t arg1, uint64_t arg2,
                                             uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_set_tid_address((int *)tidptr);
}

/* sys_flock_wrapper - apply or remove advisory lock on file
 * x0 = fd, x1 = operation
 */
static int64_t sys_flock_wrapper(uint64_t fd, uint64_t operation, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_flock((int)fd, (int)operation);
}

/* sys_mknodat_wrapper - create special file or device node
 * x0 = dirfd, x1 = pathname, x2 = mode, x3 = dev
 */
static int64_t sys_mknodat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                     uint64_t dev, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_mknodat((int)dirfd, (const char *)pathname, (uint32_t)mode, (uint32_t)dev);
}

/* sys_fchdir_wrapper - change working directory via file descriptor
 * x0 = fd
 */
static int64_t sys_fchdir_wrapper(uint64_t fd, uint64_t arg1, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fchdir((int)fd);
}

/* sys_fchmod_wrapper - change file permissions via file descriptor
 * x0 = fd, x1 = mode
 */
static int64_t sys_fchmod_wrapper(uint64_t fd, uint64_t mode, uint64_t arg2,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_fchmod((int)fd, (uint32_t)mode);
}

/* sys_umount2_wrapper - unmount filesystem with flags
 * x0 = target, x1 = flags
 */
static int64_t sys_umount2_wrapper(uint64_t target, uint64_t flags, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_umount2((const char *)target, (int)flags);
}

/* sys_mount_wrapper - mount filesystem
 * x0 = source, x1 = target, x2 = filesystemtype, x3 = mountflags, x4 = data
 */
static int64_t sys_mount_wrapper(uint64_t source, uint64_t target, uint64_t filesystemtype,
                                  uint64_t mountflags, uint64_t data, uint64_t arg5) {
    (void)arg5;
    return sys_mount((const char *)source, (const char *)target, (const char *)filesystemtype,
                     (unsigned long)mountflags, (const void *)data);
}

/* sys_copy_file_range_wrapper */
static int64_t sys_copy_file_range_wrapper(uint64_t fd_in, uint64_t off_in, uint64_t fd_out,
                                            uint64_t off_out, uint64_t len, uint64_t flags) {
    return sys_copy_file_range((int)fd_in, (int64_t *)off_in,
                                (int)fd_out, (int64_t *)off_out,
                                (size_t)len, (unsigned int)flags);
}

/* sys_rseq_wrapper */
static int64_t sys_rseq_wrapper(uint64_t rseq, uint64_t rseq_len, uint64_t flags,
                                 uint64_t sig, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_rseq((void *)rseq, (uint32_t)rseq_len, (int)flags, (uint32_t)sig);
}

/* sys_membarrier_wrapper - memory barrier */
static int64_t sys_membarrier_wrapper(uint64_t cmd, uint64_t flags, uint64_t cpu_id,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_membarrier((int)cmd, (unsigned int)flags, (int)cpu_id);
}

/* sys_statx_wrapper - extended file status */
static int64_t sys_statx_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                  uint64_t mask, uint64_t statxbuf, uint64_t arg6) {
    (void)arg6;
    return sys_statx((int)dirfd, (const char *)pathname, (int)flags,
                     (unsigned int)mask, (void *)statxbuf);
}


/* sys_syslog_wrapper - kernel log buffer */
static int64_t sys_syslog_wrapper(uint64_t type, uint64_t buf, uint64_t len,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_syslog((int)type, (char *)buf, (int)len);
}

/* sys_fadvise64_wrapper - file access advisory */
static int64_t sys_fadvise64_wrapper(uint64_t fd, uint64_t offset, uint64_t len,
                                      uint64_t advice, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_fadvise64((int)fd, (int64_t)offset, (int64_t)len, (int)advice);
}

/* sys_sched_setaffinity_wrapper */
static int64_t sys_sched_setaffinity_wrapper(uint64_t pid, uint64_t len, uint64_t mask,
                                              uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_setaffinity((int)pid, (unsigned int)len, (const void *)mask);
}

/* sys_sched_getaffinity_wrapper */
static int64_t sys_sched_getaffinity_wrapper(uint64_t pid, uint64_t len, uint64_t mask,
                                              uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_getaffinity((int)pid, (unsigned int)len, (void *)mask);
}

/* sys_getrandom_wrapper - generate random bytes */
static int64_t sys_getrandom_wrapper(uint64_t buf, uint64_t buflen, uint64_t flags,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_getrandom((void *)buf, (size_t)buflen, (unsigned int)flags);
}

/* sys_prctl_wrapper - process control operations */
static int64_t sys_prctl_wrapper(uint64_t option, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg6;
    return sys_prctl((int)option, arg2, arg3, arg4, arg5);
}

/* sys_pivot_root_wrapper - change root filesystem
 * x0 = new_root, x1 = put_old
 */
static int64_t sys_pivot_root_wrapper(uint64_t new_root, uint64_t put_old, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pivot_root((const char *)new_root, (const char *)put_old);
}

/* sys_vhangup_wrapper - hang up controlling terminal
 * No parameters
 */
static int64_t sys_vhangup_wrapper(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg0; (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_vhangup();
}

/* sys_quotactl_wrapper - manipulate disk quotas
 * x0 = cmd, x1 = special, x2 = id, x3 = addr
 */
static int64_t sys_quotactl_wrapper(uint64_t cmd, uint64_t special, uint64_t id,
                                     uint64_t addr, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_quotactl((unsigned int)cmd, (const char *)special, (int)id, (void *)addr);
}

/* sys_clock_adjtime_wrapper: clock_adjtime(clk_id, txc) — delegate to adjtimex for CLOCK_REALTIME */
static int64_t sys_clock_adjtime_wrapper(uint64_t clk_id, uint64_t txc,
                                          uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    if (clk_id != 0)  /* only CLOCK_REALTIME (0) supported */
        return -EINVAL;
    return sys_adjtimex((struct timex *)txc);
}

/* sys_setns_wrapper: setns(fd, nstype) — ENOSYS (namespaces not yet implemented) */
static int64_t sys_setns_wrapper(uint64_t fd, uint64_t nstype,
                                  uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)fd; (void)nstype; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return -38;  /* -ENOSYS */
}

/* sys_sched_setattr_wrapper */
extern long sys_sched_setattr(int pid, const void *uattr, unsigned int flags);
static int64_t sys_sched_setattr_wrapper(uint64_t pid, uint64_t uattr, uint64_t flags,
                                          uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_sched_setattr((int)pid, (const void *)uattr, (unsigned int)flags);
}

/* sys_sched_getattr_wrapper */
extern long sys_sched_getattr(int pid, void *uattr, unsigned int usize, unsigned int flags);
static int64_t sys_sched_getattr_wrapper(uint64_t pid, uint64_t uattr, uint64_t usize,
                                          uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_sched_getattr((int)pid, (void *)uattr, (unsigned int)usize, (unsigned int)flags);
}

/* sys_mlock2_wrapper */
extern long sys_mlock2(const void *addr, size_t len, unsigned int flags);
static int64_t sys_mlock2_wrapper(uint64_t addr, uint64_t len, uint64_t flags,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_mlock2((const void *)addr, (size_t)len, (unsigned int)flags);
}

/* sys_setfsuid_wrapper */
extern long sys_setfsuid(uint32_t fsuid);
static int64_t sys_setfsuid_wrapper(uint64_t fsuid, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setfsuid((uint32_t)fsuid);
}

/* sys_setfsgid_wrapper */
extern long sys_setfsgid(uint32_t fsgid);
static int64_t sys_setfsgid_wrapper(uint64_t fsgid, uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_setfsgid((uint32_t)fsgid);
}

/* sys_swapon_wrapper */
extern long sys_swapon(const char *path, int swapflags);
static int64_t sys_swapon_wrapper(uint64_t path, uint64_t swapflags,
                                   uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_swapon((const char *)path, (int)swapflags);
}

/* sys_swapoff_wrapper */
extern long sys_swapoff(const char *path);
static int64_t sys_swapoff_wrapper(uint64_t path, uint64_t arg1, uint64_t arg2,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_swapoff((const char *)path);
}

/* sys_epoll_pwait2_wrapper */
extern long sys_epoll_pwait2(int epfd, void *events, int maxevents,
                              const void *timeout_ts, const void *sigmask, size_t sigsetsize);
static int64_t sys_epoll_pwait2_wrapper(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                         uint64_t timeout_ts, uint64_t sigmask, uint64_t sigsetsize) {
    return sys_epoll_pwait2((int)epfd, (void *)events, (int)maxevents,
                             (const void *)timeout_ts, (const void *)sigmask, (size_t)sigsetsize);
}

/* sys_execveat_wrapper */
extern long sys_execveat(int dirfd, const char *pathname,
                          char *const argv[], char *const envp[], int flags);
static int64_t sys_execveat_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t argv,
                                     uint64_t envp, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_execveat((int)dirfd, (const char *)pathname,
                         (char *const *)argv, (char *const *)envp, (int)flags);
}

/* sys_preadv2_wrapper */
extern ssize_t sys_preadv2(int fd, const struct iovec *iov, int iovcnt,
                            int64_t offset, int flags);
static int64_t sys_preadv2_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                    uint64_t offset, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_preadv2((int)fd, (const struct iovec *)iov, (int)iovcnt,
                       (int64_t)offset, (int)flags);
}

/* sys_pwritev2_wrapper */
extern ssize_t sys_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                             int64_t offset, int flags);
static int64_t sys_pwritev2_wrapper(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                     uint64_t offset, uint64_t flags, uint64_t arg5) {
    (void)arg5;
    return sys_pwritev2((int)fd, (const struct iovec *)iov, (int)iovcnt,
                        (int64_t)offset, (int)flags);
}

/* sys_kcmp_wrapper */
extern long sys_kcmp(int pid1, int pid2, int type, unsigned long idx1, unsigned long idx2);
static int64_t sys_kcmp_wrapper(uint64_t pid1, uint64_t pid2, uint64_t type,
                                 uint64_t idx1, uint64_t idx2, uint64_t arg5) {
    (void)arg5;
    return sys_kcmp((int)pid1, (int)pid2, (int)type, (unsigned long)idx1, (unsigned long)idx2);
}

/* sys_seccomp_wrapper */
extern long sys_seccomp(unsigned int operation, unsigned int flags, const void *uargs);
static int64_t sys_seccomp_wrapper(uint64_t operation, uint64_t flags, uint64_t uargs,
                                    uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_seccomp((unsigned int)operation, (unsigned int)flags, (const void *)uargs);
}

/* sys_rt_sigqueueinfo_wrapper */
extern long sys_rt_sigqueueinfo(int tgid, int sig, const void *uinfo);
static int64_t sys_rt_sigqueueinfo_wrapper(uint64_t tgid, uint64_t sig, uint64_t uinfo,
                                            uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_rt_sigqueueinfo((int)tgid, (int)sig, (const void *)uinfo);
}

/* sys_rt_tgsigqueueinfo_wrapper */
extern long sys_rt_tgsigqueueinfo(int tgid, int tid, int sig, const void *uinfo);
static int64_t sys_rt_tgsigqueueinfo_wrapper(uint64_t tgid, uint64_t tid, uint64_t sig,
                                              uint64_t uinfo, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_rt_tgsigqueueinfo((int)tgid, (int)tid, (int)sig, (const void *)uinfo);
}

/* sys_recvmmsg_wrapper */
extern long sys_recvmmsg(int sockfd, void *msgvec, unsigned int vlen,
                         unsigned int flags, const struct timespec *timeout);
static int64_t sys_recvmmsg_wrapper(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t timeout, uint64_t arg5) {
    (void)arg5;
    return sys_recvmmsg((int)sockfd, (void *)msgvec, (unsigned int)vlen,
                        (unsigned int)flags, (const struct timespec *)timeout);
}

/* sys_sendmmsg_wrapper */
extern long sys_sendmmsg(int sockfd, void *msgvec, unsigned int vlen, unsigned int flags);
static int64_t sys_sendmmsg_wrapper(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_sendmmsg((int)sockfd, (void *)msgvec, (unsigned int)vlen, (unsigned int)flags);
}

/* sys_process_vm_readv_wrapper */
extern long sys_process_vm_readv(int pid, const void *lvec, unsigned long liovcnt,
                                  const void *rvec, unsigned long riovcnt, unsigned long flags);
static int64_t sys_process_vm_readv_wrapper(uint64_t pid, uint64_t lvec, uint64_t liovcnt,
                                             uint64_t rvec, uint64_t riovcnt, uint64_t flags) {
    return sys_process_vm_readv((int)pid, (const void *)lvec, (unsigned long)liovcnt,
                                 (const void *)rvec, (unsigned long)riovcnt, (unsigned long)flags);
}

/* sys_process_vm_writev_wrapper */
extern long sys_process_vm_writev(int pid, const void *lvec, unsigned long liovcnt,
                                   const void *rvec, unsigned long riovcnt, unsigned long flags);
static int64_t sys_process_vm_writev_wrapper(uint64_t pid, uint64_t lvec, uint64_t liovcnt,
                                              uint64_t rvec, uint64_t riovcnt, uint64_t flags) {
    return sys_process_vm_writev((int)pid, (const void *)lvec, (unsigned long)liovcnt,
                                  (const void *)rvec, (unsigned long)riovcnt, (unsigned long)flags);
}

/* sys_openat2_wrapper */
extern long sys_openat2(int dirfd, const char *path, const void *how, size_t usize);
static int64_t sys_openat2_wrapper(uint64_t dirfd, uint64_t path, uint64_t how,
                                    uint64_t usize, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_openat2((int)dirfd, (const char *)path, (const void *)how, (size_t)usize);
}

/* sys_pkey_mprotect_wrapper */
extern long sys_pkey_mprotect(void *addr, size_t len, int prot, int pkey);
static int64_t sys_pkey_mprotect_wrapper(uint64_t addr, uint64_t len, uint64_t prot,
                                          uint64_t pkey, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_pkey_mprotect((void *)addr, (size_t)len, (int)prot, (int)pkey);
}

/* sys_pkey_alloc_wrapper */
extern long sys_pkey_alloc(unsigned int flags, unsigned int access_rights);
static int64_t sys_pkey_alloc_wrapper(uint64_t flags, uint64_t access_rights,
                                       uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pkey_alloc((unsigned int)flags, (unsigned int)access_rights);
}

/* sys_pkey_free_wrapper */
extern long sys_pkey_free(int pkey);
static int64_t sys_pkey_free_wrapper(uint64_t pkey, uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_pkey_free((int)pkey);
}

/* sys_msgget_wrapper */
extern long sys_msgget(long key, int msgflg);
static int64_t sys_msgget_wrapper(uint64_t key, uint64_t msgflg,
                                   uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_msgget((long)key, (int)msgflg);
}

/* sys_msgsnd_wrapper */
extern long sys_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
static int64_t sys_msgsnd_wrapper(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                   uint64_t msgflg, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_msgsnd((int)msqid, (const void *)msgp, (size_t)msgsz, (int)msgflg);
}

/* sys_msgrcv_wrapper */
extern long sys_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
static int64_t sys_msgrcv_wrapper(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                   uint64_t msgtyp, uint64_t msgflg, uint64_t arg5) {
    (void)arg5;
    return sys_msgrcv((int)msqid, (void *)msgp, (size_t)msgsz, (long)msgtyp, (int)msgflg);
}

/* sys_msgctl_wrapper */
extern long sys_msgctl(int msqid, int cmd, void *buf);
static int64_t sys_msgctl_wrapper(uint64_t msqid, uint64_t cmd, uint64_t buf,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_msgctl((int)msqid, (int)cmd, (void *)buf);
}

/* sys_semget_wrapper */
extern long sys_semget(long key, int nsems, int semflg);
static int64_t sys_semget_wrapper(uint64_t key, uint64_t nsems, uint64_t semflg,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_semget((long)key, (int)nsems, (int)semflg);
}

/* sys_semop_wrapper */
extern long sys_semop(int semid, void *sops, unsigned int nsops);
static int64_t sys_semop_wrapper(uint64_t semid, uint64_t sops, uint64_t nsops,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_semop((int)semid, (void *)sops, (unsigned int)nsops);
}

/* sys_semctl_wrapper */
extern long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
static int64_t sys_semctl_wrapper(uint64_t semid, uint64_t semnum, uint64_t cmd,
                                   uint64_t arg, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_semctl((int)semid, (int)semnum, (int)cmd, (unsigned long)arg);
}

/* sys_semtimedop_wrapper */
extern long sys_semtimedop(int semid, void *sops, unsigned int nsops, const void *timeout);
static int64_t sys_semtimedop_wrapper(uint64_t semid, uint64_t sops, uint64_t nsops,
                                       uint64_t timeout, uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_semtimedop((int)semid, (void *)sops, (unsigned int)nsops, (const void *)timeout);
}

/* sys_shmget_wrapper */
extern long sys_shmget(long key, size_t size, int shmflg);
static int64_t sys_shmget_wrapper(uint64_t key, uint64_t size, uint64_t shmflg,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_shmget((long)key, (size_t)size, (int)shmflg);
}

/* sys_shmctl_wrapper */
extern long sys_shmctl(int shmid, int cmd, void *buf);
static int64_t sys_shmctl_wrapper(uint64_t shmid, uint64_t cmd, uint64_t buf,
                                   uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_shmctl((int)shmid, (int)cmd, (void *)buf);
}

/* sys_shmat_wrapper */
extern long sys_shmat(int shmid, const void *shmaddr, int shmflg);
static int64_t sys_shmat_wrapper(uint64_t shmid, uint64_t shmaddr, uint64_t shmflg,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg3; (void)arg4; (void)arg5;
    return sys_shmat((int)shmid, (const void *)shmaddr, (int)shmflg);
}

/* sys_shmdt_wrapper */
extern long sys_shmdt(const void *shmaddr);
static int64_t sys_shmdt_wrapper(uint64_t shmaddr, uint64_t arg1, uint64_t arg2,
                                  uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_shmdt((const void *)shmaddr);
}

/* sys_io_uring_setup_wrapper - io_uring setup (stub: returns ENOSYS) */
extern long sys_io_uring_setup(unsigned int entries, void *params);
static int64_t sys_io_uring_setup_wrapper(uint64_t entries, uint64_t params,
                                           uint64_t arg2, uint64_t arg3,
                                           uint64_t arg4, uint64_t arg5) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5;
    return sys_io_uring_setup((unsigned int)entries, (void *)params);
}

/* sys_io_uring_enter_wrapper - io_uring enter (stub: returns ENOSYS) */
extern long sys_io_uring_enter(unsigned int fd, unsigned int to_submit,
                                unsigned int min_complete, unsigned int flags,
                                const void *sig, size_t sigsz);
static int64_t sys_io_uring_enter_wrapper(uint64_t fd, uint64_t to_submit,
                                           uint64_t min_complete, uint64_t flags,
                                           uint64_t sig, uint64_t sigsz) {
    return sys_io_uring_enter((unsigned int)fd, (unsigned int)to_submit,
                               (unsigned int)min_complete, (unsigned int)flags,
                               (const void *)sig, (size_t)sigsz);
}

/* sys_io_uring_register_wrapper - io_uring register (stub: returns ENOSYS) */
extern long sys_io_uring_register(unsigned int fd, unsigned int opcode,
                                   void *arg, unsigned int nr_args);
static int64_t sys_io_uring_register_wrapper(uint64_t fd, uint64_t opcode,
                                              uint64_t arg, uint64_t nr_args,
                                              uint64_t arg4, uint64_t arg5) {
    (void)arg4; (void)arg5;
    return sys_io_uring_register((unsigned int)fd, (unsigned int)opcode,
                                  (void *)arg, (unsigned int)nr_args);
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
/* Extended attributes (xattr) - syscalls 5-16 */
#define __NR_setxattr        5
#define __NR_lsetxattr       6
#define __NR_fsetxattr       7
#define __NR_getxattr        8
#define __NR_lgetxattr       9
#define __NR_fgetxattr      10
#define __NR_listxattr      11
#define __NR_llistxattr     12
#define __NR_flistxattr     13
#define __NR_removexattr    14
#define __NR_lremovexattr   15
#define __NR_fremovexattr   16
/* File monitoring (inotify) - syscalls 26-28 */
#define __NR_inotify_init1      26
#define __NR_inotify_add_watch  27
#define __NR_inotify_rm_watch   28
#define __NR_eventfd2       19
#define __NR_epoll_create1  20
#define __NR_epoll_ctl      21
#define __NR_epoll_pwait    22
#define __NR_getcwd         17
#define __NR_dup            23
#define __NR_dup3           24
#define __NR_reboot             142
#define __NR_memfd_create       279
#define __NR_rt_sigtimedwait    137
#define __NR_sethostname        161
#define __NR_gettid         178
/* POSIX message queues (Linux ARM64: 180-185) */
#define __NR_mq_open         180
#define __NR_mq_unlink       181
#define __NR_mq_timedsend    182
#define __NR_mq_timedreceive 183
#define __NR_mq_notify       184
#define __NR_mq_getsetattr   185
#define __NR_setdomainname  162
#define __NR_getsockname    204
#define __NR_getpeername    205
#define __NR_sendmsg        211
#define __NR_recvmsg        212
#define __NR_sigsuspend     133
#define __NR_mremap         216
#define __NR_accept4        242
#define __NR_syncfs         267
#define __NR_renameat2      276
/* System V IPC (Linux ARM64: 186-197) */
#define __NR_msgget             186
#define __NR_msgctl             187
#define __NR_msgrcv             188
#define __NR_msgsnd             189
#define __NR_semget             190
#define __NR_semctl             191
#define __NR_semtimedop         192
#define __NR_semop              193
#define __NR_shmget             194
#define __NR_shmctl             195
#define __NR_shmat              196
#define __NR_shmdt              197
/* Socket extensions (Linux ARM64: 243, 269-271) */
#define __NR_recvmmsg           243
#define __NR_sendmmsg           269
#define __NR_process_vm_readv   270
#define __NR_process_vm_writev  271
/* clock_adjtime (Linux ARM64: 266), setns (268) */
#define __NR_clock_adjtime      266
#define __NR_setns              268
/* sched extended (Linux ARM64: 274-275; 273=finit_module) */
#define __NR_sched_setattr      274
#define __NR_sched_getattr      275
/* setfsuid/setfsgid (Linux ARM64: 151-152) */
#define __NR_setfsuid           151
#define __NR_setfsgid           152
/* Linux keyring (Linux ARM64: 217-219) */
#define __NR_add_key            217
#define __NR_request_key        218
#define __NR_keyctl             219
/* mlock2 (Linux ARM64: 284) */
#define __NR_mlock2             284
/* swapon/swapoff (Linux ARM64: 224-225) */
#define __NR_swapon             224
#define __NR_swapoff            225
/* execveat (Linux ARM64: 281) */
#define __NR_execveat           281
/* epoll_pwait2 (Linux ARM64: 441) */
#define __NR_epoll_pwait2       441
/* preadv2/pwritev2 (Linux ARM64: 286-287) */
#define __NR_preadv2            286
#define __NR_pwritev2           287
/* Memory protection keys (Linux ARM64: 288-290) */
#define __NR_pkey_mprotect      288
#define __NR_pkey_alloc         289
#define __NR_pkey_free          290
/* kcmp (Linux ARM64: 272), seccomp (277), rt_sigqueueinfo (138), rt_tgsigqueueinfo (240) */
#define __NR_kcmp               272
#define __NR_seccomp            277
#define __NR_rt_sigqueueinfo    138
#define __NR_rt_tgsigqueueinfo  240
/* pidfd and newer syscalls */
#define __NR_pidfd_send_signal  424
#define __NR_clone3             435
#define __NR_close_range        436
#define __NR_pidfd_open         434
#define __NR_pidfd_getfd        438
#define __NR_openat2            437
#define __NR_faccessat2         439
#define __NR_fcntl          25
#define __NR_ioctl          29
/* I/O priority - syscalls 30-31 */
#define __NR_ioprio_set     30
#define __NR_ioprio_get     31
#define __NR_flock          32
#define __NR_mknodat        33
#define __NR_mkdirat        34
#define __NR_unlinkat       35
#define __NR_symlinkat      36
#define __NR_linkat         37
#define __NR_renameat       38
/* Mount operations - syscalls 39-41 */
#define __NR_umount2        39
#define __NR_mount          40
#define __NR_pivot_root     41
#define __NR_statfs         43
#define __NR_fstatfs        44
#define __NR_truncate       45
#define __NR_ftruncate      46
#define __NR_fallocate      47
#define __NR_faccessat      48
#define __NR_chdir          49
#define __NR_fchdir         50
#define __NR_chroot         51
#define __NR_fchmod         52
#define __NR_fchmodat       53
#define __NR_fchownat       54
#define __NR_fchown         55
#define __NR_openat         56
#define __NR_close          57
#define __NR_vhangup        58
#define __NR_pipe2          59
#define __NR_quotactl       60
#define __NR_getdents64     61
#define __NR_lseek          62
#define __NR_read           63
#define __NR_write          64
#define __NR_readv          65
#define __NR_writev         66
#define __NR_pread64        67
#define __NR_pwrite64       68
#define __NR_preadv         69
#define __NR_pwritev        70
#define __NR_sendfile       71
#define __NR_pselect6       72
#define __NR_ppoll          73
#define __NR_signalfd4      74
/* Zero-copy I/O (splice family) - syscalls 75-77, 84 */
#define __NR_vmsplice       75
#define __NR_splice         76
#define __NR_tee            77
#define __NR_readlinkat     78
#define __NR_fstatat        79
#define __NR_fstat          80
#define __NR_sync           81
#define __NR_fsync          82
#define __NR_fdatasync      83
#define __NR_sync_file_range 84
#define __NR_timerfd_create 85
#define __NR_timerfd_settime 86
#define __NR_timerfd_gettime 87
#define __NR_utimensat      88
#define __NR_acct           89
/* Capabilities and process management - syscalls 90-92, 95-97 */
#define __NR_capget         90
#define __NR_capset         91
#define __NR_personality    92
#define __NR_exit           93
#define __NR_exit_group     94
#define __NR_waitid         95
#define __NR_set_tid_address 96
#define __NR_unshare        97
#define __NR_futex          98
#define __NR_set_robust_list 99
#define __NR_get_robust_list 100
#define __NR_nanosleep      101
#define __NR_getitimer      102
#define __NR_setitimer      103
#define __NR_timer_create   107
#define __NR_timer_gettime  108
#define __NR_timer_getoverrun 109
#define __NR_timer_settime  110
#define __NR_timer_delete   111
#define __NR_clock_settime  112
#define __NR_clock_gettime  113
#define __NR_clock_getres   114
#define __NR_clock_nanosleep 115
#define __NR_sched_setparam 118
#define __NR_sched_setscheduler 119
#define __NR_sched_getscheduler 120
#define __NR_sched_getparam 121
#define __NR_sched_yield    124
#define __NR_sched_get_priority_max 125
#define __NR_sched_get_priority_min 126
#define __NR_sched_rr_get_interval 127
#define __NR_getcpu         168
#define __NR_readahead      213
#define __NR_socketpair     199
#define __NR_getgroups      158
#define __NR_setgroups      159
#define __NR_kill           129
#define __NR_tkill          130
#define __NR_tgkill         131
#define __NR_sigaltstack    132
#define __NR_rt_sigaction   134
#define __NR_rt_sigprocmask 135
#define __NR_rt_sigpending  136
#define __NR_rt_sigsuspend  133
#define __NR_rt_sigreturn   139
#define __NR_setpriority    140
#define __NR_getpriority    141
#define __NR_uname          160
#define __NR_getpid         172
#define __NR_getppid        173
#define __NR_socket         198
#define __NR_bind           200
#define __NR_listen         201
#define __NR_accept         202
#define __NR_connect        203
#define __NR_sendto         206
#define __NR_recvfrom       207
#define __NR_setsockopt     208
#define __NR_getsockopt     209
#define __NR_setregid       143
#define __NR_setgid         144
#define __NR_setreuid       145
#define __NR_setuid         146
#define __NR_setresuid      147
#define __NR_getresuid      148
#define __NR_setresgid      149
#define __NR_getresgid      150
#define __NR_times          153
#define __NR_setpgid        154
#define __NR_getpgid        155
#define __NR_getsid         156
#define __NR_setsid         157
#define __NR_getrlimit      163
#define __NR_setrlimit      164
#define __NR_getrusage      165
#define __NR_umask          166
#define __NR_prctl          167
#define __NR_gettimeofday   169
#define __NR_settimeofday   170
#define __NR_adjtimex       171
#define __NR_getuid         174
#define __NR_geteuid        175
#define __NR_getgid         176
#define __NR_getegid        177
#define __NR_sysinfo        179
#define __NR_shutdown       210
#define __NR_brk            214
#define __NR_munmap         215
#define __NR_clone          220
#define __NR_execve         221
#define __NR_mmap           222
#define __NR_mprotect       226
#define __NR_msync          227
#define __NR_mlock          228
#define __NR_munlock        229
#define __NR_mlockall       230
#define __NR_munlockall     231
#define __NR_mincore        232
#define __NR_madvise        233
/* NUMA memory policy (Linux aarch64: 235=mbind, 236=get_mempolicy, 237=set_mempolicy) */
#define __NR_mbind          235
#define __NR_get_mempolicy  236
#define __NR_set_mempolicy  237
#define __NR_getrandom      278
#define __NR_syslog     116
#define __NR_sched_setaffinity  122
#define __NR_sched_getaffinity  123
#define __NR_fadvise64     223
#define __NR_membarrier    283
#define __NR_copy_file_range 285
#define __NR_rseq          293
#define __NR_statx         291
#define __NR_wait4          260  /* wait4/waitpid */
#define __NR_prlimit64      261

/* FIPC (Futura IPC) syscalls - Futura-specific range 401-406 */
#define __NR_fipc_create    401
#define __NR_fipc_send      402
#define __NR_fipc_recv      403
#define __NR_fipc_close     404
#define __NR_fipc_poll      405
#define __NR_fipc_connect   406

/* io_uring (Linux ARM64: 425-427) */
#define __NR_io_uring_setup     425
#define __NR_io_uring_enter     426
#define __NR_io_uring_register  427

/* Maximum syscall number — must exceed highest registered number (epoll_pwait2=441) */
#define MAX_SYSCALL         450

/* Syscall table - sparse array indexed by syscall number */
/* Syscall table - initialized at runtime to avoid ARM64 relocation issues */
static struct syscall_entry syscall_table[MAX_SYSCALL];
static bool syscall_table_initialized = false;

/* Stub that returns -ENOSYS */
static int64_t sys_enosys_stub(uint64_t a1, uint64_t a2, uint64_t a3,
                                uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return -ENOSYS;
}

/* clone3 wrapper — translates struct clone_args to fork or clone_thread */
static int64_t sys_clone3_wrapper(uint64_t cl_args, uint64_t size, uint64_t a3,
                                   uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_clone3(const void *uargs, size_t size);
    return sys_clone3((const void *)(uintptr_t)cl_args, (size_t)size);
}

/* mseal wrapper — no-op success; glibc 2.38+ seals its own segments */
static int64_t sys_mseal_wrapper(uint64_t addr, uint64_t len, uint64_t flags,
                                  uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_mseal(void *addr, size_t len, unsigned long flags);
    return sys_mseal((void *)(uintptr_t)addr, (size_t)len, (unsigned long)flags);
}

/* fchmodat2 wrapper — delegate to sys_fchmodat */
static int64_t sys_fchmodat2_wrapper(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                      uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_fchmodat2(int dirfd, const char *pathname, unsigned int mode,
                               unsigned int flags);
    return sys_fchmodat2((int)dirfd, (const char *)(uintptr_t)pathname,
                          (unsigned int)mode, (unsigned int)flags);
}

/* landlock wrappers — Landlock LSM sandbox (Linux 5.13+) */
static int64_t sys_landlock_create_ruleset_wrapper(uint64_t attr, uint64_t size,
                                                    uint64_t flags, uint64_t a4,
                                                    uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_landlock_create_ruleset(const void *attr, size_t size, uint32_t flags);
    return sys_landlock_create_ruleset((const void *)(uintptr_t)attr, (size_t)size,
                                       (uint32_t)flags);
}
static int64_t sys_landlock_add_rule_wrapper(uint64_t ruleset_fd, uint64_t rule_type,
                                              uint64_t rule_attr, uint64_t flags,
                                              uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_landlock_add_rule(int ruleset_fd, unsigned int rule_type,
                                      const void *rule_attr, uint32_t flags);
    return sys_landlock_add_rule((int)ruleset_fd, (unsigned int)rule_type,
                                  (const void *)(uintptr_t)rule_attr, (uint32_t)flags);
}
static int64_t sys_landlock_restrict_self_wrapper(uint64_t ruleset_fd, uint64_t flags,
                                                   uint64_t a3, uint64_t a4,
                                                   uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_landlock_restrict_self(int ruleset_fd, uint32_t flags);
    return sys_landlock_restrict_self((int)ruleset_fd, (uint32_t)flags);
}

/* memfd_secret wrapper — Linux 5.14+ */
static int64_t sys_memfd_secret_wrapper(uint64_t flags, uint64_t a2, uint64_t a3,
                                         uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_memfd_secret(unsigned int flags);
    return sys_memfd_secret((unsigned int)flags);
}

/* futex_waitv wrapper — Linux 5.16+ multi-futex wait (Wine/Proton) */
static int64_t sys_futex_waitv_wrapper(uint64_t waiters, uint64_t nr_futexes,
                                        uint64_t flags, uint64_t timeout,
                                        uint64_t clockid, uint64_t a6) {
    (void)a6;
    extern long sys_futex_waitv(const void *waiters, unsigned int nr_futexes,
                                unsigned int flags, const void *timeout,
                                int32_t clockid);
    return sys_futex_waitv((const void *)(uintptr_t)waiters, (unsigned int)nr_futexes,
                            (unsigned int)flags, (const void *)(uintptr_t)timeout,
                            (int32_t)clockid);
}

/* process_madvise wrapper — Linux 5.10+ */
static int64_t sys_process_madvise_wrapper(uint64_t pidfd, uint64_t iovec, uint64_t vlen,
                                            uint64_t advice, uint64_t flags, uint64_t a6) {
    (void)a6;
    extern long sys_process_madvise(int pidfd, const void *iovec, unsigned long vlen,
                                     int advice, unsigned int flags);
    return sys_process_madvise((int)pidfd, (const void *)(uintptr_t)iovec,
                                (unsigned long)vlen, (int)advice, (unsigned int)flags);
}

/* cachestat wrapper — Linux 6.5+ */
static int64_t sys_cachestat_wrapper(uint64_t fd, uint64_t cachestat_range,
                                      uint64_t cachestat, uint64_t flags,
                                      uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_cachestat(unsigned int fd, const void *cachestat_range,
                               void *cachestat, unsigned int flags);
    return sys_cachestat((unsigned int)fd, (const void *)(uintptr_t)cachestat_range,
                          (void *)(uintptr_t)cachestat, (unsigned int)flags);
}

/* set_mempolicy_home_node wrapper — Linux 5.17+ (NUMA, returns ENOSYS) */
static int64_t sys_set_mempolicy_home_node_wrapper(uint64_t start, uint64_t len,
                                                    uint64_t home_node, uint64_t flags,
                                                    uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_set_mempolicy_home_node(unsigned long start, unsigned long len,
                                             unsigned long home_node, unsigned long flags);
    return sys_set_mempolicy_home_node((unsigned long)start, (unsigned long)len,
                                        (unsigned long)home_node, (unsigned long)flags);
}

/* Initialize syscall table at runtime to avoid ARM64 relocation issues */
/* x86_64 compat: rename(old, new) */
int64_t sys_rename_compat(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    (void)c;(void)d;(void)e;(void)f;
    if (a == 0 || a >= 0xFFFFFF8000000000ULL) return -14;
    if (b == 0 || b >= 0xFFFFFF8000000000ULL) return -14;
    extern long sys_rename(const char *, const char *);
    return (int64_t)sys_rename((const char *)a, (const char *)b);
}

static void arm64_syscall_table_init(void) {
    if (syscall_table_initialized) {
        return;
    }

    /* Extended attributes (xattr) - syscalls 5-16 */
    syscall_table[__NR_setxattr].handler = (syscall_fn_t)sys_setxattr_wrapper;
    syscall_table[__NR_setxattr].name = "setxattr";
    syscall_table[__NR_lsetxattr].handler = (syscall_fn_t)sys_lsetxattr_wrapper;
    syscall_table[__NR_lsetxattr].name = "lsetxattr";
    syscall_table[__NR_fsetxattr].handler = (syscall_fn_t)sys_fsetxattr_wrapper;
    syscall_table[__NR_fsetxattr].name = "fsetxattr";
    syscall_table[__NR_getxattr].handler = (syscall_fn_t)sys_getxattr_wrapper;
    syscall_table[__NR_getxattr].name = "getxattr";
    syscall_table[__NR_lgetxattr].handler = (syscall_fn_t)sys_lgetxattr_wrapper;
    syscall_table[__NR_lgetxattr].name = "lgetxattr";
    syscall_table[__NR_fgetxattr].handler = (syscall_fn_t)sys_fgetxattr_wrapper;
    syscall_table[__NR_fgetxattr].name = "fgetxattr";
    syscall_table[__NR_listxattr].handler = (syscall_fn_t)sys_listxattr_wrapper;
    syscall_table[__NR_listxattr].name = "listxattr";
    syscall_table[__NR_llistxattr].handler = (syscall_fn_t)sys_llistxattr_wrapper;
    syscall_table[__NR_llistxattr].name = "llistxattr";
    syscall_table[__NR_flistxattr].handler = (syscall_fn_t)sys_flistxattr_wrapper;
    syscall_table[__NR_flistxattr].name = "flistxattr";
    syscall_table[__NR_removexattr].handler = (syscall_fn_t)sys_removexattr_wrapper;
    syscall_table[__NR_removexattr].name = "removexattr";
    syscall_table[__NR_lremovexattr].handler = (syscall_fn_t)sys_lremovexattr_wrapper;
    syscall_table[__NR_lremovexattr].name = "lremovexattr";
    syscall_table[__NR_fremovexattr].handler = (syscall_fn_t)sys_fremovexattr_wrapper;
    syscall_table[__NR_fremovexattr].name = "fremovexattr";
    syscall_table[__NR_eventfd2].handler = (syscall_fn_t)sys_eventfd2_wrapper;
    syscall_table[__NR_eventfd2].name = "eventfd2";
    syscall_table[__NR_epoll_create1].handler = (syscall_fn_t)sys_epoll_create1_wrapper;
    syscall_table[__NR_epoll_create1].name = "epoll_create1";
    syscall_table[__NR_epoll_ctl].handler = (syscall_fn_t)sys_epoll_ctl_wrapper;
    syscall_table[__NR_epoll_ctl].name = "epoll_ctl";
    syscall_table[__NR_epoll_pwait].handler = (syscall_fn_t)sys_epoll_pwait_wrapper;
    syscall_table[__NR_epoll_pwait].name = "epoll_pwait";
    syscall_table[__NR_getcwd].handler = (syscall_fn_t)sys_getcwd_wrapper;
    syscall_table[__NR_getcwd].name = "getcwd";
    syscall_table[__NR_dup].handler = (syscall_fn_t)sys_dup_wrapper;
    syscall_table[__NR_dup].name = "dup";
    syscall_table[__NR_dup3].handler = (syscall_fn_t)sys_dup3_wrapper;
    syscall_table[__NR_dup3].name = "dup3";
    syscall_table[__NR_fcntl].handler = (syscall_fn_t)sys_fcntl_wrapper;
    syscall_table[__NR_fcntl].name = "fcntl";
    /* File monitoring (inotify) - syscalls 26-28 */
    syscall_table[__NR_inotify_init1].handler = (syscall_fn_t)sys_inotify_init1_wrapper;
    syscall_table[__NR_inotify_init1].name = "inotify_init1";
    syscall_table[__NR_inotify_add_watch].handler = (syscall_fn_t)sys_inotify_add_watch_wrapper;
    syscall_table[__NR_inotify_add_watch].name = "inotify_add_watch";
    syscall_table[__NR_inotify_rm_watch].handler = (syscall_fn_t)sys_inotify_rm_watch_wrapper;
    syscall_table[__NR_inotify_rm_watch].name = "inotify_rm_watch";
    syscall_table[__NR_ioctl].handler = (syscall_fn_t)sys_ioctl_wrapper;
    syscall_table[__NR_ioctl].name = "ioctl";
    /* I/O priority - syscalls 30-31 */
    syscall_table[__NR_ioprio_set].handler = (syscall_fn_t)sys_ioprio_set_wrapper;
    syscall_table[__NR_ioprio_set].name = "ioprio_set";
    syscall_table[__NR_ioprio_get].handler = (syscall_fn_t)sys_ioprio_get_wrapper;
    syscall_table[__NR_ioprio_get].name = "ioprio_get";
    /* File locking and special files - syscalls 32-33 */
    syscall_table[__NR_flock].handler = (syscall_fn_t)sys_flock_wrapper;
    syscall_table[__NR_flock].name = "flock";
    syscall_table[__NR_mknodat].handler = (syscall_fn_t)sys_mknodat_wrapper;
    syscall_table[__NR_mknodat].name = "mknodat";
    syscall_table[__NR_mkdirat].handler = (syscall_fn_t)sys_mkdirat_wrapper;
    syscall_table[__NR_mkdirat].name = "mkdirat";
    syscall_table[__NR_unlinkat].handler = (syscall_fn_t)sys_unlinkat_wrapper;
    syscall_table[__NR_unlinkat].name = "unlinkat";
    syscall_table[__NR_symlinkat].handler = (syscall_fn_t)sys_symlinkat_wrapper;
    syscall_table[__NR_symlinkat].name = "symlinkat";
    syscall_table[__NR_linkat].handler = (syscall_fn_t)sys_linkat_wrapper;
    syscall_table[__NR_linkat].name = "linkat";
    syscall_table[__NR_renameat].handler = (syscall_fn_t)sys_renameat_wrapper;
    syscall_table[__NR_renameat].name = "renameat";
    /* Mount operations - syscalls 39-41 */
    syscall_table[__NR_umount2].handler = (syscall_fn_t)sys_umount2_wrapper;
    syscall_table[__NR_umount2].name = "umount2";
    syscall_table[__NR_mount].handler = (syscall_fn_t)sys_mount_wrapper;
    syscall_table[__NR_mount].name = "mount";
    syscall_table[__NR_pivot_root].handler = (syscall_fn_t)sys_pivot_root_wrapper;
    syscall_table[__NR_pivot_root].name = "pivot_root";
    syscall_table[__NR_statfs].handler = (syscall_fn_t)sys_statfs_wrapper;
    syscall_table[__NR_statfs].name = "statfs";
    syscall_table[__NR_fstatfs].handler = (syscall_fn_t)sys_fstatfs_wrapper;
    syscall_table[__NR_fstatfs].name = "fstatfs";
    syscall_table[__NR_truncate].handler = (syscall_fn_t)sys_truncate_wrapper;
    syscall_table[__NR_truncate].name = "truncate";
    syscall_table[__NR_ftruncate].handler = (syscall_fn_t)sys_ftruncate_wrapper;
    syscall_table[__NR_ftruncate].name = "ftruncate";
    syscall_table[__NR_fallocate].handler = (syscall_fn_t)sys_fallocate_wrapper;
    syscall_table[__NR_fallocate].name = "fallocate";
    syscall_table[__NR_faccessat].handler = (syscall_fn_t)sys_faccessat_wrapper;
    syscall_table[__NR_faccessat].name = "faccessat";
    syscall_table[__NR_chdir].handler = (syscall_fn_t)sys_chdir_wrapper;
    syscall_table[__NR_chdir].name = "chdir";
    syscall_table[__NR_fchdir].handler = (syscall_fn_t)sys_fchdir_wrapper;
    syscall_table[__NR_fchdir].name = "fchdir";
    syscall_table[__NR_chroot].handler = (syscall_fn_t)sys_chroot_wrapper;
    syscall_table[__NR_chroot].name = "chroot";
    syscall_table[__NR_fchmod].handler = (syscall_fn_t)sys_fchmod_wrapper;
    syscall_table[__NR_fchmod].name = "fchmod";
    syscall_table[__NR_fchmodat].handler = (syscall_fn_t)sys_fchmodat_wrapper;
    syscall_table[__NR_fchmodat].name = "fchmodat";
    syscall_table[__NR_fchownat].handler = (syscall_fn_t)sys_fchownat_wrapper;
    syscall_table[__NR_fchownat].name = "fchownat";
    syscall_table[__NR_fchown].handler = (syscall_fn_t)sys_fchown_wrapper;
    syscall_table[__NR_fchown].name = "fchown";
    syscall_table[__NR_openat].handler = (syscall_fn_t)sys_openat_wrapper;
    syscall_table[__NR_openat].name = "openat";
    syscall_table[__NR_close].handler = (syscall_fn_t)sys_close_wrapper;
    syscall_table[__NR_close].name = "close";
    syscall_table[__NR_vhangup].handler = (syscall_fn_t)sys_vhangup_wrapper;
    syscall_table[__NR_vhangup].name = "vhangup";
    syscall_table[__NR_pipe2].handler = (syscall_fn_t)sys_pipe2_wrapper;
    syscall_table[__NR_pipe2].name = "pipe2";
    syscall_table[__NR_quotactl].handler = (syscall_fn_t)sys_quotactl_wrapper;
    syscall_table[__NR_quotactl].name = "quotactl";
    syscall_table[__NR_getdents64].handler = (syscall_fn_t)sys_getdents64_wrapper;
    syscall_table[__NR_getdents64].name = "getdents64";
    syscall_table[__NR_lseek].handler = (syscall_fn_t)sys_lseek_wrapper;
    syscall_table[__NR_lseek].name = "lseek";
    syscall_table[__NR_read].handler = (syscall_fn_t)sys_read_wrapper;
    syscall_table[__NR_read].name = "read";
    syscall_table[__NR_write].handler = (syscall_fn_t)sys_write_wrapper;
    syscall_table[__NR_write].name = "write";
    syscall_table[__NR_readv].handler = (syscall_fn_t)sys_readv_wrapper;
    syscall_table[__NR_readv].name = "readv";
    syscall_table[__NR_writev].handler = (syscall_fn_t)sys_writev_wrapper;
    syscall_table[__NR_writev].name = "writev";
    syscall_table[__NR_pread64].handler = (syscall_fn_t)sys_pread64_wrapper;
    syscall_table[__NR_pread64].name = "pread64";
    syscall_table[__NR_pwrite64].handler = (syscall_fn_t)sys_pwrite64_wrapper;
    syscall_table[__NR_pwrite64].name = "pwrite64";
    syscall_table[__NR_preadv].handler = (syscall_fn_t)sys_preadv_wrapper;
    syscall_table[__NR_preadv].name = "preadv";
    syscall_table[__NR_pwritev].handler = (syscall_fn_t)sys_pwritev_wrapper;
    syscall_table[__NR_pwritev].name = "pwritev";
    syscall_table[__NR_sendfile].handler = (syscall_fn_t)sys_sendfile_wrapper;
    syscall_table[__NR_sendfile].name = "sendfile";
    syscall_table[__NR_pselect6].handler = (syscall_fn_t)sys_pselect6_wrapper;
    syscall_table[__NR_pselect6].name = "pselect6";
    syscall_table[__NR_ppoll].handler = (syscall_fn_t)sys_ppoll_wrapper;
    syscall_table[__NR_ppoll].name = "ppoll";
    syscall_table[__NR_signalfd4].handler = (syscall_fn_t)sys_signalfd4_wrapper;
    syscall_table[__NR_signalfd4].name = "signalfd4";
    /* Zero-copy I/O (splice family) - syscalls 75-77 */
    syscall_table[__NR_vmsplice].handler = (syscall_fn_t)sys_vmsplice_wrapper;
    syscall_table[__NR_vmsplice].name = "vmsplice";
    syscall_table[__NR_splice].handler = (syscall_fn_t)sys_splice_wrapper;
    syscall_table[__NR_splice].name = "splice";
    syscall_table[__NR_tee].handler = (syscall_fn_t)sys_tee_wrapper;
    syscall_table[__NR_tee].name = "tee";
    syscall_table[__NR_readlinkat].handler = (syscall_fn_t)sys_readlinkat_wrapper;
    syscall_table[__NR_readlinkat].name = "readlinkat";
    syscall_table[__NR_fstatat].handler = (syscall_fn_t)sys_fstatat_wrapper;
    syscall_table[__NR_fstatat].name = "fstatat";
    syscall_table[__NR_fstat].handler = (syscall_fn_t)sys_fstat_wrapper;
    syscall_table[__NR_fstat].name = "fstat";
    syscall_table[__NR_sync].handler = (syscall_fn_t)sys_sync_wrapper;
    syscall_table[__NR_sync].name = "sync";
    syscall_table[__NR_fsync].handler = (syscall_fn_t)sys_fsync_wrapper;
    syscall_table[__NR_fsync].name = "fsync";
    syscall_table[__NR_fdatasync].handler = (syscall_fn_t)sys_fdatasync_wrapper;
    syscall_table[__NR_fdatasync].name = "fdatasync";
    syscall_table[__NR_sync_file_range].handler = (syscall_fn_t)sys_sync_file_range_wrapper;
    syscall_table[__NR_sync_file_range].name = "sync_file_range";
    syscall_table[__NR_timerfd_create].handler = (syscall_fn_t)sys_timerfd_create_wrapper;
    syscall_table[__NR_timerfd_create].name = "timerfd_create";
    syscall_table[__NR_timerfd_settime].handler = (syscall_fn_t)sys_timerfd_settime_wrapper;
    syscall_table[__NR_timerfd_settime].name = "timerfd_settime";
    syscall_table[__NR_timerfd_gettime].handler = (syscall_fn_t)sys_timerfd_gettime_wrapper;
    syscall_table[__NR_timerfd_gettime].name = "timerfd_gettime";
    syscall_table[__NR_utimensat].handler = (syscall_fn_t)sys_utimensat_wrapper;
    syscall_table[__NR_utimensat].name = "utimensat";
    syscall_table[__NR_acct].handler = (syscall_fn_t)sys_acct_wrapper;
    syscall_table[__NR_acct].name = "acct";
    /* Capabilities and process management - syscalls 90-92, 95-97 */
    syscall_table[__NR_capget].handler = (syscall_fn_t)sys_capget_wrapper;
    syscall_table[__NR_capget].name = "capget";
    syscall_table[__NR_capset].handler = (syscall_fn_t)sys_capset_wrapper;
    syscall_table[__NR_capset].name = "capset";
    syscall_table[__NR_personality].handler = (syscall_fn_t)sys_personality_wrapper;
    syscall_table[__NR_personality].name = "personality";
    syscall_table[__NR_prctl].handler = (syscall_fn_t)sys_prctl_wrapper;
    syscall_table[__NR_prctl].name = "prctl";
    syscall_table[__NR_getrandom].handler = (syscall_fn_t)sys_getrandom_wrapper;
    syscall_table[__NR_getrandom].name = "getrandom";
    syscall_table[__NR_membarrier].handler = (syscall_fn_t)sys_membarrier_wrapper;
    syscall_table[__NR_membarrier].name = "membarrier";
    syscall_table[__NR_copy_file_range].handler = (syscall_fn_t)sys_copy_file_range_wrapper;
    syscall_table[__NR_copy_file_range].name = "copy_file_range";
    syscall_table[__NR_rseq].handler = (syscall_fn_t)sys_rseq_wrapper;
    syscall_table[__NR_rseq].name = "rseq";
    syscall_table[__NR_statx].handler = (syscall_fn_t)sys_statx_wrapper;
    syscall_table[__NR_statx].name = "statx";
    syscall_table[__NR_syslog].handler = (syscall_fn_t)sys_syslog_wrapper;
    syscall_table[__NR_syslog].name = "syslog";
    syscall_table[__NR_fadvise64].handler = (syscall_fn_t)sys_fadvise64_wrapper;
    syscall_table[__NR_fadvise64].name = "fadvise64";
    syscall_table[__NR_sched_setaffinity].handler = (syscall_fn_t)sys_sched_setaffinity_wrapper;
    syscall_table[__NR_sched_setaffinity].name = "sched_setaffinity";
    syscall_table[__NR_sched_getaffinity].handler = (syscall_fn_t)sys_sched_getaffinity_wrapper;
    syscall_table[__NR_sched_getaffinity].name = "sched_getaffinity";
    syscall_table[__NR_exit].handler = (syscall_fn_t)sys_exit;
    syscall_table[__NR_exit].name = "exit";
    syscall_table[__NR_exit_group].handler = (syscall_fn_t)sys_exit_group_wrapper;
    syscall_table[__NR_exit_group].name = "exit_group";
    syscall_table[__NR_waitid].handler = (syscall_fn_t)sys_waitid_wrapper;
    syscall_table[__NR_waitid].name = "waitid";
    syscall_table[__NR_set_tid_address].handler = (syscall_fn_t)sys_set_tid_address_wrapper;
    syscall_table[__NR_set_tid_address].name = "set_tid_address";
    syscall_table[__NR_unshare].handler = (syscall_fn_t)sys_unshare_wrapper;
    syscall_table[__NR_unshare].name = "unshare";
    syscall_table[__NR_futex].handler = (syscall_fn_t)sys_futex_wrapper;
    syscall_table[__NR_futex].name = "futex";
    syscall_table[__NR_set_robust_list].handler = (syscall_fn_t)sys_set_robust_list_wrapper;
    syscall_table[__NR_set_robust_list].name = "set_robust_list";
    syscall_table[__NR_get_robust_list].handler = (syscall_fn_t)sys_get_robust_list_wrapper;
    syscall_table[__NR_get_robust_list].name = "get_robust_list";
    syscall_table[__NR_nanosleep].handler = (syscall_fn_t)sys_nanosleep_wrapper;
    syscall_table[__NR_nanosleep].name = "nanosleep";
    syscall_table[__NR_getitimer].handler = (syscall_fn_t)sys_getitimer_wrapper;
    syscall_table[__NR_getitimer].name = "getitimer";
    syscall_table[__NR_setitimer].handler = (syscall_fn_t)sys_setitimer_wrapper;
    syscall_table[__NR_setitimer].name = "setitimer";
    syscall_table[__NR_timer_create].handler = (syscall_fn_t)sys_timer_create_wrapper;
    syscall_table[__NR_timer_create].name = "timer_create";
    syscall_table[__NR_timer_gettime].handler = (syscall_fn_t)sys_timer_gettime_wrapper;
    syscall_table[__NR_timer_gettime].name = "timer_gettime";
    syscall_table[__NR_timer_getoverrun].handler = (syscall_fn_t)sys_timer_getoverrun_wrapper;
    syscall_table[__NR_timer_getoverrun].name = "timer_getoverrun";
    syscall_table[__NR_timer_settime].handler = (syscall_fn_t)sys_timer_settime_wrapper;
    syscall_table[__NR_timer_settime].name = "timer_settime";
    syscall_table[__NR_timer_delete].handler = (syscall_fn_t)sys_timer_delete_wrapper;
    syscall_table[__NR_timer_delete].name = "timer_delete";
    syscall_table[__NR_clock_settime].handler = (syscall_fn_t)sys_clock_settime_wrapper;
    syscall_table[__NR_clock_settime].name = "clock_settime";
    syscall_table[__NR_clock_gettime].handler = (syscall_fn_t)sys_clock_gettime;
    syscall_table[__NR_clock_gettime].name = "clock_gettime";
    syscall_table[__NR_clock_getres].handler = (syscall_fn_t)sys_clock_getres_wrapper;
    syscall_table[__NR_clock_getres].name = "clock_getres";
    syscall_table[__NR_clock_nanosleep].handler = (syscall_fn_t)sys_clock_nanosleep_wrapper;
    syscall_table[__NR_clock_nanosleep].name = "clock_nanosleep";
    syscall_table[__NR_sched_setparam].handler = (syscall_fn_t)sys_sched_setparam_wrapper;
    syscall_table[__NR_sched_setparam].name = "sched_setparam";
    syscall_table[__NR_sched_setscheduler].handler = (syscall_fn_t)sys_sched_setscheduler_wrapper;
    syscall_table[__NR_sched_setscheduler].name = "sched_setscheduler";
    syscall_table[__NR_sched_getscheduler].handler = (syscall_fn_t)sys_sched_getscheduler_wrapper;
    syscall_table[__NR_sched_getscheduler].name = "sched_getscheduler";
    syscall_table[__NR_sched_getparam].handler = (syscall_fn_t)sys_sched_getparam_wrapper;
    syscall_table[__NR_sched_getparam].name = "sched_getparam";
    syscall_table[__NR_sched_yield].handler = (syscall_fn_t)sys_sched_yield_wrapper;
    syscall_table[__NR_sched_yield].name = "sched_yield";
    syscall_table[__NR_sched_get_priority_max].handler = (syscall_fn_t)sys_sched_get_priority_max_wrapper;
    syscall_table[__NR_sched_get_priority_max].name = "sched_get_priority_max";
    syscall_table[__NR_sched_get_priority_min].handler = (syscall_fn_t)sys_sched_get_priority_min_wrapper;
    syscall_table[__NR_sched_get_priority_min].name = "sched_get_priority_min";
    syscall_table[__NR_sched_rr_get_interval].handler = (syscall_fn_t)sys_sched_rr_get_interval_wrapper;
    syscall_table[__NR_sched_rr_get_interval].name = "sched_rr_get_interval";
    syscall_table[__NR_getcpu].handler = (syscall_fn_t)sys_getcpu_wrapper;
    syscall_table[__NR_getcpu].name = "getcpu";
    syscall_table[__NR_readahead].handler = (syscall_fn_t)sys_readahead_wrapper;
    syscall_table[__NR_readahead].name = "readahead";
    syscall_table[__NR_socketpair].handler = (syscall_fn_t)sys_socketpair_wrapper;
    syscall_table[__NR_socketpair].name = "socketpair";
    syscall_table[__NR_renameat2].handler = (syscall_fn_t)sys_renameat2_wrapper;
    syscall_table[__NR_renameat2].name = "renameat2";
    /* clone3: fork/thread dispatch via struct clone_args */
    syscall_table[__NR_clone3].handler = (syscall_fn_t)sys_clone3_wrapper;
    syscall_table[__NR_clone3].name = "clone3";
    syscall_table[__NR_close_range].handler = (syscall_fn_t)sys_close_range_wrapper;
    syscall_table[__NR_close_range].name = "close_range";
    /* faccessat2 (439) = same as faccessat since our wrapper already passes flags */
    syscall_table[__NR_faccessat2].handler = (syscall_fn_t)sys_faccessat_wrapper;
    syscall_table[__NR_faccessat2].name = "faccessat2";
    /* pidfd syscalls (Linux 5.2+/5.6+) */
    syscall_table[__NR_pidfd_open].handler = (syscall_fn_t)sys_pidfd_open_wrapper;
    syscall_table[__NR_pidfd_open].name = "pidfd_open";
    syscall_table[__NR_pidfd_send_signal].handler = (syscall_fn_t)sys_pidfd_send_signal_wrapper;
    syscall_table[__NR_pidfd_send_signal].name = "pidfd_send_signal";
    syscall_table[__NR_pidfd_getfd].handler = (syscall_fn_t)sys_pidfd_getfd_wrapper;
    syscall_table[__NR_pidfd_getfd].name = "pidfd_getfd";
    /* Note: sigsuspend does not exist as a separate ARM64 syscall;
     * slot 133 is rt_sigsuspend (registered below in the rt_sig* block) */
    syscall_table[__NR_mremap].handler = (syscall_fn_t)sys_mremap_wrapper;
    syscall_table[__NR_mremap].name = "mremap";
    syscall_table[__NR_sendmsg].handler = (syscall_fn_t)sys_sendmsg_wrapper;
    syscall_table[__NR_sendmsg].name = "sendmsg";
    syscall_table[__NR_recvmsg].handler = (syscall_fn_t)sys_recvmsg_wrapper;
    syscall_table[__NR_recvmsg].name = "recvmsg";
    syscall_table[__NR_getsockname].handler = (syscall_fn_t)sys_getsockname_wrapper;
    syscall_table[__NR_getsockname].name = "getsockname";
    syscall_table[__NR_getpeername].handler = (syscall_fn_t)sys_getpeername_wrapper;
    syscall_table[__NR_getpeername].name = "getpeername";
    syscall_table[__NR_accept4].handler = (syscall_fn_t)sys_accept4_wrapper;
    syscall_table[__NR_accept4].name = "accept4";
    syscall_table[__NR_syncfs].handler = (syscall_fn_t)sys_syncfs_wrapper;
    syscall_table[__NR_syncfs].name = "syncfs";
    syscall_table[__NR_gettid].handler = (syscall_fn_t)sys_gettid_wrapper;
    syscall_table[__NR_gettid].name = "gettid";
    syscall_table[__NR_reboot].handler = (syscall_fn_t)sys_reboot_wrapper;
    syscall_table[__NR_reboot].name = "reboot";
    syscall_table[__NR_memfd_create].handler = (syscall_fn_t)sys_memfd_create_wrapper;
    syscall_table[__NR_memfd_create].name = "memfd_create";
    syscall_table[__NR_rt_sigtimedwait].handler = (syscall_fn_t)sys_rt_sigtimedwait_wrapper;
    syscall_table[__NR_rt_sigtimedwait].name = "rt_sigtimedwait";
    syscall_table[__NR_sethostname].handler = (syscall_fn_t)sys_sethostname_wrapper;
    syscall_table[__NR_sethostname].name = "sethostname";
    syscall_table[__NR_setdomainname].handler = (syscall_fn_t)sys_setdomainname_wrapper;
    syscall_table[__NR_setdomainname].name = "setdomainname";
    syscall_table[__NR_getgroups].handler = (syscall_fn_t)sys_getgroups_wrapper;
    syscall_table[__NR_getgroups].name = "getgroups";
    syscall_table[__NR_setgroups].handler = (syscall_fn_t)sys_setgroups_wrapper;
    syscall_table[__NR_setgroups].name = "setgroups";
    syscall_table[__NR_kill].handler = (syscall_fn_t)sys_kill_wrapper;
    syscall_table[__NR_kill].name = "kill";
    syscall_table[__NR_tkill].handler = (syscall_fn_t)sys_tkill_wrapper;
    syscall_table[__NR_tkill].name = "tkill";
    syscall_table[__NR_tgkill].handler = (syscall_fn_t)sys_tgkill_wrapper;
    syscall_table[__NR_tgkill].name = "tgkill";
    syscall_table[__NR_sigaltstack].handler = (syscall_fn_t)sys_sigaltstack_wrapper;
    syscall_table[__NR_sigaltstack].name = "sigaltstack";
    syscall_table[__NR_rt_sigaction].handler = (syscall_fn_t)sys_rt_sigaction_wrapper;
    syscall_table[__NR_rt_sigaction].name = "rt_sigaction";
    syscall_table[__NR_rt_sigprocmask].handler = (syscall_fn_t)sys_rt_sigprocmask_wrapper;
    syscall_table[__NR_rt_sigprocmask].name = "rt_sigprocmask";
    syscall_table[__NR_rt_sigpending].handler = (syscall_fn_t)sys_rt_sigpending_wrapper;
    syscall_table[__NR_rt_sigpending].name = "rt_sigpending";
    syscall_table[__NR_rt_sigsuspend].handler = (syscall_fn_t)sys_rt_sigsuspend_wrapper;
    syscall_table[__NR_rt_sigsuspend].name = "rt_sigsuspend";
    syscall_table[__NR_rt_sigreturn].handler = (syscall_fn_t)sys_rt_sigreturn_wrapper;
    syscall_table[__NR_rt_sigreturn].name = "rt_sigreturn";
    syscall_table[__NR_setpriority].handler = (syscall_fn_t)sys_setpriority_wrapper;
    syscall_table[__NR_setpriority].name = "setpriority";
    syscall_table[__NR_getpriority].handler = (syscall_fn_t)sys_getpriority_wrapper;
    syscall_table[__NR_getpriority].name = "getpriority";
    syscall_table[__NR_setregid].handler = (syscall_fn_t)sys_setregid_wrapper;
    syscall_table[__NR_setregid].name = "setregid";
    syscall_table[__NR_setgid].handler = (syscall_fn_t)sys_setgid_wrapper;
    syscall_table[__NR_setgid].name = "setgid";
    syscall_table[__NR_setreuid].handler = (syscall_fn_t)sys_setreuid_wrapper;
    syscall_table[__NR_setreuid].name = "setreuid";
    syscall_table[__NR_setuid].handler = (syscall_fn_t)sys_setuid_wrapper;
    syscall_table[__NR_setuid].name = "setuid";
    syscall_table[__NR_setresuid].handler = (syscall_fn_t)sys_setresuid_wrapper;
    syscall_table[__NR_setresuid].name = "setresuid";
    syscall_table[__NR_getresuid].handler = (syscall_fn_t)sys_getresuid_wrapper;
    syscall_table[__NR_getresuid].name = "getresuid";
    syscall_table[__NR_setresgid].handler = (syscall_fn_t)sys_setresgid_wrapper;
    syscall_table[__NR_setresgid].name = "setresgid";
    syscall_table[__NR_getresgid].handler = (syscall_fn_t)sys_getresgid_wrapper;
    syscall_table[__NR_getresgid].name = "getresgid";
    syscall_table[__NR_times].handler = (syscall_fn_t)sys_times_wrapper;
    syscall_table[__NR_times].name = "times";
    syscall_table[__NR_setpgid].handler = (syscall_fn_t)sys_setpgid_wrapper;
    syscall_table[__NR_setpgid].name = "setpgid";
    syscall_table[__NR_getpgid].handler = (syscall_fn_t)sys_getpgid_wrapper;
    syscall_table[__NR_getpgid].name = "getpgid";
    syscall_table[__NR_getsid].handler = (syscall_fn_t)sys_getsid_wrapper;
    syscall_table[__NR_getsid].name = "getsid";
    syscall_table[__NR_setsid].handler = (syscall_fn_t)sys_setsid_wrapper;
    syscall_table[__NR_setsid].name = "setsid";
    syscall_table[__NR_getrlimit].handler = (syscall_fn_t)sys_getrlimit_wrapper;
    syscall_table[__NR_getrlimit].name = "getrlimit";
    syscall_table[__NR_setrlimit].handler = (syscall_fn_t)sys_setrlimit_wrapper;
    syscall_table[__NR_setrlimit].name = "setrlimit";
    syscall_table[__NR_getrusage].handler = (syscall_fn_t)sys_getrusage_wrapper;
    syscall_table[__NR_getrusage].name = "getrusage";
    syscall_table[__NR_umask].handler = (syscall_fn_t)sys_umask_wrapper;
    syscall_table[__NR_umask].name = "umask";
    syscall_table[__NR_gettimeofday].handler = (syscall_fn_t)sys_gettimeofday_wrapper;
    syscall_table[__NR_gettimeofday].name = "gettimeofday";
    syscall_table[__NR_settimeofday].handler = (syscall_fn_t)sys_settimeofday_wrapper;
    syscall_table[__NR_settimeofday].name = "settimeofday";
    syscall_table[__NR_adjtimex].handler = (syscall_fn_t)sys_adjtimex_wrapper;
    syscall_table[__NR_adjtimex].name = "adjtimex";
    syscall_table[__NR_uname].handler = (syscall_fn_t)sys_uname;
    syscall_table[__NR_uname].name = "uname";
    syscall_table[__NR_getuid].handler = (syscall_fn_t)sys_getuid_wrapper;
    syscall_table[__NR_getuid].name = "getuid";
    syscall_table[__NR_geteuid].handler = (syscall_fn_t)sys_geteuid_wrapper;
    syscall_table[__NR_geteuid].name = "geteuid";
    syscall_table[__NR_getgid].handler = (syscall_fn_t)sys_getgid_wrapper;
    syscall_table[__NR_getgid].name = "getgid";
    syscall_table[__NR_getegid].handler = (syscall_fn_t)sys_getegid_wrapper;
    syscall_table[__NR_getegid].name = "getegid";
    syscall_table[__NR_sysinfo].handler = (syscall_fn_t)sys_sysinfo_wrapper;
    syscall_table[__NR_sysinfo].name = "sysinfo";
    syscall_table[__NR_getpid].handler = (syscall_fn_t)sys_getpid_wrapper;
    syscall_table[__NR_getpid].name = "getpid";
    syscall_table[__NR_getppid].handler = (syscall_fn_t)sys_getppid_wrapper;
    syscall_table[__NR_getppid].name = "getppid";
    syscall_table[__NR_socket].handler = (syscall_fn_t)sys_socket_wrapper;
    syscall_table[__NR_socket].name = "socket";
    syscall_table[__NR_bind].handler = (syscall_fn_t)sys_bind_wrapper;
    syscall_table[__NR_bind].name = "bind";
    syscall_table[__NR_listen].handler = (syscall_fn_t)sys_listen_wrapper;
    syscall_table[__NR_listen].name = "listen";
    syscall_table[__NR_accept].handler = (syscall_fn_t)sys_accept_wrapper;
    syscall_table[__NR_accept].name = "accept";
    syscall_table[__NR_connect].handler = (syscall_fn_t)sys_connect_wrapper;
    syscall_table[__NR_connect].name = "connect";
    syscall_table[__NR_sendto].handler = (syscall_fn_t)sys_sendto_wrapper;
    syscall_table[__NR_sendto].name = "sendto";
    syscall_table[__NR_recvfrom].handler = (syscall_fn_t)sys_recvfrom_wrapper;
    syscall_table[__NR_recvfrom].name = "recvfrom";
    syscall_table[__NR_setsockopt].handler = (syscall_fn_t)sys_setsockopt_wrapper;
    syscall_table[__NR_setsockopt].name = "setsockopt";
    syscall_table[__NR_getsockopt].handler = (syscall_fn_t)sys_getsockopt_wrapper;
    syscall_table[__NR_getsockopt].name = "getsockopt";
    syscall_table[__NR_shutdown].handler = (syscall_fn_t)sys_shutdown_wrapper;
    syscall_table[__NR_shutdown].name = "shutdown";
    syscall_table[__NR_brk].handler = (syscall_fn_t)sys_brk;
    syscall_table[__NR_brk].name = "brk";
    syscall_table[__NR_munmap].handler = (syscall_fn_t)sys_munmap_wrapper;
    syscall_table[__NR_munmap].name = "munmap";
    syscall_table[__NR_clone].handler = (syscall_fn_t)sys_fork_wrapper;
    syscall_table[__NR_clone].name = "clone/fork";
    syscall_table[__NR_execve].handler = (syscall_fn_t)sys_execve_wrapper;
    syscall_table[__NR_execve].name = "execve";
    syscall_table[__NR_mmap].handler = (syscall_fn_t)sys_mmap_wrapper;
    syscall_table[__NR_mmap].name = "mmap";
    syscall_table[__NR_mprotect].handler = (syscall_fn_t)sys_mprotect_wrapper;
    syscall_table[__NR_mprotect].name = "mprotect";
    syscall_table[__NR_msync].handler = (syscall_fn_t)sys_msync_wrapper;
    syscall_table[__NR_msync].name = "msync";
    syscall_table[__NR_mlock].handler = (syscall_fn_t)sys_mlock_wrapper;
    syscall_table[__NR_mlock].name = "mlock";
    syscall_table[__NR_munlock].handler = (syscall_fn_t)sys_munlock_wrapper;
    syscall_table[__NR_munlock].name = "munlock";
    syscall_table[__NR_mlockall].handler = (syscall_fn_t)sys_mlockall_wrapper;
    syscall_table[__NR_mlockall].name = "mlockall";
    syscall_table[__NR_munlockall].handler = (syscall_fn_t)sys_munlockall_wrapper;
    syscall_table[__NR_munlockall].name = "munlockall";
    syscall_table[__NR_mincore].handler = (syscall_fn_t)sys_mincore_wrapper;
    syscall_table[__NR_mincore].name = "mincore";
    syscall_table[__NR_madvise].handler = (syscall_fn_t)sys_madvise_wrapper;
    syscall_table[__NR_madvise].name = "madvise";
    /* NUMA memory policy — single-node stubs */
    syscall_table[__NR_mbind].handler = (syscall_fn_t)sys_mbind_wrapper;
    syscall_table[__NR_mbind].name = "mbind";
    syscall_table[__NR_get_mempolicy].handler = (syscall_fn_t)sys_get_mempolicy_wrapper;
    syscall_table[__NR_get_mempolicy].name = "get_mempolicy";
    syscall_table[__NR_set_mempolicy].handler = (syscall_fn_t)sys_set_mempolicy_wrapper;
    syscall_table[__NR_set_mempolicy].name = "set_mempolicy";
    syscall_table[__NR_wait4].handler = (syscall_fn_t)sys_waitpid_wrapper;
    syscall_table[__NR_wait4].name = "wait4/waitpid";
    syscall_table[__NR_prlimit64].handler = (syscall_fn_t)sys_prlimit64_wrapper;
    syscall_table[__NR_prlimit64].name = "prlimit64";
    
    /* Futura syscall numbers (from include/user/sysnums.h) - added last to override Linux numbers
    *
    * IMPORTANT: These entries override conflicting Linux AArch64 syscall numbers.
    * For example:
    *   - Futura SYS_write = 1,  Linux AArch64 __NR_write = 64
    *   - Futura SYS_getpid = 39, Linux AArch64 __NR_umount2 = 39
    *
    * By placing Futura syscalls at the end of this array, they take precedence
    * over earlier Linux mappings when userland programs use Futura syscall numbers.
    */
    syscall_table[0].handler = (syscall_fn_t)sys_read_wrapper;
    syscall_table[0].name = "read";
    syscall_table[1].handler = (syscall_fn_t)sys_write_wrapper;
    syscall_table[1].name = "write";
    syscall_table[2].handler = (syscall_fn_t)sys_open_wrapper;
    syscall_table[2].name = "open";
    syscall_table[3].handler = (syscall_fn_t)sys_close_wrapper;
    syscall_table[3].name = "close";
    syscall_table[4].handler = (syscall_fn_t)sys_stat_wrapper;
    syscall_table[4].name = "stat";
    syscall_table[5].handler = (syscall_fn_t)sys_fstat_wrapper;
    syscall_table[5].name = "fstat";
    syscall_table[8].handler = (syscall_fn_t)sys_lseek_wrapper;
    syscall_table[8].name = "lseek";
    syscall_table[9].handler = (syscall_fn_t)sys_mmap_wrapper;
    syscall_table[9].name = "mmap";
    syscall_table[11].handler = (syscall_fn_t)sys_munmap_wrapper;
    syscall_table[11].name = "munmap";
    syscall_table[12].handler = (syscall_fn_t)sys_brk;
    syscall_table[12].name = "brk";
    syscall_table[16].handler = (syscall_fn_t)sys_ioctl_wrapper;
    syscall_table[16].name = "ioctl";
    syscall_table[22].handler = (syscall_fn_t)sys_pipe_wrapper;
    syscall_table[22].name = "pipe";
    syscall_table[24].handler = (syscall_fn_t)sys_sched_yield_wrapper;
    syscall_table[24].name = "sched_yield";
    syscall_table[32].handler = (syscall_fn_t)sys_dup_wrapper;
    syscall_table[32].name = "dup";
    syscall_table[33].handler = (syscall_fn_t)sys_dup2_wrapper;
    syscall_table[33].name = "dup2";
    syscall_table[35].handler = (syscall_fn_t)sys_nanosleep_wrapper;
    syscall_table[35].name = "nanosleep";
    syscall_table[39].handler = (syscall_fn_t)sys_getpid_wrapper;
    syscall_table[39].name = "getpid";
    syscall_table[42].handler = (syscall_fn_t)sys_echo_wrapper;
    syscall_table[42].name = "echo";
    syscall_table[57].handler = (syscall_fn_t)sys_fork_wrapper;
    syscall_table[57].name = "fork";
    syscall_table[59].handler = (syscall_fn_t)sys_execve_wrapper;
    syscall_table[59].name = "execve";
    syscall_table[60].handler = (syscall_fn_t)sys_exit;
    syscall_table[60].name = "exit";
    syscall_table[61].handler = (syscall_fn_t)sys_waitpid_wrapper;
    syscall_table[61].name = "wait4/waitpid";
    syscall_table[79].handler = (syscall_fn_t)sys_getcwd_wrapper;
    syscall_table[79].name = "getcwd";
    syscall_table[80].handler = (syscall_fn_t)sys_chdir_wrapper;
    syscall_table[80].name = "chdir";
    syscall_table[83].handler = (syscall_fn_t)sys_mkdir_wrapper;
    syscall_table[83].name = "mkdir";
    syscall_table[84].handler = (syscall_fn_t)sys_rmdir_wrapper;
    syscall_table[84].name = "rmdir";
    syscall_table[87].handler = (syscall_fn_t)sys_unlink_wrapper;
    syscall_table[87].name = "unlink";
    syscall_table[102].handler = (syscall_fn_t)sys_getuid_wrapper;
    syscall_table[102].name = "getuid";
    syscall_table[104].handler = (syscall_fn_t)sys_getgid_wrapper;
    syscall_table[104].name = "getgid";
    syscall_table[105].handler = (syscall_fn_t)sys_setuid_wrapper;
    syscall_table[105].name = "setuid";
    syscall_table[106].handler = (syscall_fn_t)sys_setgid_wrapper;
    syscall_table[106].name = "setgid";
    syscall_table[107].handler = (syscall_fn_t)sys_geteuid_wrapper;
    syscall_table[107].name = "geteuid";
    syscall_table[108].handler = (syscall_fn_t)sys_getegid_wrapper;
    syscall_table[108].name = "getegid";
    syscall_table[109].handler = (syscall_fn_t)sys_seteuid_wrapper;
    syscall_table[109].name = "seteuid";
    syscall_table[110].handler = (syscall_fn_t)sys_setegid_wrapper;
    syscall_table[110].name = "setegid";
    syscall_table[111].handler = (syscall_fn_t)sys_getpgrp_wrapper;
    syscall_table[111].name = "getpgrp";
    syscall_table[112].handler = (syscall_fn_t)sys_setsid_wrapper;
    syscall_table[112].name = "setsid";
    syscall_table[113].handler = (syscall_fn_t)sys_getppid_wrapper;
    syscall_table[113].name = "getppid";
    syscall_table[124].handler = (syscall_fn_t)sys_getsid_wrapper;
    syscall_table[124].name = "getsid";

    /* FIPC syscalls - Futura-specific range 401-406 */
    syscall_table[__NR_fipc_create].handler = (syscall_fn_t)sys_fipc_create_wrapper;
    syscall_table[__NR_fipc_create].name = "fipc_create";
    syscall_table[__NR_fipc_send].handler = (syscall_fn_t)sys_fipc_send_wrapper;
    syscall_table[__NR_fipc_send].name = "fipc_send";
    syscall_table[__NR_fipc_recv].handler = (syscall_fn_t)sys_fipc_recv_wrapper;
    syscall_table[__NR_fipc_recv].name = "fipc_recv";
    syscall_table[__NR_fipc_close].handler = (syscall_fn_t)sys_fipc_close_wrapper;
    syscall_table[__NR_fipc_close].name = "fipc_close";
    syscall_table[__NR_fipc_poll].handler = (syscall_fn_t)sys_fipc_poll_wrapper;
    syscall_table[__NR_fipc_poll].name = "fipc_poll";
    syscall_table[__NR_fipc_connect].handler = (syscall_fn_t)sys_fipc_connect_wrapper;
    syscall_table[__NR_fipc_connect].name = "fipc_connect";

    /* POSIX message queues */
    syscall_table[__NR_mq_open].handler = (syscall_fn_t)sys_mq_open_wrapper;
    syscall_table[__NR_mq_open].name = "mq_open";
    syscall_table[__NR_mq_unlink].handler = (syscall_fn_t)sys_mq_unlink_wrapper;
    syscall_table[__NR_mq_unlink].name = "mq_unlink";
    syscall_table[__NR_mq_timedsend].handler = (syscall_fn_t)sys_mq_timedsend_wrapper;
    syscall_table[__NR_mq_timedsend].name = "mq_timedsend";
    syscall_table[__NR_mq_timedreceive].handler = (syscall_fn_t)sys_mq_timedreceive_wrapper;
    syscall_table[__NR_mq_timedreceive].name = "mq_timedreceive";
    syscall_table[__NR_mq_notify].handler = (syscall_fn_t)sys_mq_notify_wrapper;
    syscall_table[__NR_mq_notify].name = "mq_notify";
    syscall_table[__NR_mq_getsetattr].handler = (syscall_fn_t)sys_mq_getsetattr_wrapper;
    syscall_table[__NR_mq_getsetattr].name = "mq_getsetattr";

    /* System V IPC: message queues */
    syscall_table[__NR_msgget].handler = (syscall_fn_t)sys_msgget_wrapper;
    syscall_table[__NR_msgget].name = "msgget";
    syscall_table[__NR_msgsnd].handler = (syscall_fn_t)sys_msgsnd_wrapper;
    syscall_table[__NR_msgsnd].name = "msgsnd";
    syscall_table[__NR_msgrcv].handler = (syscall_fn_t)sys_msgrcv_wrapper;
    syscall_table[__NR_msgrcv].name = "msgrcv";
    syscall_table[__NR_msgctl].handler = (syscall_fn_t)sys_msgctl_wrapper;
    syscall_table[__NR_msgctl].name = "msgctl";

    /* System V IPC: semaphores */
    syscall_table[__NR_semget].handler = (syscall_fn_t)sys_semget_wrapper;
    syscall_table[__NR_semget].name = "semget";
    syscall_table[__NR_semop].handler = (syscall_fn_t)sys_semop_wrapper;
    syscall_table[__NR_semop].name = "semop";
    syscall_table[__NR_semctl].handler = (syscall_fn_t)sys_semctl_wrapper;
    syscall_table[__NR_semctl].name = "semctl";
    syscall_table[__NR_semtimedop].handler = (syscall_fn_t)sys_semtimedop_wrapper;
    syscall_table[__NR_semtimedop].name = "semtimedop";

    /* System V IPC: shared memory */
    syscall_table[__NR_shmget].handler = (syscall_fn_t)sys_shmget_wrapper;
    syscall_table[__NR_shmget].name = "shmget";
    syscall_table[__NR_shmctl].handler = (syscall_fn_t)sys_shmctl_wrapper;
    syscall_table[__NR_shmctl].name = "shmctl";
    syscall_table[__NR_shmat].handler = (syscall_fn_t)sys_shmat_wrapper;
    syscall_table[__NR_shmat].name = "shmat";
    syscall_table[__NR_shmdt].handler = (syscall_fn_t)sys_shmdt_wrapper;
    syscall_table[__NR_shmdt].name = "shmdt";

    /* Socket extensions */
    syscall_table[__NR_recvmmsg].handler = (syscall_fn_t)sys_recvmmsg_wrapper;
    syscall_table[__NR_recvmmsg].name = "recvmmsg";
    syscall_table[__NR_sendmmsg].handler = (syscall_fn_t)sys_sendmmsg_wrapper;
    syscall_table[__NR_sendmmsg].name = "sendmmsg";
    syscall_table[__NR_process_vm_readv].handler = (syscall_fn_t)sys_process_vm_readv_wrapper;
    syscall_table[__NR_process_vm_readv].name = "process_vm_readv";
    syscall_table[__NR_process_vm_writev].handler = (syscall_fn_t)sys_process_vm_writev_wrapper;
    syscall_table[__NR_process_vm_writev].name = "process_vm_writev";

    /* Memory protection keys */
    syscall_table[__NR_pkey_mprotect].handler = (syscall_fn_t)sys_pkey_mprotect_wrapper;
    syscall_table[__NR_pkey_mprotect].name = "pkey_mprotect";
    syscall_table[__NR_pkey_alloc].handler = (syscall_fn_t)sys_pkey_alloc_wrapper;
    syscall_table[__NR_pkey_alloc].name = "pkey_alloc";
    syscall_table[__NR_pkey_free].handler = (syscall_fn_t)sys_pkey_free_wrapper;
    syscall_table[__NR_pkey_free].name = "pkey_free";

    /* openat2 (Linux 5.6+) */
    syscall_table[__NR_openat2].handler = (syscall_fn_t)sys_openat2_wrapper;
    syscall_table[__NR_openat2].name = "openat2";

    /* clock_adjtime: delegate to adjtimex for CLOCK_REALTIME */
    syscall_table[__NR_clock_adjtime].handler = (syscall_fn_t)sys_clock_adjtime_wrapper;
    syscall_table[__NR_clock_adjtime].name = "clock_adjtime";
    /* setns: ENOSYS (namespace support not yet implemented) */
    syscall_table[__NR_setns].handler = (syscall_fn_t)sys_setns_wrapper;
    syscall_table[__NR_setns].name = "setns";

    /* sched_getattr/sched_setattr (Linux 3.14+) */
    syscall_table[__NR_sched_setattr].handler = (syscall_fn_t)sys_sched_setattr_wrapper;
    syscall_table[__NR_sched_setattr].name = "sched_setattr";
    syscall_table[__NR_sched_getattr].handler = (syscall_fn_t)sys_sched_getattr_wrapper;
    syscall_table[__NR_sched_getattr].name = "sched_getattr";

    /* setfsuid/setfsgid */
    syscall_table[__NR_setfsuid].handler = (syscall_fn_t)sys_setfsuid_wrapper;
    syscall_table[__NR_setfsuid].name = "setfsuid";
    syscall_table[__NR_setfsgid].handler = (syscall_fn_t)sys_setfsgid_wrapper;
    syscall_table[__NR_setfsgid].name = "setfsgid";

    /* mlock2 (Linux 4.4+) */
    syscall_table[__NR_mlock2].handler = (syscall_fn_t)sys_mlock2_wrapper;
    syscall_table[__NR_mlock2].name = "mlock2";

    /* swapon/swapoff */
    syscall_table[__NR_swapon].handler = (syscall_fn_t)sys_swapon_wrapper;
    syscall_table[__NR_swapon].name = "swapon";
    syscall_table[__NR_swapoff].handler = (syscall_fn_t)sys_swapoff_wrapper;
    syscall_table[__NR_swapoff].name = "swapoff";

    /* execveat (Linux 3.19+) */
    syscall_table[__NR_execveat].handler = (syscall_fn_t)sys_execveat_wrapper;
    syscall_table[__NR_execveat].name = "execveat";

    /* epoll_pwait2 (Linux 5.11+) */
    syscall_table[__NR_epoll_pwait2].handler = (syscall_fn_t)sys_epoll_pwait2_wrapper;
    syscall_table[__NR_epoll_pwait2].name = "epoll_pwait2";

    /* io_uring (Linux 5.1+) — stubs that return ENOSYS so libc/apps fall back */
    syscall_table[__NR_io_uring_setup].handler = (syscall_fn_t)sys_io_uring_setup_wrapper;
    syscall_table[__NR_io_uring_setup].name = "io_uring_setup";
    syscall_table[__NR_io_uring_enter].handler = (syscall_fn_t)sys_io_uring_enter_wrapper;
    syscall_table[__NR_io_uring_enter].name = "io_uring_enter";
    syscall_table[__NR_io_uring_register].handler = (syscall_fn_t)sys_io_uring_register_wrapper;
    syscall_table[__NR_io_uring_register].name = "io_uring_register";

    /* preadv2/pwritev2 (Linux 4.6+) */
    syscall_table[__NR_preadv2].handler = (syscall_fn_t)sys_preadv2_wrapper;
    syscall_table[__NR_preadv2].name = "preadv2";
    syscall_table[__NR_pwritev2].handler = (syscall_fn_t)sys_pwritev2_wrapper;
    syscall_table[__NR_pwritev2].name = "pwritev2";

    /* kcmp (Linux 3.5+) */
    syscall_table[__NR_kcmp].handler = (syscall_fn_t)sys_kcmp_wrapper;
    syscall_table[__NR_kcmp].name = "kcmp";

    /* seccomp (Linux 3.17+) */
    syscall_table[__NR_seccomp].handler = (syscall_fn_t)sys_seccomp_wrapper;
    syscall_table[__NR_seccomp].name = "seccomp";

    /* rt_sigqueueinfo / rt_tgsigqueueinfo */
    syscall_table[__NR_rt_sigqueueinfo].handler = (syscall_fn_t)sys_rt_sigqueueinfo_wrapper;
    syscall_table[__NR_rt_sigqueueinfo].name = "rt_sigqueueinfo";
    syscall_table[__NR_rt_tgsigqueueinfo].handler = (syscall_fn_t)sys_rt_tgsigqueueinfo_wrapper;
    syscall_table[__NR_rt_tgsigqueueinfo].name = "rt_tgsigqueueinfo";

    /* Linux keyring stubs (Linux ARM64: 217-219) — ENOSYS, not implemented */
    syscall_table[__NR_add_key].handler = (syscall_fn_t)sys_enosys_stub;
    syscall_table[__NR_add_key].name = "add_key";
    syscall_table[__NR_request_key].handler = (syscall_fn_t)sys_enosys_stub;
    syscall_table[__NR_request_key].name = "request_key";
    syscall_table[__NR_keyctl].handler = (syscall_fn_t)sys_enosys_stub;
    syscall_table[__NR_keyctl].name = "keyctl";

    /* Linux 5.13-5.16 — wire to real implementations */
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule       445
#define __NR_landlock_restrict_self  446
#define __NR_memfd_secret            447
#define __NR_futex_waitv             449
    syscall_table[__NR_landlock_create_ruleset].handler = (syscall_fn_t)sys_landlock_create_ruleset_wrapper;
    syscall_table[__NR_landlock_create_ruleset].name = "landlock_create_ruleset";
    syscall_table[__NR_landlock_add_rule].handler = (syscall_fn_t)sys_landlock_add_rule_wrapper;
    syscall_table[__NR_landlock_add_rule].name = "landlock_add_rule";
    syscall_table[__NR_landlock_restrict_self].handler = (syscall_fn_t)sys_landlock_restrict_self_wrapper;
    syscall_table[__NR_landlock_restrict_self].name = "landlock_restrict_self";
    syscall_table[__NR_memfd_secret].handler = (syscall_fn_t)sys_memfd_secret_wrapper;
    syscall_table[__NR_memfd_secret].name = "memfd_secret";
    syscall_table[__NR_futex_waitv].handler = (syscall_fn_t)sys_futex_waitv_wrapper;
    syscall_table[__NR_futex_waitv].name = "futex_waitv";

    /* Linux 5.10-6.10 — wire to real implementations */
#define __NR_process_madvise         440
#define __NR_set_mempolicy_home_node 450
#define __NR_cachestat               451
#define __NR_fchmodat2               452
#define __NR_mseal                   462
    syscall_table[__NR_process_madvise].handler = (syscall_fn_t)sys_process_madvise_wrapper;
    syscall_table[__NR_process_madvise].name = "process_madvise";
    syscall_table[__NR_set_mempolicy_home_node].handler = (syscall_fn_t)sys_set_mempolicy_home_node_wrapper;
    syscall_table[__NR_set_mempolicy_home_node].name = "set_mempolicy_home_node";
    syscall_table[__NR_cachestat].handler = (syscall_fn_t)sys_cachestat_wrapper;
    syscall_table[__NR_cachestat].name = "cachestat";
    syscall_table[__NR_fchmodat2].handler = (syscall_fn_t)sys_fchmodat2_wrapper;
    syscall_table[__NR_fchmodat2].name = "fchmodat2";
    syscall_table[__NR_mseal].handler = (syscall_fn_t)sys_mseal_wrapper;
    syscall_table[__NR_mseal].name = "mseal";

    /* perf_event_open / fanotify / userfaultfd / bpf stubs */
#define __NR_perf_event_open  241  /* Linux aarch64: 241 */
#define __NR_fanotify_init    262  /* Linux aarch64: 262 */
#define __NR_fanotify_mark    263  /* Linux aarch64: 263 */
#define __NR_userfaultfd      282  /* Linux aarch64: 282 */
#define __NR_bpf              280  /* Linux aarch64: 280 */
    syscall_table[__NR_perf_event_open].handler = (syscall_fn_t)sys_perf_event_open_wrapper;
    syscall_table[__NR_perf_event_open].name = "perf_event_open";
    syscall_table[__NR_fanotify_init].handler = (syscall_fn_t)sys_fanotify_init_wrapper;
    syscall_table[__NR_fanotify_init].name = "fanotify_init";
    syscall_table[__NR_fanotify_mark].handler = (syscall_fn_t)sys_fanotify_mark_wrapper;
    syscall_table[__NR_fanotify_mark].name = "fanotify_mark";
    syscall_table[__NR_userfaultfd].handler = (syscall_fn_t)sys_userfaultfd_wrapper;
    syscall_table[__NR_userfaultfd].name = "userfaultfd";
    syscall_table[__NR_bpf].handler = (syscall_fn_t)sys_bpf_wrapper;
    syscall_table[__NR_bpf].name = "bpf";

    /* x86_64 compatibility aliases — Futura userland uses x86_64 syscall numbers */
    /* dup (x86_64: 32, ARM64: 23) */
    syscall_table[32].handler = syscall_table[__NR_dup].handler;
    syscall_table[32].name = "dup";
    /* dup2 (x86_64: 33) — use proper sys_dup2 handler instead of mknodat */
    syscall_table[33].handler = (syscall_fn_t)sys_dup2_wrapper;
    syscall_table[33].name = "dup2";
    /* kill (x86_64: 62, ARM64: 129) */
    syscall_table[62].handler = syscall_table[__NR_kill].handler;
    syscall_table[62].name = "kill";
    /* rename (x86_64: 82) — shell 'mv' command */
    extern int64_t sys_rename_compat(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    syscall_table[82].handler = (syscall_fn_t)sys_rename_compat;
    syscall_table[82].name = "rename";
    /* clock_gettime (x86_64: 98, ARM64: 113) — for shell 'date' command */
    syscall_table[98].handler = syscall_table[__NR_clock_gettime].handler;
    syscall_table[98].name = "clock_gettime";
    /* syslog (x86_64: 103, ARM64: 116) — for dmesg */
    syscall_table[103].handler = (syscall_fn_t)sys_syslog_wrapper;
    syscall_table[103].name = "syslog";
    syscall_table[__NR_syslog].handler = (syscall_fn_t)sys_syslog_wrapper;
    syscall_table[__NR_syslog].name = "syslog";
    /* Note: fcntl(72) and ftruncate(77) aliases omitted — fcntl compat
     * changes shell behavior (F_GETFL now succeeds, changing stdio setup) */

    syscall_table_initialized = true;
}

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
    /* Initialize syscall table on first call */
    arm64_syscall_table_init();

    /* Validate syscall number */
    if (syscall_num >= MAX_SYSCALL) {
        fut_serial_puts("[SYSCALL] Invalid syscall number: ");
        return -ENOSYS;
    }

    /* Get syscall handler */
    struct syscall_entry *entry = &syscall_table[syscall_num];

    if (entry->handler == NULL) {
        fut_printf("[SYSCALL] Unimplemented syscall %llu (%s)\n",
                   (unsigned long long)syscall_num,
                   entry->name ? entry->name : "unknown");
        return -ENOSYS;
    }

    /* Log syscall (optional - can be disabled for production) */
#if DEBUG_SYSCALL
    fut_serial_puts("[SYSCALL] ");
    fut_serial_puts(entry->name);
    fut_serial_puts("()\n");
#endif

    /* Call syscall handler */
    return entry->handler(arg0, arg1, arg2, arg3, arg4, arg5);
}

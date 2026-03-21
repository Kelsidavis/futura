/* posix_syscall.c - POSIX Syscall Dispatch Layer
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Central syscall dispatch mechanism for POSIX compatibility.
 * Maps syscall numbers to handler functions.
 */

#include "posix_shim.h"
#include <stdint.h>
#include <stddef.h>
#include <kernel/syscalls.h>
#include <kernel/uaccess.h>
#include <kernel/fut_vfs.h>
#include <kernel/fut_object.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/fut_socket.h>
#include <kernel/signal.h>
#include <kernel/signal_frame.h>
#include <kernel/chrdev.h>
#include <kernel/kprintf.h>
#include <fcntl.h>
#include <sched.h>

#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* ============================================================
 *   Syscall Numbers
 * ============================================================ */

/* Standard POSIX syscall numbers (subset) */
#define SYS_read        0
#define SYS_write       1
#define SYS_open        2
#define SYS_close       3
#define SYS_openat      257
#define SYS_mkdirat     258
#define SYS_mknod       133
#define SYS_mknodat     259
#define SYS_fchownat    260
#define SYS_futimesat   261  /* futimesat (not futimensat) - deprecated */
#define SYS_fstatat     262  /* newfstatat on Linux */
#define SYS_unlinkat    263
#define SYS_renameat    264
#define SYS_linkat      265
#define SYS_symlinkat   266
#define SYS_readlinkat  267
#define SYS_fchmodat    268
#define SYS_faccessat   269
#define SYS_utimensat   280
/* AT_FDCWD provided by fcntl.h */
#define SYS_stat        4
#define SYS_fstat       5
#define SYS_lstat       6
#define SYS_poll        7
#define SYS_lseek       8
#ifndef SYS_mmap
#define SYS_mmap        9
#endif
#define SYS_mprotect    10
#ifndef SYS_munmap
#define SYS_munmap      11
#endif
#ifndef SYS_brk
#define SYS_brk         12
#endif
#define SYS_ioctl       16
#define SYS_pread64     17
#define SYS_pwrite64    18
#define SYS_readv       19
#define SYS_writev      20
#define SYS_pipe        22
#define SYS_preadv              295
#define SYS_pwritev             296
#define SYS_preadv2             327  /* Linux: 327 — free in Futura */
#define SYS_pwritev2            328  /* Linux: 328 — free in Futura */
#define SYS_mlock2              325  /* Linux: 325 — free in Futura */
#define SYS_openat2             444  /* Linux: 437 — Futura: 444 (437 used by process_vm_readv) */
#define SYS_rt_tgsigqueueinfo   297
#define SYS_process_vm_readv    437  /* Linux: 310 — Futura: 437 (310/311 used by vhangup/setreuid) */
#define SYS_process_vm_writev   438  /* Linux: 311 — Futura: 438 */
#define SYS_execveat            322  /* Linux: 322 — free in Futura */
#define SYS_select      23
#define SYS_sched_yield 24
#define SYS_mremap      25
#define SYS_msync       26
#define SYS_mincore     27
#define SYS_dup         32
#define SYS_dup2        33
#define SYS_pause       34
#define SYS_alarm       37
#define SYS_fcntl       72
#define SYS_flock       73
#define SYS_fsync       74
#define SYS_fdatasync   75
#define SYS_truncate    76
#define SYS_ftruncate   77
#define SYS_clone       56
#define SYS_fork        57
#define SYS_execve      59
#ifndef SYS_exit
#define SYS_exit        60
#endif
#define SYS_wait4       61
#define SYS_kill        62
#define SYS_uname       63
#define SYS_shmget      29   /* Linux: 29 */
#define SYS_shmat       30   /* Linux: 30 */
#define SYS_shmctl      31   /* Linux: 31 */
#define SYS_shmdt       67   /* Linux: 67 */
#define SYS_semget      64   /* Linux: 64 */
#define SYS_semop       65   /* Linux: 65 */
#define SYS_semctl      66   /* Linux: 66 */
#define SYS_semtimedop  220  /* Linux: 220 */
#define SYS_sigaction   13
#define SYS_sigprocmask 14
#define SYS_sigreturn   15
#define SYS_getpid      39
#define SYS_gettid      186
#define SYS_socket      41
#define SYS_connect     53  /* Note: non-standard location (42 is echo) */
#define SYS_accept      43
#define SYS_sendto      44
#define SYS_recvfrom    45
#define SYS_sendmsg     46
#define SYS_recvmsg     47
#define SYS_shutdown    48
#define SYS_bind        49
#define SYS_listen      50
#define SYS_getsockname 51
#define SYS_getpeername 52
#define SYS_setsockopt  54
#define SYS_getsockopt  55
#ifndef SYS_getcwd
#define SYS_getcwd      79
#endif
#ifndef SYS_chdir
#define SYS_chdir       80
#endif
#define SYS_mkdir       83
#define SYS_rmdir       84
#define SYS_link        86
#define SYS_unlink      87
#define SYS_symlink     88
#define SYS_readlink    89
#ifndef SYS_chmod
#define SYS_chmod       90
#endif
#ifndef SYS_fchmod
#define SYS_fchmod      91
#endif
#ifndef SYS_chown
#define SYS_chown       92
#endif
#ifndef SYS_fchown
#define SYS_fchown      93
#endif
#ifndef SYS_lchown
#define SYS_lchown      94
#endif
#ifndef SYS_creat
#define SYS_creat       85
#endif
#ifndef SYS_setfsuid
#define SYS_setfsuid    122
#endif
#ifndef SYS_setfsgid
#define SYS_setfsgid    123
#endif
#ifndef SYS_getuid
#define SYS_getuid      102
#endif
#ifndef SYS_getgid
#define SYS_getgid      104
#endif
#define SYS_umask        95
#define SYS_gettimeofday 96
#define SYS_getrlimit    97
#define SYS_clock_gettime 98
#define SYS_getrusage    99
#define SYS_times        100
#define SYS_ptrace       101
#define SYS_setrlimit    160
#define SYS_time         201
#define SYS_syslog       103
#define SYS_reboot       169
#define SYS_memfd_create 321
#define SYS_futex        202
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define SYS_getdents64   217
#define SYS_fadvise64    221
/* Signal syscalls */
#define SYS_sigpending       127
#define SYS_rt_sigtimedwait   128
#define SYS_rt_sigqueueinfo   129
#define SYS_sigsuspend        130
#define SYS_sigaltstack      131
/* pselect6/ppoll */
#define SYS_pselect6     270
#define SYS_ppoll        271
/* accept4 / signalfd4 / dup3 / pipe2 */
/* signalfd legacy (282) / timerfd_create (283) / eventfd legacy (284) */
#define SYS_signalfd     282  /* Linux: 282 — legacy variant; flags=0 */
#define SYS_eventfd      284  /* Linux: 284 — legacy variant; flags=0 */
#define SYS_accept4      288
#define SYS_signalfd4    289
#define SYS_eventfd2     290
#define SYS_epoll_create1 291
#ifndef SYS_dup3
#define SYS_dup3         292
#endif
#ifndef SYS_pipe2
#define SYS_pipe2        293
#endif
#define SYS_getpriority  140
#define SYS_setpriority  141
#define SYS_sched_setparam      142
#define SYS_sched_getparam      143
#define SYS_sched_setscheduler  144
#define SYS_sched_getscheduler  145
#define SYS_sched_get_priority_max  146
#define SYS_sched_get_priority_min  147
#define SYS_sched_rr_get_interval  148
#define SYS_sched_setattr          439  /* Linux: 314 — Futura: 439 (314/315 used by clock_getres/nanosleep) */
#define SYS_sched_getattr          440  /* Linux: 315 — Futura: 440 */
#define SYS_seccomp                441  /* Linux: 317 — Futura: 441 (317 used by renameat2) */
#define SYS_kcmp                   442  /* Linux: 312 — Futura: 442 (312 used by capget) */
#define SYS_faccessat2             443  /* Linux: 439 — Futura: 443 (439 used by sched_setattr) */

/* xattr syscalls (Linux x86_64 188-199) */
#define SYS_setxattr     188
#define SYS_lsetxattr    189
#define SYS_fsetxattr    190
#define SYS_getxattr     191
#define SYS_lgetxattr    192
#define SYS_fgetxattr    193
#define SYS_listxattr    194
#define SYS_llistxattr   195
#define SYS_flistxattr   196
#define SYS_removexattr  197
#define SYS_lremovexattr 198
#define SYS_fremovexattr 199

/* waitid (Linux x86_64 247) */
#define SYS_waitid       247

/* Linux keyring (Linux x86_64 248-250) — implemented as ENOSYS stubs */
#define SYS_add_key      248
#define SYS_request_key  249
#define SYS_keyctl       250

/* inotify (Linux x86_64 253-255, 294) */
#define SYS_inotify_init     253
#define SYS_inotify_add_watch 254
#define SYS_inotify_rm_watch  255

/* splice/tee/vmsplice (Linux x86_64 275-278) */
#define SYS_splice       275
#define SYS_tee          276
#define SYS_vmsplice     278

/* inotify_init1 (Linux x86_64 294) */
#define SYS_inotify_init1    294

/* time/itimer/clock (Linux x86_64) */
#define SYS_getitimer        36
#define SYS_setitimer        38
/* These use Linux x86_64 numbers that don't conflict with Futura's custom scheme */
#define SYS_sendfile         40
#define SYS_fchdir           81
#define SYS_setregid        114
#define SYS_setresuid       117
#define SYS_getresuid       118
#define SYS_setresgid       119
#define SYS_getresgid       120
#define SYS_personality     135
#define SYS_statfs          137
#define SYS_fstatfs         138
#define SYS_mlock           149
#define SYS_munlock         150
#define SYS_mlockall        151
#define SYS_munlockall      152
#define SYS_pivot_root      155
#define SYS_prctl           157
#define SYS_arch_prctl      158
#define SYS_adjtimex        159
#define SYS_chroot          161
#define SYS_sync            162
#define SYS_acct            163
#define SYS_settimeofday    164
#define SYS_mount           165
#define SYS_umount2         166
#define SYS_ioprio_set      251
#define SYS_ioprio_get      252
#define SYS_set_tid_address 218
#define SYS_timer_create    222
#define SYS_timer_settime   223
#define SYS_timer_gettime   224
#define SYS_timer_getoverrun 225
#define SYS_timer_delete    226
#define SYS_clock_settime   227
#define SYS_unshare         272
#define SYS_set_robust_list 273
#define SYS_get_robust_list 274
#define SYS_sync_file_range 277
#define SYS_epoll_pwait     281
#define SYS_timerfd_create  283
#define SYS_fallocate       285
#define SYS_timerfd_settime 286
#define SYS_timerfd_gettime 287
#define SYS_prlimit64       302
#define SYS_clock_adjtime   305  /* Linux: 305 */
#define SYS_syncfs          306
#define SYS_sendmmsg        307  /* Linux: 307 */
#define SYS_setns           308  /* Linux: 308 */
#define SYS_getcpu_new      309  /* Linux: 309 — getcpu already registered at 309 */
#define SYS_recvmmsg        299  /* Linux: 299 */
#define SYS_clone3           435  /* Linux: 435 */
#define SYS_close_range      436
#define SYS_pidfd_open        434  /* Linux: 434 */
#define SYS_pidfd_send_signal 424  /* Linux: 424 */
#define SYS_pidfd_getfd       445  /* Linux: 438 — Futura: 445 (438 used by process_vm_writev) */
#define SYS_epoll_pwait2      446  /* Linux: 441 — Futura: 446 (441 used by seccomp) */
/* Linux 5.10-5.16 syscalls — remapped because 444-446 are taken above */
#define SYS_landlock_create_ruleset 447  /* Linux: 444 — Futura: 447 */
#define SYS_landlock_add_rule       448  /* Linux: 445 — Futura: 448 */
#define SYS_landlock_restrict_self  449  /* Linux: 446 — Futura: 449 */
#define SYS_memfd_secret            450  /* Linux: 447 — Futura: 450 */
#define SYS_futex_waitv             451  /* Linux: 449 — Futura: 451 */
/* Linux 5.10-6.10 syscalls — remapped (Linux numbers conflict with Futura scheme) */
#define SYS_process_madvise         452  /* Linux: 440 — Futura: 452 (440 = sched_getattr) */
#define SYS_set_mempolicy_home_node 453  /* Linux: 450 — Futura: 453 (450 = memfd_secret) */
#define SYS_cachestat               454  /* Linux: 451 — Futura: 454 (451 = futex_waitv) */
#define SYS_fchmodat2               455  /* Linux: 452 — Futura: 455 */
#define SYS_mseal                   456  /* Linux: 459 — Futura: 456 */
/* Linux 2.6-5.x syscalls missing from Futura (using their native Linux numbers) */
#define SYS_perf_event_open         298  /* Linux: 298 */
#define SYS_fanotify_init           300  /* Linux: 300 */
#define SYS_fanotify_mark           301  /* Linux: 301 */
#define SYS_userfaultfd             323  /* Linux: 323 */
#define SYS_bpf                     457  /* Linux: 321 — Futura: 457 (321 = memfd_create) */
/* Linux 5.2+ new mount API (using their native Linux numbers — no conflicts) */
#define SYS_open_tree               428  /* Linux: 428 */
#define SYS_move_mount_new          429  /* Linux: 429 */
#define SYS_fsopen                  430  /* Linux: 430 */
#define SYS_fsconfig                431  /* Linux: 431 */
#define SYS_fsmount                 432  /* Linux: 432 */
#define SYS_fspick                  433  /* Linux: 433 */
#define SYS_mount_setattr           458  /* Linux: 442 — Futura: 458 (442 = kcmp) */
/* Linux 6.8+ syscalls (2024) */
#define SYS_statmount               459  /* Linux: 453 — Futura: 459 */
#define SYS_listmount               460  /* Linux: 454 — Futura: 460 */
#define SYS_lsm_get_self_attr       461  /* Linux: 459 — Futura: 461 */
#define SYS_lsm_set_self_attr       462  /* Linux: 460 — Futura: 462 */
#define SYS_lsm_list_modules        463  /* Linux: 461 — Futura: 463 */
/* File handle syscalls (Linux 2.6.39+) */
#define SYS_name_to_handle_at       303  /* Linux: 303 (conflicts with prlimit64? no, prlimit64=302) */
#define SYS_open_by_handle_at       304  /* Linux: 304 */
#define SYS_sethostname      170
#define SYS_setdomainname    171
/* Syscalls whose Linux numbers conflict with Futura's custom scheme get
 * extended Futura numbers (310+). The kernel functions are the same;
 * only the dispatch slot differs from the Linux ABI. */
#define SYS_vhangup         310  /* Linux: 111 (Futura: getpgrp) */
#define SYS_setreuid        311  /* Linux: 113 (Futura: getppid) */
#define SYS_capget          312  /* Linux: 125 (Futura: setpgid) */
#define SYS_capset          313  /* Linux: 126 (Futura: getpgid) */
#define SYS_clock_getres    314  /* Linux: 229 (Futura: epoll_ctl) */
#define SYS_clock_nanosleep 315  /* Linux: 230 (Futura: epoll_wait) */
#define SYS_sysinfo         316  /* Linux:  99 (Futura: getrusage) */
#define SYS_renameat2       317  /* Linux: 316 — extended range, no conflict */
#define SYS_getrandom       318  /* Linux: 318 */
#define SYS_membarrier      324  /* Linux: 324 */
#define SYS_copy_file_range 326  /* Linux: 326 */
#define SYS_pkey_mprotect   329  /* Linux: 329 */
#define SYS_pkey_alloc      330  /* Linux: 330 */
#define SYS_pkey_free       331  /* Linux: 331 */
#define SYS_rseq            334  /* Linux: 334 */
#define SYS_statx           332  /* Linux: 332 */
#define SYS_tgkill          234  /* Linux: 234 */
#define SYS_tkill            200  /* Linux: 200 */
#define SYS_exit_group       319  /* Linux: 231 — Futura: 319 (231 used by madvise) */
#define SYS_getcpu           309  /* Linux: 309 */
#define SYS_readahead        187  /* Linux: 187 */
#define SYS_getgroups        115  /* Linux: 115 */
#define SYS_setgroups        116  /* Linux: 116 */
#define SYS_utimes           235  /* Linux: 235 */
#define SYS_mbind            237  /* Linux: 237 */
#define SYS_set_mempolicy    238  /* Linux: 238 */
#define SYS_get_mempolicy    239  /* Linux: 239 */
#define SYS_vfork            58   /* Linux: 58 */
#define SYS_socketpair       320  /* Linux: 53 — Futura: 320 (53 used by connect) */

#ifndef SYS_time_millis
#define SYS_time_millis  400
#endif

#define SYS_msgrcv      70
#define SYS_msgsnd      69
#define SYS_msgget      68
#define SYS_msgctl      71
/* POSIX message queues (Linux x86_64: 240-245) */
#define SYS_mq_open         240
#define SYS_mq_unlink       241
#define SYS_mq_timedsend    242
#define SYS_mq_timedreceive 243
#define SYS_mq_notify       244
#define SYS_mq_getsetattr   245

/* Capability-based syscall numbers (SYS_open_cap, etc.) are defined in
 * kernel/syscalls.h to avoid duplication */

/* Legacy utime (Linux x86_64: 132) */
#define SYS_utime            132

/* Legacy getdents / swap / ioport (Linux x86_64) */
#define SYS_getdents         78
#define SYS_swapon           167
#define SYS_swapoff          168
#define SYS_iopl             172
#define SYS_ioperm           173

/* Linux AIO (Linux x86_64: 206-210) */
#define SYS_io_setup         206
#define SYS_io_destroy       207
#define SYS_io_getevents     208
#define SYS_io_submit        209
#define SYS_io_cancel        210

/* io_uring (Linux x86_64: 425-427) */
#define SYS_io_uring_setup   425
#define SYS_io_uring_enter   426
#define SYS_io_uring_register 427

#define MAX_SYSCALL     512

/* ============================================================
 *   Socket FD Mapping System
 * ============================================================ */

/** Maximum number of socket file descriptors per task */
#define MAX_SOCKET_FDS 256

/** Per-task socket FD table mapping FDs to kernel socket objects */
static fut_socket_t *socket_fd_table[MAX_SOCKET_FDS] = {NULL};

/** Owner tid for each socket fd - prevents cross-process socket closes */
static uint64_t socket_fd_owner[MAX_SOCKET_FDS] = {0};

/* Get current thread ID for socket ownership checks */
#include "../../include/kernel/fut_percpu.h"

/* ============================================================
 *   Socket File Operations for VFS Integration
 * ============================================================ */

/**
 * Socket read operation - called via VFS read() syscall
 * The socket pointer is stored in private_data
 */
static ssize_t socket_read(void *inode, void *private_data, void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    /* AF_NETLINK: drain pending response buffer */
    if (socket->address_family == 16 /* AF_NETLINK */) {
        extern ssize_t netlink_handle_recv(fut_socket_t *sock, void *out_buf, size_t out_len);
        return netlink_handle_recv(socket, u_buf, n);
    }
    /* Named DGRAM sockets (no stream pair): use datagram queue for read */
    if (socket->socket_type == SOCK_DGRAM && !socket->pair && socket->dgram_queue) {
        return fut_socket_recvfrom_dgram(socket, u_buf, n, NULL, NULL, NULL);
    }
    ssize_t result = fut_socket_recv(socket, u_buf, n);
    return result;
}

/**
 * Socket write operation - called via VFS write() syscall
 * The socket pointer is stored in private_data
 */
static ssize_t socket_write(void *inode, void *private_data, const void *u_buf, size_t n, off_t *pos) {
    (void)inode;
    (void)pos;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    /* AF_NETLINK: parse request and build response */
    if (socket->address_family == 16 /* AF_NETLINK */) {
        extern ssize_t netlink_handle_send(fut_socket_t *sock,
                                           const void *iov_base, size_t iov_len,
                                           ssize_t total_len);
        return netlink_handle_send(socket, u_buf, n, (ssize_t)n);
    }
    /* Enforce shutdown(SHUT_WR) before any send path */
    if (socket->shutdown_wr)
        return -EPIPE;
    /* Named DGRAM sockets (no stream pair): route write() via the dgram path */
    if (socket->socket_type == SOCK_DGRAM && !socket->pair) {
        if (socket->dgram_peer_path_len == 0)
            return -EDESTADDRREQ;
        return fut_socket_sendto_dgram(socket->dgram_peer_path, socket->dgram_peer_path_len,
                                       socket->bound_path, socket->bound_path_len,
                                       u_buf, n);
    }
    ssize_t result = fut_socket_send(socket, u_buf, n);
    return result;
}

/**
 * Socket release operation - called when FD is closed
 * The socket pointer is stored in private_data
 */
static int socket_release(void *inode, void *private_data) {
    (void)inode;
    fut_socket_t *socket = (fut_socket_t *)private_data;
    if (!socket) {
        return -EBADF;
    }
    return fut_socket_close(socket);
}

/**
 * Socket ioctl handler - propagates file flags from fcntl.
 */
static int socket_ioctl(void *inode, void *private_data, unsigned long req, unsigned long arg) {
    (void)inode;
    if (req == 0xFE01 /* IOC_SETFLAGS */) {
        fut_socket_t *socket = (fut_socket_t *)private_data;
        if (socket) {
            if ((int)arg & 0x800 /* O_NONBLOCK */) {
                socket->flags |= 0x800;
            } else {
                socket->flags &= ~0x800;
            }
        }
        return 0;
    }
    return -EINVAL;
}

/** Socket file operations for VFS integration */
static struct fut_file_ops socket_fops = {
    .open = NULL,
    .release = socket_release,
    .read = socket_read,
    .write = socket_write,
    .ioctl = socket_ioctl,
    .mmap = NULL
};

/* SysV shared memory handlers */
static int64_t sys_shmget_handler(uint64_t key, uint64_t size, uint64_t shmflg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shmget(long key, size_t size, int shmflg);
    return sys_shmget((long)key, (size_t)size, (int)shmflg);
}

static int64_t sys_shmat_handler(uint64_t shmid, uint64_t shmaddr, uint64_t shmflg,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shmat(int shmid, const void *shmaddr, int shmflg);
    return sys_shmat((int)shmid, (const void *)(uintptr_t)shmaddr, (int)shmflg);
}

static int64_t sys_shmdt_handler(uint64_t shmaddr, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shmdt(const void *shmaddr);
    return sys_shmdt((const void *)(uintptr_t)shmaddr);
}

static int64_t sys_shmctl_handler(uint64_t shmid, uint64_t cmd, uint64_t buf,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shmctl(int shmid, int cmd, void *buf);
    return sys_shmctl((int)shmid, (int)cmd, (void *)(uintptr_t)buf);
}

/* SysV semaphore handlers */
static int64_t sys_semget_handler(uint64_t key, uint64_t nsems, uint64_t semflg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_semget(long key, int nsems, int semflg);
    return sys_semget((long)key, (int)nsems, (int)semflg);
}

static int64_t sys_semop_handler(uint64_t semid, uint64_t sops, uint64_t nsops,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_semop(int semid, void *sops, unsigned int nsops);
    return sys_semop((int)semid, (void *)(uintptr_t)sops, (unsigned int)nsops);
}

static int64_t sys_semctl_handler(uint64_t semid, uint64_t semnum, uint64_t cmd,
                                  uint64_t arg, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
    return sys_semctl((int)semid, (int)semnum, (int)cmd, (unsigned long)arg);
}

static int64_t sys_semtimedop_handler(uint64_t semid, uint64_t sops, uint64_t nsops,
                                      uint64_t timeout, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_semtimedop(int semid, void *sops, unsigned int nsops,
                               const void *timeout);
    return sys_semtimedop((int)semid, (void *)(uintptr_t)sops, (unsigned int)nsops,
                          (const void *)(uintptr_t)timeout);
}

static int64_t sys_msgget_handler(uint64_t key, uint64_t msgflg, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_msgget(long key, int msgflg);
    return sys_msgget((long)key, (int)msgflg);
}

static int64_t sys_msgsnd_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgflg, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);
    return sys_msgsnd((int)msqid, (const void *)(uintptr_t)msgp, (size_t)msgsz, (int)msgflg);
}

static int64_t sys_msgrcv_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgtyp, uint64_t msgflg, uint64_t arg6) {
    (void)arg6;
    extern long sys_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
    return sys_msgrcv((int)msqid, (void *)(uintptr_t)msgp, (size_t)msgsz,
                      (long)msgtyp, (int)msgflg);
}

static int64_t sys_msgctl_handler(uint64_t msqid, uint64_t cmd, uint64_t buf,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_msgctl(int msqid, int cmd, void *buf);
    return sys_msgctl((int)msqid, (int)cmd, (void *)(uintptr_t)buf);
}

/* POSIX message queue handlers */

/* mq_attr ABI structure (must match sys_mqueue.c) */
struct posix_mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
    long __pad[4];
};

extern long sys_mq_open(const char *name, int oflag, unsigned int mode,
                        const struct posix_mq_attr *attr);
extern long sys_mq_unlink(const char *name);
extern long sys_mq_timedsend(int mqdes, const char *msg_ptr, size_t msg_len,
                             unsigned msg_prio, const void *abs_timeout);
extern long sys_mq_timedreceive(int mqdes, char *msg_ptr, size_t msg_len,
                                unsigned *msg_prio, const void *abs_timeout);
extern long sys_mq_notify(int mqdes, const void *sevp);
extern long sys_mq_getsetattr(int mqdes, const struct posix_mq_attr *newattr,
                              struct posix_mq_attr *oldattr);

static int64_t sys_mq_open_handler(uint64_t name, uint64_t oflag, uint64_t mode,
                                   uint64_t attr, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    return sys_mq_open((const char *)(uintptr_t)name, (int)oflag,
                       (unsigned int)mode,
                       (const struct posix_mq_attr *)(uintptr_t)attr);
}

static int64_t sys_mq_unlink_handler(uint64_t name, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_unlink((const char *)(uintptr_t)name);
}

static int64_t sys_mq_timedsend_handler(uint64_t mqdes, uint64_t msg_ptr, uint64_t msg_len,
                                        uint64_t msg_prio, uint64_t abs_timeout, uint64_t arg6) {
    (void)arg6;
    return sys_mq_timedsend((int)mqdes, (const char *)(uintptr_t)msg_ptr,
                            (size_t)msg_len, (unsigned)msg_prio,
                            (const void *)(uintptr_t)abs_timeout);
}

static int64_t sys_mq_timedreceive_handler(uint64_t mqdes, uint64_t msg_ptr, uint64_t msg_len,
                                           uint64_t msg_prio, uint64_t abs_timeout, uint64_t arg6) {
    (void)arg6;
    return sys_mq_timedreceive((int)mqdes, (char *)(uintptr_t)msg_ptr,
                               (size_t)msg_len, (unsigned *)(uintptr_t)msg_prio,
                               (const void *)(uintptr_t)abs_timeout);
}

static int64_t sys_mq_notify_handler(uint64_t mqdes, uint64_t sevp, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_notify((int)mqdes, (const void *)(uintptr_t)sevp);
}

static int64_t sys_mq_getsetattr_handler(uint64_t mqdes, uint64_t newattr, uint64_t oldattr,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    return sys_mq_getsetattr((int)mqdes,
                             (const struct posix_mq_attr *)(uintptr_t)newattr,
                             (struct posix_mq_attr *)(uintptr_t)oldattr);
}

static inline uint64_t get_current_tid(void) {
    fut_percpu_t *percpu = fut_percpu_get();
    if (percpu && percpu->current_thread) {
        return percpu->current_thread->tid;
    }
    return 0;
}

/**
 * Get a kernel socket object from a file descriptor.
 * Returns NULL if FD is invalid, not a socket, or belongs to another process.
 */
fut_socket_t *get_socket_from_fd(int fd) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return NULL;
    }
    if (socket_fd_table[fd] == NULL) {
        return NULL;
    }
    /* Note: ownership check removed. VFS fd_table provides per-task isolation,
     * and release_socket_fd() in fut_vfs_close clears stale entries. The old
     * ownership check broke fork() — child inherited VFS fds but couldn't
     * access parent's socket_fd_table entries due to different thread IDs. */
    return socket_fd_table[fd];
}

/**
 * Store a kernel socket object for a file descriptor.
 * Returns 0 on success, -1 if FD is invalid.
 */
static inline int set_socket_for_fd(int fd, fut_socket_t *socket) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return -1;
    }
    socket_fd_table[fd] = socket;
    return 0;
}

/**
 * Find next available file descriptor for a socket.
 * Returns FD number (>=0) on success, -1 if no space.
 *
 * Uses chrdev_alloc_fd() to register the socket in VFS file table,
 * enabling VFS read/write/close operations to work on socket FDs.
 * The socket pointer is stored as private_data and used by socket_fops.
 */
int allocate_socket_fd(fut_socket_t *socket) {
    /* Use chrdev_alloc_fd to register socket in VFS file table */
    int fd = chrdev_alloc_fd(&socket_fops, NULL, socket);
    if (fd < 0) {
        return fd;  /* Return error code from chrdev_alloc_fd */
    }

    /* Also track in socket_fd_table for get_socket_from_fd() lookups */
    uint64_t tid = get_current_tid();
    if (fd < MAX_SOCKET_FDS) {
        socket_fd_table[fd] = socket;
        socket_fd_owner[fd] = tid;
    }

    return fd;
}

/**
 * Release a socket FD and cleanup the tracking table entry.
 * NOTE: The actual socket close is handled by VFS via socket_release()
 * when using chrdev_alloc_fd. This function just clears the tracking table.
 */
int release_socket_fd(int fd) {
    if (fd < 0 || fd >= MAX_SOCKET_FDS) {
        return -EBADF;
    }

    /* Just clear the tracking table entry - VFS handles actual socket close */
    socket_fd_table[fd] = NULL;
    socket_fd_owner[fd] = 0;

    return 0;
}

/**
 * Propagate socket ownership when a file descriptor is duplicated (dup/dup2).
 * If oldfd refers to a socket, newfd also needs to be tracked as a socket
 * with the same ownership.
 *
 * @param oldfd Source file descriptor
 * @param newfd Target file descriptor (the duplicate)
 * @return 0 on success (even if not a socket), negative on error
 */
int propagate_socket_dup(int oldfd, int newfd) {
    if (oldfd < 0 || oldfd >= MAX_SOCKET_FDS || newfd < 0 || newfd >= MAX_SOCKET_FDS) {
        return 0;  /* Out of range for socket table, not an error */
    }

    /* Check if oldfd is a socket */
    if (socket_fd_table[oldfd] == NULL) {
        return 0;  /* Not a socket, nothing to propagate */
    }

    /* Propagate socket and ownership to newfd */
    socket_fd_table[newfd] = socket_fd_table[oldfd];
    socket_fd_owner[newfd] = socket_fd_owner[oldfd];

    /* Increment socket refcount since we now have two FDs referring to it */
    fut_socket_ref(socket_fd_table[oldfd]);

    return 0;
}

/* ============================================================
 *   Syscall Handler Type
 * ============================================================ */

typedef int64_t (*syscall_handler_t)(uint64_t arg1, uint64_t arg2,
                                      uint64_t arg3, uint64_t arg4,
                                      uint64_t arg5, uint64_t arg6);

extern ssize_t sys_echo(const char *u_in, char *u_out, size_t n);
extern long sys_exit(int status);
extern long sys_waitpid(int pid, int *u_status, int flags);
extern long sys_nanosleep(const fut_timespec_t *u_req, fut_timespec_t *u_rem);
extern long sys_time_millis(void);
extern long sys_pipe(int pipefd[2]);
extern long sys_dup2(int oldfd, int newfd);
extern long sys_chdir(const char *path);
extern long sys_getcwd(char *buf, size_t size);
extern long sys_eventfd2(unsigned int initval, int flags);
extern long sys_epoll_create1(int flags);

/* Helpers for missing syscalls */
extern int chrdev_alloc_fd(const struct fut_file_ops *ops, void *inode, void *priv);
extern struct fut_file *vfs_get_file(int fd);
extern int vfs_alloc_specific_fd(int target_fd, struct fut_file *file);
extern void vfs_file_ref(struct fut_file *file);
extern int fut_vfs_close(int fd);

static int64_t sys_echo_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_echo((const char *)arg1, (char *)arg2, (size_t)arg3);
}

static int64_t sys_pipe_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_pipe((int *)arg1);
}

static int64_t sys_dup2_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_dup2((int)arg1, (int)arg2);
}

static int64_t sys_eventfd2_handler(uint64_t initval, uint64_t flags, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3;
    (void)arg4;
    (void)arg5;
    (void)arg6;
    return (int64_t)sys_eventfd2((unsigned int)initval, (int)flags);
}

static int64_t sys_poll_handler(uint64_t fds, uint64_t nfds, uint64_t timeout,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4;
    (void)arg5;
    (void)arg6;
    extern long sys_poll(struct pollfd *fds, unsigned long nfds, int timeout);
    return sys_poll((struct pollfd *)(uintptr_t)fds, (unsigned long)nfds, (int)timeout);
}

int copy_user_string(const char *u_path, char *kbuf, size_t max_len) {
    /* Kernel-pointer bypass: when called from kernel selftests, the pointer
     * is already in kernel space and fut_copy_from_user would reject it.
     * x86_64 kernel base: 0xFFFFFFFF80000000; ARM64: 0xFFFF800000000000 */
#if defined(__x86_64__)
#define _COPY_USER_STRING_KBASE 0xFFFFFFFF80000000ULL
#elif defined(__aarch64__)
#define _COPY_USER_STRING_KBASE 0xFFFF800000000000ULL
#else
#define _COPY_USER_STRING_KBASE 0ULL
#endif
    if (_COPY_USER_STRING_KBASE && (uintptr_t)u_path >= _COPY_USER_STRING_KBASE) {
        const char *p = u_path;
        for (size_t i = 0; i < max_len; i++) {
            kbuf[i] = p[i];
            if (p[i] == '\0') return 0;
        }
        return -ENAMETOOLONG;
    }
#undef _COPY_USER_STRING_KBASE
    for (size_t i = 0; i < max_len; ++i) {
        char ch = 0;
        if (fut_copy_from_user(&ch, u_path + i, 1) != 0) {
            return -EFAULT;
        }
        kbuf[i] = ch;
        if (ch == '\0') {
            return 0;
        }
    }
    return -ENAMETOOLONG;
}

static int64_t sys_open_handler(uint64_t pathname, uint64_t flags, uint64_t mode,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_open(const char *pathname, int flags, int mode);
    return sys_open((const char *)(uintptr_t)pathname, (int)flags, (int)mode);
}

static int64_t sys_openat_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                  uint64_t mode, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_openat(int dirfd, const char *pathname, int flags, int mode);
    return sys_openat((int)dirfd, (const char *)(uintptr_t)pathname, (int)flags, (int)mode);
}

static int64_t sys_openat2_handler(uint64_t dirfd, uint64_t path, uint64_t how,
                                   uint64_t usize, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    struct open_how_s { uint64_t flags; uint64_t mode; uint64_t resolve; };
    extern long sys_openat2(int dirfd, const char *path, const void *how, size_t usize);
    return (int64_t)sys_openat2((int)dirfd, (const char *)(uintptr_t)path,
                                 (const void *)(uintptr_t)how, (size_t)usize);
}

/* *at family syscall handlers */
static int64_t sys_mkdirat_handler(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mkdirat(int dirfd, const char *pathname, unsigned int mode);
    return sys_mkdirat((int)dirfd, (const char *)(uintptr_t)pathname, (unsigned int)mode);
}

static int64_t sys_mknodat_handler(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                   uint64_t dev, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_mknodat(int dirfd, const char *pathname, uint32_t mode, uint32_t dev);
    return sys_mknodat((int)dirfd, (const char *)(uintptr_t)pathname, (uint32_t)mode, (uint32_t)dev);
}

static int64_t sys_mknod_handler(uint64_t pathname, uint64_t mode, uint64_t dev,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mknod(const char *pathname, uint32_t mode, uint32_t dev);
    return sys_mknod((const char *)(uintptr_t)pathname, (uint32_t)mode, (uint32_t)dev);
}

static int64_t sys_fchownat_handler(uint64_t dirfd, uint64_t pathname, uint64_t uid,
                                    uint64_t gid, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_fchownat(int dirfd, const char *pathname, uint32_t uid, uint32_t gid, int flags);
    return sys_fchownat((int)dirfd, (const char *)(uintptr_t)pathname,
                        (uint32_t)uid, (uint32_t)gid, (int)flags);
}

static int64_t sys_fstatat_handler(uint64_t dirfd, uint64_t pathname, uint64_t statbuf,
                                   uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_fstatat(int dirfd, const char *pathname, void *statbuf, int flags);
    return sys_fstatat((int)dirfd, (const char *)(uintptr_t)pathname, (void *)(uintptr_t)statbuf, (int)flags);
}

static int64_t sys_unlinkat_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_unlinkat(int dirfd, const char *pathname, int flags);
    return sys_unlinkat((int)dirfd, (const char *)(uintptr_t)pathname, (int)flags);
}

static int64_t sys_renameat_handler(uint64_t olddirfd, uint64_t oldpath, uint64_t newdirfd,
                                    uint64_t newpath, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
    return sys_renameat((int)olddirfd, (const char *)(uintptr_t)oldpath,
                        (int)newdirfd, (const char *)(uintptr_t)newpath);
}

static int64_t sys_renameat2_handler(uint64_t olddirfd, uint64_t oldpath, uint64_t newdirfd,
                                     uint64_t newpath, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                               const char *newpath, unsigned int flags);
    return sys_renameat2((int)olddirfd, (const char *)(uintptr_t)oldpath,
                         (int)newdirfd, (const char *)(uintptr_t)newpath,
                         (unsigned int)flags);
}

static int64_t sys_linkat_handler(uint64_t olddirfd, uint64_t oldpath, uint64_t newdirfd,
                                  uint64_t newpath, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
    return sys_linkat((int)olddirfd, (const char *)(uintptr_t)oldpath,
                      (int)newdirfd, (const char *)(uintptr_t)newpath, (int)flags);
}

static int64_t sys_symlinkat_handler(uint64_t target, uint64_t newdirfd, uint64_t linkpath,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_symlinkat(const char *target, int newdirfd, const char *linkpath);
    return sys_symlinkat((const char *)(uintptr_t)target, (int)newdirfd,
                         (const char *)(uintptr_t)linkpath);
}

static int64_t sys_readlinkat_handler(uint64_t dirfd, uint64_t pathname, uint64_t buf,
                                      uint64_t bufsiz, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
    return sys_readlinkat((int)dirfd, (const char *)(uintptr_t)pathname,
                          (char *)(uintptr_t)buf, (size_t)bufsiz);
}

static int64_t sys_fchmodat_handler(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                    uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_fchmodat(int dirfd, const char *pathname, uint32_t mode, int flags);
    return sys_fchmodat((int)dirfd, (const char *)(uintptr_t)pathname, (uint32_t)mode, (int)flags);
}

static int64_t sys_faccessat_handler(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                     uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_faccessat(int dirfd, const char *pathname, int mode, int flags);
    return sys_faccessat((int)dirfd, (const char *)(uintptr_t)pathname, (int)mode, (int)flags);
}

static int64_t sys_utimensat_handler(uint64_t dirfd, uint64_t pathname, uint64_t times,
                                     uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_utimensat(int dirfd, const char *pathname, const fut_timespec_t *times, int flags);
    return sys_utimensat((int)dirfd, (const char *)(uintptr_t)pathname,
                         (const fut_timespec_t *)(uintptr_t)times, (int)flags);
}

static int64_t sys_close_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_close(int fd);
    return sys_close((int)fd);
}

static int64_t sys_write_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_write(int fd, const void *buf, size_t count);
    return sys_write((int)fd, (const void *)buf, (size_t)count);
}

static int64_t sys_read_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_read(int fd, void *buf, size_t count);
    return sys_read((int)fd, (void *)buf, (size_t)count);
}

static int64_t sys_pread64_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                   uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5;
    (void)arg6;
    /* Use kernel sys_pread64 for position-based reading */
    return sys_pread64((unsigned int)fd, (void *)buf, (size_t)count, (int64_t)offset);
}

static int64_t sys_pwrite64_handler(uint64_t fd, uint64_t buf, uint64_t count,
                                    uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5;
    (void)arg6;
    /* Use kernel sys_pwrite64 for position-based writing */
    return sys_pwrite64((unsigned int)fd, (const void *)buf, (size_t)count, (int64_t)offset);
}

static int64_t sys_readv_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_readv(int fd, const struct iovec *iov, int iovcnt);
    return (int64_t)sys_readv((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt);
}

static int64_t sys_writev_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt);
    return (int64_t)sys_writev((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt);
}

static int64_t sys_preadv_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                  uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern ssize_t sys_preadv(int fd, const struct iovec *iov, int iovcnt, int64_t offset);
    return (int64_t)sys_preadv((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt, (int64_t)offset);
}

static int64_t sys_pwritev_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                   uint64_t offset, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern ssize_t sys_pwritev(int fd, const struct iovec *iov, int iovcnt, int64_t offset);
    return (int64_t)sys_pwritev((int)fd, (const struct iovec *)(uintptr_t)iov, (int)iovcnt, (int64_t)offset);
}

static int64_t sys_preadv2_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                   uint64_t offset, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern ssize_t sys_preadv2(int fd, const struct iovec *iov, int iovcnt,
                               int64_t offset, int flags);
    return (int64_t)sys_preadv2((int)fd, (const struct iovec *)(uintptr_t)iov,
                                 (int)iovcnt, (int64_t)offset, (int)flags);
}

static int64_t sys_pwritev2_handler(uint64_t fd, uint64_t iov, uint64_t iovcnt,
                                    uint64_t offset, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern ssize_t sys_pwritev2(int fd, const struct iovec *iov, int iovcnt,
                                int64_t offset, int flags);
    return (int64_t)sys_pwritev2((int)fd, (const struct iovec *)(uintptr_t)iov,
                                  (int)iovcnt, (int64_t)offset, (int)flags);
}

static int64_t sys_ioctl_handler(uint64_t fd, uint64_t req, uint64_t argp,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_ioctl(int fd, unsigned long request, void *argp);
    return sys_ioctl((int)fd, (unsigned long)req, (void *)argp);
}

static int64_t sys_mmap_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                uint64_t flags, uint64_t fd, uint64_t off) {
    fut_printf("[MMAP-HANDLER] addr=0x%llx len=%llu prot=%llu flags=%llu fd=%llu off=%llu\n",
               (unsigned long long)addr, (unsigned long long)len,
               (unsigned long long)prot, (unsigned long long)flags,
               (unsigned long long)fd, (unsigned long long)off);
    return sys_mmap((void *)addr, (size_t)len, (int)prot, (int)flags, (int)fd, (long)off);
}

/* ============================================================
 *   Syscall Handlers (Wrappers)
 * ============================================================ */

/* File I/O */
/* File metadata */
static int64_t sys_stat_handler(uint64_t pathname, uint64_t statbuf, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_stat which works with fut_stat structures */
    struct fut_stat *stat_ptr = (struct fut_stat *)statbuf;
    return sys_stat((const char *)pathname, stat_ptr);
}

static int64_t sys_fstat_handler(uint64_t fd, uint64_t statbuf, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* Check if this FD is a socket */
    fut_socket_t *socket = get_socket_from_fd((int)fd);
    if (socket) {
        /* Return fake stat info for socket - just mark it as a valid file */
        struct fut_stat kernel_stat = {0};
        kernel_stat.st_mode = 0140000;  /* S_IFSOCK */
        kernel_stat.st_size = 0;
        kernel_stat.st_ino = socket->socket_id;

        if (fut_copy_to_user((struct fut_stat *)statbuf, &kernel_stat,
                             sizeof(struct fut_stat)) != 0) {
            return -EFAULT;
        }
        return 0;
    }

    /* Use kernel sys_fstat for regular files */
    return sys_fstat((int)fd, (struct fut_stat *)statbuf);
}

static int64_t sys_lstat_handler(uint64_t pathname, uint64_t statbuf, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_lstat(const char *path, struct fut_stat *statbuf);
    return sys_lstat((const char *)pathname, (struct fut_stat *)statbuf);
}

/* Process management */
static int64_t sys_fork_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_fork();
}

/* clone() — Linux process/thread creation syscall.
 * glibc/musl use clone(SIGCHLD, 0, ...) to implement fork().
 * clone3() (syscall 435) is the newer interface; also handled here. */

/* TID-management flags that are compatible with fork paths */
#define CLONE_SETTLS_          0x00080000ULL
#define CLONE_PARENT_SETTID_   0x00100000ULL
#define CLONE_CHILD_CLEARTID_  0x00200000ULL
#define CLONE_CHILD_SETTID_    0x01000000ULL
#define CLONE_TID_FLAGS_       (CLONE_SETTLS_ | CLONE_PARENT_SETTID_ | \
                                CLONE_CHILD_CLEARTID_ | CLONE_CHILD_SETTID_)

static inline int clone_copy_to_user(void *dst, const void *src, size_t n) {
#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)dst >= KERNEL_VIRTUAL_BASE) { __builtin_memcpy(dst, src, n); return 0; }
#endif
    return fut_copy_to_user(dst, src, n);
}

/**
 * clone_apply_tid_flags — handle CLONE_PARENT_SETTID, CLONE_CHILD_SETTID,
 * and CLONE_CHILD_CLEARTID after a fork.  Called in both parent and child.
 */
static int64_t clone_do_fork_with_flags(uint64_t clone_flags, uint64_t parent_tid,
                                         uint64_t child_tid) {
    long pid = posix_fork();
    if (pid < 0)
        return (int64_t)pid;

    if (pid > 0) {
        /* Parent context */

        /* CLONE_PARENT: reparent child to caller's parent */
        if (clone_flags & 0x00008000ULL /* CLONE_PARENT */) {
            extern fut_task_t *fut_task_current(void);
            extern fut_task_t *fut_task_by_pid(uint64_t pid);
            extern void fut_task_reparent(fut_task_t *child, fut_task_t *new_parent);
            fut_task_t *caller = fut_task_current();
            if (caller && caller->parent) {
                fut_task_t *child = fut_task_by_pid((uint64_t)pid);
                if (child)
                    fut_task_reparent(child, caller->parent);
            }
        }

        if ((clone_flags & CLONE_PARENT_SETTID_) && parent_tid) {
            int tid_val = (int)pid;
            clone_copy_to_user((void *)(uintptr_t)parent_tid,
                               &tid_val, sizeof(tid_val));
        }
    } else {
        /* Child context */
        extern fut_task_t *fut_task_current(void);
        fut_task_t *task = fut_task_current();
        if (task) {
            /* Set exit_signal from the low byte of clone flags.
             * clone(SIGCHLD, ...) → exit_signal=17; clone(0, ...) → keep default SIGCHLD. */
            int esig = (int)(clone_flags & 0xFFULL);
            if (esig > 0 && esig < _NSIG)
                task->exit_signal = esig;
        }
        if ((clone_flags & CLONE_CHILD_SETTID_) && child_tid && task) {
            int tid_val = (int)task->pid;
            clone_copy_to_user((void *)(uintptr_t)child_tid,
                               &tid_val, sizeof(tid_val));
        }
        if ((clone_flags & CLONE_CHILD_CLEARTID_) && child_tid && task) {
            task->clear_child_tid = (void *)(uintptr_t)child_tid;
        }
    }
    return (int64_t)pid;
}

static int64_t sys_clone_handler(uint64_t flags, uint64_t stack, uint64_t parent_tid,
                                  uint64_t child_tid, uint64_t tls, uint64_t arg6) {
    (void)arg6;
    uint64_t clone_flags = flags & ~0xFFULL;  /* Strip exit-signal from low byte */

    /* Thread creation: CLONE_THREAD (bit 16) set */
    if (clone_flags & 0x10000ULL /* CLONE_THREAD */) {
        extern long sys_clone_thread(uint64_t flags, uint64_t child_stack,
                                      uint64_t parent_tid_ptr, uint64_t child_tid_ptr,
                                      uint64_t tls);
        return (int64_t)sys_clone_thread(flags, stack, parent_tid, child_tid, tls);
    }

    /* Strip TID-management flags — these are handled after fork by clone_do_fork_with_flags */
    uint64_t structural_flags = clone_flags & ~CLONE_TID_FLAGS_;

    /* Plain fork: clone(SIGCHLD, 0, NULL, NULL, 0) — most common from libc fork().
     * Also covers glibc < 2.34 fork(): clone(CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD) */
    if (structural_flags == 0)
        return clone_do_fork_with_flags(flags, parent_tid, child_tid);

    /* vfork pattern: CLONE_VM (0x100) + CLONE_VFORK (0x4000) without CLONE_THREAD.
     * Used by musl vfork() and posix_spawn(). Futura has no separate address spaces,
     * so CLONE_VM is a no-op — fall back to regular fork without blocking the parent.
     * The child runs in its own task context and the parent continues concurrently. */
    if (structural_flags & 0x4000ULL /* CLONE_VFORK */) {
        return clone_do_fork_with_flags(flags, parent_tid, child_tid);
    }

    /* CLONE_VM without CLONE_THREAD and without CLONE_VFORK: also fall back to fork.
     * This covers clone(CLONE_VM|SIGCHLD) used by some threading libraries. */
    if (structural_flags == 0x100ULL /* CLONE_VM only */) {
        return clone_do_fork_with_flags(flags, parent_tid, child_tid);
    }

    /* Resource-sharing flags without structural flags (no CLONE_THREAD, no namespaces,
     * no CLONE_NEWNS/NEWPID/etc.): treat as fork.  Futura copies the FD table and FS
     * state on fork anyway, so CLONE_FILES (0x400), CLONE_FS (0x200), CLONE_SIGHAND
     * (0x800), CLONE_IO (0x80000000), CLONE_SYSVSEM (0x40000) are safe no-ops.
     * This covers posix_spawn implementations that pass CLONE_FILES|CLONE_FS|SIGCHLD. */
#define CLONE_FORK_COMPAT_MASK (0x100ULL   /* CLONE_VM */     | \
                                 0x200ULL   /* CLONE_FS */     | \
                                 0x400ULL   /* CLONE_FILES */  | \
                                 0x800ULL   /* CLONE_SIGHAND */| \
                                 0x8000ULL  /* CLONE_PARENT */ | \
                                 0x40000ULL /* CLONE_SYSVSEM */| \
                                 0x80000000ULL /* CLONE_IO */)
    if ((structural_flags & ~CLONE_FORK_COMPAT_MASK) == 0) {
        return clone_do_fork_with_flags(flags, parent_tid, child_tid);
    }
#undef CLONE_FORK_COMPAT_MASK

    /* Unhandled clone flags (new namespaces, etc.) */
    fut_printf("[CLONE] clone(flags=0x%llx) -> ENOSYS (unhandled clone flags)\n",
               (unsigned long long)flags);
    return -38;  /* -ENOSYS */
}

/* clone3() — newer clone interface using struct clone_args (Linux 5.3+) */
static int64_t sys_clone3_handler(uint64_t cl_args, uint64_t size, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_clone3(const void *uargs, size_t size);
    return sys_clone3((const void *)(uintptr_t)cl_args, (size_t)size);
}

static int64_t sys_execve_handler(uint64_t pathname, uint64_t argv, uint64_t envp,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)posix_execve((const char *)pathname, (char *const *)argv,
                                  (char *const *)envp);
}

static int64_t sys_execveat_handler(uint64_t dirfd, uint64_t pathname, uint64_t argv,
                                     uint64_t envp, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_execveat(int dirfd, const char *pathname,
                             char *const argv[], char *const envp[], int flags);
    return (int64_t)sys_execveat((int)dirfd, (const char *)pathname,
                                  (char *const *)argv, (char *const *)envp, (int)flags);
}

static int64_t sys_exit_handler(uint64_t status, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    sys_exit((int)status);
    return 0;
}

static int64_t sys_wait4_handler(uint64_t pid, uint64_t status, uint64_t options,
                                   uint64_t rusage, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_wait4(int pid, int *u_status, int flags, void *rusage_ptr);
    return (int64_t)sys_wait4((int)pid, (int *)(uintptr_t)status, (int)options,
                               (void *)(uintptr_t)rusage);
}

static int64_t sys_nanosleep_handler(uint64_t req, uint64_t rem, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return (int64_t)sys_nanosleep((const fut_timespec_t *)(uintptr_t)req,
                                  (fut_timespec_t *)(uintptr_t)rem);
}

static int64_t sys_alarm_handler(uint64_t seconds, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_alarm(unsigned int seconds);
    return sys_alarm((unsigned int)seconds);
}

static int64_t sys_pause_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pause(void);
    return sys_pause();
}

static int64_t sys_sched_yield_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_yield(void);
    return sys_sched_yield();
}

static int64_t sys_getpriority_handler(uint64_t which, uint64_t who, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpriority(int which, int who);
    return sys_getpriority((int)which, (int)who);
}

static int64_t sys_setpriority_handler(uint64_t which, uint64_t who, uint64_t prio,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setpriority(int which, int who, int prio);
    return sys_setpriority((int)which, (int)who, (int)prio);
}

static int64_t sys_getrusage_handler(uint64_t who, uint64_t usage, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getrusage(int who, struct rusage *usage);
    return sys_getrusage((int)who, (struct rusage *)(uintptr_t)usage);
}

static int64_t sys_times_handler(uint64_t buf, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_times(struct tms *buf);
    return sys_times((struct tms *)(uintptr_t)buf);
}

static int64_t sys_time_millis_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_time_millis();
}

static int64_t sys_mkdir_handler(uint64_t pathname, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';
    return (int64_t)fut_vfs_mkdir(path_buf, (uint32_t)mode);
}

static int64_t sys_rmdir_handler(uint64_t pathname, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';
    return (int64_t)fut_vfs_rmdir(path_buf);
}

static int64_t sys_unlink_handler(uint64_t pathname, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* Copy pathname from userspace to kernel space */
    char path_buf[256];
    if (fut_copy_from_user(path_buf, (const void *)pathname, sizeof(path_buf) - 1) != 0) {
        return -EFAULT;
    }
    path_buf[sizeof(path_buf) - 1] = '\0';  /* Ensure null termination */

    return (int64_t)fut_vfs_unlink(path_buf);
}

/* Hard link creation */
static int64_t sys_link_handler(uint64_t oldpath, uint64_t newpath, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_link((const char *)oldpath, (const char *)newpath);
}

/* Symbolic link creation */
static int64_t sys_symlink_handler(uint64_t target, uint64_t linkpath, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_symlink((const char *)target, (const char *)linkpath);
}

/* Symbolic link reading */
static int64_t sys_readlink_handler(uint64_t pathname, uint64_t buf, uint64_t bufsiz,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    return sys_readlink((const char *)pathname, (char *)buf, (size_t)bufsiz);
}

/* File truncation */
static int64_t sys_ftruncate_handler(uint64_t fd, uint64_t length, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_ftruncate for file truncation */
    return sys_ftruncate((int)fd, (uint64_t)length);
}

/* Memory management */
static int64_t sys_brk_handler(uint64_t addr, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_brk((uintptr_t)addr);
}

static int64_t sys_munmap_handler(uint64_t addr, uint64_t len, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_munmap((void *)addr, (size_t)len);
}

static int64_t sys_mprotect_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mprotect(void *addr, size_t len, int prot);
    return sys_mprotect((void *)addr, (size_t)len, (int)prot);
}

static int64_t sys_pkey_mprotect_handler(uint64_t addr, uint64_t len, uint64_t prot,
                                          uint64_t pkey, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_pkey_mprotect(void *addr, size_t len, int prot, int pkey);
    return sys_pkey_mprotect((void *)addr, (size_t)len, (int)prot, (int)pkey);
}

static int64_t sys_pkey_alloc_handler(uint64_t flags, uint64_t access_rights,
                                       uint64_t arg3, uint64_t arg4,
                                       uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pkey_alloc(unsigned int flags, unsigned int access_rights);
    return sys_pkey_alloc((unsigned int)flags, (unsigned int)access_rights);
}

static int64_t sys_pkey_free_handler(uint64_t pkey, uint64_t arg2, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pkey_free(int pkey);
    return sys_pkey_free((int)pkey);
}

static int64_t sys_mremap_handler(uint64_t old_addr, uint64_t old_size, uint64_t new_size,
                                  uint64_t flags, uint64_t new_addr, uint64_t arg6) {
    (void)arg6;
    extern long sys_mremap(void *old_address, size_t old_size, size_t new_size,
                           int flags, void *new_address);
    return sys_mremap((void *)old_addr, (size_t)old_size, (size_t)new_size,
                      (int)flags, (void *)new_addr);
}

static int64_t sys_msync_handler(uint64_t addr, uint64_t length, uint64_t flags,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_msync(void *addr, size_t length, int flags);
    return sys_msync((void *)addr, (size_t)length, (int)flags);
}

static int64_t sys_mincore_handler(uint64_t addr, uint64_t length, uint64_t vec,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mincore(void *addr, size_t length, unsigned char *vec);
    return sys_mincore((void *)addr, (size_t)length, (unsigned char *)(uintptr_t)vec);
}

/* Directory operations */
static int64_t sys_getdents64_handler(uint64_t fd, uint64_t dirp, uint64_t count,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_getdents64 for directory reading */
    return sys_getdents64((unsigned int)fd, (void *)dirp, (unsigned int)count);
}

/* getpid() handler */
static int64_t sys_getpid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern fut_task_t *fut_task_current(void);
    fut_task_t *current = fut_task_current();
    if (!current) {
        return -1;
    }
    return (int64_t)current->pid;
}

/* ============================================================
 *   Signal Handling Syscalls
 * ============================================================ */

/**
 * kill() - Send signal to a task
 * @arg1: pid (target process ID)
 * @arg2: signum (signal number, 1-30)
 */
static int64_t sys_kill_handler(uint64_t pid, uint64_t signum, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_kill(int pid, int sig);
    return sys_kill((int)pid, (int)signum);
}

/**
 * sigaction() - Install signal handler
 * @arg1: signum (signal number)
 * @arg2: act (new sigaction, may be NULL)
 * @arg3: oldact (old sigaction, may be NULL)
 */
static int64_t sys_sigaction_handler(uint64_t signum, uint64_t act, uint64_t oldact,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
    return sys_sigaction((int)signum, (const struct sigaction *)act, (struct sigaction *)oldact);
}

/**
 * sigprocmask() - Modify signal mask
 * @arg1: how (SIGPROCMASK_BLOCK, SETMASK, UNBLOCK)
 * @arg2: set (signals to modify)
 * @arg3: oldset (old mask output)
 */
static int64_t sys_sigprocmask_handler(uint64_t how, uint64_t set, uint64_t oldset,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
    return sys_sigprocmask((int)how, (const sigset_t *)set, (sigset_t *)oldset);
}

/**
 * sigreturn() - Return from signal handler
 *
 * This syscall is called by the signal handler trampoline code on the user stack.
 * It restores the full user context (registers, flags, stack pointer) that was
 * saved in the rt_sigframe when the signal was delivered.
 *
 * Context restoration:
 * 1. The trampoline code calls sigreturn with RSI = frame pointer to rt_sigframe
 * 2. This handler reads the rt_sigframe from user space
 * 3. Extracts the saved register and signal mask from the ucontext
 * 4. Modifies the kernel interrupt frame to restore all registers
 * 5. On return, the interrupt handler restores registers and switches to user mode
 *
 * Arch-specific: x86_64 version
 */
static int64_t sys_sigreturn_handler(uint64_t frame_ptr, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)frame_ptr; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;

    /* Locate the rt_sigframe using the user RSP captured at syscall entry.
     *
     * On x86_64: signal delivery sets frame->rsp = user_sp (base of rt_sigframe).
     *   The handler's 'ret' pops sigframe.return_address, advancing user RSP to
     *   user_sp + sizeof(long). __restore_rt then calls 'int $0x80' (rt_sigreturn).
     *   At that point fut_current_frame->rsp == user_sp + sizeof(long), so:
     *     sigframe_base = fut_current_frame->rsp - sizeof(long)
     *
     * On ARM64: signal delivery sets frame->sp = user_sp. The handler returns
     *   via 'ret' (br x30) where x30 = sa_restorer, which calls 'svc #0'. At that
     *   point SP is still user_sp (ARM64 ret doesn't pop the stack), so:
     *     sigframe_base = fut_current_frame->sp
     *
     * Using RSI (old approach) is wrong: RSI contains the siginfo_t pointer set at
     * signal delivery, and the signal handler may have clobbered it by the time
     * __restore_rt calls rt_sigreturn.
     */
    extern fut_interrupt_frame_t *fut_current_frame;
#ifdef __x86_64__
    void *user_frame = fut_current_frame
        ? (void *)(uintptr_t)(fut_current_frame->rsp - sizeof(long))
        : NULL;
#elif defined(__aarch64__)
    void *user_frame = fut_current_frame
        ? (void *)(uintptr_t)fut_current_frame->sp
        : NULL;
#else
    void *user_frame = NULL;
#endif

    extern fut_task_t *fut_task_current(void);
    extern int fut_copy_from_user(void *k_dst, const void *u_src, size_t n);
    extern fut_interrupt_frame_t *fut_current_frame;
    
    fut_task_t *current = fut_task_current();
    if (!current || !user_frame) {
        return -EINVAL;
    }

    /* Read the signal frame from user space */
    struct rt_sigframe sigframe;
    if (fut_copy_from_user(&sigframe, user_frame, sizeof(sigframe)) != 0) {
        fut_printf("[SIGNAL] sigreturn: failed to read sigframe from user space\n");
        return -EFAULT;
    }

    /* Restore the per-thread signal mask from the ucontext.
     * The mask was saved (per-thread) when the signal handler was entered. */
    {
        fut_thread_t *cur_thr = fut_thread_current();
        uint64_t *mptr = cur_thr ? &cur_thr->signal_mask : &current->signal_mask;
        __atomic_store_n(mptr, sigframe.uc.uc_sigmask.__mask, __ATOMIC_RELEASE);
    }

    /* Restore all general purpose registers from the saved context
     * The registers in uc_mcontext.gregs are in the same order as the interrupt frame */
    fut_interrupt_frame_t *frame = fut_current_frame;
    if (frame) {
#ifdef __x86_64__
        struct sigcontext *ctx = &sigframe.uc.uc_mcontext.gregs;

        /* Restore GPRs */
        frame->rax = ctx->rax;
        frame->rbx = ctx->rbx;
        frame->rcx = ctx->rcx;
        frame->rdx = ctx->rdx;
        frame->rsi = ctx->rsi;
        frame->rdi = ctx->rdi;
        frame->rbp = ctx->rbp;
        frame->rsp = ctx->rsp;
        frame->r8  = ctx->r8;
        frame->r9  = ctx->r9;
        frame->r10 = ctx->r10;
        frame->r11 = ctx->r11;
        frame->r12 = ctx->r12;
        frame->r13 = ctx->r13;
        frame->r14 = ctx->r14;
        frame->r15 = ctx->r15;

        /* Restore control registers */
        frame->rip    = ctx->rip;
        frame->rflags = ctx->eflags;

        /* Restore segment registers (careful with CS/SS) */
        frame->cs = ctx->cs;
        if (ctx->gs != 0) {
            frame->gs = ctx->gs;
        }
        if (ctx->fs != 0) {
            frame->fs = ctx->fs;
        }

        (void)0; /* context restored */
#elif defined(__aarch64__)
        struct sigcontext *ctx = &sigframe.uc.uc_mcontext.gregs;

        /* Restore all general purpose registers x0-x30 */
        for (int i = 0; i < 31; i++) {
            frame->x[i] = ctx->x[i];
        }

        /* Restore special ARM64 registers */
        frame->sp = ctx->sp;
        frame->pc = ctx->pc;
        frame->pstate = ctx->pstate;
        frame->far = ctx->fault_address;

        /* Restore NEON/FPU registers
         * sigcontext stores them as __uint128_t, but interrupt_frame stores as 2x uint64_t */
        for (int i = 0; i < 32; i++) {
            __uint128_t v = ctx->v[i];
            frame->fpu_state[2*i] = (uint64_t)(v & 0xFFFFFFFFFFFFFFFFULL);
            frame->fpu_state[2*i+1] = (uint64_t)(v >> 64);
        }

        frame->fpsr = ctx->fpsr;
        frame->fpcr = ctx->fpcr;

        (void)0; /* context restored */
#else
#error "Unsupported architecture for sigreturn"
#endif
    }

    /* Restore altstack from saved uc_stack (populated during signal delivery).
     * This re-arms an altstack that was autodisarmed (SS_AUTODISARM) at delivery.
     * For non-autodisarm cases uc_stack.ss_sp is NULL, so just clear SS_ONSTACK. */
    if (sigframe.uc.uc_stack.ss_sp != NULL) {
        current->sig_altstack.ss_sp    = sigframe.uc.uc_stack.ss_sp;
        current->sig_altstack.ss_flags = sigframe.uc.uc_stack.ss_flags;
        current->sig_altstack.ss_size  = sigframe.uc.uc_stack.ss_size;
    } else if (current->sig_altstack.ss_flags & SS_ONSTACK) {
        current->sig_altstack.ss_flags &= ~SS_ONSTACK;
    }

    /* Return value is overwritten by the restored register state */
    return 0;
}

/* ============================================================
 *   I/O Multiplexing Syscall
 * ============================================================ */

/**
 * select() - Wait for file descriptor sets to become ready
 * @arg1: nfds (highest fd number + 1)
 * @arg2: readfds (file descriptors ready for reading)
 * @arg3: writefds (file descriptors ready for writing)
 * @arg4: exceptfds (file descriptors with exceptional conditions)
 * @arg5: timeout (timeval pointer for timeout, NULL for blocking)
 *
 * Enhanced implementation with:
 * - Non-blocking poll (timeout=0)
 * - Timeout support (timeout > 0)
 * - Better FD readiness detection
 * - Accurate ready count reporting
 *
 * Phase 4: Full blocking multiplexing would use event queues
 */
static int64_t sys_select_handler(uint64_t nfds, uint64_t readfds, uint64_t writefds,
                                  uint64_t exceptfds, uint64_t timeout_ptr, uint64_t arg6) {
    (void)arg6;
    extern long sys_select(int nfds, void *readfds, void *writefds, void *exceptfds, fut_timeval_t *timeout);
    return sys_select((int)nfds, (void *)readfds, (void *)writefds, (void *)exceptfds, (fut_timeval_t *)timeout_ptr);
}

/* pselect6() handler */
static int64_t sys_pselect6_handler(uint64_t nfds, uint64_t readfds, uint64_t writefds,
                                    uint64_t exceptfds, uint64_t timeout_ptr, uint64_t sigmask) {
    extern long sys_pselect6(int nfds, void *readfds, void *writefds, void *exceptfds,
                              void *timeout, void *sigmask);
    return sys_pselect6((int)nfds, (void *)readfds, (void *)writefds, (void *)exceptfds,
                        (void *)timeout_ptr, (void *)sigmask);
}

/* ppoll() handler */
static int64_t sys_ppoll_handler(uint64_t fds, uint64_t nfds, uint64_t tmo_p,
                                  uint64_t sigmask, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_ppoll(void *fds, unsigned int nfds, void *tmo_p, const void *sigmask);
    return sys_ppoll((void *)fds, (unsigned int)nfds, (void *)tmo_p, (const void *)sigmask);
}

/* sigpending() handler */
static int64_t sys_sigpending_handler(uint64_t set, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sigpending(sigset_t *set);
    return sys_sigpending((sigset_t *)(uintptr_t)set);
}

/* sigsuspend() handler */
static int64_t sys_sigsuspend_handler(uint64_t mask, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sigsuspend(const sigset_t *mask);
    return sys_sigsuspend((const sigset_t *)(uintptr_t)mask);
}

/* sigaltstack() handler */
static int64_t sys_sigaltstack_handler(uint64_t ss, uint64_t old_ss, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sigaltstack(const struct sigaltstack *ss, struct sigaltstack *old_ss);
    return sys_sigaltstack((const struct sigaltstack *)(uintptr_t)ss,
                           (struct sigaltstack *)(uintptr_t)old_ss);
}

/* futex() handler */
static int64_t sys_futex_handler(uint64_t uaddr, uint64_t op, uint64_t val,
                                  uint64_t timeout, uint64_t uaddr2, uint64_t val3) {
    extern long sys_futex(uint32_t *uaddr, int op, uint32_t val,
                          const fut_timespec_t *timeout, uint32_t *uaddr2, uint32_t val3);
    return sys_futex((uint32_t *)(uintptr_t)uaddr, (int)op, (uint32_t)val,
                     (const fut_timespec_t *)(uintptr_t)timeout,
                     (uint32_t *)(uintptr_t)uaddr2, (uint32_t)val3);
}

/* pipe2() handler */
static int64_t sys_pipe2_handler(uint64_t pipefd, uint64_t flags, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pipe2(int pipefd[2], int flags);
    return sys_pipe2((int *)(uintptr_t)pipefd, (int)flags);
}

/* signalfd4() handler */
static int64_t sys_signalfd4_handler(uint64_t ufd, uint64_t mask, uint64_t sizemask,
                                      uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags);
    return sys_signalfd4((int)ufd, (const void *)(uintptr_t)mask, (size_t)sizemask, (int)flags);
}

/* dup3() handler */
static int64_t sys_dup3_handler(uint64_t oldfd, uint64_t newfd, uint64_t flags,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_dup3(int oldfd, int newfd, int flags);
    return sys_dup3((int)oldfd, (int)newfd, (int)flags);
}

/* accept4() handler */
static int64_t sys_accept4_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                    uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_accept4(int sockfd, void *addr, uint32_t *addrlen, int flags);
    return sys_accept4((int)sockfd, (void *)(uintptr_t)addr,
                       (uint32_t *)(uintptr_t)addrlen, (int)flags);
}

/* ============================================================
 *   Large syscall batch: time/cred/fs/mlock/misc handlers
 * ============================================================ */

static int64_t sys_getitimer_handler(uint64_t which, uint64_t value, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getitimer(int which, void *value);
    return sys_getitimer((int)which, (void *)(uintptr_t)value);
}

static int64_t sys_setitimer_handler(uint64_t which, uint64_t value, uint64_t ovalue,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setitimer(int which, const void *value, void *ovalue);
    return sys_setitimer((int)which, (const void *)(uintptr_t)value, (void *)(uintptr_t)ovalue);
}

static int64_t sys_sendfile_handler(uint64_t out_fd, uint64_t in_fd, uint64_t offset,
                                    uint64_t count, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_sendfile(int out_fd, int in_fd, uint64_t *offset, size_t count);
    return sys_sendfile((int)out_fd, (int)in_fd, (uint64_t *)(uintptr_t)offset, (size_t)count);
}

static int64_t sys_fchdir_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fchdir(int fd);
    return sys_fchdir((int)fd);
}

static int64_t sys_vhangup_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_vhangup(void);
    return sys_vhangup();
}

static int64_t sys_setreuid_handler(uint64_t ruid, uint64_t euid, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setreuid(uint32_t ruid, uint32_t euid);
    return sys_setreuid((uint32_t)ruid, (uint32_t)euid);
}

static int64_t sys_setregid_handler(uint64_t rgid, uint64_t egid, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setregid(uint32_t rgid, uint32_t egid);
    return sys_setregid((uint32_t)rgid, (uint32_t)egid);
}

static int64_t sys_setresuid_handler(uint64_t ruid, uint64_t euid, uint64_t suid,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setresuid(uint32_t ruid, uint32_t euid, uint32_t suid);
    return sys_setresuid((uint32_t)ruid, (uint32_t)euid, (uint32_t)suid);
}

static int64_t sys_getresuid_handler(uint64_t ruid, uint64_t euid, uint64_t suid,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getresuid(uint32_t *ruid, uint32_t *euid, uint32_t *suid);
    return sys_getresuid((uint32_t *)(uintptr_t)ruid, (uint32_t *)(uintptr_t)euid,
                         (uint32_t *)(uintptr_t)suid);
}

static int64_t sys_setresgid_handler(uint64_t rgid, uint64_t egid, uint64_t sgid,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setresgid(uint32_t rgid, uint32_t egid, uint32_t sgid);
    return sys_setresgid((uint32_t)rgid, (uint32_t)egid, (uint32_t)sgid);
}

static int64_t sys_getresgid_handler(uint64_t rgid, uint64_t egid, uint64_t sgid,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getresgid(uint32_t *rgid, uint32_t *egid, uint32_t *sgid);
    return sys_getresgid((uint32_t *)(uintptr_t)rgid, (uint32_t *)(uintptr_t)egid,
                         (uint32_t *)(uintptr_t)sgid);
}

static int64_t sys_capget_handler(uint64_t hdrp, uint64_t datap, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_capget(void *hdrp, void *datap);
    return sys_capget((void *)(uintptr_t)hdrp, (void *)(uintptr_t)datap);
}

static int64_t sys_capset_handler(uint64_t hdrp, uint64_t datap, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_capset(void *hdrp, const void *datap);
    return sys_capset((void *)(uintptr_t)hdrp, (const void *)(uintptr_t)datap);
}

static int64_t sys_personality_handler(uint64_t persona, uint64_t arg2, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_personality(unsigned long persona);
    return sys_personality((unsigned long)persona);
}

static int64_t sys_copy_file_range_handler(uint64_t fd_in, uint64_t off_in, uint64_t fd_out,
                                            uint64_t off_out, uint64_t len, uint64_t flags) {
    extern long sys_copy_file_range(int fd_in, int64_t *off_in,
                                     int fd_out, int64_t *off_out,
                                     size_t len, unsigned int flags);
    return sys_copy_file_range((int)fd_in, (int64_t *)off_in,
                                (int)fd_out, (int64_t *)off_out,
                                (size_t)len, (unsigned int)flags);
}

static int64_t sys_rseq_handler(uint64_t rseq, uint64_t rseq_len, uint64_t flags,
                                 uint64_t sig, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_rseq(void *rseq, uint32_t rseq_len, int flags, uint32_t sig);
    return sys_rseq((void *)rseq, (uint32_t)rseq_len, (int)flags, (uint32_t)sig);
}

static int64_t sys_membarrier_handler(uint64_t cmd, uint64_t flags, uint64_t cpu_id,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_membarrier(int cmd, unsigned int flags, int cpu_id);
    return sys_membarrier((int)cmd, (unsigned int)flags, (int)cpu_id);
}

static int64_t sys_statx_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                  uint64_t mask, uint64_t statxbuf, uint64_t arg6) {
    (void)arg6;
    extern long sys_statx(int dirfd, const char *pathname, int flags,
                          unsigned int mask, void *statxbuf);
    return sys_statx((int)dirfd, (const char *)pathname, (int)flags,
                     (unsigned int)mask, (void *)statxbuf);
}

static int64_t sys_tgkill_handler(uint64_t tgid, uint64_t tid, uint64_t sig,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_tgkill(int tgid, int tid, int sig);
    return sys_tgkill((int)tgid, (int)tid, (int)sig);
}

static int64_t sys_tkill_handler(uint64_t tid, uint64_t sig, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_tkill(int tid, int sig);
    return sys_tkill((int)tid, (int)sig);
}

static int64_t sys_getgroups_handler(uint64_t size, uint64_t list, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getgroups(int size, uint32_t *list);
    return sys_getgroups((int)size, (uint32_t *)list);
}

static int64_t sys_setgroups_handler(uint64_t size, uint64_t list, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setgroups(int size, const uint32_t *list);
    return sys_setgroups((int)size, (const uint32_t *)list);
}

static int64_t sys_futimesat_handler(uint64_t dirfd, uint64_t pathname, uint64_t times,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_futimesat(int dirfd, const char *pathname, const void *times);
    return sys_futimesat((int)dirfd, (const char *)pathname, (const void *)times);
}

static int64_t sys_socketpair_handler(uint64_t domain, uint64_t type, uint64_t protocol,
                                       uint64_t sv, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_socketpair(int domain, int type, int protocol, int *sv);
    return sys_socketpair((int)domain, (int)type, (int)protocol, (int *)sv);
}

static int64_t sys_utimes_handler(uint64_t pathname, uint64_t times, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_utimes(const char *pathname, const void *times);
    return sys_utimes((const char *)pathname, (const void *)times);
}

static int64_t sys_utime_handler(uint64_t pathname, uint64_t times, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_utime(const char *pathname, const void *times);
    return sys_utime((const char *)pathname, (const void *)times);
}

/* NUMA memory policy — single-node stubs (237-239) */
static int64_t sys_mbind_handler(uint64_t addr, uint64_t len, uint64_t mode,
                                  uint64_t nodemask, uint64_t maxnode, uint64_t flags) {
    extern long sys_mbind(unsigned long addr, unsigned long len, int mode,
                          const unsigned long *nodemask, unsigned long maxnode,
                          unsigned int flags);
    return sys_mbind((unsigned long)addr, (unsigned long)len, (int)mode,
                     (const unsigned long *)nodemask, (unsigned long)maxnode,
                     (unsigned int)flags);
}
static int64_t sys_set_mempolicy_handler(uint64_t mode, uint64_t nodemask,
                                          uint64_t maxnode, uint64_t arg4,
                                          uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_set_mempolicy(int mode, const unsigned long *nodemask,
                                  unsigned long maxnode);
    return sys_set_mempolicy((int)mode, (const unsigned long *)nodemask,
                             (unsigned long)maxnode);
}
static int64_t sys_get_mempolicy_handler(uint64_t mode_out, uint64_t nodemask_out,
                                          uint64_t maxnode, uint64_t addr,
                                          uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_get_mempolicy(int *mode_out, unsigned long *nodemask_out,
                                   unsigned long maxnode, unsigned long addr,
                                   unsigned int flags);
    return sys_get_mempolicy((int *)mode_out, (unsigned long *)nodemask_out,
                             (unsigned long)maxnode, (unsigned long)addr,
                             (unsigned int)flags);
}

/* Legacy getdents / swap / ioport handlers */
static int64_t sys_getdents_handler(uint64_t fd, uint64_t dirp, uint64_t count,
                                     uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_getdents(unsigned int fd, void *dirp, unsigned int count);
    return sys_getdents((unsigned int)fd, (void *)dirp, (unsigned int)count);
}
static int64_t sys_swapon_handler(uint64_t path, uint64_t flags, uint64_t a3,
                                   uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_swapon(const char *path, int swapflags);
    return sys_swapon((const char *)path, (int)flags);
}
static int64_t sys_swapoff_handler(uint64_t path, uint64_t a2, uint64_t a3,
                                    uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_swapoff(const char *path);
    return sys_swapoff((const char *)path);
}
static int64_t sys_iopl_handler(uint64_t level, uint64_t a2, uint64_t a3,
                                 uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_iopl(unsigned int level);
    return sys_iopl((unsigned int)level);
}
static int64_t sys_ioperm_handler(uint64_t from, uint64_t num, uint64_t turn_on,
                                   uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_ioperm(unsigned long from, unsigned long num, int turn_on);
    return sys_ioperm((unsigned long)from, (unsigned long)num, (int)turn_on);
}

/* Linux AIO stubs — return -ENOSYS so libaio falls back to sync I/O */
static int64_t sys_io_setup_handler(uint64_t nr_events, uint64_t ctxp, uint64_t a3,
                                     uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)nr_events; (void)ctxp; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_io_setup(unsigned int nr_events, void *ctxp);
    return sys_io_setup((unsigned int)nr_events, (void *)ctxp);
}
static int64_t sys_io_destroy_handler(uint64_t ctx_id, uint64_t a2, uint64_t a3,
                                       uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_io_destroy(unsigned long ctx_id);
    return sys_io_destroy((unsigned long)ctx_id);
}
static int64_t sys_io_getevents_handler(uint64_t ctx_id, uint64_t min_nr, uint64_t nr,
                                         uint64_t events, uint64_t timeout, uint64_t a6) {
    (void)a6;
    extern long sys_io_getevents(unsigned long ctx_id, long min_nr, long nr,
                                  void *events, const void *timeout);
    return sys_io_getevents((unsigned long)ctx_id, (long)min_nr, (long)nr,
                             (void *)events, (const void *)timeout);
}
static int64_t sys_io_submit_handler(uint64_t ctx_id, uint64_t nr, uint64_t iocbpp,
                                      uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_io_submit(unsigned long ctx_id, long nr, void **iocbpp);
    return sys_io_submit((unsigned long)ctx_id, (long)nr, (void **)iocbpp);
}
static int64_t sys_io_cancel_handler(uint64_t ctx_id, uint64_t iocb, uint64_t result,
                                      uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_io_cancel(unsigned long ctx_id, void *iocb, void *result);
    return sys_io_cancel((unsigned long)ctx_id, (void *)iocb, (void *)result);
}

/* io_uring stubs — return -ENOSYS so programs fall back to epoll/poll */
static int64_t sys_io_uring_setup_handler(uint64_t entries, uint64_t params, uint64_t a3,
                                           uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_io_uring_setup(unsigned int entries, void *params);
    return sys_io_uring_setup((unsigned int)entries, (void *)params);
}
static int64_t sys_io_uring_enter_handler(uint64_t fd, uint64_t to_submit,
                                           uint64_t min_complete, uint64_t flags,
                                           uint64_t sig, uint64_t sigsz) {
    extern long sys_io_uring_enter(unsigned int fd, unsigned int to_submit,
                                    unsigned int min_complete, unsigned int flags,
                                    const void *sig, size_t sigsz);
    return sys_io_uring_enter((unsigned int)fd, (unsigned int)to_submit,
                               (unsigned int)min_complete, (unsigned int)flags,
                               (const void *)sig, (size_t)sigsz);
}
static int64_t sys_io_uring_register_handler(uint64_t fd, uint64_t opcode, uint64_t arg,
                                              uint64_t nr_args, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_io_uring_register(unsigned int fd, unsigned int opcode,
                                       void *arg, unsigned int nr_args);
    return sys_io_uring_register((unsigned int)fd, (unsigned int)opcode,
                                  (void *)arg, (unsigned int)nr_args);
}

static int64_t sys_readahead_handler(uint64_t fd, uint64_t offset, uint64_t count,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_readahead(int fd, int64_t offset, size_t count);
    return sys_readahead((int)fd, (int64_t)offset, (size_t)count);
}

static int64_t sys_exit_group_handler(uint64_t status, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_exit_group(int status);
    return sys_exit_group((int)status);
}

static int64_t sys_getcpu_handler(uint64_t cpup, uint64_t nodep, uint64_t unused,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getcpu(unsigned int *cpup, unsigned int *nodep, void *unused);
    return sys_getcpu((unsigned int *)cpup, (unsigned int *)nodep, (void *)unused);
}

static int64_t sys_syslog_handler(uint64_t type, uint64_t buf, uint64_t len,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_syslog(int type, char *buf, int len);
    return sys_syslog((int)type, (char *)buf, (int)len);
}

static int64_t sys_rt_sigtimedwait_handler(uint64_t uthese, uint64_t uinfo,
                                           uint64_t uts, uint64_t sigsetsize,
                                           uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_rt_sigtimedwait(const uint64_t *uthese, void *uinfo,
                                    const void *uts, size_t sigsetsize);
    return sys_rt_sigtimedwait((const uint64_t *)uthese, (void *)uinfo,
                               (const void *)uts, (size_t)sigsetsize);
}

static int64_t sys_rt_sigqueueinfo_handler(uint64_t tgid, uint64_t sig, uint64_t uinfo,
                                           uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_rt_sigqueueinfo(int tgid, int sig, const void *uinfo);
    return sys_rt_sigqueueinfo((int)tgid, (int)sig, (const void *)(uintptr_t)uinfo);
}

static int64_t sys_rt_tgsigqueueinfo_handler(uint64_t tgid, uint64_t tid, uint64_t sig,
                                              uint64_t uinfo, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_rt_tgsigqueueinfo(int tgid, int tid, int sig, const void *uinfo);
    return sys_rt_tgsigqueueinfo((int)tgid, (int)tid, (int)sig,
                                  (const void *)(uintptr_t)uinfo);
}

static int64_t sys_faccessat2_handler(uint64_t dirfd, uint64_t path, uint64_t mode,
                                       uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    /* faccessat2 is faccessat with flags properly passed — delegate directly */
    extern long sys_faccessat(int dirfd, const char *pathname, int mode, int flags);
    return sys_faccessat((int)dirfd, (const char *)(uintptr_t)path,
                         (int)mode, (int)flags);
}

static int64_t sys_kcmp_handler(uint64_t pid1, uint64_t pid2, uint64_t type,
                                 uint64_t idx1, uint64_t idx2, uint64_t arg6) {
    (void)arg6;
    extern long sys_kcmp(int pid1, int pid2, int type,
                         unsigned long idx1, unsigned long idx2);
    return sys_kcmp((int)pid1, (int)pid2, (int)type,
                    (unsigned long)idx1, (unsigned long)idx2);
}

static int64_t sys_seccomp_handler(uint64_t operation, uint64_t flags, uint64_t uargs,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_seccomp(unsigned int operation, unsigned int flags, const void *uargs);
    return sys_seccomp((unsigned int)operation, (unsigned int)flags,
                       (const void *)(uintptr_t)uargs);
}

/* landlock_create_ruleset — Linux 5.13+; return ENOSYS so callers fall back */
static int64_t sys_landlock_create_ruleset_handler(uint64_t attr, uint64_t size,
                                                    uint64_t flags, uint64_t a4,
                                                    uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_landlock_create_ruleset(const void *attr, size_t size, uint32_t flags);
    return sys_landlock_create_ruleset((const void *)(uintptr_t)attr, (size_t)size,
                                       (uint32_t)flags);
}
static int64_t sys_landlock_add_rule_handler(uint64_t ruleset_fd, uint64_t rule_type,
                                              uint64_t rule_attr, uint64_t flags,
                                              uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_landlock_add_rule(int ruleset_fd, unsigned int rule_type,
                                      const void *rule_attr, uint32_t flags);
    return sys_landlock_add_rule((int)ruleset_fd, (unsigned int)rule_type,
                                  (const void *)(uintptr_t)rule_attr, (uint32_t)flags);
}
static int64_t sys_landlock_restrict_self_handler(uint64_t ruleset_fd, uint64_t flags,
                                                   uint64_t a3, uint64_t a4,
                                                   uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_landlock_restrict_self(int ruleset_fd, uint32_t flags);
    return sys_landlock_restrict_self((int)ruleset_fd, (uint32_t)flags);
}
/* memfd_secret — Linux 5.14+; return ENOSYS so callers fall back */
static int64_t sys_memfd_secret_handler(uint64_t flags, uint64_t a2, uint64_t a3,
                                         uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_memfd_secret(unsigned int flags);
    return sys_memfd_secret((unsigned int)flags);
}
/* futex_waitv — Linux 5.16+ (Wine/Proton); return ENOSYS so callers fall back */
static int64_t sys_futex_waitv_handler(uint64_t waiters, uint64_t nr_futexes,
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

/* process_madvise (Linux 5.10+) — ENOSYS; Android LMKD/systemd-oomd fall back */
static int64_t sys_process_madvise_handler(uint64_t pidfd, uint64_t iovec, uint64_t vlen,
                                            uint64_t advice, uint64_t flags, uint64_t a6) {
    (void)a6;
    extern long sys_process_madvise(int pidfd, const void *iovec, unsigned long vlen,
                                     int advice, unsigned int flags);
    return sys_process_madvise((int)pidfd, (const void *)(uintptr_t)iovec,
                                (unsigned long)vlen, (int)advice, (unsigned int)flags);
}
/* set_mempolicy_home_node (Linux 5.17+) — ENOSYS; no NUMA support */
static int64_t sys_set_mempolicy_home_node_handler(uint64_t start, uint64_t len,
                                                    uint64_t home_node, uint64_t flags,
                                                    uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_set_mempolicy_home_node(unsigned long start, unsigned long len,
                                             unsigned long home_node, unsigned long flags);
    return sys_set_mempolicy_home_node((unsigned long)start, (unsigned long)len,
                                        (unsigned long)home_node, (unsigned long)flags);
}
/* cachestat (Linux 6.5+) — ENOSYS; no page cache */
static int64_t sys_cachestat_handler(uint64_t fd, uint64_t range, uint64_t buf,
                                      uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_cachestat(unsigned int fd, const void *cachestat_range,
                               void *cachestat_buf, unsigned int flags);
    return sys_cachestat((unsigned int)fd, (const void *)(uintptr_t)range,
                          (void *)(uintptr_t)buf, (unsigned int)flags);
}
/* fchmodat2 (Linux 6.6+) — delegate to fchmodat */
static int64_t sys_fchmodat2_handler(uint64_t dirfd, uint64_t pathname, uint64_t mode,
                                      uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_fchmodat2(int dirfd, const char *pathname, unsigned int mode,
                               unsigned int flags);
    return sys_fchmodat2((int)dirfd, (const char *)(uintptr_t)pathname,
                          (unsigned int)mode, (unsigned int)flags);
}
/* mseal (Linux 6.10+) — no-op; glibc 2.38+ seals its own segments */
static int64_t sys_mseal_handler(uint64_t addr, uint64_t len, uint64_t flags,
                                   uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_mseal(void *addr, size_t len, unsigned long flags);
    return sys_mseal((void *)(uintptr_t)addr, (size_t)len, (unsigned long)flags);
}

/* perf_event_open/fanotify/userfaultfd/bpf stubs (298, 300, 301, 323, 457) */
static int64_t sys_perf_event_open_handler(uint64_t attr, uint64_t pid, uint64_t cpu,
                                            uint64_t group_fd, uint64_t flags, uint64_t a6) {
    (void)a6;
    extern long sys_perf_event_open(const void *attr, int pid, int cpu,
                                    int group_fd, unsigned long flags);
    return sys_perf_event_open((const void *)(uintptr_t)attr, (int)pid, (int)cpu,
                               (int)group_fd, (unsigned long)flags);
}
static int64_t sys_fanotify_init_handler(uint64_t flags, uint64_t event_f_flags,
                                          uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);
    return sys_fanotify_init((unsigned int)flags, (unsigned int)event_f_flags);
}
static int64_t sys_fanotify_mark_handler(uint64_t fanotify_fd, uint64_t flags,
                                          uint64_t mask, uint64_t dirfd,
                                          uint64_t pathname, uint64_t a6) {
    (void)a6;
    extern long sys_fanotify_mark(int fanotify_fd, unsigned int flags,
                                   unsigned long mask, int dirfd, const char *pathname);
    return sys_fanotify_mark((int)fanotify_fd, (unsigned int)flags,
                             (unsigned long)mask, (int)dirfd, (const char *)(uintptr_t)pathname);
}
static int64_t sys_userfaultfd_handler(uint64_t flags, uint64_t a2, uint64_t a3,
                                        uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_userfaultfd(int flags);
    return sys_userfaultfd((int)flags);
}
static int64_t sys_bpf_handler(uint64_t cmd, uint64_t attr, uint64_t size,
                                uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_bpf(int cmd, const void *attr, unsigned int size);
    return sys_bpf((int)cmd, (const void *)(uintptr_t)attr, (unsigned int)size);
}

/* New mount API handlers (Linux 5.2+) */
static int64_t sys_open_tree_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                      uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_open_tree(int dirfd, const char *pathname, unsigned int flags);
    return sys_open_tree((int)dirfd, (const char *)(uintptr_t)pathname, (unsigned int)flags);
}
static int64_t sys_move_mount_new_handler(uint64_t from_dirfd, uint64_t from_pathname,
                                           uint64_t to_dirfd, uint64_t to_pathname,
                                           uint64_t flags, uint64_t a6) {
    (void)a6;
    extern long sys_move_mount(int from_dirfd, const char *from_pathname,
                                int to_dirfd, const char *to_pathname, unsigned int flags);
    return sys_move_mount((int)from_dirfd, (const char *)(uintptr_t)from_pathname,
                           (int)to_dirfd, (const char *)(uintptr_t)to_pathname, (unsigned int)flags);
}
static int64_t sys_fsopen_handler(uint64_t fsname, uint64_t flags,
                                   uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a3; (void)a4; (void)a5; (void)a6;
    extern long sys_fsopen(const char *fsname, unsigned int flags);
    return sys_fsopen((const char *)(uintptr_t)fsname, (unsigned int)flags);
}
static int64_t sys_fsconfig_handler(uint64_t fs_fd, uint64_t cmd, uint64_t key,
                                     uint64_t value, uint64_t aux, uint64_t a6) {
    (void)a6;
    extern long sys_fsconfig(int fs_fd, unsigned int cmd, const char *key,
                              const void *value, int aux);
    return sys_fsconfig((int)fs_fd, (unsigned int)cmd, (const char *)(uintptr_t)key,
                         (const void *)(uintptr_t)value, (int)aux);
}
static int64_t sys_fsmount_handler(uint64_t fs_fd, uint64_t flags, uint64_t attr_flags,
                                    uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_fsmount(int fs_fd, unsigned int flags, unsigned int attr_flags);
    return sys_fsmount((int)fs_fd, (unsigned int)flags, (unsigned int)attr_flags);
}
static int64_t sys_fspick_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                   uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_fspick(int dirfd, const char *pathname, unsigned int flags);
    return sys_fspick((int)dirfd, (const char *)(uintptr_t)pathname, (unsigned int)flags);
}
static int64_t sys_mount_setattr_handler(uint64_t dirfd, uint64_t pathname, uint64_t flags,
                                          uint64_t uattr, uint64_t usize, uint64_t a6) {
    (void)a6;
    extern long sys_mount_setattr(int dirfd, const char *pathname, unsigned int flags,
                                   const void *uattr, size_t usize);
    return sys_mount_setattr((int)dirfd, (const char *)(uintptr_t)pathname, (unsigned int)flags,
                              (const void *)(uintptr_t)uattr, (size_t)usize);
}
/* File handle syscall handlers */
static int64_t sys_name_to_handle_at_handler(uint64_t dirfd, uint64_t pathname,
                                              uint64_t handle, uint64_t mount_id,
                                              uint64_t flags, uint64_t a6) {
    (void)a6;
    extern long sys_name_to_handle_at(int dirfd, const char *pathname,
                                       void *handle, int *mount_id, int flags);
    return sys_name_to_handle_at((int)dirfd, (const char *)(uintptr_t)pathname,
                                  (void *)(uintptr_t)handle, (int *)(uintptr_t)mount_id,
                                  (int)flags);
}
static int64_t sys_open_by_handle_at_handler(uint64_t mount_fd, uint64_t handle,
                                              uint64_t flags, uint64_t a4,
                                              uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_open_by_handle_at(int mount_fd, void *handle, int flags);
    return sys_open_by_handle_at((int)mount_fd, (void *)(uintptr_t)handle, (int)flags);
}

/* Linux 6.8+ statmount/listmount/LSM stubs */
static int64_t sys_statmount_handler(uint64_t req, uint64_t buf, uint64_t bufsize,
                                      uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_statmount(const void *req, void *buf, size_t bufsize, unsigned int flags);
    return sys_statmount((const void *)(uintptr_t)req, (void *)(uintptr_t)buf,
                         (size_t)bufsize, (unsigned int)flags);
}

static int64_t sys_listmount_handler(uint64_t req, uint64_t mnt_ids, uint64_t nr_mnt_ids,
                                      uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_listmount(const void *req, uint64_t *mnt_ids, size_t nr_mnt_ids,
                              unsigned int flags);
    return sys_listmount((const void *)(uintptr_t)req, (uint64_t *)(uintptr_t)mnt_ids,
                         (size_t)nr_mnt_ids, (unsigned int)flags);
}

static int64_t sys_lsm_get_self_attr_handler(uint64_t attr, uint64_t ctx, uint64_t size,
                                              uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_lsm_get_self_attr(unsigned int attr, void *ctx, uint32_t *size,
                                      uint32_t flags);
    return sys_lsm_get_self_attr((unsigned int)attr, (void *)(uintptr_t)ctx,
                                 (uint32_t *)(uintptr_t)size, (uint32_t)flags);
}

static int64_t sys_lsm_set_self_attr_handler(uint64_t attr, uint64_t ctx, uint64_t size,
                                              uint64_t flags, uint64_t a5, uint64_t a6) {
    (void)a5; (void)a6;
    extern long sys_lsm_set_self_attr(unsigned int attr, void *ctx, uint32_t size,
                                      uint32_t flags);
    return sys_lsm_set_self_attr((unsigned int)attr, (void *)(uintptr_t)ctx,
                                 (uint32_t)size, (uint32_t)flags);
}

static int64_t sys_lsm_list_modules_handler(uint64_t ids, uint64_t size, uint64_t flags,
                                             uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a4; (void)a5; (void)a6;
    extern long sys_lsm_list_modules(uint64_t *ids, uint32_t *size, uint32_t flags);
    return sys_lsm_list_modules((uint64_t *)(uintptr_t)ids, (uint32_t *)(uintptr_t)size,
                                (uint32_t)flags);
}

static int64_t sys_sched_setattr_handler(uint64_t pid, uint64_t uattr, uint64_t flags,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_setattr(int pid, const void *uattr, unsigned int flags);
    return sys_sched_setattr((int)pid, (const void *)(uintptr_t)uattr, (unsigned int)flags);
}

static int64_t sys_sched_getattr_handler(uint64_t pid, uint64_t uattr, uint64_t usize,
                                          uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_sched_getattr(int pid, void *uattr, unsigned int usize, unsigned int flags);
    return sys_sched_getattr((int)pid, (void *)(uintptr_t)uattr, (unsigned int)usize,
                             (unsigned int)flags);
}

static int64_t sys_pidfd_open_handler(uint64_t pid, uint64_t flags, uint64_t arg3,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pidfd_open(int pid, unsigned int flags);
    return sys_pidfd_open((int)pid, (unsigned int)flags);
}

static int64_t sys_pidfd_send_signal_handler(uint64_t pidfd, uint64_t sig, uint64_t info,
                                              uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_pidfd_send_signal(int pidfd, int sig, const void *info,
                                      unsigned int flags);
    return sys_pidfd_send_signal((int)pidfd, (int)sig, (const void *)(uintptr_t)info,
                                 (unsigned int)flags);
}

static int64_t sys_pidfd_getfd_handler(uint64_t pidfd, uint64_t targetfd, uint64_t flags,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pidfd_getfd(int pidfd, int targetfd, unsigned int flags);
    return sys_pidfd_getfd((int)pidfd, (int)targetfd, (unsigned int)flags);
}

static int64_t sys_process_vm_readv_handler(uint64_t pid, uint64_t lvec, uint64_t liovcnt,
                                             uint64_t rvec, uint64_t riovcnt, uint64_t flags) {
    extern long sys_process_vm_readv(int pid, const void *lvec, unsigned long liovcnt,
                                     const void *rvec, unsigned long riovcnt,
                                     unsigned long flags);
    return sys_process_vm_readv((int)pid, (const void *)(uintptr_t)lvec, (unsigned long)liovcnt,
                                (const void *)(uintptr_t)rvec, (unsigned long)riovcnt,
                                (unsigned long)flags);
}

static int64_t sys_process_vm_writev_handler(uint64_t pid, uint64_t lvec, uint64_t liovcnt,
                                              uint64_t rvec, uint64_t riovcnt, uint64_t flags) {
    extern long sys_process_vm_writev(int pid, const void *lvec, unsigned long liovcnt,
                                      const void *rvec, unsigned long riovcnt,
                                      unsigned long flags);
    return sys_process_vm_writev((int)pid, (const void *)(uintptr_t)lvec, (unsigned long)liovcnt,
                                 (const void *)(uintptr_t)rvec, (unsigned long)riovcnt,
                                 (unsigned long)flags);
}

static int64_t sys_memfd_create_handler(uint64_t uname, uint64_t flags, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_memfd_create(const char *uname, unsigned int flags);
    return sys_memfd_create((const char *)uname, (unsigned int)flags);
}

static int64_t sys_reboot_handler(uint64_t magic1, uint64_t magic2, uint64_t cmd,
                                   uint64_t arg, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_reboot(unsigned int magic1, unsigned int magic2,
                           unsigned int cmd, void *arg);
    return sys_reboot((unsigned int)magic1, (unsigned int)magic2,
                      (unsigned int)cmd, (void *)arg);
}

static int64_t sys_fadvise64_handler(uint64_t fd, uint64_t offset, uint64_t len,
                                      uint64_t advice, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_fadvise64(int fd, int64_t offset, int64_t len, int advice);
    return sys_fadvise64((int)fd, (int64_t)offset, (int64_t)len, (int)advice);
}

static int64_t sys_sched_setaffinity_handler(uint64_t pid, uint64_t len, uint64_t mask,
                                              uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_setaffinity(int pid, unsigned int len, const void *user_mask);
    return sys_sched_setaffinity((int)pid, (unsigned int)len, (const void *)mask);
}

static int64_t sys_sched_getaffinity_handler(uint64_t pid, uint64_t len, uint64_t mask,
                                              uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_getaffinity(int pid, unsigned int len, void *user_mask);
    return sys_sched_getaffinity((int)pid, (unsigned int)len, (void *)mask);
}

static int64_t sys_arch_prctl_handler(uint64_t code, uint64_t addr, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_arch_prctl(int code, unsigned long addr);
    return sys_arch_prctl((int)code, addr);
}

static int64_t sys_getrandom_handler(uint64_t buf, uint64_t buflen, uint64_t flags,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getrandom(void *buf, size_t buflen, unsigned int flags);
    return sys_getrandom((void *)buf, (size_t)buflen, (unsigned int)flags);
}

static int64_t sys_prctl_handler(uint64_t option, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg6;
    extern long sys_prctl(int option, unsigned long a2, unsigned long a3,
                          unsigned long a4, unsigned long a5);
    return sys_prctl((int)option, arg2, arg3, arg4, arg5);
}

static int64_t sys_statfs_handler(uint64_t path, uint64_t buf, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_statfs(const char *path, void *buf);
    return sys_statfs((const char *)(uintptr_t)path, (void *)(uintptr_t)buf);
}

static int64_t sys_fstatfs_handler(uint64_t fd, uint64_t buf, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fstatfs(int fd, void *buf);
    return sys_fstatfs((int)fd, (void *)(uintptr_t)buf);
}

static int64_t sys_mlock_handler(uint64_t addr, uint64_t len, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mlock(const void *addr, size_t len);
    return sys_mlock((const void *)(uintptr_t)addr, (size_t)len);
}

static int64_t sys_mlock2_handler(uint64_t addr, uint64_t len, uint64_t flags,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mlock2(const void *addr, size_t len, unsigned int flags);
    return sys_mlock2((const void *)(uintptr_t)addr, (size_t)len, (unsigned int)flags);
}

static int64_t sys_munlock_handler(uint64_t addr, uint64_t len, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_munlock(const void *addr, size_t len);
    return sys_munlock((const void *)(uintptr_t)addr, (size_t)len);
}

static int64_t sys_mlockall_handler(uint64_t flags, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_mlockall(int flags);
    return sys_mlockall((int)flags);
}

static int64_t sys_munlockall_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_munlockall(void);
    return sys_munlockall();
}

static int64_t sys_pivot_root_handler(uint64_t new_root, uint64_t put_old, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_pivot_root(const char *new_root, const char *put_old);
    return sys_pivot_root((const char *)(uintptr_t)new_root, (const char *)(uintptr_t)put_old);
}

static int64_t sys_adjtimex_handler(uint64_t txc, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_adjtimex(void *txc);
    return sys_adjtimex((void *)(uintptr_t)txc);
}

static int64_t sys_chroot_handler(uint64_t path, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_chroot(const char *path);
    return sys_chroot((const char *)(uintptr_t)path);
}

static int64_t sys_sync_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sync(void);
    return sys_sync();
}

static int64_t sys_acct_handler(uint64_t filename, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_acct(const char *filename);
    return sys_acct((const char *)(uintptr_t)filename);
}

static int64_t sys_settimeofday_handler(uint64_t tv, uint64_t tz, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_settimeofday(const void *tv, const void *tz);
    return sys_settimeofday((const void *)(uintptr_t)tv, (const void *)(uintptr_t)tz);
}

static int64_t sys_mount_handler(uint64_t source, uint64_t target, uint64_t filesystemtype,
                                   uint64_t mountflags, uint64_t data, uint64_t arg6) {
    (void)arg6;
    extern long sys_mount(const char *source, const char *target,
                          const char *filesystemtype, unsigned long mountflags,
                          const void *data);
    return sys_mount((const char *)(uintptr_t)source, (const char *)(uintptr_t)target,
                     (const char *)(uintptr_t)filesystemtype, (unsigned long)mountflags,
                     (const void *)(uintptr_t)data);
}

static int64_t sys_umount2_handler(uint64_t target, uint64_t flags, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_umount2(const char *target, int flags);
    return sys_umount2((const char *)(uintptr_t)target, (int)flags);
}

static int64_t sys_sysinfo_handler(uint64_t info, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sysinfo(void *info);
    return sys_sysinfo((void *)(uintptr_t)info);
}

static int64_t sys_set_tid_address_handler(uint64_t tidptr, uint64_t arg2, uint64_t arg3,
                                            uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_set_tid_address(int *tidptr);
    return sys_set_tid_address((int *)(uintptr_t)tidptr);
}

static int64_t sys_timer_create_handler(uint64_t clockid, uint64_t sevp, uint64_t timerid,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timer_create(int clockid, void *sevp, void *timerid);
    return sys_timer_create((int)clockid, (void *)(uintptr_t)sevp, (void *)(uintptr_t)timerid);
}

static int64_t sys_timer_settime_handler(uint64_t timerid, uint64_t flags,
                                          uint64_t new_value, uint64_t old_value,
                                          uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_timer_settime(int timerid, int flags,
                                   const void *new_value, void *old_value);
    return sys_timer_settime((int)timerid, (int)flags,
                              (const void *)(uintptr_t)new_value, (void *)(uintptr_t)old_value);
}

static int64_t sys_timer_gettime_handler(uint64_t timerid, uint64_t curr_value,
                                          uint64_t arg3, uint64_t arg4,
                                          uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timer_gettime(int timerid, void *curr_value);
    return sys_timer_gettime((int)timerid, (void *)(uintptr_t)curr_value);
}

static int64_t sys_timer_getoverrun_handler(uint64_t timerid, uint64_t arg2, uint64_t arg3,
                                             uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timer_getoverrun(int timerid);
    return sys_timer_getoverrun((int)timerid);
}

static int64_t sys_timer_delete_handler(uint64_t timerid, uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timer_delete(int timerid);
    return sys_timer_delete((int)timerid);
}

static int64_t sys_clock_settime_handler(uint64_t clock_id, uint64_t tp, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_clock_settime(int clock_id, const fut_timespec_t *tp);
    return sys_clock_settime((int)clock_id, (const fut_timespec_t *)(uintptr_t)tp);
}

static int64_t sys_clock_getres_handler(uint64_t clock_id, uint64_t res, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_clock_getres(int clock_id, fut_timespec_t *res);
    return sys_clock_getres((int)clock_id, (fut_timespec_t *)(uintptr_t)res);
}

static int64_t sys_clock_nanosleep_handler(uint64_t clock_id, uint64_t flags,
                                            uint64_t req, uint64_t rem,
                                            uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_clock_nanosleep(int clock_id, int flags,
                                     const fut_timespec_t *req, fut_timespec_t *rem);
    return sys_clock_nanosleep((int)clock_id, (int)flags,
                                (const fut_timespec_t *)(uintptr_t)req,
                                (fut_timespec_t *)(uintptr_t)rem);
}

static int64_t sys_unshare_handler(uint64_t flags, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_unshare(unsigned long flags);
    return sys_unshare((unsigned long)flags);
}

static int64_t sys_set_robust_list_handler(uint64_t head, uint64_t len, uint64_t arg3,
                                            uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_set_robust_list(void *head, size_t len);
    return sys_set_robust_list((void *)(uintptr_t)head, (size_t)len);
}

static int64_t sys_get_robust_list_handler(uint64_t pid, uint64_t head_ptr, uint64_t len_ptr,
                                            uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_get_robust_list(int pid, void **head_ptr, size_t *len_ptr);
    return sys_get_robust_list((int)pid, (void **)(uintptr_t)head_ptr,
                                (size_t *)(uintptr_t)len_ptr);
}

static int64_t sys_sync_file_range_handler(uint64_t fd, uint64_t offset, uint64_t nbytes,
                                            uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_sync_file_range(int fd, int64_t offset, int64_t nbytes, unsigned int flags);
    return sys_sync_file_range((int)fd, (int64_t)offset, (int64_t)nbytes, (unsigned int)flags);
}

static int64_t sys_epoll_pwait_handler(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                        uint64_t timeout, uint64_t sigmask, uint64_t arg6) {
    (void)arg6;
    extern long sys_epoll_pwait(int epfd, void *events, int maxevents,
                                 int timeout, const void *sigmask);
    return sys_epoll_pwait((int)epfd, (void *)(uintptr_t)events, (int)maxevents,
                            (int)timeout, (const void *)(uintptr_t)sigmask);
}

static int64_t sys_epoll_pwait2_handler(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                         uint64_t timeout_ts, uint64_t sigmask,
                                         uint64_t sigsetsize) {
    extern long sys_epoll_pwait2(int epfd, void *events, int maxevents,
                                  const void *timeout_ts, const void *sigmask,
                                  size_t sigsetsize);
    return sys_epoll_pwait2((int)epfd, (void *)(uintptr_t)events, (int)maxevents,
                             (const void *)(uintptr_t)timeout_ts,
                             (const void *)(uintptr_t)sigmask,
                             (size_t)sigsetsize);
}

static int64_t sys_timerfd_create_handler(uint64_t clockid, uint64_t flags, uint64_t arg3,
                                           uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timerfd_create(int clockid, int flags);
    return sys_timerfd_create((int)clockid, (int)flags);
}

static int64_t sys_fallocate_handler(uint64_t fd, uint64_t mode, uint64_t offset,
                                      uint64_t len, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_fallocate(int fd, int mode, uint64_t offset, uint64_t len);
    return sys_fallocate((int)fd, (int)mode, (uint64_t)offset, (uint64_t)len);
}

static int64_t sys_timerfd_settime_handler(uint64_t ufd, uint64_t flags,
                                            uint64_t new_value, uint64_t old_value,
                                            uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_timerfd_settime(int ufd, int flags,
                                     const void *new_value, void *old_value);
    return sys_timerfd_settime((int)ufd, (int)flags,
                                (const void *)(uintptr_t)new_value,
                                (void *)(uintptr_t)old_value);
}

static int64_t sys_timerfd_gettime_handler(uint64_t ufd, uint64_t curr_value, uint64_t arg3,
                                            uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_timerfd_gettime(int ufd, void *curr_value);
    return sys_timerfd_gettime((int)ufd, (void *)(uintptr_t)curr_value);
}

static int64_t sys_prlimit64_handler(uint64_t pid, uint64_t resource,
                                      uint64_t new_limit, uint64_t old_limit,
                                      uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_prlimit64(int pid, int resource, const void *new_limit, void *old_limit);
    return sys_prlimit64((int)pid, (int)resource,
                          (const void *)(uintptr_t)new_limit, (void *)(uintptr_t)old_limit);
}

static int64_t sys_syncfs_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_syncfs(int fd);
    return sys_syncfs((int)fd);
}

static int64_t sys_close_range_handler(uint64_t first, uint64_t last, uint64_t flags,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_close_range(unsigned int first, unsigned int last, unsigned int flags);
    return sys_close_range((unsigned int)first, (unsigned int)last, (unsigned int)flags);
}

static int64_t sys_sethostname_handler(uint64_t name, uint64_t len, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sethostname(const char *name, size_t len);
    return sys_sethostname((const char *)(uintptr_t)name, (size_t)len);
}

static int64_t sys_setdomainname_handler(uint64_t name, uint64_t len, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setdomainname(const char *name, size_t len);
    return sys_setdomainname((const char *)(uintptr_t)name, (size_t)len);
}

static int64_t sys_ioprio_set_handler(uint64_t which, uint64_t who, uint64_t ioprio,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_ioprio_set(int which, int who, int ioprio);
    return sys_ioprio_set((int)which, (int)who, (int)ioprio);
}

static int64_t sys_ioprio_get_handler(uint64_t which, uint64_t who, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_ioprio_get(int which, int who);
    return sys_ioprio_get((int)which, (int)who);
}

/* dup() handler - duplicate file descriptor with auto selection */
static int64_t sys_dup_handler(uint64_t oldfd, uint64_t arg2, uint64_t arg3,
                               uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_dup for per-task FD duplication */
    return sys_dup((int)oldfd);
}

/* Socket operations handlers */
static int64_t sys_socket_handler(uint64_t domain, uint64_t type, uint64_t protocol,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_socket(int domain, int type, int protocol);
    return sys_socket((int)domain, (int)type, (int)protocol);
}

static int64_t sys_bind_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_bind(int sockfd, const void *addr, uint32_t addrlen);
    return sys_bind((int)sockfd, (const void *)addr, (uint32_t)addrlen);
}

static int64_t sys_listen_handler(uint64_t sockfd, uint64_t backlog, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_listen(int sockfd, int backlog);
    return sys_listen((int)sockfd, (int)backlog);
}

static int64_t sys_shutdown_handler(uint64_t sockfd, uint64_t how, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_shutdown(int sockfd, int how);
    return sys_shutdown((int)sockfd, (int)how);
}

static int64_t sys_getpeername_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpeername(int sockfd, void *addr, uint32_t *addrlen);
    return sys_getpeername((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
}

static int64_t sys_getsockname_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getsockname(int sockfd, void *addr, uint32_t *addrlen);
    return sys_getsockname((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
}

static int64_t sys_setsockopt_handler(uint64_t sockfd, uint64_t level, uint64_t optname,
                                      uint64_t optval, uint64_t optlen, uint64_t arg6) {
    (void)arg6;
    extern long sys_setsockopt(int sockfd, int level, int optname, const void *optval, uint32_t optlen);
    return sys_setsockopt((int)sockfd, (int)level, (int)optname, (const void *)(uintptr_t)optval, (uint32_t)optlen);
}

static int64_t sys_getsockopt_handler(uint64_t sockfd, uint64_t level, uint64_t optname,
                                      uint64_t optval, uint64_t optlen, uint64_t arg6) {
    (void)arg6;
    extern long sys_getsockopt(int sockfd, int level, int optname, void *optval, uint32_t *optlen);
    return sys_getsockopt((int)sockfd, (int)level, (int)optname, (void *)(uintptr_t)optval, (uint32_t *)(uintptr_t)optlen);
}

static int64_t sys_accept_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_accept(int sockfd, void *addr, uint32_t *addrlen);
    return sys_accept((int)sockfd, (void *)(uintptr_t)addr, (uint32_t *)(uintptr_t)addrlen);
}

/**
 * Connect to a socket.
 * For AF_UNIX SOCK_STREAM, initiates connection to a listening socket.
 *
 * Phase 3 Implementation:
 * - Connects to a listening socket path
 * - Uses kernel socket connection mechanism
 * - Establishes bidirectional communication channel
 * - Returns 0 on success for connected socket
 */
static int64_t sys_connect_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_connect(int sockfd, const void *addr, uint32_t addrlen);
    fut_printf("[CONNECT] connect(sockfd=%llu, addr=0x%llx, addrlen=%llu) entering\n",
               sockfd, addr, addrlen);
    long result = sys_connect((int)sockfd, (const void *)addr, (uint32_t)addrlen);
    fut_printf("[CONNECT] connect() -> %ld\n", result);
    return result;
}

/**
 * Send data to a socket.
 * For pipe-based sockets, this is equivalent to writing to the pipe.
 *
 * Phase 2 Implementation Notes:
 * - Writes data to the socket's pipe backend
 * - Handles partial writes
 * - Returns bytes sent or error code
 */
static int64_t sys_sendto_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                  uint64_t flags, uint64_t addr, uint64_t addrlen) {
    (void)flags; (void)addr; (void)addrlen;
    extern ssize_t sys_sendto(int sockfd, const void *buf, size_t len, int flags, const void *dest_addr, uint32_t addrlen);
    return sys_sendto((int)sockfd, (const void *)buf, (size_t)len, (int)flags, (const void *)addr, (uint32_t)addrlen);
}

/**
 * Receive data from a socket.
 * For pipe-based sockets, this is equivalent to reading from the pipe.
 *
 * Phase 2 Implementation Notes:
 * - Reads data from the socket's pipe backend
 * - Handles partial reads
 * - Returns bytes received or error code
 */
static int64_t sys_recvfrom_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                    uint64_t flags, uint64_t addr, uint64_t addrlen) {
    (void)flags; (void)addr; (void)addrlen;
    extern ssize_t sys_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr, uint32_t *addrlen);
    return sys_recvfrom((int)sockfd, (void *)buf, (size_t)len, (int)flags, (void *)addr, (uint32_t *)addrlen);
}

static int64_t sys_sendmsg_handler(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_sendmsg(int sockfd, const void *msg, int flags);
    return sys_sendmsg((int)sockfd, (const void *)msg, (int)flags);
}

static int64_t sys_recvmsg_handler(uint64_t sockfd, uint64_t msg, uint64_t flags,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern ssize_t sys_recvmsg(int sockfd, void *msg, int flags);
    return sys_recvmsg((int)sockfd, (void *)msg, (int)flags);
}

/* sendmmsg: send multiple messages — delegate to sys_sendmmsg() */
static int64_t sys_sendmmsg_handler(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_sendmmsg(int sockfd, void *msgvec, unsigned int vlen, unsigned int flags);
    return sys_sendmmsg((int)sockfd, (void *)(uintptr_t)msgvec,
                        (unsigned int)vlen, (unsigned int)flags);
}

/* recvmmsg: receive multiple messages — delegate to sys_recvmmsg() */
static int64_t sys_recvmmsg_handler(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t timeout, uint64_t arg6) {
    (void)arg6;
    extern long sys_recvmmsg(int sockfd, void *msgvec, unsigned int vlen,
                             unsigned int flags, const void *timeout);
    return sys_recvmmsg((int)sockfd, (void *)(uintptr_t)msgvec,
                        (unsigned int)vlen, (unsigned int)flags,
                        (const void *)(uintptr_t)timeout);
}

/* clock_adjtime: like adjtimex but takes a clk_id; delegate CLOCK_REALTIME */
static int64_t sys_clock_adjtime_handler(uint64_t clk_id, uint64_t txc, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    if (clk_id != 0) return -EINVAL;  /* only CLOCK_REALTIME supported */
    extern long sys_adjtimex(void *txc);
    return sys_adjtimex((void *)(uintptr_t)txc);
}

/* setns: enter a namespace via file descriptor; namespaces not implemented */
static int64_t sys_setns_handler(uint64_t fd, uint64_t nstype, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)fd; (void)nstype; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return -38;  /* -ENOSYS: namespace support not implemented */
}

/* sched_setparam/getparam/setscheduler/getscheduler handlers */
static int64_t sys_sched_setparam_handler(uint64_t pid, uint64_t param, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_setparam(int pid, const struct sched_param *param);
    return sys_sched_setparam((int)pid, (const struct sched_param *)(uintptr_t)param);
}

static int64_t sys_sched_getparam_handler(uint64_t pid, uint64_t param, uint64_t arg3,
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_getparam(int pid, struct sched_param *param);
    return sys_sched_getparam((int)pid, (struct sched_param *)(uintptr_t)param);
}

static int64_t sys_sched_setscheduler_handler(uint64_t pid, uint64_t policy, uint64_t param,
                                              uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_setscheduler(int pid, int policy, const struct sched_param *param);
    return sys_sched_setscheduler((int)pid, (int)policy, (const struct sched_param *)(uintptr_t)param);
}

static int64_t sys_sched_getscheduler_handler(uint64_t pid, uint64_t arg2, uint64_t arg3,
                                              uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_getscheduler(int pid);
    return sys_sched_getscheduler((int)pid);
}

static int64_t sys_sched_get_priority_max_handler(uint64_t policy, uint64_t arg2, uint64_t arg3,
                                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_get_priority_max(int policy);
    return sys_sched_get_priority_max((int)policy);
}

static int64_t sys_sched_get_priority_min_handler(uint64_t policy, uint64_t arg2, uint64_t arg3,
                                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_get_priority_min(int policy);
    return sys_sched_get_priority_min((int)policy);
}

static int64_t sys_sched_rr_get_interval_handler(uint64_t pid, uint64_t interval, uint64_t arg3,
                                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_sched_rr_get_interval(int pid, void *interval);
    return sys_sched_rr_get_interval((int)pid, (void *)interval);
}

/* xattr handlers */
static int64_t sys_setxattr_handler(uint64_t path, uint64_t name, uint64_t value,
                                    uint64_t size, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_setxattr(const char *path, const char *name, const void *value, size_t size, int flags);
    return sys_setxattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name,
                        (const void *)(uintptr_t)value, (size_t)size, (int)flags);
}

static int64_t sys_lsetxattr_handler(uint64_t path, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags);
    return sys_lsetxattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name,
                         (const void *)(uintptr_t)value, (size_t)size, (int)flags);
}

static int64_t sys_fsetxattr_handler(uint64_t fd, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t flags, uint64_t arg6) {
    (void)arg6;
    extern long sys_fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);
    return sys_fsetxattr((int)fd, (const char *)(uintptr_t)name,
                         (const void *)(uintptr_t)value, (size_t)size, (int)flags);
}

static int64_t sys_getxattr_handler(uint64_t path, uint64_t name, uint64_t value,
                                    uint64_t size, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_getxattr(const char *path, const char *name, void *value, size_t size);
    return sys_getxattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name,
                        (void *)(uintptr_t)value, (size_t)size);
}

static int64_t sys_lgetxattr_handler(uint64_t path, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_lgetxattr(const char *path, const char *name, void *value, size_t size);
    return sys_lgetxattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name,
                         (void *)(uintptr_t)value, (size_t)size);
}

static int64_t sys_fgetxattr_handler(uint64_t fd, uint64_t name, uint64_t value,
                                     uint64_t size, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_fgetxattr(int fd, const char *name, void *value, size_t size);
    return sys_fgetxattr((int)fd, (const char *)(uintptr_t)name,
                         (void *)(uintptr_t)value, (size_t)size);
}

static int64_t sys_listxattr_handler(uint64_t path, uint64_t list, uint64_t size,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_listxattr(const char *path, char *list, size_t size);
    return sys_listxattr((const char *)(uintptr_t)path, (char *)(uintptr_t)list, (size_t)size);
}

static int64_t sys_llistxattr_handler(uint64_t path, uint64_t list, uint64_t size,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_llistxattr(const char *path, char *list, size_t size);
    return sys_llistxattr((const char *)(uintptr_t)path, (char *)(uintptr_t)list, (size_t)size);
}

static int64_t sys_flistxattr_handler(uint64_t fd, uint64_t list, uint64_t size,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_flistxattr(int fd, char *list, size_t size);
    return sys_flistxattr((int)fd, (char *)(uintptr_t)list, (size_t)size);
}

static int64_t sys_removexattr_handler(uint64_t path, uint64_t name, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_removexattr(const char *path, const char *name);
    return sys_removexattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name);
}

static int64_t sys_lremovexattr_handler(uint64_t path, uint64_t name, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_lremovexattr(const char *path, const char *name);
    return sys_lremovexattr((const char *)(uintptr_t)path, (const char *)(uintptr_t)name);
}

static int64_t sys_fremovexattr_handler(uint64_t fd, uint64_t name, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fremovexattr(int fd, const char *name);
    return sys_fremovexattr((int)fd, (const char *)(uintptr_t)name);
}

/* waitid handler */
static int64_t sys_waitid_handler(uint64_t idtype, uint64_t id, uint64_t infop,
                                  uint64_t options, uint64_t rusage, uint64_t arg6) {
    (void)arg6;
    extern long sys_waitid(int idtype, int id, void *infop, int options, void *rusage);
    return sys_waitid((int)idtype, (int)id, (void *)(uintptr_t)infop,
                      (int)options, (void *)(uintptr_t)rusage);
}

/* Linux keyring stubs — not implemented; return ENOSYS so callers fall back */
static int64_t sys_add_key_handler(uint64_t type, uint64_t description, uint64_t payload,
                                    uint64_t plen, uint64_t keyring, uint64_t arg6) {
    (void)arg6;
    extern long sys_add_key(const char *type, const char *description,
                            const void *payload, size_t plen, int keyring);
    return sys_add_key((const char *)(uintptr_t)type, (const char *)(uintptr_t)description,
                       (const void *)(uintptr_t)payload, (size_t)plen, (int)keyring);
}
static int64_t sys_request_key_handler(uint64_t type, uint64_t description, uint64_t callout,
                                        uint64_t dest_keyring, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_request_key(const char *type, const char *description,
                                const char *callout_info, int dest_keyring);
    return sys_request_key((const char *)(uintptr_t)type,
                           (const char *)(uintptr_t)description,
                           (const char *)(uintptr_t)callout, (int)dest_keyring);
}
static int64_t sys_keyctl_handler(uint64_t operation, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg6;
    extern long sys_keyctl(int operation, unsigned long arg2, unsigned long arg3,
                           unsigned long arg4, unsigned long arg5);
    return sys_keyctl((int)operation, (unsigned long)arg2, (unsigned long)arg3,
                      (unsigned long)arg4, (unsigned long)arg5);
}

/* signalfd legacy (282) — same as signalfd4 with flags=0 */
static int64_t sys_signalfd_handler(uint64_t ufd, uint64_t mask, uint64_t sizemask,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_signalfd4(int ufd, const void *mask, size_t sizemask, int flags);
    return sys_signalfd4((int)ufd, (const void *)(uintptr_t)mask, (size_t)sizemask, 0);
}

/* eventfd legacy (284) — same as eventfd2 with flags=0 */
static int64_t sys_eventfd_handler(uint64_t initval, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_eventfd2(unsigned int initval, int flags);
    return sys_eventfd2((unsigned int)initval, 0);
}

/* inotify handlers */
static int64_t sys_inotify_init_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_inotify_init1(int flags);
    return sys_inotify_init1(0);
}

static int64_t sys_inotify_init1_handler(uint64_t flags, uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_inotify_init1(int flags);
    return sys_inotify_init1((int)flags);
}

static int64_t sys_inotify_add_watch_handler(uint64_t fd, uint64_t pathname, uint64_t mask,
                                             uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask);
    return sys_inotify_add_watch((int)fd, (const char *)(uintptr_t)pathname, (uint32_t)mask);
}

static int64_t sys_inotify_rm_watch_handler(uint64_t fd, uint64_t wd, uint64_t arg3,
                                            uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_inotify_rm_watch(int fd, int wd);
    return sys_inotify_rm_watch((int)fd, (int)wd);
}

/* splice/tee/vmsplice handlers */
static int64_t sys_splice_handler(uint64_t fd_in, uint64_t off_in, uint64_t fd_out,
                                  uint64_t off_out, uint64_t len, uint64_t flags) {
    extern long sys_splice(int fd_in, int64_t *off_in, int fd_out, int64_t *off_out,
                           size_t len, unsigned int flags);
    return sys_splice((int)fd_in, (int64_t *)(uintptr_t)off_in,
                      (int)fd_out, (int64_t *)(uintptr_t)off_out,
                      (size_t)len, (unsigned int)flags);
}

static int64_t sys_tee_handler(uint64_t fd_in, uint64_t fd_out, uint64_t len,
                                uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags);
    return sys_tee((int)fd_in, (int)fd_out, (size_t)len, (unsigned int)flags);
}

static int64_t sys_vmsplice_handler(uint64_t fd, uint64_t iov, uint64_t nr_segs,
                                    uint64_t flags, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_vmsplice(int fd, const void *iov, size_t nr_segs, unsigned int flags);
    return sys_vmsplice((int)fd, (const void *)(uintptr_t)iov, (size_t)nr_segs, (unsigned int)flags);
}

/* Unimplemented syscall handler */
static int64_t sys_unimplemented(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return -38;  /* -ENOSYS: Function not implemented */
}

/* ptrace(2) — process tracing stub. */
static int64_t sys_ptrace_handler(uint64_t request, uint64_t pid, uint64_t addr,
                                   uint64_t data, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_ptrace(int request, int pid, void *addr, void *data);
    return sys_ptrace((int)request, (int)pid, (void *)(uintptr_t)addr,
                      (void *)(uintptr_t)data);
}

static int64_t sys_getcwd_handler(uint64_t buf, uint64_t size, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_getcwd((char *)(uintptr_t)buf, (size_t)size);
}

static int64_t sys_chdir_handler(uint64_t path, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_chdir((const char *)(uintptr_t)path);
}

/* Epoll syscall handlers */
static int64_t sys_epoll_create_handler(uint64_t size, uint64_t arg2, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_epoll_create(int size);
    return sys_epoll_create((int)size);
}

static int64_t sys_epoll_create1_handler(uint64_t flags, uint64_t arg2, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    return sys_epoll_create1((int)flags);
}

static int64_t sys_epoll_ctl_handler(uint64_t epfd, uint64_t op, uint64_t fd,
                                     uint64_t event, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_epoll_ctl(int epfd, int op, int fd, void *event);
    return sys_epoll_ctl((int)epfd, (int)op, (int)fd, (void *)(uintptr_t)event);
}

static int64_t sys_epoll_wait_handler(uint64_t epfd, uint64_t events, uint64_t maxevents,
                                      uint64_t timeout, uint64_t arg5, uint64_t arg6) {
    (void)arg5; (void)arg6;
    extern long sys_epoll_wait(int epfd, void *events, int maxevents, int timeout);
    return sys_epoll_wait((int)epfd, (void *)(uintptr_t)events, (int)maxevents, (int)timeout);
}

/* madvise() syscall handler */
static int64_t sys_madvise_handler(uint64_t addr, uint64_t length, uint64_t advice,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_madvise(void *addr, size_t length, int advice);
    return sys_madvise((void *)(uintptr_t)addr, (size_t)length, (int)advice);
}

/* Process credential syscall handlers */
static int64_t sys_getuid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getuid(void);
    return sys_getuid();
}

static int64_t sys_geteuid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_geteuid(void);
    return sys_geteuid();
}

static int64_t sys_getgid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getgid(void);
    return sys_getgid();
}

static int64_t sys_getegid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getegid(void);
    return sys_getegid();
}

static int64_t sys_setuid_handler(uint64_t uid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setuid(uint32_t uid);
    return sys_setuid((uint32_t)uid);
}

static int64_t sys_seteuid_handler(uint64_t euid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_seteuid(uint32_t euid);
    return sys_seteuid((uint32_t)euid);
}

static int64_t sys_setgid_handler(uint64_t gid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setgid(uint32_t gid);
    return sys_setgid((uint32_t)gid);
}

static int64_t sys_setegid_handler(uint64_t egid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setegid(uint32_t egid);
    return sys_setegid((uint32_t)egid);
}

static int64_t sys_umask_handler(uint64_t mask, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_umask for file creation mask */
    return sys_umask((uint32_t)mask);
}

static int64_t sys_uname_handler(uint64_t buf, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_uname for system information */
    return sys_uname((void *)(uintptr_t)buf);
}

/* Process info syscall handlers */
static int64_t sys_gettid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_gettid(void);
    return sys_gettid();
}

static int64_t sys_getppid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getppid(void);
    return sys_getppid();
}

static int64_t sys_getpgrp_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpgrp(void);
    return sys_getpgrp();
}

static int64_t sys_getsid_handler(uint64_t pid, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getsid(uint64_t pid);
    return sys_getsid((uint64_t)pid);
}

static int64_t sys_setsid_handler(uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg1; (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setsid(void);
    return sys_setsid();
}

static int64_t sys_getpgid_handler(uint64_t pid, uint64_t arg2, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getpgid(uint64_t pid);
    return sys_getpgid(pid);
}

static int64_t sys_setpgid_handler(uint64_t pid, uint64_t pgid, uint64_t arg3,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setpgid(uint64_t pid, uint64_t pgid);
    return sys_setpgid(pid, pgid);
}

static int64_t sys_getrlimit_handler(uint64_t resource, uint64_t rlim, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_getrlimit(int resource, struct rlimit *rlim);
    return sys_getrlimit((int)resource, (struct rlimit *)(uintptr_t)rlim);
}

static int64_t sys_setrlimit_handler(uint64_t resource, uint64_t rlim, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setrlimit(int resource, const struct rlimit *rlim);
    return sys_setrlimit((int)resource, (const struct rlimit *)(uintptr_t)rlim);
}

/* File manipulation syscall handlers */
static int64_t sys_rename_handler(uint64_t oldpath, uint64_t newpath, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_rename(const char *oldpath, const char *newpath);
    return sys_rename((const char *)(uintptr_t)oldpath, (const char *)(uintptr_t)newpath);
}

static int64_t sys_chmod_handler(uint64_t path, uint64_t mode, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_chmod(const char *path, uint32_t mode);
    return sys_chmod((const char *)(uintptr_t)path, (uint32_t)mode);
}

static int64_t sys_fchmod_handler(uint64_t fd, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fchmod(int fd, uint32_t mode);
    return sys_fchmod((int)fd, (uint32_t)mode);
}

static int64_t sys_chown_handler(uint64_t path, uint64_t uid, uint64_t gid,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_chown(const char *path, uint32_t uid, uint32_t gid);
    return sys_chown((const char *)(uintptr_t)path, (uint32_t)uid, (uint32_t)gid);
}

static int64_t sys_fchown_handler(uint64_t fd, uint64_t uid, uint64_t gid,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fchown(int fd, uint32_t uid, uint32_t gid);
    return sys_fchown((int)fd, (uint32_t)uid, (uint32_t)gid);
}

static int64_t sys_lchown_handler(uint64_t path, uint64_t uid, uint64_t gid,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_lchown(const char *path, uint32_t uid, uint32_t gid);
    return sys_lchown((const char *)(uintptr_t)path, (uint32_t)uid, (uint32_t)gid);
}

static int64_t sys_creat_handler(uint64_t path, uint64_t mode, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_creat(const char *pathname, int mode);
    return sys_creat((const char *)(uintptr_t)path, (int)mode);
}

static int64_t sys_setfsuid_handler(uint64_t fsuid, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setfsuid(uint32_t fsuid);
    return sys_setfsuid((uint32_t)fsuid);
}

static int64_t sys_setfsgid_handler(uint64_t fsgid, uint64_t arg2, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_setfsgid(uint32_t fsgid);
    return sys_setfsgid((uint32_t)fsgid);
}

static int64_t sys_truncate_handler(uint64_t path, uint64_t length, uint64_t arg3,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_truncate(const char *path, uint64_t length);
    return sys_truncate((const char *)(uintptr_t)path, (uint64_t)length);
}

static int64_t sys_fcntl_handler(uint64_t fd, uint64_t cmd, uint64_t arg,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long sys_fcntl(int fd, int cmd, uint64_t arg);
    return sys_fcntl((int)fd, (int)cmd, (uint64_t)arg);
}

static int64_t sys_flock_handler(uint64_t fd, uint64_t operation, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_flock(int fd, int operation);
    return sys_flock((int)fd, (int)operation);
}

static int64_t sys_fsync_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_fsync for file synchronization */
    return sys_fsync((int)fd);
}

static int64_t sys_fdatasync_handler(uint64_t fd, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    /* Use kernel sys_fdatasync for file data synchronization */
    return sys_fdatasync((int)fd);
}

static int64_t sys_access_handler(uint64_t path, uint64_t mode, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_access(const char *path, int mode);
    return sys_access((const char *)(uintptr_t)path, (int)mode);
}

static int64_t sys_lseek_handler(uint64_t fd, uint64_t offset, uint64_t whence,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int64_t sys_lseek(int fd, int64_t offset, int whence);
    return sys_lseek((int)fd, (int64_t)offset, (int)whence);
}

static int64_t sys_gettimeofday_handler(uint64_t tv, uint64_t tz, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_gettimeofday(fut_timeval_t *tv, void *tz);
    return sys_gettimeofday((fut_timeval_t *)(uintptr_t)tv, (void *)(uintptr_t)tz);
}

static int64_t sys_time_handler(uint64_t tloc, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_time(uint64_t *tloc);
    return sys_time((uint64_t *)(uintptr_t)tloc);
}

static int64_t sys_clock_gettime_handler(uint64_t clock_id, uint64_t tp, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern long sys_clock_gettime(int clock_id, fut_timespec_t *tp);
    return sys_clock_gettime((int)clock_id, (fut_timespec_t *)(uintptr_t)tp);
}

/* ============================================================
 *   Capability-based Syscall Handlers (Phase 1)
 * ============================================================ */

/**
 * sys_open_cap - Open a file with capability handle return.
 *
 * @param pathname Path to file
 * @param flags    Open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @param mode     File mode for creation
 * @return Capability handle on success, negative error on failure
 */
static int64_t sys_open_cap_handler(uint64_t pathname, uint64_t flags, uint64_t mode,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern fut_handle_t fut_vfs_open_cap(const char *path, int flags, int mode);
    fut_handle_t handle = fut_vfs_open_cap((const char *)(uintptr_t)pathname,
                                            (int)flags, (int)mode);
    if (handle == FUT_INVALID_HANDLE) {
        return -EBADF;  /* Return error if open failed */
    }
    return (int64_t)handle;
}

/**
 * sys_read_cap - Read from a capability handle.
 *
 * @param handle Capability handle
 * @param buf    Buffer to read into
 * @param count  Number of bytes to read
 * @return Number of bytes read, or negative error
 */
static int64_t sys_read_cap_handler(uint64_t handle, uint64_t buf, uint64_t count,
                                    uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_read_cap(fut_handle_t handle, void *buffer, size_t count);
    return fut_vfs_read_cap((fut_handle_t)handle, (void *)(uintptr_t)buf, (size_t)count);
}

/**
 * sys_write_cap - Write to a capability handle.
 *
 * @param handle Capability handle
 * @param buf    Buffer to write from
 * @param count  Number of bytes to write
 * @return Number of bytes written, or negative error
 */
static int64_t sys_write_cap_handler(uint64_t handle, uint64_t buf, uint64_t count,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_write_cap(fut_handle_t handle, const void *buffer, size_t count);
    return fut_vfs_write_cap((fut_handle_t)handle, (const void *)(uintptr_t)buf, (size_t)count);
}

/**
 * sys_close_cap - Close a capability handle.
 *
 * @param handle Capability handle to close
 * @return 0 on success, negative error on failure
 */
static int64_t sys_close_cap_handler(uint64_t handle, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_close_cap(fut_handle_t handle);
    return fut_vfs_close_cap((fut_handle_t)handle);
}

/**
 * sys_lseek_cap - Seek within a capability handle.
 *
 * @param handle Capability handle
 * @param offset Seek offset
 * @param whence Seek mode (SEEK_SET, SEEK_CUR, SEEK_END)
 * @return New file offset, or negative error
 */
static int64_t sys_lseek_cap_handler(uint64_t handle, uint64_t offset, uint64_t whence,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern long fut_vfs_lseek_cap(fut_handle_t handle, int64_t offset, int whence);
    return fut_vfs_lseek_cap((fut_handle_t)handle, (int64_t)offset, (int)whence);
}

/**
 * sys_fstat_cap - Get file statistics from capability handle.
 *
 * @param handle  Capability handle
 * @param statbuf Buffer to receive statistics
 * @return 0 on success, negative error on failure
 */
static int64_t sys_fstat_cap_handler(uint64_t handle, uint64_t statbuf, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_fstat_cap(fut_handle_t handle, struct fut_stat *statbuf);
    return fut_vfs_fstat_cap((fut_handle_t)handle, (struct fut_stat *)(uintptr_t)statbuf);
}

/**
 * sys_fsync_cap - Sync file data to storage from capability handle.
 *
 * @param handle Capability handle
 * @return 0 on success, negative error on failure
 */
static int64_t sys_fsync_cap_handler(uint64_t handle, uint64_t arg2, uint64_t arg3,
                                     uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg2; (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_fsync_cap(fut_handle_t handle);
    return fut_vfs_fsync_cap((fut_handle_t)handle);
}

/**
 * sys_mkdirat_cap - Create directory relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to create
 * @param mode          Directory permissions
 * @return 0 on success, negative error on failure
 */
static int64_t sys_mkdirat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t mode,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_mkdirat_cap(fut_handle_t parent_handle, const char *name, int mode);
    return fut_vfs_mkdirat_cap((fut_handle_t)parent_handle,
                               (const char *)(uintptr_t)name, (int)mode);
}

/**
 * sys_unlinkat_cap - Unlink file relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to unlink
 * @return 0 on success, negative error on failure
 */
static int64_t sys_unlinkat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t arg3,
                                        uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_unlinkat_cap(fut_handle_t parent_handle, const char *name);
    return fut_vfs_unlinkat_cap((fut_handle_t)parent_handle, (const char *)(uintptr_t)name);
}

/**
 * sys_rmdirat_cap - Remove directory relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of directory to remove
 * @return 0 on success, negative error on failure
 */
static int64_t sys_rmdirat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t arg3,
                                       uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg3; (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_rmdirat_cap(fut_handle_t parent_handle, const char *name);
    return fut_vfs_rmdirat_cap((fut_handle_t)parent_handle, (const char *)(uintptr_t)name);
}

/**
 * sys_statat_cap - Get file statistics relative to parent handle.
 *
 * @param parent_handle Capability handle to parent directory
 * @param name          Name of file to stat
 * @param statbuf       Buffer to receive statistics
 * @return 0 on success, negative error on failure
 */
static int64_t sys_statat_cap_handler(uint64_t parent_handle, uint64_t name, uint64_t statbuf,
                                      uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    (void)arg4; (void)arg5; (void)arg6;
    extern int fut_vfs_statat_cap(fut_handle_t parent_handle, const char *name,
                                  struct fut_stat *statbuf);
    return fut_vfs_statat_cap((fut_handle_t)parent_handle,
                              (const char *)(uintptr_t)name,
                              (struct fut_stat *)(uintptr_t)statbuf);
}

/* ============================================================
 *   Syscall Table
 * ============================================================ */

/* Forward declarations for socket handlers defined later */
static int64_t sys_connect_handler(uint64_t sockfd, uint64_t addr, uint64_t addrlen,
                                   uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_sendto_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                  uint64_t flags, uint64_t addr, uint64_t addrlen);
static int64_t sys_recvfrom_handler(uint64_t sockfd, uint64_t buf, uint64_t len,
                                    uint64_t flags, uint64_t addr, uint64_t addrlen);
static int64_t sys_shmget_handler(uint64_t key, uint64_t size, uint64_t shmflg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_shmat_handler(uint64_t shmid, uint64_t shmaddr, uint64_t shmflg,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_shmdt_handler(uint64_t shmaddr, uint64_t arg2, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_shmctl_handler(uint64_t shmid, uint64_t cmd, uint64_t buf,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_semget_handler(uint64_t key, uint64_t nsems, uint64_t semflg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_semop_handler(uint64_t semid, uint64_t sops, uint64_t nsops,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_semctl_handler(uint64_t semid, uint64_t semnum, uint64_t cmd,
                                  uint64_t arg, uint64_t arg5, uint64_t arg6);
static int64_t sys_semtimedop_handler(uint64_t semid, uint64_t sops, uint64_t nsops,
                                      uint64_t timeout, uint64_t arg5, uint64_t arg6);
static int64_t sys_msgget_handler(uint64_t key, uint64_t msgflg, uint64_t arg3,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_msgsnd_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgflg, uint64_t arg5, uint64_t arg6);
static int64_t sys_msgrcv_handler(uint64_t msqid, uint64_t msgp, uint64_t msgsz,
                                  uint64_t msgtyp, uint64_t msgflg, uint64_t arg6);
static int64_t sys_msgctl_handler(uint64_t msqid, uint64_t cmd, uint64_t arg,
                                  uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_sendmmsg_handler(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t arg5, uint64_t arg6);
static int64_t sys_recvmmsg_handler(uint64_t sockfd, uint64_t msgvec, uint64_t vlen,
                                    uint64_t flags, uint64_t timeout, uint64_t arg6);
static int64_t sys_clock_adjtime_handler(uint64_t clk_id, uint64_t txc, uint64_t arg3,
                                         uint64_t arg4, uint64_t arg5, uint64_t arg6);
static int64_t sys_setns_handler(uint64_t fd, uint64_t nstype, uint64_t arg3,
                                 uint64_t arg4, uint64_t arg5, uint64_t arg6);

static syscall_handler_t syscall_table[MAX_SYSCALL] = {
    [SYS_read]       = sys_read_handler,
    [SYS_pread64]    = sys_pread64_handler,
    [SYS_pwrite64]   = sys_pwrite64_handler,
    [SYS_readv]      = sys_readv_handler,
    [SYS_writev]     = sys_writev_handler,
    [SYS_write]      = sys_write_handler,
    [SYS_open]       = sys_open_handler,
    [SYS_openat]     = sys_openat_handler,
    [SYS_openat2]    = sys_openat2_handler,
    [SYS_mknod]      = sys_mknod_handler,
    /* *at family (Linux x86_64 258-269, 280) */
    [SYS_mkdirat]    = sys_mkdirat_handler,
    [SYS_mknodat]    = sys_mknodat_handler,
    [SYS_fchownat]   = sys_fchownat_handler,
    [SYS_fstatat]    = sys_fstatat_handler,
    [SYS_unlinkat]   = sys_unlinkat_handler,
    [SYS_renameat]   = sys_renameat_handler,
    [SYS_linkat]     = sys_linkat_handler,
    [SYS_symlinkat]  = sys_symlinkat_handler,
    [SYS_readlinkat] = sys_readlinkat_handler,
    [SYS_fchmodat]   = sys_fchmodat_handler,
    [SYS_faccessat]  = sys_faccessat_handler,
    [SYS_utimensat]  = sys_utimensat_handler,
    [SYS_close]      = sys_close_handler,
    [SYS_stat]       = sys_stat_handler,
    [SYS_fstat]      = sys_fstat_handler,
    [SYS_lstat]      = sys_lstat_handler,
    [SYS_poll]       = sys_poll_handler,
    [SYS_access]     = sys_access_handler,
    [SYS_lseek]      = sys_lseek_handler,
    [SYS_clone]      = sys_clone_handler,
    [SYS_fork]       = sys_fork_handler,
    [SYS_execve]     = sys_execve_handler,
    [SYS_execveat]   = sys_execveat_handler,
    [SYS_exit]       = sys_exit_handler,
    [SYS_wait4]      = sys_wait4_handler,
    [SYS_nanosleep]  = sys_nanosleep_handler,
    [SYS_brk]        = sys_brk_handler,
    [SYS_munmap]     = sys_munmap_handler,
    [SYS_mprotect]        = sys_mprotect_handler,
    [SYS_pkey_mprotect]   = sys_pkey_mprotect_handler,
    [SYS_pkey_alloc]      = sys_pkey_alloc_handler,
    [SYS_pkey_free]       = sys_pkey_free_handler,
    [SYS_echo]       = sys_echo_handler,
    [SYS_ioctl]      = sys_ioctl_handler,
    [SYS_mmap]       = sys_mmap_handler,
    [SYS_pipe]       = sys_pipe_handler,
    [SYS_select]     = sys_select_handler,
    [SYS_sched_yield] = sys_sched_yield_handler,
    [SYS_mremap]     = sys_mremap_handler,
    [SYS_msync]      = sys_msync_handler,
    [SYS_mincore]    = sys_mincore_handler,
    [SYS_dup]        = sys_dup_handler,
    [SYS_dup2]       = sys_dup2_handler,
    [SYS_pause]      = sys_pause_handler,
    [SYS_alarm]      = sys_alarm_handler,
    [SYS_fcntl]      = sys_fcntl_handler,
    [SYS_flock]      = sys_flock_handler,
    [SYS_fsync]      = sys_fsync_handler,
    [SYS_fdatasync]  = sys_fdatasync_handler,
    [SYS_truncate]   = sys_truncate_handler,
    [SYS_ftruncate]  = sys_ftruncate_handler,
    [SYS_getcwd]     = sys_getcwd_handler,
    [SYS_chdir]      = sys_chdir_handler,
    [SYS_mkdir]      = sys_mkdir_handler,
    [SYS_rmdir]      = sys_rmdir_handler,
    [SYS_unlink]     = sys_unlink_handler,
    [SYS_link]       = sys_link_handler,
    [SYS_symlink]    = sys_symlink_handler,
    [SYS_readlink]   = sys_readlink_handler,
    [SYS_rename]     = sys_rename_handler,
    [SYS_chmod]      = sys_chmod_handler,
    [SYS_fchmod]     = sys_fchmod_handler,
    [SYS_chown]      = sys_chown_handler,
    [SYS_fchown]     = sys_fchown_handler,
    [SYS_lchown]     = sys_lchown_handler,
    [SYS_creat]      = sys_creat_handler,
    [SYS_setfsuid]   = sys_setfsuid_handler,
    [SYS_setfsgid]   = sys_setfsgid_handler,
    [SYS_getdents64] = sys_getdents64_handler,
    [SYS_getpid]     = sys_getpid_handler,
    [SYS_sigaction]  = sys_sigaction_handler,
    [SYS_sigprocmask] = sys_sigprocmask_handler,
    [SYS_sigreturn]  = sys_sigreturn_handler,
    [SYS_kill]       = sys_kill_handler,
    [SYS_time_millis] = sys_time_millis_handler,
    [SYS_gettimeofday] = sys_gettimeofday_handler,
    [SYS_time]       = sys_time_handler,
    [SYS_clock_gettime] = sys_clock_gettime_handler,
    [SYS_eventfd2]   = sys_eventfd2_handler,
    /* Socket operations */
    [SYS_socket]     = sys_socket_handler,
    [SYS_bind]       = sys_bind_handler,
    [SYS_listen]     = sys_listen_handler,
    [SYS_shutdown]   = sys_shutdown_handler,
    [SYS_accept]     = sys_accept_handler,
    [SYS_getsockname] = sys_getsockname_handler,
    [SYS_getpeername] = sys_getpeername_handler,
    [SYS_setsockopt] = sys_setsockopt_handler,
    [SYS_getsockopt] = sys_getsockopt_handler,
    [SYS_connect]    = sys_connect_handler,
    [SYS_sendto]     = sys_sendto_handler,
    [SYS_recvfrom]   = sys_recvfrom_handler,
    [SYS_sendmsg]    = sys_sendmsg_handler,
    [SYS_recvmsg]    = sys_recvmsg_handler,
    /* epoll operations */
    [SYS_epoll_create1] = sys_epoll_create1_handler,
    [SYS_epoll_create] = sys_epoll_create_handler,
    [SYS_epoll_ctl]    = sys_epoll_ctl_handler,
    [SYS_epoll_wait]   = sys_epoll_wait_handler,
    /* madvise operation */
    [SYS_madvise]      = sys_madvise_handler,
    /* process credential operations */
    [SYS_getuid]       = sys_getuid_handler,
    [SYS_geteuid]      = sys_geteuid_handler,
    [SYS_getgid]       = sys_getgid_handler,
    [SYS_getegid]      = sys_getegid_handler,
    [SYS_setuid]       = sys_setuid_handler,
    [SYS_seteuid]      = sys_seteuid_handler,
    [SYS_setgid]       = sys_setgid_handler,
    [SYS_setegid]      = sys_setegid_handler,
    [SYS_umask]        = sys_umask_handler,
    [SYS_uname]        = sys_uname_handler,
    /* Process info operations */
    [SYS_gettid]       = sys_gettid_handler,
    [SYS_getppid]      = sys_getppid_handler,
    [SYS_getpgrp]      = sys_getpgrp_handler,
    /* Note: SYS_setpgrp skipped (109 conflicts with SYS_seteuid) */
    [SYS_getsid]       = sys_getsid_handler,
    [SYS_setpgid]      = sys_setpgid_handler,
    [SYS_getpgid]      = sys_getpgid_handler,
    [SYS_setsid]       = sys_setsid_handler,
    [SYS_getrlimit]    = sys_getrlimit_handler,
    [SYS_getrusage]    = sys_getrusage_handler,
    [SYS_times]        = sys_times_handler,
    [SYS_ptrace]       = sys_ptrace_handler,
    [SYS_setrlimit]    = sys_setrlimit_handler,
    [SYS_getpriority]  = sys_getpriority_handler,
    [SYS_setpriority]  = sys_setpriority_handler,
    /* Scheduler param/policy syscalls */
    [SYS_sched_setparam]         = sys_sched_setparam_handler,
    [SYS_sched_getparam]         = sys_sched_getparam_handler,
    [SYS_sched_setscheduler]     = sys_sched_setscheduler_handler,
    [SYS_sched_getscheduler]     = sys_sched_getscheduler_handler,
    [SYS_sched_get_priority_max] = sys_sched_get_priority_max_handler,
    [SYS_sched_get_priority_min] = sys_sched_get_priority_min_handler,
    [SYS_sched_rr_get_interval]  = sys_sched_rr_get_interval_handler,
    /* xattr syscalls */
    [SYS_setxattr]     = sys_setxattr_handler,
    [SYS_lsetxattr]    = sys_lsetxattr_handler,
    [SYS_fsetxattr]    = sys_fsetxattr_handler,
    [SYS_getxattr]     = sys_getxattr_handler,
    [SYS_lgetxattr]    = sys_lgetxattr_handler,
    [SYS_fgetxattr]    = sys_fgetxattr_handler,
    [SYS_listxattr]    = sys_listxattr_handler,
    [SYS_llistxattr]   = sys_llistxattr_handler,
    [SYS_flistxattr]   = sys_flistxattr_handler,
    [SYS_removexattr]  = sys_removexattr_handler,
    [SYS_lremovexattr] = sys_lremovexattr_handler,
    [SYS_fremovexattr] = sys_fremovexattr_handler,
    /* waitid */
    [SYS_waitid]            = sys_waitid_handler,
    /* Linux keyring stubs */
    [SYS_add_key]           = sys_add_key_handler,
    [SYS_request_key]       = sys_request_key_handler,
    [SYS_keyctl]            = sys_keyctl_handler,
    /* legacy signalfd/eventfd (no flags variants) */
    [SYS_signalfd]          = sys_signalfd_handler,
    [SYS_eventfd]           = sys_eventfd_handler,
    /* inotify */
    [SYS_inotify_init]      = sys_inotify_init_handler,
    [SYS_inotify_add_watch] = sys_inotify_add_watch_handler,
    [SYS_inotify_rm_watch]  = sys_inotify_rm_watch_handler,
    /* splice/tee/vmsplice */
    [SYS_splice]       = sys_splice_handler,
    [SYS_tee]          = sys_tee_handler,
    [SYS_vmsplice]     = sys_vmsplice_handler,
    [SYS_inotify_init1] = sys_inotify_init1_handler,
    [SYS_preadv]              = sys_preadv_handler,
    [SYS_pwritev]             = sys_pwritev_handler,
    [SYS_preadv2]             = sys_preadv2_handler,
    [SYS_pwritev2]            = sys_pwritev2_handler,
    [SYS_rt_tgsigqueueinfo]   = sys_rt_tgsigqueueinfo_handler,
    [SYS_process_vm_readv]    = sys_process_vm_readv_handler,
    [SYS_process_vm_writev]   = sys_process_vm_writev_handler,
    [SYS_pidfd_open]          = sys_pidfd_open_handler,
    [SYS_pidfd_send_signal]   = sys_pidfd_send_signal_handler,
    [SYS_pidfd_getfd]         = sys_pidfd_getfd_handler,
    [SYS_sched_setattr]       = sys_sched_setattr_handler,
    [SYS_sched_getattr]       = sys_sched_getattr_handler,
    [SYS_seccomp]             = sys_seccomp_handler,
    [SYS_kcmp]                = sys_kcmp_handler,
    [SYS_faccessat2]          = sys_faccessat2_handler,
    /* time / itimer / clock */
    [SYS_getitimer]         = sys_getitimer_handler,
    [SYS_setitimer]         = sys_setitimer_handler,
    [SYS_sendfile]          = sys_sendfile_handler,
    [SYS_fchdir]            = sys_fchdir_handler,
    [SYS_vhangup]           = sys_vhangup_handler,
    [SYS_setreuid]          = sys_setreuid_handler,
    [SYS_setregid]          = sys_setregid_handler,
    [SYS_setresuid]         = sys_setresuid_handler,
    [SYS_getresuid]         = sys_getresuid_handler,
    [SYS_setresgid]         = sys_setresgid_handler,
    [SYS_getresgid]         = sys_getresgid_handler,
    [SYS_capget]            = sys_capget_handler,
    [SYS_capset]            = sys_capset_handler,
    [SYS_personality]       = sys_personality_handler,
    [SYS_statfs]            = sys_statfs_handler,
    [SYS_fstatfs]           = sys_fstatfs_handler,
    [SYS_mlock]             = sys_mlock_handler,
    [SYS_mlock2]            = sys_mlock2_handler,
    [SYS_munlock]           = sys_munlock_handler,
    [SYS_mlockall]          = sys_mlockall_handler,
    [SYS_munlockall]        = sys_munlockall_handler,
    [SYS_pivot_root]        = sys_pivot_root_handler,
    [SYS_prctl]             = sys_prctl_handler,
    [SYS_syslog]            = sys_syslog_handler,
    [SYS_rt_sigtimedwait]      = sys_rt_sigtimedwait_handler,
    [SYS_rt_sigqueueinfo]      = sys_rt_sigqueueinfo_handler,
    [SYS_reboot]            = sys_reboot_handler,
    [SYS_memfd_create]      = sys_memfd_create_handler,
    [SYS_sched_setaffinity] = sys_sched_setaffinity_handler,
    [SYS_sched_getaffinity] = sys_sched_getaffinity_handler,
    [SYS_fadvise64]         = sys_fadvise64_handler,
    [SYS_arch_prctl]        = sys_arch_prctl_handler,
    [SYS_adjtimex]          = sys_adjtimex_handler,
    [SYS_chroot]            = sys_chroot_handler,
    [SYS_sync]              = sys_sync_handler,
    [SYS_acct]              = sys_acct_handler,
    [SYS_settimeofday]      = sys_settimeofday_handler,
    [SYS_mount]             = sys_mount_handler,
    [SYS_umount2]           = sys_umount2_handler,
    [SYS_sysinfo]           = sys_sysinfo_handler,
    [SYS_renameat2]         = sys_renameat2_handler,
    [SYS_getrandom]         = sys_getrandom_handler,
    [SYS_membarrier]        = sys_membarrier_handler,
    [SYS_copy_file_range]   = sys_copy_file_range_handler,
    [SYS_rseq]              = sys_rseq_handler,
    [SYS_statx]             = sys_statx_handler,
    [SYS_tgkill]            = sys_tgkill_handler,
    [SYS_tkill]             = sys_tkill_handler,
    [SYS_vfork]             = sys_fork_handler,  /* vfork = fork (no shared MM) */
    [SYS_exit_group]        = sys_exit_group_handler,
    [SYS_getcpu]            = sys_getcpu_handler,
    [SYS_readahead]         = sys_readahead_handler,
    [SYS_futimesat]         = sys_futimesat_handler,
    [SYS_getgroups]         = sys_getgroups_handler,
    [SYS_setgroups]         = sys_setgroups_handler,
    [SYS_utimes]            = sys_utimes_handler,
    [SYS_utime]             = sys_utime_handler,
    /* NUMA memory policy — single-node stubs */
    [SYS_mbind]             = sys_mbind_handler,
    [SYS_set_mempolicy]     = sys_set_mempolicy_handler,
    [SYS_get_mempolicy]     = sys_get_mempolicy_handler,
    /* Legacy getdents / swap / ioport */
    [SYS_getdents]          = sys_getdents_handler,
    [SYS_swapon]            = sys_swapon_handler,
    [SYS_swapoff]           = sys_swapoff_handler,
    [SYS_iopl]              = sys_iopl_handler,
    [SYS_ioperm]            = sys_ioperm_handler,
    /* Linux AIO stubs (206-210) — return ENOSYS so libaio falls back to sync I/O */
    [SYS_io_setup]          = sys_io_setup_handler,
    [SYS_io_destroy]        = sys_io_destroy_handler,
    [SYS_io_getevents]      = sys_io_getevents_handler,
    [SYS_io_submit]         = sys_io_submit_handler,
    [SYS_io_cancel]         = sys_io_cancel_handler,
    /* io_uring stubs (425-427) — return ENOSYS so programs fall back to epoll */
    [SYS_io_uring_setup]    = sys_io_uring_setup_handler,
    [SYS_io_uring_enter]    = sys_io_uring_enter_handler,
    [SYS_io_uring_register] = sys_io_uring_register_handler,
    [SYS_socketpair]        = sys_socketpair_handler,
    [SYS_set_tid_address]   = sys_set_tid_address_handler,
    [SYS_timer_create]      = sys_timer_create_handler,
    [SYS_timer_settime]     = sys_timer_settime_handler,
    [SYS_timer_gettime]     = sys_timer_gettime_handler,
    [SYS_timer_getoverrun]  = sys_timer_getoverrun_handler,
    [SYS_timer_delete]      = sys_timer_delete_handler,
    [SYS_clock_settime]     = sys_clock_settime_handler,
    [SYS_clock_getres]      = sys_clock_getres_handler,
    [SYS_clock_nanosleep]   = sys_clock_nanosleep_handler,
    [SYS_unshare]           = sys_unshare_handler,
    [SYS_set_robust_list]   = sys_set_robust_list_handler,
    [SYS_get_robust_list]   = sys_get_robust_list_handler,
    [SYS_sync_file_range]   = sys_sync_file_range_handler,
    [SYS_epoll_pwait]       = sys_epoll_pwait_handler,
    [SYS_epoll_pwait2]      = sys_epoll_pwait2_handler,
    [SYS_timerfd_create]    = sys_timerfd_create_handler,
    [SYS_fallocate]         = sys_fallocate_handler,
    [SYS_timerfd_settime]   = sys_timerfd_settime_handler,
    [SYS_timerfd_gettime]   = sys_timerfd_gettime_handler,
    [SYS_prlimit64]         = sys_prlimit64_handler,
    [SYS_clock_adjtime]     = sys_clock_adjtime_handler,
    [SYS_syncfs]            = sys_syncfs_handler,
    [SYS_sendmmsg]          = sys_sendmmsg_handler,
    [SYS_setns]             = sys_setns_handler,
    [SYS_recvmmsg]          = sys_recvmmsg_handler,
    [SYS_clone3]            = sys_clone3_handler,
    [SYS_close_range]       = sys_close_range_handler,
    [SYS_sethostname]       = sys_sethostname_handler,
    [SYS_setdomainname]     = sys_setdomainname_handler,
    [SYS_ioprio_set]        = sys_ioprio_set_handler,
    [SYS_ioprio_get]        = sys_ioprio_get_handler,
    /* signal / io-multiplex */
    [SYS_sigpending]   = sys_sigpending_handler,
    [SYS_sigsuspend]   = sys_sigsuspend_handler,
    [SYS_sigaltstack]  = sys_sigaltstack_handler,
    [SYS_futex]        = sys_futex_handler,
    [SYS_pselect6]     = sys_pselect6_handler,
    [SYS_ppoll]        = sys_ppoll_handler,
    [SYS_pipe2]        = sys_pipe2_handler,
    [SYS_signalfd4]    = sys_signalfd4_handler,
    [SYS_dup3]         = sys_dup3_handler,
    [SYS_accept4]      = sys_accept4_handler,
    [SYS_shmget]       = sys_shmget_handler,
    [SYS_shmat]        = sys_shmat_handler,
    [SYS_shmdt]        = sys_shmdt_handler,
    [SYS_shmctl]       = sys_shmctl_handler,
    [SYS_semget]       = sys_semget_handler,
    [SYS_semop]        = sys_semop_handler,
    [SYS_semctl]       = sys_semctl_handler,
    [SYS_semtimedop]   = sys_semtimedop_handler,
    [SYS_msgget]       = sys_msgget_handler,
    [SYS_msgsnd]       = sys_msgsnd_handler,
    [SYS_msgrcv]       = sys_msgrcv_handler,
    [SYS_msgctl]       = sys_msgctl_handler,
    /* POSIX message queues */
    [SYS_mq_open]         = sys_mq_open_handler,
    [SYS_mq_unlink]       = sys_mq_unlink_handler,
    [SYS_mq_timedsend]    = sys_mq_timedsend_handler,
    [SYS_mq_timedreceive] = sys_mq_timedreceive_handler,
    [SYS_mq_notify]       = sys_mq_notify_handler,
    [SYS_mq_getsetattr]   = sys_mq_getsetattr_handler,
    /* Capability-based syscalls (Phase 1) */
    [SYS_open_cap]     = sys_open_cap_handler,
    [SYS_read_cap]     = sys_read_cap_handler,
    [SYS_write_cap]    = sys_write_cap_handler,
    [SYS_close_cap]    = sys_close_cap_handler,
    [SYS_lseek_cap]    = sys_lseek_cap_handler,
    [SYS_fstat_cap]    = sys_fstat_cap_handler,
    [SYS_fsync_cap]    = sys_fsync_cap_handler,
    [SYS_mkdirat_cap]  = sys_mkdirat_cap_handler,
    [SYS_unlinkat_cap] = sys_unlinkat_cap_handler,
    [SYS_rmdirat_cap]  = sys_rmdirat_cap_handler,
    [SYS_statat_cap]   = sys_statat_cap_handler,
    /* Linux 5.13-5.16 stubs */
    [SYS_landlock_create_ruleset] = sys_landlock_create_ruleset_handler,
    [SYS_landlock_add_rule]       = sys_landlock_add_rule_handler,
    [SYS_landlock_restrict_self]  = sys_landlock_restrict_self_handler,
    [SYS_memfd_secret]            = sys_memfd_secret_handler,
    [SYS_futex_waitv]             = sys_futex_waitv_handler,
    [SYS_process_madvise]         = sys_process_madvise_handler,
    [SYS_set_mempolicy_home_node] = sys_set_mempolicy_home_node_handler,
    [SYS_cachestat]               = sys_cachestat_handler,
    [SYS_fchmodat2]               = sys_fchmodat2_handler,
    [SYS_mseal]                   = sys_mseal_handler,
    /* perf_event_open/fanotify/userfaultfd/bpf stubs */
    [SYS_perf_event_open]         = sys_perf_event_open_handler,
    [SYS_fanotify_init]           = sys_fanotify_init_handler,
    [SYS_fanotify_mark]           = sys_fanotify_mark_handler,
    [SYS_userfaultfd]             = sys_userfaultfd_handler,
    [SYS_bpf]                     = sys_bpf_handler,
    /* New mount API stubs (Linux 5.2-5.12) */
    [SYS_open_tree]               = sys_open_tree_handler,
    [SYS_move_mount_new]          = sys_move_mount_new_handler,
    [SYS_fsopen]                  = sys_fsopen_handler,
    [SYS_fsconfig]                = sys_fsconfig_handler,
    [SYS_fsmount]                 = sys_fsmount_handler,
    [SYS_fspick]                  = sys_fspick_handler,
    [SYS_mount_setattr]           = sys_mount_setattr_handler,
    /* File handle stubs (Linux 2.6.39+) */
    [SYS_name_to_handle_at]       = sys_name_to_handle_at_handler,
    [SYS_open_by_handle_at]       = sys_open_by_handle_at_handler,
    /* Linux 6.8+ statmount/listmount/LSM stubs */
    [SYS_statmount]               = sys_statmount_handler,
    [SYS_listmount]               = sys_listmount_handler,
    [SYS_lsm_get_self_attr]       = sys_lsm_get_self_attr_handler,
    [SYS_lsm_set_self_attr]       = sys_lsm_set_self_attr_handler,
    [SYS_lsm_list_modules]        = sys_lsm_list_modules_handler,
};

/* ============================================================
 *   Syscall Dispatcher
 * ============================================================ */

/**
 * Main syscall dispatch function.
 * Called from architecture-specific syscall entry point.
 *
 * @param syscall_num Syscall number
 * @param arg1-arg6   Syscall arguments
 * @return Syscall return value (or -errno on error)
 */
int64_t posix_syscall_dispatch(uint64_t syscall_num,
                                uint64_t arg1, uint64_t arg2, uint64_t arg3,
                                uint64_t arg4, uint64_t arg5, uint64_t arg6) {

    /* Validate syscall number */
    if (syscall_num >= MAX_SYSCALL) {
        fut_printf("[DISPATCHER] ERROR: syscall %lu >= MAX_SYSCALL %d\n", syscall_num, MAX_SYSCALL);
        return -38;  /* -ENOSYS: Function not implemented */
    }

    /* Get handler from table */
    syscall_handler_t handler = syscall_table[syscall_num];
    if (handler == NULL) {
        handler = sys_unimplemented;
    }

    if (handler == sys_unimplemented) {
        fut_printf("[SYSCALL] unimplemented nr=%lu\n", syscall_num);
    }

    /* Call handler */
    int64_t result = handler(arg1, arg2, arg3, arg4, arg5, arg6);

    return result;
}

/* ============================================================
 *   Syscall Initialization
 * ============================================================ */

/**
 * Initialize POSIX syscall subsystem.
 */
void posix_syscall_init(void) {
    /* Initialize unimplemented syscalls */
    for (int i = 0; i < MAX_SYSCALL; i++) {
        if (syscall_table[i] == NULL) {
            syscall_table[i] = sys_unimplemented;
        }
    }
}

/**
 * Deliver a signal to a task by setting up a signal frame on the user stack
 * and modifying the interrupt frame to call the handler.
 *
 * This implements proper signal frame setup as per System V AMD64 ABI.
 * The handler receives:
 *   rdi = signal number
 *   rsi = siginfo_t *
 *   rdx = ucontext_t *
 *
 * @param current Current task
 * @param signum Signal number to deliver
 * @param frame Interrupt frame to modify
 * @return true if signal was delivered, false if handler not available
 */
/* syscall_ret: the return value of the interrupted syscall, or LONG_MAX if
 * not called from a syscall context. Used to implement SA_RESTART. */
static bool posix_deliver_signal(fut_task_t *current, int signum,
                                 fut_interrupt_frame_t *frame, long syscall_ret,
                                 fut_thread_t *from_thread_info) {

    if (!current || !frame) {
        return false;
    }

    /* Get the handler for this signal */
    sighandler_t handler = fut_signal_get_handler(current, signum);

    /* Clear this signal from pending (task-wide; caller may also clear per-thread) */
    uint64_t signal_bit = (1ULL << (signum - 1));
    __atomic_and_fetch(&current->pending_signals, ~signal_bit, __ATOMIC_ACQ_REL);

    /* Handle SIG_IGN - just ignore the signal */
    if (handler == SIG_IGN) {
        return true;  /* Signal was "handled" by ignoring it */
    }

    /* Handle SIG_DFL - perform default action */
    if (!handler || handler == SIG_DFL) {
        extern void fut_task_signal_exit(int sig);
        int action = fut_signal_get_default_action(signum);
        switch (action) {
            case 0:  /* SIG_ACTION_TERM */
            case 1:  /* SIG_ACTION_CORE */
                fut_printf("[SIGNAL] Default action: terminate task %llu on signal %d\n",
                           current->pid, signum);
                fut_task_signal_exit(signum);
                return true;
            case 2: {  /* SIG_ACTION_STOP */
                extern void fut_task_do_stop(fut_task_t *t, int sig);
                fut_task_do_stop(current, signum);
                return true;
            }
            case 3: {  /* SIG_ACTION_CONT */
                extern void fut_task_do_cont(fut_task_t *t);
                fut_task_do_cont(current);
                return true;
            }
            case 4:  /* SIG_ACTION_IGN */
            default:
                return true;  /* Signal was "handled" by default ignore */
        }
    }

    /* Get user stack pointer from frame (architecture-specific) */
#ifdef __x86_64__
    uint64_t user_sp = frame->rsp;
#elif defined(__aarch64__)
    uint64_t user_sp = frame->sp;
#else
#error "Unsupported architecture for signal delivery"
#endif

    /* SA_ONSTACK: if handler requests the alternate signal stack and one is
     * configured, switch user_sp to the top of the alternate stack.
     * Conditions: SA_ONSTACK set, altstack configured (not SS_DISABLE), and
     * we are not already executing on the altstack (not SS_ONSTACK). */
    unsigned long h_flags = (signum > 0 && signum < _NSIG)
        ? current->signal_handler_flags[signum - 1] : 0;
    /* Snapshot the altstack state BEFORE any modification; saved into uc_stack
     * so that sigreturn can re-arm an altstack that was autodisarmed. */
    struct sigaltstack saved_altstack = current->sig_altstack;
    if ((h_flags & SA_ONSTACK)
        && current->sig_altstack.ss_sp != NULL
        && !(current->sig_altstack.ss_flags & SS_DISABLE)
        && !(current->sig_altstack.ss_flags & SS_ONSTACK)) {
        /* Alternate stack grows downward: start at top = base + size */
        user_sp = (uint64_t)(uintptr_t)current->sig_altstack.ss_sp
                  + (uint64_t)current->sig_altstack.ss_size;
        current->sig_altstack.ss_flags |= SS_ONSTACK;
        /* SS_AUTODISARM (Linux 4.7+): atomically disable the altstack when
         * delivering a signal to it, so nested signals cannot reuse it. */
        if (current->sig_altstack.ss_flags & SS_AUTODISARM)
            current->sig_altstack.ss_flags = SS_DISABLE;
    }

    /* Allocate rt_sigframe on user stack.
     * x86-64 ABI: at function entry RSP % 16 == 8 (as if 'call' just ran,
     * pushing the return address).  Linux: sp = round_down(sp-sz, 16) - 8.
     * ARM64 ABI: RSP must be 16-byte aligned on function entry (no -8). */
    user_sp -= sizeof(struct rt_sigframe);
    user_sp &= ~15ULL;  /* Align to 16 bytes */
#ifdef __x86_64__
    user_sp -= 8;        /* x86-64: pretcode at [RSP], so RSP must be (16n+8) */
#endif

    /* Verify user stack is accessible (basic check) */
    if (user_sp < 0x400000) {  /* Below reasonable user stack threshold */
        fut_printf("[SIGNAL] Stack underflow attempting to deliver signal %d\n", signum);
        return false;
    }

    /* Build signal frame in kernel memory */
    struct rt_sigframe sigframe = {};

    /* Use stored per-signal siginfo_t (set by fut_signal_send_with_info for
     * rt_sigqueueinfo, or defaulted to SI_USER/SI_TKILL by fut_signal_send). */
    if (from_thread_info) {
        __builtin_memcpy(&sigframe.info,
                         &from_thread_info->thread_sig_queue_info[signum - 1],
                         sizeof(siginfo_t));
    } else {
        __builtin_memcpy(&sigframe.info, &current->sig_queue_info[signum - 1],
                         sizeof(siginfo_t));
    }
    sigframe.info.si_signum = signum;

    /* Fill in machine context (CPU registers at time of interruption) */
#ifdef __x86_64__
    mcontext_t *mctx = &sigframe.uc.uc_mcontext;
    mctx->gregs.r8 = frame->r8;
    mctx->gregs.r9 = frame->r9;
    mctx->gregs.r10 = frame->r10;
    mctx->gregs.r11 = frame->r11;
    mctx->gregs.r12 = frame->r12;
    mctx->gregs.r13 = frame->r13;
    mctx->gregs.r14 = frame->r14;
    mctx->gregs.r15 = frame->r15;
    mctx->gregs.rdi = frame->rdi;
    mctx->gregs.rsi = frame->rsi;
    mctx->gregs.rbp = frame->rbp;
    mctx->gregs.rbx = frame->rbx;
    mctx->gregs.rdx = frame->rdx;
    mctx->gregs.rax = frame->rax;
    mctx->gregs.rcx = frame->rcx;
    mctx->gregs.rsp = frame->rsp;  /* Original RSP before sigframe */
    mctx->gregs.rip = frame->rip;  /* Original RIP to return to */
    /* SA_RESTART: if the syscall was interrupted (EINTR) and the handler
     * has SA_RESTART set, rewind RIP to the 'syscall' instruction so that
     * after the handler returns via rt_sigreturn, the syscall is re-executed.
     * The 'syscall' instruction (0F 05) is 2 bytes, so rip-2 is the restart PC.
     * RAX in the saved frame still contains the syscall number (the return
     * value is not written until syscall_entry_c returns), so re-execution
     * is automatic. */
    {
        unsigned long h_flags = current->signal_handler_flags[signum - 1];
        if ((h_flags & SA_RESTART) && syscall_ret == -EINTR) {
            mctx->gregs.rip = frame->rip - 2;  /* rewind to syscall insn */
        }
    }
    mctx->gregs.eflags = frame->rflags;
    mctx->gregs.cs = frame->cs;
    mctx->gregs.gs = frame->gs;
    mctx->gregs.fs = frame->fs;
    mctx->gregs.__pad0 = 0;
    mctx->gregs.err = frame->error_code;
    mctx->gregs.trapno = frame->vector;
#elif defined(__aarch64__)
    /* ARM64: Fill in machine context with registers at time of interruption */
    mcontext_t *mctx = &sigframe.uc.uc_mcontext;

    /* Copy all general purpose registers x0-x30 */
    for (int i = 0; i < 31; i++) {
        mctx->gregs.x[i] = frame->x[i];
    }

    /* Copy special ARM64 registers */
    mctx->gregs.sp = frame->sp;            /* Stack pointer (SP_EL0) */
    mctx->gregs.pc = frame->pc;            /* Program counter (ELR_EL1) */
    /* SA_RESTART on ARM64: rewind PC to 'svc' instruction (4 bytes) */
    {
        unsigned long h_flags = current->signal_handler_flags[signum - 1];
        if ((h_flags & SA_RESTART) && syscall_ret == -EINTR) {
            mctx->gregs.pc = frame->pc - 4;
        }
    }
    mctx->gregs.pstate = frame->pstate;    /* Processor state (SPSR_EL1) */
    mctx->gregs.fault_address = frame->far; /* Fault address (FAR_EL1) */

    /* Copy NEON/FPU registers
     * frame->fpu_state stores them as 2x uint64_t per register,
     * but sigcontext stores them as __uint128_t */
    for (int i = 0; i < 32; i++) {
        __uint128_t v = ((__uint128_t)frame->fpu_state[2*i+1] << 64) | frame->fpu_state[2*i];
        mctx->gregs.v[i] = v;
    }

    mctx->gregs.fpsr = frame->fpsr;  /* Floating-point status register */
    mctx->gregs.fpcr = frame->fpcr;  /* Floating-point control register */
#else
#error "Unsupported architecture for signal delivery"
#endif

    /* Fill in user context with signal mask tracking */
    sigframe.uc.uc_flags = 0;
    sigframe.uc.uc_link = NULL;
    /* Save the altstack state at delivery time (snapshot taken before SS_AUTODISARM
     * disabled it) so sigreturn can re-arm an autodisarmed altstack. */
    sigframe.uc.uc_stack.ss_sp    = saved_altstack.ss_sp;
    sigframe.uc.uc_stack.ss_flags = saved_altstack.ss_flags;
    sigframe.uc.uc_stack.ss_size  = saved_altstack.ss_size;
    /* Save the CURRENT per-thread signal mask so sigreturn can restore it */
    {
        fut_thread_t *cur_thr = fut_thread_current();
        uint64_t *mptr = cur_thr ? &cur_thr->signal_mask : &current->signal_mask;
        uint64_t saved_mask = __atomic_load_n(mptr, __ATOMIC_ACQUIRE);
        sigframe.uc.uc_sigmask.__mask = saved_mask;

        /* Apply the handler's sa_mask during delivery:
         * Block additional signals specified in the handler's sa_mask.
         * Linux also blocks the signal itself during delivery unless SA_NODEFER
         * is set (prevents recursive delivery of the same signal). */
        if (signum > 0 && signum < _NSIG) {
            uint64_t handler_mask = current->signal_handler_masks[signum - 1];
            /* Auto-block the delivered signal unless SA_NODEFER */
            if (!(current->signal_handler_flags[signum - 1] & SA_NODEFER)) {
                handler_mask |= (1ULL << (signum - 1));
            }
            __atomic_or_fetch(mptr, handler_mask, __ATOMIC_ACQ_REL);
        }
    }

    /* Set return address (for when handler calls sigreturn).
     * If the application registered a restorer via SA_RESTORER (glibc/musl always
     * do this with __restore_rt which calls rt_sigreturn), use it so that signal
     * handlers can return normally without crashing. */
    if (signum > 0 && signum < _NSIG &&
        (current->signal_handler_flags[signum - 1] & SA_RESTORER) &&
        current->signal_handler_restorers[signum - 1] != NULL) {
        sigframe.return_address = current->signal_handler_restorers[signum - 1];
    } else {
        sigframe.return_address = NULL;
    }
    sigframe.pad = 0;

    /* Copy frame to user stack */
    if (fut_copy_to_user((void *)user_sp, &sigframe, sizeof(sigframe)) != 0) {
        fut_printf("[SIGNAL] Failed to copy sigframe to user stack for signal %d\n", signum);
        return false;
    }

    /* Modify interrupt frame to call handler */
    uint64_t siginfo_addr = user_sp + offsetof(struct rt_sigframe, info);
    uint64_t ucontext_addr = user_sp + offsetof(struct rt_sigframe, uc);

#ifdef __x86_64__
    /* x86_64 calling convention:
     *   rdi = signal number
     *   rsi = siginfo_t *
     *   rdx = ucontext_t *
     */
    frame->rdi = (uint64_t)signum;
    frame->rsi = siginfo_addr;
    frame->rdx = ucontext_addr;
    frame->rip = (uint64_t)handler;
    frame->rsp = user_sp;
#elif defined(__aarch64__)
    /* ARM64 calling convention:
     *   x0 = signal number
     *   x1 = siginfo_t *
     *   x2 = ucontext_t *
     *   x30 (LR) = sa_restorer: handler 'ret' (br x30) → trampoline → rt_sigreturn
     */
    frame->x[0] = (uint64_t)signum;
    frame->x[1] = siginfo_addr;
    frame->x[2] = ucontext_addr;
    frame->pc = (uint64_t)handler;
    frame->sp = user_sp;
    frame->x[30] = (signum > 0 && signum < _NSIG &&
                    (current->signal_handler_flags[signum - 1] & SA_RESTORER) &&
                    current->signal_handler_restorers[signum - 1] != NULL)
        ? (uint64_t)(uintptr_t)current->signal_handler_restorers[signum - 1] : 0;
#else
#error "Unsupported architecture for signal frame modification"
#endif

    /* Apply SA_RESETHAND flag if set:
     * Reset handler to SIG_DFL after delivery */
    if (signum > 0 && signum <= _NSIG && (current->signal_handler_flags[signum - 1] & SA_RESETHAND)) {
        fut_signal_set_handler(current, signum, SIG_DFL);
        fut_printf("[SIGNAL] Applied SA_RESETHAND for signal %d\n", signum);
    }

    fut_printf("[SIGNAL] Delivered signal %d to task %llu, handler=%p, frame=%p\n",
              signum, current->pid, (void *)(uintptr_t)handler, (void *)user_sp);

    return true;
}

/**
 * Check for pending signals and deliver them.
 * Called from syscall return path to give pending signals a chance to execute.
 *
 * @param current Current task
 * @param frame Interrupt frame to modify for signal delivery
 * @return Signal number if one was delivered, 0 if no signals pending
 */
static int check_and_deliver_pending_signals(fut_task_t *current,
                                             fut_interrupt_frame_t *frame,
                                             long syscall_ret) {
    if (!current || !frame) {
        return 0;
    }

    fut_thread_t *cur_thread = fut_thread_current();
    /* POSIX: use current thread's per-thread signal mask */
    uint64_t signal_mask = cur_thread ?
        __atomic_load_n(&cur_thread->signal_mask, __ATOMIC_ACQUIRE) :
        __atomic_load_n(&current->signal_mask, __ATOMIC_ACQUIRE);

    /* 1. Thread-directed signals (tgkill/tkill) have priority over task-wide */
    if (cur_thread) {
        uint64_t tp = __atomic_load_n(&cur_thread->thread_pending_signals, __ATOMIC_ACQUIRE);
        uint64_t deliverable = tp & ~signal_mask;
        for (int signum = 1; signum < _NSIG && deliverable; signum++) {
            uint64_t bit = (1ULL << (signum - 1));
            if (deliverable & bit) {
                /* Clear per-thread bit BEFORE delivery to prevent re-delivery */
                __atomic_and_fetch(&cur_thread->thread_pending_signals, ~bit, __ATOMIC_ACQ_REL);
                /* Also clear task-wide bit in case of concurrent kill() */
                __atomic_and_fetch(&current->pending_signals, ~bit, __ATOMIC_ACQ_REL);
                if (posix_deliver_signal(current, signum, frame, syscall_ret, cur_thread)) {
                    return signum;
                }
                break;
            }
        }
    }

    /* 2. Task-wide signals (kill/alarm/SIGCHLD/etc.) */
    for (int signum = 1; signum < _NSIG; signum++) {
        if (fut_signal_is_pending(current, signum)) {
            if (posix_deliver_signal(current, signum, frame, syscall_ret, NULL)) {
                return signum;
            }
        }
    }

    return 0;
}

/* Syscall tracing for debugging userspace bring-up issues.
 * Traces the first SYSCALL_TRACE_COUNT syscalls to serial output.
 * Disable by setting SYSCALL_TRACE_COUNT to 0. */
#define SYSCALL_TRACE_COUNT 0
static volatile int syscall_trace_remaining = SYSCALL_TRACE_COUNT;

long syscall_entry_c(uint64_t nr,
                     uint64_t a1, uint64_t a2, uint64_t a3,
                     uint64_t a4, uint64_t a5, uint64_t a6,
                     uint64_t *frame_ptr) {
    /* Trace first N syscalls to help debug userspace bring-up */
    int do_trace = 0;
    if (SYSCALL_TRACE_COUNT > 0 && syscall_trace_remaining > 0) {
        syscall_trace_remaining--;
        do_trace = 1;
        /* Direct serial output to avoid any console/VFS dependencies */
        fut_printf("[SYSCALL-TRACE] nr=%llu a1=0x%llx a2=0x%llx a3=0x%llx\n",
                   (unsigned long long)nr,
                   (unsigned long long)a1,
                   (unsigned long long)a2,
                   (unsigned long long)a3);
    }

    long ret = (long)posix_syscall_dispatch(nr, a1, a2, a3, a4, a5, a6);

    if (do_trace) {
        fut_printf("[SYSCALL-TRACE] nr=%llu -> ret=%ld\n",
                   (unsigned long long)nr, ret);
    }

    /* Check for pending signals and deliver them before returning to user */
    extern fut_task_t *fut_task_current(void);

    fut_task_t *current = fut_task_current();
    if (current && frame_ptr) {
        /* Check both task-wide pending and per-thread pending (tgkill) */
        fut_thread_t *cur_thread = fut_thread_current();
        bool has_thread_pending = cur_thread &&
            (__atomic_load_n(&cur_thread->thread_pending_signals, __ATOMIC_ACQUIRE) != 0);
        bool has_task_pending = (__atomic_load_n(&current->pending_signals, __ATOMIC_ACQUIRE) != 0);
        if (has_thread_pending || has_task_pending) {
            fut_interrupt_frame_t *frame = (fut_interrupt_frame_t *)frame_ptr;
            check_and_deliver_pending_signals(current, frame, ret);
        }
    }

    return ret;
}

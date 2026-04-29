// SPDX-License-Identifier: MPL-2.0

#pragma once

/* Per-arch native Linux syscall numbering.
 *
 * x86_64 keeps its historical numbers (the kernel was originally
 * x86_64-only). aarch64 uses the Linux generic syscall numbers that
 * the ARM64 kernel ABI is built around — this matches what the
 * kernel's syscall_table actually registers for ARM64-native indices,
 * so userland binaries built against these numbers do not need any
 * x86_64-compat aliasing in the kernel.
 *
 * Where ARM64's generic syscall set has dropped a deprecated entry
 * (open, dup2, pipe, fork, mkdir, stat/lstat, unlink, …), we use a
 * Futura-internal sentinel ≥ 1024.  libfutura's wrapper functions
 * implement those by routing to the modern *at variant in user space.
 */

#if defined(__aarch64__)

/* Linux ARM64 generic syscall numbers (from <asm-generic/unistd.h>). */
#define SYS_io_setup            0
#define SYS_io_destroy          1
#define SYS_io_submit           2
#define SYS_io_cancel           3
#define SYS_io_getevents        4
#define SYS_setxattr            5
#define SYS_lsetxattr           6
#define SYS_fsetxattr           7
#define SYS_getxattr            8
#define SYS_lgetxattr           9
#define SYS_fgetxattr           10
#define SYS_listxattr           11
#define SYS_llistxattr          12
#define SYS_flistxattr          13
#define SYS_removexattr         14
#define SYS_lremovexattr        15
#define SYS_fremovexattr        16
#define SYS_getcwd              17
#define SYS_eventfd2            19
#define SYS_epoll_create1       20
#define SYS_epoll_ctl           21
#define SYS_epoll_pwait         22
#define SYS_epoll_wait          22  /* Same as epoll_pwait — pass NULL sigmask in libfutura */
#define SYS_dup                 23
#define SYS_dup3                24
#define SYS_fcntl               25
#define SYS_inotify_init1       26
#define SYS_inotify_add_watch   27
#define SYS_inotify_rm_watch    28
#define SYS_ioctl               29
#define SYS_flock               32
#define SYS_mknodat             33
#define SYS_mkdirat             34
#define SYS_unlinkat            35
#define SYS_symlinkat           36
#define SYS_linkat              37
#define SYS_renameat            38
#define SYS_umount2             39
#define SYS_mount               40
#define SYS_pivot_root          41
#define SYS_statfs              43
#define SYS_fstatfs             44
#define SYS_truncate            45
#define SYS_ftruncate           46
#define SYS_fallocate           47
#define SYS_faccessat           48
#define SYS_chdir               49
#define SYS_fchdir              50
#define SYS_chroot              51
#define SYS_fchmod              52
#define SYS_fchmodat            53
#define SYS_fchownat            54
#define SYS_fchown              55
#define SYS_openat              56
#define SYS_close               57
#define SYS_pipe2               59
#define SYS_lseek               62
#define SYS_read                63
#define SYS_write               64
#define SYS_readv               65
#define SYS_writev              66
#define SYS_pread64             67
#define SYS_pwrite64            68
#define SYS_preadv              69
#define SYS_pwritev             70
#define SYS_sendfile            71
#define SYS_pselect6            72
#define SYS_ppoll               73
#define SYS_signalfd4           74
#define SYS_vmsplice            75
#define SYS_splice              76
#define SYS_tee                 77
#define SYS_readlinkat          78
#define SYS_newfstatat          79
#define SYS_fstat               80
#define SYS_sync                81
#define SYS_fsync               82
#define SYS_fdatasync           83
#define SYS_capget              90
#define SYS_capset              91
#define SYS_exit                93
#define SYS_exit_group          94
#define SYS_waitid              95
#define SYS_set_tid_address     96
#define SYS_futex               98
#define SYS_set_robust_list     99
#define SYS_get_robust_list     100
#define SYS_nanosleep           101
#define SYS_getitimer           102
#define SYS_setitimer           103
#define SYS_kexec_load          104
#define SYS_clock_settime       112
#define SYS_clock_gettime       113
#define SYS_clock_getres        114
#define SYS_clock_nanosleep     115
#define SYS_syslog              116
#define SYS_ptrace              117
#define SYS_sched_setparam      118
#define SYS_sched_setscheduler  119
#define SYS_sched_getscheduler  120
#define SYS_sched_getparam      121
#define SYS_sched_setaffinity   122
#define SYS_sched_getaffinity   123
#define SYS_sched_yield         124
#define SYS_sched_get_priority_max 125
#define SYS_sched_get_priority_min 126
#define SYS_kill                129
#define SYS_tkill               130
#define SYS_tgkill              131
#define SYS_sigaltstack         132
#define SYS_rt_sigsuspend       133
#define SYS_sigaction           134
#define SYS_rt_sigaction        134
#define SYS_sigprocmask         135
#define SYS_rt_sigprocmask      135
#define SYS_rt_sigpending       136
#define SYS_rt_sigtimedwait     137
#define SYS_rt_sigqueueinfo     138
#define SYS_rt_sigreturn        139
#define SYS_setpriority         140
#define SYS_getpriority         141
#define SYS_reboot              142
#define SYS_setregid            143
#define SYS_setgid              144
#define SYS_setreuid            145
#define SYS_setuid              146
#define SYS_setresuid           147
#define SYS_getresuid           148
#define SYS_setresgid           149
#define SYS_getresgid           150
#define SYS_setfsuid            151
#define SYS_setfsgid            152
#define SYS_times               153
#define SYS_setpgid             154
#define SYS_getpgid             155
#define SYS_getsid              156
#define SYS_setsid              157
#define SYS_getgroups           158
#define SYS_setgroups           159
#define SYS_uname               160
#define SYS_setrlimit           164
#define SYS_getrlimit           163
#define SYS_getrusage           165
#define SYS_umask               166
#define SYS_prctl               167
#define SYS_getcpu              168
#define SYS_gettimeofday        169
#define SYS_settimeofday        170
#define SYS_adjtimex            171
#define SYS_getpid              172
#define SYS_getppid             173
#define SYS_getuid              174
#define SYS_geteuid             175
#define SYS_getgid              176
#define SYS_getegid             177
#define SYS_gettid              178
#define SYS_sysinfo             179
#define SYS_socket              198
#define SYS_socketpair          199
#define SYS_bind                200
#define SYS_listen              201
#define SYS_accept              202
#define SYS_connect             203
#define SYS_getsockname         204
#define SYS_getpeername         205
#define SYS_sendto              206
#define SYS_recvfrom            207
#define SYS_setsockopt          208
#define SYS_getsockopt          209
#define SYS_shutdown            210
#define SYS_sendmsg             211
#define SYS_recvmsg             212
#define SYS_getdents64          61
#define SYS_brk                 214
#define SYS_munmap              215
#define SYS_mremap              216
#define SYS_clone               220
#define SYS_execve              221
#define SYS_mmap                222
#define SYS_mprotect            226
#define SYS_msync               227
#define SYS_mincore             228
#define SYS_madvise             231
#define SYS_remap_file_pages    234
#define SYS_mbind               235
#define SYS_get_mempolicy       236
#define SYS_set_mempolicy       237
#define SYS_migrate_pages       238
#define SYS_move_pages          239
#define SYS_rt_tgsigqueueinfo   240
#define SYS_perf_event_open     241
#define SYS_accept4             242
#define SYS_recvmmsg            243
#define SYS_wait4               260
#define SYS_waitpid             260   /* alias to wait4 */
#define SYS_prlimit64           261
#define SYS_fanotify_init       262
#define SYS_fanotify_mark       263
#define SYS_name_to_handle_at   264
#define SYS_open_by_handle_at   265
#define SYS_clock_adjtime       266
#define SYS_syncfs              267
#define SYS_setns               268
#define SYS_sendmmsg            269
#define SYS_process_vm_readv    270
#define SYS_process_vm_writev   271
#define SYS_kcmp                272
#define SYS_finit_module        273
#define SYS_sched_setattr       274
#define SYS_sched_getattr       275
#define SYS_renameat2           276
#define SYS_seccomp             277
#define SYS_getrandom           278
#define SYS_memfd_create        279
#define SYS_bpf                 280
#define SYS_execveat            281
#define SYS_userfaultfd         282
#define SYS_membarrier          283
#define SYS_mlock2              284
#define SYS_copy_file_range     285
#define SYS_preadv2             286
#define SYS_pwritev2            287
#define SYS_pkey_mprotect       288
#define SYS_pkey_alloc          289
#define SYS_pkey_free           290
#define SYS_statx               291

/* Deprecated x86_64-style syscalls. ARM64 generic doesn't define
 * these. libfutura translates them to the modern *at and *2 variants
 * in user-space wrappers; the numbers below are Futura-internal
 * sentinels in the >= 1024 private range so they cannot collide with
 * real ARM64 syscalls. */
#define SYS_open                1024
#define SYS_stat                1025
#define SYS_lstat               1026
#define SYS_poll                1027
#define SYS_access              1028
#define SYS_pipe                1029
#define SYS_select              1030
#define SYS_dup2                1031
#define SYS_alarm               1032
#define SYS_pause               1033
#define SYS_fork                1034
#define SYS_unlink              1035
#define SYS_rmdir               1036
#define SYS_mkdir               1037
#define SYS_rename              1038
#define SYS_symlink             1039
#define SYS_readlink            1040
#define SYS_link                1041
#define SYS_chmod               1042
#define SYS_chown               1043
#define SYS_lchown              1044
#define SYS_creat               1045
#define SYS_time                1046
#define SYS_eventfd             1047
#define SYS_epoll_create        1048
#define SYS_signalfd            1049
#define SYS_getpgrp             1050
#define SYS_setpgrp             1051

/* Futura extensions */
#define SYS_echo                42      /* shares slot with x86_64 socket; harmless on ARM64 since 42 is unallocated in generic */
#define SYS_time_millis         400

/* FIPC (Futura Inter-Process Communication) */
#define SYS_fipc_create         401
#define SYS_fipc_send           402
#define SYS_fipc_recv           403
#define SYS_fipc_close          404
#define SYS_fipc_poll           405
#define SYS_fipc_connect        406

/* Capability-based syscalls (Futura extensions) */
#define SYS_open_cap            500
#define SYS_read_cap            501
#define SYS_write_cap           502
#define SYS_close_cap           503
#define SYS_lseek_cap           504
#define SYS_fstat_cap           505
#define SYS_fsync_cap           506
#define SYS_mkdirat_cap         507
#define SYS_unlinkat_cap        508
#define SYS_rmdirat_cap         509
#define SYS_statat_cap          510

#define SYS_seteuid             SYS_setresuid  /* libfutura passes -1,uid,-1 */
#define SYS_setegid             SYS_setresgid  /* libfutura passes -1,gid,-1 */

#else /* x86_64 — historical Linux x86_64 numbering */

#define SYS_read                0
#define SYS_write               1
#define SYS_open                2
#define SYS_close               3
#define SYS_stat                4
#define SYS_fstat               5
#define SYS_lstat               6
#define SYS_poll                7
#define SYS_access              21
#define SYS_lseek               8
#define SYS_mmap                9
#define SYS_mprotect            10
#define SYS_munmap              11
#define SYS_brk                 12
#define SYS_ioctl               16
#define SYS_pread64             17
#define SYS_pwrite64            18
#define SYS_readv               19
#define SYS_writev              20
#define SYS_pipe                22
#define SYS_select              23
#define SYS_sched_yield         24
#define SYS_mremap              25
#define SYS_msync               26
#define SYS_mincore             27
#define SYS_dup                 32
#define SYS_dup2                33
#define SYS_pause               34
#define SYS_nanosleep           35
#define SYS_alarm               37
#define SYS_echo                42
#define SYS_socket              41
#define SYS_accept              43
#define SYS_shutdown            48
#define SYS_bind                49
#define SYS_listen              50
#define SYS_getsockname         51
#define SYS_getpeername         52
#define SYS_setsockopt          54
#define SYS_getsockopt          55
#define SYS_fork                57
#define SYS_execve              59
#define SYS_exit                60
#define SYS_wait4               61
#define SYS_waitpid             61
#define SYS_kill                62
#define SYS_uname               63
#define SYS_sigaction           13
#define SYS_sigprocmask         14
#define SYS_truncate            76
#define SYS_ftruncate           77
#define SYS_getcwd              79
#define SYS_chdir               80
#define SYS_chmod               90
#define SYS_fcntl               72
#define SYS_flock               73
#define SYS_fsync               74
#define SYS_fdatasync           75
#define SYS_fchmod              91
#define SYS_chown               92
#define SYS_fchown              93
#define SYS_link                86
#define SYS_unlink              87
#define SYS_symlink             88
#define SYS_readlink            89
#define SYS_connect             53
#define SYS_sendto              44
#define SYS_recvfrom            45
#define SYS_sendmsg             46
#define SYS_recvmsg             47
#define SYS_mkdir               83
#define SYS_rmdir               84
#define SYS_rename              82
#define SYS_getdents64          217
#define SYS_getpid              39
#define SYS_gettid              186
#define SYS_openat              257
#define SYS_epoll_create        228
#define SYS_epoll_create1       291
#define SYS_epoll_ctl           229
#define SYS_epoll_wait          230
#define SYS_madvise             231
#define SYS_getuid              102
#define SYS_getgid              104
#define SYS_setuid              105
#define SYS_setgid              106
#define SYS_geteuid             107
#define SYS_umask               95
#define SYS_gettimeofday        96
#define SYS_getrlimit           97
#define SYS_clock_gettime       98
#define SYS_getrusage           99
#define SYS_times               100
#define SYS_getegid             108
#define SYS_setrlimit           160
#define SYS_seteuid             109
#define SYS_setegid             110
#define SYS_getpgrp             111
#define SYS_setsid              112
#define SYS_getppid             113
#define SYS_getsid              124
#define SYS_setpgid             125
#define SYS_getpgid             126
#define SYS_getpriority         140
#define SYS_setpriority         141
#define SYS_time                201
#define SYS_preadv              295
#define SYS_pwritev             296
#define SYS_eventfd2            290
#define SYS_time_millis         400

#define SYS_fipc_create         401
#define SYS_fipc_send           402
#define SYS_fipc_recv           403
#define SYS_fipc_close          404
#define SYS_fipc_poll           405
#define SYS_fipc_connect        406

#define SYS_open_cap            500
#define SYS_read_cap            501
#define SYS_write_cap           502
#define SYS_close_cap           503
#define SYS_lseek_cap           504
#define SYS_fstat_cap           505
#define SYS_fsync_cap           506
#define SYS_mkdirat_cap         507
#define SYS_unlinkat_cap        508
#define SYS_rmdirat_cap         509
#define SYS_statat_cap          510

#endif

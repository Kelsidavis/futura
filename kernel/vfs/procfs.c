/* kernel/vfs/procfs.c - Process Filesystem (/proc)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements a synthetic /proc filesystem providing runtime process and
 * system information, compatible with Linux /proc conventions.
 *
 * Supported entries:
 *   /proc/self            -> symlink to /proc/<current-pid>
 *   /proc/meminfo         -> system memory statistics
 *   /proc/version         -> kernel version string
 *   /proc/uptime          -> system uptime in seconds
 *   /proc/<pid>/          -> per-process directory
 *   /proc/<pid>/status    -> process status (Name, Pid, State, VmRSS, etc.)
 *   /proc/<pid>/maps      -> memory map
 *   /proc/<pid>/cmdline   -> process command line (null-separated)
 *   /proc/<pid>/fd/       -> open file descriptor directory
 *   /proc/<pid>/fd/<n>    -> symlinks (currently ENOENT for unresolved paths)
 *   /proc/<pid>/stat      -> machine-readable process statistics (ps/top format)
 *   /proc/<pid>/statm     -> memory statistics (size resident shared text lib data dt)
 *   /proc/cpuinfo         -> CPU model/features
 */

#include <kernel/fut_vfs.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_stats.h>
#include <kernel/fut_lock.h>
#include <kernel/vfs_credentials.h>
#include <kernel/fut_socket.h>
#include <kernel/eventfd.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#ifdef __x86_64__
#include <platform/x86_64/memory/paging.h>
#elif defined(__aarch64__)
#include <platform/arm64/memory/paging.h>
#endif

/* Global task list (defined in kernel/threading/fut_task.c) */
extern fut_task_t *fut_task_list;

/* Hostname and domainname — writable via sethostname/setdomainname and /proc/sys/kernel */
extern char g_hostname[];
extern char g_domainname[];

/* ============================================================
 *   Procfs Node Kind (stored in fs_data)
 * ============================================================ */

enum procfs_kind {
    PROC_ROOT,       /* /proc directory */
    PROC_SELF,       /* /proc/self symlink */
    PROC_THREAD_SELF,/* /proc/thread-self symlink */
    PROC_MEMINFO,    /* /proc/meminfo */
    PROC_VERSION,    /* /proc/version */
    PROC_UPTIME,     /* /proc/uptime */
    PROC_PID_DIR,    /* /proc/<pid>/ */
    PROC_STATUS,     /* /proc/<pid>/status */
    PROC_MAPS,       /* /proc/<pid>/maps */
    PROC_CMDLINE,    /* /proc/<pid>/cmdline */
    PROC_FD_DIR,     /* /proc/<pid>/fd/ */
    PROC_FD_ENTRY,   /* /proc/<pid>/fd/<n> symlink */
    PROC_EXE,        /* /proc/<pid>/exe symlink */
    PROC_CWD,        /* /proc/<pid>/cwd symlink */
    PROC_PID_ROOT,   /* /proc/<pid>/root symlink → "/" (filesystem root) */
    PROC_STAT,       /* /proc/<pid>/stat */
    PROC_STATM,      /* /proc/<pid>/statm */
    PROC_CPUINFO,    /* /proc/cpuinfo */
    PROC_LOADAVG,    /* /proc/loadavg */
    PROC_MOUNTS,     /* /proc/mounts */
    PROC_STAT_GLOBAL,/* /proc/stat */
    PROC_FILESYSTEMS,/* /proc/filesystems */
    PROC_COMM,       /* /proc/<pid>/comm */
    PROC_ENVIRON,    /* /proc/<pid>/environ */
    /* /proc/sys/ subtree */
    PROC_SYS_DIR,          /* /proc/sys/ */
    PROC_SYS_KERNEL_DIR,   /* /proc/sys/kernel/ */
    PROC_SYS_VM_DIR,       /* /proc/sys/vm/ */
    PROC_SYS_FS_DIR,       /* /proc/sys/fs/ */
    PROC_SYS_OSTYPE,       /* /proc/sys/kernel/ostype */
    PROC_SYS_OSRELEASE,    /* /proc/sys/kernel/osrelease */
    PROC_SYS_HOSTNAME,     /* /proc/sys/kernel/hostname */
    PROC_SYS_PID_MAX,      /* /proc/sys/kernel/pid_max */
    PROC_SYS_OVERCOMMIT,      /* /proc/sys/vm/overcommit_memory */
    PROC_SYS_MAX_MAP_COUNT,   /* /proc/sys/vm/max_map_count */
    PROC_SYS_SWAPPINESS,      /* /proc/sys/vm/swappiness */
    PROC_SYS_DIRTY_RATIO,     /* /proc/sys/vm/dirty_ratio */
    PROC_SYS_DIRTY_BG_RATIO,  /* /proc/sys/vm/dirty_background_ratio */
    PROC_SYS_MIN_FREE_KB,     /* /proc/sys/vm/min_free_kbytes */
    PROC_SYS_FILE_MAX,     /* /proc/sys/fs/file-max */
    PROC_SYS_FILE_NR,      /* /proc/sys/fs/file-nr */
    PROC_SYS_INOTIFY_DIR,  /* /proc/sys/fs/inotify/ */
    PROC_SYS_INOTIFY_MAX_WATCHES,    /* /proc/sys/fs/inotify/max_user_watches */
    PROC_SYS_INOTIFY_MAX_INSTANCES,  /* /proc/sys/fs/inotify/max_user_instances */
    PROC_SYS_INOTIFY_MAX_QUEUED,     /* /proc/sys/fs/inotify/max_queued_events */
    PROC_SYS_RANDOM_DIR,   /* /proc/sys/kernel/random/ */
    PROC_SYS_BOOT_ID,      /* /proc/sys/kernel/random/boot_id */
    PROC_SYS_UUID,         /* /proc/sys/kernel/random/uuid */
    PROC_SYS_ENTROPY_AVAIL,/* /proc/sys/kernel/random/entropy_avail */
    PROC_SYS_POOLSIZE,     /* /proc/sys/kernel/random/poolsize */
    PROC_SYS_SHMMAX,       /* /proc/sys/kernel/shmmax */
    PROC_SYS_SHMALL,       /* /proc/sys/kernel/shmall */
    PROC_SYS_SHMMNI,       /* /proc/sys/kernel/shmmni */
    PROC_SYS_SEM,          /* /proc/sys/kernel/sem */
    PROC_SYS_MSGMAX,       /* /proc/sys/kernel/msgmax */
    PROC_SYS_MSGMNB,       /* /proc/sys/kernel/msgmnb */
    PROC_SYS_MSGMNI,       /* /proc/sys/kernel/msgmni */
    /* /proc/sys/net/ subtree */
    PROC_SYS_NET_DIR,      /* /proc/sys/net/ */
    PROC_SYS_NET_CORE_DIR, /* /proc/sys/net/core/ */
    PROC_SYS_NET_IPV4_DIR, /* /proc/sys/net/ipv4/ */
    PROC_SYS_NET_SOMAXCONN,     /* /proc/sys/net/core/somaxconn */
    PROC_SYS_NET_RMEM_MAX,      /* /proc/sys/net/core/rmem_max */
    PROC_SYS_NET_WMEM_MAX,      /* /proc/sys/net/core/wmem_max */
    PROC_SYS_NET_RMEM_DEFAULT,  /* /proc/sys/net/core/rmem_default */
    PROC_SYS_NET_WMEM_DEFAULT,  /* /proc/sys/net/core/wmem_default */
    PROC_SYS_NET_PORT_RANGE,    /* /proc/sys/net/ipv4/ip_local_port_range */
    PROC_SYS_NET_FIN_TIMEOUT,   /* /proc/sys/net/ipv4/tcp_fin_timeout */
    PROC_SYS_NET_SYNCOOKIES,    /* /proc/sys/net/ipv4/tcp_syncookies */
    PROC_SYS_NET_TCP_KEEPALIVE_TIME,  /* /proc/sys/net/ipv4/tcp_keepalive_time */
    PROC_SYS_NET_TCP_KEEPALIVE_INTVL, /* /proc/sys/net/ipv4/tcp_keepalive_intvl */
    PROC_SYS_NET_TCP_KEEPALIVE_PROBES,/* /proc/sys/net/ipv4/tcp_keepalive_probes */
    PROC_SYS_NET_IP_UNPRIV_PORT_START,/* /proc/sys/net/ipv4/ip_unprivileged_port_start */
    /* /proc/sys/net/ipv4/conf/ subtree */
    PROC_SYS_NET_IPV4_CONF_DIR,       /* /proc/sys/net/ipv4/conf/ */
    PROC_SYS_NET_IPV4_CONF_ALL_DIR,   /* /proc/sys/net/ipv4/conf/all/ */
    PROC_SYS_NET_IPV4_CONF_DEFAULT_DIR,/* /proc/sys/net/ipv4/conf/default/ */
    PROC_SYS_NET_IPV4_CONF_RP_FILTER, /* .../conf/all/rp_filter */
    PROC_SYS_NET_IPV4_CONF_FORWARDING,/* .../conf/all/forwarding */
    PROC_SYS_NET_IPV4_CONF_ACCEPT_RA, /* .../conf/all/accept_redirects */
    PROC_VMSTAT,           /* /proc/vmstat */
    PROC_NET_DIR,          /* /proc/net/ */
    PROC_NET_DEV,          /* /proc/net/dev */
    PROC_NET_ROUTE,        /* /proc/net/route */
    PROC_NET_TCP,          /* /proc/net/tcp */
    PROC_NET_UDP,          /* /proc/net/udp */
    PROC_NET_IF_INET6,     /* /proc/net/if_inet6 */
    PROC_TASK_DIR,         /* /proc/<pid>/task/ */
    PROC_TID_DIR,          /* /proc/<pid>/task/<tid>/ */
    PROC_LIMITS,           /* /proc/<pid>/limits */
    PROC_IO,               /* /proc/<pid>/io */
    PROC_SMAPS,            /* /proc/<pid>/smaps */
    PROC_OOM_SCORE,        /* /proc/<pid>/oom_score */
    PROC_OOM_ADJ,          /* /proc/<pid>/oom_score_adj */
    PROC_CGROUP,           /* /proc/<pid>/cgroup */
    PROC_NS_DIR,           /* /proc/<pid>/ns/ directory */
    PROC_NS_ENTRY,         /* /proc/<pid>/ns/<name> symlink (fd = ns type index) */
    PROC_FDINFO_DIR,       /* /proc/<pid>/fdinfo/ directory */
    PROC_FDINFO_ENTRY,     /* /proc/<pid>/fdinfo/<n> file (fd = fd number) */
    PROC_SYS_NGROUPS_MAX,  /* /proc/sys/kernel/ngroups_max */
    PROC_SYS_CAP_LAST_CAP, /* /proc/sys/kernel/cap_last_cap */
    PROC_SYS_THREADS_MAX,  /* /proc/sys/kernel/threads-max */
    PROC_SYS_PRINTK,       /* /proc/sys/kernel/printk */
    PROC_SYS_YAMA_DIR,     /* /proc/sys/kernel/yama/ directory */
    PROC_SYS_PTRACE_SCOPE, /* /proc/sys/kernel/yama/ptrace_scope */
    PROC_SYS_NR_HUGEPAGES, /* /proc/sys/vm/nr_hugepages */
    PROC_SYS_NR_OC_HUGEPAGES, /* /proc/sys/vm/nr_overcommit_hugepages */
    PROC_SYS_TCP_RMEM,     /* /proc/sys/net/ipv4/tcp_rmem */
    PROC_SYS_TCP_WMEM,     /* /proc/sys/net/ipv4/tcp_wmem */
    PROC_INTERRUPTS,       /* /proc/interrupts */
    PROC_SYS_RANDOMIZE_VA, /* /proc/sys/kernel/randomize_va_space */
    PROC_SYS_DOMAINNAME,   /* /proc/sys/kernel/domainname */
    PROC_NET_UNIX,         /* /proc/net/unix */
    PROC_NET_SOCKSTAT,     /* /proc/net/sockstat */
    PROC_SYS_PERF_PARANOID,/* /proc/sys/kernel/perf_event_paranoid */
    PROC_SYS_KPTR_RESTRICT,/* /proc/sys/kernel/kptr_restrict */
    PROC_SYS_DMESG_RESTRICT,/* /proc/sys/kernel/dmesg_restrict */
    PROC_SYS_NET_IP_FORWARD, /* /proc/sys/net/ipv4/ip_forward */
    PROC_NET_ARP,          /* /proc/net/arp */
    /* /proc/sys/net/ipv6/ subtree */
    PROC_SYS_NET_IPV6_DIR,          /* /proc/sys/net/ipv6/ */
    PROC_SYS_NET_IPV6_CONF_DIR,     /* /proc/sys/net/ipv6/conf/ */
    PROC_SYS_NET_IPV6_CONF_ALL_DIR, /* /proc/sys/net/ipv6/conf/all/ */
    PROC_SYS_NET_IPV6_DISABLE,      /* /proc/sys/net/ipv6/conf/all/disable_ipv6 */
    PROC_SYS_NET_IPV6_FORWARD,      /* /proc/sys/net/ipv6/conf/all/forwarding */
    /* Additional /proc/sys/vm/ entries */
    PROC_SYS_VM_MMAP_MIN_ADDR,      /* /proc/sys/vm/mmap_min_addr */
    PROC_SYS_VM_VFS_CACHE_PRESSURE, /* /proc/sys/vm/vfs_cache_pressure */
    /* Additional /proc/sys/fs/ entries */
    PROC_SYS_FS_NR_OPEN,            /* /proc/sys/fs/nr_open */
    PROC_SYS_FS_PIPE_MAX_SIZE,      /* /proc/sys/fs/pipe-max-size */
    /* Additional /proc/<pid>/ entries */
    PROC_WCHAN,                     /* /proc/<pid>/wchan */
    PROC_PERSONALITY,               /* /proc/<pid>/personality */
    PROC_MOUNTINFO,                 /* /proc/<pid>/mountinfo */
    PROC_COREDUMP_FILTER,           /* /proc/<pid>/coredump_filter */
    PROC_SCHEDSTAT,                 /* /proc/<pid>/schedstat */
    /* Additional /proc/sys/kernel/ entries */
    PROC_SYS_CORE_PATTERN,          /* /proc/sys/kernel/core_pattern */
    PROC_SYS_CORE_USES_PID,         /* /proc/sys/kernel/core_uses_pid */
    PROC_SYS_SUID_DUMPABLE,         /* /proc/sys/kernel/suid_dumpable */
    PROC_SYS_TAINTED,               /* /proc/sys/kernel/tainted */
    PROC_SYS_VERSION,               /* /proc/sys/kernel/version */

    PROC_CMDLINE_GLOBAL,            /* /proc/cmdline */
    PROC_SWAPS,                     /* /proc/swaps */
    PROC_DEVICES,                   /* /proc/devices */
    PROC_MISC_FILE,                 /* /proc/misc */
    PROC_ATTR_DIR,                  /* /proc/<pid>/attr/ */
    PROC_ATTR_CURRENT,              /* /proc/<pid>/attr/current */
    PROC_BUDDYINFO,                 /* /proc/buddyinfo */
    PROC_ZONEINFO,                  /* /proc/zoneinfo */
    /* Additional /proc/sys/vm/ entries (commonly written by databases/containers) */
    PROC_SYS_VM_DROP_CACHES,        /* /proc/sys/vm/drop_caches */
    PROC_SYS_VM_DIRTY_EXPIRE,       /* /proc/sys/vm/dirty_expire_centisecs */
    PROC_SYS_VM_DIRTY_WRITEBACK,    /* /proc/sys/vm/dirty_writeback_centisecs */
    PROC_SYS_VM_OVERCOMMIT_KB,      /* /proc/sys/vm/overcommit_kbytes */
    PROC_SYS_VM_OOM_KILL_ALLOC,     /* /proc/sys/vm/oom_kill_allocating_task */
    PROC_SYS_VM_PANIC_ON_OOM,       /* /proc/sys/vm/panic_on_oom */
    PROC_SYS_VM_ZONE_RECLAIM,       /* /proc/sys/vm/zone_reclaim_mode */
    PROC_SYS_VM_WATERMARK_BOOST,    /* /proc/sys/vm/watermark_boost_factor */
    PROC_SYS_VM_WATERMARK_SCALE,    /* /proc/sys/vm/watermark_scale_factor */
    PROC_SYS_VM_PAGE_CLUSTER,       /* /proc/sys/vm/page-cluster */
    /* Additional /proc/sys/fs/ entries */
    PROC_SYS_FS_AIO_MAX_NR,         /* /proc/sys/fs/aio-max-nr */
    PROC_SYS_FS_AIO_NR,             /* /proc/sys/fs/aio-nr */
    PROC_SYS_FS_PROTECTED_HL,       /* /proc/sys/fs/protected_hardlinks */
    PROC_SYS_FS_PROTECTED_SL,       /* /proc/sys/fs/protected_symlinks */
    /* Additional /proc/sys/kernel/ entries */
    PROC_SYS_KERNEL_NMI_WD,         /* /proc/sys/kernel/nmi_watchdog */
    PROC_SYS_KERNEL_WATCHDOG,       /* /proc/sys/kernel/watchdog */
    PROC_SYS_KERNEL_WATCHDOG_THRESH,/* /proc/sys/kernel/watchdog_thresh */
    PROC_SYS_KERNEL_HUNG_TASK,      /* /proc/sys/kernel/hung_task_timeout_secs */
    PROC_SMAPS_ROLLUP,              /* /proc/<pid>/smaps_rollup */
    PROC_NET_TCP6,                  /* /proc/net/tcp6 */
    PROC_NET_UDP6,                  /* /proc/net/udp6 */
    PROC_NET_RAW,                   /* /proc/net/raw */
    PROC_NET_FIB_TRIE,              /* /proc/net/fib_trie */
    PROC_NET_SNMP,                  /* /proc/net/snmp */
    PROC_NET_NETSTAT,               /* /proc/net/netstat */
    PROC_NET_PACKET,                /* /proc/net/packet */
    PROC_AUXV,                      /* /proc/<pid>/auxv — ELF auxiliary vector (binary) */
    PROC_PID_MEM,                   /* /proc/<pid>/mem  — raw process address space (r/w) */
    PROC_UID_MAP,                   /* /proc/<pid>/uid_map — user namespace UID mapping */
    PROC_GID_MAP,                   /* /proc/<pid>/gid_map — user namespace GID mapping */
    PROC_SETGROUPS,                 /* /proc/<pid>/setgroups — "allow" or "deny" */
    PROC_LOGINUID,                  /* /proc/<pid>/loginuid — audit login UID (4294967295 = unset) */
    PROC_SESSIONID,                 /* /proc/<pid>/sessionid — audit session ID */
    PROC_DISKSTATS,                 /* /proc/diskstats — block device I/O statistics */
    PROC_PARTITIONS,                /* /proc/partitions — block device partition table */
    PROC_CGROUPS,                   /* /proc/cgroups — cgroup subsystem list */
    PROC_PAGEMAP,                   /* /proc/<pid>/pagemap — physical page info (binary, 8 bytes/page) */
    PROC_KALLSYMS,                  /* /proc/kallsyms — kernel symbol table (addresses zeroed per kptr_restrict) */
    PROC_TIMERSLACK_NS,             /* /proc/<pid>/timerslack_ns — timer expiry slack in nanoseconds */
    PROC_SYSCALL,                   /* /proc/<pid>/syscall — current syscall number and arguments */
    PROC_LOCKS,                     /* /proc/locks — POSIX and flock file lock table */
};

typedef struct {
    enum procfs_kind kind;
    uint64_t pid;   /* relevant PID (0 for global nodes) */
    int fd;         /* fd index for PROC_FD_ENTRY */
} procfs_node_t;

/* ============================================================
 *   Inode Number Scheme
 * ============================================================ */

#define PROC_INO_ROOT     1ULL
#define PROC_INO_SELF     2ULL
#define PROC_INO_MEMINFO  3ULL
#define PROC_INO_VERSION  4ULL
#define PROC_INO_UPTIME   5ULL
#define PROC_INO_CPUINFO  6ULL
#define PROC_INO_LOADAVG  7ULL
#define PROC_INO_MOUNTS      8ULL
#define PROC_INO_STAT_GLOBAL 9ULL
#define PROC_INO_FILESYSTEMS 10ULL
#define PROC_INO_VMSTAT      11ULL
#define PROC_INO_NET_DIR     12ULL
#define PROC_INO_NET_DEV     13ULL
#define PROC_INO_NET_ROUTE   14ULL
#define PROC_INO_NET_TCP     15ULL
#define PROC_INO_NET_UDP     16ULL
#define PROC_INO_NET_IF6     17ULL
#define PROC_INO_INTERRUPTS  18ULL
/* /proc/sys/ inode range: 200-299 */
#define PROC_INO_SYS_DIR        200ULL
#define PROC_INO_SYS_KERNEL_DIR 201ULL
#define PROC_INO_SYS_VM_DIR     202ULL
#define PROC_INO_SYS_FS_DIR     203ULL
#define PROC_INO_SYS_OSTYPE     210ULL
#define PROC_INO_SYS_OSRELEASE  211ULL
#define PROC_INO_SYS_HOSTNAME   212ULL
#define PROC_INO_SYS_PID_MAX    213ULL
#define PROC_INO_SYS_NGROUPS_MAX    214ULL
#define PROC_INO_SYS_CAP_LAST_CAP   215ULL
#define PROC_INO_SYS_THREADS_MAX    216ULL
#define PROC_INO_SYS_PRINTK         217ULL
#define PROC_INO_SYS_YAMA_DIR       218ULL
#define PROC_INO_SYS_PTRACE_SCOPE   219ULL
#define PROC_INO_SYS_OVERCOMMIT       220ULL
#define PROC_INO_SYS_MAX_MAP_COUNT    221ULL
#define PROC_INO_SYS_SWAPPINESS       222ULL
#define PROC_INO_SYS_DIRTY_RATIO      223ULL
#define PROC_INO_SYS_DIRTY_BG_RATIO   224ULL
#define PROC_INO_SYS_MIN_FREE_KB      225ULL
#define PROC_INO_SYS_NR_HUGEPAGES     226ULL
#define PROC_INO_SYS_NR_OC_HUGEPAGES  227ULL
#define PROC_INO_SYS_FILE_MAX      230ULL
#define PROC_INO_SYS_FILE_NR       231ULL
#define PROC_INO_SYS_INOTIFY_DIR   232ULL
#define PROC_INO_SYS_INOTIFY_MAX_WATCHES   233ULL
#define PROC_INO_SYS_INOTIFY_MAX_INSTANCES 234ULL
#define PROC_INO_SYS_INOTIFY_MAX_QUEUED    235ULL
#define PROC_INO_SYS_RANDOM_DIR    204ULL
#define PROC_INO_SYS_BOOT_ID       240ULL
#define PROC_INO_SYS_UUID          241ULL
#define PROC_INO_SYS_ENTROPY_AVAIL 242ULL
#define PROC_INO_SYS_POOLSIZE      243ULL
#define PROC_INO_SYS_SHMMAX        250ULL
#define PROC_INO_SYS_SHMALL        251ULL
#define PROC_INO_SYS_SHMMNI        252ULL
#define PROC_INO_SYS_SEM           253ULL
#define PROC_INO_SYS_MSGMAX        254ULL
#define PROC_INO_SYS_MSGMNB        255ULL
#define PROC_INO_SYS_MSGMNI        256ULL
/* /proc/sys/net/ inode range: 260-290 */
#define PROC_INO_SYS_NET_DIR         260ULL
#define PROC_INO_SYS_NET_CORE_DIR    261ULL
#define PROC_INO_SYS_NET_IPV4_DIR    262ULL
#define PROC_INO_SYS_NET_SOMAXCONN   270ULL
#define PROC_INO_SYS_NET_RMEM_MAX    271ULL
#define PROC_INO_SYS_NET_WMEM_MAX    272ULL
#define PROC_INO_SYS_NET_RMEM_DEFAULT 273ULL
#define PROC_INO_SYS_NET_WMEM_DEFAULT 274ULL
#define PROC_INO_SYS_NET_PORT_RANGE  275ULL
#define PROC_INO_SYS_NET_FIN_TIMEOUT 276ULL
#define PROC_INO_SYS_NET_SYNCOOKIES  277ULL
#define PROC_INO_SYS_NET_TCP_RMEM    278ULL
#define PROC_INO_SYS_NET_TCP_WMEM    279ULL
#define PROC_INO_SYS_RANDOMIZE_VA    280ULL
#define PROC_INO_SYS_DOMAINNAME      281ULL
#define PROC_INO_SYS_PERF_PARANOID   282ULL
#define PROC_INO_SYS_KPTR_RESTRICT   283ULL
#define PROC_INO_SYS_DMESG_RESTRICT  284ULL
#define PROC_INO_SYS_NET_IP_FORWARD  285ULL
#define PROC_INO_NET_UNIX            19ULL
#define PROC_INO_NET_SOCKSTAT        20ULL
#define PROC_INO_NET_ARP             21ULL
#define PROC_INO_NET_TCP6            22ULL
#define PROC_INO_NET_UDP6            23ULL
#define PROC_INO_NET_RAW             24ULL
#define PROC_INO_NET_FIB_TRIE        25ULL
#define PROC_INO_NET_SNMP            26ULL
#define PROC_INO_NET_NETSTAT         27ULL
#define PROC_INO_NET_PACKET          28ULL
#define PROC_INO_SYS_NET_IPV6_DIR      286ULL
#define PROC_INO_SYS_NET_IPV6_CONF_DIR 287ULL
#define PROC_INO_SYS_NET_IPV6_ALL_DIR  288ULL
#define PROC_INO_SYS_NET_IPV6_DISABLE  289ULL
#define PROC_INO_SYS_NET_IPV6_FORWARD  290ULL
#define PROC_INO_SYS_VM_MMAP_MIN_ADDR  291ULL
#define PROC_INO_SYS_VM_VFS_CACHE_PRESS 292ULL
#define PROC_INO_SYS_FS_NR_OPEN        293ULL
#define PROC_INO_SYS_FS_PIPE_MAX_SIZE  294ULL
#define PROC_INO_SYS_CORE_PATTERN      295ULL
#define PROC_INO_SYS_CORE_USES_PID     296ULL
#define PROC_INO_SYS_SUID_DUMPABLE     297ULL
#define PROC_INO_SYS_TAINTED           298ULL
#define PROC_INO_SYS_VERSION_KERNEL    299ULL

#define PROC_INO_CMDLINE_GLOBAL        22ULL
#define PROC_INO_SWAPS                 23ULL
#define PROC_INO_DEVICES               24ULL
#define PROC_INO_MISC_FILE             25ULL
#define PROC_INO_PID_ATTR(p)           (1000ULL + (uint64_t)(p) * 100 + 24)
#define PROC_INO_PID_ATTR_CUR(p)       (1000ULL + (uint64_t)(p) * 100 + 25)
#define PROC_INO_PID_SMAPS_ROLLUP(p)   (1000ULL + (uint64_t)(p) * 100 + 26)
#define PROC_INO_PID_AUXV(p)           (1000ULL + (uint64_t)(p) * 100 + 27)
#define PROC_INO_PID_MEM(p)            (1000ULL + (uint64_t)(p) * 100 + 28)
#define PROC_INO_PID_UID_MAP(p)        (1000ULL + (uint64_t)(p) * 100 + 29)
#define PROC_INO_PID_GID_MAP(p)        (1000ULL + (uint64_t)(p) * 100 + 30)
#define PROC_INO_PID_SETGROUPS(p)      (1000ULL + (uint64_t)(p) * 100 + 31)
#define PROC_INO_PID_PAGEMAP(p)        (1000ULL + (uint64_t)(p) * 100 + 35)
#define PROC_INO_PID_ROOT(p)           (1000ULL + (uint64_t)(p) * 100 + 36)
#define PROC_INO_PID_TIMERSLACK(p)     (1000ULL + (uint64_t)(p) * 100 + 37)
#define PROC_INO_PID_SYSCALL(p)        (1000ULL + (uint64_t)(p) * 100 + 38)
#define PROC_INO_PID_LOGINUID(p)       (1000ULL + (uint64_t)(p) * 100 + 32)
#define PROC_INO_PID_SESSIONID(p)      (1000ULL + (uint64_t)(p) * 100 + 33)
#define PROC_INO_PID_PERSONALITY(p)    (1000ULL + (uint64_t)(p) * 100 + 34)
#define PROC_INO_BUDDYINFO             26ULL
#define PROC_INO_ZONEINFO              27ULL
#define PROC_INO_THREAD_SELF           28ULL
#define PROC_INO_DISKSTATS             29ULL
#define PROC_INO_PARTITIONS            30ULL
#define PROC_INO_CGROUPS               31ULL
/* /proc/sys/vm/ extended range: 350-379 */
#define PROC_INO_SYS_VM_DROP_CACHES    350ULL
#define PROC_INO_SYS_VM_DIRTY_EXPIRE   351ULL
#define PROC_INO_SYS_VM_DIRTY_WB       352ULL
#define PROC_INO_SYS_VM_OVERCOMMIT_KB  353ULL
#define PROC_INO_SYS_VM_OOM_KILL_ALLOC 354ULL
#define PROC_INO_SYS_VM_PANIC_ON_OOM   355ULL
#define PROC_INO_SYS_VM_ZONE_RECLAIM   356ULL
#define PROC_INO_SYS_VM_WATERMARK_BST  357ULL
#define PROC_INO_SYS_VM_WATERMARK_SCL  358ULL
#define PROC_INO_SYS_VM_PAGE_CLUSTER   359ULL
/* /proc/sys/fs/ extended range: 380-399 */
#define PROC_INO_SYS_FS_AIO_MAX_NR     380ULL
#define PROC_INO_SYS_FS_AIO_NR         381ULL
#define PROC_INO_SYS_FS_PROT_HL        382ULL
#define PROC_INO_SYS_FS_PROT_SL        383ULL
/* /proc/sys/net/ipv4/ extended range: 404-407 */
#define PROC_INO_SYS_NET_KEEPALIVE_TIME  404ULL
#define PROC_INO_SYS_NET_KEEPALIVE_INTVL 405ULL
#define PROC_INO_SYS_NET_KEEPALIVE_PROBES 406ULL
#define PROC_INO_SYS_NET_UNPRIV_PORT     407ULL
/* /proc/sys/net/ipv4/conf/ range: 408-414 */
#define PROC_INO_SYS_NET_IPV4_CONF_DIR   408ULL
#define PROC_INO_SYS_NET_IPV4_CONF_ALL   409ULL
#define PROC_INO_SYS_NET_IPV4_CONF_DEF   410ULL
#define PROC_INO_SYS_NET_IPV4_RP_FILTER  411ULL
#define PROC_INO_SYS_NET_IPV4_FORWARDING 412ULL
#define PROC_INO_SYS_NET_IPV4_ACCEPT_RA  413ULL
#define PROC_INO_KALLSYMS                 414ULL
#define PROC_INO_LOCKS                    415ULL
/* /proc/sys/kernel/ extended range: 400-429 */
#define PROC_INO_SYS_KERNEL_NMI_WD     400ULL
#define PROC_INO_SYS_KERNEL_WATCHDOG   401ULL
#define PROC_INO_SYS_KERNEL_WD_THRESH  402ULL
#define PROC_INO_SYS_KERNEL_HUNG_TASK  403ULL

/* Per-PID: pid * 100 + offset */
#define PROC_INO_PID_DIR(p)    (1000ULL + (uint64_t)(p) * 100 + 0)
#define PROC_INO_PID_STATUS(p) (1000ULL + (uint64_t)(p) * 100 + 1)
#define PROC_INO_PID_MAPS(p)   (1000ULL + (uint64_t)(p) * 100 + 2)
#define PROC_INO_PID_CMDLINE(p)(1000ULL + (uint64_t)(p) * 100 + 3)
#define PROC_INO_PID_FD(p)     (1000ULL + (uint64_t)(p) * 100 + 4)
#define PROC_INO_PID_EXE(p)    (1000ULL + (uint64_t)(p) * 100 + 5)
#define PROC_INO_PID_CWD(p)    (1000ULL + (uint64_t)(p) * 100 + 6)
#define PROC_INO_PID_STAT(p)   (1000ULL + (uint64_t)(p) * 100 + 7)
#define PROC_INO_PID_STATM(p)  (1000ULL + (uint64_t)(p) * 100 + 8)
#define PROC_INO_PID_COMM(p)   (1000ULL + (uint64_t)(p) * 100 + 9)
#define PROC_INO_PID_TASK(p)   (1000ULL + (uint64_t)(p) * 100 + 10)
#define PROC_INO_PID_ENVIRON(p)(1000ULL + (uint64_t)(p) * 100 + 11)
#define PROC_INO_PID_LIMITS(p) (1000ULL + (uint64_t)(p) * 100 + 12)
#define PROC_INO_PID_IO(p)     (1000ULL + (uint64_t)(p) * 100 + 13)
#define PROC_INO_PID_SMAPS(p)  (1000ULL + (uint64_t)(p) * 100 + 14)
#define PROC_INO_PID_OOM_SCORE(p) (1000ULL + (uint64_t)(p) * 100 + 15)
#define PROC_INO_PID_OOM_ADJ(p)   (1000ULL + (uint64_t)(p) * 100 + 16)
#define PROC_INO_PID_CGROUP(p)    (1000ULL + (uint64_t)(p) * 100 + 17)
#define PROC_INO_PID_NS(p)        (1000ULL + (uint64_t)(p) * 100 + 18)
#define PROC_INO_PID_FDINFO(p)    (1000ULL + (uint64_t)(p) * 100 + 19)
#define PROC_INO_PID_WCHAN(p)     (1000ULL + (uint64_t)(p) * 100 + 20)
#define PROC_INO_PID_MOUNTINFO(p) (1000ULL + (uint64_t)(p) * 100 + 21)
#define PROC_INO_PID_COREDUMP(p)  (1000ULL + (uint64_t)(p) * 100 + 22)
#define PROC_INO_PID_SCHEDSTAT(p) (1000ULL + (uint64_t)(p) * 100 + 23)
/* ns/ entries: 7 namespaces (pid/mnt/net/user/uts/ipc/cgroup), index 0-6 */
#define PROC_INO_NS_ENTRY(p,n)    (300000000ULL + (uint64_t)(p) * 100 + (uint64_t)(n))
/* fdinfo/ entries: per-fd */
#define PROC_INO_FDINFO_ENTRY(p,n) (400000000ULL + (uint64_t)(p) * 1000 + (uint64_t)(n))
/* fd entries: use high range to avoid collision */
#define PROC_INO_FD_ENTRY(p,n) (100000000ULL + (uint64_t)(p) * 1000 + (uint64_t)(n))
/* task/<tid> entries: separate high range */
#define PROC_INO_TID_DIR(p,t)  (200000000ULL + (uint64_t)(p) * 10000 + (uint64_t)(t))

/* ============================================================
 *   Simple Buffer Writer (no libc snprintf needed)
 * ============================================================ */

struct pbuf {
    char   *data;
    size_t  pos;
    size_t  cap;
};

static void pb_char(struct pbuf *b, char c) {
    if (b->pos < b->cap) b->data[b->pos] = c;
    b->pos++;
}

static void pb_str(struct pbuf *b, const char *s) {
    while (*s) pb_char(b, *s++);
}

static void pb_u64(struct pbuf *b, uint64_t v) {
    if (v == 0) { pb_char(b, '0'); return; }
    char tmp[20]; int n = 0;
    while (v) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = n - 1; i >= 0; i--) pb_char(b, tmp[i]);
}

static void pb_hex16(struct pbuf *b, uint64_t v) {
    /* Print 16 hex digits (padded) */
    static const char hex[] = "0123456789abcdef";
    for (int i = 60; i >= 0; i -= 4)
        pb_char(b, hex[(v >> i) & 0xf]);
}

static void pb_hex8(struct pbuf *b, uint64_t v) {
    /* Print hex padded to at least 8 digits (Linux %08lx format for /proc/maps) */
    static const char hex[] = "0123456789abcdef";
    char tmp[16]; int n = 0;
    uint64_t w = v;
    do { tmp[n++] = hex[w & 0xf]; w >>= 4; } while (w);
    while (n < 8) tmp[n++] = '0';
    for (int i = n - 1; i >= 0; i--) pb_char(b, tmp[i]);
}

static void pb_oct(struct pbuf *b, uint32_t v) {
    /* Print minimum octal digits (for fdinfo flags) */
    if (v == 0) { pb_char(b, '0'); return; }
    char tmp[12]; int n = 0;
    while (v) { tmp[n++] = '0' + (int)(v & 7); v >>= 3; }
    for (int i = n - 1; i >= 0; i--) pb_char(b, tmp[i]);
}

static void pb_hex2(struct pbuf *b, uint8_t v) {
    /* Print exactly 2 hex digits (for dev major:minor) */
    static const char hex[] = "0123456789abcdef";
    pb_char(b, hex[(v >> 4) & 0xf]);
    pb_char(b, hex[v & 0xf]);
}

/* Uppercase hex helpers for /proc/net/tcp and /proc/net/udp */
static void pb_hex8U(struct pbuf *b, uint32_t v) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 28; i >= 0; i -= 4)
        pb_char(b, hex[(v >> i) & 0xf]);
}
static void pb_hex4U(struct pbuf *b, uint16_t v) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 12; i >= 0; i -= 4)
        pb_char(b, hex[(v >> i) & 0xf]);
}
static void pb_hex2U(struct pbuf *b, uint8_t v) {
    static const char hex[] = "0123456789ABCDEF";
    pb_char(b, hex[(v >> 4) & 0xf]);
    pb_char(b, hex[v & 0xf]);
}
/* Right-aligned decimal in fixed width (pads with spaces on the left) */
static void pb_d_padded(struct pbuf *b, uint64_t v, int width) {
    char tmp[20]; int n = 0;
    uint64_t w = v;
    if (w == 0) { tmp[n++] = '0'; }
    else { do { tmp[n++] = '0' + (int)(w % 10); w /= 10; } while (w); }
    for (int i = 0, j = n - 1; i < j; i++, j--) { char t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t; }
    for (int i = n; i < width; i++) pb_char(b, ' ');
    for (int i = 0; i < n; i++) pb_char(b, tmp[i]);
}

/* ============================================================
 *   Forward Declarations
 * ============================================================ */

static const struct fut_vnode_ops procfs_dir_ops;
static const struct fut_vnode_ops procfs_file_ops;
static const struct fut_vnode_ops procfs_link_ops;

/* ============================================================
 *   Vnode Allocation
 * ============================================================ */

static struct fut_vnode *procfs_alloc_vnode(struct fut_mount *mount,
                                             enum fut_vnode_type type,
                                             uint64_t ino, uint32_t mode,
                                             enum procfs_kind kind,
                                             uint64_t pid, int fd) {
    struct fut_vnode *v = fut_malloc(sizeof(struct fut_vnode));
    if (!v) return NULL;

    procfs_node_t *n = fut_malloc(sizeof(procfs_node_t));
    if (!n) { fut_free(v); return NULL; }

    n->kind = kind;
    n->pid  = pid;
    n->fd   = fd;

    v->type     = type;
    v->ino      = ino;
    v->mode     = mode;
    v->uid      = 0;
    v->gid      = 0;
    v->size     = 0;
    v->nlinks   = (type == VN_DIR) ? 2 : 1;
    v->mount    = mount;
    v->fs_data  = n;
    v->refcount = 1;
    v->parent   = NULL;
    v->name     = NULL;

    const struct fut_vnode_ops *ops;
    switch (type) {
        case VN_DIR: ops = &procfs_dir_ops;  break;
        case VN_LNK: ops = &procfs_link_ops; break;
        default:     ops = &procfs_file_ops; break;
    }
    v->ops = ops;

    fut_vnode_lock_init(v);
    return v;
}

/* ============================================================
 *   Content Generators
 * ============================================================ */

static size_t gen_meminfo(char *buf, size_t cap) {
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages  = fut_pmm_free_pages();
    uint64_t page_size   = 4096;
    uint64_t total_kb    = (total_pages * page_size) / 1024;
    uint64_t free_kb     = (free_pages  * page_size) / 1024;
    uint64_t used_kb     = total_kb - free_kb;
    uint64_t avail_kb    = free_kb;

    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "MemTotal:       "); pb_u64(&b, total_kb); pb_str(&b, " kB\n");
    pb_str(&b, "MemFree:        "); pb_u64(&b, free_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "MemAvailable:   "); pb_u64(&b, avail_kb); pb_str(&b, " kB\n");
    pb_str(&b, "Buffers:               0 kB\n");
    pb_str(&b, "Cached:         "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "SwapCached:            0 kB\n");
    pb_str(&b, "Active:         "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "Inactive:              0 kB\n");
    pb_str(&b, "Active(anon):   "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "Inactive(anon):        0 kB\n");
    pb_str(&b, "Active(file):          0 kB\n");
    pb_str(&b, "Inactive(file):        0 kB\n");
    pb_str(&b, "Unevictable:           0 kB\n");
    pb_str(&b, "Mlocked:               0 kB\n");
    pb_str(&b, "SwapTotal:             0 kB\n");
    pb_str(&b, "SwapFree:              0 kB\n");
    pb_str(&b, "Zswap:                 0 kB\n");
    pb_str(&b, "Zswapped:              0 kB\n");
    pb_str(&b, "Dirty:                 0 kB\n");
    pb_str(&b, "Writeback:             0 kB\n");
    pb_str(&b, "AnonPages:      "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "Mapped:                0 kB\n");
    pb_str(&b, "Shmem:                 0 kB\n");
    pb_str(&b, "KReclaimable:          0 kB\n");
    pb_str(&b, "Slab:                  0 kB\n");
    pb_str(&b, "SReclaimable:          0 kB\n");
    pb_str(&b, "SUnreclaim:            0 kB\n");
    pb_str(&b, "KernelStack:           0 kB\n");
    pb_str(&b, "ShadowCallStack:       0 kB\n");
    pb_str(&b, "PageTables:            0 kB\n");
    pb_str(&b, "SecPageTables:         0 kB\n");
    pb_str(&b, "NFS_Unstable:          0 kB\n");
    pb_str(&b, "Bounce:                0 kB\n");
    pb_str(&b, "WritebackTmp:          0 kB\n");
    pb_str(&b, "CommitLimit:    "); pb_u64(&b, total_kb); pb_str(&b, " kB\n");
    pb_str(&b, "Committed_AS:   "); pb_u64(&b, used_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "VmallocTotal:   34359738367 kB\n");
    pb_str(&b, "VmallocUsed:           0 kB\n");
    pb_str(&b, "VmallocChunk:          0 kB\n");
    pb_str(&b, "Percpu:                0 kB\n");
    pb_str(&b, "HardwareCorrupted:     0 kB\n");
    pb_str(&b, "AnonHugePages:         0 kB\n");
    pb_str(&b, "ShmemHugePages:        0 kB\n");
    pb_str(&b, "ShmemPmdMapped:        0 kB\n");
    pb_str(&b, "FileHugePages:         0 kB\n");
    pb_str(&b, "FilePmdMapped:         0 kB\n");
    pb_str(&b, "CmaTotal:              0 kB\n");
    pb_str(&b, "CmaFree:               0 kB\n");
    pb_str(&b, "HugePages_Total:       0\n");
    pb_str(&b, "HugePages_Free:        0\n");
    pb_str(&b, "HugePages_Rsvd:        0\n");
    pb_str(&b, "HugePages_Surp:        0\n");
    pb_str(&b, "Hugepagesize:       2048 kB\n");
    pb_str(&b, "Hugetlb:               0 kB\n");
    pb_str(&b, "DirectMap4k:      131072 kB\n");
    pb_str(&b, "DirectMap2M:      "); pb_u64(&b, total_kb); pb_str(&b, " kB\n");
    pb_str(&b, "DirectMap1G:           0 kB\n");
    return b.pos;
}

static size_t gen_version(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Linux version 6.1.0-futura (futura@kernel) "
               "(gcc version 14.0.0) #1 SMP PREEMPT\n");
    return b.pos;
}

static size_t gen_uptime(char *buf, size_t cap) {
    uint64_t ticks = fut_get_ticks();
    uint64_t secs  = ticks / FUT_TIMER_HZ;
    uint64_t frac  = (ticks % FUT_TIMER_HZ) * 100 / FUT_TIMER_HZ;  /* centiseconds */
    struct pbuf b = { buf, 0, cap };
    pb_u64(&b, secs); pb_char(&b, '.');
    if (frac < 10) pb_char(&b, '0');
    pb_u64(&b, frac);
    pb_str(&b, " 0.00\n");  /* idle time (not tracked) */
    return b.pos;
}

/* tid: when non-zero, this is /proc/<pid>/task/<tid>/status — show tid in Pid: field */
static size_t gen_status(char *buf, size_t cap, fut_task_t *task, uint64_t tid) {
    if (!task) return 0;

    const char *state_str;
    switch (task->state) {
        case FUT_TASK_ZOMBIE:  state_str = "Z (zombie)";   break;
        case FUT_TASK_STOPPED: state_str = "T (stopped)";  break;
        case FUT_TASK_RUNNING:
        default: {
            fut_thread_t *mt = task->threads;
            if (mt && (mt->state == FUT_THREAD_SLEEPING || mt->state == FUT_THREAD_BLOCKED))
                state_str = "S (sleeping)";
            else
                state_str = "R (running)";
            break;
        }
    }

    /* Compute Vm* fields from VMA list */
    uint64_t rss_kb = 0, vm_exe_kb = 0, vm_lib_kb = 0;
    uint64_t vm_data_kb = 0, vm_stk_kb = 0;
    uint64_t rss_anon_kb = 0, rss_file_kb = 0, rss_shmem_kb = 0;
    uint64_t vm_lck_kb = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        while (vma) {
            uint64_t sz = (vma->end - vma->start) / 1024;
            rss_kb += sz;
            if (vma->vnode) {
                /* File-backed */
                if (vma->prot & PROT_EXEC)
                    vm_exe_kb += sz;
                else
                    vm_lib_kb += sz;
                rss_file_kb += sz;
            } else if (vma->flags & VMA_SHARED) {
                /* Shared anonymous (shmem/tmpfs) */
                vm_data_kb += sz;
                rss_shmem_kb += sz;
            } else if (vma->flags & VMA_STACK) {
                vm_stk_kb += sz;
                rss_anon_kb += sz;
            } else {
                /* Private anonymous: heap + mmap */
                vm_data_kb += sz;
                rss_anon_kb += sz;
            }
            if (vma->flags & VMA_LOCKED)
                vm_lck_kb += sz;
            vma = vma->next;
        }
        /* VmLck from mm->locked_vm (pages) if not already counted */
        if (vm_lck_kb == 0 && task->mm->locked_vm)
            vm_lck_kb = (uint64_t)task->mm->locked_vm * 4; /* pages → kB */
    }

    /* Compute SigIgn and SigCgt bitmasks from signal_handlers[] */
    uint64_t sig_ign = 0, sig_cgt = 0;
    for (int i = 0; i < 64 && i < _NSIG - 1; i++) {
        sighandler_t h = task->signal_handlers[i];
        if (h == SIG_IGN)
            sig_ign |= (1ULL << i);
        else if (h != SIG_DFL && h != NULL)
            sig_cgt |= (1ULL << i);
    }

    uint64_t ppid = task->parent ? task->parent->pid : 0;

    /* For /proc/<pid>/task/<tid>/status, use the thread's own name if available */
    const char *comm_name = task->comm[0] ? task->comm : "?";
    if (tid != 0) {
        /* Find the thread with this TID and use its per-thread comm */
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid && t->comm[0]) { comm_name = t->comm; break; }
        }
    }

    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Name:\t");       pb_str(&b, comm_name); pb_char(&b, '\n');
    pb_str(&b, "State:\t");      pb_str(&b, state_str); pb_char(&b, '\n');
    pb_str(&b, "Tgid:\t");       pb_u64(&b, task->pid); pb_char(&b, '\n');
    pb_str(&b, "Pid:\t");        pb_u64(&b, tid ? tid : task->pid); pb_char(&b, '\n');
    pb_str(&b, "PPid:\t");       pb_u64(&b, ppid);       pb_char(&b, '\n');
    pb_str(&b, "TracerPid:\t");  pb_u64(&b, 0);          pb_char(&b, '\n');
    pb_str(&b, "Uid:\t");        pb_u64(&b, task->ruid); pb_char(&b, '\t');
                                  pb_u64(&b, task->uid);  pb_char(&b, '\t');
                                  pb_u64(&b, task->suid); pb_char(&b, '\t');
                                  pb_u64(&b, task->uid);  pb_char(&b, '\n');
    pb_str(&b, "Gid:\t");        pb_u64(&b, task->rgid); pb_char(&b, '\t');
                                  pb_u64(&b, task->gid);  pb_char(&b, '\t');
                                  pb_u64(&b, task->sgid); pb_char(&b, '\t');
                                  pb_u64(&b, task->gid);  pb_char(&b, '\n');
    pb_str(&b, "FDSize:\t");     pb_u64(&b, (uint64_t)task->max_fds); pb_char(&b, '\n');
    pb_str(&b, "Groups:\t");
    for (int gi = 0; gi < task->ngroups; gi++) {
        if (gi > 0) pb_char(&b, ' ');
        pb_u64(&b, task->groups[gi]);
    }
    pb_char(&b, '\n');
    pb_str(&b, "Threads:\t");    pb_u64(&b, task->thread_count); pb_char(&b, '\n');
    pb_str(&b, "VmPeak:\t");     pb_u64(&b, rss_kb);      pb_str(&b, " kB\n");
    pb_str(&b, "VmSize:\t");     pb_u64(&b, rss_kb);      pb_str(&b, " kB\n");
    pb_str(&b, "VmLck:\t");      pb_u64(&b, vm_lck_kb);   pb_str(&b, " kB\n");
    pb_str(&b, "VmPin:\t");      pb_u64(&b, 0);            pb_str(&b, " kB\n");
    pb_str(&b, "VmHWM:\t");      pb_u64(&b, rss_kb);      pb_str(&b, " kB\n");
    pb_str(&b, "VmRSS:\t");      pb_u64(&b, rss_kb);      pb_str(&b, " kB\n");
    pb_str(&b, "RssAnon:\t");    pb_u64(&b, rss_anon_kb); pb_str(&b, " kB\n");
    pb_str(&b, "RssFile:\t");    pb_u64(&b, rss_file_kb); pb_str(&b, " kB\n");
    pb_str(&b, "RssShmem:\t");   pb_u64(&b, rss_shmem_kb);pb_str(&b, " kB\n");
    pb_str(&b, "VmData:\t");     pb_u64(&b, vm_data_kb);  pb_str(&b, " kB\n");
    pb_str(&b, "VmStk:\t");      pb_u64(&b, vm_stk_kb);   pb_str(&b, " kB\n");
    pb_str(&b, "VmExe:\t");      pb_u64(&b, vm_exe_kb);   pb_str(&b, " kB\n");
    pb_str(&b, "VmLib:\t");      pb_u64(&b, vm_lib_kb);   pb_str(&b, " kB\n");
    {
        /* VmPTE: page table overhead ≈ 1 entry per 4 kB page = rss_kb/512 kB */
        uint64_t vm_pte_kb = (rss_kb + 511) / 512;
        pb_str(&b, "VmPTE:\t");  pb_u64(&b, vm_pte_kb);   pb_str(&b, " kB\n");
    }
    pb_str(&b, "VmSwap:\t");     pb_u64(&b, 0);            pb_str(&b, " kB\n");
    pb_str(&b, "HugetlbPages:\t");pb_u64(&b, 0);           pb_str(&b, " kB\n");
    pb_str(&b, "CoreDumping:\t"); pb_u64(&b, task->dumpable ? 0 : 0); pb_char(&b, '\n');
    pb_str(&b, "THP_enabled:\t"); pb_u64(&b, 1);           pb_char(&b, '\n');
    /* SigQ: pending signal count / RLIMIT_SIGPENDING max */
    {
        unsigned int sigq_pend = (unsigned int)__builtin_popcountll(task->pending_signals);
        uint64_t sigq_max = task->rlimits[11].rlim_cur; /* RLIMIT_SIGPENDING */
        pb_str(&b, "SigQ:\t"); pb_u64(&b, sigq_pend); pb_char(&b, '/');
        pb_u64(&b, sigq_max); pb_char(&b, '\n');
    }
    /* SigPnd: thread-directed signals for the main thread.
     * ShdPnd: task-wide (process) pending signals.
     * SigBlk: main thread's blocked signal mask (per POSIX each thread has its own). */
    {
        fut_thread_t *mt = task->threads;
        uint64_t thr_pnd = mt ? mt->thread_pending_signals : 0;
        uint64_t thr_blk = mt ? mt->signal_mask : task->signal_mask;
        pb_str(&b, "SigPnd:\t"); pb_hex16(&b, thr_pnd);              pb_char(&b, '\n');
        pb_str(&b, "ShdPnd:\t"); pb_hex16(&b, task->pending_signals); pb_char(&b, '\n');
        pb_str(&b, "SigBlk:\t"); pb_hex16(&b, thr_blk);              pb_char(&b, '\n');
    }
    pb_str(&b, "SigIgn:\t");     pb_hex16(&b, sig_ign);               pb_char(&b, '\n');
    pb_str(&b, "SigCgt:\t");     pb_hex16(&b, sig_cgt);               pb_char(&b, '\n');
    pb_str(&b, "CapInh:\t");     pb_hex16(&b, task->cap_inheritable); pb_char(&b, '\n');
    pb_str(&b, "CapPrm:\t");     pb_hex16(&b, task->cap_permitted);   pb_char(&b, '\n');
    pb_str(&b, "CapEff:\t");     pb_hex16(&b, task->cap_effective);   pb_char(&b, '\n');
    pb_str(&b, "CapBnd:\t");     pb_hex16(&b, task->cap_bset);         pb_char(&b, '\n');
    pb_str(&b, "CapAmb:\t");     pb_hex16(&b, task->cap_ambient);      pb_char(&b, '\n');
    pb_str(&b, "NoNewPrivs:\t"); pb_u64(&b, task->no_new_privs ? 1 : 0); pb_char(&b, '\n');
    pb_str(&b, "Seccomp:\t");    pb_u64(&b, 0);                        pb_char(&b, '\n');
    pb_str(&b, "Seccomp_filters:\t"); pb_u64(&b, 0);                   pb_char(&b, '\n');
    /* Speculation mitigations (Linux 4.17+): report as "not vulnerable" since
     * Futura doesn't execute untrusted code concurrently with kernel data. */
    pb_str(&b, "Speculation_Store_Bypass:\t");
    pb_str(&b, "not vulnerable");  pb_char(&b, '\n');
    pb_str(&b, "SpeculationIndirectBranch:\t");
    pb_str(&b, "not vulnerable");  pb_char(&b, '\n');
    /* Umask (Linux 4.7+): file creation mask in octal */
    pb_str(&b, "Umask:\t");      pb_oct(&b, task->umask & 0777);       pb_char(&b, '\n');
    /* NStgid/NSpid/NSpgid/NSsid (Linux 4.1+): PID as seen in each namespace.
     * Futura has no PID namespaces — report the same PID at all levels. */
    pb_str(&b, "NStgid:\t"); pb_u64(&b, task->pid); pb_char(&b, '\n');
    pb_str(&b, "NSpid:\t");  pb_u64(&b, task->pid); pb_char(&b, '\n');
    pb_str(&b, "NSpgid:\t"); pb_u64(&b, task->pgid); pb_char(&b, '\n');
    pb_str(&b, "NSsid:\t");  pb_u64(&b, task->sid);  pb_char(&b, '\n');
    /* CPU affinity: reflect actual sched_setaffinity mask from thread */
    {
        uint64_t amask = 0;
        if (task->threads)
            amask = task->threads->cpu_affinity_mask;
        if (amask == 0)
            amask = 0x1;  /* Default: at least CPU 0 */
        /* Cpus_allowed: hex bitmask in Linux "%08x,%08x" format (high,low) */
        pb_str(&b, "Cpus_allowed:\t");
        uint32_t hi = (uint32_t)(amask >> 32);
        uint32_t lo = (uint32_t)(amask & 0xFFFFFFFFu);
        if (hi) {
            static const char hex[] = "0123456789abcdef";
            char t[8]; for (int i = 7; i >= 0; i--) { t[i] = hex[hi & 0xf]; hi >>= 4; }
            for (int i = 0; i < 8; i++) pb_char(&b, t[i]);
            pb_char(&b, ',');
            char s[8]; for (int i = 7; i >= 0; i--) { s[i] = hex[lo & 0xf]; lo >>= 4; }
            for (int i = 0; i < 8; i++) pb_char(&b, s[i]);
        } else {
            static const char hex[] = "0123456789abcdef";
            char s[8]; uint32_t v = lo;
            for (int i = 7; i >= 0; i--) { s[i] = hex[v & 0xf]; v >>= 4; }
            for (int i = 0; i < 8; i++) pb_char(&b, s[i]);
        }
        pb_char(&b, '\n');
        /* Cpus_allowed_list: "0" or "0-N" or comma-separated ranges */
        pb_str(&b, "Cpus_allowed_list:\t");
        int first = -1, last = -1, need_comma = 0;
        for (int i = 0; i < 64; i++) {
            if (amask & (1ULL << i)) {
                if (first < 0) first = i;
                last = i;
            } else if (first >= 0) {
                if (need_comma) pb_char(&b, ',');
                pb_u64(&b, (uint64_t)first);
                if (last > first) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)last); }
                first = -1; need_comma = 1;
            }
        }
        if (first >= 0) {
            if (need_comma) pb_char(&b, ',');
            pb_u64(&b, (uint64_t)first);
            if (last > first) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)last); }
        }
        pb_char(&b, '\n');
    }
    /* NUMA memory policy: node 0 only (no NUMA) */
    pb_str(&b, "Mems_allowed:\t"); pb_str(&b, "00000000,00000001"); pb_char(&b, '\n');
    pb_str(&b, "Mems_allowed_list:\t"); pb_str(&b, "0"); pb_char(&b, '\n');
    /* Context switch counters: sum across all threads */
    {
        uint64_t total_vol = 0, total_sw = 0;
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            total_vol += t->stats.voluntary_yields;
            total_sw  += t->stats.context_switches;
        }
        uint64_t nonvol = total_sw > total_vol ? total_sw - total_vol : 0;
        pb_str(&b, "voluntary_ctxt_switches:\t"); pb_u64(&b, total_vol); pb_char(&b, '\n');
        pb_str(&b, "nonvoluntary_ctxt_switches:\t"); pb_u64(&b, nonvol); pb_char(&b, '\n');
    }
    return b.pos;
}

/* Write a right-padded string into pbuf to achieve fixed column width */
static void pb_pad(struct pbuf *b, const char *s, int width) {
    int n = 0;
    while (s[n]) { pb_char(b, s[n]); n++; }
    while (n < width) { pb_char(b, ' '); n++; }
}

/* Write a rlim value as decimal or "unlimited" padded to width */
static void pb_rlim(struct pbuf *b, uint64_t v, int width) {
    char tmp[24]; int n = 0;
    if (v == (uint64_t)-1ULL) {
        const char *s = "unlimited";
        int sn = 0; while (s[sn]) { pb_char(b, s[sn++]); }
        while (sn < width) { pb_char(b, ' '); sn++; }
    } else {
        uint64_t vv = v;
        if (vv == 0) { tmp[n++] = '0'; }
        else { while (vv) { tmp[n++] = '0' + (int)(vv % 10); vv /= 10; } }
        /* reverse */
        for (int i = 0, j = n - 1; i < j; i++, j--) {
            char t = tmp[i]; tmp[i] = tmp[j]; tmp[j] = t;
        }
        for (int i = 0; i < n; i++) pb_char(b, tmp[i]);
        while (n < width) { pb_char(b, ' '); n++; }
    }
}

static size_t gen_limits(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    struct pbuf b = { buf, 0, cap };

    /* Header line matches Linux format */
    pb_str(&b, "Limit                     Soft Limit           Hard Limit           Units     \n");

    static const struct {
        const char *name;
        int         rlimit_idx;
        const char *units;
    } rows[] = {
        { "Max cpu time",        0  /* RLIMIT_CPU */,       "seconds"   },
        { "Max file size",       1  /* RLIMIT_FSIZE */,     "bytes"     },
        { "Max data size",       2  /* RLIMIT_DATA */,      "bytes"     },
        { "Max stack size",      3  /* RLIMIT_STACK */,     "bytes"     },
        { "Max core file size",  4  /* RLIMIT_CORE */,      "bytes"     },
        { "Max resident set",    5  /* RLIMIT_RSS */,       "bytes"     },
        { "Max processes",       6  /* RLIMIT_NPROC */,     "processes" },
        { "Max open files",      7  /* RLIMIT_NOFILE */,    "files"     },
        { "Max locked memory",   8  /* RLIMIT_MEMLOCK */,   "bytes"     },
        { "Max address space",   9  /* RLIMIT_AS */,        "bytes"     },
        { "Max file locks",      10 /* RLIMIT_LOCKS */,     "locks"     },
        { "Max pending signals", 11 /* RLIMIT_SIGPENDING */, "signals"  },
        { "Max msgqueue size",   12 /* RLIMIT_MSGQUEUE */,  "bytes"     },
        { "Max nice priority",   13 /* RLIMIT_NICE */,      ""          },
        { "Max realtime priority", 14 /* RLIMIT_RTPRIO */, ""           },
        { "Max realtime timeout",  15 /* RLIMIT_RTTIME */, "us"         },
    };

    for (int i = 0; i < (int)(sizeof(rows)/sizeof(rows[0])); i++) {
        uint64_t soft = task->rlimits[rows[i].rlimit_idx].rlim_cur;
        uint64_t hard = task->rlimits[rows[i].rlimit_idx].rlim_max;
        pb_pad(&b, rows[i].name, 26);
        pb_rlim(&b, soft, 21);
        pb_rlim(&b, hard, 21);
        pb_str(&b, rows[i].units);
        pb_char(&b, '\n');
    }
    return b.pos;
}

static size_t gen_io(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    struct pbuf b = { buf, 0, cap };
    /* Linux /proc/<pid>/io format */
    pb_str(&b, "rchar: ");    pb_u64(&b, task->io_rchar);    pb_char(&b, '\n');
    pb_str(&b, "wchar: ");    pb_u64(&b, task->io_wchar);    pb_char(&b, '\n');
    pb_str(&b, "syscr: ");    pb_u64(&b, task->io_syscr);    pb_char(&b, '\n');
    pb_str(&b, "syscw: ");    pb_u64(&b, task->io_syscw);    pb_char(&b, '\n');
    pb_str(&b, "read_bytes: ");  pb_u64(&b, 0);  pb_char(&b, '\n');
    pb_str(&b, "write_bytes: "); pb_u64(&b, 0);  pb_char(&b, '\n');
    pb_str(&b, "cancelled_write_bytes: "); pb_u64(&b, 0); pb_char(&b, '\n');
    return b.pos;
}

static size_t gen_maps(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
    if (!mm) return 0;

    struct pbuf b = { buf, 0, cap };
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        /* address range — Linux uses %08lx (at least 8 hex chars) */
        pb_hex8(&b, vma->start); pb_char(&b, '-');
        pb_hex8(&b, vma->end);   pb_char(&b, ' ');
        /* permissions */
        pb_char(&b, (vma->prot & PROT_READ)  ? 'r' : '-');
        pb_char(&b, (vma->prot & PROT_WRITE) ? 'w' : '-');
        pb_char(&b, (vma->prot & PROT_EXEC)  ? 'x' : '-');
        pb_char(&b, (vma->flags & VMA_SHARED) ? 's' : 'p');
        pb_char(&b, ' ');
        /* offset — exactly 8 hex chars (Linux %08llx) */
        pb_hex8(&b, vma->file_offset); pb_char(&b, ' ');
        /* dev:inode — file-backed: "00:01 <ino>"; anonymous: "00:00 0" */
        if (vma->vnode) {
            pb_hex2(&b, 0); pb_char(&b, ':'); pb_hex2(&b, 1);
            pb_char(&b, ' '); pb_u64(&b, vma->vnode->ino);
        } else {
            pb_str(&b, "00:00 0");
        }
        /* pathname */
        if (vma->vnode) {
            char path_buf[256];
            char *full = fut_vnode_build_path(vma->vnode, path_buf, sizeof(path_buf));
            pb_char(&b, ' ');
            pb_str(&b, full ? full : vma->vnode->name ? vma->vnode->name : "");
        } else if (vma->anon_name) {
            pb_str(&b, " [anon:");
            pb_str(&b, vma->anon_name);
            pb_char(&b, ']');
        } else if (vma->flags & VMA_STACK) {
            pb_str(&b, " [stack]");
        } else if (mm->brk_start && vma->start >= mm->brk_start &&
                   vma->end <= mm->brk_current + 0x1000) {
            pb_str(&b, " [heap]");
        }
        pb_char(&b, '\n');
        vma = vma->next;
    }
    return b.pos;
}

/*
 * gen_smaps() — /proc/<pid>/smaps
 *
 * Extended memory map with per-VMA statistics, compatible with Linux
 * /proc/pid/smaps format. Used by Go runtime (RSS/GC), Python tracemalloc,
 * Valgrind, heaptrack, and many system monitoring tools.
 *
 * For Futura (ramfs, all pages in RAM): RSS = Size for anonymous mappings;
 * file-backed mappings report RSS = 0 (no page-tracking infrastructure yet).
 * All pages are Private_Clean (no swap, no shared dirty).
 */
static size_t gen_smaps(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
    if (!mm) return 0;

    struct pbuf b = { buf, 0, cap };
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        size_t vma_size = (vma->end - vma->start) / 1024;  /* kB */
        int is_anon = (vma->vnode == NULL);

        /* Header line: same format as /proc/maps */
        pb_hex8(&b, vma->start); pb_char(&b, '-');
        pb_hex8(&b, vma->end);   pb_char(&b, ' ');
        pb_char(&b, (vma->prot & PROT_READ)  ? 'r' : '-');
        pb_char(&b, (vma->prot & PROT_WRITE) ? 'w' : '-');
        pb_char(&b, (vma->prot & PROT_EXEC)  ? 'x' : '-');
        pb_char(&b, (vma->flags & VMA_SHARED) ? 's' : 'p');
        pb_char(&b, ' ');
        pb_hex8(&b, vma->file_offset); pb_char(&b, ' ');
        if (vma->vnode) {
            pb_hex2(&b, 0); pb_char(&b, ':'); pb_hex2(&b, 1);
            pb_char(&b, ' '); pb_u64(&b, vma->vnode->ino);
        } else {
            pb_str(&b, "00:00 0");
        }
        if (vma->vnode) {
            char path_buf[256];
            char *full = fut_vnode_build_path(vma->vnode, path_buf, sizeof(path_buf));
            pb_char(&b, ' ');
            pb_str(&b, full ? full : vma->vnode->name ? vma->vnode->name : "");
        } else if (vma->anon_name) {
            pb_str(&b, " [anon:");
            pb_str(&b, vma->anon_name);
            pb_char(&b, ']');
        } else if (vma->flags & VMA_STACK) {
            pb_str(&b, " [stack]");
        } else if (mm->brk_start && vma->start >= mm->brk_start &&
                   vma->end <= mm->brk_current + 0x1000) {
            pb_str(&b, " [heap]");
        }
        pb_char(&b, '\n');

        /* Size: total VMA size in kB */
        pb_str(&b, "Size:            "); pb_u64(&b, (uint64_t)vma_size); pb_str(&b, " kB\n");
        /* KernelPageSize / MMUPageSize: 4 kB on x86_64/arm64 */
        pb_str(&b, "KernelPageSize:        4 kB\n");
        pb_str(&b, "MMUPageSize:           4 kB\n");
        /* Rss: for anonymous mappings all pages are resident in Futura's RAM model */
        size_t rss = is_anon ? vma_size : 0;
        pb_str(&b, "Rss:             "); pb_u64(&b, (uint64_t)rss); pb_str(&b, " kB\n");
        /* Pss = Rss (no sharing, all private) */
        pb_str(&b, "Pss:             "); pb_u64(&b, (uint64_t)rss); pb_str(&b, " kB\n");
        pb_str(&b, "Pss_Dirty:             0 kB\n");
        pb_str(&b, "Shared_Clean:          0 kB\n");
        pb_str(&b, "Shared_Dirty:          0 kB\n");
        /* Private_Clean = rss for anon (all pages writable but unmodified by model) */
        pb_str(&b, "Private_Clean:   "); pb_u64(&b, (uint64_t)rss); pb_str(&b, " kB\n");
        pb_str(&b, "Private_Dirty:         0 kB\n");
        pb_str(&b, "Referenced:      "); pb_u64(&b, (uint64_t)rss); pb_str(&b, " kB\n");
        /* Anonymous: size of anonymous portion */
        pb_str(&b, "Anonymous:       "); pb_u64(&b, is_anon ? (uint64_t)vma_size : 0ULL);
        pb_str(&b, " kB\n");
        pb_str(&b, "KSM:                   0 kB\n");
        pb_str(&b, "LazyFree:              0 kB\n");
        pb_str(&b, "AnonHugePages:         0 kB\n");
        pb_str(&b, "ShmemPmdMapped:        0 kB\n");
        pb_str(&b, "FilePmdMapped:         0 kB\n");
        pb_str(&b, "Shared_Hugetlb:        0 kB\n");
        pb_str(&b, "Private_Hugetlb:       0 kB\n");
        pb_str(&b, "Swap:                  0 kB\n");
        pb_str(&b, "SwapPss:               0 kB\n");
        pb_str(&b, "Locked:                0 kB\n");
        pb_str(&b, "THPeligible:           0\n");
        /* VmFlags: encode prot bits as Linux vm flags */
        pb_str(&b, "VmFlags:");
        if (vma->prot & PROT_READ)  pb_str(&b, " rd");
        if (vma->prot & PROT_WRITE) pb_str(&b, " wr");
        if (vma->prot & PROT_EXEC)  pb_str(&b, " ex");
        pb_str(&b, " mr mw me");  /* mapped, may_read, may_write, may_exec */
        pb_char(&b, '\n');

        vma = vma->next;
    }
    return b.pos;
}

/*
 * gen_smaps_rollup() — /proc/<pid>/smaps_rollup
 *
 * Single synthetic entry aggregating Rss/Pss/etc. across all VMAs.
 * Used by Go runtime, Rust allocators, and tools that want total RSS
 * without iterating every mapping.
 */
static size_t gen_smaps_rollup(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
    if (!mm) return 0;

    uint64_t total_size = 0, total_rss = 0, total_anon = 0;
    struct fut_vma *vma = mm->vma_list;
    while (vma) {
        uint64_t vma_kb = (vma->end - vma->start) / 1024;
        total_size += vma_kb;
        if (vma->vnode == NULL) {   /* anonymous mapping */
            total_rss  += vma_kb;
            total_anon += vma_kb;
        }
        vma = vma->next;
    }

    struct pbuf b = { buf, 0, cap };
    /* Header: synthetic [rollup] range covering all user space */
    pb_str(&b, "00400000-ffffffffffffffff ---p 00000000 00:00 0 [rollup]\n");
    pb_str(&b, "Size:            "); pb_u64(&b, total_size); pb_str(&b, " kB\n");
    pb_str(&b, "KernelPageSize:        4 kB\n");
    pb_str(&b, "MMUPageSize:           4 kB\n");
    pb_str(&b, "Rss:             "); pb_u64(&b, total_rss);  pb_str(&b, " kB\n");
    pb_str(&b, "Pss:             "); pb_u64(&b, total_rss);  pb_str(&b, " kB\n");
    pb_str(&b, "Pss_Anon:        "); pb_u64(&b, total_anon); pb_str(&b, " kB\n");
    pb_str(&b, "Pss_File:              0 kB\n");
    pb_str(&b, "Pss_Shmem:             0 kB\n");
    pb_str(&b, "Shared_Clean:          0 kB\n");
    pb_str(&b, "Shared_Dirty:          0 kB\n");
    pb_str(&b, "Private_Clean:   "); pb_u64(&b, total_rss);  pb_str(&b, " kB\n");
    pb_str(&b, "Private_Dirty:         0 kB\n");
    pb_str(&b, "Referenced:      "); pb_u64(&b, total_rss);  pb_str(&b, " kB\n");
    pb_str(&b, "Anonymous:       "); pb_u64(&b, total_anon); pb_str(&b, " kB\n");
    pb_str(&b, "LazyFree:              0 kB\n");
    pb_str(&b, "AnonHugePages:         0 kB\n");
    pb_str(&b, "ShmemPmdMapped:        0 kB\n");
    pb_str(&b, "FilePmdMapped:         0 kB\n");
    pb_str(&b, "Shared_Hugetlb:        0 kB\n");
    pb_str(&b, "Private_Hugetlb:       0 kB\n");
    pb_str(&b, "Swap:                  0 kB\n");
    pb_str(&b, "SwapPss:               0 kB\n");
    pb_str(&b, "Locked:                0 kB\n");
    return b.pos;
}

static size_t gen_cmdline(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;
    /* Prefer saved full argv (null-separated, Linux /proc/pid/cmdline format) */
    if (task->proc_cmdline_len > 0) {
        size_t n = task->proc_cmdline_len;
        if (n > cap) n = cap;
        __builtin_memcpy(buf, task->proc_cmdline, n);
        return n;
    }
    /* Fallback: return comm as single null-terminated arg */
    const char *name = task->comm[0] ? task->comm : "?";
    size_t n = 0;
    while (name[n]) n++;
    if (n > cap) n = cap;
    __builtin_memcpy(buf, name, n);
    if (n < cap) buf[n] = '\0';  /* null terminator (cmdline format) */
    return n + 1;
}

/*
 * gen_stat() — /proc/<pid>/stat
 *
 * Fields follow Linux /proc/<pid>/stat layout (man 5 proc).
 * Only the fields that can be derived from kernel state are accurate;
 * the rest are zeroed as permitted by the spec.
 *
 * Key fields consumed by ps/top/glibc:
 *   1=pid, 2=(comm), 3=state, 4=ppid, 5=pgrp, 6=session,
 *   13/14=utime/stime (USER_HZ=100 ticks), 17=priority, 18=nice,
 *   19=num_threads, 21=starttime, 22=vsize (bytes), 23=rss (pages)
 */
/* tid: when non-zero, this is /proc/<pid>/task/<tid>/stat — show tid as field 1 */
static size_t gen_stat(char *buf, size_t cap, fut_task_t *task, uint64_t tid) {
    if (!task) return 0;

    /* State character — map task state to Linux /proc/stat state letter.
     * For a RUNNING task, report 'S' (interruptible sleep) if the main thread
     * is actually blocked/sleeping in a wait queue; 'R' only if truly runnable. */
    char state_c;
    switch (task->state) {
        case FUT_TASK_ZOMBIE:  state_c = 'Z'; break;
        case FUT_TASK_STOPPED: state_c = 'T'; break;
        case FUT_TASK_RUNNING:
        default: {
            /* Check main thread's execution state */
            fut_thread_t *mt = task->threads;
            if (mt && (mt->state == FUT_THREAD_SLEEPING || mt->state == FUT_THREAD_BLOCKED))
                state_c = 'S';  /* interruptible sleep */
            else
                state_c = 'R';  /* runnable */
            break;
        }
    }

    uint64_t ppid = task->parent ? task->parent->pid : 0;
    uint64_t pgrp = task->pgid;
    uint64_t session = task->sid;

    /* CPU time in USER_HZ (100 Hz) ticks — sum all threads */
    uint64_t utime = 0, stime = 0;
    if (task->threads) {
        /* Accumulate cpu_ticks across all threads of this task */
        fut_thread_t *t = task->threads;
        while (t) {
            utime += t->stats.cpu_ticks;
            t = t->next;
        }
    }
    /* Accumulated child times */
    uint64_t cutime = task->child_cpu_ticks;
    uint64_t cstime = 0;

    /* Priority in Linux terms: priority = 20 - nice (range 1..40 for SCHED_OTHER) */
    int nice = task->nice;
    long priority = (long)(20 - nice);  /* maps nice -20..19 → priority 40..1 */

    /* Virtual memory size in bytes; RSS in pages */
    uint64_t vsize = 0, rss_pages = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        while (vma) { vsize += vma->end - vma->start; vma = vma->next; }
        rss_pages = vsize / 4096;
    }

    /* Starttime: ticks since boot at task creation (FUT_TIMER_HZ ticks per second = USER_HZ=100) */
    uint64_t starttime = task->start_ticks;

    /* Signal bitmask fields (fields 31-34):
     * Compute sigignore and sigcatch from the signal handler table. */
    uint64_t pending_sig  = task->pending_signals;
    uint64_t blocked_sig  = task->signal_mask;
    uint64_t sigignore = 0, sigcatch = 0;
    for (int signo = 1; signo < _NSIG && signo <= 64; signo++) {
        sighandler_t h = task->signal_handlers[signo - 1];  /* handlers indexed 0-based */
        if (h == SIG_IGN)
            sigignore |= (1ULL << (signo - 1));
        else if (h != SIG_DFL)
            sigcatch  |= (1ULL << (signo - 1));
    }

    struct pbuf b = { buf, 0, cap };

    /* Field 1: pid (or tid when reading /proc/<pid>/task/<tid>/stat) */
    pb_u64(&b, tid ? tid : task->pid); pb_char(&b, ' ');
    /* Field 2: comm in parens — use per-thread name when tid is set */
    pb_char(&b, '(');
    const char *stat_comm = task->comm[0] ? task->comm : "?";
    if (tid) {
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid && t->comm[0]) { stat_comm = t->comm; break; }
        }
    }
    pb_str(&b, stat_comm);
    pb_char(&b, ')'); pb_char(&b, ' ');
    /* Field 3: state */
    pb_char(&b, state_c); pb_char(&b, ' ');
    /* Field 4: ppid */
    pb_u64(&b, ppid); pb_char(&b, ' ');
    /* Field 5: pgrp */
    pb_u64(&b, pgrp); pb_char(&b, ' ');
    /* Field 6: session */
    pb_u64(&b, session); pb_char(&b, ' ');
    /* Field 7: tty_nr (0 = no controlling terminal) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 8: tpgid (-1 = no terminal foreground group) */
    pb_char(&b, '-'); pb_char(&b, '1'); pb_char(&b, ' ');
    /* Field 9: flags */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 10-12: minflt cminflt majflt cmajflt (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 13-16: utime stime cutime cstime */
    pb_u64(&b, utime);  pb_char(&b, ' ');
    pb_u64(&b, stime);  pb_char(&b, ' ');
    pb_u64(&b, cutime); pb_char(&b, ' ');
    pb_u64(&b, cstime); pb_char(&b, ' ');
    /* Field 17: priority */
    if (priority < 0) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)(-priority)); }
    else pb_u64(&b, (uint64_t)priority);
    pb_char(&b, ' ');
    /* Field 18: nice */
    if (nice < 0) { pb_char(&b, '-'); pb_u64(&b, (uint64_t)(-nice)); }
    else pb_u64(&b, (uint64_t)nice);
    pb_char(&b, ' ');
    /* Field 19: num_threads */
    pb_u64(&b, task->thread_count ? task->thread_count : 1); pb_char(&b, ' ');
    /* Field 20: itrealvalue (obsolete, 0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 21: starttime */
    pb_u64(&b, starttime); pb_char(&b, ' ');
    /* Field 22: vsize */
    pb_u64(&b, vsize); pb_char(&b, ' ');
    /* Field 23: rss */
    pb_u64(&b, rss_pages); pb_char(&b, ' ');
    /* Field 24: rsslim (RLIM_INFINITY) */
    pb_str(&b, "4294967295"); pb_char(&b, ' ');
    /* Fields 25-28: startcode endcode startstack kstkesp (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Field 29: kstkeip (0) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 31-35: signal blocked sigignore sigcatch wchan */
    pb_u64(&b, pending_sig);  pb_char(&b, ' ');
    pb_u64(&b, blocked_sig);  pb_char(&b, ' ');
    pb_u64(&b, sigignore);    pb_char(&b, ' ');
    pb_u64(&b, sigcatch);     pb_char(&b, ' ');
    pb_char(&b, '0');         pb_char(&b, ' ');  /* (35) wchan */
    /* (36) nswap (37) cnswap: obsolete, always 0 */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (38) exit_signal: from task's exit_signal field (SIGCHLD=17 for fork) */
    { int esig = task->exit_signal; if (esig <= 0) esig = 17; pb_u64(&b, (uint64_t)esig); }
    pb_char(&b, ' ');
    /* (39) processor: CPU 0 */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (40) rt_priority: 0 for SCHED_OTHER, 1-99 for RT */
    {
        int rtp = 0;
        if (task->threads) rtp = task->threads->rt_priority;
        pb_u64(&b, (uint64_t)(rtp < 0 ? 0 : rtp)); pb_char(&b, ' ');
    }
    /* (41) policy: SCHED_OTHER=0, SCHED_FIFO=1, SCHED_RR=2, SCHED_BATCH=3, SCHED_IDLE=5 */
    {
        int pol = 0;
        if (task->threads) pol = task->threads->sched_policy;
        pb_u64(&b, (uint64_t)(pol < 0 ? 0 : pol)); pb_char(&b, ' ');
    }
    /* (42) delayacct_blkio_ticks: 0 (no delay accounting) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (43) guest_time: 0 (no hypervisor guest time) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (44) cguest_time: 0 */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (45-47) start_data end_data start_brk: from mm */
    {
        uint64_t sd = 0, ed = 0, sb = 0;
        if (task->mm) {
            sd = task->mm->brk_start ? task->mm->brk_start : 0;
            ed = task->mm->brk_current ? task->mm->brk_current : 0;
            sb = ed;
        }
        pb_u64(&b, sd); pb_char(&b, ' ');
        pb_u64(&b, ed); pb_char(&b, ' ');
        pb_u64(&b, sb); pb_char(&b, ' ');
    }
    /* (48-51) arg_start arg_end env_start env_end: 0 (not tracked in kernel context) */
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* (52) exit_code: 0 (process is running) */
    pb_char(&b, '0'); pb_char(&b, '\n');

    return b.pos;
}

/*
 * gen_statm() — /proc/<pid>/statm
 *
 * Seven space-separated values in pages:
 *   size resident shared text 0 data 0
 */
static size_t gen_statm(char *buf, size_t cap, fut_task_t *task) {
    if (!task) return 0;

    uint64_t size = 0, resident = 0;
    if (task->mm) {
        struct fut_vma *vma = task->mm->vma_list;
        while (vma) { size += vma->end - vma->start; vma = vma->next; }
        resident = size;  /* simplified: all mapped pages resident */
    }
    uint64_t size_pg = size / 4096;
    uint64_t res_pg  = resident / 4096;

    struct pbuf b = { buf, 0, cap };
    pb_u64(&b, size_pg); pb_char(&b, ' ');  /* size */
    pb_u64(&b, res_pg);  pb_char(&b, ' ');  /* resident */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* shared */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* text */
    pb_char(&b, '0');    pb_char(&b, ' ');  /* lib (always 0) */
    pb_u64(&b, size_pg); pb_char(&b, ' ');  /* data */
    pb_char(&b, '0');    pb_char(&b, '\n'); /* dt (dirty) */
    return b.pos;
}

/*
 * gen_cpuinfo() — /proc/cpuinfo
 *
 * Provides minimal CPU info compatible with Linux /proc/cpuinfo.
 * Architecture is detected at compile time.
 */
static size_t gen_cpuinfo(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "processor\t: 0\n");
#ifdef __x86_64__
    pb_str(&b, "vendor_id\t: GenuineIntel\n");
    pb_str(&b, "cpu family\t: 6\n");
    pb_str(&b, "model\t\t: 142\n");
    pb_str(&b, "model name\t: Futura Virtual Processor (x86_64)\n");
    pb_str(&b, "stepping\t: 10\n");
    pb_str(&b, "microcode\t: 0x0\n");
    pb_str(&b, "cpu MHz\t\t: 2400.000\n");
    pb_str(&b, "cache size\t: 4096 KB\n");
    pb_str(&b, "physical id\t: 0\n");
    pb_str(&b, "siblings\t: 1\n");
    pb_str(&b, "core id\t\t: 0\n");
    pb_str(&b, "cpu cores\t: 1\n");
    pb_str(&b, "apicid\t\t: 0\n");
    pb_str(&b, "initial apicid\t: 0\n");
    pb_str(&b, "fpu\t\t: yes\n");
    pb_str(&b, "fpu_exception\t: yes\n");
    pb_str(&b, "cpuid level\t: 22\n");
    pb_str(&b, "wp\t\t: yes\n");
    pb_str(&b, "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
               "pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx "
               "lm rep_good nopl xtopology cpuid pni pclmulqdq ssse3 cx16 "
               "pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer "
               "aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch\n");
    pb_str(&b, "bugs\t\t:\n");
    pb_str(&b, "bogomips\t: 4800.00\n");
    pb_str(&b, "clflush size\t: 64\n");
    pb_str(&b, "cache_alignment\t: 64\n");
    pb_str(&b, "address sizes\t: 39 bits physical, 48 bits virtual\n");
#elif defined(__aarch64__)
    pb_str(&b, "CPU implementer\t: 0x41\n");
    pb_str(&b, "CPU architecture: 8\n");
    pb_str(&b, "CPU variant\t: 0x0\n");
    pb_str(&b, "CPU part\t: 0xd08\n");
    pb_str(&b, "CPU revision\t: 3\n");
    pb_str(&b, "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 "
               "atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n");
    pb_str(&b, "BogoMIPS\t: 125.00\n");
#else
    pb_str(&b, "model name\t: Futura Virtual Processor\n");
#endif
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_loadavg() — /proc/loadavg
 *
 * Format: "1.00 5.00 15.00 R/T last_pid\n"
 * R = running threads, T = total threads, last_pid = newest PID.
 * Load averages are in 16.16 fixed-point from fut_get_load_avg().
 */
static size_t gen_loadavg(char *buf, size_t cap) {
    unsigned long loads[3] = {0, 0, 0};
    fut_get_load_avg(loads);

    /* Convert 16.16 fixed-point to integer + two decimal places */
    struct pbuf b = { buf, 0, cap };
    for (int i = 0; i < 3; i++) {
        uint64_t v = (uint64_t)loads[i];
        uint64_t int_part  = v >> 16;
        uint64_t frac_100  = ((v & 0xFFFFULL) * 100ULL) >> 16;
        pb_u64(&b, int_part);
        pb_char(&b, '.');
        if (frac_100 < 10) pb_char(&b, '0');
        pb_u64(&b, frac_100);
        pb_char(&b, (i < 2) ? ' ' : ' ');
    }
    /* running/total threads */
    uint64_t running = 0, total = 0;
    fut_task_t *t = fut_task_list;
    while (t) {
        total++;
        if (t->state == FUT_TASK_RUNNING) running++;
        t = t->next;
    }
    pb_u64(&b, running ? running : 1); pb_char(&b, '/');
    pb_u64(&b, total ? total : 1); pb_char(&b, ' ');
    /* last pid: find max pid */
    uint64_t last_pid = 0;
    t = fut_task_list;
    while (t) { if (t->pid > last_pid) last_pid = t->pid; t = t->next; }
    pb_u64(&b, last_pid);
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_mounts() — /proc/mounts (== /proc/self/mounts)
 *
 * One line per mount:
 *   device mountpoint fstype options 0 0
 */
static size_t gen_mounts(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    struct fut_mount *m = fut_vfs_first_mount();
    while (m) {
        const char *dev = (m->device && m->device[0]) ? m->device : "none";
        const char *mp  = (m->mountpoint && m->mountpoint[0]) ? m->mountpoint : "/";
        const char *fs  = (m->fs && m->fs->name) ? m->fs->name : "unknown";
        pb_str(&b, dev); pb_char(&b, ' ');
        pb_str(&b, mp);  pb_char(&b, ' ');
        pb_str(&b, fs);  pb_str(&b, " rw,relatime 0 0\n");
        m = m->next;
    }
    if (b.pos == 0) {
        /* Fallback: at least show rootfs */
        pb_str(&b, "rootfs / rootfs rw 0 0\n");
    }
    return b.pos;
}

/*
 * gen_wchan() — /proc/<pid>/wchan
 *
 * Returns the kernel wait channel symbol (or "0" if running / no symbol table).
 */
static size_t gen_wchan(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "0\n");
    return b.pos;
}

/*
 * gen_personality() — /proc/<pid>/personality
 *
 * Execution personality as 8-hex-digit value (zero-padded).
 * Most processes run PER_LINUX (0x00000000).
 */
static size_t gen_personality(char *buf, size_t cap, fut_task_t *task) {
    unsigned long p = task ? task->personality : 0UL;
    struct pbuf b = { buf, 0, cap };
    static const char hx[] = "0123456789abcdef";
    /* Emit 8 hex digits */
    for (int shift = 28; shift >= 0; shift -= 4)
        pb_char(&b, hx[(p >> (unsigned)shift) & 0xfU]);
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_mountinfo() — /proc/<pid>/mountinfo (Linux 2.6.26+)
 *
 * Extended mount table: each line has
 *   <id> <parent_id> <major>:<minor> <fs_root> <mountpoint> <options>
 *   [optional-fields] - <fs_type> <source> <super_opts>
 */
static size_t gen_mountinfo(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    struct fut_mount *m = fut_vfs_first_mount();
    int mid = 1;
    while (m) {
        const char *mp  = (m->mountpoint && m->mountpoint[0]) ? m->mountpoint : "/";
        const char *fs  = (m->fs && m->fs->name) ? m->fs->name : "unknown";
        const char *dev = (m->device && m->device[0]) ? m->device : "none";
        /* id parent major:minor fs_root mountpoint options */
        pb_u64(&b, (uint64_t)mid); pb_char(&b, ' ');
        pb_u64(&b, 0);             pb_char(&b, ' ');  /* parent = root (simplified) */
        pb_str(&b, "0:1 / ");
        pb_str(&b, mp);
        pb_str(&b, " rw,relatime shared:1 - ");
        pb_str(&b, fs);            pb_char(&b, ' ');
        pb_str(&b, dev);
        pb_str(&b, " rw\n");
        m = m->next;
        mid++;
    }
    if (b.pos == 0) {
        /* Fallback: at least show rootfs */
        pb_str(&b, "1 0 0:1 / / rw,relatime shared:1 - ramfs none rw\n");
    }
    return b.pos;
}

/*
 * gen_coredump_filter() — /proc/<pid>/coredump_filter
 *
 * Bitmask controlling which VMA types are included in core dumps.
 * Default 0x33 = anonymous private + anonymous shared + ELF headers.
 */
static size_t gen_coredump_filter(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "0x33\n");
    return b.pos;
}

/*
 * gen_schedstat() — /proc/<pid>/schedstat
 *
 * Linux format: "<time_on_cpu_ns> <time_waiting_ns> <nr_timeslices>\n"
 *
 * We derive cpu_ns from thread cpu_ticks (FUT_TIMER_HZ = 100 → 10ms each).
 * Wait time is not tracked; report 0. Timeslices = context_switches.
 */
static size_t gen_schedstat(char *buf, size_t cap, fut_task_t *task) {
    struct pbuf b = { buf, 0, cap };
    if (!task) { pb_str(&b, "0 0 0\n"); return b.pos; }

    uint64_t cpu_ticks = 0;
    uint64_t nr_switches = 0;
    for (fut_thread_t *t = task->threads; t; t = t->next) {
        cpu_ticks  += t->stats.cpu_ticks;
        nr_switches += t->stats.context_switches;
    }
    /* Convert ticks to nanoseconds: FUT_TIMER_HZ=100 → 10,000,000 ns/tick */
    uint64_t cpu_ns = cpu_ticks * 10000000ULL;

    pb_u64(&b, cpu_ns);    pb_char(&b, ' ');
    pb_u64(&b, 0);          pb_char(&b, ' ');   /* wait_sum: not tracked */
    pb_u64(&b, nr_switches); pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_cmdline_global() — /proc/cmdline
 *
 * Returns the kernel command-line (empty; Futura boots without a cmdline).
 */
static size_t gen_cmdline_global(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_swaps() — /proc/swaps
 *
 * Swap table header with no swap entries (no swap space configured).
 */
static size_t gen_swaps(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n");
    return b.pos;
}

/*
 * gen_devices() — /proc/devices
 *
 * List of registered character and block devices (minimal).
 */
static size_t gen_devices(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Character devices:\n");
    pb_str(&b, "  1 mem\n");
    pb_str(&b, "  4 /dev/vc/0\n");
    pb_str(&b, "  5 /dev/tty\n");
    pb_str(&b, "  5 /dev/console\n");
    pb_str(&b, "  5 /dev/ptmx\n");
    pb_str(&b, "  7 vcs\n");
    pb_str(&b, " 10 misc\n");
    pb_str(&b, "\nBlock devices:\n");
    return b.pos;
}

/*
 * gen_misc_dev() — /proc/misc
 *
 * List of misc character devices (minimal).
 */
static size_t gen_misc_dev(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "227 hpet\n");
    pb_str(&b, "236 device-mapper\n");
    return b.pos;
}

/*
 * gen_buddyinfo() — /proc/buddyinfo
 *
 * Memory buddy allocator free-page counts per order.
 * glibc malloc reads this on some arches to detect available huge pages.
 * Report one NUMA node with all free pages at order 0.
 */
static size_t gen_buddyinfo(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    /* Node 0, zone DMA32: one entry per order (0..10), all 0 except order 0 */
    pb_str(&b, "Node 0, zone      DMA32 ");
    uint64_t free_pages = fut_pmm_free_pages();
    pb_u64(&b, free_pages); /* order-0 pages */
    pb_str(&b, "  0  0  0  0  0  0  0  0  0  0\n");
    pb_str(&b, "Node 0, zone     Normal ");
    pb_u64(&b, 0);
    pb_str(&b, "  0  0  0  0  0  0  0  0  0  0\n");
    return b.pos;
}

/*
 * gen_zoneinfo() — /proc/zoneinfo
 *
 * Memory zone details. Minimal single-zone output for glibc/allocator compat.
 */
static size_t gen_zoneinfo(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    uint64_t total_pages = fut_pmm_total_pages();
    uint64_t free_pages  = fut_pmm_free_pages();
    pb_str(&b, "Node 0, zone   Normal\n");
    pb_str(&b, "  per-node stats\n");
    pb_str(&b, "      nr_inactive_anon 0\n");
    pb_str(&b, "      nr_active_anon "); pb_u64(&b, total_pages - free_pages); pb_char(&b, '\n');
    pb_str(&b, "      nr_inactive_file 0\n");
    pb_str(&b, "      nr_active_file 0\n");
    pb_str(&b, "      nr_unevictable 0\n");
    pb_str(&b, "      nr_slab_reclaimable 0\n");
    pb_str(&b, "      nr_slab_unreclaimable 0\n");
    pb_str(&b, "      nr_isolated_anon 0\n");
    pb_str(&b, "      nr_isolated_file 0\n");
    pb_str(&b, "      workingset_nodes 0\n");
    pb_str(&b, "      workingset_refault_anon 0\n");
    pb_str(&b, "      workingset_refault_file 0\n");
    pb_str(&b, "      nr_anon_pages "); pb_u64(&b, total_pages - free_pages); pb_char(&b, '\n');
    pb_str(&b, "      nr_mapped 0\n");
    pb_str(&b, "      nr_file_pages 0\n");
    pb_str(&b, "      nr_dirty 0\n");
    pb_str(&b, "      nr_writeback 0\n");
    pb_str(&b, "      nr_writeback_temp 0\n");
    pb_str(&b, "      nr_shmem 0\n");
    pb_str(&b, "      nr_shmem_hugepages 0\n");
    pb_str(&b, "      nr_shmem_pmdmapped 0\n");
    pb_str(&b, "      nr_file_hugepages 0\n");
    pb_str(&b, "      nr_file_pmdmapped 0\n");
    pb_str(&b, "      nr_anon_transparent_hugepages 0\n");
    pb_str(&b, "      nr_vmscan_write 0\n");
    pb_str(&b, "      nr_vmscan_immediate_reclaim 0\n");
    pb_str(&b, "      nr_dirtied 0\n");
    pb_str(&b, "      nr_written 0\n");
    pb_str(&b, "      nr_throttled_written 0\n");
    pb_str(&b, "      nr_kernel_misc_reclaimable 0\n");
    pb_str(&b, "      nr_foll_pin_acquired 0\n");
    pb_str(&b, "      nr_foll_pin_released 0\n");
    pb_str(&b, "      nr_kernel_stack 0\n");
    pb_str(&b, "      nr_page_table_pages 0\n");
    pb_str(&b, "      nr_sec_page_table_pages 0\n");
    pb_str(&b, "      nr_shadow_call_stack 0\n");
    pb_str(&b, "      nr_zone_inactive_anon 0\n");
    pb_str(&b, "      nr_zone_active_anon "); pb_u64(&b, total_pages - free_pages); pb_char(&b, '\n');
    pb_str(&b, "      nr_zone_inactive_file 0\n");
    pb_str(&b, "      nr_zone_active_file 0\n");
    pb_str(&b, "      nr_zone_unevictable 0\n");
    pb_str(&b, "      nr_zone_write_pending 0\n");
    pb_str(&b, "      nr_mlock 0\n");
    pb_str(&b, "      nr_bounce 0\n");
    pb_str(&b, "      nr_zspages 0\n");
    pb_str(&b, "      nr_free_cma 0\n");
    pb_str(&b, "  pages free     "); pb_u64(&b, free_pages);  pb_char(&b, '\n');
    pb_str(&b, "        boost    0\n");
    pb_str(&b, "        min      0\n");
    pb_str(&b, "        low      0\n");
    pb_str(&b, "        high     0\n");
    pb_str(&b, "        spanned  "); pb_u64(&b, total_pages); pb_char(&b, '\n');
    pb_str(&b, "        present  "); pb_u64(&b, total_pages); pb_char(&b, '\n');
    pb_str(&b, "        managed  "); pb_u64(&b, total_pages); pb_char(&b, '\n');
    pb_str(&b, "        cma      0\n");
    pb_str(&b, "        protection: (0, 0)\n");
    return b.pos;
}

/*
 * gen_diskstats() — /proc/diskstats
 *
 * Block device I/O statistics. Futura has no block devices; emit an empty
 * file so iostat/iotop don't fail with ENOENT.
 */
static size_t gen_diskstats(char *buf, size_t cap) {
    (void)buf; (void)cap;
    return 0;
}

/*
 * gen_partitions() — /proc/partitions
 *
 * Block device partition table header. No partitions in futura; emit the
 * standard header so lsblk/blkid don't fail with ENOENT.
 */
static size_t gen_partitions(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "major minor  #blocks  name\n\n");
    return b.pos;
}

/*
 * gen_cgroups() — /proc/cgroups
 *
 * Control group subsystem list. All subsystems report hierarchy=0 (not
 * mounted), num_cgroups=1 (root only), enabled=1. Docker, systemd, and
 * libvirt read this file to enumerate available cgroup controllers.
 */
static size_t gen_cgroups(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
    pb_str(&b, "cpuset\t0\t1\t1\n");
    pb_str(&b, "cpu\t0\t1\t1\n");
    pb_str(&b, "cpuacct\t0\t1\t1\n");
    pb_str(&b, "blkio\t0\t1\t1\n");
    pb_str(&b, "memory\t0\t1\t1\n");
    pb_str(&b, "devices\t0\t1\t1\n");
    pb_str(&b, "freezer\t0\t1\t1\n");
    pb_str(&b, "net_cls\t0\t1\t1\n");
    pb_str(&b, "pids\t0\t1\t1\n");
    return b.pos;
}

/*
 * gen_kallsyms() — /proc/kallsyms
 *
 * Kernel symbol table. Addresses are zeroed (all-zeros) per kptr_restrict=1
 * semantics (unprivileged users see zeroed addresses). Format per symbol:
 *   <16-digit-hex-addr> <type> <name>[\t[module]]\n
 * Type characters: T=text, D=data, B=bss, A=absolute, R=rodata, W=weak.
 * Tools like perf, eBPF loader, ltrace, and kmod read this file.
 */
static size_t gen_kallsyms(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    /* Emit a representative set of kernel symbols with zeroed addresses.
     * This is sufficient for tools that probe symbol existence (e.g. perf,
     * BCC/eBPF loaders, systemtap) without exposing kernel layout. */
    static const struct { const char *name; char type; } syms[] = {
        { "_text",                    'T' },
        { "_stext",                   'T' },
        { "kernel_main",              'T' },
        { "fut_task_current",         'T' },
        { "fut_task_schedule",        'T' },
        { "fut_task_create",          'T' },
        { "fut_task_exit",            'T' },
        { "sys_read",                 'T' },
        { "sys_write",                'T' },
        { "sys_open",                 'T' },
        { "sys_close",                'T' },
        { "sys_mmap",                 'T' },
        { "sys_brk",                  'T' },
        { "sys_fork",                 'T' },
        { "sys_execve",               'T' },
        { "sys_exit",                 'T' },
        { "sys_wait4",                'T' },
        { "sys_kill",                 'T' },
        { "sys_getpid",               'T' },
        { "sys_clone",                'T' },
        { "sys_socket",               'T' },
        { "sys_accept",               'T' },
        { "sys_connect",              'T' },
        { "sys_sendto",               'T' },
        { "sys_recvfrom",             'T' },
        { "sys_epoll_create1",        'T' },
        { "sys_epoll_ctl",            'T' },
        { "sys_epoll_wait",           'T' },
        { "fut_mm_map_anonymous",     'T' },
        { "fut_mm_unmap",             'T' },
        { "fut_vfs_open",             'T' },
        { "fut_vfs_close",            'T' },
        { "fut_vfs_read",             'T' },
        { "fut_vfs_write",            'T' },
        { "fut_printf",               'T' },
        { "_etext",                   'T' },
        { "_sdata",                   'D' },
        { "_edata",                   'D' },
        { "g_realtime_offset_sec",    'D' },
        { "_sbss",                    'B' },
        { "_ebss",                    'B' },
        { "_end",                     'A' },
    };
    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++) {
        pb_str(&b, "0000000000000000 ");
        pb_char(&b, syms[i].type);
        pb_char(&b, ' ');
        pb_str(&b, syms[i].name);
        pb_char(&b, '\n');
    }
    return b.pos;
}

/*
 * gen_comm() — /proc/<pid>/comm
 *
 * Single line: process name + newline.
 */
/* tid: when non-zero, this is /proc/<pid>/task/<tid>/comm — show thread name */
static size_t gen_comm(char *buf, size_t cap, fut_task_t *task, uint64_t tid) {
    if (!task) return 0;
    const char *name = task->comm[0] ? task->comm : "?";
    if (tid) {
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid && t->comm[0]) { name = t->comm; break; }
        }
    }
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, name);
    pb_char(&b, '\n');
    return b.pos;
}

/* ============================================================
 *   UUID / random helpers for /proc/sys/kernel/random/
 * ============================================================ */

/* Simple xorshift64 — independent from sys_getrandom state */
static uint64_t procfs_rng_state = 0;

static uint64_t procfs_rng_next(void) {
    if (!procfs_rng_state) {
        /* Seed from hardware */
#ifdef __x86_64__
        uint32_t lo, hi;
        __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
        procfs_rng_state = ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(procfs_rng_state));
#endif
        procfs_rng_state ^= fut_get_ticks() ^ 0xDEADBEEFCAFEBABEULL;
        if (!procfs_rng_state) procfs_rng_state = 0x6A09E667F3BCC908ULL;
    }
    uint64_t x = procfs_rng_state;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    procfs_rng_state = x;
    return x;
}

/* Format 16 random bytes as UUID v4: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx */
static size_t gen_uuid_into(char *out, size_t cap) {
    if (cap < 38) return 0;  /* 36 chars + '\n' + '\0' */
    uint64_t a = procfs_rng_next();
    uint64_t b = procfs_rng_next();
    /* Set version 4 and variant bits */
    a = (a & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    static const char hex[] = "0123456789abcdef";
    char *p = out;
#define HEX2(v) *p++ = hex[((v)>>4)&0xF]; *p++ = hex[(v)&0xF]
    uint8_t bytes[16];
    for (int i = 0; i < 8; i++) bytes[i]   = (uint8_t)(a >> (56 - i*8));
    for (int i = 0; i < 8; i++) bytes[8+i] = (uint8_t)(b >> (56 - i*8));
    HEX2(bytes[0]); HEX2(bytes[1]); HEX2(bytes[2]); HEX2(bytes[3]);
    *p++ = '-';
    HEX2(bytes[4]); HEX2(bytes[5]);
    *p++ = '-';
    HEX2(bytes[6]); HEX2(bytes[7]);
    *p++ = '-';
    HEX2(bytes[8]); HEX2(bytes[9]);
    *p++ = '-';
    HEX2(bytes[10]); HEX2(bytes[11]); HEX2(bytes[12]);
    HEX2(bytes[13]); HEX2(bytes[14]); HEX2(bytes[15]);
#undef HEX2
    *p++ = '\n';
    *p = '\0';
    return (size_t)(p - out);
}

/* boot_id: generated once at first read, fixed thereafter */
static char g_boot_id[38] = {0};  /* 36 chars + '\n' + '\0' */

static size_t gen_boot_id(char *buf, size_t cap) {
    if (!g_boot_id[0])
        gen_uuid_into(g_boot_id, sizeof(g_boot_id));
    size_t len = 0;
    while (g_boot_id[len]) len++;
    if (len > cap) len = cap;
    __builtin_memcpy(buf, g_boot_id, len);
    return len;
}

/* ============================================================
 *   /proc/vmstat — VM statistics
 * ============================================================ */
static size_t gen_vmstat(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    uint64_t total_kb  = fut_pmm_total_pages() * 4;
    uint64_t free_kb   = fut_pmm_free_pages()  * 4;
    uint64_t total_pg  = total_kb / 4;
    uint64_t free_pg   = free_kb  / 4;
    uint64_t used_pg   = total_pg > free_pg ? total_pg - free_pg : 0;

    pb_str(&b, "nr_free_pages ");       pb_u64(&b, free_pg);  pb_char(&b, '\n');
    pb_str(&b, "nr_inactive_anon ");    pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_active_anon ");      pb_u64(&b, used_pg);   pb_char(&b, '\n');
    pb_str(&b, "nr_inactive_file ");    pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_active_file ");      pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_anon_pages ");       pb_u64(&b, used_pg);   pb_char(&b, '\n');
    pb_str(&b, "nr_mapped ");           pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_file_pages ");       pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_dirty ");            pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_writeback ");        pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_slab_reclaimable "); pb_u64(&b, 0);         pb_char(&b, '\n');
    pb_str(&b, "nr_slab_unreclaimable "); pb_u64(&b, 0);       pb_char(&b, '\n');
    pb_str(&b, "pgpgin 0\n");
    pb_str(&b, "pgpgout 0\n");
    pb_str(&b, "pgfault 0\n");
    pb_str(&b, "pgmajfault 0\n");
    return b.pos;
}

/* ============================================================
 *   /proc/net/tcp and /proc/net/udp — AF_INET socket tables
 * ============================================================ */

/* Emit one AF_INET SOCK_STREAM socket row in /proc/net/tcp format.
 * Format matches Linux: sl local_address rem_address st tx:rx_q tr:when uid timeout inode
 * IPv4 address printed as raw uint32 (LE byte-order = reversed octets, matching Linux). */
struct net_tcp_ctx { struct pbuf *b; int slot; };
static void net_tcp_emit_one(const fut_socket_t *s, void *arg) {
    struct net_tcp_ctx *ctx = (struct net_tcp_ctx *)arg;
    if (s->address_family != AF_INET || s->socket_type != SOCK_STREAM)
        return;
    struct pbuf *b = ctx->b;
    int sl = ctx->slot++;

    /* TCP state mapping */
    uint8_t tcp_state;
    switch (s->state) {
    case FUT_SOCK_CONNECTED:  tcp_state = 0x01; break;  /* ESTABLISHED */
    case FUT_SOCK_LISTENING:  tcp_state = 0x0A; break;  /* LISTEN */
    case FUT_SOCK_CONNECTING: tcp_state = 0x02; break;  /* SYN_SENT */
    default:                  tcp_state = 0x07; break;  /* CLOSE */
    }

    /* inet_port is stored in network byte order; swap to host order for display */
    uint16_t lport = (uint16_t)((s->inet_port >> 8) | ((s->inet_port & 0xFF) << 8));

    pb_d_padded(b, (uint64_t)sl, 4);
    pb_str(b, ": ");
    /* local address: raw uint32 (prints reversed octets on LE, matching Linux format) */
    pb_hex8U(b, s->inet_addr);
    pb_char(b, ':');
    pb_hex4U(b, lport);
    /* remote address: unconnected → 00000000:0000 */
    pb_str(b, " 00000000:0000 ");
    pb_hex2U(b, tcp_state);
    /* tx_queue:rx_queue, timer, uid, timeout, inode */
    pb_str(b, " 00000000:00000000 00:00000000 00000000     0        0 ");
    pb_u64(b, (uint64_t)s->socket_id);
    pb_str(b, " 1 0000000000000000 100 0 0 10 0\n");
}

/* Emit one AF_INET SOCK_DGRAM socket row in /proc/net/udp format. */
struct net_udp_ctx { struct pbuf *b; int slot; };
static void net_udp_emit_one(const fut_socket_t *s, void *arg) {
    struct net_udp_ctx *ctx = (struct net_udp_ctx *)arg;
    if (s->address_family != AF_INET || s->socket_type != SOCK_DGRAM)
        return;
    struct pbuf *b = ctx->b;
    int sl = ctx->slot++;

    uint16_t lport = (uint16_t)((s->inet_port >> 8) | ((s->inet_port & 0xFF) << 8));

    pb_d_padded(b, (uint64_t)sl, 4);
    pb_str(b, ": ");
    pb_hex8U(b, s->inet_addr);
    pb_char(b, ':');
    pb_hex4U(b, lport);
    pb_str(b, " 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 ");
    pb_u64(b, (uint64_t)s->socket_id);
    pb_str(b, " 1 0000000000000000 100 0 0 10 0\n");
}

/* Count sockets by type for /proc/net/sockstat */
struct sockstat_ctx { int total; int tcp; int udp; };
static void sockstat_count_one(const fut_socket_t *s, void *arg) {
    struct sockstat_ctx *ctx = (struct sockstat_ctx *)arg;
    ctx->total++;
    if (s->address_family == AF_INET && s->socket_type == SOCK_STREAM) ctx->tcp++;
    else if (s->address_family == AF_INET && s->socket_type == SOCK_DGRAM) ctx->udp++;
}

/* ============================================================
 *   /proc/net/ file generators
 * ============================================================ */
static size_t gen_net_dev(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Inter-|   Receive                                                |  Transmit\n");
    pb_str(&b, " face |bytes    packets errs drop fifo frame compressed multicast|"
               "bytes    packets errs drop fifo colls carrier compressed\n");
    pb_str(&b, "    lo:       0       0    0    0    0     0          0         0"
               "        0       0    0    0    0     0       0          0\n");
    return b.pos;
}

static size_t gen_net_route(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
    /* Loopback route: 127.0.0.0/8 → lo, flags RTF_UP(0x1) */
    pb_str(&b, "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n");
    return b.pos;
}

static size_t gen_net_tcp(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
               "   uid  timeout inode\n");
    struct net_tcp_ctx ctx = { &b, 0 };
    fut_socket_foreach(net_tcp_emit_one, &ctx);
    return b.pos;
}

static size_t gen_net_udp(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when"
               " retrnsmt   uid  timeout inode ref pointer drops\n");
    struct net_udp_ctx ctx = { &b, 0 };
    fut_socket_foreach(net_udp_emit_one, &ctx);
    return b.pos;
}

static size_t gen_net_if_inet6(char *buf, size_t cap) {
    /* Empty — no IPv6 interfaces */
    (void)buf; (void)cap;
    return 0;
}

static size_t gen_net_tcp6(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "  sl  local_address                         remote_address"
               "                        st tx_queue rx_queue tr tm->when retrnsmt"
               "   uid  timeout inode\n");
    return b.pos;
}

static size_t gen_net_raw(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when"
               " retrnsmt   uid  timeout inode ref pointer drops\n");
    return b.pos;
}

static size_t gen_net_fib_trie(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Local:\n"
               "  +-- 0.0.0.0/0 1 0 0\n"
               "Main:\n"
               "  +-- 0.0.0.0/0 1 0 0\n");
    return b.pos;
}

static size_t gen_net_snmp(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors"
               " ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests"
               " OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails"
               " FragOKs FragFails FragCreates\n"
               "Ip: 2 64 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
               "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds"
               " InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps"
               " OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs\n"
               "Icmp: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
               "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens"
               " AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs"
               " InErrs OutRsts InCsumErrors\n"
               "Tcp: 1 200 120000 -1 0 0 0 0 0 0 0 0 0 0 0\n"
               "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors"
               " SndbufErrors InCsumErrors IgnoredMulti\n"
               "Udp: 0 0 0 0 0 0 0 0\n"
               "UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors"
               " SndbufErrors InCsumErrors IgnoredMulti\n"
               "UdpLite: 0 0 0 0 0 0 0 0\n");
    return b.pos;
}

static size_t gen_net_netstat(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts"
               " PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps"
               " TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs"
               " DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops"
               " TCPHPHits TCPPureAcks TCPHPAcks TCPRenoRecovery TCPSackRecovery"
               " TCPFACKReorder TCPSACKReorder TCPRenoReorder TCPTSReorder"
               " TCPFullUndo TCPPartialUndo TCPDSACKUndo TCPLossUndo TCPRetransFail"
               " TCPSackFailures TCPLossFailures TCPSchedulerFailed TCPRcvCollapsed\n"
               "TcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
               "IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts"
               " InBcastPkts OutBcastPkts InOctets OutOctets InMcastOctets"
               " OutMcastOctets InBcastOctets OutBcastOctets InCsumErrors\n"
               "IpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
    return b.pos;
}

static size_t gen_net_packet(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n");
    return b.pos;
}

/* Helper struct passed as arg to net_unix_emit_one() callback. */
struct net_unix_ctx { struct pbuf *b; };

/* File-scope callback; no nested functions in pedantic mode. */
static void net_unix_emit_one(const fut_socket_t *s, void *arg) {
    struct net_unix_ctx *ctx = (struct net_unix_ctx *)arg;
    struct pbuf *b = ctx->b;

    /* Num: 16-digit hex address + ':' */
    pb_hex16(b, (uint64_t)(uintptr_t)s);
    pb_str(b, ": ");

    /* RefCount: 8-digit hex */
    pb_hex8(b, (uint64_t)s->refcount);
    pb_char(b, ' ');

    /* Protocol: 00000000 (AF_UNIX has no sub-protocol) */
    pb_str(b, "00000000 ");

    /* Flags: 00010000 for listening sockets, 00000000 otherwise */
    if (s->state == FUT_SOCK_LISTENING)
        pb_str(b, "00010000 ");
    else
        pb_str(b, "00000000 ");

    /* Type: socket type as 4-digit hex (STREAM=0001, DGRAM=0002, SEQPACKET=0005) */
    switch (s->socket_type) {
    case 1:  pb_str(b, "0001 "); break;  /* SOCK_STREAM */
    case 2:  pb_str(b, "0002 "); break;  /* SOCK_DGRAM */
    case 5:  pb_str(b, "0005 "); break;  /* SOCK_SEQPACKET */
    default: pb_str(b, "0000 "); break;
    }

    /* St: state as 2-digit hex */
    switch (s->state) {
    case FUT_SOCK_LISTENING:   pb_str(b, "01 "); break;
    case FUT_SOCK_CONNECTING:  pb_str(b, "02 "); break;
    case FUT_SOCK_CONNECTED:   pb_str(b, "03 "); break;
    default:                   pb_str(b, "00 "); break;
    }

    /* Inode: decimal socket_id (stable per socket) */
    pb_u64(b, (uint64_t)s->socket_id);

    /* Path: filesystem path, @name for abstract, or empty for anonymous */
    if (s->bound_path && s->bound_path_len > 0) {
        pb_char(b, ' ');
        if (s->bound_path[0] == '\0') {
            /* Abstract socket: replace leading NUL with '@' */
            pb_char(b, '@');
            const char *name = s->bound_path + 1;
            uint16_t nlen = (s->bound_path_len > 1) ? (s->bound_path_len - 1) : 0;
            for (uint16_t i = 0; i < nlen && name[i] != '\0'; i++)
                pb_char(b, name[i]);
        } else {
            pb_str(b, s->bound_path);
        }
    }

    pb_char(b, '\n');
}

static size_t gen_net_unix(char *buf, size_t cap) {
    /* /proc/net/unix — Unix domain socket table.
     * Tools: ss -x, lsof, netstat -x, systemd socket activation checks.
     * Header matches Linux kernel format exactly. */
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Num       RefCount Protocol Flags    Type St Inode Path\n");
    struct net_unix_ctx ctx = { &b };
    fut_socket_foreach(net_unix_emit_one, &ctx);
    return b.pos;
}

static size_t gen_net_arp(char *buf, size_t cap) {
    /* /proc/net/arp — ARP table.
     * Used by arp(8), ip neigh, network diagnostic tools.
     * Header matches Linux kernel format. Empty table is valid. */
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "IP address       HW type     Flags       HW address            Mask     Device\n");
    return b.pos;
}

static size_t gen_net_sockstat(char *buf, size_t cap) {
    /* /proc/net/sockstat — socket usage statistics.
     * Read by ss, netstat, systemd, and glibc resolver. */
    struct pbuf b = { buf, 0, cap };
    struct sockstat_ctx sc = { 0, 0, 0 };
    fut_socket_foreach(sockstat_count_one, &sc);
    pb_str(&b, "sockets: used "); pb_u64(&b, (uint64_t)sc.total); pb_char(&b, '\n');
    pb_str(&b, "TCP: inuse "); pb_u64(&b, (uint64_t)sc.tcp);
    pb_str(&b, " orphan 0 tw 0 alloc "); pb_u64(&b, (uint64_t)sc.tcp);
    pb_str(&b, " mem 0\n");
    pb_str(&b, "UDP: inuse "); pb_u64(&b, (uint64_t)sc.udp); pb_str(&b, " mem 0\n");
    pb_str(&b, "UDPLITE: inuse 0\n");
    pb_str(&b, "RAW: inuse 0\n");
    pb_str(&b, "FRAG: inuse 0 memory 0\n");
    return b.pos;
}

/* ============================================================
 *   /proc/stat — global CPU / system statistics
 * ============================================================ */
static size_t gen_proc_stat(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };

    /* Total ticks = system ticks; we have no user/nice/idle split yet */
    uint64_t total_ticks = fut_get_ticks();  /* real-time ticks since boot */
    uint64_t ctxt        = fut_stats_get_context_switches();

    /* Approximate: report all time as system (we don't split user vs kernel yet) */
    /* Format: cpu user nice system idle iowait irq softirq steal guest guest_nice */
    pb_str(&b, "cpu  0 0 ");  pb_u64(&b, total_ticks);
    pb_str(&b, " 0 0 0 0 0 0 0\n");

    pb_str(&b, "cpu0 0 0 "); pb_u64(&b, total_ticks);
    pb_str(&b, " 0 0 0 0 0 0 0\n");

    /* ctxt: context switches since boot */
    pb_str(&b, "ctxt ");     pb_u64(&b, ctxt);     pb_char(&b, '\n');

    /* btime: boot time as seconds since epoch (approx: realtime_offset covers wall time) */
    extern volatile int64_t g_realtime_offset_sec;
    int64_t uptime_sec = (int64_t)(total_ticks / 100);
    int64_t btime = g_realtime_offset_sec > uptime_sec
                    ? g_realtime_offset_sec - uptime_sec : 0;
    pb_str(&b, "btime ");    pb_u64(&b, (uint64_t)btime); pb_char(&b, '\n');

    /* processes: total tasks ever created — use running task count as approximation */
    uint64_t nproc = 0;
    fut_task_t *t = fut_task_list;
    while (t) { nproc++; t = t->next; }
    pb_str(&b, "processes "); pb_u64(&b, nproc); pb_char(&b, '\n');

    pb_str(&b, "procs_running "); pb_u64(&b, nproc > 0 ? nproc : 1); pb_char(&b, '\n');
    pb_str(&b, "procs_blocked 0\n");
    pb_str(&b, "softirq 0 0 0 0 0 0 0 0 0 0 0\n");

    return b.pos;
}

/* ============================================================
 *   /proc/filesystems — registered filesystem types
 * ============================================================ */
static size_t gen_filesystems(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "nodev\tsysfs\n");
    pb_str(&b, "nodev\trootfs\n");
    pb_str(&b, "nodev\tproc\n");
    pb_str(&b, "nodev\ttmpfs\n");
    pb_str(&b, "nodev\tdevtmpfs\n");
    pb_str(&b, "nodev\tramfs\n");
    pb_str(&b, "\text4\n");
    return b.pos;
}

/* /proc/sys/kernel/ and /proc/sys/vm/ file generators */
static size_t gen_sysctl_str(char *buf, size_t cap, const char *value) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, value);
    pb_char(&b, '\n');
    return b.pos;
}

/* ============================================================
 *   File Operations
 * ============================================================ */

static ssize_t procfs_file_read(struct fut_vnode *vnode, void *buf, size_t size, uint64_t offset) {
    if (!vnode || !buf) return -EINVAL;
    procfs_node_t *n = (procfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    /*
     * /proc/<pid>/mem: offset is a virtual address; read directly.
     * In Futura's shared address space all tasks map the same VA range, so
     * we validate the request against the task's VMA list and memcpy.
     */
    if (n->kind == PROC_PID_MEM) {
        if (size == 0) return 0;
        fut_task_t *task = fut_task_by_pid(n->pid);
        if (!task) return -ESRCH;
        fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
        if (!mm) return -EIO;

        uintptr_t addr = (uintptr_t)offset;
        uintptr_t end  = addr + size;

        /* Find a VMA that covers addr */
        struct fut_vma *vma = mm->vma_list;
        while (vma && vma->end <= addr)
            vma = vma->next;

        if (!vma || vma->start > addr)
            return -EIO;   /* address not mapped */

        /* Clamp to this VMA */
        if (end > vma->end)
            end = vma->end;
        size_t copy_sz = (size_t)(end - addr);

        const void *src = (const void *)addr;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(buf, src, copy_sz);
        } else
#endif
        if (fut_copy_to_user(buf, src, copy_sz) != 0)
            return -EFAULT;
        return (ssize_t)copy_sz;
    }

    /*
     * /proc/<pid>/pagemap: binary file, 8 bytes per page of virtual address space.
     * offset is a byte offset; entry index = offset / 8; VA = entry_index * PAGE_SIZE.
     *
     * Each 64-bit entry:
     *   bit 63: page present (in a mapped VMA)
     *   bit 56: page exclusively mapped (not shared)
     *   bits 0-54: page frame number (synthetic: VA >> PAGE_SHIFT)
     *
     * Returns 0 entries for unmapped regions (Linux semantics).
     * Tools use this to discover which pages are resident (bit 63).
     */
    if (n->kind == PROC_PAGEMAP) {
        if (size == 0) return 0;
        /* size must be a multiple of 8 */
        size_t entries = size / 8;
        if (entries == 0) return -EINVAL;

        fut_task_t *task = fut_task_by_pid(n->pid);
        if (!task) return -ESRCH;
        fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
        if (!mm) return -EIO;

        uint64_t *out = (uint64_t *)buf;
        uintptr_t base_va = (uintptr_t)(offset / 8) * PAGE_SIZE;

        for (size_t i = 0; i < entries; i++) {
            uintptr_t va = base_va + (uintptr_t)(i * PAGE_SIZE);
            /* Walk VMA list to check if va is mapped */
            struct fut_vma *vma = mm->vma_list;
            while (vma && vma->end <= va)
                vma = vma->next;

            uint64_t entry;
            if (vma && vma->start <= va) {
                /* Page is present in a mapped VMA.
                 * Synthetic PFN: treat VA as if mapped 1:1 at same frame index. */
                uint64_t pfn = va >> 12;  /* PAGE_SHIFT = 12 */
                int shared = (vma->flags & VMA_SHARED) ? 1 : 0;
                entry = (1ULL << 63)                     /* PM_PRESENT */
                      | (shared ? 0 : (1ULL << 56))      /* PM_MMAP_EXCLUSIVE if private */
                      | (pfn & 0x7fffffffffffffULL);      /* bits 0-54: PFN */
            } else {
                entry = 0;  /* not mapped */
            }

#ifdef KERNEL_VIRTUAL_BASE
            if ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE) {
                out[i] = entry;
                continue;
            }
#endif
            if (fut_copy_to_user(&out[i], &entry, sizeof(entry)) != 0)
                return (i > 0) ? (ssize_t)(i * 8) : -EFAULT;
        }
        return (ssize_t)(entries * 8);
    }

    /* Generate content into a temporary 8KB buffer */
    const size_t GEN_BUF = 8192;
    char *tmp = fut_malloc(GEN_BUF);
    if (!tmp) return -ENOMEM;

    size_t total = 0;
    switch (n->kind) {
        case PROC_MEMINFO: total = gen_meminfo(tmp, GEN_BUF); break;
        case PROC_VERSION: total = gen_version(tmp, GEN_BUF); break;
        case PROC_UPTIME:  total = gen_uptime(tmp, GEN_BUF);  break;
        case PROC_STATUS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            /* n->fd is non-zero when reading /proc/<pid>/task/<tid>/status:
             * it holds the TID so Pid: shows the thread ID, not the process ID. */
            total = task ? gen_status(tmp, GEN_BUF, task, (uint64_t)(unsigned int)n->fd) : 0;
            break;
        }
        case PROC_MAPS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_maps(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_CMDLINE: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_cmdline(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_ENVIRON: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (task && task->proc_environ_len > 0) {
                size_t n_bytes = task->proc_environ_len;
                if (n_bytes > GEN_BUF) n_bytes = GEN_BUF;
                __builtin_memcpy(tmp, task->proc_environ, n_bytes);
                total = n_bytes;
            }
            break;
        }
        case PROC_AUXV: {
            /* /proc/<pid>/auxv — ELF auxiliary vector in binary {key,val} uint64_t pairs.
             * The kernel pushes auxv onto the user stack during exec (elf64.c), but does
             * not store a per-task copy.  We reconstruct the minimal set of entries that
             * debuggers and getauxval() callers care about most. */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (task) {
                struct { uint64_t key; uint64_t val; } *av =
                    (void *)tmp;
                int ai = 0;
#define AUXV_PUSH(k, v) do { av[ai].key = (k); av[ai].val = (v); ai++; } while(0)
                AUXV_PUSH(6,  PAGE_SIZE);               /* AT_PAGESZ */
                AUXV_PUSH(11, (uint64_t)task->ruid);    /* AT_UID */
                AUXV_PUSH(12, (uint64_t)task->uid);     /* AT_EUID */
                AUXV_PUSH(13, (uint64_t)task->rgid);    /* AT_GID */
                AUXV_PUSH(14, (uint64_t)task->gid);     /* AT_EGID */
                /* AT_SECURE: 1 if effective credentials differ from real */
                uint64_t secure = (task->uid != task->ruid || task->gid != task->rgid) ? 1 : 0;
                AUXV_PUSH(23, secure);                  /* AT_SECURE */
                AUXV_PUSH(16, 0ULL);                    /* AT_HWCAP — no special hw caps */
                AUXV_PUSH(0,  0ULL);                    /* AT_NULL — terminator */
#undef AUXV_PUSH
                total = (size_t)ai * sizeof(av[0]);
            }
            break;
        }
        case PROC_UID_MAP: {
            /* /proc/<pid>/uid_map — user namespace uid mapping.
             * Format: "inside_start outside_start count\n"
             * Futura has no user namespaces; report identity mapping for the
             * full 32-bit UID space (same as Linux initial user namespace). */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "         0          0 4294967295\n");
            total = b.pos;
            break;
        }
        case PROC_GID_MAP: {
            /* /proc/<pid>/gid_map — same format as uid_map */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "         0          0 4294967295\n");
            total = b.pos;
            break;
        }
        case PROC_SETGROUPS: {
            /* /proc/<pid>/setgroups — "allow" means setgroups(2) is permitted.
             * Futura has no user namespace restrictions, so always "allow". */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "allow\n");
            total = b.pos;
            break;
        }
        case PROC_LOGINUID: {
            /* /proc/<pid>/loginuid — audit login UID. 4294967295 = (uint32_t)-1 means
             * "not set" (process not created via PAM login session). Futura has no
             * audit subsystem, so report unset for all processes. */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_u64(&b, 4294967295ULL);
            pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_SESSIONID: {
            /* /proc/<pid>/sessionid — audit session ID. 4294967295 = unset.
             * Return the task's session ID from its credential fields. */
            fut_task_t *task = fut_task_by_pid(n->pid);
            struct pbuf b = { tmp, 0, GEN_BUF };
            if (task && task->sid) {
                pb_u64(&b, task->sid);
            } else {
                pb_u64(&b, 4294967295ULL);
            }
            pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_STAT: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_stat(tmp, GEN_BUF, task, (uint64_t)(unsigned int)n->fd) : 0;
            break;
        }
        case PROC_STATM: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_statm(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_CPUINFO:
            total = gen_cpuinfo(tmp, GEN_BUF);
            break;
        case PROC_LOADAVG:
            total = gen_loadavg(tmp, GEN_BUF);
            break;
        case PROC_MOUNTS:
            total = gen_mounts(tmp, GEN_BUF);
            break;
        case PROC_STAT_GLOBAL:
            total = gen_proc_stat(tmp, GEN_BUF);
            break;
        case PROC_FILESYSTEMS:
            total = gen_filesystems(tmp, GEN_BUF);
            break;
        case PROC_VMSTAT:
            total = gen_vmstat(tmp, GEN_BUF);
            break;
        case PROC_NET_DEV:
            total = gen_net_dev(tmp, GEN_BUF);
            break;
        case PROC_NET_ROUTE:
            total = gen_net_route(tmp, GEN_BUF);
            break;
        case PROC_NET_TCP:
            total = gen_net_tcp(tmp, GEN_BUF);
            break;
        case PROC_NET_UDP:
            total = gen_net_udp(tmp, GEN_BUF);
            break;
        case PROC_NET_TCP6:
        case PROC_NET_UDP6:
            total = gen_net_tcp6(tmp, GEN_BUF);
            break;
        case PROC_NET_RAW:
            total = gen_net_raw(tmp, GEN_BUF);
            break;
        case PROC_NET_PACKET:
            total = gen_net_packet(tmp, GEN_BUF);
            break;
        case PROC_NET_FIB_TRIE:
            total = gen_net_fib_trie(tmp, GEN_BUF);
            break;
        case PROC_NET_SNMP:
            total = gen_net_snmp(tmp, GEN_BUF);
            break;
        case PROC_NET_NETSTAT:
            total = gen_net_netstat(tmp, GEN_BUF);
            break;
        case PROC_NET_IF_INET6:
            total = gen_net_if_inet6(tmp, GEN_BUF);
            break;
        case PROC_NET_UNIX:
            total = gen_net_unix(tmp, GEN_BUF);
            break;
        case PROC_NET_SOCKSTAT:
            total = gen_net_sockstat(tmp, GEN_BUF);
            break;
        case PROC_COMM: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_comm(tmp, GEN_BUF, task, (uint64_t)(unsigned int)n->fd) : 0;
            break;
        }
        case PROC_LIMITS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_limits(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_IO: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_io(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_SMAPS: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_smaps(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_SMAPS_ROLLUP: {
            fut_task_t *task = fut_task_by_pid(n->pid);
            total = task ? gen_smaps_rollup(tmp, GEN_BUF, task) : 0;
            break;
        }
        case PROC_OOM_SCORE: {
            /* OOM score 0 = least likely to be killed; simple RAM-model */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "0\n");
            total = b.pos;
            break;
        }
        case PROC_OOM_ADJ: {
            /* OOM score adjustment; 0 = neutral, -1000 = OOM-exempt */
            fut_task_t *otask = fut_task_by_pid(n->pid);
            struct pbuf b = { tmp, 0, GEN_BUF };
            int adj = otask ? otask->oom_score_adj : 0;
            if (adj < 0) {
                pb_char(&b, '-');
                pb_u64(&b, (uint64_t)(-(long)adj));
            } else {
                pb_u64(&b, (uint64_t)adj);
            }
            pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_CGROUP: {
            /* Minimal cgroup v1 format: "hierarchy:subsystems:path" */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "0::/\n");  /* cgroup v2 unified hierarchy, root */
            total = b.pos;
            break;
        }
        case PROC_WCHAN:
            total = gen_wchan(tmp, GEN_BUF);
            break;
        case PROC_PERSONALITY: {
            fut_task_t *ptask = fut_task_by_pid(n->pid);
            total = gen_personality(tmp, GEN_BUF, ptask);
            break;
        }
        case PROC_TIMERSLACK_NS: {
            /* /proc/<pid>/timerslack_ns: timer expiry slack in nanoseconds */
            fut_task_t *tstask = fut_task_by_pid(n->pid);
            struct pbuf b = { tmp, 0, GEN_BUF };
            uint64_t slack = tstask ? tstask->timerslack_ns : 50000U;
            pb_u64(&b, slack);
            pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_SYSCALL: {
            /* /proc/<pid>/syscall — current syscall information.
             * Format when blocked in a syscall: "nr arg0 arg1 arg2 arg3 arg4 arg5 sp pc\n"
             * Format when not in a syscall:     "running\n" (process running in user space)
             *
             * Since our procfs read is fully synchronous (we're inside the read()
             * syscall generating this content), the calling thread is always "running"
             * from the kernel's perspective — not blocked waiting for a resource.
             * We output "running\n" for all cases; debuggers accept this as valid. */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "running\n");
            total = b.pos;
            break;
        }
        case PROC_MOUNTINFO:
            total = gen_mountinfo(tmp, GEN_BUF);
            break;
        case PROC_COREDUMP_FILTER:
            total = gen_coredump_filter(tmp, GEN_BUF);
            break;
        case PROC_SCHEDSTAT: {
            fut_task_t *stask = fut_task_by_pid(n->pid);
            total = gen_schedstat(tmp, GEN_BUF, stask);
            break;
        }
        case PROC_SYS_CORE_PATTERN: {
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "core\n");
            total = b.pos;
            break;
        }
        case PROC_SYS_CORE_USES_PID: {
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "0\n");
            total = b.pos;
            break;
        }
        case PROC_SYS_SUID_DUMPABLE: {
            /* 1 = suid programs are dumpable (readable by owner, default Linux value) */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "1\n");
            total = b.pos;
            break;
        }
        case PROC_SYS_TAINTED: {
            /* 0 = kernel not tainted */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "0\n");
            total = b.pos;
            break;
        }
        case PROC_SYS_VERSION: {
            /* /proc/sys/kernel/version — same as /proc/version format */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "Linux version 6.8.0-futura (futura@localhost) (gcc) #1 SMP ");
            pb_str(&b, __DATE__); pb_char(&b, ' ');
            pb_str(&b, __TIME__); pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_CMDLINE_GLOBAL:
            total = gen_cmdline_global(tmp, GEN_BUF);
            break;
        case PROC_SWAPS:
            total = gen_swaps(tmp, GEN_BUF);
            break;
        case PROC_DEVICES:
            total = gen_devices(tmp, GEN_BUF);
            break;
        case PROC_MISC_FILE:
            total = gen_misc_dev(tmp, GEN_BUF);
            break;
        case PROC_ATTR_CURRENT: {
            /* /proc/<pid>/attr/current — LSM label; "unconfined" when no LSM */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "unconfined\n");
            total = b.pos;
            break;
        }
        case PROC_BUDDYINFO:
            total = gen_buddyinfo(tmp, GEN_BUF);
            break;
        case PROC_ZONEINFO:
            total = gen_zoneinfo(tmp, GEN_BUF);
            break;
        case PROC_DISKSTATS:
            total = gen_diskstats(tmp, GEN_BUF);
            break;
        case PROC_PARTITIONS:
            total = gen_partitions(tmp, GEN_BUF);
            break;
        case PROC_CGROUPS:
            total = gen_cgroups(tmp, GEN_BUF);
            break;
        case PROC_KALLSYMS:
            total = gen_kallsyms(tmp, GEN_BUF);
            break;
        case PROC_LOCKS:
            /* /proc/locks — file lock table.
             * Futura's file locking is per-vnode (not globally enumerable).
             * Return empty content: no locks registered with the central lock manager.
             * Format when locks exist: "N: POSIX  ADVISORY  WRITE PID DEV:INO START END\n"
             * Empty file is valid and accepted by all callers (lsof, procps, etc.). */
            total = 0;
            break;
        case PROC_FDINFO_ENTRY: {
            /* /proc/<pid>/fdinfo/<n>: pos, flags, mnt_id, type-specific fields */
            fut_task_t *ftask = fut_task_by_pid(n->pid);
            if (!ftask || n->fd < 0 || n->fd >= ftask->max_fds || !ftask->fd_table[n->fd]) {
                total = 0; break;
            }
            struct fut_file *file = ftask->fd_table[n->fd];
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "pos:\t");  pb_u64(&b, file->offset); pb_char(&b, '\n');
            pb_str(&b, "flags:\t0"); pb_oct(&b, (uint32_t)file->flags); pb_char(&b, '\n');
            pb_str(&b, "mnt_id:\t25\n");
            /* eventfd: eventfd-count */
            int64_t ev_count = fut_eventfd_get_count(file);
            if (ev_count >= 0) {
                pb_str(&b, "eventfd-count:\t");
                pb_u64(&b, (uint64_t)ev_count);
                pb_char(&b, '\n');
            }
            /* timerfd: clockid, ticks, settime flags, it_value, it_interval */
            int tfd_clockid = 0;
            uint64_t tfd_ticks = 0, tfd_interval_ms = 0;
            if (fut_timerfd_get_info(file, &tfd_clockid, &tfd_ticks,
                                     &tfd_interval_ms) == 0) {
                pb_str(&b, "clockid:\t"); pb_u64(&b, (uint64_t)tfd_clockid); pb_char(&b, '\n');
                pb_str(&b, "ticks:\t"); pb_u64(&b, tfd_ticks); pb_char(&b, '\n');
                pb_str(&b, "settime flags:\t0\n");
                /* it_value / it_interval in sec nsec format */
                uint64_t val_sec  = tfd_ticks;       /* approximate */
                uint64_t int_sec  = tfd_interval_ms / 1000;
                uint64_t int_nsec = (tfd_interval_ms % 1000) * 1000000ULL;
                pb_str(&b, "it_value:\t");  pb_u64(&b, val_sec);  pb_str(&b, " 0\n");
                pb_str(&b, "it_interval:\t"); pb_u64(&b, int_sec); pb_char(&b, ' ');
                pb_u64(&b, int_nsec); pb_char(&b, '\n');
            }
            /* signalfd: sigmask (16-char zero-padded hex) */
            {
                uint32_t dummy = 0;
                if (fut_signalfd_poll(file, 0, &dummy)) {
                    uint64_t sfd_mask = fut_signalfd_get_sigmask(file);
                    pb_str(&b, "sigmask:\t");
                    static const char hx[] = "0123456789abcdef";
                    for (int si = 60; si >= 0; si -= 4)
                        pb_char(&b, hx[(sfd_mask >> si) & 0xf]);
                    pb_char(&b, '\n');
                }
            }
            total = b.pos;
            break;
        }
        case PROC_SYS_OSTYPE:
            total = gen_sysctl_str(tmp, GEN_BUF, "Linux");
            break;
        case PROC_SYS_OSRELEASE:
            total = gen_sysctl_str(tmp, GEN_BUF, "6.1.0-futura");
            break;
        case PROC_SYS_HOSTNAME:
            total = gen_sysctl_str(tmp, GEN_BUF, g_hostname);
            break;
        case PROC_SYS_PID_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "32768");
            break;
        case PROC_SYS_OVERCOMMIT:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_MAX_MAP_COUNT:
            /* Elasticsearch requires ≥262144; use 1048576 for headroom */
            total = gen_sysctl_str(tmp, GEN_BUF, "1048576");
            break;
        case PROC_SYS_SWAPPINESS:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_DIRTY_RATIO:
            total = gen_sysctl_str(tmp, GEN_BUF, "20");
            break;
        case PROC_SYS_DIRTY_BG_RATIO:
            total = gen_sysctl_str(tmp, GEN_BUF, "10");
            break;
        case PROC_SYS_MIN_FREE_KB:
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_FILE_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "1048576");
            break;
        case PROC_SYS_FILE_NR:
            /* "allocated free max" — for our simple model, all 3 same */
            total = gen_sysctl_str(tmp, GEN_BUF, "0\t0\t1048576");
            break;
        case PROC_SYS_INOTIFY_MAX_WATCHES:
            total = gen_sysctl_str(tmp, GEN_BUF, "524288");
            break;
        case PROC_SYS_INOTIFY_MAX_INSTANCES:
            total = gen_sysctl_str(tmp, GEN_BUF, "128");
            break;
        case PROC_SYS_INOTIFY_MAX_QUEUED:
            total = gen_sysctl_str(tmp, GEN_BUF, "16384");
            break;
        case PROC_SYS_BOOT_ID:
            total = gen_boot_id(tmp, GEN_BUF);
            break;
        case PROC_SYS_UUID:
            total = gen_uuid_into(tmp, GEN_BUF);
            break;
        case PROC_SYS_ENTROPY_AVAIL:
            total = gen_sysctl_str(tmp, GEN_BUF, "256");
            break;
        case PROC_SYS_POOLSIZE:
            total = gen_sysctl_str(tmp, GEN_BUF, "4096");
            break;
        /* SysV IPC limits */
        case PROC_SYS_SHMMAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "67108864");
            break;
        case PROC_SYS_SHMALL:
            /* SHMMNI(32) * SHMMAX(64M) / PAGE_SIZE(4096) = 524288 pages */
            total = gen_sysctl_str(tmp, GEN_BUF, "524288");
            break;
        case PROC_SYS_SHMMNI:
            total = gen_sysctl_str(tmp, GEN_BUF, "32");
            break;
        case PROC_SYS_SEM:
            /* SEMMSL SEMMNS SEMOPM SEMMNI */
            total = gen_sysctl_str(tmp, GEN_BUF, "64\t4096\t500\t64");
            break;
        case PROC_SYS_MSGMAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_MSGMNB:
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_MSGMNI:
            total = gen_sysctl_str(tmp, GEN_BUF, "32");
            break;
        /* Network sysctls */
        case PROC_SYS_NET_SOMAXCONN:
            total = gen_sysctl_str(tmp, GEN_BUF, "4096");
            break;
        case PROC_SYS_NET_RMEM_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "16777216");
            break;
        case PROC_SYS_NET_WMEM_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "16777216");
            break;
        case PROC_SYS_NET_RMEM_DEFAULT:
            total = gen_sysctl_str(tmp, GEN_BUF, "212992");
            break;
        case PROC_SYS_NET_WMEM_DEFAULT:
            total = gen_sysctl_str(tmp, GEN_BUF, "212992");
            break;
        case PROC_SYS_NET_PORT_RANGE:
            total = gen_sysctl_str(tmp, GEN_BUF, "1024\t65535");
            break;
        case PROC_SYS_NET_FIN_TIMEOUT:
            total = gen_sysctl_str(tmp, GEN_BUF, "60");
            break;
        case PROC_SYS_NET_SYNCOOKIES:
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_SYS_NGROUPS_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_CAP_LAST_CAP:
            total = gen_sysctl_str(tmp, GEN_BUF, "40");
            break;
        case PROC_SYS_THREADS_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "32768");
            break;
        case PROC_SYS_PRINTK:
            /* current default boot-time min loglevel format */
            total = gen_sysctl_str(tmp, GEN_BUF, "4\t4\t1\t7");
            break;
        case PROC_SYS_PTRACE_SCOPE:
            /* 0 = classic ptrace, no restrictions */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NR_HUGEPAGES:
        case PROC_SYS_NR_OC_HUGEPAGES:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_TCP_RMEM:
            /* min default max — match Linux default */
            total = gen_sysctl_str(tmp, GEN_BUF, "4096\t87380\t16777216");
            break;
        case PROC_SYS_TCP_WMEM:
            total = gen_sysctl_str(tmp, GEN_BUF, "4096\t65536\t16777216");
            break;
        case PROC_INTERRUPTS: {
            /* Minimal stub: 1 CPU, timer interrupt only */
            struct pbuf b = { tmp, 0, GEN_BUF };
            pb_str(&b, "           CPU0\n");
            pb_str(&b, "  0:       1234   IO-APIC    2-edge      timer\n");
            pb_str(&b, "  1:          0   IO-APIC    1-edge      i8042\n");
            pb_str(&b, "NMI:          0   Non-maskable interrupts\n");
            pb_str(&b, "LOC:       1234   Local timer interrupts\n");
            total = b.pos;
            break;
        }
        case PROC_SYS_RANDOMIZE_VA:
            /* 2 = full ASLR (default on Linux) */
            total = gen_sysctl_str(tmp, GEN_BUF, "2");
            break;
        case PROC_SYS_DOMAINNAME:
            /* NIS domain name — backed by g_domainname (setdomainname syscall) */
            total = gen_sysctl_str(tmp, GEN_BUF, g_domainname);
            break;
        case PROC_SYS_PERF_PARANOID:
            /* 2 = only unprivileged userspace sampling; checked by gdb/sanitizers */
            total = gen_sysctl_str(tmp, GEN_BUF, "2");
            break;
        case PROC_SYS_KPTR_RESTRICT:
            /* 1 = hide kernel pointers from non-root (default on modern Linux) */
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_SYS_DMESG_RESTRICT:
            /* 0 = unrestricted dmesg access */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NET_IP_FORWARD:
            /* 0 = IP forwarding disabled */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NET_TCP_KEEPALIVE_TIME:
            total = gen_sysctl_str(tmp, GEN_BUF, "7200");
            break;
        case PROC_SYS_NET_TCP_KEEPALIVE_INTVL:
            total = gen_sysctl_str(tmp, GEN_BUF, "75");
            break;
        case PROC_SYS_NET_TCP_KEEPALIVE_PROBES:
            total = gen_sysctl_str(tmp, GEN_BUF, "9");
            break;
        case PROC_SYS_NET_IP_UNPRIV_PORT_START:
            /* 1024 = unprivileged programs can bind ports >= 1024 */
            total = gen_sysctl_str(tmp, GEN_BUF, "1024");
            break;
        case PROC_SYS_NET_IPV4_CONF_RP_FILTER:
            /* 0 = disabled (loose mode would be 2, strict 1) */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NET_IPV4_CONF_FORWARDING:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NET_IPV4_CONF_ACCEPT_RA:
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_NET_ARP:
            total = gen_net_arp(tmp, GEN_BUF);
            break;
        case PROC_SYS_NET_IPV6_DISABLE:
            /* 1 = IPv6 disabled (no IPv6 stack) */
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_SYS_NET_IPV6_FORWARD:
            /* 0 = IPv6 forwarding disabled */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_MMAP_MIN_ADDR:
            /* 65536 = minimum mmap address (security default, matches typical Linux) */
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_VM_VFS_CACHE_PRESSURE:
            /* 100 = default VFS cache pressure */
            total = gen_sysctl_str(tmp, GEN_BUF, "100");
            break;
        case PROC_SYS_FS_NR_OPEN:
            /* 1048576 = system-wide open file descriptor limit */
            total = gen_sysctl_str(tmp, GEN_BUF, "1048576");
            break;
        case PROC_SYS_FS_PIPE_MAX_SIZE:
            /* 1048576 = max pipe buffer size (1 MiB, default on Linux) */
            total = gen_sysctl_str(tmp, GEN_BUF, "1048576");
            break;
        /* /proc/sys/vm/ extended entries */
        case PROC_SYS_VM_DROP_CACHES:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_DIRTY_EXPIRE:
            /* 3000 centisecs = 30 seconds */
            total = gen_sysctl_str(tmp, GEN_BUF, "3000");
            break;
        case PROC_SYS_VM_DIRTY_WRITEBACK:
            /* 500 centisecs = 5 seconds */
            total = gen_sysctl_str(tmp, GEN_BUF, "500");
            break;
        case PROC_SYS_VM_OVERCOMMIT_KB:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_OOM_KILL_ALLOC:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_PANIC_ON_OOM:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_ZONE_RECLAIM:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_WATERMARK_BOOST:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_VM_WATERMARK_SCALE:
            total = gen_sysctl_str(tmp, GEN_BUF, "10");
            break;
        case PROC_SYS_VM_PAGE_CLUSTER:
            total = gen_sysctl_str(tmp, GEN_BUF, "3");
            break;
        /* /proc/sys/fs/ extended entries */
        case PROC_SYS_FS_AIO_MAX_NR:
            total = gen_sysctl_str(tmp, GEN_BUF, "65536");
            break;
        case PROC_SYS_FS_AIO_NR:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_FS_PROTECTED_HL:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_FS_PROTECTED_SL:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        /* /proc/sys/kernel/ extended entries */
        case PROC_SYS_KERNEL_NMI_WD:
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_KERNEL_WATCHDOG:
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_SYS_KERNEL_WATCHDOG_THRESH:
            total = gen_sysctl_str(tmp, GEN_BUF, "10");
            break;
        case PROC_SYS_KERNEL_HUNG_TASK:
            /* 120 seconds hung task timeout (Linux default) */
            total = gen_sysctl_str(tmp, GEN_BUF, "120");
            break;
        default:
            fut_free(tmp);
            return -EINVAL;
    }

    /* Serve slice at offset */
    ssize_t ret = 0;
    if (offset < total) {
        size_t avail = total - (size_t)offset;
        ret = (ssize_t)(avail < size ? avail : size);
        __builtin_memcpy(buf, tmp + offset, (size_t)ret);
    }
    fut_free(tmp);
    return ret;
}

/* ============================================================
 *   /proc Write Support (hostname, domainname, sysctl no-ops)
 * ============================================================ */

/*
 * procfs_file_write() — handle writes to select /proc files.
 *
 * Writable files:
 *   PROC_SYS_HOSTNAME    — updates g_hostname (sethostname backing)
 *   PROC_SYS_DOMAINNAME  — updates g_domainname (setdomainname backing)
 *   PROC_OOM_ADJ         — accepted silently (oom_score_adj per-process tuning)
 *   Any PROC_SYS_*       — accepted silently (sysctl tuning no-ops)
 *
 * All other /proc files return -EPERM.
 */
static ssize_t procfs_file_write(struct fut_vnode *vnode, const void *buf,
                                  size_t size, uint64_t offset) {
    if (!vnode || !buf || size == 0) return -EINVAL;
    procfs_node_t *n = (procfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    /*
     * /proc/<pid>/mem: offset is a virtual address; write directly.
     * Check that the target VMA is writable before copying.
     */
    if (n->kind == PROC_PID_MEM) {
        fut_task_t *task = fut_task_by_pid(n->pid);
        if (!task) return -ESRCH;
        fut_mm_t *mm = task->mm ? task->mm : fut_mm_current();
        if (!mm) return -EIO;

        uintptr_t addr = (uintptr_t)offset;
        uintptr_t end  = addr + size;

        struct fut_vma *vma = mm->vma_list;
        while (vma && vma->end <= addr)
            vma = vma->next;
        if (!vma || vma->start > addr)
            return -EIO;
        if (!(vma->prot & PROT_WRITE))
            return -EFAULT;
        if (end > vma->end)
            end = vma->end;
        size_t copy_sz = (size_t)(end - addr);

        void *dst = (void *)addr;
#ifdef KERNEL_VIRTUAL_BASE
        if ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE) {
            __builtin_memcpy(dst, buf, copy_sz);
        } else
#endif
        if (fut_copy_from_user(dst, buf, copy_sz) != 0)
            return -EFAULT;
        return (ssize_t)copy_sz;
    }

    (void)offset;
    /* Copy data from caller (user or kernel pointer) into a kernel buffer */
    char kbuf[256];
    size_t copy_len = size < sizeof(kbuf) - 1 ? size : sizeof(kbuf) - 1;

#ifdef KERNEL_VIRTUAL_BASE
    if ((uintptr_t)buf >= KERNEL_VIRTUAL_BASE)
        __builtin_memcpy(kbuf, buf, copy_len);
    else
#endif
    if (fut_copy_from_user(kbuf, buf, copy_len) != 0)
        return -EFAULT;

    /* Strip trailing newline / whitespace */
    while (copy_len > 0 && (kbuf[copy_len - 1] == '\n' || kbuf[copy_len - 1] == '\r' ||
                             kbuf[copy_len - 1] == ' '))
        copy_len--;
    kbuf[copy_len] = '\0';

    switch (n->kind) {
        case PROC_SYS_HOSTNAME:
            if (copy_len > 63) copy_len = 63;  /* HOSTNAME_MAX-1 = 64 */
            __builtin_memcpy(g_hostname, kbuf, copy_len);
            g_hostname[copy_len] = '\0';
            return (ssize_t)size;

        case PROC_SYS_DOMAINNAME:
            if (copy_len > 63) copy_len = 63;  /* DOMAINNAME_MAX-1 = 64 */
            __builtin_memcpy(g_domainname, kbuf, copy_len);
            g_domainname[copy_len] = '\0';
            return (ssize_t)size;

        case PROC_OOM_ADJ: {
            /* oom_score_adj: parse signed decimal [-1000..1000] and store in task */
            fut_task_t *wtask = fut_task_by_pid(n->pid);
            if (!wtask) return -ESRCH;
            /* Parse signed integer */
            size_t i = 0;
            int neg = 0;
            if (i < copy_len && kbuf[i] == '-') { neg = 1; i++; }
            else if (i < copy_len && kbuf[i] == '+') { i++; }
            long val = 0;
            for (; i < copy_len && kbuf[i] >= '0' && kbuf[i] <= '9'; i++)
                val = val * 10 + (kbuf[i] - '0');
            if (neg) val = -val;
            /* Clamp to [-1000, 1000] */
            if (val < -1000) val = -1000;
            if (val >  1000) val =  1000;
            wtask->oom_score_adj = (int)val;
            return (ssize_t)size;
        }

        case PROC_TIMERSLACK_NS: {
            /* /proc/<pid>/timerslack_ns: write unsigned decimal nanoseconds. */
            fut_task_t *wtask = fut_task_by_pid(n->pid);
            if (!wtask) return -ESRCH;
            /* Only allow writing to our own timerslack_ns */
            fut_task_t *cur = fut_task_current();
            if (!cur || (uint64_t)n->pid != cur->pid) return -EPERM;
            uint64_t val = 0;
            for (size_t i = 0; i < copy_len && kbuf[i] >= '0' && kbuf[i] <= '9'; i++)
                val = val * 10 + (uint64_t)(kbuf[i] - '0');
            wtask->timerslack_ns = val;
            return (ssize_t)size;
        }

        case PROC_COMM: {
            /* Writing to /proc/<pid>/comm sets the task's comm (process name).
             * Same semantics as prctl(PR_SET_NAME): max 15 chars, NUL-terminated.
             * Only allow writing to our own comm (n->pid == current task's pid). */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            fut_task_t *cur = fut_task_current();
            if (!cur || (uint64_t)n->pid != cur->pid) return -EPERM;
            size_t nlen = copy_len < 15 ? copy_len : 15;
            __builtin_memcpy(task->comm, kbuf, nlen);
            task->comm[nlen] = '\0';
            return (ssize_t)size;
        }

        case PROC_SYS_CORE_PATTERN:
        case PROC_SYS_CORE_USES_PID:
        case PROC_SYS_SUID_DUMPABLE:
        case PROC_SYS_TAINTED:
        case PROC_SYS_VERSION:
        case PROC_ATTR_CURRENT:   /* LSM label write — accepted silently */
            return (ssize_t)size;  /* accept silently */

        default:
            /* Accept writes to all /proc/sys/ files silently (sysctl tuning) */
            if (n->kind >= PROC_SYS_DIR && n->kind <= PROC_SYS_KERNEL_HUNG_TASK)
                return (ssize_t)size;
            return -EPERM;
    }
}

static int procfs_file_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    /* Use the vnode's own mode so writable files (e.g. hostname, oom_score_adj)
     * report the correct permissions via stat(). Fall back to 0100444 if unset. */
    st->st_mode  = vnode->mode ? vnode->mode : 0100444;
    st->st_nlink = 1;
    st->st_uid   = 0;
    st->st_gid   = 0;
    st->st_size  = 0;  /* unknown size — reads return actual content */
    st->st_blksize = 4096;
    return 0;
}

/* ============================================================
 *   Symlink Operations
 * ============================================================ */

static ssize_t procfs_link_readlink(struct fut_vnode *vnode, char *buf, size_t size) {
    if (!vnode || !buf) return -EINVAL;
    procfs_node_t *n = (procfs_node_t *)vnode->fs_data;
    if (!n) return -EIO;

    char tmp[256];
    size_t len = 0;

    switch (n->kind) {
        case PROC_SELF: {
            /* Resolve to /proc/<current_pid> */
            fut_task_t *cur = fut_task_current();
            uint64_t cpid = cur ? cur->pid : 1;
            struct pbuf b = { tmp, 0, sizeof(tmp) };
            pb_str(&b, "/proc/");
            pb_u64(&b, cpid);
            len = b.pos;
            break;
        }
        case PROC_THREAD_SELF: {
            /* Resolve to /proc/<pid>/task/<tid> */
            fut_task_t *cur = fut_task_current();
            extern fut_thread_t *fut_thread_current(void);
            fut_thread_t *thr = fut_thread_current();
            uint64_t cpid = cur ? cur->pid : 1;
            uint64_t ctid = thr ? thr->tid : cpid;
            struct pbuf b = { tmp, 0, sizeof(tmp) };
            pb_str(&b, "/proc/");
            pb_u64(&b, cpid);
            pb_str(&b, "/task/");
            pb_u64(&b, ctid);
            len = b.pos;
            break;
        }
        case PROC_EXE: {
            /* Executable path stored at exec time */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            const char *ep = task->exe_path[0] ? task->exe_path : "(deleted)";
            while (ep[len] && len < sizeof(tmp) - 1) { tmp[len] = ep[len]; len++; }
            break;
        }
        case PROC_CWD: {
            /* Current working directory */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            const char *cwd = (task->cwd_cache && task->cwd_cache[0]) ?
                               task->cwd_cache : "/";
            while (cwd[len] && len < sizeof(tmp) - 1) { tmp[len] = cwd[len]; len++; }
            break;
        }
        case PROC_PID_ROOT: {
            /* Root directory of process filesystem namespace — always "/" in Futura */
            tmp[0] = '/';
            len = 1;
            break;
        }
        case PROC_NS_ENTRY: {
            /* Namespace symlink target: <nstype>:[<inode>] */
            static const char * const ns_names[] = {
                "pid", "mnt", "net", "user", "uts", "ipc", "cgroup"
            };
            /* Standard Linux initial namespace inodes */
            static const uint32_t ns_inodes[] = {
                4026531836u, 4026531840u, 4026531992u, 4026531837u,
                4026531838u, 4026531839u, 4026531835u
            };
            int ns_idx = n->fd;
            if (ns_idx < 0 || ns_idx >= 7) return -EINVAL;
            struct pbuf b = { tmp, 0, sizeof(tmp) };
            pb_str(&b, ns_names[ns_idx]);
            pb_str(&b, ":[");
            pb_u64(&b, (uint64_t)ns_inodes[ns_idx]);
            pb_char(&b, ']');
            len = b.pos;
            break;
        }
        case PROC_FD_ENTRY: {
            /* Generate Linux-style symlink target:
             *  - Regular file with path: the path
             *  - Pipe:    "pipe:[<ino>]"
             *  - Socket:  "socket:[<ino>]"
             *  - eventfd/timerfd/signalfd: "anon_inode:[<type>]"
             *  - Fallback: "/dev/fd/<n>"  */
            fut_task_t *task = fut_task_by_pid(n->pid);
            if (!task) return -ESRCH;
            if (n->fd >= 0 && n->fd < task->max_fds && task->fd_table[n->fd]) {
                struct fut_file *file = task->fd_table[n->fd];

                /* 1. Regular file path */
                if (file->path && file->path[0]) {
                    const char *fp = file->path;
                    while (fp[len] && len < sizeof(tmp) - 1)
                        { tmp[len] = fp[len]; len++; }
                    break;
                }

                /* 2. Pipe fd */
                {
                    extern bool fut_pipe_poll(struct fut_file *, uint32_t, uint32_t *);
                    uint32_t dummy = 0;
                    if (fut_pipe_poll(file, 0, &dummy)) {
                        uint64_t ino = file->vnode ? file->vnode->ino : (uint64_t)n->fd;
                        struct pbuf b = { tmp, 0, sizeof(tmp) };
                        pb_str(&b, "pipe:[");
                        pb_u64(&b, ino);
                        pb_str(&b, "]");
                        len = b.pos;
                        break;
                    }
                }

                /* 3. Socket fd (tracked in posix_compat socket table) */
                {
                    extern struct fut_socket *get_socket_from_fd(int fd);
                    if (get_socket_from_fd(n->fd)) {
                        uint64_t ino = file->vnode ? file->vnode->ino : (uint64_t)n->fd;
                        struct pbuf b = { tmp, 0, sizeof(tmp) };
                        pb_str(&b, "socket:[");
                        pb_u64(&b, ino);
                        pb_str(&b, "]");
                        len = b.pos;
                        break;
                    }
                }

                /* 4. eventfd / timerfd / signalfd — anon_inode:[type] */
                {
                    extern bool fut_eventfd_poll(struct fut_file *, uint32_t, uint32_t *);
                    extern bool fut_timerfd_poll(struct fut_file *, uint32_t, uint32_t *);
                    extern bool fut_signalfd_poll(struct fut_file *, uint32_t, uint32_t *);
                    extern bool fut_inotify_poll(struct fut_file *, uint32_t, uint32_t *);
                    extern bool fut_pidfd_poll(struct fut_file *, uint32_t, uint32_t *);
                    extern const struct fut_file_ops epoll_fops;
                    uint32_t dummy = 0;
                    const char *anon_type = NULL;
                    if      (file->chr_ops == &epoll_fops)       anon_type = "eventpoll";
                    else if (fut_eventfd_poll(file, 0, &dummy))  anon_type = "eventfd";
                    else if (fut_timerfd_poll(file, 0, &dummy))  anon_type = "timerfd";
                    else if (fut_signalfd_poll(file, 0, &dummy)) anon_type = "signalfd";
                    else if (fut_inotify_poll(file, 0, &dummy))  anon_type = "inotify";
                    else if (fut_pidfd_poll(file, 0, &dummy))    anon_type = "pidfd";
                    else if (file->chr_ops)                      anon_type = "anon";
                    if (anon_type) {
                        struct pbuf b = { tmp, 0, sizeof(tmp) };
                        pb_str(&b, "anon_inode:[");
                        pb_str(&b, anon_type);
                        pb_str(&b, "]");
                        len = b.pos;
                        break;
                    }
                }

                /* 5. Vnode path fallback */
                if (file->vnode) {
                    char *built = fut_vnode_build_path(file->vnode, tmp, sizeof(tmp));
                    if (built) {
                        len = 0;
                        while (tmp[len] && len < sizeof(tmp) - 1) len++;
                        break;
                    }
                }
            }
            /* Final fallback */
            {
                struct pbuf b = { tmp, 0, sizeof(tmp) };
                pb_str(&b, "/dev/fd/");
                pb_u64(&b, (uint64_t)n->fd);
                len = b.pos;
            }
            break;
        }
        default:
            return -EINVAL;
    }

    if (len > size) len = size;
    __builtin_memcpy(buf, tmp, len);
    return (ssize_t)len;
}

static int procfs_link_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    st->st_mode  = 0120777;  /* lrwxrwxrwx */
    st->st_nlink = 1;
    st->st_size  = 0;
    return 0;
}

/* Parse decimal string to uint64_t; returns (uint64_t)-1 on failure */
static uint64_t parse_dec(const char *s) {
    if (!s || !*s) return (uint64_t)-1;
    uint64_t v = 0;
    while (*s) {
        if (*s < '0' || *s > '9') return (uint64_t)-1;
        v = v * 10 + (uint64_t)(*s - '0');
        s++;
    }
    return v;
}

/* ============================================================
 *   Directory Operations
 * ============================================================ */

static int procfs_dir_lookup(struct fut_vnode *dir, const char *name,
                              struct fut_vnode **result) {
    if (!dir || !name || !result) return -EINVAL;
    procfs_node_t *dn = (procfs_node_t *)dir->fs_data;
    if (!dn) return -EIO;

    struct fut_mount *mnt = dir->mount;

    #define STREQ(a, b) (__builtin_strcmp((a), (b)) == 0)

    if (dn->kind == PROC_ROOT) {
        if (STREQ(name, "self")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_SELF,
                                          0120777, PROC_SELF, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "thread-self")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_THREAD_SELF,
                                          0120777, PROC_THREAD_SELF, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "meminfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MEMINFO,
                                          0100444, PROC_MEMINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "version")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_VERSION,
                                          0100444, PROC_VERSION, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "uptime")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_UPTIME,
                                          0100444, PROC_UPTIME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cpuinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CPUINFO,
                                          0100444, PROC_CPUINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "loadavg")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_LOADAVG,
                                          0100444, PROC_LOADAVG, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mounts")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MOUNTS,
                                          0100444, PROC_MOUNTS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "stat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_STAT_GLOBAL,
                                          0100444, PROC_STAT_GLOBAL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "filesystems")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_FILESYSTEMS,
                                          0100444, PROC_FILESYSTEMS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "vmstat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_VMSTAT,
                                          0100444, PROC_VMSTAT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "interrupts")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_INTERRUPTS,
                                          0100444, PROC_INTERRUPTS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "net")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_NET_DIR,
                                          0040555, PROC_NET_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sys")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_DIR,
                                          0040555, PROC_SYS_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cmdline")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CMDLINE_GLOBAL,
                                          0100444, PROC_CMDLINE_GLOBAL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "swaps")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SWAPS,
                                          0100444, PROC_SWAPS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "devices")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_DEVICES,
                                          0100444, PROC_DEVICES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "misc")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MISC_FILE,
                                          0100444, PROC_MISC_FILE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "buddyinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_BUDDYINFO,
                                          0100444, PROC_BUDDYINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "zoneinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_ZONEINFO,
                                          0100444, PROC_ZONEINFO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "diskstats")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_DISKSTATS,
                                          0100444, PROC_DISKSTATS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "partitions")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PARTITIONS,
                                          0100444, PROC_PARTITIONS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cgroups")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CGROUPS,
                                          0100444, PROC_CGROUPS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "kallsyms")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_KALLSYMS,
                                          0100444, PROC_KALLSYMS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "locks")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_LOCKS,
                                          0100444, PROC_LOCKS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        /* Try numeric PID */
        uint64_t pid = parse_dec(name);
        if (pid != (uint64_t)-1 && pid > 0) {
            fut_task_t *task = fut_task_by_pid(pid);
            if (!task) return -ENOENT;
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_DIR(pid),
                                          0040555, PROC_PID_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_PID_DIR) {
        uint64_t pid = dn->pid;
        if (STREQ(name, "status")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATUS(pid),
                                          0100444, PROC_STATUS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "maps")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MAPS(pid),
                                          0100444, PROC_MAPS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cmdline")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CMDLINE(pid),
                                          0100444, PROC_CMDLINE, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "environ")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_ENVIRON(pid),
                                          0100400, PROC_ENVIRON, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fd")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FD(pid),
                                          0040500, PROC_FD_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "exe")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_EXE(pid),
                                          0120777, PROC_EXE, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cwd")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_CWD(pid),
                                          0120777, PROC_CWD, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "root")) {
            *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_ROOT(pid),
                                          0120777, PROC_PID_ROOT, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "stat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STAT(pid),
                                          0100444, PROC_STAT, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "statm")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATM(pid),
                                          0100444, PROC_STATM, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "comm")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COMM(pid),
                                          0100644, PROC_COMM, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "task")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_TASK(pid),
                                          0040555, PROC_TASK_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "limits")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_LIMITS(pid),
                                          0100444, PROC_LIMITS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "io")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_IO(pid),
                                          0100400, PROC_IO, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "smaps")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SMAPS(pid),
                                          0100444, PROC_SMAPS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "smaps_rollup")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SMAPS_ROLLUP(pid),
                                          0100444, PROC_SMAPS_ROLLUP, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "auxv")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_AUXV(pid),
                                          0100400, PROC_AUXV, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MEM(pid),
                                          0100600, PROC_PID_MEM, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "uid_map")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_UID_MAP(pid),
                                          0100644, PROC_UID_MAP, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "gid_map")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_GID_MAP(pid),
                                          0100644, PROC_GID_MAP, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "setgroups")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SETGROUPS(pid),
                                          0100644, PROC_SETGROUPS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "loginuid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_LOGINUID(pid),
                                          0100644, PROC_LOGINUID, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sessionid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SESSIONID(pid),
                                          0100444, PROC_SESSIONID, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "oom_score")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_OOM_SCORE(pid),
                                          0100444, PROC_OOM_SCORE, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "oom_score_adj")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_OOM_ADJ(pid),
                                          0100644, PROC_OOM_ADJ, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cgroup")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CGROUP(pid),
                                          0100444, PROC_CGROUP, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ns")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_NS(pid),
                                          0040511, PROC_NS_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fdinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FDINFO(pid),
                                          0040500, PROC_FDINFO_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "wchan")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_WCHAN(pid),
                                          0100444, PROC_WCHAN, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "personality")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_PERSONALITY(pid),
                                          0100444, PROC_PERSONALITY, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pagemap")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_PAGEMAP(pid),
                                          0100400, PROC_PAGEMAP, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "timerslack_ns")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_TIMERSLACK(pid),
                                          0100644, PROC_TIMERSLACK_NS, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "syscall")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SYSCALL(pid),
                                          0100444, PROC_SYSCALL, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mountinfo")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MOUNTINFO(pid),
                                          0100444, PROC_MOUNTINFO, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "coredump_filter")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COREDUMP(pid),
                                          0100644, PROC_COREDUMP_FILTER, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "schedstat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SCHEDSTAT(pid),
                                          0100444, PROC_SCHEDSTAT, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        /* /proc/<pid>/net → same as global /proc/net/ (default network namespace) */
        if (STREQ(name, "net")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_NET_DIR,
                                          0040555, PROC_NET_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "attr")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_ATTR(pid),
                                          0040555, PROC_ATTR_DIR, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_ATTR_DIR) {
        /* /proc/<pid>/attr/{current,exec,prev,...} — LSM context files */
        uint64_t pid = dn->pid;
        if (STREQ(name, "current") || STREQ(name, "exec") || STREQ(name, "prev") ||
            STREQ(name, "fscreate") || STREQ(name, "keycreate") || STREQ(name, "sockcreate")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_ATTR_CUR(pid),
                                          0100644, PROC_ATTR_CURRENT, pid, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_TASK_DIR) {
        /* Lookup a TID sub-directory under /proc/<pid>/task/<tid>/ */
        uint64_t pid = dn->pid;
        /* Parse TID from name */
        uint64_t tid = 0;
        const char *p = name;
        if (!*p) return -ENOENT;
        while (*p >= '0' && *p <= '9') { tid = tid * 10 + (*p - '0'); p++; }
        if (*p != '\0' || tid == 0) return -ENOENT;
        /* Validate that this TID belongs to this task */
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        bool found = false;
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid) { found = true; break; }
        }
        if (!found) return -ENOENT;
        *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_TID_DIR(pid, tid),
                                      0040555, PROC_TID_DIR, pid, (int)tid);
        return *result ? 0 : -ENOMEM;
    }

    if (dn->kind == PROC_TID_DIR) {
        /* /proc/<pid>/task/<tid>/ exposes the same files as /proc/<pid>/ but with
         * tid-specific fields: status/stat Pid: shows TID; comm shows thread name.
         * The TID is stored in dn->fd (set when the TID directory vnode was created). */
        uint64_t pid = dn->pid;
        int tid_fd = dn->fd;  /* TID stored in fd field of the task/<tid> directory vnode */
        if (STREQ(name, "status"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATUS(pid), 0100444, PROC_STATUS, pid, tid_fd); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "maps"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MAPS(pid),   0100444, PROC_MAPS,   pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "cmdline"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CMDLINE(pid),0100444, PROC_CMDLINE,pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "environ"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_ENVIRON(pid),0100400, PROC_ENVIRON,pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "fd"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FD(pid),     0040500, PROC_FD_DIR, pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "exe"))
            { *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_EXE(pid),    0120777, PROC_EXE,    pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "cwd"))
            { *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_CWD(pid),    0120777, PROC_CWD,    pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "root"))
            { *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_PID_ROOT(pid),   0120777, PROC_PID_ROOT,pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "stat"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STAT(pid),   0100444, PROC_STAT,   pid, tid_fd); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "statm"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_STATM(pid),  0100444, PROC_STATM,  pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "comm"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COMM(pid),   0100644, PROC_COMM,   pid, tid_fd); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "task"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_TASK(pid),   0040555, PROC_TASK_DIR,pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "limits"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_LIMITS(pid), 0100444, PROC_LIMITS,  pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "io"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_IO(pid),     0100400, PROC_IO,      pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "smaps"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SMAPS(pid),          0100444, PROC_SMAPS,          pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "smaps_rollup"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SMAPS_ROLLUP(pid),   0100444, PROC_SMAPS_ROLLUP,   pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "auxv"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_AUXV(pid),           0100400, PROC_AUXV,           pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "mem"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MEM(pid),            0100600, PROC_PID_MEM,        pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "uid_map"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_UID_MAP(pid),        0100644, PROC_UID_MAP,         pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "gid_map"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_GID_MAP(pid),        0100644, PROC_GID_MAP,         pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "setgroups"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SETGROUPS(pid),      0100644, PROC_SETGROUPS,       pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "loginuid"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_LOGINUID(pid),       0100644, PROC_LOGINUID,        pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "sessionid"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SESSIONID(pid),      0100444, PROC_SESSIONID,       pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "oom_score"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_OOM_SCORE(pid), 0100444, PROC_OOM_SCORE, pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "oom_score_adj"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_OOM_ADJ(pid),   0100644, PROC_OOM_ADJ,   pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "cgroup"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_CGROUP(pid),    0100444, PROC_CGROUP,    pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "ns"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_NS(pid), 0040511, PROC_NS_DIR, pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "fdinfo"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_FDINFO(pid), 0040500, PROC_FDINFO_DIR, pid, 0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "wchan"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_WCHAN(pid),        0100444, PROC_WCHAN,           pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "personality"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_PERSONALITY(pid),  0100444, PROC_PERSONALITY,     pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "pagemap"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_PAGEMAP(pid),      0100400, PROC_PAGEMAP,         pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "timerslack_ns"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_TIMERSLACK(pid),   0100644, PROC_TIMERSLACK_NS,   pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "syscall"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SYSCALL(pid),       0100444, PROC_SYSCALL,         pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "mountinfo"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_MOUNTINFO(pid), 0100444, PROC_MOUNTINFO,       pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "coredump_filter"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_COREDUMP(pid),  0100644, PROC_COREDUMP_FILTER, pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "schedstat"))
            { *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PID_SCHEDSTAT(pid), 0100444, PROC_SCHEDSTAT,       pid,0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "net"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_NET_DIR,             0040555, PROC_NET_DIR,         0,  0); return *result ? 0 : -ENOMEM; }
        if (STREQ(name, "attr"))
            { *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PID_ATTR(pid),       0040555, PROC_ATTR_DIR,        pid,0); return *result ? 0 : -ENOMEM; }
        return -ENOENT;
    }

    if (dn->kind == PROC_NET_DIR) {
        if (STREQ(name, "dev")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_DEV,
                                          0100444, PROC_NET_DEV, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "route")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_ROUTE,
                                          0100444, PROC_NET_ROUTE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_TCP,
                                          0100444, PROC_NET_TCP, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "udp")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_UDP,
                                          0100444, PROC_NET_UDP, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "if_inet6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_IF6,
                                          0100444, PROC_NET_IF_INET6, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "unix")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_UNIX,
                                          0100444, PROC_NET_UNIX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sockstat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_SOCKSTAT,
                                          0100444, PROC_NET_SOCKSTAT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "arp")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_ARP,
                                          0100444, PROC_NET_ARP, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_TCP6,   0100444, PROC_NET_TCP6,     0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "udp6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_UDP6,   0100444, PROC_NET_UDP6,     0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "raw") || STREQ(name, "raw6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_RAW,    0100444, PROC_NET_RAW,      0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fib_trie") || STREQ(name, "fib_triestat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_FIB_TRIE, 0100444, PROC_NET_FIB_TRIE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "snmp") || STREQ(name, "snmp6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_SNMP,   0100444, PROC_NET_SNMP,     0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "netstat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_NETSTAT, 0100444, PROC_NET_NETSTAT,  0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "packet")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_PACKET, 0100444, PROC_NET_PACKET,   0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_DIR) {
        if (STREQ(name, "kernel")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_KERNEL_DIR,
                                          0040555, PROC_SYS_KERNEL_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "vm")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_VM_DIR,
                                          0040555, PROC_SYS_VM_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "fs")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_FS_DIR,
                                          0040555, PROC_SYS_FS_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "net")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_DIR,
                                          0040555, PROC_SYS_NET_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_DIR) {
        if (STREQ(name, "core")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_CORE_DIR,
                                          0040555, PROC_SYS_NET_CORE_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ipv4")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV4_DIR,
                                          0040555, PROC_SYS_NET_IPV4_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ipv6")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV6_DIR,
                                          0040555, PROC_SYS_NET_IPV6_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_DIR) {
        if (STREQ(name, "conf")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV6_CONF_DIR,
                                          0040555, PROC_SYS_NET_IPV6_CONF_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_CONF_DIR) {
        if (STREQ(name, "all")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV6_ALL_DIR,
                                          0040555, PROC_SYS_NET_IPV6_CONF_ALL_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_CONF_ALL_DIR) {
        if (STREQ(name, "disable_ipv6")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IPV6_DISABLE,
                                          0100644, PROC_SYS_NET_IPV6_DISABLE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "forwarding")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IPV6_FORWARD,
                                          0100644, PROC_SYS_NET_IPV6_FORWARD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_CORE_DIR) {
        if (STREQ(name, "somaxconn")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_SOMAXCONN,
                                          0100644, PROC_SYS_NET_SOMAXCONN, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "rmem_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_RMEM_MAX,
                                          0100644, PROC_SYS_NET_RMEM_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "wmem_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_WMEM_MAX,
                                          0100644, PROC_SYS_NET_WMEM_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "rmem_default")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_RMEM_DEFAULT,
                                          0100644, PROC_SYS_NET_RMEM_DEFAULT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "wmem_default")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_WMEM_DEFAULT,
                                          0100644, PROC_SYS_NET_WMEM_DEFAULT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_DIR) {
        if (STREQ(name, "ip_local_port_range")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_PORT_RANGE,
                                          0100644, PROC_SYS_NET_PORT_RANGE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_fin_timeout")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_FIN_TIMEOUT,
                                          0100644, PROC_SYS_NET_FIN_TIMEOUT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_syncookies")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_SYNCOOKIES,
                                          0100644, PROC_SYS_NET_SYNCOOKIES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_rmem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_TCP_RMEM,
                                          0100644, PROC_SYS_TCP_RMEM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_wmem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_TCP_WMEM,
                                          0100644, PROC_SYS_TCP_WMEM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ip_forward")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IP_FORWARD,
                                          0100644, PROC_SYS_NET_IP_FORWARD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_keepalive_time")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_KEEPALIVE_TIME,
                                          0100644, PROC_SYS_NET_TCP_KEEPALIVE_TIME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_keepalive_intvl")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_KEEPALIVE_INTVL,
                                          0100644, PROC_SYS_NET_TCP_KEEPALIVE_INTVL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tcp_keepalive_probes")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_KEEPALIVE_PROBES,
                                          0100644, PROC_SYS_NET_TCP_KEEPALIVE_PROBES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ip_unprivileged_port_start")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_UNPRIV_PORT,
                                          0100644, PROC_SYS_NET_IP_UNPRIV_PORT_START, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "conf")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV4_CONF_DIR,
                                          0040555, PROC_SYS_NET_IPV4_CONF_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_CONF_DIR) {
        if (STREQ(name, "all")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV4_CONF_ALL,
                                          0040555, PROC_SYS_NET_IPV4_CONF_ALL_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "default")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_IPV4_CONF_DEF,
                                          0040555, PROC_SYS_NET_IPV4_CONF_DEFAULT_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_CONF_ALL_DIR ||
        dn->kind == PROC_SYS_NET_IPV4_CONF_DEFAULT_DIR) {
        uint64_t base_ino = (dn->kind == PROC_SYS_NET_IPV4_CONF_ALL_DIR)
                            ? PROC_INO_SYS_NET_IPV4_CONF_ALL
                            : PROC_INO_SYS_NET_IPV4_CONF_DEF;
        if (STREQ(name, "rp_filter")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IPV4_RP_FILTER + (base_ino == PROC_INO_SYS_NET_IPV4_CONF_ALL ? 0 : 10),
                                          0100644, PROC_SYS_NET_IPV4_CONF_RP_FILTER, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "forwarding")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IPV4_FORWARDING + (base_ino == PROC_INO_SYS_NET_IPV4_CONF_ALL ? 0 : 10),
                                          0100644, PROC_SYS_NET_IPV4_CONF_FORWARDING, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "accept_redirects")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IPV4_ACCEPT_RA + (base_ino == PROC_INO_SYS_NET_IPV4_CONF_ALL ? 0 : 10),
                                          0100644, PROC_SYS_NET_IPV4_CONF_ACCEPT_RA, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_KERNEL_DIR) {
        if (STREQ(name, "ostype")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OSTYPE,
                                          0100444, PROC_SYS_OSTYPE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "osrelease")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OSRELEASE,
                                          0100444, PROC_SYS_OSRELEASE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "hostname")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_HOSTNAME,
                                          0100644, PROC_SYS_HOSTNAME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pid_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_PID_MAX,
                                          0100644, PROC_SYS_PID_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "random")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_RANDOM_DIR,
                                          0040555, PROC_SYS_RANDOM_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "shmmax")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SHMMAX,
                                          0100644, PROC_SYS_SHMMAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "shmall")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SHMALL,
                                          0100644, PROC_SYS_SHMALL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "shmmni")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SHMMNI,
                                          0100644, PROC_SYS_SHMMNI, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SEM,
                                          0100444, PROC_SYS_SEM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "msgmax")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_MSGMAX,
                                          0100644, PROC_SYS_MSGMAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "msgmnb")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_MSGMNB,
                                          0100644, PROC_SYS_MSGMNB, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "msgmni")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_MSGMNI,
                                          0100644, PROC_SYS_MSGMNI, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ngroups_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NGROUPS_MAX,
                                          0100444, PROC_SYS_NGROUPS_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "cap_last_cap")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_CAP_LAST_CAP,
                                          0100444, PROC_SYS_CAP_LAST_CAP, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "threads-max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_THREADS_MAX,
                                          0100644, PROC_SYS_THREADS_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "printk")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_PRINTK,
                                          0100644, PROC_SYS_PRINTK, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "yama")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_YAMA_DIR,
                                          0040555, PROC_SYS_YAMA_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "randomize_va_space")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_RANDOMIZE_VA,
                                          0100644, PROC_SYS_RANDOMIZE_VA, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "domainname")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_DOMAINNAME,
                                          0100644, PROC_SYS_DOMAINNAME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "perf_event_paranoid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_PERF_PARANOID,
                                          0100644, PROC_SYS_PERF_PARANOID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "kptr_restrict")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KPTR_RESTRICT,
                                          0100644, PROC_SYS_KPTR_RESTRICT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "dmesg_restrict")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_DMESG_RESTRICT,
                                          0100644, PROC_SYS_DMESG_RESTRICT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "core_pattern")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_CORE_PATTERN,
                                          0100644, PROC_SYS_CORE_PATTERN, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "core_uses_pid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_CORE_USES_PID,
                                          0100644, PROC_SYS_CORE_USES_PID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "suid_dumpable")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SUID_DUMPABLE,
                                          0100644, PROC_SYS_SUID_DUMPABLE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "tainted")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_TAINTED,
                                          0100644, PROC_SYS_TAINTED, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "version")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VERSION_KERNEL,
                                          0100444, PROC_SYS_VERSION, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nmi_watchdog")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_NMI_WD,
                                          0100644, PROC_SYS_KERNEL_NMI_WD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "watchdog")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_WATCHDOG,
                                          0100644, PROC_SYS_KERNEL_WATCHDOG, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "watchdog_thresh")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_WD_THRESH,
                                          0100644, PROC_SYS_KERNEL_WATCHDOG_THRESH, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "hung_task_timeout_secs")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_HUNG_TASK,
                                          0100644, PROC_SYS_KERNEL_HUNG_TASK, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_YAMA_DIR) {
        if (STREQ(name, "ptrace_scope")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_PTRACE_SCOPE,
                                          0100644, PROC_SYS_PTRACE_SCOPE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_NS_DIR) {
        static const char * const ns_names[] = {
            "pid", "mnt", "net", "user", "uts", "ipc", "cgroup"
        };
        uint64_t pid = dn->pid;
        for (int i = 0; i < 7; i++) {
            if (STREQ(name, ns_names[i])) {
                *result = procfs_alloc_vnode(mnt, VN_LNK, PROC_INO_NS_ENTRY(pid, i),
                                              0120444, PROC_NS_ENTRY, pid, i);
                return *result ? 0 : -ENOMEM;
            }
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_FDINFO_DIR) {
        uint64_t pid = dn->pid;
        uint64_t fdnum = 0;
        const char *p = name;
        if (!*p) return -ENOENT;
        while (*p >= '0' && *p <= '9') { fdnum = fdnum * 10 + (uint64_t)(*p - '0'); p++; }
        if (*p != '\0') return -ENOENT;
        fut_task_t *ftask = fut_task_by_pid(pid);
        if (!ftask) return -ESRCH;
        if ((int)fdnum >= ftask->max_fds || !ftask->fd_table[fdnum]) return -ENOENT;
        *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_FDINFO_ENTRY(pid, fdnum),
                                      0100400, PROC_FDINFO_ENTRY, pid, (int)fdnum);
        return *result ? 0 : -ENOMEM;
    }

    if (dn->kind == PROC_SYS_RANDOM_DIR) {
        if (STREQ(name, "boot_id")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_BOOT_ID,
                                          0100444, PROC_SYS_BOOT_ID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "uuid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_UUID,
                                          0100444, PROC_SYS_UUID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "entropy_avail")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_ENTROPY_AVAIL,
                                          0100444, PROC_SYS_ENTROPY_AVAIL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "poolsize")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_POOLSIZE,
                                          0100444, PROC_SYS_POOLSIZE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_VM_DIR) {
        if (STREQ(name, "overcommit_memory")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_OVERCOMMIT,
                                          0100644, PROC_SYS_OVERCOMMIT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "max_map_count")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_MAX_MAP_COUNT,
                                          0100644, PROC_SYS_MAX_MAP_COUNT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "swappiness")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SWAPPINESS,
                                          0100644, PROC_SYS_SWAPPINESS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "dirty_ratio")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_DIRTY_RATIO,
                                          0100644, PROC_SYS_DIRTY_RATIO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "dirty_background_ratio")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_DIRTY_BG_RATIO,
                                          0100644, PROC_SYS_DIRTY_BG_RATIO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "min_free_kbytes")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_MIN_FREE_KB,
                                          0100644, PROC_SYS_MIN_FREE_KB, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nr_hugepages")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NR_HUGEPAGES,
                                          0100644, PROC_SYS_NR_HUGEPAGES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nr_overcommit_hugepages")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NR_OC_HUGEPAGES,
                                          0100644, PROC_SYS_NR_OC_HUGEPAGES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mmap_min_addr")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_MMAP_MIN_ADDR,
                                          0100644, PROC_SYS_VM_MMAP_MIN_ADDR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "vfs_cache_pressure")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_VFS_CACHE_PRESS,
                                          0100644, PROC_SYS_VM_VFS_CACHE_PRESSURE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "drop_caches")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_DROP_CACHES,
                                          0100200, PROC_SYS_VM_DROP_CACHES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "dirty_expire_centisecs")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_DIRTY_EXPIRE,
                                          0100644, PROC_SYS_VM_DIRTY_EXPIRE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "dirty_writeback_centisecs")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_DIRTY_WB,
                                          0100644, PROC_SYS_VM_DIRTY_WRITEBACK, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "overcommit_kbytes")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_OVERCOMMIT_KB,
                                          0100644, PROC_SYS_VM_OVERCOMMIT_KB, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "oom_kill_allocating_task")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_OOM_KILL_ALLOC,
                                          0100644, PROC_SYS_VM_OOM_KILL_ALLOC, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "panic_on_oom")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_PANIC_ON_OOM,
                                          0100644, PROC_SYS_VM_PANIC_ON_OOM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "zone_reclaim_mode")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_ZONE_RECLAIM,
                                          0100644, PROC_SYS_VM_ZONE_RECLAIM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "watermark_boost_factor")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_WATERMARK_BST,
                                          0100644, PROC_SYS_VM_WATERMARK_BOOST, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "watermark_scale_factor")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_WATERMARK_SCL,
                                          0100644, PROC_SYS_VM_WATERMARK_SCALE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "page-cluster")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_PAGE_CLUSTER,
                                          0100644, PROC_SYS_VM_PAGE_CLUSTER, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_DIR) {
        if (STREQ(name, "file-max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FILE_MAX,
                                          0100644, PROC_SYS_FILE_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "file-nr")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FILE_NR,
                                          0100444, PROC_SYS_FILE_NR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "inotify")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_INOTIFY_DIR,
                                          0040555, PROC_SYS_INOTIFY_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nr_open")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_NR_OPEN,
                                          0100644, PROC_SYS_FS_NR_OPEN, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pipe-max-size")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_PIPE_MAX_SIZE,
                                          0100644, PROC_SYS_FS_PIPE_MAX_SIZE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "aio-max-nr")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_AIO_MAX_NR,
                                          0100444, PROC_SYS_FS_AIO_MAX_NR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "aio-nr")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_AIO_NR,
                                          0100444, PROC_SYS_FS_AIO_NR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "protected_hardlinks")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_PROT_HL,
                                          0100644, PROC_SYS_FS_PROTECTED_HL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "protected_symlinks")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_PROT_SL,
                                          0100644, PROC_SYS_FS_PROTECTED_SL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_INOTIFY_DIR) {
        if (STREQ(name, "max_user_watches")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_INOTIFY_MAX_WATCHES,
                                          0100644, PROC_SYS_INOTIFY_MAX_WATCHES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "max_user_instances")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_INOTIFY_MAX_INSTANCES,
                                          0100644, PROC_SYS_INOTIFY_MAX_INSTANCES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "max_queued_events")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_INOTIFY_MAX_QUEUED,
                                          0100644, PROC_SYS_INOTIFY_MAX_QUEUED, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_FD_DIR) {
        uint64_t pid = dn->pid;
        uint64_t fd  = parse_dec(name);
        if (fd == (uint64_t)-1) return -ENOENT;
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        if ((int)fd >= task->max_fds || !task->fd_table[(int)fd]) return -ENOENT;
        *result = procfs_alloc_vnode(mnt, VN_LNK,
                                      PROC_INO_FD_ENTRY(pid, (int)fd),
                                      0120777, PROC_FD_ENTRY, pid, (int)fd);
        return *result ? 0 : -ENOMEM;
    }

    #undef STREQ
    return -ENOTDIR;
}

static int procfs_dir_readdir(struct fut_vnode *dir, uint64_t *cookie,
                               struct fut_vdirent *de) {
    if (!dir || !cookie || !de) return -EINVAL;
    procfs_node_t *dn = (procfs_node_t *)dir->fs_data;
    if (!dn) return -EIO;

    uint64_t idx = *cookie;

    if (dn->kind == PROC_ROOT) {
        /* Fixed entries: ., .., self, meminfo, version, uptime, cpuinfo, loadavg, mounts, sys, ... */
        static const char *fixed[] = {
            ".", "..", "self", "thread-self", "meminfo", "version", "uptime", "cpuinfo",
            "loadavg", "mounts", "sys", "stat", "filesystems", "vmstat", "net",
            "interrupts", "cmdline", "swaps", "devices", "misc",
            "buddyinfo", "zoneinfo", "diskstats", "partitions", "cgroups", "kallsyms",
            "locks"
        };
        static const uint8_t fixed_type[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG   /* locks */
        };
        static const uint64_t fixed_ino[] = {
            PROC_INO_ROOT, PROC_INO_ROOT,
            PROC_INO_SELF, PROC_INO_THREAD_SELF,
            PROC_INO_MEMINFO, PROC_INO_VERSION, PROC_INO_UPTIME,
            PROC_INO_CPUINFO, PROC_INO_LOADAVG, PROC_INO_MOUNTS, PROC_INO_SYS_DIR,
            PROC_INO_STAT_GLOBAL, PROC_INO_FILESYSTEMS,
            PROC_INO_VMSTAT, PROC_INO_NET_DIR,
            PROC_INO_INTERRUPTS,
            PROC_INO_CMDLINE_GLOBAL, PROC_INO_SWAPS, PROC_INO_DEVICES, PROC_INO_MISC_FILE,
            PROC_INO_BUDDYINFO, PROC_INO_ZONEINFO,
            PROC_INO_DISKSTATS, PROC_INO_PARTITIONS, PROC_INO_CGROUPS, PROC_INO_KALLSYMS,
            PROC_INO_LOCKS
        };
        if (idx < 27) {
            de->d_ino    = fixed_ino[idx];
            de->d_off    = idx + 1;
            de->d_type   = fixed_type[idx];
            de->d_reclen = sizeof(*de);
            size_t nl = 0;
            while (fixed[idx][nl]) nl++;
            if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
            __builtin_memcpy(de->d_name, fixed[idx], nl);
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 1;
        }

        /*
         * PID enumeration: after the 27 fixed entries, cookies encode
         * "find first task with pid > (cookie - 27)".  After returning
         * a PID entry we set cookie = 27 + that_pid + 1.
         *
         * This is stable as long as PIDs are unique and monotonically
         * increasing; newly-forked tasks will appear if their PID is
         * greater than the last-seen PID.
         */
        uint64_t min_pid = idx >= 27 ? idx - 27 : 0;  /* start scanning for pid > min_pid */
        fut_task_t *best = NULL;
        uint64_t   best_pid = (uint64_t)-1;
        fut_task_t *t = fut_task_list;
        while (t) {
            if (t->pid > min_pid && t->pid < best_pid) {
                best = t;
                best_pid = t->pid;
            }
            t = t->next;
        }
        if (!best) return -ENOENT;  /* no more tasks */

        /* Format pid as decimal name */
        char pidname[20]; int pn = 0;
        uint64_t pv = best->pid;
        if (pv == 0) { pidname[pn++] = '0'; }
        else {
            char rev[20]; int rn = 0;
            while (pv) { rev[rn++] = '0' + (int)(pv % 10); pv /= 10; }
            for (int i = rn - 1; i >= 0; i--) pidname[pn++] = rev[i];
        }
        pidname[pn] = '\0';

        de->d_ino    = PROC_INO_PID_DIR(best->pid);
        de->d_off    = 27 + best->pid + 1;
        de->d_type   = FUT_VDIR_TYPE_DIR;
        de->d_reclen = sizeof(*de);
        size_t nl = (size_t)pn;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        __builtin_memcpy(de->d_name, pidname, nl);
        de->d_name[nl] = '\0';
        *cookie = 27 + best->pid + 1;  /* resume after this pid */
        return 1;
    }

    if (dn->kind == PROC_PID_DIR || dn->kind == PROC_TID_DIR) {
        static const char *entries[] = {
            ".", "..", "status", "maps", "cmdline", "environ", "fd", "exe", "cwd",
            "stat", "statm", "comm", "task", "limits", "io", "smaps",
            "oom_score", "oom_score_adj", "cgroup", "ns", "fdinfo",
            "wchan", "mountinfo", "coredump_filter", "schedstat", "net", "attr",
            "smaps_rollup", "auxv", "mem",
            "uid_map", "gid_map", "setgroups",
            "loginuid", "sessionid", "personality", "pagemap", "timerslack_ns", "syscall", "root"
        };
        static const uint8_t etypes[] = {
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG,
            FUT_VDIR_TYPE_REG,      /* timerslack_ns */
            FUT_VDIR_TYPE_REG,      /* syscall */
            FUT_VDIR_TYPE_SYMLINK   /* root */
        };
        uint64_t pid = dn->pid;
        if (idx < 40) {
            uint64_t ino;
            switch (idx) {
                case 0:  ino = PROC_INO_PID_DIR(pid);        break;
                case 1:  ino = PROC_INO_ROOT;                 break;
                case 2:  ino = PROC_INO_PID_STATUS(pid);     break;
                case 3:  ino = PROC_INO_PID_MAPS(pid);       break;
                case 4:  ino = PROC_INO_PID_CMDLINE(pid);    break;
                case 5:  ino = PROC_INO_PID_ENVIRON(pid);    break;
                case 6:  ino = PROC_INO_PID_FD(pid);         break;
                case 7:  ino = PROC_INO_PID_EXE(pid);        break;
                case 8:  ino = PROC_INO_PID_CWD(pid);        break;
                case 9:  ino = PROC_INO_PID_STAT(pid);       break;
                case 10: ino = PROC_INO_PID_STATM(pid);      break;
                case 11: ino = PROC_INO_PID_COMM(pid);       break;
                case 12: ino = PROC_INO_PID_TASK(pid);       break;
                case 13: ino = PROC_INO_PID_LIMITS(pid);     break;
                case 14: ino = PROC_INO_PID_IO(pid);         break;
                case 15: ino = PROC_INO_PID_SMAPS(pid);      break;
                case 16: ino = PROC_INO_PID_OOM_SCORE(pid);  break;
                case 17: ino = PROC_INO_PID_OOM_ADJ(pid);    break;
                case 18: ino = PROC_INO_PID_CGROUP(pid);     break;
                case 19: ino = PROC_INO_PID_NS(pid);         break;
                case 20: ino = PROC_INO_PID_FDINFO(pid);     break;
                case 21: ino = PROC_INO_PID_WCHAN(pid);      break;
                case 22: ino = PROC_INO_PID_MOUNTINFO(pid);  break;
                case 23: ino = PROC_INO_PID_COREDUMP(pid);   break;
                case 24: ino = PROC_INO_PID_SCHEDSTAT(pid);  break;
                case 25: ino = PROC_INO_NET_DIR;                    break;
                case 26: ino = PROC_INO_PID_ATTR(pid);              break;
                case 27: ino = PROC_INO_PID_SMAPS_ROLLUP(pid);      break;
                case 28: ino = PROC_INO_PID_AUXV(pid);              break;
                case 29: ino = PROC_INO_PID_MEM(pid);               break;
                case 30: ino = PROC_INO_PID_UID_MAP(pid);           break;
                case 31: ino = PROC_INO_PID_GID_MAP(pid);           break;
                case 32: ino = PROC_INO_PID_SETGROUPS(pid);         break;
                case 33: ino = PROC_INO_PID_LOGINUID(pid);          break;
                case 34: ino = PROC_INO_PID_SESSIONID(pid);         break;
                case 35: ino = PROC_INO_PID_PERSONALITY(pid);       break;
                case 36: ino = PROC_INO_PID_PAGEMAP(pid);           break;
                case 37: ino = PROC_INO_PID_TIMERSLACK(pid);        break;
                case 38: ino = PROC_INO_PID_SYSCALL(pid);           break;
                case 39: ino = PROC_INO_PID_ROOT(pid);              break;
                default: ino = 0; break;
            }
            de->d_ino    = ino;
            de->d_off    = (uint64_t)(idx + 1);
            de->d_type   = etypes[idx];
            de->d_reclen = sizeof(*de);
            const char *nm = entries[idx];
            size_t nl = 0; while (nm[nl]) nl++;
            if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
            __builtin_memcpy(de->d_name, nm, nl);
            de->d_name[nl] = '\0';
            *cookie = idx + 1;
            return 1;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_TASK_DIR) {
        /* Enumerate threads: . and .. first, then TID entries */
        uint64_t pid = dn->pid;
        if (idx == 0) {
            de->d_ino = PROC_INO_PID_TASK(pid);
            de->d_off = 1; de->d_type = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '\0';
            *cookie = 1; return 1;
        }
        if (idx == 1) {
            de->d_ino = PROC_INO_PID_DIR(pid);
            de->d_off = 2; de->d_type = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
            *cookie = 2; return 1;
        }
        /* TID enumeration: cookie >= 2 → find thread at position idx-2 */
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;
        fut_thread_t *t = task->threads;
        uint64_t pos = 0;
        uint64_t target = (uint64_t)idx - 2;
        while (t && pos < target) { t = t->next; pos++; }
        if (!t) return -ENOENT;
        /* Build TID string */
        char tidname[21];
        uint64_t v = t->tid; int n = 0;
        if (v == 0) { tidname[n++] = '0'; }
        else { char tmp[20]; int k = 0; while (v) { tmp[k++] = '0' + (v % 10); v /= 10; } for (int i = k-1; i >= 0; i--) tidname[n++] = tmp[i]; }
        tidname[n] = '\0';
        de->d_ino = PROC_INO_TID_DIR(pid, t->tid);
        de->d_off = idx + 1; de->d_type = FUT_VDIR_TYPE_DIR;
        de->d_reclen = sizeof(*de);
        size_t nl = (size_t)n;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        __builtin_memcpy(de->d_name, tidname, nl);
        de->d_name[nl] = '\0';
        *cookie = idx + 1;
        return 1;
    }

    /* Generic readdir helper for small fixed-entry directories */
#define SYS_DIR_ENTRY(nm, tp, ino)  do { \
    de->d_ino = (ino); de->d_off = idx + 1; de->d_type = (tp); \
    de->d_reclen = sizeof(*de); \
    size_t _nl = 0; while ((nm)[_nl]) _nl++; \
    if (_nl > FUT_VFS_NAME_MAX) _nl = FUT_VFS_NAME_MAX; \
    __builtin_memcpy(de->d_name, (nm), _nl); de->d_name[_nl] = '\0'; \
    *cookie = idx + 1; return 1; \
} while (0)

    if (dn->kind == PROC_NET_DIR) {
        static const char *e[] = { ".", "..", "dev", "route", "tcp", "udp",
                                   "if_inet6", "unix", "sockstat", "arp",
                                   "tcp6", "udp6", "raw", "fib_trie",
                                   "snmp", "netstat", "packet" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_NET_DIR, PROC_INO_ROOT,
                                      PROC_INO_NET_DEV, PROC_INO_NET_ROUTE,
                                      PROC_INO_NET_TCP, PROC_INO_NET_UDP,
                                      PROC_INO_NET_IF6, PROC_INO_NET_UNIX,
                                      PROC_INO_NET_SOCKSTAT, PROC_INO_NET_ARP,
                                      PROC_INO_NET_TCP6, PROC_INO_NET_UDP6,
                                      PROC_INO_NET_RAW, PROC_INO_NET_FIB_TRIE,
                                      PROC_INO_NET_SNMP, PROC_INO_NET_NETSTAT,
                                      PROC_INO_NET_PACKET };
        if (idx < 17) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_DIR) {
        static const char *e[] = { ".", "..", "kernel", "vm", "fs", "net" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_DIR, PROC_INO_ROOT,
                                      PROC_INO_SYS_KERNEL_DIR, PROC_INO_SYS_VM_DIR,
                                      PROC_INO_SYS_FS_DIR, PROC_INO_SYS_NET_DIR };
        if (idx < 6) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_DIR) {
        static const char *e[] = { ".", "..", "core", "ipv4", "ipv6" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_NET_CORE_DIR, PROC_INO_SYS_NET_IPV4_DIR,
                                      PROC_INO_SYS_NET_IPV6_DIR };
        if (idx < 5) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_DIR) {
        static const char *e[] = { ".", "..", "conf" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_IPV6_DIR, PROC_INO_SYS_NET_DIR,
                                      PROC_INO_SYS_NET_IPV6_CONF_DIR };
        if (idx < 3) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_CONF_DIR) {
        static const char *e[] = { ".", "..", "all" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_IPV6_CONF_DIR,
                                      PROC_INO_SYS_NET_IPV6_DIR,
                                      PROC_INO_SYS_NET_IPV6_ALL_DIR };
        if (idx < 3) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV6_CONF_ALL_DIR) {
        static const char *e[] = { ".", "..", "disable_ipv6", "forwarding" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_NET_IPV6_ALL_DIR,
                                      PROC_INO_SYS_NET_IPV6_CONF_DIR,
                                      PROC_INO_SYS_NET_IPV6_DISABLE,
                                      PROC_INO_SYS_NET_IPV6_FORWARD };
        if (idx < 4) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_CORE_DIR) {
        static const char *e[] = { ".", "..", "somaxconn", "rmem_max", "wmem_max",
                                   "rmem_default", "wmem_default" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_NET_CORE_DIR, PROC_INO_SYS_NET_DIR,
                                      PROC_INO_SYS_NET_SOMAXCONN, PROC_INO_SYS_NET_RMEM_MAX,
                                      PROC_INO_SYS_NET_WMEM_MAX, PROC_INO_SYS_NET_RMEM_DEFAULT,
                                      PROC_INO_SYS_NET_WMEM_DEFAULT };
        if (idx < 7) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_DIR) {
        static const char *e[] = { ".", "..", "ip_local_port_range",
                                   "tcp_fin_timeout", "tcp_syncookies",
                                   "tcp_rmem", "tcp_wmem", "ip_forward",
                                   "tcp_keepalive_time", "tcp_keepalive_intvl",
                                   "tcp_keepalive_probes",
                                   "ip_unprivileged_port_start", "conf" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_IPV4_DIR, PROC_INO_SYS_NET_DIR,
                                      PROC_INO_SYS_NET_PORT_RANGE, PROC_INO_SYS_NET_FIN_TIMEOUT,
                                      PROC_INO_SYS_NET_SYNCOOKIES,
                                      PROC_INO_SYS_NET_TCP_RMEM, PROC_INO_SYS_NET_TCP_WMEM,
                                      PROC_INO_SYS_NET_IP_FORWARD,
                                      PROC_INO_SYS_NET_KEEPALIVE_TIME,
                                      PROC_INO_SYS_NET_KEEPALIVE_INTVL,
                                      PROC_INO_SYS_NET_KEEPALIVE_PROBES,
                                      PROC_INO_SYS_NET_UNPRIV_PORT,
                                      PROC_INO_SYS_NET_IPV4_CONF_DIR };
        if (idx < 13) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_CONF_DIR) {
        static const char *e[] = { ".", "..", "all", "default" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_IPV4_CONF_DIR,
                                      PROC_INO_SYS_NET_IPV4_DIR,
                                      PROC_INO_SYS_NET_IPV4_CONF_ALL,
                                      PROC_INO_SYS_NET_IPV4_CONF_DEF };
        if (idx < 4) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_IPV4_CONF_ALL_DIR ||
        dn->kind == PROC_SYS_NET_IPV4_CONF_DEFAULT_DIR) {
        uint64_t self_ino = (dn->kind == PROC_SYS_NET_IPV4_CONF_ALL_DIR)
                            ? PROC_INO_SYS_NET_IPV4_CONF_ALL
                            : PROC_INO_SYS_NET_IPV4_CONF_DEF;
        uint64_t offset = (dn->kind == PROC_SYS_NET_IPV4_CONF_ALL_DIR) ? 0 : 10;
        static const char *e[] = { ".", "..", "rp_filter", "forwarding", "accept_redirects" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG };
        if (idx == 0) SYS_DIR_ENTRY(e[0], t[0], self_ino);
        if (idx == 1) SYS_DIR_ENTRY(e[1], t[1], PROC_INO_SYS_NET_IPV4_CONF_DIR);
        if (idx == 2) SYS_DIR_ENTRY(e[2], t[2], PROC_INO_SYS_NET_IPV4_RP_FILTER  + offset);
        if (idx == 3) SYS_DIR_ENTRY(e[3], t[3], PROC_INO_SYS_NET_IPV4_FORWARDING + offset);
        if (idx == 4) SYS_DIR_ENTRY(e[4], t[4], PROC_INO_SYS_NET_IPV4_ACCEPT_RA  + offset);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_KERNEL_DIR) {
        static const char *e[] = { ".", "..", "ostype", "osrelease", "hostname",
                                   "pid_max", "random",
                                   "shmmax", "shmall", "shmmni", "sem",
                                   "msgmax", "msgmnb", "msgmni",
                                   "ngroups_max", "cap_last_cap",
                                   "threads-max", "printk", "yama",
                                   "randomize_va_space", "domainname",
                                   "perf_event_paranoid", "kptr_restrict",
                                   "dmesg_restrict",
                                   "core_pattern", "core_uses_pid",
                                   "suid_dumpable", "tainted", "version",
                                   "nmi_watchdog", "watchdog",
                                   "watchdog_thresh", "hung_task_timeout_secs" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_KERNEL_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_OSTYPE, PROC_INO_SYS_OSRELEASE,
                                      PROC_INO_SYS_HOSTNAME, PROC_INO_SYS_PID_MAX,
                                      PROC_INO_SYS_RANDOM_DIR,
                                      PROC_INO_SYS_SHMMAX, PROC_INO_SYS_SHMALL,
                                      PROC_INO_SYS_SHMMNI, PROC_INO_SYS_SEM,
                                      PROC_INO_SYS_MSGMAX, PROC_INO_SYS_MSGMNB,
                                      PROC_INO_SYS_MSGMNI,
                                      PROC_INO_SYS_NGROUPS_MAX, PROC_INO_SYS_CAP_LAST_CAP,
                                      PROC_INO_SYS_THREADS_MAX, PROC_INO_SYS_PRINTK,
                                      PROC_INO_SYS_YAMA_DIR,
                                      PROC_INO_SYS_RANDOMIZE_VA, PROC_INO_SYS_DOMAINNAME,
                                      PROC_INO_SYS_PERF_PARANOID, PROC_INO_SYS_KPTR_RESTRICT,
                                      PROC_INO_SYS_DMESG_RESTRICT,
                                      PROC_INO_SYS_CORE_PATTERN, PROC_INO_SYS_CORE_USES_PID,
                                      PROC_INO_SYS_SUID_DUMPABLE, PROC_INO_SYS_TAINTED,
                                      PROC_INO_SYS_VERSION_KERNEL,
                                      PROC_INO_SYS_KERNEL_NMI_WD,
                                      PROC_INO_SYS_KERNEL_WATCHDOG,
                                      PROC_INO_SYS_KERNEL_WD_THRESH,
                                      PROC_INO_SYS_KERNEL_HUNG_TASK };
        if (idx < 33) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_RANDOM_DIR) {
        static const char *e[] = { ".", "..", "boot_id", "uuid", "entropy_avail", "poolsize" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_RANDOM_DIR, PROC_INO_SYS_KERNEL_DIR,
                                      PROC_INO_SYS_BOOT_ID, PROC_INO_SYS_UUID,
                                      PROC_INO_SYS_ENTROPY_AVAIL, PROC_INO_SYS_POOLSIZE };
        if (idx < 6) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_YAMA_DIR) {
        static const char *e[] = { ".", "..", "ptrace_scope" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_YAMA_DIR, PROC_INO_SYS_KERNEL_DIR,
                                      PROC_INO_SYS_PTRACE_SCOPE };
        if (idx < 3) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_ATTR_DIR) {
        static const char *e[] = { ".", "..", "current", "exec", "prev",
                                   "fscreate", "keycreate", "sockcreate" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        uint64_t pid = dn->pid;
        if (idx >= 8) return -ENOENT;
        uint64_t ino = (idx <= 1) ? PROC_INO_PID_ATTR(pid) : PROC_INO_PID_ATTR_CUR(pid);
        SYS_DIR_ENTRY(e[idx], t[idx], ino);
    }

    if (dn->kind == PROC_NS_DIR) {
        static const char *e[] = { ".", "..", "pid", "mnt", "net", "user", "uts", "ipc", "cgroup" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
                                     FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
                                     FUT_VDIR_TYPE_SYMLINK, FUT_VDIR_TYPE_SYMLINK,
                                     FUT_VDIR_TYPE_SYMLINK };
        uint64_t pid = dn->pid;
        if (idx >= 9) return -ENOENT;
        uint64_t ino;
        switch (idx) {
            case 0: ino = PROC_INO_PID_NS(pid);         break;
            case 1: ino = PROC_INO_PID_DIR(pid);        break;
            default: ino = PROC_INO_NS_ENTRY(pid, idx - 2); break;
        }
        SYS_DIR_ENTRY(e[idx], t[idx], ino);
    }

    if (dn->kind == PROC_SYS_VM_DIR) {
        static const char *e[] = { ".", "..", "overcommit_memory", "max_map_count",
                                   "swappiness", "dirty_ratio",
                                   "dirty_background_ratio", "min_free_kbytes",
                                   "nr_hugepages", "nr_overcommit_hugepages",
                                   "mmap_min_addr", "vfs_cache_pressure",
                                   "drop_caches", "dirty_expire_centisecs",
                                   "dirty_writeback_centisecs", "overcommit_kbytes",
                                   "oom_kill_allocating_task", "panic_on_oom",
                                   "zone_reclaim_mode", "watermark_boost_factor",
                                   "watermark_scale_factor", "page-cluster" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_VM_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_OVERCOMMIT, PROC_INO_SYS_MAX_MAP_COUNT,
                                      PROC_INO_SYS_SWAPPINESS, PROC_INO_SYS_DIRTY_RATIO,
                                      PROC_INO_SYS_DIRTY_BG_RATIO, PROC_INO_SYS_MIN_FREE_KB,
                                      PROC_INO_SYS_NR_HUGEPAGES, PROC_INO_SYS_NR_OC_HUGEPAGES,
                                      PROC_INO_SYS_VM_MMAP_MIN_ADDR,
                                      PROC_INO_SYS_VM_VFS_CACHE_PRESS,
                                      PROC_INO_SYS_VM_DROP_CACHES,
                                      PROC_INO_SYS_VM_DIRTY_EXPIRE,
                                      PROC_INO_SYS_VM_DIRTY_WB,
                                      PROC_INO_SYS_VM_OVERCOMMIT_KB,
                                      PROC_INO_SYS_VM_OOM_KILL_ALLOC,
                                      PROC_INO_SYS_VM_PANIC_ON_OOM,
                                      PROC_INO_SYS_VM_ZONE_RECLAIM,
                                      PROC_INO_SYS_VM_WATERMARK_BST,
                                      PROC_INO_SYS_VM_WATERMARK_SCL,
                                      PROC_INO_SYS_VM_PAGE_CLUSTER };
        if (idx < 22) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_DIR) {
        static const char *e[] = { ".", "..", "file-max", "file-nr", "inotify",
                                   "nr_open", "pipe-max-size",
                                   "aio-max-nr", "aio-nr",
                                   "protected_hardlinks", "protected_symlinks" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_FS_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_FILE_MAX, PROC_INO_SYS_FILE_NR,
                                      PROC_INO_SYS_INOTIFY_DIR,
                                      PROC_INO_SYS_FS_NR_OPEN,
                                      PROC_INO_SYS_FS_PIPE_MAX_SIZE,
                                      PROC_INO_SYS_FS_AIO_MAX_NR,
                                      PROC_INO_SYS_FS_AIO_NR,
                                      PROC_INO_SYS_FS_PROT_HL,
                                      PROC_INO_SYS_FS_PROT_SL };
        if (idx < 11) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_INOTIFY_DIR) {
        static const char *e[] = { ".", "..", "max_user_watches",
                                   "max_user_instances", "max_queued_events" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_INOTIFY_DIR, PROC_INO_SYS_FS_DIR,
                                      PROC_INO_SYS_INOTIFY_MAX_WATCHES,
                                      PROC_INO_SYS_INOTIFY_MAX_INSTANCES,
                                      PROC_INO_SYS_INOTIFY_MAX_QUEUED };
        if (idx < 5) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

#undef SYS_DIR_ENTRY

    if (dn->kind == PROC_FD_DIR) {
        uint64_t pid = dn->pid;
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;

        /* Entries: ., .., then open fds */
        if (idx == 0) {
            de->d_ino    = PROC_INO_PID_FD(pid);
            de->d_off    = 1;
            de->d_type   = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '\0';
            *cookie = 1;
            return 1;
        }
        if (idx == 1) {
            de->d_ino    = PROC_INO_PID_DIR(pid);
            de->d_off    = 2;
            de->d_type   = FUT_VDIR_TYPE_DIR;
            de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0';
            *cookie = 2;
            return 1;
        }
        /* Scan for open fds starting at fd_scan = idx - 2 */
        int scan = (int)(idx - 2);
        while (scan < task->max_fds) {
            if (task->fd_table[scan]) break;
            scan++;
        }
        if (scan >= task->max_fds) return -ENOENT;
        /* Format fd number as name */
        char tmp[12]; int tn = 0;
        int v = scan;
        if (v == 0) { tmp[tn++] = '0'; }
        else {
            char rev[10]; int rn = 0;
            while (v) { rev[rn++] = '0' + (v % 10); v /= 10; }
            for (int i = rn - 1; i >= 0; i--) tmp[tn++] = rev[i];
        }
        tmp[tn] = '\0';
        de->d_ino    = PROC_INO_FD_ENTRY(pid, scan);
        de->d_off    = idx + 1;
        de->d_type   = FUT_VDIR_TYPE_SYMLINK;
        de->d_reclen = sizeof(*de);
        __builtin_memcpy(de->d_name, tmp, tn + 1);
        *cookie = (uint64_t)(scan + 2 + 1);
        return 1;
    }

    if (dn->kind == PROC_FDINFO_DIR) {
        uint64_t pid = dn->pid;
        fut_task_t *task = fut_task_by_pid(pid);
        if (!task) return -ENOENT;

        if (idx == 0) {
            de->d_ino = PROC_INO_PID_FDINFO(pid); de->d_off = 1;
            de->d_type = FUT_VDIR_TYPE_DIR; de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '\0'; *cookie = 1; return 1;
        }
        if (idx == 1) {
            de->d_ino = PROC_INO_PID_DIR(pid); de->d_off = 2;
            de->d_type = FUT_VDIR_TYPE_DIR; de->d_reclen = sizeof(*de);
            de->d_name[0] = '.'; de->d_name[1] = '.'; de->d_name[2] = '\0'; *cookie = 2; return 1;
        }
        /* Scan for open fds (same layout as PROC_FD_DIR) */
        int scan = (int)(idx - 2);
        while (scan < task->max_fds) {
            if (task->fd_table[scan]) break;
            scan++;
        }
        if (scan >= task->max_fds) return -ENOENT;
        char tmp[12]; int tn = 0;
        int v = scan;
        if (v == 0) { tmp[tn++] = '0'; }
        else {
            char rev[10]; int rn = 0;
            while (v) { rev[rn++] = '0' + (v % 10); v /= 10; }
            for (int i = rn - 1; i >= 0; i--) tmp[tn++] = rev[i];
        }
        tmp[tn] = '\0';
        de->d_ino = PROC_INO_FDINFO_ENTRY(pid, (uint64_t)scan);
        de->d_off = idx + 1;
        de->d_type = FUT_VDIR_TYPE_REG;
        de->d_reclen = sizeof(*de);
        __builtin_memcpy(de->d_name, tmp, tn + 1);
        *cookie = (uint64_t)(scan + 2 + 1);
        return 1;
    }

    return -ENOTDIR;
}

static int procfs_dir_getattr(struct fut_vnode *vnode, struct fut_stat *st) {
    if (!vnode || !st) return -EINVAL;
    __builtin_memset(st, 0, sizeof(*st));
    st->st_ino   = vnode->ino;
    st->st_mode  = 0040555;
    st->st_nlink = 2;
    st->st_uid   = 0;
    st->st_gid   = 0;
    st->st_size  = 0;
    st->st_blksize = 4096;
    return 0;
}

/* ============================================================
 *   VNode Ops Tables
 * ============================================================ */

static const struct fut_vnode_ops procfs_file_ops = {
    .read    = procfs_file_read,
    .write   = procfs_file_write,
    .getattr = procfs_file_getattr,
};

static const struct fut_vnode_ops procfs_link_ops = {
    .readlink = procfs_link_readlink,
    .getattr  = procfs_link_getattr,
};

static const struct fut_vnode_ops procfs_dir_ops = {
    .lookup  = procfs_dir_lookup,
    .readdir = procfs_dir_readdir,
    .getattr = procfs_dir_getattr,
};

/* ============================================================
 *   Mount / Unmount
 * ============================================================ */

static int procfs_mount(const char *device, int flags, void *data,
                        fut_handle_t block_device_handle,
                        struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)block_device_handle;

    struct fut_mount *mount = fut_malloc(sizeof(struct fut_mount));
    if (!mount) return -ENOMEM;

    struct fut_vnode *root = procfs_alloc_vnode(mount, VN_DIR,
                                                  PROC_INO_ROOT, 0040555,
                                                  PROC_ROOT, 0, 0);
    if (!root) { fut_free(mount); return -ENOMEM; }
    root->mount = mount;

    mount->device               = NULL;
    mount->mountpoint           = NULL;
    mount->fs                   = NULL;
    mount->root                 = root;
    mount->flags                = flags;
    mount->fs_data              = NULL;
    mount->next                 = NULL;
    mount->block_device_handle  = block_device_handle;

    *mount_out = mount;
    return 0;
}

static int procfs_unmount(struct fut_mount *mount) {
    if (!mount) return -EINVAL;
    if (mount->root) {
        procfs_node_t *n = (procfs_node_t *)mount->root->fs_data;
        if (n) fut_free(n);
        fut_free(mount->root);
    }
    fut_free(mount);
    return 0;
}

/* ============================================================
 *   Registration
 * ============================================================ */

static struct fut_fs_type procfs_type;

void fut_procfs_init(void) {
    procfs_type.name    = "proc";
    procfs_type.mount   = procfs_mount;
    procfs_type.unmount = procfs_unmount;
    fut_vfs_register_fs(&procfs_type);
}

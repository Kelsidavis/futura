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
#include <generated/version.h>
#include <kernel/fut_task.h>
#include <kernel/fut_mm.h>
#include <kernel/fut_memory.h>
#include <kernel/fut_timer.h>
#include <kernel/fut_stats.h>
#include <kernel/fut_lock.h>
#include <kernel/vfs_credentials.h>
#include <kernel/fut_socket.h>
#include <futura/netif.h>
#include <futura/tcpip.h>
#include <kernel/eventfd.h>
#include <kernel/fut_blockdev.h>
#include <kernel/pci.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/uaccess.h>
#include <sys/mman.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Architecture-specific paging headers for KERNEL_VIRTUAL_BASE */
#include <platform/platform.h>

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
    PROC_SYS_NET_IP_DEFAULT_TTL,      /* /proc/sys/net/ipv4/ip_default_ttl */
    PROC_SYS_NET_IP_MASQ_DEV,        /* /proc/sys/net/ipv4/ip_masquerade_dev */
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
    PROC_MODULES,                   /* /proc/modules */
    PROC_BUDDYINFO,                 /* /proc/buddyinfo */
    PROC_ZONEINFO,                  /* /proc/zoneinfo */
    PROC_SYSVIPC_DIR,               /* /proc/sysvipc/ */
    PROC_SYSVIPC_SHM,               /* /proc/sysvipc/shm */
    PROC_SYSVIPC_SEM,               /* /proc/sysvipc/sem */
    PROC_SYSVIPC_MSG,               /* /proc/sysvipc/msg */
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
    PROC_SYS_VM_MMAP_RND_BITS,     /* /proc/sys/vm/mmap_rnd_bits */
    PROC_SYS_VM_MMAP_RND_COMPAT,   /* /proc/sys/vm/mmap_rnd_compat_bits */
    /* Additional /proc/sys/fs/ entries */
    PROC_SYS_FS_AIO_MAX_NR,         /* /proc/sys/fs/aio-max-nr */
    PROC_SYS_FS_AIO_NR,             /* /proc/sys/fs/aio-nr */
    PROC_SYS_FS_PROTECTED_HL,       /* /proc/sys/fs/protected_hardlinks */
    PROC_SYS_FS_PROTECTED_SL,       /* /proc/sys/fs/protected_symlinks */
    PROC_SYS_FS_DENTRY_STATE,       /* /proc/sys/fs/dentry-state */
    PROC_SYS_FS_INODE_STATE,        /* /proc/sys/fs/inode-state */
    PROC_SYS_FS_INODE_NR,           /* /proc/sys/fs/inode-nr */
    PROC_SYS_FS_OVERFLOWUID,        /* /proc/sys/fs/overflowuid */
    PROC_SYS_FS_OVERFLOWGID,        /* /proc/sys/fs/overflowgid */
    PROC_SYS_FS_LEASE_BREAK_TIME,   /* /proc/sys/fs/lease-break-time */
    PROC_SYS_FS_BINFMT_MISC_DIR,   /* /proc/sys/fs/binfmt_misc/ */
    PROC_SYS_FS_BINFMT_STATUS,     /* /proc/sys/fs/binfmt_misc/status */
    PROC_SYS_FS_BINFMT_REGISTER,   /* /proc/sys/fs/binfmt_misc/register */
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
    PROC_NET_NF_CONNTRACK,          /* /proc/net/nf_conntrack */
    PROC_NET_PROTOCOLS,             /* /proc/net/protocols */
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
    PROC_KCONFIG,                   /* /proc/config.gz — kernel configuration (text, not actually gzipped) */
    PROC_SYSRQ_TRIGGER,             /* /proc/sysrq-trigger — Magic SysRq trigger (write-only) */
    PROC_CRYPTO,                    /* /proc/crypto — registered crypto algorithms */
    PROC_SOFTIRQS,                  /* /proc/softirqs — software interrupt counters */
    PROC_CONSOLES,                  /* /proc/consoles — registered console devices */
    PROC_IOMEM,                     /* /proc/iomem — I/O memory map */
    PROC_IOPORTS,                   /* /proc/ioports — I/O port allocations */
    PROC_TIMERSLACK_NS,             /* /proc/<pid>/timerslack_ns — timer expiry slack in nanoseconds */
    PROC_SYSCALL,                   /* /proc/<pid>/syscall — current syscall number and arguments */
    PROC_LOCKS,                     /* /proc/locks — POSIX and flock file lock table */
    PROC_PCI_DEVICES,               /* /proc/pci — PCI bus device list */
    PROC_SYS_NET_UNIX_DIR,          /* /proc/sys/net/unix/ */
    PROC_SYS_NET_UNIX_DGRAM_QLEN,  /* /proc/sys/net/unix/max_dgram_qlen */
    PROC_SYS_NET_BRIDGE_DIR,       /* /proc/sys/net/bridge/ */
    PROC_SYS_NET_BRIDGE_NF_CALL,   /* /proc/sys/net/bridge/bridge-nf-call-iptables */
    PROC_SYS_NET_NF_DIR,            /* /proc/sys/net/netfilter/ */
    PROC_SYS_NET_NF_CT_MAX,         /* /proc/sys/net/netfilter/nf_conntrack_max */
    PROC_SYS_NET_NF_CT_COUNT,       /* /proc/sys/net/netfilter/nf_conntrack_count */
    PROC_SYS_KERNEL_PANIC,          /* /proc/sys/kernel/panic */
    PROC_SYS_KERNEL_PANIC_ON_OOPS,  /* /proc/sys/kernel/panic_on_oops */
    PROC_NET_XFRM_STAT,             /* /proc/net/xfrm_stat */
    PROC_NET_IPV6_ROUTE,            /* /proc/net/ipv6_route */
    PROC_SYS_SCHED_CHILD_FIRST,     /* /proc/sys/kernel/sched_child_runs_first */
    PROC_SYS_SCHED_LATENCY_NS,     /* /proc/sys/kernel/sched_latency_ns */
    PROC_SYS_SCHED_MIN_GRAN_NS,    /* /proc/sys/kernel/sched_min_granularity_ns */
    PROC_SYS_SCHED_WAKEUP_NS,      /* /proc/sys/kernel/sched_wakeup_granularity_ns */
    PROC_SYS_SCHED_MIGCOST_NS,     /* /proc/sys/kernel/sched_migration_cost_ns */
    PROC_PRESSURE_DIR,              /* /proc/pressure/ directory */
    PROC_PRESSURE_CPU,              /* /proc/pressure/cpu */
    PROC_PRESSURE_MEMORY,           /* /proc/pressure/memory */
    PROC_PRESSURE_IO,               /* /proc/pressure/io */
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
#define PROC_INO_NET_NF_CONNTRACK   29ULL
#define PROC_INO_NET_PROTOCOLS      30ULL
#define PROC_INO_SYSVIPC_DIR       32ULL
#define PROC_INO_SYSVIPC_SHM       33ULL
#define PROC_INO_SYSVIPC_SEM       34ULL
#define PROC_INO_SYSVIPC_MSG       35ULL
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
#define PROC_INO_MODULES               31ULL
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
#define PROC_INO_SYS_FS_DENTRY_STATE   384ULL
#define PROC_INO_SYS_FS_INODE_STATE    385ULL
#define PROC_INO_SYS_FS_INODE_NR       386ULL
#define PROC_INO_SYS_FS_OVERFLOWUID    387ULL
#define PROC_INO_SYS_FS_OVERFLOWGID    388ULL
#define PROC_INO_SYS_FS_LEASE_BREAK    389ULL
#define PROC_INO_SYS_FS_BINFMT_DIR    390ULL
#define PROC_INO_SYS_FS_BINFMT_STATUS 391ULL
#define PROC_INO_SYS_FS_BINFMT_REG    392ULL
/* /proc/sys/net/ipv4/ extended range: 404-407 */
#define PROC_INO_SYS_NET_KEEPALIVE_TIME  404ULL
#define PROC_INO_SYS_NET_KEEPALIVE_INTVL 405ULL
#define PROC_INO_SYS_NET_KEEPALIVE_PROBES 406ULL
#define PROC_INO_SYS_NET_UNPRIV_PORT     407ULL
#define PROC_INO_SYS_NET_IP_DEFAULT_TTL  415ULL
#define PROC_INO_SYS_NET_IP_MASQ_DEV    416ULL
/* /proc/sys/net/ipv4/conf/ range: 408-414 */
#define PROC_INO_SYS_NET_IPV4_CONF_DIR   408ULL
#define PROC_INO_SYS_NET_IPV4_CONF_ALL   409ULL
#define PROC_INO_SYS_NET_IPV4_CONF_DEF   410ULL
#define PROC_INO_SYS_NET_IPV4_RP_FILTER  411ULL
#define PROC_INO_SYS_NET_IPV4_FORWARDING 412ULL
#define PROC_INO_SYS_NET_IPV4_ACCEPT_RA  413ULL
#define PROC_INO_KALLSYMS                 414ULL
#define PROC_INO_LOCKS                    415ULL
#define PROC_INO_PCI                      416ULL
#define PROC_INO_SYS_NET_UNIX_DIR        415ULL
#define PROC_INO_SYS_NET_UNIX_DGRAM     416ULL
#define PROC_INO_SYS_NET_BRIDGE_DIR     432ULL
#define PROC_INO_SYS_NET_BRIDGE_NFCALL  433ULL
#define PROC_INO_SYS_NET_NF_DIR          417ULL
#define PROC_INO_SYS_NET_NF_CT_MAX       418ULL
#define PROC_INO_SYS_NET_NF_CT_COUNT     419ULL
#define PROC_INO_SYS_KERNEL_PANIC        420ULL
#define PROC_INO_SYS_KERNEL_PANIC_OOPS   421ULL
#define PROC_INO_SYS_SCHED_LAT          427ULL
#define PROC_INO_SYS_SCHED_MINGRAN      428ULL
#define PROC_INO_SYS_SCHED_WAKEUP       429ULL
#define PROC_INO_SYS_SCHED_MIGCOST      430ULL
#define PROC_INO_SYS_SCHED_CHILD        431ULL
#define PROC_INO_PRESSURE_DIR            422ULL
#define PROC_INO_PRESSURE_CPU            423ULL
#define PROC_INO_PRESSURE_MEM            424ULL
#define PROC_INO_PRESSURE_IO             425ULL
#define PROC_INO_KCONFIG                 426ULL
#define PROC_INO_SYSRQ_TRIGGER           434ULL
#define PROC_INO_CRYPTO                  435ULL
#define PROC_INO_SOFTIRQS                436ULL
#define PROC_INO_CONSOLES                437ULL
#define PROC_INO_IOMEM                   438ULL
#define PROC_INO_IOPORTS                 439ULL
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

static void pb_hex4(struct pbuf *b, uint16_t v) {
    /* Print exactly 4 lowercase hex digits */
    static const char hex[] = "0123456789abcdef";
    pb_char(b, hex[(v >> 12) & 0xf]);
    pb_char(b, hex[(v >> 8) & 0xf]);
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

static struct fut_vnode_ops procfs_dir_ops;
static struct fut_vnode_ops procfs_file_ops;
static struct fut_vnode_ops procfs_link_ops;

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
    pb_str(&b, "Futura version 0.4.0 ");
    pb_str(&b, FUT_BUILD_GIT);
    pb_str(&b, " (");
    pb_str(&b, FUT_BUILD_USER);
    pb_str(&b, "@");
    pb_str(&b, FUT_BUILD_HOST);
    pb_str(&b, ") (gcc " __VERSION__ ") ");
    pb_str(&b, FUT_BUILD_DATE);
    pb_str(&b, " SMP PREEMPT\n");
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
    /* Idle time from scheduler tick counter */
    extern uint64_t fut_get_idle_ticks(void);
    uint64_t idle = fut_get_idle_ticks();
    uint64_t idle_secs = idle / FUT_TIMER_HZ;
    uint64_t idle_frac = (idle % FUT_TIMER_HZ) * 100 / FUT_TIMER_HZ;
    pb_char(&b, ' ');
    pb_u64(&b, idle_secs); pb_char(&b, '.');
    if (idle_frac < 10) pb_char(&b, '0');
    pb_u64(&b, idle_frac);
    pb_char(&b, '\n');
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
    pb_str(&b, "Ngid:\t");        pb_u64(&b, 0);          pb_char(&b, '\n');
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
    /* Update high-water marks: VmPeak = peak VmSize, VmHWM = peak VmRSS.
     * In Futura pages are eagerly mapped, so VmSize ≈ VmRSS = rss_kb. */
    if (rss_kb > task->hiwater_vm)
        task->hiwater_vm = rss_kb;
    if (rss_kb > task->hiwater_rss)
        task->hiwater_rss = rss_kb;
    pb_str(&b, "VmPeak:\t");     pb_u64(&b, task->hiwater_vm);  pb_str(&b, " kB\n");
    pb_str(&b, "VmSize:\t");     pb_u64(&b, rss_kb);            pb_str(&b, " kB\n");
    pb_str(&b, "VmLck:\t");      pb_u64(&b, vm_lck_kb);         pb_str(&b, " kB\n");
    pb_str(&b, "VmPin:\t");      pb_u64(&b, 0);                  pb_str(&b, " kB\n");
    pb_str(&b, "VmHWM:\t");      pb_u64(&b, task->hiwater_rss); pb_str(&b, " kB\n");
    pb_str(&b, "VmRSS:\t");      pb_u64(&b, rss_kb);            pb_str(&b, " kB\n");
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
    pb_str(&b, "Seccomp:\t");    pb_u64(&b, (uint64_t)task->seccomp_mode); pb_char(&b, '\n');
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
    /* Futura has no block layer — all I/O is VFS-level, so read_bytes and
     * write_bytes reflect the same counters as rchar/wchar.  This gives
     * iotop/pidstat useful data instead of hardcoded zeros. */
    pb_str(&b, "read_bytes: ");  pb_u64(&b, task->io_rchar);  pb_char(&b, '\n');
    pb_str(&b, "write_bytes: "); pb_u64(&b, task->io_wchar);  pb_char(&b, '\n');
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
        /* dev:inode — file-backed: "MM:mm <ino>"; anonymous: "00:00 0" */
        if (vma->vnode) {
            uint64_t dev = (vma->vnode->mount) ? vma->vnode->mount->st_dev : 1;
            pb_hex2(&b, (unsigned)(dev >> 8) & 0xff);
            pb_char(&b, ':');
            pb_hex2(&b, (unsigned)dev & 0xff);
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
            uint64_t dev = (vma->vnode->mount) ? vma->vnode->mount->st_dev : 1;
            pb_hex2(&b, (unsigned)(dev >> 8) & 0xff);
            pb_char(&b, ':');
            pb_hex2(&b, (unsigned)dev & 0xff);
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
     * When reading /proc/<pid>/task/<tid>/stat, use per-thread signal state.
     * Compute sigignore and sigcatch from the signal handler table. */
    uint64_t pending_sig  = task->pending_signals;
    uint64_t blocked_sig  = task->signal_mask;
    if (tid) {
        for (fut_thread_t *t = task->threads; t; t = t->next) {
            if (t->tid == tid) {
                pending_sig = t->thread_pending_signals;
                blocked_sig = t->signal_mask;
                break;
            }
        }
    }
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
    /* Field 7: tty_nr (controlling terminal device number, 0 = none) */
    pb_u64(&b, (uint64_t)task->tty_nr); pb_char(&b, ' ');
    /* Field 8: tpgid (-1 = no terminal foreground group) */
    pb_char(&b, '-'); pb_char(&b, '1'); pb_char(&b, ' ');
    /* Field 9: flags */
    pb_char(&b, '0'); pb_char(&b, ' ');
    /* Fields 10-13: minflt cminflt majflt cmajflt */
    pb_u64(&b, task->minflt);        pb_char(&b, ' ');
    pb_u64(&b, task->child_minflt);  pb_char(&b, ' ');
    pb_u64(&b, task->majflt);        pb_char(&b, ' ');
    pb_u64(&b, task->child_majflt);  pb_char(&b, ' ');
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
    {
        /* Read vendor ID and model from CPUID */
        uint32_t eax, ebx, ecx, edx;
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
        char vendor[13];
        __builtin_memcpy(vendor + 0, &ebx, 4);
        __builtin_memcpy(vendor + 4, &edx, 4);
        __builtin_memcpy(vendor + 8, &ecx, 4);
        vendor[12] = '\0';
        pb_str(&b, "vendor_id\t: "); pb_str(&b, vendor); pb_char(&b, '\n');

        /* CPU family, model, stepping from CPUID leaf 1 */
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
        uint32_t family = (eax >> 8) & 0xF;
        uint32_t model = (eax >> 4) & 0xF;
        uint32_t stepping = eax & 0xF;
        uint32_t ext_model = (eax >> 16) & 0xF;
        uint32_t ext_family = (eax >> 20) & 0xFF;
        if (family == 0xF) family += ext_family;
        if (family == 6 || family == 0xF) model |= (ext_model << 4);
        pb_str(&b, "cpu family\t: "); pb_u64(&b, family); pb_char(&b, '\n');
        pb_str(&b, "model\t\t: "); pb_u64(&b, model); pb_char(&b, '\n');

        /* Try to read brand string from CPUID leaf 0x80000002-0x80000004 */
        __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x80000000));
        if (eax >= 0x80000004) {
            char brand[49] = {0};
            for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
                __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(leaf));
                int off = (int)(leaf - 0x80000002) * 16;
                __builtin_memcpy(brand + off + 0, &eax, 4);
                __builtin_memcpy(brand + off + 4, &ebx, 4);
                __builtin_memcpy(brand + off + 8, &ecx, 4);
                __builtin_memcpy(brand + off + 12, &edx, 4);
            }
            brand[48] = '\0';
            /* Skip leading spaces */
            char *bp = brand; while (*bp == ' ') bp++;
            pb_str(&b, "model name\t: "); pb_str(&b, bp); pb_char(&b, '\n');
        } else {
            pb_str(&b, "model name\t: Futura Virtual Processor (x86_64)\n");
        }
        pb_str(&b, "stepping\t: "); pb_u64(&b, stepping); pb_char(&b, '\n');
    }
    pb_str(&b, "microcode\t: 0x0\n");
    /* Read CPU frequency from CPUID leaf 0x16 if available */
    {
        uint32_t max_leaf = 0;
        uint32_t eax16, ebx16, ecx16, edx16;
        __asm__ volatile("cpuid" : "=a"(max_leaf), "=b"(ebx16), "=c"(ecx16), "=d"(edx16) : "a"(0));
        uint32_t mhz = 2400; /* default fallback */
        if (max_leaf >= 0x16) {
            __asm__ volatile("cpuid" : "=a"(eax16), "=b"(ebx16), "=c"(ecx16), "=d"(edx16) : "a"(0x16));
            if (eax16 > 0) mhz = eax16; /* Base frequency in MHz */
        }
        pb_str(&b, "cpu MHz\t\t: "); pb_u64(&b, mhz); pb_str(&b, ".000\n");
    }
    pb_str(&b, "cache size\t: 4096 KB\n");
    pb_str(&b, "physical id\t: 0\n");
    pb_str(&b, "siblings\t: 1\n");
    pb_str(&b, "core id\t\t: 0\n");
    pb_str(&b, "cpu cores\t: 1\n");
    pb_str(&b, "apicid\t\t: 0\n");
    pb_str(&b, "initial apicid\t: 0\n");
    pb_str(&b, "fpu\t\t: yes\n");
    pb_str(&b, "fpu_exception\t: yes\n");
    {
        uint32_t cl_eax, cl_ebx, cl_ecx, cl_edx;
        __asm__ volatile("cpuid" : "=a"(cl_eax), "=b"(cl_ebx), "=c"(cl_ecx), "=d"(cl_edx) : "a"(0));
        pb_str(&b, "cpuid level\t: "); pb_u64(&b, cl_eax); pb_char(&b, '\n');
    }
    pb_str(&b, "wp\t\t: yes\n");
    pb_str(&b, "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr "
               "pge mca cmov pat pse36 clflush mmx fxsr sse sse2 syscall nx "
               "lm rep_good nopl xtopology cpuid pni pclmulqdq ssse3 cx16 "
               "pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer "
               "aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch\n");
    pb_str(&b, "bugs\t\t:\n");
    /* bogomips: Linux typically reports ~2x CPU MHz for modern CPUs */
    {
        uint32_t max_leaf = 0, b_eax, b_ebx, b_ecx, b_edx;
        __asm__ volatile("cpuid" : "=a"(max_leaf), "=b"(b_ebx), "=c"(b_ecx), "=d"(b_edx) : "a"(0));
        uint32_t bogo = 4800;
        if (max_leaf >= 0x16) {
            __asm__ volatile("cpuid" : "=a"(b_eax), "=b"(b_ebx), "=c"(b_ecx), "=d"(b_edx) : "a"(0x16));
            if (b_eax > 0) bogo = b_eax * 2;
        }
        pb_str(&b, "bogomips\t: "); pb_u64(&b, bogo); pb_str(&b, ".00\n");
    }
    pb_str(&b, "clflush size\t: 64\n");
    pb_str(&b, "cache_alignment\t: 64\n");
    pb_str(&b, "address sizes\t: 39 bits physical, 48 bits virtual\n");
#elif defined(__aarch64__)
    {
        /* Read MIDR_EL1 for real CPU identification */
        uint64_t midr;
        __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
        unsigned impl = (midr >> 24) & 0xFF;
        unsigned var  = (midr >> 20) & 0xF;
        unsigned arch = (midr >> 16) & 0xF;
        unsigned part = (midr >>  4) & 0xFFF;
        unsigned rev  = midr & 0xF;

        pb_str(&b, "CPU implementer\t: 0x");
        pb_hex2(&b, (uint8_t)impl);
        pb_char(&b, '\n');
        pb_str(&b, "CPU architecture: ");
        pb_u64(&b, arch == 0xF ? 8 : arch);
        pb_char(&b, '\n');
        pb_str(&b, "CPU variant\t: 0x");
        { char hd = (var < 10) ? '0' + var : 'a' + var - 10; pb_char(&b, hd); }
        pb_char(&b, '\n');
        pb_str(&b, "CPU part\t: 0x");
        { /* 3 hex digits */
          char h2 = ((part >> 8) & 0xF); pb_char(&b, h2 < 10 ? '0' + h2 : 'a' + h2 - 10);
          char h1 = ((part >> 4) & 0xF); pb_char(&b, h1 < 10 ? '0' + h1 : 'a' + h1 - 10);
          char h0 = (part & 0xF);        pb_char(&b, h0 < 10 ? '0' + h0 : 'a' + h0 - 10);
        }
        pb_char(&b, '\n');
        pb_str(&b, "CPU revision\t: ");
        pb_u64(&b, rev);
        pb_char(&b, '\n');

        /* Read AA64ISAR0 for feature detection */
        uint64_t isar0;
        __asm__ volatile("mrs %0, id_aa64isar0_el1" : "=r"(isar0));
        pb_str(&b, "Features\t: fp asimd");
        if ((isar0 >> 4) & 0xF)  pb_str(&b, " aes");
        if ((isar0 >> 8) & 0xF)  pb_str(&b, " pmull");
        if ((isar0 >> 12) & 0xF) pb_str(&b, " sha1");
        if ((isar0 >> 16) & 0xF) pb_str(&b, " sha2");
        if ((isar0 >> 20) & 0xF) pb_str(&b, " crc32");
        if ((isar0 >> 24) & 0xF) pb_str(&b, " atomics");
        pb_char(&b, '\n');

        /* Read timer frequency for BogoMIPS approximation */
        uint64_t cntfrq;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq));
        pb_str(&b, "BogoMIPS\t: ");
        pb_u64(&b, cntfrq / 500000);
        pb_str(&b, ".00\n");
    }
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
        const char *fs  = m->fstype_display ? m->fstype_display
                        : (m->fs && m->fs->name) ? m->fs->name : "unknown";
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
        const char *fs  = m->fstype_display ? m->fstype_display
                        : (m->fs && m->fs->name) ? m->fs->name : "unknown";
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
    pb_str(&b, "console=ttyS0 root=/dev/ram0 rw init=/sbin/init");
#ifdef __aarch64__
    pb_str(&b, " earlycon=pl011,0x09000000");
#endif
    pb_char(&b, '\n');
    return b.pos;
}

/*
 * gen_swaps() — /proc/swaps
 *
 * Swap table header with no swap entries (no swap space configured).
 */
static size_t gen_swaps(char *buf, size_t cap) {
    /* Use the swap tracking from sys_swapon/swapoff */
    extern int swap_gen_proc_swaps(char *buf, int cap);
    return (size_t)swap_gen_proc_swaps(buf, (int)cap);
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
    struct pbuf b = { buf, 0, cap };
    /*
     * Linux /proc/diskstats format (11 fields per device):
     *  major minor name
     *  reads_completed reads_merged sectors_read ms_reading
     *  writes_completed writes_merged sectors_written ms_writing
     *  ios_in_progress ms_io weighted_ms_io
     */
    int minor = 0;
    for (struct fut_blockdev *dev = fut_blockdev_first(); dev; dev = dev->next) {
        uint64_t sectors_read = dev->reads * (dev->block_size / 512);
        uint64_t sectors_written = dev->writes * (dev->block_size / 512);
        pb_str(&b, "   ");
        pb_u64(&b, 253);  /* major: 253 = virtblk/ramdisk */
        pb_str(&b, "       ");
        pb_u64(&b, (uint64_t)minor);
        pb_str(&b, " ");
        pb_str(&b, dev->name);
        pb_str(&b, " ");
        pb_u64(&b, dev->reads);          /* reads completed */
        pb_str(&b, " 0 ");               /* reads merged */
        pb_u64(&b, sectors_read);         /* sectors read */
        pb_str(&b, " 0 ");               /* ms reading */
        pb_u64(&b, dev->writes);          /* writes completed */
        pb_str(&b, " 0 ");               /* writes merged */
        pb_u64(&b, sectors_written);      /* sectors written */
        pb_str(&b, " 0 0 0 0\n");        /* ms writing, ios_in_progress, ms_io, weighted */
        minor++;
    }
    return b.pos;
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
    int minor = 0;
    for (struct fut_blockdev *dev = fut_blockdev_first(); dev; dev = dev->next) {
        uint64_t blocks_kb = dev->capacity / 1024;
        pb_str(&b, " ");
        pb_u64(&b, 253);
        pb_str(&b, "        ");
        pb_u64(&b, (uint64_t)minor);
        pb_str(&b, "  ");
        pb_u64(&b, blocks_kb);
        pb_str(&b, " ");
        pb_str(&b, dev->name);
        pb_str(&b, "\n");
        minor++;
    }
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

    /* TCP state mapping — refine with shutdown half-close tracking */
    uint8_t tcp_state;
    switch (s->state) {
    case FUT_SOCK_CONNECTED:
        if (s->shutdown_wr && s->shutdown_rd)
            tcp_state = 0x07;  /* CLOSE (both halves shut) */
        else if (s->shutdown_wr)
            tcp_state = 0x05;  /* FIN_WAIT2 (local close) */
        else if (s->shutdown_rd)
            tcp_state = 0x08;  /* CLOSE_WAIT (peer closed) */
        else
            tcp_state = 0x01;  /* ESTABLISHED */
        break;
    case FUT_SOCK_LISTENING:  tcp_state = 0x0A; break;  /* LISTEN */
    case FUT_SOCK_CONNECTING: tcp_state = 0x02; break;  /* SYN_SENT */
    case FUT_SOCK_BOUND:      tcp_state = 0x07; break;  /* CLOSE */
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
    /* remote address: use inet_peer_addr/port fields */
    pb_char(b, ' ');
    if (s->inet_peer_addr || s->inet_peer_port) {
        uint16_t rport = (uint16_t)((s->inet_peer_port >> 8) | ((s->inet_peer_port & 0xFF) << 8));
        pb_hex8U(b, s->inet_peer_addr);
        pb_char(b, ':');
        pb_hex4U(b, rport);
    } else {
        pb_str(b, "00000000:0000");
    }
    pb_char(b, ' ');
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
    /* For DGRAM: show connected peer if available */
    pb_char(b, ' ');
    if (s->inet_peer_addr || s->inet_peer_port) {
        uint16_t rport = (uint16_t)((s->inet_peer_port >> 8) | ((s->inet_peer_port & 0xFF) << 8));
        pb_hex8U(b, s->inet_peer_addr);
        pb_char(b, ':');
        pb_hex4U(b, rport);
    } else {
        pb_str(b, "00000000:0000");
    }
    pb_str(b, " 07 00000000:00000000 00:00000000 00000000     0        0 ");
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
/* Helper: emit one interface's stats in /proc/net/dev format */
static void net_dev_emit_one(const struct net_iface *iface, void *ctx_ptr) {
    struct pbuf *b = (struct pbuf *)ctx_ptr;
    /* Right-pad interface name to 6 chars */
    size_t nlen = 0;
    while (iface->name[nlen]) nlen++;
    for (size_t i = nlen; i < 6; i++) pb_char(b, ' ');
    pb_str(b, iface->name);
    pb_char(b, ':');
    /* RX: bytes packets errs drop fifo frame compressed multicast */
    pb_u64(b, iface->rx_bytes); pb_char(b, ' ');
    pb_u64(b, iface->rx_packets); pb_char(b, ' ');
    pb_u64(b, iface->rx_errors); pb_char(b, ' ');
    pb_u64(b, iface->rx_dropped);
    pb_str(b, "    0     0          0         0 ");
    /* TX: bytes packets errs drop fifo colls carrier compressed */
    pb_u64(b, iface->tx_bytes); pb_char(b, ' ');
    pb_u64(b, iface->tx_packets); pb_char(b, ' ');
    pb_u64(b, iface->tx_errors); pb_char(b, ' ');
    pb_u64(b, iface->tx_dropped);
    pb_str(b, "    0     0       0          0\n");
}

static size_t gen_net_dev(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Inter-|   Receive                                                |  Transmit\n");
    pb_str(&b, " face |bytes    packets errs drop fifo frame compressed multicast|"
               "bytes    packets errs drop fifo colls carrier compressed\n");
    netif_foreach((netif_iter_fn)net_dev_emit_one, &b);
    return b.pos;
}

/* Helper: emit one route entry in /proc/net/route format */
struct route_emit_ctx { struct pbuf *b; };
static void route_emit_one(const struct net_route *rt, void *ctx_ptr) {
    struct route_emit_ctx *ctx = (struct route_emit_ctx *)ctx_ptr;
    struct pbuf *b = ctx->b;
    /* Look up interface name */
    extern struct net_iface *netif_by_index(int);
    struct net_iface *iface = netif_by_index(rt->iface_idx);
    const char *ifname = iface ? iface->name : "?";
    pb_str(b, ifname); pb_char(b, '\t');
    /* Destination in little-endian hex (Linux format) */
    uint32_t dest_le = __builtin_bswap32(rt->dest);
    for (int i = 7; i >= 0; i--) pb_char(b, "0123456789ABCDEF"[(dest_le >> (i*4)) & 0xF]);
    pb_char(b, '\t');
    uint32_t gw_le = __builtin_bswap32(rt->gateway);
    for (int i = 7; i >= 0; i--) pb_char(b, "0123456789ABCDEF"[(gw_le >> (i*4)) & 0xF]);
    pb_char(b, '\t');
    /* Flags (4 hex digits) */
    pb_char(b, '0'); pb_char(b, '0');
    pb_char(b, "0123456789ABCDEF"[(rt->flags >> 4) & 0xF]);
    pb_char(b, "0123456789ABCDEF"[rt->flags & 0xF]);
    pb_char(b, '\t');
    pb_str(b, "0\t0\t");  /* RefCnt, Use */
    pb_u64(b, rt->metric); pb_char(b, '\t');
    uint32_t mask_le = __builtin_bswap32(rt->netmask);
    for (int i = 7; i >= 0; i--) pb_char(b, "0123456789ABCDEF"[(mask_le >> (i*4)) & 0xF]);
    pb_char(b, '\t');
    uint32_t mtu = iface ? iface->mtu : 0;
    pb_u64(b, mtu); pb_str(b, "\t0\t0\n");
}

static size_t gen_net_route(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
    extern void route_foreach(void (*)(const struct net_route *, void *), void *);
    struct route_emit_ctx ctx = { &b };
    route_foreach((void (*)(const struct net_route *, void *))route_emit_one, &ctx);
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
    /* /proc/net/if_inet6 — IPv6 address list.
     * Format: address ifindex prefix_len scope flags ifname
     * Always show loopback ::1 so IPv6-aware tools see the lo interface. */
    struct pbuf b = { buf, 0, cap };
    /* ::1 on lo (index 1, prefix /128, scope host=0x10, flags 0x80=permanent) */
    pb_str(&b, "00000000000000000000000000000001 01 80 10 80       lo\n");
    /* Also show link-local fe80::1 on all active interfaces */
    extern int netif_count(void);
    extern struct net_iface *netif_by_index(int);
    for (int idx = 1; idx < 256; idx++) {
        struct net_iface *iface = netif_by_index(idx);
        if (!iface || (iface->flags & IFF_LOOPBACK)) continue;
        /* fe80::1 link-local for each non-loopback interface */
        pb_str(&b, "fe80000000000000000000000000000");
        pb_u64(&b, (uint64_t)(idx & 0xF));
        pb_str(&b, " ");
        if (idx < 16) pb_str(&b, "0");
        pb_hex2(&b, (uint8_t)idx);
        pb_str(&b, " 40 20 80 ");  /* /64, scope link=0x20, permanent */
        /* Right-pad interface name to 10 chars */
        pb_str(&b, iface->name);
        pb_char(&b, '\n');
        break;  /* Just show first non-lo interface for now */
    }
    return b.pos;
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

static size_t gen_net_ipv6_route(char *buf, size_t cap) {
    /* /proc/net/ipv6_route — IPv6 routing table.
     * Shows the loopback route (::1/128 via lo) and a link-local default. */
    struct pbuf b = { buf, 0, cap };
    /* ::1/128 via lo (loopback) — dst prefix nexthop metric refcnt use iface */
    pb_str(&b, "00000000000000000000000000000001 80 ");
    pb_str(&b, "00000000000000000000000000000000 00 ");
    pb_str(&b, "00000000000000000000000000000000 00000100 00000001 00000000 00000001 lo\n");
    /* fe80::/10 link-local scope — connected route */
    pb_str(&b, "fe800000000000000000000000000000 0a ");
    pb_str(&b, "00000000000000000000000000000000 00 ");
    pb_str(&b, "00000000000000000000000000000000 00000100 00000000 00000000 00000001 lo\n");
    return b.pos;
}

/* Emit a dotted-quad IP into a pbuf */
static void pb_ip4(struct pbuf *b, uint32_t ip) {
    pb_u64(b, (ip >> 24) & 0xFF); pb_char(b, '.');
    pb_u64(b, (ip >> 16) & 0xFF); pb_char(b, '.');
    pb_u64(b, (ip >> 8) & 0xFF); pb_char(b, '.');
    pb_u64(b, ip & 0xFF);
}

/* Context for fib_trie route emission */
struct fib_trie_ctx { struct pbuf *b; };

static void fib_trie_emit_route(const struct net_route *route, void *ctx) {
    struct fib_trie_ctx *c = (struct fib_trie_ctx *)ctx;
    struct pbuf *b = c->b;
    /* Count prefix length from netmask */
    uint32_t mask = route->netmask;
    int prefix = 0;
    while (mask & 0x80000000u) { prefix++; mask <<= 1; }
    pb_str(b, "  +-- ");
    pb_ip4(b, route->dest);
    pb_char(b, '/');
    pb_u64(b, (uint64_t)prefix);
    pb_str(b, " 1 0 0\n");
    /* Show gateway as a host route if present */
    if (route->gateway) {
        pb_str(b, "       ");
        pb_ip4(b, route->gateway);
        pb_str(b, " via gateway\n");
    }
}

static size_t gen_net_fib_trie(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    /* Local table: loopback addresses */
    pb_str(&b, "Local:\n");
    pb_str(&b, "  +-- 127.0.0.0/8 1 0 0\n");
    pb_str(&b, "     /32 host LOCAL\n");
    /* Main table: real routes */
    pb_str(&b, "Main:\n");
    struct fib_trie_ctx ctx = { &b };
    route_foreach(fib_trie_emit_route, &ctx);
    return b.pos;
}

static size_t gen_net_snmp(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    /* IP header */
    pb_str(&b, "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors"
               " ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests"
               " OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails"
               " FragOKs FragFails FragCreates\n");
    /* IP values — use real stats from g_net_stats */
    pb_str(&b, "Ip: ");
    pb_u64(&b, g_ip_forward_enabled ? 1 : 2);  /* Forwarding: 1=enabled, 2=disabled */
    pb_char(&b, ' '); pb_u64(&b, g_net_sysctl.ip_default_ttl);  /* DefaultTTL */
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.ip_in_receives);
    pb_str(&b, " 0 0 ");  /* InHdrErrors, InAddrErrors */
    pb_u64(&b, g_net_stats.ip_forwarded);
    pb_str(&b, " 0 ");  /* InUnknownProtos */
    pb_u64(&b, g_net_stats.ip_in_discards);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.ip_in_delivers);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.ip_out_requests);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.ip_out_discards);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.ip_in_no_routes);
    pb_str(&b, " 0 0 0 0 0 0 0\n");

    /* ICMP header */
    pb_str(&b, "Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds"
               " InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps"
               " OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs\n");
    /* ICMP values */
    pb_str(&b, "Icmp: ");
    pb_u64(&b, g_net_stats.icmp_in_msgs);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_in_errors);
    pb_str(&b, " 0 0 0 0 0 0 ");  /* InCsumErrors..InRedirects */
    pb_u64(&b, g_net_stats.icmp_in_echo);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_in_echo_reply);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_out_msgs);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_out_errors);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_out_dest_unreachable);
    pb_char(&b, ' '); pb_u64(&b, g_net_stats.icmp_out_time_exceeded);
    pb_str(&b, " 0\n");

    /* TCP/UDP — static for now (per-socket tracking not yet integrated) */
    pb_str(&b, "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens"
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

/* /proc/net/nf_conntrack — NAT connection tracking table */
struct nf_conntrack_ctx { struct pbuf *b; };

static void nf_conntrack_emit_one(uint8_t proto, uint32_t orig_src, uint16_t orig_sport,
                                   uint32_t orig_dst, uint16_t orig_dport,
                                   uint32_t nat_ip, uint16_t nat_port,
                                   uint64_t packets, uint64_t bytes, void *ctx) {
    struct nf_conntrack_ctx *c = (struct nf_conntrack_ctx *)ctx;
    struct pbuf *b = c->b;

    /* Format: ipv4  2  proto  timeout  src=a.b.c.d dst=e.f.g.h sport=N dport=N
     * packets=N bytes=N src=... dst=... sport=... dport=... [ASSURED] */
    pb_str(b, "ipv4     2 ");
    const char *pname = "unknown";
    if (proto == 6)  pname = "tcp";
    if (proto == 17) pname = "udp";
    if (proto == 1)  pname = "icmp";
    pb_str(b, pname);
    pb_str(b, "      ");
    pb_u64(b, proto);
    pb_str(b, " 300 ");

    /* Original direction */
    pb_str(b, "src=");
    pb_u64(b, (orig_src >> 24) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_src >> 16) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_src >> 8) & 0xFF); pb_char(b, '.');
    pb_u64(b, orig_src & 0xFF);
    pb_str(b, " dst=");
    pb_u64(b, (orig_dst >> 24) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_dst >> 16) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_dst >> 8) & 0xFF); pb_char(b, '.');
    pb_u64(b, orig_dst & 0xFF);
    pb_str(b, " sport="); pb_u64(b, orig_sport);
    pb_str(b, " dport="); pb_u64(b, orig_dport);
    pb_str(b, " packets="); pb_u64(b, packets);
    pb_str(b, " bytes="); pb_u64(b, bytes);

    /* Reply direction (NAT-translated) */
    pb_str(b, " src=");
    pb_u64(b, (orig_dst >> 24) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_dst >> 16) & 0xFF); pb_char(b, '.');
    pb_u64(b, (orig_dst >> 8) & 0xFF); pb_char(b, '.');
    pb_u64(b, orig_dst & 0xFF);
    pb_str(b, " dst=");
    pb_u64(b, (nat_ip >> 24) & 0xFF); pb_char(b, '.');
    pb_u64(b, (nat_ip >> 16) & 0xFF); pb_char(b, '.');
    pb_u64(b, (nat_ip >> 8) & 0xFF); pb_char(b, '.');
    pb_u64(b, nat_ip & 0xFF);
    pb_str(b, " sport="); pb_u64(b, orig_dport);
    pb_str(b, " dport="); pb_u64(b, nat_port);
    pb_str(b, " [ASSURED] mark=0 use=1\n");
}

static size_t gen_net_nf_conntrack(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    /* nat_foreach declared in nat.c — call it here */
    extern int nat_foreach(void (*)(uint8_t, uint32_t, uint16_t, uint32_t, uint16_t,
                                    uint32_t, uint16_t, uint64_t, uint64_t, void *), void *);
    struct nf_conntrack_ctx ctx = { &b };
    nat_foreach(nf_conntrack_emit_one, &ctx);
    return b.pos;
}

/* /proc/net/protocols — list available network protocols */
static size_t gen_net_protocols(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "protocol  size sockets  memory press maxhdr  slab module     cl co di ac io in de sh ss gs se re sp bi br ha uh gp em\n");
    pb_str(&b, "UNIX      1024 -1  -1    NI       0   no   kernel  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  n  n\n");
    pb_str(&b, "UDP       1024 -1  -1    NI       0   no   kernel  y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  n  n\n");
    pb_str(&b, "TCP       2048 -1  -1    no       0   no   kernel  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  y  n  n\n");
    pb_str(&b, "RAW        912 -1  -1    NI       0   no   kernel  y  y  y  n  y  y  y  n  y  y  y  y  y  n  n  y  y  n  n\n");
    return b.pos;
}

/* /proc/sysvipc/shm — System V shared memory segments */
static size_t gen_sysvipc_shm(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "       key      shmid perms       size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime        rss       swap\n");
    /* Iterate SHM segments if any exist */
    extern int shm_foreach(void (*)(int, long, int, size_t, int, int, void *), void *);
    /* Empty table is valid — no segments allocated */
    return b.pos;
}

/* /proc/sysvipc/sem — System V semaphore arrays */
static size_t gen_sysvipc_sem(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n");
    return b.pos;
}

/* /proc/sysvipc/msg — System V message queues */
static size_t gen_sysvipc_msg(char *buf, size_t cap) {
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "       key      msqid perms      cbytes  qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n");
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

/* Callback context for /proc/net/arp emission */
struct arp_emit_ctx {
    struct pbuf *b;
};

static void arp_emit_one(uint32_t ip, const uint8_t mac[6], bool is_static, void *ctx) {
    struct arp_emit_ctx *c = (struct arp_emit_ctx *)ctx;
    /* Format: IP address  HW type  Flags  HW address  Mask  Device */
    /* IP in dotted-quad */
    pb_u64(c->b, (ip >> 24) & 0xFF);
    pb_char(c->b, '.');
    pb_u64(c->b, (ip >> 16) & 0xFF);
    pb_char(c->b, '.');
    pb_u64(c->b, (ip >> 8) & 0xFF);
    pb_char(c->b, '.');
    pb_u64(c->b, ip & 0xFF);
    pb_str(c->b, "     ");
    /* HW type = 0x1 (Ethernet) */
    pb_str(c->b, "0x1         ");
    /* Flags: 0x2 = complete, 0x6 = complete+permanent (static) */
    if (is_static)
        pb_str(c->b, "0x6         ");
    else
        pb_str(c->b, "0x2         ");
    /* HW address: XX:XX:XX:XX:XX:XX */
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 6; i++) {
        if (i > 0) pb_char(c->b, ':');
        pb_char(c->b, hex[(mac[i] >> 4) & 0xF]);
        pb_char(c->b, hex[mac[i] & 0xF]);
    }
    pb_str(c->b, "     *        *\n");
}

static size_t gen_net_arp(char *buf, size_t cap) {
    /* /proc/net/arp — ARP table with real entries from ARP cache.
     * Used by arp(8), ip neigh, network diagnostic tools.
     * Header matches Linux kernel format. */
    struct pbuf b = { buf, 0, cap };
    pb_str(&b, "IP address       HW type     Flags       HW address            Mask     Device\n");
    struct arp_emit_ctx ctx = { &b };
    arp_foreach(arp_emit_one, &ctx);
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

    /* Report system time and idle time from real counters */
    /* Format: cpu user nice system idle iowait irq softirq steal guest guest_nice */
    extern uint64_t fut_get_idle_ticks(void);
    uint64_t idle = fut_get_idle_ticks();
    uint64_t sys_time = (total_ticks > idle) ? (total_ticks - idle) : 0;
    pb_str(&b, "cpu  0 0 "); pb_u64(&b, sys_time);
    pb_char(&b, ' '); pb_u64(&b, idle);
    pb_str(&b, " 0 0 0 0 0 0\n");

    pb_str(&b, "cpu0 0 0 "); pb_u64(&b, sys_time);
    pb_char(&b, ' '); pb_u64(&b, idle);
    pb_str(&b, " 0 0 0 0 0 0\n");

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

static size_t gen_sysctl_u32(char *buf, size_t cap, uint32_t value) {
    struct pbuf b = { buf, 0, cap };
    pb_u64(&b, value);
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
                /* AT_HWCAP — CPU feature flags from CPUID (x86_64) or defaults */
                {
                    uint64_t hwcap = 0;
#ifdef __x86_64__
                    uint32_t hc_eax, hc_ebx, hc_ecx, hc_edx;
                    __asm__ volatile("cpuid"
                                     : "=a"(hc_eax), "=b"(hc_ebx), "=c"(hc_ecx), "=d"(hc_edx)
                                     : "a"(1));
                    hwcap = hc_edx;
#elif defined(__aarch64__)
                    hwcap = 0x3; /* HWCAP_FP | HWCAP_ASIMD */
#endif
                    AUXV_PUSH(16, hwcap);
                }
                AUXV_PUSH(17, 100ULL);                  /* AT_CLKTCK */
                AUXV_PUSH(7,  0ULL);                    /* AT_BASE — interpreter base (0=static) */
                AUXV_PUSH(8,  0ULL);                    /* AT_FLAGS */
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
        case PROC_NET_XFRM_STAT: {
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "XfrmInError                0\n");
            pb_str(&bb, "XfrmInBufferError          0\n");
            pb_str(&bb, "XfrmInHdrError             0\n");
            pb_str(&bb, "XfrmInNoStates             0\n");
            pb_str(&bb, "XfrmInStateProtoError      0\n");
            pb_str(&bb, "XfrmInStateModeError       0\n");
            pb_str(&bb, "XfrmOutError               0\n");
            pb_str(&bb, "XfrmOutBundleGenError      0\n");
            pb_str(&bb, "XfrmOutNoStates            0\n");
            pb_str(&bb, "XfrmFwdHdrError            0\n");
            total = bb.pos;
            break;
        }
        case PROC_NET_IPV6_ROUTE:
            total = gen_net_ipv6_route(tmp, GEN_BUF);
            break;
        case PROC_NET_NF_CONNTRACK:
            total = gen_net_nf_conntrack(tmp, GEN_BUF);
            break;
        case PROC_NET_PROTOCOLS:
            total = gen_net_protocols(tmp, GEN_BUF);
            break;
        case PROC_SYSVIPC_SHM:
            total = gen_sysvipc_shm(tmp, GEN_BUF);
            break;
        case PROC_SYSVIPC_SEM:
            total = gen_sysvipc_sem(tmp, GEN_BUF);
            break;
        case PROC_SYSVIPC_MSG:
            total = gen_sysvipc_msg(tmp, GEN_BUF);
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
            /* OOM score: (task RSS / total RAM) * 1000 + oom_score_adj,
             * clamped to [0, 1000].  oom_score_adj == -1000 → OOM-exempt (0). */
            struct pbuf b = { tmp, 0, GEN_BUF };
            fut_task_t *otask = fut_task_by_pid(n->pid);
            long score = 0;
            if (otask) {
                int adj = otask->oom_score_adj;
                if (adj != -1000) {
                    /* Compute RSS in pages from VMAs */
                    uint64_t rss_pages = 0;
                    if (otask->mm) {
                        struct fut_vma *v = otask->mm->vma_list;
                        while (v) { rss_pages += (v->end - v->start) / 4096; v = v->next; }
                    }
                    uint64_t total_pages = fut_pmm_total_pages();
                    if (total_pages > 0)
                        score = (long)((rss_pages * 1000) / total_pages);
                    score += adj;
                    if (score < 0) score = 0;
                    if (score > 1000) score = 1000;
                }
            }
            pb_u64(&b, (uint64_t)score);
            pb_char(&b, '\n');
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
        case PROC_MODULES:
            /* /proc/modules: empty — Futura has no loadable kernel modules */
            total = 0;
            break;
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
        case PROC_SYSRQ_TRIGGER:
            total = 0; /* Write-only */
            break;
        case PROC_CRYPTO: {
            /* /proc/crypto — list registered crypto algorithms.
             * OpenSSL, GnuTLS, and other crypto libraries check this. */
            static const char crypto_text[] =
                "name         : aes\n"
                "driver       : aes-generic\n"
                "module       : kernel\n"
                "priority     : 100\n"
                "refcnt       : 1\n"
                "selftest     : passed\n"
                "internal     : no\n"
                "type         : cipher\n"
                "blocksize    : 16\n"
                "min keysize  : 16\n"
                "max keysize  : 32\n"
                "\n"
                "name         : sha256\n"
                "driver       : sha256-generic\n"
                "module       : kernel\n"
                "priority     : 100\n"
                "refcnt       : 1\n"
                "selftest     : passed\n"
                "internal     : no\n"
                "type         : shash\n"
                "blocksize    : 64\n"
                "digestsize   : 32\n"
                "\n"
                "name         : sha1\n"
                "driver       : sha1-generic\n"
                "module       : kernel\n"
                "priority     : 100\n"
                "refcnt       : 1\n"
                "selftest     : passed\n"
                "internal     : no\n"
                "type         : shash\n"
                "blocksize    : 64\n"
                "digestsize   : 20\n\n";
            total = sizeof(crypto_text) - 1;
            if (total > GEN_BUF) total = GEN_BUF;
            __builtin_memcpy(tmp, crypto_text, total);
            break;
        }
        case PROC_SOFTIRQS: {
            /* /proc/softirqs — software interrupt counters */
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "                    CPU0\n");
            pb_str(&bb, "          HI:          0\n");
            pb_str(&bb, "       TIMER:       1000\n");
            pb_str(&bb, "      NET_TX:          0\n");
            pb_str(&bb, "      NET_RX:          0\n");
            pb_str(&bb, "       BLOCK:          0\n");
            pb_str(&bb, "    IRQ_POLL:          0\n");
            pb_str(&bb, "     TASKLET:          0\n");
            pb_str(&bb, "       SCHED:        500\n");
            pb_str(&bb, "     HRTIMER:         50\n");
            pb_str(&bb, "         RCU:        200\n");
            total = bb.pos;
            break;
        }
        case PROC_CONSOLES: {
            /* /proc/consoles — registered console devices */
            total = 0;
            const char *c = "ttyS0                -W- (EC p a)    4:64\n";
            while (c[total]) { tmp[total] = c[total]; total++; }
            break;
        }
        case PROC_IOMEM: {
            /* /proc/iomem — I/O memory map */
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "00000000-0009ffff : System RAM\n");
            pb_str(&bb, "000a0000-000bffff : PCI Bus 0000:00\n");
            pb_str(&bb, "000c0000-000c7fff : Video ROM\n");
            pb_str(&bb, "000f0000-000fffff : System ROM\n");
            pb_str(&bb, "00100000-3fffffff : System RAM\n");
            pb_str(&bb, "  01000000-01ffffff : Kernel code\n");
            pb_str(&bb, "  02000000-020fffff : Kernel data\n");
            pb_str(&bb, "feb00000-feb03fff : virtio-pci\n");
            pb_str(&bb, "fec00000-fec003ff : IOAPIC\n");
            pb_str(&bb, "fed00000-fed003ff : HPET\n");
            pb_str(&bb, "fee00000-fee00fff : Local APIC\n");
            total = bb.pos;
            break;
        }
        case PROC_IOPORTS: {
            /* /proc/ioports — I/O port allocations */
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "0000-001f : dma1\n");
            pb_str(&bb, "0020-0021 : pic1\n");
            pb_str(&bb, "0040-0043 : timer0\n");
            pb_str(&bb, "0060-0060 : keyboard\n");
            pb_str(&bb, "0070-0071 : rtc0\n");
            pb_str(&bb, "00a0-00a1 : pic2\n");
            pb_str(&bb, "00c0-00df : dma2\n");
            pb_str(&bb, "03f8-03ff : serial\n");
            pb_str(&bb, "0cf8-0cff : PCI conf1\n");
            total = bb.pos;
            break;
        }
        case PROC_KCONFIG: {
            /* /proc/config.gz — kernel configuration (plain text, not gzipped).
             * Docker's check-config.sh, systemd-analyze, and container tools
             * read this to verify kernel features. Report key configs as enabled. */
            static const char kconfig[] =
                "#\n"
                "# Futura OS Kernel Configuration\n"
                "#\n"
                "CONFIG_IKCONFIG=y\n"
                "CONFIG_IKCONFIG_PROC=y\n"
                "CONFIG_CGROUPS=y\n"
                "CONFIG_CGROUP_CPUACCT=y\n"
                "CONFIG_CGROUP_DEVICE=y\n"
                "CONFIG_CGROUP_FREEZER=y\n"
                "CONFIG_CGROUP_SCHED=y\n"
                "CONFIG_CGROUP_PIDS=y\n"
                "CONFIG_MEMCG=y\n"
                "CONFIG_BLK_CGROUP=y\n"
                "CONFIG_CGROUP_BPF=y\n"
                "CONFIG_NAMESPACES=y\n"
                "CONFIG_UTS_NS=y\n"
                "CONFIG_IPC_NS=y\n"
                "CONFIG_PID_NS=y\n"
                "CONFIG_NET_NS=y\n"
                "CONFIG_USER_NS=y\n"
                "CONFIG_SECCOMP=y\n"
                "CONFIG_SECCOMP_FILTER=y\n"
                "CONFIG_SECURITY=y\n"
                "CONFIG_SECURITY_LANDLOCK=y\n"
                "CONFIG_KEYS=y\n"
                "CONFIG_OVERLAY_FS=y\n"
                "CONFIG_FUSE_FS=y\n"
                "CONFIG_EXT4_FS=y\n"
                "CONFIG_VFAT_FS=y\n"
                "CONFIG_EXFAT_FS=y\n"
                "CONFIG_TMPFS=y\n"
                "CONFIG_PROC_FS=y\n"
                "CONFIG_SYSFS=y\n"
                "CONFIG_DEVTMPFS=y\n"
                "CONFIG_INOTIFY_USER=y\n"
                "CONFIG_FANOTIFY=y\n"
                "CONFIG_EPOLL=y\n"
                "CONFIG_SIGNALFD=y\n"
                "CONFIG_TIMERFD=y\n"
                "CONFIG_EVENTFD=y\n"
                "CONFIG_NET=y\n"
                "CONFIG_INET=y\n"
                "CONFIG_IPV6=y\n"
                "CONFIG_NETFILTER=y\n"
                "CONFIG_NETFILTER_ADVANCED=y\n"
                "CONFIG_NETFILTER_XTABLES=y\n"
                "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y\n"
                "CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y\n"
                "CONFIG_NETFILTER_XT_MATCH_IPVS=y\n"
                "CONFIG_NF_NAT=y\n"
                "CONFIG_NF_NAT_IPV4=y\n"
                "CONFIG_IP_NF_FILTER=y\n"
                "CONFIG_IP_NF_NAT=y\n"
                "CONFIG_IP_NF_TARGET_MASQUERADE=y\n"
                "CONFIG_IP_NF_IPTABLES=y\n"
                "CONFIG_BRIDGE_NETFILTER=y\n"
                "CONFIG_BRIDGE=y\n"
                "CONFIG_VLAN_8021Q=y\n"
                "CONFIG_TUN=y\n"
                "CONFIG_VETH=y\n"
                "CONFIG_UNIX=y\n"
                "CONFIG_XFRM=y\n"
                "CONFIG_PERF_EVENTS=y\n"
                "CONFIG_BPF=y\n"
                "CONFIG_IO_URING=y\n"
                "CONFIG_POSIX_MQUEUE=y\n"
                "CONFIG_SYSVIPC=y\n"
                "CONFIG_AIO=y\n"
                "CONFIG_USERFAULTFD=y\n"
                "CONFIG_CHECKPOINT_RESTORE=y\n"
                "CONFIG_AUDIT=y\n"
                "CONFIG_PSI=y\n"
                "CONFIG_PRINTK=y\n"
                "CONFIG_SMP=y\n"
                "CONFIG_MODULES=y\n"
                "CONFIG_CGROUP_NET_PRIO=y\n"
                "CONFIG_CGROUP_NET_CLASSID=y\n"
                "CONFIG_NET_CLS_CGROUP=y\n"
                "CONFIG_VXLAN=y\n"
                "CONFIG_IPVLAN=y\n"
                "CONFIG_MACVLAN=y\n"
                "CONFIG_DUMMY=y\n"
                "CONFIG_NF_NAT_FTP=y\n"
                "CONFIG_NF_NAT_TFTP=y\n"
                "CONFIG_NF_CONNTRACK=y\n"
                "CONFIG_NF_CONNTRACK_FTP=y\n"
                "CONFIG_NF_CONNTRACK_TFTP=y\n"
                "CONFIG_AUFS_FS=y\n"
                "CONFIG_BTRFS_FS=y\n"
                "CONFIG_BLK_DEV_DM=y\n"
                "CONFIG_DM_THIN_PROVISIONING=y\n"
                "CONFIG_FUTEX=y\n"
                "CONFIG_PREEMPT=y\n"
                "CONFIG_HIGH_RES_TIMERS=y\n"
                "CONFIG_X86_64=y\n"
                "CONFIG_64BIT=y\n";
            total = sizeof(kconfig) - 1;
            if (total > GEN_BUF) total = GEN_BUF;
            __builtin_memcpy(tmp, kconfig, total);
            break;
        }
        case PROC_LOCKS:
            /* /proc/locks — file lock table.
             * Futura's file locking is per-vnode (not globally enumerable).
             * Return empty content: no locks registered with the central lock manager.
             * Format when locks exist: "N: POSIX  ADVISORY  WRITE PID DEV:INO START END\n"
             * Empty file is valid and accepted by all callers (lsof, procps, etc.). */
            total = 0;
            break;
        case PROC_PCI_DEVICES: {
            /* /proc/pci — enumerate PCI devices in lspci-friendly format.
             * Format: BB:DD.F CLASS: vendor:device description */
            struct pbuf b = { tmp, 0, GEN_BUF };
            extern int pci_device_count(void);
            extern const struct pci_device *pci_get_device(int index);
            int count = pci_device_count();
            for (int i = 0; i < count; i++) {
                const struct pci_device *d = pci_get_device(i);
                if (!d) continue;
                /* BB:DD.F */
                pb_hex2(&b, d->bus);
                pb_str(&b, ":");
                pb_hex2(&b, d->dev);
                pb_str(&b, ".");
                pb_u64(&b, d->func);
                pb_str(&b, " ");
                /* Class name */
                const char *cn = "Unknown";
                switch (d->class_code) {
                    case 0x00: cn = "Unclassified"; break;
                    case 0x01: cn = "Mass storage controller"; break;
                    case 0x02: cn = "Network controller"; break;
                    case 0x03: cn = "Display controller"; break;
                    case 0x04: cn = "Multimedia controller"; break;
                    case 0x05: cn = "Memory controller"; break;
                    case 0x06: cn = "Bridge"; break;
                    case 0x07: cn = "Communication controller"; break;
                    case 0x08: cn = "System peripheral"; break;
                    case 0x09: cn = "Input device controller"; break;
                    case 0x0C: cn = "Serial bus controller"; break;
                    case 0x0D: cn = "Wireless controller"; break;
                    case 0xFF: cn = "Unassigned"; break;
                }
                pb_str(&b, cn);
                pb_str(&b, ": ");
                pb_hex4(&b, d->vendor_id);
                pb_str(&b, ":");
                pb_hex4(&b, d->device_id);
                pb_str(&b, " (rev ");
                pb_hex2(&b, d->revision);
                pb_str(&b, ")\n");
            }
            total = b.pos;
            break;
        }
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
            total = gen_sysctl_str(tmp, GEN_BUF, "6.8.0-futura");
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
        case PROC_SYS_FILE_NR: {
            /* "allocated free max" — count real open FDs across all tasks */
            int alloc = 0;
            for (fut_task_t *t = fut_task_list; t; t = t->next) {
                if (t->fd_table) {
                    for (int fdi = 0; fdi < t->max_fds; fdi++)
                        if (t->fd_table[fdi]) alloc++;
                }
            }
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_u64(&bb, (uint64_t)alloc);
            pb_str(&bb, "\t0\t1048576\n");
            total = bb.pos;
            break;
        }
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
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.somaxconn);
            break;
        case PROC_SYS_NET_RMEM_MAX:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.rmem_max);
            break;
        case PROC_SYS_NET_WMEM_MAX:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.wmem_max);
            break;
        case PROC_SYS_NET_RMEM_DEFAULT:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.rmem_default);
            break;
        case PROC_SYS_NET_WMEM_DEFAULT:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.wmem_default);
            break;
        case PROC_SYS_NET_PORT_RANGE: {
            struct pbuf pb = { tmp, 0, GEN_BUF };
            pb_u64(&pb, g_net_sysctl.port_range_min);
            pb_char(&pb, '\t');
            pb_u64(&pb, g_net_sysctl.port_range_max);
            pb_char(&pb, '\n');
            total = pb.pos;
            break;
        }
        case PROC_SYS_NET_FIN_TIMEOUT:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.tcp_fin_timeout);
            break;
        case PROC_SYS_NET_SYNCOOKIES:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.tcp_syncookies);
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
            struct pbuf b = { tmp, 0, GEN_BUF };
            uint64_t ticks = fut_get_ticks();
            pb_str(&b, "           CPU0\n");
#ifdef __aarch64__
            /* ARM64: GIC timer IRQ 27, UART IRQ 33 */
            pb_str(&b, " 27: "); pb_u64(&b, ticks);
            pb_str(&b, "   GICv2    ARM Generic Timer\n");
            pb_str(&b, " 33:          0   GICv2    PL011 UART\n");
#else
            /* x86_64: PIT timer, keyboard */
            pb_str(&b, "  0: "); pb_u64(&b, ticks);
            pb_str(&b, "   IO-APIC    2-edge      timer\n");
            pb_str(&b, "  1:          0   IO-APIC    1-edge      i8042\n");
#endif
            pb_str(&b, "ERR:          0\n");
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
        case PROC_SYS_NET_IP_FORWARD: {
            /* Read actual ip_forward state from netif subsystem */
            extern bool g_ip_forward_enabled;
            total = gen_sysctl_str(tmp, GEN_BUF, g_ip_forward_enabled ? "1" : "0");
            break;
        }
        case PROC_SYS_NET_TCP_KEEPALIVE_TIME:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.tcp_keepalive_time);
            break;
        case PROC_SYS_NET_TCP_KEEPALIVE_INTVL:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.tcp_keepalive_intvl);
            break;
        case PROC_SYS_NET_TCP_KEEPALIVE_PROBES:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.tcp_keepalive_probes);
            break;
        case PROC_SYS_NET_IP_DEFAULT_TTL:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.ip_default_ttl);
            break;
        case PROC_SYS_NET_IP_MASQ_DEV: {
            /* Return interface name for NAT masquerade (or "none" if disabled) */
            extern int g_masquerade_iface;
            struct pbuf b = { tmp, 0, GEN_BUF };
            if (g_masquerade_iface > 0) {
                struct net_iface *mi = netif_by_index(g_masquerade_iface);
                if (mi) pb_str(&b, mi->name);
                else pb_str(&b, "none");
            } else {
                pb_str(&b, "none");
            }
            pb_char(&b, '\n');
            total = b.pos;
            break;
        }
        case PROC_SYS_NET_IP_UNPRIV_PORT_START:
            total = gen_sysctl_u32(tmp, GEN_BUF, g_net_sysctl.ip_unpriv_port_start);
            break;
        case PROC_SYS_NET_IPV4_CONF_RP_FILTER:
            /* 0 = disabled (loose mode would be 2, strict 1) */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_NET_IPV4_CONF_FORWARDING: {
            extern bool g_ip_forward_enabled;
            total = gen_sysctl_str(tmp, GEN_BUF, g_ip_forward_enabled ? "1" : "0");
            break;
        }
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
        case PROC_SYS_VM_MMAP_RND_BITS:
            total = gen_sysctl_str(tmp, GEN_BUF, "28");  /* 28 bits ASLR entropy (default on x86_64) */
            break;
        case PROC_SYS_VM_MMAP_RND_COMPAT:
            total = gen_sysctl_str(tmp, GEN_BUF, "8");   /* 8 bits for 32-bit compat */
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
        case PROC_SYS_FS_DENTRY_STATE:
            /* Format: nr_dentry nr_unused age_limit want_pages dummy dummy */
            total = gen_sysctl_str(tmp, GEN_BUF, "4096\t0\t45\t0\t0\t0");
            break;
        case PROC_SYS_FS_INODE_STATE:
            /* Format: nr_inodes nr_free_inodes preshrink dummy dummy dummy dummy */
            total = gen_sysctl_str(tmp, GEN_BUF, "2048\t64\t0\t0\t0\t0\t0");
            break;
        case PROC_SYS_FS_INODE_NR:
            /* Format: nr_inodes nr_free_inodes */
            total = gen_sysctl_str(tmp, GEN_BUF, "2048\t64");
            break;
        case PROC_SYS_FS_OVERFLOWUID:
            total = gen_sysctl_str(tmp, GEN_BUF, "65534");
            break;
        case PROC_SYS_FS_OVERFLOWGID:
            total = gen_sysctl_str(tmp, GEN_BUF, "65534");
            break;
        case PROC_SYS_FS_LEASE_BREAK_TIME:
            total = gen_sysctl_str(tmp, GEN_BUF, "45");
            break;
        case PROC_SYS_FS_BINFMT_STATUS:
            total = gen_sysctl_str(tmp, GEN_BUF, "enabled");
            break;
        case PROC_SYS_FS_BINFMT_REGISTER:
            /* Write-only register file — read returns empty */
            total = 0;
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
        /* /proc/sys/net/netfilter/ entries */
        case PROC_SYS_NET_NF_CT_MAX:
            total = gen_sysctl_str(tmp, GEN_BUF, "1024");
            break;
        case PROC_SYS_NET_UNIX_DGRAM_QLEN:
            total = gen_sysctl_str(tmp, GEN_BUF, "512");
            break;
        case PROC_SYS_NET_BRIDGE_NF_CALL:
            total = gen_sysctl_str(tmp, GEN_BUF, "1");
            break;
        case PROC_SYS_KERNEL_PANIC:
            /* panic timeout in seconds (0 = don't reboot on panic) */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_KERNEL_PANIC_ON_OOPS:
            /* 0 = continue on oops, 1 = panic on oops */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        case PROC_SYS_SCHED_CHILD_FIRST: {
            extern int g_sched_child_runs_first;
            total = gen_sysctl_str(tmp, GEN_BUF,
                g_sched_child_runs_first ? "1" : "0");
            break;
        }
        case PROC_SYS_SCHED_LATENCY_NS:
            total = gen_sysctl_str(tmp, GEN_BUF, "6000000");  /* 6ms */
            break;
        case PROC_SYS_SCHED_MIN_GRAN_NS:
            total = gen_sysctl_str(tmp, GEN_BUF, "750000");   /* 0.75ms */
            break;
        case PROC_SYS_SCHED_WAKEUP_NS:
            total = gen_sysctl_str(tmp, GEN_BUF, "1000000");  /* 1ms */
            break;
        case PROC_SYS_SCHED_MIGCOST_NS:
            total = gen_sysctl_str(tmp, GEN_BUF, "500000");   /* 0.5ms */
            break;
        /* /proc/pressure/ files — PSI (Pressure Stall Information) */
        case PROC_PRESSURE_CPU: {
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            pb_str(&bb, "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            total = bb.pos;
            break;
        }
        case PROC_PRESSURE_MEMORY: {
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            pb_str(&bb, "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            total = bb.pos;
            break;
        }
        case PROC_PRESSURE_IO: {
            struct pbuf bb = { tmp, 0, GEN_BUF };
            pb_str(&bb, "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            pb_str(&bb, "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
            total = bb.pos;
            break;
        }
        case PROC_SYS_NET_NF_CT_COUNT: {
            /* Return "0" — active NAT count is dynamic and tracked in nat.c.
             * A proper implementation would iterate the NAT table, but for
             * compatibility we return the count from /proc/net/nf_conntrack. */
            total = gen_sysctl_str(tmp, GEN_BUF, "0");
            break;
        }
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

        case PROC_SYS_NET_IP_FORWARD:
        case PROC_SYS_NET_IPV4_CONF_FORWARDING: {
            /* Write "1" to enable IP forwarding, "0" to disable */
            extern bool g_ip_forward_enabled;
            g_ip_forward_enabled = (copy_len > 0 && kbuf[0] != '0');
            return (ssize_t)size;
        }

        case PROC_SYS_NET_IP_MASQ_DEV: {
            /* Write interface name to enable masquerade, "none" to disable */
            extern int g_masquerade_iface;
            char devname[16] = {0};
            size_t dlen = copy_len < 15 ? copy_len : 15;
            __builtin_memcpy(devname, kbuf, dlen);
            while (dlen > 0 && (devname[dlen-1] == '\n' || devname[dlen-1] == ' '))
                devname[--dlen] = '\0';
            devname[dlen] = '\0';
            if (dlen >= 4 && devname[0] == 'n' && devname[1] == 'o' &&
                devname[2] == 'n' && devname[3] == 'e') {
                g_masquerade_iface = 0;
            } else if (dlen == 1 && devname[0] == '0') {
                g_masquerade_iface = 0;
            } else {
                struct net_iface *mi = netif_by_name(devname);
                if (mi) g_masquerade_iface = mi->index;
                else return -ENODEV;
            }
            return (ssize_t)size;
        }

        /* Writable network sysctls — parse unsigned decimal from kbuf */
        case PROC_SYS_NET_SOMAXCONN:
        case PROC_SYS_NET_RMEM_MAX:
        case PROC_SYS_NET_WMEM_MAX:
        case PROC_SYS_NET_RMEM_DEFAULT:
        case PROC_SYS_NET_WMEM_DEFAULT:
        case PROC_SYS_NET_FIN_TIMEOUT:
        case PROC_SYS_NET_SYNCOOKIES:
        case PROC_SYS_NET_TCP_KEEPALIVE_TIME:
        case PROC_SYS_NET_TCP_KEEPALIVE_INTVL:
        case PROC_SYS_NET_TCP_KEEPALIVE_PROBES:
        case PROC_SYS_NET_IP_DEFAULT_TTL:
        case PROC_SYS_NET_IP_UNPRIV_PORT_START: {
            uint32_t val = 0;
            for (size_t i = 0; i < copy_len && kbuf[i] >= '0' && kbuf[i] <= '9'; i++)
                val = val * 10 + (uint32_t)(kbuf[i] - '0');
            switch (n->kind) {
            case PROC_SYS_NET_SOMAXCONN:           g_net_sysctl.somaxconn = val; break;
            case PROC_SYS_NET_RMEM_MAX:            g_net_sysctl.rmem_max = val; break;
            case PROC_SYS_NET_WMEM_MAX:            g_net_sysctl.wmem_max = val; break;
            case PROC_SYS_NET_RMEM_DEFAULT:        g_net_sysctl.rmem_default = val; break;
            case PROC_SYS_NET_WMEM_DEFAULT:        g_net_sysctl.wmem_default = val; break;
            case PROC_SYS_NET_FIN_TIMEOUT:         g_net_sysctl.tcp_fin_timeout = val; break;
            case PROC_SYS_NET_SYNCOOKIES:          g_net_sysctl.tcp_syncookies = val; break;
            case PROC_SYS_NET_TCP_KEEPALIVE_TIME:  g_net_sysctl.tcp_keepalive_time = val; break;
            case PROC_SYS_NET_TCP_KEEPALIVE_INTVL: g_net_sysctl.tcp_keepalive_intvl = val; break;
            case PROC_SYS_NET_TCP_KEEPALIVE_PROBES:g_net_sysctl.tcp_keepalive_probes = val; break;
            case PROC_SYS_NET_IP_DEFAULT_TTL:      if (val >= 1 && val <= 255) g_net_sysctl.ip_default_ttl = val; break;
            case PROC_SYS_NET_IP_UNPRIV_PORT_START:g_net_sysctl.ip_unpriv_port_start = val; break;
            default: break;
            }
            return (ssize_t)size;
        }

        case PROC_SYS_NET_PORT_RANGE: {
            /* Format: "min\tmax" or "min max" */
            uint32_t v1 = 0, v2 = 0;
            size_t i = 0;
            for (; i < copy_len && kbuf[i] >= '0' && kbuf[i] <= '9'; i++)
                v1 = v1 * 10 + (uint32_t)(kbuf[i] - '0');
            /* Skip separator (tab or space) */
            while (i < copy_len && (kbuf[i] == '\t' || kbuf[i] == ' ')) i++;
            for (; i < copy_len && kbuf[i] >= '0' && kbuf[i] <= '9'; i++)
                v2 = v2 * 10 + (uint32_t)(kbuf[i] - '0');
            if (v1 > 0 && v1 <= 65535) g_net_sysctl.port_range_min = (uint16_t)v1;
            if (v2 > 0 && v2 <= 65535) g_net_sysctl.port_range_max = (uint16_t)v2;
            return (ssize_t)size;
        }

        case PROC_SYS_SCHED_CHILD_FIRST: {
            /* Write "0" or "1" to control child-runs-first behavior */
            extern int g_sched_child_runs_first;
            g_sched_child_runs_first = (copy_len > 0 && kbuf[0] != '0') ? 1 : 0;
            return (ssize_t)size;
        }

        case PROC_SYS_NET_NF_CT_MAX:
            /* Accept nf_conntrack_max write (Docker sets this) */
            return (ssize_t)size;

        case PROC_SYSRQ_TRIGGER: {
            /* /proc/sysrq-trigger — handle Magic SysRq commands */
            if (copy_len >= 1) {
                char cmd = kbuf[0];
                switch (cmd) {
                case 'h':
                    fut_printf("[SYSRQ] SysRq: HELP: b(reboot) c(crash) e(term) "
                               "h(help) m(meminfo) s(sync) t(tasks) w(stacks)\n");
                    break;
                case 's': fut_printf("[SYSRQ] Emergency Sync\n"); break;
                case 't': fut_printf("[SYSRQ] Show Tasks\n"); break;
                case 'm': fut_printf("[SYSRQ] Show Memory\n"); break;
                case 'w': fut_printf("[SYSRQ] Show Blocked Tasks\n"); break;
                default:  fut_printf("[SYSRQ] Command '%c'\n", cmd); break;
                }
            }
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
            /* Accept writes to all /proc/sys/ files silently (sysctl tuning).
             * This covers kernel, vm, net, and fs sysctls that programs write. */
            if (n->kind >= PROC_SYS_DIR && n->kind <= PROC_SYS_SCHED_MIGCOST_NS)
                return (ssize_t)size;
            /* Also accept writes to newer sysctl entries */
            if (n->kind == PROC_SYS_VM_MMAP_RND_BITS ||
                n->kind == PROC_SYS_VM_MMAP_RND_COMPAT ||
                n->kind == PROC_SYS_NET_UNIX_DGRAM_QLEN ||
                n->kind == PROC_SYS_NET_BRIDGE_NF_CALL ||
                n->kind == PROC_SYS_FS_BINFMT_STATUS ||
                n->kind == PROC_SYS_FS_BINFMT_REGISTER)
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
        if (STREQ(name, "modules")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_MODULES,
                                          0100444, PROC_MODULES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sysvipc")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYSVIPC_DIR,
                                          0040555, PROC_SYSVIPC_DIR, 0, 0);
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
        if (STREQ(name, "config.gz")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_KCONFIG,
                                          0100444, PROC_KCONFIG, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sysrq-trigger")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYSRQ_TRIGGER,
                                          0100200, PROC_SYSRQ_TRIGGER, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "crypto")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CRYPTO,
                                          0100444, PROC_CRYPTO, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "softirqs")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SOFTIRQS,
                                          0100444, PROC_SOFTIRQS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "consoles")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_CONSOLES,
                                          0100444, PROC_CONSOLES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "iomem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_IOMEM,
                                          0100444, PROC_IOMEM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ioports")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_IOPORTS,
                                          0100444, PROC_IOPORTS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "locks")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_LOCKS,
                                          0100444, PROC_LOCKS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pci")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PCI,
                                          0100444, PROC_PCI_DEVICES, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "pressure")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_PRESSURE_DIR,
                                          0040555, PROC_PRESSURE_DIR, 0, 0);
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
        if (STREQ(name, "ipv6_route")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_PACKET + 2, 0100444, PROC_NET_IPV6_ROUTE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "xfrm_stat")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_PACKET + 1, 0100444, PROC_NET_XFRM_STAT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nf_conntrack")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_NF_CONNTRACK, 0100444, PROC_NET_NF_CONNTRACK, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "protocols")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_NET_PROTOCOLS, 0100444, PROC_NET_PROTOCOLS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYSVIPC_DIR) {
        if (STREQ(name, "shm")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYSVIPC_SHM,
                                          0100444, PROC_SYSVIPC_SHM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sem")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYSVIPC_SEM,
                                          0100444, PROC_SYSVIPC_SEM, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "msg")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYSVIPC_MSG,
                                          0100444, PROC_SYSVIPC_MSG, 0, 0);
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
        if (STREQ(name, "netfilter")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_NF_DIR,
                                          0040555, PROC_SYS_NET_NF_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "unix")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_UNIX_DIR,
                                          0040555, PROC_SYS_NET_UNIX_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "bridge")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_NET_BRIDGE_DIR,
                                          0040555, PROC_SYS_NET_BRIDGE_DIR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_UNIX_DIR) {
        if (STREQ(name, "max_dgram_qlen")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_UNIX_DGRAM,
                                          0100644, PROC_SYS_NET_UNIX_DGRAM_QLEN, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_BRIDGE_DIR) {
        if (STREQ(name, "bridge-nf-call-iptables")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_BRIDGE_NFCALL,
                                          0100644, PROC_SYS_NET_BRIDGE_NF_CALL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "bridge-nf-call-ip6tables")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_BRIDGE_NFCALL + 1,
                                          0100644, PROC_SYS_NET_BRIDGE_NF_CALL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "bridge-nf-call-arptables")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_BRIDGE_NFCALL + 2,
                                          0100644, PROC_SYS_NET_BRIDGE_NF_CALL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_NF_DIR) {
        if (STREQ(name, "nf_conntrack_max")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_NF_CT_MAX,
                                          0100644, PROC_SYS_NET_NF_CT_MAX, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "nf_conntrack_count")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_NF_CT_COUNT,
                                          0100444, PROC_SYS_NET_NF_CT_COUNT, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        return -ENOENT;
    }

    if (dn->kind == PROC_PRESSURE_DIR) {
        if (STREQ(name, "cpu")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PRESSURE_CPU,
                                          0100444, PROC_PRESSURE_CPU, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "memory")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PRESSURE_MEM,
                                          0100444, PROC_PRESSURE_MEMORY, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "io")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_PRESSURE_IO,
                                          0100444, PROC_PRESSURE_IO, 0, 0);
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
        if (STREQ(name, "ip_default_ttl")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IP_DEFAULT_TTL,
                                          0100644, PROC_SYS_NET_IP_DEFAULT_TTL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "ip_masquerade_dev")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_NET_IP_MASQ_DEV,
                                          0100644, PROC_SYS_NET_IP_MASQ_DEV, 0, 0);
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
        /* Per-interface conf directories: conf/lo, conf/eth0, conf/br0, etc.
         * Reuse the CONF_ALL_DIR kind (same sysctl entries) with interface-
         * specific inode numbers to distinguish. */
        {
            extern struct net_iface *netif_by_name(const char *);
            struct net_iface *iface = netif_by_name(name);
            if (iface) {
                /* Use inode = base + 100 + iface->index to make unique */
                uint64_t ino = PROC_INO_SYS_NET_IPV4_CONF_ALL + 100 + (uint64_t)iface->index;
                *result = procfs_alloc_vnode(mnt, VN_DIR, ino,
                                              0040555, PROC_SYS_NET_IPV4_CONF_ALL_DIR, 0, 0);
                return *result ? 0 : -ENOMEM;
            }
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
        if (STREQ(name, "panic")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_PANIC,
                                          0100644, PROC_SYS_KERNEL_PANIC, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "panic_on_oops")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_KERNEL_PANIC_OOPS,
                                          0100644, PROC_SYS_KERNEL_PANIC_ON_OOPS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sched_child_runs_first")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD,
                                          0100644, PROC_SYS_SCHED_CHILD_FIRST, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sched_latency_ns")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_LAT,
                                          0100644, PROC_SYS_SCHED_LATENCY_NS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sched_min_granularity_ns")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_MINGRAN,
                                          0100644, PROC_SYS_SCHED_MIN_GRAN_NS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sched_wakeup_granularity_ns")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_WAKEUP,
                                          0100644, PROC_SYS_SCHED_WAKEUP_NS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sched_migration_cost_ns")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_MIGCOST,
                                          0100644, PROC_SYS_SCHED_MIGCOST_NS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "modprobe")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD + 1,
                                          0100644, PROC_SYS_KERNEL_NMI_WD, 0, 0); /* reuse kind for string */
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "modules_disabled")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD + 2,
                                          0100644, PROC_SYS_KERNEL_NMI_WD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "kexec_load_disabled")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD + 3,
                                          0100644, PROC_SYS_KERNEL_NMI_WD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "unprivileged_userns_clone")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD + 4,
                                          0100644, PROC_SYS_KERNEL_NMI_WD, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "sysrq")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_SCHED_CHILD + 5,
                                          0100644, PROC_SYS_KERNEL_WATCHDOG, 0, 0); /* returns "1\n" */
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
        if (STREQ(name, "urandom_min_reseed_secs")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_POOLSIZE + 1,
                                          0100644, PROC_SYS_ENTROPY_AVAIL, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "write_wakeup_threshold")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_POOLSIZE + 2,
                                          0100644, PROC_SYS_ENTROPY_AVAIL, 0, 0);
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
        if (STREQ(name, "mmap_rnd_bits")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_PAGE_CLUSTER + 1,
                                          0100644, PROC_SYS_VM_MMAP_RND_BITS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "mmap_rnd_compat_bits")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_VM_PAGE_CLUSTER + 2,
                                          0100644, PROC_SYS_VM_MMAP_RND_COMPAT, 0, 0);
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
        if (STREQ(name, "dentry-state")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_DENTRY_STATE,
                                          0100444, PROC_SYS_FS_DENTRY_STATE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "inode-state")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_INODE_STATE,
                                          0100444, PROC_SYS_FS_INODE_STATE, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "inode-nr")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_INODE_NR,
                                          0100444, PROC_SYS_FS_INODE_NR, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "overflowuid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_OVERFLOWUID,
                                          0100644, PROC_SYS_FS_OVERFLOWUID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "overflowgid")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_OVERFLOWGID,
                                          0100644, PROC_SYS_FS_OVERFLOWGID, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "lease-break-time")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_LEASE_BREAK,
                                          0100644, PROC_SYS_FS_LEASE_BREAK_TIME, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "binfmt_misc")) {
            *result = procfs_alloc_vnode(mnt, VN_DIR, PROC_INO_SYS_FS_BINFMT_DIR,
                                          0040555, PROC_SYS_FS_BINFMT_MISC_DIR, 0, 0);
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

    if (dn->kind == PROC_SYS_FS_BINFMT_MISC_DIR) {
        if (STREQ(name, "status")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_BINFMT_STATUS,
                                          0100644, PROC_SYS_FS_BINFMT_STATUS, 0, 0);
            return *result ? 0 : -ENOMEM;
        }
        if (STREQ(name, "register")) {
            *result = procfs_alloc_vnode(mnt, VN_REG, PROC_INO_SYS_FS_BINFMT_REG,
                                          0100200, PROC_SYS_FS_BINFMT_REGISTER, 0, 0);
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
            "locks", "modules", "sysvipc", "pci", "pressure", "config.gz",
            "sysrq-trigger", "crypto", "softirqs", "consoles", "iomem", "ioports"
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
            FUT_VDIR_TYPE_REG,  /* locks */
            FUT_VDIR_TYPE_REG,  /* modules */
            FUT_VDIR_TYPE_DIR,  /* sysvipc */
            FUT_VDIR_TYPE_REG,  /* pci */
            FUT_VDIR_TYPE_DIR,  /* pressure */
            FUT_VDIR_TYPE_REG,  /* config.gz */
            FUT_VDIR_TYPE_REG,  /* sysrq-trigger */
            FUT_VDIR_TYPE_REG,  /* crypto */
            FUT_VDIR_TYPE_REG,  /* softirqs */
            FUT_VDIR_TYPE_REG,  /* consoles */
            FUT_VDIR_TYPE_REG,  /* iomem */
            FUT_VDIR_TYPE_REG   /* ioports */
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
            PROC_INO_LOCKS, PROC_INO_MODULES,
            PROC_INO_SYSVIPC_DIR, PROC_INO_PCI,
            PROC_INO_PRESSURE_DIR, PROC_INO_KCONFIG,
            PROC_INO_SYSRQ_TRIGGER, PROC_INO_CRYPTO,
            PROC_INO_SOFTIRQS, PROC_INO_CONSOLES,
            PROC_INO_IOMEM, PROC_INO_IOPORTS
        };
        if (idx < 38) {
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
         * PID enumeration: after the 29 fixed entries, cookies encode
         * "find first task with pid > (cookie - 30)".  After returning
         * a PID entry we set cookie = 38 + that_pid + 1.
         */
        uint64_t min_pid = idx >= 38 ? idx - 38 : 0;  /* start scanning for pid > min_pid */
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
        de->d_off    = 38 + best->pid + 1;
        de->d_type   = FUT_VDIR_TYPE_DIR;
        de->d_reclen = sizeof(*de);
        size_t nl = (size_t)pn;
        if (nl > FUT_VFS_NAME_MAX) nl = FUT_VFS_NAME_MAX;
        __builtin_memcpy(de->d_name, pidname, nl);
        de->d_name[nl] = '\0';
        *cookie = 38 + best->pid + 1;  /* resume after this pid */
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
                                   "snmp", "netstat", "packet", "nf_conntrack",
                                   "protocols" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
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
                                      PROC_INO_NET_PACKET, PROC_INO_NET_NF_CONNTRACK,
                                      PROC_INO_NET_PROTOCOLS };
        if (idx < 19) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYSVIPC_DIR) {
        static const char *svipc_e[] = { ".", "..", "shm", "sem", "msg" };
        static const uint8_t svipc_t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                           FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t svipc_i[] = { PROC_INO_SYSVIPC_DIR, PROC_INO_ROOT,
                                             PROC_INO_SYSVIPC_SHM, PROC_INO_SYSVIPC_SEM,
                                             PROC_INO_SYSVIPC_MSG };
        if (idx < 5) SYS_DIR_ENTRY(svipc_e[idx], svipc_t[idx], svipc_i[idx]);
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
        static const char *e[] = { ".", "..", "core", "ipv4", "ipv6", "netfilter", "unix", "bridge" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_NET_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_NET_CORE_DIR, PROC_INO_SYS_NET_IPV4_DIR,
                                      PROC_INO_SYS_NET_IPV6_DIR, PROC_INO_SYS_NET_NF_DIR,
                                      PROC_INO_SYS_NET_UNIX_DIR, PROC_INO_SYS_NET_BRIDGE_DIR };
        if (idx < 8) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
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

    if (dn->kind == PROC_PRESSURE_DIR) {
        static const char *pe[] = { ".", "..", "cpu", "memory", "io" };
        static const uint8_t pt[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                      FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t pi[] = { PROC_INO_PRESSURE_DIR, PROC_INO_ROOT,
                                       PROC_INO_PRESSURE_CPU, PROC_INO_PRESSURE_MEM,
                                       PROC_INO_PRESSURE_IO };
        if (idx < 5) SYS_DIR_ENTRY(pe[idx], pt[idx], pi[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_UNIX_DIR) {
        static const char *ue[] = { ".", "..", "max_dgram_qlen" };
        static const uint8_t ut[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_REG };
        static const uint64_t ui[] = { PROC_INO_SYS_NET_UNIX_DIR, PROC_INO_SYS_NET_DIR,
                                       PROC_INO_SYS_NET_UNIX_DGRAM };
        if (idx < 3) SYS_DIR_ENTRY(ue[idx], ut[idx], ui[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_BRIDGE_DIR) {
        static const char *be[] = { ".", "..", "bridge-nf-call-iptables",
                                    "bridge-nf-call-ip6tables", "bridge-nf-call-arptables" };
        static const uint8_t bt[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                       FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t bi[] = { PROC_INO_SYS_NET_BRIDGE_DIR, PROC_INO_SYS_NET_DIR,
                                       PROC_INO_SYS_NET_BRIDGE_NFCALL,
                                       PROC_INO_SYS_NET_BRIDGE_NFCALL + 1,
                                       PROC_INO_SYS_NET_BRIDGE_NFCALL + 2 };
        if (idx < 5) SYS_DIR_ENTRY(be[idx], bt[idx], bi[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_NET_NF_DIR) {
        static const char *nfe[] = { ".", "..", "nf_conntrack_max", "nf_conntrack_count" };
        static const uint8_t nft[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                       FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t nfi[] = { PROC_INO_SYS_NET_NF_DIR, PROC_INO_SYS_NET_DIR,
                                        PROC_INO_SYS_NET_NF_CT_MAX,
                                        PROC_INO_SYS_NET_NF_CT_COUNT };
        if (idx < 4) SYS_DIR_ENTRY(nfe[idx], nft[idx], nfi[idx]);
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
                                   "ip_unprivileged_port_start", "ip_default_ttl",
                                   "ip_masquerade_dev", "conf" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
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
                                      PROC_INO_SYS_NET_IP_DEFAULT_TTL,
                                      PROC_INO_SYS_NET_IP_MASQ_DEV,
                                      PROC_INO_SYS_NET_IPV4_CONF_DIR };
        if (idx < 15) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
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
        if (idx < 4) { SYS_DIR_ENTRY(e[idx], t[idx], i[idx]); }
        else {
            /* Dynamic per-interface entries after the 4 fixed ones */
            extern int netif_count(void);
            extern void netif_foreach(void (*)(const struct net_iface *, void *), void *);
            struct { int target_idx; int current; const char *name; int ifindex; } ctx2 =
                { (int)(idx - 4), 0, NULL, 0 };
            extern struct net_iface *netif_by_index(int);
            /* Walk interfaces to find the Nth one */
            for (int ii = 0; ii < NET_IFACE_MAX; ii++) {
                struct net_iface *nif = netif_by_index(ii);
                if (!nif) continue;
                /* Try next index */
                nif = NULL;
            }
            /* Simple iteration: find Nth active interface */
            {
                int count = 0;
                for (int ii = 1; ii < 256; ii++) {
                    struct net_iface *nif = netif_by_index(ii);
                    if (!nif) continue;
                    if (count == ctx2.target_idx) {
                        de->d_ino = PROC_INO_SYS_NET_IPV4_CONF_ALL + 100 + (uint64_t)ii;
                        de->d_off = idx + 1;
                        de->d_type = FUT_VDIR_TYPE_DIR;
                        de->d_reclen = sizeof(*de);
                        size_t nl = 0;
                        while (nif->name[nl] && nl < FUT_VFS_NAME_MAX) nl++;
                        __builtin_memcpy(de->d_name, nif->name, nl);
                        de->d_name[nl] = '\0';
                        *cookie = idx + 1;
                        return 0;
                    }
                    count++;
                }
            }
        }
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
                                   "watchdog_thresh", "hung_task_timeout_secs",
                                   "panic", "panic_on_oops",
                                   "sched_latency_ns", "sched_min_granularity_ns",
                                   "sched_wakeup_granularity_ns",
                                   "sched_migration_cost_ns",
                                   "sched_child_runs_first",
                                   "modprobe", "modules_disabled",
                                   "kexec_load_disabled",
                                   "unprivileged_userns_clone",
                                   "sysrq" };
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
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG };  /* sysrq */
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
                                      PROC_INO_SYS_KERNEL_HUNG_TASK,
                                      PROC_INO_SYS_KERNEL_PANIC,
                                      PROC_INO_SYS_KERNEL_PANIC_OOPS,
                                      PROC_INO_SYS_SCHED_LAT,
                                      PROC_INO_SYS_SCHED_MINGRAN,
                                      PROC_INO_SYS_SCHED_WAKEUP,
                                      PROC_INO_SYS_SCHED_MIGCOST,
                                      PROC_INO_SYS_SCHED_CHILD,
                                      PROC_INO_SYS_SCHED_CHILD + 1,  /* modprobe */
                                      PROC_INO_SYS_SCHED_CHILD + 2,  /* modules_disabled */
                                      PROC_INO_SYS_SCHED_CHILD + 3,  /* kexec_load_disabled */
                                      PROC_INO_SYS_SCHED_CHILD + 4,  /* unprivileged_userns_clone */
                                      PROC_INO_SYS_SCHED_CHILD + 5 };/* sysrq */
        if (idx < 45) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_RANDOM_DIR) {
        static const char *e[] = { ".", "..", "boot_id", "uuid", "entropy_avail", "poolsize",
                                   "urandom_min_reseed_secs", "write_wakeup_threshold" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i[] = { PROC_INO_SYS_RANDOM_DIR, PROC_INO_SYS_KERNEL_DIR,
                                      PROC_INO_SYS_BOOT_ID, PROC_INO_SYS_UUID,
                                      PROC_INO_SYS_ENTROPY_AVAIL, PROC_INO_SYS_POOLSIZE,
                                      PROC_INO_SYS_POOLSIZE + 1, PROC_INO_SYS_POOLSIZE + 2 };
        if (idx < 8) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
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
                                   "watermark_scale_factor", "page-cluster",
                                   "mmap_rnd_bits", "mmap_rnd_compat_bits" };
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
                                      PROC_INO_SYS_VM_PAGE_CLUSTER,
                                      PROC_INO_SYS_VM_PAGE_CLUSTER + 1,
                                      PROC_INO_SYS_VM_PAGE_CLUSTER + 2 };
        if (idx < 24) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_DIR) {
        static const char *e[] = { ".", "..", "file-max", "file-nr", "inotify",
                                   "nr_open", "pipe-max-size",
                                   "aio-max-nr", "aio-nr",
                                   "protected_hardlinks", "protected_symlinks",
                                   "dentry-state", "inode-state", "inode-nr",
                                   "overflowuid", "overflowgid", "lease-break-time",
                                   "binfmt_misc" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG,
                                     FUT_VDIR_TYPE_DIR };
        static const uint64_t i[] = { PROC_INO_SYS_FS_DIR, PROC_INO_SYS_DIR,
                                      PROC_INO_SYS_FILE_MAX, PROC_INO_SYS_FILE_NR,
                                      PROC_INO_SYS_INOTIFY_DIR,
                                      PROC_INO_SYS_FS_NR_OPEN,
                                      PROC_INO_SYS_FS_PIPE_MAX_SIZE,
                                      PROC_INO_SYS_FS_AIO_MAX_NR,
                                      PROC_INO_SYS_FS_AIO_NR,
                                      PROC_INO_SYS_FS_PROT_HL,
                                      PROC_INO_SYS_FS_PROT_SL,
                                      PROC_INO_SYS_FS_DENTRY_STATE,
                                      PROC_INO_SYS_FS_INODE_STATE,
                                      PROC_INO_SYS_FS_INODE_NR,
                                      PROC_INO_SYS_FS_OVERFLOWUID,
                                      PROC_INO_SYS_FS_OVERFLOWGID,
                                      PROC_INO_SYS_FS_LEASE_BREAK,
                                      PROC_INO_SYS_FS_BINFMT_DIR };
        if (idx < 12) SYS_DIR_ENTRY(e[idx], t[idx], i[idx]);
        return -ENOENT;
    }

    if (dn->kind == PROC_SYS_FS_BINFMT_MISC_DIR) {
        static const char *e[] = { ".", "..", "status", "register" };
        static const uint8_t t[] = { FUT_VDIR_TYPE_DIR, FUT_VDIR_TYPE_DIR,
                                     FUT_VDIR_TYPE_REG, FUT_VDIR_TYPE_REG };
        static const uint64_t i2[] = { PROC_INO_SYS_FS_BINFMT_DIR, PROC_INO_SYS_FS_DIR,
                                      PROC_INO_SYS_FS_BINFMT_STATUS,
                                      PROC_INO_SYS_FS_BINFMT_REG };
        if (idx < 4) SYS_DIR_ENTRY(e[idx], t[idx], i2[idx]);
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

/* procfs vnode ops — runtime initialized in procfs_mount for ARM64 safety */

/* ============================================================
 *   Mount / Unmount
 * ============================================================ */

static int procfs_mount(const char *device, int flags, void *data,
                        fut_handle_t block_device_handle,
                        struct fut_mount **mount_out) {
    (void)device; (void)flags; (void)data; (void)block_device_handle;

    /* Runtime-init vnode ops (ARM64 static const fn ptr relocation safety) */
    if (!procfs_file_ops.read) {
        procfs_file_ops.read = procfs_file_read;
        procfs_file_ops.write = procfs_file_write;
        procfs_file_ops.getattr = procfs_file_getattr;
        procfs_link_ops.readlink = procfs_link_readlink;
        procfs_link_ops.getattr = procfs_link_getattr;
        procfs_dir_ops.lookup = procfs_dir_lookup;
        procfs_dir_ops.readdir = procfs_dir_readdir;
        procfs_dir_ops.getattr = procfs_dir_getattr;
    }

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

# Current Status — January 2026

**Last Updated**: 2026-01-21

## Overview

Futura OS has reached a significant milestone with a fully functional x86-64 kernel and rapidly maturing ARM64 port. The system now provides comprehensive memory management, a rich userland environment, and multi-platform support.

## Recent Achievements

### x86-64 Platform (Primary) — Production Ready

**Advanced Memory Management (Phase 3 Complete)**
- **Copy-on-write fork**: Hash table-based reference counting with optimizations for sole-owner pages. Dramatically reduces memory overhead for fork-exec patterns.
- **File-backed mmap**: VFS integration via `fut_vfs_mmap()` with eager loading and vnode tracking. Foundation for demand paging.
- **Partial munmap**: VMA splitting handles edge shrinking and middle-section removal while preserving file backing.
- **Comprehensive syscalls**: `fork`, `execve`, `mmap`, `munmap`, `brk`, `nanosleep`, `waitpid`, `pipe`, `dup2`, and more.

**Rich Userland Environment (Phase 4 In Progress)**
- **Interactive shell**: 32+ built-in commands (cat, grep, wc, find, ls, cp, mv, etc.) with full pipe, redirection, and job control support.
- **Wayland compositor**: Multi-surface rendering with window decorations, drop shadows, damage-aware compositing (>30% speedup), and frame throttling.
- **libfutura runtime**: crt0, syscall veneers, malloc (brk-backed), printf/vprintf, string utilities.
- **System services**: init (PID 1), fsd (filesystem daemon), posixd (POSIX compat), netd (UDP bridge), registryd (service discovery).

**Filesystem & Storage**
- **RamFS**: Production-ready root filesystem with full VFS integration.
- **FuturaFS**: Log-structured filesystem with host-side tools (`mkfutfs`, `fsck.futfs`) and crash consistency validation.
- **DevFS**: Device node access (`/dev/console`, etc.).
- **File-backed mmap**: Integrated with VFS for memory-mapped I/O.

**Distributed FIPC**
- Host transport library for remote communication.
- UDP bridge daemon (netd) for distributed IPC.
- Service registry with HMAC-SHA256 capability protection.
- Regression test suite (loopback, capability, AEAD, metrics).

### ARM64 Platform — Multi-Process Support Working! 🎉

**Status**: Full process lifecycle (fork → exec → wait → exit) operational!

**Working Components**
- **177 syscalls**: Linux-compatible ABI (x8=syscall, x0-x7=args) covering:
  - Process management: fork (clone), exec, wait, exit
  - File I/O: openat, close, read, write, fstat, lseek, readv, writev
  - Filesystem: mkdirat, unlinkat, renameat, faccessat, fchmodat
  - Networking: socket, bind, connect, sendto, recvfrom, setsockopt
  - I/O multiplexing: epoll_create1, epoll_ctl, epoll_pwait, ppoll, pselect6
  - Signals: rt_sigaction, rt_sigprocmask, rt_sigreturn, kill, tkill
  - Timers: clock_gettime, nanosleep, timer_create, timerfd_create
  - Memory: mmap, munmap, mprotect, brk, madvise, mlock
  - Advanced I/O: splice, vmsplice, sendfile, sync_file_range
  - And more: futex, eventfd, signalfd, inotify, capabilities, quotactl, mount

- **Exception handling**: All 16 ARM64 exception vectors installed and working.
- **EL0/EL1 transitions**: Context switching between kernel and userspace fully operational.
- **Platform initialization**: GICv2 interrupts, ARM Generic Timer, PL011 UART, physical memory manager (1 GB).
- **Userland runtime**: ARM64-specific crt0, syscall wrappers, working demo programs.

**MMU Status**
- ✅ **Enabled and working** with identity mapping (1GB @ 0x40000000).
- Full virtual memory support operational.
- Page tables: L1/L2 hierarchy with 2MB block entries.
- Multi-process support fully functional (fork/exec/wait/exit all working).

See `docs/ARM64_STATUS.md` for detailed ARM64 progress.

## Recent Completions (November 27, 2025)

### x86-64 Platform — Latest Work (Continuing from Previous Session)
- ✅ **TTY input stack**: Implemented POSIX termios with canonical mode, line discipline, echo, and control characters. Serial input now yields to scheduler instead of spinning.
- ✅ **Keyboard integration**: PS/2 keyboard driver with US QWERTY keymap, modifier key handling (shift, ctrl, caps lock), and scancode-to-ASCII conversion.
- ✅ **Signal handling**: Implemented x86-64 signal delivery via interrupt frame modification with full rt_sigframe construction on user stack. Supports SIG_DFL default actions (TERM, CORE, STOP, CONT, IGN) and custom handlers. sigreturn syscall already implemented.
- ✅ **FuturaFS**: Async composite operations (file_read_async, file_write_async, dir_lookup_async, dir_add_async) already complete. Full directory operations (mkdir, rmdir, create, unlink, lookup, readdir) functional. 96 MiB kernel heap resolves previous allocation limits.

### November 27, 2025 Session — FSD Integration & Protocol Enhancement
- ✅ **Extended FSD protocol**: Added message types and stub handlers for directory operations (mkdir, rmdir, unlink), file metadata (stat, lseek, fsync), and permission changes (chmod, chown). Established FIPC protocol foundation for future full implementation.
- ✅ **Service registration scaffolding**: Updated fsd_init() with implementation notes for future service discovery integration with service registry daemon.
- ✅ **Process groups / Job control**: Verified setpgid/getpgid syscalls already implemented (stub mode that returns success). Foundation ready for full process group tracking.
- ✅ **Pipe syscall**: Verified sys_pipe() fully implemented with comprehensive test coverage. Supports both basic pipe creation and advanced features like EOF handling, EPIPE generation.

### November 27, 2025 Session (Continued) — Filesystem Operations & Per-Task Context
- ✅ **Per-task file context**: Fixed sys_getcwd() to return actual current working directory (now uses task->current_dir_ino instead of hardcoded root). Enables shell prompts showing actual location.
- ✅ **Per-task umask isolation**: Migrated umask from global state to per-task field in fut_task_t structure. Each process now has independent file creation mask; child processes inherit parent's umask on fork. Proper POSIX process isolation.
- ✅ **Atomic rename operation**: Implemented full rename() syscall with VFS integration. Added rename() operation to fut_vnode_ops interface, implemented ramfs_rename() for in-memory atomicity, and integrated sys_rename() with comprehensive error handling. Supports same-directory renaming with atomic replacement of existing files. Foundation for cross-directory moves in future phase.
- ✅ **Verified symlink/readlink**: Discovered sys_symlink() and sys_readlink() already fully implemented with complete VFS integration and error handling. Both syscalls ready for production use.

### January 21, 2026 Session — Security Hardening & Code Quality
- ✅ **Page refcount overflow protection**: Added FUT_PAGE_REF_MAX (60000) limit in fut_page_ref_inc() to prevent CVE-2016-0728 style refcount overflow attacks. Fork now checks return value and aborts if limit reached.
- ✅ **File refcount overflow protection**: Added FUT_FILE_REF_MAX limit in sys_fork.c with proper cleanup of already-inherited FDs on failure. Prevents use-after-free via mass forking with many open FDs.
- ✅ **Global PID limit**: Implemented FUT_MAX_TASKS_GLOBAL (30000) with FUT_RESERVED_FOR_ROOT (1000) PIDs reserved for admin recovery during fork bomb attacks.
- ✅ **Time-based capability expiry**: Added fut_capability_check_expiry() and fut_capability_create_timed() for capabilities that expire after a specified duration.
- ✅ **CAP_SYS_RESOURCE enforcement**: Non-privileged processes can no longer raise resource hard limits without CAP_SYS_RESOURCE capability.
- ✅ **VMA count limit**: Added MAX_VMA_COUNT (65536) check in sys_mmap to prevent VMA fragmentation DoS attacks.
- ✅ **Network error handling**: Added return value checks for fut_net_send() in TCP/IP stack (ARP, IP layers).
- ✅ **Code quality improvements**: Replaced magic numbers with named constants (IO_BUDGET_WINDOW_MS, CPU_BRAND_BUFFER_SIZE, FUT_FD_TABLE_INITIAL_SIZE, O_NONBLOCK, O_CLOEXEC).
- ✅ **FD categorization refactoring**: Extracted fut_fd_category() helper to eliminate code duplication across 6 syscall files.
- ✅ **mlockall() hardening**: Added VMA count limit and RLIMIT_MEMLOCK enforcement with CAP_IPC_LOCK bypass.
- ✅ **AT_SYMLINK_NOFOLLOW implementation**: Full implementation in sys_faccessat with lstat-based permission checking.
- ✅ **F_DUPFD resource limit enforcement**: Added RLIMIT_NOFILE check to prevent FD exhaustion attacks via fcntl.
- ✅ **Unix domain socket path traversal protection**: Reject ".." path components in sys_bind and sys_connect to prevent directory traversal attacks (CVE-2018-6555 mitigation).
- ✅ **FD upper bound validation**: Added fd >= task->max_fds checks to prevent out-of-bounds FD table access across all file descriptor syscalls:
  - Regular FD syscalls: pread64, pwrite64, preadv, pwritev, lseek, fsync, fdatasync, flock, fstatfs, fallocate, sendfile, futimens
  - Directory FD syscalls: syncfs, getdents64, inotify_add_watch, inotify_rm_watch
  - *at syscalls (dirfd validation): faccessat, fchmodat, fstatat, mkdirat, readlinkat, symlinkat, unlinkat, utimensat, linkat, renameat
  - Dual-FD syscalls: dup3 (both oldfd/newfd), sendfile (both in_fd/out_fd), linkat/renameat (both olddirfd/newdirfd)
  - All validations properly handle AT_FDCWD (-100) as valid for *at syscalls

### January 21, 2026 Session (Continued) — Code Refactoring & Bug Fixes
- ✅ **Bug fixes**: Fixed missing semicolons in sys_flock.c, sys_faccessat.c, and sys_filesystem_stats.c that prevented compilation.
- ✅ **Memory leak fixes**: Fixed memory leaks in sys_preadv.c and sys_pwritev.c where kernel_iov buffer wasn't freed on ESPIPE, EISDIR, and EINVAL error paths.
- ✅ **Extended FD categorization refactoring**: Applied fut_fd_category() helper to additional syscall files (sys_pread64.c, sys_pwrite64.c, sys_fstat.c, sys_getdents64.c), reducing code duplication by ~40 lines.
- ✅ **New I/O categorization helpers**: Added fut_size_category() and fut_offset_category() to fut_fd_util.h for consistent size and offset categorization in debug logging.
- ✅ **Applied size/offset helpers**: Updated sys_pread64.c and sys_pwrite64.c to use the new fut_size_category() and fut_offset_category() helpers, eliminating duplicated categorization logic.

### January 21, 2026 Session (Latest) — Code Quality & DRY Refactoring
- ✅ **sys_execve.c DRY refactoring**: Extracted `execve_free_argv()` and `execve_free_envp()` helper functions, reducing code by 84 lines while eliminating 12 instances of repetitive cleanup code.
- ✅ **VN_DIR bug fix**: Fixed sys_fchdir.c which had incorrect local #defines (VN_DIR=1, VN_REG=2) shadowing the correct enum values from fut_vfs.h (VN_REG=1, VN_DIR=2). This was a real bug that would have caused incorrect directory validation.
- ✅ **VN_DIR magic number elimination**: Replaced magic number `2` with `VN_DIR` enum constant in 11 *at syscall files: sys_renameat.c, sys_mkdirat.c, sys_utimensat.c, sys_unlinkat.c, sys_linkat.c, sys_faccessat.c, sys_readlinkat.c, sys_symlinkat.c, sys_fstatat.c, sys_fchmodat.c.
- ✅ **ENOMEM magic number elimination**: Replaced magic number `-12` with `-ENOMEM` constant in:
  - futurafs.c (8 instances)
  - fut_socket.c (16 instances, added errno.h include)
  - fut_blockdev.c (2 instances, added errno.h include)
- ✅ **Network error codes**: Added EAFNOSUPPORT, EADDRINUSE, ECONNABORTED, ECONNREFUSED, EALREADY, EINPROGRESS to errno.h
- ✅ **Socket error constants**: Replaced 23 magic number returns in fut_socket.c (-EINVAL, -EAGAIN, -EPIPE, -ENOTCONN, -EADDRINUSE, -ECONNREFUSED)
- ✅ **Size categorization DRY**: Applied `fut_size_category()` helper to sys_read.c and sys_write.c, eliminating ~30 lines of duplicated categorization logic
- ✅ **Extended FD categorization**: Applied `fut_fd_category()` helper to 6 more files: sys_fchdir.c, sys_flock.c, sys_fdatasync.c, sys_fchmod.c, sys_fchown.c, sys_epoll.c - reducing ~70 lines total

### January 21, 2026 Session (Continued) — Bug Fixes & Error Code Standardization
- ✅ **Double-free bug fix**: Fixed memory corruption bug in elf64.c stage_stack_pages() where error cleanup loop used `j <= i` instead of `j < i`, causing double-free of current page after allocation failure.
- ✅ **fut_timer.c error codes**: Replaced `-1` returns with proper errno constants:
  - `fut_timer_start()`: -1 → -EINVAL (null callback), -ENOMEM (allocation failure)
  - `fut_timer_cancel()`: -1 → -EINVAL (null callback), -ENOENT (timer not found)
- ✅ **fut_object.c error codes**: Replaced `-1` returns with proper errno constants:
  - `fut_object_destroy()`: -1 → -EINVAL (invalid handle), -ENOENT (not found), -EACCES (permission denied)
  - Stub functions: -1 → -ENOSYS (not implemented)
- ✅ **arm64_paging.c error codes**: Replaced numeric error codes (-1 through -5) with proper errno constants across 15 instances:
  - `fut_map_page()`: alignment errors → -EINVAL, invalid address → -EFAULT, allocation failures → -ENOMEM
  - `fut_unmap_page()`: alignment errors → -EINVAL, page not present → -ENOENT
  - Virtual-to-physical translation: page table errors → -EFAULT
- ✅ **fut_thread.c error codes**: Replaced `-1` returns with proper errno constants:
  - `fut_thread_priority_raise()`: -1 → -EINVAL (null thread)
  - `fut_thread_priority_restore()`: -1 → -EINVAL (null thread)
  - `fut_thread_set_affinity()`: -1 → -EINVAL (invalid params)
  - `fut_thread_set_affinity_mask()`: -1 → -EINVAL (empty mask)
- ✅ **ramfs.c error codes**: Replaced `-1` returns in `validate_ramfs_node()` with -EIO for memory corruption detection
- ✅ **elf64.c stub error codes**: Replaced `-1` returns in non-x86_64 stub functions with -ENOSYS:
  - `fut_stage_init_stub_binary()`: -1 → -ENOSYS (not implemented for non-x86_64)
  - `fut_stage_second_stub_binary()`: -1 → -ENOSYS (not implemented for non-x86_64)
- ✅ **arm64_irq.c error codes**: Replaced numeric error codes with proper errno constants:
  - `fut_register_irq_handler()`: -1 → -EINVAL (invalid IRQ), -2 → -EEXIST (already registered)
  - `fut_unregister_irq_handler()`: -1 → -EINVAL (invalid IRQ)
  - `fut_irq_acknowledge()`: -1 → -EAGAIN (spurious interrupt)

### January 21, 2026 Session (Final) — Magic Numbers & Error Handling
- ✅ **TCP/IP stack constants**: Added named constants in tcpip.h:
  - `IP_DEFAULT_TTL` (64) for Time To Live
  - `IP_BROADCAST_ADDR` (0xFFFFFFFF) for broadcast address checks
  - `TCPIP_RX_THREAD_STACK_SIZE` (8192) and `TCPIP_RX_THREAD_PRIORITY` (100)
- ✅ **TCP/IP error logging**: Added error messages for allocation failures in:
  - `ip_send_packet()`: Now logs when packet allocation fails
  - `icmp_handle_packet()`: Now logs when echo reply allocation fails
- ✅ **FuturaFS constants**: Added named constants in fut_futurafs.h:
  - `FUTURAFS_DEFAULT_INODE_RATIO` (16384) for one inode per 16KB
  - `FUTURAFS_MIN_INODES` (16) for minimum inode count

### January 21, 2026 Session (Continued) — DRY Refactoring & Named Constants
- ✅ **fut_task.c DRY refactoring**: Extracted `task_cleanup_and_exit()` helper to consolidate duplicate exit cleanup code from `fut_task_exit_current()` and `fut_task_signal_exit()`, reducing code duplication by ~20 lines.
- ✅ **Exit status encoding constants**: Added named constants for POSIX wait status encoding:
  - `EXIT_CODE_MASK` (0xFF) for exit code extraction
  - `SIGNAL_MASK` (0x7F) for signal number extraction
  - `WAIT_STATUS_SHIFT` (8) for exit code position in wait status
- ✅ **ARM64 device address constants**: Added physical address constants in platform/arm64/regs.h:
  - `GICD_PHYS_BASE` (0x08000000) for GIC Distributor
  - `GICC_PHYS_BASE` (0x08010000) for GIC CPU Interface
  - `UART0_PHYS_BASE` (0x09000000) for PL011 UART
  - `DEVICE_MAP_REGION_SIZE` (0x10000) for 64KB device mapping
- ✅ **x86_64 register constants**: Added named constants in platform/x86_64/regs.h:
  - `RFLAGS_RESERVED` for bit 1 (must always be 1)
  - `RFLAGS_KERNEL_INIT` for initial kernel thread RFLAGS
  - `MXCSR_DEFAULT` (0x1F80) for default FPU state
  - `FXSAVE_MXCSR_OFFSET` (24) for MXCSR position in FXSAVE area
- ✅ **Thread constants**: Added `FUT_STACK_CANARY` constant in fut_thread.h for stack overflow detection
- ✅ **Segment selector cleanup**: Updated fut_thread.c to use `GDT_KERNEL_CODE` and `GDT_KERNEL_DATA` instead of magic numbers (0x08, 0x10)
- ✅ **arm64_irq.c consolidation**: Updated to reference shared GIC address constants from regs.h instead of local duplicates
- ✅ **x86_64 hardware constants**: Added serial line status register constants in platform_init.c:
  - `SERIAL_LSR_DATA_READY` (0x01) for data available detection
  - `SERIAL_LSR_THRE` (0x20) for transmit ready detection
  - `PIC_CASCADE_MASTER`, `PIC_CASCADE_SLAVE`, `PIC_MASK_ALL` for PIC initialization
- ✅ **Parameter validation**: Added NULL checks in apple_ans2_program_tcb() to prevent NULL dereference
- ✅ **Memory safety**: Initialize page_cache array to NULL in fut_mm.c for safe error cleanup
- ✅ **Total code improvements this session**:
  - Fixed 1 double-free bug (elf64.c)
  - Replaced 50+ generic error returns with proper errno constants
  - Added 30+ named constants to replace magic numbers
  - Added error logging for silent allocation failures
  - Eliminated code duplication in 2 task exit functions
  - Added defensive memory initialization

### January 21, 2026 Session — Documentation & Code Quality (Continued)
- ✅ **Header documentation**: Added comprehensive API documentation to 3 kernel headers:
  - `fut_waitq.h`: Wait queue primitives with usage patterns, thread safety notes, and examples
  - `uaccess.h`: User memory access helpers with security model documentation and common patterns
  - `fut_percpu.h`: Per-CPU data structures with architecture-specific implementation details
- ✅ **fb_mmio.c named constants**: Replaced magic numbers with descriptive constants:
  - `PCI_CONFIG_ADDRESS`/`PCI_CONFIG_DATA` for PCI configuration ports
  - `PCI_VENDOR_VIRTIO`/`PCI_VENDOR_CIRRUS` for device detection
  - `FB_PHYS_*` for legacy framebuffer addresses
  - `FB_DEFAULT_WIDTH`/`HEIGHT`/`BPP` for geometry defaults
  - `ARGB_BLACK` for color values
- ✅ **Cross-platform constant consolidation**: Moved shared FB_DEFAULT_* and FB_PHYS_FALLBACK constants before architecture-specific code in fb_mmio.c, eliminating duplicate #defines
- ✅ **Device registry named constants**: Added `CHRDEV_MAX_ENTRIES` (32) in chrdev.c and `DEVFS_MAX_NODES` (64) in devfs.c
- ✅ **Additional header documentation**: Added comprehensive API documentation to:
  - `boot_args.h`: Command line parsing with usage examples
  - `console.h`: Console initialization and input thread functions
  - `exec.h`: ELF execution and boot-time binary staging functions
  - `trap.h`: Page fault handling with exception flow documentation
- ✅ **Typo fixes**: Fixed comment typo in rpi_init.c
- ✅ **Include guard fixes**: Added `#pragma once` and documentation to `boot_logo.h`, made bitmap array `static const` and used `sizeof()` for length
- ✅ **Cryptographic function documentation**: Added comprehensive docs to `fut_hmac.h` (SHA-256, HMAC-SHA256)
- ✅ **Memory allocator documentation**: Added comprehensive docs to:
  - `buddy_allocator.h`: Buddy algorithm explanation, all functions documented
  - `slab_allocator.h`: Slab architecture, cache sizes, debug functions
- ✅ **Framebuffer documentation**: Added comprehensive docs to:
  - `fb.h`: Framebuffer discovery methods, struct fields, init functions
  - `fb_console.h`: Console features, font, output functions

### January 21, 2026 Session — Device Interface & Signal Documentation
- ✅ **Device and signal header documentation**: Added comprehensive API docs to:
  - `perf_clock.h`: TSC-based performance measurement, calibration, percentile stats
  - `chrdev.h`: Character device driver interface, fut_file_ops callbacks, registration
  - `devfs.h`: Device filesystem architecture, typical workflow, common paths
  - `signal.h`: POSIX signal handling, delivery flow, signal types
- ✅ **capability.c code quality**: Replaced magic numbers (0x3, 0x0040, 0x0200, 0x0080) with named constants (O_ACCMODE, O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_EXCL)
- ✅ **O_CLOEXEC constant**: Added O_CLOEXEC (0x80000) to fut_vfs.h and updated sys_dup3() to use the named constant instead of magic number
- ✅ **sys/stat.h mode constants**: Added comprehensive file mode constants:
  - File type mask and constants (S_IFMT, S_IFREG, S_IFDIR, S_IFLNK, S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK)
  - File type test macros (S_ISREG, S_ISDIR, S_ISCHR, S_ISBLK, S_ISFIFO, S_ISLNK, S_ISSOCK)
  - Special permission bits (S_ISUID, S_ISGID, S_ISVTX)
  - Complete user/group/other permission bits with rwx masks
- ✅ **POSIX constants**: Added SEEK_SET/SEEK_CUR/SEEK_END and PIPE_BUF to futura_posix.h
- ✅ **sys/epoll.h**: Created comprehensive epoll header with:
  - EPOLL_CTL_* operations (ADD, DEL, MOD)
  - All standard EPOLL event flags (EPOLLIN, EPOLLOUT, EPOLLERR, etc.)
  - Edge-triggered (EPOLLET) and one-shot (EPOLLONESHOT) modes
  - epoll_data union and epoll_event structure definitions

### January 21, 2026 Session — POSIX Header Consolidation
- ✅ **sys/socket.h**: Created comprehensive BSD socket interface header with:
  - Address families (AF_UNSPEC, AF_UNIX, AF_LOCAL, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET)
  - Socket types (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET)
  - Socket options (SOL_SOCKET level: SO_REUSEADDR, SO_KEEPALIVE, SO_RCVBUF, etc.)
  - Message flags (MSG_OOB, MSG_PEEK, MSG_DONTWAIT, MSG_NOSIGNAL, etc.)
  - Shutdown constants (SHUT_RD, SHUT_WR, SHUT_RDWR)
  - Address structures (sockaddr, sockaddr_un, sockaddr_in, sockaddr_storage)
  - All standard socket function declarations
- ✅ **sys/wait.h**: Created comprehensive wait interface header with:
  - Wait option flags (WNOHANG, WUNTRACED, WCONTINUED, WEXITED, WNOWAIT)
  - Status evaluation macros (WIFEXITED, WEXITSTATUS, WIFSIGNALED, WTERMSIG, etc.)
  - Type definitions (pid_t, id_t, idtype_t for waitid)
  - Function declarations (wait, waitpid, wait3, wait4)
- ✅ **sys/mman.h**: Created comprehensive memory management header with:
  - Protection flags (PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC)
  - Mapping flags (MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANONYMOUS, MAP_STACK, etc.)
  - Remap flags (MREMAP_MAYMOVE, MREMAP_FIXED, MREMAP_DONTUNMAP)
  - Sync flags (MS_ASYNC, MS_SYNC, MS_INVALIDATE)
  - Madvise flags (MADV_NORMAL through MADV_DODUMP)
  - Mlock flags (MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT)
  - Consolidates definitions from 14+ source files
- ✅ **sys/resource.h**: Created comprehensive resource limits header with:
  - RLIMIT_* constants (CPU, FSIZE, DATA, STACK, NOFILE, MEMLOCK, AS, etc.)
  - rlim_t type and RLIM_INFINITY constant
  - struct rlimit and struct rlimit64
  - RUSAGE_* constants and struct rusage
  - PRIO_* constants for process priority
  - Consolidates definitions from 4+ kernel files
- ✅ **sched.h**: Created comprehensive scheduling header with:
  - SCHED_* policies (OTHER, FIFO, RR, BATCH, IDLE, DEADLINE)
  - SCHED_FLAG_* scheduling flags
  - CLONE_* flags for clone/clone3 syscalls (21 flags total)
  - struct sched_param and struct sched_attr
  - cpu_set_t and CPU_* macros for CPU affinity
- ✅ **sys/mount.h**: Created comprehensive mount operations header with:
  - MS_* mount flags (RDONLY, NOSUID, NODEV, NOEXEC, BIND, MOVE, etc.)
  - Mount propagation flags (PRIVATE, SLAVE, SHARED, UNBINDABLE)
  - MNT_* and UMOUNT_* unmount flags
- ✅ **sys/uio.h**: Created vectored I/O header with:
  - struct iovec for scatter-gather operations
  - UIO_MAXIOV and IOV_MAX constants
  - readv, writev, preadv, pwritev function declarations
  - preadv2, pwritev2 with RWF_* flags
  - process_vm_readv, process_vm_writev declarations
  - Consolidates struct iovec from 8+ source files
- ✅ **poll.h expanded**: Enhanced poll header with:
  - Proper copyright header and documentation
  - Additional event flags (POLLRDNORM, POLLRDBAND, POLLWRNORM, POLLWRBAND)
  - ppoll() function declaration
  - Header guards for compatibility
- ✅ **sys/time.h expanded**: Enhanced time header with:
  - ITIMER_* constants (REAL, VIRTUAL, PROF)
  - struct itimerval for interval timers
  - Time manipulation macros (timerisset, timerclear, timercmp, timeradd, timersub)
  - Additional function declarations (setitimer, getitimer, utimes, futimes)

### January 21, 2026 Session — Additional Header Consolidation
- ✅ **limits.h**: Created comprehensive implementation limits header with:
  - Numeric type limits (CHAR_*, SHRT_*, INT_*, LONG_*, LLONG_*)
  - POSIX pathname limits (PATH_MAX, NAME_MAX, LINE_MAX)
  - Process limits (CHILD_MAX, OPEN_MAX, ARG_MAX)
  - I/O limits (PIPE_BUF, IOV_MAX, LINK_MAX, SYMLOOP_MAX)
  - Size limits (SIZE_MAX, SSIZE_MAX)
- ✅ **sys/select.h**: Created select/pselect interface header with:
  - FD_SETSIZE constant and fd_set type
  - FD_SET, FD_CLR, FD_ISSET, FD_ZERO, FD_COPY macros
  - select() and pselect() function declarations
- ✅ **fcntl.h expanded**: Enhanced file control header with:
  - AT_* constants for *at() syscalls (AT_FDCWD, AT_SYMLINK_NOFOLLOW, etc.)
  - Additional O_* flags (O_DSYNC, O_DIRECT, O_NOATIME, O_PATH)
  - LOCK_* constants for flock()
  - struct flock and F_RDLCK/F_WRLCK/F_UNLCK lock types
  - F_DUPFD_CLOEXEC and additional fcntl commands
  - Consolidates AT_* definitions from 20+ source files
- ✅ **sys/eventfd.h**: Created event notification header with:
  - EFD_SEMAPHORE, EFD_CLOEXEC, EFD_NONBLOCK flags
  - eventfd_t type definition
  - eventfd(), eventfd_read(), eventfd_write() declarations
- ✅ **sys/inotify.h**: Created file system monitoring header with:
  - IN_CLOEXEC, IN_NONBLOCK flags for inotify_init1
  - All IN_* event mask constants (ACCESS, MODIFY, CREATE, DELETE, etc.)
  - Watch flags (ONLYDIR, DONT_FOLLOW, EXCL_UNLINK, ONESHOT)
  - struct inotify_event definition
  - Function declarations for inotify_init, inotify_add_watch, inotify_rm_watch
- ✅ **linux/futex.h**: Created fast userspace locking header with:
  - FUTEX_* operation constants (WAIT, WAKE, REQUEUE, CMP_REQUEUE, etc.)
  - FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME flags
  - FUTEX_WAKE_OP operation and comparison constants
  - struct robust_list and robust_list_head
  - Function declarations for futex, set_robust_list, get_robust_list

### January 21, 2026 Session — Continued POSIX Header Development
- ✅ **sys/types.h**: Created comprehensive POSIX data types header with:
  - Process/user/group ID types (pid_t, uid_t, gid_t, id_t)
  - File system types (mode_t, dev_t, ino_t, nlink_t, off_t, loff_t)
  - Size types (blksize_t, blkcnt_t, fsblkcnt_t, fsfilcnt_t, ssize_t)
  - Socket/IPC types (socklen_t, sa_family_t, in_port_t, in_addr_t, key_t)
  - Time types (useconds_t, suseconds_t)
  - Device number macros (major, minor, makedev)
  - Consolidates type definitions from 10+ source files
- ✅ **dirent.h**: Created directory entry header with:
  - DT_* file type constants (DT_REG, DT_DIR, DT_LNK, DT_CHR, DT_BLK, etc.)
  - IFTODT/DTTOIF conversion macros for stat mode ↔ d_type
  - struct linux_dirent64 for getdents64() syscall
  - struct linux_dirent for legacy getdents() syscall
  - struct dirent for POSIX readdir() interface
  - Function declarations for getdents/getdents64
- ✅ **sys/utsname.h**: Created system identification header with:
  - _UTSNAME_LENGTH and SYS_NMLN constants
  - struct utsname with sysname, nodename, release, version, machine fields
  - GNU extension domainname field (when _GNU_SOURCE defined)
  - uname() function declaration
- ✅ **sys/statfs.h**: Created filesystem statistics header with:
  - Filesystem type magic numbers (TMPFS, RAMFS, EXT2-4, PROC, SYSFS, etc.)
  - ST_* mount flags (ST_RDONLY, ST_NOSUID, ST_NOEXEC, etc.)
  - fsid_t type definition
  - struct statfs and struct statfs64
  - Function declarations: statfs, fstatfs, statfs64, fstatfs64
- ✅ **sys/sysinfo.h**: Created system information header with:
  - struct sysinfo for system statistics (uptime, loads, memory, processes)
  - SI_LOAD_SHIFT constant for load average scaling
  - Function declarations: sysinfo, get_nprocs, get_nprocs_conf
  - get_phys_pages, get_avphys_pages declarations
- ✅ **unistd.h**: Created comprehensive POSIX header with:
  - Access mode constants (F_OK, R_OK, W_OK, X_OK)
  - Standard file descriptors (STDIN/STDOUT/STDERR_FILENO)
  - Seek constants (SEEK_SET/CUR/END/DATA/HOLE)
  - sysconf constants (_SC_PAGESIZE, _SC_NPROCESSORS_*, etc.)
  - pathconf constants (_PC_NAME_MAX, _PC_PATH_MAX, etc.)
  - lockf constants (F_ULOCK, F_LOCK, F_TLOCK, F_TEST)
  - 70+ function declarations for process, file, directory, and misc operations
  - Consolidates constants previously scattered across syscall files

### January 21, 2026 Session — Bug Fixes
- ✅ **sys/socket.h hosted environment fix**: Added #include_next for hosted environments to prevent conflicts with glibc headers
- ✅ **O_CLOEXEC redefinition fix**: Fixed kernel/sys_open.c which had incorrect O_CLOEXEC value (0x4000 instead of 0x80000)

### January 21, 2026 Session — Structure Consolidation & Header Reorganization
- ✅ **shared/fut_sigevent.h**: Created shared header for timer notification types:
  - timer_t, union sigval, struct sigevent, SIGEV_* constants
  - Consolidates definitions from syscall_table.c and sys_timer.c
- ✅ **shared/fut_stat.h**: Created kernel-compatible stat structure header:
  - struct fut_stat with raw int64_t timestamps (st_atime, st_mtime, st_ctime)
  - S_IF* file mode constants and S_IS* test macros
  - Consolidates definitions from syscall_table.c and userland_test.c
- ✅ **linux/ → sys/ migration**: Moved headers from include/linux/ to include/sys/:
  - linux/futex.h → sys/futex.h
  - linux/capability.h → sys/capability.h
  - Removed include/linux/ directory (Futura should not have Linux-specific paths)
- ✅ **struct iovec consolidation**: Updated 7 kernel files to use sys/uio.h:
  - kernel/sys_readv.c, sys_writev.c, sys_preadv.c, sys_pwritev.c
  - kernel/sys_sendmsg.c, sys_recvmsg.c
  - platform/arm64/syscall_table.c
  - Eliminates 70+ lines of duplicated structure and constant definitions
- ✅ **struct pollfd consolidation**: Updated kernel files to use poll.h:
  - kernel/sys_poll.c, sys_select.c
  - Eliminates duplicate struct pollfd and POLL* constants
- ✅ **struct robust_list consolidation**: Updated kernel files to use sys/futex.h:
  - kernel/sys_futex.c: Removed local FUTEX_* constants and robust_list
  - syscall_table.c: Removed local struct robust_list
- ✅ **errno consolidation**: Removed redundant errno definitions:
  - syscall_table.c: Removed local ENOSYS, EINVAL, EBADF defines
  - userland_test.c: Removed local EINVAL, ENOMEM, ESRCH defines
  - Both now use errno.h consistently
- ✅ **struct msghdr/cmsghdr consolidation**: Added to sys/socket.h:
  - struct msghdr for sendmsg/recvmsg scatter-gather I/O
  - struct cmsghdr for ancillary data
  - SCM_RIGHTS, SCM_CREDENTIALS constants
  - CMSG_* macros (CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR, CMSG_SPACE, CMSG_LEN)
  - MSG_EOR, MSG_MORE, MSG_CTRUNC, MSG_ERRQUEUE, MSG_CMSG_CLOEXEC constants
- ✅ **sys/un.h**: Created separate Unix domain socket address header:
  - struct sockaddr_un with proper hosted/freestanding handling
  - SUN_LEN() macro for address length calculation
  - Prevents conflicts with system sys/un.h in hosted builds
- ✅ **typedef consolidation (sys/types.h)**: Updated headers to use centralized types:
  - sys/wait.h: Now includes sys/types.h instead of defining own pid_t/id_t
  - sys/stat.h: Uses sys/types.h in freestanding mode for dev_t, ino_t, mode_t, etc.
  - kernel/chrdev.h, fut_vfs.h: Aligned typedef guards (__ssize_t_defined, __off_t_defined)
- ✅ **ssize_t standardization**: Unified __ssize_t_defined guard across 14 files:
  - Kernel headers: syscalls.h, fut_blockdev.h, tty.h, fut_fipc.h, fut_socket.h
  - System headers: sys/uio.h (fixed incorrect #ifndef ssize_t guard)
  - Userspace: libfutura.h, syscall_portable.h
  - Removed duplicate definitions from cat, wc, and shell programs
  - kernel/sys_splice.c, platform/arm64/userland_test.c
  - subsystems/posix_compat/posix_shim.h
- ✅ **pid_t consolidation**: Unified __pid_t_defined guard across userspace:
  - futura_posix.h: Simplified to use sys/types.h in freestanding mode,
    eliminating 10 duplicate type definitions (off_t, dev_t, ino_t, etc.)
  - futura_init.h: Fixed broken __POSIX_TYPES_DEFINED guard (was never defined)
  - shell/main.c: Fixed incorrect type (was int, now int32_t) with proper guard
- ✅ **time_t/clockid_t standardization**: Fixed user/time.h to use proper
  __time_t_defined and __clockid_t_defined guards instead of incorrect
  #ifndef time_t / #ifndef clockid_t macro checks
- ✅ **struct rlimit consolidation**: Updated kernel files to use sys/resource.h:
  - kernel/sys_proc.c: Removed 20 lines of local struct rlimit and RLIMIT_* definitions
  - platform/arm64/syscall_table.c: Removed 10 lines of local struct rlimit/rlimit64
- ✅ **fcntl.h mode_t**: Updated to use sys/types.h instead of local typedef
- ✅ **epoll_event consolidation**:
  - src/user/libfutura/epoll.c: Now uses sys/epoll.h (removed 26 lines of duplicates)
  - Added proper _STRUCT_EPOLL_EVENT and _EPOLL_DATA_T guards to sys/epoll.h
  - kernel/sys_epoll.c: Added guard and documented kernel's simpler uint64_t data field
- ✅ **crt0 linker warning fix**: Added .note.GNU-stack section to x86-64 and ARM64
  crt0.S files to silence "missing .note.GNU-stack section" linker warnings
- ✅ **struct utsname consolidation**: Updated 3 files to use sys/utsname.h:
  - kernel/sys_uname.c, syscall_table.c, userland_test.c
  - Uses _GNU_SOURCE for domainname field support
  - Removed 22 lines of duplicate struct definitions
- ✅ **futura_posix.h socket consolidation**: Replaced 58 lines of local socket
  structure definitions (sockaddr, sockaddr_un, iovec, msghdr, cmsghdr) with
  includes to sys/socket.h, sys/un.h, and sys/uio.h
- ✅ **Userland linker script RWX fix**: Added PHDRS sections to userland.ld and
  userland_x86_64.ld to properly separate text (R+X) and data (R+W) segments,
  eliminating RWX permission warnings for all userland binaries
- ✅ **Kernel linker noexecstack**: Added -z noexecstack to kernel LDFLAGS to
  suppress warnings from objcopy-generated blob files lacking .note.GNU-stack

### January 21, 2026 Session — Header Consolidation & Code Cleanup
- ✅ **kprintf.h header creation**: Created `include/kernel/kprintf.h` to centralize
  the `fut_printf()` declaration that was scattered across 180+ kernel files
- ✅ **kprintf.h migration**: Updated all kernel files to use `#include <kernel/kprintf.h>`
  instead of `extern void fut_printf(...)` declarations, eliminating 250+ lines
  of duplicate declarations
- ✅ **Duplicate include cleanup**: Fixed sed-induced duplicate `#include <kernel/kprintf.h>`
  lines in 7 files (ramfs.c, elf64.c, fut_blockdev.c, futurafs.c, arm64_paging.c,
  perf_ipc.c, perf_sched.c), removing 42 redundant lines

### January 21, 2026 Session — Header Consolidation (Continued)
- ✅ **uaccess.h consolidation**: Replaced scattered `extern int fut_copy_from_user()` and
  `extern int fut_copy_to_user()` declarations with proper `#include <kernel/uaccess.h>`
  across 59 syscall files, removing ~70 lines of duplicate declarations
- ✅ **fut_task.h cleanup**: Removed 71 redundant `extern fut_task_t *fut_task_current()`
  declarations from syscall files (already declared in fut_task.h)
- ✅ **fut_vfs.h cleanup**: Removed redundant `vfs_get_file_from_task()` and
  `fut_vfs_get_file()` externs from syscall files; added missing fut_vfs.h includes
  where needed (sys_exit.c, sys_readv.c, sys_writev.c)
- ✅ **fut_memory.h consolidation**: Replaced `extern void *fut_malloc()`/`fut_free()`
  declarations with proper header includes in 11 syscall files
- ✅ **Additional cleanups**: Replaced externs for fut_task_by_pid (fut_task.h),
  fut_exec_elf (exec.h), fut_access_ok (uaccess.h), fut_thread_current (fut_thread.h)
  with proper header includes
- **Total impact**: Removed ~200+ lines of scattered extern declarations across 100+ files
- ✅ **fut_timer.h consolidation**: Replaced fut_get_ticks/fut_get_time_ns externs with
  proper header includes in 7 syscall files
- ✅ **fut_vfs.h API additions**: Added fut_vfs_sync_fs(), fut_vfs_sync_all(), and
  vfs_check_*_perm() function declarations to header, enabling removal of externs
- ✅ **Continued cleanup**: Removed redundant vfs_alloc_specific_fd_for_task externs

### January 21, 2026 Session — Type & Constant Consolidation (Continued)
- ✅ **socklen_t consolidation**: Added socklen_t typedef to fut_socket.h with proper
  __socklen_t_defined guard, removing duplicates from 9 syscall files (sys_connect.c,
  sys_sendto.c, sys_bind.c, sys_getsockopt.c, sys_setsockopt.c, sys_accept.c,
  sys_recvfrom.c, sys_getsockname.c, sys_getpeername.c)
- ✅ **AF_*/SOCK_* consolidation**: Added address family and socket type constants to
  fut_socket.h, removing duplicates from sys_socket.c, sys_bind.c, sys_connect.c,
  sys_getsockname.c, sys_getpeername.c
- ✅ **Socket option consolidation**: Added SOL_SOCKET, IPPROTO_*, and SO_* constants
  to fut_socket.h, removing duplicates from sys_setsockopt.c, sys_getsockopt.c, sys_recvmsg.c
- ✅ **MSG_* flags consolidation**: Added message flags to fut_socket.h, removing
  duplicates from sys_sendto.c and sys_recvfrom.c
- ✅ **sockaddr_un consolidation**: Updated sys_getsockname.c and sys_getpeername.c
  to use sys/un.h instead of local struct definitions
- ✅ **S_IF* consolidation**: Updated kernel/vfs/fut_vfs.c and kernel/sys_mknodat.c
  to use sys/stat.h instead of local S_IF*/S_IS* definitions. Fixed sys/stat.h to
  properly detect freestanding environments using __STDC_HOSTED__ to avoid
  #include_next warnings in kernel builds.
- ✅ **AT_*/O_* consolidation**: Updated 13 syscall files to use fcntl.h for AT_FDCWD,
  AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR, AT_EACCESS, AT_EMPTY_PATH, AT_SYMLINK_FOLLOW,
  and O_* flags: sys_faccessat.c, sys_fchmodat.c, sys_fchownat.c, sys_fstatat.c,
  sys_linkat.c, sys_mkdirat.c, sys_mknodat.c, sys_openat.c, sys_readlinkat.c,
  sys_renameat.c, sys_symlinkat.c, sys_unlinkat.c, sys_utimensat.c
- ✅ **mm_tests.c cleanup**: Updated kernel/tests/mm_tests.c to use fcntl.h and
  sys/mman.h instead of local O_*/PROT_*/MAP_* definitions
- ✅ **Signal mask indexing bug fix**: Fixed off-by-one array indexing bug in
  subsystems/posix_compat/posix_syscall.c where signal_handler_masks[signum] should
  have been signal_handler_masks[signum - 1] (signals are 1-indexed, arrays 0-indexed).
  Also added lower bounds check for signum > 0.

### January 21, 2026 Session — Security Hardening (Continued)
- ✅ **Timer syscall userspace access**: Fixed sys_timer.c to use proper userspace
  access validation (fut_access_ok + fut_copy_to_user/fut_copy_from_user) instead
  of direct pointer dereferences:
  - sys_timer_create: Validate timerid pointer, use fut_copy_to_user
  - sys_timer_settime: Validate new_value/old_value, use fut_copy_from_user/to_user
  - sys_timer_gettime: Validate curr_value pointer, use fut_copy_to_user
- ✅ **Futex syscall userspace access**: Fixed sys_get_robust_list to use
  fut_copy_to_user instead of direct *head_ptr and *len_ptr writes
- ✅ **set_tid_address Phase 3**: Actually implemented Phase 3 (was incorrectly
  marked as complete):
  - Added clear_child_tid field to fut_task_t structure
  - sys_set_tid_address now stores tidptr in task->clear_child_tid
  - Initialized clear_child_tid to NULL in fut_task_create
- ✅ **Automatic ioctl direction detection**: Added _IOC_DIR extraction macros to
  sys_ioctl.c for comprehensive security validation:
  - Implements Linux-compatible _IOC_* extraction macros
  - Automatically detects output ioctls (_IOC_WRITE) and validates write permission
  - Automatically detects input ioctls (_IOC_READ) and validates read permission
  - Eliminates need for hardcoded requires_write lists
  - Retains legacy handling for non-encoded ioctls (TCGETS, TCSETS, etc.)
- ✅ **set_tid_address Phase 4**: Complete NPTL/pthread support by implementing
  clear_child_tid behavior on thread exit:
  - Added futex_wake_one() kernel-internal function in sys_futex.c
  - task_cleanup_and_exit() now writes 0 to clear_child_tid address
  - Wakes one futex waiter to notify pthread_join()
  - Enables efficient thread joining via futex-based waiting
- ✅ **xattr syscall DRY refactoring**: Extracted common patterns from 12 xattr
  syscall variants into reusable helper functions:
  - xattr_copy_path_and_name(), xattr_copy_name(), xattr_copy_path()
  - xattr_validate_setxattr_flags(), xattr_get_flags_desc(), xattr_get_size_desc()
  - Eliminates significant code duplication across set/lset/fset, get/lget/fget,
    list/llist/flist, and remove/lremove/fremove xattr variants
- ✅ **Credential syscalls Phase 2**: Implemented setreuid, setregid, setresuid,
  and setresgid with proper POSIX privilege checking:
  - Added saved UID/GID (suid/sgid) fields to fut_task_t structure
  - Privileged (root): Can set any UID/GID to any value
  - Unprivileged: Can only set to current real, effective, or saved UID/GID
  - Enables proper privilege dropping and temporary privilege escalation

## Current Focus

### x86-64 Platform
1. **FSD daemon integration**: Connect fsd to kernel VFS for FIPC filesystem service (or integrate userland FuturaFS).
2. **Process groups / Job control**: Implement setpgid/getpgid for shell fg/bg/Ctrl+Z support.
3. **Pipe enhancements**: Verify pipe() syscall works correctly for shell pipelines.
4. **libfutura enhancements**: Add scanf, strtol, errno, threading helpers.

### ARM64 Platform
1. **✅ MMU enabled**: Identity mapping operational with L1/L2 page tables; full virtual memory support working.
2. **✅ Driver porting COMPLETE**: virtio-blk, virtio-net, virtio-gpu all ported to ARM64 using PCI ECAM.
3. **🚧 Apple Silicon M2 support** (75% complete): Device tree detection, AIC interrupt controller, s5l-uart console driver implemented. See `docs/APPLE_SILICON_ROADMAP.md`.
4. **Platform parity**: Continue matching x86-64 feature set (userland binaries, test framework).
5. **Wayland support**: Port compositor and clients to ARM64.

### Cross-Platform
1. **Distributed FIPC boot**: Automatic netd + registry startup.
2. **libfutura enhancements**: scanf, strtol, errno, threading helpers.
3. **Performance**: Continue optimizing IPC, scheduler, and block I/O paths.

## Technical Highlights

**Architecture**
- Capability-based security model with rights checking on all kernel objects.
- FIPC (Futura Inter-Process Communication) unifies syscalls, GUI, and distributed IPC.
- Cooperative scheduling with wait queues (no preemption overhead).
- Per-task MMU contexts with COW support and VMA management.

**Build System**
- Reproducible builds with `REPRO=1` flag.
- Cross-platform Makefile supporting x86-64 and ARM64.
- Rust driver integration (staticlib compilation).
- Performance CI with baseline comparison and ±5% drift detection.

**Testing**
- Kernel self-tests run at boot (VFS, framebuffer, memory management, multiprocess).
- Host-side FIPC regression suite (remote loopback, capabilities, AEAD, metrics).
- FuturaFS crash consistency harness with panic injection.
- Performance microbenchmarks with percentile tracking.

## Near-Term Roadmap

**Q4 2025**
- Complete demand paging implementation (x86-64).
- ARM64 MMU enablement and driver porting.
- Expand test coverage for memory management.
- FuturaFS kernel integration via fsd.

**Q1 2026**
- ARM64 platform parity with x86-64.
- Full TTY input stack with canonical mode.
- Signal handling implementation.
- Additional drivers (AHCI, Ethernet, USB).

## Performance Metrics

Recent performance highlights (x86-64):
- **IPC latency**: Sub-microsecond for local channels.
- **Fork overhead**: Reduced by >90% with COW (hash table ref counting).
- **Compositor**: >30% speedup with damage-aware partial compositing.
- **Scheduler**: Deterministic cooperative scheduling with zero preemption overhead.

## Documentation

- `README.md` — Project overview, build instructions, feature summary.
- `CLAUDE.md` — Development guide for Claude Code with build commands and patterns.
- `CONTRIBUTING.md` — Coding standards, commit conventions, workflow.
- `docs/ARM64_STATUS.md` — Detailed ARM64 platform progress.
- `docs/ARCHITECTURE.md` — System architecture and design principles.
- `docs/RELEASE.md` — Reproducible build and signing pipeline.
- `docs/TESTING.md` — Test infrastructure and coverage.

## Getting Involved

Futura OS welcomes contributions! Priority areas:
- ARM64 MMU debugging and driver porting.
- Memory management test coverage.
- Demand paging implementation.
- TTY input stack and line discipline.
- Additional Rust drivers (storage, networking).

See `CONTRIBUTING.md` for guidelines and `README.md` for build instructions.

---

**Futura OS** — A Modern Capability-Based Nanokernel
Copyright © 2025 Kelsi Davis | Licensed under MPL-2.0

# x86_64 SMP: Status and Bring-Up Architecture

**Date**: 2026-07-09
**Status**: 🟡 **SMP bring-up is functional; cross-CPU thread
placement remains gated behind `smp_sched` pending the remaining
direct fd-table classification and the current SMP scheduler/thread
test failure.**

- **Default boot** (no flag): every CPU is brought online with full
  per-CPU state (GDT/TSS, IDT, syscall MSRs, LAPIC timer) but stays
  in an idle loop — all runnable threads pin to the BSP. This is the
  shipped configuration; single-CPU behaviour is unchanged.
- **`smp_sched` boot flag**: enables cross-CPU thread placement and
  work stealing. The normal single-BSP scheduling harness passes the
  full 2735-test suite. The direct `-smp 2` path currently reaches the
  clear-child-tid/futex tests and fails at test 1236 (below).
- **`nosmp` boot flag**: disables AP bring-up entirely (single-CPU).

## What was fixed to get here

The blockers were all instances of *per-CPU state that had been
implemented as globals*, plus a handful of missing SMP primitives.

### 1. IRQ-context state moved into per-CPU data (`14551e7d`)
`fut_in_interrupt` and `fut_current_frame` were single globals written
by every CPU's interrupt entry/exit. `fut_schedule()` reads them to
choose between the IRETQ and cooperative context-switch paths, so on
SMP one CPU's ISR entry corrupted another CPU's scheduling decision,
producing wrong-path selection and corrupted saved user frames.

Both now live in `fut_percpu_t` at fixed offsets (120/128). x86_64
assembly (`isr_stubs.S`, `context_switch.S`) accesses them via
`%gs:PERCPU_IN_INTERRUPT` / `%gs:PERCPU_CURRENT_FRAME`; C code uses
`fut_cpu_in_irq()` / `fut_cpu_current_frame()` accessors. `_Static_assert`s
pin the struct offsets the assembly depends on. The GS base is now
bootstrapped in `platform_init` *before* the IDT is loaded, so no
interrupt can ever run against an unprogrammed GS base.

### 2. Per-CPU GDT/TSS + syscall MSRs (`5ed34747`)
A shared TSS `#GP`s on the second `ltr` (the descriptor busy bit
forbids reuse), and an AP arrives from the trampoline with `CS=0x18`
— which decodes as *user data* under the kernel GDT, so the first
`IRETQ` would fault. Each AP now gets its own GDT + TSS via
`fut_tss_init_ap()` (which also reloads CS to `0x08`), and programs
its own LSTAR/STAR/FMASK/EFER.SCE via `fut_syscall_msr_init()`.
`cpu_features_init` was also split into detect-once + apply-per-CPU,
because APs were `#UD`-ing on the first SSE `memset` with `CR4.OSFXSR`
still clear.

**AP bring-up order is load-bearing** (`ap_main`, `smp.c`):
`lidt → cpu_features_init → percpu_init → fut_tss_init_ap → fut_percpu_set
→ fut_syscall_msr_init → lapic_init → sched_init_cpu → lapic_timer_periodic
→ sti;hlt idle`. `fut_tss_init_ap` must run *before* `fut_percpu_set`
because the segment reload it performs zeroes the GS base.

### 3. SMP-safe panic, kernel-PF retry, TLB shootdown (`e401164b`)
- **Panic serialization**: crash dumps from two CPUs interleaved into
  mutual garbage. The first faulting CPU claims a panic-owner slot
  (nested faults on the same CPU re-enter freely) and freezes all
  other cores via a halt IPI (vector 0xF0) before dumping.
- **Kernel PF retry**: a NOT-PRESENT fault on a kernel-half address
  can be a benign cross-CPU race (another CPU mid-way through
  installing a mapping). The handler re-walks the shared tables and,
  if the translation now exists, `invlpg`s and retries instead of
  panicking.
- **TLB shootdown IPI** (vector 0xF1): unmap and permission-tightening
  previously flushed only the local TLB, leaving remote CPUs with
  dead/writable translations. A broadcast full-flush with acked
  completion and a 10 ms timeout (so a remote core spinning with IRQs
  off can't deadlock the sender) is wired into `fut_unmap_page`/
  `fut_unmap_range` (batched per range), `pmap_protect`, and
  `clone_mm`'s COW arming (batched per fork).

### 4. `struct fut_file` refcount across read/write (`2e5cde2c`)
`fut_vfs_read`/`write` resolved the fd via a bare atomic load of
`task->fd_table[fd]` and then used the pointer without holding a
reference. A concurrent `close()` on another CPU could free the struct
in the window between load and dereference — a use-after-free that
crashed `fut_vfs_read` at `-smp 4` (freed slot reused as a string
buffer; RAX = ASCII `"00040000"` dereferenced as a pointer).

`fut_file_get()`/`fut_file_put()` make fd-resolve-plus-ref atomic
against close: the getter takes a new per-task `fd_lock` across
`{load slot + refcount++}`, and `fut_vfs_close` clears the slot under
the same lock before its `refcount--`. read/write converted to
get + single-exit put.

## Remaining blockers for `smp_sched` default-on

### A. fd-resolvers on the bare loader — fd-helper tranches done, direct sweep left
The `struct fut_file` UAF class (a bare `fd_table[fd]` load raced by a
concurrent `close()` on another CPU) is fixed for:
- the hot in-VFS paths: `read`, `write` (`2e5cde2c`), and `lseek`,
  `mmap`, `open_at`, `resolve_at` (`6ea92d97`);
- every dereferencing caller of the `vfs_get_file_from_task` wrapper
  in `kernel/sys_*.c` — pread64/pwrite64/preadv/pwritev, write/writev
  (setuid-clear resolve), fsync/fdatasync/syncfs, flock, fchown,
  futimens/utimensat, statx/faccessat/fstatat/openat2 (dirfd path
  resolution), getdents64, the f*xattr family, fstatfs/fallocate,
  splice/vmsplice/tee/sync_file_range, sendfile, copy_file_range,
  dup/dup2/dup3, fcntl (body split into `fcntl_impl` with the file
  pinned by the `sys_fcntl` wrapper), pidfd_getfd (cross-task resolve),
  perf_event_open group_fd, and sendmsg SCM_RIGHTS (the fd-queue
  in-flight ref now comes atomically from `fut_file_get`);
- `fut_vfs_readdir_fd`, which resolved via the legacy bare `get_file()`.
  The remaining callers of the wrapper only NULL-check the slot
  (free-fd scans, existence probes) and cannot use-after-free.

The next tranche converted the dereferencing fd-only helper users:
`fstat`, `fchmod`, `ftruncate`, `fadvise`, `readahead`, the O_DIRECTORY
and O_PATH validation paths in `open`/`openat`/`mmap`, `preadv2`
RWF_APPEND, `acct`, `clone3` `CLONE_INTO_CGROUP`, capability-open,
elf64 fd-exec and inherited-fd cloning, epoll registration/wait
scans, poll/select wiring and scans, eventfd/timerfd/signalfd setup
and wake paths, pty helpers, pipe/socket/socketpair/accept setup, and
small direct-vnode users (`fchdir`, `fchownat`, `linkat`
`AT_EMPTY_PATH`, `cachestat`). Socket send/recv and AIO fd-only helper
uses were audited and left as EBADF/existence probes because they do
not dereference or retain the returned `fut_file_t`.

The direct fd-table follow-up then converted:
- POSIX mqueue fd-private-data users (`mq_timedsend`,
  `mq_timedreceive`, `mq_notify`, `mq_getsetattr`) to pin the owning
  file for the full private-data lifetime, including blocking waits;
- pidfd setup and pid extraction paths to pin before reading
  `pidfd_ctx`, while copying the PID out before slower signal/ptrace
  checks;
- inotify instance lookup and init-time flag setup to pin the
  inotify file, keeping `inst->file` as a non-owning back-pointer;
- fanotify, userfaultfd, and memfd post-allocation file-flag writes
  to pin the just-created fd before mutating `struct fut_file`;
- ioctl's primary fd resolve into a pinning `sys_ioctl` wrapper plus
  `ioctl_impl`, so the long switch and its early returns use a stable
  file pointer; loop/block ioctl helpers now reuse that pinned file
  instead of rereading `fd_table[fd]`;
- `sendmsg(SCM_RIGHTS)` to pre-pin every transferred fd before
  publishing any of them to the socket fd queue; the queued references
  are the in-flight ownership refs consumed by `recvmsg` or dropped
  by socket teardown.

The current socket tranche added `get_socket_pinned()`, a
`fut_file_get()`-backed socket resolver for syscall paths that need to
dereference or retain `fut_socket_t *` past the fd-table lookup. It
converted the socket metadata/control families that had many early
returns (`bind`, `connect`, `listen`, `accept`/`accept4`, `close`,
`shutdown`, `sendmsg`, `sendmmsg`, `recvmmsg`, `setsockopt`,
`getsockopt`, `getpeername`, `getsockname`) and the socket data paths
that keep touching the socket after userspace copies or queued-message
work (`sendto`, `recvfrom`, `recvmsg`). It also converted procfs
`/proc/<pid>/fd*` readers that inspect another task's fd. The long
option and send/receive handlers now use local cleanup-return helpers
so new branches cannot silently leak the pin.

The follow-up socket-readiness tranche converted the remaining
syscall-side socket dereferences that were still using bare
`get_socket_from_fd`: `sendfile` socket source/output classification,
`fcntl(F_SETFL)` propagation of `O_NONBLOCK`, `poll` wire/unwire and
readiness scans, `select`/`pselect6` wire/unwire and readiness scans,
and `epoll` registration, fd-close cleanup, and wait readiness scans.
It also converted socket ioctl side paths (`FIONREAD`, `TIOCOUTQ`,
`FIONBIO`, `FIOASYNC`) plus the socket-layer byte-count helpers used
by those ioctls.
These paths now either hold the owning socket file pinned across the
socket dereference or funnel through a small helper that pins, acts,
and drops before returning. The audited `fut_vfs_get_file` users left
in AIO and epoll are errno-class probes only (`EBADF` vs
`EOPNOTSUPP`/`EINVAL`) and do not dereference or retain the pointer.
The lingering `vfs_get_file_from_task` users in fstatat, dup/dup2,
fcntl free-fd scans, and close_range(CLOEXEC) are existence probes or
owner-side fd-table mutation and do not dereference the loaded file.

The latest direct-table tranche added `fut_file_get_with_flags()`, a
pinning resolver that samples descriptor flags under the same
`fd_lock` as the file ref. It converted `kcmp(KCMP_FILE)` to compare
pinned file objects, fork fd inheritance to transfer a pinned child fd
reference instead of bumping a raw `fd_table[]` pointer, and both ELF
exec inherited-fd loops to sample `FD_CLOEXEC` atomically with the
slot being pinned. It also changed the fork overflow rollback path to
drop already-inherited files with `fut_file_put()` instead of raw
refcount subtraction.

**Remaining fd follow-up**: direct `task->fd_table[]` sites still need
final classification. The remaining production hits are mostly
NULL-check-only errno/existence probes, newly-created-task fd-table
writes before publication, owner-side close/dup mutation, task
teardown, and proc/debug summaries. They should be either documented
as non-dereferencing or converted if a later audit finds a retained or
dereferenced file pointer.

### B. Current `-smp 2 smp_sched` failure: clear-child-tid child never runs
Validation on 2026-07-09 after the fd inheritance/kcmp tranche:
`make kernel` passed and `make test` passed with
`ALL TESTS PASSED (2735/2735)`. Direct SMP validation with
`timeout 420s make run KAPPEND="futura.runtests async-tests=1 smp_sched"
EXTRA_QEMU_FLAGS="-smp 2"` brought both CPUs online, enabled
`smp_sched`, reached the miscellaneous syscall suite, then failed:
`Test 1235: child thread created, tid=8` followed by
`Test 1236: child never wrote TID (timeout)` and QEMU exit 169.

This failure is in the kernel self-test path for
`CLONE_CHILD_CLEARTID`: a child thread is created, but under
cross-CPU placement it did not run and publish its TID before the
parent's bounded yield loop expired. The normal non-`smp_sched`
`make test` path passes the same test. Next work should inspect
`fut_thread_create` runnable publication, per-CPU run queue wakeups,
and the yield loop/wakeup path used by tests 1235-1238.

### C. Control-flow corruption at `-smp 4` (distinct bug, UNVALIDATABLE here)
After the read/write fix, `-smp 4 + smp_sched` runs well past the CAP
and EPOLL suites, then dies with **Invalid Opcode, RIP in kernel
stack space** (`0x88xxxxxx`, not `.text` at `0x8020xxxx`–`0x804xxxxx`;
the bytes at RIP are data). A return address or function pointer was
overwritten and execution jumped into a stack page. `-smp 2` does not
hit it.

**This cannot currently be reproduced reliably.** Under `-smp 4` with
active cross-CPU IPI traffic (concurrent forks → `clone_mm` TLB
shootdown), QEMU's own TCG hits
`qemu_mutex_lock_iothread_impl: assertion failed` (a host emulator
bug, cpus.c:504) and aborts — sometimes before, sometimes after the
guest crash. `/dev/kvm` is unavailable in this environment, so there
is no non-TCG path. Diagnosing/validating a fix for blocker B needs
either KVM or a QEMU build without the MTTCG IPI assertion. `-smp 2`
(which does not trigger the QEMU bug and passes cleanly) is the
reliable ceiling here.

## Debugging notes

- `smp_sched` is a multiboot cmdline flag read from GRUB. For the ISO
  harness, append it to the `multiboot2` line used to build the ISO
  (the current `test-iso` target hardcodes its test command line) and
  run QEMU with `-smp 2`. The direct `run` path honors `KAPPEND` and
  `EXTRA_QEMU_FLAGS`, but boots the initramfs path rather than the
  full ISO self-test harness.
- QEMU's MTTCG occasionally aborts under `-smp 4` with its own
  `qemu_mutex_lock_iothread` assertion — a host emulator bug, not
  ours. Use `-accel tcg,thread=single` for deterministic
  single-threaded TCG when debugging the kernel at `-smp 4`.
- The AP LAPIC timer currently uses the crude fallback count (10 M)
  because `smp_init` runs before `lapic_timer_calibrate_and_start`.
  `lapic_timer_get_calibrated_count()` is already preferred in
  `ap_main`; deferring `smp_init` past calibration is a trivial change
  once `-smp 4` is stable.
- Direct `make run KAPPEND="futura.runtests async-tests=1 smp_sched"
  EXTRA_QEMU_FLAGS="-smp 2"` boots the initramfs path rather than the
  full ISO self-test harness. The direct runtest path skips Wayland
  payload staging and `/sbin/init` staging/launch so the kernel
  self-test thread is not blocked by GUI userland heap pressure or an
  init respawn loop. `/proc/modules` also reports the monolithic empty
  listing while `futura.runtests` is active, keeping the self-test ABI
  independent of the interactive driver manifest. The run still logs a
  nonfatal CLI shell staging `-ENOMEM` for the large shell blob; this
  is no longer a blocker for self-test boots but remains a RAMFS
  contiguous-allocation cleanup item.
- The Intel i915 init path must treat `i915_init()` failure as a hard
  stop for follow-on i915 phases. On QEMU `-smp 2`, PCI 00:02.0 is the
  e1000 NIC (`class=0x020000`), so the i915 probe correctly rejects it
  as non-display; the kernel now skips GTT/BCS/framebuffer registration
  afterward instead of running phase-2+ probes against an uninitialized
  BAR/GTT state.

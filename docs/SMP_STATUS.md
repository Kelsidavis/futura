# x86_64 SMP: Status and Bring-Up Architecture

**Date**: 2026-07-08
**Status**: 🟡 **Bring-up complete and validated; cross-CPU thread
placement gated behind `smp_sched` boot flag pending two remaining
concurrency fixes.**

- **Default boot** (no flag): every CPU is brought online with full
  per-CPU state (GDT/TSS, IDT, syscall MSRs, LAPIC timer) but stays
  in an idle loop — all runnable threads pin to the BSP. This is the
  shipped configuration; single-CPU behaviour is unchanged.
- **`smp_sched` boot flag**: enables cross-CPU thread placement and
  work stealing. Passes the full 2735-test suite at `-smp 2`. At
  `-smp 4` two distinct concurrency bugs remain (below).
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

### A. Remaining fd-resolvers still use the bare loader
`lseek`, `ioctl`, `fstat`, `sendmsg`, `recvmsg`, `getdents`, and other
syscalls still resolve fds via `get_file_from_task` without a
reference — same UAF class as read/write, not yet converted to
`fut_file_get`/`fut_file_put`. Mechanical sweep.

### B. Control-flow corruption at `-smp 4` (distinct bug)
After the read/write fix, `-smp 4 + smp_sched` runs well past the CAP
and EPOLL suites, then dies with **Invalid Opcode, RIP in kernel
stack space** (`0x88xxxxxx`, not `.text` at `0x8020xxxx`–`0x804xxxxx`;
the bytes at RIP are data). A return address or function pointer was
overwritten and execution jumped into a stack page. `-smp 2` does not
hit it. This is the current top blocker.

## Debugging notes

- `smp_sched` is a **multiboot cmdline flag** read from GRUB, *not*
  the compiled `KAPPEND` fallback. The `test-iso` Makefile target
  hardcodes the GRUB cmdline; to test with the flag, rebuild the ISO
  with `smp_sched` appended to the `multiboot2` line in
  `iso/boot/grub/grub.cfg` (or a copy) and `grub-mkrescue`.
- QEMU's MTTCG occasionally aborts under `-smp 4` with its own
  `qemu_mutex_lock_iothread` assertion — a host emulator bug, not
  ours. Use `-accel tcg,thread=single` for deterministic
  single-threaded TCG when debugging the kernel at `-smp 4`.
- The AP LAPIC timer currently uses the crude fallback count (10 M)
  because `smp_init` runs before `lapic_timer_calibrate_and_start`.
  `lapic_timer_get_calibrated_count()` is already preferred in
  `ap_main`; deferring `smp_init` past calibration is a trivial change
  once `-smp 4` is stable.

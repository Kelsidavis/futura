# Futura OS Architecture (Updated Oct 2025)

## High-Level Design

Futura OS keeps the trusted computing base intentionally small. The kernel owns timekeeping, scheduling, memory management, interrupt handling, and the FIPC message fabric. Everything else—including filesystems, networking, compositor, and user tools—lives in user space as replaceable services that communicate over FIPC.

```
┌─────────────┐      ┌────────────────────┐
│ Applications│◀────▶│  User Services     │
│  (fbtest,   │  FIPC│  (fsd, posixd,     │
│  future CLI)│      │   futurawayd, …)   │
└─────────────┘      └────────┬───────────┘
                               │ FIPC channels
┌──────────────────────────────┴───────────────────────────────┐
│                        Futura Kernel                         │
│  Scheduler & WaitQs │  Syscall Bridge │  VFS  │ FIPC Core    │
│  Timer Wheel        │  MM Contexts    │  RamFS│ Capability AC│
└─────────────────────┴─────────────────┴───────┴──────────────┘
                 │ HW Abstraction │ Platform Drivers
                 └────────────────┴────────────────────────────
```

## Kernel Components

- **Per-task MM contexts (`kernel/memory/fut_mm.c`)**  
  A reference-counted wrapper around page tables. Each task receives a dedicated address space, the kernel half is shared, and the loader seeds a heap base after the last ELF segment. Anonymous mappings, `brk`, and heap reclamation operate through this layer.

- **Scheduler & Wait Queues (`kernel/scheduler`, `kernel/threading`)**  
  The run queue remains priority-aware and non-preemptive for now. New wait queue primitives (`fut_waitq`) allow syscalls such as `waitpid` and the timer subsystem to block threads without spinning.

- **Syscall Surface (`kernel/sys_*.c`)**  
  `int 0x80` bridges now cover `exit`, `waitpid`, `time_millis`, `brk`, `mmap`, `munmap`, `nanosleep`, and the diagnostic `echo`. The dispatcher is shared with the POSIX compatibility layer (`subsystems/posix_compat/`).

- **FIPC Core (`kernel/ipc/`)**  
  Provides capability-tagged channels used by syscalls, compositor traffic, and remote transports. Phase 4 introduces CRC-backed remote framing and authenticated control paths.

- **Virtual File System (`kernel/vfs/`, `docs/VFS_IMPLEMENTATION.md`)**  
  Stable path resolution and reference counting back the RAM-backed root volume. Ongoing work tracks integrating FuturaFS and file-backed `mmap`.

- **Device Layer (`drivers/`)**  
  The new TTY console driver fronts `/dev/console` and feeds the serial backend. Framebuffer MMIO glue remains under `drivers/video/`.

## Userland Stack

- **libfutura (`src/user/libfutura/`)**  
  Provides crt0, inline syscall veneers (`include/user/sys.h`), a `brk`-backed allocator, `printf`, and basic string utilities. Everything links statically.

- **Core Services**  
  `init`, `fsd`, `posixd`, and `futurawayd` provide the bootstrap envelope, filesystem façade, POSIX compatibility, and compositor respectively. Tests and demos live under `src/user/`.

- **Host Tooling (`tests/`, `host/transport/`)**  
  Reuses FIPC framing to deliver deterministic regression tests for remote transport, registry auth, and compositor output.

## Memory Map Summary (x86-64 Reference)

- **Higher-half kernel**: canonical mapping with direct-map identity for physical memory management.
- **User space layout**:
  - Text + data from ELF segments mapped read-only/read-write per header.
  - Heap base seeded one page above the last load segment; grows via `sys_brk`.
  - Anonymous `mmap` regions allocated above `mm->mmap_base`, respecting capability-enforced limits.
  - Stack staged via `stage_stack_pages()` with guard pages.

## Concurrency Model

The kernel remains cooperative: threads yield on blocking calls, wait queues wake them when work arrives, and timer sleeps enqueue on a sorted wheel. Phase 5 will layer preemption and per-CPU scheduler shards atop the existing primitives.

## Roadmap Alignment

- **Phase 2** (current): mature user services, solidify syscall/runtime surface, and harden VFS integration.
- **Phase 3**: compositor upgrades (multi-surface, metrics) and richer system telemetry over FIPC.
- **Phase 4**: encrypted remote transport, registry hardening, and kernel metrics publication.

For historical milestones, see `docs/PHASE*_*.md`; for the latest operational summary, see `docs/CURRENT_STATUS.md`.

# Futura OS API Reference (Updated Jan 22 2026)

This document indexes the public headers and categorises their stability. The
focus is on surfaces consumed by userland services, host tooling, and external
contributors.

## Legend

- **Stable** – committed to backward compatibility within the current major.
- **Beta** – expected to change with feedback; provide tests when consuming.
- **Experimental** – subject to rapid iteration; avoid depending on unless you
  own the call site.

## Kernel-Facing Headers

| Header | Area | Status | Notes |
| --- | --- | --- | --- |
| `include/kernel/fut_object.h` | Handle/object API | **Stable** | Rights bits, object types, sharing stubs. |
| `include/kernel/fut_mm.h` | Per-task memory contexts | **Beta** | API settled; expect additional helpers for copy-on-write. |
| `include/kernel/fut_sched.h` | Scheduler + wait queues | **Beta** | Wait queues new; SMP hooks stubbed. |
| `include/kernel/syscalls.h` | Syscall prototypes | **Stable** | Surface adds `mmap`, `munmap`, `brk`, `nanosleep`. |
| `include/kernel/fut_blockdev.h` | Legacy blockdev shim | **Experimental** | Superseded by async blkcore + log FS bridge. |
| `include/kernel/fut_waitq.h` | Wait queue primitives | **Stable** | Backed by scheduler infrastructure. |
| `include/kernel/console.h` | `/dev/console` registration | **Stable** | Console driver now lives in `drivers/tty/`. |

## Async Block Core & Filesystems

| Header | Area | Status | Notes |
| --- | --- | --- | --- |
| `include/futura/blkdev.h` | Async block core user API | **Beta** | Rights enforced; submit/flush/close available. |
| `subsystems/futura_fs/futfs.h` | Log-structured FS skeleton | **Experimental** | Minimal create/write/read/rename; expect expanded directory metadata. |
| `include/kernel/fut_futurafs.h` | Legacy kernel FS | **Stable** | Bitmap allocator; kept for compatibility until fsd migrates. |

## Userland Runtime

| Header | Area | Status | Notes |
| --- | --- | --- | --- |
| `include/user/sys.h` | Syscall veneers | **Stable** | Inline `int 0x80` glue for 0–6 args. |
| `include/user/stdio.h` | Minimal printf | **Beta** | New `printf/vprintf` implementation; scan variants pending. |
| `include/user/sysnums.h` | Syscall numbers | **Stable** | Mirrors kernel definitions. |
| `include/shared/fut_timespec.h` | ABI struct | **Stable** | Shared between kernel and user nanosleep. |

## Host Tooling

| Artifact | Status | Notes |
| --- | --- | --- |
| `build/lib/libfipc_host.a` | **Stable** | Deterministic FIPC harness for tests (built by `host/transport`). |
| `build/tools/mkfutfs` | **Experimental** | Formats images for the log-structured FS; interface will grow options. |
| `build/tools/syswatch` | **Beta** | Observability helper; evolving with metrics schema. |

## Subsystem Libraries

| Path | Status | Notes |
| --- | --- | --- |
| `subsystems/futura_fs/` | **Experimental** | Log FS skeleton + tests; targeting eventual fsd integration. |
| `subsystems/posix_compat/` | **Beta** | int80 dispatcher and POSIX bridge helpers. |

## Consuming Guidance

- Prefer capability handles over raw descriptors. The async block core and
  log-structured FS deliberately mirror object rights to avoid security gaps.
- When integrating new drivers, document any C implementations that violate the
  “memory-safe by default” security OKR and open an issue to track Rust ports.
- Host tools should link against the static libraries in `build/lib` to avoid
  stale object files. See `tests/Makefile` and `tools/Makefile` for examples.

For a live view of milestones, risks, and OKRs consult `docs/STATUS.md`.

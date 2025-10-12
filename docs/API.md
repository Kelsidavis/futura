# Futura OS API Overview (Updated Oct 2025)

This document captures the developer-facing interfaces that are stable (or stabilising) in the Phase 2 codebase.

## Kernel Syscalls

| Syscall               | Number | Status      | Notes |
|-----------------------|--------|-------------|-------|
| `sys_exit`            | 60     | Stable      | Terminates the calling task, wakes parent waiters. |
| `sys_waitpid`         | 61     | Stable      | Blocks on child exit using `fut_waitq`; supports exact PID waits. |
| `sys_time_millis`     | 400    | Stable      | Returns monotonic milliseconds since boot. |
| `sys_echo`            | 42     | Diagnostic  | Copies a buffer back to user space for smoke tests. |
| `sys_brk`             | 12     | Stable      | Grows/shrinks the heap within `fut_mm` limits; backs `malloc`. |
| `sys_mmap`            | 9      | Beta        | Supports anonymous mappings today; file-backed mappings next. |
| `sys_munmap`          | 11     | Beta        | Unmaps regions created by `sys_mmap`. |
| `sys_nanosleep`       | 35     | Beta        | Sleeps with millisecond granularity via the timer wheel. |

- All syscalls are invoked via the `int $0x80` bridge using wrappers in `include/user/sys.h`.
- Return values follow POSIX conventions (negative errno on failure).

## Userland Runtime (`libfutura`)

Header: `src/user/libfutura/include` (exported via `include/user/` during build).

| Component        | Key APIs                                  | Notes |
|------------------|-------------------------------------------|-------|
| crt0             | `_start`, `libc_init`                     | Minimal entry sequence that sets up stack arguments and calls `main`. |
| Syscall veneers  | `sys_call0..6`, `sys_write`, `sys_mmap`…  | Inline assembly wrappers preserved in headers for zero overhead. |
| Memory allocator | `malloc`, `free`, `calloc`, `realloc`     | Free-list allocator seeded via `sys_brk_call`; coalesces adjacent blocks. |
| I/O              | `printf`, `vprintf`, `puts` (via `printf`)| Buffered format routines writing to FD 1 using `sys_write`. |
| Strings          | `memcpy`, `memset`, `strcmp`, …           | Provided in `string.c`; optimised for small binaries. |

User binaries link statically against `libfutura.a`. There is no dynamic loader yet; all dependencies must be bundled.

## POSIX Compatibility (`subsystems/posix_compat/`)

- `posix_syscall.c` translates host-side test requests into Futura syscalls.  
- Supported subset: `open`, `close`, `read`, `write`, `ioctl`, `mmap`, `munmap`, `brk`, `nanosleep`, `wait4`, `exit`.  
- Intended for development tooling; production services should target the native FIPC APIs.

## FIPC Service APIs

- **Kernel**: `include/kernel/fut_fipc.h` defines channel descriptors, capability tokens, and synchronous send/recv helpers.
- **Host/Tests**: `host/transport/` reuses the same headers for remote loopback and registry tests.
- **User Services**: `src/user/libfutura/fipc.c` offers a thin veneer over the kernel message queues (pending Phase 4 refactor).

## Device Interfaces

- `/dev/console`: serial-backed character device; opens return a stream that normalises `\n` to `\r\n`.
- Framebuffer IOCTLs: defined in `include/kernel/fb_ioctl.h`; consumed by `src/user/fbtest`.

## Stability Policy

- Everything tagged **Stable** is covered by regression tests and expected to remain backward compatible through Phase 2.
- **Beta** surfaces may change; expect field feedback to influence struct layouts or return codes.
- Diagnostic endpoints (e.g., `sys_echo`) can disappear once replacement tooling lands.

For implementation details, cross-reference `include/kernel/syscalls.h`, `include/user/sys.h`, and the per-module documentation listed in `docs/`.

# Current Status — Memory & Userland Refresh

## Highlights
- Per-task MM contexts (`fut_mm`) own page tables, manage `CR3` switches, and expose VMA helpers for `brk`/`mmap`.
- Scheduler wait queues unblock `waitpid` callers and prepare the ground for future blocking I/O.
- `/dev/console` now lands via a dedicated TTY driver that bridges directly to the serial backend.
- Syscall surface expands with `mmap`, `munmap`, `brk`, and `nanosleep`; the POSIX shim dispatches to the real kernel handlers.
- `libfutura` grows a `sys.h` veneer set, `printf`, and a `brk`-backed allocator; demos rely on libc-lite instead of ad-hoc helpers.

## Kernel Progress
- Introduced `kernel/memory/fut_mm.c` with reference-counted mm objects, heap tracking, and anonymous mapping helpers.
- ELF loader seeds heap bases after the final load segment so user heaps start clean and page-aligned.
- Added syscall implementations: `sys_brk`, `sys_mmap`, `sys_munmap`, `sys_nanosleep`, all exposed through `include/kernel/syscalls.h`.
- Implemented `fut_waitq` (scheduler wait queues) and wired them into task tear-down so `waitpid` callers block without spinning.
- Timer sleep path now relies on wait queues instead of manually unlinking threads from the run queue.

## Userland & Runtime
- New shared header (`include/shared/fut_timespec.h`) defines the ABI struct shared between kernel and userland.
- `include/user/sys.h` exposes inline `int 0x80` veneers for the syscall surface; `include/user/sysnums.h` centralises the numbers.
- `libfutura`'s allocator now grows via `sys_brk_call` and maintains a free-list with coalescing; `printf`/`vprintf` sit on top of `write(2)`.
- `fbtest` demo consumes the new runtime: uses `sys_mmap`, allocates scanlines, sleeps with `sys_nanosleep_call`, and prints FPS via `printf`.

## Tooling & Devices
- Registered `/dev/console` through a new TTY driver that performs CR→LF translation and advertises itself via devfs.
- POSIX compatibility layer now forwards `mmap`, `munmap`, `brk`, and `nanosleep` requests to the kernel implementations.
- Build system updated to pull in new kernel/object files (wait queue, syscalls, console driver, libfutura `printf`).

## Immediate Next Steps
1. Extend `sys_mmap` path to back file mappings and add regression coverage for `munmap`.
2. Push wait queues into timers and IPC primitives that still spin (pipes, event channels).
3. Add console input handling (basic line discipline) and surface a userland REPL over `/dev/console`.
4. Expand `libfutura` with formatted output variants, errno, and time helpers so demos can drop bespoke glue.

# Futura OS

**A Modern Capability-Based Nanokernel Operating System**

<div align="center">
  <img src="Rory the Ouroboros.png" alt="Rory the Ouroboros - Futura OS Mascot" width="280" />
  <p><em>Rory the Ouroboros — Futura's self-contained, eternally evolving mascot</em></p>
</div>

Copyright © 2025 Kelsi Davis
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE)

---

## 🚀 Overview

Futura OS is a capability-first nanokernel that keeps the core minimal—time, scheduling, IPC, and hardware mediation live in the kernel while everything else runs as message-passing services over FIPC. The current development focus is on building out a practical userland surface so real applications can execute against the kernel primitives.

### Status Snapshot — Updated Nov 4 2025

- **Kernel**: Advanced memory management with COW fork, file-backed mmap, and partial munmap; comprehensive syscall surface (`fork`, `execve`, `mmap`, `munmap`, `brk`, `nanosleep`, `waitpid`, `pipe`, `dup2`).
- **VFS**: Path resolution + RamFS production-ready; file-backed mmap integrated with eager loading; FuturaFS implementation complete with host-side tools.
- **Shell & Userland**: 32+ built-in commands with pipes, redirections, job control, and history; `libfutura` provides crt0, syscall veneers, heap allocator, and formatted I/O.
- **Distributed FIPC**: Host transport and registry daemons stable; remote UDP bridge for distributed communication.
- **Wayland Compositor**: Multi-surface capable with window decorations, drop shadows, damage-aware compositing, and frame throttling.
- **ARM64 Port**: Full multi-process support with 177 syscalls, EL0/EL1 transitions, fork/exec/wait working. MMU disabled but kernel fully functional.

### What's new — Updated Nov 4 2025

**Recent kernel enhancements (Phase 3—Memory Management):**
- **Copy-on-write (COW) fork**: Process creation shares pages between parent and child, copying only on write via page fault handler. Hash table-based reference counting tracks shared pages with optimizations for sole-owner cases. Dramatically reduces fork() memory overhead and enables efficient fork-exec patterns.
- **File-backed mmap**: VFS-backed memory mappings through `fut_vfs_mmap()`. Files are eagerly loaded with vnode reference counting. VMAs track file backing for future demand paging.
- **Partial munmap with VMA splitting**: `munmap()` handles shrinking VMAs from edges or splitting middle sections while preserving file backing.

**Recent userland focus (Shell & utilities):**
- **32+ shell built-in commands**: Comprehensive Unix-like shell with full support for pipes (`|`), input/output redirection (`<`, `>`, `>>`), job control (`&`, `fg`, `bg`), and command history with arrow keys + tab completion.
  - **File operations**: `cat`, `cp` (multi-file), `mv` (atomic rename), `rm` (with `-f`), `touch`, `mkdir` (recursive `-p`), `rmdir`, `ls` (with `-a`, `-l` flags)
  - **Text processing**: `grep`, `wc`, `head`, `tail`, `cut`, `tr`, `sort`, `uniq`, `paste`, `diff`, `tee`
  - **Utilities**: `find`, `echo`, `test`, `[`, `pwd`, `cd`, `clear`, `help`, and more
  - **Stdin support across all tools**: Proper pipeline integration for Unix-style data flow.

**Advanced compositor:**
- **Wayland compositor** with multi-surface support, window decorations, drop shadows, damage-aware partial compositing (>30% speedup), and frame throttling for smooth rendering.
- **FuturaFS host tools**: `mkfutfs` (formats images with configurable segments), `fsck.futfs` (offline integrity checker with repair).

**Kernel & runtime stability:**
- **Scheduler wait queues**: `fut_waitq` delivers blocking semantics for `waitpid`, timers, and future I/O without spinning.
- **Console character device**: `/dev/console` via TTY driver with automatic newline normalization.
- **libfutura**: crt0, syscall veneers, heap allocator backed by `sys_brk`, lightweight `printf` on `write(2)`, and string utilities.

**ARM64 platform bring-up:**
- **177 working syscalls**: Full Linux-compatible ABI (x8=syscall, x0-x7=args) including fork, exec, wait, networking, filesystem, I/O multiplexing, signals, timers, futex, and more.
- **Multi-process support**: Complete fork → exec → wait → exit cycle working with EL0/EL1 context switching.
- **Platform initialization**: Exception vectors, GICv2 interrupts, ARM Generic Timer, PL011 UART, physical memory manager (1 GB).
- **Userland runtime**: crt0 for ARM64, syscall wrappers, working demo programs.
- **MMU status**: Currently disabled but kernel fully functional with physical addressing; MMU enablement deferred.

See `docs/CURRENT_STATUS.md` and `docs/ARM64_STATUS.md` for deeper dives into the latest changes and platform-specific progress.

**Website**: [https://futuraos.com/](https://futuraos.com/)

---

## 📁 Project Structure

```
futura/
├── drivers/
│   ├── rust/                # Rust staticlib drivers (virtio-blk, virtio-net, common FFI)
│   ├── tty/                 # Console character device → serial with line discipline
│   ├── video/               # Framebuffer MMIO, PCI VGA, virtio-gpu drivers
│   └── input/               # PS/2 keyboard and mouse drivers
├── docs/                    # Architecture, status, testing, release documentation
├── include/
│   ├── kernel/              # Kernel-facing headers
│   ├── shared/              # Shared ABI types (e.g., fut_timespec)
│   └── user/                # Userland syscall shims & libc-lite headers
├── kernel/
│   ├── memory/              # fut_mm (per-task MMU contexts, COW, mmap)
│   ├── scheduler/           # Runqueue, wait queues, stats
│   ├── ipc/                 # FIPC core, object table, registry
│   ├── vfs/                 # Path resolution, RamFS, devfs, FuturaFS
│   ├── fs/                  # FuturaFS kernel integration
│   ├── blockdev/            # Block core, virtio-blk bridge
│   ├── net/                 # FuturaNet, loopback device
│   ├── video/               # Framebuffer management, graphics
│   ├── sys_*.c              # System call implementations
│   └── tests/               # Kernel self-tests (run at boot)
├── platform/
│   ├── x86_64/              # Primary hardware target (QEMU/KVM reference)
│   │   └── drivers/         # x86-specific: AHCI, PCI, APIC
│   └── arm64/               # ARM64 port: 177 syscalls, multi-process support, EL0/EL1 transitions
├── src/user/
│   ├── libfutura/           # Minimal C runtime (crt0, malloc, printf, syscalls)
│   ├── shell/               # 32+ built-in commands, pipes, redirects, job control
│   ├── fsd/                 # Filesystem daemon
│   ├── posixd/              # POSIX compatibility daemon
│   ├── init/                # Process 1, service bootstrap
│   ├── svc_registryd/       # Service discovery with HMAC protection
│   ├── netd/                # UDP bridge for distributed FIPC
│   ├── compositor/          # Wayland server (multi-surface, decorations, shadows)
│   ├── clients/             # Wayland client demos (wl-simple, wl-colorwheel)
│   ├── fbtest/              # Framebuffer sample app exercising syscalls
│   ├── services/winsrv/     # Legacy window server (pre-Wayland)
│   └── ...                  # Various utilities and demos
├── subsystems/
│   ├── posix_compat/        # int80 dispatcher bridging POSIX ABIs to Futura
│   └── futura_fs/           # Log-structured FuturaFS (host-side tools, kernel skeleton)
├── tests/                   # Host-side FIPC regression and filesystem tests
├── tools/                   # Build utilities (mkfutfs, fsck.futfs)
├── third_party/wayland/     # Vendored Wayland 1.23.0 libraries
├── host/                    # Host-side transport library for remote FIPC
└── iso/                     # GRUB boot configuration and staging
```

Futura currently targets x86-64 as the primary architecture (QEMU/KVM reference builds). The ARM64 port under `platform/arm64/` has achieved full multi-process support with 177 working syscalls and is rapidly approaching parity with x86-64.

---

## 🔧 Building

### Prerequisites

- GCC/Clang with C23 support
- GNU Make & Binutils
- Rust toolchain (`rustc` + `cargo`) for kernel drivers (`make rust-drivers`)
- QEMU (optional, for kernel ISO boot tests)
- Optional: OpenSSL (`-lcrypto`) if you want to run remote FIPC AEAD tests (auto-skip otherwise)

### Quick Start (host-side libraries & tests)

```bash
# Build host transport library + userland runtime
make -C host/transport
make -C src/user/libfutura
make -C tests

# Run the remote FIPC regression suite (examples)
./build/tests/fipc_remote_loopback
./build/tests/fipc_remote_capability
./build/tests/fipc_remote_aead_toy
./build/tests/fipc_remote_metrics
```

### Kernel (QEMU ISO)

```bash
# Build Rust drivers + kernel + ISO
make rust-drivers
make
cp build/bin/futura_kernel.elf iso/boot/
grub-mkrescue -o futura.iso iso/

# Boot with serial output
qemu-system-x86_64 -cdrom futura.iso -serial stdio -display none -m 128M
```

On boot you should see RAM/VMM init, device registration (including `/dev/console`), FIPC bring-up, and bootstrap threads that exercise VFS and the framebuffer user smoke test.

### Desktop Step 2 demo

```bash
# Build + boot the winsrv/winstub loop (enable logs with DEBUG_WINSRV=1)
make DEBUG_WINSRV=1 desktop-step2
```

The QEMU console will show the window server announcing readiness and the stub client drawing its three test rectangles:

```
[WINSRV] ready 800x600 bpp=32
[WINSRV] create 320x200 -> id=1
[WINSRV] damage id=1 rect x=0 y=0 w=320 h=200
[WINSTUB] connected; created surface 1 (320x200)
[WINSTUB] drew 3 rects; bye
```

The stub throttles updates with short sleeps so the damage passes remain visible on hardware-backed framebuffers.

### Wayland compositor demo

Futura includes a mature Wayland server implementation with advanced compositor features:

```bash
# One-time setup: vendor Wayland libraries
make third_party-wayland

# Build and run the Wayland demo
make wayland-step2
```

This builds the full Wayland server (`futura-wayland`) with multi-surface support, window decorations,
drop shadows (configurable radius), damage-aware partial compositing (>30% speedup), and frame throttling.
Client demos (`wl-simple`, `wl-colorwheel`) exercise the server's surface management and rendering.

**Features**:
- **Multi-surface compositing**: Layered surfaces with z-ordering
- **Window decorations & shadows**: With configurable shadow radius
- **Damage-aware updates**: Only recomposite changed regions (>30% speedup in M2)
- **Frame throttling**: Smooth rendering at display refresh rates
- **Backbuffer mode**: Off-screen rendering for advanced effects
- **Premultiplied alpha**: Correct blending with transparency
- **Environment variables** for feature toggle:
  - `WAYLAND_BACKBUFFER=1` – Enable off-screen rendering
  - `WAYLAND_DECO=1` – Window decorations
  - `WAYLAND_SHADOW=1` – Drop shadow rendering
  - `WAYLAND_RESIZE=1` – Window resize support
  - `WAYLAND_THROTTLE=1` – Frame throttling

> **Tip (headful runs)**  
> The Wayland demo expects a linear framebuffer. When launching QEMU manually use either Bochs or
> virtio GPU output, e.g.
>
> ```bash
> qemu-system-x86_64 \
>     -m 512 \
>     -serial stdio \
>     -drive if=virtio,file=futura_disk.img,format=raw \
>     -display gtk \
>     -vga none \
>     -device bochs-display \
>     -kernel build/bin/futura_kernel.elf \
>     -initrd build/initramfs.cpio \
>     -append "XDG_RUNTIME_DIR=/tmp WAYLAND_DISPLAY=wayland-0 WAYLAND_MULTI=1 \
>              WAYLAND_BACKBUFFER=1 WAYLAND_DECO=1 WAYLAND_SHADOW=1 \
>              WAYLAND_RESIZE=1 WAYLAND_THROTTLE=1 fb-fallback=1"
> ```
>
> Avoid the harness-only `-device isa-debug-exit` flag when running interactively; otherwise QEMU will
> terminate as soon as the kernel finishes the demo.

### Debugging

Enable targeted tracing at build time by defining the relevant flag, for example:

```bash
make CFLAGS+=-DDEBUG_VFS   # verbose VFS path-walker logs
make CFLAGS+=-DDEBUG_VM    # paging / large-page split diagnostics
make CFLAGS+=-DDEBUG_BLK   # block stack + virtio-blk traces
make CFLAGS+=-DDEBUG_NET   # FuturaNet + virtio-net driver traces
```

`DEBUG_BLK` automatically propagates to the Rust virtio-blk driver (`--cfg debug_blk`) so the BAR/capability dumps only reappear when you opt in.

### Rust driver builds

### Filesystem utilities

Run `make tools` to build the host-side helpers under `build/tools/`:

- `mkfutfs` — formats a FuturaFS image. Useful flags:
  - `--segments <N>` control total log segments
  - `--segment-sectors <N>` set sectors per segment
  - `--block-size <bytes>` select on-disk block granularity (default 512)
  - `--inodes <N>` seed the inode high-water mark
  - `--label <text>` stamp the volume label
  Example: `build/tools/mkfutfs futfs.img --segments 64 --segment-sectors 16 --block-size 4096 --label Demo`

- `fsck.futfs` — offline integrity checker/repair tool:
  - `fsck.futfs --device futfs.img --dry-run` reports structural issues without touching the image
  - `fsck.futfs --device futfs.img --repair` rewrites malformed directory streams and refreshes superblock counters
  - Add `--gc` to opportunistically compact directories with heavy tombstone churn

### Crash-consistency harness

`make futfs-crash-test` regenerates a scratch image, forces a compaction panic (`futurafs.test_crash_compact=1`) to simulate power loss, reboots without the flag, then runs `fsck.futfs` in dry-run and repair modes. A `futfs_crash_gc: PASS` banner indicates the loop survived and post-crash metadata is clean.

### Performance harness

- `make perf` boots the kernel with `perf=on`, runs the deterministic IPC/scheduler/block/net microbenchmarks, and saves the summary lines to `build/perf_latest.txt` while streaming console output to the terminal.
- `make perf-ci` reruns the harness and compares the latest results against `tests/baselines/perf_baseline.json`, failing the build if any percentile drifts beyond ±5 %.
- To refresh the baseline after intentional optimisations, inspect `build/perf_latest.txt`, update the JSON with the new steady-state values, and commit both files together.

### Release pipeline

See `docs/RELEASE.md` for the reproducible build + signing workflow (`make repro`, `make release`, `make sbom`, `make sign`, `make metadata`, `make verify`) and integration notes for Cosign/SBOM tooling.

Rust drivers live under `drivers/rust/` and compile to `staticlib` artifacts that the kernel links directly. You can rebuild them without touching the C pieces via:

```bash
make rust-drivers
```

`make clean` tears down both the C objects and the Cargo `target/` directories.

---

## 🧠 Architecture Highlights

- **Nanokernel core**: Deterministic cooperative scheduler, per-task MMU contexts with COW support, comprehensive syscall surface (fork, execve, mmap, munmap, brk, nanosleep, waitpid, pipe, dup2), and unified FIPC transport.

- **FIPC everywhere**: Same capability-backed message path serves syscalls, GUI surfaces, distributed communication, and remote transports. Host tooling reuses kernel framing logic for testing without hardware.

- **Capability security**: Tokens (handles) accompany every inter-process operation. Rights bitmaps enforce read/write/admin permissions on all kernel objects. Remote transports bind capabilities into HMAC-SHA256 headers to reject mismatches early.

- **Advanced memory management**:
  - Copy-on-write fork() with hash table-based page reference counting and optimizations for sole owners
  - File-backed mmap with vnode tracking (supports future demand paging)
  - Partial munmap with VMA splitting for fine-grained memory control
  - Per-task MMU contexts owning page tables and driving CR3 switches
  - Executable inheritance of clean address spaces with kernel half pre-mapped

- **Scheduler & synchronization**: Cooperative scheduling with wait queues for `waitpid`, timers, and future I/O—no busy-waiting, no preemption overhead.

- **Console + VFS**: `/dev/console` routes to serial with line discipline; RamFS powers the root filesystem; file-backed mmap enables memory-mapped I/O; devfs provides device access.

- **Wayland compositor**: Multi-surface capable with window decorations, drop shadows, damage-aware partial compositing, frame throttling, and premultiplied-alpha blending.

- **Comprehensive shell**: 32+ built-in commands with pipes, I/O redirection, job control, command history, and tab completion—enabling interactive scripting and workflow automation.

- **Userland runtime**: crt0, syscall veneers, malloc backed by kernel heap growth, printf/vprintf stack, FIPC client library, and POSIX compatibility stubs for legacy code.

---

## 🧪 Test & Demo Catalog

**Kernel & IPC:**
- `tests/fipc_*` — Host transport & security regression coverage (loopback, capability, header v1, AEAD, metrics, admin ops).
- `kernel/tests/` — VFS smoke tests, framebuffer surface checks, syscall exercises (run at boot via serial log).

**Storage & Filesystem:**
- `tests/futfs_*` — FuturaFS host-mode unit tests and crash consistency validation.
- `make futfs-crash-test` — Simulates power loss with panic injection, validates fsck recovery.
- `tools/mkfutfs` — Image formatter with configurable segments/block size.
- `tools/fsck.futfs` — Offline integrity checker with repair mode.

**Wayland & Graphics:**
- `tests/futuraway_*` — Compositor smoke & benchmark harnesses with deterministic framebuffer hashing for CI.
- `src/user/compositor/futura-wayland/` — Full Wayland server with multi-surface support.
- `src/user/clients/wl-simple`, `wl-colorwheel` — Client demos exercising compositor.
- `src/user/fbtest` — Framebuffer demo using `mmap`, `nanosleep`, printf stack.

**Shell & Utilities:**
- `src/user/shell/` — 32+ built-in commands with pipes, redirections, job control, history, tab completion.
- `make test` — Full system boot test with shell initialization.

**Performance & Metrics:**
- `make perf` — Deterministic IPC/scheduler/block/net microbenchmarks with percentile tracking.
- `make perf-ci` — Compare against baseline, fail on >5% drift.
- `build/perf_latest.txt` — Latest benchmark results.

---

## 🗺️ Roadmap (Next Steps)

**Phase 3 — Memory Management (✅ Complete)**
1. ✅ Copy-on-write fork with reference counting
2. ✅ File-backed mmap with eager loading
3. ✅ Partial munmap with VMA splitting
4. ✅ Comprehensive syscall surface (fork, execve, mmap, munmap, brk, nanosleep, waitpid, pipe)

**Phase 4 — Userland Foundations (🚧 In Progress)**
1. ✅ 32+ shell built-in commands with pipes, redirections, job control
2. ✅ Wayland compositor with advanced compositing features
3. 🚧 Full TTY input stack (extend `/dev/console` with canonical mode input, line discipline completion)
4. 🚧 FuturaFS kernel integration via fsd FIPC bridge
5. 🚧 Demand paging for file-backed mmap (page fault handler for unmapped pages)
6. 🚧 Comprehensive test coverage for memory management edge cases

**Phase 5 — Advanced Features (🚧 In Progress)**
1. Distributed FIPC boot integration (automatic netd + registry startup)
2. Enrich `libfutura` with formatted scanning, errno handling, threading helpers
3. Signal handling support
4. Additional subsystems (futex, semaphores, advanced IPC primitives)
5. ✅ ARM64 multi-process support (177 syscalls working)
6. 🚧 ARM64 MMU enablement for proper address space isolation
7. 🚧 ARM64 platform parity with x86-64 (drivers, networking, graphics)
8. Additional drivers (AHCI/SATA, Ethernet/WiFi, USB)

**Future Enhancements (Planned)**
- Multi-user support and permission model
- Secure Boot integration
- Audio/sound subsystem
- Bluetooth and advanced wireless
- GPU driver improvements and CUDA-like compute support

---

## 🤝 Contributing

We favour focused, well-tested patches. The project values quality kernel implementations and practical userland features. Good entry points:

**Memory Management & Kernel:**
- Add comprehensive tests for memory management (COW fork edge cases, file-backed mmap stress tests, munmap scenarios).
- Implement demand paging for file-backed mmap (optimize from eager loading to lazy page-fault handler).
- Extend signals support (currently scaffolding only).
- Build advanced IPC primitives (futex, semaphores).

**Userland & Shell:**
- Expand `/dev/console` with full TTY input stack (canonical mode, input buffering, control characters).
- Enhance shell scripting features (functions, arrays, advanced expansions).
- Build additional userland utilities and tools using the syscall layer.
- Polish `libfutura` with formatted scanning (scanf, strtol), proper errno handling, threading helpers.

**Filesystem & Storage:**
- Complete FuturaFS kernel integration via fsd FIPC bridge.
- Build tools for filesystem analysis and debugging.
- Add crash-recovery tests and validation.

**Drivers & Platforms:**
- Contribute memory-safe drivers in Rust (AHCI/SATA, Ethernet, USB).
- ARM64 development: Enable MMU, port drivers (virtio-blk, virtio-net), add graphics support.
- Improve virtio-net driver integration.
- Test ARM64 on real hardware (Raspberry Pi, etc.).

**Testing & CI:**
- Expand performance microbenchmark coverage.
- Build integration tests for shell + filesystem workflows.
- Add fuzzing harnesses for parser/protocol components.

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding style, commit conventions, and workflow details.

---

## 📜 License

Mozilla Public License 2.0 (MPL-2.0). See [LICENSE](LICENSE).

---

## 🐉 About Rory the Ouroboros

Rory is Futura's beloved mascot — a self-contained serpent embodying the eternal cycle of system evolution. With pastel coloring and circuit-board patterns woven throughout, Rory represents the kernel's capability-based design philosophy: a system that feeds back into itself, continuously improving and adapting. Like the mythical ouroboros, Futura OS is designed to be complete yet ever-evolving.

---

## 📞 Contact & Community

- **Author**: Kelsi Davis
- **Email**: [dumbandroid@gmail.com](mailto:dumbandroid@gmail.com)
- **Issues/Discussions**: GitHub

Built with ❤️ and Rory's wisdom for the future of operating systems.

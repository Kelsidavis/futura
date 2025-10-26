# Futura OS

**A Modern Capability-Based Nanokernel Operating System**

Copyright © 2025 Kelsi Davis  
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE)

---

## 🚀 Overview

Futura OS is a capability-first nanokernel that keeps the core minimal—time, scheduling, IPC, and hardware mediation live in the kernel while everything else runs as message-passing services over FIPC. The current development focus is on building out a practical userland surface so real applications can execute against the kernel primitives.

### Status Snapshot — Updated Oct 26 2025

- **Kernel**: Advanced memory management with COW fork, file-backed mmap, and partial munmap; syscall surface covers `mmap`, `munmap`, `brk`, `nanosleep`.
- **VFS**: Path resolution + RamFS production-ready; file-backed mmap integrated with eager loading.
- **Userland**: `libfutura` provides crt0, syscall veneers, heap allocator, and formatted I/O; framebuffer demo exercises the stack.
- **Distributed FIPC**: Host transport and registry daemons stable; kernel transport hardening continues in Phase 4.

### What's new — Updated Oct 26 2025

- **Copy-on-write (COW) fork**: Process creation now shares pages between parent and child, copying only on write via page fault handler. Hash table-based reference counting tracks shared pages, with optimizations for sole-owner cases. Dramatically reduces fork() memory overhead and enables efficient fork-exec patterns.
- **File-backed mmap**: VFS-backed memory mappings now supported through `fut_vfs_mmap()`. Files are eagerly loaded into memory with vnode reference counting. VMAs track file backing (vnode pointer + offset) for future demand paging optimization.
- **Partial munmap with VMA splitting**: `munmap()` now handles unmapping parts of VMAs (shrink from left/right), splitting VMAs when unmapping middle sections, and unmapping across multiple VMAs in one call. Properly preserves file backing information during splits.
- **Per-task MMU contexts**: `fut_mm` objects now own page tables, track VMAs, drive `CR3` switches, and manage heap growth via `brk(2)` plus anonymous `mmap(2)`.
- **Rust virtio-blk driver**: async blkcore now links against a Rust staticlib that probes PCI, negotiates queues, and registers `/dev/vda` through the new FFI layer.
- **Syscall surface**: kernel exports `mmap`, `munmap`, `brk`, and `nanosleep`; userland gains inline wrappers in `include/user/sys.h` and a shared ABI header for `timespec`.
- **Scheduler wait queues**: `fut_waitq` delivers blocking semantics to `waitpid`, timers, and future drivers without spinning.
- **Console character device**: `/dev/console` is wired through a TTY driver that fans out to the serial backend with automatic newline normalization.
- **libfutura refresh**: heap allocator now grows via `sys_brk_call`, a lightweight `printf` stack sits on top of `write(2)`, and higher-level code (e.g. `fbtest`) uses the new syscall shims.

See `docs/CURRENT_STATUS.md` for a deeper dive into the latest changes and near-term plans.

---

## 📁 Project Structure

```
futura/
├── drivers/
│   ├── rust/                # Rust staticlib drivers (virtio-blk, common FFI)
│   ├── tty/                 # Console character device → serial
│   └── video/               # Framebuffer MMIO glue
├── docs/                    # Architecture and status reports
├── include/
│   ├── kernel/              # Kernel-facing headers
│   ├── shared/              # Shared ABI types (e.g., fut_timespec)
│   └── user/                # Userland syscall shims & libc-lite headers
├── kernel/
│   ├── memory/              # fut_mm (per-task MMU contexts)
│   ├── scheduler/           # Runqueue, wait queues, stats
│   ├── sys_*                # System call implementations
│   └── ...                  # IPC, VFS, device code
├── platform/
│   ├── x86_64/              # Primary hardware target (QEMU/KVM reference)
│   └── arm64/               # Experimental bring-up scaffolding
├── src/user/
│   ├── fbtest/              # Framebuffer sample app exercising syscalls
│   └── libfutura/           # Minimal C runtime (crt0, malloc, printf, syscalls)
└── subsystems/
    └── posix_compat/        # int80 dispatcher bridging POSIX ABIs to Futura
```

Futura currently targets x86-64 as the primary architecture (QEMU/KVM reference builds). The legacy 32-bit path is archived only for historical context, and a nascent arm64 port lives under `platform/arm64/` with significant TODOs.

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

### Wayland toolchain prep (early access)

We are beginning the migration toward a Wayland-compatible compositor. To stage the required
libraries and code generators, vendor the upstream stack once:

```bash
make third_party-wayland
```

This downloads Wayland 1.23.0 into `third_party/wayland/`, builds static client/server libraries,
installs `wayland-scanner` under `build/third_party/wayland/install/bin/`, and exposes make
variables (`WAYLAND_*`) so userland components can consume the headers and libs in later steps.

To exercise the current compositor/client skeleton loop, run:

```bash
make wayland-step2
```

This target rebuilds the kernel with the Wayland demo enabled, stages the compositor (`futura-wayland`)
and client (`wl-simple`) into `/sbin` and `/bin`, then boots QEMU to show the handshake logs on the
serial console.

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

- **Nanokernel core**: deterministic scheduler, per-task MM contexts with COW support, and a unified FIPC transport for syscalls, IPC, and GUI traffic.
- **FIPC everywhere**: same capability-backed message path serves syscalls, GUI surfaces, and remote transports; host tooling reuses the kernel's framing logic.
- **Capability security**: tokens accompany every hop; remote transports bind the capability into header authentication to reject mismatches early.
- **Advanced memory management**: Copy-on-write fork() with page reference counting, file-backed mmap with vnode tracking, partial munmap with VMA splitting. Executables inherit clean address spaces with kernel half mapped, ELF loaders seed a post-binary heap base, and `sys_brk` + `sys_mmap` drive growth.
- **Wait queues**: scheduler-level queues unblock `waitpid` callers, timers, and future I/O without busy-waiting.
- **Console + VFS**: `/dev/console` routes to serial; VFS scaffolding powering the RAM-backed root and ELF loader remains stable, with file-backed mmap enabling memory-mapped I/O.
- **Userland runtime**: crt0, syscall veneers, `malloc` backed by the kernel heap, and `printf`/`string` utilities make it possible to write small demos with predictable behaviour.

---

## 🧪 Test & Demo Catalog

- `tests/fipc_*` — Host transport & security regression coverage (loopback, capability, header v1, AEAD, metrics, admin ops).
- `tests/futuraway_*` — Compositor smoke & benchmark harnesses (layered surfaces, deterministic framebuffer hashes).
- `src/user/fbtest` — Framebuffer demo using `mmap`, `nanosleep`, and the refreshed `printf` stack to benchmark draw throughput.
- Kernel self-tests: VFS smoke, framebuffer surface checks, syscall exercises executed during boot (see serial log).

---

## 🗺️ Roadmap (Next Steps)

1. ✅ ~~Wire the anonymous `mmap` path into VFS-backed file mappings~~ (Completed: file-backed mmap with eager loading)
2. ✅ ~~Flesh out `munmap` test coverage~~ (Completed: partial munmap with VMA splitting)
3. Extend `/dev/console` into a full TTY stack (line discipline, input buffering, canonical mode) and surface it to userland shells for interactive REPL.
4. Plumb wait queues into additional subsystems (pipes, futex-style sync, compositor events).
5. Enrich `libfutura` with formatted scanning, errno handling, and lightweight threading helpers.
6. Add comprehensive test coverage for memory management (COW fork behavior, file-backed mmap, munmap edge cases).
7. Optimize file-backed mmap with demand paging (page fault handler for unmapped file pages).
8. Integrate distributed FIPC transport into the boot sequence (automatic `netd` + registry registration).

---

## 🤝 Contributing

We favour focused, well-tested patches. Good entry points:

- Add targeted tests for memory management (COW fork behavior, file-backed mmap, partial munmap edge cases).
- Implement demand paging for file-backed mmap (optimize from eager loading to lazy fault-in).
- Expand `/dev/console` with line discipline and input buffering for interactive shells.
- Polish `libfutura` primitives (strtol, snprintf, errno, scanf) to support richer demos.
- Build simple userland tools using the new syscall layer.

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding style and workflow details.

---

## 📜 License

Mozilla Public License 2.0 (MPL-2.0). See [LICENSE](LICENSE).

---

## 📞 Contact & Community

- **Author**: Kelsi Davis  
- **Email**: [dumbandroid@gmail.com](mailto:dumbandroid@gmail.com)  
- **Issues/Discussions**: GitHub

Built with ❤️ for the future of operating systems.

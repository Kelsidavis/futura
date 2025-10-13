# Futura OS

**A Modern Capability-Based Nanokernel Operating System**

Copyright © 2025 Kelsi Davis  
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE)

---

## 🚀 Overview

Futura OS is a capability-first nanokernel that keeps the core minimal—time, scheduling, IPC, and hardware mediation live in the kernel while everything else runs as message-passing services over FIPC. The current development focus is on building out a practical userland surface so real applications can execute against the kernel primitives.

### Status Snapshot — Updated Oct 12 2025

- **Kernel**: Per-task MM and wait queues landed; syscall surface now covers `mmap`, `munmap`, `brk`, `nanosleep`.
- **VFS**: Path resolution + RamFS remain production-ready; ongoing work tracks integrating FuturaFS and file-backed `mmap`.
- **Userland**: `libfutura` provides crt0, syscall veneers, heap allocator, and formatted I/O; framebuffer demo exercises the stack.
- **Distributed FIPC**: Host transport and registry daemons stable; kernel transport hardening continues in Phase 4.

### What's new — Updated Oct 12 2025

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

Rust drivers live under `drivers/rust/` and compile to `staticlib` artifacts that the kernel links directly. You can rebuild them without touching the C pieces via:

```bash
make rust-drivers
```

`make clean` tears down both the C objects and the Cargo `target/` directories.

---

## 🧠 Architecture Highlights

- **Nanokernel core**: deterministic scheduler, per-task MM contexts, and a unified FIPC transport for syscalls, IPC, and GUI traffic.
- **FIPC everywhere**: same capability-backed message path serves syscalls, GUI surfaces, and remote transports; host tooling reuses the kernel’s framing logic.
- **Capability security**: tokens accompany every hop; remote transports bind the capability into header authentication to reject mismatches early.
- **Per-task heap management**: executables inherit clean address spaces with kernel half mapped, ELF loaders seed a post-binary heap base, and `sys_brk` + `sys_mmap` drive growth.
- **Wait queues**: scheduler-level queues unblock `waitpid` callers, timers, and future I/O without busy-waiting.
- **Console + VFS**: `/dev/console` routes to serial; VFS scaffolding powering the RAM-backed root and ELF loader remains stable, while FuturaFS integration is the next milestone.
- **Userland runtime**: crt0, syscall veneers, `malloc` backed by the kernel heap, and `printf`/`string` utilities make it possible to write small demos with predictable behaviour.

---

## 🧪 Test & Demo Catalog

- `tests/fipc_*` — Host transport & security regression coverage (loopback, capability, header v1, AEAD, metrics, admin ops).
- `tests/futuraway_*` — Compositor smoke & benchmark harnesses (layered surfaces, deterministic framebuffer hashes).
- `src/user/fbtest` — Framebuffer demo using `mmap`, `nanosleep`, and the refreshed `printf` stack to benchmark draw throughput.
- Kernel self-tests: VFS smoke, framebuffer surface checks, syscall exercises executed during boot (see serial log).

---

## 🗺️ Roadmap (Next Steps)

1. Wire the anonymous `mmap` path into VFS-backed file mappings and flesh out `munmap` test coverage.
2. Plumb wait queues into additional subsystems (pipes, futex-style sync, compositor events).
3. Extend `/dev/console` into a full TTY stack (line discipline, input buffering) and surface it to userland shells.
4. Enrich `libfutura` with formatted scanning, errno handling, and lightweight threading helpers.
5. Integrate distributed FIPC transport into the boot sequence (automatic `netd` + registry registration).

---

## 🤝 Contributing

We favour focused, well-tested patches. Good entry points:

- Add targeted tests for the new memory manager (`sys_brk`, anonymous `mmap`, wait queue wakeups).
- Expand `/dev/console` capabilities or build simple userland tools using the new syscall layer.
- Polish `libfutura` primitives (strtol, snprintf, errno) to support richer demos.

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

# Futura OS

**A capability-first nanokernel OS with message-passing userland**

<div align="center">
  <img src="Rory the Ouroboros.png" alt="Rory the Ouroboros - Futura OS Mascot" width="280" />
  <p><em>Rory the Ouroboros — Futura's self-contained, eternally evolving mascot</em></p>
</div>

Copyright © 2025 Kelsi Davis
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE)

---

## 🚀 Overview

Futura OS is a capability-based nanokernel that keeps the core minimal (time, scheduling, IPC, and hardware mediation) and pushes policy into userland services connected via FIPC (Futura Inter-Process Communication). The repository includes the kernel, userland services, host tooling, and test harnesses used to validate the end-to-end stack.

### Status Snapshot — Updated Mar 17 2026

- **Kernel core**: Capability-backed object model, priority-aware scheduler (nice + RT), per-task MMU contexts, COW fork, file-backed mmap, VMA_LOCKED tracking, and 147 syscall implementation files in `kernel/`.
- **Linux compat**: 173 automated kernel self-tests across 11 test groups. Broad POSIX coverage: signals (SA_NODEFER, SA_RESETHAND, sigpending, signalfd, sigsuspend, sigtimedwait), epoll (EPOLLET, EPOLLONESHOT, EPOLLRDHUP), pipes (F_SETPIPE_SZ resize, poll POLLHUP, short writes), sockets (MSG_PEEK, SO_PEERCRED, SCM_RIGHTS, SOCK_CLOEXEC), timers (timerfd, POSIX timers, alarm, itimer), file I/O (O_APPEND, O_CLOEXEC per-fd, ftruncate, readv/writev, splice/tee, sendfile), process lifecycle (fork, waitpid, execve with ELF loading, clone).
- **Storage + VFS**: RamFS (full POSIX: chmod/chown/utimensat, symlinks, hardlinks, xattrs, inotify) + devfs (/dev/null, /dev/zero, /dev/full, /dev/urandom, /dev/console, /dev/tty, /dev/stdin/stdout/stderr); FuturaFS tooling in `tools/`.
- **Userland**: `init`, `fsd`, `posixd`, `netd`, `svc_registryd`, and `libfutura` under `src/user/`, plus a Unix-like shell with pipes, redirection, and job control.
- **Graphics**: Legacy window server (`services/winsrv` + `apps/winstub`) and a Wayland compositor (`src/user/compositor/futura-wayland`) with demo clients in `src/user/clients/`.
- **Platforms**: x86-64 is the reference build; ARM64 port passes all 173 tests. Apple Silicon bring-up under `platform/arm64/`.
- **CI**: GitHub Actions with x86_64 + ARM64 QEMU test runners, both green.

For deeper status notes see `docs/CURRENT_STATUS.md` and `docs/ARM64_STATUS.md`.

**Website**: [https://futuraos.com/](https://futuraos.com/)

---

## 🗺️ Current Milestone: Phase 4 – Userland Foundations

Status: 🚧 In progress (see `docs/STATUS.md` for milestone tracking and OKRs).

---

## 📁 Project Structure

```
futura/
├── kernel/              # Nanokernel core (mm, ipc, scheduler, vfs, syscalls)
├── platform/            # Platform HAL + arch-specific drivers (x86_64, arm64)
├── drivers/             # Rust/C driver sources (virtio, input, video, tty)
├── src/user/            # Userland services, shell, compositor, demos
├── include/             # Kernel + userland headers
├── subsystems/          # Optional subsystems (posix_compat, futura_fs)
├── host/                # Host-side FIPC transport + tooling
├── tools/               # mkfutfs, fsck.futfs, release helpers
├── tests/               # Host regression + perf suites
├── docs/                # Architecture, status, porting, testing
├── iso/                 # GRUB boot artifacts
├── mk/ scripts/         # Build helpers
└── build/               # Build output (kernel, initramfs, tools)
```

---

## 🔧 Building & Running

### Common targets

```bash
# Full rebuild (kernel + userland + ISO staging)
make clean && make

# Build Rust drivers (virtio-blk/net/gpu)
make rust-drivers

# Build host tools (mkfutfs, fsck.futfs, etc.)
make tools
```

### Run under QEMU (direct kernel + initramfs)

```bash
# Headless run (serial in terminal)
make run

# Headful run with GTK display
make run-headful

# Headful with VNC
make VNC=1 VNC_DISPLAY=unix:/tmp/futura-vnc run-headful
```

### ISO + harnessed test run

```bash
# Build GRUB ISO
make iso

# Automated QEMU harness (isa-debug-exit)
make test
```

### Wayland demo

```bash
make wayland-step2
# Optional headful run with auto-exit
make run-headful VNC=1 VNC_DISPLAY=unix:/tmp/futura-vnc AUTOEXIT=1
```

### Perf & crash tests

```bash
make perf
make perf-ci
make futfs-crash-test
```

See `docs/TESTING.md` for detailed test flows and troubleshooting.

---

## 📚 Documentation Map

- **Architecture**: `docs/ARCHITECTURE.md`
- **Current status**: `docs/CURRENT_STATUS.md`
- **ARM64 progress**: `docs/ARM64_STATUS.md`
- **Desktop roadmap**: `docs/DESKTOP_ROADMAP.md`
- **API surface**: `docs/API_REFERENCE.md`
- **Testing guide**: `docs/TESTING.md`
- **Porting**: `docs/PORTING_GUIDE.md`

---

## 🤝 Contributing

We favor focused, well-tested patches. See [CONTRIBUTING.md](CONTRIBUTING.md) for coding style, commit conventions, and workflow details.

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

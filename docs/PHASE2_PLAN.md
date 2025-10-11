# Phase 2 Commit Plan — Multi-Architecture Foundation

**Project:** Futura OS
**Status:** Post-nanokernel milestone — Cooperative + Preemptive Threading Stable
**Objective:** Establish a unified multi-architecture base (x86-64 + ARM64) with modern tooling and POSIX-compliant interfaces.

---

## 🧠 1. Core Goals

| Category | Target | Summary |
|----------|--------|---------|
| **Architectures** | x86-64 (active), ARM64 (prep) | Shared core kernel with platform abstraction in `/src/platform/<arch>/` |
| **Compiler Standard** | C23 + optional C++23 modules | Clean modern syntax, no C99 legacy, zero undefined behavior |
| **Build System** | Cross-platform Make + Ninja bridge | Modular targets per subsystem (kernel, drivers, userland) |
| **License** | MPL 2.0 | Flexible for open development, permits editorial/YouTube coverage |
| **Userland Interface** | POSIX compatible (syscalls + libc compat layer) | Ready for porting busybox, bash, and POSIX test suites |
| **Display** | FuturaWay (Wayland-compatible protocol on FIPC) | Async, multi-surface, GPU-accelerated compositor foundation |
| **Filesystem** | Modular VFS (FAT, ext4, FuturaFS) | Mountable backends with journaling and metadata API |
| **Networking** | Modern stack (IPv6, QUIC, WireGuard) | Socket API over FIPC transport |
| **Design Language** | Clean Futuristic (macOS 14 inspired) | Flat geometry, dynamic depth, contrast-driven hierarchy |

---

## ⚙️ 2. Planned Commits and Milestones

### 2.1 Platform Layer Rebuild

**Goal:** Establish architecturally clean platform abstractions.

```
src/platform/x86_64/
 ├─ nk_context.S
 ├─ nk_isr.S
 ├─ nk_thread_entry.S
 ├─ nk_platform_init.c
src/platform/arm64/
 ├─ nk_context.S
 ├─ nk_isr.S
 ├─ nk_platform_init.c
```

**Tasks:**
- [ ] Move all low-level assembly routines to `/platform/<arch>/`
- [ ] Define `struct nk_platform_ops` interface for init hooks
- [ ] Implement ARM64 boot and context switch skeleton
- [ ] Add platform auto-detection and build target switches

---

### 2.2 Kernel Configuration Framework

**Goal:** Unified architecture and feature flags.

- [ ] Create `config/futura_config.h` with `ARCH_X86_64`, `ARCH_ARM64`
- [ ] Add `CONFIG_VFS`, `CONFIG_FUTURAWAY`, `CONFIG_NET` macros
- [ ] Define `CONFIG_DEBUG_SERIAL` and `CONFIG_TRACE_IRQS`

---

### 2.3 Toolchain and Build System

**Goal:** Fully modular cross-compile environment.

- [ ] Add ARM64 GCC/Clang cross target (`aarch64-elf-gcc`)
- [ ] Split kernel vs userland builds
- [ ] Introduce ninja build config for incremental builds
- [ ] Automate CI/CD via FUTURA_BUILD agent

---

### 2.4 POSIX Subsystem

**Goal:** Baseline syscall table and userland bridge.

- [ ] Implement core syscalls: `open`, `read`, `write`, `fork`, `exec`, `wait`, `exit`
- [ ] Create `posix_syscall.c` dispatch layer
- [ ] Provide `libposix` stubs for compatibility tests
- [ ] Prepare for newlib integration or custom `futuralibc`

---

### 2.5 Filesystem Framework

**Goal:** Introduce VFS abstraction layer compatible with multiple backends.

- [ ] Add `vfs_mount`, `vfs_read`, `vfs_write`, `vfs_ioctl`
- [ ] Create mount drivers for FuturaFS and FAT
- [ ] Define `struct vnode_ops`
- [ ] Begin port of HFS allocation layer as optional backend module

---

### 2.6 IPC and Display Base

**Goal:** Foundation for FIPC and FuturaWay.

- [ ] Define shared memory IPC regions and event channels
- [ ] Implement `fipc_send()`, `fipc_recv()`
- [ ] Prototype `futurawayd` — a minimal user-space compositor daemon
- [ ] Implement basic surface creation and shared buffer mapping

---

### 2.7 Testing and Verification

**Goal:** Confirm multi-arch and POSIX stability.

- [ ] Add QEMU targets for x86_64 and aarch64
- [ ] Boot tests: thread context, interrupts, syscalls
- [ ] File tests: open → write → read → unlink
- [ ] Networking loopback simulation (test FIPC)

---

## 🧱 3. Deliverables

| Deliverable | Description |
|-------------|-------------|
| `kernel.elf` (x86-64) | Stable boot with multitasking and IPC |
| `kernel.elf` (ARM64) | Minimal boot with serial output |
| `futurawayd` | Prototype compositor daemon |
| `libposix.a` | Syscall compatibility library |
| `tests/` suite | POSIX and platform self-tests |

---

## 🧭 4. Design and Governance

### Lead Agents

- **FUTURA_KERNEL** – core context and scheduler
- **FUTURA_POSIX** – syscall and userland bridge
- **FUTURA_FS** – VFS and filesystem drivers
- **FUTURA_UI** – compositor and display layer
- **FUTURA_DIRECTION** – overall architectural cohesion

### Guiding Principles

- Minimal kernel, maximum userland services
- Architecture-neutral APIs
- Modular builds by subsystem
- Consistent documentation via FUTURA_DOC

---

## 🚀 5. Next Phase Preview

### Phase 3 — FuturaWay & Userland Genesis

- Launch userland environment and window server
- Begin FuturaUI toolkit prototype
- Integrate graphics stack and Wayland-compatible IPC

---

**Document Status:** Phase 2 roadmap
**Created:** 2025-10-11
**Owner:** Futura OS Core Team

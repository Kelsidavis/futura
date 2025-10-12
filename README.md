# Futura OS

**A Modern Capability-Based Nanokernel Operating System**

Copyright © 2025 Kelsi Davis
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE) for details

---

## 🚀 Overview

Futura OS is a modern modular nanokernel designed for contemporary hardware and security. It centers on a unified message‑passing fabric (FIPC), capability‑based access control, and strict separation between a tiny, deterministic kernel and replaceable user‑space services. The core stays small; everything else evolves independently over FIPC.

### What’s new (Oct 2025)

* **Remote FIPC v1**: UDP transport with a **versioned wire header**, **sequence numbers**, and **optional credits**.
* **Security**: **Replay protection** (sliding 64‑packet window) and **AEAD framing** (toy provider + optional OpenSSL ChaCha20‑Poly1305).
* **Service Discovery**: **Lazy auto‑discovery on first send** via a tiny registry; `netd` retries automatically once a service is registered.
* **Observability**: **System Metrics Stream (IDL‑v0)** on a reserved FIPC channel, published by **netd** and a **kernel metrics shim**; counters include lookups, retries, frames, auth failures, and replay drops.
* **Tests**: Full host test suite for loopback, discovery, capability guard, header v1, replay, AEAD (toy & OpenSSL), and system metrics subscribers.

---

## 📁 Project Structure

```
futura/
├── include/
│   ├── kernel/
│   │   ├── fut_fipc.h         # FIPC API (local + remote)
│   │   └── fut_fipc_sys.h     # System metrics channel & IDL tags
│   └── ...
├── kernel/
│   ├── ipc/                   # FIPC rings + host shim integration
│   └── ...
├── src/user/
│   ├── netd/                  # UDP transport bridge (AEAD, replay, discovery, metrics)
│   └── sys/                   # System metrics (IDL‑v0) publish/subscribe + kernel shim
└── tests/                     # Host-side tests for transport, security, and metrics
```

---

## 🔧 Building

### Prerequisites

* GCC/Clang with C23 support
* GNU Make & Binutils
* QEMU (optional, for kernel ISO boot tests)
* **Optional**: OpenSSL (`-lcrypto`) for real AEAD provider (tests auto‑skip if unavailable)

### Quick Start (host tests)

```bash
# Build host transport library + tests
make -C host/transport
make -C tests

# Run the full suite
./build/tests/fipc_remote_loopback
./build/tests/fipc_remote_discovery
./build/tests/fipc_remote_autodiscover
./build/tests/fipc_remote_capability
./build/tests/fipc_remote_header_v1
./build/tests/fipc_remote_replay
./build/tests/fipc_remote_aead_toy
./build/tests/fipc_remote_aead_openssl   # prints SKIP if libcrypto is absent
./build/tests/fipc_remote_metrics
./build/tests/fipc_sys_metrics_subscriber
./build/tests/fipc_sys_kernel_metrics
```

### Kernel (QEMU ISO)

```bash
# Build and create ISO
make
cp build/bin/futura_kernel.elf iso/boot/
grub-mkrescue -o futura.iso iso/

# Boot with serial
qemu-system-x86_64 -cdrom futura.iso -serial stdio -display none -m 128M
```

Expected serial notes (illustrative): PMM init, heap at higher‑half, **system channel reserved**, FIPC rings, self‑tests, and idle loop.

---

## 🧠 Architecture Highlights

* **Nanokernel core** (time, interrupts, scheduling, and FIPC) with **replaceable user‑space managers** (FS, Net, Device, Compositor). The core is small and deterministic; everything else speaks messages.
* **FIPC**: unified event fabric for syscalls, GUI, FS notifications, and inter‑service IPC. Local: zero‑copy rings; Remote: versioned framing over transports.
* **Capabilities**: first‑class tokens on every hop; AEAD authenticates frames and **binds capability into AAD** so mismatches fail fast at the boundary.
* **Transport header v1**: `magic | version | flags | seq | credits | channel_id | payload_len | crc` (credits reserved).
* **Replay protection**: sliding window per remote binding; duplicates and stale frames are dropped and counted.
* **Service discovery**: `netd` auto‑resolves `remote.channel_id` on first send via a UDP registry and caches it; returns `EAGAIN` while unregistered, succeeds after registration.
* **System metrics stream**: reserved **system channel** with **IDL‑v0** tag+varint encoding. Publishers:

  * **netd**: `lookup_attempts`, `lookup_hits`, `lookup_miss`, `send_eagain`, `tx_frames`, `tx_blocked_credits`, `auth_fail`, `replay_drop`.
  * **kernel shim**: placeholder `pmm_pages_total`, `pmm_pages_free`, `fipc_channels` (ready to map to real counters).
    Subscribers decode via tiny header‑only helpers.

---

## 🧪 Test Catalog

* `fipc_remote_loopback` — Local framing sanity over UDP
* `fipc_remote_discovery` — Name → channel id
* `fipc_remote_autodiscover` — First‑send lazy lookup + retry
* `fipc_remote_capability` — Mismatch **drops**, match **delivers**
* `fipc_remote_header_v1` — Seq/metrics exercised (proxy)
* `fipc_remote_replay` — Duplicate/stale rejection (window)
* `fipc_remote_aead_toy` — Toy AEAD (valid vs mismatch)
* `fipc_remote_aead_openssl` — Real AEAD (ChaCha20‑Poly1305; **SKIP** if no OpenSSL)
* `fipc_remote_metrics` — Counters advance + text publish
* `fipc_sys_metrics_subscriber` — **IDL‑v0** system stream decode (netd)
* `fipc_sys_kernel_metrics` — Unified stream decode (netd + kernel shim)

---

## 🗺️ Roadmap

### Phase 2 (Core Services) – **In Progress**

* ✅ VFS + RamFS
* 🧪 FuturaFS scaffolding & tests
* 🌐 Netd bridge (done host‑side; kernel sockets later)
* 📊 **System Metrics Stream (IDL‑v0)** — **Done (host + kernel shim)**

### Phase 3

* **FuturaWay telemetry** on system stream (surface create/commit/input; latency buckets)
* Multi‑surface compositor, redraw scheduling, GPU backend (Vulkan/GL)

### Phase 4

* **Real kernel metrics** feeding the same IDL stream (PMM, scheduler, IPC)
* IDL/codegen expansion (schemas + generated C/Rust)
* Secure transports (WireGuard/QUIC) and multi‑node discovery

---

## 🤝 Contributing

We love clean, testable code and small, focused PRs. Good first issues:

* Add a new **system metrics tag** (with tests & decode)
* Extend **AEAD** with alternative providers under feature flags
* Implement **FuturaWay** metrics hooks (surface commit timing)

See [CONTRIBUTING.md](CONTRIBUTING.md) for style & workflow.

---

## 📜 License

Mozilla Public License 2.0 (MPL‑2.0). See [LICENSE](LICENSE) for details.

---

## 📞 Contact & Community

* **Author**: Kelsi Davis
* **Email**: [dumbandroid@gmail.com](mailto:dumbandroid@gmail.com)
* **Issues/Discussions**: GitHub

---

**Built with ❤️ for the future of operating systems.**


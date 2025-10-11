# Futura OS

**A Modern Capability-Based Nanokernel Operating System**

Copyright © 2025 Kelsi Davis
Licensed under Mozilla Public License 2.0 — see [LICENSE](LICENSE) for details
---

## 🚀 Overview

Futura OS is a modern modular nanokernel, completely written from scratch for contemporary hardware and security principles. It features a unified object/handle abstraction, capability-based access control, asynchronous message-passing IPC, and a modular architecture that supports multiple platforms.

### Key Features

- **🔐 Capability-Based Security**: All kernel resources are objects with fine-grained capability tokens
- **⚡ Async-First Design**: Message-passing IPC and async I/O throughout
- **🧩 Modular Architecture**: Clean separation between kernel, subsystems, and platform layers
- **🖥️ Multi-Platform**: Support for x86-64, ARM64, more (in development)
- **🐧 POSIX Compatibility**: Optional compatibility layer for Unix software
- **🎯 C23 Standard**: Modern, clean C codebase with no legacy cruft

---

## 📁 Project Structure

```
futura/
├── kernel/               # Core nanokernel
│   ├── memory/          # Physical memory manager & heap allocator
│   ├── scheduler/       # Preemptive scheduler with statistics
│   ├── threading/       # Thread and task management
│   ├── timer/           # Timer subsystem and sleep queue
│   ├── interrupts/      # IDT and interrupt handling
│   ├── ipc/             # Object system and message passing
│   └── vfs/             # Virtual filesystem
├── subsystems/          # Modular kernel services
│   ├── posix_compat/   # POSIX compatibility layer
│   ├── futura_fs/      # Native filesystem
│   ├── futura_net/     # Network stack
│   └── futura_gui/     # GUI compositor
├── platform/            # Platform-specific code
│   ├── x86/            # x86-32 boot and drivers
│   ├── arm64/          # ARM64 support
│   └── apple_silicon/  # Apple Silicon support
└── include/             # Public headers
```

## 🔧 Building

### Prerequisites

- GCC (C23 support)
- GNU Make
- GNU Binutils (ld, as)
- QEMU (for testing)

### Quick Start

```bash
# Clone the repository
cd /path/to/futura

# Build the kernel (default: x86 debug)
make

# Build for release
make BUILD_MODE=release

# Clean build artifacts
make clean

# View all build options
make help
```

### Platform-Specific Builds

```bash
# Build for x86-32 (default)
make PLATFORM=x86

# Build for ARM64 (Phase 2)
make PLATFORM=arm64

# Build for Apple Silicon (Phase 2)
make PLATFORM=apple_silicon
```

### Build Outputs

- `build/bin/futura_kernel.elf` - Kernel ELF binary
- `build/obj/` - Object files (organized by component)

---

## 🎯 Phase 1 Deliverables (Current)

✅ **Completed:**
- Modular directory structure
- Memory manager (PMM + kernel heap)
- Threading system (creation, context switching)
- Preemptive scheduler with priority queues
- Timer subsystem with sleep management
- Interrupt handling (IDT, ISR stubs)
- Task/process containers
- Platform abstraction for x86
- Object system foundation (handles & capabilities)
- POSIX compatibility skeleton
- Modular build system

🔄 **In Progress:**
- Comprehensive documentation
- Kernel initialization sequence
- Example programs and test harness

---

## 🗺️ Roadmap

### Phase 2: Core Services
- Virtual filesystem (VFS) layer
- Block device drivers
- Native Futura filesystem
- Async network stack foundation
- IPC channels and message queues

### Phase 3: Advanced Features
- GUI compositor and window manager
- Multi-core SMP support
- Memory protection (VMM with paging)
- Dynamic linking and module loading
- Performance profiling tools

### Phase 4: Ecosystem
- Futura Shell (CLI + GUI hybrid)
- Package manager
- Development toolchain
- Documentation and tutorials
- Community contributions

---

## 🏗️ Architecture

### Nanokernel Design

Futura uses a **nanokernel** architecture where the kernel provides only the absolute minimum:

1. **Memory Management**: Physical page allocator and kernel heap
2. **Scheduling**: Thread scheduler and context switching
3. **IPC**: Object system with capability-based access control
4. **Platform Abstraction**: Boot, interrupts, timers

All other services (filesystems, networking, GUI) run as modular subsystems with minimal privilege.

### Object System

All kernel resources are represented as **objects** with **handles**:

```c
fut_handle_t file = fut_object_create(FUT_OBJ_FILE, FUT_RIGHT_READ | FUT_RIGHT_WRITE, data);
fut_object_send(file, buffer, size);    // Async write
fut_object_receive(file, buffer, size); // Async read
fut_object_destroy(file);
```

Capabilities control access at a fine-grained level without traditional Unix permissions.

### POSIX Compatibility

The POSIX layer translates standard Unix calls to Futura objects:

```c
// POSIX API (emulated)
int fd = open("/etc/passwd", O_RDONLY);
read(fd, buffer, 1024);
close(fd);

// Internally maps to Futura objects
fut_handle_t handle = fut_object_create(...);
fut_object_receive(handle, ...);
fut_object_destroy(handle);
```

---

## 🧪 Testing

(Phase 2 - Test harness under development)

```bash
# Run kernel in QEMU
qemu-system-i386 -kernel build/bin/futura_kernel.elf -serial stdio

# Run with debugging
make debug
```

---

## 📚 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md) (Phase 2)
- [API Reference](docs/API.md) (Phase 2)
- [Platform Porting Guide](docs/PORTING.md) (Phase 2)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas Needing Help
- ARM64 and Apple Silicon platform support
- Device drivers (network, storage, graphics)
- Filesystem implementations
- Documentation and tutorials
- Test coverage

---

## 📜 License

Futura OS is licensed under the **Mozilla Public License 2.0** (MPL-2.0).

This means:
- ✅ You can use, modify, and distribute Futura OS
- ✅ You can create proprietary applications that run on Futura
- ✅ Modifications to Futura kernel code must be shared under MPL-2.0
- ✅ Media and editorial use permitted (YouTube, blogs, reviews)
- NO AI scraping

See [LICENSE](LICENSE) for full terms.

---

## 📞 Contact & Community

- **Author**: Kelsi Davis
- **Email**: dumbandroid@gmail.com
- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for Q&A and design discussions

---

## 🌟 Acknowledgments

Futura OS builds upon lessons learned from:
- seL4 (capability-based security)
- Zircon (modern nanokernel architecture)
- Redox OS (Rust-based microkernel ideas)

Special thanks to the systems programming community for feedback and inspiration.

---

## 📊 Project Status

**Status**: 🚧 **Phase 1 - Foundation** 🚧

Futura OS is in active early development. The core nanokernel is functional, but many subsystems are skeletal or stubbed out. This is **not production-ready** software.

**Current Milestone**: Completing Phase 1 deliverables and beginning VFS integration.

---

**Built with ❤️ for the future of operating systems**

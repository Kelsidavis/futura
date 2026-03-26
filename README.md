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

### Status Snapshot — Updated Mar 26 2026

- **Kernel core**: 352+ Linux-compatible syscalls across 147 implementation files. Priority-aware scheduler (nice + RT), per-task MMU contexts, COW fork, file-backed mmap, ELF loader with PT_INTERP interpreter support.
- **Testing**: **2036 automated kernel self-tests** across 11 test groups, all passing. CI: GitHub Actions with x86_64 + ARM64 QEMU test runners, consistently green.
- **Linux compat**: Comprehensive POSIX coverage: signals (SA_SIGINFO, SA_RESTART, SA_NOCLDWAIT, sigpending, signalfd, sigsuspend, sigtimedwait, SIGSTOP/SIGCONT), epoll (EPOLLET, EPOLLONESHOT, EPOLLRDHUP, EPOLLEXCLUSIVE), pipes (F_SETPIPE_SZ, poll POLLHUP), sockets (MSG_PEEK, SO_PEERCRED, SCM_RIGHTS, SOCK_CLOEXEC, SO_BINDTODEVICE, SO_REUSEADDR/PORT), timers (timerfd, POSIX timers, alarm, itimer), file I/O (O_APPEND, O_CLOEXEC, ftruncate, readv/writev/preadv/pwritev, splice/tee, sendfile, copy_file_range), process lifecycle (fork, clone, clone3 with CLONE_PIDFD, waitpid/wait4/waitid, execve with shebang + ELF + PIE).
- **Networking (Router OS)**: Full TCP/IP stack with multi-interface routing, longest-prefix-match, IP forwarding with TTL/checksum, NAT/masquerade (1024-entry conntrack), 3-chain firewall (INPUT/FORWARD/OUTPUT), TUN/TAP virtual devices, 802.1Q VLANs, L2 bridging (brctl), GRE tunnels, **IP policy routing** (multiple tables, `ip rule` source-based routing), DNS resolver with caching, ARP cache, ICMP echo/time-exceeded/dest-unreachable, real SNMP statistics (/proc/net/snmp), PCI bus enumeration, per-interface /proc/sys/net/ipv4/conf/. All configurable via ioctls and sysctls.
- **Storage + VFS**: RamFS, procfs (31 root entries including /proc/pressure/, per-pid with 30+ files), sysfs (dynamic /sys/class/net/), devfs (/dev/null, /dev/zero, /dev/full, /dev/urandom, /dev/random, /dev/kmsg, /dev/hwrng, /dev/ptmx, /dev/pts/\*, /dev/tty, /dev/console, /dev/net/tun, /dev/watchdog, /dev/loop0-7), **FuturaFS** (19 dedicated tests: CRUD, mkdir, stat, ftruncate, rename, lseek, flock, O_APPEND, O_TRUNC, O_EXCL, symlinks, readdir, concurrent access), AHCI SATA driver; **loop block devices** for mounting disk images; block device layer with real /proc/diskstats and /proc/partitions; **software watchdog** (WDIOC_SETTIMEOUT, auto-reboot on hang); real I/O accounting (/proc/<pid>/io); full xattr, inotify, hardlink, symlink support.
- **Shell**: 118 built-in commands including ip rule/tunnel/addr/route/link, ifconfig, iptables, brctl, ethtool, conntrack, losetup, mkfs.futura, logger, ping, traceroute, netstat, ss, arp, wget, nc, httpd, nslookup, dhclient for networking; top, ps, free, df, iostat, vmstat, stty, sysctl, dmesg, lspci, lsblk, lsof, wdctl for system admin; grep with `^`/`$`/`.`/`-w`/`-c`/`-l` pattern support, tail -f follow mode; full scripting with for/while/if, pipes, redirects, globs, command substitution, **Ctrl+Z job suspension**, Ctrl+C interrupt, job control (bg/fg/jobs).
- **IPC**: Unix domain sockets (stream, datagram, seqpacket), AF_INET TCP/UDP with loopback, System V IPC (shm, sem, msg), POSIX message queues, pipes, eventfd, signalfd, timerfd.
- **Graphics**: Legacy window server (`services/winsrv` + `apps/winstub`) and a Wayland compositor (`src/user/compositor/futura-wayland`) with demo clients in `src/user/clients/`.
- **Platforms**: x86-64 is the reference build; ARM64 port with Apple Silicon driver support. 16 Rust drivers for Apple Silicon (AIC, UART, RTKit, ANS2, GPIO, I2C, PCIe, SPI, DART, SMC, MCA) and VirtIO (blk, gpu, input, net).

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

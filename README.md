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

### Status Snapshot — Updated Mar 27 2026

- **Kernel core**: 400 Linux-compatible syscalls (356 x86_64 + 398 ARM64) across 226 implementation files, 110K lines of kernel C. Priority-aware scheduler (nice + RT), per-task MMU contexts, COW fork, file-backed mmap, ELF loader with PT_INTERP interpreter support.
- **Testing**: **2213 automated kernel self-tests** across 11 test groups, all passing. CI: GitHub Actions with x86_64 + ARM64 QEMU test runners, consistently green.
- **Containers**: All 6 Linux namespaces (PID, mount, UTS, network, user, IPC), **cgroup v2** with all 5 controllers (memory, CPU, I/O, PID, freezer) + mountable **cgroup2 filesystem**, **pivot_root()**, **overlayfs**. Full rootless Docker workflow: `unshare → uid_map → mount overlay → pivot_root → exec`.
- **Security**: **seccomp-bpf** with real BPF filter enforcement in syscall dispatch, **Landlock LSM** file access sandboxing, **Linux keyring** (add_key/request_key/keyctl), classic BPF interpreter, capability system with ambient caps.
- **Async I/O**: **io_uring** (NOP/READ/WRITE/FSYNC/CLOSE/POLL), **userfaultfd** for CRIU/QEMU, **fanotify** filesystem notifications, **perf_event_open** HW/SW counters.
- **Modern APIs**: **fsopen/fsconfig/fsmount** (Linux 5.2+), **statmount/listmount** (Linux 6.8+), **memfd_secret**, **/proc/config.gz** (93 CONFIG_* entries for Docker/k8s check-config), **debugfs/tracefs** virtual filesystems, DMI/SMBIOS sysfs, /dev/rtc0, /proc/sysrq-trigger.
- **Linux compat**: Comprehensive POSIX coverage: signals (SA_SIGINFO, SA_RESTART, SA_NOCLDWAIT, sigpending, signalfd, sigsuspend, sigtimedwait, SIGSTOP/SIGCONT), epoll (EPOLLET, EPOLLONESHOT, EPOLLRDHUP, EPOLLEXCLUSIVE), pipes (F_SETPIPE_SZ, poll POLLHUP), sockets (MSG_PEEK, SO_PEERCRED, SCM_RIGHTS, SOCK_CLOEXEC, SO_BINDTODEVICE, SO_REUSEADDR/PORT), timers (timerfd, POSIX timers, alarm, itimer), file I/O (O_APPEND, O_CLOEXEC, ftruncate, readv/writev/preadv/pwritev, splice/tee, sendfile, copy_file_range), process lifecycle (fork, clone, clone3 with CLONE_PIDFD, waitpid/wait4/waitid, execve with shebang + ELF + PIE).
- **Networking (Router OS)**: Full TCP/IP stack with multi-interface routing, longest-prefix-match, IP forwarding with TTL/checksum, NAT/masquerade (1024-entry conntrack), 3-chain firewall (INPUT/FORWARD/OUTPUT), TUN/TAP virtual devices, 802.1Q VLANs, L2 bridging (brctl), GRE tunnels, **IP policy routing** (multiple tables, `ip rule` source-based routing), **traffic control/QoS** (`tc qdisc` with TBF/HTB rate limiting), **IPsec** SA/SP database (ESP/AH, tunnel/transport mode, AES/SHA), **AF_INET6** socket support, DNS resolver with caching, ARP cache, ICMP echo/time-exceeded/dest-unreachable, real SNMP statistics (/proc/net/snmp), PCI bus enumeration, per-interface /proc/sys/net/ipv4/conf/. All configurable via ioctls, sysctls, and shell commands (`tc`, `ip xfrm`).
- **Storage + VFS**: 7 filesystem drivers — **ext2/3/4**, **FAT12/16/32**, **exFAT**, **overlayfs**, **FUSE** (/dev/fuse for userspace filesystems), **FuturaFS** (native), RamFS; **cgroup2** filesystem; **debugfs/tracefs**; procfs (38 root entries including /proc/config.gz, /proc/crypto, /proc/softirqs, /proc/iomem, /proc/ioports, /proc/pressure/, /proc/sysrq-trigger, per-pid with 38+ files), sysfs (dynamic /sys/class/net/, /sys/class/block/, /sys/class/rtc/, /sys/bus/pci/devices/, /sys/firmware/dmi/id/), devfs (/dev/null, /dev/zero, /dev/full, /dev/urandom, /dev/random, /dev/kmsg, /dev/hwrng, /dev/rtc0, /dev/mem, /dev/ptmx, /dev/pts/\*, /dev/tty, /dev/console, /dev/net/tun, /dev/watchdog, /dev/loop0-7), **FuturaFS** (21 dedicated tests), AHCI SATA driver; **loop block devices**; block device ioctls (BLKGETSIZE64, BLKSSZGET, BLKBSZGET); **software watchdog**; real I/O accounting; full xattr, inotify, fanotify, hardlink, symlink support.
- **Shell**: 136 built-in commands with **multi-line scripting** (if/then/fi, for/in/do/done, while/do/done, case/in/esac), pipes (|, up to 10 stages), I/O redirection (>, >>, <), && / || chains, background jobs (&), globbing, variable expansion, `$(...)` command substitution; **awk** (field splitting, /pattern/ matching, NR/NF/$N, -F), **sed** (s/pat/rep/g), grep, sort, wc, cut, tr, tee, diff, rev, nl, base64, od for text processing; enhanced **test** command (-d/-r/-w/-x/-s/-L/-h/-p operators); **eval**, **let**, **getopts**, **unset**, **return**, **shift**, **command** [-v] for scripting; **pushd/popd/dirs** for directory navigation; ip, ifconfig, iptables, brctl, tc for networking; top, ps, free, df, dmesg for system admin; **Ctrl+Z job suspension**, bg/fg/jobs.
- **IPC**: Unix domain sockets (stream, datagram, seqpacket), AF_INET TCP/UDP with loopback, System V IPC (shm, sem, msg), POSIX message queues, pipes, eventfd, signalfd, timerfd.
- **Graphics**: Legacy window server (`services/winsrv` + `apps/winstub`) and a Wayland compositor (`src/user/compositor/futura-wayland`) with demo clients in `src/user/clients/`.
- **Platforms**: x86-64 is the reference build; ARM64 port with **Raspberry Pi 4/5** and Apple Silicon support. **48 Rust driver crates**: x86-64 AMD Ryzen AM4/AM5 (**18 drivers**: NVMe, AHCI SATA, xHCI USB 3.x, RTL8111 GbE, Intel I225-V 2.5GbE, Intel I211 GbE, HD Audio, AMD SMBus, AMD IOMMU, AMD GPIO, AMD Watchdog, AMD SPI Flash, AMD SB-TSI temp, AMD P-State/CPPC, HPET, CMOS RTC, TPM 2.0 CRB, PCI MSI-X), RPi (**15 drivers**: mailbox, eMMC2/SDHCI, GPIO, GENET Ethernet, HDMI display, USB xHCI, watchdog, I2C, SPI, PWM, HW RNG, DMA, PCIe, audio, thermal/DVFS), Apple Silicon (AIC, UART, RTKit, ANS2, GPIO, I2C, PCIe, SPI, DART, SMC, MCA), VirtIO (blk, gpu, input, net). RPi4/5 boot entry with EL drop, DTB detection, PL011 UART, GIC-400; complete BCM2711/BCM2712 peripheral maps; SD card config.txt generation via `make rpi-image`.

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

# Build Rust drivers (virtio-blk/net/gpu + NVMe/xHCI/RTL8111/HDA/SMBus/IOMMU on x86_64)
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

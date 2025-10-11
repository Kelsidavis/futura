# Futura OS Userland

This directory contains all user-space services and applications for Futura OS Phase 3.

## Directory Structure

```
src/user/
├── init/               # Init system (PID 1)
├── futurawayd/         # FuturaWay display compositor
├── posixd/             # POSIX runtime daemon
├── fsd/                # Filesystem daemon
│   └── backends/       # Filesystem backend drivers
├── libfutura/          # User-space library
├── futura_ui/          # UI widget toolkit
└── demo/               # Demo applications
```

## Service Architecture

All userland services communicate via **FIPC** (Futura Inter-Process Communication):

- **init** (PID 1) - Service orchestration and management
- **fsd** - Virtual filesystem management
- **posixd** - POSIX syscall bridge
- **futurawayd** - Display server and compositor

## Protocol Headers

Protocol headers are in `include/user/`:

- `futura_init.h` - Init system API
- `futura_way.h` - FuturaWay compositor protocol
- `futura_posix.h` - POSIX daemon protocol
- `futura_ui.h` - UI widget toolkit API

## Building

Userland services are built separately from the kernel:

```bash
make userland              # Build all userland services
make userland-init         # Build init only
make userland-futurawayd   # Build compositor only
make userland-posixd       # Build POSIX daemon only
```

## Implementation Status

- [ ] Init system
- [ ] Filesystem daemon (fsd)
- [ ] POSIX daemon (posixd)
- [ ] FuturaWay compositor
- [ ] FuturaUI toolkit
- [ ] Demo applications

## Testing

```bash
make qemu-x86_64-userland  # Test x86-64 with userland
make qemu-arm64-userland   # Test ARM64 with userland
```

## Documentation

See [Phase 3 Plan](../../docs/PHASE3_PLAN.md) for detailed specifications.

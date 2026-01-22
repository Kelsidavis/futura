# Futura OS Userland

This directory contains user-space services, utilities, and demos. Most components communicate over FIPC and link against `libfutura`.

## Directory Structure

```
src/user/
├── libfutura/            # C runtime, syscall veneers, printf/malloc
├── init/                 # PID 1 / service bootstrap
├── fsd/                  # Filesystem daemon
├── posixd/               # POSIX compatibility daemon
├── netd/                 # UDP bridge for distributed FIPC
├── svc_registryd/        # Service registry + capability auth
├── shell/                # Interactive shell (pipes, redirects, job control)
├── fbtest/               # Framebuffer demo
├── futurawayd/           # Legacy display server
├── compositor/           # Wayland compositor (futura-wayland)
├── services/winsrv/      # Legacy window server
├── apps/winstub/         # Legacy window client
├── clients/              # Wayland demo clients (wl-simple, wl-colorwheel, wl-term)
├── apps/                 # Additional app stubs
├── sys/                  # Generated FIPC glue + syscall shims
├── stubs/                # Init/ELF stub binaries
├── cat/ echo/ wc/         # Basic utilities
├── arm64_gfxtest/        # ARM64 graphics test
└── arm64_uidemo/         # ARM64 UI demo
```

## Service Architecture

Core daemons:
- **init** — PID 1; starts the service graph
- **fsd** — filesystem daemon
- **posixd** — POSIX compatibility layer over FIPC
- **netd** — UDP bridge for distributed IPC
- **svc_registryd** — service discovery with capability authentication

Display stacks:
- **Legacy**: `services/winsrv` + `apps/winstub`
- **Wayland**: `compositor/futura-wayland` with clients in `clients/`

## Building

From the repo root:

```bash
make userland
```

Or directly from this directory:

```bash
make -C src/user            # build all userland services
make -C src/user init        # build init only
make -C src/user shell       # build shell only
make -C src/user futurawayd  # build legacy display server
```

Notes:
- On macOS, the userland Makefile builds a minimal subset (libfutura + init + stubs).
- Set `PLATFORM=x86_64` or `PLATFORM=arm64` to control the target.

## Related Docs

- `docs/ARCHITECTURE.md`
- `docs/CURRENT_STATUS.md`
- `docs/WAYLAND_UI_STATUS.md`

# Wayland Third-Party Vendor Tree

This directory vendors the upstream Wayland project (libwayland client/server +
`wayland-scanner`).  The build is driven through Meson and Ninja but wrapped by
`make third_party-wayland` to keep everything deterministic.

## Version

- Upstream project: https://gitlab.freedesktop.org/wayland/wayland
- Release tag: `1.23.0`
- Tarball: `https://gitlab.freedesktop.org/wayland/wayland/-/archive/1.23.0/wayland-1.23.0.tar.gz`

## Build Output

Running `make third_party-wayland` produces:

- Static libraries: `libwayland-client.a`, `libwayland-server.a`, `libwayland-util.a`, `libwayland-private.a`
- Executable: `wayland-scanner`
- Installed into: `build/third_party/wayland/install`
- Helper metadata: `build/third_party/wayland/paths.mk` (make variables) and `mk/wayland.mk` scanner rules

All binaries are built with:

- `-O2 -g0 -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections`
- Deterministic archive ordering (`ARFLAGS=rcsD`)
- `HAVE_MEMFD_CREATE` forced off so wl_shm uses POSIX shared memory
- `cursor/` and `egl/` components disabled (no `dlopen`, no libpng)

## Workflow

1. `make third_party-wayland`  
   - downloads the tarball to `third_party/wayland/vendor/`
   - applies patches in `third_party/wayland/patches/`
   - configures Meson with reproducible flags
   - builds & installs into `build/third_party/wayland/install`

2. Generated headers and static libraries can then be consumed by user-space
   components via the include/lib directories exposed in `build/third_party/wayland/install`.

### Host Requirements

- Python 3, Meson (≥1.1), Ninja
- `pkg-config`, `libffi`, `libexpat` development headers (used for compile/link; static libs still link
  against libffi/pthread/rt/m)

Artifacts are not checked into git; rebuilds are reproducible as long as the
downloaded tarball matches the recorded SHA256 checksum.

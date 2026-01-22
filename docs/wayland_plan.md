# Wayland Stack Bring-Up — Weeks 1–2

## Audit Snapshot (Jan 2026)
- `third_party/wayland/` vendors Wayland 1.23.0 and builds static libs + `wayland-scanner` via `make third_party-wayland`.
- `include/futura/compat/posix_shm.h` / `src/user/libfutura/posix_shm.c` expose placeholder APIs that do not interoperate with upstream libwayland expectations (no name unlink, zero-fill only).
- Makefile ships a `third_party-wayland` target; winsrv/winstub remain the default desktop payload unless Wayland demos are enabled.

## Vendor Strategy Decision
- **Approach**: vendor the official Wayland 1.23.x release under `third_party/wayland/`, build static `libwayland-client.a`, `libwayland-server.a`, and the `wayland-scanner` tool using Meson/Ninja.
- **Rationale**: keeps protocol compatibility with the wider ecosystem, avoids maintaining a divergent fork, and lets us cherry-pick upstream security fixes.
- **Toolchain**: host `gcc` + Meson cross file tuned for freestanding build flags (no `dlopen`, `memfd_create`, signalfd, or libffi). We will statically link and disable optional deps (`wayland-drm`, `wayland-egl`).
- **Artifacts**: copy the generated headers and static libs into `build/third_party/wayland/` for userland consumption; ship `wayland-scanner` into `build/tools/`.

## Work Items for Stage 1
1. Replace the stub headers/sources with a vendor directory containing the upstream tarball plus Meson wrap metadata.
2. Add a reproducible make target (`make third_party-wayland`) that:
   - configures Meson with deterministic compiler/linker flags,
   - disables runtime loaders (`dlopen`), memfd-backed shm, and libffi,
   - builds static client/server libs and `wayland-scanner`.
3. Integrate `wayland-scanner` generation rules into the top-level build (exports a helper make include for later protocol compilations).
4. Flesh out the POSIX shm shim so that wl_shm buffers can land on tmpfs-backed files without memfd.

_Exit criteria_: running `make third_party-wayland` produces headers, libs, and the scanner with identical hashes across rebuilds, and the rest of the tree remains untouched pending compositor/client wiring.

## Week 1 Progress (Jan 10, 2026)
- Replaced the proto stub with an upstream 1.23.0 vendor harness driven by `third_party/wayland/Makefile`.
- `make third_party-wayland` now fetches, patches, and installs static `libwayland-{client,server}` plus `wayland-scanner` into `build/third_party/wayland/`.
- Exported helper metadata (`paths.mk`) and a reusable protocol generation include (`mk/wayland.mk`) so later compositor/client work can reference `WAYLAND_SCANNER` and reuse the same scanner recipes.
- Stub compositor (`futura-wayland`) and client (`wl-simple`) compile against the vendored libs, and `make wayland-step2` boots them via QEMU to prove the hello handshake.

### Open Technical Items
- `fut_shm_unlink()` currently no-ops because the kernel lacks `unlink`; once the POSIX bridge exposes it we should remove temp files after compositors release buffers.
- Consider replacing the zero-fill growth helper with a real `ftruncate` once the syscall lands, to avoid large write loops when allocating pools.
- Static Wayland libs still depend on host `libffi`, `libexpat`, `libm`, and `libpthread`; capture the explicit link lines via pkg-config in the compositor/client build rules when we wire them up.

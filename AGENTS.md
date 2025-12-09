# Repository Guidelines

## Project Structure & Module Organization
Kernel code stays in `kernel/` with platform glue in `platform/x86_64/` and `platform/arm64/`. Userland and compositor sources live in `src/user/`, Rust staticlibs in `drivers/rust/`, tooling/docs in `tools/`, `docs/`, and `tests/`, boot assets in `iso/`, and `third_party/wayland/` vendors the Wayland stack.

## Build, Test, and Development Commands
- `make rust-drivers` – build driver staticlibs before the kernel link.
- `make` – compile the kernel into `build/bin/` and refresh `iso/boot/`.
- `make test` – boot the QEMU harness and capture `*.log` outputs.
- `make wayland-step2` – build the compositor plus demos; toggle features via `WAYLAND_*`.
- `make tools` – build host filesystem helpers, then run `build/tools/mkfutfs …` or `fsck.futfs …`.
- `make perf` / `make perf-ci` – run IPC/block/net microbenchmarks and compare with `tests/baselines/perf_baseline.json`.
- `make futfs-crash-test` – regenerate a scratch image, force panic compaction, and verify recovery.

## Coding Style & Naming Conventions
C code follows 4-space indentation, ≤100-character lines, and K&R braces. Functions use `fut_*` snake_case (e.g., `fut_thread_create`), types end with `_t`, and macros or constants are `FUT_*` SCREAMING_SNAKE_CASE. Enum values keep the prefix (`FUT_THREAD_READY`). Keep files self-documenting with focused comments and retain the MPL header template.

## Testing Guidelines
Kernel self-tests in `kernel/tests/` run during boot; expand them whenever you touch scheduler, MMU, or IPC code. Host regressions live under `tests/fipc_*` and `tests/futfs_*`; keep deterministic names such as `*_loopback.c` so the harness emits meaningful `*_test.log` artifacts. Always run `make test` plus a targeted harness (e.g., `make perf` after scheduler edits or `make futfs-crash-test` for filesystem changes).

## Commit & Pull Request Guidelines
Recent history (`git log -5`) shows imperative summaries like “Add is_accepted flag…”; keep first lines under 72 characters, explain the “why,” and reference issues (`Closes #123`). Group related edits into cohesive commits rather than “WIP” dumps. PRs should outline the subsystem touched, list test commands executed, attach essential log snippets, and link supporting design docs when adding daemons or protocols. Call out feature flags reviewers need (for instance `WAYLAND_BACKBUFFER=1`) so CI can replicate behavior.

## Security & Configuration Tips
Capability handles are the authority boundary: never dump raw pointers or AEAD keys from `host/transport`, and scrub logs before sharing. Run `setup-asahi-external.sh` for Apple Silicon so boot artifacts and signing keys land where the build scripts expect them. Snapshot `futura_disk.img` before risky experiments and gate compositor or kernel tracing tweaks behind `WAYLAND_*` variables or `DEBUG_*` flags to avoid surprising defaults.

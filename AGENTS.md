# Repository Guidelines

## Project Structure & Module Organization
Kernel code resides in `kernel/` with platform helpers under `platform/x86_64/` and `platform/arm64/`. Wayland/compositor sources live in `src/`, host tooling is grouped in `tools/`, `mk/`, and `scripts/`, and regression suites plus perf benchmarks stay under `tests/`. Documentation remains in `docs/`, and boot artifacts (`iso/`, disk images, `boot.bmp`) sit at the repo root for `Makefile` targets.

## Build, Test, and Development Commands
- `make clean && make` – rebuild the kernel, initramfs, and ISO into `build/bin/`.
- `make rust-drivers` – compile Rust static libraries before the link step.
- `make test` – launch the QEMU harness and emit `*.log` traces at the repository root.
- `make perf` / `make perf-ci` – run IPC/block/net microbenchmarks and compare with `tests/baselines/perf_baseline.json`.
- `make futfs-crash-test` – create a scratch image, trigger panic/compaction, and verify the recovery log.
- `make wayland-step2` plus `make run-headful VNC=1 VNC_DISPLAY=unix:/tmp/futura-vnc AUTOEXIT=1` – build the compositor stack and start headful QEMU via VNC.
- `make tools` – refresh host helpers (`build/tools/mkfutfs`, `fsck.futfs`, etc.).

## Coding Style & Naming Conventions
Follow `CONTRIBUTING.md`: use 4-space indentation, ≤100-character lines, and K&R braces. Functions and helpers take `fut_*` snake_case, types end with `_t`, macros/constants stay `FUT_*`, and enum members keep their prefix. Every source file keeps the MPL v2.0 header plus a short description, and public APIs get Doxygen-style summaries (`@param`, `@return`). Keep comments focused on non-obvious behavior and prefer descriptive names over explanation.

## Testing Guidelines
`make test` runs the default QEMU harness plus `kernel/tests/` and the suites under `tests/`. Keep regression filenames deterministic (`tests/fipc_*`, `tests/futfs_*`) so `*_test.log` artifacts stay stable, and complement `make test` with targeted commands (`make perf`, `make perf-ci`, `make futfs-crash-test`, compositor runs). Note each command and the resulting log file in the PR description.

## Commit & Pull Request Guidelines
Use imperative commit titles ≤72 characters, explain the “why” in the body, and reference issues (`Closes #123`). Avoid mixing unrelated work in one commit, and note verification commands plus log filenames (`headful_boot.log`, etc.) and relevant feature flags (`WAYLAND_BACKBUFFER=1`, `DEBUG_*`) in PR descriptions so reviewers can reproduce your run.

## Security & Configuration Tips
Treat capability handles and transport logs as sensitive—never leak secrets from `host/transport`. Snapshot `futura_disk.img` before risky experiments, gate tracing/Wayland tweaks behind `WAYLAND_*` or `DEBUG_*`, and run `setup-asahi-external.sh` on Apple Silicon so signing keys and disk layout follow build expectations.

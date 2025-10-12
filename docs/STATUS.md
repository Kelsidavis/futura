# Project Status (Updated Oct 12 2025)

## Current Milestone: Phase 2 – Userland Foundations

- ✅ Async block core with rights-enforced handles.
- ✅ Virtio-blk and AHCI drivers bridged to the block core.
- ✅ Log-structured FuturaFS skeleton (host-mode) with create/write/read/rename.
- ✅ mkfutfs formatter and regression test (`tests/futfs_log_basic`).
- 🚧 FSD integration with the log skeleton (capability propagation).
- 🚧 Memory-safe driver journey (tracking Rust conversions and exceptions).

> **Doc drift guard**: CI must assert that this `Current Milestone` string
> matches the roadmap entry in `README.md`. Update both together.

## Security OKRs

1. **Memory-safe drivers** – 100% of new drivers/subsystems must land in Rust or
   document a performance exception. Track “% memory-safe LOC” in CI dashboards.
2. **Sanitised dev builds** – Enable KASAN/UBSan (or platform equivalent) for
   nightly builds; extend fuzzers to cover the FIPC codec, log-structured FS
   recovery, and ELF loading.
3. **Supply chain** – Deliver reproducible builds, cosign signatures, and TUF
   metadata for all release artifacts.

## Performance OKRs

1. Gate every PR on IPC round-trip, context switch, and block I/O microbench
   deltas; notify when regressions exceed 5%.
2. Maintain low-latency async block completions (qemu baseline target: <250µs).
3. Keep compositor smoke tests (`futuraway_smoke`, `futuraway_m2_smoke`) within
   existing frame budget.

## Risks & Mitigations

| Risk | Mitigation |
| --- | --- |
| Documentation drift | CI check linking `docs/STATUS.md` and `README.md` milestones. |
| Secure Boot churn (keys/SBAT) | Maintain a “boot chain compatibility” appendix in `docs/PORTING_GUIDE.md`; track key rollovers. |
| Firmware vulnerabilities | Publish guidance for updating UEFI/BIOS and validating Secure Boot; document behaviour when Secure Boot is disabled. |

## Reference Artifacts

- **Architecture** – `docs/ARCHITECTURE.md`
- **API Surface** – `docs/API_REFERENCE.md`
- **Porting** – `docs/PORTING_GUIDE.md`
- **Testing** – `tests/` (host suite) and `kernel/tests/`
- **Tooling** – `tools/mkfutfs`, `tools/syswatch`, `tools/ctltool`

Keep this status page updated with every milestone and major subsystem landing.

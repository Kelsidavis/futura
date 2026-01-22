# Desktop Roadmap — Functional OS + Desktop Environment

**Purpose**: Define the concrete path from today’s bootable kernel to a functional desktop environment, with explicit milestones, deliverables, and validation steps.

**Scope**: x86-64 reference platform first, ARM64 parity second. Apple Silicon hardware milestones are tracked in `docs/APPLE_SILICON_ROADMAP.md`.

---

## Guiding Principles

- **Ship small, validate often**: every milestone has pass/fail criteria and a log artifact.
- **Userland-first policy**: desktop services live in userland; kernel only supplies primitives.
- **Test-driven progress**: add a test or harness when a new subsystem is introduced.

---

## Milestone 0 — Baseline Snapshot (Now)

**Goal**: Establish the current baseline and lock in a known-good boot path.

**Deliverables**
- Kernel boots under QEMU and reaches idle loop.
- init stages compositor and client binaries from initramfs.
- FIPC, VFS, network, and block subsystems init successfully.

**Validation**
- `make run` and review `qemu.log`.
- `make test` (GRUB ISO harness) for deterministic pass/fail.

---

## Milestone 1 — Boot + Session Stability

**Goal**: Reliable boot-to-session without manual intervention.

**Deliverables**
- Deterministic headless boot from `make run` with optional auto-exit.
- init sequence fully logs success/failure of compositor + client launch.
- Kernel log shows no fatal errors.

**Acceptance Criteria**
- `make run AUTOEXIT=1` exits in <60s with `[RUN] PASS`.
- `qemu.log` contains a clear success marker from init after compositor socket creation.

**Suggested Work**
- Ensure Wayland socket creation path is logged and retried with bounded backoff.
- Explicitly fail boot if compositor cannot come up (configurable).

---

## Milestone 2 — Userland Core Services

**Goal**: Shell + daemon ecosystem that can support a graphical session.

**Deliverables**
- `init`, `fsd`, `posixd`, `netd`, `svc_registryd` all launch reliably.
- Shell supports pipes, redirection, and job control on /dev/console.
- Service registry responds to basic queries (health and service list).

**Acceptance Criteria**
- `make run` shows all daemons started in `qemu.log`.
- Shell accepts commands on console and can run `cat`, `ls`, `ps`, and `mount` equivalents (where implemented).

**Suggested Work**
- Add a `svc_registryd` smoke test under `tests/`.
- Add `/proc` or `ps`-like visibility for task listings.

---

## Milestone 3 — Filesystem + Storage Completeness

**Goal**: A stable, writable root with predictable permissions.

**Deliverables**
- FuturaFS host tools build and run (`mkfutfs`, `fsck.futfs`).
- fsd exposes stable file operations used by the shell and services.
- Crash-test harness (`make futfs-crash-test`) passes.

**Acceptance Criteria**
- `make futfs-crash-test` passes and produces a recovery log.
- Basic file ops used by shell tools operate without kernel warnings.

**Suggested Work**
- Integrate capability-based FS flows end-to-end in fsd.
- Add a host-side FS integration test under `tests/`.

---

## Milestone 4 — Input + Graphics Foundation

**Goal**: Reliable input stack and framebuffer-backed compositing.

**Deliverables**
- Keyboard + mouse input routed to compositor.
- Framebuffer and damage tracking stable in compositor.
- Basic window management with focus, move, resize.

**Acceptance Criteria**
- `make run` or `make run-headful` shows a composited surface.
- Input events reach the focused client.

**Suggested Work**
- Add a compositor smoke test under `tests/futuraway_*`.
- Log input events in compositor debug mode.

---

## Milestone 5 — Desktop Session

**Goal**: A minimal but functional desktop session.

**Deliverables**
- Session manager starts compositor, shell terminal, and settings panel.
- Basic UI elements: panel, app launcher, window list.
- Clipboard and drag-and-drop at least for text.

**Acceptance Criteria**
- Desktop boots to a terminal window within 10s (headless or VNC).
- Clipboard copy/paste works between two demo apps.

**Suggested Work**
- Add a session config file and startup scripts.
- Implement a small panel app and a launcher.

---

## Milestone 6 — App Toolkit + UX

**Goal**: Consistent GUI applications and a simple toolkit.

**Deliverables**
- Basic widget toolkit for buttons, lists, input fields.
- At least 3 apps: terminal, file browser, and system monitor.
- Theming (fonts, colors, spacing) centralized in one config.

**Acceptance Criteria**
- Apps share visual style and input handling.
- Widgets rendered correctly at 1024x768 and 800x600.

---

## Milestone 7 — Packaging + Distribution

**Goal**: Installable image with reproducible build pipeline.

**Deliverables**
- ISO + disk image generation scripted.
- Versioned build artifacts under `build/` with metadata.
- Basic update mechanism (even if manual fetch + reboot).

**Acceptance Criteria**
- `make iso` produces a bootable image with desktop session.
- Release artifacts pass `tools/release/verify.py`.

---

## Milestone 8 — ARM64 Parity + Hardware Enablement

**Goal**: Desktop session parity on ARM64 (QEMU first, hardware later).

**Deliverables**
- Wayland compositor and clients boot on ARM64 QEMU.
- Virtio GPU + input working on ARM64.
- Apple Silicon bring-up progresses via `docs/APPLE_SILICON_ROADMAP.md`.

**Acceptance Criteria**
- `make qemu-arm64` boots and shows a composited surface (headful or VNC).

---

## Dependencies & Risks

- **Wayland socket readiness**: Current boot logs show socket wait stalls; must be resolved for auto-exit and session startup.
- **Input timing**: PS/2 and event loop stability can gate UI tests.
- **Filesystem integration**: fsd + capability enforcement can block userland.
- **Performance regressions**: compositor and IPC microbenchmarks must stay stable.

---

## Tracking Checklist (Short-Term)

- [ ] Wayland socket appears within 5s of compositor exec
- [ ] `make run AUTOEXIT=1` exits successfully
- [ ] `make test` passes on x86-64
- [ ] `tests/futuraway_*` smoke tests produce stable hashes
- [ ] fsd + shell can create, read, and delete files on writable root

---

## References

- `docs/ARCHITECTURE.md`
- `docs/CURRENT_STATUS.md`
- `docs/WAYLAND_UI_STATUS.md`
- `docs/TESTING.md`
- `docs/APPLE_SILICON_ROADMAP.md`

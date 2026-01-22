# Futura OS Testing Guide

This guide covers the two supported boot/test flows:

1. **Direct kernel + initramfs** (used by `make run` / `make run-headful`)
2. **GRUB ISO + harness** (used by `make iso` / `make test`)

Choose the path that matches what you're validating.

---

## 1) Direct kernel + initramfs (fast iteration)

This is the default developer loop. It builds the kernel, stages userland into an initramfs, and boots via QEMU `-kernel`.

```bash
# Headless run (serial output to terminal)
make run

# Headful run with GTK display
make run-headful

# Headful via VNC (headless-friendly)
make VNC=1 VNC_DISPLAY=unix:/tmp/futura-vnc run-headful
```

Artifacts:
- `build/bin/futura_kernel.elf`
- `build/initramfs.cpio`
- `qemu.log` (captured output from `make run`)

---

## 2) GRUB ISO + automated harness (CI-style)

Use this for deterministic pass/fail runs and when validating the GRUB boot path.

```bash
# Build a bootable ISO
make iso

# Run the automated harness (isa-debug-exit)
make test
```

`make test` boots the ISO under QEMU with `isa-debug-exit` enabled; the exit code signals pass/fail.

Artifacts:
- `futura.iso`
- `futura_disk.img` (scratch disk image)

---

## Expected Output Hints (x86-64)

The early boot path emits short serial markers from the platform init code. If you need to confirm boot flow, look in `qemu.log` or the serial output from the harness run. For deeper traces, enable debug toggles:

```bash
make DEBUG=1 run
```

---

## Common Issues

### QEMU exits immediately
- Ensure you built for the intended platform (`PLATFORM=x86_64` or `PLATFORM=arm64`).
- For ISO runs, verify `grub-mkrescue` is installed.

### Headful run shows no window
- Set `DISPLAY` (X11) or `WAYLAND_DISPLAY` (Wayland).
- Alternatively use VNC: `make VNC=1 run-headful`.

### No disk image available
- Run `make disk` or `make test`, which will create `futura_disk.img`.

---

## Related Docs

- `docs/ARCHITECTURE.md`
- `docs/CURRENT_STATUS.md`
- `docs/ARM64_STATUS.md`
- `docs/PORTING_GUIDE.md`

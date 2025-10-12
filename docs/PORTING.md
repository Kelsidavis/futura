# Porting Guide (Updated Oct 12 2025)

This guide outlines the current requirements for bringing Futura OS to a new hardware platform. The reference implementation targets x86-64 (QEMU/KVM). Arm64 bring-up has started but is incomplete; use it as inspiration rather than gospel.

## Prerequisites

- Cross toolchain with C23 support and a 64-bit ELF target.
- GNU Make and Binutils (linker scripts assume `ld` semantics).
- Early boot firmware or bootloader capable of loading an ELF kernel (GRUB2 today).

## Directory Layout

- `platform/x86_64/`: Production-quality startup, paging bootstrap, interrupt glue, and GRUB-friendly entry points.
- `platform/arm64/`: Early WIP; contains skeleton start code and linker notes.
- `arch/x86_64/`: Architecture helpers shared between kernel subsystems (paging, TSS, GDT, CR3 switches).

Legacy 32-bit artefacts remain in the tree for historical reference—they are not part of the supported build.

## Porting Checklist

1. **Boot Strap**
   - Provide a platform-specific `_start` that establishes paging, stack, and jumps into `kernel_main`.
   - Supply a linker script and memory map aligned with the new architecture’s virtual address expectations.

2. **Paging & Memory Management**
   - Implement the architecture-specific pieces under `arch/<arch>/paging.*` so that `fut_mm` can create/destroy address spaces.
   - Map a higher-half kernel with direct-map region for physical memory allocations.

3. **Interrupts & Exceptions**
   - Deliver IDT/GIC/etc. setup plus ISR stubs that translate into the generic `fut_isr_trampoline` (or architecture equivalent).
   - Wire timer interrupts into `fut_timer_tick()` to advance the scheduler.

4. **Device Prototypes**
   - Minimum set: serial console for `/dev/console`, timer source, and a block or RAM disk interface for the root filesystem.
   - Optional: framebuffer support mirroring the x86-64 MMIO driver if you want `fbtest` running.

5. **Syscall Entry**
   - Implement the user→kernel transition (e.g., `int 0x80`, `syscall`, SVC). Update `include/user/sys.h` with the calling convention.
   - Ensure userland register preservation matches the kernel dispatch expectations in `subsystems/posix_compat/`.

6. **Tooling & Build Integration**
   - Extend `config/toolchain.mk` and top-level `Makefile` to recognise the new architecture (`ARCH=<new>`).
   - Provide QEMU run scripts or docs for smoke testing if applicable.

## Testing Expectations

- Kernel boots to the init sequence, registers `/dev/console`, and runs the VFS smoke test without asserts.
- `src/user/fbtest` executes via the syscall veneer, mmaping the framebuffer and reporting FPS.
- Host-side transport tests continue to run on the development machine (independent of the target port).

## Future Work

- Introduce architecture-specific crates for interrupt routing.
- Harmonise bootstrap code so more logic lives in arch-neutral paths.
- Add CI jobs that cross-compile for arm64 once the bring-up stabilises.

For additional context, review `docs/ARCHITECTURE.md` and `docs/CURRENT_STATUS.md` to ensure platform work lines up with the current roadmap.

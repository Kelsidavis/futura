# Futura OS Porting Guide (Updated Jan 22 2026)

This guide captures the minimum checklist for bringing Futura OS to a new
platform or firmware environment.

## Hardware Abstraction Checklist

1. **Timers** – Provide a periodic source (100 Hz today) and wire the handler to
   `fut_timer_tick()`. Ensure the device continues ticking after `hlt` so
   sleepers wake up.
2. **Interrupts** – Initialise the local APIC/PIC equivalent, populate the IDT,
   and remap vectors so the syscall gate (INT 0x80) and timer interrupt do not
   collide. The x86-64 port lives in `platform/x86_64/platform_init.c` as a
   reference.
3. **Paging** – Supply an architecture-specific `pmap_map` / `pmap_map_user`
   implementation so `fut_mm` can create address spaces. Higher-half kernels are
   assumed; update `KERNEL_VIRTUAL_BASE` as needed.
4. **PCI Enumeration** – Implement config-space access and walk class codes to
   discover virtio-blk and AHCI controllers. The new drivers expect MMIO BARs
   to be mapped into the direct map.
5. **Console I/O** – Bring up a simple serial or framebuffer-backed console so
   `/dev/console` works during early boot.

## Block & Filesystem Integration

- Ensure at least one block transport (virtio-blk or AHCI) enumerates and
  bridges into `fut_blk_core_init()`. The blkcore queues BIOs, so drivers only
  need to fill descriptor tables and raise interrupts or poll completions.
- The log-structured FuturaFS skeleton (`subsystems/futura_fs/`) operates on
  regular files when hosted, but the long-term plan is to back fsd with real
  block handles. Expose DMA-capable buffers and follow PCIe ordering rules to
  keep the log append semantics crash-safe.

## Secure Boot & Firmware

1. **Boot Chain** – Maintain a shim → loader → kernel chain. For Secure Boot,
   sign the shim and loader, then verify the kernel image before hand-off.
2. **Compatibility Advisory** – Track SBAT levels and publish any key-rollover
   requirements. Porters should contribute to the “boot chain compatibility”
   appendix so downstream users know which shims stretch across firmware
   versions.
3. **Firmware Hygiene** – Document how to update the target’s UEFI/BIOS and how
   to validate Secure Boot settings. Provide guidance for operating when Secure
   Boot is disabled (e.g., ensure the log-structured FS still detects tampering
   via checksums).

## CI & Doc Drift Safeguards

- Add a CI job that checks `docs/STATUS.md` for a matching “Current Milestone”
  entry before merges. When updating milestones, update the docs in the same
  commit to avoid drift.
- Track security and performance OKRs (see `docs/STATUS.md`) as part of the
  port. The memory-safe-language goal applies to all new drivers—if the port
  requires C for performance, open an issue documenting the exception.
- Wire KASAN/UBSan (or the platform equivalent) into debug builds. For platforms
  without hardware assistance, consider software sanitizers or qemu-based
  instrumentation.

## Reproducible Builds & Supply Chain

- Ensure the toolchain used for the port is hermetic; record versions in
  `docs/STATUS.md`.
- Integrate cosign signing of artifacts and publish TUF metadata so consumers
  can verify the boot chain.

## Bringing Up Userland

1. Port the syscall veneers (`include/user/sys.h`) if the calling convention
   differs.
2. Validate that `libfutura`’s allocator (`sys_brk`) and mmap wrappers work with
   the new MMU implementation.
3. Run the new blkcore/FuturaFS self-test (`tests/test_futfs.c`) under QEMU to
   confirm virtio-blk backed storage works end-to-end on the platform.

With these steps in place, the platform should boot to serial console, mount
root, run `/bin/fbtest`, exercise the block self-tests, and be ready for higher
level services.

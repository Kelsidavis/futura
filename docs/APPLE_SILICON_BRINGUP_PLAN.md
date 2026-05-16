# Apple Silicon Bring-up Plan

**Last Updated**: 2026-05-16
**Status**: 🚧 Foundation only — kernel does **not yet boot** on real Apple
Silicon hardware.  `make m1n1-payload` produces a valid m1n1-compatible
Image.gz with the ARM64 Linux header, but the kernel's early MMU setup
is still QEMU-virt-tuned.

This document captures the staged work needed to get the existing
ARM64 kernel (currently `make test-arm64` → 2654/2654 PASS under
`qemu-system-aarch64 -M virt`) booting on a real M1/M2/M3/M4 Mac via
m1n1.

## What Works Today

- **m1n1 payload generation** (`scripts/create-m1n1-payload.sh`,
  `make m1n1-payload`).  The kernel image carries the ARM64 Linux
  header that m1n1 expects.
- **Apple Silicon driver scaffolding** under `platform/arm64/drivers/`:
  `apple_uart.c` (s5l-uart), `apple_aic.c` (interrupt controller),
  `apple_rtkit.c` (RTKit IPC), `apple_ans2.c` (NVMe), `apple_dcp.c`
  (display controller), `apple_hid.c`, `apple_xhci.c`, `apple_power.c`.
- **DTB-driven platform detection**: `kernel/dtb/arm64_dtb.c:170-185`
  recognises Apple M1/M2/M3/M4 by their root compatible strings and
  fills `fut_platform_info_t` accordingly.
- **MIDR_EL1 implementer captured at boot entry**
  (`platform/arm64/boot.S:_kernel_entry`, commit `1902941e`).  The
  implementer field is saved in `x19` so future setup code can
  branch on platform without re-reading the register.

## What's Still Missing

The reason the kernel doesn't actually boot on Apple Silicon today
breaks down into five blockers.  Each can be tackled independently and
verified incrementally — items 1 and 2 unblock the rest.

### 1. Dynamic load-PA detection in `boot.S` ✅ LANDED (commit `c028e0c3`)

`platform/arm64/boot.S` previously hardcoded three QEMU-virt-specific
physical addresses into the boot page tables:

- L2 identity-map start PA = `0x40000000`.
- L1[1] → L2_dram (only valid when load PA is in
  `0x40000000-0x7FFFFFFF`).
- Kernel high-VA L2_dram start PA = `0x40200000`.

All three are now derived from `adr x21, _start`:

```asm
adr     x21, _start
bic     x21, x21, #0x1FFFFF        /* 2 MB align down  — kernel high-VA target */
bic     x22, x21, #0x3FFFFFFF      /* 1 GB align down  — identity 1 GB base */
lsr     x23, x22, #30              /* L1 index for the identity 1 GB block */
```

For QEMU virt the values are bit-identical to the previous literals
(0x40200000 / 0x40000000 / 1), so the existing 2654/2654 selftest
path is unchanged.  For PA-relocated loads within the 39-bit VA
window the identity and high-VA mappings now slide with the kernel.

### 2. 48-bit VA across the board ✅ LANDED (commit `ffd99e31`)

The previous TCR_EL1 setup used T0SZ/T1SZ = 25 (39-bit VA, L1 root,
8 GB addressable per half).  Apple Silicon DRAM lives at PA
`0x10_0000_0000` or higher on M1 — past the 39-bit window.

The migration was unified rather than Y-branched on platform: both
TTBR0 and TTBR1 now walk a 4-level L0/L1/L2 chain (T0SZ = T1SZ = 16),
which is a strict superset of the old 39-bit space.  Concretely:

- New `boot_l0_table` / `kernel_l0_table` (4 KiB each) sit above the
  existing L1 tables.
- `boot_l0_table[bits 47:39 of load_PA]` → `boot_l1_table`.
  For QEMU virt (load PA = 0x40200000) the L0 index is 0; for Apple
  Silicon with the kernel above 512 GB it lands in a higher slot.
- `kernel_l0_table[511]` → `kernel_l1_table`.  KERN_VA_BASE
  (0xFFFFFF8040000000) always occupies L0 index 511 regardless of
  load PA.
- TCR_EL1: T0SZ/T1SZ flipped 0x19→0x10.  Granule, shareability, and
  IPS unchanged.
- TTBR0_EL1 / TTBR1_EL1 now point at the L0 tables.

QEMU virt regression: `make test-arm64` PASS 2654/2654 unchanged.

### 3. `KERN_PA_BASE` becomes a runtime value ✅ LANDED (commit `8cd7a32a`)

`include/platform/arm64/memory/pmap.h:31` defines:

```c
#define KERN_PA_BASE      0x40200000ULL
#define KERN_VA_BASE      0xFFFFFF8040000000ULL
#define KERNEL_VIRT_OFFSET (KERN_VA_BASE - KERN_PA_BASE)
```

Every `phys_to_virt` / `virt_to_phys` in the kernel uses
`KERNEL_VIRT_OFFSET` as a compile-time constant.  Once boot.S can
load anywhere, this has to become a runtime variable populated by
boot.S before any C code runs.  The cleanest path:

- Store the actual load PA in a `.bss` symbol that boot.S writes
  before jumping to C.
- Convert the inline macros into static inlines that read the
  variable.  Touches many sites (`grep -rn KERNEL_VIRT_OFFSET kernel`),
  but each call is small.

### 4. Apple s5l-UART early-debug shim 🚧 PARTIAL (commit `1a156b28`)

**Post-MMU side landed.**  `fut_serial_putc()` now reads a
function-pointer backend before falling through to PL011; the
`fut_apple_uart_init()` driver registers its s5l-uart `putc` as the
backend once the DTB-discovered UART base has been cached.  After
that point every `fut_printf()` routes through the Apple UART driver
on real hardware.  On QEMU virt the backend stays NULL and the
PL011 path runs unchanged.

**Pre-MMU side still TBD.**  `platform/arm64/boot.S` writes
diagnostic characters to PL011 at `0x09000000` (QEMU virt UART) for
the early-debug path.  Those writes are commented out today, so they
don't actually fault on real Apple Silicon — but if a future
debugging session uncomments them, the kernel would silently drop
the writes (the peripheral L2 map covers PA 0-1 GiB which is empty
on Apple hardware).  The remaining work is either to probe MIDR_EL1
before the early write and skip on Apple, or to add a minimum-
viable assembly shim for the s5l-uart base.

### 5. AIC wiring in the IRQ entry path

`platform/arm64/boot.S:fut_irq_handler` and the post-MMU IRQ
dispatch (`gic_irq_handler.c`) currently assume GICv2 at
`0x08000000/0x08010000`.  Apple Silicon uses the Apple Interrupt
Controller (AIC); `platform/arm64/interrupt/apple_aic.c` has the
register-level driver but the boot path never wires it in.  Once
the kernel runs C code on Apple Silicon, swap the dispatch based on
`fut_platform_info_t::has_aic`.

## Verification Strategy

Each phase above ships independently with the **invariant** that
`make test-arm64` (QEMU virt) continues to PASS 2654/2654.

For Apple Silicon end-to-end:
1. Tethered boot via `python3 -m m1n1.run m1n1.macho -b Image.gz kernel.macho`.
2. Capture serial output once the Apple-UART early-debug shim is in
   place.
3. Diff against the QEMU virt boot log to find the first divergence.

## References

- `docs/ARM64_STATUS.md` — current ARM64 bring-up status.
- `docs/APPLE_SILICON_ROADMAP.md` — broader Apple Silicon roadmap.
- `scripts/create-m1n1-payload.sh` — m1n1 payload generator.
- m1n1 docs: <https://github.com/AsahiLinux/m1n1>

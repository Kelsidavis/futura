# Apple Silicon Bring-up Plan

**Last Updated**: 2026-05-16
**Status**: 🚧 Kernel-side bring-up done.  5/5 original blockers
landed, plus a follow-up round closing FIQ dispatch + DAIF.F clear +
64 GiB Apple peripheral mapping window + DMA-PA correctness across
xhci/ans2/dcp/dart + Asahi `/soc/<type>@<addr>` DT path fallbacks +
ARM64 Image header flags + m1n1 framebuffer first-light fast-path.
Not yet validated on real Apple Silicon hardware.  `make m1n1-payload`
produces a valid m1n1-compatible Image.gz with the ARM64 Linux
header (now correctly flagged as relocatable).  All progress is
implemented behind runtime detection so that QEMU virt's selftest
suite (currently 2870/2870 PASS under `qemu-system-aarch64 -M virt`)
stays green at every step.

This document captures the staged work originally needed to get the
ARM64 kernel booting on a real M1/M2/M3/M4 Mac via m1n1.  Most
items are now ✅ LANDED — see the per-blocker sections for the
commit references and remaining gaps.

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

## Blocker Status

Originally five blockers stood between today's state and a successful
Apple Silicon boot.  Most are now landed — the only remaining piece
on the kernel side is the pre-MMU early-debug asm path in boot.S,
which is currently inactive (writes are commented out), so a real
hardware boot attempt now depends on actual M1/M2 verification work,
not further code design.

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
(0x40200000 / 0x40000000 / 1), so the existing 2870/2870 selftest
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

QEMU virt regression: `make test-arm64` PASS 2870/2870 unchanged.

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

### 4. Apple s5l-UART early-debug shim ✅ LANDED (commits `1a156b28`, `1de1d8d4`)

**Post-MMU side** (`1a156b28`).  `fut_serial_putc()` now reads a
function-pointer backend before falling through to PL011; the
`fut_apple_uart_init()` driver registers its s5l-uart `putc` as the
backend once the DTB-discovered UART base has been cached.  After
that point every `fut_printf()` routes through the Apple UART driver
on real hardware.  On QEMU virt the backend stays NULL and the
PL011 path runs unchanged.

**Pre-MMU side** (`1de1d8d4`).  `bss_cleared` in `boot.S` now uses
the MIDR_EL1 implementer field (already stashed in x19 at boot)
to pick the right UART PA:
- implementer 0x61 ('a' = Apple) → s5l-uart at PA 0x235200000
  (data register = base + 0x20)
- anything else → PL011 at PA 0x09000000 (data register = base + 0x00)

The diagnostic character store itself stays commented out by
default — uncomment it when debugging a hang before MMU comes up
and the write lands on the right hardware.

### 5. AIC wiring in the IRQ entry path ✅ LANDED (commits `a48210a3`, `942ee205`)

Two-step landing:

1. **boot.S → C trampoline + pluggable backend** (`a48210a3`).  The
   asm `fut_irq_handler` now shrinks to a thin `bl fut_irq_main`,
   moving the GICv2 IAR/spurious-check/timer/EOI flow into C.
   Adds `fut_irq_set_dispatch_backend()` so platform-init can swap
   the entire IRQ flow with a single function pointer.
2. **AIC registers itself as the backend** (`942ee205`).
   `fut_apple_irq_init()` calls
   `fut_irq_set_dispatch_backend(apple_aic_handle_irq)` after the
   AIC driver comes up; from that point boot.S delegates to the
   AIC's event-bitmap scan + auto-clear instead of poking at
   non-existent GICC/GICD MMIO on Apple hardware.

QEMU virt's `has_aic` is false, so the AIC hook never runs and the
GIC default stays in place.  2870/2870 selftest PASS unchanged.

### 5a. FIQ dispatch for the ARM Generic Timer ✅ LANDED (commit `e814dc1f`)

Apple delivers the ARM Generic Timer via the FIQ exception vector
rather than IRQ.  Before this fix all four `fiq_*_handler` labels in
`boot.S` branched to `generic_exception_handler` (which panics) —
so the first timer FIQ on real Apple hardware would have crashed
the kernel before the scheduler ever got a tick.

The fix mirrors the IRQ path on the FIQ side:

- `fut_fiq_main()` + `fut_fiq_set_dispatch_backend()` in
  `platform_init.c`, with the same backend-pointer pattern as
  `fut_irq_main`.  Default behavior (no backend) is to return
  silently — QEMU virt never delivers FIQ legitimately, so a
  spurious one shouldn't crash.
- New `fiq_handler_entry` trampoline + `fut_fiq_handler` asm in
  `boot.S`, mirror of `irq_handler_entry`.
- `fiq_sp0_handler` / `fiq_spx_handler` / `fiq_aarch64_handler`
  now branch to `fiq_handler_entry`.  `fiq_aarch32_handler`
  stays on the panic path because we don't run AArch32 guests.
- `apple_aic.c::fut_apple_irq_init()` registers
  `apple_aic_handle_irq` on the IRQ backend slot AND
  `apple_aic_handle_fiq` (commit `3b1e93a2`) on the FIQ slot.
  The FIQ dispatcher checks `CNTP_CTL_EL0.ISTATUS` first and
  re-arms the timer if it's the source — the AIC's event bitmap
  doesn't surface the architectural timer.

### 5b. DAIF.F unmask + critical-section symmetry ✅ LANDED (commits `28f6ab00`, `fd098716`)

`fut_enable_interrupts` only cleared the I bit, leaving F (FIQ)
masked at its boot default of 1.  On QEMU virt this was harmless
because nothing fires as FIQ there; on Apple it meant the timer
FIQ never reached the CPU even after blocker #5a's dispatch path
was in place.  Switch to `daifclr #3` (clears I + F) and drop
`PSTATE_F_BIT` from new-thread initial PSTATE in
`fut_context_init`.

`fut_save_and_disable_interrupts` also only masked I, which would
have let a timer FIQ race scheduler-lock acquisition.  Updated to
`daifset #3` (mask I + F) and `fut_restore_interrupts` writes the
saved DAIF back atomically.

### 6. Apple peripheral PA→VA mapping ✅ LANDED (commits `4013e2cc`, `056797c7`, `62ae1555`)

Apple peripherals (UART, AIC, SMC, DCP, ANS, MCA, PCIe, DART)
all sit at PAs the boot identity map and kernel DRAM window both
miss.  Three iterations:

1. **Initial 8 GiB window** (`4013e2cc`) — `kernel_l1_table[8..15]`
   maps VA `0xFFFFFF8200000000-0xFFFFFF83FFFFFFFF` → PA
   `0x200000000-0x3FFFFFFFF` with device-nGnRE attrs.  Covers
   every M1 / M2 SoC-internal peripheral.  New
   `fut_kernel_peripheral_va(pa) = pa | 0xFFFFFF8000000000ULL`
   helper.  Every Apple C wrapper converts DTB-discovered PA to
   kernel VA before handing it to its Rust crate.
2. **32 GiB extension** (`056797c7`) — bumped to cover M1's PCIe
   at PA `0x690000000` (~26 GiB).
3. **64 GiB extension** (`62ae1555`) — bumped again to cover
   M1 Pro / Max's PCIe at PA `0xc00000000` (~48 GiB).

### 7. DMA address correctness ✅ LANDED (commits `fcb7a5d4`, `447e1aae`, `47bc5d30`, `69cc8a71`)

Sweep of "treating kernel VA as PA" bugs surfaced by the peripheral
mapping work.  Multiple Apple-side drivers were writing kernel VAs
into hardware registers / DMA descriptors that the controller
interprets as physical addresses — latent on QEMU virt because the
identity-ish DRAM mapping made VA ≈ PA, would have caused silent
DMA corruption on real Apple HW.  Fixed:

- `apple_xhci`: ring buffers + control / bulk transfers take
  paired (va, pa); CRCR / DCBAAP / TRB.param get the PA.
- `apple_ans2`: ASQ / ACQ / NVMMU TCB base + every `cmd.prp1`
  goes through `rust_virt_to_phys` (which itself was returning
  the VA unchanged on ARM64 — also fixed).
- `apple_dcp`: surface allocation now stores `va` for memset and
  `phys = pmap_virt_to_phys(va)` for DART map.
- `apple_dart`: IOMMU page-table chunks go through
  `rust_virt_to_phys` instead of the bogus `ptr as u64`.

### 8. Asahi DT path fallbacks ✅ LANDED (commits `578f6fbb`, `4057cd83`)

Fixing `fut_dtb_get_property` (`578f6fbb`) to handle nested nodes
correctly revealed that the existing `/arm-io/*` path strings were
historical Futura-test-fixture naming, not the Asahi `/soc/<type>
@<addr>` paths m1n1 actually emits.  Added Asahi-spec fallbacks
first in each chain, kept `/arm-io/*` as last-ditch.

### 9. ARM64 Image header flags ✅ LANDED (commit `a0291515`)

The `flags` field at offset 0x18 was 0 → "page size unspecified,
bound to text_offset = 0" per arm64/booting.rst.  m1n1 would have
honoured that and tried to place the kernel at PA 0 (which it
itself occupies on real Apple HW).  Set `flags = 0xA` → 4K pages +
bit 3 = relocatable.

### 10. m1n1 framebuffer first-light ✅ LANDED (commits `cbaa1eb6`, `ffcfcd1a`, `a103eb48`, `3fc851f0`)

If m1n1 publishes a Simple Framebuffer at `/chosen/framebuffer`
(width / height / stride / reg), the kernel paints into it
directly via the peripheral mapping VA — bypassing the
not-yet-complete DCP swap-chain protocol.  Runs BEFORE RTKit boot
so first-light survives an RTKit failure.  `fut_fb_hwinfo.virt`
field lets probers pre-compute the VA when `pmap_phys_to_virt`
would give a bogus answer (m1n1 FB at DRAM PA outside the
`L2_dram` window).

## Asahi-Linux-Derived Rust Drivers

Per the project's Rust-only-drivers policy, all hardware register-
level Apple Silicon code lives in `drivers/rust/apple_*` — these are
Asahi-Linux-derived ports.  The C surface under
`platform/arm64/{drivers,interrupt}/apple_*.c` is a thin compat
bridge that:

- Caches the DTB-discovered MMIO base in a static.
- Forwards every public C function call into the Rust FFI
  (`rust_<driver>_*`).
- Is gated on the DTB having identified Apple Silicon, so RPi /
  QEMU virt builds never reach these wrappers.

Status of the C → Rust migration (refreshed 2026-05-16):

| C file           | Rust crate                | Status                                |
|------------------|---------------------------|---------------------------------------|
| `apple_aic.c`    | `apple_aic`               | ✅ wrapped (`ba6ae1d5`)                 |
| `apple_uart.c`   | `apple_uart`              | ✅ wrapped (`7128f82e`)                 |
| `apple_power.c`  | `apple_smc`               | ✅ already wrapped                       |
| `apple_hid.c`    | `apple_hid` (new)         | ✅ wrapped (`dd81c949`, US-layout parser)|
| `apple_audio.c`  | `apple_mca`               | ✅ wraps existing crate (`f95357b9`)    |
| `apple_xhci.c`   | `apple_xhci` (new)        | ✅ wrapped (`71f2db0b`, full xHCI body)  |
| `apple_rtkit.c`  | `apple_rtkit` (extended)  | ✅ wrapped (`8b4e1322`) — added FFI for |
|                  |                           | `start_endpoint`, `set_ap/iop_power_state`, |
|                  |                           | `shutdown`, `process_messages`, `recv`  |
| `apple_ans2.c`   | `apple_ans2`              | ✅ collapsed to thunk (`634f6d8c`,      |
|                  |                           | -1290 lines — Rust crate already had   |
|                  |                           | full FFI; C body was a duplicate)       |
| `apple_dcp.c`    | `apple_dcp` (new)         | ✅ wrapped (`997e4c06`, 602→220 lines C;|
|                  |                           | Rust owns state machine + protocol,    |
|                  |                           | C keeps page alloc + DART + RTKit boot)|

All Apple-Silicon C drivers in `platform/arm64/drivers/apple_*.c`
now have their hardware-touching layer in a Rust crate under
`drivers/rust/apple_*`.  Latest DTB additions wire `/arm-io/mca`
into `fut_platform_info_t.mca_base` (commit `ceaefe69`), so the
audio MCA actually initialises on real hardware instead of staying
in "probed but inactive" mode.

Each wrap is verified by the QEMU virt 2870/2870 selftest — the
new Rust code only runs once the DTB-driven Apple-Silicon init path
runs, which on QEMU never happens.

## Verification Strategy

Each phase above ships independently with the **invariant** that
`make test-arm64` (QEMU virt) continues to PASS 2870/2870.  RPi
config-only build (`make rpi-image`) also stays green.

For Apple Silicon end-to-end:
1. Tethered boot via `python3 -m m1n1.run m1n1.macho -b Image.gz kernel.macho`.
2. Capture serial output once the s5l-UART early-debug shim is in
   place.
3. Diff against the QEMU virt boot log to find the first divergence.

## References

- `docs/ARM64_STATUS.md` — current ARM64 bring-up status.
- `docs/APPLE_SILICON_ROADMAP.md` — broader Apple Silicon roadmap.
- `scripts/create-m1n1-payload.sh` — m1n1 payload generator.
- m1n1 docs: <https://github.com/AsahiLinux/m1n1>

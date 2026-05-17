# Apple Silicon Framebuffer Initialisation

**Status (2026-05-17)**: Two-tier path in tree — m1n1 first-light fast-path always runs, DCP-owned takeover now attempts whenever DCP comes up. Real-hardware validation pending pmgr clock-gate wiring.

## Goal

The kernel should be able to drive the panel itself on real Apple Silicon hardware, rather than piggybacking on m1n1's framebuffer mapping forever. That means owning the DCP (Display Coprocessor) bring-up, swap-chain, and scanout — not just borrowing m1n1's pre-published `/chosen/framebuffer`.

## Two-tier strategy

```
┌─────────────────────────────────────────────────────────────────┐
│ TIER 1 — m1n1 first-light fast-path                              │
│   Trigger: info->framebuffer_phys != 0 in DT                     │
│   Effect:  fb_set_hwinfo published immediately, kernel has a     │
│            console before any DCP / DART / RTKit traffic         │
│   Status:  ✅ in tree, exercised on every Apple boot              │
└─────────────────────────────────────────────────────────────────┘
                                ↓
┌─────────────────────────────────────────────────────────────────┐
│ TIER 2 — DCP-owned takeover                                      │
│   Trigger: DCP RTKit endpoint comes up + mode set succeeds        │
│   Steps:   1. Bring up DART (apple_dart_*)                       │
│            2. Boot RTKit endpoint (apple_rtkit_boot)             │
│            3. Send power-on message                              │
│            4. Set mode from DT-published panel geometry          │
│            5. Allocate page-aligned surface; map through DART    │
│            6. Build swap_submit message via Rust                 │
│            7. Send swap_submit through RTKit                     │
│            8. Re-register fb_hwinfo pointing at DCP surface PA   │
│   Fallback: any failure leaves the m1n1 FB registration intact   │
│   Status:  ⚠ wired in apple_dcp_init since 24a9488f; not yet      │
│            verified on real hardware                             │
└─────────────────────────────────────────────────────────────────┘
```

The fallback property is important: if tier 2 fails at any step the kernel still has a working console because tier 1 already registered the m1n1 FB.

## What's in tree

| Layer                    | Status | Code pointer                                |
|--------------------------|--------|---------------------------------------------|
| DTB walker for panel info | ✅    | `kernel/dtb/arm64_dtb.c:fut_dtb_get_chosen_framebuffer` |
| Tier 1 fast-path         | ✅     | `platform/arm64/drivers/apple_dcp.c:207-231` |
| DART (IOMMU)             | ✅     | `drivers/rust/apple_dart/`                  |
| RTKit endpoint dispatch  | ✅     | `drivers/rust/apple_rtkit/`, `platform/arm64/drivers/apple_rtkit.c` |
| DCP mode set             | ✅     | `rust_apple_dcp_set_mode`                   |
| DCP surface registration | ✅     | `rust_apple_dcp_register_surface`           |
| DCP swap submit          | ✅     | `rust_apple_dcp_swap_submit_build`          |
| Kernel fb_hwinfo register | ✅    | `dcp_register_fb` → `fb_set_hwinfo`         |
| Tier 2 takeover hook     | ✅     | `apple_dcp_init` after `rust_apple_dcp_mode_is_set` |

## What's outstanding

1. **pmgr power-domain enable for DCP.** On real Apple hardware the DCP coprocessor's power and clock are gated by the SoC's pmgr block until software writes the standard `PS_TARGET=0xF` pattern.  `apple_pmgr_enable(offset)` exists (`platform/arm64/drivers/apple_pmgr.c`); what's missing is the per-SoC table of DCP power-domain offsets (or DT-phandle resolution of each device node's `power-domains` property).  Without this, RTKit boot likely fails on cold boot and the kernel falls back to the m1n1 FB silently.

2. **DCP firmware verification.** m1n1 normally loads the DCP firmware before transferring control. We assume that's done. If a future bring-up scenario skips m1n1's DCP setup, we'd need our own firmware loader path here.

3. ~~**Swap completion ack tracking.**~~ ✅ Landed in `18eb9fe4` — `apple_dcp_init` now polls `rust_apple_dcp_swap_take_complete` every 1ms for up to 250ms after sending the swap_submit message.  Failure to ack within that budget leaves the m1n1 FB in place (when present) instead of registering an unverified DCP FB.

4. **Hotplug / mode change.** Resolution changes and panel reconfigurations need full swap-chain control.  Today we set the mode once at init and never revisit.

## Code path on a successful boot (real hardware, when pmgr lands)

```
arm64 platform_init.c
  └─ fut_dtb_parse → info->framebuffer_phys, display_width, height
  └─ fut_apple_dcp_platform_init
       └─ apple_dcp_init
            ├─ [DCP] First-light: m1n1 FB at PA … VA …      ← TIER 1
            ├─ apple_dart_init                              ← DART up
            ├─ apple_rtkit_init / boot / register endpoint  ← RTKit
            ├─ apple_rtkit_send_message(POWER_ON)
            ├─ rust_apple_dcp_set_mode(W, H, 60, BGRA8888)
            ├─ [DCP] m1n1 FB published, attempting DCP-owned takeover
            ├─ dcp_alloc_surface(W, H, fmt)                 ← page alloc + DART map
            ├─ rust_apple_dcp_swap_submit_build              ← marshal command
            ├─ apple_rtkit_send_message(swap_msg)            ← hand off to DCP
            ├─ dcp_register_fb(fb_idx)                       ← swap kernel FB
            └─ [DCP] DCP-owned FB now active (surface N)
```

When pmgr isn't wired the boot stops one of two ways:
- RTKit boot fails → return -1 from apple_dcp_init; kernel keeps tier-1 FB.
- Swap-submit messages silently drop (DCP not actually running) → kernel re-registers FB but scanout doesn't update; rare in practice because the swap-submit build returns 0 when the message can't be assembled.

## Code pointers

- DCP wrapper: `platform/arm64/drivers/apple_dcp.c`
- DCP Rust crate: `drivers/rust/apple_dcp/`
- Tier-2 takeover decision: lines around `[DCP] m1n1 FB published, attempting DCP-owned takeover` in `apple_dcp.c`
- pmgr helper: `include/platform/arm64/apple_pmgr.h`
- Reference: `docs/APPLE_SILICON_ROADMAP.md` Phase 3 (Display + Input)

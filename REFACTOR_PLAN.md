# Refactoring Plan: From Demo Mode to Production Architecture

## Executive Summary

**UPDATE**: The flag has been renamed from `ENABLE_WAYLAND` to `ENABLE_WAYLAND` to reflect that Wayland is the production UI, not a demo. This plan proposes further eliminating the flag entirely and making Wayland + wl-term the standard, always-enabled user interface for Futura OS. The current architecture treats Wayland as an optional feature wrapped in conditional compilation, creating a messy split between different code paths. This refactoring moves to a clean, unified architecture where `make run` and `make run-headful` build a fully-featured OS.

## Current State Analysis

### Problems with Current Architecture

1. **Conditional Compilation Mess**: ENABLE_WAYLAND (Makefile:203) creates two completely different builds:
   - When ENABLE_WAYLAND=0: Only fbtest and shell binaries are embedded
   - When ENABLE_WAYLAND=1: Wayland compositor + clients are embedded
   - This creates 12+ conditional compilation blocks across kernel_main.c and elf64.c

2. **Build System Inconsistency**:
   - `make kernel` does NOT build Wayland userland binaries
   - `make run` sets ENABLE_WAYLAND=1 and builds everything
   - `make test` and `make iso` build without Wayland, creating non-functional system
   - Developers must remember to use specific targets to get a working system

3. **Binary Embedding Chaos**:
   - 5 Wayland binaries (compositor, wl-simple, wl-colorwheel, futura-shell, wl-term) wrapped in #if blocks
   - Staging functions in elf64.c:655-823 wrapped in ENABLE_WAYLAND
   - kernel_main.c has 11 separate #if ENABLE_WAYLAND blocks (lines 72, 79, 779, 962, 1055, 1171, 1356, 1366, 1388, 1413, 1427)

4. **Init Process Confusion**:
   - init_stub.c is designed to launch wl-term (lines 35-68)
   - But wl-term is only staged when ENABLE_WAYLAND=1
   - When ENABLE_WAYLAND=0, init attempts to exec a binary that doesn't exist
   - Currently masked by the fact that init_stub.c was recently modified to launch wl-term but no binaries are staged without the flag

5. **Feature Flag Semantics**:
   - ENABLE_WINSRV_DEMO (line 202) - legacy window server demo (should be removed entirely)
   - ENABLE_WAYLAND (line 203) - Wayland is NOT a demo, it's the production UI
   - These flags suggest the OS is in a "demo" state rather than production-ready

## Target Architecture

### Design Principles

1. **Wayland is Production**: The compositor and wl-term are the standard user interface, not a demo
2. **Single Build Path**: `make kernel` should produce a bootable, fully-functional system
3. **No Conditional UI**: The kernel always embeds and stages the compositor and terminal client
4. **Clean Dependencies**: Build targets have clear, predictable dependencies

### New Build Structure

```
all (default)
  ├─ rust-drivers      # Build Rust virtio drivers
  ├─ kernel            # Build kernel with ALL userland binaries embedded
  │   ├─ libfutura     # Minimal C runtime
  │   ├─ userland      # All user services
  │   │   ├─ compositor (futura-wayland)
  │   │   ├─ wl-term
  │   │   ├─ wl-simple
  │   │   ├─ wl-colorwheel
  │   │   ├─ futura-shell
  │   │   ├─ init_stub
  │   │   └─ fbtest (legacy, for diagnostics)
  │   └─ link kernel.elf
  └─ userland (already exists)

test: kernel disk
  └─ Boot and run smoke tests

run: kernel disk
  └─ Boot headless

run-headful: kernel disk
  └─ Boot with QEMU graphics window
```

### Binary Embedding Strategy

**Always Embed (Production)**:
- futura-wayland (compositor) → /sbin/futura-wayland
- wl-term (terminal client) → /bin/wl-term
- futura-shell (shell) → /sbin/futura-shell
- init_stub → /sbin/init

**Conditionally Embed (Testing/Debug)**:
- wl-simple → only if ENABLE_WAYLANDS=1 (testing, not required)
- wl-colorwheel → only if ENABLE_WAYLANDS=1 (testing, not required)
- fbtest → only if ENABLE_FB_DIAGNOSTICS=1 (diagnostics)

**Remove Entirely**:
- winsrv, winstub (legacy window server demo, unmaintained)

## Implementation Steps

### Phase 1: Remove Legacy Demo Code (Low Risk)

**Goal**: Eliminate ENABLE_WINSRV_DEMO and associated dead code

**Files to Modify**:
1. Makefile (lines 202, 638-640)
   - Remove ENABLE_WINSRV_DEMO flag
   - Remove WINSRV_BLOB and WINSTUB_BLOB from OBJECTS
   - Remove binary build rules for winsrv/winstub (lines 742-748, 794-800)

2. kernel_main.c (line 79)
   - Remove #if ENABLE_WINSRV_DEMO || ENABLE_WAYLAND
   - Keep only WAYLAND includes

3. kernel/exec/elf64.c
   - Remove winsrv/winstub staging functions (if any exist)

4. include/kernel/exec.h
   - Remove winsrv/winstub declarations (lines 15-16)

**Verification**:
- Build with `make kernel iso` should succeed
- Boot test should show no winsrv references
- Git grep for WINSRV should return no results

### Phase 2: Make Core Wayland Binaries Unconditional (Medium Risk)

**Goal**: futura-wayland, wl-term, futura-shell, and init_stub are ALWAYS built and embedded

**Files to Modify**:
1. Makefile
   - Move futura-wayland, wl-term, futura-shell definitions outside #if ENABLE_WAYLAND (lines 617-622)
   - Move blob objects to unconditional OBJECTS list (remove from line 643 conditional)
   - Move build rules outside conditional (lines 760-772, 807-822)
   - Keep ENABLE_WAYLAND for optional clients only (wl-simple, wl-colorwheel)

2. kernel/exec/elf64.c
   - Move extern declarations outside #if ENABLE_WAYLAND (lines 655-667)
   - Move staging functions outside #if ENABLE_WAYLAND (lines 771-842)
   - Keep only test clients (wl-simple, wl-colorwheel) inside #if ENABLE_WAYLANDS (renamed)

3. kernel/kernel_main.c
   - Remove #if ENABLE_WAYLAND from core staging (line 1171)
   - Always call fut_stage_wayland_compositor_binary()
   - Always call fut_stage_wl_term_binary()
   - Always call fut_stage_wayland_shell_binary()
   - Keep #if ENABLE_WAYLANDS for test clients

4. include/kernel/exec.h
   - No changes needed (declarations already unconditional)

**Verification**:
- Build with `make clean && make kernel iso` (no flags)
- Boot and check for staging messages:
  ```
  [INIT] futura-wayland staged at /sbin/futura-wayland
  [INIT] wl-term staged at /bin/wl-term
  [INIT] futura-shell staged at /sbin/futura-shell
  ```
- Verify init_stub can exec /bin/wl-term successfully

### Phase 3: Refactor userland Build Target (Medium Risk)

**Goal**: `make kernel` depends on `userland`, ensuring binaries are built before kernel links

**Files to Modify**:
1. Makefile
   - Update kernel target dependency (line 694):
     ```makefile
     kernel: userland rust-drivers $(BIN_DIR)/futura_kernel.elf
     ```
   - Remove redundant userspace target (lines 892-898) - merge into userland
   - Update userland target (lines 877-879):
     ```makefile
     userland: libfutura third_party-wayland
         @echo "Building userland services..."
         @$(MAKE) -C src/user all
         @$(MAKE) -C src/user/compositor/futura-wayland all
         @$(MAKE) -C src/user/clients/wl-term all
         @$(MAKE) -C src/user/shell/futura-shell all
     ```

2. src/user/Makefile
   - Ensure `all` target builds compositor, wl-term, futura-shell
   - Remove any ENABLE_WAYLAND conditionals

**Verification**:
- `make clean && make kernel` should build all Wayland binaries automatically
- No need to set ENABLE_WAYLAND=1
- Binary embedding should work without manual intervention

### Phase 4: Simplify Build Targets (Low Risk)

**Goal**: Clean up run/run-headful to remove ENABLE_WAYLAND=1 overrides

**Files to Modify**:
1. Makefile (lines 1019-1058)
   - Remove ENABLE_WAYLAND=1 from run target (lines 1020-1025)
   - Simplify to:
     ```makefile
     run:
         @$(MAKE) vendor
         @$(MAKE) kernel disk
         @echo "==> Running QEMU (headful=$(HEADFUL), mem=$(MEM) MiB, debug=$(DEBUG))"
         @set -o pipefail; \
         $(QEMU) $(RUN_QEMU_FLAGS) -kernel $(BIN_DIR)/futura_kernel.elf -initrd $(INITRAMFS) $(RUN_QEMU_APPEND) | tee qemu.log
     ```
   - Update help-run documentation (lines 1066-1093) to reflect production build

2. README.md
   - Update "Build Commands" section to remove ENABLE_WAYLAND mentions
   - Document that Wayland is the standard UI, not a demo

**Verification**:
- `make run` should work identically to current `make ENABLE_WAYLAND=1 run`
- `make test` should boot a fully-functional system
- Documentation should no longer reference "demo mode"

### Phase 5: Rename Remaining Demo Flag (Low Risk)

**Goal**: Rename ENABLE_WAYLAND → ENABLE_WAYLAND_TEST_CLIENTS for clarity

**Files to Modify**:
1. Makefile (line 203)
   ```makefile
   ENABLE_WAYLAND_TEST_CLIENTS ?= 0  # wl-simple, wl-colorwheel
   ```

2. kernel/kernel_main.c
   - Replace `#if ENABLE_WAYLAND` with `#if ENABLE_WAYLAND_TEST_CLIENTS` for wl-simple/wl-colorwheel only

3. kernel/exec/elf64.c
   - Replace `#if ENABLE_WAYLAND` with `#if ENABLE_WAYLAND_TEST_CLIENTS` for test clients only

4. README.md
   - Document ENABLE_WAYLAND_TEST_CLIENTS as optional testing flag

**Verification**:
- `git grep ENABLE_WAYLAND` should return 0 results
- `git grep ENABLE_WAYLAND_TEST_CLIENTS` should only show test client code

### Phase 6: Remove fbtest Embedding (Optional, Low Priority)

**Goal**: Move fbtest from always-embedded to diagnostic-only flag

**Rationale**: fbtest is a legacy framebuffer test, not needed for production boots

**Files to Modify**:
1. Makefile
   - Add ENABLE_FB_DIAGNOSTICS ?= 0 flag
   - Wrap FBTEST_BLOB in #if ENABLE_FB_DIAGNOSTICS

2. kernel/exec/elf64.c
   - Wrap fbtest staging in #if ENABLE_FB_DIAGNOSTICS

**Verification**:
- Default builds should not embed fbtest
- `make ENABLE_FB_DIAGNOSTICS=1 kernel` should embed it

## Risk Assessment

### High Risk Changes
- None (all changes are additive or remove dead code)

### Medium Risk Changes
- Phase 2: Making Wayland binaries unconditional
  - **Risk**: Build failures if Wayland dependencies (libwayland-client, etc.) are missing
  - **Mitigation**: Check for pkg-config/wayland in configure step, provide clear error message
  - **Rollback**: Revert Makefile changes, re-enable ENABLE_WAYLAND=1 for CI

- Phase 3: Making kernel depend on userland
  - **Risk**: Circular dependencies or build order issues
  - **Mitigation**: Test with `make clean && make kernel` repeatedly
  - **Rollback**: Remove userland dependency from kernel target

### Low Risk Changes
- Phase 1: Removing WINSRV_DEMO (dead code removal)
- Phase 4: Simplifying run targets (cosmetic)
- Phase 5: Renaming flag (semantic clarity)
- Phase 6: Making fbtest conditional (optional)

## Testing Strategy

### Unit Testing
- Each phase should be tested independently
- Build from clean state: `make clean && make kernel iso`
- Verify binary sizes are consistent
- Check objdump for expected symbols

### Integration Testing
- Boot test after each phase: `make test`
- Check serial output for expected staging messages
- Verify init process can launch wl-term
- Run headful: `make run-headful` and verify graphics work

### Regression Testing
- Ensure `make perf` still passes
- Check that `make release` builds reproducibly
- Verify ARM64 build still works (may not have Wayland)

## Success Criteria

1. **Build System**:
   - `make` (default) builds a bootable OS with Wayland
   - `make kernel` builds all necessary userland binaries
   - `make test` boots and runs smoke tests successfully

2. **Code Cleanliness**:
   - Zero `#if ENABLE_WAYLAND` blocks in kernel_main.c
   - Clear separation between production (always) and test (optional) binaries
   - No dead code references to winsrv/winstub

3. **User Experience**:
   - `make run` boots to a working wl-term terminal
   - `make run-headful` shows graphical terminal in QEMU window
   - No need to set obscure build flags to get a working system

4. **Documentation**:
   - README.md reflects production architecture and build flow
   - No references to "demo mode"
   - Clear documentation of optional test client flags

## Timeline Estimate

- Phase 1: 30 minutes (remove dead code)
- Phase 2: 2 hours (make Wayland unconditional, test thoroughly)
- Phase 3: 1 hour (refactor build dependencies)
- Phase 4: 30 minutes (simplify run targets)
- Phase 5: 15 minutes (rename flag)
- Phase 6: 30 minutes (optional fbtest work)

**Total**: ~4.5-5 hours for complete refactoring

## Rollback Plan

Each phase can be independently reverted:

1. **Git commits**: Each phase should be a separate commit
2. **Feature branch**: Work on `refactor/production-wayland` branch
3. **CI gating**: Ensure all tests pass before merging to main

If critical issues arise:
```bash
git revert <commit-sha>  # Revert specific phase
# or
git reset --hard origin/main  # Nuclear option
```

## Future Work (Out of Scope)

These improvements are desirable but not part of this refactoring:

1. **Dynamic compositor selection**: Allow choosing between futurawayd, weston, etc. at build time
2. **Multi-backend support**: Support both Wayland and framebuffer console as runtime choice
3. **Compositor configuration**: Move compositor settings to a config file instead of hardcoded
4. **Better error handling**: If compositor fails to start, fall back to framebuffer console
5. **ARM64 Wayland support**: Port Wayland stack to ARM64 platform

## Open Questions

1. **Wayland library dependencies**: Should we vendor libwayland-client or continue using system libraries?
   - **Recommendation**: Continue using system libraries for now, document in deps

2. **Compositor startup failures**: What should happen if futura-wayland fails to start?
   - **Recommendation**: Kernel should print error and halt (Phase 2 can add this)

3. **fbtest removal timing**: Should we remove fbtest entirely or keep it for diagnostics?
   - **Recommendation**: Keep it conditional (Phase 6), useful for debugging framebuffer issues

4. **Test clients in CI**: Should CI build wl-simple/wl-colorwheel by default?
   - **Recommendation**: No, keep ENABLE_WAYLAND_TEST_CLIENTS=0 for CI to reduce build time

## Conclusion

This refactoring eliminates the false dichotomy between "demo mode" and "production mode" by making Wayland + wl-term the standard, production-quality user interface. The changes are low-to-medium risk, can be implemented incrementally, and result in a cleaner, more maintainable codebase. After completion, developers can simply run `make` to build a fully-functional OS without needing to understand obscure build flags.

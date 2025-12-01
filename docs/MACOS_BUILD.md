# Building Futura on macOS

This document describes the build setup for Futura OS on macOS (Apple Silicon).

## Prerequisites

The following tools need to be installed via Homebrew:

### Core Toolchain
```bash
brew install gcc@14                  # x86-64 native GCC (for Linux builds)
brew install x86_64-elf-gcc         # x86-64 cross-compiler for kernel
brew install x86_64-elf-binutils    # x86-64 binutils (as, ld, ar, objcopy)
brew install aarch64-elf-gcc        # ARM64 cross-compiler for kernel
brew install aarch64-elf-binutils   # ARM64 binutils
```

### Rust Toolchain
```bash
brew install rustup-init
rustup default stable
rustup target add x86_64-unknown-linux-gnu
```

**Important:** The Homebrew `rust` package doesn't include rustup, so you must use `rustup-init` and add the Linux targets manually.

### Build Tools
```bash
brew install meson ninja pkg-config
```

## Makefile Changes for macOS Compatibility

The following changes were made to support building on macOS:

### 1. Main Makefile (Makefile)

Added macOS detection for x86_64 platform to use cross-compiler:

```makefile
ifeq ($(PLATFORM),x86_64)
    # x86-64 toolchain
    # On macOS, use the cross-compiler; on Linux, use native tools
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC := $(CROSS_COMPILE_X86)gcc
        AS := $(CROSS_COMPILE_X86)as
        LD := $(CROSS_COMPILE_X86)ld
        AR := $(CROSS_COMPILE_X86)ar
        OBJCOPY := $(CROSS_COMPILE_X86)objcopy
    else
        CC := gcc-14
        AS := as
        LD := ld
        AR := ar
        OBJCOPY := objcopy
    endif
    ...
endif
```

Fixed Rust driver builds to use `$(AR)` instead of hardcoded `ar`:

```makefile
# Before:
cd $$tmpdir && ar x $(abspath $(RUST_LIB_VIRTIO_BLK)) && ... && ar rcs ...

# After:
cd $$tmpdir && $(AR) x $(abspath $(RUST_LIB_VIRTIO_BLK)) && ... && $(AR) rcs ...
```

### 2. libfutura Makefile (src/user/libfutura/Makefile)

Added similar macOS detection:

```makefile
else
    # x86_64 platform - use cross-compiler on macOS
    ifeq ($(shell uname -s),Darwin)
        CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
        CC := $(CROSS_COMPILE_X86)gcc
        AS := $(CROSS_COMPILE_X86)as
        AR := $(CROSS_COMPILE_X86)ar
    else
        CC := gcc
        AS := as
        AR := ar
    endif
    ARCH_CFLAGS := -m64
    ARCH_ASFLAGS := --64
endif
```

### 3. Wayland Makefile (third_party/wayland/Makefile)

Added macOS-specific compiler and linker flags:

```makefile
# macOS: Remove -fno-semantic-interposition (unsupported by Clang) and add -D_POSIX_C_SOURCE
ifeq ($(shell uname -s),Darwin)
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1', '-D_POSIX_C_SOURCE=200809L'
else
NATIVE_C_ARGS_LIST := '-O2', '-g0', '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-fno-semantic-interposition', '-fno-stack-protector', '-DFUTURA_NO_GLIBC=1'
endif

# macOS uses Apple ld, not GNU ld - use compatible flags
ifeq ($(shell uname -s),Darwin)
NATIVE_LINK_ARGS_LIST := '-Wl,-dead_strip'
else
NATIVE_LINK_ARGS_LIST := '-Wl,--build-id=none', '-Wl,--gc-sections'
endif
```

## Build Instructions

### Setting up Environment

Add rustup to your PATH:

```bash
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
```

You may want to add this to your `~/.zshrc` for persistence.

### Building Components

1. **Build libfutura** (userspace library):
   ```bash
   make libfutura
   ```
   ✅ This works on macOS

2. **Build Rust drivers**:
   ```bash
   make rust-drivers
   ```
   ✅ This works on macOS

3. **Build kernel**:
   ```bash
   make kernel
   ```
   ✅ Works on macOS (Wayland automatically skipped)

## Known Limitations

### Wayland Support

**Status:** ❌ Does not work on macOS

Wayland requires Linux-specific system calls that don't exist on macOS:
- `sys/epoll.h` - Event polling interface
- `MSG_DONTWAIT`, `CMSG_LEN` - Socket control message macros
- Other Linux-specific APIs

**Why this is an issue:**
- The build tries to compile Wayland libraries for the *host* (macOS) not the target (Futura)
- This is because `wayland-scanner` needs to run during the build to generate protocol code
- `wayland-scanner` depends on Linux-specific features

**Workarounds:**
1. **Skip Wayland** (recommended for kernel-only development):
   - Set `ENABLE_WAYLAND_DEMO=0` when building
   - This should skip Wayland-dependent components

2. **Use Docker/Linux container**:
   - Run the build in a Linux container
   - This is the best solution for full builds including Wayland

3. **Cross-compile approach** (future work):
   - Build Wayland libraries targeting x86_64-unknown-linux-gnu
   - Use a pre-built wayland-scanner binary for the host
   - Requires significant build system changes

## Testing

### Verify Toolchain Installation

```bash
# Check x86_64 cross-compiler
/opt/homebrew/bin/x86_64-elf-gcc --version
/opt/homebrew/bin/x86_64-elf-as --version

# Check ARM64 cross-compiler
/opt/homebrew/bin/aarch64-elf-gcc --version

# Check Rust targets
rustc --print target-list | grep -E '(x86_64-unknown-linux|aarch64-unknown-linux)'
```

### Build Status Summary

| Component | Status | Notes |
|-----------|--------|-------|
| **x86_64 Platform** | | |
| libfutura (x86_64) | ✅ Working | Builds successfully |
| Rust drivers (virtio_blk, virtio_net) | ✅ Working | Builds successfully |
| Kernel (without Wayland) | ✅ Working | **Builds successfully** (verified 2025-11-30) |
| init + stubs userland | ✅ Working | Basic userland builds successfully |
| **ARM64 Platform** | | |
| libfutura (arm64) | ✅ Working | Builds successfully |
| Rust drivers (arm64) | ✅ Working | Builds successfully |
| Kernel (arm64) | ✅ Working | **Builds successfully** (3.2MB, verified 2025-11-30) |
| init + stubs + forktest userland | ✅ Working | ARM64 userland builds successfully |
| **Blocked on macOS** | | |
| Wayland libraries | ❌ Blocked | Requires Linux-specific syscalls |
| Shell binary | ❌ Blocked | Uses GNU nested functions (clang incompatible) |
| Full Wayland userland | ❌ Blocked | Depends on Wayland |

## Additional macOS Build Fixes (2025-11-30)

The following additional changes were required to successfully build the kernel on macOS:

### 1. Conditional Userland Programs (src/user/Makefile)

Only build non-Wayland programs on macOS:
```makefile
ifeq ($(shell uname -s),Darwin)
USERLAND_DIRS := libfutura init stubs
else
USERLAND_DIRS := libfutura init shell cat echo wc fsd posixd futurawayd fbtest stubs ...
endif
```

### 2. Fixed init and stubs Makefiles

Added cross-compiler support to `src/user/init/Makefile` and `src/user/stubs/Makefile`:
```makefile
ifeq ($(shell uname -s),Darwin)
    CROSS_COMPILE_X86 ?= /opt/homebrew/bin/x86_64-elf-
    CC := $(CROSS_COMPILE_X86)gcc
    LD := $(CROSS_COMPILE_X86)ld
    AR := $(CROSS_COMPILE_X86)ar
endif
```

### 3. Fixed virtio_gpu.c Inline Assembly

Replaced incompatible inline assembly with standard I/O functions:
```c
// Before:
__asm__ volatile("outl %0, %1" : : "a"(addr), "Nd"(0xCF8));

// After:
fut_outl(0xCF8, addr);
```

### 4. Removed stdio.h from hal_halt.c

Kernel code shouldn't include standard library headers:
```c
// Removed:
#include <stdio.h>
```

### 5. Conditional Blob Objects (Main Makefile)

Skip shell and Wayland blobs on macOS:
```makefile
# Skip shell blob on macOS (uses GNU nested functions)
ifneq ($(shell uname -s),Darwin)
OBJECTS += $(SHELL_BLOB)
endif

# Skip Wayland blobs on macOS
ifneq ($(shell uname -s),Darwin)
OBJECTS += $(WAYLAND_COMPOSITOR_BLOB) $(WAYLAND_SHELL_BLOB) ...
endif
```

### 6. Stub Functions for Missing Blobs (kernel/exec/elf64.c)

Provide stub implementations when blobs aren't available:
```c
#ifndef FUTURA_MACOS_HOST_BUILD
int fut_stage_shell_binary(void) {
    return stage_blob(...);  // Real implementation
}
#else
int fut_stage_shell_binary(void) {
    return -ENOSYS;  // Stub for macOS
}
#endif
```

### 7. Conditional Vendor Target (Main Makefile)

Skip Wayland library build on macOS:
```makefile
ifeq ($(shell uname -s),Darwin)
vendor:
    @echo "Skipping Wayland on macOS (requires Linux-specific syscalls)"
else
vendor: third_party-wayland
endif
```

### 8. macOS Build Flag (Main Makefile)

Added compile-time flag for conditional compilation:
```makefile
ifeq ($(shell uname -s),Darwin)
CFLAGS += -DFUTURA_MACOS_HOST_BUILD=1
endif
```

## Successful Build Output

When building on macOS, you should see:
```
$ make kernel
CC abort.c
...
Skipping Wayland on macOS (requires Linux-specific syscalls)
Building userland services...
Building libfutura for x86_64...
Building init for x86_64...
CC main.c
LD ../../../build/bin/x86_64/user/init
Building stubs for x86_64...
...
Build complete: build/bin/futura_kernel.elf
```

Kernel size: approximately 2.2MB

## Next Steps

1. **For kernel development**: macOS is now fully supported!
2. **For full system**: Set up Linux development environment (VM or Docker) for Wayland work
3. **Future improvement**: Port shell to standard C (remove nested functions)

## Troubleshooting

### Issue: `ar` errors during Rust driver build
**Solution:** Make sure the Makefile uses `$(AR)` instead of hardcoded `ar` in the Rust driver targets.

### Issue: Assembly errors with `--64` flag
**Solution:** Use x86_64-elf-as instead of system `as`. This is now handled by the macOS detection in the Makefile.

### Issue: Rust target not found
**Solution:** Install the target with rustup:
```bash
rustup target add x86_64-unknown-linux-gnu
```

### Issue: Wrong Rust toolchain
**Solution:** Ensure rustup's bin directory is first in PATH:
```bash
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
```

## ARM64 Build Support (2025-11-30)

ARM64 builds have been successfully enabled on macOS with full parity to x86_64 builds.

### ARM64 Build Instructions

```bash
# Install ARM64 Rust target
rustup target add aarch64-unknown-linux-gnu

# Build ARM64 kernel
export PATH="/opt/homebrew/opt/rustup/bin:/usr/bin:/bin:$PATH"
PLATFORM=arm64 make kernel
```

### ARM64 Build Fixes Applied

#### 1. Type Compatibility (pmap_virt_to_phys)

Fixed type mismatches where ARM64's `pmap_virt_to_phys` expects `const void *` while x86_64 uses `uintptr_t`:

**Files modified:**
- `kernel/memory/fut_memory.c`
- `kernel/exec/elf64.c`
- `kernel/trap/page_fault.c`
- `kernel/sys_fork.c`
- `kernel/memory/fut_mm.c`
- `kernel/sys_brk.c`
- `kernel/tests/*.c`
- `kernel/kernel_main.c`

**Change:** `pmap_virt_to_phys((uintptr_t)ptr)` → `pmap_virt_to_phys((void *)ptr)`

#### 2. Platform-Specific Thread Trampoline

Added ARM64-specific thread trampoline implementation in `kernel/threading/fut_thread.c`:
- x86_64: Uses naked assembly with x86 instructions
- ARM64: Simplified C wrapper (naked attribute not well-supported on ARM64 cross-compiler)

#### 3. EXEC_DEBUG Macro for ARM64

Added missing `EXEC_DEBUG` macro definition in ARM64 section of `kernel/exec/elf64.c`.

#### 4. Wayland Interactive Mode

Fixed conditional compilation in `kernel/video/fb_mmio.c` to handle ARM64 builds without `WAYLAND_INTERACTIVE_MODE` defined.

#### 5. Userland Makefile Updates

Added macOS cross-compiler detection to:
- `src/user/forktest/Makefile`

#### 6. Binary Blob Stubs

Added stub functions for Wayland/shell binaries in `platform/arm64/interrupt/arm64_stubs.c`:
- `fut_stage_wl_term_binary()`
- `fut_stage_init_stub_binary()`
- `fut_stage_second_stub_binary()`
- `fut_stage_shell_binary()`
- `fut_stage_fbtest_binary()`

#### 7. Duplicate Symbol Resolution

Removed duplicate `sys_sync()` definition from `kernel/sys_fileio_advanced.c` (kept the one in `kernel/sys_sync.c`).

#### 8. Objcopy Fix

Updated main Makefile to use `$(OBJCOPY)` variable instead of hardcoded `aarch64-elf-objcopy`.

### ARM64 Build Output

```bash
$ PLATFORM=arm64 make kernel
...
Build complete: build/bin/futura_kernel.elf
OBJCOPY build/bin/futura_kernel.bin
```

**Kernel size:** 3.2MB (ARM aarch64 ELF64 executable)

# Futura OS ARM64 Platform-Agnostic Refactoring Report

## Executive Summary

The Futura OS codebase is **well-architected for cross-platform ARM64 support**. Most code is already platform-agnostic, with inline assembly properly isolated behind conditional compilation directives. However, **3 critical issues** remain that will prevent ARM64 userland builds from succeeding:

1. **Makefiles missing PLATFORM propagation** (2 files)
2. **Hardcoded memory address** (1 file)  
3. **Library path references not using PLATFORM variable** (1 file)

---

## Detailed Findings

### 1. Inline Assembly & Syscall Dispatch - STATUS: GOOD

**Location**: `src/user/libfutura/syscall_portable.h`

The codebase correctly implements platform-specific syscall dispatch using conditional compilation:

```c
/* x86-64 Platform (int $0x80) */
#ifdef PLATFORM_X86_64
static inline long syscall0(long nr) {
    long ret;
    __asm__ __volatile__(
        "int $0x80"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r11", "memory"
    );
    return ret;
}
/* ... syscall1-6 with x86 register constraints (rdi, rsi, rdx, r8, r9) ... */
#endif

/* ARM64 Platform (SVC #0) */
#ifdef PLATFORM_ARM64
static inline long syscall0(long nr) {
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0"
        : "=r"(x8)
        : "r"(x8)
        : "memory"
    );
    return x8;
}
/* ... syscall1-6 with ARM64 register constraints (x0-x8) ... */
#endif
```

**Verdict**: Platform-specific assembly properly isolated. No refactoring needed.

**Files affected**:
- `/Users/kelsi/futura/src/user/libfutura/syscall_portable.h` (lines 19-216)
- `/Users/kelsi/futura/src/user/libfutura/syscall_shim.c` (lines 11-14)
- `/Users/kelsi/futura/src/user/compositor/futura-wayland/syscall_wrappers.c` (uses portable header)

---

### 2. Makefiles - PLATFORM Detection

#### GOOD: 13 Makefiles with proper PLATFORM detection

```bash
/Users/kelsi/futura/src/user/libfutura/Makefile                  # Lines 5-6
/Users/kelsi/futura/src/user/init/Makefile                       # Lines 5-6
/Users/kelsi/futura/src/user/fbtest/Makefile                     # Lines 3-4
/Users/kelsi/futura/src/user/echo/Makefile                       # Lines 3-4
/Users/kelsi/futura/src/user/cat/Makefile                        # (PLATFORM propagated)
/Users/kelsi/futura/src/user/wc/Makefile                         # (PLATFORM propagated)
/Users/kelsi/futura/src/user/fsd/Makefile                        # (PLATFORM propagated)
/Users/kelsi/futura/src/user/netd/Makefile                       # (PLATFORM propagated)
/Users/kelsi/futura/src/user/posixd/Makefile                     # (PLATFORM propagated)
/Users/kelsi/futura/src/user/svc_registryd/Makefile              # (PLATFORM propagated)
/Users/kelsi/futura/src/user/stubs/Makefile                      # (PLATFORM propagated)
/Users/kelsi/futura/src/user/arm64_gfxtest/Makefile              # (ARM64-specific)
/Users/kelsi/futura/src/user/arm64_uidemo/Makefile               # (ARM64-specific)
/Users/kelsi/futura/src/user/shell/futura-shell/Makefile         # Lines 3-4, 39-40
```

Example from `src/user/init/Makefile` (correct pattern):
```makefile
PLATFORM ?= x86_64

ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    ARCH_CFLAGS := -march=armv8-a -mtune=cortex-a53
    LDSCRIPT := ../libfutura/userland_arm64.ld
else
    CC := gcc
    ARCH_CFLAGS := -m64
    LDSCRIPT := ../libfutura/userland.ld
endif

# Library paths use $(PLATFORM)
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a
```

#### CRITICAL: 2 Makefiles missing PLATFORM detection

**Problem 1: `/Users/kelsi/futura/src/user/shell/Makefile`** (Lines 1-12)

```makefile
# SPDX-License-Identifier: MPL-2.0

SUBDIRS := futura-shell

.PHONY: all clean

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir all || exit 1; done

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1; done
```

**Issue**: Does NOT propagate `PLATFORM` variable to subdirectory `futura-shell`.

**Impact**: When building with `make PLATFORM=arm64`, the futura-shell subdirectory won't receive the PLATFORM variable, causing it to default to x86_64 and link against x86_64 libraries.

**Fix**:
```makefile
PLATFORM ?= x86_64
SUBDIRS := futura-shell

.PHONY: all clean

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir PLATFORM=$(PLATFORM) all || exit 1; done

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir PLATFORM=$(PLATFORM) clean || exit 1; done
```

---

**Problem 2: `/Users/kelsi/futura/src/user/compositor/futura-wayland/Makefile`** (Lines 1-53)

```makefile
# SPDX-License-Identifier: MPL-2.0

ROOT := ../../../..
BUILD_ROOT := $(ROOT)/build
OBJ_DIR := $(BUILD_ROOT)/obj/user/compositor/futura-wayland
BIN_DIR := $(BUILD_ROOT)/bin/user

include $(ROOT)/mk/wayland.mk

TARGET := $(BIN_DIR)/futura-wayland
SRCS := main.c comp.c shm_backend.c ...
...
LDSCRIPT := ../../libfutura/userland.ld
CRT0 := $(BUILD_ROOT)/lib/crt0.o                    # <- NO $(PLATFORM)
LIBFUTURA := $(BUILD_ROOT)/lib/libfutura.a          # <- NO $(PLATFORM)
...
CC := gcc
...
LDFLAGS := -nostdlib -static -no-pie -T $(LDSCRIPT) ...
```

**Issues**:
1. Missing `PLATFORM ?= x86_64` at top
2. `CRT0` should be `$(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o` (line 35)
3. `LIBFUTURA` should be `$(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a` (line 36)
4. `LDSCRIPT` should be `../../libfutura/userland_$(PLATFORM).ld` (line 34)
5. `OBJ_DIR` should include `$(PLATFORM)` for proper separation (line 5)

**Impact**: Will always try to link x86_64 crt0 and libfutura even when cross-compiling for ARM64. Link will fail.

**Fix** (insert after line 1):
```makefile
# Platform detection
PLATFORM ?= x86_64

ifeq ($(PLATFORM),arm64)
    CC := aarch64-elf-gcc
    ARCH_CFLAGS := -march=armv8-a
else
    CC := gcc
    ARCH_CFLAGS := -m64
endif

# Update paths to use $(PLATFORM)
OBJ_DIR := $(BUILD_ROOT)/obj/$(PLATFORM)/user/compositor/futura-wayland
LDSCRIPT := ../../libfutura/userland_$(PLATFORM).ld
CRT0 := $(BUILD_ROOT)/lib/$(PLATFORM)/crt0.o
LIBFUTURA := $(BUILD_ROOT)/lib/$(PLATFORM)/libfutura.a
```

---

### 3. Hardcoded Memory Values & Page Sizes

#### GOOD: Page sizes are platform-neutral

```bash
# All correct (both x86-64 and ARM64 use 4KB pages)
src/user/libfutura/fstat.c:12           #define FUT_DEFAULT_BLKSIZE 4096ULL
src/user/libfutura/memory_map.c:9       #define FUT_PAGE_SIZE  4096UL
src/user/libfutura/mremap.c:12          #define FUT_PAGE_SIZE 4096UL
```

#### CRITICAL: Hardcoded memory address in shell

**Location**: `/Users/kelsi/futura/src/user/shell/main.c` (Lines 1242-1245)

```c
/* Helper function to process a file descriptor */
auto int process_fd(int fd, int max_lines) {
    char *file_buffer = (char *)0x50000000;  /* Use high memory region */
    long total_bytes = 0;
    // ...
}
```

**Issue**: 
- Hardcoded x86-64 virtual address `0x50000000`
- ARM64 kernel may load userland at different base address (e.g., 0x40000000)
- Will cause memory corruption, segfault, or silent data corruption on ARM64

**Impact**: CRITICAL - Will break `tail` command on ARM64

**Fix**: Use dynamic memory allocation instead:
```c
auto int process_fd(int fd, int max_lines) {
    // Option 1: Allocate on heap using brk()
    long max_size = 65536;  /* 64KB limit */
    char *file_buffer = (char *)sys_brk((void *)((char *)sbrk(0) + max_size));
    
    // Option 2: Use stack-allocated smaller buffer and process in chunks
    // Option 3: Use mmap() if available
```

---

### 4. Linker Scripts - STATUS: GOOD

**Location**: `src/user/libfutura/`

Three platform-specific linker scripts exist:

```bash
userland.ld              # Old x86 generic (926 bytes)
userland_x86_64.ld       # Explicit x86-64 (926 bytes) - OUTPUT_FORMAT("elf64-x86-64")
userland_arm64.ld        # ARM64 (927 bytes) - OUTPUT_FORMAT("elf64-littleaarch64")
```

Both `userland_x86_64.ld` and `userland_arm64.ld` are identical except for OUTPUT_FORMAT and OUTPUT_ARCH:
- x86-64: `OUTPUT_FORMAT("elf64-x86-64")`, `OUTPUT_ARCH(i386:x86-64)`
- ARM64:  `OUTPUT_FORMAT("elf64-littleaarch64")`, `OUTPUT_ARCH(aarch64)`

Both use same memory layout: `0x400000` (4MB) base address, 16MB heap.

**Status**: Linker scripts are correctly configured. Good pattern.

---

### 5. CRT0 & Library Linking

#### GOOD: Most Makefiles properly reference platform-specific CRT0

Example from `src/user/fbtest/Makefile`:
```makefile
ifeq ($(PLATFORM),arm64)
    LDSCRIPT := ../libfutura/userland_arm64.ld
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    LDSCRIPT := ../libfutura/userland.ld
    LIBGCC :=
endif
CRT0 := $(LIB_DIR)/crt0.o
LIBFUTURA := $(LIB_DIR)/libfutura.a
```

#### BROKEN: futura-wayland Makefile (see section 2.2)

CRT0 and LIBFUTURA paths missing `$(PLATFORM)` variable.

---

### 6. Architecture-Specific ABI - STATUS: GOOD

**Location**: `include/platform/`

Proper conditional ABI selection:

```bash
include/platform/x86_64/syscall_abi.h   # x86-64 syscall numbers
include/platform/arm64/syscall_abi.h    # ARM64 syscall numbers
```

**Usage in `src/user/libfutura/syscall_shim.c` (lines 11-14)**:
```c
#if defined(__x86_64__)
#include <platform/x86_64/syscall_abi.h>
#elif defined(__aarch64__) || defined(__arm64__)
#include <platform/arm64/syscall_abi.h>
#else
#error "Unsupported architecture"
#endif
```

**Verdict**: Properly isolated. No refactoring needed.

---

### 7. Register Constraints & Calling Conventions - STATUS: GOOD

Handled correctly in `syscall_portable.h`:

**x86-64 ABI** (System V AMD64 x86-64 calling convention):
```c
/* 4-argument syscall on x86-64 */
static inline long syscall4(long nr, long arg1, long arg2, long arg3, long arg4) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3), "r"(arg4)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```
- `a` = RAX (syscall number, return value)
- `D` = RDI (arg1)
- `S` = RSI (arg2)
- `d` = RDX (arg3)
- `r` = arbitrary (arg4+)

**ARM64 ABI** (ARM64 EABI):
```c
static inline long syscall4(long nr, long arg1, long arg2, long arg3, long arg4) {
    register long x0 __asm__("x0") = arg1;
    register long x1 __asm__("x1") = arg2;
    register long x2 __asm__("x2") = arg3;
    register long x3 __asm__("x3") = arg4;
    register long x8 __asm__("x8") = nr;
    __asm__ __volatile__(
        "svc #0\n"
        : "=r"(x0)
        : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory"
    );
    return x0;
}
```
- `x8` = syscall number
- `x0-x7` = arguments/return value

**Verdict**: Both correctly implemented. No refactoring needed.

---

## Summary of Issues

| # | Severity | File | Issue | Fix |
|---|----------|------|-------|-----|
| 1 | CRITICAL | `src/user/shell/Makefile` | Missing PLATFORM propagation to subdirectory | Add `PLATFORM ?= x86_64` and pass to $(MAKE) |
| 2 | CRITICAL | `src/user/compositor/futura-wayland/Makefile` | CRT0/LIBFUTURA paths missing $(PLATFORM); missing PLATFORM detection | Add PLATFORM detection; update paths to use $(PLATFORM) |
| 3 | CRITICAL | `src/user/shell/main.c:1242` | Hardcoded memory address 0x50000000 | Replace with dynamic memory allocation (brk/mmap) |
| 4 | INFO | `src/user/futurawayd/Makefile` | No PLATFORM | Host-side tool; intentional - no fix needed |

---

## Code Quality Observations

### What's Done Well

1. **Platform isolation via #ifdef**: All platform-specific code properly guarded
2. **Linker scripts**: Correct per-platform scripts with proper ELF headers
3. **CRT0 handling**: Platform-specific startup code correctly selected
4. **ABI abstraction**: Syscall numbers and ABIs properly abstracted
5. **Cross-compilation support**: Most Makefiles support `PLATFORM=arm64`

### Patterns to Continue

From `src/user/init/Makefile`:
```makefile
PLATFORM ?= x86_64

ifeq ($(PLATFORM),arm64)
    CROSS_COMPILE ?= /opt/homebrew/bin/aarch64-elf-
    CC := $(CROSS_COMPILE)gcc
    LDSCRIPT := ../libfutura/userland_arm64.ld
    LIBGCC := $(shell $(CC) -print-libgcc-file-name)
else
    CC := gcc
    LDSCRIPT := ../libfutura/userland.ld
    LIBGCC :=
endif

# Use $(PLATFORM) in all path variables
LIB_DIR := $(BUILD_DIR)/lib/$(PLATFORM)
OBJ_DIR := $(BUILD_DIR)/obj/$(PLATFORM)/user/...
```

This pattern should be followed in:
- `src/user/shell/Makefile`
- `src/user/compositor/futura-wayland/Makefile`

---

## Recommendations

### Immediate Actions (Blocks ARM64 builds)

1. **Fix `src/user/shell/Makefile`**: Add PLATFORM detection and propagation
2. **Fix `src/user/compositor/futura-wayland/Makefile`**: Add PLATFORM detection; fix library paths
3. **Fix `src/user/shell/main.c:1242`**: Replace hardcoded address with dynamic allocation

### Follow-up Actions

4. **Verify linker script memory layouts**: Confirm both x86_64 and ARM64 userland can accommodate 16MB heap at their respective load addresses
5. **Test end-to-end**: Build userland with `make PLATFORM=arm64` and verify all programs link correctly
6. **Review other hardcoded addresses**: Grep for `0x[0-9a-f]{5,}` patterns to catch similar issues

---

## Conclusion

The Futura OS codebase demonstrates **excellent architecture for cross-platform support**. The remaining issues are primarily **build system configuration** rather than fundamental design problems. Fixing the 3 critical issues identified will unblock ARM64 userland builds and demonstrate the robustness of the platform abstraction layer.

**Effort estimate**: 1-2 hours for fixes + testing
**Risk level**: Low (changes are isolated to Makefiles and one memory allocation)

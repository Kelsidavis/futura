# Futura OS Kernel Process Management - Complete Documentation

## Overview

This documentation set provides comprehensive coverage of the Futura OS kernel's process management subsystem, including task creation, process execution, and ELF binary loading.

## Documentation Files

### 1. **PROCESS_MANAGEMENT.md** (1417 lines, 39KB)
   **Complete technical reference** covering all aspects of process management
   
   **Contents:**
   - Section 1: Task Management (fut_task.c) - structures and all functions
   - Section 2: Thread Management (fut_thread.c) - thread creation and lifecycle
   - Section 3: Fork Syscall (sys_fork.c) - process cloning with CoW
   - Section 4: Execve Syscall (sys_execve.c) - program execution
   - Section 5: ELF Executable Loading (elf64.c) - detailed ELF loading process
   - Section 6: Memory Management (fut_mm.c) - address space management
   - Section 7: Process Management Syscalls - all implemented syscalls
   - Section 8: Architecture-Specific Contexts - x86-64 and ARM64
   - Section 9: Execution Flow Summary - complete flow diagrams
   - Section 10: Key Design Decisions - architectural choices
   - Section 11: Limitations and TODOs - known limitations

### 2. **PROCESS_MANAGEMENT_QUICK_REF.md** (313 lines, 9.8KB)
   **Quick reference guide** for developers
   
   **Contents:**
   - File locations table for all components
   - Function signatures organized by component
   - Key data structure overview
   - Critical design points (5 major patterns)
   - Process creation and ELF loading flow diagrams
   - Address space layout
   - Common code patterns
   - Return values for all syscalls
   - Testing commands

### 3. **This File: KERNEL_STRUCTURE_OVERVIEW.md**
   Navigation guide and summary overview

---

## Quick Navigation

### By Component

| Component | Main File | Header | Section |
|-----------|-----------|--------|---------|
| **Task Management** | `kernel/threading/fut_task.c` | `include/kernel/fut_task.h` | [1](PROCESS_MANAGEMENT.md#1-task-management) |
| **Thread Management** | `kernel/threading/fut_thread.c` | `include/kernel/fut_thread.h` | [2](PROCESS_MANAGEMENT.md#2-thread-management) |
| **Fork Syscall** | `kernel/sys_fork.c` | `include/kernel/fut_task.h` | [3](PROCESS_MANAGEMENT.md#3-fork-syscall) |
| **Execve Syscall** | `kernel/sys_execve.c` | `include/kernel/exec.h` | [4](PROCESS_MANAGEMENT.md#4-execve-syscall) |
| **ELF Loading** | `kernel/exec/elf64.c` | `include/kernel/exec.h` | [5](PROCESS_MANAGEMENT.md#5-elf-executable-loading) |
| **Memory Management** | `kernel/memory/fut_mm.c` | `include/kernel/fut_mm.h` | [6](PROCESS_MANAGEMENT.md#6-memory-management) |

### By Topic

| Topic | Location | Length |
|-------|----------|--------|
| Task creation | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#task-creation-and-destruction) | 2 functions |
| Thread creation | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#thread-creation) | Complete lifecycle |
| Process cloning (fork) | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#3-fork-syscall) | Full implementation |
| Copy-on-Write (CoW) | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#memory-cloning-strategy-copy-on-write-cow) | Detailed mechanism |
| ELF format parsing | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#1-elf-header-validation) | Header validation |
| Segment mapping | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#4-segment-mapping) | Complete walkthrough |
| User stack setup | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#7-build-user-stack) | With diagrams |
| Address space switching | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#mm-switching) | CR3/TTBR0_EL1 |
| x86-64 context | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#x86-64-context-platformx86_64regsh) | Full structure |
| ARM64 context | [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md#arm64-context-platformarm64regsh) | Full structure |

---

## Key Concepts

### 1. Process Model
- **Task** = Process container with independent address space
- **Thread** = Execution unit within a task (can have multiple per task)
- **PID** = 64-bit process identifier
- **TID** = 64-bit thread identifier

### 2. Memory Model
- **Per-task memory context** (fut_mm_t) with independent page tables
- **Copy-on-Write (CoW)** for efficient fork() implementation
- **Virtual Memory Areas (VMAs)** for tracking mapped regions
- **Heap** managed via sys_brk()

### 3. Process Creation
```
fork()     → Duplicates task + thread (with CoW memory sharing)
execve()   → Replaces task's memory with new ELF binary (preserves FDs)
```

### 4. Execution Model
- **Cooperative scheduling** (no preemption)
- **Priority-based scheduling** (0-255, higher = higher)
- **Wait queues** for blocking operations
- **Per-CPU affinity** support

---

## Common Tasks

### Understanding Fork

1. Read [Quick Reference: Process Creation Flow](PROCESS_MANAGEMENT_QUICK_REF.md#process-creation-flow)
2. Read [PROCESS_MANAGEMENT.md Section 3: Fork Syscall](PROCESS_MANAGEMENT.md#3-fork-syscall)
3. Reference implementation: `kernel/sys_fork.c`

### Understanding Execve

1. Read [Quick Reference: ELF Loading Flow](PROCESS_MANAGEMENT_QUICK_REF.md#elf-loading-flow)
2. Read [PROCESS_MANAGEMENT.md Section 4-5: Execve and ELF Loading](PROCESS_MANAGEMENT.md#4-execve-syscall)
3. Reference implementation: `kernel/sys_execve.c` and `kernel/exec/elf64.c`

### Understanding Memory Management

1. Read [Quick Reference: Address Space Regions](PROCESS_MANAGEMENT_QUICK_REF.md#address-space-regions-x86-64)
2. Read [PROCESS_MANAGEMENT.md Section 6: Memory Management](PROCESS_MANAGEMENT.md#6-memory-management)
3. Reference implementation: `kernel/memory/fut_mm.c`

### Creating a New Task with Thread

See [Quick Reference: Common Patterns](PROCESS_MANAGEMENT_QUICK_REF.md#common-patterns)

---

## Syscall Summary

| Syscall | Number | File | Returns |
|---------|--------|------|---------|
| `fork()` | 57 | `kernel/sys_fork.c` | Parent: child PID, Child: 0 |
| `execve()` | 59 | `kernel/sys_execve.c` | Never (on success) or -errno |
| `exit()` | 60 | (via exit_current) | Never returns |
| `waitpid()` | 61 | (via waitpid) | Child PID or -ECHILD |
| `kill()` | 62 | (signal handling) | Status |

---

## Architecture Support

### x86-64 (Primary)
- **Status**: Fully implemented
- **ELF Loader**: `kernel/exec/elf64.c` (x86-64 section)
- **Context**: `platform/x86_64/regs.h`
- **User Entry**: IRETQ instruction
- **Bootstrap**: Boot via GRUB with Multiboot2

### ARM64 (Experimental)
- **Status**: Scaffolding present, not tested
- **ELF Loader**: `kernel/exec/elf64.c` (ARM64 section)
- **Context**: `platform/arm64/regs.h`
- **User Entry**: ERET instruction
- **Notes**: Requires cross-compiler, no real hardware testing yet

---

## Testing and Debugging

### Building
```bash
make kernel              # Build kernel
make test                # Build ISO and boot with GRUB
make iso                 # Build ISO only
```

### Debug Output
```bash
make CFLAGS+=-DEBUG_VFS kernel    # Enable VFS debugging
# Check for [EXEC] and [FORK] prefixed messages in output
```

### Key Log Prefixes
- `[EXEC]` - ELF loading progress
- `[FORK]` - Process cloning
- `[MM-*]` - Memory management
- `[TASK]` - Task operations
- `[THREAD]` - Thread operations

---

## Known Limitations

1. **CoW Page Fault Handler Not Implemented**
   - Pages marked read-only but write handler not attached
   - Fallback to full copy if VMAs not tracked

2. **Signal Delivery Incomplete**
   - Signal handlers stored but not invoked
   - Pending signals tracked but not checked

3. **VMA Tracking Optional**
   - Fork falls back to fixed-range scanning
   - sys_mmap/munmap don't create/remove VMAs yet

4. **ARM64 Not Production Ready**
   - ELF loader exists but not fully tested
   - Requires dedicated hardware or complete ARM64 QEMU setup

5. **Real-Time Features Partial**
   - Priority inheritance structure present
   - Deadline scheduling partial

---

## File Cross-Reference

### Header Files
- `/home/k/futura/include/kernel/fut_task.h` - Task structures and API
- `/home/k/futura/include/kernel/fut_thread.h` - Thread structures and API
- `/home/k/futura/include/kernel/fut_mm.h` - Memory management API
- `/home/k/futura/include/kernel/exec.h` - ELF loading API
- `/home/k/futura/include/kernel/syscalls.h` - Syscall declarations

### Implementation Files
- `/home/k/futura/kernel/threading/fut_task.c` - Task implementation (398 lines)
- `/home/k/futura/kernel/threading/fut_thread.c` - Thread implementation (600+ lines)
- `/home/k/futura/kernel/sys_fork.c` - Fork syscall (450+ lines)
- `/home/k/futura/kernel/sys_execve.c` - Execve syscall (83 lines)
- `/home/k/futura/kernel/exec/elf64.c` - ELF loader (1389 lines)
- `/home/k/futura/kernel/memory/fut_mm.c` - MM implementation (600+ lines)

### Syscall Number Definition
- `/home/k/futura/include/user/sysnums.h` - Syscall numbers

---

## Next Steps

### For Understanding the System
1. Start with [Quick Reference](PROCESS_MANAGEMENT_QUICK_REF.md)
2. Read [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md) for detailed information
3. Examine source files referenced in the documentation

### For Implementation
1. Review the relevant section in [PROCESS_MANAGEMENT.md](PROCESS_MANAGEMENT.md)
2. Check [Quick Reference: Common Patterns](PROCESS_MANAGEMENT_QUICK_REF.md#common-patterns)
3. Reference the actual source code files

### For Testing
1. Build with `make test`
2. Look for `[EXEC]` and `[FORK]` log messages
3. Use debug flags: `make CFLAGS+=-DEBUG_VFS kernel`

---

## Documentation Statistics

| Document | Lines | Size | Sections |
|----------|-------|------|----------|
| PROCESS_MANAGEMENT.md | 1,417 | 39 KB | 11 major + subsections |
| PROCESS_MANAGEMENT_QUICK_REF.md | 313 | 9.8 KB | 12 major sections |
| KERNEL_STRUCTURE_OVERVIEW.md | This file | - | Navigation guide |
| **Total** | **~1,730** | **~49 KB** | **Comprehensive** |

---

## Contacts and References

See `CLAUDE.md` in repository root for:
- Build system details
- Testing procedures
- Performance benchmarking
- Release pipeline
- Contributing guidelines


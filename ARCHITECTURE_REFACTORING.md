# Futura OS Multi-Platform Architecture Refactoring

## Design Overview

### Principle: Separation of Concerns
- **Platform code** (`/platform/{arm64,x86_64}`): Low-level boot, initialization, and platform-specific features
- **Architecture-specific kernel code** (`/kernel/arch/{arm64,x86_64}`): Architecture-specific kernel implementations
- **Hardware Abstraction Layer** (`/kernel/hal`): Platform-independent interfaces for architecture-specific operations
- **Core kernel code** (`/kernel/core`): Platform-independent generic kernel subsystems

### Directory Structure

```
futura/
├── platform/                          # Low-level platform code
│   ├── arm64/                        # ARM64 boot, linker, platform init
│   │   ├── boot.S                    # ARM64 bootloader
│   │   ├── link.ld                   # ARM64 linker script
│   │   ├── platform_init.c           # ARM64 platform initialization
│   │   ├── context_switch.S          # ARM64 context switching
│   │   └── ...
│   └── x86_64/                       # x86-64 boot, linker, platform init
│       ├── boot.S                    # x86-64 bootloader
│       ├── link.ld                   # x86-64 linker script
│       ├── platform_init.c           # x86-64 platform initialization
│       ├── gdt.c, gdt_idt.S          # GDT and IDT setup
│       ├── context_switch.S          # x86-64 context switching
│       └── ...
│
├── kernel/                            # Kernel code
│   ├── core/                          # Platform-independent generic code
│   │   ├── scheduler/                 # Task scheduling (no arch-specific code)
│   │   ├── threading/                 # Thread management (no arch-specific code)
│   │   ├── memory/                    # Generic memory management
│   │   │   ├── buddy_allocator.c
│   │   │   ├── slab_allocator.c
│   │   │   └── ...
│   │   ├── vfs/                       # Virtual file system
│   │   ├── ipc/                       # Inter-process communication
│   │   ├── syscalls/                  # Generic syscall implementations
│   │   ├── network/                   # Network stack
│   │   └── ...
│   │
│   ├── arch/                          # Architecture-specific kernel code
│   │   ├── x86_64/                    # x86-64 specific kernel code
│   │   │   ├── exec/
│   │   │   │   └── elf64.c            # ELF64 loader (x86-64 specific)
│   │   │   ├── interrupts/
│   │   │   │   └── fut_idt.c          # IDT management (x86-64 specific)
│   │   │   ├── memory/
│   │   │   │   └── fut_mm.c           # x86-64 specific MM (if any)
│   │   │   └── ...
│   │   │
│   │   └── arm64/                     # ARM64 specific kernel code
│   │       ├── exec/
│   │       │   └── elf64.c (ARM64)    # ARM64 ELF64 loader
│   │       ├── interrupts/
│   │       │   └── gic.c              # ARM Generic Interrupt Controller
│   │       └── ...
│   │
│   ├── hal/                           # Hardware Abstraction Layer
│   │   ├── halt.h                     # CPU halt/sleep abstraction
│   │   ├── interrupts.h               # Interrupt enable/disable
│   │   ├── context.h                  # Context switching interface
│   │   ├── timer.h                    # Timer interface
│   │   ├── io_ports.h                 # Port I/O abstraction (x86-64)
│   │   ├── exceptions.h               # Exception handling
│   │   └── ...
│   │
│   └── include/                       # Kernel headers
```

### Files to Move

#### x86-64 Specific Code → `kernel/arch/x86_64/`
- `kernel/exec/elf64.c` → `kernel/arch/x86_64/exec/elf64.c`
- `kernel/interrupts/fut_idt.c` → `kernel/arch/x86_64/interrupts/fut_idt.c`
- `kernel/memory/fut_mm.c` (partially) → `kernel/arch/x86_64/memory/`
- Architecture-specific portions of scheduling, threading

#### ARM64 Specific Code → `kernel/arch/arm64/`
- ARM64-specific exception handling
- ARM64-specific GIC interrupt controller
- ARM64-specific context switching (from platform/arm64/context_switch.S)

#### Platform-Independent → `kernel/core/`
- Scheduler (fut_sched.c, fut_stats.c, fut_waitq.c)
- Threading (fut_task.c, fut_thread.c)
- Memory allocators (buddy_allocator.c, slab_allocator.c)
- VFS (fut_vfs.c, ramfs.c, devfs.c)
- IPC (fut_object.c, fut_fipc.c)
- Syscalls (sys_*.c files)
- Network stack
- Generic drivers

### Hardware Abstraction Layer (HAL) Interfaces

#### `kernel/hal/halt.h`
```c
// CPU halt/wait-for-interrupt abstraction
void hal_cpu_halt(void);      // x86-64: hlt, ARM64: wfi
void hal_cpu_wait_intr(void); // x86-64: sti;hlt, ARM64: msr daifset,#2; wfi
```

#### `kernel/hal/interrupts.h`
```c
// Interrupt enable/disable abstraction
void hal_intr_enable(void);   // x86-64: sti, ARM64: msr daifset,#2
void hal_intr_disable(void);  // x86-64: cli, ARM64: msr daifclr,#2
```

#### `kernel/hal/context.h`
```c
// Context switching abstraction
void hal_context_switch(struct context *from, struct context *to);
```

### Build System Changes

1. Makefile detects target architecture via `ARCH` variable or `cross_compile` prefix
2. Each architecture has its own subdirectory with architecture-specific build rules
3. Conditional compilation for kernel/arch/{arm64,x86_64} based on target
4. HAL interfaces compiled for specific architecture

### Migration Strategy

**Phase 1**: Identify and categorize (DONE)
- Analyze all kernel files
- Categorize as architecture-specific or generic
- Identify which #ifdef statements can be removed

**Phase 2**: Consolidate (IN PROGRESS)
- Move architecture-specific files to kernel/arch/{arm64,x86_64}/
- Create HAL interface headers
- Implement HAL for x86-64 and ARM64

**Phase 3**: Cleanup
- Remove scattered #ifdef statements
- Update Makefile for clean architecture support
- Test x86-64 build
- Test ARM64 build

### Benefits

1. **Cleaner codebase**: No scattered #ifdef statements throughout generic code
2. **Easier maintenance**: Architecture-specific code is self-contained
3. **Better scalability**: Adding new architecture is just adding new directory
4. **Clear interfaces**: HAL defines clean separation between generic and specific code
5. **Build system clarity**: Easy to see what's compiled for each architecture

### Backward Compatibility

- Platform code (`/platform/{arm64,x86_64}`) remains largely unchanged
- Core kernel code migrated to `/kernel/core/` for clarity
- Architecture-specific kernel code consolidated in `/kernel/arch/`
- All existing include paths updated accordingly

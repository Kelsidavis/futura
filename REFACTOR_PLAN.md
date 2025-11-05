# Platform Main Routine Consolidation Plan

## Goal
Make ARM64 follow the same initialization pattern as x86_64, eliminating code duplication and ensuring consistent behavior across architectures.

## Current State

### x86_64 (Good Pattern)
```
platform/x86_64/platform_init.c
  └─> arch_early_init()      // Serial, PIC, APIC, GDT, IDT
  └─> fut_kernel_main()      // Shared kernel init (kernel/kernel_main.c)
      ├─> PMM init
      ├─> Heap init
      ├─> Timer subsystem
      ├─> VFS init
      ├─> Network init
      ├─> Scheduler init
      ├─> Threading init
      └─> Launch init/shell
```

### ARM64 (Needs Refactoring)
```
platform/arm64/kernel_main.c
  └─> fut_kernel_main()      // DUPLICATE implementation
      ├─> PMM init           // Duplicates kernel/kernel_main.c
      ├─> Heap init          // Duplicates kernel/kernel_main.c
      ├─> Scheduler init     // Duplicates kernel/kernel_main.c
      ├─> Threading init     // Duplicates kernel/kernel_main.c
      └─> Custom EL0 test    // Platform-specific, should be in callback

PROBLEM: Skips VFS, network, tests that x86_64 runs!
```

## Refactoring Strategy

### Step 1: Rename ARM64 Main
Rename `platform/arm64/kernel_main.c` → `platform/arm64/platform_init.c`
Rename `fut_kernel_main()` → `arm64_platform_init()`

### Step 2: Create Platform Init Hook Pattern
Add to `kernel/kernel_main.c`:
```c
/* Weak symbol - platforms can override */
__attribute__((weak)) void arch_late_init(void) {
    /* Default: do nothing */
}
```

### Step 3: ARM64 Platform Init
```c
// platform/arm64/platform_init.c

void arm64_platform_init(void) {
    fut_serial_puts("[ARM64] Platform initialization...\n");

    /* Platform-specific early init */
    check_exception_level();
    init_gic();              // ARM64 interrupt controller
    init_generic_timer();    // ARM64 timer

    /* Call shared kernel initialization */
    fut_kernel_main();       // From kernel/kernel_main.c

    /* Should not reach here */
    while (1) __asm__ volatile("wfi");
}

/* Platform late init hook - called after scheduler/VFS ready */
void arch_late_init(void) {
    fut_serial_puts("[ARM64] Late initialization...\n");

    /* Spawn init from embedded binary */
    spawn_embedded_init();

    /* Fallback to EL0 test if init fails */
    test_el0_transition();
}
```

### Step 4: Extract Platform-Specific Memory Config
Create `arch_memory_config()` callback:

```c
// platform/arm64/platform_init.c
void arch_memory_config(uintptr_t *ram_start, uintptr_t *ram_end) {
    *ram_start = 0x40800000;  // After kernel/stack
    *ram_end   = 0x48000000;  // 120MB
}

// platform/x86_64/platform_init.c
void arch_memory_config(uintptr_t *ram_start, uintptr_t *ram_end) {
    *ram_start = calculate_kernel_end();
    *ram_end   = *ram_start + TOTAL_MEMORY_SIZE;
}
```

### Step 5: Unified Kernel Main
Modify `kernel/kernel_main.c` to use platform hooks:

```c
void fut_kernel_main(void) {
    /* Get platform-specific memory layout */
    uintptr_t ram_start, ram_end;
    arch_memory_config(&ram_start, &ram_end);

    /* Common initialization */
    fut_pmm_init(ram_end - ram_start, ram_start);
    fut_heap_init(heap_start, heap_end);
    fut_timer_subsystem_init();
    fut_vfs_init();              // Now ARM64 gets VFS!
    fut_network_init();          // Now ARM64 gets networking!
    fut_sched_init();
    fut_thread_subsystem_init();

    /* Platform late initialization hook */
    arch_late_init();            // ARM64 spawns init here

    /* Drop to idle loop */
    kernel_idle_loop();
}
```

## Benefits

1. **Single source of truth**: One init sequence in `kernel/kernel_main.c`
2. **Consistent behavior**: Both platforms get VFS, networking, all subsystems
3. **Easy maintenance**: Changes to init order happen in one place
4. **Clear separation**: Platform-specific in `platform/`, shared in `kernel/`
5. **Flexible hooks**: Platforms can inject custom logic via callbacks

## File Changes

### Delete/Rename
- `platform/arm64/kernel_main.c` → `platform/arm64/platform_init.c`

### Modify
- `platform/arm64/platform_init.c` - Extract platform-specific code
- `kernel/kernel_main.c` - Add platform hook calls
- `platform/x86_64/platform_init.c` - Add memory config hook

### New Files (Optional)
- `include/kernel/platform_hooks.h` - Document callback API

## Migration Path

1. **Phase 1** (Safe): Keep both implementations, add hooks
2. **Phase 2**: Move ARM64-specific code to callbacks
3. **Phase 3**: Delete duplicated code from ARM64
4. **Phase 4**: Test both platforms boot identically

## Testing

- [ ] x86_64 boots normally (no regression)
- [ ] ARM64 boots and reaches same subsystems as x86_64
- [ ] ARM64 still spawns init correctly
- [ ] Both platforms run VFS tests
- [ ] Both platforms run network tests

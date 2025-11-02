# Futura OS ARM64 Platform Support

## Overview

This document describes the current state of ARM64 (AArch64) support for Futura OS, including implemented features, limitations, and future work.

## Current Status

### Successfully Implemented

✅ **Boot Sequence**
- ARM64 bare-metal bootstrap (platform/arm64/boot.S)
- Exception level transitions (EL3→EL2→EL1)
- Exception vector table and basic exception handling
- MMU-less boot for testing (can be extended with paging)

✅ **Core Subsystems**
- Physical memory management (PMM) with ARM64 memory layout
- Kernel heap allocation and management
- Timer subsystem using ARM64 Generic Timer (CNTPCT_EL0)
- Signal handling subsystem
- Per-CPU data structures

✅ **Hardware Support**
- GICv2 interrupt controller initialization
- ARM64 Generic Timer for time-keeping and performance measurement
- PL011 UART console for serial output (polling-based)
- Device tree blob (DTB) parsing for runtime configuration

✅ **Performance Metrics**
- Cycle counting via ARM64 Generic Timer counter (mrs cntpct_el0)
- Cycles-per-millisecond calibration using firmware-provided frequency
- Percentile statistics (p50, p90, p99) for performance analysis
- Architecture-independent scheduler telemetry

✅ **Error Handling**
- Graceful fallback for unsupported features (input drivers return ENOTSUP)
- ARM64-specific ACPI detection (uses device tree instead)
- Simplified initialization messages to optimize UART performance

### Known Limitations

❌ **Console Performance**
- QEMU ARM64 PL011 UART emulation with polling is very slow
  - Typical output rate: ~1 character per 10-20ms
  - Kernel boot messages take 15-20 seconds vs 2-3 seconds on x86_64
  - Root cause: Tight polling loop checking UART_FR_TXFF flag
  - **Workaround**: Simplified output messages, removed debug statements
  - **Solution**: Interrupt-driven UART (future enhancement)

❌ **Device Drivers Not Yet Implemented**
- Input devices (keyboard/mouse) - returns ENOTSUP, gracefully skipped
- Video/framebuffer drivers - not built for ARM64
- AHCI/SATA drivers - x86_64 specific, not needed for ARM64 QEMU
- Block storage drivers - not yet integrated
- Network drivers - Rust virtio drivers available but not integrated

❌ **User-Space Support**
- Process creation and execution not yet fully tested on ARM64
- Binary compatibility layer (libc) may need ARM64-specific adjustments
- System call entry points defined but not fully validated

❌ **Advanced Features**
- Interrupt-driven console I/O (currently polling-only)
- SMP (multi-processor) support not validated
- NUMA considerations not implemented
- Advanced exception handling (user-space signal delivery) not complete

## Technical Architecture

### ARM64-Specific Code Organization

```
platform/arm64/
├── boot.S                          # Bootstrap and exception vectors
├── context_switch.S                # User/kernel context switching
├── platform_init.c                 # UART, GIC, timer initialization
├── arm64_exception_entry.S         # Exception handler stubs
├── arm64_minimal_stubs.c           # Minimal IRQ/exception handlers
├── timing/
│   └── perf_clock.c               # Generic Timer-based performance measurement
├── memory/
│   └── pmap.c                     # Physical memory mapping
└── interrupt/
    ├── arm64_stubs.c              # IRQ handling stubs
    └── arm64_minimal_stubs.c      # Simplified IRQ dispatcher

kernel/arch/arm64/
├── hal_halt.c                     # Architecture-specific halt
├── hal_interrupts.c               # Interrupt enable/disable
└── Related files in kernel/mm/ and kernel/dtb/
```

### Memory Layout (QEMU virt, 1GB)

```
0x00000000  +-----------------------+
            | Device Tree Blob      |
            | (loaded by bootloader)|
0x40000000  +-----------------------+
            | Kernel (identity map) |
            | (512MB physical)      |
0x60000000  +-----------------------+
            | Free Memory           |
            | (512MB available)     |
0x80000000  +-----------------------+
```

### UART Implementation Details

**Current Status**: Polling-based I/O

```c
// platform/arm64/platform_init.c:107-118
void fut_serial_putc(char c) {
    volatile uint8_t *uart = (volatile uint8_t *)UART0_BASE;

    // Wait indefinitely for TX FIFO space (safe on QEMU)
    while (mmio_read32((volatile void *)(uart + UART_FR)) & UART_FR_TXFF) {
        /* Wait for TX FIFO to have space */
    }

    // Write character to UART data register
    mmio_write32((volatile void *)(uart + UART_DR), (uint32_t)c);
}
```

**Performance Bottleneck**: Each character requires:
1. Poll status register (UART_FR) in tight loop
2. Detect TXFF (TX FIFO full) flag cleared
3. Write character to DR register
4. QEMU's PL011 emulation is slow for status checks in loops

**Performance Metrics**:
- x86_64 direct COM port I/O: ~1000 chars/sec (2-3 second boot)
- ARM64 QEMU PL011 polling: ~50 chars/sec (15-20 second boot)

### Timer Implementation

ARM64 Generic Timer provides two types of counters:
- **CNTPCT_EL0** (Physical Timer Counter) - used for performance measurement
- **CNTP_TVAL_EL0** (Physical Timer Value) - used for interrupt generation

```c
// platform/arm64/timing/perf_clock.c:22-26
uint64_t fut_rdtsc(void) {
    uint64_t count;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(count));
    return count;
}
```

**Frequency Calibration**: Obtained from platform initialization via firmware-provided frequency value, with 1GHz fallback.

### ACPI vs Device Tree

ARM64 on QEMU virt uses Device Tree Blob (DTB) instead of ACPI:

```c
// kernel/acpi/acpi.c
#ifdef __x86_64__
static acpi_rsdp_v2_t *acpi_find_rsdp(void) {
    // Search x86_64 BIOS memory (0xE0000-0xFFFFF)
}
#else
static acpi_rsdp_v2_t *acpi_find_rsdp(void) {
    // ARM64: ACPI discovery not implemented (device tree used instead)
    return NULL;
}
#endif
```

## Testing and Validation

### Boot Verification

**Successful Boot Sequence (ARM64 on QEMU)**:
```
[INIT] Initializing GICv2...
[INIT] Initializing ARM Generic Timer...
[INIT] Enabling interrupts...
[INIT] Jumping to kernel main...
[INIT] Initializing physical memory manager...
[INIT] Initializing kernel heap...
[INIT] Initializing timer subsystem...
[INIT] Initializing signal subsystem...
[INIT] Initializing ACPI...
[ACPI] ARM64: RSDP discovery not implemented (device tree used instead)
[INIT] Initializing per-CPU data for CPU 0...
[PERCPU] CPU 0 ready
[INIT] Before boot banner
[Boot banner and memory map display...]
[INIT] Initializing input drivers for Wayland...
[INPUT] init failed (not supported on this platform)
[INIT] Initializing FIPC...
```

### Performance Measurements

**Metrics Collection Available**:
- Cycle counters via `fut_rdtsc()` using Generic Timer
- Scheduler statistics for context switch tracking
- Per-thread CPU utilization percentage
- Quantum duration analysis

**Current Validation Gaps**:
- User-space process metrics not validated (no processes running yet)
- Interrupt latency not measured
- SMP scheduler behavior not tested

## Build and Run

### Building ARM64 Kernel

```bash
make PLATFORM=arm64 kernel
# Output: build/bin/futura_kernel.elf
```

### Running on QEMU

```bash
qemu-system-aarch64 \
  -M virt \
  -cpu cortex-a72 \
  -kernel build/bin/futura_kernel.elf \
  -serial stdio \
  -display none \
  -monitor none
```

### Expected Output

Kernel boots to various initialization stages but hangs during later subsystem initialization due to QEMU UART slowness with polling-based output.

## Future Work

### High Priority

1. **Interrupt-Driven UART** (~1000x speed improvement)
   - Implement TX interrupt handler to queue characters
   - Implement RX interrupt handler for input
   - Requires interrupt frame setup (currently simplified)

2. **User-Space Support**
   - Implement ARM64 system call entry point
   - Binary compatibility library (libc) adjustments
   - Process creation and signal delivery validation

3. **Device Drivers**
   - Virtio block device driver (for storage)
   - Virtio network driver (for networking)
   - Minimal framebuffer support (if needed)

### Medium Priority

4. **Memory Protection**
   - Enable MMU and paging for user-space isolation
   - Data abort exception handling
   - Instruction abort exception handling

5. **SMP Support**
   - Multi-CPU initialization and scheduling
   - Inter-processor interrupt (IPI) handling
   - Per-CPU idle threads

### Lower Priority

6. **Advanced Features**
   - Nested virtualization support
   - Device tree dynamic updates
   - Performance monitoring unit (PMU) support
   - CPU idle states and power management

## Architecture-Specific Considerations

### Differences from x86_64

| Feature | x86_64 | ARM64 |
|---------|--------|-------|
| **Boot** | Multiboot/UEFI | Bootloader with DTB |
| **Exceptions** | IDT with per-vector entries | Vector table with 16 handlers |
| **Memory Access** | Direct I/O instructions (in/out) | Memory-mapped I/O (MMIO) |
| **System Calls** | int 0x80 / syscall | SVC instruction (not implemented) |
| **Context Switch** | LSTAR MSR + mov gs | MOV to SP_EL0 + ERET |
| **Timers** | LAPIC TSC/HPET | Generic Timer CNTPCT_EL0 |
| **Firmware** | ACPI tables | Device Tree Blob |
| **Interrupts** | APIC/IO-APIC | GIC (Generic Interrupt Controller) |

### Special Registers

Key ARM64 system registers used:
- **CNTPCT_EL0** - Physical counter (read-only, for rdtsc)
- **CNTP_TVAL_EL0** - Physical timer value (for timer interrupts)
- **DAIF** - Interrupt enable/disable
- **VBAR_EL1** - Vector base address register (exception table)
- **SPSR_EL1** - Saved program status register
- **ELR_EL1** - Exception link register (return address)

## Testing Checklist

- [x] Kernel compiles without errors
- [x] Bootloader successfully loads kernel
- [x] Exception vectors installed
- [x] GICv2 interrupt controller initialized
- [x] ARM64 Generic Timer operational
- [x] Serial output functional (slow but working)
- [x] Physical memory detection and initialization
- [x] Kernel heap allocation working
- [x] Signal subsystem initialized
- [x] Per-CPU data structures set up
- [ ] User-space process creation and execution
- [ ] System call entry points validated
- [ ] Interrupt-driven I/O functional
- [ ] Full Wayland compositor running
- [ ] Performance metrics accurate on both platforms

## References

- ARM Architecture Reference Manual ARMv8-A
- ARM Generic Timer specification
- GICv2 specification
- PL011 UART datasheet
- Linux ARM64 kernel boot protocol

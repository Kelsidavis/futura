/* rpi_boot.h - Raspberry Pi Boot Configuration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Boot parameters and configuration for Raspberry Pi platforms.
 * Defines memory layout, DTB location, and boot protocol details.
 */

#ifndef __FUTURA_ARM64_RPI_BOOT_H__
#define __FUTURA_ARM64_RPI_BOOT_H__

#include <stdint.h>

/* ============================================================
 *   ARM64 Boot Protocol (EBBR - Embedded Base Boot Requirements)
 * ============================================================
 *
 * Raspberry Pi firmware follows EBBR for AArch64 boot:
 * - X0: Physical address of device tree blob (DTB)
 * - X1-X3: Reserved, must be 0
 * - SPSR_EL1: EL1 PSR value (mode=EL1, DAIF=0xF for early boot)
 * - ELR_EL1: Entry point (kernel_main address)
 * - SP_EL1: Stack pointer (initialized by bootloader)
 */

/* Boot mode definitions */
#define BOOT_MODE_EL1 0  /* EL1 mode (standard) */
#define BOOT_MODE_EL2 1  /* EL2 mode (hypervisor) - not typical for RPi */

/* Memory layout for different RPi models */
#define RPi_RAM_BASE 0x00000000

#ifdef CONFIG_RPI3
    #define RPi_RAM_SIZE 0x40000000         /* 1 GB */
    #define RPi_KERNEL_BASE 0x80000        /* Loaded at 512 KB by firmware */
    #define RPi_DTB_OFFSET 0x20000000       /* DTB at 512 MB by convention */
#elif defined(CONFIG_RPI4)
    #define RPi_RAM_SIZE 0x100000000        /* 1-4 GB (configurable) */
    #define RPi_KERNEL_BASE 0x80000        /* Can be loaded higher on RPi4 */
    #define RPi_DTB_OFFSET 0x100            /* Often at low offset by new firmware */
#elif defined(CONFIG_RPI5)
    #define RPi_RAM_SIZE 0x100000000        /* 4-8 GB */
    #define RPi_KERNEL_BASE 0x80000        /* Modern firmware uses higher addresses */
    #define RPi_DTB_OFFSET 0x100            /* DTB at fixed offset */
#else
    /* Generic ARM64 defaults */
    #define RPi_RAM_SIZE 0x100000000        /* 4 GB default */
    #define RPi_KERNEL_BASE 0x80000
    #define RPi_DTB_OFFSET 0x100
#endif

/* Interrupt enable/disable macros for early boot */
#define DAIF_INT_DISABLE (0xF << 6)  /* Disable IRQ, FIQ, SError, Debug */
#define DAIF_INT_ENABLE (0x0 << 6)   /* Enable interrupts */

/* ============================================================
 *   Early Boot State Structure
 * ============================================================
 *
 * This structure captures the state passed to kernel_main
 * by the bootloader. It's preserved in registers and memory.
 */

typedef struct {
    uint64_t dtb_addr;          /* X0: Device Tree Blob physical address */
    uint64_t kernel_base;       /* Kernel load address */
    uint64_t boot_mode;         /* EL1 or EL2 */
    uint32_t boot_hart;         /* Which CPU is booting (hart ID) */
} boot_state_t;

/* ============================================================
 *   QEMU RPi Machine Emulation Parameters
 * ============================================================
 *
 * For testing on QEMU before hardware deployment:
 *
 * QEMU Raspberry Pi 3 emulation:
 *   qemu-system-aarch64 -M raspi3b -kernel kernel.elf -dtb rpi3.dtb
 *
 * QEMU Raspberry Pi 4 emulation:
 *   qemu-system-aarch64 -M raspi4b -kernel kernel.elf -dtb rpi4.dtb
 *
 * Note: QEMU's RPi emulation has limited peripheral support.
 * Some devices may not be fully emulated.
 */

#define QEMU_RPI3_MACHINE "raspi3b"
#define QEMU_RPI4_MACHINE "raspi4b"

/* ============================================================
 *   Boot Sequence
 * ============================================================
 *
 * 1. Bootloader (firmware) initializes:
 *    - Clears exception tables
 *    - Initializes core registers
 *    - Loads kernel binary at 0x80000
 *    - Places DTB in memory (address in X0)
 *    - Sets up stack
 *
 * 2. Bootloader jumps to kernel_main with:
 *    - X0 = physical address of DTB
 *    - X1-X3 = 0
 *    - SP_EL1 = stack pointer
 *    - ELR_EL1 = kernel_main address
 *
 * 3. Kernel early boot (kernel_main in arch/arm64/boot.S):
 *    - Sets up exception handlers
 *    - Enables MMU (creates page tables)
 *    - Initializes platform (DTB parsing)
 *    - Jumps to kernel_init in C
 *
 * 4. Kernel initialization (kernel/init.c):
 *    - Initialize memory management
 *    - Initialize scheduling
 *    - Initialize filesystem
 *    - Start init process
 */

#endif /* __FUTURA_ARM64_RPI_BOOT_H__ */

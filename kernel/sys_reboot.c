/* kernel/sys_reboot.c - reboot() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements the Linux reboot(2) syscall for power-off, restart, and halt.
 * Uses ACPI shutdown on x86_64 and PSCI on ARM64.
 */

#include <kernel/fut_task.h>
#include <kernel/errno.h>
#include <kernel/kprintf.h>
#include <kernel/acpi.h>
#include <stdint.h>

/* Linux reboot magic numbers (must match exactly) */
#define LINUX_REBOOT_MAGIC1  0xfee1dead
#define LINUX_REBOOT_MAGIC2  672274793   /* 0x28121969 */
#define LINUX_REBOOT_MAGIC2A 85072278    /* 0x05121996 */
#define LINUX_REBOOT_MAGIC2B 369367448   /* 0x16041998 */
#define LINUX_REBOOT_MAGIC2C 537993216   /* 0x20112000 */

/* Linux reboot commands */
#define LINUX_REBOOT_CMD_RESTART    0x01234567
#define LINUX_REBOOT_CMD_HALT       0xCDEF0123
#define LINUX_REBOOT_CMD_POWER_OFF  0x4321FEDC
#define LINUX_REBOOT_CMD_RESTART2   0xA1B2C3D4

/* CAP_SYS_BOOT = 22 */
#define CAP_SYS_BOOT 22

/**
 * sys_reboot - Reboot, halt, or power off the system
 *
 * @param magic1  Must be LINUX_REBOOT_MAGIC1
 * @param magic2  Must be one of LINUX_REBOOT_MAGIC2[ABC]
 * @param cmd     Reboot command (RESTART, HALT, POWER_OFF, RESTART2)
 * @param arg     Unused (RESTART2 uses this for reboot string on Linux)
 *
 * Returns:
 *   Does not return on success (system reboots/halts/powers off)
 *   -EINVAL if magic numbers or command are invalid
 *   -EPERM  if caller lacks CAP_SYS_BOOT
 */
long sys_reboot(unsigned int magic1, unsigned int magic2,
                unsigned int cmd, void *arg) {
    (void)arg;

    /* Validate magic numbers */
    if (magic1 != LINUX_REBOOT_MAGIC1) {
        return -EINVAL;
    }
    if (magic2 != LINUX_REBOOT_MAGIC2 &&
        magic2 != LINUX_REBOOT_MAGIC2A &&
        magic2 != LINUX_REBOOT_MAGIC2B &&
        magic2 != LINUX_REBOOT_MAGIC2C) {
        return -EINVAL;
    }

    /* Check CAP_SYS_BOOT capability */
    fut_task_t *task = fut_task_current();
    if (task && !(task->cap_effective & (1ULL << CAP_SYS_BOOT))) {
        return -EPERM;
    }

    switch (cmd) {
        case LINUX_REBOOT_CMD_POWER_OFF:
            fut_printf("[REBOOT] Power off requested\n");
#ifdef __x86_64__
            acpi_shutdown();
            /* Fallback: QEMU debug exit */
            __asm__ volatile("outw %0, %1" :: "a"((uint16_t)0x2000), "Nd"((uint16_t)0x604));
#elif defined(__aarch64__)
            /* PSCI SYSTEM_OFF (0x84000008) */
            {
                register uint64_t x0 __asm__("x0") = 0x84000008ULL;
                __asm__ volatile("hvc #0" :: "r"(x0));
            }
#endif
            /* If we get here, shutdown failed */
            fut_printf("[REBOOT] Power off failed, halting CPU\n");
            for (;;) {
#ifdef __x86_64__
                __asm__ volatile("cli; hlt");
#elif defined(__aarch64__)
                __asm__ volatile("wfi");
#endif
            }

        case LINUX_REBOOT_CMD_HALT:
            fut_printf("[REBOOT] Halt requested\n");
            for (;;) {
#ifdef __x86_64__
                __asm__ volatile("cli; hlt");
#elif defined(__aarch64__)
                __asm__ volatile("wfi");
#endif
            }

        case LINUX_REBOOT_CMD_RESTART:
        case LINUX_REBOOT_CMD_RESTART2:
            fut_printf("[REBOOT] Restart requested\n");
#ifdef __x86_64__
            /* Triple fault via null IDT causes CPU reset */
            {
                struct { uint16_t limit; uint64_t base; } __attribute__((packed)) null_idt = {0, 0};
                __asm__ volatile("lidt %0; int3" :: "m"(null_idt));
            }
#elif defined(__aarch64__)
            /* PSCI SYSTEM_RESET (0x84000009) */
            {
                register uint64_t x0 __asm__("x0") = 0x84000009ULL;
                __asm__ volatile("hvc #0" :: "r"(x0));
            }
#endif
            /* Should not reach here */
            for (;;) {
#ifdef __x86_64__
                __asm__ volatile("cli; hlt");
#elif defined(__aarch64__)
                __asm__ volatile("wfi");
#endif
            }

        default:
            return -EINVAL;
    }
}

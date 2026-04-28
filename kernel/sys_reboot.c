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
#define LINUX_REBOOT_CMD_CAD_ON     0x89ABCDEF
#define LINUX_REBOOT_CMD_CAD_OFF    0x00000000
#define LINUX_REBOOT_CMD_POWER_OFF  0x4321FEDC
#define LINUX_REBOOT_CMD_RESTART2   0xA1B2C3D4
#define LINUX_REBOOT_CMD_SW_SUSPEND 0xD000FCE2
#define LINUX_REBOOT_CMD_KEXEC      0x45584543

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

    /* Linux's sys_reboot validates the capability FIRST, before the
     * magic numbers — 'if (!capable(CAP_SYS_BOOT)) return -EPERM' runs
     * before the magic1/magic2 checks. Without that ordering an
     * unprivileged caller probing the syscall sees EINVAL (bad
     * magic) instead of EPERM (insufficient privilege), which leaks
     * the magic-number protocol to userspace and inverts the libc
     * 'is the kernel willing to reboot?' probe pattern. Match Linux. */
    fut_task_t *task = fut_task_current();
    if (task && task->uid != 0 &&
        !(task->cap_effective & (1ULL << CAP_SYS_BOOT))) {
        return -EPERM;
    }

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

    /* Sync all filesystems before shutdown/reboot */
    {
        extern long sys_sync(void);
        fut_printf("[REBOOT] Syncing filesystems...\n");
        sys_sync();
        fut_printf("[REBOOT] Filesystems synced\n");
    }

    switch (cmd) {
        case LINUX_REBOOT_CMD_POWER_OFF:
            fut_printf("[REBOOT] System going down for power off NOW\n");
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
            fut_printf("[REBOOT] System going down for restart NOW\n");
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

        case LINUX_REBOOT_CMD_CAD_ON:
        case LINUX_REBOOT_CMD_CAD_OFF:
            /* Linux's sys_reboot accepts these to enable/disable
             * Ctrl-Alt-Del-as-reboot:
             *   case LINUX_REBOOT_CMD_CAD_ON:  C_A_D = 1; break;
             *   case LINUX_REBOOT_CMD_CAD_OFF: C_A_D = 0; break;
             * The previous Futura code returned EINVAL for these,
             * so init systems / sysctl wrappers that toggle the
             * Ctrl-Alt-Del policy at boot got a fatal error where
             * Linux just stores the bit.  Futura has no kbd-driven
             * reboot path, so accepting the call as a no-op preserves
             * the documented ABI without any behavioural change. */
            return 0;

        case LINUX_REBOOT_CMD_SW_SUSPEND:
        case LINUX_REBOOT_CMD_KEXEC:
            /* Linux returns ENOSYS when the corresponding feature
             * (CONFIG_HIBERNATION / CONFIG_KEXEC) isn't built.
             * Futura supports neither suspend/resume nor kexec, so
             * report ENOSYS rather than EINVAL — userspace probes
             * use the distinction to choose a fallback path. */
            return -ENOSYS;

        default:
            return -EINVAL;
    }
}

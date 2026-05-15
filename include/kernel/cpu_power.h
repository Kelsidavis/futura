// SPDX-License-Identifier: MPL-2.0
/*
 * include/kernel/cpu_power.h - CPU power-management policy API
 *
 * Platform-neutral interface for the kernel to apply optional power
 * policies that constrain the hardware's autonomous behaviour.  The
 * underlying mechanisms are CPU-vendor specific (Intel uses
 * MSR_PKG_CST_CONFIG_CONTROL / IA32_POWER_CTL; AMD uses different
 * MSRs; ARM uses PSCI / power domain controls) so each architecture
 * provides its own implementation in kernel/arch/<arch>/cpu_power.c.
 *
 * The functions here are opt-in only -- the universal kernel default
 * is to leave platform power management alone.  Callers (typically
 * kernel_main, gated by a boot cmdline flag like cstate_cap=) decide
 * whether to apply a cap.
 *
 * Return values:
 *    0          success, cap applied
 *   -ENOSYS    not implemented on this CPU/arch
 *   -EBUSY     firmware lock blocks the change (BIOS CFG_LOCK etc.)
 *   negative   other error
 */

#pragma once

/**
 * Cap the deepest C-state the CPU's power control unit is allowed to
 * enter autonomously.  Useful on Intel parts whose PCU transitions
 * cores into C3/C6 without software HLT and disables the LAPIC timer
 * in those states (Whiskey Lake on ThinkPad L490 is the canonical
 * example).
 *
 * Values: 0 = C0 only (busy), 1 = C1, 2 = C2, ...  Implementations
 * may silently round up to the closest supported value.
 */
int cpu_power_cap_cstates(unsigned int max_cstate);

/**
 * Disable C1E (Enhanced C1) so the CPU's "regular" C1 keeps the bus
 * clock running.  No-op or -ENOSYS on CPUs that don't have C1E.
 */
int cpu_power_disable_c1e(void);

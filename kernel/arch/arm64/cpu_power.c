// SPDX-License-Identifier: MPL-2.0
/*
 * kernel/arch/arm64/cpu_power.c - ARM64 stub for cpu_power_* API
 *
 * ARM64 power management goes through PSCI / SCMI and an entirely
 * different mental model from x86 C-states.  Not wiring it up here
 * yet -- return -ENOSYS so the caller knows the policy doesn't
 * apply on this platform.
 */

#include <kernel/cpu_power.h>
#include <kernel/errno.h>

int cpu_power_cap_cstates(unsigned int max_cstate) {
    (void)max_cstate;
    return -ENOSYS;
}

int cpu_power_disable_c1e(void) {
    return -ENOSYS;
}

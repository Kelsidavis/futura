/* smp.h - x86_64 SMP (Symmetric Multi-Processing) support
 *
 * Copyright (c) 2025 Futura OS
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * Initialize SMP and start all Application Processors.
 *
 * @param apic_ids Array of APIC IDs to start
 * @param num_cpus Number of CPUs in the array
 */
void smp_init(uint32_t *apic_ids, uint32_t num_cpus);

/**
 * Get total CPU count (BSP + APs).
 *
 * @return Number of online CPUs
 */
uint32_t smp_get_cpu_count(void);

/**
 * Check if a CPU is online.
 *
 * @param apic_id APIC ID of the CPU
 * @return true if online, false otherwise
 */
bool smp_is_cpu_online(uint32_t apic_id);

/**
 * AP entry point (called from trampoline).
 * DO NOT call this directly!
 *
 * @param apic_id APIC ID of this CPU
 */
void ap_main(uint32_t apic_id);

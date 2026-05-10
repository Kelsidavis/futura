// SPDX-License-Identifier: MPL-2.0
/*
 * pat.h - Page Attribute Table helpers
 */

#pragma once

#include <stdint.h>

/* PAT memory-type encodings — Intel SDM Vol. 3 Table 11-12.
 * Encodings 0x02 and 0x03 are RESERVED; writing them to MSR_IA32_PAT
 * (in any of the 8 entries) raises #GP. The previous PAT_MT_UC_MINUS
 * value of 0x03 silently triple-faulted on real hardware whenever
 * pat_init() ran before the IDT was loaded — QEMU's TCG happened to
 * accept the bad encoding, masking the bug in CI/dev. */
#define PAT_MT_UC       0x00u   /* Uncacheable (strong) */
#define PAT_MT_WC       0x01u   /* Write Combining */
#define PAT_MT_WT       0x04u   /* Write Through */
#define PAT_MT_WP       0x05u   /* Write Protected */
#define PAT_MT_WB       0x06u   /* Write Back */
#define PAT_MT_UC_MINUS 0x07u   /* Uncached (UC-) — weak uncacheable */

void pat_init(void);
uint64_t pat_choose_page_attr_wc(void);

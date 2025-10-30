// SPDX-License-Identifier: MPL-2.0
/*
 * pat.h - Page Attribute Table helpers
 */

#pragma once

#include <stdint.h>

#define PAT_MT_WB 0x06u
#define PAT_MT_WC 0x01u
#define PAT_MT_WT 0x04u
#define PAT_MT_UC_MINUS 0x03u
#define PAT_MT_UC 0x00u

void pat_init(void);
uint64_t pat_choose_page_attr_wc(void);

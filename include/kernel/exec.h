// SPDX-License-Identifier: MPL-2.0
/*
 * exec.h - User process loading interfaces
 */

#pragma once

#include <stddef.h>

struct fut_task;

int fut_exec_elf(const char *path, char *const argv[]);
int fut_stage_fbtest_binary(void);

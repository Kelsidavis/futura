// SPDX-License-Identifier: MPL-2.0
/*
 * exec.h - User process loading interfaces
 */

#pragma once

#include <stddef.h>

struct fut_task;

int fut_exec_elf(const char *path, char *const argv[], char *const envp[]);
int fut_stage_fbtest_binary(void);
int fut_stage_shell_binary(void);
int fut_stage_init_stub_binary(void);
int fut_stage_second_stub_binary(void);
int fut_stage_wayland_compositor_binary(void);
int fut_stage_wayland_client_binary(void);
int fut_stage_wl_term_binary(void);
int fut_stage_wayland_color_client_binary(void);

// SPDX-License-Identifier: MPL-2.0
/*
 * exec.h - User process loading interfaces
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides ELF binary execution and binary staging functions for boot-time
 * processes. The staging functions load embedded binaries into RAM for
 * immediate execution without requiring a filesystem.
 *
 * Execution model:
 *   - fut_exec_elf(): Loads ELF from filesystem, replaces current process
 *   - fut_stage_*(): Load embedded binaries for boot-time initialization
 *
 * Boot sequence typically uses staging functions to launch init and
 * essential services before the filesystem is fully available.
 */

#pragma once

#include <stddef.h>

struct fut_task;

/**
 * Execute an ELF binary, replacing the current process.
 *
 * Loads the ELF file from the given path into the current task's address
 * space and begins execution at the entry point. The current process image
 * is completely replaced (this function does not return on success).
 *
 * @param path  Path to the ELF executable
 * @param argv  Null-terminated argument array (argv[0] is program name)
 * @param envp  Null-terminated environment array
 * @return Negative errno on failure (does not return on success)
 */
int fut_exec_elf(const char *path, char *const argv[], char *const envp[]);

/* ============================================================
 *   Boot-time Binary Staging Functions
 *
 *   These functions load embedded binaries linked into the kernel
 *   image for boot-time process creation. They return 0 on success
 *   or negative errno on failure.
 * ============================================================ */

/** Stage framebuffer test program (fbtest) */
int fut_stage_fbtest_binary(void);

/** Stage the user shell binary */
int fut_stage_shell_binary(void);

/** Stage the init process (PID 1) */
int fut_stage_init_binary(void);

/** Stage secondary init helper */
int fut_stage_second_stub_binary(void);

/** Stage Wayland compositor (futurawayd) */
int fut_stage_wayland_compositor_binary(void);

/** Stage Wayland demo client */
int fut_stage_wayland_client_binary(void);

/** Stage Wayland terminal emulator */
int fut_stage_wl_term_binary(void);

/** Stage Wayland color wheel demo client */
int fut_stage_wayland_color_client_binary(void);

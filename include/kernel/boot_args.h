// SPDX-License-Identifier: MPL-2.0
/*
 * boot_args.h - Kernel boot command line argument parsing
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Provides helpers for parsing kernel command line arguments passed by
 * the bootloader (GRUB, direct boot, etc.). Supports both flag arguments
 * (e.g., "debug") and key=value arguments (e.g., "console=ttyS0").
 *
 * Usage:
 *   // During early boot, initialize with cmdline from bootloader
 *   fut_boot_args_init(multiboot_cmdline);
 *
 *   // Check for presence of a flag
 *   if (fut_boot_arg_flag("debug")) {
 *       enable_debug_mode();
 *   }
 *
 *   // Get value of a key=value argument
 *   const char *console = fut_boot_arg_value("console");
 *   if (console) {
 *       init_console(console);
 *   }
 */

#pragma once

#include <stdbool.h>

/**
 * Initialize boot argument parsing.
 *
 * Must be called early in boot with the command line string from the
 * bootloader. The string is copied internally, so the original can be
 * freed or overwritten after this call.
 *
 * @param cmdline  Null-terminated command line string (may be NULL)
 */
void fut_boot_args_init(const char *cmdline);

/**
 * Get the value of a key=value boot argument.
 *
 * @param key  Argument key to look for (e.g., "console")
 * @return Value string if found, NULL if not present
 *
 * Example:
 *   const char *root = fut_boot_arg_value("root");
 *   // For cmdline "root=/dev/sda1", returns "/dev/sda1"
 */
const char *fut_boot_arg_value(const char *key);

/**
 * Check if a flag argument is present.
 *
 * @param key  Flag name to check (e.g., "debug")
 * @return true if flag is present, false otherwise
 *
 * Example:
 *   if (fut_boot_arg_flag("nosmp")) {
 *       disable_smp();
 *   }
 */
bool fut_boot_arg_flag(const char *key);

/* boot_args.h - simple boot command line helpers */

#pragma once

#include <stdbool.h>

void fut_boot_args_init(const char *cmdline);
const char *fut_boot_arg_value(const char *key);
bool fut_boot_arg_flag(const char *key);

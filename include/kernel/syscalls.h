// SPDX-License-Identifier: MPL-2.0
/*
 * syscalls.h - Kernel syscall prototypes (Phase 1 scaffolding)
 *
 * Provides the minimal declarations needed to exercise newly added
 * uaccess helpers via a simple echo syscall.  Future work will expand
 * this table as the userland ABI stabilises.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

#define SYS_echo 42u

ssize_t sys_echo(const char *u_in, char *u_out, size_t n);

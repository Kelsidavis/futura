/* kernel/pty.h - Pseudo-terminal (PTY) subsystem interface
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct fut_file;

/* Initialize the PTY subsystem (/dev/ptmx + /dev/pts/) */
void pty_init(void);

/* Poll callback for sys_poll integration */
bool fut_pty_poll(struct fut_file *file, uint32_t requested, uint32_t *ready_out);

/* Epoll wakeup registration */
void fut_pty_set_epoll_notify(struct fut_file *file, void *wq);

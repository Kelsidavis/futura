/* kernel/debug_config.h - Centralized kernel debug configuration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * This header consolidates all kernel debug flags for easy management.
 * Set individual flags to 1 to enable verbose debug output for that subsystem.
 * By default all debug output is disabled (0) for production builds.
 *
 * Usage:
 *   #include <kernel/debug_config.h>
 *   #if SOCKET_DEBUG
 *       fut_printf("[SOCKET] Debug message...\n");
 *   #endif
 */

#pragma once

/* ============================================================================
 *   Master Debug Switch
 * ============================================================================
 *
 * Set KERNEL_DEBUG_ALL to 1 to enable ALL debug output (useful for debugging).
 * Individual flags below can still be overridden after this.
 */
#ifndef KERNEL_DEBUG_ALL
#define KERNEL_DEBUG_ALL 0
#endif

/* ============================================================================
 *   Syscall Debug Flags
 * ============================================================================ */

/* File operations */
#ifndef OPEN_DEBUG
#define OPEN_DEBUG      KERNEL_DEBUG_ALL
#endif

#ifndef CLOSE_DEBUG
#define CLOSE_DEBUG     KERNEL_DEBUG_ALL
#endif

#ifndef WRITE_DEBUG
#define WRITE_DEBUG     KERNEL_DEBUG_ALL
#endif

/* Process management */
#ifndef FORK_DEBUG
#define FORK_DEBUG      KERNEL_DEBUG_ALL
#endif

#ifndef EXIT_DEBUG
#define EXIT_DEBUG      KERNEL_DEBUG_ALL
#endif

#ifndef EXECVE_DEBUG
#define EXECVE_DEBUG    KERNEL_DEBUG_ALL
#endif

#ifndef BRK_DEBUG
#define BRK_DEBUG       KERNEL_DEBUG_ALL
#endif

/* ============================================================================
 *   Networking Debug Flags
 * ============================================================================ */

#ifndef SOCKET_DEBUG
#define SOCKET_DEBUG    KERNEL_DEBUG_ALL
#endif

#ifndef CONNECT_DEBUG
#define CONNECT_DEBUG   KERNEL_DEBUG_ALL
#endif

#ifndef BIND_DEBUG
#define BIND_DEBUG      KERNEL_DEBUG_ALL
#endif

#ifndef LISTEN_DEBUG
#define LISTEN_DEBUG    KERNEL_DEBUG_ALL
#endif

#ifndef ACCEPT_DEBUG
#define ACCEPT_DEBUG    KERNEL_DEBUG_ALL
#endif

#ifndef SENDMSG_DEBUG
#define SENDMSG_DEBUG   KERNEL_DEBUG_ALL
#endif

#ifndef RECVMSG_DEBUG
#define RECVMSG_DEBUG   KERNEL_DEBUG_ALL
#endif

/* ============================================================================
 *   I/O Multiplexing Debug Flags
 * ============================================================================ */

#ifndef POLL_DEBUG
#define POLL_DEBUG      KERNEL_DEBUG_ALL
#endif

#ifndef EPOLL_DEBUG
#define EPOLL_DEBUG     KERNEL_DEBUG_ALL
#endif

/* ============================================================================
 *   Memory Management Debug Flags
 * ============================================================================ */

#ifndef MM_CREATE_DEBUG
#define MM_CREATE_DEBUG KERNEL_DEBUG_ALL
#endif

#ifndef SLAB_DEBUG
#define SLAB_DEBUG      KERNEL_DEBUG_ALL
#endif

/* ============================================================================
 *   ELF Loader Debug Flags
 * ============================================================================ */

#ifndef ELF_DEBUG
#define ELF_DEBUG       KERNEL_DEBUG_ALL
#endif

#ifndef STACK_DEBUG
#define STACK_DEBUG     KERNEL_DEBUG_ALL
#endif

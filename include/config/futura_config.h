/* futura_config.h - Futura OS Kernel Configuration
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Unified configuration system for architecture and feature selection.
 * This file is the single source of truth for build-time configuration.
 */

#pragma once

/* ============================================================
 *   Architecture Configuration
 * ============================================================ */

/* Architecture selection (defined by build system) */
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X86_64 1
    #define ARCH_NAME "x86_64"
    #define ARCH_BITS 64
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH_ARM64 1
    #define ARCH_NAME "arm64"
    #define ARCH_BITS 64
#else
    #error "Unsupported architecture"
#endif

/* Validate 64-bit only */
#if ARCH_BITS != 64
    #error "Futura OS requires 64-bit architecture"
#endif

/* ============================================================
 *   Feature Configuration
 * ============================================================ */

/* Core kernel features */
#define CONFIG_MULTITHREADING      1    /* Enable multi-threading support */
#define CONFIG_PREEMPTIVE_SCHED    1    /* Enable preemptive scheduling */
#define CONFIG_SMP                 0    /* Symmetric multiprocessing (Phase 3) */
#define CONFIG_MAX_CPUS            1    /* Maximum CPU cores (1 for Phase 2) */

/* Memory management */
#define CONFIG_PAGING              1    /* Enable virtual memory paging */
#define CONFIG_PAGE_SIZE           4096 /* Page size in bytes */
#define CONFIG_HEAP_SIZE           (16 * 1024 * 1024)  /* 16 MB initial heap */

/* IPC and object system */
#define CONFIG_IPC                 1    /* Enable IPC subsystem */
#define CONFIG_FIPC                1    /* Enable Futura IPC (shared memory channels) */
#define CONFIG_MAX_HANDLES         4096 /* Maximum object handles per task */

/* Subsystems */
#define CONFIG_VFS                 1    /* Enable Virtual File System */
#define CONFIG_FUTURA_FS           1    /* Enable FuturaFS driver */
#define CONFIG_FAT_FS              1    /* Enable FAT filesystem support */
#define CONFIG_EXT4_FS             0    /* ext4 support (Phase 3) */

#define CONFIG_NETWORKING          1    /* Enable networking stack */
#define CONFIG_NET_IPV6            1    /* Enable IPv6 support */
#define CONFIG_NET_QUIC            0    /* QUIC protocol (Phase 3) */

#define CONFIG_FUTURAWAY           1    /* Enable FuturaWay compositor */
#define CONFIG_GPU_ACCEL           0    /* GPU acceleration (Phase 3) */

/* POSIX compatibility */
#define CONFIG_POSIX_COMPAT        1    /* Enable POSIX compatibility layer */
#define CONFIG_POSIX_SYSCALLS      1    /* Enable POSIX syscall interface */

/* ============================================================
 *   Debugging and Diagnostics
 * ============================================================ */

#if defined(DEBUG) || !defined(NDEBUG)
    #define CONFIG_DEBUG           1    /* Debug mode enabled */
    #define CONFIG_DEBUG_SERIAL    1    /* Serial console debugging */
    #define CONFIG_TRACE_IRQS      1    /* Trace interrupt handlers */
    #define CONFIG_TRACE_CONTEXT   1    /* Trace context switches */
    #define CONFIG_ASSERTIONS      1    /* Enable runtime assertions */
    #define CONFIG_KMEM_DEBUG      1    /* Memory allocator debugging */
#else
    #define CONFIG_DEBUG           0    /* Release mode */
    #define CONFIG_DEBUG_SERIAL    1    /* Keep serial for production logs */
    #define CONFIG_TRACE_IRQS      0
    #define CONFIG_TRACE_CONTEXT   0
    #define CONFIG_ASSERTIONS      0
    #define CONFIG_KMEM_DEBUG      0
#endif

/* Serial port configuration (x86_64) */
#ifdef ARCH_X86_64
    #define CONFIG_SERIAL_PORT     0x3F8    /* COM1 */
    #define CONFIG_SERIAL_BAUD     38400    /* Baud rate */
#endif

/* UART configuration (ARM64) */
#ifdef ARCH_ARM64
    #define CONFIG_UART_BASE       0x09000000  /* PL011 UART base (QEMU virt) */
    #define CONFIG_UART_BAUD       115200      /* Baud rate */
#endif

/* ============================================================
 *   Performance Tuning
 * ============================================================ */

#define CONFIG_TIMER_HZ            100    /* Timer frequency (ticks per second) */
#define CONFIG_TIME_SLICE_MS       10     /* Scheduler time slice in milliseconds */
#define CONFIG_MAX_THREADS         256    /* Maximum threads system-wide */
#define CONFIG_MAX_TASKS           64     /* Maximum tasks (processes) */

/* Stack sizes */
#define CONFIG_KERNEL_STACK_SIZE   (64 * 1024)   /* 64 KB kernel stack (doubled from 32KB to fix VFS deep-call-chain overflow) */
#define CONFIG_USER_STACK_SIZE     (64 * 1024)   /* 64 KB user stack */
#define CONFIG_IRQ_STACK_SIZE      (8 * 1024)    /* 8 KB IRQ stack */

/* ============================================================
 *   Version Information
 * ============================================================ */

#define FUTURA_VERSION_MAJOR       0
#define FUTURA_VERSION_MINOR       2
#define FUTURA_VERSION_PATCH       0
#define FUTURA_VERSION_STRING      "0.2.0-alpha"
#define FUTURA_CODENAME            "Multi-Arch Foundation"

/* ============================================================
 *   Build Information
 * ============================================================ */

#define FUTURA_BUILD_TIMESTAMP     __DATE__ " " __TIME__
#define FUTURA_COMPILER            __VERSION__

/* ============================================================
 *   Configuration Validation
 * ============================================================ */

/* Ensure required features are enabled */
#if CONFIG_MULTITHREADING && !CONFIG_PREEMPTIVE_SCHED
    #warning "Multi-threading enabled but preemptive scheduling disabled"
#endif

#if CONFIG_FUTURAWAY && !CONFIG_FIPC
    #error "FuturaWay requires FIPC to be enabled"
#endif

#if CONFIG_POSIX_SYSCALLS && !CONFIG_POSIX_COMPAT
    #error "POSIX syscalls require POSIX compatibility layer"
#endif

#if CONFIG_SMP && (CONFIG_MAX_CPUS < 2)
    #error "SMP requires CONFIG_MAX_CPUS >= 2"
#endif

/* ============================================================
 *   Convenience Macros
 * ============================================================ */

/* Feature test macros */
#define FUTURA_HAS(feature) (CONFIG_##feature)

/* Debug logging macros */
#if CONFIG_DEBUG
    #define DEBUG_PRINT(fmt, ...) fut_serial_puts("[DEBUG] " fmt)
#else
    #define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

/* Architecture-specific header inclusion */
#ifdef ARCH_X86_64
    #define ARCH_HEADER(file) <arch/x86_64/file>
#elif defined(ARCH_ARM64)
    #define ARCH_HEADER(file) <arch/arm64/file>
#endif

/* Static assertions for configuration validation */
#define CONFIG_ASSERT(expr, msg) _Static_assert(expr, msg)

CONFIG_ASSERT(CONFIG_PAGE_SIZE == 4096, "Only 4KB pages supported");
CONFIG_ASSERT(CONFIG_TIMER_HZ > 0 && CONFIG_TIMER_HZ <= 1000, "Invalid timer frequency");
CONFIG_ASSERT(CONFIG_MAX_THREADS > 0, "Must support at least one thread");

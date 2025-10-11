/* fut_object.h - Futura OS Object System (C23)
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Unified object and handle abstraction for capability-based kernel services.
 * All kernel resources (files, sockets, threads, etc.) are represented as objects
 * with capability-based access control.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================
 *   Object Types
 * ============================================================ */

enum fut_object_type {
    FUT_OBJ_NONE = 0,
    FUT_OBJ_FILE,           // File descriptor
    FUT_OBJ_SOCKET,         // Network socket
    FUT_OBJ_THREAD,         // Thread handle
    FUT_OBJ_TASK,           // Process/task handle
    FUT_OBJ_MEMORY,         // Shared memory region
    FUT_OBJ_CHANNEL,        // IPC channel
    FUT_OBJ_EVENT,          // Event/synchronization primitive
    FUT_OBJ_DEVICE,         // Device node
};

/* ============================================================
 *   Capability Rights
 * ============================================================ */

/* Rights bitfield for capability-based access control */
typedef uint64_t fut_rights_t;

#define FUT_RIGHT_READ      (1ULL << 0)   // Read access
#define FUT_RIGHT_WRITE     (1ULL << 1)   // Write access
#define FUT_RIGHT_EXECUTE   (1ULL << 2)   // Execute permission
#define FUT_RIGHT_SHARE     (1ULL << 3)   // Can share with other tasks
#define FUT_RIGHT_DESTROY   (1ULL << 4)   // Can destroy/close object
#define FUT_RIGHT_WAIT      (1ULL << 5)   // Can wait on object (events/threads)
#define FUT_RIGHT_SIGNAL    (1ULL << 6)   // Can signal object (events)
#define FUT_RIGHT_ADMIN     (1ULL << 7)   // Administrative rights

#define FUT_RIGHT_ALL       (0xFFFFFFFFFFFFFFFFULL)  // All rights
#define FUT_RIGHT_NONE      (0ULL)                    // No rights

/* ============================================================
 *   Handle Type
 * ============================================================ */

/* Opaque handle to kernel objects */
typedef uint64_t fut_handle_t;

#define FUT_INVALID_HANDLE  ((fut_handle_t)0)

/* ============================================================
 *   Object Structure (Internal)
 * ============================================================ */

/**
 * Generic kernel object.
 * All kernel resources are represented as objects.
 */
typedef struct fut_object {
    enum fut_object_type type;      // Object type
    fut_rights_t rights;            // Capability rights
    uint64_t refcount;              // Reference count (64-bit)
    void *data;                     // Type-specific data pointer
    struct fut_object *next;        // Next in free list or hash chain
} fut_object_t;

/* ============================================================
 *   Object System API
 * ============================================================ */

/**
 * Initialize the object system.
 * Must be called during kernel initialization.
 */
void fut_object_system_init(void);

/**
 * Create a new kernel object.
 *
 * @param type   Object type
 * @param rights Initial capability rights
 * @param data   Type-specific data pointer
 * @return Object handle, or FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_object_create(enum fut_object_type type, fut_rights_t rights, void *data);

/**
 * Destroy an object and free its resources.
 *
 * @param handle Handle to destroy
 * @return 0 on success, -1 on error
 */
int fut_object_destroy(fut_handle_t handle);

/**
 * Get a reference to an object (increases refcount).
 *
 * @param handle Handle to reference
 * @param required_rights Rights required to access this object
 * @return Pointer to object, or nullptr on failure
 */
fut_object_t *fut_object_get(fut_handle_t handle, fut_rights_t required_rights);

/**
 * Release a reference to an object (decreases refcount).
 *
 * @param obj Object to release
 */
void fut_object_put(fut_object_t *obj);

/**
 * Check if a handle has specific rights.
 *
 * @param handle Handle to check
 * @param required_rights Rights to verify
 * @return true if handle has all required rights, false otherwise
 */
bool fut_object_has_rights(fut_handle_t handle, fut_rights_t required_rights);

/**
 * Share an object with another task (creates new handle with reduced rights).
 *
 * @param handle Source handle
 * @param target_task Task PID to share with (64-bit)
 * @param shared_rights Rights to grant to new handle
 * @return New handle in target task, or FUT_INVALID_HANDLE on failure
 */
fut_handle_t fut_object_share(fut_handle_t handle, uint64_t target_task, fut_rights_t shared_rights);

/* ============================================================
 *   Message Passing (Async IPC)
 * ============================================================ */

/**
 * Send a message to an object (async IPC).
 *
 * @param handle Target object handle
 * @param msg Message buffer
 * @param msg_len Length of message in bytes
 * @return 0 on success, -1 on error
 */
int fut_object_send(fut_handle_t handle, const void *msg, size_t msg_len);

/**
 * Receive a message from an object (async IPC).
 *
 * @param handle Source object handle
 * @param buf Buffer to receive message
 * @param buf_len Size of receive buffer
 * @return Number of bytes received, or -1 on error
 */
int fut_object_receive(fut_handle_t handle, void *buf, size_t buf_len);

/**
 * Wait for an object to become ready (event/thread completion).
 *
 * @param handle Object to wait on
 * @param timeout_ms Timeout in milliseconds (0 = no timeout)
 * @return 0 on success, -1 on timeout/error
 */
int fut_object_wait(fut_handle_t handle, uint64_t timeout_ms);

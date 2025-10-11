/* fut_object.c - Futura OS Object System Implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Phase 1: Stub implementation for object system foundation.
 * This provides the basic API structure for future expansion.
 */

#include "../../include/kernel/fut_object.h"
#include "../../include/kernel/fut_memory.h"

/* ============================================================
 *   Object Table (Phase 1: Simple Linear Array)
 * ============================================================ */

#define FUT_MAX_OBJECTS 4096

static fut_object_t *object_table[FUT_MAX_OBJECTS];
static uint32_t next_handle = 1;

/* ============================================================
 *   Object System Initialization
 * ============================================================ */

void fut_object_system_init(void) {
    for (uint32_t i = 0; i < FUT_MAX_OBJECTS; ++i) {
        object_table[i] = nullptr;
    }
    next_handle = 1;
}

/* ============================================================
 *   Object Creation and Destruction
 * ============================================================ */

fut_handle_t fut_object_create(enum fut_object_type type, fut_rights_t rights, void *data) {
    // Find free slot in object table
    for (uint32_t i = 1; i < FUT_MAX_OBJECTS; ++i) {
        if (object_table[i] == nullptr) {
            // Allocate object structure
            fut_object_t *obj = (fut_object_t *)fut_malloc(sizeof(fut_object_t));
            if (!obj) {
                return FUT_INVALID_HANDLE;
            }

            // Initialize object
            obj->type = type;
            obj->rights = rights;
            obj->refcount = 1;
            obj->data = data;
            obj->next = nullptr;

            // Store in table
            object_table[i] = obj;

            return (fut_handle_t)i;
        }
    }

    return FUT_INVALID_HANDLE;  // Object table full
}

int fut_object_destroy(fut_handle_t handle) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return -1;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return -1;  // Already destroyed or never existed
    }

    // Check if caller has DESTROY rights
    if (!(obj->rights & FUT_RIGHT_DESTROY)) {
        return -1;  // Permission denied
    }

    // Decrement refcount and free if zero
    if (--obj->refcount == 0) {
        fut_free(obj);
        object_table[handle] = nullptr;
    }

    return 0;
}

/* ============================================================
 *   Object Reference Management
 * ============================================================ */

fut_object_t *fut_object_get(fut_handle_t handle, fut_rights_t required_rights) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return nullptr;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return nullptr;
    }

    // Check rights
    if ((obj->rights & required_rights) != required_rights) {
        return nullptr;  // Insufficient rights
    }

    // Increment refcount
    ++obj->refcount;

    return obj;
}

void fut_object_put(fut_object_t *obj) {
    if (!obj) return;

    // Decrement refcount and free if zero
    if (--obj->refcount == 0) {
        fut_free(obj);
        // Note: We should also clear the object_table entry, but we don't have the handle here
        // Future: Use reverse lookup or store handle in object
    }
}

bool fut_object_has_rights(fut_handle_t handle, fut_rights_t required_rights) {
    if (handle == FUT_INVALID_HANDLE || handle >= FUT_MAX_OBJECTS) {
        return false;
    }

    fut_object_t *obj = object_table[handle];
    if (!obj) {
        return false;
    }

    return (obj->rights & required_rights) == required_rights;
}

/* ============================================================
 *   Object Sharing (Phase 1: Stub)
 * ============================================================ */

fut_handle_t fut_object_share(fut_handle_t handle, uint32_t target_task, fut_rights_t shared_rights) {
    // Phase 1: Stub implementation
    // Future: Implement proper cross-task handle sharing
    (void)handle;
    (void)target_task;
    (void)shared_rights;
    return FUT_INVALID_HANDLE;
}

/* ============================================================
 *   Message Passing (Phase 1: Stubs)
 * ============================================================ */

int fut_object_send(fut_handle_t handle, const void *msg, size_t msg_len) {
    // Phase 1: Stub implementation
    // Future: Implement async message queues
    (void)handle;
    (void)msg;
    (void)msg_len;
    return -1;
}

int fut_object_receive(fut_handle_t handle, void *buf, size_t buf_len) {
    // Phase 1: Stub implementation
    // Future: Implement async message queues
    (void)handle;
    (void)buf;
    (void)buf_len;
    return -1;
}

int fut_object_wait(fut_handle_t handle, uint64_t timeout_ms) {
    // Phase 1: Stub implementation
    // Future: Integrate with scheduler for event waiting
    (void)handle;
    (void)timeout_ms;
    return -1;
}

// SPDX-License-Identifier: MPL-2.0
/*
 * uaccess.c - Safe user memory access helpers
 *
 * Provides minimal page-aware validation and copy routines so kernel code can
 * interact with user pointers without relying on hardware faults.  The checks
 * currently operate on the global kernel address space; future VM work will
 * extend this to per-process contexts.
 */

#include <kernel/uaccess.h>
#include <kernel/errno.h>
#include <kernel/fut_mm.h>

#if defined(__x86_64__)
#include <arch/x86_64/paging.h>
#include <arch/x86_64/pmap.h>
#elif defined(__aarch64__)
#include <arch/arm64/paging.h>
#endif

#include <stdbool.h>
#include <string.h>

uintptr_t g_user_lo = 0x0000000000400000ULL;
uintptr_t g_user_hi = USER_SPACE_END + 1ULL; /* exclusive upper bound */

#define COPY_CHUNK 64u

typedef struct {
    struct fut_uaccess_window window;
    bool active;
    bool faulted;
    int error;
} fut_uaccess_state_t;

static fut_uaccess_state_t g_uaccess_state = {
    .window = {
        .user_ptr = NULL,
        .length = 0,
        .to_user = 0,
        .resume = NULL,
    },
    .active = false,
    .faulted = false,
    .error = 0,
};

static inline void uaccess_activate(const void *user_ptr, size_t len, int to_user, void *resume) {
    g_uaccess_state.window.user_ptr = user_ptr;
    g_uaccess_state.window.length = len;
    g_uaccess_state.window.to_user = to_user;
    g_uaccess_state.window.resume = resume;
    g_uaccess_state.active = true;
    g_uaccess_state.faulted = false;
    g_uaccess_state.error = 0;
}

static inline void uaccess_update(const void *user_ptr, size_t len) {
    if (!g_uaccess_state.active) {
        return;
    }
    g_uaccess_state.window.user_ptr = user_ptr;
    g_uaccess_state.window.length = len;
}

static inline void uaccess_clear(void) {
    g_uaccess_state.active = false;
    g_uaccess_state.faulted = false;
    g_uaccess_state.error = 0;
    g_uaccess_state.window.user_ptr = NULL;
    g_uaccess_state.window.length = 0;
    g_uaccess_state.window.resume = NULL;
    g_uaccess_state.window.to_user = 0;
}

const struct fut_uaccess_window *fut_uaccess_window_current(void) {
    return g_uaccess_state.active ? &g_uaccess_state.window : NULL;
}

void fut_uaccess_window_fault(int error) {
    if (!g_uaccess_state.active) {
        return;
    }
    g_uaccess_state.faulted = true;
    g_uaccess_state.error = error;
}

int fut_uaccess_window_error(void) {
    if (g_uaccess_state.faulted && g_uaccess_state.error != 0) {
        return g_uaccess_state.error;
    }
    return -EFAULT;
}

static inline int __range_user_ok(uintptr_t u, size_t n) {
    if (n == 0) {
        return 1;
    }

    if (u < g_user_lo) {
        return 0;
    }

    uintptr_t max_len = g_user_hi > u ? (g_user_hi - u) : 0;
    if (n > max_len) {
        return 0;
    }

    return 1;
}

int fut_access_ok(const void *u_ptr, size_t len, int write) {
#if defined(__x86_64__)
    uintptr_t u = (uintptr_t)u_ptr;

    if (!__range_user_ok(u, len)) {
        return -EFAULT;
    }

    if (len == 0) {
        return 0;
    }

    uintptr_t start = u & ~(uintptr_t)(PAGE_SIZE - 1ULL);
    uintptr_t end = (u + len - 1ULL) & ~(uintptr_t)(PAGE_SIZE - 1ULL);

    fut_mm_t *mm = fut_mm_current();
    fut_vmem_context_t *ctx = fut_mm_context(mm);

    for (uintptr_t addr = start; addr <= end; addr += PAGE_SIZE) {
        uint64_t pte = 0;
        if (pmap_probe_pte(ctx, addr, &pte) != 0) {
            return -EFAULT;
        }

        if (!(pte & PTE_PRESENT) || !(pte & PTE_USER)) {
            return -EFAULT;
        }

        if (write && !(pte & PTE_WRITABLE)) {
            return -EFAULT;
        }
    }

    return 0;
#elif defined(__aarch64__)
    /* ARM64: Validation delegated to MMU */
    (void)u_ptr;
    (void)len;
    (void)write;
    return 0;
#endif
}

int fut_copy_from_user(void *k_dst, const void *u_src, size_t n) {
    if (n == 0) {
        return 0;
    }

    int rc = fut_access_ok(u_src, n, 0);
    if (rc != 0) {
        return rc;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    void *resume = &&copy_fault;
#pragma GCC diagnostic pop

    uaccess_activate(u_src, n, 0, resume);

    uint8_t *dst = (uint8_t *)k_dst;
    const volatile uint8_t *src = (const volatile uint8_t *)u_src;

    size_t remaining = n;
    while (remaining > 0) {
        size_t chunk = remaining > COPY_CHUNK ? COPY_CHUNK : remaining;
        uaccess_update((const void *)src, chunk);

        for (size_t i = 0; i < chunk; ++i) {
            dst[i] = src[i];
        }

        dst += chunk;
        src += chunk;
        remaining -= chunk;
    }

    uaccess_clear();
    return 0;

copy_fault:
    {
        int err = fut_uaccess_window_error();
        uaccess_clear();
        return err;
    }
}

int fut_copy_to_user(void *u_dst, const void *k_src, size_t n) {
    if (n == 0) {
        return 0;
    }

    int rc = fut_access_ok(u_dst, n, 1);
    if (rc != 0) {
        return rc;
    }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    void *resume = &&copy_fault;
#pragma GCC diagnostic pop

    uaccess_activate(u_dst, n, 1, resume);

    volatile uint8_t *dst = (volatile uint8_t *)u_dst;
    const uint8_t *src = (const uint8_t *)k_src;

    size_t remaining = n;
    while (remaining > 0) {
        size_t chunk = remaining > COPY_CHUNK ? COPY_CHUNK : remaining;
        uaccess_update((const void *)dst, chunk);

        for (size_t i = 0; i < chunk; ++i) {
            dst[i] = src[i];
        }

        dst += chunk;
        src += chunk;
        remaining -= chunk;
    }

    uaccess_clear();
    return 0;

copy_fault:
    {
        int err = fut_uaccess_window_error();
        uaccess_clear();
        return err;
    }
}

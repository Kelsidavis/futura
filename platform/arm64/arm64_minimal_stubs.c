/* ARM64 Minimal Stubs for ARM64 Build
 * Provides minimal implementations to allow ARM64 kernel to link
 * These are stubs to satisfy linker requirements for boot
 */

#include <kernel/fut_mm.h>
#include <arch/arm64/irq.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ============================================================
 *   Memory Management Stubs
 * ============================================================ */

void fut_paging_init(void) {
    /* Stub: ARM64 uses hardware MMU directly */
    return;
}

/* ============================================================
 *   Scheduling Stubs
 * ============================================================ */

void fut_scheduler_init(void) {
    /* Stub: Scheduler initialization (basic stub for boot) */
    return;
}

/* ============================================================
 *   IRQ Handler Registration Stubs
 * ============================================================ */

int fut_register_irq_handler(int irq, fut_irq_handler_t handler) {
    /* Stub: Already implemented in arm64_irq.c, but ensure it's linked */
    (void)irq;
    (void)handler;
    return 0;
}

/* ============================================================
 *   GIC Initialization Stubs
 * ============================================================ */

void fut_gic_init(void) {
    /* Stub: Already partially implemented in arm64_irq.c */
    return;
}

/* ============================================================
 *   Timer Management Stubs
 * ============================================================ */

void fut_timer_set_timeout(uint64_t ticks) {
    /* Stub: Timer configuration for ARM64 */
    (void)ticks;
    return;
}

/* ============================================================
 *   C Library String Functions
 * ============================================================ */

/**
 * Compare two null-terminated strings.
 * @param s1 First string (must not be NULL)
 * @param s2 Second string (must not be NULL)
 * @return 0 if equal, <0 if s1<s2, >0 if s1>s2
 */
int strcmp(const char *s1, const char *s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        s1++;
        s2++;
    }

    return (unsigned char)*s1 - (unsigned char)*s2;
}

/**
 * Find substring s2 in string s1.
 * @param s1 Haystack string (must not be NULL)
 * @param s2 Needle string (must not be NULL)
 * @return Pointer to first occurrence of s2 in s1, or NULL if not found
 */
char *strstr(const char *s1, const char *s2) {
    if (*s2 == '\0') {
        return (char *)s1;
    }

    while (*s1) {
        const char *a = s1;
        const char *b = s2;

        while (*a && *b && *a == *b) {
            a++;
            b++;
        }

        if (*b == '\0') {
            return (char *)s1;
        }

        s1++;
    }

    return NULL;
}

/* ============================================================
 *   Memory Management Stubs (Additional)
 * ============================================================ */

fut_mm_t *fut_mm_create(void) {
    /* Stub: Create memory management context */
    return NULL;
}

/* ============================================================
 *   Serial/Console I/O Stubs
 * ============================================================ */

int fut_serial_getc_blocking(void) {
    /* Stub: Blocking serial input (not implemented for ARM64 yet) */
    return -1;
}

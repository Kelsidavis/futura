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
 *   Scheduling Stubs
 * ============================================================ */

void fut_scheduler_init(void) {
    /* Stub: Scheduler initialization (basic stub for boot) */
    return;
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
 *   Serial/Console I/O
 * ============================================================ */

/* Forward declarations for RX buffer access */
extern volatile char uart_rx_buffer[4096];
extern volatile uint32_t uart_rx_head;
extern volatile uint32_t uart_rx_tail;

/**
 * Non-blocking read from UART RX ring buffer.
 * Returns -1 if no character available, character code otherwise.
 */
int fut_serial_getc(void) {
    /* Non-blocking read - check if character available */
    if (uart_rx_head == uart_rx_tail) {
        return -1;  /* No character available */
    }

    /* Character available - read from buffer */
    char c = uart_rx_buffer[uart_rx_tail];
    uart_rx_tail = (uart_rx_tail + 1) % 4096;

    return (int)(unsigned char)c;
}

/**
 * Blocking read from UART RX ring buffer.
 * Yields CPU while waiting for character to be available.
 * Uses futex-style polling with exponential backoff.
 */
int fut_serial_getc_blocking(void) {
    /* Blocking read with proper yields */
    int spin_count = 0;

    while (uart_rx_head == uart_rx_tail) {
        /* Buffer empty - yield to other threads */
        if (spin_count < 100) {
            /* Light spin for first 100 iterations */
            spin_count++;
            __asm__ volatile("yield");  /* AArch64 YIELD instruction */
        } else if (spin_count < 1000) {
            /* Heavier yield after 100 iterations */
            spin_count++;
            /* Could implement proper thread sleep here if kernel supports it */
            for (volatile int i = 0; i < 1000; i++) {
                __asm__ volatile("yield");
            }
        } else {
            /* Give other threads a chance - still spin but less frequently */
            spin_count++;
            for (volatile int i = 0; i < 10000; i++) {
                __asm__ volatile("yield");
            }
        }
    }

    /* Character available - read from buffer */
    char c = uart_rx_buffer[uart_rx_tail];
    uart_rx_tail = (uart_rx_tail + 1) % 4096;

    return (int)(unsigned char)c;
}

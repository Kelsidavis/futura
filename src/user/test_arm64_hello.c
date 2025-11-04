/* test_arm64_hello.c - Simple ARM64 userspace test program
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Minimal test program to verify ARM64 crt0 and syscalls work.
 */

/* Simple syscall wrappers */
static inline long syscall1(long n, long a1) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static inline long syscall3(long n, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}

/* Syscall numbers (ARM64 Linux-compatible) */
#define __NR_write  64
#define __NR_exit   93
#define __NR_getpid 172

/* Simple strlen */
static int strlen_local(const char *s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

/* Write to stdout */
static void write_str(const char *s) {
    int len = strlen_local(s);
    syscall3(__NR_write, 1, (long)s, len);
}

/* Simple integer to string */
static void write_int(long val) {
    char buf[32];
    int i = 0;

    if (val == 0) {
        buf[i++] = '0';
    } else {
        while (val > 0) {
            buf[i++] = '0' + (val % 10);
            val /= 10;
        }
        /* Reverse */
        for (int j = 0; j < i / 2; j++) {
            char tmp = buf[j];
            buf[j] = buf[i - 1 - j];
            buf[i - 1 - j] = tmp;
        }
    }
    buf[i] = '\0';
    write_str(buf);
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    write_str("Hello from ARM64 userspace!\n");
    write_str("This is running with crt0_arm64.S\n");

    /* Test getpid syscall */
    long pid = syscall1(__NR_getpid, 0);
    write_str("My PID is: ");
    write_int(pid);
    write_str("\n");

    write_str("Test completed successfully!\n");

    return 0;
}

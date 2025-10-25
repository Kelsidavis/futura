/* echo - display a line of text
 *
 * Simple implementation of the Unix echo utility.
 * Prints arguments separated by spaces, followed by a newline.
 */

#include <stdint.h>
#include <stddef.h>

/* Syscall numbers */
#define __NR_write  1
#define __NR_exit   60

typedef long ssize_t;

/* Syscall wrapper */
static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long syscall1(long nr, long arg1) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline ssize_t sys_write(int fd, const void *buf, size_t count) {
    return syscall3(__NR_write, fd, (long)buf, count);
}

static inline void sys_exit(int status) {
    syscall1(__NR_exit, status);
    __builtin_unreachable();
}

/* Write a string to stdout */
static void write_str(const char *str) {
    size_t len = 0;
    for (const char *p = str; *p; p++) len++;
    sys_write(1, str, len);
}

/* Simple string comparison */
static int strcmp_simple(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

int main(int argc, char **argv) {
    int newline = 1;  /* Default: print newline */
    int start = 1;    /* Index of first argument to print */

    /* Check for -n flag (no trailing newline) */
    if (argc > 1 && strcmp_simple(argv[1], "-n") == 0) {
        newline = 0;
        start = 2;
    }

    /* Print arguments */
    for (int i = start; i < argc; i++) {
        write_str(argv[i]);
        if (i < argc - 1) {
            sys_write(1, " ", 1);  /* Space between args */
        }
    }

    /* Print trailing newline unless -n was specified */
    if (newline) {
        sys_write(1, "\n", 1);
    }

    return 0;
}

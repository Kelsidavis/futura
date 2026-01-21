/* wc - print newline, word, and byte counts
 *
 * Implementation of the Unix wc utility.
 * Counts lines, words, and characters in files or stdin.
 */

#include <stdint.h>
#include <stddef.h>
#include "../libfutura/syscall_portable.h"

/* ssize_t is provided by syscall_portable.h */

static inline ssize_t sys_read(int fd, void *buf, size_t count) {
    return syscall3(__NR_read, fd, (long)buf, count);
}

static inline ssize_t sys_write(int fd, const void *buf, size_t count) {
    return syscall3(__NR_write, fd, (long)buf, count);
}

static inline int sys_open(const char *pathname, int flags, int mode) {
    return (int)syscall3(__NR_open, (long)pathname, flags, mode);
}

static inline int sys_close(int fd) {
    return (int)syscall1(__NR_close, fd);
}

static inline void sys_exit(int status) {
    syscall1(__NR_exit, status);
    __builtin_unreachable();
}

/* Write a string to stderr */
static void write_err(const char *str) {
    size_t len = 0;
    for (const char *p = str; *p; p++) len++;
    sys_write(2, str, len);
}

/* Write a string to stdout */
static void write_str(const char *str) {
    size_t len = 0;
    for (const char *p = str; *p; p++) len++;
    sys_write(1, str, len);
}

/* Simple number to string conversion */
static void write_num(size_t num) {
    char buf[32];
    int i = 0;

    if (num == 0) {
        sys_write(1, "0", 1);
        return;
    }

    while (num > 0) {
        buf[i++] = '0' + (num % 10);
        num /= 10;
    }

    /* Reverse the digits */
    for (int j = i - 1; j >= 0; j--) {
        sys_write(1, &buf[j], 1);
    }
}

/* Count lines, words, and bytes in a file descriptor */
static int count_fd(int fd, size_t *lines, size_t *words, size_t *bytes) {
    char buf[4096];
    ssize_t nread;
    int in_word = 0;

    *lines = 0;
    *words = 0;
    *bytes = 0;

    while ((nread = sys_read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            char c = buf[i];
            (*bytes)++;

            if (c == '\n') {
                (*lines)++;
            }

            /* Word boundary detection: whitespace (space, tab, newline) */
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (in_word) {
                    (*words)++;
                    in_word = 0;
                }
            } else {
                in_word = 1;
            }
        }
    }

    /* Count last word if file doesn't end with whitespace */
    if (in_word) {
        (*words)++;
    }

    if (nread < 0) {
        write_err("wc: read error\n");
        return 1;
    }

    return 0;
}

/* Print counts in standard format: lines words bytes [filename] */
static void print_counts(size_t lines, size_t words, size_t bytes, const char *name) {
    write_str("  ");
    write_num(lines);
    write_str("  ");
    write_num(words);
    write_str("  ");
    write_num(bytes);

    if (name) {
        write_str(" ");
        write_str(name);
    }

    sys_write(1, "\n", 1);
}

int main(int argc, char **argv) {
    int exit_status = 0;
    size_t total_lines = 0, total_words = 0, total_bytes = 0;

    /* No arguments - count stdin */
    if (argc == 1) {
        size_t lines, words, bytes;
        if (count_fd(0, &lines, &words, &bytes) == 0) {
            print_counts(lines, words, bytes, (const char *)0);
        } else {
            exit_status = 1;
        }
        return exit_status;
    }

    /* Count each file */
    for (int i = 1; i < argc; i++) {
        const char *filename = argv[i];
        size_t lines, words, bytes;

        /* Special case: "-" means stdin */
        if (filename[0] == '-' && filename[1] == '\0') {
            if (count_fd(0, &lines, &words, &bytes) == 0) {
                print_counts(lines, words, bytes, "-");
            } else {
                exit_status = 1;
                continue;
            }
        } else {
            /* Open the file */
            int fd = sys_open(filename, 0, 0);  /* O_RDONLY = 0 */
            if (fd < 0) {
                write_err("wc: ");
                write_err(filename);
                write_err(": cannot open file\n");
                exit_status = 1;
                continue;
            }

            if (count_fd(fd, &lines, &words, &bytes) == 0) {
                print_counts(lines, words, bytes, filename);
            } else {
                exit_status = 1;
            }

            sys_close(fd);
        }

        /* Accumulate totals */
        total_lines += lines;
        total_words += words;
        total_bytes += bytes;
    }

    /* Print total if more than one file */
    if (argc > 2) {
        print_counts(total_lines, total_words, total_bytes, "total");
    }

    return exit_status;
}

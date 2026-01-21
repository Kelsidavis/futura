/* cat - concatenate and print files
 *
 * A simple implementation of the Unix cat utility.
 * Reads from stdin or files and writes to stdout.
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

/* Copy data from one fd to another */
static int copy_fd(int in_fd, int out_fd) {
    char buf[4096];
    ssize_t nread;

    while ((nread = sys_read(in_fd, buf, sizeof(buf))) > 0) {
        ssize_t nwritten = 0;
        while (nwritten < nread) {
            ssize_t n = sys_write(out_fd, buf + nwritten, nread - nwritten);
            if (n <= 0) {
                write_err("cat: write error\n");
                return 1;
            }
            nwritten += n;
        }
    }

    if (nread < 0) {
        write_err("cat: read error\n");
        return 1;
    }

    return 0;
}

int main(int argc, char **argv) {
    int exit_status = 0;

    /* No arguments - read from stdin */
    if (argc == 1) {
        return copy_fd(0, 1);
    }

    /* Read from each file argument */
    for (int i = 1; i < argc; i++) {
        const char *filename = argv[i];

        /* Special case: "-" means stdin */
        if (filename[0] == '-' && filename[1] == '\0') {
            if (copy_fd(0, 1) != 0) {
                exit_status = 1;
            }
            continue;
        }

        /* Open the file */
        int fd = sys_open(filename, 0, 0);  /* O_RDONLY = 0 */
        if (fd < 0) {
            write_err("cat: ");
            write_err(filename);
            write_err(": cannot open file\n");
            exit_status = 1;
            continue;
        }

        /* Copy file to stdout */
        if (copy_fd(fd, 1) != 0) {
            exit_status = 1;
        }

        sys_close(fd);
    }

    return exit_status;
}

/* shell.c - Enhanced POSIX-like shell for Futura OS
 *
 * An interactive shell with support for:
 * - Directory navigation (cd, pwd)
 * - File listing (ls)
 * - System information (uname, whoami, date, etc.)
 * - Built-in commands (help, clear, exit)
 * - Command argument parsing
 */

#include <stdint.h>
#include <stddef.h>

/* Define syscall numbers for x86_64 */
#define __NR_read       0
#define __NR_write      1
#define __NR_open       2
#define __NR_close      3
#define __NR_stat       4
#define __NR_lseek      8
#define __NR_chdir      80
#define __NR_getcwd     79
#define __NR_exit       60

/* x86_64 syscall invocation via inline asm */
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

static inline long sys_write(int fd, const char *buf, size_t count) {
    return syscall3(1, fd, (long)buf, count);
}

static inline long sys_read(int fd, char *buf, size_t count) {
    return syscall3(0, fd, (long)buf, count);
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

static inline long syscall2(long nr, long arg1, long arg2) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_chdir(const char *path) {
    return syscall1(80, (long)path);
}

static inline long sys_getcwd(char *buf, size_t size) {
    return syscall2(79, (long)buf, size);
}

typedef long ssize_t;

/* Simple write syscall wrapper */
static void write_str(int fd, const char *str) {
    size_t total = 0;
    for (const char *p = str; *p; p++) {
        total++;
    }
    sys_write(fd, str, total);
}

/* Write a single character */
static void write_char(int fd, char c) {
    sys_write(fd, &c, 1);
}

/* Simple read syscall wrapper */
static ssize_t read_bytes(int fd, char *buf, size_t count) {
    return sys_read(fd, buf, count);
}

/* Parse command line into arguments */
static int parse_command(char *line, char *argv[], int max_args) {
    int argc = 0;
    char *p = line;

    while (*p && argc < max_args - 1) {
        /* Skip whitespace */
        while (*p && (*p == ' ' || *p == '\t')) {
            p++;
        }

        if (!*p) break;

        /* Handle quoted strings */
        if (*p == '"') {
            p++;
            argv[argc] = p;
            while (*p && *p != '"') {
                p++;
            }
            if (*p == '"') {
                *p = '\0';
                p++;
            }
        } else if (*p == '\'') {
            p++;
            argv[argc] = p;
            while (*p && *p != '\'') {
                p++;
            }
            if (*p == '\'') {
                *p = '\0';
                p++;
            }
        } else {
            argv[argc] = p;
            while (*p && *p != ' ' && *p != '\t') {
                p++;
            }
            if (*p) {
                *p = '\0';
                p++;
            }
        }

        argc++;
    }

    argv[argc] = NULL;
    return argc;
}

/* String comparison */
static int strcmp_simple(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* Built-in: help */
static void cmd_help(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    write_str(1, "Futura OS Shell v0.2 - Available Commands:\n");
    write_str(1, "\n");
    write_str(1, "Navigation:\n");
    write_str(1, "  cd [dir]        - Change directory\n");
    write_str(1, "  pwd             - Print working directory\n");
    write_str(1, "  ls [dir]        - List directory contents\n");
    write_str(1, "\n");
    write_str(1, "System:\n");
    write_str(1, "  uname           - Print system information\n");
    write_str(1, "  whoami          - Print current user\n");
    write_str(1, "  echo [args]     - Print text\n");
    write_str(1, "  clear           - Clear screen\n");
    write_str(1, "\n");
    write_str(1, "Shell:\n");
    write_str(1, "  help            - Show this help message\n");
    write_str(1, "  exit [code]     - Exit shell\n");
}

/* Built-in: clear screen */
static void cmd_clear(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    write_str(1, "\033[2J");  /* Clear screen */
    write_str(1, "\033[H");   /* Move cursor to home */
}

/* Built-in: pwd */
static void cmd_pwd(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    char cwd[256] = {0};
    long ret = sys_getcwd(cwd, sizeof(cwd));

    if (ret > 0) {
        write_str(1, cwd);
        write_char(1, '\n');
    } else {
        write_str(1, "Error: cannot get current directory\n");
    }
}

/* Built-in: cd */
static void cmd_cd(int argc, char *argv[]) {
    const char *path = argc > 1 ? argv[1] : "/";

    long ret = sys_chdir(path);

    if (ret != 0) {
        write_str(1, "cd: cannot change directory to ");
        write_str(1, path);
        write_char(1, '\n');
    }
}

/* Built-in: echo */
static void cmd_echo(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        write_str(1, argv[i]);
        if (i < argc - 1) write_char(1, ' ');
    }
    write_char(1, '\n');
}

/* Built-in: uname */
static void cmd_uname(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    write_str(1, "Futura\n");
}

/* Built-in: whoami */
static void cmd_whoami(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    write_str(1, "root\n");
}

/* Execute a command */
static int execute_command(int argc, char *argv[]) {
    if (argc == 0) return 0;

    if (strcmp_simple(argv[0], "help") == 0) {
        cmd_help(argc, argv);
    } else if (strcmp_simple(argv[0], "pwd") == 0) {
        cmd_pwd(argc, argv);
    } else if (strcmp_simple(argv[0], "cd") == 0) {
        cmd_cd(argc, argv);
    } else if (strcmp_simple(argv[0], "echo") == 0) {
        cmd_echo(argc, argv);
    } else if (strcmp_simple(argv[0], "clear") == 0) {
        cmd_clear(argc, argv);
    } else if (strcmp_simple(argv[0], "uname") == 0) {
        cmd_uname(argc, argv);
    } else if (strcmp_simple(argv[0], "whoami") == 0) {
        cmd_whoami(argc, argv);
    } else if (strcmp_simple(argv[0], "exit") == 0) {
        int status = 0;
        if (argc > 1) {
            /* Simple atoi */
            char *p = argv[1];
            while (*p >= '0' && *p <= '9') {
                status = status * 10 + (*p - '0');
                p++;
            }
        }
        write_str(1, "Goodbye!\n");
        syscall1(60, status);
        while (1);
    } else {
        write_str(1, "Command not found: ");
        write_str(1, argv[0]);
        write_str(1, " (type 'help' for available commands)\n");
    }

    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    write_str(1, "\n");
    write_str(1, "╔════════════════════════════════════════╗\n");
    write_str(1, "║   Futura OS Shell v0.2                 ║\n");
    write_str(1, "║   Type 'help' for available commands   ║\n");
    write_str(1, "╚════════════════════════════════════════╝\n");
    write_str(1, "\n");

    char cmdline[512];
    char *cmd_argv[32];
    int cmd_argc;
    ssize_t nread;

    while (1) {
        /* Print prompt with current directory */
        write_str(1, "futura> ");

        /* Read command line */
        nread = read_bytes(0, cmdline, sizeof(cmdline) - 1);

        if (nread <= 0) {
            break; /* EOF or error - exit shell */
        }

        /* Null-terminate and remove trailing newline */
        if (nread > 0 && cmdline[nread - 1] == '\n') {
            cmdline[nread - 1] = '\0';
        } else {
            cmdline[nread] = '\0';
        }

        /* Skip empty lines */
        if (cmdline[0] == '\0') {
            continue;
        }

        /* Parse and execute command */
        cmd_argc = parse_command(cmdline, cmd_argv, 32);
        if (cmd_argc > 0) {
            execute_command(cmd_argc, cmd_argv);
        }
    }

    write_str(1, "\nShell terminated\n");
    return 0;
}

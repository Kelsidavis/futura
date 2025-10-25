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
#define __NR_pipe       22
#define __NR_dup2       33
#define __NR_fork       57
#define __NR_execve     59
#define __NR_exit       60
#define __NR_wait4      61
#define __NR_chdir      80
#define __NR_getcwd     79

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

static inline long sys_fork(void) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(__NR_fork)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_pipe(int pipefd[2]) {
    return syscall1(__NR_pipe, (long)pipefd);
}

static inline long sys_dup2(int oldfd, int newfd) {
    return syscall2(__NR_dup2, oldfd, newfd);
}

static inline long sys_close(int fd) {
    return syscall1(__NR_close, fd);
}

static inline long sys_waitpid(int pid, int *status, int options) {
    return syscall3(__NR_wait4, pid, (long)status, options);
}

static inline long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    return syscall3(__NR_execve, (long)pathname, (long)argv, (long)envp);
}

typedef long ssize_t;
typedef int pid_t;

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

/* Read a line with interactive editing support (backspace, etc.) */
static ssize_t read_line(int fd, char *buf, size_t max_len) {
    size_t pos = 0;
    char c;
    ssize_t nread;

    while (pos < max_len - 1) {
        nread = read_bytes(fd, &c, 1);

        if (nread <= 0) {
            /* EOF or error */
            if (pos > 0) {
                buf[pos] = '\0';
                return pos;
            }
            return nread;
        }

        /* Handle different control characters */
        if (c == '\n' || c == '\r') {
            /* End of line */
            write_char(1, '\n');
            buf[pos] = '\0';
            return pos;
        } else if (c == 0x7F || c == 0x08) {
            /* Backspace (DEL=0x7F or BS=0x08) */
            if (pos > 0) {
                pos--;
                /* Erase character on screen: backspace, space, backspace */
                write_char(1, '\b');
                write_char(1, ' ');
                write_char(1, '\b');
            }
        } else if (c == 0x03) {
            /* Ctrl+C - interrupt */
            write_str(1, "^C\n");
            buf[0] = '\0';
            return 0;
        } else if (c >= 0x20 && c < 0x7F) {
            /* Printable character - echo it and add to buffer */
            buf[pos++] = c;
            write_char(1, c);
        }
        /* Ignore other control characters */
    }

    /* Buffer full */
    buf[max_len - 1] = '\0';
    return max_len - 1;
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

/* Check if a command is a shell builtin */
static int is_builtin(const char *cmd) {
    return (strcmp_simple(cmd, "cd") == 0 ||
            strcmp_simple(cmd, "exit") == 0 ||
            strcmp_simple(cmd, "help") == 0 ||
            strcmp_simple(cmd, "pwd") == 0 ||
            strcmp_simple(cmd, "echo") == 0 ||
            strcmp_simple(cmd, "clear") == 0 ||
            strcmp_simple(cmd, "uname") == 0 ||
            strcmp_simple(cmd, "whoami") == 0);
}

/* Parse command line into pipeline stages separated by '|' */
static int parse_pipeline(char *line, char *stages[], int max_stages) {
    int stage_count = 0;
    char *p = line;
    char *stage_start = p;

    while (*p && stage_count < max_stages - 1) {
        if (*p == '|') {
            *p = '\0';  /* Null-terminate this stage */
            stages[stage_count++] = stage_start;
            p++;
            /* Skip whitespace after pipe */
            while (*p == ' ' || *p == '\t') p++;
            stage_start = p;
        } else {
            p++;
        }
    }

    /* Add the final stage if non-empty */
    if (*stage_start) {
        stages[stage_count++] = stage_start;
    }

    stages[stage_count] = (char *)0;
    return stage_count;
}

/* Execute a single command in a pipeline (with fork/exec) */
static void exec_external_command(int argc, char *argv[]) {
    (void)argc;  /* Unused for now */

    /* For now, just indicate external commands are not yet supported */
    write_str(2, "Error: External commands not yet supported (tried: ");
    write_str(2, argv[0]);
    write_str(2, ")\n");
    syscall1(__NR_exit, 1);
}

/* Execute a pipeline of commands */
static int execute_pipeline(int num_stages, char *stages[]) {
    if (num_stages == 0) {
        return 0;
    }

    /* Single command - no piping needed */
    if (num_stages == 1) {
        char *argv[32];
        int argc = parse_command(stages[0], argv, 32);
        if (argc > 0) {
            /* Execute directly if builtin, otherwise would need fork/exec */
            if (is_builtin(argv[0])) {
                return execute_command(argc, argv);
            } else {
                write_str(2, "Error: External commands not yet supported\n");
                return -1;
            }
        }
        return 0;
    }

    /* Multi-stage pipeline */
    int pipes[10][2];  /* Support up to 10 stages */
    pid_t pids[10];

    if (num_stages > 10) {
        write_str(2, "Error: Too many pipeline stages (max 10)\n");
        return -1;
    }

    /* Create all pipes */
    for (int i = 0; i < num_stages - 1; i++) {
        if (sys_pipe(pipes[i]) < 0) {
            write_str(2, "Error: Failed to create pipe\n");
            return -1;
        }
    }

    /* Spawn processes for each stage */
    for (int i = 0; i < num_stages; i++) {
        char *argv[32];
        int argc = parse_command(stages[i], argv, 32);

        if (argc == 0) continue;

        /* Builtins can't be in pipelines (for now) */
        if (is_builtin(argv[0])) {
            write_str(2, "Error: Builtin '");
            write_str(2, argv[0]);
            write_str(2, "' cannot be used in a pipeline\n");
            /* Close all pipes and return */
            for (int j = 0; j < num_stages - 1; j++) {
                sys_close(pipes[j][0]);
                sys_close(pipes[j][1]);
            }
            return -1;
        }

        pid_t pid = sys_fork();

        if (pid < 0) {
            write_str(2, "Error: fork() failed\n");
            return -1;
        }

        if (pid == 0) {
            /* Child process */

            /* Redirect stdin from previous pipe (if not first stage) */
            if (i > 0) {
                sys_dup2(pipes[i-1][0], 0);  /* stdin = read end of previous pipe */
            }

            /* Redirect stdout to next pipe (if not last stage) */
            if (i < num_stages - 1) {
                sys_dup2(pipes[i][1], 1);  /* stdout = write end of current pipe */
            }

            /* Close all pipe fds in child */
            for (int j = 0; j < num_stages - 1; j++) {
                sys_close(pipes[j][0]);
                sys_close(pipes[j][1]);
            }

            /* Execute the command */
            exec_external_command(argc, argv);

            /* Should not reach here */
            syscall1(__NR_exit, 1);
        }

        pids[i] = pid;
    }

    /* Parent: close all pipes */
    for (int i = 0; i < num_stages - 1; i++) {
        sys_close(pipes[i][0]);
        sys_close(pipes[i][1]);
    }

    /* Wait for all children */
    for (int i = 0; i < num_stages; i++) {
        int status = 0;
        sys_waitpid(pids[i], &status, 0);
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
    ssize_t nread;

    while (1) {
        /* Print prompt with current directory */
        write_str(1, "futura> ");

        /* Read command line with interactive editing */
        nread = read_line(0, cmdline, sizeof(cmdline));

        if (nread < 0) {
            break; /* EOF or error - exit shell */
        }

        /* Skip empty lines */
        if (cmdline[0] == '\0') {
            continue;
        }

        /* Parse pipeline and execute */
        char *pipeline_stages[10];
        int num_stages = parse_pipeline(cmdline, pipeline_stages, 10);
        if (num_stages > 0) {
            execute_pipeline(num_stages, pipeline_stages);
        }
    }

    write_str(1, "\nShell terminated\n");
    return 0;
}

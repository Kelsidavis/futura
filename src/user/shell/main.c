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

/* File flags (from VFS) */
#define O_RDONLY    0x0000
#define O_WRONLY    0x0001
#define O_RDWR      0x0002
#define O_CREAT     0x0040
#define O_TRUNC     0x0200
#define O_APPEND    0x0400

/* File mode bits */
#define S_IRWXU     0000700  /* User RWX */
#define S_IRUSR     0000400  /* User read */
#define S_IWUSR     0000200  /* User write */
#define S_IXUSR     0000100  /* User execute */

/* Variable storage */
#define MAX_VARS 64
#define MAX_VAR_NAME 64
#define MAX_VAR_VALUE 256

struct shell_var {
    char name[MAX_VAR_NAME];
    char value[MAX_VAR_VALUE];
    int used;
};

static struct shell_var shell_vars[MAX_VARS];
static int last_exit_status = 0;

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

static inline int sys_open(const char *pathname, int flags, int mode) {
    return (int)syscall3(__NR_open, (long)pathname, flags, mode);
}

typedef long ssize_t;
typedef int pid_t;

/* Redirection types */
enum redir_type {
    REDIR_NONE = 0,
    REDIR_INPUT,      /* < file */
    REDIR_OUTPUT,     /* > file */
    REDIR_APPEND      /* >> file */
};

/* Redirection information for a command */
struct redir_info {
    enum redir_type input_type;
    char *input_file;
    enum redir_type output_type;
    char *output_file;
};

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

/* String comparison */
static int strcmp_simple(const char *a, const char *b) {
    while (*a && *b && *a == *b) {
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* String copy with length limit */
static void strncpy_simple(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

/* Get variable value */
static const char *get_var(const char *name) {
    /* Check special variables */
    static char exit_status_buf[16];
    if (strcmp_simple(name, "?") == 0) {
        /* Convert last_exit_status to string */
        int val = last_exit_status;
        int i = 0;
        if (val == 0) {
            exit_status_buf[i++] = '0';
        } else {
            char tmp[16];
            int j = 0;
            while (val > 0) {
                tmp[j++] = '0' + (val % 10);
                val /= 10;
            }
            for (int k = j - 1; k >= 0; k--) {
                exit_status_buf[i++] = tmp[k];
            }
        }
        exit_status_buf[i] = '\0';
        return exit_status_buf;
    }

    /* Look up user variable */
    for (int i = 0; i < MAX_VARS; i++) {
        if (shell_vars[i].used && strcmp_simple(shell_vars[i].name, name) == 0) {
            return shell_vars[i].value;
        }
    }
    return "";
}

/* Set variable value */
static void set_var(const char *name, const char *value) {
    /* Find existing variable or empty slot */
    int empty_slot = -1;
    for (int i = 0; i < MAX_VARS; i++) {
        if (shell_vars[i].used && strcmp_simple(shell_vars[i].name, name) == 0) {
            /* Update existing variable */
            strncpy_simple(shell_vars[i].value, value, MAX_VAR_VALUE);
            return;
        }
        if (!shell_vars[i].used && empty_slot == -1) {
            empty_slot = i;
        }
    }

    /* Add new variable */
    if (empty_slot != -1) {
        strncpy_simple(shell_vars[empty_slot].name, name, MAX_VAR_NAME);
        strncpy_simple(shell_vars[empty_slot].value, value, MAX_VAR_VALUE);
        shell_vars[empty_slot].used = 1;
    }
}

/* Check if line is a variable assignment (VAR=value) */
static int is_var_assignment(const char *line, char *name, char *value) {
    const char *p = line;
    int name_len = 0;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Variable name must start with letter or underscore */
    if (!(*p >= 'A' && *p <= 'Z') && !(*p >= 'a' && *p <= 'z') && *p != '_') {
        return 0;
    }

    /* Collect variable name */
    while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
           (*p >= '0' && *p <= '9') || *p == '_') {
        if (name_len < MAX_VAR_NAME - 1) {
            name[name_len++] = *p;
        }
        p++;
    }
    name[name_len] = '\0';

    /* Must have '=' */
    if (*p != '=') {
        return 0;
    }
    p++;  /* Skip '=' */

    /* Rest is the value */
    int value_len = 0;
    while (*p && value_len < MAX_VAR_VALUE - 1) {
        value[value_len++] = *p++;
    }
    value[value_len] = '\0';

    return 1;
}

/* Expand variables in a string (e.g., $VAR or ${VAR}) */
static void expand_variables(char *dest, const char *src, size_t dest_size) {
    size_t dest_pos = 0;
    const char *p = src;

    while (*p && dest_pos < dest_size - 1) {
        if (*p == '$') {
            p++;
            if (*p == '{') {
                /* ${VAR} syntax */
                p++;
                char var_name[MAX_VAR_NAME];
                int name_len = 0;
                while (*p && *p != '}' && name_len < MAX_VAR_NAME - 1) {
                    var_name[name_len++] = *p++;
                }
                var_name[name_len] = '\0';
                if (*p == '}') p++;  /* Skip closing brace */

                /* Get variable value */
                const char *value = get_var(var_name);
                while (*value && dest_pos < dest_size - 1) {
                    dest[dest_pos++] = *value++;
                }
            } else {
                /* $VAR syntax */
                char var_name[MAX_VAR_NAME];
                int name_len = 0;
                while ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
                       (*p >= '0' && *p <= '9') || *p == '_' || *p == '?') {
                    if (name_len < MAX_VAR_NAME - 1) {
                        var_name[name_len++] = *p++;
                    }
                }
                var_name[name_len] = '\0';

                /* Get variable value */
                const char *value = get_var(var_name);
                while (*value && dest_pos < dest_size - 1) {
                    dest[dest_pos++] = *value++;
                }
            }
        } else {
            dest[dest_pos++] = *p++;
        }
    }
    dest[dest_pos] = '\0';
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

/* Simple string copy */
static void strcpy_simple(char *dest, const char *src) {
    while (*src) {
        *dest++ = *src++;
    }
    *dest = '\0';
}

/* Simple string concatenation */
static void strcat_simple(char *dest, const char *src) {
    while (*dest) dest++;
    strcpy_simple(dest, src);
}

/* Check if string starts with a character */
static int starts_with(const char *str, char c) {
    return str[0] == c;
}

/* Parse redirections from a command and remove them from argv
 * Returns the new argc after removing redirection tokens */
static int parse_redirections(int argc, char *argv[], struct redir_info *redir) {
    int new_argc = 0;

    /* Initialize redirection info */
    redir->input_type = REDIR_NONE;
    redir->input_file = (char *)0;
    redir->output_type = REDIR_NONE;
    redir->output_file = (char *)0;

    for (int i = 0; i < argc; i++) {
        if (strcmp_simple(argv[i], "<") == 0) {
            /* Input redirection */
            if (i + 1 < argc) {
                redir->input_type = REDIR_INPUT;
                redir->input_file = argv[i + 1];
                i++;  /* Skip the filename */
            }
        } else if (strcmp_simple(argv[i], ">") == 0) {
            /* Output redirection (truncate) */
            if (i + 1 < argc) {
                redir->output_type = REDIR_OUTPUT;
                redir->output_file = argv[i + 1];
                i++;  /* Skip the filename */
            }
        } else if (strcmp_simple(argv[i], ">>") == 0) {
            /* Output redirection (append) */
            if (i + 1 < argc) {
                redir->output_type = REDIR_APPEND;
                redir->output_file = argv[i + 1];
                i++;  /* Skip the filename */
            }
        } else {
            /* Regular argument - keep it */
            argv[new_argc++] = argv[i];
        }
    }

    /* Null-terminate the new argv */
    argv[new_argc] = (char *)0;

    return new_argc;
}

/* Apply redirections by opening files and using dup2 */
static int apply_redirections(const struct redir_info *redir) {
    /* Handle input redirection */
    if (redir->input_type == REDIR_INPUT && redir->input_file) {
        int fd = sys_open(redir->input_file, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "Error: cannot open input file '");
            write_str(2, redir->input_file);
            write_str(2, "'\n");
            return -1;
        }
        sys_dup2(fd, 0);  /* Redirect stdin */
        sys_close(fd);
    }

    /* Handle output redirection */
    if (redir->output_type != REDIR_NONE && redir->output_file) {
        int flags, fd;

        if (redir->output_type == REDIR_OUTPUT) {
            /* Truncate mode: create or truncate file */
            flags = O_WRONLY | O_CREAT | O_TRUNC;
        } else {
            /* Append mode: create or append to file */
            flags = O_WRONLY | O_CREAT | O_APPEND;
        }

        fd = sys_open(redir->output_file, flags, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            write_str(2, "Error: cannot open output file '");
            write_str(2, redir->output_file);
            write_str(2, "'\n");
            return -1;
        }
        sys_dup2(fd, 1);  /* Redirect stdout */
        sys_close(fd);
    }

    return 0;
}

/* Execute a single command in a pipeline (with fork/exec) */
static void exec_external_command(int argc, char *argv[]) {
    if (argc == 0 || !argv[0]) {
        write_str(2, "Error: No command to execute\n");
        syscall1(__NR_exit, 1);
    }

    const char *cmd = argv[0];
    char path_buf[256];

    /* If command contains '/', use as-is (absolute or relative path) */
    if (starts_with(cmd, '/')) {
        /* Absolute path */
        sys_execve(cmd, argv, (char *const *)0);
    } else {
        /* Try to find in /bin/user/ */
        strcpy_simple(path_buf, "/bin/user/");
        strcat_simple(path_buf, cmd);
        sys_execve(path_buf, argv, (char *const *)0);
    }

    /* If execve returns, it failed */
    write_str(2, "Error: Failed to execute '");
    write_str(2, cmd);
    write_str(2, "'\n");
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
            /* Parse redirections */
            struct redir_info redir;
            argc = parse_redirections(argc, argv, &redir);

            if (argc == 0) {
                write_str(2, "Error: No command specified\n");
                return -1;
            }

            /* Execute directly if builtin */
            if (is_builtin(argv[0])) {
                /* Builtins with redirections need special handling */
                if (redir.input_type != REDIR_NONE || redir.output_type != REDIR_NONE) {
                    write_str(2, "Warning: Redirections not supported for builtins yet\n");
                }
                return execute_command(argc, argv);
            } else {
                /* External command - fork and exec */
                pid_t pid = sys_fork();
                if (pid < 0) {
                    write_str(2, "Error: fork() failed\n");
                    return -1;
                }

                if (pid == 0) {
                    /* Child: apply redirections and exec */
                    if (apply_redirections(&redir) < 0) {
                        syscall1(__NR_exit, 1);
                    }
                    exec_external_command(argc, argv);
                    syscall1(__NR_exit, 1);
                }

                /* Parent: wait for child */
                int status = 0;
                sys_waitpid(pid, &status, 0);
                return 0;
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

        /* Parse redirections */
        struct redir_info redir;
        argc = parse_redirections(argc, argv, &redir);

        if (argc == 0) {
            write_str(2, "Error: No command in pipeline stage\n");
            /* Close all pipes and return */
            for (int j = 0; j < num_stages - 1; j++) {
                sys_close(pipes[j][0]);
                sys_close(pipes[j][1]);
            }
            return -1;
        }

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

            /* Apply file redirections (for first/last stages) */
            if (apply_redirections(&redir) < 0) {
                syscall1(__NR_exit, 1);
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

        /* Check for variable assignment */
        char var_name[MAX_VAR_NAME];
        char var_value[MAX_VAR_VALUE];
        if (is_var_assignment(cmdline, var_name, var_value)) {
            /* Expand variables in the value */
            char expanded_value[MAX_VAR_VALUE];
            expand_variables(expanded_value, var_value, MAX_VAR_VALUE);
            set_var(var_name, expanded_value);
            last_exit_status = 0;
            continue;
        }

        /* Expand variables in command line */
        char expanded_cmdline[512];
        expand_variables(expanded_cmdline, cmdline, sizeof(expanded_cmdline));

        /* Parse pipeline and execute */
        char *pipeline_stages[10];
        int num_stages = parse_pipeline(expanded_cmdline, pipeline_stages, 10);
        if (num_stages > 0) {
            int status = execute_pipeline(num_stages, pipeline_stages);
            last_exit_status = (status < 0) ? 1 : 0;
        }
    }

    write_str(1, "\nShell terminated\n");
    return 0;
}

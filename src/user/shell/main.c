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
#define __NR_getdents64 217

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
    int exported;  /* 1 if exported to child processes */
};

static struct shell_var shell_vars[MAX_VARS];
static int last_exit_status = 0;

/* Type definitions */
typedef long ssize_t;
typedef int pid_t;

/* Environment array for passing to execve */
static char *envp[MAX_VARS + 1];  /* +1 for NULL terminator */
static char env_strings[MAX_VARS][MAX_VAR_NAME + MAX_VAR_VALUE + 2];  /* name=value\0 */

/* Command history */
#define MAX_HISTORY 100
#define MAX_CMD_LEN 512
static char history[MAX_HISTORY][MAX_CMD_LEN];
static int history_count = 0;

/* Job control */
#define MAX_JOBS 32

enum job_status {
    JOB_RUNNING = 0,
    JOB_DONE,
    JOB_STOPPED
};

struct job {
    int job_id;
    pid_t pid;
    enum job_status status;
    char command[MAX_CMD_LEN];
    int used;
};

static struct job jobs[MAX_JOBS];
static int next_job_id = 1;

/* Forward declarations for utility functions */
static int strcmp_simple(const char *a, const char *b);
static void strncpy_simple(char *dest, const char *src, size_t n);

/* Forward declarations for history functions */
static void add_to_history(const char *cmd);
static const char *get_history(int index);

/* Forward declaration for tab completion */
static void complete_command(char *buf, size_t *pos, size_t max_len);

/* x86_64 syscall invocation via inline asm */
static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
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
        : "rcx", "r11", "memory",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
    );
    return ret;
}

static inline long syscall2(long nr, long arg1, long arg2) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2)
        : "rcx", "r11", "memory",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
    );
    return ret;
}

static inline long sys_chdir(const char *path) {
    return syscall1(80, (long)path);
}

static inline long sys_getcwd(char *buf, size_t size) {
    return syscall2(79, (long)buf, size);
}

static inline long sys_mkdir(const char *path, unsigned int mode) {
    return syscall2(83, (long)path, mode);
}

static inline long sys_rmdir(const char *path) {
    return syscall1(84, (long)path);
}

static inline long sys_unlink(const char *path) {
    return syscall1(87, (long)path);
}

static inline long sys_fork(void) {
    long ret;
    __asm__ __volatile__(
        "int $0x80\n"
        : "=a"(ret)
        : "a"(__NR_fork)
        : "rcx", "r11", "memory",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
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

static inline long sys_getdents64(int fd, void *dirp, unsigned long count) {
    return syscall3(__NR_getdents64, fd, (long)dirp, count);
}

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

/* Write number to stdout */
static void write_num(int num) {
    char buf[32];
    int i = 0;

    if (num == 0) {
        write_char(1, '0');
        return;
    }

    if (num < 0) {
        write_char(1, '-');
        num = -num;
    }

    while (num > 0) {
        buf[i++] = '0' + (num % 10);
        num /= 10;
    }

    /* Reverse the digits */
    for (int j = i - 1; j >= 0; j--) {
        write_char(1, buf[j]);
    }
}

/* Simple read syscall wrapper */
static ssize_t read_bytes(int fd, char *buf, size_t count) {
    return sys_read(fd, buf, count);
}

/* Read a line with interactive editing support (backspace, arrow keys, history) */
static ssize_t read_line(int fd, char *buf, size_t max_len) {
    size_t pos = 0;
    char c;
    ssize_t nread;
    static int current_history_index = -1;  /* -1 means not browsing history */
    static char saved_input[MAX_CMD_LEN];   /* Save current input when browsing history */

    /* Reset history position at start of new line */
    current_history_index = -1;
    saved_input[0] = '\0';

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

        /* Handle escape sequences (arrow keys) */
        if (c == 0x1B) {  /* ESC */
            char seq[2];
            if (read_bytes(fd, &seq[0], 1) <= 0) continue;
            if (seq[0] != '[') continue;
            if (read_bytes(fd, &seq[1], 1) <= 0) continue;

            if (seq[1] == 'A') {  /* Up arrow */
                /* Save current input if this is first history navigation */
                if (current_history_index == -1) {
                    buf[pos] = '\0';
                    strncpy_simple(saved_input, buf, MAX_CMD_LEN);
                    current_history_index = history_count;
                }

                /* Go to previous command */
                if (current_history_index > 0) {
                    current_history_index--;
                    const char *hist = get_history(current_history_index);
                    if (hist) {
                        /* Clear current line */
                        while (pos > 0) {
                            write_char(1, '\b');
                            write_char(1, ' ');
                            write_char(1, '\b');
                            pos--;
                        }
                        /* Copy history entry and display it */
                        pos = 0;
                        while (hist[pos] && pos < max_len - 1) {
                            buf[pos] = hist[pos];
                            write_char(1, buf[pos]);
                            pos++;
                        }
                    }
                }
            } else if (seq[1] == 'B') {  /* Down arrow */
                if (current_history_index != -1) {
                    /* Go to next command */
                    current_history_index++;

                    /* Clear current line */
                    while (pos > 0) {
                        write_char(1, '\b');
                        write_char(1, ' ');
                        write_char(1, '\b');
                        pos--;
                    }

                    if (current_history_index >= history_count) {
                        /* Reached end, restore saved input */
                        current_history_index = -1;
                        pos = 0;
                        while (saved_input[pos] && pos < max_len - 1) {
                            buf[pos] = saved_input[pos];
                            write_char(1, buf[pos]);
                            pos++;
                        }
                    } else {
                        /* Show next history entry */
                        const char *hist = get_history(current_history_index);
                        if (hist) {
                            pos = 0;
                            while (hist[pos] && pos < max_len - 1) {
                                buf[pos] = hist[pos];
                                write_char(1, buf[pos]);
                                pos++;
                            }
                        }
                    }
                }
            }
            continue;
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
        } else if (c == 0x09) {
            /* Tab - command completion */
            buf[pos] = '\0';  /* Null-terminate for completion */
            complete_command(buf, &pos, max_len);
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

/* Add command to history */
static void add_to_history(const char *cmd) {
    /* Don't add empty commands or duplicates of the last command */
    if (!cmd || !cmd[0]) return;
    if (history_count > 0 && strcmp_simple(history[(history_count - 1) % MAX_HISTORY], cmd) == 0) {
        return;
    }

    /* Add to circular buffer */
    int idx = history_count % MAX_HISTORY;
    strncpy_simple(history[idx], cmd, MAX_CMD_LEN);
    history_count++;
}

/* String starts with prefix */
static int starts_with_prefix(const char *str, const char *prefix) {
    while (*prefix) {
        if (*str != *prefix) return 0;
        str++;
        prefix++;
    }
    return 1;
}

/* String length */
static size_t strlen_simple(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

/* Find common prefix length of two strings */
static size_t common_prefix_len(const char *s1, const char *s2) {
    size_t len = 0;
    while (s1[len] && s2[len] && s1[len] == s2[len]) {
        len++;
    }
    return len;
}

/* Tab completion for commands */
static void complete_command(char *buf, size_t *pos, size_t max_len) {
    /* List of builtin commands */
    const char *builtins[] = {
        "bg", "cd", "clear", "echo", "exit", "export", "fg", "help",
        "jobs", "ls", "pwd", "test", "uname", "whoami", NULL
    };

    /* External commands we might have */
    const char *externals[] = {
        "cat", "echo", "fbtest", "fsd", "futurawayd",
        "init", "posixd", "shell", "wc", "winsrv", "winstub", NULL
    };

    const char *prefix = buf;

    /* Find matching commands */
    char matches[64][64];
    int match_count = 0;

    /* Check builtins */
    for (int i = 0; builtins[i] != NULL && match_count < 64; i++) {
        if (starts_with_prefix(builtins[i], prefix)) {
            strncpy_simple(matches[match_count], builtins[i], 64);
            match_count++;
        }
    }

    /* Check external commands */
    for (int i = 0; externals[i] != NULL && match_count < 64; i++) {
        if (starts_with_prefix(externals[i], prefix)) {
            strncpy_simple(matches[match_count], externals[i], 64);
            match_count++;
        }
    }

    if (match_count == 0) {
        /* No matches - do nothing */
        return;
    } else if (match_count == 1) {
        /* Single match - complete it */
        const char *completion = matches[0];
        size_t comp_len = strlen_simple(completion);

        /* Add the rest of the command */
        while (*pos < max_len - 2 && *pos < comp_len) {
            buf[*pos] = completion[*pos];
            write_char(1, buf[*pos]);
            (*pos)++;
        }

        /* Add space after command */
        if (*pos < max_len - 1) {
            buf[*pos] = ' ';
            write_char(1, ' ');
            (*pos)++;
        }
    } else {
        /* Multiple matches - find common prefix */
        size_t common_len = strlen_simple(matches[0]);
        for (int i = 1; i < match_count; i++) {
            size_t cp_len = common_prefix_len(matches[0], matches[i]);
            if (cp_len < common_len) common_len = cp_len;
        }

        /* Complete up to common prefix */
        while (*pos < common_len && *pos < max_len - 1) {
            buf[*pos] = matches[0][*pos];
            write_char(1, buf[*pos]);
            (*pos)++;
        }

        /* If at common prefix, show all matches */
        if (*pos == common_len) {
            write_str(1, "\n");
            for (int i = 0; i < match_count; i++) {
                write_str(1, "  ");
                write_str(1, matches[i]);
                if ((i + 1) % 4 == 0) {
                    write_str(1, "\n");
                } else if (i < match_count - 1) {
                    write_str(1, "  ");
                }
            }
            if (match_count % 4 != 0) {
                write_str(1, "\n");
            }

            /* Reprint prompt and current input */
            write_str(1, "futura> ");
            for (size_t i = 0; i < *pos; i++) {
                write_char(1, buf[i]);
            }
        }
    }
}

/* Get history entry by index (0 = oldest, history_count-1 = newest) */
static const char *get_history(int index) {
    if (index < 0 || index >= history_count) return NULL;
    if (history_count > MAX_HISTORY && index < history_count - MAX_HISTORY) return NULL;
    return history[index % MAX_HISTORY];
}

/* Job management functions */

/* Add a new background job */
static int add_job(pid_t pid, const char *command) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (!jobs[i].used) {
            jobs[i].job_id = next_job_id++;
            jobs[i].pid = pid;
            jobs[i].status = JOB_RUNNING;
            jobs[i].used = 1;
            strncpy_simple(jobs[i].command, command, MAX_CMD_LEN);
            return jobs[i].job_id;
        }
    }
    return -1;  /* No free slots */
}

/* Find job by job ID */
static struct job *find_job(int job_id) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].used && jobs[i].job_id == job_id) {
            return &jobs[i];
        }
    }
    return NULL;
}

/* Update job statuses by checking for finished processes */
static void update_jobs(void) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].used && jobs[i].status == JOB_RUNNING) {
            /* Check if process has finished (non-blocking wait) */
            int status = 0;
            pid_t result = sys_waitpid(jobs[i].pid, &status, 1);  /* WNOHANG = 1 */

            if (result == jobs[i].pid) {
                /* Process has finished */
                jobs[i].status = JOB_DONE;
            }
        }
    }
}

/* Remove a job from the job table */
static void remove_job(int job_id) {
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].used && jobs[i].job_id == job_id) {
            jobs[i].used = 0;
            return;
        }
    }
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
        shell_vars[empty_slot].exported = 0;
    }
}

/* Export a variable (mark it to be passed to child processes) */
static void export_var(const char *name) {
    for (int i = 0; i < MAX_VARS; i++) {
        if (shell_vars[i].used && strcmp_simple(shell_vars[i].name, name) == 0) {
            shell_vars[i].exported = 1;
            return;
        }
    }
    /* If variable doesn't exist, create it with empty value and export it */
    for (int i = 0; i < MAX_VARS; i++) {
        if (!shell_vars[i].used) {
            strncpy_simple(shell_vars[i].name, name, MAX_VAR_NAME);
            shell_vars[i].value[0] = '\0';
            shell_vars[i].used = 1;
            shell_vars[i].exported = 1;
            return;
        }
    }
}

/* Build environment array for execve */
static void build_envp(void) {
    int env_count = 0;

    for (int i = 0; i < MAX_VARS && env_count < MAX_VARS; i++) {
        if (shell_vars[i].used && shell_vars[i].exported) {
            /* Format as "NAME=value" */
            int pos = 0;
            const char *name = shell_vars[i].name;
            while (*name && pos < MAX_VAR_NAME + MAX_VAR_VALUE) {
                env_strings[env_count][pos++] = *name++;
            }
            if (pos < MAX_VAR_NAME + MAX_VAR_VALUE) {
                env_strings[env_count][pos++] = '=';
            }
            const char *value = shell_vars[i].value;
            while (*value && pos < MAX_VAR_NAME + MAX_VAR_VALUE) {
                env_strings[env_count][pos++] = *value++;
            }
            env_strings[env_count][pos] = '\0';

            envp[env_count] = env_strings[env_count];
            env_count++;
        }
    }
    envp[env_count] = NULL;  /* NULL-terminate the array */
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

/* Forward declarations */
static int simple_atoi(const char *str);

/* Built-in: help */
static void cmd_help(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    write_str(1, "Futura OS Shell v0.3 - Available Commands:\n");
    write_str(1, "\n");
    write_str(1, "Navigation:\n");
    write_str(1, "  cd [dir]        - Change directory\n");
    write_str(1, "  pwd             - Print working directory\n");
    write_str(1, "  ls [dir]        - List directory contents\n");
    write_str(1, "  find [path] [-name pattern] [-type f|d] - Search for files recursively\n");
    write_str(1, "  cat <file>      - Display file contents\n");
    write_str(1, "  wc <file>...    - Count lines, words, and bytes\n");
    write_str(1, "  head [-n N] <file>... - Display first N lines (default 10)\n");
    write_str(1, "  tail [-n N] <file>... - Display last N lines (default 10)\n");
    write_str(1, "  grep [-n] [-i] <pattern> <file>... - Search for pattern in files\n");
    write_str(1, "  sort [-r] [-n] <file>... - Sort lines of text\n");
    write_str(1, "\n");
    write_str(1, "File Operations:\n");
    write_str(1, "  mkdir <dir>     - Create directory\n");
    write_str(1, "  rmdir <dir>     - Remove empty directory\n");
    write_str(1, "  touch <file>    - Create empty file\n");
    write_str(1, "  rm <file>       - Remove file\n");
    write_str(1, "  cp <src> <dst>  - Copy file\n");
    write_str(1, "  mv <src> <dst>  - Move/rename file\n");
    write_str(1, "\n");
    write_str(1, "System:\n");
    write_str(1, "  uname           - Print system information\n");
    write_str(1, "  whoami          - Print current user\n");
    write_str(1, "  env             - Show environment variables\n");
    write_str(1, "  echo [args]     - Print text\n");
    write_str(1, "  clear           - Clear screen\n");
    write_str(1, "\n");
    write_str(1, "Shell:\n");
    write_str(1, "  help            - Show this help message\n");
    write_str(1, "  exit [code]     - Exit shell\n");
    write_str(1, "  export VAR=val  - Export environment variable\n");
    write_str(1, "  test / [        - Test conditions (see below)\n");
    write_str(1, "  jobs            - List background jobs\n");
    write_str(1, "  fg [job_id]     - Bring job to foreground\n");
    write_str(1, "  bg [job_id]     - Resume job in background (not supported)\n");
    write_str(1, "\n");
    write_str(1, "Features:\n");
    write_str(1, "  Variables:      VAR=value, $VAR, ${VAR}, $?\n");
    write_str(1, "  Pipelines:      cmd1 | cmd2 | cmd3\n");
    write_str(1, "  Redirection:    cmd > file, cmd >> file, cmd < file\n");
    write_str(1, "  Conditionals:   cmd1 && cmd2, cmd1 || cmd2\n");
    write_str(1, "  Background:     cmd &\n");
    write_str(1, "  History:        Up/down arrow keys\n");
    write_str(1, "  Completion:     Tab key for command completion\n");
    write_str(1, "\n");
    write_str(1, "Test operators:\n");
    write_str(1, "  String:   = != -n -z\n");
    write_str(1, "  Numeric:  -eq -ne -lt -le -gt -ge\n");
    write_str(1, "  File:     -e -f -d\n");
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

/* Built-in: env - Show environment variables */
static void cmd_env(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Iterate through all shell variables and print exported ones */
    for (int i = 0; i < MAX_VARS; i++) {
        if (shell_vars[i].used && shell_vars[i].exported) {
            write_str(1, shell_vars[i].name);
            write_char(1, '=');
            write_str(1, shell_vars[i].value);
            write_char(1, '\n');
        }
    }
}

/* Helper: Convert integer to string */
static void int_to_str(long n, char *buf, int size) {
    int i = 0;
    int is_negative = 0;

    if (n < 0) {
        is_negative = 1;
        n = -n;
    }

    /* Handle zero case */
    if (n == 0) {
        buf[i++] = '0';
        buf[i] = '\0';
        return;
    }

    /* Convert digits in reverse */
    while (n > 0 && i < size - 1) {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    }

    if (is_negative && i < size - 1) {
        buf[i++] = '-';
    }

    buf[i] = '\0';

    /* Reverse the string */
    for (int j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
}

/* Built-in: wc - Count lines, words, and bytes */
static void cmd_wc(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "wc: missing file operand\n");
        write_str(2, "Usage: wc <file>...\n");
        return;
    }

    /* Process each file */
    for (int file_idx = 1; file_idx < argc; file_idx++) {
        const char *path = argv[file_idx];

        /* Open the file */
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "wc: ");
            write_str(2, path);
            write_str(2, ": cannot open file\n");
            continue;
        }

        /* Count lines, words, and bytes */
        long lines = 0;
        long words = 0;
        long bytes = 0;
        int in_word = 0;

        char buffer[256];
        long bytes_read;

        while ((bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
            bytes += bytes_read;

            for (long i = 0; i < bytes_read; i++) {
                char c = buffer[i];

                /* Count newlines */
                if (c == '\n') {
                    lines++;
                }

                /* Count words (whitespace-delimited) */
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    in_word = 0;
                } else if (!in_word) {
                    in_word = 1;
                    words++;
                }
            }
        }

        sys_close(fd);

        if (bytes_read < 0) {
            write_str(2, "wc: ");
            write_str(2, path);
            write_str(2, ": read error\n");
            continue;
        }

        /* Print results: lines words bytes filename */
        char num_buf[32];

        int_to_str(lines, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');

        int_to_str(words, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');

        int_to_str(bytes, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');

        write_str(1, path);
        write_char(1, '\n');
    }
}

/* Built-in: head - Display first N lines of files */
static void cmd_head(int argc, char *argv[]) {
    int num_lines = 10;  /* Default: 10 lines */
    int file_start = 1;

    if (argc < 2) {
        write_str(2, "head: missing file operand\n");
        write_str(2, "Usage: head [-n lines] <file>...\n");
        return;
    }

    /* Parse -n option */
    if (argc >= 3 && strcmp_simple(argv[1], "-n") == 0) {
        num_lines = simple_atoi(argv[2]);
        if (num_lines <= 0) {
            num_lines = 10;
        }
        file_start = 3;
    }

    /* Process each file */
    for (int file_idx = file_start; file_idx < argc; file_idx++) {
        const char *path = argv[file_idx];

        /* Print header if multiple files */
        if (argc - file_start > 1) {
            if (file_idx > file_start) {
                write_char(1, '\n');
            }
            write_str(1, "==> ");
            write_str(1, path);
            write_str(1, " <==\n");
        }

        /* Open the file */
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "head: ");
            write_str(2, path);
            write_str(2, ": cannot open file\n");
            continue;
        }

        /* Read and print first N lines */
        int lines_printed = 0;
        char buffer[256];
        long bytes_read;

        while (lines_printed < num_lines &&
               (bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
            for (long i = 0; i < bytes_read && lines_printed < num_lines; i++) {
                char c = buffer[i];
                write_char(1, c);
                if (c == '\n') {
                    lines_printed++;
                }
            }
        }

        sys_close(fd);

        if (bytes_read < 0) {
            write_str(2, "head: ");
            write_str(2, path);
            write_str(2, ": read error\n");
        }
    }
}

/* Built-in: tail - Display last N lines of files */
static void cmd_tail(int argc, char *argv[]) {
    int num_lines = 10;  /* Default: 10 lines */
    int file_start = 1;

    if (argc < 2) {
        write_str(2, "tail: missing file operand\n");
        write_str(2, "Usage: tail [-n lines] <file>...\n");
        return;
    }

    /* Parse -n option */
    if (argc >= 3 && strcmp_simple(argv[1], "-n") == 0) {
        num_lines = simple_atoi(argv[2]);
        if (num_lines <= 0) {
            num_lines = 10;
        }
        file_start = 3;
    }

    /* Process each file */
    for (int file_idx = file_start; file_idx < argc; file_idx++) {
        const char *path = argv[file_idx];

        /* Print header if multiple files */
        if (argc - file_start > 1) {
            if (file_idx > file_start) {
                write_char(1, '\n');
            }
            write_str(1, "==> ");
            write_str(1, path);
            write_str(1, " <==\n");
        }

        /* Open the file */
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "tail: ");
            write_str(2, path);
            write_str(2, ": cannot open file\n");
            continue;
        }

        /* First pass: read entire file into buffer and count total lines */
        #define MAX_FILE_SIZE 65536  /* 64KB limit for simplicity */
        char *file_buffer = (char *)0x50000000;  /* Use high memory region */
        long total_bytes = 0;
        long bytes_read;
        char chunk[256];

        while ((bytes_read = sys_read(fd, chunk, sizeof(chunk))) > 0) {
            if (total_bytes + bytes_read > MAX_FILE_SIZE) {
                write_str(2, "tail: ");
                write_str(2, path);
                write_str(2, ": file too large\n");
                sys_close(fd);
                goto next_file;
            }
            for (long i = 0; i < bytes_read; i++) {
                file_buffer[total_bytes++] = chunk[i];
            }
        }

        sys_close(fd);

        if (bytes_read < 0) {
            write_str(2, "tail: ");
            write_str(2, path);
            write_str(2, ": read error\n");
            continue;
        }

        /* Count total lines and find line start positions */
        long total_lines = 0;
        for (long i = 0; i < total_bytes; i++) {
            if (file_buffer[i] == '\n') {
                total_lines++;
            }
        }

        /* If file doesn't end with newline, count the last line */
        if (total_bytes > 0 && file_buffer[total_bytes - 1] != '\n') {
            total_lines++;
        }

        /* Calculate how many lines to skip */
        long skip_lines = total_lines > num_lines ? total_lines - num_lines : 0;

        /* Output the last N lines */
        long current_line = 0;
        int started_output = 0;

        for (long i = 0; i < total_bytes; i++) {
            /* Check if we've reached the lines to output */
            if (current_line >= skip_lines) {
                if (!started_output && file_buffer[i] == '\n' && current_line == skip_lines) {
                    /* Skip the newline that ends the skip_lines-th line */
                    current_line++;
                    continue;
                }
                started_output = 1;
                write_char(1, file_buffer[i]);
            }

            if (file_buffer[i] == '\n') {
                current_line++;
            }
        }

        /* Ensure output ends with newline if file didn't */
        if (total_bytes > 0 && file_buffer[total_bytes - 1] != '\n') {
            write_char(1, '\n');
        }

next_file:
        ;  /* Empty statement for label */
    }
}

/* Helper: Simple case-insensitive character comparison */
static int char_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

/* Helper: Case-insensitive string search */
static const char *strstr_case(const char *haystack, const char *needle, int case_insensitive) {
    if (!*needle) return haystack;

    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;

        while (*h && *n) {
            char hc = case_insensitive ? char_tolower(*h) : *h;
            char nc = case_insensitive ? char_tolower(*n) : *n;
            if (hc != nc) break;
            h++;
            n++;
        }

        if (!*n) return haystack;
    }

    return 0;
}

/* Built-in: grep - Search for pattern in files */
static void cmd_grep(int argc, char *argv[]) {
    int show_line_numbers = 0;
    int case_insensitive = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-n") == 0) {
            show_line_numbers = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-i") == 0) {
            case_insensitive = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "grep: unknown option: ");
            write_str(2, argv[arg_start]);
            write_str(2, "\n");
            return;
        }
    }

    if (argc - arg_start < 1) {
        write_str(2, "grep: missing pattern\n");
        write_str(2, "Usage: grep [-n] [-i] <pattern> [file]...\n");
        return;
    }

    const char *pattern = argv[arg_start];
    int file_start = arg_start + 1;
    int multiple_files = (argc - file_start) > 1;

    /* If no files specified, read from stdin - not implemented yet */
    if (argc - file_start == 0) {
        write_str(2, "grep: reading from stdin not yet supported\n");
        return;
    }

    /* Process each file */
    for (int file_idx = file_start; file_idx < argc; file_idx++) {
        const char *path = argv[file_idx];

        /* Open the file */
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "grep: ");
            write_str(2, path);
            write_str(2, ": cannot open file\n");
            continue;
        }

        /* Read file and search for pattern */
        char line_buffer[1024];
        int line_pos = 0;
        long line_number = 0;
        char read_buffer[256];
        long bytes_read;

        while ((bytes_read = sys_read(fd, read_buffer, sizeof(read_buffer))) > 0) {
            for (long i = 0; i < bytes_read; i++) {
                char c = read_buffer[i];

                if (c == '\n' || line_pos >= (int)sizeof(line_buffer) - 1) {
                    line_buffer[line_pos] = '\0';
                    line_number++;

                    /* Search for pattern in line */
                    if (strstr_case(line_buffer, pattern, case_insensitive)) {
                        /* Print filename if multiple files */
                        if (multiple_files) {
                            write_str(1, path);
                            write_char(1, ':');
                        }

                        /* Print line number if requested */
                        if (show_line_numbers) {
                            char num_buf[32];
                            int_to_str(line_number, num_buf, sizeof(num_buf));
                            write_str(1, num_buf);
                            write_char(1, ':');
                        }

                        /* Print the matching line */
                        write_str(1, line_buffer);
                        write_char(1, '\n');
                    }

                    line_pos = 0;
                } else {
                    if (line_pos < (int)sizeof(line_buffer) - 1) {
                        line_buffer[line_pos++] = c;
                    }
                }
            }
        }

        /* Handle last line if file doesn't end with newline */
        if (line_pos > 0) {
            line_buffer[line_pos] = '\0';
            line_number++;

            if (strstr_case(line_buffer, pattern, case_insensitive)) {
                if (multiple_files) {
                    write_str(1, path);
                    write_char(1, ':');
                }

                if (show_line_numbers) {
                    char num_buf[32];
                    int_to_str(line_number, num_buf, sizeof(num_buf));
                    write_str(1, num_buf);
                    write_char(1, ':');
                }

                write_str(1, line_buffer);
                write_char(1, '\n');
            }
        }

        sys_close(fd);

        if (bytes_read < 0) {
            write_str(2, "grep: ");
            write_str(2, path);
            write_str(2, ": read error\n");
        }
    }
}

/* Helper: Simple wildcard pattern matching for find -name */
static int match_pattern(const char *str, const char *pattern) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return 1;  /* Pattern ends with *, match rest */

            /* Try to match the rest of pattern with remaining string */
            while (*str) {
                if (match_pattern(str, pattern)) return 1;
                str++;
            }
            return 0;
        } else if (*pattern == '?') {
            if (!*str) return 0;  /* ? must match exactly one char */
            str++;
            pattern++;
        } else {
            if (*str != *pattern) return 0;
            str++;
            pattern++;
        }
    }
    return !*str;  /* Both must be exhausted */
}

/* Helper: Recursive directory traversal for find */
static void find_recurse(const char *path, const char *name_pattern, int type_filter, int depth) {
    /* Prevent infinite recursion */
    if (depth > 32) {
        return;
    }

    /* Open directory */
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        return;  /* Silently skip directories we can't open */
    }

    /* Define Linux dirent64 structure */
    struct linux_dirent64 {
        unsigned long long d_ino;
        long long d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[256];
    };

    char buf[4096];
    long nread;

    while ((nread = sys_getdents64(fd, buf, sizeof(buf))) > 0) {
        char *ptr = buf;
        while (ptr < buf + nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)ptr;

            /* Skip . and .. */
            if (strcmp_simple(d->d_name, ".") != 0 && strcmp_simple(d->d_name, "..") != 0) {
                /* Build full path */
                char full_path[1024];
                int path_len = 0;

                /* Copy directory path */
                const char *p = path;
                while (*p && path_len < 1023) {
                    full_path[path_len++] = *p++;
                }

                /* Add separator if needed */
                if (path_len > 0 && full_path[path_len - 1] != '/') {
                    full_path[path_len++] = '/';
                }

                /* Copy entry name */
                p = d->d_name;
                while (*p && path_len < 1023) {
                    full_path[path_len++] = *p++;
                }
                full_path[path_len] = '\0';

                /* Check if this entry matches our filters */
                int type_match = 1;
                if (type_filter == 'f') {
                    type_match = (d->d_type != 4);  /* DT_DIR = 4 */
                } else if (type_filter == 'd') {
                    type_match = (d->d_type == 4);  /* DT_DIR = 4 */
                }

                int name_match = 1;
                if (name_pattern) {
                    name_match = match_pattern(d->d_name, name_pattern);
                }

                /* Print if matches all filters */
                if (type_match && name_match) {
                    write_str(1, full_path);
                    write_str(1, "\n");
                }

                /* Recurse into subdirectories */
                if (d->d_type == 4) {  /* DT_DIR = 4 */
                    find_recurse(full_path, name_pattern, type_filter, depth + 1);
                }
            }

            ptr += d->d_reclen;
        }
    }

    sys_close(fd);
}

/* Built-in: find - Search for files in directory hierarchy */
static void cmd_find(int argc, char *argv[]) {
    const char *start_path = ".";
    const char *name_pattern = 0;
    int type_filter = 0;  /* 0 = all, 'f' = files, 'd' = directories */
    int arg_idx = 1;

    /* If first arg doesn't start with -, it's the path */
    if (arg_idx < argc && argv[arg_idx][0] != '-') {
        start_path = argv[arg_idx];
        arg_idx++;
    }

    /* Parse options */
    while (arg_idx < argc) {
        if (strcmp_simple(argv[arg_idx], "-name") == 0) {
            if (arg_idx + 1 >= argc) {
                write_str(2, "find: -name requires an argument\n");
                return;
            }
            name_pattern = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-type") == 0) {
            if (arg_idx + 1 >= argc) {
                write_str(2, "find: -type requires an argument\n");
                return;
            }
            if (strcmp_simple(argv[arg_idx + 1], "f") == 0) {
                type_filter = 'f';
            } else if (strcmp_simple(argv[arg_idx + 1], "d") == 0) {
                type_filter = 'd';
            } else {
                write_str(2, "find: -type must be 'f' or 'd'\n");
                return;
            }
            arg_idx += 2;
        } else {
            write_str(2, "find: unknown option: ");
            write_str(2, argv[arg_idx]);
            write_str(2, "\n");
            write_str(2, "Usage: find [path] [-name pattern] [-type f|d]\n");
            return;
        }
    }

    /* Print the starting directory if it matches filters */
    if (type_filter == 0 || type_filter == 'd') {
        if (!name_pattern || match_pattern(start_path, name_pattern)) {
            write_str(1, start_path);
            write_str(1, "\n");
        }
    }

    /* Start recursive search */
    find_recurse(start_path, name_pattern, type_filter, 0);
}

/* Helper: Simple string comparison for sorting */
static int str_compare(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (*s1 != *s2) {
            return (*s1 < *s2) ? -1 : 1;
        }
        s1++;
        s2++;
    }
    if (*s1) return 1;
    if (*s2) return -1;
    return 0;
}

/* Helper: Numerical string comparison for sorting */
static int str_compare_numeric(const char *s1, const char *s2) {
    long n1 = 0, n2 = 0;
    int neg1 = 0, neg2 = 0;

    /* Parse first number */
    if (*s1 == '-') {
        neg1 = 1;
        s1++;
    }
    while (*s1 >= '0' && *s1 <= '9') {
        n1 = n1 * 10 + (*s1 - '0');
        s1++;
    }
    if (neg1) n1 = -n1;

    /* Parse second number */
    if (*s2 == '-') {
        neg2 = 1;
        s2++;
    }
    while (*s2 >= '0' && *s2 <= '9') {
        n2 = n2 * 10 + (*s2 - '0');
        s2++;
    }
    if (neg2) n2 = -n2;

    if (n1 < n2) return -1;
    if (n1 > n2) return 1;
    return 0;
}

/* Built-in: sort - Sort lines of text */
static void cmd_sort(int argc, char *argv[]) {
    int reverse = 0;
    int numeric = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-r") == 0) {
            reverse = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-n") == 0) {
            numeric = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "sort: unknown option: ");
            write_str(2, argv[arg_start]);
            write_str(2, "\n");
            write_str(2, "Usage: sort [-r] [-n] [file]...\n");
            return;
        }
    }

    /* Allocate buffer for all lines */
    #define MAX_LINES 1000
    #define MAX_LINE_LENGTH 1024
    static char line_buffer[MAX_LINES][MAX_LINE_LENGTH];
    char *lines[MAX_LINES];
    int line_count = 0;

    /* Read from files or stdin */
    if (arg_start >= argc) {
        /* Read from stdin - not yet supported */
        write_str(2, "sort: reading from stdin not yet supported\n");
        return;
    }

    /* Process each file */
    for (int file_idx = arg_start; file_idx < argc; file_idx++) {
        const char *path = argv[file_idx];

        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "sort: ");
            write_str(2, path);
            write_str(2, ": cannot open file\n");
            continue;
        }

        /* Read file line by line */
        char read_buf[256];
        int line_pos = 0;
        long bytes_read;

        while ((bytes_read = sys_read(fd, read_buf, sizeof(read_buf))) > 0) {
            for (long i = 0; i < bytes_read; i++) {
                char c = read_buf[i];

                if (c == '\n' || line_pos >= MAX_LINE_LENGTH - 1) {
                    if (line_count < MAX_LINES) {
                        line_buffer[line_count][line_pos] = '\0';
                        lines[line_count] = line_buffer[line_count];
                        line_count++;
                    }
                    line_pos = 0;
                } else {
                    if (line_count < MAX_LINES) {
                        line_buffer[line_count][line_pos++] = c;
                    }
                }
            }
        }

        /* Handle last line if file doesn't end with newline */
        if (line_pos > 0 && line_count < MAX_LINES) {
            line_buffer[line_count][line_pos] = '\0';
            lines[line_count] = line_buffer[line_count];
            line_count++;
        }

        sys_close(fd);

        if (bytes_read < 0) {
            write_str(2, "sort: ");
            write_str(2, path);
            write_str(2, ": read error\n");
        }
    }

    /* Sort lines using bubble sort */
    for (int i = 0; i < line_count - 1; i++) {
        for (int j = 0; j < line_count - i - 1; j++) {
            int cmp;
            if (numeric) {
                cmp = str_compare_numeric(lines[j], lines[j + 1]);
            } else {
                cmp = str_compare(lines[j], lines[j + 1]);
            }

            /* Reverse comparison if -r flag is set */
            if (reverse) {
                cmp = -cmp;
            }

            if (cmp > 0) {
                /* Swap */
                char *temp = lines[j];
                lines[j] = lines[j + 1];
                lines[j + 1] = temp;
            }
        }
    }

    /* Output sorted lines */
    for (int i = 0; i < line_count; i++) {
        write_str(1, lines[i]);
        write_char(1, '\n');
    }
}

/* Built-in: ls - List directory contents */
static void cmd_ls(int argc, char *argv[]) {
    const char *path = argc > 1 ? argv[1] : ".";

    /* Open the directory */
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "ls: cannot open directory ");
        write_str(2, path);
        write_str(2, "\n");
        return;
    }

    /* Define Linux dirent64 structure matching kernel implementation */
    struct linux_dirent64 {
        unsigned long long d_ino;
        long long d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[256];
    };

    char buf[4096];
    long nread;

    while ((nread = sys_getdents64(fd, buf, sizeof(buf))) > 0) {
        char *ptr = buf;
        while (ptr < buf + nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)ptr;

            /* Print entry name */
            write_str(1, d->d_name);
            write_str(1, "\n");

            /* Move to next entry */
            ptr += d->d_reclen;
        }
    }

    if (nread < 0) {
        write_str(2, "ls: error reading directory\n");
    }

    sys_close(fd);
}

/* Built-in: cat - Display file contents */
static void cmd_cat(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "cat: missing file operand\n");
        write_str(2, "Usage: cat <file>\n");
        return;
    }

    const char *path = argv[1];

    /* Open the file */
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "cat: ");
        write_str(2, path);
        write_str(2, ": cannot open file\n");
        return;
    }

    /* Read and print file contents in chunks */
    char buffer[256];
    long bytes_read;

    while ((bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
        /* Write chunk to stdout */
        long written = 0;
        while (written < bytes_read) {
            long n = sys_write(1, buffer + written, bytes_read - written);
            if (n <= 0) {
                write_str(2, "cat: write error\n");
                sys_close(fd);
                return;
            }
            written += n;
        }
    }

    if (bytes_read < 0) {
        write_str(2, "cat: read error\n");
    }

    sys_close(fd);
}

/* Built-in: mkdir - Create a directory */
static void cmd_mkdir(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "mkdir: missing operand\n");
        write_str(2, "Usage: mkdir <directory>\n");
        return;
    }

    const char *path = argv[1];

    /* Create the directory with default permissions (0755) */
    long ret = sys_mkdir(path, 0755);
    if (ret < 0) {
        write_str(2, "mkdir: cannot create directory '");
        write_str(2, path);
        write_str(2, "'\n");
    }
}

/* Built-in: rmdir - Remove an empty directory */
static void cmd_rmdir(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "rmdir: missing operand\n");
        write_str(2, "Usage: rmdir <directory>\n");
        return;
    }

    const char *path = argv[1];

    long ret = sys_rmdir(path);
    if (ret < 0) {
        write_str(2, "rmdir: failed to remove '");
        write_str(2, path);
        write_str(2, "'\n");
    }
}

/* Built-in: rm - Remove a file */
static void cmd_rm(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "rm: missing operand\n");
        write_str(2, "Usage: rm <file>\n");
        return;
    }

    const char *path = argv[1];

    long ret = sys_unlink(path);
    if (ret < 0) {
        write_str(2, "rm: cannot remove '");
        write_str(2, path);
        write_str(2, "'\n");
    }
}

/* Built-in: touch */
static void cmd_touch(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "touch: missing file operand\n");
        write_str(2, "Usage: touch <file>\n");
        return;
    }

    const char *path = argv[1];

    /* Create file by opening with O_CREAT and then closing */
    int fd = sys_open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
        write_str(2, "touch: cannot touch '");
        write_str(2, path);
        write_str(2, "'\n");
        return;
    }

    /* Close the file immediately */
    sys_close(fd);
}

/* Built-in: cp */
static void cmd_cp(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "cp: missing operand\n");
        write_str(2, "Usage: cp <source> <dest>\n");
        return;
    }

    const char *src_path = argv[1];
    const char *dst_path = argv[2];

    /* Open source file for reading */
    int src_fd = sys_open(src_path, O_RDONLY, 0);
    if (src_fd < 0) {
        write_str(2, "cp: cannot open '");
        write_str(2, src_path);
        write_str(2, "'\n");
        return;
    }

    /* Open destination file for writing (create if needed) */
    int dst_fd = sys_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        write_str(2, "cp: cannot create '");
        write_str(2, dst_path);
        write_str(2, "'\n");
        sys_close(src_fd);
        return;
    }

    /* Copy data from source to destination */
    char buffer[4096];
    long bytes_read;
    while ((bytes_read = sys_read(src_fd, buffer, sizeof(buffer))) > 0) {
        long total_written = 0;
        while (total_written < bytes_read) {
            long written = sys_write(dst_fd, buffer + total_written, bytes_read - total_written);
            if (written <= 0) {
                write_str(2, "cp: write error\n");
                sys_close(src_fd);
                sys_close(dst_fd);
                return;
            }
            total_written += written;
        }
    }

    if (bytes_read < 0) {
        write_str(2, "cp: read error\n");
    }

    sys_close(src_fd);
    sys_close(dst_fd);
}

/* Built-in: mv - Move/rename a file */
static void cmd_mv(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "mv: missing operand\n");
        write_str(2, "Usage: mv <source> <dest>\n");
        return;
    }

    const char *src_path = argv[1];
    const char *dst_path = argv[2];

    /* Open source file for reading */
    int src_fd = sys_open(src_path, O_RDONLY, 0);
    if (src_fd < 0) {
        write_str(2, "mv: cannot open '");
        write_str(2, src_path);
        write_str(2, "'\n");
        return;
    }

    /* Open destination file for writing (create if needed) */
    int dst_fd = sys_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        write_str(2, "mv: cannot create '");
        write_str(2, dst_path);
        write_str(2, "'\n");
        sys_close(src_fd);
        return;
    }

    /* Copy data from source to destination */
    char buffer[4096];
    long bytes_read;
    int copy_failed = 0;
    while ((bytes_read = sys_read(src_fd, buffer, sizeof(buffer))) > 0) {
        long total_written = 0;
        while (total_written < bytes_read) {
            long written = sys_write(dst_fd, buffer + total_written, bytes_read - total_written);
            if (written <= 0) {
                write_str(2, "mv: write error\n");
                copy_failed = 1;
                break;
            }
            total_written += written;
        }
        if (copy_failed) break;
    }

    if (bytes_read < 0) {
        write_str(2, "mv: read error\n");
        copy_failed = 1;
    }

    sys_close(src_fd);
    sys_close(dst_fd);

    /* Only delete source if copy was successful */
    if (!copy_failed) {
        long ret = sys_unlink(src_path);
        if (ret < 0) {
            write_str(2, "mv: cannot remove '");
            write_str(2, src_path);
            write_str(2, "'\n");
        }
    }
}

/* Built-in: export */
static void cmd_export(int argc, char *argv[]) {
    if (argc < 2) {
        /* No arguments - list all exported variables */
        write_str(1, "Exported variables:\n");
        for (int i = 0; i < MAX_VARS; i++) {
            if (shell_vars[i].used && shell_vars[i].exported) {
                write_str(1, "  ");
                write_str(1, shell_vars[i].name);
                write_str(1, "=");
                write_str(1, shell_vars[i].value);
                write_str(1, "\n");
            }
        }
        return;
    }

    /* Export each variable listed */
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        /* Check if it's NAME=value format */
        const char *eq = arg;
        while (*eq && *eq != '=') eq++;

        if (*eq == '=') {
            /* Assignment: export NAME=value */
            char name[MAX_VAR_NAME];
            char value[MAX_VAR_VALUE];
            int name_len = 0;

            /* Extract name */
            const char *p = arg;
            while (*p != '=' && name_len < MAX_VAR_NAME - 1) {
                name[name_len++] = *p++;
            }
            name[name_len] = '\0';
            p++;  /* Skip '=' */

            /* Extract value */
            int value_len = 0;
            while (*p && value_len < MAX_VAR_VALUE - 1) {
                value[value_len++] = *p++;
            }
            value[value_len] = '\0';

            /* Expand variables in value */
            char expanded_value[MAX_VAR_VALUE];
            expand_variables(expanded_value, value, MAX_VAR_VALUE);

            /* Set and export */
            set_var(name, expanded_value);
            export_var(name);
        } else {
            /* Just export existing variable */
            export_var(arg);
        }
    }
}

/* Helper: Simple atoi */
static int simple_atoi(const char *str) {
    int result = 0;
    int sign = 1;

    if (*str == '-') {
        sign = -1;
        str++;
    }

    while (*str >= '0' && *str <= '9') {
        result = result * 10 + (*str - '0');
        str++;
    }

    return result * sign;
}

/* Built-in: test - evaluate conditional expressions */
static int cmd_test(int argc, char *argv[]) {
    /* Handle [ command - last arg should be ] */
    int is_bracket = (strcmp_simple(argv[0], "[") == 0);
    if (is_bracket) {
        if (argc < 2 || strcmp_simple(argv[argc - 1], "]") != 0) {
            write_str(2, "test: missing ']'\n");
            return 1;
        }
        argc--;  /* Remove the ']' from consideration */
    }

    /* No arguments: false */
    if (argc == 1) {
        return 1;
    }

    /* Single argument: true if non-empty string */
    if (argc == 2) {
        return (argv[1][0] == '\0') ? 1 : 0;
    }

    /* Two arguments: unary operators */
    if (argc == 3) {
        const char *op = argv[1];
        const char *arg = argv[2];

        if (strcmp_simple(op, "-n") == 0) {
            /* String is not empty */
            return (arg[0] == '\0') ? 1 : 0;
        } else if (strcmp_simple(op, "-z") == 0) {
            /* String is empty */
            return (arg[0] == '\0') ? 0 : 1;
        } else if (strcmp_simple(op, "-e") == 0 || strcmp_simple(op, "-f") == 0) {
            /* File exists (we don't have stat yet, so just try to open) */
            int fd = sys_open(arg, 0, 0);
            if (fd >= 0) {
                sys_close(fd);
                return 0;
            }
            return 1;
        } else if (strcmp_simple(op, "-d") == 0) {
            /* Directory exists (simplified - just check if we can open) */
            int fd = sys_open(arg, 0, 0);
            if (fd >= 0) {
                sys_close(fd);
                return 0;
            }
            return 1;
        } else if (strcmp_simple(op, "!") == 0) {
            /* Logical NOT */
            return (arg[0] == '\0') ? 0 : 1;
        }
    }

    /* Three arguments: binary operators */
    if (argc == 4) {
        const char *left = argv[1];
        const char *op = argv[2];
        const char *right = argv[3];

        /* String comparisons */
        if (strcmp_simple(op, "=") == 0 || strcmp_simple(op, "==") == 0) {
            return strcmp_simple(left, right) == 0 ? 0 : 1;
        } else if (strcmp_simple(op, "!=") == 0) {
            return strcmp_simple(left, right) != 0 ? 0 : 1;
        }

        /* Numeric comparisons */
        int left_num = simple_atoi(left);
        int right_num = simple_atoi(right);

        if (strcmp_simple(op, "-eq") == 0) {
            return (left_num == right_num) ? 0 : 1;
        } else if (strcmp_simple(op, "-ne") == 0) {
            return (left_num != right_num) ? 0 : 1;
        } else if (strcmp_simple(op, "-lt") == 0) {
            return (left_num < right_num) ? 0 : 1;
        } else if (strcmp_simple(op, "-le") == 0) {
            return (left_num <= right_num) ? 0 : 1;
        } else if (strcmp_simple(op, "-gt") == 0) {
            return (left_num > right_num) ? 0 : 1;
        } else if (strcmp_simple(op, "-ge") == 0) {
            return (left_num >= right_num) ? 0 : 1;
        }
    }

    write_str(2, "test: invalid expression\n");
    return 1;
}

/* Built-in: jobs - list background jobs */
static void cmd_jobs(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Update job statuses first */
    update_jobs();

    int has_jobs = 0;
    for (int i = 0; i < MAX_JOBS; i++) {
        if (jobs[i].used) {
            has_jobs = 1;
            write_str(1, "[");
            write_num(jobs[i].job_id);
            write_str(1, "]  ");

            /* Show status */
            if (jobs[i].status == JOB_RUNNING) {
                write_str(1, "Running");
            } else if (jobs[i].status == JOB_DONE) {
                write_str(1, "Done   ");
            } else if (jobs[i].status == JOB_STOPPED) {
                write_str(1, "Stopped");
            }

            write_str(1, "  ");
            write_str(1, jobs[i].command);
            write_str(1, "\n");

            /* Clean up done jobs */
            if (jobs[i].status == JOB_DONE) {
                remove_job(jobs[i].job_id);
            }
        }
    }

    if (!has_jobs) {
        write_str(1, "No background jobs\n");
    }
}

/* Built-in: fg - bring job to foreground */
static void cmd_fg(int argc, char *argv[]) {
    /* Update job statuses first */
    update_jobs();

    struct job *j = NULL;

    if (argc < 2) {
        /* Find most recent job */
        int max_id = 0;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (jobs[i].used && jobs[i].job_id > max_id) {
                max_id = jobs[i].job_id;
                j = &jobs[i];
            }
        }

        if (!j) {
            write_str(2, "fg: no current job\n");
            return;
        }
    } else {
        /* Get job ID from argument */
        int job_id = simple_atoi(argv[1]);
        j = find_job(job_id);

        if (!j) {
            write_str(2, "fg: job not found: ");
            write_str(2, argv[1]);
            write_str(2, "\n");
            return;
        }
    }

    if (j->status == JOB_DONE) {
        write_str(1, "Job already done\n");
        remove_job(j->job_id);
        return;
    }

    /* Wait for the job to complete */
    write_str(1, j->command);
    write_str(1, "\n");

    int status = 0;
    sys_waitpid(j->pid, &status, 0);

    /* Remove from job table */
    remove_job(j->job_id);
}

/* Built-in: bg - resume job in background */
static void cmd_bg(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    /* Without proper signal support (SIGCONT), we can't resume stopped jobs */
    write_str(2, "bg: not supported (no SIGCONT support)\n");
}

/* Execute a command */
static int execute_command(int argc, char *argv[]) {
    if (argc == 0) return 0;

    if (strcmp_simple(argv[0], "help") == 0) {
        cmd_help(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "pwd") == 0) {
        cmd_pwd(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cd") == 0) {
        cmd_cd(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "echo") == 0) {
        cmd_echo(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "clear") == 0) {
        cmd_clear(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "uname") == 0) {
        cmd_uname(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "whoami") == 0) {
        cmd_whoami(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "env") == 0) {
        cmd_env(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "wc") == 0) {
        cmd_wc(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "head") == 0) {
        cmd_head(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tail") == 0) {
        cmd_tail(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "grep") == 0) {
        cmd_grep(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "sort") == 0) {
        cmd_sort(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "find") == 0) {
        cmd_find(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "ls") == 0) {
        cmd_ls(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cat") == 0) {
        cmd_cat(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "mkdir") == 0) {
        cmd_mkdir(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "rmdir") == 0) {
        cmd_rmdir(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "rm") == 0) {
        cmd_rm(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "touch") == 0) {
        cmd_touch(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cp") == 0) {
        cmd_cp(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "mv") == 0) {
        cmd_mv(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "echo") == 0) {
        cmd_echo(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "export") == 0) {
        cmd_export(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "test") == 0 || strcmp_simple(argv[0], "[") == 0) {
        return cmd_test(argc, argv);
    } else if (strcmp_simple(argv[0], "jobs") == 0) {
        cmd_jobs(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "fg") == 0) {
        cmd_fg(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "bg") == 0) {
        cmd_bg(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "exit") == 0) {
        int status = 0;
        if (argc > 1) {
            status = simple_atoi(argv[1]);
        }
        write_str(1, "Goodbye!\n");
        syscall1(60, status);
        while (1);
    } else {
        write_str(1, "Command not found: ");
        write_str(1, argv[0]);
        write_str(1, " (type 'help' for available commands)\n");
        return 1;
    }
}

/* Check if a command is a shell builtin */
static int is_builtin(const char *cmd) {
    return (strcmp_simple(cmd, "cd") == 0 ||
            strcmp_simple(cmd, "exit") == 0 ||
            strcmp_simple(cmd, "help") == 0 ||
            strcmp_simple(cmd, "pwd") == 0 ||
            strcmp_simple(cmd, "ls") == 0 ||
            strcmp_simple(cmd, "echo") == 0 ||
            strcmp_simple(cmd, "clear") == 0 ||
            strcmp_simple(cmd, "uname") == 0 ||
            strcmp_simple(cmd, "whoami") == 0 ||
            strcmp_simple(cmd, "export") == 0 ||
            strcmp_simple(cmd, "test") == 0 ||
            strcmp_simple(cmd, "[") == 0 ||
            strcmp_simple(cmd, "jobs") == 0 ||
            strcmp_simple(cmd, "fg") == 0 ||
            strcmp_simple(cmd, "bg") == 0);
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

    /* Build environment array */
    build_envp();

    /* If command contains '/', use as-is (absolute or relative path) */
    if (starts_with(cmd, '/')) {
        /* Absolute path */
        sys_execve(cmd, argv, envp);
    } else {
        /* Try to find in /bin/user/ */
        strcpy_simple(path_buf, "/bin/user/");
        strcat_simple(path_buf, cmd);
        sys_execve(path_buf, argv, envp);
    }

    /* If execve returns, it failed */
    write_str(2, "Error: Failed to execute '");
    write_str(2, cmd);
    write_str(2, "'\n");
    syscall1(__NR_exit, 1);
}

/* Execute a pipeline of commands */
static int execute_pipeline(int num_stages, char *stages[], int background, const char *cmdtext) {
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
                /* Builtins cannot be backgrounded */
                if (background) {
                    write_str(2, "Warning: Cannot background builtin commands\n");
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

                /* Parent: wait for child or add to background jobs */
                if (background) {
                    int job_id = add_job(pid, cmdtext);
                    write_str(1, "[");
                    write_num(job_id);
                    write_str(1, "] ");
                    write_num(pid);
                    write_str(1, "\n");
                    return 0;
                } else {
                    int status = 0;
                    sys_waitpid(pid, &status, 0);
                    return 0;
                }
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

    /* Wait for all children or add last one to background jobs */
    if (background) {
        /* For pipelines, add the last process to jobs (the whole pipeline) */
        int job_id = add_job(pids[num_stages - 1], cmdtext);
        write_str(1, "[");
        write_num(job_id);
        write_str(1, "] ");
        write_num(pids[num_stages - 1]);
        write_str(1, "\n");

        /* Still need to wait for other processes in the pipeline to avoid zombies */
        for (int i = 0; i < num_stages - 1; i++) {
            int status = 0;
            sys_waitpid(pids[i], &status, 1);  /* WNOHANG */
        }
    } else {
        for (int i = 0; i < num_stages; i++) {
            int status = 0;
            sys_waitpid(pids[i], &status, 0);
        }
    }

    return 0;
}

/* Parse and execute command chain with && and || operators */
static int execute_command_chain(char *cmdline) {
    /* Parse command chain into segments separated by && or || */
    char *segments[32];
    int operators[32];  /* 0 = &&, 1 = || */
    int num_segments = 0;
    char *p = cmdline;
    char *segment_start = cmdline;

    while (*p && num_segments < 31) {
        if (p[0] == '&' && p[1] == '&') {
            /* Found && operator */
            *p = '\0';  /* Null-terminate current segment */
            segments[num_segments] = segment_start;
            operators[num_segments] = 0;  /* && */
            num_segments++;
            p += 2;
            /* Skip whitespace */
            while (*p == ' ' || *p == '\t') p++;
            segment_start = p;
        } else if (p[0] == '|' && p[1] == '|') {
            /* Found || operator */
            *p = '\0';  /* Null-terminate current segment */
            segments[num_segments] = segment_start;
            operators[num_segments] = 1;  /* || */
            num_segments++;
            p += 2;
            /* Skip whitespace */
            while (*p == ' ' || *p == '\t') p++;
            segment_start = p;
        } else {
            p++;
        }
    }

    /* Add the last segment */
    segments[num_segments] = segment_start;
    num_segments++;

    /* Execute each segment based on operators */
    int last_status = 0;
    for (int i = 0; i < num_segments; i++) {
        /* Check if we should execute this segment */
        if (i > 0) {
            if (operators[i - 1] == 0) {  /* && */
                if (last_status != 0) {
                    /* Previous command failed, skip rest of && chain */
                    continue;
                }
            } else {  /* || */
                if (last_status == 0) {
                    /* Previous command succeeded, skip || alternative */
                    continue;
                }
            }
        }

        /* Check for background execution (&) */
        int background = 0;
        char *seg = segments[i];
        char *end = seg;
        while (*end) end++;
        end--;  /* Point to last character */

        /* Trim trailing whitespace */
        while (end >= seg && (*end == ' ' || *end == '\t')) {
            end--;
        }

        /* Check for & */
        if (end >= seg && *end == '&') {
            background = 1;
            *end = '\0';  /* Remove & from command */
            end--;
            /* Trim whitespace before & */
            while (end >= seg && (*end == ' ' || *end == '\t')) {
                *end = '\0';
                end--;
            }
        }

        /* Execute this segment as a pipeline */
        char *pipeline_stages[10];
        int num_stages = parse_pipeline(segments[i], pipeline_stages, 10);
        if (num_stages > 0) {
            last_status = execute_pipeline(num_stages, pipeline_stages, background, segments[i]);
        }
    }

    return last_status;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    write_str(1, "\n");
    write_str(1, "╔════════════════════════════════════════╗\n");
    write_str(1, "║   Futura OS Shell v0.3                 ║\n");
    write_str(1, "║   Type 'help' for available commands   ║\n");
    write_str(1, "╚════════════════════════════════════════╝\n");
    write_str(1, "\n");

    char cmdline[512];
    ssize_t nread;

    while (1) {
        /* Update background job statuses */
        update_jobs();

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

        /* Add command to history */
        add_to_history(cmdline);

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

        /* Execute command chain (handles &&, ||, and pipelines) */
        int status = execute_command_chain(expanded_cmdline);
        last_exit_status = (status < 0) ? 1 : 0;
    }

    write_str(1, "\nShell terminated\n");
    return 0;
}

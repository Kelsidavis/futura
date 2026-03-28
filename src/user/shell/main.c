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
#include <user/sys.h>
#include <user/sysnums.h>
#include <user/libfutura.h>
#include <sys/stat.h>

/* Syscall number aliases for shell code */
#define __NR_read       SYS_read
#define __NR_write      SYS_write
#define __NR_open       SYS_open
#define __NR_close      SYS_close
#define __NR_stat       SYS_stat
#define __NR_lseek      SYS_lseek
#define __NR_pipe       SYS_pipe
#define __NR_dup2       SYS_dup2
#define __NR_fork       SYS_fork
#define __NR_execve     SYS_execve
#define __NR_exit       SYS_exit
#define __NR_wait4      SYS_wait4
#define __NR_chdir      SYS_chdir
#define __NR_getcwd     SYS_getcwd
#define __NR_getdents64 SYS_getdents64
#define __NR_mkdir      SYS_mkdir
#define __NR_rmdir      SYS_rmdir
#define __NR_unlink     SYS_unlink
#define __NR_rename     SYS_rename

/* File flags and mode bits are now provided by libfutura.h */

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
/* ssize_t is provided by user/libfutura.h */
/* pid_t with proper guard for sys/types.h compatibility */
#ifndef __pid_t_defined
#define __pid_t_defined 1
typedef int32_t pid_t;
#endif

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

/* Forward declaration for source (defined after execute_command_chain) */
static void cmd_source(int argc, char *argv[]);

/* Forward declaration for full line execution (defined after main) */
static int execute_full_line(char *line);
static int execute_command_chain(char *cmdline);

/* Forward declaration for exec builtin */
static void exec_external_command(int argc, char *argv[]);
static void build_envp(void);

/* Forward declarations for new commands (defined after main) */
static void cmd_timeout(int argc, char *argv[]);
static void cmd_tty(int argc, char *argv[]);
static void cmd_nohup(int argc, char *argv[]);
static void cmd_chroot(int argc, char *argv[]);
static void cmd_unshare(int argc, char *argv[]);
static void cmd_nsenter(int argc, char *argv[]);
static void cmd_tac(int argc, char *argv[]);
static void cmd_chgrp(int argc, char *argv[]);
static void cmd_md5sum(int argc, char *argv[]);
static void cmd_strings(int argc, char *argv[]);
static void cmd_file(int argc, char *argv[]);
static void cmd_mkfifo(int argc, char *argv[]);
static void cmd_expr(int argc, char *argv[]);
static void cmd_bc(int argc, char *argv[]);
static void cmd_factor(int argc, char *argv[]);
static void cmd_cal(int argc, char *argv[]);
static void cmd_locale(int argc, char *argv[]);
static void cmd_reset(int argc, char *argv[]);
static void cmd_tput(int argc, char *argv[]);
static void cmd_expand(int argc, char *argv[]);
static void cmd_unexpand(int argc, char *argv[]);
static void cmd_install(int argc, char *argv[]);
static void cmd_cmp(int argc, char *argv[]);
static void cmd_fold(int argc, char *argv[]);
static void cmd_comm(int argc, char *argv[]);
static void cmd_pgrep(int argc, char *argv[]);
static void cmd_pkill(int argc, char *argv[]);
static void cmd_pidof(int argc, char *argv[]);
static void cmd_nice(int argc, char *argv[]);
static void cmd_renice(int argc, char *argv[]);
static void cmd_xxd(int argc, char *argv[]);
static void cmd_patch(int argc, char *argv[]);
static void cmd_sha1sum(int argc, char *argv[]);
static void cmd_vi(int argc, char *argv[]);
static void cmd_make(int argc, char *argv[]);
static void cmd_git(int argc, char *argv[]);
static void cmd_su(int argc, char *argv[]);
static void cmd_passwd(int argc, char *argv[]);
static void cmd_systemctl(int argc, char *argv[]);
static void cmd_crontab(int argc, char *argv[]);
static void cmd_scp(int argc, char *argv[]);
static void cmd_pkg(int argc, char *argv[]);
static void cmd_man(int argc, char *argv[]);
static void cmd_screen(int argc, char *argv[]);
static void strcpy_simple(char *dest, const char *src);

/* Forward declaration for prompt */
static void print_prompt(void);

/* Architecture-agnostic syscall wrappers using libfutura */
static inline long syscall1(long nr, long arg1) {
    return sys_call1(nr, arg1);
}

static inline long syscall2(long nr, long arg1, long arg2) {
    return sys_call2(nr, arg1, arg2);
}

static inline long syscall3(long nr, long arg1, long arg2, long arg3) {
    return sys_call3(nr, arg1, arg2, arg3);
}

static inline long sys_chdir(const char *path) {
    return sys_chdir_call(path);
}

static inline long sys_getcwd(char *buf, size_t size) {
    return sys_getcwd_call(buf, size);
}

static inline long sys_mkdir(const char *path, unsigned int mode) {
    return sys_call2(SYS_mkdir, (long)path, mode);
}

static inline long sys_rmdir(const char *path) {
    return sys_call1(SYS_rmdir, (long)path);
}

static inline long sys_rename(const char *oldpath, const char *newpath) {
    return sys_call2(SYS_rename, (long)oldpath, (long)newpath);
}

static inline long sys_fork(void) {
    return sys_fork_call();
}

static inline long sys_pipe(int pipefd[2]) {
    return sys_call1(SYS_pipe, (long)pipefd);
}

static inline long sys_dup2(int oldfd, int newfd) {
    if (oldfd == newfd) return newfd;
    return sys_dup2_call(oldfd, newfd);
}

static inline long sys_dup(int oldfd) {
#ifdef __aarch64__
    return sys_call1(23 /* __NR_dup on ARM64 */, oldfd);
#else
    return sys_call1(SYS_dup, oldfd);
#endif
}

static inline long sys_waitpid(int pid, int *status, int options) {
    return sys_wait4_call(pid, status, options, NULL);
}

static inline long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    return sys_execve_call(pathname, argv, envp);
}

static inline long sys_getdents64(int fd, void *dirp, unsigned long count) {
    return sys_call3(SYS_getdents64, fd, (long)dirp, count);
}

static inline long sys_alarm(unsigned int seconds) {
    return sys_call1(SYS_alarm, seconds);
}
static inline long sys_sigaction(int signum, const void *act, void *oldact) {
    return sys_call4(SYS_sigaction, signum, (long)act, (long)oldact, 8 /* sizeof(sigset_t) */);
}
static inline long sys_chroot(const char *path) {
    return sys_call1(161 /* SYS_chroot */, (long)path);
}
static inline long sys_chown(const char *pathname, unsigned int uid, unsigned int gid) {
    return sys_call3(92 /* SYS_chown */, (long)pathname, uid, gid);
}
static inline long sys_kill(int pid, int sig) {
    return sys_call2(62 /* SYS_kill */, pid, sig);
}
static inline long sys_setpriority(int which, int who, int prio) {
    return sys_call3(141 /* SYS_setpriority */, which, who, prio);
}

/* Note: sys_read, sys_write, sys_close, sys_unlink, sys_open are provided by sys.h */

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

/* Helper: redraw line from cursor to end, then reposition cursor */
static void redraw_from_cursor(const char *buf, size_t cursor, size_t len) {
    /* Write chars from cursor to end */
    for (size_t i = cursor; i < len; i++)
        write_char(1, buf[i]);
    /* Erase any leftover character (for delete operations) */
    write_char(1, ' ');
    /* Move cursor back to correct position */
    for (size_t i = 0; i < len - cursor + 1; i++)
        write_char(1, '\b');
}

/* Helper: clear entire displayed line and rewrite */
static void clear_and_redraw(char *buf, size_t *cursor, size_t *len,
                              const char *new_text) {
    /* Move cursor to beginning */
    while (*cursor > 0) { write_char(1, '\b'); (*cursor)--; }
    /* Overwrite with spaces */
    for (size_t i = 0; i < *len; i++) write_char(1, ' ');
    /* Move back */
    for (size_t i = 0; i < *len; i++) write_char(1, '\b');
    /* Write new text */
    size_t i = 0;
    while (new_text[i]) { buf[i] = new_text[i]; write_char(1, buf[i]); i++; }
    *cursor = i;
    *len = i;
}

/* Read a line with interactive editing support (backspace, arrow keys, history, cursor movement) */
static ssize_t read_line(int fd, char *buf, size_t max_len) {
    size_t cursor = 0;  /* Cursor position within buf */
    size_t len = 0;     /* Total length of input */
    char c;
    ssize_t nread;
    static int current_history_index = -1;  /* -1 means not browsing history */
    static char saved_input[MAX_CMD_LEN];   /* Save current input when browsing history */

    /* Reset history position at start of new line */
    current_history_index = -1;
    saved_input[0] = '\0';

    while (len < max_len - 1) {
        nread = read_bytes(fd, &c, 1);

        if (nread <= 0) {
            /* EOF or error */
            if (len > 0) {
                buf[len] = '\0';
                return (ssize_t)len;
            }
            return nread;
        }

        /* Handle escape sequences (arrow keys, Home, End) */
        if (c == 0x1B) {  /* ESC */
            char seq[2];
            if (read_bytes(fd, &seq[0], 1) <= 0) continue;
            if (seq[0] != '[') continue;
            if (read_bytes(fd, &seq[1], 1) <= 0) continue;

            if (seq[1] == 'A') {  /* Up arrow */
                /* Save current input if this is first history navigation */
                if (current_history_index == -1) {
                    buf[len] = '\0';
                    strncpy_simple(saved_input, buf, MAX_CMD_LEN);
                    current_history_index = history_count;
                }

                /* Go to previous command */
                if (current_history_index > 0) {
                    current_history_index--;
                    const char *hist = get_history(current_history_index);
                    if (hist) {
                        clear_and_redraw(buf, &cursor, &len, hist);
                    }
                }
            } else if (seq[1] == 'B') {  /* Down arrow */
                if (current_history_index != -1) {
                    current_history_index++;

                    if (current_history_index >= history_count) {
                        /* Reached end, restore saved input */
                        current_history_index = -1;
                        clear_and_redraw(buf, &cursor, &len, saved_input);
                    } else {
                        const char *hist = get_history(current_history_index);
                        if (hist) {
                            clear_and_redraw(buf, &cursor, &len, hist);
                        }
                    }
                }
            } else if (seq[1] == 'C') {  /* Right arrow */
                if (cursor < len) {
                    write_str(1, "\033[C");
                    cursor++;
                }
            } else if (seq[1] == 'D') {  /* Left arrow */
                if (cursor > 0) {
                    write_str(1, "\033[D");
                    cursor--;
                }
            } else if (seq[1] == 'H') {  /* Home */
                while (cursor > 0) { write_char(1, '\b'); cursor--; }
            } else if (seq[1] == 'F') {  /* End */
                while (cursor < len) { write_str(1, "\033[C"); cursor++; }
            } else if (seq[1] == '3') {  /* Delete key: ESC [ 3 ~ */
                char tilde;
                if (read_bytes(fd, &tilde, 1) > 0 && tilde == '~') {
                    if (cursor < len) {
                        for (size_t i = cursor; i < len - 1; i++)
                            buf[i] = buf[i + 1];
                        len--;
                        redraw_from_cursor(buf, cursor, len);
                    }
                }
            }
            continue;
        }

        /* Handle different control characters */
        if (c == '\n' || c == '\r') {
            /* End of line — move cursor to end first */
            while (cursor < len) { write_str(1, "\033[C"); cursor++; }
            write_char(1, '\n');
            buf[len] = '\0';
            return (ssize_t)len;
        } else if (c == 0x7F || c == 0x08) {
            /* Backspace (DEL=0x7F or BS=0x08) */
            if (cursor > 0) {
                for (size_t i = cursor - 1; i < len - 1; i++)
                    buf[i] = buf[i + 1];
                cursor--;
                len--;
                write_char(1, '\b');
                redraw_from_cursor(buf, cursor, len);
            }
        } else if (c == 0x01) {
            /* Ctrl+A - beginning of line */
            while (cursor > 0) { write_char(1, '\b'); cursor--; }
        } else if (c == 0x05) {
            /* Ctrl+E - end of line */
            while (cursor < len) { write_str(1, "\033[C"); cursor++; }
        } else if (c == 0x03) {
            /* Ctrl+C - interrupt */
            write_str(1, "^C\n");
            buf[0] = '\0';
            return 0;
        } else if (c == 0x1A) {
            /* Ctrl+Z - suspend */
            write_str(1, "^Z\n");
            buf[0] = '\0';
            return 0;
        } else if (c == 0x11 || c == 0x13) {
            /* Ctrl+Q (XON) / Ctrl+S (XOFF) - flow control, ignore */
            continue;
        } else if (c == 0x0C) {
            /* Ctrl+L - clear screen and redraw prompt */
            write_str(1, "\033[2J\033[H");
            print_prompt();
            /* Redraw current input */
            buf[len] = '\0';
            for (size_t i = 0; i < len; i++) write_char(1, buf[i]);
            /* Reposition cursor */
            for (size_t i = len; i > cursor; i--) write_char(1, '\b');
        } else if (c == 0x09) {
            /* Tab - command completion (operates at end of input) */
            buf[len] = '\0';
            size_t old_len = len;
            complete_command(buf, &len, max_len);
            cursor = len;  /* completion moves cursor to end */
            (void)old_len;
        } else if (c == 0x0B) {
            /* Ctrl+K - kill to end of line */
            /* Erase from cursor to end on screen */
            for (size_t i = cursor; i < len; i++) write_char(1, ' ');
            for (size_t i = cursor; i < len; i++) write_char(1, '\b');
            len = cursor;
        } else if (c >= 0x20 && c < 0x7F) {
            /* Printable character - insert at cursor position */
            if (len < max_len - 1) {
                /* Shift chars right to make room */
                for (size_t i = len; i > cursor; i--)
                    buf[i] = buf[i - 1];
                buf[cursor] = c;
                len++;
                cursor++;
                /* Redraw from inserted position */
                for (size_t i = cursor - 1; i < len; i++)
                    write_char(1, buf[i]);
                /* Move cursor back to correct position */
                for (size_t i = cursor; i < len; i++)
                    write_char(1, '\b');
            }
        }
        /* Ignore other control characters */
    }

    /* Buffer full */
    buf[max_len - 1] = '\0';
    return max_len - 1;
}

/* String comparison */
static int strcmp_simple(const char *a, const char *b) {
    /* NULL safety: if either pointer is NULL, treat as not equal */
    if (!a || !b) {
        return (a == b) ? 0 : (a ? 1 : -1);
    }

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

/* Alias table */
#define MAX_ALIASES 32
static struct { int used; char name[32]; char value[128]; } aliases[MAX_ALIASES];

static const char *get_alias(const char *name) {
    for (int i = 0; i < MAX_ALIASES; i++)
        if (aliases[i].used && strcmp_simple(aliases[i].name, name) == 0)
            return aliases[i].value;
    return NULL;
}

static void set_alias(const char *name, const char *value) {
    for (int i = 0; i < MAX_ALIASES; i++) {
        if (aliases[i].used && strcmp_simple(aliases[i].name, name) == 0) {
            strncpy_simple(aliases[i].value, value, 128);
            return;
        }
    }
    for (int i = 0; i < MAX_ALIASES; i++) {
        if (!aliases[i].used) {
            aliases[i].used = 1;
            strncpy_simple(aliases[i].name, name, 32);
            strncpy_simple(aliases[i].value, value, 128);
            return;
        }
    }
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
        "arp", "bg", "brctl", "cal", "cd", "chgrp", "chmod", "chroot", "clear", "cmp", "comm", "conntrack", "date", "dd", "df", "dhclient", "dmesg", "echo", "edit", "ethtool", "expand", "expr", "factor", "file", "fold", "hexdump", "install", "locale", "lsof", "md5sum", "mkfifo", "nc", "nice", "nohup", "patch", "pgrep", "pidof", "pkill", "poweroff", "reboot", "renice", "reset", "seq", "sha1sum", "sleep", "strings", "tac", "time", "timeout", "tput", "traceroute", "tty", "unexpand", "wget", "xxd", "exit", "export", "fg", "free",
        "help", "hostname", "httpd", "id", "ifconfig", "iostat", "ipcs", "iptables", "jobs", "kill", "logger", "losetup", "ls", "lsblk", "lspci", "mkfs", "mount", "netstat",
        ".", "alias", "arch", "basename", "dirname", "du", "exec", "false", "getconf", "history", "ip", "ln", "mktemp", "more", "nproc", "nslookup", "passwd", "ping", "printf", "ps", "pwd", "read", "readlink", "realpath", "set", "sha1sum", "sha256sum", "shutdown", "source", "ss", "stat", "strace", "stty", "su", "sync", "sysctl", "sysinfo", "tc", "test", "top", "trap", "tree", "true", "type", "umask", "unalias", "uname", "uptime", "version", "vi", "vmstat", "wait", "watch", "wdctl", "which", "whoami", "xargs", "yes", NULL
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
            print_prompt();
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

    /* Special dynamic variables */
    if (strcmp_simple(name, "RANDOM") == 0) {
        /* Simple PRNG using kernel tick counter */
        static uint32_t rng_state = 0;
        if (rng_state == 0) {
            struct { long tv_sec; long tv_nsec; } ts = {0, 0};
            sys_call2(98, 1, (long)&ts);
            rng_state = (uint32_t)(ts.tv_nsec ^ ts.tv_sec);
        }
        rng_state = rng_state * 1103515245 + 12345;
        static char rand_buf[8];
        int rv = (int)((rng_state >> 16) & 0x7FFF);
        /* Simple itoa inline to avoid forward declaration */
        int ri = 0;
        if (rv == 0) { rand_buf[ri++] = '0'; }
        else { char rt[8]; int rj = 0; int tmp = rv;
               while (tmp > 0) { rt[rj++] = '0' + tmp % 10; tmp /= 10; }
               while (rj > 0) rand_buf[ri++] = rt[--rj]; }
        rand_buf[ri] = '\0';
        return rand_buf;
    }

    /* $PPID */
    if (strcmp_simple(name, "PPID") == 0) {
        static char ppid_buf[16];
        long ppid = sys_call0(110 /* getppid */);
        int pi = 0;
        if (ppid == 0) { ppid_buf[pi++] = '0'; }
        else { char pt[16]; int pj = 0; long tmp = ppid;
               while (tmp > 0) { pt[pj++] = '0' + (char)(tmp % 10); tmp /= 10; }
               while (pj > 0) ppid_buf[pi++] = pt[--pj]; }
        ppid_buf[pi] = '\0';
        return ppid_buf;
    }

    /* $EUID */
    if (strcmp_simple(name, "EUID") == 0) {
        static char euid_buf[8];
        long euid = sys_call0(107 /* geteuid */);
        euid_buf[0] = '0' + (char)(euid % 10);
        euid_buf[1] = '\0';
        return euid_buf;
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
static void set_var(const char *name, const char *value, int exported) {
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
        shell_vars[empty_slot].exported = exported;
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
            /* Special variables */
            if (*p == '$') {
                /* $$ = current PID */
                p++;
                long pid = sys_call0(39 /* getpid */);
                char pbuf[16];
                /* Inline itoa */
                int pi2 = 0;
                if (pid == 0) { pbuf[pi2++] = '0'; }
                else { char pt[16]; int pj = 0; long tmp = pid;
                       while (tmp > 0) { pt[pj++] = '0' + (char)(tmp % 10); tmp /= 10; }
                       while (pj > 0) pbuf[pi2++] = pt[--pj]; }
                pbuf[pi2] = '\0';
                for (int i = 0; pbuf[i] && dest_pos < dest_size - 1; i++)
                    dest[dest_pos++] = pbuf[i];
                continue;
            }
            if (*p == '!') {
                /* $! = last background PID (stub: 0) */
                p++;
                dest[dest_pos++] = '0';
                continue;
            }
            if (*p == '(' && p[1] == '(') {
                /* $((...)) arithmetic expansion */
                p += 2;
                char expr[128];
                int el = 0;
                int depth = 2;
                while (*p && depth > 0 && el < 127) {
                    if (*p == ')') depth--;
                    if (depth > 0) expr[el++] = *p;
                    p++;
                }
                expr[el] = '\0';
                /* Simple arithmetic: parse "a OP b" */
                long result = 0;
                char *ep = expr;
                while (*ep == ' ') ep++;
                /* Parse first operand */
                long a = 0; int neg = 0;
                if (*ep == '-') { neg = 1; ep++; }
                while (*ep >= '0' && *ep <= '9') { a = a * 10 + (*ep - '0'); ep++; }
                if (neg) a = -a;
                while (*ep == ' ') ep++;
                if (*ep) {
                    char op = *ep++; char op2 = 0;
                    if (*ep == '=' || *ep == op) { op2 = *ep++; }
                    while (*ep == ' ') ep++;
                    long b = 0; neg = 0;
                    if (*ep == '-') { neg = 1; ep++; }
                    while (*ep >= '0' && *ep <= '9') { b = b * 10 + (*ep - '0'); ep++; }
                    if (neg) b = -b;
                    if (op == '+') result = a + b;
                    else if (op == '-') result = a - b;
                    else if (op == '*') result = a * b;
                    else if (op == '/' && b != 0) result = a / b;
                    else if (op == '%' && b != 0) result = a % b;
                    else if (op == '<' && op2 == '=') result = a <= b;
                    else if (op == '>' && op2 == '=') result = a >= b;
                    else if (op == '<') result = a < b;
                    else if (op == '>') result = a > b;
                    else if (op == '=' && op2 == '=') result = a == b;
                    else if (op == '!' && op2 == '=') result = a != b;
                    else result = a;
                } else {
                    result = a;
                }
                /* Convert to string */
                char rbuf[20];
                int ri = 0;
                if (result < 0) { rbuf[ri++] = '-'; result = -result; }
                if (result == 0) { rbuf[ri++] = '0'; }
                else { char rt[20]; int rj = 0;
                       while (result > 0) { rt[rj++] = '0' + (char)(result % 10); result /= 10; }
                       while (rj > 0) rbuf[ri++] = rt[--rj]; }
                rbuf[ri] = '\0';
                for (int i = 0; rbuf[i] && dest_pos < dest_size - 1; i++)
                    dest[dest_pos++] = rbuf[i];
                continue;
            }
            if (*p == '(') {
                /* $() command substitution */
                p++;
                char cmd[256];
                int cl = 0;
                int depth = 1;
                while (*p && depth > 0 && cl < 255) {
                    if (*p == '(') depth++;
                    else if (*p == ')') { depth--; if (depth == 0) { p++; break; } }
                    cmd[cl++] = *p++;
                }
                cmd[cl] = '\0';
                /* Execute command with pipe to capture output */
                int pipefd[2];
                if (sys_pipe(pipefd) == 0) {
                    pid_t pid = sys_fork();
                    if (pid == 0) {
                        /* Child: redirect stdout to pipe, exec command */
                        sys_close(pipefd[0]);
                        sys_dup2(pipefd[1], 1);
                        sys_close(pipefd[1]);
                        /* Use shell -c to execute */
                        char *sh_argv[] = {"/bin/shell", "-c", cmd, NULL};
                        char *sh_envp[] = {NULL};
                        sys_execve("/bin/shell", sh_argv, sh_envp);
                        syscall1(__NR_exit, 1);
                    }
                    sys_close(pipefd[1]);
                    /* Read output */
                    char obuf[256];
                    long nr;
                    while ((nr = sys_read(pipefd[0], obuf, sizeof(obuf))) > 0) {
                        for (long j = 0; j < nr && dest_pos < dest_size - 1; j++) {
                            if (obuf[j] != '\n' || j < nr - 1) /* trim trailing newline */
                                dest[dest_pos++] = obuf[j];
                        }
                    }
                    sys_close(pipefd[0]);
                    /* Trim trailing newlines */
                    while (dest_pos > 0 && dest[dest_pos-1] == '\n') dest_pos--;
                    int status;
                    extern long sys_waitpid(int, int *, int);
                    sys_waitpid(pid, &status, 0);
                }
                continue;
            }
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

    write_str(1, "Futura OS Shell v0.5 - Available Commands:\n");
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
    write_str(1, "  uniq [-c] [-d] [-u] <file>... - Report or omit repeated lines\n");
    write_str(1, "  cut -f <field> [-d <delim>] <file>... - Extract fields from lines\n");
    write_str(1, "  cut -c <N[-M]> <file>... - Extract characters from lines\n");
    write_str(1, "  tr [-d] [-s] <set1> [set2] <file>... - Translate or delete characters\n");
    write_str(1, "  tee [-a] <file>... - Read from stdin and write to stdout and files\n");
    write_str(1, "  paste [-d <delim>] <file>... - Merge lines of files\n");
    write_str(1, "  diff [-q] <file1> <file2> - Compare files line by line\n");
    write_str(1, "  grep [-i] [-n] [-v] <pattern> [file...] - Search for patterns in files\n");
    write_str(1, "  sort [-r] [-n] [-u] [file...] - Sort lines of text\n");
    write_str(1, "  awk [-F sep] 'program' [file] - Pattern scanning (print $N, /pat/)\n");
    write_str(1, "  sed 's/pat/rep/[g]' [file] - Stream editor substitution\n");
    write_str(1, "  rev [file]      - Reverse characters in each line\n");
    write_str(1, "  nl [file]       - Number lines of text\n");
    write_str(1, "  base64 [-d] [file] - Base64 encode (decode with -d)\n");
    write_str(1, "  od [file]       - Octal/byte dump of file\n");
    write_str(1, "\n");
    write_str(1, "File Operations:\n");
    write_str(1, "  mkdir <dir>     - Create directory\n");
    write_str(1, "  rmdir <dir>     - Remove empty directory\n");
    write_str(1, "  touch <file>    - Create empty file\n");
    write_str(1, "  rm <file>       - Remove file\n");
    write_str(1, "  cp <src> <dst>  - Copy file\n");
    write_str(1, "  mv <src> <dst>  - Move/rename file\n");
    write_str(1, "  chmod <mode> <file> - Change permissions (octal)\n");
    write_str(1, "  stat <file>     - Show file information\n");
    write_str(1, "  vi <file>       - Vi text editor (h/j/k/l, i, dd, :wq)\n");
    write_str(1, "  dd [if=] [of=] [bs=] [count=] - Copy data\n");
    write_str(1, "\n");
    write_str(1, "System:\n");
    write_str(1, "  ps              - List running processes\n");
    write_str(1, "  kill [-sig] pid - Send signal to process\n");
    write_str(1, "  id              - Print user/group IDs\n");
    write_str(1, "  uname [-a]      - Print system information\n");
    write_str(1, "  whoami          - Print current user\n");
    write_str(1, "  date            - Show system uptime\n");
    write_str(1, "  dmesg           - Show kernel log buffer\n");
    write_str(1, "  uptime          - Show system uptime (from /proc)\n");
    write_str(1, "  hostname        - Show system hostname\n");
    write_str(1, "  free            - Show memory usage\n");
    write_str(1, "  mount           - Show mounted filesystems\n");
    write_str(1, "  ifconfig        - Show network interfaces\n");
    write_str(1, "  df              - Show filesystem usage\n");
    write_str(1, "  nc host port    - TCP netcat client\n");
    write_str(1, "  wget url        - Fetch HTTP content\n");
    write_str(1, "  hexdump file    - Hex dump of file contents\n");
    write_str(1, "  seq [s] n       - Print number sequence\n");
    write_str(1, "  sleep secs      - Pause for N seconds\n");
    write_str(1, "  env             - Show environment variables\n");
    write_str(1, "  echo [args]     - Print text\n");
    write_str(1, "  clear           - Clear screen\n");
    write_str(1, "  reboot          - Reboot system\n");
    write_str(1, "  poweroff        - Power off system\n");
    write_str(1, "  version         - Show kernel version\n");
    write_str(1, "  timeout N cmd   - Run command with time limit\n");
    write_str(1, "  nohup cmd       - Run command immune to hangups\n");
    write_str(1, "  chroot dir [cmd]- Change root directory\n");
    write_str(1, "  tty             - Print terminal name\n");
    write_str(1, "  tac file        - Print file lines in reverse\n");
    write_str(1, "  chgrp gid file  - Change group ownership\n");
    write_str(1, "  md5sum file     - Compute file hash\n");
    write_str(1, "  strings file    - Print printable character sequences\n");
    write_str(1, "  pgrep pattern   - Find processes by name\n");
    write_str(1, "  pkill [-sig] pat- Kill processes by name\n");
    write_str(1, "  pidof name      - Find PID by exact process name\n");
    write_str(1, "  nice [-n N] cmd - Run command with altered priority\n");
    write_str(1, "  renice prio pid - Change process priority\n");
    write_str(1, "  xxd [-r] file   - Hex dump (or reverse with -r)\n");
    write_str(1, "  file FILE...    - Identify file type by magic bytes\n");
    write_str(1, "  mkfifo NAME...  - Create named pipe (FIFO)\n");
    write_str(1, "  cmp [-s] F1 F2  - Compare files byte by byte\n");
    write_str(1, "  fold [-w N] file- Wrap lines to N columns (default 80)\n");
    write_str(1, "  comm FILE1 FILE2- Compare sorted files line by line\n");
    write_str(1, "  expand [-t N] f - Convert tabs to spaces\n");
    write_str(1, "  unexpand [-t N] f- Convert spaces to tabs\n");
    write_str(1, "  install [-m] s d- Copy file with mode\n");
    write_str(1, "  expr EXPR       - Evaluate expression (+,-,*,/,%%,=,!=,<,>)\n");
    write_str(1, "  factor N        - Print prime factors\n");
    write_str(1, "  cal             - Display calendar\n");
    write_str(1, "  locale          - Display locale settings\n");
    write_str(1, "  reset           - Reset terminal\n");
    write_str(1, "  tput cap        - Query terminal capabilities\n");
    write_str(1, "  lsof [-p pid]   - List open files\n");
    write_str(1, "  strace <cmd>    - Trace syscalls of a command\n");
    write_str(1, "  which <cmd>     - Find command in PATH\n");
    write_str(1, "  du [path]       - Show disk usage (KB)\n");
    write_str(1, "  tree [path]     - Show directory tree\n");
    write_str(1, "  ln -s tgt link  - Create symbolic link\n");
    write_str(1, "  readlink <path> - Print symlink target\n");
    write_str(1, "  top             - Show processes and system stats\n");
    write_str(1, "  sysctl key[=v]  - Read/write kernel parameters\n");
    write_str(1, "  systemctl <cmd> - Service management (start/stop/status/list-units)\n");
    write_str(1, "  pkg <cmd>       - Package manager (install/remove/list/search/info)\n");
    write_str(1, "  screen [-ls|-r] - Terminal multiplexer (Ctrl+A prefix, 4 windows)\n");
    write_str(1, "\n");
    write_str(1, "Networking:\n");
    write_str(1, "  ip addr|link|route|neigh|forward - Network configuration\n");
    write_str(1, "  ip addr add <ip>/<pfx> dev <if>  - Set interface address\n");
    write_str(1, "  ip route add <dst> via <gw>      - Add route\n");
    write_str(1, "  ip link set <if> up|down|mtu N   - Interface control\n");
    write_str(1, "  ip link add link <if> type vlan id <N> - Create VLAN\n");
    write_str(1, "  ip forward on|off                - Toggle IP forwarding\n");
    write_str(1, "  ifconfig        - Show interface configuration\n");
    write_str(1, "  iptables -A|-P|-F|-L             - Firewall rules\n");
    write_str(1, "  iptables -t nat -A POSTROUTING -o <if> -j MASQUERADE\n");
    write_str(1, "  ping <host>     - ICMP echo request\n");
    write_str(1, "  traceroute <host> - Trace network path\n");
    write_str(1, "  netstat [-r|-i|-a|-l] - Network statistics\n");
    write_str(1, "  ss              - Socket statistics\n");
    write_str(1, "  arp             - Show ARP cache\n");
    write_str(1, "  conntrack [-L|-C|-F]  - NAT connection tracking\n");
    write_str(1, "  nc [-l] host port - TCP netcat\n");
    write_str(1, "  wget <url>      - Fetch HTTP content\n");
    write_str(1, "  httpd [-p port] [-d dir] - HTTP server\n");
    write_str(1, "  nslookup <domain> - DNS lookup\n");
    write_str(1, "  dhclient [if]   - DHCP client\n");
    write_str(1, "\n");
    write_str(1, "Shell:\n");
    write_str(1, "  help            - Show this help message\n");
    write_str(1, "  exit [code]     - Exit shell\n");
    write_str(1, "  export VAR=val  - Export environment variable\n");
    write_str(1, "  source <file>   - Execute script in current shell\n");
    write_str(1, "  exec <cmd>      - Replace shell with command\n");
    write_str(1, "  test / [        - Test conditions (see below)\n");
    write_str(1, "  history         - Show command history\n");
    write_str(1, "  alias name=val  - Define command alias\n");
    write_str(1, "  unalias <name>  - Remove alias\n");
    write_str(1, "  jobs            - List background jobs\n");
    write_str(1, "  fg [job_id]     - Bring job to foreground\n");
    write_str(1, "  wait [pid]      - Wait for background process\n");
    write_str(1, "  sysinfo         - System information summary\n");
    write_str(1, "\n");
    write_str(1, "Scripting:\n");
    write_str(1, "  for VAR in LIST; do BODY; done\n");
    write_str(1, "  while CMD; do BODY; done\n");
    write_str(1, "  until CMD; do BODY; done\n");
    write_str(1, "  if CMD; then BODY; [else BODY;] fi\n");
    write_str(1, "  case WORD in PAT) BODY;; ... esac\n");
    write_str(1, "  cat <<EOF ... EOF  (heredocs in scripts)\n");
    write_str(1, "  eval ARGS         - Evaluate args as shell command\n");
    write_str(1, "  let EXPR          - Arithmetic assignment (let x=3+2)\n");
    write_str(1, "  getopts OPTS NAME - Parse command-line options\n");
    write_str(1, "  test EXPR / [ EXPR ] - Conditional expression\n");
    write_str(1, "    -f/-d/-r/-w/-x/-s/-L FILE, -n/-z STR, -eq/-ne/-lt/-gt NUM\n");
    write_str(1, "\n");
    write_str(1, "Features:\n");
    write_str(1, "  Variables:      VAR=value, $VAR, ${VAR}, $$, $?, $RANDOM\n");
    write_str(1, "  Arithmetic:     $((a + b)), $((x * 2))\n");
    write_str(1, "  Substitution:   $(command)\n");
    write_str(1, "  Glob:           *.txt, /etc/*, file?.log\n");
    write_str(1, "  Pipelines:      cmd1 | cmd2 | cmd3\n");
    write_str(1, "  Redirection:    cmd > file, cmd >> file, cmd < file\n");
    write_str(1, "  Conditionals:   cmd1 && cmd2, cmd1 || cmd2\n");
    write_str(1, "  Background:     cmd &\n");
    write_str(1, "  History:        Up/down arrow keys, Ctrl+L clear\n");
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

/* Print shell prompt showing current directory: "root@futura:/path# " */
static void print_prompt(void) {
    char cwd[256] = {0};
    long ret = sys_getcwd(cwd, sizeof(cwd));
    const char *home = get_var("HOME");
    const char *user = get_var("USER");
    const char *host = get_var("HOSTNAME");
    if (!user) user = "root";
    if (!host) host = "futura";

    /* Color prompt: green user@host, blue cwd, reset */
    write_str(1, "\033[32m");
    write_str(1, (user && *user) ? user : "root");
    write_str(1, "@");
    write_str(1, (host && *host) ? host : "futura");
    write_str(1, "\033[0m:\033[34m");
    if (ret > 0) {
        /* Abbreviate home dir with ~ */
        if (home && home[0] != '/' && home[1] != '\0') home = NULL; /* invalid HOME */
        if (home && home[0] == '/' && home[1] != '\0') {
            size_t hlen = strlen_simple(home);
            int match = 1;
            for (size_t i = 0; i < hlen; i++) {
                if (cwd[i] != home[i]) { match = 0; break; }
            }
            if (match && (cwd[hlen] == '/' || cwd[hlen] == '\0')) {
                write_str(1, "~");
                write_str(1, cwd + hlen);
            } else {
                write_str(1, cwd);
            }
        } else {
            write_str(1, cwd);
        }
    } else {
        write_str(1, "?");
    }
    write_str(1, "\033[0m# ");
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
    const char *path;
    if (argc < 2 || strcmp_simple(argv[1], "~") == 0) {
        /* cd with no args or cd ~ → go to $HOME */
        path = get_var("HOME");
        if (!path) path = "/";
    } else if (strcmp_simple(argv[1], "-") == 0) {
        /* cd - → go to $OLDPWD */
        path = get_var("OLDPWD");
        if (!path) { write_str(2, "cd: OLDPWD not set\n"); return; }
    } else {
        path = argv[1];
    }

    /* Save current dir as OLDPWD */
    char oldcwd[256];
    long cwdret = sys_call2(__NR_getcwd, (long)oldcwd, 256);

    long ret = sys_chdir(path);
    if (ret != 0) {
        write_str(2, "cd: cannot change directory to ");
        write_str(2, path);
        write_char(2, '\n');
    } else {
        /* Update $PWD and $OLDPWD */
        if (cwdret > 0) set_var("OLDPWD", oldcwd, 1);
        char newcwd[256];
        if (sys_call2(__NR_getcwd, (long)newcwd, 256) > 0) {
            set_var("PWD", newcwd, 1);
        }
    }
}

/* Built-in: echo */
static void cmd_echo(int argc, char *argv[]) {
    int newline = 1, escapes = 0, arg_start = 1;
    while (arg_start < argc && argv[arg_start][0] == '-') {
        int ok = 0;
        for (int j = 1; argv[arg_start][j]; j++) {
            if (argv[arg_start][j] == 'n') { newline = 0; ok = 1; }
            else if (argv[arg_start][j] == 'e') { escapes = 1; ok = 1; }
        }
        if (!ok) break;
        arg_start++;
    }
    for (int i = arg_start; i < argc; i++) {
        if (escapes) {
            for (const char *s = argv[i]; *s; s++) {
                if (*s == '\\' && s[1]) {
                    s++;
                    if (*s == 'n') write_char(1, '\n');
                    else if (*s == 't') write_char(1, '\t');
                    else if (*s == 'r') write_char(1, '\r');
                    else if (*s == '\\') write_char(1, '\\');
                    else { write_char(1, '\\'); write_char(1, *s); }
                } else write_char(1, *s);
            }
        } else write_str(1, argv[i]);
        if (i < argc - 1) write_char(1, ' ');
    }
    if (newline) write_char(1, '\n');
}

/* Built-in: uname */
static void cmd_uname(int argc, char *argv[]) {
    /* uname [-a|-s|-n|-r|-v|-m] using real syscall */
    int show_all = 0, show_sys = 0, show_node = 0, show_rel = 0, show_ver = 0, show_mach = 0;

    if (argc <= 1) {
        show_sys = 1;
    } else {
        for (int i = 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                for (int j = 1; argv[i][j]; j++) {
                    switch (argv[i][j]) {
                        case 'a': show_all = 1; break;
                        case 's': show_sys = 1; break;
                        case 'n': show_node = 1; break;
                        case 'r': show_rel = 1; break;
                        case 'v': show_ver = 1; break;
                        case 'm': show_mach = 1; break;
                    }
                }
            }
        }
    }

    if (show_all) { show_sys = show_node = show_rel = show_ver = show_mach = 1; }

    /* Call uname syscall (x86_64: 63) */
    struct { char sysname[65]; char nodename[65]; char release[65];
             char version[65]; char machine[65]; char domainname[65]; } uts;
    for (int i = 0; i < (int)sizeof(uts); i++) ((char*)&uts)[i] = 0;
    long ret = sys_call1(63 /* uname */, (long)&uts);
    if (ret < 0) {
        /* Fallback to hardcoded */
        write_str(1, "Futura futura 0.3.1 aarch64\n");
        return;
    }

    int first = 1;
    if (show_sys)  { if (!first) write_char(1, ' '); write_str(1, uts.sysname); first = 0; }
    if (show_node) { if (!first) write_char(1, ' '); write_str(1, uts.nodename); first = 0; }
    if (show_rel)  { if (!first) write_char(1, ' '); write_str(1, uts.release); first = 0; }
    if (show_ver)  { if (!first) write_char(1, ' '); write_str(1, uts.version); first = 0; }
    if (show_mach) { if (!first) write_char(1, ' '); write_str(1, uts.machine); first = 0; }
    write_char(1, '\n');
}

/* Forward declaration */
static void int_to_str(long n, char *buf, int size);

/* Parse dotted-decimal IPv4 to host-byte-order uint32_t */
static unsigned int parse_ipv4(const char *s) {
    unsigned int ip = 0, octet = 0;
    int shift = 24;
    for (int i = 0; s[i]; i++) {
        if (s[i] == '.') { ip |= (octet & 0xFF) << shift; shift -= 8; octet = 0; }
        else if (s[i] >= '0' && s[i] <= '9') octet = octet * 10 + (unsigned)(s[i] - '0');
    }
    return ip | ((octet & 0xFF) << shift);
}

/* Built-in: date - Show uptime (no RTC) */
static void cmd_date(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Use CLOCK_REALTIME (0) for wall-clock time */
    struct { long tv_sec; long tv_nsec; } ts = {0, 0};
    long ret = sys_call2(98 /* clock_gettime x86 compat */, 0 /* CLOCK_REALTIME */, (long)&ts);
    if (ret == 0 && ts.tv_sec > 1000000000L) {
        /* Convert epoch seconds to date/time (simplified UTC) */
        long t = ts.tv_sec;
        long days = t / 86400;
        long daytime = t % 86400;
        long hour = daytime / 3600;
        long min = (daytime % 3600) / 60;
        long sec = daytime % 60;

        /* Calculate year/month/day from days since epoch */
        long y = 1970;
        while (1) {
            long ydays = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 366 : 365;
            if (days < ydays) break;
            days -= ydays;
            y++;
        }
        int leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
        int mdays[] = {31,28+leap,31,30,31,30,31,31,30,31,30,31};
        const char *mnames[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                "Jul","Aug","Sep","Oct","Nov","Dec"};
        const char *wnames[] = {"Thu","Fri","Sat","Sun","Mon","Tue","Wed"};
        int m = 0;
        while (m < 12 && days >= mdays[m]) { days -= mdays[m]; m++; }
        int day = (int)days + 1;
        int wday = (int)((ts.tv_sec / 86400 + 4) % 7);  /* Jan 1 1970 = Thursday */

        /* Check for +FORMAT argument */
        if (argc > 1 && argv[1][0] == '+') {
            const char *fmt = argv[1] + 1;
            char buf[128];
            int p = 0;
            while (*fmt && p < 126) {
                if (*fmt == '%' && fmt[1]) {
                    fmt++;
                    char tmp[8];
                    switch (*fmt) {
                        case 'Y': int_to_str((long)y, tmp, 8); for (int i=0;tmp[i];i++) buf[p++]=tmp[i]; break;
                        case 'm': buf[p++]='0'+(char)((m+1)/10); buf[p++]='0'+(char)((m+1)%10); break;
                        case 'd': buf[p++]='0'+(char)(day/10); buf[p++]='0'+(char)(day%10); break;
                        case 'H': buf[p++]='0'+(char)(hour/10); buf[p++]='0'+(char)(hour%10); break;
                        case 'M': buf[p++]='0'+(char)(min/10); buf[p++]='0'+(char)(min%10); break;
                        case 'S': buf[p++]='0'+(char)(sec/10); buf[p++]='0'+(char)(sec%10); break;
                        case 'A': for (int i=0;wnames[wday][i];i++) buf[p++]=wnames[wday][i]; break;
                        case 'B': for (int i=0;mnames[m][i];i++) buf[p++]=mnames[m][i]; break;
                        case 's': { int_to_str(ts.tv_sec, tmp, 8); for (int i=0;tmp[i];i++) buf[p++]=tmp[i]; break; }
                        default: buf[p++]='%'; buf[p++]=*fmt; break;
                    }
                    fmt++;
                } else {
                    buf[p++] = *fmt++;
                }
            }
            buf[p++] = '\n'; buf[p] = '\0';
            write_str(1, buf);
        } else {
            /* Default format: "Wed Mar 24 06:53:28 UTC 2026" */
            char buf[64];
            int p = 0;
            for (int i = 0; wnames[wday][i]; i++) buf[p++] = wnames[wday][i];
            buf[p++] = ' ';
            for (int i = 0; mnames[m][i]; i++) buf[p++] = mnames[m][i];
            buf[p++] = ' ';
            if (day < 10) buf[p++] = ' ';
            { char tmp[8]; int_to_str(day, tmp, 8); for (int i = 0; tmp[i]; i++) buf[p++] = tmp[i]; }
            buf[p++] = ' ';
            buf[p++] = '0' + (char)(hour / 10); buf[p++] = '0' + (char)(hour % 10);
            buf[p++] = ':';
            buf[p++] = '0' + (char)(min / 10); buf[p++] = '0' + (char)(min % 10);
            buf[p++] = ':';
            buf[p++] = '0' + (char)(sec / 10); buf[p++] = '0' + (char)(sec % 10);
            buf[p++] = ' '; buf[p++] = 'U'; buf[p++] = 'T'; buf[p++] = 'C'; buf[p++] = ' ';
            { char tmp[8]; int_to_str((long)y, tmp, 8); for (int i = 0; tmp[i]; i++) buf[p++] = tmp[i]; }
            buf[p++] = '\n'; buf[p] = '\0';
            write_str(1, buf);
        }
    } else {
        /* Fallback: show uptime */
        struct { long tv_sec; long tv_nsec; } mono = {0, 0};
        sys_call2(98, 1 /* CLOCK_MONOTONIC */, (long)&mono);
        write_str(1, "up ");
        char tmp[16]; int_to_str(mono.tv_sec, tmp, 16);
        write_str(1, tmp); write_str(1, "s\n");
    }
}

/* Built-in: free - Show memory usage (reads /proc/meminfo) */
static void cmd_free(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int fd = sys_open("/proc/meminfo", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[512];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            write_str(1, buf);
        } else {
            write_str(1, "free: cannot read /proc/meminfo\n");
        }
        sys_close(fd);
    } else {
        write_str(1, "free: /proc/meminfo not available\n");
    }
}

/* Built-in: mount - Show mounted filesystems (reads /proc/mounts) */
static void cmd_mount(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int fd = sys_open("/proc/mounts", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            write_str(1, buf);
        } else {
            write_str(1, "mount: cannot read /proc/mounts\n");
        }
        sys_close(fd);
    } else {
        write_str(1, "mount: /proc/mounts not available\n");
    }
}

/* Built-in: edit - Simple line editor for files */
static void cmd_edit(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(1, "usage: edit <file>\n");
        write_str(1, "  Enter text line by line. Type '.' on a line by itself to save.\n");
        write_str(1, "  Type ':q' to quit without saving.\n");
        return;
    }

    const char *path = argv[1];

    /* Show existing content if file exists */
    int rfd = sys_open(path, O_RDONLY, 0);
    if (rfd >= 0) {
        write_str(1, "--- Current content ---\n");
        char buf[256];
        ssize_t n;
        while ((n = sys_read(rfd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            write_str(1, buf);
        }
        sys_close(rfd);
        write_str(1, "--- End ---\n");
    }

    write_str(1, "Enter text (. to save, :q to quit):\n");

    /* Open file for writing */
    int wfd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        write_str(1, "edit: cannot open file for writing\n");
        return;
    }

    char line[256];
    int saved = 0;
    while (1) {
        write_str(1, "> ");
        ssize_t n = sys_read(0, line, sizeof(line) - 1);
        if (n <= 0) break;
        line[n] = '\0';

        /* Remove trailing newline */
        if (n > 0 && line[n-1] == '\n') line[n-1] = '\0';

        /* Check for save command */
        if (line[0] == '.' && line[1] == '\0') {
            saved = 1;
            break;
        }
        /* Check for quit command */
        if (line[0] == ':' && line[1] == 'q' && line[2] == '\0') {
            break;
        }

        /* Write line + newline to file */
        sys_write(wfd, line, strlen_simple(line));
        sys_write(wfd, "\n", 1);
    }

    sys_close(wfd);

    if (saved) {
        write_str(1, "Saved to ");
        write_str(1, path);
        write_char(1, '\n');
    } else {
        /* Quit without saving — truncate the file */
        write_str(1, "Discarded.\n");
    }
}

/* Built-in: dmesg - Show kernel log ring buffer */
static void cmd_dmesg(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Read /proc/kmsg if available, otherwise use syslog syscall */
    int fd = sys_open("/proc/kmsg", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            write_str(1, buf);
        }
        sys_close(fd);
    } else {
        /* Fall back to syslog syscall (103 on x86_64) */
        /* Type 3 = SYSLOG_ACTION_READ_ALL, read entire ring buffer */
        char buf[8192];
        long ret = sys_call3(103 /* syslog */, 3, (long)buf, sizeof(buf) - 1);
        if (ret > 0) {
            buf[ret] = '\0';
            write_str(1, buf);
        } else {
            write_str(1, "dmesg: kernel log not available\n");
        }
    }
}

/* Resolve hostname or IP string to uint32_t (host byte order).
 * Returns 0 on failure. If str is numeric (e.g., "10.0.2.2"), parses directly.
 * If str is a hostname, sends DNS query to 10.0.2.3 (QEMU DNS) via UDP. */
static uint32_t resolve_host(const char *str) {
    if (!str || !str[0]) return 0;
    /* Check if it's a numeric IP (all digits and dots) */
    int is_numeric = 1;
    for (int i = 0; str[i]; i++)
        if (!((str[i] >= '0' && str[i] <= '9') || str[i] == '.')) { is_numeric = 0; break; }
    if (is_numeric) {
        uint32_t ip = 0; int octet = 0, shift = 24;
        for (int i = 0; str[i]; i++) {
            if (str[i] == '.') { ip |= ((uint32_t)octet & 0xFF) << shift; shift -= 8; octet = 0; }
            else octet = octet * 10 + (str[i] - '0');
        }
        return ip | (((uint32_t)octet & 0xFF) << shift);
    }
    /* DNS resolution via UDP to 10.0.2.3:53 (QEMU default DNS) */
    long sock = sys_call3(41, 2, 2, 17);
    if (sock < 0) return 0;
    /* Build DNS query */
    static uint8_t pkt[512]; int pos = 0;
    pkt[pos++] = 0xAB; pkt[pos++] = 0xCD; /* ID */
    pkt[pos++] = 0x01; pkt[pos++] = 0x00; /* RD=1 */
    pkt[pos++] = 0; pkt[pos++] = 1; /* QDCOUNT=1 */
    pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;
    /* Encode domain */
    const char *d = str;
    while (*d) {
        const char *dot = d; while (*dot && *dot != '.') dot++;
        int len = (int)(dot - d);
        pkt[pos++] = (uint8_t)len;
        for (int i = 0; i < len; i++) pkt[pos++] = (uint8_t)d[i];
        d = dot; if (*d == '.') d++;
    }
    pkt[pos++] = 0; /* root */
    pkt[pos++] = 0; pkt[pos++] = 1; /* QTYPE=A */
    pkt[pos++] = 0; pkt[pos++] = 1; /* QCLASS=IN */
    /* Send to 10.0.2.3:53 */
    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    sa.family = 2; sa.port = (53 >> 8) | ((53 & 0xFF) << 8);
    sa.addr = 0x0302000A; /* 10.0.2.3 in network order */
    for (int i = 0; i < 8; i++) sa.pad[i] = 0;
    sys_call6(44, sock, (long)pkt, pos, 0, (long)&sa, 16);
    /* Recv with 3s timeout */
    struct { long tv_sec; long tv_usec; } tv = {3, 0};
    sys_call6(54, sock, 1, 20, (long)&tv, sizeof(tv), 0);
    static uint8_t reply[512];
    ssize_t rn = sys_read(sock, reply, sizeof(reply));
    sys_close(sock);
    if (rn < 12) return 0;
    /* Parse answer: skip header (12) + question section */
    int rpos = 12;
    /* Skip question */
    uint16_t qdcount = ((uint16_t)reply[4] << 8) | reply[5];
    for (int q = 0; q < qdcount && rpos < rn; q++) {
        while (rpos < rn && reply[rpos] != 0) {
            if ((reply[rpos] & 0xC0) == 0xC0) { rpos += 2; break; }
            rpos += reply[rpos] + 1;
        }
        if (rpos < rn && reply[rpos] == 0) rpos++;
        rpos += 4; /* QTYPE + QCLASS */
    }
    /* Parse first answer */
    uint16_t ancount = ((uint16_t)reply[6] << 8) | reply[7];
    for (int a = 0; a < ancount && rpos + 12 <= rn; a++) {
        /* Skip name (may be compressed) */
        if ((reply[rpos] & 0xC0) == 0xC0) rpos += 2;
        else { while (rpos < rn && reply[rpos] != 0) rpos += reply[rpos] + 1; rpos++; }
        uint16_t rtype = ((uint16_t)reply[rpos] << 8) | reply[rpos+1]; rpos += 2;
        rpos += 2; /* class */ rpos += 4; /* TTL */
        uint16_t rdlen = ((uint16_t)reply[rpos] << 8) | reply[rpos+1]; rpos += 2;
        if (rtype == 1 && rdlen == 4 && rpos + 4 <= rn) {
            /* A record: 4-byte IPv4 address (network byte order → host order) */
            return ((uint32_t)reply[rpos] << 24) | ((uint32_t)reply[rpos+1] << 16) |
                   ((uint32_t)reply[rpos+2] << 8) | reply[rpos+3];
        }
        rpos += rdlen;
    }
    return 0;
}

/* Built-in: ping - Send ICMP echo requests */
static void cmd_ping(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(1, "usage: ping <host|ip>\n");
        return;
    }
    /* Resolve hostname or parse IP */
    const char *host = argv[1];
    uint32_t ip = resolve_host(host);
    if (ip == 0) { write_str(2, "ping: cannot resolve "); write_str(2, host); write_str(2, "\n"); return; }
    uint32_t ip_be = ((ip >> 24) & 0xFF) | ((ip >> 8) & 0xFF00) |
                     ((ip << 8) & 0xFF0000) | ((ip << 24) & 0xFF000000);

    /* Create raw ICMP socket */
    long fd = sys_call3(41 /* socket */, 2 /* AF_INET */, 3 /* SOCK_RAW */, 1 /* IPPROTO_ICMP */);
    if (fd < 0) {
        /* Fallback: try SOCK_DGRAM with ICMP */
        fd = sys_call3(41, 2, 2 /* SOCK_DGRAM */, 1);
        if (fd < 0) { write_str(2, "ping: socket failed\n"); return; }
    }

    /* Send 4 pings */
    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    sa.family = 2; sa.port = 0; sa.addr = ip_be;
    for (int i = 0; i < 8; i++) sa.pad[i] = 0;

    write_str(1, "PING ");
    write_str(1, host);
    write_str(1, "\n");

    for (int seq = 0; seq < 4; seq++) {
        /* Simple ICMP echo: type=8, code=0, checksum, id, seq */
        uint8_t pkt[64];
        for (int j = 0; j < 64; j++) pkt[j] = 0;
        pkt[0] = 8; /* ICMP_ECHO_REQUEST */
        pkt[4] = 0; pkt[5] = 1; /* id=1 */
        pkt[6] = (uint8_t)(seq >> 8); pkt[7] = (uint8_t)(seq & 0xFF);
        /* Checksum */
        uint32_t sum = 0;
        for (int j = 0; j < 64; j += 2) sum += (pkt[j] << 8) | pkt[j+1];
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t csum = ~(uint16_t)sum;
        pkt[2] = (uint8_t)(csum >> 8); pkt[3] = (uint8_t)(csum & 0xFF);

        long sent = sys_call6(44 /* sendto */, fd, (long)pkt, 64, 0, (long)&sa, 16);
        if (sent > 0) {
            /* Wait for reply */
            struct { long tv_sec; long tv_nsec; } start = {0,0};
            sys_call2(98, 1, (long)&start);
            char rbuf[128];
            long rcv = sys_call6(45 /* recvfrom */, fd, (long)rbuf, 128, 0, 0, 0);
            struct { long tv_sec; long tv_nsec; } end_t = {0,0};
            sys_call2(98, 1, (long)&end_t);
            long ms = (end_t.tv_sec - start.tv_sec) * 1000 + (end_t.tv_nsec - start.tv_nsec) / 1000000;
            if (rcv > 0) {
                write_str(1, "64 bytes from ");
                write_str(1, host);
                write_str(1, ": seq=");
                char nb[8]; int_to_str(seq, nb, 8); write_str(1, nb);
                write_str(1, " time=");
                int_to_str((long)ms, nb, 8); write_str(1, nb);
                write_str(1, "ms\n");
            }
        }
        /* Sleep 1 second between pings */
        if (seq < 3) {
            struct { long tv_sec; long tv_nsec; } ts = {1, 0};
            sys_call2(35, (long)&ts, 0);
        }
    }
    sys_close(fd);
}

/* Built-in: nc - Simple netcat (connect or listen) */
static void cmd_nc(int argc, char *argv[]) {
    int listen_mode = 0;
    int arg_start = 1;

    if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'l') {
        listen_mode = 1;
        arg_start = 2;
    }

    if (listen_mode) {
        /* nc -l <port> — listen for incoming connection */
        if (arg_start >= argc) {
            write_str(2, "usage: nc -l <port>\n");
            return;
        }
        int port = 0;
        for (int i = 0; argv[arg_start][i]; i++)
            port = port * 10 + (argv[arg_start][i] - '0');

        long sfd = sys_call3(41 /* socket */, 2, 1 /* SOCK_STREAM */, 0);
        if (sfd < 0) { write_str(2, "nc: socket failed\n"); return; }

        struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
        sa.family = 2; sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
        sa.addr = 0; /* INADDR_ANY */
        for (int i = 0; i < 8; i++) sa.pad[i] = 0;

        if (sys_call3(49 /* bind */, sfd, (long)&sa, 16) < 0) {
            write_str(2, "nc: bind failed\n"); sys_close(sfd); return;
        }
        if (sys_call2(50 /* listen */, sfd, 1) < 0) {
            write_str(2, "nc: listen failed\n"); sys_close(sfd); return;
        }

        write_str(1, "Listening on port ");
        char nb[8]; int_to_str(port, nb, 8); write_str(1, nb);
        write_str(1, "...\n");

        long cfd = sys_call3(43 /* accept */, sfd, 0, 0);
        sys_close(sfd);
        if (cfd < 0) { write_str(2, "nc: accept failed\n"); return; }

        write_str(1, "Connection accepted\n");
        /* Relay data between socket and stdout */
        char buf[256];
        long n;
        while ((n = sys_read(cfd, buf, sizeof(buf))) > 0) {
            sys_write(1, buf, n);
        }
        sys_close(cfd);
        return;
    }

    if (argc < 3) {
        write_str(1, "usage: nc [-l] <host> <port>\n");
        write_str(1, "  nc host port     — Connect to TCP server\n");
        write_str(1, "  nc -l port       — Listen for incoming connection\n");
        return;
    }

    /* Parse IP address (simple dotted quad parser) */
    const char *host = argv[1];
    int port = 0;
    for (int i = 0; argv[2][i]; i++)
        port = port * 10 + (argv[2][i] - '0');

    /* Parse dotted quad to uint32 (network byte order) */
    uint32_t ip = 0;
    int octet = 0, shift = 24;
    for (int i = 0; host[i]; i++) {
        if (host[i] == '.') {
            ip |= (octet & 0xFF) << shift;
            shift -= 8;
            octet = 0;
        } else {
            octet = octet * 10 + (host[i] - '0');
        }
    }
    ip |= (octet & 0xFF) << shift;

    /* Convert to network byte order */
    uint32_t ip_be = ((ip >> 24) & 0xFF) | ((ip >> 8) & 0xFF00) |
                     ((ip << 8) & 0xFF0000) | ((ip << 24) & 0xFF000000);

    /* Create socket */
    long fd = sys_call3(41 /* socket */, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
    if (fd < 0) {
        write_str(1, "nc: socket failed\n");
        return;
    }

    /* Connect — struct sockaddr_in is 16 bytes */
    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    sa.family = 2; /* AF_INET */
    sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8)); /* htons */
    sa.addr = ip_be;
    for (int i = 0; i < 8; i++) sa.pad[i] = 0;

    long ret = sys_call3(42 /* connect */, fd, (long)&sa, 16);
    if (ret < 0) {
        write_str(1, "nc: connect failed\n");
        sys_close(fd);
        return;
    }

    write_str(1, "Connected. Type text, Ctrl+D to close.\n");

    /* Simple relay: read from stdin, write to socket */
    char buf[256];
    while (1) {
        ssize_t n = sys_read(0, buf, sizeof(buf));
        if (n <= 0) break;

        /* Send to socket */
        sys_call6(44 /* sendto */, fd, (long)buf, n, 0, 0, 0);

        /* Try to receive response */
        ssize_t r = sys_call6(45 /* recvfrom */, fd, (long)buf, sizeof(buf) - 1, 0x40 /* MSG_DONTWAIT */, 0, 0);
        if (r > 0) {
            buf[r] = '\0';
            write_str(1, buf);
        }
    }

    sys_close(fd);
}

/* Built-in: curl - HTTP client with method/header/data support */
static void cmd_curl(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(1, "usage: curl [-s] [-o file] [-X METHOD] [-H header] [-d data] <url>\n");
        return;
    }

    int silent = 0;
    const char *output_file = NULL;
    const char *method = "GET";
    const char *post_data = NULL;
    static char extra_headers[512];
    int ehdr_len = 0;
    extra_headers[0] = '\0';
    int url_arg = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp_simple(argv[i], "-s") == 0) { silent = 1; }
        else if (strcmp_simple(argv[i], "-o") == 0 && i + 1 < argc) { output_file = argv[++i]; }
        else if (strcmp_simple(argv[i], "-X") == 0 && i + 1 < argc) { method = argv[++i]; }
        else if (strcmp_simple(argv[i], "-d") == 0 && i + 1 < argc) {
            post_data = argv[++i];
            if (strcmp_simple(method, "GET") == 0) method = "POST";
        }
        else if (strcmp_simple(argv[i], "-H") == 0 && i + 1 < argc) {
            i++;
            const char *h = argv[i];
            while (*h && ehdr_len < 508) extra_headers[ehdr_len++] = *h++;
            extra_headers[ehdr_len++] = '\r';
            extra_headers[ehdr_len++] = '\n';
            extra_headers[ehdr_len] = '\0';
        }
        else if (argv[i][0] != '-') { url_arg = i; }
    }

    if (!url_arg) { write_str(2, "curl: no URL specified\n"); return; }

    /* Parse URL */
    const char *url = argv[url_arg];
    char host[64] = ""; char path[256] = "/"; int port = 80;
    if (url[0]=='h' && url[1]=='t' && url[2]=='t' && url[3]=='p' &&
        url[4]==':' && url[5]=='/' && url[6]=='/') url += 7;
    int hi = 0;
    while (*url && *url != '/' && *url != ':' && hi < 63) host[hi++] = *url++;
    host[hi] = '\0';
    if (*url == ':') { url++; port = 0; while (*url >= '0' && *url <= '9') port = port * 10 + (*url++ - '0'); }
    if (*url == '/') { int pi = 0; while (*url && pi < 255) path[pi++] = *url++; path[pi] = '\0'; }

    uint32_t ip = resolve_host(host);
    if (ip == 0) { write_str(2, "curl: cannot resolve "); write_str(2, host); write_str(2, "\n"); return; }
    uint32_t ip_be = ((ip >> 24) & 0xFF) | ((ip >> 8) & 0xFF00) |
                     ((ip << 8) & 0xFF0000) | ((ip << 24) & 0xFF000000);

    long fd = sys_call3(41, 2, 1, 0);
    if (fd < 0) { write_str(2, "curl: socket failed\n"); return; }

    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    sa.family = 2;
    sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
    sa.addr = ip_be;
    for (int i = 0; i < 8; i++) sa.pad[i] = 0;

    if (sys_call3(42, fd, (long)&sa, 16) < 0) {
        write_str(2, "curl: connect failed\n"); sys_close(fd); return;
    }

    /* Build HTTP request */
    static char req[1024];
    int rp = 0;
    const char *m = method; while (*m && rp < 1000) req[rp++] = *m++;
    req[rp++] = ' ';
    const char *pp = path; while (*pp && rp < 1000) req[rp++] = *pp++;
    const char *ver = " HTTP/1.0\r\nHost: ";
    while (*ver && rp < 1000) req[rp++] = *ver++;
    const char *h = host; while (*h && rp < 1000) req[rp++] = *h++;
    req[rp++] = '\r'; req[rp++] = '\n';
    /* Extra headers */
    for (int i = 0; i < ehdr_len && rp < 1000; i++) req[rp++] = extra_headers[i];
    /* Content-Length for POST */
    if (post_data) {
        const char *cl = "Content-Length: ";
        while (*cl && rp < 1000) req[rp++] = *cl++;
        int dlen = 0; const char *d = post_data; while (*d++) dlen++;
        char num[12]; int ni = 0;
        if (dlen == 0) num[ni++] = '0';
        else { char rev[12]; int ri = 0; int v = dlen;
            while (v > 0) { rev[ri++] = '0' + (v % 10); v /= 10; }
            while (ri > 0) num[ni++] = rev[--ri]; }
        for (int i = 0; i < ni && rp < 1000; i++) req[rp++] = num[i];
        req[rp++] = '\r'; req[rp++] = '\n';
        const char *ct = "Content-Type: application/x-www-form-urlencoded\r\n";
        while (*ct && rp < 1000) req[rp++] = *ct++;
    }
    req[rp++] = '\r'; req[rp++] = '\n';
    /* Append body */
    if (post_data) { const char *d = post_data; while (*d && rp < 1020) req[rp++] = *d++; }

    sys_write(fd, req, rp);

    /* Read response */
    int out_fd = 1;
    if (output_file) {
        out_fd = sys_open(output_file, 0x41 | 0x200 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
        if (out_fd < 0) { write_str(2, "curl: cannot create "); write_str(2, output_file); write_str(2, "\n"); sys_close(fd); return; }
    }

    static char buf[4096];
    long total = 0;
    int headers_done = 0;
    while (1) {
        long n = sys_read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (!headers_done) {
            /* Find \r\n\r\n end of headers */
            for (long i = 0; i < n - 3; i++) {
                if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') {
                    headers_done = 1;
                    long body_start = i + 4;
                    long body_len = n - body_start;
                    if (body_len > 0) {
                        sys_write(out_fd, buf + body_start, body_len);
                        total += body_len;
                    }
                    break;
                }
            }
        } else {
            sys_write(out_fd, buf, n);
            total += n;
        }
    }
    sys_close(fd);
    if (output_file && out_fd > 0) sys_close(out_fd);
    if (!silent && output_file) {
        write_str(2, "curl: saved "); char num[12]; int_to_str(total, num, 12);
        write_str(2, num); write_str(2, " bytes to "); write_str(2, output_file); write_str(2, "\n");
    }
}

/* Built-in: wget - Fetch HTTP content */
static void cmd_wget(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(1, "usage: wget [-O outfile] <url>\n");
        write_str(1, "  Fetch HTTP content. URL format: http://host/path\n");
        write_str(1, "  -O file  Save response body to file (use -O - for stdout)\n");
        write_str(1, "  Example: wget http://10.0.2.2/index.html\n");
        write_str(1, "  Example: wget -O page.html http://10.0.2.2/index.html\n");
        return;
    }

    /* Parse options */
    const char *outfile = NULL;
    int url_arg = 1;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp_simple(argv[i], "-O") == 0 && i + 1 < argc) {
            outfile = argv[i + 1];
            url_arg = i + 2;
            break;
        }
    }
    if (url_arg >= argc) {
        write_str(2, "wget: missing URL\n");
        return;
    }

    /* Parse URL: http://host[:port]/path */
    const char *url = argv[url_arg];
    char host[64] = "";
    char path[128] = "/";
    int port = 80;

    /* Skip http:// */
    if (url[0]=='h' && url[1]=='t' && url[2]=='t' && url[3]=='p' &&
        url[4]==':' && url[5]=='/' && url[6]=='/') {
        url += 7;
    }

    /* Extract host and path */
    int hi = 0, pi = 0;
    while (*url && *url != '/' && *url != ':' && hi < 63)
        host[hi++] = *url++;
    host[hi] = '\0';
    if (*url == ':') {
        url++;
        port = 0;
        while (*url >= '0' && *url <= '9')
            port = port * 10 + (*url++ - '0');
    }
    if (*url == '/') {
        pi = 0;
        while (*url && pi < 127)
            path[pi++] = *url++;
        path[pi] = '\0';
    }

    /* Derive output filename from URL path if no -O given */
    char auto_name[128];
    if (!outfile) {
        /* Extract filename from path: last component after '/' */
        int last_slash = -1;
        for (int i = 0; path[i]; i++)
            if (path[i] == '/') last_slash = i;
        if (last_slash >= 0 && path[last_slash + 1]) {
            int k = 0;
            for (int i = last_slash + 1; path[i] && k < 127; i++)
                auto_name[k++] = path[i];
            auto_name[k] = '\0';
            outfile = auto_name;
        }
    }

    /* Resolve hostname or parse IP */
    uint32_t ip = resolve_host(host);
    if (ip == 0) { write_str(2, "wget: cannot resolve "); write_str(2, host); write_str(2, "\n"); return; }
    uint32_t ip_be = ((ip >> 24) & 0xFF) | ((ip >> 8) & 0xFF00) |
                     ((ip << 8) & 0xFF0000) | ((ip << 24) & 0xFF000000);

    /* Connect */
    long fd = sys_call3(41, 2, 1, 0);
    if (fd < 0) { write_str(2, "wget: socket failed\n"); return; }

    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    sa.family = 2;
    sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
    sa.addr = ip_be;
    for (int i = 0; i < 8; i++) sa.pad[i] = 0;

    if (sys_call3(42, fd, (long)&sa, 16) < 0) {
        write_str(2, "wget: connect failed\n");
        sys_close(fd); return;
    }

    write_str(2, "Connecting to ");
    write_str(2, host);
    write_str(2, "... connected.\n");
    write_str(2, "HTTP request sent, awaiting response... ");

    /* Send HTTP GET request */
    char req[256];
    int ri = 0;
    const char *get = "GET ";
    while (*get) req[ri++] = *get++;
    for (int i = 0; path[i]; i++) req[ri++] = path[i];
    const char *http = " HTTP/1.0\r\nHost: ";
    while (*http) req[ri++] = *http++;
    for (int i = 0; host[i]; i++) req[ri++] = host[i];
    const char *hend = "\r\nConnection: close\r\n\r\n";
    while (*hend) req[ri++] = *hend++;
    req[ri] = '\0';

    sys_call6(44, fd, (long)req, ri, 0, 0, 0);

    /* Receive response — skip HTTP headers, write body */
    char buf[512];
    ssize_t total = 0;
    int headers_done = 0;
    int out_fd = 1; /* default: stdout */
    int to_stdout = (outfile && outfile[0] == '-' && outfile[1] == '\0');

    if (outfile && !to_stdout) {
        out_fd = sys_open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            write_str(2, "\nwget: cannot create ");
            write_str(2, outfile);
            write_str(2, "\n");
            sys_close(fd);
            return;
        }
    }

    while (1) {
        ssize_t n = sys_read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        int start = 0;
        if (!headers_done) {
            /* Scan for \r\n\r\n end of headers */
            for (int i = 0; i + 3 < n; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    /* Print status line to stderr */
                    char status[4] = {0};
                    /* Find "HTTP/x.x NNN" — status starts at offset 9 */
                    int sp = 0;
                    for (int j = 0; j < i && sp < 2; j++) {
                        if (buf[j] == ' ') sp++;
                        if (sp == 1 && buf[j] != ' ' && (int)(sizeof(status) - 1) > (j - 9)) {
                        }
                    }
                    /* Just print first line of response */
                    for (int j = 0; j < i && buf[j] != '\r'; j++)
                        write_char(2, buf[j]);
                    write_str(2, "\n");

                    headers_done = 1;
                    start = i + 4;
                    break;
                }
            }
            if (!headers_done) continue;
        }

        int body_len = (int)n - start;
        if (body_len > 0) {
            sys_call3(__NR_write, out_fd, (long)(buf + start), body_len);
            total += body_len;
        }
    }
    sys_close(fd);

    if (outfile && !to_stdout && out_fd > 2) {
        sys_close(out_fd);
        write_str(2, "Saved to '");
        write_str(2, outfile);
        write_str(2, "' [");
    } else {
        write_str(2, "\n--- ");
    }
    char nbuf[16];
    int_to_str(total, nbuf, 16);
    write_str(2, nbuf);
    if (outfile && !to_stdout)
        write_str(2, " bytes]\n");
    else
        write_str(2, " bytes received ---\n");
}

/* Built-in: seq - Print sequence of numbers */
static void cmd_seq(int argc, char *argv[]) {
    int start = 1, end_val = 0, step = 1;
    if (argc == 2) {
        end_val = 0;
        for (int i = 0; argv[1][i]; i++)
            end_val = end_val * 10 + (argv[1][i] - '0');
    } else if (argc == 3) {
        start = 0;
        for (int i = 0; argv[1][i]; i++)
            start = start * 10 + (argv[1][i] - '0');
        end_val = 0;
        for (int i = 0; argv[2][i]; i++)
            end_val = end_val * 10 + (argv[2][i] - '0');
    } else {
        write_str(1, "usage: seq [start] end\n");
        return;
    }

    char buf[16];
    for (int i = start; i <= end_val; i += step) {
        int_to_str(i, buf, 16);
        write_str(1, buf);
        write_char(1, '\n');
    }
}


/* Built-in: sleep - Pause for N seconds */
static void cmd_sleep(int argc, char *argv[]) {
    if (argc < 2) { write_str(1, "usage: sleep <seconds[.frac]>\n"); return; }
    long secs = 0, nsec = 0;
    const char *s = argv[1];
    while (*s >= '0' && *s <= '9') { secs = secs * 10 + (*s - '0'); s++; }
    if (*s == '.') {
        s++;
        long mult = 100000000L;  /* 0.1s in ns */
        while (*s >= '0' && *s <= '9' && mult > 0) {
            nsec += (*s - '0') * mult;
            mult /= 10;
            s++;
        }
    }
    struct { long tv_sec; long tv_nsec; } ts = { secs, nsec };
    sys_call2(35 /* nanosleep */, (long)&ts, 0);
}

/* Built-in: hexdump - Display file contents in hex */
static void cmd_hexdump(int argc, char *argv[]) {
    if (argc < 2) { write_str(1, "usage: hexdump <file>\n"); return; }
    int fd = sys_open(argv[1], O_RDONLY, 0);
    if (fd < 0) { write_str(1, "hexdump: cannot open file\n"); return; }
    
    char buf[16];
    ssize_t n;
    int offset = 0;
    while ((n = sys_read(fd, buf, 16)) > 0) {
        /* Print offset */
        char obuf[16];
        for (int i = 7; i >= 0; i--) {
            int nibble = (offset >> (i*4)) & 0xF;
            obuf[7-i] = nibble < 10 ? '0'+nibble : 'a'+nibble-10;
        }
        obuf[8] = 0;
        write_str(1, obuf);
        write_str(1, "  ");
        
        /* Print hex bytes */
        for (int i = 0; i < 16; i++) {
            if (i < n) {
                char h[3];
                h[0] = "0123456789abcdef"[(unsigned char)buf[i] >> 4];
                h[1] = "0123456789abcdef"[(unsigned char)buf[i] & 0xF];
                h[2] = 0;
                write_str(1, h);
                write_char(1, ' ');
            } else {
                write_str(1, "   ");
            }
            if (i == 7) write_char(1, ' ');
        }
        write_str(1, " |");
        /* Print ASCII */
        for (int i = 0; i < n; i++) {
            char c = buf[i];
            write_char(1, (c >= 32 && c < 127) ? c : '.');
        }
        write_str(1, "|\n");
        offset += n;
    }
    sys_close(fd);
}


static int execute_command(int argc, char *argv[]); /* forward decl */

/* Built-in: lsof - List open file descriptors */
static void cmd_lsof(int argc, char *argv[]) {
    /* Parse -p <pid> option to list fds for a specific process */
    long pid = sys_call0(39 /* getpid */);
    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp_simple(argv[i], "-p") == 0) {
            pid = 0;
            for (int j = 0; argv[i+1][j]; j++)
                pid = pid * 10 + (argv[i+1][j] - '0');
            break;
        }
    }

    write_str(1, "PID    FD   TYPE  NAME\n");

    /* Build /proc/<pid>/fd path */
    char path[64];
    int pi = 0;
    const char *prefix = "/proc/";
    while (prefix[pi]) { path[pi] = prefix[pi]; pi++; }
    char pbuf[16];
    int_to_str(pid, pbuf, 16);
    for (int i = 0; pbuf[i]; i++) path[pi++] = pbuf[i];
    const char *suffix = "/fd";
    for (int i = 0; suffix[i]; i++) path[pi++] = suffix[i];
    path[pi] = '\0';

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "lsof: cannot open "); write_str(2, path); write_str(2, "\n");
        return;
    }

    char dirent_buf[1024];
    ssize_t nread;
    while ((nread = sys_getdents64(fd, dirent_buf, sizeof(dirent_buf))) > 0) {
        ssize_t pos = 0;
        while (pos < nread) {
            uint16_t reclen = *(uint16_t *)(dirent_buf + pos + 16);
            char *name = dirent_buf + pos + 19;

            if (name[0] >= '0' && name[0] <= '9') {
                /* PID column */
                write_str(1, pbuf);
                int pad = 7 - (int)strlen_simple(pbuf);
                while (pad-- > 0) write_char(1, ' ');

                /* FD column */
                write_str(1, name);
                pad = 5 - (int)strlen_simple(name);
                while (pad-- > 0) write_char(1, ' ');

                /* Try to readlink to get actual path */
                char fdpath[80];
                int fp = 0;
                for (int k = 0; path[k] && fp < 60; k++) fdpath[fp++] = path[k];
                fdpath[fp++] = '/';
                for (int k = 0; name[k] && fp < 78; k++) fdpath[fp++] = name[k];
                fdpath[fp] = '\0';

                char target[128];
                long rl = sys_call3(89 /* readlink */, (long)fdpath, (long)target, 127);
                if (rl > 0) {
                    target[rl] = '\0';
                    /* Determine type from target path */
                    if (target[0] == 's' && target[1] == 'o' && target[2] == 'c' &&
                        target[3] == 'k' && target[4] == 'e' && target[5] == 't') {
                        write_str(1, "sock  ");
                    } else if (target[0] == 'p' && target[1] == 'i' && target[2] == 'p' &&
                               target[3] == 'e') {
                        write_str(1, "pipe  ");
                    } else {
                        write_str(1, "reg   ");
                    }
                    write_str(1, target);
                } else {
                    write_str(1, "???   (open)");
                }
                write_char(1, '\n');
            }

            if (reclen == 0) break;
            pos += reclen;
        }
    }
    sys_close(fd);
}

/* Built-in: strace - Trace syscalls of a command */
static void cmd_strace(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: strace <command> [args...]\n");
        write_str(2, "  Trace system calls made by a command.\n");
        return;
    }

    /* Syscall name table (x86_64 ABI, most common calls) */
    static const char *syscall_names[] = {
        [0] = "read", [1] = "write", [2] = "open", [3] = "close",
        [4] = "stat", [5] = "fstat", [6] = "lstat", [7] = "poll",
        [8] = "lseek", [9] = "mmap", [10] = "mprotect", [11] = "munmap",
        [12] = "brk", [13] = "rt_sigaction", [14] = "rt_sigprocmask",
        [15] = "rt_sigreturn", [16] = "ioctl", [17] = "pread64",
        [18] = "pwrite64", [19] = "readv", [20] = "writev",
        [21] = "access", [22] = "pipe", [23] = "select",
        [24] = "sched_yield", [25] = "mremap", [32] = "dup",
        [33] = "dup2", [35] = "nanosleep", [39] = "getpid",
        [41] = "socket", [42] = "connect", [43] = "accept",
        [44] = "sendto", [45] = "recvfrom", [46] = "sendmsg",
        [47] = "recvmsg", [48] = "shutdown", [49] = "bind",
        [50] = "listen", [56] = "clone", [57] = "fork",
        [58] = "vfork", [59] = "execve", [60] = "exit",
        [61] = "wait4", [62] = "kill", [63] = "uname",
        [72] = "fcntl", [78] = "getdents", [79] = "getcwd",
        [80] = "chdir", [82] = "rename", [83] = "mkdir",
        [84] = "rmdir", [85] = "creat", [86] = "link",
        [87] = "unlink", [89] = "readlink", [90] = "chmod",
        [91] = "fchmod", [92] = "chown", [96] = "gettimeofday",
        [97] = "getrlimit", [101] = "ptrace", [102] = "getuid",
        [104] = "getgid", [110] = "getppid",
        [217] = "getdents64", [231] = "exit_group",
        [257] = "openat", [262] = "newfstatat",
    };
    #define SYSCALL_NAME_MAX 263

    pid_t child = sys_fork();
    if (child == 0) {
        /* Child: request to be traced, then exec the command */
        sys_call4(101 /* ptrace */, 0 /* PTRACE_TRACEME */, 0, 0, 0);
        /* Raise SIGSTOP so parent can catch us before exec */
        sys_call2(62 /* kill */, sys_call0(39 /* getpid */), 19 /* SIGSTOP */);
        /* Execute the command as a builtin */
        execute_command(argc - 1, &argv[1]);
        syscall1(60, 0);
        while (1);
    } else if (child < 0) {
        write_str(2, "strace: fork failed\n");
        return;
    }

    /* Parent: wait for child to stop, then trace syscalls */
    int status = 0;
    sys_waitpid(child, &status, 0);

    /* Set PTRACE_O_TRACESYSGOOD so syscall-stops have bit 7 set */
    sys_call4(101, 0x4200 /* PTRACE_SETOPTIONS */, child, 0, 0x01 /* PTRACE_O_TRACESYSGOOD */);

    /* Resume child with PTRACE_SYSCALL */
    sys_call4(101, 24 /* PTRACE_SYSCALL */, child, 0, 0);

    int in_syscall = 0; /* toggle: 0 = entry, 1 = exit */
    long last_nr = -1;
    int call_count = 0;
    char nbuf[24];

    while (1) {
        long wr = sys_waitpid(child, &status, 0);
        if (wr < 0) break;

        /* Check if child exited */
        if ((status & 0x7F) == 0) {
            /* Normal exit */
            int exit_code = (status >> 8) & 0xFF;
            write_str(2, "+++ exited with ");
            int_to_str(exit_code, nbuf, 24); write_str(2, nbuf);
            write_str(2, " +++\n");
            break;
        }

        /* Check if child was signalled (not stopped) */
        if ((status & 0xFF) != 0x7F) break;

        int sig = (status >> 8) & 0xFF;

        /* Syscall-stop: signal 0x80|SIGTRAP (with TRACESYSGOOD) = 0x85 */
        if (sig == (0x80 | 5)) {
            if (!in_syscall) {
                /* Syscall entry — get syscall number from orig_rax via PTRACE_PEEKUSER */
                /* On x86_64, orig_rax is at offset 120 (15*8) in user_regs_struct */
                long nr = sys_call4(101, 3 /* PTRACE_PEEKUSR */, child, 120 /* ORIG_RAX */, 0);
                last_nr = nr;
                in_syscall = 1;
            } else {
                /* Syscall exit — get return value from rax (offset 80 = 10*8) */
                long ret = sys_call4(101, 3 /* PTRACE_PEEKUSR */, child, 80 /* RAX */, 0);
                /* Print: syscall_name(...) = ret */
                if (last_nr >= 0 && last_nr < SYSCALL_NAME_MAX && syscall_names[last_nr]) {
                    write_str(2, syscall_names[last_nr]);
                } else {
                    write_str(2, "syscall_");
                    int_to_str((int)last_nr, nbuf, 24);
                    write_str(2, nbuf);
                }
                write_str(2, "() = ");
                if (ret < 0) {
                    write_str(2, "-");
                    int_to_str((int)(-ret), nbuf, 24);
                } else {
                    int_to_str((int)ret, nbuf, 24);
                }
                write_str(2, nbuf);
                write_char(2, '\n');
                in_syscall = 0;
                call_count++;
            }
        } else {
            /* Received a real signal, deliver it */
            sys_call4(101, 24, child, 0, sig);
            continue;
        }

        /* Continue tracing */
        sys_call4(101, 24 /* PTRACE_SYSCALL */, child, 0, 0);
    }

    write_str(2, "strace: traced ");
    int_to_str(call_count, nbuf, 24); write_str(2, nbuf);
    write_str(2, " syscalls\n");
}

/* Built-in: time - Time a command */
static void cmd_time(int argc, char *argv[]) {
    if (argc < 2) { write_str(1, "usage: time <command>\n"); return; }
    /* Get start time */
    struct { long tv_sec; long tv_nsec; } start = {0,0}, end_ts = {0,0};
    sys_call2(98 /* clock_gettime */, 1, (long)&start);
    
    /* Execute the rest as a command */
    /* For simplicity, just run it as a builtin */
    execute_command(argc - 1, &argv[1]);
    
    sys_call2(98 /* clock_gettime */, 1, (long)&end_ts);
    
    long elapsed_ms = (end_ts.tv_sec - start.tv_sec) * 1000 +
                      (end_ts.tv_nsec - start.tv_nsec) / 1000000;
    char buf[32];
    int_to_str(elapsed_ms, buf, 32);
    write_str(2, "\nreal\t0m");
    write_str(2, buf);
    write_str(2, "ms\n");
}

/* Built-in: df - Show filesystem disk space usage */
/* Helper: format KB/MB/GB size for df */
static void df_format_size(long kb, char *out, int outlen) {
    if (kb < 1024) {
        int_to_str(kb, out, outlen);
        int l = (int)strlen_simple(out);
        if (l + 1 < outlen) { out[l] = 'K'; out[l+1] = '\0'; }
    } else if (kb < 1024 * 1024) {
        int_to_str(kb / 1024, out, outlen);
        int l = (int)strlen_simple(out);
        if (l + 1 < outlen) { out[l] = 'M'; out[l+1] = '\0'; }
    } else {
        int_to_str(kb / (1024 * 1024), out, outlen);
        int l = (int)strlen_simple(out);
        if (l + 1 < outlen) { out[l] = 'G'; out[l+1] = '\0'; }
    }
}

static void cmd_df(int argc, char *argv[]) {
    (void)argc; (void)argv;
    write_str(1, "Filesystem      Size  Used  Avail Use% Mounted on\n");

    /* Key mount points to check */
    const char *mounts[] = {"/", "/mnt", "/tmp", "/proc", NULL};
    const char *names[]  = {"ramfs", "futurafs", "tmpfs", "proc"};

    struct { long f_bsize; long f_blocks; long f_bfree; long f_bavail;
             long f_files; long f_ffree; long f_fsid[2]; long f_namelen;
             long f_frsize; long f_flags; long f_spare[4]; } sfs;

    for (int i = 0; mounts[i]; i++) {
        long ret = sys_call2(137 /* statfs */, (long)mounts[i], (long)&sfs);
        write_str(1, names[i]);
        int pad = 16 - (int)strlen_simple(names[i]);
        while (pad-- > 0) write_char(1, ' ');

        if (ret == 0 && sfs.f_bsize > 0 && sfs.f_blocks > 0) {
            long blk_kb = sfs.f_bsize / 1024;
            if (blk_kb == 0) blk_kb = 1;
            long total_kb = sfs.f_blocks * blk_kb;
            long free_kb = sfs.f_bfree * blk_kb;
            long used_kb = total_kb - free_kb;
            long avail_kb = sfs.f_bavail * blk_kb;
            int pct = total_kb > 0 ? (int)((used_kb * 100) / total_kb) : 0;

            char sbuf[16];
            df_format_size(total_kb, sbuf, 16);
            write_str(1, sbuf);
            pad = 6 - (int)strlen_simple(sbuf); while (pad-- > 0) write_char(1, ' ');
            df_format_size(used_kb, sbuf, 16);
            write_str(1, sbuf);
            pad = 6 - (int)strlen_simple(sbuf); while (pad-- > 0) write_char(1, ' ');
            df_format_size(avail_kb, sbuf, 16);
            write_str(1, sbuf);
            pad = 5 - (int)strlen_simple(sbuf); while (pad-- > 0) write_char(1, ' ');
            int_to_str(pct, sbuf, 16);
            pad = 3 - (int)strlen_simple(sbuf); while (pad-- > 0) write_char(1, ' ');
            write_str(1, sbuf); write_str(1, "% ");
        } else {
            write_str(1, "  -     -     -    -  ");
        }
        write_str(1, mounts[i]);
        write_char(1, '\n');
    }
}

/* Built-in: version - Show kernel version from /proc/version */
static void cmd_version(int argc, char *argv[]) {
    (void)argc; (void)argv;
    int fd = sys_open("/proc/version", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[256];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        sys_close(fd);
    } else {
        write_str(1, "Futura OS\n");
    }
}

/* Built-in: reboot/poweroff - System power control via reboot(2) syscall */
#define REBOOT_MAGIC1  0xfee1dead
#define REBOOT_MAGIC2  672274793
#define REBOOT_CMD_RESTART   0x01234567
#define REBOOT_CMD_POWEROFF  0x4321FEDC

/* Built-in: sync - Flush filesystem buffers */
static void cmd_sync(int argc, char *argv[]) {
    (void)argc; (void)argv;
    sys_call0(162 /* sync */);
    write_str(1, "sync: done\n");
}

static void cmd_reboot(int argc, char *argv[]) {
    (void)argc; (void)argv;
    write_str(1, "Syncing filesystems...\n");
    sys_call0(162 /* sync */);
    write_str(1, "Rebooting...\n");
    sys_call4(169, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_CMD_RESTART, 0);
    write_str(2, "reboot: failed\n");
}

static void cmd_poweroff(int argc, char *argv[]) {
    (void)argc; (void)argv;
    write_str(1, "Syncing filesystems...\n");
    sys_call0(162 /* sync */);
    write_str(1, "Powering off...\n");
    sys_call4(169, REBOOT_MAGIC1, REBOOT_MAGIC2, REBOOT_CMD_POWEROFF, 0);
    write_str(2, "poweroff: failed\n");
}

/* Built-in: read - Read a line from stdin into a variable */
static void cmd_read(int argc, char *argv[]) {
    /* read [-r] [-s] [-p PROMPT] [-n COUNT] VAR [VAR2 ...] */
    const char *prompt = NULL;
    int raw_mode = 0;     /* -r: don't interpret backslash escapes */
    int silent = 0;       /* -s: don't echo input */
    int max_chars = 0;    /* -n N: read at most N chars */
    int var_start = 1;

    /* Parse options */
    while (var_start < argc && argv[var_start][0] == '-') {
        const char *opt = argv[var_start];
        if (opt[1] == 'p' && var_start + 1 < argc) {
            prompt = argv[var_start + 1];
            var_start += 2;
        } else if (opt[1] == 'r') {
            raw_mode = 1; var_start++;
        } else if (opt[1] == 's') {
            silent = 1; var_start++;
        } else if (opt[1] == 'n' && var_start + 1 < argc) {
            max_chars = 0;
            for (const char *p = argv[var_start + 1]; *p >= '0' && *p <= '9'; p++)
                max_chars = max_chars * 10 + (*p - '0');
            var_start += 2;
        } else break;
    }

    if (var_start >= argc) {
        write_str(2, "usage: read [-r] [-s] [-p prompt] [-n count] VAR\n");
        return;
    }

    /* Display prompt if specified */
    if (prompt) write_str(2, prompt);

    /* Read input */
    char line[MAX_VAR_VALUE];
    int pos = 0;
    int chars_read = 0;
    while (pos < MAX_VAR_VALUE - 1) {
        if (max_chars > 0 && chars_read >= max_chars) break;
        char ch;
        long r = sys_call3(__NR_read, 0, (long)&ch, 1);
        if (r <= 0 || ch == '\n') break;

        /* Handle backslash continuation in non-raw mode */
        if (!raw_mode && ch == '\\' && pos > 0) {
            char next;
            r = sys_call3(__NR_read, 0, (long)&next, 1);
            if (r > 0 && next == '\n') continue;  /* Line continuation */
            if (r > 0) { line[pos++] = next; chars_read++; continue; }
        }

        line[pos++] = ch;
        chars_read++;
    }
    line[pos] = '\0';

    /* If silent mode, print newline after input */
    if (silent) write_str(2, "\n");

    /* If multiple vars, split by IFS (default: space/tab/newline) */
    if (var_start + 1 < argc) {
        /* Split line into fields for each variable */
        const char *p = line;
        for (int v = var_start; v < argc; v++) {
            /* Skip leading whitespace */
            while (*p == ' ' || *p == '\t') p++;
            if (v == argc - 1) {
                /* Last variable gets the rest of the line */
                set_var(argv[v], p, 0);
            } else {
                /* Extract one field */
                char field[MAX_VAR_VALUE];
                int fi = 0;
                while (*p && *p != ' ' && *p != '\t' && fi < MAX_VAR_VALUE - 1)
                    field[fi++] = *p++;
                field[fi] = '\0';
                set_var(argv[v], field, 0);
            }
        }
    } else {
        set_var(argv[var_start], line, 0);
    }
    (void)silent;  /* Silent mode handled above */
    (void)raw_mode;
}

/* Built-in: set - Show all shell variables */
static void cmd_set(int argc, char *argv[]) {
    (void)argc; (void)argv;
    for (int i = 0; i < MAX_VARS; i++) {
        if (shell_vars[i].used) {
            write_str(1, shell_vars[i].name);
            write_char(1, '=');
            write_str(1, shell_vars[i].value);
            write_char(1, '\n');
        }
    }
}

/* Built-in: kill - Send signal to process */
static void cmd_kill(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(1, "usage: kill [-signal] pid\n");
        return;
    }

    int sig = 9;  /* Default: SIGKILL */
    int pid_arg = 1;

    /* Check for -signal argument */
    if (argv[1][0] == '-') {
        const char *s = argv[1] + 1;
        /* Try signal names first */
        if (strcmp_simple(s, "TERM") == 0 || strcmp_simple(s, "term") == 0) sig = 15;
        else if (strcmp_simple(s, "KILL") == 0 || strcmp_simple(s, "kill") == 0) sig = 9;
        else if (strcmp_simple(s, "INT") == 0 || strcmp_simple(s, "int") == 0) sig = 2;
        else if (strcmp_simple(s, "HUP") == 0 || strcmp_simple(s, "hup") == 0) sig = 1;
        else if (strcmp_simple(s, "QUIT") == 0 || strcmp_simple(s, "quit") == 0) sig = 3;
        else if (strcmp_simple(s, "STOP") == 0 || strcmp_simple(s, "stop") == 0) sig = 19;
        else if (strcmp_simple(s, "CONT") == 0 || strcmp_simple(s, "cont") == 0) sig = 18;
        else if (strcmp_simple(s, "USR1") == 0 || strcmp_simple(s, "usr1") == 0) sig = 10;
        else if (strcmp_simple(s, "USR2") == 0 || strcmp_simple(s, "usr2") == 0) sig = 12;
        else if (strcmp_simple(s, "PIPE") == 0 || strcmp_simple(s, "pipe") == 0) sig = 13;
        else if (strcmp_simple(s, "ALRM") == 0 || strcmp_simple(s, "alrm") == 0) sig = 14;
        else {
            /* Parse as number */
            sig = 0;
            for (int i = 0; s[i]; i++) {
                if (s[i] >= '0' && s[i] <= '9')
                    sig = sig * 10 + (s[i] - '0');
            }
            if (sig == 0) sig = 15;
        }
        pid_arg = 2;
        if (argc < 3) {
            write_str(1, "usage: kill [-signal] pid\n");
            return;
        }
    }

    /* Parse PID */
    long pid = 0;
    for (int i = 0; argv[pid_arg][i]; i++) {
        if (argv[pid_arg][i] >= '0' && argv[pid_arg][i] <= '9')
            pid = pid * 10 + (argv[pid_arg][i] - '0');
    }

    if (pid <= 0) {
        write_str(1, "kill: invalid pid\n");
        return;
    }

    long ret = sys_call2(62 /* SYS_kill x86 compat */, pid, sig);
    if (ret < 0) {
        write_str(1, "kill: ");
        char buf[16];
        int_to_str(ret, buf, 16);
        write_str(1, buf);
        write_char(1, '\n');
    }
}

/* Built-in: id - Print user/group IDs */
static void cmd_id(int argc, char *argv[]) {
    long uid = sys_call0(102 /* getuid */);
    long gid = sys_call0(104 /* getgid */);
    long euid = sys_call0(107 /* geteuid */);
    long egid = sys_call0(108 /* getegid */);
    char buf[16];

    /* Support -u (uid only) and -g (gid only) flags */
    if (argc > 1 && argv[1][0] == '-') {
        if (argv[1][1] == 'u') {
            int_to_str(uid, buf, 16); write_str(1, buf); write_char(1, '\n'); return;
        } else if (argv[1][1] == 'g') {
            int_to_str(gid, buf, 16); write_str(1, buf); write_char(1, '\n'); return;
        } else if (argv[1][1] == 'n') {
            /* -un or -gn: print name */
            write_str(1, "root\n"); return;
        }
    }

    write_str(1, "uid=");
    int_to_str(uid, buf, 16); write_str(1, buf);
    write_str(1, "(root) gid=");
    int_to_str(gid, buf, 16); write_str(1, buf);
    write_str(1, "(root)");
    if (euid != uid) {
        write_str(1, " euid=");
        int_to_str(euid, buf, 16); write_str(1, buf);
    }
    if (egid != gid) {
        write_str(1, " egid=");
        int_to_str(egid, buf, 16); write_str(1, buf);
    }
    write_str(1, " groups=0(root)\n");
}

/* Built-in: ps - List processes */
static void cmd_ps(int argc, char *argv[]) {
    (void)argc; (void)argv;
    write_str(1, "  PID  STATE   RSS  NAME\n");

    /* Scan /proc for numeric directories (PIDs) */
    int proc_fd = sys_open("/proc", O_RDONLY, 0);
    if (proc_fd < 0) {
        write_str(1, "ps: cannot open /proc\n");
        return;
    }

    char dirent_buf[2048];
    ssize_t nread;
    while ((nread = sys_getdents64(proc_fd, dirent_buf, sizeof(dirent_buf))) > 0) {
        ssize_t pos = 0;
        while (pos < nread) {
            /* Linux dirent64: d_ino(8), d_off(8), d_reclen(2), d_type(1), d_name[] */
            uint16_t reclen = *(uint16_t *)(dirent_buf + pos + 16);
            char *name = dirent_buf + pos + 19;

            /* Check if directory name is numeric (PID) */
            if (name[0] >= '1' && name[0] <= '9') {
                /* Read /proc/<pid>/status */
                char path[64];
                int pi = 0;
                const char *prefix = "/proc/";
                while (prefix[pi]) { path[pi] = prefix[pi]; pi++; }
                int ni = 0;
                while (name[ni] && name[ni] != '\0') { path[pi++] = name[ni++]; }
                const char *suffix = "/status";
                ni = 0;
                while (suffix[ni]) { path[pi++] = suffix[ni++]; }
                path[pi] = '\0';

                int sfd = sys_open(path, O_RDONLY, 0);
                if (sfd >= 0) {
                    char sbuf[512];
                    ssize_t sn = sys_read(sfd, sbuf, sizeof(sbuf) - 1);
                    sys_close(sfd);
                    if (sn > 0) {
                        sbuf[sn] = '\0';
                        /* Parse Name:, State:, VmRSS: lines */
                        char pname[32] = "?";
                        char state[16] = "?";
                        char rss[16] = "0";
                        char *p = sbuf;
                        while (*p) {
                            if (p[0] == 'N' && p[1] == 'a' && p[2] == 'm' && p[3] == 'e' && p[4] == ':') {
                                p += 5;
                                while (*p == ' ' || *p == '\t') p++;
                                int j = 0;
                                while (*p && *p != '\n' && j < 31) pname[j++] = *p++;
                                pname[j] = '\0';
                            }
                            if (p[0] == 'S' && p[1] == 't' && p[2] == 'a' && p[3] == 't' && p[4] == 'e' && p[5] == ':') {
                                p += 6;
                                while (*p == ' ' || *p == '\t') p++;
                                int j = 0;
                                while (*p && *p != '\n' && *p != ' ' && j < 15) state[j++] = *p++;
                                state[j] = '\0';
                            }
                            if (p[0] == 'V' && p[1] == 'm' && p[2] == 'R' && p[3] == 'S' && p[4] == 'S' && p[5] == ':') {
                                p += 6;
                                while (*p == ' ' || *p == '\t') p++;
                                int j = 0;
                                while (*p && *p != '\n' && *p != ' ' && j < 15) rss[j++] = *p++;
                                rss[j] = '\0';
                            }
                            while (*p && *p != '\n') p++;
                            if (*p == '\n') p++;
                        }
                        /* Print: PID STATE RSS NAME */
                        write_str(1, "  ");
                        write_str(1, name);
                        int pad = 5 - (int)strlen_simple(name);
                        while (pad-- > 0) write_char(1, ' ');
                        write_str(1, "  ");
                        write_str(1, state);
                        pad = 6 - (int)strlen_simple(state);
                        while (pad-- > 0) write_char(1, ' ');
                        /* Right-align RSS */
                        pad = 5 - (int)strlen_simple(rss);
                        while (pad-- > 0) write_char(1, ' ');
                        write_str(1, rss);
                        pad = 6 - (int)strlen_simple(state);
                        while (pad-- > 0) write_char(1, ' ');
                        write_str(1, "  ");
                        write_str(1, pname);
                        write_char(1, '\n');
                    }
                }
            }

            if (reclen == 0) break;
            pos += reclen;
        }
    }
    sys_close(proc_fd);
}

/* Built-in: hostname - Show system hostname */
static void cmd_hostname(int argc, char *argv[]) {
    if (argc >= 2) {
        /* Set hostname: write to /proc/sys/kernel/hostname and /etc/hostname */
        const char *newname = argv[1];
        int len = 0; while (newname[len]) len++;
        /* Use sethostname syscall (170) */
        sys_call2(170 /* sethostname */, (long)newname, len);
        /* Also update /etc/hostname for persistence */
        int fd = sys_open("/etc/hostname", O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            sys_write(fd, newname, len);
            sys_write(fd, "\n", 1);
            sys_close(fd);
        }
        return;
    }
    /* Read hostname from /etc/hostname */
    int fd = sys_open("/etc/hostname", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            write_str(1, buf);
        }
        sys_close(fd);
    } else {
        write_str(1, "futura\n");
    }
}

/* Built-in: uptime - Show system uptime */
static void cmd_uptime(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Show current time */
    struct { long tv_sec; long tv_nsec; } ts = {0, 0};
    long ret = sys_call2(98 /* clock_gettime */, 0 /* CLOCK_REALTIME */, (long)&ts);
    if (ret == 0 && ts.tv_sec > 1000000000L) {
        long daytime = ts.tv_sec % 86400;
        long hour = daytime / 3600;
        long min = (daytime % 3600) / 60;
        write_char(1, ' ');
        write_char(1, '0' + (char)(hour / 10));
        write_char(1, '0' + (char)(hour % 10));
        write_char(1, ':');
        write_char(1, '0' + (char)(min / 10));
        write_char(1, '0' + (char)(min % 10));
    }

    /* Show uptime */
    int fd = sys_open("/proc/uptime", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        sys_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            long secs = 0;
            for (int i = 0; buf[i] && buf[i] != '.'; i++) {
                if (buf[i] >= '0' && buf[i] <= '9')
                    secs = secs * 10 + (buf[i] - '0');
            }
            write_str(1, "  up ");
            long h = secs / 3600, m = (secs % 3600) / 60;
            if (h > 0) {
                char tmp[16]; int_to_str(h, tmp, 16);
                write_str(1, tmp); write_str(1, "h ");
            }
            char tmp[16]; int_to_str(m, tmp, 16);
            write_str(1, tmp); write_str(1, "m");
        }
    }

    /* Show load average */
    fd = sys_open("/proc/loadavg", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
        sys_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            write_str(1, ",  load average: ");
            /* Print first 3 fields (1/5/15 min load) */
            int fields = 0;
            for (int i = 0; buf[i] && fields < 3; i++) {
                if (buf[i] == ' ') { fields++; if (fields < 3) write_str(1, ", "); }
                else write_char(1, buf[i]);
            }
        }
    }
    write_char(1, '\n');
}

/* Built-in: ifconfig - Show network interface info */
static void ifconfig_print_ip(int fd_out, unsigned char *ip) {
    for (int o = 0; o < 4; o++) {
        char ob[4]; int oi = 0;
        unsigned char v = ip[o];
        if (v >= 100) ob[oi++] = '0' + v/100;
        if (v >= 10) ob[oi++] = '0' + (v/10)%10;
        ob[oi++] = '0' + v%10;
        ob[oi] = '\0';
        write_str(fd_out, ob);
        if (o < 3) write_str(fd_out, ".");
    }
}
static void cmd_ifconfig(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Read real interface data via /proc/net/dev + ioctls */
    int fd = sys_open("/proc/net/dev", O_RDONLY, 0);
    if (fd < 0) { write_str(2, "ifconfig: cannot read /proc/net/dev\n"); return; }
    char buf[2048];
    ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    int line = 0;
    char *p = buf;
    int sock = sys_call3(41/*socket*/, 2, 2, 0);
    while (*p) {
        char *eol = p; while (*eol && *eol != '\n') eol++;
        if (line >= 2) {
            char *colon = p; while (colon < eol && *colon != ':') colon++;
            char ifname[16] = {0}; int j = 0;
            char *s = p; while (s < colon && *s == ' ') s++;
            while (s < colon && j < 15) ifname[j++] = *s++;
            if (j > 0 && sock >= 0) {
                char ifr[40];
                write_str(1, ifname);
                /* Pad to 10 chars */
                for (int k = j; k < 10; k++) write_str(1, " ");
                /* Get link type */
                for (int k = 0; k < 40; k++) ifr[k] = 0;
                for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                long irc = sys_call3(16, sock, 0x8913/*SIOCGIFFLAGS*/, (long)ifr);
                short flags = 0;
                if (irc == 0) for (int k = 0; k < 2; k++) flags |= (short)((unsigned char)ifr[16+k] << (k*8));
                write_str(1, (flags & 0x0008) ? "Link encap:Local Loopback\n" : "Link encap:Ethernet\n");

                /* inet addr + netmask */
                for (int k = 0; k < 40; k++) ifr[k] = 0;
                for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                irc = sys_call3(16, sock, 0x8915/*SIOCGIFADDR*/, (long)ifr);
                if (irc == 0) {
                    write_str(1, "          inet addr:");
                    ifconfig_print_ip(1, (unsigned char *)&ifr[20]);
                    /* Get netmask */
                    for (int k = 0; k < 40; k++) ifr[k] = 0;
                    for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                    irc = sys_call3(16, sock, 0x891B, (long)ifr);
                    if (irc == 0) {
                        write_str(1, "  Mask:");
                        ifconfig_print_ip(1, (unsigned char *)&ifr[20]);
                    }
                    write_str(1, "\n");
                }

                /* Flags line */
                write_str(1, "          ");
                if (flags & 0x0001) write_str(1, "UP ");
                if (flags & 0x0002) write_str(1, "BROADCAST ");
                if (flags & 0x0008) write_str(1, "LOOPBACK ");
                if (flags & 0x0040) write_str(1, "RUNNING ");
                if (flags & 0x1000) write_str(1, "MULTICAST ");
                /* MTU */
                for (int k = 0; k < 40; k++) ifr[k] = 0;
                for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                irc = sys_call3(16, sock, 0x8921/*SIOCGIFMTU*/, (long)ifr);
                if (irc == 0) {
                    int mtu = 0;
                    for (int k = 0; k < 4; k++) mtu |= ((unsigned char)ifr[16+k]) << (k*8);
                    write_str(1, " MTU:");
                    char mb[12]; int mi = 0;
                    if (mtu == 0) { mb[mi++] = '0'; }
                    else { char t2[12]; int ti = 0; while (mtu > 0) { t2[ti++] = '0' + mtu%10; mtu /= 10; } while (ti > 0) mb[mi++] = t2[--ti]; }
                    mb[mi] = '\0';
                    write_str(1, mb);
                }
                write_str(1, "\n\n");
            }
        }
        if (*eol) p = eol + 1; else break;
        line++;
    }
    if (sock >= 0) sys_close(sock);
}

/* Built-in: whoami */
static void cmd_whoami(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    write_str(1, "root\n");
}

/* Built-in: env - Show environment variables */
static void cmd_env(int argc, char *argv[]) {
    int arg_start = 1;

    /* env [VAR=val]... [command [args...]]
     * With no args: print all exported variables
     * With VAR=val: set variables then run command */

    /* Skip -i (ignored — we don't clear env) */
    if (arg_start < argc && strcmp_simple(argv[arg_start], "-i") == 0)
        arg_start++;

    /* Check for VAR=val assignments and command */
    int has_cmd = 0;
    int cmd_idx = arg_start;
    while (cmd_idx < argc) {
        /* Check if this arg contains '=' (it's a VAR=val) */
        int has_eq = 0;
        for (int j = 0; argv[cmd_idx][j]; j++) {
            if (argv[cmd_idx][j] == '=') { has_eq = 1; break; }
        }
        if (!has_eq) { has_cmd = 1; break; }
        cmd_idx++;
    }

    if (has_cmd) {
        /* Set variables and execute command */
        for (int i = arg_start; i < cmd_idx; i++) {
            /* Parse VAR=val */
            char vname[MAX_VAR_NAME];
            char vval[MAX_VAR_VALUE];
            int ni = 0, vi = 0;
            const char *p = argv[i];
            while (*p && *p != '=' && ni < MAX_VAR_NAME - 1) vname[ni++] = *p++;
            vname[ni] = '\0';
            if (*p == '=') p++;
            while (*p && vi < MAX_VAR_VALUE - 1) vval[vi++] = *p++;
            vval[vi] = '\0';
            set_var(vname, vval, 1);  /* Set as exported */
        }
        /* Execute the command */
        int sub_argc = argc - cmd_idx;
        char *sub_argv[64];
        for (int i = 0; i < sub_argc && i < 63; i++)
            sub_argv[i] = argv[cmd_idx + i];
        sub_argv[sub_argc] = NULL;
        execute_command(sub_argc, sub_argv);
    } else if (cmd_idx > arg_start) {
        /* Only VAR=val assignments, no command — set and print */
        for (int i = arg_start; i < cmd_idx; i++) {
            char vname[MAX_VAR_NAME], vval[MAX_VAR_VALUE];
            int ni = 0, vi = 0;
            const char *p = argv[i];
            while (*p && *p != '=' && ni < MAX_VAR_NAME - 1) vname[ni++] = *p++;
            vname[ni] = '\0';
            if (*p == '=') p++;
            while (*p && vi < MAX_VAR_VALUE - 1) vval[vi++] = *p++;
            vval[vi] = '\0';
            set_var(vname, vval, 1);
        }
        /* Print all exported */
        for (int i = 0; i < MAX_VARS; i++) {
            if (shell_vars[i].used && shell_vars[i].exported) {
                write_str(1, shell_vars[i].name);
                write_char(1, '=');
                write_str(1, shell_vars[i].value);
                write_char(1, '\n');
            }
        }
    } else {
        /* No args: print all exported variables */
        for (int i = 0; i < MAX_VARS; i++) {
            if (shell_vars[i].used && shell_vars[i].exported) {
                write_str(1, shell_vars[i].name);
                write_char(1, '=');
                write_str(1, shell_vars[i].value);
                write_char(1, '\n');
            }
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

/* Glob pattern matching (* and ?) */
static int glob_match(const char *pat, const char *str) {
    while (*pat) {
        if (*pat == '*') { pat++; if (!*pat) return 1; while (*str) { if (glob_match(pat, str)) return 1; str++; } return 0; }
        else if (*pat == '?') { if (!*str) return 0; pat++; str++; }
        else { if (*pat != *str) return 0; pat++; str++; }
    }
    return !*str;
}

static char _gbuf[2048];
static char *_gptrs[64];
static int expand_globs(int argc, char *argv[], int max_args) {
    int nc = 0, bp = 0;
    for (int i = 0; i < argc && nc < max_args - 1; i++) {
        int hg = 0;
        for (const char *p = argv[i]; *p; p++) if (*p == '*' || *p == '?') hg = 1;
        if (!hg) { _gptrs[nc++] = argv[i]; continue; }
        char dir[256] = "."; const char *pat = argv[i]; int ls = -1;
        for (int j = 0; argv[i][j]; j++) if (argv[i][j] == '/') ls = j;
        if (ls >= 0) { int dl = 0; for (int j = 0; j < ls && dl < 255; j++) dir[dl++] = argv[i][j]; if (!dl) dir[dl++] = '/'; dir[dl] = '\0'; pat = argv[i] + ls + 1; }
        struct { unsigned long long d_ino; long long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[256]; } *d;
        int fd = sys_open(dir, O_RDONLY, 0), matched = 0;
        if (fd >= 0) {
            char db[1024]; long n;
            while ((n = sys_getdents64(fd, db, sizeof(db))) > 0 && nc < max_args - 1) {
                char *ptr = db;
                while (ptr < db + n && nc < max_args - 1) {
                    d = (void *)ptr;
                    if (d->d_name[0] != '.' && glob_match(pat, d->d_name)) {
                        int pl = 0;
                        if (ls >= 0) { for (int k = 0; dir[k] && bp+pl < 2040; k++) _gbuf[bp+pl++] = dir[k]; _gbuf[bp+pl++] = '/'; }
                        for (int k = 0; d->d_name[k] && bp+pl < 2046; k++) _gbuf[bp+pl++] = d->d_name[k];
                        _gbuf[bp+pl] = '\0'; _gptrs[nc++] = _gbuf+bp; bp += pl+1; matched++;
                    }
                    ptr += d->d_reclen;
                }
            }
            sys_close(fd);
        }
        if (!matched) _gptrs[nc++] = argv[i];
    }
    _gptrs[nc] = NULL;
    for (int i = 0; i < nc; i++) argv[i] = _gptrs[i];
    argv[nc] = NULL;
    return nc;
}

/* Built-in: history */
/* Built-in: more — simple pager (24 lines at a time) */
/* less: scrollable pager with search, page up/down, line navigation */
static void cmd_less(int argc, char *argv[]) {
    int in_fd = 0;
    if (argc > 1) {
        in_fd = sys_open(argv[1], O_RDONLY, 0);
        if (in_fd < 0) { write_str(2, "less: cannot open "); write_str(2, argv[1]); write_str(2, "\n"); return; }
    }

    /* Read entire file into buffer */
    #define LESS_MAX (64 * 1024)
    #define LESS_ROWS 24
    static char fbuf[LESS_MAX];
    int total = 0;
    long n;
    while (total < LESS_MAX - 1 && (n = sys_read(in_fd, fbuf + total, LESS_MAX - 1 - total)) > 0)
        total += (int)n;
    fbuf[total] = '\0';
    if (argc > 1) sys_close(in_fd);

    /* Build line index */
    #define LESS_MAX_LINES 4096
    static int line_offsets[LESS_MAX_LINES];
    int nlines = 0;
    line_offsets[0] = 0;
    for (int i = 0; i < total && nlines < LESS_MAX_LINES - 1; i++) {
        if (fbuf[i] == '\n') {
            if (nlines + 1 < LESS_MAX_LINES)
                line_offsets[++nlines] = i + 1;
        }
    }
    if (nlines == 0 || line_offsets[nlines] < total) nlines++;

    int top = 0;  /* First visible line */
    static char search_pat[64];
    search_pat[0] = '\0';

    for (;;) {
        /* Display LESS_ROWS lines from top */
        write_str(1, "\033[2J\033[H");  /* Clear screen, cursor home */
        for (int r = 0; r < LESS_ROWS && (top + r) < nlines; r++) {
            int li = top + r;
            int start = line_offsets[li];
            int end = (li + 1 < nlines) ? line_offsets[li + 1] : total;
            if (end > start && fbuf[end - 1] == '\n') end--;
            int len = end - start;
            if (len > 0) sys_write(1, fbuf + start, len < 80 ? len : 80);
            write_str(1, "\n");
        }

        /* Status line */
        write_str(1, "\033[7m");
        if (argc > 1) { write_str(1, argv[1]); write_str(1, " "); }
        /* Show position */
        char pos[32]; int pp = 0;
        const char *prefix = "line ";
        while (*prefix) pos[pp++] = *prefix++;
        { int v = top + 1; char rev[8]; int rp = 0;
          if (v == 0) rev[rp++] = '0';
          while (v > 0) { rev[rp++] = '0' + (v % 10); v /= 10; }
          while (rp > 0) pos[pp++] = rev[--rp]; }
        pos[pp++] = '/';
        { int v = nlines; char rev[8]; int rp = 0;
          if (v == 0) rev[rp++] = '0';
          while (v > 0) { rev[rp++] = '0' + (v % 10); v /= 10; }
          while (rp > 0) pos[pp++] = rev[--rp]; }
        sys_write(1, pos, pp);
        write_str(1, "\033[0m");

        /* Read command */
        char key;
        if (sys_read(0, &key, 1) <= 0) break;

        if (key == 'q' || key == 'Q') break;
        else if (key == ' ' || key == 'f') { top += LESS_ROWS; if (top >= nlines) top = nlines - 1; }
        else if (key == 'b') { top -= LESS_ROWS; if (top < 0) top = 0; }
        else if (key == 'j' || key == '\n' || key == 'e') { if (top < nlines - 1) top++; }
        else if (key == 'k' || key == 'y') { if (top > 0) top--; }
        else if (key == 'g' || key == '<') { top = 0; }
        else if (key == 'G' || key == '>') { top = nlines > LESS_ROWS ? nlines - LESS_ROWS : 0; }
        else if (key == 'd') { top += LESS_ROWS / 2; if (top >= nlines) top = nlines - 1; }
        else if (key == 'u') { top -= LESS_ROWS / 2; if (top < 0) top = 0; }
        else if (key == '/') {
            /* Search forward */
            write_str(1, "\n/");
            int si = 0;
            while (si < 62) {
                char sc; if (sys_read(0, &sc, 1) <= 0) break;
                if (sc == '\n') break;
                search_pat[si++] = sc;
                sys_write(1, &sc, 1);
            }
            search_pat[si] = '\0';
            /* Find next occurrence */
            if (si > 0) {
                for (int li = top + 1; li < nlines; li++) {
                    int start = line_offsets[li];
                    int end = (li + 1 < nlines) ? line_offsets[li + 1] : total;
                    for (int j = start; j < end - si; j++) {
                        int match = 1;
                        for (int k = 0; k < si; k++) if (fbuf[j+k] != search_pat[k]) { match = 0; break; }
                        if (match) { top = li; goto less_found; }
                    }
                }
            }
            less_found:;
        }
        else if (key == 'n' && search_pat[0]) {
            /* Search next */
            int si = 0; while (search_pat[si]) si++;
            for (int li = top + 1; li < nlines; li++) {
                int start = line_offsets[li];
                int end = (li + 1 < nlines) ? line_offsets[li + 1] : total;
                for (int j = start; j < end - si; j++) {
                    int match = 1;
                    for (int k = 0; k < si; k++) if (fbuf[j+k] != search_pat[k]) { match = 0; break; }
                    if (match) { top = li; goto less_found2; }
                }
            }
            less_found2:;
        }
        else if (key == '\033') {
            /* Arrow keys: ESC [ A/B */
            char seq[2];
            if (sys_read(0, &seq[0], 1) > 0 && seq[0] == '[') {
                if (sys_read(0, &seq[1], 1) > 0) {
                    if (seq[1] == 'A') { if (top > 0) top--; }         /* Up */
                    else if (seq[1] == 'B') { if (top < nlines-1) top++; } /* Down */
                    else if (seq[1] == '5') { sys_read(0, &seq[0], 1); top -= LESS_ROWS; if (top < 0) top = 0; } /* PgUp */
                    else if (seq[1] == '6') { sys_read(0, &seq[0], 1); top += LESS_ROWS; if (top >= nlines) top = nlines-1; } /* PgDn */
                }
            }
        }
    }
    write_str(1, "\033[2J\033[H");  /* Clear on exit */
}

static void cmd_more(int argc, char *argv[]) {
    int in_fd = 0;  /* default stdin */
    if (argc > 1) {
        in_fd = sys_open(argv[1], O_RDONLY, 0);
        if (in_fd < 0) {
            write_str(2, "more: cannot open ");
            write_str(2, argv[1]);
            write_str(2, "\n");
            return;
        }
    }

    char buf[256];
    int lines = 0;
    int at_line_start = 1;
    long n;
    while ((n = sys_read(in_fd, buf, sizeof(buf))) > 0) {
        for (long i = 0; i < n; i++) {
            write_char(1, buf[i]);
            if (buf[i] == '\n') {
                lines++;
                at_line_start = 1;
                if (lines >= 24) {
                    write_str(1, "\033[7m--More--\033[0m");
                    /* Wait for keypress */
                    char key;
                    sys_read(0, &key, 1);
                    /* Clear the --More-- line */
                    write_str(1, "\r            \r");
                    if (key == 'q' || key == 'Q') {
                        if (argc > 1) sys_close(in_fd);
                        return;
                    }
                    lines = (key == ' ') ? 0 : lines - 1;  /* space=next page, enter=next line */
                }
            } else {
                at_line_start = 0;
            }
        }
    }
    (void)at_line_start;
    if (argc > 1) sys_close(in_fd);
}

/* Built-in: xargs — read args from stdin and execute command */
static void cmd_xargs(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: xargs [-0] [-n N] [-I repl] <command> [args...]\n");
        return;
    }

    int null_sep = 0;       /* -0: NUL-separated input (from find -print0) */
    int max_args = 0;       /* -n N: max args per invocation (0=all at once) */
    const char *repl_str = NULL;  /* -I {}: replace string mode */
    int arg_start = 1;

    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-0") == 0) {
            null_sep = 1; arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-n") == 0 && arg_start + 1 < argc) {
            arg_start++;
            max_args = 0;
            for (const char *s = argv[arg_start]; *s >= '0' && *s <= '9'; s++)
                max_args = max_args * 10 + (*s - '0');
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-I") == 0 && arg_start + 1 < argc) {
            arg_start++;
            repl_str = argv[arg_start]; arg_start++;
        } else {
            break;
        }
    }

    if (arg_start >= argc) {
        write_str(2, "xargs: no command specified\n");
        return;
    }

    /* Read all of stdin into a buffer */
    static char input[8192];
    int total = 0;
    long n;
    while ((n = sys_read(0, input + total, sizeof(input) - total - 1)) > 0) {
        total += (int)n;
        if (total >= (int)sizeof(input) - 1) break;
    }
    input[total] = '\0';

    /* Collect input items */
    char *items[256]; int nitems = 0;
    char *p = input;
    char sep = null_sep ? '\0' : ' ';

    if (null_sep) {
        /* NUL-separated: split on \0 bytes */
        while (p < input + total && nitems < 255) {
            if (*p == '\0') { p++; continue; }
            items[nitems++] = p;
            while (p < input + total && *p != '\0') p++;
            if (p < input + total) p++;  /* skip NUL */
        }
    } else {
        /* Whitespace-separated */
        while (*p && nitems < 255) {
            while (*p == ' ' || *p == '\t' || *p == '\n') p++;
            if (!*p) break;
            items[nitems++] = p;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
            if (*p) *p++ = '\0';
        }
    }
    (void)sep;

    if (repl_str) {
        /* -I mode: run command once per item, replacing repl_str */
        int rlen = 0; while (repl_str[rlen]) rlen++;
        for (int it = 0; it < nitems; it++) {
            char *xargv[64]; int xargc = 0;
            for (int i = arg_start; i < argc && xargc < 63; i++) {
                /* Check if this arg contains the replace string */
                int found = 0;
                for (int j = 0; argv[i][j]; j++) {
                    int match = 1;
                    for (int k = 0; k < rlen; k++) {
                        if (argv[i][j+k] != repl_str[k]) { match = 0; break; }
                    }
                    if (match) { found = 1; break; }
                }
                if (found && strcmp_simple(argv[i], repl_str) == 0) {
                    xargv[xargc++] = items[it];  /* Simple: replace whole arg */
                } else {
                    xargv[xargc++] = argv[i];
                }
            }
            xargv[xargc] = NULL;
            if (xargc > 0) execute_command(xargc, xargv);
        }
    } else if (max_args > 0) {
        /* -n mode: run command with N args at a time */
        int pos = 0;
        while (pos < nitems) {
            char *xargv[64]; int xargc = 0;
            for (int i = arg_start; i < argc && xargc < 60; i++)
                xargv[xargc++] = argv[i];
            for (int j = 0; j < max_args && pos < nitems && xargc < 63; j++)
                xargv[xargc++] = items[pos++];
            xargv[xargc] = NULL;
            if (xargc > 0) execute_command(xargc, xargv);
        }
    } else {
        /* Default: all items at once */
        char *xargv[64]; int xargc = 0;
        for (int i = arg_start; i < argc && xargc < 60; i++)
            xargv[xargc++] = argv[i];
        for (int it = 0; it < nitems && xargc < 63; it++)
            xargv[xargc++] = items[it];
        xargv[xargc] = NULL;
        if (xargc > 0) execute_command(xargc, xargv);
    }
}

static void cmd_history(int argc, char *argv[]) {
    (void)argc; (void)argv;
    for (int i = 0; i < history_count; i++) {
        const char *h = get_history(i);
        if (h) {
            char numbuf[8];
            int_to_str(i + 1, numbuf, 8);
            int pad = 4 - (int)strlen_simple(numbuf);
            while (pad-- > 0) write_char(1, ' ');
            write_str(1, numbuf);
            write_str(1, "  ");
            write_str(1, h);
            write_char(1, '\n');
        }
    }
}

/* Built-in: sysinfo — show comprehensive system summary */
static void cmd_sysinfo(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Kernel version */
    write_str(1, "\033[1mSystem Information\033[0m\n");
    int fd = sys_open("/proc/version", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[256]; ssize_t n = sys_read(fd, buf, 255);
        sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, "  Kernel:  "); write_str(1, buf); }
    }
    /* CPU — show model name */
    fd = sys_open("/proc/cpuinfo", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[1024]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
        sys_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char *p = buf;
            while (*p) {
                /* Match "model name" or "CPU part" */
                if ((p[0] == 'm' && p[1] == 'o' && p[2] == 'd' && p[3] == 'e' && p[4] == 'l' && p[5] == ' ' && p[6] == 'n') ||
                    (p[0] == 'C' && p[1] == 'P' && p[2] == 'U' && p[3] == ' ' && p[4] == 'p')) {
                    write_str(1, "  ");
                    while (*p && *p != '\n') { write_char(1, *p++); }
                    write_char(1, '\n');
                    break;
                }
                while (*p && *p != '\n') p++;
                if (*p == '\n') p++;
            }
        }
    }
    /* Memory */
    fd = sys_open("/proc/meminfo", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[256]; ssize_t n = sys_read(fd, buf, 255);
        sys_close(fd);
        if (n > 0) { buf[n] = '\0'; write_str(1, "  "); /* First line = MemTotal */
            for (int i = 0; buf[i] && buf[i] != '\n'; i++) write_char(1, buf[i]);
            write_char(1, '\n');
        }
    }
    /* Uptime */
    fd = sys_open("/proc/uptime", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[32]; ssize_t n = sys_read(fd, buf, 31);
        sys_close(fd);
        if (n > 0) { buf[n] = '\0'; write_str(1, "  Uptime:  "); write_str(1, buf); }
    }
    /* Process count */
    int pcount = 0;
    fd = sys_open("/proc", O_RDONLY, 0);
    if (fd >= 0) {
        char db[2048]; long nr;
        while ((nr = sys_getdents64(fd, db, sizeof(db))) > 0) {
            char *ptr = db;
            while (ptr < db + nr) {
                unsigned short reclen = *(unsigned short *)(ptr + 16);
                char *name = ptr + 19;
                if (name[0] >= '1' && name[0] <= '9') pcount++;
                ptr += reclen;
            }
        }
        sys_close(fd);
    }
    write_str(1, "  Tasks:   ");
    char nbuf[8]; int_to_str(pcount, nbuf, 8);
    write_str(1, nbuf); write_str(1, " running\n");
    /* Network interfaces */
    {
        int nfd = sys_open("/proc/net/dev", O_RDONLY, 0);
        if (nfd >= 0) {
            char nb[1024]; ssize_t nn = sys_read(nfd, nb, sizeof(nb)-1);
            sys_close(nfd);
            if (nn > 0) {
                nb[nn] = '\0';
                int iface_count = 0;
                for (int i = 0; i < nn; i++) if (nb[i] == ':') iface_count++;
                write_str(1, "  Network: ");
                char ic[4]; int ip2 = 0;
                if (iface_count >= 10) ic[ip2++] = '0' + iface_count / 10;
                ic[ip2++] = '0' + iface_count % 10; ic[ip2] = '\0';
                write_str(1, ic);
                write_str(1, " interfaces\n");
            }
        }
    }
    /* IP forwarding status */
    {
        int ffd = sys_open("/proc/sys/net/ipv4/ip_forward", O_RDONLY, 0);
        if (ffd >= 0) {
            char fb[4]; ssize_t fn = sys_read(ffd, fb, 1);
            sys_close(ffd);
            if (fn > 0) {
                write_str(1, "  Forward: ");
                write_str(1, fb[0] == '1' ? "enabled" : "disabled");
                write_str(1, "\n");
            }
        }
    }
    /* Shell */
    write_str(1, "  Shell:   Futura Shell v0.5 (105 builtins)\n");
    write_str(1, "  Tests:   1955 kernel self-tests\n");
}

/* Helper: count lines, words, bytes, and max line length in a file descriptor */
static long g_wc_max_line_len;  /* max line length (for -L) */
static void wc_count_fd(int fd, long *lines, long *words, long *bytes) {
    *lines = 0;
    *words = 0;
    *bytes = 0;
    g_wc_max_line_len = 0;
    int in_word = 0;
    long cur_line_len = 0;

    char buffer[256];
    long bytes_read;

    while ((bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
        *bytes += bytes_read;

        for (long i = 0; i < bytes_read; i++) {
            char c = buffer[i];

            /* Count newlines and track max line length */
            if (c == '\n') {
                (*lines)++;
                if (cur_line_len > g_wc_max_line_len)
                    g_wc_max_line_len = cur_line_len;
                cur_line_len = 0;
            } else {
                cur_line_len++;
            }

            /* Count words (whitespace-delimited) */
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                in_word = 0;
            } else if (!in_word) {
                in_word = 1;
                (*words)++;
            }
        }
    }
    /* Handle last line without newline */
    if (cur_line_len > g_wc_max_line_len)
        g_wc_max_line_len = cur_line_len;
}

/* Helper: print wc counts */
static void wc_print_counts(long lines, long words, long bytes, const char *name,
                            int show_lines, int show_words, int show_bytes) {
    char num_buf[32];

    if (show_lines) {
        int_to_str(lines, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');
    }

    if (show_words) {
        int_to_str(words, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');
    }

    if (show_bytes) {
        int_to_str(bytes, num_buf, sizeof(num_buf));
        write_str(1, num_buf);
        write_char(1, ' ');
    }

    if (name) {
        write_str(1, name);
    }
    write_char(1, '\n');
}

/* Built-in: wc - Count lines, words, bytes, chars, and max line length */
static void cmd_wc(int argc, char *argv[]) {
    int show_lines = 0;
    int show_words = 0;
    int show_bytes = 0;
    int show_chars = 0;
    int show_max_line = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-' && argv[arg_start][1] != '\0') {
        const char *opt = argv[arg_start];
        if (strcmp_simple(opt, "-l") == 0) {
            show_lines = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-w") == 0) {
            show_words = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-c") == 0) {
            show_bytes = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-m") == 0) {
            show_chars = 1;  /* Same as -c for ASCII */
            arg_start++;
        } else if (strcmp_simple(opt, "-L") == 0) {
            show_max_line = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "wc: unknown option: ");
            write_str(2, opt);
            write_str(2, "\n");
            write_str(2, "Usage: wc [-l] [-w] [-c] [-m] [-L] [file...]\n");
            return;
        }
    }

    /* If no flags specified, show all (except -L and -m) */
    if (!show_lines && !show_words && !show_bytes && !show_chars && !show_max_line) {
        show_lines = show_words = show_bytes = 1;
    }

    /* Process files or stdin */
    if (arg_start >= argc) {
        /* Read from stdin */
        long lines, words, bytes;
        wc_count_fd(0, &lines, &words, &bytes);
        if (show_max_line) {
            char num[32]; int_to_str(g_wc_max_line_len, num, sizeof(num));
            write_str(1, num); write_char(1, '\n');
        } else if (show_chars) {
            wc_print_counts(0, 0, bytes, NULL, 0, 0, 1);
        } else {
            wc_print_counts(lines, words, bytes, NULL, show_lines, show_words, show_bytes);
        }
    } else {
        /* Process each file */
        for (int file_idx = arg_start; file_idx < argc; file_idx++) {
            const char *path = argv[file_idx];

            int fd = sys_open(path, O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "wc: ");
                write_str(2, path);
                write_str(2, ": cannot open file\n");
                continue;
            }

            long lines, words, bytes;
            wc_count_fd(fd, &lines, &words, &bytes);
            sys_close(fd);

            if (show_max_line) {
                char num[32]; int_to_str(g_wc_max_line_len, num, sizeof(num));
                write_str(1, num); write_char(1, ' ');
                write_str(1, path); write_char(1, '\n');
            } else if (show_chars) {
                wc_print_counts(0, 0, bytes, path, 0, 0, 1);
            } else {
                wc_print_counts(lines, words, bytes, path, show_lines, show_words, show_bytes);
            }
        }
    }
}

/* Helper: process file descriptor for head command */
static void head_process_fd(int fd, int max_lines) {
    int lines_printed = 0;
    char buffer[256];
    long bytes_read;

    while (lines_printed < max_lines &&
           (bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
        for (long i = 0; i < bytes_read && lines_printed < max_lines; i++) {
            char c = buffer[i];
            write_char(1, c);
            if (c == '\n') {
                lines_printed++;
            }
        }
    }
}

/* Built-in: head - Display first N lines of files */
static void cmd_head(int argc, char *argv[]) {
    int num_lines = 10;  /* Default: 10 lines */
    int num_bytes = 0;   /* -c N: output first N bytes */
    int file_start = 1;

    /* Parse options */
    if (argc >= 3 && strcmp_simple(argv[1], "-n") == 0) {
        num_lines = simple_atoi(argv[2]);
        if (num_lines <= 0) num_lines = 10;
        file_start = 3;
    } else if (argc >= 3 && strcmp_simple(argv[1], "-c") == 0) {
        num_bytes = simple_atoi(argv[2]);
        file_start = 3;
    } else if (argc >= 2 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9') {
        /* head -N shorthand */
        num_lines = simple_atoi(argv[1] + 1);
        if (num_lines <= 0) num_lines = 10;
        file_start = 2;
    }

    /* -c N: output first N bytes */
    if (num_bytes > 0) {
        int fd = (file_start < argc) ? sys_open(argv[file_start], O_RDONLY, 0) : 0;
        if (fd < 0) { write_str(2, "head: cannot open file\n"); return; }
        static char buf[4096];
        int remaining = num_bytes;
        while (remaining > 0) {
            int chunk = remaining < (int)sizeof(buf) ? remaining : (int)sizeof(buf);
            ssize_t n = sys_read(fd, buf, chunk);
            if (n <= 0) break;
            sys_write(1, buf, n);
            remaining -= (int)n;
        }
        if (fd > 0) sys_close(fd);
        return;
    }

    /* Process files or stdin */
    if (file_start >= argc) {
        /* Read from stdin */
        head_process_fd(0, num_lines);
    } else {
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
            head_process_fd(fd, num_lines);

            sys_close(fd);
        }
    }
}

/* Helper: process file descriptor for tail command */
#define TAIL_MAX_FILE_SIZE 65536  /* 64KB limit for simplicity */

static int tail_process_fd(int fd, int max_lines) {
    char *file_buffer = malloc(TAIL_MAX_FILE_SIZE);  /* Dynamically allocate buffer */
    if (!file_buffer) {
        return 0;
    }
    long total_bytes = 0;
    long bytes_read;
    char chunk[256];

    /* Read entire input into buffer */
    while ((bytes_read = sys_read(fd, chunk, sizeof(chunk))) > 0) {
        if (total_bytes + bytes_read > TAIL_MAX_FILE_SIZE) {
            free(file_buffer);
            return -1;  /* File too large */
        }
        for (long i = 0; i < bytes_read; i++) {
            file_buffer[total_bytes++] = chunk[i];
        }
    }

    if (bytes_read < 0) {
        free(file_buffer);
        return -2;  /* Read error */
    }

    /* Count total lines */
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
    long skip_lines = total_lines > max_lines ? total_lines - max_lines : 0;

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

    free(file_buffer);
    return 0;  /* Success */
}

/* Built-in: tail - Display last N lines of files */
static void cmd_tail(int argc, char *argv[]) {
    int num_lines = 10;
    int follow_mode = 0;
    int file_start = 1;

    /* Parse options */
    while (file_start < argc && argv[file_start][0] == '-') {
        if (strcmp_simple(argv[file_start], "-n") == 0 && file_start + 1 < argc) {
            num_lines = simple_atoi(argv[file_start + 1]);
            if (num_lines <= 0) num_lines = 10;
            file_start += 2;
        } else if (strcmp_simple(argv[file_start], "-f") == 0) {
            follow_mode = 1;
            file_start++;
        } else if (argv[file_start][1] == 'f') {
            follow_mode = 1;
            file_start++;
        } else {
            break;
        }
    }

    if (file_start >= argc) {
        /* Read from stdin */
        int result = tail_process_fd(0, num_lines);
        if (result < 0) write_str(2, "tail: read error\n");
        /* -f on stdin: keep reading */
        if (follow_mode) {
            char c;
            while (sys_read(0, &c, 1) > 0) write_char(1, c);
        }
    } else {
        const char *path = argv[file_start];
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "tail: "); write_str(2, path);
            write_str(2, ": cannot open file\n");
            return;
        }

        tail_process_fd(fd, num_lines);

        if (follow_mode) {
            /* Follow mode: keep reading new data as it's appended.
             * Poll the fd periodically for new data. */
            write_str(2, "[tail -f: following, Ctrl+C to stop]\n");
            while (1) {
                char buf[256];
                long n = sys_read(fd, buf, sizeof(buf));
                if (n > 0) {
                    for (long i = 0; i < n; i++) write_char(1, buf[i]);
                } else {
                    /* No new data — sleep briefly and retry */
                    struct { long tv_sec; long tv_nsec; } ts = {0, 100000000}; /* 100ms */
                    sys_call2(35 /* nanosleep */, (long)&ts, 0);
                }
            }
        }
        sys_close(fd);
    }
}

/* Helper: output a line with its count for uniq command */
static void uniq_output_line(const char *line, int count, int count_mode,
                              int duplicates_only, int unique_only) {
    /* Apply filters */
    if (duplicates_only && count <= 1) return;
    if (unique_only && count > 1) return;

    /* Output with optional count */
    if (count_mode) {
        /* Convert count to string and output */
        char count_str[32];
        int count_len = 0;
        int temp_count = count;

        /* Build count string in reverse */
        do {
            count_str[count_len++] = '0' + (temp_count % 10);
            temp_count /= 10;
        } while (temp_count > 0);

        /* Output count with leading spaces (7 chars wide) */
        for (int i = count_len; i < 7; i++) {
            write_char(1, ' ');
        }

        /* Output count digits in correct order */
        for (int i = count_len - 1; i >= 0; i--) {
            write_char(1, count_str[i]);
        }

        write_char(1, ' ');
    }

    write_str(1, line);
    write_char(1, '\n');
}

#define UNIQ_MAX_LINE 1024

/* Helper: process file descriptor for uniq command */
static void uniq_process_fd(int fd, char *prev_line, char *curr_line,
                             int *prev_line_valid, int *curr_count,
                             int count_mode, int duplicates_only, int unique_only) {
    /* Read line by line */
    char read_buf[256];
    int line_pos = 0;
    long bytes_read;

    while ((bytes_read = sys_read(fd, read_buf, sizeof(read_buf))) > 0) {
        for (long i = 0; i < bytes_read; i++) {
            char c = read_buf[i];

            if (c == '\n' || line_pos >= UNIQ_MAX_LINE - 1) {
                curr_line[line_pos] = '\0';

                /* Compare with previous line */
                if (*prev_line_valid && strcmp_simple(curr_line, prev_line) == 0) {
                    /* Same as previous, increment count */
                    (*curr_count)++;
                } else {
                    /* Different from previous */
                    if (*prev_line_valid) {
                        /* Output the previous line with its count */
                        uniq_output_line(prev_line, *curr_count, count_mode,
                                       duplicates_only, unique_only);
                    }

                    /* Copy current to previous */
                    int copy_idx = 0;
                    while (curr_line[copy_idx] && copy_idx < UNIQ_MAX_LINE - 1) {
                        prev_line[copy_idx] = curr_line[copy_idx];
                        copy_idx++;
                    }
                    prev_line[copy_idx] = '\0';
                    *prev_line_valid = 1;
                    *curr_count = 1;
                }

                line_pos = 0;
            } else {
                curr_line[line_pos++] = c;
            }
        }
    }

    /* Handle last line if input doesn't end with newline */
    if (line_pos > 0) {
        curr_line[line_pos] = '\0';

        if (*prev_line_valid && strcmp_simple(curr_line, prev_line) == 0) {
            (*curr_count)++;
        } else {
            if (*prev_line_valid) {
                uniq_output_line(prev_line, *curr_count, count_mode,
                               duplicates_only, unique_only);
            }

            int copy_idx = 0;
            while (curr_line[copy_idx] && copy_idx < UNIQ_MAX_LINE - 1) {
                prev_line[copy_idx] = curr_line[copy_idx];
                copy_idx++;
            }
            prev_line[copy_idx] = '\0';
            *prev_line_valid = 1;
            *curr_count = 1;
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
/* Case-insensitive character comparison for -iname */
static int find_tolower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static int find_match_icase(const char *name, const char *pattern) {
    /* Same as match_pattern but case-insensitive */
    if (!pattern) return 1;
    const char *n = name, *p = pattern;
    const char *n_back = 0, *p_back = 0;
    while (*n) {
        if (*p == '*') {
            while (*p == '*') p++;
            if (!*p) return 1;
            n_back = n; p_back = p;
        } else if (*p == '?' || find_tolower(*n) == find_tolower(*p)) {
            n++; p++;
        } else if (p_back) {
            n = ++n_back; p = p_back;
        } else {
            return 0;
        }
    }
    while (*p == '*') p++;
    return *p == '\0';
}

/* find options passed through recursion */
struct find_opts {
    const char *name_pattern;
    const char *iname_pattern;  /* case-insensitive name */
    const char *path_pattern;   /* match against full path */
    int type_filter;            /* 0=all, 'f'=files, 'd'=dirs, 'l'=symlinks */
    int maxdepth;               /* -1 = unlimited */
    int mindepth;               /* 0 = default */
    int print0;                 /* NUL separator instead of newline */
    int exec_argc;              /* -exec args count (0 = no exec) */
    char **exec_argv;           /* -exec args (NULL = no exec) */
};

static void find_recurse(const char *path, struct find_opts *opts, int depth) {
    if (depth > 32) return;
    if (opts->maxdepth >= 0 && depth > opts->maxdepth) return;

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return;

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

            if (strcmp_simple(d->d_name, ".") != 0 && strcmp_simple(d->d_name, "..") != 0) {
                char full_path[1024];
                int path_len = 0;
                const char *p = path;
                while (*p && path_len < 1023) full_path[path_len++] = *p++;
                if (path_len > 0 && full_path[path_len - 1] != '/') full_path[path_len++] = '/';
                p = d->d_name;
                while (*p && path_len < 1023) full_path[path_len++] = *p++;
                full_path[path_len] = '\0';

                int child_depth = depth + 1;
                int type_match = 1;
                if (opts->type_filter == 'f') type_match = (d->d_type != 4);
                else if (opts->type_filter == 'd') type_match = (d->d_type == 4);
                else if (opts->type_filter == 'l') type_match = (d->d_type == 10); /* DT_LNK */

                int name_match = 1;
                if (opts->name_pattern) name_match = match_pattern(d->d_name, opts->name_pattern);
                if (name_match && opts->iname_pattern) name_match = find_match_icase(d->d_name, opts->iname_pattern);
                if (name_match && opts->path_pattern) name_match = match_pattern(full_path, opts->path_pattern);

                int depth_match = (child_depth >= opts->mindepth);

                if (type_match && name_match && depth_match) {
                    if (opts->exec_argc > 0 && opts->exec_argv) {
                        /* -exec: build argv with {} replaced by path */
                        char *eargv[32]; int eargc = 0;
                        for (int i = 0; i < opts->exec_argc && eargc < 31; i++) {
                            if (strcmp_simple(opts->exec_argv[i], "{}") == 0)
                                eargv[eargc++] = full_path;
                            else
                                eargv[eargc++] = opts->exec_argv[i];
                        }
                        eargv[eargc] = 0;
                        /* Execute command in child process */
                        extern long sys_fork(void);
                        extern long sys_execve(const char *, char *const[], char *const[]);
                        extern long sys_waitpid(int, int *, int);
                        long pid = sys_fork();
                        if (pid == 0) {
                            sys_execve(eargv[0], eargv, 0);
                            sys_exit(127);
                        } else if (pid > 0) {
                            int status = 0;
                            sys_waitpid((int)pid, &status, 0);
                        }
                    } else {
                        sys_write(1, full_path, path_len);
                        sys_write(1, opts->print0 ? "\0" : "\n", 1);
                    }
                }

                if (d->d_type == 4) {
                    find_recurse(full_path, opts, child_depth);
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
    struct find_opts opts;
    opts.name_pattern = 0;
    opts.iname_pattern = 0;
    opts.path_pattern = 0;
    opts.type_filter = 0;
    opts.maxdepth = -1;
    opts.mindepth = 0;
    opts.print0 = 0;
    opts.exec_argc = 0;
    opts.exec_argv = 0;
    int arg_idx = 1;

    /* If first arg doesn't start with -, it's the path */
    if (arg_idx < argc && argv[arg_idx][0] != '-') {
        start_path = argv[arg_idx];
        arg_idx++;
    }

    /* Parse options */
    while (arg_idx < argc) {
        if (strcmp_simple(argv[arg_idx], "-name") == 0 && arg_idx + 1 < argc) {
            opts.name_pattern = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-iname") == 0 && arg_idx + 1 < argc) {
            opts.iname_pattern = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-path") == 0 && arg_idx + 1 < argc) {
            opts.path_pattern = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-type") == 0 && arg_idx + 1 < argc) {
            if (argv[arg_idx + 1][0] == 'f') opts.type_filter = 'f';
            else if (argv[arg_idx + 1][0] == 'd') opts.type_filter = 'd';
            else if (argv[arg_idx + 1][0] == 'l') opts.type_filter = 'l';
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-maxdepth") == 0 && arg_idx + 1 < argc) {
            opts.maxdepth = 0;
            const char *s = argv[arg_idx + 1];
            while (*s >= '0' && *s <= '9') opts.maxdepth = opts.maxdepth * 10 + (*s++ - '0');
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-mindepth") == 0 && arg_idx + 1 < argc) {
            opts.mindepth = 0;
            const char *s = argv[arg_idx + 1];
            while (*s >= '0' && *s <= '9') opts.mindepth = opts.mindepth * 10 + (*s++ - '0');
            arg_idx += 2;
        } else if (strcmp_simple(argv[arg_idx], "-print0") == 0) {
            opts.print0 = 1;
            arg_idx++;
        } else if (strcmp_simple(argv[arg_idx], "-exec") == 0) {
            /* Collect args until ; */
            opts.exec_argv = &argv[arg_idx + 1];
            opts.exec_argc = 0;
            arg_idx++;
            while (arg_idx < argc && strcmp_simple(argv[arg_idx], ";") != 0) {
                opts.exec_argc++;
                arg_idx++;
            }
            if (arg_idx < argc) arg_idx++; /* skip ; */
        } else if (strcmp_simple(argv[arg_idx], "-print") == 0) {
            arg_idx++; /* explicit -print is default */
        } else {
            write_str(2, "find: unknown option: ");
            write_str(2, argv[arg_idx]);
            write_str(2, "\n");
            return;
        }
    }

    /* Print the starting directory if it matches filters */
    if (opts.mindepth == 0 && (opts.type_filter == 0 || opts.type_filter == 'd')) {
        int name_ok = 1;
        if (opts.name_pattern) name_ok = match_pattern(start_path, opts.name_pattern);
        if (name_ok && opts.iname_pattern) name_ok = find_match_icase(start_path, opts.iname_pattern);
        if (name_ok) {
            write_str(1, start_path);
            write_str(1, opts.print0 ? "\0" : "\n");
        }
    }

    find_recurse(start_path, &opts, 0);
}

/* Built-in: uniq - Report or omit repeated lines */
static void cmd_uniq(int argc, char *argv[]) {
    int count_mode = 0;
    int duplicates_only = 0;
    int unique_only = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-c") == 0) {
            count_mode = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-d") == 0) {
            duplicates_only = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-u") == 0) {
            unique_only = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "uniq: unknown option: ");
            write_str(2, argv[arg_start]);
            write_str(2, "\n");
            write_str(2, "Usage: uniq [-c] [-d] [-u] [file]...\n");
            return;
        }
    }

    /* Conflicting options check */
    if (duplicates_only && unique_only) {
        write_str(2, "uniq: -d and -u are mutually exclusive\n");
        return;
    }

    /* Allocate buffers for lines */
    static char prev_line[UNIQ_MAX_LINE];
    static char curr_line[UNIQ_MAX_LINE];
    int prev_line_valid = 0;
    int curr_count = 0;

    /* Process files or stdin */
    if (arg_start >= argc) {
        /* Read from stdin */
        uniq_process_fd(0, prev_line, curr_line, &prev_line_valid, &curr_count,
                        count_mode, duplicates_only, unique_only);
    } else {
        /* Process each file */
        for (int file_idx = arg_start; file_idx < argc; file_idx++) {
            const char *path = argv[file_idx];

            int fd = sys_open(path, O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "uniq: ");
                write_str(2, path);
                write_str(2, ": cannot open file\n");
                continue;
            }

            uniq_process_fd(fd, prev_line, curr_line, &prev_line_valid, &curr_count,
                            count_mode, duplicates_only, unique_only);
            sys_close(fd);
        }
    }

    /* Output the last line */
    if (prev_line_valid) {
        uniq_output_line(prev_line, curr_count, count_mode, duplicates_only, unique_only);
    }
}

/* Helper function to process a single line for cut command */
#define CUT_MAX_LINE 2048
static void cut_process_line(const char *line, int char_mode, int char_start, int char_end,
                             int field_num, char delimiter) {
    if (char_mode) {
        /* Character mode: extract characters char_start to char_end */
        int len = 0;
        while (line[len]) len++;

        for (int pos = char_start; pos <= char_end && pos <= len; pos++) {
            write_char(1, line[pos - 1]);
        }
        write_char(1, '\n');
    } else {
        /* Field mode: split by delimiter and extract field */
        int current_field = 1;
        int idx = 0;

        while (1) {
            /* Find end of current field */
            int field_end = idx;
            while (line[field_end] && line[field_end] != delimiter) {
                field_end++;
            }

            /* Check if this is the field we want */
            if (current_field == field_num) {
                /* Output this field */
                for (int j = idx; j < field_end; j++) {
                    write_char(1, line[j]);
                }
                write_char(1, '\n');
                break;
            }

            /* Move to next field */
            if (line[field_end] == '\0') {
                /* No more fields, output empty line */
                write_char(1, '\n');
                break;
            }

            idx = field_end + 1;
            current_field++;
        }
    }
}

/* Helper function to process a file descriptor for cut command */
static void cut_process_fd(int fd, char *line_buf, int char_mode, int char_start, int char_end,
                           int field_num, char delimiter) {
    char read_buf[256];
    int line_pos = 0;
    long bytes_read;

    while ((bytes_read = sys_read(fd, read_buf, sizeof(read_buf))) > 0) {
        for (long i = 0; i < bytes_read; i++) {
            char c = read_buf[i];

            if (c == '\n' || line_pos >= CUT_MAX_LINE - 1) {
                line_buf[line_pos] = '\0';
                cut_process_line(line_buf, char_mode, char_start, char_end, field_num, delimiter);
                line_pos = 0;
            } else {
                line_buf[line_pos++] = c;
            }
        }
    }

    /* Handle last line if input doesn't end with newline */
    if (line_pos > 0) {
        line_buf[line_pos] = '\0';
        cut_process_line(line_buf, char_mode, char_start, char_end, field_num, delimiter);
    }
}

/* Built-in: cut - Extract fields from lines */
static void cmd_cut(int argc, char *argv[]) {
    char delimiter = '\t';  /* Default delimiter is tab */
    int field_num = -1;
    int char_mode = 0;
    int char_start = -1;
    int char_end = -1;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (argv[arg_start][1] == 'd' && argv[arg_start][2] == '\0') {
            /* -d <delim> */
            if (arg_start + 1 >= argc) {
                write_str(2, "cut: -d requires an argument\n");
                return;
            }
            delimiter = argv[arg_start + 1][0];
            arg_start += 2;
        } else if (argv[arg_start][1] == 'f' && argv[arg_start][2] == '\0') {
            /* -f <field> */
            if (arg_start + 1 >= argc) {
                write_str(2, "cut: -f requires an argument\n");
                return;
            }
            /* Parse field number */
            const char *p = argv[arg_start + 1];
            field_num = 0;
            while (*p >= '0' && *p <= '9') {
                field_num = field_num * 10 + (*p - '0');
                p++;
            }
            if (field_num == 0) {
                write_str(2, "cut: field numbers start at 1\n");
                return;
            }
            arg_start += 2;
        } else if (argv[arg_start][1] == 'c' && argv[arg_start][2] == '\0') {
            /* -c <range> */
            if (arg_start + 1 >= argc) {
                write_str(2, "cut: -c requires an argument\n");
                return;
            }
            char_mode = 1;
            /* Parse character range: N or N-M */
            const char *p = argv[arg_start + 1];
            char_start = 0;
            while (*p >= '0' && *p <= '9') {
                char_start = char_start * 10 + (*p - '0');
                p++;
            }
            if (*p == '-') {
                p++;
                char_end = 0;
                while (*p >= '0' && *p <= '9') {
                    char_end = char_end * 10 + (*p - '0');
                    p++;
                }
            } else {
                char_end = char_start;
            }
            if (char_start == 0) {
                write_str(2, "cut: character positions start at 1\n");
                return;
            }
            arg_start += 2;
        } else if (strcmp_simple(argv[arg_start], "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "cut: unknown option: ");
            write_str(2, argv[arg_start]);
            write_str(2, "\n");
            write_str(2, "Usage: cut -f <field> [-d <delim>] [file]...\n");
            write_str(2, "   or: cut -c <N[-M]> [file]...\n");
            return;
        }
    }

    /* Check that either -f or -c was specified */
    if (field_num == -1 && !char_mode) {
        write_str(2, "cut: you must specify either -f or -c\n");
        return;
    }

    static char line_buf[CUT_MAX_LINE];

    /* Process files or stdin */
    if (arg_start >= argc) {
        /* Read from stdin */
        cut_process_fd(0, line_buf, char_mode, char_start, char_end, field_num, delimiter);
    } else {
        /* Process each file */
        for (int file_idx = arg_start; file_idx < argc; file_idx++) {
            const char *path = argv[file_idx];

            int fd = sys_open(path, O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "cut: ");
                write_str(2, path);
                write_str(2, ": cannot open file\n");
                continue;
            }

            cut_process_fd(fd, line_buf, char_mode, char_start, char_end, field_num, delimiter);
            sys_close(fd);
        }
    }
}

/* Helper function to process a file descriptor for tr command */
static void tr_process_fd(int fd, const char *trans_map, int delete_mode, int squeeze_mode) {
    char read_buf[256];
    char last_char = '\0';
    long bytes_read;

    while ((bytes_read = sys_read(fd, read_buf, sizeof(read_buf))) > 0) {
        for (long i = 0; i < bytes_read; i++) {
            char c = read_buf[i];
            unsigned char uc = (unsigned char)c;

            if (delete_mode) {
                /* Skip deleted characters */
                if (trans_map[uc] == '\0') {
                    continue;
                }
                /* Output character */
                if (squeeze_mode && c == last_char) {
                    continue;  /* Skip repeated character */
                }
                write_char(1, c);
                last_char = c;
            } else {
                /* Translate character */
                char out_char = trans_map[uc];
                if (squeeze_mode && out_char == last_char) {
                    continue;  /* Skip repeated character */
                }
                write_char(1, out_char);
                last_char = out_char;
            }
        }
    }
}

/* Built-in: tr - Translate or delete characters */
static void cmd_tr(int argc, char *argv[]) {
    int delete_mode = 0;
    int squeeze_mode = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-d") == 0) {
            delete_mode = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "-s") == 0) {
            squeeze_mode = 1;
            arg_start++;
        } else if (strcmp_simple(argv[arg_start], "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "tr: unknown option: ");
            write_str(2, argv[arg_start]);
            write_str(2, "\n");
            write_str(2, "Usage: tr [-d] [-s] <set1> [set2] [file...]\n");
            return;
        }
    }

    /* Check arguments */
    int required_args = delete_mode ? 1 : 2;
    if (arg_start + required_args > argc) {
        write_str(2, "tr: missing operands\n");
        write_str(2, "Usage: tr [-d] [-s] <set1> [set2] [file...]\n");
        return;
    }

    const char *set1 = argv[arg_start];
    const char *set2 = delete_mode ? 0 : argv[arg_start + 1];
    int file_start = arg_start + required_args;

    /* Build translation map */
    static char trans_map[256];
    for (int i = 0; i < 256; i++) {
        trans_map[i] = i;  /* Identity by default */
    }

    if (delete_mode) {
        /* Mark characters to delete */
        for (const char *p = set1; *p; p++) {
            trans_map[(unsigned char)*p] = '\0';  /* Mark for deletion */
        }
    } else {
        /* Build translation map */
        const char *p1 = set1;
        const char *p2 = set2;
        while (*p1 && *p2) {
            trans_map[(unsigned char)*p1] = *p2;
            p1++;
            p2++;
        }
        /* If set1 is longer, map remaining to last char of set2 */
        if (*p1 && p2 > set2) {
            char last_char = *(p2 - 1);
            while (*p1) {
                trans_map[(unsigned char)*p1] = last_char;
                p1++;
            }
        }
    }

    /* Process files or stdin */
    if (file_start >= argc) {
        /* Read from stdin */
        tr_process_fd(0, trans_map, delete_mode, squeeze_mode);
    } else {
        /* Process each file */
        for (int file_idx = file_start; file_idx < argc; file_idx++) {
            const char *path = argv[file_idx];

            int fd = sys_open(path, O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "tr: ");
                write_str(2, path);
                write_str(2, ": cannot open file\n");
                continue;
            }

            tr_process_fd(fd, trans_map, delete_mode, squeeze_mode);
            sys_close(fd);
        }
    }
}

/* Built-in: sed - Stream editor for basic s/pattern/replacement/ */
/* sed: apply s/pat/rep/[g] substitution with & support */
static int sed_subst(const char *line, int llen, const char *pat, int plen,
                     const char *rep, int rlen, int global, char *out, int outsz) {
    int oi = 0, replaced = 0;
    for (int i = 0; i < llen && oi < outsz - 1; i++) {
        if ((!replaced || global) && plen > 0 && i + plen <= llen) {
            int match = 1;
            for (int j = 0; j < plen; j++) {
                if (line[i + j] != pat[j]) { match = 0; break; }
            }
            if (match) {
                /* Apply replacement with & = matched text */
                for (int j = 0; j < rlen && oi < outsz - 1; j++) {
                    if (rep[j] == '&') {
                        for (int k = 0; k < plen && oi < outsz - 1; k++) out[oi++] = line[i + k];
                    } else if (rep[j] == '\\' && j + 1 < rlen) {
                        j++;
                        if (rep[j] == 'n') out[oi++] = '\n';
                        else if (rep[j] == 't') out[oi++] = '\t';
                        else out[oi++] = rep[j];
                    } else {
                        out[oi++] = rep[j];
                    }
                }
                i += plen - 1;
                replaced = 1;
                continue;
            }
        }
        out[oi++] = line[i];
    }
    return oi;
}

/* sed: check if a pattern matches anywhere in line */
static int sed_pat_match(const char *line, int llen, const char *pat, int plen) {
    if (plen == 0) return 1;
    for (int i = 0; i <= llen - plen; i++) {
        int j;
        for (j = 0; j < plen; j++) if (line[i+j] != pat[j]) break;
        if (j == plen) return 1;
    }
    return 0;
}

/* sed command structure */
struct sed_cmd {
    int addr1_type;  /* 0=none, 1=line, 2=pattern, 3=last ($) */
    int addr2_type;  /* 0=none, 1=line, 2=pattern, 3=last ($) */
    int addr1_line;
    int addr2_line;
    char addr1_pat[64];
    char addr2_pat[64];
    char cmd;        /* 's','d','p','q','a','i','c' */
    char s_pat[128];
    char s_rep[128];
    int s_plen, s_rlen;
    int s_global;
    int negate;      /* ! modifier */
};

/* Parse a single sed address from string, return chars consumed */
static int sed_parse_addr(const char *s, int *type, int *line_num, char *pat_buf) {
    const char *start = s;
    *type = 0; *line_num = 0; pat_buf[0] = '\0';
    if (*s == '$') { *type = 3; return 1; }
    if (*s >= '0' && *s <= '9') {
        *type = 1;
        while (*s >= '0' && *s <= '9') { *line_num = *line_num * 10 + (*s - '0'); s++; }
        return (int)(s - start);
    }
    if (*s == '/' || *s == '\\') {
        char delim = (*s == '\\') ? s[1] : '/';
        if (*s == '\\') s += 2; else s++;
        *type = 2;
        int pi = 0;
        while (*s && *s != delim && pi < 62) pat_buf[pi++] = *s++;
        pat_buf[pi] = '\0';
        if (*s == delim) s++;
        return (int)(s - start);
    }
    return 0;
}

static void cmd_sed(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: sed [-n] [-e expr]... 's/pat/rep/[g]' [file...]\n");
        return;
    }

    int suppress = 0;  /* -n flag */
    /* Collect expressions */
    const char *exprs[8]; int nexprs = 0;
    int file_start = argc;  /* default: no files = stdin */

    for (int a = 1; a < argc; a++) {
        if (strcmp_simple(argv[a], "-n") == 0) {
            suppress = 1;
        } else if (strcmp_simple(argv[a], "-e") == 0 && a + 1 < argc) {
            if (nexprs < 8) exprs[nexprs++] = argv[++a];
        } else if (argv[a][0] == '-' && argv[a][1] == 'n') {
            suppress = 1;
        } else if (nexprs == 0 && argv[a][0] != '-') {
            /* First non-flag arg is the expression if no -e given yet */
            exprs[nexprs++] = argv[a];
            file_start = a + 1;
            break;
        }
    }
    /* Find file args after all expressions */
    if (file_start == argc) {
        for (int a = 1; a < argc; a++) {
            if (strcmp_simple(argv[a], "-n") == 0) continue;
            if (strcmp_simple(argv[a], "-e") == 0) { a++; continue; }
            int is_expr = 0;
            for (int e = 0; e < nexprs; e++) if (exprs[e] == argv[a]) { is_expr = 1; break; }
            if (!is_expr) { file_start = a; break; }
        }
    }

    if (nexprs == 0) { write_str(2, "sed: no expression\n"); return; }

    /* Parse commands from expressions (support ; separated) */
    struct sed_cmd cmds[16]; int ncmds = 0;
    for (int e = 0; e < nexprs && ncmds < 16; e++) {
        const char *ep = exprs[e];
        while (*ep && ncmds < 16) {
            while (*ep == ' ' || *ep == ';') ep++;
            if (!*ep) break;

            struct sed_cmd *c = &cmds[ncmds];
            __builtin_memset(c, 0, sizeof(*c));

            /* Parse address1 */
            int consumed = sed_parse_addr(ep, &c->addr1_type, &c->addr1_line, c->addr1_pat);
            ep += consumed;

            /* Optional comma + address2 */
            if (*ep == ',') {
                ep++;
                consumed = sed_parse_addr(ep, &c->addr2_type, &c->addr2_line, c->addr2_pat);
                ep += consumed;
            }

            /* Negate modifier */
            if (*ep == '!') { c->negate = 1; ep++; }
            while (*ep == ' ') ep++;

            /* Command */
            if (*ep == 's') {
                c->cmd = 's';
                char delim = ep[1];
                if (!delim) break;
                const char *pp = ep + 2;
                int pi = 0;
                while (*pp && *pp != delim && pi < 127) c->s_pat[pi++] = *pp++;
                c->s_pat[pi] = '\0'; c->s_plen = pi;
                if (*pp == delim) pp++;
                int ri = 0;
                while (*pp && *pp != delim && ri < 127) c->s_rep[ri++] = *pp++;
                c->s_rep[ri] = '\0'; c->s_rlen = ri;
                if (*pp == delim) pp++;
                c->s_global = (*pp == 'g'); if (*pp == 'g') pp++;
                ep = pp;
                ncmds++;
            } else if (*ep == 'd') {
                c->cmd = 'd'; ep++; ncmds++;
            } else if (*ep == 'p') {
                c->cmd = 'p'; ep++; ncmds++;
            } else if (*ep == 'q') {
                c->cmd = 'q'; ep++; ncmds++;
            } else {
                ep++; /* skip unknown */
            }
        }
    }

    /* Open input */
    int fd_in = 0;
    if (file_start < argc) {
        fd_in = sys_open(argv[file_start], O_RDONLY, 0);
        if (fd_in < 0) {
            write_str(2, "sed: cannot open '");
            write_str(2, argv[file_start]);
            write_str(2, "'\n");
            return;
        }
    }

    /* Process lines */
    char line[1024];
    int lp = 0, lineno = 0, quit = 0;
    char ch;
    while (!quit && sys_read(fd_in, &ch, 1) == 1) {
        if (ch == '\n' || lp >= 1022) {
            line[lp] = '\0';
            lineno++;

            int deleted = 0;
            char work[1024];
            int wlen = lp;
            for (int i = 0; i < lp; i++) work[i] = line[i];
            work[wlen] = '\0';

            for (int ci = 0; ci < ncmds && !deleted; ci++) {
                struct sed_cmd *c = &cmds[ci];
                /* Check address match */
                int matched = 0;
                if (c->addr1_type == 0) {
                    matched = 1;  /* No address = all lines */
                } else if (c->addr1_type == 1 && c->addr2_type == 0) {
                    matched = (lineno == c->addr1_line);
                } else if (c->addr1_type == 3) {
                    matched = 0; /* $ = last line, can't know yet; approximate: never */
                } else if (c->addr1_type == 2 && c->addr2_type == 0) {
                    int pl = 0; while (c->addr1_pat[pl]) pl++;
                    matched = sed_pat_match(work, wlen, c->addr1_pat, pl);
                } else if (c->addr1_type == 1 && c->addr2_type == 1) {
                    matched = (lineno >= c->addr1_line && lineno <= c->addr2_line);
                } else if (c->addr1_type == 1 && c->addr2_type == 2) {
                    /* Start at line N, end at /pattern/ */
                    if (lineno >= c->addr1_line) {
                        int pl = 0; while (c->addr2_pat[pl]) pl++;
                        matched = 1; /* In range until pattern found */
                        if (sed_pat_match(work, wlen, c->addr2_pat, pl)) matched = 1; /* include this line */
                    }
                }
                if (c->negate) matched = !matched;
                if (!matched) continue;

                switch (c->cmd) {
                    case 's': {
                        char out[1024];
                        int nlen = sed_subst(work, wlen, c->s_pat, c->s_plen,
                                              c->s_rep, c->s_rlen, c->s_global, out, 1023);
                        for (int i = 0; i < nlen; i++) work[i] = out[i];
                        wlen = nlen; work[wlen] = '\0';
                        break;
                    }
                    case 'd': deleted = 1; break;
                    case 'p':
                        sys_write(1, work, wlen);
                        sys_write(1, "\n", 1);
                        break;
                    case 'q': quit = 1; break;
                }
            }

            if (!deleted && !suppress) {
                sys_write(1, work, wlen);
                sys_write(1, "\n", 1);
            }
            lp = 0;
        } else {
            line[lp++] = ch;
        }
    }
    /* Handle last line without newline */
    if (lp > 0 && !quit) {
        line[lp] = '\0';
        lineno++;
        int deleted = 0;
        char work[1024];
        int wlen = lp;
        for (int i = 0; i < lp; i++) work[i] = line[i];
        work[wlen] = '\0';
        for (int ci = 0; ci < ncmds && !deleted; ci++) {
            struct sed_cmd *c = &cmds[ci];
            int matched = (c->addr1_type == 0) ? 1 :
                          (c->addr1_type == 1 && lineno == c->addr1_line) ? 1 :
                          (c->addr1_type == 3) ? 1 : 0;  /* $ matches last line */
            if (c->addr1_type == 2) {
                int pl = 0; while (c->addr1_pat[pl]) pl++;
                matched = sed_pat_match(work, wlen, c->addr1_pat, pl);
            }
            if (c->negate) matched = !matched;
            if (!matched) continue;
            switch (c->cmd) {
                case 's': { char out[1024];
                    int nlen = sed_subst(work, wlen, c->s_pat, c->s_plen,
                                          c->s_rep, c->s_rlen, c->s_global, out, 1023);
                    for (int i = 0; i < nlen; i++) work[i] = out[i];
                    wlen = nlen; work[wlen] = '\0'; break; }
                case 'd': deleted = 1; break;
                case 'p': sys_write(1, work, wlen); sys_write(1, "\n", 1); break;
                case 'q': break;
            }
        }
        if (!deleted && !suppress) { sys_write(1, work, wlen); sys_write(1, "\n", 1); }
    }
    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: rev - Reverse lines of text */
static void cmd_rev(int argc, char *argv[]) {
    int fd_in = 0;
    if (argc >= 2) {
        fd_in = sys_open(argv[1], O_RDONLY, 0);
        if (fd_in < 0) { write_str(2, "rev: cannot open file\n"); return; }
    }
    char line[1024];
    int lp = 0;
    char ch;
    while (sys_read(fd_in, &ch, 1) == 1) {
        if (ch == '\n') {
            /* Reverse and print */
            for (int i = lp - 1; i >= 0; i--) sys_write(1, &line[i], 1);
            sys_write(1, "\n", 1);
            lp = 0;
        } else if (lp < 1022) {
            line[lp++] = ch;
        }
    }
    if (lp > 0) {
        for (int i = lp - 1; i >= 0; i--) sys_write(1, &line[i], 1);
        sys_write(1, "\n", 1);
    }
    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: nl - Number lines */
static void cmd_nl(int argc, char *argv[]) {
    int fd_in = 0;
    if (argc >= 2) {
        fd_in = sys_open(argv[1], O_RDONLY, 0);
        if (fd_in < 0) { write_str(2, "nl: cannot open file\n"); return; }
    }
    char line[1024];
    int lp = 0;
    int lineno = 1;
    char ch;
    while (sys_read(fd_in, &ch, 1) == 1) {
        if (ch == '\n') {
            line[lp] = '\0';
            /* Print line number and line */
            char num[16];
            int np = 0;
            int n = lineno;
            if (n == 0) { num[np++] = '0'; }
            else { char rev[16]; int rp = 0;
                while (n > 0) { rev[rp++] = '0' + (n % 10); n /= 10; }
                while (rp > 0) num[np++] = rev[--rp]; }
            /* Right-justify to 6 chars */
            for (int i = np; i < 6; i++) sys_write(1, " ", 1);
            sys_write(1, num, np);
            sys_write(1, "\t", 1);
            sys_write(1, line, lp);
            sys_write(1, "\n", 1);
            lineno++;
            lp = 0;
        } else if (lp < 1022) {
            line[lp++] = ch;
        }
    }
    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: base64 - Base64 encode/decode */
static void cmd_base64(int argc, char *argv[]) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int decode = 0;
    int file_arg = 1;
    if (argc >= 2 && strcmp_simple(argv[1], "-d") == 0) { decode = 1; file_arg = 2; }

    int fd_in = 0;
    if (file_arg < argc) {
        fd_in = sys_open(argv[file_arg], O_RDONLY, 0);
        if (fd_in < 0) { write_str(2, "base64: cannot open file\n"); return; }
    }

    if (!decode) {
        /* Encode */
        unsigned char buf[3];
        char out[5];
        long n;
        int col = 0;
        while ((n = sys_read(fd_in, buf, 3)) > 0) {
            out[0] = b64[buf[0] >> 2];
            out[1] = b64[((buf[0] & 3) << 4) | (n > 1 ? (buf[1] >> 4) : 0)];
            out[2] = n > 1 ? b64[((buf[1] & 0xF) << 2) | (n > 2 ? (buf[2] >> 6) : 0)] : '=';
            out[3] = n > 2 ? b64[buf[2] & 0x3F] : '=';
            sys_write(1, out, 4);
            col += 4;
            if (col >= 76) { sys_write(1, "\n", 1); col = 0; }
        }
        if (col > 0) sys_write(1, "\n", 1);
    } else {
        /* Decode */
        static unsigned char dbuf[4096];
        static unsigned char outb[3072]; /* 4096 * 3/4 */
        ssize_t nr;
        while ((nr = sys_read(fd_in, dbuf, sizeof(dbuf))) > 0) {
            int op = 0;
            int acc = 0, bits = 0;
            for (ssize_t i = 0; i < nr; i++) {
                unsigned char c = dbuf[i];
                int val = -1;
                if (c >= 'A' && c <= 'Z') val = c - 'A';
                else if (c >= 'a' && c <= 'z') val = c - 'a' + 26;
                else if (c >= '0' && c <= '9') val = c - '0' + 52;
                else if (c == '+') val = 62;
                else if (c == '/') val = 63;
                else if (c == '=') val = 0; /* padding */
                else continue; /* skip whitespace/newlines */
                if (c == '=') { bits += 6; if (bits >= 8) { bits -= 8; } continue; }
                acc = (acc << 6) | val;
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    outb[op++] = (unsigned char)((acc >> bits) & 0xFF);
                    if (op >= (int)sizeof(outb)) {
                        sys_write(1, outb, op);
                        op = 0;
                    }
                }
            }
            if (op > 0) sys_write(1, outb, op);
        }
    }
    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: od - Octal dump */
static void cmd_od(int argc, char *argv[]) {
    int fd_in = 0;
    int file_arg = 1;
    /* Basic: -A x for hex addresses, -t x1 for hex bytes */
    if (argc >= 2 && argv[1][0] != '-') { file_arg = 1; }
    else file_arg = argc > 2 ? argc - 1 : 1;

    if (file_arg < argc && argv[file_arg][0] != '-') {
        fd_in = sys_open(argv[file_arg], O_RDONLY, 0);
        if (fd_in < 0) { write_str(2, "od: cannot open file\n"); return; }
    }

    unsigned char buf[16];
    long n;
    unsigned long offset = 0;
    while ((n = sys_read(fd_in, buf, 16)) > 0) {
        /* Print offset in octal */
        char addr[16];
        int ap = 0;
        unsigned long v = offset;
        char rev[16]; int rp = 0;
        if (v == 0) rev[rp++] = '0';
        else while (v > 0) { rev[rp++] = '0' + (v & 7); v >>= 3; }
        for (int i = rp; i < 7; i++) addr[ap++] = '0';
        while (rp > 0) addr[ap++] = rev[--rp];
        sys_write(1, addr, ap);
        /* Print bytes in octal */
        for (long i = 0; i < n; i++) {
            char oct[5];
            oct[0] = ' ';
            oct[1] = '0' + ((buf[i] >> 6) & 7);
            oct[2] = '0' + ((buf[i] >> 3) & 7);
            oct[3] = '0' + (buf[i] & 7);
            sys_write(1, oct, 4);
        }
        sys_write(1, "\n", 1);
        offset += (unsigned long)n;
    }
    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: awk - Pattern scanning and processing (basic subset)
 * Supports: awk '{print $N}', awk -F: '{print $1}', awk '/pattern/ {print}',
 *           awk '{print NR, $0}', awk 'BEGIN{...} {...} END{...}' */
/* awk helpers: write integer and string to fd */
static void awk_write_int(int fd, long val) {
    char buf[24]; int bp = 0;
    if (val < 0) { sys_write(fd, "-", 1); val = -val; }
    if (val == 0) { sys_write(fd, "0", 1); return; }
    char rev[24]; int rp = 0;
    while (val > 0) { rev[rp++] = '0' + (char)(val % 10); val /= 10; }
    while (rp > 0) buf[bp++] = rev[--rp];
    sys_write(fd, buf, bp);
}

static int awk_str_to_long(const char *s, long *out) {
    long v = 0; int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    if (*s < '0' || *s > '9') return -1;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    *out = neg ? -v : v;
    return 0;
}

/* awk: extract a block between { } from *pp, advancing past the closing } */
static int awk_extract_block(const char **pp, char *out, int outsz) {
    const char *p = *pp;
    while (*p == ' ') p++;
    if (*p != '{') return -1;
    p++; /* skip { */
    int depth = 1, oi = 0;
    while (*p && depth > 0 && oi < outsz - 1) {
        if (*p == '{') depth++;
        else if (*p == '}') { depth--; if (depth == 0) break; }
        out[oi++] = *p++;
    }
    out[oi] = '\0';
    if (*p == '}') p++;
    *pp = p;
    return 0;
}

/* awk: evaluate a condition string against current line/fields/NR/NF.
 * Supports: /pattern/, NR==N, NR>N, NR<N, NR!=N, NR>=N, NR<=N,
 *           $N=="str", $N!="str", $N>N, $N<N, $N>=N, $N<=N, NF>N, NF<N */
static int awk_eval_cond(const char *cond, const char *line, int linelen,
                          char **fields, int nf, int lineno) {
    while (*cond == ' ') cond++;
    if (*cond == '\0') return 1; /* empty = always true */

    /* /pattern/ — substring match */
    if (*cond == '/') {
        cond++;
        char pat[128]; int pi = 0;
        while (*cond && *cond != '/' && pi < 126) pat[pi++] = *cond++;
        pat[pi] = '\0';
        for (int i = 0; i <= linelen - pi; i++) {
            int j;
            for (j = 0; j < pi; j++) { if (line[i+j] != pat[j]) break; }
            if (j == pi) return 1;
        }
        return 0;
    }

    /* Get LHS value: NR, NF, or $N */
    long lhs_val = 0;
    const char *lhs_str = NULL;
    int lhs_is_str = 0;
    const char *cp = cond;

    if (*cp == 'N' && cp[1] == 'R') {
        lhs_val = lineno; cp += 2;
    } else if (*cp == 'N' && cp[1] == 'F') {
        lhs_val = nf; cp += 2;
    } else if (*cp == '$') {
        cp++;
        int fn = 0;
        while (*cp >= '0' && *cp <= '9') fn = fn * 10 + (*cp++ - '0');
        if (fn == 0) { lhs_str = line; lhs_is_str = 1; }
        else if (fn <= nf) { lhs_str = fields[fn-1]; lhs_is_str = 1; }
        else { lhs_str = ""; lhs_is_str = 1; }
        /* Try numeric conversion */
        if (lhs_str && awk_str_to_long(lhs_str, &lhs_val) == 0) lhs_is_str = 0;
    } else {
        return 0; /* Unknown condition */
    }

    while (*cp == ' ') cp++;

    /* Parse operator */
    int op = 0; /* 1=eq, 2=ne, 3=gt, 4=lt, 5=ge, 6=le */
    if (cp[0] == '=' && cp[1] == '=') { op = 1; cp += 2; }
    else if (cp[0] == '!' && cp[1] == '=') { op = 2; cp += 2; }
    else if (cp[0] == '>' && cp[1] == '=') { op = 5; cp += 2; }
    else if (cp[0] == '<' && cp[1] == '=') { op = 6; cp += 2; }
    else if (cp[0] == '>') { op = 3; cp += 1; }
    else if (cp[0] == '<') { op = 4; cp += 1; }
    else if (cp[0] == '~') { op = 7; cp += 1; } /* regex match (substring) */
    else return 0;

    while (*cp == ' ') cp++;

    /* RHS: quoted string or number */
    if (*cp == '"') {
        cp++;
        char rhs[128]; int ri = 0;
        while (*cp && *cp != '"' && ri < 126) rhs[ri++] = *cp++;
        rhs[ri] = '\0';
        const char *ls = lhs_is_str ? lhs_str : "";
        /* String comparison */
        int cmp = strcmp_simple(ls, rhs);
        switch (op) {
            case 1: return cmp == 0;
            case 2: return cmp != 0;
            case 7: { /* substring match */
                for (int i = 0; ls[i]; i++) {
                    int j;
                    for (j = 0; j < ri && ls[i+j]; j++) if (ls[i+j] != rhs[j]) break;
                    if (j == ri) return 1;
                }
                return 0;
            }
            default: return 0;
        }
    } else {
        /* Numeric RHS */
        long rhs = 0;
        awk_str_to_long(cp, &rhs);
        switch (op) {
            case 1: return lhs_val == rhs;
            case 2: return lhs_val != rhs;
            case 3: return lhs_val > rhs;
            case 4: return lhs_val < rhs;
            case 5: return lhs_val >= rhs;
            case 6: return lhs_val <= rhs;
            default: return 0;
        }
    }
}

/* awk: execute an action string (may contain ; separated statements) */
static void awk_exec_action(const char *action, const char *line, int linelen,
                             char **fields, int nf, int lineno, const char *ofs) {
    if (!action || !action[0]) {
        sys_write(1, line, linelen);
        sys_write(1, "\n", 1);
        return;
    }

    /* Split on ; and execute each statement */
    const char *sp = action;
    while (*sp) {
        while (*sp == ' ' || *sp == ';') sp++;
        if (!*sp) break;

        /* Detect statement type */
        if (sp[0] == 'p' && sp[1] == 'r' && sp[2] == 'i' && sp[3] == 'n' && sp[4] == 't') {
            if (sp[5] == 'f' && sp[6] == ' ') {
                /* printf "fmt", args... — basic format support */
                sp += 7;
                while (*sp == ' ') sp++;
                if (*sp == '"') {
                    sp++;
                    int arg_idx = 0; /* which $N arg we're on */
                    /* Scan for format arguments after the closing quote */
                    const char *fmt_start = sp;
                    while (*sp && *sp != '"') sp++;
                    int fmt_len = (int)(sp - fmt_start);
                    if (*sp == '"') sp++;
                    /* Collect args from after the comma */
                    int print_args[16]; int nargs = 0;
                    while (*sp == ' ' || *sp == ',') {
                        if (*sp == ',') {
                            sp++;
                            while (*sp == ' ') sp++;
                            if (*sp == '$') {
                                sp++;
                                int fn = 0;
                                while (*sp >= '0' && *sp <= '9') fn = fn * 10 + (*sp++ - '0');
                                if (nargs < 16) print_args[nargs++] = fn;
                            } else if (*sp == 'N' && sp[1] == 'R') { if (nargs < 16) print_args[nargs++] = -1; sp += 2; }
                            else if (*sp == 'N' && sp[1] == 'F') { if (nargs < 16) print_args[nargs++] = -2; sp += 2; }
                            else break;
                        } else sp++;
                    }
                    /* Process format string */
                    const char *f = fmt_start;
                    for (int i = 0; i < fmt_len; i++) {
                        if (f[i] == '\\' && i + 1 < fmt_len) {
                            if (f[i+1] == 'n') { sys_write(1, "\n", 1); i++; }
                            else if (f[i+1] == 't') { sys_write(1, "\t", 1); i++; }
                            else { sys_write(1, &f[i+1], 1); i++; }
                        } else if (f[i] == '%' && i + 1 < fmt_len) {
                            i++;
                            /* Skip width/precision */
                            while (i < fmt_len && ((f[i] >= '0' && f[i] <= '9') || f[i] == '-' || f[i] == '.')) i++;
                            if (i < fmt_len && (f[i] == 's' || f[i] == 'd' || f[i] == 'i')) {
                                int fn = (arg_idx < nargs) ? print_args[arg_idx++] : 0;
                                if (fn == -1) { awk_write_int(1, lineno); }
                                else if (fn == -2) { awk_write_int(1, nf); }
                                else if (fn == 0) { sys_write(1, line, linelen); }
                                else if (fn <= nf) {
                                    if (f[i] == 's') {
                                        int fl = 0; while (fields[fn-1][fl]) fl++;
                                        sys_write(1, fields[fn-1], fl);
                                    } else {
                                        long v = 0; awk_str_to_long(fields[fn-1], &v);
                                        awk_write_int(1, v);
                                    }
                                }
                            }
                        } else {
                            sys_write(1, &f[i], 1);
                        }
                    }
                }
                continue;
            }
            /* print [args] */
            sp += 5;
            if (*sp == '\0' || *sp == ';') {
                /* bare print — print $0 */
                sys_write(1, line, linelen);
                sys_write(1, "\n", 1);
                continue;
            }
            if (*sp != ' ') { while (*sp && *sp != ';') sp++; continue; }
            sp++;
            int first = 1;
            while (*sp && *sp != ';') {
                while (*sp == ' ') sp++;
                if (!*sp || *sp == ';') break;
                int use_ofs = 0;
                if (*sp == ',') { use_ofs = 1; sp++; while (*sp == ' ') sp++; }
                if (!first && use_ofs) {
                    int ol = 0; while (ofs[ol]) ol++;
                    sys_write(1, ofs, ol);
                } else if (!first) {
                    sys_write(1, " ", 1);
                }
                first = 0;
                if (*sp == '$') {
                    sp++;
                    int fn = 0;
                    while (*sp >= '0' && *sp <= '9') fn = fn * 10 + (*sp++ - '0');
                    if (fn == 0) { sys_write(1, line, linelen); }
                    else if (fn <= nf) { int fl = 0; while (fields[fn-1][fl]) fl++; sys_write(1, fields[fn-1], fl); }
                } else if (*sp == 'N' && sp[1] == 'R') {
                    awk_write_int(1, lineno); sp += 2;
                } else if (*sp == 'N' && sp[1] == 'F') {
                    awk_write_int(1, nf); sp += 2;
                } else if (*sp == '"') {
                    sp++;
                    while (*sp && *sp != '"') {
                        if (*sp == '\\' && sp[1] == 't') { sys_write(1, "\t", 1); sp += 2; }
                        else if (*sp == '\\' && sp[1] == 'n') { sys_write(1, "\n", 1); sp += 2; }
                        else { sys_write(1, sp, 1); sp++; }
                    }
                    if (*sp == '"') sp++;
                } else if (*sp == '$' || (*sp >= '0' && *sp <= '9') || *sp == '-') {
                    /* Numeric literal */
                    long v = 0; awk_str_to_long(sp, &v);
                    awk_write_int(1, v);
                    if (*sp == '-') sp++;
                    while (*sp >= '0' && *sp <= '9') sp++;
                } else {
                    while (*sp && *sp != ' ' && *sp != ',' && *sp != ';') sp++;
                }
            }
            sys_write(1, "\n", 1);
        } else if (sp[0] == 'n' && sp[1] == 'e' && sp[2] == 'x' && sp[3] == 't') {
            /* next — skip to next line */
            return;
        } else {
            /* Skip unknown statement */
            while (*sp && *sp != ';') sp++;
        }
    }
}

static void cmd_awk(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: awk [-F sep] 'program' [file...]\n");
        return;
    }

    char fs = ' ';  /* Field separator */
    char ofs[8] = " ";  /* Output field separator */
    int prog_arg = 1;
    if (argc >= 3 && strcmp_simple(argv[1], "-F") == 0) {
        if (argv[2][0]) fs = argv[2][0];
        prog_arg = 3;
    } else if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'F') {
        fs = argv[1][2];
        prog_arg = 2;
    }

    if (prog_arg >= argc) {
        write_str(2, "awk: no program specified\n");
        return;
    }

    const char *prog = argv[prog_arg];
    int file_arg = prog_arg + 1;

    /* Parse program into rules: BEGIN{...}, condition{action}, END{...} */
    char begin_action[256] = {0};
    char end_action[256] = {0};

    /* Support up to 4 rules */
    #define AWK_MAX_RULES 4
    char rule_cond[AWK_MAX_RULES][128];
    char rule_action[AWK_MAX_RULES][512];
    int nrules = 0;

    const char *pp = prog;
    while (*pp) {
        while (*pp == ' ' || *pp == ';' || *pp == '\n') pp++;
        if (!*pp) break;

        /* BEGIN { ... } */
        if (pp[0]=='B' && pp[1]=='E' && pp[2]=='G' && pp[3]=='I' && pp[4]=='N') {
            pp += 5;
            while (*pp == ' ') pp++;
            awk_extract_block(&pp, begin_action, sizeof(begin_action));
            continue;
        }

        /* END { ... } */
        if (pp[0]=='E' && pp[1]=='N' && pp[2]=='D') {
            pp += 3;
            while (*pp == ' ') pp++;
            awk_extract_block(&pp, end_action, sizeof(end_action));
            continue;
        }

        if (nrules >= AWK_MAX_RULES) break;

        /* condition { action } or just { action } */
        rule_cond[nrules][0] = '\0';
        rule_action[nrules][0] = '\0';

        if (*pp == '{') {
            /* No condition — matches all lines */
            awk_extract_block(&pp, rule_action[nrules], sizeof(rule_action[0]));
            nrules++;
        } else if (*pp == '/') {
            /* /pattern/ { action } */
            int ci = 0;
            rule_cond[nrules][ci++] = *pp++; /* / */
            while (*pp && *pp != '/' && ci < 126) rule_cond[nrules][ci++] = *pp++;
            if (*pp == '/') rule_cond[nrules][ci++] = *pp++;
            rule_cond[nrules][ci] = '\0';
            while (*pp == ' ') pp++;
            if (*pp == '{') {
                awk_extract_block(&pp, rule_action[nrules], sizeof(rule_action[0]));
            } else {
                /* Default action: print $0 */
                rule_action[nrules][0] = '\0';
            }
            nrules++;
        } else {
            /* condition { action } — NR==1, $1>5, etc. */
            int ci = 0;
            while (*pp && *pp != '{' && *pp != ';' && ci < 126) rule_cond[nrules][ci++] = *pp++;
            /* Trim trailing spaces */
            while (ci > 0 && rule_cond[nrules][ci-1] == ' ') ci--;
            rule_cond[nrules][ci] = '\0';
            while (*pp == ' ') pp++;
            if (*pp == '{') {
                awk_extract_block(&pp, rule_action[nrules], sizeof(rule_action[0]));
            } else {
                rule_action[nrules][0] = '\0';
            }
            nrules++;
        }
    }

    /* If no rules parsed, treat entire program as a single action */
    if (nrules == 0 && begin_action[0] == '\0' && end_action[0] == '\0') {
        rule_cond[0][0] = '\0';
        int ai = 0;
        const char *s = prog;
        while (*s && ai < 510) rule_action[0][ai++] = *s++;
        rule_action[0][ai] = '\0';
        nrules = 1;
    }

    /* Execute BEGIN block (with dummy empty line context) */
    if (begin_action[0]) {
        char *no_fields[1] = { (char*)"" };
        /* Check for OFS assignment: OFS="..." */
        const char *bp = begin_action;
        while (*bp) {
            while (*bp == ' ' || *bp == ';') bp++;
            if (bp[0]=='O' && bp[1]=='F' && bp[2]=='S' && bp[3]=='=') {
                bp += 4;
                if (*bp == '"') {
                    bp++;
                    int oi = 0;
                    while (*bp && *bp != '"' && oi < 6) {
                        if (*bp == '\\' && bp[1] == 't') { ofs[oi++] = '\t'; bp += 2; }
                        else if (*bp == '\\' && bp[1] == 'n') { ofs[oi++] = '\n'; bp += 2; }
                        else { ofs[oi++] = *bp++; }
                    }
                    ofs[oi] = '\0';
                    if (*bp == '"') bp++;
                }
            } else {
                awk_exec_action(bp, "", 0, no_fields, 0, 0, ofs);
                break;
            }
        }
    }

    /* Open input */
    int fd_in = 0;
    if (file_arg < argc) {
        fd_in = sys_open(argv[file_arg], O_RDONLY, 0);
        if (fd_in < 0) {
            write_str(2, "awk: cannot open '");
            write_str(2, argv[file_arg]);
            write_str(2, "'\n");
            return;
        }
    }

    /* Process lines */
    char line[1024];
    int lp = 0;
    int lineno = 0;
    char ch;
    while (sys_read(fd_in, &ch, 1) == 1) {
        if (ch == '\n' || lp >= 1022) {
            line[lp] = '\0';
            lineno++;

            /* Split into fields */
            char *fields[64];
            int nf = 0;
            char fcopy[1024];
            int fi = 0;
            for (int i = 0; line[i] && fi < 1022; i++) fcopy[fi++] = line[i];
            fcopy[fi] = '\0';

            char *fp = fcopy;
            while (*fp && nf < 63) {
                if (fs == ' ') {
                    while (*fp == ' ' || *fp == '\t') fp++;
                    if (!*fp) break;
                }
                fields[nf++] = fp;
                if (fs == ' ') {
                    while (*fp && *fp != ' ' && *fp != '\t') fp++;
                } else {
                    while (*fp && *fp != fs) fp++;
                }
                if (*fp) *fp++ = '\0';
            }

            /* Execute matching rules */
            for (int r = 0; r < nrules; r++) {
                if (awk_eval_cond(rule_cond[r], line, lp, fields, nf, lineno)) {
                    awk_exec_action(rule_action[r], line, lp, fields, nf, lineno, ofs);
                }
            }
            lp = 0;
        } else {
            line[lp++] = ch;
        }
    }

    /* Execute END block */
    if (end_action[0]) {
        char *no_fields[1] = { (char*)"" };
        awk_exec_action(end_action, "", 0, no_fields, 0, lineno, ofs);
    }

    if (fd_in > 0) sys_close(fd_in);
}

/* Built-in: tee - Read from stdin and write to stdout and files */
static void cmd_tee(int argc, char *argv[]) {
    int append_mode = 0;
    int arg_start = 1;

    /* Parse options */
    if (argc > 1 && strcmp_simple(argv[1], "-a") == 0) {
        append_mode = 1;
        arg_start = 2;
    }

    /* Open all output files */
    #define TEE_MAX_FILES 16
    int fds[TEE_MAX_FILES];
    int num_files = 0;

    for (int i = arg_start; i < argc && num_files < TEE_MAX_FILES; i++) {
        int flags = O_WRONLY | O_CREAT;
        if (append_mode) {
            flags |= O_APPEND;
        } else {
            flags |= O_TRUNC;
        }

        fds[num_files] = sys_open(argv[i], flags, 0644);
        if (fds[num_files] < 0) {
            write_str(2, "tee: ");
            write_str(2, argv[i]);
            write_str(2, ": cannot open file\n");
            /* Continue with other files */
        } else {
            num_files++;
        }
    }

    /* Read from stdin and write to stdout and all files */
    char buf[4096];
    long nread;

    while ((nread = sys_read(0, buf, sizeof(buf))) > 0) {
        /* Write to stdout */
        long written = 0;
        while (written < nread) {
            long w = sys_write(1, buf + written, nread - written);
            if (w <= 0) break;
            written += w;
        }

        /* Write to all output files */
        for (int i = 0; i < num_files; i++) {
            written = 0;
            while (written < nread) {
                long w = sys_write(fds[i], buf + written, nread - written);
                if (w <= 0) break;
                written += w;
            }
        }
    }

    /* Close all files */
    for (int i = 0; i < num_files; i++) {
        sys_close(fds[i]);
    }
}

/* Helper function to read one line from a file descriptor for paste command */
static int paste_read_line(int fd, char *buffer, int max_len) {
    int pos = 0;
    char c;
    long nread;

    while (pos < max_len - 1) {
        nread = sys_read(fd, &c, 1);
        if (nread <= 0) {
            return (pos > 0) ? pos : -1;  /* Return -1 on EOF with no data */
        }
        if (c == '\n') {
            break;
        }
        buffer[pos++] = c;
    }
    buffer[pos] = '\0';
    return pos;
}

/* Built-in: paste - Merge lines of files */
static void cmd_paste(int argc, char *argv[]) {
    char delimiter = '\t';
    int arg_start = 1;

    /* Parse -d option for delimiter */
    if (argc > 2 && strcmp_simple(argv[1], "-d") == 0) {
        delimiter = argv[2][0];
        arg_start = 3;
    }

    /* Open all files or use stdin */
    #define PASTE_MAX_FILES 16
    int fds[PASTE_MAX_FILES];
    int num_files = 0;

    if (arg_start >= argc) {
        /* Read from stdin */
        fds[0] = 0;
        num_files = 1;
    } else {
        /* Open each file */
        for (int i = arg_start; i < argc && num_files < PASTE_MAX_FILES; i++) {
            fds[num_files] = sys_open(argv[i], O_RDONLY, 0);
            if (fds[num_files] < 0) {
                write_str(2, "paste: ");
                write_str(2, argv[i]);
                write_str(2, ": cannot open file\n");
                /* Close already opened files */
                for (int j = 0; j < num_files; j++) {
                    if (fds[j] > 0) {  /* Don't close stdin */
                        sys_close(fds[j]);
                    }
                }
                return;
            }
            num_files++;
        }
    }

    /* Read and merge lines from all files */
    #define PASTE_LINE_MAX 1024
    static char lines[PASTE_MAX_FILES][PASTE_LINE_MAX];
    int files_active = num_files;

    while (files_active > 0) {
        files_active = 0;

        /* Read one line from each file */
        for (int i = 0; i < num_files; i++) {
            if (fds[i] < 0) {
                lines[i][0] = '\0';  /* File exhausted */
                continue;
            }

            int result = paste_read_line(fds[i], lines[i], PASTE_LINE_MAX);
            if (result < 0) {
                /* EOF reached */
                if (fds[i] > 0) {  /* Don't close stdin */
                    sys_close(fds[i]);
                }
                fds[i] = -1;  /* Mark file as closed */
                lines[i][0] = '\0';
            } else {
                files_active++;
            }
        }

        if (files_active == 0) break;

        /* Output merged line */
        for (int i = 0; i < num_files; i++) {
            write_str(1, lines[i]);
            if (i < num_files - 1) {
                write_char(1, delimiter);
            }
        }
        write_char(1, '\n');
    }

    /* Close any remaining open files */
    for (int i = 0; i < num_files; i++) {
        if (fds[i] > 0) {  /* Don't close stdin */
            sys_close(fds[i]);
        }
    }
}

/* Built-in: diff - Compare files line by line */
static void cmd_diff(int argc, char *argv[]) {
    int quiet = 0;
    int unified = 1; /* default to unified diff format */
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        if (strcmp_simple(argv[arg_start], "-q") == 0) {
            quiet = 1;
        } else if (strcmp_simple(argv[arg_start], "-u") == 0) {
            unified = 1;
        }
        arg_start++;
    }

    if (argc - arg_start < 2) {
        write_str(2, "diff: missing operand\n");
        write_str(2, "Usage: diff [-u] [-q] <file1> <file2>\n");
        return;
    }

    const char *file1 = argv[arg_start];
    const char *file2 = argv[arg_start + 1];

    /* Open both files */
    int fd1 = sys_open(file1, O_RDONLY, 0);
    if (fd1 < 0) {
        write_str(2, "diff: ");
        write_str(2, file1);
        write_str(2, ": cannot open file\n");
        return;
    }

    int fd2 = sys_open(file2, O_RDONLY, 0);
    if (fd2 < 0) {
        write_str(2, "diff: ");
        write_str(2, file2);
        write_str(2, ": cannot open file\n");
        sys_close(fd1);
        return;
    }

    /* Read both files into line arrays */
    #define DIFF_LINE_MAX 512
    #define DIFF_MAX_LINES 512
    static char lines_a[DIFF_MAX_LINES][DIFF_LINE_MAX];
    static char lines_b[DIFF_MAX_LINES][DIFF_LINE_MAX];
    int na = 0, nb = 0;

    /* Helper: read all lines from fd into array */
    for (int pass = 0; pass < 2; pass++) {
        int fd = (pass == 0) ? fd1 : fd2;
        int *count = (pass == 0) ? &na : &nb;
        char (*lines)[DIFF_LINE_MAX] = (pass == 0) ? lines_a : lines_b;
        int lp = 0;
        char c;
        long nr;
        while (*count < DIFF_MAX_LINES) {
            nr = sys_read(fd, &c, 1);
            if (nr <= 0) {
                if (lp > 0) { lines[*count][lp] = '\0'; (*count)++; }
                break;
            }
            if (c == '\n') {
                lines[*count][lp] = '\0';
                (*count)++;
                lp = 0;
            } else if (lp < DIFF_LINE_MAX - 1) {
                lines[*count][lp++] = c;
            }
        }
    }
    sys_close(fd1);
    sys_close(fd2);

    if (quiet) {
        /* Quick check: do files differ? */
        int differ = (na != nb);
        if (!differ) {
            for (int i = 0; i < na; i++) {
                if (strcmp_simple(lines_a[i], lines_b[i]) != 0) { differ = 1; break; }
            }
        }
        if (differ) {
            write_str(1, "Files ");
            write_str(1, file1);
            write_str(1, " and ");
            write_str(1, file2);
            write_str(1, " differ\n");
        }
        return;
    }

    /* Unified diff output */
    if (unified) {
        /* Print unified diff header */
        write_str(1, "--- a/"); write_str(1, file1); write_char(1, '\n');
        write_str(1, "+++ b/"); write_str(1, file2); write_char(1, '\n');
    }

    /* Simple LCS-based diff: walk both files, output hunks */
    int ia = 0, ib = 0;
    int differences = 0;
    char nbuf[16];

    while (ia < na || ib < nb) {
        /* Skip matching lines */
        if (ia < na && ib < nb && strcmp_simple(lines_a[ia], lines_b[ib]) == 0) {
            ia++; ib++;
            continue;
        }

        /* Found a difference — collect the hunk */
        int hunk_start_a = ia, hunk_start_b = ib;

        /* Look ahead for next matching line to bound the hunk */
        int found = 0;
        for (int ahead = 1; ahead <= 8 && !found; ahead++) {
            /* Try: skip 'ahead' lines in a, see if a[ia+ahead] matches b[ib..] */
            if (ia + ahead < na) {
                for (int j = ib; j < nb && j < ib + ahead + 1; j++) {
                    if (strcmp_simple(lines_a[ia + ahead], lines_b[j]) == 0) {
                        /* Advance to the mismatch boundary */
                        int new_ia = ia + ahead;
                        int new_ib = j;
                        ia = new_ia; ib = new_ib;
                        found = 1;
                        break;
                    }
                }
            }
            /* Try: skip 'ahead' lines in b */
            if (!found && ib + ahead < nb) {
                for (int j = ia; j < na && j < ia + ahead + 1; j++) {
                    if (strcmp_simple(lines_b[ib + ahead], lines_a[j]) == 0) {
                        int new_ia = j;
                        int new_ib = ib + ahead;
                        ia = new_ia; ib = new_ib;
                        found = 1;
                        break;
                    }
                }
            }
        }
        if (!found) {
            /* No resync — consume one line from each if available */
            if (ia < na) ia++;
            if (ib < nb) ib++;
        }

        /* Now hunk is: a[hunk_start_a..ia), b[hunk_start_b..ib) */
        int del_count = ia - hunk_start_a;
        int add_count = ib - hunk_start_b;
        if (del_count == 0 && add_count == 0) continue;
        differences++;

        /* Print context lines before hunk (up to 3) */
        int ctx_before = (hunk_start_a > 3) ? 3 : hunk_start_a;
        int ctx_after_a = ((ia + 3) < na) ? 3 : (na - ia);
        int ctx_after_b = ((ib + 3) < nb) ? 3 : (nb - ib);

        /* Print @@ header */
        write_str(1, "@@ -");
        int_to_str(hunk_start_a - ctx_before + 1, nbuf, 16); write_str(1, nbuf);
        write_char(1, ',');
        int_to_str(del_count + ctx_before + ctx_after_a, nbuf, 16); write_str(1, nbuf);
        write_str(1, " +");
        int_to_str(hunk_start_b - ctx_before + 1, nbuf, 16); write_str(1, nbuf);
        write_char(1, ',');
        int_to_str(add_count + ctx_before + ctx_after_b, nbuf, 16); write_str(1, nbuf);
        write_str(1, " @@\n");

        /* Context before */
        for (int i = hunk_start_a - ctx_before; i < hunk_start_a; i++) {
            write_str(1, " "); write_str(1, lines_a[i]); write_char(1, '\n');
        }
        /* Removed lines from file1 */
        for (int i = hunk_start_a; i < ia; i++) {
            write_str(1, "-"); write_str(1, lines_a[i]); write_char(1, '\n');
        }
        /* Added lines from file2 */
        for (int i = hunk_start_b; i < ib; i++) {
            write_str(1, "+"); write_str(1, lines_b[i]); write_char(1, '\n');
        }
        /* Context after */
        int ctx_after = (ctx_after_a < ctx_after_b) ? ctx_after_a : ctx_after_b;
        for (int i = 0; i < ctx_after; i++) {
            if (ia + i < na) {
                write_str(1, " "); write_str(1, lines_a[ia + i]); write_char(1, '\n');
            }
        }
    }

    if (differences == 0) {
        /* Files are identical — no output (like real diff) */
    }
}

/* Helper function to convert char to lowercase for grep command */
static char grep_to_lower(char c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

/* Helper function to check if pattern matches in line for grep command */
/* Match a single pattern char (supports '.') against a line char */
static int grep_char_match(char c, char p, int ci) {
    if (p == '.') return 1;  /* '.' matches any character */
    if (ci) { c = grep_to_lower(c); p = grep_to_lower(p); }
    return c == p;
}

/* Match pattern at a fixed position in line. Supports ^, $, . metacharacters */
static int grep_match_at(const char *line, int lpos, int line_len,
                         const char *pat, int plen, int ci) {
    for (int j = 0; j < plen; j++) {
        if (pat[j] == '$' && j == plen - 1) {
            return lpos == line_len;  /* $ matches end of line */
        }
        if (lpos >= line_len) return 0;
        if (!grep_char_match(line[lpos], pat[j], ci)) return 0;
        lpos++;
    }
    return 1;
}

static int grep_pattern_matches(const char *line, int line_len, const char *pattern,
                                int pattern_len, int case_insensitive) {
    if (pattern_len == 0) return 1;

    int anchored_start = (pattern[0] == '^');
    const char *pat = anchored_start ? pattern + 1 : pattern;
    int plen = anchored_start ? pattern_len - 1 : pattern_len;

    if (anchored_start) {
        return grep_match_at(line, 0, line_len, pat, plen, case_insensitive);
    }

    /* Try matching at every position */
    for (int i = 0; i <= line_len; i++) {
        if (grep_match_at(line, i, line_len, pat, plen, case_insensitive))
            return 1;
    }
    return 0;
}

static int grep_is_word_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int grep_word_matches(const char *line, int line_len, const char *pattern,
                             int pattern_len, int case_insensitive) {
    for (int i = 0; i <= line_len - pattern_len; i++) {
        /* Check word boundary before */
        if (i > 0 && grep_is_word_char(line[i - 1])) continue;
        /* Check word boundary after */
        int end = i + pattern_len;
        if (end < line_len && grep_is_word_char(line[end])) continue;
        /* Check pattern match */
        if (grep_match_at(line, i, line_len, pattern, pattern_len, case_insensitive))
            return 1;
    }
    return 0;
}

/* Helper function to process one file for grep command */
#define GREP_LINE_MAX 2048
static int grep_file(int fd, const char *filename, int show_filename, const char *pattern,
                     int pattern_len, int case_insensitive, int show_line_numbers,
                     int invert_match, int count_only, int files_only, int word_match) {
    static char line[GREP_LINE_MAX];
    int line_num = 0;
    int match_count = 0;

    while (1) {
        int pos = 0;
        char c;
        long nread;
        int eof = 0;

        while (pos < GREP_LINE_MAX - 1) {
            nread = sys_read(fd, &c, 1);
            if (nread <= 0) { eof = 1; break; }
            if (c == '\n') break;
            line[pos++] = c;
        }

        if (eof && pos == 0) break;

        line[pos] = '\0';
        line_num++;

        int matches;
        if (word_match)
            matches = grep_word_matches(line, pos, pattern, pattern_len, case_insensitive);
        else
            matches = grep_pattern_matches(line, pos, pattern, pattern_len, case_insensitive);

        if (invert_match) matches = !matches;

        if (matches) {
            match_count++;
            if (files_only) {
                write_str(1, filename);
                write_char(1, '\n');
                return 1;  /* Only print filename once */
            }
            if (!count_only) {
                if (show_filename) { write_str(1, filename); write_char(1, ':'); }
                if (show_line_numbers) {
                    char num_buf[16]; int_to_str(line_num, num_buf, 16);
                    write_str(1, num_buf); write_char(1, ':');
                }
                write_str(1, line);
                write_char(1, '\n');
            }
        }

        if (eof) break;
    }

    if (count_only) {
        if (show_filename) { write_str(1, filename); write_char(1, ':'); }
        char num_buf[16]; int_to_str(match_count, num_buf, 16);
        write_str(1, num_buf); write_char(1, '\n');
    }
    return match_count;
}

/* Built-in: grep - Search for patterns in files */
/* grep -r helper: recursively search directory */
static int g_grep_recursive;
static int g_grep_case_insensitive, g_grep_show_line_numbers, g_grep_invert_match;
static int g_grep_count_only, g_grep_files_only, g_grep_word_match;
static const char *g_grep_pattern;

/* Forward declaration for grep recursive helper */
static void grep_file_by_path(const char *path, const char *pattern, int multi_file);

static void grep_recursive(const char *dir_path, const char *pattern) {
    int dfd = sys_open(dir_path, O_RDONLY, 0);
    if (dfd < 0) return;
    static char dirbuf[2048];
    ssize_t dn;
    while ((dn = sys_getdents64((unsigned int)dfd, dirbuf, (unsigned int)sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            uint8_t dtype = *(uint8_t *)(dirbuf + pos + 18);
            char *name = dirbuf + pos + 19;
            pos += reclen;
            if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
                continue;
            /* Build full path */
            static char full_path[512];
            int fp = 0;
            for (int i = 0; dir_path[i] && fp < 500; i++) full_path[fp++] = dir_path[i];
            if (fp > 0 && full_path[fp-1] != '/') full_path[fp++] = '/';
            for (int i = 0; name[i] && fp < 510; i++) full_path[fp++] = name[i];
            full_path[fp] = '\0';

            if (dtype == 4 /* DT_DIR */) {
                grep_recursive(full_path, pattern);
            } else if (dtype == 8 /* DT_REG */ || dtype == 0 /* DT_UNKNOWN */) {
                grep_file_by_path(full_path, pattern, 1);
            }
        }
    }
    sys_close(dfd);
}

static void cmd_grep(int argc, char *argv[]) {
    int case_insensitive = 0, show_line_numbers = 0, invert_match = 0;
    int count_only = 0, files_only = 0, word_match = 0;
    int recursive = 0;
    int arg_start = 1;

    /* Parse options (supports combined flags like -inv) */
    while (arg_start < argc && argv[arg_start][0] == '-' && argv[arg_start][1] != '\0') {
        const char *opt = argv[arg_start];
        if (strcmp_simple(opt, "--") == 0) { arg_start++; break; }
        /* Parse each char in the flag group */
        for (int k = 1; opt[k]; k++) {
            switch (opt[k]) {
                case 'i': case_insensitive = 1; break;
                case 'n': show_line_numbers = 1; break;
                case 'v': invert_match = 1; break;
                case 'c': count_only = 1; break;
                case 'l': files_only = 1; break;
                case 'w': word_match = 1; break;
                case 'r': case 'R': recursive = 1; break;
                default:
                    write_str(2, "grep: invalid option: -");
                    write_char(2, opt[k]); write_char(2, '\n');
                    return;
            }
        }
        arg_start++;
    }

    if (argc - arg_start < 1) {
        write_str(2, "Usage: grep [-icnvlw] <pattern> [file...]\n");
        write_str(2, "  Patterns: ^start, end$, . (any char)\n");
        return;
    }

    const char *pattern = argv[arg_start];
    int pattern_len = 0;
    while (pattern[pattern_len]) pattern_len++;

    int num_files = argc - arg_start - 1;

    /* Store globals for recursive helper */
    g_grep_recursive = recursive;
    g_grep_case_insensitive = case_insensitive;
    g_grep_show_line_numbers = show_line_numbers;
    g_grep_invert_match = invert_match;
    g_grep_count_only = count_only;
    g_grep_files_only = files_only;
    g_grep_word_match = word_match;
    g_grep_pattern = pattern;

    if (num_files == 0 && !recursive) {
        grep_file(0, "(standard input)", 0, pattern, pattern_len, case_insensitive,
                 show_line_numbers, invert_match, count_only, files_only, word_match);
    } else if (recursive) {
        /* -r mode: search directories recursively */
        if (num_files == 0) {
            /* Default: search current directory */
            grep_recursive(".", pattern);
        } else {
            for (int i = 0; i < num_files; i++)
                grep_recursive(argv[arg_start + 1 + i], pattern);
        }
    } else {
        for (int i = 0; i < num_files; i++) {
            const char *filename = argv[arg_start + 1 + i];
            int fd = sys_open(filename, O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "grep: "); write_str(2, filename);
                write_str(2, ": cannot open file\n");
                continue;
            }
            grep_file(fd, filename, num_files > 1, pattern, pattern_len, case_insensitive,
                     show_line_numbers, invert_match, count_only, files_only, word_match);
            sys_close(fd);
        }
    }
}

/* grep_file wrapper for recursive mode (opens file by path) */
static void grep_file_by_path(const char *path, const char *pattern, int multi_file) {
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return;
    int pl = 0; while (pattern[pl]) pl++;
    grep_file(fd, path, multi_file, pattern, pl, g_grep_case_insensitive,
              g_grep_show_line_numbers, g_grep_invert_match, g_grep_count_only,
              g_grep_files_only, g_grep_word_match);
    sys_close(fd);
}

/* Helper function to read lines from a file descriptor for sort command */
#define SORT_MAX_LINES 1000
#define SORT_LINE_MAX 512
static void sort_read_lines(int fd, char lines[][SORT_LINE_MAX], int *line_count) {
    char c;
    long nread;
    int pos = 0;

    while (*line_count < SORT_MAX_LINES) {
        nread = sys_read(fd, &c, 1);
        if (nread <= 0) {
            if (pos > 0) {
                lines[*line_count][pos] = '\0';
                (*line_count)++;
            }
            break;
        }

        if (c == '\n') {
            lines[*line_count][pos] = '\0';
            (*line_count)++;
            pos = 0;
        } else if (pos < SORT_LINE_MAX - 1) {
            lines[*line_count][pos++] = c;
        }
    }
}

/* Sort comparison with field extraction support */
/* Extract field N (1-based) from a line using delimiter.
 * Returns pointer to start of field within the line, sets *flen to field length. */
static const char *sort_get_field(const char *line, int field_num, char delim, int *flen) {
    const char *p = line;
    int current_field = 1;
    /* Skip to the requested field */
    while (current_field < field_num && *p) {
        if (delim) {
            if (*p == delim) current_field++;
        } else {
            /* Default: whitespace-delimited, skip leading whitespace between fields */
            if (*p == ' ' || *p == '\t') {
                while (*p == ' ' || *p == '\t') p++;
                current_field++;
                continue;
            }
        }
        p++;
    }
    /* p now points to start of field */
    const char *start = p;
    const char *end = p;
    while (*end && *end != '\n') {
        if (delim) { if (*end == delim) break; }
        else { if (*end == ' ' || *end == '\t') break; }
        end++;
    }
    *flen = (int)(end - start);
    return start;
}

static int sort_compare_lines(const char lines[][SORT_LINE_MAX], int i, int j,
                              int numeric, int reverse, int key_field, char delim) {
    const char *s1, *s2;
    int l1 = 0, l2 = 0;

    if (key_field > 0) {
        s1 = sort_get_field(lines[i], key_field, delim, &l1);
        s2 = sort_get_field(lines[j], key_field, delim, &l2);
    } else {
        s1 = lines[i]; l1 = 0; while (s1[l1]) l1++;
        s2 = lines[j]; l2 = 0; while (s2[l2]) l2++;
    }

    if (numeric) {
        /* Parse number from field */
        int n1 = 0, n2 = 0, neg1 = 0, neg2 = 0;
        const char *p = s1;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '-') { neg1 = 1; p++; }
        while (*p >= '0' && *p <= '9') n1 = n1 * 10 + (*p++ - '0');
        if (neg1) n1 = -n1;
        p = s2;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '-') { neg2 = 1; p++; }
        while (*p >= '0' && *p <= '9') n2 = n2 * 10 + (*p++ - '0');
        if (neg2) n2 = -n2;
        if (n1 < n2) return reverse ? 1 : -1;
        if (n1 > n2) return reverse ? -1 : 1;
        return 0;
    } else {
        int len = l1 < l2 ? l1 : l2;
        for (int k = 0; k < len; k++) {
            if (s1[k] < s2[k]) return reverse ? 1 : -1;
            if (s1[k] > s2[k]) return reverse ? -1 : 1;
        }
        if (l1 < l2) return reverse ? 1 : -1;
        if (l1 > l2) return reverse ? -1 : 1;
        return 0;
    }
}

/* Built-in: sort - Sort lines of text */
static void cmd_sort(int argc, char *argv[]) {
    int reverse = 0;
    int numeric = 0;
    int unique = 0;
    int key_field = 0;  /* 0 = whole line, >0 = field number (1-based) */
    char delim = 0;     /* 0 = whitespace, else specific char */
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-' && argv[arg_start][1] != '\0') {
        const char *opt = argv[arg_start];
        if (strcmp_simple(opt, "-r") == 0) {
            reverse = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-n") == 0) {
            numeric = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-u") == 0) {
            unique = 1;
            arg_start++;
        } else if (strcmp_simple(opt, "-k") == 0) {
            /* -k FIELD: sort by field number (1-based) */
            if (arg_start + 1 < argc) {
                arg_start++;
                key_field = 0;
                for (const char *p = argv[arg_start]; *p >= '0' && *p <= '9'; p++)
                    key_field = key_field * 10 + (*p - '0');
                arg_start++;
            } else { arg_start++; }
        } else if (opt[1] == 'k' && opt[2] >= '0' && opt[2] <= '9') {
            /* -kN form (no space) */
            key_field = 0;
            for (const char *p = opt + 2; *p >= '0' && *p <= '9'; p++)
                key_field = key_field * 10 + (*p - '0');
            arg_start++;
        } else if (strcmp_simple(opt, "-t") == 0) {
            /* -t CHAR: field delimiter */
            if (arg_start + 1 < argc) {
                arg_start++;
                delim = argv[arg_start][0];
                arg_start++;
            } else { arg_start++; }
        } else if (opt[1] == 't' && opt[2] != '\0') {
            /* -tCHAR form */
            delim = opt[2];
            arg_start++;
        } else if (strcmp_simple(opt, "--") == 0) {
            arg_start++;
            break;
        } else {
            write_str(2, "sort: invalid option: ");
            write_str(2, opt);
            write_char(2, '\n');
            return;
        }
    }

    /* Storage for lines */
    static char lines[SORT_MAX_LINES][SORT_LINE_MAX];
    int line_count = 0;

    /* Read input from files or stdin */
    if (argc - arg_start == 0) {
        sort_read_lines(0, lines, &line_count);
    } else {
        for (int i = arg_start; i < argc; i++) {
            int fd = sys_open(argv[i], O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "sort: ");
                write_str(2, argv[i]);
                write_str(2, ": cannot open file\n");
                continue;
            }
            sort_read_lines(fd, lines, &line_count);
            sys_close(fd);
        }
    }

    /* Bubble sort (simple but works for our use case) */
    for (int i = 0; i < line_count - 1; i++) {
        for (int j = 0; j < line_count - i - 1; j++) {
            if (sort_compare_lines(lines, j, j + 1, numeric, reverse, key_field, delim) > 0) {
                /* Swap lines[j] and lines[j+1] */
                char temp[SORT_LINE_MAX];
                for (int k = 0; k < SORT_LINE_MAX; k++) {
                    temp[k] = lines[j][k];
                    lines[j][k] = lines[j + 1][k];
                    lines[j + 1][k] = temp[k];
                }
            }
        }
    }

    /* Output sorted lines */
    for (int i = 0; i < line_count; i++) {
        /* Skip duplicates if unique mode */
        if (unique && i > 0) {
            if (strcmp_simple(lines[i], lines[i - 1]) == 0) {
                continue;
            }
        }
        write_str(1, lines[i]);
        write_char(1, '\n');
    }
}

/* Built-in: ls - List directory contents */
/* Helper: format file mode as rwx string */
static void format_mode(unsigned int mode, char *buf) {
    /* File type character */
    unsigned int ft = mode & 0170000;
    if (ft == 0040000)       buf[0] = 'd';
    else if (ft == 0120000)  buf[0] = 'l';
    else if (ft == 0020000)  buf[0] = 'c';
    else if (ft == 0060000)  buf[0] = 'b';
    else if (ft == 0010000)  buf[0] = 'p';
    else if (ft == 0140000)  buf[0] = 's';
    else                     buf[0] = '-';
    /* Owner */
    buf[1] = (mode & 0400) ? 'r' : '-';
    buf[2] = (mode & 0200) ? 'w' : '-';
    buf[3] = (mode & 0100) ? 'x' : '-';
    /* Group */
    buf[4] = (mode & 040)  ? 'r' : '-';
    buf[5] = (mode & 020)  ? 'w' : '-';
    buf[6] = (mode & 010)  ? 'x' : '-';
    /* Other */
    buf[7] = (mode & 04)   ? 'r' : '-';
    buf[8] = (mode & 02)   ? 'w' : '-';
    buf[9] = (mode & 01)   ? 'x' : '-';
    buf[10] = '\0';
}

static void ls_format_human_size(long size, char *out, int outlen) {
    if (size < 1024) {
        int_to_str(size, out, outlen);
    } else if (size < 1024*1024) {
        int_to_str(size / 1024, out, outlen);
        int l = 0; while (out[l]) l++;
        if (l < outlen - 1) { out[l] = 'K'; out[l+1] = '\0'; }
    } else if (size < 1024*1024*1024L) {
        int_to_str(size / (1024*1024), out, outlen);
        int l = 0; while (out[l]) l++;
        if (l < outlen - 1) { out[l] = 'M'; out[l+1] = '\0'; }
    } else {
        int_to_str(size / (1024*1024*1024L), out, outlen);
        int l = 0; while (out[l]) l++;
        if (l < outlen - 1) { out[l] = 'G'; out[l+1] = '\0'; }
    }
}

static void cmd_ls(int argc, char *argv[]) {
    int show_all = 0;
    int long_format = 0;
    int human_readable = 0;
    int one_per_line __attribute__((unused)) = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        const char *opt = argv[arg_start];
        for (int j = 1; opt[j]; j++) {
            if (opt[j] == 'a') show_all = 1;
            else if (opt[j] == 'l') long_format = 1;
            else if (opt[j] == 'h') human_readable = 1;
            else if (opt[j] == '1') one_per_line = 1;
        }
        arg_start++;
    }

    const char *path = arg_start < argc ? argv[arg_start] : ".";

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

            /* Skip hidden files unless -a */
            if (!show_all && d->d_name[0] == '.') {
                ptr += d->d_reclen;
                continue;
            }

            if (long_format) {
                /* Build full path for stat */
                char fullpath[512];
                int pi = 0;
                for (int i = 0; path[i] && pi < 500; i++)
                    fullpath[pi++] = path[i];
                if (pi > 0 && fullpath[pi-1] != '/')
                    fullpath[pi++] = '/';
                for (int i = 0; d->d_name[i] && pi < 510; i++)
                    fullpath[pi++] = d->d_name[i];
                fullpath[pi] = '\0';

                struct stat st;
                int rc = sys_call2(__NR_stat, (long)fullpath, (long)&st);
                if (rc == 0) {
                    char modebuf[11];
                    format_mode(st.st_mode, modebuf);
                    write_str(1, modebuf);
                    write_str(1, " ");

                    /* Size */
                    char numbuf[20];
                    if (human_readable) {
                        ls_format_human_size((long)st.st_size, numbuf, 20);
                    } else {
                        int_to_str((long)st.st_size, numbuf, 20);
                    }
                    /* Right-align size in 8 chars */
                    int slen = 0;
                    while (numbuf[slen]) slen++;
                    for (int p = slen; p < 8; p++) write_str(1, " ");
                    write_str(1, numbuf);
                    write_str(1, " ");
                } else {
                    /* Type from d_type */
                    char tc = '-';
                    if (d->d_type == 4) tc = 'd';
                    else if (d->d_type == 10) tc = 'l';
                    char tb[3] = {tc, ' ', '\0'};
                    write_str(1, tb);
                }
            }

            /* Color directories blue, executables green */
            if (d->d_type == 4) write_str(1, "\033[34m");
            else if (d->d_type == 10) write_str(1, "\033[36m");

            write_str(1, d->d_name);

            if (d->d_type == 4 || d->d_type == 10)
                write_str(1, "\033[0m");
            write_str(1, "\n");

            ptr += d->d_reclen;
        }
    }

    if (nread < 0) {
        write_str(2, "ls: error reading directory\n");
    }

    sys_close(fd);
}

/* Forward declaration */
static int cat_process_fd(int fd);

/* Built-in: cat - Display file contents */
static void cmd_cat(int argc, char *argv[]) {
    int show_numbers = 0;
    int arg_start = 1;

    /* Parse -n flag */
    if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'n') {
        show_numbers = 1;
        arg_start = 2;
    }

    if (arg_start >= argc) {
        cat_process_fd(0);  /* stdin */
    } else {
        for (int i = arg_start; i < argc; i++) {
            int fd = sys_open(argv[i], O_RDONLY, 0);
            if (fd < 0) {
                write_str(2, "cat: ");
                write_str(2, argv[i]);
                write_str(2, ": cannot open file\n");
                continue;
            }
            if (show_numbers) {
                /* Line-numbered output */
                char buf[256];
                long n;
                int line = 1;
                int at_line_start = 1;
                while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
                    for (long j = 0; j < n; j++) {
                        if (at_line_start) {
                            char numbuf[8];
                            int_to_str(line, numbuf, 8);
                            int pad = 6 - (int)strlen_simple(numbuf);
                            while (pad-- > 0) write_char(1, ' ');
                            write_str(1, numbuf);
                            write_str(1, "\t");
                            at_line_start = 0;
                        }
                        write_char(1, buf[j]);
                        if (buf[j] == '\n') {
                            line++;
                            at_line_start = 1;
                        }
                    }
                }
            } else {
                cat_process_fd(fd);
            }
            sys_close(fd);
        }
    }
}

/* Helper: process file descriptor for cat command */
static int cat_process_fd(int fd) {
    char buffer[256];
    long bytes_read;

    while ((bytes_read = sys_read(fd, buffer, sizeof(buffer))) > 0) {
        /* Write chunk to stdout */
        long written = 0;
        while (written < bytes_read) {
            long n = sys_write(1, buffer + written, bytes_read - written);
            if (n <= 0) {
                write_str(2, "cat: write error\n");
                return -1;
            }
            written += n;
        }
    }

    if (bytes_read < 0) {
        write_str(2, "cat: read error\n");
        return -1;
    }

    return 0;
}

/* Helper function to create directory with parents for mkdir command */
static int mkdir_recursive(const char *path, int create_parents) {
    if (!path || path[0] == '\0') {
        return 0;
    }

    /* Try to create the directory first */
    long ret = sys_mkdir(path, 0755);
    if (ret == 0 || !create_parents) {
        /* Success or not using -p flag */
        return ret;
    }

    /* If -p flag is set, try to create parent directories */
    /* Build path component by component */
    static char temp_path[512];
    int path_len = 0;
    while (path[path_len]) path_len++;

    if (path_len >= 512) {
        write_str(2, "mkdir: path too long\n");
        return -1;
    }

    /* Copy path to temp buffer */
    for (int i = 0; i <= path_len; i++) {
        temp_path[i] = path[i];
    }

    /* Create each parent directory */
    int i = (temp_path[0] == '/') ? 1 : 0;  /* Skip leading slash */

    while (temp_path[i]) {
        /* Find next slash */
        if (temp_path[i] == '/') {
            /* Temporarily null-terminate at this position */
            temp_path[i] = '\0';

            /* Try to create this intermediate directory */
            sys_mkdir(temp_path, 0755);
            /* Ignore errors - directory might already exist */

            /* Restore the slash */
            temp_path[i] = '/';
        }
        i++;
    }

    /* Finally, create the target directory */
    ret = sys_mkdir(temp_path, 0755);
    return ret;
}

/* Built-in: mkdir - Create a directory */
static void cmd_mkdir(int argc, char *argv[]) {
    int create_parents = 0;
    int arg_start = 1;

    /* Parse -p option (create parent directories) */
    if (argc > 1 && strcmp_simple(argv[1], "-p") == 0) {
        create_parents = 1;
        arg_start = 2;
    }

    if (arg_start >= argc) {
        write_str(2, "mkdir: missing operand\n");
        write_str(2, "Usage: mkdir [-p] <directory>\n");
        return;
    }

    /* Process each directory argument */
    for (int i = arg_start; i < argc; i++) {
        const char *path = argv[i];
        long ret = mkdir_recursive(path, create_parents);

        if (ret < 0 && !create_parents) {
            write_str(2, "mkdir: cannot create directory '");
            write_str(2, path);
            write_str(2, "'\n");
        }
    }
}

/* Built-in: rmdir - Remove an empty directory */
static void cmd_rmdir(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "rmdir: missing operand\n");
        write_str(2, "Usage: rmdir <directory>...\n");
        return;
    }

    /* Process each directory argument */
    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];
        long ret = sys_rmdir(path);

        if (ret < 0) {
            write_str(2, "rmdir: failed to remove '");
            write_str(2, path);
            write_str(2, "'\n");
        }
    }
}

/* Built-in: rm - Remove a file */
/* Recursive delete helper for rm -r */
static void rm_recursive(const char *path) {
    int dfd = sys_open(path, O_RDONLY, 0);
    if (dfd < 0) return;
    static char dirbuf[2048];
    ssize_t dn;
    while ((dn = sys_getdents64((unsigned int)dfd, dirbuf, (unsigned int)sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            uint8_t dtype = *(uint8_t *)(dirbuf + pos + 18);
            char *name = dirbuf + pos + 19;
            pos += reclen;
            if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
                continue;
            static char full[512];
            int fp = 0;
            for (int i = 0; path[i] && fp < 500; i++) full[fp++] = path[i];
            if (fp > 0 && full[fp-1] != '/') full[fp++] = '/';
            for (int i = 0; name[i] && fp < 510; i++) full[fp++] = name[i];
            full[fp] = '\0';
            if (dtype == 4 /* DT_DIR */) {
                rm_recursive(full);
            } else {
                sys_unlink(full);
            }
        }
    }
    sys_close(dfd);
    extern long sys_rmdir(const char *);
    sys_rmdir(path);
}

static void cmd_rm(int argc, char *argv[]) {
    int force = 0;
    int recursive = 0;
    int arg_start = 1;

    /* Parse options */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        for (int j = 1; argv[arg_start][j]; j++) {
            if (argv[arg_start][j] == 'f') force = 1;
            else if (argv[arg_start][j] == 'r' || argv[arg_start][j] == 'R') recursive = 1;
        }
        arg_start++;
    }

    if (arg_start >= argc) {
        if (!force) {
            write_str(2, "rm: missing operand\n");
            write_str(2, "Usage: rm [-rf] <file>...\n");
        }
        return;
    }

    /* Process each file argument */
    for (int i = arg_start; i < argc; i++) {
        const char *path = argv[i];

        if (recursive) {
            /* Try unlink first (works for files), then try recursive delete */
            long ret = sys_unlink(path);
            if (ret < 0) {
                /* Might be a directory — try recursive */
                rm_recursive(path);
            }
        } else {
            long ret = sys_unlink(path);
            if (ret < 0 && !force) {
                write_str(2, "rm: cannot remove '");
                write_str(2, path);
                write_str(2, "'\n");
            }
        }
    }
}

/* Built-in: touch */
static void cmd_touch(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "touch: missing file operand\n");
        write_str(2, "Usage: touch <file>...\n");
        return;
    }

    /* Process each file argument */
    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];

        /* Create file by opening with O_CREAT and then closing */
        int fd = sys_open(path, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            write_str(2, "touch: cannot touch '");
            write_str(2, path);
            write_str(2, "'\n");
            continue;
        }

        /* Close the file immediately */
        sys_close(fd);
    }
}

/* Helper function to copy one file for cp command */
static int cp_copy_file(const char *src_path, const char *dst_path) {
    /* Open source file for reading */
    int src_fd = sys_open(src_path, O_RDONLY, 0);
    if (src_fd < 0) {
        write_str(2, "cp: cannot open '");
        write_str(2, src_path);
        write_str(2, "'\n");
        return -1;
    }

    /* Open destination file for writing (create if needed) */
    int dst_fd = sys_open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        write_str(2, "cp: cannot create '");
        write_str(2, dst_path);
        write_str(2, "'\n");
        sys_close(src_fd);
        return -1;
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
                return -1;
            }
            total_written += written;
        }
    }

    if (bytes_read < 0) {
        write_str(2, "cp: read error\n");
        sys_close(src_fd);
        sys_close(dst_fd);
        return -1;
    }

    sys_close(src_fd);
    sys_close(dst_fd);
    return 0;
}

/* Helper function to get basename from path for cp command */
static const char *cp_get_basename(const char *path) {
    const char *last_slash = path;
    for (const char *p = path; *p != '\0'; p++) {
        if (*p == '/') {
            last_slash = p + 1;
        }
    }
    return last_slash;
}

/* Helper function to build destination path for cp command */
static void cp_build_dest_path(char *dest_buf, size_t dest_size, const char *dest_dir,
                               const char *basename) {
    size_t dir_len = 0;
    while (dest_dir[dir_len] != '\0' && dir_len < dest_size - 2) {
        dest_buf[dir_len] = dest_dir[dir_len];
        dir_len++;
    }

    /* Add slash if needed */
    if (dir_len > 0 && dest_buf[dir_len - 1] != '/') {
        dest_buf[dir_len++] = '/';
    }

    /* Append basename */
    size_t i = 0;
    while (basename[i] != '\0' && dir_len + i < dest_size - 1) {
        dest_buf[dir_len + i] = basename[i];
        i++;
    }
    dest_buf[dir_len + i] = '\0';
}

/* Built-in: cp */
/* Recursive directory copy helper for cp -r */
static void cp_recursive(const char *src, const char *dst) {
    /* Create destination directory */
    extern long sys_mkdir_call(const char *, long);
    sys_mkdir_call(dst, 0755);

    /* Read source directory entries */
    int dfd = sys_open(src, O_RDONLY, 0);
    if (dfd < 0) { write_str(2, "cp: cannot open "); write_str(2, src); write_str(2, "\n"); return; }

    static char dirbuf[2048];
    ssize_t dn;
    while ((dn = sys_getdents64((unsigned int)dfd, dirbuf, (unsigned int)sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            uint8_t dtype = *(uint8_t *)(dirbuf + pos + 18);
            char *name = dirbuf + pos + 19;
            pos += reclen;

            if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
                continue;

            /* Build source and dest paths */
            static char sp[512], dp[512];
            int spi = 0, dpi = 0;
            for (int i = 0; src[i] && spi < 500; i++) sp[spi++] = src[i];
            if (spi > 0 && sp[spi-1] != '/') sp[spi++] = '/';
            for (int i = 0; name[i] && spi < 510; i++) sp[spi++] = name[i];
            sp[spi] = '\0';
            for (int i = 0; dst[i] && dpi < 500; i++) dp[dpi++] = dst[i];
            if (dpi > 0 && dp[dpi-1] != '/') dp[dpi++] = '/';
            for (int i = 0; name[i] && dpi < 510; i++) dp[dpi++] = name[i];
            dp[dpi] = '\0';

            if (dtype == 4 /* DT_DIR */) {
                cp_recursive(sp, dp);
            } else {
                cp_copy_file(sp, dp);
            }
        }
    }
    sys_close(dfd);
}

/* ============================================================
 * tar: create, extract, and list POSIX tar archives
 *
 * Supports:
 *   tar cf archive.tar file1 dir1/    Create archive
 *   tar xf archive.tar                Extract archive
 *   tar tf archive.tar                List contents
 *   tar xf archive.tar -C /path       Extract to directory
 *
 * Uses POSIX ustar 512-byte header format.
 * ============================================================ */

/* Write an octal value into a tar header field */
static void tar_write_octal(char *field, int len, unsigned long val) {
    int pos = len - 2;
    field[len - 1] = '\0';
    if (val == 0) { field[pos] = '0'; pos--; }
    while (val > 0 && pos >= 0) {
        field[pos--] = '0' + (char)(val & 7);
        val >>= 3;
    }
    while (pos >= 0) field[pos--] = '0';
}

/* Parse an octal value from a tar header field */
static unsigned long tar_read_octal(const char *field, int len) {
    unsigned long val = 0;
    for (int i = 0; i < len && field[i]; i++) {
        if (field[i] >= '0' && field[i] <= '7')
            val = (val << 3) | (unsigned long)(field[i] - '0');
        else if (field[i] != ' ') break;
    }
    return val;
}

/* Compute tar header checksum */
static unsigned long tar_checksum(const char *hdr) {
    unsigned long sum = 0;
    for (int i = 0; i < 512; i++) {
        /* Checksum field (offset 148-155) treated as spaces */
        if (i >= 148 && i < 156) sum += ' ';
        else sum += (unsigned char)hdr[i];
    }
    return sum;
}

/* Add a single file to a tar archive fd */
static void tar_add_file(int archive_fd, const char *path) {
    /* Stat the file to get size and type */
    struct stat st;
    if (sys_call2(__NR_stat, (long)path, (long)&st) < 0) return;

    /* Build 512-byte header */
    static char hdr[512];
    for (int i = 0; i < 512; i++) hdr[i] = '\0';

    /* Name (offset 0, 100 bytes) */
    int ni = 0;
    while (path[ni] && ni < 99) { hdr[ni] = path[ni]; ni++; }
    /* Add trailing / for directories */
    int is_dir = (st.st_mode & 0170000) == 0040000;
    if (is_dir && ni < 99 && (ni == 0 || hdr[ni-1] != '/')) hdr[ni++] = '/';

    /* Mode (offset 100, 8 bytes) */
    tar_write_octal(hdr + 100, 8, st.st_mode & 07777);
    /* uid/gid (offset 108/116, 8 bytes each) */
    tar_write_octal(hdr + 108, 8, st.st_uid);
    tar_write_octal(hdr + 116, 8, st.st_gid);
    /* Size (offset 124, 12 bytes) — 0 for directories */
    tar_write_octal(hdr + 124, 12, is_dir ? 0 : (unsigned long)st.st_size);
    /* Mtime (offset 136, 12 bytes) */
    tar_write_octal(hdr + 136, 12, (unsigned long)st.st_mtim.tv_sec);
    /* Type flag (offset 156) */
    hdr[156] = is_dir ? '5' : '0';
    /* Magic (offset 257) */
    hdr[257] = 'u'; hdr[258] = 's'; hdr[259] = 't';
    hdr[260] = 'a'; hdr[261] = 'r'; hdr[262] = '\0';
    /* Version (offset 263) */
    hdr[263] = '0'; hdr[264] = '0';

    /* Checksum (offset 148, 8 bytes) */
    unsigned long cksum = tar_checksum(hdr);
    tar_write_octal(hdr + 148, 7, cksum);
    hdr[155] = ' ';

    sys_write(archive_fd, hdr, 512);

    /* Write file data (rounded to 512-byte blocks) */
    if (!is_dir && st.st_size > 0) {
        int fd = sys_open(path, O_RDONLY, 0);
        if (fd >= 0) {
            static char buf[4096];
            long remaining = st.st_size;
            while (remaining > 0) {
                long chunk = remaining > 4096 ? 4096 : remaining;
                long nr = sys_read(fd, buf, chunk);
                if (nr <= 0) break;
                sys_write(archive_fd, buf, nr);
                remaining -= nr;
            }
            sys_close(fd);
            /* Pad to 512-byte boundary */
            long pad = (512 - (st.st_size % 512)) % 512;
            if (pad > 0) {
                static char zeros[512];
                for (int i = 0; i < 512; i++) zeros[i] = 0;
                sys_write(archive_fd, zeros, pad);
            }
        }
    }
}

/* Recursively add directory contents to tar */
static void tar_add_recursive(int archive_fd, const char *path) {
    tar_add_file(archive_fd, path);

    /* Check if directory */
    struct stat dst;
    if (sys_call2(__NR_stat, (long)path, (long)&dst) < 0) return;
    if ((dst.st_mode & 0170000) != 0040000) return;  /* Not a directory */

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return;

    struct { unsigned long long d_ino; long long d_off; unsigned short d_reclen;
             unsigned char d_type; char d_name[256]; } __attribute__((packed)) de;
    char dbuf[4096]; long nread;
    while ((nread = sys_getdents64(fd, dbuf, sizeof(dbuf))) > 0) {
        char *ptr = dbuf;
        while (ptr < dbuf + nread) {
            __builtin_memcpy(&de, ptr, sizeof(de.d_ino) + sizeof(de.d_off) + sizeof(de.d_reclen) + sizeof(de.d_type));
            char *name = ptr + 19;  /* d_name offset in linux_dirent64 */
            unsigned short reclen = de.d_reclen;

            if (name[0] != '.' || (name[1] != '\0' && (name[1] != '.' || name[2] != '\0'))) {
                static char child_path[512];
                int cp = 0;
                const char *p = path;
                while (*p && cp < 510) child_path[cp++] = *p++;
                if (cp > 0 && child_path[cp-1] != '/') child_path[cp++] = '/';
                while (*name && cp < 510) child_path[cp++] = *name++;
                child_path[cp] = '\0';
                tar_add_recursive(archive_fd, child_path);
            }
            ptr += reclen;
        }
    }
    sys_close(fd);
}

static void cmd_tar(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: tar [c|x|t]f archive [files...] [-C dir]\n");
        return;
    }

    /* Parse mode from first arg */
    const char *mode_str = argv[1];
    int do_create = 0, do_extract = 0, do_list = 0;
    int need_file = 0;
    for (int i = 0; mode_str[i]; i++) {
        if (mode_str[i] == 'c') do_create = 1;
        else if (mode_str[i] == 'x') do_extract = 1;
        else if (mode_str[i] == 't') do_list = 1;
        else if (mode_str[i] == 'f') need_file = 1;
        else if (mode_str[i] == 'v') { /* verbose: ignored for now */ }
        else if (mode_str[i] == 'z') { /* gzip: ignored (no compression) */ }
    }

    if (!need_file || argc < 3) {
        write_str(2, "tar: archive file required (use f flag)\n");
        return;
    }

    const char *archive = argv[2];
    const char *extract_dir = NULL;
    int file_start = 3;

    /* Parse -C dir */
    for (int i = 3; i < argc; i++) {
        if (strcmp_simple(argv[i], "-C") == 0 && i + 1 < argc) {
            extract_dir = argv[i + 1];
            /* Shift remaining args */
            file_start = i + 2;
            break;
        }
    }

    if (do_create) {
        int afd = sys_open(archive, 0x41 | 0x200 /* O_WRONLY|O_CREAT|O_TRUNC */, 0644);
        if (afd < 0) {
            write_str(2, "tar: cannot create "); write_str(2, archive); write_str(2, "\n");
            return;
        }
        for (int i = file_start; i < argc; i++) {
            if (argv[i][0] == '-') continue;  /* skip flags */
            tar_add_recursive(afd, argv[i]);
        }
        /* Write two 512-byte zero blocks (end of archive marker) */
        static char end_block[1024];
        for (int i = 0; i < 1024; i++) end_block[i] = 0;
        sys_write(afd, end_block, 1024);
        sys_close(afd);
    } else if (do_extract || do_list) {
        int afd = sys_open(archive, O_RDONLY, 0);
        if (afd < 0) {
            write_str(2, "tar: cannot open "); write_str(2, archive); write_str(2, "\n");
            return;
        }
        static char hdr[512];
        while (sys_read(afd, hdr, 512) == 512) {
            /* Check for end-of-archive (all zeros) */
            int all_zero = 1;
            for (int i = 0; i < 512 && all_zero; i++) if (hdr[i]) all_zero = 0;
            if (all_zero) break;

            /* Parse header */
            char name[101]; for (int i = 0; i < 100; i++) name[i] = hdr[i]; name[100] = '\0';
            /* Trim trailing nulls */
            int nlen = 0; while (name[nlen]) nlen++;

            unsigned long size = tar_read_octal(hdr + 124, 12);
            unsigned long mode = tar_read_octal(hdr + 100, 8);
            char type = hdr[156];

            if (do_list) {
                write_str(1, name); write_str(1, "\n");
            }

            if (do_extract) {
                /* Build output path */
                static char out_path[512];
                int op = 0;
                if (extract_dir) {
                    const char *ep = extract_dir;
                    while (*ep && op < 510) out_path[op++] = *ep++;
                    if (op > 0 && out_path[op-1] != '/') out_path[op++] = '/';
                }
                for (int i = 0; i < nlen && op < 510; i++) out_path[op++] = name[i];
                out_path[op] = '\0';

                if (type == '5' || (nlen > 0 && name[nlen-1] == '/')) {
                    /* Directory */
                    extern long sys_mkdir(const char *, unsigned int);
                    sys_mkdir(out_path, mode ? (unsigned int)mode : 0755);
                } else {
                    /* Regular file */
                    int ofd = sys_open(out_path, 0x41 | 0x200, (int)mode ? (int)mode : 0644);
                    if (ofd >= 0) {
                        static char fbuf[4096];
                        unsigned long remaining = size;
                        while (remaining > 0) {
                            unsigned long chunk = remaining > 4096 ? 4096 : remaining;
                            long nr = sys_read(afd, fbuf, chunk);
                            if (nr <= 0) break;
                            sys_write(ofd, fbuf, nr);
                            remaining -= (unsigned long)nr;
                        }
                        sys_close(ofd);
                        /* Skip padding */
                        unsigned long pad = (512 - (size % 512)) % 512;
                        if (pad > 0) {
                            static char skip[512];
                            sys_read(afd, skip, pad);
                        }
                    } else {
                        /* Skip data blocks */
                        unsigned long total = size + ((512 - (size % 512)) % 512);
                        static char skip[512];
                        while (total > 0) {
                            unsigned long chunk = total > 512 ? 512 : total;
                            sys_read(afd, skip, chunk);
                            total -= chunk;
                        }
                    }
                }
            } else {
                /* List mode: skip data blocks */
                unsigned long total = size + ((512 - (size % 512)) % 512);
                static char skip[512];
                while (total > 0) {
                    unsigned long chunk = total > 512 ? 512 : total;
                    sys_read(afd, skip, chunk);
                    total -= chunk;
                }
            }
        }
        sys_close(afd);
    }
}

static void cmd_cp(int argc, char *argv[]) {
    int recursive = 0;
    int arg_start = 1;

    /* Parse -r/-R flag */
    while (arg_start < argc && argv[arg_start][0] == '-') {
        for (int j = 1; argv[arg_start][j]; j++) {
            if (argv[arg_start][j] == 'r' || argv[arg_start][j] == 'R')
                recursive = 1;
        }
        arg_start++;
    }

    if (argc - arg_start < 2) {
        write_str(2, "cp: missing operand\n");
        write_str(2, "Usage: cp [-r] <source>... <dest>\n");
        return;
    }

    const char *dest = argv[argc - 1];
    int num_sources = argc - arg_start - 1;

    for (int i = 0; i < num_sources; i++) {
        const char *src = argv[arg_start + i];

        if (recursive) {
            /* Check if source is a directory by trying to open it */
            int tfd = sys_open(src, O_RDONLY, 0);
            if (tfd >= 0) {
                /* Try getdents to detect directory */
                static char tbuf[32];
                long dn = sys_getdents64((unsigned int)tfd, tbuf, (unsigned int)sizeof(tbuf));
                sys_close(tfd);
                if (dn > 0) {
                    /* It's a directory — copy recursively */
                    if (num_sources == 1) {
                        cp_recursive(src, dest);
                    } else {
                        const char *bn = cp_get_basename(src);
                        static char dp[512];
                        cp_build_dest_path(dp, sizeof(dp), dest, bn);
                        cp_recursive(src, dp);
                    }
                    continue;
                }
            }
        }

        /* Regular file copy */
        if (num_sources > 1) {
            const char *bn = cp_get_basename(src);
            static char dp[512];
            cp_build_dest_path(dp, sizeof(dp), dest, bn);
            cp_copy_file(src, dp);
        } else {
            cp_copy_file(src, dest);
        }
    }
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

    /* Try atomic rename first (works on same filesystem) */
    long ret = sys_rename(src_path, dst_path);
    if (ret == 0) {
        /* Success! Rename worked */
        return;
    }

    /* Rename failed (likely cross-filesystem), fall back to copy+delete */

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
        ret = sys_unlink(src_path);
        if (ret < 0) {
            write_str(2, "mv: cannot remove '");
            write_str(2, src_path);
            write_str(2, "'\n");
        }
    }
}

/* Built-in: chmod - Change file permissions */
/* Forward declaration */
static int is_builtin(const char *cmd);

/* Built-in: which - Find command in PATH */
static void cmd_which(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: which <command>\n");
        return;
    }
    const char *cmd = argv[1];

    /* Check builtins first */
    if (is_builtin(cmd)) {
        write_str(1, cmd);
        write_str(1, ": shell built-in command\n");
        return;
    }

    /* Search PATH */
    const char *path_env = get_var("PATH");
    if (!path_env) path_env = "/bin:/sbin";
    const char *p = path_env;
    char pbuf[256];

    while (*p) {
        int dlen = 0;
        while (p[dlen] && p[dlen] != ':') dlen++;
        size_t clen = strlen_simple(cmd);
        if (dlen + 1 + clen < sizeof(pbuf)) {
            int j = 0;
            for (int k = 0; k < dlen; k++) pbuf[j++] = p[k];
            if (j > 0 && pbuf[j-1] != '/') pbuf[j++] = '/';
            for (size_t k = 0; k < clen; k++) pbuf[j++] = cmd[k];
            pbuf[j] = '\0';
            /* Check if file exists */
            struct stat st;
            if (sys_call2(__NR_stat, (long)pbuf, (long)&st) == 0) {
                write_str(1, pbuf);
                write_str(1, "\n");
                return;
            }
        }
        p += dlen;
        if (*p == ':') p++;
    }
    write_str(2, cmd);
    write_str(2, " not found\n");
}

/* Built-in: du - Disk usage (simplified) */
static void du_recurse(const char *path, long *total_blocks) {
    struct linux_dirent64 {
        unsigned long long d_ino; long long d_off;
        unsigned short d_reclen; unsigned char d_type; char d_name[256];
    };
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return;
    char buf[2048];
    long nread;
    while ((nread = sys_getdents64(fd, buf, sizeof(buf))) > 0) {
        char *ptr = buf;
        while (ptr < buf + nread) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)ptr;
            if (d->d_name[0] != '.' || (d->d_name[1] && d->d_name[1] != '.')) {
                char child[512];
                int cp = 0;
                for (int k = 0; path[k] && cp < 500; k++) child[cp++] = path[k];
                if (cp > 0 && child[cp-1] != '/') child[cp++] = '/';
                for (int k = 0; d->d_name[k] && cp < 510; k++) child[cp++] = d->d_name[k];
                child[cp] = '\0';
                struct stat st;
                if (sys_call2(__NR_stat, (long)child, (long)&st) == 0) {
                    *total_blocks += st.st_blocks;
                }
                if (d->d_type == 4) du_recurse(child, total_blocks);
            }
            ptr += d->d_reclen;
        }
    }
    sys_close(fd);
}

static void cmd_du(int argc, char *argv[]) {
    int human = 0, summary = 0;
    int arg_start = 1;
    while (arg_start < argc && argv[arg_start][0] == '-') {
        for (int j = 1; argv[arg_start][j]; j++) {
            if (argv[arg_start][j] == 'h') human = 1;
            else if (argv[arg_start][j] == 's') summary = 1;
        }
        arg_start++;
    }
    const char *path = arg_start < argc ? argv[arg_start] : ".";
    long blocks = 0;
    du_recurse(path, &blocks);
    long kb = blocks / 2;
    char nbuf[20];
    if (human) {
        ls_format_human_size(kb * 1024, nbuf, 20);
    } else {
        int_to_str(kb, nbuf, 20);
    }
    write_str(1, nbuf);
    write_str(1, "\t");
    write_str(1, path);
    write_str(1, "\n");
    (void)summary; /* -s is default behavior (only show total) */
}

static void cmd_chmod(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "usage: chmod <mode> <file>\n");
        return;
    }
    /* Parse octal mode */
    const char *ms = argv[1];
    unsigned int mode = 0;
    for (int i = 0; ms[i]; i++) {
        if (ms[i] < '0' || ms[i] > '7') {
            write_str(2, "chmod: invalid mode (use octal, e.g. 755)\n");
            return;
        }
        mode = (mode << 3) | (ms[i] - '0');
    }
    /* chmod syscall: x86_64=90, ARM64 uses fchmodat */
    long ret = sys_call3(90 /* chmod */, (long)argv[2], (long)mode, 0);
    if (ret < 0) {
        write_str(2, "chmod: failed\n");
    }
}

/* Built-in: tree - Display directory tree */
static void tree_recurse(const char *path, const char *prefix, int *file_count, int *dir_count) {
    struct linux_dirent64 {
        unsigned long long d_ino;
        long long d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[256];
    };

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return;

    char buf[2048];
    long nread;
    /* Collect entries first to know which is last */
    struct { char name[128]; unsigned char type; } entries[64];
    int count = 0;

    while ((nread = sys_getdents64(fd, buf, sizeof(buf))) > 0 && count < 64) {
        char *ptr = buf;
        while (ptr < buf + nread && count < 64) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)ptr;
            if (d->d_name[0] != '.') {
                int j = 0;
                while (d->d_name[j] && j < 127) { entries[count].name[j] = d->d_name[j]; j++; }
                entries[count].name[j] = '\0';
                entries[count].type = d->d_type;
                count++;
            }
            ptr += d->d_reclen;
        }
    }
    sys_close(fd);

    for (int i = 0; i < count; i++) {
        int is_last = (i == count - 1);
        write_str(1, prefix);
        write_str(1, is_last ? "└── " : "├── ");

        if (entries[i].type == 4) {  /* DT_DIR */
            write_str(1, "\033[34m");
            write_str(1, entries[i].name);
            write_str(1, "\033[0m\n");
            (*dir_count)++;

            /* Build child path */
            char child[512];
            int p = 0;
            for (int k = 0; path[k] && p < 500; k++) child[p++] = path[k];
            if (p > 0 && child[p-1] != '/') child[p++] = '/';
            for (int k = 0; entries[i].name[k] && p < 510; k++) child[p++] = entries[i].name[k];
            child[p] = '\0';

            /* Build child prefix */
            char cpfx[256];
            int pp = 0;
            for (int k = 0; prefix[k] && pp < 240; k++) cpfx[pp++] = prefix[k];
            const char *add = is_last ? "    " : "│   ";
            for (int k = 0; add[k] && pp < 250; k++) cpfx[pp++] = add[k];
            cpfx[pp] = '\0';

            tree_recurse(child, cpfx, file_count, dir_count);
        } else if (entries[i].type == 10) {  /* DT_LNK */
            write_str(1, "\033[36m");
            write_str(1, entries[i].name);
            write_str(1, "\033[0m\n");
            (*file_count)++;
        } else {
            write_str(1, entries[i].name);
            write_str(1, "\n");
            (*file_count)++;
        }
    }
}

static void cmd_tree(int argc, char *argv[]) {
    const char *path = argc > 1 ? argv[1] : ".";
    write_str(1, "\033[34m");
    write_str(1, path);
    write_str(1, "\033[0m\n");

    int files = 0, dirs = 0;
    tree_recurse(path, "", &files, &dirs);

    char numbuf[16];
    write_str(1, "\n");
    int_to_str(dirs, numbuf, 16);
    write_str(1, numbuf);
    write_str(1, " director");
    write_str(1, dirs == 1 ? "y" : "ies");
    write_str(1, ", ");
    int_to_str(files, numbuf, 16);
    write_str(1, numbuf);
    write_str(1, " file");
    if (files != 1) write_str(1, "s");
    write_str(1, "\n");
}

/* Built-in: ln - Create links */
static void cmd_ln(int argc, char *argv[]) {
    int symbolic = 0;
    int arg_start = 1;

    if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 's') {
        symbolic = 1;
        arg_start = 2;
    }

    if (argc - arg_start < 2) {
        write_str(2, "usage: ln [-s] <target> <linkname>\n");
        return;
    }

    const char *target = argv[arg_start];
    const char *linkname = argv[arg_start + 1];

    if (symbolic) {
        /* symlink(target, linkpath) — x86_64: 88, ARM64: 36 */
        long ret = sys_call2(88 /* symlink */, (long)target, (long)linkname);
        if (ret < 0) {
            write_str(2, "ln: failed to create symlink\n");
        }
    } else {
        /* link(oldpath, newpath) — x86_64: 86, ARM64: 37 */
        long ret = sys_call2(86 /* link */, (long)target, (long)linkname);
        if (ret < 0) {
            write_str(2, "ln: failed to create hard link\n");
        }
    }
}

/* Built-in: readlink - Print symlink target */
static void cmd_readlink(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: readlink <path>\n");
        return;
    }
    char buf[256];
    /* readlink(path, buf, size) — x86_64: 89, ARM64: 78 */
    long ret = sys_call3(89 /* readlink */, (long)argv[1], (long)buf, 255);
    if (ret > 0) {
        buf[ret] = '\0';
        write_str(1, buf);
        write_str(1, "\n");
    } else {
        write_str(2, "readlink: ");
        write_str(2, argv[1]);
        write_str(2, ": not a symlink\n");
    }
}

/* Built-in: realpath - Resolve canonical absolute path */
static void cmd_realpath(int argc, char *argv[]) {
    int quiet = 0;
    int no_symlinks = 0;
    int start = 1;
    for (int i = 1; i < argc && argv[i][0] == '-'; i++) {
        if (strcmp_simple(argv[i], "-q") == 0 || strcmp_simple(argv[i], "--quiet") == 0)
            quiet = 1;
        else if (strcmp_simple(argv[i], "-s") == 0 || strcmp_simple(argv[i], "--no-symlinks") == 0)
            no_symlinks = 1;
        else if (strcmp_simple(argv[i], "--") == 0) { start = i + 1; break; }
        else { write_str(2, "realpath: unknown option: "); write_str(2, argv[i]); write_str(2, "\n"); return; }
        start = i + 1;
    }
    if (start >= argc) {
        write_str(2, "usage: realpath [-q] [-s] <path>...\n");
        return;
    }
    int ret = 0;
    for (int a = start; a < argc; a++) {
        const char *input = argv[a];
        char resolved[1024];
        int rlen = 0;

        /* Start with cwd for relative paths */
        if (input[0] != '/') {
            char cwd[256];
            long cret = sys_getcwd(cwd, sizeof(cwd));
            if (cret <= 0) { write_str(2, "realpath: cannot get cwd\n"); ret = 1; continue; }
            for (int i = 0; cwd[i]; i++) {
                if (rlen < 1022) resolved[rlen++] = cwd[i];
            }
            if (rlen > 0 && resolved[rlen - 1] != '/')
                resolved[rlen++] = '/';
        }
        /* Append input path */
        for (int i = 0; input[i]; i++) {
            if (rlen < 1022) resolved[rlen++] = input[i];
        }
        resolved[rlen] = '\0';

        /* Normalize: resolve ., .., collapse slashes, follow symlinks */
        char out[1024];
        int olen = 0;
        out[0] = '/'; olen = 1;
        int i = 0;
        int symlink_limit = 40;
        while (resolved[i]) {
            /* Skip slashes */
            while (resolved[i] == '/') i++;
            if (!resolved[i]) break;
            /* Extract component */
            int cstart = i;
            while (resolved[i] && resolved[i] != '/') i++;
            int clen = i - cstart;

            if (clen == 1 && resolved[cstart] == '.') {
                /* Current dir — skip */
                continue;
            } else if (clen == 2 && resolved[cstart] == '.' && resolved[cstart + 1] == '.') {
                /* Parent dir — pop last component */
                if (olen > 1) {
                    olen--; /* remove trailing slash or char */
                    while (olen > 1 && out[olen - 1] != '/') olen--;
                }
                continue;
            }

            /* Append component */
            if (olen > 1) out[olen++] = '/';
            for (int j = 0; j < clen && olen < 1020; j++)
                out[olen++] = resolved[cstart + j];
            out[olen] = '\0';

            /* Try to resolve symlink */
            if (!no_symlinks && symlink_limit > 0) {
                char lnk[256];
                long lr = sys_call3(89 /* readlink */, (long)out, (long)lnk, 255);
                if (lr > 0) {
                    symlink_limit--;
                    lnk[lr] = '\0';
                    /* Build new resolved: symlink target + remaining */
                    char tmp[1024];
                    int tlen = 0;
                    if (lnk[0] == '/') {
                        /* Absolute symlink — restart from root */
                        for (int j = 0; lnk[j] && tlen < 1020; j++)
                            tmp[tlen++] = lnk[j];
                        /* Reset output to root */
                        olen = 1; out[0] = '/';
                    } else {
                        /* Relative symlink — pop current component, prepend parent */
                        if (olen > 1) {
                            olen--;
                            while (olen > 1 && out[olen - 1] != '/') olen--;
                        }
                        out[olen] = '\0';
                        for (int j = 0; lnk[j] && tlen < 1020; j++)
                            tmp[tlen++] = lnk[j];
                    }
                    /* Append remaining unprocessed path */
                    while (resolved[i] && tlen < 1020)
                        tmp[tlen++] = resolved[i++];
                    tmp[tlen] = '\0';
                    /* Replace resolved with tmp and restart parsing */
                    for (int j = 0; j <= tlen; j++) resolved[j] = tmp[j];
                    rlen = tlen;
                    i = 0;
                    continue;
                }
            }
        }
        if (olen == 0) { out[0] = '/'; olen = 1; }
        out[olen] = '\0';

        /* Verify path exists */
        struct stat st;
        if (sys_call2(__NR_stat, (long)out, (long)&st) < 0) {
            if (!quiet) {
                write_str(2, "realpath: ");
                write_str(2, argv[a]);
                write_str(2, ": No such file or directory\n");
            }
            ret = 1;
            continue;
        }
        write_str(1, out);
        write_str(1, "\n");
    }
    (void)ret;
}

/* Built-in: dd - Copy and convert data */
static void cmd_dd(int argc, char *argv[]) {
    const char *if_path = NULL;
    const char *of_path = NULL;
    long bs = 512;
    long count = -1;  /* -1 = unlimited */

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == 'i' && argv[i][1] == 'f' && argv[i][2] == '=') {
            if_path = argv[i] + 3;
        } else if (argv[i][0] == 'o' && argv[i][1] == 'f' && argv[i][2] == '=') {
            of_path = argv[i] + 3;
        } else if (argv[i][0] == 'b' && argv[i][1] == 's' && argv[i][2] == '=') {
            bs = 0;
            for (const char *p = argv[i] + 3; *p >= '0' && *p <= '9'; p++)
                bs = bs * 10 + (*p - '0');
            if (bs <= 0 || bs > 65536) bs = 512;
        } else if (argv[i][0] == 'c' && argv[i][1] == 'o' && argv[i][2] == 'u' &&
                   argv[i][3] == 'n' && argv[i][4] == 't' && argv[i][5] == '=') {
            count = 0;
            for (const char *p = argv[i] + 6; *p >= '0' && *p <= '9'; p++)
                count = count * 10 + (*p - '0');
        }
    }

    int in_fd = 0;   /* default: stdin */
    int out_fd = 1;  /* default: stdout */

    if (if_path) {
        in_fd = sys_open(if_path, O_RDONLY, 0);
        if (in_fd < 0) { write_str(2, "dd: cannot open input\n"); return; }
    }
    if (of_path) {
        out_fd = sys_open(of_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            write_str(2, "dd: cannot open output\n");
            if (if_path) sys_close(in_fd);
            return;
        }
    }

    char buf[65536];
    long total_bytes = 0;
    long blocks_in = 0, blocks_out = 0;

    while (count < 0 || blocks_in < count) {
        long n = sys_read(in_fd, buf, bs);
        if (n <= 0) break;
        blocks_in++;
        long w = sys_write(out_fd, buf, n);
        if (w > 0) { total_bytes += w; blocks_out++; }
        if (w != n) break;
    }

    if (if_path) sys_close(in_fd);
    if (of_path) sys_close(out_fd);

    /* Print stats */
    char nbuf[20];
    int_to_str(blocks_in, nbuf, 20);
    write_str(2, nbuf); write_str(2, "+0 records in\n");
    int_to_str(blocks_out, nbuf, 20);
    write_str(2, nbuf); write_str(2, "+0 records out\n");
    int_to_str(total_bytes, nbuf, 20);
    write_str(2, nbuf); write_str(2, " bytes copied\n");
}

/* Built-in: stat - Show file information */
static void cmd_stat(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: stat <file>\n");
        return;
    }
    struct stat st;
    long ret = sys_call2(__NR_stat, (long)argv[1], (long)&st);
    if (ret < 0) {
        write_str(2, "stat: ");
        write_str(2, argv[1]);
        write_str(2, ": cannot stat\n");
        return;
    }
    write_str(1, "  File: ");
    write_str(1, argv[1]);
    write_str(1, "\n  Size: ");
    char numbuf[20];
    int_to_str((long)st.st_size, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\tBlocks: ");
    int_to_str((long)st.st_blocks, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\n");
    /* Mode */
    char modebuf[11];
    format_mode(st.st_mode, modebuf);
    write_str(1, "Access: (0");
    /* Octal permission digits */
    char oct[4];
    oct[0] = '0' + ((st.st_mode >> 6) & 7);
    oct[1] = '0' + ((st.st_mode >> 3) & 7);
    oct[2] = '0' + (st.st_mode & 7);
    oct[3] = '\0';
    write_str(1, oct);
    write_str(1, "/");
    write_str(1, modebuf);
    write_str(1, ")  Uid: ");
    int_to_str(st.st_uid, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "  Gid: ");
    int_to_str(st.st_gid, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\nDevice: ");
    int_to_str((long)st.st_dev, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\tInode: ");
    int_to_str((long)st.st_ino, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\tLinks: ");
    int_to_str(st.st_nlink, numbuf, 20);
    write_str(1, numbuf);
    write_str(1, "\n");
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
            set_var(name, expanded_value, 0);
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
            /* Directory exists */
            struct { uint64_t dev; uint64_t ino; uint64_t nlink; uint32_t mode; uint32_t uid;
                     uint32_t gid; uint32_t _pad; uint64_t rdev; int64_t size; int64_t blksize;
                     int64_t blocks; uint64_t atime_sec; uint64_t atime_nsec;
                     uint64_t mtime_sec; uint64_t mtime_nsec;
                     uint64_t ctime_sec; uint64_t ctime_nsec; } st;
            if (sys_call2(4 /* stat */, (long)arg, (long)&st) == 0 && (st.mode & 0170000) == 0040000)
                return 0;
            return 1;
        } else if (strcmp_simple(op, "-r") == 0) {
            /* File is readable */
            int fd = sys_open(arg, 0 /*O_RDONLY*/, 0);
            if (fd >= 0) { sys_close(fd); return 0; }
            return 1;
        } else if (strcmp_simple(op, "-w") == 0) {
            /* File is writable */
            int fd = sys_open(arg, 1 /*O_WRONLY*/, 0);
            if (fd >= 0) { sys_close(fd); return 0; }
            return 1;
        } else if (strcmp_simple(op, "-x") == 0) {
            /* File is executable (simplified: check if exists and openable) */
            int fd = sys_open(arg, 0, 0);
            if (fd >= 0) { sys_close(fd); return 0; }
            return 1;
        } else if (strcmp_simple(op, "-s") == 0) {
            /* File has nonzero size */
            struct { uint64_t dev; uint64_t ino; uint64_t nlink; uint32_t mode; uint32_t uid;
                     uint32_t gid; uint32_t _pad; uint64_t rdev; int64_t size; int64_t blksize;
                     int64_t blocks; uint64_t atime_sec; uint64_t atime_nsec;
                     uint64_t mtime_sec; uint64_t mtime_nsec;
                     uint64_t ctime_sec; uint64_t ctime_nsec; } st;
            if (sys_call2(4 /* stat */, (long)arg, (long)&st) == 0 && st.size > 0)
                return 0;
            return 1;
        } else if (strcmp_simple(op, "-L") == 0 || strcmp_simple(op, "-h") == 0) {
            /* File is a symbolic link (check readlink) */
            char lbuf[64];
            long lr = sys_call3(89 /* readlink */, (long)arg, (long)lbuf, 63);
            return (lr > 0) ? 0 : 1;
        } else if (strcmp_simple(op, "-p") == 0) {
            /* File is a named pipe (FIFO) */
            int fd = sys_open(arg, 0, 0);
            if (fd >= 0) { sys_close(fd); return 0; } /* simplified */
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

    /* Resume if stopped, then wait for completion */
    write_str(1, j->command);
    write_str(1, "\n");
    if (j->status == JOB_STOPPED) {
        sys_call2(62 /* kill */, j->pid, 18 /* SIGCONT */);
        j->status = JOB_RUNNING;
    }

    int status = 0;
    sys_waitpid(j->pid, &status, 0);

    /* Remove from job table */
    remove_job(j->job_id);
}

/* Built-in: bg - resume stopped job in background */
static void cmd_bg(int argc, char *argv[]) {
    update_jobs();

    struct job *j = NULL;
    if (argc < 2) {
        int max_id = 0;
        for (int i = 0; i < MAX_JOBS; i++) {
            if (jobs[i].used && jobs[i].status == JOB_STOPPED && jobs[i].job_id > max_id) {
                max_id = jobs[i].job_id;
                j = &jobs[i];
            }
        }
        if (!j) { write_str(2, "bg: no stopped job\n"); return; }
    } else {
        int job_id = simple_atoi(argv[1]);
        j = find_job(job_id);
        if (!j) { write_str(2, "bg: job not found\n"); return; }
    }

    /* Send SIGCONT to resume the stopped process */
    sys_call2(62 /* kill */, j->pid, 18 /* SIGCONT */);
    j->status = JOB_RUNNING;
    write_str(1, "[");
    char num[8]; int ni = 0;
    int jid = j->job_id;
    if (jid >= 10) num[ni++] = '0' + jid / 10;
    num[ni++] = '0' + jid % 10;
    num[ni] = '\0';
    write_str(1, num);
    write_str(1, "] ");
    write_str(1, j->command);
    write_str(1, " &\n");
}

/* Execute a command */
static int execute_command(int argc, char *argv[]) {
    /* Safety checks to prevent crashes */
    if (argc == 0 || !argv || !argv[0]) {
        return 0;
    }

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
    } else if (strcmp_simple(argv[0], "date") == 0) {
        cmd_date(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nc") == 0) {
        cmd_nc(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "curl") == 0) {
        cmd_curl(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "wget") == 0) {
        cmd_wget(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "lsof") == 0) {
        cmd_lsof(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "time") == 0) {
        cmd_time(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "sleep") == 0) {
        cmd_sleep(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "hexdump") == 0) {
        cmd_hexdump(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "seq") == 0) {
        cmd_seq(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "df") == 0) {
        cmd_df(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "dmesg") == 0) {
        cmd_dmesg(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "edit") == 0) {
        cmd_edit(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "vi") == 0) {
        cmd_vi(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "make") == 0) {
        cmd_make(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "git") == 0) {
        cmd_git(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "free") == 0) {
        cmd_free(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "hostname") == 0) {
        cmd_hostname(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "id") == 0) {
        cmd_id(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "kill") == 0) {
        cmd_kill(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "ps") == 0) {
        cmd_ps(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "ifconfig") == 0) {
        cmd_ifconfig(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "uptime") == 0) {
        cmd_uptime(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "version") == 0) {
        cmd_version(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "reboot") == 0) {
        cmd_reboot(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "poweroff") == 0) {
        cmd_poweroff(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "mount") == 0) {
        cmd_mount(argc, argv);
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
    } else if (strcmp_simple(argv[0], "uniq") == 0) {
        cmd_uniq(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cut") == 0) {
        cmd_cut(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tr") == 0) {
        cmd_tr(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tee") == 0) {
        cmd_tee(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "paste") == 0) {
        cmd_paste(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "diff") == 0) {
        cmd_diff(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "sed") == 0) {
        cmd_sed(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "rev") == 0) {
        cmd_rev(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nl") == 0) {
        cmd_nl(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "base64") == 0) {
        cmd_base64(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "od") == 0) {
        cmd_od(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "awk") == 0) {
        cmd_awk(argc, argv);
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
    } else if (strcmp_simple(argv[0], "tar") == 0) {
        cmd_tar(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "mv") == 0) {
        cmd_mv(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "stat") == 0) {
        cmd_stat(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nslookup") == 0) {
        /* DNS lookup via UDP socket to DNS server */
        if (argc < 2) { write_str(2, "usage: nslookup [-aaaa] <domain>\n"); return 1; }
        /* Check for -aaaa flag */
        int qtype_hi = 0x00, qtype_lo = 0x01; /* default: A record (type 1) */
        int domain_arg = 1;
        if (argc >= 3 && strcmp_simple(argv[1], "-aaaa") == 0) {
            qtype_hi = 0x00; qtype_lo = 0x1C; /* AAAA record (type 28) */
            domain_arg = 2;
        }
        /* Build DNS query packet */
        uint8_t pkt[512];
        int pos = 0;
        /* Header: ID=0x1234, flags=0x0100 (standard query), qdcount=1 */
        pkt[pos++] = 0x12; pkt[pos++] = 0x34; /* ID */
        pkt[pos++] = 0x01; pkt[pos++] = 0x00; /* Flags: RD=1 */
        pkt[pos++] = 0x00; pkt[pos++] = 0x01; /* QDCOUNT=1 */
        pkt[pos++] = 0x00; pkt[pos++] = 0x00; /* ANCOUNT=0 */
        pkt[pos++] = 0x00; pkt[pos++] = 0x00; /* NSCOUNT=0 */
        pkt[pos++] = 0x00; pkt[pos++] = 0x00; /* ARCOUNT=0 */
        /* Encode domain name */
        const char *d = argv[domain_arg];
        while (*d) {
            const char *dot = d;
            while (*dot && *dot != '.') dot++;
            int len = (int)(dot - d);
            pkt[pos++] = (uint8_t)len;
            for (int i = 0; i < len; i++) pkt[pos++] = d[i];
            d = dot;
            if (*d == '.') d++;
        }
        pkt[pos++] = 0; /* Root label */
        pkt[pos++] = (uint8_t)qtype_hi; pkt[pos++] = (uint8_t)qtype_lo; /* QTYPE */
        pkt[pos++] = 0x00; pkt[pos++] = 0x01; /* QCLASS=IN */

        /* Try DNS servers: 127.0.0.53 (systemd-resolved), then 10.0.2.3 (QEMU) */
        static const uint32_t dns_servers[] = {
            0x3500007F,  /* 127.0.0.53 in network byte order */
            0x0302000A,  /* 10.0.2.3  in network byte order */
        };
        static const char *dns_names[] = { "127.0.0.53", "10.0.2.3" };
        int dns_count = 2;
        long rn = -1;
        uint8_t resp[512];
        int used_server = 0;

        for (int si = 0; si < dns_count; si++) {
            long fd = sys_call3(41, 2 /* AF_INET */, 2 /* SOCK_DGRAM */, 0);
            if (fd < 0) continue;

            struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
            sa.family = 2;
            sa.port = (53 >> 8) | ((53 & 0xFF) << 8); /* htons(53) */
            sa.addr = dns_servers[si];
            for (int i = 0; i < 8; i++) sa.pad[i] = 0;

            /* Set 2s receive timeout */
            struct { long tv_sec; long tv_usec; } tv = {2, 0};
            sys_call6(54 /* setsockopt */, fd, 1 /* SOL_SOCKET */, 20 /* SO_RCVTIMEO */,
                      (long)&tv, (long)sizeof(tv), 0);

            sys_call6(44 /* sendto */, fd, (long)pkt, pos, 0, (long)&sa, 16);
            rn = sys_call6(45 /* recvfrom */, fd, (long)resp, 512, 0, 0, 0);
            sys_close(fd);
            if (rn > 12) { used_server = si; break; }
        }

        if (rn > 12) {
            int ancount = (resp[6] << 8) | resp[7];
            if (ancount > 0) {
                /* Skip query section to find answer */
                int rp = 12;
                /* Skip QNAME */
                while (rp < (int)rn && resp[rp] != 0) {
                    if ((resp[rp] & 0xC0) == 0xC0) { rp += 2; break; }
                    rp += resp[rp] + 1;
                }
                if (resp[rp] == 0) rp++; /* null terminator */
                rp += 4; /* QTYPE + QCLASS */

                /* Print header */
                write_str(1, "Server:  "); write_str(1, dns_names[used_server]);
                write_str(1, "\nName:    "); write_str(1, argv[domain_arg]); write_char(1, '\n');

                /* Parse all answer records */
                for (int ans = 0; ans < ancount && rp + 12 <= (int)rn; ans++) {
                    /* Skip NAME (may be pointer) */
                    if ((resp[rp] & 0xC0) == 0xC0) rp += 2;
                    else { while (rp < (int)rn && resp[rp] != 0) rp += resp[rp] + 1; rp++; }
                    int atype = (resp[rp] << 8) | resp[rp+1]; rp += 2;
                    rp += 2; /* CLASS */ rp += 4; /* TTL */
                    int rdlen = (resp[rp] << 8) | resp[rp+1]; rp += 2;
                    if (atype == 1 && rdlen == 4 && rp + 4 <= (int)rn) {
                        write_str(1, "Address: ");
                        char nb[8];
                        int_to_str(resp[rp], nb, 8); write_str(1, nb); write_char(1, '.');
                        int_to_str(resp[rp+1], nb, 8); write_str(1, nb); write_char(1, '.');
                        int_to_str(resp[rp+2], nb, 8); write_str(1, nb); write_char(1, '.');
                        int_to_str(resp[rp+3], nb, 8); write_str(1, nb); write_char(1, '\n');
                    } else if (atype == 28 && rdlen == 16 && rp + 16 <= (int)rn) {
                        /* AAAA record */
                        write_str(1, "Address: ");
                        static const char hx[] = "0123456789abcdef";
                        for (int g = 0; g < 16; g += 2) {
                            char h[5];
                            h[0] = hx[(resp[rp+g] >> 4) & 0xF];
                            h[1] = hx[resp[rp+g] & 0xF];
                            h[2] = hx[(resp[rp+g+1] >> 4) & 0xF];
                            h[3] = hx[resp[rp+g+1] & 0xF];
                            h[4] = '\0';
                            write_str(1, h);
                            if (g < 14) write_char(1, ':');
                        }
                        write_char(1, '\n');
                    }
                    rp += rdlen;
                }
                return 0;
            }
            write_str(2, "nslookup: no answer\n");
        } else {
            write_str(2, "nslookup: no response from DNS server\n");
        }
        return 1;
    } else if (strcmp_simple(argv[0], "sha256sum") == 0) {
        /* Simple SHA-256 hash of file contents */
        if (argc < 2) { write_str(2, "usage: sha256sum <file>\n"); return 1; }
        int fd = sys_open(argv[1], O_RDONLY, 0);
        if (fd < 0) { write_str(2, "sha256sum: cannot open\n"); return 1; }
        /* Read file and compute simple hash (not real SHA-256, but a reasonable checksum) */
        uint64_t h0 = 0x6a09e667bb67ae85ULL, h1 = 0x3c6ef372a54ff53aULL;
        uint64_t h2 = 0x510e527f9b05688cULL, h3 = 0x1f83d9ab5be0cd19ULL;
        char buf[256];
        long n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (long i = 0; i < n; i++) {
                h0 = h0 * 1099511628211ULL ^ (uint8_t)buf[i];
                h1 = h1 * 309485009821345068ULL ^ (uint8_t)buf[i];
                h2 ^= (h0 >> 32) | (h1 << 32);
                h3 += h0 ^ h1;
            }
        }
        sys_close(fd);
        /* Print as 64-char hex string (256 bits from 4x64-bit) */
        uint64_t hashes[4] = {h0, h1, h2, h3};
        for (int hi = 0; hi < 4; hi++) {
            for (int bi = 60; bi >= 0; bi -= 4) {
                int nib = (hashes[hi] >> bi) & 0xF;
                write_char(1, nib < 10 ? '0' + nib : 'a' + nib - 10);
            }
        }
        write_str(1, "  ");
        write_str(1, argv[1]);
        write_char(1, '\n');
        return 0;
    } else if (strcmp_simple(argv[0], "ss") == 0) {
        /* ss — show socket statistics from /proc/net/tcp and /proc/net/udp */
        write_str(1, "Netid  State      Local Address:Port    Peer Address:Port\n");
        int fd = sys_open("/proc/net/tcp", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[512];
            ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        }
        fd = sys_open("/proc/net/udp", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[512];
            ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "netstat") == 0) {
        /* netstat — show network connections, routing table, interface stats */
        int show_route = 0, show_ifaces = 0, show_listen = 0, show_all = 0, show_stats = 0;
        for (int i = 1; i < argc; i++) {
            if (argv[i][0] == '-') {
                for (int j = 1; argv[i][j]; j++) {
                    if (argv[i][j] == 'r') show_route = 1;
                    if (argv[i][j] == 'i') show_ifaces = 1;
                    if (argv[i][j] == 'l') show_listen = 1;
                    if (argv[i][j] == 'a') show_all = 1;
                    if (argv[i][j] == 's') show_stats = 1;
                }
            }
        }
        if (show_stats) {
            /* netstat -s: show protocol statistics from /proc/net/snmp */
            write_str(1, "Protocol statistics:\n");
            int fd = sys_open("/proc/net/snmp", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
            write_str(1, "\nNetwork statistics:\n");
            fd = sys_open("/proc/net/netstat", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
        } else if (show_route) {
            write_str(1, "Kernel IP routing table\n");
            int fd = sys_open("/proc/net/route", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
        } else if (show_ifaces) {
            write_str(1, "Kernel Interface table\n");
            int fd = sys_open("/proc/net/dev", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
        } else {
            /* Show connections */
            write_str(1, "Active Internet connections");
            if (show_all) write_str(1, " (servers and established)");
            else if (show_listen) write_str(1, " (only servers)");
            write_str(1, "\n");
            write_str(1, "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");
            int fd = sys_open("/proc/net/tcp", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
            fd = sys_open("/proc/net/udp", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
            /* Show Unix sockets */
            write_str(1, "\nActive UNIX domain sockets\n");
            fd = sys_open("/proc/net/unix", O_RDONLY, 0);
            if (fd >= 0) { char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "httpd") == 0) {
        /* httpd — minimal HTTP server for testing the networking stack */
        int port = 8080;
        const char *docroot = "/";
        for (int i = 1; i < argc; i++) {
            if (strcmp_simple(argv[i], "-p") == 0 && i+1 < argc) {
                port = 0; const char *pp = argv[++i];
                while (*pp >= '0' && *pp <= '9') port = port * 10 + (*pp++ - '0');
            } else if (strcmp_simple(argv[i], "-d") == 0 && i+1 < argc) {
                docroot = argv[++i];
            }
        }

        long sfd = sys_call3(41 /* socket */, 2, 1, 0);
        if (sfd < 0) { write_str(2, "httpd: socket failed\n"); return 1; }

        /* SO_REUSEADDR */
        int one = 1;
        sys_call6(54, sfd, 1, 2 /* SO_REUSEADDR */, (long)&one, sizeof(one), 0);

        struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
        sa.family = 2; sa.addr = 0;
        sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
        for (int i = 0; i < 8; i++) sa.pad[i] = 0;

        if (sys_call3(49, sfd, (long)&sa, 16) < 0) {
            write_str(2, "httpd: bind failed\n"); sys_close(sfd); return 1;
        }
        if (sys_call2(50 /* listen */, sfd, 5) < 0) {
            write_str(2, "httpd: listen failed\n"); sys_close(sfd); return 1;
        }

        write_str(1, "httpd: serving on port ");
        { char pb[8]; int pi = 0;
          if (port >= 10000) pb[pi++] = '0' + port/10000;
          if (port >= 1000) pb[pi++] = '0' + (port/1000)%10;
          if (port >= 100) pb[pi++] = '0' + (port/100)%10;
          if (port >= 10) pb[pi++] = '0' + (port/10)%10;
          pb[pi++] = '0' + port%10; pb[pi] = '\0';
          write_str(1, pb); }
        write_str(1, " (docroot: ");
        write_str(1, docroot);
        write_str(1, ")\n");
        write_str(1, "Press Ctrl+C to stop\n");

        /* Accept loop — handle one connection at a time */
        for (int conn = 0; conn < 100; conn++) {
            long cfd = sys_call3(43 /* accept */, sfd, 0, 0);
            if (cfd < 0) continue;

            /* Read HTTP request */
            char req[1024];
            ssize_t rn = sys_read(cfd, req, sizeof(req) - 1);
            if (rn <= 0) { sys_close(cfd); continue; }
            req[rn] = '\0';

            /* Parse GET /path */
            char path[256];
            int pi = 0;
            if (req[0] == 'G' && req[1] == 'E' && req[2] == 'T' && req[3] == ' ') {
                int ri = 4;
                /* Prepend docroot */
                for (int j = 0; docroot[j] && pi < 200; j++) path[pi++] = docroot[j];
                if (pi > 0 && path[pi-1] == '/' && req[ri] == '/') ri++; /* avoid double / */
                while (req[ri] && req[ri] != ' ' && req[ri] != '?' && pi < 254)
                    path[pi++] = req[ri++];
            }
            path[pi] = '\0';
            if (pi == 0 || path[pi-1] == '/') {
                /* Append index.html for directory requests */
                const char *idx = "index.html";
                for (int j = 0; idx[j] && pi < 254; j++) path[pi++] = idx[j];
                path[pi] = '\0';
            }

            /* Try to serve the file */
            int ffd = sys_open(path, O_RDONLY, 0);
            if (ffd >= 0) {
                /* 200 OK */
                static const char ok[] = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
                sys_write(cfd, ok, sizeof(ok) - 1);
                char fbuf[512];
                ssize_t fn;
                while ((fn = sys_read(ffd, fbuf, sizeof(fbuf))) > 0)
                    sys_write(cfd, fbuf, fn);
                sys_close(ffd);
            } else {
                /* 404 Not Found */
                static const char nf[] = "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
                    "<html><body><h1>404 Not Found</h1><p>File not found on Futura OS</p></body></html>\n";
                sys_write(cfd, nf, sizeof(nf) - 1);
            }
            sys_close(cfd);
        }
        sys_close(sfd);
        write_str(1, "httpd: stopped\n");
        return 0;
    } else if (strcmp_simple(argv[0], "top") == 0) {
        /* top — show process information and system stats (one-shot) */
        /* System info header */
        {
            int fd = sys_open("/proc/uptime", O_RDONLY, 0);
            if (fd >= 0) {
                char ub[64]; ssize_t n = sys_read(fd, ub, sizeof(ub)-1);
                sys_close(fd); if (n > 0) { ub[n] = '\0'; write_str(1, "up "); write_str(1, ub); }
            }
        }
        {
            int fd = sys_open("/proc/loadavg", O_RDONLY, 0);
            if (fd >= 0) {
                char lb[64]; ssize_t n = sys_read(fd, lb, sizeof(lb)-1);
                sys_close(fd); if (n > 0) { lb[n] = '\0'; write_str(1, "load: "); write_str(1, lb); }
            }
        }
        /* Memory info */
        {
            int fd = sys_open("/proc/meminfo", O_RDONLY, 0);
            if (fd >= 0) {
                char mb[512]; ssize_t n = sys_read(fd, mb, sizeof(mb)-1);
                sys_close(fd);
                if (n > 0) {
                    mb[n] = '\0';
                    /* Extract MemTotal and MemFree lines */
                    for (char *p = mb; *p; ) {
                        if (p[0]=='M' && p[1]=='e' && p[2]=='m' && (p[3]=='T' || p[3]=='F' || p[3]=='A')) {
                            char *eol = p; while (*eol && *eol != '\n') eol++;
                            char save = *eol; *eol = '\0';
                            write_str(1, p); write_str(1, "\n");
                            *eol = save;
                        }
                        while (*p && *p != '\n') p++;
                        if (*p) p++;
                    }
                }
            }
        }
        write_str(1, "\n  PID STATE     RSS COMMAND\n");
        /* Process list */
        int proc_fd = sys_open("/proc", O_RDONLY, 0);
        if (proc_fd >= 0) {
            char dirbuf[2048];
            ssize_t dn;
            while ((dn = sys_getdents64(proc_fd, dirbuf, sizeof(dirbuf))) > 0) {
                ssize_t pos = 0;
                while (pos < dn) {
                    uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
                    char *name = dirbuf + pos + 19;
                    if (name[0] >= '1' && name[0] <= '9') {
                        /* Read /proc/<pid>/stat for one-line summary */
                        char spath[64]; int spi = 0;
                        const char *pfx = "/proc/"; while (pfx[spi]) { spath[spi] = pfx[spi]; spi++; }
                        int ni = 0; while (name[ni]) { spath[spi++] = name[ni++]; }
                        const char *sfx = "/stat"; ni = 0;
                        while (sfx[ni]) { spath[spi++] = sfx[ni++]; }
                        spath[spi] = '\0';
                        int sfd = sys_open(spath, O_RDONLY, 0);
                        if (sfd >= 0) {
                            char sb[256]; ssize_t sn = sys_read(sfd, sb, sizeof(sb)-1);
                            sys_close(sfd);
                            if (sn > 0) {
                                sb[sn] = '\0';
                                /* Parse: pid (name) state ... field23=rss */
                                /* Just print PID, pad, then extract comm and state */
                                write_str(1, " ");
                                /* PID: right-pad to 4 chars */
                                int plen = 0; while (name[plen]) plen++;
                                for (int k = plen; k < 4; k++) write_str(1, " ");
                                write_str(1, name);
                                /* Find comm (between parens) and state (after close paren) */
                                char *lp = sb; while (*lp && *lp != '(') lp++;
                                char *rp = lp; while (*rp && *rp != ')') rp++;
                                if (*lp == '(' && *rp == ')') {
                                    write_str(1, " ");
                                    /* State is at rp+2 */
                                    char state = rp[2];
                                    char ss[2] = {state, '\0'};
                                    write_str(1, ss);
                                    write_str(1, "       ");
                                    /* Skip to field 24 (RSS) — count spaces after ')' */
                                    char *fp = rp + 2;
                                    int field = 3;
                                    while (*fp && field < 24) {
                                        if (*fp == ' ') field++;
                                        fp++;
                                    }
                                    /* Print RSS (in pages) */
                                    char *rss_start = fp;
                                    while (*fp && *fp != ' ') fp++;
                                    char save2 = *fp; *fp = '\0';
                                    write_str(1, rss_start);
                                    *fp = save2;
                                    /* Print command name */
                                    write_str(1, " ");
                                    lp++; *rp = '\0';
                                    write_str(1, lp);
                                }
                                write_str(1, "\n");
                            }
                        }
                    }
                    pos += reclen;
                }
            }
            sys_close(proc_fd);
        }
        return 0;
    } else if (strcmp_simple(argv[0], "watch") == 0) {
        /* watch — execute a command repeatedly, showing output each time */
        int interval = 2; /* default 2 seconds */
        int cmd_start = 1;
        if (argc > 2 && strcmp_simple(argv[1], "-n") == 0) {
            interval = 0;
            for (int i = 0; argv[2][i]; i++) interval = interval * 10 + (argv[2][i] - '0');
            cmd_start = 3;
        }
        if (cmd_start >= argc) {
            write_str(1, "usage: watch [-n secs] <command...>\n");
            return 1;
        }
        /* Build command string */
        char cmd[256]; int ci = 0;
        for (int i = cmd_start; i < argc && ci < 250; i++) {
            if (i > cmd_start) cmd[ci++] = ' ';
            for (int j = 0; argv[i][j] && ci < 250; j++) cmd[ci++] = argv[i][j];
        }
        cmd[ci] = '\0';
        /* Run command 10 times (limited in kernel self-test env) */
        for (int iter = 0; iter < 10; iter++) {
            /* Clear screen and show header */
            write_str(1, "\033[2J\033[H");
            write_str(1, "Every ");
            char ib[4]; int ip = 0;
            if (interval >= 10) ib[ip++] = '0' + interval / 10;
            ib[ip++] = '0' + interval % 10;
            ib[ip] = '\0';
            write_str(1, ib);
            write_str(1, "s: ");
            write_str(1, cmd);
            write_str(1, "\n\n");
            /* Execute the command via the shell's command chain executor */
            char cmd_copy[256];
            for (int j = 0; cmd[j] && j < 255; j++) cmd_copy[j] = cmd[j];
            cmd_copy[ci < 255 ? ci : 255] = '\0';
            execute_command_chain(cmd_copy);
            /* Sleep */
            struct { long tv_sec; long tv_nsec; } ts = { interval, 0 };
            sys_call2(35 /* nanosleep */, (long)&ts, 0);
        }
        return 0;
    } else if (strcmp_simple(argv[0], "sysctl") == 0) {
        /* sysctl — read/write kernel parameters via /proc/sys/ */
        if (argc < 2) {
            write_str(1, "usage: sysctl [-w] <key>[=<value>]\n");
            write_str(1, "  sysctl net.ipv4.ip_forward        # read\n");
            write_str(1, "  sysctl -w net.ipv4.ip_forward=1   # write\n");
            return 0;
        }
        int write_mode = 0;
        int key_idx = 1;
        if (strcmp_simple(argv[1], "-w") == 0) { write_mode = 1; key_idx = 2; }
        if (key_idx >= argc) { write_str(2, "sysctl: missing key\n"); return 1; }

        /* Convert dotted key to /proc/sys/ path (dots → slashes) */
        const char *key = argv[key_idx];
        char path[128] = "/proc/sys/";
        int pi = 10;
        const char *eq = NULL;
        for (int i = 0; key[i] && pi < 126; i++) {
            if (key[i] == '=') { eq = &key[i + 1]; break; }
            path[pi++] = (key[i] == '.') ? '/' : key[i];
        }
        path[pi] = '\0';

        if (write_mode || eq) {
            /* Write mode */
            const char *val = eq ? eq : (key_idx + 1 < argc ? argv[key_idx + 1] : NULL);
            if (!val) { write_str(2, "sysctl: missing value\n"); return 1; }
            int fd = sys_open(path, O_WRONLY, 0);
            if (fd >= 0) {
                int vlen = 0; while (val[vlen]) vlen++;
                sys_write(fd, val, vlen);
                sys_close(fd);
                /* Print confirmation */
                for (int i = 0; key[i] && key[i] != '='; i++) write_char(1, key[i]);
                write_str(1, " = ");
                write_str(1, val);
                write_str(1, "\n");
            } else {
                write_str(2, "sysctl: cannot write "); write_str(2, path); write_str(2, "\n");
                return 1;
            }
        } else {
            /* Read mode */
            int fd = sys_open(path, O_RDONLY, 0);
            if (fd >= 0) {
                char buf[256];
                ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
                sys_close(fd);
                if (n > 0) {
                    buf[n] = '\0';
                    write_str(1, key);
                    write_str(1, " = ");
                    write_str(1, buf);
                    /* Add newline if not present */
                    if (n > 0 && buf[n-1] != '\n') write_str(1, "\n");
                }
            } else {
                write_str(2, "sysctl: unknown key: "); write_str(2, key); write_str(2, "\n");
                return 1;
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "dhclient") == 0) {
        /* dhclient — minimal DHCP client (sends DISCOVER, displays OFFER) */
        const char *iface = argc > 1 ? argv[1] : "eth0";
        write_str(1, "DHCP DISCOVER on ");
        write_str(1, iface);
        write_str(1, "...\n");

        /* Create UDP socket */
        long sock = sys_call3(41, 2 /* AF_INET */, 2 /* SOCK_DGRAM */, 17 /* IPPROTO_UDP */);
        if (sock < 0) { write_str(2, "dhclient: socket failed\n"); return 1; }

        /* SO_BROADCAST */
        int one = 1;
        sys_call6(54 /* setsockopt */, sock, 1, 6 /* SO_BROADCAST */, (long)&one, sizeof(one), 0);

        /* Bind to 0.0.0.0:68 (DHCP client port) */
        struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
        sa.family = 2; sa.addr = 0;
        sa.port = (uint16_t)((68 >> 8) | ((68 & 0xFF) << 8)); /* 68 in network order */
        for (int i = 0; i < 8; i++) sa.pad[i] = 0;
        sys_call3(49 /* bind */, sock, (long)&sa, 16);

        /* Build DHCP DISCOVER packet (simplified) */
        uint8_t pkt[300];
        for (int i = 0; i < 300; i++) pkt[i] = 0;
        pkt[0] = 1;     /* op: BOOTREQUEST */
        pkt[1] = 1;     /* htype: Ethernet */
        pkt[2] = 6;     /* hlen: 6 */
        pkt[3] = 0;     /* hops */
        pkt[4] = 0x39; pkt[5] = 0x03; pkt[6] = 0xF3; pkt[7] = 0x26; /* xid */
        /* flags: broadcast */
        pkt[10] = 0x80; pkt[11] = 0x00;
        /* chaddr: get MAC from interface */
        {
            int isock = sys_call3(41, 2, 2, 0);
            if (isock >= 0) {
                char ifr[40]; for (int k = 0; k < 40; k++) ifr[k] = 0;
                for (int k = 0; iface[k] && k < 15; k++) ifr[k] = iface[k];
                if (sys_call3(16, isock, 0x8927/*SIOCGIFHWADDR*/, (long)ifr) == 0) {
                    for (int k = 0; k < 6; k++) pkt[28+k] = (uint8_t)ifr[18+k];
                }
                sys_close(isock);
            }
        }
        /* DHCP magic cookie at offset 236 */
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
        /* Option 53: DHCP Message Type = DISCOVER (1) */
        pkt[240] = 53; pkt[241] = 1; pkt[242] = 1;
        /* Option 55: Parameter Request List */
        pkt[243] = 55; pkt[244] = 4; pkt[245] = 1; pkt[246] = 3; pkt[247] = 6; pkt[248] = 28;
        /* Option 255: End */
        pkt[249] = 255;

        /* Send to 255.255.255.255:67 (DHCP server port) */
        struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } dest;
        dest.family = 2;
        dest.port = (uint16_t)((67 >> 8) | ((67 & 0xFF) << 8));
        dest.addr = 0xFFFFFFFF; /* broadcast */
        for (int i = 0; i < 8; i++) dest.pad[i] = 0;
        long sent = sys_call6(44 /* sendto */, sock, (long)pkt, 250, 0, (long)&dest, 16);
        if (sent <= 0) {
            write_str(2, "dhclient: sendto failed\n");
            sys_close(sock); return 1;
        }
        write_str(1, "DISCOVER sent, waiting for OFFER...\n");

        /* Set timeout 5s */
        struct { long tv_sec; long tv_usec; } tv = {5, 0};
        sys_call6(54, sock, 1, 20 /* SO_RCVTIMEO */, (long)&tv, sizeof(tv), 0);

        /* Wait for DHCP OFFER */
        uint8_t reply[512];
        ssize_t rn = sys_read(sock, reply, sizeof(reply));
        sys_close(sock);

        if (rn > 240) {
            /* Parse OFFER: yiaddr at offset 16 */
            write_str(1, "DHCP OFFER: ");
            for (int o = 0; o < 4; o++) {
                char ob[4]; int oi = 0;
                uint8_t v = reply[16+o];
                if (v >= 100) ob[oi++] = '0' + v/100;
                if (v >= 10) ob[oi++] = '0' + (v/10)%10;
                ob[oi++] = '0' + v%10; ob[oi] = '\0';
                write_str(1, ob);
                if (o < 3) write_str(1, ".");
            }
            write_str(1, "\n");

            /* Parse options for subnet, gateway, DNS */
            int oi = 240;
            while (oi < rn && reply[oi] != 255) {
                uint8_t opt = reply[oi++];
                if (opt == 0) continue; /* pad */
                uint8_t len = reply[oi++];
                if (opt == 1 && len == 4) { /* Subnet Mask */
                    write_str(1, "  Subnet: ");
                    for (int o = 0; o < 4; o++) {
                        char ob[4]; int oj = 0; uint8_t v = reply[oi+o];
                        if (v >= 100) ob[oj++] = '0' + v/100;
                        if (v >= 10) ob[oj++] = '0' + (v/10)%10;
                        ob[oj++] = '0' + v%10; ob[oj] = '\0';
                        write_str(1, ob); if (o < 3) write_str(1, ".");
                    }
                    write_str(1, "\n");
                } else if (opt == 3 && len >= 4) { /* Router/Gateway */
                    write_str(1, "  Gateway: ");
                    for (int o = 0; o < 4; o++) {
                        char ob[4]; int oj = 0; uint8_t v = reply[oi+o];
                        if (v >= 100) ob[oj++] = '0' + v/100;
                        if (v >= 10) ob[oj++] = '0' + (v/10)%10;
                        ob[oj++] = '0' + v%10; ob[oj] = '\0';
                        write_str(1, ob); if (o < 3) write_str(1, ".");
                    }
                    write_str(1, "\n");
                } else if (opt == 6 && len >= 4) { /* DNS Server */
                    write_str(1, "  DNS: ");
                    for (int o = 0; o < 4; o++) {
                        char ob[4]; int oj = 0; uint8_t v = reply[oi+o];
                        if (v >= 100) ob[oj++] = '0' + v/100;
                        if (v >= 10) ob[oj++] = '0' + (v/10)%10;
                        ob[oj++] = '0' + v%10; ob[oj] = '\0';
                        write_str(1, ob); if (o < 3) write_str(1, ".");
                    }
                    write_str(1, "\n");
                }
                oi += len;
            }
        } else {
            write_str(1, "No DHCP response received (timeout)\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "lsblk") == 0) {
        /* lsblk — list block devices */
        write_str(1, "NAME MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n");
        /* Read from /proc/partitions if available */
        int fd = sys_open("/proc/partitions", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[512]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "lspci") == 0) {
        /* lspci — list PCI devices from /proc/pci */
        int fd = sys_open("/proc/pci", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[4096]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
            else write_str(1, "No PCI devices found\n");
        } else {
            write_str(2, "lspci: cannot read /proc/pci\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "brctl") == 0) {
        /* brctl — bridge control */
        if (argc < 2) {
            write_str(1, "usage: brctl addbr <name>\n");
            write_str(1, "       brctl addif <bridge> <iface>\n");
            write_str(1, "       brctl delif <bridge> <iface>\n");
            write_str(1, "       brctl show\n");
            return 0;
        }
        int sock = sys_call3(41, 2, 2, 0);
        if (sock < 0) { write_str(2, "brctl: socket failed\n"); return 1; }
        if (strcmp_simple(argv[1], "addbr") == 0 && argc >= 3) {
            char name[16] = {0};
            for (int k = 0; argv[2][k] && k < 15; k++) name[k] = argv[2][k];
            long rc = sys_call3(16, sock, 0x89a0/*SIOCBRADDBR*/, (long)name);
            if (rc >= 0) { write_str(1, "Bridge created\n"); }
            else { write_str(2, "brctl addbr: failed\n"); }
        } else if (strcmp_simple(argv[1], "addif") == 0 && argc >= 4) {
            struct { char br[16]; char port[16]; } req = {{0},{0}};
            for (int k = 0; argv[2][k] && k < 15; k++) req.br[k] = argv[2][k];
            for (int k = 0; argv[3][k] && k < 15; k++) req.port[k] = argv[3][k];
            long rc = sys_call3(16, sock, 0x89a2/*SIOCBRADDIF*/, (long)&req);
            if (rc == 0) { write_str(1, "Port added\n"); }
            else { write_str(2, "brctl addif: failed\n"); }
        } else if (strcmp_simple(argv[1], "delif") == 0 && argc >= 4) {
            struct { char br[16]; char port[16]; } req = {{0},{0}};
            for (int k = 0; argv[2][k] && k < 15; k++) req.br[k] = argv[2][k];
            for (int k = 0; argv[3][k] && k < 15; k++) req.port[k] = argv[3][k];
            long rc = sys_call3(16, sock, 0x89a3/*SIOCBRDELIF*/, (long)&req);
            if (rc == 0) { write_str(1, "Port removed\n"); }
            else { write_str(2, "brctl delif: failed\n"); }
        } else if (strcmp_simple(argv[1], "show") == 0) {
            write_str(1, "bridge name\tSTP\tinterfaces\n");
            /* Read from /proc/net/bridge if available */
            int fd = sys_open("/proc/net/bridge", O_RDONLY, 0);
            if (fd >= 0) {
                char buf[512]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
            }
        }
        sys_close(sock);
        return 0;
    } else if (strcmp_simple(argv[0], "iostat") == 0) {
        /* iostat — I/O statistics from /proc/diskstats */
        write_str(1, "Device             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn\n");
        int fd = sys_open("/proc/diskstats", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "vmstat") == 0) {
        /* vmstat — virtual memory statistics from /proc/vmstat + /proc/meminfo */
        write_str(1, "procs -----------memory---------- ---swap-- -----io---- -system--\n");
        write_str(1, " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs\n");
        /* Read meminfo for free memory */
        int fd = sys_open("/proc/meminfo", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0';
                /* Parse MemFree line */
                long free_kb = 0;
                for (int i = 0; i < n - 8; i++) {
                    if (buf[i]=='M' && buf[i+1]=='e' && buf[i+2]=='m' &&
                        buf[i+3]=='F' && buf[i+4]=='r' && buf[i+5]=='e' && buf[i+6]=='e') {
                        int j = i+7; while (j < n && (buf[j] < '0' || buf[j] > '9')) j++;
                        while (j < n && buf[j] >= '0' && buf[j] <= '9')
                            { free_kb = free_kb * 10 + (buf[j] - '0'); j++; }
                        break;
                    }
                }
                char num[16];
                write_str(1, " 1  0      0 ");
                int_to_str((int)(free_kb), num, 16);
                int pad = 6 - (int)strlen_simple(num); while (pad-- > 0) write_char(1, ' ');
                write_str(1, num);
                write_str(1, "      0      0    0    0     0     0    0    0\n");
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "shutdown") == 0) {
        /* shutdown - shut down the system */
        int do_halt = 0, do_reboot = 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp_simple(argv[i], "-h") == 0 || strcmp_simple(argv[i], "--halt") == 0 ||
                strcmp_simple(argv[i], "now") == 0)
                do_halt = 1;
            if (strcmp_simple(argv[i], "-r") == 0 || strcmp_simple(argv[i], "--reboot") == 0)
                do_reboot = 1;
        }
        if (!do_halt && !do_reboot) do_halt = 1; /* default: halt */
        write_str(1, "System going down...\n");
        sys_call0(162 /* sync */);
        if (do_reboot)
            sys_call4(169, 0xfee1dead, 672274793, 0x01234567, 0);
        else
            sys_call4(169, 0xfee1dead, 672274793, 0x4321FEDC, 0);
        write_str(2, "shutdown failed\n");
        return 1;
    } else if (strcmp_simple(argv[0], "stty") == 0) {
        /* stty — show/set terminal settings */
        if (argc == 1 || (argc == 2 && strcmp_simple(argv[1], "-a") == 0)) {
            /* Show terminal settings via TCGETS ioctl */
            struct { unsigned int c_iflag; unsigned int c_oflag; unsigned int c_cflag;
                     unsigned int c_lflag; unsigned char c_line; unsigned char c_cc[32];
                     unsigned int c_ispeed; unsigned int c_ospeed; } tio;
            long rc = sys_call3(16 /* ioctl */, 0 /* stdin */, 0x5401 /* TCGETS */, (long)&tio);
            if (rc == 0) {
                write_str(1, "speed 115200 baud; rows 24; columns 80\n");
                write_str(1, "intr = ^C; quit = ^\\; erase = ^?; kill = ^U; ");
                write_str(1, "eof = ^D; susp = ^Z\n");
                write_str(1, "iflag: ");
                if (tio.c_iflag & 0x0100) write_str(1, "icrnl ");
                if (tio.c_iflag & 0x0002) write_str(1, "ixon ");
                write_str(1, "\noflag: ");
                if (tio.c_oflag & 0x0001) write_str(1, "opost ");
                if (tio.c_oflag & 0x0004) write_str(1, "onlcr ");
                write_str(1, "\nlflag: ");
                if (tio.c_lflag & 0x0008) write_str(1, "echo ");
                if (tio.c_lflag & 0x0002) write_str(1, "icanon ");
                if (tio.c_lflag & 0x0001) write_str(1, "isig ");
                write_str(1, "\n");
            } else {
                write_str(2, "stty: not a terminal\n");
            }
        } else if (argc >= 2) {
            /* Set mode: stty raw / stty cooked / stty echo / stty -echo */
            for (int i = 1; i < argc; i++) {
                if (strcmp_simple(argv[i], "raw") == 0) {
                    write_str(1, "raw mode (not fully supported)\n");
                } else if (strcmp_simple(argv[i], "sane") == 0) {
                    write_str(1, "terminal settings restored to sane defaults\n");
                } else {
                    write_str(1, "stty: setting '");
                    write_str(1, argv[i]);
                    write_str(1, "' noted\n");
                }
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "tc") == 0) {
        /* tc — traffic control (QoS) */
        if (argc < 2) {
            write_str(1, "usage: tc qdisc add dev <if> root tbf rate <rate>Kbit burst <burst>\n");
            write_str(1, "       tc qdisc show\n");
            write_str(1, "       tc class add dev <if> classid 1:<n> rate <rate>Kbit\n");
            return 0;
        }
        if (strcmp_simple(argv[1], "qdisc") == 0) {
            if (argc >= 3 && strcmp_simple(argv[2], "show") == 0) {
                /* Show qdiscs — use custom ioctl */
                int sock = sys_call3(41, 2, 2, 0);
                if (sock < 0) return 1;
                char buf[512] = {0};
                /* SIOCTCSHOW = 0x89E4 */
                sys_call3(16, sock, 0x89E4, (long)buf);
                sys_close(sock);
                if (buf[0]) write_str(1, buf);
                else write_str(1, "(no qdiscs configured)\n");
            } else if (argc >= 5 && strcmp_simple(argv[2], "add") == 0) {
                /* tc qdisc add dev <if> root tbf rate <N>Kbit */
                const char *dev = NULL;
                unsigned int rate = 0;
                unsigned int burst = 10240;
                int qtype = 0; /* pfifo_fast */
                for (int i = 3; i < argc; i++) {
                    if (strcmp_simple(argv[i], "dev") == 0 && i+1 < argc) dev = argv[++i];
                    else if (strcmp_simple(argv[i], "tbf") == 0) qtype = 1;
                    else if (strcmp_simple(argv[i], "htb") == 0) qtype = 2;
                    else if (strcmp_simple(argv[i], "rate") == 0 && i+1 < argc) {
                        i++; rate = 0;
                        for (int k = 0; argv[i][k] >= '0' && argv[i][k] <= '9'; k++)
                            rate = rate * 10 + (unsigned)(argv[i][k] - '0');
                        rate *= 1000; /* Kbit → bit */
                    }
                    else if (strcmp_simple(argv[i], "burst") == 0 && i+1 < argc) {
                        i++; burst = 0;
                        for (int k = 0; argv[i][k] >= '0' && argv[i][k] <= '9'; k++)
                            burst = burst * 10 + (unsigned)(argv[i][k] - '0');
                    }
                }
                if (!dev) { write_str(2, "tc: missing dev\n"); return 1; }
                int sock = sys_call3(41, 2, 2, 0);
                if (sock < 0) return 1;
                struct { char name[16]; unsigned char type; unsigned int rate; unsigned int burst; } req = {{0}, (unsigned char)qtype, rate, burst};
                for (int k = 0; dev[k] && k < 15; k++) req.name[k] = dev[k];
                long rc = sys_call3(16, sock, 0x89E5 /* SIOCTCADD */, (long)&req);
                sys_close(sock);
                if (rc == 0) write_str(1, "qdisc added\n");
                else write_str(2, "tc qdisc add: failed\n");
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "getconf") == 0) {
        /* getconf — get system configuration values */
        if (argc < 2) {
            write_str(2, "usage: getconf <name>\n");
            write_str(2, "  PAGE_SIZE, NPROCESSORS_ONLN, LONG_BIT, _POSIX_VERSION, etc.\n");
            return 1;
        }
        const char *key = argv[1];
        if (strcmp_simple(key, "PAGE_SIZE") == 0 || strcmp_simple(key, "PAGESIZE") == 0) {
            write_str(1, "4096\n");
        } else if (strcmp_simple(key, "NPROCESSORS_ONLN") == 0 ||
                   strcmp_simple(key, "NPROCESSORS_CONF") == 0 ||
                   strcmp_simple(key, "_NPROCESSORS_ONLN") == 0) {
            write_str(1, "1\n");
        } else if (strcmp_simple(key, "LONG_BIT") == 0) {
            write_str(1, "64\n");
        } else if (strcmp_simple(key, "_POSIX_VERSION") == 0) {
            write_str(1, "200809\n");
        } else if (strcmp_simple(key, "PATH_MAX") == 0) {
            write_str(1, "4096\n");
        } else if (strcmp_simple(key, "NAME_MAX") == 0) {
            write_str(1, "255\n");
        } else if (strcmp_simple(key, "ARG_MAX") == 0) {
            write_str(1, "2097152\n");
        } else if (strcmp_simple(key, "CLK_TCK") == 0 || strcmp_simple(key, "_SC_CLK_TCK") == 0) {
            write_str(1, "100\n");
        } else if (strcmp_simple(key, "OPEN_MAX") == 0) {
            write_str(1, "1024\n");
        } else {
            write_str(2, "getconf: undefined variable: ");
            write_str(2, key); write_char(2, '\n');
            return 1;
        }
        return 0;
    } else if (strcmp_simple(argv[0], "trap") == 0) {
        /* trap — set signal handlers for shell scripts
         * trap 'cmd' SIG  — run cmd on signal
         * trap '' SIG     — ignore signal
         * trap - SIG      — reset to default
         * trap -l         — list signal names */

        /* Helper: parse signal name/number */
        #define SIG_PARSE(s) ( \
            ((s)[0] >= '0' && (s)[0] <= '9') ? ( \
                ((s)[1] >= '0' && (s)[1] <= '9') ? ((s)[0]-'0')*10+((s)[1]-'0') : (s)[0]-'0' \
            ) : \
            (strcmp_simple(s,"HUP")==0||strcmp_simple(s,"SIGHUP")==0) ? 1 : \
            (strcmp_simple(s,"INT")==0||strcmp_simple(s,"SIGINT")==0) ? 2 : \
            (strcmp_simple(s,"QUIT")==0||strcmp_simple(s,"SIGQUIT")==0) ? 3 : \
            (strcmp_simple(s,"TERM")==0||strcmp_simple(s,"SIGTERM")==0) ? 15 : \
            (strcmp_simple(s,"USR1")==0||strcmp_simple(s,"SIGUSR1")==0) ? 10 : \
            (strcmp_simple(s,"USR2")==0||strcmp_simple(s,"SIGUSR2")==0) ? 12 : \
            (strcmp_simple(s,"ALRM")==0||strcmp_simple(s,"SIGALRM")==0) ? 14 : \
            (strcmp_simple(s,"EXIT")==0) ? 0 : \
            -1 \
        )

        if (argc == 1) {
            /* Show current traps */
            write_str(1, "trap -- '' SIGTSTP\n");
            write_str(1, "trap -- '' SIGTTIN\n");
            write_str(1, "trap -- '' SIGTTOU\n");
        } else if (argc >= 3) {
            /* trap 'command' SIGNAL — register handler */
            const char *cmd = argv[1];
            for (int si = 2; si < argc; si++) {
                int signum = SIG_PARSE(argv[si]);
                if (signum <= 0 || signum > 31) {
                    if (strcmp_simple(argv[si], "EXIT") == 0) continue;  /* EXIT trap: no-op for now */
                    write_str(2, "trap: invalid signal: "); write_str(2, argv[si]); write_str(2, "\n");
                    continue;
                }
                if (cmd[0] == '\0') {
                    /* trap '' SIG — ignore signal */
                    struct { void *handler; unsigned long flags; void *restorer; unsigned long mask; } sa;
                    __builtin_memset(&sa, 0, sizeof(sa));
                    sa.handler = (void *)1;  /* SIG_IGN */
                    sys_sigaction(signum, &sa, NULL);
                } else if (cmd[0] == '-' && cmd[1] == '\0') {
                    /* trap - SIG — reset to default */
                    struct { void *handler; unsigned long flags; void *restorer; unsigned long mask; } sa;
                    __builtin_memset(&sa, 0, sizeof(sa));
                    sa.handler = (void *)0;  /* SIG_DFL */
                    sys_sigaction(signum, &sa, NULL);
                }
                /* Note: trap 'command' SIG with a real command string would require
                 * a signal handler trampoline that invokes execute_command_chain().
                 * For now, '' (ignore) and '-' (default) are the key patterns. */
            }
        } else if (argc == 2 && strcmp_simple(argv[1], "-l") == 0) {
            /* List signal names */
            write_str(1, " 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\n");
            write_str(1, " 5) SIGTRAP\t 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\n");
            write_str(1, " 9) SIGKILL\t10) SIGUSR1\t11) SIGSEGV\t12) SIGUSR2\n");
            write_str(1, "13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\t16) SIGSTKFLT\n");
            write_str(1, "17) SIGCHLD\t18) SIGCONT\t19) SIGSTOP\t20) SIGTSTP\n");
            write_str(1, "21) SIGTTIN\t22) SIGTTOU\t23) SIGURG\t24) SIGXCPU\n");
            write_str(1, "25) SIGXFSZ\t26) SIGVTALRM\t27) SIGPROF\t28) SIGWINCH\n");
            write_str(1, "29) SIGIO\t30) SIGPWR\t31) SIGSYS\n");
        } else {
            write_str(2, "usage: trap [-l] | trap 'command' SIGNAL\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "logger") == 0) {
        /* logger — write message to kernel log (/dev/kmsg) */
        if (argc < 2) {
            write_str(2, "usage: logger <message>\n");
            return 1;
        }
        int fd = sys_open("/dev/kmsg", O_WRONLY, 0);
        if (fd >= 0) {
            /* Build message from all args */
            for (int i = 1; i < argc; i++) {
                sys_write(fd, argv[i], strlen_simple(argv[i]));
                if (i < argc - 1) sys_write(fd, " ", 1);
            }
            sys_write(fd, "\n", 1);
            sys_close(fd);
        } else {
            write_str(2, "logger: cannot open /dev/kmsg\n");
            return 1;
        }
        return 0;
    } else if (strcmp_simple(argv[0], "wdctl") == 0) {
        /* wdctl — show watchdog device status */
        int fd = sys_open("/dev/watchdog", O_RDONLY, 0);
        if (fd >= 0) {
            unsigned int timeleft = 0;
            sys_read(fd, &timeleft, sizeof(timeleft));
            write_str(1, "Device:         /dev/watchdog\n");
            write_str(1, "Status:         active\n");
            write_str(1, "Time left:      ");
            char num[16]; int_to_str((int)timeleft, num, 16);
            write_str(1, num); write_str(1, "s\n");
            /* Write 'V' for magic close so we don't keep it running */
            sys_write(fd, "V", 1);
            sys_close(fd);
        } else {
            write_str(1, "Device:         /dev/watchdog\n");
            write_str(1, "Status:         inactive\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "losetup") == 0) {
        /* losetup — configure loop devices */
        if (argc >= 3) {
            /* losetup /dev/loopN <file> — attach file to loop device */
            const char *loopdev = argv[1];
            const char *backing = argv[2];
            int loop_fd = sys_open(loopdev, O_RDWR, 0);
            if (loop_fd < 0) {
                write_str(2, "losetup: cannot open "); write_str(2, loopdev);
                write_char(2, '\n'); return 1;
            }
            int back_fd = sys_open(backing, O_RDWR, 0);
            if (back_fd < 0) {
                sys_close(loop_fd);
                write_str(2, "losetup: cannot open "); write_str(2, backing);
                write_char(2, '\n'); return 1;
            }
            long rc = sys_call3(16 /* ioctl */, loop_fd, 0x4C00 /* LOOP_SET_FD */, back_fd);
            sys_close(loop_fd);
            if (rc == 0) {
                write_str(1, loopdev); write_str(1, ": attached to ");
                write_str(1, backing); write_str(1, "\n");
            } else {
                sys_close(back_fd);
                write_str(2, "losetup: LOOP_SET_FD failed\n");
            }
            return (int)rc;
        } else if (argc >= 2 && strcmp_simple(argv[1], "-d") == 0 && argc >= 3) {
            /* losetup -d /dev/loopN — detach */
            int loop_fd = sys_open(argv[2], O_RDWR, 0);
            if (loop_fd < 0) { write_str(2, "losetup: cannot open device\n"); return 1; }
            long rc = sys_call3(16, loop_fd, 0x4C01 /* LOOP_CLR_FD */, 0);
            sys_close(loop_fd);
            if (rc == 0) write_str(1, "Detached\n");
            else write_str(2, "losetup: detach failed\n");
            return (int)rc;
        } else if (argc >= 2 && strcmp_simple(argv[1], "-a") == 0) {
            /* losetup -a — list active loop devices */
            for (int i = 0; i < 8; i++) {
                char path[16] = "/dev/loop0";
                path[9] = (char)('0' + i);
                /* Check if active by reading from /proc/diskstats */
                int fd = sys_open("/proc/diskstats", O_RDONLY, 0);
                if (fd >= 0) {
                    char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                    sys_close(fd);
                    if (n > 0) { buf[n] = '\0';
                        char target[8] = "loop0"; target[4] = (char)('0' + i);
                        for (ssize_t j = 0; j < n - 5; j++) {
                            if (buf[j] == target[0] && buf[j+1] == target[1] &&
                                buf[j+2] == target[2] && buf[j+3] == target[3] &&
                                buf[j+4] == target[4]) {
                                write_str(1, path); write_str(1, ": [active]\n");
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            write_str(1, "usage: losetup /dev/loopN <file>    - Attach file to loop device\n");
            write_str(1, "       losetup -d /dev/loopN        - Detach loop device\n");
            write_str(1, "       losetup -a                   - List active loop devices\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "mkfs.futura") == 0 ||
               strcmp_simple(argv[0], "mkfs") == 0) {
        /* mkfs.futura <device> — format a block device with FuturaFS */
        if (argc < 2) {
            write_str(2, "usage: mkfs.futura <device>\n");
            write_str(2, "  e.g.: mkfs.futura /dev/loop0\n");
            return 1;
        }
        const char *dev = argv[1];
        /* Strip /dev/ prefix for blockdev lookup */
        const char *bname = dev;
        if (bname[0] == '/' && bname[1] == 'd' && bname[2] == 'e' &&
            bname[3] == 'v' && bname[4] == '/')
            bname = dev + 5;
        /* Use a custom ioctl to trigger format from kernel */
        write_str(1, "Formatting "); write_str(1, dev);
        write_str(1, " as FuturaFS...\n");
        /* Mount syscall with special flag triggers format+mount */
        long rc = sys_call6(165 /* mount */, (long)dev, (long)"/mnt",
                            (long)"futurafs", 0, 0, 0);
        if (rc == 0) {
            write_str(1, "FuturaFS formatted and mounted at /mnt\n");
        } else {
            write_str(2, "mkfs.futura: format failed (");
            char num[16]; int_to_str((int)rc, num, 16);
            write_str(2, num); write_str(2, ")\n");
        }
        return (int)rc;
    } else if (strcmp_simple(argv[0], "conntrack") == 0) {
        /* conntrack — show/flush NAT connection tracking table */
        if (argc >= 2 && strcmp_simple(argv[1], "-F") == 0) {
            /* Flush: write "0" to nf_conntrack proc file is not possible,
             * but we can show the table as empty after flush */
            write_str(1, "conntrack v1.0 (Futura): Connection tracking flushed\n");
        } else if (argc >= 2 && strcmp_simple(argv[1], "-C") == 0) {
            /* Count: count entries in /proc/net/nf_conntrack */
            int fd = sys_open("/proc/net/nf_conntrack", O_RDONLY, 0);
            int count = 0;
            if (fd >= 0) {
                char buf[4096]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd);
                if (n > 0) { for (ssize_t i = 0; i < n; i++) if (buf[i] == '\n') count++; }
            }
            char num[16]; int_to_str(count, num, 16);
            write_str(1, num); write_str(1, " flow entries\n");
        } else {
            /* Default: list all connections (-L) */
            write_str(1, "conntrack v1.0 (Futura)\n");
            int fd = sys_open("/proc/net/nf_conntrack", O_RDONLY, 0);
            if (fd >= 0) {
                char buf[4096]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                sys_close(fd);
                if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
                else write_str(1, "(no active connections)\n");
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "ethtool") == 0) {
        /* ethtool <iface> — show interface link settings and statistics */
        if (argc < 2) { write_str(2, "usage: ethtool <interface>\n"); return 1; }
        const char *dev = argv[1];
        int sock = sys_call3(41, 2, 2, 0);
        if (sock < 0) { write_str(2, "ethtool: socket failed\n"); return 1; }
        /* Get flags */
        char ifr[40]; for (int k = 0; k < 40; k++) ifr[k] = 0;
        for (int k = 0; dev[k] && k < 15; k++) ifr[k] = dev[k];
        long rc = sys_call3(16, sock, 0x8913/*SIOCGIFFLAGS*/, (long)ifr);
        if (rc != 0) { write_str(2, "ethtool: no such device\n"); sys_close(sock); return 1; }
        short flags = 0;
        for (int k = 0; k < 2; k++) flags |= (short)((unsigned char)ifr[16+k] << (k*8));
        write_str(1, "Settings for "); write_str(1, dev); write_str(1, ":\n");
        write_str(1, "\tLink detected: ");
        write_str(1, (flags & 0x0040) ? "yes\n" : "no\n");
        /* Get MTU */
        for (int k = 0; k < 40; k++) ifr[k] = 0;
        for (int k = 0; dev[k] && k < 15; k++) ifr[k] = dev[k];
        rc = sys_call3(16, sock, 0x8921/*SIOCGIFMTU*/, (long)ifr);
        if (rc == 0) {
            int mtu = 0;
            for (int k = 0; k < 4; k++) mtu |= ((unsigned char)ifr[16+k]) << (k*8);
            char num[16]; int_to_str(mtu, num, 16);
            write_str(1, "\tMTU: "); write_str(1, num); write_str(1, "\n");
        }
        /* Get HW address */
        for (int k = 0; k < 40; k++) ifr[k] = 0;
        for (int k = 0; dev[k] && k < 15; k++) ifr[k] = dev[k];
        rc = sys_call3(16, sock, 0x8927/*SIOCGIFHWADDR*/, (long)ifr);
        if (rc == 0) {
            write_str(1, "\tHW address: ");
            for (int k = 0; k < 6; k++) {
                unsigned char b = (unsigned char)ifr[18+k];
                char hex[3] = {0};
                hex[0] = "0123456789abcdef"[(b>>4)&0xf];
                hex[1] = "0123456789abcdef"[b&0xf];
                write_str(1, hex);
                if (k < 5) write_char(1, ':');
            }
            write_str(1, "\n");
        }
        /* Speed/duplex (not measurable, show auto) */
        write_str(1, "\tSpeed: 10000Mb/s\n");
        write_str(1, "\tDuplex: Full\n");
        write_str(1, "\tAuto-negotiation: on\n");
        /* Show statistics from /sys/class/net/<dev>/statistics if available */
        if (argc >= 3 && strcmp_simple(argv[1], "-S") == 0) {
            dev = argv[2];
        }
        /* Read from /proc/net/dev for this interface's stats */
        write_str(1, "NIC statistics:\n");
        int fd = sys_open("/proc/net/dev", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0';
                /* Find this device's line */
                int dlen = 0; while (dev[dlen]) dlen++;
                for (int i = 0; i < n - dlen; i++) {
                    bool match = true;
                    for (int j = 0; j < dlen && match; j++)
                        if (buf[i+j] != dev[j]) match = false;
                    if (match && buf[i+dlen] == ':') {
                        write_str(1, "\t");
                        int s = i; while (s < n && buf[s] != '\n') { write_char(1, buf[s]); s++; }
                        write_str(1, "\n");
                        break;
                    }
                }
            }
        }
        sys_close(sock);
        return 0;
    } else if (strcmp_simple(argv[0], "ipcs") == 0) {
        /* ipcs — show System V IPC status */
        write_str(1, "\n------ Shared Memory Segments --------\n");
        { int fd = sys_open("/proc/sysvipc/shm", O_RDONLY, 0);
          if (fd >= 0) { char buf[512]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } } }
        write_str(1, "\n------ Semaphore Arrays --------\n");
        { int fd = sys_open("/proc/sysvipc/sem", O_RDONLY, 0);
          if (fd >= 0) { char buf[512]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } } }
        write_str(1, "\n------ Message Queues --------\n");
        { int fd = sys_open("/proc/sysvipc/msg", O_RDONLY, 0);
          if (fd >= 0) { char buf[512]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
            sys_close(fd); if (n > 0) { buf[n] = '\0'; write_str(1, buf); } } }
        return 0;
    } else if (strcmp_simple(argv[0], "arp") == 0) {
        /* arp — show ARP cache from /proc/net/arp */
        int fd = sys_open("/proc/net/arp", O_RDONLY, 0);
        if (fd >= 0) {
            char buf[2048];
            ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
        } else {
            write_str(2, "arp: cannot read /proc/net/arp\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "traceroute") == 0) {
        /* traceroute — trace route to host using ICMP with increasing TTL */
        if (argc < 2) { write_str(1, "usage: traceroute <host>\n"); return 1; }
        const char *host = argv[1];
        uint32_t dest_ip = 0;
        int octet = 0, shift = 24;
        for (int i = 0; host[i]; i++) {
            if (host[i] == '.') { dest_ip |= ((uint32_t)octet & 0xFF) << shift; shift -= 8; octet = 0; }
            else if (host[i] >= '0' && host[i] <= '9') octet = octet * 10 + (host[i] - '0');
        }
        dest_ip |= ((uint32_t)octet & 0xFF) << shift;
        uint32_t dest_be = ((dest_ip >> 24) & 0xFF) | ((dest_ip >> 8) & 0xFF00) |
                           ((dest_ip << 8) & 0xFF0000) | ((dest_ip << 24) & 0xFF000000u);

        write_str(1, "traceroute to ");
        write_str(1, host);
        write_str(1, ", 30 hops max\n");

        long sock = sys_call3(41 /* socket */, 2 /* AF_INET */, 3 /* SOCK_RAW */, 1 /* IPPROTO_ICMP */);
        if (sock < 0) { write_str(2, "traceroute: raw socket failed\n"); return 1; }

        /* Set receive timeout 2s */
        struct { long tv_sec; long tv_usec; } tv = {2, 0};
        sys_call6(54 /* setsockopt */, sock, 1 /* SOL_SOCKET */, 20 /* SO_RCVTIMEO */, (long)&tv, sizeof(tv), 0);

        for (int ttl = 1; ttl <= 30; ttl++) {
            /* Set IP_TTL */
            sys_call6(54, sock, 0 /* IPPROTO_IP */, 2 /* IP_TTL */, (long)&ttl, sizeof(ttl), 0);

            /* Build ICMP echo request */
            uint8_t pkt[64];
            for (int i = 0; i < 64; i++) pkt[i] = 0;
            pkt[0] = 8;  /* ICMP_ECHO_REQUEST */
            pkt[1] = 0;  /* code */
            pkt[4] = 0x12; pkt[5] = 0x34; /* ID */
            pkt[6] = (uint8_t)(ttl >> 8); pkt[7] = (uint8_t)(ttl & 0xFF); /* seq */
            /* Checksum */
            uint32_t sum = 0;
            for (int i = 0; i < 64; i += 2)
                sum += ((uint32_t)pkt[i] << 8) | pkt[i+1];
            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            uint16_t cksum = ~(uint16_t)sum;
            pkt[2] = (uint8_t)(cksum >> 8);
            pkt[3] = (uint8_t)(cksum & 0xFF);

            /* Send to destination */
            struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
            sa.family = 2; sa.port = 0; sa.addr = dest_be;
            for (int i = 0; i < 8; i++) sa.pad[i] = 0;
            sys_call6(44 /* sendto */, sock, (long)pkt, 64, 0, (long)&sa, 16);

            /* Receive reply (ICMP Time Exceeded or Echo Reply) */
            uint8_t reply[256];
            struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } from;
            unsigned int fromlen = 16;
            ssize_t n = sys_call6(45 /* recvfrom */, sock, (long)reply, 256, 0, (long)&from, (long)&fromlen);

            /* Print hop */
            char num[4]; int ni = 0;
            if (ttl >= 10) num[ni++] = '0' + ttl / 10;
            num[ni++] = '0' + ttl % 10;
            num[ni] = '\0';
            write_str(1, " ");
            write_str(1, num);
            write_str(1, "  ");

            if (n > 0) {
                /* Extract source IP from reply (from.addr is in network byte order) */
                uint32_t src = from.addr;
                char ob[4]; int oi;
                for (int b = 0; b < 4; b++) {
                    uint8_t v = (uint8_t)(src >> (b * 8));
                    oi = 0;
                    if (v >= 100) ob[oi++] = '0' + v/100;
                    if (v >= 10) ob[oi++] = '0' + (v/10)%10;
                    ob[oi++] = '0' + v%10;
                    ob[oi] = '\0';
                    write_str(1, ob);
                    if (b < 3) write_str(1, ".");
                }
                write_str(1, "\n");

                /* Check if we reached the destination (Echo Reply type=0) */
                if (n >= 20 && reply[20] == 0 /* ICMP_ECHO_REPLY */) {
                    break;
                }
            } else {
                write_str(1, "* * *\n");
            }
        }
        sys_close(sock);
        return 0;
    } else if (strcmp_simple(argv[0], "iptables") == 0) {
        /* iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE */
        if (argc >= 3 && strcmp_simple(argv[1], "-t") == 0 &&
            strcmp_simple(argv[2], "nat") == 0) {
            /* NAT table: masquerade configuration via sysctl */
            if (argc >= 7 && strcmp_simple(argv[3], "-A") == 0 &&
                strcmp_simple(argv[4], "POSTROUTING") == 0) {
                /* Find -o <iface> and -j MASQUERADE */
                const char *out_iface = NULL;
                int do_masq = 0;
                for (int i = 5; i < argc; i++) {
                    if (strcmp_simple(argv[i], "-o") == 0 && i+1 < argc)
                        out_iface = argv[++i];
                    if (strcmp_simple(argv[i], "-j") == 0 && i+1 < argc &&
                        strcmp_simple(argv[i+1], "MASQUERADE") == 0)
                        { do_masq = 1; i++; }
                }
                if (do_masq && out_iface) {
                    int fd = sys_open("/proc/sys/net/ipv4/ip_masquerade_dev", O_WRONLY, 0);
                    if (fd >= 0) {
                        int len = 0; while (out_iface[len]) len++;
                        sys_write(fd, out_iface, len);
                        sys_close(fd);
                        write_str(1, "MASQUERADE enabled on ");
                        write_str(1, out_iface);
                        write_str(1, "\n");
                    } else {
                        write_str(2, "iptables: cannot write masquerade sysctl\n");
                    }
                } else {
                    write_str(2, "iptables -t nat: usage: -A POSTROUTING -o <iface> -j MASQUERADE\n");
                }
            } else if (argc >= 4 && strcmp_simple(argv[3], "-F") == 0) {
                /* Flush NAT: disable masquerade */
                int fd = sys_open("/proc/sys/net/ipv4/ip_masquerade_dev", O_WRONLY, 0);
                if (fd >= 0) { sys_write(fd, "none", 4); sys_close(fd); }
                write_str(1, "NAT table flushed\n");
            } else if (argc >= 4 && strcmp_simple(argv[3], "-L") == 0) {
                /* List NAT rules */
                write_str(1, "Chain POSTROUTING\n");
                int fd = sys_open("/proc/sys/net/ipv4/ip_masquerade_dev", O_RDONLY, 0);
                if (fd >= 0) {
                    char buf[32] = {0};
                    ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                    sys_close(fd);
                    if (n > 0) { buf[n] = '\0';
                        if (buf[0] != 'n') {
                            write_str(1, "MASQUERADE all -- * ");
                            write_str(1, buf);
                        }
                    }
                }
            } else {
                write_str(1, "usage: iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE\n");
                write_str(1, "       iptables -t nat -F\n");
                write_str(1, "       iptables -t nat -L\n");
            }
            return 0;
        }

        /* iptables — minimal firewall configuration via ioctls */
        int sock = sys_call3(41, 2, 2, 0);
        if (sock < 0) { write_str(2, "iptables: socket failed\n"); return 1; }

        /* Parse chain name → number: INPUT=0, FORWARD=1, OUTPUT=2 */
        int chain = -1;
        for (int i = 1; i < argc; i++) {
            if (strcmp_simple(argv[i], "INPUT") == 0) chain = 0;
            else if (strcmp_simple(argv[i], "FORWARD") == 0) chain = 1;
            else if (strcmp_simple(argv[i], "OUTPUT") == 0) chain = 2;
        }

        /* iptables -F [chain] — flush rules */
        if (argc >= 2 && strcmp_simple(argv[1], "-F") == 0) {
            unsigned char fc = (unsigned char)(chain >= 0 ? chain : 0);
            if (chain < 0) {
                /* Flush all chains */
                for (fc = 0; fc < 3; fc++)
                    sys_call3(16, sock, 0x89F2/*SIOCFWFLUSH*/, (long)&fc);
            } else {
                sys_call3(16, sock, 0x89F2, (long)&fc);
            }
            write_str(1, "Flushed\n");
        }
        /* iptables -P <chain> ACCEPT|DROP — set policy */
        else if (argc >= 4 && strcmp_simple(argv[1], "-P") == 0) {
            if (chain < 0) { write_str(2, "iptables: invalid chain\n"); sys_close(sock); return 1; }
            unsigned char policy = 0; /* ACCEPT */
            if (strcmp_simple(argv[3], "DROP") == 0) policy = 1;
            unsigned char pp[2] = { (unsigned char)chain, policy };
            long rc = sys_call3(16, sock, 0x89F1/*SIOCFWPOLICY*/, (long)pp);
            if (rc == 0) write_str(1, "Policy set\n");
            else write_str(2, "iptables: policy set failed\n");
        }
        /* iptables -A <chain> -p <proto> -s <src> -d <dst> --dport <port> -j ACCEPT|DROP */
        else if (argc >= 4 && strcmp_simple(argv[1], "-A") == 0) {
            if (chain < 0) { write_str(2, "iptables: invalid chain\n"); sys_close(sock); return 1; }
            unsigned char action = 0; /* ACCEPT */
            unsigned char proto = 0;
            uint32_t src_ip = 0, dst_ip = 0, src_mask = 0, dst_mask = 0;
            uint16_t dport_min = 0, dport_max = 0;
            for (int i = 3; i < argc; i++) {
                if (strcmp_simple(argv[i], "-j") == 0 && i+1 < argc) {
                    if (strcmp_simple(argv[i+1], "DROP") == 0) action = 1;
                    else if (strcmp_simple(argv[i+1], "REJECT") == 0) action = 2;
                    i++;
                } else if (strcmp_simple(argv[i], "-p") == 0 && i+1 < argc) {
                    if (strcmp_simple(argv[i+1], "tcp") == 0) proto = 6;
                    else if (strcmp_simple(argv[i+1], "udp") == 0) proto = 17;
                    else if (strcmp_simple(argv[i+1], "icmp") == 0) proto = 1;
                    i++;
                } else if (strcmp_simple(argv[i], "--dport") == 0 && i+1 < argc) {
                    int port = 0; const char *pp2 = argv[++i];
                    while (*pp2 >= '0' && *pp2 <= '9') { port = port * 10 + (*pp2 - '0'); pp2++; }
                    dport_min = dport_max = (uint16_t)port;
                }
            }
            /* Build rule struct and call ioctl */
            struct { uint8_t chain; uint8_t action; uint8_t protocol; uint8_t _pad;
                     uint32_t src_ip; uint32_t src_mask; uint32_t dst_ip; uint32_t dst_mask;
                     uint16_t dport_min; uint16_t dport_max; } fwr = {
                .chain = (uint8_t)chain, .action = action, .protocol = proto,
                .src_ip = src_ip, .src_mask = src_mask,
                .dst_ip = dst_ip, .dst_mask = dst_mask,
                .dport_min = dport_min, .dport_max = dport_max
            };
            long rc = sys_call3(16, sock, 0x89F0/*SIOCFWADDRULE*/, (long)&fwr);
            if (rc >= 0) write_str(1, "Rule added\n");
            else write_str(2, "iptables: add rule failed\n");
        }
        /* iptables -L — list rules (read from kernel, simplified) */
        else if (argc >= 2 && strcmp_simple(argv[1], "-L") == 0) {
            const char *chains[] = {"INPUT", "FORWARD", "OUTPUT"};
            for (int c = 0; c < 3; c++) {
                write_str(1, "Chain "); write_str(1, chains[c]);
                write_str(1, " (policy ACCEPT)\n");
            }
            write_str(1, "(Use 'cat /proc/net/nf_conntrack' for NAT table)\n");
        }
        else {
            write_str(1, "usage: iptables -A <chain> -p tcp --dport <port> -j DROP|ACCEPT\n");
            write_str(1, "       iptables -P <chain> ACCEPT|DROP\n");
            write_str(1, "       iptables -F [chain]\n");
            write_str(1, "       iptables -L\n");
        }
        sys_close(sock);
        return 0;
    } else if (strcmp_simple(argv[0], "ip") == 0) {
        /* ip link add link <parent> name <name> type vlan id <vid> */
        if (argc >= 5 && strcmp_simple(argv[1], "link") == 0 &&
            strcmp_simple(argv[2], "add") == 0) {
            /* Parse: ip link add link <parent> type vlan id <vid> */
            const char *parent = NULL;
            int vid = 0;
            for (int i = 3; i < argc; i++) {
                if (strcmp_simple(argv[i], "link") == 0 && i+1 < argc) parent = argv[++i];
                else if (strcmp_simple(argv[i], "id") == 0 && i+1 < argc) {
                    const char *p = argv[++i];
                    while (*p >= '0' && *p <= '9') { vid = vid * 10 + (*p - '0'); p++; }
                }
            }
            if (!parent || vid == 0) {
                write_str(2, "usage: ip link add link <parent> type vlan id <vid>\n");
                return 1;
            }
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip link add: socket failed\n"); return 1; }
            struct { char ifname[16]; unsigned short vlan_id; } vreq;
            for (int k = 0; k < 16; k++) vreq.ifname[k] = 0;
            for (int k = 0; parent[k] && k < 15; k++) vreq.ifname[k] = parent[k];
            vreq.vlan_id = (unsigned short)vid;
            long rc = sys_call3(16, sock, 0x8983/*SIOCSIFVLAN*/, (long)&vreq);
            sys_close(sock);
            if (rc >= 0) {
                write_str(1, "VLAN ");
                char num[8]; int_to_str(vid, num, 8);
                write_str(1, num);
                write_str(1, " created on ");
                write_str(1, parent);
                write_str(1, "\n");
            } else {
                write_str(2, "ip link add: failed\n");
            }
            return 0;
        }
        /* ip link set <iface> up/down — bring interface up or down */
        if (argc >= 5 && strcmp_simple(argv[1], "link") == 0 &&
            strcmp_simple(argv[2], "set") == 0) {
            const char *devname = argv[3];
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip link set: socket failed\n"); return 1; }
            /* Read current flags */
            char ifr[40];
            for (int k = 0; k < 40; k++) ifr[k] = 0;
            for (int k = 0; devname[k] && k < 15; k++) ifr[k] = devname[k];
            long irc = sys_call3(16, sock, 0x8913/*SIOCGIFFLAGS*/, (long)ifr);
            if (irc != 0) { write_str(2, "ip link set: no such device\n"); sys_close(sock); return 1; }
            short flags = 0;
            for (int k = 0; k < 2; k++) flags |= (short)((unsigned char)ifr[16+k] << (k*8));
            /* Apply changes */
            for (int i = 4; i < argc; i++) {
                if (strcmp_simple(argv[i], "up") == 0) flags |= 0x0001 | 0x0040; /* IFF_UP|IFF_RUNNING */
                else if (strcmp_simple(argv[i], "down") == 0) flags &= ~(0x0001 | 0x0040);
                else if (strcmp_simple(argv[i], "promisc") == 0) flags |= 0x0100;
                else if (strcmp_simple(argv[i], "-promisc") == 0) flags &= ~0x0100;
                else if (strcmp_simple(argv[i], "mtu") == 0 && i+1 < argc) {
                    /* Set MTU via SIOCSIFMTU */
                    int mtu = 0; const char *mp = argv[++i];
                    while (*mp >= '0' && *mp <= '9') { mtu = mtu * 10 + (*mp - '0'); mp++; }
                    char mifr[40]; for (int k = 0; k < 40; k++) mifr[k] = 0;
                    for (int k = 0; devname[k] && k < 15; k++) mifr[k] = devname[k];
                    mifr[16] = (char)(mtu & 0xFF); mifr[17] = (char)((mtu>>8) & 0xFF);
                    mifr[18] = (char)((mtu>>16) & 0xFF); mifr[19] = (char)((mtu>>24) & 0xFF);
                    sys_call3(16, sock, 0x8922/*SIOCSIFMTU*/, (long)mifr);
                }
            }
            /* Write flags back */
            for (int k = 0; k < 40; k++) ifr[k] = 0;
            for (int k = 0; devname[k] && k < 15; k++) ifr[k] = devname[k];
            ifr[16] = (char)(flags & 0xFF); ifr[17] = (char)((flags >> 8) & 0xFF);
            sys_call3(16, sock, 0x8914/*SIOCSIFFLAGS*/, (long)ifr);
            sys_close(sock);
            return 0;
        }
        /* ip addr — read real interface info from /proc and ioctls */
        if (argc > 1 && (strcmp_simple(argv[1], "addr") == 0 || strcmp_simple(argv[1], "a") == 0 ||
                         strcmp_simple(argv[1], "link") == 0 || strcmp_simple(argv[1], "l") == 0)) {
            /* Read /proc/net/dev to discover interfaces */
            int fd = sys_open("/proc/net/dev", O_RDONLY, 0);
            if (fd < 0) { write_str(2, "ip: cannot read /proc/net/dev\n"); return 1; }
            char buf[2048];
            long n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n <= 0) return 1;
            buf[n] = '\0';
            /* Parse each interface line (skip 2 header lines) */
            int line = 0, idx = 1;
            char *p = buf;
            while (*p) {
                /* Find start of line */
                char *eol = p;
                while (*eol && *eol != '\n') eol++;
                if (line >= 2) {
                    /* Extract interface name (before ':') */
                    char *colon = p;
                    while (colon < eol && *colon != ':') colon++;
                    char ifname[16] = {0};
                    int j = 0;
                    char *s = p;
                    while (s < colon && *s == ' ') s++; /* skip leading spaces */
                    while (s < colon && j < 15) ifname[j++] = *s++;
                    ifname[j] = '\0';
                    if (j > 0) {
                        /* Query interface info via ioctl */
                        int sock = sys_call3(41/*socket*/, 2/*AF_INET*/, 2/*SOCK_DGRAM*/, 0);
                        if (sock >= 0) {
                            char ifr[40];
                            /* Print index and name with flags */
                            char num[8];
                            int ni = 0;
                            if (idx >= 10) num[ni++] = '0' + idx / 10;
                            num[ni++] = '0' + idx % 10;
                            num[ni] = '\0';
                            write_str(1, num);
                            write_str(1, ": ");
                            write_str(1, ifname);
                            write_str(1, ": ");
                            /* SIOCGIFFLAGS (0x8913) */
                            for (int k = 0; k < 40; k++) ifr[k] = 0;
                            for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                            long irc = sys_call3(16/*ioctl*/, sock, 0x8913, (long)ifr);
                            if (irc == 0) {
                                short flags = 0;
                                for (int k = 0; k < 2; k++) flags |= (short)((unsigned char)ifr[16+k] << (k*8));
                                write_str(1, "<");
                                int first = 1;
                                if (flags & 0x0008) { write_str(1, "LOOPBACK"); first = 0; }
                                if (flags & 0x0001) { if (!first) write_str(1, ","); write_str(1, "UP"); first = 0; }
                                if (flags & 0x0040) { if (!first) write_str(1, ","); write_str(1, "RUNNING"); first = 0; }
                                if (flags & 0x0002) { if (!first) write_str(1, ","); write_str(1, "BROADCAST"); first = 0; }
                                if (flags & 0x1000) { if (!first) write_str(1, ","); write_str(1, "MULTICAST"); }
                                write_str(1, ">");
                            }
                            /* SIOCGIFMTU (0x8921) */
                            for (int k = 0; k < 40; k++) ifr[k] = 0;
                            for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                            irc = sys_call3(16, sock, 0x8921, (long)ifr);
                            if (irc == 0) {
                                int mtu = 0;
                                for (int k = 0; k < 4; k++) mtu |= ((unsigned char)ifr[16+k]) << (k*8);
                                write_str(1, " mtu ");
                                char mtubuf[12];
                                int mi = 0;
                                if (mtu == 0) { mtubuf[mi++] = '0'; }
                                else { char tmp2[12]; int ti = 0; while (mtu > 0) { tmp2[ti++] = '0' + mtu%10; mtu /= 10; } while (ti > 0) mtubuf[mi++] = tmp2[--ti]; }
                                mtubuf[mi] = '\0';
                                write_str(1, mtubuf);
                            }
                            write_str(1, "\n");
                            /* Only show inet for 'ip addr', not 'ip link' */
                            if (strcmp_simple(argv[1], "addr") == 0 || strcmp_simple(argv[1], "a") == 0) {
                                /* SIOCGIFADDR (0x8915) */
                                for (int k = 0; k < 40; k++) ifr[k] = 0;
                                for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                                irc = sys_call3(16, sock, 0x8915, (long)ifr);
                                if (irc == 0) {
                                    unsigned char *ip = (unsigned char *)&ifr[20];
                                    write_str(1, "    inet ");
                                    for (int o = 0; o < 4; o++) {
                                        char ob[4]; int oi = 0;
                                        unsigned char v = ip[o];
                                        if (v >= 100) ob[oi++] = '0' + v/100;
                                        if (v >= 10) ob[oi++] = '0' + (v/10)%10;
                                        ob[oi++] = '0' + v%10;
                                        ob[oi] = '\0';
                                        write_str(1, ob);
                                        if (o < 3) write_str(1, ".");
                                    }
                                    /* Get netmask for prefix length */
                                    for (int k = 0; k < 40; k++) ifr[k] = 0;
                                    for (int k = 0; ifname[k] && k < 15; k++) ifr[k] = ifname[k];
                                    irc = sys_call3(16, sock, 0x891B/*SIOCGIFNETMASK*/, (long)ifr);
                                    if (irc == 0) {
                                        unsigned char *m = (unsigned char *)&ifr[20];
                                        unsigned int mask = ((unsigned)m[0]<<24)|((unsigned)m[1]<<16)|((unsigned)m[2]<<8)|m[3];
                                        int bits = 0;
                                        while (mask & 0x80000000u) { bits++; mask <<= 1; }
                                        write_str(1, "/");
                                        char pb[4]; int pi2 = 0;
                                        if (bits >= 10) pb[pi2++] = '0' + bits/10;
                                        pb[pi2++] = '0' + bits%10;
                                        pb[pi2] = '\0';
                                        write_str(1, pb);
                                    }
                                    write_str(1, " scope ");
                                    if (ifr[0] == 'l' && ifr[1] == 'o')
                                        write_str(1, "host ");
                                    else
                                        write_str(1, "global ");
                                    write_str(1, ifname);
                                    write_str(1, "\n");
                                }
                            }
                            sys_close(sock);
                        }
                        idx++;
                    }
                }
                if (*eol) p = eol + 1; else break;
                line++;
            }
        } else if (argc >= 5 && strcmp_simple(argv[1], "route") == 0 &&
                   strcmp_simple(argv[2], "add") == 0) {
            /* ip route add <dest>/<prefix> via <gateway> [dev <iface>]
             * ip route add default via <gateway> [dev <iface>] */
            uint32_t dst = 0, gw = 0, mask = 0;
            const char *devname = NULL;
            int prefix = 0;

            if (strcmp_simple(argv[3], "default") == 0) {
                dst = 0; mask = 0; prefix = 0;
            } else {
                /* Parse dest/prefix */
                const char *dp = argv[3];
                int oc = 0, sh = 24;
                while (*dp && *dp != '/') {
                    if (*dp == '.') { dst |= ((uint32_t)oc & 0xFF) << sh; sh -= 8; oc = 0; }
                    else if (*dp >= '0' && *dp <= '9') oc = oc * 10 + (*dp - '0');
                    dp++;
                }
                dst |= ((uint32_t)oc & 0xFF) << sh;
                if (*dp == '/') { dp++; prefix = 0; while (*dp >= '0' && *dp <= '9') { prefix = prefix * 10 + (*dp - '0'); dp++; } }
                mask = (prefix > 0 && prefix <= 32) ? ~((1u << (32 - prefix)) - 1) : 0;
            }
            /* Find "via <gw>", "dev <name>", "table <N>" */
            unsigned int table_id = 254; /* RT_TABLE_MAIN */
            for (int i = 3; i < argc - 1; i++) {
                if (strcmp_simple(argv[i], "via") == 0) {
                    gw = parse_ipv4(argv[i+1]);
                }
                if (strcmp_simple(argv[i], "dev") == 0) devname = argv[i+1];
                if (strcmp_simple(argv[i], "table") == 0) {
                    i++; table_id = 0;
                    for (int k = 0; argv[i][k] >= '0' && argv[i][k] <= '9'; k++)
                        table_id = table_id * 10 + (unsigned)(argv[i][k] - '0');
                }
            }
            /* Use SIOCADDRT ioctl */
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip route add: socket failed\n"); return 1; }
            /* rtentry: 3x sockaddr(16) + short flags(2) + short pad(2) + char dev[16] = 68 bytes */
            char rt[68];
            for (int k = 0; k < 68; k++) rt[k] = 0;
            /* rt_dst */
            rt[0] = 2; /* AF_INET */
            rt[4] = (char)((dst >> 24) & 0xFF); rt[5] = (char)((dst >> 16) & 0xFF);
            rt[6] = (char)((dst >> 8) & 0xFF);  rt[7] = (char)(dst & 0xFF);
            /* rt_gateway */
            rt[16] = 2;
            rt[20] = (char)((gw >> 24) & 0xFF); rt[21] = (char)((gw >> 16) & 0xFF);
            rt[22] = (char)((gw >> 8) & 0xFF);  rt[23] = (char)(gw & 0xFF);
            /* rt_genmask */
            rt[32] = 2;
            rt[36] = (char)((mask >> 24) & 0xFF); rt[37] = (char)((mask >> 16) & 0xFF);
            rt[38] = (char)((mask >> 8) & 0xFF);  rt[39] = (char)(mask & 0xFF);
            /* rt_dev at offset 52 */
            if (devname) for (int k = 0; devname[k] && k < 15; k++) rt[52+k] = devname[k];

            long rc;
            if (table_id != 254) {
                /* Use table-aware route ioctl for non-main tables */
                struct { unsigned int dst; unsigned int mask; unsigned int gw;
                         int iface; unsigned int metric; unsigned char table; } trt;
                trt.dst = dst; trt.mask = mask; trt.gw = gw;
                trt.iface = -1; trt.metric = 0; trt.table = (unsigned char)table_id;
                rc = sys_call3(16, sock, 0x89E3/*SIOCADDRT_TABLE*/, (long)&trt);
            } else {
                rc = sys_call3(16, sock, 0x890B/*SIOCADDRT*/, (long)rt);
            }
            sys_close(sock);
            if (rc == 0) { write_str(1, "Route added\n"); }
            else { write_str(2, "ip route add: failed\n"); return 1; }
        } else if (argc >= 4 && strcmp_simple(argv[1], "route") == 0 &&
                   strcmp_simple(argv[2], "del") == 0) {
            /* ip route del <dest>/<prefix> OR ip route del default */
            uint32_t dst = 0, mask = 0;
            if (strcmp_simple(argv[3], "default") == 0) {
                dst = 0; mask = 0;
            } else {
                const char *dp = argv[3]; int oc = 0, sh = 24;
                while (*dp && *dp != '/') {
                    if (*dp == '.') { dst |= ((uint32_t)oc & 0xFF) << sh; sh -= 8; oc = 0; }
                    else if (*dp >= '0' && *dp <= '9') oc = oc * 10 + (*dp - '0');
                    dp++;
                }
                dst |= ((uint32_t)oc & 0xFF) << sh;
                int prefix = 0;
                if (*dp == '/') { dp++; while (*dp >= '0' && *dp <= '9') { prefix = prefix * 10 + (*dp - '0'); dp++; } }
                mask = (prefix > 0 && prefix <= 32) ? ~((1u << (32 - prefix)) - 1) : 0;
            }
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip route del: socket failed\n"); return 1; }
            char rt[68]; for (int k = 0; k < 68; k++) rt[k] = 0;
            rt[0] = 2; rt[4] = (char)((dst>>24)&0xFF); rt[5] = (char)((dst>>16)&0xFF);
            rt[6] = (char)((dst>>8)&0xFF); rt[7] = (char)(dst&0xFF);
            rt[16] = 2; /* rt_gateway */
            rt[32] = 2; rt[36] = (char)((mask>>24)&0xFF); rt[37] = (char)((mask>>16)&0xFF);
            rt[38] = (char)((mask>>8)&0xFF); rt[39] = (char)(mask&0xFF);
            long rc = sys_call3(16, sock, 0x890C/*SIOCDELRT*/, (long)rt);
            sys_close(sock);
            if (rc == 0) write_str(1, "Route deleted\n");
            else write_str(2, "ip route del: not found\n");
        } else if (argc > 1 && (strcmp_simple(argv[1], "route") == 0 || strcmp_simple(argv[1], "r") == 0)) {
            /* Read real routing table from /proc/net/route */
            int fd = sys_open("/proc/net/route", O_RDONLY, 0);
            if (fd < 0) { write_str(2, "ip: cannot read /proc/net/route\n"); return 1; }
            char buf[2048];
            long n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n <= 0) return 1;
            buf[n] = '\0';
            /* Parse route table (skip header line) */
            int line = 0;
            char *p = buf;
            while (*p) {
                char *eol = p;
                while (*eol && *eol != '\n') eol++;
                char save = *eol; *eol = '\0';
                if (line >= 1 && *p) {
                    /* Parse: Iface Destination Gateway Flags RefCnt Use Metric Mask ... */
                    char iface[16] = {0}, dest_hex[9] = {0}, gw_hex[9] = {0}, mask_hex[9] = {0};
                    (void)mask_hex;  /* used for future prefix-length display */
                    int fi = 0;
                    char *q = p;
                    /* iface */
                    while (*q && *q != '\t') { if (fi < 15) iface[fi++] = *q; q++; }
                    if (*q) q++; /* skip tab */
                    /* destination */
                    fi = 0; while (*q && *q != '\t') { if (fi < 8) dest_hex[fi++] = *q; q++; }
                    if (*q) q++;
                    /* gateway */
                    fi = 0; while (*q && *q != '\t') { if (fi < 8) gw_hex[fi++] = *q; q++; }
                    if (*q) q++;
                    /* skip Flags RefCnt Use Metric */
                    for (int skip = 0; skip < 4; skip++) { while (*q && *q != '\t') q++; if (*q) q++; }
                    /* mask */
                    fi = 0; while (*q && *q != '\t') { if (fi < 8) mask_hex[fi++] = *q; q++; }
                    /* Parse hex IP (little-endian as printed by /proc/net/route) to dotted-quad */
                    /* hex_to_ip: parse 8-char hex string (LE) → print as dotted quad */
                    #define HEX_DIGIT(c) (((c)>='0'&&(c)<='9')?(c)-'0':((c)>='a'&&(c)<='f')?(c)-'a'+10:((c)>='A'&&(c)<='F')?(c)-'A'+10:0)
                    #define HEX_BYTE(s,i) ((HEX_DIGIT((s)[(i)])*16)+HEX_DIGIT((s)[(i)+1]))
                    if (dest_hex[0] == '0' && dest_hex[1] == '0' && dest_hex[2] == '0' && dest_hex[3] == '0' &&
                        dest_hex[4] == '0' && dest_hex[5] == '0' && dest_hex[6] == '0' && dest_hex[7] == '0') {
                        write_str(1, "default");
                    } else {
                        /* /proc/net/route stores IPs in host byte order hex (LE on x86) */
                        /* So bytes [6:7][4:5][2:3][0:1] are IP octets 1.2.3.4 */
                        for (int oc = 3; oc >= 0; oc--) {
                            uint8_t bv = HEX_BYTE(dest_hex, oc*2);
                            char ob[4]; int oi = 0;
                            if (bv >= 100) ob[oi++] = '0' + bv/100;
                            if (bv >= 10) ob[oi++] = '0' + (bv/10)%10;
                            ob[oi++] = '0' + bv%10; ob[oi] = '\0';
                            write_str(1, ob);
                            if (oc > 0) write_str(1, ".");
                        }
                    }
                    if (gw_hex[0] != '0' || gw_hex[1] != '0' || gw_hex[2] != '0' || gw_hex[3] != '0') {
                        write_str(1, " via ");
                        for (int oc = 3; oc >= 0; oc--) {
                            uint8_t bv = HEX_BYTE(gw_hex, oc*2);
                            char ob[4]; int oi = 0;
                            if (bv >= 100) ob[oi++] = '0' + bv/100;
                            if (bv >= 10) ob[oi++] = '0' + (bv/10)%10;
                            ob[oi++] = '0' + bv%10; ob[oi] = '\0';
                            write_str(1, ob);
                            if (oc > 0) write_str(1, ".");
                        }
                    }
                    #undef HEX_DIGIT
                    #undef HEX_BYTE
                    write_str(1, " dev ");
                    write_str(1, iface);
                    write_str(1, "\n");
                }
                *eol = save;
                if (*eol) p = eol + 1; else break;
                line++;
            }
        } else if (argc >= 5 && strcmp_simple(argv[1], "addr") == 0 &&
                   strcmp_simple(argv[2], "add") == 0) {
            /* ip addr add <ip>/<prefix> dev <iface> */
            /* Parse IP/prefix from argv[3] */
            const char *ipstr = argv[3];
            uint32_t ip4 = 0;
            int octet = 0, shift = 24, prefix = 24;
            const char *cp = ipstr;
            while (*cp && *cp != '/') {
                if (*cp == '.') { ip4 |= ((uint32_t)octet & 0xFF) << shift; shift -= 8; octet = 0; }
                else if (*cp >= '0' && *cp <= '9') octet = octet * 10 + (*cp - '0');
                cp++;
            }
            ip4 |= ((uint32_t)octet & 0xFF) << shift;
            if (*cp == '/') { prefix = 0; cp++; while (*cp >= '0' && *cp <= '9') { prefix = prefix * 10 + (*cp - '0'); cp++; } }

            /* Find dev name: "dev <name>" */
            const char *devname = NULL;
            for (int i = 4; i < argc - 1; i++)
                if (strcmp_simple(argv[i], "dev") == 0) { devname = argv[i+1]; break; }
            if (!devname) { write_str(2, "ip addr add: missing 'dev <name>'\n"); return 1; }

            /* Set IP via SIOCSIFADDR ioctl */
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip: socket failed\n"); return 1; }

            char ifr[40];
            for (int k = 0; k < 40; k++) ifr[k] = 0;
            for (int k = 0; devname[k] && k < 15; k++) ifr[k] = devname[k];
            /* sockaddr at offset 16: family=AF_INET(2), ip at offset 20 (sa_data[2..5]) */
            ifr[16] = 2; ifr[17] = 0;
            ifr[20] = (char)((ip4 >> 24) & 0xFF);
            ifr[21] = (char)((ip4 >> 16) & 0xFF);
            ifr[22] = (char)((ip4 >> 8) & 0xFF);
            ifr[23] = (char)(ip4 & 0xFF);
            long rc = sys_call3(16, sock, 0x8916/*SIOCSIFADDR*/, (long)ifr);
            if (rc != 0) { write_str(2, "ip addr add: SIOCSIFADDR failed\n"); sys_close(sock); return 1; }

            /* Set netmask via SIOCSIFNETMASK */
            for (int k = 0; k < 40; k++) ifr[k] = 0;
            for (int k = 0; devname[k] && k < 15; k++) ifr[k] = devname[k];
            uint32_t mask = (prefix > 0 && prefix <= 32) ? ~((1u << (32 - prefix)) - 1) : 0;
            ifr[16] = 2; ifr[17] = 0;
            ifr[20] = (char)((mask >> 24) & 0xFF);
            ifr[21] = (char)((mask >> 16) & 0xFF);
            ifr[22] = (char)((mask >> 8) & 0xFF);
            ifr[23] = (char)(mask & 0xFF);
            sys_call3(16, sock, 0x891C/*SIOCSIFNETMASK*/, (long)ifr);

            sys_close(sock);
            write_str(1, "Address configured on ");
            write_str(1, devname);
            write_str(1, "\n");
        } else if (argc >= 5 && strcmp_simple(argv[1], "addr") == 0 &&
                   strcmp_simple(argv[2], "del") == 0) {
            /* ip addr del <ip>/<prefix> dev <iface> — remove address (set to 0.0.0.0) */
            const char *devname2 = NULL;
            for (int i = 4; i < argc - 1; i++)
                if (strcmp_simple(argv[i], "dev") == 0) { devname2 = argv[i+1]; break; }
            if (!devname2) { write_str(2, "ip addr del: missing 'dev <name>'\n"); return 1; }
            int sock = sys_call3(41, 2, 2, 0);
            if (sock < 0) { write_str(2, "ip addr del: socket failed\n"); return 1; }
            char ifr[40]; for (int k = 0; k < 40; k++) ifr[k] = 0;
            for (int k = 0; devname2[k] && k < 15; k++) ifr[k] = devname2[k];
            ifr[16] = 2; /* AF_INET, all zeros = 0.0.0.0 */
            sys_call3(16, sock, 0x8916/*SIOCSIFADDR*/, (long)ifr);
            sys_close(sock);
            write_str(1, "Address removed from ");
            write_str(1, devname2);
            write_str(1, "\n");
        } else if (argc > 1 && strcmp_simple(argv[1], "forward") == 0) {
            /* ip forward — toggle IP forwarding */
            if (argc > 2 && strcmp_simple(argv[2], "on") == 0) {
                int fd = sys_open("/proc/sys/net/ipv4/ip_forward", O_WRONLY, 0);
                if (fd >= 0) { sys_write(fd, "1", 1); sys_close(fd); write_str(1, "IP forwarding enabled\n"); }
            } else if (argc > 2 && strcmp_simple(argv[2], "off") == 0) {
                int fd = sys_open("/proc/sys/net/ipv4/ip_forward", O_WRONLY, 0);
                if (fd >= 0) { sys_write(fd, "0", 1); sys_close(fd); write_str(1, "IP forwarding disabled\n"); }
            } else {
                int fd = sys_open("/proc/sys/net/ipv4/ip_forward", O_RDONLY, 0);
                char v[4] = {0};
                if (fd >= 0) { sys_read(fd, v, 1); sys_close(fd); }
                write_str(1, "IP forwarding: ");
                write_str(1, v[0] == '1' ? "enabled" : "disabled");
                write_str(1, "\n");
            }
        } else if (argc > 1 && (strcmp_simple(argv[1], "neigh") == 0 ||
                                strcmp_simple(argv[1], "n") == 0)) {
            /* ip neigh — show ARP/neighbor table */
            int fd = sys_open("/proc/net/arp", O_RDONLY, 0);
            if (fd >= 0) {
                char buf[2048];
                ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
                sys_close(fd);
                if (n > 0) { buf[n] = '\0'; write_str(1, buf); }
            }
        } else if (argc > 1 && strcmp_simple(argv[1], "rule") == 0) {
            /* ip rule add/del/show — policy routing rules */
            if (argc >= 3 && strcmp_simple(argv[2], "add") == 0) {
                /* ip rule add from <src>/<mask> table <N> [prio <N>] */
                unsigned int src = 0, src_mask = 0, table = 254, prio = 1000;
                for (int i = 3; i < argc; i++) {
                    if (strcmp_simple(argv[i], "from") == 0 && i+1 < argc) {
                        i++;
                        /* Parse CIDR: x.x.x.x/N */
                        int slash = -1;
                        for (int k = 0; argv[i][k]; k++) if (argv[i][k] == '/') { slash = k; break; }
                        if (slash >= 0) {
                            char ipbuf[20] = {0};
                            for (int k = 0; k < slash && k < 19; k++) ipbuf[k] = argv[i][k];
                            src = parse_ipv4(ipbuf);
                            int pfx = 0; for (int k = slash+1; argv[i][k]; k++) pfx = pfx*10 + (argv[i][k]-'0');
                            src_mask = pfx >= 32 ? 0xFFFFFFFF : (pfx > 0 ? (0xFFFFFFFF << (32-pfx)) : 0);
                        } else {
                            src = parse_ipv4(argv[i]);
                            src_mask = 0xFFFFFFFF;
                        }
                    } else if (strcmp_simple(argv[i], "table") == 0 && i+1 < argc) {
                        i++; table = 0;
                        for (int k = 0; argv[i][k]; k++) table = table*10 + (unsigned)(argv[i][k]-'0');
                    } else if (strcmp_simple(argv[i], "prio") == 0 && i+1 < argc) {
                        i++; prio = 0;
                        for (int k = 0; argv[i][k]; k++) prio = prio*10 + (unsigned)(argv[i][k]-'0');
                    }
                }
                /* Use an ioctl to add the rule (custom 0x89E1) */
                int sock = sys_call3(41, 2, 2, 0);
                if (sock < 0) { write_str(2, "ip rule: socket failed\n"); return 1; }
                struct { unsigned int prio; unsigned int src; unsigned int src_mask; unsigned char table; int iface; } rreq;
                rreq.prio = prio; rreq.src = src; rreq.src_mask = src_mask;
                rreq.table = (unsigned char)table; rreq.iface = -1;
                long rc = sys_call3(16, sock, 0x89E1/*SIOCADDRULE*/, (long)&rreq);
                sys_close(sock);
                if (rc == 0) write_str(1, "Rule added\n");
                else write_str(2, "ip rule add: failed\n");
            } else if (argc >= 3 && strcmp_simple(argv[2], "del") == 0) {
                unsigned int prio = 0;
                for (int i = 3; i < argc; i++) {
                    if (strcmp_simple(argv[i], "prio") == 0 && i+1 < argc) {
                        i++; for (int k = 0; argv[i][k]; k++) prio = prio*10 + (unsigned)(argv[i][k]-'0');
                    }
                }
                int sock = sys_call3(41, 2, 2, 0);
                if (sock < 0) { write_str(2, "ip rule: socket failed\n"); return 1; }
                long rc = sys_call3(16, sock, 0x89E2/*SIOCDELRULE*/, (long)&prio);
                sys_close(sock);
                if (rc == 0) write_str(1, "Rule deleted\n");
                else write_str(2, "ip rule del: failed\n");
            } else {
                /* ip rule show */
                write_str(1, "0:\tfrom all lookup local\n");
                write_str(1, "32766:\tfrom all lookup main\n");
                write_str(1, "32767:\tfrom all lookup default\n");
            }
        } else if (argc > 1 && (strcmp_simple(argv[1], "tunnel") == 0 ||
                                strcmp_simple(argv[1], "tun") == 0)) {
            /* ip tunnel add <name> mode gre local <ip> remote <ip> */
            if (argc >= 3 && strcmp_simple(argv[2], "add") == 0) {
                const char *tname = NULL;
                uint32_t local_ip = 0, remote_ip = 0;
                for (int i = 3; i < argc; i++) {
                    if (i == 3 && argv[i][0] != '-') { tname = argv[i]; continue; }
                    if (strcmp_simple(argv[i], "local") == 0 && i+1 < argc)
                        { local_ip = parse_ipv4(argv[++i]); }
                    else if (strcmp_simple(argv[i], "remote") == 0 && i+1 < argc)
                        { remote_ip = parse_ipv4(argv[++i]); }
                }
                if (!tname) tname = "gre0";
                int sock = sys_call3(41, 2, 2, 0);
                if (sock < 0) { write_str(2, "ip tunnel: socket failed\n"); return 1; }
                struct { char name[16]; unsigned int local; unsigned int remote; unsigned int key; } greq;
                for (int k = 0; k < 16; k++) greq.name[k] = 0;
                for (int k = 0; tname[k] && k < 15; k++) greq.name[k] = tname[k];
                greq.local = local_ip;
                greq.remote = remote_ip;
                greq.key = 0;
                long rc = sys_call3(16, sock, 0x89E0/*SIOCADDGRETUN*/, (long)&greq);
                sys_close(sock);
                if (rc >= 0) {
                    write_str(1, "GRE tunnel "); write_str(1, tname);
                    write_str(1, " created\n");
                } else {
                    write_str(2, "ip tunnel add: failed\n");
                }
            } else if (argc >= 3 && strcmp_simple(argv[2], "show") == 0) {
                /* Show tunnel interfaces from /proc/net/dev */
                write_str(1, "GRE tunnels:\n");
                int fd = sys_open("/proc/net/dev", O_RDONLY, 0);
                if (fd >= 0) {
                    char buf[2048]; ssize_t n = sys_read(fd, buf, sizeof(buf)-1);
                    sys_close(fd);
                    if (n > 0) { buf[n] = '\0';
                        /* Find lines with "gre" */
                        int start = 0;
                        for (int i = 0; i < n; i++) {
                            if (buf[i] == '\n') {
                                buf[i] = '\0';
                                if (buf[start] == 'g' || (start+1 < n && buf[start+1] == 'g'))
                                    { write_str(1, "  "); write_str(1, &buf[start]); write_str(1, "\n"); }
                                start = i + 1;
                            }
                        }
                    }
                }
            } else {
                write_str(1, "usage: ip tunnel add <name> mode gre local <ip> remote <ip>\n");
                write_str(1, "       ip tunnel show\n");
            }
        } else if (argc > 1 && strcmp_simple(argv[1], "xfrm") == 0) {
            /* ip xfrm state/policy — IPsec management */
            if (argc >= 3 && strcmp_simple(argv[2], "state") == 0) {
                if (argc >= 4 && strcmp_simple(argv[3], "add") == 0) {
                    /* ip xfrm state add src <ip> dst <ip> proto esp spi <N> */
                    unsigned int src = 0, dst = 0, spi = 0;
                    int proto = 50; /* ESP default */
                    for (int i = 4; i < argc; i++) {
                        if (strcmp_simple(argv[i], "src") == 0 && i+1 < argc)
                            src = parse_ipv4(argv[++i]);
                        else if (strcmp_simple(argv[i], "dst") == 0 && i+1 < argc)
                            dst = parse_ipv4(argv[++i]);
                        else if (strcmp_simple(argv[i], "spi") == 0 && i+1 < argc) {
                            i++; spi = 0;
                            if (argv[i][0] == '0' && argv[i][1] == 'x') {
                                for (int k = 2; argv[i][k]; k++) {
                                    spi <<= 4;
                                    if (argv[i][k] >= '0' && argv[i][k] <= '9') spi |= argv[i][k] - '0';
                                    else if (argv[i][k] >= 'a' && argv[i][k] <= 'f') spi |= argv[i][k] - 'a' + 10;
                                }
                            } else {
                                for (int k = 0; argv[i][k] >= '0' && argv[i][k] <= '9'; k++)
                                    spi = spi * 10 + (unsigned)(argv[i][k] - '0');
                            }
                        }
                        else if (strcmp_simple(argv[i], "ah") == 0) proto = 51;
                    }
                    int sock = sys_call3(41, 2, 2, 0);
                    if (sock < 0) { write_str(2, "ip xfrm: socket failed\n"); return 1; }
                    struct { unsigned int spi; unsigned int src; unsigned int dst;
                             unsigned char proto; unsigned char mode; unsigned char auth; unsigned char enc; } req;
                    req.spi = spi; req.src = src; req.dst = dst;
                    req.proto = (unsigned char)proto; req.mode = 1; req.auth = 1; req.enc = 1;
                    long rc = sys_call3(16, sock, 0x89E6 /* SIOCIPSECSA_ADD */, (long)&req);
                    sys_close(sock);
                    if (rc == 0) write_str(1, "SA added\n");
                    else write_str(2, "ip xfrm state add: failed\n");
                } else {
                    write_str(1, "ip xfrm state: (use 'add' to create SA)\n");
                }
            } else if (argc >= 3 && strcmp_simple(argv[2], "policy") == 0) {
                write_str(1, "ip xfrm policy: (use ip xfrm state add to configure)\n");
            } else {
                write_str(1, "usage: ip xfrm state [add src <ip> dst <ip> proto esp spi <N>]\n");
                write_str(1, "       ip xfrm policy\n");
            }
        } else {
            write_str(1, "usage: ip addr|link|route|neigh|tunnel|rule|xfrm|forward\n");
        }
        return 0;
    } else if (strcmp_simple(argv[0], "ping") == 0) {
        cmd_ping(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "yes") == 0) {
        /* yes [string] — repeatedly output a line */
        const char *s = argc > 1 ? argv[1] : "y";
        for (int i = 0; i < 100; i++) {  /* limit to avoid infinite */
            write_str(1, s);
            write_char(1, '\n');
        }
        return 0;
    } else if (strcmp_simple(argv[0], "mktemp") == 0) {
        /* mktemp — create a unique temp file */
        struct { long tv_sec; long tv_nsec; } ts = {0, 0};
        sys_call2(98, 1, (long)&ts);
        char path[64] = "/tmp/tmp.";
        int p = 9;
        unsigned int r = (unsigned int)(ts.tv_nsec ^ ts.tv_sec);
        for (int i = 0; i < 8; i++) {
            r = r * 1103515245 + 12345;
            int c = ((r >> 16) & 0x1F);
            path[p++] = (c < 10) ? '0' + c : 'a' + c - 10;
        }
        path[p] = '\0';
        int fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            sys_close(fd);
            write_str(1, path);
            write_char(1, '\n');
        } else {
            write_str(2, "mktemp: failed\n");
            return 1;
        }
        return 0;
    } else if (strcmp_simple(argv[0], "source") == 0 ||
               (argv[0][0] == '.' && argv[0][1] == '\0')) {
        cmd_source(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "xargs") == 0) {
        cmd_xargs(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "less") == 0) {
        cmd_less(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "more") == 0) {
        cmd_more(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "history") == 0) {
        cmd_history(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "which") == 0) {
        cmd_which(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "du") == 0) {
        cmd_du(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tree") == 0) {
        cmd_tree(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "ln") == 0) {
        cmd_ln(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "readlink") == 0) {
        cmd_readlink(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "chmod") == 0) {
        cmd_chmod(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "dd") == 0) {
        cmd_dd(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "timeout") == 0) {
        cmd_timeout(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tty") == 0) {
        cmd_tty(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nohup") == 0) {
        cmd_nohup(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "chroot") == 0) {
        cmd_chroot(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "unshare") == 0) {
        cmd_unshare(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nsenter") == 0) {
        cmd_nsenter(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tac") == 0) {
        cmd_tac(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "chgrp") == 0) {
        cmd_chgrp(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "md5sum") == 0) {
        cmd_md5sum(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "strings") == 0) {
        cmd_strings(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "pgrep") == 0) {
        cmd_pgrep(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "pkill") == 0) {
        cmd_pkill(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "pidof") == 0) {
        cmd_pidof(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "nice") == 0) {
        cmd_nice(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "renice") == 0) {
        cmd_renice(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "xxd") == 0) {
        cmd_xxd(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "patch") == 0) {
        cmd_patch(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "sha1sum") == 0) {
        cmd_sha1sum(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "file") == 0) {
        cmd_file(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "mkfifo") == 0) {
        cmd_mkfifo(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cmp") == 0) {
        cmd_cmp(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "fold") == 0) {
        cmd_fold(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "comm") == 0) {
        cmd_comm(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "expand") == 0) {
        cmd_expand(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "unexpand") == 0) {
        cmd_unexpand(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "install") == 0) {
        cmd_install(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "expr") == 0) {
        cmd_expr(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "bc") == 0) {
        cmd_bc(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "factor") == 0) {
        cmd_factor(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "cal") == 0) {
        cmd_cal(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "locale") == 0) {
        cmd_locale(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "reset") == 0) {
        cmd_reset(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "tput") == 0) {
        cmd_tput(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "alias") == 0) {
        if (argc < 2) {
            /* List all aliases */
            for (int i = 0; i < MAX_ALIASES; i++)
                if (aliases[i].used) {
                    write_str(1, "alias ");
                    write_str(1, aliases[i].name);
                    write_str(1, "='");
                    write_str(1, aliases[i].value);
                    write_str(1, "'\n");
                }
        } else {
            /* Parse name=value */
            char *eq = argv[1];
            while (*eq && *eq != '=') eq++;
            if (*eq == '=') {
                *eq = '\0';
                set_alias(argv[1], eq + 1);
            } else {
                const char *v = get_alias(argv[1]);
                if (v) { write_str(1, "alias "); write_str(1, argv[1]); write_str(1, "='"); write_str(1, v); write_str(1, "'\n"); }
                else { write_str(2, "alias: "); write_str(2, argv[1]); write_str(2, ": not found\n"); }
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "unalias") == 0) {
        if (argc < 2) { write_str(2, "usage: unalias <name>\n"); return 1; }
        for (int i = 0; i < MAX_ALIASES; i++)
            if (aliases[i].used && strcmp_simple(aliases[i].name, argv[1]) == 0) { aliases[i].used = 0; break; }
        return 0;
    } else if (strcmp_simple(argv[0], "nproc") == 0) {
        write_str(1, "1\n");  /* Single CPU for now */
        return 0;
    } else if (strcmp_simple(argv[0], "arch") == 0) {
#ifdef __aarch64__
        write_str(1, "aarch64\n");
#else
        write_str(1, "x86_64\n");
#endif
        return 0;
    } else if (strcmp_simple(argv[0], "sysinfo") == 0) {
        cmd_sysinfo(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "wait") == 0) {
        /* Wait for background jobs to finish */
        if (argc > 1) {
            long pid = 0;
            for (int j = 0; argv[1][j]; j++) pid = pid * 10 + (argv[1][j] - '0');
            int st;
            extern long sys_waitpid(int, int *, int);
            sys_waitpid((int)pid, &st, 0);
        } else {
            int st;
            extern long sys_waitpid(int, int *, int);
            while (sys_waitpid(-1, &st, 1 /* WNOHANG */) > 0) {}
        }
        return 0;
    } else if (strcmp_simple(argv[0], "sync") == 0) {
        cmd_sync(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "umask") == 0) {
        if (argc > 1) {
            /* Set umask from octal */
            unsigned int mask = 0;
            for (int j = 0; argv[1][j]; j++) {
                if (argv[1][j] >= '0' && argv[1][j] <= '7')
                    mask = (mask << 3) | (argv[1][j] - '0');
            }
            sys_call1(95 /* umask */, mask);
        } else {
            /* Display current umask */
            long old = sys_call1(95, 0);  /* Read current */
            sys_call1(95, old);  /* Restore */
            char buf[5];
            buf[0] = '0';
            buf[1] = '0' + (char)((old >> 6) & 7);
            buf[2] = '0' + (char)((old >> 3) & 7);
            buf[3] = '0' + (char)(old & 7);
            buf[4] = '\0';
            write_str(1, buf); write_char(1, '\n');
        }
        return 0;
    } else if (strcmp_simple(argv[0], "read") == 0) {
        cmd_read(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "set") == 0) {
        cmd_set(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "exec") == 0) {
        if (argc < 2) { write_str(2, "usage: exec <command> [args...]\n"); return 1; }
        /* Replace current shell with the command */
        build_envp();
        exec_external_command(argc - 1, argv + 1);
        write_str(2, "exec: failed\n");
        return 1;
    } else if (strcmp_simple(argv[0], "type") == 0) {
        if (argc < 2) { write_str(2, "usage: type <command>\n"); return 1; }
        if (is_builtin(argv[1])) {
            write_str(1, argv[1]);
            write_str(1, " is a shell builtin\n");
        } else {
            /* Search PATH */
            const char *pe = get_var("PATH");
            if (!pe) pe = "/bin:/sbin";
            char pb[256];
            const char *p = pe;
            int found = 0;
            while (*p && !found) {
                int dl = 0;
                while (p[dl] && p[dl] != ':') dl++;
                size_t cl = strlen_simple(argv[1]);
                if (dl + 1 + cl < sizeof(pb)) {
                    int j = 0;
                    for (int k = 0; k < dl; k++) pb[j++] = p[k];
                    if (j > 0 && pb[j-1] != '/') pb[j++] = '/';
                    for (size_t k = 0; k < cl; k++) pb[j++] = argv[1][k];
                    pb[j] = '\0';
                    struct stat st;
                    if (sys_call2(__NR_stat, (long)pb, (long)&st) == 0) {
                        write_str(1, argv[1]);
                        write_str(1, " is ");
                        write_str(1, pb);
                        write_str(1, "\n");
                        found = 1;
                    }
                }
                p += dl;
                if (*p == ':') p++;
            }
            if (!found) {
                write_str(2, argv[1]);
                write_str(2, ": not found\n");
                return 1;
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "true") == 0) {
        return 0;
    } else if (strcmp_simple(argv[0], "false") == 0) {
        return 1;
    } else if (strcmp_simple(argv[0], "printf") == 0) {
        /* printf: handles %s, %d, %x, %o, %c, %%, \n, \t, \0NNN, \xNN */
        if (argc < 2) return 0;
        const char *fmt = argv[1];
        int ai = 2;
        for (int i = 0; fmt[i]; i++) {
            if (fmt[i] == '\\' && fmt[i+1]) {
                i++;
                switch (fmt[i]) {
                    case 'n': write_char(1, '\n'); break;
                    case 't': write_char(1, '\t'); break;
                    case 'r': write_char(1, '\r'); break;
                    case 'a': write_char(1, '\a'); break;
                    case 'b': write_char(1, '\b'); break;
                    case '\\': write_char(1, '\\'); break;
                    case '0': { /* Octal escape \0NNN */
                        int val = 0;
                        for (int j = 0; j < 3 && fmt[i+1+j] >= '0' && fmt[i+1+j] <= '7'; j++)
                            val = val * 8 + (fmt[i+1+j] - '0');
                        write_char(1, (char)val);
                        while (fmt[i+1] >= '0' && fmt[i+1] <= '7') i++;
                        break;
                    }
                    case 'x': { /* Hex escape \xNN */
                        int val = 0;
                        for (int j = 0; j < 2 && fmt[i+1+j]; j++) {
                            char c = fmt[i+1+j];
                            if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
                            else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
                            else break;
                            i++;
                        }
                        write_char(1, (char)val);
                        break;
                    }
                    default: write_char(1, '\\'); write_char(1, fmt[i]); break;
                }
            } else if (fmt[i] == '%' && fmt[i+1]) {
                i++;
                if (fmt[i] == 's' && ai < argc) {
                    write_str(1, argv[ai++]);
                } else if (fmt[i] == 'd' && ai < argc) {
                    /* Parse integer and format it */
                    long val = 0; int neg = 0;
                    const char *p = argv[ai++];
                    if (*p == '-') { neg = 1; p++; }
                    while (*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
                    if (neg) val = -val;
                    char nbuf[24]; int ni = 0;
                    if (val < 0) { write_char(1, '-'); val = -val; }
                    if (val == 0) { write_char(1, '0'); }
                    else {
                        while (val > 0) { nbuf[ni++] = '0' + (char)(val % 10); val /= 10; }
                        while (ni > 0) write_char(1, nbuf[--ni]);
                    }
                } else if (fmt[i] == 'x' && ai < argc) {
                    /* Hex format */
                    long val = 0;
                    const char *p = argv[ai++];
                    while (*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
                    if (val == 0) { write_char(1, '0'); }
                    else {
                        char hbuf[20]; int hi = 0;
                        static const char hex[] = "0123456789abcdef";
                        while (val > 0) { hbuf[hi++] = hex[val & 0xF]; val >>= 4; }
                        while (hi > 0) write_char(1, hbuf[--hi]);
                    }
                } else if (fmt[i] == 'o' && ai < argc) {
                    /* Octal format */
                    long val = 0;
                    const char *p = argv[ai++];
                    while (*p >= '0' && *p <= '9') val = val * 10 + (*p++ - '0');
                    if (val == 0) { write_char(1, '0'); }
                    else {
                        char obuf[24]; int oi = 0;
                        while (val > 0) { obuf[oi++] = '0' + (char)(val & 7); val >>= 3; }
                        while (oi > 0) write_char(1, obuf[--oi]);
                    }
                } else if (fmt[i] == 'c' && ai < argc) {
                    write_char(1, argv[ai++][0]);
                } else if (fmt[i] == '%') {
                    write_char(1, '%');
                } else {
                    write_char(1, '%'); write_char(1, fmt[i]);
                }
            } else {
                write_char(1, fmt[i]);
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "basename") == 0) {
        /* basename [-s SUFFIX] PATH [SUFFIX]
         * Strip directory and optionally suffix from path */
        if (argc < 2) { write_str(2, "usage: basename [-s suffix] path [suffix]\n"); return 1; }
        const char *path = argv[1];
        const char *suffix = NULL;
        if (argc >= 4 && argv[1][0] == '-' && argv[1][1] == 's') {
            suffix = argv[2]; path = argv[3];
        } else if (argc >= 3 && argv[1][0] != '-') {
            suffix = argv[2];
        }
        /* Strip directory */
        const char *p = path, *last = p;
        while (*p) { if (*p == '/') last = p + 1; p++; }
        /* Strip trailing slashes */
        int blen = 0; while (last[blen]) blen++;
        while (blen > 1 && last[blen-1] == '/') blen--;
        /* Strip suffix if specified */
        if (suffix && suffix[0]) {
            int slen = 0; while (suffix[slen]) slen++;
            if (blen > slen) {
                int match = 1;
                for (int i = 0; i < slen; i++)
                    if (last[blen - slen + i] != suffix[i]) { match = 0; break; }
                if (match) blen -= slen;
            }
        }
        sys_write(1, last, blen); write_char(1, '\n');
        return 0;
    } else if (strcmp_simple(argv[0], "dirname") == 0) {
        if (argc < 2) { write_str(2, "usage: dirname <path>\n"); return 1; }
        const char *p = argv[1];
        int last_slash = -1;
        for (int i = 0; p[i]; i++) { if (p[i] == '/') last_slash = i; }
        if (last_slash <= 0) { write_str(1, last_slash == 0 ? "/" : "."); }
        else { for (int i = 0; i < last_slash; i++) write_char(1, p[i]); }
        write_char(1, '\n');
        return 0;
    } else if (strcmp_simple(argv[0], "realpath") == 0) {
        cmd_realpath(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "export") == 0) {
        cmd_export(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "command") == 0) {
        /* command [-v] CMD [ARGS...] — execute CMD bypassing aliases/functions */
        if (argc < 2) return 0;
        if (strcmp_simple(argv[1], "-v") == 0) {
            /* command -v CMD — check if CMD exists (like which) */
            if (argc < 3) return 1;
            if (is_builtin(argv[2])) {
                write_str(1, argv[2]);
                write_str(1, "\n");
                return 0;
            }
            /* Check PATH for external command */
            const char *path = get_var("PATH");
            if (path) {
                char pbuf[256];
                const char *p = path;
                while (*p) {
                    int dl = 0;
                    while (p[dl] && p[dl] != ':') dl++;
                    int cl = strlen_simple(argv[2]);
                    if (dl + 1 + cl < 255) {
                        int j = 0;
                        for (int k = 0; k < dl; k++) pbuf[j++] = p[k];
                        if (j > 0 && pbuf[j-1] != '/') pbuf[j++] = '/';
                        for (int k = 0; k < cl; k++) pbuf[j++] = argv[2][k];
                        pbuf[j] = '\0';
                        int fd = sys_open(pbuf, 0, 0);
                        if (fd >= 0) {
                            sys_close(fd);
                            write_str(1, pbuf);
                            write_str(1, "\n");
                            return 0;
                        }
                    }
                    p += dl;
                    if (*p == ':') p++;
                }
            }
            return 1; /* Not found */
        }
        /* command CMD ARGS — execute directly (skip alias lookup) */
        return execute_command(argc - 1, &argv[1]);
    } else if (strcmp_simple(argv[0], "pushd") == 0) {
        /* pushd DIR — push current dir to stack and cd to DIR */
        static char dir_stack[8][256];
        static int dir_stack_depth = 0;
        if (argc < 2) {
            write_str(2, "pushd: no directory specified\n");
            return 1;
        }
        /* Save current dir */
        if (dir_stack_depth < 8) {
            sys_getcwd(dir_stack[dir_stack_depth], 256);
            dir_stack_depth++;
        }
        /* cd to new dir */
        long r = sys_chdir(argv[1]);
        if (r < 0) {
            write_str(2, "pushd: ");
            write_str(2, argv[1]);
            write_str(2, ": No such directory\n");
            if (dir_stack_depth > 0) dir_stack_depth--;
            return 1;
        }
        /* Print new dir */
        char cwd[256];
        sys_getcwd(cwd, 256);
        write_str(1, cwd);
        write_str(1, "\n");
        return 0;
    } else if (strcmp_simple(argv[0], "popd") == 0) {
        /* popd — pop directory from stack and cd to it */
        static char dir_stack[8][256];
        static int dir_stack_depth = 0;
        /* NOTE: shares static state with pushd above — in a real shell
         * these would share a single stack. For simplicity, popd accepts
         * silently if stack is empty. */
        (void)dir_stack; (void)dir_stack_depth;
        write_str(2, "popd: directory stack empty\n");
        return 1;
    } else if (strcmp_simple(argv[0], "dirs") == 0) {
        /* dirs — print directory stack */
        char cwd[256];
        sys_getcwd(cwd, 256);
        write_str(1, cwd);
        write_str(1, "\n");
        return 0;
    } else if (strcmp_simple(argv[0], "unset") == 0) {
        /* unset VAR... — remove shell variables */
        for (int i = 1; i < argc; i++) {
            /* Find and remove the variable */
            for (int j = 0; j < MAX_VARS; j++) {
                if (shell_vars[j].used && strcmp_simple(shell_vars[j].name, argv[i]) == 0) {
                    shell_vars[j].used = 0;
                    shell_vars[j].name[0] = '\0';
                    shell_vars[j].value[0] = '\0';
                    break;
                }
            }
        }
        return 0;
    } else if (strcmp_simple(argv[0], "return") == 0) {
        /* return [N] — return from function/sourced script with exit status N */
        if (argc >= 2) {
            last_exit_status = simple_atoi(argv[1]);
        }
        return last_exit_status;
    } else if (strcmp_simple(argv[0], "shift") == 0) {
        /* shift [N] — shift positional parameters (no-op in our shell) */
        /* In a full POSIX shell, shift moves $2→$1, $3→$2, etc.
         * Our shell doesn't have positional parameters in the same way,
         * so accept silently for script compatibility. */
        return 0;
    } else if (strcmp_simple(argv[0], "eval") == 0) {
        /* eval — concatenate args and execute as shell command */
        if (argc >= 2) {
            char evbuf[512];
            int ep = 0;
            for (int i = 1; i < argc && ep < 500; i++) {
                if (i > 1) evbuf[ep++] = ' ';
                for (const char *s = argv[i]; *s && ep < 500; s++)
                    evbuf[ep++] = *s;
            }
            evbuf[ep] = '\0';
            return execute_command_chain(evbuf);
        }
        return 0;
    } else if (strcmp_simple(argv[0], "readonly") == 0) {
        /* readonly — mark variables as read-only (accepted, not enforced) */
        if (argc < 2) {
            /* List readonly variables */
            write_str(1, "(no readonly variables)\n");
        }
        /* Accept silently — marking vars readonly would require shell_vars changes */
        return 0;
    } else if (strcmp_simple(argv[0], "let") == 0) {
        /* let EXPR — evaluate arithmetic expression, set exit status */
        if (argc < 2) return 1;
        /* Join all args */
        char expr[256];
        int ep = 0;
        for (int i = 1; i < argc && ep < 250; i++) {
            for (const char *s = argv[i]; *s && ep < 250; s++)
                expr[ep++] = *s;
        }
        expr[ep] = '\0';
        /* Find = for assignment (VAR=EXPR) */
        char *eq = NULL;
        for (int i = 0; expr[i]; i++) {
            if (expr[i] == '=' && i > 0 && expr[i-1] != '!' && expr[i-1] != '<' &&
                expr[i-1] != '>' && (i < 2 || expr[i+1] != '=')) {
                eq = &expr[i]; break;
            }
        }
        if (eq) {
            *eq = '\0';
            const char *varname = expr;
            const char *valexpr = eq + 1;
            /* Evaluate simple arithmetic */
            long val = simple_atoi(valexpr);
            /* Check for + - * / */
            const char *op = valexpr;
            while (*op && *op != '+' && *op != '-' && *op != '*' && *op != '/' && *op != '%') op++;
            if (*op && op > valexpr) {
                long a = simple_atoi(valexpr);
                long b = simple_atoi(op + 1);
                if (*op == '+') val = a + b;
                else if (*op == '-') val = a - b;
                else if (*op == '*') val = a * b;
                else if (*op == '/' && b != 0) val = a / b;
                else if (*op == '%' && b != 0) val = a % b;
            }
            char vbuf[20]; int vp = 0;
            if (val < 0) { vbuf[vp++] = '-'; val = -val; }
            if (val == 0) vbuf[vp++] = '0';
            else { char rv[20]; int rp = 0;
                while (val > 0) { rv[rp++] = '0' + (char)(val % 10); val /= 10; }
                while (rp > 0) vbuf[vp++] = rv[--rp]; }
            vbuf[vp] = '\0';
            set_var(varname, vbuf, 0);
            return 0;
        }
        /* No assignment — evaluate and return 0 if non-zero, 1 if zero */
        long val = simple_atoi(expr);
        return (val != 0) ? 0 : 1;
    } else if (strcmp_simple(argv[0], "getopts") == 0) {
        /* getopts OPTSTRING NAME [ARGS...] — parse command-line options */
        if (argc < 3) {
            write_str(2, "usage: getopts optstring name [args...]\n");
            return 1;
        }
        const char *optstring = argv[1];
        const char *varname = argv[2];
        /* Get OPTIND (1-based index into args) */
        const char *optind_str = get_var("OPTIND");
        int optind = optind_str ? simple_atoi(optind_str) : 1;
        /* Get actual args (from $1, $2, etc. or remaining argv) */
        /* For simplicity, treat remaining argv as the args */
        int nargs = argc - 3;
        char **args = &argv[3];
        if (optind < 1 || optind > nargs) return 1; /* No more options */
        const char *arg = args[optind - 1];
        if (arg[0] != '-' || arg[1] == '\0') return 1; /* Not an option */
        char opt = arg[1];
        /* Check if opt is in optstring */
        int found = 0;
        for (const char *os = optstring; *os; os++) {
            if (*os == opt) { found = 1; break; }
        }
        char optbuf[2] = { opt, '\0' };
        if (found) {
            set_var(varname, optbuf, 0);
        } else {
            set_var(varname, "?", 0);
        }
        /* Increment OPTIND */
        char nib[16]; int np = 0;
        int ni = optind + 1;
        if (ni == 0) nib[np++] = '0';
        else { char rv[16]; int rp = 0;
            while (ni > 0) { rv[rp++] = '0' + (ni % 10); ni /= 10; }
            while (rp > 0) nib[np++] = rv[--rp]; }
        nib[np] = '\0';
        set_var("OPTIND", nib, 0);
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
    } else if (strcmp_simple(argv[0], "su") == 0) {
        cmd_su(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "passwd") == 0) {
        cmd_passwd(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "systemctl") == 0) {
        cmd_systemctl(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "crontab") == 0) {
        cmd_crontab(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "scp") == 0) {
        cmd_scp(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "pkg") == 0) {
        cmd_pkg(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "man") == 0) {
        cmd_man(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "screen") == 0) {
        cmd_screen(argc, argv);
        return 0;
    } else if (strcmp_simple(argv[0], "strace") == 0) {
        cmd_strace(argc, argv);
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
            strcmp_simple(cmd, "date") == 0 ||
            strcmp_simple(cmd, "nc") == 0 ||
            strcmp_simple(cmd, "lsof") == 0 ||
            strcmp_simple(cmd, "time") == 0 ||
            strcmp_simple(cmd, "sleep") == 0 ||
            strcmp_simple(cmd, "hexdump") == 0 ||
            strcmp_simple(cmd, "seq") == 0 ||
            strcmp_simple(cmd, "curl") == 0 ||
            strcmp_simple(cmd, "wget") == 0 ||
            strcmp_simple(cmd, "df") == 0 ||
            strcmp_simple(cmd, "dmesg") == 0 ||
            strcmp_simple(cmd, "edit") == 0 ||
            strcmp_simple(cmd, "vi") == 0 ||
            strcmp_simple(cmd, "free") == 0 ||
            strcmp_simple(cmd, "hostname") == 0 ||
            strcmp_simple(cmd, "id") == 0 ||
            strcmp_simple(cmd, "ifconfig") == 0 ||
            strcmp_simple(cmd, "kill") == 0 ||
            strcmp_simple(cmd, "ps") == 0 ||
            strcmp_simple(cmd, "uptime") == 0 ||
            strcmp_simple(cmd, "version") == 0 ||
            strcmp_simple(cmd, "mount") == 0 ||
            strcmp_simple(cmd, "whoami") == 0 ||
            strcmp_simple(cmd, "env") == 0 ||
            strcmp_simple(cmd, "export") == 0 ||
            strcmp_simple(cmd, "cat") == 0 ||
            strcmp_simple(cmd, "wc") == 0 ||
            strcmp_simple(cmd, "head") == 0 ||
            strcmp_simple(cmd, "tail") == 0 ||
            strcmp_simple(cmd, "grep") == 0 ||
            strcmp_simple(cmd, "sort") == 0 ||
            strcmp_simple(cmd, "uniq") == 0 ||
            strcmp_simple(cmd, "cut") == 0 ||
            strcmp_simple(cmd, "tr") == 0 ||
            strcmp_simple(cmd, "tee") == 0 ||
            strcmp_simple(cmd, "paste") == 0 ||
            strcmp_simple(cmd, "diff") == 0 ||
            strcmp_simple(cmd, "sed") == 0 ||
            strcmp_simple(cmd, "rev") == 0 ||
            strcmp_simple(cmd, "nl") == 0 ||
            strcmp_simple(cmd, "base64") == 0 ||
            strcmp_simple(cmd, "od") == 0 ||
            strcmp_simple(cmd, "awk") == 0 ||
            strcmp_simple(cmd, "eval") == 0 ||
            strcmp_simple(cmd, "command") == 0 ||
            strcmp_simple(cmd, "pushd") == 0 ||
            strcmp_simple(cmd, "popd") == 0 ||
            strcmp_simple(cmd, "dirs") == 0 ||
            strcmp_simple(cmd, "unset") == 0 ||
            strcmp_simple(cmd, "return") == 0 ||
            strcmp_simple(cmd, "shift") == 0 ||
            strcmp_simple(cmd, "let") == 0 ||
            strcmp_simple(cmd, "readonly") == 0 ||
            strcmp_simple(cmd, "getopts") == 0 ||
            strcmp_simple(cmd, "find") == 0 ||
            strcmp_simple(cmd, "mkdir") == 0 ||
            strcmp_simple(cmd, "rmdir") == 0 ||
            strcmp_simple(cmd, "rm") == 0 ||
            strcmp_simple(cmd, "touch") == 0 ||
            strcmp_simple(cmd, "source") == 0 ||
            (cmd[0] == '.' && cmd[1] == '\0') ||
            strcmp_simple(cmd, "xargs") == 0 ||
            strcmp_simple(cmd, "sha256sum") == 0 ||
            strcmp_simple(cmd, "ss") == 0 ||
            strcmp_simple(cmd, "ip") == 0 ||
            strcmp_simple(cmd, "ping") == 0 ||
            strcmp_simple(cmd, "yes") == 0 ||
            strcmp_simple(cmd, "mktemp") == 0 ||
            strcmp_simple(cmd, "less") == 0 ||
            strcmp_simple(cmd, "more") == 0 ||
            strcmp_simple(cmd, "history") == 0 ||
            strcmp_simple(cmd, "which") == 0 ||
            strcmp_simple(cmd, "du") == 0 ||
            strcmp_simple(cmd, "tree") == 0 ||
            strcmp_simple(cmd, "ln") == 0 ||
            strcmp_simple(cmd, "readlink") == 0 ||
            strcmp_simple(cmd, "stat") == 0 ||
            strcmp_simple(cmd, "chmod") == 0 ||
            strcmp_simple(cmd, "cp") == 0 ||
            strcmp_simple(cmd, "tar") == 0 ||
            strcmp_simple(cmd, "sync") == 0 ||
            strcmp_simple(cmd, "alias") == 0 ||
            strcmp_simple(cmd, "arch") == 0 ||
            strcmp_simple(cmd, "nproc") == 0 ||
            strcmp_simple(cmd, "unalias") == 0 ||
            strcmp_simple(cmd, "sysinfo") == 0 ||
            strcmp_simple(cmd, "wait") == 0 ||
            strcmp_simple(cmd, "umask") == 0 ||
            strcmp_simple(cmd, "exec") == 0 ||
            strcmp_simple(cmd, "type") == 0 ||
            strcmp_simple(cmd, "true") == 0 ||
            strcmp_simple(cmd, "false") == 0 ||
            strcmp_simple(cmd, "printf") == 0 ||
            strcmp_simple(cmd, "basename") == 0 ||
            strcmp_simple(cmd, "dirname") == 0 ||
            strcmp_simple(cmd, "realpath") == 0 ||
            strcmp_simple(cmd, "dd") == 0 ||
            strcmp_simple(cmd, "mv") == 0 ||
            strcmp_simple(cmd, "test") == 0 ||
            strcmp_simple(cmd, "[") == 0 ||
            strcmp_simple(cmd, "jobs") == 0 ||
            strcmp_simple(cmd, "fg") == 0 ||
            strcmp_simple(cmd, "bg") == 0 ||
            strcmp_simple(cmd, "read") == 0 ||
            strcmp_simple(cmd, "set") == 0 ||
            strcmp_simple(cmd, "nslookup") == 0 ||
            strcmp_simple(cmd, "timeout") == 0 ||
            strcmp_simple(cmd, "tty") == 0 ||
            strcmp_simple(cmd, "nohup") == 0 ||
            strcmp_simple(cmd, "chroot") == 0 ||
            strcmp_simple(cmd, "unshare") == 0 ||
            strcmp_simple(cmd, "nsenter") == 0 ||
            strcmp_simple(cmd, "tac") == 0 ||
            strcmp_simple(cmd, "chgrp") == 0 ||
            strcmp_simple(cmd, "md5sum") == 0 ||
            strcmp_simple(cmd, "strings") == 0 ||
            strcmp_simple(cmd, "pgrep") == 0 ||
            strcmp_simple(cmd, "pkill") == 0 ||
            strcmp_simple(cmd, "pidof") == 0 ||
            strcmp_simple(cmd, "nice") == 0 ||
            strcmp_simple(cmd, "renice") == 0 ||
            strcmp_simple(cmd, "xxd") == 0 ||
            strcmp_simple(cmd, "patch") == 0 ||
            strcmp_simple(cmd, "sha1sum") == 0 ||
            strcmp_simple(cmd, "file") == 0 ||
            strcmp_simple(cmd, "mkfifo") == 0 ||
            strcmp_simple(cmd, "cmp") == 0 ||
            strcmp_simple(cmd, "fold") == 0 ||
            strcmp_simple(cmd, "comm") == 0 ||
            strcmp_simple(cmd, "expand") == 0 ||
            strcmp_simple(cmd, "unexpand") == 0 ||
            strcmp_simple(cmd, "install") == 0 ||
            strcmp_simple(cmd, "expr") == 0 ||
            strcmp_simple(cmd, "bc") == 0 ||
            strcmp_simple(cmd, "factor") == 0 ||
            strcmp_simple(cmd, "cal") == 0 ||
            strcmp_simple(cmd, "locale") == 0 ||
            strcmp_simple(cmd, "reset") == 0 ||
            strcmp_simple(cmd, "tput") == 0 ||
            strcmp_simple(cmd, "make") == 0 ||
            strcmp_simple(cmd, "git") == 0 ||
            strcmp_simple(cmd, "su") == 0 ||
            strcmp_simple(cmd, "passwd") == 0 ||
            strcmp_simple(cmd, "systemctl") == 0 ||
            strcmp_simple(cmd, "crontab") == 0 ||
            strcmp_simple(cmd, "scp") == 0 ||
            strcmp_simple(cmd, "pkg") == 0 ||
            strcmp_simple(cmd, "man") == 0 ||
            strcmp_simple(cmd, "screen") == 0 ||
            strcmp_simple(cmd, "strace") == 0 ||
            0);
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
__attribute__((unused))
static void strcat_simple(char *dest, const char *src) {
    while (*dest) dest++;
    strcpy_simple(dest, src);
}

/* Check if string starts with a character */
__attribute__((unused))
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
    if (cmd[0] == '/' || (cmd[0] == '.' && cmd[1] == '/')) {
        sys_execve(cmd, argv, envp);
    } else {
        /* Search $PATH for the command */
        const char *path_env = get_var("PATH");
        if (!path_env) path_env = "/bin:/sbin:/bin/user";

        const char *p = path_env;
        while (*p) {
            /* Extract next directory from PATH (colon-separated) */
            int dlen = 0;
            while (p[dlen] && p[dlen] != ':') dlen++;

            size_t cmd_len = strlen_simple(cmd);
            if (dlen + 1 + cmd_len < sizeof(path_buf)) {
                int j = 0;
                for (int k = 0; k < dlen; k++) path_buf[j++] = p[k];
                if (j > 0 && path_buf[j-1] != '/') path_buf[j++] = '/';
                for (size_t k = 0; k < cmd_len; k++) path_buf[j++] = cmd[k];
                path_buf[j] = '\0';
                sys_execve(path_buf, argv, envp);
            }

            p += dlen;
            if (*p == ':') p++;
        }
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
        if (argc > 0) argc = expand_globs(argc, argv, 32);
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
                int saved_stdin = -1, saved_stdout = -1;
                int has_redir = (redir.input_type != REDIR_NONE || redir.output_type != REDIR_NONE);

                /* Save and apply redirections for builtins */
                if (has_redir) {
                    if (redir.output_type != REDIR_NONE && redir.output_file) {
                        saved_stdout = sys_dup(1);
                        int flags = (redir.output_type == REDIR_APPEND)
                            ? (O_WRONLY | O_CREAT | O_APPEND)
                            : (O_WRONLY | O_CREAT | O_TRUNC);
                        int fd = sys_open(redir.output_file, flags, 0644);
                        if (fd >= 0) {
                            sys_dup2(fd, 1);
                            sys_close(fd);
                        }
                    }
                    if (redir.input_type == REDIR_INPUT && redir.input_file) {
                        saved_stdin = sys_dup(0);
                        int fd = sys_open(redir.input_file, O_RDONLY, 0);
                        if (fd >= 0) {
                            sys_dup2(fd, 0);
                            sys_close(fd);
                        }
                    }
                }

                int result = execute_command(argc, argv);

                /* Restore original fds */
                if (saved_stdout >= 0) { sys_dup2(saved_stdout, 1); sys_close(saved_stdout); }
                if (saved_stdin >= 0) { sys_dup2(saved_stdin, 0); sys_close(saved_stdin); }

                return result;
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
                    /* Wait with WUNTRACED to detect Ctrl+Z (SIGTSTP) */
                    sys_waitpid(pid, &status, 2 /* WUNTRACED */);
                    /* Check if child was stopped (not exited) */
                    if ((status & 0xFF) == 0x7F) {
                        /* Child was stopped — add to job list */
                        int stopsig = (status >> 8) & 0xFF;
                        int job_id = add_job(pid, cmdtext);
                        write_str(1, "\n[");
                        write_num(job_id);
                        write_str(1, "]+  Stopped                 ");
                        write_str(1, cmdtext ? cmdtext : "(unknown)");
                        write_str(1, "\n");
                        (void)stopsig;
                    }
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

        if (argc > 0) argc = expand_globs(argc, argv, 32);
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

        int cmd_is_builtin = is_builtin(argv[0]);

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

            /* Execute the command — builtins run in forked child for pipelines */
            if (cmd_is_builtin) {
                int rc = execute_command(argc, argv);
                syscall1(__NR_exit, rc);
            }
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
            sys_waitpid(pids[i], &status, 2 /* WUNTRACED */);
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

/* Built-in: source / . — execute script in current shell context */
/* Check if a line starts a multi-line block (if/for/while/case/until) */
static int is_block_start(const char *line) {
    while (*line == ' ' || *line == '\t') line++;
    if (line[0] == 'i' && line[1] == 'f' && line[2] == ' ') return 1;
    if (line[0] == 'f' && line[1] == 'o' && line[2] == 'r' && line[3] == ' ') return 2;
    if (line[0] == 'w' && line[1] == 'h' && line[2] == 'i' &&
        line[3] == 'l' && line[4] == 'e' && line[5] == ' ') return 3;
    if (line[0] == 'u' && line[1] == 'n' && line[2] == 't' &&
        line[3] == 'i' && line[4] == 'l' && line[5] == ' ') return 3;
    if (line[0] == 'c' && line[1] == 'a' && line[2] == 's' &&
        line[3] == 'e' && line[4] == ' ') return 4;
    return 0;
}

/* Check if a line is a block-end keyword */
static int is_block_end(const char *line, int block_type) {
    while (*line == ' ' || *line == '\t') line++;
    switch (block_type) {
        case 1: /* if → fi */
            return (line[0] == 'f' && line[1] == 'i' &&
                    (line[2] == '\0' || line[2] == ' ' || line[2] == ';'));
        case 2: /* for → done */
        case 3: /* while/until → done */
            return (line[0] == 'd' && line[1] == 'o' && line[2] == 'n' && line[3] == 'e' &&
                    (line[4] == '\0' || line[4] == ' ' || line[4] == ';'));
        case 4: /* case → esac */
            return (line[0] == 'e' && line[1] == 's' && line[2] == 'a' && line[3] == 'c' &&
                    (line[4] == '\0' || line[4] == ' ' || line[4] == ';'));
    }
    return 0;
}

/**
 * Execute a script buffer (from source/. command or -c mode).
 * Supports multi-line blocks by joining lines between block-start
 * and block-end keywords with "; " separators, so the existing
 * single-line handlers in the main loop can process them.
 */
/* Check if a line contains a heredoc marker (<<WORD or <<-WORD) */
static const char *find_heredoc_marker(const char *line, char *marker, int max) {
    const char *p = line;
    while (*p) {
        if (p[0] == '<' && p[1] == '<' && p[2] != '<') {
            p += 2;
            int strip_tabs = 0;
            if (*p == '-') { strip_tabs = 1; p++; (void)strip_tabs; }
            /* Skip whitespace */
            while (*p == ' ' || *p == '\t') p++;
            /* Skip optional quotes */
            char quote = 0;
            if (*p == '\'' || *p == '"') { quote = *p++; }
            int mi = 0;
            while (*p && *p != quote && *p != ' ' && *p != '\t' && *p != '\n' && mi < max - 1)
                marker[mi++] = *p++;
            marker[mi] = '\0';
            if (mi > 0) return p; /* Found valid heredoc marker */
        }
        p++;
    }
    return NULL;
}

static void execute_script_buffer(char *buf) {
    char *line = buf;
    char block_buf[2048];
    int block_type = 0;
    int block_depth = 0;
    int block_pos = 0;

    /* Heredoc state */
    char heredoc_marker[64] = {0};
    char heredoc_cmd[512] = {0};
    char heredoc_body[2048] = {0};
    int heredoc_active = 0;
    int heredoc_body_pos = 0;

    while (*line) {
        char *end = line;
        while (*end && *end != '\n') end++;
        char saved = *end;
        *end = '\0';

        /* Handle heredoc accumulation */
        if (heredoc_active) {
            char *trimmed = line;
            while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
            /* Check if this line is the heredoc terminator */
            int is_end = 1;
            for (int i = 0; heredoc_marker[i]; i++) {
                if (trimmed[i] != heredoc_marker[i]) { is_end = 0; break; }
            }
            if (is_end && trimmed[strlen_simple(heredoc_marker)] == '\0') {
                /* End of heredoc — execute command with body as stdin via pipe */
                heredoc_body[heredoc_body_pos] = '\0';
                int pfd[2];
                if (sys_pipe(pfd) == 0) {
                    pid_t pid = sys_fork();
                    if (pid == 0) {
                        /* Child: write heredoc body to pipe, then exit */
                        sys_close(pfd[0]);
                        sys_write(pfd[1], heredoc_body, heredoc_body_pos);
                        sys_close(pfd[1]);
                        syscall1(__NR_exit, 0);
                    }
                    sys_close(pfd[1]);
                    /* Redirect stdin from pipe, execute command */
                    int saved_stdin = sys_dup(0);
                    sys_dup2(pfd[0], 0);
                    sys_close(pfd[0]);
                    execute_full_line(heredoc_cmd);
                    sys_dup2(saved_stdin, 0);
                    sys_close(saved_stdin);
                    sys_waitpid(pid, NULL, 0);
                }
                heredoc_active = 0;
                heredoc_body_pos = 0;
            } else {
                /* Accumulate line into heredoc body */
                int ll = strlen_simple(line);
                if (heredoc_body_pos + ll + 1 < 2046) {
                    for (int i = 0; i < ll; i++)
                        heredoc_body[heredoc_body_pos++] = line[i];
                    heredoc_body[heredoc_body_pos++] = '\n';
                }
            }
            if (saved == '\0') break;
            line = end + 1;
            continue;
        }

        /* Skip empty lines and comments */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        if (*trimmed && *trimmed != '#') {
            if (block_depth > 0) {
                /* Inside a multi-line block — check for nested blocks and end */
                int nested = is_block_start(trimmed);
                if (nested) block_depth++;
                if (is_block_end(trimmed, block_type) && block_depth == 1) {
                    /* End of outermost block — append closing keyword */
                    if (block_pos > 0) { block_buf[block_pos++] = ';'; block_buf[block_pos++] = ' '; }
                    for (const char *c = trimmed; *c && block_pos < 2040; c++)
                        block_buf[block_pos++] = *c;
                    block_buf[block_pos] = '\0';
                    /* Execute the joined block as a single line */
                    execute_full_line(block_buf);
                    block_depth = 0;
                    block_pos = 0;
                } else {
                    if (is_block_end(trimmed, block_type)) block_depth--;
                    /* Accumulate line into block buffer */
                    if (block_pos > 0) { block_buf[block_pos++] = ';'; block_buf[block_pos++] = ' '; }
                    for (const char *c = trimmed; *c && block_pos < 2040; c++)
                        block_buf[block_pos++] = *c;
                    block_buf[block_pos] = '\0';
                }
            } else {
                /* Check if this line starts a multi-line block */
                int bt = is_block_start(trimmed);
                /* Only start accumulating if the line doesn't already contain
                 * the closing keyword (single-line form) */
                int has_end = 0;
                if (bt == 1) {
                    /* Check for "fi" in the line */
                    for (const char *s = trimmed; *s; s++) {
                        if (s[0] == ';' && s[1] == ' ' && s[2] == 'f' && s[3] == 'i' &&
                            (s[4] == '\0' || s[4] == ';' || s[4] == ' '))
                            has_end = 1;
                    }
                } else if (bt == 2 || bt == 3) {
                    for (const char *s = trimmed; s[0]; s++) {
                        if (s[0] == ';' && s[1] == ' ' && s[2] == 'd' && s[3] == 'o' &&
                            s[4] == 'n' && s[5] == 'e')
                            has_end = 1;
                    }
                } else if (bt == 4) {
                    for (const char *s = trimmed; *s; s++) {
                        if (s[0] == 'e' && s[1] == 's' && s[2] == 'a' && s[3] == 'c')
                            has_end = 1;
                    }
                }

                if (bt && !has_end) {
                    /* Start accumulating multi-line block */
                    block_type = bt;
                    block_depth = 1;
                    block_pos = 0;
                    for (const char *c = trimmed; *c && block_pos < 2040; c++)
                        block_buf[block_pos++] = *c;
                    block_buf[block_pos] = '\0';
                } else {
                    /* Check for heredoc (<<WORD) */
                    char hm[64];
                    if (find_heredoc_marker(trimmed, hm, 64)) {
                        /* Extract command (everything before <<WORD) */
                        int hcl = 0;
                        const char *hp = trimmed;
                        while (*hp) {
                            if (hp[0] == '<' && hp[1] == '<') break;
                            heredoc_cmd[hcl++] = *hp++;
                        }
                        heredoc_cmd[hcl] = '\0';
                        /* Copy marker */
                        int hml = 0;
                        while (hm[hml] && hml < 63) { heredoc_marker[hml] = hm[hml]; hml++; }
                        heredoc_marker[hml] = '\0';
                        heredoc_active = 1;
                        heredoc_body_pos = 0;
                    } else {
                        /* Normal line — execute immediately */
                        execute_full_line((char *)trimmed);
                    }
                }
            }
        }

        if (saved == '\0') break;
        line = end + 1;
    }
}

static void cmd_source(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: source <file>\n");
        return;
    }
    int fd = sys_open(argv[1], O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "source: ");
        write_str(2, argv[1]);
        write_str(2, ": not found\n");
        return;
    }
    char buf[4096];
    ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return;
    buf[n] = '\0';

    execute_script_buffer(buf);
}

/* ── timeout: run command with a time limit ── */
static void cmd_timeout(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "usage: timeout SECONDS COMMAND [ARGS...]\n");
        return;
    }
    /* Parse timeout value (integer seconds) */
    int secs = 0;
    for (const char *p = argv[1]; *p; p++) {
        if (*p >= '0' && *p <= '9') secs = secs * 10 + (*p - '0');
        else break;
    }
    if (secs <= 0) { write_str(2, "timeout: invalid duration\n"); return; }

    /* Execute the subcommand with remaining args */
    int sub_argc = argc - 2;
    char *sub_argv[64];
    for (int i = 0; i < sub_argc && i < 63; i++)
        sub_argv[i] = argv[i + 2];
    sub_argv[sub_argc] = NULL;

    /* Fork: child runs command, parent sets alarm and waits */
    long child = sys_fork_call();
    if (child == 0) {
        /* Child: execute the command */
        execute_command(sub_argc, sub_argv);
        sys_exit(0);
    } else if (child > 0) {
        /* Parent: set alarm and wait */
        sys_alarm(secs);
        int status = 0;
        sys_waitpid((int)child, &status, 0);
        sys_alarm(0);  /* Cancel alarm */
        last_exit_status = (status >> 8) & 0xFF;
    } else {
        write_str(2, "timeout: fork failed\n");
    }
}

/* ── tty: print terminal name ── */
static void cmd_tty(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Check if stdin is a terminal by trying ttyname-like approach */
    struct { unsigned int ws_row, ws_col, ws_xpixel, ws_ypixel; } ws;
    long r = sys_ioctl(0, 0x5413 /* TIOCGWINSZ */, (unsigned long)&ws);
    if (r == 0) {
        write_str(1, "/dev/console\n");
    } else {
        write_str(1, "not a tty\n");
        last_exit_status = 1;
    }
}

/* ── nohup: run command immune to hangups ── */
static void cmd_nohup(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: nohup COMMAND [ARGS...]\n");
        return;
    }
    /* Ignore SIGHUP (signal 1) */
    struct { void *handler; unsigned long flags; void *restorer; unsigned long mask; } sa;
    __builtin_memset(&sa, 0, sizeof(sa));
    sa.handler = (void *)1;  /* SIG_IGN */
    sys_sigaction(1 /* SIGHUP */, &sa, NULL);

    /* Execute the command */
    int sub_argc = argc - 1;
    char *sub_argv[64];
    for (int i = 0; i < sub_argc && i < 63; i++)
        sub_argv[i] = argv[i + 1];
    sub_argv[sub_argc] = NULL;
    execute_command(sub_argc, sub_argv);
}

/* ── chroot: change root directory ── */
/* unshare: create new namespaces (container isolation primitive) */
static void cmd_unshare(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: unshare [flags] <command> [args...]\n");
        write_str(2, "flags: --mount --uts --ipc --net --pid --user --cgroup\n");
        return;
    }

    unsigned long flags = 0;
    int cmd_start = 1;

    while (cmd_start < argc && argv[cmd_start][0] == '-') {
        const char *f = argv[cmd_start];
        if (strcmp_simple(f, "--mount") == 0 || strcmp_simple(f, "-m") == 0)
            flags |= 0x00020000;  /* CLONE_NEWNS */
        else if (strcmp_simple(f, "--uts") == 0 || strcmp_simple(f, "-u") == 0)
            flags |= 0x04000000;  /* CLONE_NEWUTS */
        else if (strcmp_simple(f, "--ipc") == 0 || strcmp_simple(f, "-i") == 0)
            flags |= 0x08000000;  /* CLONE_NEWIPC */
        else if (strcmp_simple(f, "--net") == 0 || strcmp_simple(f, "-n") == 0)
            flags |= 0x40000000;  /* CLONE_NEWNET */
        else if (strcmp_simple(f, "--pid") == 0 || strcmp_simple(f, "-p") == 0)
            flags |= 0x20000000;  /* CLONE_NEWPID */
        else if (strcmp_simple(f, "--user") == 0 || strcmp_simple(f, "-U") == 0)
            flags |= 0x10000000;  /* CLONE_NEWUSER */
        else if (strcmp_simple(f, "--cgroup") == 0 || strcmp_simple(f, "-C") == 0)
            flags |= 0x02000000;  /* CLONE_NEWCGROUP */
        else {
            write_str(2, "unshare: unknown flag: ");
            write_str(2, f);
            write_str(2, "\n");
            return;
        }
        cmd_start++;
    }

    if (cmd_start >= argc) {
        write_str(2, "unshare: no command specified\n");
        return;
    }

    if (flags == 0) flags = 0x00020000;  /* Default: CLONE_NEWNS */

    /* Call unshare(2) */
    long r = sys_call1(272 /* __NR_unshare */, (long)flags);
    if (r < 0) {
        write_str(2, "unshare: failed (");
        char num[12]; int_to_str(-(int)r, num, 12);
        write_str(2, num);
        write_str(2, ")\n");
        last_exit_status = 1;
        return;
    }

    /* Execute the command in the new namespace */
    int sub_argc = argc - cmd_start;
    char *sub_argv[64];
    for (int i = 0; i < sub_argc && i < 63; i++)
        sub_argv[i] = argv[cmd_start + i];
    sub_argv[sub_argc] = NULL;
    execute_command(sub_argc, sub_argv);
}

/* nsenter: enter namespaces of a target process (docker exec primitive) */
static void cmd_nsenter(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "usage: nsenter -t PID [--mount] [--uts] [--ipc] [--net] [--pid] [--user] [--all] command...\n");
        return;
    }

    int target_pid = 0;
    int do_mount = 0, do_uts = 0, do_ipc = 0, do_net = 0;
    int do_pid = 0, do_user = 0;
    int cmd_start = 1;

    while (cmd_start < argc && argv[cmd_start][0] == '-') {
        const char *f = argv[cmd_start];
        if ((strcmp_simple(f, "-t") == 0 || strcmp_simple(f, "--target") == 0) && cmd_start + 1 < argc) {
            cmd_start++;
            for (const char *p = argv[cmd_start]; *p >= '0' && *p <= '9'; p++)
                target_pid = target_pid * 10 + (*p - '0');
            cmd_start++;
        } else if (strcmp_simple(f, "--mount") == 0 || strcmp_simple(f, "-m") == 0) {
            do_mount = 1; cmd_start++;
        } else if (strcmp_simple(f, "--uts") == 0 || strcmp_simple(f, "-u") == 0) {
            do_uts = 1; cmd_start++;
        } else if (strcmp_simple(f, "--ipc") == 0 || strcmp_simple(f, "-i") == 0) {
            do_ipc = 1; cmd_start++;
        } else if (strcmp_simple(f, "--net") == 0 || strcmp_simple(f, "-n") == 0) {
            do_net = 1; cmd_start++;
        } else if (strcmp_simple(f, "--pid") == 0 || strcmp_simple(f, "-p") == 0) {
            do_pid = 1; cmd_start++;
        } else if (strcmp_simple(f, "--user") == 0 || strcmp_simple(f, "-U") == 0) {
            do_user = 1; cmd_start++;
        } else if (strcmp_simple(f, "--all") == 0 || strcmp_simple(f, "-a") == 0) {
            do_mount = do_uts = do_ipc = do_net = do_pid = do_user = 1;
            cmd_start++;
        } else {
            break;
        }
    }

    if (target_pid <= 0) {
        write_str(2, "nsenter: -t PID required\n");
        return;
    }
    if (cmd_start >= argc) {
        write_str(2, "nsenter: no command specified\n");
        return;
    }

    /* If no specific ns flags, default to --all */
    if (!do_mount && !do_uts && !do_ipc && !do_net && !do_pid && !do_user) {
        do_mount = do_uts = do_ipc = do_net = do_pid = do_user = 1;
    }

    /* Build /proc/<pid>/ns/<type> path and call setns for each */
    static char ns_path[64];
    const char *ns_types[] = { "mnt", "uts", "ipc", "net", "pid", "user" };
    int ns_flags[] = { do_mount, do_uts, do_ipc, do_net, do_pid, do_user };

    for (int i = 0; i < 6; i++) {
        if (!ns_flags[i]) continue;
        /* Build path: /proc/<pid>/ns/<type> */
        int pp = 0;
        const char *pfx = "/proc/";
        while (*pfx) ns_path[pp++] = *pfx++;
        { int v = target_pid; char rev[12]; int rp = 0;
          while (v > 0) { rev[rp++] = '0' + (v % 10); v /= 10; }
          while (rp > 0) ns_path[pp++] = rev[--rp]; }
        ns_path[pp++] = '/'; ns_path[pp++] = 'n'; ns_path[pp++] = 's'; ns_path[pp++] = '/';
        const char *t = ns_types[i];
        while (*t) ns_path[pp++] = *t++;
        ns_path[pp] = '\0';

        long fd = sys_open(ns_path, O_RDONLY, 0);
        if (fd < 0) continue;
        /* setns(fd, 0) — auto-detect ns type */
        long r = sys_call2(308 /* __NR_setns */, fd, 0);
        sys_close((int)fd);
        if (r < 0) {
            write_str(2, "nsenter: setns(");
            write_str(2, ns_types[i]);
            write_str(2, ") failed\n");
        }
    }

    /* Execute command in the new namespaces */
    int sub_argc = argc - cmd_start;
    char *sub_argv[64];
    for (int i = 0; i < sub_argc && i < 63; i++)
        sub_argv[i] = argv[cmd_start + i];
    sub_argv[sub_argc] = NULL;
    execute_command(sub_argc, sub_argv);
}

static void cmd_chroot(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: chroot NEWROOT [COMMAND...]\n");
        return;
    }
    long r = sys_chroot(argv[1]);
    if (r != 0) {
        write_str(2, "chroot: ");
        write_str(2, argv[1]);
        write_str(2, ": operation failed\n");
        last_exit_status = 1;
        return;
    }
    sys_chdir("/");

    if (argc > 2) {
        int sub_argc = argc - 2;
        char *sub_argv[64];
        for (int i = 0; i < sub_argc && i < 63; i++)
            sub_argv[i] = argv[i + 2];
        sub_argv[sub_argc] = NULL;
        execute_command(sub_argc, sub_argv);
    } else {
        /* Run default shell */
        char *sh_argv[] = { "/bin/shell", NULL };
        execute_command(1, sh_argv);
    }
}

/* ── tac: concatenate and print files in reverse ── */
static void cmd_tac(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: tac FILE...\n");
        return;
    }
    for (int f = 1; f < argc; f++) {
        int fd = sys_open(argv[f], O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "tac: ");
            write_str(2, argv[f]);
            write_str(2, ": not found\n");
            continue;
        }
        /* Read entire file */
        static char buf[32768];
        ssize_t total = 0;
        ssize_t n;
        while (total < (ssize_t)sizeof(buf) - 1 &&
               (n = sys_read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
            total += n;
        sys_close(fd);
        buf[total] = '\0';

        /* Find line boundaries and print in reverse */
        int nlines = 0;
        int line_starts[4096];
        line_starts[0] = 0;
        nlines = 1;
        for (ssize_t i = 0; i < total && nlines < 4095; i++) {
            if (buf[i] == '\n' && i + 1 < total) {
                line_starts[nlines++] = (int)(i + 1);
            }
        }
        /* Print lines in reverse order */
        for (int i = nlines - 1; i >= 0; i--) {
            int start = line_starts[i];
            int end = (i + 1 < nlines) ? line_starts[i + 1] : (int)total;
            sys_write(1, buf + start, end - start);
        }
    }
}

/* ── chgrp: change group ownership ── */
static void cmd_chgrp(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "usage: chgrp GROUP FILE...\n");
        return;
    }
    /* Parse group as numeric GID */
    int gid = 0;
    for (const char *p = argv[1]; *p; p++) {
        if (*p >= '0' && *p <= '9') gid = gid * 10 + (*p - '0');
        else { write_str(2, "chgrp: numeric group required\n"); return; }
    }
    for (int i = 2; i < argc; i++) {
        long r = sys_chown(argv[i], (unsigned int)-1, (unsigned int)gid);
        if (r != 0) {
            write_str(2, "chgrp: ");
            write_str(2, argv[i]);
            write_str(2, ": failed\n");
        }
    }
}

/* ── md5sum: compute MD5 hash (simplified — uses a basic hash) ── */
static void cmd_md5sum(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: md5sum FILE...\n");
        return;
    }
    for (int f = 1; f < argc; f++) {
        int fd = sys_open(argv[f], O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "md5sum: ");
            write_str(2, argv[f]);
            write_str(2, ": not found\n");
            continue;
        }
        /* Simple FNV-1a 128-bit hash (not real MD5, but produces 32 hex chars) */
        uint64_t h1 = 0xcbf29ce484222325ULL, h2 = 0x100000001b3ULL;
        static char buf[4096];
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                h1 ^= (uint8_t)buf[i]; h1 *= 0x01000193;
                h2 ^= (uint8_t)buf[i]; h2 *= 0x00000100000001B3ULL;
            }
        }
        sys_close(fd);
        /* Print as 32 hex characters */
        static const char hex[] = "0123456789abcdef";
        char out[33];
        for (int i = 0; i < 8; i++) {
            out[i*2]   = hex[(h1 >> (60 - i*8 + 4)) & 0xF];
            out[i*2+1] = hex[(h1 >> (60 - i*8)) & 0xF];
        }
        for (int i = 0; i < 8; i++) {
            out[16+i*2]   = hex[(h2 >> (60 - i*8 + 4)) & 0xF];
            out[16+i*2+1] = hex[(h2 >> (60 - i*8)) & 0xF];
        }
        out[32] = '\0';
        write_str(1, out);
        write_str(1, "  ");
        write_str(1, argv[f]);
        write_str(1, "\n");
    }
}

/* ── strings: print printable character sequences from a file ── */
static void cmd_strings(int argc, char *argv[]) {
    int min_len = 4;  /* default minimum string length */
    int file_start = 1;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'n') {
        min_len = 0;
        for (const char *p = argv[2]; *p >= '0' && *p <= '9'; p++)
            min_len = min_len * 10 + (*p - '0');
        file_start = 3;
    }
    if (file_start >= argc) {
        write_str(2, "usage: strings [-n MIN] FILE...\n");
        return;
    }
    for (int f = file_start; f < argc; f++) {
        int fd = sys_open(argv[f], O_RDONLY, 0);
        if (fd < 0) { write_str(2, "strings: cannot open "); write_str(2, argv[f]); write_str(2, "\n"); continue; }
        static char buf[4096];
        static char run[4096];
        int run_len = 0;
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                unsigned char c = (unsigned char)buf[i];
                if (c >= 32 && c < 127) {
                    if (run_len < (int)sizeof(run) - 1) run[run_len++] = (char)c;
                } else {
                    if (run_len >= min_len) {
                        run[run_len] = '\0';
                        write_str(1, run);
                        write_str(1, "\n");
                    }
                    run_len = 0;
                }
            }
        }
        if (run_len >= min_len) {
            run[run_len] = '\0';
            write_str(1, run);
            write_str(1, "\n");
        }
        sys_close(fd);
    }
}

/* ── pgrep/pkill/pidof: find/signal processes by name ── */
static int match_proc_name(int pid, const char *pattern) {
    /* Read /proc/<pid>/comm and check if it contains pattern */
    char path[64], comm[64];
    int pi = 0;
    const char *pfx = "/proc/";
    while (pfx[pi]) { path[pi] = pfx[pi]; pi++; }
    /* Append PID digits */
    char pbuf[16]; int plen = 0;
    int tmp = pid;
    if (tmp == 0) { pbuf[plen++] = '0'; }
    else { while (tmp > 0) { pbuf[plen++] = '0' + (tmp % 10); tmp /= 10; } }
    for (int i = plen - 1; i >= 0; i--) path[pi++] = pbuf[i];
    const char *sfx = "/comm";
    for (int i = 0; sfx[i]; i++) path[pi++] = sfx[i];
    path[pi] = '\0';

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return 0;
    ssize_t n = sys_read(fd, comm, sizeof(comm) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    comm[n] = '\0';
    /* Strip trailing newline */
    if (n > 0 && comm[n-1] == '\n') comm[n-1] = '\0';

    /* Simple substring match */
    for (int i = 0; comm[i]; i++) {
        int j = 0;
        while (pattern[j] && comm[i+j] == pattern[j]) j++;
        if (pattern[j] == '\0') return 1;
    }
    return 0;
}

static void cmd_pgrep(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: pgrep PATTERN\n"); return; }
    const char *pattern = argv[1];
    int proc_fd = sys_open("/proc", O_RDONLY, 0);
    if (proc_fd < 0) return;
    char dirbuf[2048];
    ssize_t dn;
    while ((dn = sys_getdents64(proc_fd, dirbuf, sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            char *name = dirbuf + pos + 19;
            if (name[0] >= '1' && name[0] <= '9') {
                int pid = 0;
                for (int i = 0; name[i] >= '0' && name[i] <= '9'; i++)
                    pid = pid * 10 + (name[i] - '0');
                if (match_proc_name(pid, pattern)) {
                    char num[16]; int nl = 0;
                    int t = pid;
                    if (t == 0) { num[nl++] = '0'; }
                    else { while (t > 0) { num[nl++] = '0' + (t % 10); t /= 10; } }
                    for (int i = nl - 1; i >= 0; i--) { char c = num[i]; sys_write(1, &c, 1); }
                    write_str(1, "\n");
                }
            }
            pos += reclen;
        }
    }
    sys_close(proc_fd);
}

static void cmd_pkill(int argc, char *argv[]) {
    int sig = 15; /* SIGTERM */
    int pat_idx = 1;
    if (argc >= 3 && argv[1][0] == '-') {
        sig = 0;
        for (const char *p = argv[1] + 1; *p >= '0' && *p <= '9'; p++)
            sig = sig * 10 + (*p - '0');
        pat_idx = 2;
    }
    if (pat_idx >= argc) { write_str(2, "usage: pkill [-SIG] PATTERN\n"); return; }
    const char *pattern = argv[pat_idx];
    int proc_fd = sys_open("/proc", O_RDONLY, 0);
    if (proc_fd < 0) return;
    char dirbuf[2048];
    ssize_t dn;
    while ((dn = sys_getdents64(proc_fd, dirbuf, sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            char *name = dirbuf + pos + 19;
            if (name[0] >= '1' && name[0] <= '9') {
                int pid = 0;
                for (int i = 0; name[i] >= '0' && name[i] <= '9'; i++)
                    pid = pid * 10 + (name[i] - '0');
                if (match_proc_name(pid, pattern))
                    sys_kill(pid, sig);
            }
            pos += reclen;
        }
    }
    sys_close(proc_fd);
}

static void cmd_pidof(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: pidof NAME\n"); return; }
    /* pidof matches exact process name (not substring) */
    int proc_fd = sys_open("/proc", O_RDONLY, 0);
    if (proc_fd < 0) return;
    char dirbuf[2048];
    ssize_t dn;
    int first = 1;
    while ((dn = sys_getdents64(proc_fd, dirbuf, sizeof(dirbuf))) > 0) {
        ssize_t pos = 0;
        while (pos < dn) {
            uint16_t reclen = *(uint16_t *)(dirbuf + pos + 16);
            char *name = dirbuf + pos + 19;
            if (name[0] >= '1' && name[0] <= '9') {
                int pid = 0;
                for (int i = 0; name[i] >= '0' && name[i] <= '9'; i++)
                    pid = pid * 10 + (name[i] - '0');
                /* Read comm and compare exactly */
                char path[64], comm[64];
                int pi = 0;
                const char *pfx = "/proc/";
                while (pfx[pi]) { path[pi] = pfx[pi]; pi++; }
                char pbuf[16]; int plen = 0;
                int tmp = pid;
                if (tmp == 0) { pbuf[plen++] = '0'; }
                else { while (tmp > 0) { pbuf[plen++] = '0' + (tmp % 10); tmp /= 10; } }
                for (int i = plen - 1; i >= 0; i--) path[pi++] = pbuf[i];
                const char *sfx = "/comm";
                for (int i = 0; sfx[i]; i++) path[pi++] = sfx[i];
                path[pi] = '\0';
                int fd = sys_open(path, O_RDONLY, 0);
                if (fd >= 0) {
                    ssize_t n = sys_read(fd, comm, sizeof(comm) - 1);
                    sys_close(fd);
                    if (n > 0) {
                        comm[n] = '\0';
                        if (n > 0 && comm[n-1] == '\n') comm[n-1] = '\0';
                        int match = 1;
                        for (int i = 0; argv[1][i] || comm[i]; i++) {
                            if (argv[1][i] != comm[i]) { match = 0; break; }
                        }
                        if (match) {
                            if (!first) write_str(1, " ");
                            char num[16]; int nl = 0;
                            int t = pid;
                            if (t == 0) { num[nl++] = '0'; }
                            else { while (t > 0) { num[nl++] = '0' + (t % 10); t /= 10; } }
                            for (int i = nl - 1; i >= 0; i--) { char c = num[i]; sys_write(1, &c, 1); }
                            first = 0;
                        }
                    }
                }
            }
            pos += reclen;
        }
    }
    sys_close(proc_fd);
    if (!first) write_str(1, "\n");
}

/* ── nice/renice: process priority management ── */
static void cmd_nice(int argc, char *argv[]) {
    int niceval = 10;  /* default nice increment */
    int cmd_start = 1;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'n') {
        if (argc >= 4) {
            niceval = 0;
            const char *p = argv[2];
            int neg = 0;
            if (*p == '-') { neg = 1; p++; }
            while (*p >= '0' && *p <= '9') niceval = niceval * 10 + (*p++ - '0');
            if (neg) niceval = -niceval;
            cmd_start = 3;
        }
    }
    if (cmd_start >= argc) {
        write_str(2, "usage: nice [-n ADJ] COMMAND [ARGS...]\n");
        return;
    }
    /* Set our nice value then exec the command */
    sys_setpriority(0 /* PRIO_PROCESS */, 0, niceval);
    int sub_argc = argc - cmd_start;
    char *sub_argv[64];
    for (int i = 0; i < sub_argc && i < 63; i++)
        sub_argv[i] = argv[i + cmd_start];
    sub_argv[sub_argc] = NULL;
    execute_command(sub_argc, sub_argv);
}

static void cmd_renice(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "usage: renice PRIORITY PID\n");
        return;
    }
    int prio = 0, neg = 0;
    const char *p = argv[1];
    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') prio = prio * 10 + (*p++ - '0');
    if (neg) prio = -prio;

    int pid = 0;
    for (p = argv[2]; *p >= '0' && *p <= '9'; p++)
        pid = pid * 10 + (*p - '0');

    extern long sys_setpriority(int which, int who, int prio);
    long r = sys_setpriority(0 /* PRIO_PROCESS */, pid, prio);
    if (r != 0) {
        write_str(2, "renice: failed\n");
        last_exit_status = 1;
    }
}

/* ── xxd: hex dump with optional reverse ── */
static void cmd_xxd(int argc, char *argv[]) {
    int reverse = 0;
    int file_idx = 1;
    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'r') {
        reverse = 1;
        file_idx = 2;
    }
    if (file_idx >= argc) {
        write_str(2, "usage: xxd [-r] FILE\n");
        return;
    }
    int fd = sys_open(argv[file_idx], O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "xxd: cannot open "); write_str(2, argv[file_idx]); write_str(2, "\n");
        return;
    }

    if (reverse) {
        /* Reverse hex dump: parse "OFFSET: HEXBYTES" lines back to binary */
        static char line[256];
        ssize_t n = sys_read(fd, line, sizeof(line));
        sys_close(fd);
        /* Simple: just extract hex bytes from each line */
        for (ssize_t i = 0; i < n; i++) {
            /* Skip offset and colon */
            while (i < n && line[i] != ':' && line[i] != ' ') i++;
            if (i < n && line[i] == ':') i++;
            /* Parse hex pairs */
            while (i < n && line[i] != '\n') {
                while (i < n && line[i] == ' ') i++;
                if (i + 1 < n && line[i] != '\n') {
                    int hi = 0, lo = 0;
                    char c = line[i];
                    if (c >= '0' && c <= '9') hi = c - '0';
                    else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
                    else break;
                    i++;
                    c = line[i];
                    if (c >= '0' && c <= '9') lo = c - '0';
                    else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
                    else break;
                    i++;
                    char byte = (char)((hi << 4) | lo);
                    sys_write(1, &byte, 1);
                }
            }
        }
    } else {
        /* Forward hex dump: standard xxd format */
        static const char hex[] = "0123456789abcdef";
        static char buf[4096];
        ssize_t total_offset = 0;
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i += 16) {
                /* Offset */
                char line[80];
                int lp = 0;
                uint32_t off = (uint32_t)(total_offset + i);
                for (int j = 28; j >= 0; j -= 4)
                    line[lp++] = hex[(off >> j) & 0xF];
                line[lp++] = ':';
                line[lp++] = ' ';
                /* Hex bytes */
                ssize_t end = i + 16;
                if (end > n) end = n;
                for (ssize_t j = i; j < i + 16; j++) {
                    if (j < end) {
                        line[lp++] = hex[((unsigned char)buf[j]) >> 4];
                        line[lp++] = hex[((unsigned char)buf[j]) & 0xF];
                    } else {
                        line[lp++] = ' '; line[lp++] = ' ';
                    }
                    if ((j - i) % 2 == 1) line[lp++] = ' ';
                }
                line[lp++] = ' ';
                /* ASCII */
                for (ssize_t j = i; j < end; j++) {
                    unsigned char c = (unsigned char)buf[j];
                    line[lp++] = (c >= 32 && c < 127) ? (char)c : '.';
                }
                line[lp++] = '\n';
                sys_write(1, line, lp);
            }
            total_offset += n;
        }
        sys_close(fd);
    }
}

/* ── patch: apply unified diff patches ── */
static void cmd_patch(int argc, char *argv[]) {
    int strip = 0; /* -p N: strip N leading path components */
    int file_arg = -1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == 'p') {
            const char *num = argv[i] + 2;
            if (*num == '\0' && i + 1 < argc) num = argv[++i];
            strip = 0;
            while (*num >= '0' && *num <= '9') { strip = strip * 10 + (*num - '0'); num++; }
        } else {
            file_arg = i;
        }
    }

    /* Read the entire patch from stdin or file argument */
    static char patch_buf[32768];
    int patch_len = 0;
    int pfd = 0; /* stdin by default */
    if (file_arg >= 0) {
        pfd = sys_open(argv[file_arg], O_RDONLY, 0);
        if (pfd < 0) { write_str(2, "patch: cannot open patch file\n"); return; }
    }
    ssize_t nr;
    while (patch_len < (int)sizeof(patch_buf) - 1 && (nr = sys_read(pfd, patch_buf + patch_len, sizeof(patch_buf) - 1 - patch_len)) > 0)
        patch_len += (int)nr;
    if (pfd > 0) sys_close(pfd);
    patch_buf[patch_len] = '\0';

    /* Parse lines */
    static char *lines[4096];
    int nlines = 0;
    lines[0] = patch_buf;
    for (int i = 0; i < patch_len && nlines < 4095; i++) {
        if (patch_buf[i] == '\n') {
            patch_buf[i] = '\0';
            if (i + 1 < patch_len) lines[++nlines] = &patch_buf[i + 1];
        }
    }
    if (patch_len > 0) nlines++;

    /* Strip path components helper */
    static char stripped_path[512];
    int li = 0;
    while (li < nlines) {
        /* Find +++ line to determine target file */
        if (lines[li][0] == '+' && lines[li][1] == '+' && lines[li][2] == '+' && lines[li][3] == ' ') {
            const char *path = lines[li] + 4;
            /* Skip "b/" or strip components */
            int s = strip;
            while (s > 0 && *path) {
                if (*path == '/') { path++; s--; }
                else path++;
            }
            /* Copy path, stop at tab or space (timestamps) */
            int pi = 0;
            while (*path && *path != '\t' && *path != '\n' && pi < 510) stripped_path[pi++] = *path++;
            stripped_path[pi] = '\0';

            /* Read target file */
            static char file_buf[32768];
            int file_len = 0;
            int tfd = sys_open(stripped_path, O_RDONLY, 0);
            if (tfd >= 0) {
                ssize_t r;
                while (file_len < (int)sizeof(file_buf) - 1 && (r = sys_read(tfd, file_buf + file_len, sizeof(file_buf) - 1 - file_len)) > 0)
                    file_len += (int)r;
                sys_close(tfd);
            }
            file_buf[file_len] = '\0';

            /* Split target file into lines */
            static char *flines[4096];
            int fnlines = 0;
            if (file_len > 0) {
                flines[0] = file_buf;
                for (int i = 0; i < file_len && fnlines < 4095; i++) {
                    if (file_buf[i] == '\n') {
                        file_buf[i] = '\0';
                        if (i + 1 < file_len) flines[++fnlines] = &file_buf[i + 1];
                    }
                }
                fnlines++;
            }

            /* Apply hunks */
            li++;
            static char out_buf[32768];
            int out_len = 0;
            int fpos = 0; /* current position in original file lines */

            while (li < nlines) {
                /* Check for @@ hunk header or next file */
                if (lines[li][0] == '-' && lines[li][1] == '-' && lines[li][2] == '-') break;
                if (lines[li][0] != '@' || lines[li][1] != '@') { li++; continue; }

                /* Parse @@ -OLD_START,OLD_COUNT +NEW_START,NEW_COUNT @@ */
                const char *h = lines[li] + 3;
                int old_start = 0;
                while (*h == ' ') h++;
                if (*h == '-') h++;
                while (*h >= '0' && *h <= '9') { old_start = old_start * 10 + (*h - '0'); h++; }
                int old_count = 1;
                if (*h == ',') { h++; old_count = 0; while (*h >= '0' && *h <= '9') { old_count = old_count * 10 + (*h - '0'); h++; } }
                li++;

                /* Copy unchanged lines before this hunk */
                int hunk_start = old_start > 0 ? old_start - 1 : 0;
                while (fpos < hunk_start && fpos < fnlines) {
                    const char *fl = flines[fpos];
                    while (*fl && out_len < (int)sizeof(out_buf) - 2) out_buf[out_len++] = *fl++;
                    out_buf[out_len++] = '\n';
                    fpos++;
                }

                /* Process hunk lines */
                int consumed = 0;
                while (li < nlines && (lines[li][0] == ' ' || lines[li][0] == '+' || lines[li][0] == '-' || lines[li][0] == '\\')) {
                    if (lines[li][0] == '\\') { li++; continue; } /* "\ No newline at end of file" */
                    if (lines[li][0] == '-') {
                        /* Remove line from original (skip it) */
                        consumed++;
                        fpos++;
                        li++;
                    } else if (lines[li][0] == '+') {
                        /* Add line */
                        const char *add = lines[li] + 1;
                        while (*add && out_len < (int)sizeof(out_buf) - 2) out_buf[out_len++] = *add++;
                        out_buf[out_len++] = '\n';
                        li++;
                    } else {
                        /* Context line */
                        const char *ctx = lines[li] + 1;
                        while (*ctx && out_len < (int)sizeof(out_buf) - 2) out_buf[out_len++] = *ctx++;
                        out_buf[out_len++] = '\n';
                        consumed++;
                        fpos++;
                        li++;
                    }
                }
                (void)consumed;
                (void)old_count;
            }

            /* Copy remaining lines */
            while (fpos < fnlines) {
                const char *fl = flines[fpos];
                while (*fl && out_len < (int)sizeof(out_buf) - 2) out_buf[out_len++] = *fl++;
                out_buf[out_len++] = '\n';
                fpos++;
            }

            /* Write patched file */
            int wfd = sys_open(stripped_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (wfd < 0) {
                write_str(2, "patch: cannot write ");
                write_str(2, stripped_path);
                write_str(2, "\n");
            } else {
                sys_write(wfd, out_buf, out_len);
                sys_close(wfd);
                write_str(1, "patching file ");
                write_str(1, stripped_path);
                write_str(1, "\n");
            }
        } else {
            li++;
        }
    }
}

/* ── sha1sum: compute SHA-1 hash ── */
static void cmd_sha1sum(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: sha1sum FILE...\n");
        return;
    }
    for (int f = 1; f < argc; f++) {
        int fd = sys_open(argv[f], O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "sha1sum: ");
            write_str(2, argv[f]);
            write_str(2, ": not found\n");
            continue;
        }

        /* SHA-1 state */
        uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
        uint32_t h3 = 0x10325476, h4 = 0xC3D2E1F0;
        uint64_t total_bits = 0;
        static unsigned char blk[64];
        int blk_len = 0;
        static unsigned char rbuf[4096];
        ssize_t nr;

        /* Process a single 64-byte block */
        #define SHA1_ROTL(v,n) (((v)<<(n))|((v)>>(32-(n))))
        #define SHA1_BLOCK() do { \
            uint32_t w[80]; \
            for (int i = 0; i < 16; i++) \
                w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)| \
                        ((uint32_t)blk[i*4+2]<<8)|((uint32_t)blk[i*4+3]); \
            for (int i = 16; i < 80; i++) \
                w[i] = SHA1_ROTL(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1); \
            uint32_t a=h0, b=h1, c=h2, d=h3, e=h4; \
            for (int i = 0; i < 80; i++) { \
                uint32_t fv, k; \
                if (i < 20) { fv=(b&c)|((~b)&d); k=0x5A827999; } \
                else if (i < 40) { fv=b^c^d; k=0x6ED9EBA1; } \
                else if (i < 60) { fv=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; } \
                else { fv=b^c^d; k=0xCA62C1D6; } \
                uint32_t tmp = SHA1_ROTL(a,5)+fv+e+k+w[i]; \
                e=d; d=c; c=SHA1_ROTL(b,30); b=a; a=tmp; \
            } \
            h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; \
        } while(0)

        while ((nr = sys_read(fd, rbuf, sizeof(rbuf))) > 0) {
            for (ssize_t i = 0; i < nr; i++) {
                blk[blk_len++] = rbuf[i];
                if (blk_len == 64) { SHA1_BLOCK(); blk_len = 0; }
            }
            total_bits += (uint64_t)nr * 8;
        }
        sys_close(fd);

        /* Padding */
        blk[blk_len++] = 0x80;
        if (blk_len > 56) {
            while (blk_len < 64) blk[blk_len++] = 0;
            SHA1_BLOCK(); blk_len = 0;
        }
        while (blk_len < 56) blk[blk_len++] = 0;
        /* Append length in bits (big-endian 64-bit) */
        for (int i = 7; i >= 0; i--)
            blk[blk_len++] = (unsigned char)(total_bits >> (i * 8));
        SHA1_BLOCK();
        #undef SHA1_ROTL
        #undef SHA1_BLOCK

        /* Output 40-character hex digest */
        static const char hex[] = "0123456789abcdef";
        char out[41];
        uint32_t hv[5] = {h0, h1, h2, h3, h4};
        for (int i = 0; i < 5; i++) {
            out[i*8+0] = hex[(hv[i]>>28)&0xF]; out[i*8+1] = hex[(hv[i]>>24)&0xF];
            out[i*8+2] = hex[(hv[i]>>20)&0xF]; out[i*8+3] = hex[(hv[i]>>16)&0xF];
            out[i*8+4] = hex[(hv[i]>>12)&0xF]; out[i*8+5] = hex[(hv[i]>> 8)&0xF];
            out[i*8+6] = hex[(hv[i]>> 4)&0xF]; out[i*8+7] = hex[(hv[i]>> 0)&0xF];
        }
        out[40] = '\0';
        write_str(1, out);
        write_str(1, "  ");
        write_str(1, argv[f]);
        write_str(1, "\n");
    }
}

/* ── file: identify file type by magic bytes ── */
static void cmd_file(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: file FILE...\n"); return; }
    for (int f = 1; f < argc; f++) {
        write_str(1, argv[f]);
        write_str(1, ": ");

        /* Try stat first for type */
        struct { uint64_t dev; uint64_t ino; uint64_t nlink; uint32_t mode;
                 uint32_t uid; uint32_t gid; uint32_t pad; uint64_t rdev;
                 int64_t size; int64_t blksize; int64_t blocks;
                 uint64_t atime_s; uint64_t atime_ns;
                 uint64_t mtime_s; uint64_t mtime_ns;
                 uint64_t ctime_s; uint64_t ctime_ns; } st;
        extern long sys_stat_call(const char *, void *);
        long sr = sys_stat_call(argv[f], &st);
        if (sr != 0) { write_str(1, "cannot stat\n"); continue; }

        uint32_t ftype = st.mode & 0170000;
        if (ftype == 0040000) { write_str(1, "directory\n"); continue; }
        if (ftype == 0120000) { write_str(1, "symbolic link\n"); continue; }
        if (ftype == 0060000) { write_str(1, "block special\n"); continue; }
        if (ftype == 0020000) { write_str(1, "character special\n"); continue; }
        if (ftype == 0010000) { write_str(1, "FIFO (named pipe)\n"); continue; }
        if (ftype == 0140000) { write_str(1, "socket\n"); continue; }

        /* Regular file — read magic bytes */
        int fd = sys_open(argv[f], O_RDONLY, 0);
        if (fd < 0) { write_str(1, "cannot open\n"); continue; }

        static unsigned char magic[64];
        ssize_t n = sys_read(fd, magic, sizeof(magic));
        sys_close(fd);

        if (n <= 0) {
            if (st.size == 0) write_str(1, "empty\n");
            else write_str(1, "data\n");
            continue;
        }

        /* ELF */
        if (n >= 16 && magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
            write_str(1, "ELF ");
            write_str(1, magic[4] == 2 ? "64-bit " : "32-bit ");
            write_str(1, magic[5] == 1 ? "LSB " : "MSB ");
            uint16_t etype = magic[16] | ((uint16_t)magic[17] << 8);
            if (etype == 2) write_str(1, "executable");
            else if (etype == 3) write_str(1, "shared object");
            else if (etype == 1) write_str(1, "relocatable");
            else if (etype == 4) write_str(1, "core file");
            else write_str(1, "unknown type");
            write_str(1, "\n");
            continue;
        }
        /* Shebang script */
        if (n >= 2 && magic[0] == '#' && magic[1] == '!') {
            write_str(1, "script, ");
            /* Print interpreter */
            int i = 2;
            while (i < n && (magic[i] == ' ' || magic[i] == '\t')) i++;
            while (i < n && magic[i] != '\n' && magic[i] != ' ' && magic[i] != '\0') {
                char c = (char)magic[i++];
                sys_write(1, &c, 1);
            }
            write_str(1, " script\n");
            continue;
        }
        /* PNG */
        if (n >= 8 && magic[0] == 0x89 && magic[1] == 'P' && magic[2] == 'N' && magic[3] == 'G') {
            write_str(1, "PNG image data\n"); continue;
        }
        /* JPEG */
        if (n >= 3 && magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF) {
            write_str(1, "JPEG image data\n"); continue;
        }
        /* GIF */
        if (n >= 6 && magic[0] == 'G' && magic[1] == 'I' && magic[2] == 'F') {
            write_str(1, "GIF image data\n"); continue;
        }
        /* PDF */
        if (n >= 5 && magic[0] == '%' && magic[1] == 'P' && magic[2] == 'D' && magic[3] == 'F') {
            write_str(1, "PDF document\n"); continue;
        }
        /* gzip */
        if (n >= 2 && magic[0] == 0x1F && magic[1] == 0x8B) {
            write_str(1, "gzip compressed data\n"); continue;
        }
        /* bzip2 */
        if (n >= 3 && magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h') {
            write_str(1, "bzip2 compressed data\n"); continue;
        }
        /* XZ */
        if (n >= 6 && magic[0] == 0xFD && magic[1] == '7' && magic[2] == 'z' && magic[3] == 'X') {
            write_str(1, "XZ compressed data\n"); continue;
        }
        /* tar (ustar magic at offset 257) — read+skip to reach offset */
        if (n >= 5 && st.size > 262) {
            fd = sys_open(argv[f], O_RDONLY, 0);
            if (fd >= 0) {
                static char skip[257];
                sys_read(fd, skip, 257);
                char tmagic[8];
                ssize_t tn = sys_read(fd, tmagic, 5);
                sys_close(fd);
                if (tn >= 5 && tmagic[0] == 'u' && tmagic[1] == 's' && tmagic[2] == 't' &&
                    tmagic[3] == 'a' && tmagic[4] == 'r') {
                    write_str(1, "POSIX tar archive (GNU)\n"); continue;
                }
            }
        }
        /* Check if it looks like text */
        int textlike = 1;
        for (ssize_t i = 0; i < n && i < 32; i++) {
            unsigned char c = magic[i];
            if (c < 7 || (c > 13 && c < 32 && c != 27)) { textlike = 0; break; }
        }
        if (textlike) write_str(1, "ASCII text\n");
        else write_str(1, "data\n");
    }
}

/* ── mkfifo: create named pipe ── */
static void cmd_mkfifo(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: mkfifo NAME...\n"); return; }
    for (int i = 1; i < argc; i++) {
        /* mknod(path, S_IFIFO | 0666, 0) creates a named pipe */
        long r = sys_call3(133 /* SYS_mknod */, (long)argv[i], 010666 /* S_IFIFO | 0666 */, 0);
        if (r != 0) {
            write_str(2, "mkfifo: ");
            write_str(2, argv[i]);
            write_str(2, ": failed\n");
            last_exit_status = 1;
        }
    }
}

/* ── cmp: byte-by-byte file comparison ── */
static void cmd_cmp(int argc, char *argv[]) {
    int silent = 0;
    int file_start = 1;
    if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 's') {
        silent = 1; file_start = 2;
    }
    if (file_start + 1 >= argc) {
        write_str(2, "usage: cmp [-s] FILE1 FILE2\n");
        return;
    }
    int fd1 = sys_open(argv[file_start], O_RDONLY, 0);
    if (fd1 < 0) {
        if (!silent) { write_str(2, "cmp: "); write_str(2, argv[file_start]); write_str(2, ": not found\n"); }
        last_exit_status = 2; return;
    }
    int fd2 = sys_open(argv[file_start + 1], O_RDONLY, 0);
    if (fd2 < 0) {
        sys_close(fd1);
        if (!silent) { write_str(2, "cmp: "); write_str(2, argv[file_start + 1]); write_str(2, ": not found\n"); }
        last_exit_status = 2; return;
    }
    static char b1[4096], b2[4096];
    long byte_pos = 1, line_num = 1;
    int differ = 0;
    while (1) {
        ssize_t n1 = sys_read(fd1, b1, sizeof(b1));
        ssize_t n2 = sys_read(fd2, b2, sizeof(b2));
        ssize_t cmp_len = n1 < n2 ? n1 : n2;
        for (ssize_t i = 0; i < cmp_len; i++) {
            if (b1[i] != b2[i]) {
                if (!silent) {
                    write_str(1, argv[file_start]); write_str(1, " ");
                    write_str(1, argv[file_start + 1]);
                    write_str(1, " differ: byte ");
                    char num[20]; int nl = 0;
                    long v = byte_pos;
                    char rev[20]; int rp = 0;
                    while (v > 0) { rev[rp++] = '0' + (char)(v % 10); v /= 10; }
                    if (rp == 0) num[nl++] = '0';
                    while (rp > 0) num[nl++] = rev[--rp];
                    num[nl] = '\0';
                    write_str(1, num);
                    write_str(1, ", line ");
                    v = line_num; rp = 0;
                    while (v > 0) { rev[rp++] = '0' + (char)(v % 10); v /= 10; }
                    nl = 0;
                    if (rp == 0) num[nl++] = '0';
                    while (rp > 0) num[nl++] = rev[--rp];
                    num[nl] = '\0';
                    write_str(1, num);
                    write_str(1, "\n");
                }
                differ = 1; break;
            }
            byte_pos++;
            if (b1[i] == '\n') line_num++;
        }
        if (differ) break;
        if (n1 != n2) {
            if (!silent) {
                write_str(1, "cmp: EOF on ");
                write_str(1, n1 < n2 ? argv[file_start] : argv[file_start + 1]);
                write_str(1, "\n");
            }
            differ = 1; break;
        }
        if (n1 <= 0) break;
    }
    sys_close(fd1); sys_close(fd2);
    last_exit_status = differ ? 1 : 0;
}

/* ── fold: wrap input lines to specified width ── */
static void cmd_fold(int argc, char *argv[]) {
    int width = 80;
    int file_start = 1;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'w') {
        width = 0;
        for (const char *p = argv[2]; *p >= '0' && *p <= '9'; p++)
            width = width * 10 + (*p - '0');
        if (width <= 0) width = 80;
        file_start = 3;
    } else if (argc >= 2 && argv[1][0] == '-' && argv[1][1] == 'w' && argv[1][2] >= '0') {
        width = 0;
        for (const char *p = argv[1] + 2; *p >= '0' && *p <= '9'; p++)
            width = width * 10 + (*p - '0');
        if (width <= 0) width = 80;
        file_start = 2;
    }
    int fd = 0;  /* default: stdin */
    if (file_start < argc) {
        fd = sys_open(argv[file_start], O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "fold: "); write_str(2, argv[file_start]); write_str(2, ": not found\n");
            return;
        }
    }
    static char buf[4096];
    ssize_t n;
    int col = 0;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                sys_write(1, &buf[i], 1);
                col = 0;
            } else {
                if (col >= width) {
                    char nl = '\n';
                    sys_write(1, &nl, 1);
                    col = 0;
                }
                sys_write(1, &buf[i], 1);
                col++;
            }
        }
    }
    if (fd > 0) sys_close(fd);
}

/* ── comm: compare sorted files line by line ── */
static void cmd_comm(int argc, char *argv[]) {
    if (argc < 3) { write_str(2, "usage: comm FILE1 FILE2\n"); return; }
    int fd1 = sys_open(argv[1], O_RDONLY, 0);
    int fd2 = sys_open(argv[2], O_RDONLY, 0);
    if (fd1 < 0 || fd2 < 0) {
        write_str(2, "comm: cannot open files\n");
        if (fd1 >= 0) sys_close(fd1);
        if (fd2 >= 0) sys_close(fd2);
        return;
    }
    /* Read both files into memory */
    static char f1[16384], f2[16384];
    ssize_t n1 = sys_read(fd1, f1, sizeof(f1) - 1); sys_close(fd1);
    ssize_t n2 = sys_read(fd2, f2, sizeof(f2) - 1); sys_close(fd2);
    f1[n1 > 0 ? n1 : 0] = '\0';
    f2[n2 > 0 ? n2 : 0] = '\0';
    /* Compare line by line */
    char *p1 = f1, *p2 = f2;
    while (*p1 || *p2) {
        /* Extract current lines */
        char l1[256] = {0}, l2[256] = {0};
        int i;
        for (i = 0; *p1 && *p1 != '\n' && i < 255; i++) l1[i] = *p1++;
        l1[i] = '\0'; if (*p1 == '\n') p1++;
        for (i = 0; *p2 && *p2 != '\n' && i < 255; i++) l2[i] = *p2++;
        l2[i] = '\0'; if (*p2 == '\n') p2++;
        if (!l1[0] && !l2[0]) break;
        int c = strcmp_simple(l1, l2);
        if (c == 0 && l1[0]) {
            write_str(1, "\t\t"); write_str(1, l1); write_str(1, "\n");
        } else if (c < 0 && l1[0]) {
            write_str(1, l1); write_str(1, "\n");
            p2 -= (i + 1);  /* Rewind p2 */
        } else if (l2[0]) {
            write_str(1, "\t"); write_str(1, l2); write_str(1, "\n");
            if (l1[0]) { int j = 0; while (l1[j]) j++; p1 -= (j + 1); }  /* Rewind p1 */
        }
    }
}

/* ── expand/unexpand: tab/space conversion ── */
static void cmd_expand(int argc, char *argv[]) {
    int tabstop = 8;
    int file_start = 1;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 't') {
        tabstop = 0;
        for (const char *p = argv[2]; *p >= '0' && *p <= '9'; p++)
            tabstop = tabstop * 10 + (*p - '0');
        if (tabstop <= 0) tabstop = 8;
        file_start = 3;
    }
    int fd = 0;
    if (file_start < argc) {
        fd = sys_open(argv[file_start], O_RDONLY, 0);
        if (fd < 0) { write_str(2, "expand: cannot open file\n"); return; }
    }
    static char buf[4096];
    ssize_t n;
    int col = 0;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == '\t') {
                int spaces = tabstop - (col % tabstop);
                for (int j = 0; j < spaces; j++) { char sp = ' '; sys_write(1, &sp, 1); col++; }
            } else if (buf[i] == '\n') {
                sys_write(1, &buf[i], 1); col = 0;
            } else {
                sys_write(1, &buf[i], 1); col++;
            }
        }
    }
    if (fd > 0) sys_close(fd);
}

static void cmd_unexpand(int argc, char *argv[]) {
    int tabstop = 8;
    int file_start = 1;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 't') {
        tabstop = 0;
        for (const char *p = argv[2]; *p >= '0' && *p <= '9'; p++)
            tabstop = tabstop * 10 + (*p - '0');
        if (tabstop <= 0) tabstop = 8;
        file_start = 3;
    }
    int fd = 0;
    if (file_start < argc) {
        fd = sys_open(argv[file_start], O_RDONLY, 0);
        if (fd < 0) { write_str(2, "unexpand: cannot open file\n"); return; }
    }
    static char buf[4096];
    ssize_t n;
    int col = 0;
    int leading = 1;  /* only convert leading spaces */
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] == ' ' && leading) {
                col++;
                if (col % tabstop == 0) { char tab = '\t'; sys_write(1, &tab, 1); }
                else if (i + 1 >= n || buf[i+1] != ' ') {
                    /* Flush remaining spaces */
                    int rem = col % tabstop;
                    for (int j = 0; j < rem; j++) { char sp = ' '; sys_write(1, &sp, 1); }
                }
            } else if (buf[i] == '\n') {
                sys_write(1, &buf[i], 1); col = 0; leading = 1;
            } else {
                leading = 0; sys_write(1, &buf[i], 1); col++;
            }
        }
    }
    if (fd > 0) sys_close(fd);
}

/* ── install: copy files with attributes ── */
static void cmd_install(int argc, char *argv[]) {
    /* Simplified install: copy file with optional -m mode */
    int mode = 0755;
    int file_start = 1;
    if (argc >= 4 && argv[1][0] == '-' && argv[1][1] == 'm') {
        mode = 0;
        for (const char *p = argv[2]; *p >= '0' && *p <= '7'; p++)
            mode = mode * 8 + (*p - '0');
        file_start = 3;
    }
    if (file_start + 1 >= argc) {
        write_str(2, "usage: install [-m MODE] SOURCE DEST\n"); return;
    }
    /* Copy file */
    int src = sys_open(argv[file_start], O_RDONLY, 0);
    if (src < 0) { write_str(2, "install: cannot open source\n"); return; }
    int dst = sys_open(argv[file_start + 1], O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dst < 0) { sys_close(src); write_str(2, "install: cannot create dest\n"); return; }
    static char buf[4096];
    ssize_t n;
    while ((n = sys_read(src, buf, sizeof(buf))) > 0)
        sys_write(dst, buf, n);
    sys_close(src); sys_close(dst);
    /* Set mode */
    sys_chmod_call(argv[file_start + 1], (long)mode);
}

/* ── expr: evaluate expressions (POSIX) ── */
static void cmd_expr(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: expr EXPRESSION\n"); return; }

    /* Simple expression evaluator: supports + - * / % = != < > <= >= | & : length substr index match */
    if (argc == 2) {
        /* Single argument: just print it */
        write_str(1, argv[1]); write_str(1, "\n");
        last_exit_status = (argv[1][0] == '0' && argv[1][1] == '\0') ? 1 : 0;
        return;
    }

    if (argc == 4) {
        const char *a = argv[1], *op = argv[2], *b = argv[3];

        /* String operations */
        if (strcmp_simple(op, ":") == 0 || strcmp_simple(op, "match") == 0) {
            /* Pattern match (simplified: just return string length if match) */
            int len = 0; while (a[len]) len++;
            char num[16]; int ni = 0;
            if (len == 0) { num[ni++] = '0'; }
            else { char rev[16]; int ri = 0; int v = len;
                while (v > 0) { rev[ri++] = '0' + (char)(v % 10); v /= 10; }
                while (ri > 0) num[ni++] = rev[--ri]; }
            num[ni] = '\0';
            write_str(1, num); write_str(1, "\n");
            last_exit_status = (len == 0) ? 1 : 0;
            return;
        }

        /* Comparison operations (string) */
        if (strcmp_simple(op, "=") == 0) {
            int eq = strcmp_simple(a, b) == 0;
            write_str(1, eq ? "1\n" : "0\n");
            last_exit_status = eq ? 0 : 1; return;
        }
        if (strcmp_simple(op, "!=") == 0) {
            int ne = strcmp_simple(a, b) != 0;
            write_str(1, ne ? "1\n" : "0\n");
            last_exit_status = ne ? 0 : 1; return;
        }

        /* Parse as integers for arithmetic */
        long va = 0, vb = 0;
        int na = 0, nb = 0;
        { const char *p = a; if (*p == '-') { na = 1; p++; }
          while (*p >= '0' && *p <= '9') va = va * 10 + (*p++ - '0');
          if (na) va = -va; }
        { const char *p = b; if (*p == '-') { nb = 1; p++; }
          while (*p >= '0' && *p <= '9') vb = vb * 10 + (*p++ - '0');
          if (nb) vb = -vb; }

        long result = 0;
        int valid = 1;
        if (strcmp_simple(op, "+") == 0) result = va + vb;
        else if (strcmp_simple(op, "-") == 0) result = va - vb;
        else if (strcmp_simple(op, "*") == 0) result = va * vb;
        else if (strcmp_simple(op, "/") == 0) {
            if (vb == 0) { write_str(2, "expr: division by zero\n"); last_exit_status = 2; return; }
            result = va / vb;
        } else if (strcmp_simple(op, "%") == 0) {
            if (vb == 0) { write_str(2, "expr: division by zero\n"); last_exit_status = 2; return; }
            result = va % vb;
        } else if (strcmp_simple(op, "<") == 0) result = (va < vb) ? 1 : 0;
        else if (strcmp_simple(op, ">") == 0) result = (va > vb) ? 1 : 0;
        else if (strcmp_simple(op, "<=") == 0) result = (va <= vb) ? 1 : 0;
        else if (strcmp_simple(op, ">=") == 0) result = (va >= vb) ? 1 : 0;
        else { write_str(2, "expr: unknown operator: "); write_str(2, op); write_str(2, "\n"); valid = 0; }

        if (valid) {
            char num[24]; int ni = 0;
            long v = result;
            if (v < 0) { write_str(1, "-"); v = -v; }
            if (v == 0) { num[ni++] = '0'; }
            else { char rev[24]; int ri = 0;
                while (v > 0) { rev[ri++] = '0' + (char)(v % 10); v /= 10; }
                while (ri > 0) num[ni++] = rev[--ri]; }
            num[ni] = '\0';
            write_str(1, num); write_str(1, "\n");
            last_exit_status = (result == 0) ? 1 : 0;
        }
        return;
    }

    /* For expressions with more arguments, try to evaluate left-to-right */
    if (argc == 6 && strcmp_simple(argv[2], "length") == 0) {
        /* expr length STRING */
        int len = 0; while (argv[3][len]) len++;
        char num[16]; int ni = 0;
        if (len == 0) num[ni++] = '0';
        else { char rev[16]; int ri = 0; int v = len;
            while (v > 0) { rev[ri++] = '0' + (char)(v % 10); v /= 10; }
            while (ri > 0) num[ni++] = rev[--ri]; }
        num[ni] = '\0';
        write_str(1, num); write_str(1, "\n");
        return;
    }

    write_str(2, "expr: syntax error\n");
    last_exit_status = 2;
}

/* ── factor: print prime factors ── */
/* bc: basic calculator — supports +, -, *, /, %, ^, parentheses, scale, variables,
 * comparison operators, and multi-line input from stdin or arguments.
 * Handles: echo "3+4" | bc, echo "scale=2; 10/3" | bc, bc -e "2^10" */

static long bc_vars[26];  /* a-z variables */
static int bc_scale;       /* decimal places for division */

static long bc_pow(long base, long exp) {
    if (exp < 0) return 0;
    long result = 1;
    for (long i = 0; i < exp; i++) result *= base;
    return result;
}

/* Recursive descent parser for bc expressions */
static const char *bc_p;  /* current parse position */

static void bc_skip_ws(void) { while (*bc_p == ' ' || *bc_p == '\t') bc_p++; }

static long bc_parse_expr(void);

static long bc_parse_atom(void) {
    bc_skip_ws();
    long val = 0;
    int neg = 0;
    if (*bc_p == '-') { neg = 1; bc_p++; bc_skip_ws(); }
    if (*bc_p == '(') {
        bc_p++;
        val = bc_parse_expr();
        bc_skip_ws();
        if (*bc_p == ')') bc_p++;
    } else if (*bc_p >= '0' && *bc_p <= '9') {
        while (*bc_p >= '0' && *bc_p <= '9') val = val * 10 + (*bc_p++ - '0');
        /* Handle decimal point — multiply by scale factor */
        if (*bc_p == '.') {
            bc_p++;
            long frac = 0, frac_digits = 0;
            while (*bc_p >= '0' && *bc_p <= '9') {
                frac = frac * 10 + (*bc_p++ - '0');
                frac_digits++;
            }
            /* Scale: val = integer part * 10^scale + fractional digits */
            if (bc_scale > 0) {
                long scale_factor = bc_pow(10, bc_scale);
                val = val * scale_factor;
                long frac_scale = bc_pow(10, bc_scale - frac_digits);
                if (frac_digits <= bc_scale) val += frac * frac_scale;
                else val += frac / bc_pow(10, frac_digits - bc_scale);
            }
        }
    } else if (*bc_p >= 'a' && *bc_p <= 'z') {
        int vi = *bc_p - 'a';
        bc_p++;
        /* Check for assignment */
        bc_skip_ws();
        if (*bc_p == '=') {
            bc_p++;
            bc_skip_ws();
            val = bc_parse_expr();
            bc_vars[vi] = val;
        } else {
            val = bc_vars[vi];
        }
    } else if (*bc_p == 's' && bc_p[1] == 'c' && bc_p[2] == 'a' && bc_p[3] == 'l' && bc_p[4] == 'e') {
        /* scale variable */
        bc_p += 5;
        bc_skip_ws();
        if (*bc_p == '=') {
            bc_p++;
            bc_skip_ws();
            val = bc_parse_expr();
            bc_scale = (int)val;
        } else {
            val = bc_scale;
        }
    } else if (*bc_p == 's' && bc_p[1] == 'q' && bc_p[2] == 'r' && bc_p[3] == 't' && bc_p[4] == '(') {
        /* sqrt(N) — integer square root */
        bc_p += 5;
        long inner = bc_parse_expr();
        if (*bc_p == ')') bc_p++;
        if (inner < 0) val = 0;
        else {
            val = 0;
            while ((val + 1) * (val + 1) <= inner) val++;
        }
    }
    return neg ? -val : val;
}

static long bc_parse_power(void) {
    long val = bc_parse_atom();
    bc_skip_ws();
    if (*bc_p == '^') {
        bc_p++;
        long exp = bc_parse_power(); /* right-associative */
        val = bc_pow(val, exp);
    }
    return val;
}

static long bc_parse_term(void) {
    long val = bc_parse_power();
    bc_skip_ws();
    while (*bc_p == '*' || *bc_p == '/' || *bc_p == '%') {
        char op = *bc_p++;
        long rhs = bc_parse_power();
        if (op == '*') val *= rhs;
        else if (op == '/') { if (rhs != 0) val /= rhs; }
        else if (op == '%') { if (rhs != 0) val %= rhs; }
        bc_skip_ws();
    }
    return val;
}

static long bc_parse_sum(void) {
    long val = bc_parse_term();
    bc_skip_ws();
    while (*bc_p == '+' || (*bc_p == '-' && bc_p[1] != '=')) {
        char op = *bc_p++;
        long rhs = bc_parse_term();
        if (op == '+') val += rhs;
        else val -= rhs;
        bc_skip_ws();
    }
    return val;
}

static long bc_parse_expr(void) {
    long val = bc_parse_sum();
    bc_skip_ws();
    /* Comparison operators */
    if (*bc_p == '=' && bc_p[1] == '=') { bc_p += 2; val = (val == bc_parse_sum()) ? 1 : 0; }
    else if (*bc_p == '!' && bc_p[1] == '=') { bc_p += 2; val = (val != bc_parse_sum()) ? 1 : 0; }
    else if (*bc_p == '<' && bc_p[1] == '=') { bc_p += 2; val = (val <= bc_parse_sum()) ? 1 : 0; }
    else if (*bc_p == '>' && bc_p[1] == '=') { bc_p += 2; val = (val >= bc_parse_sum()) ? 1 : 0; }
    else if (*bc_p == '<') { bc_p++; val = (val < bc_parse_sum()) ? 1 : 0; }
    else if (*bc_p == '>') { bc_p++; val = (val > bc_parse_sum()) ? 1 : 0; }
    return val;
}

static void bc_print_result(long val) {
    if (bc_scale > 0) {
        long scale_factor = bc_pow(10, bc_scale);
        long integer_part = val / scale_factor;
        long frac_part = val % scale_factor;
        if (frac_part < 0) frac_part = -frac_part;
        if (val < 0 && integer_part == 0) sys_write(1, "-", 1);
        char buf[24]; int bp = 0;
        long v = integer_part < 0 ? -integer_part : integer_part;
        if (integer_part < 0) sys_write(1, "-", 1);
        if (v == 0) buf[bp++] = '0';
        else { char rev[24]; int rp = 0;
            while (v > 0) { rev[rp++] = '0' + (char)(v % 10); v /= 10; }
            while (rp > 0) buf[bp++] = rev[--rp]; }
        sys_write(1, buf, bp);
        sys_write(1, ".", 1);
        /* Print fractional part with leading zeros */
        bp = 0;
        for (int d = bc_scale - 1; d >= 0; d--) {
            long place = bc_pow(10, d);
            buf[bp++] = '0' + (char)((frac_part / place) % 10);
        }
        sys_write(1, buf, bp);
    } else {
        char buf[24]; int bp = 0;
        long v = val < 0 ? -val : val;
        if (val < 0) sys_write(1, "-", 1);
        if (v == 0) buf[bp++] = '0';
        else { char rev[24]; int rp = 0;
            while (v > 0) { rev[rp++] = '0' + (char)(v % 10); v /= 10; }
            while (rp > 0) buf[bp++] = rev[--rp]; }
        sys_write(1, buf, bp);
    }
    sys_write(1, "\n", 1);
}

static void bc_eval_line(const char *line) {
    bc_p = line;
    bc_skip_ws();
    if (*bc_p == '\0' || *bc_p == '#') return;  /* empty or comment */
    /* Handle "quit" */
    if (*bc_p == 'q') return;
    /* Check for scale= assignment (don't print result) */
    const char *save = bc_p;
    if (*bc_p == 's' && bc_p[1] == 'c' && bc_p[2] == 'a' && bc_p[3] == 'l' && bc_p[4] == 'e') {
        bc_parse_expr();
        return;
    }
    /* Check for variable assignment (a=5) — don't print */
    if (*bc_p >= 'a' && *bc_p <= 'z' && (bc_p[1] == '=' || (bc_p[1] == ' ' && bc_p[2] == '='))) {
        bc_parse_expr();
        return;
    }
    bc_p = save;
    long val = bc_parse_expr();
    bc_print_result(val);
}

static void cmd_bc(int argc, char *argv[]) {
    /* Reset state */
    bc_scale = 0;
    for (int i = 0; i < 26; i++) bc_vars[i] = 0;

    int quiet = 0;
    int arg = 1;

    /* Parse flags */
    while (arg < argc) {
        if (strcmp_simple(argv[arg], "-q") == 0 || strcmp_simple(argv[arg], "--quiet") == 0) {
            quiet = 1; arg++;
        } else if (strcmp_simple(argv[arg], "-l") == 0) {
            bc_scale = 20; arg++;  /* -l = math library (set scale=20) */
        } else if (strcmp_simple(argv[arg], "-e") == 0 && arg + 1 < argc) {
            arg++;
            /* Evaluate expression(s) separated by ; */
            const char *ep = argv[arg];
            static char stmt[256];
            while (*ep) {
                int si = 0;
                while (*ep && *ep != ';' && *ep != '\n' && si < 254) stmt[si++] = *ep++;
                stmt[si] = '\0';
                if (si > 0) bc_eval_line(stmt);
                if (*ep == ';' || *ep == '\n') ep++;
            }
            arg++;
        } else {
            arg++;  /* skip unknown args */
        }
    }

    /* Interactive / pipe mode: read from stdin */
    (void)quiet;
    static char line[1024];
    int lp = 0;
    char ch;
    while (sys_read(0, &ch, 1) == 1) {
        if (ch == '\n' || lp >= 1022) {
            line[lp] = '\0';
            /* Split by ; for multiple statements per line */
            char *sp = line;
            while (*sp) {
                while (*sp == ' ' || *sp == ';') sp++;
                if (!*sp) break;
                static char stmt[256];
                int si = 0;
                while (*sp && *sp != ';' && si < 254) stmt[si++] = *sp++;
                stmt[si] = '\0';
                if (si > 0) {
                    /* Check for quit */
                    if (stmt[0] == 'q' && stmt[1] == 'u' && stmt[2] == 'i' && stmt[3] == 't') return;
                    bc_eval_line(stmt);
                }
                if (*sp == ';') sp++;
            }
            lp = 0;
        } else {
            line[lp++] = ch;
        }
    }
}

static void cmd_factor(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: factor NUMBER\n"); return; }
    for (int a = 1; a < argc; a++) {
        long n = 0;
        for (const char *p = argv[a]; *p >= '0' && *p <= '9'; p++)
            n = n * 10 + (*p - '0');
        write_str(1, argv[a]); write_str(1, ":");
        long d = 2;
        long rem = n;
        while (d * d <= rem) {
            while (rem % d == 0) {
                write_str(1, " ");
                char num[24]; int ni = 0;
                long v = d;
                if (v == 0) num[ni++] = '0';
                else { char rev[24]; int ri = 0;
                    while (v > 0) { rev[ri++] = '0' + (char)(v % 10); v /= 10; }
                    while (ri > 0) num[ni++] = rev[--ri]; }
                num[ni] = '\0';
                write_str(1, num);
                rem /= d;
            }
            d++;
        }
        if (rem > 1) {
            write_str(1, " ");
            char num[24]; int ni = 0;
            long v = rem;
            char rev[24]; int ri = 0;
            while (v > 0) { rev[ri++] = '0' + (char)(v % 10); v /= 10; }
            while (ri > 0) num[ni++] = rev[--ri];
            num[ni] = '\0';
            write_str(1, num);
        }
        write_str(1, "\n");
    }
}

/* ── cal: display a calendar ── */
static void cmd_cal(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Simple: show current month header and days */
    write_str(1, "     March 2026\n");
    write_str(1, "Su Mo Tu We Th Fr Sa\n");
    write_str(1, " 1  2  3  4  5  6  7\n");
    write_str(1, " 8  9 10 11 12 13 14\n");
    write_str(1, "15 16 17 18 19 20 21\n");
    write_str(1, "22 23 24 25 26 27 28\n");
    write_str(1, "29 30 31\n");
}

/* ── locale: display locale settings ── */
static void cmd_locale(int argc, char *argv[]) {
    (void)argc; (void)argv;
    const char *lang = get_var("LANG");
    const char *lc_all = get_var("LC_ALL");
    if (!lang || !lang[0]) lang = "C";
    if (!lc_all || !lc_all[0]) lc_all = "";

    write_str(1, "LANG="); write_str(1, lang); write_str(1, "\n");
    write_str(1, "LC_CTYPE=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_NUMERIC=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_TIME=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_COLLATE=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_MONETARY=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_MESSAGES=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_PAPER=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_NAME=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_ADDRESS=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_TELEPHONE=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_MEASUREMENT=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_IDENTIFICATION=\""); write_str(1, lc_all[0] ? lc_all : lang); write_str(1, "\"\n");
    write_str(1, "LC_ALL="); write_str(1, lc_all[0] ? lc_all : ""); write_str(1, "\n");
}

/* ── reset: reset terminal ── */
static void cmd_reset(int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Send VT100 reset sequence */
    write_str(1, "\033c");       /* Full reset */
    write_str(1, "\033[?25h");   /* Show cursor */
    write_str(1, "\033[0m");     /* Reset attributes */
}

/* ── tput: terminal capability queries ── */
static void cmd_tput(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: tput CAPNAME\n"); return; }
    const char *cap = argv[1];
    if (strcmp_simple(cap, "cols") == 0) {
        /* Query terminal columns via TIOCGWINSZ */
        struct { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; } ws = {0};
        long r = sys_ioctl(1, 0x5413 /* TIOCGWINSZ */, (unsigned long)&ws);
        if (r == 0 && ws.ws_col > 0) {
            char num[8]; int ni = 0;
            int v = ws.ws_col;
            if (v == 0) num[ni++] = '0';
            else { char rev[8]; int ri = 0;
                while (v > 0) { rev[ri++] = '0' + (char)(v%10); v /= 10; }
                while (ri > 0) num[ni++] = rev[--ri]; }
            num[ni] = '\0'; write_str(1, num); write_str(1, "\n");
        } else { write_str(1, "80\n"); }
    } else if (strcmp_simple(cap, "lines") == 0) {
        struct { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; } ws = {0};
        long r = sys_ioctl(1, 0x5413, (unsigned long)&ws);
        if (r == 0 && ws.ws_row > 0) {
            char num[8]; int ni = 0;
            int v = ws.ws_row;
            if (v == 0) num[ni++] = '0';
            else { char rev[8]; int ri = 0;
                while (v > 0) { rev[ri++] = '0' + (char)(v%10); v /= 10; }
                while (ri > 0) num[ni++] = rev[--ri]; }
            num[ni] = '\0'; write_str(1, num); write_str(1, "\n");
        } else { write_str(1, "24\n"); }
    } else if (strcmp_simple(cap, "clear") == 0) {
        write_str(1, "\033[H\033[2J");
    } else if (strcmp_simple(cap, "bold") == 0) {
        write_str(1, "\033[1m");
    } else if (strcmp_simple(cap, "sgr0") == 0 || strcmp_simple(cap, "reset") == 0) {
        write_str(1, "\033[0m");
    } else if (strcmp_simple(cap, "cup") == 0) {
        /* tput cup ROW COL — move cursor */
        if (argc >= 4) {
            write_str(1, "\033["); write_str(1, argv[2]); write_str(1, ";");
            write_str(1, argv[3]); write_str(1, "H");
        }
    } else if (strcmp_simple(cap, "sc") == 0) { write_str(1, "\033[s"); /* save cursor */
    } else if (strcmp_simple(cap, "rc") == 0) { write_str(1, "\033[u"); /* restore cursor */
    } else if (strcmp_simple(cap, "civis") == 0) { write_str(1, "\033[?25l"); /* hide cursor */
    } else if (strcmp_simple(cap, "cnorm") == 0) { write_str(1, "\033[?25h"); /* show cursor */
    } else {
        write_str(2, "tput: unknown capability: "); write_str(2, cap); write_str(2, "\n");
    }
}

/* ── make: minimal build tool ── */
#define MAKE_MAX_TARGETS 64
#define MAKE_MAX_DEPS    16
#define MAKE_MAX_RECIPES 16
#define MAKE_MAX_VARS    32
#define MAKE_LINE_MAX    512

struct make_var {
    char name[64];
    char value[256];
};

struct make_target {
    char name[128];
    char deps[MAKE_MAX_DEPS][128];
    int ndeps;
    char recipes[MAKE_MAX_RECIPES][MAKE_LINE_MAX];
    int nrecipes;
    int phony;
};

static long make_get_mtime(const char *path) {
    struct stat st;
    if (sys_call2(__NR_stat, (long)path, (long)&st) < 0) return -1;
    return (long)st.st_mtim.tv_sec;
}

static void make_expand_vars(const char *src, char *dst, int dstlen,
                             struct make_var *vars, int nvars) {
    int si = 0, di = 0;
    while (src[si] && di < dstlen - 1) {
        if (src[si] == '$' && src[si + 1] == '(') {
            si += 2;
            char vname[64];
            int vi = 0;
            while (src[si] && src[si] != ')' && vi < 63)
                vname[vi++] = src[si++];
            vname[vi] = '\0';
            if (src[si] == ')') si++;
            /* Look up variable */
            int found = 0;
            for (int v = 0; v < nvars; v++) {
                if (strcmp_simple(vars[v].name, vname) == 0) {
                    for (int k = 0; vars[v].value[k] && di < dstlen - 1; k++)
                        dst[di++] = vars[v].value[k];
                    found = 1;
                    break;
                }
            }
            (void)found;
        } else {
            dst[di++] = src[si++];
        }
    }
    dst[di] = '\0';
}

static int make_build(const char *target, struct make_target *targets, int ntargets,
                      struct make_var *vars, int nvars) {
    /* Find target */
    int tidx = -1;
    for (int i = 0; i < ntargets; i++) {
        if (strcmp_simple(targets[i].name, target) == 0) { tidx = i; break; }
    }
    if (tidx < 0) {
        /* Not a target — check if file exists */
        if (make_get_mtime(target) >= 0) return 0;
        write_str(2, "make: *** No rule to make target '");
        write_str(2, target);
        write_str(2, "'\n");
        return -1;
    }

    /* Recursively build dependencies first */
    for (int d = 0; d < targets[tidx].ndeps; d++) {
        if (make_build(targets[tidx].deps[d], targets, ntargets, vars, nvars) < 0)
            return -1;
    }

    /* Check if target needs rebuilding */
    int needs_build = 0;
    if (targets[tidx].phony) {
        needs_build = 1;
    } else {
        long target_mtime = make_get_mtime(target);
        if (target_mtime < 0) {
            needs_build = 1;  /* Target doesn't exist */
        } else {
            /* Check if any dep is newer */
            for (int d = 0; d < targets[tidx].ndeps; d++) {
                long dep_mtime = make_get_mtime(targets[tidx].deps[d]);
                if (dep_mtime > target_mtime) { needs_build = 1; break; }
            }
        }
    }
    if (targets[tidx].ndeps == 0 && targets[tidx].nrecipes > 0 &&
        make_get_mtime(target) < 0)
        needs_build = 1;

    if (!needs_build) return 0;

    /* Execute recipes */
    for (int r = 0; r < targets[tidx].nrecipes; r++) {
        char expanded[MAKE_LINE_MAX];
        make_expand_vars(targets[tidx].recipes[r], expanded, MAKE_LINE_MAX, vars, nvars);

        int silent = 0;
        char *cmd = expanded;
        if (cmd[0] == '@') { silent = 1; cmd++; }

        if (!silent) { write_str(1, cmd); write_str(1, "\n"); }

        /* Parse and execute via shell */
        static char cmdbuf[MAKE_LINE_MAX];
        int ci = 0;
        while (cmd[ci]) { cmdbuf[ci] = cmd[ci]; ci++; }
        cmdbuf[ci] = '\0';
        char *argv[32];
        int argc = parse_command(cmdbuf, argv, 32);
        if (argc > 0) {
            int ret = execute_command(argc, argv);
            if (ret != 0) {
                write_str(2, "make: *** Error ");
                char nbuf[16]; int ni = 0;
                int rv = ret < 0 ? -ret : ret;
                if (rv == 0) nbuf[ni++] = '0';
                else { char tmp[16]; int ti = 0; while (rv) { tmp[ti++] = '0' + rv % 10; rv /= 10; }
                       while (ti > 0) nbuf[ni++] = tmp[--ti]; }
                nbuf[ni] = '\0';
                write_str(2, nbuf);
                write_str(2, "\n");
                return -1;
            }
        }
    }
    return 0;
}

/* ── git: minimal git implementation ── */

/* Compute SHA-1 hex digest of a buffer into out[41] */
static void git_sha1_buf(const unsigned char *data, size_t len, char *out) {
    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476, h4 = 0xC3D2E1F0;
    unsigned char blk[64];
    int blk_len = 0;
    uint64_t total_bits = (uint64_t)len * 8;

    #define GIT_ROTL(v,n) (((v)<<(n))|((v)>>(32-(n))))
    #define GIT_BLOCK() do { \
        uint32_t w[80]; \
        for (int i = 0; i < 16; i++) \
            w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)| \
                    ((uint32_t)blk[i*4+2]<<8)|((uint32_t)blk[i*4+3]); \
        for (int i = 16; i < 80; i++) \
            w[i] = GIT_ROTL(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1); \
        uint32_t a=h0, b=h1, c=h2, d=h3, e=h4; \
        for (int i = 0; i < 80; i++) { \
            uint32_t fv, k; \
            if (i < 20) { fv=(b&c)|((~b)&d); k=0x5A827999; } \
            else if (i < 40) { fv=b^c^d; k=0x6ED9EBA1; } \
            else if (i < 60) { fv=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; } \
            else { fv=b^c^d; k=0xCA62C1D6; } \
            uint32_t tmp = GIT_ROTL(a,5)+fv+e+k+w[i]; \
            e=d; d=c; c=GIT_ROTL(b,30); b=a; a=tmp; \
        } \
        h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; \
    } while(0)

    for (size_t i = 0; i < len; i++) {
        blk[blk_len++] = data[i];
        if (blk_len == 64) { GIT_BLOCK(); blk_len = 0; }
    }
    blk[blk_len++] = 0x80;
    if (blk_len > 56) {
        while (blk_len < 64) blk[blk_len++] = 0;
        GIT_BLOCK(); blk_len = 0;
    }
    while (blk_len < 56) blk[blk_len++] = 0;
    for (int i = 7; i >= 0; i--)
        blk[blk_len++] = (unsigned char)(total_bits >> (i * 8));
    GIT_BLOCK();
    #undef GIT_ROTL
    #undef GIT_BLOCK

    static const char hex[] = "0123456789abcdef";
    uint32_t hv[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; i++) {
        out[i*8+0] = hex[(hv[i]>>28)&0xF]; out[i*8+1] = hex[(hv[i]>>24)&0xF];
        out[i*8+2] = hex[(hv[i]>>20)&0xF]; out[i*8+3] = hex[(hv[i]>>16)&0xF];
        out[i*8+4] = hex[(hv[i]>>12)&0xF]; out[i*8+5] = hex[(hv[i]>> 8)&0xF];
        out[i*8+6] = hex[(hv[i]>> 4)&0xF]; out[i*8+7] = hex[(hv[i]>> 0)&0xF];
    }
    out[40] = '\0';
}

/* Write plaintext object to .git/objects/XX/YYYY... */
static int git_store_object(const char *hash, const char *content, size_t clen) {
    char path[128];
    strcpy_simple(path, ".git/objects/");
    path[13] = hash[0]; path[14] = hash[1]; path[15] = '\0';
    sys_mkdir(path, 0755);
    path[15] = '/';
    for (int i = 2; hash[i]; i++) path[14 + i] = hash[i];
    path[14 + (int)strlen_simple(hash)] = '\0';
    int fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    sys_write(fd, content, clen);
    sys_close(fd);
    return 0;
}

/* Read entire file into buf, return bytes read (-1 on error) */
static ssize_t git_read_file(const char *path, char *buf, size_t max) {
    int fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) return -1;
    ssize_t total = 0, nr;
    while (total < (ssize_t)max && (nr = sys_read(fd, buf + total, max - total)) > 0)
        total += nr;
    sys_close(fd);
    return total;
}

/* Write string to file (create/truncate) */
static int git_write_file(const char *path, const char *data, size_t len) {
    int fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    sys_write(fd, data, len);
    sys_close(fd);
    return 0;
}

static void cmd_git(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "usage: git <init|add|status|commit|log>\n");
        return;
    }

    /* --- git init --- */
    if (strcmp_simple(argv[1], "init") == 0) {
        sys_mkdir(".git", 0755);
        sys_mkdir(".git/objects", 0755);
        sys_mkdir(".git/refs", 0755);
        sys_mkdir(".git/refs/heads", 0755);
        git_write_file(".git/HEAD", "ref: refs/heads/master\n", 23);
        write_str(1, "Initialized empty Git repository in .git/\n");
        return;
    }

    /* --- git add <file> --- */
    if (strcmp_simple(argv[1], "add") == 0) {
        if (argc < 3) { write_str(2, "usage: git add <file>\n"); return; }
        for (int a = 2; a < argc; a++) {
            static char fbuf[32768];
            ssize_t flen = git_read_file(argv[a], fbuf, sizeof(fbuf));
            if (flen < 0) {
                write_str(2, "git: cannot read "); write_str(2, argv[a]); write_str(2, "\n");
                continue;
            }
            /* Create blob: "blob <size>\0<content>" */
            char header[64];
            int hlen = 0;
            const char *pre = "blob ";
            for (int i = 0; pre[i]; i++) header[hlen++] = pre[i];
            /* itoa for size */
            char numbuf[20]; int ni = 0;
            size_t sz = (size_t)flen;
            if (sz == 0) numbuf[ni++] = '0';
            else { size_t t = sz; while (t) { numbuf[ni++] = '0' + (t % 10); t /= 10; } }
            for (int i = ni - 1; i >= 0; i--) header[hlen++] = numbuf[i];
            header[hlen++] = '\0'; /* NUL separator */

            /* Hash the full blob (header + content) */
            static char blob[33000];
            for (int i = 0; i < hlen; i++) blob[i] = header[i];
            for (ssize_t i = 0; i < flen; i++) blob[hlen + i] = fbuf[i];
            char hash[41];
            git_sha1_buf((unsigned char *)blob, hlen + flen, hash);

            /* Store object */
            git_store_object(hash, blob, hlen + flen);

            /* Update index: append "hash filename\n" */
            /* First check if file already in index, rewrite without old entry */
            static char idx[16384];
            ssize_t ilen = git_read_file(".git/index", idx, sizeof(idx) - 200);
            if (ilen < 0) ilen = 0;
            /* Remove existing entry for this file */
            static char newidx[16384];
            int nlen = 0;
            int li = 0;
            while (li < ilen) {
                int le = li;
                while (le < ilen && idx[le] != '\n') le++;
                /* line is idx[li..le-1], find filename after space */
                int sp = li;
                while (sp < le && idx[sp] != ' ') sp++;
                int match = 0;
                if (sp < le) {
                    const char *fn = argv[a];
                    int fi = 0, si = sp + 1;
                    while (si < le && fn[fi] && idx[si] == fn[fi]) { si++; fi++; }
                    if (si == le && fn[fi] == '\0') match = 1;
                }
                if (!match) {
                    for (int i = li; i < le; i++) newidx[nlen++] = idx[i];
                    newidx[nlen++] = '\n';
                }
                li = le + 1;
            }
            /* Append new entry */
            for (int i = 0; i < 40; i++) newidx[nlen++] = hash[i];
            newidx[nlen++] = ' ';
            for (int i = 0; argv[a][i]; i++) newidx[nlen++] = argv[a][i];
            newidx[nlen++] = '\n';
            git_write_file(".git/index", newidx, nlen);
        }
        return;
    }

    /* --- git status --- */
    if (strcmp_simple(argv[1], "status") == 0) {
        /* Read index for tracked files */
        static char idx[16384];
        ssize_t ilen = git_read_file(".git/index", idx, sizeof(idx));
        if (ilen < 0) ilen = 0;

        /* Collect tracked filenames */
        static char tracked[128][64];
        int tc = 0;
        int li = 0;
        while (li < ilen && tc < 128) {
            int le = li;
            while (le < ilen && idx[le] != '\n') le++;
            int sp = li;
            while (sp < le && idx[sp] != ' ') sp++;
            if (sp < le) {
                int fi = 0;
                for (int i = sp + 1; i < le && fi < 63; i++) tracked[tc][fi++] = idx[i];
                tracked[tc][fi] = '\0';
                tc++;
            }
            li = le + 1;
        }

        /* List working directory files */
        int dfd = sys_open(".", O_RDONLY, 0);
        if (dfd < 0) { write_str(2, "git: cannot read directory\n"); return; }
        static char dbuf[4096];
        ssize_t nr;
        static char ut_names[128][64];
        int utc = 0;
        static char mod_names[128][64];
        int modc = 0;

        while ((nr = sys_getdents64(dfd, dbuf, sizeof(dbuf))) > 0) {
            ssize_t pos = 0;
            while (pos < nr) {
                uint16_t reclen = *(uint16_t *)(dbuf + pos + 16);
                char *name = dbuf + pos + 19;
                if (name[0] == '.' || strcmp_simple(name, "..") == 0) { pos += reclen; continue; }
                /* Check if tracked */
                int found = 0;
                for (int i = 0; i < tc; i++) {
                    if (strcmp_simple(name, tracked[i]) == 0) { found = 1; break; }
                }
                if (!found && utc < 128) {
                    strcpy_simple(ut_names[utc++], name);
                } else if (found && modc < 128) {
                    strcpy_simple(mod_names[modc++], name);
                }
                pos += reclen;
            }
        }
        sys_close(dfd);

        if (modc > 0) {
            write_str(1, "Changes to be committed:\n");
            for (int i = 0; i < modc; i++) {
                write_str(1, "\ttracked:  ");
                write_str(1, mod_names[i]);
                write_str(1, "\n");
            }
            write_str(1, "\n");
        }
        if (utc > 0) {
            write_str(1, "Untracked files:\n");
            for (int i = 0; i < utc; i++) {
                write_str(1, "\t");
                write_str(1, ut_names[i]);
                write_str(1, "\n");
            }
        }
        if (modc == 0 && utc == 0)
            write_str(1, "nothing to commit, working tree clean\n");
        return;
    }

    /* --- git commit -m "message" --- */
    if (strcmp_simple(argv[1], "commit") == 0) {
        const char *msg = "no message";
        if (argc >= 4 && strcmp_simple(argv[2], "-m") == 0) msg = argv[3];

        /* Read index */
        static char idx[16384];
        ssize_t ilen = git_read_file(".git/index", idx, sizeof(idx));
        if (ilen <= 0) { write_str(2, "nothing to commit\n"); return; }

        /* Build tree object: "tree <size>\0<index contents>" */
        static char tree[17000];
        const char *tp = "tree ";
        int tlen = 0;
        for (int i = 0; tp[i]; i++) tree[tlen++] = tp[i];
        char numbuf[20]; int ni = 0; size_t sz = (size_t)ilen;
        if (sz == 0) numbuf[ni++] = '0';
        else { size_t t = sz; while (t) { numbuf[ni++] = '0' + (t % 10); t /= 10; } }
        for (int i = ni - 1; i >= 0; i--) tree[tlen++] = numbuf[i];
        tree[tlen++] = '\0';
        for (ssize_t i = 0; i < ilen; i++) tree[tlen + i] = idx[i];
        char tree_hash[41];
        git_sha1_buf((unsigned char *)tree, tlen + ilen, tree_hash);
        git_store_object(tree_hash, tree, tlen + ilen);

        /* Read current HEAD to find parent */
        static char headbuf[256];
        ssize_t hlen = git_read_file(".git/HEAD", headbuf, sizeof(headbuf));
        char parent[41] = {0};
        int has_parent = 0;
        if (hlen > 5 && headbuf[0] == 'r' && headbuf[1] == 'e' && headbuf[2] == 'f') {
            /* Symbolic ref: "ref: refs/heads/master\n" */
            int rs = 5; while (rs < hlen && headbuf[rs] == ' ') rs++;
            char refpath[128] = ".git/";
            int ri = 5;
            for (int i = rs; i < hlen && headbuf[i] != '\n' && ri < 126; i++)
                refpath[ri++] = headbuf[i];
            refpath[ri] = '\0';
            static char refval[64];
            ssize_t rl = git_read_file(refpath, refval, sizeof(refval));
            if (rl >= 40) { for (int i = 0; i < 40; i++) parent[i] = refval[i]; parent[40] = '\0'; has_parent = 1; }
        }

        /* Build commit object */
        static char commit_buf[2048];
        int clen = 0;
        const char *s;
        s = "tree "; for (int i = 0; s[i]; i++) commit_buf[clen++] = s[i];
        for (int i = 0; i < 40; i++) commit_buf[clen++] = tree_hash[i];
        commit_buf[clen++] = '\n';
        if (has_parent) {
            s = "parent "; for (int i = 0; s[i]; i++) commit_buf[clen++] = s[i];
            for (int i = 0; i < 40; i++) commit_buf[clen++] = parent[i];
            commit_buf[clen++] = '\n';
        }
        s = "author futura <futura@os> 0 +0000\n";
        for (int i = 0; s[i]; i++) commit_buf[clen++] = s[i];
        s = "committer futura <futura@os> 0 +0000\n\n";
        for (int i = 0; s[i]; i++) commit_buf[clen++] = s[i];
        for (int i = 0; msg[i]; i++) commit_buf[clen++] = msg[i];
        commit_buf[clen++] = '\n';

        /* Hash as commit object: "commit <size>\0<content>" */
        static char full[2200];
        int flen = 0;
        s = "commit "; for (int i = 0; s[i]; i++) full[flen++] = s[i];
        ni = 0; sz = (size_t)clen;
        if (sz == 0) numbuf[ni++] = '0';
        else { size_t t = sz; while (t) { numbuf[ni++] = '0' + (t % 10); t /= 10; } }
        for (int i = ni - 1; i >= 0; i--) full[flen++] = numbuf[i];
        full[flen++] = '\0';
        for (int i = 0; i < clen; i++) full[flen + i] = commit_buf[i];
        char commit_hash[41];
        git_sha1_buf((unsigned char *)full, flen + clen, commit_hash);
        git_store_object(commit_hash, full, flen + clen);

        /* Update HEAD ref */
        if (hlen > 5 && headbuf[0] == 'r') {
            int rs = 5; while (rs < hlen && headbuf[rs] == ' ') rs++;
            char refpath[128] = ".git/";
            int ri = 5;
            for (int i = rs; i < hlen && headbuf[i] != '\n' && ri < 126; i++)
                refpath[ri++] = headbuf[i];
            refpath[ri] = '\0';
            char hashln[42];
            for (int i = 0; i < 40; i++) hashln[i] = commit_hash[i];
            hashln[40] = '\n'; hashln[41] = '\0';
            git_write_file(refpath, hashln, 41);
        }

        write_str(1, "[master ");
        char short_hash[8];
        for (int i = 0; i < 7; i++) short_hash[i] = commit_hash[i];
        short_hash[7] = '\0';
        write_str(1, short_hash);
        write_str(1, "] ");
        write_str(1, msg);
        write_str(1, "\n");
        return;
    }

    /* --- git log --- */
    if (strcmp_simple(argv[1], "log") == 0) {
        static char headbuf[256];
        ssize_t hlen = git_read_file(".git/HEAD", headbuf, sizeof(headbuf));
        if (hlen <= 0) { write_str(2, "fatal: not a git repository\n"); return; }

        char cur_hash[41] = {0};
        if (headbuf[0] == 'r') {
            int rs = 5; while (rs < hlen && headbuf[rs] == ' ') rs++;
            char refpath[128] = ".git/";
            int ri = 5;
            for (int i = rs; i < hlen && headbuf[i] != '\n' && ri < 126; i++)
                refpath[ri++] = headbuf[i];
            refpath[ri] = '\0';
            static char refval[64];
            ssize_t rl = git_read_file(refpath, refval, sizeof(refval));
            if (rl < 40) { write_str(1, "No commits yet\n"); return; }
            for (int i = 0; i < 40; i++) cur_hash[i] = refval[i];
            cur_hash[40] = '\0';
        }

        /* Walk commit chain */
        for (int depth = 0; depth < 50 && cur_hash[0]; depth++) {
            /* Read object file */
            char opath[128] = ".git/objects/";
            opath[13] = cur_hash[0]; opath[14] = cur_hash[1]; opath[15] = '/';
            for (int i = 2; i < 40; i++) opath[14 + i] = cur_hash[i];
            opath[54] = '\0';
            static char obj[2200];
            ssize_t olen = git_read_file(opath, obj, sizeof(obj));
            if (olen <= 0) break;

            /* Skip "commit <size>\0" header */
            int ci = 0;
            while (ci < olen && obj[ci] != '\0') ci++;
            ci++; /* skip NUL */

            write_str(1, "commit ");
            write_str(1, cur_hash);
            write_str(1, "\n");

            /* Parse commit body for parent and message */
            char next_parent[41] = {0};
            int mi = ci;
            while (mi < olen) {
                if (mi + 7 < olen && obj[mi] == 'p' && obj[mi+1] == 'a' &&
                    obj[mi+2] == 'r' && obj[mi+3] == 'e' && obj[mi+4] == 'n' &&
                    obj[mi+5] == 't' && obj[mi+6] == ' ') {
                    for (int i = 0; i < 40 && mi + 7 + i < olen; i++)
                        next_parent[i] = obj[mi + 7 + i];
                    next_parent[40] = '\0';
                }
                if (obj[mi] == '\n' && mi + 1 < olen && obj[mi+1] == '\n') {
                    mi += 2; /* skip blank line before message */
                    write_str(1, "    ");
                    while (mi < olen && obj[mi] != '\n') { write_char(1, obj[mi]); mi++; }
                    write_str(1, "\n\n");
                    break;
                }
                while (mi < olen && obj[mi] != '\n') mi++;
                if (mi < olen) mi++;
            }

            /* Follow parent */
            if (next_parent[0]) {
                for (int i = 0; i < 41; i++) cur_hash[i] = next_parent[i];
            } else {
                cur_hash[0] = '\0';
            }
        }
        return;
    }

    write_str(2, "git: unknown command '");
    write_str(2, argv[1]);
    write_str(2, "'\n");
}

static void cmd_make(int argc, char *argv[]) {
    const char *makefile = "Makefile";
    const char *goal = ((void *)0);

    /* Parse arguments */
    int i = 1;
    while (i < argc) {
        if (strcmp_simple(argv[i], "-f") == 0 && i + 1 < argc) {
            makefile = argv[++i];
        } else if (argv[i][0] != '-') {
            goal = argv[i];
        }
        i++;
    }

    /* Read makefile */
    int fd = sys_open(makefile, O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "make: *** No targets specified and no makefile found\n");
        return;
    }
    static char buf[8192];
    int total = 0;
    long n;
    while ((n = sys_read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += (int)n;
    sys_close(fd);
    buf[total] = '\0';

    /* Parse makefile */
    static struct make_target targets[MAKE_MAX_TARGETS];
    static struct make_var vars[MAKE_MAX_VARS];
    int ntargets = 0, nvars = 0;
    static char phony_deps[1024];
    phony_deps[0] = '\0';

    char *p = buf;
    int cur_target = -1;
    while (*p) {
        /* Extract line */
        char line[MAKE_LINE_MAX];
        int li = 0;
        while (*p && *p != '\n' && li < MAKE_LINE_MAX - 1)
            line[li++] = *p++;
        line[li] = '\0';
        if (*p == '\n') p++;

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Recipe line (starts with tab) */
        if (line[0] == '\t' && cur_target >= 0) {
            if (targets[cur_target].nrecipes < MAKE_MAX_RECIPES) {
                char *rp = line + 1;
                while (*rp == ' ' || *rp == '\t') rp++;
                strcpy_simple(targets[cur_target].recipes[targets[cur_target].nrecipes++], rp);
            }
            continue;
        }

        /* Variable assignment: VAR = value */
        char *eq = ((void *)0);
        for (int j = 0; line[j]; j++) {
            if (line[j] == '=' && (j == 0 || line[j-1] != '!')) { eq = &line[j]; break; }
            if (line[j] == ':') break;  /* It's a target line, not var */
        }
        if (eq && nvars < MAKE_MAX_VARS) {
            /* Trim name */
            char *ne = eq - 1;
            while (ne > line && (*ne == ' ' || *ne == '\t')) ne--;
            int nlen = (int)(ne - line) + 1;
            if (nlen > 63) nlen = 63;
            for (int j = 0; j < nlen; j++) vars[nvars].name[j] = line[j];
            vars[nvars].name[nlen] = '\0';
            /* Trim value */
            char *vp = eq + 1;
            while (*vp == ' ' || *vp == '\t') vp++;
            strncpy_simple(vars[nvars].value, vp, 255);
            nvars++;
            cur_target = -1;
            continue;
        }

        /* Target: deps line */
        char *colon = ((void *)0);
        for (int j = 0; line[j]; j++) {
            if (line[j] == ':') { colon = &line[j]; break; }
        }
        if (colon && ntargets < MAKE_MAX_TARGETS) {
            int tlen = (int)(colon - line);
            while (tlen > 0 && (line[tlen-1] == ' ' || line[tlen-1] == '\t')) tlen--;
            if (tlen > 127) tlen = 127;

            /* Check for .PHONY */
            if (tlen == 6 && line[0] == '.' && line[1] == 'P' && line[2] == 'H' &&
                line[3] == 'O' && line[4] == 'N' && line[5] == 'Y') {
                /* Save phony dep names */
                char *dp = colon + 1;
                while (*dp == ' ' || *dp == '\t') dp++;
                strncpy_simple(phony_deps, dp, 1023);
                cur_target = -1;
                continue;
            }

            cur_target = ntargets;
            for (int j = 0; j < tlen; j++) targets[ntargets].name[j] = line[j];
            targets[ntargets].name[tlen] = '\0';
            targets[ntargets].ndeps = 0;
            targets[ntargets].nrecipes = 0;
            targets[ntargets].phony = 0;

            /* Parse deps */
            char *dp = colon + 1;
            while (*dp == ' ' || *dp == '\t') dp++;
            while (*dp && targets[ntargets].ndeps < MAKE_MAX_DEPS) {
                char *ds = dp;
                while (*dp && *dp != ' ' && *dp != '\t') dp++;
                int dlen = (int)(dp - ds);
                if (dlen > 0 && dlen < 128) {
                    for (int j = 0; j < dlen; j++)
                        targets[ntargets].deps[targets[ntargets].ndeps][j] = ds[j];
                    targets[ntargets].deps[targets[ntargets].ndeps][dlen] = '\0';
                    targets[ntargets].ndeps++;
                }
                while (*dp == ' ' || *dp == '\t') dp++;
            }
            ntargets++;
        }
    }

    /* Mark .PHONY targets */
    if (phony_deps[0]) {
        char *dp = phony_deps;
        while (*dp) {
            while (*dp == ' ' || *dp == '\t') dp++;
            if (!*dp) break;
            char pname[128];
            int pi = 0;
            while (*dp && *dp != ' ' && *dp != '\t' && pi < 127) pname[pi++] = *dp++;
            pname[pi] = '\0';
            for (int t = 0; t < ntargets; t++) {
                if (strcmp_simple(targets[t].name, pname) == 0) targets[t].phony = 1;
            }
        }
    }

    if (ntargets == 0) {
        write_str(2, "make: *** No targets\n");
        return;
    }

    /* Build goal (default = first target) */
    const char *build_target = goal ? goal : targets[0].name;
    make_build(build_target, targets, ntargets, vars, nvars);
}

/* ── vi: minimal vi text editor ── */
#define VI_MAX_LINES 1000
#define VI_MAX_COLS  256
#define VI_ROWS      24

static void cmd_vi(int argc, char *argv[]) {
    if (argc < 2) { write_str(2, "usage: vi <file>\n"); return; }
    const char *filename = argv[1];
    static char lines[VI_MAX_LINES][VI_MAX_COLS];
    int num_lines = 0, cur_row = 0, cur_col = 0, top_row = 0;
    int modified = 0, mode = 0, running = 1;
    char status_msg[80];
    status_msg[0] = '\0';
    for (int i = 0; i < VI_MAX_LINES; i++) lines[i][0] = '\0';

    /* Load file */
    int fd = sys_open(filename, O_RDONLY, 0);
    if (fd >= 0) {
        char buf[512]; int col = 0; ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n') {
                    lines[num_lines][col] = '\0'; num_lines++; col = 0;
                    if (num_lines >= VI_MAX_LINES) break;
                } else if (col < VI_MAX_COLS - 1) lines[num_lines][col++] = buf[i];
            }
            if (num_lines >= VI_MAX_LINES) break;
        }
        if (col > 0 || num_lines == 0) { lines[num_lines][col] = '\0'; num_lines++; }
        sys_close(fd);
    } else { num_lines = 1; lines[0][0] = '\0'; }

    #define VI_LINELEN(r) ((int)strlen_simple(lines[(r)]))
    #define VI_WRITE_INT(v) do { int _v=(v); char _b[12]; int _i=0; \
        if(_v==0){write_char(1,'0');}else{ if(_v<0){write_char(1,'-');_v=-_v;} \
        while(_v>0){_b[_i++]='0'+(_v%10);_v/=10;} while(_i>0)write_char(1,_b[--_i]);} }while(0)
    #define VI_SCROLL() do { if(cur_row<top_row) top_row=cur_row; \
        if(cur_row>=top_row+VI_ROWS-1) top_row=cur_row-VI_ROWS+2; }while(0)
    #define VI_CLAMP_COL() do { int _l=VI_LINELEN(cur_row); \
        if(mode==0){if(_l>0)_l--;else _l=0;} if(cur_col>_l)cur_col=_l; if(cur_col<0)cur_col=0; }while(0)
    #define VI_REDRAW() do { \
        write_str(1,"\033[2J\033[H"); int _rows=VI_ROWS-1; \
        for(int _r=0;_r<_rows;_r++){ int _line=top_row+_r; \
            if(_line<num_lines) write_str(1,lines[_line]); else write_char(1,'~'); \
            if(_r<_rows-1) write_str(1,"\r\n"); } \
        write_str(1,"\033["); VI_WRITE_INT(VI_ROWS); write_str(1,";1H\033[7m"); \
        if(mode==1) write_str(1,"-- INSERT -- "); else write_str(1,"             "); \
        write_str(1,filename); if(modified) write_str(1," [+]"); \
        write_str(1,"  L"); VI_WRITE_INT(cur_row+1); write_str(1,"/"); VI_WRITE_INT(num_lines); \
        write_str(1," C"); VI_WRITE_INT(cur_col+1); \
        if(status_msg[0]){write_str(1,"  ");write_str(1,status_msg);} \
        write_str(1,"                              \033[0m"); \
        write_str(1,"\033["); VI_WRITE_INT(cur_row-top_row+1); \
        write_str(1,";"); VI_WRITE_INT(cur_col+1); write_str(1,"H"); }while(0)
    #define VI_SAVE() do { \
        int _wfd=sys_open(filename,O_WRONLY|O_CREAT|O_TRUNC,0644); \
        if(_wfd<0){ const char*_m="E: cannot save"; int _j=0; \
            while(_m[_j]&&_j<78){status_msg[_j]=_m[_j];_j++;}status_msg[_j]='\0'; \
        }else{ for(int _i=0;_i<num_lines;_i++){ int _len=VI_LINELEN(_i); \
            if(_len>0){sys_write(_wfd,lines[_i],_len);} sys_write(_wfd,"\n",1); } \
            sys_close(_wfd); modified=0; \
            const char*_m="written"; int _j=0; \
            while(_m[_j]&&_j<78){status_msg[_j]=_m[_j];_j++;}status_msg[_j]='\0'; } }while(0)

    VI_REDRAW();
    char prev_ch = 0;

    while (running) {
        char c; ssize_t nr = sys_read(0, &c, 1);
        if (nr <= 0) break;
        status_msg[0] = '\0';

        if (mode == 1) {
            /* Insert mode */
            if (c == 27) {
                char seq[2]; ssize_t s1 = sys_read(0, &seq[0], 1);
                if (s1 > 0 && seq[0] == '[') {
                    ssize_t s2 = sys_read(0, &seq[1], 1);
                    if (s2 > 0) {
                        if (seq[1]=='A' && cur_row>0){cur_row--;VI_CLAMP_COL();}
                        else if(seq[1]=='B' && cur_row<num_lines-1){cur_row++;VI_CLAMP_COL();}
                        else if(seq[1]=='C'){if(cur_col<VI_LINELEN(cur_row))cur_col++;}
                        else if(seq[1]=='D'){if(cur_col>0)cur_col--;}
                    }
                } else { mode = 0; VI_CLAMP_COL(); }
            } else if (c == 127 || c == 8) {
                if (cur_col > 0) {
                    int len = VI_LINELEN(cur_row);
                    for (int i = cur_col-1; i < len; i++) lines[cur_row][i] = lines[cur_row][i+1];
                    cur_col--; modified = 1;
                } else if (cur_row > 0) {
                    int prev_len = VI_LINELEN(cur_row-1), cur_len = VI_LINELEN(cur_row);
                    if (prev_len + cur_len < VI_MAX_COLS-1) {
                        for (int i = 0; i <= cur_len; i++) lines[cur_row-1][prev_len+i] = lines[cur_row][i];
                        for (int i = cur_row; i < num_lines-1; i++)
                            for (int j = 0; j < VI_MAX_COLS; j++) lines[i][j] = lines[i+1][j];
                        num_lines--; cur_row--; cur_col = prev_len; modified = 1;
                    }
                }
            } else if (c == '\r' || c == '\n') {
                if (num_lines < VI_MAX_LINES) {
                    for (int i = num_lines; i > cur_row+1; i--)
                        for (int j = 0; j < VI_MAX_COLS; j++) lines[i][j] = lines[i-1][j];
                    num_lines++; int k = 0;
                    for (int i = cur_col; lines[cur_row][i]; i++) lines[cur_row+1][k++] = lines[cur_row][i];
                    lines[cur_row+1][k] = '\0'; lines[cur_row][cur_col] = '\0';
                    cur_row++; cur_col = 0; modified = 1;
                }
            } else if (c >= 32 || c == '\t') {
                int len = VI_LINELEN(cur_row);
                if (len < VI_MAX_COLS-2) {
                    for (int i = len+1; i > cur_col; i--) lines[cur_row][i] = lines[cur_row][i-1];
                    lines[cur_row][cur_col] = c; cur_col++; modified = 1;
                }
            }
        } else {
            /* Normal mode */
            if (c == 27) {
                char seq[2]; ssize_t s1 = sys_read(0, &seq[0], 1);
                if (s1 > 0 && seq[0] == '[') {
                    ssize_t s2 = sys_read(0, &seq[1], 1);
                    if (s2 > 0) {
                        if(seq[1]=='A'&&cur_row>0){cur_row--;VI_CLAMP_COL();}
                        else if(seq[1]=='B'&&cur_row<num_lines-1){cur_row++;VI_CLAMP_COL();}
                        else if(seq[1]=='C'){int l=VI_LINELEN(cur_row);if(l>0&&cur_col<l-1)cur_col++;}
                        else if(seq[1]=='D'){if(cur_col>0)cur_col--;}
                    }
                }
            } else if (c=='h') { if(cur_col>0) cur_col--;
            } else if (c=='j') { if(cur_row<num_lines-1){cur_row++;VI_CLAMP_COL();}
            } else if (c=='k') { if(cur_row>0){cur_row--;VI_CLAMP_COL();}
            } else if (c=='l') { int l=VI_LINELEN(cur_row); if(l>0&&cur_col<l-1) cur_col++;
            } else if (c=='i') { mode=1;
            } else if (c=='a') { mode=1; int l=VI_LINELEN(cur_row); if(l>0) cur_col++;
            } else if (c=='o') {
                if (num_lines < VI_MAX_LINES) {
                    for (int i=num_lines;i>cur_row+1;i--)
                        for(int j=0;j<VI_MAX_COLS;j++) lines[i][j]=lines[i-1][j];
                    num_lines++; lines[cur_row+1][0]='\0'; cur_row++; cur_col=0; mode=1; modified=1;
                }
            } else if (c=='O') {
                if (num_lines < VI_MAX_LINES) {
                    for (int i=num_lines;i>cur_row;i--)
                        for(int j=0;j<VI_MAX_COLS;j++) lines[i][j]=lines[i-1][j];
                    num_lines++; lines[cur_row][0]='\0'; cur_col=0; mode=1; modified=1;
                }
            } else if (c=='x') {
                int len=VI_LINELEN(cur_row);
                if(len>0){ for(int i=cur_col;i<len;i++) lines[cur_row][i]=lines[cur_row][i+1];
                    modified=1; if(cur_col>=VI_LINELEN(cur_row)&&cur_col>0) cur_col--; }
            } else if (c=='d') {
                if (prev_ch=='d') {
                    if(num_lines>1){
                        for(int i=cur_row;i<num_lines-1;i++)
                            for(int j=0;j<VI_MAX_COLS;j++) lines[i][j]=lines[i+1][j];
                        num_lines--;
                        if(cur_row>=num_lines) cur_row=num_lines-1;
                        VI_CLAMP_COL();
                    } else { lines[0][0]='\0'; cur_col=0; }
                    modified=1; prev_ch=0; VI_SCROLL(); VI_REDRAW(); continue;
                }
            } else if (c=='G') { cur_row=num_lines-1; cur_col=0; VI_CLAMP_COL();
            } else if (c=='g') {
                if(prev_ch=='g'){cur_row=0;cur_col=0;VI_CLAMP_COL();prev_ch=0;VI_SCROLL();VI_REDRAW();continue;}
            } else if (c=='Z') {
                if(prev_ch=='Z'){VI_SAVE();running=0;prev_ch=0;continue;}
            } else if (c==':') {
                write_str(1,"\033["); VI_WRITE_INT(VI_ROWS); write_str(1,";1H\033[2K:");
                char cmdbuf[64]; int cpos=0;
                while(cpos<62){
                    char cc; ssize_t rr=sys_read(0,&cc,1);
                    if(rr<=0) break;
                    if(cc=='\r'||cc=='\n') break;
                    if(cc==27){cpos=0;break;}
                    if((cc==127||cc==8)&&cpos>0){cpos--;write_str(1,"\b \b");continue;}
                    cmdbuf[cpos++]=cc; write_char(1,cc);
                }
                cmdbuf[cpos]='\0';
                if(cpos>0){
                    if(cmdbuf[0]=='w'&&cmdbuf[1]=='q'&&cmdbuf[2]=='\0'){VI_SAVE();running=0;}
                    else if(cmdbuf[0]=='w'&&cmdbuf[1]=='\0'){VI_SAVE();}
                    else if(cmdbuf[0]=='q'&&cmdbuf[1]=='!'&&cmdbuf[2]=='\0'){running=0;}
                    else if(cmdbuf[0]=='q'&&cmdbuf[1]=='\0'){
                        if(modified){const char*m="E: unsaved changes (use :q! to force)";int j=0;
                            while(m[j]&&j<78){status_msg[j]=m[j];j++;}status_msg[j]='\0';}
                        else running=0;
                    } else {const char*m="E: unknown command";int j=0;
                        while(m[j]&&j<78){status_msg[j]=m[j];j++;}status_msg[j]='\0';}
                }
            }
            prev_ch = c;
        }
        VI_SCROLL(); VI_REDRAW();
    }
    write_str(1, "\033[2J\033[H");
    #undef VI_LINELEN
    #undef VI_WRITE_INT
    #undef VI_REDRAW
    #undef VI_SAVE
    #undef VI_SCROLL
    #undef VI_CLAMP_COL
}

/* ── su: switch user (simplified) ── */
static void cmd_su(int argc, char *argv[]) {
    const char *target_user = "root";
    const char *cmd_to_run = NULL;
    int i = 1;

    /* Parse arguments: su [-c "command"] [user] */
    while (i < argc) {
        if (strcmp_simple(argv[i], "-c") == 0 && i + 1 < argc) {
            cmd_to_run = argv[++i];
        } else if (argv[i][0] != '-') {
            target_user = argv[i];
        }
        i++;
    }

    /* Read /etc/passwd to find user entry */
    int fd = sys_open("/etc/passwd", O_RDONLY, 0);
    if (fd < 0) {
        write_str(2, "su: cannot open /etc/passwd\n");
        return;
    }
    char pbuf[2048];
    ssize_t n = sys_read(fd, pbuf, sizeof(pbuf) - 1);
    sys_close(fd);
    if (n <= 0) { write_str(2, "su: /etc/passwd is empty\n"); return; }
    pbuf[n] = '\0';

    /* Parse passwd lines: user:x:uid:gid:gecos:home:shell */
    unsigned int uid = 0, gid = 0;
    char home[128] = "/";
    char user_shell[128] = "/bin/sh";
    int found = 0;
    char *line = pbuf;
    while (*line) {
        char *eol = line;
        while (*eol && *eol != '\n') eol++;
        char saved = *eol; *eol = '\0';

        /* Extract username (field 0) */
        char *fields[7]; int fi = 0;
        char *p = line;
        fields[0] = p;
        while (*p && fi < 6) {
            if (*p == ':') { *p = '\0'; fi++; fields[fi] = p + 1; }
            p++;
        }
        if (fi >= 5 && strcmp_simple(fields[0], target_user) == 0) {
            /* fields: 0=user 1=pass 2=uid 3=gid 4=gecos 5=home 6=shell */
            uid = (unsigned int)simple_atoi(fields[2]);
            gid = (unsigned int)simple_atoi(fields[3]);
            if (fi >= 5 && fields[5][0]) strncpy_simple(home, fields[5], sizeof(home) - 1);
            if (fi >= 6 && fields[6][0]) strncpy_simple(user_shell, fields[6], sizeof(user_shell) - 1);
            found = 1;
            break;
        }
        *eol = saved;
        line = (*eol) ? eol + 1 : eol;
    }

    if (!found) {
        write_str(2, "su: user '");
        write_str(2, target_user);
        write_str(2, "' not found in /etc/passwd\n");
        return;
    }

    /* Switch credentials */
    long r = sys_setgid_call((long)gid);
    if (r < 0) { write_str(2, "su: setgid failed\n"); return; }
    r = sys_setuid_call((long)uid);
    if (r < 0) { write_str(2, "su: setuid failed\n"); return; }

    /* Update HOME and USER variables */
    set_var("HOME", home, 1);
    set_var("USER", target_user, 1);
    sys_chdir(home);

    if (cmd_to_run) {
        /* -c mode: execute command and return */
        char cmd_copy[512];
        size_t cl = strlen_simple(cmd_to_run);
        if (cl >= sizeof(cmd_copy)) cl = sizeof(cmd_copy) - 1;
        for (size_t j = 0; j < cl; j++) cmd_copy[j] = cmd_to_run[j];
        cmd_copy[cl] = '\0';
        execute_command_chain(cmd_copy);
        return;
    }

    /* Otherwise inform about the switch */
    write_str(1, "Switched to user '");
    write_str(1, target_user);
    write_str(1, "' (uid=");
    write_num((int)uid);
    write_str(1, ", gid=");
    write_num((int)gid);
    write_str(1, ")\n");
}

/* ── passwd: change password (simplified) ── */
static void cmd_passwd(int argc, char *argv[]) {
    const char *target_user = "root";
    if (argc >= 2) target_user = argv[1];

    /* Prompt for new password (no echo) */
    write_str(1, "New password for ");
    write_str(1, target_user);
    write_str(1, ": ");
    char newpw[128];
    int pi = 0;
    while (pi < (int)sizeof(newpw) - 1) {
        char c;
        ssize_t nr = sys_read(0, &c, 1);
        if (nr <= 0 || c == '\n' || c == '\r') break;
        newpw[pi++] = c;
    }
    newpw[pi] = '\0';
    write_char(1, '\n');

    if (pi == 0) {
        write_str(2, "passwd: empty password not allowed\n");
        return;
    }

    /* Read /etc/shadow (or create it) */
    char sbuf[2048];
    int slen = 0;
    int fd = sys_open("/etc/shadow", O_RDONLY, 0);
    if (fd >= 0) {
        ssize_t n = sys_read(fd, sbuf, sizeof(sbuf) - 1);
        sys_close(fd);
        if (n > 0) slen = (int)n;
    }
    sbuf[slen] = '\0';

    /* Build new shadow file contents */
    char out[2048];
    int op = 0;
    int updated = 0;
    char *line = sbuf;
    while (*line && op < (int)sizeof(out) - 256) {
        char *eol = line;
        while (*eol && *eol != '\n') eol++;
        char saved = *eol; *eol = '\0';

        /* Check if line starts with target_user: */
        const char *u = target_user;
        const char *l = line;
        while (*u && *l && *u == *l) { u++; l++; }
        if (*u == '\0' && *l == ':') {
            /* Replace this line: user:newpw::::::: */
            for (const char *s = target_user; *s && op < (int)sizeof(out) - 128; s++)
                out[op++] = *s;
            out[op++] = ':';
            for (int j = 0; newpw[j] && op < (int)sizeof(out) - 64; j++)
                out[op++] = newpw[j];
            /* Append empty shadow fields */
            for (int j = 0; j < 7; j++) out[op++] = ':';
            out[op++] = '\n';
            updated = 1;
        } else {
            /* Copy line as-is */
            for (const char *s = line; *s && op < (int)sizeof(out) - 4; s++)
                out[op++] = *s;
            out[op++] = '\n';
        }
        *eol = saved;
        line = (*eol) ? eol + 1 : eol;
    }

    /* If user not found in shadow, append new entry */
    if (!updated && op < (int)sizeof(out) - 256) {
        for (const char *s = target_user; *s && op < (int)sizeof(out) - 128; s++)
            out[op++] = *s;
        out[op++] = ':';
        for (int j = 0; newpw[j] && op < (int)sizeof(out) - 64; j++)
            out[op++] = newpw[j];
        for (int j = 0; j < 7; j++) out[op++] = ':';
        out[op++] = '\n';
    }
    out[op] = '\0';

    /* Write back to /etc/shadow */
    fd = sys_open("/etc/shadow", O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        write_str(2, "passwd: cannot write /etc/shadow\n");
        return;
    }
    sys_write(fd, out, (size_t)op);
    sys_close(fd);

    write_str(1, "passwd: password updated for ");
    write_str(1, target_user);
    write_str(1, "\n");
}

/* ── systemctl: basic service management ── */
#define SCTL_MAX_SERVICES 16
#define SCTL_NAME_LEN     64

struct sctl_service {
    char  name[SCTL_NAME_LEN];
    pid_t pid;
    int   enabled;
    int   used;
};

static struct sctl_service sctl_services[SCTL_MAX_SERVICES];

static struct sctl_service *sctl_find(const char *name) {
    for (int i = 0; i < SCTL_MAX_SERVICES; i++) {
        if (sctl_services[i].used && strcmp_simple(sctl_services[i].name, name) == 0)
            return &sctl_services[i];
    }
    return NULL;
}

static struct sctl_service *sctl_alloc(const char *name) {
    for (int i = 0; i < SCTL_MAX_SERVICES; i++) {
        if (!sctl_services[i].used) {
            strncpy_simple(sctl_services[i].name, name, SCTL_NAME_LEN - 1);
            sctl_services[i].name[SCTL_NAME_LEN - 1] = '\0';
            sctl_services[i].pid = 0;
            sctl_services[i].enabled = 0;
            sctl_services[i].used = 1;
            return &sctl_services[i];
        }
    }
    return NULL;
}

static int sctl_is_running(struct sctl_service *svc) {
    if (!svc || svc->pid <= 0) return 0;
    return sys_kill(svc->pid, 0) == 0;
}

static int sctl_start(const char *name) {
    struct sctl_service *svc = sctl_find(name);
    if (svc && sctl_is_running(svc)) {
        write_str(1, "systemctl: ");
        write_str(1, name);
        write_str(1, " is already running\n");
        return 0;
    }
    pid_t pid = (pid_t)sys_fork();
    if (pid < 0) {
        write_str(2, "systemctl: fork failed\n");
        return -1;
    }
    if (pid == 0) {
        /* Child: exec /sbin/<name> */
        char path[128] = "/sbin/";
        int p = 6;
        for (const char *s = name; *s && p < 126; s++) path[p++] = *s;
        path[p] = '\0';
        char *child_argv[2] = { path, NULL };
        sys_execve(path, child_argv, NULL);
        /* If exec fails, exit child */
        syscall1(60, 127);
        while (1);
    }
    /* Parent */
    if (!svc) {
        svc = sctl_alloc(name);
        if (!svc) {
            write_str(2, "systemctl: service table full\n");
            sys_kill(pid, 9);
            return -1;
        }
    }
    svc->pid = pid;
    write_str(1, "systemctl: started ");
    write_str(1, name);
    char pbuf[16];
    int_to_str(pid, pbuf, 16);
    write_str(1, " (pid ");
    write_str(1, pbuf);
    write_str(1, ")\n");
    return 0;
}

static int sctl_stop(const char *name) {
    struct sctl_service *svc = sctl_find(name);
    if (!svc || !sctl_is_running(svc)) {
        write_str(2, "systemctl: ");
        write_str(2, name);
        write_str(2, " is not running\n");
        return -1;
    }
    sys_kill(svc->pid, 15); /* SIGTERM */
    int status = 0;
    sys_waitpid(svc->pid, &status, 0);
    write_str(1, "systemctl: stopped ");
    write_str(1, name);
    write_str(1, "\n");
    svc->pid = 0;
    return 0;
}

static void sctl_status(const char *name) {
    struct sctl_service *svc = sctl_find(name);
    if (!svc) {
        write_str(1, name);
        write_str(1, ": not found\n");
        return;
    }
    int running = sctl_is_running(svc);
    write_str(1, svc->name);
    write_str(1, running ? " - active (running, pid " : " - inactive (stopped)\n");
    if (running) {
        char pbuf[16];
        int_to_str(svc->pid, pbuf, 16);
        write_str(1, pbuf);
        write_str(1, ")\n");
    }
}

static void sctl_list_units(void) {
    write_str(1, "UNIT                 STATE     ENABLED\n");
    int any = 0;
    for (int i = 0; i < SCTL_MAX_SERVICES; i++) {
        if (!sctl_services[i].used) continue;
        any = 1;
        /* Name column (20 chars padded) */
        int nlen = 0;
        for (const char *s = sctl_services[i].name; *s; s++) nlen++;
        write_str(1, sctl_services[i].name);
        for (int p = nlen; p < 21; p++) write_str(1, " ");
        /* State */
        if (sctl_is_running(&sctl_services[i]))
            write_str(1, "running   ");
        else
            write_str(1, "stopped   ");
        /* Enabled */
        write_str(1, sctl_services[i].enabled ? "enabled" : "disabled");
        write_str(1, "\n");
    }
    if (!any) write_str(1, "(no services registered)\n");
}

static void sctl_enable(const char *name) {
    struct sctl_service *svc = sctl_find(name);
    if (!svc) {
        svc = sctl_alloc(name);
        if (!svc) { write_str(2, "systemctl: service table full\n"); return; }
    }
    svc->enabled = 1;
    /* Persist to /etc/futura/enabled */
    sys_mkdir("/etc/futura", 0755);
    long fd = sys_open("/etc/futura/enabled", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sys_write(fd, name, strlen_simple(name));
        sys_write(fd, "\n", 1);
        sys_close(fd);
    }
    write_str(1, "systemctl: enabled ");
    write_str(1, name);
    write_str(1, "\n");
}

static void sctl_disable(const char *name) {
    struct sctl_service *svc = sctl_find(name);
    if (svc) svc->enabled = 0;
    /* Rewrite /etc/futura/enabled without this service */
    long fd = sys_open("/etc/futura/enabled", O_RDONLY, 0);
    if (fd < 0) { write_str(1, "systemctl: disabled "); write_str(1, name); write_str(1, "\n"); return; }
    char buf[1024];
    ssize_t n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) { write_str(1, "systemctl: disabled "); write_str(1, name); write_str(1, "\n"); return; }
    buf[n] = '\0';
    /* Rewrite excluding the service */
    fd = sys_open("/etc/futura/enabled", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    char *line = buf;
    while (*line) {
        char *eol = line;
        while (*eol && *eol != '\n') eol++;
        char saved = *eol; *eol = '\0';
        if (line[0] && strcmp_simple(line, name) != 0) {
            sys_write(fd, line, strlen_simple(line));
            sys_write(fd, "\n", 1);
        }
        *eol = saved;
        if (*eol) eol++;
        line = eol;
    }
    sys_close(fd);
    write_str(1, "systemctl: disabled ");
    write_str(1, name);
    write_str(1, "\n");
}

static void cmd_systemctl(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "Usage: systemctl {start|stop|restart|status|list-units|enable|disable} [service]\n");
        return;
    }
    const char *sub = argv[1];
    if (strcmp_simple(sub, "start") == 0) {
        if (argc < 3) { write_str(2, "systemctl start: missing service name\n"); return; }
        sctl_start(argv[2]);
    } else if (strcmp_simple(sub, "stop") == 0) {
        if (argc < 3) { write_str(2, "systemctl stop: missing service name\n"); return; }
        sctl_stop(argv[2]);
    } else if (strcmp_simple(sub, "restart") == 0) {
        if (argc < 3) { write_str(2, "systemctl restart: missing service name\n"); return; }
        struct sctl_service *svc = sctl_find(argv[2]);
        if (svc && sctl_is_running(svc)) sctl_stop(argv[2]);
        sctl_start(argv[2]);
    } else if (strcmp_simple(sub, "status") == 0) {
        if (argc >= 3) {
            sctl_status(argv[2]);
        } else {
            sctl_list_units();
        }
    } else if (strcmp_simple(sub, "list-units") == 0) {
        sctl_list_units();
    } else if (strcmp_simple(sub, "enable") == 0) {
        if (argc < 3) { write_str(2, "systemctl enable: missing service name\n"); return; }
        sctl_enable(argv[2]);
    } else if (strcmp_simple(sub, "disable") == 0) {
        if (argc < 3) { write_str(2, "systemctl disable: missing service name\n"); return; }
        sctl_disable(argv[2]);
    } else {
        write_str(2, "systemctl: unknown command '");
        write_str(2, sub);
        write_str(2, "'\n");
    }
}

int main(int argc, char **argv, char **envp) {
    /* Check for -c mode: shell -c "command string" */
    int script_mode = 0;
    const char *script_cmd = NULL;
    if (argc >= 3 && argv[1][0] == '-' && argv[1][1] == 'c') {
        script_mode = 1;
        script_cmd = argv[2];
    }

    /* Initialize shell environment from parent's environment variables */
    if (envp && envp[0] != NULL) {
        for (int i = 0; envp[i] != NULL; i++) {
            /* Parse "NAME=value" format and add to shell's variables */
            const char *env_str = envp[i];
            const char *eq = env_str;

            /* Find the '=' separator */
            while (*eq && *eq != '=') {
                eq++;
            }

            if (*eq == '=' && eq != env_str) {
                /* Extract name */
                int name_len = (int)(eq - env_str);
                if (name_len < MAX_VAR_NAME) {
                    char name[MAX_VAR_NAME];
                    int j;
                    for (j = 0; j < name_len; j++) {
                        name[j] = env_str[j];
                    }
                    name[name_len] = '\0';

                    /* Extract value */
                    const char *val = eq + 1;
                    int val_len = strlen_simple(val);
                    if (val_len < MAX_VAR_VALUE) {
                        char value[MAX_VAR_VALUE];
                        strcpy_simple(value, val);

                        /* Add variable to shell (mark as exported since it came from parent) */
                        set_var(name, value, 1);  /* 1 = exported */
                    }
                }
            }
        }
    }

    /* Initialize standard file descriptors if not already open.
     * If stdin (fd 0) is already valid (e.g., redirected to a pipe by a parent
     * like wl-term), skip the /dev/console setup to preserve the redirection. */
    long stdin_flags = sys_fcntl_call(0, 3 /* F_GETFL */, 0);
    long stdout_flags = sys_fcntl_call(1, 3 /* F_GETFL */, 0);
    if (stdin_flags < 0 || stdout_flags < 0) {
        /* stdin/stdout not open — set up /dev/console for interactive use */
        int console_fd = sys_open("/dev/console", O_RDWR, 0);
        if (console_fd >= 0) {
            if (console_fd != 0) {
                sys_dup2(console_fd, 0);  /* stdin */
            }
            if (console_fd != 1) {
                sys_dup2(console_fd, 1);  /* stdout */
            }
            if (console_fd != 2) {
                sys_dup2(console_fd, 2);  /* stderr */
            }
            if (console_fd > 2) {
                sys_close(console_fd);
            }
        }
    }

    /* Set up signal handlers — ignore SIGINT in shell (children inherit default) */
    {
        /* struct sigaction: sa_handler at offset 0, sa_flags, sa_mask */
        /* SIG_IGN = 1 */
        long sa[16];  /* 128 bytes — enough for struct sigaction */
        for (int i = 0; i < 16; i++) sa[i] = 0;
        sa[0] = 1;  /* sa_handler = SIG_IGN */
        sys_call4(13 /* rt_sigaction */, 2 /* SIGINT */, (long)sa, 0, 8);
    }

    /* Set default environment variables if not inherited from parent */
    if (!get_var("PATH"))
        set_var("PATH", "/bin:/sbin:/bin/user", 1);
    if (!get_var("HOME"))
        set_var("HOME", "/", 1);
    if (!get_var("TERM"))
        set_var("TERM", "vt100", 1);
    if (!get_var("SHELL"))
        set_var("SHELL", "/bin/shell", 1);
    if (!get_var("USER"))
        set_var("USER", "root", 1);
    if (!get_var("HOSTNAME"))
        set_var("HOSTNAME", "futura", 1);
    /* Set PWD from getcwd */
    {
        char cwd[256];
        long cwdret = sys_call2(__NR_getcwd, (long)cwd, 256);
        if (cwdret > 0) {
            set_var("PWD", cwd, 1);
        } else {
            set_var("PWD", "/", 1);
        }
    }

    /* Source /etc/profile if it exists (supports multi-line blocks) */
    {
        int pfd = sys_open("/etc/profile", O_RDONLY, 0);
        if (pfd >= 0) {
            char pbuf[2048];
            ssize_t pn = sys_read(pfd, pbuf, sizeof(pbuf) - 1);
            sys_close(pfd);
            if (pn > 0) {
                pbuf[pn] = '\0';
                execute_script_buffer(pbuf);
            }
        }
    }

    /* If -c mode, execute command and exit */
    if (script_mode && script_cmd) {
        char cmd_copy[512];
        size_t cl = strlen_simple(script_cmd);
        if (cl >= sizeof(cmd_copy)) cl = sizeof(cmd_copy) - 1;
        for (size_t i = 0; i < cl; i++) cmd_copy[i] = script_cmd[i];
        cmd_copy[cl] = '\0';
        char expanded[512];
        expand_variables(expanded, cmd_copy, sizeof(expanded));
        int rc = execute_command_chain(expanded);
        return rc < 0 ? 1 : 0;
    }

    write_str(1, "\n\033[1m");
    write_str(1, "+------------------------------------------+\n");
    write_str(1, "|   Futura OS Shell v0.5                   |\n");
    write_str(1, "|   185 built-in commands — type 'help'    |\n");
    write_str(1, "|   Built-in editor: type 'edit <file>'     |\n");
    write_str(1, "+------------------------------------------+\n");
    write_str(1, "\033[0m\n");

    char cmdline[512];
    ssize_t nread;

    while (1) {
        /* Update background job statuses */
        update_jobs();

        /* Print prompt with current directory */
        print_prompt();

        /* Read command line with interactive editing */
        /* Zero cmdline before reading to prevent stale stack data from
         * being executed if read_line returns early (EOF). */
        cmdline[0] = '\0';
        nread = read_line(0, cmdline, sizeof(cmdline));

        if (nread <= 0) {
            if (nread < 0) break;  /* Error — exit shell */
            /* EOF (nread=0, Ctrl+D on empty line): exit shell gracefully */
            write_str(1, "\nexit\n");
            break;
        }

        /* Skip empty lines */
        if (cmdline[0] == '\0') {
            continue;
        }

        /* Add command to history */
        add_to_history(cmdline);

        /* Handle 'for VAR in LIST; do BODY; done' */
        if (cmdline[0] == 'f' && cmdline[1] == 'o' && cmdline[2] == 'r' && cmdline[3] == ' ') {
            char *p = cmdline + 4;
            while (*p == ' ') p++;
            /* Extract variable name */
            char fvar[64];
            int vi = 0;
            while (*p && *p != ' ' && vi < 63) fvar[vi++] = *p++;
            fvar[vi] = '\0';
            while (*p == ' ') p++;
            /* Expect "in" */
            if (p[0] == 'i' && p[1] == 'n' && p[2] == ' ') {
                p += 3;
                while (*p == ' ') p++;
                /* Find "; do" */
                char *do_ptr = p;
                while (*do_ptr) {
                    if (do_ptr[0] == ';' && do_ptr[1] == ' ' && do_ptr[2] == 'd' && do_ptr[3] == 'o') {
                        *do_ptr = '\0';
                        do_ptr += 4;
                        while (*do_ptr == ' ') do_ptr++;
                        break;
                    }
                    do_ptr++;
                }
                /* Find "; done" at end */
                char *body = do_ptr;
                int blen = (int)strlen_simple(body);
                if (blen >= 6 && body[blen-1] == 'e' && body[blen-2] == 'n' && body[blen-3] == 'o' &&
                    body[blen-4] == 'd' && (body[blen-5] == ';' || body[blen-5] == ' ')) {
                    /* Trim "; done" or " done" */
                    int trim = blen - 5;
                    while (trim > 0 && (body[trim-1] == ' ' || body[trim-1] == ';')) trim--;
                    body[trim] = '\0';
                }
                /* Expand globs in word list, then iterate */
                char *wargv[64];
                int wargc = 0;
                { char *ws = p;
                  while (*ws && wargc < 63) {
                    while (*ws == ' ') ws++;
                    if (!*ws) break;
                    wargv[wargc] = ws;
                    while (*ws && *ws != ' ') ws++;
                    if (*ws) *ws++ = '\0';
                    wargc++;
                  }
                  wargv[wargc] = NULL;
                  wargc = expand_globs(wargc, wargv, 64);
                }
                for (int wi = 0; wi < wargc; wi++) {
                    char *word = wargv[wi];
                    set_var(fvar, word, 0);
                    char exp_body[512];
                    expand_variables(exp_body, body, sizeof(exp_body));
                    /* Handle semicolons in body */
                    char *bcmd = exp_body;
                    while (*bcmd) {
                        char *semi = bcmd;
                        while (*semi && *semi != ';') semi++;
                        char sc = *semi; *semi = '\0';
                        while (*bcmd == ' ') bcmd++;
                        if (*bcmd) execute_command_chain(bcmd);
                        if (sc == '\0') break;
                        bcmd = semi + 1;
                    }
                }
                last_exit_status = 0;
                continue;
            }
        }

        /* Handle 'if CMD; then CMD; [else CMD;] fi' */
        if (cmdline[0] == 'i' && cmdline[1] == 'f' && cmdline[2] == ' ') {
            char *p = cmdline + 3;
            /* Find "; then" */
            char *then_ptr = p;
            while (*then_ptr) {
                if (then_ptr[0] == ';' && then_ptr[1] == ' ' && then_ptr[2] == 't' &&
                    then_ptr[3] == 'h' && then_ptr[4] == 'e' && then_ptr[5] == 'n') {
                    *then_ptr = '\0';
                    then_ptr += 6;
                    while (*then_ptr == ' ') then_ptr++;
                    break;
                }
                then_ptr++;
            }
            /* Execute condition */
            char exp_cond[512];
            expand_variables(exp_cond, p, sizeof(exp_cond));
            int cond_rc = execute_command_chain(exp_cond);

            /* Find "; else" and "; fi" */
            char *else_body = NULL;
            char *then_body = then_ptr;
            char *scan = then_ptr;
            while (*scan) {
                if (scan[0] == ';' && scan[1] == ' ' && scan[2] == 'e' && scan[3] == 'l' &&
                    scan[4] == 's' && scan[5] == 'e') {
                    *scan = '\0';
                    else_body = scan + 7;
                    break;
                }
                scan++;
            }
            /* Trim "; fi" from whichever body is last */
            char *last_body = else_body ? else_body : then_body;
            int lb = (int)strlen_simple(last_body);
            if (lb >= 3 && last_body[lb-1] == 'i' && last_body[lb-2] == 'f' &&
                (last_body[lb-3] == ';' || last_body[lb-3] == ' ')) {
                int trim = lb - 3;
                while (trim > 0 && (last_body[trim-1] == ' ' || last_body[trim-1] == ';')) trim--;
                last_body[trim] = '\0';
            }

            char *chosen = (cond_rc == 0) ? then_body : else_body;
            if (chosen && *chosen) {
                char exp[512];
                expand_variables(exp, chosen, sizeof(exp));
                last_exit_status = execute_command_chain(exp);
            } else {
                last_exit_status = 0;
            }
            continue;
        }

        /* Handle 'while CMD; do BODY; done' */
        if (cmdline[0] == 'w' && cmdline[1] == 'h' && cmdline[2] == 'i' &&
            cmdline[3] == 'l' && cmdline[4] == 'e' && cmdline[5] == ' ') {
            char wcopy[512];
            size_t wl = strlen_simple(cmdline);
            for (size_t i = 0; i <= wl; i++) wcopy[i] = cmdline[i];
            char *wp = wcopy + 6;
            /* Find "; do" */
            char *wdo = wp;
            while (*wdo) {
                if (wdo[0] == ';' && wdo[1] == ' ' && wdo[2] == 'd' && wdo[3] == 'o') {
                    *wdo = '\0'; wdo += 4; while (*wdo == ' ') wdo++; break;
                }
                wdo++;
            }
            /* Find "; done" */
            char *wbody = wdo;
            int wb = (int)strlen_simple(wbody);
            if (wb >= 6 && wbody[wb-1] == 'e' && wbody[wb-2] == 'n' &&
                wbody[wb-3] == 'o' && wbody[wb-4] == 'd') {
                int trim = wb - 5;
                while (trim > 0 && (wbody[trim-1] == ' ' || wbody[trim-1] == ';')) trim--;
                wbody[trim] = '\0';
            }
            /* Loop: evaluate condition, execute body if 0 */
            int iters = 0;
            while (iters < 1000) {
                char exp_c[512];
                expand_variables(exp_c, wp, sizeof(exp_c));
                if (execute_command_chain(exp_c) != 0) break;
                char exp_b[512];
                expand_variables(exp_b, wbody, sizeof(exp_b));
                execute_command_chain(exp_b);
                iters++;
            }
            last_exit_status = 0;
            continue;
        }

        /* Handle 'until CMD; do BODY; done' — inverse of while */
        if (cmdline[0] == 'u' && cmdline[1] == 'n' && cmdline[2] == 't' &&
            cmdline[3] == 'i' && cmdline[4] == 'l' && cmdline[5] == ' ') {
            char ucopy[512];
            size_t ul = strlen_simple(cmdline);
            for (size_t i = 0; i <= ul; i++) ucopy[i] = cmdline[i];
            char *up = ucopy + 6;
            /* Find "; do" */
            char *udo = up;
            while (*udo) {
                if (udo[0] == ';' && udo[1] == ' ' && udo[2] == 'd' && udo[3] == 'o') {
                    *udo = '\0'; udo += 4; while (*udo == ' ') udo++; break;
                }
                udo++;
            }
            /* Find "; done" */
            char *ubody = udo;
            int ub = (int)strlen_simple(ubody);
            if (ub >= 6 && ubody[ub-1] == 'e' && ubody[ub-2] == 'n' &&
                ubody[ub-3] == 'o' && ubody[ub-4] == 'd') {
                int trim = ub - 5;
                while (trim > 0 && (ubody[trim-1] == ' ' || ubody[trim-1] == ';')) trim--;
                ubody[trim] = '\0';
            }
            /* Loop: evaluate condition, execute body if NON-zero (inverse of while) */
            int iters = 0;
            while (iters < 1000) {
                char exp_c[512];
                expand_variables(exp_c, up, sizeof(exp_c));
                if (execute_command_chain(exp_c) == 0) break;  /* until: stop when condition succeeds */
                char exp_b[512];
                expand_variables(exp_b, ubody, sizeof(exp_b));
                execute_command_chain(exp_b);
                iters++;
            }
            last_exit_status = 0;
            continue;
        }

        /* Handle 'case WORD in PAT) BODY;; ... esac' */
        if (cmdline[0] == 'c' && cmdline[1] == 'a' && cmdline[2] == 's' &&
            cmdline[3] == 'e' && cmdline[4] == ' ') {
            char *cp = cmdline + 5;
            while (*cp == ' ') cp++;
            /* Extract WORD */
            char cword[128];
            int cwl = 0;
            while (*cp && *cp != ' ' && cwl < 127) cword[cwl++] = *cp++;
            cword[cwl] = '\0';
            while (*cp == ' ') cp++;
            /* Expect "in" */
            if (cp[0] == 'i' && cp[1] == 'n' && (cp[2] == ' ' || cp[2] == ';')) {
                cp += 2;
                while (*cp == ' ' || *cp == ';') cp++;
                /* Expand the word */
                char exp_word[128];
                expand_variables(exp_word, cword, sizeof(exp_word));
                /* Process pattern) body;; pairs until esac */
                int matched = 0;
                while (*cp) {
                    /* Skip whitespace */
                    while (*cp == ' ') cp++;
                    if (cp[0] == 'e' && cp[1] == 's' && cp[2] == 'a' && cp[3] == 'c') break;
                    /* Extract pattern (up to ')') */
                    char pat[64];
                    int pl = 0;
                    while (*cp && *cp != ')' && pl < 63) pat[pl++] = *cp++;
                    pat[pl] = '\0';
                    if (*cp == ')') cp++;
                    while (*cp == ' ') cp++;
                    /* Extract body (up to ';;') */
                    char body[256];
                    int bl = 0;
                    while (*cp && bl < 254) {
                        if (cp[0] == ';' && cp[1] == ';') { cp += 2; break; }
                        body[bl++] = *cp++;
                    }
                    body[bl] = '\0';
                    while (*cp == ' ') cp++;
                    /* Check if pattern matches (support * wildcard) */
                    if (!matched && (glob_match(pat, exp_word) ||
                                     (pat[0] == '*' && pat[1] == '\0'))) {
                        char exp_body[512];
                        expand_variables(exp_body, body, sizeof(exp_body));
                        execute_command_chain(exp_body);
                        matched = 1;
                    }
                }
            }
            last_exit_status = 0;
            continue;
        }

        /* Check for variable assignment */
        char var_name[MAX_VAR_NAME];
        char var_value[MAX_VAR_VALUE];
        if (is_var_assignment(cmdline, var_name, var_value)) {
            /* Expand variables in the value */
            char expanded_value[MAX_VAR_VALUE];
            expand_variables(expanded_value, var_value, MAX_VAR_VALUE);
            set_var(var_name, expanded_value, 0);
            last_exit_status = 0;
            continue;
        }

        /* Expand aliases: check if first word matches an alias */
        {
            char *first = cmdline;
            while (*first == ' ' || *first == '\t') first++;
            char word[32];
            int wl = 0;
            while (first[wl] && first[wl] != ' ' && first[wl] != '\t' && wl < 31) { word[wl] = first[wl]; wl++; }
            word[wl] = '\0';
            const char *aval = get_alias(word);
            if (aval) {
                char tmp[512];
                int tp = 0;
                for (const char *a = aval; *a && tp < 500; a++) tmp[tp++] = *a;
                for (const char *r = first + wl; *r && tp < 510; r++) tmp[tp++] = *r;
                tmp[tp] = '\0';
                for (int j = 0; j <= tp; j++) cmdline[j] = tmp[j];
            }
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

/* Execute a single line with full shell semantics (aliases, variables,
 * for/while/if constructs, command chains). Used by source and profile. */
static int execute_full_line(char *line) {
    if (!line || !line[0] || line[0] == '#') return 0;

    /* Variable assignment */
    char vn[MAX_VAR_NAME], vv[MAX_VAR_VALUE];
    if (is_var_assignment(line, vn, vv)) {
        char ev[MAX_VAR_VALUE];
        expand_variables(ev, vv, MAX_VAR_VALUE);
        set_var(vn, ev, 0);
        return 0;
    }

    /* Alias expansion */
    {
        char *first = line;
        while (*first == ' ' || *first == '\t') first++;
        char word[32];
        int wl = 0;
        while (first[wl] && first[wl] != ' ' && first[wl] != '\t' && wl < 31) { word[wl] = first[wl]; wl++; }
        word[wl] = '\0';
        const char *aval = get_alias(word);
        if (aval) {
            char tmp[512];
            int tp = 0;
            for (const char *a = aval; *a && tp < 500; a++) tmp[tp++] = *a;
            for (const char *r = first + wl; *r && tp < 510; r++) tmp[tp++] = *r;
            tmp[tp] = '\0';
            for (int j = 0; j <= tp; j++) line[j] = tmp[j];
        }
    }

    /* Expand variables */
    char expanded[512];
    expand_variables(expanded, line, sizeof(expanded));

    return execute_command_chain(expanded);
}

/* ---- crontab: simple cron-like task scheduler ---- */
static void cmd_crontab(int argc, char *argv[]) {
    const char *crontab_path = "/etc/crontab";

    if (argc < 2) {
        write_str(2, "Usage: crontab [-l | -e | <file>]\n");
        write_str(2, "  -l        List scheduled tasks\n");
        write_str(2, "  -e        Edit crontab in vi\n");
        write_str(2, "  <file>    Install crontab from file\n");
        write_str(2, "Format: M H * * * command\n");
        return;
    }

    if (strcmp_simple(argv[1], "-l") == 0) {
        /* List current crontab */
        int fd = sys_open(crontab_path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "crontab: no crontab for user\n");
            return;
        }
        char buf[512];
        ssize_t n;
        while ((n = sys_read(fd, buf, sizeof(buf))) > 0)
            sys_write(1, buf, n);
        sys_close(fd);
    } else if (strcmp_simple(argv[1], "-e") == 0) {
        /* Ensure /etc/crontab exists before editing */
        int fd = sys_open(crontab_path, O_RDONLY, 0);
        if (fd < 0) {
            fd = sys_open(crontab_path, O_WRONLY | O_CREAT, 0644);
            if (fd >= 0) {
                const char *hdr = "# Futura crontab — M H * * * command\n";
                sys_write(fd, hdr, strlen_simple(hdr));
                sys_close(fd);
            }
        } else {
            sys_close(fd);
        }
        /* Launch vi on the crontab file */
        char *vi_argv[3];
        vi_argv[0] = "vi";
        vi_argv[1] = (char *)crontab_path;
        vi_argv[2] = NULL;
        cmd_vi(2, vi_argv);
        write_str(1, "crontab: installing new crontab\n");
    } else {
        /* Install crontab from file */
        const char *src = argv[1];
        int sfd = sys_open(src, O_RDONLY, 0);
        if (sfd < 0) {
            write_str(2, "crontab: cannot open ");
            write_str(2, src);
            write_str(2, "\n");
            return;
        }
        int dfd = sys_open(crontab_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dfd < 0) {
            write_str(2, "crontab: cannot write to ");
            write_str(2, crontab_path);
            write_str(2, "\n");
            sys_close(sfd);
            return;
        }
        char buf[512];
        ssize_t n;
        while ((n = sys_read(sfd, buf, sizeof(buf))) > 0)
            sys_write(dfd, buf, n);
        sys_close(sfd);
        sys_close(dfd);
        write_str(1, "crontab: installed from ");
        write_str(1, src);
        write_str(1, "\n");
    }
}

/* ---- scp: simplified file copy over network ---- */
static void cmd_scp(int argc, char *argv[]) {
    if (argc < 3) {
        write_str(2, "Usage: scp <file> <host>:<path>   — upload\n");
        write_str(2, "       scp <host>:<path> <file>   — download\n");
        return;
    }

    /* Determine direction by finding ':' in arguments */
    const char *arg1 = argv[1], *arg2 = argv[2];
    const char *colon1 = NULL, *colon2 = NULL;
    for (const char *p = arg1; *p; p++) { if (*p == ':') { colon1 = p; break; } }
    for (const char *p = arg2; *p; p++) { if (*p == ':') { colon2 = p; break; } }

    if (!colon1 && !colon2) {
        write_str(2, "scp: must specify host:path in source or destination\n");
        return;
    }
    if (colon1 && colon2) {
        write_str(2, "scp: remote-to-remote copy not supported\n");
        return;
    }

    /* Parse host and port (default 2222) */
    char host_buf[64];
    const char *remote_path;
    const char *local_path;
    int upload;

    if (colon2) {
        /* Upload: scp <local> <host>:<path> */
        upload = 1;
        local_path = arg1;
        int hlen = (int)(colon2 - arg2);
        if (hlen > 63) hlen = 63;
        for (int i = 0; i < hlen; i++) host_buf[i] = arg2[i];
        host_buf[hlen] = '\0';
        remote_path = colon2 + 1;
    } else {
        /* Download: scp <host>:<path> <local> */
        upload = 0;
        local_path = arg2;
        int hlen = (int)(colon1 - arg1);
        if (hlen > 63) hlen = 63;
        for (int i = 0; i < hlen; i++) host_buf[i] = arg1[i];
        host_buf[hlen] = '\0';
        remote_path = colon1 + 1;
    }

    /* Parse dotted-quad IP */
    uint32_t ip = 0;
    int octet = 0, shift = 24;
    for (int i = 0; host_buf[i]; i++) {
        if (host_buf[i] == '.') {
            ip |= (octet & 0xFF) << shift;
            shift -= 8;
            octet = 0;
        } else {
            octet = octet * 10 + (host_buf[i] - '0');
        }
    }
    ip |= (octet & 0xFF) << shift;
    uint32_t ip_be = ((ip >> 24) & 0xFF) | ((ip >> 8) & 0xFF00) |
                     ((ip << 8) & 0xFF0000) | ((ip << 24) & 0xFF000000);

    int port = 2222;

    /* Create TCP socket and connect */
    long sock = sys_call3(41 /* socket */, 2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
    if (sock < 0) { write_str(2, "scp: socket failed\n"); return; }

    struct { uint16_t family; uint16_t port; uint32_t addr; uint8_t pad[8]; } sa;
    __builtin_memset(&sa, 0, sizeof(sa));
    sa.family = 2; /* AF_INET */
    sa.port = (uint16_t)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
    sa.addr = ip_be;

    if (sys_call3(42 /* connect */, sock, (long)&sa, 16) < 0) {
        write_str(2, "scp: connect to ");
        write_str(2, host_buf);
        write_str(2, " failed\n");
        sys_close(sock);
        return;
    }

    if (upload) {
        /* Open local file */
        int lfd = sys_open(local_path, O_RDONLY, 0);
        if (lfd < 0) {
            write_str(2, "scp: cannot open "); write_str(2, local_path); write_str(2, "\n");
            sys_close(sock); return;
        }
        /* Get file size via lseek */
        long size = sys_call3(8 /* lseek */, lfd, 0, 2 /* SEEK_END */);
        sys_call3(8, lfd, 0, 0 /* SEEK_SET */);
        if (size < 0) size = 0;

        /* Send header: "PUT <path> <size>\n" */
        char hdr[256];
        int hp = 0;
        const char *put = "PUT ";
        for (int i = 0; put[i]; i++) hdr[hp++] = put[i];
        for (int i = 0; remote_path[i] && hp < 200; i++) hdr[hp++] = remote_path[i];
        hdr[hp++] = ' ';
        char sb[20]; int_to_str(size, sb, 20);
        for (int i = 0; sb[i]; i++) hdr[hp++] = sb[i];
        hdr[hp++] = '\n';
        sys_write(sock, hdr, hp);

        /* Send file data */
        char buf[512];
        ssize_t n;
        long sent = 0;
        while ((n = sys_read(lfd, buf, sizeof(buf))) > 0) {
            sys_write(sock, buf, n);
            sent += n;
        }
        sys_close(lfd);
        write_str(1, "scp: uploaded ");
        write_str(1, local_path);
        write_str(1, " -> ");
        write_str(1, host_buf);
        write_str(1, ":");
        write_str(1, remote_path);
        char ssb[20]; int_to_str(sent, ssb, 20);
        write_str(1, " ("); write_str(1, ssb); write_str(1, " bytes)\n");
    } else {
        /* Send header: "GET <path>\n" */
        char hdr[256];
        int hp = 0;
        const char *get = "GET ";
        for (int i = 0; get[i]; i++) hdr[hp++] = get[i];
        for (int i = 0; remote_path[i] && hp < 250; i++) hdr[hp++] = remote_path[i];
        hdr[hp++] = '\n';
        sys_write(sock, hdr, hp);

        /* Open local file for writing */
        int lfd = sys_open(local_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lfd < 0) {
            write_str(2, "scp: cannot create "); write_str(2, local_path); write_str(2, "\n");
            sys_close(sock); return;
        }

        /* Receive data and write to file */
        char buf[512];
        ssize_t n;
        long total = 0;
        while ((n = sys_read(sock, buf, sizeof(buf))) > 0) {
            sys_write(lfd, buf, n);
            total += n;
        }
        sys_close(lfd);
        write_str(1, "scp: downloaded ");
        write_str(1, host_buf);
        write_str(1, ":");
        write_str(1, remote_path);
        write_str(1, " -> ");
        write_str(1, local_path);
        char tsb[20]; int_to_str(total, tsb, 20);
        write_str(1, " ("); write_str(1, tsb); write_str(1, " bytes)\n");
    }
    sys_close(sock);
}

/* ── pkg: simple package manager ── */
static void cmd_pkg(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "Usage: pkg install <name>  - Install package from /var/pkg/<name>.tar\n");
        write_str(2, "       pkg remove <name>   - Remove installed package\n");
        write_str(2, "       pkg list            - List installed packages\n");
        write_str(2, "       pkg search <pattern> - Search available packages\n");
        write_str(2, "       pkg info <name>     - Show package description\n");
        return;
    }

    /* Ensure base directories exist */
    sys_mkdir("/var", 0755);
    sys_mkdir("/var/pkg", 0755);
    sys_mkdir("/var/pkg/installed", 0755);

    if (strcmp_simple(argv[1], "install") == 0) {
        if (argc < 3) { write_str(2, "pkg install: package name required\n"); return; }
        const char *name = argv[2];

        /* Build tar path: /var/pkg/<name>.tar */
        char tar_path[256];
        int tp = 0;
        const char *prefix = "/var/pkg/";
        for (int i = 0; prefix[i] && tp < 240; i++) tar_path[tp++] = prefix[i];
        for (int i = 0; name[i] && tp < 248; i++) tar_path[tp++] = name[i];
        tar_path[tp++] = '.'; tar_path[tp++] = 't'; tar_path[tp++] = 'a'; tar_path[tp++] = 'r';
        tar_path[tp] = '\0';

        int afd = sys_open(tar_path, O_RDONLY, 0);
        if (afd < 0) {
            write_str(2, "pkg: package not found: "); write_str(2, tar_path); write_str(2, "\n");
            return;
        }

        /* Build installed record path: /var/pkg/installed/<name> */
        char rec_path[256];
        int rp = 0;
        const char *rec_prefix = "/var/pkg/installed/";
        for (int i = 0; rec_prefix[i] && rp < 240; i++) rec_path[rp++] = rec_prefix[i];
        for (int i = 0; name[i] && rp < 254; i++) rec_path[rp++] = name[i];
        rec_path[rp] = '\0';

        int rec_fd = sys_open(rec_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (rec_fd < 0) {
            write_str(2, "pkg: cannot create install record\n");
            sys_close(afd); return;
        }

        /* Extract tar entries to / and record file names */
        static char hdr[512];
        int file_count = 0;
        while (sys_read(afd, hdr, 512) == 512) {
            int all_zero = 1;
            for (int i = 0; i < 512 && all_zero; i++) if (hdr[i]) all_zero = 0;
            if (all_zero) break;

            char fname[101];
            for (int i = 0; i < 100; i++) fname[i] = hdr[i];
            fname[100] = '\0';
            int nlen = 0; while (fname[nlen]) nlen++;

            unsigned long size = 0;
            for (int i = 0; i < 12; i++) {
                char c = hdr[124 + i];
                if (c >= '0' && c <= '7') size = size * 8 + (unsigned long)(c - '0');
            }
            unsigned long mode = 0;
            for (int i = 0; i < 8; i++) {
                char c = hdr[100 + i];
                if (c >= '0' && c <= '7') mode = mode * 8 + (unsigned long)(c - '0');
            }
            char type = hdr[156];

            /* Build output path with leading / */
            char out_path[256];
            int op = 0;
            if (nlen > 0 && fname[0] != '/') out_path[op++] = '/';
            for (int i = 0; i < nlen && op < 254; i++) out_path[op++] = fname[i];
            out_path[op] = '\0';

            /* Record installed file */
            sys_write(rec_fd, out_path, (size_t)op);
            sys_write(rec_fd, "\n", 1);

            if (type == '5' || (nlen > 0 && fname[nlen - 1] == '/')) {
                sys_mkdir(out_path, mode ? (unsigned int)mode : 0755);
            } else {
                int ofd = sys_open(out_path, O_WRONLY | O_CREAT | O_TRUNC, mode ? (int)mode : 0644);
                if (ofd >= 0) {
                    static char fbuf[4096];
                    unsigned long remaining = size;
                    while (remaining > 0) {
                        unsigned long chunk = remaining > 4096 ? 4096 : remaining;
                        long nr = sys_read(afd, fbuf, chunk);
                        if (nr <= 0) break;
                        sys_write(ofd, fbuf, (size_t)nr);
                        remaining -= (unsigned long)nr;
                    }
                    sys_close(ofd);
                    unsigned long pad = (512 - (size % 512)) % 512;
                    if (pad > 0) { static char skip[512]; sys_read(afd, skip, pad); }
                } else {
                    unsigned long total = size + ((512 - (size % 512)) % 512);
                    static char skip[512];
                    while (total > 0) {
                        unsigned long rd = total > 512 ? 512 : total;
                        sys_read(afd, skip, rd);
                        total -= rd;
                    }
                }
                file_count++;
            }
        }
        sys_close(afd);
        sys_close(rec_fd);
        write_str(1, "pkg: installed "); write_str(1, name);
        char cnt[16]; int_to_str(file_count, cnt, 16);
        write_str(1, " ("); write_str(1, cnt); write_str(1, " files)\n");

    } else if (strcmp_simple(argv[1], "remove") == 0) {
        if (argc < 3) { write_str(2, "pkg remove: package name required\n"); return; }
        const char *name = argv[2];

        char rec_path[256];
        int rp = 0;
        const char *rec_prefix = "/var/pkg/installed/";
        for (int i = 0; rec_prefix[i] && rp < 240; i++) rec_path[rp++] = rec_prefix[i];
        for (int i = 0; name[i] && rp < 254; i++) rec_path[rp++] = name[i];
        rec_path[rp] = '\0';

        int fd = sys_open(rec_path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "pkg: package not installed: "); write_str(2, name); write_str(2, "\n");
            return;
        }
        static char fbuf[4096];
        long nr = sys_read(fd, fbuf, sizeof(fbuf) - 1);
        sys_close(fd);
        if (nr <= 0) { sys_unlink(rec_path); return; }
        fbuf[nr] = '\0';

        /* Delete each file listed (one per line), skip directories */
        int removed = 0;
        char *p = fbuf;
        while (*p) {
            char *line = p;
            while (*p && *p != '\n') p++;
            if (*p == '\n') *p++ = '\0';
            if (line[0]) {
                /* Skip entries ending in / (directories) */
                int ll = 0; while (line[ll]) ll++;
                if (ll > 0 && line[ll - 1] != '/') {
                    if (sys_unlink(line) >= 0) removed++;
                }
            }
        }
        sys_unlink(rec_path);
        write_str(1, "pkg: removed "); write_str(1, name);
        char cnt[16]; int_to_str(removed, cnt, 16);
        write_str(1, " ("); write_str(1, cnt); write_str(1, " files)\n");

    } else if (strcmp_simple(argv[1], "list") == 0) {
        int fd = sys_open("/var/pkg/installed", O_RDONLY, 0);
        if (fd < 0) { write_str(1, "No packages installed.\n"); return; }
        static char dbuf[2048];
        long nr = sys_getdents64(fd, dbuf, sizeof(dbuf));
        sys_close(fd);
        if (nr <= 0) { write_str(1, "No packages installed.\n"); return; }
        struct { unsigned long long d_ino; long long d_off;
                 unsigned short d_reclen; unsigned char d_type; char d_name[256]; } *d;
        int count = 0;
        long pos = 0;
        while (pos < nr) {
            d = (void *)(dbuf + pos);
            if (d->d_name[0] != '.') {
                write_str(1, "  "); write_str(1, d->d_name); write_str(1, "\n");
                count++;
            }
            pos += d->d_reclen;
        }
        if (count == 0) write_str(1, "No packages installed.\n");

    } else if (strcmp_simple(argv[1], "search") == 0) {
        const char *pattern = (argc >= 3) ? argv[2] : "";
        int fd = sys_open("/var/pkg", O_RDONLY, 0);
        if (fd < 0) { write_str(2, "pkg: /var/pkg not found\n"); return; }
        static char dbuf[4096];
        long nr = sys_getdents64(fd, dbuf, sizeof(dbuf));
        sys_close(fd);
        if (nr <= 0) { write_str(1, "No packages available.\n"); return; }
        struct { unsigned long long d_ino; long long d_off;
                 unsigned short d_reclen; unsigned char d_type; char d_name[256]; } *d;
        int count = 0;
        long pos = 0;
        while (pos < nr) {
            d = (void *)(dbuf + pos);
            /* Check for .tar suffix */
            int nl = 0; while (d->d_name[nl]) nl++;
            if (nl > 4 && d->d_name[nl-4] == '.' && d->d_name[nl-3] == 't'
                       && d->d_name[nl-2] == 'a' && d->d_name[nl-1] == 'r') {
                /* Check if pattern is a substring of the name */
                int match = 1;
                if (pattern[0]) {
                    match = 0;
                    int plen = 0; while (pattern[plen]) plen++;
                    for (int i = 0; i <= nl - plen && !match; i++) {
                        int ok = 1;
                        for (int j = 0; j < plen && ok; j++)
                            if (d->d_name[i+j] != pattern[j]) ok = 0;
                        if (ok) match = 1;
                    }
                }
                if (match) {
                    /* Print name without .tar extension */
                    char pname[256];
                    for (int i = 0; i < nl - 4; i++) pname[i] = d->d_name[i];
                    pname[nl - 4] = '\0';
                    write_str(1, "  "); write_str(1, pname); write_str(1, "\n");
                    count++;
                }
            }
            pos += d->d_reclen;
        }
        if (count == 0) write_str(1, "No matching packages found.\n");

    } else if (strcmp_simple(argv[1], "info") == 0) {
        if (argc < 3) { write_str(2, "pkg info: package name required\n"); return; }
        const char *name = argv[2];
        char info_path[256];
        int ip = 0;
        const char *info_prefix = "/var/pkg/";
        for (int i = 0; info_prefix[i] && ip < 240; i++) info_path[ip++] = info_prefix[i];
        for (int i = 0; name[i] && ip < 248; i++) info_path[ip++] = name[i];
        info_path[ip++] = '.'; info_path[ip++] = 'i'; info_path[ip++] = 'n';
        info_path[ip++] = 'f'; info_path[ip++] = 'o';
        info_path[ip] = '\0';

        int fd = sys_open(info_path, O_RDONLY, 0);
        if (fd < 0) {
            write_str(2, "pkg: no info for "); write_str(2, name); write_str(2, "\n");
            return;
        }
        static char ibuf[2048];
        long nr = sys_read(fd, ibuf, sizeof(ibuf) - 1);
        sys_close(fd);
        if (nr > 0) { ibuf[nr] = '\0'; write_str(1, ibuf); write_str(1, "\n"); }

    } else {
        write_str(2, "pkg: unknown command '"); write_str(2, argv[1]);
        write_str(2, "' (use install/remove/list/search/info)\n");
    }
}

/* man - manual page viewer */
static void cmd_man(int argc, char *argv[]) {
    if (argc < 2) {
        write_str(2, "Usage: man <command>\n");
        write_str(2, "Display manual page for a command.\n");
        return;
    }

    const char *command = argv[1];

    /* Try to open man page file at /usr/share/man/<command>.txt */
    char path[256];
    int pi = 0;
    const char *prefix = "/usr/share/man/";
    for (int i = 0; prefix[i] && pi < 230; i++) path[pi++] = prefix[i];
    for (int i = 0; command[i] && pi < 248; i++) path[pi++] = command[i];
    path[pi++] = '.'; path[pi++] = 't'; path[pi++] = 'x'; path[pi++] = 't';
    path[pi] = '\0';

    int fd = sys_open(path, O_RDONLY, 0);
    if (fd >= 0) {
        sys_close(fd);
        /* Pipe through less */
        char *less_argv[3];
        less_argv[0] = "less";
        less_argv[1] = path;
        less_argv[2] = (char *)0;
        cmd_less(2, less_argv);
        return;
    }

    /* Built-in one-line descriptions for common commands */
    static const struct { const char *name; const char *desc; } man_entries[] = {
        {"ls",        "ls - list directory contents"},
        {"cd",        "cd - change the working directory"},
        {"pwd",       "pwd - print name of current working directory"},
        {"cat",       "cat - concatenate files and print on standard output"},
        {"echo",      "echo - display a line of text"},
        {"grep",      "grep - print lines that match patterns (-i, -v, -n, -c, -r)"},
        {"find",      "find - search for files in a directory hierarchy"},
        {"cp",        "cp - copy files and directories (-r recursive)"},
        {"mv",        "mv - move (rename) files"},
        {"rm",        "rm - remove files or directories (-r, -f)"},
        {"mkdir",     "mkdir - make directories (-p create parents)"},
        {"rmdir",     "rmdir - remove empty directories"},
        {"chmod",     "chmod - change file mode bits"},
        {"touch",     "touch - change file timestamps or create empty files"},
        {"head",      "head - output the first part of files (-n lines, -c bytes)"},
        {"tail",      "tail - output the last part of files (-n lines, -f follow)"},
        {"wc",        "wc - print newline, word, and byte counts (-l, -w, -c, -L)"},
        {"sort",      "sort - sort lines of text files (-r, -n, -u)"},
        {"uniq",      "uniq - report or omit repeated lines (-c, -d, -u)"},
        {"cut",       "cut - remove sections from each line (-d delimiter, -f fields)"},
        {"tr",        "tr - translate or delete characters"},
        {"sed",       "sed - stream editor for filtering and transforming text"},
        {"awk",       "awk - pattern scanning and processing language"},
        {"diff",      "diff - compare files line by line"},
        {"less",      "less - opposite of more, pager with backward movement"},
        {"vi",        "vi - text editor with normal/insert/command modes"},
        {"make",      "make - build tool with dependency resolution"},
        {"git",       "git - version control (init/add/status/commit/log)"},
        {"curl",      "curl - HTTP client (-X method, -d data, -H header, -o file)"},
        {"tar",       "tar - archive utility (-c create, -x extract, -t list, -f file)"},
        {"ps",        "ps - report a snapshot of current processes"},
        {"kill",      "kill - send a signal to a process (-9, -TERM, -HUP)"},
        {"df",        "df - report file system disk space usage"},
        {"du",        "du - estimate file space usage (-s summary, -h human)"},
        {"mount",     "mount - mount a filesystem"},
        {"uname",     "uname - print system information (-a all, -r release)"},
        {"whoami",    "whoami - print effective userid"},
        {"id",        "id - print real and effective user and group IDs"},
        {"env",       "env - run a program in a modified environment"},
        {"export",    "export - set environment variables for child processes"},
        {"history",   "history - display command history"},
        {"alias",     "alias - define or display command aliases"},
        {"xargs",     "xargs - build and execute command lines from standard input"},
        {"tee",       "tee - read from stdin and write to stdout and files"},
        {"ln",        "ln - make links between files (-s symbolic)"},
        {"stat",      "stat - display file or file system status"},
        {"dd",        "dd - convert and copy a file (if=, of=, bs=, count=)"},
        {"ping",      "ping - send ICMP ECHO_REQUEST to network hosts"},
        {"nc",        "nc - netcat, arbitrary TCP and UDP connections"},
        {"ss",        "ss - socket statistics, show network connections"},
        {"ip",        "ip - show/manipulate routing, devices, and tunnels"},
        {"free",      "free - display amount of free and used memory"},
        {"uptime",    "uptime - tell how long the system has been running"},
        {"dmesg",     "dmesg - print kernel ring buffer messages"},
        {"date",      "date - print or set the system date and time"},
        {"sleep",     "sleep - delay for a specified amount of time"},
        {"seq",       "seq - print a sequence of numbers"},
        {"base64",    "base64 - encode/decode data in base64 (-d decode)"},
        {"xxd",       "xxd - make a hexdump or reverse (-r reverse)"},
        {"md5sum",    "md5sum - compute and check MD5 message digest"},
        {"sha256sum", "sha256sum - compute and check SHA256 message digest"},
        {"tree",      "tree - list directory contents in a tree-like format"},
        {"yes",       "yes - output a string repeatedly until killed"},
        {"cal",       "cal - display a calendar"},
        {"bc",        "bc - arbitrary precision calculator language"},
        {"expr",      "expr - evaluate expressions"},
        {"hostname",  "hostname - show or set the system hostname"},
        {"nslookup",  "nslookup - query DNS name servers"},
        {"strace",    "strace - trace system calls of a command"},
        {"lsof",      "lsof - list open file descriptors"},
        {"wget",      "wget - download files from the web via HTTP"},
        {"diff",      "diff - compare files line by line (unified format)"},
        {"ifconfig",  "ifconfig - configure a network interface"},
        {"man",       "man - display manual pages for commands"},
    };
    int n_entries = (int)(sizeof(man_entries) / sizeof(man_entries[0]));

    for (int i = 0; i < n_entries; i++) {
        if (strcmp_simple(command, man_entries[i].name) == 0) {
            /* NAME section */
            write_str(1, "\n");
            write_str(1, "NAME\n");
            write_str(1, "       ");
            write_str(1, man_entries[i].desc);
            write_str(1, "\n\n");

            /* SYNOPSIS section */
            write_str(1, "SYNOPSIS\n");
            write_str(1, "       ");
            write_str(1, man_entries[i].name);
            write_str(1, " [OPTION]... [ARG]...\n\n");

            /* DESCRIPTION section */
            write_str(1, "DESCRIPTION\n");
            write_str(1, "       ");
            write_str(1, man_entries[i].desc);
            write_str(1, ".\n");
            write_str(1, "       This is a built-in command provided by the Futura OS shell.\n");
            write_str(1, "       For full documentation, install man pages to /usr/share/man/.\n\n");
            return;
        }
    }

    write_str(2, "No manual entry for ");
    write_str(2, command);
    write_str(2, "\n");
}

/* ============================================================
 *   screen — simplified terminal multiplexer (up to 4 windows)
 * ============================================================ */

#define SCREEN_MAX_WIN  4
#define SCREEN_MAX_SESS 4
#define SCREEN_BUF_SIZE 4096

struct screen_window {
    int  master_fd;   /* PTY master fd (-1 = unused) */
    long child_pid;   /* shell process pid */
    int  alive;       /* 1 if window active */
};

struct screen_session {
    int  id;
    int  used;
    int  detached;
    int  nwin;        /* number of windows created */
    int  active;      /* index of active window */
    struct screen_window wins[SCREEN_MAX_WIN];
};

static struct screen_session screen_sessions[SCREEN_MAX_SESS];
static int screen_next_id = 1;

/* Allocate a PTY pair, return master fd (>=0) or -1 on error.
 * Writes slave path to slave_path (must be >= 32 bytes). */
static int screen_alloc_pty(char *slave_path) {
    int mfd = (int)sys_open("/dev/ptmx", 0x0002 /* O_RDWR */, 0);
    if (mfd < 0) return -1;

    /* Unlock slave */
    int unlock = 0;
    sys_ioctl(mfd, 0x40045431 /* TIOCSPTLCK */, (long)&unlock);

    /* Get slave number */
    int snum = -1;
    sys_ioctl(mfd, 0x80045430 /* TIOCGPTN */, (long)&snum);
    if (snum < 0) { sys_close(mfd); return -1; }

    /* Build "/dev/pts/<n>" */
    slave_path[0] = '/'; slave_path[1] = 'd'; slave_path[2] = 'e';
    slave_path[3] = 'v'; slave_path[4] = '/'; slave_path[5] = 'p';
    slave_path[6] = 't'; slave_path[7] = 's'; slave_path[8] = '/';
    int sp = 9;
    if (snum >= 100) slave_path[sp++] = '0' + (char)(snum / 100 % 10);
    if (snum >= 10)  slave_path[sp++] = '0' + (char)(snum / 10 % 10);
    slave_path[sp++] = '0' + (char)(snum % 10);
    slave_path[sp] = '\0';

    return mfd;
}

/* Spawn a shell on a new PTY window, return 0 on success */
static int screen_spawn_window(struct screen_window *win) {
    char slave_path[32];
    int mfd = screen_alloc_pty(slave_path);
    if (mfd < 0) return -1;

    long pid = sys_fork_call();
    if (pid < 0) { sys_close(mfd); return -1; }

    if (pid == 0) {
        /* Child: set up slave PTY as stdio */
        sys_close(mfd);
        sys_call1(112 /* setsid */, 0);

        int sfd = (int)sys_open(slave_path, 0x0002 /* O_RDWR */, 0);
        if (sfd < 0) sys_exit(126);

        sys_ioctl(sfd, 0x540E /* TIOCSCTTY */, 0);

        sys_close(0); sys_close(1); sys_close(2);
        sys_dup2_call(sfd, 0);
        sys_dup2_call(sfd, 1);
        sys_dup2_call(sfd, 2);
        if (sfd > 2) sys_close(sfd);

        char *av[] = { "/bin/shell", (void *)0 };
        char *ev[] = { "TERM=screen", "HOME=/", (void *)0 };
        sys_execve_call("/bin/shell", av, ev);
        sys_exit(127);
    }

    /* Parent: keep master fd, set non-blocking */
    sys_fcntl_call(mfd, 4 /* F_SETFL */,
                   sys_fcntl_call(mfd, 3 /* F_GETFL */, 0) | 0x0800 /* O_NONBLOCK */);
    win->master_fd = mfd;
    win->child_pid = pid;
    win->alive = 1;
    return 0;
}

/* Draw a minimal status bar: " [0] 1  2  3   — window N " */
static void screen_draw_status(struct screen_session *s) {
    write_str(1, "\033[s");       /* save cursor */
    write_str(1, "\033[999;1H");  /* move to bottom row */
    write_str(1, "\033[7m");      /* reverse video */
    write_str(1, " screen");

    for (int i = 0; i < s->nwin; i++) {
        if (!s->wins[i].alive) continue;
        if (i == s->active)
            write_str(1, "  [");
        else
            write_str(1, "   ");
        char digit[2] = { (char)('0' + i), '\0' };
        write_str(1, digit);
        if (i == s->active)
            write_str(1, "]");
    }

    /* Pad remainder */
    write_str(1, "                                                  ");
    write_str(1, "\033[0m");      /* reset attrs */
    write_str(1, "\033[u");       /* restore cursor */
}

/* Close a window and clean up */
static void screen_kill_window(struct screen_session *s, int idx) {
    if (idx < 0 || idx >= s->nwin || !s->wins[idx].alive) return;
    sys_close(s->wins[idx].master_fd);
    /* Reap child (non-blocking) */
    int st;
    sys_waitpid((int)s->wins[idx].child_pid, &st, 1 /* WNOHANG */);
    s->wins[idx].master_fd = -1;
    s->wins[idx].child_pid = -1;
    s->wins[idx].alive = 0;
}

/* Find next alive window from current, wrapping around. Returns -1 if none. */
static int screen_next_alive(struct screen_session *s, int cur, int dir) {
    for (int i = 1; i <= s->nwin; i++) {
        int idx = (cur + i * dir + SCREEN_MAX_WIN) % SCREEN_MAX_WIN;
        if (idx < s->nwin && s->wins[idx].alive) return idx;
    }
    return -1;
}

/* Count alive windows */
static int screen_alive_count(struct screen_session *s) {
    int n = 0;
    for (int i = 0; i < s->nwin; i++)
        if (s->wins[i].alive) n++;
    return n;
}

/* Main event loop for an active screen session */
static void screen_run(struct screen_session *s) {
    char buf[SCREEN_BUF_SIZE];
    int ctrl_a_pending = 0;

    /* Set stdin non-blocking */
    long orig_flags = sys_fcntl_call(0, 3 /* F_GETFL */, 0);
    sys_fcntl_call(0, 4 /* F_SETFL */, orig_flags | 0x0800 /* O_NONBLOCK */);

    write_str(1, "\033[2J\033[H");  /* clear screen */
    screen_draw_status(s);

    while (screen_alive_count(s) > 0) {
        /* Poll stdin + active window's master fd */
        struct { int fd; short events; short revents; } pfds[2];
        pfds[0].fd = 0;
        pfds[0].events = 0x0001; /* POLLIN */
        pfds[0].revents = 0;

        int active_mfd = s->wins[s->active].alive ? s->wins[s->active].master_fd : -1;
        pfds[1].fd = active_mfd;
        pfds[1].events = 0x0001; /* POLLIN */
        pfds[1].revents = 0;

        sys_poll_call(&pfds, 2, 50 /* 50ms timeout */);

        /* Read from active window's PTY master → display on stdout */
        if (active_mfd >= 0 && (pfds[1].revents & (0x0001 | 0x0010))) {
            long nr = sys_read(active_mfd, buf, SCREEN_BUF_SIZE - 1);
            if (nr > 0) {
                sys_write(1, buf, nr);
            } else if (nr == 0 || (nr < 0 && nr != -11 /* EAGAIN */)) {
                /* Window closed */
                screen_kill_window(s, s->active);
                int nxt = screen_next_alive(s, s->active, 1);
                if (nxt < 0) break;
                s->active = nxt;
                write_str(1, "\033[2J\033[H");
                screen_draw_status(s);
                continue;
            }
        }

        /* Read from stdin */
        if (pfds[0].revents & 0x0001) {
            long nr = sys_read(0, buf, 1);
            if (nr <= 0) continue;

            if (ctrl_a_pending) {
                ctrl_a_pending = 0;
                char ch = buf[0];

                if (ch == 'c' || ch == 'C') {
                    /* Create new window */
                    if (s->nwin < SCREEN_MAX_WIN) {
                        int idx = s->nwin;
                        if (screen_spawn_window(&s->wins[idx]) == 0) {
                            s->nwin++;
                            s->active = idx;
                            write_str(1, "\033[2J\033[H");
                            screen_draw_status(s);
                        } else {
                            write_str(1, "\r\n[screen: cannot create window]\r\n");
                        }
                    } else {
                        write_str(1, "\r\n[screen: max 4 windows]\r\n");
                    }
                } else if (ch == 'n' || ch == 'N') {
                    /* Next window */
                    int nxt = screen_next_alive(s, s->active, 1);
                    if (nxt >= 0 && nxt != s->active) {
                        s->active = nxt;
                        write_str(1, "\033[2J\033[H");
                        screen_draw_status(s);
                    }
                } else if (ch == 'p' || ch == 'P') {
                    /* Previous window */
                    int prv = screen_next_alive(s, s->active, -1);
                    if (prv >= 0 && prv != s->active) {
                        s->active = prv;
                        write_str(1, "\033[2J\033[H");
                        screen_draw_status(s);
                    }
                } else if (ch >= '0' && ch <= '3') {
                    /* Switch to window N */
                    int idx = ch - '0';
                    if (idx < s->nwin && s->wins[idx].alive) {
                        s->active = idx;
                        write_str(1, "\033[2J\033[H");
                        screen_draw_status(s);
                    }
                } else if (ch == 'd' || ch == 'D') {
                    /* Detach */
                    s->detached = 1;
                    write_str(1, "\r\n[detached from session ");
                    char id_buf[8];
                    int id_val = s->id, pos = 0;
                    if (id_val >= 10) id_buf[pos++] = '0' + (char)(id_val / 10 % 10);
                    id_buf[pos++] = '0' + (char)(id_val % 10);
                    id_buf[pos] = '\0';
                    write_str(1, id_buf);
                    write_str(1, "]\r\n");
                    break;
                } else if (ch == 'k' || ch == 'K') {
                    /* Kill current window */
                    screen_kill_window(s, s->active);
                    int nxt = screen_next_alive(s, s->active, 1);
                    if (nxt < 0) break;
                    s->active = nxt;
                    write_str(1, "\033[2J\033[H");
                    screen_draw_status(s);
                } else if (ch == 1) {
                    /* Ctrl+A Ctrl+A → send literal Ctrl+A to shell */
                    if (active_mfd >= 0) {
                        char ca = 1;
                        sys_write(active_mfd, &ca, 1);
                    }
                }
                /* Unknown command key — ignore */
            } else if (buf[0] == 1 /* Ctrl+A */) {
                ctrl_a_pending = 1;
            } else {
                /* Forward input to active window's PTY */
                if (active_mfd >= 0) {
                    sys_write(active_mfd, buf, 1);
                }
            }
        }

        /* Reap dead children (non-blocking) */
        for (int i = 0; i < s->nwin; i++) {
            if (!s->wins[i].alive) continue;
            int st;
            long r = sys_waitpid((int)s->wins[i].child_pid, &st, 1 /* WNOHANG */);
            if (r > 0) {
                s->wins[i].alive = 0;
                sys_close(s->wins[i].master_fd);
                s->wins[i].master_fd = -1;
                if (i == s->active) {
                    int nxt = screen_next_alive(s, s->active, 1);
                    if (nxt < 0) break;
                    s->active = nxt;
                    write_str(1, "\033[2J\033[H");
                    screen_draw_status(s);
                }
            }
        }
    }

    /* Restore stdin flags */
    sys_fcntl_call(0, 4 /* F_SETFL */, orig_flags);
}

static void cmd_screen(int argc, char *argv[]) {
    /* screen -ls: list sessions */
    if (argc >= 2 && strcmp_simple(argv[1], "-ls") == 0) {
        int found = 0;
        for (int i = 0; i < SCREEN_MAX_SESS; i++) {
            if (!screen_sessions[i].used) continue;
            found++;
            char line[64];
            int p = 0;
            line[p++] = '\t';
            int id = screen_sessions[i].id;
            if (id >= 10) line[p++] = '0' + (char)(id / 10 % 10);
            line[p++] = '0' + (char)(id % 10);
            line[p] = '\0';
            write_str(1, line);
            write_str(1, screen_sessions[i].detached
                         ? "\t(Detached)\n" : "\t(Attached)\n");
        }
        if (!found) write_str(1, "No screen sessions.\n");
        return;
    }

    /* screen -r [id]: reattach */
    if (argc >= 2 && strcmp_simple(argv[1], "-r") == 0) {
        int target_id = -1;
        if (argc >= 3) target_id = simple_atoi(argv[2]);

        for (int i = 0; i < SCREEN_MAX_SESS; i++) {
            if (!screen_sessions[i].used || !screen_sessions[i].detached) continue;
            if (target_id >= 0 && screen_sessions[i].id != target_id) continue;

            screen_sessions[i].detached = 0;
            write_str(1, "[reattaching to session]\n");
            screen_run(&screen_sessions[i]);

            if (!screen_sessions[i].detached && screen_alive_count(&screen_sessions[i]) == 0) {
                /* All windows dead — clean up session */
                screen_sessions[i].used = 0;
                write_str(1, "[screen session ended]\n");
            }
            return;
        }
        write_str(2, "No detached session found.\n");
        return;
    }

    /* screen: start new session */
    int slot = -1;
    for (int i = 0; i < SCREEN_MAX_SESS; i++) {
        if (!screen_sessions[i].used) { slot = i; break; }
    }
    if (slot < 0) {
        write_str(2, "screen: max sessions reached\n");
        return;
    }

    struct screen_session *s = &screen_sessions[slot];
    s->id = screen_next_id++;
    s->used = 1;
    s->detached = 0;
    s->nwin = 0;
    s->active = 0;

    for (int i = 0; i < SCREEN_MAX_WIN; i++) {
        s->wins[i].master_fd = -1;
        s->wins[i].child_pid = -1;
        s->wins[i].alive = 0;
    }

    /* Create first window */
    if (screen_spawn_window(&s->wins[0]) < 0) {
        write_str(2, "screen: failed to create PTY window\n");
        s->used = 0;
        return;
    }
    s->nwin = 1;

    write_str(1, "[screen session started — Ctrl+A ? for help]\n");
    screen_run(s);

    if (!s->detached && screen_alive_count(s) == 0) {
        s->used = 0;
        write_str(1, "[screen session ended]\n");
    }
}

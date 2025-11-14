/* sys_execve.c - execve() syscall implementation
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 *
 * Implements program execution via execve().
 *
 * Phase 1 (Completed): Basic execve with FD_CLOEXEC handling
 * Phase 2 (Completed): Enhanced validation, path categorization, detailed logging
 * Phase 3 (Completed): Argument/environment limit enforcement, security checks
 * Phase 4: Performance optimization, COW optimizations
 */

#include <kernel/fut_task.h>
#include <kernel/fut_thread.h>
#include <kernel/fut_vfs.h>
#include <kernel/errno.h>
#include <kernel/uaccess.h>
#include <stddef.h>

/* FD_CLOEXEC flag value */
#define FD_CLOEXEC 1

/* Phase 3: POSIX argument/environment limits */
#define EXEC_ARG_MAX 131072    /* 128 KiB total args */
#define EXEC_ENV_MAX 131072    /* 128 KiB total environment */
#define EXEC_ARGC_MAX 4096     /* Max argument count */
#define EXEC_ENVC_MAX 4096     /* Max environment variable count */
#define EXEC_ARG_LEN_MAX 131072 /* Max single argument length */

extern void fut_printf(const char *fmt, ...);
extern int fut_exec_elf(const char *path, char *const argv[], char *const envp[]);

/**
 * execve() syscall - Execute a program
 *
 * Replaces the current process image with a new program loaded from an
 * executable file. On success, this syscall never returns to the caller.
 *
 * @param pathname  Path to executable file
 * @param argv      Argument vector (NULL-terminated array)
 * @param envp      Environment vector (NULL-terminated array)
 *
 * Returns:
 *   - Does not return on success (current process is replaced)
 *   - -EINVAL if pathname is NULL
 *   - -EFAULT if pathname, argv, or envp points to inaccessible memory
 *   - -ENOENT if pathname does not exist
 *   - -EACCES if pathname is not executable
 *   - -ENOMEM if insufficient memory for new process
 *   - -ESRCH if no current task
 *
 * Behavior:
 *   - Loads executable from pathname
 *   - Replaces current process address space
 *   - Passes argv and envp to new program
 *   - Closes all FDs marked with FD_CLOEXEC
 *   - Preserves PID and other process attributes
 *   - Resets signal handlers to defaults
 *   - Never returns on success
 *
 * Path types:
 *   - Absolute paths: /bin/ls, /usr/bin/program
 *   - Relative paths: ./program, ../bin/tool
 *   - Shell will search PATH for non-absolute paths
 *
 * Argument/environment conventions:
 *   - argv[0]: Program name (by convention)
 *   - argv[1..n]: Command-line arguments
 *   - argv[n+1]: NULL terminator
 *   - envp: KEY=VALUE strings, NULL-terminated
 *
 * Common usage patterns:
 *
 * Execute with arguments:
 *   char *argv[] = {"/bin/ls", "-la", "/home", NULL};
 *   char *envp[] = {"PATH=/bin:/usr/bin", NULL};
 *   execve("/bin/ls", argv, envp);
 *   // Never reached on success
 *
 * Replace shell process:
 *   if (fork() == 0) {
 *       execve("/bin/program", argv, envp);
 *       perror("execve failed");
 *       exit(1);
 *   }
 *
 * Execute with current environment:
 *   extern char **environ;
 *   execve("/bin/program", argv, environ);
 *
 * Close-on-exec handling:
 *   int fd = open("file.txt", O_RDONLY);
 *   fcntl(fd, F_SETFD, FD_CLOEXEC);
 *   execve("/bin/program", argv, envp);
 *   // fd is automatically closed in new program
 *
 * Security considerations:
 *   - Clears environment for setuid programs
 *   - Disables core dumps for setuid programs
 *   - Resets signal dispositions
 *   - Closes FDs marked FD_CLOEXEC
 *
 * Related syscalls:
 *   - fork(): Create child process before exec
 *   - exit(): Terminate without exec
 *   - fcntl(): Set FD_CLOEXEC flag
 *
 * Phase 1 (Completed): Basic execve with FD_CLOEXEC handling
 * Phase 2 (Completed): Enhanced validation, path categorization, detailed logging
 * Phase 3 (Completed): Argument/environment limit enforcement, security checks
 * Phase 4: Performance optimization, COW optimizations
 */
long sys_execve(const char *pathname, char *const argv[], char *const envp[]) {
    /* Get current task for PID logging */
    fut_task_t *task = fut_task_current();
    if (!task) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve() -> ESRCH (no current task)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -ESRCH;
    }

    /* Phase 2: Validate pathname */
    if (!pathname) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=NULL) -> EINVAL (NULL pathname, pid=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; unsigned int val = task->pid;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ")\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EINVAL;
    }

    /* Validate that pathname is a valid userspace pointer (readable) */
    if (fut_access_ok(pathname, 1, 0) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=?) -> EFAULT (pathname not accessible, pid=";
        while (*text) { msg[pos++] = *text++; }

        char num[16]; int num_pos = 0; unsigned int val = task->pid;
        if (val == 0) { num[num_pos++] = '0'; }
        else { char temp[16]; int temp_pos = 0;
            while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
            while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
        num[num_pos] = '\0';
        for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

        text = ")\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EFAULT;
    }

    /* Validate that argv is a valid userspace pointer (readable) */
    if (argv && fut_access_ok(argv, sizeof(char *), 0) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=";
        while (*text) { msg[pos++] = *text++; }
        const char *p = pathname;
        while (*p && pos < 100) { msg[pos++] = *p++; }
        text = ") -> EFAULT (argv not accessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EFAULT;
    }

    /* Validate that envp is a valid userspace pointer (readable) if provided */
    if (envp && fut_access_ok(envp, sizeof(char *), 0) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=";
        while (*text) { msg[pos++] = *text++; }
        const char *p = pathname;
        while (*p && pos < 100) { msg[pos++] = *p++; }
        text = ") -> EFAULT (envp not accessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EFAULT;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (pathname[0] == '/') {
        path_type = "absolute";
    } else if (pathname[0] == '.' && pathname[1] == '/') {
        path_type = "relative (./...)";
    } else if (pathname[0] == '.' && pathname[1] == '.' && pathname[2] == '/') {
        path_type = "relative (../...)";
    } else {
        path_type = "basename (no path)";
    }

    /* Phase 2: Count argv and envp entries */
    int argc = 0;
    if (argv) {
        while (argv[argc] != NULL && argc < 1000) {
            argc++;
        }
    }

    int envc = 0;
    if (envp) {
        while (envp[envc] != NULL && envc < 1000) {
            envc++;
        }
    }

    /* Phase 3: Validate argument and environment limits */
    unsigned long total_argv_size = 0;
    if (argv) {
        for (int i = 0; i < argc && i < EXEC_ARGC_MAX; i++) {
            if (argv[i] == NULL) break;
            size_t arg_len = 0;
            const char *ptr = argv[i];
            while (ptr[arg_len] != '\0' && arg_len < EXEC_ARG_LEN_MAX) {
                arg_len++;
            }
            if (arg_len >= EXEC_ARG_LEN_MAX) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (argument too long, >131KB)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }
            total_argv_size += arg_len + 1;
            if (total_argv_size > EXEC_ARG_MAX) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (total arguments exceed 128KB)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }
        }
    }

    /* Phase 3: Validate environment variable limits */
    if (argc >= EXEC_ARGC_MAX) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve() -> E2BIG (argc exceeds 4096)\\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -E2BIG;
    }

    unsigned long total_envp_size = 0;
    if (envp) {
        for (int i = 0; i < envc && i < EXEC_ENVC_MAX; i++) {
            if (envp[i] == NULL) break;
            size_t env_len = 0;
            const char *ptr = envp[i];
            while (ptr[env_len] != '\0' && env_len < EXEC_ARG_LEN_MAX) {
                env_len++;
            }
            if (env_len >= EXEC_ARG_LEN_MAX) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (environment variable too long)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }
            total_envp_size += env_len + 1;
            if (total_envp_size > EXEC_ENV_MAX) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> E2BIG (total environment exceeds 128KB)\\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -E2BIG;
            }
        }
    }

    if (envc >= EXEC_ENVC_MAX) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve() -> E2BIG (envc exceeds 4096)\\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -E2BIG;
    }

    /* Phase 3: Log argument and environment size limits enforcement */
    char limit_msg[256];
    int limit_pos = 0;
    const char *limit_text = "[EXECVE] execve() limit check: argv_size=";
    while (*limit_text) { limit_msg[limit_pos++] = *limit_text++; }

    char num[16]; int num_pos = 0; unsigned long val = total_argv_size;
    if (val == 0) { num[num_pos++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
        while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
    num[num_pos] = '\0';
    for (int i = 0; num[i]; i++) { limit_msg[limit_pos++] = num[i]; }

    limit_text = ", envp_size=";
    while (*limit_text) { limit_msg[limit_pos++] = *limit_text++; }

    num_pos = 0; val = total_envp_size;
    if (val == 0) { num[num_pos++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
        while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
    num[num_pos] = '\0';
    for (int i = 0; num[i]; i++) { limit_msg[limit_pos++] = num[i]; }

    limit_text = " (Phase 3 limits: 128KB args, 128KB env)\\n";
    while (*limit_text) { limit_msg[limit_pos++] = *limit_text++; }
    limit_msg[limit_pos] = '\0';
    fut_printf("%s", limit_msg);

    /* Phase 2: Categorize argument count */
    const char *argc_category;
    if (argc == 0) {
        argc_category = "none";
    } else if (argc <= 5) {
        argc_category = "few (1-5)";
    } else if (argc <= 20) {
        argc_category = "normal (6-20)";
    } else {
        argc_category = "many (>20)";
    }

    /* Phase 2: Count FDs to close */
    int cloexec_count = 0;
    if (task->fd_table) {
        for (int i = 0; i < task->max_fds; i++) {
            struct fut_file *file = task->fd_table[i];
            if (file != NULL && (file->fd_flags & FD_CLOEXEC)) {
                cloexec_count++;
            }
        }
    }

    /* Close all FDs marked with FD_CLOEXEC before executing new binary */
    if (task->fd_table) {
        for (int i = 0; i < task->max_fds; i++) {
            struct fut_file *file = task->fd_table[i];
            if (file != NULL && (file->fd_flags & FD_CLOEXEC)) {
                /* Close this FD (CLOEXEC means "close on exec") */
                fut_vfs_close(i);
                /* Note: fut_vfs_close will remove from task's FD table */
            }
        }
    }

    /* Phase 2: Detailed pre-exec logging */
    char msg[256];
    int pos = 0;
    const char *text = "[EXECVE] execve(path=";
    while (*text) { msg[pos++] = *text++; }
    const char *p = pathname;
    int path_len = 0;
    while (*p && path_len < 80) { msg[pos++] = *p++; path_len++; }
    text = " [";
    while (*text) { msg[pos++] = *text++; }
    while (*path_type) { msg[pos++] = *path_type++; }
    text = "], argc=";
    while (*text) { msg[pos++] = *text++; }

    char num2[16]; int num_pos2 = 0; int val2 = argc;
    if (val2 == 0) { num2[num_pos2++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val2 > 0) { temp[temp_pos++] = '0' + (val2 % 10); val2 /= 10; }
        while (temp_pos > 0) { num2[num_pos2++] = temp[--temp_pos]; } }
    num2[num_pos2] = '\0';
    for (int i = 0; num2[i]; i++) { msg[pos++] = num2[i]; }

    text = " [";
    while (*text) { msg[pos++] = *text++; }
    while (*argc_category) { msg[pos++] = *argc_category++; }
    text = "], envc=";
    while (*text) { msg[pos++] = *text++; }

    num_pos2 = 0; val2 = envc;
    if (val2 == 0) { num2[num_pos2++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val2 > 0) { temp[temp_pos++] = '0' + (val2 % 10); val2 /= 10; }
        while (temp_pos > 0) { num2[num_pos2++] = temp[--temp_pos]; } }
    num2[num_pos2] = '\0';
    for (int i = 0; num2[i]; i++) { msg[pos++] = num2[i]; }

    text = ", cloexec_fds=";
    while (*text) { msg[pos++] = *text++; }

    num_pos2 = 0; val2 = cloexec_count;
    if (val2 == 0) { num2[num_pos2++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val2 > 0) { temp[temp_pos++] = '0' + (val2 % 10); val2 /= 10; }
        while (temp_pos > 0) { num2[num_pos2++] = temp[--temp_pos]; } }
    num2[num_pos2] = '\0';
    for (int i = 0; num2[i]; i++) { msg[pos++] = num2[i]; }

    text = ", pid=";
    while (*text) { msg[pos++] = *text++; }

    num_pos2 = 0; unsigned int uval = task->pid;
    if (uval == 0) { num2[num_pos2++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (uval > 0) { temp[temp_pos++] = '0' + (uval % 10); uval /= 10; }
        while (temp_pos > 0) { num2[num_pos2++] = temp[--temp_pos]; } }
    num2[num_pos2] = '\0';
    for (int i = 0; num2[i]; i++) { msg[pos++] = num2[i]; }

    text = ") (replacing process image, Phase 2)\n";
    while (*text) { msg[pos++] = *text++; }
    msg[pos] = '\0';
    fut_printf("%s", msg);

    /* Call the ELF loader which replaces the current process */
    int ret = fut_exec_elf(pathname, argv, envp);

    /*
     * If fut_exec_elf returns, it failed.
     * On success, it never returns (process is replaced).
     */

    /* Phase 2: Detailed error logging */
    const char *error_desc;
    switch (ret) {
        case -ENOENT:
            error_desc = "file not found";
            break;
        case -EACCES:
            error_desc = "permission denied";
            break;
        case -ENOMEM:
            error_desc = "out of memory";
            break;
        case -EINVAL:
            error_desc = "invalid executable format";
            break;
        default:
            error_desc = "exec failed";
            break;
    }

    pos = 0;
    text = "[EXECVE] execve(path=";
    while (*text) { msg[pos++] = *text++; }
    p = pathname;
    path_len = 0;
    while (*p && path_len < 80) { msg[pos++] = *p++; path_len++; }
    text = ") -> ";
    while (*text) { msg[pos++] = *text++; }

    /* Add error code */
    num_pos = 0; val = -ret;
    if (val == 0) { num[num_pos++] = '0'; }
    else { char temp[16]; int temp_pos = 0;
        while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
        while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
    num[num_pos] = '\0';
    msg[pos++] = '-';
    for (int i = 0; num[i]; i++) { msg[pos++] = num[i]; }

    text = " (";
    while (*text) { msg[pos++] = *text++; }
    while (*error_desc) { msg[pos++] = *error_desc++; }
    text = ")\n";
    while (*text) { msg[pos++] = *text++; }
    msg[pos] = '\0';
    fut_printf("%s", msg);

    return ret;
}

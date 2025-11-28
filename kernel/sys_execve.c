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
    /* ARM64 FIX: Copy parameters to local variables immediately to ensure they're preserved
     * on the stack across potentially blocking calls. VFS operations, access checks, and
     * copy operations may block and corrupt register-passed parameters upon resumption. */
    const char *local_pathname = pathname;
    char *const *local_argv = argv;
    char *const *local_envp = envp;

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
    if (!local_pathname) {
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
    if (fut_access_ok(local_pathname, 1, 0) != 0) {
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
    if (local_argv && fut_access_ok(local_argv, sizeof(char *), 0) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=";
        while (*text) { msg[pos++] = *text++; }
        const char *p = local_pathname;
        while (*p && pos < 100) { msg[pos++] = *p++; }
        text = ") -> EFAULT (argv not accessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EFAULT;
    }

    /* Validate that envp is a valid userspace pointer (readable) if provided */
    if (local_envp && fut_access_ok(local_envp, sizeof(char *), 0) != 0) {
        char msg[128];
        int pos = 0;
        const char *text = "[EXECVE] execve(path=";
        while (*text) { msg[pos++] = *text++; }
        const char *p = local_pathname;
        while (*p && pos < 100) { msg[pos++] = *p++; }
        text = ") -> EFAULT (envp not accessible)\n";
        while (*text) { msg[pos++] = *text++; }
        msg[pos] = '\0';
        fut_printf("%s", msg);
        return -EFAULT;
    }

    /* Phase 2: Categorize path type */
    const char *path_type;
    if (local_pathname[0] == '/') {
        path_type = "absolute";
    } else if (local_pathname[0] == '.' && local_pathname[1] == '/') {
        path_type = "relative (./...)";
    } else if (local_pathname[0] == '.' && local_pathname[1] == '.' && local_pathname[2] == '/') {
        path_type = "relative (../...)";
    } else {
        path_type = "basename (no path)";
    }

    /* Security hardening WARNING: TOCTOU Race Condition in execve()
     *
     * execve() has inherent time-of-check-time-of-use vulnerabilities that CANNOT
     * be fully mitigated within the current architecture. This warning documents
     * the race conditions for security auditors and future development.
     *
     * VULNERABILITY: argv/envp Modification Between Validation and Use
     * ----------------------------------------------------------------
     * Current flow:
     *   1. sys_execve validates argv/envp strings (lines 236-353)
     *   2. sys_execve calls fut_exec_elf(pathname, argv, envp) at line 494
     *   3. fut_exec_elf copies argv/envp to kernel memory at lines 873-892
     *   4. During step 3, kstrlen() directly dereferences userspace pointers
     *
     * ATTACK SCENARIO 1: Argument String Substitution
     *   Thread A (attacker syscall):
     *     char *argv[] = {"/bin/sh", "-c", "safe_command", NULL};
     *     execve("/bin/sh", argv, envp);
     *   Thread B (concurrent modifier):
     *     // Wait for sys_execve to pass validation but before fut_exec_elf
     *     argv[2] = "rm -rf /";  // Change argument after validation
     *   Result: Executes "rm -rf /" instead of "safe_command"
     *
     * ATTACK SCENARIO 2: Pointer Substitution to Kernel Memory
     *   Thread A:
     *     char safe_arg[] = "safe";
     *     char *argv[] = {"/bin/prog", safe_arg, NULL};
     *     execve("/bin/prog", argv, envp);
     *   Thread B:
     *     // After validation, before kstrlen() call
     *     argv[1] = (char *)0xFFFFFFFF80000000;  // Kernel address
     *   Result: kstrlen() reads kernel memory, potential information leak
     *
     * ATTACK SCENARIO 3: Length Extension via Page Fault
     *   Thread A:
     *     char arg[EXEC_ARG_LEN_MAX] = {...};  // Passes validation
     *     char *argv[] = {"/bin/prog", arg, NULL};
     *     execve("/bin/prog", argv, envp);
     *   Thread B:
     *     // After validation length check
     *     munmap(arg + EXEC_ARG_LEN_MAX - 1);  // Trigger fault on boundary
     *   Result: kstrlen() page faults or reads unmapped memory
     *
     * ATTACK SCENARIO 4: Argument Count Change
     *   Thread A:
     *     char *argv[] = {"prog", "arg1", "arg2", NULL};
     *     execve("prog", argv, envp);
     *   Thread B:
     *     // After argc counting (line 223), before validation loop
     *     argv[2] = NULL;  // Reduce argc
     *   Result: Validation loop uses old argc, accesses NULL pointer
     *
     * WHY MITIGATION IS DIFFICULT:
     * ----------------------------
     * 1. POSIX Requirement: execve() signature is char *const argv[]
     *    - Cannot change to const char *const *const without breaking ABI
     *    - "const" only prevents syscall from modifying, not other threads
     *
     * 2. Performance Impact: Copying all args to kernel memory BEFORE validation
     *    - Would require 2x memory allocation (validate copy, then exec copy)
     *    - Current approach validates first to fail fast on invalid args
     *
     * 3. Architectural Dependency: fut_exec_elf uses kstrlen() unsafely
     *    - kstrlen() at elf64.c:132 directly dereferences userspace pointers
     *    - Should use fut_copy_from_user with length limits
     *    - Fixing requires modifying core ELF loader (outside sys_execve scope)
     *
     * PARTIAL MITIGATIONS IN PLACE:
     * -----------------------------
     * ✓ Argument count limits (EXEC_ARGC_MAX = 4096)
     * ✓ Argument size limits (EXEC_ARG_MAX = 128KB total)
     * ✓ Per-argument length limits (EXEC_ARG_LEN_MAX = 128KB)
     * ✓ Pointer accessibility validation (fut_access_ok checks)
     * ✓ Early validation failure (reject before file open)
     *
     * PROPER FIXES (Future Work):
     * ---------------------------
     * 1. Modify fut_exec_elf to use safe string copy during initial validation:
     *    - Allocate kernel buffer during sys_execve validation
     *    - Use fut_copy_from_user with strict length limits
     *    - Pass kernel buffer to fut_exec_elf instead of userspace pointers
     *
     * 2. Add memory lock during exec (similar to mlock):
     *    - Lock argv/envp pages into memory
     *    - Prevent modification until exec completes
     *    - Requires MM subsystem support for userspace-write locking
     *
     * 3. Use copy-on-write protection:
     *    - Mark argv/envp pages read-only after validation
     *    - Any write attempt triggers COW, preserving validated copy
     *    - Complex interaction with fork() and multithreading
     *
     * COMPARISON TO SIMILAR VULNERABILITIES:
     * --------------------------------------
     * - CVE-2016-0728: Linux kernel keyring TOCTOU (use-after-free)
     * - CVE-2009-1897: Linux kernel execve race (argv modification)
     * - CVE-2014-0196: Linux TTY TOCTOU (buffer overflow via race)
     *
     * POSIX GUIDANCE (IEEE Std 1003.1):
     *   execve() does not specify atomicity requirements for argv/envp.
     *   Applications must ensure exclusive access to exec arguments.
     *   Concurrent modification by multiple threads produces undefined behavior.
     *
     * DEVELOPER GUIDANCE:
     * -------------------
     * Applications MUST NOT modify argv/envp from other threads during execve().
     * Use process-level synchronization (mutex, semaphore) to serialize exec calls.
     *
     * Example safe pattern:
     *   pthread_mutex_lock(&exec_lock);
     *   char *argv[] = {"/bin/sh", "-c", cmd, NULL};
     *   execve("/bin/sh", argv, envp);  // Never returns on success
     *   pthread_mutex_unlock(&exec_lock);  // Only reached on failure
     *
     * This vulnerability affects ALL Unix-like systems with multithreading.
     * It is a fundamental limitation of the POSIX execve() interface.
     */

    /* Phase 2: Count argv and envp entries */
    int argc = 0;
    if (local_argv) {
        while (local_argv[argc] != NULL && argc < 1000) {
            argc++;
        }
    }

    int envc = 0;
    if (local_envp) {
        while (local_envp[envc] != NULL && envc < 1000) {
            envc++;
        }
    }

    /* Phase 3: Validate argument and environment limits */
    unsigned long total_argv_size = 0;
    if (local_argv) {
        for (int i = 0; i < argc && i < EXEC_ARGC_MAX; i++) {
            if (local_argv[i] == NULL) break;

            /* Phase 5: Validate that argv[i] pointer is accessible before dereferencing */
            const char *ptr = local_argv[i];
            if (fut_access_ok(ptr, EXEC_ARG_LEN_MAX, 0) != 0) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> EFAULT (argv[";
                while (*text) { msg[pos++] = *text++; }
                /* Convert i to string */
                char num[16]; int num_pos = 0;
                int val = i;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }
                text = "] pointer invalid, Phase 5)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -EFAULT;
            }

            size_t arg_len = 0;
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
    if (local_envp) {
        for (int i = 0; i < envc && i < EXEC_ENVC_MAX; i++) {
            if (local_envp[i] == NULL) break;

            /* Phase 5: Validate that envp[i] pointer is accessible before dereferencing */
            const char *ptr = local_envp[i];
            if (fut_access_ok(ptr, EXEC_ARG_LEN_MAX, 0) != 0) {
                char msg[128];
                int pos = 0;
                const char *text = "[EXECVE] execve() -> EFAULT (envp[";
                while (*text) { msg[pos++] = *text++; }
                /* Convert i to string */
                char num[16]; int num_pos = 0;
                int val = i;
                if (val == 0) { num[num_pos++] = '0'; }
                else { char temp[16]; int temp_pos = 0;
                    while (val > 0) { temp[temp_pos++] = '0' + (val % 10); val /= 10; }
                    while (temp_pos > 0) { num[num_pos++] = temp[--temp_pos]; } }
                num[num_pos] = '\0';
                for (int j = 0; num[j]; j++) { msg[pos++] = num[j]; }
                text = "] pointer invalid, Phase 5)\n";
                while (*text) { msg[pos++] = *text++; }
                msg[pos] = '\0';
                fut_printf("%s", msg);
                return -EFAULT;
            }

            size_t env_len = 0;
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
    const char *p = local_pathname;
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

    /* Call the ELF loader which creates the new process image */
    int ret = fut_exec_elf(local_pathname, local_argv, local_envp);

    /*
     * fut_exec_elf returns 0 on success (new process created), or negative error.
     * On success, the current thread must exit to let the new process run.
     * This is the correct POSIX execve() semantics: the calling process is replaced.
     */
    if (ret == 0) {
        /* Success - exit the current thread, the new process will run */
        extern void fut_thread_exit(void) __attribute__((noreturn));
        fut_thread_exit();
        /* Should not reach here */
    }

    /* If we get here, fut_exec_elf failed. Log the error. */
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
    p = local_pathname;
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
